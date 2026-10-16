use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use ed25519_dalek::SigningKey;

use super::messages::*;

pub const MAX_TOTAL_PEERS: usize = 64;
pub const MAX_PEERS_PER_IP: usize = 4;
pub const BAN_DURATION_SECS: u64 = 3600; // 1 hour ban in case of attack

#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub addr: SocketAddr,
    pub node_pubkey: [u8; 32],
    pub height: u64,
    pub last_seen: u64,
    pub connected_at: u64,
    pub is_outbound: bool,
}

pub struct PeerHandle {
    pub info: PeerInfo,
    pub tx: mpsc::Sender<P2PPayload>,
    pub cancel_tx: tokio::sync::watch::Sender<bool>,
    pub conn_id: u64,
}

pub struct PeerManager {
    pub chain_id: String,
    pub signing_key: Arc<SigningKey>,
    pub peers: HashMap<SocketAddr, PeerHandle>,
    pub banned_ips: HashMap<IpAddr, u64>,
    pub seed_nodes: Vec<SocketAddr>,
    pub seen_hashes: HashSet<[u8; 32]>,
    pub seen_hashes_order: VecDeque<[u8; 32]>,
}

impl PeerManager {
    pub fn new(chain_id: &str, signing_key: Arc<SigningKey>, seeds: Vec<SocketAddr>) -> Self {
        Self {
            chain_id: chain_id.to_string(),
            signing_key,
            peers: HashMap::new(),
            banned_ips: HashMap::new(),
            seed_nodes: seeds,
            seen_hashes: HashSet::new(),
            seen_hashes_order: VecDeque::new(),
        }
    }

    /// Checks if an IP is allowed to connect (not banned and below IP connection limit)
    pub fn check_admission(&mut self, addr: &SocketAddr) -> Result<(), String> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // 1. Clear expired bans
        self.banned_ips.retain(|_, &mut expire_ts| expire_ts > now);

        // 2. Check if IP is banned
        if let Some(&expire_ts) = self.banned_ips.get(&addr.ip()) {
            let remaining = expire_ts.saturating_sub(now);
            return Err(format!(
                "IP {} is banned for malicious behavior. {}s remaining",
                addr.ip(), remaining
            ));
        }

        // 3. Purge dead/cancelled peers before evaluating limits
        self.peers.retain(|_, handle| !*handle.cancel_tx.borrow());

        // 4. Check global peer limit
        if self.peers.len() >= MAX_TOTAL_PEERS {
            return Err(format!(
                "Global peer limit reached ({})",
                MAX_TOTAL_PEERS
            ));
        }

        // 5. Check peer limit per IP
        let ip_count = self.peers.keys().filter(|a| a.ip() == addr.ip()).count();
        if ip_count >= MAX_PEERS_PER_IP {
            return Err(format!(
                "Concurrent connection limit for IP {} reached ({})",
                addr.ip(), MAX_PEERS_PER_IP
            ));
        }

        Ok(())
    }

    /// Adds an authenticated peer, deduplicating by node_pubkey and by addr.
    /// If an existing connection for the same node_pubkey exists, it cancels and evicts the old connection.
    pub fn add_peer(
        &mut self,
        addr: SocketAddr,
        node_pubkey: [u8; 32],
        height: u64,
        is_outbound: bool,
        tx: mpsc::Sender<P2PPayload>,
        cancel_tx: tokio::sync::watch::Sender<bool>,
        conn_id: u64,
    ) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // 1. If an old connection with the exact same addr exists, cancel and remove it
        if let Some(old) = self.peers.remove(&addr) {
            println!("🔄 [P2P Wire] Replacing existing connection for addr {} (cancelling old conn #{})", addr, old.conn_id);
            let _ = old.cancel_tx.send(true);
        }

        // 2. Deduplicate by node_pubkey: find and cancel any connection for this pubkey from other addresses
        let old_addrs: Vec<(SocketAddr, u64)> = self.peers.iter()
            .filter(|(existing_addr, peer)| peer.info.node_pubkey == node_pubkey && **existing_addr != addr)
            .map(|(existing_addr, peer)| (*existing_addr, peer.conn_id))
            .collect();

        for (old_addr, old_cid) in old_addrs {
            println!(
                "🔄 [P2P Wire] Deduplicating connection for peer pubkey 0x{}... (closing old {} conn #{})",
                hex::encode(&node_pubkey[..4]),
                old_addr,
                old_cid
            );
            if let Some(old) = self.peers.remove(&old_addr) {
                let _ = old.cancel_tx.send(true);
            }
        }

        let info = PeerInfo {
            addr,
            node_pubkey,
            height,
            last_seen: now,
            connected_at: now,
            is_outbound,
        };

        self.peers.insert(addr, PeerHandle { info, tx, cancel_tx, conn_id });
    }

    /// Removes a disconnected peer only if its connection ID matches (preventing stale workers from removing newer connections)
    pub fn remove_peer_conn(&mut self, addr: &SocketAddr, conn_id: u64) -> bool {
        if let Some(peer) = self.peers.get(addr) {
            if peer.conn_id == conn_id {
                let peer = self.peers.remove(addr).unwrap();
                let _ = peer.cancel_tx.send(true);
                return true;
            }
        }
        false
    }

    /// Removes a disconnected peer and signals its cancellation
    pub fn remove_peer(&mut self, addr: &SocketAddr) {
        if let Some(peer) = self.peers.remove(addr) {
            let _ = peer.cancel_tx.send(true);
        }
    }

    /// Bans an IP for consensus violation or malicious attack and terminates connection
    pub fn ban_peer(&mut self, addr: &SocketAddr, reason: &str) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        println!(
            "🚨 [P2P DEFENSE] Banning IP {} for 1h. Reason: {}",
            addr.ip(), reason
        );

        self.banned_ips.insert(addr.ip(), now + BAN_DURATION_SECS);
        if let Some(peer) = self.peers.remove(addr) {
            let _ = peer.cancel_tx.send(true);
        }
    }

    /// Records a seen message hash to prevent circular gossip storms (Gossip Loop)
    pub fn mark_seen(&mut self, hash: [u8; 32]) -> bool {
        if self.seen_hashes.contains(&hash) {
            return false; // Already seen
        }

        self.seen_hashes.insert(hash);
        self.seen_hashes_order.push_back(hash);

        // Keeps cache at 10,000 max items with O(1) removal
        if self.seen_hashes_order.len() > 10_000 {
            if let Some(old) = self.seen_hashes_order.pop_front() {
                self.seen_hashes.remove(&old);
            }
        }

        true // New
    }

    /// Broadcasts a message to all connected peers (optionally excluding sender) without locking during transmission
    pub async fn broadcast(&mut self, message: P2PPayload, exclude: Option<SocketAddr>) {
        let peer_channels: Vec<(SocketAddr, mpsc::Sender<P2PPayload>, tokio::sync::watch::Sender<bool>)> = self.peers.iter()
            .filter(|(&addr, _)| Some(addr) != exclude)
            .map(|(&addr, handle)| (addr, handle.tx.clone(), handle.cancel_tx.clone()))
            .collect();

        let mut dead_peers = Vec::new();
        for (addr, tx, cancel_tx) in peer_channels {
            match tx.try_send(message.clone()) {
                Ok(_) => {},
                Err(mpsc::error::TrySendError::Full(_)) => {
                    let msg = message.clone();
                    tokio::spawn(async move {
                        let _ = tokio::time::timeout(std::time::Duration::from_millis(500), tx.send(msg)).await;
                    });
                },
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    let _ = cancel_tx.send(true);
                    dead_peers.push(addr);
                }
            }
        }

        for dead in dead_peers {
            self.peers.remove(&dead);
        }
    }

    /// Returns highest known peer height
    pub fn highest_peer_height(&self) -> u64 {
        self.peers.values().map(|p| p.info.height).max().unwrap_or(0)
    }

    /// Updates last_seen and height of a peer
    pub fn touch_peer(&mut self, addr: &SocketAddr, height: Option<u64>) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        if let Some(peer) = self.peers.get_mut(addr) {
            peer.info.last_seen = now;
            if let Some(h) = height {
                if h > peer.info.height {
                    peer.info.height = h;
                }
            }
        }
    }
}

pub type SharedPeerManager = Arc<Mutex<PeerManager>>;

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_peer_manager_admission_and_ip_limits() {
        let key = Arc::new(SigningKey::generate(&mut OsRng));
        let mut pm = PeerManager::new("vera-testnet-1", key, vec![]);

        let addr1: SocketAddr = "192.168.1.10:26656".parse().unwrap();
        assert!(pm.check_admission(&addr1).is_ok());

        // Add 4 peers from same IP with distinct node_pubkeys (maximum allowed limit)
        for port in 1000..1004 {
            let addr: SocketAddr = format!("192.168.1.10:{}", port).parse().unwrap();
            let (tx, _) = mpsc::channel(1);
            let (cancel_tx, _) = tokio::sync::watch::channel(false);
            let mut pk = [0u8; 32];
            pk[0] = (port - 1000) as u8 + 1;
            pm.add_peer(addr, pk, 10, false, tx, cancel_tx, port as u64);
        }

        // 5th connection from same IP must be rejected
        let addr5: SocketAddr = "192.168.1.10:1005".parse().unwrap();
        let res = pm.check_admission(&addr5);
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("Concurrent connection limit"));

        // But another IP must be accepted normally
        let addr_other: SocketAddr = "10.0.0.1:26656".parse().unwrap();
        assert!(pm.check_admission(&addr_other).is_ok());
    }

    #[test]
    fn test_peer_manager_pubkey_deduplication() {
        let key = Arc::new(SigningKey::generate(&mut OsRng));
        let mut pm = PeerManager::new("vera-testnet-1", key, vec![]);

        let pubkey_a = [42u8; 32];
        let addr1: SocketAddr = "192.168.1.10:26656".parse().unwrap();
        let addr2: SocketAddr = "192.168.1.10:26657".parse().unwrap();

        let (tx1, _) = mpsc::channel(1);
        let (cancel_tx1, cancel_rx1) = tokio::sync::watch::channel(false);
        pm.add_peer(addr1, pubkey_a, 10, false, tx1, cancel_tx1, 1);

        assert_eq!(pm.peers.len(), 1);
        assert!(!*cancel_rx1.borrow(), "Initial connection must not be cancelled");

        // Reconnect from new address with SAME node_pubkey
        let (tx2, _) = mpsc::channel(1);
        let (cancel_tx2, cancel_rx2) = tokio::sync::watch::channel(false);
        pm.add_peer(addr2, pubkey_a, 11, false, tx2, cancel_tx2, 2);

        assert_eq!(pm.peers.len(), 1, "Must have exactly 1 peer after deduplication");
        assert!(pm.peers.contains_key(&addr2), "New address must be registered");
        assert!(!pm.peers.contains_key(&addr1), "Old address must be evicted");
        assert!(*cancel_rx1.borrow(), "Old peer connection must be cancelled immediately");
        assert!(!*cancel_rx2.borrow(), "New peer connection must remain active");
    }

    #[test]
    fn test_peer_manager_remove_peer_conn_prevents_stale_eviction() {
        let key = Arc::new(SigningKey::generate(&mut OsRng));
        let mut pm = PeerManager::new("vera-testnet-1", key, vec![]);

        let pubkey_a = [99u8; 32];
        let addr: SocketAddr = "192.168.1.50:26656".parse().unwrap();

        // 1. Initial connection (conn_id = 1)
        let (tx1, _) = mpsc::channel(1);
        let (cancel_tx1, cancel_rx1) = tokio::sync::watch::channel(false);
        pm.add_peer(addr, pubkey_a, 10, false, tx1, cancel_tx1, 1);

        // 2. Peer quickly reconnects with new connection (conn_id = 2) on same addr
        let (tx2, _) = mpsc::channel(1);
        let (cancel_tx2, cancel_rx2) = tokio::sync::watch::channel(false);
        pm.add_peer(addr, pubkey_a, 11, false, tx2, cancel_tx2, 2);

        assert!(*cancel_rx1.borrow(), "Old connection was cancelled");
        assert!(!*cancel_rx2.borrow(), "New connection is active");

        // 3. Stale worker from conn_id = 1 attempts to clean up its address
        let removed_stale = pm.remove_peer_conn(&addr, 1);
        assert!(!removed_stale, "Stale worker must NOT remove newer connection");
        assert_eq!(pm.peers.len(), 1, "Peer map must retain connection #2");
        assert!(!*cancel_rx2.borrow(), "New connection must not be cancelled by stale worker");

        // 4. Proper worker from conn_id = 2 cleans up
        let removed_proper = pm.remove_peer_conn(&addr, 2);
        assert!(removed_proper, "Current worker cleans up connection #2");
        assert_eq!(pm.peers.len(), 0, "Peer map now empty");
    }

    #[test]
    fn test_peer_manager_banlist_enforcement() {
        let key = Arc::new(SigningKey::generate(&mut OsRng));
        let mut pm = PeerManager::new("vera-testnet-1", key, vec![]);

        let bad_peer: SocketAddr = "45.33.22.11:26656".parse().unwrap();
        assert!(pm.check_admission(&bad_peer).is_ok());

        // Apply ban
        pm.ban_peer(&bad_peer, "Attempted forged block injection");

        // New connection must be blocked
        let res = pm.check_admission(&bad_peer);
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("is banned for malicious behavior"));
    }

    #[test]
    fn test_peer_manager_gossip_dedup_cache_o1() {
        let key = Arc::new(SigningKey::generate(&mut OsRng));
        let mut pm = PeerManager::new("vera-testnet-1", key, vec![]);

        let hash = [77u8; 32];
        assert!(pm.mark_seen(hash), "First time must be new");
        assert!(!pm.mark_seen(hash), "Second time must be detected as duplicate");
    }

    #[test]
    fn test_mini_validator_vote_crypto_roundtrip() {
        let key = SigningKey::generate(&mut OsRng);
        let block_hash = [42u8; 32];
        let vote = MiniValidatorVote::new("vera-testnet-1", 150, block_hash, &key);

        assert!(vote.verify("vera-testnet-1").is_ok());
        assert!(vote.verify("vera-mainnet").is_err(), "Incorrect Chain ID must be rejected");

        let mut tampered_vote = vote.clone();
        tampered_vote.block_hash[0] ^= 0xFF;
        assert!(tampered_vote.verify("vera-testnet-1").is_err(), "Tampered hash must fail signature verification");
    }
}
