pub mod messages;
pub mod wire;
pub mod peer_manager;

pub use messages::*;
pub use wire::*;
pub use peer_manager::*;

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};
use ed25519_dalek::SigningKey;

static NEXT_CONN_ID: AtomicU64 = AtomicU64::new(1);

/// Events dispatched by P2P network to FullNode
#[derive(Debug, Clone)]
pub enum P2PEvent {
    NewTransaction(crate::transaction::Transaction),
    BlockProposal(crate::block::Block),
    BftVote(crate::consensus::Vote),
    MiniValidatorVote(MiniValidatorVote),
    BlockCommit(crate::block::Block),
    SyncRequest { peer_addr: SocketAddr, req: SyncRequest },
    SyncResponse { peer_addr: SocketAddr, res: SyncResponse },
    PeerConnected { addr: SocketAddr, height: u64 },
    /// Signature/freshness-checked by the receiver; validator-set membership is checked
    /// by the node event loop before the announce is stored, relayed or dialed.
    PeerAnnounce { peer_addr: SocketAddr, announce: PeerAnnounce },
    TmProposal { peer_addr: SocketAddr, proposal: TmProposal },
    TmVote { peer_addr: SocketAddr, vote: crate::consensus::Vote },
    TmCompactProposal { peer_addr: SocketAddr, compact: TmCompactProposal },
    TmProposalRequest { peer_addr: SocketAddr, height: u64, round: u64, missing: String },
    TmProposalTxs { peer_addr: SocketAddr, height: u64, round: u64, txs: Vec<crate::transaction::Transaction> },
    PeerDisconnected { addr: SocketAddr },
}

/// Stable categories of seed connection failures used to prevent log flooding
/// while preserving timing details in emitted messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeedFailureType {
    TcpTimeout,
    TcpRefused,
    HsSend,
    AckTimeout,
    AckEof,
    AckReadErr,
    AckUnexpected,
    AckRejected,
    Admission,
}

impl SeedFailureType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::TcpTimeout => "TcpTimeout",
            Self::TcpRefused => "TcpRefused",
            Self::HsSend => "HsSend",
            Self::AckTimeout => "AckTimeout",
            Self::AckEof => "AckEof",
            Self::AckReadErr => "AckReadErr",
            Self::AckUnexpected => "AckUnexpected",
            Self::AckRejected => "AckRejected",
            Self::Admission => "Admission",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeedFailure {
    pub kind: SeedFailureType,
    pub message: String,
}

impl SeedFailure {
    pub fn new(kind: SeedFailureType, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    pub fn contains(&self, pat: &str) -> bool {
        self.message.contains(pat)
    }
}

impl std::fmt::Display for SeedFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for SeedFailure {}

impl std::ops::Deref for SeedFailure {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        &self.message
    }
}

pub struct SeedConnTracker {
    pub attempts: u32,
    pub first_failed_at: std::time::Instant,
    pub last_failure_type: Option<SeedFailureType>,
    pub last_reason: String,
}

/// Pure decision function determining whether a seed failure line should be emitted.
/// - Attempt 1: always emits (first failure).
/// - Subsequent attempts: emits only if the stable failure type changes, or every 10 attempts.
pub fn should_log(attempts: u32, last_type: Option<SeedFailureType>, current_type: SeedFailureType) -> bool {
    if attempts == 1 {
        true
    } else {
        last_type != Some(current_type) || attempts % 10 == 0
    }
}

/// Per-connection queue for consensus messages (ahead of transaction gossip).
const PRIORITY_QUEUE_LEN: usize = 1024;

pub struct P2PService {
    pub chain_id: String,
    pub peer_manager: SharedPeerManager,
    pub signing_key: Arc<SigningKey>,
    pub event_tx: mpsc::Sender<P2PEvent>,
    /// When set, gossiped transactions go here instead of `event_tx` (try_send: a flood
    /// of transactions never blocks the connection reader, so the consensus messages
    /// behind them on the same socket are not delayed).
    pub tx_event_tx: Option<mpsc::Sender<crate::transaction::Transaction>>,
    pub local_height: Arc<AtomicU64>,
    pub seed_trackers: Arc<Mutex<std::collections::HashMap<SocketAddr, SeedConnTracker>>>,
}

impl P2PService {
    pub fn new(
        chain_id: &str,
        signing_key: SigningKey,
        seeds: Vec<SocketAddr>,
        event_tx: mpsc::Sender<P2PEvent>,
        local_height: Arc<AtomicU64>,
    ) -> (Self, SharedPeerManager) {
        let key_arc = Arc::new(signing_key);
        let peer_manager = Arc::new(Mutex::new(PeerManager::new(
            chain_id,
            Arc::clone(&key_arc),
            seeds,
        )));

        let service = Self {
            chain_id: chain_id.to_string(),
            peer_manager: Arc::clone(&peer_manager),
            signing_key: key_arc,
            event_tx,
            tx_event_tx: None,
            local_height,
            seed_trackers: Arc::new(Mutex::new(std::collections::HashMap::new())),
        };

        (service, peer_manager)
    }

    /// Starts TCP listener on specified port and active connection loop
    pub async fn start(self: Arc<Self>, bind_addr: SocketAddr) -> Result<SocketAddr, String> {
        let listener = TcpListener::bind(bind_addr).await
            .map_err(|e| format!("Failed to bind P2P listener on {}: {}", bind_addr, e))?;
        let local_addr = listener.local_addr()
            .map_err(|e| format!("Failed to get local address of P2P listener: {}", e))?;

        println!("🌐 [P2P Wire] Listener listening for peer-to-peer connections on {}", local_addr);
        self.peer_manager.lock().await.listen_port = local_addr.port();

        // 1. Inbound connection loop
        let svc_inbound = Arc::clone(&self);
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((socket, remote_addr)) => {
                        let svc = Arc::clone(&svc_inbound);
                        tokio::spawn(async move {
                            if let Err(e) = svc.handle_inbound_connection(socket, remote_addr).await {
                                eprintln!("⚠️ [P2P Wire] Connection with {} closed: {}", remote_addr, e);
                            }
                        });
                    }
                    Err(e) => {
                        eprintln!("Error in P2P listener accept: {}", e);
                        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                    }
                }
            }
        });

        // 2. Outbound seed connection loop
        let svc_outbound = Arc::clone(&self);
        tokio::spawn(async move {
            // Seeds every 30 s (unchanged); discovered validators every 10 s so a new
            // validator joins the mesh quickly.
            let mut tick: u64 = 0;
            loop {
                if tick % 3 == 0 {
                    svc_outbound.maintain_seed_connections().await;
                }
                svc_outbound.maintain_discovered_connections().await;
                tick = tick.wrapping_add(1);
                tokio::time::sleep(std::time::Duration::from_secs(10)).await;
            }
        });

        Ok(local_addr)
    }

    /// Handles an incoming TCP connection
    async fn handle_inbound_connection(
        &self,
        mut socket: TcpStream,
        remote_addr: SocketAddr,
    ) -> Result<(), String> {
        let t_conn = std::time::Instant::now();
        // 1. Check admission (banlist and IP limit)
        {
            let mut pm = self.peer_manager.lock().await;
            if let Err(e) = pm.check_admission(&remote_addr) {
                return Err(format!("Inbound admission rejected for {}: {}", remote_addr, e));
            }
        }

        // 2. Await authenticated initial Handshake
        let hs_msg = match tokio::time::timeout(
            std::time::Duration::from_secs(5),
            recv_p2p_message(&mut socket)
        ).await {
            Err(_) => return Err(format!("Handshake timeout with peer {} after {} ms", remote_addr, t_conn.elapsed().as_millis())),
            Ok(Err(e)) => return Err(format!("Handshake read error with peer {} after {} ms: {}", remote_addr, t_conn.elapsed().as_millis(), e)),
            Ok(Ok(msg)) => msg,
        };

        let remote_handshake = match hs_msg {
            P2PPayload::Handshake(hs) => hs,
            other => return Err(format!("First message from {} is not Handshake: received '{}'", remote_addr, other.type_name())),
        };

        // Validate cryptographic signature and chain_id
        remote_handshake.verify(&self.chain_id, 30)
            .map_err(|e| format!("Handshake verification failed from {}: {}", remote_addr, e))?;

        // 3. Respond with HandshakeAck signed with actual local height
        let local_height = self.local_height.load(Ordering::Relaxed);
        let my_ack = HandshakeMsg::new(&self.chain_id, local_height, &self.signing_key);
        send_p2p_message(&mut socket, &P2PPayload::HandshakeAck(my_ack)).await
            .map_err(|e| format!("Failed to send HandshakeAck to {}: {}", remote_addr, e))?;
        // Self-connection: refuse only AFTER the ack, so the dialing side (also us) sees
        // its own key in the ack and stops dialing that address.
        if remote_handshake.node_pubkey == self.signing_key.verifying_key().to_bytes() {
            return Err(format!("Refusing self-connection from {} (our own node key)", remote_addr));
        }

        // 4. Connection established: create channels and register in PeerManager
        self.spawn_peer_worker(socket, remote_addr, remote_handshake.node_pubkey, remote_handshake.height, false, remote_handshake.features).await
    }

    /// Establishes outbound connection to a seed node
    /// Returns Ok(true) if newly connected, Ok(false) if already connected
    pub async fn connect_to_seed(&self, seed_addr: SocketAddr) -> Result<bool, SeedFailure> {
        // 1. Check admission
        {
            let mut pm = self.peer_manager.lock().await;
            if pm.peers.values().any(|p| p.info.addr == seed_addr && !*p.cancel_tx.borrow()) {
                return Ok(false); // Already connected and active
            }
            if pm.self_addrs.contains(&seed_addr) {
                return Ok(false); // this address is ourselves
            }
            if let Err(e) = pm.check_admission(&seed_addr) {
                return Err(SeedFailure::new(SeedFailureType::Admission, format!("Local admission rejected: {}", e)));
            }
        }

        // Print connecting only on first attempt (when no failure tracker exists for this seed)
        let is_first_attempt = {
            let trackers = self.seed_trackers.lock().await;
            !trackers.contains_key(&seed_addr)
        };
        if is_first_attempt {
            println!("🔗 [P2P Wire] Connecting to seed node {}", seed_addr);
        }
        let t_tcp = std::time::Instant::now();
        let mut socket = match tokio::time::timeout(
            std::time::Duration::from_secs(5),
            TcpStream::connect(seed_addr)
        ).await {
            Err(_) => {
                let ms = t_tcp.elapsed().as_millis();
                return Err(SeedFailure::new(
                    SeedFailureType::TcpTimeout,
                    format!("TCP connection timeout after {} ms", ms),
                ));
            }
            Ok(Err(e)) => {
                let ms = t_tcp.elapsed().as_millis();
                return Err(SeedFailure::new(
                    SeedFailureType::TcpRefused,
                    format!("TCP connection refused or failed after {} ms: {}", ms, e),
                ));
            }
            Ok(Ok(s)) => s,
        };

        // 2. Send Handshake with actual local height
        let t_hs = std::time::Instant::now();
        let local_height = self.local_height.load(Ordering::Relaxed);
        let my_hs = HandshakeMsg::new(&self.chain_id, local_height, &self.signing_key);
        if let Err(e) = send_p2p_message(&mut socket, &P2PPayload::Handshake(my_hs)).await {
            let ms = t_hs.elapsed().as_millis();
            return Err(SeedFailure::new(
                SeedFailureType::HsSend,
                format!("Handshake send failed after {} ms: {}", ms, e),
            ));
        }

        // 3. Await HandshakeAck with dedicated timeout
        let t_ack = std::time::Instant::now();
        let ack_msg = match tokio::time::timeout(
            std::time::Duration::from_secs(5),
            recv_p2p_message(&mut socket)
        ).await {
            Err(_) => {
                let ms = t_ack.elapsed().as_millis();
                return Err(SeedFailure::new(
                    SeedFailureType::AckTimeout,
                    format!("HandshakeAck timeout after {} ms", ms),
                ));
            }
            Ok(Err(e)) => {
                let ms = t_ack.elapsed().as_millis();
                if e.contains("early eof") || e.contains("closed") || e.contains("EOF") {
                    return Err(SeedFailure::new(
                        SeedFailureType::AckEof,
                        format!("HandshakeAck read EOF after {} ms (peer closed connection)", ms),
                    ));
                } else {
                    return Err(SeedFailure::new(
                        SeedFailureType::AckReadErr,
                        format!("HandshakeAck read error after {} ms: {}", ms, e),
                    ));
                }
            }
            Ok(Ok(msg)) => msg,
        };

        // 4. Verify message type
        let remote_ack = match ack_msg {
            P2PPayload::HandshakeAck(ack) => ack,
            other => {
                let ms = t_ack.elapsed().as_millis();
                return Err(SeedFailure::new(
                    SeedFailureType::AckUnexpected,
                    format!("Unexpected response after {} ms: received message type '{}' instead of HandshakeAck", ms, other.type_name()),
                ));
            }
        };

        // 5. Verify cryptographic signature, chain_id, and clock skew
        remote_ack.verify(&self.chain_id, 30)
            .map_err(|e| SeedFailure::new(
                SeedFailureType::AckRejected,
                format!("HandshakeAck verification rejected: {}", e),
            ))?;

        if remote_ack.node_pubkey == self.signing_key.verifying_key().to_bytes() {
            // Our own IP is in the seed list: remember it and stop dialing it.
            println!("ℹ️ [P2P Wire] Seed {} is this node itself; it will not be dialed again", seed_addr);
            self.peer_manager.lock().await.self_addrs.insert(seed_addr);
            return Ok(false);
        }

        println!("✅ [P2P Wire] Authenticated connection established with seed {}", seed_addr);

        self.spawn_peer_worker(socket, seed_addr, remote_ack.node_pubkey, remote_ack.height, true, remote_ack.features).await
            .map_err(|e| SeedFailure::new(SeedFailureType::Admission, format!("Failed to spawn peer worker: {}", e)))?;
        Ok(true)
    }

    /// Spawns async read/write worker for connected peer with synchronized cancellation and socket cleanup
    async fn spawn_peer_worker(
        &self,
        socket: TcpStream,
        remote_addr: SocketAddr,
        node_pubkey: [u8; 32],
        height: u64,
        is_outbound: bool,
        features: u32,
    ) -> Result<(), String> {
        let (mut reader, mut writer) = socket.into_split();
        let (outgoing_tx, mut outgoing_rx) = mpsc::channel::<P2PPayload>(128);
        let (prio_tx, mut prio_rx) = mpsc::channel::<P2PPayload>(PRIORITY_QUEUE_LEN);
        let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
        let conn_id = NEXT_CONN_ID.fetch_add(1, Ordering::Relaxed);

        let connected_at = std::time::Instant::now();
        let last_sent = Arc::new(std::sync::Mutex::new(if is_outbound { Some("Handshake") } else { Some("HandshakeAck") }));
        let last_received = Arc::new(std::sync::Mutex::new(if is_outbound { Some("HandshakeAck") } else { Some("Handshake") }));
        let disconnect_logged = Arc::new(std::sync::atomic::AtomicBool::new(false));

        // Register in PeerManager
        {
            let mut pm = self.peer_manager.lock().await;
            pm.add_peer(remote_addr, node_pubkey, height, is_outbound, outgoing_tx.clone(), cancel_tx.clone(), conn_id);
            pm.set_features(&remote_addr, features);
            pm.set_priority_channel(&remote_addr, prio_tx);
            if features & FEATURE_PEER_DISCOVERY != 0 {
                // Tell the peer which IP we see it on, and hand it every validator we know.
                let _ = outgoing_tx.try_send(P2PPayload::AddrHint { ip: remote_addr.ip().to_string() });
                for d in pm.fresh_discovered() {
                    let _ = outgoing_tx.try_send(P2PPayload::PeerAnnounce(d.announce.clone()));
                }
            }
        }

        let _ = self.event_tx.send(P2PEvent::PeerConnected { addr: remote_addr, height }).await;

        let cancel_tx_keepalive = cancel_tx.clone();
        let keepalive_tx = outgoing_tx.clone();
        let mut cancel_rx_keepalive = cancel_rx.clone();

        // Task 0: Keepalive — send Ping every 5s with cancellation support
        tokio::spawn(async move {
            let mut nonce: u64 = 0;
            loop {
                tokio::select! {
                    _ = cancel_rx_keepalive.changed() => {
                        break;
                    }
                    _ = tokio::time::sleep(std::time::Duration::from_secs(5)) => {
                        nonce = nonce.wrapping_add(1);
                        if keepalive_tx.send(P2PPayload::Ping { nonce }).await.is_err() {
                            let _ = cancel_tx_keepalive.send(true);
                            break;
                        }
                    }
                }
            }
        });

        let cancel_tx_write = cancel_tx.clone();
        let mut cancel_rx_write = cancel_rx.clone();
        let pm_ref_write = Arc::clone(&self.peer_manager);
        let last_sent_write = Arc::clone(&last_sent);
        let last_received_write = Arc::clone(&last_received);
        let connected_at_write = connected_at;
        let disconnect_logged_write = Arc::clone(&disconnect_logged);

        // Task 1: Write messages from queue to TCP socket with timeout and cancellation
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    _ = cancel_rx_write.changed() => {
                        break;
                    }
                    // Consensus first; the channel never closes while this task runs
                    // (the PeerManager holds its sender), so None is not reachable here.
                    Some(msg) = prio_rx.recv() => {
                        let msg = match msg.adapt_for(features) {
                            Some(m) => m,
                            None => continue,
                        };
                        if let Ok(mut guard) = last_sent_write.lock() {
                            *guard = Some(msg.type_name());
                        }
                        if let Err(e) = send_p2p_message(&mut writer, &msg).await {
                            if !disconnect_logged_write.swap(true, Ordering::Relaxed) {
                                eprintln!("🔌 [P2P Wire] Peer {} write error after {:.2}s: {}",
                                    remote_addr, connected_at_write.elapsed().as_secs_f64(), e);
                            }
                            let _ = cancel_tx_write.send(true);
                            break;
                        }
                    }
                    msg = outgoing_rx.recv() => {
                        match msg.map(|m| m.adapt_for(features)) {
                            Some(None) => continue,
                            Some(Some(msg)) => {
                                if let Ok(mut guard) = last_sent_write.lock() {
                                    *guard = Some(msg.type_name());
                                }
                                if let Err(e) = send_p2p_message(&mut writer, &msg).await {
                                    if !disconnect_logged_write.swap(true, Ordering::Relaxed) {
                                        let dur = connected_at_write.elapsed();
                                        let ls = last_sent_write.lock().ok().and_then(|g| *g).unwrap_or("None");
                                        let lr = last_received_write.lock().ok().and_then(|g| *g).unwrap_or("None");
                                        eprintln!("🔌 [P2P Wire] Peer {} write error after {:.2}s: {} (last sent: {}, last received: {})",
                                            remote_addr, dur.as_secs_f64(), e, ls, lr);
                                    }
                                    let _ = cancel_tx_write.send(true);
                                    break;
                                }
                            }
                            None => {
                                let _ = cancel_tx_write.send(true);
                                break;
                            }
                        }
                    }
                }
            }

            // Explicit TCP socket shutdown & close
            use tokio::io::AsyncWriteExt;
            let _ = writer.shutdown().await;
            drop(writer);

            let mut pm = pm_ref_write.lock().await;
            pm.remove_peer_conn(&remote_addr, conn_id);
        });

        let cancel_tx_read = cancel_tx.clone();
        let mut cancel_rx_read = cancel_rx.clone();
        let pm_ref_read = Arc::clone(&self.peer_manager);
        let event_tx_clone = self.event_tx.clone();
        let tx_event_tx = self.tx_event_tx.clone();
        let local_height_clone = Arc::clone(&self.local_height);
        let pong_tx = outgoing_tx.clone();
        let last_sent_read = Arc::clone(&last_sent);
        let last_received_read = Arc::clone(&last_received);
        let connected_at_read = connected_at;
        let disconnect_logged_read = Arc::clone(&disconnect_logged);
        let chain_id_read = self.chain_id.clone();

        // Task 2: Read messages from TCP socket with timeout, cancellation, and zero lock-holding during await
        tokio::spawn(async move {
            // One AddrHint per connection: a single peer must not be able to outvote others.
            let mut addr_hint_taken = false;
            loop {
                tokio::select! {
                    _ = cancel_rx_read.changed() => {
                        if !disconnect_logged_read.swap(true, Ordering::Relaxed) {
                            let dur = connected_at_read.elapsed();
                            let ls = last_sent_read.lock().ok().and_then(|g| *g).unwrap_or("None");
                            let lr = last_received_read.lock().ok().and_then(|g| *g).unwrap_or("None");
                            println!("🔌 [P2P Wire] Peer {} connection closed after {:.2}s (last sent: {}, last received: {})",
                                remote_addr, dur.as_secs_f64(), ls, lr);
                        }
                        break;
                    }
                    res = recv_p2p_message(&mut reader) => {
                        match res {
                            Ok(payload) => {
                                if let Ok(mut guard) = last_received_read.lock() {
                                    *guard = Some(payload.type_name());
                                }
                                let (maybe_event, maybe_pong) = {
                                    let mut pm = pm_ref_read.lock().await;
                                    pm.touch_peer(&remote_addr, None);

                                    match payload {
                                        P2PPayload::Ping { nonce } => {
                                            let current_h = local_height_clone.load(Ordering::Relaxed);
                                            let pong = P2PPayload::Pong { nonce, height: current_h };
                                            (None, Some(pong))
                                        }
                                        P2PPayload::Pong { height, .. } => {
                                            pm.touch_peer(&remote_addr, Some(height));
                                            (None, None)
                                        }
                                        P2PPayload::NewTransaction(tx) => {
                                            let hash = tx.tx_hash();
                                            if pm.seen_hashes.contains(&hash) {
                                                (None, None)
                                            } else if let Some(ch) = &tx_event_tx {
                                                // Full = the node is behind on admissions: drop
                                                // this copy instead of stalling the socket. It is
                                                // not marked seen, so a later re-gossip gets in.
                                                if ch.try_send(tx).is_ok() {
                                                    pm.mark_seen(hash);
                                                }
                                                (None, None)
                                            } else if !pm.mark_seen(hash) {
                                                (None, None)
                                            } else {
                                                (Some(P2PEvent::NewTransaction(tx)), None)
                                            }
                                        }
                                        P2PPayload::BlockProposal(block) => {
                                            let hash = block.hash();
                                            if pm.mark_seen(hash) {
                                                (Some(P2PEvent::BlockProposal(block)), None)
                                            } else {
                                                (None, None)
                                            }
                                        }
                                        P2PPayload::BftVote(vote) => {
                                            (Some(P2PEvent::BftVote(vote)), None)
                                        }
                                        P2PPayload::MiniVote(mvote) => {
                                            (Some(P2PEvent::MiniValidatorVote(mvote)), None)
                                        }
                                        P2PPayload::BlockCommit(block) => {
                                            let hash = block.hash();
                                            if pm.mark_seen(hash) {
                                                (Some(P2PEvent::BlockCommit(block)), None)
                                            } else {
                                                (None, None)
                                            }
                                        }
                                        P2PPayload::SyncRequest(req) => {
                                            (Some(P2PEvent::SyncRequest { peer_addr: remote_addr, req }), None)
                                        }
                                        P2PPayload::SyncResponse(res) => {
                                            (Some(P2PEvent::SyncResponse { peer_addr: remote_addr, res }), None)
                                        }
                                        // Tendermint messages: dedupe by signature here; the node
                                        // verifies them and relays the ones it accepts.
                                        P2PPayload::TmProposal(proposal) => {
                                            let mut sig_id = [0u8; 32];
                                            sig_id.copy_from_slice(&proposal.signature[..32]);
                                            if pm.mark_seen(sig_id) {
                                                (Some(P2PEvent::TmProposal { peer_addr: remote_addr, proposal }), None)
                                            } else {
                                                (None, None)
                                            }
                                        }
                                        P2PPayload::TmVote(vote) => {
                                            let mut sig_id = [0u8; 32];
                                            sig_id.copy_from_slice(&vote.signature[..32]);
                                            if pm.mark_seen(sig_id) {
                                                (Some(P2PEvent::TmVote { peer_addr: remote_addr, vote }), None)
                                            } else {
                                                (None, None)
                                            }
                                        }
                                        P2PPayload::TmCompactProposal(compact) => {
                                            let mut sig_id = [0u8; 32];
                                            sig_id.copy_from_slice(&compact.proposal.signature[..32]);
                                            if pm.mark_seen(sig_id) {
                                                (Some(P2PEvent::TmCompactProposal { peer_addr: remote_addr, compact }), None)
                                            } else {
                                                (None, None)
                                            }
                                        }
                                        P2PPayload::TmProposalRequest { height, round, missing } => {
                                            (Some(P2PEvent::TmProposalRequest { peer_addr: remote_addr, height, round, missing }), None)
                                        }
                                        P2PPayload::TmProposalTxs { height, round, txs } => {
                                            (Some(P2PEvent::TmProposalTxs { peer_addr: remote_addr, height, round, txs }), None)
                                        }
                                        // Requested by us: delivered even though the compact form
                                        // of the same proposal was already seen.
                                        P2PPayload::TmProposalFull(proposal) => {
                                            (Some(P2PEvent::TmProposal { peer_addr: remote_addr, proposal }), None)
                                        }
                                        P2PPayload::AddrHint { ip } => {
                                            if !addr_hint_taken {
                                                addr_hint_taken = true;
                                                if let Ok(ip) = ip.parse::<std::net::IpAddr>() {
                                                    if pm.observed_ips.len() < 16 || pm.observed_ips.contains_key(&ip) {
                                                        *pm.observed_ips.entry(ip).or_insert(0) += 1;
                                                    }
                                                }
                                            }
                                            (None, None)
                                        }
                                        P2PPayload::PeerAnnounce(announce) => {
                                            // Cheap checks here; the node checks validator-set membership.
                                            let now = std::time::SystemTime::now()
                                                .duration_since(std::time::UNIX_EPOCH)
                                                .map(|d| d.as_secs())
                                                .unwrap_or(0);
                                            let mut sig_id = [0u8; 32];
                                            sig_id.copy_from_slice(&announce.signature[..32]);
                                            if announce.verify(&chain_id_read, now).is_ok() && pm.mark_seen(sig_id) {
                                                (Some(P2PEvent::PeerAnnounce { peer_addr: remote_addr, announce }), None)
                                            } else {
                                                (None, None)
                                            }
                                        }
                                        _ => (None, None),
                                    }
                                }; // pm lock dropped immediately here!

                                if let Some(pong) = maybe_pong {
                                    let _ = pong_tx.try_send(pong);
                                }

                                if let Some(evt) = maybe_event {
                                    let _ = event_tx_clone.send(evt).await;
                                }
                            }
                            Err(e) => {
                                if !disconnect_logged_read.swap(true, Ordering::Relaxed) {
                                    let dur = connected_at_read.elapsed();
                                    let ls = last_sent_read.lock().ok().and_then(|g| *g).unwrap_or("None");
                                    let lr = last_received_read.lock().ok().and_then(|g| *g).unwrap_or("None");
                                    eprintln!("🔌 [P2P Wire] Peer {} disconnected after {:.2}s: {} (last sent: {}, last received: {})",
                                        remote_addr, dur.as_secs_f64(), e, ls, lr);
                                }
                                let _ = cancel_tx_read.send(true);
                                break;
                            }
                        }
                    }
                }
            }

            // Signal writer and keepalive to terminate
            let _ = cancel_tx_read.send(true);
            drop(reader);

            let was_removed = {
                let mut pm = pm_ref_read.lock().await;
                pm.remove_peer_conn(&remote_addr, conn_id)
            };
            if was_removed {
                let _ = event_tx_clone.send(P2PEvent::PeerDisconnected { addr: remote_addr }).await;
            }
        });

        Ok(())
    }

    /// Dials validators learned through PeerAnnounce that we are not connected to yet.
    pub async fn maintain_discovered_connections(&self) {
        let my_pubkey = self.signing_key.verifying_key().to_bytes();
        let targets = self.peer_manager.lock().await.discovery_dial_targets(&my_pubkey);
        for addr in targets {
            match self.connect_to_seed(addr).await {
                Ok(true) => println!("🧭 [P2P Discovery] Connected to discovered validator at {}", addr),
                Ok(false) => {}
                Err(e) => {
                    let mut trackers = self.seed_trackers.lock().await;
                    let tracker = trackers.entry(addr).or_insert_with(|| SeedConnTracker {
                        attempts: 0,
                        first_failed_at: std::time::Instant::now(),
                        last_failure_type: None,
                        last_reason: String::new(),
                    });
                    tracker.attempts += 1;
                    if should_log(tracker.attempts, tracker.last_failure_type, e.kind) {
                        eprintln!("⚠️ [P2P Discovery] Dial to discovered validator {} failed: {} (attempt {})", addr, e.message, tracker.attempts);
                        tracker.last_failure_type = Some(e.kind);
                    }
                }
            }
        }
    }

    /// Attempts to maintain active connections with known seed nodes
    pub async fn maintain_seed_connections(&self) {
        let seeds = {
            let pm = self.peer_manager.lock().await;
            pm.seed_nodes.clone()
        };

        for seed in seeds {
            match self.connect_to_seed(seed).await {
                Ok(true) => {
                    let mut trackers = self.seed_trackers.lock().await;
                    if let Some(tracker) = trackers.remove(&seed) {
                        let elapsed = tracker.first_failed_at.elapsed().as_secs();
                        println!("✅ [P2P Wire] Seed {} reconnected after {} attempts ({} s)", seed, tracker.attempts, elapsed);
                    }
                }
                Ok(false) => {
                    let mut trackers = self.seed_trackers.lock().await;
                    if let Some(tracker) = trackers.remove(&seed) {
                        let elapsed = tracker.first_failed_at.elapsed().as_secs();
                        println!("✅ [P2P Wire] Seed {} reconnected after {} attempts ({} s)", seed, tracker.attempts, elapsed);
                    }
                }
                Err(failure) => {
                    let mut trackers = self.seed_trackers.lock().await;
                    let tracker = trackers.entry(seed).or_insert_with(|| SeedConnTracker {
                        attempts: 0,
                        first_failed_at: std::time::Instant::now(),
                        last_failure_type: None,
                        last_reason: String::new(),
                    });
                    tracker.attempts += 1;
                    let elapsed = tracker.first_failed_at.elapsed().as_secs();

                    if should_log(tracker.attempts, tracker.last_failure_type, failure.kind) {
                        if tracker.attempts == 1 {
                            eprintln!("⚠️ [P2P Wire] Seed {} connection failed: {}", seed, failure.message);
                        } else {
                            eprintln!("⚠️ [P2P Wire] Seed {} connection failed: {} (attempt {}, failing for {} s)", seed, failure.message, tracker.attempts, elapsed);
                        }
                        tracker.last_failure_type = Some(failure.kind);
                        tracker.last_reason = failure.message.clone();
                    }
                }
            }
        }
    }
}
