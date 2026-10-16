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
    PeerDisconnected { addr: SocketAddr },
}

pub struct P2PService {
    pub chain_id: String,
    pub peer_manager: SharedPeerManager,
    pub signing_key: Arc<SigningKey>,
    pub event_tx: mpsc::Sender<P2PEvent>,
    pub local_height: Arc<AtomicU64>,
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
            local_height,
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
            loop {
                svc_outbound.maintain_seed_connections().await;
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
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
        // 1. Check admission (banlist and IP limit)
        {
            let mut pm = self.peer_manager.lock().await;
            pm.check_admission(&remote_addr)?;
        }

        // 2. Await authenticated initial Handshake
        let hs_msg = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            recv_p2p_message(&mut socket)
        ).await
        .map_err(|_| "Handshake timeout with peer".to_string())??;

        let remote_handshake = match hs_msg {
            P2PPayload::Handshake(hs) => hs,
            _ => return Err("First message received is not a valid Handshake".to_string()),
        };

        // Validate cryptographic signature and chain_id
        remote_handshake.verify(&self.chain_id, 30)?;

        // 3. Respond with HandshakeAck signed with actual local height
        let local_height = self.local_height.load(Ordering::Relaxed);
        let my_ack = HandshakeMsg::new(&self.chain_id, local_height, &self.signing_key);
        send_p2p_message(&mut socket, &P2PPayload::HandshakeAck(my_ack)).await?;

        // 4. Connection established: create channels and register in PeerManager
        self.spawn_peer_worker(socket, remote_addr, remote_handshake.node_pubkey, remote_handshake.height, false).await
    }

    /// Establishes outbound connection to a seed node
    pub async fn connect_to_seed(&self, seed_addr: SocketAddr) -> Result<(), String> {
        // Check admission
        {
            let mut pm = self.peer_manager.lock().await;
            if pm.peers.values().any(|p| p.info.addr == seed_addr && !*p.cancel_tx.borrow()) {
                return Ok(()); // Already connected and active
            }
            pm.check_admission(&seed_addr)?;
        }

        println!("🔗 [P2P Wire] Connecting to seed node {}", seed_addr);
        let mut socket = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            TcpStream::connect(seed_addr)
        ).await
        .map_err(|_| "Connection timeout with seed node".to_string())?
        .map_err(|e| format!("TCP connection failed: {}", e))?;

        // Send Handshake with actual local height
        let local_height = self.local_height.load(Ordering::Relaxed);
        let my_hs = HandshakeMsg::new(&self.chain_id, local_height, &self.signing_key);
        send_p2p_message(&mut socket, &P2PPayload::Handshake(my_hs)).await?;

        // Await HandshakeAck
        let ack_msg = recv_p2p_message(&mut socket).await?;
        let remote_ack = match ack_msg {
            P2PPayload::HandshakeAck(ack) => ack,
            _ => return Err("Seed connection response is not HandshakeAck".to_string()),
        };

        remote_ack.verify(&self.chain_id, 30)?;

        println!("✅ [P2P Wire] Authenticated connection established with seed {}", seed_addr);

        self.spawn_peer_worker(socket, seed_addr, remote_ack.node_pubkey, remote_ack.height, true).await
    }

    /// Spawns async read/write worker for connected peer with synchronized cancellation and socket cleanup
    async fn spawn_peer_worker(
        &self,
        socket: TcpStream,
        remote_addr: SocketAddr,
        node_pubkey: [u8; 32],
        height: u64,
        is_outbound: bool,
    ) -> Result<(), String> {
        let (mut reader, mut writer) = socket.into_split();
        let (outgoing_tx, mut outgoing_rx) = mpsc::channel::<P2PPayload>(128);
        let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
        let conn_id = NEXT_CONN_ID.fetch_add(1, Ordering::Relaxed);

        // Register in PeerManager
        {
            let mut pm = self.peer_manager.lock().await;
            pm.add_peer(remote_addr, node_pubkey, height, is_outbound, outgoing_tx.clone(), cancel_tx.clone(), conn_id);
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

        // Task 1: Write messages from queue to TCP socket with timeout and cancellation
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = cancel_rx_write.changed() => {
                        break;
                    }
                    msg = outgoing_rx.recv() => {
                        match msg {
                            Some(msg) => {
                                if let Err(e) = send_p2p_message(&mut writer, &msg).await {
                                    eprintln!("Error sending message to peer {}: {}", remote_addr, e);
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
        let local_height_clone = Arc::clone(&self.local_height);
        let pong_tx = outgoing_tx.clone();

        // Task 2: Read messages from TCP socket with timeout, cancellation, and zero lock-holding during await
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = cancel_rx_read.changed() => {
                        break;
                    }
                    res = recv_p2p_message(&mut reader) => {
                        match res {
                            Ok(payload) => {
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
                                            if pm.mark_seen(hash) {
                                                (Some(P2PEvent::NewTransaction(tx)), None)
                                            } else {
                                                (None, None)
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
                                eprintln!("P2P read closed with {}: {}", remote_addr, e);
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

    /// Attempts to maintain active connections with known seed nodes
    async fn maintain_seed_connections(&self) {
        let seeds = {
            let pm = self.peer_manager.lock().await;
            pm.seed_nodes.clone()
        };

        for seed in seeds {
            let _ = self.connect_to_seed(seed).await;
        }
    }
}
