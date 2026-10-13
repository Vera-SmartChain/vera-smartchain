use std::env;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::net::TcpListener;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;
use ed25519_dalek::SigningKey;

use vera_blockchain::genesis::GenesisConfig;
use vera_blockchain::node::{FullNode, SharedNode};
use vera_blockchain::p2p::{P2PEvent, P2PPayload, P2PService, SyncRequest, SyncResponse};
use vera_blockchain::rpc::{RpcError, RpcHandler, RpcRequest, RpcResponse};

/// Attempts to commit pending block for next height when collected votes
/// reach BFT supermajority (2/3 + 1 stake). Applies locally and broadcasts.
async fn try_commit_pending(
    node: &SharedNode,
    pm: &vera_blockchain::p2p::SharedPeerManager,
    local_height: &Arc<AtomicU64>,
    pending: &mut std::collections::HashMap<u64, (vera_blockchain::block::Block, Vec<vera_blockchain::block::ValidatorCommit>, std::time::Instant)>,
    height: u64,
) {
    let (block, commits) = match pending.get(&height) {
        Some(e) => (e.0.clone(), e.1.clone()),
        None => return,
    };
    let mut n = node.lock().await;
    if height <= n.height {
        pending.remove(&height);
        return;
    }
    if height != n.height + 1 {
        return;
    }
    let bhash = block.hash();
    let ok = n.validator_set
        .check_commit_supermajority(&n.chain_id, height, 0, &bhash, &commits)
        .unwrap_or(false);
    if !ok {
        return; // supermajority not yet reached — wait for more votes
    }
    let mut final_block = block;
    final_block.validator_signatures = commits;
    match n.apply_block(final_block.clone()).await {
        Ok(h) => {
            println!("✅ [BFT] Block #{} COMMITTED with 2/3 + 1 stake! Hash: 0x{} ({} txs)",
                height, hex::encode(h), final_block.transactions.len());
            let committed: std::collections::HashSet<[u8; 32]> =
                final_block.transactions.iter().map(|t| t.tx_hash()).collect();
            n.mempool.retain(|t| !committed.contains(&t.tx_hash()));
            drop(n);
            local_height.store(height, Ordering::Relaxed);
            {
                let mut p = pm.lock().await;
                p.broadcast(P2PPayload::BlockCommit(final_block), None).await;
            }
            pending.remove(&height);
        }
        Err(e) => {
            eprintln!("⚠️ [BFT] Failed to commit block #{}: {}", height, e);
        }
    }
}

/// Proposes a block if this node is the deterministic proposer for the next height,
/// there are txs in mempool, and no in-flight proposal exists for this height (anti-churn).
/// Event-driven: called on fast tick -> proposes ~immediately upon tx arrival.
async fn try_propose(
    node: &SharedNode,
    pm: &vera_blockchain::p2p::SharedPeerManager,
    local_height: &Arc<AtomicU64>,
    pending: &mut std::collections::HashMap<u64, (vera_blockchain::block::Block, Vec<vera_blockchain::block::ValidatorCommit>, std::time::Instant)>,
    mempool_since: &mut std::collections::HashMap<u64, std::time::Instant>,
) {
    let proposal = {
        let mut n = node.lock().await;
        let h = n.height + 1;
        if pending.get(&h).map_or(false, |e| e.2.elapsed() < std::time::Duration::from_millis(2000)) {
            None  // recent in-flight proposal for this height (anti-churn); re-proposes if expired
        } else {
            if n.mempool.is_empty() {
                mempool_since.remove(&h);
                None
            } else {
                let first_seen = mempool_since.entry(h).or_insert_with(std::time::Instant::now);
                let round = (first_seen.elapsed().as_millis() / 2000) as u64; // advances every 2s if proposer is missing
                let is_proposer = n.keypair.is_some()
                    && n.validator_set.get_proposer(h, round).map(|p| p.address == n.address).unwrap_or(false);
                if is_proposer {
                    match n.build_proposal().await {
                        Ok(b) => Some(b),
                        Err(e) => { eprintln!("Error building proposal: {}", e); None }
                    }
                } else {
                    None
                }
            }
        }
    };
    if let Some(b) = proposal {
        let h = b.header.height;
        pending.insert(h, (b.clone(), b.validator_signatures.clone(), std::time::Instant::now()));
        println!("📤 [BFT] Proposing block #{} ({} txs)", h, b.transactions.len());
        {
            let mut p = pm.lock().await;
            p.broadcast(P2PPayload::BlockProposal(b), None).await;
        }
        try_commit_pending(node, pm, local_height, pending, h).await;
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!("VERA SmartChain Node v1.0.0 (BFT-PoS & EVM compatible)");
        println!("Usage: vera_node [OPTIONS]");
        println!();
        println!("Options:");
        println!("  --help, -h               Print this help overview and exit");
        println!("  --version, -v            Print binary version and exit");
        println!("  --data-dir <DIR>         Database storage directory (default: ./data/vera_node_default)");
        println!("  --genesis <FILE>         Path to genesis JSON file (default: testnet-genesis.json)");
        println!("  --rpc-port <PORT>        JSON-RPC HTTP server port (default: 8545)");
        println!("  --bind <IP>              IP address to bind RPC server (default: 127.0.0.1)");
        println!("  --p2p-port <PORT>        TCP port for P2P wire protocol (default: 26656)");
        println!("  --p2p-bind <IP>          IP address to bind P2P wire (default: 0.0.0.0)");
        println!("  --seed-peers <IP:PORT>   Comma-separated list of seed peers for P2P sync");
        println!("  --validator              Enable validator mode to participate in BFT consensus and propose blocks");
        println!("  --key-file <FILE>        Path to 32-byte hex private key file for validator");
        println!("  --key <HEX>              Validator hex private key via command line");
        return Ok(());
    }

    if args.iter().any(|a| a == "--version" || a == "-v") {
        println!("vera_node 1.0.0 (commit testnet-1, target x86_64-unknown-linux-gnu)");
        return Ok(());
    }

    let mut data_dir = "./data/vera_node_default".to_string();
    let mut genesis_path = "testnet-genesis.json".to_string();
    let mut port = 8545u16;
    let mut is_validator = false;
    let mut key_hex: Option<String> = None;
    let mut key_file: Option<String> = None;

    let mut bind_host = "127.0.0.1".to_string();
    let mut p2p_bind = "0.0.0.0".to_string();
    let mut p2p_port = 26656u16;
    let mut seed_peers_str = String::new();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--data-dir" if i + 1 < args.len() => {
                data_dir = args[i + 1].clone();
                i += 2;
            }
            "--genesis" if i + 1 < args.len() => {
                genesis_path = args[i + 1].clone();
                i += 2;
            }
            "--bind" if i + 1 < args.len() => {
                bind_host = args[i + 1].clone();
                i += 2;
            }
            "--port" | "--rpc-port" if i + 1 < args.len() => {
                port = args[i + 1].parse().unwrap_or(8545);
                i += 2;
            }
            "--p2p-bind" if i + 1 < args.len() => {
                p2p_bind = args[i + 1].clone();
                i += 2;
            }
            "--p2p-port" if i + 1 < args.len() => {
                p2p_port = args[i + 1].parse().unwrap_or(26656);
                i += 2;
            }
            "--peers" | "--seed-peers" if i + 1 < args.len() => {
                seed_peers_str = args[i + 1].clone();
                i += 2;
            }
            "--validator" => {
                is_validator = true;
                i += 1;
            }
            "--key" if i + 1 < args.len() => {
                key_hex = Some(args[i + 1].clone());
                i += 2;
            }
            "--key-file" if i + 1 < args.len() => {
                key_file = Some(args[i + 1].clone());
                i += 2;
            }
            _ => {
                i += 1;
            }
        }
    }

    println!("=======================================================");
    println!("             VERA CHAIN FULL NODE v1.0.0               ");
    println!("=======================================================");
    println!("Data Directory: {}", data_dir);
    println!("Genesis Config: {}", genesis_path);
    println!("RPC Bind:       http://{}:{}", bind_host, port);
    println!("P2P Wire Bind:  tcp://{}:{}", p2p_bind, p2p_port);

    let genesis = GenesisConfig::load_from_file(&genesis_path)?;

    let signing_key = if is_validator {
        if let Some(kf) = key_file {
            let content = std::fs::read_to_string(&kf)
                .map_err(|e| format!("Error reading key-file '{}': {}", kf, e))?;
            let trimmed = content.trim().trim_start_matches("0x");
            let bytes = hex::decode(trimmed)
                .map_err(|e| format!("Invalid hex format in key-file: {}", e))?;
            if bytes.len() != 32 {
                return Err(format!("Key must be 32 bytes (64 hex characters), found {} bytes", bytes.len()).into());
            }
            let mut key_bytes = [0u8; 32];
            key_bytes.copy_from_slice(&bytes);
            println!("[OK] Validator key securely loaded from: {}", kf);
            Some(SigningKey::from_bytes(&key_bytes))
        } else if let Some(kh) = key_hex {
            let trimmed = kh.trim().trim_start_matches("0x");
            let bytes = hex::decode(trimmed)?;
            let mut key_bytes = [0u8; 32];
            key_bytes.copy_from_slice(&bytes);
            Some(SigningKey::from_bytes(&key_bytes))
        } else {
            // Generate temporary validation key
            use rand::rngs::OsRng;
            let mut csprng = OsRng;
            Some(SigningKey::generate(&mut csprng))
        }
    } else {
        None
    };

    let node = FullNode::load_or_init(&data_dir, &genesis, signing_key)?;
    println!("Node initialized successfully!");
    println!("Height:     {}", node.height);
    println!("State Root: 0x{}", hex::encode(node.csmt.root()));
    println!("Node Addr:  0x{}", hex::encode(node.address));
    println!("-------------------------------------------------------");

    let p2p_key = match &node.keypair {
        Some(k) => SigningKey::from_bytes(&k.to_bytes()),
        None => {
            use rand::rngs::OsRng;
            SigningKey::generate(&mut OsRng)
        }
    };

    let local_height = Arc::new(AtomicU64::new(node.height));
    let shared_node: SharedNode = Arc::new(Mutex::new(node));

    // P2P Wire Network Initialization
    let mut seed_addrs = Vec::new();
    for s in seed_peers_str.split(',') {
        let trimmed = s.trim();
        if !trimmed.is_empty() {
            if let Ok(addr) = trimmed.parse::<std::net::SocketAddr>() {
                seed_addrs.push(addr);
            } else {
                eprintln!("⚠️ [P2P] Invalid seed address ignored: {}", trimmed);
            }
        }
    }

    let (p2p_event_tx, mut p2p_event_rx) = tokio::sync::mpsc::channel(256);
    let (p2p_service, peer_manager) = P2PService::new(
        &genesis.chain_id,
        p2p_key,
        seed_addrs,
        p2p_event_tx,
        Arc::clone(&local_height),
    );
    let p2p_service = Arc::new(p2p_service);
    let p2p_addr: std::net::SocketAddr = format!("{}:{}", p2p_bind, p2p_port).parse()?;

    let p2p_srv_clone = Arc::clone(&p2p_service);
    tokio::spawn(async move {
        if let Err(e) = p2p_srv_clone.start(p2p_addr).await {
            eprintln!("❌ [P2P Wire] Fatal error in P2P listener on {}: {}", p2p_addr, e);
        }
    });

    // P2P network event dispatch task
    let event_node = Arc::clone(&shared_node);
    let event_pm = Arc::clone(&peer_manager);
    let event_lh = Arc::clone(&local_height);
    tokio::spawn(async move {
        // Consensus state in progress: height -> (proposed block, collected commits)
        let mut pending: std::collections::HashMap<u64, (vera_blockchain::block::Block, Vec<vera_blockchain::block::ValidatorCommit>, std::time::Instant)> = std::collections::HashMap::new();
        let mut mempool_since: std::collections::HashMap<u64, std::time::Instant> = std::collections::HashMap::new();
        let mut tick = tokio::time::interval(tokio::time::Duration::from_millis(50));
        let mut sync_tick_counter: u64 = 0;
        loop {
            let event = tokio::select! {
                maybe = p2p_event_rx.recv() => match maybe { Some(e) => e, None => break },
                _ = tick.tick() => {
                    try_propose(&event_node, &event_pm, &event_lh, &mut pending, &mut mempool_since).await;
                    sync_tick_counter = sync_tick_counter.wrapping_add(1);
                    // Every 20 ticks (1s), check if there is height divergence with peers
                    if sync_tick_counter % 20 == 0 {
                        let cur_h = event_lh.load(Ordering::Relaxed);
                        let mut pm = event_pm.lock().await;
                        event_node.lock().await.peer_count = pm.peers.len();
                        let highest = pm.highest_peer_height();
                        if highest > cur_h {
                            println!("🔄 [Sync Watchdog] Local node at height #{} detected peer at height #{}. Requesting sync...", cur_h, highest);
                            let req = SyncRequest::new(cur_h + 1, 50);
                            pm.broadcast(P2PPayload::SyncRequest(req), None).await;
                        }
                    }
                    continue;
                }
            };
            match event {
                P2PEvent::NewTransaction(tx) => {
                    let mut n = event_node.lock().await;
                    if let Ok(_) = n.submit_transaction(tx.clone()) {
                        let mut pm = event_pm.lock().await;
                        pm.broadcast(P2PPayload::NewTransaction(tx), None).await;
                    }
                }
                P2PEvent::BlockProposal(block) => {
                    let height = block.header.height;
                    let bhash = block.hash();
                    // Validate context (height/prev/deterministic proposer) and prepare vote
                    let (accept, my_vote) = {
                        let n = event_node.lock().await;
                        if height != n.height + 1 || block.header.prev_hash != n.latest_block_hash {
                            (false, None)
                        } else {
                            let proposer_ok = (0..=10u64).any(|r| {
                                n.validator_set.get_proposer(height, r)
                                    .map(|p| p.address == block.header.proposer)
                                    .unwrap_or(false)
                            });
                            if !proposer_ok {
                                (false, None)
                            } else {
                                // Phase 3: validate state transition BEFORE voting (never blind sign)
                                match n.validate_proposal(&block).await {
                                    Ok(()) => {
                                        let mv = n.keypair.as_ref().map(|k| vera_blockchain::consensus::Vote::new(
                                            &n.chain_id, height, 0, bhash,
                                            vera_blockchain::consensus::VoteType::PreCommit, k));
                                        (true, mv)
                                    }
                                    Err(e) => {
                                        eprintln!("🚫 [BFT] Proposal #{} rejected (invalid state): {}", height, e);
                                        (false, None)
                                    }
                                }
                            }
                        }
                    };
                    if accept {
                        println!("📦 [BFT] Proposal #{} accepted (0x{})", height, hex::encode(bhash));
                        let entry = pending.entry(height).or_insert_with(|| (block.clone(), Vec::new(), std::time::Instant::now()));
                        entry.0 = block.clone();
                        // Commits already included in block (from proposer)
                        for c in &block.validator_signatures {
                            if !entry.1.iter().any(|x| x.validator_pubkey == c.validator_pubkey) {
                                entry.1.push(c.clone());
                            }
                        }
                        // Forward accepted proposal to other connected peers (BFT P2P Gossip)
                        {
                            let mut pm = event_pm.lock().await;
                            pm.broadcast(P2PPayload::BlockProposal(block.clone()), None).await;
                        }
                        // My vote (if validator)
                        if let Some(mv) = my_vote {
                            let commit = vera_blockchain::block::ValidatorCommit::new(mv.validator_pubkey, mv.signature);
                            if !entry.1.iter().any(|x| x.validator_pubkey == commit.validator_pubkey) {
                                entry.1.push(commit);
                            }
                            let mut pm = event_pm.lock().await;
                            pm.broadcast(P2PPayload::BftVote(mv), None).await;
                        }
                        try_commit_pending(&event_node, &event_pm, &event_lh, &mut pending, height).await;
                    }
                }
                P2PEvent::BftVote(vote) => {
                    let height = vote.height;
                    // Only accept votes with valid signature AND on our pending block
                    if vote.verify().is_ok() {
                        let mut new_commit = false;
                        if let Some(entry) = pending.get_mut(&height) {
                            if vote.block_hash == entry.0.hash()
                                && !entry.1.iter().any(|x| x.validator_pubkey == vote.validator_pubkey)
                            {
                                entry.1.push(vera_blockchain::block::ValidatorCommit::new(vote.validator_pubkey, vote.signature));
                                new_commit = true;
                            }
                        }
                        if new_commit {
                            // Forward vote to other validators in P2P mesh
                            let mut pm = event_pm.lock().await;
                            pm.broadcast(P2PPayload::BftVote(vote.clone()), None).await;
                        }
                        try_commit_pending(&event_node, &event_pm, &event_lh, &mut pending, height).await;
                    }
                }
                P2PEvent::MiniValidatorVote(mvote) => {
                    println!("⚡ [P2P Light Validator] Vote received for height #{}: 0x{}", mvote.height, hex::encode(mvote.validator_pubkey));
                }
                P2PEvent::BlockCommit(block) => {
                    let bheight = block.header.height;
                    let mut n = event_node.lock().await;
                    if bheight == n.height + 1 {
                        match n.apply_block(block.clone()).await {
                            Ok(hash) => {
                                println!("✅ [P2P] Block #{} applied from network! Hash: 0x{}", bheight, hex::encode(hash));
                                let committed: std::collections::HashSet<[u8; 32]> =
                                    block.transactions.iter().map(|t| t.tx_hash()).collect();
                                n.mempool.retain(|t| !committed.contains(&t.tx_hash()));
                                drop(n);
                                event_lh.store(bheight, Ordering::Relaxed);
                                pending.remove(&bheight);
                                let mut pm = event_pm.lock().await;
                                pm.broadcast(P2PPayload::BlockCommit(block), None).await;
                            }
                            Err(e) => {
                                eprintln!("⚠️ [P2P] Block #{} rejected from network: {}", bheight, e);
                            }
                        }
                    } else if bheight > n.height + 1 {
                        let cur_h = n.height;
                        drop(n);
                        println!("⚠️ [Sync Gap] Received Block #{} while local node is at height {}. Requesting sync...", bheight, cur_h);
                        let mut pm = event_pm.lock().await;
                        let req = SyncRequest::new(cur_h + 1, 50);
                        pm.broadcast(P2PPayload::SyncRequest(req), None).await;
                    }
                }
                P2PEvent::SyncRequest { peer_addr, req } => {
                    let n = event_node.lock().await;
                    let max_b = req.bounded_max_blocks();
                    let mut blocks = Vec::new();
                    for h in req.from_height..(req.from_height + max_b as u64) {
                        if let Ok(Some(b)) = n.storage.load_block(h) {
                            blocks.push(b);
                        } else {
                            break;
                        }
                    }
                    drop(n);
                    let pm = event_pm.lock().await;
                    if let Some(peer) = pm.peers.get(&peer_addr) {
                        let _ = peer.tx.send(P2PPayload::SyncResponse(SyncResponse::new(blocks))).await;
                    }
                }
                P2PEvent::SyncResponse { peer_addr, res } => {
                    let mut n = event_node.lock().await;
                    let mut applied_count = 0;
                    for b in res.blocks {
                        let bheight = b.header.height;
                        if bheight == n.height + 1 {
                            match n.apply_block(b).await {
                                Ok(hash) => {
                                    applied_count += 1;
                                    println!("✅ [Sync] Block #{} synced and applied! Hash: 0x{}", bheight, hex::encode(hash));
                                }
                                Err(e) => {
                                    eprintln!("❌ [Sync] Failed to apply synced block #{}: {}", bheight, e);
                                    break;
                                }
                            }
                        }
                    }
                    let new_h = n.height;
                    drop(n);
                    event_lh.store(new_h, Ordering::Relaxed);

                    if applied_count > 0 {
                        let pm = event_pm.lock().await;
                        if let Some(peer) = pm.peers.get(&peer_addr) {
                            if peer.info.height > new_h {
                                println!("🔄 [Sync] Requesting next batch from #{} (peer {} at #{})...", new_h + 1, peer_addr, peer.info.height);
                                let req = SyncRequest::new(new_h + 1, 50);
                                let _ = peer.tx.send(P2PPayload::SyncRequest(req)).await;
                            }
                        }
                    }
                }
                P2PEvent::PeerConnected { addr, height } => {
                    let cur_h = event_lh.load(Ordering::Relaxed);
                    println!("🤝 [P2P Wire] Peer connected: {} (peer height: {}, local: {})", addr, height, cur_h);
                    let pm = event_pm.lock().await;
                    event_node.lock().await.peer_count = pm.peers.len();
                    if height > cur_h {
                        println!("🔄 [Sync] Peer {} connected with height {} ahead. Requesting sync from #{}...", addr, height, cur_h + 1);
                        let req = SyncRequest::new(cur_h + 1, 50);
                        if let Some(peer) = pm.peers.get(&addr) {
                            let _ = peer.tx.send(P2PPayload::SyncRequest(req)).await;
                        }
                    }
                }
                P2PEvent::PeerDisconnected { addr } => {
                    println!("🔌 [P2P Wire] Peer disconnected: {}", addr);
                    let pm = event_pm.lock().await;
                    event_node.lock().await.peer_count = pm.peers.len();
                }
            }
        }
    });

    // (Separate producer removed: proposal is now EVENT-DRIVEN via try_propose() on 50ms tick with anti-churn)

    const MAX_RPC_PAYLOAD_SIZE: usize = 1_048_576; // 1 MB max (Anti-OOM Killer)
    const RPC_SOCKET_TIMEOUT: tokio::time::Duration = tokio::time::Duration::from_secs(10); // Anti-Slowloris

    let listener = TcpListener::bind(format!("{}:{}", bind_host, port)).await?;
    println!("RPC Server listening on http://{}:{}", bind_host, port);

    loop {
        let (mut socket, _) = listener.accept().await?;
        let node_ref = Arc::clone(&shared_node);
        let node_pm = Arc::clone(&peer_manager);

        tokio::spawn(async move {
            let read_task = async {
                let mut buffer = Vec::new();
                let mut temp_buf = [0u8; 8192];
                let mut content_length: Option<usize> = None;
                let mut header_end: Option<usize> = None;

                loop {
                    match socket.read(&mut temp_buf).await {
                        Ok(0) => break,
                        Ok(n) => {
                            if buffer.len() + n > MAX_RPC_PAYLOAD_SIZE {
                                // Reject and abort connection if exceeding 1 MB
                                return Err("Payload exceeds maximum allowed limit of 1MB".to_string());
                            }
                            buffer.extend_from_slice(&temp_buf[..n]);

                            if header_end.is_none() {
                                if let Some(pos) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
                                    header_end = Some(pos + 4);
                                    let header_str = String::from_utf8_lossy(&buffer[..pos]);
                                    for line in header_str.lines() {
                                        if line.to_lowercase().starts_with("content-length:") {
                                            if let Some(val) = line.split(':').nth(1) {
                                                if let Ok(len) = val.trim().parse::<usize>() {
                                                    if len > MAX_RPC_PAYLOAD_SIZE {
                                                        return Err("Content-Length exceeds maximum limit".to_string());
                                                    }
                                                    content_length = Some(len);
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            if let Some(h_end) = header_end {
                                let c_len = content_length.unwrap_or(0);
                                if buffer.len() >= h_end + c_len {
                                    break;
                                }
                            } else if !buffer.is_empty() && (buffer[0] == b'{' || buffer[0] == b'[') {
                                // Only stop reading JSON without headers if syntactically closed
                                if serde_json::from_slice::<serde_json::Value>(&buffer).is_ok() {
                                    break;
                                }
                            }
                        }
                        Err(e) => return Err(e.to_string()),
                    }
                }
                Ok(buffer)
            };

            // Apply 10s timeout against Slowloris
            let buffer_result = tokio::time::timeout(RPC_SOCKET_TIMEOUT, read_task).await;

            let buffer = match buffer_result {
                Ok(Ok(buf)) => buf,
                Ok(Err(msg)) if msg.contains("exceeds maximum") => {
                    let err_body = "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32000,\"message\":\"Payload Too Large (max 1MB)\"}}";
                    let http_response = format!(
                        "HTTP/1.1 413 Payload Too Large\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\nAccess-Control-Allow-Origin: *\r\n\r\n{}",
                        err_body.len(),
                        err_body
                    );
                    let _ = socket.write_all(http_response.as_bytes()).await;
                    return;
                }
                _ => return, // Silently disconnect on timeout
            };

            if !buffer.is_empty() {
                let request_str = String::from_utf8_lossy(&buffer);

                // CORS Preflight Support (OPTIONS)
                if request_str.starts_with("OPTIONS") {
                    let http_response = "HTTP/1.1 200 OK\r\nConnection: close\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: POST, GET, OPTIONS\r\nAccess-Control-Allow-Headers: *\r\nAccess-Control-Max-Age: 86400\r\nContent-Length: 0\r\n\r\n";
                    let _ = socket.write_all(http_response.as_bytes()).await;
                    return;
                }

                // Connectivity test support via GET (MetaMask and browsers)
                if request_str.starts_with("GET ") {
                    let (evm_chain_id, chain_name) = {
                        let n = node_ref.lock().await;
                        (n.evm_chain_id, n.chain_id.clone())
                    };
                    let body = format!(
                        r#"{{"status":"ok","chain":"{}","chainId":"0x{:x}","networkId":{}}}"#,
                        chain_name, evm_chain_id, evm_chain_id
                    );
                    let http_response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: POST, GET, OPTIONS\r\nAccess-Control-Allow-Headers: *\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = socket.write_all(http_response.as_bytes()).await;
                    return;
                }

                let json_payload = if let Some(idx) = request_str.find("\r\n\r\n") {
                    &request_str[idx + 4..]
                } else {
                    &request_str
                };

                let trimmed = json_payload.trim();

                // Silent in release to avoid filling disk

                // Support JSON-RPC Batch Requests (MetaMask frequently uses [{...}, {...}])
                if trimmed.starts_with('[') {
                    if let Ok(batch_reqs) = serde_json::from_str::<Vec<RpcRequest>>(trimmed) {
                        let mut batch_res = Vec::new();
                        for req in batch_reqs {
                            let is_send_raw = req.method == "eth_sendRawTransaction" || req.method == "vera_sendRawTransaction";
                            let res = RpcHandler::handle(&node_ref, req).await;
                            if is_send_raw && res.error.is_none() {
                                let n = node_ref.lock().await;
                                if let Some(last_tx) = n.mempool.last().cloned() {
                                    drop(n);
                                    let mut pm = node_pm.lock().await;
                                    pm.broadcast(P2PPayload::NewTransaction(last_tx), None).await;
                                }
                            }
                            batch_res.push(res);
                        }
                        let res_json = serde_json::to_string(&batch_res).unwrap_or_default();
                        // Silent in release
                        let http_response = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: POST, GET, OPTIONS\r\nAccess-Control-Allow-Headers: *\r\n\r\n{}",
                            res_json.len(),
                            res_json
                        );
                        let _ = socket.write_all(http_response.as_bytes()).await;
                        return;
                    }
                }

                if let Ok(rpc_req) = serde_json::from_str::<RpcRequest>(trimmed) { let method_name = rpc_req.method.clone();
                    let is_send_raw = rpc_req.method == "eth_sendRawTransaction" || rpc_req.method == "vera_sendRawTransaction";
                    let rpc_res = RpcHandler::handle(&node_ref, rpc_req).await;
                    if is_send_raw && rpc_res.error.is_none() {
                        let n = node_ref.lock().await;
                        if let Some(last_tx) = n.mempool.last().cloned() {
                            drop(n);
                            let mut pm = node_pm.lock().await;
                            pm.broadcast(P2PPayload::NewTransaction(last_tx), None).await;
                        }
                    }
                    let res_json = serde_json::to_string(&rpc_res).unwrap_or_default();
                    if let Some(ref err) = rpc_res.error {
                        eprintln!("⚠️ [RPC] method={} code={} error={}", method_name, err.code, err.message);
                    }
                    let http_response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: POST, GET, OPTIONS\r\nAccess-Control-Allow-Headers: *\r\n\r\n{}",
                        res_json.len(),
                        res_json
                    );
                    let _ = socket.write_all(http_response.as_bytes()).await;
                } else {
                    let err_res = RpcResponse {
                        jsonrpc: "2.0".to_string(),
                        id: serde_json::Value::Null,
                        result: None,
                        error: Some(RpcError {
                            code: -32700,
                            message: "Parse error".to_string(),
                            data: None,
                        }),
                    };
                    let res_json = serde_json::to_string(&err_res).unwrap_or_default();
                    let http_response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: POST, GET, OPTIONS\r\nAccess-Control-Allow-Headers: Content-Type, Authorization\r\n\r\n{}",
                        res_json.len(),
                        res_json
                    );
                    let _ = socket.write_all(http_response.as_bytes()).await;
                }
            }
        });
    }
}
