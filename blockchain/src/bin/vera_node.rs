use std::env;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::net::TcpListener;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use ed25519_dalek::SigningKey;

use vera_blockchain::genesis::GenesisConfig;
use vera_blockchain::node::{FullNode, SharedNode};
use vera_blockchain::p2p::{P2PEvent, P2PPayload, P2PService, SyncRequest, SyncResponse, MAX_SYNC_RESPONSE_BYTES};
use vera_blockchain::p2p::wire::MAX_P2P_FRAME_SIZE;
use vera_blockchain::rpc::{RpcError, RpcHandler, RpcRequest, RpcResponse};

/// Equivocation guard (hotfix v0.2.4.3): this validator signs AT MOST ONE block per height.
///
/// Two different blocks committed at the same height would each need 2/3 of the stake,
/// so more than 1/3 of the stake would have to sign both. With this guard no honest
/// validator ever signs two different blocks for one height, so the chain cannot fork.
/// The signed block is fsynced to `<data-dir>/signed_heights/<height>.json` BEFORE the
/// signature leaves the node, so a crash or restart cannot lead to a second signature.
///
/// Trade-off (accepted for the testnet): if the votes of a height split and no block
/// reaches 2/3, that height waits until a validator that has not signed yet receives
/// one of the signed blocks, which are re-broadcast every 2 s.
struct SignGuard {
    dir: std::path::PathBuf,
    signed: std::collections::HashMap<u64, vera_blockchain::block::Block>,
}

impl SignGuard {
    /// Loads the records of heights not yet committed. Fails closed: an unreadable
    /// record stops the node instead of risking a second signature for that height.
    fn load(data_dir: &str, committed_height: u64) -> Result<Self, String> {
        let dir = std::path::Path::new(data_dir).join("signed_heights");
        std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {}", dir.display(), e))?;
        let mut guard = Self { dir, signed: std::collections::HashMap::new() };
        let entries = std::fs::read_dir(&guard.dir).map_err(|e| format!("{}: {}", guard.dir.display(), e))?;
        for entry in entries {
            let path = entry.map_err(|e| e.to_string())?.path();
            if path.extension().map_or(true, |ext| ext != "json") {
                continue; // leftover *.json.tmp from an interrupted write: never broadcast
            }
            let height = match path.file_stem().and_then(|s| s.to_str()).and_then(|s| s.parse::<u64>().ok()) {
                Some(h) => h,
                None => continue,
            };
            let bytes = std::fs::read(&path).map_err(|e| format!("{}: {}", path.display(), e))?;
            let block: vera_blockchain::block::Block = serde_json::from_slice(&bytes)
                .map_err(|e| format!("{}: {}", path.display(), e))?;
            if block.header.height != height {
                return Err(format!("{}: block height {} does not match file name", path.display(), block.header.height));
            }
            guard.signed.insert(height, block);
        }
        guard.prune(committed_height);
        Ok(guard)
    }

    fn signed_hash(&self, height: u64) -> Option<[u8; 32]> {
        self.signed.get(&height).map(|b| b.hash())
    }

    /// Records the intent to sign `block`. Returns Ok(false) when a DIFFERENT block was
    /// already signed at this height (caller must not sign). Ok(true) only after fsync.
    fn record(&mut self, block: &vera_blockchain::block::Block) -> Result<bool, String> {
        use std::io::Write;
        let height = block.header.height;
        if let Some(prev) = self.signed.get(&height) {
            return Ok(prev.hash() == block.hash());
        }
        let tmp = self.dir.join(format!("{}.json.tmp", height));
        let fin = self.dir.join(format!("{}.json", height));
        let bytes = serde_json::to_vec(block).map_err(|e| e.to_string())?;
        let mut f = std::fs::File::create(&tmp).map_err(|e| e.to_string())?;
        f.write_all(&bytes).map_err(|e| e.to_string())?;
        f.sync_all().map_err(|e| e.to_string())?;
        drop(f);
        std::fs::rename(&tmp, &fin).map_err(|e| e.to_string())?;
        std::fs::File::open(&self.dir).and_then(|d| d.sync_all()).map_err(|e| e.to_string())?;
        self.signed.insert(height, block.clone());
        Ok(true)
    }

    /// Drops records of committed heights: those can never be signed again anyway,
    /// because every proposal for a height <= committed_height is rejected.
    fn prune(&mut self, committed_height: u64) {
        let stale: Vec<u64> = self.signed.keys().copied().filter(|h| *h <= committed_height).collect();
        for h in stale {
            self.signed.remove(&h);
            let _ = std::fs::remove_file(self.dir.join(format!("{}.json", h)));
        }
    }
}

/// Announces this validator's P2P address (signed with the validator key) when it is an
/// active validator and knows its public address: from --external-addr, or the IP peers
/// report seeing (AddrHint) plus our listen port. Re-announces on change and every 10 min
/// (receivers drop announces older than PEER_ANNOUNCE_MAX_AGE_SECS).
async fn maybe_announce_self(
    node: &SharedNode,
    pm: &vera_blockchain::p2p::SharedPeerManager,
    external_addr: Option<std::net::SocketAddr>,
    last: &mut Option<(std::net::SocketAddr, std::time::Instant)>,
) {
    let (chain_id, key) = {
        let n = node.read().await;
        let key = match n.keypair.as_ref() {
            Some(k) => k.clone(),
            None => return,
        };
        let my_pub = key.verifying_key().to_bytes();
        if !n.validator_set.active_validators().iter().any(|v| v.public_key == my_pub) {
            return;
        }
        (n.chain_id.clone(), key)
    };
    let mut p = pm.lock().await;
    let addr = match external_addr {
        Some(a) => a,
        None => match (p.best_observed_ip(), p.listen_port) {
            (Some(ip), port) if port != 0 => std::net::SocketAddr::new(ip, port),
            _ => return, // no peer has told us our IP yet
        },
    };
    if let Some((prev, at)) = last {
        if *prev == addr && at.elapsed() < std::time::Duration::from_secs(600) {
            return;
        }
    }
    let announce = vera_blockchain::p2p::PeerAnnounce::new(&chain_id, addr, &key);
    println!("📣 [P2P Discovery] Announcing this validator at {}", addr);
    p.store_announce(announce.clone(), addr);
    p.broadcast_discovery(P2PPayload::PeerAnnounce(announce), None).await;
    *last = Some((addr, std::time::Instant::now()));
}

/// The transaction a successful send-raw call just admitted, found by the hash the RPC
/// returned (searching from the end of the mempool, where it was pushed). Gossiping
/// `mempool.last()` instead sent the wrong tx whenever submissions overlapped, so some
/// txs never reached the other validators and waited for their own node's turn.
async fn admitted_tx(node: &SharedNode, res: &RpcResponse) -> Option<vera_blockchain::transaction::Transaction> {
    let hex_hash = res.result.as_ref()?.as_str()?.trim_start_matches("0x").to_string();
    let bytes = hex::decode(hex_hash).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let n = node.read().await;
    // vera_sendRawTransaction returns tx_hash(); eth_sendRawTransaction returns the
    // Ethereum hash, keccak256 of the raw RLP kept in `raw_evm`.
    n.mempool.iter().rev().find(|t| {
        t.tx_hash()[..] == bytes[..]
            || t.raw_evm.as_ref().map_or(false, |raw| vera_blockchain::account::keccak256(raw)[..] == bytes[..])
    }).cloned()
}

/// Pending txs sent to a peer when it connects, and re-gossiped every 5 s.
const MEMPOOL_REGOSSIP_ON_CONNECT: usize = 5_000;
const MEMPOOL_REGOSSIP_PER_TICK: usize = 256;

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
    let mut n = node.write().await;
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
    guard: &mut SignGuard,
) {
    let proposal = {
        let mut n = node.write().await;
        let h = n.height + 1;
        if n.tendermint_active(h) {
            return; // decided by the Tendermint engine (tm_driver)
        }
        if pending.get(&h).map_or(false, |e| e.2.elapsed() < std::time::Duration::from_millis(2000)) {
            None  // recent in-flight proposal for this height (anti-churn); re-proposes if expired
        } else if let Some(signed) = guard.signed.get(&h) {
            // Already signed a block at this height: never build a new one, only
            // re-broadcast the signed block so a validator that has not signed can join it.
            Some(signed.clone())
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
        let bhash = b.hash();
        let rebroadcast = guard.signed_hash(h) == Some(bhash);
        // Fail-closed: the signature inside `b` must not leave the node before it is on disk.
        match guard.record(&b) {
            Ok(true) => {}
            Ok(false) => {
                eprintln!("🛡️ [BFT Guard] Refusing to propose #{}: a different block is already signed at this height", h);
                return;
            }
            Err(e) => {
                eprintln!("💥 [BFT Guard] Failed to persist signature record for #{}: {}. Proposal aborted.", h, e);
                return;
            }
        }
        // Our own vote (the signed block may be another validator's proposal we voted for).
        let my_vote = {
            let n = node.read().await;
            n.keypair.as_ref().map(|k| vera_blockchain::consensus::Vote::new(
                &n.chain_id, h, 0, bhash, vera_blockchain::consensus::VoteType::PreCommit, k))
        };
        // Keep the commits already collected for this same block.
        let mut commits = match pending.remove(&h) {
            Some((pb, pc, _)) if pb.hash() == bhash => pc,
            _ => Vec::new(),
        };
        for c in b.validator_signatures.iter().cloned()
            .chain(my_vote.iter().map(|v| vera_blockchain::block::ValidatorCommit::new(v.validator_pubkey, v.signature)))
        {
            if !commits.iter().any(|x| x.validator_pubkey == c.validator_pubkey) {
                commits.push(c);
            }
        }
        pending.insert(h, (b.clone(), commits, std::time::Instant::now()));
        if rebroadcast {
            println!("🔁 [BFT Guard] Re-broadcasting signed block #{} (0x{})", h, hex::encode(bhash));
        } else {
            println!("📤 [BFT] Proposing block #{} ({} txs)", h, b.transactions.len());
        }
        {
            let mut p = pm.lock().await;
            p.broadcast(P2PPayload::BlockProposal(b), None).await;
            if let Some(v) = my_vote {
                p.broadcast(P2PPayload::BftVote(v), None).await;
            }
        }
        try_commit_pending(node, pm, local_height, pending, h).await;
    }
}

/// Gossiped transactions waiting for admission (beyond this, copies are dropped and
/// arrive again by re-gossip or in a block).
const GOSSIP_TX_QUEUE_LEN: usize = 20_000;
/// Gossiped transactions admitted per event-loop turn (bounds how long consensus waits).
const GOSSIP_ADMIT_BATCH: usize = 512;

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
        println!("  --external-addr <IP:PORT> Public P2P address announced to other validators (default: IP reported by peers + --p2p-port)");
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
    let mut external_addr: Option<std::net::SocketAddr> = None;

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
            "--external-addr" if i + 1 < args.len() => {
                external_addr = Some(args[i + 1].parse().map_err(|e| format!("invalid --external-addr '{}': {}", args[i + 1], e))?);
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

    let hw = vera_blockchain::hw::profile();
    println!("Hardware:       {} thread(s) ({}), {} MiB memory, {} | signature cache {} entries",
        hw.threads, hw.threads_source, hw.memory_bytes / (1024 * 1024), hw.simd, hw.signature_cache_entries());
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
    let shared_node: SharedNode = Arc::new(tokio::sync::RwLock::new(node));

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
    // Gossiped transactions get their own queue (see P2PService::tx_event_tx): the event
    // loop serves consensus first and admits these in batches.
    let (gossip_tx_tx, mut gossip_tx_rx) = tokio::sync::mpsc::channel::<vera_blockchain::transaction::Transaction>(GOSSIP_TX_QUEUE_LEN);
    let (mut p2p_service, peer_manager) = P2PService::new(
        &genesis.chain_id,
        p2p_key,
        seed_addrs,
        p2p_event_tx,
        Arc::clone(&local_height),
    );
    p2p_service.tx_event_tx = Some(gossip_tx_tx);
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
    let mut sign_guard = {
        let committed = shared_node.write().await.height;
        SignGuard::load(&data_dir, committed).map_err(|e| format!("[BFT Guard] cannot load signature records: {}", e))?
    };
    // Tendermint engine host (active from the activation height on; idle before).
    let (tm_timer_tx, mut tm_timer_rx) = tokio::sync::mpsc::channel::<vera_blockchain::tm_driver::TmTimeout>(1024);
    let mut tm = {
        let n = shared_node.read().await;
        if let Some(a) = n.tendermint_activation {
            println!("🧩 [TM] Tendermint consensus active from height #{}", a);
        }
        vera_blockchain::tm_driver::TmDriver::new(&n.chain_id, n.keypair.clone(), &data_dir, tm_timer_tx, Arc::clone(&local_height))
            .map_err(|e| format!("[TM] cannot initialize: {}", e))?
    };
    if !sign_guard.signed.is_empty() {
        println!("🛡️ [BFT Guard] Restored signature records for heights {:?}", sign_guard.signed.keys().collect::<Vec<_>>());
    }
    tokio::spawn(async move {
        // Consensus state in progress: height -> (proposed block, collected commits)
        let mut pending: std::collections::HashMap<u64, (vera_blockchain::block::Block, Vec<vera_blockchain::block::ValidatorCommit>, std::time::Instant)> = std::collections::HashMap::new();
        let mut mempool_since: std::collections::HashMap<u64, std::time::Instant> = std::collections::HashMap::new();
        let mut tick = tokio::time::interval(tokio::time::Duration::from_millis(50));
        let mut sync_tick_counter: u64 = 0;
        let full_prune_running = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut last_announce: Option<(std::net::SocketAddr, std::time::Instant)> = None;
        loop {
            // biased: consensus messages and timers before the tick, and all of them before
            // transaction gossip, which can arrive by the thousand.
            let event = tokio::select! {
                biased;
                maybe = p2p_event_rx.recv() => match maybe { Some(e) => e, None => break },
                Some(t) = tm_timer_rx.recv() => {
                    tm.on_timeout(&event_node, &event_pm, t).await;
                    continue;
                }
                _ = tick.tick() => {
                    tm.tick(&event_node, &event_pm).await;
                    sign_guard.prune(event_lh.load(Ordering::Relaxed));
                    try_propose(&event_node, &event_pm, &event_lh, &mut pending, &mut mempool_since, &mut sign_guard).await;
                    sync_tick_counter = sync_tick_counter.wrapping_add(1);
                    // Every 20 ticks (1s), check if there is height divergence with peers
                    // Every 600 ticks (30 s): announce our validator address (peer discovery).
                    if sync_tick_counter % 600 == 1 {
                        maybe_announce_self(&event_node, &event_pm, external_addr, &mut last_announce).await;
                    }
                    // Every 5 s re-gossip the oldest pending txs (bounded). Peers drop the ones
                    // they already have (P2P seen-cache), so this only fills gaps left by a
                    // gossip that happened while a link was down.
                    if sync_tick_counter % 100 == 50 {
                        let oldest: Vec<_> = event_node.read().await.mempool.iter().take(MEMPOOL_REGOSSIP_PER_TICK).cloned().collect();
                        if !oldest.is_empty() {
                            let mut pm = event_pm.lock().await;
                            for tx in oldest {
                                pm.broadcast(P2PPayload::NewTransaction(tx), None).await;
                            }
                        }
                    }
                    if sync_tick_counter % 20 == 0 {
                        event_node.write().await.flush_mempool_if_dirty();
                        // Full mempool prune (re-executes pending txs: seconds with tens of
                        // thousands pending) in its own task, on a state copy, one at a time:
                        // neither consensus nor RPC waits for it.
                        if !full_prune_running.load(Ordering::Relaxed) {
                            let snap = {
                                let n = event_node.read().await;
                                if n.full_prune_due() { Some(n.full_prune_snapshot()) } else { None }
                            };
                            if let Some(snap) = snap {
                                full_prune_running.store(true, Ordering::Relaxed);
                                let node = Arc::clone(&event_node);
                                let running = Arc::clone(&full_prune_running);
                                tokio::spawn(async move {
                                    let pending = snap.mempool.len();
                                    let t = std::time::Instant::now();
                                    if let Ok(result) = tokio::task::spawn_blocking(move || vera_blockchain::node::FullNode::compute_full_prune(snap)).await {
                                        let pruned = node.write().await.apply_full_prune(result);
                                        if pruned > 0 {
                                            println!("🧹 [Mempool] Full prune: {} of {} pending dropped ({:.0} ms, off-lock)",
                                                pruned, pending, t.elapsed().as_secs_f64() * 1000.0);
                                        }
                                    }
                                    running.store(false, Ordering::Relaxed);
                                });
                            }
                        }
                        let cur_h = event_lh.load(Ordering::Relaxed);
                        let mut pm = event_pm.lock().await;
                        event_node.write().await.peer_count = pm.peers.len();
                        let highest = pm.highest_peer_height();
                        if highest > cur_h {
                            println!("🔄 [Sync Watchdog] Local node at height #{} detected peer at height #{}. Requesting sync...", cur_h, highest);
                            let req = SyncRequest::new(cur_h + 1, 50);
                            pm.broadcast(P2PPayload::SyncRequest(req), None).await;
                        }
                    }
                    continue;
                }
                Some(first) = gossip_tx_rx.recv() => {
                    let mut batch = vec![first];
                    while batch.len() < GOSSIP_ADMIT_BATCH {
                        match gossip_tx_rx.try_recv() {
                            Ok(tx) => batch.push(tx),
                            Err(_) => break,
                        }
                    }
                    // Signatures verified in parallel off the event loop (cached), then
                    // the whole batch admitted under one write lock.
                    let batch = tokio::task::spawn_blocking(move || {
                        vera_blockchain::state_transition::preverify_signatures(&batch);
                        batch
                    }).await.unwrap_or_default();
                    let accepted: Vec<_> = {
                        let mut n = event_node.write().await;
                        batch.into_iter().filter(|tx| n.submit_transaction(tx.clone()).is_ok()).collect()
                    };
                    if !accepted.is_empty() {
                        let mut pm = event_pm.lock().await;
                        for tx in accepted {
                            pm.broadcast(P2PPayload::NewTransaction(tx), None).await;
                        }
                    }
                    continue;
                }
            };
            match event {
                P2PEvent::NewTransaction(tx) => {
                    let mut n = event_node.write().await;
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
                        let n = event_node.read().await;
                        if height != n.height + 1 || block.header.prev_hash != n.latest_block_hash
                            || n.tendermint_active(height)
                        {
                            (false, None)
                        } else {
                            let proposer_ok = (0..=10u64).any(|r| {
                                n.validator_set.get_proposer(height, r)
                                    .map(|p| p.address == block.header.proposer)
                                    .unwrap_or(false)
                            });
                            if !proposer_ok {
                                (false, None)
                            } else if sign_guard.signed_hash(height).map_or(false, |h| h != bhash) {
                                // Already signed another block at this height: neither vote nor
                                // replace our pending block (see SignGuard).
                                println!("🛡️ [BFT Guard] Ignoring proposal #{} (0x{}): a different block is already signed at this height",
                                    height, hex::encode(bhash));
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
                        // Fail-closed: persist the signature record before the vote leaves the node.
                        let my_vote = match my_vote {
                            Some(mv) => match sign_guard.record(&block) {
                                Ok(true) => Some(mv),
                                Ok(false) => {
                                    eprintln!("🛡️ [BFT Guard] Not voting on #{}: a different block is already signed at this height", height);
                                    None
                                }
                                Err(e) => {
                                    eprintln!("💥 [BFT Guard] Failed to persist signature record for #{}: {}. Vote withheld.", height, e);
                                    None
                                }
                            },
                            None => None,
                        };
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
                    let mut n = event_node.write().await;
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
                    let n = event_node.read().await;
                    let max_b = req.bounded_max_blocks();
                    let mut blocks = Vec::new();
                    for h in req.from_height..(req.from_height + max_b as u64) {
                        if let Ok(Some(b)) = n.storage.load_block(h) {
                            if blocks.is_empty() {
                                // Check if single block exceeds frame limit
                                let single_frame_len = 1 + serde_json::to_vec(&P2PPayload::SyncResponse(SyncResponse { blocks: vec![b.clone()] }))
                                    .map(|v| v.len())
                                    .unwrap_or(0);
                                if single_frame_len > MAX_P2P_FRAME_SIZE {
                                    eprintln!(
                                        "❌ [Sync Warning] block #{} exceeds P2P frame limit ({} > {} bytes), cannot be served",
                                        b.header.height, single_frame_len, MAX_P2P_FRAME_SIZE
                                    );
                                    break;
                                }
                                blocks.push(b);
                            } else {
                                let mut test_blocks = blocks.clone();
                                test_blocks.push(b.clone());
                                let test_frame_len = 1 + serde_json::to_vec(&P2PPayload::SyncResponse(SyncResponse { blocks: test_blocks }))
                                    .map(|v| v.len())
                                    .unwrap_or(0);
                                if test_frame_len > MAX_SYNC_RESPONSE_BYTES {
                                    break;
                                }
                                blocks.push(b);
                            }
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
                    let mut n = event_node.write().await;
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
                    event_node.write().await.peer_count = pm.peers.len();
                    if height > cur_h {
                        println!("🔄 [Sync] Peer {} connected with height {} ahead. Requesting sync from #{}...", addr, height, cur_h + 1);
                        let req = SyncRequest::new(cur_h + 1, 50);
                        if let Some(peer) = pm.peers.get(&addr) {
                            let _ = peer.tx.send(P2PPayload::SyncRequest(req)).await;
                        }
                    }
                    // Hand the new peer our pending txs: a tx gossiped while we had no
                    // peers (e.g. right after a restart) otherwise stays on this node only,
                    // and every other proposer finds an empty mempool round after round.
                    if let Some(peer) = pm.peers.get(&addr) {
                        let tx_ch = peer.tx.clone();
                        drop(pm);
                        let pending: Vec<_> = event_node.read().await.mempool.iter().take(MEMPOOL_REGOSSIP_ON_CONNECT).cloned().collect();
                        if !pending.is_empty() {
                            tokio::spawn(async move {
                                for tx in pending {
                                    if tx_ch.send(P2PPayload::NewTransaction(tx)).await.is_err() {
                                        break;
                                    }
                                }
                            });
                        }
                    }
                }
                P2PEvent::PeerDisconnected { addr } => {
                    println!("🔌 [P2P Wire] Peer disconnected: {}", addr);
                    let pm = event_pm.lock().await;
                    event_node.write().await.peer_count = pm.peers.len();
                }
                P2PEvent::TmProposal { peer_addr, proposal } => {
                    tm.on_message(&event_node, &event_pm, P2PPayload::TmProposal(proposal), Some(peer_addr)).await;
                }
                P2PEvent::TmVote { peer_addr, vote } => {
                    tm.on_message(&event_node, &event_pm, P2PPayload::TmVote(vote), Some(peer_addr)).await;
                }
                P2PEvent::TmCompactProposal { peer_addr, compact } => {
                    tm.on_compact_proposal(&event_node, &event_pm, compact, peer_addr).await;
                }
                P2PEvent::TmProposalRequest { peer_addr, height, round, missing } => {
                    let reply = if missing.is_empty() {
                        tm.proposal_for(height, round).map(P2PPayload::TmProposalFull)
                    } else {
                        tm.proposal_txs_for(height, round, &missing).map(|txs| P2PPayload::TmProposalTxs { height, round, txs })
                    };
                    if let Some(reply) = reply {
                        event_pm.lock().await.send_priority(&peer_addr, reply);
                    }
                }
                P2PEvent::TmProposalTxs { peer_addr, height, round, txs } => {
                    tm.on_proposal_txs(&event_node, &event_pm, height, round, txs, peer_addr).await;
                }
                P2PEvent::PeerAnnounce { peer_addr, announce } => {
                    // Authorization = the on-chain validator set (governance allowlist +
                    // stake): only ACTIVE validators get stored, relayed and dialed.
                    let is_active = event_node.write().await.validator_set.active_validators()
                        .iter().any(|v| v.public_key == announce.node_pubkey);
                    if !is_active {
                        continue;
                    }
                    let addr = match announce.addr.parse::<std::net::SocketAddr>() {
                        Ok(a) => a,
                        Err(_) => continue,
                    };
                    let mut pm = event_pm.lock().await;
                    let known = pm.discovered.get(&announce.node_pubkey).map(|d| d.addr);
                    if pm.store_announce(announce.clone(), addr) {
                        if known != Some(addr) {
                            println!("🧭 [P2P Discovery] Validator 0x{}… is at {}", hex::encode(&announce.node_pubkey[..4]), addr);
                        }
                        pm.broadcast_discovery(P2PPayload::PeerAnnounce(announce), Some(peer_addr)).await;
                    }
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
                        let n = node_ref.read().await;
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
                        // Native raw txs of the batch get their signatures verified in parallel
                        // off the async workers first (cached), so each admission below only
                        // holds the node lock for the nonce/balance checks.
                        let natives: Vec<vera_blockchain::transaction::Transaction> = batch_reqs.iter()
                            .filter(|r| r.method == "vera_sendRawTransaction")
                            .filter_map(|r| r.params.as_array().and_then(|a| a.get(0)).and_then(|v| v.as_str()).map(|s| s.to_string()))
                            .filter_map(|h| hex::decode(h.strip_prefix("0x").unwrap_or(&h)).ok())
                            .filter_map(|b| vera_blockchain::transaction::Transaction::from_bytes(&b).ok())
                            .collect();
                        if natives.len() > 1 {
                            let _ = tokio::task::spawn_blocking(move || {
                                vera_blockchain::state_transition::preverify_signatures(&natives);
                            }).await;
                        }
                        let mut batch_res = Vec::new();
                        let mut to_gossip = Vec::new();
                        for req in batch_reqs {
                            let is_send_raw = req.method == "eth_sendRawTransaction" || req.method == "vera_sendRawTransaction";
                            let res = RpcHandler::handle(&node_ref, req).await;
                            if is_send_raw && res.error.is_none() {
                                if let Some(tx) = admitted_tx(&node_ref, &res).await {
                                    to_gossip.push(tx);
                                }
                            }
                            batch_res.push(res);
                        }
                        if !to_gossip.is_empty() {
                            let mut pm = node_pm.lock().await;
                            for tx in to_gossip {
                                pm.broadcast(P2PPayload::NewTransaction(tx), None).await;
                            }
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
                        if let Some(tx) = admitted_tx(&node_ref, &rpc_res).await {
                            let mut pm = node_pm.lock().await;
                            pm.broadcast(P2PPayload::NewTransaction(tx), None).await;
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
