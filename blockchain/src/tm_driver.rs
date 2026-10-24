//! Host of the Tendermint engine (`crate::tendermint`) inside the node (v0.2.6).
//!
//! Turns engine outputs into signed P2P messages, timers, block building and block
//! commits, and feeds verified network messages back into the engine. One height at a
//! time; the height after the latest applied block.
//!
//! Idle heights: like CometBFT with `create_empty_blocks = false`, a height starts only
//! when the mempool has transactions or a consensus message for it arrives, so an idle
//! chain sends no consensus traffic and its rounds do not grow while nobody transacts.
//!
//! Crash safety (WAL): every input of the current height is appended to
//! `<data-dir>/tm_wal/<height>.wal`, and every message this validator signs is recorded
//! there and fsynced BEFORE it is broadcast. After a restart the engine is rebuilt by
//! replaying the WAL (the engine is deterministic), so locks survive restarts and the
//! validator never signs two different messages for the same (height, round, step).

use std::collections::{HashMap, HashSet, VecDeque};
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use crate::block::{Block, ValidatorCommit};
use crate::transaction::Transaction;
use crate::consensus::{Vote, VoteType};
use crate::node::{FullNode, SharedNode};
use crate::p2p::{P2PPayload, SharedPeerManager, TmCompactProposal, TmProposal};
use crate::tendermint::{NodeId, Output, Tendermint, TimeoutKind, Value, ValueId, VoteKind};

/// Votes for nil carry the zero hash.
const NIL: [u8; 32] = [0u8; 32];
/// Bounds against a peer flooding messages for far-away heights or rounds.
const MAX_FUTURE_MESSAGES: usize = 5_000;
const MAX_ROUND_AHEAD: u64 = 1_000;
const MAX_GOSSIP_MESSAGES: usize = 4_000;
/// Re-gossip interval (the paper's liveness proof assumes reliable gossip).
const GOSSIP_EVERY: std::time::Duration = std::time::Duration::from_secs(2);

/// Where the time of one height goes (for the `⏱️ [TM]` log line). Only measures.
#[derive(Default)]
struct HeightTiming {
    started: Option<std::time::Instant>,
    build_ms: Option<f64>,
    proposal_at_ms: Option<f64>,
    validate_ms: Option<f64>,
    wal_ms: f64,
    precommit_at_ms: Option<f64>,
}

impl HeightTiming {
    fn since(&self) -> f64 {
        self.started.map_or(0.0, |t| t.elapsed().as_secs_f64() * 1000.0)
    }
}

fn opt_ms(v: Option<f64>) -> String {
    v.map_or("-".to_string(), |v| format!("{:.0}", v))
}

#[derive(Clone, Debug, PartialEq)]
pub struct BlockValue(pub Block);

impl Value for BlockValue {
    fn id(&self) -> ValueId {
        self.0.hash()
    }
}

/// Timer expirations, delivered back to the node event loop.
#[derive(Debug, Clone, Copy)]
pub struct TmTimeout {
    pub kind: TimeoutKind,
    pub height: u64,
    pub round: u64,
}

/// Round-dependent timeouts (the paper's timeoutX(round): must grow with the round).
pub fn timeout_duration(kind: TimeoutKind, round: u64) -> std::time::Duration {
    let ms = match kind {
        TimeoutKind::Propose => 3_000 + 1_000 * round.min(60),
        TimeoutKind::Prevote | TimeoutKind::Precommit => 1_000 + 500 * round.min(60),
    };
    std::time::Duration::from_millis(ms)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
enum Input {
    Proposal { proposal: TmProposal, valid: bool },
    Vote(Vote),
    Value { round: u64, block: Block },
    Timeout { kind: u8, round: u64 },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
enum WalEntry {
    Input(Input),
    /// A message this validator signed: (step, round, block id). 0 = proposal,
    /// 1 = prevote, 2 = precommit.
    Signed { step: u8, round: u64, id: [u8; 32] },
}

fn kind_code(kind: TimeoutKind) -> u8 {
    match kind {
        TimeoutKind::Propose => 0,
        TimeoutKind::Prevote => 1,
        TimeoutKind::Precommit => 2,
    }
}

fn kind_from(code: u8) -> TimeoutKind {
    match code {
        0 => TimeoutKind::Propose,
        1 => TimeoutKind::Prevote,
        _ => TimeoutKind::Precommit,
    }
}

pub struct TmDriver {
    chain_id: String,
    key: Option<SigningKey>,
    wal_dir: PathBuf,
    timer_tx: mpsc::Sender<TmTimeout>,
    local_height: Arc<AtomicU64>,

    /// Height being decided (latest applied + 1).
    height: u64,
    sm: Option<Tendermint<BlockValue, [u8; 64]>>,
    wal: Option<std::fs::File>,
    replaying: bool,
    signed: HashMap<(u8, u64), [u8; 32]>,
    pending_value: Option<u64>,
    future: Vec<P2PPayload>,
    gossip: Vec<P2PPayload>,
    gossip_keys: HashSet<[u8; 32]>,
    last_gossip: std::time::Instant,
    /// Buffered messages may belong to the height we just entered: replay on next tick.
    replay_future: bool,
    timing: HeightTiming,
    /// Compact proposal waiting for the txs we asked its sender for.
    pending_compact: Option<(TmCompactProposal, std::net::SocketAddr)>,
}

impl TmDriver {
    pub fn new(
        chain_id: &str,
        key: Option<SigningKey>,
        data_dir: &str,
        timer_tx: mpsc::Sender<TmTimeout>,
        local_height: Arc<AtomicU64>,
    ) -> Result<Self, String> {
        let wal_dir = std::path::Path::new(data_dir).join("tm_wal");
        std::fs::create_dir_all(&wal_dir).map_err(|e| format!("{}: {}", wal_dir.display(), e))?;
        Ok(Self {
            chain_id: chain_id.to_string(),
            key,
            wal_dir,
            timer_tx,
            local_height,
            height: 0,
            sm: None,
            wal: None,
            replaying: false,
            signed: HashMap::new(),
            pending_value: None,
            future: Vec::new(),
            gossip: Vec::new(),
            gossip_keys: HashSet::new(),
            last_gossip: std::time::Instant::now(),
            replay_future: false,
            timing: HeightTiming::default(),
            pending_compact: None,
        })
    }

    fn wal_path(&self, height: u64) -> PathBuf {
        self.wal_dir.join(format!("{}.wal", height))
    }

    /// Called on every tick and after any block is applied (consensus, BlockCommit or
    /// sync): moves to the next height, starts it when there is work, retries a pending
    /// GetValue, and re-gossips.
    pub async fn tick(&mut self, node: &SharedNode, pm: &SharedPeerManager) {
        let (next, active, has_txs) = {
            let n = node.read().await;
            (n.height + 1, n.tendermint_active(n.height + 1), !n.mempool.is_empty())
        };
        if !active {
            return;
        }
        if next != self.height {
            // Moved by a block from the network / sync, or first tick after start-up.
            self.enter_height(next);
        }
        if self.sm.is_none() && self.wal_path(self.height).exists() {
            // A WAL for this height means we crashed in the middle of it: resume now.
            self.start(node, pm).await;
        }
        if self.replay_future {
            self.replay_future = false;
            let buffered: Vec<P2PPayload> = std::mem::take(&mut self.future);
            for msg in buffered {
                self.on_message(node, pm, msg, None).await;
            }
        }
        if self.sm.is_none() && has_txs {
            self.start(node, pm).await;
        }
        if let Some(round) = self.pending_value {
            self.try_build_value(node, pm, round).await;
        }
        if self.sm.is_some() && self.last_gossip.elapsed() >= GOSSIP_EVERY {
            self.last_gossip = std::time::Instant::now();
            let msgs = self.gossip.clone();
            let mut p = pm.lock().await;
            for m in msgs {
                p.broadcast(m, None).await;
            }
        }
    }

    fn enter_height(&mut self, height: u64) {
        // Older WALs belong to applied heights.
        if let Ok(entries) = std::fs::read_dir(&self.wal_dir) {
            for e in entries.flatten() {
                let p = e.path();
                let h = p.file_stem().and_then(|s| s.to_str()).and_then(|s| s.parse::<u64>().ok());
                if h.map_or(false, |h| h < height) {
                    let _ = std::fs::remove_file(&p);
                }
            }
        }
        self.height = height;
        self.sm = None;
        self.wal = None;
        self.signed.clear();
        self.pending_value = None;
        self.gossip.clear();
        self.gossip_keys.clear();
        self.future.retain(|m| message_height(m).map_or(false, |h| h >= height));
        self.replay_future = true;
        self.timing = HeightTiming::default();
        self.pending_compact = None;
    }

    /// Starts the engine for `self.height` (replaying the WAL if one exists).
    async fn start(&mut self, node: &SharedNode, pm: &SharedPeerManager) {
        if self.height == 0 || self.sm.is_some() {
            return;
        }
        let (vals, quorum, proposer_set, me_active) = {
            let n = node.read().await;
            if n.height + 1 != self.height {
                return; // our block store moved on; tick will enter the right height
            }
            let active = n.validator_set.active_validators();
            let vals: Vec<(NodeId, u128)> = active.iter().map(|v| (v.public_key, v.stake)).collect();
            let me_active = self.key.as_ref()
                .map(|k| k.verifying_key().to_bytes())
                .map_or(false, |pk| vals.iter().any(|(p, _)| *p == pk));
            (vals, n.validator_set.supermajority_threshold(), n.validator_set.clone(), me_active)
        };
        if vals.is_empty() {
            return;
        }
        let proposer: crate::tendermint::ProposerFn = Arc::new(move |h, r| {
            proposer_set.get_proposer(h, r).map(|v| v.public_key).unwrap_or([0u8; 32])
        });
        let me = if me_active { self.key.as_ref().map(|k| k.verifying_key().to_bytes()) } else { None };
        let mut sm = Tendermint::new(me, proposer);
        let first = sm.start_height(self.height, vals, quorum);
        self.timing.started = Some(std::time::Instant::now());
        self.sm = Some(sm);

        // Replay a WAL left by a crash, then keep appending to it.
        let path = self.wal_path(self.height);
        let mut replay: Vec<Input> = Vec::new();
        if let Ok(content) = std::fs::read_to_string(&path) {
            for line in content.lines() {
                match serde_json::from_str::<WalEntry>(line) {
                    Ok(WalEntry::Input(i)) => replay.push(i),
                    Ok(WalEntry::Signed { step, round, id }) => {
                        self.signed.insert((step, round), id);
                    }
                    Err(_) => break, // torn last line from the crash
                }
            }
            println!("♻️ [TM] Resuming height #{} from WAL ({} inputs, {} signed messages)",
                self.height, replay.len(), self.signed.len());
        }
        match std::fs::OpenOptions::new().create(true).append(true).open(&path) {
            Ok(f) => self.wal = Some(f),
            Err(e) => {
                eprintln!("💥 [TM] Cannot open WAL {}: {}. Not participating in this height.", path.display(), e);
                self.sm = None;
                return;
            }
        }
        println!("🟢 [TM] Height #{} started (validator: {})", self.height, me_active);

        self.replaying = true;
        self.process_outputs(node, pm, first).await;
        for input in replay {
            self.feed(node, pm, input, false).await;
        }
        self.replaying = false;
        if let Some(round) = self.pending_value {
            self.try_build_value(node, pm, round).await;
        }
    }

    /// Network message (already deduplicated by the P2P layer). `from` is the peer it
    /// came from, so it is not echoed back.
    pub async fn on_message(&mut self, node: &SharedNode, pm: &SharedPeerManager, msg: P2PPayload, from: Option<std::net::SocketAddr>) {
        let h = match message_height(&msg) {
            Some(h) => h,
            None => return,
        };
        let ok = match &msg {
            P2PPayload::TmProposal(p) => p.verify(&self.chain_id).is_ok(),
            P2PPayload::TmVote(v) => v.chain_id == self.chain_id && v.verify().is_ok(),
            _ => false,
        };
        if !ok || h < self.height || h == 0 {
            return;
        }
        // Only messages signed by active validators are kept or relayed (anyone can
        // generate keys; this stops strangers from flooding consensus traffic).
        let signer = match &msg {
            P2PPayload::TmProposal(p) => p.proposer_pubkey,
            P2PPayload::TmVote(v) => v.validator_pubkey,
            _ => return,
        };
        let is_validator = node.read().await.validator_set.active_validators()
            .iter().any(|v| v.public_key == signer);
        if !is_validator {
            return;
        }
        if h > self.height || self.height == 0 {
            if self.future.len() < MAX_FUTURE_MESSAGES {
                self.future.push(msg);
            }
            return;
        }
        if let Some(sm) = &self.sm {
            let r = message_round(&msg);
            if r > sm.round() + MAX_ROUND_AHEAD {
                return;
            }
        }
        // Relay what we accept (reliable gossip), then feed the engine. A proposal rebuilt
        // from a compact one has no receipts yet: it is relayed once they are computed.
        let rebuilt = matches!(&msg, P2PPayload::TmProposal(p) if p.block.receipts.is_empty() && !p.block.transactions.is_empty());
        if !rebuilt {
            let mut p = pm.lock().await;
            p.broadcast(msg.clone(), from).await;
            drop(p);
            self.remember_for_gossip(&msg);
        }
        if self.sm.is_none() {
            self.start(node, pm).await;
            if self.sm.is_none() {
                return;
            }
        }
        let input = match msg {
            P2PPayload::TmProposal(mut proposal) => {
                if self.timing.proposal_at_ms.is_none() {
                    self.timing.proposal_at_ms = Some(self.timing.since());
                }
                let t_validate = std::time::Instant::now();
                // Cheap checks under the lock; the re-execution runs with no lock held, so
                // RPC admissions are not stalled behind it.
                let snap = node.read().await.tm_proposal_precheck(&proposal.block, proposal.round);
                let result = match snap {
                    Ok(snap) => {
                        let block = proposal.block.clone();
                        match off_runtime(async move { FullNode::execute_proposal(snap, &block).await }).await {
                            Ok((exec, receipts)) => {
                                node.read().await.store_execution(exec);
                                if rebuilt {
                                    // Same receipts as the proposer's (receipts_root checked).
                                    proposal.block.receipts = receipts;
                                    let msg = P2PPayload::TmProposal(proposal.clone());
                                    pm.lock().await.broadcast(msg.clone(), from).await;
                                    self.remember_for_gossip(&msg);
                                }
                                Ok(())
                            }
                            Err(e) => Err(e),
                        }
                    }
                    Err(e) => Err(e),
                };
                let valid = {
                    match result {
                        Ok(()) => true,
                        Err(e) => {
                            eprintln!("🚫 [TM] Proposal #{} round {} is invalid: {} (signer 0x{}…, header.proposer 0x{}…, block 0x{}…, from {:?})",
                                proposal.height, proposal.round, e, hex::encode(&proposal.proposer_pubkey[..4]),
                                hex::encode(&proposal.block.header.proposer[..4]), hex::encode(&proposal.block.hash()[..4]), from);
                            false
                        }
                    }
                };
                self.timing.validate_ms.get_or_insert(t_validate.elapsed().as_secs_f64() * 1000.0);
                Input::Proposal { proposal, valid }
            }
            P2PPayload::TmVote(v) => Input::Vote(v),
            _ => return,
        };
        self.feed(node, pm, input, true).await;
    }

    /// Compact proposal (tx hashes only): rebuilt from the mempool and handled like a full
    /// one; if some txs are not here (yet), the full proposal is asked from the sender.
    pub async fn on_compact_proposal(&mut self, node: &SharedNode, pm: &SharedPeerManager, compact: TmCompactProposal, from: std::net::SocketAddr) {
        let p = &compact.proposal;
        if p.verify(&self.chain_id).is_err() || p.height < self.height {
            return;
        }
        let hashes = match compact.hashes() {
            Ok(h) => h,
            Err(_) => return,
        };
        let found = node.read().await.mempool_lookup(&hashes);
        let missing: Vec<[u8; 32]> = hashes.iter().zip(&found).filter(|(_, t)| t.is_none()).map(|(h, _)| *h).collect();
        if missing.is_empty() {
            let txs: Vec<Transaction> = found.into_iter().flatten().collect();
            if Block::compute_tx_root(&txs) == p.block.header.tx_root {
                let mut proposal = compact.proposal;
                proposal.block.transactions = txs;
                self.on_message(node, pm, P2PPayload::TmProposal(proposal), Some(from)).await;
                return;
            }
        }
        // Usually txs the proposer got just before building (they travel on the normal
        // queue, the proposal on the priority one): ask for only those.
        let (height, round) = (p.height, p.round);
        let request = if missing.is_empty() || missing.len() * 2 > hashes.len() {
            String::new() // most of the block (or a tx_root mismatch): ask for all of it
        } else {
            crate::p2p::encode_hashes(&missing)
        };
        println!("📦 [TM] Compact proposal #{} round {}: {} of {} txs not in the mempool; asking {} for {}",
            height, round, missing.len(), hashes.len(), from, if request.is_empty() { "the full proposal" } else { "them" });
        self.pending_compact = Some((compact, from));
        pm.lock().await.send_priority(&from, P2PPayload::TmProposalRequest { height, round, missing: request });
    }

    /// The txs we asked for a pending compact proposal: rebuild it with them and the
    /// mempool; if it still does not match, ask for the full proposal.
    pub async fn on_proposal_txs(&mut self, node: &SharedNode, pm: &SharedPeerManager, height: u64, round: u64, txs: Vec<Transaction>, from: std::net::SocketAddr) {
        let (compact, sender) = match self.pending_compact.take() {
            Some((c, s)) if c.proposal.height == height && c.proposal.round == round => (c, s),
            other => {
                self.pending_compact = other;
                return;
            }
        };
        let hashes = match compact.hashes() {
            Ok(h) => h,
            Err(_) => return,
        };
        let received: HashMap<[u8; 32], Transaction> = txs.into_iter().map(|t| (t.tx_hash(), t)).collect();
        let found = node.read().await.mempool_lookup(&hashes);
        let rebuilt: Option<Vec<Transaction>> = hashes.iter().zip(found)
            .map(|(h, t)| t.or_else(|| received.get(h).cloned()))
            .collect();
        match rebuilt {
            Some(txs) if Block::compute_tx_root(&txs) == compact.proposal.block.header.tx_root => {
                let mut proposal = compact.proposal;
                proposal.block.transactions = txs;
                self.on_message(node, pm, P2PPayload::TmProposal(proposal), Some(from)).await;
            }
            _ => {
                println!("📦 [TM] Proposal #{} round {} still incomplete; asking {} for the full proposal", height, round, sender);
                pm.lock().await.send_priority(&sender, P2PPayload::TmProposalRequest { height, round, missing: String::new() });
            }
        }
    }

    /// The txs of a proposal we hold for (height, round) with these hashes.
    pub fn proposal_txs_for(&self, height: u64, round: u64, missing: &str) -> Option<Vec<Transaction>> {
        let wanted: HashSet<[u8; 32]> = crate::p2p::decode_hashes(missing).ok()?.into_iter().collect();
        let p = self.proposal_for(height, round)?;
        Some(p.block.transactions.into_iter().filter(|t| wanted.contains(&t.tx_hash())).collect())
    }

    /// A full proposal we hold for (height, round), to answer a TmProposalRequest.
    pub fn proposal_for(&self, height: u64, round: u64) -> Option<TmProposal> {
        self.gossip.iter().find_map(|m| match m {
            P2PPayload::TmProposal(p) if p.height == height && p.round == round && p.block.receipts.len() == p.block.transactions.len() => Some(p.clone()),
            _ => None,
        })
    }

    pub async fn on_timeout(&mut self, node: &SharedNode, pm: &SharedPeerManager, t: TmTimeout) {
        if t.height != self.height || self.sm.is_none() {
            return;
        }
        self.feed(node, pm, Input::Timeout { kind: kind_code(t.kind), round: t.round }, true).await;
    }

    fn remember_for_gossip(&mut self, msg: &P2PPayload) {
        let sig = match msg {
            P2PPayload::TmProposal(p) => p.signature,
            P2PPayload::TmVote(v) => v.signature,
            _ => return,
        };
        let mut key = [0u8; 32];
        key.copy_from_slice(&sig[..32]);
        if self.gossip.len() < MAX_GOSSIP_MESSAGES && self.gossip_keys.insert(key) {
            self.gossip.push(msg.clone());
        }
    }

    fn wal_append(&mut self, entry: &WalEntry, sync: bool) -> Result<(), String> {
        let f = self.wal.as_mut().ok_or("WAL not open")?;
        let line = serde_json::to_string(entry).map_err(|e| e.to_string())?;
        writeln!(f, "{}", line).map_err(|e| e.to_string())?;
        if sync {
            f.sync_data().map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    /// Feeds one input (and everything it causes) through the engine. `record` = append
    /// it to the WAL (false for WAL replay and for our own messages, which the engine
    /// regenerates deterministically).
    async fn feed(&mut self, node: &SharedNode, pm: &SharedPeerManager, input: Input, record: bool) {
        let mut queue: VecDeque<(Input, bool)> = VecDeque::new();
        queue.push_back((input, record));
        while let Some((input, record)) = queue.pop_front() {
            if record && !self.replaying {
                let t_wal = std::time::Instant::now();
                let r = self.wal_append(&WalEntry::Input(input.clone()), false);
                self.timing.wal_ms += t_wal.elapsed().as_secs_f64() * 1000.0;
                if let Err(e) = r {
                    eprintln!("💥 [TM] WAL write failed: {}. Input dropped.", e);
                    continue;
                }
            }
            let sm = match self.sm.as_mut() {
                Some(sm) => sm,
                None => return,
            };
            let outs = match input {
                Input::Proposal { proposal, valid } => sm.on_proposal(
                    proposal.height, proposal.round, BlockValue(proposal.block),
                    proposal.valid_round, proposal.proposer_pubkey, valid,
                ),
                Input::Vote(v) => {
                    let kind = match v.vote_type {
                        VoteType::PreVote => VoteKind::Prevote,
                        VoteType::PreCommit => VoteKind::Precommit,
                    };
                    let id = if v.block_hash == NIL { None } else { Some(v.block_hash) };
                    sm.on_vote(kind, v.height, v.round, id, v.validator_pubkey, v.signature)
                }
                Input::Value { round, block } => {
                    if self.pending_value == Some(round) {
                        self.pending_value = None;
                    }
                    sm.on_value(self.height, round, BlockValue(block))
                }
                Input::Timeout { kind, round } => sm.on_timeout(kind_from(kind), self.height, round),
            };
            for own in self.process_outputs(node, pm, outs).await {
                queue.push_back((own, false));
            }
        }
    }

    /// Executes engine outputs. Returns our own signed messages, to be fed back.
    async fn process_outputs(&mut self, node: &SharedNode, pm: &SharedPeerManager, outs: Vec<Output<BlockValue, [u8; 64]>>) -> Vec<Input> {
        let mut own = Vec::new();
        for o in outs {
            match o {
                Output::GetValue { round, .. } => {
                    // During WAL replay the value we proposed is in the WAL; build only after.
                    self.pending_value = Some(round);
                    if !self.replaying {
                        if let Some(input) = self.build_value(node, round).await {
                            own.push(input);
                        }
                    }
                }
                Output::Proposal { height, round, value, valid_round } => {
                    let key = match self.key.clone() {
                        Some(k) => k,
                        None => continue,
                    };
                    let id = value.id();
                    if !self.record_signed(0, round, id) {
                        continue;
                    }
                    let proposal = TmProposal::new(&self.chain_id, round, valid_round, value.0, &key);
                    println!("📤 [TM] Proposing block #{} round {} ({} txs, valid_round {:?})",
                        height, round, proposal.block.transactions.len(), valid_round);
                    let msg = P2PPayload::TmProposal(proposal.clone());
                    self.remember_for_gossip(&msg);
                    pm.lock().await.broadcast(msg, None).await;
                    own.push(Input::Proposal { proposal, valid: true });
                }
                Output::Vote { kind, height, round, id } => {
                    let key = match self.key.clone() {
                        Some(k) => k,
                        None => continue,
                    };
                    let (step, vote_type) = match kind {
                        VoteKind::Prevote => (1u8, VoteType::PreVote),
                        VoteKind::Precommit => (2u8, VoteType::PreCommit),
                    };
                    let hash = id.unwrap_or(NIL);
                    if !self.record_signed(step, round, hash) {
                        continue;
                    }
                    if step == 2 && self.timing.precommit_at_ms.is_none() {
                        self.timing.precommit_at_ms = Some(self.timing.since());
                    }
                    let vote = Vote::new(&self.chain_id, height, round, hash, vote_type, &key);
                    let msg = P2PPayload::TmVote(vote.clone());
                    self.remember_for_gossip(&msg);
                    pm.lock().await.broadcast(msg, None).await;
                    own.push(Input::Vote(vote));
                }
                Output::ScheduleTimeout { kind, height, round } => {
                    let tx = self.timer_tx.clone();
                    let d = timeout_duration(kind, round);
                    tokio::spawn(async move {
                        tokio::time::sleep(d).await;
                        let _ = tx.send(TmTimeout { kind, height, round }).await;
                    });
                }
                Output::Decide { height, round, value, commits } => {
                    self.commit(node, pm, height, round, value.0, commits).await;
                    return Vec::new();
                }
                Output::Equivocation { height, round, from } => {
                    eprintln!("⚠️ [TM] Equivocation by validator 0x{}… at #{} round {}",
                        hex::encode(&from[..4]), height, round);
                }
            }
        }
        own
    }

    /// Never sign two different messages for one (height, round, step): checked against
    /// the WAL record and fsynced before the signature leaves the node.
    fn record_signed(&mut self, step: u8, round: u64, id: [u8; 32]) -> bool {
        if let Some(prev) = self.signed.get(&(step, round)) {
            if *prev != id {
                eprintln!("💥 [TM] Refusing to sign a second, different message for #{} round {} step {}", self.height, round, step);
                return false;
            }
            return true; // same message again (e.g. after a restart)
        }
        if let Err(e) = self.wal_append(&WalEntry::Signed { step, round, id }, true) {
            eprintln!("💥 [TM] WAL fsync failed: {}. Not signing.", e);
            return false;
        }
        self.signed.insert((step, round), id);
        true
    }

    async fn build_value(&mut self, node: &SharedNode, round: u64) -> Option<Input> {
        // A proposal we already signed for this round (crash after signing) must be reused.
        if self.signed.contains_key(&(0, round)) {
            return None;
        }
        let inputs = {
            let n = node.read().await;
            if n.height + 1 != self.height || n.mempool.is_empty() {
                return None;
            }
            n.build_inputs().ok()?
        };
        // Built and executed with no lock held (see FullNode::build_block); stored after.
        let t_build = std::time::Instant::now();
        let built = off_runtime(FullNode::build_block(inputs)).await;
        let built = match built {
            Ok(b) => {
                let mut n = node.write().await;
                if n.height + 1 != self.height {
                    return None; // the chain moved on while building
                }
                self.timing.build_ms = Some(t_build.elapsed().as_secs_f64() * 1000.0);
                Ok(n.finish_build(b))
            }
            Err(e) => Err(e),
        };
        match built {
            Ok(block) if block.header.height != self.height => {
                eprintln!("💥 [TM] Built block #{} while deciding #{}: dropped", block.header.height, self.height);
                None
            }
            Ok(mut block) => {
                block.validator_signatures.clear(); // build_proposal adds a legacy vote
                block.commit_round = 0;
                Some(Input::Value { round, block })
            }
            Err(_) => None, // empty mempool: retried on the next tick
        }
    }

    async fn try_build_value(&mut self, node: &SharedNode, pm: &SharedPeerManager, round: u64) {
        let still_proposing = self.sm.as_ref().map_or(false, |sm| sm.round() == round && !sm.is_decided());
        if !still_proposing {
            self.pending_value = None;
            return;
        }
        if let Some(input) = self.build_value(node, round).await {
            self.feed(node, pm, input, true).await;
        }
    }

    async fn commit(&mut self, node: &SharedNode, pm: &SharedPeerManager, height: u64, round: u64, mut block: Block, commits: Vec<(NodeId, [u8; 64])>) {
        block.validator_signatures = commits.into_iter().map(|(pk, sig)| ValidatorCommit::new(pk, sig)).collect();
        Block::canonicalize_commits(&mut block.validator_signatures);
        block.commit_round = round;
        let decide_at = self.timing.since();
        let t_apply = std::time::Instant::now();
        let result = {
            let mut n = node.write().await;
            if n.height + 1 != height {
                Err("height already applied".to_string())
            } else {
                n.apply_block(block.clone()).await
            }
        };
        let apply_ms = t_apply.elapsed().as_secs_f64() * 1000.0;
        match result {
            Ok(hash) => {
                // Times in ms from the start of the height: proposal received or built,
                // own precommit signed (= prevote quorum seen), decided, then apply.
                println!("⏱️ [TM] #{} {} txs | build {} | proposal at {} (validate {}) | wal {:.0} | precommit at {} | decided at {:.0} | apply {:.0} | total {:.0}",
                    height, block.transactions.len(), opt_ms(self.timing.build_ms), opt_ms(self.timing.proposal_at_ms),
                    opt_ms(self.timing.validate_ms), self.timing.wal_ms, opt_ms(self.timing.precommit_at_ms),
                    decide_at, apply_ms, self.timing.since());
                println!("✅ [TM] Block #{} COMMITTED in round {} ({} txs, {} precommits). Hash: 0x{}",
                    height, round, block.transactions.len(), block.validator_signatures.len(), hex::encode(hash));
                self.local_height.store(height, Ordering::Relaxed);
                pm.lock().await.broadcast(P2PPayload::BlockCommit(block), None).await;
            }
            Err(e) => {
                let applied_elsewhere = node.write().await.height >= height;
                if !applied_elsewhere {
                    // Keep the decided engine and the WAL: never restart this height
                    // without its locks. The block will arrive by BlockCommit / sync and
                    // the next tick then moves on.
                    eprintln!("⚠️ [TM] Decided block #{} not applied: {}. Waiting for it from the network.", height, e);
                    return;
                }
            }
        }
        // Straight to the next height (idle until there is work). Its WAL and buffered
        // messages are handled by enter_height / the next tick.
        self.enter_height(height + 1);
    }
}

/// Runs a CPU-heavy future (block execution) on a blocking thread, off the async
/// workers: on a 1-vCPU node the RPC and P2P tasks keep getting CPU time meanwhile.
async fn off_runtime<T: Send + 'static>(f: impl std::future::Future<Output = Result<T, String>> + Send + 'static) -> Result<T, String> {
    let handle = tokio::runtime::Handle::current();
    tokio::task::spawn_blocking(move || handle.block_on(f))
        .await
        .unwrap_or_else(|e| Err(format!("execution task failed: {}", e)))
}

fn message_height(msg: &P2PPayload) -> Option<u64> {
    match msg {
        P2PPayload::TmProposal(p) => Some(p.height),
        P2PPayload::TmVote(v) => Some(v.height),
        _ => None,
    }
}

fn message_round(msg: &P2PPayload) -> u64 {
    match msg {
        P2PPayload::TmProposal(p) => p.round,
        P2PPayload::TmVote(v) => v.round,
        _ => 0,
    }
}
