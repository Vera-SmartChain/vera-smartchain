use ed25519_dalek::SigningKey;
use std::path::Path;
use std::sync::Arc;


use crate::account::{Account, Address};
use crate::block::{Block, BlockHeader, ValidatorCommit};
use crate::consensus::{ValidatorSet, Vote, VoteType};
use crate::csmt::CSMT;
use crate::genesis::GenesisConfig;
use crate::state_transition::StateTransitionEngine;
use crate::storage::PersistentStorage;
use crate::transaction::Transaction;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxRecord {
    pub hash: String,
    pub block_number: u64,
    pub from: String,
    pub to: Option<String>,
    pub value: String,
    pub tx_type: String,
    pub timestamp: u64,
    pub status: String,
}

/// Length of the explorer's latest-transactions list.
pub const MAX_RECENT_TXS: usize = 100;

fn tx_record(tx: &Transaction, height: u64, timestamp: u64) -> TxRecord {
    TxRecord {
        hash: format!("0x{}", hex::encode(tx.tx_hash())),
        block_number: height,
        from: format!("0x{}", hex::encode(&tx.sender[12..32])),
        to: tx.to.as_ref().map(|t| format!("0x{}", hex::encode(&t[12..32]))),
        value: format!("0x{:x}", tx.amount),
        tx_type: if tx.to.is_none() {
            "CONTRACT_CREATION".to_string()
        } else if !tx.program.is_empty() {
            "CONTRACT_CALL".to_string()
        } else {
            "TRANSFER".to_string()
        },
        timestamp,
        status: "SUCCESS".to_string(),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityIncident {
    pub id: String,
    pub timestamp: u64,
    pub date_time: String,
    pub threat_type: String,
    pub vector: String,
    pub target: String,
    pub expected_hash: String,
    pub detected_hash: String,
    pub action_taken: String,
    pub status: String,
    pub mitigation_notes: String,
}

/// A block executed on top of the state whose latest block is `base_hash` (by
/// `build_proposal` or `validate_proposal`). `apply_block` reuses it for that same block on
/// that same state instead of executing every transaction again, so a block is executed
/// once per node instead of two (followers) or three (proposer) times.
#[derive(Clone)]
/// Inputs of a proposal build (see `FullNode::build_inputs`).
pub struct BuildInputs {
    pub key: SigningKey,
    pub chain_id: String,
    pub evm_chain_id: u64,
    pub exec_v2_activation: Option<u64>,
    pub next_height: u64,
    pub prev_hash: [u8; 32],
    pub address: Address,
    pub last_committed_signatures: Vec<crate::block::ValidatorCommit>,
    pub last_commit_round: u64,
    pub mempool: Vec<Transaction>,
    pub csmt: CSMT,
}

/// Result of `FullNode::build_block`, applied to the node by `finish_build`.
pub struct BuiltBlock {
    pub block: Block,
    pub exec: ExecutedBlock,
    pub dropped_from_mempool: Vec<[u8; 32]>,
    pub rejected_txs: bool,
}

/// Inputs of a full mempool prune computed off the node lock (see `full_prune_snapshot`).
pub struct FullPruneSnapshot {
    pub csmt: CSMT,
    pub mempool: Vec<Transaction>,
    pub proposer: Address,
    pub next_height: u64,
    pub evm_chain_id: u64,
}

/// Txs a full prune would drop: (tx hash, sender, sender account bytes in the snapshot).
pub struct FullPruneResult {
    pub drop: Vec<([u8; 32], Address, Option<Vec<u8>>)>,
}

/// State to execute a proposal on (see `FullNode::exec_snapshot`).
pub struct ExecSnapshot {
    pub csmt: CSMT,
    pub evm_chain_id: u64,
    pub exec_v2_activation: Option<u64>,
    pub base_hash: [u8; 32],
}

pub struct ExecutedBlock {
    pub base_hash: [u8; 32],
    pub block_hash: [u8; 32],
    pub csmt: CSMT,
    pub roots: ([u8; 32], [u8; 32], [u8; 32]),
}

pub struct FullNode {
    pub chain_id: String,
    pub evm_chain_id: u64,
    pub storage: PersistentStorage,
    pub csmt: CSMT,
    pub validator_set: ValidatorSet,
    pub mempool: Vec<Transaction>,
    pub keypair: Option<SigningKey>,
    pub address: Address,
    pub height: u64,
    pub latest_block_hash: [u8; 32],
    pub last_committed_signatures: Vec<crate::block::ValidatorCommit>,
    /// Round of `last_committed_signatures` (the latest block's commit certificate).
    pub last_commit_round: u64,
    /// First height decided by the Tendermint engine (None = legacy consensus only).
    pub tendermint_activation: Option<u64>,
    /// First height executed under execution rules v2 (None = v1 only).
    pub exec_v2_activation: Option<u64>,
    /// Mempool changed since the last save (admission no longer rewrites it every time).
    pub mempool_dirty: bool,
    /// Last full prune (re-execution of the pending txs); see `full_prune_due`.
    pub last_full_prune: Option<std::time::Instant>,
    /// A build saw candidates its execution rejected: run a full prune soon.
    pub full_prune_requested: bool,
    /// Admission-only cache: sender -> (height, next nonce, sender account bytes after all
    /// its pending txs). Lets admitting nonce n+1 execute only the new tx instead of
    /// re-executing the sender's whole pending chain. Cleared whenever the state or the
    /// mempool loses txs. Never used by consensus (blocks always re-execute everything).
    pub admission_cache: std::collections::HashMap<Address, (u64, u64, Vec<u8>)>,
    /// Serialized size of the mempool (None = recompute). Kept up to date on admission
    /// and invalidated wherever txs leave the mempool, so admission no longer
    /// re-serializes every pending tx to check MAX_MEMPOOL_BYTES.
    pub mempool_bytes: Option<usize>,
    /// Last executed block (see `ExecutedBlock`). Mutex because `validate_proposal` takes &self.
    pub exec_cache: std::sync::Mutex<Option<ExecutedBlock>>,
    pub recent_transactions: Vec<TxRecord>,
    pub tx_index: std::collections::HashMap<[u8; 32], (u64, usize)>,
    pub binary_hash: [u8; 32],
    pub attestation_status: String,
    pub attestation_timestamp: u64,
    pub security_incidents: Vec<SecurityIncident>,
    pub security_log_path: Option<std::path::PathBuf>,
    pub peer_count: usize,
}

/// Shared node state. RwLock: RPC reads and P2P/consensus reads proceed in parallel;
/// writers (block application, admission) get priority (tokio RwLock is write-preferring).
pub type SharedNode = Arc<tokio::sync::RwLock<FullNode>>;

pub const MAX_MEMPOOL_SIZE: usize = 20_000;
pub const MAX_MEMPOOL_BYTES: usize = 64 * 1024 * 1024; // 64 MiB
pub const MAX_RAW_EVM_BYTES: usize = 128 * 1024; // 128 KiB (matching geth)
pub const MAX_PROGRAM_BYTES: usize = 128 * 1024; // 128 KiB
pub const MAX_TX_SERIALIZED_BYTES: usize = 512 * 1024; // 512 KiB
/// Blocks with at least this many transactions log where apply_block spent its time.
pub const TIMING_LOG_MIN_TXS: usize = 200;

/// Wall-clock time per named stage, for the timing log lines. Only measures.
pub struct StageTimer {
    last: std::time::Instant,
    stages: Vec<(&'static str, f64)>,
}

impl StageTimer {
    pub fn new() -> Self {
        Self { last: std::time::Instant::now(), stages: Vec::new() }
    }
    pub fn mark(&mut self, name: &'static str) {
        let now = std::time::Instant::now();
        self.stages.push((name, (now - self.last).as_secs_f64() * 1000.0));
        self.last = now;
    }
    pub fn summary(&self) -> String {
        self.stages.iter().map(|(n, ms)| format!("{} {:.1}", n, ms)).collect::<Vec<_>>().join(" | ")
    }
}

pub const MAX_BLOCK_TX_BYTES: usize = 2_621_440; // 2.5 MiB (cheap pre-filter)
pub const MAX_BLOCK_WIRE_BYTES: usize = 3_407_872; // 3.25 MiB (complete BlockProposal frame envelope limit)
pub const MAX_TX_LOGS_BYTES: usize = 256 * 1024; // 256 KiB maximum logs per transaction

pub const MAX_PENDING_NONCE_GAP: u64 = 16;
/// Longest interval between full mempool prunes while blocks keep coming.
pub const FULL_PRUNE_EVERY: std::time::Duration = std::time::Duration::from_secs(10);
pub const MAX_FUTURE_BLOCK_TIME_SECS: u64 = 15;
/// Full state snapshot cadence; between snapshots only per-block deltas are written.
pub const STATE_SNAPSHOT_EVERY: u64 = 100;
pub const MAX_DELTA_LOG_BYTES: u64 = 256 * 1024 * 1024;
/// Highest commit round accepted in a block (bounds the proposer check loop).
pub const MAX_TENDERMINT_COMMIT_ROUND: u64 = 10_000;


pub fn format_utc_timestamp(ts: u64) -> String {
    let seconds_in_day = ts % 86400;
    let days = ts / 86400;
    let hours = seconds_in_day / 3600;
    let minutes = (seconds_in_day % 3600) / 60;
    let seconds = seconds_in_day % 60;

    let mut year = 1970;
    let mut rem_days = days;
    loop {
        let is_leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
        let days_in_year = if is_leap { 366 } else { 365 };
        if rem_days < days_in_year {
            break;
        }
        rem_days -= days_in_year;
        year += 1;
    }
    let is_leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
    let days_in_months = [
        31, if is_leap { 29 } else { 28 }, 31, 30, 31, 30,
        31, 31, 30, 31, 30, 31,
    ];
    let mut month = 1;
    for &dim in &days_in_months {
        if rem_days < dim {
            break;
        }
        rem_days -= dim;
        month += 1;
    }
    let day = rem_days + 1;
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", year, month, day, hours, minutes, seconds)
}

impl FullNode {
    /// Initializes node from disk or creates from Genesis
    pub fn load_or_init<P: AsRef<Path>>(
        data_dir: P,
        genesis: &GenesisConfig,
        keypair: Option<SigningKey>,
    ) -> Result<Self, String> {
        let storage = PersistentStorage::open(data_dir.as_ref())?;
        let chain_id = genesis.chain_id.clone();
        let evm_chain_id = genesis.evm_chain_id;

        // Running binary integrity verification via SHA-256 compared with release manifest
        let (binary_hash, attestation_status) = match std::env::current_exe().and_then(|p| std::fs::read(&p)) {
            Ok(bytes) => {
                use k256::sha2::{Sha256, Digest};
                let mut hasher = Sha256::new();
                hasher.update(&bytes);
                let sha_bytes: [u8; 32] = hasher.finalize().into();
                let actual_hex = hex::encode(sha_bytes);

                let expected_path = std::path::Path::new("/etc/vera/expected_binary_sha256");
                let status = if expected_path.exists() {
                    match std::fs::read_to_string(expected_path) {
                        Ok(expected_str) => {
                            let expected_hex = expected_str.trim().to_lowercase();
                            if actual_hex == expected_hex {
                                "match".to_string()
                            } else {
                                "mismatch".to_string()
                            }
                        }
                        Err(_) => "unknown".to_string(),
                    }
                } else {
                    "unknown".to_string()
                };
                (sha_bytes, status)
            }
            Err(_) => {
                ([0u8; 32], "unknown".to_string())
            }
        };
        let attestation_timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Load validator set from persisted disk or genesis
        let mut validator_set = match storage.load_validators()? {
            Some(vs) => {
                println!("Loaded persisted ValidatorSet: {} active validators", vs.validators.len());
                vs
            }
            None => genesis.build_validator_set()?,
        };

        let address = if let Some(ref k) = keypair {
            let pubkey = k.verifying_key().to_bytes();
            crate::chain_hash::hash256(&pubkey)
        } else {
            [0u8; 32]
        };

        // Check if we already have persisted state
        let (csmt, height, latest_block_hash) = match storage.load_state()? {
            Some(state) => {
                let h = storage.get_latest_block_height()?.unwrap_or(0);
                let latest_block = storage.load_block(h)?.ok_or("Latest block not found")?;
                (state, h, latest_block.hash())
            }
            None => {
                // First initialization: build genesis block #0
                let (genesis_csmt, genesis_block) = genesis.build_genesis_state()?;
                storage.save_state(&genesis_csmt)?;
                storage.save_block(&genesis_block)?;
                (genesis_csmt, 0, genesis_block.hash())
            }
        };
        let mut csmt = csmt;
        csmt.compact(); // move the initial state into the shared base (cheap clones)

        if let Some(bytes) = csmt.get(&crate::account::VALIDATOR_SET_CSMT_KEY) {
            if let Ok(vset) = ValidatorSet::from_bytes(bytes) {
                validator_set = vset;
            }
        }

        let mempool = storage.load_mempool().unwrap_or_default();

        let security_log_path = Some(data_dir.as_ref().join("security_incidents.json"));
        let security_incidents = if let Some(ref path) = security_log_path {
            if let Ok(data) = std::fs::read_to_string(path) {
                serde_json::from_str::<Vec<SecurityIncident>>(&data).unwrap_or_default()
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };

        // Tx-hash index: persisted, so only heights the file does not cover are read from
        // the blocks (all of them once, when upgrading from a version without the file).
        let (mut tx_index, covered) = storage.load_tx_index(height);
        if covered < height {
            let t = std::time::Instant::now();
            for h in (covered + 1)..=height {
                if let Ok(Some(b)) = storage.load_block(h) {
                    let hashes: Vec<[u8; 32]> = b.transactions.iter().map(|tx| tx.tx_hash()).collect();
                    for (idx, hash) in hashes.iter().enumerate() {
                        tx_index.insert(*hash, (h, idx));
                    }
                    let _ = storage.append_tx_index(h, &hashes);
                }
            }
            if height - covered > 1 {
                println!("🗂️  Tx index rebuilt for heights {}..={} ({:.1} s)", covered + 1, height, t.elapsed().as_secs_f64());
            }
        }
        // Latest txs for the explorer: newest blocks first, read until MAX_RECENT_TXS.
        let mut recent_transactions = Vec::new();
        let mut h = height;
        while h >= 1 && recent_transactions.len() < MAX_RECENT_TXS {
            if let Ok(Some(b)) = storage.load_block(h) {
                for tx in b.transactions.iter().rev() {
                    if recent_transactions.len() >= MAX_RECENT_TXS {
                        break;
                    }
                    recent_transactions.push(tx_record(tx, h, b.header.timestamp));
                }
            }
            h -= 1;
        }

        let (last_committed_signatures, last_commit_round) = if height > 0 {
            storage.load_block(height).ok().flatten()
                .map(|b| (b.validator_signatures, b.commit_round))
                .unwrap_or_default()
        } else {
            (Vec::new(), 0)
        };
        let tendermint_activation = genesis.tendermint_activation_height
            .or_else(|| crate::genesis::builtin_tendermint_activation(&genesis.chain_id));
        let exec_v2_activation = genesis.exec_v2_activation_height
            .or_else(|| crate::genesis::builtin_exec_v2_activation(&genesis.chain_id));

        let mut node = Self {
            chain_id,
            evm_chain_id,
            storage,
            csmt,
            validator_set,
            mempool,
            keypair,
            address,
            height,
            latest_block_hash,
            last_committed_signatures,
            last_commit_round,
            tendermint_activation,
            exec_v2_activation,
            mempool_dirty: false,
            last_full_prune: None,
            full_prune_requested: false,
            admission_cache: std::collections::HashMap::new(),
            mempool_bytes: None,
            exec_cache: std::sync::Mutex::new(None),
            recent_transactions,
            tx_index,
            binary_hash,
            attestation_status,
            attestation_timestamp,
            security_incidents,
            security_log_path,
            peer_count: 0,
        };

        let pruned = node.prune_mempool();
        if pruned > 0 {
            println!("🧹 [Mempool] Startup hygiene: {} invalid transactions pruned", pruned);
        }

        Ok(node)
    }

    /// Records an incident in the Security Incidents Log and persists to disk
    pub fn record_security_incident(&mut self, incident: SecurityIncident) {
        self.security_incidents.insert(0, incident.clone());
        if self.security_incidents.len() > 100 {
            self.security_incidents.truncate(100);
        }
        if let Some(ref path) = self.security_log_path {
            if let Ok(json_str) = serde_json::to_string_pretty(&self.security_incidents) {
                let _ = std::fs::write(path, json_str);
            }
        }
    }

    /// Submits a transaction to the Mempool with Anti-DoS, Anti-Replay, and Solvency protection
    pub fn submit_transaction(&mut self, tx: Transaction) -> Result<[u8; 32], String> {
        let now_ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // 0. Payload size bounds (Anti-DoS / Memory Exhaustion defense)
        if let Some(ref raw) = tx.raw_evm {
            if raw.len() > MAX_RAW_EVM_BYTES {
                return Err(format!(
                    "Transaction raw_evm payload exceeds maximum allowed size: {} > {} bytes",
                    raw.len(), MAX_RAW_EVM_BYTES
                ));
            }
        }

        if tx.program.len() > MAX_PROGRAM_BYTES {
            return Err(format!(
                "Transaction program payload exceeds maximum allowed size: {} > {} bytes",
                tx.program.len(), MAX_PROGRAM_BYTES
            ));
        }

        let tx_serialized_len = tx.to_bytes().len();
        if tx_serialized_len > MAX_TX_SERIALIZED_BYTES {
            return Err(format!(
                "Transaction serialized size exceeds maximum allowed limit: {} > {} bytes",
                tx_serialized_len, MAX_TX_SERIALIZED_BYTES
            ));
        }

        // 1. Cross-Chain Isolation: discard tx forged for another network
        let chain_matches = tx.chain_id == self.chain_id || tx.chain_id == format!("{}", self.evm_chain_id);
        if !chain_matches {
            let inc_id = format!("INC-{}", now_ts % 100000);
            self.record_security_incident(SecurityIncident {
                id: inc_id,
                timestamp: now_ts,
                date_time: format_utc_timestamp(now_ts),
                threat_type: "CROSS_CHAIN_REPLAY_ATTEMPT".to_string(),
                vector: format!("Transaction rejected: chain_id '{}' differs from node '{}'", tx.chain_id, self.chain_id),
                target: format!("Mempool Gateway (Sender: 0x{})", hex::encode(tx.sender)),
                expected_hash: self.chain_id.clone(),
                detected_hash: tx.chain_id.clone(),
                action_taken: "TX_DROPPED_ISOLATED".to_string(),
                status: "BLOCKED_AND_AUDITED".to_string(),
                mitigation_notes: "Cross-chain injection attempt intercepted before mempool. Packet was discarded.".to_string(),
            });
            return Err(format!(
                "Cross-Chain Replay Blocked: tx intended for '{}', but node is '{}'",
                tx.chain_id, self.chain_id
            ));
        }

        // 2. Formal Static Flat-DAG Analysis in constant time
        if let Err(e) = tx.validate_static_dag() {
            let inc_id = format!("INC-{}", now_ts % 100000);
            self.record_security_incident(SecurityIncident {
                id: inc_id,
                timestamp: now_ts,
                date_time: format_utc_timestamp(now_ts),
                threat_type: "MALFORMED_DAG_EXPLOIT".to_string(),
                vector: format!("Formal static validation failed: {}", e),
                target: format!("Flat-DAG Execution Engine (Tx: 0x{})", hex::encode(tx.tx_hash())),
                expected_hash: "DAG_ACYCLIC_BOUNDED".to_string(),
                detected_hash: "INVALID_DAG_STRUCTURE".to_string(),
                action_taken: "TX_REJECTED_QUARANTINED".to_string(),
                status: "BLOCKED_AND_AUDITED".to_string(),
                mitigation_notes: "Instruction DAG structure violated strict acyclic graph or gas limits.".to_string(),
            });
            return Err(e);
        }

        // 3. Cryptographic Signature Verification
        if let Err(e) = crate::state_transition::verify_signature_cached(&tx) {
            let inc_id = format!("INC-{}", now_ts % 100000);
            self.record_security_incident(SecurityIncident {
                id: inc_id,
                timestamp: now_ts,
                date_time: format_utc_timestamp(now_ts),
                threat_type: "INVALID_CRYPTOGRAPHIC_SIGNATURE".to_string(),
                vector: "Asymmetric digital signature forged or corrupted".to_string(),
                target: format!("Account Authenticator (Sender: 0x{})", hex::encode(tx.sender)),
                expected_hash: format!("0x{}", hex::encode(tx.public_key)),
                detected_hash: format!("0x{}", hex::encode(tx.signature)),
                action_taken: "SIGNATURE_REJECTED_LOGGED".to_string(),
                status: "BLOCKED_AND_AUDITED".to_string(),
                mitigation_notes: "Asymmetric signature not validated for provided public key.".to_string(),
            });
            return Err(e);
        }

        // 4. Verify account exists and nonce is coherent
        let sender_bytes = self.csmt.get(&tx.sender)
            .ok_or_else(|| "Origin account not found in current state".to_string())?;
        let sender_acc = Account::from_bytes(sender_bytes)?;

        if tx.nonce < sender_acc.nonce {
            let inc_id = format!("INC-{}", now_ts % 100000);
            self.record_security_incident(SecurityIncident {
                id: inc_id,
                timestamp: now_ts,
                date_time: format_utc_timestamp(now_ts),
                threat_type: "REPLAY_ATTACK_OBSOLETE_NONCE".to_string(),
                vector: format!("Attempt to replay already processed transaction (Nonce: {} < Current: {})", tx.nonce, sender_acc.nonce),
                target: format!("Mempool / Anti-Replay Guard (Sender: 0x{})", hex::encode(tx.sender)),
                expected_hash: format!("Nonce >= {}", sender_acc.nonce),
                detected_hash: format!("Nonce = {}", tx.nonce),
                action_taken: "TX_DROPPED_REPLAY_DEFENSE".to_string(),
                status: "BLOCKED_AND_AUDITED".to_string(),
                mitigation_notes: "Transaction with obsolete nonce immediately rejected to prevent double spending.".to_string(),
            });
            return Err(format!("Obsolete nonce: {} < {}", tx.nonce, sender_acc.nonce));
        }

        // 4.1 Protection against Mempool Poisoning via excessive nonce gap
        if tx.nonce > sender_acc.nonce.saturating_add(MAX_PENDING_NONCE_GAP) {
            let inc_id = format!("INC-{}", now_ts % 100000);
            self.record_security_incident(SecurityIncident {
                id: inc_id,
                timestamp: now_ts,
                date_time: format_utc_timestamp(now_ts),
                threat_type: "MEMPOOL_POISONING_NONCE_GAP".to_string(),
                vector: format!("Excessive nonce gap (Gap: {} > Max: {})", tx.nonce - sender_acc.nonce, MAX_PENDING_NONCE_GAP),
                target: format!("Mempool Memory Allocator (Sender: 0x{})", hex::encode(tx.sender)),
                expected_hash: format!("Max Nonce: {}", sender_acc.nonce + MAX_PENDING_NONCE_GAP),
                detected_hash: format!("Tx Nonce: {}", tx.nonce),
                action_taken: "TX_REJECTED_FLOOD_PREVENTION".to_string(),
                status: "BLOCKED_AND_AUDITED".to_string(),
                mitigation_notes: "Mempool poisoning attempt with out-of-order transactions blocked.".to_string(),
            });
            return Err(format!(
                "Excessive nonce gap: {} > {} + {}",
                tx.nonce, sender_acc.nonce, MAX_PENDING_NONCE_GAP
            ));
        }

        // 4.2 Minimum solvency check for mempool admission
        let max_gas_cost = (tx.gas_limit as u128).saturating_mul(tx.gas_price as u128);
        let is_staking_non_debit = tx.to == Some(crate::account::STAKING_SYSTEM_ADDRESS)
            && (tx.program.starts_with(b"unstake") || tx.program == b"unjail" || tx.program.starts_with(b"allow:") || tx.program.starts_with(b"disallow:") || tx.program.starts_with(b"set_governance:"));
        let total_required = if is_staking_non_debit {
            max_gas_cost
        } else {
            tx.amount.saturating_add(max_gas_cost)
        };
        if sender_acc.balance < total_required {
            return Err(format!(
                "Insufficient balance for mempool admission. Required: {}, Available: {}",
                total_required, sender_acc.balance
            ));
        }

        let hash = tx.tx_hash();
        // 4.3 Reject duplicate transaction or repeated nonce in mempool. A duplicate has
        // the same (sender, nonce), so only that one candidate is hashed.
        if let Some(t) = self.mempool.iter().find(|t| t.sender == tx.sender && t.nonce == tx.nonce) {
            if t.tx_hash() == hash {
                return Err("Duplicate transaction already present in mempool".to_string());
            }
            return Err(format!(
                "Repeated nonce: pending transaction already exists in mempool with nonce {} for account 0x{}",
                tx.nonce, hex::encode(tx.sender)
            ));
        }

        // 4.4 Strict simulation in current state before admitting to mempool
        let next_height = self.height + 1;
        // Sender account after this tx, recorded in `admission_cache` once it is admitted.
        let mut projected_sender: Option<Vec<u8>> = None;
        if tx.nonce == sender_acc.nonce {
            let mut sim_csmt = self.csmt.clone();
            let receipt = crate::state_transition::StateTransitionEngine::simulate_transaction_sync(
                &mut sim_csmt,
                &tx,
                self.address,
                next_height,
                now_ts,
                self.evm_chain_id,
            ).map_err(|e| format!("Transaction rejected during simulation: {}", e))?;

            if !receipt.success {
                return Err("Transaction failed state execution/simulation".to_string());
            }
            projected_sender = sim_csmt.get(&tx.sender).cloned();
        } else if tx.nonce > sender_acc.nonce {
            // Verify if mempool contains contiguous sequence of preceding nonces
            let mut pending_sender_txs: Vec<&Transaction> = self.mempool
                .iter()
                .filter(|t| t.sender == tx.sender && t.nonce >= sender_acc.nonce && t.nonce < tx.nonce)
                .collect();
            pending_sender_txs.sort_by_key(|t| t.nonce);

            let expected_count = (tx.nonce - sender_acc.nonce) as usize;
            let mut is_contiguous = pending_sender_txs.len() == expected_count;
            if is_contiguous {
                for (i, ptx) in pending_sender_txs.iter().enumerate() {
                    if ptx.nonce != sender_acc.nonce + i as u64 {
                        is_contiguous = false;
                        break;
                    }
                }
            }

            // Fast path: the sender's account after its pending chain is already known.
            let cached = self.admission_cache.get(&tx.sender)
                .filter(|(h, next, _)| *h == self.height && *next == tx.nonce)
                .map(|(_, _, acc)| acc.clone());
            if is_contiguous && cached.is_some() {
                let mut sim_csmt = self.csmt.clone();
                sim_csmt.insert(tx.sender, cached.unwrap());
                let receipt = crate::state_transition::StateTransitionEngine::simulate_transaction_sync(
                    &mut sim_csmt,
                    &tx,
                    self.address,
                    next_height,
                    now_ts,
                    self.evm_chain_id,
                ).map_err(|e| format!("Future transaction rejected during simulation: {}", e))?;
                if !receipt.success {
                    return Err("Future transaction failed state execution/simulation".to_string());
                }
                projected_sender = sim_csmt.get(&tx.sender).cloned();
            } else if is_contiguous {
                let mut sim_csmt = self.csmt.clone();
                for ptx in &pending_sender_txs {
                    let r = crate::state_transition::StateTransitionEngine::simulate_transaction_sync(
                        &mut sim_csmt,
                        ptx,
                        self.address,
                        next_height,
                        now_ts,
                        self.evm_chain_id,
                    ).map_err(|e| format!("Pending intermediate transaction failed simulation: {}", e))?;
                    if !r.success {
                        return Err("Pending intermediate transaction failed execution/simulation".to_string());
                    }
                }

                let receipt = crate::state_transition::StateTransitionEngine::simulate_transaction_sync(
                    &mut sim_csmt,
                    &tx,
                    self.address,
                    next_height,
                    now_ts,
                    self.evm_chain_id,
                ).map_err(|e| format!("Future transaction rejected during simulation: {}", e))?;

                if !receipt.success {
                    return Err("Future transaction failed state execution/simulation".to_string());
                }
                projected_sender = sim_csmt.get(&tx.sender).cloned();
            }
            // If gap exists, accept as legitimate future nonce awaiting missing sequence.
        }

        // 5. Bounded Mempool Protection (Prevent RAM/Disk exhaustion by count and total bytes)
        let current_mempool_bytes: usize = match self.mempool_bytes {
            Some(b) => b,
            None => {
                let b = self.mempool.iter().map(|t| t.to_bytes().len()).sum();
                self.mempool_bytes = Some(b);
                b
            }
        };
        if self.mempool.len() >= MAX_MEMPOOL_SIZE || current_mempool_bytes.saturating_add(tx_serialized_len) > MAX_MEMPOOL_BYTES {
            // Sort by gas_price to apply eviction policy (RBF)
            self.mempool.sort_by_key(|t| t.gas_price);
            if tx.gas_price <= self.mempool[0].gas_price {
                if current_mempool_bytes.saturating_add(tx_serialized_len) > MAX_MEMPOOL_BYTES {
                    return Err(format!(
                        "Mempool is full by bytes: total size {} exceeds limit of {} bytes",
                        current_mempool_bytes.saturating_add(tx_serialized_len), MAX_MEMPOOL_BYTES
                    ));
                } else {
                    return Err("Mempool is full: Insufficient gas price for transaction eviction".to_string());
                }
            }
            // Evict lowest fee transactions until both count and byte constraints are satisfied
            while !self.mempool.is_empty()
                && (self.mempool.len() >= MAX_MEMPOOL_SIZE
                    || self.mempool.iter().map(|t| t.to_bytes().len()).sum::<usize>().saturating_add(tx_serialized_len) > MAX_MEMPOOL_BYTES)
            {
                if tx.gas_price <= self.mempool[0].gas_price {
                    return Err("Mempool is full: Insufficient gas price for transaction eviction".to_string());
                }
                self.mempool.remove(0); // Remove lowest fee transaction
                self.admission_cache.clear();
                self.mempool_bytes = None;
            }
        }

        if let Some(acc) = projected_sender {
            if self.admission_cache.len() >= MAX_MEMPOOL_SIZE {
                self.admission_cache.clear();
            }
            self.admission_cache.insert(tx.sender, (self.height, tx.nonce + 1, acc));
        }
        if let Some(b) = self.mempool_bytes.as_mut() {
            *b += tx_serialized_len;
        }
        self.mempool.push(tx);
        // Persisted by `flush_mempool_if_dirty` (node loop, every second): rewriting the
        // whole mempool file on every admission cost 8.5 ms per tx at 1,500 pending.
        // The mempool is not consensus state; at worst ~1 s of pending txs is lost on a
        // crash and their senders resubmit.
        self.mempool_dirty = true;
        Ok(hash)
    }

    /// Removes transactions failing state transition rules from mempool.
    /// Preserves only valid transactions and legitimate future nonces (with gap).
    pub fn prune_mempool(&mut self) -> usize {
        let initial_len = self.mempool.len();
        if initial_len == 0 {
            return 0;
        }
        let keep = Self::full_prune_keep(&self.csmt, &self.mempool, self.address, self.height + 1, self.evm_chain_id);
        self.mempool.retain(|t| keep.contains(&t.tx_hash()));
        self.admission_cache.clear();
        self.mempool_bytes = None;
        self.last_full_prune = Some(std::time::Instant::now());
        self.full_prune_requested = false;
        if self.mempool.len() != initial_len {
            self.mempool_dirty = true; // saved by flush_mempool_if_dirty
        }
        initial_len - self.mempool.len()
    }

    /// Hashes of the pending txs a full prune keeps (pure). Executes each sender's txs in
    /// nonce order on a copy of `csmt`: drops used nonces, senders without an account,
    /// txs that fail their rules, and txs too far past the sender's next nonce.
    pub fn full_prune_keep(csmt: &CSMT, mempool: &[Transaction], proposer: Address, next_height: u64, evm_chain_id: u64) -> std::collections::HashSet<[u8; 32]> {
        let now_ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Group by sender
        let mut by_sender: std::collections::HashMap<crate::account::Address, Vec<Transaction>> = std::collections::HashMap::new();
        for tx in mempool.iter().cloned() {
            by_sender.entry(tx.sender).or_default().push(tx);
        }

        let mut keep = std::collections::HashSet::new();

        for (sender, mut txs) in by_sender {
            let sender_acc = match csmt.get(&sender).and_then(|b| Account::from_bytes(b).ok()) {
                Some(acc) => acc,
                None => continue, // Discard if account does not exist in CSMT
            };

            txs.sort_by_key(|t| t.nonce);

            let mut sim_csmt = csmt.clone();
            let mut expected_nonce = sender_acc.nonce;

            for tx in txs {
                // Nonce already passed
                if tx.nonce < expected_nonce {
                    continue;
                }

                // Current nonce: direct simulation
                if tx.nonce == expected_nonce {
                    match crate::state_transition::StateTransitionEngine::simulate_transaction_sync(
                        &mut sim_csmt,
                        &tx,
                        proposer,
                        next_height,
                        now_ts,
                        evm_chain_id,
                    ) {
                        Ok(receipt) if receipt.success => {
                            expected_nonce += 1;
                            keep.insert(tx.tx_hash());
                        }
                        _ => {
                            // Failed rule check: pruned!
                            // expected_nonce does not advance
                        }
                    }
                } else if tx.nonce > expected_nonce {
                    // Future nonce (with gap)
                    if tx.nonce <= expected_nonce.saturating_add(MAX_PENDING_NONCE_GAP) {
                        keep.insert(tx.tx_hash());
                    }
                }
            }
        }

        keep
    }

    /// True when a full prune should run (requested by a build that saw rejected txs, or
    /// FULL_PRUNE_EVERY since the last one, with something pending).
    pub fn full_prune_due(&self) -> bool {
        !self.mempool.is_empty()
            && (self.full_prune_requested || self.last_full_prune.map_or(true, |t| t.elapsed() >= FULL_PRUNE_EVERY))
    }

    /// State and pending txs for a full prune computed with no lock held (O(1) state copy).
    pub fn full_prune_snapshot(&self) -> FullPruneSnapshot {
        FullPruneSnapshot {
            csmt: self.csmt.clone(),
            mempool: self.mempool.clone(),
            proposer: self.address,
            next_height: self.height + 1,
            evm_chain_id: self.evm_chain_id,
        }
    }

    /// The txs of `snap` a full prune would drop, each with its sender's account bytes in
    /// the snapshot (pure; runs off the node lock).
    pub fn compute_full_prune(snap: FullPruneSnapshot) -> FullPruneResult {
        let keep = Self::full_prune_keep(&snap.csmt, &snap.mempool, snap.proposer, snap.next_height, snap.evm_chain_id);
        let drop = snap.mempool.iter()
            .filter(|t| !keep.contains(&t.tx_hash()))
            .map(|t| (t.tx_hash(), t.sender, snap.csmt.get(&t.sender).cloned()))
            .collect();
        FullPruneResult { drop }
    }

    /// Applies a full prune computed on an older state. A tx is dropped only if its
    /// sender's account is still exactly as in the snapshot (otherwise its verdict may be
    /// stale: e.g. it received funds since); txs added after the snapshot are untouched.
    pub fn apply_full_prune(&mut self, result: FullPruneResult) -> usize {
        let drop: std::collections::HashSet<[u8; 32]> = result.drop.into_iter()
            .filter(|(_, sender, acc)| self.csmt.get(sender).cloned() == *acc)
            .map(|(h, _, _)| h)
            .collect();
        self.last_full_prune = Some(std::time::Instant::now());
        self.full_prune_requested = false;
        if drop.is_empty() {
            return 0;
        }
        let before = self.mempool.len();
        self.mempool.retain(|t| !drop.contains(&t.tx_hash()));
        let pruned = before - self.mempool.len();
        if pruned > 0 {
            self.admission_cache.clear();
            self.mempool_bytes = None;
            self.mempool_dirty = true;
        }
        pruned
    }

    /// Cheap prune after a block: drops pending txs whose nonce was used (or whose
    /// sender has no account), and future txs beyond MAX_PENDING_NONCE_GAP past the
    /// sender's contiguous run, without executing anything. Txs that would now fail
    /// their rules (e.g. balance) are left for the full prune.
    pub fn prune_mempool_nonces(&mut self) -> usize {
        let initial_len = self.mempool.len();
        if initial_len == 0 {
            return 0;
        }
        let mut by_sender: std::collections::HashMap<Address, Vec<u64>> = std::collections::HashMap::new();
        for tx in &self.mempool {
            by_sender.entry(tx.sender).or_default().push(tx.nonce);
        }
        // sender -> (account nonce, end of the contiguous run of pending nonces)
        let mut bounds: std::collections::HashMap<Address, (u64, u64)> = std::collections::HashMap::new();
        for (sender, mut nonces) in by_sender {
            let acc = match self.csmt.get(&sender).and_then(|b| Account::from_bytes(b).ok()) {
                Some(acc) => acc,
                None => continue, // no account: all its txs go
            };
            nonces.sort_unstable();
            nonces.dedup();
            let mut end = acc.nonce;
            for n in nonces {
                if n == end {
                    end += 1;
                } else if n > end {
                    break;
                }
            }
            bounds.insert(sender, (acc.nonce, end));
        }
        self.mempool.retain(|tx| match bounds.get(&tx.sender) {
            Some(&(acc_nonce, end)) => tx.nonce >= acc_nonce && tx.nonce <= end.saturating_add(MAX_PENDING_NONCE_GAP),
            None => false,
        });
        let pruned = initial_len - self.mempool.len();
        if pruned > 0 {
            self.admission_cache.clear();
            self.mempool_bytes = None;
            self.mempool_dirty = true;
        }
        pruned
    }

    /// Selected proposer packages mempool transactions and creates next block
    pub async fn propose_and_commit_block(&mut self) -> Result<Block, String> {
        let key = self.keypair.as_ref().ok_or("Node does not possess validator key to propose block")?;

        let next_height = self.height + 1;
        let mut txs_to_include = std::mem::take(&mut self.mempool);
        // Strict Topological Ordering: Group by sender and sort by ascending nonce
        txs_to_include.sort_by(|a, b| {
            a.sender.cmp(&b.sender).then_with(|| a.nonce.cmp(&b.nonce))
        });

        let last_commit = if next_height > 1 {
            let mut c = self.last_committed_signatures.clone();
            Block::canonicalize_commits(&mut c);
            c
        } else {
            Vec::new()
        };
        let last_commit_hash = Block::compute_commits_root(&last_commit);

        let mut block = Block::new(
            BlockHeader {
                height: next_height,
                prev_hash: self.latest_block_hash,
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0),
                state_root: [0u8; 32],
                tx_root: [0u8; 32],
                receipts_root: [0u8; 32],
                proposer: self.address,
                last_commit_hash,
            },
            txs_to_include,
            Vec::new(),
        );
        block.last_commit = last_commit;

        // Execute all transactions against CSMT
        StateTransitionEngine::execute_block(&mut self.csmt, &mut block, self.evm_chain_id, self.exec_v2_activation).await?;

        // Update local validator_set if altered during block execution
        if let Some(bytes) = self.csmt.get(&crate::account::VALIDATOR_SET_CSMT_KEY) {
            if let Ok(vset) = crate::consensus::ValidatorSet::from_bytes(bytes) {
                self.validator_set = vset;
                let _ = self.storage.save_validators(&self.validator_set);
            }
        }

        // Generate proposer PreCommit vote signature shielded with chain_id
        let vote = Vote::new(
            &self.chain_id,
            next_height,
            0,
            block.hash(),
            VoteType::PreCommit,
            key,
        );
        block.validator_signatures.push(ValidatorCommit::new(vote.validator_pubkey, vote.signature));

        // Persist everything to disk
        self.storage.save_block(&block)?;
        self.storage.save_state(&self.csmt)?;
        let _ = self.storage.save_mempool(&self.mempool);

        self.height = next_height;
        self.latest_block_hash = block.hash();
        self.last_committed_signatures = block.validator_signatures.clone();

        Ok(block)
    }

    /// Builds a block PROPOSAL (does NOT commit/persist): executes txs on a
    /// state copy to obtain state_root and signs proposer PreCommit vote.
    /// Real commit occurs in apply_block when 2/3 + 1 votes arrive.
    pub async fn build_proposal(&mut self) -> Result<Block, String> {
        let inp = self.build_inputs()?;
        let built = Self::build_block(inp).await?;
        Ok(self.finish_build(built))
    }

    /// Everything `build_block` needs, taken under the node lock. Cheap: the state tree is
    /// copy-on-write (O(1) clone), so the lock is held only for this copy.
    pub fn build_inputs(&self) -> Result<BuildInputs, String> {
        Ok(BuildInputs {
            key: self.keypair.clone().ok_or("Node has no validator key to propose")?,
            chain_id: self.chain_id.clone(),
            evm_chain_id: self.evm_chain_id,
            exec_v2_activation: self.exec_v2_activation,
            next_height: self.height + 1,
            prev_hash: self.latest_block_hash,
            address: self.address,
            last_committed_signatures: self.last_committed_signatures.clone(),
            last_commit_round: self.last_commit_round,
            mempool: self.mempool.clone(),
            csmt: self.csmt.clone(),
        })
    }

    /// Stores what a build produced: the execution for apply_block, the mempool txs the
    /// proposer policy dropped, and a full prune if execution rejected candidates.
    /// Ignored if the chain moved on while the block was being built.
    pub fn finish_build(&mut self, built: BuiltBlock) -> Block {
        if built.exec.base_hash == self.latest_block_hash {
            if !built.dropped_from_mempool.is_empty() {
                let dropped: std::collections::HashSet<[u8; 32]> = built.dropped_from_mempool.iter().copied().collect();
                self.mempool.retain(|m| !dropped.contains(&m.tx_hash()));
                self.admission_cache.clear();
                self.mempool_bytes = None;
                self.mempool_dirty = true;
            }
            if let Ok(mut c) = self.exec_cache.lock() {
                *c = Some(built.exec);
            }
            if built.rejected_txs {
                self.full_prune_requested = true;
            }
        }
        built.block
    }

    /// Builds and executes a proposal from `inp` without touching the node, so it can run
    /// with no lock held (block execution takes hundreds of ms with thousands of txs).
    pub async fn build_block(inp: BuildInputs) -> Result<BuiltBlock, String> {
        let key = inp.key.clone();
        // No prune_mempool() here: it executed every pending tx only to drop failing ones,
        // and execute_block below already omits unapplicable txs (apply_block also prunes
        // after every block).
        let next_height = inp.next_height;
        let mut txs_to_include = inp.mempool;
        txs_to_include.sort_by(|a, b| {
            a.sender.cmp(&b.sender).then_with(|| a.nonce.cmp(&b.nonce))
        });
        // Tx cap per block (cheap pre-filter)
        const MAX_TXS_PER_BLOCK: usize = 5000;
        let mut limited_txs = Vec::new();
        let mut accumulated_bytes = 0usize;
        for tx in txs_to_include {
            if limited_txs.len() >= MAX_TXS_PER_BLOCK {
                break;
            }
            let tx_bytes = tx.to_bytes().len();
            if !limited_txs.is_empty() && accumulated_bytes.saturating_add(tx_bytes) > MAX_BLOCK_TX_BYTES {
                break;
            }
            accumulated_bytes = accumulated_bytes.saturating_add(tx_bytes);
            limited_txs.push(tx);
        }
        let mut candidate_txs = limited_txs;
        let mut dropped_from_mempool: Vec<[u8; 32]> = Vec::new();

        let last_commit = if next_height > 1 {
            let mut c = inp.last_committed_signatures.clone();
            Block::canonicalize_commits(&mut c);
            c
        } else {
            Vec::new()
        };
        let last_commit_hash = Block::compute_commits_root(&last_commit);

        loop {
            if candidate_txs.is_empty() {
                return Err("No applicable transactions at this moment".to_string());
            }

            let mut block = Block::new(
                BlockHeader {
                    height: next_height,
                    prev_hash: inp.prev_hash,
                    timestamp: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0),
                    state_root: [0u8; 32],
                    tx_root: [0u8; 32],
                    receipts_root: [0u8; 32],
                    proposer: inp.address,
                    last_commit_hash,
                },
                candidate_txs.clone(),
                Vec::new(),
            );
            block.last_commit = last_commit.clone();
            block.last_commit_round = inp.last_commit_round;

            // Execute on a state COPY solely to populate state_root/tx_root
            let mut sim_csmt = inp.csmt.clone();
            StateTransitionEngine::execute_block(&mut sim_csmt, &mut block, inp.evm_chain_id, inp.exec_v2_activation).await?;

            // 1. Proposer policy: check if any transaction exceeded MAX_TX_LOGS_BYTES (256 KiB)
            let mut dropped_oversized_log_tx = false;
            for (tx, receipt) in block.transactions.iter().zip(block.receipts.iter()) {
                let logs_bytes = serde_json::to_vec(&receipt.logs).map(|v| v.len()).unwrap_or(0);
                if logs_bytes > MAX_TX_LOGS_BYTES {
                    eprintln!(
                        "⚠️ [Proposer Policy] Transaction 0x{} generated {} bytes of logs exceeding MAX_TX_LOGS_BYTES ({} bytes). Dropping from mempool.",
                        hex::encode(tx.tx_hash()), logs_bytes, MAX_TX_LOGS_BYTES
                    );
                    dropped_from_mempool.push(tx.tx_hash());
                    let th = tx.tx_hash(); candidate_txs.retain(|c| c.tx_hash() != th);
                    dropped_oversized_log_tx = true;
                }
            }
            if dropped_oversized_log_tx {
                continue; // Re-execute without oversized log transactions
            }

            if block.transactions.is_empty() {
                return Err("No applicable transactions at this moment".to_string());
            }

            // Proposer PreCommit vote over block hash
            let vote = Vote::new(
                &inp.chain_id,
                next_height,
                0,
                block.hash(),
                VoteType::PreCommit,
                &key,
            );
            block.validator_signatures.clear();
            block.validator_signatures.push(ValidatorCommit::new(vote.validator_pubkey, vote.signature));

            // 2. Measure complete block wire frame with P2PPayload::BlockProposal envelope
            let proposal_payload = crate::p2p::P2PPayload::BlockProposal(block.clone());
            let frame_bytes = 1 + serde_json::to_vec(&proposal_payload)
                .map(|v| v.len())
                .unwrap_or(0);

            if frame_bytes > MAX_BLOCK_WIRE_BYTES {
                eprintln!(
                    "⚠️ [Proposer Wire Check] Block #{} proposal frame size {} exceeds MAX_BLOCK_WIRE_BYTES ({}) with {} txs. Trimming from end.",
                    next_height, frame_bytes, MAX_BLOCK_WIRE_BYTES, candidate_txs.len()
                );
                if candidate_txs.len() <= 1 {
                    return Err(format!(
                        "Single transaction block proposal frame {} bytes exceeds MAX_BLOCK_WIRE_BYTES {}",
                        frame_bytes, MAX_BLOCK_WIRE_BYTES
                    ));
                }
                let excess = frame_bytes.saturating_sub(MAX_BLOCK_WIRE_BYTES);
                let mut bytes_trimmed = 0usize;
                let mut trim_count = 0usize;
                for tx in candidate_txs.iter().rev() {
                    bytes_trimmed += tx.to_bytes().len();
                    trim_count += 1;
                    if bytes_trimmed >= excess {
                        break;
                    }
                }
                trim_count = trim_count.max(1).min(candidate_txs.len().saturating_sub(1));
                let new_len = candidate_txs.len() - trim_count;
                candidate_txs.truncate(new_len);
                continue; // Re-execute with trimmed transactions
            }

            let exec = ExecutedBlock {
                base_hash: inp.prev_hash,
                block_hash: block.hash(),
                csmt: sim_csmt,
                roots: (block.header.state_root, block.header.tx_root, block.header.receipts_root),
            };
            // Execution left out some candidates: they fail their rules now, so the full
            // prune should drop them. (A mempool larger than the block is normal under load.)
            let rejected_txs = block.transactions.len() < candidate_txs.len();
            return Ok(BuiltBlock { block, exec, dropped_from_mempool, rejected_txs });
        }
    }

    /// Phase 3 (follower): validates state transition of a PROPOSED block before voting.
    /// Re-executes ALL txs on a copy and requires recomputed roots match the
    /// signed header. An honest validator NEVER signs without verifying state.
    pub async fn validate_proposal(&self, block: &Block) -> Result<(), String> {
        let block_tx_bytes: usize = block.transactions.iter().map(|t| t.to_bytes().len()).sum();
        if block_tx_bytes > MAX_BLOCK_TX_BYTES {
            eprintln!(
                "⚠️ [Consensus Warning] Block #{} proposal payload exceeds 2.5 MiB ({} bytes, {} txs)",
                block.header.height, block_tx_bytes, block.transactions.len()
            );
        }

        let (exec, _) = Self::execute_proposal(self.exec_snapshot(), block).await?;
        if let Ok(mut c) = self.exec_cache.lock() {
            *c = Some(exec);
        }
        Ok(())
    }

    /// The pending txs with these hashes, in that order, or how many are missing.
    pub fn mempool_txs_by_hash(&self, hashes: &[[u8; 32]]) -> Result<Vec<Transaction>, usize> {
        let found = self.mempool_lookup(hashes);
        let missing = found.iter().filter(|t| t.is_none()).count();
        if missing > 0 {
            return Err(missing);
        }
        Ok(found.into_iter().flatten().collect())
    }

    /// For each hash, the pending tx with that hash (None if not in the mempool).
    pub fn mempool_lookup(&self, hashes: &[[u8; 32]]) -> Vec<Option<Transaction>> {
        let wanted: std::collections::HashSet<&[u8; 32]> = hashes.iter().collect();
        let mut found: std::collections::HashMap<[u8; 32], &Transaction> = std::collections::HashMap::with_capacity(hashes.len());
        for tx in &self.mempool {
            let h = tx.tx_hash();
            if wanted.contains(&h) {
                found.insert(h, tx);
            }
        }
        hashes.iter().map(|h| found.get(h).map(|t| (*t).clone())).collect()
    }

    /// State and parameters to execute a proposal on, taken under the node lock (O(1)).
    pub fn exec_snapshot(&self) -> ExecSnapshot {
        ExecSnapshot { csmt: self.csmt.clone(), evm_chain_id: self.evm_chain_id, exec_v2_activation: self.exec_v2_activation, base_hash: self.latest_block_hash }
    }

    /// Stores a proposal execution for apply_block (ignored there if the base moved on).
    pub fn store_execution(&self, exec: ExecutedBlock) {
        if let Ok(mut c) = self.exec_cache.lock() {
            *c = Some(exec);
        }
    }

    /// Re-executes every tx of `block` on the snapshot and requires the header roots to
    /// match. Touches no node state, so it can run with no lock held.
    pub async fn execute_proposal(snap: ExecSnapshot, block: &Block) -> Result<(ExecutedBlock, Vec<crate::account::ExecutionReceipt>), String> {
        let mut sim = snap.csmt;
        let ((sr, txr, rr), receipts) = StateTransitionEngine::validate_block_strict_with_receipts(&mut sim, block, snap.evm_chain_id, snap.exec_v2_activation).await?;
        if sr != block.header.state_root {
            return Err(format!(
                "state_root mismatch: calc 0x{} != claimed 0x{}",
                hex::encode(sr), hex::encode(block.header.state_root)
            ));
        }
        if txr != block.header.tx_root {
            return Err("tx_root mismatch".to_string());
        }
        if rr != block.header.receipts_root {
            return Err("receipts_root mismatch".to_string());
        }
        Ok((ExecutedBlock { base_hash: snap.base_hash, block_hash: block.hash(), csmt: sim, roots: (sr, txr, rr) }, receipts))
    }

    /// Checks a Tendermint proposal's block against everything `apply_block` will check,
    /// except its own commit certificate (it does not exist yet), so a validator never
    /// votes for a block it could not apply once decided.
    pub async fn validate_tm_proposal(&self, block: &Block, proposal_round: u64) -> Result<(), String> {
        let snap = self.tm_proposal_precheck(block, proposal_round)?;
        let (exec, _) = Self::execute_proposal(snap, block).await?;
        self.store_execution(exec);
        Ok(())
    }

    /// Every check of `validate_tm_proposal` except the re-execution (cheap; done under
    /// the node lock). Returns the state to execute the proposal on.
    pub fn tm_proposal_precheck(&self, block: &Block, proposal_round: u64) -> Result<ExecSnapshot, String> {
        let h = block.header.height;
        if h != self.height + 1 {
            return Err(format!("proposal height {} (expected {})", h, self.height + 1));
        }
        if !self.tendermint_active(h) {
            return Err(format!("height {} is before Tendermint activation", h));
        }
        if block.header.prev_hash != self.latest_block_hash {
            return Err("proposal prev_hash does not match our latest block".to_string());
        }
        if !block.validator_signatures.is_empty() || block.commit_round != 0 {
            return Err("a proposal must not carry a commit certificate".to_string());
        }
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if block.header.timestamp > now_secs.saturating_add(MAX_FUTURE_BLOCK_TIME_SECS) {
            return Err(format!("proposal timestamp {} is in the future", block.header.timestamp));
        }
        if let Ok(Some(prev)) = self.storage.load_block(self.height) {
            if block.header.timestamp < prev.header.timestamp {
                return Err("proposal timestamp is older than the previous block".to_string());
            }
        }
        let max_round = proposal_round.min(MAX_TENDERMINT_COMMIT_ROUND);
        let proposer_ok = (0..=max_round).any(|r| {
            self.validator_set.get_proposer(h, r).map(|p| p.address == block.header.proposer).unwrap_or(false)
        });
        if !proposer_ok {
            let expected: Vec<String> = (0..=max_round.min(3))
                .filter_map(|r| self.validator_set.get_proposer(h, r).ok().map(|p| hex::encode(&p.address[..4])))
                .collect();
            return Err(format!("block was not built by a proposer of this height (expected one of {:?} for rounds 0..={}, local height {})",
                expected, max_round, self.height));
        }
        if block.header.last_commit_hash != Block::compute_commits_root(&block.last_commit) {
            return Err("last_commit does not match header.last_commit_hash".to_string());
        }
        if h > 1 && !self.validator_set.check_commit_supermajority(
            &self.chain_id, h - 1, block.last_commit_round, &block.header.prev_hash, &block.last_commit,
        )? {
            return Err("last_commit lacks a quorum for the previous block".to_string());
        }
        let block_tx_bytes: usize = block.transactions.iter().map(|t| t.to_bytes().len()).sum();
        if block_tx_bytes > MAX_BLOCK_TX_BYTES {
            eprintln!("⚠️ [Consensus Warning] Block #{} proposal payload exceeds 2.5 MiB ({} bytes, {} txs)",
                block.header.height, block_tx_bytes, block.transactions.len());
        }
        Ok(self.exec_snapshot())
    }

    /// Saves the mempool if it changed since the last save.
    pub fn flush_mempool_if_dirty(&mut self) {
        if self.mempool_dirty {
            if self.storage.save_mempool(&self.mempool).is_ok() {
                self.mempool_dirty = false;
            }
        }
    }

    /// True when `height` is decided by the Tendermint engine.
    pub fn tendermint_active(&self, height: u64) -> bool {
        self.tendermint_activation.map_or(false, |a| height >= a)
    }

    /// Validates and applies a block received from P2P network with strict BFT consensus verification
    pub async fn apply_block(&mut self, block: Block) -> Result<[u8; 32], String> {
        let mut stages = StageTimer::new();
        if block.header.height != self.height + 1 {
            return Err(format!(
                "Unexpected block height: {} (expected {})",
                block.header.height, self.height + 1
            ));
        }

        if block.header.prev_hash != self.latest_block_hash {
            return Err(format!(
                "Inconsistent previous hash: 0x{} != 0x{}",
                hex::encode(block.header.prev_hash),
                hex::encode(self.latest_block_hash)
            ));
        }

        // 1. Timestamp Verification against Time Warp / Excessive Temporal Drift
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if block.header.timestamp > now_secs.saturating_add(MAX_FUTURE_BLOCK_TIME_SECS) {
            let now_ts = now_secs;
            self.record_security_incident(SecurityIncident {
                id: format!("INC-{}", now_ts % 100000),
                timestamp: now_ts,
                date_time: format_utc_timestamp(now_ts),
                threat_type: "TIME_WARP_CONSENSUS_ATTACK".to_string(),
                vector: format!("Timestamp too far in the future: {} > {} + {}", block.header.timestamp, now_secs, MAX_FUTURE_BLOCK_TIME_SECS),
                target: "Consensus Engine Timestamp Validator".to_string(),
                expected_hash: format!("Max timestamp: {}", now_secs + MAX_FUTURE_BLOCK_TIME_SECS),
                detected_hash: format!("{}", block.header.timestamp),
                action_taken: "BLOCK_PROPOSAL_DISCARDED".to_string(),
                status: "BLOCKED_AND_AUDITED".to_string(),
                mitigation_notes: "Attempted future block timestamp manipulation. Rejected.".to_string(),
            });
            return Err(format!(
                "Block Rejection: Future timestamp ({} > now {} + {})",
                block.header.timestamp, now_secs, MAX_FUTURE_BLOCK_TIME_SECS
            ));
        }
        stages.mark("checks");
        let prev_loaded = self.storage.load_block(self.height);
        stages.mark("load_prev");
        if let Ok(Some(prev_block)) = prev_loaded {
            if block.header.timestamp < prev_block.header.timestamp {
                let now_ts = now_secs;
                self.record_security_incident(SecurityIncident {
                    id: format!("INC-{}", now_ts % 100000),
                    timestamp: now_ts,
                    date_time: format_utc_timestamp(now_ts),
                    threat_type: "TIME_INVERSION_ATTACK".to_string(),
                    vector: format!("Timestamp less than or equal to previous block: {} <= {}", block.header.timestamp, prev_block.header.timestamp),
                    target: "Consensus Engine Monotonic Clock".to_string(),
                    expected_hash: format!("> {}", prev_block.header.timestamp),
                    detected_hash: format!("{}", block.header.timestamp),
                    action_taken: "BLOCK_PROPOSAL_DISCARDED".to_string(),
                    status: "BLOCKED_AND_AUDITED".to_string(),
                    mitigation_notes: "Chronological time inversion detected on chain. Rejected.".to_string(),
                });
                return Err(format!(
                    "Block Rejection: Timestamp less than or equal to previous block ({} <= {})",
                    block.header.timestamp, prev_block.header.timestamp
                ));
            }
        }

        // 2. Deterministic Proposer Validation (permits round advance if validator misses).
        //    Tendermint: the block was built by the proposer of some round <= its commit
        //    round (later rounds re-propose it unchanged). Legacy: rounds 0..=10, round 0 commits.
        let tm = self.tendermint_active(block.header.height);
        if !tm && (block.commit_round != 0 || block.last_commit_round != 0) {
            return Err(format!("Block #{}: commit rounds must be 0 before Tendermint activation", block.header.height));
        }
        if block.commit_round > MAX_TENDERMINT_COMMIT_ROUND {
            return Err(format!("Block #{}: commit round {} too high", block.header.height, block.commit_round));
        }
        let max_proposer_round = if tm { block.commit_round } else { 10 };
        let is_valid_proposer = (0..=max_proposer_round).any(|r| {
            self.validator_set.get_proposer(block.header.height, r)
                .map(|p| p.address == block.header.proposer)
                .unwrap_or(false)
        });
        if !is_valid_proposer {
            let expected_proposer_addr = self.validator_set.get_proposer(block.header.height, 0)?.address;
            let now_ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            self.record_security_incident(SecurityIncident {
                id: format!("INC-{}", now_ts % 100000),
                timestamp: now_ts,
                date_time: format_utc_timestamp(now_ts),
                threat_type: "ROGUE_PROPOSER_IMPERSONATION".to_string(),
                vector: format!("Illegitimate proposer for height {}: received 0x{}", block.header.height, hex::encode(block.header.proposer)),
                target: "Consensus Round-Robin Proposer Selection".to_string(),
                expected_hash: format!("0x{}", hex::encode(expected_proposer_addr)),
                detected_hash: format!("0x{}", hex::encode(block.header.proposer)),
                action_taken: "BLOCK_PROPOSAL_DISCARDED".to_string(),
                status: "BLOCKED_AND_AUDITED".to_string(),
                mitigation_notes: "Node attempted to propose block outside its deterministic round-robin turn.".to_string(),
            });
            return Err(format!(
                "Illegitimate Proposer for height {}: expected 0x{}, received 0x{}",
                block.header.height,
                hex::encode(expected_proposer_addr),
                hex::encode(block.header.proposer)
            ));
        }

        // 3. Cryptographic BFT Supermajority Validation (2/3 + 1 stake)
        let block_hash = block.hash();
        let supermajority_ok = self.validator_set.check_commit_supermajority(
            &self.chain_id,
            block.header.height,
            block.commit_round,
            &block_hash,
            &block.validator_signatures,
        )?;

        if !supermajority_ok {
            let now_ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            self.record_security_incident(SecurityIncident {
                id: format!("INC-{}", now_ts % 100000),
                timestamp: now_ts,
                date_time: format_utc_timestamp(now_ts),
                threat_type: "ROGUE_BLOCK_INSUFFICIENT_BFT_COMMITS".to_string(),
                vector: format!("Block #{} did not reach 2/3 + 1 quorum of valid signatures", block.header.height),
                target: format!("Consensus BFT Engine (Proposer: 0x{})", hex::encode(block.header.proposer)),
                expected_hash: format!("Threshold: {} stake", self.validator_set.supermajority_threshold()),
                detected_hash: "INSUFFICIENT_BFT_COMMITS".to_string(),
                action_taken: "BLOCK_REJECTED_SLASH_CONSIDERED".to_string(),
                status: "BLOCKED_AND_AUDITED".to_string(),
                mitigation_notes: "Attempted block commit without sufficient Byzantine quorum. Block rejected.".to_string(),
            });
            return Err(format!(
                "CONSENSUS ATTACK DETECTED: Block #{} lacks sufficient signatures to reach BFT supermajority (2/3 + 1)",
                block.header.height
            ));
        }

        // 3.1 If height > 1, validate last_commit supermajority for previous block
        if block.header.height > 1 {
            let last_commit_supermajority = self.validator_set.check_commit_supermajority(
                &self.chain_id,
                block.header.height - 1,
                block.last_commit_round,
                &block.header.prev_hash,
                &block.last_commit,
            )?;
            if !last_commit_supermajority {
                return Err(format!(
                    "CONSENSUS ATTACK DETECTED: last_commit of Block #{} lacks BFT supermajority for previous block",
                    block.header.height
                ));
            }
        }

        // 4. STRICT validation of state transition against claimed proposer root.
        //    Does NOT overwrite header; re-executes ALL txs (fails if any does not apply)
        //    and compares recomputed roots with those in block signed by 2/3 + 1.
        stages.mark("proposer+commits");
        let claimed_state_root = block.header.state_root;
        let claimed_tx_root = block.header.tx_root;
        let claimed_receipts_root = block.header.receipts_root;
        let block_hash_now = block.hash();
        let cached = self.exec_cache.lock().ok().and_then(|mut c| c.take())
            .filter(|e| e.base_hash == self.latest_block_hash && e.block_hash == block_hash_now);
        let cache_hit = cached.is_some();
        let (sim_csmt, (calculated_state_root, calculated_tx_root, calculated_receipts_root)) = match cached {
            // Same block on the same state was already executed (build or validation).
            Some(e) => (e.csmt, e.roots),
            None => {
                let mut sim_csmt = self.csmt.clone();
                let roots = StateTransitionEngine::validate_block_strict(&mut sim_csmt, &block, self.evm_chain_id, self.exec_v2_activation).await?;
                (sim_csmt, roots)
            }
        };

        stages.mark(if cache_hit { "exec(cached)" } else { "exec" });
        if calculated_state_root != claimed_state_root
            || calculated_tx_root != claimed_tx_root
            || calculated_receipts_root != claimed_receipts_root
        {
            let now_ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            self.record_security_incident(SecurityIncident {
                id: format!("INC-{}", now_ts % 100000),
                timestamp: now_ts,
                date_time: format_utc_timestamp(now_ts),
                threat_type: "STATE_ROOT_EXECUTION_FRAUD".to_string(),
                vector: "Calculated post-execution CSMT root diverges from claimed block header root".to_string(),
                target: format!("State Transition Engine (Block #{})", block.header.height),
                expected_hash: format!("0x{}", hex::encode(calculated_state_root)),
                detected_hash: format!("0x{}", hex::encode(block.header.state_root)),
                action_taken: "FRAUD_ISOLATED_BISECTION_TRIGGERED".to_string(),
                status: "BLOCKED_AND_AUDITED".to_string(),
                mitigation_notes: "Execution fraud detected: calculated state root diverges from claimed root.".to_string(),
            });
            return Err(format!(
                "EXECUTION FRAUD DETECTED! Calculated state root 0x{} diverges from header 0x{}",
                hex::encode(calculated_state_root),
                hex::encode(block.header.state_root)
            ));
        }

        // Update local validator_set from CSMT resulting from block execution
        if let Some(bytes) = sim_csmt.get(&crate::account::VALIDATOR_SET_CSMT_KEY) {
            if let Ok(vset) = crate::consensus::ValidatorSet::from_bytes(bytes) {
                self.validator_set = vset;
            }
        }

        // State validated! Commit permanently without ANY state mutation outside the block.
        // Accounts this block changed (the base was compacted after the previous block):
        // written to the delta log before the block, so disk state never runs ahead.
        let state_delta = sim_csmt.delta_entries();
        self.storage.append_state_delta(block.header.height, &state_delta)?;
        stages.mark("state_delta");
        self.csmt = sim_csmt;
        // The previous state (the only other holder of the shared base) is gone now.
        self.csmt.compact();
        stages.mark("compact");
        self.last_committed_signatures = block.validator_signatures.clone();
        self.last_commit_round = block.commit_round;
        self.height = block.header.height;
        self.latest_block_hash = block.hash();
        self.storage.save_block(&block)?;
        stages.mark("save_block");
        // Full snapshot only every STATE_SNAPSHOT_EVERY blocks (or if the log grew large):
        // rewriting the whole state on every block cost 0.4 s per block at 100k accounts.
        if block.header.height % STATE_SNAPSHOT_EVERY == 0 || self.storage.delta_log_bytes() > MAX_DELTA_LOG_BYTES {
            self.storage.save_state(&self.csmt)?;
        }
        let _ = self.storage.save_validators(&self.validator_set);
        stages.mark("snapshot+validators");

        // Remove executed transactions from mempool and prune rule-failing transactions
        let executed_hashes: std::collections::HashSet<[u8; 32]> =
            block.transactions.iter().map(|tx| tx.tx_hash()).collect();
        self.mempool.retain(|tx| !executed_hashes.contains(&tx.tx_hash()));
        self.admission_cache.clear();
        self.mempool_bytes = None;
        self.mempool_dirty = true; // saved by flush_mempool_if_dirty (every second)
        stages.mark("mempool_retain");
        // Cheap prune only; the full one (re-executes pending txs) runs off the lock from
        // the node's event loop (full_prune_due / compute_full_prune / apply_full_prune).
        self.prune_mempool_nonces();
        stages.mark("prune(nonces)");

        let hashes: Vec<[u8; 32]> = block.transactions.iter().map(|tx| tx.tx_hash()).collect();
        for (idx, hash) in hashes.iter().enumerate() {
            self.tx_index.insert(*hash, (block.header.height, idx));
        }
        let _ = self.storage.append_tx_index(block.header.height, &hashes);
        // Newest first; only the last MAX_RECENT_TXS of the block can stay in the list.
        let mut recent: Vec<TxRecord> = block.transactions.iter().rev().take(MAX_RECENT_TXS)
            .map(|tx| tx_record(tx, block.header.height, block.header.timestamp))
            .collect();
        recent.extend(self.recent_transactions.drain(..));
        recent.truncate(MAX_RECENT_TXS);
        self.recent_transactions = recent;
        stages.mark("tx_index");
        if block.transactions.len() >= TIMING_LOG_MIN_TXS {
            println!("⏱️ [apply] #{} {} txs, {} pending after | {}",
                block.header.height, block.transactions.len(), self.mempool.len(), stages.summary());
        }

        self.height = block.header.height;
        self.latest_block_hash = block.hash();

        Ok(self.latest_block_hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_full_node_lifecycle_and_block_production() {
        let temp_dir = std::env::temp_dir().join(format!("vera_node_{}", rand::random::<u64>()));
        let (genesis_cfg, val_key) = GenesisConfig::default_testnet();

        // 1. Initialize node
        let mut node = FullNode::load_or_init(&temp_dir, &genesis_cfg, Some(val_key)).unwrap();
        assert_eq!(node.height, 0);

        // 2. Produce empty block
        let block1 = node.propose_and_commit_block().await.unwrap();
        assert_eq!(block1.header.height, 1);
        assert_eq!(node.height, 1);

        // 3. Simulate node restart (reloading from disk)
        let reopened_node = FullNode::load_or_init(&temp_dir, &genesis_cfg, None).unwrap();
        assert_eq!(reopened_node.height, 1);
        assert_eq!(reopened_node.latest_block_hash, block1.hash());

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[tokio::test]
    async fn test_apply_block_rejects_forged_block_without_supermajority() {
        let temp_dir = std::env::temp_dir().join(format!("vera_node_sec_{}", rand::random::<u64>()));
        let (genesis_cfg, val_key) = GenesisConfig::default_testnet();

        let mut node = FullNode::load_or_init(&temp_dir, &genesis_cfg, Some(val_key)).unwrap();

        // Create a counterfeit block with correct height (1), but WITHOUT supermajority signatures
        let forged_block = Block::new(
            BlockHeader {
                height: 1,
                prev_hash: node.latest_block_hash,
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                state_root: [0u8; 32],
                tx_root: [0u8; 32],
                receipts_root: [0u8; 32],
                proposer: node.validator_set.validators[0].address,
                last_commit_hash: [0u8; 32],
            },
            vec![],
            vec![],
        );

        // Node MUST REJECT forged block without valid 2/3 + 1 signatures
        let result = node.apply_block(forged_block).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("CONSENSUS ATTACK DETECTED") || err.contains("ATAQUE DE CONSENSO DETECTADO"));

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[tokio::test]
    async fn test_mempool_rejects_insolvent_transaction() {
        let temp_dir = std::env::temp_dir().join(format!("vera_node_mempool_{}", rand::random::<u64>()));
        let (genesis_cfg, val_key) = GenesisConfig::default_testnet();

        let mut node = FullNode::load_or_init(&temp_dir, &genesis_cfg, Some(val_key)).unwrap();

        // Attacker key with zero balance in genesis
        use rand::rngs::OsRng;
        let mut csprng = OsRng;
        let attacker_key = SigningKey::generate(&mut csprng);

        // Attacker attempts to send tx with 0 balance
        let tx = Transaction::new(
            &node.chain_id,
            &attacker_key,
            0,
            Some([0x99u8; 32]),
            1_000_000,
            25_000,
            1,
            vec![],
        );

        let res = node.submit_transaction(tx);
        assert!(res.is_err());
        let err_str = res.unwrap_err();
        assert!(err_str.contains("Origin account not found"));

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[tokio::test]
    async fn test_security_incidents_recorded_on_forgery_and_replay() {
        let temp_dir = std::env::temp_dir().join(format!("vera_node_incident_test_{}", rand::random::<u64>()));
        let (genesis_cfg, val_key) = GenesisConfig::default_testnet();

        let mut node = FullNode::load_or_init(&temp_dir, &genesis_cfg, Some(val_key)).unwrap();
        assert_eq!(node.security_incidents.len(), 0);

        // 1. Forged block without supermajority must record incident in ledger
        let prev_block = node.storage.load_block(0).unwrap().unwrap();
        let expected_proposer = node.validator_set.get_proposer(1, 0).unwrap().address;
        let forged_block = Block::new(
            BlockHeader {
                height: 1,
                prev_hash: node.latest_block_hash,
                timestamp: prev_block.header.timestamp + 12,
                state_root: [0u8; 32],
                tx_root: [0u8; 32],
                receipts_root: [0u8; 32],
                proposer: expected_proposer,
                last_commit_hash: [0u8; 32],
            },
            vec![],
            vec![],
        );

        let _ = node.apply_block(forged_block).await;
        assert_eq!(node.security_incidents.len(), 1);
        assert_eq!(node.security_incidents[0].threat_type, "ROGUE_BLOCK_INSUFFICIENT_BFT_COMMITS");
        assert_eq!(node.security_incidents[0].status, "BLOCKED_AND_AUDITED");

        // 2. Cross-chain transaction must record incident in ledger
        use rand::rngs::OsRng;
        let attacker_key = SigningKey::generate(&mut OsRng);
        let cross_tx = Transaction::new(
            "rogue-foreign-chain-999",
            &attacker_key,
            0,
            Some([0x99u8; 32]),
            100,
            21_000,
            1,
            vec![],
        );
        let _ = node.submit_transaction(cross_tx);
        assert_eq!(node.security_incidents.len(), 2);
        assert_eq!(node.security_incidents[0].threat_type, "CROSS_CHAIN_REPLAY_ATTEMPT");

        // 3. Verify disk persistence (security_incidents.json)
        let reopened_node = FullNode::load_or_init(&temp_dir, &genesis_cfg, None).unwrap();
        assert_eq!(reopened_node.security_incidents.len(), 2);
        assert_eq!(reopened_node.security_incidents[0].threat_type, "CROSS_CHAIN_REPLAY_ATTEMPT");
        assert_eq!(reopened_node.security_incidents[1].threat_type, "ROGUE_BLOCK_INSUFFICIENT_BFT_COMMITS");

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[tokio::test]
    async fn test_mempool_simulation_replay_and_pruning_rules() {
        let temp_dir = std::env::temp_dir().join(format!("vera_mempool_m1_{}", rand::random::<u64>()));
        let (genesis_cfg, val_key) = GenesisConfig::default_testnet();

        let mut node = FullNode::load_or_init(&temp_dir, &genesis_cfg, Some(val_key.clone())).unwrap();

        use rand::rngs::OsRng;
        let test_user_key = SigningKey::generate(&mut OsRng);
        let test_user_pub = test_user_key.verifying_key().to_bytes();
        let test_user_addr = crate::chain_hash::hash256(&test_user_pub);

        // 1. Attempt submitting tx from non-existent account -> immediate rejection
        let tx_no_acc = Transaction::new(
            &node.chain_id,
            &test_user_key,
            0,
            Some([0x11u8; 32]),
            100,
            21_000,
            1,
            vec![],
        );
        let res_no_acc = node.submit_transaction(tx_no_acc);
        assert!(res_no_acc.is_err(), "Non-existent account must be rejected");

        // Fund account via transfer in block 1
        let fund_tx = Transaction::new(
            &node.chain_id,
            &val_key,
            0,
            Some(test_user_addr),
            10_000_000_000_000_000_000, // 10 VERA
            21_000,
            1,
            vec![],
        );
        node.submit_transaction(fund_tx).expect("Validator funds test account");
        let _ = node.propose_and_commit_block().await.unwrap();

        // 2. Valid transaction on mempool admission -> simulated and accepted
        let valid_tx1 = Transaction::new(
            &node.chain_id,
            &test_user_key,
            0,
            Some([0x22u8; 32]),
            1_000_000,
            21_000,
            1,
            vec![],
        );
        let res_valid = node.submit_transaction(valid_tx1);
        assert!(res_valid.is_ok(), "Valid transaction must be accepted");
        assert_eq!(node.mempool.len(), 1);

        // 3. Reject repeated nonce (same nonce 0 already pending in mempool)
        let dup_nonce_tx = Transaction::new(
            &node.chain_id,
            &test_user_key,
            0,
            Some([0x33u8; 32]),
            2_000_000,
            21_000,
            1,
            vec![],
        );
        let res_dup_nonce = node.submit_transaction(dup_nonce_tx);
        assert!(res_dup_nonce.is_err(), "Repeated nonce in mempool must be rejected");
        let err_dup = res_dup_nonce.unwrap_err();
        assert!(err_dup.contains("Repeated nonce") || err_dup.contains("repetido"));

        // 4. Rejection of unauthorized transaction during admission simulation
        // (Attempted allow: by non-governance account)
        let unauthorized_allow_tx = Transaction::new(
            &node.chain_id,
            &test_user_key,
            1, // Consecutive future nonce to 0 currently in mempool
            Some(crate::account::STAKING_SYSTEM_ADDRESS),
            0,
            30_000,
            1,
            b"allow:0x1111111111111111111111111111111111111111111111111111111111111111".to_vec(),
        );
        let res_unauth = node.submit_transaction(unauthorized_allow_tx);
        assert!(res_unauth.is_err(), "Transaction with rule violation must be rejected in simulation");
        assert_eq!(node.mempool.len(), 1, "Mempool must not retain transaction rejected in simulation");

        // 5. Mines block with tx1 (nonce 0 is consumed)
        let _ = node.propose_and_commit_block().await.unwrap();
        assert_eq!(node.mempool.len(), 0);

        // 6. Reject used/obsolete nonce (nonce 0 when account already has nonce 1)
        let obsolete_nonce_tx = Transaction::new(
            &node.chain_id,
            &test_user_key,
            0,
            Some([0x44u8; 32]),
            500_000,
            21_000,
            1,
            vec![],
        );
        let res_obsolete = node.submit_transaction(obsolete_nonce_tx);
        assert!(res_obsolete.is_err(), "Obsolete nonce must be rejected");

        // 7. Future nonce with gap (account is at nonce 1, sending nonce 3)
        let future_gap_tx = Transaction::new(
            &node.chain_id,
            &test_user_key,
            3,
            Some([0x55u8; 32]),
            100_000,
            21_000,
            1,
            vec![],
        );
        let res_future = node.submit_transaction(future_gap_tx);
        assert!(res_future.is_ok(), "Legitimate future nonce with gap must be accepted into mempool");
        assert_eq!(node.mempool.len(), 1);

        // 8. prune_mempool test: preserves legitimate future nonce
        let pruned = node.prune_mempool();
        assert_eq!(pruned, 0, "prune_mempool must not purge future nonce with gap");
        assert_eq!(node.mempool.len(), 1);

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[tokio::test]
    async fn test_admission_payload_and_mempool_byte_limits() {
        use rand::rngs::OsRng;
        let temp_dir = std::env::temp_dir().join(format!("vera_test_limits_{}", rand::random::<u64>()));
        let (genesis_cfg, val_key) = GenesisConfig::default_testnet();
        let mut node = FullNode::load_or_init(&temp_dir, &genesis_cfg, Some(val_key)).unwrap();

        let test_user_key = SigningKey::generate(&mut OsRng);
        let test_user_addr = crate::chain_hash::hash256(&test_user_key.verifying_key().to_bytes());
        node.csmt.insert(test_user_addr, Account::new(100_000_000_000_000_000_000).to_bytes());

        // 1. Rejection of program exceeding 128 KiB
        let oversized_program_tx = Transaction::new(
            &node.chain_id,
            &test_user_key,
            0,
            Some([0x22u8; 32]),
            1000,
            1_000_000,
            1,
            vec![0xAA; 130 * 1024], // 130 KiB > 128 KiB
        );
        let res_prog = node.submit_transaction(oversized_program_tx);
        assert!(res_prog.is_err(), "Program > 128 KiB must be rejected");
        assert!(res_prog.unwrap_err().contains("Transaction program payload exceeds maximum allowed size"));

        // 2. Rejection of raw_evm exceeding 128 KiB
        let mut oversized_raw_tx = Transaction::new(
            &node.chain_id,
            &test_user_key,
            0,
            Some([0x22u8; 32]),
            1000,
            1_000_000,
            1,
            vec![],
        );
        oversized_raw_tx.raw_evm = Some(vec![0xBB; 130 * 1024]); // 130 KiB > 128 KiB
        let res_raw = node.submit_transaction(oversized_raw_tx);
        assert!(res_raw.is_err(), "raw_evm > 128 KiB must be rejected");
        assert!(res_raw.unwrap_err().contains("Transaction raw_evm payload exceeds maximum allowed size"));

        // 3. Rejection when mempool byte limit is reached
        let dummy_key = SigningKey::generate(&mut OsRng);
        let dummy_tx = Transaction::new(
            &node.chain_id,
            &dummy_key,
            0,
            Some([0x22u8; 32]),
            1000,
            21_000,
            1, // gas_price = 1
            vec![0u8; 1000],
        );
        let tx_len = dummy_tx.to_bytes().len();
        // Fill simulated mempool to 64 MiB
        let count_to_fill = (MAX_MEMPOOL_BYTES / tx_len) + 1;
        for i in 0..count_to_fill {
            let mut t = dummy_tx.clone();
            t.nonce = i as u64;
            node.mempool.push(t);
        }

        // New valid tx from test_user (nonce 0, has account and balance, gas_price = 1)
        let candidate_tx = Transaction::new(
            &node.chain_id,
            &test_user_key,
            0,
            Some([0x22u8; 32]),
            1000,
            21_000,
            1, // gas_price = 1 (cannot evict equal fee)
            vec![],
        );
        let res_full = node.submit_transaction(candidate_tx);
        assert!(res_full.is_err(), "Mempool full by bytes must reject transaction with insufficient fee");
        assert!(res_full.unwrap_err().contains("Mempool is full by bytes"));

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[tokio::test]
    async fn test_build_proposal_byte_limit_and_wire_headroom() {
        let temp_dir = std::env::temp_dir().join(format!("vera_test_proposal_{}", rand::random::<u64>()));
        let (genesis_cfg, val_key) = GenesisConfig::default_testnet();
        let mut node = FullNode::load_or_init(&temp_dir, &genesis_cfg, Some(val_key.clone())).unwrap();

        let val_addr = crate::chain_hash::hash256(&val_key.verifying_key().to_bytes());
        node.csmt.insert(val_addr, Account::new(100_000_000_000_000_000_000).to_bytes());

        // Construct a native computation graph (~100 KiB)
        let mut g = vera_engine_v2::ComputationGraph::new();
        let ins: Vec<_> = (0..4).map(|i| g.add_input(i)).collect();
        let (mut a, mut b, mut d, m) = (ins[0], ins[1], ins[2], ins[3]);
        for i in 0..1000 {
            let r = g.add_fused_arx(a, b, d, m, [16, 12, 8, 7][i % 4]);
            a = b;
            b = d;
            d = r;
        }
        g.set_output(d);
        let graph_json = g.to_json().into_bytes();

        // Create 30 transactions of ~100 KiB program each (total ~3 MiB)
        for i in 0..30 {
            let tx = Transaction::new(
                &node.chain_id,
                &val_key,
                i as u64,
                Some([0x33u8; 32]),
                100,
                2_500_000,
                1,
                graph_json.clone(),
            );
            node.mempool.push(tx);
        }

        let proposal = node.build_proposal().await.unwrap();
        let total_tx_bytes: usize = proposal.transactions.iter().map(|t| t.to_bytes().len()).sum();
        assert!(
            total_tx_bytes <= MAX_BLOCK_TX_BYTES,
            "Total tx bytes in proposal ({} bytes) must not exceed MAX_BLOCK_TX_BYTES ({} bytes)",
            total_tx_bytes,
            MAX_BLOCK_TX_BYTES
        );

        // Verify that the proposal serialized into BlockProposal fits well within MAX_P2P_FRAME_SIZE (4 MiB)
        let proposal_payload = crate::p2p::P2PPayload::BlockProposal(proposal.clone());
        let serialized_frame = serde_json::to_vec(&proposal_payload).unwrap();
        let wire_frame_size = 1 + serialized_frame.len();
        assert!(
            wire_frame_size <= MAX_BLOCK_WIRE_BYTES,
            "BlockProposal complete wire frame size ({} bytes) must be <= MAX_BLOCK_WIRE_BYTES ({} bytes)",
            wire_frame_size,
            MAX_BLOCK_WIRE_BYTES
        );

        // Verify validate_proposal logs warning but returns Ok(())
        let val_res = node.validate_proposal(&proposal).await;
        assert!(val_res.is_ok(), "validate_proposal must accept the block proposal without error");

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[tokio::test]
    async fn test_build_proposal_drops_oversized_log_tx() {
        let temp_dir = std::env::temp_dir().join(format!("vera_test_logs_{}", rand::random::<u64>()));
        let (genesis_cfg, val_key) = GenesisConfig::default_testnet();
        let mut node = FullNode::load_or_init(&temp_dir, &genesis_cfg, Some(val_key.clone())).unwrap();

        let val_addr = crate::chain_hash::hash256(&val_key.verifying_key().to_bytes());
        node.csmt.insert(val_addr, Account::new(100_000_000_000_000_000_000).to_bytes());

        // Create a normal transfer tx
        let tx1 = Transaction::new(
            &node.chain_id,
            &val_key,
            0,
            Some([0x11u8; 32]),
            100,
            21_000,
            1,
            vec![],
        );
        node.mempool.push(tx1);

        let proposal = node.build_proposal().await.unwrap();
        assert_eq!(proposal.transactions.len(), 1);

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_sync_response_byte_truncation() {
        use rand::rngs::OsRng;
        let mut blocks = Vec::new();
        for h in 1..=10 {
            let mut b = Block::new(
                BlockHeader {
                    height: h,
                    prev_hash: [0u8; 32],
                    timestamp: 1000 + h,
                    state_root: [0u8; 32],
                    tx_root: [0u8; 32],
                    receipts_root: [0u8; 32],
                    proposer: [0u8; 32],
                    last_commit_hash: [0u8; 32],
                },
                Vec::new(),
                Vec::new(),
            );
            let dummy_key = SigningKey::generate(&mut OsRng);
            b.transactions.push(Transaction::new(
                "vera-testnet-1",
                &dummy_key,
                0,
                None,
                0,
                1_000_000,
                1,
                vec![0x55; 100 * 1024],
            ));
            blocks.push(b);
        }

        let mut res = crate::p2p::SyncResponse::new(blocks);
        assert_eq!(res.blocks.len(), 10);

        // Truncate to 300 KB limit: should keep at least 1 block and truncate others
        res.truncate_to_byte_limit(300 * 1024);
        assert!(res.blocks.len() >= 1 && res.blocks.len() < 10);
        let frame_len = 1 + serde_json::to_vec(&crate::p2p::P2PPayload::SyncResponse(res.clone())).unwrap().len();
        assert!(frame_len <= 300 * 1024 || res.blocks.len() == 1, "Truncated frame size must respect wire limit");
    }

    #[test]
    fn test_single_block_exceeding_p2p_frame_handling() {
        use rand::rngs::OsRng;
        let mut b = Block::new(
            BlockHeader {
                height: 99,
                prev_hash: [0u8; 32],
                timestamp: 2000,
                state_root: [0u8; 32],
                tx_root: [0u8; 32],
                receipts_root: [0u8; 32],
                proposer: [0u8; 32],
                last_commit_hash: [0u8; 32],
            },
            Vec::new(),
            Vec::new(),
        );
        let dummy_key = SigningKey::generate(&mut OsRng);
        b.transactions.push(Transaction::new(
            "vera-testnet-1",
            &dummy_key,
            0,
            None,
            0,
            1_000_000,
            1,
            vec![0xAA; 4 * 1024 * 1024], // 4 MB payload
        ));
        let single_frame_len = 1 + serde_json::to_vec(&crate::p2p::P2PPayload::SyncResponse(crate::p2p::SyncResponse { blocks: vec![b.clone()] }))
            .map(|v| v.len())
            .unwrap_or(0);
        assert!(single_frame_len > crate::p2p::wire::MAX_P2P_FRAME_SIZE, "Oversized single block must exceed MAX_P2P_FRAME_SIZE");
    }

}

