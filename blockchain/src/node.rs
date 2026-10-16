use ed25519_dalek::SigningKey;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::Mutex;

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
    pub recent_transactions: Vec<TxRecord>,
    pub tx_index: std::collections::HashMap<[u8; 32], (u64, usize)>,
    pub binary_hash: [u8; 32],
    pub attestation_status: String,
    pub attestation_timestamp: u64,
    pub security_incidents: Vec<SecurityIncident>,
    pub security_log_path: Option<std::path::PathBuf>,
    pub peer_count: usize,
}

pub type SharedNode = Arc<Mutex<FullNode>>;

pub const MAX_MEMPOOL_SIZE: usize = 5_000;

pub const MAX_PENDING_NONCE_GAP: u64 = 16;
pub const MAX_FUTURE_BLOCK_TIME_SECS: u64 = 15;


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

        let mut recent_transactions = Vec::new();
        let mut tx_index = std::collections::HashMap::new();
        for h in 1..=height {
            if let Ok(Some(b)) = storage.load_block(h) {
                for (idx, tx) in b.transactions.iter().enumerate() {
                    tx_index.insert(tx.tx_hash(), (h, idx));
                    recent_transactions.insert(0, TxRecord {
                        hash: format!("0x{}", hex::encode(tx.tx_hash())),
                        block_number: h,
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
                        timestamp: b.header.timestamp,
                        status: "SUCCESS".to_string(),
                    });
                }
            }
        }

        let last_committed_signatures = if height > 0 {
            storage.load_block(height).ok().flatten().map(|b| b.validator_signatures).unwrap_or_default()
        } else {
            Vec::new()
        };

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
        if let Err(e) = tx.verify_signature() {
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
        // 4.3 Reject duplicate transaction or repeated nonce in mempool
        if self.mempool.iter().any(|t| t.tx_hash() == hash) {
            return Err("Duplicate transaction already present in mempool".to_string());
        }
        if self.mempool.iter().any(|t| t.sender == tx.sender && t.nonce == tx.nonce) {
            return Err(format!(
                "Repeated nonce: pending transaction already exists in mempool with nonce {} for account 0x{}",
                tx.nonce, hex::encode(tx.sender)
            ));
        }

        // 4.4 Strict simulation in current state before admitting to mempool
        let next_height = self.height + 1;
        if tx.nonce == sender_acc.nonce {
            let mut sim_csmt = self.csmt.clone();
            let receipt = crate::state_transition::StateTransitionEngine::execute_transaction_with_context_sync(
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

            if is_contiguous {
                let mut sim_csmt = self.csmt.clone();
                for ptx in &pending_sender_txs {
                    let r = crate::state_transition::StateTransitionEngine::execute_transaction_with_context_sync(
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

                let receipt = crate::state_transition::StateTransitionEngine::execute_transaction_with_context_sync(
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
            }
            // If gap exists, accept as legitimate future nonce awaiting missing sequence.
        }

        // 5. Bounded Mempool Protection (Prevent RAM/Disk exhaustion)
        if self.mempool.len() >= MAX_MEMPOOL_SIZE {
            // Sort by gas_price to apply eviction policy (RBF)
            self.mempool.sort_by_key(|t| t.gas_price);
            if tx.gas_price <= self.mempool[0].gas_price {
                return Err("Mempool is full: Insufficient gas price for transaction eviction".to_string());
            }
            self.mempool.remove(0); // Remove lowest fee transaction
        }

        self.mempool.push(tx);
        let _ = self.storage.save_mempool(&self.mempool);
        Ok(hash)
    }

    /// Removes transactions failing state transition rules from mempool.
    /// Preserves only valid transactions and legitimate future nonces (with gap).
    pub fn prune_mempool(&mut self) -> usize {
        let initial_len = self.mempool.len();
        if initial_len == 0 {
            return 0;
        }

        let now_ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let next_height = self.height + 1;

        // Group by sender
        let mut by_sender: std::collections::HashMap<crate::account::Address, Vec<Transaction>> = std::collections::HashMap::new();
        for tx in self.mempool.drain(..) {
            by_sender.entry(tx.sender).or_default().push(tx);
        }

        let mut valid_txs = Vec::new();

        for (sender, mut txs) in by_sender {
            let sender_acc = match self.csmt.get(&sender).and_then(|b| Account::from_bytes(b).ok()) {
                Some(acc) => acc,
                None => continue, // Discard if account does not exist in CSMT
            };

            txs.sort_by_key(|t| t.nonce);

            let mut sim_csmt = self.csmt.clone();
            let mut expected_nonce = sender_acc.nonce;

            for tx in txs {
                // Nonce already passed
                if tx.nonce < expected_nonce {
                    continue;
                }

                // Current nonce: direct simulation
                if tx.nonce == expected_nonce {
                    match crate::state_transition::StateTransitionEngine::execute_transaction_with_context_sync(
                        &mut sim_csmt,
                        &tx,
                        self.address,
                        next_height,
                        now_ts,
                        self.evm_chain_id,
                    ) {
                        Ok(receipt) if receipt.success => {
                            expected_nonce += 1;
                            valid_txs.push(tx);
                        }
                        _ => {
                            // Failed rule check: pruned!
                            // expected_nonce does not advance
                        }
                    }
                } else if tx.nonce > expected_nonce {
                    // Future nonce (with gap)
                    if tx.nonce <= expected_nonce.saturating_add(MAX_PENDING_NONCE_GAP) {
                        valid_txs.push(tx);
                    }
                }
            }
        }

        self.mempool = valid_txs;
        if self.mempool.len() != initial_len {
            let _ = self.storage.save_mempool(&self.mempool);
        }
        initial_len - self.mempool.len()
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
        StateTransitionEngine::execute_block(&mut self.csmt, &mut block, self.evm_chain_id).await?;

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
        let key = self.keypair.clone().ok_or("Node has no validator key to propose")?;
        self.prune_mempool();
        let next_height = self.height + 1;
        let mut txs_to_include = self.mempool.clone();
        txs_to_include.sort_by(|a, b| {
            a.sender.cmp(&b.sender).then_with(|| a.nonce.cmp(&b.nonce))
        });
        // Tx cap per block (limits block size and execution within round)
        const MAX_TXS_PER_BLOCK: usize = 5000;
        txs_to_include.truncate(MAX_TXS_PER_BLOCK);

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
            txs_to_include.clone(),
            Vec::new(),
        );
        block.last_commit = last_commit;

        // Execute on a state COPY solely to populate state_root/tx_root (does not mutate real state)
        let mut sim_csmt = self.csmt.clone();
        StateTransitionEngine::execute_block(&mut sim_csmt, &mut block, self.evm_chain_id).await?;
        if block.transactions.len() != txs_to_include.len() {
            self.prune_mempool();
        }
        // After filtering applicable txs: do not propose empty block
        if block.transactions.is_empty() {
            return Err("No applicable transactions at this moment".to_string());
        }

        // Proposer PreCommit vote over block hash (which does NOT include signatures)
        let vote = Vote::new(
            &self.chain_id,
            next_height,
            0,
            block.hash(),
            VoteType::PreCommit,
            &key,
        );
        block.validator_signatures.push(ValidatorCommit::new(vote.validator_pubkey, vote.signature));

        Ok(block)
    }

    /// Phase 3 (follower): validates state transition of a PROPOSED block before voting.
    /// Re-executes ALL txs on a copy and requires recomputed roots match the
    /// signed header. An honest validator NEVER signs without verifying state.
    pub async fn validate_proposal(&self, block: &Block) -> Result<(), String> {
        let mut sim = self.csmt.clone();
        let (sr, txr, rr) = StateTransitionEngine::validate_block_strict(&mut sim, block, self.evm_chain_id).await?;
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
        Ok(())
    }

    /// Validates and applies a block received from P2P network with strict BFT consensus verification
    pub async fn apply_block(&mut self, block: Block) -> Result<[u8; 32], String> {
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
        if let Ok(Some(prev_block)) = self.storage.load_block(self.height) {
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

        // 2. Deterministic Proposer Validation (permits round advance if validator misses)
        let is_valid_proposer = (0..=10u64).any(|r| {
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
            0,
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
                0,
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
        let claimed_state_root = block.header.state_root;
        let claimed_tx_root = block.header.tx_root;
        let claimed_receipts_root = block.header.receipts_root;
        let mut sim_csmt = self.csmt.clone();
        let (calculated_state_root, calculated_tx_root, calculated_receipts_root) =
            StateTransitionEngine::validate_block_strict(&mut sim_csmt, &block, self.evm_chain_id).await?;

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

        // State validated! Commit permanently without ANY state mutation outside the block
        self.csmt = sim_csmt;
        self.last_committed_signatures = block.validator_signatures.clone();
        self.height = block.header.height;
        self.latest_block_hash = block.hash();
        self.storage.save_block(&block)?;
        self.storage.save_state(&self.csmt)?;
        let _ = self.storage.save_validators(&self.validator_set);

        // Remove executed transactions from mempool and prune rule-failing transactions
        let executed_hashes: std::collections::HashSet<[u8; 32]> =
            block.transactions.iter().map(|tx| tx.tx_hash()).collect();
        self.mempool.retain(|tx| !executed_hashes.contains(&tx.tx_hash()));
        self.prune_mempool();
        let _ = self.storage.save_mempool(&self.mempool);

        for (idx, tx) in block.transactions.iter().enumerate() {
            self.tx_index.insert(tx.tx_hash(), (block.header.height, idx));
            self.recent_transactions.insert(0, TxRecord {
                hash: format!("0x{}", hex::encode(tx.tx_hash())),
                block_number: block.header.height,
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
                timestamp: block.header.timestamp,
                status: "SUCCESS".to_string(),
            });
        }
        if self.recent_transactions.len() > 100 {
            self.recent_transactions.truncate(100);
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
}

