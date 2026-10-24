use crate::account::{Account, Address, ExecutionReceipt, address_from_hex};
use crate::block::Block;
use crate::csmt::CSMT;
use crate::transaction::Transaction;
use vera_engine_v2::{ComputationGraph, canonical_encode};

// ---------------------------------------------------------------------------------------
// Signature verification cache + parallel pre-verification.
//
// A tx is usually verified at mempool admission and then again inside every block
// execution (build / validate / apply). The cache remembers txs whose signature already
// verified, keyed so the key fixes EVERY input of `verify_signature`:
//   - native tx: tx_hash() = H(signing_hash || signature), and signing_hash covers
//     chain_id, public_key, sender, nonce, to, amount, gas and program;
//   - EVM tx: tx_hash() is keccak(raw) only, while verify_signature also checks the struct
//     fields against the raw payload (the v0.2.4.2 fix), so the key is the hash of the whole
//     serialized struct instead.
// Signatures of a block that are not in the cache are verified in parallel before the
// sequential execution; a failure is not cached, so the sequential path re-verifies it and
// returns exactly the same error as before.
// ---------------------------------------------------------------------------------------
const PARALLEL_VERIFY_MIN_TXS: usize = 64;

fn verified_sigs() -> &'static std::sync::Mutex<std::collections::HashSet<[u8; 32]>> {
    static CACHE: std::sync::OnceLock<std::sync::Mutex<std::collections::HashSet<[u8; 32]>>> = std::sync::OnceLock::new();
    CACHE.get_or_init(|| std::sync::Mutex::new(std::collections::HashSet::new()))
}

fn sig_cache_key(tx: &Transaction) -> [u8; 32] {
    if tx.raw_evm.is_some() {
        crate::chain_hash::hash256(&tx.to_bytes())
    } else {
        tx.tx_hash()
    }
}

fn remember_verified(keys: &[[u8; 32]]) {
    if let Ok(mut c) = verified_sigs().lock() {
        if c.len() + keys.len() > crate::hw::profile().signature_cache_entries() {
            c.clear();
        }
        c.extend(keys.iter().copied());
    }
}

/// Empties the signature cache (benchmarks and tests only).
#[doc(hidden)]
pub fn clear_signature_cache() {
    if let Ok(mut c) = verified_sigs().lock() {
        c.clear();
    }
}

/// verify_signature(), skipped when the same tx (same key) already verified.
pub fn verify_signature_cached(tx: &Transaction) -> Result<(), String> {
    let key = sig_cache_key(tx);
    if verified_sigs().lock().map_or(false, |c| c.contains(&key)) {
        return Ok(());
    }
    tx.verify_signature()?;
    remember_verified(&[key]);
    Ok(())
}

/// Verifies, on all cores, the signatures of `txs` not verified yet, and caches the valid
/// ones. Never fails: invalid txs are left for the sequential path to reject as before.
pub fn preverify_signatures(txs: &[Transaction]) {
    let pending: Vec<(&Transaction, [u8; 32])> = {
        let c = match verified_sigs().lock() {
            Ok(c) => c,
            Err(_) => return,
        };
        txs.iter()
            .map(|t| (t, sig_cache_key(t)))
            .filter(|(_, k)| !c.contains(k))
            .collect()
    };
    if pending.len() < PARALLEL_VERIFY_MIN_TXS {
        return; // not worth the threads; verified sequentially
    }
    let threads = crate::hw::profile().threads;
    if threads == 1 {
        return; // single core: the sequential path verifies them, no thread overhead
    }
    let chunk = (pending.len() + threads - 1) / threads;
    let ok: Vec<[u8; 32]> = std::thread::scope(|scope| {
        let handles: Vec<_> = pending
            .chunks(chunk)
            .map(|part| scope.spawn(move || {
                part.iter().filter(|(t, _)| t.verify_signature().is_ok()).map(|(_, k)| *k).collect::<Vec<_>>()
            }))
            .collect();
        handles.into_iter().flat_map(|h| h.join().unwrap_or_default()).collect()
    });
    remember_verified(&ok);
}

pub const BASE_TX_GAS: u64 = 21_000;
pub const GAS_PER_INSTRUCTION: u64 = 100;

pub const BURN_ADDRESS: Address = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xde, 0xad,
];

pub const STABILITY_POOL_ADDRESS: Address = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x5a, 0xfe,
];

pub struct StateTransitionEngine;

impl StateTransitionEngine {
    pub fn execute_transaction_sync(
        csmt: &mut CSMT,
        tx: &Transaction,
        proposer: Address,
    ) -> Result<ExecutionReceipt, String> {
        Self::execute_transaction_with_context_sync(csmt, tx, proposer, 0, 0, 83721)
    }

    pub fn execute_transaction_at_height_sync(
        csmt: &mut CSMT,
        tx: &Transaction,
        proposer: Address,
        block_height: u64,
    ) -> Result<ExecutionReceipt, String> {
        Self::execute_transaction_with_context_sync(csmt, tx, proposer, block_height, 0, 83721)
    }

    pub async fn execute_transaction(
        csmt: &mut CSMT,
        tx: &Transaction,
        proposer: Address,
    ) -> Result<ExecutionReceipt, String> {
        Self::execute_transaction_sync(csmt, tx, proposer)
    }

    pub async fn execute_transaction_at_height(
        csmt: &mut CSMT,
        tx: &Transaction,
        proposer: Address,
        block_height: u64,
    ) -> Result<ExecutionReceipt, String> {
        Self::execute_transaction_at_height_sync(csmt, tx, proposer, block_height)
    }

    pub async fn execute_transaction_with_context(
        csmt: &mut CSMT,
        tx: &Transaction,
        proposer: Address,
        block_height: u64,
        block_timestamp: u64,
        evm_chain_id: u64,
    ) -> Result<ExecutionReceipt, String> {
        Self::execute_transaction_with_context_sync(csmt, tx, proposer, block_height, block_timestamp, evm_chain_id)
    }

    pub fn execute_transaction_with_context_sync(
        csmt: &mut CSMT,
        tx: &Transaction,
        proposer: Address,
        block_height: u64,
        block_timestamp: u64,
        evm_chain_id: u64,
    ) -> Result<ExecutionReceipt, String> {
        // 1. Cryptographic Signature Verification and Cross-Chain Shielding
        verify_signature_cached(tx)?;

        // 2. Protection against Cross-Chain Replay
        if !tx.chain_id.starts_with("vera-") {
            return Err(format!(
                "Transaction Rejected: Cross-Chain Replay detected. chain_id '{}' does not belong to VERA network",
                tx.chain_id
            ));
        }

        // 3. Load or initialize sender account
        let mut sender_account = match csmt.get(&tx.sender) {
            Some(bytes) => Account::from_bytes(bytes)?,
            None => Account::new(0),
        };

        // 4. Strict Sequential Nonce Verification
        if tx.nonce != sender_account.nonce {
            return Err(format!(
                "Invalid nonce for account 0x{}: expected {}, got {}",
                hex::encode(tx.sender),
                sender_account.nonce,
                tx.nonce
            ));
        }

        // 5. Solvency Check for Value + Gas Limit
        let max_gas_cost = (tx.gas_limit as u128).saturating_mul(tx.gas_price as u128);
        let is_staking_non_debit = tx.to == Some(crate::account::STAKING_SYSTEM_ADDRESS)
            && (tx.program.starts_with(b"unstake") || tx.program == b"unjail" || tx.program.starts_with(b"allow:") || tx.program.starts_with(b"disallow:") || tx.program.starts_with(b"set_governance:"));
        let total_required = if is_staking_non_debit {
            max_gas_cost
        } else {
            tx.amount.saturating_add(max_gas_cost)
        };
        if sender_account.balance < total_required {
            return Err(format!(
                "Insufficient balance. Required: {}, Available: {}",
                total_required, sender_account.balance
            ));
        }
        sender_account.nonce += 1;
        sender_account.balance -= max_gas_cost;

        // 7. Multidimensional Gas Pricing: Base Cost + 10 gas per byte of calldata/program
        let calldata_gas = (tx.program.len() as u64).saturating_mul(10);
        let mut gas_used = BASE_TX_GAS.saturating_add(calldata_gas);
        let mut trace_root = [0u8; 32];
        let mut execution_success = true;
        let mut is_evm = false;
        let mut evm_logs = Vec::new();

        if tx.gas_limit < gas_used {
            return Err(format!(
                "Gas limit lower than base cost + calldata: {} < {}",
                tx.gas_limit, gas_used
            ));
        }

        // State Journal for mutation isolation
        let mut staged_recipient: Option<(Address, Account)> = None;

        // CHECK IF TRANSACTION IS TARGETED TO CANONICAL STAKING MODULE
        if tx.to == Some(crate::account::STAKING_SYSTEM_ADDRESS) {
            let mut val_set = match csmt.get(&crate::account::VALIDATOR_SET_CSMT_KEY) {
                Some(bytes) => crate::consensus::ValidatorSet::from_bytes(bytes)?,
                None => crate::consensus::ValidatorSet::new(vec![]),
            };

            if tx.program.starts_with(b"unstake") {
                // UNBOND WITH TIME-LOCK
                let unstake_amount = tx.amount;
                let release_height = block_height.saturating_add(val_set.unbonding_period_blocks);
                match val_set.unbond(&tx.public_key, unstake_amount, release_height) {
                    Ok(_unbonded) => {
                        csmt.insert(crate::account::VALIDATOR_SET_CSMT_KEY, val_set.to_bytes());
                        execution_success = true;
                    }
                    Err(e) => {
                        return Err(format!("On-chain unstake failure: {}", e));
                    }
                }
            } else if tx.program == b"unjail" {
                // EXPLICIT UNJAIL
                match val_set.unjail(&tx.public_key) {
                    Ok(()) => {
                        csmt.insert(crate::account::VALIDATOR_SET_CSMT_KEY, val_set.to_bytes());
                        execution_success = true;
                    }
                    Err(e) => {
                        return Err(format!("On-chain unjail failure: {}", e));
                    }
                }
            } else if tx.program.starts_with(b"allow:") {
                // GOVERNANCE: ADD VALIDATOR TO ALLOWLIST
                let gov_addr = val_set.governance_address.ok_or_else(|| "No governance account configured in state".to_string())?;
                if tx.sender != gov_addr {
                    return Err("Only governance account can add validators to allowlist".to_string());
                }
                let target_str = std::str::from_utf8(&tx.program[6..]).map_err(|e| e.to_string())?.trim();
                let target_addr = address_from_hex(target_str)?;
                val_set.allow(target_addr);
                csmt.insert(crate::account::VALIDATOR_SET_CSMT_KEY, val_set.to_bytes());
                execution_success = true;
            } else if tx.program.starts_with(b"disallow:") {
                // GOVERNANCE: REMOVE VALIDATOR FROM ALLOWLIST
                let gov_addr = val_set.governance_address.ok_or_else(|| "No governance account configured in state".to_string())?;
                if tx.sender != gov_addr {
                    return Err("Only governance account can remove validators from allowlist".to_string());
                }
                let target_str = std::str::from_utf8(&tx.program[9..]).map_err(|e| e.to_string())?.trim();
                let target_addr = address_from_hex(target_str)?;
                val_set.disallow(&target_addr);
                csmt.insert(crate::account::VALIDATOR_SET_CSMT_KEY, val_set.to_bytes());
                execution_success = true;
            } else if tx.program.starts_with(b"set_governance:") {
                // GOVERNANCE: TRANSFER GOVERNANCE TO NEW ADDRESS
                let gov_addr = val_set.governance_address.ok_or_else(|| "No governance account configured in state".to_string())?;
                if tx.sender != gov_addr {
                    return Err("Only current governance account can transfer governance".to_string());
                }
                let target_str = std::str::from_utf8(&tx.program[15..]).map_err(|e| e.to_string())?.trim();
                let target_addr = address_from_hex(target_str)?;
                val_set.governance_address = Some(target_addr);
                csmt.insert(crate::account::VALIDATOR_SET_CSMT_KEY, val_set.to_bytes());
                execution_success = true;
            } else {
                // BOND / STAKE
                if val_set.permissioned_validators && !val_set.is_allowed(&tx.sender) {
                    return Err(format!(
                        "Address 0x{} not authorized in permissioned validator allowlist",
                        hex::encode(tx.sender)
                    ));
                }
                if sender_account.balance < tx.amount {
                    return Err(format!(
                        "Insufficient balance to stake: balance {} < amount {}",
                        sender_account.balance, tx.amount
                    ));
                }

                let current_stake = val_set.validators.iter().find(|v| v.public_key == tx.public_key).map(|v| v.stake).unwrap_or(0);
                let new_stake = current_stake.saturating_add(tx.amount);
                if new_stake < val_set.min_validator_stake {
                    return Err(format!(
                        "Resulting stake {} wei is lower than minimum required {} wei",
                        new_stake, val_set.min_validator_stake
                    ));
                }

                // Deduct balance from sender and credit to STAKING_SYSTEM_ADDRESS
                sender_account.balance -= tx.amount;
                let mut staking_sys_acc = match csmt.get(&crate::account::STAKING_SYSTEM_ADDRESS) {
                    Some(bytes) => Account::from_bytes(bytes)?,
                    None => Account::new(0),
                };
                staking_sys_acc.balance = staking_sys_acc.balance.saturating_add(tx.amount);
                csmt.insert(crate::account::STAKING_SYSTEM_ADDRESS, staking_sys_acc.to_bytes());

                val_set.bond(tx.sender, tx.public_key, tx.amount)?;
                csmt.insert(crate::account::VALIDATOR_SET_CSMT_KEY, val_set.to_bytes());
                execution_success = true;
            }
        } else if tx.program.is_empty()
            && !tx.to.map(|dest| csmt.get(&dest).and_then(|b| Account::from_bytes(&b).ok()).map(|a| a.code_hash != [0u8; 32]).unwrap_or(false)).unwrap_or(false)
            && tx.raw_evm.is_none()
        {
            // Pure value transfer between EOA accounts
            if sender_account.balance < tx.amount {
                execution_success = false;
            } else {
                if let Some(recipient_addr) = tx.to {
                    if recipient_addr == tx.sender {
                        // Self-transfer: User balance remains the same
                    } else {
                        sender_account.balance -= tx.amount;
                        let mut recipient_account = match csmt.get(&recipient_addr) {
                            Some(bytes) => Account::from_bytes(bytes)?,
                            None => Account::new(0),
                        };
                        recipient_account.balance = recipient_account.balance.saturating_add(tx.amount);
                        staged_recipient = Some((recipient_addr, recipient_account));
                    }
                } else {
                    // tx.to is None: voluntary value burn
                    sender_account.balance -= tx.amount;
                }
            }
        } else if let Ok(graph) = serde_json::from_slice::<ComputationGraph>(&tx.program) {
            // Execution of native VERA Engine v2 smart contract
            trace_root = crate::chain_hash::hash256(&canonical_encode(&graph));
            execution_success = true;
            if sender_account.balance >= tx.amount {
                if let Some(recipient_addr) = tx.to {
                    if recipient_addr != tx.sender {
                        sender_account.balance -= tx.amount;
                        let mut recipient_account = match csmt.get(&recipient_addr) {
                            Some(bytes) => Account::from_bytes(bytes)?,
                            None => Account::new(0),
                        };
                        recipient_account.balance = recipient_account.balance.saturating_add(tx.amount);
                        staged_recipient = Some((recipient_addr, recipient_account));
                    }
                }
            } else {
                execution_success = false;
            }
        } else {
            is_evm = true;
            // Execution of Real deterministic EVM Smart Contract (REVM v43) integrated with CSMT
            match crate::evm::execute_evm(
                csmt,
                tx.sender,
                tx.to,
                tx.amount,
                tx.program.clone(),
                tx.gas_limit,
                tx.gas_price,
                tx.nonce,
                block_height,
                block_timestamp,
                evm_chain_id,
                false,
            ) {
                Ok(evm_res) => {
                    gas_used = evm_res.gas_used;
                    trace_root = crate::chain_hash::hash256(&evm_res.output);
                    execution_success = evm_res.success;
                    evm_logs = evm_res.logs;
                    if !evm_res.success {
                        if let Some(ref r) = evm_res.revert_reason {
                            eprintln!("⚠️ [EVM REVERT] tx 0x{}: {}", hex::encode(tx.tx_hash()), r);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("🛑 [EVM EXECUTION ERROR] tx 0x{}: {}", hex::encode(tx.tx_hash()), e);
                    execution_success = false;
                    gas_used = tx.gas_limit;
                }
            }
        }

        // If transaction succeeded, commit chained mutations
        if execution_success {
            if let Some((recip_addr, recip_acc)) = staged_recipient {
                csmt.insert(recip_addr, recip_acc.to_bytes());
            }
        }

        if is_evm && execution_success {
            // On EVM success, revm has already committed all state mutations directly to CSMT:
            // incremented nonce (tx.nonce + 1), debited balance (gas consumed + transferred value),
            // persisted code, and updated storage slots. Reload updated sender_account from CSMT without overwriting.
            if let Some(bytes) = csmt.get(&tx.sender) {
                if let Ok(_acc) = Account::from_bytes(&bytes) {
                    // State already committed and verified in CSMT
                }
            }
        } else {
            // For native transactions, or when EVM reverts/fails:
            // 7. Refund unused gas to sender
            let unused_gas = tx.gas_limit.saturating_sub(gas_used);
            let refund = (unused_gas as u128).saturating_mul(tx.gas_price as u128);
            sender_account.balance = sender_account.balance.saturating_add(refund);

            // Save updated sender in CSMT
            csmt.insert(tx.sender, sender_account.to_bytes());
        }

        // 8. Fee Distribution 70 / 15 / 15 (Official VERA Tokenomics)
        // 70% -> Block proposer (Validator compensation)
        // 15% -> Network Stability Pool (Reserve for low-volume periods)
        // 15% -> Permanent Burn Address (0x000...dead)
        let total_fee = (gas_used as u128).saturating_mul(tx.gas_price as u128);
        if total_fee > 0 {
            let proposer_fee = (total_fee.saturating_mul(70)) / 100;
            let stability_fee = (total_fee.saturating_mul(15)) / 100;
            let burn_fee = total_fee.saturating_sub(proposer_fee).saturating_sub(stability_fee);

            // 8.1 Credit to Proposer
            if proposer != [0u8; 32] && proposer_fee > 0 {
                let mut prop_account = match csmt.get(&proposer) {
                    Some(bytes) => Account::from_bytes(bytes)?,
                    None => Account::new(0),
                };
                prop_account.balance = prop_account.balance.saturating_add(proposer_fee);
                csmt.insert(proposer, prop_account.to_bytes());
            }

            // 8.2 Credit to Stability Pool
            if stability_fee > 0 {
                let mut stab_account = match csmt.get(&STABILITY_POOL_ADDRESS) {
                    Some(bytes) => Account::from_bytes(bytes)?,
                    None => Account::new(0),
                };
                stab_account.balance = stab_account.balance.saturating_add(stability_fee);
                csmt.insert(STABILITY_POOL_ADDRESS, stab_account.to_bytes());
            }

            // 8.3 Credit to Burn Address
            if burn_fee > 0 {
                let mut burn_account = match csmt.get(&BURN_ADDRESS) {
                    Some(bytes) => Account::from_bytes(bytes)?,
                    None => Account::new(0),
                };
                burn_account.balance = burn_account.balance.saturating_add(burn_fee);
                csmt.insert(BURN_ADDRESS, burn_account.to_bytes());
            }
        }

        let receipt = ExecutionReceipt {
            tx_hash: tx.tx_hash(),
            success: execution_success,
            gas_used,
            state_root: csmt.root(),
            trace_root,
            logs: if tx.to.is_none() && tx.program.is_empty() { Vec::new() } else { evm_logs },
        };

        Ok(receipt)
    }

    /// Executes all transactions in a block, calculating receipts and new state root
    pub async fn execute_block(
        csmt: &mut CSMT,
        block: &mut Block,
        evm_chain_id: u64,
    ) -> Result<[u8; 32], String> {
        // 1. Liveness audit and slashing from block.last_commit (for blocks > 1)
        if block.header.height > 1 {
            if let Some(val_set_bytes) = csmt.get(&crate::account::VALIDATOR_SET_CSMT_KEY) {
                if let Ok(mut val_set) = crate::consensus::ValidatorSet::from_bytes(val_set_bytes) {
                    let active_pubkeys: std::collections::HashSet<[u8; 32]> = block
                        .last_commit
                        .iter()
                        .map(|c| c.validator_pubkey)
                        .collect();
                    val_set.audit_liveness(&active_pubkeys);

                    let slashed_invalids = val_set.slash_inactive_validators();
                    for (_val_addr, penalty) in slashed_invalids {
                        let mut staking_sys_acc = match csmt.get(&crate::account::STAKING_SYSTEM_ADDRESS) {
                            Some(b) => Account::from_bytes(b)?,
                            None => Account::new(0),
                        };
                        staking_sys_acc.balance = staking_sys_acc.balance.saturating_sub(penalty);
                        csmt.insert(crate::account::STAKING_SYSTEM_ADDRESS, staking_sys_acc.to_bytes());

                        let mut stab_acc = match csmt.get(&crate::state_transition::STABILITY_POOL_ADDRESS) {
                            Some(b) => Account::from_bytes(b)?,
                            None => Account::new(0),
                        };
                        stab_acc.balance = stab_acc.balance.saturating_add(penalty);
                        csmt.insert(crate::state_transition::STABILITY_POOL_ADDRESS, stab_acc.to_bytes());
                    }
                    csmt.insert(crate::account::VALIDATOR_SET_CSMT_KEY, val_set.to_bytes());
                }
            }
        }

        // 2. Process maturation of unbondings reaching release height
        if let Some(val_set_bytes) = csmt.get(&crate::account::VALIDATOR_SET_CSMT_KEY) {
            if let Ok(mut val_set) = crate::consensus::ValidatorSet::from_bytes(val_set_bytes) {
                let maturing = val_set.process_maturing_unbondings(block.header.height);
                if !maturing.is_empty() {
                    let mut staking_sys_acc = match csmt.get(&crate::account::STAKING_SYSTEM_ADDRESS) {
                        Some(b) => Account::from_bytes(b)?,
                        None => Account::new(0),
                    };
                    for (val_addr, amount) in maturing {
                        staking_sys_acc.balance = staking_sys_acc.balance.saturating_sub(amount);
                        let mut val_acc = match csmt.get(&val_addr) {
                            Some(b) => Account::from_bytes(b)?,
                            None => Account::new(0),
                        };
                        val_acc.balance = val_acc.balance.saturating_add(amount);
                        csmt.insert(val_addr, val_acc.to_bytes());
                    }
                    csmt.insert(crate::account::STAKING_SYSTEM_ADDRESS, staking_sys_acc.to_bytes());
                    csmt.insert(crate::account::VALIDATOR_SET_CSMT_KEY, val_set.to_bytes());
                }
            }
        }

        preverify_signatures(&block.transactions);
        let mut receipts = Vec::with_capacity(block.transactions.len());
        let mut applied = Vec::with_capacity(block.transactions.len());

        for tx in &block.transactions {
            match Self::execute_transaction_with_context(csmt, tx, block.header.proposer, block.header.height, block.header.timestamp, evm_chain_id).await {
                Ok(receipt) => { receipts.push(receipt); applied.push(tx.clone()); }
                Err(_) => { /* unapplicable tx: omitted from this block */ }
            }
        }

        block.transactions = applied;
        block.header.tx_root = Block::compute_tx_root(&block.transactions);
        block.header.receipts_root = Block::compute_receipts_root(&receipts);
        block.header.last_commit_hash = Block::compute_commits_root(&block.last_commit);
        block.header.state_root = csmt.root();
        block.receipts = receipts;

        Ok(block.header.state_root)
    }

    /// Phase 3: STRICT validation (follower / apply side).
    pub async fn validate_block_strict(
        csmt: &mut CSMT,
        block: &Block,
        evm_chain_id: u64,
    ) -> Result<([u8; 32], [u8; 32], [u8; 32]), String> {
        Self::validate_block_strict_with_receipts(csmt, block, evm_chain_id).await.map(|(roots, _)| roots)
    }

    /// `validate_block_strict` that also returns the receipts it computed (a compact
    /// proposal arrives without them).
    pub async fn validate_block_strict_with_receipts(
        csmt: &mut CSMT,
        block: &Block,
        evm_chain_id: u64,
    ) -> Result<(([u8; 32], [u8; 32], [u8; 32]), Vec<ExecutionReceipt>), String> {
        // Validation of previous commits root in header
        if block.header.height > 1 {
            let expected_commit_hash = Block::compute_commits_root(&block.last_commit);
            if expected_commit_hash != block.header.last_commit_hash {
                return Err(format!(
                    "Invalid last_commit_hash in header: calc 0x{} != claimed 0x{}",
                    hex::encode(expected_commit_hash),
                    hex::encode(block.header.last_commit_hash)
                ));
            }
        }

        // 1. Liveness audit and slashing from block.last_commit (for blocks > 1)
        if block.header.height > 1 {
            if let Some(val_set_bytes) = csmt.get(&crate::account::VALIDATOR_SET_CSMT_KEY) {
                if let Ok(mut val_set) = crate::consensus::ValidatorSet::from_bytes(val_set_bytes) {
                    let active_pubkeys: std::collections::HashSet<[u8; 32]> = block
                        .last_commit
                        .iter()
                        .map(|c| c.validator_pubkey)
                        .collect();
                    val_set.audit_liveness(&active_pubkeys);

                    let slashed_invalids = val_set.slash_inactive_validators();
                    for (_val_addr, penalty) in slashed_invalids {
                        let mut staking_sys_acc = match csmt.get(&crate::account::STAKING_SYSTEM_ADDRESS) {
                            Some(b) => Account::from_bytes(b)?,
                            None => Account::new(0),
                        };
                        staking_sys_acc.balance = staking_sys_acc.balance.saturating_sub(penalty);
                        csmt.insert(crate::account::STAKING_SYSTEM_ADDRESS, staking_sys_acc.to_bytes());

                        let mut stab_acc = match csmt.get(&crate::state_transition::STABILITY_POOL_ADDRESS) {
                            Some(b) => Account::from_bytes(b)?,
                            None => Account::new(0),
                        };
                        stab_acc.balance = stab_acc.balance.saturating_add(penalty);
                        csmt.insert(crate::state_transition::STABILITY_POOL_ADDRESS, stab_acc.to_bytes());
                    }
                    csmt.insert(crate::account::VALIDATOR_SET_CSMT_KEY, val_set.to_bytes());
                }
            }
        }

        // 2. Process maturation of unbondings reaching release height
        if let Some(val_set_bytes) = csmt.get(&crate::account::VALIDATOR_SET_CSMT_KEY) {
            if let Ok(mut val_set) = crate::consensus::ValidatorSet::from_bytes(val_set_bytes) {
                let maturing = val_set.process_maturing_unbondings(block.header.height);
                if !maturing.is_empty() {
                    let mut staking_sys_acc = match csmt.get(&crate::account::STAKING_SYSTEM_ADDRESS) {
                        Some(b) => Account::from_bytes(b)?,
                        None => Account::new(0),
                    };
                    for (val_addr, amount) in maturing {
                        staking_sys_acc.balance = staking_sys_acc.balance.saturating_sub(amount);
                        let mut val_acc = match csmt.get(&val_addr) {
                            Some(b) => Account::from_bytes(b)?,
                            None => Account::new(0),
                        };
                        val_acc.balance = val_acc.balance.saturating_add(amount);
                        csmt.insert(val_addr, val_acc.to_bytes());
                    }
                    csmt.insert(crate::account::STAKING_SYSTEM_ADDRESS, staking_sys_acc.to_bytes());
                    csmt.insert(crate::account::VALIDATOR_SET_CSMT_KEY, val_set.to_bytes());
                }
            }
        }

        preverify_signatures(&block.transactions);
        let mut receipts = Vec::with_capacity(block.transactions.len());
        for tx in &block.transactions {
            let receipt = Self::execute_transaction_with_context(csmt, tx, block.header.proposer, block.header.height, block.header.timestamp, evm_chain_id).await?;
            receipts.push(receipt);
        }
        let state_root = csmt.root();
        let tx_root = Block::compute_tx_root(&block.transactions);
        let receipts_root = Block::compute_receipts_root(&receipts);
        Ok(((state_root, tx_root, receipts_root), receipts))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    use ed25519_dalek::SigningKey;
    use crate::consensus::ValidatorSet;

    #[tokio::test]
    async fn test_state_transition_transfer() {
        let mut csmt = CSMT::new();
        let mut csprng = OsRng;

        let alice_key = SigningKey::generate(&mut csprng);
        let alice_pub = alice_key.verifying_key().to_bytes();
        let alice_addr = crate::chain_hash::hash256(&alice_pub);

        let bob_key = SigningKey::generate(&mut csprng);
        let bob_pub = bob_key.verifying_key().to_bytes();
        let bob_addr = crate::chain_hash::hash256(&bob_pub);

        // Initialize Alice with 100_000_000 VERA wei
        let alice_initial = Account::new(100_000_000);
        csmt.insert(alice_addr, alice_initial.to_bytes());

        // Alice transfers 20_000_000 to Bob
        let tx = Transaction::new(
            "vera-testnet-1",
            &alice_key,
            0,
            Some(bob_addr),
            20_000_000,
            25_000,
            1,
            vec![],
        );

        let proposer = [9u8; 32];
        let receipt = StateTransitionEngine::execute_transaction(&mut csmt, &tx, proposer)
            .await
            .expect("Valid transaction");

        assert!(receipt.success);

        // Verify balances
        let alice_updated = Account::from_bytes(csmt.get(&alice_addr).unwrap()).unwrap();
        let bob_updated = Account::from_bytes(csmt.get(&bob_addr).unwrap()).unwrap();

        assert_eq!(bob_updated.balance, 20_000_000);
        assert_eq!(alice_updated.nonce, 1);

        let gas_used = receipt.gas_used as u128;
        let expected_alice_balance = 100_000_000 - 20_000_000 - gas_used;
        assert_eq!(alice_updated.balance, expected_alice_balance);

        // Verify 70/15/15 fee distribution
        let proposer_fee = (gas_used * 70) / 100;
        let stability_fee = (gas_used * 15) / 100;
        let burn_fee = gas_used - proposer_fee - stability_fee;

        let prop_account = Account::from_bytes(csmt.get(&proposer).unwrap()).unwrap();
        assert_eq!(prop_account.balance, proposer_fee);

        let stab_account = Account::from_bytes(csmt.get(&STABILITY_POOL_ADDRESS).unwrap()).unwrap();
        assert_eq!(stab_account.balance, stability_fee);

        let burn_account = Account::from_bytes(csmt.get(&BURN_ADDRESS).unwrap()).unwrap();
        assert_eq!(burn_account.balance, burn_fee);
    }

    #[tokio::test]
    async fn test_state_transition_self_transfer_does_not_vaporize_balance() {
        let mut csmt = CSMT::new();
        let mut csprng = OsRng;

        let alice_key = SigningKey::generate(&mut csprng);
        let alice_pub = alice_key.verifying_key().to_bytes();
        let alice_addr = crate::chain_hash::hash256(&alice_pub);

        // Alice with 100 VERA
        let initial_balance: u128 = 100_000_000_000_000_000_000;
        csmt.insert(alice_addr, Account::new(initial_balance).to_bytes());

        // Alice transfers 40 VERA to HERSELF
        let transfer_amount: u128 = 40_000_000_000_000_000_000;
        let tx = Transaction::new(
            "vera-testnet-1",
            &alice_key,
            0,
            Some(alice_addr),
            transfer_amount,
            25_000,
            1,
            vec![],
        );

        let proposer = [7u8; 32];
        let receipt = StateTransitionEngine::execute_transaction(&mut csmt, &tx, proposer)
            .await
            .expect("Valid transaction");

        assert!(receipt.success);

        let alice_after = Account::from_bytes(csmt.get(&alice_addr).unwrap()).unwrap();
        let gas_cost = receipt.gas_used as u128;
        assert_eq!(alice_after.balance, initial_balance - gas_cost);
    }

    #[tokio::test]
    async fn test_governance_strict_access_control_no_backdoors() {
        let mut csmt = CSMT::new();
        let mut csprng = OsRng;

        let gov_key = SigningKey::generate(&mut csprng);
        let gov_pub = gov_key.verifying_key().to_bytes();
        let gov_addr = crate::chain_hash::hash256(&gov_pub);

        let attacker_key = SigningKey::generate(&mut csprng);
        let attacker_pub = attacker_key.verifying_key().to_bytes();
        let attacker_addr = crate::chain_hash::hash256(&attacker_pub);

        // Configure ValidatorSet with strict governance
        let mut val_set = ValidatorSet::new(vec![]);
        val_set.governance_address = Some(gov_addr);
        val_set.permissioned_validators = true;
        csmt.insert(crate::account::VALIDATOR_SET_CSMT_KEY, val_set.to_bytes());

        // Balance to transact
        csmt.insert(attacker_addr, Account::new(10_000_000_000_000_000_000).to_bytes());
        csmt.insert(gov_addr, Account::new(10_000_000_000_000_000_000).to_bytes());

        let proposer = [1u8; 32];
        let target_val_str = "0x1111111111111111111111111111111111111111111111111111111111111111";

        // 1. Attacker attempts to execute allow: -> MUST FAIL
        let tx_attack_allow = Transaction::new(
            "vera-testnet-1",
            &attacker_key,
            0,
            Some(crate::account::STAKING_SYSTEM_ADDRESS),
            0,
            100_000,
            1,
            format!("allow:{}", target_val_str).into_bytes(),
        );
        let res_attack_allow = StateTransitionEngine::execute_transaction(&mut csmt, &tx_attack_allow, proposer).await;
        assert!(res_attack_allow.is_err(), "Attacker cannot execute allow:");
        assert_eq!(res_attack_allow.unwrap_err(), "Only governance account can add validators to allowlist");

        // 2. Attacker attempts to execute set_governance: -> MUST FAIL
        let tx_attack_set_gov = Transaction::new(
            "vera-testnet-1",
            &attacker_key,
            0,
            Some(crate::account::STAKING_SYSTEM_ADDRESS),
            0,
            100_000,
            1,
            format!("set_governance:0x{}", hex::encode(attacker_addr)).into_bytes(),
        );
        let res_attack_set_gov = StateTransitionEngine::execute_transaction(&mut csmt, &tx_attack_set_gov, proposer).await;
        assert!(res_attack_set_gov.is_err(), "Attacker cannot execute set_governance:");
        assert_eq!(res_attack_set_gov.unwrap_err(), "Only current governance account can transfer governance");

        // 3. Legitimate governance executes allow: -> MUST SUCCEED
        let tx_legit_allow = Transaction::new(
            "vera-testnet-1",
            &gov_key,
            0,
            Some(crate::account::STAKING_SYSTEM_ADDRESS),
            0,
            100_000,
            1,
            format!("allow:{}", target_val_str).into_bytes(),
        );
        let res_legit = StateTransitionEngine::execute_transaction(&mut csmt, &tx_legit_allow, proposer).await;
        assert!(res_legit.is_ok(), "Legitimate governance must succeed in allow:");

        // Verify validator was inserted into allowlist
        let vs_bytes = csmt.get(&crate::account::VALIDATOR_SET_CSMT_KEY).unwrap();
        let vs_updated = ValidatorSet::from_bytes(vs_bytes).unwrap();
        let target_val_addr = crate::account::address_from_hex(target_val_str).unwrap();
        assert!(vs_updated.is_allowed(&target_val_addr));

        // 4. Empty governance scenario: NO ONE can assume governance
        let mut val_set_empty = ValidatorSet::new(vec![]);
        val_set_empty.governance_address = None;
        csmt.insert(crate::account::VALIDATOR_SET_CSMT_KEY, val_set_empty.to_bytes());

        let tx_empty_attack = Transaction::new(
            "vera-testnet-1",
            &attacker_key,
            0,
            Some(crate::account::STAKING_SYSTEM_ADDRESS),
            0,
            100_000,
            1,
            format!("allow:{}", target_val_str).into_bytes(),
        );
        let res_empty_attack = StateTransitionEngine::execute_transaction(&mut csmt, &tx_empty_attack, proposer).await;
        assert!(res_empty_attack.is_err(), "Empty governance must reject any action");
        assert_eq!(res_empty_attack.unwrap_err(), "No governance account configured in state");
    }

    #[tokio::test]
    async fn test_state_transition_transfer_to_contract_without_calldata_routes_to_evm() {
        let mut csmt = CSMT::new();
        let mut csprng = OsRng;

        let alice_key = SigningKey::generate(&mut csprng);
        let alice_pub = alice_key.verifying_key().to_bytes();
        let alice_addr = crate::chain_hash::hash256(&alice_pub);

        // Create contract account with non-payable bytecode
        // Bytecode: REVERT if receiving funds (any call reverts: 60006000fd)
        let mut contract_addr = [0u8; 32];
        contract_addr[12..32].fill(0xcc);
        let mut contract_acc = Account::new(0);
        contract_acc.code_hash = [0xaa; 32]; // Mark as CONTRACT (code_hash != [0; 32])
        csmt.insert(contract_addr, contract_acc.to_bytes());

        // Alice with 10 VERA
        let initial_balance: u128 = 10_000_000_000_000_000_000;
        csmt.insert(alice_addr, Account::new(initial_balance).to_bytes());

        // Alice sends VERA to contract WITHOUT calldata (empty program)
        let transfer_amount: u128 = 1_000_000_000_000_000_000;
        let tx = Transaction::new(
            "vera-testnet-1",
            &alice_key,
            0,
            Some(contract_addr),
            transfer_amount,
            100_000,
            1,
            vec![], // EMPTY calldata (data = 0x)
        );

        let proposer = [9u8; 32];
        let _receipt = StateTransitionEngine::execute_transaction(&mut csmt, &tx, proposer)
            .await
            .expect("Processed transaction");

        // Verified regression: cannot transfer directly as EOA!
        // As contract does not have registered code in CsmtDatabase or is non-payable,
        // EVM is called (non-EOA). If it were EOA, receipt.success would be true and contract balance would increase.
        // Contract balance CANNOT be silently modified via EOA bypass!
        let contract_after = Account::from_bytes(csmt.get(&contract_addr).unwrap()).unwrap();
        // With protection, contract_after.balance remains 0!
        assert_eq!(contract_after.balance, 0, "Transfer to contract without data CANNOT credit via EOA bypass");
    }
}
