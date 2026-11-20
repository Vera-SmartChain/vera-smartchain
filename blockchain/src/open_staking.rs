//! VIP-004: open validator entry by stake, with the protections that make it safe.
//!
//! From activation on (mainnet only; the testnet keeps entry by approval):
//!
//! - **Open entry.** Anyone who bonds at least `min_validator_stake` becomes a validator. There
//!   is no allowlist: `allow:`/`disallow:` are refused for every sender. The active set is the
//!   `max_active_validators` largest stakes (`ValidatorSet::active_validators`), so a larger
//!   stake displaces the smallest one.
//! - **Entry churn.** New stake waits in a FIFO queue and enters at most
//!   `active stake ÷ CHURN_DIVISOR` per rolling churn window (24 h in production), counted by
//!   block timestamp. The window is kept as `CHURN_BUCKETS + 1` buckets of `window ÷ 24`, so
//!   any 24 h interval admits at most the limit.
//! - **Equivocation slashing.** Anyone can submit evidence that a key signed two different
//!   votes, or two different proposals, for the same height, round and step. The key loses
//!   `SLASH_BPS` of the stake at risk (100% once the keys slashed within one unbonding period
//!   hold 1/3 of the active stake), is removed from the set and is tombstoned forever.
//! - **Unbonding by time.** Unstaked stake is released `unbonding_secs` after the unstake
//!   (21 days in production, never below `MIN_UNBONDING_SECS`). It still answers for
//!   equivocation at heights up to the unstake block.
//! - **Anti-cartel.** Votes cannot close the door: `SetMaxActiveValidators` can only go up,
//!   `SetMinValidatorStake` only down, `Disallow` does not exist, and the liveness and
//!   unbonding parameters have floors in code (`check_gov_action`).
//!
//! Records are JSON in the CSMT (fixed field order, no maps), like the validator set.

use crate::account::{Account, Address, EvmLog, STAKING_SYSTEM_ADDRESS, VALIDATOR_SET_CSMT_KEY};
use crate::chain_hash::hash256;
use crate::consensus::{UnbondingEntry, Validator, ValidatorSet, Vote, VoteType};
use crate::csmt::CSMT;
use crate::governance::{FailCode, GovAction};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Evidence transactions are sent here (amount 0, payload `VEVD1` + JSON `Evidence`).
pub const EVIDENCE_SYSTEM_ADDRESS: Address = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x14, 0x00,
];
/// CSMT key of this record: `hash256(b"VOPEN1/state")`. It is a hash, not an address, so no account
/// can ever sit on it (a transfer to a fixed low address could create an `Account` there and
/// break `load_state` for every later block). The test below pins the value.
pub const OPEN_STATE_KEY: Address = [
    0x47, 0x03, 0xaa, 0x0f, 0xf0, 0x2b, 0x25, 0x94,
    0xe9, 0xa6, 0x52, 0xc0, 0xa3, 0xfd, 0x4a, 0x01,
    0x2b, 0xbc, 0x9f, 0xc1, 0x48, 0xd6, 0x5d, 0xf5,
    0xb7, 0xc0, 0xe0, 0x0d, 0xd9, 0x2b, 0x0e, 0x67,
];

pub const EVIDENCE_MAGIC: &[u8] = b"VEVD1";
pub const MAX_EVIDENCE_BYTES: usize = 4_096;
/// At most 1/20 (5%) of the active stake enters per churn window.
pub const CHURN_DIVISOR: u128 = 20;
/// The churn window is split into this many buckets (one more is kept, see module docs).
pub const CHURN_BUCKETS: u64 = 24;
/// Queued entries per validator key (bounds the queue a single key can grow).
pub const MAX_QUEUED_PER_KEY: usize = 8;
/// Equivocation slash: 5% of the stake at risk...
pub const SLASH_BPS: u128 = 500;
/// ...or all of it once the stake slashed within one unbonding period reaches 1/3 of the
/// active stake (enough to break BFT safety).
pub const BPS: u128 = 10_000;
/// Unbonding bounds for votes (fixed in code).
pub const MIN_UNBONDING_SECS: u64 = 14 * 86_400;
pub const MAX_UNBONDING_SECS: u64 = 60 * 86_400;
/// Liveness floor once entry is open: governance may raise `max_missed_blocks`, never set it
/// below the mainnet genesis value (a cartel could otherwise jail slower newcomers).
pub const MIN_MAX_MISSED_BLOCKS: u64 = 100;

/// Production values are fixed in code; only a devnet genesis may shorten them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenTiming {
    pub unbonding_secs: u64,
    pub churn_window_secs: u64,
}

impl OpenTiming {
    pub const PRODUCTION: OpenTiming = OpenTiming { unbonding_secs: 21 * 86_400, churn_window_secs: 86_400 };
}

impl Default for OpenTiming {
    fn default() -> Self {
        Self::PRODUCTION
    }
}

/// What a node passes to VIP-004 at activation (written into state, so nodes must agree).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct OpenConfig {
    pub timing: OpenTiming,
    /// `hash256(chain_id)`: evidence signatures must be for this chain.
    pub chain_id_hash: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueuedStake {
    pub address: Address,
    pub public_key: [u8; 32],
    pub amount: u128,
    pub queued_ts: u64,
}

/// A key slashed within the current correlation window (one unbonding period).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Offender {
    pub public_key: [u8; 32],
    pub address: Address,
    pub offense_height: u64,
    pub slashed_at_ts: u64,
    /// Stake at risk when the evidence was applied (bonded + queued + unbonding after the offense).
    pub base_stake: u128,
    /// Burned so far.
    pub slashed: u128,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenState {
    pub activated_height: u64,
    pub chain_id_hash: [u8; 32],
    pub timing: OpenTiming,
    /// Stake waiting to enter, oldest first.
    pub queue: Vec<QueuedStake>,
    /// (bucket index, stake admitted in it), oldest first.
    pub churn: Vec<(u64, u128)>,
    /// Keys banned forever for equivocation, sorted.
    pub tombstoned: Vec<[u8; 32]>,
    pub offenders: Vec<Offender>,
    /// Active stake when the first offender of the current window was slashed.
    pub window_ref_stake: u128,
}

pub fn load_state(csmt: &CSMT) -> Result<Option<OpenState>, String> {
    match csmt.get(&OPEN_STATE_KEY) {
        Some(b) => serde_json::from_slice(b).map(Some).map_err(|e| format!("VIP-004: bad state: {}", e)),
        None => Ok(None),
    }
}

fn save_state(csmt: &mut CSMT, st: &OpenState) {
    csmt.insert(OPEN_STATE_KEY, serde_json::to_vec(st).expect("OpenState serializes"));
}

fn validator_set(csmt: &CSMT) -> Result<ValidatorSet, String> {
    match csmt.get(&VALIDATOR_SET_CSMT_KEY) {
        Some(b) => ValidatorSet::from_bytes(b),
        None => Ok(ValidatorSet::new(vec![])),
    }
}

/// True when VIP-004 rules apply to a block at `height` (mempool admission uses `tip + 1`).
pub fn is_active_for(csmt: &CSMT, height: u64, activation: Option<u64>) -> bool {
    csmt.get(&OPEN_STATE_KEY).is_some() || activation.map_or(false, |a| height >= a)
}

/// At the first block at or above the activation height: the allowlist is switched off and
/// cleared, the liveness floor applies, and the initial state is written.
pub fn activate_if_due(csmt: &mut CSMT, height: u64, activation: Option<u64>, cfg: OpenConfig) {
    let Some(a) = activation else { return };
    if height < a || csmt.get(&OPEN_STATE_KEY).is_some() {
        return;
    }
    if let Some(Ok(mut vs)) = csmt.get(&VALIDATOR_SET_CSMT_KEY).map(|b| ValidatorSet::from_bytes(b)) {
        vs.permissioned_validators = false;
        vs.allowlist.clear();
        vs.max_missed_blocks = vs.max_missed_blocks.max(MIN_MAX_MISSED_BLOCKS);
        csmt.insert(VALIDATOR_SET_CSMT_KEY, vs.to_bytes());
    }
    save_state(
        csmt,
        &OpenState {
            activated_height: height,
            chain_id_hash: cfg.chain_id_hash,
            timing: cfg.timing,
            queue: Vec::new(),
            churn: Vec::new(),
            tombstoned: Vec::new(),
            offenders: Vec::new(),
            window_ref_stake: 0,
        },
    );
}

fn bucket_of(st: &OpenState, ts: u64) -> u64 {
    ts / (st.timing.churn_window_secs / CHURN_BUCKETS).max(1)
}

/// Stake admitted in the window ending at `now` (current bucket and the 24 before it).
pub fn churn_used(st: &OpenState, now: u64) -> u128 {
    let cur = bucket_of(st, now);
    st.churn.iter().filter(|(b, _)| b + CHURN_BUCKETS >= cur).map(|(_, a)| *a).sum()
}

/// Most stake that may enter per window: a fixed share of the active stake.
pub fn churn_limit(vs: &ValidatorSet) -> u128 {
    vs.active_total_stake() / CHURN_DIVISOR
}

fn queued_for(st: &OpenState, pk: &[u8; 32]) -> u128 {
    st.queue.iter().filter(|q| &q.public_key == pk).map(|q| q.amount).sum()
}

/// Runs at the start of every block, after unbonding maturation: activation, window
/// housekeeping, then admission of queued stake within the churn limit.
pub fn process_block(csmt: &mut CSMT, height: u64, now: u64, activation: Option<u64>, cfg: OpenConfig) -> Result<(), String> {
    activate_if_due(csmt, height, activation, cfg);
    let Some(mut st) = load_state(csmt)? else { return Ok(()) };
    let before = st.clone();
    let cur = bucket_of(&st, now);
    st.churn.retain(|(b, _)| b + CHURN_BUCKETS >= cur);
    let window = st.timing.unbonding_secs;
    st.offenders.retain(|o| now < o.slashed_at_ts.saturating_add(window));
    if st.offenders.is_empty() {
        st.window_ref_stake = 0;
    }
    if !st.queue.is_empty() {
        let mut vs = validator_set(csmt)?;
        let mut room = churn_limit(&vs).saturating_sub(churn_used(&st, now));
        let mut admitted = 0u128;
        while room > 0 && !st.queue.is_empty() {
            let q = &mut st.queue[0];
            let take = q.amount.min(room);
            match vs.validators.iter_mut().find(|v| v.public_key == q.public_key) {
                Some(v) => v.stake = v.stake.saturating_add(take),
                None => vs.validators.push(Validator {
                    address: q.address,
                    public_key: q.public_key,
                    stake: take,
                    missed_blocks: 0,
                    is_jailed: false,
                }),
            }
            q.amount -= take;
            room -= take;
            admitted += take;
            if q.amount == 0 {
                st.queue.remove(0);
            }
        }
        if admitted > 0 {
            match st.churn.last_mut() {
                Some((b, a)) if *b == cur => *a += admitted,
                _ => st.churn.push((cur, admitted)),
            }
            csmt.insert(VALIDATOR_SET_CSMT_KEY, vs.to_bytes());
        }
    }
    if st != before {
        save_state(csmt, &st);
    }
    Ok(())
}

/// Stake transaction under VIP-004: no allowlist, the stake waits in the entry queue. The
/// caller moves the funds to the staking account.
pub fn queue_stake(csmt: &mut CSMT, sender: Address, public_key: [u8; 32], amount: u128, now: u64) -> Result<(), String> {
    let mut st = load_state(csmt)?.ok_or("VIP-004: not active")?;
    if amount == 0 {
        return Err("Stake amount must be greater than zero".into());
    }
    crate::consensus::check_staking_key(false, &public_key)?;
    if st.tombstoned.binary_search(&public_key).is_ok() {
        return Err("VIP-004: this validator key is tombstoned for equivocation and cannot stake again".into());
    }
    let vs = validator_set(csmt)?;
    let current = vs.validators.iter().find(|v| v.public_key == public_key).map_or(0, |v| v.stake);
    let total = current.saturating_add(queued_for(&st, &public_key)).saturating_add(amount);
    if total < vs.min_validator_stake {
        return Err(format!(
            "Resulting stake {} wei is lower than minimum required {} wei",
            total, vs.min_validator_stake
        ));
    }
    match st.queue.last_mut() {
        Some(q) if q.public_key == public_key => q.amount = q.amount.saturating_add(amount),
        _ => {
            if st.queue.iter().filter(|q| q.public_key == public_key).count() >= MAX_QUEUED_PER_KEY {
                return Err(format!("VIP-004: at most {} queued stake entries per validator key", MAX_QUEUED_PER_KEY));
            }
            st.queue.push(QueuedStake { address: sender, public_key, amount, queued_ts: now });
        }
    }
    save_state(csmt, &st);
    Ok(())
}

/// Unstake under VIP-004: queued stake first (newest first), then bonded stake. Everything
/// unstaked is released `unbonding_secs` later, by timestamp. `amount` 0 = all.
pub fn unstake(csmt: &mut CSMT, public_key: &[u8; 32], amount: u128, height: u64, now: u64) -> Result<u128, String> {
    let mut st = load_state(csmt)?.ok_or("VIP-004: not active")?;
    let mut vs = validator_set(csmt)?;
    let idx = vs.validators.iter().position(|v| &v.public_key == public_key);
    let staked = idx.map_or(0, |i| vs.validators[i].stake);
    let queued = queued_for(&st, public_key);
    let total = staked.saturating_add(queued);
    if total == 0 {
        return Err("Validator not found for unstake".into());
    }
    let take = if amount == 0 || amount > total { total } else { amount };
    let remaining = total - take;
    if remaining > 0 && remaining < vs.min_validator_stake {
        return Err(format!(
            "Remaining stake of {} wei would fall below the required minimum of {} wei",
            remaining, vs.min_validator_stake
        ));
    }
    let address = idx
        .map(|i| vs.validators[i].address)
        .or_else(|| st.queue.iter().find(|q| &q.public_key == public_key).map(|q| q.address))
        .unwrap_or_else(|| hash256(public_key));
    let mut left = take;
    for q in st.queue.iter_mut().rev().filter(|q| &q.public_key == public_key) {
        let t = q.amount.min(left);
        q.amount -= t;
        left -= t;
    }
    st.queue.retain(|q| q.amount > 0);
    if left > 0 {
        let i = idx.ok_or("Validator not found for unstake")?;
        vs.validators[i].stake -= left;
        if vs.validators[i].stake == 0 {
            vs.validators.remove(i);
        }
    }
    vs.unbonding_queue.push(UnbondingEntry {
        validator_address: address,
        amount: take,
        release_height: 0,
        release_ts: Some(now.saturating_add(st.timing.unbonding_secs)),
        start_height: Some(height),
        public_key: Some(*public_key),
    });
    csmt.insert(VALIDATOR_SET_CSMT_KEY, vs.to_bytes());
    save_state(csmt, &st);
    Ok(take)
}

/// Unjail under VIP-004: a tombstoned key never comes back.
pub fn check_unjail(csmt: &CSMT, public_key: &[u8; 32]) -> Result<(), String> {
    let st = load_state(csmt)?.ok_or("VIP-004: not active")?;
    if st.tombstoned.binary_search(public_key).is_ok() {
        return Err("VIP-004: this validator key is tombstoned for equivocation".into());
    }
    Ok(())
}

// ------------------------------------------------------------------ evidence

/// A signed Tendermint proposal without the block body (the signature covers the block hash).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedProposal {
    pub chain_id: String,
    pub height: u64,
    pub round: u64,
    pub valid_round: Option<u64>,
    pub block_hash: [u8; 32],
    pub proposer_pubkey: [u8; 32],
    #[serde(with = "crate::account::serde_sig")]
    pub signature: [u8; 64],
}

impl SignedProposal {
    pub fn from_tm(p: &crate::p2p::messages::TmProposal) -> Self {
        Self {
            chain_id: p.chain_id.clone(),
            height: p.height,
            round: p.round,
            valid_round: p.valid_round,
            block_hash: p.block.hash(),
            proposer_pubkey: p.proposer_pubkey,
            signature: p.signature,
        }
    }

    fn digest(&self) -> [u8; 32] {
        crate::p2p::messages::TmProposal::signing_digest(
            &self.chain_id, self.height, self.round, self.valid_round, &self.block_hash, &self.proposer_pubkey,
        )
    }
}

fn verify_strict(pubkey: &[u8; 32], msg: &[u8; 32], sig: &[u8; 64]) -> Result<(), String> {
    let vk = VerifyingKey::from_bytes(pubkey).map_err(|e| format!("evidence: bad public key: {}", e))?;
    vk.verify_strict(msg, &Signature::from_bytes(sig)).map_err(|_| "evidence: invalid signature".to_string())
}

/// Proof that one key signed two different messages for the same height, round and step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Evidence {
    DuplicateVote { a: Vote, b: Vote },
    DuplicateProposal { a: SignedProposal, b: SignedProposal },
}

impl Evidence {
    pub fn parse(program: &[u8]) -> Result<Self, String> {
        if program.len() > MAX_EVIDENCE_BYTES {
            return Err("evidence: payload too large".into());
        }
        let body = program.strip_prefix(EVIDENCE_MAGIC).ok_or("evidence: payload must start with VEVD1")?;
        serde_json::from_slice(body).map_err(|e| format!("evidence: malformed payload: {}", e))
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = EVIDENCE_MAGIC.to_vec();
        out.extend_from_slice(&serde_json::to_vec(self).expect("Evidence serializes"));
        out
    }

    pub fn offender(&self) -> [u8; 32] {
        match self {
            Evidence::DuplicateVote { a, .. } => a.validator_pubkey,
            Evidence::DuplicateProposal { a, .. } => a.proposer_pubkey,
        }
    }

    pub fn height(&self) -> u64 {
        match self {
            Evidence::DuplicateVote { a, .. } => a.height,
            Evidence::DuplicateProposal { a, .. } => a.height,
        }
    }

    /// Both messages are for this chain, conflict, and carry valid signatures of one key.
    pub fn verify(&self, chain_id_hash: &[u8; 32]) -> Result<(), String> {
        let (chains, same, differ) = match self {
            Evidence::DuplicateVote { a, b } => (
                [&a.chain_id, &b.chain_id],
                a.height == b.height && a.round == b.round && a.vote_type == b.vote_type && a.validator_pubkey == b.validator_pubkey,
                a.block_hash != b.block_hash,
            ),
            Evidence::DuplicateProposal { a, b } => (
                [&a.chain_id, &b.chain_id],
                a.height == b.height && a.round == b.round && a.proposer_pubkey == b.proposer_pubkey,
                a.block_hash != b.block_hash,
            ),
        };
        if chains.iter().any(|c| &hash256(c.as_bytes()) != chain_id_hash) {
            return Err("evidence: signed for another chain".into());
        }
        if !same {
            return Err("evidence: the two messages are not for the same key, height, round and step".into());
        }
        if !differ {
            return Err("evidence: the two messages are for the same block".into());
        }
        match self {
            Evidence::DuplicateVote { a, b } => {
                verify_strict(&a.validator_pubkey, &a.signing_hash(), &a.signature)?;
                verify_strict(&b.validator_pubkey, &b.signing_hash(), &b.signature)
            }
            Evidence::DuplicateProposal { a, b } => {
                verify_strict(&a.proposer_pubkey, &a.digest(), &a.signature)?;
                verify_strict(&b.proposer_pubkey, &b.digest(), &b.signature)
            }
        }
    }
}

/// Stake of `pk` that answers for an offense at `offense_height` in this unbonding entry.
fn entry_at_risk(e: &UnbondingEntry, pk: &[u8; 32], addr: &Address, offense_height: u64) -> bool {
    let owner = match e.public_key {
        Some(k) => &k == pk,
        None => &e.validator_address == addr,
    };
    // Unstaked in block s: the stake was still in the active set for heights <= s.
    owner && e.start_height.map_or(true, |s| s >= offense_height)
}

/// Applies valid evidence: forced exit, tombstone, slash (correlated over the window).
pub fn apply_evidence(csmt: &mut CSMT, ev: &Evidence, height: u64, now: u64) -> Result<Vec<EvmLog>, String> {
    let mut st = load_state(csmt)?.ok_or("VIP-004: not active")?;
    ev.verify(&st.chain_id_hash)?;
    let pk = ev.offender();
    let h = ev.height();
    if h < st.activated_height {
        return Err("evidence: the offense predates VIP-004".into());
    }
    if h > height {
        return Err("evidence: height is in the future".into());
    }
    if st.tombstoned.binary_search(&pk).is_ok() {
        return Err("evidence: this key is already tombstoned".into());
    }
    let mut vs = validator_set(csmt)?;
    let active_now = vs.active_total_stake();

    // Forced exit: bonded and queued stake go to unbonding, still slashable.
    let idx = vs.validators.iter().position(|v| v.public_key == pk);
    let address = idx
        .map(|i| vs.validators[i].address)
        .or_else(|| st.queue.iter().find(|q| q.public_key == pk).map(|q| q.address))
        .unwrap_or_else(|| hash256(&pk));
    let bonded = idx.map_or(0, |i| vs.validators[i].stake).saturating_add(queued_for(&st, &pk));
    let unbonding: u128 = vs.unbonding_queue.iter().filter(|e| entry_at_risk(e, &pk, &address, h)).map(|e| e.amount).sum();
    let base_stake = bonded.saturating_add(unbonding);
    if base_stake == 0 {
        return Err("evidence: this key has no stake at risk for that height".into());
    }
    if let Some(i) = idx {
        vs.validators.remove(i);
    }
    // Never leave the chain without validators (for example a one-validator network whose
    // operator ran the key on two nodes): the chain could not make another block.
    if vs.active_validators().is_empty() {
        return Err("evidence: removing this key would leave no active validator".into());
    }
    st.queue.retain(|q| q.public_key != pk);
    if bonded > 0 {
        vs.unbonding_queue.push(UnbondingEntry {
            validator_address: address,
            amount: bonded,
            release_height: 0,
            release_ts: Some(now.saturating_add(st.timing.unbonding_secs)),
            start_height: Some(height),
            public_key: Some(pk),
        });
    }
    let pos = st.tombstoned.binary_search(&pk).unwrap_err();
    st.tombstoned.insert(pos, pk);
    if st.offenders.is_empty() {
        st.window_ref_stake = active_now.max(1);
    }
    st.offenders.push(Offender { public_key: pk, address, offense_height: h, slashed_at_ts: now, base_stake, slashed: 0 });

    // 5%, or everything once the keys slashed in this window hold 1/3 of the stake.
    let window_stake: u128 = st.offenders.iter().map(|o| o.base_stake).sum();
    let bps = if window_stake.saturating_mul(3) >= st.window_ref_stake { BPS } else { SLASH_BPS };
    let mut burned = 0u128;
    for o in st.offenders.iter_mut() {
        let target = o.base_stake / BPS * bps + o.base_stake % BPS * bps / BPS;
        let mut extra = target.saturating_sub(o.slashed);
        for e in vs.unbonding_queue.iter_mut().rev() {
            if extra == 0 {
                break;
            }
            if entry_at_risk(e, &o.public_key, &o.address, o.offense_height) {
                let t = e.amount.min(extra);
                e.amount -= t;
                extra -= t;
                o.slashed += t;
                burned += t;
            }
        }
    }
    vs.unbonding_queue.retain(|e| e.amount > 0);

    if burned > 0 {
        let mut staking = match csmt.get(&STAKING_SYSTEM_ADDRESS) {
            Some(b) => Account::from_bytes(b)?,
            None => Account::new(0),
        };
        // Same accounting as the liveness slash (never lets an equivocator escape on a
        // rounding gap in the staking account).
        staking.balance = staking.balance.saturating_sub(burned);
        let mut burn = match csmt.get(&crate::state_transition::BURN_ADDRESS) {
            Some(b) => Account::from_bytes(b)?,
            None => Account::new(0),
        };
        burn.balance = burn.balance.saturating_add(burned);
        csmt.insert(STAKING_SYSTEM_ADDRESS, staking.to_bytes());
        csmt.insert(crate::state_transition::BURN_ADDRESS, burn.to_bytes());
    }
    csmt.insert(VALIDATOR_SET_CSMT_KEY, vs.to_bytes());
    save_state(csmt, &st);
    let mut data = base_stake.to_be_bytes().to_vec();
    data.extend_from_slice(&burned.to_be_bytes());
    Ok(vec![EvmLog { address: EVIDENCE_SYSTEM_ADDRESS, topics: vec![hash256(b"VEVD1.Slashed"), pk], data }])
}

// ------------------------------------------------------------------ governance limits

/// VIP-004 limits on governance actions, checked when proposing and again at execution.
pub fn check_gov_action(csmt: &CSMT, a: &GovAction) -> Result<(), FailCode> {
    let Some(st) = load_state(csmt).map_err(|_| FailCode::InvalidAction)? else {
        return match a {
            GovAction::SetUnbondingPeriodSecs { .. } => Err(FailCode::InvalidAction),
            _ => Ok(()),
        };
    };
    let vs = validator_set(csmt).map_err(|_| FailCode::InvalidAction)?;
    match a {
        // No allowlist, and unbonding is counted in time.
        GovAction::Allow { .. } | GovAction::SetUnbondingPeriodBlocks { .. } => Err(FailCode::InvalidAction),
        GovAction::Disallow { .. } => Err(FailCode::ClosesEntry),
        GovAction::SetMaxActiveValidators { count } if (*count as usize) < vs.max_active_validators => Err(FailCode::ClosesEntry),
        GovAction::SetMinValidatorStake { wei } if *wei > vs.min_validator_stake => Err(FailCode::ClosesEntry),
        GovAction::SetMaxMissedBlocks { blocks } if *blocks < MIN_MAX_MISSED_BLOCKS => Err(FailCode::BelowFloor),
        // Static bounds here; the "at most half per window" cut is checked at execution
        // against the window peak (governance rails).
        GovAction::SetUnbondingPeriodSecs { secs }
            if !(MIN_UNBONDING_SECS..=MAX_UNBONDING_SECS).contains(secs) || secs.saturating_mul(2) < st.timing.unbonding_secs =>
        {
            Err(FailCode::BelowFloor)
        }
        _ => Ok(()),
    }
}

/// Executes `SetUnbondingPeriodSecs` (after `check_gov_action`). Entries already unbonding
/// keep their release time.
pub fn set_unbonding_secs(csmt: &mut CSMT, secs: u64) -> Result<(), FailCode> {
    let mut st = load_state(csmt).map_err(|_| FailCode::InvalidAction)?.ok_or(FailCode::InvalidAction)?;
    st.timing.unbonding_secs = secs;
    save_state(csmt, &st);
    Ok(())
}

// ------------------------------------------------------------------ detection (node side)

/// Watches the consensus messages of one height and returns evidence the first time a key
/// signs two different messages for the same round and step. Not part of consensus.
#[derive(Debug, Default)]
pub struct EquivocationTracker {
    height: u64,
    votes: HashMap<(u64, u8, [u8; 32]), Vote>,
    proposals: HashMap<(u64, [u8; 32]), SignedProposal>,
    reported: HashSet<[u8; 32]>,
}

impl EquivocationTracker {
    /// Forgets that `offender` was reported, so the next conflicting message returns the
    /// evidence again. Call it when submitting the evidence failed.
    pub fn forget(&mut self, offender: &[u8; 32]) {
        self.reported.remove(offender);
    }

    fn at(&mut self, height: u64) {
        if height != self.height {
            *self = EquivocationTracker { height, ..Default::default() };
        }
    }

    pub fn on_vote(&mut self, v: &Vote) -> Option<Evidence> {
        self.at(v.height);
        let step = match v.vote_type {
            VoteType::PreVote => 1,
            VoteType::PreCommit => 2,
        };
        let key = (v.round, step, v.validator_pubkey);
        match self.votes.get(&key) {
            None => {
                self.votes.insert(key, v.clone());
                None
            }
            Some(first) if first.block_hash != v.block_hash && self.reported.insert(v.validator_pubkey) => {
                Some(Evidence::DuplicateVote { a: first.clone(), b: v.clone() })
            }
            Some(_) => None,
        }
    }

    pub fn on_proposal(&mut self, p: SignedProposal) -> Option<Evidence> {
        self.at(p.height);
        let key = (p.round, p.proposer_pubkey);
        match self.proposals.get(&key) {
            None => {
                self.proposals.insert(key, p);
                None
            }
            Some(first) if first.block_hash != p.block_hash && self.reported.insert(p.proposer_pubkey) => {
                Some(Evidence::DuplicateProposal { a: first.clone(), b: p })
            }
            Some(_) => None,
        }
    }
}

#[cfg(test)]
mod reserved_key_tests {
    #[test]
    fn state_key_is_the_domain_separated_hash() {
        assert_eq!(super::OPEN_STATE_KEY, crate::chain_hash::hash256(b"VOPEN1/state"));
    }
}
