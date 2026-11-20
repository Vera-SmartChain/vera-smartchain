//! VIP-003: on-chain governance by validator vote.
//!
//! From activation on, the protocol parameters that the governance key used to change alone
//! (the VIP-001 fees and registrar, the validator allowlist and the staking parameters) can
//! only change through a proposal approved by the validators:
//!
//! - an active validator proposes an action with a voting period;
//! - the active validators and their stake are snapshotted at that moment;
//! - the proposal passes when the "yes" stake reaches the consensus supermajority threshold
//!   of the snapshot (`ceil(2 × total ÷ 3)`, the same threshold that finalizes blocks);
//! - it executes after a timelock, at the start of the first block whose timestamp is at or
//!   after `passed_at + timelock`. If the action fails (for example a VIP-001 bound), the
//!   proposal is recorded as failed and nothing changes.
//!
//! The governance key keeps two powers: `set_governance` (key rotation, in the staking
//! module) and the emergency `PAUSE_REGISTRY`, which stops new VIP-001 registrations for at
//! most 72 hours, at most once every 30 days, and only until the emergency power expires
//! (365 days after activation, or earlier by vote).
//!
//! Records are stored as JSON in the CSMT, like the validator set: fixed field order, no
//! maps, so the encoding is deterministic.

use crate::account::{Address, EvmLog};
use crate::chain_hash::hash256;
use crate::csmt::CSMT;
use serde::{Deserialize, Serialize};

/// Governance operations are sent here (amount 0).
pub const GOVERNANCE_SYSTEM_ADDRESS: Address = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x13, 0x00,
];
/// CSMT key of this record: `hash256(b"VGOV1/state")`. It is a hash, not an address, so no account
/// can ever sit on it (a transfer to a fixed low address could create an `Account` there and
/// break `load_state` for every later block). The test below pins the value.
pub const GOV_STATE_KEY: Address = [
    0xdf, 0xfc, 0xab, 0x7c, 0x14, 0xdb, 0x37, 0xda,
    0x36, 0xca, 0x77, 0x7e, 0x26, 0xca, 0x51, 0x04,
    0x45, 0xfd, 0x77, 0x33, 0x8d, 0xea, 0xf3, 0xbc,
    0xf9, 0x29, 0x1f, 0xa9, 0x79, 0x7e, 0xe1, 0xe7,
];

pub const MAGIC: &[u8] = b"VGOV1";
pub const MAX_OPEN_PER_VALIDATOR: usize = 3;
pub const MAX_PAUSE_SECS: u64 = 72 * 3_600;
pub const KEY_PAUSE_COOLDOWN_SECS: u64 = 30 * 86_400;
pub const EMERGENCY_POWER_SECS: u64 = 365 * 86_400;
pub const MAX_PAYLOAD_BYTES: usize = 1_024;
/// Safety floors for staking parameters changed by vote (fixed in code).
pub const MIN_MAX_MISSED_BLOCKS: u64 = 10;
pub const MIN_UNBONDING_PERIOD_BLOCKS: u64 = 5;
/// The safety rails are cumulative over this window, not per proposal: at most 1/3 of the
/// active stake removed, and no parameter cut below half of its highest value, per window.
pub const RAIL_WINDOW_SECS: u64 = 7 * 86_400;

/// What a node passes to VIP-003 at activation. Both values are written into state at the
/// activation block, so every node must agree on them (a mismatch diverges at once).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GovConfig {
    pub timing: GovTiming,
    /// The governance key keeps `allow:`/`disallow:` after activation (testnet only;
    /// never on mainnet, see `genesis::builtin_key_keeps_allowlist`).
    pub key_allowlist: bool,
}

impl From<GovTiming> for GovConfig {
    fn from(timing: GovTiming) -> Self {
        GovConfig { timing, key_allowlist: false }
    }
}

/// Voting windows. Production values are fixed in code; only a devnet genesis may shorten
/// them (for tests that must run a full cycle in minutes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovTiming {
    pub timelock_secs: u64,
    pub min_voting_secs: u64,
    pub max_voting_secs: u64,
}

impl GovTiming {
    pub const PRODUCTION: GovTiming = GovTiming {
        timelock_secs: 48 * 3_600,
        min_voting_secs: 3 * 86_400,
        max_voting_secs: 14 * 86_400,
    };
}

impl Default for GovTiming {
    fn default() -> Self {
        Self::PRODUCTION
    }
}

/// What a passed proposal does.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GovAction {
    /// VIP-001 `min_gas_price_wei` (VIP-001 bounds apply).
    SetGasPrice { min_gas_price_wei: u64 },
    /// VIP-001 `fee_per_item_wei` (VIP-001 bounds apply).
    SetFee { fee_per_item_wei: u128 },
    /// VIP-001 registrar (the address that attests issuers).
    SetRegistrar { address: Address },
    /// Validator allowlist.
    Allow { address: Address },
    Disallow { address: Address },
    /// Staking parameters.
    SetMinValidatorStake { wei: u128 },
    SetMaxActiveValidators { count: u64 },
    SetUnbondingPeriodBlocks { blocks: u64 },
    SetMaxMissedBlocks { blocks: u64 },
    /// VIP-004 (once active): unbonding period in seconds, within the bounds fixed in code.
    SetUnbondingPeriodSecs { secs: u64 },
    /// Ends a registry pause now.
    Unpause,
    /// Ends the governance key's emergency pause power now (it cannot come back).
    EndEmergencyPower,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GovOp {
    /// Active validators. `voting_period_secs` within the timing bounds.
    Propose { action: GovAction, voting_period_secs: u64 },
    /// Validators in the proposal's snapshot, once each.
    Vote { id: u64, yes: bool },
    /// The proposer, before any vote.
    Cancel { id: u64 },
    /// Governance key, emergency only (see module docs).
    PauseRegistry { duration_secs: u64 },
    /// Governance key: ends its own pause early.
    Unpause,
}

impl GovOp {
    pub fn parse(program: &[u8]) -> Result<Self, String> {
        if program.len() > MAX_PAYLOAD_BYTES {
            return Err("governance: payload too large".to_string());
        }
        let body = program.strip_prefix(MAGIC).ok_or("governance: payload must start with VGOV1")?;
        serde_json::from_slice(body).map_err(|e| format!("governance: malformed payload: {}", e))
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = MAGIC.to_vec();
        out.extend_from_slice(&serde_json::to_vec(self).expect("GovOp serializes"));
        out
    }

    fn topic(&self) -> [u8; 32] {
        let name: &[u8] = match self {
            GovOp::Propose { .. } => b"VGOV1.Propose",
            GovOp::Vote { .. } => b"VGOV1.Vote",
            GovOp::Cancel { .. } => b"VGOV1.Cancel",
            GovOp::PauseRegistry { .. } => b"VGOV1.PauseRegistry",
            GovOp::Unpause => b"VGOV1.Unpause",
        };
        hash256(name)
    }
}

/// Why a passed proposal failed at execution. Stored in state, so these are fixed codes:
/// never store error text in state (a later release could change the wording and change
/// the state root of old blocks). Variants are never renamed or reordered (serde stores
/// the name); new ones are only appended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FailCode {
    /// The action needs the document registry (VIP-001), which is not active.
    RegistryInactive,
    /// VIP-001 refused the change (2x bound, 7-day interval or ceiling).
    RegistryRejected,
    /// The action is invalid for the current state.
    InvalidAction,
    /// The active validator set would be empty.
    EmptyActiveSet,
    /// The action would deactivate more than 1/3 of the active stake.
    RemovesTooMuchStake,
    /// A staking parameter would go below its floor or drop by more than half at once.
    BelowFloor,
    /// VIP-004: the action would close validator entry (lower the active-set size, raise
    /// the minimum stake, or remove a validator without proof).
    ClosesEntry,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProposalStatus {
    Open,
    Passed { at: u64 },
    Executed { at: u64 },
    Failed { at: u64, code: FailCode },
    Expired { at: u64 },
    Cancelled { at: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proposal {
    pub id: u64,
    pub proposer: Address,
    pub action: GovAction,
    pub created_ts: u64,
    pub deadline_ts: u64,
    /// Active validators and their stake when the proposal was created.
    pub snapshot: Vec<(Address, u128)>,
    pub threshold: u128,
    pub votes: Vec<(Address, bool)>,
    pub yes_stake: u128,
    pub status: ProposalStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovState {
    pub timing: GovTiming,
    pub next_id: u64,
    /// Proposals still Open or Passed (not yet executed), oldest first.
    pub open: Vec<u64>,
    /// New VIP-001 registrations are refused while `timestamp < paused_until_ts`.
    pub paused_until_ts: u64,
    pub last_key_pause_ts: u64,
    /// The governance key may pause only while `timestamp < emergency_until_ts`.
    pub emergency_until_ts: u64,
    /// The governance key keeps `allow:`/`disallow:` (testnet only).
    pub key_allowlist: bool,
    /// Current window of the safety rails (None until the first staking action executes).
    #[serde(default)]
    pub rail_window: Option<RailWindow>,
}

/// Cumulative safety rails over `RAIL_WINDOW_SECS`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RailWindow {
    pub start_ts: u64,
    /// Active stake (allowlisted, on permissioned sets) when the window started.
    pub active_stake: u128,
    /// Stake removed from the active set by votes in this window.
    pub removed: u128,
    /// Highest value of each parameter in this window (starts at the value at window start).
    pub max_missed_peak: u64,
    pub unbonding_blocks_peak: u64,
    pub unbonding_secs_peak: u64,
}

fn proposal_key(id: u64) -> Address {
    let mut pre = b"VGOV1/proposal".to_vec();
    pre.extend_from_slice(&id.to_le_bytes());
    hash256(&pre)
}

pub fn load_state(csmt: &CSMT) -> Result<Option<GovState>, String> {
    match csmt.get(&GOV_STATE_KEY) {
        Some(b) => serde_json::from_slice(b).map(Some).map_err(|e| format!("governance: bad state: {}", e)),
        None => Ok(None),
    }
}

fn save_state(csmt: &mut CSMT, st: &GovState) {
    csmt.insert(GOV_STATE_KEY, serde_json::to_vec(st).expect("GovState serializes"));
}

pub fn load_proposal(csmt: &CSMT, id: u64) -> Result<Option<Proposal>, String> {
    match csmt.get(&proposal_key(id)) {
        Some(b) => serde_json::from_slice(b).map(Some).map_err(|e| format!("governance: bad proposal: {}", e)),
        None => Ok(None),
    }
}

fn save_proposal(csmt: &mut CSMT, p: &Proposal) {
    csmt.insert(proposal_key(p.id), serde_json::to_vec(p).expect("Proposal serializes"));
}

/// True when VIP-003 rules apply to a block at `height` (stored, or this is the first block
/// at or above the activation height). Mempool admission and the RPC use `tip + 1`.
pub fn is_active_for(csmt: &CSMT, height: u64, activation: Option<u64>) -> bool {
    csmt.get(&GOV_STATE_KEY).is_some() || activation.map_or(false, |a| height >= a)
}

/// Writes the initial state at the first block at or above the activation height.
pub fn activate_if_due(csmt: &mut CSMT, height: u64, timestamp: u64, activation: Option<u64>, cfg: impl Into<GovConfig>) {
    let GovConfig { timing, key_allowlist } = cfg.into();
    if let Some(a) = activation {
        if height >= a && csmt.get(&GOV_STATE_KEY).is_none() {
            save_state(
                csmt,
                &GovState {
                    timing,
                    next_id: 1,
                    open: Vec::new(),
                    paused_until_ts: 0,
                    last_key_pause_ts: 0,
                    emergency_until_ts: timestamp.saturating_add(EMERGENCY_POWER_SECS),
                    key_allowlist,
                    rail_window: None,
                },
            );
        }
    }
}

/// True when new VIP-001 registrations are paused at `timestamp`.
pub fn registrations_paused(csmt: &CSMT, timestamp: u64) -> Result<bool, String> {
    Ok(load_state(csmt)?.map_or(false, |s| timestamp < s.paused_until_ts))
}

fn validator_set(csmt: &CSMT) -> Result<crate::consensus::ValidatorSet, String> {
    match csmt.get(&crate::account::VALIDATOR_SET_CSMT_KEY) {
        Some(b) => crate::consensus::ValidatorSet::from_bytes(b),
        None => Err("governance: no validator set in state".to_string()),
    }
}

/// Checks that need no state (run when proposing, so a hopeless proposal is refused early).
/// Bounds that depend on state (VIP-001 limits) are checked again at execution.
pub fn validate_action(a: &GovAction) -> Result<(), String> {
    action_code(a).map_err(|code| match (code, a) {
        (FailCode::BelowFloor, GovAction::SetUnbondingPeriodBlocks { .. }) => {
            format!("governance: unbonding period must be {}..=10,000,000 blocks", MIN_UNBONDING_PERIOD_BLOCKS)
        }
        (FailCode::BelowFloor, GovAction::SetMaxMissedBlocks { .. }) => {
            format!("governance: max missed blocks must be {}..=1,000,000", MIN_MAX_MISSED_BLOCKS)
        }
        (FailCode::BelowFloor, _) => format!(
            "governance: unbonding period must be {}..={} seconds",
            crate::open_staking::MIN_UNBONDING_SECS,
            crate::open_staking::MAX_UNBONDING_SECS
        ),
        (_, GovAction::SetGasPrice { .. }) => "governance: gas price must be > 0".into(),
        (_, GovAction::SetFee { .. }) => "governance: fee must be > 0".into(),
        (_, GovAction::SetMinValidatorStake { .. }) => "governance: min stake must be > 0".into(),
        (_, GovAction::SetMaxActiveValidators { .. }) => "governance: max active validators must be 1..=200".into(),
        _ => "governance: zero address".into(),
    })
}

/// The fixed code of a static check: malformed values are `InvalidAction`; only a staking
/// parameter outside its floor or ceiling is `BelowFloor`.
pub fn action_code(a: &GovAction) -> Result<(), FailCode> {
    use crate::open_staking::{MAX_UNBONDING_SECS, MIN_UNBONDING_SECS};
    match a {
        GovAction::SetGasPrice { min_gas_price_wei: 0 } | GovAction::SetFee { fee_per_item_wei: 0 } => Err(FailCode::InvalidAction),
        GovAction::SetRegistrar { address } | GovAction::Allow { address } | GovAction::Disallow { address } if *address == [0u8; 32] => {
            Err(FailCode::InvalidAction)
        }
        GovAction::SetMinValidatorStake { wei: 0 } => Err(FailCode::InvalidAction),
        GovAction::SetMaxActiveValidators { count } if !(1..=200).contains(count) => Err(FailCode::InvalidAction),
        GovAction::SetUnbondingPeriodBlocks { blocks } if !(MIN_UNBONDING_PERIOD_BLOCKS..=10_000_000).contains(blocks) => {
            Err(FailCode::BelowFloor)
        }
        GovAction::SetMaxMissedBlocks { blocks } if !(MIN_MAX_MISSED_BLOCKS..=1_000_000).contains(blocks) => Err(FailCode::BelowFloor),
        GovAction::SetUnbondingPeriodSecs { secs } if !(MIN_UNBONDING_SECS..=MAX_UNBONDING_SECS).contains(secs) => {
            Err(FailCode::BelowFloor)
        }
        _ => Ok(()),
    }
}

/// The rail window open at `now` (a new one starts from the current values once the last
/// one is over).
fn rail_window(st: &GovState, csmt: &CSMT, vs: &crate::consensus::ValidatorSet, now: u64) -> RailWindow {
    match &st.rail_window {
        Some(w) if now < w.start_ts.saturating_add(RAIL_WINDOW_SECS) => w.clone(),
        _ => RailWindow {
            start_ts: now,
            active_stake: counted_active(vs).iter().map(|(_, s)| *s).sum(),
            removed: 0,
            max_missed_peak: vs.max_missed_blocks,
            unbonding_blocks_peak: vs.unbonding_period_blocks,
            unbonding_secs_peak: crate::open_staking::load_state(csmt).ok().flatten().map_or(0, |o| o.timing.unbonding_secs),
        },
    }
}

/// Active validators that count for the rails. On a permissioned set a disallowed validator
/// does not count, before or after the action (it is treated as already gone).
fn counted_active(vs: &crate::consensus::ValidatorSet) -> Vec<(Address, u128)> {
    vs.active_validators()
        .iter()
        .filter(|v| !vs.permissioned_validators || vs.is_allowed(&v.address))
        .map(|v| (v.address, v.stake))
        .collect()
}

/// Context of a governance transaction.
pub struct GovCtx {
    pub sender: Address,
    pub height: u64,
    pub timestamp: u64,
}

/// Validates and applies a governance transaction. On `Err` nothing has been written.
pub fn apply_op(csmt: &mut CSMT, op: &GovOp, ctx: &GovCtx) -> Result<Vec<EvmLog>, String> {
    let mut st = load_state(csmt)?.ok_or("governance: not active")?;
    let now = ctx.timestamp;
    let mut data = Vec::new();
    match op {
        GovOp::Propose { action, voting_period_secs } => {
            let vs = validator_set(csmt)?;
            let active = vs.active_validators();
            if !active.iter().any(|v| v.address == ctx.sender) {
                return Err("governance: only an active validator can propose".into());
            }
            if *voting_period_secs < st.timing.min_voting_secs || *voting_period_secs > st.timing.max_voting_secs {
                return Err(format!(
                    "governance: voting period must be {}..={} seconds",
                    st.timing.min_voting_secs, st.timing.max_voting_secs
                ));
            }
            validate_action(action)?;
            crate::open_staking::check_gov_action(csmt, action)
                .map_err(|code| format!("governance: refused by VIP-004 ({:?})", code))?;
            let mut mine = 0;
            for id in &st.open {
                if load_proposal(csmt, *id)?.map_or(false, |p| p.proposer == ctx.sender) {
                    mine += 1;
                }
            }
            if mine >= MAX_OPEN_PER_VALIDATOR {
                return Err(format!("governance: at most {} open proposals per validator", MAX_OPEN_PER_VALIDATOR));
            }
            let snapshot: Vec<(Address, u128)> = active.iter().map(|v| (v.address, v.stake)).collect();
            let total: u128 = snapshot.iter().map(|(_, s)| *s).sum();
            let p = Proposal {
                id: st.next_id,
                proposer: ctx.sender,
                action: action.clone(),
                created_ts: now,
                deadline_ts: now.saturating_add(*voting_period_secs),
                snapshot,
                threshold: (total * 2 + 2) / 3,
                votes: Vec::new(),
                yes_stake: 0,
                status: ProposalStatus::Open,
            };
            data.extend_from_slice(&p.id.to_le_bytes());
            st.open.push(p.id);
            st.next_id += 1;
            save_proposal(csmt, &p);
        }
        GovOp::Vote { id, yes } => {
            let mut p = load_proposal(csmt, *id)?.ok_or_else(|| format!("governance: no proposal {}", id))?;
            if p.status != ProposalStatus::Open {
                return Err(format!("governance: proposal {} is not open for voting", id));
            }
            if now > p.deadline_ts {
                return Err(format!("governance: voting on proposal {} has ended", id));
            }
            let stake = p.snapshot.iter().find(|(a, _)| *a == ctx.sender).map(|(_, s)| *s)
                .ok_or("governance: only validators in the proposal's snapshot can vote")?;
            if p.votes.iter().any(|(a, _)| *a == ctx.sender) {
                return Err("governance: already voted".into());
            }
            p.votes.push((ctx.sender, *yes));
            if *yes {
                p.yes_stake = p.yes_stake.saturating_add(stake);
                if p.yes_stake >= p.threshold {
                    p.status = ProposalStatus::Passed { at: now };
                }
            }
            data.extend_from_slice(&id.to_le_bytes());
            data.push(*yes as u8);
            save_proposal(csmt, &p);
        }
        GovOp::Cancel { id } => {
            let mut p = load_proposal(csmt, *id)?.ok_or_else(|| format!("governance: no proposal {}", id))?;
            if p.proposer != ctx.sender {
                return Err("governance: only the proposer can cancel".into());
            }
            if p.status != ProposalStatus::Open || !p.votes.is_empty() {
                return Err("governance: a proposal can only be cancelled while open and before any vote".into());
            }
            p.status = ProposalStatus::Cancelled { at: now };
            st.open.retain(|x| x != id);
            data.extend_from_slice(&id.to_le_bytes());
            save_proposal(csmt, &p);
        }
        GovOp::PauseRegistry { duration_secs } => {
            let gov = validator_set(csmt)?.governance_address;
            if gov != Some(ctx.sender) {
                return Err("governance: only the governance key can pause the registry".into());
            }
            if now >= st.emergency_until_ts {
                return Err("governance: the emergency pause power has expired".into());
            }
            if *duration_secs == 0 || *duration_secs > MAX_PAUSE_SECS {
                return Err(format!("governance: pause must be 1..={} seconds", MAX_PAUSE_SECS));
            }
            if now < st.paused_until_ts {
                return Err("governance: the registry is already paused".into());
            }
            if st.last_key_pause_ts != 0 && now < st.last_key_pause_ts.saturating_add(KEY_PAUSE_COOLDOWN_SECS) {
                return Err("governance: the key can pause at most once every 30 days; a longer stop needs a vote".into());
            }
            st.paused_until_ts = now + duration_secs;
            st.last_key_pause_ts = now;
            data.extend_from_slice(&st.paused_until_ts.to_le_bytes());
        }
        GovOp::Unpause => {
            let gov = validator_set(csmt)?.governance_address;
            if gov != Some(ctx.sender) {
                return Err("governance: only the governance key can unpause".into());
            }
            if now >= st.paused_until_ts {
                return Err("governance: the registry is not paused".into());
            }
            st.paused_until_ts = now;
        }
    }
    save_state(csmt, &st);
    Ok(vec![EvmLog { address: GOVERNANCE_SYSTEM_ADDRESS, topics: vec![op.topic(), ctx.sender], data }])
}

/// Applies a passed proposal's action. On `Err` nothing has been written to `csmt`
/// (changes to `st` are only kept by the caller on success).
fn execute_action(csmt: &mut CSMT, st: &mut GovState, a: &GovAction, height: u64, now: u64) -> Result<(), FailCode> {
    use crate::registry::{self, RegistryOp};
    // VIP-004 limits (no-op before VIP-004): a proposal that was valid when made can still
    // be refused here, with a fixed code.
    crate::open_staking::check_gov_action(csmt, a)?;
    let registry_op = match a {
        GovAction::SetGasPrice { min_gas_price_wei } => Some(RegistryOp::SetGasPrice { min_gas_price_wei: *min_gas_price_wei }),
        GovAction::SetFee { fee_per_item_wei } => Some(RegistryOp::SetFee { fee_per_item_wei: *fee_per_item_wei }),
        GovAction::SetRegistrar { address } => Some(RegistryOp::SetRegistrar { addr: *address }),
        _ => None,
    };
    if let Some(op) = registry_op {
        let params = registry::load_params(csmt).map_err(|_| FailCode::InvalidAction)?.ok_or(FailCode::RegistryInactive)?;
        let ctx = registry::ApplyCtx {
            sender: GOVERNANCE_SYSTEM_ADDRESS,
            governance: None,
            height,
            timestamp: now,
            by_vote: true,
            key_retired: true,
            registrations_paused: false,
        };
        return registry::apply(csmt, &op, &params, &ctx).map(|_| ()).map_err(|_| FailCode::RegistryRejected);
    }
    match a {
        GovAction::Unpause => {
            st.paused_until_ts = st.paused_until_ts.min(now);
            Ok(())
        }
        GovAction::EndEmergencyPower => {
            st.emergency_until_ts = st.emergency_until_ts.min(now);
            Ok(())
        }
        _ => {
            action_code(a)?;
            let mut vs = validator_set(csmt).map_err(|_| FailCode::InvalidAction)?;
            let mut w = rail_window(st, csmt, &vs, now);
            // No cut below half of the highest value in the window: several votes in a row
            // cannot walk a parameter down faster than one vote could.
            let halves = |peak: u64, new: u64| new.saturating_mul(2) < peak;
            let before = counted_active(&vs);
            match a {
                GovAction::SetUnbondingPeriodSecs { secs } => {
                    // A window opened before VIP-004 has no unbonding value yet: use the current one.
                    let current = crate::open_staking::load_state(csmt).ok().flatten().map_or(0, |o| o.timing.unbonding_secs);
                    w.unbonding_secs_peak = w.unbonding_secs_peak.max(current);
                    if halves(w.unbonding_secs_peak, *secs) {
                        return Err(FailCode::BelowFloor);
                    }
                    crate::open_staking::set_unbonding_secs(csmt, *secs)?;
                    w.unbonding_secs_peak = w.unbonding_secs_peak.max(*secs);
                    st.rail_window = Some(w);
                    return Ok(());
                }
                GovAction::Allow { address } => vs.allow(*address),
                GovAction::Disallow { address } => vs.disallow(address),
                GovAction::SetMinValidatorStake { wei } => vs.min_validator_stake = *wei,
                GovAction::SetMaxActiveValidators { count } => vs.max_active_validators = *count as usize,
                GovAction::SetUnbondingPeriodBlocks { blocks } => {
                    if halves(w.unbonding_blocks_peak, *blocks) {
                        return Err(FailCode::BelowFloor);
                    }
                    vs.unbonding_period_blocks = *blocks;
                    w.unbonding_blocks_peak = w.unbonding_blocks_peak.max(*blocks);
                }
                GovAction::SetMaxMissedBlocks { blocks } => {
                    if halves(w.max_missed_peak, *blocks) {
                        return Err(FailCode::BelowFloor);
                    }
                    vs.max_missed_blocks = *blocks;
                    w.max_missed_peak = w.max_missed_peak.max(*blocks);
                }
                _ => return Err(FailCode::InvalidAction),
            }
            let after: Vec<Address> = counted_active(&vs).into_iter().map(|(a, _)| a).collect();
            if after.is_empty() {
                return Err(FailCode::EmptyActiveSet);
            }
            let removed: u128 = before.iter().filter(|(a, _)| !after.contains(a)).map(|(_, s)| *s).sum();
            // Cumulative over the window, against the active stake when it started.
            if w.removed.saturating_add(removed).saturating_mul(3) > w.active_stake {
                return Err(FailCode::RemovesTooMuchStake);
            }
            w.removed += removed;
            st.rail_window = Some(w);
            csmt.insert(crate::account::VALIDATOR_SET_CSMT_KEY, vs.to_bytes());
            Ok(())
        }
    }
}

/// Runs at the start of every block (proposer and validator path, same point): activation,
/// then execution of passed proposals whose timelock is over and expiry of the others.
pub fn process_block(csmt: &mut CSMT, height: u64, now: u64, activation: Option<u64>, cfg: impl Into<GovConfig>) -> Result<(), String> {
    activate_if_due(csmt, height, now, activation, cfg);
    let Some(mut st) = load_state(csmt)? else { return Ok(()) };
    let before = serde_json::to_vec(&st).ok();
    let mut still_open = Vec::with_capacity(st.open.len());
    let ids = st.open.clone();
    for id in ids {
        let Some(mut p) = load_proposal(csmt, id)? else { continue };
        match p.status.clone() {
            ProposalStatus::Passed { at } if now >= at.saturating_add(st.timing.timelock_secs) => {
                // Execute on a copy so a failure leaves no partial write.
                let mut trial = csmt.clone();
                let mut trial_st = st.clone();
                match execute_action(&mut trial, &mut trial_st, &p.action, height, now) {
                    Ok(()) => {
                        *csmt = trial;
                        st.paused_until_ts = trial_st.paused_until_ts;
                        st.emergency_until_ts = trial_st.emergency_until_ts;
                        st.rail_window = trial_st.rail_window;
                        p.status = ProposalStatus::Executed { at: now };
                    }
                    Err(code) => p.status = ProposalStatus::Failed { at: now, code },
                }
                save_proposal(csmt, &p);
            }
            ProposalStatus::Open if now > p.deadline_ts => {
                p.status = ProposalStatus::Expired { at: now };
                save_proposal(csmt, &p);
            }
            ProposalStatus::Open | ProposalStatus::Passed { .. } => still_open.push(id),
            _ => {}
        }
    }
    st.open = still_open;
    if serde_json::to_vec(&st).ok() != before {
        save_state(csmt, &st);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn op_encoding_round_trips() {
        let ops = vec![
            GovOp::Propose { action: GovAction::SetFee { fee_per_item_wei: u128::MAX }, voting_period_secs: 7 },
            GovOp::Propose { action: GovAction::Allow { address: [3; 32] }, voting_period_secs: 9 },
            GovOp::Vote { id: 4, yes: false },
            GovOp::Cancel { id: 5 },
            GovOp::PauseRegistry { duration_secs: 60 },
            GovOp::Unpause,
        ];
        for op in ops {
            assert_eq!(GovOp::parse(&op.encode()).unwrap(), op);
        }
        assert!(GovOp::parse(b"VGOV1{bad").is_err());
        assert!(GovOp::parse(b"XXXXX{}").is_err());
    }
}

#[cfg(test)]
mod reserved_key_tests {
    #[test]
    fn state_key_is_the_domain_separated_hash() {
        assert_eq!(super::GOV_STATE_KEY, crate::chain_hash::hash256(b"VGOV1/state"));
    }
}
