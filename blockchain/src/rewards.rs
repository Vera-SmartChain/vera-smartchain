//! VIP-002: validator rewards paid from the pre-minted reward pool.
//!
//! The pool is an ordinary account at `REWARD_POOL_ADDRESS` (the mainnet genesis already
//! allocates 35,000,000 VERA to it). It has no private key: only this module debits it.
//! Emission moves pre-allocated coins to validators and never mints, so the total supply
//! never changes.
//!
//! Emission is time-based: each block pays for `elapsed`, the time since the previous
//! block, capped at `MAX_REWARD_GAP_SECS` so a proposer cannot claim idle hours. The
//! amount is the smaller of two limits:
//!
//! - the schedule: `rate(year) × elapsed` (a ceiling on the whole network), and
//! - the stake cap: `MAX_REWARD_BPS_PER_YEAR` of the stake of the validators being paid,
//!   pro rata for `elapsed`. A validator can never earn more than that fraction of its own
//!   stake per year, however few validators there are.
//!
//! Whatever is not paid stays in the pool. The reward goes to the validators that signed
//! the previous block (the block's `last_commit`), pro rata by stake; the integer
//! remainder goes to the proposer.

use crate::account::{Account, Address};
use crate::block::ValidatorCommit;
use crate::csmt::CSMT;
use revm::primitives::U256;

/// Reward pool account (mainnet genesis: 35,000,000 VERA).
pub const REWARD_POOL_ADDRESS: Address = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x7a, 0x1d,
];

/// CSMT key of this record: `hash256(b"VREW1/state")`. It is a hash, not an address, so no account
/// can ever sit on it (a transfer to a fixed low address could create an `Account` there and
/// break `load_state` for every later block). The test below pins the value.
pub const REWARD_STATE_KEY: Address = [
    0x34, 0x73, 0x20, 0x6f, 0x64, 0x57, 0xcc, 0xae,
    0x5b, 0x03, 0xc6, 0x1a, 0x5c, 0xa7, 0x7e, 0xa5,
    0xec, 0xc0, 0x3b, 0x21, 0x6b, 0xc5, 0x06, 0xbf,
    0x14, 0x34, 0x4d, 0x99, 0xdc, 0xac, 0x57, 0x5a,
];

pub const SECONDS_PER_YEAR: u64 = 31_536_000;
pub const MAX_REWARD_GAP_SECS: u64 = 60;
/// Stake cap: at most 10% (1,000 basis points) of the paid validators' stake per year.
pub const MAX_REWARD_BPS_PER_YEAR: u128 = 1_000;

/// Emission rate in wei per second for years 1..10 (index 0..9), 0 afterwards.
///
/// Yearly budgets: `B1 = 35M × 0.15 ÷ (1 − 0.85^10)`, each year 15% below the previous
/// one, year 10 = 35M − Σ(years 1..9); rate = budget ÷ 31,536,000 (truncated). Generated
/// with exact rational arithmetic; see VIP-002 §3 and the `rate_table_matches_budgets` test.
pub const RATE_WEI_PER_SEC: [u128; 10] = [
    207_285_645_999_247_912,
    176_192_799_099_360_725,
    149_763_879_234_456_616,
    127_299_297_349_288_124,
    108_204_402_746_894_905,
    91_973_742_334_860_669,
    78_177_680_984_631_569,
    66_451_028_836_936_833,
    56_483_374_511_396_308,
    48_010_868_334_686_862,
];

/// Yearly budgets in wei, the source of `RATE_WEI_PER_SEC` (they sum to exactly 35M VERA).
pub const YEARLY_BUDGET_WEI: [u128; 10] = [
    6_536_960_132_232_282_159_831_118,
    5_556_416_112_397_439_835_856_450,
    4_722_953_695_537_823_860_477_983,
    4_014_510_641_207_150_281_406_285,
    3_412_334_045_026_077_739_195_342,
    2_900_483_938_272_166_078_316_041,
    2_465_411_347_531_341_166_568_635,
    2_095_599_645_401_639_991_583_339,
    1_781_259_698_591_393_992_845_838,
    1_514_070_743_802_684_893_918_969,
];

const STATE_VERSION: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RewardState {
    /// Timestamp of the activation block (start of year 1).
    pub start_ts: u64,
    /// Timestamp of the last block processed.
    pub last_ts: u64,
    /// Total paid out of the pool since activation (for RPC and audits).
    pub total_paid: u128,
}

impl RewardState {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(1 + 8 + 8 + 16);
        v.push(STATE_VERSION);
        v.extend_from_slice(&self.start_ts.to_le_bytes());
        v.extend_from_slice(&self.last_ts.to_le_bytes());
        v.extend_from_slice(&self.total_paid.to_le_bytes());
        v
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self, String> {
        if b.len() != 33 || b[0] != STATE_VERSION {
            return Err("rewards: malformed reward state".to_string());
        }
        Ok(Self {
            start_ts: u64::from_le_bytes(b[1..9].try_into().unwrap()),
            last_ts: u64::from_le_bytes(b[9..17].try_into().unwrap()),
            total_paid: u128::from_le_bytes(b[17..33].try_into().unwrap()),
        })
    }
}

pub fn load_state(csmt: &CSMT) -> Result<Option<RewardState>, String> {
    match csmt.get(&REWARD_STATE_KEY) {
        Some(b) => RewardState::from_bytes(b).map(Some),
        None => Ok(None),
    }
}

/// Emission rate (wei/s) at timestamp `ts` for a schedule started at `start_ts`.
pub fn rate_at(start_ts: u64, ts: u64) -> u128 {
    let year = (ts.saturating_sub(start_ts) / SECONDS_PER_YEAR) as usize;
    RATE_WEI_PER_SEC.get(year).copied().unwrap_or(0)
}

fn balance(csmt: &CSMT, a: &Address) -> Result<u128, String> {
    Ok(match csmt.get(a) {
        Some(b) => Account::from_bytes(b)?.balance,
        None => 0,
    })
}

fn credit(csmt: &mut CSMT, a: &Address, amount: u128) -> Result<(), String> {
    if amount == 0 {
        return Ok(());
    }
    let mut acc = match csmt.get(a) {
        Some(b) => Account::from_bytes(b)?,
        None => Account::new(0),
    };
    acc.balance = acc.balance.checked_add(amount).ok_or("rewards: balance overflow")?;
    csmt.insert(*a, acc.to_bytes());
    Ok(())
}

/// `a × b ÷ c` without overflow (c > 0, result ≤ a when b ≤ c).
fn mul_div(a: u128, b: u128, c: u128) -> u128 {
    let r = U256::from(a) * U256::from(b) / U256::from(c);
    r.try_into().unwrap_or(u128::MAX)
}

/// Most the validators holding `stake` may earn for `elapsed` seconds:
/// `stake × MAX_REWARD_BPS_PER_YEAR ÷ 10,000 × elapsed ÷ SECONDS_PER_YEAR`.
pub fn stake_cap(stake: u128, elapsed: u64) -> u128 {
    let r = U256::from(stake) * U256::from(MAX_REWARD_BPS_PER_YEAR) * U256::from(elapsed)
        / (U256::from(10_000u64) * U256::from(SECONDS_PER_YEAR));
    r.try_into().unwrap_or(u128::MAX)
}

/// What one block paid (for tests and logs).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BlockReward {
    pub total: u128,
    pub shares: Vec<(Address, u128)>,
    pub remainder_to_proposer: u128,
}

/// Applies VIP-002 for a block. Runs at the start of the block, after the liveness audit
/// and unbonding maturation and before any transaction, on both the proposer and the
/// validator path. Before `activation` it does nothing. The first block at or above the
/// activation height only starts the clock.
pub fn apply_block_reward(
    csmt: &mut CSMT,
    height: u64,
    timestamp: u64,
    proposer: Address,
    last_commit: &[ValidatorCommit],
    activation: Option<u64>,
) -> Result<BlockReward, String> {
    let Some(a) = activation else { return Ok(BlockReward::default()) };
    if height < a {
        return Ok(BlockReward::default());
    }
    let mut state = match load_state(csmt)? {
        Some(s) => s,
        None => {
            let s = RewardState { start_ts: timestamp, last_ts: timestamp, total_paid: 0 };
            csmt.insert(REWARD_STATE_KEY, s.to_bytes());
            return Ok(BlockReward::default());
        }
    };

    let elapsed = timestamp.saturating_sub(state.last_ts).min(MAX_REWARD_GAP_SECS);
    let pool = balance(csmt, &REWARD_POOL_ADDRESS)?;
    let scheduled = rate_at(state.start_ts, timestamp).saturating_mul(elapsed as u128).min(pool);
    state.last_ts = state.last_ts.max(timestamp);

    // Eligible: active (not jailed, enough stake, within the active cap) validators that
    // signed the previous block. Duplicated commits count once.
    let mut paid = BlockReward::default();
    if scheduled > 0 {
        if let Some(vs_bytes) = csmt.get(&crate::account::VALIDATOR_SET_CSMT_KEY) {
            let vs = crate::consensus::ValidatorSet::from_bytes(vs_bytes)?;
            let signers: std::collections::HashSet<[u8; 32]> =
                last_commit.iter().map(|c| c.validator_pubkey).collect();
            let eligible: Vec<(Address, u128)> = vs
                .active_validators()
                .into_iter()
                .filter(|v| signers.contains(&v.public_key))
                .map(|v| (v.address, v.stake))
                .collect();
            let total_stake: u128 = eligible.iter().map(|(_, s)| *s).sum();
            let due = scheduled.min(stake_cap(total_stake, elapsed));
            if total_stake > 0 && due > 0 {
                let mut distributed = 0u128;
                for (addr, stake) in eligible {
                    let share = mul_div(due, stake, total_stake);
                    credit(csmt, &addr, share)?;
                    distributed += share;
                    paid.shares.push((addr, share));
                }
                paid.remainder_to_proposer = due - distributed;
                credit(csmt, &proposer, paid.remainder_to_proposer)?;
                paid.total = due;
            }
        }
    }

    if paid.total > 0 {
        let mut pool_acc = match csmt.get(&REWARD_POOL_ADDRESS) {
            Some(b) => Account::from_bytes(b)?,
            None => Account::new(0),
        };
        pool_acc.balance = pool_acc.balance.checked_sub(paid.total).ok_or("rewards: pool underflow")?;
        csmt.insert(REWARD_POOL_ADDRESS, pool_acc.to_bytes());
        state.total_paid = state.total_paid.saturating_add(paid.total);
    }
    csmt.insert(REWARD_STATE_KEY, state.to_bytes());
    Ok(paid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_table_matches_budgets() {
        let total: u128 = YEARLY_BUDGET_WEI.iter().sum();
        assert_eq!(total, 35_000_000u128 * 1_000_000_000_000_000_000);
        for (b, r) in YEARLY_BUDGET_WEI.iter().zip(RATE_WEI_PER_SEC.iter()) {
            assert_eq!(*r, b / SECONDS_PER_YEAR as u128);
        }
        for w in YEARLY_BUDGET_WEI[..9].windows(2) {
            // 15% decay per year (exact up to the truncation of each budget).
            let expected = w[0] * 85 / 100;
            assert!(w[1].abs_diff(expected) <= 1, "{} vs {}", w[1], expected);
        }
    }

    #[test]
    fn rate_by_year_and_after_schedule() {
        assert_eq!(rate_at(1000, 1000), RATE_WEI_PER_SEC[0]);
        assert_eq!(rate_at(1000, 1000 + SECONDS_PER_YEAR - 1), RATE_WEI_PER_SEC[0]);
        assert_eq!(rate_at(1000, 1000 + SECONDS_PER_YEAR), RATE_WEI_PER_SEC[1]);
        assert_eq!(rate_at(1000, 1000 + 9 * SECONDS_PER_YEAR), RATE_WEI_PER_SEC[9]);
        assert_eq!(rate_at(1000, 1000 + 10 * SECONDS_PER_YEAR), 0);
    }

    #[test]
    fn state_round_trips() {
        let s = RewardState { start_ts: 7, last_ts: 9, total_paid: u128::MAX - 3 };
        assert_eq!(RewardState::from_bytes(&s.to_bytes()).unwrap(), s);
        assert!(RewardState::from_bytes(&[1, 2, 3]).is_err());
    }

    #[test]
    fn stake_cap_is_ten_percent_a_year() {
        let stake = 10_000u128 * 1_000_000_000_000_000_000;
        assert_eq!(stake_cap(stake, SECONDS_PER_YEAR), stake / 10);
        assert_eq!(stake_cap(stake, 60), stake / 10 * 60 / SECONDS_PER_YEAR as u128);
        assert_eq!(stake_cap(0, 60), 0);
    }

    #[test]
    fn mul_div_does_not_overflow() {
        let reward = 60 * RATE_WEI_PER_SEC[0];
        let stake = 100_000_000u128 * 1_000_000_000_000_000_000;
        assert_eq!(mul_div(reward, stake, stake), reward);
        assert!(mul_div(reward, stake / 3, stake).abs_diff(reward / 3) <= 1);
    }
}

#[cfg(test)]
mod reserved_key_tests {
    #[test]
    fn state_key_is_the_domain_separated_hash() {
        assert_eq!(super::REWARD_STATE_KEY, crate::chain_hash::hash256(b"VREW1/state"));
    }
}
