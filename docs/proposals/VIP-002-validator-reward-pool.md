# VIP-002: Validator Reward Pool Emission

| Field | Value |
|---|---|
| Status | **Draft**: implemented and tested locally, not scheduled |
| Author | Claude-PC, for Carlos |
| Base | `vera-smartchain` main `218bc03` (v0.2.9.1-testnet) |
| Type | Consensus-breaking (hard fork at a fixed activation height) |
| Depends on | none. **Planned to be active from the mainnet genesis only** (decided 2026-11-18); the testnet does not need it |
| Date | 2026-11-17 |

## 1. Problem

`TOKENOMICS.md` sets aside **35,000,000 VERA (35%)** as a validator reward pool "released
over 10 years". In the same file, §3 says "There is no block reward or inflation". The code
pays no reward at all: `rpc.rs` reports `reward: 0x0`, and validators earn only 70% of fees.

At today's fee volume a validator earns almost nothing, so nobody outside the team has a
reason to run one. VIP-001 creates real fee income, but that income only grows with usage.
This VIP pays validators from the pool **in the meantime**.

**This is not inflation.** The pool is part of the fixed 100M supply. Emission only moves
pre-allocated coins from the pool address to validators, and the total supply never goes
above 100M.

## 2. Pool address

`REWARD_POOL_ADDRESS = 0x…7a1d`. This is the address the mainnet genesis already uses for the
validator reward allocation (`GenesisConfig::mainnet`). It is a system address with no
private key, and only the state transition can debit it. The emission state
(`start_ts`, `last_ts`, `total_paid`) lives under the CSMT key `hash256("VREW1/state")`, a hash that
no account can occupy.

- **Mainnet.** Genesis allocates 35,000,000 VERA to it (already in the code).
- **Testnet.** Governance funds it with a plain transfer (test amount). Emission stops on its
  own when the pool is empty.

## 3. Emission schedule

The schedule is **time-based**, not block-based. VeraChain blocks only come when there is
work (the testnet sat idle at #734), so a fixed reward per block would pay for nothing on
quiet days and too much on busy ones.

The emission rate falls **15% each year**. Year 1 is the yearly budget `B₁ = 35M × 0.15 ÷ (1 − 0.85¹⁰)`.
Year 10 pays whatever is left, so the total is exactly 35,000,000 VERA.

| Year | Emitted (VERA) | Cumulative | Per second |
|---|---|---|---|
| 1 | 6,536,960 | 6,536,960 | 0.2071 |
| 2 | 5,556,416 | 12,093,376 | 0.1761 |
| 3 | 4,722,954 | 16,816,330 | 0.1497 |
| 4 | 4,014,511 | 20,830,841 | 0.1272 |
| 5 | 3,412,334 | 24,243,175 | 0.1081 |
| 6 | 2,900,484 | 27,143,659 | 0.0919 |
| 7 | 2,465,411 | 29,609,070 | 0.0781 |
| 8 | 2,095,600 | 31,704,670 | 0.0664 |
| 9 | 1,781,260 | 33,485,929 | 0.0564 |
| 10 | 1,514,071 (remainder) | 35,000,000 | 0.0480 |

The values come from the formula above. The code (`blockchain/src/rewards.rs`) keeps the
yearly budgets in integer wei (computed with exact rational arithmetic; year 10 is the
remainder, so the budgets add up to exactly 35,000,000 VERA) and a per-second rate per year
(`budget ÷ 31,536,000`, truncated). After year 10 the rate is 0. A test checks that the
rates match the budgets and that each budget is 15% below the previous one.

## 4. Per-block reward

For a block at height `h` with timestamp `tₕ`:

```
elapsed   = min(tₕ − tₕ₋₁, MAX_REWARD_GAP_SECS)                  // MAX_REWARD_GAP_SECS = 60
scheduled = min(rate(year(tₕ)) × elapsed, pool_balance)
cap       = stake(signers) × 10% × elapsed ÷ SECONDS_PER_YEAR      // stake cap
reward(h) = min(scheduled, cap)
```

- **Stake cap** (decided 2026-11-18). The schedule is only a ceiling for the whole network.
  A validator never earns more than **10% of its own stake per year**
  (`MAX_REWARD_BPS_PER_YEAR = 1,000`), however few validators there are. The cap uses the
  stake of the validators being paid, so an offline validator does not raise the others'
  cap. Whatever is not paid stays in the pool. It is not burned or carried over.
- Without the cap, the fixed schedule would pay about 2.2M VERA per validator in year 1
  with 3 validators, against a 32 VERA stake.

- `year(t)` counts from `emission_start_ts`, the timestamp of the activation block.
- **The cap stops timestamp games.** A proposer cannot claim hours of emission by setting a
  large timestamp. Blocks already must not be in the future (`MAX_FUTURE_BLOCK_TIME_SECS`)
  or go backwards. Time beyond the cap while the chain is idle is **not paid**, and those
  coins stay in the pool.
- **Unpaid coins.** When the chain is idle, the pool lasts longer than 10 years. What to do
  with that remainder is a VIP-003 governance decision. Nothing happens to it automatically.

### No activity, no reward

The chain only produces a block when there are transactions, and each block pays for at
most 60 seconds. **When the network is idle, validators earn nothing.** This is
deliberate, on testnet and on mainnet (Carlos's decision, 2026-11-18): rewards follow real
use of the network, so validators grow when the network grows.

- **No empty blocks to earn rewards.** No periodic empty block, heartbeat or other
  mechanism will be added to pay validators while the chain is idle.
- Time beyond the 60-second cap is never paid, and those coins stay in the pool.

## 5. Who receives it

The reward goes to the validators who **actually signed** the previous block, meaning the
`last_commit` the block carries. It is split pro rata by stake:

```
share(v) = reward(h) × stake(v) ÷ Σ stake(signers of last_commit)
```

- A validator that is offline, or jailed, gets nothing. Liveness pays.
- Integer division leaves a remainder of at most a few wei. That goes to the proposer, so
  every wei is accounted for.
- The credit happens once per block, **before the block's transactions**, right after the
  liveness audit and unbonding maturation, on both the proposer and the validator path.
  The validator set used is the one at that point. Each block does at most 50 account
  writes (the maximum active validator set).
- Eligible signers are the active validators (not jailed, minimum stake, within the active
  cap) whose public key appears in `last_commit`. A duplicated commit counts once, and an
  unknown key is ignored. Commit signatures of active validators are already verified by
  the quorum check of the previous block, so a proposer cannot add a signer that did not
  sign.
- **Known limit.** A proposer can leave honest precommits out of `last_commit`, as long as
  the quorum remains. The left-out validators then miss that block's reward (and are
  already counted as missed by the existing liveness audit). Today's proposer includes
  every precommit it received. Rotating proposers limit the effect.
- The first block at or above the activation height only starts the clock and pays
  nothing. A block whose timestamp is not after the previous one pays nothing.
- Shares use 256-bit intermediate arithmetic, so large stakes cannot overflow.
- Fees keep their 70/15/15 split. **The reward is separate and is not split.** All of it
  goes to the signers.

## 6. Economics and mainnet parameters (decided 2026-11-18)

- **Stake cap** of 10% of stake per year, as in §4. With it, the payout scales with the
  value at stake instead of with the number of validators. With 50 validators at the
  minimum stake, the network pays at most 50,000 VERA per year, far below the schedule.
  The pool then lasts much longer than 10 years.
- **Minimum stake on mainnet: 10,000 VERA** (`MAINNET_MIN_VALIDATOR_STAKE_VERA`). The
  testnet keeps 32 VERA. `max_active_validators` stays at 50.
- **Unreleased allocations cannot stake.** The team, treasury, liquidity and community
  allocations sit at system addresses with no private key (`0x…c07e`, `0x…ec05`,
  `0x…119d`, `0x…c033`), so they cannot sign a `stake` transaction, and nothing in them
  can earn a reward. There is no vesting mechanism yet. A future vesting VIP must release
  coins only to ordinary accounts, at the release time, and keep this property.
- **Public wording.** Public material describes the reward as payment for running a
  validator. It does not present a yield or a rate of return. The 10% is a technical
  limit, not a promise.

### Mainnet genesis: found while reviewing (not part of this VIP)

1. `GenesisConfig::mainnet` sets `governance_address` to `0x…ec05`, an address with no
   key. On mainnet nobody could send governance transactions. It needs the real
   governance key (kept offline).
2. `build_genesis_state` credits each initial validator's stake both to the validator's
   balance and to the staking account `0x…1000`, on top of the 100M in `initial_accounts`.
   On mainnet the total would exceed 100M by `2 × stake × validators`. The testnet genesis
   already works this way and cannot change. The mainnet genesis must take the initial
   stake from an allocation so the total is exactly 100M, with a test that sums every
   account after `build_genesis_state`.
3. Slashing for equivocation (signing two blocks at the same height), with on-chain
   evidence, is missing. Today only liveness is slashed (1%). It needs its own VIP before
   mainnet.

## 7. RPC

`vera_rewardInfo` returns `active`, `activation_height`, the pool address and balance and,
once active, `emission_start_ts`, `last_ts`, `year`, `rate_wei_per_sec`,
`max_reward_gap_secs` and `total_paid_wei`.

## 8. Required evidence before release

1. Unit tests: rate per year, the remainder in year 10, the elapsed cap, an empty pool,
   pro-rata rounding, and the remainder going to the proposer.
2. Conservation: before and after any sequence of blocks, `pool + Σ validators + burn + stability + others`
   is unchanged. Emission moves coins and never creates them.
3. Determinism across two nodes. The activation boundary behaves the same as v0.2.9.1
   before the height.
4. At least 2 local nodes running for more than 60 s, with reward balances checked by hand
   against the formula.

### Evidence collected (2026-11-18, local, Windows build)

- Unit tests in `rewards.rs` (5, including the stake cap) and integration tests in
  `blockchain/tests/test_rewards_vip002.rs` (11/11). They cover:
  - before activation and without activation;
  - the clock starting at activation;
  - the pro-rata split, the remainder and conservation;
  - the 60 s cap;
  - a pool that limits the reward and an empty pool;
  - jailed and unknown signers;
  - no signers;
  - timestamps going backwards;
  - the year boundary and the end of the schedule;
  - the stake cap binding with small stake, where an offline validator does not raise
    the cap of the others;
  - two full nodes agreeing.
- Live devnet: 2 `vera_node` validators via P2P, pool funded with 1,000 VERA in the devnet
  genesis, VIP-001 at #3 and VIP-002 at #5, 80 s of real traffic. Result 10/10:
  - each validator's balance change equals 70% of the fees of the blocks it proposed plus
    its reward shares, recomputed by hand from every block's timestamp, proposer and
    `last_commit`, to the wei;
  - the pool decreased by exactly that amount. Two 32-VERA validators received
    15,017,757,483,504 wei over 25 blocks (74 s), which is 10% per year of 64 VERA: the
    stake cap binds, not the schedule. A first run without the cap paid 15.34 VERA (the
    schedule, 0.207 VERA/s);
  - block hash and state root are identical on both nodes for every height;
  - `vera_rewardInfo` matches on both nodes;
  - the account total is conserved to the wei.

## 9. Open decisions

1. Decided on 2026-11-18:
   - keep the 10-year, 15% decay schedule as a ceiling;
   - add the stake cap of 10% per year;
   - set the mainnet minimum stake to 10,000 VERA;
   - activate at the mainnet genesis only.
2. The mainnet genesis fixes listed in §6.
3. Fix `TOKENOMICS.md` §3 ("no block reward or inflation") in the same release. The draft
   is in `docs/TOKENOMICS.md`.
