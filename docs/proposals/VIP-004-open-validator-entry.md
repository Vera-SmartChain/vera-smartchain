# VIP-004: Open Validator Entry by Stake (Mainnet)

| Field | Value |
|---|---|
| Status | **Implemented, not scheduled** (activation height not set on any public network) |
| Author | Claude-PC, for Carlos |
| Base | `vera-smartchain` main `218bc03` (v0.2.9.1-testnet) + VIP-001..003 |
| Type | Consensus-breaking (hard fork at a fixed activation height) |
| Scope | **Mainnet only.** The testnet keeps entry by approval and never gets an activation height. |
| Depends on | VIP-003 (its governance actions get the limits below) |
| Date | 2026-11-18 |

## 1. Problem

On mainnet, the governance key never approves validators (VIP-003 onboarding decision), so
until this VIP a new validator can only join by a vote of the validators already in place.
A set that admits newcomers only by its own vote can close itself.

Carlos's decision (2026-11-18): on mainnet, **anyone who bonds the minimum stake becomes a
validator**, with no approval from anyone, as on Ethereum and Cosmos.

Opening entry is only safe when misbehaviour costs real stake and the set cannot change
faster than the network can react. So this VIP ships open entry together with its
prerequisites, and it does not activate without them.

## 2. Where security comes from

Security does not come from approving validators. It comes from four things:

1. **Real stake.** Every validator has at least `min_validator_stake` (10,000 VERA on mainnet)
   bonded. That stake can be taken.
2. **Slashing with proof.** Signing two different blocks or votes for the same height,
   round and step (equivocation) is the only way a validator can help break consensus
   safety. It is provable from the two signatures alone, and it costs stake (§4).
3. **An entry limit.** New stake enters gradually (§3.2), so nobody can buy a large share of
   the set at once.
4. **BFT.** Tendermint finalizes a block only with the signatures of more than 2/3 of the
   active stake. A group holding less than 1/3 cannot finalize a conflicting block or stop
   the chain, whatever it does.

## 3. Open entry

### 3.1 Rules (from activation on)

- A `stake` transaction from any account is accepted when the key's total (bonded + queued
  + new) is at least `min_validator_stake`. There is no allowlist: `allow:` and `disallow:`
  are refused for every sender, including the governance key, and the activation block
  clears the allowlist and switches `permissioned_validators` off.
- The active set is the `max_active_validators` largest stakes (unchanged rule:
  `ValidatorSet::active_validators`). A larger stake displaces the smallest one, which keeps
  its stake and comes back when there is room.
- A validator leaves the active set only by its own unstake, by being displaced by a larger
  stake, by jail (missed blocks, existing rule), or by slashing with proof (§4).
- Only validators in the active set can miss a block. A bonded validator outside it
  (displaced, or still entering below the minimum) cannot sign, so its missed-block counter
  stays at zero. Before VIP-004 every non-jailed validator counted, which with open entry
  would jail and cut 1% from validators that had no way to sign.

### 3.2 Entry churn limit

New stake does not enter at once. It waits in a first-in, first-out queue, and at the start
of every block the queue admits at most:

> **`active stake ÷ 20` (5%) per rolling 24 hours, counted by block timestamp.**

- The 24 hours are tracked as 25 buckets of one hour, so that **any** 24-hour interval admits
  at most the limit (not just calendar days).
- The head of the queue can enter partly; the rest waits for the next window. A key counts as
  active once its admitted stake reaches the minimum.
- Top-ups of existing validators go through the same queue.
- The divisor is fixed in code. No vote can change it.

**Why 5%.** Assume an attacker is the only newcomer, has unlimited money, and nobody leaves.
Each day the active stake grows by at most 5%, so the attacker's share after `d` days is at
most `1 − 1.05^−d`:

| Churn per day | Days to 1/3 (can halt) | Days to 2/3 (can finalize alone) | Honest set doubles in |
|---|---|---|---|
| 10% | 5 | 12 | 7.3 days |
| **5% (proposed)** | **9** | **23** | **14.2 days** |

With 5%, gaining control of 2/3 takes longer than the 21-day unbonding period (§5), so every
key that took part in such a takeover is still slashable while it happens. Growth stays
fast enough for a new network: the honest set can double in about two weeks. At launch, with
a small set, a new validator may wait a few days (for example, 4 × 10,000 VERA admits 2,000
VERA per day).

Jailing yourself and coming back later does not beat the limit: stake is counted when it is
admitted, so stake held back and released at once grows only linearly (`0.05 × d`), which is
slower than the compounding case above. Unjail therefore needs no extra limit.

## 4. Equivocation slashing

### 4.1 Evidence

Anyone can send an evidence transaction to `0x…1400` (amount 0, payload `VEVD1` + JSON):

- `DuplicateVote { a, b }`: two signed votes (prevote or precommit) by the same key for the
  same chain, height, round and vote type, with different block hashes (nil included).
- `DuplicateProposal { a, b }`: two signed Tendermint proposals by the same key for the same
  chain, height and round, with different block hashes.

The evidence is valid only when both signatures verify (strict Ed25519), both messages name
this chain (a key reused on the testnet is not slashed on mainnet), the height is not in
the future and not before VIP-004's activation (no retroactive slashing), the key is not
already tombstoned, and the key has stake at risk.

Every node also watches the consensus messages it receives and submits evidence by itself,
signed with its own key, the first time it sees a key sign two different messages for one
round and step. An honest node never produces such a pair: it records each signature in its
write-ahead log before sending it and refuses to sign a second, different message.

### 4.2 Penalty

When valid evidence is applied:

1. **Forced exit.** The key's bonded and queued stake leaves the set and starts unbonding
   (§5), still slashable.
2. **Tombstone.** The key is banned forever: it can never stake or unjail again.
3. **Slash.** The stake at risk is the bonded and queued stake plus unbonding stake that
   left at or after the offense height. The key loses:
   - **5%** of it, as on Cosmos, when it acts alone or with a small group;
   - **100%** of it once the stake slashed within one unbonding period reaches **1/3 of the
     active stake**, measured when the first of them was slashed. That is the amount needed to
     break safety, so an attack that could work costs everything. Earlier offenders in the same
     window are topped up to 100% from what they still have unbonding.
4. **Burn.** Slashed VERA goes to the burn address. Nobody receives it, so nobody gains from
   reporting or from a slash.

Evidence that would leave no active validator at all is refused (a one-validator network
whose operator ran the key on two nodes would otherwise stop for good).

A single operator error (for example, two nodes running with one key) costs 5% and the key.
A coordinated attack by 1/3 of the stake costs all of it.

### 4.3 Validator keys and operation

- **Reserved state keys are hashes.** The records of VIP-001..004 live under
  domain-separated hashes (`hash256("VGOV1/state")`, `"VOPEN1/state"`, `"VREG1/params"`,
  `"VREW1/state"`), not under fixed low addresses. A transfer to a fixed address could create
  an `Account` there before the record existed, and every later block would fail to load it.
  The hashes are public, so hashing alone is not enough: execution and mempool admission also
  refuse any transaction whose `to` is one of these four keys (`is_reserved_state_key`).
  Tests send payments to the new keys (refused, no account created, every `load_state` still
  returns "no record", `process_block` still succeeds) and to the old addresses (ordinary
  accounts now).

- Stake, unstake and unjail need a native ed25519 transaction with a strong key, on every
  network and before and after activation. An EVM-wrapped transaction carries
  `public_key = 0`, a weak (small-order) point. Without this rule, stake from several wallets
  would pool on that one key, any wallet could unstake all of it to the first staker, and
  votes for that key could be forged. Weak keys are refused when staking.
- Consensus votes are verified with strict Ed25519, as proposals and evidence already were.
  Honest signatures always pass.
- Operators must never run one key on two nodes, and never restore a key on a new disk
  without its `tm_wal/` folder (`docs/RUNNING_A_VALIDATOR.md`, "Key Safety").

## 5. Unbonding by time

- Unstaked stake (and the stake of a slashed key) is released **21 days** after the unstake,
  by block timestamp, not by block count. Counted in blocks, the period froze whenever the
  chain was idle (blocks are produced only when there are transactions), so the rule had no
  meaning in time.
- While unbonding, the stake still answers for equivocation at heights up to the block of the
  unstake.
- Unstake takes queued stake first, then bonded stake. What remains must be zero or at least
  the minimum stake.
- Block timestamps cannot run ahead: a proposal more than 15 s ahead of a validator's clock
  is refused, and timestamps never go backwards.
- Entries created before activation keep their release height.

**Why 21 days.** Same as Cosmos. It is long enough for evidence to reach the chain and for
the correlation window (§4.2), and short enough not to lock capital for months. Governance
may set it between **14 and 60 days** (`SetUnbondingPeriodSecs`, bounds fixed in code), and
never below half of its highest value in a 7-day window. Stake already unbonding keeps its release time.

## 6. Anti-cartel: votes cannot close the door

From activation on, the VIP-003 governance actions are limited as follows. A forbidden
proposal is refused when it is made. A proposal made before activation that would now be
forbidden fails at execution with a fixed code, and nothing changes.

| Action | Rule after VIP-004 | Code at execution |
|---|---|---|
| `SetMaxActiveValidators` | may only go up (or stay) | `ClosesEntry` |
| `SetMinValidatorStake` | may only go down (or stay); raising it needs a new release signed by Carlos | `ClosesEntry` |
| `Disallow` | does not exist: a validator leaves only by jail or slashing with proof | `ClosesEntry` |
| `Allow` | meaningless (no allowlist) | `InvalidAction` |
| `SetUnbondingPeriodBlocks` | replaced by `SetUnbondingPeriodSecs` | `InvalidAction` |
| `SetMaxMissedBlocks` | at least **100** (the mainnet genesis value), so a cartel cannot jail slower newcomers | `BelowFloor` |
| `SetUnbondingPeriodSecs` | 14 to 60 days, never below half of its highest value in a 7-day window | `BelowFloor` |

The VIP-003 rails still apply and are cumulative over a rolling 7-day window: the set is
never empty, at most 1/3 of the active stake at the start of the window leaves by vote, and
no parameter goes below half of its highest value in the window. With the rules above, what
is left for those rails on mainnet are `max_missed_blocks` and the unbonding period. The entry churn divisor, slash rates and floors are constants in code: only a
new signed release can change them.

## 7. Activation

- `genesis::builtin_open_entry_activation(chain_id)` returns the height per network. It is
  `None` for every network today. The testnet stays `None` permanently.
- At the first block at or above the height: the allowlist is switched off and cleared,
  `max_missed_blocks` is raised to at least 100, and the VIP-004 state (`hash256("VOPEN1/state")`) is written
  with the unbonding period, the churn window and `hash256(chain_id)` for evidence.
- On `vera-mainnet` the production timing is always used. A devnet genesis may shorten the
  unbonding and churn windows (`open_entry_timing`) for tests.
- Block order: liveness → unbonding maturation → **VIP-004 (activation, queue admission)** →
  VIP-001 → VIP-002 → VIP-003 → transactions.

## 8. Interfaces

- Stake, unstake and unjail: unchanged transactions to the staking address.
- Evidence: transaction to `0x…1400`, payload `VEVD1` + JSON `Evidence`, max 4 KiB. CLI:
  `vera_cli evidence submit <file.json>`.
- RPC `vera_openEntryInfo`: activation, timing, minimum stake, active-set size, churn limit
  and use, the queue, tombstoned keys and the offenders in the current window.
- Log `VEVD1.Slashed` (topics: event, key; data: stake at risk, burned).

## 9. Known limits

- The queue is first in, first out. Someone with a lot of stake can fill it and make others
  wait. That locks their capital without rewards while it waits (only active stake is paid),
  and it is the same trade-off Ethereum makes.
- Exits are not rate-limited: honest validators leaving at once raises everyone else's share.
  Unbonding still keeps leaving stake slashable for 21 days.
- Stake added after an offense is also at risk (the stake at risk is measured when the
  evidence is applied).
- Equivocation is the only slashable fault. Downtime keeps the existing rule (1% and jail
  after `max_missed_blocks` consecutive misses).
- Reporting is not rewarded: a node reports what it sees and pays only the transaction fee.

## 10. Evidence before release

- Unit and integration tests: `blockchain/tests/test_open_entry_vip004.rs`.
- Two local nodes for more than 60 seconds with identical block hashes and state roots,
  covering open stake, churn, unbonding by time and a slash.
- Full crate regression.

### Evidence collected (2026-11-18)

- `test_open_entry_vip004`: **22/22**. Round 2 adds the window-peak test for unbonding;
  round 3 adds the liveness rule (only active validators can miss) and the empty-set rule
  for evidence. Covers activation, open entry, displacement, churn
  per rolling day in queue order, the per-key queue bound, time-based release, unstaking
  queued stake first, the 5% slash with tombstone and forced exit, duplicate-proposal
  evidence, 9 kinds of invalid evidence, stake at risk while unbonding, 100% correlation at
  1/3 with the window reset, the node-side tracker, governance refused at propose time,
  governance that still passes, the fixed failure codes at execution, unchanged bytes
  before activation, and two `FullNode`s end to end.
- Whole crate: **170 passed, 0 failed** (151 before VIP-004 + 19).
- Devnet: two nodes over 112 s, **25/25** checks (`devnet/open-run1.txt`):
  - 150 VERA staked by an account nobody approved: 100 admitted (limit 2,000 ÷ 20), the rest
    after the 48 s devnet window;
  - unstaking 20 VERA released exactly 20 VERA after the 30 s devnet period;
  - `Disallow`, lowering the active-set size and raising the minimum stake were refused with
    `ClosesEntry`;
  - a duplicate prevote cost 6.5 of 130 VERA (5%), burned, and the key was tombstoned;
    staking again and a second evidence were refused;
  - block hash and state root were identical at heights 0..18.

## Known limit: a minimum gas price raise applies in the same block

VIP-003 proposals run at the start of a block, before its transactions. If a passed
`SetGasPrice` raises the minimum, transactions admitted under the old price fail in that block
and are dropped from it (blocks are still produced, possibly empty). It is a short
liveness effect, not a halt, and the vote needs 2/3 plus a timelock, so it is deliberate.
Applying the new minimum from the next block is a possible later refinement.
