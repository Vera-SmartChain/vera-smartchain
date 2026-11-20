# VIP-003: On-Chain Governance by Validator Vote

| Field | Value |
|---|---|
| Status | **Implemented, not scheduled** (activation height not set on any public network) |
| Author | Claude-PC, for Carlos |
| Base | `vera-smartchain` main `218bc03` (v0.2.9.1-testnet) |
| Type | Consensus-breaking (hard fork at a fixed activation height) |
| Depends on | VIP-001 (the fee parameters it governs) |
| Date | 2026-11-17 (spec), 2026-11-18 (implementation) |

## 1. Problem

Today one address, `ValidatorSet.governance_address`, controls the validator allowlist and
can hand governance to another address. VIP-001 adds fee parameters and an issuer registrar.
If that same single key kept control of prices, outside issuers would have to trust one
person with their costs.

Carlos's decision (2026-11-17): **validators decide by vote.**

## 2. What is governed by vote

| Action | Effect |
|---|---|
| `SET_GAS_PRICE(v)` | `min_gas_price_wei` (VIP-001) |
| `SET_FEE(v)` | `fee_per_item_wei` (VIP-001) |
| `SET_REGISTRAR(addr)` | the address that attests issuers (VIP-001 §6) |
| `ALLOW(addr)` / `DISALLOW(addr)` | validator allowlist (today: governance key) |
| `SET_PARAM(name, v)` | `min_validator_stake`, `max_active_validators` (1–200), `unbonding_period_blocks` (5–10,000,000), `max_missed_blocks` (10–1,000,000) |
| `UNPAUSE` | ends a registry pause now |
| `END_EMERGENCY_POWER` | ends the governance key's pause power now (it cannot come back) |

VIP-001's hard bounds (at most 2× per change, at least 7 days between changes, ceilings fixed
in code) **still apply after a vote passes**. A proposal that breaks them fails when it is
executed.

**Safety rails on validator actions.** The executor checks the state *after* the action
and refuses it (status `Failed` with a code, nothing changes) when:

- the active validator set would be empty. The chain could not produce the block needed
  to vote the change back;
- the votes executed within a rolling 7-day window would deactivate, together, more than
  1/3 of the active stake at the start of that window (a raised minimum stake, a lower
  `max_active_validators`, or a `Disallow` on a permissioned set). On a permissioned set, a
  validator already disallowed (but still bonded) does not count, before or after;
- `max_missed_blocks` or `unbonding_period_blocks` would go below the floor fixed in code
  (10 and 5 blocks), or below half of its highest value in the same 7-day window.

The rails are cumulative over the window, not per proposal: several proposals that execute
in the same block, or in blocks in a row, cannot add up to 1/3 + 1/3 of the stake, or walk a
parameter down 100 → 50 → 25 → 12 in one round.

**Failure codes, not text.** A failed proposal stores a fixed code in state:
`RegistryInactive`, `RegistryRejected`, `InvalidAction`, `EmptyActiveSet`,
`RemovesTooMuchStake`, `BelowFloor` or (VIP-004) `ClosesEntry`. Error text is never written
to state, because a later release could change the wording and change the state root of old
blocks. Malformed values (zero address, zero amount, a count outside 1..=200) are
`InvalidAction`; only a staking parameter outside its floor or ceiling is `BelowFloor`.
Variants are never renamed or reordered; new ones are only appended.

A vote cannot change anything that needs new code: the emission table, the 70/15/15 split,
the supply or the bounds themselves. Those need a new release and an upgrade by the
validators, which is a vote in practice too.

## 3. Mechanics

New native operations sent to `GOVERNANCE_SYSTEM_ADDRESS = 0x…1300`, with `amount = 0`:

| Op | Who | Fields |
|---|---|---|
| `PROPOSE` | any active validator | `action`, `voting_period_secs` (from 3 to 14 days) |
| `VOTE` | any validator in the snapshot | `proposal_id`, `yes \| no` |
| `CANCEL` | the proposer, before any vote | `proposal_id` |
| `PAUSE_REGISTRY` | the governance key (§4) | `duration_secs` (at most 72 h) |
| `UNPAUSE` | the governance key, to end its own pause early | — |

The payload is `VGOV1` followed by a JSON encoding of the op (at most 1 KiB). Ops are
accepted only from the activation height on. State lives in the CSMT: `GovState` at
`hash256("VGOV1/state")`, one record per proposal at `hash256("VGOV1/proposal" ‖ id)`.

- **Snapshot.** The active validators and their stake are recorded when the proposal is
  created. Stake added later does not count, so nobody can buy a vote halfway through.
- **Passing.** Yes votes must reach the **supermajority threshold of the snapshot stake**,
  `ceil(2 × total ÷ 3)`. That is the same threshold that finalizes blocks
  (`ValidatorSet::supermajority_threshold`). The proposal passes as soon as it reaches that
  threshold, but it only executes after a **48 h timelock** (block timestamps) so users can
  react.
- **Failing.** If the deadline passes without reaching 2/3, the proposal fails. Abstaining
  counts against it.
- **Execution.** The first block whose timestamp is at or after `passed_at + 48h` applies
  the action before its transactions. The action is applied in full or not at all. If it
  fails (for example because a VIP-001 bound is broken), it is recorded as failed and nothing
  changes.
- **Spam.** There are at most 3 open proposals per validator, and the normal gas is charged
  (VIP-001).

## 4. Transition from the governance key

1. From VIP-003 activation, `allow`, `disallow` and the VIP-001 setters sent by the governance
   key are **rejected**. Only executed proposals can make those changes.
2. The governance key keeps one emergency power: `PAUSE_REGISTRY` stops new VIP-001
   registrations for at most 72 h. It cannot move funds, change prices or touch existing
   records. Transfers, revocations and everything else keep working.
   - **Not renewable by the key.** The key can start at most one pause every 30 days.
     A longer stop needs a vote. A vote can also end a pause early (`UNPAUSE`).
   - **It expires on its own** 365 days (by block timestamps) after VIP-003 activation, or
     earlier by a validator vote (`END_EMERGENCY_POWER`). On mainnet VIP-003 is meant to be
     active from genesis, so that is 12 months after the mainnet genesis. A timestamp is
     used instead of a fixed height because block times vary (no empty blocks).
     A "temporary" power with no end date tends to become permanent.
   - **Key custody.** The governance key is kept offline by Carlos, like the release
     signing key, and never on a server.
3. `set_governance` (handing over the key) keeps working, for key rotation.
4. The registrar role (VIP-001 §6) is unchanged: whoever is the registrar keeps attesting
   issuers. Only *who* the registrar is changes by vote. If no registrar was ever appointed,
   the governance key still acts as registrar until a vote appoints one.

**Validator onboarding (Carlos's decision, 2026-11-18).**

- **Testnet: approval by the governance key.** Testnet VERA is free from the faucet and does
  not carry over to mainnet, so stake is no barrier there. On the testnet the key **keeps**
  `allow:`/`disallow:` (`vera_cli approve-validator`) after VIP-003 activation. All other
  VIP-003 rules apply normally.
- **Mainnet: the key never has `allow:`.** Entry is by vote until VIP-004 (open entry with
  the minimum stake, slashing and an entry rate limit) is active.
- The rule is per chain id and fails closed: only `vera-testnet-1` (`genesis::is_test_chain`)
  keeps the key's allowlist and accepts the shorter test windows from a genesis file. Any
  other id, including a misspelled mainnet id, gets the mainnet rules. It is written into
  state at the activation block (`GovState.key_allowlist`, shown by `vera_govInfo`).

**Counted in blocks.** `unbonding_period_blocks` and `max_missed_blocks` count blocks, and
the chain only produces blocks when there are transactions. On an idle network, unbonding
and the missed-block count do not advance. This is consistent with "no activity, no reward"
(VIP-002). VIP-004 moves unbonding to time (block timestamps) before mainnet entry is open.

**Note.** On the public testnet today (block #2269, 2026-11-18) there are 3 active
validators with 32 VERA each: total 96, threshold 64. Two are run by the core team and one
by an outside operator, so the core team alone reaches the threshold. A vote only becomes
more than a core-team decision once outside stake passes one third of the total. The
public text says so plainly.

## 5. Interfaces

- RPC `vera_govInfo`: active flag, activation height, timing, `paused_until_ts`,
  `last_key_pause_ts`, `emergency_until_ts` and the proposals still open or waiting for
  their timelock.
- RPC `vera_getProposal(id)`: one proposal with snapshot, threshold, votes and status
  (`Open`, `Passed`, `Executed`, `Failed` with the reason, `Expired`, `Cancelled`).
- `vera_cli gov [--key-file f] propose '<action json>' <secs> | vote <id> yes|no |
  cancel <id> | pause <secs> | unpause`.
- Each op emits a log from `0x…1300` with topic `hash256("VGOV1.<Op>")` and the sender.

## 6. Required evidence before release

1. Unit tests: snapshot isolation, the exact 2/3 boundary (just above and exactly at 2/3),
   the timelock, expiry, cancel, the per-validator limit, a proposal that breaks a bound
   failing at execution, and the governance key being rejected after activation.
2. Determinism across two nodes, including a proposal that passes and executes while both
   nodes run.
3. At least 2 local nodes running for more than 60 s with a full proposal cycle (the voting
   period and timelock are shortened only in the test genesis).

### Evidence collected (2026-11-18)

- `tests/test_governance_vip003.rs`: 14 tests, all passing. They cover every case in item 1,
  `UNPAUSE`/`END_EMERGENCY_POWER` by vote, the pause rules, the static bounds, and a
  two-node `FullNode` test where a proposal passes and executes and both state roots
  match.
- Local devnet (2 validators, 32 VERA each, devnet timing 10 s–600 s vote and 20 s
  timelock): 24/24 checks over 97 s. They cover:
  - refusal before activation;
  - the key rejected for SET_FEE and `allow:`;
  - a proposal at 1/2 of the stake staying open, then passing at 2/2;
  - a non-validator's vote and a double vote refused;
  - pause → registration refused → unpause → registration accepted;
  - the fee unchanged before the timelock and doubled on both nodes after it;
  - expiry and cancellation;
  - identical block hash and state root at every height (0..15) on both nodes.
- The mainnet chain id always uses the production timing, so a genesis file cannot
  shorten it. A node with a different timing writes a different state at the activation
  block and diverges at once.
- Regression: lib, VIP-001 and VIP-002 tests unchanged and passing.
- After Claude-VPS's review (2026-11-18), round 2:
  - fixed failure codes;
  - the safety rails;
  - the testnet/mainnet allowlist rule.

  Evidence:
  - `test_governance_vip003`: 20/20. New tests: empty set, more than 1/3 removed (minimum
    stake, max active, disallow), floors and the "at most half" rule, the code stored
    instead of text, the allowlist rule per chain.
  - Devnet 25/25 over 90 s:
    - the key's `allow:` works on testnet;
    - a vote to raise the minimum stake above every validator fails with
      `EmptyActiveSet`, and the chain keeps producing blocks;
    - hash and state root are identical at heights 0..20.

## 7. Open decisions

1. The timelock (48 h) and the voting window (3–14 days).
2. Decided on 2026-11-18: `PAUSE_REGISTRY` stays, limited as in §4 (72 h, registry only,
   expires about 12 months after the mainnet genesis, key kept offline).
3. Decided on 2026-11-18: the testnet keeps approval by the key, mainnet entry opens with
   VIP-004 (see §4).
