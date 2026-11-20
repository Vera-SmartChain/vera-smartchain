# VIP-001: Native Document Registry with a Fee Set by Governance (BRL Reference)

| Field | Value |
|---|---|
| Status | **Draft**: implemented and tested locally, not scheduled |
| Author | Claude-PC, for Carlos (governance key holder) |
| Base | `vera-smartchain` main `218bc03` (v0.2.9.1-testnet) |
| Type | Consensus-breaking (hard fork at a fixed activation height) |
| Date | 2026-11-17 |

## 1. Problem

Proof of existence is the main real-world use of VeraChain today. The first pilot (CBSA)
writes `CBSA1:REG:<type>:<code>:<sha256>` as calldata in a 0-value EVM transaction to
itself. Measured cost: about `0.0000215 VERA` per document (21,000 base gas plus calldata
gas, at the 1 gwei floor in `evm.rs`).

Three consequences:

1. **Validators earn nothing meaningful.** The 70/15/15 split works, but 70% of almost zero
   is still almost zero.
2. **The price has no relation to the value delivered.** For a registration to cost
   R$ 0.05 at the current gas, VERA would have to trade at about R$ 2,300.
3. **The fee cannot be raised per document.** Anyone can put 1,000,000 document hashes
   under one Merkle root and pay for one transaction.

The protocol cannot stop anyone from writing arbitrary bytes, and this proposal does not
try to. It makes the **recognized** way to register a document (the one the official
verifier, explorer and issuer registry honor) a native operation with a per-document fee.
That fee is set in VERA by governance to track a target price in fiat, and it goes to
validators through the existing split.

## 2. Summary of changes

1. A new system address `REGISTRY_SYSTEM_ADDRESS = 0x…1100`. EVM-signed transactions reach
   it as `0x0000…1100`, because the 32-byte address has 12 leading zero bytes.
2. Native operations sent to it: `REGISTER`, `REGISTER_BATCH`, `REVOKE`, plus governance-only
   `SET_FEE`, `SET_ISSUER` and `REMOVE_ISSUER`.
3. A per-item registry fee `fee_per_item_wei`, kept in state and changed only by governance
   within hard bounds (§5).
4. The registry fee is added to the gas fee and split **70 / 15 / 15** through the existing
   proposer credit and `FeeBatch`. No new money flows and no new addresses.
5. An on-chain **issuer registry**: governance attests that an address belongs to a named
   organization for a validity window. The protocol stores the attestation. Identity
   checks (KYC) happen off-chain.
6. Activation height per chain, set in `genesis.rs` the same way as `builtin_exec_v2_activation`.

7. A **consensus-enforced minimum gas price** `min_gas_price_wei`, kept in state and
   governed the same way. It sets the cost of **every** transaction (transfers, DEX swaps,
   contract calls, registry ops). Today there is none on the native path (`gas_price = 1 wei`
   is accepted) and only a hard-coded 1 gwei on the EVM path.

Two price targets, in fiat (Carlos's decision, 2026-11-17):

| What | Target | Charged as |
|---|---|---|
| Any transaction (simple transfer = 21,000 gas) | **R$ 0.005** | `gas_used × gas_price`, with `gas_price ≥ min_gas_price_wei` |
| Each registered document | **R$ 0.05** | `fee_per_item_wei × items`, on top of the gas |

A single document in its own transaction therefore costs about R$ 0.055. A batch of
10,000 documents costs about R$ 500 plus the gas of one transaction.

Out of scope: the validator reward pool (VIP-002), validator voting (VIP-003), oracles, and
an on-chain fee for issuer verification.

## 3. State

All new state lives in the CSMT under keys that no account can produce.

| Key | Value |
|---|---|
| `REGISTRY_PARAMS_KEY = hash256("VREG1/params")` | `FeeParams { min_gas_price_wei: u64, fee_per_item_wei: u128, last_gas_change_ts: u64, last_item_change_ts: u64, max_batch_leaves: u32 }` |
| `H("VREG1/issuer" ‖ address)` | `IssuerState { issuer_id: [u8;32], display_name: String (≤ 96 B), windows: Vec<(valid_from_ts, valid_until_ts)> (≤ 32) }` |
| `H("VREG1/doc" ‖ registrant ‖ doc_hash)` | `DocRecord { kind: u16, leaf_count: u32, parent: Option<[u8;32]>, height: u64, timestamp: u64, revoked_at: Option<u64> }` |

- `issuer_id` is a hash of the organization identifier, for example a CNPJ with a salt that
  governance keeps. No personal data ever goes on-chain. Only `display_name` is public.
- A document record is keyed by **registrant + hash**. Two issuers can register the same
  hash, and each record is independent.
- Serialization follows the existing CSMT values: a fixed-order binary encoding with
  `to_bytes` and `from_bytes`, plus round-trip tests.

## 4. Operations

`program` is a binary payload: the magic `VREG1` (5 bytes), then an opcode (1 byte), then
the fields. Any malformed payload rejects the whole transaction. Nothing is partially
applied (fail-hard).

| Op | Code | Fields | Items charged | Who may send |
|---|---|---|---|---|
| `REGISTER` | `0x01` | `kind u16, doc_hash [32], parent? [32]` | 1 | anyone |
| `REGISTER_BATCH` | `0x02` | `kind u16, merkle_root [32], leaf_count u32` | `leaf_count` | anyone |
| `REVOKE` | `0x03` | `doc_hash [32]` | 1 | the original registrant only |
| `SET_FEE` | `0x10` | `fee_per_item_wei u128` | 0 | governance (see §5) |
| `SET_GAS_PRICE` | `0x13` | `min_gas_price_wei u64` | 0 | governance (see §5) |
| `SET_ISSUER` | `0x11` | `address [32], issuer_id [32], valid_from u64, valid_until u64, name` | 0 | the registrar (see §6) |
| `REMOVE_ISSUER` | `0x12` | `address [32]` | 0 | the registrar |
| `SET_REGISTRAR` | `0x14` | `address [32]` | 0 | governance |

Rules:

- `REGISTER` and `REGISTER_BATCH` fail if a record with the same key already exists.
  Re-registering is not idempotent. It is an error, so nobody pays twice by accident.
- `REGISTER_BATCH` requires `1 ≤ leaf_count ≤ max_batch_leaves`. A leaf is verified as
  `H(leaf_index ‖ doc_hash)` with `leaf_index < leaf_count`. **The verifier rejects any leaf
  whose index is at or above the declared count**, so declaring fewer leaves than are
  really in the tree only leaves the extra documents unverifiable. That is what makes the
  per-item charge hold for batches.
- `REVOKE` sets `revoked_at` to the block timestamp. Records are never deleted.
- `tx.amount` must be 0 for every registry op. Any other value is rejected.
- Every successful op emits a receipt log (`topic0 = H("VREG1.<Op>")`) so indexers and the
  explorer do not have to read state.

## 5. Fee

```
registry_fee = fee_per_item_wei × items_charged
total_fee    = gas_used × gas_price + registry_fee
```

- **Solvency.** The admission and execution checks use
  `MaxDebit(tx) = amount + gas_limit × gas_price + registry_fee`, which matches the
  async-exec spec (D2). There is no `fee.min(balance)`. An insufficient balance rejects the
  transaction.
- **Split.** `registry_fee` is added to `total_fee` before the existing 70/15/15 code runs,
  so proposer, stability pool and burn shares need no new code paths. The v2 `FeeBatch`
  still applies.
- **Failed ops** (for example, revoking a hash you did not register) are rejected at
  execution. No registry fee is charged and the state does not change.
- **Minimum gas price.** From activation on, a transaction with
  `gas_price < min_gas_price_wei` is invalid, both in the mempool and in block validation,
  on the native and the EVM path. This replaces the hard-coded 1 gwei in `evm.rs` and
  `rpc.rs`. `eth_gasPrice` returns `min_gas_price_wei`, so wallets quote the right fee.
- **Set by governance with a BRL reference.** The fee is not pegged to any currency and
  VERA's price is not pegged either. Governance publishes reference targets off-chain
  (R$ 0.005 per simple transfer and R$ 0.05 per document) and converts them at the current
  VERA price:
  `min_gas_price_wei = (0.005 ÷ price_BRL) × 10¹⁸ ÷ 21,000` and
  `fee_per_item_wei = (0.05 ÷ price_BRL) × 10¹⁸`.
  Until VIP-003 is active, the governance key sends `SET_FEE` and `SET_GAS_PRICE`. After
  that, only an approved validator proposal can. Hard bounds apply on every path, so
  neither a stolen key nor a hasty vote can wreck users:
  - each new value must be between `current ÷ 2` and `current × 2`;
  - at least `604,800 s` (7 days, from block timestamps) must pass since the last change
    to the same parameter;
  - absolute ceilings `MAX_FEE_PER_ITEM_WEI` and `MAX_MIN_GAS_PRICE_WEI`, compile-time
    constants fixed per release.
  An on-chain price oracle can replace manual updates later. That would need its own VIP.
- **Before VERA has a market price.** The testnet uses a reference price that governance
  publishes, set in the activation code. The fee formulas stay the same.

## 6. Issuer registry

The protocol does not decide who an issuer is. It stores what the **registrar** attests.
The registrar is an address that governance appoints. Under VIP-003, validators appoint
and replace it by vote. Approving each issuer by a full validator vote would be too slow
for a commercial service. Until VIP-003 is active, the registrar is the governance key.

- **Verified.** A record counts as issued by organization X when one of the registrant's
  attestation windows covers the record's timestamp. Records made outside every window, or
  by addresses that were never attested, show as **unverified issuer** in the official
  verifier. They are still valid proofs of existence.
- **No retroactive attestation** (Carlos's decision, 2026-11-18). A window never starts
  before the block that records it: `valid_from` earlier than the block time is moved up
  to the block time. Records made before an address is attested never become verified.
- **History is kept.** An address keeps every window it ever had (at most 32). Renewing a
  current window only changes its end, and the end cannot move into the past. Attesting an
  address again after its window ended opens a new window from that block on, so records
  made in the gap stay unverified. An attested address cannot change organization
  (`issuer_id`); a new organization needs a new address.
- **Revoking an issuer.** `REMOVE_ISSUER` ends the current window at the block time (a
  window that has not started yet is dropped). Records made while it was valid stay
  verified.
- **Business model.** Off-chain identity checks and the yearly issuer fee are a service of
  the VeraChain operator, paid in fiat. The chain only carries the result.

## 7. Activation and compatibility

- `builtin_registry_activation(chain_id) -> Option<u64>`, with the same pattern and the
  same coordinated upgrade procedure as `exec_v2`. Local or private networks can set
  `registry_activation_height` in their genesis instead.
- The chain does not produce empty blocks, so the rules start at the **first block whose
  height is at or above** the activation height. That block writes the default `FeeParams`
  before its transactions run, and from then on their presence in state is what marks the
  rules as active (mempool and executor read the same state).
- **The activation block itself.** Mempool admission, mempool pruning, `eth_gasPrice` and
  `vera_registryParams` use the rules of the **next** block
  (`registry::effective_params(state, tip + 1, activation)`). Without that, wallets kept
  quoting the old 1 gwei until activation, every pending tx was invalid in the activation
  block, no block could be built and stale txs pinned their senders' nonces: the chain
  stalled at `activation − 1`. This was found on a local 2-node devnet and is covered by
  `activation_block_is_reachable_with_pending_old_price_txs`.
- **Before activation.** The mempool rejects transactions to `0x…1100` (local policy), so
  nobody sends funds to an address no one controls.
- **After activation.** Every transaction to `0x…1100` goes to the registry handler before
  the EVM branch, both native and EVM-signed. All other paths are byte-for-byte unchanged.
- **Direct transactions only.** The registry handles transactions whose `to` is
  `0x…1100`. A smart contract that calls `0x…1100` from inside the EVM reaches an address
  with no code: nothing is registered and no registry fee is charged. Contracts that need
  to register documents must have a wallet send the registry transaction.
- **Revocation is charged as one item**, like a registration, so revocations cannot be used
  to spam the state for free.
- **Existing calldata registrations** (the CBSA pilot format) stay on chain as they are. The
  official verifier treats records from before activation as legacy proofs of existence.
  The pilot moves to `REGISTER` after activation.

## 8. Clients and validators on the live testnet

Checked on 2026-11-18: v0.2.9.1-testnet at block #2269, 3 active validators, one of them run
by an outside operator.

- **Every validator must run the release before the activation height.** A node on
  v0.2.9.1 would accept the activation block's txs under the old rules and fork off.
- **Any client with a hard-coded gas price breaks at activation.** `vera_cli` sent every
  native tx at 1 wei. It now reads `eth_gasPrice` (and `signraw`, which is offline, takes an
  optional `gas_price_wei`). Other clients must be checked before the height is announced:
  the faucet and explorer backend, the exchange bots, and any external tool. The CBSA pilot
  panel already reads `eth_gasPrice` (checked). MetaMask and other EVM wallets read
  `eth_gasPrice` and need no change.
- `vera_cli registry …` sends every registry operation (`register`, `batch`, `revoke`,
  `set-fee`, `set-gas-price`, `set-registrar`, `set-issuer`, `remove-issuer`).

## 9. Required evidence before release

These follow the memory-bank rules: evidence comes from real stdout, mocks are not
accepted, and nothing is load-tested on the public testnet.

1. Unit tests: every op, every rejection path, fee bounds, timing of fee changes, batch
   limits, revoke by someone who is not the registrant, re-registration, an amount other
   than 0, and malformed payloads.
2. Fee accounting: proposer, stability pool, burn and sender balances add up exactly,
   with and without `FeeBatch`.
3. Determinism: the same blocks give the same state root on two independent nodes.
4. Activation boundary: identical behavior to v0.2.9.1 below the height and the new
   behavior from that height on.
5. **At least 2 local nodes running for more than 60 s under registry load**, with the
   state roots compared.
6. RPC: `vera_getRecord`, `vera_getIssuer` and `vera_registryParams`, tested end to end.

### Evidence collected (2026-11-18, local, Windows build)

- Unit and integration tests: `blockchain/tests/test_registry_vip001.rs`, 13/13 pass (including `attestation_is_never_retroactive`).
- Live devnet: 2 `vera_node` validators over P2P, activation at #8, real CLI traffic for
  87 s (37 single registrations, a 1,000-document batch, issuer attestation, revocations,
  a rejected out-of-bounds fee change). Result 23/23 checks:
  - the activation block is produced while the old price is pending;
  - block hash and state root are identical on both nodes for every height 0..48;
  - balances match on both nodes, and the account total is conserved to the wei;
  - the user paid exactly 0.05 VERA per item plus gas (1,038 items = 51.9 VERA);
  - the stability pool and burn each received exactly 15% of fees;
  - `vera_getRecord`, `vera_getIssuer`, `vera_registryParams` and `eth_gasPrice` were checked end to end.

## 10. Decisions

Decided by Carlos on 2026-11-17:

1. Targets: **R$ 0.005 per transaction** and **R$ 0.05 per document** (minimum, for now).
2. Validator rewards come from the pre-minted 35M pool (VIP-002). That is not inflation.
3. Fee changes and the registrar are decided by **validator vote** (VIP-003).
4. `max_batch_leaves = 10,000`. This only caps the size of one batch transaction. Every
   document in it is still charged.

Still open:

- The VERA/BRL reference price for the testnet (1 VERA = R$ 1 in the defaults).
- The ceilings `MAX_FEE_PER_ITEM_WEI` and `MAX_MIN_GAS_PRICE_WEI`.
