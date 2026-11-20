# 📊 VERA SmartChain ($VERA) — Tokenomics

**How the network is paid for, who earns, and who decides.**

> [!NOTE]
> Items marked **Proposed** are specified in `docs/proposals/` (VIP-001 to VIP-003) and are
> **not live yet**. Everything else describes the public testnet as it runs today.

---

## 1. Native Currency Specifications

| Parameter | Value |
| :--- | :--- |
| **Asset Name** | VERA SmartChain Native Coin |
| **Ticker** | **$VERA** |
| **Decimal Precision** | 18 decimals (1 VERA = 10¹⁸ wei) |
| **Total Hard Cap** | **100,000,000 VERA** (100 Million). Planned for mainnet, may change. No coin is ever created beyond it. |
| **Fee Split** | 70 / 15 / 15 (implemented on the testnet) |
| **Consensus Engine** | Tendermint BFT Proof-of-Stake, committed by validators holding more than 2/3 of the stake |
| **Signature Scheme** | Ed25519 (256-bit Edwards Curve) |
| **State Hashing** | BLAKE3 (256-bit cryptographic tree hashing) |
| **Finality** | Immediate deterministic BFT finality (no probabilistic forks; measured median finality 554 ms) |

---

## 2. How the Network Earns

Users of an application built on VeraChain pay that application in whatever currency it
accepts. The application, not its users, holds VERA and pays the network fees.

```
User ──pays the app (any currency)──▶ Application operator
                                         │ holds VERA, pays network fees
                                         ▼
                          Transaction on VeraChain
                                         ▼
          70% block proposer │ 15% stability pool │ 15% burned
```

Any application on the network pays the same fees, whoever built it. Validators are paid
by every application that uses the chain.

### 2.1 Two kinds of fee — **Proposed (VIP-001)**

| Fee | Applies to | Target price | Charged as |
| :--- | :--- | :---: | :--- |
| **Transaction fee** | every transaction (transfer, swap, contract, registration) | **R$ 0.005** for a simple transfer | `gas used × gas price`, with a minimum gas price set by governance |
| **Document registration fee** | each document registered in the native registry | **R$ 0.05 per document** | per document, including each document inside a batch |

- **Why per document.** One transaction can carry one document or a batch of up to 10,000.
  A batch of 10,000 documents pays 10,000 × R$ 0.05 = R$ 500 plus one transaction fee. The
  official verifier only recognizes documents inside the count that was paid for.
- **Set by governance with a BRL reference.** Businesses need to know their costs in
  advance. Fees are charged in VERA. Governance sets them using a reference price in
  Brazilian reais and updates them when VERA's price moves. Each change is at most 2× up
  or down, at least 7 days apart, and under a ceiling fixed in the code. Neither the fee
  nor VERA is pegged to any currency.
- Both fees go through the same 70 / 15 / 15 split.

### 2.2 Verified issuers — **Proposed (VIP-001)**

Anyone can register a document. A record shows the issuing organization by name only when
the issuer's address has been verified by the registrar. The registrar is an address that
validators appoint by vote. Identity checks happen off-chain. Only the verification result
goes on-chain. Personal data never does.

---

## 3. Fee Split (70 / 15 / 15) — Live on the Testnet

Every transaction fee is split deterministically:

1. **70% to the block proposer:** pays the validator that produced the block.
2. **15% to the stability pool:** a reserve (`0x0000000000000000000000000000000000000000000000000000000000005afe`), which also receives slashed stake.
3. **15% burned:** sent to `0x000000000000000000000000000000000000000000000000000000000000dead`, which no one controls. Supply goes down as usage goes up.

---

## 4. Validator Rewards — **Proposed (VIP-002)**

The testnet pays validators no reward today, only their 70% share of fees. VIP-002 releases
the **35,000,000 VERA reward pool**, which already exists inside the 100M cap. This
**is not inflation**: coins move from the pool to validators, and none are created.

- The pool is released **over time, not per block**. The rate falls 15% each year over 10
  years: about 6.54M VERA in year 1, about 1.51M in year 10, and exactly 35M in total.
- Each block pays the time since the previous block, capped at 60 seconds. The payment goes
  to the validators who **signed** the previous block, in proportion to their stake.
  Validators that are offline or jailed earn nothing.
- The schedule is a ceiling. Each validator's payment is also limited in proportion to the
  stake it puts at risk, so a small number of validators cannot collect the whole schedule.
  Whatever is not paid stays in the pool.
- **No activity, no reward.** Blocks are only produced when there are transactions, so an
  idle network pays nothing. Rewards follow real use of the network, and no empty blocks
  are produced to earn them.
- The reward is payment for operating a validator. It is not a yield or an investment
  return.
- Planned for mainnet only. The testnet does not pay rewards.

---

## 5. Governance — **Proposed (VIP-003)**

Validators decide by on-chain vote, weighted by stake:

- **What they vote on:** the transaction fee, the document fee, the issuer registrar, the
  validator allowlist and the staking parameters.
- **Rules:** a proposal needs at least **2/3 of the stake** (the same threshold that
  finalizes blocks). Stake is counted when the proposal is created, and an approved change
  waits **48 hours** before taking effect.
- **What a vote cannot change:** the supply cap, the 70/15/15 split, the reward schedule
  and the fee limits. Those need a new software release, which validators have to adopt.
- Today most of the validator stake is run by the core team (2 of the 3 testnet
  validators), so a validator vote is in practice that team's decision. This changes once
  outside validators hold more than one third of the stake.

---

## 6. Genesis Allocation Breakdown *(Planned for Mainnet, May Change)*

> [!NOTE]
> The breakdown below is planned for mainnet and may change before launch. The public
> testnet runs with a minimal test allocation.

| Category | Share | Allocation | Release Schedule & Vesting |
| :--- | :---: | :---: | :--- |
| **Validator Reward Pool** | 35% | 35,000,000 VERA | Released over 10 years by the schedule in §4 (Proposed, VIP-002). |
| **Ecosystem & Grants** | 25% | 25,000,000 VERA | Developer tooling, multichain bridges and security audits. |
| **Core Team & Contributors** | 20% | 20,000,000 VERA | 12-month cliff, then linear monthly vesting over 36 months. |
| **Market Liquidity** | 10% | 10,000,000 VERA | Initial pairs on decentralized and centralized exchange order books. |
| **Community Onboarding** | 10% | 10,000,000 VERA | Testnet grants, early developer incentives and ecosystem bootstrapping. |

---

## 7. Staking & Slashing Parameters

- **Mainnet Minimum Validator Stake:** `10,000 VERA` (planned for mainnet, may change)
- **Testnet-1 Minimum Validator Stake:** `32 VERA` (up to 50 validators via the allowlist)
- **Unbonding Period:**
  - Mainnet: to be defined before mainnet
  - Testnet-1: 5 blocks
- **Liveness Slashing:** missing 10 blocks means jailing and a 1% slash. The slashed stake
  goes to the stability pool.
