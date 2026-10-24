# 📊 VERA SmartChain ($VERA) — Official Tokenomics

**Economic Model Backed by Real Utility**

---

## 1. Native Currency Specifications

| Parameter | Value |
| :--- | :--- |
| **Asset Name** | VERA SmartChain Native Coin |
| **Ticker** | **$VERA** |
| **Decimal Precision** | 18 decimals (1 VERA = 10¹⁸ wei) |
| **Total Hard Cap** | **100,000,000 VERA** (100 Million) — *planned for mainnet, may change* |
| **Economic Model** | Fee split 70/15/15 (implemented on the testnet) |
| **Consensus Engine** | Tendermint BFT Proof-of-Stake with 2/3 + 1 supermajority commitment |
| **Signature Scheme** | Ed25519 (256-bit Edwards Curve) |
| **State Hashing** | BLAKE3 (256-bit cryptographic tree hashing) |
| **Finality** | Immediate deterministic BFT finality (zero probabilistic forks; measured median finality 554 ms) |

---

## 2. Genesis Allocation Breakdown *(Planned for Mainnet, May Change)*

> [!NOTE]
> The allocation breakdown below is planned for mainnet and may change prior to mainnet launch. The current public testnet operates with a minimal test allocation.

| Category | Share | Allocation | Release Schedule & Vesting |
| :--- | :---: | :---: | :--- |
| **Validator Reward Pool** | 35% | 35,000,000 VERA | Released algorithmically over 10 years as protocol block incentives. |
| **Ecosystem & Grants** | 25% | 25,000,000 VERA | Funding for developer tooling, multichain bridges, and security audits. |
| **Core Team & Contributors** | 20% | 20,000,000 VERA | 12-month cliff followed by linear monthly vesting over 36 months. |
| **Market Liquidity** | 10% | 10,000,000 VERA | Initial pairs on decentralized and centralized exchange order books. |
| **Community Onboarding** | 10% | 10,000,000 VERA | Testnet grants, early developer incentives, and ecosystem bootstrapping. |

---

## 3. Fee Split Mechanism (70 / 15 / 15)

Every transaction fee and smart contract gas cost processed on the network is split deterministically:

1. **70% to Block Proposer:** Directly rewards the active proposer node securing the consensus.
2. **15% Stability Pool:** Sent to the stability reserve (`0x00000000000000000000000000000000000057ab`).
3. **15% Protocol Burn:** Sent to the burn address `0x000000000000000000000000000000000000dead`, which no one controls. There is no block reward or inflation.

---

## 4. Staking & Slashing Parameters

- **Mainnet Minimum Validator Stake:** `10,000 VERA` (planned for mainnet, may change)
- **Testnet-1 Minimum Validator Stake:** `32 VERA` (up to 50 validators via governance allowlist)
- **Unbonding Period:**
  - Mainnet: to be defined before mainnet
  - Testnet-1: 5 blocks
- **Liveness Slashing:** Missing 10 blocks results in jailing and a 1% slash (slashed stake is transferred to the stability pool).
