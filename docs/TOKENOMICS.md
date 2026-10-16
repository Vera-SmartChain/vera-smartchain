# 📊 VERA SmartChain ($VERA) — Official Tokenomics

**Perpetual Recirculation Economic Model Backed by Real Utility**

---

## 1. Native Currency Specifications

| Parameter | Value |
| :--- | :--- |
| **Asset Name** | VERA SmartChain Native Coin |
| **Ticker** | **$VERA** |
| **Decimal Precision** | 18 decimals (1 VERA = 10¹⁸ wei) |
| **Total Hard Cap** | **100,000,000 VERA** (100 Million) — immutably configured at Genesis |
| **Economic Model** | Deflationary perpetual recirculation with partial fee burning |
| **Consensus Engine** | BFT Proof-of-Stake with 2/3 + 1 supermajority commitment |
| **Signature Scheme** | Ed25519 (256-bit Edwards Curve) |
| **State Hashing** | BLAKE3 (256-bit cryptographic tree hashing) |
| **Target Block Time** | 12 seconds |
| **Finality** | Immediate deterministic sub-second BFT finality (zero probabilistic forks) |

---

## 2. Genesis Allocation Breakdown

| Category | Share | Allocation | Release Schedule & Vesting |
| :--- | :---: | :---: | :--- |
| **Validator Reward Pool** | 35% | 35,000,000 VERA | Released algorithmically over 10 years as protocol block incentives. |
| **Ecosystem & Grants** | 25% | 25,000,000 VERA | Funding for developer tooling, multichain bridges, and security audits. |
| **Core Team & Contributors** | 20% | 20,000,000 VERA | 12-month cliff followed by linear monthly vesting over 36 months. |
| **Market Liquidity** | 10% | 10,000,000 VERA | Initial pairs on decentralized and centralized exchange order books. |
| **Community Onboarding** | 10% | 10,000,000 VERA | Testnet grants, early developer incentives, and ecosystem bootstrapping. |

---

## 3. Perpetual Recirculation Mechanism (70 / 15 / 15)

Every transaction fee and smart contract gas cost processed on the network is split deterministically:

1. **70% to Block Proposer & Validators:** Directly rewards active nodes securing the consensus.
2. **15% Protocol Burn:** Permanently subtracted from the circulating supply, applying organic deflationary pressure.
3. **15% Ecosystem Treasury:** Funds ongoing development, public infrastructure maintenance, and developer grants.

---

## 4. Staking & Slashing Parameters

- **Mainnet Minimum Validator Stake:** `10,000 VERA`
- **Testnet-1 Minimum Validator Stake:** `32 VERA` (to enable accessible testing)
- **Unbonding Period:**
  - Mainnet: 50,400 blocks (~7 days)
  - Testnet-1: 5 blocks (~60 seconds)
- **Liveness Slashing:** Missing 10 consecutive consensus rounds results in automatic jailing.
