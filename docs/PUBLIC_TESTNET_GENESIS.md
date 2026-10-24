# 🌐 VERA SmartChain — Public Testnet Genesis Documentation

This document describes the parameters and cryptographic state of the **VERA SmartChain Public Testnet-1**.

---

## 📋 Network Parameters

| Parameter | Configuration |
| :--- | :--- |
| **Network Name** | VERA SmartChain Testnet-1 |
| **P2P Chain ID** | `vera-testnet-1` |
| **EVM Chain ID** | `83721` (`0x14709`) |
| **Genesis Timestamp**| `1790520233` (Sun Sep 27 2026 14:43:53 UTC) |
| **Consensus Engine** | BFT Proof-of-Stake |
| **State Hashing** | BLAKE3 (Compact Sparse Merkle Tree) |
| **Minimum Stake** | `32 VERA` (`32000000000000000000` wei) |
| **Unbonding Window** | `5` blocks |
| **Max Missed Blocks**| `10` blocks before jailing |
| **Permissioned Mode** | `true` (Testnet sybil protection via on-chain governance allowlist) |
| **Governance Account**| `0xd12949512c92d3e70be1789b3f086044c4483205a20f29b34b066396c00f0ea5` |

---

## 👥 Genesis Validators

```json
[
  {
    "address": "0x19824ac38727c94e97a4d51651ebe350b3571b4d9a46dc09bd2b53068a3e34cb",
    "public_key": "8d2b423c2b284f1a1ed40730c4e7b6d317042965eb77e24d245bafe279f50a75",
    "stake": "32000000000000000000"
  },
  {
    "address": "0x9393907ce109384586bc753c04bfd3d9bba7d37bac7db0b1aec7f45f40607840",
    "public_key": "b0e860166167e5e8b09d4d310f3f8a2b7f04518498ca7c177e259dabbf1f8a21",
    "stake": "32000000000000000000"
  }
]
```

---

## 💰 Initial Funded Accounts

- **Testnet Faucet Pool:** `0x596bb3da434843b7bd1657cd828194a6639ea1521ce6b07d507fe0cb991e2df3` (1,000 VERA)
- **Validator #1 Operating Balance:** `0x19824ac38727c94e97a4d51651ebe350b3571b4d9a46dc09bd2b53068a3e34cb` (50 VERA)
- **Validator #2 Operating Balance:** `0x9393907ce109384586bc753c04bfd3d9bba7d37bac7db0b1aec7f45f40607840` (50 VERA)
- **Testnet Governance Multi-Sig:** `0xd12949512c92d3e70be1789b3f086044c4483205a20f29b34b066396c00f0ea5` (10 VERA)

---

## 📡 Public RPC & P2P Seeds

- **HTTP JSON-RPC:** `https://testnet-rpc.verachain.cloud` (or `http://2.25.216.206:8545`)
- **Block Explorer:** `https://testnet-explorer.verachain.cloud`
- **P2P Seed Nodes:**
  - `2.25.216.206:26656` (Node 1)
  - `31.97.93.163:26656` (Node 2)
