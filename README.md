# 🌐 Vera SmartChain

The official open-source core repository for **Vera SmartChain**.

Vera SmartChain is an enterprise-grade Layer-1 blockchain engineered in Rust. Consensus and state verification use the industry-standard BLAKE3 hash function for high throughput and provable security. Key architectural components include:
- **Tendermint/PBFT-style Proof-of-Stake Consensus:** 12-second block intervals with deterministic BFT commit, dynamic validator staking, and unbonding.
- **Compact Sparse Merkle Tree (CSMT):** High-throughput authenticated key-value state commitment with cryptographic non-existence proofs.
- **Native EVM Execution:** Full Ethereum Virtual Machine compatibility powered by [`revm`](https://github.com/bluealloy/revm).
- **VERA Engine v2:** AI-Native execution engine featuring canonical SSA computation graphs, isomorphic normalizers, and high-speed ARX-64 hashing.

---

## 📦 Repository Structure

This repository is organized as a Rust workspace:

- [`blockchain/`](blockchain/): Core blockchain implementation:
  - `vera_node`: Full node binary with JSON-RPC (HTTP), P2P gossip engine, mempool, and block production.
  - `vera_cli`: Command-line interface for wallet key generation, balance inspection, transfers, and staking.
  - `consensus`: Dynamic validator set, 2/3+1 supermajority voting, liveness tracking, and slashing.
  - `csmt`: Compact Sparse Merkle Tree state storage and verification.
  - `state_transition`: Transaction routing (native transfers, EVM contracts, and governance).
  - `rpc`: Ethereum-compatible JSON-RPC 2.0 interface (`eth_*`, `net_*`, `web3_*`).
- [`vera-engine-v2/`](vera-engine-v2/): AI-Native execution engine:
  - `graph`: Static Single Assignment (SSA) computation graphs with verified invariants.
  - `canonical`: Isomorphic graph normalizer (constant folding, dead-code elimination, CSE).
  - `vera_hash`: Experimental ARX-64 research hash function with Oct-Tree parallel folding (not used in consensus; consensus uses BLAKE3).
  - `jit_x86`: Native x86-64 machine code generation with W^X memory protection.

---

## 🛠️ Building from Source

### Prerequisites

- **Rust toolchain:** Rust 1.78+ (`cargo`, `rustc`)
- **Architecture:** `x86_64` (Linux, macOS, Windows)

### Build All Workspace Binaries

```bash
cargo build --release
```

The compiled binaries will be available in `target/release/`:
- `vera_node` — Full blockchain node
- `vera_cli` — CLI wallet and management tool

---

## 🧪 Running Tests

Run the complete test suite across both workspace crates:

```bash
cargo test --workspace
```

Run crate-specific tests:

```bash
# Test blockchain consensus, EVM, and state transitions
cargo test -p vera-blockchain

# Test AI-native engine, isomorphism, and cryptographic hashing
cargo test -p vera-engine-v2
```

---

## 🌐 Testnet Connection

To connect to the public Vera SmartChain Testnet:

- **EVM Chain ID:** `83721` (`0x14709`)
- **Internal Chain ID:** `vera-testnet-1`
- **RPC Endpoint:** `https://testnet-rpc.verachain.cloud`
- **Block Explorer:** `https://testnet-explorer.verachain.cloud`
- **Faucet:** `https://testnet-faucet.verachain.cloud`

Pre-compiled verified binaries and automated installation scripts are distributed in the [`vera-node-releases`](https://github.com/Vera-SmartChain/vera-node-releases) repository.

---

## 📄 License & Attribution

This project is licensed under the **Apache License, Version 2.0**.  
See [LICENSE](LICENSE) and [NOTICE](NOTICE) for details.
