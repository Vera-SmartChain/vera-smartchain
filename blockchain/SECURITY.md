# Security Invariants of VERA SmartChain ($VERA)

This document establishes the **Systemic Hardening Framework** of VERA SmartChain. Every invariant listed here represents a mathematical or cryptographic law governing the protocol, mapped directly to an automated test preventing regressions.

---

## 1. Cryptographic Invariants

| ID | Invariant | Formal Description | Verification Test |
|:---|:---|:---|:---|
| **C1** | **Transaction Authenticity** | Every executed transaction carries an Ed25519 signature strictly valid for the canonical payload hash. | `prop_signature_always_valid_after_creation`<br>`test_transaction_signature_and_chain_isolation` |
| **C2** | **Chain Isolation (Cross-Chain Anti-Replay)** | Transactions issued for one `chain_id` are strictly rejected by nodes operating on another `chain_id`. | `test_transaction_signature_and_chain_isolation`<br>`test_cross_chain_replay_rejected_mainnet_to_testnet` |
| **C3** | **Proposer Authentication** | Blocks may only be proposed by the validator deterministically elected for that specific height/round. | `test_full_node_lifecycle_and_block_production`<br>`test_pos_bft_and_bisection_arbitration` |
| **C4** | **BFT Quorum Certificate Supermajority (2/3 + 1)** | No block can be committed without valid signatures from at least $\lfloor 2N/3 \rfloor + 1$ active validators. | `test_apply_block_rejects_forged_block_without_supermajority`<br>`test_bft_consensus_voting_supermajority` |

---

## 2. Economic and Accounting Invariants

| ID | Invariant | Formal Description | Verification Test |
|:---|:---|:---|:---|
| **E1** | **Conservation Law (Conservation of $VERA)** | The sum of all balances before a transaction is identical to the sum of all balances after: $\sum B_{before} = \sum B_{after}$. No tokens can be arbitrarily minted or destroyed. | `prop_conservation_of_vera`<br>`test_total_supply_integrity_after_multiple_blocks` |
| **E2** | **Self-Transfer Integrity** | Sending tokens to oneself ($sender == to$) never alters the principal balance; only the consumed gas fee is deducted. | `prop_self_transfer_preserves_balance`<br>`test_state_transition_self_transfer_does_not_vaporize_balance` |
| **E3** | **Strict Nonce Monotonicity** | An account's nonce increments by exactly +1 per confirmed transaction. No arbitrary jumps or reuse of past nonces are permitted. | `prop_nonce_strictly_monotonic` |
| **E4** | **Deterministic Insolvency Rejection** | If $amount + max\_gas > balance$, the transaction is rejected prior to any state mutation. Balances can never become negative. | `prop_insufficient_balance_never_creates_vera`<br>`test_mempool_rejects_insolvent_transaction` |
| **E5** | **Exact Fee Distribution (70 / 15 / 15)** | Consumed gas fee is partitioned with integer precision: 70% to proposer, 15% to stability pool (`0x00...57ab`), 15% to permanent burn (`0x00...dead`). The sum of parts equals the exact deducted amount. | `prop_conservation_of_vera`<br>`test_total_supply_integrity_after_multiple_blocks` |

---

## 3. Network and DoS Mitigation Invariants

| ID | Invariant | Formal Description | Mechanism / Test |
|:---|:---|:---|:---|
| **N1** | **RPC Payload Limit (Anti-OOM)** | HTTP/RPC payloads exceeding 1 MB are immediately rejected with `HTTP 413 Payload Too Large`. | `MAX_RPC_PAYLOAD_SIZE = 1MB` (`bin/vera_node.rs`) |
| **N2** | **Socket Read Timeout (Anti-Slowloris)** | TCP connections that hold open sockets without transmitting full payloads for over 10 seconds are forcibly dropped. | `tokio::time::timeout(10s)` (`bin/vera_node.rs`) |
| **N3** | **Solvent Mempool Admission** | Transactions with insufficient balance to cover `amount + gas_limit * gas_price` are blocked at mempool entry. | `test_mempool_rejects_insolvent_transaction` |
| **N4** | **Bounded Nonce Gap Window** | The mempool rejects transactions whose nonce exceeds the account's current confirmed nonce by more than 16 (`MAX_PENDING_NONCE_GAP = 16`). | `FullNode::submit_transaction` |
| **N5** | **Bounded Block Time Drift** | Blocks with a timestamp drifting by more than 15 seconds from the node's local clock are rejected. | `MAX_FUTURE_TIMESTAMP_DRIFT = 15s` (`src/node.rs`) |

---

## 4. State Machine and VERA Language v2 Invariants

| ID | Invariant | Formal Description | Verification Test |
|:---|:---|:---|:---|
| **S1** | **Structural Acyclicity (DAG SSA)** | Computation graphs submitted as smart contracts undergo static $O(V+E)$ acyclicity validation prior to execution. | `Transaction::validate_static_dag` |
| **S2** | **Universal Cross-Platform Determinism** | Smart contract execution is evaluated deterministically, guaranteeing bit-for-bit parity across Windows, Linux, and macOS. | `test_v2_smart_contract_execution_on_blockchain`<br>`test_state_transition_transfer` |
| **S3** | **CSMT Cryptographic Isolation** | State roots computed by the Compact Sparse Merkle Tree (CSMT) depend solely on valid key/value pairs hashed via Blake3. | `test_csmt_inclusion_and_non_existence` |

---

## 5. Executing Invariant Verification

```bash
# 1. Run full test suite (unit + integration + property tests)
cargo test --all

# 2. Run mathematical property tests exclusively (proptest)
cargo test --test property_tests -- --test-threads=1

# 3. Run accounting supply integrity audit test
cargo test --test supply_integrity_test
```

> [!IMPORTANT]
> **CI/CD Golden Rule:** Any commit or pull request resulting in a failure in any test of this matrix must be rejected immediately. Mathematical invariance is non-negotiable.
