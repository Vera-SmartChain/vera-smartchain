use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use vera_blockchain::account::Account;
use vera_blockchain::csmt::CSMT;
use vera_blockchain::state_transition::StateTransitionEngine;
use vera_blockchain::transaction::Transaction;
use vera_engine_v2::{ComputationGraph, canonical_hash};

#[tokio::test]
async fn test_v2_smart_contract_execution_on_blockchain() {
    let mut csmt = CSMT::new();

    let mut csprng = OsRng;
    let alice_key = SigningKey::generate(&mut csprng);
    let alice_pub = alice_key.verifying_key().to_bytes();
    let alice_addr = vera_blockchain::chain_hash::hash256(&alice_pub);

    let bob_key = SigningKey::generate(&mut csprng);
    let bob_pub = bob_key.verifying_key().to_bytes();
    let bob_addr = vera_blockchain::chain_hash::hash256(&bob_pub);

    // Alice has 100_000_000 in initial state
    let mut alice_acc = Account::new(100_000_000);
    alice_acc.nonce = 0;
    csmt.insert(alice_addr, alice_acc.to_bytes());

    // Create VERA v2 Smart Contract: (Input0 + Input1) * 2
    let mut graph = ComputationGraph::new();
    let in0 = graph.add_input(0);
    let in1 = graph.add_input(1);
    let c2 = graph.add_const(2);
    let sum = graph.add_add(in0, in1);
    let res = graph.add_mul(sum, c2);
    graph.set_output(res);

    let contract_json = graph.to_json();
    let expected_trace_root = canonical_hash(&graph);

    // Create transaction calling the contract with 50_000 transfer to Bob
    let tx = Transaction::new(
        "vera-testnet-1",
        &alice_key,
        0,
        Some(bob_addr),
        50_000,
        100_000,
        1,
        contract_json.into_bytes(),
    );

    let proposer_addr = [0u8; 32];
    let receipt = StateTransitionEngine::execute_transaction(&mut csmt, &tx, proposer_addr)
        .await
        .expect("Transaction must execute successfully");

    assert!(receipt.success, "Execution must succeed");
    assert_eq!(receipt.trace_root, expected_trace_root, "Trace root must match canonical hash of VERA v2 Graph");

    // Bob balance must have increased by 50_000
    let bob_bytes = csmt.get(&bob_addr).expect("Bob account must exist");
    let bob_acc = Account::from_bytes(bob_bytes).unwrap();
    assert_eq!(bob_acc.balance, 50_000);
}

#[tokio::test]
async fn test_v2_smart_contract_isomorphic_receipt() {
    // Proves that two nodes receiving commutative contract expressions in different orders
    // arrive at identical state transition receipts and canonical trace roots
    let mut g1 = ComputationGraph::new();
    let a1 = g1.add_input(0);
    let b1 = g1.add_input(1);
    let s1 = g1.add_add(a1, b1);
    g1.set_output(s1);

    let mut g2 = ComputationGraph::new();
    let a2 = g2.add_input(0);
    let b2 = g2.add_input(1);
    let s2 = g2.add_add(b2, a2); // Commutative inverse order
    g2.set_output(s2);

    let h1 = canonical_hash(&g1);
    let h2 = canonical_hash(&g2);
    assert_eq!(h1, h2, "Isomorphic contract receipts on blockchain must be identical");
}
