use rand::rngs::OsRng;
use ed25519_dalek::SigningKey;

use vera_blockchain::account::{Account, address_from_pubkey};
use vera_blockchain::csmt::CSMT;
use vera_blockchain::genesis::GenesisConfig;
use vera_blockchain::node::FullNode;
use vera_blockchain::state_transition::{BURN_ADDRESS, STABILITY_POOL_ADDRESS};
use vera_blockchain::transaction::Transaction;

fn calculate_total_system_supply(csmt: &CSMT) -> u128 {
    let mut total: u128 = 0;
    for (_addr, acc_bytes) in csmt.to_key_values() {
        if let Ok(acc) = Account::from_bytes(&acc_bytes) {
            total = total.checked_add(acc.balance).expect("Overflow summing total supply");
        }
    }
    total
}

#[tokio::test]
async fn test_total_supply_integrity_after_multiple_blocks() {
    let temp_dir = std::env::temp_dir().join(format!("vera_supply_integrity_{}", rand::random::<u64>()));
    let (genesis_cfg, val_key) = GenesisConfig::default_testnet();

    // 1. Initialize FullNode from Genesis
    let mut node = FullNode::load_or_init(&temp_dir, &genesis_cfg, Some(val_key.clone())).unwrap();
    assert_eq!(node.height, 0);

    // 2. Calculate initial total supply at Genesis
    let initial_supply = calculate_total_system_supply(&node.csmt);
    assert!(initial_supply > 0, "Initial supply must be greater than zero");

    // 3. Create test accounts
    let mut csprng = OsRng;
    let bob_key = SigningKey::generate(&mut csprng);
    let bob_addr = address_from_pubkey(&bob_key.verifying_key().to_bytes());

    let carol_key = SigningKey::generate(&mut csprng);
    let carol_addr = address_from_pubkey(&carol_key.verifying_key().to_bytes());

    let dave_key = SigningKey::generate(&mut csprng);
    let dave_addr = address_from_pubkey(&dave_key.verifying_key().to_bytes());

    // Block 1: Validator sends funds to Bob and Carol
    let tx1 = Transaction::new(
        &node.chain_id,
        &val_key,
        0,
        Some(bob_addr),
        10_000_000_000, // 10 Gwei VERA
        30_000,
        2,
        vec![],
    );
    let tx2 = Transaction::new(
        &node.chain_id,
        &val_key,
        1,
        Some(carol_addr),
        15_000_000_000, // 15 Gwei VERA
        30_000,
        3,
        vec![],
    );
    node.submit_transaction(tx1).expect("Tx1 to Bob must be admitted");
    node.submit_transaction(tx2).expect("Tx2 to Carol must be admitted");

    let block1 = node.propose_and_commit_block().await.expect("Block 1 committed");
    assert_eq!(block1.header.height, 1);
    assert_eq!(node.height, 1);

    // Accounting invariant check on Block 1
    let supply_after_block1 = calculate_total_system_supply(&node.csmt);
    assert_eq!(
        supply_after_block1, initial_supply,
        "Law of Conservation violated in Block 1: initial_supply ({}) != supply_block1 ({})",
        initial_supply, supply_after_block1
    );

    // Block 2: Bob sends to Dave, Carol sends to Dave, Validator sends to Bob
    let tx3 = Transaction::new(
        &node.chain_id,
        &bob_key,
        0,
        Some(dave_addr),
        2_000_000_000,
        25_000,
        1,
        vec![],
    );
    let tx4 = Transaction::new(
        &node.chain_id,
        &carol_key,
        0,
        Some(dave_addr),
        3_000_000_000,
        25_000,
        2,
        vec![],
    );
    let tx5 = Transaction::new(
        &node.chain_id,
        &val_key,
        2,
        Some(bob_addr),
        5_000_000_000,
        30_000,
        1,
        vec![],
    );
    node.submit_transaction(tx3).expect("Tx3 from Bob to Dave must be admitted");
    node.submit_transaction(tx4).expect("Tx4 from Carol to Dave must be admitted");
    node.submit_transaction(tx5).expect("Tx5 from Validator to Bob must be admitted");

    let block2 = node.propose_and_commit_block().await.expect("Block 2 committed");
    assert_eq!(block2.header.height, 2);
    assert_eq!(node.height, 2);

    // Accounting invariant check on Block 2
    let supply_after_block2 = calculate_total_system_supply(&node.csmt);
    assert_eq!(
        supply_after_block2, initial_supply,
        "Law of Conservation violated in Block 2: initial_supply ({}) != supply_block2 ({})",
        initial_supply, supply_after_block2
    );

    // Block 3: Dave self-transfers (Edge Case) + Bob sends to Carol with VERA v2 smart contract
    let mut graph = vera_engine_v2::ComputationGraph::new();
    let in0 = graph.add_input(0);
    let in1 = graph.add_input(1);
    let sum = graph.add_add(in0, in1);
    graph.set_output(sum);
    let contract_bytes = graph.to_json().into_bytes();

    let tx6 = Transaction::new(
        &node.chain_id,
        &dave_key,
        0,
        Some(dave_addr), // Self transfer
        1_000_000_000,
        25_000,
        1,
        vec![],
    );
    let tx7 = Transaction::new(
        &node.chain_id,
        &bob_key,
        1,
        Some(carol_addr),
        500_000_000,
        35_000,
        1,
        contract_bytes,
    );
    node.submit_transaction(tx6).expect("Tx6 self-transfer from Dave must be admitted");
    node.submit_transaction(tx7).expect("Tx7 from Bob with calldata must be admitted");

    let block3 = node.propose_and_commit_block().await.expect("Block 3 committed");
    assert_eq!(block3.header.height, 3);
    assert_eq!(node.height, 3);

    // Final accounting invariant check on Block 3
    let supply_after_block3 = calculate_total_system_supply(&node.csmt);
    assert_eq!(
        supply_after_block3, initial_supply,
        "Law of Conservation violated in Block 3: initial_supply ({}) != supply_block3 ({})",
        initial_supply, supply_after_block3
    );

    // Additional check: Fees properly distributed to protocol addresses
    let stability_acc = Account::from_bytes(
        node.csmt.get(&STABILITY_POOL_ADDRESS).expect("Stability pool must hold fee balance")
    ).unwrap();
    assert!(stability_acc.balance > 0, "Stability pool must have received 15% of fees");

    let burn_acc = Account::from_bytes(
        node.csmt.get(&BURN_ADDRESS).expect("Burn address must hold fee balance")
    ).unwrap();
    assert!(burn_acc.balance > 0, "Burn address must have received 15% of fees");

    // Cleanup
    let _ = std::fs::remove_dir_all(&temp_dir);
}
