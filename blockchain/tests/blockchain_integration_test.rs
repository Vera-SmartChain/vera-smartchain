use rand::rngs::OsRng;
use ed25519_dalek::SigningKey;

use vera_blockchain::account::{Account, address_from_hex};
use vera_blockchain::consensus::{Validator, ValidatorSet, Vote, VoteType};
use vera_blockchain::genesis::GenesisConfig;
use vera_blockchain::node::FullNode;
use vera_blockchain::transaction::Transaction;
use vera_blockchain::bisection::{BisectionGame, BisectionStatus};

#[tokio::test]
async fn test_full_blockchain_flow() {
    let temp_dir = std::env::temp_dir().join(format!("vera_integration_{}", rand::random::<u64>()));
    let (genesis_cfg, val_key) = GenesisConfig::default_testnet();

    // 1. Initialize FullNode from Genesis
    let mut node = FullNode::load_or_init(&temp_dir, &genesis_cfg, Some(val_key.clone())).unwrap();
    assert_eq!(node.height, 0);

    // Initial account configured in Genesis
    let user_addr = address_from_hex(&genesis_cfg.initial_accounts[0].address).unwrap();
    let user_acc_bytes = node.csmt.get(&user_addr).expect("Genesis user account must exist");
    let user_acc = Account::from_bytes(user_acc_bytes).unwrap();
    assert_eq!(user_acc.balance, 1000000000000000000000); // 1,000 VERA

    // 2. Create recipient account (Bob)
    let mut csprng = OsRng;
    let bob_key = SigningKey::generate(&mut csprng);
    let bob_pub = bob_key.verifying_key().to_bytes();
    let bob_addr = *blake3::hash(&bob_pub).as_bytes();

    // 3. Produce and submit valid transaction
    let val_pub = val_key.verifying_key().to_bytes();
    let _val_addr = *blake3::hash(&val_pub).as_bytes();

    let tx = Transaction::new(
        "vera-testnet-1",
        &val_key,
        0,
        Some(bob_addr),
        5_000_000_000, // 5 Gwei VERA
        30_000,
        1,
        vec![],
    );

    let _tx_hash = node.submit_transaction(tx).expect("Valid transaction must be admitted to mempool");
    assert_eq!(node.mempool.len(), 1);

    // 4. Validator proposes and commits Block #1
    let block1 = node.propose_and_commit_block().await.expect("Block #1 committed");
    assert_eq!(block1.header.height, 1);
    assert_eq!(node.height, 1);
    assert_eq!(node.mempool.len(), 0); // Clean mempool

    // 5. Verify post-block balances
    let bob_acc = Account::from_bytes(node.csmt.get(&bob_addr).unwrap()).unwrap();
    assert_eq!(bob_acc.balance, 5_000_000_000);

    // 6. Anti-Replay: Attempting to submit same nonce must fail
    let duplicate_tx = Transaction::new(
        "vera-testnet-1",
        &val_key,
        0, // Nonce 0 already executed in Block #1
        Some(bob_addr),
        1_000_000,
        30_000,
        1,
        vec![],
    );
    let replay_err = node.submit_transaction(duplicate_tx);
    assert!(replay_err.is_err(), "Anti-replay must reject obsolete nonce");

    // 6.1. Cross-Chain Protection: Replay from another network (e.g. mainnet) MUST fail
    let cross_chain_tx = Transaction::new(
        "vera-mainnet",
        &val_key,
        1,
        Some(bob_addr),
        1_000_000,
        30_000,
        1,
        vec![],
    );
    let cross_err = node.submit_transaction(cross_chain_tx);
    assert!(cross_err.is_err(), "Node must block tx from different chain_id immediately");

    // 7. Resilience: Close and reload FullNode from disk
    let reopened = FullNode::load_or_init(&temp_dir, &genesis_cfg, None).unwrap();
    assert_eq!(reopened.height, 1);
    assert_eq!(reopened.latest_block_hash, block1.hash());
    let bob_restored = Account::from_bytes(reopened.csmt.get(&bob_addr).unwrap()).unwrap();
    assert_eq!(bob_restored.balance, 5_000_000_000);

    // Cleanup
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_pos_bft_and_bisection_arbitration() {
    let mut csprng = OsRng;

    // 1. Test BFT Consensus
    let v1 = SigningKey::generate(&mut csprng);
    let v2 = SigningKey::generate(&mut csprng);
    let v3 = SigningKey::generate(&mut csprng);

    let p1 = v1.verifying_key().to_bytes();
    let p2 = v2.verifying_key().to_bytes();
    let p3 = v3.verifying_key().to_bytes();

    let val_set = ValidatorSet::new(vec![
        Validator { address: [1; 32], public_key: p1, stake: 50, missed_blocks: 0, is_jailed: false },
        Validator { address: [2; 32], public_key: p2, stake: 30, missed_blocks: 0, is_jailed: false },
        Validator { address: [3; 32], public_key: p3, stake: 20, missed_blocks: 0, is_jailed: false },
    ]);

    // Total: 100. Threshold 2/3 + 1: 67.
    let block_hash = [0x77u8; 32];
    let vote1 = Vote::new("vera-testnet-1", 5, 0, block_hash, VoteType::PreCommit, &v1);
    let vote2 = Vote::new("vera-testnet-1", 5, 0, block_hash, VoteType::PreCommit, &v2);

    // 50 + 30 = 80 >= 67 -> Supermajority
    assert!(val_set.check_supermajority("vera-testnet-1", &[vote1, vote2], 5, 0, &block_hash, VoteType::PreCommit).unwrap());

    // 2. Test Bisection Game and Fraud Proof with Deadlines
    let mut game = BisectionGame::new(
        [0x11; 32],
        [1; 32],
        [2; 32],
        100_000,
        16, // 16 instructions
        [0; 32],
        [0xff; 32],
        [0xee; 32],
        100, // start_height
        50,  // round_timeout
    );

    // Converge 4 rounds to isolate single step
    for _i in 0..4 {
        let mid = game.midpoint();
        let _ = game.step_bisection([mid as u8; 32], mid < 7).unwrap();
    }
    assert_eq!(game.right - game.left, 1);

    let step_bytes = b"CONTESTED_STEP_7";
    let mut h = vera_engine_v2::VeraHasher::new();
    h.update(b"STEP_ARBITRATION");
    h.update(&game.left_hash);
    h.update(step_bytes);
    let correct_output = h.finalize();

    let res = game.arbitrate_single_step(step_bytes, correct_output);
    match res {
        BisectionStatus::ResolvedChallengerWon { .. } => {
            // Success! Challenger won and fraudulent proposer slashed
        }
        _ => panic!("Expected ChallengerWon"),
    }
}
