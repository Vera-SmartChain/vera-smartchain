//! Execution rules v2: stability-pool and burn fee shares credited once per block,
//! receipts without a per-transaction state root, receipt hash v2 covering the logs.

use ed25519_dalek::SigningKey;
use vera_blockchain::account::{address_from_pubkey, address_to_hex, Account, EvmLog, ExecutionReceipt};
use vera_blockchain::block::Block;
use vera_blockchain::genesis::{GenesisAccount, GenesisConfig};
use vera_blockchain::node::FullNode;
use vera_blockchain::state_transition::{BURN_ADDRESS, STABILITY_POOL_ADDRESS};
use vera_blockchain::transaction::Transaction;

const PAYERS: u8 = 12;
const PER_PAYER: u64 = 4;

fn payer(i: u8) -> SigningKey {
    SigningKey::from_bytes(&[i.wrapping_add(1); 32])
}

fn genesis() -> (GenesisConfig, SigningKey) {
    let (mut cfg, val_key) = GenesisConfig::default_testnet();
    for i in 0..PAYERS {
        cfg.initial_accounts.push(GenesisAccount {
            address: address_to_hex(&address_from_pubkey(&payer(i).verifying_key().to_bytes())),
            balance: "1000000000000000000000".to_string(),
        });
    }
    (cfg, val_key)
}

fn node(cfg: &GenesisConfig, key: Option<SigningKey>) -> FullNode {
    let dir = std::env::temp_dir().join(format!("vera_exec_v2_{}", rand::random::<u64>()));
    FullNode::load_or_init(&dir, cfg, key).unwrap()
}

fn fill_mempool(n: &mut FullNode) {
    for nonce in 0..PER_PAYER {
        for i in 0..PAYERS {
            let tx = Transaction::new(&n.chain_id, &payer(i), nonce, Some([0x11u8; 32]), 1_000 + i as u128, 21_000, 7, vec![]);
            n.submit_transaction(tx).expect("admission");
        }
    }
}

fn balance(n: &FullNode, addr: &[u8; 32]) -> u128 {
    n.csmt.get(addr).and_then(|b| Account::from_bytes(b).ok()).map_or(0, |a| a.balance)
}

/// Sum of every account balance in the state (non-account entries are skipped).
fn supply(n: &FullNode) -> u128 {
    n.csmt.iter().filter_map(|(_, b)| Account::from_bytes(b).ok()).map(|a| a.balance).sum()
}

/// Builds one block on a fresh node with the given activation, applies it, and returns
/// (block, node after the block).
async fn one_block(cfg: &GenesisConfig, key: &SigningKey) -> (Block, FullNode) {
    let mut n = node(cfg, Some(key.clone()));
    fill_mempool(&mut n);
    let block = n.build_proposal().await.expect("build");
    n.validate_proposal(&block).await.expect("own proposal validates");
    n.apply_block(block.clone()).await.expect("apply");
    (block, n)
}

#[tokio::test]
async fn v2_reaches_the_same_state_as_v1() {
    let (cfg_v1, key) = genesis();
    let mut cfg_v2 = cfg_v1.clone();
    cfg_v2.exec_v2_activation_height = Some(1);

    let supply_before = supply(&node(&cfg_v1, None));
    let (b1, n1) = one_block(&cfg_v1, &key).await;
    let (b2, n2) = one_block(&cfg_v2, &key).await;

    let txs = (PAYERS as u64 * PER_PAYER) as usize;
    assert_eq!(b1.transactions.len(), txs);
    assert_eq!(b2.transactions.len(), txs);
    // Same balances everywhere, including the stability pool and the burn address.
    assert_eq!(b1.header.state_root, b2.header.state_root, "v2 must not change the resulting state");
    assert_eq!(balance(&n1, &STABILITY_POOL_ADDRESS), balance(&n2, &STABILITY_POOL_ADDRESS));
    assert_eq!(balance(&n1, &BURN_ADDRESS), balance(&n2, &BURN_ADDRESS));
    assert!(balance(&n2, &BURN_ADDRESS) > 0);
    assert_eq!(supply(&n1), supply_before);
    assert_eq!(supply(&n2), supply_before);
    // Only the receipts differ: no per-transaction root, new hash.
    assert_ne!(b1.header.receipts_root, b2.header.receipts_root);
    assert!(b1.receipts.iter().all(|r| r.state_root != [0u8; 32]));
    assert!(b2.receipts.iter().all(|r| r.state_root == [0u8; 32]));
    assert_eq!(b2.header.receipts_root, Block::compute_receipts_root_v2(&b2.receipts));
}

#[tokio::test]
async fn activation_mismatch_is_rejected_both_ways() {
    let (cfg_v1, key) = genesis();
    let mut cfg_v2 = cfg_v1.clone();
    cfg_v2.exec_v2_activation_height = Some(1);

    let (b2, _) = one_block(&cfg_v2, &key).await;
    let follower_v1 = node(&cfg_v1, None);
    assert!(follower_v1.validate_proposal(&b2).await.is_err(), "a v1 node must reject a v2 block");
    let follower_v2 = node(&cfg_v2, None);
    follower_v2.validate_proposal(&b2).await.expect("a v2 node accepts it");

    let (b1, _) = one_block(&cfg_v1, &key).await;
    assert!(follower_v2.validate_proposal(&b1).await.is_err(), "a v2 node must reject a v1 block at its height");
}

#[tokio::test]
async fn activation_height_switches_rules() {
    let (mut cfg, key) = genesis();
    cfg.exec_v2_activation_height = Some(2);
    let mut n = node(&cfg, Some(key));
    let follower = node(&cfg, None);
    let mut follower = follower;

    for nonce in 0..2u64 {
        for i in 0..PAYERS {
            let tx = Transaction::new(&n.chain_id, &payer(i), nonce, Some([0x11u8; 32]), 1, 21_000, 7, vec![]);
            n.submit_transaction(tx).expect("admission");
        }
        let block = n.build_proposal().await.expect("build");
        follower.validate_proposal(&block).await.expect("follower agrees");
        let v2 = block.header.height >= 2;
        assert!(!block.transactions.is_empty());
        assert_eq!(block.receipts.iter().all(|r| r.state_root == [0u8; 32]), v2, "height {}", block.header.height);
        n.apply_block(block.clone()).await.expect("apply");
        follower.apply_block(block).await.expect("follower apply");
    }
    assert_eq!(n.csmt.root(), follower.csmt.root());
}

#[test]
fn receipt_hash_v2_covers_logs() {
    let base = ExecutionReceipt {
        tx_hash: [1u8; 32],
        success: true,
        gas_used: 21_000,
        state_root: [0u8; 32],
        trace_root: [2u8; 32],
        logs: vec![EvmLog { address: [3u8; 32], topics: vec![[4u8; 32]], data: vec![5, 6] }],
    };
    let mut other = base.clone();
    other.logs[0].data = vec![5, 7];
    assert_eq!(base.hash(), other.hash(), "v1 hash leaves the logs out");
    assert_ne!(base.hash_v2(), other.hash_v2());

    // Moving a byte between topic and data must change the hash (length prefixes).
    let mut a = base.clone();
    a.logs[0] = EvmLog { address: [3u8; 32], topics: vec![], data: [[4u8; 32].as_slice(), &[5, 6]].concat() };
    assert_ne!(base.hash_v2(), a.hash_v2());
    let mut no_logs = base.clone();
    no_logs.logs.clear();
    assert_ne!(base.hash_v2(), no_logs.hash_v2());
}
