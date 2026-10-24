//! Cheap mempool prune after a block (nonces only): must drop exactly what the full
//! prune drops for nonce reasons, and keep the sender's contiguous pending run.

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use vera_blockchain::account::{address_from_pubkey, address_to_hex};
use vera_blockchain::genesis::{GenesisAccount, GenesisConfig};
use vera_blockchain::node::{FullNode, MAX_PENDING_NONCE_GAP};
use vera_blockchain::transaction::Transaction;

#[tokio::test]
async fn nonce_prune_keeps_contiguous_run_and_drops_stale_or_far_future() {
    let (mut cfg, val_key) = GenesisConfig::default_testnet();
    let payer = SigningKey::generate(&mut OsRng);
    cfg.initial_accounts.push(GenesisAccount {
        address: address_to_hex(&address_from_pubkey(&payer.verifying_key().to_bytes())),
        balance: "1000000000000000000000".to_string(),
    });
    let dir = std::env::temp_dir().join(format!("vera_prune_{}", rand::random::<u64>()));
    let mut node = FullNode::load_or_init(&dir, &cfg, Some(val_key)).unwrap();
    let to = Some([7u8; 32]);
    let tx = |n: u64| Transaction::new(&node_chain(&cfg), &payer, n, to, 1, 21_000, 1, vec![]);

    // Block with nonces 0..3 (account nonce becomes 3).
    for n in 0..3 {
        node.submit_transaction(tx(n)).expect("admission");
    }
    let block = node.build_proposal().await.expect("build");
    node.apply_block(block).await.expect("apply");

    // Pending as a peer could leave it: a stale nonce, a contiguous run 3..6, a gap
    // inside the allowed window, and one beyond it.
    let end_of_run = 6u64;
    let in_window = end_of_run + 2;
    let too_far = end_of_run + MAX_PENDING_NONCE_GAP + 1;
    node.mempool = vec![tx(1), tx(3), tx(4), tx(5), tx(in_window), tx(too_far)];

    let pruned = node.prune_mempool_nonces();
    let mut kept: Vec<u64> = node.mempool.iter().map(|t| t.nonce).collect();
    kept.sort_unstable();
    assert_eq!(kept, vec![3, 4, 5, in_window], "stale and far-future txs go, the rest stays");
    assert_eq!(pruned, 2);
    assert!(node.mempool_dirty, "a prune that removed txs must schedule a mempool save");
    let _ = std::fs::remove_dir_all(&dir);
}

fn node_chain(cfg: &GenesisConfig) -> String {
    cfg.chain_id.clone()
}

#[tokio::test]
async fn off_lock_full_prune_drops_failing_txs_but_not_ones_whose_sender_changed() {
    let (mut cfg, val_key) = GenesisConfig::default_testnet();
    let rich = SigningKey::generate(&mut OsRng);
    let poor = SigningKey::generate(&mut OsRng);
    let poor2 = SigningKey::generate(&mut OsRng);
    for (k, bal) in [(&rich, "1000000000000000000000"), (&poor, "100000"), (&poor2, "100000")] {
        cfg.initial_accounts.push(GenesisAccount {
            address: address_to_hex(&address_from_pubkey(&k.verifying_key().to_bytes())),
            balance: bal.to_string(),
        });
    }
    let dir = std::env::temp_dir().join(format!("vera_prune_full_{}", rand::random::<u64>()));
    let mut node = FullNode::load_or_init(&dir, &cfg, Some(val_key)).unwrap();
    let chain = cfg.chain_id.clone();
    // Both poor accounts try to send more than they have (fails when executed).
    let too_big = |k: &SigningKey| Transaction::new(&chain, k, 0, Some([5u8; 32]), 10_000_000, 21_000, 1, vec![]);
    let good = Transaction::new(&chain, &rich, 0, Some([5u8; 32]), 1, 21_000, 1, vec![]);
    node.mempool = vec![too_big(&poor), too_big(&poor2), good.clone()];

    let snap = node.full_prune_snapshot();
    let result = FullNode::compute_full_prune(snap);
    assert_eq!(result.drop.len(), 2, "both overspending txs fail");

    // Meanwhile poor2 receives funds in a block: its tx may be valid now, so it stays.
    let poor2_addr = address_from_pubkey(&poor2.verifying_key().to_bytes());
    let fund = Transaction::new(&chain, &rich, 0, Some(poor2_addr), 1_000_000_000_000, 21_000, 1, vec![]);
    let saved = std::mem::take(&mut node.mempool);
    node.submit_transaction(fund).expect("admission");
    let block = node.build_proposal().await.expect("build");
    node.apply_block(block).await.expect("apply");
    node.mempool = saved.into_iter().filter(|t| t.tx_hash() != good.tx_hash()).collect();

    let pruned = node.apply_full_prune(result);
    assert_eq!(pruned, 1, "only the tx whose sender did not change is dropped");
    assert_eq!(node.mempool.len(), 1);
    assert_eq!(node.mempool[0].sender, poor2_addr);
    let _ = std::fs::remove_dir_all(&dir);
}
