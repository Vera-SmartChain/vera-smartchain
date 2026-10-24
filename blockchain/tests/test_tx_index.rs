//! Persisted tx-hash index: a reopened node must have the same index and latest-txs list
//! as the one that applied the blocks, with the index file intact, missing (upgrade from
//! a version without it) or torn at the end (crash during an append).

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::io::Write;
use vera_blockchain::account::{address_from_pubkey, address_to_hex};
use vera_blockchain::genesis::{GenesisAccount, GenesisConfig};
use vera_blockchain::node::FullNode;
use vera_blockchain::storage::TX_INDEX_FILE;
use vera_blockchain::transaction::Transaction;

#[tokio::test]
async fn reopen_restores_tx_index_from_file_or_blocks() {
    let (mut cfg, val_key) = GenesisConfig::default_testnet();
    let payers: Vec<SigningKey> = (0..8).map(|_| SigningKey::generate(&mut OsRng)).collect();
    for k in &payers {
        cfg.initial_accounts.push(GenesisAccount {
            address: address_to_hex(&address_from_pubkey(&k.verifying_key().to_bytes())),
            balance: "1000000000000000000000".to_string(),
        });
    }
    let dir = std::env::temp_dir().join(format!("vera_tx_index_{}", rand::random::<u64>()));
    let (index, recent) = {
        let mut node = FullNode::load_or_init(&dir, &cfg, Some(val_key.clone())).unwrap();
        for b in 0..30u64 {
            for k in payers.iter() {
                let tx = Transaction::new(&node.chain_id, k, b, Some([9u8; 32]), 1, 21_000, 1, vec![]);
                node.submit_transaction(tx).expect("admission");
            }
            let block = node.build_proposal().await.expect("build");
            node.apply_block(block).await.expect("apply");
        }
        assert_eq!(node.tx_index.len(), 240);
        assert_eq!(node.recent_transactions.len(), 100);
        (node.tx_index.clone(), node.recent_transactions.iter().map(|r| r.hash.clone()).collect::<Vec<_>>())
    };
    let check = |label: &str| {
        let node = FullNode::load_or_init(&dir, &cfg, Some(val_key.clone())).unwrap();
        assert_eq!(node.tx_index, index, "{}: tx index", label);
        let r: Vec<String> = node.recent_transactions.iter().map(|r| r.hash.clone()).collect();
        assert_eq!(r, recent, "{}: latest txs", label);
    };
    let file = dir.join("blocks").join(TX_INDEX_FILE);

    check("index file");
    std::fs::remove_file(&file).unwrap();
    check("no index file (rebuilt from blocks)");
    assert!(file.exists(), "the rebuild writes the index file");
    std::fs::OpenOptions::new().append(true).open(&file).unwrap().write_all(&[0xAB; 20]).unwrap();
    check("torn tail");
    let _ = std::fs::remove_dir_all(&dir);
}
