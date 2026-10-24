//! Incremental state persistence: full snapshot every STATE_SNAPSHOT_EVERY blocks plus a
//! per-block delta log. A node reopened from disk must have exactly the same height and
//! state root, also when the last delta record is torn (crash in the middle of an append).

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::io::Write;
use vera_blockchain::account::{address_from_pubkey, address_to_hex};
use vera_blockchain::genesis::{GenesisAccount, GenesisConfig};
use vera_blockchain::node::{FullNode, STATE_SNAPSHOT_EVERY};
use vera_blockchain::transaction::Transaction;

#[tokio::test]
async fn reopen_restores_exact_state_across_snapshot_and_deltas() {
    let (mut cfg, val_key) = GenesisConfig::default_testnet();
    let payers: Vec<SigningKey> = (0..20).map(|_| SigningKey::generate(&mut OsRng)).collect();
    for k in &payers {
        cfg.initial_accounts.push(GenesisAccount {
            address: address_to_hex(&address_from_pubkey(&k.verifying_key().to_bytes())),
            balance: "1000000000000000000000".to_string(),
        });
    }
    let dir = std::env::temp_dir().join(format!("vera_incr_state_{}", rand::random::<u64>()));
    let blocks = STATE_SNAPSHOT_EVERY + 50;
    let (height, root) = {
        let mut node = FullNode::load_or_init(&dir, &cfg, Some(val_key.clone())).unwrap();
        for b in 0..blocks {
            // a few transfers per block, to fresh and existing recipients
            for (i, k) in payers.iter().enumerate().take(5) {
                let to = vera_blockchain::chain_hash::hash256(&(b * 100 + i as u64).to_le_bytes());
                let tx = Transaction::new(&node.chain_id, k, b, Some(to), 1, 21_000, 1, vec![]);
                node.submit_transaction(tx).expect("admission");
            }
            let block = node.build_proposal().await.expect("build");
            node.apply_block(block).await.expect("apply");
        }
        assert_eq!(node.height, blocks);
        (node.height, node.csmt.root())
    };

    // 1. Reopen: snapshot at STATE_SNAPSHOT_EVERY + 50 replayed deltas.
    {
        let node = FullNode::load_or_init(&dir, &cfg, Some(val_key.clone())).unwrap();
        assert_eq!(node.height, height);
        assert_eq!(node.csmt.root(), root, "state root after reopen must match");
    }

    // 2. A torn record at the end of the log (crash during an append) is ignored.
    {
        let log = dir.join("state").join("state_deltas.log");
        let mut f = std::fs::OpenOptions::new().append(true).open(&log).unwrap();
        f.write_all(b"VDL1\x99\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00partial").unwrap();
        let node = FullNode::load_or_init(&dir, &cfg, Some(val_key)).unwrap();
        assert_eq!(node.height, height);
        assert_eq!(node.csmt.root(), root, "torn tail must not change the state");
    }
    let _ = std::fs::remove_dir_all(&dir);
}
