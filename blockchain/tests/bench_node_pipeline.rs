//! Node pipeline micro-benchmark (no network): where does the time of a block go?
//! Run: cargo test --release --test bench_node_pipeline -- --ignored --nocapture
//! PAYERS × PER_PAYER native transfers: admission time per tx as the mempool grows,
//! then build_proposal / validate_proposal / apply_block for one block with all of them.

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::time::Instant;
use vera_blockchain::account::{address_from_pubkey, address_to_hex};
use vera_blockchain::genesis::{GenesisAccount, GenesisConfig};
use vera_blockchain::node::FullNode;
use vera_blockchain::transaction::Transaction;

#[tokio::test]
#[ignore]
async fn bench_admission_and_block_stages() {
    let payers_n: usize = std::env::var("PAYERS").ok().and_then(|s| s.parse().ok()).unwrap_or(100);
    let per: u64 = std::env::var("PER_PAYER").ok().and_then(|s| s.parse().ok()).unwrap_or(15);
    let (mut cfg, val_key) = GenesisConfig::default_testnet();
    let payers: Vec<SigningKey> = (0..payers_n).map(|_| SigningKey::generate(&mut OsRng)).collect();
    for k in &payers {
        cfg.initial_accounts.push(GenesisAccount {
            address: address_to_hex(&address_from_pubkey(&k.verifying_key().to_bytes())),
            balance: "1000000000000000000000".to_string(),
        });
    }
    // Extra accounts to emulate a grown chain (STATE_ACCOUNTS, default 0).
    let extra: usize = std::env::var("STATE_ACCOUNTS").ok().and_then(|s| s.parse().ok()).unwrap_or(0);
    for i in 0..extra {
        let addr = vera_blockchain::chain_hash::hash256(&(i as u64).to_le_bytes());
        cfg.initial_accounts.push(GenesisAccount { address: address_to_hex(&addr), balance: "1000".to_string() });
    }
    let dir = std::env::temp_dir().join(format!("vera_bench_pipeline_{}", rand::random::<u64>()));
    let t = Instant::now();
    let mut node = FullNode::load_or_init(&dir, &cfg, Some(val_key)).unwrap();
    println!("state: {} accounts (genesis load {:.2} s)", node.csmt.len(), t.elapsed().as_secs_f64());
    let sink = [0x11u8; 32];

    // Sign everything first: signing is the client's cost, not the node's.
    let mut txs = Vec::new();
    for nonce in 0..per {
        for k in &payers {
            txs.push(Transaction::new(&node.chain_id, k, nonce, Some(sink), 1, 21_000, 1, vec![]));
        }
    }
    let total = txs.len();
    let mut bucket = Vec::new();
    let t_all = Instant::now();
    for (i, tx) in txs.into_iter().enumerate() {
        let t = Instant::now();
        node.submit_transaction(tx).expect("admission");
        bucket.push(t.elapsed().as_micros());
        if (i + 1) % 250 == 0 || i + 1 == total {
            let avg = bucket.iter().sum::<u128>() as f64 / bucket.len() as f64;
            println!("admission: mempool {:>5} -> avg {:>8.1} µs/tx", i + 1, avg);
            bucket.clear();
        }
    }
    let adm = t_all.elapsed();
    println!("admission total: {} tx in {:.3} s = {:.0} tx/s", total, adm.as_secs_f64(), total as f64 / adm.as_secs_f64());

    // Cost of the two per-admission O(mempool) steps, at the final mempool size.
    let t = Instant::now();
    let _ = node.storage.save_mempool(&node.mempool);
    let save = t.elapsed();
    let t = Instant::now();
    let bytes: usize = node.mempool.iter().map(|t| t.to_bytes().len()).sum();
    let sum = t.elapsed();
    let t = Instant::now();
    let probe = node.mempool[0].tx_hash();
    let _ = node.mempool.iter().any(|t| t.tx_hash() == probe && false);
    let hashes = t.elapsed();
    let t = Instant::now();
    let _ = node.csmt.clone();
    let clone = t.elapsed();
    println!("at mempool {}: save_mempool {:.2} ms | bytes sum {:.2} ms ({} B) | hash scan {:.2} ms | csmt.clone {:.3} ms",
        node.mempool.len(), save.as_secs_f64() * 1e3, sum.as_secs_f64() * 1e3, bytes, hashes.as_secs_f64() * 1e3, clone.as_secs_f64() * 1e3);

    let t = Instant::now();
    let mut block = node.build_proposal().await.expect("build");
    let build = t.elapsed();
    let n_in_block = block.transactions.len();
    let committed = block.clone(); // carries the (single) validator's commit signature
    block.validator_signatures.clear();
    // A second node with the same genesis that never saw these txs (empty signature cache):
    // its validation verifies all 1,500 signatures, in parallel.
    let dir2 = std::env::temp_dir().join(format!("vera_bench_pipeline2_{}", rand::random::<u64>()));
    let node2 = FullNode::load_or_init(&dir2, &cfg, None).unwrap();
    vera_blockchain::state_transition::clear_signature_cache();
    let t = Instant::now();
    node2.validate_proposal(&block).await.expect("validate on fresh node");
    let validate_fresh = t.elapsed();
    let threads = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
    println!("fresh node validate (signatures unseen, {} threads): {:.3} s", threads, validate_fresh.as_secs_f64());
    let _ = std::fs::remove_dir_all(&dir2);
    let t = Instant::now();
    node.validate_proposal(&block).await.expect("validate");
    let validate = t.elapsed();
    let t = Instant::now();
    node.apply_block(committed).await.expect("apply");
    let apply = t.elapsed();
    println!("block of {} tx: build_proposal {:.3} s | validate_proposal {:.3} s | apply_block {:.3} s",
        n_in_block, build.as_secs_f64(), validate.as_secs_f64(), apply.as_secs_f64());
    let t = Instant::now();
    node.storage.save_state(&node.csmt).unwrap();
    println!("save_state (done inside every apply_block): {:.3} s", t.elapsed().as_secs_f64());
    let t = Instant::now();
    let _c = node.csmt.clone();
    println!("csmt.clone (done per admission simulation and per validation): {:.3} ms", t.elapsed().as_secs_f64() * 1e3);
    let _ = std::fs::remove_dir_all(&dir);
}
