//! Replays a copy of real testnet blocks on a fresh node with this code and requires every
//! header root to match. Run: REPLAY_DIR=<dir with testnet-genesis.json and blocks/>
//! [EXEC_V2_AT=<h>] cargo test --release --test replay_testnet -- --ignored --nocapture

use vera_blockchain::genesis::GenesisConfig;
use vera_blockchain::node::FullNode;
use vera_blockchain::storage::PersistentStorage;

#[tokio::test]
#[ignore]
async fn replay_testnet_blocks() {
    let dir = std::path::PathBuf::from(std::env::var("REPLAY_DIR").expect("REPLAY_DIR"));
    let mut cfg: GenesisConfig = serde_json::from_str(&std::fs::read_to_string(dir.join("testnet-genesis.json")).unwrap()).unwrap();
    if let Ok(h) = std::env::var("EXEC_V2_AT") {
        cfg.exec_v2_activation_height = Some(h.parse().unwrap());
    }
    let src = PersistentStorage::open(&dir).unwrap();
    let last = src.get_latest_block_height().unwrap().expect("latest height");

    let data = std::env::temp_dir().join(format!("vera_replay_{}", rand::random::<u64>()));
    let mut node = FullNode::load_or_init(&data, &cfg, None).unwrap();
    let genesis = src.load_block(0).unwrap().expect("block 0");
    assert_eq!(node.latest_block_hash, genesis.hash(), "genesis hash");
    println!("exec v2 activation: {:?}", node.exec_v2_activation);

    let t = std::time::Instant::now();
    let mut txs = 0;
    for h in 1..=last {
        let block = src.load_block(h).unwrap().unwrap_or_else(|| panic!("missing block {h}"));
        let (want_root, want_hash) = (block.header.state_root, block.hash());
        txs += block.transactions.len();
        let got_hash = node.apply_block(block).await.unwrap_or_else(|e| panic!("block {h}: {e}"));
        assert_eq!(got_hash, want_hash, "block hash at {h}");
        assert_eq!(node.csmt.root(), want_root, "state root at {h}");
    }
    println!("REPLAYED {} blocks, {} txs, final root 0x{} in {:.1} s", last, txs, hex::encode(node.csmt.root()), t.elapsed().as_secs_f64());
    let _ = std::fs::remove_dir_all(&data);
}
