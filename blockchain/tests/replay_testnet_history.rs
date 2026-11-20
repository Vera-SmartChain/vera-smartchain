//! Review harness (Claude-VPS): replays the live testnet history (genesis + every block,
//! dumped from the node RPC) through this build: validates and applies each block and checks
//! the state root in each header. Paths come from VERA_REPLAY_DIR. Ignored by default.

use std::io::BufRead;
use vera_blockchain::block::Block;
use vera_blockchain::genesis::GenesisConfig;
use vera_blockchain::node::FullNode;

#[tokio::test]
#[ignore]
async fn replay_live_testnet_history() {
    let dir = std::path::PathBuf::from(std::env::var("VERA_REPLAY_DIR").expect("VERA_REPLAY_DIR"));
    let cfg: GenesisConfig = serde_json::from_str(&std::fs::read_to_string(dir.join("genesis.json")).unwrap()).unwrap();
    let data = std::env::temp_dir().join(format!("vera_replay_{}", std::process::id()));
    let mut n = FullNode::load_or_init(&data, &cfg, None).unwrap();
    let f = std::fs::File::open(dir.join("blocks.jsonl")).unwrap();
    let (mut applied, mut validated, mut vfail) = (0u64, 0u64, Vec::new());
    for line in std::io::BufReader::new(f).lines() {
        let b: Block = serde_json::from_str(&line.unwrap()).unwrap();
        let h = b.header.height;
        if h == 0 {
            assert_eq!(n.csmt.root(), b.header.state_root, "genesis state root");
            continue;
        }
        match n.validate_proposal(&b).await {
            Ok(_) => validated += 1,
            Err(e) => vfail.push((h, e)),
        }
        let root = b.header.state_root;
        n.apply_block(b).await.unwrap_or_else(|e| panic!("apply #{h}: {e}"));
        assert_eq!(n.csmt.root(), root, "state root differs at #{h}");
        applied += 1;
    }
    println!("applied {applied} blocks, state roots identical; validate_proposal ok {validated}, failed {}", vfail.len());
    for (h, e) in vfail.iter().take(5) {
        println!("  validate #{h}: {e}");
    }
    let _ = std::fs::remove_dir_all(&data);
}
