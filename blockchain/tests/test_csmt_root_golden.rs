//! Golden state root: the CSMT root for a fixed set of inserts and updates must never
//! change (consensus depends on it). The expected value was produced by the code before
//! the v0.2.7 insert optimization (no full-tree clone per insert).
use vera_blockchain::chain_hash::hash256;
use vera_blockchain::csmt::CSMT;

fn dataset() -> Vec<([u8; 32], Vec<u8>)> {
    let mut v = Vec::new();
    for i in 0u64..3000 {
        v.push((hash256(&i.to_le_bytes()), format!("account-{}", i).into_bytes()));
    }
    // updates of existing keys
    for i in (0u64..3000).step_by(7) {
        v.push((hash256(&i.to_le_bytes()), format!("updated-{}", i * 3).into_bytes()));
    }
    v
}

fn root_in_order(entries: &[([u8; 32], Vec<u8>)]) -> String {
    let mut t = CSMT::new();
    for (k, val) in entries {
        t.insert(*k, val.clone());
    }
    hex::encode(t.root())
}

#[test]
fn csmt_root_is_unchanged() {
    let d = dataset();
    let forward = root_in_order(&d);
    // Same final contents, different insertion order (updates applied last per key).
    let mut finals = std::collections::BTreeMap::new();
    for (k, v) in &d {
        finals.insert(*k, v.clone());
    }
    let mut rev: Vec<_> = finals.into_iter().collect();
    rev.reverse();
    let reverse = root_in_order(&rev);
    println!("golden root: {}", forward);
    assert_eq!(forward, reverse, "root must not depend on insertion order");
    if let Ok(expected) = std::env::var("CSMT_GOLDEN") {
        assert_eq!(forward, expected, "state root changed!");
    } else {
        assert_eq!(forward, GOLDEN);
    }
}

const GOLDEN: &str = "525c77400d765014ef8d03184b96e40c6b37f57fa4f5e87fbdce0b19d51c31ac";
