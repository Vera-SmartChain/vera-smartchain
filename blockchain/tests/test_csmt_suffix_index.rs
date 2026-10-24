//! The 20-byte suffix index (RPC EVM-address lookup) finds exactly the keys a full scan
//! would, also across clones and compaction.
use vera_blockchain::chain_hash::hash256;
use vera_blockchain::csmt::CSMT;

#[test]
fn suffix_index_matches_full_scan() {
    let mut t = CSMT::new();
    let mut keys = Vec::new();
    for i in 0u64..2000 {
        let k = hash256(&i.to_le_bytes());
        t.insert(k, vec![i as u8]);
        keys.push(k);
    }
    // a key sharing the suffix of keys[5] (different first 12 bytes)
    let mut twin = keys[5];
    twin[0] ^= 0xFF;
    t.compact();
    let mut clone = t.clone();
    clone.insert(twin, vec![7]);
    clone.insert(keys[9], vec![9, 9]); // update, not a new key
    for k in keys.iter().chain(std::iter::once(&twin)) {
        let mut sfx = [0u8; 20];
        sfx.copy_from_slice(&k[12..32]);
        let mut scan: Vec<[u8; 32]> = clone.iter().map(|(k, _)| *k).filter(|kk| kk[12..32] == k[12..32]).collect();
        let mut idx = clone.keys_with_suffix20(&sfx);
        scan.sort();
        idx.sort();
        assert_eq!(idx, scan, "index must equal a full scan");
    }
    // the original (pre-clone) state does not see the clone's new key
    let mut sfx = [0u8; 20];
    sfx.copy_from_slice(&twin[12..32]);
    assert_eq!(t.keys_with_suffix20(&sfx), vec![keys[5]]);
    clone.compact();
    assert_eq!(clone.keys_with_suffix20(&sfx).len(), 2);
}
