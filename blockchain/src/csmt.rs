use std::collections::HashMap;
use std::sync::Arc;
use serde::{Deserialize, Serialize};

pub const EMPTY_HASH: [u8; 32] = [0u8; 32];

fn hash_leaf(key: &[u8; 32], value_hash: &[u8; 32]) -> [u8; 32] {
    let mut hasher = crate::chain_hash::ChainHasher::new();
    hasher.update(b"LEAF");
    hasher.update(key);
    hasher.update(value_hash);
    hasher.finalize()
}

fn hash_internal(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = crate::chain_hash::ChainHasher::new();
    hasher.update(b"INTERNAL");
    hasher.update(left);
    hasher.update(right);
    hasher.finalize()
}

fn get_bit(key: &[u8; 32], depth: usize) -> bool {
    if depth >= 256 {
        return false;
    }
    let byte = key[depth / 8];
    let bit_idx = 7 - (depth % 8);
    ((byte >> bit_idx) & 1) == 1
}

/// Tree node. Children are shared (`Arc`), so cloning a whole CSMT is O(1) and an insert
/// copies only the nodes on its path (persistent / copy-on-write tree). Hashes and
/// shape are exactly the same as with the former `Box` children.
#[derive(Debug, Clone)]
pub enum TreeNode {
    Empty,
    Leaf {
        key: [u8; 32],
        value_hash: [u8; 32],
    },
    Internal {
        left: Arc<TreeNode>,
        right: Arc<TreeNode>,
        hash: [u8; 32],
    },
}

impl TreeNode {
    pub fn hash(&self) -> [u8; 32] {
        match self {
            TreeNode::Empty => EMPTY_HASH,
            TreeNode::Leaf { key, value_hash } => hash_leaf(key, value_hash),
            TreeNode::Internal { hash, .. } => *hash,
        }
    }
}

/// Cryptographic proof of inclusion or non-existence
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleProof {
    pub key: [u8; 32],
    pub value_hash: Option<[u8; 32]>,
    /// Siblings along the path: (bit_direction, sibling_hash)
    pub siblings: Vec<(bool, [u8; 32])>,
    /// If non-existence proof, the colliding existing leaf (if any)
    pub non_existence_leaf: Option<([u8; 32], [u8; 32])>,
}

/// Compact Sparse Merkle Tree (CSMT) Jellyfish-style.
///
/// Values live in a shared `base` map plus a private `delta` of changes since the last
/// `compact`, so `clone()` is O(changes) instead of O(accounts): mempool admission and
/// block validation simulate on clones of the whole state.
#[derive(Debug, Clone)]
pub struct CSMT {
    root_node: TreeNode,
    base: Arc<HashMap<[u8; 32], Vec<u8>>>,
    delta: HashMap<[u8; 32], Vec<u8>>,
    /// Keys by their last 20 bytes (EVM-style address lookup in the RPC, which used to scan
    /// every account). Same base/delta sharing as the values. Not used by consensus.
    suffix_base: Arc<HashMap<[u8; 20], Vec<[u8; 32]>>>,
    suffix_delta: HashMap<[u8; 20], Vec<[u8; 32]>>,
}

fn suffix20(key: &[u8; 32]) -> [u8; 20] {
    let mut s = [0u8; 20];
    s.copy_from_slice(&key[12..32]);
    s
}

impl CSMT {
    pub fn new() -> Self {
        Self {
            root_node: TreeNode::Empty,
            base: Arc::new(HashMap::new()),
            delta: HashMap::new(),
            suffix_base: Arc::new(HashMap::new()),
            suffix_delta: HashMap::new(),
        }
    }

    pub fn root(&self) -> [u8; 32] {
        self.root_node.hash()
    }

    pub fn get(&self, key: &[u8; 32]) -> Option<&Vec<u8>> {
        self.delta.get(key).or_else(|| self.base.get(key))
    }

    /// Number of stored keys.
    pub fn len(&self) -> usize {
        self.base.len() + self.delta.keys().filter(|k| !self.base.contains_key(*k)).count()
    }

    /// All (key, value) pairs; changed values override the shared base.
    pub fn iter(&self) -> impl Iterator<Item = (&[u8; 32], &Vec<u8>)> {
        self.delta.iter().chain(self.base.iter().filter(move |(k, _)| !self.delta.contains_key(*k)))
    }

    pub fn insert(&mut self, key: [u8; 32], value: Vec<u8>) {
        let val_hash = crate::chain_hash::hash256(&value);
        if self.get(&key).is_none() {
            self.suffix_delta.entry(suffix20(&key)).or_default().push(key);
        }
        self.delta.insert(key, value);
        self.root_node = Self::insert_at(&self.root_node, key, val_hash, 0);
    }

    /// Keys changed since the last `compact` (with their current values).
    pub fn delta_entries(&self) -> Vec<([u8; 32], Vec<u8>)> {
        let mut v: Vec<_> = self.delta.iter().map(|(k, val)| (*k, val.clone())).collect();
        v.sort_by(|a, b| a.0.cmp(&b.0));
        v
    }

    /// Folds `delta` into `base` when no clone shares the base any more (O(changes)).
    /// Call after replacing the canonical state; a no-op while clones are alive.
    pub fn compact(&mut self) {
        if !self.delta.is_empty() {
            if let Some(base) = Arc::get_mut(&mut self.base) {
                base.extend(self.delta.drain());
            }
        }
        if !self.suffix_delta.is_empty() {
            if let Some(idx) = Arc::get_mut(&mut self.suffix_base) {
                for (suffix, keys) in self.suffix_delta.drain() {
                    idx.entry(suffix).or_default().extend(keys);
                }
            }
        }
    }

    /// Keys whose last 20 bytes are `suffix`, in insertion order (RPC address lookup).
    pub fn keys_with_suffix20(&self, suffix: &[u8; 20]) -> Vec<[u8; 32]> {
        let mut out: Vec<[u8; 32]> = self.suffix_base.get(suffix).cloned().unwrap_or_default();
        if let Some(more) = self.suffix_delta.get(suffix) {
            out.extend(more.iter().copied());
        }
        out
    }

    /// Returns the subtree with `key` set to `val_hash`, sharing every untouched subtree.
    fn insert_at(node: &TreeNode, key: [u8; 32], val_hash: [u8; 32], depth: usize) -> TreeNode {
        match node {
            TreeNode::Empty => TreeNode::Leaf {
                key,
                value_hash: val_hash,
            },
            TreeNode::Leaf {
                key: existing_key,
                value_hash: existing_val_hash,
            } => {
                let (existing_key, existing_val_hash) = (*existing_key, *existing_val_hash);
                if existing_key == key {
                    // Update existing key value
                    TreeNode::Leaf {
                        key,
                        value_hash: val_hash,
                    }
                } else {
                    // Prefix collision: unfolds into Internal nodes until bits diverge
                    let bit_existing = get_bit(&existing_key, depth);
                    let bit_new = get_bit(&key, depth);

                    let (left, right) = if bit_existing == bit_new {
                        let sub = Self::insert_at(
                            &TreeNode::Leaf {
                                key: existing_key,
                                value_hash: existing_val_hash,
                            },
                            key,
                            val_hash,
                            depth + 1,
                        );
                        if bit_existing {
                            (TreeNode::Empty, sub)
                        } else {
                            (sub, TreeNode::Empty)
                        }
                    } else if bit_new {
                        (
                            TreeNode::Leaf {
                                key: existing_key,
                                value_hash: existing_val_hash,
                            },
                            TreeNode::Leaf {
                                key,
                                value_hash: val_hash,
                            },
                        )
                    } else {
                        (
                            TreeNode::Leaf {
                                key,
                                value_hash: val_hash,
                            },
                            TreeNode::Leaf {
                                key: existing_key,
                                value_hash: existing_val_hash,
                            },
                        )
                    };

                    let hash = hash_internal(&left.hash(), &right.hash());
                    TreeNode::Internal {
                        left: Arc::new(left),
                        right: Arc::new(right),
                        hash,
                    }
                }
            }
            TreeNode::Internal { left, right, .. } => {
                let bit = get_bit(&key, depth);
                let (new_left, new_right) = if bit {
                    (Arc::clone(left), Arc::new(Self::insert_at(right, key, val_hash, depth + 1)))
                } else {
                    (Arc::new(Self::insert_at(left, key, val_hash, depth + 1)), Arc::clone(right))
                };

                let hash = hash_internal(&new_left.hash(), &new_right.hash());
                TreeNode::Internal {
                    left: new_left,
                    right: new_right,
                    hash,
                }
            }
        }
    }

    /// Generates inclusion proof in O(log N)
    pub fn proof_of_inclusion(&self, key: &[u8; 32]) -> Result<MerkleProof, String> {
        let mut siblings = Vec::new();
        let mut current = &self.root_node;
        let mut depth = 0;

        while let TreeNode::Internal { left, right, .. } = current {
            let bit = get_bit(key, depth);
            if bit {
                siblings.push((true, left.hash()));
                current = right;
            } else {
                siblings.push((false, right.hash()));
                current = left;
            }
            depth += 1;
        }

        match current {
            TreeNode::Leaf {
                key: k,
                value_hash: vh,
            } if k == key => Ok(MerkleProof {
                key: *key,
                value_hash: Some(*vh),
                siblings,
                non_existence_leaf: None,
            }),
            _ => Err("Key not found for inclusion proof".to_string()),
        }
    }

    /// Generates non-existence proof (formal anti-replay)
    pub fn proof_of_non_existence(&self, key: &[u8; 32]) -> Result<MerkleProof, String> {
        let mut siblings = Vec::new();
        let mut current = &self.root_node;
        let mut depth = 0;

        while let TreeNode::Internal { left, right, .. } = current {
            let bit = get_bit(key, depth);
            if bit {
                siblings.push((true, left.hash()));
                current = right;
            } else {
                siblings.push((false, right.hash()));
                current = left;
            }
            depth += 1;
        }

        match current {
            TreeNode::Empty => Ok(MerkleProof {
                key: *key,
                value_hash: None,
                siblings,
                non_existence_leaf: None,
            }),
            TreeNode::Leaf {
                key: k,
                value_hash: vh,
            } if k != key => Ok(MerkleProof {
                key: *key,
                value_hash: None,
                siblings,
                non_existence_leaf: Some((*k, *vh)),
            }),
            _ => Err("Key exists in tree (cannot prove non-existence)".to_string()),
        }
    }

    /// Mathematically verifies proof against an expected root
    pub fn verify_proof(root: &[u8; 32], proof: &MerkleProof) -> bool {
        let mut current_hash = match proof.value_hash {
            Some(vh) => hash_leaf(&proof.key, &vh),
            None => match proof.non_existence_leaf {
                Some((other_k, other_vh)) => hash_leaf(&other_k, &other_vh),
                None => EMPTY_HASH,
            },
        };

        for (direction_is_right, sibling_hash) in proof.siblings.iter().rev() {
            current_hash = if *direction_is_right {
                hash_internal(sibling_hash, &current_hash)
            } else {
                hash_internal(&current_hash, sibling_hash)
            };
        }

        &current_hash == root
    }

    /// Returns all stored key/value pairs
    pub fn to_key_values(&self) -> Vec<([u8; 32], Vec<u8>)> {
        self.iter().map(|(k, v)| (*k, v.clone())).collect()
    }

    /// Deterministically reconstructs CSMT from key/value pairs
    pub fn from_key_values(entries: &[([u8; 32], Vec<u8>)]) -> Self {
        let mut tree = Self::new();
        for (k, v) in entries {
            tree.insert(*k, v.clone());
        }
        tree.compact();
        tree
    }
}

impl Default for CSMT {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_csmt_inclusion_and_non_existence() {
        let mut tree = CSMT::new();
        assert_eq!(tree.root(), EMPTY_HASH);

        let key1 = crate::chain_hash::hash256(b"account_alice");
        let val1 = b"balance=1000,nonce=0".to_vec();

        let key2 = crate::chain_hash::hash256(b"account_bob");
        let val2 = b"balance=500,nonce=1".to_vec();

        let key_absent = crate::chain_hash::hash256(b"account_eve");

        tree.insert(key1, val1.clone());
        tree.insert(key2, val2.clone());

        let root = tree.root();
        assert_ne!(root, EMPTY_HASH);

        // 1. Alice inclusion proof
        let proof1 = tree.proof_of_inclusion(&key1).expect("Alice proof");
        assert!(CSMT::verify_proof(&root, &proof1));

        // 2. Bob inclusion proof
        let proof2 = tree.proof_of_inclusion(&key2).expect("Bob proof");
        assert!(CSMT::verify_proof(&root, &proof2));

        // 3. Eve non-existence proof
        let proof_eve = tree.proof_of_non_existence(&key_absent).expect("Eve proof");
        assert!(CSMT::verify_proof(&root, &proof_eve));

        // 4. Forged proof must fail
        let mut fake_proof = proof1.clone();
        fake_proof.value_hash = Some([0xFF; 32]);
        assert!(!CSMT::verify_proof(&root, &fake_proof));
    }
}
