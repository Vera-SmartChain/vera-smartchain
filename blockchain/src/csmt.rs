use std::collections::HashMap;
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TreeNode {
    Empty,
    Leaf {
        key: [u8; 32],
        value_hash: [u8; 32],
    },
    Internal {
        left: Box<TreeNode>,
        right: Box<TreeNode>,
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

mod serde_values_map {
    use std::collections::HashMap;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(map: &HashMap<[u8; 32], Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeSeq;
        let mut seq = serializer.serialize_seq(Some(map.len()))?;
        for (k, v) in map {
            let entry = (hex::encode(k), hex::encode(v));
            seq.serialize_element(&entry)?;
        }
        seq.end()
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<HashMap<[u8; 32], Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let list: Vec<(String, String)> = Vec::deserialize(deserializer)?;
        let mut map = HashMap::with_capacity(list.len());
        for (k_hex, v_hex) in list {
            let k_bytes = hex::decode(&k_hex).map_err(serde::de::Error::custom)?;
            let v_bytes = hex::decode(&v_hex).map_err(serde::de::Error::custom)?;
            if k_bytes.len() != 32 {
                return Err(serde::de::Error::custom("key must be 32 bytes"));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&k_bytes);
            map.insert(arr, v_bytes);
        }
        Ok(map)
    }
}

/// Compact Sparse Merkle Tree (CSMT) Jellyfish-style
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CSMT {
    root_node: TreeNode,
    #[serde(with = "serde_values_map")]
    values: HashMap<[u8; 32], Vec<u8>>,
}

impl CSMT {
    pub fn values(&self) -> &HashMap<[u8; 32], Vec<u8>> {
        &self.values
    }

    pub fn new() -> Self {
        Self {
            root_node: TreeNode::Empty,
            values: HashMap::new(),
        }
    }

    pub fn root(&self) -> [u8; 32] {
        self.root_node.hash()
    }

    pub fn get(&self, key: &[u8; 32]) -> Option<&Vec<u8>> {
        self.values.get(key)
    }

    pub fn insert(&mut self, key: [u8; 32], value: Vec<u8>) {
        let val_hash = crate::chain_hash::hash256(&value);
        self.values.insert(key, value);
        self.root_node = Self::insert_at(self.root_node.clone(), key, val_hash, 0);
    }

    fn insert_at(node: TreeNode, key: [u8; 32], val_hash: [u8; 32], depth: usize) -> TreeNode {
        match node {
            TreeNode::Empty => TreeNode::Leaf {
                key,
                value_hash: val_hash,
            },
            TreeNode::Leaf {
                key: existing_key,
                value_hash: existing_val_hash,
            } => {
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
                            TreeNode::Leaf {
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
                        left: Box::new(left),
                        right: Box::new(right),
                        hash,
                    }
                }
            }
            TreeNode::Internal { left, right, .. } => {
                let bit = get_bit(&key, depth);
                let (new_left, new_right) = if bit {
                    (*left, Self::insert_at(*right, key, val_hash, depth + 1))
                } else {
                    (Self::insert_at(*left, key, val_hash, depth + 1), *right)
                };

                let hash = hash_internal(&new_left.hash(), &new_right.hash());
                TreeNode::Internal {
                    left: Box::new(new_left),
                    right: Box::new(new_right),
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
        self.values.iter().map(|(k, v)| (*k, v.clone())).collect()
    }

    /// Deterministically reconstructs CSMT from key/value pairs
    pub fn from_key_values(entries: &[([u8; 32], Vec<u8>)]) -> Self {
        let mut tree = Self::new();
        for (k, v) in entries {
            tree.insert(*k, v.clone());
        }
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
