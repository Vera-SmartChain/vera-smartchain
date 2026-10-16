use serde::{Deserialize, Serialize};
use crate::account::{Address, ExecutionReceipt};
use crate::transaction::Transaction;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockHeader {
    pub height: u64,
    pub prev_hash: [u8; 32],
    pub timestamp: u64,
    pub state_root: [u8; 32],
    pub tx_root: [u8; 32],
    pub receipts_root: [u8; 32],
    pub proposer: Address,
    #[serde(default)]
    pub last_commit_hash: [u8; 32],
}

impl BlockHeader {
    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = crate::chain_hash::ChainHasher::new();
        hasher.update(b"VERA_BLOCK_HEADER_V2");
        hasher.update(&self.height.to_le_bytes());
        hasher.update(&self.prev_hash);
        hasher.update(&self.timestamp.to_le_bytes());
        hasher.update(&self.state_root);
        hasher.update(&self.tx_root);
        hasher.update(&self.receipts_root);
        hasher.update(&self.proposer);
        hasher.update(&self.last_commit_hash);
        hasher.finalize()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorCommit {
    pub validator_pubkey: [u8; 32],
    #[serde(with = "crate::account::serde_sig")]
    pub signature: [u8; 64],
}

impl ValidatorCommit {
    pub fn new(validator_pubkey: [u8; 32], signature: [u8; 64]) -> Self {
        Self { validator_pubkey, signature }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<Transaction>,
    pub receipts: Vec<ExecutionReceipt>,
    #[serde(default)]
    pub last_commit: Vec<ValidatorCommit>,
    pub validator_signatures: Vec<ValidatorCommit>,
}

impl Block {
    pub fn new(
        header: BlockHeader,
        transactions: Vec<Transaction>,
        receipts: Vec<ExecutionReceipt>,
    ) -> Self {
        Self {
            header,
            transactions,
            receipts,
            last_commit: Vec::new(),
            validator_signatures: Vec::new(),
        }
    }

    pub fn canonicalize_commits(commits: &mut Vec<ValidatorCommit>) {
        commits.sort_by(|a, b| a.validator_pubkey.cmp(&b.validator_pubkey));
        commits.dedup_by(|a, b| a.validator_pubkey == b.validator_pubkey);
    }

    pub fn compute_commits_root(commits: &[ValidatorCommit]) -> [u8; 32] {
        let mut sorted = commits.to_vec();
        Self::canonicalize_commits(&mut sorted);
        if sorted.is_empty() {
            return [0u8; 32];
        }
        let hashes: Vec<[u8; 32]> = sorted
            .iter()
            .map(|c| {
                let mut hasher = crate::chain_hash::ChainHasher::new();
                hasher.update(b"COMMIT_SIGNATURE");
                hasher.update(&c.validator_pubkey);
                hasher.update(&c.signature);
                hasher.finalize()
            })
            .collect();
        Self::merkle_root_of_hashes(&hashes)
    }

    pub fn hash(&self) -> [u8; 32] {
        self.header.hash()
    }

    pub fn compute_tx_root(transactions: &[Transaction]) -> [u8; 32] {
        if transactions.is_empty() {
            return [0u8; 32];
        }
        let hashes: Vec<[u8; 32]> = transactions.iter().map(|tx| tx.tx_hash()).collect();
        Self::merkle_root_of_hashes(&hashes)
    }

    pub fn compute_receipts_root(receipts: &[ExecutionReceipt]) -> [u8; 32] {
        if receipts.is_empty() {
            return [0u8; 32];
        }
        let hashes: Vec<[u8; 32]> = receipts.iter().map(|r| r.hash()).collect();
        Self::merkle_root_of_hashes(&hashes)
    }

    fn merkle_root_of_hashes(leaves: &[[u8; 32]]) -> [u8; 32] {
        if leaves.is_empty() {
            return [0u8; 32];
        }
        let mut current_layer: Vec<[u8; 32]> = leaves.to_vec();

        while current_layer.len() > 1 {
            let mut next_layer = Vec::with_capacity((current_layer.len() + 1) / 2);
            for chunk in current_layer.chunks(2) {
                let left = chunk[0];
                let right = if chunk.len() > 1 { chunk[1] } else { left };
                let mut hasher = crate::chain_hash::ChainHasher::new();
                hasher.update(b"MERKLE_NODE");
                hasher.update(&left);
                hasher.update(&right);
                next_layer.push(hasher.finalize());
            }
            current_layer = next_layer;
        }

        current_layer[0]
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("Failed to serialize Block")
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        serde_json::from_slice(bytes).map_err(|e| format!("Failed to deserialize Block: {}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_merkle_roots() {
        let empty_root = Block::compute_tx_root(&[]);
        assert_eq!(empty_root, [0u8; 32]);

        let h1 = [1u8; 32];
        let h2 = [2u8; 32];
        let root = Block::merkle_root_of_hashes(&[h1, h2]);
        assert_ne!(root, [0u8; 32]);
    }
}
