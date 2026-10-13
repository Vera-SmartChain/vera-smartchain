use serde::{Deserialize, Serialize};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey, Verifier};
use tiny_keccak::{Hasher, Keccak};
use crate::block::Block;
use crate::consensus::Vote;
use crate::transaction::Transaction;

/// P2P Wire Protocol Message Types (1 byte in binary header)
pub const MSG_TYPE_HANDSHAKE: u8      = 0x01;
pub const MSG_TYPE_HANDSHAKE_ACK: u8  = 0x02;
pub const MSG_TYPE_PING: u8           = 0x03;
pub const MSG_TYPE_PONG: u8           = 0x04;
pub const MSG_TYPE_NEW_TX: u8         = 0x05;
pub const MSG_TYPE_BLOCK_PROPOSAL: u8 = 0x06;
pub const MSG_TYPE_BFT_VOTE: u8       = 0x07;
pub const MSG_TYPE_MINI_VOTE: u8      = 0x08;
pub const MSG_TYPE_BLOCK_COMMIT: u8   = 0x09;
pub const MSG_TYPE_SYNC_REQUEST: u8   = 0x0A;
pub const MSG_TYPE_SYNC_RESPONSE: u8  = 0x0B;

/// Initial Cryptographic Handshake (mutual peer authentication exchange)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandshakeMsg {
    pub chain_id: String,
    pub node_pubkey: [u8; 32],
    pub height: u64,
    pub timestamp: u64,
    pub nonce: u64,
    #[serde(with = "crate::account::serde_sig")]
    pub signature: [u8; 64],
}

impl HandshakeMsg {
    pub fn new(chain_id: &str, height: u64, signing_key: &SigningKey) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let nonce = rand::random::<u64>();

        let node_pubkey = signing_key.verifying_key().to_bytes();
        let digest = Self::signing_digest(chain_id, &node_pubkey, height, timestamp, nonce);
        let sig = signing_key.sign(&digest);

        Self {
            chain_id: chain_id.to_string(),
            node_pubkey,
            height,
            timestamp,
            nonce,
            signature: sig.to_bytes(),
        }
    }

    pub fn signing_digest(chain_id: &str, pubkey: &[u8; 32], height: u64, timestamp: u64, nonce: u64) -> [u8; 32] {
        let mut hasher = Keccak::v256();
        hasher.update(b"VERA_P2P_HANDSHAKE_V1");
        hasher.update(chain_id.as_bytes());
        hasher.update(pubkey);
        hasher.update(&height.to_be_bytes());
        hasher.update(&timestamp.to_be_bytes());
        hasher.update(&nonce.to_be_bytes());
        let mut out = [0u8; 32];
        hasher.finalize(&mut out);
        out
    }

    pub fn verify(&self, expected_chain_id: &str, max_time_skew_secs: u64) -> Result<(), String> {
        if self.chain_id != expected_chain_id {
            return Err(format!(
                "Network incompatibility: peer belongs to chain '{}', expected '{}'",
                self.chain_id, expected_chain_id
            ));
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let diff = if self.timestamp > now {
            self.timestamp - now
        } else {
            now - self.timestamp
        };

        if diff > max_time_skew_secs {
            return Err(format!(
                "Excessive clock skew in handshake: {}s (max allowed: {}s)",
                diff, max_time_skew_secs
            ));
        }

        let vk = VerifyingKey::from_bytes(&self.node_pubkey)
            .map_err(|e| format!("Invalid peer public key: {}", e))?;
        let sig = Signature::from_bytes(&self.signature);
        let digest = Self::signing_digest(&self.chain_id, &self.node_pubkey, self.height, self.timestamp, self.nonce);

        vk.verify(&digest, &sig)
            .map_err(|e| format!("Invalid handshake signature: {}", e))
    }
}

/// Lightweight Community Mini-Validator Vote (VERA DePIN)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MiniValidatorVote {
    pub chain_id: String,
    pub height: u64,
    pub block_hash: [u8; 32],
    pub validator_pubkey: [u8; 32],
    #[serde(with = "crate::account::serde_sig")]
    pub signature: [u8; 64],
}

impl MiniValidatorVote {
    pub fn new(
        chain_id: &str,
        height: u64,
        block_hash: [u8; 32],
        signing_key: &SigningKey,
    ) -> Self {
        let validator_pubkey = signing_key.verifying_key().to_bytes();
        let digest = Self::signing_digest(chain_id, height, &block_hash, &validator_pubkey);
        let sig = signing_key.sign(&digest);

        Self {
            chain_id: chain_id.to_string(),
            height,
            block_hash,
            validator_pubkey,
            signature: sig.to_bytes(),
        }
    }

    pub fn signing_digest(
        chain_id: &str,
        height: u64,
        block_hash: &[u8; 32],
        pubkey: &[u8; 32],
    ) -> [u8; 32] {
        let mut hasher = Keccak::v256();
        hasher.update(b"VERA_MINI_VALIDATOR_VOTE_V1");
        hasher.update(chain_id.as_bytes());
        hasher.update(&height.to_be_bytes());
        hasher.update(block_hash);
        hasher.update(pubkey);
        let mut out = [0u8; 32];
        hasher.finalize(&mut out);
        out
    }

    pub fn verify(&self, expected_chain_id: &str) -> Result<(), String> {
        if self.chain_id != expected_chain_id {
            return Err("Vote Chain ID differs from node".to_string());
        }
        let vk = VerifyingKey::from_bytes(&self.validator_pubkey)
            .map_err(|e| format!("Invalid mini-validator public key: {}", e))?;
        let sig = Signature::from_bytes(&self.signature);
        let digest = Self::signing_digest(&self.chain_id, self.height, &self.block_hash, &self.validator_pubkey);
        vk.verify(&digest, &sig)
            .map_err(|e| format!("Mini-validator vote has invalid signature: {}", e))
    }
}

/// Maximum blocks per sync request (RAM exhaustion attack prevention)
pub const MAX_SYNC_BLOCKS_PER_REQUEST: u32 = 100;

/// History Sync Request
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncRequest {
    pub from_height: u64,
    pub max_blocks: u32,
}

impl SyncRequest {
    pub fn new(from_height: u64, max_blocks: u32) -> Self {
        Self {
            from_height,
            max_blocks: max_blocks.min(MAX_SYNC_BLOCKS_PER_REQUEST),
        }
    }

    pub fn bounded_max_blocks(&self) -> u32 {
        self.max_blocks.min(MAX_SYNC_BLOCKS_PER_REQUEST)
    }
}

/// History Sync Response
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncResponse {
    pub blocks: Vec<Block>,
}

impl SyncResponse {
    pub fn new(mut blocks: Vec<Block>) -> Self {
        if blocks.len() > MAX_SYNC_BLOCKS_PER_REQUEST as usize {
            blocks.truncate(MAX_SYNC_BLOCKS_PER_REQUEST as usize);
        }
        Self { blocks }
    }
}

/// General P2P Protocol Message
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum P2PPayload {
    Handshake(HandshakeMsg),
    HandshakeAck(HandshakeMsg),
    Ping { nonce: u64 },
    Pong { nonce: u64, height: u64 },
    NewTransaction(Transaction),
    BlockProposal(Block),
    BftVote(Vote),
    MiniVote(MiniValidatorVote),
    BlockCommit(Block),
    SyncRequest(SyncRequest),
    SyncResponse(SyncResponse),
}

impl P2PPayload {
    pub fn msg_type(&self) -> u8 {
        match self {
            P2PPayload::Handshake(_) => MSG_TYPE_HANDSHAKE,
            P2PPayload::HandshakeAck(_) => MSG_TYPE_HANDSHAKE_ACK,
            P2PPayload::Ping { .. } => MSG_TYPE_PING,
            P2PPayload::Pong { .. } => MSG_TYPE_PONG,
            P2PPayload::NewTransaction(_) => MSG_TYPE_NEW_TX,
            P2PPayload::BlockProposal(_) => MSG_TYPE_BLOCK_PROPOSAL,
            P2PPayload::BftVote(_) => MSG_TYPE_BFT_VOTE,
            P2PPayload::MiniVote(_) => MSG_TYPE_MINI_VOTE,
            P2PPayload::BlockCommit(_) => MSG_TYPE_BLOCK_COMMIT,
            P2PPayload::SyncRequest(_) => MSG_TYPE_SYNC_REQUEST,
            P2PPayload::SyncResponse(_) => MSG_TYPE_SYNC_RESPONSE,
        }
    }
}
