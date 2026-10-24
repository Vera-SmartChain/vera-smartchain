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
pub const MSG_TYPE_ADDR_HINT: u8      = 0x0C;
pub const MSG_TYPE_PEER_ANNOUNCE: u8  = 0x0D;
pub const MSG_TYPE_TM_PROPOSAL: u8    = 0x0E;
pub const MSG_TYPE_TM_VOTE: u8        = 0x0F;
pub const MSG_TYPE_TM_COMPACT_PROPOSAL: u8 = 0x10;
pub const MSG_TYPE_TM_PROPOSAL_REQUEST: u8 = 0x11;
pub const MSG_TYPE_TM_PROPOSAL_FULL: u8    = 0x12;
pub const MSG_TYPE_TM_PROPOSAL_TXS: u8     = 0x13;

/// Capability bit advertised in the handshake: the peer understands `AddrHint` and
/// `PeerAnnounce`. Nodes older than v0.2.5 drop the connection on any unknown payload,
/// so these messages are only ever sent to peers that advertise this bit.
pub const FEATURE_PEER_DISCOVERY: u32 = 1;
/// Capability bit: the peer runs the Tendermint engine (`TmProposal` / `TmVote`).
pub const FEATURE_TENDERMINT: u32 = 2;
/// Capability bit: the peer takes compact proposals (tx hashes instead of txs, rebuilt
/// from its mempool; full proposal on request) and does not need `BlockCommit` gossip
/// (validators decide by consensus; a node that falls behind catches up by sync).
pub const FEATURE_COMPACT_BLOCKS: u32 = 4;
/// Proposals with fewer txs are sent whole even to FEATURE_COMPACT_BLOCKS peers.
pub const COMPACT_PROPOSAL_MIN_TXS: usize = 256;

/// How old a validator address announcement may be before it is ignored.
pub const PEER_ANNOUNCE_MAX_AGE_SECS: u64 = 3600;

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
    /// Capability bits (FEATURE_*). Not covered by the signature: a forged value can
    /// only make us send discovery messages to a peer that then drops the connection.
    /// Absent (0) on nodes older than v0.2.5; old nodes ignore the unknown field.
    #[serde(default)]
    pub features: u32,
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
            features: FEATURE_PEER_DISCOVERY | FEATURE_TENDERMINT | FEATURE_COMPACT_BLOCKS,
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

/// Signed "validator X listens at ip:port" record (peer discovery).
/// Receivers accept it only when `node_pubkey` belongs to an ACTIVE validator of the
/// on-chain set, so the existing governance allowlist is the authorization list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerAnnounce {
    pub chain_id: String,
    pub node_pubkey: [u8; 32],
    pub addr: String,
    pub timestamp: u64,
    #[serde(with = "crate::account::serde_sig")]
    pub signature: [u8; 64],
}

impl PeerAnnounce {
    pub fn new(chain_id: &str, addr: std::net::SocketAddr, signing_key: &SigningKey) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let node_pubkey = signing_key.verifying_key().to_bytes();
        let addr = addr.to_string();
        let digest = Self::signing_digest(chain_id, &node_pubkey, &addr, timestamp);
        Self {
            chain_id: chain_id.to_string(),
            node_pubkey,
            addr,
            timestamp,
            signature: signing_key.sign(&digest).to_bytes(),
        }
    }

    pub fn signing_digest(chain_id: &str, pubkey: &[u8; 32], addr: &str, timestamp: u64) -> [u8; 32] {
        let mut hasher = Keccak::v256();
        hasher.update(b"VERA_P2P_PEER_ANNOUNCE_V1");
        hasher.update(&(chain_id.len() as u64).to_be_bytes());
        hasher.update(chain_id.as_bytes());
        hasher.update(pubkey);
        hasher.update(&(addr.len() as u64).to_be_bytes());
        hasher.update(addr.as_bytes());
        hasher.update(&timestamp.to_be_bytes());
        let mut out = [0u8; 32];
        hasher.finalize(&mut out);
        out
    }

    /// Checks chain, signature, address syntax and freshness. Validator-set membership
    /// is checked by the caller, which owns the chain state.
    pub fn verify(&self, expected_chain_id: &str, now: u64) -> Result<std::net::SocketAddr, String> {
        if self.chain_id != expected_chain_id {
            return Err(format!("announce for chain '{}', expected '{}'", self.chain_id, expected_chain_id));
        }
        if self.timestamp > now + 60 {
            return Err(format!("announce timestamp {} is in the future (now {})", self.timestamp, now));
        }
        if now.saturating_sub(self.timestamp) > PEER_ANNOUNCE_MAX_AGE_SECS {
            return Err(format!("announce is stale ({} s old)", now - self.timestamp));
        }
        let addr: std::net::SocketAddr = self.addr.parse()
            .map_err(|e| format!("invalid announce address '{}': {}", self.addr, e))?;
        if addr.port() == 0 || addr.ip().is_unspecified() || addr.ip().is_multicast() {
            return Err(format!("unusable announce address {}", addr));
        }
        let vk = VerifyingKey::from_bytes(&self.node_pubkey)
            .map_err(|e| format!("invalid announce pubkey: {}", e))?;
        let digest = Self::signing_digest(&self.chain_id, &self.node_pubkey, &self.addr, self.timestamp);
        vk.verify_strict(&digest, &Signature::from_bytes(&self.signature))
            .map_err(|e| format!("invalid announce signature: {}", e))?;
        Ok(addr)
    }
}

/// Tendermint ⟨PROPOSAL, height, round, block, valid_round⟩, signed by the proposer of
/// `round` (who may be re-proposing a block built in an earlier round: the block, its
/// header and its hash stay unchanged).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TmProposal {
    pub chain_id: String,
    pub height: u64,
    pub round: u64,
    pub valid_round: Option<u64>,
    pub block: Block,
    pub proposer_pubkey: [u8; 32],
    #[serde(with = "crate::account::serde_sig")]
    pub signature: [u8; 64],
}

/// A Tendermint proposal without the block body: `proposal.block` has no transactions
/// or receipts, and `tx_hashes` lists the tx hashes in block order (hex, 64 characters
/// per tx). The signature covers the block hash, which is the header hash, so it still
/// verifies; the receiver rebuilds the txs from its mempool and checks them against
/// `header.tx_root`, and recomputes the receipts when it executes the block.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TmCompactProposal {
    pub proposal: TmProposal,
    pub tx_hashes: String,
}

impl TmCompactProposal {
    pub fn from_full(p: &TmProposal) -> Self {
        let b = &p.block;
        let shell = Block {
            header: b.header.clone(),
            transactions: Vec::new(),
            receipts: Vec::new(),
            last_commit: b.last_commit.clone(),
            validator_signatures: b.validator_signatures.clone(),
            commit_round: b.commit_round,
            last_commit_round: b.last_commit_round,
        };
        let mut tx_hashes = String::with_capacity(b.transactions.len() * 64);
        for tx in &b.transactions {
            tx_hashes.push_str(&hex::encode(tx.tx_hash()));
        }
        Self {
            proposal: TmProposal {
                chain_id: p.chain_id.clone(),
                height: p.height,
                round: p.round,
                valid_round: p.valid_round,
                block: shell,
                proposer_pubkey: p.proposer_pubkey,
                signature: p.signature,
            },
            tx_hashes,
        }
    }

    pub fn hashes(&self) -> Result<Vec<[u8; 32]>, String> {
        decode_hashes(&self.tx_hashes)
    }
}

/// Hashes as one hex string (64 characters each), for compact messages.
pub fn encode_hashes(hashes: &[[u8; 32]]) -> String {
    let mut s = String::with_capacity(hashes.len() * 64);
    for h in hashes {
        s.push_str(&hex::encode(h));
    }
    s
}

pub fn decode_hashes(s: &str) -> Result<Vec<[u8; 32]>, String> {
    if s.len() % 64 != 0 {
        return Err("hash list length is not a multiple of 64".to_string());
    }
    (0..s.len() / 64).map(|i| {
        let mut h = [0u8; 32];
        hex::decode_to_slice(&s[i * 64..(i + 1) * 64], &mut h).map_err(|e| e.to_string())?;
        Ok(h)
    }).collect()
}

impl TmProposal {
    pub fn new(chain_id: &str, round: u64, valid_round: Option<u64>, block: Block, key: &SigningKey) -> Self {
        let height = block.header.height;
        let proposer_pubkey = key.verifying_key().to_bytes();
        let digest = Self::signing_digest(chain_id, height, round, valid_round, &block.hash(), &proposer_pubkey);
        Self {
            chain_id: chain_id.to_string(),
            height,
            round,
            valid_round,
            block,
            proposer_pubkey,
            signature: key.sign(&digest).to_bytes(),
        }
    }

    pub fn signing_digest(chain_id: &str, height: u64, round: u64, valid_round: Option<u64>, block_hash: &[u8; 32], pubkey: &[u8; 32]) -> [u8; 32] {
        let mut hasher = crate::chain_hash::ChainHasher::new();
        hasher.update(b"VERA_TM_PROPOSAL_V1");
        hasher.update(&(chain_id.len() as u64).to_le_bytes());
        hasher.update(chain_id.as_bytes());
        hasher.update(&height.to_le_bytes());
        hasher.update(&round.to_le_bytes());
        match valid_round {
            Some(vr) => {
                hasher.update(&[1u8]);
                hasher.update(&vr.to_le_bytes());
            }
            None => {
                hasher.update(&[0u8]);
            }
        }
        hasher.update(block_hash);
        hasher.update(pubkey);
        hasher.finalize()
    }

    pub fn verify(&self, expected_chain_id: &str) -> Result<(), String> {
        if self.chain_id != expected_chain_id {
            return Err(format!("proposal for chain '{}', expected '{}'", self.chain_id, expected_chain_id));
        }
        if self.height != self.block.header.height {
            return Err(format!("proposal height {} != block height {}", self.height, self.block.header.height));
        }
        if self.valid_round.map_or(false, |vr| vr >= self.round) {
            return Err("valid_round must be lower than round".to_string());
        }
        let vk = VerifyingKey::from_bytes(&self.proposer_pubkey).map_err(|e| format!("invalid proposer key: {}", e))?;
        let digest = Self::signing_digest(&self.chain_id, self.height, self.round, self.valid_round, &self.block.hash(), &self.proposer_pubkey);
        vk.verify_strict(&digest, &Signature::from_bytes(&self.signature))
            .map_err(|e| format!("invalid proposal signature: {}", e))
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

/// Maximum serialized size for SyncResponse payload (3 MiB) to fit within MAX_P2P_FRAME_SIZE (4 MiB)
pub const MAX_SYNC_RESPONSE_BYTES: usize = 3 * 1024 * 1024;

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

    /// Truncates the block list so that the complete P2PPayload::SyncResponse wire frame fits within max_bytes, always preserving at least 1 block
    pub fn truncate_to_byte_limit(&mut self, max_bytes: usize) {
        if self.blocks.len() <= 1 {
            return;
        }
        while self.blocks.len() > 1 {
            let frame_len = 1 + serde_json::to_vec(&P2PPayload::SyncResponse(self.clone()))
                .map(|v| v.len())
                .unwrap_or(0);
            if frame_len <= max_bytes {
                break;
            }
            self.blocks.pop();
        }
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
    /// "This is the IP I see you connecting from" — lets a node learn its public IP.
    AddrHint { ip: String },
    PeerAnnounce(PeerAnnounce),
    TmProposal(TmProposal),
    /// Tendermint prevote/precommit (`Vote` with its round; nil = zero block hash).
    TmVote(Vote),
    /// A `TmProposal` whose block carries no txs or receipts, plus the tx hashes.
    TmCompactProposal(TmCompactProposal),
    /// "Send me what I miss of the proposal of (height, round)": the txs whose hashes are
    /// in `missing` (hex, 64 characters each), or the full proposal when it is empty.
    TmProposalRequest { height: u64, round: u64, #[serde(default)] missing: String },
    /// Answer to a TmProposalRequest with `missing`: those txs of the proposal.
    TmProposalTxs { height: u64, round: u64, txs: Vec<Transaction> },
    /// Answer to `TmProposalRequest` (never turned into a compact proposal).
    TmProposalFull(TmProposal),
}

impl P2PPayload {
    /// Payloads that nodes older than v0.2.5 cannot decode (sending them drops the link).
    pub fn requires_peer_discovery(&self) -> bool {
        matches!(self, P2PPayload::AddrHint { .. } | P2PPayload::PeerAnnounce(_))
    }

    /// Capability a peer must advertise to receive this payload (0 = every peer).
    /// Older nodes drop the connection on payloads they cannot decode.
    /// Consensus traffic: sent ahead of transaction gossip on every connection.
    pub fn is_consensus(&self) -> bool {
        matches!(self,
            P2PPayload::TmProposal(_) | P2PPayload::TmVote(_) | P2PPayload::BlockCommit(_)
            | P2PPayload::BlockProposal(_) | P2PPayload::BftVote(_) | P2PPayload::MiniVote(_)
            | P2PPayload::TmCompactProposal(_) | P2PPayload::TmProposalRequest { .. } | P2PPayload::TmProposalFull(_)
            | P2PPayload::TmProposalTxs { .. })
    }

    /// The form of this payload a peer with `features` gets: compact proposals and no
    /// `BlockCommit` for FEATURE_COMPACT_BLOCKS peers, everything unchanged for others.
    pub fn adapt_for(self, features: u32) -> Option<P2PPayload> {
        if features & FEATURE_COMPACT_BLOCKS == 0 {
            return Some(self);
        }
        match self {
            // Small blocks go whole: they cost little to send, and their txs often arrived
            // at the proposer just before (gossiped on the normal queue, behind the
            // priority proposal), so a compact form would cost an extra round trip.
            P2PPayload::TmProposal(p) if p.block.transactions.len() >= COMPACT_PROPOSAL_MIN_TXS => {
                Some(P2PPayload::TmCompactProposal(TmCompactProposal::from_full(&p)))
            }
            P2PPayload::BlockCommit(_) => None,
            other => Some(other),
        }
    }

    pub fn required_feature(&self) -> u32 {
        match self {
            P2PPayload::AddrHint { .. } | P2PPayload::PeerAnnounce(_) => FEATURE_PEER_DISCOVERY,
            P2PPayload::TmProposal(_) | P2PPayload::TmVote(_) => FEATURE_TENDERMINT,
            P2PPayload::TmCompactProposal(_) | P2PPayload::TmProposalRequest { .. } | P2PPayload::TmProposalFull(_)
            | P2PPayload::TmProposalTxs { .. } => FEATURE_COMPACT_BLOCKS,
            _ => 0,
        }
    }
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
            P2PPayload::AddrHint { .. } => MSG_TYPE_ADDR_HINT,
            P2PPayload::PeerAnnounce(_) => MSG_TYPE_PEER_ANNOUNCE,
            P2PPayload::TmProposal(_) => MSG_TYPE_TM_PROPOSAL,
            P2PPayload::TmVote(_) => MSG_TYPE_TM_VOTE,
            P2PPayload::TmCompactProposal(_) => MSG_TYPE_TM_COMPACT_PROPOSAL,
            P2PPayload::TmProposalRequest { .. } => MSG_TYPE_TM_PROPOSAL_REQUEST,
            P2PPayload::TmProposalFull(_) => MSG_TYPE_TM_PROPOSAL_FULL,
            P2PPayload::TmProposalTxs { .. } => MSG_TYPE_TM_PROPOSAL_TXS,
        }
    }

    pub fn type_name(&self) -> &'static str {
        match self {
            P2PPayload::Handshake(_) => "Handshake",
            P2PPayload::HandshakeAck(_) => "HandshakeAck",
            P2PPayload::Ping { .. } => "Ping",
            P2PPayload::Pong { .. } => "Pong",
            P2PPayload::NewTransaction(_) => "NewTransaction",
            P2PPayload::BlockProposal(_) => "BlockProposal",
            P2PPayload::BftVote(_) => "BftVote",
            P2PPayload::MiniVote(_) => "MiniVote",
            P2PPayload::BlockCommit(_) => "BlockCommit",
            P2PPayload::SyncRequest(_) => "SyncRequest",
            P2PPayload::SyncResponse(_) => "SyncResponse",
            P2PPayload::AddrHint { .. } => "AddrHint",
            P2PPayload::PeerAnnounce(_) => "PeerAnnounce",
            P2PPayload::TmProposal(_) => "TmProposal",
            P2PPayload::TmVote(_) => "TmVote",
            P2PPayload::TmCompactProposal(_) => "TmCompactProposal",
            P2PPayload::TmProposalRequest { .. } => "TmProposalRequest",
            P2PPayload::TmProposalFull(_) => "TmProposalFull",
            P2PPayload::TmProposalTxs { .. } => "TmProposalTxs",
        }
    }
}
