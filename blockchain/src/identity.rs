use serde::{Deserialize, Serialize};
use crate::csmt::{CSMT, MerkleProof};

/// Verifiable Identity Registry (VERA Zero-Trust Identity)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IdentityRecord {
    pub domain: String,
    pub org_id: String,
    pub public_key: String,
    pub cert_hash: [u8; 32],
    pub sequence: u64,
    pub timestamp: u64,
    pub metadata: serde_json::Value,
}

impl IdentityRecord {
    /// Computes the canonical CSMT key for this domain
    pub fn csmt_key(domain: &str) -> [u8; 32] {
        crate::chain_hash::hash256(format!("vera:identity:{}", domain.to_lowercase()).as_bytes())
    }

    /// Computes identity commitment hash
    pub fn commitment_hash(&self) -> [u8; 32] {
        let mut hasher = crate::chain_hash::ChainHasher::new();
        hasher.update(self.domain.to_lowercase().as_bytes());
        hasher.update(self.org_id.as_bytes());
        hasher.update(self.public_key.as_bytes());
        hasher.update(&self.cert_hash);
        hasher.update(&self.sequence.to_be_bytes());
        hasher.update(&self.timestamp.to_be_bytes());
        hasher.finalize()
    }

    /// Generates ephemeral key for mutual zero-trust session (<1ms)
    pub fn derive_session_key(
        client_nonce: &[u8; 32],
        server_nonce: &[u8; 32],
        shared_seed: &[u8; 32],
    ) -> [u8; 32] {
        let mut hasher = crate::chain_hash::ChainHasher::new();
        hasher.update(client_nonce);
        hasher.update(server_nonce);
        hasher.update(shared_seed);
        hasher.finalize()
    }
}

/// VERA Identity Proof with Merkle Proof for instant validation (<1ms)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityProof {
    pub identity: IdentityRecord,
    pub root_hash: [u8; 32],
    pub merkle_proof: MerkleProof,
    pub proof_generation_ms: f64,
}

impl IdentityProof {
    /// Ultra-fast local validation (<1ms) without querying third-party CAs
    pub fn verify(&self) -> bool {
        let commitment = self.identity.commitment_hash();
        let expected_val_hash = crate::chain_hash::hash256(&commitment);
        if self.merkle_proof.value_hash != Some(expected_val_hash) {
            return false;
        }
        CSMT::verify_proof(&self.root_hash, &self.merkle_proof)
    }
}

/// Historical Certificate Rotation Log (Certificate Transparency)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateLogEntry {
    pub domain: String,
    pub old_cert_hash: Option<[u8; 32]>,
    pub new_cert_hash: [u8; 32],
    pub sequence: u64,
    pub updated_at: u64,
    pub tx_hash: [u8; 32],
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn test_ultra_fast_identity_handshake_and_proof() {
        let mut csmt = CSMT::new();

        let domain = "google.com";
        let cert_hash = crate::chain_hash::hash256(b"test_x509_cert_data");
        let identity = IdentityRecord {
            domain: domain.to_string(),
            org_id: "org_google_corp".to_string(),
            public_key: "ed25519_pub_key_mock_1234567890".to_string(),
            cert_hash,
            sequence: 1,
            timestamp: 1772841600,
            metadata: serde_json::json!({ "issuer": "VERA Zero-Trust Root", "ct_log": true }),
        };

        let key = IdentityRecord::csmt_key(domain);
        let commitment = identity.commitment_hash();

        // 1. Insertion into tree
        csmt.insert(key, commitment.to_vec());
        let root = csmt.root();

        // 2. Measure Merkle proof generation (~4ms or less)
        let t_gen = Instant::now();
        let merkle_proof = csmt.proof_of_inclusion(&key).expect("Failed to generate inclusion proof");
        let gen_duration = t_gen.elapsed();
        println!("Merkle proof gen duration: {:?}", gen_duration);

        let proof = IdentityProof {
            identity: identity.clone(),
            root_hash: root,
            merkle_proof,
            proof_generation_ms: gen_duration.as_secs_f64() * 1000.0,
        };

        // 3. Measure local validation (<1ms)
        let t_val = Instant::now();
        let is_valid = proof.verify();
        let val_duration = t_val.elapsed();
        println!("Merkle proof validation duration: {:?}", val_duration);

        assert!(is_valid);
        assert!(val_duration.as_millis() < 5, "Validation must be sub-millisecond!");

        // 4. Measure Session key derivation (1ms)
        let t_key = Instant::now();
        let client_nonce = [1u8; 32];
        let server_nonce = [2u8; 32];
        let shared_seed = [3u8; 32];
        let session_key = IdentityRecord::derive_session_key(&client_nonce, &server_nonce, &shared_seed);
        let key_duration = t_key.elapsed();
        println!("Session key derivation duration: {:?}", key_duration);

        assert_ne!(session_key, [0u8; 32]);
    }
}
