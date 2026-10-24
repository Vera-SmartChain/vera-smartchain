use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use crate::account::Address;
use crate::csmt::MerkleProof;
use vera_engine_v2::ComputationGraph;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Transaction {
    pub chain_id: String,
    pub public_key: [u8; 32],
    pub sender: Address,
    pub nonce: u64,
    pub to: Option<Address>,
    pub amount: u128,
    pub gas_limit: u64,
    pub gas_price: u64,
    pub program: Vec<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub witness: Option<MerkleProof>, // Stateless proof of sender account
    #[serde(with = "crate::account::serde_sig")]
    pub signature: [u8; 64],
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_evm: Option<Vec<u8>>,
}

impl Transaction {
    pub fn new(
        chain_id: &str,
        signing_key: &SigningKey,
        nonce: u64,
        to: Option<Address>,
        amount: u128,
        gas_limit: u64,
        gas_price: u64,
        program: Vec<u8>,
    ) -> Self {
        let verifying_key = signing_key.verifying_key();
        let public_key = verifying_key.to_bytes();
        let sender = crate::chain_hash::hash256(&public_key);

        let mut tx = Self {
            chain_id: chain_id.to_string(),
            public_key,
            sender,
            nonce,
            to,
            amount,
            gas_limit,
            gas_price,
            program,
            witness: None,
            signature: [0u8; 64],
            raw_evm: None,
        };

        let signing_payload = tx.signing_hash();
        let signature = signing_key.sign(&signing_payload);
        tx.signature = signature.to_bytes();
        tx
    }

    pub fn signing_hash(&self) -> [u8; 32] {
        let mut hasher = crate::chain_hash::ChainHasher::new();
        hasher.update(b"VERA_TX_V2");
        hasher.update(self.chain_id.as_bytes());
        hasher.update(&self.public_key);
        hasher.update(&self.sender);
        hasher.update(&self.nonce.to_le_bytes());
        match &self.to {
            Some(t) => {
                hasher.update(&[1u8]);
                hasher.update(t);
            }
            None => {
                hasher.update(&[0u8]);
            }
        }
        hasher.update(&self.amount.to_le_bytes());
        hasher.update(&self.gas_limit.to_le_bytes());
        hasher.update(&self.gas_price.to_le_bytes());
        hasher.update(&(self.program.len() as u64).to_le_bytes());
        hasher.update(&self.program);
        hasher.finalize()
    }

    pub fn tx_hash(&self) -> [u8; 32] {
        if let Some(ref raw) = self.raw_evm {
            crate::account::keccak256(raw)
        } else {
            let mut hasher = crate::chain_hash::ChainHasher::new();
            hasher.update(&self.signing_hash());
            hasher.update(&self.signature);
            hasher.finalize()
        }
    }

    pub fn verify_signature(&self) -> Result<(), String> {
        if let Some(ref raw) = self.raw_evm {
            let chain_id_num: u64 = self.chain_id.parse().unwrap_or(83721);
            let recovered = crate::rpc::parse_and_recover_evm_tx(raw, chain_id_num)?;
            if recovered.from != self.sender {
                return Err("Sender address does not match recovered ECDSA address".to_string());
            }
            if recovered.nonce != self.nonce {
                return Err("Nonce differs from ECDSA signature".to_string());
            }
            if recovered.value != self.amount {
                return Err("Value differs from ECDSA signature".to_string());
            }
            // Every field the state transition reads must be bound to the ECDSA-signed payload;
            // otherwise a relayer or proposer could rewrite to/calldata/gas around a valid signature.
            let expected_to = if recovered.is_contract_creation { None } else { Some(recovered.to) };
            if self.to != expected_to {
                return Err("Recipient differs from ECDSA signature".to_string());
            }
            if recovered.gas_limit != self.gas_limit || recovered.gas_price != self.gas_price {
                return Err("Gas parameters differ from ECDSA signature".to_string());
            }
            if recovered.data != self.program {
                return Err("Calldata differs from ECDSA signature".to_string());
            }
            if self.public_key != [0u8; 32] || self.signature != [0u8; 64] {
                return Err("EVM transaction must not carry native public_key/signature fields".to_string());
            }
            return Ok(());
        }

        let verifying_key = VerifyingKey::from_bytes(&self.public_key)
            .map_err(|e| format!("Invalid public key: {}", e))?;

        let expected_sender = crate::chain_hash::hash256(&self.public_key);
        if self.sender != expected_sender {
            return Err("Sender address does not match public_key hash".to_string());
        }

        let signature = Signature::from_bytes(&self.signature);
        let signing_payload = self.signing_hash();

        verifying_key
            .verify_strict(&signing_payload, &signature)
            .map_err(|e| format!("Invalid signature (strict RFC 8032): {}", e))?;

        Ok(())
    }

    /// Formal static analysis of Flat-DAG / VERA v2 Graph / Calldata in O(V + E) before mempool admission
    /// Computes Worst Case Execution Time (WCET) and static gas cost
    pub fn validate_static_dag(&self) -> Result<u64, String> {
        if self.program.is_empty() {
            return Ok(21_000);
        }

        // 1. Attempts validation as canonical VERA v2 SSA Graph
        if let Ok(json_str) = std::str::from_utf8(&self.program) {
            if let Ok(graph) = ComputationGraph::from_json(json_str) {
                graph.validate_invariants()?;
                let base_gas: u64 = 21_000;
                let instruction_gas = (graph.nodes.len() as u64).saturating_mul(100);
                let total_static_wcet = base_gas.saturating_add(instruction_gas);

                if total_static_wcet > self.gas_limit {
                    return Err(format!(
                        "Static Rejection: GasLimit ({}) insufficient for VERA v2 Graph WCET ({})",
                        self.gas_limit, total_static_wcet
                    ));
                }

                return Ok(total_static_wcet);
            }
        }

        // 2. Binary calldata / program buffer
        let base_gas: u64 = 21_000;
        let calldata_gas = (self.program.len() as u64).saturating_mul(10);
        let total_static_wcet = base_gas.saturating_add(calldata_gas);

        if total_static_wcet > self.gas_limit {
            return Err(format!(
                "Static Rejection: GasLimit ({}) insufficient for Calldata WCET ({})",
                self.gas_limit, total_static_wcet
            ));
        }

        Ok(total_static_wcet)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("Failed to serialize Transaction")
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        serde_json::from_slice(bytes).map_err(|e| format!("Failed to deserialize Transaction: {}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_transaction_signature_and_chain_isolation() {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);

        let tx = Transaction::new(
            "vera-mainnet",
            &signing_key,
            0,
            Some([2u8; 32]),
            1_000_000,
            50_000,
            1,
            vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
        );

        assert!(tx.verify_signature().is_ok());
        assert!(tx.validate_static_dag().is_ok());

        // Cross-chain isolation test: replay on testnet MUST fail
        let mut replayed_tx = tx.clone();
        replayed_tx.chain_id = "vera-testnet-1".to_string();
        assert!(replayed_tx.verify_signature().is_err());
    }
}
