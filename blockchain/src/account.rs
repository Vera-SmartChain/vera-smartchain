use serde::{Deserialize, Serialize};

pub type Address = [u8; 32];

/// Canonical Address of the Dynamic Staking Module (Precompile / System Contract)
pub const STAKING_SYSTEM_ADDRESS: Address = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10, 0x00,
];

/// Canonical CSMT key where the ValidatorSet state is committed
pub const VALIDATOR_SET_CSMT_KEY: Address = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10, 0x01,
];

pub mod serde_sig {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let clean = s.strip_prefix("0x").unwrap_or(&s);
        let v = hex::decode(clean).map_err(serde::de::Error::custom)?;
        if v.len() != 64 {
            return Err(serde::de::Error::custom(format!(
                "Signature must be 64 bytes, received {}",
                v.len()
            )));
        }
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&v);
        Ok(arr)
    }
}

pub fn address_from_hex(s: &str) -> Result<Address, String> {
    let clean = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(clean).map_err(|e| format!("Hex decode error: {}", e))?;
    let mut addr = [0u8; 32];
    if bytes.len() == 32 {
        addr.copy_from_slice(&bytes);
        Ok(addr)
    } else if bytes.len() == 20 {
        // EVM address (20 bytes Ethereum / MetaMask): normalize to last 20 bytes
        addr[12..32].copy_from_slice(&bytes);
        Ok(addr)
    } else {
        Err(format!("Address must be 20 bytes (EVM) or 32 bytes (VERA), received {}", bytes.len()))
    }
}

pub fn address_to_hex(addr: &Address) -> String {
    format!("0x{}", hex::encode(addr))
}

pub fn address_from_pubkey(pubkey: &[u8; 32]) -> Address {
    vera_engine_v2::vera_hash_256(pubkey)
}

/// VERA Account Model
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Account {
    pub nonce: u64,
    pub balance: u128,
    pub code_hash: [u8; 32],
    pub storage_root: [u8; 32],
}

impl Account {
    pub fn new(balance: u128) -> Self {
        Self {
            nonce: 0,
            balance,
            code_hash: [0u8; 32],
            storage_root: [0u8; 32],
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("Failed to serialize Account")
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        serde_json::from_slice(bytes).map_err(|e| format!("Failed to deserialize Account: {}", e))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvmLog {
    pub address: Address,
    pub topics: Vec<[u8; 32]>,
    pub data: Vec<u8>,
}

pub fn compute_logs_bloom(logs: &[EvmLog]) -> [u8; 256] {
    let mut bloom = [0u8; 256];
    for log in logs {
        add_to_bloom(&mut bloom, &log.address[12..32]);
        for topic in &log.topics {
            add_to_bloom(&mut bloom, topic);
        }
    }
    bloom
}

pub fn keccak256(data: &[u8]) -> [u8; 32] {
    use tiny_keccak::{Hasher, Keccak};
    let mut hasher = Keccak::v256();
    let mut output = [0u8; 32];
    hasher.update(data);
    hasher.finalize(&mut output);
    output
}

fn add_to_bloom(bloom: &mut [u8; 256], item: &[u8]) {
    use tiny_keccak::{Hasher, Keccak};
    let mut hasher = Keccak::v256();
    hasher.update(item);
    let mut hash = [0u8; 32];
    hasher.finalize(&mut hash);

    for i in 0..3 {
        let b1 = hash[2 * i] as usize;
        let b2 = hash[2 * i + 1] as usize;
        let bit = ((b1 << 8) | b2) & 0x07ff;
        let byte_idx = 255 - (bit / 8);
        let bit_idx = bit % 8;
        bloom[byte_idx] |= 1 << bit_idx;
    }
}

/// Cryptographic transaction execution receipt
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionReceipt {
    pub tx_hash: [u8; 32],
    pub success: bool,
    pub gas_used: u64,
    pub state_root: [u8; 32],
    pub trace_root: [u8; 32],
    #[serde(default)]
    pub logs: Vec<EvmLog>,
}

impl ExecutionReceipt {
    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = vera_engine_v2::VeraHasher::new();
        hasher.update(&self.tx_hash);
        hasher.update(&[if self.success { 1 } else { 0 }]);
        hasher.update(&self.gas_used.to_le_bytes());
        hasher.update(&self.state_root);
        hasher.update(&self.trace_root);
        hasher.finalize()
    }

    pub fn logs_bloom(&self) -> String {
        let bloom = compute_logs_bloom(&self.logs);
        format!("0x{}", hex::encode(bloom))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_account_serialization() {
        let acc = Account {
            nonce: 42,
            balance: 10_000_000_000,
            code_hash: [1u8; 32],
            storage_root: [2u8; 32],
        };
        let bytes = acc.to_bytes();
        let decoded = Account::from_bytes(&bytes).unwrap();
        assert_eq!(acc, decoded);
    }

    #[test]
    fn test_address_hex_conversion() {
        let addr = [0xabu8; 32];
        let hex_str = address_to_hex(&addr);
        assert!(hex_str.starts_with("0x"));
        let parsed = address_from_hex(&hex_str).unwrap();
        assert_eq!(addr, parsed);
    }
}
