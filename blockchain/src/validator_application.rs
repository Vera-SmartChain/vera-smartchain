use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::path::Path;
use crate::account::{address_from_pubkey, address_to_hex};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorApplication {
    pub chain_id: String,
    pub address: String,
    pub public_key: String,
    pub operator: String,
    pub timestamp: u64,
    pub signature: String,
}

impl ValidatorApplication {
    pub fn new(signing_key: &SigningKey, chain_id: &str, operator: &str) -> Self {
        let pubkey_bytes = signing_key.verifying_key().to_bytes();
        let address = address_to_hex(&address_from_pubkey(&pubkey_bytes));
        let pubkey_hex = format!("0x{}", hex::encode(pubkey_bytes));
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let message = Self::canonical_message(chain_id, &address, operator, timestamp);
        let signature = signing_key.sign(message.as_bytes());
        let signature_hex = format!("0x{}", hex::encode(signature.to_bytes()));

        Self {
            chain_id: chain_id.to_string(),
            address,
            public_key: pubkey_hex,
            operator: operator.to_string(),
            timestamp,
            signature: signature_hex,
        }
    }

    pub fn canonical_message(chain_id: &str, address: &str, operator: &str, timestamp: u64) -> String {
        format!("VERA-VALIDATOR-APPLICATION|{}|{}|{}|{}", chain_id, address, operator, timestamp)
    }

    pub fn to_block_text(&self) -> String {
        format!(
            "-----BEGIN VERA VALIDATOR APPLICATION-----\n\
             chain_id: {}\n\
             address: {}\n\
             public_key: {}\n\
             operator: {}\n\
             timestamp: {}\n\
             signature: {}\n\
             -----END VERA VALIDATOR APPLICATION-----",
            self.chain_id, self.address, self.public_key, self.operator, self.timestamp, self.signature
        )
    }

    pub fn parse_block(text: &str) -> Result<Self, String> {
        let trimmed = text.trim();
        if trimmed.starts_with('{') {
            return serde_json::from_str(trimmed).map_err(|e| format!("JSON parse error: {}", e));
        }

        let mut chain_id = None;
        let mut address = None;
        let mut public_key = None;
        let mut operator = None;
        let mut timestamp = None;
        let mut signature = None;

        for line in trimmed.lines() {
            let line = line.trim();
            if line.starts_with("-----") || line.is_empty() {
                continue;
            }
            if let Some((k, v)) = line.split_once(':') {
                let key = k.trim().to_lowercase();
                let val = v.trim().trim_matches('"').to_string();
                match key.as_str() {
                    "chain_id" | "chainid" => chain_id = Some(val),
                    "address" => address = Some(val),
                    "public_key" | "publickey" | "pubkey" => public_key = Some(val),
                    "operator" => operator = Some(val),
                    "timestamp" => timestamp = val.parse::<u64>().ok(),
                    "signature" => signature = Some(val),
                    _ => {}
                }
            }
        }

        Ok(Self {
            chain_id: chain_id.ok_or_else(|| "Missing chain_id in application block".to_string())?,
            address: address.ok_or_else(|| "Missing address in application block".to_string())?,
            public_key: public_key.ok_or_else(|| "Missing public_key in application block".to_string())?,
            operator: operator.ok_or_else(|| "Missing operator in application block".to_string())?,
            timestamp: timestamp.ok_or_else(|| "Missing timestamp in application block".to_string())?,
            signature: signature.ok_or_else(|| "Missing signature in application block".to_string())?,
        })
    }

    pub fn verify(&self, expected_chain_id: &str, max_age_secs: u64) -> Result<(), String> {
        if self.chain_id != expected_chain_id {
            return Err(format!("Chain ID mismatch: expected '{}', got '{}'", expected_chain_id, self.chain_id));
        }

        let clean_pub = self.public_key.trim_start_matches("0x");
        let pub_bytes = hex::decode(clean_pub).map_err(|e| format!("Invalid public_key hex: {}", e))?;
        if pub_bytes.len() != 32 {
            return Err(format!("Public key must be 32 bytes, got {}", pub_bytes.len()));
        }
        let mut pub_arr = [0u8; 32];
        pub_arr.copy_from_slice(&pub_bytes);

        let derived_addr = address_to_hex(&address_from_pubkey(&pub_arr));
        if derived_addr.to_lowercase() != self.address.to_lowercase() {
            return Err(format!(
                "Public key does not match address: derived {}, application has {}",
                derived_addr, self.address
            ));
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Check not from future > 300s (5 minutes clock skew tolerance)
        if self.timestamp > now + 300 {
            return Err(format!(
                "Timestamp is in the future: application {}, current {}",
                self.timestamp, now
            ));
        }

        // Check age <= max_age_secs (7 days = 604800s)
        if now.saturating_sub(self.timestamp) > max_age_secs {
            return Err(format!(
                "Application has expired (age {}s > max allowed {}s)",
                now.saturating_sub(self.timestamp),
                max_age_secs
            ));
        }

        let clean_sig = self.signature.trim_start_matches("0x");
        let sig_bytes = hex::decode(clean_sig).map_err(|e| format!("Invalid signature hex: {}", e))?;
        if sig_bytes.len() != 64 {
            return Err(format!("Signature must be 64 bytes, got {}", sig_bytes.len()));
        }
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig_bytes);

        let verifying_key = VerifyingKey::from_bytes(&pub_arr)
            .map_err(|e| format!("Invalid Ed25519 public key: {}", e))?;
        let sig = Signature::from_bytes(&sig_arr);

        let message = Self::canonical_message(&self.chain_id, &self.address, &self.operator, self.timestamp);
        verifying_key
            .verify_strict(message.as_bytes(), &sig)
            .map_err(|e| format!("Ed25519 signature verification failed: {}", e))?;

        Ok(())
    }
}

pub fn read_key_from_file_or_hex(input: &str) -> Result<SigningKey, Box<dyn std::error::Error>> {
    let raw = if Path::new(input).exists() {
        std::fs::read_to_string(input)?
    } else {
        input.to_string()
    };
    let clean = raw.trim().trim_start_matches("0x");
    let bytes = hex::decode(clean)?;
    if bytes.len() != 32 {
        return Err(format!(
            "Private key must be 32 bytes (64 hex characters), received {} bytes",
            bytes.len()
        ).into());
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(SigningKey::from_bytes(&arr))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatorStatusInfo {
    pub state: String,
    pub stake_wei: u128,
    pub is_jailed: bool,
    pub missed_blocks: u64,
}

pub fn is_address_in_allowlist(val_json: &serde_json::Value, address: &str) -> bool {
    let norm = address.to_lowercase();
    let allowlist_opt = val_json.get("result")
        .and_then(|r| r.get("allowlist").or_else(|| r.get("validatorAllowlist")))
        .or_else(|| val_json.get("allowlist").or_else(|| val_json.get("validatorAllowlist")))
        .and_then(|v| v.as_array());

    if let Some(allowlist) = allowlist_opt {
        allowlist.iter().any(|a| a.as_str().map(|s| s.to_lowercase()) == Some(norm.clone()))
    } else {
        false
    }
}

pub fn parse_validator_status_from_json(val_json: &serde_json::Value, address: &str) -> ValidatorStatusInfo {
    let norm = address.to_lowercase();
    let result = val_json.get("result").unwrap_or(val_json);

    let mut found_active = false;
    let mut found_jailed = false;
    let mut stake_str = "0".to_string();
    let mut missed_blocks: u64 = 0;

    if let Some(active) = result.get("activeValidators").and_then(|v| v.as_array()) {
        for v in active {
            if v["address"].as_str().map(|s| s.to_lowercase()) == Some(norm.clone()) {
                found_active = true;
                stake_str = v["stake"].as_str().unwrap_or("0").to_string();
                missed_blocks = v["missedBlocks"].as_u64().unwrap_or(0);
                break;
            }
        }
    }

    if !found_active {
        if let Some(all) = result.get("validators").and_then(|v| v.as_array()) {
            for v in all {
                if v["address"].as_str().map(|s| s.to_lowercase()) == Some(norm.clone()) {
                    stake_str = v["stake"].as_str().unwrap_or("0").to_string();
                    missed_blocks = v["missedBlocks"].as_u64().unwrap_or(0);
                    if v["isJailed"].as_bool().unwrap_or(false) {
                        found_jailed = true;
                    }
                    break;
                }
            }
        }
    }

    let stake_wei = stake_str.parse::<u128>().unwrap_or(0);
    let state = if found_active {
        "ACTIVE".to_string()
    } else if found_jailed {
        "JAILED".to_string()
    } else if stake_wei > 0 {
        "INACTIVE".to_string()
    } else {
        "UNREGISTERED".to_string()
    };

    ValidatorStatusInfo {
        state,
        stake_wei,
        is_jailed: found_jailed,
        missed_blocks,
    }
}
