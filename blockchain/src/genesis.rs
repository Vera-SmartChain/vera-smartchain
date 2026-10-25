use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use crate::account::{Account, Address, address_from_hex, address_to_hex};
use crate::block::{Block, BlockHeader};
use crate::consensus::{Validator, ValidatorSet};
use crate::csmt::CSMT;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisValidator {
    pub address: String,
    pub stake: String, // String to avoid integer overflow in JSON
    pub public_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisAccount {
    pub address: String,
    pub balance: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisConfig {
    pub chain_id: String,
    #[serde(default = "default_evm_chain_id")]
    pub evm_chain_id: u64,
    pub timestamp: u64,
    pub block_time: u64,
    pub validator_count: usize,
    pub initial_validators: Vec<GenesisValidator>,
    pub initial_accounts: Vec<GenesisAccount>,
    #[serde(default = "default_min_validator_stake_str")]
    pub min_validator_stake: String,
    #[serde(default = "default_max_active_validators")]
    pub max_active_validators: usize,
    #[serde(default = "default_unbonding_period_blocks")]
    pub unbonding_period_blocks: u64,
    #[serde(default = "default_max_missed_blocks")]
    pub max_missed_blocks: u64,
    #[serde(default = "default_permissioned_validators")]
    pub permissioned_validators: bool,
    #[serde(default)]
    pub governance_address: Option<String>,
    #[serde(default)]
    pub validator_allowlist: Vec<String>,
    /// First height decided by the Tendermint engine (devnets). Public networks take it
    /// from `builtin_tendermint_activation` instead, so their genesis file never changes.
    #[serde(default)]
    pub tendermint_activation_height: Option<u64>,
    /// First height executed under execution rules v2 (devnets). Public networks take it
    /// from `builtin_exec_v2_activation` instead.
    #[serde(default)]
    pub exec_v2_activation_height: Option<u64>,
}

/// Tendermint activation height of public networks, fixed per release (a coordinated,
/// consensus-breaking upgrade). None = not scheduled yet.
pub fn builtin_tendermint_activation(chain_id: &str) -> Option<u64> {
    match chain_id {
        // v0.2.6 (21/Out/2026): announced at #102, every validator upgrades before #152.
        "vera-testnet-1" => Some(152),
        _ => None,
    }
}

/// Activation height of execution rules v2 on public networks (consensus-breaking):
/// stability-pool and burn fee shares credited once per block, receipts without a
/// per-transaction state root, receipt hash v2 covering the logs. None = not scheduled yet.
pub fn builtin_exec_v2_activation(chain_id: &str) -> Option<u64> {
    match chain_id {
        // v0.2.9 (25/Oct/2026): chain idle at #734; every validator upgrades before #760.
        "vera-testnet-1" => Some(760),
        _ => None,
    }
}

fn default_evm_chain_id() -> u64 {
    83721
}

fn default_min_validator_stake_str() -> String {
    "32000000000000000000".to_string() // 32 VERA
}

fn default_max_active_validators() -> usize {
    50
}

fn default_unbonding_period_blocks() -> u64 {
    5
}

fn default_max_missed_blocks() -> u64 {
    10
}

fn default_permissioned_validators() -> bool {
    true
}

impl GenesisConfig {
    pub fn min_validator_stake_wei(&self) -> u128 {
        self.min_validator_stake
            .parse::<u128>()
            .unwrap_or(32_000_000_000_000_000_000)
    }

    pub fn parsed_governance_address(&self) -> Option<Address> {
        self.governance_address
            .as_ref()
            .and_then(|s| address_from_hex(s).ok())
    }

    pub fn parsed_validator_allowlist(&self) -> Vec<Address> {
        let mut addrs = Vec::new();
        for s in &self.validator_allowlist {
            if let Ok(a) = address_from_hex(s) {
                if !addrs.contains(&a) {
                    addrs.push(a);
                }
            }
        }
        addrs.sort();
        addrs
    }

    pub fn build_validator_set(&self) -> Result<ValidatorSet, String> {
        let mut validators = Vec::new();
        for gv in &self.initial_validators {
            let addr = address_from_hex(&gv.address)?;
            let stake: u128 = gv.stake.parse().map_err(|e| format!("Invalid stake: {}", e))?;
            let pubkey_bytes = hex::decode(&gv.public_key).map_err(|e| format!("Invalid hex: {}", e))?;
            let mut pubkey = [0u8; 32];
            pubkey.copy_from_slice(&pubkey_bytes);
            validators.push(Validator {
                address: addr,
                public_key: pubkey,
                stake,
                missed_blocks: 0,
                is_jailed: false,
            });
        }

        let allowlist = self.parsed_validator_allowlist();
        let gov_addr = self.parsed_governance_address();
        let min_stake = self.min_validator_stake_wei();

        Ok(ValidatorSet::with_params(
            validators,
            min_stake,
            self.max_active_validators,
            self.unbonding_period_blocks,
            self.max_missed_blocks,
            self.permissioned_validators,
            gov_addr,
            allowlist,
        ))
    }

    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        let content = fs::read_to_string(path).map_err(|e| format!("Error reading genesis: {}", e))?;
        serde_json::from_str(&content).map_err(|e| format!("Error parsing genesis JSON: {}", e))
    }

    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), String> {
        let json = serde_json::to_string_pretty(self).map_err(|e| format!("Error serializing genesis: {}", e))?;
        fs::write(path, json).map_err(|e| format!("Error saving genesis: {}", e))
    }

    /// Initializes the CSMT and creates Block #0 of the blockchain
    pub fn build_genesis_state(&self) -> Result<(CSMT, Block), String> {
        let mut csmt = CSMT::new();

        // 1. Initialize default accounts
        for ga in &self.initial_accounts {
            let addr = address_from_hex(&ga.address)?;
            let balance: u128 = ga.balance.parse().map_err(|e| format!("Invalid balance: {}", e))?;
            let acc = Account::new(balance);
            csmt.insert(addr, acc.to_bytes());
        }

        // 2. Ensure validators have registered accounts (or add stake)
        let mut total_staked: u128 = 0;
        for gv in &self.initial_validators {
            let addr = address_from_hex(&gv.address)?;
            let stake: u128 = gv.stake.parse().map_err(|e| format!("Invalid stake: {}", e))?;
            total_staked = total_staked.saturating_add(stake);
            if let Some(existing_bytes) = csmt.get(&addr) {
                let mut acc = Account::from_bytes(existing_bytes)?;
                acc.balance = acc.balance.saturating_add(stake);
                csmt.insert(addr, acc.to_bytes());
            } else {
                let acc = Account::new(stake);
                csmt.insert(addr, acc.to_bytes());
            }
        }

        // 3. Initialize STAKING_SYSTEM_ADDRESS with total initial stakes
        let mut staking_sys_acc = match csmt.get(&crate::account::STAKING_SYSTEM_ADDRESS) {
            Some(b) => Account::from_bytes(b)?,
            None => Account::new(0),
        };
        staking_sys_acc.balance = staking_sys_acc.balance.saturating_add(total_staked);
        csmt.insert(crate::account::STAKING_SYSTEM_ADDRESS, staking_sys_acc.to_bytes());

        // 4. Save canonical ValidatorSet under VALIDATOR_SET_CSMT_KEY
        let val_set = self.build_validator_set()?;
        csmt.insert(crate::account::VALIDATOR_SET_CSMT_KEY, val_set.to_bytes());

        let state_root = csmt.root();

        // 5. Create Block #0 header
        let header = BlockHeader {
            height: 0,
            prev_hash: [0u8; 32],
            timestamp: self.timestamp,
            state_root,
            tx_root: [0u8; 32],
            receipts_root: [0u8; 32],
            proposer: [0u8; 32],
            last_commit_hash: [0u8; 32],
        };

        let block = Block::new(header, Vec::new(), Vec::new());
        Ok((csmt, block))
    }

    /// Generates default configuration for quick testnet
    pub fn default_testnet() -> (Self, ed25519_dalek::SigningKey) {
        use rand::rngs::OsRng;
        use ed25519_dalek::SigningKey;

        let mut csprng = OsRng;
        let val_signing_key = SigningKey::generate(&mut csprng);
        let val_pubkey = val_signing_key.verifying_key().to_bytes();
        let val_addr = crate::chain_hash::hash256(&val_pubkey);

        let user_signing_key = SigningKey::generate(&mut csprng);
        let user_pubkey = user_signing_key.verifying_key().to_bytes();
        let user_addr = crate::chain_hash::hash256(&user_pubkey);

        let cfg = GenesisConfig {
            chain_id: "vera-testnet-1".to_string(),
            evm_chain_id: 83721,
            timestamp: 1725580800,
            block_time: 12,
            validator_count: 1,
            initial_validators: vec![GenesisValidator {
                address: address_to_hex(&val_addr),
                stake: "32000000000000000000".to_string(), // 32 VERA
                public_key: hex::encode(val_pubkey),
            }],
            initial_accounts: vec![GenesisAccount {
                address: address_to_hex(&user_addr),
                balance: "1000000000000000000000".to_string(), // 1,000 VERA
            }],
            min_validator_stake: "32000000000000000000".to_string(),
            max_active_validators: 50,
            unbonding_period_blocks: 5,
            max_missed_blocks: 10,
            permissioned_validators: true,
            governance_address: Some(address_to_hex(&user_addr)),
            validator_allowlist: vec![address_to_hex(&val_addr)],
            tendermint_activation_height: None,
            exec_v2_activation_height: None,
        };

        (cfg, val_signing_key)
    }

    /// Generates official Mainnet configuration for VERA Chain ($VERA)
    pub fn mainnet(initial_validator_pubkeys: &[[u8; 32]]) -> Result<Self, String> {
        if initial_validator_pubkeys.is_empty() {
            return Err("Mainnet requires at least 1 initial validator".to_string());
        }

        let wei_unit: u128 = 1_000_000_000_000_000_000;
        let stake_per_val = (32 * wei_unit).to_string(); // Minimum stake of 32 VERA

        let initial_validators: Vec<GenesisValidator> = initial_validator_pubkeys
            .iter()
            .map(|pk| {
                let addr = crate::chain_hash::hash256(pk);
                GenesisValidator {
                    address: address_to_hex(&addr),
                    stake: stake_per_val.clone(),
                    public_key: hex::encode(pk),
                }
            })
            .collect();

        let initial_accounts = vec![
            GenesisAccount {
                address: "0000000000000000000000000000000000000000000000000000000000007a1d".to_string(),
                balance: (35_000_000 * wei_unit).to_string(),
            },
            GenesisAccount {
                address: "000000000000000000000000000000000000000000000000000000000000ec05".to_string(),
                balance: (25_000_000 * wei_unit).to_string(),
            },
            GenesisAccount {
                address: "000000000000000000000000000000000000000000000000000000000000c07e".to_string(),
                balance: (20_000_000 * wei_unit).to_string(),
            },
            GenesisAccount {
                address: "000000000000000000000000000000000000000000000000000000000000119d".to_string(),
                balance: (10_000_000 * wei_unit).to_string(),
            },
            GenesisAccount {
                address: "000000000000000000000000000000000000000000000000000000000000c033".to_string(),
                balance: (10_000_000 * wei_unit).to_string(),
            },
        ];

        Ok(GenesisConfig {
            chain_id: "vera-mainnet".to_string(),
            evm_chain_id: 8372,
            timestamp: 1725580800,
            block_time: 12,
            validator_count: initial_validators.len(),
            initial_validators,
            initial_accounts,
            min_validator_stake: (32 * wei_unit).to_string(),
            max_active_validators: 50,
            unbonding_period_blocks: 50400,
            max_missed_blocks: 100,
            permissioned_validators: false,
            governance_address: Some("000000000000000000000000000000000000000000000000000000000000ec05".to_string()),
            validator_allowlist: vec![],
            tendermint_activation_height: None,
            exec_v2_activation_height: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_genesis_initialization() {
        let (cfg, _) = GenesisConfig::default_testnet();
        let (csmt, block) = cfg.build_genesis_state().unwrap();

        assert_eq!(block.header.height, 0);
        assert_eq!(block.header.prev_hash, [0u8; 32]);
        assert_eq!(block.header.state_root, csmt.root());
        assert_ne!(csmt.root(), [0u8; 32]);
    }

    #[test]
    fn test_mainnet_genesis_100m_allocation() {
        let val_pub = [0x42u8; 32];
        let cfg = GenesisConfig::mainnet(&[val_pub]).expect("Mainnet genesis must be valid");

        assert_eq!(cfg.chain_id, "vera-mainnet");
        assert_eq!(cfg.validator_count, 1);

        let wei_unit: u128 = 1_000_000_000_000_000_000;
        let total_allocated: u128 = cfg
            .initial_accounts
            .iter()
            .map(|a| a.balance.parse::<u128>().unwrap())
            .sum();

        let expected_100m = 100_000_000 * wei_unit;
        assert_eq!(total_allocated, expected_100m, "A soma deve ser exatamente 100.000.000 VERA");

        let (csmt, block) = cfg.build_genesis_state().unwrap();
        assert_eq!(block.header.height, 0);
        assert_ne!(csmt.root(), [0u8; 32]);
    }
}
