use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey, Verifier};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use crate::account::Address;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Validator {
    pub address: Address,
    pub public_key: [u8; 32],
    pub stake: u128,
    #[serde(default)]
    pub missed_blocks: u64,
    #[serde(default)]
    pub is_jailed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnbondingEntry {
    pub validator_address: Address,
    pub amount: u128,
    pub release_height: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VoteType {
    PreVote,
    PreCommit,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Vote {
    pub chain_id: String,
    pub height: u64,
    pub round: u64,
    pub block_hash: [u8; 32],
    pub vote_type: VoteType,
    pub validator_pubkey: [u8; 32],
    #[serde(with = "crate::account::serde_sig")]
    pub signature: [u8; 64],
}

impl Vote {
    pub fn new(
        chain_id: &str,
        height: u64,
        round: u64,
        block_hash: [u8; 32],
        vote_type: VoteType,
        signing_key: &SigningKey,
    ) -> Self {
        let verifying_key = signing_key.verifying_key();
        let validator_pubkey = verifying_key.to_bytes();

        let mut vote = Self {
            chain_id: chain_id.to_string(),
            height,
            round,
            block_hash,
            vote_type,
            validator_pubkey,
            signature: [0u8; 64],
        };

        let signing_hash = vote.signing_hash();
        let sig = signing_key.sign(&signing_hash);
        vote.signature = sig.to_bytes();
        vote
    }

    pub fn signing_hash(&self) -> [u8; 32] {
        let mut hasher = vera_engine_v2::VeraHasher::new();
        hasher.update(b"VERA_BFT_VOTE_V2");
        hasher.update(self.chain_id.as_bytes());
        hasher.update(&self.height.to_le_bytes());
        hasher.update(&self.round.to_le_bytes());
        hasher.update(&self.block_hash);
        hasher.update(&[match self.vote_type {
            VoteType::PreVote => 0,
            VoteType::PreCommit => 1,
        }]);
        hasher.update(&self.validator_pubkey);
        hasher.finalize()
    }

    pub fn verify(&self) -> Result<(), String> {
        let vk = VerifyingKey::from_bytes(&self.validator_pubkey)
            .map_err(|e| format!("Invalid validator public key: {}", e))?;
        let sig = Signature::from_bytes(&self.signature);
        let hash = self.signing_hash();
        vk.verify(&hash, &sig)
            .map_err(|e| format!("Vote has invalid signature: {}", e))
    }
}

fn default_min_stake() -> u128 { 32_000_000_000_000_000_000 }
fn default_max_active() -> usize { 50 }
fn default_unbonding_period() -> u64 { 5 }
fn default_max_missed() -> u64 { 10 }
fn default_permissioned() -> bool { true }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorSet {
    pub validators: Vec<Validator>,
    #[serde(default)]
    pub unbonding_queue: Vec<UnbondingEntry>,
    #[serde(default)]
    pub allowlist: Vec<Address>,
    #[serde(default = "default_min_stake")]
    pub min_validator_stake: u128,
    #[serde(default = "default_max_active")]
    pub max_active_validators: usize,
    #[serde(default = "default_unbonding_period")]
    pub unbonding_period_blocks: u64,
    #[serde(default = "default_max_missed")]
    pub max_missed_blocks: u64,
    #[serde(default = "default_permissioned")]
    pub permissioned_validators: bool,
    #[serde(default)]
    pub governance_address: Option<Address>,
}

impl ValidatorSet {
    pub fn new(validators: Vec<Validator>) -> Self {
        Self {
            validators,
            unbonding_queue: Vec::new(),
            allowlist: Vec::new(),
            min_validator_stake: 0,
            max_active_validators: 50,
            unbonding_period_blocks: 5,
            max_missed_blocks: 10,
            permissioned_validators: false,
            governance_address: None,
        }
    }

    pub fn with_params(
        validators: Vec<Validator>,
        min_validator_stake: u128,
        max_active_validators: usize,
        unbonding_period_blocks: u64,
        max_missed_blocks: u64,
        permissioned_validators: bool,
        governance_address: Option<Address>,
        mut allowlist: Vec<Address>,
    ) -> Self {
        allowlist.sort();
        Self {
            validators,
            unbonding_queue: Vec::new(),
            allowlist,
            min_validator_stake,
            max_active_validators,
            unbonding_period_blocks,
            max_missed_blocks,
            permissioned_validators,
            governance_address,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("Failed to serialize ValidatorSet")
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        serde_json::from_slice(bytes).map_err(|e| format!("Failed to deserialize ValidatorSet: {}", e))
    }

    pub fn total_stake(&self) -> u128 {
        self.validators.iter().map(|v| v.stake).sum()
    }

    /// Returns active validators meeting requirements (not jailed, stake >= min_stake),
    /// sorted by highest stake (tie-breaker by lexicographic address) and capped at max_active_validators.
    pub fn active_validators(&self) -> Vec<&Validator> {
        let mut active: Vec<&Validator> = self
            .validators
            .iter()
            .filter(|v| !v.is_jailed && v.stake >= self.min_validator_stake && v.stake > 0)
            .collect();

        active.sort_by(|a, b| {
            b.stake.cmp(&a.stake).then_with(|| a.address.cmp(&b.address))
        });

        if active.len() > self.max_active_validators {
            active.truncate(self.max_active_validators);
        }

        active
    }

    pub fn active_total_stake(&self) -> u128 {
        self.active_validators().iter().map(|v| v.stake).sum()
    }

    /// Supermajority threshold 2/3 + 1 based on active validators
    pub fn supermajority_threshold(&self) -> u128 {
        let total = self.active_total_stake();
        (total * 2 + 2) / 3
    }

    pub fn find_validator(&self, pubkey: &[u8; 32]) -> Option<&Validator> {
        self.validators.iter().find(|v| &v.public_key == pubkey)
    }

    pub fn is_allowed(&self, addr: &Address) -> bool {
        if !self.permissioned_validators {
            return true;
        }
        self.allowlist.contains(addr)
    }

    pub fn allow(&mut self, addr: Address) {
        if !self.allowlist.contains(&addr) {
            self.allowlist.push(addr);
            self.allowlist.sort();
        }
    }

    pub fn disallow(&mut self, addr: &Address) {
        self.allowlist.retain(|a| a != addr);
    }

    /// Dynamically adds or increments validator stake at runtime
    pub fn bond(&mut self, address: Address, public_key: [u8; 32], amount: u128) -> Result<(), String> {
        if self.permissioned_validators && !self.is_allowed(&address) {
            return Err(format!(
                "Address 0x{} not authorized in validator allowlist",
                hex::encode(address)
            ));
        }

        let current_stake = self.validators.iter().find(|v| v.public_key == public_key).map(|v| v.stake).unwrap_or(0);
        let new_stake = current_stake.saturating_add(amount);

        if new_stake < self.min_validator_stake {
            return Err(format!(
                "Total stake {} wei below minimum required {} wei",
                new_stake, self.min_validator_stake
            ));
        }

        if let Some(existing) = self.validators.iter_mut().find(|v| v.public_key == public_key) {
            existing.stake = new_stake;
        } else {
            self.validators.push(Validator {
                address,
                public_key,
                stake: new_stake,
                missed_blocks: 0,
                is_jailed: false,
            });
        }
        Ok(())
    }

    /// Executes an unbond/unstake request with time-lock into the unbonding_queue
    pub fn unbond(
        &mut self,
        public_key: &[u8; 32],
        amount: u128,
        release_height: u64,
    ) -> Result<u128, String> {
        let val_idx = self
            .validators
            .iter()
            .position(|v| &v.public_key == public_key)
            .ok_or_else(|| "Validator not found for unstake".to_string())?;

        let val = &mut self.validators[val_idx];
        let actual_amount = if amount == 0 || amount > val.stake {
            val.stake
        } else {
            amount
        };

        if actual_amount == 0 {
            return Err("Unstake amount must be greater than zero".to_string());
        }

        let remaining_stake = val.stake.saturating_sub(actual_amount);
        if remaining_stake > 0 && remaining_stake < self.min_validator_stake {
            return Err(format!(
                "Remaining stake of {} wei would fall below the required minimum of {} wei",
                remaining_stake, self.min_validator_stake
            ));
        }

        val.stake = remaining_stake;
        let val_addr = val.address;

        if val.stake == 0 {
            self.validators.remove(val_idx);
        }

        self.unbonding_queue.push(UnbondingEntry {
            validator_address: val_addr,
            amount: actual_amount,
            release_height,
        });

        Ok(actual_amount)
    }

    /// Releases matured unbondings whose release height has been reached
    pub fn process_maturing_unbondings(&mut self, current_height: u64) -> Vec<(Address, u128)> {
        let mut maturing = Vec::new();
        let mut remaining = Vec::new();

        for entry in self.unbonding_queue.drain(..) {
            if entry.release_height <= current_height {
                maturing.push((entry.validator_address, entry.amount));
            } else {
                remaining.push(entry);
            }
        }

        self.unbonding_queue = remaining;
        maturing
    }

    /// Restores a validator from JAIL to the active set upon fulfilling conditions
    pub fn unjail(&mut self, public_key: &[u8; 32]) -> Result<(), String> {
        if let Some(val) = self.validators.iter_mut().find(|v| &v.public_key == public_key) {
            if !val.is_jailed {
                return Ok(());
            }
            if val.stake < self.min_validator_stake {
                return Err(format!(
                    "Current stake of {} wei is insufficient to exit jail (minimum: {} wei)",
                    val.stake, self.min_validator_stake
                ));
            }
            val.is_jailed = false;
            val.missed_blocks = 0;
            Ok(())
        } else {
            Err("Validator not found for unjail".to_string())
        }
    }

    /// Deterministically selects a stake-weighted proposer among active validators
    pub fn get_proposer(&self, height: u64, round: u64) -> Result<&Validator, String> {
        let active = self.active_validators();
        if active.is_empty() {
            return Err("Active validator set is empty".to_string());
        }
        let total_active_stake: u128 = active.iter().map(|v| v.stake).sum();
        if total_active_stake == 0 {
            return Err("No active validator has stake".to_string());
        }

        let mut hasher = vera_engine_v2::VeraHasher::new();
        hasher.update(b"VERA_STAKE_WEIGHTED_PROPOSER_V1");
        hasher.update(&height.to_le_bytes());
        hasher.update(&round.to_le_bytes());
        let seed = hasher.finalize();

        let mut seed_bytes = [0u8; 16];
        seed_bytes.copy_from_slice(&seed[0..16]);
        let rand_val = u128::from_le_bytes(seed_bytes);
        let target = rand_val % total_active_stake;

        let mut accumulated = 0u128;
        for val in &active {
            accumulated = accumulated.saturating_add(val.stake);
            if target < accumulated {
                return Ok(*val);
            }
        }

        Ok(active[0])
    }

    /// Validates a batch of votes and checks whether the 2/3 + 1 active stake threshold was reached
    pub fn check_supermajority(
        &self,
        expected_chain_id: &str,
        votes: &[Vote],
        expected_height: u64,
        expected_round: u64,
        expected_block_hash: &[u8; 32],
        expected_type: VoteType,
    ) -> Result<bool, String> {
        let active = self.active_validators();
        let mut accumulated_stake: u128 = 0;
        let mut seen_validators = HashSet::new();

        for vote in votes {
            if vote.chain_id != expected_chain_id
                || vote.height != expected_height
                || vote.round != expected_round
                || &vote.block_hash != expected_block_hash
                || vote.vote_type != expected_type
            {
                continue;
            }

            if seen_validators.contains(&vote.validator_pubkey) {
                continue;
            }

            if let Some(val) = active.iter().find(|v| v.public_key == vote.validator_pubkey) {
                vote.verify()?;
                accumulated_stake = accumulated_stake.saturating_add(val.stake);
                seen_validators.insert(vote.validator_pubkey);
            }
        }

        let threshold = self.supermajority_threshold();
        Ok(accumulated_stake >= threshold)
    }

    /// Validates commit (PreCommit) signatures of a block against the active validator set
    /// and checks whether the BFT 2/3 + 1 supermajority of stake was achieved.
    pub fn check_commit_supermajority(
        &self,
        chain_id: &str,
        height: u64,
        round: u64,
        block_hash: &[u8; 32],
        commits: &[crate::block::ValidatorCommit],
    ) -> Result<bool, String> {
        let votes: Vec<Vote> = commits
            .iter()
            .map(|c| Vote {
                chain_id: chain_id.to_string(),
                height,
                round,
                block_hash: *block_hash,
                vote_type: VoteType::PreCommit,
                validator_pubkey: c.validator_pubkey,
                signature: c.signature,
            })
            .collect();

        self.check_supermajority(
            chain_id,
            &votes,
            height,
            round,
            block_hash,
            VoteType::PreCommit,
        )
    }

    /// Audits validator liveness in a committed block.
    /// Committing validators have their missed count reset; missing validators have their missed count incremented.
    pub fn audit_liveness(&mut self, active_pubkeys: &HashSet<[u8; 32]>) {
        for val in &mut self.validators {
            if val.is_jailed {
                continue;
            }
            if active_pubkeys.contains(&val.public_key) {
                val.missed_blocks = 0;
            } else {
                val.missed_blocks = val.missed_blocks.saturating_add(1);
            }
        }
    }

    /// Applies penalty (Inactivity Slashing) to validators exceeding max_missed_blocks.
    /// Slashes 1% of stake, sends validator to JAIL, and resets missed blocks counter.
    pub fn slash_inactive_validators(&mut self) -> Vec<(Address, u128)> {
        let mut slashed_records = Vec::new();
        for val in &mut self.validators {
            if !val.is_jailed && val.missed_blocks >= self.max_missed_blocks && val.stake > 0 {
                // Slash 1% of absent validator stake
                let penalty = (val.stake.saturating_mul(1)) / 100;
                let actual_penalty = if penalty == 0 && val.stake > 0 { 1 } else { penalty };
                val.stake = val.stake.saturating_sub(actual_penalty);
                val.is_jailed = true;
                val.missed_blocks = 0;
                slashed_records.push((val.address, actual_penalty));
            }
        }
        slashed_records
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_bft_consensus_voting_supermajority() {
        let mut csprng = OsRng;

        let key1 = SigningKey::generate(&mut csprng);
        let key2 = SigningKey::generate(&mut csprng);
        let key3 = SigningKey::generate(&mut csprng);

        let pub1 = key1.verifying_key().to_bytes();
        let pub2 = key2.verifying_key().to_bytes();
        let pub3 = key3.verifying_key().to_bytes();

        let val_set = ValidatorSet::new(vec![
            Validator {
                address: vera_engine_v2::vera_hash_256(&pub1),
                public_key: pub1,
                stake: 40,
                missed_blocks: 0,
                is_jailed: false,
            },
            Validator {
                address: vera_engine_v2::vera_hash_256(&pub2),
                public_key: pub2,
                stake: 40,
                missed_blocks: 0,
                is_jailed: false,
            },
            Validator {
                address: vera_engine_v2::vera_hash_256(&pub3),
                public_key: pub3,
                stake: 20,
                missed_blocks: 0,
                is_jailed: false,
            },
        ]);

        assert_eq!(val_set.total_stake(), 100);
        assert_eq!(val_set.supermajority_threshold(), 67);

        let block_hash = [0x55u8; 32];
        let vote1 = Vote::new("vera-testnet-1", 1, 0, block_hash, VoteType::PreCommit, &key1);
        let vote2 = Vote::new("vera-testnet-1", 1, 0, block_hash, VoteType::PreCommit, &key2);
        let vote3 = Vote::new("vera-testnet-1", 1, 0, block_hash, VoteType::PreCommit, &key3);

        assert!(!val_set.check_supermajority("vera-testnet-1", &[vote1.clone()], 1, 0, &block_hash, VoteType::PreCommit).unwrap());
        assert!(val_set.check_supermajority("vera-testnet-1", &[vote1.clone(), vote2.clone()], 1, 0, &block_hash, VoteType::PreCommit).unwrap());
        assert!(!val_set.check_supermajority("vera-testnet-1", &[vote1.clone(), vote3.clone()], 1, 0, &block_hash, VoteType::PreCommit).unwrap());
        assert!(!val_set.check_supermajority("vera-mainnet", &[vote1.clone(), vote2.clone()], 1, 0, &block_hash, VoteType::PreCommit).unwrap());
    }

    #[test]
    fn test_dynamic_bonding_and_unbonding() {
        let mut val_set = ValidatorSet::new(vec![]);
        assert_eq!(val_set.validators.len(), 0);

        // Bond
        let addr1 = [1u8; 32];
        let pub1 = [11u8; 32];
        val_set.bond(addr1, pub1, 500).unwrap();
        assert_eq!(val_set.validators.len(), 1);
        assert_eq!(val_set.total_stake(), 500);

        // Incremental Bond
        val_set.bond(addr1, pub1, 300).unwrap();
        assert_eq!(val_set.validators.len(), 1);
        assert_eq!(val_set.total_stake(), 800);

        // Second validator
        let addr2 = [2u8; 32];
        let pub2 = [22u8; 32];
        val_set.bond(addr2, pub2, 200).unwrap();
        assert_eq!(val_set.validators.len(), 2);
        assert_eq!(val_set.total_stake(), 1000);

        // Unbond partial
        assert_eq!(val_set.unbond(&pub1, 300, 10).unwrap(), 300);
        assert_eq!(val_set.validators.len(), 2);
        assert_eq!(val_set.total_stake(), 700);

        // Unbond full
        assert_eq!(val_set.unbond(&pub1, 600, 10).unwrap(), 500);
        assert_eq!(val_set.validators.len(), 1);
        assert_eq!(val_set.total_stake(), 200);

        // Process maturing
        let matured = val_set.process_maturing_unbondings(10);
        assert_eq!(matured.len(), 2);
        assert_eq!(matured[0].1 + matured[1].1, 800);
    }
}
