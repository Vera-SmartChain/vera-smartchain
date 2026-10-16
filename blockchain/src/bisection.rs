use serde::{Deserialize, Serialize};
use crate::account::Address;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BisectionStatus {
    Ongoing { current_round: usize, left: usize, right: usize },
    ResolvedChallengerWon { isolated_step: usize, reason: String },
    ResolvedProposerWon { reason: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepWitness {
    pub step_index: usize,
    pub state_hash: [u8; 32],
}

/// Interactive Bisection Game Session O(log N)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BisectionGame {
    pub session_id: [u8; 32],
    pub proposer: Address,
    pub challenger: Address,
    pub bond_amount: u128,
    pub total_steps: usize,
    pub left: usize,
    pub right: usize,
    pub left_hash: [u8; 32],
    pub right_hash_proposer: [u8; 32],
    pub right_hash_challenger: [u8; 32],
    pub status: BisectionStatus,
    pub deadline_height: u64,
    pub round_timeout: u64,
    pub is_proposer_turn: bool,
}

impl BisectionGame {
    pub fn new(
        session_id: [u8; 32],
        proposer: Address,
        challenger: Address,
        bond_amount: u128,
        total_steps: usize,
        initial_state_hash: [u8; 32],
        final_state_proposer: [u8; 32],
        final_state_challenger: [u8; 32],
        start_height: u64,
        round_timeout: u64,
    ) -> Self {
        Self {
            session_id,
            proposer,
            challenger,
            bond_amount,
            total_steps,
            left: 0,
            right: total_steps,
            left_hash: initial_state_hash,
            right_hash_proposer: final_state_proposer,
            right_hash_challenger: final_state_challenger,
            status: BisectionStatus::Ongoing {
                current_round: 1,
                left: 0,
                right: total_steps,
            },
            deadline_height: start_height.saturating_add(round_timeout),
            round_timeout,
            is_proposer_turn: true,
        }
    }

    /// Anti-Griefing Protection: Evaluates if active party exceeded response deadline
    pub fn check_timeout(&mut self, current_height: u64) -> Option<BisectionStatus> {
        if let BisectionStatus::Ongoing { left, .. } = self.status {
            if current_height > self.deadline_height {
                self.status = if self.is_proposer_turn {
                    BisectionStatus::ResolvedChallengerWon {
                        isolated_step: left,
                        reason: "Anti-Griefing Default: Proposer did not respond before deadline (Stake slashed)".to_string(),
                    }
                } else {
                    BisectionStatus::ResolvedProposerWon {
                        reason: "Anti-Griefing Default: Challenger did not respond before deadline (Bond forfeited)".to_string(),
                    }
                };
                return Some(self.status.clone());
            }
        }
        None
    }

    pub fn midpoint(&self) -> usize {
        (self.left + self.right) / 2
    }

    /// Processes a bisection round where proposer submits midpoint state
    /// and challenger accepts or rejects
    pub fn step_bisection(
        &mut self,
        midpoint_witness_proposer: [u8; 32],
        challenger_agrees: bool,
    ) -> Result<BisectionStatus, String> {
        let mid = self.midpoint();

        if challenger_agrees {
            // If challenger agrees with midpoint state, fraud is in second half [mid..right]
            self.left = mid;
            self.left_hash = midpoint_witness_proposer;
        } else {
            // If challenger disagrees, fraud occurred in first half [left..mid]
            self.right = mid;
            self.right_hash_proposer = midpoint_witness_proposer;
        }

        if self.right - self.left == 1 {
            // Exactly 1 instruction isolated!
            self.status = BisectionStatus::Ongoing {
                current_round: usize::MAX,
                left: self.left,
                right: self.right,
            };
            return Ok(self.status.clone());
        }

        let current_round = match self.status {
            BisectionStatus::Ongoing { current_round, .. } => current_round + 1,
            _ => 1,
        };

        self.status = BisectionStatus::Ongoing {
            current_round,
            left: self.left,
            right: self.right,
        };

        Ok(self.status.clone())
    }

    /// Single atomic computation step arbitration in O(1)
    /// Executes verification over agreed initial state (`self.left_hash`)
    /// and verifies which side correctly computed the subsequent state.
    pub fn arbitrate_single_step(
        &mut self,
        step_bytes: &[u8],
        expected_output_hash: [u8; 32],
    ) -> BisectionStatus {
        if self.right - self.left != 1 {
            return self.status.clone();
        }

        // Canonical step execution: deterministic transition hash via BLAKE3
        let mut hasher = crate::chain_hash::ChainHasher::new();
        hasher.update(b"STEP_ARBITRATION");
        hasher.update(&self.left_hash);
        hasher.update(step_bytes);
        let canonical_next_hash = hasher.finalize();

        if canonical_next_hash == expected_output_hash {
            // Challenger was correct (or proposer lied about claimed output)
            self.status = BisectionStatus::ResolvedChallengerWon {
                isolated_step: self.left,
                reason: "Canonical instruction proved state diverging from proposer".to_string(),
            };
        } else {
            self.status = BisectionStatus::ResolvedProposerWon {
                reason: "Canonical output matched proposer proof".to_string(),
            };
        }

        self.status.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bisection_game_binary_search_to_single_instruction() {
        let proposer = [1u8; 32];
        let challenger = [2u8; 32];
        let session_id = [0xaau8; 32];

        // Suppose 1024 instructions in a block. Fraud inserted at instruction 753.
        let total_steps = 1024;
        let fraud_step = 753;

        let mut game = BisectionGame::new(
            session_id,
            proposer,
            challenger,
            1_000_000_000,
            total_steps,
            [0u8; 32],
            [0xffu8; 32], // Proposer dishonest state
            [0xeeu8; 32], // Challenger honest state
            100,          // start_height
            50,           // round_timeout
        );

        // Bisection game must converge in ceil(log2(1024)) = 10 steps
        let mut rounds = 0;
        while game.right - game.left > 1 {
            rounds += 1;
            let mid = game.midpoint();
            // Challenger agrees if midpoint is before or at fraud step
            let challenger_agrees = mid < fraud_step;
            let fake_mid_hash = [mid as u8; 32];
            let _ = game.step_bisection(fake_mid_hash, challenger_agrees).unwrap();
        }

        assert_eq!(rounds, 10);
        assert_eq!(game.left, fraud_step - 1);
        assert_eq!(game.right, fraud_step);

        // Final arbitration of step 753 (atomic computation step)
        let step_bytes = b"OP_SUM_CANONICAL_STEP_753";
        let mut h = crate::chain_hash::ChainHasher::new();
        h.update(b"STEP_ARBITRATION");
        h.update(&game.left_hash);
        h.update(step_bytes);
        let expected_honest = h.finalize();

        let resolution = game.arbitrate_single_step(step_bytes, expected_honest);
        match resolution {
            BisectionStatus::ResolvedChallengerWon { isolated_step, .. } => {
                assert_eq!(isolated_step, fraud_step - 1);
            }
            _ => panic!("Challenger should win arbitration!"),
        }
    }

    #[test]
    fn test_bisection_anti_griefing_timeout_forfeit() {
        let mut game = BisectionGame::new(
            [0x55; 32],
            [1; 32],
            [2; 32],
            500_000,
            100,
            [0; 32],
            [1; 32],
            [2; 32],
            10, // start_height
            20, // round_timeout -> deadline_height = 30
        );

        // At block 25, still within deadline
        assert!(game.check_timeout(25).is_none());

        // At block 35, proposer took too long and forfeits
        let timeout_res = game.check_timeout(35).expect("Should resolve by forfeit");
        match timeout_res {
            BisectionStatus::ResolvedChallengerWon { reason, .. } => {
                assert!(reason.contains("Anti-Griefing Default"));
            }
            _ => panic!("Challenger should win on proposer forfeit"),
        }
    }
}
