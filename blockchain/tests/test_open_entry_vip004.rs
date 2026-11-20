//! VIP-004: open validator entry by stake, entry churn, equivocation slashing with
//! tombstone, time-based unbonding, and the anti-cartel limits on governance votes.

use ed25519_dalek::{Signer, SigningKey};
use vera_blockchain::account::{
    address_from_pubkey, address_to_hex, Account, Address, STAKING_SYSTEM_ADDRESS, VALIDATOR_SET_CSMT_KEY,
};
use vera_blockchain::chain_hash::hash256;
use vera_blockchain::consensus::{UnbondingEntry, Validator, ValidatorSet, Vote, VoteType};
use vera_blockchain::csmt::CSMT;
use vera_blockchain::genesis::{GenesisAccount, GenesisConfig};
use vera_blockchain::governance::{self, apply_op, load_proposal, FailCode, GovAction, GovCtx, GovOp, GovTiming, ProposalStatus};
use vera_blockchain::node::FullNode;
use vera_blockchain::open_staking::{
    self, apply_evidence, churn_used, load_state, process_block, queue_stake, unstake, EquivocationTracker, Evidence,
    OpenConfig, OpenState, OpenTiming, SignedProposal, EVIDENCE_SYSTEM_ADDRESS,
};
use vera_blockchain::p2p::messages::TmProposal;
use vera_blockchain::registry::DEFAULT_MIN_GAS_PRICE_WEI;
use vera_blockchain::state_transition::BURN_ADDRESS;
use vera_blockchain::transaction::Transaction;

const VERA: u128 = 1_000_000_000_000_000_000;
const CHAIN: &str = "vera-mainnet";
const DAY: u64 = 86_400;
const T0: u64 = 1_000_000;
const UNBOND: u64 = OpenTiming::PRODUCTION.unbonding_secs;
const GOV_KEY: Address = [0xee; 32];

fn cfg() -> OpenConfig {
    OpenConfig { timing: OpenTiming::PRODUCTION, chain_id_hash: hash256(CHAIN.as_bytes()) }
}
fn key(i: u8) -> SigningKey {
    SigningKey::from_bytes(&[i; 32])
}
fn pk(i: u8) -> [u8; 32] {
    key(i).verifying_key().to_bytes()
}
fn addr(i: u8) -> Address {
    address_from_pubkey(&pk(i))
}

fn balance(c: &CSMT, a: &Address) -> u128 {
    c.get(a).and_then(|b| Account::from_bytes(b).ok()).map_or(0, |x| x.balance)
}
fn credit(c: &mut CSMT, a: Address, amount: u128) {
    let mut acc = c.get(&a).and_then(|b| Account::from_bytes(b).ok()).unwrap_or(Account::new(0));
    acc.balance += amount;
    c.insert(a, acc.to_bytes());
}

/// Permissioned set (index, stake), min stake 10, governance key; VIP-004 activates at
/// height `act` (the state below is at height 1, T0).
fn base(vals: &[(u8, u128)], act: u64) -> CSMT {
    let mut c = CSMT::new();
    let validators: Vec<Validator> = vals
        .iter()
        .map(|&(i, stake)| Validator { address: addr(i), public_key: pk(i), stake, missed_blocks: 0, is_jailed: false })
        .collect();
    let vs = ValidatorSet::with_params(
        validators,
        10,
        50,
        5,
        10,
        true,
        Some(GOV_KEY),
        vals.iter().map(|&(i, _)| addr(i)).collect(),
    );
    c.insert(VALIDATOR_SET_CSMT_KEY, vs.to_bytes());
    credit(&mut c, STAKING_SYSTEM_ADDRESS, vals.iter().map(|v| v.1).sum());
    process_block(&mut c, 1, T0, Some(act), cfg()).unwrap();
    c
}
fn state(vals: &[(u8, u128)]) -> CSMT {
    base(vals, 1)
}
fn block(c: &mut CSMT, h: u64, ts: u64) {
    process_block(c, h, ts, Some(1), cfg()).unwrap();
}
fn vset(c: &CSMT) -> ValidatorSet {
    ValidatorSet::from_bytes(c.get(&VALIDATOR_SET_CSMT_KEY).unwrap()).unwrap()
}
fn ost(c: &CSMT) -> OpenState {
    load_state(c).unwrap().unwrap()
}
fn stake_of(c: &CSMT, i: u8) -> u128 {
    vset(c).validators.iter().find(|v| v.public_key == pk(i)).map_or(0, |v| v.stake)
}
fn is_active(c: &CSMT, i: u8) -> bool {
    vset(c).active_validators().iter().any(|v| v.public_key == pk(i))
}
/// Stake transaction effect: queue + funds into the staking account.
fn stake(c: &mut CSMT, i: u8, amount: u128, ts: u64) -> Result<(), String> {
    queue_stake(c, addr(i), pk(i), amount, ts)?;
    credit(c, STAKING_SYSTEM_ADDRESS, amount);
    Ok(())
}

fn vote(i: u8, chain: &str, height: u64, round: u64, hash: u8) -> Vote {
    Vote::new(chain, height, round, [hash; 32], VoteType::PreVote, &key(i))
}
fn dup_vote(i: u8, height: u64) -> Evidence {
    Evidence::DuplicateVote { a: vote(i, CHAIN, height, 0, 1), b: vote(i, CHAIN, height, 0, 2) }
}
fn proposal(i: u8, height: u64, round: u64, hash: u8) -> SignedProposal {
    let digest = TmProposal::signing_digest(CHAIN, height, round, None, &[hash; 32], &pk(i));
    SignedProposal {
        chain_id: CHAIN.into(),
        height,
        round,
        valid_round: None,
        block_hash: [hash; 32],
        proposer_pubkey: pk(i),
        signature: key(i).sign(&digest).to_bytes(),
    }
}

// ------------------------------------------------------------------ activation and entry

#[test]
fn activation_opens_entry_and_raises_liveness_floor() {
    let c = base(&[(1, 1_000)], 5);
    assert!(load_state(&c).unwrap().is_none(), "not before the activation height");
    assert!(vset(&c).permissioned_validators);

    let c = state(&[(1, 1_000)]);
    let st = ost(&c);
    assert_eq!((st.activated_height, st.timing), (1, OpenTiming::PRODUCTION));
    assert_eq!(st.chain_id_hash, hash256(CHAIN.as_bytes()));
    let vs = vset(&c);
    assert!(!vs.permissioned_validators && vs.allowlist.is_empty());
    assert_eq!(vs.max_missed_blocks, open_staking::MIN_MAX_MISSED_BLOCKS);
}

#[test]
fn anyone_with_the_minimum_stake_enters_through_the_queue() {
    let mut c = state(&[(1, 1_000)]);
    assert!(stake(&mut c, 9, 9, T0).is_err(), "below the minimum stake");
    stake(&mut c, 9, 10, T0).unwrap();
    assert_eq!(stake_of(&c, 9), 0, "queued, not active yet");
    assert_eq!(ost(&c).queue.len(), 1);
    block(&mut c, 2, T0 + 5);
    assert_eq!(stake_of(&c, 9), 10);
    assert!(is_active(&c, 9), "no approval needed");
    assert!(ost(&c).queue.is_empty());
}

#[test]
fn a_larger_stake_displaces_the_smallest_when_the_set_is_full() {
    let mut c = state(&[(1, 1_000), (2, 1_000), (3, 20)]);
    let mut vs = vset(&c);
    vs.max_active_validators = 3;
    c.insert(VALIDATOR_SET_CSMT_KEY, vs.to_bytes());
    stake(&mut c, 4, 50, T0).unwrap();
    block(&mut c, 2, T0 + 5);
    assert!(is_active(&c, 4) && !is_active(&c, 3), "50 displaces 20 in a set of 3");
    assert_eq!(stake_of(&c, 3), 20, "the displaced validator keeps its stake");
}

#[test]
fn churn_limits_new_stake_per_rolling_day_in_queue_order() {
    // Active 2,000 → at most 100 per day (1/20).
    let mut c = state(&[(1, 2_000)]);
    stake(&mut c, 8, 250, T0).unwrap();
    stake(&mut c, 9, 20, T0 + 1).unwrap();
    block(&mut c, 2, T0 + 10);
    assert_eq!(stake_of(&c, 8), 100, "first window: 100 of 250");
    assert_eq!(churn_used(&ost(&c), T0 + 10), 100);
    block(&mut c, 3, T0 + DAY / 2);
    assert_eq!(stake_of(&c, 8), 105, "active is now 2,100 → limit 105, 100 used");
    assert_eq!(stake_of(&c, 9), 0, "FIFO: the second entry waits for the first");
    block(&mut c, 4, T0 + DAY - 3_600);
    assert_eq!(stake_of(&c, 8), 105, "nothing more within 24 h");
    // The first bucket leaves the window; the 12 h one still counts.
    block(&mut c, 5, T0 + DAY + 2 * 3_600);
    assert_eq!(stake_of(&c, 8), 205);
    for (h, d) in (6..).zip(2..6u64) {
        block(&mut c, h, T0 + d * DAY + 2 * 3_600);
    }
    assert_eq!(stake_of(&c, 8), 250);
    assert_eq!(stake_of(&c, 9), 20, "the second entry follows once the first is in");
    assert!(ost(&c).queue.is_empty());
}

#[test]
fn queued_stake_is_bounded_per_key() {
    let mut c = state(&[(1, 100)]);
    for i in 0..open_staking::MAX_QUEUED_PER_KEY as u8 {
        stake(&mut c, 9, 10, T0).unwrap();
        stake(&mut c, 10 + i, 10, T0).unwrap();
    }
    assert!(stake(&mut c, 9, 10, T0).is_err(), "the per-key queue limit applies");
}

// ------------------------------------------------------------------ unbonding by time

#[test]
fn unbonding_is_released_by_time_not_blocks() {
    let mut c = state(&[(1, 1_000), (2, 100)]);
    assert!(unstake(&mut c, &pk(2), 95, 7, T0).is_err(), "remaining 5 < minimum 10");
    assert_eq!(unstake(&mut c, &pk(2), 0, 7, T0).unwrap(), 100, "0 = everything");
    let vs = vset(&c);
    assert_eq!(stake_of(&c, 2), 0);
    let e = vs.unbonding_queue.last().unwrap();
    assert_eq!((e.release_ts, e.start_height, e.public_key), (Some(T0 + UNBOND), Some(7), Some(pk(2))));
    let mut vs2 = vs.clone();
    assert!(vs2.process_maturing_unbondings(u64::MAX, T0 + UNBOND - 1).is_empty(), "blocks do not release it");
    assert_eq!(vs2.process_maturing_unbondings(8, T0 + UNBOND), vec![(addr(2), 100)]);
    assert!(UNBOND >= open_staking::MIN_UNBONDING_SECS);
}

#[test]
fn queued_stake_is_unstaked_first() {
    let mut c = state(&[(1, 2_000), (2, 100)]);
    stake(&mut c, 2, 50, T0).unwrap();
    assert_eq!(unstake(&mut c, &pk(2), 30, 3, T0).unwrap(), 30);
    assert_eq!(ost(&c).queue[0].amount, 20, "taken from the queue");
    assert_eq!(stake_of(&c, 2), 100, "bonded stake untouched");
}

// ------------------------------------------------------------------ equivocation

#[test]
fn equivocation_slashes_five_percent_tombstones_and_forces_exit() {
    let mut c = state(&[(1, 1_000), (2, 1_000), (3, 1_000), (4, 1_000)]);
    let staking_before = balance(&c, &STAKING_SYSTEM_ADDRESS);
    let logs = apply_evidence(&mut c, &dup_vote(2, 5), 6, T0 + 60).unwrap();
    assert_eq!(logs.len(), 1);
    assert_eq!(stake_of(&c, 2), 0, "removed from the set");
    let st = ost(&c);
    assert_eq!(st.tombstoned, vec![pk(2)]);
    assert_eq!((st.offenders[0].base_stake, st.offenders[0].slashed), (1_000, 50));
    let e = vset(&c).unbonding_queue.into_iter().find(|e| e.public_key == Some(pk(2))).unwrap();
    assert_eq!((e.amount, e.release_ts), (950, Some(T0 + 60 + UNBOND)), "the rest unbonds, still slashable");
    assert_eq!(balance(&c, &BURN_ADDRESS), 50, "burned, nobody receives it");
    assert_eq!(balance(&c, &STAKING_SYSTEM_ADDRESS), staking_before - 50);

    // Tombstone: no second slash, no new stake, no unjail.
    assert!(apply_evidence(&mut c, &dup_vote(2, 5), 7, T0 + 70).is_err());
    assert!(stake(&mut c, 2, 2_000, T0 + 80).is_err());
    assert!(open_staking::check_unjail(&c, &pk(2)).is_err());
}

#[test]
fn duplicate_proposal_is_evidence_too() {
    let mut c = state(&[(1, 1_000), (2, 1_000), (3, 1_000), (4, 1_000)]);
    let ev = Evidence::DuplicateProposal { a: proposal(3, 4, 1, 7), b: proposal(3, 4, 1, 8) };
    apply_evidence(&mut c, &ev, 5, T0).unwrap();
    assert_eq!(ost(&c).tombstoned, vec![pk(3)]);
    let same = Evidence::DuplicateProposal { a: proposal(1, 4, 1, 7), b: proposal(1, 4, 2, 8) };
    assert!(apply_evidence(&mut c, &same, 5, T0).is_err(), "different rounds are not equivocation");
}

#[test]
fn invalid_evidence_is_refused() {
    let mut c = base(&[(1, 1_000), (2, 1_000), (3, 1_000)], 1);
    let refused = |c: &mut CSMT, ev: Evidence, h: u64| apply_evidence(c, &ev, h, T0).unwrap_err();
    let same_block = Evidence::DuplicateVote { a: vote(2, CHAIN, 5, 0, 1), b: vote(2, CHAIN, 5, 0, 1) };
    assert!(refused(&mut c, same_block, 6).contains("same block"));
    let other_round = Evidence::DuplicateVote { a: vote(2, CHAIN, 5, 0, 1), b: vote(2, CHAIN, 5, 1, 2) };
    assert!(refused(&mut c, other_round, 6).contains("same key"));
    let mut precommit = vote(2, CHAIN, 5, 0, 2);
    precommit = Vote::new(CHAIN, 5, 0, precommit.block_hash, VoteType::PreCommit, &key(2));
    assert!(refused(&mut c, Evidence::DuplicateVote { a: vote(2, CHAIN, 5, 0, 1), b: precommit }, 6).contains("same key"));
    let two_keys = Evidence::DuplicateVote { a: vote(2, CHAIN, 5, 0, 1), b: vote(3, CHAIN, 5, 0, 2) };
    assert!(refused(&mut c, two_keys, 6).contains("same key"));
    let testnet = Evidence::DuplicateVote { a: vote(2, "vera-testnet-1", 5, 0, 1), b: vote(2, "vera-testnet-1", 5, 0, 2) };
    assert!(refused(&mut c, testnet, 6).contains("another chain"), "a key reused on testnet is not slashed on mainnet");
    let mut forged = vote(2, CHAIN, 5, 0, 2);
    forged.signature[0] ^= 1;
    assert!(refused(&mut c, Evidence::DuplicateVote { a: vote(2, CHAIN, 5, 0, 1), b: forged }, 6).contains("signature"));
    assert!(refused(&mut c, dup_vote(2, 9), 6).contains("future"));
    assert!(refused(&mut c, dup_vote(7, 5), 6).contains("no stake"), "a key that never staked");
    assert!(ost(&c).tombstoned.is_empty());

    let mut late = base(&[(1, 1_000), (2, 1_000)], 10);
    process_block(&mut late, 10, T0, Some(10), cfg()).unwrap();
    assert!(refused(&mut late, dup_vote(2, 9), 11).contains("predates"), "no retroactive slashing");
}

#[test]
fn unbonding_stake_answers_for_offenses_before_the_exit() {
    let mut c = state(&[(1, 1_000), (2, 1_000), (3, 1_000), (4, 1_000), (5, 1_000), (6, 1_000)]);
    unstake(&mut c, &pk(2), 0, 10, T0).unwrap();
    unstake(&mut c, &pk(3), 0, 10, T0).unwrap();
    // Offense at height 10: the stake was still active for that height.
    apply_evidence(&mut c, &dup_vote(2, 10), 12, T0 + 5).unwrap();
    let e = vset(&c).unbonding_queue.into_iter().find(|e| e.public_key == Some(pk(2))).unwrap();
    assert_eq!(e.amount, 950);
    // Offense at height 11, after the exit: nothing was at risk.
    assert!(apply_evidence(&mut c, &dup_vote(3, 11), 12, T0 + 5).unwrap_err().contains("no stake"));
}

#[test]
fn correlated_slashing_takes_everything_once_a_third_equivocates() {
    // 6 × 1,000: the second offender brings the window to 2,000 = 1/3 of 6,000.
    let mut c = state(&[(1, 1_000), (2, 1_000), (3, 1_000), (4, 1_000), (5, 1_000), (6, 1_000)]);
    apply_evidence(&mut c, &dup_vote(5, 3), 4, T0).unwrap();
    assert_eq!(ost(&c).offenders[0].slashed, 50, "alone: 5%");
    apply_evidence(&mut c, &dup_vote(6, 3), 4, T0 + 100).unwrap();
    let st = ost(&c);
    assert_eq!(st.offenders.iter().map(|o| o.slashed).collect::<Vec<_>>(), vec![1_000, 1_000], "both lose everything");
    assert_eq!(balance(&c, &BURN_ADDRESS), 2_000);
    assert!(vset(&c).unbonding_queue.iter().all(|e| e.public_key != Some(pk(5)) && e.public_key != Some(pk(6))));

    // After one unbonding period the window resets: a lone offender is back to 5%.
    block(&mut c, 5, T0 + 100 + UNBOND);
    assert!(ost(&c).offenders.is_empty());
    apply_evidence(&mut c, &dup_vote(4, 5), 5, T0 + 100 + UNBOND).unwrap();
    assert_eq!(ost(&c).offenders[0].slashed, 50);
}

#[test]
fn tracker_reports_conflicting_messages_once_per_key_and_height() {
    let mut t = EquivocationTracker::default();
    assert!(t.on_vote(&vote(2, CHAIN, 5, 0, 1)).is_none());
    assert!(t.on_vote(&vote(2, CHAIN, 5, 0, 1)).is_none(), "the same vote again");
    assert!(t.on_vote(&vote(3, CHAIN, 5, 0, 2)).is_none(), "another key");
    let ev = t.on_vote(&vote(2, CHAIN, 5, 0, 2)).expect("conflict");
    assert!(ev.verify(&hash256(CHAIN.as_bytes())).is_ok());
    assert!(t.on_vote(&vote(2, CHAIN, 5, 0, 3)).is_none(), "reported once");
    assert!(t.on_proposal(proposal(4, 5, 0, 1)).is_none());
    assert!(t.on_proposal(proposal(4, 5, 0, 2)).is_some());
    assert!(t.on_vote(&vote(2, CHAIN, 6, 0, 9)).is_none(), "new height, fresh record");
}

// ------------------------------------------------------------------ anti-cartel

/// VIP-003 governance (production timing) on top of `base`.
fn gov_state(act: u64) -> CSMT {
    let mut c = base(&[(1, 1_000), (2, 1_000), (3, 1_000)], act);
    let mut vs = vset(&c);
    vs.max_missed_blocks = 100;
    c.insert(VALIDATOR_SET_CSMT_KEY, vs.to_bytes());
    governance::process_block(&mut c, 1, T0, Some(1), GovTiming::PRODUCTION).unwrap();
    c
}

fn propose_by(c: &mut CSMT, by: u8, a: GovAction, ts: u64) -> Result<u64, String> {
    let id = governance::load_state(c).unwrap().unwrap().next_id;
    apply_op(c, &GovOp::Propose { action: a, voting_period_secs: 3 * DAY }, &GovCtx { sender: addr(by), height: 2, timestamp: ts })?;
    Ok(id)
}

fn propose(c: &mut CSMT, a: GovAction, ts: u64) -> Result<u64, String> {
    propose_by(c, 1, a, ts)
}

fn pass(c: &mut CSMT, id: u64, ts: u64) {
    for i in [1, 2] {
        apply_op(c, &GovOp::Vote { id, yes: true }, &GovCtx { sender: addr(i), height: 2, timestamp: ts }).unwrap();
    }
}

fn status(c: &CSMT, id: u64) -> ProposalStatus {
    load_proposal(c, id).unwrap().unwrap().status
}

fn closing_actions() -> Vec<(GovAction, FailCode)> {
    vec![
        (GovAction::Disallow { address: addr(3) }, FailCode::ClosesEntry),
        (GovAction::SetMaxActiveValidators { count: 49 }, FailCode::ClosesEntry),
        (GovAction::SetMinValidatorStake { wei: 11 }, FailCode::ClosesEntry),
        (GovAction::SetMaxMissedBlocks { blocks: 60 }, FailCode::BelowFloor),
        (GovAction::Allow { address: addr(9) }, FailCode::InvalidAction),
        (GovAction::SetUnbondingPeriodBlocks { blocks: 100 }, FailCode::InvalidAction),
    ]
}

#[test]
fn votes_that_close_entry_are_refused_when_proposed() {
    let mut c = gov_state(1);
    for (a, code) in closing_actions() {
        let e = propose(&mut c, a.clone(), T0).unwrap_err();
        assert!(e.contains(&format!("VIP-004 ({:?})", code)), "{:?}: {}", a, e);
    }
    for secs in [open_staking::MIN_UNBONDING_SECS - 1, open_staking::MAX_UNBONDING_SECS + 1] {
        assert!(propose(&mut c, GovAction::SetUnbondingPeriodSecs { secs }, T0).is_err());
    }
}

#[test]
fn votes_that_open_entry_further_still_pass() {
    let mut c = gov_state(1);
    let mut ts = T0;
    for a in [
        GovAction::SetMaxActiveValidators { count: 60 },
        GovAction::SetMinValidatorStake { wei: 5 },
        GovAction::SetMaxMissedBlocks { blocks: 200 },
        GovAction::SetUnbondingPeriodSecs { secs: 28 * DAY },
    ] {
        let id = propose(&mut c, a.clone(), ts).unwrap();
        pass(&mut c, id, ts);
        ts += GovTiming::PRODUCTION.timelock_secs;
        governance::process_block(&mut c, 3, ts, Some(1), GovTiming::PRODUCTION).unwrap();
        assert!(matches!(status(&c, id), ProposalStatus::Executed { .. }), "{:?}: {:?}", a, status(&c, id));
    }
    let vs = vset(&c);
    assert_eq!((vs.max_active_validators, vs.min_validator_stake, vs.max_missed_blocks), (60, 5, 200));
    assert_eq!(ost(&c).timing.unbonding_secs, 28 * DAY);
}

#[test]
fn closing_votes_passed_before_vip004_fail_at_execution_with_fixed_codes() {
    // Governance first; VIP-004 activates at height 10, while the proposals wait.
    let mut c = gov_state(10);
    assert!(propose(&mut c, GovAction::SetUnbondingPeriodSecs { secs: 28 * DAY }, T0).is_err(), "needs VIP-004");
    let ids: Vec<(u64, FailCode)> = closing_actions()
        .into_iter()
        .zip([1u8, 2, 3].into_iter().cycle())
        .map(|((a, code), by)| {
            let id = propose_by(&mut c, by, a, T0).unwrap();
            pass(&mut c, id, T0);
            (id, code)
        })
        .collect();
    let ts = T0 + GovTiming::PRODUCTION.timelock_secs;
    // Block 10: VIP-004 activates (step 2b), then governance executes (step 5).
    process_block(&mut c, 10, ts, Some(10), cfg()).unwrap();
    governance::process_block(&mut c, 10, ts, Some(1), GovTiming::PRODUCTION).unwrap();
    for (id, code) in ids {
        assert_eq!(status(&c, id), ProposalStatus::Failed { at: ts, code }, "proposal {}", id);
    }
    let vs = vset(&c);
    assert_eq!((vs.max_active_validators, vs.min_validator_stake, vs.max_missed_blocks), (50, 10, 100), "nothing changed");
}

// ------------------------------------------------------------------ compatibility

#[test]
fn state_before_vip004_keeps_its_bytes() {
    let old = UnbondingEntry {
        validator_address: [1; 32],
        amount: 5,
        release_height: 9,
        release_ts: None,
        start_height: None,
        public_key: None,
    };
    let json = String::from_utf8(serde_json::to_vec(&old).unwrap()).unwrap();
    assert!(!json.contains("release_ts") && !json.contains("start_height") && !json.contains("public_key"), "{}", json);
    let parsed: UnbondingEntry = serde_json::from_str(r#"{"validator_address":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],"amount":5,"release_height":9}"#).unwrap();
    assert_eq!(parsed, old);

    let mut c = base(&[(1, 1_000)], 1);
    let mut never = CSMT::new();
    never.insert(VALIDATOR_SET_CSMT_KEY, c.get(&VALIDATOR_SET_CSMT_KEY).unwrap().to_vec());
    let root = never.root();
    process_block(&mut never, 50, T0, None, cfg()).unwrap();
    assert_eq!(never.root(), root, "not scheduled: no write at all");
    block(&mut c, 2, T0 + 1);
}

// ------------------------------------------------------------------ two nodes

#[tokio::test]
async fn nodes_open_entry_queue_stake_and_slash_on_evidence() {
    let (mut cfg, vk) = GenesisConfig::default_testnet();
    cfg.initial_validators[0].stake = (1_000 * VERA).to_string();
    let user = key(41);
    let reporter = key(42);
    let val_addr = address_from_pubkey(&vk.verifying_key().to_bytes());
    for (a, amount) in [(address_from_pubkey(&pk(41)), 100 * VERA), (address_from_pubkey(&pk(42)), 10 * VERA), (val_addr, 10 * VERA)] {
        cfg.initial_accounts.push(GenesisAccount { address: address_to_hex(&a), balance: amount.to_string() });
    }
    cfg.governance_address = Some(address_to_hex(&address_from_pubkey(&pk(42))));
    cfg.registry_activation_height = Some(1);
    cfg.open_entry_activation_height = Some(1);
    let dir = |t: &str| std::env::temp_dir().join(format!("vera_vip004_{}_{}", t, rand::random::<u64>()));
    let mut n = FullNode::load_or_init(&dir("a"), &cfg, Some(vk.clone())).unwrap();
    let mut f = FullNode::load_or_init(&dir("b"), &cfg, None).unwrap();
    let nonce = |n: &FullNode, a: &Address| n.csmt.get(a).and_then(|b| Account::from_bytes(b).ok()).map_or(0, |x| x.nonce);
    let tx = |n: &FullNode, k: &SigningKey, to: Address, amount: u128, p: Vec<u8>| {
        let a = address_from_pubkey(&k.verifying_key().to_bytes());
        Transaction::new(&n.chain_id, k, nonce(n, &a), Some(to), amount, 40_000 + 10 * p.len() as u64, DEFAULT_MIN_GAS_PRICE_WEI, p)
    };
    async fn step(n: &mut FullNode, f: &mut FullNode) {
        let b = n.build_proposal().await.expect("build");
        f.validate_proposal(&b).await.expect("follower validates");
        f.apply_block(b.clone()).await.unwrap();
        n.apply_block(b).await.unwrap();
        assert_eq!(n.csmt.root(), f.csmt.root());
    }

    // Block 1: activation. The user stakes 40 VERA without any approval.
    n.submit_transaction(tx(&n, &user, STAKING_SYSTEM_ADDRESS, 40 * VERA, Vec::new())).unwrap();
    step(&mut n, &mut f).await;
    assert!(load_state(&f.csmt).unwrap().is_some());
    assert_eq!(ost(&f.csmt).queue.len(), 1, "queued in the block that took the stake");
    // The allowlist is gone for everyone, including the governance key.
    let gov_key_tx = tx(&n, &reporter, STAKING_SYSTEM_ADDRESS, 0, format!("allow:{}", address_to_hex(&[7u8; 32])).into_bytes());
    assert!(n.submit_transaction(gov_key_tx).is_err());
    // Block 2: admitted (40 ≤ 1,000 / 20), the user is an active validator.
    n.submit_transaction(tx(&n, &reporter, address_from_pubkey(&pk(43)), 1, Vec::new())).unwrap();
    step(&mut n, &mut f).await;
    assert!(vset(&f.csmt).active_validators().iter().any(|v| v.public_key == pk(41)));

    // The user's key signs two prevotes for one round; the node reports it with its own key.
    let chain = n.chain_id.clone();
    let ev = Evidence::DuplicateVote {
        a: Vote::new(&chain, 2, 0, [1; 32], VoteType::PreVote, &user),
        b: Vote::new(&chain, 2, 0, [2; 32], VoteType::PreVote, &user),
    };
    n.submit_evidence(&ev).unwrap();
    step(&mut n, &mut f).await;
    let st = ost(&f.csmt);
    assert_eq!(st.tombstoned, vec![pk(41)]);
    assert_eq!(balance(&f.csmt, &BURN_ADDRESS) >= 2 * VERA, true, "5% of 40 VERA burned");
    assert!(!vset(&f.csmt).validators.iter().any(|v| v.public_key == pk(41)));
    // The same evidence again is refused at admission.
    let again = tx(&n, &reporter, EVIDENCE_SYSTEM_ADDRESS, 0, ev.encode());
    assert!(n.submit_transaction(again).is_err());
}

#[tokio::test]
async fn evidence_is_refused_before_activation() {
    let (mut cfg, vk) = GenesisConfig::default_testnet();
    cfg.open_entry_activation_height = Some(100);
    let dir = std::env::temp_dir().join(format!("vera_vip004_pre_{}", rand::random::<u64>()));
    let mut n = FullNode::load_or_init(&dir, &cfg, Some(vk.clone())).unwrap();
    let ev = Evidence::DuplicateVote { a: vote(2, "vera-testnet-1", 1, 0, 1), b: vote(2, "vera-testnet-1", 1, 0, 2) };
    assert!(n.submit_evidence(&ev).unwrap_err().contains("not active"));
}

#[test]
fn unbonding_cuts_count_against_the_window_peak() {
    // 21 → 60 days, then 29 days within the same 7-day window: each vote is "at most half"
    // of the value before it, but 29 is less than half of the window's 60.
    let mut c = gov_state(1);
    let ts = T0;
    let up = propose(&mut c, GovAction::SetUnbondingPeriodSecs { secs: 60 * DAY }, ts).unwrap();
    let down = propose_by(&mut c, 2, GovAction::SetUnbondingPeriodSecs { secs: 29 * DAY }, ts).unwrap();
    pass(&mut c, up, ts);
    pass(&mut c, down, ts);
    let t = ts + GovTiming::PRODUCTION.timelock_secs;
    governance::process_block(&mut c, 3, t, Some(1), GovTiming::PRODUCTION).unwrap();
    assert!(matches!(status(&c, up), ProposalStatus::Executed { .. }));
    assert_eq!(status(&c, down), ProposalStatus::Failed { at: t, code: FailCode::BelowFloor });
    assert_eq!(ost(&c).timing.unbonding_secs, 60 * DAY);
}

#[tokio::test]
async fn only_active_validators_can_miss_blocks() {
    use vera_blockchain::block::{Block, BlockHeader, ValidatorCommit};
    use vera_blockchain::state_transition::{ForkHeights, StateTransitionEngine};
    // Set of 3: 1 and 5 sign, 2 is active and silent, 3 is displaced (20), 4 is still
    // entering (5 < minimum 10). Only 2 is jailed; 3 takes its seat after that and only
    // then starts counting.
    async fn run(act: u64) -> ValidatorSet {
        let mut c = base(&[(1, 1_000), (2, 1_000), (5, 1_000), (3, 20), (4, 5)], act);
        let mut vs = vset(&c);
        vs.max_active_validators = 3;
        vs.max_missed_blocks = 100;
        c.insert(VALIDATOR_SET_CSMT_KEY, vs.to_bytes());
        let forks = ForkHeights { open_entry: Some(act), open_timing: OpenTiming::PRODUCTION, chain_id_hash: hash256(CHAIN.as_bytes()), ..Default::default() };
        for h in 2..=105u64 {
            let header = BlockHeader {
                height: h,
                prev_hash: [0; 32],
                timestamp: T0 + h,
                state_root: [0; 32],
                tx_root: [0; 32],
                receipts_root: [0; 32],
                proposer: addr(1),
                last_commit_hash: [0; 32],
            };
            let mut b = Block::new(header, Vec::new(), Vec::new());
            b.last_commit = vec![ValidatorCommit::new(pk(1), [0; 64]), ValidatorCommit::new(pk(5), [0; 64])];
            StateTransitionEngine::execute_block_with_forks(&mut c, &mut b, 83721, None, forks).await.unwrap();
        }
        vset(&c)
    }
    let get = |vs: &ValidatorSet, i: u8| vs.validators.iter().find(|v| v.public_key == pk(i)).unwrap().clone();
    let vs = run(1).await;
    assert!(get(&vs, 2).is_jailed, "an active validator that never signs is jailed");
    let (v3, v4) = (get(&vs, 3), get(&vs, 4));
    assert!(!v3.is_jailed && v3.missed_blocks < 10, "displaced: counted only since it took the seat ({:?})", v3);
    assert!(!v4.is_jailed && v4.missed_blocks == 0, "still entering: cannot sign, cannot miss");
    // Before VIP-004 the old rule is unchanged (every non-jailed validator counts).
    let vs = run(1_000).await;
    assert!(get(&vs, 3).is_jailed && get(&vs, 4).is_jailed, "pre-VIP-004 behaviour kept as is");
}

#[test]
fn evidence_never_empties_the_active_set() {
    let mut c = state(&[(1, 1_000)]);
    let e = apply_evidence(&mut c, &dup_vote(1, 1), 2, T0).unwrap_err();
    assert!(e.contains("no active validator"), "{}", e);
    assert!(ost(&c).tombstoned.is_empty() && stake_of(&c, 1) == 1_000, "nothing changed");
}
