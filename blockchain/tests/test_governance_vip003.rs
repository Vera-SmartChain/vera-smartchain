//! VIP-003: governance by validator vote, and the governance key's emergency pause.

use ed25519_dalek::SigningKey;
use vera_blockchain::account::{address_from_pubkey, address_to_hex, Account, Address, VALIDATOR_SET_CSMT_KEY};
use vera_blockchain::consensus::{Validator, ValidatorSet};
use vera_blockchain::csmt::CSMT;
use vera_blockchain::genesis::{GenesisAccount, GenesisConfig};
use vera_blockchain::governance::{
    self, apply_op, load_proposal, load_state, process_block, FailCode, GovAction, GovConfig, GovCtx, GovOp, GovTiming, ProposalStatus,
    EMERGENCY_POWER_SECS, GOVERNANCE_SYSTEM_ADDRESS, KEY_PAUSE_COOLDOWN_SECS, MAX_PAUSE_SECS,
};
use vera_blockchain::node::FullNode;
use vera_blockchain::registry::{self, ApplyCtx, FeeParams, RegistryOp, DEFAULT_FEE_PER_ITEM_WEI, DEFAULT_MIN_GAS_PRICE_WEI};
use vera_blockchain::transaction::Transaction;

const VERA: u128 = 1_000_000_000_000_000_000;
const T: GovTiming = GovTiming::PRODUCTION;
const DAY: u64 = 86_400;
const T0: u64 = 1_000_000;
const KEY: Address = [0xee; 32];

fn va(i: u8) -> Address {
    let mut a = [0u8; 32];
    a[0] = 0xa0;
    a[31] = i;
    a
}

/// State with VIP-001 and VIP-003 active at T0 and validators (index, stake).
fn state(vals: &[(u8, u128)]) -> CSMT {
    let mut c = CSMT::new();
    let mut vs = ValidatorSet::new(
        vals.iter()
            .map(|&(i, stake)| Validator { address: va(i), public_key: [i; 32], stake, missed_blocks: 0, is_jailed: false })
            .collect(),
    );
    vs.governance_address = Some(KEY);
    c.insert(VALIDATOR_SET_CSMT_KEY, vs.to_bytes());
    registry::activate_if_due(&mut c, 1, Some(1));
    process_block(&mut c, 1, T0, Some(1), T).unwrap();
    c
}

fn op(c: &mut CSMT, sender: Address, ts: u64, o: GovOp) -> Result<(), String> {
    apply_op(c, &o, &GovCtx { sender, height: 2, timestamp: ts }).map(|_| ())
}

fn propose(c: &mut CSMT, by: u8, ts: u64, action: GovAction) -> u64 {
    let id = load_state(c).unwrap().unwrap().next_id;
    op(c, va(by), ts, GovOp::Propose { action, voting_period_secs: 3 * DAY }).unwrap();
    id
}

fn status(c: &CSMT, id: u64) -> ProposalStatus {
    load_proposal(c, id).unwrap().unwrap().status
}

fn fee(c: &CSMT) -> u128 {
    registry::load_params(c).unwrap().unwrap().fee_per_item_wei
}

const NEW_FEE: GovAction = GovAction::SetFee { fee_per_item_wei: DEFAULT_FEE_PER_ITEM_WEI * 2 };

#[test]
fn activation_writes_state_with_emergency_window() {
    let c = state(&[(1, VERA)]);
    let st = load_state(&c).unwrap().unwrap();
    assert_eq!(st.next_id, 1);
    assert_eq!(st.emergency_until_ts, T0 + EMERGENCY_POWER_SECS);
    assert_eq!(st.timing, T);
}

#[test]
fn full_cycle_passes_waits_timelock_and_executes() {
    let mut c = state(&[(1, VERA), (2, VERA), (3, VERA)]);
    let id = propose(&mut c, 1, T0 + 10, NEW_FEE);
    op(&mut c, va(1), T0 + 20, GovOp::Vote { id, yes: true }).unwrap();
    assert_eq!(status(&c, id), ProposalStatus::Open, "1/3 is not enough");
    op(&mut c, va(2), T0 + 30, GovOp::Vote { id, yes: true }).unwrap();
    assert_eq!(status(&c, id), ProposalStatus::Passed { at: T0 + 30 }, "2 of 3 equal stakes = exactly the threshold");

    // Before the timelock: nothing changes.
    process_block(&mut c, 3, T0 + 30 + T.timelock_secs - 1, Some(1), T).unwrap();
    assert_eq!(fee(&c), DEFAULT_FEE_PER_ITEM_WEI);
    // At the timelock: executed.
    process_block(&mut c, 4, T0 + 30 + T.timelock_secs, Some(1), T).unwrap();
    assert_eq!(fee(&c), DEFAULT_FEE_PER_ITEM_WEI * 2);
    assert_eq!(status(&c, id), ProposalStatus::Executed { at: T0 + 30 + T.timelock_secs });
    assert!(load_state(&c).unwrap().unwrap().open.is_empty());
}

#[test]
fn threshold_boundary_just_below_and_exactly_at() {
    // Total 300: threshold = ceil(600 / 3) = 200.
    let mut c = state(&[(1, 199), (2, 1), (3, 100)]);
    let id = propose(&mut c, 1, T0, NEW_FEE);
    op(&mut c, va(1), T0, GovOp::Vote { id, yes: true }).unwrap();
    assert_eq!(status(&c, id), ProposalStatus::Open, "199 < 200");
    op(&mut c, va(3), T0, GovOp::Vote { id, yes: false }).unwrap();
    assert_eq!(status(&c, id), ProposalStatus::Open);
    op(&mut c, va(2), T0, GovOp::Vote { id, yes: true }).unwrap();
    assert_eq!(status(&c, id), ProposalStatus::Passed { at: T0 }, "200 = threshold");
}

#[test]
fn snapshot_isolation_late_stake_does_not_vote() {
    let mut c = state(&[(1, VERA), (2, VERA)]);
    let id = propose(&mut c, 1, T0, NEW_FEE);
    // A validator that joins (or adds stake) after the proposal cannot vote on it,
    // and extra stake of an existing validator does not count.
    let mut vs = ValidatorSet::from_bytes(c.get(&VALIDATOR_SET_CSMT_KEY).unwrap()).unwrap();
    vs.validators.push(Validator { address: va(9), public_key: [9; 32], stake: 100 * VERA, missed_blocks: 0, is_jailed: false });
    vs.validators[0].stake = 50 * VERA;
    c.insert(VALIDATOR_SET_CSMT_KEY, vs.to_bytes());
    assert!(op(&mut c, va(9), T0, GovOp::Vote { id, yes: true }).unwrap_err().contains("snapshot"));
    op(&mut c, va(1), T0, GovOp::Vote { id, yes: true }).unwrap();
    let p = load_proposal(&c, id).unwrap().unwrap();
    assert_eq!(p.yes_stake, VERA, "snapshot stake, not the new 50 VERA");
    assert_eq!(p.status, ProposalStatus::Open);
}

#[test]
fn only_validators_propose_and_vote_once() {
    let mut c = state(&[(1, VERA), (2, VERA)]);
    let r = op(&mut c, va(7), T0, GovOp::Propose { action: NEW_FEE, voting_period_secs: 3 * DAY });
    assert!(r.unwrap_err().contains("active validator"));
    let r = op(&mut c, va(1), T0, GovOp::Propose { action: NEW_FEE, voting_period_secs: DAY });
    assert!(r.unwrap_err().contains("voting period"));
    let r = op(&mut c, va(1), T0, GovOp::Propose { action: NEW_FEE, voting_period_secs: 15 * DAY });
    assert!(r.unwrap_err().contains("voting period"));
    let id = propose(&mut c, 1, T0, NEW_FEE);
    op(&mut c, va(2), T0, GovOp::Vote { id, yes: false }).unwrap();
    assert!(op(&mut c, va(2), T0, GovOp::Vote { id, yes: true }).unwrap_err().contains("already voted"));
}

#[test]
fn expiry_and_votes_after_deadline() {
    let mut c = state(&[(1, VERA), (2, VERA), (3, VERA)]);
    let id = propose(&mut c, 1, T0, NEW_FEE);
    op(&mut c, va(1), T0, GovOp::Vote { id, yes: true }).unwrap();
    let deadline = T0 + 3 * DAY;
    assert!(op(&mut c, va(2), deadline + 1, GovOp::Vote { id, yes: true }).unwrap_err().contains("ended"));
    process_block(&mut c, 5, deadline, Some(1), T).unwrap();
    assert_eq!(status(&c, id), ProposalStatus::Open, "still open at the deadline itself");
    process_block(&mut c, 6, deadline + 1, Some(1), T).unwrap();
    assert_eq!(status(&c, id), ProposalStatus::Expired { at: deadline + 1 });
    assert_eq!(fee(&c), DEFAULT_FEE_PER_ITEM_WEI);
}

#[test]
fn cancel_only_by_proposer_before_any_vote() {
    let mut c = state(&[(1, VERA), (2, VERA)]);
    let a = propose(&mut c, 1, T0, NEW_FEE);
    assert!(op(&mut c, va(2), T0, GovOp::Cancel { id: a }).unwrap_err().contains("proposer"));
    op(&mut c, va(1), T0, GovOp::Cancel { id: a }).unwrap();
    assert_eq!(status(&c, a), ProposalStatus::Cancelled { at: T0 });
    let b = propose(&mut c, 1, T0, NEW_FEE);
    op(&mut c, va(2), T0, GovOp::Vote { id: b, yes: false }).unwrap();
    assert!(op(&mut c, va(1), T0, GovOp::Cancel { id: b }).unwrap_err().contains("before any vote"));
}

#[test]
fn at_most_three_open_proposals_per_validator() {
    let mut c = state(&[(1, VERA), (2, VERA)]);
    for _ in 0..3 {
        propose(&mut c, 1, T0, NEW_FEE);
    }
    let r = op(&mut c, va(1), T0, GovOp::Propose { action: NEW_FEE, voting_period_secs: 3 * DAY });
    assert!(r.unwrap_err().contains("at most 3"));
    propose(&mut c, 2, T0, NEW_FEE); // another validator still can
}

#[test]
fn proposal_breaking_a_vip001_bound_fails_at_execution_and_changes_nothing() {
    let mut c = state(&[(1, VERA)]);
    let bad = GovAction::SetFee { fee_per_item_wei: DEFAULT_FEE_PER_ITEM_WEI * 3 }; // > 2x
    let id = propose(&mut c, 1, T0, bad);
    op(&mut c, va(1), T0, GovOp::Vote { id, yes: true }).unwrap();
    let before = c.root();
    process_block(&mut c, 3, T0 + T.timelock_secs, Some(1), T).unwrap();
    match status(&c, id) {
        ProposalStatus::Failed { code, .. } => assert_eq!(code, FailCode::RegistryRejected),
        s => panic!("expected Failed, got {:?}", s),
    }
    assert_eq!(fee(&c), DEFAULT_FEE_PER_ITEM_WEI);
    assert_ne!(c.root(), before, "only the proposal status and the open list changed");
}

#[test]
fn staking_parameters_and_allowlist_by_vote() {
    let mut c = state(&[(1, VERA)]);
    let actions = [
        GovAction::Allow { address: va(8) },
        GovAction::SetMinValidatorStake { wei: VERA / 2 },
        GovAction::SetMaxActiveValidators { count: 21 },
        GovAction::SetUnbondingPeriodBlocks { blocks: 77 },
        GovAction::SetMaxMissedBlocks { blocks: 33 },
    ];
    let mut ts = T0;
    for a in actions {
        let id = propose(&mut c, 1, ts, a);
        op(&mut c, va(1), ts, GovOp::Vote { id, yes: true }).unwrap();
        ts += T.timelock_secs;
        process_block(&mut c, 3, ts, Some(1), T).unwrap();
        assert!(matches!(status(&c, id), ProposalStatus::Executed { .. }));
    }
    let vs = ValidatorSet::from_bytes(c.get(&VALIDATOR_SET_CSMT_KEY).unwrap()).unwrap();
    assert!(vs.allowlist.contains(&va(8)));
    assert_eq!((vs.min_validator_stake, vs.max_active_validators, vs.unbonding_period_blocks, vs.max_missed_blocks), (VERA / 2, 21, 77, 33));
    let r = op(&mut c, va(1), ts, GovOp::Propose { action: GovAction::SetMaxActiveValidators { count: 0 }, voting_period_secs: 3 * DAY });
    assert!(r.is_err(), "static bounds refuse a hopeless proposal");
}

#[test]
fn governance_key_cannot_change_fees_or_registrar_after_activation() {
    let c = state(&[(1, VERA)]);
    let params = registry::load_params(&c).unwrap().unwrap();
    let ctx = |retired| ApplyCtx {
        sender: KEY,
        governance: Some(KEY),
        height: 2,
        timestamp: T0,
        by_vote: false,
        key_retired: retired,
        registrations_paused: false,
    };
    for o in [
        RegistryOp::SetFee { fee_per_item_wei: DEFAULT_FEE_PER_ITEM_WEI * 2 },
        RegistryOp::SetGasPrice { min_gas_price_wei: DEFAULT_MIN_GAS_PRICE_WEI * 2 },
        RegistryOp::SetRegistrar { addr: va(5) },
    ] {
        let mut before = c.clone();
        assert!(registry::apply(&mut before, &o, &params, &ctx(false)).is_ok(), "key works before VIP-003");
        let mut after = c.clone();
        assert!(registry::apply(&mut after, &o, &params, &ctx(true)).is_err(), "key rejected after VIP-003");
    }
    let _ = FeeParams::default();
}

#[test]
fn emergency_pause_rules() {
    let mut c = state(&[(1, VERA)]);
    // Only the key; at most 72 h.
    assert!(op(&mut c, va(1), T0, GovOp::PauseRegistry { duration_secs: 60 }).unwrap_err().contains("governance key"));
    assert!(op(&mut c, KEY, T0, GovOp::PauseRegistry { duration_secs: MAX_PAUSE_SECS + 1 }).is_err());
    op(&mut c, KEY, T0, GovOp::PauseRegistry { duration_secs: MAX_PAUSE_SECS }).unwrap();
    assert!(governance::registrations_paused(&c, T0 + 10).unwrap());
    assert!(!governance::registrations_paused(&c, T0 + MAX_PAUSE_SECS).unwrap(), "ends on its own");

    // Registrations are refused while paused; other registry ops still work.
    let params = registry::load_params(&c).unwrap().unwrap();
    let ctx = ApplyCtx { sender: va(4), governance: Some(KEY), height: 2, timestamp: T0 + 10, by_vote: false, key_retired: true, registrations_paused: true };
    let reg = RegistryOp::Register { kind: 1, doc_hash: [1; 32], parent: None };
    assert!(registry::apply(&mut c.clone(), &reg, &params, &ctx).unwrap_err().contains("paused"));

    // Not renewable by the key: no new pause for 30 days after the last one started.
    let after = T0 + MAX_PAUSE_SECS + 1;
    assert!(op(&mut c, KEY, after, GovOp::PauseRegistry { duration_secs: 60 }).unwrap_err().contains("30 days"));
    op(&mut c, KEY, T0 + KEY_PAUSE_COOLDOWN_SECS, GovOp::PauseRegistry { duration_secs: 60 }).unwrap();
    op(&mut c, KEY, T0 + KEY_PAUSE_COOLDOWN_SECS + 1, GovOp::Unpause).unwrap();
    assert!(!governance::registrations_paused(&c, T0 + KEY_PAUSE_COOLDOWN_SECS + 2).unwrap());

    // The power expires on its own.
    let late = T0 + EMERGENCY_POWER_SECS;
    assert!(op(&mut c, KEY, late, GovOp::PauseRegistry { duration_secs: 60 }).unwrap_err().contains("expired"));
}

#[test]
fn votes_can_unpause_and_end_the_emergency_power_early() {
    let mut c = state(&[(1, VERA)]);
    op(&mut c, KEY, T0, GovOp::PauseRegistry { duration_secs: MAX_PAUSE_SECS }).unwrap();
    // Voting takes days, so use a long pause scenario: the vote to unpause passes now.
    let id = propose(&mut c, 1, T0 + 1, GovAction::EndEmergencyPower);
    op(&mut c, va(1), T0 + 1, GovOp::Vote { id, yes: true }).unwrap();
    let id2 = propose(&mut c, 1, T0 + 1, GovAction::Unpause);
    op(&mut c, va(1), T0 + 1, GovOp::Vote { id: id2, yes: true }).unwrap();
    let ts = T0 + 1 + T.timelock_secs;
    process_block(&mut c, 3, ts, Some(1), T).unwrap();
    let st = load_state(&c).unwrap().unwrap();
    assert_eq!(st.emergency_until_ts, ts);
    assert!(!governance::registrations_paused(&c, ts).unwrap());
    let later = T0 + KEY_PAUSE_COOLDOWN_SECS + 1;
    assert!(op(&mut c, KEY, later, GovOp::PauseRegistry { duration_secs: 60 }).unwrap_err().contains("expired"));
}

// ------------------------------------------------------------------ full node level

fn gen_key(i: u8) -> SigningKey {
    SigningKey::from_bytes(&[i.wrapping_add(90); 32])
}

#[tokio::test]
async fn nodes_run_a_full_cycle_and_reject_the_key() {
    let (mut cfg, vk) = GenesisConfig::default_testnet();
    let gov = gen_key(1);
    let gov_addr = address_from_pubkey(&gov.verifying_key().to_bytes());
    cfg.initial_accounts.push(GenesisAccount { address: address_to_hex(&gov_addr), balance: (10 * VERA).to_string() });
    let val_addr = address_from_pubkey(&vk.verifying_key().to_bytes());
    cfg.initial_accounts.push(GenesisAccount { address: address_to_hex(&val_addr), balance: (10 * VERA).to_string() });
    cfg.governance_address = Some(address_to_hex(&gov_addr));
    cfg.registry_activation_height = Some(1);
    cfg.governance_activation_height = Some(1);
    cfg.governance_timing = Some(GovTiming { timelock_secs: 2, min_voting_secs: 1, max_voting_secs: 600 });
    let dir = |t: &str| std::env::temp_dir().join(format!("vera_vip003_{}_{}", t, rand::random::<u64>()));
    let mut n = FullNode::load_or_init(&dir("a"), &cfg, Some(vk.clone())).unwrap();
    let mut f = FullNode::load_or_init(&dir("b"), &cfg, None).unwrap();

    let nonce = |n: &FullNode, a: &Address| n.csmt.get(a).and_then(|b| Account::from_bytes(b).ok()).map_or(0, |x| x.nonce);
    let gtx = |n: &FullNode, k: &SigningKey, o: &GovOp| {
        let a = address_from_pubkey(&k.verifying_key().to_bytes());
        let p = o.encode();
        Transaction::new(&n.chain_id, k, nonce(n, &a), Some(GOVERNANCE_SYSTEM_ADDRESS), 0, 21_000 + 10 * p.len() as u64, DEFAULT_MIN_GAS_PRICE_WEI, p)
    };
    async fn step(n: &mut FullNode, f: &mut FullNode) {
        let b = n.build_proposal().await.expect("build");
        f.validate_proposal(&b).await.expect("follower validates");
        f.apply_block(b.clone()).await.unwrap();
        n.apply_block(b).await.unwrap();
        assert_eq!(n.csmt.root(), f.csmt.root());
    }

    // Block 1: the validator proposes; block 2: it votes (1 of 1 = passes).
    n.submit_transaction(gtx(&n, &vk, &GovOp::Propose { action: NEW_FEE, voting_period_secs: 60 })).unwrap();
    step(&mut n, &mut f).await;
    assert!(load_state(&n.csmt).unwrap().is_some());
    n.submit_transaction(gtx(&n, &vk, &GovOp::Vote { id: 1, yes: true })).unwrap();
    step(&mut n, &mut f).await;
    assert!(matches!(status(&n.csmt, 1), ProposalStatus::Passed { .. }));

    // The key can no longer use allow: (staking) or SET_FEE (registry).
    let allow = Transaction::new(&n.chain_id, &gov, nonce(&n, &gov_addr), Some(vera_blockchain::account::STAKING_SYSTEM_ADDRESS), 0, 30_000, DEFAULT_MIN_GAS_PRICE_WEI, format!("allow:{}", address_to_hex(&[7u8; 32])).into_bytes());
    // Testnet: the key keeps the allowlist (validators are approved there).
    n.submit_transaction(allow).unwrap();
    step(&mut n, &mut f).await;
    let vs = ValidatorSet::from_bytes(f.csmt.get(&VALIDATOR_SET_CSMT_KEY).unwrap()).unwrap();
    assert!(vs.allowlist.contains(&[7u8; 32]), "testnet key allow: works after VIP-003");
    assert!(load_state(&f.csmt).unwrap().unwrap().key_allowlist);
    let set_fee = RegistryOp::SetFee { fee_per_item_wei: DEFAULT_FEE_PER_ITEM_WEI * 2 }.encode();
    let k_fee = Transaction::new(&n.chain_id, &gov, nonce(&n, &gov_addr), Some(registry::REGISTRY_SYSTEM_ADDRESS), 0, 30_000, DEFAULT_MIN_GAS_PRICE_WEI, set_fee);
    assert!(n.submit_transaction(k_fee).is_err());

    // After the timelock, the next block executes the proposal on both nodes.
    std::thread::sleep(std::time::Duration::from_millis(2_200));
    n.submit_transaction(gtx(&n, &gov, &GovOp::PauseRegistry { duration_secs: 60 })).unwrap();
    step(&mut n, &mut f).await;
    assert!(matches!(status(&n.csmt, 1), ProposalStatus::Executed { .. }));
    assert_eq!(fee(&f.csmt), DEFAULT_FEE_PER_ITEM_WEI * 2);
    assert!(governance::registrations_paused(&f.csmt, load_state(&f.csmt).unwrap().unwrap().last_key_pause_ts).unwrap());
}

// ------------------------------------------------------------------ safety rails (review fix 2)

/// Runs one action through propose → unanimous vote → timelock → execution.
fn run(c: &mut CSMT, ts: &mut u64, voters: &[u8], a: GovAction) -> ProposalStatus {
    let id = propose(c, voters[0], *ts, a);
    for v in voters {
        if status(c, id) != ProposalStatus::Open {
            break;
        }
        op(c, va(*v), *ts, GovOp::Vote { id, yes: true }).unwrap();
    }
    *ts += T.timelock_secs;
    process_block(c, 3, *ts, Some(1), T).unwrap();
    status(c, id)
}

fn vset(c: &CSMT) -> ValidatorSet {
    ValidatorSet::from_bytes(c.get(&VALIDATOR_SET_CSMT_KEY).unwrap()).unwrap()
}

#[test]
fn vote_cannot_empty_the_active_set() {
    let mut c = state(&[(1, VERA)]);
    let mut ts = T0;
    let before = vset(&c);
    let s = run(&mut c, &mut ts, &[1], GovAction::SetMinValidatorStake { wei: 2 * VERA });
    assert!(matches!(s, ProposalStatus::Failed { code: FailCode::EmptyActiveSet, .. }), "{:?}", s);
    assert_eq!(vset(&c).min_validator_stake, before.min_validator_stake, "nothing changed");
}

#[test]
fn vote_cannot_remove_more_than_a_third_of_active_stake() {
    // 4 validators: 40 + 30 + 20 + 10 = 100. Raising the minimum to 25 removes 30 (ok, < 1/3);
    // raising it to 35 removes 60 (refused).
    let mut c = state(&[(1, 40), (2, 30), (3, 20), (4, 10)]);
    let mut ts = T0;
    let s = run(&mut c, &mut ts, &[1, 2, 3], GovAction::SetMinValidatorStake { wei: 35 });
    assert!(matches!(s, ProposalStatus::Failed { code: FailCode::RemovesTooMuchStake, .. }), "{:?}", s);
    let s = run(&mut c, &mut ts, &[1, 2, 3], GovAction::SetMaxActiveValidators { count: 1 });
    assert!(matches!(s, ProposalStatus::Failed { code: FailCode::RemovesTooMuchStake, .. }), "{:?}", s);
    let s = run(&mut c, &mut ts, &[1, 2, 3], GovAction::SetMinValidatorStake { wei: 25 });
    assert!(matches!(s, ProposalStatus::Executed { .. }), "{:?}", s);
    assert_eq!(vset(&c).active_validators().len(), 2);
}

#[test]
fn disallow_counts_as_removal_on_permissioned_sets() {
    let mut c = state(&[(1, 50), (2, 30), (3, 20)]);
    let mut vs = vset(&c);
    vs.permissioned_validators = true;
    for i in 1..=3 {
        vs.allow(va(i));
    }
    c.insert(VALIDATOR_SET_CSMT_KEY, vs.to_bytes());
    let mut ts = T0;
    let s = run(&mut c, &mut ts, &[1, 2], GovAction::Disallow { address: va(1) });
    assert!(matches!(s, ProposalStatus::Failed { code: FailCode::RemovesTooMuchStake, .. }), "{:?}", s);
    let s = run(&mut c, &mut ts, &[1, 2], GovAction::Disallow { address: va(3) });
    assert!(matches!(s, ProposalStatus::Executed { .. }), "{:?}", s);
}

#[test]
fn staking_floors_and_at_most_half_per_vote() {
    let mut c = state(&[(1, VERA)]);
    // Static floors refuse the proposal up front.
    for a in [GovAction::SetMaxMissedBlocks { blocks: 9 }, GovAction::SetUnbondingPeriodBlocks { blocks: 4 }] {
        assert!(op(&mut c, va(1), T0, GovOp::Propose { action: a, voting_period_secs: 3 * DAY }).is_err());
    }
    let mut ts = T0;
    assert!(matches!(run(&mut c, &mut ts, &[1], GovAction::SetMaxMissedBlocks { blocks: 100 }), ProposalStatus::Executed { .. }));
    assert!(matches!(run(&mut c, &mut ts, &[1], GovAction::SetUnbondingPeriodBlocks { blocks: 1_000 }), ProposalStatus::Executed { .. }));
    // More than halving at once fails with a fixed code; halving exactly is allowed.
    let s = run(&mut c, &mut ts, &[1], GovAction::SetMaxMissedBlocks { blocks: 49 });
    assert!(matches!(s, ProposalStatus::Failed { code: FailCode::BelowFloor, .. }), "{:?}", s);
    let s = run(&mut c, &mut ts, &[1], GovAction::SetUnbondingPeriodBlocks { blocks: 499 });
    assert!(matches!(s, ProposalStatus::Failed { code: FailCode::BelowFloor, .. }), "{:?}", s);
    assert!(matches!(run(&mut c, &mut ts, &[1], GovAction::SetMaxMissedBlocks { blocks: 50 }), ProposalStatus::Executed { .. }));
    let vs = vset(&c);
    assert_eq!((vs.max_missed_blocks, vs.unbonding_period_blocks), (50, 1_000));
}

#[test]
fn failure_code_is_stored_not_error_text() {
    let mut c = state(&[(1, VERA)]);
    let mut ts = T0;
    run(&mut c, &mut ts, &[1], GovAction::SetMinValidatorStake { wei: 2 * VERA });
    let raw = String::from_utf8(c.get(&{
        let mut pre = b"VGOV1/proposal".to_vec();
        pre.extend_from_slice(&1u64.to_le_bytes());
        vera_blockchain::chain_hash::hash256(&pre)
    }).unwrap().to_vec()).unwrap();
    assert!(raw.contains("\"EmptyActiveSet\""), "{}", raw);
    assert!(!raw.contains("governance:") && !raw.contains("registry:"), "no error text in state: {}", raw);
}

#[test]
fn key_allowlist_is_kept_on_testnet_only() {
    use vera_blockchain::genesis::builtin_key_keeps_allowlist;
    assert!(builtin_key_keeps_allowlist("vera-testnet-1"));
    assert!(!builtin_key_keeps_allowlist("vera-mainnet"));
    for keep in [true, false] {
        let mut c = CSMT::new();
        let mut vs = ValidatorSet::new(vec![Validator { address: va(1), public_key: [1; 32], stake: VERA, missed_blocks: 0, is_jailed: false }]);
        vs.governance_address = Some(KEY);
        c.insert(VALIDATOR_SET_CSMT_KEY, vs.to_bytes());
        process_block(&mut c, 1, T0, Some(1), GovConfig { timing: T, key_allowlist: keep }).unwrap();
        assert_eq!(load_state(&c).unwrap().unwrap().key_allowlist, keep);
    }
}

// ------------------------------------------------------------------ review round 2 (VPS)

#[test]
fn malformed_actions_are_invalid_and_only_bounds_are_below_floor() {
    use governance::action_code;
    for a in [
        GovAction::SetRegistrar { address: [0; 32] },
        GovAction::Disallow { address: [0; 32] },
        GovAction::SetMinValidatorStake { wei: 0 },
        GovAction::SetMaxActiveValidators { count: 0 },
        GovAction::SetMaxActiveValidators { count: 201 },
        GovAction::SetFee { fee_per_item_wei: 0 },
    ] {
        assert_eq!(action_code(&a), Err(FailCode::InvalidAction), "{:?}", a);
    }
    for a in [GovAction::SetMaxMissedBlocks { blocks: 9 }, GovAction::SetUnbondingPeriodBlocks { blocks: 4 }] {
        assert_eq!(action_code(&a), Err(FailCode::BelowFloor), "{:?}", a);
    }
}

#[test]
fn unknown_chain_ids_get_production_rules() {
    let short = GovTiming { timelock_secs: 2, min_voting_secs: 1, max_voting_secs: 600 };
    let open_short = vera_blockchain::open_staking::OpenTiming { unbonding_secs: 30, churn_window_secs: 48 };
    for (id, test) in [("vera-testnet-1", true), ("vera-mainnet", false), ("vera-mainnet-2", false), ("vera-mainnet-1", false)] {
        let (mut cfg, _) = GenesisConfig::default_testnet();
        cfg.chain_id = id.to_string();
        cfg.governance_timing = Some(short);
        cfg.open_entry_timing = Some(open_short);
        let f = cfg.fork_heights();
        assert_eq!(f.gov_key_allowlist, test, "{}", id);
        assert_eq!(f.gov_timing, if test { short } else { GovTiming::PRODUCTION }, "{}", id);
        assert_eq!(f.open_timing, if test { open_short } else { vera_blockchain::open_staking::OpenTiming::PRODUCTION }, "{}", id);
    }
}

#[test]
fn validator_disallowed_earlier_is_not_counted_as_leaving() {
    // 3 was disallowed by the key (testnet) but stays bonded and active; it must not make
    // every later vote look like it removes 60 of 140.
    let mut c = state(&[(1, 50), (2, 30), (3, 60)]);
    let mut vs = vset(&c);
    vs.permissioned_validators = true;
    vs.allow(va(1));
    vs.allow(va(2));
    c.insert(VALIDATOR_SET_CSMT_KEY, vs.to_bytes());
    let mut ts = T0;
    let s = run(&mut c, &mut ts, &[1, 2, 3], GovAction::SetMaxMissedBlocks { blocks: 20 });
    assert!(matches!(s, ProposalStatus::Executed { .. }), "{:?}", s);
}

#[test]
fn rails_are_cumulative_over_a_seven_day_window() {
    // 25 + 25 + 25 + 15 + 10 = 100. Each vote alone is within 1/3 of what is active then.
    let mut c = state(&[(1, 25), (2, 25), (3, 25), (4, 15), (5, 10)]);
    let mut ts = T0;
    let v = [1, 2, 3];
    assert!(matches!(run(&mut c, &mut ts, &v, GovAction::SetMinValidatorStake { wei: 11 }), ProposalStatus::Executed { .. }));
    assert!(matches!(run(&mut c, &mut ts, &v, GovAction::SetMinValidatorStake { wei: 16 }), ProposalStatus::Executed { .. }));
    // 25 of the remaining 75 would be fine for one vote, but 10 + 15 + 25 = 50 > 100 / 3.
    let s = run(&mut c, &mut ts, &v, GovAction::SetMaxActiveValidators { count: 2 });
    assert!(matches!(s, ProposalStatus::Failed { code: FailCode::RemovesTooMuchStake, .. }), "{:?}", s);
    assert_eq!(vset(&c).active_validators().len(), 3);
    // A new window measures against the stake active when it starts.
    ts += governance::RAIL_WINDOW_SECS;
    let s = run(&mut c, &mut ts, &v, GovAction::SetMaxActiveValidators { count: 2 });
    assert!(matches!(s, ProposalStatus::Executed { .. }), "{:?}", s);
}

#[test]
fn two_cuts_executing_in_one_block_cannot_go_below_half() {
    let mut c = state(&[(1, VERA)]);
    let mut ts = T0;
    assert!(matches!(run(&mut c, &mut ts, &[1], GovAction::SetMaxMissedBlocks { blocks: 100 }), ProposalStatus::Executed { .. }));
    ts += governance::RAIL_WINDOW_SECS;
    let a = propose(&mut c, 1, ts, GovAction::SetMaxMissedBlocks { blocks: 50 });
    let b = propose(&mut c, 1, ts, GovAction::SetMaxMissedBlocks { blocks: 26 });
    for id in [a, b] {
        op(&mut c, va(1), ts, GovOp::Vote { id, yes: true }).unwrap();
    }
    ts += T.timelock_secs;
    process_block(&mut c, 3, ts, Some(1), T).unwrap();
    assert!(matches!(status(&c, a), ProposalStatus::Executed { .. }));
    assert!(matches!(status(&c, b), ProposalStatus::Failed { code: FailCode::BelowFloor, .. }), "100 → 50 → 26 in one block");
    assert_eq!(vset(&c).max_missed_blocks, 50);
}
