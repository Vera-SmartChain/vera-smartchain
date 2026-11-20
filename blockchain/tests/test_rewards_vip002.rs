//! VIP-002: validator rewards from the pre-minted reward pool.

use ed25519_dalek::SigningKey;
use vera_blockchain::account::{address_from_pubkey, address_to_hex, Account, Address, VALIDATOR_SET_CSMT_KEY};
use vera_blockchain::block::ValidatorCommit;
use vera_blockchain::consensus::{Validator, ValidatorSet};
use vera_blockchain::csmt::CSMT;
use vera_blockchain::genesis::{GenesisAccount, GenesisConfig};
use vera_blockchain::node::FullNode;
use vera_blockchain::registry::DEFAULT_MIN_GAS_PRICE_WEI;
use vera_blockchain::rewards::{
    self, apply_block_reward, load_state, stake_cap, MAX_REWARD_GAP_SECS, RATE_WEI_PER_SEC, REWARD_POOL_ADDRESS,
    SECONDS_PER_YEAR,
};
use vera_blockchain::transaction::Transaction;

const VERA: u128 = 1_000_000_000_000_000_000;
/// A stake large enough that the schedule, not the 10%/year stake cap, is the binding limit.
const BIG: u128 = 100_000_000 * VERA;

fn pk(i: u8) -> [u8; 32] {
    [i; 32]
}
fn va(i: u8) -> Address {
    let mut a = [0u8; 32];
    a[0] = 0xa0;
    a[31] = i;
    a
}
fn commit(i: u8) -> ValidatorCommit {
    ValidatorCommit { validator_pubkey: pk(i), signature: [0u8; 64] }
}

fn bal(c: &CSMT, a: &Address) -> u128 {
    c.get(a).and_then(|b| Account::from_bytes(b).ok()).map_or(0, |a| a.balance)
}
fn total(c: &CSMT) -> u128 {
    c.iter().filter_map(|(_, b)| Account::from_bytes(b).ok()).map(|a| a.balance).sum()
}

/// State with validators (index, stake, jailed) and a funded pool.
fn state(vals: &[(u8, u128, bool)], pool: u128) -> CSMT {
    let mut c = CSMT::new();
    let vs = ValidatorSet::new(
        vals.iter()
            .map(|&(i, stake, jailed)| Validator { address: va(i), public_key: pk(i), stake, missed_blocks: 0, is_jailed: jailed })
            .collect(),
    );
    c.insert(VALIDATOR_SET_CSMT_KEY, vs.to_bytes());
    c.insert(REWARD_POOL_ADDRESS, Account::new(pool).to_bytes());
    c
}

const ACT: Option<u64> = Some(10);

#[test]
fn nothing_before_activation_or_without_it() {
    let mut c = state(&[(1, VERA, false)], 1_000 * VERA);
    let before = c.root();
    assert_eq!(apply_block_reward(&mut c, 9, 1000, va(1), &[commit(1)], ACT).unwrap().total, 0);
    assert_eq!(apply_block_reward(&mut c, 50, 1000, va(1), &[commit(1)], None).unwrap().total, 0);
    assert_eq!(c.root(), before, "state untouched");
}

#[test]
fn activation_block_starts_the_clock_and_pays_nothing() {
    let mut c = state(&[(1, VERA, false)], 1_000 * VERA);
    let r = apply_block_reward(&mut c, 10, 5_000, va(1), &[commit(1)], ACT).unwrap();
    assert_eq!(r.total, 0);
    let st = load_state(&c).unwrap().unwrap();
    assert_eq!((st.start_ts, st.last_ts, st.total_paid), (5_000, 5_000, 0));
}

#[test]
fn pro_rata_by_stake_remainder_to_proposer_and_conservation() {
    // Validator 3 is active but did not sign; it proposes and gets only the remainder.
    let mut c = state(&[(1, BIG, false), (2, 2 * BIG, false), (3, 4 * BIG, false)], 1_000 * VERA);
    apply_block_reward(&mut c, 10, 5_000, va(3), &[], ACT).unwrap();
    let supply = total(&c);
    let r = apply_block_reward(&mut c, 11, 5_007, va(3), &[commit(1), commit(2), commit(2)], ACT).unwrap();
    let due = 7 * RATE_WEI_PER_SEC[0];
    assert_eq!(r.total, due);
    assert_eq!(bal(&c, &va(1)), due / 3);
    assert_eq!(bal(&c, &va(2)), due * 2 / 3);
    assert_eq!(bal(&c, &va(3)), due - due / 3 - due * 2 / 3);
    assert!(r.remainder_to_proposer <= 2);
    assert_eq!(bal(&c, &REWARD_POOL_ADDRESS), 1_000 * VERA - due);
    assert_eq!(total(&c), supply, "emission moves coins, never creates them");
    assert_eq!(load_state(&c).unwrap().unwrap().total_paid, due);
}

#[test]
fn elapsed_time_is_capped() {
    let mut c = state(&[(1, BIG, false)], 1_000_000 * VERA);
    apply_block_reward(&mut c, 10, 5_000, va(1), &[], ACT).unwrap();
    let r = apply_block_reward(&mut c, 11, 5_000 + 3_600, va(1), &[commit(1)], ACT).unwrap();
    assert_eq!(r.total, MAX_REWARD_GAP_SECS as u128 * RATE_WEI_PER_SEC[0]);
}

#[test]
fn pool_limits_the_reward_and_an_empty_pool_pays_nothing() {
    let mut c = state(&[(1, VERA, false)], 5);
    apply_block_reward(&mut c, 10, 5_000, va(1), &[], ACT).unwrap();
    assert_eq!(apply_block_reward(&mut c, 11, 5_010, va(1), &[commit(1)], ACT).unwrap().total, 5);
    assert_eq!(bal(&c, &REWARD_POOL_ADDRESS), 0);
    let r = apply_block_reward(&mut c, 12, 5_020, va(1), &[commit(1)], ACT).unwrap();
    assert_eq!(r.total, 0);
    assert_eq!(load_state(&c).unwrap().unwrap().last_ts, 5_020);
}

#[test]
fn jailed_and_unknown_signers_get_nothing() {
    let mut c = state(&[(1, BIG, false), (2, BIG, true)], 1_000 * VERA);
    apply_block_reward(&mut c, 10, 5_000, va(1), &[], ACT).unwrap();
    let r = apply_block_reward(&mut c, 11, 5_001, va(1), &[commit(1), commit(2), commit(9)], ACT).unwrap();
    assert_eq!(r.shares, vec![(va(1), RATE_WEI_PER_SEC[0])]);
    assert_eq!(bal(&c, &va(2)), 0);
}

/// Decision 2026-11-18: no validator earns more than 10% of its own stake per year,
/// however few validators there are. The rest of the schedule stays in the pool.
#[test]
fn stake_cap_binds_with_small_stake() {
    let s32 = 32 * VERA;
    let mut c = state(&[(1, s32, false), (2, s32, false), (3, s32, false)], 1_000 * VERA);
    apply_block_reward(&mut c, 10, 5_000, va(1), &[], ACT).unwrap();
    // Validator 3 is offline: its stake does not raise the cap of the other two.
    let r = apply_block_reward(&mut c, 11, 5_060, va(1), &[commit(1), commit(2)], ACT).unwrap();
    let cap = stake_cap(2 * s32, 60);
    assert_eq!(r.total, cap);
    assert!(cap < 60 * RATE_WEI_PER_SEC[0] / 1_000, "far below the schedule");
    assert_eq!(bal(&c, &va(1)), cap / 2 + r.remainder_to_proposer);
    assert_eq!(bal(&c, &va(2)), cap / 2);
    assert_eq!(bal(&c, &va(3)), 0);
    assert_eq!(bal(&c, &REWARD_POOL_ADDRESS), 1_000 * VERA - cap);
    // Over a full year of 60 s blocks a validator earns 10% of its stake, not more.
    assert!(stake_cap(s32, SECONDS_PER_YEAR) == s32 / 10);
}

#[test]
fn no_signers_means_coins_stay_in_the_pool() {
    let mut c = state(&[(1, VERA, false)], 1_000 * VERA);
    apply_block_reward(&mut c, 10, 5_000, va(1), &[], ACT).unwrap();
    assert_eq!(apply_block_reward(&mut c, 11, 5_030, va(1), &[], ACT).unwrap().total, 0);
    assert_eq!(bal(&c, &REWARD_POOL_ADDRESS), 1_000 * VERA);
    assert_eq!(bal(&c, &va(1)), 0);
}

#[test]
fn timestamp_going_backwards_pays_nothing_and_keeps_the_clock() {
    let mut c = state(&[(1, VERA, false)], 1_000 * VERA);
    apply_block_reward(&mut c, 10, 5_000, va(1), &[], ACT).unwrap();
    assert_eq!(apply_block_reward(&mut c, 11, 4_000, va(1), &[commit(1)], ACT).unwrap().total, 0);
    assert_eq!(load_state(&c).unwrap().unwrap().last_ts, 5_000);
}

#[test]
fn rate_follows_the_year_of_the_block() {
    let mut c = state(&[(1, BIG, false)], 10_000_000 * VERA);
    apply_block_reward(&mut c, 10, 0, va(1), &[], ACT).unwrap();
    // Jump the clock to the end of year 1 (no reward: gap capped), then 10 s into year 2.
    apply_block_reward(&mut c, 11, SECONDS_PER_YEAR - 5, va(1), &[], ACT).unwrap();
    let r = apply_block_reward(&mut c, 12, SECONDS_PER_YEAR + 5, va(1), &[commit(1)], ACT).unwrap();
    assert_eq!(r.total, 10 * RATE_WEI_PER_SEC[1]);
    apply_block_reward(&mut c, 13, 10 * SECONDS_PER_YEAR, va(1), &[], ACT).unwrap();
    let r = apply_block_reward(&mut c, 14, 10 * SECONDS_PER_YEAR + 30, va(1), &[commit(1)], ACT).unwrap();
    assert_eq!(r.total, 0, "nothing after year 10");
}

// ------------------------------------------------------------------ full node level

fn filler_key() -> SigningKey {
    SigningKey::from_bytes(&[77u8; 32])
}

fn genesis(activation: Option<u64>) -> (GenesisConfig, SigningKey) {
    let (mut cfg, vk) = GenesisConfig::default_testnet();
    let f = filler_key();
    cfg.initial_accounts.push(GenesisAccount {
        address: address_to_hex(&address_from_pubkey(&f.verifying_key().to_bytes())),
        balance: (100 * VERA).to_string(),
    });
    cfg.initial_accounts.push(GenesisAccount { address: address_to_hex(&REWARD_POOL_ADDRESS), balance: (1_000 * VERA).to_string() });
    cfg.rewards_activation_height = activation;
    (cfg, vk)
}

fn node(cfg: &GenesisConfig, key: Option<SigningKey>) -> FullNode {
    let dir = std::env::temp_dir().join(format!("vera_vip002_{}", rand::random::<u64>()));
    FullNode::load_or_init(&dir, cfg, key).unwrap()
}

fn node_total(n: &FullNode) -> u128 {
    total(&n.csmt)
}

#[tokio::test]
async fn node_pays_the_validator_and_two_nodes_agree() {
    let (cfg, vk) = genesis(Some(2));
    let mut n = node(&cfg, Some(vk.clone()));
    let mut f = node(&cfg, None);
    let val = address_from_pubkey(&vk.verifying_key().to_bytes());
    let supply = node_total(&n);
    let fk = filler_key();
    let fa = address_from_pubkey(&fk.verifying_key().to_bytes());

    let mut last_pool = bal(&n.csmt, &REWARD_POOL_ADDRESS);
    for h in 1..=5u64 {
        let nonce = n.csmt.get(&fa).and_then(|b| Account::from_bytes(b).ok()).map_or(0, |a| a.nonce);
        let tx = Transaction::new(&n.chain_id, &fk, nonce, Some([0x22; 32]), 1, 21_000, DEFAULT_MIN_GAS_PRICE_WEI, vec![]);
        n.submit_transaction(tx).unwrap();
        let block = n.build_proposal().await.expect("build");
        f.validate_proposal(&block).await.expect("follower validates");
        f.apply_block(block.clone()).await.unwrap();
        n.apply_block(block).await.unwrap();
        assert_eq!(n.csmt.root(), f.csmt.root(), "same state root at #{}", h);
        assert_eq!(node_total(&n), supply, "supply unchanged at #{}", h);
        let pool = bal(&n.csmt, &REWARD_POOL_ADDRESS);
        if h < 2 {
            assert!(load_state(&n.csmt).unwrap().is_none());
        }
        if h >= 3 {
            assert!(pool <= last_pool);
        }
        last_pool = pool;
        std::thread::sleep(std::time::Duration::from_millis(1_100));
    }
    let st = load_state(&n.csmt).unwrap().unwrap();
    let paid = 1_000 * VERA - bal(&n.csmt, &REWARD_POOL_ADDRESS);
    assert_eq!(st.total_paid, paid);
    assert!(paid > 0, "blocks at least 1 s apart pay something");
    assert!(paid <= (st.last_ts - st.start_ts) as u128 * RATE_WEI_PER_SEC[0]);
    // One 32-VERA validator: the 10%/year stake cap binds, not the schedule.
    assert!(paid <= stake_cap(32 * VERA, st.last_ts - st.start_ts) + 5);
    assert!(bal(&n.csmt, &val) > 0);
    let _ = rewards::SECONDS_PER_YEAR;
}
