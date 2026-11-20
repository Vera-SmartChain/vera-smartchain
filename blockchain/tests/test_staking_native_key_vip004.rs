//! VIP-004 review (Claude-VPS): staking needs a native, strong ed25519 key. An EVM-wrapped tx
//! carries public_key = [0; 32], a weak (small-order) point: stake would pool on that key,
//! anyone could unstake it to the first staker, and its votes could be forged. The two PoC
//! tests from the review are kept here, inverted: the attack must fail.

use ed25519_dalek::VerifyingKey;
use vera_blockchain::account::{address_to_hex, Account, Address, STAKING_SYSTEM_ADDRESS, VALIDATOR_SET_CSMT_KEY};
use vera_blockchain::chain_hash::hash256;
use vera_blockchain::consensus::{check_staking_key, Validator, ValidatorSet, Vote, VoteType};
use vera_blockchain::csmt::CSMT;
use vera_blockchain::genesis::{GenesisAccount, GenesisConfig};
use vera_blockchain::node::FullNode;
use vera_blockchain::open_staking::{process_block, queue_stake, OpenConfig, OpenTiming};
use vera_blockchain::registry::DEFAULT_MIN_GAS_PRICE_WEI;
use vera_blockchain::state_transition::StateTransitionEngine;
use vera_blockchain::transaction::Transaction;

const ZERO: [u8; 32] = [0u8; 32];
const VERA: u128 = 1_000_000_000_000_000_000;

#[test]
fn forged_votes_for_a_weak_key_are_rejected() {
    let vk = VerifyingKey::from_bytes(&ZERO).expect("[0;32] decodes to a point");
    assert!(vk.is_weak(), "small-order point");
    // R = identity, s = 0 passed the non-strict check for ~1 in 4 messages (11/40 in the PoC).
    let mut sig = [0u8; 64];
    sig[0] = 1;
    let forged = (0..40u64)
        .filter(|round| {
            Vote {
                chain_id: "vera-mainnet".into(),
                height: 100,
                round: *round,
                block_hash: [0xab; 32],
                vote_type: VoteType::PreCommit,
                validator_pubkey: ZERO,
                signature: sig,
            }
            .verify()
            .is_ok()
        })
        .count();
    assert_eq!(forged, 0, "Vote::verify is strict now");
    assert!(check_staking_key(false, &ZERO).is_err());
    assert!(check_staking_key(true, &[7; 32]).is_err(), "any EVM-wrapped tx");
}

fn addr(i: u8) -> Address {
    [i; 32]
}

#[test]
fn stake_can_no_longer_pool_on_key_zero() {
    let mut c = CSMT::new();
    let honest = Validator { address: addr(9), public_key: [9; 32], stake: 1_000_000, missed_blocks: 0, is_jailed: false };
    let vs = ValidatorSet::with_params(vec![honest], 10, 50, 5, 10, false, None, vec![]);
    c.insert(VALIDATOR_SET_CSMT_KEY, vs.to_bytes());
    let cfg = OpenConfig { timing: OpenTiming::PRODUCTION, chain_id_hash: hash256(b"vera-mainnet") };
    process_block(&mut c, 1, 1_000_000, Some(1), cfg).unwrap();
    assert!(queue_stake(&mut c, addr(0xA), ZERO, 10, 1_000_000).is_err(), "VIP-004 path");
    // The pre-VIP-004 path with an open set (mainnet genesis has permissioned = false).
    let mut open = ValidatorSet::with_params(vec![], 10, 50, 5, 10, false, None, vec![]);
    assert!(open.bond(addr(0xA), ZERO, 10).is_err(), "old bond path");
}

fn rlp_bytes(b: &[u8]) -> Vec<u8> {
    if b.len() == 1 && b[0] < 0x80 {
        return b.to_vec();
    }
    let mut out = rlp_len(b.len(), 0x80);
    out.extend_from_slice(b);
    out
}
fn rlp_len(len: usize, offset: u8) -> Vec<u8> {
    if len < 56 {
        vec![offset + len as u8]
    } else {
        let be: Vec<u8> = len.to_be_bytes().iter().copied().skip_while(|x| *x == 0).collect();
        let mut out = vec![offset + 55 + be.len() as u8];
        out.extend(be);
        out
    }
}
fn rlp_uint(v: u128) -> Vec<u8> {
    let be: Vec<u8> = v.to_be_bytes().iter().copied().skip_while(|x| *x == 0).collect();
    rlp_bytes(&be)
}
fn rlp_list(items: &[Vec<u8>]) -> Vec<u8> {
    let body: Vec<u8> = items.concat();
    let mut out = rlp_len(body.len(), 0xc0);
    out.extend(body);
    out
}

fn evm_key() -> k256::ecdsa::SigningKey {
    k256::ecdsa::SigningKey::from_bytes(&[0x5au8; 32].into()).unwrap()
}
fn evm_addr() -> [u8; 32] {
    let pk = evm_key().verifying_key().to_encoded_point(false);
    let h = vera_blockchain::account::keccak256(&pk.as_bytes()[1..]);
    let mut a = [0u8; 32];
    a[12..].copy_from_slice(&h[12..]);
    a
}

/// A legacy EIP-155 tx (chainId 83721) wrapped like the RPC does (public_key = 0).
fn evm_tx(nonce: u64, to: [u8; 32], value: u128, data: Vec<u8>) -> Transaction {
    const CHAIN: u128 = 83721;
    let fields = |v: Vec<u8>, r: Vec<u8>, s: Vec<u8>| {
        rlp_list(&[
            rlp_uint(nonce as u128),
            rlp_uint(DEFAULT_MIN_GAS_PRICE_WEI as u128),
            rlp_uint(200_000),
            rlp_bytes(&to[12..]),
            rlp_uint(value),
            rlp_bytes(&data),
            v,
            r,
            s,
        ])
    };
    let unsigned = fields(rlp_uint(CHAIN), rlp_uint(0), rlp_uint(0));
    let digest = vera_blockchain::account::keccak256(&unsigned);
    let (sig, recid) = evm_key().sign_prehash_recoverable(&digest).unwrap();
    let v = recid.to_byte() as u128 + CHAIN * 2 + 35;
    let strip = |b: &[u8]| -> Vec<u8> { b.iter().copied().skip_while(|x| *x == 0).collect() };
    let raw = fields(rlp_uint(v), rlp_bytes(&strip(&sig.r().to_bytes())), rlp_bytes(&strip(&sig.s().to_bytes())));
    let rec = vera_blockchain::rpc::parse_and_recover_evm_tx(&raw, 83721).expect("recover");
    Transaction {
        chain_id: "vera-testnet-1".into(),
        public_key: [0u8; 32],
        sender: rec.from,
        nonce: rec.nonce,
        to: Some(rec.to),
        amount: rec.value,
        gas_limit: rec.gas_limit,
        gas_price: rec.gas_price,
        program: rec.data.clone(),
        witness: None,
        signature: [0u8; 64],
        raw_evm: Some(raw),
    }
}

#[tokio::test]
async fn evm_wrapped_staking_is_refused_at_admission_and_execution() {
    // Both rule sets: before VIP-004 with an open set, and with VIP-004 active.
    for open_entry in [None, Some(1)] {
        let (mut cfg, vk) = GenesisConfig::default_testnet();
        cfg.permissioned_validators = false;
        cfg.open_entry_activation_height = open_entry;
        cfg.initial_accounts.push(GenesisAccount { address: address_to_hex(&evm_addr()), balance: (1_000 * VERA).to_string() });
        let dir = std::env::temp_dir().join(format!("vera_vip004_evm_{}", rand::random::<u64>()));
        let mut n = FullNode::load_or_init(&dir, &cfg, Some(vk)).unwrap();
        for (value, data) in [(100 * VERA, Vec::new()), (0, b"unstake".to_vec()), (0, b"unjail".to_vec())] {
            let tx = evm_tx(0, STAKING_SYSTEM_ADDRESS, value, data);
            let e = n.submit_transaction(tx.clone()).unwrap_err();
            assert!(e.contains("native ed25519"), "{:?}: {}", open_entry, e);
            let mut c = n.csmt.clone();
            vera_blockchain::state_transition::apply_next_block_activations(&mut c, 1, 2_000_000_000, &n.forks());
            let e = StateTransitionEngine::execute_transaction_in_block_sync(&mut c, &tx, [0; 32], 1, 2_000_000_000, 83721, None).unwrap_err();
            assert!(e.contains("native ed25519"), "{:?}: {}", open_entry, e);
        }
        let bal = n.csmt.get(&evm_addr()).and_then(|b| Account::from_bytes(b).ok()).unwrap().balance;
        assert_eq!(bal, 1_000 * VERA, "nothing moved");
    }
}
