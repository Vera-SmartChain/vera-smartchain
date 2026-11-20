//! VIP-004 ultrareview finding 1 (Claude-VPS PoC, inverted): a transfer to one of the old fixed
//! state addresses (0x…1301 gov, …1401 open entry, …1101 fee params, …7a1e rewards) used to
//! create an `Account` there, after which `load_state` failed and every block failed. The records
//! now live under domain-separated hashed keys, so the old addresses are ordinary accounts and
//! nothing the chain reads is touched by them.

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use vera_blockchain::account::{Account, Address};
use vera_blockchain::chain_hash::hash256;
use vera_blockchain::csmt::CSMT;
use vera_blockchain::governance::{load_state as gov_load, GOV_STATE_KEY};
use vera_blockchain::open_staking::{load_state as open_load, process_block, OpenConfig, OpenTiming, OPEN_STATE_KEY};
use vera_blockchain::registry::{load_params, FEE_PARAMS_KEY};
use vera_blockchain::rewards::{load_state as rew_load, REWARD_STATE_KEY};
use vera_blockchain::genesis::GenesisConfig;
use vera_blockchain::node::FullNode;
use vera_blockchain::state_transition::{is_reserved_state_key, StateTransitionEngine};
use vera_blockchain::transaction::Transaction;

fn low(a: u8, b: u8) -> Address {
    let mut k = [0u8; 32];
    k[30] = a;
    k[31] = b;
    k
}

#[test]
fn state_keys_are_hashes_and_not_low_addresses() {
    for (k, old) in [
        (GOV_STATE_KEY, low(0x13, 0x01)),
        (OPEN_STATE_KEY, low(0x14, 0x01)),
        (FEE_PARAMS_KEY, low(0x11, 0x01)),
        (REWARD_STATE_KEY, low(0x7a, 0x1e)),
    ] {
        assert_ne!(k, old);
        assert!(k[..16].iter().any(|b| *b != 0), "not an address in the reserved low range");
    }
    let all = [GOV_STATE_KEY, OPEN_STATE_KEY, FEE_PARAMS_KEY, REWARD_STATE_KEY];
    for i in 0..4 {
        for j in i + 1..4 {
            assert_ne!(all[i], all[j]);
        }
    }
    assert_eq!(GOV_STATE_KEY, hash256(b"VGOV1/state"));
}

/// Hashing the keys is not enough on its own: they are public constants, so a native transaction
/// can still name one as `to`. Execution and admission refuse it.
#[tokio::test]
async fn transfers_to_the_reserved_keys_are_refused_and_state_stays_loadable() {
    for (name, key) in [("gov", GOV_STATE_KEY), ("open", OPEN_STATE_KEY), ("fee", FEE_PARAMS_KEY), ("reward", REWARD_STATE_KEY)] {
        assert!(is_reserved_state_key(&key), "{name}");
        let mut c = CSMT::new();
        let k = SigningKey::generate(&mut OsRng);
        let a = hash256(&k.verifying_key().to_bytes());
        c.insert(a, Account::new(100_000_000).to_bytes());
        let tx = Transaction::new("vera-testnet-1", &k, 0, Some(key), 1_000, 25_000, 1, vec![]);
        let e = StateTransitionEngine::execute_transaction(&mut c, &tx, [9u8; 32]).await.unwrap_err();
        assert!(e.contains("reserved state key"), "{name}: {e}");
        assert!(c.get(&key).is_none(), "{name}: no account was created on the key");
        assert!(gov_load(&c).unwrap().is_none(), "{name}");
        assert!(open_load(&c).unwrap().is_none(), "{name}");
        assert!(rew_load(&c).unwrap().is_none(), "{name}");
        assert!(load_params(&c).unwrap().is_none(), "{name}");
        let cfg = OpenConfig { timing: OpenTiming::PRODUCTION, chain_id_hash: hash256(b"vera-mainnet") };
        process_block(&mut c, 1, 1_000_000, None, cfg).unwrap();
    }
}

#[tokio::test]
async fn the_old_low_addresses_are_ordinary_accounts_now() {
    for old in [low(0x13, 0x01), low(0x14, 0x01), low(0x11, 0x01), low(0x7a, 0x1e)] {
        assert!(!is_reserved_state_key(&old));
        let mut c = CSMT::new();
        let k = SigningKey::generate(&mut OsRng);
        let a = hash256(&k.verifying_key().to_bytes());
        c.insert(a, Account::new(100_000_000).to_bytes());
        let tx = Transaction::new("vera-testnet-1", &k, 0, Some(old), 1_000, 25_000, 1, vec![]);
        assert!(StateTransitionEngine::execute_transaction(&mut c, &tx, [9u8; 32]).await.is_ok());
        assert!(gov_load(&c).unwrap().is_none() && open_load(&c).unwrap().is_none());
        assert!(rew_load(&c).unwrap().is_none() && load_params(&c).unwrap().is_none());
    }
}

#[tokio::test]
async fn the_mempool_refuses_transactions_to_reserved_keys() {
    let (cfg, vk) = GenesisConfig::default_testnet();
    let dir = std::env::temp_dir().join(format!("vera_reserved_keys_{}", rand::random::<u64>()));
    let mut n = FullNode::load_or_init(&dir, &cfg, Some(vk.clone())).unwrap();
    for key in [GOV_STATE_KEY, OPEN_STATE_KEY, FEE_PARAMS_KEY, REWARD_STATE_KEY] {
        let tx = Transaction::new(&cfg.chain_id, &vk, 0, Some(key), 1_000, 25_000, 1_000_000_000, vec![]);
        let e = n.submit_transaction(tx).unwrap_err();
        assert!(e.contains("reserved state key"), "{e}");
    }
}
