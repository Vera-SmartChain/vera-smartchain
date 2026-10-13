
use vera_blockchain::consensus::ValidatorSet;
use vera_blockchain::account::VALIDATOR_SET_CSMT_KEY;
use vera_blockchain::csmt::CSMT;
use vera_blockchain::storage::PersistentStorage;

fn main() {
    let storage = PersistentStorage::open("/var/lib/vera/data").unwrap();
    let csmt = storage.load_state().unwrap().unwrap_or_else(CSMT::new);
    if let Some(bytes) = csmt.get(&VALIDATOR_SET_CSMT_KEY) {
        let vset = ValidatorSet::from_bytes(bytes).unwrap();
        println!("Validators count: {}", vset.validators.len());
        for v in &vset.validators {
            println!("  Val: 0x{}, Stake: {}, Jailed: {}", hex::encode(v.address), v.stake, v.is_jailed);
        }
        for h in 5..=10 {
            if let Ok(prop) = vset.get_proposer(h, 0) {
                println!("  Height #{}, Round 0 Proposer: 0x{}", h, hex::encode(prop.address));
            }
        }
    } else {
        println!("No validator set in CSMT");
    }
}
