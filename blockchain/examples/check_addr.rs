use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::env;

fn main() {
    let (signing_key, generated) = if let Some(arg) = env::args().nth(1) {
        let clean = arg.trim_start_matches("0x");
        let priv_bytes = hex::decode(clean).expect("Failed to decode hex private key");
        if priv_bytes.len() != 32 {
            eprintln!("Error: Private key must be 32 bytes (64 hex characters)");
            std::process::exit(1);
        }
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&priv_bytes);
        (SigningKey::from_bytes(&key_bytes), false)
    } else {
        println!("No private key supplied via argument. Generating a random keypair for demonstration:");
        (SigningKey::generate(&mut OsRng), true)
    };

    let pubkey = signing_key.verifying_key().to_bytes();
    let addr = vera_engine_v2::vera_hash_256(&pubkey);

    if generated {
        println!("Private Key:  0x{}", hex::encode(signing_key.to_bytes()));
    }
    println!("Public Key:   0x{}", hex::encode(pubkey));
    println!("Real Address: 0x{}", hex::encode(addr));
}
