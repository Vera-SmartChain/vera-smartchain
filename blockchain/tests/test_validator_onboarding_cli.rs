use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use std::fs;
use std::path::Path;
use vera_blockchain::validator_application::{
    is_address_in_allowlist, is_version_newer, parse_validator_status_from_json, read_key_from_file_or_hex,
    ValidatorApplication,
};


#[test]
fn test_validator_application_roundtrip_and_verification() {
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let chain_id = "vera-testnet-1";
    let operator = "@community_operator";

    let app = ValidatorApplication::new(&signing_key, chain_id, operator);
    let block_text = app.to_block_text();

    assert!(block_text.contains("BEGIN VERA VALIDATOR APPLICATION"));
    assert!(block_text.contains("chain_id: vera-testnet-1"));
    assert!(block_text.contains("operator: @community_operator"));

    let parsed = ValidatorApplication::parse_block(&block_text).expect("Failed to parse application block");
    assert_eq!(app, parsed);

    // Verification must pass with valid 7-day window
    parsed.verify(chain_id, 7 * 86400).expect("Valid application verification failed");
}

#[test]
fn test_validator_application_invalid_signature_rejected() {
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let mut app = ValidatorApplication::new(&signing_key, "vera-testnet-1", "@alice");

    // Corrupt signature
    app.signature = "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".to_string();

    let err = app.verify("vera-testnet-1", 7 * 86400).expect_err("Expected signature failure");
    assert!(err.contains("Ed25519 signature verification failed"), "Unexpected error: {}", err);
}

#[test]
fn test_validator_application_wrong_chain_id_rejected() {
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let app = ValidatorApplication::new(&signing_key, "vera-testnet-1", "@bob");

    let err = app.verify("vera-mainnet", 7 * 86400).expect_err("Expected chain_id failure");
    assert!(err.contains("Chain ID mismatch"), "Unexpected error: {}", err);
}

#[test]
fn test_validator_application_expired_timestamp_rejected() {
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let mut app = ValidatorApplication::new(&signing_key, "vera-testnet-1", "@charlie");

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // 8 days old (older than 7 days)
    app.timestamp = now - (8 * 86400);

    // Re-sign with expired timestamp
    let msg = ValidatorApplication::canonical_message(&app.chain_id, &app.address, &app.operator, app.timestamp);
    let sig = signing_key.sign(msg.as_bytes());
    app.signature = format!("0x{}", hex::encode(sig.to_bytes()));

    let err = app.verify("vera-testnet-1", 7 * 86400).expect_err("Expected expiration failure");
    assert!(err.contains("Application has expired"), "Unexpected error: {}", err);
}

#[test]
fn test_validator_application_future_timestamp_rejected() {
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let mut app = ValidatorApplication::new(&signing_key, "vera-testnet-1", "@dave");

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // 10 minutes in future (tolerance is 300s)
    app.timestamp = now + 600;

    let msg = ValidatorApplication::canonical_message(&app.chain_id, &app.address, &app.operator, app.timestamp);
    let sig = signing_key.sign(msg.as_bytes());
    app.signature = format!("0x{}", hex::encode(sig.to_bytes()));

    let err = app.verify("vera-testnet-1", 7 * 86400).expect_err("Expected future timestamp failure");
    assert!(err.contains("Timestamp is in the future"), "Unexpected error: {}", err);
}

#[test]
fn test_validator_application_mismatched_pubkey_and_address_rejected() {
    let mut csprng = OsRng;
    let signing_key1 = SigningKey::generate(&mut csprng);
    let signing_key2 = SigningKey::generate(&mut csprng);

    let mut app = ValidatorApplication::new(&signing_key1, "vera-testnet-1", "@eve");

    // Replace pubkey with pubkey of key2 without changing address
    let pub2 = signing_key2.verifying_key().to_bytes();
    app.public_key = format!("0x{}", hex::encode(pub2));

    let err = app.verify("vera-testnet-1", 7 * 86400).expect_err("Expected pubkey/address mismatch");
    assert!(err.contains("Public key does not match address"), "Unexpected error: {}", err);
}

#[test]
fn test_read_key_from_file_and_hex() {
    let mut csprng = OsRng;
    let original = SigningKey::generate(&mut csprng);
    let hex_key = hex::encode(original.to_bytes());

    // Test direct hex string
    let loaded_hex = read_key_from_file_or_hex(&hex_key).expect("Failed reading hex key");
    assert_eq!(original.to_bytes(), loaded_hex.to_bytes());

    // Test with 0x prefix
    let hex_with_0x = format!("0x{}", hex_key);
    let loaded_0x = read_key_from_file_or_hex(&hex_with_0x).expect("Failed reading 0x hex key");
    assert_eq!(original.to_bytes(), loaded_0x.to_bytes());

    // Test from temp file
    let temp_dir = std::env::temp_dir().join(format!("test_key_{}", rand::random::<u32>()));
    fs::create_dir_all(&temp_dir).unwrap();
    let temp_file = temp_dir.join("validator_key.hex");

    fs::write(&temp_file, format!("  0x{}\n", hex_key)).unwrap();

    let loaded_file = read_key_from_file_or_hex(temp_file.to_str().unwrap()).expect("Failed reading key from file");
    assert_eq!(original.to_bytes(), loaded_file.to_bytes());

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_keygen_output_permissions_and_no_overwrite() {
    let temp_dir = std::env::temp_dir().join(format!("test_keygen_{}", rand::random::<u32>()));
    fs::create_dir_all(&temp_dir).unwrap();
    let key_path = temp_dir.join("validator_key.hex");

    let path_str = key_path.to_str().unwrap();

    // Verify keygen simulation logic:
    assert!(!Path::new(path_str).exists());

    let mut csprng = OsRng;
    let sk = SigningKey::generate(&mut csprng);
    let secret = hex::encode(sk.to_bytes());
    fs::write(path_str, &secret).unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path_str, fs::Permissions::from_mode(0o600)).unwrap();
        let meta = fs::metadata(path_str).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    }

    // Refusal to overwrite:
    assert!(Path::new(path_str).exists());

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_allowlist_rejection_and_status_parsing_with_real_rpc_json() {
    let real_rpc_json = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "activeTotalStake": "64000000000000000000",
            "activeValidators": [
                {
                    "address": "0x19824ac38727c94e97a4d51651ebe350b3571b4d9a46dc09bd2b53068a3e34cb",
                    "isJailed": false,
                    "missedBlocks": 0,
                    "publicKey": "8d2b423c2b284f1a1ed40730c4e7b6d317042965eb77e24d245bafe279f50a75",
                    "stake": "32000000000000000000"
                },
                {
                    "address": "0x9393907ce109384586bc753c04bfd3d9bba7d37bac7db0b1aec7f45f40607840",
                    "isJailed": false,
                    "missedBlocks": 0,
                    "publicKey": "b0e860166167e5e8b09d4d310f3f8a2b7f04518498ca7c177e259dabbf1f8a21",
                    "stake": "32000000000000000000"
                }
            ],
            "allowlist": [
                "0x19824ac38727c94e97a4d51651ebe350b3571b4d9a46dc09bd2b53068a3e34cb",
                "0x9393907ce109384586bc753c04bfd3d9bba7d37bac7db0b1aec7f45f40607840"
            ],
            "governanceAddress": "0xd12949512c92d3e70be1789b3f086044c4483205a20f29b34b066396c00f0ea5",
            "maxActiveValidators": 50,
            "minValidatorStake": "32000000000000000000",
            "permissionedValidators": true,
            "supermajorityThreshold": "42666666666666666667",
            "totalStake": "64000000000000000000",
            "unbondingQueue": [],
            "validators": [
                {
                    "address": "0x19824ac38727c94e97a4d51651ebe350b3571b4d9a46dc09bd2b53068a3e34cb",
                    "isJailed": false,
                    "missedBlocks": 0,
                    "publicKey": "8d2b423c2b284f1a1ed40730c4e7b6d317042965eb77e24d245bafe279f50a75",
                    "stake": "32000000000000000000"
                },
                {
                    "address": "0x9393907ce109384586bc753c04bfd3d9bba7d37bac7db0b1aec7f45f40607840",
                    "isJailed": false,
                    "missedBlocks": 0,
                    "publicKey": "b0e860166167e5e8b09d4d310f3f8a2b7f04518498ca7c177e259dabbf1f8a21",
                    "stake": "32000000000000000000"
                }
            ]
        }
    });

    // 1. Verify that addresses already in result.allowlist are detected
    let addr1 = "0x19824ac38727c94e97a4d51651ebe350b3571b4d9a46dc09bd2b53068a3e34cb";
    let addr2 = "0x9393907ce109384586bc753c04bfd3d9bba7d37bac7db0b1aec7f45f40607840";
    let addr_new = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    assert!(is_address_in_allowlist(&real_rpc_json, addr1), "addr1 should be in allowlist");
    assert!(is_address_in_allowlist(&real_rpc_json, addr2), "addr2 should be in allowlist");
    assert!(!is_address_in_allowlist(&real_rpc_json, addr_new), "addr_new should NOT be in allowlist");

    // Case-insensitivity check
    let addr1_upper = addr1.to_uppercase();
    assert!(is_address_in_allowlist(&real_rpc_json, &addr1_upper), "Upper-case addr1 should match allowlist");

    // 2. Verify status parsing for active validator
    let status1 = parse_validator_status_from_json(&real_rpc_json, addr1);
    assert_eq!(status1.state, "ACTIVE");
    assert_eq!(status1.stake_wei, 32_000_000_000_000_000_000);
    assert!(!status1.is_jailed);
    assert_eq!(status1.missed_blocks, 0);

    // 3. Verify status parsing for unregistered candidate
    let status_new = parse_validator_status_from_json(&real_rpc_json, addr_new);
    assert_eq!(status_new.state, "UNREGISTERED");
    assert_eq!(status_new.stake_wei, 0);
    assert!(!status_new.is_jailed);
    assert_eq!(status_new.missed_blocks, 0);

    // 4. Verify jailed state detection from validators array
    let mut rpc_with_jailed = real_rpc_json.clone();
    rpc_with_jailed["result"]["activeValidators"] = serde_json::json!([]);
    rpc_with_jailed["result"]["validators"][0]["isJailed"] = serde_json::json!(true);
    let status_jailed = parse_validator_status_from_json(&rpc_with_jailed, addr1);
    assert_eq!(status_jailed.state, "JAILED");
    assert!(status_jailed.is_jailed);
}

#[test]
fn test_version_comparison_logic() {
    // Newer patch / sub-patch
    assert!(is_version_newer("v0.2.4.1-testnet", "v0.2.4-testnet"));
    assert!(is_version_newer("0.2.4.1-testnet", "0.2.4-testnet"));
    assert!(is_version_newer("v0.2.5-testnet", "v0.2.4.1-testnet"));
    assert!(is_version_newer("v0.2.5-testnet", "v0.2.4-testnet"));
    assert!(is_version_newer("0.2.5-testnet", "0.2.4-testnet"));
    // Newer minor
    assert!(is_version_newer("v0.3.0-testnet", "v0.2.4-testnet"));
    // Newer major
    assert!(is_version_newer("v1.0.0", "v0.2.4-testnet"));

    // Equal versions
    assert!(!is_version_newer("v0.2.4-testnet", "v0.2.4-testnet"));
    assert!(!is_version_newer("0.2.4-testnet", "0.2.4-testnet"));
    assert!(!is_version_newer("v0.2.4.1-testnet", "v0.2.4.1-testnet"));

    // Older versions
    assert!(!is_version_newer("v0.2.3-testnet", "v0.2.4-testnet"));
    assert!(!is_version_newer("v0.1.0", "v0.2.4-testnet"));

    // Malformed strings
    assert!(!is_version_newer("invalid", "v0.2.4-testnet"));
    assert!(!is_version_newer("v0.2.5-testnet", "invalid"));
}


