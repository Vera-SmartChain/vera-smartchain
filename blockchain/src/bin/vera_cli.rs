use ed25519_dalek::SigningKey;
use serde_json::json;
use std::env;
use std::path::Path;
use vera_blockchain::account::{address_from_hex, address_to_hex, address_from_pubkey};
use vera_blockchain::csmt::MerkleProof;
use vera_blockchain::genesis::GenesisConfig;
use vera_blockchain::transaction::Transaction;
use vera_blockchain::validator_application::{
    is_address_in_allowlist, is_version_newer, parse_validator_status_from_json, read_key_from_file_or_hex,
    ValidatorApplication,
};
use vera_engine_v2::{canonical_encode, normalize, ComputationGraph};

const CURRENT_VERSION: &str = vera_blockchain::NODE_VERSION;

async fn check_new_version_notice() {
    let cache_dir = if Path::new("/var/lib/vera").is_dir() {
        Path::new("/var/lib/vera")
    } else {
        Path::new("/tmp")
    };
    let cache_file = cache_dir.join("latest_version_cache.json");

    let now_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut latest_version: Option<String> = None;

    if let Ok(content) = std::fs::read_to_string(&cache_file) {
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&content) {
            let ts = val["timestamp"].as_u64().unwrap_or(0);
            if now_ts >= ts && (now_ts - ts) < 6 * 3600 {
                latest_version = val["latest_version"].as_str().map(|s| s.to_string());
            }
        }
    }

    if latest_version.is_none() {
        if let Ok(client) = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(3))
            .user_agent("vera_cli")
            .build()
        {
            if let Ok(res) = client.get("https://api.github.com/repos/Vera-SmartChain/vera-node-releases/releases/latest").send().await {
                if let Ok(val) = res.json::<serde_json::Value>().await {
                    if let Some(tag) = val["tag_name"].as_str() {
                        latest_version = Some(tag.to_string());
                        let cache_data = serde_json::json!({
                            "timestamp": now_ts,
                            "latest_version": tag
                        });
                        let _ = std::fs::write(&cache_file, cache_data.to_string());
                    }
                }
            }
        }
    }

    if let Some(latest) = latest_version {
        if is_version_newer(&latest, CURRENT_VERSION) {
            println!("\n💡 New version {} available — run: sudo bash vera-join.sh --upgrade", latest);
        }
    }
}


fn parse_key_and_remaining_args(
    args: &[String],
) -> Result<(SigningKey, Vec<String>), Box<dyn std::error::Error>> {
    if args.is_empty() {
        return Err("Missing private key or --key-file argument".into());
    }

    if args[0] == "--key-file" {
        if args.len() < 2 {
            return Err("Missing file path following '--key-file'".into());
        }
        let key = read_key_from_file_or_hex(&args[1])?;
        Ok((key, args[2..].to_vec()))
    } else {
        let key = read_key_from_file_or_hex(&args[0])?;
        Ok((key, args[1..].to_vec()))
    }
}

fn parse_block_number(val: &serde_json::Value) -> Option<u64> {
    if let Some(res) = val.get("result") {
        return parse_block_number(res);
    }
    match val {
        serde_json::Value::Number(n) => n.as_u64(),
        serde_json::Value::String(s) => {
            let clean = s.trim().trim_matches('"');
            if clean.starts_with("0x") || clean.starts_with("0X") {
                u64::from_str_radix(clean.trim_start_matches("0x").trim_start_matches("0X"), 16).ok()
            } else {
                clean.parse::<u64>().ok()
            }
        }
        _ => None,
    }
}

async fn wait_for_receipt(
    client: &reqwest::Client,
    rpc_url: &str,
    tx_hash: &str,
    timeout_secs: u64,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let start = std::time::Instant::now();
    let payload = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_getTransactionReceipt",
        "params": [tx_hash]
    });

    while start.elapsed().as_secs() < timeout_secs {
        if let Ok(res) = client.post(rpc_url).json(&payload).send().await {
            if let Ok(json) = res.json::<serde_json::Value>().await {
                if let Some(receipt) = json.get("result") {
                    if !receipt.is_null() {
                        let status = receipt["status"].as_str().unwrap_or("0x0");
                        if status == "0x1" {
                            return Ok(receipt.clone());
                        } else if status == "0x0" {
                            return Err(format!("Transaction {} execution failed on-chain (status 0x0)", tx_hash).into());
                        }
                    }
                }
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
    }
    Err(format!("Timeout waiting for transaction {} receipt after {}s", tx_hash, timeout_secs).into())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        print_usage();
        return Ok(());
    }

    if args.iter().any(|a| a == "--help" || a == "-h") {
        print_usage();
        return Ok(());
    }

    if args.iter().any(|a| a == "--version" || a == "-V" || a == "version") {
        println!("vera_cli {}", CURRENT_VERSION);
        return Ok(());
    }


    let rpc_url = env::var("VERA_RPC_URL").unwrap_or_else(|_| "http://127.0.0.1:8545".to_string());

    match args[1].as_str() {
        "keygen" => {
            let mut out_path: Option<String> = None;
            let mut i = 2;
            while i < args.len() {
                if args[i] == "--out" && i + 1 < args.len() {
                    out_path = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    i += 1;
                }
            }

            if let Some(ref path_str) = out_path {
                let path = Path::new(path_str);

                if let Some(parent) = path.parent() {
                    if !parent.as_os_str().is_empty() {
                        let _ = std::fs::create_dir_all(parent);
                    }
                }

                let mut csprng = rand::rngs::OsRng;
                let signing_key = SigningKey::generate(&mut csprng);
                let verifying_key = signing_key.verifying_key();
                let secret_bytes = signing_key.to_bytes();
                let pubkey_bytes = verifying_key.to_bytes();
                let address = address_from_pubkey(&pubkey_bytes);

                #[cfg(unix)]
                {
                    use std::fs::OpenOptions;
                    use std::io::Write;
                    use std::os::unix::fs::OpenOptionsExt;

                    let mut file = match OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .mode(0o600)
                        .open(path)
                    {
                        Ok(f) => f,
                        Err(e) => {
                            if e.kind() == std::io::ErrorKind::AlreadyExists {
                                eprintln!("Error: Output key file '{}' already exists. Refusing to overwrite.", path_str);
                            } else {
                                eprintln!("Error creating key file '{}': {}", path_str, e);
                            }
                            std::process::exit(1);
                        }
                    };
                    file.write_all(hex::encode(secret_bytes).as_bytes())?;
                    file.flush()?;

                    let is_root = std::process::Command::new("id")
                        .arg("-u")
                        .output()
                        .ok()
                        .and_then(|o| String::from_utf8(o.stdout).ok())
                        .map(|s| s.trim() == "0")
                        .unwrap_or(false);

                    if is_root {
                        let status = std::process::Command::new("chown").arg("vera:vera").arg(path_str).status();
                        match status {
                            Ok(s) if s.success() => {},
                            Ok(s) => {
                                eprintln!("Error: Failed to change ownership of '{}' to vera:vera (exit code: {:?})", path_str, s.code());
                                std::process::exit(1);
                            }
                            Err(e) => {
                                eprintln!("Error executing chown vera:vera on '{}': {}", path_str, e);
                                std::process::exit(1);
                            }
                        }
                    }
                }

                #[cfg(not(unix))]
                {
                    use std::fs::OpenOptions;
                    use std::io::Write;

                    let mut file = match OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(path)
                    {
                        Ok(f) => f,
                        Err(e) => {
                            if e.kind() == std::io::ErrorKind::AlreadyExists {
                                eprintln!("Error: Output key file '{}' already exists. Refusing to overwrite.", path_str);
                            } else {
                                eprintln!("Error creating key file '{}': {}", path_str, e);
                            }
                            std::process::exit(1);
                        }
                    };
                    file.write_all(hex::encode(secret_bytes).as_bytes())?;
                    file.flush()?;
                }

                println!("Address:    {}", address_to_hex(&address));
                println!("Public Key: 0x{}", hex::encode(pubkey_bytes));
            } else {
                let mut csprng = rand::rngs::OsRng;
                let signing_key = SigningKey::generate(&mut csprng);
                let verifying_key = signing_key.verifying_key();
                let secret_bytes = signing_key.to_bytes();
                let pubkey_bytes = verifying_key.to_bytes();
                let address = address_from_pubkey(&pubkey_bytes);

                println!("🔑 New Account Generated (Ed25519):");
                println!("Private Key: 0x{}", hex::encode(secret_bytes));
                println!("Public Key:  0x{}", hex::encode(pubkey_bytes));
                println!("Address:     {}", address_to_hex(&address));
            }
        }
        "status" => {
            let client = reqwest::Client::new();
            let payload = json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "vera_blockNumber",
                "params": []
            });

            match client.post(&rpc_url).json(&payload).send().await {
                Ok(res) => {
                    let json: serde_json::Value = res.json().await?;
                    println!("VERA Testnet Status:");
                    println!("Latest Block Height: {}", json["result"]);
                }
                Err(e) => eprintln!("Error connecting to RPC node ({}): {}", rpc_url, e),
            }
            check_new_version_notice().await;
        }

        "balance" => {
            if args.len() < 3 {
                eprintln!("Usage: vera_cli balance <hex_address>");
                return Ok(());
            }
            let addr = &args[2];
            let client = reqwest::Client::new();
            let payload = json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "vera_getAccount",
                "params": [addr]
            });

            match client.post(&rpc_url).json(&payload).send().await {
                Ok(res) => {
                    let json: serde_json::Value = res.json().await?;
                    println!("Account {}:", addr);
                    println!("Balance: {} wei", json["result"]["balance"]);
                    println!("Nonce:   {}", json["result"]["nonce"]);
                }
                Err(e) => eprintln!("Error connecting to RPC node: {}", e),
            }
        }
        "verify" => {
            if args.len() < 3 {
                eprintln!("Usage: vera_cli verify <hex_address>");
                return Ok(());
            }
            let addr_str = &args[2];
            let client = reqwest::Client::new();
            let payload = json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "vera_getProof",
                "params": [addr_str]
            });

            let res = client.post(&rpc_url).json(&payload).send().await?;
            let json_res: serde_json::Value = res.json().await?;
            let proof: MerkleProof = serde_json::from_value(json_res["result"].clone())?;

            let block_req = json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "vera_getBlockByNumber",
                "params": ["latest"]
            });
            let block_res = client.post(&rpc_url).json(&block_req).send().await?;
            let block_json: serde_json::Value = block_res.json().await?;
            let state_root_hex = block_json["result"]["header"]["state_root"].as_str().unwrap();
            let state_root_bytes = hex::decode(state_root_hex.trim_start_matches("0x"))?;
            let mut expected_state_root = [0u8; 32];
            expected_state_root.copy_from_slice(&state_root_bytes);

            let is_valid = vera_blockchain::csmt::CSMT::verify_proof(&expected_state_root, &proof);
            println!("🔍 CSMT Inclusion Proof Verification:");
            println!("Verified address:    {}", addr_str);
            println!("Proof siblings:      {} nodes", proof.siblings.len());
            println!("Proof Result:        {}", if is_valid { "✅ VALID (100% Deterministic)" } else { "❌ INVALID" });
        }
        "transfer" => {
            if args.len() < 4 {
                eprintln!("Usage: vera_cli transfer [--key-file <path> | <priv_hex>] <recipient_hex> <amount_wei> [nonce]");
                return Ok(());
            }
            let (signing_key, rem) = parse_key_and_remaining_args(&args[2..])?;
            if rem.len() < 2 {
                eprintln!("Usage: vera_cli transfer [--key-file <path> | <priv_hex>] <recipient_hex> <amount_wei> [nonce]");
                return Ok(());
            }
            let to_hex = &rem[0];
            let amount: u128 = rem[1].parse()?;
            let user_nonce: Option<u64> = if rem.len() > 2 { Some(rem[2].parse()?) } else { None };

            let to_addr = address_from_hex(to_hex)?;
            let client = reqwest::Client::new();
            let nonce = resolve_nonce(&client, &rpc_url, &signing_key, user_nonce).await?;

            let tx = Transaction::new(
                "vera-testnet-1",
                &signing_key,
                nonce,
                Some(to_addr),
                amount,
                25_000,
                1,
                vec![],
            );

            let raw_tx_hex = hex::encode(tx.to_bytes());
            let payload = json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "vera_sendRawTransaction",
                "params": [format!("0x{}", raw_tx_hex)]
            });

            let res = client.post(&rpc_url).json(&payload).send().await?;
            let json_res: serde_json::Value = res.json().await?;
            handle_rpc_tx_response(&json_res, "🚀 Transaction Broadcast!")?;
        }
        "stake" => {
            let mut force = false;
            let mut filtered_args = Vec::new();
            for a in &args[2..] {
                if a == "--force" {
                    force = true;
                } else {
                    filtered_args.push(a.clone());
                }
            }

            if filtered_args.is_empty() {
                eprintln!("Usage: vera_cli stake [--key-file <path> | <priv_hex>] [--force] <amount_wei> [nonce]");
                return Ok(());
            }
            let (signing_key, rem) = parse_key_and_remaining_args(&filtered_args)?;
            if rem.is_empty() {
                eprintln!("Usage: vera_cli stake [--key-file <path> | <priv_hex>] [--force] <amount_wei> [nonce]");
                return Ok(());
            }
            let amount: u128 = rem[0].parse()?;
            let user_nonce: Option<u64> = if rem.len() > 1 { Some(rem[1].parse()?) } else { None };

            let client = reqwest::Client::new();

            if !force {
                let pub_bytes = signing_key.verifying_key().to_bytes();
                let caller_addr = address_to_hex(&address_from_pubkey(&pub_bytes));

                let val_payload = json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "vera_getValidators",
                    "params": []
                });

                let val_res = client.post(&rpc_url).json(&val_payload).send().await
                    .map_err(|e| format!("Failed to connect to RPC node ({}): {}", rpc_url, e))?;
                let val_json: serde_json::Value = val_res.json().await?;

                if !is_address_in_allowlist(&val_json, &caller_addr) {
                    eprintln!("Error: not in validator allowlist — apply first (Step 5)");
                    std::process::exit(1);
                }
            }

            let nonce = resolve_nonce(&client, &rpc_url, &signing_key, user_nonce).await?;

            let tx = Transaction::new(
                "vera-testnet-1",
                &signing_key,
                nonce,
                Some(vera_blockchain::account::STAKING_SYSTEM_ADDRESS),
                amount,
                30_000,
                1,
                b"stake".to_vec(),
            );

            let raw_tx_hex = hex::encode(tx.to_bytes());
            let payload = json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "vera_sendRawTransaction",
                "params": [format!("0x{}", raw_tx_hex)]
            });

            let res = client.post(&rpc_url).json(&payload).send().await?;
            let json_res: serde_json::Value = res.json().await?;
            handle_rpc_tx_response(&json_res, "🔒 Staking Transaction Broadcast!")?;
        }

        "unstake" => {
            if args.len() < 3 {
                eprintln!("Usage: vera_cli unstake [--key-file <path> | <priv_hex>] <amount_wei> [nonce]");
                return Ok(());
            }
            let (signing_key, rem) = parse_key_and_remaining_args(&args[2..])?;
            if rem.is_empty() {
                eprintln!("Usage: vera_cli unstake [--key-file <path> | <priv_hex>] <amount_wei> [nonce]");
                return Ok(());
            }
            let amount: u128 = rem[0].parse()?;
            let user_nonce: Option<u64> = if rem.len() > 1 { Some(rem[1].parse()?) } else { None };

            let client = reqwest::Client::new();
            let nonce = resolve_nonce(&client, &rpc_url, &signing_key, user_nonce).await?;

            let tx = Transaction::new(
                "vera-testnet-1",
                &signing_key,
                nonce,
                Some(vera_blockchain::account::STAKING_SYSTEM_ADDRESS),
                amount,
                30_000,
                1,
                b"unstake".to_vec(),
            );

            let raw_tx_hex = hex::encode(tx.to_bytes());
            let payload = json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "vera_sendRawTransaction",
                "params": [format!("0x{}", raw_tx_hex)]
            });

            let res = client.post(&rpc_url).json(&payload).send().await?;
            let json_res: serde_json::Value = res.json().await?;
            handle_rpc_tx_response(&json_res, "🔓 Unstake Transaction Broadcast!")?;
        }
        "unjail" => {
            if args.len() < 2 {
                eprintln!("Usage: vera_cli unjail [--key-file <path> | <priv_hex>] [nonce]");
                return Ok(());
            }
            let (signing_key, rem) = parse_key_and_remaining_args(&args[2..])?;
            let user_nonce: Option<u64> = if !rem.is_empty() { Some(rem[0].parse()?) } else { None };

            let client = reqwest::Client::new();
            let nonce = resolve_nonce(&client, &rpc_url, &signing_key, user_nonce).await?;

            let tx = Transaction::new(
                "vera-testnet-1",
                &signing_key,
                nonce,
                Some(vera_blockchain::account::STAKING_SYSTEM_ADDRESS),
                0,
                30_000,
                1,
                b"unjail".to_vec(),
            );

            let raw_tx_hex = hex::encode(tx.to_bytes());
            let payload = json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "vera_sendRawTransaction",
                "params": [format!("0x{}", raw_tx_hex)]
            });

            let res = client.post(&rpc_url).json(&payload).send().await?;
            let json_res: serde_json::Value = res.json().await?;
            handle_rpc_tx_response(&json_res, "⚖️ Unjail Transaction Broadcast!")?;
        }
        "allow" => {
            if args.len() < 3 {
                eprintln!("Usage: vera_cli allow [--key-file <path> | <gov_priv_hex>] <val_addr_hex> [nonce]");
                return Ok(());
            }
            let (signing_key, rem) = parse_key_and_remaining_args(&args[2..])?;
            if rem.is_empty() {
                eprintln!("Usage: vera_cli allow [--key-file <path> | <gov_priv_hex>] <val_addr_hex> [nonce]");
                return Ok(());
            }
            let val_addr_hex = rem[0].strip_prefix("0x").unwrap_or(&rem[0]);
            let user_nonce: Option<u64> = if rem.len() > 1 { Some(rem[1].parse()?) } else { None };

            let client = reqwest::Client::new();
            let nonce = resolve_nonce(&client, &rpc_url, &signing_key, user_nonce).await?;

            let payload_data = format!("allow:0x{}", val_addr_hex).into_bytes();

            let tx = Transaction::new(
                "vera-testnet-1",
                &signing_key,
                nonce,
                Some(vera_blockchain::account::STAKING_SYSTEM_ADDRESS),
                0,
                30_000,
                1,
                payload_data,
            );

            let raw_tx_hex = hex::encode(tx.to_bytes());
            let payload = json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "vera_sendRawTransaction",
                "params": [format!("0x{}", raw_tx_hex)]
            });

            let res = client.post(&rpc_url).json(&payload).send().await?;
            let json_res: serde_json::Value = res.json().await?;
            handle_rpc_tx_response(&json_res, "🛡️ Governance Transaction (Allowlist Add) Broadcast!")?;
        }
        "disallow" => {
            if args.len() < 3 {
                eprintln!("Usage: vera_cli disallow [--key-file <path> | <gov_priv_hex>] <val_addr_hex> [nonce]");
                return Ok(());
            }
            let (signing_key, rem) = parse_key_and_remaining_args(&args[2..])?;
            if rem.is_empty() {
                eprintln!("Usage: vera_cli disallow [--key-file <path> | <gov_priv_hex>] <val_addr_hex> [nonce]");
                return Ok(());
            }
            let val_addr_hex = rem[0].strip_prefix("0x").unwrap_or(&rem[0]);
            let user_nonce: Option<u64> = if rem.len() > 1 { Some(rem[1].parse()?) } else { None };

            let client = reqwest::Client::new();
            let nonce = resolve_nonce(&client, &rpc_url, &signing_key, user_nonce).await?;

            let payload_data = format!("disallow:0x{}", val_addr_hex).into_bytes();

            let tx = Transaction::new(
                "vera-testnet-1",
                &signing_key,
                nonce,
                Some(vera_blockchain::account::STAKING_SYSTEM_ADDRESS),
                0,
                30_000,
                1,
                payload_data,
            );

            let raw_tx_hex = hex::encode(tx.to_bytes());
            let payload = json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "vera_sendRawTransaction",
                "params": [format!("0x{}", raw_tx_hex)]
            });

            let res = client.post(&rpc_url).json(&payload).send().await?;
            let json_res: serde_json::Value = res.json().await?;
            handle_rpc_tx_response(&json_res, "🛡️ Governance Transaction (Allowlist Remove) Broadcast!")?;
        }
        "set_governance" => {
            if args.len() < 3 {
                eprintln!("Usage: vera_cli set_governance [--key-file <path> | <gov_priv_hex>] <new_gov_addr_hex> [nonce]");
                return Ok(());
            }
            let (signing_key, rem) = parse_key_and_remaining_args(&args[2..])?;
            if rem.is_empty() {
                eprintln!("Usage: vera_cli set_governance [--key-file <path> | <gov_priv_hex>] <new_gov_addr_hex> [nonce]");
                return Ok(());
            }
            let new_gov_hex = rem[0].strip_prefix("0x").unwrap_or(&rem[0]);
            let user_nonce: Option<u64> = if rem.len() > 1 { Some(rem[1].parse()?) } else { None };

            let client = reqwest::Client::new();
            let nonce = resolve_nonce(&client, &rpc_url, &signing_key, user_nonce).await?;

            let payload_data = format!("set_governance:0x{}", new_gov_hex).into_bytes();

            let tx = Transaction::new(
                "vera-testnet-1",
                &signing_key,
                nonce,
                Some(vera_blockchain::account::STAKING_SYSTEM_ADDRESS),
                0,
                30_000,
                1,
                payload_data,
            );

            let raw_tx_hex = hex::encode(tx.to_bytes());
            let payload = json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "vera_sendRawTransaction",
                "params": [format!("0x{}", raw_tx_hex)]
            });

            let res = client.post(&rpc_url).json(&payload).send().await?;
            let json_res: serde_json::Value = res.json().await?;
            handle_rpc_tx_response(&json_res, "🏛️ Governance Transaction (Governance Transfer) Broadcast!")?;
        }
        "validators" => {
            let client = reqwest::Client::new();
            let payload = json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "vera_getValidators",
                "params": []
            });

            match client.post(&rpc_url).json(&payload).send().await {
                Ok(res) => {
                    let json: serde_json::Value = res.json().await?;
                    if let Some(result) = json.get("result") {
                        println!("=== VERA VALIDATOR SET ===");
                        println!("Total Stake:             {} wei", result["totalStake"]);
                        println!("Active Total Stake:      {} wei", result["activeTotalStake"]);
                        println!("Supermajority Threshold: {} wei", result["supermajorityThreshold"]);
                        println!("Min Validator Stake:     {} wei", result["minValidatorStake"]);
                        println!("Max Active Validators:   {}", result["maxActiveValidators"]);
                        println!("Permissioned:            {}", result["permissionedValidators"]);
                        println!("Governance:              {}", result["governanceAddress"]);
                        println!("\nActive Validators ({:?}):", result["activeValidators"].as_array().map(|a| a.len()).unwrap_or(0));
                        if let Some(arr) = result["activeValidators"].as_array() {
                            for v in arr {
                                println!("  - {} (stake: {} wei, missed: {})", v["address"], v["stake"], v["missedBlocks"]);
                            }
                        }
                        if let Some(arr) = result["validators"].as_array() {
                            let jailed: Vec<_> = arr.iter().filter(|v| v["isJailed"].as_bool().unwrap_or(false)).collect();
                            if !jailed.is_empty() {
                                println!("\nJailed Validators ({}):", jailed.len());
                                for v in jailed {
                                    println!("  - {} (stake: {} wei)", v["address"], v["stake"]);
                                }
                            }
                        }
                    } else {
                        eprintln!("Failed to parse validator set: {}", json);
                    }
                }
                Err(e) => eprintln!("Error fetching validator set from RPC: {}", e),
            }
        }
        "syncwait" => {
            let mut timeout_secs: u64 = 300;
            let mut remote_url = env::var("VERA_REMOTE_RPC_URL")
                .unwrap_or_else(|_| "https://testnet-rpc.verachain.cloud".to_string());
            let mut local_url = rpc_url.clone();

            let mut i = 2;
            while i < args.len() {
                if args[i] == "--timeout" && i + 1 < args.len() {
                    timeout_secs = args[i + 1].parse().unwrap_or(300);
                    i += 2;
                } else if args[i] == "--remote" && i + 1 < args.len() {
                    remote_url = args[i + 1].clone();
                    i += 2;
                } else if args[i] == "--local" && i + 1 < args.len() {
                    local_url = args[i + 1].clone();
                    i += 2;
                } else {
                    i += 1;
                }
            }

            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(5))
                .build()?;

            let start = std::time::Instant::now();
            let payload = json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "vera_blockNumber",
                "params": []
            });

            let mut last_log = std::time::Instant::now() - std::time::Duration::from_secs(10);

            loop {
                if start.elapsed().as_secs() > timeout_secs {
                    eprintln!("Error: Timeout waiting for synchronization after {}s", timeout_secs);
                    std::process::exit(1);
                }

                let local_res = client.post(&local_url).json(&payload).send().await;
                let remote_res = client.post(&remote_url).json(&payload).send().await;

                let local_h = match local_res {
                    Ok(r) => r.json::<serde_json::Value>().await.ok().and_then(|j| parse_block_number(&j)),
                    Err(_) => None,
                };

                let remote_h = match remote_res {
                    Ok(r) => r.json::<serde_json::Value>().await.ok().and_then(|j| parse_block_number(&j)),
                    Err(_) => None,
                };

                if let (Some(lh), Some(rh)) = (local_h, remote_h) {
                    if lh >= rh {
                        println!("SYNCED at block #{}", lh);
                        return Ok(());
                    }
                }

                if last_log.elapsed().as_secs() >= 5 {
                    last_log = std::time::Instant::now();
                    match (local_h, remote_h) {
                        (Some(lh), Some(rh)) => {
                            println!("Sync progress: local #{} / network #{}", lh, rh);
                        }
                        (None, Some(rh)) => {
                            eprintln!("local RPC unreachable at {} — is vera-node running? (network is at #{})", local_url, rh);
                        }
                        (Some(lh), None) => {
                            eprintln!("network RPC unreachable at {} — check internet connectivity (local is at #{})", remote_url, lh);
                        }

                        (None, None) => {
                            eprintln!("local RPC unreachable at {} AND network RPC unreachable at {}", local_url, remote_url);
                        }
                    }
                }

                tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
            }
        }

        "apply-validator" => {
            let mut key_file: Option<String> = None;
            let mut operator: Option<String> = None;

            let mut i = 2;
            while i < args.len() {
                if args[i] == "--key-file" && i + 1 < args.len() {
                    key_file = Some(args[i + 1].clone());
                    i += 2;
                } else if args[i] == "--operator" && i + 1 < args.len() {
                    operator = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    i += 1;
                }
            }

            let kf = key_file.ok_or("Missing required argument --key-file <path>")?;
            let op = operator.ok_or("Missing required argument --operator <name>")?;

            let signing_key = read_key_from_file_or_hex(&kf)?;
            let chain_id = "vera-testnet-1";

            let app = ValidatorApplication::new(&signing_key, chain_id, &op);
            println!("{}", app.to_block_text());
        }
        "validator-status" => {
            let mut key_file: Option<String> = None;
            let mut target_addr: Option<String> = None;

            let mut i = 2;
            while i < args.len() {
                if args[i] == "--key-file" && i + 1 < args.len() {
                    key_file = Some(args[i + 1].clone());
                    i += 2;
                } else if args[i] == "--address" && i + 1 < args.len() {
                    target_addr = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    i += 1;
                }
            }

            let addr_to_check = if let Some(a) = target_addr {
                a
            } else if let Some(kf) = key_file {
                let sk = read_key_from_file_or_hex(&kf)?;
                let pub_bytes = sk.verifying_key().to_bytes();
                address_to_hex(&address_from_pubkey(&pub_bytes))
            } else if Path::new("/etc/vera/validator_key.hex").exists() {
                let sk = read_key_from_file_or_hex("/etc/vera/validator_key.hex")?;
                let pub_bytes = sk.verifying_key().to_bytes();
                address_to_hex(&address_from_pubkey(&pub_bytes))
            } else {
                eprintln!("Usage: vera_cli validator-status --key-file <path> OR --address <hex_addr>");
                std::process::exit(1);
            };

            let client = reqwest::Client::new();
            let val_payload = json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "vera_getValidators",
                "params": []
            });

            let res = client.post(&rpc_url).json(&val_payload).send().await
                .map_err(|e| format!("Failed to connect to RPC node ({}): {}", rpc_url, e))?;
            let val_json: serde_json::Value = res.json().await?;
            let _result = val_json.get("result").ok_or("Invalid response from vera_getValidators")?;

            let peer_payload = json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "net_peerCount",
                "params": []
            });
            let peer_count = match client.post(&rpc_url).json(&peer_payload).send().await {
                Ok(r) => {
                    if let Ok(j) = r.json::<serde_json::Value>().await {
                        if let Some(s) = j["result"].as_str() {
                            u64::from_str_radix(s.trim_start_matches("0x"), 16).unwrap_or(0)
                        } else {
                            j["result"].as_u64().unwrap_or(0)
                        }
                    } else { 0 }
                }
                Err(_) => 0,
            };

            let status = parse_validator_status_from_json(&val_json, &addr_to_check);
            let stake_vera = status.stake_wei / 1_000_000_000_000_000_000;

            println!("Validator:     {}", addr_to_check);
            println!("Status:        {} stake={} VERA jailed={}", status.state, stake_vera, status.is_jailed);
            println!("Missed Blocks: {}", status.missed_blocks);
            println!("Active Peers:  {}", peer_count);
            println!();
            println!("{} stake={} VERA jailed={}", status.state, stake_vera, status.is_jailed);
            check_new_version_notice().await;
        }

        "approve-validator" => {
            let mut block_text: Option<String> = None;
            let mut gov_key_path = "/etc/vera/governance_key.hex".to_string();
            let mut treasury_key_path = "/etc/vera/treasury_key.hex".to_string();
            let mut expected_chain_id = "vera-testnet-1".to_string();

            let mut i = 2;
            while i < args.len() {
                if args[i] == "--gov-key" && i + 1 < args.len() {
                    gov_key_path = args[i + 1].clone();
                    i += 2;
                } else if args[i] == "--treasury-key" && i + 1 < args.len() {
                    treasury_key_path = args[i + 1].clone();
                    i += 2;
                } else if args[i] == "--chain-id" && i + 1 < args.len() {
                    expected_chain_id = args[i + 1].clone();
                    i += 2;
                } else if block_text.is_none() && (args[i].starts_with("-----") || !args[i].starts_with("--")) {
                    block_text = Some(args[i].clone());
                    i += 1;
                } else {
                    i += 1;
                }
            }

            let text = block_text.ok_or("Missing application block argument. Usage: vera_cli approve-validator '<block>'")?;
            let raw_text = if Path::new(&text).exists() {
                std::fs::read_to_string(&text)?
            } else {
                text
            };
            let app = ValidatorApplication::parse_block(&raw_text)
                .map_err(|e| format!("Application block parsing error: {}", e))?;

            app.verify(&expected_chain_id, 7 * 86400)
                .map_err(|e| format!("Application verification error: {}", e))?;

            let val_addr = address_from_hex(&app.address)?;

            let client = reqwest::Client::new();
            let val_res = client.post(&rpc_url).json(&json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "vera_getValidators",
                "params": []
            })).send().await
                .map_err(|e| format!("Failed to connect to RPC node ({}): {}", rpc_url, e))?;
            let val_json: serde_json::Value = val_res.json().await?;
            if is_address_in_allowlist(&val_json, &app.address) {
                eprintln!("Error: Address {} is already in the validator allowlist.", app.address);
                std::process::exit(1);
            }

            if !Path::new(&treasury_key_path).exists() && Path::new("/etc/vera/faucet_key.hex").exists() {
                treasury_key_path = "/etc/vera/faucet_key.hex".to_string();
            }

            let gov_key = read_key_from_file_or_hex(&gov_key_path)
                .map_err(|e| format!("Failed to read governance key from '{}': {}", gov_key_path, e))?;
            let gov_pub = gov_key.verifying_key().to_bytes();
            let gov_addr = address_to_hex(&address_from_pubkey(&gov_pub));
            println!("Using governance key: {} (Address: {})", gov_key_path, gov_addr);

            let gov_nonce = resolve_nonce(&client, &rpc_url, &gov_key, None).await?;

            let allow_payload = format!("allow:{}", app.address).into_bytes();
            let allow_tx = Transaction::new(
                &expected_chain_id,
                &gov_key,
                gov_nonce,
                Some(vera_blockchain::account::STAKING_SYSTEM_ADDRESS),
                0,
                30_000,
                1,
                allow_payload,
            );
            let allow_raw = format!("0x{}", hex::encode(allow_tx.to_bytes()));
            let allow_resp = client.post(&rpc_url).json(&json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "vera_sendRawTransaction",
                "params": [allow_raw]
            })).send().await?;
            let allow_json: serde_json::Value = allow_resp.json().await?;
            if let Some(err) = allow_json.get("error") {
                eprintln!("Error submitting allow transaction: {}", err);
                std::process::exit(1);
            }
            let allow_tx_hash = allow_json["result"].as_str().ok_or("Missing allow tx hash")?.to_string();
            println!("Submitted allow transaction: {}", allow_tx_hash);

            let treasury_key = read_key_from_file_or_hex(&treasury_key_path)
                .map_err(|e| format!("Failed to read treasury key from '{}': {}", treasury_key_path, e))?;
            let treasury_pub = treasury_key.verifying_key().to_bytes();
            let treasury_addr = address_to_hex(&address_from_pubkey(&treasury_pub));
            println!("Using treasury key: {} (Address: {})", treasury_key_path, treasury_addr);

            let funding_amount: u128 = 33_000_000_000_000_000_000;
            let mut fund_tx_hash: Option<String> = None;

            for attempt in 1..=2 {
                let treasury_nonce = resolve_nonce(&client, &rpc_url, &treasury_key, None).await?;
                let fund_tx = Transaction::new(
                    &expected_chain_id,
                    &treasury_key,
                    treasury_nonce,
                    Some(val_addr),
                    funding_amount,
                    25_000,
                    1,
                    vec![],
                );
                let fund_raw = format!("0x{}", hex::encode(fund_tx.to_bytes()));
                let fund_resp = client.post(&rpc_url).json(&json!({
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "vera_sendRawTransaction",
                    "params": [fund_raw]
                })).send().await?;
                let fund_json: serde_json::Value = fund_resp.json().await?;
                if let Some(err) = fund_json.get("error") {
                    let err_msg = err.to_string();
                    if attempt == 1 && (err_msg.contains("nonce") || err_msg.contains("Nonce")) {
                        eprintln!("Treasury nonce conflict detected on attempt 1, re-querying network nonce and retrying...");
                        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                        continue;
                    }
                    eprintln!("Error submitting funding transaction: {}", err);
                    std::process::exit(1);
                }
                fund_tx_hash = fund_json["result"].as_str().map(|s| s.to_string());
                break;
            }

            let fund_tx_hash = fund_tx_hash.ok_or("Missing funding tx hash")?;
            println!("Submitted funding transaction (33 VERA): {}", fund_tx_hash);

            println!("Waiting for transactions to commit on-chain...");
            let allow_receipt = wait_for_receipt(&client, &rpc_url, &allow_tx_hash, 60).await?;
            let fund_receipt = wait_for_receipt(&client, &rpc_url, &fund_tx_hash, 60).await?;

            let allow_block = allow_receipt["blockNumber"].as_str().unwrap_or("confirmed");
            let fund_block = fund_receipt["blockNumber"].as_str().unwrap_or("confirmed");

            let formatted_operator = if app.operator.starts_with('@') {
                app.operator.clone()
            } else {
                format!("@{}", app.operator)
            };

            println!();
            println!("✅ Validator application approved successfully!");
            println!("Allow TX:     {} (Block {})", allow_tx_hash, allow_block);
            println!("Funding TX:   {} (Block {}, 33 VERA funded)", fund_tx_hash, fund_block);
            println!();
            println!("Issue Response Template:");
            println!("--------------------------------------------------------------------------------");
            println!("Hello {}! Your validator application for address {} has been approved and funded with 33 VERA.", formatted_operator, app.address);
            println!("- Allowlist TX: {}", allow_tx_hash);
            println!("- Funding TX:   {}", fund_tx_hash);
            println!("Proceed to Step 7 (enable validator service) and Step 8 (stake 32 VERA).");
            println!("--------------------------------------------------------------------------------");
        }
        "signraw" => {
            if args.len() < 7 {
                eprintln!("Usage: vera_cli signraw <priv_hex> <dest_hex> <amount_wei> <start_nonce> <count>");
                return Ok(());
            }
            let priv_hex = args[2].strip_prefix("0x").unwrap_or(&args[2]);
            let dest_hex = &args[3];
            let amount: u128 = args[4].parse()?;
            let start_nonce: u64 = args[5].parse()?;
            let count: u64 = args[6].parse()?;

            let priv_bytes = hex::decode(priv_hex)?;
            let mut key_bytes = [0u8; 32];
            key_bytes.copy_from_slice(&priv_bytes);
            let signing_key = SigningKey::from_bytes(&key_bytes);
            let to_addr = address_from_hex(dest_hex)?;

            let mut batch = Vec::new();
            for i in 0..count {
                let tx = Transaction::new(
                    "vera-testnet-1",
                    &signing_key,
                    start_nonce + i,
                    Some(to_addr),
                    amount,
                    25_000,
                    1,
                    vec![],
                );
                batch.push(format!("0x{}", hex::encode(tx.to_bytes())));
            }
            println!("{}", serde_json::to_string(&batch)?);
        }
        "assemble" => {
            if args.len() < 4 {
                eprintln!("Usage: vera_cli assemble <source.json> <dest.json>");
                return Ok(());
            }
            let src_path = &args[2];
            let out_path = &args[3];
            let src = std::fs::read_to_string(src_path)?;
            let graph = ComputationGraph::from_json(&src)
                .map_err(|e| format!("Failed to parse VERA v2 JSON Graph: {}", e))?;
            graph.validate_invariants()
                .map_err(|e| format!("DAG invariant violated: {}", e))?;

            let normalized = normalize(&graph);
            let canonical_bytes = normalized.to_json();
            let hash = vera_blockchain::chain_hash::hash256(&canonical_encode(&graph));
            std::fs::write(out_path, canonical_bytes.as_bytes())?;

            println!("✅ VERA v2 Contract successfully compiled and normalized!");
            println!("Source:       {}", src_path);
            println!("Destination:  {} ({} canonical nodes)", out_path, normalized.nodes.len());
            println!("VERA Canonical Hash: 0x{}", hex::encode(hash));
        }
        "disassemble" => {
            if args.len() < 3 {
                eprintln!("Usage: vera_cli disassemble <contract.v2>");
                return Ok(());
            }
            let bin_path = &args[2];
            let content = std::fs::read_to_string(bin_path)?;
            let graph = ComputationGraph::from_json(&content)
                .map_err(|e| format!("Failed to read VERA v2 contract: {}", e))?;
            println!("=== VERA v2 CANONICAL SSA GRAPH ({}) ===", bin_path);
            for node in &graph.nodes {
                println!("  Node {:?}: {:?}", node.id, node.op);
            }
        }
        "genesis" => {
            let out_file = if args.len() > 2 { &args[2] } else { "genesis_mainnet.json" };
            let default_val_pub = [0x42u8; 32];
            let cfg = GenesisConfig::mainnet(&[default_val_pub])?;
            cfg.save_to_file(out_file)?;
            println!("🌟 Official VERA Mainnet Genesis File generated successfully!");
            println!("File:             {}", out_file);
            println!("Chain ID:         {}", cfg.chain_id);
            println!("Total Supply:     100,000,000 VERA");
            println!("Official Allocations:");
            println!("  - Validator Rewards (10 years): 35,000,000 VERA (35%)");
            println!("  - Treasury & Ecosystem:         25,000,000 VERA (25%)");
            println!("  - Founders & Core Team (Vesting):20,000,000 VERA (20%)");
            println!("  - Market Liquidity (DEX/CEX):    10,000,000 VERA (10%)");
            println!("  - Community Onboarding:          10,000,000 VERA (10%)");
        }
        cmd => {
            eprintln!("Unknown command: {}", cmd);
            print_usage();
        }
    }

    Ok(())
}

fn print_usage() {
    println!("VERA SmartChain Node CLI (v{})", CURRENT_VERSION);
    println!("Usage: vera_cli <command> [options]");
    println!();
    println!("Commands:");
    println!("  vera_cli --version");
    println!("  vera_cli keygen [--out <path>]");
    println!("  vera_cli status");
    println!("  vera_cli syncwait [--timeout <seconds>] [--remote <url>] [--local <url>]");
    println!("  vera_cli apply-validator --key-file <path> --operator <name>");
    println!("  vera_cli validator-status [--key-file <path>] [--address <hex>]");
    println!("  vera_cli approve-validator '<application_block>' [--gov-key <path>] [--treasury-key <path>]");
    println!("  vera_cli balance <address>");
    println!("  vera_cli verify <address>");
    println!("  vera_cli transfer [--key-file <path> | <priv_hex>] <recipient_hex> <amount> [nonce]");
    println!("  vera_cli stake [--key-file <path> | <priv_hex>] [--force] <amount_wei> [nonce]");
    println!("  vera_cli unstake [--key-file <path> | <priv_hex>] <amount_wei> [nonce]");
    println!("  vera_cli unjail [--key-file <path> | <priv_hex>] [nonce]");
    println!("  vera_cli allow [--key-file <path> | <gov_priv_hex>] <val_addr_hex> [nonce]");
    println!("  vera_cli disallow [--key-file <path> | <gov_priv_hex>] <val_addr_hex> [nonce]");
    println!("  vera_cli set_governance [--key-file <path> | <gov_priv_hex>] <new_gov_addr_hex> [nonce]");
    println!("  vera_cli validators");
    println!("  vera_cli signraw <priv_hex> <dest_hex> <amount_wei> <start_nonce> <count>");
    println!("  vera_cli assemble <source.json> <dest.json>");
    println!("  vera_cli disassemble <binary.vbc>");
    println!("  vera_cli genesis [dest.json]");
}


fn handle_rpc_tx_response(json_res: &serde_json::Value, success_msg: &str) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(err) = json_res.get("error") {
        let msg = err.get("message").and_then(|m| m.as_str()).unwrap_or_else(|| err.as_str().unwrap_or("Unknown error"));
        eprintln!("❌ RPC Error: {}", msg);
        std::process::exit(1);
    }
    println!("{}", success_msg);
    if let Some(res) = json_res.get("result").and_then(|r| r.as_str()) {
        println!("TX Hash: \"{}\"", res);
    } else {
        println!("TX Hash: {}", json_res["result"]);
    }
    Ok(())
}

async fn resolve_nonce(
    client: &reqwest::Client,
    rpc_url: &str,
    signing_key: &SigningKey,
    user_nonce: Option<u64>,
) -> Result<u64, Box<dyn std::error::Error>> {
    if let Some(n) = user_nonce {
        return Ok(n);
    }

    let pubkey = signing_key.verifying_key().to_bytes();
    let addr = address_from_pubkey(&pubkey);
    let addr_hex = address_to_hex(&addr);

    let payload = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "vera_getAccount",
        "params": [addr_hex]
    });

    let res = client.post(rpc_url).json(&payload).send().await
        .map_err(|e| format!("Failed to connect to RPC ({}) to query nonce: {}", rpc_url, e))?;
    let json: serde_json::Value = res.json().await
        .map_err(|e| format!("Failed to parse RPC response: {}", e))?;

    if let Some(err) = json.get("error") {
        let msg = err.get("message").and_then(|m| m.as_str()).unwrap_or("Unknown error");
        return Err(format!("RPC error querying account nonce: {}", msg).into());
    }

    let nonce_val = &json["result"]["nonce"];
    let nonce = match nonce_val {
        serde_json::Value::Number(n) => n.as_u64().ok_or_else(|| "Invalid numeric nonce".to_string())?,
        serde_json::Value::String(s) => {
            if s.starts_with("0x") {
                u64::from_str_radix(s.trim_start_matches("0x"), 16)?
            } else {
                s.parse::<u64>()?
            }
        }
        _ => return Err(format!("Invalid or missing nonce in RPC response for account {}", addr_hex).into()),
    };

    println!("ℹ️ Nonce not provided: auto-fetched current nonce {} from network", nonce);
    Ok(nonce)
}
