use ed25519_dalek::SigningKey;
use serde_json::json;
use std::env;
use vera_blockchain::account::{address_from_hex, address_to_hex};
use vera_blockchain::csmt::MerkleProof;
use vera_blockchain::genesis::GenesisConfig;
use vera_blockchain::transaction::Transaction;
use vera_engine_v2::{canonical_encode, normalize, ComputationGraph};

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

    let rpc_url = env::var("VERA_RPC_URL").unwrap_or_else(|_| "http://127.0.0.1:8545".to_string());

    match args[1].as_str() {
        "keygen" => {
            let mut csprng = rand::rngs::OsRng;
            let signing_key = SigningKey::generate(&mut csprng);
            let verifying_key = signing_key.verifying_key();
            let secret_bytes = signing_key.to_bytes();
            let pubkey_bytes = verifying_key.to_bytes();
            let address = vera_blockchain::account::address_from_pubkey(&pubkey_bytes);

            println!("🔑 New Account Generated (Ed25519):");
            println!("Private Key: 0x{}", hex::encode(secret_bytes));
            println!("Public Key:  0x{}", hex::encode(pubkey_bytes));
            println!("Address:     {}", address_to_hex(&address));
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
            if args.len() < 5 {
                eprintln!("Usage: vera_cli transfer <private_key_hex> <recipient_hex> <amount_wei> [nonce]");
                return Ok(());
            }
            let priv_hex = args[2].strip_prefix("0x").unwrap_or(&args[2]);
            let to_hex = &args[3];
            let amount: u128 = args[4].parse()?;
            let nonce: u64 = if args.len() > 5 { args[5].parse()? } else { 0 };

            let priv_bytes = hex::decode(priv_hex)?;
            let mut key_bytes = [0u8; 32];
            key_bytes.copy_from_slice(&priv_bytes);
            let signing_key = SigningKey::from_bytes(&key_bytes);

            let to_addr = address_from_hex(to_hex)?;

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
            let client = reqwest::Client::new();
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
            if args.len() < 4 {
                eprintln!("Usage: vera_cli stake <private_key_hex> <amount_wei> [nonce]");
                return Ok(());
            }
            let priv_hex = args[2].strip_prefix("0x").unwrap_or(&args[2]);
            let amount: u128 = args[3].parse()?;
            let nonce: u64 = if args.len() > 4 { args[4].parse()? } else { 0 };

            let priv_bytes = hex::decode(priv_hex)?;
            let mut key_bytes = [0u8; 32];
            key_bytes.copy_from_slice(&priv_bytes);
            let signing_key = SigningKey::from_bytes(&key_bytes);

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
            let client = reqwest::Client::new();
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
            if args.len() < 4 {
                eprintln!("Usage: vera_cli unstake <private_key_hex> <amount_wei> [nonce]");
                return Ok(());
            }
            let priv_hex = args[2].strip_prefix("0x").unwrap_or(&args[2]);
            let amount: u128 = args[3].parse()?;
            let nonce: u64 = if args.len() > 4 { args[4].parse()? } else { 0 };

            let priv_bytes = hex::decode(priv_hex)?;
            let mut key_bytes = [0u8; 32];
            key_bytes.copy_from_slice(&priv_bytes);
            let signing_key = SigningKey::from_bytes(&key_bytes);

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
            let client = reqwest::Client::new();
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
            if args.len() < 3 {
                eprintln!("Usage: vera_cli unjail <private_key_hex> [nonce]");
                return Ok(());
            }
            let priv_hex = args[2].strip_prefix("0x").unwrap_or(&args[2]);
            let nonce: u64 = if args.len() > 3 { args[3].parse()? } else { 0 };

            let priv_bytes = hex::decode(priv_hex)?;
            let mut key_bytes = [0u8; 32];
            key_bytes.copy_from_slice(&priv_bytes);
            let signing_key = SigningKey::from_bytes(&key_bytes);

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
            let client = reqwest::Client::new();
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
            if args.len() < 4 {
                eprintln!("Usage: vera_cli allow <gov_priv_key_hex> <val_addr_hex> [nonce]");
                return Ok(());
            }
            let priv_hex = args[2].strip_prefix("0x").unwrap_or(&args[2]);
            let val_addr_hex = args[3].strip_prefix("0x").unwrap_or(&args[3]);
            let nonce: u64 = if args.len() > 4 { args[4].parse()? } else { 0 };

            let priv_bytes = hex::decode(priv_hex)?;
            let mut key_bytes = [0u8; 32];
            key_bytes.copy_from_slice(&priv_bytes);
            let signing_key = SigningKey::from_bytes(&key_bytes);

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
            let client = reqwest::Client::new();
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
            if args.len() < 4 {
                eprintln!("Usage: vera_cli disallow <gov_priv_key_hex> <val_addr_hex> [nonce]");
                return Ok(());
            }
            let priv_hex = args[2].strip_prefix("0x").unwrap_or(&args[2]);
            let val_addr_hex = args[3].strip_prefix("0x").unwrap_or(&args[3]);
            let nonce: u64 = if args.len() > 4 { args[4].parse()? } else { 0 };

            let priv_bytes = hex::decode(priv_hex)?;
            let mut key_bytes = [0u8; 32];
            key_bytes.copy_from_slice(&priv_bytes);
            let signing_key = SigningKey::from_bytes(&key_bytes);

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
            let client = reqwest::Client::new();
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
            if args.len() < 4 {
                eprintln!("Usage: vera_cli set_governance <gov_priv_key_hex> <new_gov_addr_hex> [nonce]");
                return Ok(());
            }
            let priv_hex = args[2].strip_prefix("0x").unwrap_or(&args[2]);
            let new_gov_hex = args[3].strip_prefix("0x").unwrap_or(&args[3]);
            let nonce: u64 = if args.len() > 4 { args[4].parse()? } else { 0 };

            let priv_bytes = hex::decode(priv_hex)?;
            let mut key_bytes = [0u8; 32];
            key_bytes.copy_from_slice(&priv_bytes);
            let signing_key = SigningKey::from_bytes(&key_bytes);

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
            let client = reqwest::Client::new();
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
                        if let Some(arr) = result["unbondingQueue"].as_array() {
                            if !arr.is_empty() {
                                println!("\nUnbonding Queue ({}):", arr.len());
                                for u in arr {
                                    println!("  - {} amount: {} wei, release at block #{}", u["validatorAddress"], u["amount"], u["releaseHeight"]);
                                }
                            }
                        }
                    } else {
                        eprintln!("RPC response error: {:?}", json);
                    }
                }
                Err(e) => eprintln!("Error connecting to RPC node: {}", e),
            }
        }
        "signraw" => {
            if args.len() < 7 {
                eprintln!("Usage: vera_cli signraw <priv_hex> <dest_hex> <amount_wei> <start_nonce> <count>");
                return Ok(());
            }
            let priv_hex = args[2].strip_prefix("0x").unwrap_or(&args[2]);
            let to_hex = &args[3];
            let amount: u128 = args[4].parse()?;
            let start_nonce: u64 = args[5].parse()?;
            let count: u64 = args[6].parse()?;
            let priv_bytes = hex::decode(priv_hex)?;
            let mut key_bytes = [0u8; 32];
            key_bytes.copy_from_slice(&priv_bytes);
            let signing_key = SigningKey::from_bytes(&key_bytes);
            let to_addr = address_from_hex(to_hex)?;
            let mut out = String::new();
            for i in 0..count {
                let tx = Transaction::new(
                    "vera-testnet-1", &signing_key, start_nonce + i,
                    Some(to_addr), amount, 25_000, 1, vec![],
                );
                out.push_str("0x");
                out.push_str(&hex::encode(tx.to_bytes()));
                out.push('\n');
            }
            print!("{}", out);
        }
        "assemble" => {
            if args.len() < 4 {
                eprintln!("Usage: vera_cli assemble <source.json> <dest.v2>");
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
        _ => {
            print_usage();
        }
    }

    Ok(())
}

fn print_usage() {
    println!("VERA Chain CLI");
    println!("Usage:");
    println!("  vera_cli keygen");
    println!("  vera_cli status");
    println!("  vera_cli balance <address>");
    println!("  vera_cli verify <address>");
    println!("  vera_cli transfer <priv_key_hex> <recipient_hex> <amount> [nonce]");
    println!("  vera_cli stake <priv_key_hex> <amount_wei> [nonce]");
    println!("  vera_cli unstake <priv_key_hex> <amount_wei> [nonce]");
    println!("  vera_cli unjail <priv_key_hex> [nonce]");
    println!("  vera_cli allow <gov_priv_key_hex> <val_addr_hex> [nonce]");
    println!("  vera_cli disallow <gov_priv_key_hex> <val_addr_hex> [nonce]");
    println!("  vera_cli set_governance <gov_priv_key_hex> <new_gov_addr_hex> [nonce]");
    println!("  vera_cli validators");
    println!("  vera_cli signraw <priv_hex> <dest_hex> <amount_wei> <start_nonce> <count>");
    println!("  vera_cli assemble <source.vera> <dest.vbc>");
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
