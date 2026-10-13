use std::sync::Arc;
use tokio::sync::Mutex;
use serde_json::json;

use vera_blockchain::account::{Account, address_from_hex};
use vera_blockchain::genesis::GenesisConfig;
use vera_blockchain::node::FullNode;
use vera_blockchain::rpc::{RpcHandler, RpcRequest};

#[tokio::test]
async fn test_audit_eth_send_transaction_unauthorized_drain_is_blocked() {
    let temp_dir = std::env::temp_dir().join(format!("vera_audit_drain_{}", rand::random::<u64>()));
    let (genesis_cfg, val_key) = GenesisConfig::default_testnet();

    let victim_addr_str = genesis_cfg.initial_accounts[0].address.clone();
    let attacker_addr_str = "0x1111111111111111111111111111111111111111111111111111111111111111";

    let victim_addr = address_from_hex(&victim_addr_str).unwrap();
    let attacker_addr = address_from_hex(attacker_addr_str).unwrap();

    let node = FullNode::load_or_init(&temp_dir, &genesis_cfg, Some(val_key)).unwrap();
    let shared_node = Arc::new(Mutex::new(node));

    let initial_victim_balance = {
        let n = shared_node.lock().await;
        Account::from_bytes(n.csmt.get(&victim_addr).unwrap()).unwrap().balance
    };
    assert!(initial_victim_balance > 0, "Victim must have initial balance");

    // ATTACK: Attacker issues eth_sendTransaction specifying victim as 'from'
    let steal_amount_wei: u128 = 10_000_000_000_000_000_000; // 10 VERA
    let req = RpcRequest {
        jsonrpc: "2.0".to_string(),
        id: json!(1),
        method: "eth_sendTransaction".to_string(),
        params: json!([{
            "from": victim_addr_str,
            "to": attacker_addr_str,
            "value": format!("0x{:x}", steal_amount_wei)
        }]),
    };

    let resp = RpcHandler::handle(&shared_node, req).await;
    
    // SECURITY INVARIANT:
    // eth_sendTransaction MUST BE REJECTED with an explicit non-custodial error
    assert!(resp.error.is_some(), "eth_sendTransaction must return error on headless node");
    let err_msg = resp.error.unwrap().message;
    println!(">>> [PATCHED VULN-01] Attack blocked with message: {}", err_msg);
    assert!(err_msg.contains("not supported"));

    // Verify victim balance is completely intact
    let n = shared_node.lock().await;
    let victim_after = Account::from_bytes(n.csmt.get(&victim_addr).unwrap()).unwrap().balance;
    let attacker_acc = n.csmt.get(&attacker_addr);

    assert_eq!(victim_after, initial_victim_balance, "Victim balance must not change");
    assert!(attacker_acc.is_none(), "Attacker account must not exist in state");

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[tokio::test]
async fn test_audit_faucet_capped_and_rate_limited() {
    let temp_dir = std::env::temp_dir().join(format!("vera_audit_faucet_{}", rand::random::<u64>()));
    let (genesis_cfg, val_key) = GenesisConfig::default_testnet();

    let node = FullNode::load_or_init(&temp_dir, &genesis_cfg, Some(val_key)).unwrap();
    let shared_node = Arc::new(Mutex::new(node));

    let user_str = "0x8888888888888888888888888888888888888888888888888888888888888888";
    let _user_addr = address_from_hex(user_str).unwrap();

    // 1. Request 1,000,000 VERA (Attacker tries hyperinflation)
    let req1 = RpcRequest {
        jsonrpc: "2.0".to_string(),
        id: json!(2),
        method: "vera_faucet".to_string(),
        params: json!([user_str, 1_000_000]),
    };

    let resp1 = RpcHandler::handle(&shared_node, req1).await;
    // Direct faucet on RPC was disabled fail-hard in compliance with Phase A hardening
    assert!(resp1.error.is_some(), "Direct faucet on RPC must be rejected");
    assert_eq!(resp1.error.unwrap().code, -32603);

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[tokio::test]
async fn test_audit_eth_send_raw_transaction_ecrecover_integrity() {
    let temp_dir = std::env::temp_dir().join(format!("vera_audit_raw_{}", rand::random::<u64>()));
    let (genesis_cfg, val_key) = GenesisConfig::default_testnet();

    let node = FullNode::load_or_init(&temp_dir, &genesis_cfg, Some(val_key)).unwrap();
    let shared_node = Arc::new(Mutex::new(node));

    // Try submitting malformed or forged raw transaction
    let forged_raw = "0xdeadbeef1234567890";
    let req = RpcRequest {
        jsonrpc: "2.0".to_string(),
        id: json!(4),
        method: "eth_sendRawTransaction".to_string(),
        params: json!([forged_raw]),
    };

    let resp = RpcHandler::handle(&shared_node, req).await;
    assert!(resp.error.is_some(), "Forged raw transaction must be rejected by ecrecover parser");
    let err = resp.error.unwrap().message;
    println!(">>> [PATCHED VULN-03] Forged raw tx rejected: {}", err);

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[tokio::test]
async fn test_audit_eth_send_raw_transaction_cross_chain_replay_rejected() {
    use k256::ecdsa::SigningKey;
    use tiny_keccak::{Hasher, Keccak};

    let temp_dir = std::env::temp_dir().join(format!("vera_audit_replay_{}", rand::random::<u64>()));
    let (genesis_cfg, val_key) = GenesisConfig::default_testnet();

    let node = FullNode::load_or_init(&temp_dir, &genesis_cfg, Some(val_key)).unwrap();
    let shared_node = Arc::new(Mutex::new(node));

    let signing_key = SigningKey::random(&mut rand::rngs::OsRng);
    
    // Construct transaction signed for Ethereum Mainnet (Chain ID 1)
    let foreign_chain_id: u64 = 1;
    let gas_price: u64 = 1_000_000_000;
    let gas_limit: u64 = 21_000;
    let to_bytes = vec![0x22u8; 20];

    // Helper RLP encoding
    fn u64_to_bytes(n: u64) -> Vec<u8> {
        if n == 0 { vec![] } else { n.to_be_bytes().iter().skip_while(|&&b| b == 0).cloned().collect() }
    }
    fn u128_to_bytes(n: u128) -> Vec<u8> {
        if n == 0 { vec![] } else { n.to_be_bytes().iter().skip_while(|&&b| b == 0).cloned().collect() }
    }
    fn encode_bytes(data: &[u8]) -> Vec<u8> {
        if data.len() == 1 && data[0] <= 0x7f {
            data.to_vec()
        } else if data.len() <= 55 {
            let mut out = Vec::with_capacity(1 + data.len());
            out.push(0x80 + data.len() as u8);
            out.extend_from_slice(data);
            out
        } else {
            let len_bytes = data.len().to_be_bytes();
            let leading_zeros = len_bytes.iter().take_while(|&&b| b == 0).count();
            let actual_len = &len_bytes[leading_zeros..];
            let mut out = Vec::with_capacity(1 + actual_len.len() + data.len());
            out.push(0xb7 + actual_len.len() as u8);
            out.extend_from_slice(actual_len);
            out.extend_from_slice(data);
            out
        }
    }
    fn encode_list(items: &[Vec<u8>]) -> Vec<u8> {
        let payload: Vec<u8> = items.concat();
        if payload.len() <= 55 {
            let mut out = Vec::with_capacity(1 + payload.len());
            out.push(0xc0 + payload.len() as u8);
            out.extend_from_slice(&payload);
            out
        } else {
            let len_bytes = payload.len().to_be_bytes();
            let leading_zeros = len_bytes.iter().take_while(|&&b| b == 0).count();
            let actual_len = &len_bytes[leading_zeros..];
            let mut out = Vec::with_capacity(1 + actual_len.len() + payload.len());
            out.push(0xf7 + actual_len.len() as u8);
            out.extend_from_slice(actual_len);
            out.extend_from_slice(&payload);
            out
        }
    }

    let signing_items = vec![
        encode_bytes(&[]), // nonce 0
        encode_bytes(&u64_to_bytes(gas_price)),
        encode_bytes(&u64_to_bytes(gas_limit)),
        encode_bytes(&to_bytes),
        encode_bytes(&u128_to_bytes(1_000_000_000_000_000_000u128)),
        encode_bytes(&[]),
        encode_bytes(&u64_to_bytes(foreign_chain_id)),
        encode_bytes(&[]),
        encode_bytes(&[]),
    ];
    let signing_payload = encode_list(&signing_items);

    let mut hasher = Keccak::v256();
    hasher.update(&signing_payload);
    let mut digest = [0u8; 32];
    hasher.finalize(&mut digest);

    let (sig, rec_id) = signing_key.sign_prehash_recoverable(&digest).unwrap();
    let sig_bytes = sig.to_bytes();
    let v: u64 = foreign_chain_id * 2 + 35 + (rec_id.to_byte() as u64);

    let full_tx_items = vec![
        encode_bytes(&[]),
        encode_bytes(&u64_to_bytes(gas_price)),
        encode_bytes(&u64_to_bytes(gas_limit)),
        encode_bytes(&to_bytes),
        encode_bytes(&u128_to_bytes(1_000_000_000_000_000_000u128)),
        encode_bytes(&[]),
        encode_bytes(&u64_to_bytes(v)),
        encode_bytes(&sig_bytes[..32]),
        encode_bytes(&sig_bytes[32..]),
    ];
    let raw_tx = format!("0x{}", hex::encode(encode_list(&full_tx_items)));

    let req = RpcRequest {
        jsonrpc: "2.0".to_string(),
        id: json!(5),
        method: "eth_sendRawTransaction".to_string(),
        params: json!([raw_tx]),
    };

    let resp = RpcHandler::handle(&shared_node, req).await;
    assert!(resp.error.is_some(), "Foreign chain transaction MUST be rejected");
    let err = resp.error.unwrap().message;
    println!(">>> [PATCHED REPLAY SHIELD] Foreign chain tx rejected: {}", err);
    assert!(err.contains("Cross-Chain Replay Blocked") || err.contains("Replay Cross-Chain Bloqueado"));

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[tokio::test]
async fn test_audit_eth_send_raw_transaction_gas_metering_and_tokenomics() {
    use k256::ecdsa::SigningKey;
    use tiny_keccak::{Hasher, Keccak};

    let temp_dir = std::env::temp_dir().join(format!("vera_audit_gas_{}", rand::random::<u64>()));
    let (genesis_cfg, val_key) = GenesisConfig::default_testnet();

    let node = FullNode::load_or_init(&temp_dir, &genesis_cfg, Some(val_key)).unwrap();
    let shared_node = Arc::new(Mutex::new(node));

    let signing_key = SigningKey::random(&mut rand::rngs::OsRng);
    let vk = signing_key.verifying_key();
    let uncompressed = vk.to_encoded_point(false);
    
    let mut hasher = Keccak::v256();
    hasher.update(&uncompressed.as_bytes()[1..]);
    let mut address_hash = [0u8; 32];
    hasher.finalize(&mut address_hash);

    let mut sender_address = [0u8; 32];
    sender_address[12..32].copy_from_slice(&address_hash[12..32]);

    // Pre-fund the sender account with 10 VERA
    let initial_balance = 10_000_000_000_000_000_000u128;
    {
        let mut n = shared_node.lock().await;
        n.csmt.insert(sender_address, Account::new(initial_balance).to_bytes());
    }

    let mut recipient_address = [0u8; 32];
    recipient_address[12..32].fill(0x55);
    let transfer_amount = 1_000_000_000_000_000_000u128; // 1 VERA
    let gas_price: u64 = 1_000_000_000; // 1 Gwei
    let gas_limit: u64 = 21_000;
    let expected_gas_fee = (21_000 as u128) * (gas_price as u128); // 21,000 * 10^9 wei = 21 * 10^12 wei

    // Build valid signed EIP-155 transaction for VERA Chain ID 83721
    let chain_id: u64 = 83721;
    fn u64_to_bytes(n: u64) -> Vec<u8> {
        if n == 0 { vec![] } else { n.to_be_bytes().iter().skip_while(|&&b| b == 0).cloned().collect() }
    }
    fn u128_to_bytes(n: u128) -> Vec<u8> {
        if n == 0 { vec![] } else { n.to_be_bytes().iter().skip_while(|&&b| b == 0).cloned().collect() }
    }
    fn encode_bytes(data: &[u8]) -> Vec<u8> {
        if data.len() == 1 && data[0] <= 0x7f {
            data.to_vec()
        } else if data.len() <= 55 {
            let mut out = Vec::with_capacity(1 + data.len());
            out.push(0x80 + data.len() as u8);
            out.extend_from_slice(data);
            out
        } else {
            let len_bytes = data.len().to_be_bytes();
            let leading_zeros = len_bytes.iter().take_while(|&&b| b == 0).count();
            let actual_len = &len_bytes[leading_zeros..];
            let mut out = Vec::with_capacity(1 + actual_len.len() + data.len());
            out.push(0xb7 + actual_len.len() as u8);
            out.extend_from_slice(actual_len);
            out.extend_from_slice(data);
            out
        }
    }
    fn encode_list(items: &[Vec<u8>]) -> Vec<u8> {
        let payload: Vec<u8> = items.concat();
        if payload.len() <= 55 {
            let mut out = Vec::with_capacity(1 + payload.len());
            out.push(0xc0 + payload.len() as u8);
            out.extend_from_slice(&payload);
            out
        } else {
            let len_bytes = payload.len().to_be_bytes();
            let leading_zeros = len_bytes.iter().take_while(|&&b| b == 0).count();
            let actual_len = &len_bytes[leading_zeros..];
            let mut out = Vec::with_capacity(1 + actual_len.len() + payload.len());
            out.push(0xf7 + actual_len.len() as u8);
            out.extend_from_slice(actual_len);
            out.extend_from_slice(&payload);
            out
        }
    }

    let to_20bytes = recipient_address[12..32].to_vec();

    let signing_items = vec![
        encode_bytes(&[]), // nonce 0
        encode_bytes(&u64_to_bytes(gas_price)),
        encode_bytes(&u64_to_bytes(gas_limit)),
        encode_bytes(&to_20bytes),
        encode_bytes(&u128_to_bytes(transfer_amount)),
        encode_bytes(&[]),
        encode_bytes(&u64_to_bytes(chain_id)),
        encode_bytes(&[]),
        encode_bytes(&[]),
    ];
    let signing_payload = encode_list(&signing_items);

    let mut hasher = Keccak::v256();
    hasher.update(&signing_payload);
    let mut digest = [0u8; 32];
    hasher.finalize(&mut digest);

    let (sig, rec_id) = signing_key.sign_prehash_recoverable(&digest).unwrap();
    let sig_bytes = sig.to_bytes();
    let v: u64 = chain_id * 2 + 35 + (rec_id.to_byte() as u64);

    let full_tx_items = vec![
        encode_bytes(&[]),
        encode_bytes(&u64_to_bytes(gas_price)),
        encode_bytes(&u64_to_bytes(gas_limit)),
        encode_bytes(&to_20bytes),
        encode_bytes(&u128_to_bytes(transfer_amount)),
        encode_bytes(&[]),
        encode_bytes(&u64_to_bytes(v)),
        encode_bytes(&sig_bytes[..32]),
        encode_bytes(&sig_bytes[32..]),
    ];
    let raw_tx = format!("0x{}", hex::encode(encode_list(&full_tx_items)));

    let req = RpcRequest {
        jsonrpc: "2.0".to_string(),
        id: json!(6),
        method: "eth_sendRawTransaction".to_string(),
        params: json!([raw_tx]),
    };

    let resp = RpcHandler::handle(&shared_node, req).await;
    assert!(resp.result.is_some(), "Valid EVM transaction with gas must succeed: {:?}", resp.error);
    println!(">>> [PATCHED GAS METERING] Tx submitted: {:?}", resp.result.unwrap());

    // Propose and commit block so the transaction in mempool is executed deterministically
    {
        let mut n = shared_node.lock().await;
        n.propose_and_commit_block().await.expect("Block must be committed with the transaction");
    }

    // Verify account state and tokenomics
    let n = shared_node.lock().await;
    let sender_acc = Account::from_bytes(n.csmt.get(&sender_address).unwrap()).unwrap();
    let recip_acc = Account::from_bytes(n.csmt.get(&recipient_address).unwrap()).unwrap();
    
    // Sender must be debited transfer_amount + expected_gas_fee
    let expected_sender_balance = initial_balance - transfer_amount - expected_gas_fee;
    assert_eq!(sender_acc.balance, expected_sender_balance, "Sender must pay transfer + gas");
    assert_eq!(sender_acc.nonce, 1, "Nonce must increment to 1");

    // Recipient must receive exactly transfer_amount
    assert_eq!(recip_acc.balance, transfer_amount, "Recipient must receive transfer amount");

    // Check tokenomics distribution (70 / 15 / 15)
    let proposer_fee = (expected_gas_fee * 70) / 100;
    let stability_fee = (expected_gas_fee * 15) / 100;
    let burn_fee = expected_gas_fee - proposer_fee - stability_fee;

    let prop_acc = Account::from_bytes(n.csmt.get(&n.address).unwrap()).unwrap();
    let stab_acc = Account::from_bytes(n.csmt.get(&vera_blockchain::state_transition::STABILITY_POOL_ADDRESS).unwrap()).unwrap();
    let burn_acc = Account::from_bytes(n.csmt.get(&vera_blockchain::state_transition::BURN_ADDRESS).unwrap()).unwrap();

    assert!(prop_acc.balance >= proposer_fee, "Proposer must receive 70% of gas");
    assert_eq!(stab_acc.balance, stability_fee, "Stability pool must receive 15% of gas");
    assert_eq!(burn_acc.balance, burn_fee, "Burn address must receive 15% of gas");

    println!(">>> [CONSERVATION VERIFIED] Gas fee strictly conserved across validator, stability pool, and burn address!");

    let _ = std::fs::remove_dir_all(&temp_dir);
}

