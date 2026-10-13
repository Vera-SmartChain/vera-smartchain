use k256::ecdsa::SigningKey;
use tiny_keccak::{Hasher, Keccak};
use vera_blockchain::rpc::parse_and_recover_evm_tx;

fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    let mut output = [0u8; 32];
    hasher.update(data);
    hasher.finalize(&mut output);
    output
}

#[derive(Debug, Clone)]
enum RlpItem {
    Bytes(Vec<u8>),
    List(Vec<RlpItem>),
}

fn encode_rlp_bytes(data: &[u8]) -> Vec<u8> {
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

fn encode_rlp_list(items: &[Vec<u8>]) -> Vec<u8> {
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

impl RlpItem {
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            RlpItem::Bytes(b) => encode_rlp_bytes(b),
            RlpItem::List(items) => {
                let encoded: Vec<Vec<u8>> = items.iter().map(|it| it.to_bytes()).collect();
                encode_rlp_list(&encoded)
            }
        }
    }
}

fn create_signed_eip155_tx(signing_key: &SigningKey, chain_id: u64) -> Vec<u8> {
    let gas_price: u64 = 1_000_000_000;
    let gas_limit: u64 = 21_000;
    let to_bytes = vec![0x11u8; 20];
    let value_bytes = 1_000_000_000_000_000_000u128.to_be_bytes().to_vec();
    let data_bytes = vec![];

    let signing_items = vec![
        RlpItem::Bytes(vec![]), // nonce 0
        RlpItem::Bytes(gas_price.to_be_bytes().to_vec()),
        RlpItem::Bytes(gas_limit.to_be_bytes().to_vec()),
        RlpItem::Bytes(to_bytes.clone()),
        RlpItem::Bytes(value_bytes.clone()),
        RlpItem::Bytes(data_bytes.clone()),
        RlpItem::Bytes(chain_id.to_be_bytes().to_vec()),
        RlpItem::Bytes(vec![]),
        RlpItem::Bytes(vec![]),
    ];
    let signing_payload = RlpItem::List(signing_items).to_bytes();
    let digest = keccak256(&signing_payload);

    let (sig, rec_id) = signing_key.sign_prehash_recoverable(&digest).unwrap();
    let sig_bytes = sig.to_bytes();
    let r_bytes = sig_bytes[..32].to_vec();
    let s_bytes = sig_bytes[32..].to_vec();
    let v: u64 = chain_id * 2 + 35 + (rec_id.to_byte() as u64);

    let full_tx_items = vec![
        RlpItem::Bytes(vec![]),
        RlpItem::Bytes(gas_price.to_be_bytes().to_vec()),
        RlpItem::Bytes(gas_limit.to_be_bytes().to_vec()),
        RlpItem::Bytes(to_bytes),
        RlpItem::Bytes(value_bytes),
        RlpItem::Bytes(data_bytes),
        RlpItem::Bytes(v.to_be_bytes().to_vec()),
        RlpItem::Bytes(r_bytes),
        RlpItem::Bytes(s_bytes),
    ];
    RlpItem::List(full_tx_items).to_bytes()
}

#[test]
fn test_cross_chain_replay_rejected_mainnet_to_testnet() {
    let signing_key = SigningKey::random(&mut rand::rngs::OsRng);
    
    // 1. Sign EVM tx for Mainnet (Chain ID 8372)
    let raw_mainnet_tx = create_signed_eip155_tx(&signing_key, 8372);
    
    // 2. Attempt submission on Testnet (expected Chain ID: 83721)
    let testnet_chain_id = 83721;
    let result = parse_and_recover_evm_tx(&raw_mainnet_tx, testnet_chain_id);
    
    // 3. Validate strict anti-replay rejection
    assert!(result.is_err(), "Mainnet tx (8372) MUST be rejected on Testnet (83721)");
    let err_msg = result.unwrap_err();
    println!("Anti-replay blocking verified: {}", err_msg);
    assert!(err_msg.contains("Cross-Chain Replay Blocked"), "Error message must indicate cross-chain replay blocked");
    assert!(err_msg.contains("8372"), "Error must cite received chain_id (8372)");
    assert!(err_msg.contains("83721"), "Error must cite expected chain_id (83721)");
}

#[test]
fn test_cross_chain_replay_rejected_ethereum_to_testnet() {
    let signing_key = SigningKey::random(&mut rand::rngs::OsRng);
    
    // 1. Sign EVM tx for Ethereum Mainnet (Chain ID 1)
    let raw_eth_tx = create_signed_eip155_tx(&signing_key, 1);
    
    // 2. Attempt submission on Testnet (Chain ID 83721)
    let testnet_chain_id = 83721;
    let result = parse_and_recover_evm_tx(&raw_eth_tx, testnet_chain_id);
    
    assert!(result.is_err(), "Ethereum Mainnet tx (1) MUST be rejected on VERA Testnet (83721)");
    let err_msg = result.unwrap_err();
    assert!(err_msg.contains("Cross-Chain Replay Blocked"));
    println!("Ethereum replay blocking verified (1 -> 83721): {}", err_msg);
}

#[test]
fn test_valid_testnet_tx_accepted() {
    let signing_key = SigningKey::random(&mut rand::rngs::OsRng);
    
    // 1. Sign valid EVM tx for Testnet (Chain ID 83721)
    let raw_testnet_tx = create_signed_eip155_tx(&signing_key, 83721);
    
    // 2. Submit with expected chain_id 83721
    let testnet_chain_id = 83721;
    let result = parse_and_recover_evm_tx(&raw_testnet_tx, testnet_chain_id);
    
    assert!(result.is_ok(), "Legitimate Testnet tx (83721) must be accepted");
    let recovered = result.unwrap();
    assert_eq!(recovered.chain_id, 83721);
    println!("Tx accepted on Testnet: chain_id {}", recovered.chain_id);
}

#[ignore]
#[tokio::test]
async fn test_live_rpc_rejects_mainnet_replay_tx() {
    let signing_key = SigningKey::random(&mut rand::rngs::OsRng);
    let raw_mainnet_tx = create_signed_eip155_tx(&signing_key, 8372);
    let raw_hex = format!("0x{}", hex::encode(raw_mainnet_tx));

    let client = reqwest::Client::new();
    let rpc_payload = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "eth_sendRawTransaction",
        "params": [raw_hex],
        "id": 100
    });

    let resp = match client.post("http://127.0.0.1:8545")
        .json(&rpc_payload)
        .send()
        .await {
            Ok(r) => r,
            Err(_) => return, // Skip if live node not running
        };

    let json_resp: serde_json::Value = resp.json().await.unwrap();
    assert!(json_resp.get("error").is_some());
}
