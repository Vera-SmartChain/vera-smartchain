use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};
use tiny_keccak::{Hasher, Keccak};

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

fn decode_rlp(data: &[u8]) -> Result<(RlpItem, usize), String> {
    if data.is_empty() {
        return Err("RLP data empty".to_string());
    }
    let prefix = data[0];
    if prefix <= 0x7f {
        Ok((RlpItem::Bytes(vec![prefix]), 1))
    } else if prefix <= 0xb7 {
        let len = (prefix - 0x80) as usize;
        if data.len() < 1 + len {
            return Err("RLP string out of bounds".to_string());
        }
        Ok((RlpItem::Bytes(data[1..1 + len].to_vec()), 1 + len))
    } else if prefix <= 0xbf {
        let len_of_len = (prefix - 0xb7) as usize;
        if data.len() < 1 + len_of_len {
            return Err("RLP long string len out of bounds".to_string());
        }
        let mut len = 0usize;
        for &b in &data[1..1 + len_of_len] {
            len = (len << 8) | (b as usize);
        }
        if data.len() < 1 + len_of_len + len {
            return Err("RLP long string out of bounds".to_string());
        }
        Ok((RlpItem::Bytes(data[1 + len_of_len..1 + len_of_len + len].to_vec()), 1 + len_of_len + len))
    } else if prefix <= 0xf7 {
        let list_len = (prefix - 0xc0) as usize;
        if data.len() < 1 + list_len {
            return Err("RLP list out of bounds".to_string());
        }
        let mut items = Vec::new();
        let mut offset = 0;
        let subdata = &data[1..1 + list_len];
        while offset < subdata.len() {
            let (item, read_len) = decode_rlp(&subdata[offset..])?;
            items.push(item);
            offset += read_len;
        }
        Ok((RlpItem::List(items), 1 + list_len))
    } else {
        let len_of_len = (prefix - 0xf7) as usize;
        if data.len() < 1 + len_of_len {
            return Err("RLP long list len out of bounds".to_string());
        }
        let mut list_len = 0usize;
        for &b in &data[1..1 + len_of_len] {
            list_len = (list_len << 8) | (b as usize);
        }
        if data.len() < 1 + len_of_len + list_len {
            return Err("RLP long list out of bounds".to_string());
        }
        let mut items = Vec::new();
        let mut offset = 0;
        let subdata = &data[1 + len_of_len..1 + len_of_len + list_len];
        while offset < subdata.len() {
            let (item, read_len) = decode_rlp(&subdata[offset..])?;
            items.push(item);
            offset += read_len;
        }
        Ok((RlpItem::List(items), 1 + len_of_len + list_len))
    }
}

fn pad_32(b: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    if b.len() <= 32 {
        out[32 - b.len()..].copy_from_slice(b);
    } else {
        out.copy_from_slice(&b[..32]);
    }
    out
}

#[test]
fn test_evm_transaction_signing_and_recovery() {
    let signing_key = SigningKey::random(&mut rand::rngs::OsRng);
    let vk = signing_key.verifying_key();
    let uncompressed = vk.to_encoded_point(false);
    let expected_address_hash = keccak256(&uncompressed.as_bytes()[1..]);
    let mut expected_address = [0u8; 32];
    expected_address[12..32].copy_from_slice(&expected_address_hash[12..32]);

    // Construct a Legacy EIP-155 transaction for Chain ID 8545 (0x2161)
    let chain_id: u64 = 8545;
    let _nonce: u64 = 0;
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

    // Full transaction RLP
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
    let raw_tx_bytes = RlpItem::List(full_tx_items).to_bytes();

    // Now decode and RECOVER
    let (decoded, _) = decode_rlp(&raw_tx_bytes).unwrap();
    if let RlpItem::List(items) = decoded {
        assert_eq!(items.len(), 9);
        let dec_r = match &items[7] { RlpItem::Bytes(b) => pad_32(b), _ => panic!() };
        let dec_s = match &items[8] { RlpItem::Bytes(b) => pad_32(b), _ => panic!() };
        let dec_v = match &items[6] {
            RlpItem::Bytes(b) => {
                let mut val = 0u64;
                for &byte in b { val = (val << 8) | (byte as u64); }
                val
            },
            _ => panic!()
        };
        let dec_rec_id = ((dec_v - 35) % 2) as u8;

        let reconstruct_signing = vec![
            items[0].clone(),
            items[1].clone(),
            items[2].clone(),
            items[3].clone(),
            items[4].clone(),
            items[5].clone(),
            RlpItem::Bytes(chain_id.to_be_bytes().to_vec()),
            RlpItem::Bytes(vec![]),
            RlpItem::Bytes(vec![]),
        ];
        let re_digest = keccak256(&RlpItem::List(reconstruct_signing).to_bytes());
        assert_eq!(digest, re_digest);

        let mut recombined = [0u8; 64];
        recombined[..32].copy_from_slice(&dec_r);
        recombined[32..].copy_from_slice(&dec_s);
        let parsed_sig = Signature::from_slice(&recombined).unwrap();
        let parsed_rec_id = RecoveryId::try_from(dec_rec_id).unwrap();

        let recovered = VerifyingKey::recover_from_prehash(&re_digest, &parsed_sig, parsed_rec_id).unwrap();
        assert_eq!(*vk, recovered);

        let recovered_point = recovered.to_encoded_point(false);
        let recovered_hash = keccak256(&recovered_point.as_bytes()[1..]);
        let mut recovered_address = [0u8; 32];
        recovered_address[12..32].copy_from_slice(&recovered_hash[12..32]);

        assert_eq!(expected_address, recovered_address);
        println!("Successfully recovered signer address: 0x{}", hex::encode(recovered_address));
    }
}
