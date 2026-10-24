// Regression test (v0.2.4.2): the Transaction wrapper fields executed by the state transition
// (to, gas_limit, gas_price, program) must match the ECDSA-signed raw EVM payload.
use vera_blockchain::transaction::Transaction;

// Legacy EIP-155 tx, chainId 83721: 1000 wei to 0x1111…1111, nonce 0, gas 21000 @ 1 gwei.
const RAW: &str = "f86880843b9aca008252089411111111111111111111111111111111111111118203e88083028e36a056b8d7a430085d428d9a4d674ed87241ccf40a7e6650bb8518654aac53081a1ea05ce793df66a9cbe82e3e0b32e788ef1c2407722ddfaca53d562b986c24140d81";

fn honest() -> Transaction {
    let raw = hex::decode(RAW).unwrap();
    let rec = vera_blockchain::rpc::parse_and_recover_evm_tx(&raw, 83721).unwrap();
    Transaction {
        chain_id: "vera-testnet-1".into(),
        public_key: [0u8; 32],
        sender: rec.from,
        nonce: rec.nonce,
        to: if rec.is_contract_creation { None } else { Some(rec.to) },
        amount: rec.value,
        gas_limit: rec.gas_limit,
        gas_price: rec.gas_price,
        program: rec.data.clone(),
        witness: None,
        signature: [0u8; 64],
        raw_evm: Some(raw),
    }
}

#[test]
fn evm_wrapper_matching_signed_payload_is_accepted() {
    assert!(honest().verify_signature().is_ok());
}

#[test]
fn evm_wrapper_with_rewritten_fields_is_rejected() {
    let mut t = honest();
    t.to = Some([0xAA; 32]);
    assert!(t.verify_signature().unwrap_err().contains("Recipient"));

    let mut t = honest();
    t.to = None;
    assert!(t.verify_signature().unwrap_err().contains("Recipient"));

    let mut t = honest();
    t.gas_price = 1_000_000_000_000;
    assert!(t.verify_signature().unwrap_err().contains("Gas"));

    let mut t = honest();
    t.gas_limit = 10_000_000;
    assert!(t.verify_signature().unwrap_err().contains("Gas"));

    let mut t = honest();
    t.program = vec![0xde, 0xad];
    assert!(t.verify_signature().unwrap_err().contains("Calldata"));

    let mut t = honest();
    t.public_key = [7u8; 32];
    assert!(t.verify_signature().is_err());

    // Rewritten wrappers keep the same tx hash, so mempool de-duplication alone cannot stop them.
    assert_eq!(t.tx_hash(), honest().tx_hash());
}
