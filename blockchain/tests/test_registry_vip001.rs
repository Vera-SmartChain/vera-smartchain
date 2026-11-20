//! VIP-001: native document registry, per-document fee and consensus minimum gas price.

use ed25519_dalek::SigningKey;
use vera_blockchain::account::{address_from_pubkey, address_to_hex, Account};
use vera_blockchain::genesis::{GenesisAccount, GenesisConfig};
use vera_blockchain::node::FullNode;
use vera_blockchain::registry::{
    self, FeeParams, IssuerRecord, RegistryOp, DEFAULT_FEE_PER_ITEM_WEI, DEFAULT_MIN_GAS_PRICE_WEI,
    FEE_CHANGE_MIN_INTERVAL_SECS, REGISTRY_SYSTEM_ADDRESS,
};
use vera_blockchain::state_transition::{BURN_ADDRESS, STABILITY_POOL_ADDRESS};
use vera_blockchain::transaction::Transaction;

const VERA: u128 = 1_000_000_000_000_000_000;
const GAS_PRICE: u64 = DEFAULT_MIN_GAS_PRICE_WEI;

fn key(i: u8) -> SigningKey {
    SigningKey::from_bytes(&[i.wrapping_add(40); 32])
}
fn addr(k: &SigningKey) -> [u8; 32] {
    address_from_pubkey(&k.verifying_key().to_bytes())
}
fn gov() -> SigningKey {
    key(200)
}
fn filler_key() -> SigningKey {
    key(150)
}

/// Testnet genesis with funded payers 0..4, governance = key(200), registry active from
/// `activation` (None = registry not scheduled).
fn genesis(activation: Option<u64>) -> (GenesisConfig, SigningKey) {
    let (mut cfg, val_key) = GenesisConfig::default_testnet();
    for k in (0..4).map(key).chain([gov(), filler_key()]) {
        cfg.initial_accounts.push(GenesisAccount { address: address_to_hex(&addr(&k)), balance: (1_000 * VERA).to_string() });
    }
    cfg.governance_address = Some(address_to_hex(&addr(&gov())));
    cfg.registry_activation_height = activation;
    (cfg, val_key)
}

fn node(cfg: &GenesisConfig, key: Option<SigningKey>) -> FullNode {
    let dir = std::env::temp_dir().join(format!("vera_vip001_{}", rand::random::<u64>()));
    FullNode::load_or_init(&dir, cfg, key).unwrap()
}

fn balance(n: &FullNode, a: &[u8; 32]) -> u128 {
    n.csmt.get(a).and_then(|b| Account::from_bytes(b).ok()).map_or(0, |a| a.balance)
}
fn supply(n: &FullNode) -> u128 {
    n.csmt.iter().filter_map(|(_, b)| Account::from_bytes(b).ok()).map(|a| a.balance).sum()
}
fn nonce(n: &FullNode, a: &[u8; 32]) -> u64 {
    n.csmt.get(a).and_then(|b| Account::from_bytes(b).ok()).map_or(0, |a| a.nonce)
}

/// Builds, self-validates and applies one block; also replays it on `follower` if given.
async fn step(n: &mut FullNode, follower: Option<&mut FullNode>) -> vera_blockchain::block::Block {
    let block = n.build_proposal().await.expect("build");
    n.validate_proposal(&block).await.expect("own proposal validates");
    if let Some(f) = follower {
        f.validate_proposal(&block).await.expect("follower validates");
        f.apply_block(block.clone()).await.expect("follower applies");
    }
    n.apply_block(block.clone()).await.expect("apply");
    block
}

/// The chain does not build empty blocks: a 1-wei transfer to carry a block.
fn filler(n: &mut FullNode) {
    let k = filler_key();
    let tx = Transaction::new(&n.chain_id, &k, nonce(n, &addr(&k)), Some([0x22; 32]), 1, 21_000, GAS_PRICE, vec![]);
    n.submit_transaction(tx).expect("filler admission");
}

fn reg_tx(n: &FullNode, k: &SigningKey, op: &RegistryOp) -> Transaction {
    Transaction::new(&n.chain_id, k, nonce(n, &addr(k)), Some(REGISTRY_SYSTEM_ADDRESS), 0, 200_000, GAS_PRICE, op.encode())
}

fn doc(i: u8) -> [u8; 32] {
    [i; 32]
}

/// Node with the registry active (activation at height 1, one empty block applied).
async fn active_node() -> (FullNode, SigningKey) {
    let (cfg, vk) = genesis(Some(1));
    let mut n = node(&cfg, Some(vk.clone()));
    filler(&mut n);
    step(&mut n, None).await;
    assert!(registry::load_params(&n.csmt).unwrap().is_some(), "params written at activation");
    (n, vk)
}

#[tokio::test]
async fn before_activation_nothing_changes() {
    let (cfg, vk) = genesis(None);
    let mut n = node(&cfg, Some(vk));
    // Old rules: a 7-wei gas price is still accepted.
    let tx = Transaction::new(&n.chain_id, &key(0), 0, Some([0x11; 32]), 1, 21_000, 7, vec![]);
    n.submit_transaction(tx).expect("low gas price accepted before activation");
    // Mempool policy: nothing may be sent to the registry address before activation.
    let op = RegistryOp::Register { kind: 1, doc_hash: doc(1), parent: None };
    let tx = Transaction::new(&n.chain_id, &key(1), 0, Some(REGISTRY_SYSTEM_ADDRESS), 0, 200_000, 7, op.encode());
    assert!(n.submit_transaction(tx).unwrap_err().contains("registry"));
    step(&mut n, None).await;
    assert!(registry::load_params(&n.csmt).unwrap().is_none());
}

#[tokio::test]
async fn activation_writes_default_params() {
    let (n, _) = active_node().await;
    let p = registry::load_params(&n.csmt).unwrap().unwrap();
    assert_eq!(p, FeeParams::default());
    assert_eq!(p.min_gas_price_wei, 238_095_238_095);
    assert_eq!(p.fee_per_item_wei, 50_000_000_000_000_000);
    // R$ 0.005 per 21,000-gas transfer at 1 VERA = R$ 1 (truncated to whole wei).
    assert_eq!(21_000u128 * p.min_gas_price_wei as u128, 4_999_999_999_995_000);
}

#[tokio::test]
async fn minimum_gas_price_is_enforced() {
    let (mut n, _) = active_node().await;
    let low = Transaction::new(&n.chain_id, &key(0), 0, Some([0x11; 32]), 1, 21_000, GAS_PRICE - 1, vec![]);
    let err = n.submit_transaction(low).unwrap_err();
    assert!(err.contains("minimum gas price"), "{}", err);
    let ok = Transaction::new(&n.chain_id, &key(0), 0, Some([0x11; 32]), 1, 21_000, GAS_PRICE, vec![]);
    n.submit_transaction(ok).expect("gas price at the minimum is accepted");
    let b = step(&mut n, None).await;
    assert_eq!(b.transactions.len(), 1);
}

#[tokio::test]
async fn register_charges_fee_and_splits_70_15_15() {
    let (mut n, vk) = active_node().await;
    let proposer = addr(&vk);
    let sender = addr(&key(0));
    let (s0, p0, st0, b0, sup0) = (
        balance(&n, &sender),
        balance(&n, &proposer),
        balance(&n, &STABILITY_POOL_ADDRESS),
        balance(&n, &BURN_ADDRESS),
        supply(&n),
    );
    let op = RegistryOp::Register { kind: 7, doc_hash: doc(9), parent: None };
    n.submit_transaction(reg_tx(&n, &key(0), &op)).expect("admission");
    let b = step(&mut n, None).await;
    assert_eq!(b.transactions.len(), 1);
    let gas_used = b.receipts[0].gas_used as u128;
    let total = gas_used * GAS_PRICE as u128 + DEFAULT_FEE_PER_ITEM_WEI;

    assert_eq!(s0 - balance(&n, &sender), total, "sender pays gas + one document fee");
    assert_eq!(balance(&n, &proposer) - p0, total * 70 / 100);
    assert_eq!(balance(&n, &STABILITY_POOL_ADDRESS) - st0, total * 15 / 100);
    assert_eq!(balance(&n, &BURN_ADDRESS) - b0, total - total * 70 / 100 - total * 15 / 100);
    assert_eq!(supply(&n), sup0, "no coin created or destroyed");

    let rec = registry::load_doc(&n.csmt, &sender, &doc(9)).unwrap().expect("record stored");
    assert_eq!((rec.kind, rec.leaf_count, rec.revoked_at), (7, 0, None));
    assert_eq!(b.receipts[0].logs.len(), 1);
    assert_eq!(b.receipts[0].logs[0].address, REGISTRY_SYSTEM_ADDRESS);
}

#[tokio::test]
async fn batch_is_charged_per_document() {
    let (mut n, _) = active_node().await;
    let sender = addr(&key(1));
    let s0 = balance(&n, &sender);
    let op = RegistryOp::RegisterBatch { kind: 1, merkle_root: doc(3), leaf_count: 10_000 };
    n.submit_transaction(reg_tx(&n, &key(1), &op)).expect("admission");
    let b = step(&mut n, None).await;
    let gas = b.receipts[0].gas_used as u128 * GAS_PRICE as u128;
    // 10,000 documents x 0.05 VERA = 500 VERA, plus the gas of one transaction.
    assert_eq!(s0 - balance(&n, &sender), 500 * VERA + gas);

    for bad in [0u32, 10_001] {
        let op = RegistryOp::RegisterBatch { kind: 1, merkle_root: doc(4), leaf_count: bad };
        assert!(n.submit_transaction(reg_tx(&n, &key(1), &op)).is_err(), "leaf_count {} must be rejected", bad);
    }
    // A batch the sender cannot pay for is rejected, not partially applied.
    let op = RegistryOp::RegisterBatch { kind: 1, merkle_root: doc(5), leaf_count: 10_000 };
    assert!(n.submit_transaction(reg_tx(&n, &key(1), &op)).unwrap_err().contains("nsufficient"));
}

#[tokio::test]
async fn duplicates_revocation_and_amount_rules() {
    let (mut n, _) = active_node().await;
    let reg = RegistryOp::Register { kind: 1, doc_hash: doc(1), parent: None };
    n.submit_transaction(reg_tx(&n, &key(0), &reg)).unwrap();
    step(&mut n, None).await;

    // Same sender, same hash: rejected. Another sender may register the same hash.
    assert!(n.submit_transaction(reg_tx(&n, &key(0), &reg)).unwrap_err().contains("already registered"));
    n.submit_transaction(reg_tx(&n, &key(1), &reg)).expect("independent record for another issuer");
    step(&mut n, None).await;

    // Only the registrant can revoke, and only once.
    let rev = RegistryOp::Revoke { doc_hash: doc(1) };
    assert!(n.submit_transaction(reg_tx(&n, &key(2), &rev)).unwrap_err().contains("not registered by this sender"));
    n.submit_transaction(reg_tx(&n, &key(0), &rev)).unwrap();
    step(&mut n, None).await;
    assert!(registry::load_doc(&n.csmt, &addr(&key(0)), &doc(1)).unwrap().unwrap().revoked_at.is_some());
    assert!(registry::load_doc(&n.csmt, &addr(&key(1)), &doc(1)).unwrap().unwrap().revoked_at.is_none());
    assert!(n.submit_transaction(reg_tx(&n, &key(0), &rev)).unwrap_err().contains("already revoked"));

    // Value must be zero; malformed payloads are rejected.
    let reg2 = RegistryOp::Register { kind: 1, doc_hash: doc(2), parent: None };
    let tx = Transaction::new(&n.chain_id, &key(0), nonce(&n, &addr(&key(0))), Some(REGISTRY_SYSTEM_ADDRESS), 1, 200_000, GAS_PRICE, reg2.encode());
    assert!(n.submit_transaction(tx).unwrap_err().contains("amount"));
    let mut bad = reg2.encode();
    bad.push(0);
    let tx = Transaction::new(&n.chain_id, &key(0), nonce(&n, &addr(&key(0))), Some(REGISTRY_SYSTEM_ADDRESS), 0, 200_000, GAS_PRICE, bad);
    assert!(n.submit_transaction(tx).unwrap_err().contains("trailing"));
}

#[tokio::test]
async fn governance_fee_changes_are_bounded() {
    let (mut n, _) = active_node().await;
    let set = |v: u128| RegistryOp::SetFee { fee_per_item_wei: v };

    assert!(n.submit_transaction(reg_tx(&n, &key(0), &set(DEFAULT_FEE_PER_ITEM_WEI))).unwrap_err().contains("only governance"));
    assert!(n.submit_transaction(reg_tx(&n, &gov(), &set(DEFAULT_FEE_PER_ITEM_WEI * 2 + 1))).unwrap_err().contains("2x"));
    assert!(n.submit_transaction(reg_tx(&n, &gov(), &set(DEFAULT_FEE_PER_ITEM_WEI / 2 - 1))).unwrap_err().contains("2x"));
    assert!(n.submit_transaction(reg_tx(&n, &gov(), &set(0))).unwrap_err().contains("greater than zero"));

    n.submit_transaction(reg_tx(&n, &gov(), &set(DEFAULT_FEE_PER_ITEM_WEI * 2))).expect("2x is allowed");
    step(&mut n, None).await;
    let p = registry::load_params(&n.csmt).unwrap().unwrap();
    assert_eq!(p.fee_per_item_wei, DEFAULT_FEE_PER_ITEM_WEI * 2);
    assert!(p.last_item_change_ts > 0);

    // A second change inside 7 days is rejected.
    let err = n.submit_transaction(reg_tx(&n, &gov(), &set(DEFAULT_FEE_PER_ITEM_WEI))).unwrap_err();
    assert!(err.contains("next change allowed"), "{}", err);
    assert_eq!(FEE_CHANGE_MIN_INTERVAL_SECS, 7 * 24 * 3600);

    // The gas price has its own clock and bounds.
    let gp = RegistryOp::SetGasPrice { min_gas_price_wei: GAS_PRICE * 2 };
    n.submit_transaction(reg_tx(&n, &gov(), &gp)).expect("gas price change is independent");
    step(&mut n, None).await;
    assert_eq!(registry::load_params(&n.csmt).unwrap().unwrap().min_gas_price_wei, GAS_PRICE * 2);
    // The old minimum is now too low.
    let tx = Transaction::new(&n.chain_id, &key(3), 0, Some([0x11; 32]), 1, 21_000, GAS_PRICE, vec![]);
    assert!(n.submit_transaction(tx).unwrap_err().contains("minimum gas price"));
}

#[tokio::test]
async fn issuer_attestation_by_registrar() {
    let (mut n, _) = active_node().await;
    let issuer = addr(&key(0));
    let rec = IssuerRecord { issuer_id: [9; 32], display_name: "CBSA".into(), valid_from_ts: 0, valid_until_ts: u64::MAX };
    let set = RegistryOp::SetIssuer { addr: issuer, record: rec.clone() };

    assert!(n.submit_transaction(reg_tx(&n, &key(1), &set)).unwrap_err().contains("registrar"));
    n.submit_transaction(reg_tx(&n, &gov(), &set)).expect("governance is the registrar by default");
    let b = step(&mut n, None).await;
    let st = registry::load_issuer(&n.csmt, &issuer).unwrap().unwrap();
    assert_eq!((st.issuer_id, st.display_name.as_str()), ([9; 32], "CBSA"));
    // valid_from 0 is not retroactive: the window starts at the block that records it.
    assert_eq!(st.windows, vec![(b.header.timestamp, u64::MAX)]);

    // Governance appoints a separate registrar; governance itself then loses that power.
    let appoint = RegistryOp::SetRegistrar { addr: addr(&key(3)) };
    n.submit_transaction(reg_tx(&n, &gov(), &appoint)).unwrap();
    step(&mut n, None).await;
    let remove = RegistryOp::RemoveIssuer { addr: issuer };
    assert!(n.submit_transaction(reg_tx(&n, &gov(), &remove)).unwrap_err().contains("registrar"));
    n.submit_transaction(reg_tx(&n, &key(3), &remove)).expect("new registrar removes");
    let b = step(&mut n, None).await;
    let after = registry::load_issuer(&n.csmt, &issuer).unwrap().unwrap();
    assert_eq!(after.windows.last().unwrap().1, b.header.timestamp, "attestation ends now, earlier records stay verified");
}

fn verified(n: &FullNode, registrant: &[u8; 32], h: [u8; 32]) -> bool {
    let rec = registry::load_doc(&n.csmt, registrant, &h).unwrap().expect("record exists");
    registry::load_issuer(&n.csmt, registrant).unwrap().map_or(false, |i| i.covers(rec.timestamp))
}

/// Carlos's decision (2026-11-18): no retroactive attestation. Records made before an
/// address is attested, or while its attestation was removed, never become verified;
/// records made inside a window stay verified forever.
#[tokio::test]
async fn attestation_is_never_retroactive() {
    let (mut n, _) = active_node().await;
    let k = key(0);
    let issuer = addr(&k);
    let pause = || std::thread::sleep(std::time::Duration::from_millis(1_100));
    let attest = |id: u8| RegistryOp::SetIssuer {
        addr: issuer,
        record: IssuerRecord { issuer_id: [id; 32], display_name: "CBSA".into(), valid_from_ts: 0, valid_until_ts: u64::MAX },
    };
    let register = |i: u8| RegistryOp::Register { kind: 1, doc_hash: doc(i), parent: None };

    n.submit_transaction(reg_tx(&n, &k, &register(1))).unwrap(); // before any attestation
    step(&mut n, None).await;
    pause();
    n.submit_transaction(reg_tx(&n, &gov(), &attest(9))).unwrap(); // valid_from 0 asked
    step(&mut n, None).await;
    assert!(!verified(&n, &issuer, doc(1)), "a record made before the attestation is not verified");
    pause();
    n.submit_transaction(reg_tx(&n, &k, &register(2))).unwrap();
    step(&mut n, None).await;
    assert!(verified(&n, &issuer, doc(2)));

    // Another organization cannot take over an attested address.
    let err = n.submit_transaction(reg_tx(&n, &gov(), &attest(8))).unwrap_err();
    assert!(err.contains("cannot change organization"), "{}", err);

    pause();
    n.submit_transaction(reg_tx(&n, &gov(), &RegistryOp::RemoveIssuer { addr: issuer })).unwrap();
    step(&mut n, None).await;
    pause();
    n.submit_transaction(reg_tx(&n, &k, &register(3))).unwrap(); // while removed
    step(&mut n, None).await;
    pause();
    n.submit_transaction(reg_tx(&n, &gov(), &attest(9))).unwrap(); // attested again
    step(&mut n, None).await;
    pause();
    n.submit_transaction(reg_tx(&n, &k, &register(4))).unwrap();
    step(&mut n, None).await;

    assert!(!verified(&n, &issuer, doc(1)));
    assert!(verified(&n, &issuer, doc(2)), "verified once, verified forever");
    assert!(!verified(&n, &issuer, doc(3)), "the gap is not covered by the new attestation");
    assert!(verified(&n, &issuer, doc(4)));
    assert_eq!(registry::load_issuer(&n.csmt, &issuer).unwrap().unwrap().windows.len(), 2);

    // A window cannot end in the past.
    let past = RegistryOp::SetIssuer {
        addr: issuer,
        record: IssuerRecord { issuer_id: [9; 32], display_name: "CBSA".into(), valid_from_ts: 0, valid_until_ts: 1 },
    };
    assert!(n.submit_transaction(reg_tx(&n, &gov(), &past)).is_err());
}

#[tokio::test]
async fn two_nodes_reach_the_same_state() {
    let (cfg, vk) = genesis(Some(2));
    let mut a = node(&cfg, Some(vk.clone()));
    let mut b = node(&cfg, None);
    // Block 1: old rules on both. Block 2: activation on both.
    filler(&mut a);
    step(&mut a, Some(&mut b)).await;
    assert!(registry::load_params(&b.csmt).unwrap().is_none());
    filler(&mut a);
    step(&mut a, Some(&mut b)).await;
    assert!(registry::load_params(&b.csmt).unwrap().is_some());
    for i in 0..4u8 {
        let op = RegistryOp::Register { kind: 1, doc_hash: doc(100 + i), parent: None };
        a.submit_transaction(reg_tx(&a, &key(i), &op)).unwrap();
    }
    let op = RegistryOp::RegisterBatch { kind: 2, merkle_root: doc(200), leaf_count: 50 };
    a.submit_transaction(reg_tx(&a, &gov(), &op)).unwrap();
    let blk = step(&mut a, Some(&mut b)).await;
    assert_eq!(blk.transactions.len(), 5);
    assert_eq!(a.csmt.root(), b.csmt.root(), "follower reaches the same state root");
    assert_eq!(registry::load_params(&a.csmt).unwrap(), registry::load_params(&b.csmt).unwrap());
}

#[test]
fn op_encoding_round_trips() {
    let ops = vec![
        RegistryOp::Register { kind: 3, doc_hash: [1; 32], parent: Some([2; 32]) },
        RegistryOp::Register { kind: 3, doc_hash: [1; 32], parent: None },
        RegistryOp::RegisterBatch { kind: 4, merkle_root: [5; 32], leaf_count: 77 },
        RegistryOp::Revoke { doc_hash: [6; 32] },
        RegistryOp::SetFee { fee_per_item_wei: 123 },
        RegistryOp::SetGasPrice { min_gas_price_wei: 456 },
        RegistryOp::SetIssuer { addr: [7; 32], record: IssuerRecord { issuer_id: [8; 32], display_name: "Org".into(), valid_from_ts: 1, valid_until_ts: 2 } },
        RegistryOp::RemoveIssuer { addr: [9; 32] },
        RegistryOp::SetRegistrar { addr: [10; 32] },
    ];
    for op in ops {
        assert_eq!(RegistryOp::parse(&op.encode()).unwrap(), op);
    }
    assert!(RegistryOp::parse(b"VREG2\x01").is_err());
    assert!(RegistryOp::parse(b"VREG1\x7f").unwrap_err().contains("unknown opcode"));
}

// ---------------------------------------------------------------------------------------
// EVM-signed (secp256k1, legacy EIP-155) registration: how the CBSA pilot wallet sends.
// ---------------------------------------------------------------------------------------

fn rlp_bytes(b: &[u8]) -> Vec<u8> {
    if b.len() == 1 && b[0] < 0x80 {
        return b.to_vec();
    }
    let mut out = rlp_len(b.len(), 0x80);
    out.extend_from_slice(b);
    out
}
fn rlp_len(len: usize, offset: u8) -> Vec<u8> {
    if len < 56 {
        vec![offset + len as u8]
    } else {
        let be: Vec<u8> = len.to_be_bytes().iter().copied().skip_while(|x| *x == 0).collect();
        let mut out = vec![offset + 55 + be.len() as u8];
        out.extend(be);
        out
    }
}
fn rlp_uint(v: u128) -> Vec<u8> {
    let be: Vec<u8> = v.to_be_bytes().iter().copied().skip_while(|x| *x == 0).collect();
    rlp_bytes(&be)
}
fn rlp_list(items: &[Vec<u8>]) -> Vec<u8> {
    let body: Vec<u8> = items.concat();
    let mut out = rlp_len(body.len(), 0xc0);
    out.extend(body);
    out
}

fn evm_key() -> k256::ecdsa::SigningKey {
    k256::ecdsa::SigningKey::from_bytes(&[0x5au8; 32].into()).unwrap()
}
fn evm_addr() -> [u8; 32] {
    let pk = evm_key().verifying_key().to_encoded_point(false);
    let h = vera_blockchain::account::keccak256(&pk.as_bytes()[1..]);
    let mut a = [0u8; 32];
    a[12..].copy_from_slice(&h[12..]);
    a
}

/// Signs a legacy EIP-155 tx (chainId 83721) and wraps it like the RPC does.
fn evm_tx(nonce: u64, to: [u8; 32], data: Vec<u8>) -> Transaction {
    const CHAIN: u128 = 83721;
    let fields = |v: Vec<u8>, r: Vec<u8>, s: Vec<u8>| {
        rlp_list(&[
            rlp_uint(nonce as u128),
            rlp_uint(GAS_PRICE as u128),
            rlp_uint(200_000),
            rlp_bytes(&to[12..]),
            rlp_uint(0),
            rlp_bytes(&data),
            v,
            r,
            s,
        ])
    };
    let unsigned = fields(rlp_uint(CHAIN), rlp_uint(0), rlp_uint(0));
    let digest = vera_blockchain::account::keccak256(&unsigned);
    let (sig, recid) = evm_key().sign_prehash_recoverable(&digest).unwrap();
    let v = recid.to_byte() as u128 + CHAIN * 2 + 35;
    let strip = |b: &[u8]| -> Vec<u8> { b.iter().copied().skip_while(|x| *x == 0).collect() };
    let raw = fields(rlp_uint(v), rlp_bytes(&strip(&sig.r().to_bytes())), rlp_bytes(&strip(&sig.s().to_bytes())));
    let rec = vera_blockchain::rpc::parse_and_recover_evm_tx(&raw, 83721).expect("recover");
    assert_eq!(rec.from, evm_addr());
    Transaction {
        chain_id: "vera-testnet-1".into(),
        public_key: [0u8; 32],
        sender: rec.from,
        nonce: rec.nonce,
        to: Some(rec.to),
        amount: rec.value,
        gas_limit: rec.gas_limit,
        gas_price: rec.gas_price,
        program: rec.data.clone(),
        witness: None,
        signature: [0u8; 64],
        raw_evm: Some(raw),
    }
}

#[tokio::test]
async fn evm_signed_wallet_registers_a_document() {
    let (mut cfg, vk) = genesis(Some(1));
    cfg.initial_accounts.push(GenesisAccount { address: address_to_hex(&evm_addr()), balance: (10 * VERA).to_string() });
    let mut n = node(&cfg, Some(vk));
    filler(&mut n);
    step(&mut n, None).await;

    let op = RegistryOp::Register { kind: 1, doc_hash: doc(77), parent: None };
    let tx = evm_tx(0, REGISTRY_SYSTEM_ADDRESS, op.encode());
    assert_eq!(tx.to, Some(REGISTRY_SYSTEM_ADDRESS), "20-byte 0x…1100 maps to the registry address");
    let b0 = balance(&n, &evm_addr());
    n.submit_transaction(tx).expect("EVM-signed registry tx admitted");
    let b = step(&mut n, None).await;
    assert_eq!(b.transactions.len(), 1);
    let rec = registry::load_doc(&n.csmt, &evm_addr(), &doc(77)).unwrap().expect("record under the EVM address");
    assert_eq!(rec.kind, 1);
    let gas = b.receipts[0].gas_used as u128 * GAS_PRICE as u128;
    assert_eq!(b0 - balance(&n, &evm_addr()), gas + DEFAULT_FEE_PER_ITEM_WEI);
    assert_eq!(nonce(&n, &evm_addr()), 1);
}

/// Regression (found on a live 2-node devnet): wallets priced txs at the old 1 gwei up to
/// the activation block, every pending tx was invalid in that block, no empty block can be
/// built, and a stale tx pinned its sender's nonce, so the chain stalled at activation - 1.
/// Admission, pruning and the RPC now use the rules of the next block.
#[tokio::test]
async fn activation_block_is_reachable_with_pending_old_price_txs() {
    let (cfg, vk) = genesis(Some(3));
    let mut n = node(&cfg, Some(vk));

    // Block 1 under the old rules (a 7-wei gas price is fine).
    let tx = Transaction::new(&n.chain_id, &filler_key(), 0, Some([0x22; 32]), 1, 21_000, 7, vec![]);
    n.submit_transaction(tx).unwrap();
    step(&mut n, None).await;

    // Block 2 is built; a cheap tx arrives while it is in flight (admitted: next height
    // is still 2 at that moment) and so stays pending into the activation block.
    let tx = Transaction::new(&n.chain_id, &filler_key(), 1, Some([0x22; 32]), 1, 21_000, 7, vec![]);
    n.submit_transaction(tx).unwrap();
    let b2 = n.build_proposal().await.expect("build #2");
    let stale = Transaction::new(&n.chain_id, &key(1), 0, Some([0x22; 32]), 1, 21_000, 7, vec![]);
    let stale_hash = stale.tx_hash();
    n.submit_transaction(stale).expect("admitted under the old rules");
    n.validate_proposal(&b2).await.unwrap();
    n.apply_block(b2).await.unwrap();
    assert_eq!(n.height, 2);

    // Next block is the activation block: old prices are refused at admission...
    assert_eq!(registry::effective_params(&n.csmt, 3, Some(3)).unwrap(), Some(FeeParams::default()));
    let cheap = Transaction::new(&n.chain_id, &key(0), 0, Some([0x22; 32]), 1, 21_000, 7, vec![]);
    assert!(n.submit_transaction(cheap).unwrap_err().contains("minimum gas price"));
    // ...and the stale pending tx is pruned, so it no longer pins key(1)'s nonce.
    n.prune_mempool();
    assert!(n.mempool.iter().all(|t| t.tx_hash() != stale_hash), "stale old-price tx pruned");
    let repriced = Transaction::new(&n.chain_id, &key(1), 0, Some([0x22; 32]), 1, 21_000, GAS_PRICE, vec![]);
    n.submit_transaction(repriced).expect("same nonce at the new price");

    // The activation block is built and the rules are on.
    let b3 = step(&mut n, None).await;
    assert_eq!(b3.header.height, 3);
    assert_eq!(registry::load_params(&n.csmt).unwrap(), Some(FeeParams::default()));
}
