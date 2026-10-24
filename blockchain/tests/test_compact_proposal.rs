//! Compact proposals: the signature still verifies without the block body, the hashes
//! round-trip, the block is rebuilt from the mempool exactly (tx_root), missing txs are
//! counted, and each peer gets the form its capabilities allow.

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use vera_blockchain::account::{address_from_pubkey, address_to_hex};
use vera_blockchain::block::Block;
use vera_blockchain::genesis::{GenesisAccount, GenesisConfig};
use vera_blockchain::node::FullNode;
use vera_blockchain::p2p::{P2PPayload, TmCompactProposal, TmProposal, FEATURE_COMPACT_BLOCKS, FEATURE_PEER_DISCOVERY, FEATURE_TENDERMINT};
use vera_blockchain::transaction::Transaction;

#[tokio::test]
async fn compact_proposal_round_trip_and_rebuild() {
    let (mut cfg, val_key) = GenesisConfig::default_testnet();
    let payers: Vec<SigningKey> = (0..6).map(|_| SigningKey::generate(&mut OsRng)).collect();
    for k in &payers {
        cfg.initial_accounts.push(GenesisAccount {
            address: address_to_hex(&address_from_pubkey(&k.verifying_key().to_bytes())),
            balance: "1000000000000000000000".to_string(),
        });
    }
    let dir = std::env::temp_dir().join(format!("vera_compact_{}", rand::random::<u64>()));
    let mut node = FullNode::load_or_init(&dir, &cfg, Some(val_key.clone())).unwrap();
    for (i, k) in payers.iter().enumerate() {
        for n in 0..3u64 {
            let tx = Transaction::new(&node.chain_id, k, n, Some([i as u8; 32]), 1, 21_000, 1, vec![]);
            node.submit_transaction(tx).expect("admission");
        }
    }
    let block = node.build_proposal().await.expect("build");
    assert_eq!(block.transactions.len(), 18);
    let full = TmProposal::new(&node.chain_id, 0, None, block.clone(), &val_key);

    let compact = TmCompactProposal::from_full(&full);
    assert!(compact.proposal.block.transactions.is_empty() && compact.proposal.block.receipts.is_empty());
    compact.proposal.verify(&node.chain_id).expect("signature covers the header only");
    let hashes = compact.hashes().unwrap();
    assert_eq!(hashes, block.transactions.iter().map(|t| t.tx_hash()).collect::<Vec<_>>());
    let wire = serde_json::to_vec(&P2PPayload::TmCompactProposal(compact.clone())).unwrap().len();
    let wire_full = serde_json::to_vec(&P2PPayload::TmProposal(full.clone())).unwrap().len();
    assert!(wire * 4 < wire_full, "compact {} bytes vs full {}", wire, wire_full);

    // Rebuilt from the mempool: same txs, same tx_root.
    let txs = node.mempool_txs_by_hash(&hashes).expect("all pending");
    assert_eq!(Block::compute_tx_root(&txs), block.header.tx_root);

    // Some txs missing on the receiver: counted, so it asks for the full proposal.
    let gone: Vec<[u8; 32]> = hashes[..5].to_vec();
    node.mempool.retain(|t| !gone.contains(&t.tx_hash()));
    assert_eq!(node.mempool_txs_by_hash(&hashes).unwrap_err(), 5);

    // Per-peer form.
    let legacy = FEATURE_PEER_DISCOVERY | FEATURE_TENDERMINT;
    let modern = legacy | FEATURE_COMPACT_BLOCKS;
    assert!(matches!(P2PPayload::TmProposal(full.clone()).adapt_for(legacy), Some(P2PPayload::TmProposal(_))));
    // 18 txs: below COMPACT_PROPOSAL_MIN_TXS, so it goes whole even to a modern peer.
    assert!(matches!(P2PPayload::TmProposal(full.clone()).adapt_for(modern), Some(P2PPayload::TmProposal(_))));
    let mut big = full.clone();
    big.block.transactions = (0..vera_blockchain::p2p::COMPACT_PROPOSAL_MIN_TXS).map(|_| block.transactions[0].clone()).collect();
    assert!(matches!(P2PPayload::TmProposal(big).adapt_for(modern), Some(P2PPayload::TmCompactProposal(_))));
    assert!(P2PPayload::BlockCommit(block.clone()).adapt_for(modern).is_none());
    assert!(matches!(P2PPayload::BlockCommit(block.clone()).adapt_for(legacy), Some(P2PPayload::BlockCommit(_))));
    assert!(matches!(P2PPayload::TmProposalFull(full).adapt_for(modern), Some(P2PPayload::TmProposalFull(_))));
    let _ = std::fs::remove_dir_all(&dir);
}
