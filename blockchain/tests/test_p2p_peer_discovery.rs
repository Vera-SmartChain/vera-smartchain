//! v0.2.5 peer discovery: signed validator address announcements.
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::sync::Arc;
use tokio::sync::mpsc;
use vera_blockchain::p2p::*;

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
}

#[test]
fn announce_roundtrip_and_tamper_detection() {
    let key = SigningKey::generate(&mut OsRng);
    let addr = "203.0.113.7:26656".parse().unwrap();
    let ann = PeerAnnounce::new("vera-testnet-1", addr, &key);
    assert_eq!(ann.verify("vera-testnet-1", now()).unwrap(), addr);

    // Survives the wire encoding used by P2P (serde_json inside P2PPayload).
    let wire = serde_json::to_vec(&P2PPayload::PeerAnnounce(ann.clone())).unwrap();
    match serde_json::from_slice::<P2PPayload>(&wire).unwrap() {
        P2PPayload::PeerAnnounce(back) => assert!(back.verify("vera-testnet-1", now()).is_ok()),
        _ => panic!("wrong payload"),
    }

    let mut moved = ann.clone();
    moved.addr = "198.51.100.9:26656".to_string(); // a relay rewriting the address
    assert!(moved.verify("vera-testnet-1", now()).is_err());

    let mut other_key = ann.clone();
    other_key.node_pubkey = SigningKey::generate(&mut OsRng).verifying_key().to_bytes();
    assert!(other_key.verify("vera-testnet-1", now()).is_err());

    assert!(ann.verify("vera-mainnet", now()).is_err(), "other chain must be rejected");
}

#[test]
fn announce_freshness_window() {
    let key = SigningKey::generate(&mut OsRng);
    let ann = PeerAnnounce::new("vera-testnet-1", "203.0.113.7:26656".parse().unwrap(), &key);
    assert!(ann.verify("vera-testnet-1", now() + PEER_ANNOUNCE_MAX_AGE_SECS + 5).is_err(), "stale");
    assert!(ann.verify("vera-testnet-1", now().saturating_sub(120)).is_err(), "from the future");
    let unusable = PeerAnnounce::new("vera-testnet-1", "0.0.0.0:26656".parse().unwrap(), &key);
    assert!(unusable.verify("vera-testnet-1", now()).is_err());
}

#[test]
fn old_handshake_without_features_still_decodes() {
    // A v0.2.4.x handshake has no `features` field: must decode as features = 0.
    let key = SigningKey::generate(&mut OsRng);
    let hs = HandshakeMsg::new("vera-testnet-1", 5, &key);
    let mut v = serde_json::to_value(&P2PPayload::Handshake(hs)).unwrap();
    v["Handshake"].as_object_mut().unwrap().remove("features");
    match serde_json::from_value::<P2PPayload>(v).unwrap() {
        P2PPayload::Handshake(old) => {
            assert_eq!(old.features, 0);
            assert!(old.verify("vera-testnet-1", 30).is_ok(), "signature does not cover features");
        }
        _ => panic!("wrong payload"),
    }
}

#[tokio::test]
async fn discovery_store_dial_and_broadcast_rules() {
    let my_key = SigningKey::generate(&mut OsRng);
    let my_pub = my_key.verifying_key().to_bytes();
    let mut pm = PeerManager::new("vera-testnet-1", Arc::new(my_key), vec![]);

    let peer_key = SigningKey::generate(&mut OsRng);
    let peer_pub = peer_key.verifying_key().to_bytes();
    let a1: std::net::SocketAddr = "203.0.113.7:26656".parse().unwrap();
    let ann1 = PeerAnnounce::new("vera-testnet-1", a1, &peer_key);
    assert!(pm.store_announce(ann1.clone(), a1));
    assert!(!pm.store_announce(ann1.clone(), a1), "same announce is not stored twice (no relay loop)");

    let mut older = ann1.clone();
    older.timestamp -= 10;
    assert!(!pm.store_announce(older, "198.51.100.1:1".parse().unwrap()), "older announce never wins");
    assert_eq!(pm.discovered[&peer_pub].addr, a1);

    // Tie-break: only the lower pubkey dials first.
    let targets = pm.discovery_dial_targets(&my_pub);
    assert_eq!(targets.contains(&a1), my_pub < peer_pub);
    assert!(pm.discovery_dial_targets(&peer_pub).is_empty(), "never dial ourselves");

    // Discovery payloads only reach peers that advertised the capability.
    let (old_tx, mut old_rx) = mpsc::channel(8);
    let (new_tx, mut new_rx) = mpsc::channel(8);
    let (c1, _r1) = tokio::sync::watch::channel(false);
    let (c2, _r2) = tokio::sync::watch::channel(false);
    let old_addr = "192.0.2.1:26656".parse().unwrap();
    let new_addr = "192.0.2.2:26656".parse().unwrap();
    pm.add_peer(old_addr, [1u8; 32], 0, false, old_tx, c1, 1);
    pm.add_peer(new_addr, [2u8; 32], 0, false, new_tx, c2, 2);
    pm.set_features(&new_addr, FEATURE_PEER_DISCOVERY);
    pm.broadcast(P2PPayload::PeerAnnounce(ann1.clone()), None).await;
    pm.broadcast_discovery(P2PPayload::AddrHint { ip: "192.0.2.9".into() }, None).await;
    assert!(old_rx.try_recv().is_err(), "old peer must never get discovery payloads");
    assert!(matches!(new_rx.try_recv(), Ok(P2PPayload::PeerAnnounce(_))));
    assert!(matches!(new_rx.try_recv(), Ok(P2PPayload::AddrHint { .. })));
}
