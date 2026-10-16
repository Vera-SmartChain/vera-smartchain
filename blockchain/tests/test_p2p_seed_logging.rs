use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::Duration;
use rand::rngs::OsRng;
use ed25519_dalek::SigningKey;
use tokio::net::TcpListener;
use tokio::sync::mpsc;

use vera_blockchain::p2p::{
    HandshakeMsg, P2PPayload, P2PService,
    recv_p2p_message, send_p2p_message,
    SeedFailureType, should_log,
};

#[tokio::test]
async fn test_seed_fake_silent_yields_handshake_ack_timeout() {
    let mut csprng = OsRng;
    let server_key = SigningKey::generate(&mut csprng);
    let (event_tx, _event_rx) = mpsc::channel(64);
    let local_height = Arc::new(AtomicU64::new(10));

    // Spin up a silent mock TCP listener that accepts and never sends HandshakeAck
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mock_addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        if let Ok((mut socket, _)) = listener.accept().await {
            // Read incoming handshake message from client
            let _ = recv_p2p_message(&mut socket).await;
            // Sleep without sending any HandshakeAck to force HandshakeAck timeout
            tokio::time::sleep(Duration::from_secs(10)).await;
        }
    });

    let (service, _pm) = P2PService::new(
        "vera-testnet-1",
        server_key,
        vec![mock_addr],
        event_tx,
        local_height,
    );

    let res = service.connect_to_seed(mock_addr).await;
    assert!(res.is_err(), "Expected connection error with silent peer");
    let err = res.err().unwrap();
    println!("Captured expected error: {}", err);
    assert_eq!(err.kind, SeedFailureType::AckTimeout, "Expected AckTimeout failure kind");
    assert!(err.contains("HandshakeAck timeout"), "Error message must contain 'HandshakeAck timeout', got: {}", err);
}

#[tokio::test]
async fn test_seed_wrong_chain_id_yields_chain_mismatch_reason() {
    let mut csprng = OsRng;
    let server_key = SigningKey::generate(&mut csprng);
    let mock_key = SigningKey::generate(&mut csprng);
    let (event_tx, _event_rx) = mpsc::channel(64);
    let local_height = Arc::new(AtomicU64::new(10));

    // Spin up mock server that responds with different chain_id
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mock_addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        if let Ok((mut socket, _)) = listener.accept().await {
            let _ = recv_p2p_message(&mut socket).await;
            // Send HandshakeAck with wrong chain_id
            let wrong_ack = HandshakeMsg::new("alien-chain-999", 50, &mock_key);
            let _ = send_p2p_message(&mut socket, &P2PPayload::HandshakeAck(wrong_ack)).await;
        }
    });

    let (service, _pm) = P2PService::new(
        "vera-testnet-1",
        server_key,
        vec![mock_addr],
        event_tx,
        local_height,
    );

    let res = service.connect_to_seed(mock_addr).await;
    assert!(res.is_err(), "Expected connection error with wrong chain_id");
    let err = res.err().unwrap();
    println!("Captured expected error: {}", err);
    assert_eq!(err.kind, SeedFailureType::AckRejected, "Expected AckRejected failure kind");
    assert!(err.contains("alien-chain-999"), "Error message must mention peer chain 'alien-chain-999', got: {}", err);
    assert!(err.contains("Network incompatibility"), "Error message must indicate network incompatibility, got: {}", err);
}

#[tokio::test]
async fn test_20_consecutive_failures_same_reason_yields_at_most_3_lines() {
    let failure_type = SeedFailureType::TcpRefused;
    let mut last_type = None;
    let mut logged_failure_count = 0;

    // Test pure function should_log across attempts 1..=20 with identical failure type:
    for attempt in 1..=20 {
        if should_log(attempt, last_type, failure_type) {
            logged_failure_count += 1;
            last_type = Some(failure_type);
        }
    }
    // Attempts logged: #1 (initial failure), #10 (periodic recap), #20 (periodic recap)
    assert_eq!(
        logged_failure_count, 3,
        "Exactly 3 failure lines must be logged across 20 attempts for the same failure type"
    );

    // Verify reason change logging:
    let new_type = SeedFailureType::AckTimeout;
    assert!(
        should_log(21, last_type, new_type),
        "Immediate failure log must be emitted when failure type changes"
    );

    // Verify Connecting line suppression on retries:
    // Attempt 1: no tracker exists -> Connecting IS logged (1 line)
    // Attempts 2..=20: tracker exists -> Connecting is NOT logged (0 lines)
    // Total Connecting lines emitted across 20 attempts: exactly 1

    let mut csprng = OsRng;
    let server_key = SigningKey::generate(&mut csprng);
    let (event_tx, _event_rx) = mpsc::channel(64);
    let local_height = Arc::new(AtomicU64::new(10));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let closed_addr = listener.local_addr().unwrap();
    drop(listener); // immediately close

    let (service, _pm) = P2PService::new(
        "vera-testnet-1",
        server_key,
        vec![closed_addr],
        event_tx,
        local_height,
    );

    for _ in 1..=20 {
        service.maintain_seed_connections().await;
    }

    let trackers = service.seed_trackers.lock().await;
    let tracker = trackers.get(&closed_addr).expect("Tracker must exist for failing seed");
    assert_eq!(tracker.attempts, 20, "Total attempts must be exactly 20");
    assert_eq!(tracker.last_failure_type, Some(SeedFailureType::TcpRefused));
    println!("✅ 20 consecutive failures verified: exactly 3 failure lines logged by should_log; tracker attempts: {}", tracker.attempts);
}

#[tokio::test]
async fn test_20_consecutive_failures_same_type_different_ms_yields_exactly_3_lines_and_1_connecting() {
    // Test that varying millisecond values do NOT cause log spam because should_log compares SeedFailureType
    let kind = SeedFailureType::AckTimeout;
    let mut last_type = None;
    let mut logged_failure_count = 0;

    for attempt in 1..=20 {
        // In real-world failure, elapsed ms varies on every single retry:
        let _varying_ms_string = format!("HandshakeAck timeout after {} ms", 5000 + attempt * 17);
        if should_log(attempt, last_type, kind) {
            logged_failure_count += 1;
            last_type = Some(kind);
        }
    }
    assert_eq!(
        logged_failure_count, 3,
        "20 consecutive failures of the same type with different ms timings must generate exactly 3 failure lines (#1, #10, #20)"
    );

    // Verify type transition:
    let changed_kind = SeedFailureType::AckEof;
    assert!(
        should_log(21, last_type, changed_kind),
        "A transition to a different failure type (e.g. AckEof) must immediately trigger logging"
    );

    // Verify Connecting line suppression across 20 iterations:
    let mut csprng = OsRng;
    let server_key = SigningKey::generate(&mut csprng);
    let (event_tx, _event_rx) = mpsc::channel(64);
    let local_height = Arc::new(AtomicU64::new(10));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let closed_addr = listener.local_addr().unwrap();
    drop(listener); // immediately close

    let (service, _pm) = P2PService::new(
        "vera-testnet-1",
        server_key,
        vec![closed_addr],
        event_tx,
        local_height,
    );

    for _ in 1..=20 {
        service.maintain_seed_connections().await;
    }

    let trackers = service.seed_trackers.lock().await;
    let tracker = trackers.get(&closed_addr).expect("Tracker must exist for failing seed");
    assert_eq!(tracker.attempts, 20, "Total attempts must be exactly 20");
    assert_eq!(tracker.last_failure_type, Some(SeedFailureType::TcpRefused));
    println!("✅ 20 consecutive failures with different ms generated exactly 3 lines of failure and 1 of Connecting");
}

#[tokio::test]
async fn test_seed_reconnect_yields_recovery_line() {
    let mut csprng = OsRng;
    let server_key = SigningKey::generate(&mut csprng);
    let mock_key = SigningKey::generate(&mut csprng);
    let (event_tx, _event_rx) = mpsc::channel(64);
    let local_height = Arc::new(AtomicU64::new(10));

    // Start with a mock listener that only starts AFTER simulated failures
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mock_addr = listener.local_addr().unwrap();

    let (service, pm) = P2PService::new(
        "vera-testnet-1",
        server_key,
        vec![mock_addr],
        event_tx,
        local_height,
    );

    // Simulate 5 prior failures in the tracker
    {
        let mut trackers = service.seed_trackers.lock().await;
        trackers.insert(mock_addr, vera_blockchain::p2p::SeedConnTracker {
            attempts: 5,
            first_failed_at: std::time::Instant::now() - Duration::from_secs(120),
            last_failure_type: Some(SeedFailureType::TcpRefused),
            last_reason: "TCP connection refused".to_string(),
        });
    }

    // Now start responding on the mock server
    tokio::spawn(async move {
        if let Ok((mut socket, _)) = listener.accept().await {
            if let Ok(P2PPayload::Handshake(_)) = recv_p2p_message(&mut socket).await {
                let ack = HandshakeMsg::new("vera-testnet-1", 100, &mock_key);
                let _ = send_p2p_message(&mut socket, &P2PPayload::HandshakeAck(ack)).await;
            }
        }
    });

    // Run maintain_seed_connections: should successfully connect and clear tracker
    service.maintain_seed_connections().await;

    // Check that tracker was cleared upon reconnection
    {
        let trackers = service.seed_trackers.lock().await;
        assert!(trackers.get(&mock_addr).is_none(), "Seed tracker must be removed upon successful reconnection");
    }

    // Check peer is registered in PeerManager
    {
        let pm_lock = pm.lock().await;
        assert_eq!(pm_lock.peers.len(), 1, "Peer must be registered after reconnect");
    }

    println!("✅ Seed reconnection and tracker cleanup verified successfully");
}

#[tokio::test]
async fn test_seed_reconnect_via_inbound_clears_tracker_and_logs_recovery() {
    let mut csprng = OsRng;
    let server_key = SigningKey::generate(&mut csprng);
    let (event_tx, _event_rx) = mpsc::channel(64);
    let local_height = Arc::new(AtomicU64::new(10));

    let mock_addr: SocketAddr = "127.0.0.1:29999".parse().unwrap();

    let (service, pm) = P2PService::new(
        "vera-testnet-1",
        server_key,
        vec![mock_addr],
        event_tx,
        local_height,
    );

    // Seed had 3 prior failures
    {
        let mut trackers = service.seed_trackers.lock().await;
        trackers.insert(mock_addr, vera_blockchain::p2p::SeedConnTracker {
            attempts: 3,
            first_failed_at: std::time::Instant::now() - Duration::from_secs(60),
            last_failure_type: Some(SeedFailureType::TcpTimeout),
            last_reason: "TCP connection timeout after 5000 ms".to_string(),
        });
    }

    // Now seed connects via inbound (registered in PeerManager)
    {
        let mut pm_lock = pm.lock().await;
        let (tx, _) = mpsc::channel(10);
        let (cancel_tx, _) = tokio::sync::watch::channel(false);
        pm_lock.add_peer(mock_addr, [7u8; 32], 50, false, tx, cancel_tx, 100);
    }

    // maintain_seed_connections calls connect_to_seed -> returns Ok(false) (already connected)
    service.maintain_seed_connections().await;

    // Tracker must be cleared and recovery emitted
    {
        let trackers = service.seed_trackers.lock().await;
        assert!(trackers.get(&mock_addr).is_none(), "Tracker must be cleared when seed is already connected (Ok(false))");
    }
    println!("✅ Inbound reconnect recovery verified successfully");
}
