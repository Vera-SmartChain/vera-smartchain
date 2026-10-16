use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::{Duration, Instant};
use rand::rngs::OsRng;
use ed25519_dalek::SigningKey;
use tokio::net::TcpStream;
use tokio::sync::mpsc;

use vera_blockchain::p2p::{
    HandshakeMsg, P2PEvent, P2PPayload, P2PService,
    recv_p2p_message, send_p2p_message,
};

#[tokio::test]
async fn test_peer_drop_cleans_up_within_15s() {
    let mut csprng = OsRng;
    let server_key = SigningKey::generate(&mut csprng);
    let (event_tx, mut event_rx) = mpsc::channel(64);
    let local_height = Arc::new(AtomicU64::new(100));

    let (service, peer_manager) = P2PService::new(
        "vera-testnet-1",
        server_key,
        vec![],
        event_tx,
        local_height,
    );

    let server_addr = Arc::new(service).start("127.0.0.1:0".parse().unwrap()).await.expect("Bind failed");

    // 1. Client connects and performs Handshake
    let client_key = SigningKey::generate(&mut csprng);
    let mut client_socket = TcpStream::connect(server_addr).await.expect("Client connect failed");

    let client_hs = HandshakeMsg::new("vera-testnet-1", 50, &client_key);
    send_p2p_message(&mut client_socket, &P2PPayload::Handshake(client_hs)).await.expect("Send handshake failed");

    let ack = recv_p2p_message(&mut client_socket).await.expect("Recv ack failed");
    match ack {
        P2PPayload::HandshakeAck(ack_msg) => {
            assert_eq!(ack_msg.height, 100);
        }
        other => panic!("Expected HandshakeAck, got {:?}", other),
    }

    // Wait until peer is registered
    let start_wait = Instant::now();
    loop {
        {
            let pm = peer_manager.lock().await;
            if pm.peers.len() == 1 {
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(start_wait.elapsed() < Duration::from_secs(5), "Peer registration timeout");
    }

    // Verify PeerConnected event
    match event_rx.recv().await.expect("Expected event") {
        P2PEvent::PeerConnected { height, .. } => assert_eq!(height, 50),
        other => panic!("Expected PeerConnected event, got {:?}", other),
    }

    // 2. Drop the client socket abruptly
    let drop_time = Instant::now();
    drop(client_socket);

    // 3. Monitor server cleanup: MUST be <= 15 seconds
    let mut cleaned_up = false;
    while drop_time.elapsed() <= Duration::from_secs(15) {
        {
            let pm = peer_manager.lock().await;
            if pm.peers.is_empty() {
                cleaned_up = true;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let elapsed = drop_time.elapsed();
    assert!(cleaned_up, "Server failed to clean up dead peer within 15s (elapsed: {:?})", elapsed);
    println!("✅ Dead peer socket cleanup verified in {:?}", elapsed);
    assert!(elapsed <= Duration::from_secs(15), "Cleanup exceeded 15 seconds limit: {:?}", elapsed);

    // Verify PeerDisconnected event was received
    let disc_event = tokio::time::timeout(Duration::from_secs(2), event_rx.recv()).await;
    assert!(disc_event.is_ok(), "Expected PeerDisconnected event");
    match disc_event.unwrap().expect("Event channel closed") {
        P2PEvent::PeerDisconnected { .. } => {},
        other => panic!("Expected PeerDisconnected, got {:?}", other),
    }
}

#[tokio::test]
async fn test_stalled_peer_server_initiates_close_within_15s() {
    use tokio::io::AsyncReadExt;

    let mut csprng = OsRng;
    let server_key = SigningKey::generate(&mut csprng);
    let (event_tx, mut event_rx) = mpsc::channel(64);
    let local_height = Arc::new(AtomicU64::new(100));

    let (service, peer_manager) = P2PService::new(
        "vera-testnet-1",
        server_key,
        vec![],
        event_tx,
        local_height,
    );

    let server_addr = Arc::new(service).start("127.0.0.1:0".parse().unwrap()).await.expect("Bind failed");

    // 1. Client connects and performs Handshake
    let client_key = SigningKey::generate(&mut csprng);
    let client_socket = TcpStream::connect(server_addr).await.expect("Client connect failed");
    let (mut client_reader, mut client_writer) = client_socket.into_split();

    let client_hs = HandshakeMsg::new("vera-testnet-1", 50, &client_key);
    send_p2p_message(&mut client_writer, &P2PPayload::Handshake(client_hs)).await.expect("Send handshake failed");

    let ack = recv_p2p_message(&mut client_reader).await.expect("Recv ack failed");
    match ack {
        P2PPayload::HandshakeAck(ack_msg) => {
            assert_eq!(ack_msg.height, 100);
        }
        other => panic!("Expected HandshakeAck, got {:?}", other),
    }

    // Wait until peer is registered on server
    loop {
        {
            let pm = peer_manager.lock().await;
            if pm.peers.len() == 1 {
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // Drain PeerConnected event
    let _ = event_rx.recv().await;

    // 2. STALLED CLIENT: client does NOT write, does NOT send Pong/Ping, and does NOT close socket!
    // The client keeps client_writer alive and open.
    // The server read timeout (P2P_SOCKET_TIMEOUT = 10s) must trigger,
    // causing the server to terminate all tasks, call writer.shutdown(), and close the socket.
    // The client MUST receive EOF (Ok(0) from read) within <= 15s.
    let stall_start = Instant::now();
    let mut buf = [0u8; 1024];
    let mut eof_received = false;

    while stall_start.elapsed() <= Duration::from_secs(15) {
        match tokio::time::timeout(Duration::from_millis(500), client_reader.read(&mut buf)).await {
            Ok(Ok(0)) => {
                // Server closed the TCP socket!
                eof_received = true;
                break;
            }
            Ok(Ok(_bytes_read)) => {
                // Bytes received from server (e.g. keepalive Ping).
                // Client intentionally stays silent: no Pong, no writes.
            }
            Ok(Err(_)) => {
                // Connection reset / aborted by server shutdown
                eof_received = true;
                break;
            }
            Err(_) => {
                // 500ms slice timeout, continue waiting until overall 15s limit
            }
        }
    }

    let elapsed = stall_start.elapsed();
    assert!(eof_received, "Stalled peer must receive EOF from server within 15s (elapsed: {:?})", elapsed);
    assert!(elapsed <= Duration::from_secs(15), "Server took too long (>15s) to close stalled socket: {:?}", elapsed);
    assert!(elapsed >= Duration::from_secs(9), "Server closed too early ({:?}), expected ~10s read timeout", elapsed);
    println!("✅ Stalled peer closed by server: client received EOF in {:?}", elapsed);

    // 3. Verify server peer_manager is now empty
    {
        let pm = peer_manager.lock().await;
        assert_eq!(pm.peers.len(), 0, "Server must have removed stalled peer from peer_manager");
    }

    // 4. Verify PeerDisconnected was dispatched
    let disc_event = tokio::time::timeout(Duration::from_secs(2), event_rx.recv()).await;
    assert!(disc_event.is_ok(), "Expected PeerDisconnected event for stalled peer");

    // Client writer is explicitly dropped only at the end to guarantee it remained open during test
    drop(client_writer);
}

#[tokio::test]
async fn test_peer_reconnect_deduplicates_to_single_connection() {
    let mut csprng = OsRng;
    let server_key = SigningKey::generate(&mut csprng);
    let (event_tx, _event_rx) = mpsc::channel(64);
    let local_height = Arc::new(AtomicU64::new(200));

    let (service, peer_manager) = P2PService::new(
        "vera-testnet-1",
        server_key,
        vec![],
        event_tx,
        local_height,
    );

    let server_addr = Arc::new(service).start("127.0.0.1:0".parse().unwrap()).await.expect("Bind failed");

    // Common client identity
    let client_key = SigningKey::generate(&mut csprng);

    // 1. First connection
    let mut socket1 = TcpStream::connect(server_addr).await.expect("Connect 1 failed");
    let hs1 = HandshakeMsg::new("vera-testnet-1", 10, &client_key);
    send_p2p_message(&mut socket1, &P2PPayload::Handshake(hs1)).await.expect("Send hs1 failed");
    let _ = recv_p2p_message(&mut socket1).await.expect("Recv ack1 failed");

    // Wait until peer 1 registered
    loop {
        let pm = peer_manager.lock().await;
        if pm.peers.len() == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let initial_addr = {
        let pm = peer_manager.lock().await;
        *pm.peers.keys().next().unwrap()
    };

    // 2. Second connection from SAME client identity (simulating reconnect)
    let mut socket2 = TcpStream::connect(server_addr).await.expect("Connect 2 failed");
    let hs2 = HandshakeMsg::new("vera-testnet-1", 15, &client_key);
    send_p2p_message(&mut socket2, &P2PPayload::Handshake(hs2)).await.expect("Send hs2 failed");
    let _ = recv_p2p_message(&mut socket2).await.expect("Recv ack2 failed");

    // Wait for deduplication to settle
    let start_dedup = Instant::now();
    loop {
        {
            let pm = peer_manager.lock().await;
            if pm.peers.len() == 1 {
                let current_addr = *pm.peers.keys().next().unwrap();
                if current_addr != initial_addr {
                    // New connection took over
                    break;
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(start_dedup.elapsed() < Duration::from_secs(5), "Deduplication timeout");
    }

    // Verify exactly 1 connection remains
    {
        let pm = peer_manager.lock().await;
        assert_eq!(pm.peers.len(), 1, "Must have exactly 1 peer after reconnect deduplication");
    }

    // Verify old socket1 was cancelled and closed by server
    // Trying to read from old socket1 should return EOF or error
    let read_res = tokio::time::timeout(Duration::from_secs(3), recv_p2p_message(&mut socket1)).await;
    assert!(read_res.is_err() || read_res.unwrap().is_err(), "Old socket must be closed/terminated by server");

    // 3. Clean up socket2
    drop(socket2);
    let drop_time = Instant::now();
    loop {
        {
            let pm = peer_manager.lock().await;
            if pm.peers.is_empty() {
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(drop_time.elapsed() < Duration::from_secs(15), "Final cleanup timeout");
    }
}
