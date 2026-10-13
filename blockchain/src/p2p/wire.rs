use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use std::time::Duration;
use super::messages::*;

/// Maximum P2P network frame size (4 MB) protecting against RAM exhaustion attacks
pub const MAX_P2P_FRAME_SIZE: usize = 4 * 1024 * 1024;

/// Maximum timeout for receiving a full frame (10 seconds) against Slowloris
pub const P2P_SOCKET_TIMEOUT: Duration = Duration::from_secs(10);

/// Reads a binary frame from stream with timeout protection and size limit
pub async fn read_raw_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<(u8, Vec<u8>), String> {
    let read_future = async {
        let mut len_buf = [0u8; 4];
        reader.read_exact(&mut len_buf).await
            .map_err(|e| format!("Failed to read P2P frame length: {}", e))?;
        
        let frame_len = u32::from_be_bytes(len_buf) as usize;
        
        if frame_len == 0 {
            return Err("Empty P2P frame received".to_string());
        }
        if frame_len > MAX_P2P_FRAME_SIZE {
            return Err(format!(
                "P2P frame size exceeds maximum allowed limit: {} > {} bytes",
                frame_len, MAX_P2P_FRAME_SIZE
            ));
        }

        let mut type_buf = [0u8; 1];
        reader.read_exact(&mut type_buf).await
            .map_err(|e| format!("Failed to read P2P message type: {}", e))?;
        let msg_type = type_buf[0];

        let payload_len = frame_len - 1;
        let mut payload = vec![0u8; payload_len];
        if payload_len > 0 {
            reader.read_exact(&mut payload).await
                .map_err(|e| format!("Failed to read P2P frame payload: {}", e))?;
        }

        Ok((msg_type, payload))
    };

    match tokio::time::timeout(P2P_SOCKET_TIMEOUT, read_future).await {
        Ok(res) => res,
        Err(_) => Err("P2P frame read timeout reached (Slowloris Defense)".to_string()),
    }
}

/// Writes a binary frame to stream with length prefix
pub async fn write_raw_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    msg_type: u8,
    payload: &[u8],
) -> Result<(), String> {
    let frame_len = 1 + payload.len();
    if frame_len > MAX_P2P_FRAME_SIZE {
        return Err(format!(
            "Attempted to send P2P frame exceeding 4MB: {} bytes",
            frame_len
        ));
    }

    let len_bytes = (frame_len as u32).to_be_bytes();
    writer.write_all(&len_bytes).await
        .map_err(|e| format!("Failed to write P2P frame length: {}", e))?;
    writer.write_all(&[msg_type]).await
        .map_err(|e| format!("Failed to write P2P message type: {}", e))?;
    if !payload.is_empty() {
        writer.write_all(payload).await
            .map_err(|e| format!("Failed to write P2P payload: {}", e))?;
    }
    writer.flush().await
        .map_err(|e| format!("Failed to flush P2P buffer: {}", e))?;

    Ok(())
}

/// Serializes and sends a high-level message
pub async fn send_p2p_message<W: AsyncWrite + Unpin>(
    writer: &mut W,
    message: &P2PPayload,
) -> Result<(), String> {
    let msg_type = message.msg_type();
    let serialized = serde_json::to_vec(message)
        .map_err(|e| format!("Failed to serialize P2P message: {}", e))?;
    write_raw_frame(writer, msg_type, &serialized).await
}

/// Reads and deserializes a high-level message
pub async fn recv_p2p_message<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<P2PPayload, String> {
    let (_msg_type, payload) = read_raw_frame(reader).await?;
    let message: P2PPayload = serde_json::from_slice(&payload)
        .map_err(|e| format!("Failed to deserialize P2P payload: {}", e))?;
    Ok(message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    #[tokio::test]
    async fn test_p2p_wire_frame_roundtrip() {
        let (mut client, mut server) = duplex(65536);

        let test_payload = b"VERA_BLOCKCHAIN_DISTRIBUTED_TRANSACTION_PAYLOAD";
        let msg_type = MSG_TYPE_NEW_TX;

        let client_task = tokio::spawn(async move {
            write_raw_frame(&mut client, msg_type, test_payload).await.unwrap();
        });

        let server_task = tokio::spawn(async move {
            let (rec_type, rec_payload) = read_raw_frame(&mut server).await.unwrap();
            assert_eq!(rec_type, msg_type);
            assert_eq!(rec_payload, test_payload);
        });

        client_task.await.unwrap();
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_p2p_wire_rejects_oversized_frame() {
        let (mut client, mut server) = duplex(65536);

        let client_task = tokio::spawn(async move {
            // Write forged 5 MB size
            let fake_size: u32 = 5 * 1024 * 1024;
            client.write_all(&fake_size.to_be_bytes()).await.unwrap();
        });

        let server_task = tokio::spawn(async move {
            let res = read_raw_frame(&mut server).await;
            assert!(res.is_err(), "Frame > 4MB must be rejected");
            let err = res.unwrap_err();
            assert!(err.contains("exceeds maximum allowed limit"));
        });

        client_task.await.unwrap();
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_p2p_handshake_crypto_roundtrip() {
        let (mut client, mut server) = duplex(65536);
        let signing_key = SigningKey::generate(&mut OsRng);

        let handshake = HandshakeMsg::new("vera-testnet-1", 100, &signing_key);
        let original_msg = P2PPayload::Handshake(handshake);

        let to_send = original_msg.clone();
        let client_task = tokio::spawn(async move {
            send_p2p_message(&mut client, &to_send).await.unwrap();
        });

        let server_task = tokio::spawn(async move {
            let received = recv_p2p_message(&mut server).await.unwrap();
            assert_eq!(received, original_msg);

            if let P2PPayload::Handshake(hs) = received {
                assert!(hs.verify("vera-testnet-1", 30).is_ok());
                // Test against incompatible chain
                assert!(hs.verify("vera-mainnet", 30).is_err());
            } else {
                panic!("Expected Handshake");
            }
        });

        client_task.await.unwrap();
        server_task.await.unwrap();
    }
}
