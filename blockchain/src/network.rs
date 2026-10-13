use tokio::sync::broadcast;

pub use crate::p2p::*;

pub type P2PMessage = crate::p2p::P2PPayload;

pub struct P2PNetworkHub {
    tx: broadcast::Sender<P2PMessage>,
}

impl P2PNetworkHub {
    pub fn new(capacity: usize) -> Self {
        let (tx, _) = broadcast::channel(capacity);
        Self { tx }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<P2PMessage> {
        self.tx.subscribe()
    }

    pub fn broadcast(&self, msg: P2PMessage) -> Result<usize, String> {
        self.tx.send(msg).map_err(|e| format!("Error transmitting P2P message: {}", e))
    }
}
