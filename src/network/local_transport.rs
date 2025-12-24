//! In-memory transport implementation for local testing and development.
//!
//! Enables direct message passing between nodes without network I/O,
//! ideal for unit tests and single-process simulations.

use crate::network::rpc::Rpc;
use crate::network::transport::{Transport, TransportError};
use crate::types::serializable_bytes::SerializableBytes;
use bytes::Bytes;
use dashmap::DashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::sync::mpsc::{Receiver, Sender, channel};

/// In-memory transport using async channels for local message passing.
///
/// Maintains a peer registry and routes messages directly through memory
/// without network overhead. Thread-safe and suitable for concurrent use.
pub struct LocalTransport {
    peers: DashMap<String, Arc<LocalTransport>>,
    tx: Sender<Rpc>,
    rx: Mutex<Option<Receiver<Rpc>>>,
    address: String,
}

impl LocalTransport {
    /// Creates a new LocalTransport instance with the given address.
    ///
    /// The transport is wrapped in an Arc for shared ownership across async tasks.
    pub fn new(address: &str) -> Arc<LocalTransport> {
        let (tx, rx) = channel(1024);

        Arc::new(LocalTransport {
            address: address.to_string(),
            peers: DashMap::new(),
            tx,
            rx: Mutex::new(Some(rx)),
        })
    }

    /// Establishes a connection to another transport node.
    ///
    /// Adds the peer to this transport's routing table for message delivery.
    pub async fn connect(&self, other: Arc<LocalTransport>) {
        self.peers.insert(other.addr().to_string(), other);
    }
}

#[async_trait::async_trait]
impl Transport for LocalTransport {
    async fn consume(&self) -> Receiver<Rpc> {
        let mut guard = self.rx.lock().await;
        guard.take().unwrap()
    }

    async fn send_message(&self, to: String, payload: Bytes) -> Result<(), TransportError> {
        let peer = match self.peers.get(to.trim()) {
            Some(r) => r.value().clone(),
            None => {
                return Err(TransportError::PeerNotFound(to.to_string()));
            }
        };

        peer.tx
            .send(Rpc::new(self.address.clone(), payload))
            .await
            .map_err(|_| TransportError::SendFailed(to.to_string()))
    }

    async fn broadcast(&self, data: SerializableBytes) -> Result<(), String> {
        for peer in &self.peers {
            if let Err(e) = self.send_message(peer.addr(), data.0.clone()).await {
                return Err(e.to_string());
            }
        }
        Ok(())
    }

    fn addr(&self) -> String {
        self.address.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_connect() {
        let tr_a = LocalTransport::new("A");
        let tr_b = LocalTransport::new("B");

        tr_a.connect(tr_b.clone()).await;
        tr_b.connect(tr_a.clone()).await;

        assert!(tr_a.peers.contains_key("B"));
        assert_eq!(tr_a.peers.get("B").unwrap().addr(), tr_b.addr());

        assert!(tr_b.peers.contains_key("A"));
        assert_eq!(tr_b.peers.get("A").unwrap().addr(), tr_a.addr());
    }

    #[tokio::test]
    async fn test_send_message() {
        let tr_a = LocalTransport::new("A");
        let tr_b = LocalTransport::new("B");

        tr_a.connect(tr_b.clone()).await;
        tr_b.connect(tr_a.clone()).await;

        let mut rx = tr_b.consume().await;

        let payload: Bytes = Bytes::from("The first message.");
        tr_a.send_message(tr_b.addr(), payload.clone())
            .await
            .unwrap();

        let received = rx.recv().await.unwrap();
        assert_eq!(received.from, tr_a.address);
        assert_eq!(received.payload, payload.into());
    }

    #[tokio::test]
    async fn test_broadcast() {
        let tr_a = LocalTransport::new("A");
        let tr_b = LocalTransport::new("B");
        let tr_c = LocalTransport::new("C");

        tr_a.connect(tr_b.clone()).await;
        tr_a.connect(tr_c.clone()).await;

        let mut rx_b = tr_b.consume().await;
        let mut rx_c = tr_c.consume().await;

        let payload = SerializableBytes::new("Broadcast message");
        tr_a.broadcast(payload.clone()).await.unwrap();

        let received_b = rx_b.recv().await.unwrap();
        assert_eq!(received_b.from, tr_a.address);
        assert_eq!(received_b.payload, payload.clone());

        let received_c = rx_c.recv().await.unwrap();
        assert_eq!(received_c.from, tr_a.address);
        assert_eq!(received_c.payload, payload);
    }
}
