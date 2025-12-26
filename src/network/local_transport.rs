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

    /// Establishes a bidirectional connection to another transport node.
    ///
    /// Both transports are added to each other's routing tables.
    pub async fn connect(self: &Arc<LocalTransport>, other: &Arc<LocalTransport>) {
        self.peers.insert(other.addr(), other.clone());
        other.peers.insert(self.addr(), self.clone());
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

    async fn broadcast(&self, from: String, data: SerializableBytes) -> Result<(), String> {
        for peer in &self.peers {
            if from == peer.addr() {
                continue;
            }
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

        tr_a.connect(&tr_b).await;
        tr_b.connect(&tr_a).await;

        assert!(tr_a.peers.contains_key("B"));
        assert_eq!(tr_a.peers.get("B").unwrap().addr(), tr_b.addr());

        assert!(tr_b.peers.contains_key("A"));
        assert_eq!(tr_b.peers.get("A").unwrap().addr(), tr_a.addr());
    }

    #[tokio::test]
    async fn test_send_message() {
        let tr_a = LocalTransport::new("A");
        let tr_b = LocalTransport::new("B");

        tr_a.connect(&tr_b).await;
        tr_b.connect(&tr_a).await;

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

        tr_a.connect(&tr_b).await;
        tr_a.connect(&tr_c).await;

        let mut rx_b = tr_b.consume().await;
        let mut rx_c = tr_c.consume().await;

        let payload = SerializableBytes::new("Broadcast message");
        tr_a.broadcast(tr_a.addr(), payload.clone()).await.unwrap();

        let received_b = rx_b.recv().await.unwrap();
        assert_eq!(received_b.from, tr_a.address);
        assert_eq!(received_b.payload, payload.clone());

        let received_c = rx_c.recv().await.unwrap();
        assert_eq!(received_c.from, tr_a.address);
        assert_eq!(received_c.payload, payload);
    }

    #[tokio::test]
    async fn connect_is_bidirectional() {
        let tr_a = LocalTransport::new("A");
        let tr_b = LocalTransport::new("B");

        // Single connect call should add both directions
        tr_a.connect(&tr_b).await;

        assert!(tr_a.peers.contains_key("B"));
        assert!(tr_b.peers.contains_key("A"));
    }

    #[tokio::test]
    async fn connect_multiple_peers() {
        let tr_a = LocalTransport::new("A");
        let tr_b = LocalTransport::new("B");
        let tr_c = LocalTransport::new("C");

        tr_a.connect(&tr_b).await;
        tr_a.connect(&tr_c).await;

        assert_eq!(tr_a.peers.len(), 2);
        assert!(tr_a.peers.contains_key("B"));
        assert!(tr_a.peers.contains_key("C"));

        // B and C should only have A as peer
        assert_eq!(tr_b.peers.len(), 1);
        assert_eq!(tr_c.peers.len(), 1);
    }

    #[tokio::test]
    async fn broadcast_excludes_sender() {
        let tr_a = LocalTransport::new("A");
        let tr_b = LocalTransport::new("B");
        let tr_c = LocalTransport::new("C");

        tr_a.connect(&tr_b).await;
        tr_b.connect(&tr_c).await;

        let mut rx_a = tr_a.consume().await;
        let mut rx_c = tr_c.consume().await;

        let payload = SerializableBytes::new("Broadcast from B");
        tr_b.broadcast(tr_b.addr(), payload.clone()).await.unwrap();

        // A and C should receive the message
        let received_a = rx_a.recv().await.unwrap();
        assert_eq!(received_a.from, tr_b.address);

        let received_c = rx_c.recv().await.unwrap();
        assert_eq!(received_c.from, tr_b.address);
    }

    #[tokio::test]
    async fn send_to_nonexistent_peer_fails() {
        let tr_a = LocalTransport::new("A");

        let result = tr_a
            .send_message("NonExistent".to_string(), Bytes::from("test"))
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn addr_returns_correct_address() {
        let tr = LocalTransport::new("TestAddr");
        assert_eq!(tr.addr(), "TestAddr");
    }

    #[tokio::test]
    async fn chain_topology_message_passing() {
        // A -> B -> C topology
        let tr_a = LocalTransport::new("A");
        let tr_b = LocalTransport::new("B");
        let tr_c = LocalTransport::new("C");

        tr_a.connect(&tr_b).await;
        tr_b.connect(&tr_c).await;

        let mut rx_b = tr_b.consume().await;

        // A sends to B
        tr_a.send_message(tr_b.addr(), Bytes::from("from A"))
            .await
            .unwrap();
        let msg = rx_b.recv().await.unwrap();
        assert_eq!(msg.from, "A");

        // A cannot send directly to C (not connected)
        let result = tr_a.send_message(tr_c.addr(), Bytes::from("test")).await;
        assert!(result.is_err());
    }
}
