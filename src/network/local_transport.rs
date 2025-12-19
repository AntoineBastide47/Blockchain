//! In-memory transport implementation for local testing and development.
//!
//! Enables direct message passing between nodes without network I/O,
//! ideal for unit tests and single-process simulations.

use crate::network::transport::{Rpc, Transport, TransportError};
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
    address: Arc<str>,
}

impl LocalTransport {
    /// Creates a new LocalTransport instance with the given address.
    ///
    /// The transport is wrapped in an Arc for shared ownership across async tasks.
    pub fn new(address: &str) -> Arc<LocalTransport> {
        let (tx, rx) = channel(1024);

        Arc::new(LocalTransport {
            address: Arc::from(address),
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

    async fn send_message(&self, to: Arc<str>, payload: Bytes) -> Result<(), TransportError> {
        let peer = match self.peers.get(to.trim()) {
            Some(r) => r.value().clone(),
            None => {
                return Err(TransportError::PeerNotFound(to.to_string()));
            }
        };

        peer.tx
            .send(Rpc {
                from: self.address.clone(),
                payload,
            })
            .await
            .map_err(|_| TransportError::SendFailed(to.to_string()))
    }

    fn addr(&self) -> Arc<str> {
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
        assert_eq!(received.payload, payload);
    }
}
