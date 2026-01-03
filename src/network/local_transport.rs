//! In-memory transport implementation for local testing and development.
//!
//! Enables direct message passing between nodes without network I/O,
//! ideal for unit tests and single-process simulations.

#[cfg(test)]
pub mod tests {
    use crate::impl_transport_consume;
    use crate::network::rpc::Rpc;
    use crate::network::transport::{Transport, TransportError, spawn_rpc_forwarder};
    use crate::types::bytes::Bytes;
    use crate::types::wrapper_types::BoxFuture;
    use crate::utils::test_utils::utils::test_rpc;
    use dashmap::DashMap;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use tokio::sync::Mutex;
    use tokio::sync::mpsc::{Receiver, Sender, channel};

    /// In-memory transport using async channels for local message passing.
    ///
    /// Maintains a peer registry and routes messages directly through memory
    /// without network overhead. Thread-safe and suitable for concurrent use.
    pub struct LocalTransport {
        peers: DashMap<SocketAddr, Arc<LocalTransport>>,
        tx: Sender<Rpc>,
        rx: Arc<Mutex<Option<Receiver<Rpc>>>>,
        address: SocketAddr,
    }

    impl LocalTransport {
        /// Creates a new LocalTransport instance with the given address.
        ///
        /// The transport is wrapped in an Arc for shared ownership across async tasks.
        pub fn new(address: SocketAddr) -> Arc<LocalTransport> {
            let (tx, rx) = channel(1024);

            Arc::new(LocalTransport {
                address,
                peers: DashMap::new(),
                tx,
                rx: Arc::new(Mutex::new(Some(rx))),
            })
        }
    }

    impl Transport for LocalTransport {
        fn connect(self: &Arc<Self>, other: &Arc<Self>) {
            self.peers.insert(other.addr(), other.clone());
            other.peers.insert(self.addr(), self.clone());
        }

        fn start(self: &Arc<Self>, sx: Sender<Rpc>) {
            spawn_rpc_forwarder(self.clone(), sx);
        }

        impl_transport_consume!();

        fn send_message(
            self: &Arc<Self>,
            to: SocketAddr,
            payload: Bytes,
        ) -> BoxFuture<'static, Result<(), TransportError>> {
            let peers = self.peers.clone();
            let address = self.address;

            Box::pin(async move {
                let peer = match peers.get(&to) {
                    Some(r) => r.value().clone(),
                    None => return Err(TransportError::PeerNotFound(to)),
                };

                peer.tx
                    .send(test_rpc(address, payload))
                    .await
                    .map_err(|_| TransportError::SendFailed(to))
            })
        }

        fn addr(self: &Arc<Self>) -> SocketAddr {
            self.address
        }

        fn peer_addrs(self: &Arc<Self>) -> Vec<SocketAddr> {
            self.peers.iter().map(|e| *e.key()).collect()
        }
    }

    #[tokio::test]
    async fn test_connect() {
        let addr_a: SocketAddr = "127.0.0.1:3000".parse().unwrap();
        let addr_b: SocketAddr = "127.0.0.1:3001".parse().unwrap();
        let tr_a = LocalTransport::new(addr_a);
        let tr_b = LocalTransport::new(addr_b);

        tr_a.connect(&tr_b);
        tr_b.connect(&tr_a);

        assert!(tr_a.peers.contains_key(&addr_b));
        assert_eq!(tr_a.peers.get(&addr_b).unwrap().addr(), tr_b.addr());

        assert!(tr_b.peers.contains_key(&addr_a));
        assert_eq!(tr_b.peers.get(&addr_a).unwrap().addr(), tr_a.addr());
    }

    #[tokio::test]
    async fn test_send_message() {
        let tr_a = LocalTransport::new("127.0.0.1:3000".parse().unwrap());
        let tr_b = LocalTransport::new("127.0.0.1:3001".parse().unwrap());

        tr_a.connect(&tr_b);
        tr_b.connect(&tr_a);

        let mut rx = tr_b.consume().await;

        let payload: Bytes = Bytes::from("The first message.");
        tr_a.send_message(tr_b.addr(), payload.clone())
            .await
            .unwrap();

        let received = rx.recv().await.unwrap();
        assert_eq!(received.from, tr_a.address);
        assert_eq!(received.payload, payload);
    }

    #[tokio::test]
    async fn test_broadcast() {
        let tr_a = LocalTransport::new("127.0.0.1:3000".parse().unwrap());
        let tr_b = LocalTransport::new("127.0.0.1:3001".parse().unwrap());
        let tr_c = LocalTransport::new("127.0.0.1:3002".parse().unwrap());

        tr_a.connect(&tr_b);
        tr_a.connect(&tr_c);

        let mut rx_b = tr_b.consume().await;
        let mut rx_c = tr_c.consume().await;

        let payload = Bytes::new("Broadcast message");
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
        let addr_a: SocketAddr = "127.0.0.1:3000".parse().unwrap();
        let addr_b: SocketAddr = "127.0.0.1:3001".parse().unwrap();
        let tr_a = LocalTransport::new(addr_a);
        let tr_b = LocalTransport::new(addr_b);

        // Single connect call should add both directions
        tr_a.connect(&tr_b);

        assert!(tr_a.peers.contains_key(&addr_b));
        assert!(tr_b.peers.contains_key(&addr_a));
    }

    #[tokio::test]
    async fn connect_multiple_peers() {
        let addr_a: SocketAddr = "127.0.0.1:3000".parse().unwrap();
        let addr_b: SocketAddr = "127.0.0.1:3001".parse().unwrap();
        let addr_c: SocketAddr = "127.0.0.1:3002".parse().unwrap();
        let tr_a = LocalTransport::new(addr_a);
        let tr_b = LocalTransport::new(addr_b);
        let tr_c = LocalTransport::new(addr_c);

        tr_a.connect(&tr_b);
        tr_a.connect(&tr_c);

        assert_eq!(tr_a.peers.len(), 2);
        assert!(tr_a.peers.contains_key(&addr_b));
        assert!(tr_a.peers.contains_key(&addr_c));

        // B and C should only have A as peer
        assert_eq!(tr_b.peers.len(), 1);
        assert_eq!(tr_c.peers.len(), 1);
    }

    #[tokio::test]
    async fn broadcast_excludes_sender() {
        let tr_a = LocalTransport::new("127.0.0.1:3000".parse().unwrap());
        let tr_b = LocalTransport::new("127.0.0.1:3001".parse().unwrap());
        let tr_c = LocalTransport::new("127.0.0.1:3002".parse().unwrap());

        tr_a.connect(&tr_b);
        tr_b.connect(&tr_c);

        let mut rx_a = tr_a.consume().await;
        let mut rx_c = tr_c.consume().await;

        let payload = Bytes::new("Broadcast from B");
        tr_b.broadcast(tr_b.addr(), payload.clone()).await.unwrap();

        // A and C should receive the message
        let received_a = rx_a.recv().await.unwrap();
        assert_eq!(received_a.from, tr_b.address);

        let received_c = rx_c.recv().await.unwrap();
        assert_eq!(received_c.from, tr_b.address);
    }

    #[tokio::test]
    async fn send_to_nonexistent_peer_fails() {
        let tr_a = LocalTransport::new("127.0.0.1:3000".parse().unwrap());

        let result = tr_a
            .send_message("127.0.0.1:2982".parse().unwrap(), Bytes::from("test"))
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn addr_returns_correct_address() {
        let addr: SocketAddr = "127.0.0.1:3000".parse().unwrap();
        let tr = LocalTransport::new(addr);
        assert_eq!(tr.addr(), addr);
    }

    #[tokio::test]
    async fn chain_topology_message_passing() {
        // A -> B -> C topology
        let addr_a: SocketAddr = "127.0.0.1:3000".parse().unwrap();
        let addr_b: SocketAddr = "127.0.0.1:3001".parse().unwrap();
        let addr_c: SocketAddr = "127.0.0.1:3002".parse().unwrap();
        let tr_a = LocalTransport::new(addr_a);
        let tr_b = LocalTransport::new(addr_b);
        let tr_c = LocalTransport::new(addr_c);

        tr_a.connect(&tr_b);
        tr_b.connect(&tr_c);

        let mut rx_b = tr_b.consume().await;

        // A sends to B
        tr_a.send_message(tr_b.addr(), Bytes::from("from A"))
            .await
            .unwrap();
        let msg = rx_b.recv().await.unwrap();
        assert_eq!(msg.from, addr_a);

        // A cannot send directly to C (not connected)
        let result = tr_a.send_message(tr_c.addr(), Bytes::from("test")).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn peer_addrs_returns_empty_when_no_connections() {
        let tr = LocalTransport::new("127.0.0.1:3000".parse().unwrap());
        assert!(tr.peer_addrs().is_empty());
    }

    #[tokio::test]
    async fn peer_addrs_returns_connected_addresses() {
        let addr_a: SocketAddr = "127.0.0.1:3000".parse().unwrap();
        let addr_b: SocketAddr = "127.0.0.1:3001".parse().unwrap();
        let addr_c: SocketAddr = "127.0.0.1:3002".parse().unwrap();
        let tr_a = LocalTransport::new(addr_a);
        let tr_b = LocalTransport::new(addr_b);
        let tr_c = LocalTransport::new(addr_c);

        tr_a.connect(&tr_b);
        tr_a.connect(&tr_c);

        let addrs = tr_a.peer_addrs();
        assert_eq!(addrs.len(), 2);
        assert!(addrs.contains(&addr_b));
        assert!(addrs.contains(&addr_c));
    }

    #[tokio::test]
    async fn peer_addrs_reflects_bidirectional_connections() {
        let addr_a: SocketAddr = "127.0.0.1:3000".parse().unwrap();
        let addr_b: SocketAddr = "127.0.0.1:3001".parse().unwrap();
        let tr_a = LocalTransport::new(addr_a);
        let tr_b = LocalTransport::new(addr_b);

        tr_a.connect(&tr_b);

        let a_peers = tr_a.peer_addrs();
        let b_peers = tr_b.peer_addrs();

        assert_eq!(a_peers.len(), 1);
        assert_eq!(a_peers[0], addr_b);

        assert_eq!(b_peers.len(), 1);
        assert_eq!(b_peers[0], addr_a);
    }
}
