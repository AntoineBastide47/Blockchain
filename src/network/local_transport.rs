//! In-memory transport implementation for local testing and development.
//!
//! Enables direct message passing between nodes without network I/O,
//! ideal for unit tests and single-process simulations.

#[cfg(test)]
pub mod tests {
    use crate::impl_transport_consume;
    use crate::network::rpc::Rpc;
    use crate::network::transport::{
        Multiaddr, PeerId, Transport, TransportError, spawn_rpc_forwarder,
    };
    use crate::types::bytes::Bytes;
    use crate::types::hash::Hash;
    use crate::types::wrapper_types::BoxFuture;
    use crate::utils::test_utils::utils::{
        multiaddr_to_socket_addr, socket_addr_to_multiaddr, test_rpc,
    };
    use dashmap::DashMap;
    use std::net::SocketAddr;
    use std::sync::{Arc, LazyLock};
    use tokio::sync::Mutex;
    use tokio::sync::mpsc::{Receiver, Sender, channel};

    /// Global registry of LocalTransport instances indexed by their listen address.
    static TRANSPORT_REGISTRY: LazyLock<DashMap<Multiaddr, Arc<LocalTransport>>> =
        LazyLock::new(DashMap::new);

    /// In-memory transport using async channels for local message passing.
    ///
    /// Maintains a peer registry and routes messages directly through memory
    /// without network overhead. Thread-safe and suitable for concurrent use.
    pub struct LocalTransport {
        peers: DashMap<PeerId, Arc<LocalTransport>>,
        tx: Sender<Rpc>,
        rx: Arc<Mutex<Option<Receiver<Rpc>>>>,
        address: SocketAddr,
        multiaddr: Multiaddr,
        peer_id: PeerId,
    }

    impl LocalTransport {
        /// Creates a new LocalTransport instance with the given address.
        ///
        /// The transport is wrapped in an Arc for shared ownership across async tasks
        /// and registered in the global registry for address-based lookup.
        pub fn new(address: SocketAddr) -> Arc<LocalTransport> {
            let (tx, rx) = channel(1024);
            let mut hasher = Hash::sha3();
            hasher.update(b"LOCAL_TRANSPORT");
            hasher.update(address.to_string().as_bytes());
            let peer_id = hasher.finalize();
            let multiaddr = socket_addr_to_multiaddr(address);

            let transport = Arc::new(LocalTransport {
                address,
                multiaddr: multiaddr.clone(),
                peers: DashMap::new(),
                tx,
                rx: Arc::new(Mutex::new(Some(rx))),
                peer_id,
            });

            TRANSPORT_REGISTRY.insert(multiaddr, transport.clone());

            transport
        }
    }

    impl Transport for LocalTransport {
        fn connect(self: &Arc<Self>, addr: Multiaddr) -> BoxFuture<Option<PeerId>> {
            let this = self.clone();
            Box::pin(async move {
                let other = match TRANSPORT_REGISTRY.get(&addr) {
                    Some(entry) => entry.value().clone(),
                    None => return None,
                };

                let peer_id = other.peer_id();
                this.peers.insert(peer_id, other.clone());
                other.peers.insert(this.peer_id(), this.clone());
                Some(peer_id)
            })
        }

        fn start(self: &Arc<Self>, sx: Sender<Rpc>) {
            spawn_rpc_forwarder(self.clone(), sx);
        }

        fn wait_until_listening(self: &Arc<Self>) -> BoxFuture<()> {
            Box::pin(async {})
        }

        impl_transport_consume!();

        fn send_message(
            self: &Arc<Self>,
            to: PeerId,
            origin: PeerId,
            payload: Bytes,
        ) -> BoxFuture<Result<(), TransportError>> {
            let peers = self.peers.clone();
            let self_id = self.peer_id;
            let self_addr = self.address;

            Box::pin(async move {
                let peer = peers
                    .get(&to)
                    .map(|r| r.value().clone())
                    .ok_or(TransportError::PeerNotFound(to))?;

                let origin_addr = if origin == self_id {
                    self_addr
                } else {
                    peers
                        .get(&origin)
                        .map(|p| p.address)
                        .ok_or(TransportError::PeerNotFound(origin))?
                };

                peer.tx
                    .send(test_rpc(origin_addr, payload))
                    .await
                    .map_err(|_| TransportError::SendFailed(to))
            })
        }

        fn peer_id(self: &Arc<Self>) -> PeerId {
            self.peer_id
        }

        fn peer_ids(self: &Arc<Self>) -> Vec<PeerId> {
            self.peers.iter().map(|e| *e.key()).collect()
        }

        fn addr(self: &Arc<Self>) -> Multiaddr {
            self.multiaddr.clone()
        }

        fn stop(self: &Arc<Self>) -> BoxFuture<()> {
            let this = self.clone();
            Box::pin(async move {
                let peer_ids: Vec<PeerId> = this.peers.iter().map(|entry| *entry.key()).collect();

                for peer_id in peer_ids {
                    if let Some((_, peer)) = this.peers.remove(&peer_id) {
                        peer.peers.remove(&this.peer_id);
                    }
                }

                TRANSPORT_REGISTRY.remove(&this.multiaddr);
            })
        }
    }

    #[tokio::test]
    async fn test_connect() {
        let addr_a: SocketAddr = "127.0.0.1:4000".parse().unwrap();
        let addr_b: SocketAddr = "127.0.0.1:4001".parse().unwrap();
        let tr_a = LocalTransport::new(addr_a);
        let tr_b = LocalTransport::new(addr_b);

        tr_a.connect(tr_b.addr()).await;
        tr_b.connect(tr_a.addr()).await;

        assert!(tr_a.peers.contains_key(&tr_b.peer_id()));
        assert_eq!(
            tr_a.peers.get(&tr_b.peer_id()).unwrap().address,
            tr_b.address
        );

        assert!(tr_b.peers.contains_key(&tr_a.peer_id()));
        assert_eq!(
            tr_b.peers.get(&tr_a.peer_id()).unwrap().address,
            tr_a.address
        );
    }

    #[tokio::test]
    async fn test_send_message() {
        let tr_a = LocalTransport::new("127.0.0.1:4002".parse().unwrap());
        let tr_b = LocalTransport::new("127.0.0.1:4003".parse().unwrap());

        tr_a.connect(tr_b.addr()).await;
        tr_b.connect(tr_a.addr()).await;

        let mut rx = tr_b.consume().await;

        let payload: Bytes = Bytes::from("The first message.");
        tr_a.send_message(tr_b.peer_id(), tr_a.peer_id(), payload.clone())
            .await
            .unwrap();

        let received = rx.recv().await.unwrap();
        assert_eq!(received.payload, payload);
    }

    #[tokio::test]
    async fn test_broadcast() {
        let tr_a = LocalTransport::new("127.0.0.1:4004".parse().unwrap());
        let tr_b = LocalTransport::new("127.0.0.1:4005".parse().unwrap());
        let tr_c = LocalTransport::new("127.0.0.1:4006".parse().unwrap());

        tr_a.connect(tr_b.addr()).await;
        tr_a.connect(tr_c.addr()).await;

        let mut rx_b = tr_b.consume().await;
        let mut rx_c = tr_c.consume().await;

        let payload = Bytes::new("Broadcast message");
        tr_a.broadcast(tr_a.peer_id(), payload.clone())
            .await
            .unwrap();

        let received_b = rx_b.recv().await.unwrap();
        assert_eq!(received_b.payload, payload.clone());

        let received_c = rx_c.recv().await.unwrap();
        assert_eq!(received_c.payload, payload);
    }

    #[tokio::test]
    async fn connect_is_bidirectional() {
        let addr_a: SocketAddr = "127.0.0.1:4007".parse().unwrap();
        let addr_b: SocketAddr = "127.0.0.1:4008".parse().unwrap();
        let tr_a = LocalTransport::new(addr_a);
        let tr_b = LocalTransport::new(addr_b);

        // Single connect call should add both directions
        tr_a.connect(tr_b.addr()).await;

        assert!(tr_a.peers.contains_key(&tr_b.peer_id()));
        assert!(tr_b.peers.contains_key(&tr_a.peer_id()));
    }

    #[tokio::test]
    async fn connect_multiple_peers() {
        let addr_a: SocketAddr = "127.0.0.1:4009".parse().unwrap();
        let addr_b: SocketAddr = "127.0.0.1:4010".parse().unwrap();
        let addr_c: SocketAddr = "127.0.0.1:4011".parse().unwrap();
        let tr_a = LocalTransport::new(addr_a);
        let tr_b = LocalTransport::new(addr_b);
        let tr_c = LocalTransport::new(addr_c);

        tr_a.connect(tr_b.addr()).await;
        tr_a.connect(tr_c.addr()).await;

        assert_eq!(tr_a.peers.len(), 2);
        assert!(tr_a.peers.contains_key(&tr_b.peer_id()));
        assert!(tr_a.peers.contains_key(&tr_c.peer_id()));

        // B and C should only have A as peer
        assert_eq!(tr_b.peers.len(), 1);
        assert_eq!(tr_c.peers.len(), 1);
    }

    #[tokio::test]
    async fn broadcast_excludes_sender() {
        let tr_a = LocalTransport::new("127.0.0.1:4012".parse().unwrap());
        let tr_b = LocalTransport::new("127.0.0.1:4013".parse().unwrap());
        let tr_c = LocalTransport::new("127.0.0.1:4014".parse().unwrap());

        tr_a.connect(tr_b.addr()).await;
        tr_b.connect(tr_c.addr()).await;

        let mut rx_a = tr_a.consume().await;
        let mut rx_c = tr_c.consume().await;

        let payload = Bytes::new("Broadcast from B");
        tr_b.broadcast(tr_b.peer_id(), payload.clone())
            .await
            .unwrap();

        // A and C should receive the message
        let received_a = rx_a.recv().await.unwrap();
        assert_eq!(received_a.payload, payload.clone());

        let received_c = rx_c.recv().await.unwrap();
        assert_eq!(received_c.payload, payload.clone());
    }

    #[tokio::test]
    async fn send_to_nonexistent_peer_fails() {
        let tr_a = LocalTransport::new("127.0.0.1:4015".parse().unwrap());
        let mut hasher = Hash::sha3();
        hasher.update(b"missing peer");
        let missing_peer = hasher.finalize();

        let result = tr_a
            .send_message(missing_peer, tr_a.peer_id(), Bytes::from("test"))
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn chain_topology_message_passing() {
        // A -> B -> C topology
        let addr_a: SocketAddr = "127.0.0.1:4016".parse().unwrap();
        let addr_b: SocketAddr = "127.0.0.1:4017".parse().unwrap();
        let addr_c: SocketAddr = "127.0.0.1:4018".parse().unwrap();
        let tr_a = LocalTransport::new(addr_a);
        let tr_b = LocalTransport::new(addr_b);
        let tr_c = LocalTransport::new(addr_c);

        tr_a.connect(tr_b.addr()).await;
        tr_b.connect(tr_c.addr()).await;

        // A sends to B
        tr_a.send_message(tr_b.peer_id(), tr_a.peer_id(), Bytes::from("from A"))
            .await
            .unwrap();

        // A cannot send directly to C (not connected)
        let result = tr_a
            .send_message(tr_c.peer_id(), tr_a.peer_id(), Bytes::from("test"))
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn peer_ids_returns_empty_when_no_connections() {
        let tr = LocalTransport::new("127.0.0.1:4019".parse().unwrap());
        assert!(tr.peer_ids().is_empty());
    }

    #[tokio::test]
    async fn peer_ids_returns_connected_peers() {
        let addr_a: SocketAddr = "127.0.0.1:4020".parse().unwrap();
        let addr_b: SocketAddr = "127.0.0.1:4021".parse().unwrap();
        let addr_c: SocketAddr = "127.0.0.1:4022".parse().unwrap();
        let tr_a = LocalTransport::new(addr_a);
        let tr_b = LocalTransport::new(addr_b);
        let tr_c = LocalTransport::new(addr_c);

        tr_a.connect(tr_b.addr()).await;
        tr_a.connect(tr_c.addr()).await;

        let peers = tr_a.peer_ids();
        assert_eq!(peers.len(), 2);
        assert!(peers.contains(&tr_b.peer_id()));
        assert!(peers.contains(&tr_c.peer_id()));
    }

    #[tokio::test]
    async fn peer_ids_reflects_bidirectional_connections() {
        let addr_a: SocketAddr = "127.0.0.1:4023".parse().unwrap();
        let addr_b: SocketAddr = "127.0.0.1:4024".parse().unwrap();
        let tr_a = LocalTransport::new(addr_a);
        let tr_b = LocalTransport::new(addr_b);

        tr_a.connect(tr_b.addr()).await;

        let a_peers = tr_a.peer_ids();
        let b_peers = tr_b.peer_ids();

        assert_eq!(a_peers.len(), 1);
        assert_eq!(a_peers[0], tr_b.peer_id());

        assert_eq!(b_peers.len(), 1);
        assert_eq!(b_peers[0], tr_a.peer_id());
    }

    #[tokio::test]
    async fn addr_returns_correct_multiaddr() {
        let addr: SocketAddr = "127.0.0.1:4025".parse().unwrap();
        let tr = LocalTransport::new(addr);
        let multiaddr = tr.addr();
        assert_eq!(multiaddr_to_socket_addr(&multiaddr), Some(addr));
    }
}
