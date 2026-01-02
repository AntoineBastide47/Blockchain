//! Core transport abstractions for network communication.
//!
//! Defines the Transport trait and RPC message structure used by all
//! network implementations to send and receive data between nodes.

use crate::network::rpc::Rpc;
use crate::types::bytes::Bytes;
use crate::types::encoding::{Decode, DecodeError, Encode, EncodeSink};
use crate::types::wrapper_types::BoxFuture;
use blockchain_derive::Error;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc::{Receiver, Sender};

/// Implements the `consume` method for transports with a standard rx field.
#[macro_export]
macro_rules! impl_transport_consume {
    () => {
        fn consume(self: &Arc<Self>) -> BoxFuture<'static, Receiver<Rpc>> {
            let rx = self.rx.clone();
            Box::pin(async move {
                let mut guard = rx.lock().await;
                guard.take().expect("receiver already taken")
            })
        }
    };
}

/// Spawns a forwarding task that consumes RPCs and sends them to the provided channel.
pub fn spawn_rpc_forwarder<T: Transport>(transport: Arc<T>, sx: Sender<Rpc>) {
    tokio::spawn(async move {
        let mut rx = transport.consume().await;
        while let Some(rpc) = rx.recv().await {
            let _ = sx.send(rpc).await;
        }
    });
}

/// Errors that can occur during transport operations.
#[derive(Debug, Error)]
pub enum TransportError {
    /// Peer with the specified address was not found.
    #[error("peer not found: {0}")]
    PeerNotFound(SocketAddr),
    /// Failed to send message to the specified address.
    #[error("failed to send message to {0}")]
    SendFailed(SocketAddr),
    /// Failed to send message to the specified address.
    #[error("failed to broadcast: {0}")]
    BroadcastFailed(String),
}

impl Encode for SocketAddr {
    fn encode<S: EncodeSink>(&self, out: &mut S) {
        self.to_string().encode(out);
    }
}

impl Decode for SocketAddr {
    fn decode(input: &mut &[u8]) -> Result<Self, DecodeError> {
        let address = String::decode(input)?;
        address
            .parse()
            .map_err(|_| DecodeError::InvalidIpAddr(address))
    }
}

/// Async transport layer for network communication between nodes.
///
/// Implementors provide the underlying mechanism for sending and receiving messages
/// between network peers in a blockchain network.
pub trait Transport: Send + Sync + 'static {
    /// Establishes a bidirectional connection with another in-process transport.
    ///
    /// This is a test-only convenience for connecting two transports running
    /// in the same process. Production code should use address-based connection.
    fn connect(self: &Arc<Self>, other: &Arc<Self>);

    /// Async version of connect that waits for connection to be established.
    fn connect_async(self: &Arc<Self>, other: &Arc<Self>) -> BoxFuture<'static, bool> {
        self.connect(other);
        Box::pin(async { true })
    }

    /// Starts the transport, enabling it to accept connections and forward RPCs.
    fn start(self: &Arc<Self>, sx: Sender<Rpc>);

    /// Returns a receiver for incoming RPC messages.
    fn consume(self: &Arc<Self>) -> BoxFuture<'static, Receiver<Rpc>>;

    /// Sends a message to a specific address.
    ///
    /// # Errors
    /// Returns `TransportError::PeerNotFound` if the peer is not connected.
    /// Returns `TransportError::SendFailed` if the send operation fails.
    fn send_message(
        self: &Arc<Self>,
        to: SocketAddr,
        payload: Bytes,
    ) -> BoxFuture<'static, Result<(), TransportError>>;

    /// Broadcasts data to all connected peers except the sender.
    ///
    /// # Errors
    /// Returns a `TransportError` if any peer transmission fails.
    fn broadcast(
        self: &Arc<Self>,
        from: SocketAddr,
        data: Bytes,
    ) -> BoxFuture<'static, Result<(), TransportError>> {
        let peers = self.peer_addrs();
        let this = self.clone();

        Box::pin(async move {
            let mut errors = Vec::new();
            for addr in peers.iter() {
                if from == *addr {
                    continue;
                }

                if let Err(e) = this.send_message(*addr, data.clone()).await {
                    errors.push(e.to_string());
                }
            }
            if errors.is_empty() {
                Ok(())
            } else {
                Err(TransportError::BroadcastFailed(errors.join("; ")))
            }
        })
    }

    /// Returns the local address of this transport.
    fn addr(self: &Arc<Self>) -> SocketAddr;

    /// Returns addresses of all connected peers.
    fn peer_addrs(self: &Arc<Self>) -> Vec<SocketAddr>;
}
