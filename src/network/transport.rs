//! Core transport abstractions for network communication.
//!
//! Defines the Transport trait and RPC message structure used by all
//! network implementations to send and receive data between nodes.

use crate::network::rpc::Rpc;
use crate::types::bytes::Bytes;
use crate::types::hash::Hash;
use crate::types::wrapper_types::BoxFuture;
use blockchain_derive::Error;
pub use libp2p::Multiaddr;
use std::sync::Arc;
use tokio::sync::mpsc::{Receiver, Sender};

/// Stable peer identifier used across transports.
pub type PeerId = Hash;

/// Implements the `consume` method for transports with a standard rx field.
#[macro_export]
macro_rules! impl_transport_consume {
    () => {
        fn consume(self: &Arc<Self>) -> BoxFuture<Receiver<Rpc>> {
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
    /// Peer with the specified identifier was not found.
    #[error("peer not found: {0}")]
    PeerNotFound(PeerId),
    /// Failed to send message to the specified peer.
    #[error("failed to send message to {0}")]
    SendFailed(PeerId),
    /// Failed to send message to the specified peers.
    #[error("failed to broadcast: {0}")]
    BroadcastFailed(String),
}

/// Async transport layer for network communication between nodes.
///
/// Implementors provide the underlying mechanism for sending and receiving messages
/// between network peers in a blockchain network.
pub trait Transport: Send + Sync + 'static {
    /// Initiates a connection to a peer at the given multiaddr.
    ///
    /// Returns the peer's identifier if connection was established successfully,
    /// None otherwise.
    fn connect(self: &Arc<Self>, addr: Multiaddr) -> BoxFuture<Option<PeerId>>;

    /// Starts the transport, enabling it to accept connections and forward RPCs.
    fn start(self: &Arc<Self>, sx: Sender<Rpc>);

    /// Returns a receiver for incoming RPC messages.
    fn consume(self: &Arc<Self>) -> BoxFuture<Receiver<Rpc>>;

    /// Resolves when the transport is ready to accept inbound connections.
    fn wait_until_listening(self: &Arc<Self>) -> BoxFuture<()>;

    /// Sends a message to a specific peer.
    ///
    /// The `origin` parameter specifies the original sender's peer ID, which is
    /// encoded in the wire format for proper broadcast loop prevention. When
    /// originating a message, pass `self.peer_id()`. When re-broadcasting, pass
    /// the original sender's ID from the received message.
    ///
    /// # Errors
    /// Returns `TransportError::PeerNotFound` if the peer is not connected.
    /// Returns `TransportError::SendFailed` if the send operation fails.
    fn send_message(
        self: &Arc<Self>,
        to: PeerId,
        origin: PeerId,
        payload: Bytes,
    ) -> BoxFuture<Result<(), TransportError>>;

    /// Broadcasts data to all connected peers except the original sender.
    ///
    /// The `origin` peer ID is both excluded from recipients and encoded in the
    /// wire format so downstream nodes can continue excluding it when re-broadcasting.
    ///
    /// # Errors
    /// Returns a `TransportError` if any peer transmission fails.
    fn broadcast(
        self: &Arc<Self>,
        origin: PeerId,
        data: Bytes,
    ) -> BoxFuture<Result<(), TransportError>> {
        let peers = self.peer_ids();
        let this = self.clone();

        Box::pin(async move {
            let mut errors = Vec::new();
            for peer in peers.iter() {
                if origin == *peer {
                    continue;
                }

                if let Err(e) = this.send_message(*peer, origin, data.clone()).await {
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

    /// Returns the stable peer identifier for this transport.
    fn peer_id(self: &Arc<Self>) -> PeerId;

    /// Returns peer identifiers of all connected peers.
    fn peer_ids(self: &Arc<Self>) -> Vec<PeerId>;

    /// Returns the local listen address of this transport.
    #[cfg(test)]
    fn addr(self: &Arc<Self>) -> Multiaddr;

    /// Disconnects from all connected peers.
    fn stop(self: &Arc<Self>) -> BoxFuture<()>;
}
