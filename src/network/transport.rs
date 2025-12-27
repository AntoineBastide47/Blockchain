//! Core transport abstractions for network communication.
//!
//! Defines the Transport trait and RPC message structure used by all
//! network implementations to send and receive data between nodes.

use crate::network::rpc::Rpc;
use crate::types::bytes::Bytes;
use crate::types::wrapper_types::BoxFuture;
use std::sync::Arc;
use tokio::sync::mpsc::Receiver;

/// Errors that can occur during transport operations.
#[derive(Debug, blockchain_derive::Error)]
pub enum TransportError {
    /// Peer with the specified address was not found.
    #[error("peer not found: {0}")]
    PeerNotFound(String),

    /// Failed to send message to the specified address.
    #[error("failed to send message to {0}")]
    SendFailed(String),

    /// Failed to send message to the specified address.
    #[error("failed to broadcast: {0}")]
    BroadcastFailed(String),
}

/// Async transport layer for network communication between nodes.
///
/// Implementors provide the underlying mechanism for sending and receiving messages
/// between network peers in a blockchain network.
pub trait Transport: Send + Sync {
    /// Returns a receiver for incoming RPC messages.
    ///
    /// Messages can be consumed from the receiver to process incoming network traffic.
    fn consume(self: &Arc<Self>) -> BoxFuture<'static, Receiver<Rpc>>;

    /// Sends a message to a specific address.
    ///
    /// # Arguments
    /// * `to` - Destination address
    /// * `payload` - Message data to send
    ///
    /// # Errors
    /// Returns `TransportError::PeerNotFound` if the peer is not in the routing table.
    /// Returns `TransportError::SendFailed` if the message cannot be sent.
    fn send_message(
        self: &Arc<Self>,
        to: String,
        payload: Bytes,
    ) -> BoxFuture<'static, Result<(), TransportError>>;

    /// Broadcasts data to all connected peers except the sender.
    ///
    /// # Arguments
    /// * `from` - Address of the sender to exclude from broadcast
    /// * `data` - Message data to broadcast
    ///
    /// # Errors
    /// Returns an error string if any peer transmission fails.
    fn broadcast(
        self: &Arc<Self>,
        from: String,
        data: Bytes,
    ) -> BoxFuture<'static, Result<(), TransportError>>;

    /// Returns the local address of this transport.
    fn addr(self: &Arc<Self>) -> String;
}
