//! Core transport abstractions for network communication.
//!
//! Defines the Transport trait and RPC message structure used by all
//! network implementations to send and receive data between nodes.

use bytes::Bytes;
use std::sync::Arc;
use tokio::sync::mpsc::Receiver;

/// Errors that can occur during transport operations.
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    /// Peer with the specified address was not found.
    #[error("peer not found: {0}")]
    PeerNotFound(String),

    /// Failed to send message to the specified address.
    #[error("failed to send message to {0}")]
    SendFailed(String),
}

/// Remote procedure call message containing sender address and payload data.
pub struct Rpc {
    /// Address of the sender.
    pub from: Arc<str>,
    /// Raw message payload.
    pub payload: Bytes,
}

/// Async transport layer for network communication between nodes.
///
/// Implementors provide the underlying mechanism for sending and receiving messages
/// between network peers in a blockchain network.
#[async_trait::async_trait]
pub trait Transport: Send + Sync {
    /// Returns a receiver for incoming RPC messages.
    ///
    /// Messages can be consumed from the receiver to process incoming network traffic.
    async fn consume(&self) -> Receiver<Rpc>;

    /// Sends a message to a specific address.
    ///
    /// # Arguments
    /// * `to` - Destination address
    /// * `payload` - Message data to send
    ///
    /// # Errors
    /// Returns `TransportError::PeerNotFound` if the peer is not in the routing table.
    /// Returns `TransportError::SendFailed` if the message cannot be sent.
    async fn send_message(&self, to: Arc<str>, payload: Bytes) -> Result<(), TransportError>;

    /// Returns the local address of this transport.
    fn addr(&self) -> Arc<str>;
}
