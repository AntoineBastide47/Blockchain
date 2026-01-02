//! RPC message types and traits for network communication.
//!
//! Defines the protocol-level message structures exchanged between nodes,
//! including message framing, type discrimination, and handler traits.

use crate::core::block::Block;
use crate::core::transaction::Transaction;
use crate::network::message::{GetBlocksMessage, SendBlocksMessage, SendStatusMessage};
use crate::types::bytes::Bytes;
use crate::types::wrapper_types::BoxFuture;
use blockchain_derive::{BinaryCodec, Error};
use std::error::Error;
use std::fmt::Debug;
use std::net::SocketAddr;
use std::sync::Arc;

/// Remote procedure call message containing sender address and payload data.
#[derive(BinaryCodec)]
pub struct Rpc {
    /// Address of the sender.
    pub(crate) from: SocketAddr,
    /// Raw message payload.
    pub(crate) payload: Bytes,
}

impl Rpc {
    /// Creates a new RPC message from the given sender and payload.
    pub fn new(from: SocketAddr, payload: impl Into<Bytes>) -> Self {
        Self {
            from,
            payload: payload.into(),
        }
    }
}

/// Decoded payload variants after deserializing a protocol message.
#[derive(Debug)]
pub enum DecodedMessageData {
    /// A deserialized transaction.
    Transaction(Transaction),
    /// A deserialized block.
    Block(Block),
    /// Status request from a peer.
    GetStatus,
    /// Status response containing peer's chain info.
    SendStatus(SendStatusMessage),
    /// Block range request from a peer.
    GetBlocks(GetBlocksMessage),
    /// Block range response.
    SendBlocks(SendBlocksMessage),
}

/// A fully decoded RPC message with sender and typed payload.
#[derive(Debug)]
pub struct DecodedMessage {
    /// Address of the node that sent the message.
    pub from: SocketAddr,
    /// The decoded payload data.
    pub data: DecodedMessageData,
}

/// Errors that can occur while decoding RPC messages.
#[derive(Debug, Error)]
pub enum RpcError {
    #[error("failed to decode message from {from}: {details}")]
    Message { from: SocketAddr, details: String },
    #[error("failed to decode transaction: {0}")]
    Transaction(String),
    #[error("failed to decode block: {0}")]
    Block(String),
    #[error("failed to decode status: {0}")]
    Status(String),
}

/// Trait for processing decoded message payloads.
///
/// Implementors handle decoded RPC messages after deserialization.
pub trait RpcProcessor: Send + Sync {
    type Error: Debug + Error;
    /// Routes a decoded message to the appropriate type-specific handler.
    fn process_message(
        self: Arc<Self>,
        decoded: DecodedMessage,
    ) -> BoxFuture<'static, Result<(), Self::Error>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::message::{Message, MessageType};
    use crate::types::encoding::{Decode, Encode};

    #[test]
    fn rpc_serialization_roundtrip() {
        let addr: SocketAddr = "127.0.0.1:3000".parse().unwrap();
        let payload = vec![1, 2, 3, 4, 5];
        let rpc = Rpc::new(addr, payload.clone());

        let encoded = rpc.to_bytes();
        let decoded = Rpc::from_bytes(encoded.as_slice()).expect("deserialization failed");

        assert_eq!(decoded.from, addr);
        assert_eq!(decoded.payload.as_ref(), payload.as_slice());
    }

    #[test]
    fn rpc_roundtrip_block_payload() {
        let addr: SocketAddr = "127.0.0.1:3001".parse().unwrap();
        let payload = Bytes::new(vec![9u8; 16]);
        let msg = Message::new(MessageType::Block, payload.clone());
        let rpc = Rpc::new(addr, msg.to_bytes());

        let encoded = rpc.to_bytes();
        let decoded = Rpc::from_bytes(encoded.as_slice()).expect("deserialization failed");

        assert_eq!(decoded.from, addr);

        let decoded_msg = Message::from_bytes(decoded.payload.as_slice()).expect("message decode");
        assert!(matches!(decoded_msg.header, MessageType::Block));
        assert_eq!(decoded_msg.data, payload);
    }
}
