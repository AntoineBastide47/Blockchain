//! RPC message types and traits for network communication.
//!
//! Defines the protocol-level message structures exchanged between nodes,
//! including message framing, type discrimination, and handler traits.

use crate::core::block::Block;
use crate::core::transaction::Transaction;
use crate::types::bytes::Bytes;
use crate::types::wrapper_types::BoxFuture;
use blockchain_derive::BinaryCodec;
use std::sync::Arc;

/// Discriminant for message payload types.
///
/// Used as a header to identify how to deserialize the message body.
#[derive(BinaryCodec)]
pub enum MessageType {
    /// Payload contains a serialized transaction.
    Transaction = 0,
    /// Payload contains a serialized block.
    Block,
}

/// Framed message with type header and serialized payload.
#[derive(BinaryCodec)]
pub struct Message {
    /// Type discriminant for payload deserialization.
    pub(crate) header: MessageType,
    /// Serialized payload data.
    pub(crate) data: Bytes,
}

impl Message {
    /// Creates a new message with the given type and payload.
    pub fn new(header: MessageType, data: impl Into<Bytes>) -> Self {
        Self {
            header,
            data: data.into(),
        }
    }
}

/// Remote procedure call message containing sender address and payload data.
#[derive(BinaryCodec)]
pub struct Rpc {
    /// Address of the sender.
    pub(crate) from: String,
    /// Raw message payload.
    pub(crate) payload: Bytes,
}

impl Rpc {
    /// Creates a new RPC message from the given sender and payload.
    pub fn new(from: impl Into<String>, payload: impl Into<Bytes>) -> Self {
        Self {
            from: from.into(),
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
}

/// A fully decoded RPC message with sender and typed payload.
#[derive(Debug)]
pub struct DecodedMessage {
    /// Address of the node that sent the message.
    pub from: String,
    /// The decoded payload data.
    pub data: DecodedMessageData,
}

/// Function signature for custom RPC handlers.
///
/// Takes a raw RPC message and returns a decoded message or an error string.
pub type HandleRpcFn = fn(Rpc) -> Result<DecodedMessage, String>;

/// Trait for processing decoded message payloads.
///
/// Implementors handle decoded RPC messages after deserialization.
pub trait RpcProcessor: Send + Sync {
    /// Routes a decoded message to the appropriate type-specific handler.
    fn process_message(
        self: Arc<Self>,
        decoded: DecodedMessage,
    ) -> BoxFuture<'static, Result<(), String>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::encoding::{Decode, Encode};

    #[test]
    fn message_serialization_roundtrip() {
        let payload = Bytes::new(vec![0xDE, 0xAD, 0xBE, 0xEF]);
        let msg = Message::new(MessageType::Transaction, payload.clone());

        let encoded = msg.to_bytes();
        let decoded = Message::from_bytes(encoded.as_slice()).expect("deserialization failed");

        assert_eq!(decoded.data, payload);
    }

    #[test]
    fn rpc_serialization_roundtrip() {
        let payload = vec![1, 2, 3, 4, 5];
        let rpc = Rpc::new("node_a", payload.clone());

        let encoded = rpc.to_bytes();
        let decoded = Rpc::from_bytes(encoded.as_slice()).expect("deserialization failed");

        assert_eq!(decoded.from, "node_a");
        assert_eq!(decoded.payload.as_ref(), payload.as_slice());
    }

    #[test]
    fn message_type_discriminants() {
        let tx_msg = Message::new(MessageType::Transaction, vec![]);
        let block_msg = Message::new(MessageType::Block, vec![]);

        let tx_bytes = tx_msg.to_bytes();
        let block_bytes = block_msg.to_bytes();

        // First byte is the discriminant
        assert_eq!(tx_bytes[0], 0, "Transaction discriminant should be 0");
        assert_eq!(block_bytes[0], 1, "Block discriminant should be 1");
    }
}
