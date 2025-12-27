//! RPC message types and traits for network communication.
//!
//! Defines the protocol-level message structures exchanged between nodes,
//! including message framing, type discrimination, and handler traits.

use crate::core::block::Block;
use crate::core::transaction::Transaction;
use crate::types::serializable_bytes::SerializableBytes;
use blockchain_derive::BinaryCodec;
use std::format;
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
    pub(crate) data: SerializableBytes,
}

impl Message {
    /// Creates a new message with the given type and payload.
    pub fn new(header: MessageType, data: impl Into<SerializableBytes>) -> Self {
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
    pub(crate) payload: SerializableBytes,
}

impl Rpc {
    /// Creates a new RPC message from the given sender and payload.
    pub fn new(from: impl Into<String>, payload: impl Into<SerializableBytes>) -> Self {
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
/// Provides handlers for each message type after deserialization.
#[async_trait::async_trait]
pub trait RpcProcessor: Send + Sync {
    /// Routes a decoded message to the appropriate type-specific handler.
    ///
    /// Dispatches to `process_transaction` or `process_block` based on the message payload.
    async fn process_message(self: Arc<Self>, decoded: DecodedMessage) -> Result<(), String>;

    /// Validates and adds a transaction to the pool, then broadcasts to peers.
    ///
    /// Skips duplicate transactions. Returns an error if verification fails.
    async fn process_transaction(
        self: Arc<Self>,
        from: String,
        transaction: Transaction,
    ) -> Result<(), String>;

    /// Validates and adds a block to the chain, then broadcasts to peers.
    ///
    /// Returns an error if the block fails validation or cannot be added.
    async fn process_block(self: Arc<Self>, from: String, block: Block) -> Result<(), String>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use borsh::BorshDeserialize;

    #[test]
    fn message_serialization_roundtrip() {
        let payload = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let msg = Message::new(MessageType::Transaction, payload.clone());

        let encoded = borsh::to_vec(&msg).expect("serialization failed");
        let decoded = Message::try_from_slice(&encoded).expect("deserialization failed");

        assert_eq!(decoded.data.as_ref(), payload.as_slice());
    }

    #[test]
    fn rpc_serialization_roundtrip() {
        let payload = vec![1, 2, 3, 4, 5];
        let rpc = Rpc::new("node_a", payload.clone());

        let encoded = borsh::to_vec(&rpc).expect("serialization failed");
        let decoded = Rpc::try_from_slice(&encoded).expect("deserialization failed");

        assert_eq!(decoded.from, "node_a");
        assert_eq!(decoded.payload.as_ref(), payload.as_slice());
    }

    #[test]
    fn message_type_discriminants() {
        let tx_msg = Message::new(MessageType::Transaction, vec![]);
        let block_msg = Message::new(MessageType::Block, vec![]);

        let tx_bytes = borsh::to_vec(&tx_msg).unwrap();
        let block_bytes = borsh::to_vec(&block_msg).unwrap();

        // First byte is the discriminant
        assert_eq!(tx_bytes[0], 0, "Transaction discriminant should be 0");
        assert_eq!(block_bytes[0], 1, "Block discriminant should be 1");
    }
}
