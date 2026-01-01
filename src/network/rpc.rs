//! RPC message types and traits for network communication.
//!
//! Defines the protocol-level message structures exchanged between nodes,
//! including message framing, type discrimination, and handler traits.

use crate::core::block::Block;
use crate::core::transaction::Transaction;
use crate::network::message::{GetBlocksMessage, SendBlocksMessage, SendStatusMessage};
use crate::types::bytes::Bytes;
use crate::types::wrapper_types::BoxFuture;
use blockchain_derive::BinaryCodec;
use std::error::Error;
use std::fmt::Debug;
use std::sync::Arc;

/// Discriminant for message payload types.
///
/// Used as a header to identify how to deserialize the message body.
#[derive(BinaryCodec)]
pub enum MessageType {
    /// Payload contains a serialized transaction.
    Transaction,
    /// Payload contains a serialized block.
    Block,
    /// Request for peer's chain status (empty payload).
    GetStatus,
    /// Response containing peer's chain status.
    SendStatus,
    /// Request for a range of blocks.
    GetBlocks,
    /// Response containing requested blocks.
    SendBlocks,
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
    pub from: String,
    /// The decoded payload data.
    pub data: DecodedMessageData,
}

/// Errors that can occur while decoding RPC messages.
#[derive(Debug, blockchain_derive::Error)]
pub enum RpcError {
    #[error("failed to decode message from {from}: {details}")]
    Message { from: String, details: String },

    #[error("failed to decode transaction: {0}")]
    Transaction(String),

    #[error("failed to decode block: {0}")]
    Block(String),

    #[error("failed to decode status: {0}")]
    Status(String),
}

/// Function signature for custom RPC handlers.
///
/// Takes a raw RPC message and returns a decoded message or a decoding error.
pub type HandleRpcFn = fn(Rpc) -> Result<DecodedMessage, RpcError>;

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
    fn block_message_roundtrip() {
        let payload = Bytes::new(vec![1u8, 2, 3, 4, 5]);
        let msg = Message::new(MessageType::Block, payload.clone());

        let encoded = msg.to_bytes();
        let decoded = Message::from_bytes(encoded.as_slice()).expect("deserialization failed");

        assert!(matches!(decoded.header, MessageType::Block));
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
    fn rpc_roundtrip_block_payload() {
        let payload = Bytes::new(vec![9u8; 16]);
        let msg = Message::new(MessageType::Block, payload.clone());
        let rpc = Rpc::new("node_b", msg.to_bytes());

        let encoded = rpc.to_bytes();
        let decoded = Rpc::from_bytes(encoded.as_slice()).expect("deserialization failed");

        assert_eq!(decoded.from, "node_b");

        let decoded_msg = Message::from_bytes(decoded.payload.as_slice()).expect("message decode");
        assert!(matches!(decoded_msg.header, MessageType::Block));
        assert_eq!(decoded_msg.data, payload);
    }

    #[test]
    fn message_type_discriminants() {
        let tx_msg = Message::new(MessageType::Transaction, vec![]);
        let block_msg = Message::new(MessageType::Block, vec![]);
        let get_status_msg = Message::new(MessageType::GetStatus, vec![]);
        let send_status_msg = Message::new(MessageType::SendStatus, vec![]);
        let get_blocks_msg = Message::new(MessageType::GetBlocks, vec![]);
        let send_blocks_msg = Message::new(MessageType::SendBlocks, vec![]);

        let tx_bytes = tx_msg.to_bytes();
        let block_bytes = block_msg.to_bytes();
        let get_status_bytes = get_status_msg.to_bytes();
        let send_status_bytes = send_status_msg.to_bytes();
        let get_blocks_bytes = get_blocks_msg.to_bytes();
        let send_blocks_bytes = send_blocks_msg.to_bytes();

        // First byte is the discriminant
        assert_eq!(tx_bytes[0], 0, "Transaction discriminant should be 0");
        assert_eq!(block_bytes[0], 1, "Block discriminant should be 1");
        assert_eq!(get_status_bytes[0], 2, "GetStatus discriminant should be 2");
        assert_eq!(
            send_status_bytes[0], 3,
            "SendStatus discriminant should be 3"
        );
        assert_eq!(get_blocks_bytes[0], 4, "GetBlocks discriminant should be 4");
        assert_eq!(
            send_blocks_bytes[0], 5,
            "SendBlocks discriminant should be 5"
        );
    }

    #[test]
    fn get_status_message_roundtrip() {
        let msg = Message::new(MessageType::GetStatus, vec![0x08]);
        let encoded = msg.to_bytes();
        let decoded = Message::from_bytes(&encoded).expect("decode failed");

        assert!(matches!(decoded.header, MessageType::GetStatus));
        assert_eq!(decoded.data.as_ref(), &[0x08]);
    }

    #[test]
    fn send_status_message_roundtrip() {
        let payload = vec![1, 2, 3, 4, 5];
        let msg = Message::new(MessageType::SendStatus, payload.clone());
        let encoded = msg.to_bytes();
        let decoded = Message::from_bytes(&encoded).expect("decode failed");

        assert!(matches!(decoded.header, MessageType::SendStatus));
        assert_eq!(decoded.data.as_ref(), payload.as_slice());
    }

    #[test]
    fn get_blocks_message_roundtrip() {
        let payload = vec![10, 20, 30];
        let msg = Message::new(MessageType::GetBlocks, payload.clone());
        let encoded = msg.to_bytes();
        let decoded = Message::from_bytes(&encoded).expect("decode failed");

        assert!(matches!(decoded.header, MessageType::GetBlocks));
        assert_eq!(decoded.data.as_ref(), payload.as_slice());
    }

    #[test]
    fn send_blocks_message_roundtrip() {
        let payload = vec![100, 200];
        let msg = Message::new(MessageType::SendBlocks, payload.clone());
        let encoded = msg.to_bytes();
        let decoded = Message::from_bytes(&encoded).expect("decode failed");

        assert!(matches!(decoded.header, MessageType::SendBlocks));
        assert_eq!(decoded.data.as_ref(), payload.as_slice());
    }
}
