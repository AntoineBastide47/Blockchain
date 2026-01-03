//! RPC message types and traits for network communication.
//!
//! Defines the protocol-level message structures exchanged between nodes,
//! including message framing, type discrimination, and handler traits.

use crate::core::block::Block;
use crate::core::transaction::Transaction;
use crate::network::message::{GetBlocksMessage, SendBlocksMessage, SendStatusMessage};
use crate::network::tcp_transport::{decode_socket_addr, encode_socket_addr};
use crate::types::bytes::Bytes;
use crate::types::encoding::{Decode, DecodeError, Encode, EncodeSink};
use crate::types::hash::Hash;
use crate::types::wrapper_types::BoxFuture;
use blockchain_derive::Error;
use std::error::Error;
use std::fmt::Debug;
use std::net::SocketAddr;
use std::sync::Arc;

/// Wire-format RPC message for network serialization.
///
/// Contains only the sender's socket address and payload bytes. Unlike [`Rpc`],
/// this does not include the authenticated peer ID since that information is
/// added after the Noise handshake verifies the sender's identity.
pub struct RawRpc {
    /// Listen address of the sender.
    pub(crate) from: SocketAddr,
    /// Raw message payload.
    pub(crate) payload: Bytes,
}

impl Encode for RawRpc {
    fn encode<S: EncodeSink>(&self, out: &mut S) {
        encode_socket_addr(self.from).encode(out);
        self.payload.encode(out);
    }
}

impl Decode for RawRpc {
    fn decode(input: &mut &[u8]) -> Result<Self, DecodeError> {
        let vec = Vec::<u8>::decode(input)?;
        Ok(RawRpc {
            from: decode_socket_addr(&vec)
                .map_err(|e| DecodeError::InvalidValueWithMessage(e.to_string()))?,
            payload: Bytes::decode(input)?,
        })
    }
}

/// Authenticated RPC message with verified sender identity.
///
/// Contains the cryptographic peer ID derived from the sender's Noise static key,
/// providing authenticated origin for all messages after handshake completion.
pub struct Rpc {
    /// Cryptographic identity of the sender, derived from their Noise static key.
    pub(crate) peer_id: Hash,
    /// Listen address of the sender.
    pub(crate) from: SocketAddr,
    /// Raw message payload.
    pub(crate) payload: Bytes,
}

impl Rpc {
    /// Creates a new RPC message from the given sender and payload.
    pub fn new(peer_id: Hash, from: SocketAddr, payload: impl Into<Bytes>) -> Self {
        Self {
            from,
            payload: payload.into(),
            peer_id,
        }
    }

    /// Converts to wire format for network transmission.
    ///
    /// Strips the peer ID since it's re-derived from the authenticated session.
    pub fn to_raw(&self) -> RawRpc {
        RawRpc {
            from: self.from,
            payload: self.payload.clone(),
        }
    }

    /// Reconstructs an authenticated RPC from wire format.
    ///
    /// The `peer_id` is provided by the transport layer after verifying the
    /// sender's identity through the Noise handshake.
    pub fn from_raw(raw: RawRpc, peer_id: Hash) -> Self {
        Self {
            peer_id,
            from: raw.from,
            payload: raw.payload,
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
    use crate::utils::test_utils::utils::test_rpc;

    #[test]
    fn rpc_serialization_roundtrip() {
        let addr: SocketAddr = "127.0.0.1:3000".parse().unwrap();
        let payload = vec![1, 2, 3, 4, 5];
        let rpc = test_rpc(addr, payload.clone());

        let encoded = rpc.to_raw().to_bytes();
        let decoded = RawRpc::from_bytes(encoded.as_slice()).expect("deserialization failed");

        assert_eq!(decoded.from, addr);
        assert_eq!(decoded.payload.as_ref(), payload.as_slice());
    }

    #[test]
    fn rpc_roundtrip_block_payload() {
        let addr: SocketAddr = "127.0.0.1:3001".parse().unwrap();
        let payload = Bytes::new(vec![9u8; 16]);
        let msg = Message::new(MessageType::Block, payload.clone());
        let rpc = test_rpc(addr, msg.to_bytes());

        let encoded = rpc.to_raw().to_bytes();
        let decoded = RawRpc::from_bytes(encoded.as_slice()).expect("deserialization failed");

        assert_eq!(decoded.from, addr);

        let decoded_msg = Message::from_bytes(decoded.payload.as_slice()).expect("message decode");
        assert!(matches!(decoded_msg.header, MessageType::Block));
        assert_eq!(decoded_msg.data, payload);
    }
}
