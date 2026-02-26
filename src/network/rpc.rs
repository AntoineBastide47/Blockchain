//! RPC message types and traits for network communication.
//!
//! Defines the protocol-level message structures exchanged between nodes,
//! including message framing, type discrimination, and handler traits.

use crate::core::block::Block;
use crate::core::transaction::Transaction;
use crate::network::message::{
    GetBlockBodiesMessage, GetBlocksMessage, GetHeadersMessage, GetSnapshotStateMessage,
    SendBlockBodiesMessage, SendBlocksMessage, SendHeadersMessage, SendSnapshotStateMessage,
    SendSyncStatusMessage,
};
use crate::types::bytes::Bytes;
use crate::types::hash::Hash;
use crate::types::wrapper_types::BoxFuture;
use blockchain_derive::{BinaryCodec, Error};
use std::error::Error;
use std::fmt::Debug;
use std::sync::Arc;

/// Wire-format RPC message for network serialization.
///
/// Contains only the raw payload bytes. Unlike [`Rpc`],
/// this does not include the authenticated peer ID since that information is
/// added by the transport layer after verifying the sender's identity.
#[derive(BinaryCodec)]
pub struct RawRpc {
    /// Raw message payload.
    pub(crate) payload: Bytes,
}

/// Authenticated RPC message with verified sender identity.
///
/// Contains the cryptographic peer ID derived from the transport layer's
/// authentication mechanism, providing authenticated origin for all messages.
pub struct Rpc {
    /// Cryptographic identity of the sender derived from the transport layer.
    pub(crate) peer_id: Hash,
    /// Raw message payload.
    pub(crate) payload: Bytes,
}

impl Rpc {
    /// Creates a new RPC message with authenticated sender identity.
    pub fn new(peer_id: Hash, payload: impl Into<Bytes>) -> Self {
        Self {
            payload: payload.into(),
            peer_id,
        }
    }

    /// Reconstructs an authenticated RPC from wire format.
    ///
    /// The `peer_id` is provided by the transport layer after verifying the
    /// sender's cryptographic identity (e.g., via Noise handshake or libp2p identify).
    pub fn from_raw(raw: RawRpc, peer_id: Hash) -> Self {
        Self {
            peer_id,
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
    /// Sync status request from a peer.
    GetSyncStatus,
    /// Sync status response containing peer's chain info and snapshots.
    SendSyncStatus(SendSyncStatusMessage),
    /// Header range request from a peer.
    GetHeaders(GetHeadersMessage),
    /// Header range response.
    SendHeaders(SendHeadersMessage),
    /// Block range request from a peer.
    GetBlocks(GetBlocksMessage),
    /// Block range response.
    SendBlocks(SendBlocksMessage),
    /// Block bodies-by-hash request from a peer.
    GetBlockBodies(GetBlockBodiesMessage),
    /// Block bodies-by-hash response.
    SendBlockBodies(SendBlockBodiesMessage),
    /// Snapshot state request from a peer.
    GetSnapshotState(GetSnapshotStateMessage),
    /// Snapshot state response containing full state.
    SendSnapshotState(SendSnapshotStateMessage),
}

/// A fully decoded RPC message with sender and typed payload.
#[derive(Debug)]
pub struct DecodedMessage {
    /// Cryptographic identity of the sender derived from the transport layer.
    ///
    /// For libp2p transport, this is a SHA3 hash of the peer's Ed25519 public key.
    /// Unlike `from` (which is a mutable IP address), this identity is stable
    /// and can be used for peer reputation, banning, and Sybil resistance.
    pub(crate) peer_id: Hash,
    /// The decoded payload data.
    pub(crate) data: DecodedMessageData,
}

/// Errors that can occur while decoding RPC messages.
#[derive(Debug, Error)]
pub enum RpcError {
    #[error("failed to decode message from {from}: {details}")]
    Message { from: Hash, details: String },
    #[error("failed to decode transaction: {0}")]
    Transaction(String),
    #[error("failed to decode block: {0}")]
    Block(String),
    #[error("failed to decode: {0}")]
    Decode(String),
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
    ) -> BoxFuture<Result<(), Self::Error>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::message::{Message, MessageType};
    use crate::types::encoding::{Decode, Encode};
    use crate::utils::test_utils::utils::test_rpc;
    use std::net::SocketAddr;

    /// Converts to wire format for network transmission.
    ///
    /// Strips the peer ID since it's re-derived from the authenticated session.
    pub fn to_raw(rpc: Rpc) -> RawRpc {
        RawRpc {
            payload: rpc.payload.clone(),
        }
    }

    #[test]
    fn rpc_serialization_roundtrip() {
        let addr: SocketAddr = "127.0.0.1:3000".parse().unwrap();
        let payload = vec![1, 2, 3, 4, 5];
        let rpc = test_rpc(addr, payload.clone());

        let encoded = to_raw(rpc).to_bytes();
        let decoded = RawRpc::from_bytes(encoded.as_slice()).expect("deserialization failed");

        assert_eq!(decoded.payload.as_ref(), payload.as_slice());
    }

    #[test]
    fn rpc_roundtrip_block_payload() {
        let addr: SocketAddr = "127.0.0.1:3001".parse().unwrap();
        let payload = Bytes::new(vec![9u8; 16]);
        let msg = Message::new(MessageType::Block, payload.clone());
        let rpc = test_rpc(addr, msg.to_bytes());

        let encoded = to_raw(rpc).to_bytes();
        let decoded = RawRpc::from_bytes(encoded.as_slice()).expect("deserialization failed");

        let decoded_msg = Message::from_bytes(decoded.payload.as_slice()).expect("message decode");
        assert!(matches!(decoded_msg.header, MessageType::Block));
        assert_eq!(decoded_msg.data, payload);
    }
}
