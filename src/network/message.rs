//! Protocol messages for node synchronization.
//!
//! Defines request/response message types for status exchange and block retrieval
//! during peer synchronization.

use crate::core::block::Block;
use crate::types::bytes::Bytes;
use blockchain_derive::BinaryCodec;

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

/// Response message containing a node's current chain status.
///
/// Sent in response to a `GetStatus` request to inform peers
/// of this node's protocol version and chain height.
#[derive(BinaryCodec, Debug)]
pub struct SendStatusMessage {
    /// Protocol version number.
    pub version: u32,
    /// Current blockchain height.
    pub current_height: u64,
}

/// Request message to retrieve a range of blocks from a peer.
#[derive(Debug, BinaryCodec)]
pub struct GetBlocksMessage {
    /// Starting block height (inclusive). When 0, starts from height 1.
    pub start: u64,
    /// Ending block height (inclusive). When 0, retrieves all blocks from start to tip.
    pub end: u64,
}

/// Response message containing requested blocks.
#[derive(Debug, BinaryCodec)]
pub struct SendBlocksMessage {
    /// Blocks in ascending height order.
    pub blocks: Vec<Block>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::block::Header;
    use crate::crypto::key_pair::PrivateKey;
    use crate::types::encoding::{Decode, Encode};
    use crate::types::hash::Hash;

    const TEST_CHAIN_ID: u64 = 10;

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
    fn send_status_message_roundtrip() {
        let msg = SendStatusMessage {
            version: 42,
            current_height: 1000,
        };

        let bytes = msg.to_bytes();
        let decoded = SendStatusMessage::from_bytes(&bytes).expect("decode failed");

        assert_eq!(decoded.version, 42);
        assert_eq!(decoded.current_height, 1000);
    }

    #[test]
    fn get_blocks_message_roundtrip() {
        let msg = GetBlocksMessage { start: 5, end: 15 };

        let bytes = msg.to_bytes();
        let decoded = GetBlocksMessage::from_bytes(&bytes).expect("decode failed");

        assert_eq!(decoded.start, 5);
        assert_eq!(decoded.end, 15);
    }

    #[test]
    fn get_blocks_message_zero_end() {
        let msg = GetBlocksMessage { start: 1, end: 0 };

        let bytes = msg.to_bytes();
        let decoded = GetBlocksMessage::from_bytes(&bytes).expect("decode failed");

        assert_eq!(decoded.start, 1);
        assert_eq!(decoded.end, 0);
    }

    #[test]
    fn send_blocks_message_empty() {
        let msg = SendBlocksMessage { blocks: vec![] };

        let bytes = msg.to_bytes();
        let decoded = SendBlocksMessage::from_bytes(&bytes).expect("decode failed");

        assert!(decoded.blocks.is_empty());
    }

    fn create_test_block(height: u64, previous: Hash) -> Block {
        let header = Header {
            version: 1,
            height,
            timestamp: 1234567890,
            previous_block: previous,
            merkle_root: Hash::zero(),
            state_root: Hash::zero(),
        };
        let block = Block::new(header, PrivateKey::new(), vec![], TEST_CHAIN_ID);
        (*block).clone()
    }

    #[test]
    fn send_blocks_message_with_blocks() {
        let block1 = create_test_block(1, Hash::zero());
        let block2 = create_test_block(2, block1.header_hash(TEST_CHAIN_ID));

        let msg = SendBlocksMessage {
            blocks: vec![block1.clone(), block2.clone()],
        };

        let bytes = msg.to_bytes();
        let decoded = SendBlocksMessage::from_bytes(&bytes).expect("decode failed");

        assert_eq!(decoded.blocks.len(), 2);
        assert_eq!(
            decoded.blocks[0].header_hash(TEST_CHAIN_ID),
            block1.header_hash(TEST_CHAIN_ID)
        );
        assert_eq!(
            decoded.blocks[1].header_hash(TEST_CHAIN_ID),
            block2.header_hash(TEST_CHAIN_ID)
        );
    }
}
