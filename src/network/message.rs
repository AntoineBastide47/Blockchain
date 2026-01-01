//! Protocol messages for node synchronization.
//!
//! Defines request/response message types for status exchange and block retrieval
//! during peer synchronization.

use crate::core::block::Block;
use crate::utils::log::LogId;
use blockchain_derive::BinaryCodec;

/// Response message containing a node's current chain status.
///
/// Sent in response to a `GetStatus` request to inform peers
/// of this node's protocol version and chain height.
#[derive(BinaryCodec, Debug)]
pub struct SendStatusMessage {
    /// Node identifier.
    pub id: LogId,
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
    fn send_status_message_roundtrip() {
        let msg = SendStatusMessage {
            id: LogId::new("test-node"),
            version: 42,
            current_height: 1000,
        };

        let bytes = msg.to_bytes();
        let decoded = SendStatusMessage::from_bytes(&bytes).expect("decode failed");

        assert_eq!(decoded.id.as_str(), "test-node");
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
            data_hash: Hash::zero(),
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
