//! Protocol messages for node synchronization.
//!
//! Defines request/response message types for status exchange, header sync,
//! block retrieval, and state snapshot transfer during peer synchronization.

use crate::core::block::{Block, Header};
use crate::types::bytes::Bytes;
use crate::types::hash::Hash;
use blockchain_derive::BinaryCodec;

/// Sync protocol capability bitflags advertised via [`SendSyncStatusMessage`].
pub type SyncCapabilities = u64;
/// Supports locator-based header requests (`GetHeadersMessage`).
pub const SYNC_CAP_HEADER_LOCATORS: SyncCapabilities = 1 << 0;
/// Supports requesting block bodies by hash (`GetBlockBodiesMessage`).
pub const SYNC_CAP_BLOCK_BODIES_BY_HASH: SyncCapabilities = 1 << 1;

/// Discriminant for message payload types.
///
/// Used as a header to identify how to deserialize the message body.
#[derive(BinaryCodec)]
pub enum MessageType {
    /// Payload contains a serialized transaction.
    Transaction,
    /// Payload contains a serialized block.
    Block,
    /// Request for peer's sync status (empty payload).
    GetSyncStatus,
    /// Response containing peer's sync status with snapshot info.
    SendSyncStatus,
    /// Request for a range of headers.
    GetHeaders,
    /// Response containing requested headers.
    SendHeaders,
    /// Request for a range of blocks (bodies).
    GetBlocks,
    /// Response containing requested blocks.
    SendBlocks,
    /// Request for a state snapshot at a specific height.
    GetSnapshotState,
    /// Response containing a full state snapshot.
    SendSnapshotState,
    /// Request for block bodies by hash.
    GetBlockBodies,
    /// Response containing block bodies for requested hashes.
    SendBlockBodies,
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

/// Response message containing a node's current sync status.
///
/// Sent in response to a `GetSyncStatus` request to inform peers
/// of this node's chain state and available snapshots for sync.
#[derive(BinaryCodec, Debug)]
pub struct SendSyncStatusMessage {
    /// Protocol version number.
    pub version: u32,
    /// Genesis block hash (network compatibility check).
    pub genesis_hash: Hash,
    /// Deterministic hash of chain parameters.
    pub chain_params_hash: Hash,
    /// Current blockchain height (highest block).
    pub height: u64,
    /// Current tip hash.
    pub tip: Hash,
    /// Highest known header height (may exceed block height during header-first sync).
    pub best_header_height: u64,
    /// Hash of the best known header tip.
    pub best_header_tip: Hash,
    /// Highest finalized height (for PoS chains).
    pub finalized_height: u64,
    /// Hash of the finalized tip.
    pub finalized_tip: Hash,
    /// Available snapshot heights this peer can serve.
    pub snapshot_heights: Vec<u64>,
    /// Supported sync protocol capabilities.
    pub capabilities: SyncCapabilities,
}

/// Request message to retrieve headers using block locators.
#[derive(Debug, BinaryCodec)]
pub struct GetHeadersMessage {
    /// Locator hashes ordered newest -> oldest.
    pub locators: Vec<Hash>,
    /// Optional stop hash (all-zero hash means "no stop hash").
    pub stop_hash: Hash,
    /// Maximum headers to return (0 => responder default cap).
    pub limit: u64,
}

/// Response message containing requested headers.
#[derive(Debug, BinaryCodec)]
pub struct SendHeadersMessage {
    /// Headers in ascending height order.
    pub headers: Box<[Header]>,
}

/// Request message to retrieve a range of blocks from a peer.
#[derive(Debug, BinaryCodec)]
pub struct GetBlocksMessage {
    /// Starting block height (inclusive).
    pub start: u64,
    /// Ending block height (inclusive). When 0, retrieves to tip.
    pub end: u64,
}

/// Response message containing requested blocks.
#[derive(Debug, BinaryCodec)]
pub struct SendBlocksMessage {
    /// Blocks in ascending height order.
    pub blocks: Box<[Block]>,
}

/// Request message to retrieve block bodies by hash.
#[derive(Debug, BinaryCodec)]
pub struct GetBlockBodiesMessage {
    /// Requested block hashes.
    pub hashes: Box<[Hash]>,
}

/// Response message containing block bodies for requested hashes.
#[derive(Debug, BinaryCodec)]
pub struct SendBlockBodiesMessage {
    /// Resolved block bodies in request order.
    pub blocks: Box<[Block]>,
}

/// Request message to retrieve a state snapshot from a peer.
#[derive(Debug, BinaryCodec)]
pub struct GetSnapshotStateMessage {
    /// Block height for the requested snapshot.
    pub height: u64,
}

/// A single key-value entry in a state snapshot.
#[derive(Debug, Clone, BinaryCodec)]
pub struct SnapshotEntry {
    /// 32-byte state key (account address or storage slot).
    pub key: Hash,
    /// Serialized value (account data or storage value).
    pub value: Bytes,
}

/// Response message containing a full state snapshot.
///
/// Contains the block at the snapshot height plus all state entries,
/// allowing a node to bootstrap state without replaying history.
#[derive(Debug, BinaryCodec)]
pub struct SendSnapshotStateMessage {
    /// Block height of this snapshot.
    pub height: u64,
    /// Block at the snapshot height (for verification).
    pub block: Block,
    /// All state entries at this snapshot height.
    pub entries: Box<[SnapshotEntry]>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::encoding::{Decode, Encode};
    use crate::types::hash::Hash;
    use crate::utils::test_utils::utils::create_test_block;

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
        let get_sync_status_msg = Message::new(MessageType::GetSyncStatus, vec![]);
        let send_sync_status_msg = Message::new(MessageType::SendSyncStatus, vec![]);
        let get_headers_msg = Message::new(MessageType::GetHeaders, vec![]);
        let send_headers_msg = Message::new(MessageType::SendHeaders, vec![]);
        let get_blocks_msg = Message::new(MessageType::GetBlocks, vec![]);
        let send_blocks_msg = Message::new(MessageType::SendBlocks, vec![]);
        let get_snapshot_msg = Message::new(MessageType::GetSnapshotState, vec![]);
        let send_snapshot_msg = Message::new(MessageType::SendSnapshotState, vec![]);
        let get_block_bodies_msg = Message::new(MessageType::GetBlockBodies, vec![]);
        let send_block_bodies_msg = Message::new(MessageType::SendBlockBodies, vec![]);

        let tx_bytes = tx_msg.to_bytes();
        let block_bytes = block_msg.to_bytes();
        let get_sync_status_bytes = get_sync_status_msg.to_bytes();
        let send_sync_status_bytes = send_sync_status_msg.to_bytes();
        let get_headers_bytes = get_headers_msg.to_bytes();
        let send_headers_bytes = send_headers_msg.to_bytes();
        let get_blocks_bytes = get_blocks_msg.to_bytes();
        let send_blocks_bytes = send_blocks_msg.to_bytes();
        let get_snapshot_bytes = get_snapshot_msg.to_bytes();
        let send_snapshot_bytes = send_snapshot_msg.to_bytes();
        let get_block_bodies_bytes = get_block_bodies_msg.to_bytes();
        let send_block_bodies_bytes = send_block_bodies_msg.to_bytes();

        // First byte is the discriminant
        assert_eq!(tx_bytes[0], 0, "Transaction discriminant should be 0");
        assert_eq!(block_bytes[0], 1, "Block discriminant should be 1");
        assert_eq!(
            get_sync_status_bytes[0], 2,
            "GetSyncStatus discriminant should be 2"
        );
        assert_eq!(
            send_sync_status_bytes[0], 3,
            "SendSyncStatus discriminant should be 3"
        );
        assert_eq!(
            get_headers_bytes[0], 4,
            "GetHeaders discriminant should be 4"
        );
        assert_eq!(
            send_headers_bytes[0], 5,
            "SendHeaders discriminant should be 5"
        );
        assert_eq!(get_blocks_bytes[0], 6, "GetBlocks discriminant should be 6");
        assert_eq!(
            send_blocks_bytes[0], 7,
            "SendBlocks discriminant should be 7"
        );
        assert_eq!(
            get_snapshot_bytes[0], 8,
            "GetSnapshotState discriminant should be 8"
        );
        assert_eq!(
            send_snapshot_bytes[0], 9,
            "SendSnapshotState discriminant should be 9"
        );
        assert_eq!(
            get_block_bodies_bytes[0], 10,
            "GetBlockBodies discriminant should be 10"
        );
        assert_eq!(
            send_block_bodies_bytes[0], 11,
            "SendBlockBodies discriminant should be 11"
        );
    }

    #[test]
    fn send_sync_status_message_roundtrip() {
        let msg = SendSyncStatusMessage {
            version: 1,
            genesis_hash: Hash::from_slice(&[0x11u8; 32]).unwrap(),
            chain_params_hash: Hash::from_slice(&[0x22u8; 32]).unwrap(),
            height: 1000,
            tip: Hash::zero(),
            best_header_height: 1005,
            best_header_tip: Hash::from_slice(&[0x33u8; 32]).unwrap(),
            finalized_height: 990,
            finalized_tip: Hash::from_slice(&[0x44u8; 32]).unwrap(),
            snapshot_heights: vec![100, 200, 300],
            capabilities: SYNC_CAP_HEADER_LOCATORS | SYNC_CAP_BLOCK_BODIES_BY_HASH,
        };

        let bytes = msg.to_bytes();
        let decoded = SendSyncStatusMessage::from_bytes(&bytes).expect("decode failed");

        assert_eq!(decoded.version, 1);
        assert_eq!(
            decoded.genesis_hash,
            Hash::from_slice(&[0x11u8; 32]).unwrap()
        );
        assert_eq!(
            decoded.chain_params_hash,
            Hash::from_slice(&[0x22u8; 32]).unwrap()
        );
        assert_eq!(decoded.height, 1000);
        assert_eq!(decoded.tip, Hash::zero());
        assert_eq!(decoded.best_header_height, 1005);
        assert_eq!(
            decoded.best_header_tip,
            Hash::from_slice(&[0x33u8; 32]).unwrap()
        );
        assert_eq!(decoded.finalized_height, 990);
        assert_eq!(
            decoded.finalized_tip,
            Hash::from_slice(&[0x44u8; 32]).unwrap()
        );
        assert_eq!(decoded.snapshot_heights, vec![100, 200, 300]);
        assert_eq!(
            decoded.capabilities,
            SYNC_CAP_HEADER_LOCATORS | SYNC_CAP_BLOCK_BODIES_BY_HASH
        );
    }

    #[test]
    fn get_headers_message_roundtrip() {
        let msg = GetHeadersMessage {
            locators: vec![Hash::zero(), Hash::from_slice(&[1u8; 32]).unwrap()],
            stop_hash: Hash::from_slice(&[2u8; 32]).unwrap(),
            limit: 15,
        };

        let bytes = msg.to_bytes();
        let decoded = GetHeadersMessage::from_bytes(&bytes).expect("decode failed");

        assert_eq!(decoded.locators.len(), 2);
        assert_eq!(decoded.locators[0], Hash::zero());
        assert_eq!(decoded.locators[1], Hash::from_slice(&[1u8; 32]).unwrap());
        assert_eq!(decoded.stop_hash, Hash::from_slice(&[2u8; 32]).unwrap());
        assert_eq!(decoded.limit, 15);
    }

    #[test]
    fn send_headers_message_roundtrip() {
        let block1 = create_test_block(1, Hash::zero(), TEST_CHAIN_ID);
        let block2 = create_test_block(2, block1.header_hash(TEST_CHAIN_ID), TEST_CHAIN_ID);

        let msg = SendHeadersMessage {
            headers: vec![block1.header.clone(), block2.header.clone()].into_boxed_slice(),
        };

        let bytes = msg.to_bytes();
        let decoded = SendHeadersMessage::from_bytes(&bytes).expect("decode failed");

        assert_eq!(decoded.headers.len(), 2);
        assert_eq!(decoded.headers[0].height, 1);
        assert_eq!(decoded.headers[1].height, 2);
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
    fn get_block_bodies_message_roundtrip() {
        let msg = GetBlockBodiesMessage {
            hashes: vec![Hash::zero(), Hash::from_slice(&[7u8; 32]).unwrap()].into_boxed_slice(),
        };

        let bytes = msg.to_bytes();
        let decoded = GetBlockBodiesMessage::from_bytes(&bytes).expect("decode failed");

        assert_eq!(decoded.hashes.len(), 2);
        assert_eq!(decoded.hashes[0], Hash::zero());
        assert_eq!(decoded.hashes[1], Hash::from_slice(&[7u8; 32]).unwrap());
    }

    #[test]
    fn send_blocks_message_empty() {
        let msg = SendBlocksMessage {
            blocks: Box::new([]),
        };

        let bytes = msg.to_bytes();
        let decoded = SendBlocksMessage::from_bytes(&bytes).expect("decode failed");

        assert!(decoded.blocks.is_empty());
    }

    #[test]
    fn send_blocks_message_with_blocks() {
        let block1 = create_test_block(1, Hash::zero(), TEST_CHAIN_ID);
        let block2 = create_test_block(2, block1.header_hash(TEST_CHAIN_ID), TEST_CHAIN_ID);

        let msg = SendBlocksMessage {
            blocks: vec![block1.clone(), block2.clone()].into_boxed_slice(),
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

    #[test]
    fn send_block_bodies_message_with_blocks() {
        let block1 = create_test_block(1, Hash::zero(), TEST_CHAIN_ID);
        let block2 = create_test_block(2, block1.header_hash(TEST_CHAIN_ID), TEST_CHAIN_ID);

        let msg = SendBlockBodiesMessage {
            blocks: vec![block1.clone(), block2.clone()].into_boxed_slice(),
        };

        let bytes = msg.to_bytes();
        let decoded = SendBlockBodiesMessage::from_bytes(&bytes).expect("decode failed");

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

    #[test]
    fn get_snapshot_state_message_roundtrip() {
        let msg = GetSnapshotStateMessage { height: 100 };

        let bytes = msg.to_bytes();
        let decoded = GetSnapshotStateMessage::from_bytes(&bytes).expect("decode failed");

        assert_eq!(decoded.height, 100);
    }

    #[test]
    fn snapshot_entry_roundtrip() {
        let entry = SnapshotEntry {
            key: Hash::zero(),
            value: Bytes::new(vec![1, 2, 3, 4]),
        };

        let bytes = entry.to_bytes();
        let decoded = SnapshotEntry::from_bytes(&bytes).expect("decode failed");

        assert_eq!(decoded.key, Hash::zero());
        assert_eq!(decoded.value.as_ref(), &[1, 2, 3, 4]);
    }

    #[test]
    fn send_snapshot_state_message_roundtrip() {
        let block = create_test_block(10, Hash::zero(), TEST_CHAIN_ID);
        let entries = vec![
            SnapshotEntry {
                key: Hash::zero(),
                value: Bytes::new(vec![1, 2, 3]),
            },
            SnapshotEntry {
                key: Hash::from_slice(&[1u8; 32]).unwrap(),
                value: Bytes::new(vec![4, 5, 6]),
            },
        ];

        let msg = SendSnapshotStateMessage {
            height: 10,
            block: block.clone(),
            entries: entries.into_boxed_slice(),
        };

        let bytes = msg.to_bytes();
        let decoded = SendSnapshotStateMessage::from_bytes(&bytes).expect("decode failed");

        assert_eq!(decoded.height, 10);
        assert_eq!(
            decoded.block.header_hash(TEST_CHAIN_ID),
            block.header_hash(TEST_CHAIN_ID)
        );
        assert_eq!(decoded.entries.len(), 2);
    }

    #[test]
    fn send_snapshot_state_message_empty_entries() {
        let block = create_test_block(0, Hash::zero(), TEST_CHAIN_ID);
        let msg = SendSnapshotStateMessage {
            height: 0,
            block,
            entries: Box::new([]),
        };

        let bytes = msg.to_bytes();
        let decoded = SendSnapshotStateMessage::from_bytes(&bytes).expect("decode failed");

        assert_eq!(decoded.height, 0);
        assert!(decoded.entries.is_empty());
    }
}
