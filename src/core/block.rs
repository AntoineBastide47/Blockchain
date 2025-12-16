//! Blockchain block and header structures with memory-optimized layouts.

use crate::core::transaction::Transaction;
use crate::types::binary_codec::{BinaryCodec, BinaryCodecHash};
use crate::types::hash::Hash;
use borsh::{BorshDeserialize, BorshSerialize};
use std::io::{Read, Write};
use tokio::io;

/// Block header containing metadata and cryptographic commitments.
///
/// This type is `Copy` (88 bytes) for performance - headers are passed constantly
/// during validation, and stack allocation avoids heap allocations and pointer chasing.
///
/// # Binary Format
/// ```text
/// [version: u32][height: u32][timestamp: u64][nonce: u64]
/// [previous_block: [u8; 32]][merkle_root: [u8; 32]]
/// ```
#[derive(Copy, Clone, Debug, PartialEq, Eq, BinaryCodec)]
pub struct Header {
    /// Protocol version for future upgrades
    pub version: u32,
    /// Block index in the chain (genesis = 0)
    pub height: u32,
    /// Unix timestamp in nanoseconds for temporal ordering
    pub timestamp: u64,
    /// Proof-of-work nonce for mining difficulty adjustment
    pub nonce: u64,
    /// Hash of parent block, forming the chain
    pub previous_block: Hash,
    /// Root of merkle tree of transactions, enables SPV proofs
    pub merkle_root: Hash,
}

/// Immutable block containing header and transactions.
///
/// Blocks are validated once upon receipt and never modified.
///
/// The `header_hash` is pre-computed at construction for O(1) lookups during
/// chain traversal and validation.
#[derive(Debug, PartialEq, Eq)]
pub struct Block {
    pub header: Header,
    pub transactions: Box<[Transaction]>,
    pub header_hash: Hash,
}

impl BorshSerialize for Block {
    fn serialize<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        self.header.serialize(writer)?;
        self.transactions.serialize(writer)?;
        Ok(())
    }
}

impl BorshDeserialize for Block {
    fn deserialize_reader<R: Read>(reader: &mut R) -> io::Result<Self> {
        let header = Header::deserialize_reader(reader)?;
        let transactions: Vec<Transaction> = BorshDeserialize::deserialize_reader(reader)?;
        Block::new(header, transactions)
    }
}

impl Block {
    /// Creates a new block with pre-computed header hash.
    ///
    /// The header hash is computed once at construction rather than lazily,
    /// since blocks are validated immediately upon receipt. This makes hash lookups infallible and O(1).
    ///
    /// # Errors
    /// Returns an error if header encoding fails during hash computation.
    pub fn new(header: Header, transactions: Vec<Transaction>) -> io::Result<Self> {
        let header_hash = header.hash()?;
        Ok(Block {
            header,
            transactions: transactions.into_boxed_slice(),
            header_hash,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::binary_codec::BinaryCodecHash;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn create_header(version: u32, height: u32, nonce: u64) -> Header {
        Header {
            version,
            height,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64,
            nonce,
            previous_block: Hash::random(),
            merkle_root: Hash::random(),
        }
    }

    #[test]
    fn test_header_binary_codec() {
        let mut buf: Vec<u8> = Vec::new();
        let header = create_header(1, 3, 93482432);
        header
            .serialize(&mut buf)
            .expect("Could not encode the header");

        let decoded =
            Header::deserialize_reader(&mut buf.as_slice()).expect("Could not decode the header");
        assert_eq!(
            header, decoded,
            "The decoded header does not match the original header"
        );
    }

    #[test]
    fn test_block_binary_codec() {
        let mut buf: Vec<u8> = Vec::new();
        let block = Block::new(create_header(1, 10, 13459265), vec![])
            .expect("Encoding error while creating the header_hash variable");
        block
            .serialize(&mut buf)
            .expect("Could not encode the block");

        let decoded =
            Block::deserialize_reader(&mut buf.as_slice()).expect("Could not decode the block");
        assert_eq!(
            block, decoded,
            "The decoded block does not match the original block"
        );
    }

    #[test]
    fn test_hash() {
        let block = Block::new(create_header(1, 10, 13459265), vec![])
            .expect("Encoding error while creating the header_hash variable");
        assert_ne!(block.header_hash, Hash::zero(), "Hashing failed");
    }

    #[test]
    fn test_hash_determinism() {
        let header = create_header(1, 5, 12345);
        let hash1 = header.hash().expect("Failed to hash header");
        let hash2 = header.hash().expect("Failed to hash header");
        assert_eq!(hash1, hash2, "Same header should produce same hash");
    }

    #[test]
    fn test_different_headers_different_hashes() {
        let header1 = create_header(1, 5, 12345);
        let header2 = create_header(1, 5, 12346);
        let hash1 = header1.hash().expect("Failed to hash header");
        let hash2 = header2.hash().expect("Failed to hash header");
        assert_ne!(
            hash1, hash2,
            "Different headers should produce different hashes"
        );
    }

    #[test]
    fn test_genesis_block() {
        let genesis_header = Header {
            version: 0,
            height: 0,
            timestamp: 0,
            nonce: 0,
            previous_block: Hash::zero(),
            merkle_root: Hash::zero(),
        };
        let block = Block::new(genesis_header, vec![]).expect("Failed to create genesis block");
        assert_eq!(block.header.height, 0);
        assert_eq!(block.header.previous_block, Hash::zero());
        assert_ne!(block.header_hash, Hash::zero());
    }

    #[test]
    fn test_header_decode_insufficient_data() {
        let mut buf: Vec<u8> = Vec::new();
        let header = create_header(1, 3, 93482432);
        header
            .serialize(&mut buf)
            .expect("Could not encode the header");

        // Truncate buffer to simulate corrupted data
        buf.truncate(50);

        let result = Header::deserialize_reader(&mut buf.as_slice());
        assert!(result.is_err(), "Should fail with insufficient data");
    }

    #[test]
    fn test_header_max_values() {
        let header = Header {
            version: u32::MAX,
            height: u32::MAX,
            timestamp: u64::MAX,
            nonce: u64::MAX,
            previous_block: Hash::random(),
            merkle_root: Hash::random(),
        };

        let mut buf: Vec<u8> = Vec::new();
        header.serialize(&mut buf).expect("Could not encode header");

        let decoded =
            Header::deserialize_reader(&mut buf.as_slice()).expect("Could not decode header");
        assert_eq!(header, decoded);
    }

    #[test]
    fn test_block_hash_consistency() {
        let header = create_header(2, 100, 999999);
        let block1 = Block::new(header, vec![]).expect("Failed to create block");
        let block2 = Block::new(block1.header, vec![]).expect("Failed to create block");
        assert_eq!(
            block1.header_hash, block2.header_hash,
            "Blocks with same header should have same hash"
        );
    }
}
