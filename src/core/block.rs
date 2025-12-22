//! Blockchain block and header structures with memory-optimized layouts.

use crate::core::transaction::Transaction;
use crate::crypto::key_pair::{PrivateKey, PublicKey};
use crate::types::binary_codec::{BinaryCodec, BinaryCodecHash};
use crate::types::hash::Hash;
use crate::types::serializable_bytes::SerializableBytes;
use crate::types::serializable_signature::SerializableSignature;
use borsh::{BorshDeserialize, BorshSerialize};
use std::io::{Read, Write};
use std::sync::Arc;
use tokio::io;
use tracing::warn;

/// Block header containing metadata and cryptographic commitments.
///
/// This type is `Copy` (88 bytes) for performance - headers are passed constantly
/// during validation, and stack allocation avoids heap allocations and pointer chasing.
#[derive(Copy, Clone, Debug, PartialEq, Eq, BinaryCodec)]
pub struct Header {
    /// Protocol version for future upgrades
    pub version: u32,
    /// Block index in the chain (genesis = 0)
    pub height: u32,
    /// Unix timestamp in nanoseconds for temporal ordering
    pub timestamp: u64,
    /// Hash of parent block, forming the chain
    pub previous_block: Hash,
    /// Hash of the data stored in the block
    pub data_hash: Hash,
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
    pub header_hash: Hash,
    pub validator: PublicKey,
    pub signature: SerializableSignature,
    pub transactions: Box<[Transaction]>,
}

impl BorshSerialize for Block {
    fn serialize<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        self.header.serialize(writer)?;
        self.validator.serialize(writer)?;
        self.signature.serialize(writer)?;
        self.transactions.serialize(writer)?;
        Ok(())
    }
}

impl BorshDeserialize for Block {
    fn deserialize_reader<R: Read>(reader: &mut R) -> io::Result<Self> {
        let header = Header::deserialize_reader(reader)?;
        let validator = PublicKey::deserialize_reader(reader)?;
        let signature = SerializableSignature::deserialize_reader(reader)?;
        let transactions: Vec<Transaction> = BorshDeserialize::deserialize_reader(reader)?;
        let header_hash = header.hash()?;
        Ok(Block {
            header,
            header_hash,
            validator,
            signature,
            transactions: transactions.into_boxed_slice(),
        })
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
    pub fn new(
        header: Header,
        validator: PrivateKey,
        transactions: Vec<Transaction>,
    ) -> io::Result<Arc<Self>> {
        let header_hash = header.hash()?;
        Ok(Arc::new(Block {
            header,
            header_hash,
            validator: validator.public_key(),
            signature: validator.sign(&SerializableBytes::from(header_hash.as_slice())),
            transactions: transactions.into_boxed_slice(),
        }))
    }

    pub fn verify(&self) -> bool {
        if !self
            .validator
            .verify(self.header_hash.as_slice(), self.signature)
        {
            warn!(block=%self.header_hash, "invalid block signature");
            return false;
        }

        for t in &self.transactions {
            if !t.verify() {
                warn!(block=%self.header_hash, "invalid transaction signature in block");
                return false;
            }
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::key_pair::PrivateKey;
    use crate::types::binary_codec::BinaryCodecHash;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn create_header(height: u32) -> Header {
        Header {
            version: 1,
            height,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64,
            previous_block: Hash::random(),
            data_hash: Hash::random(),
            merkle_root: Hash::random(),
        }
    }

    fn create_block(header: Header, transactions: Vec<Transaction>) -> Arc<Block> {
        let key = PrivateKey::new();
        Block::new(header, key, transactions).expect("Failed to create block")
    }

    #[test]
    fn test_header_binary_codec() {
        let mut buf: Vec<u8> = Vec::new();
        let header = create_header(3);
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
    fn test_different_headers_different_hashes() {
        let header1 = create_header(5);
        let header2 = create_header(5);
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
            previous_block: Hash::zero(),
            data_hash: Hash::zero(),
            merkle_root: Hash::zero(),
        };
        let block = create_block(genesis_header, vec![]);
        assert_eq!(block.header.height, 0);
        assert_eq!(block.header.previous_block, Hash::zero());
        assert_ne!(block.header_hash, Hash::zero());
    }

    #[test]
    fn test_header_decode_insufficient_data() {
        let mut buf: Vec<u8> = Vec::new();
        let header = create_header(3);
        header
            .serialize(&mut buf)
            .expect("Could not encode the header");

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
            data_hash: Hash::random(),
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
        let header = create_header(100);
        let block1 = create_block(header, vec![]);
        let block2 = create_block(block1.header, vec![]);
        assert_eq!(
            block1.header_hash, block2.header_hash,
            "Blocks with same header should have same hash"
        );
    }

    #[test]
    fn new_creates_verifiable_block() {
        let block = create_block(create_header(1), vec![]);
        assert!(block.verify());
    }

    #[test]
    fn verify_fails_with_wrong_validator() {
        let mut block = Arc::try_unwrap(create_block(create_header(1), vec![])).unwrap();
        block.validator = PrivateKey::new().public_key();
        assert!(!block.verify());
    }

    #[test]
    fn verify_fails_with_tampered_header_hash() {
        let mut block = Arc::try_unwrap(create_block(create_header(1), vec![])).unwrap();
        block.header_hash = Hash::random();
        assert!(!block.verify());
    }

    #[test]
    fn new_with_transactions() {
        let key = PrivateKey::new();
        let tx = Transaction::new(b"data".as_slice(), key).expect("Hashing failed");

        let block = create_block(create_header(1), vec![tx]);
        assert_eq!(block.transactions.len(), 1);
        assert!(block.verify());
    }
}
