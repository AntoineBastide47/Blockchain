//! Blockchain block and header structures with memory-optimized layouts.

use crate::core::transaction::Transaction;
use crate::crypto::key_pair::{PrivateKey, PublicKey};
use crate::types::binary_codec::{BinaryCodec, BinaryCodecHash, Decode};
use crate::types::bytes::Bytes;
use crate::types::encoding::{DecodeError, Encode, EncodeSink};
use crate::types::hash::Hash;
use crate::types::serializable_signature::SerializableSignature;
use crate::utils::log::Logger;
use std::sync::Arc;

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

impl Encode for Block {
    fn encode<S: EncodeSink>(&self, out: &mut S) {
        self.header.encode(out);
        self.validator.encode(out);
        self.signature.encode(out);
        self.transactions.encode(out);
    }
}

impl Decode for Block {
    fn decode(input: &mut &[u8]) -> Result<Self, DecodeError> {
        let header = Header::decode(input)?;
        let validator = PublicKey::decode(input)?;
        let signature = SerializableSignature::decode(input)?;
        let transactions: Vec<Transaction> = Decode::decode(input)?;
        let header_hash = header.hash();
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
        mut header: Header,
        validator: PrivateKey,
        transactions: Vec<Transaction>,
    ) -> Arc<Self> {
        header.data_hash = transactions.hash();
        let header_hash = header.hash();

        Arc::new(Block {
            header,
            header_hash,
            validator: validator.public_key(),
            signature: validator.sign(&Bytes::new(header_hash.as_slice())),
            transactions: transactions.into_boxed_slice(),
        })
    }

    /// Verifies the block's cryptographic integrity.
    ///
    /// Checks that:
    /// - The validator signature is valid for the header hash.
    /// - All transaction signatures are valid.
    /// - The data hash matches the hash of the transactions.
    ///
    /// Logs warnings for any verification failures.
    pub fn verify(&self, logger: &Logger) -> bool {
        if !self
            .validator
            .verify(self.header_hash.as_slice(), self.signature)
        {
            logger.warn(&format!(
                "invalid block signature: block={}",
                self.header_hash
            ));
            return false;
        }

        for t in &self.transactions {
            if !t.verify() {
                logger.warn(&format!(
                    "invalid transaction signature in block: block={}",
                    self.header_hash
                ));
                return false;
            }
        }

        if self.transactions.hash() != self.header.data_hash {
            logger.warn(&format!(
                "invalid data hash in block: block={}",
                self.header_hash
            ));
            return false;
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::key_pair::PrivateKey;
    use crate::types::binary_codec::BinaryCodecHash;
    use crate::utils::test_utils::utils::random_hash;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn test_logger() -> Logger {
        Logger::new("test")
    }

    fn create_header(height: u32) -> Header {
        Header {
            version: 1,
            height,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64,
            previous_block: random_hash(),
            data_hash: random_hash(),
            merkle_root: random_hash(),
        }
    }

    fn create_block(header: Header, transactions: Vec<Transaction>) -> Arc<Block> {
        let key = PrivateKey::new();
        Block::new(header, key, transactions)
    }

    #[test]
    fn test_header_binary_codec() {
        let header = create_header(3);
        let buf = header.to_bytes();

        let decoded = Header::from_bytes(buf.as_slice()).expect("Could not decode the header");
        assert_eq!(
            header, decoded,
            "The decoded header does not match the original header"
        );
    }

    #[test]
    fn test_different_headers_different_hashes() {
        let header1 = create_header(5);
        let header2 = create_header(5);
        let hash1 = header1.hash();
        let hash2 = header2.hash();
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
        let header = create_header(3);
        let mut buf = header.to_bytes();
        buf.truncate(50);

        let result = Header::from_bytes(buf.as_slice());
        assert!(result.is_err(), "Should fail with insufficient data");
    }

    #[test]
    fn test_header_max_values() {
        let header = Header {
            version: u32::MAX,
            height: u32::MAX,
            timestamp: u64::MAX,
            data_hash: random_hash(),
            previous_block: random_hash(),
            merkle_root: random_hash(),
        };

        let buf = header.to_bytes();
        let decoded = Header::from_bytes(buf.as_slice()).expect("Could not decode header");
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
        assert!(block.verify(&test_logger()));
    }

    #[test]
    fn verify_fails_with_wrong_validator() {
        let mut block = Arc::try_unwrap(create_block(create_header(1), vec![])).unwrap();
        block.validator = PrivateKey::new().public_key();
        assert!(!block.verify(&test_logger()));
    }

    #[test]
    fn verify_fails_with_tampered_header_hash() {
        let mut block = Arc::try_unwrap(create_block(create_header(1), vec![])).unwrap();
        block.header_hash = random_hash();
        assert!(!block.verify(&test_logger()));
    }

    #[test]
    fn new_with_transactions() {
        let key = PrivateKey::new();
        let tx = Transaction::new(b"data".as_slice(), key);

        let block = create_block(create_header(1), vec![tx]);
        assert_eq!(block.transactions.len(), 1);
        assert!(block.verify(&test_logger()));
    }

    #[test]
    fn verify_fails_with_tampered_data_hash() {
        let key = PrivateKey::new();
        let tx = Transaction::new(b"data".as_slice(), key);

        let mut block = Arc::try_unwrap(create_block(create_header(1), vec![tx])).unwrap();
        block.header.data_hash = random_hash();
        assert!(!block.verify(&test_logger()));
    }

    #[test]
    fn verify_fails_with_tampered_transaction() {
        let key = PrivateKey::new();
        let tx = Transaction::new(b"original".as_slice(), key.clone());

        let mut block = Arc::try_unwrap(create_block(create_header(1), vec![tx])).unwrap();

        let tampered_tx = Transaction::new(b"tampered".as_slice(), key);
        block.transactions = vec![tampered_tx].into_boxed_slice();

        assert!(!block.verify(&test_logger()));
    }

    #[test]
    fn verify_fails_with_invalid_transaction_signature() {
        let key1 = PrivateKey::new();
        let key2 = PrivateKey::new();

        let mut tx = Transaction::new(b"data".as_slice(), key1);
        tx.from = key2.public_key();

        let header = create_header(1);
        let validator = PrivateKey::new();
        let block = Block::new(header, validator, vec![tx]);

        assert!(!block.verify(&test_logger()));
    }

    #[test]
    fn new_computes_data_hash_from_transactions() {
        let key = PrivateKey::new();
        let tx1 = Transaction::new(b"tx1".as_slice(), key.clone());
        let tx2 = Transaction::new(b"tx2".as_slice(), key);

        let header = create_header(1);
        let validator = PrivateKey::new();
        let block = Block::new(header, validator, vec![tx1, tx2]);

        assert_ne!(block.header.data_hash, Hash::zero());
        assert!(block.verify(&test_logger()));
    }

    #[test]
    fn verify_with_multiple_transactions() {
        let mut txs = Vec::new();
        for i in 0..10 {
            let key = PrivateKey::new();
            let tx = Transaction::new(format!("tx{}", i).as_bytes(), key);
            txs.push(tx);
        }

        let block = create_block(create_header(1), txs);
        assert_eq!(block.transactions.len(), 10);
        assert!(block.verify(&test_logger()));
    }

    #[test]
    fn empty_block_has_valid_data_hash() {
        let header = create_header(1);
        let validator = PrivateKey::new();
        let block = Block::new(header, validator, vec![]);

        assert!(block.verify(&test_logger()));
    }
}
