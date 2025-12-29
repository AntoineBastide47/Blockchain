//! Blockchain block and header structures with memory-optimized layouts.

use crate::core::transaction::Transaction;
use crate::crypto::key_pair::{PrivateKey, PublicKey};
use crate::types::encoding::{Decode, DecodeError, Encode, EncodeSink};
use crate::types::hash::Hash;
use crate::types::serializable_signature::SerializableSignature;
use crate::utils::log::Logger;
use blockchain_derive::BinaryCodec;
use std::sync::{Arc, OnceLock};

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

impl Header {
    /// Computes the chain-specific hash of this header.
    ///
    /// The hash includes a domain separator ("BLOCK_HEADER"), the chain ID,
    /// and all header fields to prevent cross-chain replay attacks.
    fn compute_hash(&self, chain_id: u64) -> Hash {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"BLOCK_HEADER");
        chain_id.encode(&mut buf);
        self.encode(&mut buf);
        Hash::sha3_from_bytes(&buf)
    }
}

/// Constructs the data that validators sign when producing a block.
///
/// Includes a domain separator ("BLOCK"), the chain ID, and the header hash
/// to bind the signature to a specific chain and block.
fn block_sign_data(chain_id: u64, hash: Hash) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(b"BLOCK");
    chain_id.encode(&mut buf);
    hash.encode(&mut buf);
    buf
}

/// Intermediate block state before signing.
///
/// Used during block construction to hold all block data before
/// the validator signature is computed and attached.
struct UnsignedBlock {
    /// Block metadata and cryptographic commitments.
    pub header: Header,
    /// Public key of the validator producing this block.
    pub validator: PublicKey,
    /// Transactions included in this block.
    pub transactions: Box<[Transaction]>,
}

/// Immutable block containing header and transactions.
///
/// Blocks are validated once upon receipt and never modified.
/// The header hash is lazily computed and cached for O(1) subsequent lookups.
#[derive(Debug, PartialEq, Eq)]
pub struct Block {
    pub header: Header,
    pub validator: PublicKey,
    pub signature: SerializableSignature,
    pub transactions: Box<[Transaction]>,

    /// Lazily computed header hash, cached after first computation, do not use directly.
    cached_header_hash: OnceLock<Hash>,
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
        Ok(Block {
            header: Header::decode(input)?,
            validator: PublicKey::decode(input)?,
            signature: SerializableSignature::decode(input)?,
            transactions: Vec::<Transaction>::decode(input)?.into_boxed_slice(),
            cached_header_hash: OnceLock::new(),
        })
    }
}

impl Block {
    /// Creates a new signed block.
    ///
    /// Computes the data hash from the transactions, signs the block with the
    /// validator's private key, and returns the complete block. The `chain_id`
    /// is incorporated into both the data hash and signature to prevent
    /// cross-chain replay attacks.
    pub fn new(
        mut header: Header,
        validator: PrivateKey,
        transactions: Vec<Transaction>,
        chain_id: u64,
    ) -> Arc<Self> {
        header.data_hash = Block::data_hash(&transactions, chain_id);

        let unsigned = UnsignedBlock {
            header,
            validator: validator.public_key(),
            transactions: transactions.into_boxed_slice(),
        };

        Arc::new(Block {
            header: unsigned.header,
            validator: unsigned.validator,
            signature: validator
                .sign(block_sign_data(chain_id, unsigned.header.compute_hash(chain_id)).as_slice()),
            transactions: unsigned.transactions,
            cached_header_hash: OnceLock::new(),
        })
    }

    /// Returns the chain-specific header hash, computing and caching it on first call.
    ///
    /// The hash uniquely identifies this block within the given chain.
    pub fn header_hash(&self, chain_id: u64) -> Hash {
        *self
            .cached_header_hash
            .get_or_init(|| self.header.compute_hash(chain_id))
    }

    /// Computes the data hash for a set of transactions.
    ///
    /// The hash commits to all transaction IDs in order, prefixed with a
    /// domain separator ("BLOCK_TXS") and chain ID for replay protection.
    pub fn data_hash(transactions: &[Transaction], chain_id: u64) -> Hash {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"BLOCK_TXS");
        chain_id.encode(&mut buf);

        for tx in transactions {
            let id = tx.id(chain_id);
            id.encode(&mut buf);
        }

        Hash::sha3_from_bytes(&buf)
    }

    /// Verifies the block's cryptographic integrity.
    ///
    /// Checks that:
    /// - The validator signature is valid for the header hash.
    /// - All transaction signatures are valid for the given chain ID.
    /// - The data hash matches the hash of the transactions.
    ///
    /// The `chain_id` parameter ensures transactions are verified against the
    /// correct chain, preventing cross-chain replay attacks.
    ///
    /// Logs warnings for any verification failures.
    pub fn verify(&self, logger: &Logger, chain_id: u64) -> bool {
        let hash = self.header_hash(chain_id);
        if !self
            .validator
            .verify(block_sign_data(chain_id, hash).as_slice(), self.signature)
        {
            logger.warn(&format!("invalid block signature: block={}", hash));
            return false;
        }

        for t in &self.transactions {
            if !t.verify(chain_id) {
                logger.warn(&format!(
                    "invalid transaction signature in block: block={}",
                    hash
                ));
                return false;
            }
        }

        if Block::data_hash(&self.transactions, chain_id) != self.header.data_hash {
            logger.warn(&format!("invalid data hash in block: block={}", hash));
            return false;
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::key_pair::PrivateKey;
    use crate::utils::test_utils::utils::random_hash;
    use std::time::{SystemTime, UNIX_EPOCH};

    const TEST_CHAIN_ID: u64 = 832489;

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
        Block::new(header, key, transactions, TEST_CHAIN_ID)
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
        let hash1 = header1.compute_hash(TEST_CHAIN_ID);
        let hash2 = header2.compute_hash(TEST_CHAIN_ID);
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
        assert_ne!(block.header_hash(TEST_CHAIN_ID), Hash::zero());
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
            block1.header_hash(TEST_CHAIN_ID),
            block2.header_hash(TEST_CHAIN_ID),
            "Blocks with same header should have same hash"
        );
    }

    #[test]
    fn new_creates_verifiable_block() {
        let block = create_block(create_header(1), vec![]);
        assert!(block.verify(&test_logger(), TEST_CHAIN_ID));
    }

    #[test]
    fn verify_fails_with_wrong_validator() {
        let mut block = Arc::try_unwrap(create_block(create_header(1), vec![])).unwrap();
        block.validator = PrivateKey::new().public_key();
        assert!(!block.verify(&test_logger(), TEST_CHAIN_ID));
    }

    #[test]
    fn new_with_transactions() {
        let key = PrivateKey::new();
        let tx = Transaction::new(b"data".as_slice(), key, TEST_CHAIN_ID);

        let block = create_block(create_header(1), vec![tx]);
        assert_eq!(block.transactions.len(), 1);
        assert!(block.verify(&test_logger(), TEST_CHAIN_ID));
    }

    #[test]
    fn verify_fails_with_tampered_data_hash() {
        let key = PrivateKey::new();
        let tx = Transaction::new(b"data".as_slice(), key, TEST_CHAIN_ID);

        let mut block = Arc::try_unwrap(create_block(create_header(1), vec![tx])).unwrap();
        block.header.data_hash = random_hash();
        assert!(!block.verify(&test_logger(), TEST_CHAIN_ID));
    }

    #[test]
    fn verify_fails_with_tampered_transaction() {
        let key = PrivateKey::new();
        let tx = Transaction::new(b"original".as_slice(), key.clone(), TEST_CHAIN_ID);

        let mut block = Arc::try_unwrap(create_block(create_header(1), vec![tx])).unwrap();

        let tampered_tx = Transaction::new(b"tampered".as_slice(), key, TEST_CHAIN_ID);
        block.transactions = vec![tampered_tx].into_boxed_slice();

        assert!(!block.verify(&test_logger(), TEST_CHAIN_ID));
    }

    #[test]
    fn verify_fails_with_invalid_transaction_signature() {
        let key1 = PrivateKey::new();
        let key2 = PrivateKey::new();

        let mut tx = Transaction::new(b"data".as_slice(), key1, TEST_CHAIN_ID);
        tx.from = key2.public_key();

        let header = create_header(1);
        let validator = PrivateKey::new();
        let block = Block::new(header, validator, vec![tx], TEST_CHAIN_ID);

        assert!(!block.verify(&test_logger(), TEST_CHAIN_ID));
    }

    #[test]
    fn new_computes_data_hash_from_transactions() {
        let key = PrivateKey::new();
        let tx1 = Transaction::new(b"tx1".as_slice(), key.clone(), TEST_CHAIN_ID);
        let tx2 = Transaction::new(b"tx2".as_slice(), key, TEST_CHAIN_ID);

        let header = create_header(1);
        let validator = PrivateKey::new();
        let block = Block::new(header, validator, vec![tx1, tx2], TEST_CHAIN_ID);

        assert_ne!(block.header.data_hash, Hash::zero());
        assert!(block.verify(&test_logger(), TEST_CHAIN_ID));
    }

    #[test]
    fn verify_with_multiple_transactions() {
        let mut txs = Vec::new();
        for i in 0..10 {
            let key = PrivateKey::new();
            let tx = Transaction::new(format!("tx{}", i).as_bytes(), key, TEST_CHAIN_ID);
            txs.push(tx);
        }

        let block = create_block(create_header(1), txs);
        assert_eq!(block.transactions.len(), 10);
        assert!(block.verify(&test_logger(), TEST_CHAIN_ID));
    }

    #[test]
    fn empty_block_has_valid_data_hash() {
        let header = create_header(1);
        let validator = PrivateKey::new();
        let block = Block::new(header, validator, vec![], TEST_CHAIN_ID);

        assert!(block.verify(&test_logger(), TEST_CHAIN_ID));
    }
}
