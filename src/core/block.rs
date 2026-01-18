//! Blockchain block and header structures with memory-optimized layouts.

use crate::core::transaction::Transaction;
use crate::core::validator::BLOCK_MAX_BYTES;
use crate::core::validator::BlockValidatorError;
use crate::crypto::key_pair::{PrivateKey, PublicKey};
use crate::types::encoding::Encode;
use crate::types::hash::{Hash, HashCache};
use crate::types::merkle_tree::MerkleTree;
use crate::types::serializable_signature::SerializableSignature;
use blockchain_derive::BinaryCodec;

/// Block header containing metadata and cryptographic commitments.
#[derive(Clone, Debug, PartialEq, Eq, BinaryCodec)]
pub struct Header {
    /// Protocol version for future upgrades
    pub version: u32,
    /// Block index in the chain (genesis = 0)
    pub height: u64,
    /// Unix timestamp in nanoseconds for temporal ordering
    pub timestamp: u64,
    /// How much gas this block used
    pub gas_used: u64,
    /// Hash of parent block, forming the chain
    pub previous_block: Hash,
    /// Root of merkle tree of transactions
    pub merkle_root: Hash,
    /// Root hash of the VM storage after executing all transactions in this block
    pub state_root: Hash,
}

impl Header {
    /// Computes the chain-specific hash of this header.
    ///
    /// The hash includes a domain separator ("BLOCK_HEADER"), the chain ID,
    /// and all header fields to prevent cross-chain replay attacks.
    fn compute_hash(&self, chain_id: u64) -> Hash {
        let mut h = Hash::sha3();
        h.update(b"BLOCK_HEADER");
        chain_id.encode(&mut h);
        self.encode(&mut h);
        h.finalize()
    }
}

/// Constructs the data that validators sign when producing a block.
///
/// Includes a domain separator ("BLOCK"), the chain ID, and the header hash
/// to bind the signature to a specific chain and block.
fn block_sign_data(chain_id: u64, hash: &Hash) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(b"BLOCK");
    chain_id.encode(&mut buf);
    hash.encode(&mut buf);
    buf
}

/// Immutable block containing header and transactions.
///
/// Blocks are validated once upon receipt and never modified.
/// The header hash is lazily computed and cached for O(1) subsequent lookups.
#[derive(Debug, PartialEq, Eq, Clone, BinaryCodec)]
#[binary_codec(max_size = BLOCK_MAX_BYTES)]
pub struct Block {
    pub header: Header,
    pub validator: PublicKey,
    pub signature: SerializableSignature,
    pub transactions: Box<[Transaction]>,

    /// Lazily computed header hash, cached after first computation, do not use directly.
    cached_header_hash: HashCache,
}

impl Block {
    /// Creates a new signed block.
    ///
    /// Computes the data hash from the transactions, signs the block with the
    /// validator's private key, and returns the complete block. The `chain_id`
    /// is incorporated into both the data hash and signature to prevent
    /// cross-chain replay attacks.
    pub fn new(
        header: Header,
        validator: PrivateKey,
        transactions: Vec<Transaction>,
        chain_id: u64,
    ) -> Self {
        Self {
            header: header.clone(),
            validator: validator.public_key(),
            signature: validator
                .sign(block_sign_data(chain_id, &header.compute_hash(chain_id)).as_slice()),
            transactions: transactions.into_boxed_slice(),
            cached_header_hash: HashCache::new(),
        }
    }

    /// Returns the chain-specific header hash, computing and caching it on first call.
    ///
    /// The hash uniquely identifies this block within the given chain.
    pub fn header_hash(&self, chain_id: u64) -> Hash {
        self.cached_header_hash
            .get_or_compute(chain_id, || self.header.compute_hash(chain_id))
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
    pub fn verify(&self, chain_id: u64) -> Result<(), BlockValidatorError> {
        let hash = self.header_hash(chain_id);
        if !self
            .validator
            .verify(block_sign_data(chain_id, &hash).as_slice(), self.signature)
        {
            return Err(BlockValidatorError::InvalidSignature(hash));
        }

        for t in &self.transactions {
            if !t.verify(chain_id) {
                return Err(BlockValidatorError::InvalidTransactionSignature(hash));
            }
        }

        if MerkleTree::from_transactions(&self.transactions, chain_id) != self.header.merkle_root {
            return Err(BlockValidatorError::InvalidMerkleRoot(hash));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::key_pair::PrivateKey;
    use crate::types::bytes::Bytes;
    use crate::types::encoding::{Decode, DecodeError};
    use crate::utils::test_utils::utils::{new_tx, random_hash};
    use crate::virtual_machine::vm::BLOCK_GAS_LIMIT;
    use std::time::{SystemTime, UNIX_EPOCH};

    const TEST_CHAIN_ID: u64 = 832489;

    fn build_tx(data: &[u8], key: PrivateKey) -> Transaction {
        new_tx(Bytes::new(data), key, TEST_CHAIN_ID)
    }

    fn create_header(height: u64, transactions: &[Transaction]) -> Header {
        Header {
            version: 1,
            height,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64,
            gas_used: BLOCK_GAS_LIMIT,
            previous_block: random_hash(),
            merkle_root: MerkleTree::from_transactions(transactions, TEST_CHAIN_ID),
            state_root: random_hash(),
        }
    }

    fn create_block(header: Header, transactions: Vec<Transaction>) -> Block {
        let key = PrivateKey::new();
        Block::new(header, key, transactions, TEST_CHAIN_ID)
    }

    #[test]
    fn test_header_binary_codec() {
        let header = create_header(3, &[]);
        let buf = header.to_bytes();

        let decoded = Header::from_bytes(buf.as_slice()).expect("Could not decode the header");
        assert_eq!(
            header, decoded,
            "The decoded header does not match the original header"
        );
    }

    #[test]
    fn test_different_headers_different_hashes() {
        let header1 = create_header(5, &[]);
        let header2 = create_header(5, &[]);
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
            gas_used: BLOCK_GAS_LIMIT,
            previous_block: Hash::zero(),
            merkle_root: Hash::zero(),
            state_root: Hash::zero(),
        };
        let block = create_block(genesis_header, vec![]);
        assert_eq!(block.header.height, 0);
        assert_eq!(block.header.previous_block, Hash::zero());
        assert_ne!(block.header_hash(TEST_CHAIN_ID), Hash::zero());
    }

    #[test]
    fn test_header_decode_insufficient_data() {
        let header = create_header(3, &[]);
        let mut buf = header.to_bytes();
        buf.make_mut().truncate(50);

        let result = Header::from_bytes(buf.as_slice());
        assert!(result.is_err(), "Should fail with insufficient data");
    }

    #[test]
    fn test_header_max_values() {
        let header = Header {
            version: u32::MAX,
            height: u64::MAX,
            timestamp: u64::MAX,
            gas_used: BLOCK_GAS_LIMIT,
            previous_block: random_hash(),
            merkle_root: random_hash(),
            state_root: random_hash(),
        };

        let buf = header.to_bytes();
        let decoded = Header::from_bytes(buf.as_slice()).expect("Could not decode header");
        assert_eq!(header, decoded);
    }

    #[test]
    fn test_block_hash_consistency() {
        let header = create_header(100, &[]);
        let block1 = create_block(header, vec![]);
        let block2 = create_block(block1.header.clone(), vec![]);
        assert_eq!(
            block1.header_hash(TEST_CHAIN_ID),
            block2.header_hash(TEST_CHAIN_ID),
            "Blocks with same header should have same hash"
        );
    }

    #[test]
    fn new_creates_verifiable_block() {
        let block = create_block(create_header(1, &[]), vec![]);
        assert!(block.verify(TEST_CHAIN_ID).is_ok());
    }

    #[test]
    fn verify_fails_with_wrong_validator() {
        let mut block = create_block(create_header(1, &[]), vec![]);
        block.validator = PrivateKey::new().public_key();
        assert!(block.verify(TEST_CHAIN_ID).is_err());
    }

    #[test]
    fn new_with_transactions() {
        let key = PrivateKey::new();
        let tx = build_tx(b"data", key);

        let block = create_block(create_header(1, std::slice::from_ref(&tx)), vec![tx]);
        assert_eq!(block.transactions.len(), 1);
        assert!(block.verify(TEST_CHAIN_ID).is_ok());
    }

    #[test]
    fn verify_fails_with_tampered_merkle_root() {
        let key = PrivateKey::new();
        let tx = build_tx(b"data", key);

        let mut block = create_block(create_header(1, std::slice::from_ref(&tx)), vec![tx]);
        block.header.merkle_root = random_hash();
        assert!(block.verify(TEST_CHAIN_ID).is_err());
    }

    #[test]
    fn verify_fails_with_tampered_transaction() {
        let key = PrivateKey::new();
        let tx = build_tx(b"original", key.clone());

        let mut block = create_block(create_header(1, std::slice::from_ref(&tx)), vec![tx]);

        let tampered_tx = build_tx(b"tampered", key);
        block.transactions = vec![tampered_tx].into_boxed_slice();

        assert!(block.verify(TEST_CHAIN_ID).is_err());
    }

    #[test]
    fn verify_fails_with_invalid_transaction_signature() {
        let key1 = PrivateKey::new();
        let key2 = PrivateKey::new();

        let mut tx = build_tx(b"data", key1);
        tx.from = key2.public_key();

        let header = create_header(1, std::slice::from_ref(&tx));
        let validator = PrivateKey::new();
        let block = Block::new(header, validator, vec![tx], TEST_CHAIN_ID);

        assert!(block.verify(TEST_CHAIN_ID).is_err());
    }

    #[test]
    fn new_computes_merkle_root_from_transactions() {
        let key = PrivateKey::new();
        let tx1 = build_tx(b"tx1", key.clone());
        let tx2 = build_tx(b"tx2", key);

        let header = create_header(1, &[tx1.clone(), tx2.clone()]);
        let validator = PrivateKey::new();
        let block = Block::new(header, validator, vec![tx1, tx2], TEST_CHAIN_ID);

        assert_ne!(block.header.merkle_root, Hash::zero());
        assert!(block.verify(TEST_CHAIN_ID).is_ok());
    }

    #[test]
    fn verify_with_multiple_transactions() {
        let mut txs = Vec::new();
        for i in 0..10 {
            let key = PrivateKey::new();
            let tx = build_tx(format!("tx{}", i).as_bytes(), key);
            txs.push(tx);
        }

        let block = create_block(create_header(1, &txs), txs);
        assert_eq!(block.transactions.len(), 10);
        assert!(block.verify(TEST_CHAIN_ID).is_ok());
    }

    #[test]
    fn empty_block_has_valid_merkle_root() {
        let header = create_header(1, &[]);
        let validator = PrivateKey::new();
        let block = Block::new(header, validator, vec![], TEST_CHAIN_ID);

        assert!(block.verify(TEST_CHAIN_ID).is_ok());
    }

    #[test]
    fn serialize_deserialize_roundtrip() {
        let key = PrivateKey::new();
        let tx = build_tx(b"roundtrip test", key);
        let block = create_block(create_header(1, std::slice::from_ref(&tx)), vec![tx]);

        let encoded = block.to_bytes();
        let decoded = Block::from_bytes(encoded.as_slice()).expect("deserialization failed");

        assert_eq!(block, decoded);
        assert!(decoded.verify(TEST_CHAIN_ID).is_ok());
    }

    #[test]
    fn decode_rejects_oversized_length_prefix() {
        let block = create_block(create_header(1, &[]), vec![]);

        let mut encoded = block.to_bytes().to_vec();

        // Replace length prefix with value exceeding BLOCK_MAX_BYTES
        let fake_len = (BLOCK_MAX_BYTES + 1) as u64;
        encoded[..8].copy_from_slice(&fake_len.to_le_bytes());

        let result = Block::from_bytes(&encoded);
        assert!(matches!(
            result,
            Err(DecodeError::LengthOverflow {
                type_name: "Block",
                ..
            })
        ));
    }

    #[test]
    fn decode_rejects_trailing_bytes() {
        let block = create_block(create_header(1, &[]), vec![]);

        let mut encoded = block.to_bytes().to_vec();
        encoded.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);

        // from_bytes requires all bytes to be consumed
        let result = Block::from_bytes(&encoded);
        assert!(matches!(result, Err(DecodeError::InvalidValue)));
    }

    #[test]
    fn decode_fails_on_truncated_input() {
        let block = create_block(create_header(1, &[]), vec![]);

        let encoded = block.to_bytes();

        // Try decoding with progressively shorter input
        for truncate_at in [0, 4, 8, encoded.len() / 2, encoded.len() - 1] {
            let truncated = &encoded[..truncate_at];
            let result = Block::from_bytes(truncated);
            assert!(
                result.is_err(),
                "should fail at truncation point {truncate_at}"
            );
        }
    }

    #[test]
    fn decode_fails_on_empty_input() {
        let result = Block::from_bytes(&[]);
        assert!(matches!(result, Err(DecodeError::UnexpectedEof)));
    }

    #[test]
    fn encoding_is_deterministic() {
        let key = PrivateKey::new();
        let tx = build_tx(b"determinism test", key);
        let block = create_block(create_header(1, std::slice::from_ref(&tx)), vec![tx]);

        let encoded1 = block.to_bytes();
        let encoded2 = block.to_bytes();
        let encoded3 = block.to_bytes();

        assert_eq!(encoded1, encoded2);
        assert_eq!(encoded2, encoded3);
    }

    #[test]
    fn roundtrip_with_empty_transactions() {
        let block = create_block(create_header(1, &[]), vec![]);

        let encoded = block.to_bytes();
        let decoded = Block::from_bytes(encoded.as_slice()).expect("decode failed");

        assert_eq!(block, decoded);
    }

    #[test]
    fn multiple_blocks_decode_sequentially() {
        let key = PrivateKey::new();
        let tx1 = build_tx(b"first", key.clone());
        let tx2 = build_tx(b"second", key.clone());
        let tx3 = build_tx(b"third", key);

        let block1 = create_block(create_header(1, std::slice::from_ref(&tx1)), vec![tx1]);
        let block2 = create_block(create_header(2, std::slice::from_ref(&tx2)), vec![tx2]);
        let block3 = create_block(create_header(3, std::slice::from_ref(&tx3)), vec![tx3]);

        let mut buffer = Vec::new();
        block1.encode(&mut buffer);
        block2.encode(&mut buffer);
        block3.encode(&mut buffer);

        let mut slice = buffer.as_slice();
        let decoded1 = Block::decode(&mut slice).expect("block1 decode failed");
        let decoded2 = Block::decode(&mut slice).expect("block2 decode failed");
        let decoded3 = Block::decode(&mut slice).expect("block3 decode failed");

        assert!(slice.is_empty(), "all bytes should be consumed");
        assert_eq!(block1, decoded1);
        assert_eq!(block2, decoded2);
        assert_eq!(block3, decoded3);
    }

    #[test]
    fn decode_preserves_all_fields() {
        let key = PrivateKey::new();
        let tx = build_tx(b"field preservation test", key);
        let original = create_block(create_header(42, std::slice::from_ref(&tx)), vec![tx]);

        let encoded = original.to_bytes();
        let decoded = Block::from_bytes(encoded.as_slice()).expect("decode failed");

        assert_eq!(original.header, decoded.header);
        assert_eq!(original.validator, decoded.validator);
        assert_eq!(original.signature, decoded.signature);
        assert_eq!(original.transactions, decoded.transactions);
    }
}
