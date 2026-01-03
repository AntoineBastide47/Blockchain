//! Transaction structure with reference-counted data storage.

use crate::crypto::key_pair::{PrivateKey, PublicKey, SerializableSignature};
use crate::types::bytes::Bytes;
use crate::types::encoding::{Decode, DecodeError, Encode, EncodeSink};
use crate::types::hash::Hash;
use blockchain_derive::BinaryCodec;
use std::sync::OnceLock;

/// Unsigned transaction used internally for signing and verification.
///
/// Contains the transaction data without the signature, used to compute
/// the signing hash that gets signed by the sender's private key.
#[derive(BinaryCodec)]
struct UnsignedTransaction {
    /// Sender's public key.
    pub from: PublicKey,
    /// Arbitrary transaction payload.
    pub data: Bytes,
}

impl UnsignedTransaction {
    /// Constructs the byte sequence to be hashed and signed.
    ///
    /// Includes a domain separator prefix and chain ID to prevent replay attacks
    /// across different chains.
    pub fn signing_bytes(&self, chain_id: u64) -> Hash {
        let mut buf = Hash::sha3();
        buf.update(b"TX");
        chain_id.encode(&mut buf);
        self.encode(&mut buf);
        buf.finalize()
    }
}

/// A blockchain transaction containing arbitrary data.
///
/// Uses `Bytes` for zero-copy sharing - transactions are immutable after creation
/// and often referenced by multiple blocks during reorganizations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transaction {
    /// Sender's public key, also used for signature verification.
    pub from: PublicKey,
    /// ECDSA signature over the transaction hash.
    pub signature: SerializableSignature,
    /// Arbitrary transaction payload.
    pub data: Bytes,
    /// Cached transaction ID, computed lazily on first access, do not use directly.
    cached_id: OnceLock<Hash>,
}

impl Transaction {
    /// Creates a new signed transaction.
    ///
    /// Signs the transaction data with the provided private key, binding it
    /// to the specified chain to prevent cross-chain replay attacks.
    pub fn new(data: impl Into<Bytes>, key: PrivateKey, chain_id: u64) -> Self {
        let data = data.into();

        let unsigned = UnsignedTransaction {
            from: key.public_key(),
            data: data.clone(),
        };
        let signature = &unsigned.signing_bytes(chain_id);

        Transaction {
            from: unsigned.from,
            signature: key.sign(signature.as_slice()),
            data: unsigned.data,
            cached_id: OnceLock::new(),
        }
    }

    /// Returns the bytes that were signed to produce this transaction's signature.
    ///
    /// Used during verification to reconstruct the signed message.
    pub fn signing_bytes(&self, chain_id: u64) -> Hash {
        UnsignedTransaction {
            from: self.from,
            data: self.data.clone(),
        }
        .signing_bytes(chain_id)
    }

    /// Returns the unique transaction identifier.
    ///
    /// Computed from the full transaction including signature, ensuring uniqueness
    /// even for identical payloads signed by different keys. Result is cached.
    pub fn id(&self, chain_id: u64) -> Hash {
        *self.cached_id.get_or_init(|| {
            let mut h = Hash::sha3();
            h.update(b"TXID");
            chain_id.encode(&mut h);
            self.encode(&mut h);
            h.finalize()
        })
    }

    /// Verifies the transaction signature against the sender's public key.
    ///
    /// Returns `true` if the signature is valid for the given chain ID.
    pub fn verify(&self, chain_id: u64) -> bool {
        let hash = self.signing_bytes(chain_id);
        self.from.verify(hash.as_slice(), self.signature)
    }
}

impl Encode for Transaction {
    fn encode<S: EncodeSink>(&self, out: &mut S) {
        self.from.encode(out);
        self.signature.encode(out);
        self.data.encode(out);
    }
}

impl Decode for Transaction {
    fn decode(input: &mut &[u8]) -> Result<Self, DecodeError> {
        Ok(Self {
            from: PublicKey::decode(input)?,
            signature: SerializableSignature::decode(input)?,
            data: Bytes::decode(input)?,
            cached_id: OnceLock::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_CHAIN_ID: u64 = 32;

    #[test]
    fn new_creates_valid_transaction() {
        let key = PrivateKey::new();
        let data = Bytes::new(b"test data");
        let tx = Transaction::new(data.clone(), key, TEST_CHAIN_ID);

        assert_eq!(tx.data, data);
        assert!(tx.verify(TEST_CHAIN_ID));
    }

    #[test]
    fn verify_fails_with_wrong_public_key() {
        let key1 = PrivateKey::new();
        let key2 = PrivateKey::new();
        let data = Bytes::new(b"payload");

        let mut tx = Transaction::new(data, key1, TEST_CHAIN_ID);
        tx.from = key2.public_key();

        assert!(!tx.verify(TEST_CHAIN_ID));
    }

    #[test]
    fn verify_fails_with_tampered_data() {
        let key = PrivateKey::new();
        let mut tx = Transaction::new(b"original".as_slice(), key, TEST_CHAIN_ID);
        tx.data = Bytes::new(b"tampered");

        assert!(!tx.verify(TEST_CHAIN_ID));
    }

    #[test]
    fn verify_succeeds_with_empty_data() {
        let key = PrivateKey::new();
        let tx = Transaction::new(b"".as_slice(), key, TEST_CHAIN_ID);
        assert!(tx.verify(TEST_CHAIN_ID));
    }

    #[test]
    fn verify_succeeds_with_large_data() {
        let key = PrivateKey::new();
        let large_data = vec![0xAB; 100_000];
        let tx = Transaction::new(large_data, key, TEST_CHAIN_ID);
        assert!(tx.verify(TEST_CHAIN_ID));
    }

    #[test]
    fn serialize_deserialize_roundtrip() {
        let key = PrivateKey::new();
        let binary_data: Vec<u8> = (0..=255).collect();
        let tx = Transaction::new(binary_data, key, TEST_CHAIN_ID);

        let encoded: Bytes = tx.to_bytes();
        let decoded = Transaction::from_bytes(encoded.as_slice()).expect("deserialization failed");

        assert_eq!(tx, decoded);
        assert!(decoded.verify(TEST_CHAIN_ID));
    }

    #[test]
    fn hash_is_deterministic() {
        let key = PrivateKey::new();
        let tx = Transaction::new(b"hash test", key, TEST_CHAIN_ID);

        let hash1 = tx.id(TEST_CHAIN_ID);
        let hash2 = tx.id(TEST_CHAIN_ID);

        assert_eq!(hash1, hash2, "rehashing twice");
        assert_eq!(tx.id(TEST_CHAIN_ID), hash1);
        assert_eq!(tx.id(TEST_CHAIN_ID), hash2);
    }

    #[test]
    fn same_data_different_keys_have_different_hashes() {
        let key1 = PrivateKey::new();
        let key2 = PrivateKey::new();
        let data = b"identical data";

        let tx1 = Transaction::new(data, key1, TEST_CHAIN_ID);
        let tx2 = Transaction::new(data, key2, TEST_CHAIN_ID);

        let hash1 = tx1.id(TEST_CHAIN_ID);
        let hash2 = tx2.id(TEST_CHAIN_ID);

        assert_ne!(hash1, hash2);
    }
}
