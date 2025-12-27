//! Transaction structure with reference-counted data storage.

use crate::crypto::key_pair::{PrivateKey, PublicKey, SerializableSignature};
use crate::types::binary_codec::BinaryCodecHash;
use crate::types::bytes::Bytes;
use crate::types::encoding::{Decode, DecodeError, Encode, EncodeSink};
use crate::types::hash::Hash;

/// A blockchain transaction containing arbitrary data.
///
/// Uses `Bytes` for zero-copy sharing - transactions are immutable after creation
/// and often referenced by multiple blocks during reorganizations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transaction {
    pub from: PublicKey,
    pub signature: SerializableSignature,
    pub data: Bytes,
    pub hash: Hash,
}

impl Transaction {
    pub fn new(data: impl Into<Bytes>, key: PrivateKey) -> Self {
        let data = data.into();
        let mut tx = Transaction {
            from: key.public_key(),
            signature: key.sign(&data),
            data,
            hash: Hash::zero(),
        };
        tx.hash = tx.hash();
        tx
    }

    pub fn verify(&self) -> bool {
        self.from.verify(&self.data, self.signature)
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
        let from = PublicKey::decode(input)?;
        let signature = SerializableSignature::decode(input)?;
        let data = Bytes::decode(input)?;
        let mut tx = Self {
            from,
            signature,
            data,
            hash: Hash::zero(),
        };
        tx.hash = tx.hash();
        Ok(tx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::binary_codec::BinaryCodecHash;

    #[test]
    fn new_creates_valid_transaction() {
        let key = PrivateKey::new();
        let data = Bytes::new(b"test data");
        let tx = Transaction::new(data.clone(), key);

        assert_eq!(tx.data, data);
        assert!(tx.verify());
    }

    #[test]
    fn verify_fails_with_wrong_public_key() {
        let key1 = PrivateKey::new();
        let key2 = PrivateKey::new();
        let data = Bytes::new(b"payload");

        let mut tx = Transaction::new(data, key1);
        tx.from = key2.public_key();

        assert!(!tx.verify());
    }

    #[test]
    fn verify_fails_with_tampered_data() {
        let key = PrivateKey::new();
        let mut tx = Transaction::new(b"original".as_slice(), key);
        tx.data = Bytes::new(b"tampered");

        assert!(!tx.verify());
    }

    #[test]
    fn verify_succeeds_with_empty_data() {
        let key = PrivateKey::new();
        let tx = Transaction::new(b"".as_slice(), key);
        assert!(tx.verify());
    }

    #[test]
    fn verify_succeeds_with_large_data() {
        let key = PrivateKey::new();
        let large_data = vec![0xAB; 100_000];
        let tx = Transaction::new(large_data, key);
        assert!(tx.verify());
    }

    #[test]
    fn serialize_deserialize_roundtrip() {
        let key = PrivateKey::new();
        let binary_data: Vec<u8> = (0..=255).collect();
        let tx = Transaction::new(binary_data, key);

        let encoded: Bytes = tx.to_bytes();
        let decoded = Transaction::from_bytes(encoded.as_slice()).expect("deserialization failed");

        assert_eq!(tx, decoded);
        assert!(decoded.verify());
    }

    #[test]
    fn hash_is_deterministic() {
        let key = PrivateKey::new();
        let tx = Transaction::new(b"hash test", key);

        let hash1 = tx.hash();
        let hash2 = tx.hash();

        assert_eq!(hash1, hash2, "rehashing twice");
        assert_eq!(tx.hash, hash1);
        assert_eq!(tx.hash, hash2);
    }

    #[test]
    fn same_data_different_keys_have_different_hashes() {
        let key1 = PrivateKey::new();
        let key2 = PrivateKey::new();
        let data = b"identical data";

        let tx1 = Transaction::new(data, key1);
        let tx2 = Transaction::new(data, key2);

        let hash1 = tx1.hash();
        let hash2 = tx2.hash();

        assert_ne!(hash1, hash2);
    }
}
