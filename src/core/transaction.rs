//! Transaction structure with reference-counted data storage.

use crate::crypto::key_pair::{PrivateKey, PublicKey, SerializableSignature};
use crate::types::serializable_bytes::SerializableBytes;
use blockchain_derive::BinaryCodec;

/// A blockchain transaction containing arbitrary data.
///
/// Uses `SerializableBytes` for zero-copy sharing - transactions are immutable after creation
/// and often referenced by multiple blocks during reorganizations.
#[derive(Debug, PartialEq, Eq, BinaryCodec)]
pub struct Transaction {
    pub from: PublicKey,
    pub signature: SerializableSignature,
    pub data: SerializableBytes,
}

impl Transaction {
    pub fn new(data: SerializableBytes, key: PrivateKey) -> Self {
        Transaction {
            from: key.public_key(),
            signature: key.sign(&data),
            data,
        }
    }

    pub fn verify(&self) -> bool {
        self.from.verify(&self.data, self.signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::binary_codec::BinaryCodecHash;
    use borsh::BorshDeserialize;

    #[test]
    fn new_creates_valid_transaction() {
        let key = PrivateKey::new();
        let data = SerializableBytes::from(b"test data".as_slice());
        let tx = Transaction::new(data.clone(), key);

        assert_eq!(tx.data, data);
        assert!(tx.verify());
    }

    #[test]
    fn verify_fails_with_wrong_public_key() {
        let key1 = PrivateKey::new();
        let key2 = PrivateKey::new();
        let data = SerializableBytes::from(b"payload".as_slice());

        let mut tx = Transaction::new(data, key1);
        tx.from = key2.public_key();

        assert!(!tx.verify());
    }

    #[test]
    fn verify_fails_with_tampered_data() {
        let key = PrivateKey::new();
        let mut tx = Transaction::new(SerializableBytes::from(b"original".as_slice()), key);
        tx.data = SerializableBytes::from(b"tampered".as_slice());

        assert!(!tx.verify());
    }

    #[test]
    fn verify_succeeds_with_empty_data() {
        let key = PrivateKey::new();
        let tx = Transaction::new(SerializableBytes::from(b"".as_slice()), key);
        assert!(tx.verify());
    }

    #[test]
    fn verify_succeeds_with_large_data() {
        let key = PrivateKey::new();
        let large_data = vec![0xAB; 100_000];
        let tx = Transaction::new(SerializableBytes::from(large_data.as_slice()), key);
        assert!(tx.verify());
    }

    #[test]
    fn serialize_deserialize_roundtrip() {
        let key = PrivateKey::new();
        let binary_data: Vec<u8> = (0..=255).collect();
        let tx = Transaction::new(SerializableBytes::from(binary_data.as_slice()), key);

        let encoded = borsh::to_vec(&tx).expect("serialization failed");
        let decoded = Transaction::try_from_slice(&encoded).expect("deserialization failed");

        assert_eq!(tx, decoded);
        assert!(decoded.verify());
    }

    #[test]
    fn hash_is_deterministic() {
        let key = PrivateKey::new();
        let tx = Transaction::new(SerializableBytes::from(b"hash test".as_slice()), key);

        let hash1 = tx.hash().expect("hash failed");
        let hash2 = tx.hash().expect("hash failed");

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn same_data_different_keys_have_different_hashes() {
        let key1 = PrivateKey::new();
        let key2 = PrivateKey::new();
        let data = b"identical data";

        let tx1 = Transaction::new(SerializableBytes::from(data.as_slice()), key1);
        let tx2 = Transaction::new(SerializableBytes::from(data.as_slice()), key2);

        let hash1 = tx1.hash().expect("hash failed");
        let hash2 = tx2.hash().expect("hash failed");

        assert_ne!(hash1, hash2);
    }
}
