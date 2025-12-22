//! Transaction structure with reference-counted data storage.

use crate::crypto::key_pair::{PrivateKey, PublicKey, SerializableSignature};
use crate::types::binary_codec::BinaryCodecHash;
use crate::types::hash::Hash;
use crate::types::serializable_bytes::SerializableBytes;
use borsh::{BorshDeserialize, BorshSerialize};
use std::io::{Read, Write};

/// A blockchain transaction containing arbitrary data.
///
/// Uses `SerializableBytes` for zero-copy sharing - transactions are immutable after creation
/// and often referenced by multiple blocks during reorganizations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transaction {
    pub from: PublicKey,
    pub signature: SerializableSignature,
    pub data: SerializableBytes,
    pub hash: Hash,
}

impl Transaction {
    pub fn new(data: impl Into<SerializableBytes>, key: PrivateKey) -> std::io::Result<Self> {
        let data = data.into();
        let mut tx = Transaction {
            from: key.public_key(),
            signature: key.sign(&data),
            data,
            hash: Hash::zero(),
        };
        tx.hash = tx.hash()?;
        Ok(tx)
    }

    pub fn verify(&self) -> bool {
        self.from.verify(&self.data, self.signature)
    }
}

impl BorshSerialize for Transaction {
    fn serialize<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        self.from.serialize(writer)?;
        self.signature.serialize(writer)?;
        self.data.serialize(writer)?;
        Ok(())
    }
}

impl BorshDeserialize for Transaction {
    fn deserialize_reader<R: Read>(reader: &mut R) -> std::io::Result<Self> {
        let from = PublicKey::deserialize_reader(reader)?;
        let signature = SerializableSignature::deserialize_reader(reader)?;
        let data = SerializableBytes::deserialize_reader(reader)?;
        let mut tx = Self {
            from,
            signature,
            data,
            hash: Hash::zero(),
        };
        tx.hash = tx.hash()?;
        Ok(tx)
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
        let tx = Transaction::new(data.clone(), key).expect("Hashing failed");

        assert_eq!(tx.data, data);
        assert!(tx.verify());
    }

    #[test]
    fn verify_fails_with_wrong_public_key() {
        let key1 = PrivateKey::new();
        let key2 = PrivateKey::new();
        let data = SerializableBytes::from(b"payload".as_slice());

        let mut tx = Transaction::new(data, key1).expect("Hashing failed");
        tx.from = key2.public_key();

        assert!(!tx.verify());
    }

    #[test]
    fn verify_fails_with_tampered_data() {
        let key = PrivateKey::new();
        let mut tx = Transaction::new(b"original".as_slice(), key).expect("Hashing failed");
        tx.data = SerializableBytes::from(b"tampered".as_slice());

        assert!(!tx.verify());
    }

    #[test]
    fn verify_succeeds_with_empty_data() {
        let key = PrivateKey::new();
        let tx = Transaction::new(b"".as_slice(), key).expect("Hashing failed");
        assert!(tx.verify());
    }

    #[test]
    fn verify_succeeds_with_large_data() {
        let key = PrivateKey::new();
        let large_data = vec![0xAB; 100_000];
        let tx = Transaction::new(large_data.as_slice(), key).expect("Hashing failed");
        assert!(tx.verify());
    }

    #[test]
    fn serialize_deserialize_roundtrip() {
        let key = PrivateKey::new();
        let binary_data: Vec<u8> = (0..=255).collect();
        let tx = Transaction::new(binary_data.as_slice(), key).expect("Hashing failed");

        let encoded = borsh::to_vec(&tx).expect("serialization failed");
        let decoded = Transaction::try_from_slice(&encoded).expect("deserialization failed");

        assert_eq!(tx, decoded);
        assert!(decoded.verify());
    }

    #[test]
    fn hash_is_deterministic() {
        let key = PrivateKey::new();
        let tx = Transaction::new(b"hash test".as_slice(), key).expect("Hashing failed");

        let hash1 = tx.hash().expect("Hashing failed");
        let hash2 = tx.hash().expect("Hashing failed");

        assert_eq!(hash1, hash2, "rehashing twice");
        assert_eq!(tx.hash, hash1);
        assert_eq!(tx.hash, hash2);
    }

    #[test]
    fn same_data_different_keys_have_different_hashes() {
        let key1 = PrivateKey::new();
        let key2 = PrivateKey::new();
        let data = b"identical data";

        let tx1 = Transaction::new(data.as_slice(), key1).expect("Hashing failed");
        let tx2 = Transaction::new(data.as_slice(), key2).expect("Hashing failed");

        let hash1 = tx1.hash().expect("Hashing failed");
        let hash2 = tx2.hash().expect("Hashing failed");

        assert_ne!(hash1, hash2);
    }
}
