//! Schnorr signature key pairs on secp256k1.

use crate::types::address::Address;
use crate::types::serializable_bytes::SerializableBytes;
pub(crate) use crate::types::serializable_signature::SerializableSignature;
use borsh::{BorshDeserialize, BorshSerialize};
use k256::ecdsa::signature::Signer;
use k256::schnorr::signature::Verifier;
use k256::schnorr::{SigningKey, VerifyingKey};
use rand_core::OsRng;
use sha3::{Digest, Sha3_256};
use std::io::{Read, Write};

/// Private key for signing transactions.
///
/// Generated using cryptographically secure randomness from the OS.
/// Never serialized or transmitted over the network.
#[derive(Clone)]
pub struct PrivateKey {
    key: SigningKey,
}

/// Public key for signature verification and address derivation.
///
/// The address is derived by hashing the verifying key with SHA3-256 and
/// taking the last 20 bytes.
///
/// This type is `Copy` (52 bytes total: 32 for key + 20 for address) for performance.
/// Public keys are passed frequently during transaction validation, and stack
/// allocation avoids heap overhead and improves cache locality.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PublicKey {
    pub key: VerifyingKey,
    pub address: Address,
}

impl PrivateKey {
    /// Generates a new random private key using OS-provided entropy.
    pub fn new() -> Self {
        let mut rng = OsRng;
        Self {
            key: SigningKey::random(&mut rng),
        }
    }

    /// Creates a private key from raw bytes.
    ///
    /// Returns `None` if the bytes do not represent a valid scalar for secp256k1.
    pub fn from_bytes(bytes: &[u8; 32]) -> Option<Self> {
        SigningKey::from_bytes(bytes).ok().map(|key| Self { key })
    }

    /// Derives the corresponding public key.
    pub fn public_key(&self) -> PublicKey {
        PublicKey::new(self)
    }

    /// Signs arbitrary data, producing a Schnorr signature.
    pub fn sign(&self, data: &SerializableBytes) -> SerializableSignature {
        SerializableSignature(self.key.sign(data))
    }
}

impl PublicKey {
    /// Derives a public key from a private key and computes its address.
    ///
    /// Address derivation: SHA3-256(verifying_key_bytes)[12..32]
    pub(crate) fn new(private: &PrivateKey) -> Self {
        let vk = private.key.verifying_key();

        let mut hasher = Sha3_256::new();
        hasher.update(vk.to_bytes());
        let full: [u8; 32] = hasher.finalize().into();

        let mut addr = [0u8; 20];
        addr.copy_from_slice(&full[12..]);

        PublicKey {
            key: *vk,
            address: Address(addr),
        }
    }

    /// Returns the blockchain address derived from this public key.
    pub fn address(&self) -> Address {
        self.address
    }

    /// Verifies a Schnorr signature against the given data.
    ///
    /// Returns `true` if the signature is valid, `false` otherwise.
    pub fn verify(&self, data: &[u8], signature: SerializableSignature) -> bool {
        self.key.verify(data, &signature.0).is_ok()
    }
}

impl BorshSerialize for PublicKey {
    fn serialize<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        let key_bytes: [u8; 32] = self.key.to_bytes().into();
        key_bytes.serialize(writer)?;
        self.address.serialize(writer)
    }
}

impl BorshDeserialize for PublicKey {
    fn deserialize_reader<R: Read>(reader: &mut R) -> std::io::Result<Self> {
        let key_bytes = <[u8; 32]>::deserialize_reader(reader)?;
        let key = VerifyingKey::from_bytes(&key_bytes)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let address = Address::deserialize_reader(reader)?;
        Ok(PublicKey { key, address })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_verify_success() {
        let private = PrivateKey::new();
        let public = private.public_key();

        let data = "Hello World".as_bytes();
        let signature = private.sign(&SerializableBytes::from(data));
        assert!(public.verify(data, signature));
    }

    #[test]
    fn test_sign_verify_failure() {
        let private = PrivateKey::new();
        let public = private.public_key();
        let private_2 = PrivateKey::new();

        let data = "Hello World".as_bytes();
        let signature = private_2.sign(&SerializableBytes::from(data));
        assert!(!public.verify(data, signature));
    }

    #[test]
    fn test_sign_verify_failure_2() {
        let private = PrivateKey::new();
        let private_2 = PrivateKey::new();
        let public_2 = private_2.public_key();

        let data = "Hello World".as_bytes();
        let signature = private.sign(&SerializableBytes::from(data));
        assert!(!public_2.verify(data, signature));
    }

    #[test]
    fn test_verify_tampered_data() {
        let private = PrivateKey::new();
        let public = private.public_key();

        let original_data = "Hello World".as_bytes();
        let tampered_data = "Hello World!".as_bytes();
        let signature = private.sign(&SerializableBytes::from(original_data));

        assert!(!public.verify(tampered_data, signature));
    }

    #[test]
    fn test_verify_empty_data() {
        let private = PrivateKey::new();
        let public = private.public_key();

        let data = b"";
        let signature = private.sign(&SerializableBytes::from(data));
        assert!(public.verify(data, signature));
    }

    #[test]
    fn test_address_uniqueness() {
        let private1 = PrivateKey::new();
        let private2 = PrivateKey::new();
        let public1 = private1.public_key();
        let public2 = private2.public_key();

        assert_ne!(public1.address(), public2.address());
    }

    #[test]
    fn test_address_determinism() {
        let private = PrivateKey::new();
        let public1 = private.public_key();
        let public2 = private.public_key();

        assert_eq!(public1.address(), public2.address());
    }

    #[test]
    fn test_sign_large_data() {
        let private = PrivateKey::new();
        let public = private.public_key();

        let data = vec![0xAB; 10000];
        let signature = private.sign(&SerializableBytes::from(&data));
        assert!(public.verify(&data, signature));
    }

    #[test]
    fn from_bytes_with_valid_key() {
        let bytes: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];
        let key = PrivateKey::from_bytes(&bytes);
        assert!(key.is_some());
    }

    #[test]
    fn from_bytes_with_zero_key_fails() {
        let bytes: [u8; 32] = [0u8; 32];
        let key = PrivateKey::from_bytes(&bytes);
        assert!(key.is_none());
    }

    #[test]
    fn from_bytes_produces_deterministic_key() {
        let bytes: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];
        let key1 = PrivateKey::from_bytes(&bytes).unwrap();
        let key2 = PrivateKey::from_bytes(&bytes).unwrap();

        assert_eq!(key1.public_key().address(), key2.public_key().address());
    }

    #[test]
    fn from_bytes_sign_verify_roundtrip() {
        let bytes: [u8; 32] = [
            0xaa, 0xbb, 0xcc, 0xdd, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];
        let private = PrivateKey::from_bytes(&bytes).unwrap();
        let public = private.public_key();

        let data = b"test message";
        let signature = private.sign(&SerializableBytes::from(data));
        assert!(public.verify(data, signature));
    }

    #[test]
    fn from_bytes_different_bytes_different_keys() {
        let bytes1: [u8; 32] = [1u8; 32];
        let bytes2: [u8; 32] = [2u8; 32];

        let key1 = PrivateKey::from_bytes(&bytes1).unwrap();
        let key2 = PrivateKey::from_bytes(&bytes2).unwrap();

        assert_ne!(key1.public_key().address(), key2.public_key().address());
    }
}
