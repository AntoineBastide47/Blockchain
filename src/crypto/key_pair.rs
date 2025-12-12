//! Schnorr signature key pairs on secp256k1.

use crate::types::address::Address;
use k256::ecdsa::signature::Signer;
use k256::schnorr::signature::Verifier;
use k256::schnorr::{Signature, SigningKey, VerifyingKey};
use rand_core::OsRng;
use sha3::{Digest, Sha3_256};

/// Private key for signing transactions.
///
/// Generated using cryptographically secure randomness from the OS.
/// Never serialized or transmitted over the network.
struct PrivateKey {
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
#[derive(Copy, Clone)]
struct PublicKey {
    pub key: VerifyingKey,
    address: Address,
}

impl PrivateKey {
    /// Generates a new random private key using OS-provided entropy.
    pub fn new() -> PrivateKey {
        let mut rng = OsRng;
        PrivateKey {
            key: SigningKey::random(&mut rng),
        }
    }

    /// Derives the corresponding public key.
    pub fn public_key(&self) -> PublicKey {
        PublicKey::new(&self)
    }

    /// Signs arbitrary data, producing a Schnorr signature.
    pub fn sign(&self, data: &[u8]) -> Signature {
        self.key.sign(&data)
    }
}

impl PublicKey {
    /// Derives a public key from a private key and computes its address.
    ///
    /// Address derivation: SHA3-256(verifying_key_bytes)[12..32]
    pub(crate) fn new(private: &PrivateKey) -> PublicKey {
        let vk = private.key.verifying_key();

        let mut hasher = Sha3_256::new();
        hasher.update(&vk.to_bytes());
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
    pub fn verify(&self, data: &[u8], signature: Signature) -> bool {
        self.key.verify(data, &signature).is_ok()
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
        let signature = private.sign(data);
        assert_eq!(true, public.verify(data, signature));
    }

    #[test]
    fn test_sign_verify_failure() {
        let private = PrivateKey::new();
        let public = private.public_key();
        let private_2 = PrivateKey::new();

        let data = "Hello World".as_bytes();
        let signature = private_2.sign(data);
        assert_ne!(true, public.verify(data, signature));
    }

    #[test]
    fn test_sign_verify_failure_2() {
        let private = PrivateKey::new();
        let private_2 = PrivateKey::new();
        let public_2 = private_2.public_key();

        let data = "Hello World".as_bytes();
        let signature = private.sign(data);
        assert_ne!(true, public_2.verify(data, signature));
    }

    #[test]
    fn test_verify_tampered_data() {
        let private = PrivateKey::new();
        let public = private.public_key();

        let original_data = "Hello World".as_bytes();
        let tampered_data = "Hello World!".as_bytes();
        let signature = private.sign(original_data);

        assert_eq!(false, public.verify(tampered_data, signature));
    }

    #[test]
    fn test_verify_empty_data() {
        let private = PrivateKey::new();
        let public = private.public_key();

        let data = b"";
        let signature = private.sign(data);
        assert_eq!(true, public.verify(data, signature));
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
        let signature = private.sign(&data);
        assert_eq!(true, public.verify(&data, signature));
    }
}
