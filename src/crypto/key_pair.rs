//! Schnorr signature key pairs on secp256k1.

use crate::info;
use crate::types::address::{ADDRESS_SIZE, Address};
use crate::types::encoding::{Decode, DecodeError, Encode, EncodeSink};
pub(crate) use crate::types::serializable_signature::SerializableSignature;
use argon2::Argon2;
use chacha20poly1305::{
    XChaCha20Poly1305,
    aead::{Aead, KeyInit},
};
use k256::ecdsa::signature::Signer;
use k256::schnorr::signature::Verifier;
use k256::schnorr::{SigningKey, VerifyingKey};
use rand_core::{OsRng, RngCore};
use sha3::{Digest, Sha3_256};
use std::fs;
use std::io;
use std::path::PathBuf;
use zeroize::Zeroizing;

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

    /// Returns the raw bytes of the private key.
    ///
    /// **Security**: Handle with care. These bytes should be zeroized after use
    /// and never logged or transmitted.
    fn to_bytes(&self) -> [u8; 32] {
        self.key.to_bytes().into()
    }

    /// Derives the corresponding public key.
    pub fn public_key(&self) -> PublicKey {
        PublicKey::new(self)
    }

    /// Signs arbitrary data, producing a Schnorr signature.
    pub fn sign(&self, data: &[u8]) -> SerializableSignature {
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

        let mut addr = [0u8; ADDRESS_SIZE];
        addr.copy_from_slice(&full[12..]);

        PublicKey {
            key: *vk,
            address: Address(addr),
        }
    }

    /// Verifies a Schnorr signature against the given data.
    ///
    /// Returns `true` if the signature is valid, `false` otherwise.
    pub fn verify(&self, data: &[u8], signature: SerializableSignature) -> bool {
        self.key.verify(data, &signature.0).is_ok()
    }
}

impl Encode for PublicKey {
    fn encode<S: EncodeSink>(&self, out: &mut S) {
        out.write(&self.key.to_bytes());
    }
}

impl Decode for PublicKey {
    fn decode(input: &mut &[u8]) -> Result<Self, DecodeError> {
        let key_bytes = <[u8; 32]>::decode(input)?;
        let key = VerifyingKey::from_bytes(&key_bytes).map_err(|_| DecodeError::InvalidValue)?;

        // Derive address for key to maintain the invariance
        let mut hasher = Sha3_256::new();
        hasher.update(key.to_bytes());
        let full: [u8; 32] = hasher.finalize().into();
        let mut address = [0u8; ADDRESS_SIZE];
        address.copy_from_slice(&full[12..]);

        Ok(PublicKey {
            key,
            address: Address(address),
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Encrypted Validator Key Persistence
// ─────────────────────────────────────────────────────────────────────────────

/// Magic bytes identifying a validator key file.
const VALIDATOR_KEY_MAGIC: &[u8; 4] = b"BVAL";

/// Current version of the validator key file format.
const VALIDATOR_KEY_VERSION: u8 = 1;

/// Length of the Argon2id salt in bytes.
const SALT_LEN: usize = 32;

/// Length of the XChaCha20-Poly1305 nonce in bytes.
const NONCE_LEN: usize = 24;

/// Returns the path to the validator key file for the given node.
///
/// Path: `~/.blockchain/{chain_id}/{node_name}/validator.key`
fn validator_key_path(chain_id: u64, node_name: &str) -> io::Result<PathBuf> {
    let home =
        dirs::home_dir().ok_or_else(|| io::Error::other("cannot determine home directory"))?;
    Ok(home
        .join(".blockchain")
        .join(chain_id.to_string())
        .join(node_name)
        .join("validator.key"))
}

/// Derives a 32-byte encryption key from a passphrase and salt using Argon2id.
fn derive_key(passphrase: &[u8], salt: &[u8]) -> io::Result<Zeroizing<[u8; 32]>> {
    let mut key = Zeroizing::new([0u8; 32]);
    Argon2::default()
        .hash_password_into(passphrase, salt, key.as_mut())
        .map_err(|e| io::Error::other(format!("argon2 key derivation failed: {e}")))?;
    Ok(key)
}

/// Encrypts and saves a validator private key to disk.
///
/// File format: `[4B magic][1B version][32B salt][24B nonce][ciphertext+16B tag]`
fn save_encrypted_validator_key(
    key: &PrivateKey,
    path: &PathBuf,
    passphrase: &[u8],
) -> io::Result<()> {
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);

    let derived = derive_key(passphrase, &salt)?;
    let cipher = XChaCha20Poly1305::new(derived.as_ref().into());

    let plaintext = Zeroizing::new(key.to_bytes());
    let ciphertext = cipher
        .encrypt(nonce.as_ref().into(), plaintext.as_ref())
        .map_err(|e| io::Error::other(format!("encryption failed: {e}")))?;

    let mut data = Vec::with_capacity(4 + 1 + SALT_LEN + NONCE_LEN + ciphertext.len());
    data.extend_from_slice(VALIDATOR_KEY_MAGIC);
    data.push(VALIDATOR_KEY_VERSION);
    data.extend_from_slice(&salt);
    data.extend_from_slice(&nonce);
    data.extend_from_slice(&ciphertext);

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, &data)?;

    info!("Validator key saved to {}", path.display());
    Ok(())
}

/// Loads and decrypts a validator private key from disk.
///
/// Returns an error if the file is corrupt, the passphrase is wrong, or the
/// format version is unsupported.
fn load_encrypted_validator_key(path: &PathBuf, passphrase: &[u8]) -> io::Result<PrivateKey> {
    let data = fs::read(path)?;

    const HEADER_LEN: usize = 4 + 1 + SALT_LEN + NONCE_LEN;
    if data.len() < HEADER_LEN + 16 {
        return Err(io::Error::other("validator key file too short"));
    }
    if &data[0..4] != VALIDATOR_KEY_MAGIC {
        return Err(io::Error::other("invalid validator key file magic"));
    }
    if data[4] != VALIDATOR_KEY_VERSION {
        return Err(io::Error::other(format!(
            "unsupported validator key file version: {}",
            data[4]
        )));
    }

    let salt = &data[5..5 + SALT_LEN];
    let nonce = &data[5 + SALT_LEN..5 + SALT_LEN + NONCE_LEN];
    let ciphertext = &data[HEADER_LEN..];

    let derived = derive_key(passphrase, salt)?;
    let cipher = XChaCha20Poly1305::new(derived.as_ref().into());

    let plaintext = cipher
        .decrypt(nonce.into(), ciphertext)
        .map_err(|_| io::Error::other("decryption failed: wrong passphrase or corrupt file"))?;

    if plaintext.len() != 32 {
        return Err(io::Error::other("decrypted key has invalid length"));
    }

    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&plaintext);

    PrivateKey::from_bytes(&key_bytes)
        .ok_or_else(|| io::Error::other("decrypted bytes are not a valid private key"))
}

/// Loads an existing validator key or generates a new one.
///
/// If the key file exists, it is decrypted with the passphrase and returned.
/// If it does not exist, a new random key is generated, encrypted, and saved.
///
/// # Errors
/// Returns an error if:
/// - The key file exists but cannot be decrypted (wrong passphrase or corrupt)
/// - The key file cannot be written (filesystem error)
pub fn load_or_generate_validator_key(
    chain_id: u64,
    node_name: &str,
    passphrase: &[u8],
) -> io::Result<PrivateKey> {
    let path = validator_key_path(chain_id, node_name)?;

    if path.exists() {
        info!("Loading validator key from {}", path.display());
        load_encrypted_validator_key(&path, passphrase)
    } else {
        info!("Generating new validator key");
        let key = PrivateKey::new();
        save_encrypted_validator_key(&key, &path, passphrase)?;
        Ok(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::bytes::Bytes;

    #[test]
    fn test_sign_verify_success() {
        let private = PrivateKey::new();
        let public = private.public_key();

        let data = "Hello World".as_bytes();
        let signature = private.sign(&Bytes::from(data));
        assert!(public.verify(data, signature));
    }

    #[test]
    fn test_sign_verify_failure() {
        let private = PrivateKey::new();
        let public = private.public_key();
        let private_2 = PrivateKey::new();

        let data = "Hello World".as_bytes();
        let signature = private_2.sign(&Bytes::from(data));
        assert!(!public.verify(data, signature));
    }

    #[test]
    fn test_sign_verify_failure_2() {
        let private = PrivateKey::new();
        let private_2 = PrivateKey::new();
        let public_2 = private_2.public_key();

        let data = "Hello World".as_bytes();
        let signature = private.sign(&Bytes::from(data));
        assert!(!public_2.verify(data, signature));
    }

    #[test]
    fn test_verify_tampered_data() {
        let private = PrivateKey::new();
        let public = private.public_key();

        let original_data = "Hello World".as_bytes();
        let tampered_data = "Hello World!".as_bytes();
        let signature = private.sign(&Bytes::from(original_data));

        assert!(!public.verify(tampered_data, signature));
    }

    #[test]
    fn test_verify_empty_data() {
        let private = PrivateKey::new();
        let public = private.public_key();

        let data = b"";
        let signature = private.sign(&Bytes::from(data));
        assert!(public.verify(data, signature));
    }

    #[test]
    fn test_address_uniqueness() {
        let private1 = PrivateKey::new();
        let private2 = PrivateKey::new();
        let public1 = private1.public_key();
        let public2 = private2.public_key();

        assert_ne!(public1.address, public2.address);
    }

    #[test]
    fn test_address_determinism() {
        let private = PrivateKey::new();
        let public1 = private.public_key();
        let public2 = private.public_key();

        assert_eq!(public1.address, public2.address);
    }

    #[test]
    fn test_sign_large_data() {
        let private = PrivateKey::new();
        let public = private.public_key();

        let data = vec![0xAB; 10000];
        let signature = private.sign(&Bytes::from(data.clone()));
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

        assert_eq!(key1.public_key().address, key2.public_key().address);
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
        let signature = private.sign(&Bytes::from(data));
        assert!(public.verify(data, signature));
    }

    #[test]
    fn from_bytes_different_bytes_different_keys() {
        let bytes1: [u8; 32] = [1u8; 32];
        let bytes2: [u8; 32] = [2u8; 32];

        let key1 = PrivateKey::from_bytes(&bytes1).unwrap();
        let key2 = PrivateKey::from_bytes(&bytes2).unwrap();

        assert_ne!(key1.public_key().address, key2.public_key().address);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Encrypted Validator Key Persistence Tests
    // ─────────────────────────────────────────────────────────────────────────

    use std::fs;
    use tempfile::tempdir;

    fn test_key_path(dir: &std::path::Path) -> PathBuf {
        dir.join("test_validator.key")
    }

    #[test]
    fn derive_key_deterministic() {
        let passphrase = b"test_passphrase";
        let salt = [0xABu8; SALT_LEN];

        let key1 = derive_key(passphrase, &salt).unwrap();
        let key2 = derive_key(passphrase, &salt).unwrap();

        assert_eq!(key1.as_ref(), key2.as_ref());
    }

    #[test]
    fn derive_key_different_salts_produce_different_keys() {
        let passphrase = b"test_passphrase";
        let salt1 = [0xAAu8; SALT_LEN];
        let salt2 = [0xBBu8; SALT_LEN];

        let key1 = derive_key(passphrase, &salt1).unwrap();
        let key2 = derive_key(passphrase, &salt2).unwrap();

        assert_ne!(key1.as_ref(), key2.as_ref());
    }

    #[test]
    fn derive_key_different_passphrases_produce_different_keys() {
        let salt = [0xABu8; SALT_LEN];

        let key1 = derive_key(b"passphrase_one", &salt).unwrap();
        let key2 = derive_key(b"passphrase_two", &salt).unwrap();

        assert_ne!(key1.as_ref(), key2.as_ref());
    }

    #[test]
    fn save_and_load_roundtrip() {
        let dir = tempdir().unwrap();
        let path = test_key_path(dir.path());
        let passphrase = b"secure_passphrase_123";

        let original_key = PrivateKey::new();
        let original_address = original_key.public_key().address;

        save_encrypted_validator_key(&original_key, &path, passphrase).unwrap();
        assert!(path.exists());

        let loaded_key = load_encrypted_validator_key(&path, passphrase).unwrap();
        let loaded_address = loaded_key.public_key().address;

        assert_eq!(original_address, loaded_address);
    }

    #[test]
    fn save_and_load_preserves_signing_capability() {
        let dir = tempdir().unwrap();
        let path = test_key_path(dir.path());
        let passphrase = b"test_pass";

        let original_key = PrivateKey::new();
        save_encrypted_validator_key(&original_key, &path, passphrase).unwrap();

        let loaded_key = load_encrypted_validator_key(&path, passphrase).unwrap();

        let data = b"message to sign";
        let signature = loaded_key.sign(&Bytes::from(data));
        assert!(original_key.public_key().verify(data, signature));
    }

    #[test]
    fn wrong_passphrase_fails_decryption() {
        let dir = tempdir().unwrap();
        let path = test_key_path(dir.path());

        let key = PrivateKey::new();
        save_encrypted_validator_key(&key, &path, b"correct_passphrase").unwrap();

        let result = load_encrypted_validator_key(&path, b"wrong_passphrase");
        assert!(result.is_err());
        assert!(
            result
                .err()
                .unwrap()
                .to_string()
                .contains("decryption failed")
        );
    }

    #[test]
    fn empty_passphrase_works() {
        let dir = tempdir().unwrap();
        let path = test_key_path(dir.path());
        let passphrase = b"";

        let original_key = PrivateKey::new();
        save_encrypted_validator_key(&original_key, &path, passphrase).unwrap();

        let loaded_key = load_encrypted_validator_key(&path, passphrase).unwrap();
        assert_eq!(
            original_key.public_key().address,
            loaded_key.public_key().address
        );
    }

    #[test]
    fn unicode_passphrase_works() {
        let dir = tempdir().unwrap();
        let path = test_key_path(dir.path());
        let passphrase = "日本語パスワード🔐".as_bytes();

        let original_key = PrivateKey::new();
        save_encrypted_validator_key(&original_key, &path, passphrase).unwrap();

        let loaded_key = load_encrypted_validator_key(&path, passphrase).unwrap();
        assert_eq!(
            original_key.public_key().address,
            loaded_key.public_key().address
        );
    }

    #[test]
    fn truncated_file_fails() {
        let dir = tempdir().unwrap();
        let path = test_key_path(dir.path());

        let key = PrivateKey::new();
        save_encrypted_validator_key(&key, &path, b"passphrase").unwrap();

        // Truncate file to be too short
        let data = fs::read(&path).unwrap();
        fs::write(&path, &data[..20]).unwrap();

        let result = load_encrypted_validator_key(&path, b"passphrase");
        assert!(result.is_err());
        assert!(result.err().unwrap().to_string().contains("too short"));
    }

    #[test]
    fn invalid_magic_fails() {
        let dir = tempdir().unwrap();
        let path = test_key_path(dir.path());

        let key = PrivateKey::new();
        save_encrypted_validator_key(&key, &path, b"passphrase").unwrap();

        // Corrupt magic bytes
        let mut data = fs::read(&path).unwrap();
        data[0] = 0xFF;
        data[1] = 0xFF;
        fs::write(&path, &data).unwrap();

        let result = load_encrypted_validator_key(&path, b"passphrase");
        assert!(result.is_err());
        assert!(
            result
                .err()
                .unwrap()
                .to_string()
                .contains("invalid validator key file magic")
        );
    }

    #[test]
    fn unsupported_version_fails() {
        let dir = tempdir().unwrap();
        let path = test_key_path(dir.path());

        let key = PrivateKey::new();
        save_encrypted_validator_key(&key, &path, b"passphrase").unwrap();

        // Change version byte to unsupported version
        let mut data = fs::read(&path).unwrap();
        data[4] = 99;
        fs::write(&path, &data).unwrap();

        let result = load_encrypted_validator_key(&path, b"passphrase");
        assert!(result.is_err());
        assert!(
            result
                .err()
                .unwrap()
                .to_string()
                .contains("unsupported validator key file version")
        );
    }

    #[test]
    fn corrupted_ciphertext_fails() {
        let dir = tempdir().unwrap();
        let path = test_key_path(dir.path());

        let key = PrivateKey::new();
        save_encrypted_validator_key(&key, &path, b"passphrase").unwrap();

        // Corrupt ciphertext (after header)
        let mut data = fs::read(&path).unwrap();
        let header_len = 4 + 1 + SALT_LEN + NONCE_LEN;
        if data.len() > header_len + 5 {
            data[header_len + 5] ^= 0xFF;
        }
        fs::write(&path, &data).unwrap();

        let result = load_encrypted_validator_key(&path, b"passphrase");
        assert!(result.is_err());
        assert!(
            result
                .err()
                .unwrap()
                .to_string()
                .contains("decryption failed")
        );
    }

    #[test]
    fn corrupted_nonce_fails() {
        let dir = tempdir().unwrap();
        let path = test_key_path(dir.path());

        let key = PrivateKey::new();
        save_encrypted_validator_key(&key, &path, b"passphrase").unwrap();

        // Corrupt nonce
        let mut data = fs::read(&path).unwrap();
        let nonce_offset = 4 + 1 + SALT_LEN;
        data[nonce_offset] ^= 0xFF;
        fs::write(&path, &data).unwrap();

        let result = load_encrypted_validator_key(&path, b"passphrase");
        assert!(result.is_err());
    }

    #[test]
    fn corrupted_salt_fails() {
        let dir = tempdir().unwrap();
        let path = test_key_path(dir.path());

        let key = PrivateKey::new();
        save_encrypted_validator_key(&key, &path, b"passphrase").unwrap();

        // Corrupt salt (changes derived key)
        let mut data = fs::read(&path).unwrap();
        data[5] ^= 0xFF;
        fs::write(&path, &data).unwrap();

        let result = load_encrypted_validator_key(&path, b"passphrase");
        assert!(result.is_err());
        assert!(
            result
                .err()
                .unwrap()
                .to_string()
                .contains("decryption failed")
        );
    }

    #[test]
    fn load_nonexistent_file_fails() {
        let path = PathBuf::from("/nonexistent/path/validator.key");
        let result = load_encrypted_validator_key(&path, b"passphrase");
        assert!(result.is_err());
    }

    #[test]
    fn save_creates_parent_directories() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("nested").join("dirs").join("validator.key");

        let key = PrivateKey::new();
        save_encrypted_validator_key(&key, &path, b"passphrase").unwrap();

        assert!(path.exists());
    }

    #[test]
    fn overwrite_existing_key() {
        let dir = tempdir().unwrap();
        let path = test_key_path(dir.path());

        let key1 = PrivateKey::new();
        let key2 = PrivateKey::new();

        save_encrypted_validator_key(&key1, &path, b"pass1").unwrap();
        save_encrypted_validator_key(&key2, &path, b"pass2").unwrap();

        // Should load key2 with pass2
        let loaded = load_encrypted_validator_key(&path, b"pass2").unwrap();
        assert_eq!(key2.public_key().address, loaded.public_key().address);

        // pass1 should no longer work
        let result = load_encrypted_validator_key(&path, b"pass1");
        assert!(result.is_err());
    }

    #[test]
    fn file_format_correct_length() {
        let dir = tempdir().unwrap();
        let path = test_key_path(dir.path());

        let key = PrivateKey::new();
        save_encrypted_validator_key(&key, &path, b"passphrase").unwrap();

        let data = fs::read(&path).unwrap();
        // magic(4) + version(1) + salt(32) + nonce(24) + ciphertext(32) + tag(16)
        let expected_len = 4 + 1 + SALT_LEN + NONCE_LEN + 32 + 16;
        assert_eq!(data.len(), expected_len);
    }

    #[test]
    fn file_has_correct_magic() {
        let dir = tempdir().unwrap();
        let path = test_key_path(dir.path());

        let key = PrivateKey::new();
        save_encrypted_validator_key(&key, &path, b"passphrase").unwrap();

        let data = fs::read(&path).unwrap();
        assert_eq!(&data[0..4], VALIDATOR_KEY_MAGIC);
    }

    #[test]
    fn file_has_correct_version() {
        let dir = tempdir().unwrap();
        let path = test_key_path(dir.path());

        let key = PrivateKey::new();
        save_encrypted_validator_key(&key, &path, b"passphrase").unwrap();

        let data = fs::read(&path).unwrap();
        assert_eq!(data[4], VALIDATOR_KEY_VERSION);
    }

    #[test]
    fn each_save_produces_different_ciphertext() {
        let dir = tempdir().unwrap();
        let path1 = dir.path().join("key1.key");
        let path2 = dir.path().join("key2.key");

        let key = PrivateKey::new();

        save_encrypted_validator_key(&key, &path1, b"same_passphrase").unwrap();
        save_encrypted_validator_key(&key, &path2, b"same_passphrase").unwrap();

        let data1 = fs::read(&path1).unwrap();
        let data2 = fs::read(&path2).unwrap();

        // Salt and nonce should be different, making entire file different
        assert_ne!(data1, data2);

        // But both should decrypt to the same key
        let loaded1 = load_encrypted_validator_key(&path1, b"same_passphrase").unwrap();
        let loaded2 = load_encrypted_validator_key(&path2, b"same_passphrase").unwrap();
        assert_eq!(loaded1.public_key().address, loaded2.public_key().address);
    }

    #[test]
    fn long_passphrase_works() {
        let dir = tempdir().unwrap();
        let path = test_key_path(dir.path());
        let passphrase = vec![b'a'; 10000];

        let original_key = PrivateKey::new();
        save_encrypted_validator_key(&original_key, &path, &passphrase).unwrap();

        let loaded_key = load_encrypted_validator_key(&path, &passphrase).unwrap();
        assert_eq!(
            original_key.public_key().address,
            loaded_key.public_key().address
        );
    }

    #[test]
    fn binary_passphrase_works() {
        let dir = tempdir().unwrap();
        let path = test_key_path(dir.path());
        let passphrase: Vec<u8> = (0u8..=255).collect();

        let original_key = PrivateKey::new();
        save_encrypted_validator_key(&original_key, &path, &passphrase).unwrap();

        let loaded_key = load_encrypted_validator_key(&path, &passphrase).unwrap();
        assert_eq!(
            original_key.public_key().address,
            loaded_key.public_key().address
        );
    }
}
