//! 32-byte SHA3-256 hash type with zero-allocation operations.

use blockchain_derive::BinaryCodec;
use sha3::{Digest, Sha3_256};
use std::fmt;

/// SHA3-256 hash length in bytes.
pub const HASH_LEN: usize = 32;

/// Fixed-size 32-byte hash used throughout the blockchain.
///
/// This type is `Copy` for performance - hashes are passed frequently during
/// block validation and should live on the stack to avoid heap allocations.
/// At 32 bytes, copying is cheaper than reference indirection on modern CPUs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, BinaryCodec, Default, Hash, Ord, PartialOrd)]
pub struct Hash(pub [u8; HASH_LEN]);

impl Hash {
    /// Creates a zero-valued hash (all bytes are 0x00).
    ///
    /// Used as a sentinel value for genesis blocks or uninitialized state.
    pub fn zero() -> Hash {
        Hash([0u8; HASH_LEN])
    }

    /// Returns the hash as a byte slice.
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Converts the hash into an owned byte vector.
    pub fn to_vec(self) -> Vec<u8> {
        Vec::<u8>::from(self.as_slice())
    }

    /// Computes SHA3-256 hash of the encoded representation.
    pub fn sha3_from_bytes(data: &[u8]) -> Hash {
        let mut hasher = Sha3_256::new();
        hasher.update(data);
        Hash(hasher.finalize().into())
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_vec_returns_correct_bytes() {
        let hash = Hash::sha3_from_bytes(b"test");
        let vec = hash.to_vec();
        assert_eq!(vec.len(), HASH_LEN);
        assert_eq!(vec.as_slice(), hash.as_slice());
    }

    #[test]
    fn to_vec_zero_hash() {
        let hash = Hash::zero();
        let vec = hash.to_vec();
        assert!(vec.iter().all(|&b| b == 0));
    }
}
