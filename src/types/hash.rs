//! 32-byte SHA3-256 hash type with zero-allocation operations.

use crate::types::encoding::EncodeSink;
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

    /// Creates a new SHA3-256 hash builder for incremental hashing.
    ///
    /// Use this for streaming data or when computing hashes over multiple inputs
    /// without intermediate allocations.
    pub fn sha3() -> HashBuilder {
        HashBuilder::new()
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

/// Incremental SHA3-256 hash builder.
///
/// Allows feeding data in chunks and finalizing to produce a [`Hash`].
/// Implements [`EncodeSink`] so encodable types can be hashed directly
/// without intermediate byte buffers.
pub struct HashBuilder {
    hasher: Sha3_256,
}

impl HashBuilder {
    /// Creates a new hash builder with empty state.
    pub fn new() -> Self {
        Self {
            hasher: Sha3_256::new(),
        }
    }

    /// Feeds data into the hash computation.
    pub fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    /// Consumes the builder and returns the final hash.
    pub fn finalize(self) -> Hash {
        Hash(self.hasher.finalize().into())
    }
}

impl EncodeSink for HashBuilder {
    fn write(&mut self, bytes: &[u8]) {
        self.hasher.update(bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_vec_returns_correct_bytes() {
        let mut h = Hash::sha3();
        h.update(b"test");
        let hash = h.finalize();
        let vec = hash.0.to_vec();
        assert_eq!(vec.len(), HASH_LEN);
        assert_eq!(vec.as_slice(), hash.as_slice());
    }

    #[test]
    fn to_vec_zero_hash() {
        let hash = Hash::zero();
        let vec = hash.0.to_vec();
        assert!(vec.iter().all(|&b| b == 0));
    }
}
