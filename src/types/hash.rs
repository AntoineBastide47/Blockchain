//! 32-byte SHA3-256 hash type with zero-allocation operations.

use crate::types::binary_codec::BinaryCodec;
use std::fmt;

/// SHA3-256 hash length in bytes.
pub const HASH_LEN: usize = 32;

/// Fixed-size 32-byte hash used throughout the blockchain.
///
/// This type is `Copy` for performance - hashes are passed frequently during
/// block validation and should live on the stack to avoid heap allocations.
/// At 32 bytes, copying is cheaper than reference indirection on modern CPUs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, BinaryCodec, Default, Hash)]
pub struct Hash(pub [u8; HASH_LEN]);

impl Hash {
    /// Creates a zero-valued hash (all bytes are 0x00).
    ///
    /// Used as a sentinel value for genesis blocks or uninitialized state.
    pub fn zero() -> Hash {
        Hash([0u8; HASH_LEN])
    }

    /// Creates a hash from a byte slice.
    ///
    /// Panics if the slice length is not exactly 32 bytes.
    pub fn from_bytes(b: &[u8]) -> Hash {
        if b.len() != HASH_LEN {
            panic!("expected {} bytes, got {} bytes", HASH_LEN, b.len());
        }

        let mut value = [0u8; HASH_LEN];
        value.copy_from_slice(b);
        Hash(value)
    }

    /// Creates a hash from a vector, consuming the vector.
    ///
    /// Panics if the vector length is not exactly 32 bytes.
    pub fn from_vec(b: Vec<u8>) -> Hash {
        Hash::from_bytes(b.as_slice())
    }

    /// Returns the hash as a byte slice.
    pub fn as_slice(&self) -> &[u8] {
        &self.0
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
