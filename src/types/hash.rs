//! 32-byte SHA3-256 hash type with zero-allocation operations.

use rand::RngCore;
use std::fmt;

/// SHA3-256 hash length in bytes.
pub const HASH_LEN: usize = 32;

/// Fixed-size 32-byte hash used throughout the blockchain.
///
/// This type is `Copy` for performance - hashes are passed frequently during
/// block validation and should live on the stack to avoid heap allocations.
/// At 32 bytes, copying is cheaper than reference indirection on modern CPUs.
///
/// # Examples
/// ```
/// let hash = Hash::zero();
/// let hash2 = hash; // Cheap copy, not a move
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
        let slice = b.as_slice();
        Hash::from_bytes(slice)
    }

    /// Generates a cryptographically random hash for testing.
    ///
    /// Only available in test builds to prevent misuse in production code.
    #[cfg(test)]
    pub fn random() -> Hash {
        let mut buf = vec![0u8; HASH_LEN];
        rand::rng().fill_bytes(&mut buf);
        Hash::from_vec(buf)
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
