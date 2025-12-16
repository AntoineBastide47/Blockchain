//! Binary serialization trait with zero-allocation hashing.
//!
//! This module provides a unified interface for binary encoding via `borsh`.
//! Use `#[derive(BinaryCodec)]` to automatically implement serialization,
//! deserialization, and zero-allocation hashing.

use crate::types::hash::Hash;
use borsh::{BorshDeserialize, BorshSerialize};
use sha3::{Digest, Sha3_256};
use std::io::{Result, Write};

pub use blockchain_derive::BinaryCodec;

/// Adapter that implements `Write` by feeding bytes directly into a hash digest.
///
/// This eliminates the need for intermediate buffer allocations when computing hashes.
/// During blockchain sync, thousands of hashes are computed per second - avoiding
/// allocations here significantly reduces GC pressure.
struct HasherWriter<'a, D: Digest>(&'a mut D);

impl<D: Digest> Write for HasherWriter<'_, D> {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        self.0.update(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}

/// Trait for types that can be serialized to/from binary format and hashed.
///
/// This trait is automatically implemented for all types that derive `BinaryCodec`.
/// The binary format uses little-endian encoding for multibyte integers.
///
/// # Usage
/// ```ignore
/// use crate::types::binary_codec::BinaryCodec;
///
/// #[derive(BinaryCodec)]
/// struct MyType { ... }
///
/// let hash = my_instance.hash()?;
/// ```
pub trait BinaryCodecHash: BorshSerialize + BorshDeserialize {
    /// Computes SHA3-256 hash of the encoded representation.
    ///
    /// This implementation streams data directly into the hasher without
    /// allocating an intermediate buffer, making it optimal for frequent
    /// hash computations during block validation.
    ///
    /// # Performance
    /// Zero-allocation implementation. On a typical block header (~88 bytes),
    /// this saves ~100 bytes of heap allocation per hash.
    fn hash(&self) -> Result<Hash> {
        let mut hasher = Sha3_256::new();
        self.serialize(&mut HasherWriter(&mut hasher))?;
        Ok(Hash(hasher.finalize().into()))
    }
}

impl<T: BorshSerialize + BorshDeserialize> BinaryCodecHash for T {}
