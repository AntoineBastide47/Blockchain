//! Binary serialization trait with zero-allocation hashing.

use crate::types::hash::Hash;
use sha3::{Digest, Sha3_256};
use std::io::{Read, Result, Write};

/// Adapter that implements `Write` by feeding bytes directly into a hash digest.
///
/// This eliminates the need for intermediate buffer allocations when computing hashes.
/// During blockchain sync, thousands of hashes are computed per second - avoiding
/// allocations here significantly reduces GC pressure.
struct HasherWriter<'a, D: Digest>(&'a mut D);

impl<'a, D: Digest> Write for HasherWriter<'a, D> {
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
/// All blockchain primitives (blocks, transactions, headers) implement this trait
/// to enable network transmission and cryptographic verification.
///
/// # Binary Format
/// Uses little-endian encoding for multibyte integers.
pub trait BinaryCodec {
    /// Encodes the type to binary format via the provided writer.
    ///
    /// Implementations should write all fields in a deterministic order to ensure
    /// consistent hashing across different nodes.
    fn encode<W: Write>(&self, w: W) -> Result<()>;

    /// Decodes the type from binary format via the provided reader.
    ///
    /// The reader should contain data previously written by `encode`.
    fn decode<R: Read>(&mut self, r: R) -> Result<()>;

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
        self.encode(HasherWriter(&mut hasher))?;
        Ok(Hash(hasher.finalize().into()))
    }
}
