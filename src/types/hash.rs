//! 32-byte SHA3-256 hash type with zero-allocation operations.

use crate::types::encoding::EncodeSink;
use blockchain_derive::BinaryCodec;
use sha3::{Digest, Sha3_256};
use std::fmt;
use std::sync::Mutex;

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
    /// Used as a sentinel value for genesis blocks or uninitialized storage.
    pub const fn zero() -> Hash {
        Hash([0u8; HASH_LEN])
    }

    /// Returns the hash as a byte slice.
    pub const fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Returns the hash as a byte Vec.
    pub fn to_vec(self) -> Vec<u8> {
        self.0.to_vec()
    }

    /// Creates a hash from a byte slice.
    ///
    /// Returns `None` if the slice length is not exactly [`HASH_LEN`] bytes.
    pub fn from_slice(slice: &[u8]) -> Option<Hash> {
        if slice.len() != HASH_LEN {
            return None;
        }
        let mut bytes = [0u8; HASH_LEN];
        bytes.copy_from_slice(slice);
        Some(Hash(bytes))
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
    /// Creates a new hash builder with empty storage.
    pub fn new() -> Self {
        Self {
            hasher: Sha3_256::new(),
        }
    }

    /// Feeds data into the hash computation.
    pub fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    pub fn chain(mut self, data: &[u8]) -> Self {
        self.hasher.update(data);
        self
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

/// Chain-aware hash cache that invalidates when chain_id changes.
///
/// Unlike `OnceLock`, this cache can be updated when called with a different
/// chain_id, ensuring correct hashes across multiple chains.
#[derive(Debug)]
pub struct HashCache {
    /// Cached (chain_id, hash) pair. None if not yet computed.
    cached: Mutex<Option<(u64, Hash)>>,
}

impl HashCache {
    /// Creates an empty cache.
    pub fn new() -> Self {
        Self {
            cached: Mutex::new(None),
        }
    }

    /// Returns the cached hash if chain_id matches, otherwise computes and caches it.
    ///
    /// - If no value is cached, computes via `f`, caches, and returns it.
    /// - If cached chain_id matches, returns the cached hash without calling `f`.
    /// - If cached chain_id differs, recomputes via `f`, caches, and returns it.
    ///
    /// Note: To avoid computing when unnecessary, check with `get` first if the
    /// computation involves expensive setup that happens before the closure.
    pub fn get_or_compute(&self, chain_id: u64, f: impl FnOnce() -> Hash) -> Hash {
        if let Some(hash) = self.get(chain_id) {
            return hash;
        }

        let hash = f();

        let mut guard = self.cached.lock().unwrap();
        if let Some((cached_chain_id, hash)) = *guard
            && cached_chain_id == chain_id
        {
            return hash;
        }

        *guard = Some((chain_id, hash));
        hash
    }

    /// Returns the cached hash if chain_id matches, without computing.
    pub fn get(&self, chain_id: u64) -> Option<Hash> {
        match *self.cached.lock().unwrap() {
            Some((cached_chain_id, hash)) if cached_chain_id == chain_id => Some(hash),
            _ => None,
        }
    }
}

impl Default for HashCache {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for HashCache {
    fn clone(&self) -> Self {
        let cached = *self.cached.lock().unwrap();
        HashCache {
            cached: Mutex::new(cached),
        }
    }
}

impl PartialEq for HashCache {
    fn eq(&self, other: &Self) -> bool {
        *self.cached.lock().unwrap() == *other.cached.lock().unwrap()
    }
}

impl Eq for HashCache {}

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

    fn make_hash(seed: u8) -> Hash {
        let mut h = Hash::sha3();
        h.update(&[seed]);
        h.finalize()
    }

    #[test]
    fn hash_cache_computes_on_first_call() {
        let cache = HashCache::new();
        let mut called = false;

        let hash = cache.get_or_compute(1, || {
            called = true;
            make_hash(1)
        });

        assert!(called);
        assert_eq!(hash, make_hash(1));
    }

    #[test]
    fn hash_cache_returns_cached_for_same_chain_id() {
        let cache = HashCache::new();
        let mut call_count = 0;

        let hash1 = cache.get_or_compute(1, || {
            call_count += 1;
            make_hash(1)
        });

        let hash2 = cache.get_or_compute(1, || {
            call_count += 1;
            make_hash(99) // Different hash, but should not be called
        });

        assert_eq!(call_count, 1);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn hash_cache_recomputes_for_different_chain_id() {
        let cache = HashCache::new();
        let mut call_count = 0;

        let hash1 = cache.get_or_compute(1, || {
            call_count += 1;
            make_hash(1)
        });

        let hash2 = cache.get_or_compute(2, || {
            call_count += 1;
            make_hash(2)
        });

        assert_eq!(call_count, 2);
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn hash_cache_recomputes_when_returning_to_original_chain() {
        let cache = HashCache::new();
        let mut call_count = 0;

        let hash1 = cache.get_or_compute(1, || {
            call_count += 1;
            make_hash(1)
        });

        let _hash2 = cache.get_or_compute(2, || {
            call_count += 1;
            make_hash(2)
        });

        let hash1_again = cache.get_or_compute(1, || {
            call_count += 1;
            make_hash(1)
        });

        assert_eq!(call_count, 3);
        assert_eq!(hash1, hash1_again);
    }

    #[test]
    fn hash_cache_clone_preserves_cached_value() {
        let cache = HashCache::new();

        let _ = cache.get_or_compute(5, || make_hash(42));

        let cloned = cache.clone();

        assert_eq!(cloned.get(5), Some(make_hash(42)));
        assert!(cloned.get(4).is_none());
    }

    #[test]
    fn hash_cache_stores_correct_chain_id() {
        let cache = HashCache::new();

        let _ = cache.get_or_compute(123, || make_hash(1));

        assert!(cache.get(123).is_some());
        assert!(cache.get(122).is_none());
    }

    #[test]
    fn hash_cache_chain_id_zero() {
        let cache = HashCache::new();

        let hash = cache.get_or_compute(0, || make_hash(1));

        assert_eq!(hash, make_hash(1));
        assert_eq!(cache.get(0), Some(make_hash(1)));
    }

    #[test]
    fn hash_cache_chain_id_max() {
        let cache = HashCache::new();

        let hash = cache.get_or_compute(u64::MAX, || make_hash(1));

        assert_eq!(hash, make_hash(1));
        assert_eq!(cache.get(u64::MAX), Some(make_hash(1)));
    }

    #[test]
    fn hash_cache_get_returns_none_for_wrong_chain_id() {
        let cache = HashCache::new();

        cache.get_or_compute(1, || make_hash(10));

        assert!(cache.get(2).is_none());
        assert_eq!(cache.get(1), Some(make_hash(10)));
    }

    #[test]
    fn hash_cache_get_or_compute_overwrites_on_chain_change() {
        let cache = HashCache::new();

        cache.get_or_compute(1, || make_hash(10));
        cache.get_or_compute(2, || make_hash(20));

        assert!(cache.get(1).is_none());
        assert_eq!(cache.get(2), Some(make_hash(20)));
    }
}
