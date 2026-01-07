//! VM storage management and overlay abstractions.
//!
//! Provides traits and types for managing blockchain storage during VM execution.
//! The [`State`] trait defines the interface for key-value storage, while
//! [`OverlayState`] enables transactional writes that can be committed or discarded.

use crate::types::hash::Hash;
use std::collections::BTreeMap;

/// Key-value storage interface for VM execution.
///
/// Implementations provide persistent storage that the VM reads from and writes to
/// during smart contract execution. Keys are always hashes to ensure uniform
/// distribution and fixed-size indexing.
pub trait State {
    /// Retrieves a value by key, returning `None` if the key does not exist.
    fn get(&self, key: Hash) -> Option<Vec<u8>>;
    /// Stores a key-value pair, overwriting any existing value.
    fn push(&mut self, key: Hash, value: Vec<u8>);
    /// Removes a key from storage.
    fn delete(&mut self, key: Hash);
}

/// Write-through overlay on top of a base storage.
///
/// Buffers writes in memory while reading through to the base storage for keys
/// not yet written. Enables transactional execution where writes can be
/// committed atomically or discarded on error.
pub struct OverlayState<'a> {
    /// Underlying storage for read-through on cache misses.
    _base: &'a dyn State,
    /// Pending writes: `Some(value)` for insertions, `None` for deletions.
    pub(crate) writes: BTreeMap<Hash, Option<Vec<u8>>>,
}

impl<'a> OverlayState<'a> {
    /// Creates a new overlay backed by the given base storage.
    pub fn new(base: &'a dyn State) -> Self {
        Self {
            _base: base,
            writes: BTreeMap::new(),
        }
    }

    /// Consumes the overlay and returns the pending writes as a vector.
    pub fn into_writes(self) -> Vec<(Hash, Option<Vec<u8>>)> {
        self.writes.into_iter().collect()
    }
}

impl<'a> State for OverlayState<'a> {
    fn get(&self, key: Hash) -> Option<Vec<u8>> {
        if let Some(v) = self.writes.get(&key) {
            return v.clone();
        }
        self._base.get(key)
    }

    fn push(&mut self, key: Hash, value: Vec<u8>) {
        self.writes.insert(key, Some(value));
    }

    fn delete(&mut self, key: Hash) {
        self.writes.insert(key, None);
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    pub struct TestState {
        data: BTreeMap<Hash, Vec<u8>>,
    }

    impl TestState {
        pub fn new() -> Self {
            Self {
                data: BTreeMap::new(),
            }
        }

        pub fn with_data(data: Vec<(Hash, Vec<u8>)>) -> Self {
            Self {
                data: data.into_iter().collect(),
            }
        }
    }

    impl State for TestState {
        fn get(&self, key: Hash) -> Option<Vec<u8>> {
            self.data.get(&key).cloned()
        }

        fn push(&mut self, key: Hash, value: Vec<u8>) {
            self.data.insert(key, value);
        }

        fn delete(&mut self, key: Hash) {
            self.data.remove(&key);
        }
    }

    fn h(s: &[u8]) -> Hash {
        let mut h = Hash::sha3();
        h.update(s);
        h.finalize()
    }

    #[test]
    fn overlay_reads_through_to_base() {
        let base = TestState::with_data(vec![(h(b"key"), b"value".to_vec())]);
        let overlay = OverlayState::new(&base);
        assert_eq!(overlay.get(h(b"key")), Some(b"value".to_vec()));
        assert_eq!(overlay.get(h(b"missing")), None);
    }

    #[test]
    fn overlay_write_shadows_base() {
        let base = TestState::with_data(vec![(h(b"key"), b"old".to_vec())]);
        let mut overlay = OverlayState::new(&base);
        overlay.push(h(b"key"), b"new".to_vec());
        assert_eq!(overlay.get(h(b"key")), Some(b"new".to_vec()));
    }

    #[test]
    fn overlay_delete_returns_none() {
        let base = TestState::with_data(vec![(h(b"key"), b"value".to_vec())]);
        let mut overlay = OverlayState::new(&base);
        overlay.delete(h(b"key"));
        assert_eq!(overlay.get(h(b"key")), None);
    }

    #[test]
    fn overlay_into_writes_captures_all_operations() {
        let base = TestState::new();
        let mut overlay = OverlayState::new(&base);
        overlay.push(h(b"a"), b"1".to_vec());
        overlay.push(h(b"b"), b"2".to_vec());
        overlay.delete(h(b"c"));

        let writes = overlay.into_writes();
        assert_eq!(writes.len(), 3);
        assert!(writes.contains(&(h(b"a"), Some(b"1".to_vec()))));
        assert!(writes.contains(&(h(b"b"), Some(b"2".to_vec()))));
        assert!(writes.contains(&(h(b"c"), None)));
    }

    #[test]
    fn overlay_write_after_delete_restores_value() {
        let base = TestState::new();
        let mut overlay = OverlayState::new(&base);
        overlay.push(h(b"key"), b"first".to_vec());
        overlay.delete(h(b"key"));
        overlay.push(h(b"key"), b"second".to_vec());
        assert_eq!(overlay.get(h(b"key")), Some(b"second".to_vec()));
    }
}
