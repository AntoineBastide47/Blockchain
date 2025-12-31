//! VM state management and overlay abstractions.
//!
//! Provides traits and types for managing blockchain state during VM execution.
//! The [`State`] trait defines the interface for key-value storage, while
//! [`OverlayState`] enables transactional writes that can be committed or discarded.

use std::collections::BTreeMap;

/// Key-value state interface for VM execution.
///
/// Implementations provide persistent storage that the VM reads from and writes to
/// during smart contract execution.
pub trait State {
    /// Retrieves a value by key, returning `None` if the key does not exist.
    fn get(&self, key: &[u8]) -> Option<Vec<u8>>;
    /// Stores a key-value pair, overwriting any existing value.
    fn push(&mut self, key: Vec<u8>, value: Vec<u8>);
    /// Removes a key from storage.
    fn delete(&mut self, key: &[u8]);
}

/// Write-through overlay on top of a base state.
///
/// Buffers writes in memory while reading through to the base state for keys
/// not yet written. Enables transactional execution where writes can be
/// committed atomically or discarded on error.
pub struct OverlayState<'a> {
    /// Underlying state for read-through on cache misses.
    _base: &'a dyn State,
    /// Pending writes: `Some(value)` for insertions, `None` for deletions.
    pub(crate) writes: BTreeMap<Vec<u8>, Option<Vec<u8>>>,
}

impl<'a> OverlayState<'a> {
    /// Creates a new overlay backed by the given base state.
    pub fn new(base: &'a dyn State) -> Self {
        Self {
            _base: base,
            writes: BTreeMap::new(),
        }
    }

    /// Consumes the overlay and returns the pending writes as a vector.
    pub fn into_writes(self) -> Vec<(Vec<u8>, Option<Vec<u8>>)> {
        self.writes.into_iter().collect()
    }
}

impl<'a> State for OverlayState<'a> {
    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        if let Some(v) = self.writes.get(key) {
            return v.clone();
        }
        self._base.get(key)
    }

    fn push(&mut self, key: Vec<u8>, value: Vec<u8>) {
        self.writes.insert(key, Some(value));
    }

    fn delete(&mut self, key: &[u8]) {
        self.writes.insert(key.to_vec(), None);
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    pub struct TestState {
        data: BTreeMap<Vec<u8>, Vec<u8>>,
    }

    impl TestState {
        pub fn new() -> Self {
            Self {
                data: BTreeMap::new(),
            }
        }

        pub fn with_data(data: Vec<(Vec<u8>, Vec<u8>)>) -> Self {
            Self {
                data: data.into_iter().collect(),
            }
        }
    }

    impl State for TestState {
        fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
            self.data.get(key).cloned()
        }

        fn push(&mut self, key: Vec<u8>, value: Vec<u8>) {
            self.data.insert(key, value);
        }

        fn delete(&mut self, key: &[u8]) {
            self.data.remove(key);
        }
    }

    #[test]
    fn overlay_reads_through_to_base() {
        let base = TestState::with_data(vec![(b"key".to_vec(), b"value".to_vec())]);
        let overlay = OverlayState::new(&base);
        assert_eq!(overlay.get(b"key"), Some(b"value".to_vec()));
        assert_eq!(overlay.get(b"missing"), None);
    }

    #[test]
    fn overlay_write_shadows_base() {
        let base = TestState::with_data(vec![(b"key".to_vec(), b"old".to_vec())]);
        let mut overlay = OverlayState::new(&base);
        overlay.push(b"key".to_vec(), b"new".to_vec());
        assert_eq!(overlay.get(b"key"), Some(b"new".to_vec()));
    }

    #[test]
    fn overlay_delete_returns_none() {
        let base = TestState::with_data(vec![(b"key".to_vec(), b"value".to_vec())]);
        let mut overlay = OverlayState::new(&base);
        overlay.delete(b"key");
        assert_eq!(overlay.get(b"key"), None);
    }

    #[test]
    fn overlay_into_writes_captures_all_operations() {
        let base = TestState::new();
        let mut overlay = OverlayState::new(&base);
        overlay.push(b"a".to_vec(), b"1".to_vec());
        overlay.push(b"b".to_vec(), b"2".to_vec());
        overlay.delete(b"c");

        let writes = overlay.into_writes();
        assert_eq!(writes.len(), 3);
        assert!(writes.contains(&(b"a".to_vec(), Some(b"1".to_vec()))));
        assert!(writes.contains(&(b"b".to_vec(), Some(b"2".to_vec()))));
        assert!(writes.contains(&(b"c".to_vec(), None)));
    }

    #[test]
    fn overlay_write_after_delete_restores_value() {
        let base = TestState::new();
        let mut overlay = OverlayState::new(&base);
        overlay.push(b"key".to_vec(), b"first".to_vec());
        overlay.delete(b"key");
        overlay.push(b"key".to_vec(), b"second".to_vec());
        assert_eq!(overlay.get(b"key"), Some(b"second".to_vec()));
    }
}
