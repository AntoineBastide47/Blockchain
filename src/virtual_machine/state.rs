//! VM storage management and overlay abstractions.
//!
//! Provides traits and types for managing blockchain storage during VM execution.
//! The [`State`] trait defines the interface for key-value storage, while
//! [`OverlayState`] enables transactional writes that can be committed or discarded.

use crate::crypto::key_pair::Address;
use crate::types::hash::Hash;
use std::collections::BTreeMap;

/// Key-value storage interface for VM execution.
///
/// Implementations provide persistent storage that the VM reads from and writes to
/// during smart contract execution. Keys are always hashes to ensure uniform
/// distribution and fixed-size indexing.
pub trait State {
    /// Return `true` if the state contains the given key, `false` if not
    fn contains_key(&self, key: Hash) -> bool;
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
pub struct OverlayState<'a, S: State> {
    /// Underlying storage for read-through on cache misses.
    _base: &'a S,
    /// Pending writes: `Some(value)` for insertions, `None` for deletions.
    pub(crate) writes: BTreeMap<Hash, Option<Vec<u8>>>,
}

impl<'a, S: State> OverlayState<'a, S> {
    /// Creates a new overlay backed by the given base state.
    pub fn new(base: &'a S) -> Self {
        Self {
            _base: base,
            writes: BTreeMap::new(),
        }
    }

    /// Consumes the overlay and returns the pending writes as a vector.
    pub fn into_writes(self) -> OverlayWrites {
        OverlayWrites(self.writes.into_iter().collect())
    }
}

/// Collected writes from an [`OverlayState`] ready for batch application.
///
/// Wraps a vector of key-value pairs where `Some(value)` represents an insertion
/// and `None` represents a deletion. Created by [`OverlayState::into_writes`].
pub struct OverlayWrites(pub Vec<(Hash, Option<Vec<u8>>)>);

impl OverlayWrites {
    /// Applies the collected writes to a target overlay, merging transaction state.
    ///
    /// First inserts the account state at the given address, then replays all
    /// buffered writes (insertions and deletions) into the target overlay. This
    /// enables hierarchical state composition where a child overlay's changes are
    /// merged into a parent overlay.
    pub fn apply_to<S: State>(
        self,
        (addr, account): (Address, Vec<u8>),
        overlay: &mut OverlayState<S>,
    ) {
        overlay.push(addr, account);
        for (k, v) in self.0 {
            match v {
                Some(val) => overlay.push(k, val),
                None => overlay.delete(k),
            }
        }
    }
}

impl<'a, S: State> State for OverlayState<'a, S> {
    fn contains_key(&self, key: Hash) -> bool {
        self.writes.contains_key(&key)
    }

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

    impl Default for TestState {
        fn default() -> Self {
            Self::new()
        }
    }

    impl State for TestState {
        fn contains_key(&self, key: Hash) -> bool {
            self.data.contains_key(&key)
        }

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
        assert_eq!(writes.0.len(), 3);
        assert!(writes.0.contains(&(h(b"a"), Some(b"1".to_vec()))));
        assert!(writes.0.contains(&(h(b"b"), Some(b"2".to_vec()))));
        assert!(writes.0.contains(&(h(b"c"), None)));
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

    #[test]
    fn apply_to_merges_writes_into_target() {
        let base = TestState::new();
        let mut parent = OverlayState::new(&base);

        // Create child overlay with some writes
        let mut child = OverlayState::new(&parent);
        child.push(h(b"k1"), b"v1".to_vec());
        child.push(h(b"k2"), b"v2".to_vec());

        // Apply to parent
        let addr = Hash([1u8; 32]);
        child
            .into_writes()
            .apply_to((addr, b"acc".to_vec()), &mut parent);

        assert_eq!(parent.get(addr), Some(b"acc".to_vec()));
        assert_eq!(parent.get(h(b"k1")), Some(b"v1".to_vec()));
        assert_eq!(parent.get(h(b"k2")), Some(b"v2".to_vec()));
    }

    #[test]
    fn apply_to_propagates_deletions() {
        let base = TestState::with_data(vec![(h(b"existing"), b"val".to_vec())]);
        let mut parent = OverlayState::new(&base);

        let mut child = OverlayState::new(&parent);
        child.delete(h(b"existing"));

        let addr = Hash([2u8; 32]);
        child
            .into_writes()
            .apply_to((addr, b"acc".to_vec()), &mut parent);

        assert_eq!(parent.get(h(b"existing")), None);
    }

    #[test]
    fn apply_to_handles_mixed_operations() {
        let base = TestState::with_data(vec![(h(b"to_delete"), b"old".to_vec())]);
        let mut parent = OverlayState::new(&base);

        let mut child = OverlayState::new(&parent);
        child.push(h(b"new_key"), b"new_val".to_vec());
        child.delete(h(b"to_delete"));

        let addr = Hash([3u8; 32]);
        child
            .into_writes()
            .apply_to((addr, b"account_data".to_vec()), &mut parent);

        assert_eq!(parent.get(addr), Some(b"account_data".to_vec()));
        assert_eq!(parent.get(h(b"new_key")), Some(b"new_val".to_vec()));
        assert_eq!(parent.get(h(b"to_delete")), None);
    }
}
