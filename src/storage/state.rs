use crate::types::hash::Hash;
use crate::virtual_machine::state::State;

/// State storage interface for VM execution.
///
/// Provides key-value storage operations and storage root management.
/// Implementations must be thread-safe.
pub trait StateStore: Send + Sync {
    /// Retrieves a value by key from the storage store.
    fn get(&self, key: Hash) -> Option<Vec<u8>>;
    /// Applies a batch of writes atomically. `None` values indicate deletions.
    fn apply_batch(&self, writes: Vec<(Hash, Option<Vec<u8>>)>);
    /// Returns the current storage root hash.
    fn state_root(&self) -> Hash;
    /// Updates the stored storage root hash.
    fn set_state_root(&self, root: Hash);
}

/// Allows iteration over all key-value pairs in the storage.
///
/// Used for computing storage roots. Production implementations should use
/// a sparse Merkle tree instead of full iteration.
pub trait IterableState {
    /// Returns an iterator over all key-value pairs in the storage.
    fn iter_all(&self) -> Box<dyn Iterator<Item = (Hash, Vec<u8>)> + '_>;
}

/// Read-only view into the storage store.
///
/// Implements [`State`] for use with the VM while preventing writes.
pub struct StateView<'a, S: StateStore> {
    storage: &'a S,
}

impl<'a, S: StateStore> StateView<'a, S> {
    pub fn new(storage: &'a S) -> Self {
        Self { storage }
    }
}

/// Provides a read-only storage view from a storage store.
pub trait StateViewProvider {
    /// Returns a read-only view of the current storage.
    fn state_view(&self) -> StateView<'_, Self>
    where
        Self: Sized + StateStore;
}

impl<'a, S: StateStore> State for StateView<'a, S> {
    fn get(&self, key: Hash) -> Option<Vec<u8>> {
        self.storage.get(key)
    }

    fn push(&mut self, _key: Hash, _value: Vec<u8>) {
        unreachable!("StateView is read-only")
    }

    fn delete(&mut self, _key: Hash) {
        unreachable!("StateView is read-only")
    }
}
