use crate::storage::state_store::VmStorage;
use crate::types::hash::Hash;
use crate::virtual_machine::state::State;

/// Read-only view into the storage store.
///
/// Implements [`State`] for use with the VM while preventing writes.
pub struct StateView<'a, S: VmStorage> {
    storage: &'a S,
}

impl<'a, S: VmStorage> StateView<'a, S> {
    /// Creates a new read-only view wrapping the given storage.
    pub fn new(storage: &'a S) -> Self {
        Self { storage }
    }
}

/// Provides a read-only storage view from a storage store.
pub trait StateViewProvider {
    /// Returns a read-only view of the current storage.
    fn state_view(&self) -> StateView<'_, Self>
    where
        Self: Sized + VmStorage;
}

impl<'a, S: VmStorage> State for StateView<'a, S> {
    fn contains_key(&self, key: Hash) -> bool {
        self.storage.contains_key(key)
    }

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
