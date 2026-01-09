use crate::core::account::Account;
use crate::crypto::key_pair::Address;
use crate::types::hash::Hash;

/// Allows iteration over all key-value pairs in the storage.
///
/// Used for computing storage roots. Production implementations should use
/// a sparse Merkle tree instead of full iteration.
pub trait IterableState {
    /// Returns an iterator over all key-value pairs in the storage.
    fn iter_all(&self) -> Box<dyn Iterator<Item = (Hash, Vec<u8>)> + '_>;
}

pub trait StateStore: Send + Sync {
    /// Applies a batch of writes atomically. `None` values indicate deletions.
    fn apply_batch(&self, writes: Vec<(Hash, Option<Vec<u8>>)>);
    /// Returns the current storage root hash.
    fn state_root(&self) -> Hash;
}

pub trait AccountStorage: StateStore {
    /// Fetches the full account state for an address.
    fn get_account(&self, addr: Address) -> Option<Account>;
    /// Writes or overwrites the account state for an address.
    fn set_account(&mut self, addr: Address, account: Account);
    /// Removes an account and its state.
    fn delete_account(&mut self, addr: Address);
}

/// State storage interface for VM execution.
///
/// Provides key-value storage operations and storage root management.
/// Implementations must be thread-safe.
pub trait VmStorage: StateStore {
    /// Retrieves a value by key from the storage store.
    fn get(&self, key: Hash) -> Option<Vec<u8>>;
    /// Updates the stored storage root hash.
    fn set_state_root(&self, root: Hash);
}
