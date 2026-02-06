//! State storage traits for blockchain state management.
//!
//! Defines the core storage interfaces used by the blockchain and VM:
//! - [`StateStore`]: Atomic state updates with merkle root computation
//! - [`AccountStorage`]: Account-level read/write operations
//! - [`VmStorage`]: Read-only state access for VM execution

use crate::core::account::Account;
use crate::crypto::key_pair::Address;
use crate::types::hash::Hash;

/// Core trait for atomic state updates with merkle root computation.
///
/// Implementations must be thread-safe and provide atomic batch operations
/// that update the state merkle root consistently.
pub trait StateStore: Send + Sync {
    /// Applies a batch of writes atomically to a copy of the current state and returns the computed root.
    ///
    /// `None` values indicate deletions.
    fn preview_root(&self, writes: &[(Hash, Option<Vec<u8>>)]) -> Hash;
    /// Applies a batch of writes atomically and computes the new state root.
    ///
    /// `None` values indicate deletions.
    fn apply_batch(&self, writes: Vec<(Hash, Option<Vec<u8>>)>);
    /// Returns the current storage root hash.
    fn state_root(&self) -> Hash;
}

/// High-level account operations built on [`StateStore`].
///
/// Provides typed access to account data, handling serialization and
/// deserialization of account structures.
pub trait AccountStorage: StateStore {
    /// Fetches the full account state for an address.
    fn get_account(&self, addr: Address) -> Option<Account>;
    /// Writes or overwrites the account state for an address.
    fn set_account(&self, addr: Address, account: Account);
    /// Removes an account and its state.
    fn delete_account(&self, addr: Address);
}

/// State storage interface for VM execution.
///
/// Provides key-value storage operations and storage root management.
/// Implementations must be thread-safe.
pub trait VmStorage: StateStore {
    /// Return `true` if the state contains the given key, `false` if not
    fn contains_key(&self, key: Hash) -> bool;
    /// Retrieves a value by key from the storage store.
    fn get(&self, key: Hash) -> Option<Vec<u8>>;
}
