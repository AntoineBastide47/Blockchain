//! Blockchain storage abstractions and implementations.
//!
//! Defines the [`Storage`] trait for persisting blocks and headers.

use crate::core::block::{Block, Header};
use crate::core::receipt::Receipt;
use crate::types::encoding::DecodeError;
use crate::types::hash::Hash;
use crate::virtual_machine::errors::VMError;
use blockchain_derive::Error;
use std::sync::Arc;

/// Canonical storage state write entry `(key, value)` where `None` means delete.
pub type StateWrite = (Hash, Option<Vec<u8>>);

/// Errors that can occur while interacting with storage backends.
#[derive(Debug, Error)]
pub enum StorageError {
    /// Block's previous hash does not match the current chain tip.
    #[error("block does not extend current tip: expected previous hash {expected}, got {actual}")]
    NotOnTip { expected: Hash, actual: Hash },
    /// Block failed validation rules.
    #[error("block validation failed: {0}")]
    ValidationFailed(String),
    /// Virtual machine execution failed while processing transactions.
    #[error("{0}")]
    VMError(String),
    /// Failed to decode data from storage.
    #[error("{0}")]
    DecodeError(String),
    /// Account lookup failed for the given address.
    #[error("no account exist for the given public_key={0}")]
    MissingAccount(Hash),
    /// Contract code lookup failed for the given contract_id.
    #[error("no code exist for the given contract_id={0}")]
    MissingCode(Hash),
    /// Gas cost computation overflowed u128.
    #[error(
        "error computing gas cost in transaction, gas_used={gas_used} * gas_price={gas_price} > u128::MAX"
    )]
    ArithmeticOverflow { gas_used: u64, gas_price: u128 },
    /// Account balance insufficient to cover gas costs.
    #[error("insufficient balance in expected at least {expected} but got {actual}")]
    InsufficientBalance { actual: u128, expected: u128 },
    /// Transaction rejected due to zero gas limit or gas price.
    #[error("transaction gas limit and gas price must be non-zero")]
    InvalidTransactionGasParams,
    /// Credit to account would exceed the maximum representable balance.
    #[error("balance overflow: adding {increment} to {current} would exceed max balance {max}")]
    BalanceOverflow {
        current: u128,
        increment: u128,
        max: u128,
    },
}

impl From<VMError> for StorageError {
    fn from(value: VMError) -> Self {
        StorageError::VMError(value.to_string())
    }
}

impl From<DecodeError> for StorageError {
    fn from(value: DecodeError) -> Self {
        StorageError::DecodeError(value.to_string())
    }
}

/// Storage backend for blockchain data.
///
/// Implementations must be thread-safe (`Send + Sync`) to support
/// concurrent access from multiple network handlers.
pub trait Storage: Send + Sync {
    /// Returns `true` if a block with the given hash exists.
    fn has_block(&self, hash: Hash) -> bool;

    /// Retrieves a block header by its hash.
    fn get_header(&self, hash: Hash) -> Option<Header>;

    /// Retrieves a full block by its hash.
    fn get_block(&self, hash: Hash) -> Option<Arc<Block>>;

    /// Appends a block and its receipts to storage and updates the chain tip (thread-safe).
    fn append_block(
        &self,
        block: Block,
        receipts: Vec<Receipt>,
        chain_id: u64,
    ) -> Result<(), StorageError>;

    /// Returns the current chain height (genesis = 0).
    fn height(&self) -> u64;

    /// Returns the hash of the current chain tip.
    fn tip(&self) -> Hash;
}

/// Optional fork-aware storage primitives used by header DAG tracking and reorg logic.
///
/// This trait extends [`Storage`] without forcing all call sites to depend on
/// fork/reorg-specific methods immediately.
pub trait ForkStore: Storage {
    /// Returns the canonical header hash at `height`, if present.
    fn canonical_hash_at_height(&self, height: u64) -> Option<Hash>;

    /// Finds the lowest common ancestor of two known headers, if both can be resolved.
    fn find_lca(&self, a: Hash, b: Hash) -> Result<Option<Hash>, StorageError>;

    /// Captures prior values for the given state keys before a canonical state transition.
    ///
    /// Implementations return `(key, previous_value)` tuples suitable for embedding in
    /// backend-specific undo records.
    fn capture_state_undo(
        &self,
        state_writes: &[StateWrite],
    ) -> Result<Vec<StateWrite>, StorageError>;

    /// Marks the start of a reorg operation for crash recovery.
    fn begin_reorg_marker(&self, marker: Vec<u8>) -> Result<(), StorageError>;

    /// Clears any persisted in-progress reorg marker.
    fn clear_reorg_marker(&self) -> Result<(), StorageError>;
}
