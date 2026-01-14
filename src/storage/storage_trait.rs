//! Blockchain storage abstractions and implementations.
//!
//! Defines the [`Storage`] trait for persisting blocks and headers.

use crate::core::account::Account;
use crate::core::block::{Block, Header};
use crate::crypto::key_pair::Address;
use crate::types::encoding::DecodeError;
use crate::types::hash::Hash;
use crate::virtual_machine::errors::VMError;
use blockchain_derive::Error;
use std::sync::Arc;

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
    /// Gas cost computation overflowed u128.
    #[error(
        "error computing gas cost in transaction, gas_used={gas_used} * gas_price={gas_price} > u128::MAX"
    )]
    ArithmeticOverflow { gas_used: u64, gas_price: u128 },
    /// Account balance insufficient to cover gas costs.
    #[error("insufficient balance in expected at least {expected} but got {actual}")]
    InsufficientBalance { actual: u128, expected: u128 },
    #[error("transaction gas limit and gas price can not be set to 0")]
    InvalidTransactionGasParams,
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
    /// Creates a new storage instance initialized with the genesis block.
    fn new(genesis: Block, chain_id: u64, initial_accounts: &[(Address, Account)]) -> Self;

    /// Returns `true` if a block with the given hash exists.
    fn has_block(&self, hash: Hash) -> bool;

    /// Retrieves a block header by its hash.
    fn get_header(&self, hash: Hash) -> Option<Header>;

    /// Retrieves a full block by its hash.
    fn get_block(&self, hash: Hash) -> Option<Arc<Block>>;

    /// Appends a block to storage and updates the chain tip (thread-safe).
    fn append_block(&self, block: Block, chain_id: u64) -> Result<(), StorageError>;

    /// Returns the current chain height (genesis = 0).
    fn height(&self) -> u64;

    /// Returns the hash of the current chain tip.
    fn tip(&self) -> Hash;
}
