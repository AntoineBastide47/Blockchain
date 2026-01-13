//! Blockchain storage abstractions and implementations.
//!
//! Defines the [`Storage`] trait for persisting blocks and headers,
//! along with [`InMemoryStorage`] for testing and development.

use crate::core::block::{Block, Header};
use crate::types::hash::Hash;
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
}

/// Storage backend for blockchain data.
///
/// Implementations must be thread-safe (`Send + Sync`) to support
/// concurrent access from multiple network handlers.
pub trait Storage: Send + Sync {
    /// Creates a new storage instance initialized with the genesis block.
    fn new(genesis: Block, chain_id: u64) -> Self;

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
