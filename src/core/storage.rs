//! Blockchain storage abstractions and implementations.
//!
//! Defines the [`Storage`] trait for persisting blocks and headers,
//! along with [`InMemoryStorage`] for testing and development.

use crate::core::block::{Block, Header};
use crate::types::hash::Hash;
use std::collections::HashMap;
use std::sync::Arc;

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

    /// Appends a block to storage and updates the chain tip.
    fn append_block(&mut self, block: Arc<Block>);

    /// Returns the current chain height (genesis = 0).
    fn height(&self) -> u32;

    /// Returns the hash of the current chain tip.
    fn tip(&self) -> Hash;
}

/// In-memory storage for testing and development.
///
/// Stores blocks and headers in hash maps with O(1) lookup.
/// Not suitable for production due to memory constraints.
pub struct InMemoryStorage {
    /// Block headers indexed by hash.
    headers: HashMap<Hash, Header>,
    /// Full blocks indexed by hash.
    blocks: HashMap<Hash, Arc<Block>>,
    /// Hash of the current chain tip.
    tip: Hash,
}

impl InMemoryStorage {
    /// Creates a new storage initialized with a genesis block.
    ///
    /// # Arguments
    ///
    /// * `genesis` - The genesis block to initialize the chain.
    pub fn new(genesis: Arc<Block>) -> Self {
        let hash = genesis.header_hash;

        let mut headers = HashMap::new();
        let mut blocks = HashMap::new();

        headers.insert(hash, genesis.header);
        blocks.insert(hash, genesis);

        Self {
            headers,
            blocks,
            tip: hash,
        }
    }
}

impl Storage for InMemoryStorage {
    fn has_block(&self, hash: Hash) -> bool {
        self.blocks.contains_key(&hash)
    }

    fn get_header(&self, hash: Hash) -> Option<Header> {
        self.headers.get(&hash).copied()
    }

    fn get_block(&self, hash: Hash) -> Option<Arc<Block>> {
        self.blocks.get(&hash).cloned()
    }

    fn append_block(&mut self, block: Arc<Block>) {
        if block.header.previous_block != self.tip {
            panic!("Block does not build on current tip");
        }

        let hash = block.header_hash;

        self.headers.insert(hash, block.header);
        self.blocks.insert(hash, block);

        self.tip = hash;
    }

    fn height(&self) -> u32 {
        self.headers
            .len()
            .saturating_sub(1)
            .try_into()
            .expect("blockchain height exceeds u32::MAX")
    }

    fn tip(&self) -> Hash {
        self.tip
    }
}
