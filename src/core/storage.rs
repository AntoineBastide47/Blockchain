//! Blockchain storage abstractions and implementations.
//!
//! Defines the [`Storage`] trait for persisting blocks and headers,
//! along with [`InMemoryStorage`] for testing and development.

use crate::core::block::{Block, Header};
use crate::types::hash::Hash;
use std::collections::HashMap;

use std::sync::{Arc, Mutex};

/// Storage backend for blockchain data.
///
/// Implementations must be thread-safe (`Send + Sync`) to support
/// concurrent access from multiple network handlers.
pub trait Storage: Send + Sync {
    /// Creates a new storage instance initialized with the genesis block.
    fn new(genesis: Arc<Block>) -> Self;

    /// Returns `true` if a block with the given hash exists.
    fn has_block(&self, hash: Hash) -> bool;

    /// Retrieves a block header by its hash.
    fn get_header(&self, hash: Hash) -> Option<Header>;

    /// Retrieves a full block by its hash.
    fn get_block(&self, hash: Hash) -> Option<Arc<Block>>;

    /// Appends a block to storage and updates the chain tip (thread-safe).
    fn append_block(&self, _block: Arc<Block>) -> Result<(), String>;

    /// Returns the current chain height (genesis = 0).
    fn height(&self) -> u32;

    /// Returns the hash of the current chain tip.
    fn tip(&self) -> Hash;
}

struct Inner {
    /// Block headers indexed by hash.
    headers: HashMap<Hash, Header>,
    /// Full blocks indexed by hash.
    blocks: HashMap<Hash, Arc<Block>>,
    /// Hash of the current chain tip.
    tip: Hash,
}

/// In-memory storage for development as it is thread safe
///
/// Stores blocks and headers in hash maps with O(1) lookup.
/// Not yet fully suitable for production due to storing all blocks in memory.
pub struct ThreadSafeMemoryStorage {
    // TODO: add disk persistency for blocks and in memory caching LRU block caching
    inner: Mutex<Inner>,
}

impl Storage for ThreadSafeMemoryStorage {
    fn new(genesis: Arc<Block>) -> Self {
        let mut headers = HashMap::new();
        let mut blocks = HashMap::new();

        let genesis_hash = genesis.header_hash;

        headers.insert(genesis_hash, genesis.header);
        blocks.insert(genesis_hash, genesis);

        let inner = Inner {
            headers,
            blocks,
            tip: genesis_hash,
        };

        Self {
            inner: Mutex::new(inner),
        }
    }

    fn has_block(&self, hash: Hash) -> bool {
        let inner = self.inner.lock().unwrap();
        inner.blocks.contains_key(&hash)
    }

    fn get_header(&self, hash: Hash) -> Option<Header> {
        let inner = self.inner.lock().unwrap();
        inner.headers.get(&hash).cloned()
    }

    fn get_block(&self, hash: Hash) -> Option<Arc<Block>> {
        let inner = self.inner.lock().unwrap();
        inner.blocks.get(&hash).cloned()
    }

    fn append_block(&self, block: Arc<Block>) -> Result<(), String> {
        let mut inner = self.inner.lock().unwrap();

        if block.header.previous_block != inner.tip {
            return Err("Invalid chain".to_string());
        }

        let hash = block.header_hash;

        inner.headers.insert(hash, block.header);
        inner.blocks.insert(hash, block);
        inner.tip = hash;

        Ok(())
    }

    fn height(&self) -> u32 {
        let inner = self.inner.lock().unwrap();

        inner
            .headers
            .len()
            .saturating_sub(1)
            .try_into()
            .expect("blockchain height exceeds u32::MAX")
    }

    fn tip(&self) -> Hash {
        let inner = self.inner.lock().unwrap();
        inner.tip
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::core::block::Header;
    use crate::crypto::key_pair::PrivateKey;
    use crate::utils::test_utils::utils::{create_genesis, random_hash};
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::thread;

    pub trait StorageExtForTests {
        /// Appends a block to storage and updates the chain tip (requires mutable access).
        ///
        /// # Panics
        /// Panics if not implemented for this storage type.
        #[cfg(test)]
        fn append_block_mut(&mut self, _block: Arc<Block>);
    }

    /// In-memory storage for testing and development.
    ///
    /// Stores blocks and headers in hash maps with O(1) lookup.
    /// Not suitable for production due to memory constraints and being thread unsafe.
    pub struct TestStorage {
        /// Block headers indexed by hash.
        headers: HashMap<Hash, Header>,
        /// Full blocks indexed by hash.
        blocks: HashMap<Hash, Arc<Block>>,
        /// Hash of the current chain tip.
        tip: Hash,
    }

    impl Storage for TestStorage {
        fn new(genesis: Arc<Block>) -> Self {
            let mut storage = Self {
                headers: HashMap::new(),
                blocks: HashMap::new(),
                tip: Hash::zero(),
            };
            storage.append_block_mut(genesis);
            storage
        }

        fn has_block(&self, hash: Hash) -> bool {
            self.blocks.contains_key(&hash)
        }

        fn get_header(&self, hash: Hash) -> Option<Header> {
            self.headers.get(&hash).copied()
        }

        fn get_block(&self, hash: Hash) -> Option<Arc<Block>> {
            self.blocks.get(&hash).cloned()
        }

        fn append_block(&self, _block: Arc<Block>) -> Result<(), String> {
            panic!(
                "TestStorage::append_block is not supported. Use append_block_mut from StorageExtForTests trait instead."
            )
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

    impl StorageExtForTests for TestStorage {
        fn append_block_mut(&mut self, block: Arc<Block>) {
            if block.header.previous_block != self.tip {
                panic!(
                    "Block does not build on current tip: {} != {}",
                    block.header.previous_block, self.tip
                );
            }

            let hash = block.header_hash;

            self.headers.insert(hash, block.header);
            self.blocks.insert(hash, block);

            self.tip = hash;
        }
    }

    fn create_block_at(height: u32, previous: Hash) -> Arc<Block> {
        let header = Header {
            version: 1,
            height,
            timestamp: 0,
            previous_block: previous,
            data_hash: Hash::zero(),
            merkle_root: Hash::zero(),
        };
        Block::new(header, PrivateKey::new(), vec![])
    }

    #[test]
    fn in_memory_storage_new_initializes_with_genesis() {
        let genesis = create_genesis();
        let hash = genesis.header_hash;
        let storage = TestStorage::new(genesis);

        assert_eq!(storage.height(), 0);
        assert_eq!(storage.tip(), hash);
        assert!(storage.has_block(hash));
    }

    #[test]
    fn in_memory_storage_append_and_retrieve() {
        let genesis = create_genesis();
        let mut storage = TestStorage::new(genesis.clone());

        let block1 = create_block_at(1, genesis.header_hash);
        storage.append_block_mut(block1.clone());

        assert_eq!(storage.height(), 1);
        assert_eq!(storage.tip(), block1.header_hash);
        assert!(storage.has_block(block1.header_hash));
        assert_eq!(
            storage.get_block(block1.header_hash).unwrap().header_hash,
            block1.header_hash
        );
    }

    #[test]
    fn in_memory_storage_get_header() {
        let genesis = create_genesis();
        let storage = TestStorage::new(genesis.clone());

        let header = storage.get_header(genesis.header_hash).unwrap();
        assert_eq!(header.height, 0);
    }

    #[test]
    fn in_memory_storage_get_nonexistent_block() {
        let genesis = create_genesis();
        let storage = TestStorage::new(genesis);

        assert!(storage.get_block(random_hash()).is_none());
        assert!(storage.get_header(random_hash()).is_none());
    }

    #[test]
    #[should_panic(expected = "Block does not build on current tip")]
    fn in_memory_storage_rejects_block_not_on_tip() {
        let genesis = create_genesis();
        let mut storage = TestStorage::new(genesis);

        let orphan = create_block_at(1, random_hash());
        storage.append_block_mut(orphan);
    }

    #[test]
    fn thread_safe_storage_new_initializes_with_genesis() {
        let genesis = create_genesis();
        let hash = genesis.header_hash;
        let storage = ThreadSafeMemoryStorage::new(genesis);

        assert_eq!(storage.height(), 0);
        assert_eq!(storage.tip(), hash);
        assert!(storage.has_block(hash));
    }

    #[test]
    fn thread_safe_storage_append_and_retrieve() {
        let genesis = create_genesis();
        let storage = ThreadSafeMemoryStorage::new(genesis.clone());

        let block1 = create_block_at(1, genesis.header_hash);
        assert!(storage.append_block(block1.clone()).is_ok());

        assert_eq!(storage.height(), 1);
        assert_eq!(storage.tip(), block1.header_hash);
        assert!(storage.has_block(block1.header_hash));
    }

    #[test]
    fn thread_safe_storage_concurrent_reads() {
        let genesis = create_genesis();
        let storage = Arc::new(ThreadSafeMemoryStorage::new(genesis.clone()));
        let hash = genesis.header_hash;

        let handles: Vec<_> = (0..10)
            .map(|_| {
                let s = Arc::clone(&storage);
                let h = hash;
                thread::spawn(move || {
                    assert!(s.has_block(h));
                    assert_eq!(s.height(), 0);
                    assert_eq!(s.tip(), h);
                    s.get_block(h).is_some()
                })
            })
            .collect();

        for handle in handles {
            assert!(handle.join().unwrap());
        }
    }

    #[test]
    fn thread_safe_storage_rejects_block_not_on_tip() {
        let genesis = create_genesis();
        let storage = ThreadSafeMemoryStorage::new(genesis);

        let orphan = create_block_at(1, random_hash());
        assert!(storage.append_block(orphan).is_err());
    }

    #[test]
    fn thread_safe_storage_chain_of_blocks() {
        let genesis = create_genesis();
        let storage = ThreadSafeMemoryStorage::new(genesis.clone());

        let mut prev_hash = genesis.header_hash;
        for i in 1..=10 {
            let block = create_block_at(i, prev_hash);
            prev_hash = block.header_hash;
            assert!(storage.append_block(block).is_ok());
        }

        assert_eq!(storage.height(), 10);
        assert_eq!(storage.tip(), prev_hash);
    }
}
