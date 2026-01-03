//! Blockchain storage abstractions and implementations.
//!
//! Defines the [`Storage`] trait for persisting blocks and headers,
//! along with [`InMemoryStorage`] for testing and development.

use crate::core::block::{Block, Header};
use crate::types::hash::Hash;
use crate::virtual_machine::state::State;
use blockchain_derive::Error;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

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
    fn new(genesis: Arc<Block>, chain_id: u64) -> Self;

    /// Returns `true` if a block with the given hash exists.
    fn has_block(&self, hash: Hash) -> bool;

    /// Retrieves a block header by its hash.
    fn get_header(&self, hash: Hash) -> Option<Header>;

    /// Retrieves a full block by its hash.
    fn get_block(&self, hash: Hash) -> Option<Arc<Block>>;

    /// Appends a block to storage and updates the chain tip (thread-safe).
    fn append_block(&self, block: Arc<Block>, chain_id: u64) -> Result<(), StorageError>;

    /// Returns the current chain height (genesis = 0).
    fn height(&self) -> u64;

    /// Returns the hash of the current chain tip.
    fn tip(&self) -> Hash;
}

/// State storage interface for VM execution.
///
/// Provides key-value storage operations and state root management.
/// Implementations must be thread-safe.
pub trait StateStore: Send + Sync {
    /// Retrieves a value by key from the state store.
    fn get(&self, key: Hash) -> Option<Vec<u8>>;
    /// Applies a batch of writes atomically. `None` values indicate deletions.
    fn apply_batch(&self, writes: Vec<(Hash, Option<Vec<u8>>)>);
    /// Returns the current state root hash.
    fn state_root(&self) -> Hash;
    /// Updates the stored state root hash.
    fn set_state_root(&self, root: Hash);
}

/// Allows iteration over all key-value pairs in the state.
///
/// Used for computing state roots. Production implementations should use
/// a sparse Merkle tree instead of full iteration.
pub trait IterableState {
    /// Returns an iterator over all key-value pairs in the state.
    fn iter_all(&self) -> Box<dyn Iterator<Item = (Hash, Vec<u8>)> + '_>;
}

/// Read-only view into the state store.
///
/// Implements [`State`] for use with the VM while preventing writes.
pub struct StateView<'a, S: StateStore> {
    storage: &'a S,
}

/// Provides a read-only state view from a state store.
pub trait StateViewProvider {
    /// Returns a read-only view of the current state.
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

struct Inner {
    /// Block headers indexed by hash.
    headers: HashMap<Hash, Header>,
    /// Full blocks indexed by hash.
    blocks: HashMap<Hash, Arc<Block>>,
    /// Hash of the current chain tip.
    tip: Hash,
    /// Key-value state storage for VM execution.
    state: HashMap<Hash, Vec<u8>>,
    /// Root hash of the current state.
    state_root: Hash,
}

/// In-memory storage for development as it is thread safe
///
/// Stores blocks and headers in hash maps with O(1) lookup.
/// Not yet fully suitable for production due to storing all blocks in memory.
pub struct ThreadSafeMemoryStorage {
    // TODO: add disk persistency for blocks and in memory caching LRU block caching
    inner: Mutex<Inner>,
}

impl ThreadSafeMemoryStorage {
    /// Returns a read-only view of the current state for VM execution.
    pub fn state_view(&self) -> StateView<'_, Self> {
        StateView { storage: self }
    }
}

impl Storage for ThreadSafeMemoryStorage {
    fn new(genesis: Arc<Block>, chain_id: u64) -> Self {
        let mut headers = HashMap::new();
        let mut blocks = HashMap::new();

        let genesis_hash = genesis.header_hash(chain_id);
        let state_root = genesis.header.state_root;

        headers.insert(genesis_hash, genesis.header);
        blocks.insert(genesis_hash, genesis);

        let inner = Inner {
            headers,
            blocks,
            tip: genesis_hash,
            state: HashMap::new(),
            state_root,
        };

        Self {
            inner: Mutex::new(inner),
        }
    }

    fn has_block(&self, hash: Hash) -> bool {
        let inner = self.inner.lock().unwrap();
        inner.headers.contains_key(&hash)
    }

    fn get_header(&self, hash: Hash) -> Option<Header> {
        let inner = self.inner.lock().unwrap();
        inner.headers.get(&hash).cloned()
    }

    fn get_block(&self, hash: Hash) -> Option<Arc<Block>> {
        let inner = self.inner.lock().unwrap();
        inner.blocks.get(&hash).cloned()
    }

    fn append_block(&self, block: Arc<Block>, chain_id: u64) -> Result<(), StorageError> {
        let mut inner = self.inner.lock().unwrap();

        let expected_tip = inner.tip;
        if block.header.previous_block != expected_tip {
            return Err(StorageError::NotOnTip {
                expected: expected_tip,
                actual: block.header.previous_block,
            });
        }

        let hash = block.header_hash(chain_id);

        inner.headers.insert(hash, block.header);
        inner.blocks.insert(hash, block);
        inner.tip = hash;

        Ok(())
    }

    fn height(&self) -> u64 {
        let inner = self.inner.lock().unwrap();

        inner
            .headers
            .len()
            .saturating_sub(1)
            .try_into()
            .expect("blockchain height exceeds u64::MAX")
    }

    fn tip(&self) -> Hash {
        let inner = self.inner.lock().unwrap();
        inner.tip
    }
}

impl StateStore for ThreadSafeMemoryStorage {
    fn get(&self, key: Hash) -> Option<Vec<u8>> {
        self.inner.lock().unwrap().state.get(&key).cloned()
    }

    fn apply_batch(&self, writes: Vec<(Hash, Option<Vec<u8>>)>) {
        let mut inner = self.inner.lock().unwrap();

        for (key, value_opt) in writes {
            match value_opt {
                Some(value) => {
                    inner.state.insert(key, value);
                }
                None => {
                    inner.state.remove(&key);
                }
            }
        }
    }

    fn state_root(&self) -> Hash {
        self.inner.lock().unwrap().state_root
    }

    fn set_state_root(&self, root: Hash) {
        self.inner.lock().unwrap().state_root = root;
    }
}

impl IterableState for ThreadSafeMemoryStorage {
    fn iter_all(&self) -> Box<dyn Iterator<Item = (Hash, Vec<u8>)> + '_> {
        let snapshot: Vec<(Hash, Vec<u8>)> = {
            let inner = self.inner.lock().unwrap();
            inner.state.iter().map(|(k, v)| (*k, v.clone())).collect()
        };

        Box::new(snapshot.into_iter())
    }
}

impl StateViewProvider for ThreadSafeMemoryStorage {
    fn state_view(&self) -> StateView<'_, Self>
    where
        Self: Sized + StateStore,
    {
        StateView { storage: self }
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

    const TEST_CHAIN_ID: u64 = 78909876543;

    pub trait StorageExtForTests {
        /// Appends a block to storage and updates the chain tip (requires mutable access).
        ///
        /// # Panics
        /// Panics if not implemented for this storage type.
        #[cfg(test)]
        fn append_block_mut(&mut self, block: Arc<Block>, chain_id: u64);
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
        state: HashMap<Hash, Vec<u8>>,
        state_root: Hash,
    }

    impl Storage for TestStorage {
        fn new(genesis: Arc<Block>, chain_id: u64) -> Self {
            let mut storage = Self {
                headers: HashMap::new(),
                blocks: HashMap::new(),
                tip: Hash::zero(),
                state: HashMap::new(),
                state_root: Hash::zero(),
            };
            storage.append_block_mut(genesis, chain_id);
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

        fn append_block(&self, _: Arc<Block>, _: u64) -> Result<(), StorageError> {
            panic!(
                "TestStorage::append_block is not supported. Use append_block_mut from StorageExtForTests trait instead."
            )
        }

        fn height(&self) -> u64 {
            self.headers
                .len()
                .saturating_sub(1)
                .try_into()
                .expect("blockchain height exceeds u64::MAX")
        }

        fn tip(&self) -> Hash {
            self.tip
        }
    }

    impl StateStore for TestStorage {
        fn get(&self, key: Hash) -> Option<Vec<u8>> {
            self.state.get(&key).cloned()
        }

        fn apply_batch(&self, _writes: Vec<(Hash, Option<Vec<u8>>)>) {
            todo!()
        }

        fn state_root(&self) -> Hash {
            self.state_root
        }

        fn set_state_root(&self, _root: Hash) {
            todo!()
        }
    }

    impl IterableState for TestStorage {
        fn iter_all(&self) -> Box<dyn Iterator<Item = (Hash, Vec<u8>)> + '_> {
            Box::new(self.state.iter().map(|(k, v)| (*k, v.clone())))
        }
    }

    impl StorageExtForTests for TestStorage {
        fn append_block_mut(&mut self, block: Arc<Block>, chain_id: u64) {
            if block.header.previous_block != self.tip {
                panic!(
                    "Block does not build on current tip: {} != {}",
                    block.header.previous_block, self.tip
                );
            }

            let hash = block.header_hash(chain_id);

            self.headers.insert(hash, block.header);
            self.blocks.insert(hash, block);

            self.tip = hash;
        }
    }

    impl StateViewProvider for TestStorage {
        fn state_view(&self) -> StateView<'_, Self>
        where
            Self: Sized + StateStore,
        {
            StateView { storage: self }
        }
    }

    fn create_block_at(height: u64, previous: Hash) -> Arc<Block> {
        let header = Header {
            version: 1,
            height,
            timestamp: 0,
            previous_block: previous,
            data_hash: Hash::zero(),
            merkle_root: Hash::zero(),
            state_root: Hash::zero(),
        };
        Block::new(header, PrivateKey::new(), vec![], TEST_CHAIN_ID)
    }

    #[test]
    fn in_memory_storage_new_initializes_with_genesis() {
        let genesis = create_genesis(TEST_CHAIN_ID);
        let hash = genesis.header_hash(TEST_CHAIN_ID);
        let storage = TestStorage::new(genesis, TEST_CHAIN_ID);

        assert_eq!(storage.height(), 0);
        assert_eq!(storage.tip(), hash);
        assert!(storage.has_block(hash));
    }

    #[test]
    fn in_memory_storage_append_and_retrieve() {
        let genesis = create_genesis(TEST_CHAIN_ID);
        let mut storage = TestStorage::new(genesis.clone(), TEST_CHAIN_ID);

        let block1 = create_block_at(1, genesis.header_hash(TEST_CHAIN_ID));
        storage.append_block_mut(block1.clone(), TEST_CHAIN_ID);

        assert_eq!(storage.height(), 1);
        assert_eq!(storage.tip(), block1.header_hash(TEST_CHAIN_ID));
        assert!(storage.has_block(block1.header_hash(TEST_CHAIN_ID)));
        assert_eq!(
            storage
                .get_block(block1.header_hash(TEST_CHAIN_ID))
                .unwrap()
                .header_hash(TEST_CHAIN_ID),
            block1.header_hash(TEST_CHAIN_ID)
        );
    }

    #[test]
    fn in_memory_storage_get_header() {
        let genesis = create_genesis(TEST_CHAIN_ID);
        let storage = TestStorage::new(genesis.clone(), TEST_CHAIN_ID);

        let header = storage
            .get_header(genesis.header_hash(TEST_CHAIN_ID))
            .unwrap();
        assert_eq!(header.height, 0);
    }

    #[test]
    fn in_memory_storage_get_nonexistent_block() {
        let genesis = create_genesis(TEST_CHAIN_ID);
        let storage = TestStorage::new(genesis, TEST_CHAIN_ID);

        assert!(storage.get_block(random_hash()).is_none());
        assert!(storage.get_header(random_hash()).is_none());
    }

    #[test]
    #[should_panic(expected = "Block does not build on current tip")]
    fn in_memory_storage_rejects_block_not_on_tip() {
        let genesis = create_genesis(TEST_CHAIN_ID);
        let mut storage = TestStorage::new(genesis, TEST_CHAIN_ID);

        let orphan = create_block_at(1, random_hash());
        storage.append_block_mut(orphan, TEST_CHAIN_ID);
    }

    #[test]
    fn thread_safe_storage_new_initializes_with_genesis() {
        let genesis = create_genesis(TEST_CHAIN_ID);
        let hash = genesis.header_hash(TEST_CHAIN_ID);
        let storage = ThreadSafeMemoryStorage::new(genesis, TEST_CHAIN_ID);

        assert_eq!(storage.height(), 0);
        assert_eq!(storage.tip(), hash);
        assert!(storage.has_block(hash));
    }

    #[test]
    fn thread_safe_storage_append_and_retrieve() {
        let genesis = create_genesis(TEST_CHAIN_ID);
        let storage = ThreadSafeMemoryStorage::new(genesis.clone(), TEST_CHAIN_ID);

        let block1 = create_block_at(1, genesis.header_hash(TEST_CHAIN_ID));
        assert!(storage.append_block(block1.clone(), TEST_CHAIN_ID).is_ok());

        assert_eq!(storage.height(), 1);
        assert_eq!(storage.tip(), block1.header_hash(TEST_CHAIN_ID));
        assert!(storage.has_block(block1.header_hash(TEST_CHAIN_ID)));
    }

    #[test]
    fn thread_safe_storage_concurrent_reads() {
        let genesis = create_genesis(TEST_CHAIN_ID);
        let storage = Arc::new(ThreadSafeMemoryStorage::new(genesis.clone(), TEST_CHAIN_ID));
        let hash = genesis.header_hash(TEST_CHAIN_ID);

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
        let genesis = create_genesis(TEST_CHAIN_ID);
        let storage = ThreadSafeMemoryStorage::new(genesis, TEST_CHAIN_ID);

        let orphan = create_block_at(1, random_hash());
        assert!(storage.append_block(orphan, TEST_CHAIN_ID).is_err());
    }

    #[test]
    fn thread_safe_storage_chain_of_blocks() {
        let genesis = create_genesis(TEST_CHAIN_ID);
        let storage = ThreadSafeMemoryStorage::new(genesis.clone(), TEST_CHAIN_ID);

        let mut prev_hash = genesis.header_hash(TEST_CHAIN_ID);
        for i in 1..=10 {
            let block = create_block_at(i, prev_hash);
            prev_hash = block.header_hash(TEST_CHAIN_ID);
            assert!(storage.append_block(block, TEST_CHAIN_ID).is_ok());
        }

        assert_eq!(storage.height(), 10);
        assert_eq!(storage.tip(), prev_hash);
    }

    // ==================== StateStore Tests ====================

    fn h(s: &[u8]) -> Hash {
        let mut h = Hash::sha3();
        h.update(s);
        h.finalize()
    }

    #[test]
    fn state_store_get_returns_none_for_missing_key() {
        let genesis = create_genesis(TEST_CHAIN_ID);
        let storage = ThreadSafeMemoryStorage::new(genesis, TEST_CHAIN_ID);
        assert_eq!(StateStore::get(&storage, h(b"missing")), None);
    }

    #[test]
    fn state_store_apply_batch_inserts_and_deletes() {
        let genesis = create_genesis(TEST_CHAIN_ID);
        let storage = ThreadSafeMemoryStorage::new(genesis, TEST_CHAIN_ID);

        let key1 = h(b"key1");
        let key2 = h(b"key2");

        storage.apply_batch(vec![
            (key1, Some(b"value1".to_vec())),
            (key2, Some(b"value2".to_vec())),
        ]);

        assert_eq!(StateStore::get(&storage, key1), Some(b"value1".to_vec()));
        assert_eq!(StateStore::get(&storage, key2), Some(b"value2".to_vec()));

        storage.apply_batch(vec![(key1, None)]);
        assert_eq!(StateStore::get(&storage, key1), None);
        assert_eq!(StateStore::get(&storage, key2), Some(b"value2".to_vec()));
    }

    #[test]
    fn state_store_state_root_operations() {
        let genesis = create_genesis(TEST_CHAIN_ID);
        let storage = ThreadSafeMemoryStorage::new(genesis.clone(), TEST_CHAIN_ID);

        assert_eq!(storage.state_root(), genesis.header.state_root);

        let new_root = random_hash();
        storage.set_state_root(new_root);
        assert_eq!(storage.state_root(), new_root);
    }

    #[test]
    fn iterable_state_iter_all() {
        let genesis = create_genesis(TEST_CHAIN_ID);
        let storage = ThreadSafeMemoryStorage::new(genesis, TEST_CHAIN_ID);

        let key_a = h(b"a");
        let key_b = h(b"b");

        storage.apply_batch(vec![
            (key_a, Some(b"1".to_vec())),
            (key_b, Some(b"2".to_vec())),
        ]);

        let entries: Vec<_> = storage.iter_all().collect();
        assert_eq!(entries.len(), 2);
        assert!(entries.contains(&(key_a, b"1".to_vec())));
        assert!(entries.contains(&(key_b, b"2".to_vec())));
    }
}
