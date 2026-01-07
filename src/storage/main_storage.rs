use crate::core::block::{Block, Header};
use crate::storage::state::{IterableState, StateStore, StateView, StateViewProvider};
use crate::storage::storage_trait::{Storage, StorageError};
use crate::types::hash::Hash;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

struct Inner {
    /// Block headers indexed by hash.
    headers: HashMap<Hash, Header>,
    /// Full blocks indexed by hash.
    blocks: HashMap<Hash, Arc<Block>>,
    /// Hash of the current chain tip.
    tip: Hash,
    /// Key-value storage storage for VM execution.
    state: HashMap<Hash, Vec<u8>>,
    /// Root hash of the current storage.
    state_root: Hash,
}

/// In-memory storage for development as it is thread safe
///
/// Stores blocks and headers in hash maps with O(1) lookup.
/// Not yet fully suitable for production due to storing all blocks in memory.
pub struct MainStorage {
    // TODO: add disk persistency for blocks and in memory caching LRU block caching
    inner: Mutex<Inner>,
}

impl Storage for MainStorage {
    fn new(genesis: Arc<Block>, chain_id: u64) -> Self {
        let mut headers = HashMap::new();
        let mut blocks = HashMap::new();

        let genesis_hash = genesis.header_hash(chain_id);
        let state_root = genesis.header.state_root;

        headers.insert(genesis_hash, genesis.header.clone());
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

        inner.headers.insert(hash, block.header.clone());
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

impl StateStore for MainStorage {
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

impl IterableState for MainStorage {
    fn iter_all(&self) -> Box<dyn Iterator<Item = (Hash, Vec<u8>)> + '_> {
        let snapshot: Vec<(Hash, Vec<u8>)> = {
            let inner = self.inner.lock().unwrap();
            inner.state.iter().map(|(k, v)| (*k, v.clone())).collect()
        };

        Box::new(snapshot.into_iter())
    }
}

impl StateViewProvider for MainStorage {
    fn state_view(&self) -> StateView<'_, Self>
    where
        Self: Sized + StateStore,
    {
        StateView::new(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::block::Header;
    use crate::crypto::key_pair::PrivateKey;
    use crate::storage::state::{IterableState, StateStore};
    use crate::utils::test_utils::utils::{create_genesis, random_hash};
    use std::thread;

    const TEST_CHAIN_ID: u64 = 78909876543;

    fn create_block_at(height: u64, previous: Hash) -> Arc<Block> {
        let header = Header {
            version: 1,
            height,
            timestamp: 0,
            previous_block: previous,
            merkle_root: Hash::zero(),
            state_root: Hash::zero(),
        };
        Block::new(header, PrivateKey::new(), vec![], TEST_CHAIN_ID)
    }

    fn h(s: &[u8]) -> Hash {
        let mut h = Hash::sha3();
        h.update(s);
        h.finalize()
    }

    #[test]
    fn new_initializes_with_genesis() {
        let genesis = create_genesis(TEST_CHAIN_ID);
        let hash = genesis.header_hash(TEST_CHAIN_ID);
        let storage = MainStorage::new(genesis, TEST_CHAIN_ID);

        assert_eq!(storage.height(), 0);
        assert_eq!(storage.tip(), hash);
        assert!(storage.has_block(hash));
    }

    #[test]
    fn append_and_retrieve() {
        let genesis = create_genesis(TEST_CHAIN_ID);
        let storage = MainStorage::new(genesis.clone(), TEST_CHAIN_ID);

        let block1 = create_block_at(1, genesis.header_hash(TEST_CHAIN_ID));
        assert!(storage.append_block(block1.clone(), TEST_CHAIN_ID).is_ok());

        assert_eq!(storage.height(), 1);
        assert_eq!(storage.tip(), block1.header_hash(TEST_CHAIN_ID));
        assert!(storage.has_block(block1.header_hash(TEST_CHAIN_ID)));
    }

    #[test]
    fn concurrent_reads() {
        let genesis = create_genesis(TEST_CHAIN_ID);
        let storage = Arc::new(MainStorage::new(genesis.clone(), TEST_CHAIN_ID));
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
    fn rejects_block_not_on_tip() {
        let genesis = create_genesis(TEST_CHAIN_ID);
        let storage = MainStorage::new(genesis, TEST_CHAIN_ID);

        let orphan = create_block_at(1, random_hash());
        assert!(storage.append_block(orphan, TEST_CHAIN_ID).is_err());
    }

    #[test]
    fn chain_of_blocks() {
        let genesis = create_genesis(TEST_CHAIN_ID);
        let storage = MainStorage::new(genesis.clone(), TEST_CHAIN_ID);

        let mut prev_hash = genesis.header_hash(TEST_CHAIN_ID);
        for i in 1..=10 {
            let block = create_block_at(i, prev_hash);
            prev_hash = block.header_hash(TEST_CHAIN_ID);
            assert!(storage.append_block(block, TEST_CHAIN_ID).is_ok());
        }

        assert_eq!(storage.height(), 10);
        assert_eq!(storage.tip(), prev_hash);
    }

    #[test]
    fn state_store_get_returns_none_for_missing_key() {
        let genesis = create_genesis(TEST_CHAIN_ID);
        let storage = MainStorage::new(genesis, TEST_CHAIN_ID);
        assert_eq!(StateStore::get(&storage, h(b"missing")), None);
    }

    #[test]
    fn state_store_apply_batch_inserts_and_deletes() {
        let genesis = create_genesis(TEST_CHAIN_ID);
        let storage = MainStorage::new(genesis, TEST_CHAIN_ID);

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
        let storage = MainStorage::new(genesis.clone(), TEST_CHAIN_ID);

        assert_eq!(storage.state_root(), genesis.header.state_root);

        let new_root = random_hash();
        storage.set_state_root(new_root);
        assert_eq!(storage.state_root(), new_root);
    }

    #[test]
    fn iterable_state_iter_all() {
        let genesis = create_genesis(TEST_CHAIN_ID);
        let storage = MainStorage::new(genesis, TEST_CHAIN_ID);

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
