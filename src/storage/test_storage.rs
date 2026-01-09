#[cfg(test)]
pub mod test {
    use crate::core::account::Account;
    use crate::core::block::{Block, Header};
    use crate::crypto::key_pair::{Address, PrivateKey};
    use crate::storage::state_store::{AccountStorage, IterableState, StateStore, VmStorage};
    use crate::storage::state_view::{StateView, StateViewProvider};
    use crate::storage::storage_trait::{Storage, StorageError};
    use crate::types::encoding::{Decode, Encode};
    use crate::types::hash::Hash;
    use crate::utils::test_utils::utils::{create_genesis, random_hash};
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::sync::RwLock;

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
        state: RwLock<HashMap<Hash, Vec<u8>>>,
        state_root: RwLock<Hash>,
    }

    impl Storage for TestStorage {
        fn new(genesis: Arc<Block>, chain_id: u64) -> Self {
            let mut storage = Self {
                headers: HashMap::new(),
                blocks: HashMap::new(),
                tip: Hash::zero(),
                state: RwLock::new(HashMap::new()),
                state_root: RwLock::new(Hash::zero()),
            };
            storage.append_block_mut(genesis, chain_id);
            storage
        }

        fn has_block(&self, hash: Hash) -> bool {
            self.blocks.contains_key(&hash)
        }

        fn get_header(&self, hash: Hash) -> Option<Header> {
            self.headers.get(&hash).cloned()
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
        fn apply_batch(&self, writes: Vec<(Hash, Option<Vec<u8>>)>) {
            let mut state = self.state.write().unwrap();
            for (key, value) in writes {
                match value {
                    Some(v) => {
                        state.insert(key, v);
                    }
                    None => {
                        state.remove(&key);
                    }
                }
            }

            // Recompute root deterministically from sorted entries.
            let mut sorted = std::collections::BTreeMap::new();
            for (k, v) in state.iter() {
                sorted.insert(*k, v.clone());
            }

            let mut h = Hash::sha3();
            h.update(b"STATE_ROOT");
            for (k, v) in sorted {
                k.encode(&mut h);
                v.encode(&mut h);
            }

            *self.state_root.write().unwrap() = h.finalize();
        }
        fn state_root(&self) -> Hash {
            *self.state_root.read().unwrap()
        }
    }

    impl VmStorage for TestStorage {
        fn get(&self, key: Hash) -> Option<Vec<u8>> {
            self.state.read().unwrap().get(&key).cloned()
        }

        fn set_state_root(&self, root: Hash) {
            *self.state_root.write().unwrap() = root;
        }
    }

    impl AccountStorage for TestStorage {
        fn get_account(&self, addr: Address) -> Option<Account> {
            self.get(addr)
                .and_then(|bytes| Account::decode(&mut bytes.as_slice()).ok())
        }

        fn set_account(&mut self, addr: Address, account: Account) {
            self.apply_batch(vec![(addr, Some(account.to_vec()))]);
        }

        fn delete_account(&mut self, addr: Address) {
            self.apply_batch(vec![(addr, None)]);
        }
    }

    impl IterableState for TestStorage {
        fn iter_all(&self) -> Box<dyn Iterator<Item = (Hash, Vec<u8>)> + '_> {
            let snapshot: Vec<(Hash, Vec<u8>)> = self
                .state
                .read()
                .unwrap()
                .iter()
                .map(|(k, v)| (*k, v.clone()))
                .collect();

            Box::new(snapshot.into_iter())
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

            self.headers.insert(hash, block.header.clone());
            self.blocks.insert(hash, block);

            self.tip = hash;
        }
    }

    impl StateViewProvider for TestStorage {
        fn state_view(&self) -> StateView<'_, Self>
        where
            Self: Sized + VmStorage,
        {
            StateView::new(self)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

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

        #[test]
        fn new_initializes_with_genesis() {
            let genesis = create_genesis(TEST_CHAIN_ID);
            let hash = genesis.header_hash(TEST_CHAIN_ID);
            let storage = TestStorage::new(genesis, TEST_CHAIN_ID);

            assert_eq!(storage.height(), 0);
            assert_eq!(storage.tip(), hash);
            assert!(storage.has_block(hash));
        }

        #[test]
        fn append_and_retrieve() {
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
        fn get_header() {
            let genesis = create_genesis(TEST_CHAIN_ID);
            let storage = TestStorage::new(genesis.clone(), TEST_CHAIN_ID);

            let header = storage
                .get_header(genesis.header_hash(TEST_CHAIN_ID))
                .unwrap();
            assert_eq!(header.height, 0);
        }

        #[test]
        fn get_nonexistent_block() {
            let genesis = create_genesis(TEST_CHAIN_ID);
            let storage = TestStorage::new(genesis, TEST_CHAIN_ID);

            assert!(storage.get_block(random_hash()).is_none());
            assert!(storage.get_header(random_hash()).is_none());
        }

        #[test]
        #[should_panic(expected = "Block does not build on current tip")]
        fn rejects_block_not_on_tip() {
            let genesis = create_genesis(TEST_CHAIN_ID);
            let mut storage = TestStorage::new(genesis, TEST_CHAIN_ID);

            let orphan = create_block_at(1, random_hash());
            storage.append_block_mut(orphan, TEST_CHAIN_ID);
        }
    }
}
