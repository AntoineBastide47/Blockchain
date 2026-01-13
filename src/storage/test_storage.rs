#[cfg(test)]
pub mod test {
    use crate::core::account::Account;
    use crate::core::block::{Block, Header};
    use crate::crypto::key_pair::Address;
    use crate::storage::state_store::{AccountStorage, IterableState, StateStore, VmStorage};
    use crate::storage::state_view::{StateView, StateViewProvider};
    use crate::storage::storage_trait::{Storage, StorageError};
    use crate::types::encoding::{Decode, Encode};
    use crate::types::hash::Hash;
    use crate::utils::test_utils::utils::{create_genesis, create_test_block, random_hash};
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::sync::RwLock;

    /// In-memory storage for testing and development.
    ///
    /// Stores blocks and headers in hash maps with O(1) lookup.
    /// Not suitable for production due to memory constraints and being thread unsafe.
    pub struct TestStorage {
        headers: RwLock<HashMap<Hash, Header>>,
        blocks: RwLock<HashMap<Hash, Arc<Block>>>,
        tip: RwLock<Hash>,
        state: RwLock<HashMap<Hash, Vec<u8>>>,
        state_root: RwLock<Hash>,
    }

    impl Storage for TestStorage {
        fn new(genesis: Block, chain_id: u64) -> Self {
            let storage = Self {
                headers: RwLock::new(HashMap::new()),
                blocks: RwLock::new(HashMap::new()),
                tip: RwLock::new(Hash::zero()),
                state: RwLock::new(HashMap::new()),
                state_root: RwLock::new(Hash::zero()),
            };
            storage
                .append_block(genesis, chain_id)
                .expect("append_block failed");
            storage
        }

        fn has_block(&self, hash: Hash) -> bool {
            self.blocks.read().unwrap().contains_key(&hash)
        }

        fn get_header(&self, hash: Hash) -> Option<Header> {
            self.headers.read().unwrap().get(&hash).cloned()
        }

        fn get_block(&self, hash: Hash) -> Option<Arc<Block>> {
            self.blocks.read().unwrap().get(&hash).cloned()
        }

        fn append_block(&self, block: Block, chain_id: u64) -> Result<(), StorageError> {
            let current_tip = *self.tip.read().unwrap();
            if block.header.previous_block != current_tip {
                panic!(
                    "Block does not build on current tip: {} != {}",
                    block.header.previous_block, current_tip
                );
            }

            let hash = block.header_hash(chain_id);

            self.headers
                .write()
                .unwrap()
                .insert(hash, block.header.clone());
            self.blocks.write().unwrap().insert(hash, Arc::new(block));
            *self.tip.write().unwrap() = hash;

            Ok(())
        }

        fn height(&self) -> u64 {
            self.headers
                .read()
                .unwrap()
                .len()
                .saturating_sub(1)
                .try_into()
                .expect("blockchain height exceeds u64::MAX")
        }

        fn tip(&self) -> Hash {
            *self.tip.read().unwrap()
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

    impl StateViewProvider for TestStorage {
        fn state_view(&self) -> StateView<'_, Self>
        where
            Self: Sized + VmStorage,
        {
            StateView::new(self)
        }
    }

    const TEST_CHAIN_ID: u64 = 78909876543;

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
        let storage = TestStorage::new(genesis.clone(), TEST_CHAIN_ID);

        let block1 = create_test_block(1, genesis.header_hash(TEST_CHAIN_ID), TEST_CHAIN_ID);
        storage.append_block(block1.clone(), TEST_CHAIN_ID).unwrap();

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
        let storage = TestStorage::new(genesis, TEST_CHAIN_ID);

        let orphan = create_test_block(1, random_hash(), TEST_CHAIN_ID);
        storage.append_block(orphan, TEST_CHAIN_ID).unwrap();
    }
}
