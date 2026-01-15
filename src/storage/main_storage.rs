use crate::core::account::Account;
use crate::core::block::{Block, Header};
use crate::crypto::key_pair::Address;
use crate::storage::state_store::{AccountStorage, StateStore, VmStorage};
use crate::storage::state_view::{StateView, StateViewProvider};
use crate::storage::storage_trait::{Storage, StorageError};
use crate::types::encoding::{Decode, Encode};
use crate::types::hash::Hash;
use sparse_merkle_tree::blake2b::Blake2bHasher;
use sparse_merkle_tree::default_store::DefaultStore;
use sparse_merkle_tree::traits::Value;
use sparse_merkle_tree::{H256, SparseMerkleTree};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Wrapper type for byte vectors stored in the sparse Merkle tree.
#[derive(Default, Clone)]
pub struct SmtValue(pub Vec<u8>);

impl Value for SmtValue {
    fn to_h256(&self) -> H256 {
        if self.0.is_empty() {
            return H256::zero();
        }
        let mut hasher = Hash::sha3();
        hasher.update(&self.0);
        H256::from(hasher.finalize().0)
    }

    fn zero() -> Self {
        Self(Vec::new())
    }
}

pub type Smt = SparseMerkleTree<Blake2bHasher, SmtValue, DefaultStore<SmtValue>>;

struct Inner {
    /// Block headers indexed by hash.
    headers: HashMap<Hash, Header>,
    /// Full blocks indexed by hash.
    blocks: HashMap<Hash, Arc<Block>>,
    /// Hash of the current chain tip.
    tip: Hash,
    /// Key-value storage for VM execution.
    state: Smt,
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
    fn new(genesis: Block, chain_id: u64, initial_accounts: &[(Address, Account)]) -> Self {
        let mut headers = HashMap::new();
        let mut blocks = HashMap::new();

        let mut state = Smt::new(H256::zero(), DefaultStore::default());
        for (addr, account) in initial_accounts {
            state
                .update(hash_to_h256(addr), SmtValue(account.to_bytes().to_vec()))
                .expect("smt update failed");
        }

        let state_root = h256_to_hash(state.root());
        if state_root != genesis.header.state_root {
            panic!(
                "Creating storage failed: {}",
                StorageError::ValidationFailed(format!(
                    "state_root mismatch: expected {} and got {state_root}",
                    genesis.header.state_root,
                ))
            )
        }

        let genesis_hash = genesis.header_hash(chain_id);
        headers.insert(genesis_hash, genesis.header.clone());
        blocks.insert(genesis_hash, Arc::new(genesis));

        let inner = Inner {
            headers,
            blocks,
            tip: genesis_hash,
            state,
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

    fn append_block(&self, block: Block, chain_id: u64) -> Result<(), StorageError> {
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
        inner.blocks.insert(hash, Arc::new(block));
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

pub fn hash_to_h256(hash: &Hash) -> H256 {
    H256::from(hash.0)
}

pub fn h256_to_hash(h256: &H256) -> Hash {
    Hash::from_slice(h256.as_slice()).unwrap_or_else(Hash::zero)
}

impl StateStore for MainStorage {
    fn preview_root(&self, writes: &[(Hash, Option<Vec<u8>>)]) -> Hash {
        let inner = self.inner.lock().unwrap();
        let clone = inner.state.store().clone();
        let mut state = Smt::new(*inner.state.root(), clone);

        for (key, value_opt) in writes {
            let val = match value_opt {
                Some(v) => SmtValue(v.clone()),
                None => SmtValue::zero(),
            };
            state
                .update(hash_to_h256(key), val)
                .expect("SMT update failed");
        }
        h256_to_hash(state.root())
    }

    fn apply_batch(&self, writes: Vec<(Hash, Option<Vec<u8>>)>) {
        let mut inner = self.inner.lock().unwrap();

        for (key, value_opt) in writes {
            inner
                .state
                .update(hash_to_h256(&key), SmtValue(value_opt.unwrap_or_default()))
                .expect("SMT update failed");
        }

        inner.state_root = h256_to_hash(inner.state.root());
    }

    fn state_root(&self) -> Hash {
        self.inner.lock().unwrap().state_root
    }
}

impl VmStorage for MainStorage {
    fn contains_key(&self, key: Hash) -> bool {
        let inner = self.inner.lock().unwrap();
        inner.state.get(&hash_to_h256(&key)).is_ok()
    }

    fn get(&self, key: Hash) -> Option<Vec<u8>> {
        let inner = self.inner.lock().unwrap();
        inner
            .state
            .get(&hash_to_h256(&key))
            .ok()
            .filter(|v| !v.0.is_empty())
            .map(|v| v.0)
    }
}

impl AccountStorage for MainStorage {
    fn get_account(&self, addr: Address) -> Option<Account> {
        let inner = self.inner.lock().unwrap();
        inner
            .state
            .get(&hash_to_h256(&addr))
            .ok()
            .filter(|v| !v.0.is_empty())
            .and_then(|v| Account::decode(&mut v.0.as_slice()).ok())
    }

    fn set_account(&self, addr: Address, account: Account) {
        self.apply_batch(vec![(addr, Some(account.to_vec()))]);
    }

    fn delete_account(&self, addr: Address) {
        self.apply_batch(vec![(addr, None)]);
    }
}

impl StateViewProvider for MainStorage {
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
    use crate::storage::state_store::VmStorage;
    use crate::utils::test_utils::utils::{create_genesis, create_test_block, random_hash};
    use std::thread;

    const TEST_CHAIN_ID: u64 = 78909876543;

    fn h(s: &[u8]) -> Hash {
        let mut h = Hash::sha3();
        h.update(s);
        h.finalize()
    }

    fn main_storage(block: Block) -> MainStorage {
        MainStorage::new(block, TEST_CHAIN_ID, &[])
    }

    #[test]
    fn new_initializes_with_genesis() {
        let genesis = create_genesis(TEST_CHAIN_ID);
        let hash = genesis.header_hash(TEST_CHAIN_ID);
        let storage = main_storage(genesis);

        assert_eq!(storage.height(), 0);
        assert_eq!(storage.tip(), hash);
        assert!(storage.has_block(hash));
    }

    #[test]
    fn append_and_retrieve() {
        let genesis = create_genesis(TEST_CHAIN_ID);
        let storage = main_storage(genesis.clone());

        let block1 = create_test_block(1, genesis.header_hash(TEST_CHAIN_ID), TEST_CHAIN_ID);
        assert!(storage.append_block(block1.clone(), TEST_CHAIN_ID).is_ok());

        assert_eq!(storage.height(), 1);
        assert_eq!(storage.tip(), block1.header_hash(TEST_CHAIN_ID));
        assert!(storage.has_block(block1.header_hash(TEST_CHAIN_ID)));
    }

    #[test]
    fn concurrent_reads() {
        let genesis = create_genesis(TEST_CHAIN_ID);
        let storage = Arc::new(main_storage(genesis.clone()));
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
        let storage = main_storage(genesis);

        let orphan = create_test_block(1, random_hash(), TEST_CHAIN_ID);
        assert!(storage.append_block(orphan, TEST_CHAIN_ID).is_err());
    }

    #[test]
    fn chain_of_blocks() {
        let genesis = create_genesis(TEST_CHAIN_ID);
        let storage = main_storage(genesis.clone());

        let mut prev_hash = genesis.header_hash(TEST_CHAIN_ID);
        for i in 1..=10 {
            let block = create_test_block(i, prev_hash, TEST_CHAIN_ID);
            prev_hash = block.header_hash(TEST_CHAIN_ID);
            assert!(storage.append_block(block, TEST_CHAIN_ID).is_ok());
        }

        assert_eq!(storage.height(), 10);
        assert_eq!(storage.tip(), prev_hash);
    }

    #[test]
    fn state_store_get_returns_none_for_missing_key() {
        let genesis = create_genesis(TEST_CHAIN_ID);
        let storage = main_storage(genesis);
        assert_eq!(VmStorage::get(&storage, h(b"missing")), None);
    }

    #[test]
    fn state_store_apply_batch_inserts_and_deletes() {
        let genesis = create_genesis(TEST_CHAIN_ID);
        let storage = main_storage(genesis);

        let key1 = h(b"key1");
        let key2 = h(b"key2");

        storage.apply_batch(vec![
            (key1, Some(b"value1".to_vec())),
            (key2, Some(b"value2".to_vec())),
        ]);

        assert_eq!(VmStorage::get(&storage, key1), Some(b"value1".to_vec()));
        assert_eq!(VmStorage::get(&storage, key2), Some(b"value2".to_vec()));

        storage.apply_batch(vec![(key1, None)]);
        assert_eq!(VmStorage::get(&storage, key1), None);
        assert_eq!(VmStorage::get(&storage, key2), Some(b"value2".to_vec()));
    }
}
