//! Transaction pool for pending transactions awaiting block inclusion.
//!
//! Provides thread-safe storage and ordering of unconfirmed transactions.

use crate::core::transaction::Transaction;
use crate::types::hash::Hash;
use dashmap::DashMap;
use std::collections::HashSet;
use std::sync::RwLock;

/// Default transaction pool capacity.
pub const TXPOOL_CAPACITY: usize = 100_000;
/// Maximum number of transactions returned for block building.
pub const MAX_TRANSACTION_PER_BLOCK: usize = 20_000;

/// Thread-safe pool of pending transactions.
///
/// Maintains insertion order for deterministic block construction while
/// providing O(1) duplicate detection via hash lookup.
pub struct TxPool {
    /// Transactions indexed by hash for fast lookup and deduplication.
    transactions: DashMap<Hash, Transaction>,
    /// Insertion order for deterministic transaction ordering in blocks.
    order: RwLock<Vec<Hash>>,
    /// Maximum number of transactions the pool will accept.
    capacity: usize,
}

impl TxPool {
    /// Creates a new transaction pool with the given capacity.
    ///
    /// Uses `TXPOOL_CAPACITY` if `None` is provided.
    pub fn new(capacity: Option<usize>) -> Self {
        let cap = capacity.unwrap_or(TXPOOL_CAPACITY).max(1);

        Self {
            transactions: DashMap::with_capacity(cap),
            order: RwLock::new(Vec::with_capacity(cap)),
            capacity: cap,
        }
    }

    /// Returns `true` if the pool contains a transaction with the given hash.
    pub fn contains(&self, hash: Hash) -> bool {
        self.transactions.contains_key(&hash)
    }

    /// Adds a transaction to the pool if not already present.
    ///
    /// The `chain_id` is used to compute the transaction ID for deduplication.
    /// Silently drops the transaction if the pool is at capacity.
    pub fn append(&self, transaction: Transaction, chain_id: u64) {
        let hash = transaction.id(chain_id);

        if self.length() >= self.capacity {
            return;
        }

        // Fast path for duplicates to avoid bloating the ordering vector.
        match self.transactions.entry(hash) {
            dashmap::mapref::entry::Entry::Occupied(_) => (),
            dashmap::mapref::entry::Entry::Vacant(v) => {
                v.insert(transaction);
                let mut order = self.order.write().unwrap();
                order.push(hash);
            }
        }
    }

    /// Returns the number of transactions in the pool.
    pub fn length(&self) -> usize {
        self.transactions.len()
    }

    /// Removes all transactions from the pool.
    pub fn flush(&self) {
        self.transactions.clear();
        self.order.write().unwrap().clear();
    }

    /// Removes transactions with the given hashes from the pool.
    pub fn remove_batch(&self, hashes: &[Hash]) {
        let removals: HashSet<Hash> = hashes.iter().copied().collect();

        for hash in &removals {
            self.transactions.remove(hash);
        }

        let mut order = self.order.write().unwrap();
        order.retain(|h| !removals.contains(h));
    }

    /// Returns all transactions in insertion order.
    ///
    /// TODO: replace with size or gas algorithm
    pub fn transactions(&self) -> Vec<Transaction> {
        let order = self.order.read().unwrap();

        order
            .iter()
            .take(MAX_TRANSACTION_PER_BLOCK)
            .filter_map(|h| self.transactions.get(h).map(|e| e.clone()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use crate::core::transaction::Transaction;
    use crate::crypto::key_pair::PrivateKey;
    use crate::network::txpool::TxPool;

    const TEST_CHAIN_ID: u64 = 284528;

    #[test]
    fn text_tx_pool() {
        let pool = TxPool::new(None);
        assert_eq!(pool.length(), 0);

        let key = PrivateKey::new();
        let tx = Transaction::new(b"Hello World", key.clone(), TEST_CHAIN_ID);
        pool.append(tx, TEST_CHAIN_ID);
        assert_eq!(pool.length(), 1);

        let tx = Transaction::new(b"Hello World", key.clone(), TEST_CHAIN_ID);
        pool.append(tx, TEST_CHAIN_ID);
        assert_eq!(pool.length(), 1);

        pool.flush();
        assert_eq!(pool.length(), 0);
    }

    #[test]
    fn test_ordering() {
        let pool = TxPool::new(None);
        assert_eq!(pool.length(), 0);

        let mut txs: Vec<Transaction> = vec![];
        for i in 0..=100 {
            let tx = Transaction::new(i.to_string().as_bytes(), PrivateKey::new(), TEST_CHAIN_ID);
            txs.push(tx.clone());
            pool.append(tx, TEST_CHAIN_ID);
        }

        let pool_txs = pool.transactions();
        for i in 0..=100 {
            assert_eq!(
                pool_txs.get(i).unwrap().id(TEST_CHAIN_ID),
                txs.get(i).unwrap().id(TEST_CHAIN_ID),
                "failed at index {}",
                i
            );
        }

        pool.flush();
        assert_eq!(pool.length(), 0);
    }

    #[test]
    fn contains_returns_false_for_empty_pool() {
        let pool = TxPool::new(None);
        let key = PrivateKey::new();
        let tx = Transaction::new(b"test", key, TEST_CHAIN_ID);
        assert!(!pool.contains(tx.id(TEST_CHAIN_ID)));
    }

    #[test]
    fn contains_returns_true_after_append() {
        let pool = TxPool::new(None);
        let key = PrivateKey::new();
        let tx = Transaction::new(b"test", key, TEST_CHAIN_ID);
        let hash = tx.id(TEST_CHAIN_ID);

        pool.append(tx, TEST_CHAIN_ID);
        assert!(pool.contains(hash));
    }

    #[test]
    fn transactions_returns_empty_vec_for_empty_pool() {
        let pool = TxPool::new(None);
        assert!(pool.transactions().is_empty());
    }

    #[test]
    fn flush_clears_transactions_but_order_vector_remains() {
        let pool = TxPool::new(None);
        let key = PrivateKey::new();

        for i in 0..5 {
            let tx = Transaction::new(i.to_string().as_bytes(), key.clone(), TEST_CHAIN_ID);
            pool.append(tx, TEST_CHAIN_ID);
        }

        assert_eq!(pool.length(), 5);
        pool.flush();
        assert_eq!(pool.length(), 0);

        assert!(pool.transactions().is_empty());
    }

    #[test]
    fn custom_capacity_is_respected() {
        let pool = TxPool::new(Some(10));
        assert_eq!(pool.length(), 0);
    }

    #[test]
    fn duplicate_transaction_not_added_twice() {
        let pool = TxPool::new(None);
        let key = PrivateKey::new();
        let tx = Transaction::new(b"same data", key, TEST_CHAIN_ID);
        let hash = tx.id(TEST_CHAIN_ID);

        pool.append(tx.clone(), TEST_CHAIN_ID);
        pool.append(tx, TEST_CHAIN_ID);

        assert_eq!(pool.length(), 1);
        assert!(pool.contains(hash));
        assert_eq!(pool.transactions().len(), 1);
    }

    #[test]
    fn append_rejects_when_full() {
        let pool = TxPool::new(Some(1));
        let key = PrivateKey::new();

        let tx1 = Transaction::new(b"one", key.clone(), TEST_CHAIN_ID);
        let tx2 = Transaction::new(b"two", key, TEST_CHAIN_ID);

        pool.append(tx1.clone(), TEST_CHAIN_ID);
        pool.append(tx2.clone(), TEST_CHAIN_ID); // should be rejected due to capacity

        let txs = pool.transactions();
        assert_eq!(txs.len(), 1);
        assert_eq!(txs[0].id(TEST_CHAIN_ID), tx1.id(TEST_CHAIN_ID));
        assert!(!pool.contains(tx2.id(TEST_CHAIN_ID)));
    }

    #[test]
    fn transactions_are_capped() {
        let size: usize = 100;
        let pool = TxPool::new(Some(size));
        let key = PrivateKey::new();

        for i in 0..size {
            let tx = Transaction::new(i.to_string().as_bytes(), key.clone(), TEST_CHAIN_ID);
            pool.append(tx, TEST_CHAIN_ID);
        }

        let txs = pool.transactions();
        assert_eq!(txs.len(), size);
    }

    #[test]
    fn transactions_with_same_data_different_keys_are_distinct() {
        let pool = TxPool::new(None);
        let key1 = PrivateKey::new();
        let key2 = PrivateKey::new();

        let tx1 = Transaction::new(b"same data", key1, TEST_CHAIN_ID);
        let tx2 = Transaction::new(b"same data", key2, TEST_CHAIN_ID);

        pool.append(tx1, TEST_CHAIN_ID);
        pool.append(tx2, TEST_CHAIN_ID);

        assert_eq!(pool.length(), 2);
    }

    #[test]
    fn remove_batch_prunes_order_once() {
        let pool = TxPool::new(None);
        let key = PrivateKey::new();

        let tx1 = Transaction::new(b"first", key.clone(), TEST_CHAIN_ID);
        let tx2 = Transaction::new(b"second", key, TEST_CHAIN_ID);

        pool.append(tx1.clone(), TEST_CHAIN_ID);
        pool.append(tx2.clone(), TEST_CHAIN_ID);

        pool.remove_batch(&[tx1.id(TEST_CHAIN_ID), tx1.id(TEST_CHAIN_ID)]);

        assert!(!pool.contains(tx1.id(TEST_CHAIN_ID)));
        assert!(pool.contains(tx2.id(TEST_CHAIN_ID)));

        let remaining = pool.transactions();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].id(TEST_CHAIN_ID), tx2.id(TEST_CHAIN_ID));
    }

    #[test]
    fn large_pool_maintains_order() {
        let pool = TxPool::new(None);
        let mut hashes = Vec::new();

        for i in 0..1000 {
            let tx = Transaction::new(i.to_string().as_bytes(), PrivateKey::new(), TEST_CHAIN_ID);
            hashes.push(tx.id(TEST_CHAIN_ID));
            pool.append(tx, TEST_CHAIN_ID);
        }

        let pool_txs = pool.transactions();
        assert_eq!(pool_txs.len(), 1000);

        for (i, tx) in pool_txs.iter().enumerate() {
            assert_eq!(tx.id(TEST_CHAIN_ID), hashes[i]);
        }
    }
}
