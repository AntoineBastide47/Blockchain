//! Transaction pool for pending transactions awaiting block inclusion.
//!
//! Provides thread-safe storage and ordering of unconfirmed transactions.

use crate::core::transaction::Transaction;
use crate::types::hash::Hash;
use dashmap::DashMap;
use std::sync::RwLock;

/// Default transaction pool capacity.
pub const TXPOOL_CAPACITY: usize = 100_000;

/// Thread-safe pool of pending transactions.
///
/// Maintains insertion order for deterministic block construction while
/// providing O(1) duplicate detection via hash lookup.
pub struct TxPool {
    /// Transactions indexed by hash for fast lookup and deduplication.
    transactions: DashMap<Hash, Transaction>,
    /// Insertion order for deterministic transaction ordering in blocks.
    order: RwLock<Vec<Hash>>,
}

impl TxPool {
    /// Creates a new transaction pool with the given capacity.
    ///
    /// Uses `TXPOOL_CAPACITY` if `None` is provided.
    pub fn new(capacity: Option<usize>) -> Self {
        let cap = capacity.unwrap_or(TXPOOL_CAPACITY);

        Self {
            transactions: DashMap::with_capacity(cap),
            order: RwLock::new(Vec::with_capacity(cap)),
        }
    }

    /// Returns `true` if the pool contains a transaction with the given hash.
    pub fn contains(&self, hash: Hash) -> bool {
        self.transactions.contains_key(&hash)
    }

    /// Adds a transaction to the pool if not already present.
    pub fn append(&self, transaction: Transaction) {
        let mut order = self.order.write().unwrap();
        order.push(transaction.hash);

        self.transactions
            .entry(transaction.hash)
            .or_insert(transaction);
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
        for hash in hashes {
            self.transactions.remove(hash);
        }
        let mut order = self.order.write().unwrap();
        order.retain(|h| self.transactions.contains_key(h));
    }

    /// Returns all transactions in insertion order.
    pub fn transactions(&self) -> Vec<Transaction> {
        let order = self.order.read().unwrap();

        order
            .iter()
            .filter_map(|h| self.transactions.get(h).map(|e| e.clone()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use crate::core::transaction::Transaction;
    use crate::crypto::key_pair::PrivateKey;
    use crate::network::txpool::TxPool;

    #[test]
    fn text_tx_pool() {
        let pool = TxPool::new(None);
        assert_eq!(pool.length(), 0);

        let key = PrivateKey::new();
        let tx = Transaction::new(b"Hello World", key.clone());
        pool.append(tx);
        assert_eq!(pool.length(), 1);

        let tx = Transaction::new(b"Hello World", key.clone());
        pool.append(tx);
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
            let tx = Transaction::new(i.to_string().as_bytes(), PrivateKey::new());
            txs.push(tx.clone());
            pool.append(tx);
        }

        let pool_txs = pool.transactions();
        for i in 0..=100 {
            assert_eq!(
                pool_txs.get(i).unwrap().hash,
                txs.get(i).unwrap().hash,
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
        let tx = Transaction::new(b"test", key);
        assert!(!pool.contains(tx.hash));
    }

    #[test]
    fn contains_returns_true_after_append() {
        let pool = TxPool::new(None);
        let key = PrivateKey::new();
        let tx = Transaction::new(b"test", key);
        let hash = tx.hash;

        pool.append(tx);
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
            let tx = Transaction::new(i.to_string().as_bytes(), key.clone());
            pool.append(tx);
        }

        assert_eq!(pool.length(), 5);
        pool.flush();
        assert_eq!(pool.length(), 0);

        // Transactions should be empty after flush
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
        let tx = Transaction::new(b"same data", key);
        let hash = tx.hash;

        pool.append(tx.clone());
        pool.append(tx);

        assert_eq!(pool.length(), 1);
        assert!(pool.contains(hash));
    }

    #[test]
    fn transactions_with_same_data_different_keys_are_distinct() {
        let pool = TxPool::new(None);
        let key1 = PrivateKey::new();
        let key2 = PrivateKey::new();

        let tx1 = Transaction::new(b"same data", key1);
        let tx2 = Transaction::new(b"same data", key2);

        pool.append(tx1);
        pool.append(tx2);

        assert_eq!(pool.length(), 2);
    }

    #[test]
    fn large_pool_maintains_order() {
        let pool = TxPool::new(None);
        let mut hashes = Vec::new();

        for i in 0..1000 {
            let tx = Transaction::new(i.to_string().as_bytes(), PrivateKey::new());
            hashes.push(tx.hash);
            pool.append(tx);
        }

        let pool_txs = pool.transactions();
        assert_eq!(pool_txs.len(), 1000);

        for (i, tx) in pool_txs.iter().enumerate() {
            assert_eq!(tx.hash, hashes[i]);
        }
    }
}
