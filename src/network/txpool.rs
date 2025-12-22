use crate::core::transaction::Transaction;
use crate::types::hash::Hash;
use dashmap::DashMap;

const TXPOOL_CAPACITY: usize = 100_000;

pub struct TxPool {
    transactions: DashMap<Hash, Transaction>,
}

impl TxPool {
    pub fn new(capacity: Option<usize>) -> Self {
        let transactions = match capacity {
            Some(cap) => DashMap::with_capacity(cap),
            None => DashMap::with_capacity(TXPOOL_CAPACITY),
        };

        Self { transactions }
    }

    pub fn contains(&self, hash: Hash) -> bool {
        self.transactions.contains_key(&hash)
    }

    pub fn append(&self, transaction: Transaction) {
        self.transactions
            .entry(transaction.hash)
            .or_insert(transaction);
    }

    pub fn length(&self) -> usize {
        self.transactions.len()
    }

    pub fn flush(&self) {
        self.transactions.clear()
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
        let tx = Transaction::new(b"Hello World", key.clone()).expect("Hashing failed");
        pool.append(tx);
        assert_eq!(pool.length(), 1);

        let tx = Transaction::new(b"Hello World", key.clone()).expect("Hashing failed");
        pool.append(tx);
        assert_eq!(pool.length(), 1);

        pool.flush();
        assert_eq!(pool.length(), 0);
    }
}
