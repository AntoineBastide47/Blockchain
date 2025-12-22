use crate::core::transaction::Transaction;
use crate::types::hash::Hash;
use dashmap::DashMap;
use std::sync::RwLock;

const TXPOOL_CAPACITY: usize = 100_000;

pub struct TxPool {
    transactions: DashMap<Hash, Transaction>,
    order: RwLock<Vec<Hash>>,
}

impl TxPool {
    pub fn new(capacity: Option<usize>) -> Self {
        let cap = capacity.unwrap_or(TXPOOL_CAPACITY);

        Self {
            transactions: DashMap::with_capacity(cap),
            order: RwLock::new(Vec::with_capacity(cap)),
        }
    }

    pub fn contains(&self, hash: Hash) -> bool {
        self.transactions.contains_key(&hash)
    }

    pub fn append(&self, transaction: Transaction) {
        let mut order = self.order.write().unwrap();
        order.push(transaction.hash);

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

    pub fn transactions(&self) -> Box<[Transaction]> {
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
        let tx = Transaction::new(b"Hello World", key.clone()).expect("Hashing failed");
        pool.append(tx);
        assert_eq!(pool.length(), 1);

        let tx = Transaction::new(b"Hello World", key.clone()).expect("Hashing failed");
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
            let tx = Transaction::new(i.to_string().as_bytes(), PrivateKey::new())
                .expect("Hashing failed");
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
}
