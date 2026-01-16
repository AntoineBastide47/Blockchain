//! Transaction pool for pending transactions awaiting block inclusion.
//!
//! Provides thread-safe storage and ordering of unconfirmed transactions.
//! Transactions are organized per-account with nonce-based ordering to ensure
//! correct execution sequence. A max-heap prioritizes transactions by gas price
//! for block building.

use crate::core::account::Account;
use crate::core::transaction::Transaction;
use crate::crypto::key_pair::Address;
use crate::types::encoding::Encode;
use crate::types::hash::Hash;
use crate::warn;
use dashmap::DashMap;
use std::cmp::Reverse;
use std::collections::{BTreeMap, BinaryHeap};
use std::sync::{Mutex, MutexGuard};

/// Default transaction pool capacity.
pub const TXPOOL_CAPACITY: usize = 100_000;
/// Maximum number of transactions returned for block building.
pub const MAX_TRANSACTION_PER_BLOCK: usize = 20_000;

/// Per-account transaction queue with ready and future partitions.
struct AccountQueue {
    /// Transactions ready for immediate execution (nonces are contiguous from `next_nonce`).
    ready: BTreeMap<u64, Transaction>,
    /// Transactions waiting for missing nonces to become executable.
    future: BTreeMap<u64, Transaction>,
    /// Next expected nonce for this account; transactions with this nonce go to `ready`.
    next_nonce: u64,
}

/// Heap entry for transaction priority ordering.
///
/// Ordered solely by gas_price for heap operations.
/// Only one entry per account exists in the heap at a time (the lowest ready nonce).
#[derive(Eq, PartialEq, Debug)]
struct PoolEntry {
    gas_price: u128,
    addr: Address,
    nonce: u64,
    hash: Hash,
}

impl Ord for PoolEntry {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.gas_price.cmp(&other.gas_price)
    }
}

impl PartialOrd for PoolEntry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// Thread-safe pool of pending transactions.
///
/// Transactions are partitioned per-account into "ready" (executable) and "future"
/// (waiting for prior nonces). A global max-heap orders ready transactions by gas
/// price for efficient block building. Provides O(1) duplicate detection via hash lookup.
pub struct TxPool {
    /// Chain identifier.
    chain_id: u64,
    /// Maximum number of transactions the pool will accept.
    capacity: usize,
    /// Current number of transactions in the pool.
    length: Mutex<usize>,
    /// Per-account transaction queues keyed by sender address.
    accounts: DashMap<Address, AccountQueue>,
    /// Max-heap of ready transactions ordered by gas price for block building.
    ready: Mutex<BinaryHeap<PoolEntry>>,
    /// Min-heap for eviction (lowest gas price first).
    eviction: Mutex<BinaryHeap<Reverse<PoolEntry>>>,
    /// Maps transaction hash to (address, nonce) for O(1) lookups and removal.
    hash_index: DashMap<Hash, (Address, u64)>,
}

impl TxPool {
    /// Creates a new transaction pool with the given capacity.
    ///
    /// Uses `TXPOOL_CAPACITY` if `None` is provided.
    pub fn new(capacity: Option<usize>, chain_id: u64) -> Self {
        let cap = capacity.unwrap_or(TXPOOL_CAPACITY).max(1);

        Self {
            chain_id,
            capacity: cap,
            length: Mutex::new(0),
            accounts: DashMap::new(),
            ready: Mutex::new(BinaryHeap::new()),
            eviction: Mutex::new(BinaryHeap::new()),
            hash_index: DashMap::new(),
        }
    }

    /// Returns `true` if the pool contains a transaction with the given hash.
    ///
    /// Uses the hash index for O(1) lookup.
    pub fn contains(&self, hash: Hash) -> bool {
        self.hash_index.contains_key(&hash)
    }

    /// Inserts a transaction into the ready map and updates the global heap if needed.
    ///
    /// Only adds a heap entry when the map was empty (one heap entry per account).
    fn insert_ready(
        &self,
        ready: &mut MutexGuard<BinaryHeap<PoolEntry>>,
        map: &mut BTreeMap<u64, Transaction>,
        transaction: Transaction,
    ) {
        if map.is_empty() {
            ready.push(PoolEntry {
                gas_price: transaction.gas_price,
                addr: transaction.from.address(),
                nonce: transaction.nonce,
                hash: transaction.id(self.chain_id),
            });
        }
        map.insert(transaction.nonce, transaction);
    }

    /// Adds a transaction to the pool.
    ///
    /// Returns `true` if the transaction was accepted. The transaction is placed in
    /// the "ready" queue if its nonce matches the account's next expected nonce, or
    /// in the "future" queue otherwise. Future transactions with gaps are promoted
    /// to ready when preceding nonces arrive.
    ///
    /// Returns `false` if:
    /// - Gas price or limit is zero
    /// - Nonce is below the account's current nonce
    /// - Nonce exceeds the account nonce by more than 64
    /// - Account balance is insufficient for gas costs
    /// - Pool is at capacity
    /// - A transaction with the same nonce exists with equal or higher gas price
    pub fn append(&self, account: &Account, transaction: Transaction) -> bool {
        let hash = transaction.id(self.chain_id);
        if transaction.gas_price == 0 || transaction.gas_limit == 0 {
            warn!("Transaction gas price or gas limit cannot be set to 0: transaction={hash}");
            return false;
        }

        let address = transaction.from.address();
        let nonce = transaction.nonce;

        let mut ready = self.ready.lock().unwrap();
        let mut q = self.accounts.entry(address).or_insert(AccountQueue {
            ready: BTreeMap::new(),
            future: BTreeMap::new(),
            next_nonce: account.nonce(),
        });

        // Resync next_nonce if chain has advanced past our recorded nonce
        if account.nonce() > q.next_nonce {
            // Purge stale transactions with nonces below current account nonce
            let stale_ready: Vec<u64> = q.ready.range(..account.nonce()).map(|(&n, _)| n).collect();
            let mut removed = 0usize;
            for n in stale_ready {
                if let Some(tx) = q.ready.remove(&n) {
                    self.hash_index.remove(&tx.id(self.chain_id));
                    removed += 1;
                }
            }
            let stale_future: Vec<u64> =
                q.future.range(..account.nonce()).map(|(&n, _)| n).collect();
            for n in stale_future {
                if let Some(tx) = q.future.remove(&n) {
                    self.hash_index.remove(&tx.id(self.chain_id));
                    removed += 1;
                }
            }

            *self.length.lock().unwrap() -= removed;
            q.next_nonce = account.nonce();

            // Promote future transactions that are now contiguous
            while let Some(n) = Some(q.next_nonce)
                && let Some(t) = q.future.remove(&n)
            {
                self.insert_ready(&mut ready, &mut q.ready, t);
                q.next_nonce += 1;
            }
        }

        if nonce < q.next_nonce {
            warn!("transaction nonce is smaller than account nonce: transaction={hash}");
            return false;
        }

        if nonce > account.nonce() + 64 {
            warn!("transaction nonce is larger than the 64 max threshold: transaction={hash}");
            return false;
        }

        if transaction.gas_price * (transaction.gas_limit as u128) > account.balance() {
            warn!("Insufficient balance in account to execute transaction: transaction={hash}");
            return false;
        }

        if self.length() >= self.capacity {
            let mut eviction = self.eviction.lock().unwrap();
            // Find valid lowest-price tx (skip stale entries)
            loop {
                let Some(Reverse(entry)) = eviction.peek() else {
                    return false;
                };

                // Verify entry is still valid
                if let Some(acct) = self.accounts.get(&entry.addr)
                    && (acct.ready.contains_key(&entry.nonce)
                        || acct.future.contains_key(&entry.nonce))
                {
                    // Incoming tx is worse than current lowest transaction
                    if transaction.gas_price <= entry.gas_price {
                        warn!("TxPool is at full capacity, transaction rejected: hash={hash}");
                        return false;
                    }

                    // Evict the low-price tx
                    self.remove_batch(&[entry.hash]);
                    eviction.pop();
                    break;
                }
                // Stale entry, continue to next
            }
        }

        if nonce == q.next_nonce {
            // Transaction is ready to be executed
            self.hash_index.insert(hash, (address, nonce));
            self.insert_ready(&mut ready, &mut q.ready, transaction);
            *self.length.lock().unwrap() += 1;
            q.next_nonce += 1;

            // Try promoting future transactions now contiguous
            while let Some(n) = Some(q.next_nonce)
                && let Some(t) = q.future.remove(&n)
            {
                self.insert_ready(&mut ready, &mut q.ready, t);
                q.next_nonce += 1;
            }

            // Release the ready lock so other threads can use it
            drop(ready);
            return true;
        }

        // Store for later promotion
        if !q.future.contains_key(&nonce) {
            self.hash_index.insert(hash, (address, nonce));
            q.future.insert(nonce, transaction);
            *self.length.lock().unwrap() += 1;
        } else if transaction.gas_price > q.future[&nonce].gas_price {
            // Remove old hash from index, add new one
            let old_hash = q.future[&nonce].id(self.chain_id);
            self.hash_index.remove(&old_hash);
            self.hash_index.insert(hash, (address, nonce));
            q.future.insert(nonce, transaction);
        } else {
            warn!(
                "existing transaction with the same nonce={} has better a bigger gas price: {} VS {}",
                nonce, transaction.gas_price, q.future[&nonce].gas_price
            );
            return false;
        }

        true
    }

    /// Returns the total number of transactions in the pool (both ready and future).
    pub fn length(&self) -> usize {
        *self.length.lock().unwrap()
    }

    /// Removes transactions with the given hashes from the pool.
    ///
    /// Handles removal from both ready and future queues, updates the hash index,
    /// and ensures the heap remains consistent by adding entries for remaining
    /// ready transactions when needed.
    pub fn remove_batch(&self, hashes: &[Hash]) {
        let mut ready_lock = self.ready.lock().unwrap();

        for hash in hashes {
            let Some((_, (addr, nonce))) = self.hash_index.remove(hash) else {
                continue;
            };

            let Some(mut acct) = self.accounts.get_mut(&addr) else {
                continue;
            };

            let removed_from_ready = acct.ready.remove(&nonce).is_some();
            let removed_from_future = !removed_from_ready && acct.future.remove(&nonce).is_some();

            if removed_from_ready || removed_from_future {
                *self.length.lock().unwrap() -= 1;
            }

            // If removed from ready and more ready txs exist, ensure heap has an entry
            if removed_from_ready && let Some((&next_nonce, next_tx)) = acct.ready.first_key_value()
            {
                ready_lock.push(PoolEntry {
                    gas_price: next_tx.gas_price,
                    addr,
                    nonce: next_nonce,
                    hash: next_tx.id(self.chain_id),
                });
            }

            // Clean up empty account queues
            if acct.ready.is_empty() && acct.future.is_empty() {
                drop(acct);
                self.accounts.remove(&addr);
            }
        }
    }

    /// Returns and removes the highest-priority executable transaction that fits within gas and size budgets.
    ///
    /// Selects the transaction with the highest gas price among all accounts' next
    /// executable nonces. Skips transactions exceeding `gas_left` or `size_left`.
    /// After removal, promotes the next transaction for the same account to the heap
    /// and attempts to promote any now-contiguous future transactions.
    ///
    /// Returns `None` if no suitable transaction exists.
    pub fn take_one(&self, gas_left: u64, size_left: usize) -> (Option<Transaction>, usize) {
        let mut ready = self.ready.lock().unwrap();
        let mut skipped = Vec::new();

        loop {
            let entry = match ready.pop() {
                Some(e) => e,
                None => {
                    // No more candidates, re-add skipped entries
                    for e in skipped {
                        ready.push(e);
                    }
                    return (None, 0);
                }
            };

            let addr = entry.addr;
            let nonce = entry.nonce;

            // Check underlying account queue still has this tx
            let Some(mut acct) = self.accounts.get_mut(&addr) else {
                continue;
            };

            let Some(tx) = acct.ready.get(&nonce) else {
                // Stale heap entry, try next
                drop(acct);
                continue;
            };

            let size = tx.byte_size();
            if tx.gas_limit > gas_left || size > size_left {
                // Doesn't fit budget, skip but remember to re-add
                skipped.push(entry);
                drop(acct);
                continue;
            }

            // Found a fitting transaction - re-add skipped entries first
            for e in skipped {
                ready.push(e);
            }

            // Remove from account ready map and get next ready transaction
            let removed = acct.ready.remove(&nonce);
            let next_entry = acct.ready.first_key_value().map(|(&n, t)| PoolEntry {
                gas_price: t.gas_price,
                addr,
                nonce: n,
                hash: t.id(self.chain_id),
            });
            drop(acct);

            // Remove from hash index
            if let Some(ref tx) = removed {
                self.hash_index.remove(&tx.id(self.chain_id));
                *self.length.lock().unwrap() -= 1;
            }

            // Add next ready transaction and promote contiguous transactions for this account
            if let Some(entry) = next_entry {
                ready.push(entry);
            }
            self.promote_contiguous(addr, &mut ready);

            return (removed, size);
        }
    }

    /// Promotes contiguous transactions from future to ready for the given account.
    ///
    /// Moves transactions from `future` to `ready` as long as their nonces are
    /// contiguous with `next_nonce`. Each promoted transaction gets a heap entry.
    /// Removes the account queue if both ready and future become empty.
    fn promote_contiguous(&self, addr: Address, ready: &mut MutexGuard<BinaryHeap<PoolEntry>>) {
        if let Some(mut entry) = self.accounts.get_mut(&addr) {
            while let Some(n) = Some(entry.next_nonce)
                && let Some(tx) = entry.future.remove(&n)
            {
                self.insert_ready(ready, &mut entry.ready, tx);
                entry.next_nonce += 1;
            }

            // optional: GC empty-account queues
            if entry.ready.is_empty() && entry.future.is_empty() {
                drop(entry);
                self.accounts.remove(&addr);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::transaction::TransactionType;
    use crate::crypto::key_pair::PrivateKey;
    use crate::types::bytes::Bytes;
    use crate::types::hash::Hash;

    const CHAIN_ID: u64 = 1;
    const HIGH_BALANCE: u128 = 10u128.pow(20);
    const INF_GAS: u64 = u64::MAX;
    const INF_SIZE: usize = usize::MAX;

    fn pool() -> TxPool {
        TxPool::new(None, CHAIN_ID)
    }

    fn pool_with_capacity(cap: usize) -> TxPool {
        TxPool::new(Some(cap), CHAIN_ID)
    }

    fn account(balance: u128, nonce: u64) -> Account {
        Account::from(nonce, balance, Hash::zero(), Hash::zero())
    }

    fn tx(key: &PrivateKey, nonce: u64, gas_price: u128, gas_limit: u64) -> Transaction {
        Transaction::new(
            Address::zero(),
            None,
            Bytes::new(nonce.to_le_bytes().as_slice()),
            0,
            0,
            gas_price,
            gas_limit,
            nonce,
            key.clone(),
            CHAIN_ID,
            TransactionType::TransferFunds,
        )
    }

    fn simple_tx(key: &PrivateKey, nonce: u64) -> Transaction {
        tx(key, nonce, 1, 1)
    }

    // ==================== Append validation ====================

    #[test]
    fn append_rejects_zero_gas_price_or_limit() {
        let pool = pool();
        let acc = account(HIGH_BALANCE, 0);
        let key = PrivateKey::new();

        assert!(!pool.append(&acc, tx(&key, 0, 0, 100)));
        assert!(!pool.append(&acc, tx(&key, 0, 100, 0)));
        assert_eq!(pool.length(), 0);
    }

    #[test]
    fn append_validates_nonce_bounds() {
        let pool = pool();
        let acc = account(HIGH_BALANCE, 5);
        let key = PrivateKey::new();

        // Below account nonce
        assert!(!pool.append(&acc, simple_tx(&key, 4)));
        // At threshold (5 + 64 = 69)
        assert!(pool.append(&acc, simple_tx(&key, 69)));
        // Above threshold
        assert!(!pool.append(&acc, simple_tx(&key, 70)));
    }

    #[test]
    fn append_validates_balance() {
        let pool = pool();
        let key = PrivateKey::new();

        // gas_price * gas_limit = 100, balance = 99
        assert!(!pool.append(&account(99, 0), tx(&key, 0, 10, 10)));
        // Exact balance
        assert!(pool.append(&account(100, 0), tx(&key, 0, 10, 10)));
    }

    #[test]
    fn append_rejects_at_capacity() {
        let pool = pool_with_capacity(1);
        let acc = account(HIGH_BALANCE, 0);
        let key = PrivateKey::new();

        assert!(pool.append(&acc, simple_tx(&key, 0)));
        assert!(!pool.append(&acc, simple_tx(&PrivateKey::new(), 0)));
        assert_eq!(pool.length(), 1);
    }

    // ==================== Ready vs Future queue ====================

    #[test]
    fn append_places_tx_in_ready_when_nonce_matches() {
        let pool = pool();
        let acc = account(HIGH_BALANCE, 0);
        let key = PrivateKey::new();

        assert!(pool.append(&acc, simple_tx(&key, 0)));
        assert_eq!(pool.length(), 1);

        // Should be immediately available
        let (taken, _) = pool.take_one(INF_GAS, INF_SIZE);
        assert!(taken.is_some());
        assert_eq!(taken.unwrap().nonce, 0);
    }

    #[test]
    fn append_places_tx_in_future_when_nonce_gap_exists() {
        let pool = pool();
        let acc = account(HIGH_BALANCE, 0);
        let key = PrivateKey::new();

        // Nonce 2 with gap (0, 1 missing)
        assert!(pool.append(&acc, simple_tx(&key, 2)));
        assert_eq!(pool.length(), 1);

        // Not available because it's in future queue
        assert!(pool.take_one(INF_GAS, INF_SIZE).0.is_none());
    }

    #[test]
    fn future_txs_promoted_when_gap_filled() {
        let pool = pool();
        let acc = account(HIGH_BALANCE, 0);
        let key = PrivateKey::new();

        // Add nonces 2, 3 first (future)
        assert!(pool.append(&acc, simple_tx(&key, 2)));
        assert!(pool.append(&acc, simple_tx(&key, 3)));
        assert_eq!(pool.length(), 2);
        assert!(pool.take_one(INF_GAS, INF_SIZE).0.is_none());

        // Add nonce 0 (ready), should promote 1 is still missing
        assert!(pool.append(&acc, simple_tx(&key, 0)));
        assert_eq!(pool.length(), 3);

        // Only nonce 0 ready
        let (t, _) = pool.take_one(INF_GAS, INF_SIZE);
        assert_eq!(t.unwrap().nonce, 0);
        assert!(pool.take_one(INF_GAS, INF_SIZE).0.is_none());

        // Add nonce 1, should promote 2 and 3
        assert!(pool.append(&acc, simple_tx(&key, 1)));
        for expected in [1, 2, 3] {
            let (t, _) = pool.take_one(INF_GAS, INF_SIZE);
            assert_eq!(t.unwrap().nonce, expected);
        }
        assert!(pool.take_one(INF_GAS, INF_SIZE).0.is_none());
    }

    // ==================== Gas price replacement ====================

    #[test]
    fn future_tx_replaced_by_higher_gas_price() {
        let pool = pool();
        let acc = account(HIGH_BALANCE, 0);
        let key = PrivateKey::new();

        // Add nonce 5 with gas_price 10
        let tx_low = tx(&key, 5, 10, 1);
        let hash_low = tx_low.id(CHAIN_ID);
        assert!(pool.append(&acc, tx_low));

        // Replace with higher gas price
        let tx_high = tx(&key, 5, 20, 1);
        let hash_high = tx_high.id(CHAIN_ID);
        assert!(pool.append(&acc, tx_high));

        assert_eq!(pool.length(), 1);
        assert!(!pool.contains(hash_low));
        assert!(pool.contains(hash_high));
    }

    #[test]
    fn future_tx_not_replaced_by_lower_or_equal_gas_price() {
        let pool = pool();
        let acc = account(HIGH_BALANCE, 0);
        let key = PrivateKey::new();

        let tx_first = tx(&key, 5, 10, 1);
        let hash_first = tx_first.id(CHAIN_ID);
        assert!(pool.append(&acc, tx_first));

        // Equal gas price rejected
        assert!(!pool.append(&acc, tx(&key, 5, 10, 1)));
        // Lower gas price rejected
        assert!(!pool.append(&acc, tx(&key, 5, 5, 1)));

        assert_eq!(pool.length(), 1);
        assert!(pool.contains(hash_first));
    }

    // ==================== take_one ====================

    #[test]
    fn take_one_returns_highest_gas_price_first() {
        let pool = pool();
        let acc = account(HIGH_BALANCE, 0);

        // Add transactions from different accounts with varying gas prices
        for gas_price in [5u128, 10, 1, 8, 3] {
            let key = PrivateKey::new();
            assert!(pool.append(&acc, tx(&key, 0, gas_price, 1)));
        }

        // Should return in descending gas price order
        for expected in [10, 8, 5, 3, 1] {
            let (t, _) = pool.take_one(INF_GAS, INF_SIZE);
            assert_eq!(t.unwrap().gas_price, expected);
        }
        assert!(pool.take_one(INF_GAS, INF_SIZE).0.is_none());
    }

    #[test]
    fn take_one_respects_gas_budget() {
        let pool = pool();
        let acc = account(HIGH_BALANCE, 0);

        let key1 = PrivateKey::new();
        let key2 = PrivateKey::new();

        // High gas price but high gas limit
        assert!(pool.append(&acc, tx(&key1, 0, 100, 500)));
        // Lower gas price but fits budget
        assert!(pool.append(&acc, tx(&key2, 0, 50, 100)));

        // Budget of 200 should skip first tx and return second
        let (t, size) = pool.take_one(200, INF_SIZE);
        let t = t.unwrap();
        assert_eq!(t.gas_price, 50);
        assert_eq!(t.gas_limit, 100);
        assert_eq!(size, t.byte_size());

        // First tx should still be in pool
        assert_eq!(pool.length(), 1);
        let (t, _) = pool.take_one(INF_GAS, INF_SIZE);
        assert_eq!(t.unwrap().gas_price, 100);
    }

    #[test]
    fn take_one_advances_account_queue() {
        let pool = pool();
        let acc = account(HIGH_BALANCE, 0);
        let key = PrivateKey::new();

        // Same account, sequential nonces, increasing gas prices
        for nonce in 0..3 {
            assert!(pool.append(&acc, tx(&key, nonce, (nonce + 1) as u128, 1)));
        }

        // Should get nonces in order (0, 1, 2)
        for expected in 0..3 {
            let (t, _) = pool.take_one(INF_GAS, INF_SIZE);
            assert_eq!(t.unwrap().nonce, expected);
        }
    }

    // ==================== contains & remove_batch ====================

    #[test]
    fn contains_tracks_hash_index() {
        let pool = pool();
        let acc = account(HIGH_BALANCE, 0);
        let key = PrivateKey::new();

        let transaction = simple_tx(&key, 0);
        let hash = transaction.id(CHAIN_ID);

        assert!(!pool.contains(hash));
        pool.append(&acc, transaction);
        assert!(pool.contains(hash));

        pool.remove_batch(&[hash]);
        assert!(!pool.contains(hash));
    }

    #[test]
    fn remove_batch_handles_ready_and_future() {
        let pool = pool();
        let acc = account(HIGH_BALANCE, 0);
        let key = PrivateKey::new();

        let tx_ready = simple_tx(&key, 0);
        let tx_future = simple_tx(&key, 5);
        let hash_ready = tx_ready.id(CHAIN_ID);
        let hash_future = tx_future.id(CHAIN_ID);

        pool.append(&acc, tx_ready);
        pool.append(&acc, tx_future);
        assert_eq!(pool.length(), 2);

        pool.remove_batch(&[hash_ready, hash_future]);
        assert_eq!(pool.length(), 0);
        assert!(!pool.contains(hash_ready));
        assert!(!pool.contains(hash_future));
    }

    #[test]
    fn remove_batch_promotes_next_ready_to_heap() {
        let pool = pool();
        let acc = account(HIGH_BALANCE, 0);
        let key = PrivateKey::new();

        let tx0 = simple_tx(&key, 0);
        let tx1 = simple_tx(&key, 1);
        let hash0 = tx0.id(CHAIN_ID);

        pool.append(&acc, tx0);
        pool.append(&acc, tx1);

        // Remove first, second should still be available
        pool.remove_batch(&[hash0]);
        assert_eq!(pool.length(), 1);

        let (t, _) = pool.take_one(INF_GAS, INF_SIZE);
        assert_eq!(t.unwrap().nonce, 1);
    }

    // ==================== Edge cases ====================

    #[test]
    fn different_accounts_same_data_are_distinct() {
        let pool = pool();
        let acc = account(HIGH_BALANCE, 0);

        let key1 = PrivateKey::new();
        let key2 = PrivateKey::new();

        assert!(pool.append(&acc, simple_tx(&key1, 0)));
        assert!(pool.append(&acc, simple_tx(&key2, 0)));
        assert_eq!(pool.length(), 2);
    }

    #[test]
    fn duplicate_same_nonce_same_account_rejected() {
        let pool = pool();
        let acc = account(HIGH_BALANCE, 0);
        let key = PrivateKey::new();

        let transaction = simple_tx(&key, 0);
        assert!(pool.append(&acc, transaction.clone()));
        assert!(!pool.append(&acc, transaction));
        assert_eq!(pool.length(), 1);
    }

    #[test]
    fn empty_pool_operations() {
        let pool = pool();

        assert_eq!(pool.length(), 0);
        assert!(pool.take_one(INF_GAS, INF_SIZE).0.is_none());
        pool.remove_batch(&[Hash::zero()]); // no-op
        assert!(!pool.contains(Hash::zero()));
    }

    // ==================== Nonce resync ====================

    #[test]
    fn resync_purges_stale_txs_when_chain_advances() {
        let pool = pool();
        let key = PrivateKey::new();

        // Account starts at nonce 0
        let acc_v0 = account(HIGH_BALANCE, 0);

        // Add nonces 0 (ready) and 5 (future)
        let tx0 = simple_tx(&key, 0);
        let tx5 = simple_tx(&key, 5);
        let hash0 = tx0.id(CHAIN_ID);
        let hash5 = tx5.id(CHAIN_ID);
        assert!(pool.append(&acc_v0, tx0));
        assert!(pool.append(&acc_v0, tx5));
        assert_eq!(pool.length(), 2);

        // Chain advances to nonce 5 externally
        let acc_v5 = account(HIGH_BALANCE, 5);

        // Submit new tx with nonce 5 (matching current chain state)
        let tx5_new = simple_tx(&key, 5);
        let hash5_new = tx5_new.id(CHAIN_ID);
        // Should purge old stale txs and accept new one (or reject as duplicate nonce)
        // Since old tx5 has same gas price, replacement fails, but resync should have purged tx0
        pool.append(&acc_v5, tx5_new);

        // tx0 should be purged (nonce < 5)
        assert!(!pool.contains(hash0));
        // Old tx5 was in future but now should be promoted to ready
        assert!(pool.contains(hash5) || pool.contains(hash5_new));
        // tx5 should now be ready (take_one should return it)
        let taken = pool.take_one(INF_GAS, INF_SIZE).0;
        assert!(taken.is_some());
        assert_eq!(taken.unwrap().nonce, 5);
    }

    #[test]
    fn resync_promotes_future_txs_when_chain_advances() {
        let pool = pool();
        let key = PrivateKey::new();

        // Account at nonce 0, add future tx at nonce 5
        let acc_v0 = account(HIGH_BALANCE, 0);
        let tx5 = simple_tx(&key, 5);
        assert!(pool.append(&acc_v0, tx5));
        assert!(pool.take_one(INF_GAS, INF_SIZE).0.is_none()); // Not ready yet

        // Chain advances to nonce 5
        let acc_v5 = account(HIGH_BALANCE, 5);
        // Trigger resync by appending another tx
        let tx6 = simple_tx(&key, 6);
        assert!(pool.append(&acc_v5, tx6));

        // Now tx5 should be ready (promoted during resync)
        let (t, _) = pool.take_one(INF_GAS, INF_SIZE);
        let t = t.unwrap();
        assert_eq!(t.nonce, 5);
        // And tx6 should follow
        let (t, _) = pool.take_one(INF_GAS, INF_SIZE);
        assert_eq!(t.unwrap().nonce, 6);
    }

    // ==================== Size limits ====================

    #[test]
    fn take_one_respects_size_budget() {
        let pool = pool();
        let acc = account(HIGH_BALANCE, 0);
        let key = PrivateKey::new();

        let tx = Transaction::new(
            Address::zero(),
            None,
            Bytes::new(vec![1u8; 256]),
            0,
            0,
            10,
            1,
            0,
            key,
            CHAIN_ID,
            TransactionType::TransferFunds,
        );
        let expected_size = tx.byte_size();
        assert!(pool.append(&acc, tx));

        // Too small size budget rejects the tx but keeps it in the pool
        let (none, size) = pool.take_one(INF_GAS, expected_size - 1);
        assert!(none.is_none());
        assert_eq!(size, 0);
        assert_eq!(pool.length(), 1);

        // Adequate size budget should now return it
        let (taken, size) = pool.take_one(INF_GAS, expected_size);
        let taken = taken.expect("tx should be returned");
        assert_eq!(taken.byte_size(), expected_size);
        assert_eq!(size, expected_size);
        assert_eq!(pool.length(), 0);
    }

    #[test]
    fn take_one_skips_oversized_and_picks_smaller() {
        let pool = pool();
        let acc = account(HIGH_BALANCE, 0);

        let big_key = PrivateKey::new();
        let small_key = PrivateKey::new();

        let big_tx = Transaction::new(
            Address::zero(),
            None,
            Bytes::new(vec![2u8; 512]),
            0,
            0,
            100,
            1,
            0,
            big_key,
            CHAIN_ID,
            TransactionType::TransferFunds,
        );
        let small_tx = tx(&small_key, 0, 50, 1);
        let small_size = small_tx.byte_size();

        assert!(pool.append(&acc, big_tx));
        assert!(pool.append(&acc, small_tx));

        // Size budget blocks the large tx but allows the small one
        let (taken, size) = pool.take_one(INF_GAS, small_size);
        let taken = taken.expect("small tx should be selected");
        assert_eq!(taken.gas_price, 50);
        assert_eq!(size, small_size);
        assert_eq!(pool.length(), 1);
    }
}
