//! Blockchain storage subsystem.
//!
//! This module provides the storage abstractions and implementations for
//! persisting blockchain data:
//!
//! - [`storage_trait`]: Core [`Storage`](storage_trait::Storage) trait for block persistence
//! - [`state_store`]: State management traits ([`StateStore`](state_store::StateStore),
//!   [`VmStorage`](state_store::VmStorage), [`AccountStorage`](state_store::AccountStorage))
//! - [`state_view`]: Read-only state views for VM execution
//! - [`rocksdb_storage`]: Production RocksDB-backed implementation with sparse Merkle tree,
//!   fork-aware header metadata, and reorg groundwork (undo journals / canonical index)
//! - [`test_storage`]: In-memory implementation for testing
//! - [`txpool`]: Transaction pool for pending transactions
//!
//! Receipt storage semantics (current default):
//! - Receipts are treated as canonical-chain data (`CF_RECEIPTS`)
//! - Side branches may store headers/bodies without receipts until executed
//! - Reorg disconnect removes receipts for blocks that leave the canonical chain
//! - Reorg connect writes receipts for newly canonical blocks after execution
//! - Reset/snapshot import/replay may prune and later rebuild canonical receipts

pub mod rocksdb_storage;
pub mod state_store;
pub mod state_view;
pub mod storage_trait;
pub mod test_storage;
pub mod txpool;
