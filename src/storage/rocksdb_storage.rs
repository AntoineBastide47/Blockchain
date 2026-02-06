//! RocksDB-backed blockchain storage with sparse Merkle tree state management.
//!
//! Provides persistent storage for blocks, headers, and account state using RocksDB
//! with column families for data separation. State is managed via an in-memory sparse
//! Merkle tree with leaves persisted to disk, enabling fast merkle proofs without
//! disk I/O during execution.
//!
//! # Snapshots
//!
//! Periodic snapshots are created at [`SNAPSHOT_INTERVAL`] block intervals for state sync.
//! Snapshots enable nodes to bootstrap from a recent state rather than replaying the entire
//! blockchain history.

use crate::core::account::Account;
use crate::core::block::{Block, Header};
use crate::crypto::key_pair::Address;
use crate::storage::state_store::{AccountStorage, StateStore, VmStorage};
use crate::storage::state_view::{StateView, StateViewProvider};
use crate::storage::storage_trait::Storage;
use crate::storage::storage_trait::StorageError;
use crate::types::encoding::{Decode, Encode};
use crate::types::hash::Hash;
use crate::{error, info, warn};
use rocksdb::{ColumnFamily, DB, IteratorMode, ReadOptions, WriteBatch};
use sparse_merkle_tree::blake2b::Blake2bHasher;
use sparse_merkle_tree::default_store::DefaultStore;
use sparse_merkle_tree::traits::Value;
use sparse_merkle_tree::{H256, SparseMerkleTree};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

/// Column family name for block headers indexed by hash.
pub const CF_HEADERS: &str = "headers";
/// Column family name for full blocks indexed by hash.
pub const CF_BLOCKS: &str = "blocks";
/// Column family name for metadata (tip hash, state root).
pub const CF_META: &str = "meta";
/// Column family name for SMT key-value pairs (persisted leaves).
pub const CF_STATE: &str = "state";
/// Column family name for full state snapshots.
pub const CF_SNAPSHOTS: &str = "snapshots";

/// Default snapshot interval in blocks.
#[cfg(not(test))]
pub const SNAPSHOT_INTERVAL: u64 = 1_000;
/// Smaller default for unit tests to keep snapshots and pruning cheap.
#[cfg(test)]
pub const SNAPSHOT_INTERVAL: u64 = 10;
/// Default number of recent block bodies to retain.
///
/// Must be > 2 * SNAPSHOT_INTERVAL to ensure blocks are available for syncing
/// from any snapshot in the retention window (we keep 2 snapshots).
pub const BLOCK_BODY_RETENTION: u64 = SNAPSHOT_INTERVAL * 3;

/// Wrapper type for byte vectors stored in the sparse Merkle tree.
#[derive(Default, Clone)]
pub struct SmtValue(pub Vec<u8>);

impl Value for SmtValue {
    fn to_h256(&self) -> H256 {
        if self.0.is_empty() {
            return H256::zero();
        }

        let encoded = self.0.to_bytes();
        H256::from(Hash::sha3().chain(&encoded).finalize().0)
    }

    fn zero() -> Self {
        Self(Vec::new())
    }
}

/// Sparse Merkle Tree type alias using Blake2b hasher and in-memory store.
pub type Smt = SparseMerkleTree<Blake2bHasher, SmtValue, DefaultStore<SmtValue>>;

/// Converts a 32-byte [`Hash`] to the SMT's [`H256`] representation.
pub fn hash_to_h256(hash: &Hash) -> H256 {
    H256::from(hash.0)
}

/// Converts an SMT [`H256`] back to a 32-byte [`Hash`].
///
/// Returns [`Hash::zero()`] if the slice conversion fails.
pub fn h256_to_hash(h256: &H256) -> Hash {
    Hash::from_slice(h256.as_slice()).unwrap_or_else(Hash::zero)
}

/// Metadata keys stored in the meta column family.
pub mod meta_keys {
    /// Hash of the current chain tip (highest applied block).
    pub const TIP: &[u8] = b"tip";
    /// Hash of the highest synced header (maybe ahead of tip during sync).
    pub const HEADER_TIP: &[u8] = b"header_tip";
    /// Current state root hash.
    pub const STATE_ROOT: &[u8] = b"state_root";
    /// List of available snapshot heights.
    pub const SNAPSHOT_HEIGHTS: &[u8] = b"snapshot_heights";
    /// Prefix for snapshot metadata entries.
    pub const SNAPSHOT_META_PREFIX: &[u8] = b"snapshot_meta:";
}

/// Constructs the metadata key for a snapshot at the given height.
fn snapshot_meta_key(height: u64) -> Vec<u8> {
    let mut key = Vec::with_capacity(meta_keys::SNAPSHOT_META_PREFIX.len() + 8);
    key.extend_from_slice(meta_keys::SNAPSHOT_META_PREFIX);
    key.extend_from_slice(&height.to_le_bytes());
    key
}

/// Constructs a prefixed key for storing a state entry within a snapshot.
fn snapshot_entry_key(height: u64, state_key: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(8 + state_key.len());
    key.extend_from_slice(&height.to_le_bytes());
    key.extend_from_slice(state_key);
    key
}

struct Inner {
    /// RocksDB instance with column families for headers, blocks, meta, and state.
    db: Arc<DB>,
    /// Sparse Merkle Tree for state storage and merkle proofs.
    ///
    /// Uses in-memory `DefaultStore` (HashMap-backed) for fast merkle operations.
    /// Leaves are persisted to CF_STATE and rebuilt on startup.
    state: Smt,
    /// Cached tip hash (also persisted in meta CF).
    tip: Hash,
    /// Cached state root (also persisted in meta CF).
    state_root: Hash,
    /// Whether the in-memory SMT is loaded with the full state.
    state_loaded: bool,
}

impl Inner {
    /// Rebuilds the in-memory SMT from persisted leaves in CF_STATE.
    ///
    /// Iterates all key-value pairs in the state column family and inserts
    /// them into a fresh SMT. Called once during storage initialization.
    fn rebuild_smt_from_disk(db: &DB) -> Smt {
        let mut state = Smt::new(H256::zero(), DefaultStore::default());

        let cf = db.cf_handle(CF_STATE).expect("CF_STATE must exist");
        let snapshot = db.snapshot();
        let mut ro_iter = ReadOptions::default();
        ro_iter.set_snapshot(&snapshot);
        let mut ro_get = ReadOptions::default();
        ro_get.set_snapshot(&snapshot);
        let iter = db.iterator_cf_opt(cf, ro_iter, IteratorMode::Start);

        let mut leaves: Vec<(H256, SmtValue)> = Vec::new();
        for item in iter {
            let (key, value) = item.expect("RocksDB iteration failed");
            if key.len() == 32 {
                if let Ok(Some(get_back)) = db.get_cf_opt(cf, key.as_ref(), &ro_get)
                    && get_back.as_slice() != value.as_ref()
                {
                    error!(
                        "rebuild: iterator/get mismatch key_len={} iter_len={} get_len={} iter_first8={:02x?} get_first8={:02x?}",
                        key.len(),
                        value.len(),
                        get_back.len(),
                        value[..8.min(value.len())].try_into().unwrap_or([0; 8]),
                        get_back[..8.min(get_back.len())]
                            .try_into()
                            .unwrap_or([0; 8])
                    );
                }
                let arr: [u8; 32] = key.as_ref().try_into().expect("length already checked");
                let smt_value = SmtValue(value.clone().into_vec());
                leaves.push((H256::from(arr), smt_value));
            }
        }

        if !leaves.is_empty() {
            state.update_all(leaves).expect("SMT rebuild failed");
        }

        state
    }
}

/// RocksDB-backed storage for blockchain data.
///
/// Stores blocks and headers in RocksDB with column families for data separation.
/// State is managed via an in-memory sparse Merkle tree with leaves persisted to
/// CF_STATE. The SMT is rebuilt from disk on startup, enabling fast merkle proofs
/// without disk I/O during execution.
pub struct RocksDbStorage {
    inner: Mutex<Inner>,
}

impl RocksDbStorage {
    fn lock_inner(&self) -> std::sync::MutexGuard<'_, Inner> {
        // If a previous panic occurred while holding the lock, recover the inner state.
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn ensure_state_loaded_or_panic(
        mut inner: std::sync::MutexGuard<'_, Inner>,
    ) -> std::sync::MutexGuard<'_, Inner> {
        if let Err(e) = Self::ensure_state_loaded(&mut inner) {
            // Drop the lock before panicking to avoid poisoning the mutex.
            let msg = format!("state load failed: {e}");
            drop(inner);
            panic!("{msg}");
        }
        inner
    }

    /// Creates a new RocksDB-backed storage with the given database.
    ///
    /// If the database is empty (no tip stored), initializes with the genesis block
    /// and initial accounts. Otherwise, loads existing state from disk.
    pub fn new(
        db: Arc<DB>,
        genesis: Block,
        chain_id: u64,
        initial_accounts: &[(Address, Account)],
    ) -> Result<Self, StorageError> {
        let cf_meta = db.cf_handle(CF_META).expect("CF_META must exist");

        // Check if we have existing data
        let existing_tip = db
            .get_cf(cf_meta, meta_keys::TIP)
            .map_err(|e| StorageError::ValidationFailed(e.to_string()))?;

        let inner = if let Some(tip_bytes) = existing_tip {
            // Load existing state
            let tip = Hash::from_slice(&tip_bytes)
                .ok_or_else(|| StorageError::ValidationFailed("invalid tip hash".into()))?;

            let mut inner = Inner {
                db,
                state: Smt::new(H256::zero(), DefaultStore::default()),
                tip,
                state_root: Hash::zero(),
                state_loaded: false,
            };

            info!("Loading existing storage: tip={}", inner.tip);
            Self::ensure_state_loaded(&mut inner)?;

            inner
        } else {
            info!("Initializing fresh storage with genesis");
            // Initialize with genesis
            let mut state = Smt::new(H256::zero(), DefaultStore::default());
            let mut batch = WriteBatch::default();
            let cf_state = db.cf_handle(CF_STATE).expect("CF_STATE must exist");

            for (addr, account) in initial_accounts {
                let value = account.to_vec();
                state
                    .update(hash_to_h256(addr), SmtValue(value.clone()))
                    .expect("SMT update failed");
                batch.put_cf(cf_state, addr.as_slice(), &value);
            }

            let state_root = h256_to_hash(state.root());
            if state_root != genesis.header.state_root {
                return Err(StorageError::ValidationFailed(format!(
                    "state_root mismatch: expected {} and got {state_root}",
                    genesis.header.state_root,
                )));
            }

            let genesis_hash = genesis.header_hash(chain_id);
            let cf_headers = db.cf_handle(CF_HEADERS).expect("CF_HEADERS must exist");
            let cf_blocks = db.cf_handle(CF_BLOCKS).expect("CF_BLOCKS must exist");

            batch.put_cf(
                cf_headers,
                genesis_hash.as_slice(),
                genesis.header.to_bytes().as_slice(),
            );
            batch.put_cf(
                cf_blocks,
                genesis_hash.as_slice(),
                genesis.to_bytes().as_slice(),
            );
            batch.put_cf(cf_meta, meta_keys::TIP, genesis_hash.as_slice());
            batch.put_cf(cf_meta, meta_keys::STATE_ROOT, state_root.as_slice());

            db.write(batch)
                .map_err(|e| StorageError::ValidationFailed(e.to_string()))?;

            Inner {
                db,
                state,
                tip: genesis_hash,
                state_root,
                state_loaded: true,
            }
        };

        Ok(Self {
            inner: Mutex::new(inner),
        })
    }

    fn ensure_state_loaded(inner: &mut Inner) -> Result<(), StorageError> {
        if inner.state_loaded {
            return Ok(());
        }

        let cf_meta = inner.db.cf_handle(CF_META).expect("CF_META must exist");
        let cf_headers = inner
            .db
            .cf_handle(CF_HEADERS)
            .expect("CF_HEADERS must exist");
        let state_root_bytes = inner
            .db
            .get_cf(cf_meta, meta_keys::STATE_ROOT)
            .map_err(|e| StorageError::ValidationFailed(e.to_string()))?
            .ok_or_else(|| StorageError::ValidationFailed("missing state root".into()))?;
        let meta_root = Hash::from_slice(&state_root_bytes)
            .ok_or_else(|| StorageError::ValidationFailed("invalid state root".into()))?;

        // Count entries before rebuild for debugging
        let state = Inner::rebuild_smt_from_disk(&inner.db);
        let computed_root = h256_to_hash(state.root());

        if computed_root != meta_root {
            // Try to reconcile using the tip header's state_root.
            let tip_bytes = inner
                .db
                .get_cf(cf_meta, meta_keys::TIP)
                .map_err(|e| StorageError::ValidationFailed(e.to_string()))?
                .ok_or_else(|| StorageError::ValidationFailed("missing tip hash".into()))?;
            let tip = Hash::from_slice(&tip_bytes)
                .ok_or_else(|| StorageError::ValidationFailed("invalid tip hash".into()))?;

            let tip_header = Self::get_header_by_hash(&inner.db, cf_headers, tip)?
                .ok_or_else(|| StorageError::ValidationFailed("missing tip header".into()))?;

            if tip_header.state_root == computed_root {
                warn!(
                    "state_root mismatch: meta={} computed_from_disk={} tip_header={} (repairing meta)",
                    meta_root, computed_root, tip_header.state_root
                );
                inner
                    .db
                    .put_cf(cf_meta, meta_keys::STATE_ROOT, computed_root.as_slice())
                    .map_err(|e| StorageError::ValidationFailed(e.to_string()))?;
            } else if tip_header.state_root == meta_root {
                return Err(StorageError::ValidationFailed(format!(
                    "state_root mismatch: disk_root={} does not match tip header {}",
                    computed_root, tip_header.state_root
                )));
            } else {
                return Err(StorageError::ValidationFailed(format!(
                    "state_root mismatch: meta={} computed_from_disk={} tip_header={}",
                    meta_root, computed_root, tip_header.state_root
                )));
            }
        }

        inner.state = state;
        inner.state_root = computed_root;
        inner.state_loaded = true;
        Ok(())
    }

    fn flush_state_to_disk_and_discard(inner: &mut Inner) -> Result<(), StorageError> {
        if !inner.state_loaded {
            return Ok(());
        }

        let db = &inner.db;
        let cf_state = db.cf_handle(CF_STATE).expect("CF_STATE must exist");
        let cf_meta = db.cf_handle(CF_META).expect("CF_META must exist");

        // Capture state before flush for debugging
        let smt_root_before = h256_to_hash(inner.state.root());
        if smt_root_before != inner.state_root {
            error!(
                "CONSISTENCY ERROR: in-memory SMT root {} differs from cached state_root {}",
                smt_root_before, inner.state_root
            );
        }

        // Clear existing state entries.
        let mut batch = WriteBatch::default();
        let iter = db.iterator_cf(cf_state, IteratorMode::Start);
        for item in iter {
            let (key, _) = item.map_err(|e| StorageError::ValidationFailed(e.to_string()))?;
            batch.delete_cf(cf_state, key);
        }

        // Persist all current leaves from memory and verify they're non-empty.
        let mut written_count = 0u64;
        let leaves: Vec<_> = inner.state.store().leaves_map().iter().collect();
        for (key, value) in &leaves {
            if value.0.is_empty() {
                warn!("flush: skipping empty value for key {:?}", key.as_slice());
                continue;
            }
            let key_bytes = key.as_slice();
            batch.put_cf(cf_state, key_bytes, &value.0);
            written_count += 1;
        }

        // Persist authoritative state_root.
        batch.put_cf(cf_meta, meta_keys::STATE_ROOT, inner.state_root.as_slice());

        db.write(batch)
            .map_err(|e| StorageError::ValidationFailed(e.to_string()))?;

        // Direct read-back check before rebuild
        let cf_state = db.cf_handle(CF_STATE).expect("CF_STATE must exist");
        for (key, value) in &leaves {
            if let Ok(Some(read_back)) = db.get_cf(cf_state, key.as_slice()) {
                if read_back.as_slice() != value.0.as_slice() {
                    let wrote_first_8: [u8; 8] = value.0[..8].try_into().unwrap_or([0; 8]);
                    let read_first_8: [u8; 8] = read_back[..8].try_into().unwrap_or([0; 8]);
                    error!(
                        "READBACK MISMATCH for key={}: wrote {:02x?}... but read {:02x?}...",
                        Hash::from_slice(key.as_slice()).unwrap_or(Hash::zero()),
                        wrote_first_8,
                        read_first_8
                    );
                }
            } else {
                error!(
                    "READBACK MISSING for key={}",
                    Hash::from_slice(key.as_slice()).unwrap_or(Hash::zero())
                );
            }
        }

        // Verify: rebuild SMT from what we just wrote and check root matches
        let verify_smt = Inner::rebuild_smt_from_disk(db);
        let verify_root = h256_to_hash(verify_smt.root());
        if verify_root != inner.state_root {
            error!(
                "FLUSH VERIFICATION FAILED: wrote state_root={} but rebuilt root={}",
                inner.state_root, verify_root
            );
            // Log the entries we wrote vs what we read back
            let cf_state = db.cf_handle(CF_STATE).expect("CF_STATE must exist");
            let mut readback_count = 0u64;
            let iter = db.iterator_cf(cf_state, IteratorMode::Start);
            for item in iter {
                if item.is_ok() {
                    readback_count += 1;
                }
            }
            error!(
                "  wrote {} entries, read back {} entries",
                written_count, readback_count
            );

            // Deep compare: memory vs disk values for each leaf
            let mut dumped = false;
            for (key, value) in &leaves {
                let mem_hash = value.to_h256();
                match db.get_cf(cf_state, key.as_slice()) {
                    Ok(Some(read_back)) => {
                        let disk_hash = SmtValue(read_back.clone()).to_h256();
                        if read_back.as_slice() != value.0.as_slice() || mem_hash != disk_hash {
                            error!(
                                "  LEAF MISMATCH key={} mem_hash={:?} disk_hash={:?} mem_len={} disk_len={} mem_first8={:02x?} disk_first8={:02x?}",
                                Hash::from_slice(key.as_slice()).unwrap_or(Hash::zero()),
                                mem_hash,
                                disk_hash,
                                value.0.len(),
                                read_back.len(),
                                value.0[..8.min(value.0.len())].try_into().unwrap_or([0; 8]),
                                read_back[..8.min(read_back.len())]
                                    .try_into()
                                    .unwrap_or([0; 8]),
                            );
                            let min_len = value.0.len().min(read_back.len());
                            let mut first_diff: Option<(usize, u8, u8)> = None;
                            for (i, _) in read_back.iter().enumerate().take(min_len) {
                                let a = value.0[i];
                                let b = read_back[i];
                                if a != b {
                                    first_diff = Some((i, a, b));
                                    break;
                                }
                            }
                            if let Some((idx, a, b)) = first_diff {
                                error!(
                                    "  BYTE DIFF key={} idx={} mem={:02x} disk={:02x}",
                                    Hash::from_slice(key.as_slice()).unwrap_or(Hash::zero()),
                                    idx,
                                    a,
                                    b
                                );
                            } else if value.0.len() == read_back.len() {
                                error!(
                                    "  BYTE DIFF key={} none (bytes identical but hash mismatch)",
                                    Hash::from_slice(key.as_slice()).unwrap_or(Hash::zero())
                                );
                            } else {
                                error!(
                                    "  BYTE DIFF key={} none within min_len (len mem={} disk={})",
                                    Hash::from_slice(key.as_slice()).unwrap_or(Hash::zero()),
                                    value.0.len(),
                                    read_back.len()
                                );
                            }
                            if !dumped {
                                let mem_hex: String =
                                    value.0.iter().map(|b| format!("{:02x}", b)).collect();
                                let disk_hex: String =
                                    read_back.iter().map(|b| format!("{:02x}", b)).collect();
                                error!(
                                    "  MEM HEX key={} {}",
                                    Hash::from_slice(key.as_slice()).unwrap_or(Hash::zero()),
                                    mem_hex
                                );
                                error!(
                                    "  DISK HEX key={} {}",
                                    Hash::from_slice(key.as_slice()).unwrap_or(Hash::zero()),
                                    disk_hex
                                );
                                dumped = true;
                            }
                            let mut mem_slice = value.0.as_slice();
                            let mut disk_slice = read_back.as_slice();
                            if let (Ok(mem_account), Ok(disk_account)) = (
                                Account::decode(&mut mem_slice),
                                Account::decode(&mut disk_slice),
                            ) {
                                error!(
                                    "  ACCOUNT DIFF key={} mem(nonce={}, balance={}, code_hash={}, storage_root={}, trailing={}) disk(nonce={}, balance={}, code_hash={}, storage_root={}, trailing={})",
                                    Hash::from_slice(key.as_slice()).unwrap_or(Hash::zero()),
                                    mem_account.nonce(),
                                    mem_account.balance(),
                                    mem_account.code_hash(),
                                    mem_account.storage_root(),
                                    mem_slice.len(),
                                    disk_account.nonce(),
                                    disk_account.balance(),
                                    disk_account.code_hash(),
                                    disk_account.storage_root(),
                                    disk_slice.len()
                                );
                            }
                        }
                    }
                    Ok(None) => {
                        error!(
                            "  LEAF MISSING ON DISK key={} mem_len={}",
                            Hash::from_slice(key.as_slice()).unwrap_or(Hash::zero()),
                            value.0.len()
                        );
                    }
                    Err(e) => {
                        error!(
                            "  LEAF READ ERROR key={} err={}",
                            Hash::from_slice(key.as_slice()).unwrap_or(Hash::zero()),
                            e
                        );
                    }
                }
            }
        }

        // Drop in-memory SMT to force reload before next execution.
        inner.state = Smt::new(H256::zero(), DefaultStore::default());
        inner.state_loaded = false;

        Ok(())
    }

    fn load_snapshot_heights(db: &DB, cf_meta: &ColumnFamily) -> Result<Vec<u64>, StorageError> {
        let bytes = db
            .get_cf(cf_meta, meta_keys::SNAPSHOT_HEIGHTS)
            .map_err(|e| StorageError::ValidationFailed(e.to_string()))?;
        match bytes {
            Some(b) => Vec::<u64>::decode(&mut b.as_slice())
                .map_err(|e| StorageError::DecodeError(e.to_string())),
            None => Ok(Vec::new()),
        }
    }

    fn store_snapshot_heights(batch: &mut WriteBatch, cf_meta: &ColumnFamily, heights: &[u64]) {
        let mut buf = Vec::new();
        heights.to_vec().encode(&mut buf);
        batch.put_cf(cf_meta, meta_keys::SNAPSHOT_HEIGHTS, buf);
    }

    fn delete_snapshot_entries(
        db: &DB,
        cf_snapshots: &ColumnFamily,
        height: u64,
        batch: &mut WriteBatch,
    ) -> Result<(), StorageError> {
        let prefix = height.to_le_bytes();
        let iter = db.iterator_cf(cf_snapshots, IteratorMode::Start);
        for item in iter {
            let (key, _) = item.map_err(|e| StorageError::ValidationFailed(e.to_string()))?;
            if key.starts_with(&prefix) {
                batch.delete_cf(cf_snapshots, key);
            }
        }
        Ok(())
    }

    fn get_header_by_hash(
        db: &DB,
        cf_headers: &ColumnFamily,
        hash: Hash,
    ) -> Result<Option<Header>, StorageError> {
        Ok(db
            .get_cf(cf_headers, hash.as_slice())
            .map_err(|e| StorageError::ValidationFailed(e.to_string()))?
            .and_then(|bytes| Header::decode(&mut bytes.as_slice()).ok()))
    }

    fn find_hash_by_height(
        db: &DB,
        cf_headers: &ColumnFamily,
        mut current: Hash,
        target_height: u64,
    ) -> Result<Option<Hash>, StorageError> {
        loop {
            let Some(header) = Self::get_header_by_hash(db, cf_headers, current)? else {
                return Ok(None);
            };
            if header.height == target_height {
                return Ok(Some(current));
            }
            if header.height == 0 {
                return Ok(None);
            }
            current = header.previous_block;
        }
    }

    fn create_snapshot_with_inner(
        inner: &mut Inner,
        height: u64,
        tip: Hash,
    ) -> Result<(), StorageError> {
        let db = &inner.db;
        let cf_snapshots = db.cf_handle(CF_SNAPSHOTS).expect("CF_SNAPSHOTS must exist");
        let cf_state = db.cf_handle(CF_STATE).expect("CF_STATE must exist");
        let cf_meta = db.cf_handle(CF_META).expect("CF_META must exist");

        let mut batch = WriteBatch::default();
        Self::delete_snapshot_entries(db, cf_snapshots, height, &mut batch)?;

        // Collect entries - only 32-byte keys (Hash keys) to match SMT leaves
        let mut entry_count = 0u64;
        let mut skipped_keys = 0u64;
        let iter = db.iterator_cf(cf_state, IteratorMode::Start);
        for item in iter {
            let (key, value) = item.map_err(|e| StorageError::ValidationFailed(e.to_string()))?;
            if key.len() == 32 {
                let snap_key = snapshot_entry_key(height, key.as_ref());
                batch.put_cf(cf_snapshots, snap_key, value);
                entry_count += 1;
            } else {
                skipped_keys += 1;
                warn!(
                    "snapshot: skipping non-32-byte key in CF_STATE: len={} key={:?}",
                    key.len(),
                    &key[..std::cmp::min(key.len(), 16)]
                );
            }
        }

        // Verify the in-memory SMT root matches what we're saving
        let smt_root_from_memory = h256_to_hash(inner.state.root());
        if smt_root_from_memory != inner.state_root {
            error!(
                "snapshot: in-memory SMT root mismatch! cached={} computed={}",
                inner.state_root, smt_root_from_memory
            );
        }

        info!(
            "creating snapshot at height={height} tip={tip} entries={entry_count} skipped={skipped_keys} state_root={}",
            inner.state_root
        );

        let mut heights = Self::load_snapshot_heights(db, cf_meta)?;
        if !heights.contains(&height) {
            heights.push(height);
            heights.sort_unstable();
        }

        // Keep only the last two snapshots (bounded replay window).
        while heights.len() > 2 {
            let removed = heights.remove(0);
            Self::delete_snapshot_entries(db, cf_snapshots, removed, &mut batch)?;
            batch.delete_cf(cf_meta, snapshot_meta_key(removed));
        }

        Self::store_snapshot_heights(&mut batch, cf_meta, &heights);

        let mut meta_val = Vec::with_capacity(32);
        meta_val.extend_from_slice(tip.as_slice());
        batch.put_cf(cf_meta, snapshot_meta_key(height), meta_val);

        db.write(batch)
            .map_err(|e| StorageError::ValidationFailed(e.to_string()))?;

        // Verify entries were written by reading them back
        let prefix = height.to_le_bytes();
        let mut verify_count = 0u64;
        let iter = db.iterator_cf(
            cf_snapshots,
            IteratorMode::From(&prefix, rocksdb::Direction::Forward),
        );
        for item in iter {
            let (key, _) = item.map_err(|e| StorageError::ValidationFailed(e.to_string()))?;
            if !key.starts_with(&prefix) {
                break;
            }
            verify_count += 1;
        }
        if verify_count != entry_count {
            error!(
                "snapshot verification failed: wrote {} entries but found {} in CF_SNAPSHOTS",
                entry_count, verify_count
            );
        }

        Ok(())
    }

    /// Clears existing data and reinitialized storage with the given genesis block.
    pub fn reset(
        &self,
        genesis: Block,
        chain_id: u64,
        initial_accounts: &[(Address, Account)],
    ) -> Result<(), StorageError> {
        let mut inner = self.lock_inner();
        let db = &inner.db;

        let cf_headers = db.cf_handle(CF_HEADERS).expect("CF_HEADERS must exist");
        let cf_blocks = db.cf_handle(CF_BLOCKS).expect("CF_BLOCKS must exist");
        let cf_meta = db.cf_handle(CF_META).expect("CF_META must exist");
        let cf_state = db.cf_handle(CF_STATE).expect("CF_STATE must exist");
        let cf_snapshots = db.cf_handle(CF_SNAPSHOTS).expect("CF_SNAPSHOTS must exist");

        let mut batch = WriteBatch::default();
        for cf in [cf_headers, cf_blocks, cf_meta, cf_state, cf_snapshots] {
            let iter = db.iterator_cf(cf, IteratorMode::Start);
            for item in iter {
                let (key, _) = item.map_err(|e| StorageError::ValidationFailed(e.to_string()))?;
                batch.delete_cf(cf, key);
            }
        }

        let mut state = Smt::new(H256::zero(), DefaultStore::default());
        for (addr, account) in initial_accounts {
            let value = account.to_vec();
            state
                .update(hash_to_h256(addr), SmtValue(value.clone()))
                .expect("SMT update failed");
            batch.put_cf(cf_state, addr.as_slice(), &value);
        }

        let state_root = h256_to_hash(state.root());
        if state_root != genesis.header.state_root {
            return Err(StorageError::ValidationFailed(format!(
                "state_root mismatch: expected {} and got {state_root}",
                genesis.header.state_root,
            )));
        }

        let genesis_hash = genesis.header_hash(chain_id);
        batch.put_cf(
            cf_headers,
            genesis_hash.as_slice(),
            genesis.header.to_bytes().as_slice(),
        );
        batch.put_cf(
            cf_blocks,
            genesis_hash.as_slice(),
            genesis.to_bytes().as_slice(),
        );
        batch.put_cf(cf_meta, meta_keys::TIP, genesis_hash.as_slice());
        batch.put_cf(cf_meta, meta_keys::STATE_ROOT, state_root.as_slice());

        db.write(batch)
            .map_err(|e| StorageError::ValidationFailed(e.to_string()))?;

        inner.state = state;
        inner.state_root = state_root;
        inner.tip = genesis_hash;
        inner.state_loaded = true;

        Ok(())
    }

    /// Returns the list of available snapshot heights (ascending).
    pub fn snapshot_heights(&self) -> Result<Vec<u64>, StorageError> {
        let inner = self.lock_inner();
        let cf_meta = inner.db.cf_handle(CF_META).expect("CF_META must exist");
        Self::load_snapshot_heights(&inner.db, cf_meta)
    }

    /// Returns the tip hash recorded for the snapshot at the given height.
    pub fn snapshot_tip(&self, height: u64) -> Result<Option<Hash>, StorageError> {
        let inner = self.lock_inner();
        let cf_meta = inner.db.cf_handle(CF_META).expect("CF_META must exist");
        let key = snapshot_meta_key(height);
        let bytes = inner
            .db
            .get_cf(cf_meta, key)
            .map_err(|e| StorageError::ValidationFailed(e.to_string()))?;
        Ok(bytes.and_then(|b| Hash::from_slice(&b)))
    }

    // ========== Header-only storage methods for header-first sync ==========

    /// Stores a header without its block body.
    ///
    /// Used during header-first sync to store headers before downloading block bodies.
    /// The header_tip is updated if this header extends the header chain.
    pub fn store_header_only(&self, header: &Header, hash: Hash) -> Result<(), StorageError> {
        let inner = self.lock_inner();
        let db = &inner.db;
        let cf_headers = db.cf_handle(CF_HEADERS).expect("CF_HEADERS must exist");
        let cf_meta = db.cf_handle(CF_META).expect("CF_META must exist");

        // Check if header already exists
        if db
            .get_cf(cf_headers, hash.as_slice())
            .map_err(|e| StorageError::ValidationFailed(e.to_string()))?
            .is_some()
        {
            return Ok(()); // Already have this header
        }

        let mut batch = WriteBatch::default();
        batch.put_cf(cf_headers, hash.as_slice(), header.to_bytes().as_slice());

        // Update header_tip if this extends the chain
        let current_header_tip = db
            .get_cf(cf_meta, meta_keys::HEADER_TIP)
            .map_err(|e| StorageError::ValidationFailed(e.to_string()))?;

        let should_update_tip = match current_header_tip {
            None => true,
            Some(tip_bytes) => {
                let tip_hash = Hash::from_slice(&tip_bytes)
                    .ok_or_else(|| StorageError::ValidationFailed("invalid header tip".into()))?;
                if let Some(tip_header) = Self::get_header_by_hash(db, cf_headers, tip_hash)? {
                    header.height > tip_header.height
                } else {
                    true
                }
            }
        };

        if should_update_tip {
            batch.put_cf(cf_meta, meta_keys::HEADER_TIP, hash.as_slice());
        }

        db.write(batch)
            .map_err(|e| StorageError::ValidationFailed(e.to_string()))?;

        Ok(())
    }

    /// Stores multiple headers atomically.
    ///
    /// Headers should be in ascending height order. Updates header_tip to the
    /// highest header if it extends the current header chain.
    pub fn store_headers(&self, headers: &[Header], chain_id: u64) -> Result<(), StorageError> {
        if headers.is_empty() {
            return Ok(());
        }

        let inner = self.lock_inner();
        let db = &inner.db;
        let cf_headers = db.cf_handle(CF_HEADERS).expect("CF_HEADERS must exist");
        let cf_meta = db.cf_handle(CF_META).expect("CF_META must exist");

        let mut batch = WriteBatch::default();
        let mut highest_header: Option<(Hash, u64)> = None;

        for header in headers {
            let hash = header.header_hash(chain_id);

            // Skip if already exists
            if db
                .get_cf(cf_headers, hash.as_slice())
                .map_err(|e| StorageError::ValidationFailed(e.to_string()))?
                .is_some()
            {
                continue;
            }

            batch.put_cf(cf_headers, hash.as_slice(), header.to_bytes().as_slice());

            match &highest_header {
                None => highest_header = Some((hash, header.height)),
                Some((_, h)) if header.height > *h => {
                    highest_header = Some((hash, header.height));
                }
                _ => {}
            }
        }

        // Update header_tip if we have a new highest header
        if let Some((new_tip_hash, new_height)) = highest_header {
            let current_header_tip = db
                .get_cf(cf_meta, meta_keys::HEADER_TIP)
                .map_err(|e| StorageError::ValidationFailed(e.to_string()))?;

            let should_update = match current_header_tip {
                None => true,
                Some(tip_bytes) => {
                    let tip_hash = Hash::from_slice(&tip_bytes).ok_or_else(|| {
                        StorageError::ValidationFailed("invalid header tip".into())
                    })?;
                    if let Some(tip_header) = Self::get_header_by_hash(db, cf_headers, tip_hash)? {
                        new_height > tip_header.height
                    } else {
                        true
                    }
                }
            };

            if should_update {
                batch.put_cf(cf_meta, meta_keys::HEADER_TIP, new_tip_hash.as_slice());
            }
        }

        db.write(batch)
            .map_err(|e| StorageError::ValidationFailed(e.to_string()))?;

        Ok(())
    }

    /// Returns the hash of the highest synced header.
    ///
    /// During sync, this may be ahead of the block tip. Returns None if no headers
    /// have been stored yet.
    pub fn header_tip(&self) -> Option<Hash> {
        let inner = self.lock_inner();
        let cf_meta = inner.db.cf_handle(CF_META).expect("CF_META must exist");
        inner
            .db
            .get_cf(cf_meta, meta_keys::HEADER_TIP)
            .ok()
            .flatten()
            .and_then(|b| Hash::from_slice(&b))
    }

    /// Returns the height of the highest synced header.
    pub fn header_height(&self) -> u64 {
        let Some(tip) = self.header_tip() else {
            return self.height();
        };
        self.get_header(tip)
            .map(|h| h.height)
            .unwrap_or_else(|| self.height())
    }

    /// Returns the header at the given height by walking back from header_tip.
    ///
    /// Returns None if no header exists at that height.
    pub fn get_header_by_height(&self, target_height: u64) -> Option<Header> {
        let inner = self.lock_inner();
        let db = &inner.db;
        let cf_headers = db.cf_handle(CF_HEADERS).expect("CF_HEADERS must exist");
        let cf_meta = db.cf_handle(CF_META).expect("CF_META must exist");

        // Start from header_tip if available, otherwise use block tip
        let start_hash = db
            .get_cf(cf_meta, meta_keys::HEADER_TIP)
            .ok()
            .flatten()
            .and_then(|b| Hash::from_slice(&b))
            .or_else(|| {
                db.get_cf(cf_meta, meta_keys::TIP)
                    .ok()
                    .flatten()
                    .and_then(|b| Hash::from_slice(&b))
            })?;

        Self::find_hash_by_height(db, cf_headers, start_hash, target_height)
            .ok()
            .flatten()
            .and_then(|hash| {
                Self::get_header_by_hash(db, cf_headers, hash)
                    .ok()
                    .flatten()
            })
    }

    /// Checks if a header exists at the given height.
    pub fn has_header_at_height(&self, height: u64) -> bool {
        self.get_header_by_height(height).is_some()
    }

    // ========== End header-only storage methods ==========

    /// Exports all state entries from the snapshot at the given height.
    ///
    /// Returns a vector of (key, value) pairs representing the full state at that height.
    /// Used for state sync to send snapshot data to peers.
    pub fn export_snapshot(&self, height: u64) -> Result<Vec<(Hash, Vec<u8>)>, StorageError> {
        let inner = self.lock_inner();
        let db = &inner.db;
        let cf_snapshots = db.cf_handle(CF_SNAPSHOTS).expect("CF_SNAPSHOTS must exist");

        let prefix = height.to_le_bytes();
        let mut entries = Vec::new();

        // Use prefix seek for efficiency
        let iter = db.iterator_cf(
            cf_snapshots,
            IteratorMode::From(&prefix, rocksdb::Direction::Forward),
        );
        for item in iter {
            let (key, value) = item.map_err(|e| StorageError::ValidationFailed(e.to_string()))?;
            // Stop once we're past our prefix
            if !key.starts_with(&prefix) {
                break;
            }
            let raw_key = &key[8..];
            if raw_key.len() != 32 {
                continue;
            }
            let hash = Hash::from_slice(raw_key)
                .ok_or_else(|| StorageError::ValidationFailed("invalid key in snapshot".into()))?;
            entries.push((hash, value.into_vec()));
        }

        info!(
            "export_snapshot: height={} entries={}",
            height,
            entries.len()
        );

        Ok(entries)
    }

    /// Imports a snapshot received from a peer and initializes storage from it.
    ///
    /// This replaces the current state with the snapshot state, stores the block,
    /// and sets the tip to the snapshot block. Used for state sync when the node
    /// cannot sync from genesis due to pruned blocks.
    pub fn import_snapshot(
        &self,
        height: u64,
        block: Block,
        entries: Vec<(Hash, Vec<u8>)>,
        chain_id: u64,
    ) -> Result<(), StorageError> {
        let mut inner = self.lock_inner();
        let db = &inner.db;

        // Make sure the block is a valid one
        block
            .verify(chain_id)
            .map_err(|e| StorageError::ValidationFailed(e.to_string()))?;

        let cf_headers = db.cf_handle(CF_HEADERS).expect("CF_HEADERS must exist");
        let cf_blocks = db.cf_handle(CF_BLOCKS).expect("CF_BLOCKS must exist");
        let cf_meta = db.cf_handle(CF_META).expect("CF_META must exist");
        let cf_state = db.cf_handle(CF_STATE).expect("CF_STATE must exist");
        let cf_snapshots = db.cf_handle(CF_SNAPSHOTS).expect("CF_SNAPSHOTS must exist");

        // Verify the block height matches
        if block.header.height != height {
            return Err(StorageError::ValidationFailed(format!(
                "block height {} does not match snapshot height {}",
                block.header.height, height
            )));
        }

        // Build new state from entries
        let mut batch = WriteBatch::default();
        let mut state = Smt::new(H256::zero(), DefaultStore::default());
        for (key, value) in &entries {
            state
                .update(hash_to_h256(key), SmtValue(value.clone()))
                .expect("SMT update failed");
            batch.put_cf(cf_state, key.as_slice(), value);
        }

        let state_root = h256_to_hash(state.root());

        info!(
            "import_snapshot: height={} block_height={} entries={} block_state_root={} computed_state_root={}",
            height,
            block.header.height,
            entries.len(),
            block.header.state_root,
            state_root
        );

        // Verify state root matches the block's state root
        if state_root != block.header.state_root {
            return Err(StorageError::ValidationFailed(format!(
                "state_root mismatch: block has {} but computed {}",
                block.header.state_root, state_root
            )));
        }

        // Store the block
        let block_hash = block.header_hash(chain_id);
        batch.put_cf(
            cf_headers,
            block_hash.as_slice(),
            block.header.to_bytes().as_slice(),
        );
        batch.put_cf(
            cf_blocks,
            block_hash.as_slice(),
            block.to_bytes().as_slice(),
        );

        // Update metadata
        batch.put_cf(cf_meta, meta_keys::TIP, block_hash.as_slice());
        batch.put_cf(cf_meta, meta_keys::HEADER_TIP, block_hash.as_slice());
        batch.put_cf(cf_meta, meta_keys::STATE_ROOT, state_root.as_slice());

        // Create a snapshot at this height
        for (key, value) in &entries {
            let snap_key = snapshot_entry_key(height, key.as_slice());
            batch.put_cf(cf_snapshots, snap_key, value);
        }

        // Store snapshot metadata
        let mut meta_val = Vec::with_capacity(32);
        meta_val.extend_from_slice(block_hash.as_slice());
        batch.put_cf(cf_meta, snapshot_meta_key(height), meta_val);

        // Update snapshot heights list
        Self::store_snapshot_heights(&mut batch, cf_meta, &[height]);

        db.write(batch)
            .map_err(|e| StorageError::ValidationFailed(e.to_string()))?;

        inner.state = state;
        inner.state_root = state_root;
        inner.tip = block_hash;
        inner.state_loaded = true;

        Ok(())
    }

    /// Resets state to the snapshot at the given height and truncates headers/blocks above it.
    pub fn reset_to_snapshot(&self, height: u64) -> Result<(), StorageError> {
        let mut inner = self.lock_inner();
        let db = &inner.db;

        let cf_headers = db.cf_handle(CF_HEADERS).expect("CF_HEADERS must exist");
        let cf_blocks = db.cf_handle(CF_BLOCKS).expect("CF_BLOCKS must exist");
        let cf_meta = db.cf_handle(CF_META).expect("CF_META must exist");
        let cf_state = db.cf_handle(CF_STATE).expect("CF_STATE must exist");
        let cf_snapshots = db.cf_handle(CF_SNAPSHOTS).expect("CF_SNAPSHOTS must exist");

        let meta_key = snapshot_meta_key(height);
        let tip_bytes = db
            .get_cf(cf_meta, meta_key)
            .map_err(|e| StorageError::ValidationFailed(e.to_string()))?
            .ok_or_else(|| StorageError::ValidationFailed("snapshot meta missing".into()))?;
        let snapshot_tip = Hash::from_slice(&tip_bytes)
            .ok_or_else(|| StorageError::ValidationFailed("invalid snapshot tip".into()))?;

        let mut batch = WriteBatch::default();

        // Clear current state.
        let iter = db.iterator_cf(cf_state, IteratorMode::Start);
        for item in iter {
            let (key, _) = item.map_err(|e| StorageError::ValidationFailed(e.to_string()))?;
            batch.delete_cf(cf_state, key);
        }

        // Load snapshot state.
        let mut state = Smt::new(H256::zero(), DefaultStore::default());
        let prefix = height.to_le_bytes();
        let iter = db.iterator_cf(cf_snapshots, IteratorMode::Start);
        for item in iter {
            let (key, value) = item.map_err(|e| StorageError::ValidationFailed(e.to_string()))?;
            if !key.starts_with(&prefix) {
                continue;
            }
            let raw_key = &key[8..];
            if raw_key.len() != 32 {
                continue;
            }
            let arr: [u8; 32] = raw_key.try_into().expect("length already checked");
            state
                .update(H256::from(arr), SmtValue(value.clone().into_vec()))
                .expect("SMT update failed");
            batch.put_cf(cf_state, raw_key, value);
        }

        let state_root = h256_to_hash(state.root());
        batch.put_cf(cf_meta, meta_keys::STATE_ROOT, state_root.as_slice());

        // Truncate headers/blocks above the snapshot height.
        let mut current = inner.tip;
        loop {
            let Some(header) = Self::get_header_by_hash(db, cf_headers, current)? else {
                return Err(StorageError::ValidationFailed(
                    "missing header during reset".into(),
                ));
            };
            if header.height <= height {
                break;
            }

            batch.delete_cf(cf_headers, current.as_slice());
            batch.delete_cf(cf_blocks, current.as_slice());
            current = header.previous_block;
        }

        if current != snapshot_tip {
            return Err(StorageError::ValidationFailed(
                "snapshot tip does not match header chain".into(),
            ));
        }

        batch.put_cf(cf_meta, meta_keys::TIP, snapshot_tip.as_slice());
        batch.put_cf(cf_meta, meta_keys::HEADER_TIP, snapshot_tip.as_slice());

        db.write(batch)
            .map_err(|e| StorageError::ValidationFailed(e.to_string()))?;

        inner.state = state;
        inner.state_root = state_root;
        inner.tip = snapshot_tip;
        inner.state_loaded = true;

        Ok(())
    }
}

impl Storage for RocksDbStorage {
    fn has_block(&self, hash: Hash) -> bool {
        let inner = self.lock_inner();
        // Check CF_BLOCKS, not CF_HEADERS - a "block" means the full block with transactions,
        // not just the header (which may exist from header-first sync)
        let cf = inner.db.cf_handle(CF_BLOCKS).expect("CF_BLOCKS must exist");
        inner
            .db
            .get_cf(cf, hash.as_slice())
            .ok()
            .flatten()
            .is_some()
    }

    fn get_header(&self, hash: Hash) -> Option<Header> {
        let inner = self.lock_inner();
        let cf = inner
            .db
            .cf_handle(CF_HEADERS)
            .expect("CF_HEADERS must exist");
        inner
            .db
            .get_cf(cf, hash.as_slice())
            .ok()
            .flatten()
            .and_then(|bytes| Header::decode(&mut bytes.as_slice()).ok())
    }

    fn get_block(&self, hash: Hash) -> Option<Arc<Block>> {
        let inner = self.lock_inner();
        let cf = inner.db.cf_handle(CF_BLOCKS).expect("CF_BLOCKS must exist");
        inner
            .db
            .get_cf(cf, hash.as_slice())
            .ok()
            .flatten()
            .and_then(|bytes| Block::decode(&mut bytes.as_slice()).ok())
            .map(Arc::new)
    }

    fn append_block(&self, block: Block, chain_id: u64) -> Result<(), StorageError> {
        let mut inner = self.lock_inner();
        let db = inner.db.clone();

        if block.header.previous_block != inner.tip {
            return Err(StorageError::NotOnTip {
                expected: inner.tip,
                actual: block.header.previous_block,
            });
        }

        let hash = block.header_hash(chain_id);
        let cf_headers = db.cf_handle(CF_HEADERS).expect("CF_HEADERS must exist");
        let cf_blocks = db.cf_handle(CF_BLOCKS).expect("CF_BLOCKS must exist");
        let cf_meta = db.cf_handle(CF_META).expect("CF_META must exist");

        let mut batch = WriteBatch::default();
        batch.put_cf(
            cf_headers,
            hash.as_slice(),
            block.header.to_bytes().as_slice(),
        );
        batch.put_cf(cf_blocks, hash.as_slice(), block.to_bytes().as_slice());
        batch.put_cf(cf_meta, meta_keys::TIP, hash.as_slice());

        db.write(batch)
            .map_err(|e| StorageError::ValidationFailed(e.to_string()))?;

        inner.tip = hash;

        let height = block.header.height;

        // Flush state to disk BEFORE creating snapshot so snapshot reads correct data
        if height != 0 && height.is_multiple_of(SNAPSHOT_INTERVAL) {
            Self::flush_state_to_disk_and_discard(&mut inner)?;
            Self::ensure_state_loaded(&mut inner)?;
            Self::create_snapshot_with_inner(&mut inner, height, hash)?;
        }

        if height > BLOCK_BODY_RETENTION {
            let target_height = height - BLOCK_BODY_RETENTION;
            // Never prune genesis (height 0) or snapshot blocks
            if target_height != 0 {
                let snapshot_heights = Self::load_snapshot_heights(&db, cf_meta)?;
                if !snapshot_heights.contains(&target_height)
                    && let Some(prune_hash) =
                        Self::find_hash_by_height(&db, cf_headers, hash, target_height)?
                {
                    let mut prune_batch = WriteBatch::default();
                    prune_batch.delete_cf(cf_blocks, prune_hash.as_slice());
                    db.write(prune_batch)
                        .map_err(|e| StorageError::ValidationFailed(e.to_string()))?;
                }
            }
        }

        // Persist full SMT state to disk and drop in-memory copy
        // (skip if we already flushed for snapshot creation)
        if inner.state_loaded {
            Self::flush_state_to_disk_and_discard(&mut inner)?;
        }
        Ok(())
    }

    fn height(&self) -> u64 {
        let inner = self.lock_inner();
        let cf = inner
            .db
            .cf_handle(CF_HEADERS)
            .expect("CF_HEADERS must exist");

        // Get the height from the tip block's header, not by counting headers
        // (header-only sync may have more headers than applied blocks)
        inner
            .db
            .get_cf(cf, inner.tip.as_slice())
            .ok()
            .flatten()
            .and_then(|bytes| Header::decode(&mut bytes.as_slice()).ok())
            .map(|h| h.height)
            .unwrap_or(0)
    }

    fn tip(&self) -> Hash {
        self.lock_inner().tip
    }
}

impl StateStore for RocksDbStorage {
    fn preview_root(&self, writes: &[(Hash, Option<Vec<u8>>)]) -> Hash {
        let inner = Self::ensure_state_loaded_or_panic(self.lock_inner());
        let mut leaves_map: BTreeMap<H256, SmtValue> = inner
            .state
            .store()
            .leaves_map()
            .iter()
            .map(|(key, value)| (*key, value.clone()))
            .collect();

        for (key, value_opt) in writes {
            let key_h = hash_to_h256(key);
            match value_opt {
                Some(v) => {
                    leaves_map.insert(key_h, SmtValue(v.clone()));
                }
                None => {
                    leaves_map.remove(&key_h);
                }
            }
        }

        let mut state = Smt::new(H256::zero(), DefaultStore::default());
        if !leaves_map.is_empty() {
            let leaves: Vec<(H256, SmtValue)> = leaves_map.into_iter().collect();
            state.update_all(leaves).expect("SMT update failed");
        }
        h256_to_hash(state.root())
    }

    fn apply_batch(&self, writes: Vec<(Hash, Option<Vec<u8>>)>) {
        let mut inner = Self::ensure_state_loaded_or_panic(self.lock_inner());
        // Update in-memory SMT first
        let mut leaves_map: BTreeMap<H256, SmtValue> = inner
            .state
            .store()
            .leaves_map()
            .iter()
            .map(|(key, value)| (*key, value.clone()))
            .collect();
        for (key, value_opt) in &writes {
            let val = match value_opt {
                Some(v) => SmtValue(v.clone()),
                None => SmtValue::zero(),
            };
            let key_h = hash_to_h256(key);
            if val.0.is_empty() {
                leaves_map.remove(&key_h);
            } else {
                leaves_map.insert(key_h, val);
            }
        }

        let mut state = Smt::new(H256::zero(), DefaultStore::default());
        if !leaves_map.is_empty() {
            let leaves: Vec<(H256, SmtValue)> = leaves_map.into_iter().collect();
            state.update_all(leaves).expect("SMT update failed");
        }
        inner.state = state;
        inner.state_root = h256_to_hash(inner.state.root());
    }

    fn state_root(&self) -> Hash {
        self.lock_inner().state_root
    }
}

impl VmStorage for RocksDbStorage {
    fn contains_key(&self, key: Hash) -> bool {
        let inner = Self::ensure_state_loaded_or_panic(self.lock_inner());
        inner
            .state
            .get(&hash_to_h256(&key))
            .ok()
            .map(|v| !v.0.is_empty())
            .unwrap_or(false)
    }

    fn get(&self, key: Hash) -> Option<Vec<u8>> {
        let inner = Self::ensure_state_loaded_or_panic(self.lock_inner());
        let result = inner
            .state
            .get(&hash_to_h256(&key))
            .ok()
            .filter(|v| !v.0.is_empty());
        result.map(|v| v.0)
    }
}

impl AccountStorage for RocksDbStorage {
    fn get_account(&self, addr: Address) -> Option<Account> {
        let inner = Self::ensure_state_loaded_or_panic(self.lock_inner());
        inner
            .state
            .get(&hash_to_h256(&addr))
            .ok()
            .filter(|v| !v.0.is_empty())
            .and_then(|v| match Account::decode(&mut v.0.as_slice()) {
                Ok(acc) => Some(acc),
                Err(e) => {
                    warn!("failed to decode account {addr}: {e} (len={})", v.0.len());
                    None
                }
            })
    }

    fn set_account(&self, addr: Address, account: Account) {
        self.apply_batch(vec![(addr, Some(account.to_vec()))]);
    }

    fn delete_account(&self, addr: Address) {
        self.apply_batch(vec![(addr, None)]);
    }
}

impl StateViewProvider for RocksDbStorage {
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
    use crate::core::block::Header;
    use crate::crypto::key_pair::PrivateKey;
    use crate::types::merkle_tree::MerkleTree;
    use crate::virtual_machine::state::State;
    use crate::virtual_machine::vm::BLOCK_GAS_LIMIT;
    use rocksdb::{ColumnFamilyDescriptor, Options};
    use std::path::PathBuf;

    const TEST_CHAIN_ID: u64 = 12345;

    fn cf_descriptors() -> Vec<ColumnFamilyDescriptor> {
        vec![
            ColumnFamilyDescriptor::new(CF_HEADERS, Options::default()),
            ColumnFamilyDescriptor::new(CF_BLOCKS, Options::default()),
            ColumnFamilyDescriptor::new(CF_META, Options::default()),
            ColumnFamilyDescriptor::new(CF_STATE, Options::default()),
            ColumnFamilyDescriptor::new(CF_SNAPSHOTS, Options::default()),
        ]
    }

    fn open_db(path: &std::path::Path) -> Arc<DB> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);

        Arc::new(
            DB::open_cf_descriptors(&opts, path, cf_descriptors()).expect("failed to open test db"),
        )
    }

    fn test_db() -> Arc<DB> {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let path = dir.keep();
        open_db(&path)
    }

    fn test_db_with_path() -> (Arc<DB>, PathBuf) {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let path = dir.keep();
        let db = open_db(&path);
        (db, path)
    }

    fn genesis_block(initial_accounts: &[(Address, Account)]) -> Block {
        let mut state = Smt::new(H256::zero(), DefaultStore::default());
        for (addr, account) in initial_accounts {
            state
                .update(hash_to_h256(addr), SmtValue(account.to_vec()))
                .expect("smt update failed");
        }

        let header = Header {
            version: 1,
            height: 0,
            timestamp: 0,
            gas_used: 0,
            previous_block: Hash::zero(),
            merkle_root: Hash::zero(),
            state_root: h256_to_hash(state.root()),
        };

        let genesis_key = PrivateKey::new();
        Block::new(header, genesis_key, vec![], TEST_CHAIN_ID)
    }

    fn create_storage(initial_accounts: &[(Address, Account)]) -> RocksDbStorage {
        let genesis = genesis_block(initial_accounts);
        RocksDbStorage::new(test_db(), genesis, TEST_CHAIN_ID, initial_accounts)
            .expect("failed to create storage")
    }

    // ==================== SmtValue Tests ====================

    #[test]
    fn smt_value_zero_returns_empty() {
        let zero = SmtValue::zero();
        assert!(zero.0.is_empty());
    }

    #[test]
    fn smt_value_empty_hashes_to_h256_zero() {
        let empty = SmtValue(vec![]);
        assert_eq!(empty.to_h256(), H256::zero());
    }

    #[test]
    fn smt_value_non_empty_produces_deterministic_hash() {
        let val1 = SmtValue(vec![1, 2, 3, 4]);
        let val2 = SmtValue(vec![1, 2, 3, 4]);
        let val3 = SmtValue(vec![1, 2, 3, 5]);

        assert_eq!(val1.to_h256(), val2.to_h256());
        assert_ne!(val1.to_h256(), val3.to_h256());
    }

    // ==================== Hash Conversion Tests ====================

    #[test]
    fn hash_to_h256_and_back_roundtrip() {
        let original = Hash::sha3().chain(b"test data").finalize();
        let h256 = hash_to_h256(&original);
        let back = h256_to_hash(&h256);
        assert_eq!(original, back);
    }

    #[test]
    fn hash_to_h256_zero() {
        let zero = Hash::zero();
        let h256 = hash_to_h256(&zero);
        assert_eq!(h256, H256::zero());
    }

    // ==================== Storage Initialization Tests ====================

    #[test]
    fn new_storage_initializes_with_genesis() {
        let storage = create_storage(&[]);
        assert_eq!(storage.height(), 0);
        assert_ne!(storage.tip(), Hash::zero());
    }

    #[test]
    fn new_storage_with_initial_accounts() {
        let key = PrivateKey::new();
        let addr = key.public_key().address();
        let account = Account::new(1_000_000);

        let storage = create_storage(&[(addr, account.clone())]);

        let retrieved = storage.get_account(addr);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().balance(), 1_000_000);
    }

    #[test]
    fn storage_state_root_matches_genesis_after_init() {
        let key = PrivateKey::new();
        let addr = key.public_key().address();
        let account = Account::new(500);
        let initial = [(addr, account)];

        let genesis = genesis_block(&initial);
        let expected_root = genesis.header.state_root;

        let storage = create_storage(&initial);
        assert_eq!(storage.state_root(), expected_root);
    }

    // ==================== Block Operations Tests ====================

    #[test]
    fn has_block_returns_true_for_genesis() {
        let storage = create_storage(&[]);
        let tip = storage.tip();
        assert!(storage.has_block(tip));
    }

    #[test]
    fn has_block_returns_false_for_unknown() {
        let storage = create_storage(&[]);
        let unknown = Hash::sha3().chain(b"unknown").finalize();
        assert!(!storage.has_block(unknown));
    }

    #[test]
    fn get_header_returns_genesis_header() {
        let storage = create_storage(&[]);
        let tip = storage.tip();
        let header = storage.get_header(tip);

        assert!(header.is_some());
        assert_eq!(header.unwrap().height, 0);
    }

    #[test]
    fn get_block_returns_genesis_block() {
        let storage = create_storage(&[]);
        let tip = storage.tip();
        let block = storage.get_block(tip);

        assert!(block.is_some());
        assert_eq!(block.unwrap().header.height, 0);
    }

    #[test]
    fn get_block_returns_none_for_unknown() {
        let storage = create_storage(&[]);
        let unknown = Hash::sha3().chain(b"unknown").finalize();
        assert!(storage.get_block(unknown).is_none());
    }

    // ==================== Account Operations Tests ====================

    #[test]
    fn set_and_get_account() {
        let storage = create_storage(&[]);

        let key = PrivateKey::new();
        let addr = key.public_key().address();
        let account = Account::new(42_000);

        storage.set_account(addr, account);

        let retrieved = storage.get_account(addr);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().balance(), 42_000);
    }

    #[test]
    fn delete_account_removes_from_storage() {
        let key = PrivateKey::new();
        let addr = key.public_key().address();
        let account = Account::new(100);

        let storage = create_storage(&[(addr, account)]);
        assert!(storage.get_account(addr).is_some());

        storage.delete_account(addr);
        assert!(storage.get_account(addr).is_none());
    }

    #[test]
    fn update_account_changes_state_root() {
        let storage = create_storage(&[]);
        let root_before = storage.state_root();

        let key = PrivateKey::new();
        let addr = key.public_key().address();
        storage.set_account(addr, Account::new(100));

        let root_after = storage.state_root();
        assert_ne!(root_before, root_after);
    }

    // ==================== StateStore Tests ====================

    #[test]
    fn preview_root_does_not_modify_state() {
        let storage = create_storage(&[]);
        let root_before = storage.state_root();

        let key = Hash::sha3().chain(b"preview_key").finalize();
        let writes = vec![(key, Some(vec![1, 2, 3]))];

        let preview = storage.preview_root(&writes);
        assert_ne!(preview, root_before);

        // State should be unchanged
        assert_eq!(storage.state_root(), root_before);
        assert!(storage.get(key).is_none());
    }

    #[test]
    fn preview_root_matches_apply_batch_result() {
        let storage = create_storage(&[]);

        let key = Hash::sha3().chain(b"test_key").finalize();
        let writes = vec![(key, Some(vec![4, 5, 6]))];

        let preview = storage.preview_root(&writes);
        storage.apply_batch(writes);

        assert_eq!(storage.state_root(), preview);
    }

    #[test]
    fn preview_root_handles_deletions() {
        let key = PrivateKey::new();
        let addr = key.public_key().address();
        let account = Account::new(1000);

        let storage = create_storage(&[(addr, account)]);
        let root_with_account = storage.state_root();

        let preview = storage.preview_root(&[(addr, None)]);
        assert_ne!(preview, root_with_account);
    }

    #[test]
    fn apply_batch_multiple_writes() {
        let storage = create_storage(&[]);

        let key1 = Hash::sha3().chain(b"key1").finalize();
        let key2 = Hash::sha3().chain(b"key2").finalize();
        let writes = vec![(key1, Some(vec![1, 2, 3])), (key2, Some(vec![4, 5, 6]))];

        storage.apply_batch(writes);

        assert_eq!(storage.get(key1), Some(vec![1, 2, 3]));
        assert_eq!(storage.get(key2), Some(vec![4, 5, 6]));
    }

    // ==================== VmStorage Tests ====================

    #[test]
    fn contains_key_returns_false_for_missing() {
        let storage = create_storage(&[]);
        let key = Hash::sha3().chain(b"missing").finalize();
        assert!(!storage.contains_key(key));
    }

    #[test]
    fn contains_key_returns_true_after_write() {
        let storage = create_storage(&[]);
        let key = Hash::sha3().chain(b"exists").finalize();

        storage.apply_batch(vec![(key, Some(vec![1]))]);
        assert!(storage.contains_key(key));
    }

    #[test]
    fn get_returns_none_for_missing_key() {
        let storage = create_storage(&[]);
        let key = Hash::sha3().chain(b"missing").finalize();
        assert!(storage.get(key).is_none());
    }

    // ==================== Append Block Tests ====================

    #[test]
    fn append_block_updates_tip() {
        let validator_key = PrivateKey::new();
        let validator_addr = validator_key.public_key().address();
        let validator_account = Account::new(0);

        let storage = create_storage(&[(validator_addr, validator_account)]);
        let genesis_tip = storage.tip();

        let header = Header {
            version: 1,
            height: 1,
            timestamp: 1000,
            gas_used: 0,
            previous_block: genesis_tip,
            merkle_root: MerkleTree::from_transactions(&[], TEST_CHAIN_ID),
            state_root: storage.state_root(),
        };
        let block = Block::new(header, validator_key, vec![], TEST_CHAIN_ID);

        storage.append_block(block.clone(), TEST_CHAIN_ID).unwrap();

        assert_eq!(storage.tip(), block.header_hash(TEST_CHAIN_ID));
        assert_eq!(storage.height(), 1);
    }

    #[test]
    fn append_block_rejects_wrong_parent() {
        let storage = create_storage(&[]);

        let wrong_parent = Hash::sha3().chain(b"wrong").finalize();
        let header = Header {
            version: 1,
            height: 1,
            timestamp: 1000,
            gas_used: 0,
            previous_block: wrong_parent,
            merkle_root: Hash::zero(),
            state_root: storage.state_root(),
        };
        let block = Block::new(header, PrivateKey::new(), vec![], TEST_CHAIN_ID);

        let result = storage.append_block(block, TEST_CHAIN_ID);
        assert!(matches!(result, Err(StorageError::NotOnTip { .. })));
    }

    // ==================== Reset Tests ====================

    #[test]
    fn reset_clears_and_reinitializes() {
        let key = PrivateKey::new();
        let addr = key.public_key().address();
        let account = Account::new(1000);

        let storage = create_storage(&[(addr, account.clone())]);

        // Add another account
        let key2 = PrivateKey::new();
        let addr2 = key2.public_key().address();
        storage.set_account(addr2, Account::new(500));

        // Reset with different initial accounts
        let new_key = PrivateKey::new();
        let new_addr = new_key.public_key().address();
        let new_account = Account::new(2000);
        let new_initial = [(new_addr, new_account)];

        let new_genesis = genesis_block(&new_initial);
        storage
            .reset(new_genesis, TEST_CHAIN_ID, &new_initial)
            .unwrap();

        // Old account should be gone, new account should exist
        assert!(storage.get_account(addr2).is_none());
        assert!(storage.get_account(new_addr).is_some());
        assert_eq!(storage.height(), 0);
    }

    // ==================== Header-Only Storage Tests ====================

    #[test]
    fn store_header_only_stores_header_not_block() {
        let storage = create_storage(&[]);
        let genesis_tip = storage.tip();

        let header = Header {
            version: 1,
            height: 1,
            timestamp: 1000,
            gas_used: BLOCK_GAS_LIMIT,
            previous_block: genesis_tip,
            merkle_root: Hash::zero(),
            state_root: Hash::zero(),
        };
        let hash = header.header_hash(TEST_CHAIN_ID);

        storage.store_header_only(&header, hash).unwrap();

        // Header should exist
        assert!(storage.get_header(hash).is_some());
        // But full block should not (has_block checks CF_BLOCKS)
        assert!(!storage.has_block(hash));
    }

    #[test]
    fn store_headers_batch() {
        let storage = create_storage(&[]);
        let genesis_tip = storage.tip();

        let header1 = Header {
            version: 1,
            height: 1,
            timestamp: 1000,
            gas_used: BLOCK_GAS_LIMIT,
            previous_block: genesis_tip,
            merkle_root: Hash::zero(),
            state_root: Hash::zero(),
        };
        let hash1 = header1.header_hash(TEST_CHAIN_ID);

        let header2 = Header {
            version: 1,
            height: 2,
            timestamp: 2000,
            gas_used: BLOCK_GAS_LIMIT,
            previous_block: hash1,
            merkle_root: Hash::zero(),
            state_root: Hash::zero(),
        };

        storage
            .store_headers(&[header1.clone(), header2.clone()], TEST_CHAIN_ID)
            .unwrap();

        assert!(storage.get_header(hash1).is_some());
        assert_eq!(storage.header_height(), 2);
    }

    #[test]
    fn get_header_by_height_returns_correct_header() {
        let storage = create_storage(&[]);

        // Genesis is at height 0
        let genesis_header = storage.get_header_by_height(0);
        assert!(genesis_header.is_some());
        assert_eq!(genesis_header.unwrap().height, 0);
    }

    #[test]
    fn has_header_at_height() {
        let storage = create_storage(&[]);

        assert!(storage.has_header_at_height(0)); // Genesis
        assert!(!storage.has_header_at_height(1)); // Not yet stored
    }

    // ==================== Snapshot Tests ====================

    #[test]
    fn snapshot_heights_initially_empty() {
        let storage = create_storage(&[]);
        let heights = storage.snapshot_heights().unwrap();
        assert!(heights.is_empty());
    }

    #[test]
    fn snapshot_tip_returns_none_for_missing_snapshot() {
        let storage = create_storage(&[]);
        let tip = storage.snapshot_tip(100).unwrap();
        assert!(tip.is_none());
    }

    // ==================== StateView Tests ====================

    #[test]
    fn state_view_provides_read_access() {
        let key = PrivateKey::new();
        let addr = key.public_key().address();
        let account = Account::new(5000);

        let storage = create_storage(&[(addr, account)]);
        let view = storage.state_view();

        // Can read through view
        assert!(view.get(addr).is_some());
    }

    // ==================== Persistence & Snapshot Tests ====================

    fn append_empty_block(storage: &RocksDbStorage, height: u64, previous: Hash) -> Hash {
        let header = Header {
            version: 1,
            height,
            timestamp: 0,
            gas_used: 0,
            previous_block: previous,
            merkle_root: Hash::zero(),
            state_root: storage.state_root(),
        };
        let block = Block::new(header, PrivateKey::new(), vec![], TEST_CHAIN_ID);
        let hash = block.header_hash(TEST_CHAIN_ID);
        storage
            .append_block(block, TEST_CHAIN_ID)
            .expect("append_block failed");
        hash
    }

    #[test]
    fn reopen_existing_storage_rebuilds_state_and_tip() {
        let (db, path) = test_db_with_path();

        let key1 = PrivateKey::new();
        let addr1 = key1.public_key().address();
        let account1 = Account::new(100);
        let initial = [(addr1, account1.clone())];
        let genesis = genesis_block(&initial);

        let storage =
            RocksDbStorage::new(db.clone(), genesis.clone(), TEST_CHAIN_ID, &initial).unwrap();

        let key2 = PrivateKey::new();
        let addr2 = key2.public_key().address();
        let account2 = Account::new(55);
        storage.set_account(addr2, account2.clone());

        let tip_before = append_empty_block(&storage, 1, storage.tip());
        let root_before = storage.state_root();

        drop(storage);
        drop(db);

        let db2 = open_db(&path);
        let storage2 = RocksDbStorage::new(db2, genesis, TEST_CHAIN_ID, &initial).unwrap();

        assert_eq!(storage2.tip(), tip_before);
        assert_eq!(storage2.state_root(), root_before);
        assert_eq!(storage2.height(), 1);
        let retrieved = storage2.get_account(addr2).expect("account should persist");
        assert_eq!(retrieved.balance(), 55);
    }

    #[test]
    fn import_snapshot_replaces_state_and_exports() {
        let storage = create_storage(&[]);

        let key = PrivateKey::new();
        let addr = key.public_key().address();
        let account = Account::new(777);

        let mut state = Smt::new(H256::zero(), DefaultStore::default());
        state
            .update(hash_to_h256(&addr), SmtValue(account.to_vec()))
            .expect("SMT update failed");
        let state_root = h256_to_hash(state.root());

        let header = Header {
            version: 1,
            height: 5,
            timestamp: 0,
            gas_used: 0,
            previous_block: Hash::zero(),
            merkle_root: Hash::zero(),
            state_root,
        };
        let block = Block::new(header, PrivateKey::new(), vec![], TEST_CHAIN_ID);
        let entries = vec![(addr, account.to_vec())];

        storage
            .import_snapshot(5, block.clone(), entries.clone(), TEST_CHAIN_ID)
            .expect("import_snapshot failed");

        assert_eq!(storage.height(), 5);
        assert_eq!(storage.tip(), block.header_hash(TEST_CHAIN_ID));
        let retrieved = storage
            .get_account(addr)
            .expect("account should be restored");
        assert_eq!(retrieved.balance(), 777);

        let heights = storage.snapshot_heights().unwrap();
        assert_eq!(heights, vec![5]);
        assert_eq!(
            storage.snapshot_tip(5).unwrap(),
            Some(block.header_hash(TEST_CHAIN_ID))
        );

        let exported = storage.export_snapshot(5).unwrap();
        let exported_entry = exported
            .iter()
            .find(|(k, _)| *k == addr)
            .expect("exported entry missing");
        assert_eq!(exported_entry.1, account.to_vec());
    }

    #[test]
    fn reset_to_snapshot_removes_newer_state_and_blocks() {
        let key = PrivateKey::new();
        let addr_a = key.public_key().address();
        let storage = create_storage(&[(addr_a, Account::new(100))]);

        let mut prev = storage.tip();
        let mut hash_at_10 = Hash::zero();
        for height in 1..=10 {
            prev = append_empty_block(&storage, height, prev);
            if height == 10 {
                hash_at_10 = prev;
            }
        }

        assert!(storage.snapshot_heights().unwrap().contains(&10));

        let key_b = PrivateKey::new();
        let addr_b = key_b.public_key().address();
        storage.set_account(addr_b, Account::new(55));
        let hash_at_11 = append_empty_block(&storage, 11, prev);

        assert!(storage.get_account(addr_b).is_some());

        storage
            .reset_to_snapshot(10)
            .expect("reset_to_snapshot failed");

        assert_eq!(storage.height(), 10);
        assert_eq!(storage.tip(), hash_at_10);
        assert!(storage.get_account(addr_b).is_none());
        assert!(!storage.has_block(hash_at_11));
    }

    #[test]
    fn snapshots_retained_and_block_bodies_pruned() {
        let key = PrivateKey::new();
        let addr = key.public_key().address();
        let storage = create_storage(&[(addr, Account::new(1))]);

        let mut prev = storage.tip();
        let mut hash_height1 = Hash::zero();
        let mut hash_height20 = Hash::zero();
        let mut hash_height30 = Hash::zero();

        for height in 1..=31 {
            prev = append_empty_block(&storage, height, prev);
            if height == 1 {
                hash_height1 = prev;
            }
            if height == 20 {
                hash_height20 = prev;
            }
            if height == 30 {
                hash_height30 = prev;
            }
        }

        let heights = storage.snapshot_heights().unwrap();
        assert_eq!(heights, vec![20, 30]);
        assert_eq!(storage.snapshot_tip(20).unwrap(), Some(hash_height20));
        assert_eq!(storage.snapshot_tip(30).unwrap(), Some(hash_height30));

        // Block body at height 1 should be pruned, header should remain.
        assert!(!storage.has_block(hash_height1));
        assert!(storage.get_header(hash_height1).is_some());
    }
}
