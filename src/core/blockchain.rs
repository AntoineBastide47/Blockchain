//! Core blockchain data structure and block management.

use crate::core::account::Account;
use crate::core::block::{Block, Header};
use crate::core::consensus::{
    ClaimUnbondedTxData, ConsensusState, SlashingEvidenceTxData, StakeTxData, UnstakeTxData,
    ValidatorRecord, ValidatorSetSnapshot, consensus_state_key, default_staking_params,
    next_randomness_seed, select_leader, slashing_evidence_seen_key, validator_record_key,
    validator_set_key,
};
use crate::core::receipt::Receipt;
use crate::core::transaction::{Transaction, TransactionType};
use crate::core::validator::{BLOCK_MAX_BYTES, BlockValidator, BlockValidatorError, Validator};
use crate::crypto::key_pair::{Address, PrivateKey};
use crate::network::server::BLOCK_TIME;
use crate::storage::rocksdb_storage::RocksDbStorage;
use crate::storage::state_store::{AccountStorage, StateStore, VmStorage};
use crate::storage::state_view::StateViewProvider;
use crate::storage::storage_trait::{Storage, StorageError};
use crate::storage::txpool::TxPool;
use crate::types::bytes::Bytes;
use crate::types::encoding::{Decode, Encode};
use crate::types::hash::Hash;
use crate::types::merkle_tree::MerkleTree;
use crate::virtual_machine::errors::VMError;
use crate::virtual_machine::program::{DeployProgram, ExecuteProgram};
use crate::virtual_machine::state::{OverlayState, State, TxAccountChanges};
use crate::virtual_machine::vm::{BLOCK_GAS_LIMIT, ExecContext, VM};
use crate::{info, warn};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// Maximum allowable clock drift for incoming blocks.
///
/// Blocks with timestamps further in the future than this threshold are rejected
/// to prevent time manipulation attacks.
const MAX_BLOCK_TIME_DRIFT: u64 = 3 * BLOCK_TIME.as_secs();

/// Base reward coefficient for validator block rewards (in smallest currency unit).
///
/// Combined with the square root of total stake to compute per-block rewards,
/// incentivizing validators proportionally to their stake.
const BASE_REWARD: u128 = 64_000_000_000;

/// Combined storage trait for blockchain operations.
///
/// Bundles all storage capabilities required by the blockchain: block persistence,
/// VM state access, account management, and state view creation.
pub trait StorageTrait: Storage + VmStorage + AccountStorage + StateViewProvider {}
impl<T> StorageTrait for T where T: Storage + VmStorage + AccountStorage + StateViewProvider {}

/// The main blockchain structure holding headers and validation logic.
///
/// Generic over validator and storage types for zero-cost abstraction.
pub struct Blockchain<V: Validator, S: StorageTrait> {
    /// Chain identifier.
    pub id: u64,
    /// Block validator for consensus rules.
    validator: V,
    /// Block storage backend.
    storage: S,
}

impl Blockchain<BlockValidator, RocksDbStorage> {
    /// Creates a new blockchain with default validator and RocksDB storage.
    ///
    /// The `id` parameter is the chain identifier used for transaction signing
    /// and verification, preventing replay attacks across different chains.
    pub fn new(
        id: u64,
        db: Arc<rocksdb::DB>,
        genesis: Block,
        initial_accounts: &[(Address, Account)],
    ) -> Result<Self, StorageError> {
        info!(
            "Initializing blockchain with genesis block: height={} hash={} transactions={}",
            genesis.header.height,
            genesis.header_hash(id),
            genesis.transactions.len()
        );

        Ok(Self {
            id,
            storage: RocksDbStorage::new(db, genesis, id, initial_accounts)?,
            validator: BlockValidator,
        })
    }

    /// Resets storage to the given genesis block and initial accounts.
    pub fn reset_to_genesis(
        &self,
        genesis: Block,
        initial_accounts: &[(Address, Account)],
    ) -> Result<(), StorageError> {
        self.storage.reset(genesis, self.id, initial_accounts)
    }

    /// Returns available snapshot heights (ascending).
    pub fn snapshot_heights(&self) -> Result<Vec<u64>, StorageError> {
        self.storage.snapshot_heights()
    }

    /// Returns the tip hash recorded for a snapshot at the given height.
    pub fn snapshot_tip(&self, height: u64) -> Result<Option<Hash>, StorageError> {
        self.storage.snapshot_tip(height)
    }

    /// Resets chain state to the snapshot at the given height.
    pub fn reset_to_snapshot(&self, height: u64) -> Result<(), StorageError> {
        self.storage.reset_to_snapshot(height)
    }

    /// Exports all state entries from the snapshot at the given height.
    ///
    /// Returns a vector of (key, value) pairs for state sync.
    pub fn export_snapshot(&self, height: u64) -> Result<Vec<(Hash, Vec<u8>)>, StorageError> {
        self.storage.export_snapshot(height)
    }

    /// Imports a snapshot received from a peer.
    ///
    /// Replaces current state with the snapshot state and sets the tip to the snapshot block.
    pub fn import_snapshot(
        &self,
        height: u64,
        block: Block,
        entries: Vec<(Hash, Vec<u8>)>,
    ) -> Result<(), StorageError> {
        self.storage
            .import_snapshot(height, block, entries, self.id)
    }

    /// Initializes consensus state from genesis allocations if it is not yet present.
    ///
    /// This is idempotent and only writes state keys when they are missing.
    #[allow(dead_code)]
    fn initialize_consensus_from_genesis_accounts(&self, initial_accounts: &[(Address, Account)]) {
        if self.storage.get(consensus_state_key()).is_some()
            && self.storage.get(validator_set_key()).is_some()
        {
            return;
        }

        let params = default_staking_params();
        let mut writes: Vec<(Hash, Option<Vec<u8>>)> = Vec::new();

        let mut validator_set = ValidatorSetSnapshot::empty();
        for (address, account) in initial_accounts {
            // Bootstrap active stake from genesis balances above the minimum threshold.
            if account.balance() < params.min_stake {
                continue;
            }

            let mut record = ValidatorRecord::new(*address);
            record.active_stake = account.balance();
            validator_set.tracked_validators.push(*address);
            validator_set
                .validators
                .push(crate::core::consensus::ActiveValidatorEntry {
                    address: *address,
                    stake: record.active_stake,
                });

            writes.push((validator_record_key(*address), Some(record.to_vec())));
        }
        validator_set.normalize();

        let consensus_state = ConsensusState {
            last_processed_height: 0,
            total_active_stake: validator_set.total_active_stake,
            randomness_seed: self.storage.tip(),
        };

        writes.push((validator_set_key(), Some(validator_set.to_vec())));
        writes.push((consensus_state_key(), Some(consensus_state.to_vec())));
        self.storage.apply_batch(writes);
    }

    /// Returns the height of the highest header we have stored.
    ///
    /// This may be higher than `height()` during header-first sync.
    pub fn header_height(&self) -> u64 {
        self.storage.header_height()
    }

    /// Returns the header at the given height, if it exists.
    pub fn get_header_by_height(&self, height: u64) -> Option<Header> {
        self.storage.get_header_by_height(height)
    }

    /// Returns the height of the best known header tip (header DAG best-tip view).
    pub fn best_header_height(&self) -> u64 {
        self.storage.header_height()
    }

    /// Stores multiple headers and validates the chain.
    ///
    /// Used during header-first sync to store headers before downloading blocks.
    pub fn store_headers(&self, headers: &[Header]) -> Result<(), StorageError> {
        self.storage.store_headers(headers, self.id)
    }

    /// Returns the best known header tip hash (header DAG tip), falling back to canonical tip.
    pub fn best_header_tip(&self) -> Hash {
        self.storage
            .header_tip()
            .unwrap_or_else(|| self.storage.tip())
    }

    /// Returns the canonical block hash at `height`, if available.
    pub fn canonical_hash_at_height(&self, height: u64) -> Option<Hash> {
        self.storage.canonical_hash_at_height(height)
    }

    /// Returns the finalized height under a depth-based finality heuristic.
    pub fn finalized_height_at_depth(&self, finality_depth: u64) -> u64 {
        self.height().saturating_sub(finality_depth)
    }

    /// Returns the finalized tip hash under a depth-based finality heuristic.
    pub fn finalized_tip_at_depth(&self, finality_depth: u64) -> Hash {
        let finalized_height = self.finalized_height_at_depth(finality_depth);
        self.get_header_by_height(finalized_height)
            .map(|h| h.header_hash(self.id))
            .unwrap_or_else(|| self.storage.tip())
    }

    /// Returns receipts for a canonical-applied block hash, if present.
    ///
    /// Receipt semantics (v1):
    /// - Receipts are stored for canonical executed blocks only.
    /// - Reorg disconnects delete receipts for blocks leaving the canonical chain.
    /// - Reset/snapshot replay may prune or rebuild canonical receipts alongside blocks.
    pub fn get_receipts(&self, block_hash: Hash) -> Option<Vec<Receipt>> {
        self.storage.get_receipts(block_hash)
    }

    /// Finds the lowest common ancestor of two known headers in the header DAG.
    pub fn find_header_lca(&self, a: Hash, b: Hash) -> Result<Option<Hash>, StorageError> {
        self.storage.find_lca(a, b)
    }

    /// Rolls back the canonical chain tip to `target_tip` using persisted undo records.
    ///
    /// This is a conservative helper used by sync catchup before replaying a better header branch.
    pub fn rollback_canonical_to(&self, target_tip: Hash) -> Result<(), StorageError> {
        if self.storage_tip() == target_tip {
            return Ok(());
        }
        if self.get_header(target_tip).is_none() {
            return Err(StorageError::ValidationFailed(format!(
                "rollback target header not found: {target_tip}"
            )));
        }

        while self.storage_tip() != target_tip {
            let current = self.storage_tip();
            self.storage.apply_reorg_disconnect(current)?;
        }
        Ok(())
    }

    /// Ingests a block body into the canonical execution path during sync/catchup.
    ///
    /// Currently this is a thin wrapper over `apply_block` that treats already-stored bodies as a
    /// no-op and preserves all block/receipt validation (including `receipt_root` checks).
    pub fn ingest_block(&self, block: Block) -> Result<(), StorageError> {
        let hash = block.header_hash(self.id);
        if self.has_block(hash) {
            return Ok(());
        }
        self.apply_block(block)
    }

    /// Resets to the nearest snapshot and replays stored block bodies forward.
    ///
    /// Reads all needed block bodies into memory before resetting state, since
    /// `reset_to_snapshot` deletes both headers and block bodies above the snapshot
    /// height. Returns the height reached after replay. Stops early if a block body
    /// was pruned or replay fails.
    pub fn replay_from_last_snapshot(&self) -> Result<u64, StorageError> {
        let old_height = self.storage.height();
        let snapshots = self.storage.snapshot_heights()?;

        // Find the highest snapshot at or below the current height.
        let snap_height = snapshots
            .into_iter()
            .rev()
            .find(|&h| h <= old_height)
            .ok_or_else(|| {
                StorageError::ValidationFailed("no snapshot available for replay".into())
            })?;

        if snap_height >= old_height {
            // Already at or behind the snapshot; nothing to replay.
            self.storage.reset_to_snapshot(snap_height)?;
            return Ok(snap_height);
        }

        // Read block bodies into memory *before* the reset deletes them.
        let blocks = self
            .storage
            .get_blocks_in_range(snap_height + 1, old_height);

        self.storage.reset_to_snapshot(snap_height)?;

        let mut reached = snap_height;
        for (i, maybe_block) in blocks.into_iter().enumerate() {
            let Some(block) = maybe_block else {
                // Block body was pruned; stop here.
                warn!(
                    "replay stopped at height {}: block body pruned",
                    snap_height + 1 + i as u64
                );
                break;
            };
            if let Err(e) = self.apply_block(block) {
                warn!(
                    "replay failed at height {}: {e}",
                    snap_height + 1 + i as u64
                );
                break;
            }
            reached = snap_height + 1 + i as u64;
        }

        Ok(reached)
    }
}

impl<V: Validator, S: StorageTrait> Blockchain<V, S> {
    /// Returns the height of the chain.
    pub fn height(&self) -> u64 {
        self.storage.height()
    }

    /// Returns the hash of the current chain tip block.
    pub fn storage_tip(&self) -> Hash {
        self.storage.tip()
    }

    /// Returns true if a block with the given hash exists.
    pub fn has_block(&self, hash: Hash) -> bool {
        self.storage.has_block(hash)
    }

    /// Returns the block with the given hash, if it exists.
    pub fn get_block(&self, hash: Hash) -> Option<Arc<Block>> {
        self.storage.get_block(hash)
    }

    /// Returns the header with the given hash, if it exists.
    pub fn get_header(&self, hash: Hash) -> Option<Header> {
        self.storage.get_header(hash)
    }

    /// Returns the current state root from storage.
    pub fn state_root(&self) -> Hash {
        self.storage.state_root()
    }

    pub fn get_account(&self, address: Address) -> Option<Account> {
        self.storage.get_account(address)
    }

    /// Loads the consensus state from persistent storage, defaulting if absent.
    fn load_consensus_state(&self) -> Result<ConsensusState, StorageError> {
        match self.storage.get(consensus_state_key()) {
            Some(bytes) => ConsensusState::decode(&mut bytes.as_slice())
                .map_err(|e| StorageError::DecodeError(e.to_string())),
            None => Ok(ConsensusState::default()),
        }
    }

    /// Loads the active validator set snapshot from persistent storage.
    fn load_validator_set(&self) -> Result<ValidatorSetSnapshot, StorageError> {
        match self.storage.get(validator_set_key()) {
            Some(bytes) => ValidatorSetSnapshot::decode(&mut bytes.as_slice())
                .map_err(|e| StorageError::DecodeError(e.to_string())),
            None => Ok(ValidatorSetSnapshot::empty()),
        }
    }

    /// Loads a validator record from persistent storage, returning an empty record if absent.
    fn load_validator_record(&self, address: Address) -> Result<ValidatorRecord, StorageError> {
        let key = validator_record_key(address);
        match self.storage.get(key) {
            Some(bytes) => ValidatorRecord::decode(&mut bytes.as_slice())
                .map_err(|e| StorageError::DecodeError(e.to_string())),
            None => Ok(ValidatorRecord::new(address)),
        }
    }

    /// Loads the consensus state from the overlay if present, otherwise falls back to storage.
    fn load_consensus_state_overlay<T: State>(
        &self,
        overlay: &OverlayState<T>,
    ) -> Result<ConsensusState, StorageError> {
        match overlay.get(consensus_state_key()) {
            Some(bytes) => ConsensusState::decode(&mut bytes.as_slice())
                .map_err(|e| StorageError::DecodeError(e.to_string())),
            None => self.load_consensus_state(),
        }
    }

    /// Loads the validator set snapshot from the overlay if present, otherwise from storage.
    fn load_validator_set_overlay<T: State>(
        &self,
        overlay: &OverlayState<T>,
    ) -> Result<ValidatorSetSnapshot, StorageError> {
        match overlay.get(validator_set_key()) {
            Some(bytes) => ValidatorSetSnapshot::decode(&mut bytes.as_slice())
                .map_err(|e| StorageError::DecodeError(e.to_string())),
            None => self.load_validator_set(),
        }
    }

    /// Loads a validator record from the overlay if present, otherwise from storage.
    fn load_validator_record_overlay<T: State>(
        &self,
        address: Address,
        overlay: &OverlayState<T>,
    ) -> Result<ValidatorRecord, StorageError> {
        let key = validator_record_key(address);
        match overlay.get(key) {
            Some(bytes) => ValidatorRecord::decode(&mut bytes.as_slice())
                .map_err(|e| StorageError::DecodeError(e.to_string())),
            None => self.load_validator_record(address),
        }
    }

    /// Stores consensus state into the given overlay.
    fn store_consensus_state_overlay<T: State>(
        &self,
        overlay: &mut OverlayState<T>,
        state: &ConsensusState,
    ) {
        overlay.push(consensus_state_key(), state.to_vec());
    }

    /// Stores validator set snapshot into the given overlay.
    fn store_validator_set_overlay<T: State>(
        &self,
        overlay: &mut OverlayState<T>,
        set: &ValidatorSetSnapshot,
    ) {
        overlay.push(validator_set_key(), set.to_vec());
    }

    /// Stores validator record into the given overlay.
    fn store_validator_record_overlay<T: State>(
        &self,
        overlay: &mut OverlayState<T>,
        record: &ValidatorRecord,
    ) {
        overlay.push(validator_record_key(record.address), record.to_vec());
    }

    /// Returns true when explicit consensus state has been initialized.
    fn has_initialized_consensus<T: State>(&self, overlay: &OverlayState<T>) -> bool {
        overlay.contains_key(consensus_state_key())
            || self.storage.contains_key(consensus_state_key())
    }

    /// Updates or inserts a validator's active stake in the validator set snapshot.
    fn upsert_validator_stake(
        set: &mut ValidatorSetSnapshot,
        address: Address,
        new_active_stake: u128,
    ) {
        if !set.tracked_validators.contains(&address) {
            set.tracked_validators.push(address);
        }

        if let Some(entry) = set.validators.iter_mut().find(|v| v.address == address) {
            entry.stake = new_active_stake;
        } else if new_active_stake > 0 {
            set.validators
                .push(crate::core::consensus::ActiveValidatorEntry {
                    address,
                    stake: new_active_stake,
                });
        }
        set.normalize();
    }

    /// Applies scheduled stake activations and unbonding transitions for the block height.
    fn process_scheduled_staking_transitions<T: State>(
        &self,
        block_height: u64,
        overlay: &mut OverlayState<T>,
    ) -> Result<(ConsensusState, ValidatorSetSnapshot), StorageError> {
        let mut state = self.load_consensus_state_overlay(overlay)?;
        let mut set = self.load_validator_set_overlay(overlay)?;

        if state.last_processed_height >= block_height {
            return Ok((state, set));
        }

        let tracked = set.tracked_validators.clone();
        for address in tracked {
            let mut record = self.load_validator_record_overlay(address, overlay)?;

            let mut activated_total = 0u128;
            let mut remaining_activations = Vec::with_capacity(record.pending_activations.len());
            for pending in record.pending_activations.drain(..) {
                if pending.activate_height <= block_height {
                    activated_total = activated_total.saturating_add(pending.amount);
                } else {
                    remaining_activations.push(pending);
                }
            }
            record.pending_activations = remaining_activations;
            if activated_total > 0 {
                record.active_stake = record.active_stake.saturating_add(activated_total);
            }

            Self::upsert_validator_stake(&mut set, address, record.active_stake);
            self.store_validator_record_overlay(overlay, &record);
        }

        set.normalize();
        state.last_processed_height = block_height;
        state.total_active_stake = set.total_active_stake;
        self.store_validator_set_overlay(overlay, &set);
        self.store_consensus_state_overlay(overlay, &state);
        Ok((state, set))
    }

    /// Validates that the expected proposer is selected for the target block height.
    fn validate_selected_proposer<T: State>(
        &self,
        block_height: u64,
        proposer: Address,
        overlay: &mut OverlayState<T>,
    ) -> Result<(ConsensusState, ValidatorSetSnapshot), StorageError> {
        let (state, set) = if self.has_initialized_consensus(overlay) {
            self.process_scheduled_staking_transitions(block_height, overlay)?
        } else {
            (ConsensusState::default(), ValidatorSetSnapshot::empty())
        };

        if set.total_active_stake == 0 || set.validators.is_empty() {
            // Bootstrap grace: allow block production while stake is bonding and no active
            // validators are available yet. Rewards are already zeroed by `validator_reward`.
            return Ok((state, set));
        }

        let expected = select_leader(block_height, state.randomness_seed, &set)
            .ok_or_else(|| StorageError::ValidationFailed("no leader could be selected".into()))?;
        if expected != proposer {
            return Err(StorageError::ValidationFailed(format!(
                "unexpected proposer for height {}: expected {} got {}",
                block_height, expected, proposer
            )));
        }

        Ok((state, set))
    }

    /// Computes a deterministic contract identifier from a deployment transaction.
    ///
    /// The ID is derived from the sender, nonce, and bytecode, ensuring each
    /// deployment produces a unique address even with identical code.
    pub fn contract_id(transaction: &Transaction) -> Hash {
        let mut h = Hash::sha3();
        h.update(b"SMART_CONTRACT");
        transaction.from.encode(&mut h);
        transaction.nonce.encode(&mut h);
        h.finalize()
    }

    /// Computes a namespaced hash for contract runtime bytecode.
    ///
    /// The `"RUNTIME_CODE"` prefix ensures this hash cannot collide with state
    /// storage keys (prefixed with `"STATE"`) or other hash domains.
    fn code_hash(bytes: &[u8]) -> Hash {
        Hash::sha3().chain(b"RUNTIME_CODE").chain(bytes).finalize()
    }

    /// Computes the base gas cost for a transaction before execution.
    ///
    /// The intrinsic cost includes a fixed base of 21,000 gas units plus a per-byte
    /// charge on the data field that varies by transaction type:
    /// - `TransferFunds`: 0 gas per byte (data ignored)
    /// - `DeployContract`: 200 gas per byte (bytecode storage)
    /// - `InvokeContract`: 20 gas per byte (call data processing)
    /// - Consensus txs (`Stake`, `Unstake`, `ClaimUnbonded`, `SubmitSlashingEvidence`):
    ///   standard per-byte pricing with no extra base surcharge
    pub fn intrinsic_gas_units(tx_type: TransactionType, data: &Bytes) -> u64 {
        let mut gas = 21_000 + ((tx_type == TransactionType::DeployContract) as u64 * 32_000);
        for b in data {
            gas = gas.saturating_add(4 + (*b != 0) as u64 * 12);
        }
        gas
    }

    /// Retrieves an account from the overlay or falls back to persistent storage.
    ///
    /// Checks the overlay first for uncommitted changes, then queries the underlying
    /// storage if not found. Returns an error if the account does not exist in either.
    fn try_get_account_overlay<T: State>(
        &self,
        address: Address,
        overlay: &OverlayState<T>,
    ) -> Result<Account, StorageError> {
        match overlay.get(address) {
            Some(b) => {
                let mut slice: &[u8] = b.as_slice();
                let original_len = slice.len();
                let slice_ref: &mut &[u8] = &mut slice;
                Account::decode(slice_ref).map_err(|e| {
                    warn!(
                        "try_get_account_overlay decode failed for {address}: {e} (len={original_len}, from overlay)"
                    );
                    StorageError::DecodeError(e.to_string())
                })
            }
            None => self
                .storage
                .get_account(address)
                .ok_or(StorageError::MissingAccount(address)),
        }
    }

    /// Applies a stake transaction by locking funds and scheduling activation.
    fn apply_stake_tx<T: State>(
        &self,
        transaction: &Transaction,
        tx_overlay: &mut OverlayState<T>,
        from: (Address, &mut Account),
    ) -> Result<(), StorageError> {
        if transaction.amount != 0 {
            return Err(StorageError::ValidationFailed(
                "stake transaction amount field must be zero (use payload amount)".into(),
            ));
        }

        let payload = StakeTxData::decode(&mut transaction.data.as_slice())
            .map_err(|e| StorageError::DecodeError(e.to_string()))?;
        if payload.amount == 0 {
            return Err(StorageError::ValidationFailed(
                "stake amount must be non-zero".into(),
            ));
        }

        let params = default_staking_params();
        let current_height = self.storage.height().saturating_add(1);
        let mut record = self.load_validator_record_overlay(from.0, tx_overlay)?;
        let total_tracked = record.active_stake.saturating_add(
            record
                .pending_activations
                .iter()
                .fold(0u128, |acc, p| acc.saturating_add(p.amount)),
        );
        if total_tracked == 0 && payload.amount < params.min_stake {
            return Err(StorageError::ValidationFailed(format!(
                "stake amount below minimum: {} < {}",
                payload.amount, params.min_stake
            )));
        }

        from.1.charge(payload.amount)?;
        record
            .pending_activations
            .push(crate::core::consensus::PendingActivation {
                amount: payload.amount,
                activate_height: current_height.saturating_add(params.bonding_period_blocks),
            });

        let mut set = self.load_validator_set_overlay(tx_overlay)?;
        if !set.tracked_validators.contains(&from.0) {
            set.tracked_validators.push(from.0);
            set.normalize();
            self.store_validator_set_overlay(tx_overlay, &set);
        }
        let mut state = self.load_consensus_state_overlay(tx_overlay)?;
        state.total_active_stake = set.total_active_stake;
        self.store_consensus_state_overlay(tx_overlay, &state);
        self.store_validator_record_overlay(tx_overlay, &record);
        Ok(())
    }

    /// Applies an unstake transaction by moving active stake into the unbonding queue.
    fn apply_unstake_tx<T: State>(
        &self,
        transaction: &Transaction,
        tx_overlay: &mut OverlayState<T>,
        from_address: Address,
    ) -> Result<(), StorageError> {
        if transaction.amount != 0 {
            return Err(StorageError::ValidationFailed(
                "unstake transaction amount field must be zero (use payload amount)".into(),
            ));
        }
        let payload = UnstakeTxData::decode(&mut transaction.data.as_slice())
            .map_err(|e| StorageError::DecodeError(e.to_string()))?;
        if payload.amount == 0 {
            return Err(StorageError::ValidationFailed(
                "unstake amount must be non-zero".into(),
            ));
        }

        let params = default_staking_params();
        let current_height = self.storage.height().saturating_add(1);
        let mut record = self.load_validator_record_overlay(from_address, tx_overlay)?;
        if record.active_stake < payload.amount {
            return Err(StorageError::ValidationFailed(format!(
                "insufficient active stake: have {} need {}",
                record.active_stake, payload.amount
            )));
        }

        record.active_stake -= payload.amount;
        record
            .pending_unbonds
            .push(crate::core::consensus::PendingUnbond {
                amount: payload.amount,
                claim_height: current_height.saturating_add(params.unbonding_period_blocks),
            });

        let mut set = self.load_validator_set_overlay(tx_overlay)?;
        Self::upsert_validator_stake(&mut set, from_address, record.active_stake);
        let mut state = self.load_consensus_state_overlay(tx_overlay)?;
        state.total_active_stake = set.total_active_stake;

        self.store_validator_record_overlay(tx_overlay, &record);
        self.store_validator_set_overlay(tx_overlay, &set);
        self.store_consensus_state_overlay(tx_overlay, &state);
        Ok(())
    }

    /// Applies a claim-unbonded transaction by crediting matured unbonded funds.
    fn apply_claim_unbonded_tx<T: State>(
        &self,
        transaction: &Transaction,
        tx_overlay: &mut OverlayState<T>,
        from: (Address, &mut Account),
    ) -> Result<(), StorageError> {
        if transaction.amount != 0 {
            return Err(StorageError::ValidationFailed(
                "claim transaction amount field must be zero (use payload amount)".into(),
            ));
        }
        let payload = ClaimUnbondedTxData::decode(&mut transaction.data.as_slice())
            .map_err(|e| StorageError::DecodeError(e.to_string()))?;

        let current_height = self.storage.height().saturating_add(1);
        let mut record = self.load_validator_record_overlay(from.0, tx_overlay)?;
        let matured_total = record
            .pending_unbonds
            .iter()
            .filter(|p| p.claim_height <= current_height)
            .fold(0u128, |acc, p| acc.saturating_add(p.amount));
        if matured_total == 0 {
            return Err(StorageError::ValidationFailed(
                "no matured unbonded funds to claim".into(),
            ));
        }

        let claim_amount = if payload.amount == 0 {
            matured_total
        } else {
            payload.amount
        };
        if claim_amount > matured_total {
            return Err(StorageError::ValidationFailed(format!(
                "claim amount exceeds matured total: {} > {}",
                claim_amount, matured_total
            )));
        }

        let mut remaining = claim_amount;
        let mut next_unbonds = Vec::with_capacity(record.pending_unbonds.len());
        for mut pending in record.pending_unbonds.drain(..) {
            if pending.claim_height > current_height || remaining == 0 {
                next_unbonds.push(pending);
                continue;
            }

            let take = pending.amount.min(remaining);
            pending.amount -= take;
            remaining -= take;
            if pending.amount > 0 {
                next_unbonds.push(pending);
            }
        }
        if remaining != 0 {
            return Err(StorageError::ValidationFailed(
                "internal error while claiming unbonded funds".into(),
            ));
        }

        record.pending_unbonds = next_unbonds;
        from.1.credit(claim_amount)?;
        self.store_validator_record_overlay(tx_overlay, &record);
        Ok(())
    }

    /// Applies slashing evidence against a double-signed validator.
    fn apply_slashing_evidence_tx<T: State>(
        &self,
        transaction: &Transaction,
        tx_overlay: &mut OverlayState<T>,
    ) -> Result<(), StorageError> {
        if transaction.amount != 0 {
            return Err(StorageError::ValidationFailed(
                "slashing evidence transaction amount field must be zero".into(),
            ));
        }

        let payload = SlashingEvidenceTxData::decode(&mut transaction.data.as_slice())
            .map_err(|e| StorageError::DecodeError(e.to_string()))?;
        if !payload.evidence.is_valid_double_sign(self.id) {
            return Err(StorageError::ValidationFailed(
                "invalid slashing evidence".into(),
            ));
        }

        let evidence_id = payload.evidence.evidence_id(self.id);
        let seen_key = slashing_evidence_seen_key(evidence_id);
        if tx_overlay
            .get(seen_key)
            .or_else(|| self.storage.get(seen_key))
            .is_some()
        {
            return Err(StorageError::ValidationFailed(
                "slashing evidence already processed".into(),
            ));
        }

        let offender = payload.evidence.first.validator.address();
        let mut record = self.load_validator_record_overlay(offender, tx_overlay)?;
        if record.active_stake == 0 {
            return Err(StorageError::ValidationFailed(
                "validator has no active stake to slash".into(),
            ));
        }

        let params = default_staking_params();
        let mut slash_amount =
            record.active_stake.saturating_mul(params.slash_bps as u128) / 10_000u128;
        if slash_amount == 0 {
            slash_amount = 1.min(record.active_stake);
        }
        record.active_stake = record.active_stake.saturating_sub(slash_amount);
        record.slashed_total = record.slashed_total.saturating_add(slash_amount);

        let mut set = self.load_validator_set_overlay(tx_overlay)?;
        Self::upsert_validator_stake(&mut set, offender, record.active_stake);
        let mut state = self.load_consensus_state_overlay(tx_overlay)?;
        state.total_active_stake = set.total_active_stake;

        self.store_validator_record_overlay(tx_overlay, &record);
        self.store_validator_set_overlay(tx_overlay, &set);
        self.store_consensus_state_overlay(tx_overlay, &state);
        tx_overlay.push(seen_key, vec![1]);
        Ok(())
    }

    /// Executes a transaction based on its type and updates gas usage.
    ///
    /// Handles three transaction types:
    /// - `TransferFunds`: moves native currency between accounts
    /// - `DeployContract`: runs init_code, then persists the contract account and
    ///   runtime bytecode under a namespaced `code_hash` key
    /// - `InvokeContract`: loads stored runtime bytecode and executes
    /// - Staking txs: mutate consensus validator state in VM storage
    fn execute_tx<T: State>(
        &self,
        transaction: &Transaction,
        tx_overlay: &mut OverlayState<T>,
        gas_used: &mut u64,
        from: (Address, &mut Account),
        to: (Address, &mut Account),
    ) -> Result<Vec<u8>, StorageError> {
        match transaction.tx_type {
            TransactionType::TransferFunds => {
                if from.0 == to.0 {
                    return Ok(vec![]);
                }

                from.1.charge(transaction.amount)?;
                to.1.credit(transaction.amount)?;
                Ok(vec![])
            }
            TransactionType::DeployContract => {
                let mut program = DeployProgram::from_bytes(transaction.data.as_slice())?;

                // Compute remaining gas after intrinsic costs
                let max_gas =
                    transaction
                        .gas_limit
                        .checked_sub(*gas_used)
                        .ok_or(VMError::OutOfGas {
                            used: *gas_used,
                            limit: transaction.gas_limit,
                        })?;

                let mut vm = VM::new_deploy(program.clone(), max_gas, vec![], vec![])?;
                let contract_id = Self::contract_id(transaction);
                let ctx = ExecContext {
                    chain_id: self.id,
                    contract_id,
                    caller: transaction.from.address(),
                };

                // Run init_code (may call into runtime_code for setup)
                let result = vm.run(tx_overlay, &ctx);
                *gas_used += vm.gas_used();
                let return_data = vm.return_data();

                match result {
                    Ok(_) => {
                        // Charge sender for amount transferred to contract
                        from.1.charge(transaction.amount)?;

                        // Persist runtime bytecode + const memory under namespaced hash
                        let code_hash = Self::code_hash(&program.runtime_code);
                        program.init_code = vec![];
                        tx_overlay.push(code_hash, program.to_vec());

                        // Create contract account with code_hash reference
                        tx_overlay.push(
                            contract_id,
                            Account::from(
                                0,
                                transaction.amount,
                                code_hash,
                                Account::EMPTY_STORAGE_ROOT,
                            )
                            .to_vec(),
                        );
                        Ok(return_data)
                    }
                    Err(e) => Err(e.into()),
                }
            }
            TransactionType::InvokeContract => {
                let program = ExecuteProgram::from_bytes(transaction.data.as_slice())?;

                // Compute remaining gas after intrinsic costs
                let max_gas =
                    transaction
                        .gas_limit
                        .checked_sub(*gas_used)
                        .ok_or(VMError::OutOfGas {
                            used: *gas_used,
                            limit: transaction.gas_limit,
                        })?;

                let contract_id = program.contract_id;
                let contract = self
                    .storage
                    .get_account(contract_id)
                    .ok_or(StorageError::MissingAccount(contract_id))?;
                let deploy = DeployProgram::decode(
                    &mut self
                        .storage
                        .get(contract.code_hash())
                        .ok_or(StorageError::MissingCode(contract_id))?
                        .as_slice(),
                )?;

                // Decode stored format: max_register + items + runtime_code
                let mut vm = VM::new_execute(program, deploy, max_gas)?;
                let ctx = ExecContext {
                    chain_id: self.id,
                    contract_id,
                    caller: transaction.from.address(),
                };

                // Run runtime_code
                let result = vm.run(tx_overlay, &ctx);
                *gas_used += vm.gas_used();
                let return_data = vm.return_data();
                result?;

                Ok(return_data)
            }
            TransactionType::Stake => {
                self.apply_stake_tx(transaction, tx_overlay, from)?;
                Ok(vec![])
            }
            TransactionType::Unstake => {
                self.apply_unstake_tx(transaction, tx_overlay, from.0)?;
                Ok(vec![])
            }
            TransactionType::ClaimUnbonded => {
                self.apply_claim_unbonded_tx(transaction, tx_overlay, from)?;
                Ok(vec![])
            }
            TransactionType::SubmitSlashingEvidence => {
                self.apply_slashing_evidence_tx(transaction, tx_overlay)?;
                Ok(vec![])
            }
        }
    }

    /// Validates and executes a single transaction into the provided block overlay.
    ///
    /// Runs validator checks (signature, nonce, balance, gas) before decoding the
    /// program bytes and executing them in a per-tx overlay. The per-tx writes are
    /// merged into `block_overlay` only after successful execution.
    fn apply_tx<T: State>(
        &self,
        transaction: &Transaction,
        block_overlay: &OverlayState<T>,
        tx_overlay: &mut OverlayState<OverlayState<T>>,
    ) -> Result<(TxAccountChanges, u64, Vec<u8>), StorageError> {
        if transaction.gas_price == 0 || transaction.gas_limit == 0 {
            return Err(StorageError::InvalidTransactionGasParams);
        }

        // Charge base transaction cost: covers processing + broadcasting
        let intrinsic = Self::intrinsic_gas_units(transaction.tx_type, &transaction.data);
        if transaction.gas_limit < intrinsic {
            return Err(VMError::OutOfGas {
                used: intrinsic,
                limit: transaction.gas_limit,
            }
            .into());
        }

        // Make sure an account exists for the transaction sender and receiver
        let from_hash = transaction.from.address();
        let mut from = self.try_get_account_overlay(from_hash, block_overlay)?;
        let to_hash = match transaction.tx_type {
            TransactionType::Stake
            | TransactionType::Unstake
            | TransactionType::ClaimUnbonded
            | TransactionType::SubmitSlashingEvidence => from_hash,
            _ => transaction.to,
        };
        let mut to = if to_hash == from_hash {
            from.clone()
        } else {
            self.try_get_account_overlay(to_hash, block_overlay)?
        };

        // Make sure the account has enough funds if the gas limit is attained
        let user_total = transaction
            .gas_price
            .checked_mul(transaction.gas_limit as u128)
            .ok_or(StorageError::ArithmeticOverflow {
                gas_used: transaction.gas_limit,
                gas_price: transaction.gas_price,
            })?
            .checked_add(transaction.amount)
            .ok_or(StorageError::ArithmeticOverflow {
                gas_used: transaction.gas_limit,
                gas_price: transaction.gas_price,
            })?;
        if from.balance() < user_total {
            return Err(StorageError::InsufficientBalance {
                actual: from.balance(),
                expected: user_total,
            });
        }

        // Validate the transaction
        self.validator
            .validate_tx(transaction, &from, self.id)
            .map_err(|e| StorageError::ValidationFailed(e.to_string()))?;

        // Execute and compute gas usage
        let mut gas_used: u64 = intrinsic;
        let transaction_result = self.execute_tx(
            transaction,
            tx_overlay,
            &mut gas_used,
            (from_hash, &mut from),
            (to_hash, &mut to),
        );

        // If the transaction failed: charge gas and skip the tx_overlay states
        from.increment_nonce();
        from.charge(
            (transaction.gas_price + transaction.priority_fee)
                .checked_mul(gas_used as u128)
                .ok_or(StorageError::ArithmeticOverflow {
                    gas_used,
                    gas_price: transaction.gas_price + transaction.priority_fee,
                })?,
        )?;

        let return_data = transaction_result?;

        let accounts: TxAccountChanges = if from_hash == to_hash {
            [(from_hash, from.to_vec()), (from_hash, from.to_vec())]
        } else {
            [(from_hash, from.to_vec()), (to_hash, to.to_vec())]
        };
        Ok((accounts, gas_used, return_data))
    }

    /// Appends a block to storage and updates the chain tip (thread-safe).
    ///
    /// Logs an info message to notify the node owner
    fn append_block(&self, block: &Block, receipts: Vec<Receipt>) -> Result<(), StorageError> {
        self.storage
            .append_block(block.clone(), receipts, self.id)?;

        info!(
            "adding a new block to the chain: height={} hash={} transactions={}",
            block.header.height,
            block.header_hash(self.id),
            block.transactions.len()
        );

        Ok(())
    }

    /// Computes the block reward for a validator based on their stake proportion.
    ///
    /// The reward formula scales with the square root of total stake to provide
    /// diminishing returns as network stake grows, while distributing rewards
    /// proportionally to individual validator stakes.
    fn validator_reward(validator_stake: u128, total_active_stake: u128) -> u128 {
        if validator_stake == 0 || total_active_stake == 0 {
            return 0;
        }
        let total = total_active_stake.isqrt() * BASE_REWARD;
        // Divide first to reduce overflow risk, accepting minor precision loss
        total / total_active_stake * validator_stake
            + (total % total_active_stake) * validator_stake / total_active_stake
    }

    /// Builds, executes, and commits a new block linked to the current tip.
    ///
    /// Executes all transactions, computes the state root, signs the block,
    /// commits state changes to storage, and appends the block to the chain.
    pub fn build_block(
        &self,
        validator: PrivateKey,
        tx_pool: &TxPool,
    ) -> Result<Block, StorageError> {
        let parent_tip = self.storage.tip();
        let next_height = self.storage.height().saturating_add(1);
        // Make sure the validator actually exists
        let validator_address = validator.public_key().address();
        let base = self.storage.state_view();
        let mut block_overlay = OverlayState::new(&base);
        let (pre_consensus_state, pre_validator_set) =
            self.validate_selected_proposer(next_height, validator_address, &mut block_overlay)?;
        self.try_get_account_overlay(validator_address, &block_overlay)?;
        let proposer_stake = pre_validator_set.stake_of(validator_address);

        // Executes all transactions in the block and computes the resulting state root.
        let mut gas_left = BLOCK_GAS_LIMIT;
        let mut validator_fee = 0u128;
        let mut size_left = BLOCK_MAX_BYTES;
        let mut cumulative_gas: u64 = 0;

        let mut hashes = Vec::<Hash>::new();
        let mut transactions = Vec::<Transaction>::new();
        let mut receipts = Vec::<Receipt>::new();

        // Take transactions from the pool while the block gas limit is not reached
        while let (Some(tx), size) = tx_pool.take_one(gas_left, size_left) {
            let hash = tx.id(self.id);
            let mut tx_overlay = OverlayState::new(&block_overlay);

            // Try and apply the transaction to the current state
            match self.apply_tx(&tx, &block_overlay, &mut tx_overlay) {
                Ok((accounts, gas_used, return_data)) => {
                    tx_overlay
                        .into_writes()
                        .apply_tx_overlay(accounts, &mut block_overlay);
                    gas_left -= gas_used;
                    size_left -= size;
                    cumulative_gas += gas_used;
                    validator_fee = validator_fee
                        .saturating_add(tx.priority_fee.saturating_mul(gas_used as u128));
                    receipts.push(Receipt {
                        tx_hash: hash,
                        success: true,
                        gas_used,
                        cumulative_gas_used: cumulative_gas,
                        return_data,
                    });
                    hashes.push(hash);
                    transactions.push(tx);
                }
                Err(e) => warn!("tx {hash} failed: {e}"),
            }
        }

        // Reward the validator for creating the block using staking + transaction fees.
        let mut validator_account =
            self.try_get_account_overlay(validator_address, &block_overlay)?;
        let reward = Self::validator_reward(proposer_stake, pre_validator_set.total_active_stake);
        validator_account.credit(reward + validator_fee)?;
        block_overlay.push(validator_address, validator_account.to_vec());

        if self.has_initialized_consensus(&block_overlay) {
            let mut state = self.load_consensus_state_overlay(&block_overlay)?;
            let set = self.load_validator_set_overlay(&block_overlay)?;
            state.total_active_stake = set.total_active_stake;
            state.randomness_seed =
                next_randomness_seed(pre_consensus_state.randomness_seed, parent_tip);
            self.store_consensus_state_overlay(&mut block_overlay, &state);
        }

        // Apply the block state changes to the chain
        self.storage.apply_batch(block_overlay.into_writes().0);
        tx_pool.remove_batch(&hashes);

        let receipt_root = MerkleTree::from_raw(receipts.iter().map(|r| r.hash()).collect());

        let header = Header {
            version: 1,
            height: next_height,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0),
            gas_used: BLOCK_GAS_LIMIT - gas_left,
            previous_block: parent_tip,
            merkle_root: MerkleTree::from_transactions(&transactions, self.id),
            state_root: self.storage.state_root(),
            receipt_root,
        };

        let block = Block::new(header, validator, transactions, self.id);
        self.append_block(&block, receipts)?;
        Ok(block)
    }

    /// Validates and applies an entire block to the chain state.
    ///
    /// Performs block-level validation, executes each transaction into a block
    /// overlay (after per-tx validation), checks the resulting state_root, then
    /// commits the writes and appends the block.
    pub fn apply_block(&self, block: Block) -> Result<(), StorageError> {
        // Make sure new blocks don't drift too far in the future in date creation
        if block.header_hash(self.id) == self.storage.tip() {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();

            let max = now + MAX_BLOCK_TIME_DRIFT;
            if block.header.timestamp > max {
                return Err(StorageError::ValidationFailed(
                    BlockValidatorError::TimestampTooFarInFuture {
                        now,
                        max_allowed: max,
                        block: block.header.timestamp,
                    }
                    .to_string(),
                ));
            }
        }

        let hash = block.header_hash(self.id);
        if self.storage.has_block(hash) {
            return Err(StorageError::ValidationFailed(
                "block already exists".into(),
            ));
        }

        self.validator
            .validate_block(&block, &self.storage, self.id)
            .map_err(|e| StorageError::ValidationFailed(e.to_string()))?;

        // Make sure the validator actually exists
        let validator_address = block.validator.address();
        let base = self.storage.state_view();
        let mut block_overlay = OverlayState::new(&base);
        let (pre_consensus_state, pre_validator_set) = self.validate_selected_proposer(
            block.header.height,
            validator_address,
            &mut block_overlay,
        )?;
        self.try_get_account_overlay(validator_address, &block_overlay)?;
        let proposer_stake = pre_validator_set.stake_of(validator_address);

        let mut validator_fee = 0u128;
        let mut cumulative_gas: u64 = 0;
        let mut receipts = Vec::<Receipt>::new();

        for tx in &block.transactions {
            let hash = tx.id(self.id);
            let mut tx_overlay = OverlayState::new(&block_overlay);
            match self.apply_tx(tx, &block_overlay, &mut tx_overlay) {
                Ok((accounts, gas_used, return_data)) => {
                    tx_overlay
                        .into_writes()
                        .apply_tx_overlay(accounts, &mut block_overlay);
                    cumulative_gas += gas_used;
                    validator_fee = validator_fee
                        .saturating_add(tx.priority_fee.saturating_mul(gas_used as u128));
                    receipts.push(Receipt {
                        tx_hash: hash,
                        success: true,
                        gas_used,
                        cumulative_gas_used: cumulative_gas,
                        return_data,
                    });
                }
                Err(e) => Err(e)?,
            }
        }

        // Reward the validator for creating the block using: staking + transaction fees
        let mut validator_account =
            self.try_get_account_overlay(validator_address, &block_overlay)?;
        let reward = Self::validator_reward(proposer_stake, pre_validator_set.total_active_stake);
        validator_account.credit(reward + validator_fee)?;
        block_overlay.push(validator_address, validator_account.to_vec());

        if self.has_initialized_consensus(&block_overlay) {
            let mut state = self.load_consensus_state_overlay(&block_overlay)?;
            let set = self.load_validator_set_overlay(&block_overlay)?;
            state.total_active_stake = set.total_active_stake;
            state.randomness_seed = next_randomness_seed(
                pre_consensus_state.randomness_seed,
                block.header.previous_block,
            );
            self.store_consensus_state_overlay(&mut block_overlay, &state);
        }

        // Compute expected post-storage root deterministically
        let writes = block_overlay.into_writes();
        let computed_root = self.storage.preview_root(&writes.0);
        if computed_root != block.header.state_root {
            return Err(StorageError::ValidationFailed(format!(
                "state_root mismatch: expected {} and got {computed_root}",
                block.header.state_root
            )));
        }

        // Validate receipt root
        let computed_receipt_root =
            MerkleTree::from_raw(receipts.iter().map(|r| r.hash()).collect());
        BlockValidator::validate_receipt_root(&block, computed_receipt_root)
            .map_err(|e| StorageError::ValidationFailed(e.to_string()))?;

        self.storage.apply_batch(writes.0);
        self.append_block(&block, receipts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::block::Header;
    use crate::crypto::key_pair::PrivateKey;
    use crate::network::server::tests::test_db;
    use crate::storage::test_storage::test::TestStorage;
    use crate::types::bytes::Bytes;
    use crate::types::hash::Hash;
    use crate::types::merkle_tree::MerkleTree;
    use crate::utils::test_utils::utils::{create_genesis, new_tx, random_hash};
    use blockchain_derive::Error;

    const TEST_CHAIN_ID: u64 = 93;

    /// Creates a new blockchain with custom validator and storage.
    pub fn with_validator_and_storage<
        V: Validator,
        S: Storage + VmStorage + StateViewProvider + AccountStorage,
    >(
        id: u64,
        validator: V,
        storage: S,
    ) -> Blockchain<V, S> {
        Blockchain {
            id,
            storage,
            validator,
        }
    }

    pub fn add_block<V: Validator, S: StorageTrait>(
        chain: &Blockchain<V, S>,
        block: Block,
    ) -> Result<(), StorageError> {
        match chain
            .validator
            .validate_block(&block, &chain.storage, TEST_CHAIN_ID)
        {
            Ok(_) => chain.storage.append_block(block, vec![], chain.id),
            Err(err) => Err(StorageError::ValidationFailed(err.to_string())),
        }
    }

    #[derive(Debug, Error)]
    enum TestError {
        #[error("dummy error")]
        Dummy,
    }

    struct AcceptAllValidator;
    impl Validator for AcceptAllValidator {
        type Error = TestError;

        fn validate_tx(&self, _: &Transaction, _: &Account, _: u64) -> Result<(), Self::Error> {
            Ok(())
        }

        fn validate_block<S: Storage>(&self, _: &Block, _: &S, _: u64) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    struct RejectAllValidator;
    impl Validator for RejectAllValidator {
        type Error = TestError;

        fn validate_tx(&self, _: &Transaction, _: &Account, _: u64) -> Result<(), Self::Error> {
            Err(TestError::Dummy)
        }

        fn validate_block<S: Storage>(&self, _: &Block, _: &S, _: u64) -> Result<(), Self::Error> {
            Err(TestError::Dummy)
        }
    }

    fn create_header(height: u64, previous: Hash) -> Header {
        Header {
            version: 1,
            height,
            timestamp: 0,
            gas_used: BLOCK_GAS_LIMIT,
            previous_block: previous,
            merkle_root: Hash::zero(),
            state_root: random_hash(),
            receipt_root: Hash::zero(),
        }
    }

    fn test_storage(block: Block) -> TestStorage {
        TestStorage::new(block, TEST_CHAIN_ID, &[])
    }

    #[test]
    fn new_creates_blockchain_with_genesis() {
        let block = create_genesis(TEST_CHAIN_ID);
        let hash = block.header_hash(TEST_CHAIN_ID);
        let bc = Blockchain::new(TEST_CHAIN_ID, test_db(), block, &[]).unwrap();
        assert_eq!(bc.height(), 0);
        assert!(bc.get_block(hash).is_some());
    }

    #[test]
    fn height_increases_with_blocks() {
        let genesis = create_genesis(TEST_CHAIN_ID);
        let storage = test_storage(genesis.clone());
        let bc = with_validator_and_storage(TEST_CHAIN_ID, AcceptAllValidator, storage);

        let block1 = Block::new(
            create_header(1, bc.storage.tip()),
            PrivateKey::new(),
            vec![],
            TEST_CHAIN_ID,
        );

        assert!(add_block(&bc, block1).is_ok());
        assert_eq!(bc.height(), 1);
    }

    #[test]
    fn add_block_respects_validator() {
        let genesis = create_genesis(TEST_CHAIN_ID);
        let accept_bc = with_validator_and_storage(
            TEST_CHAIN_ID,
            AcceptAllValidator,
            test_storage(genesis.clone()),
        );
        let reject_bc = with_validator_and_storage(
            TEST_CHAIN_ID,
            RejectAllValidator,
            test_storage(genesis.clone()),
        );

        let block = Block::new(
            create_header(1, genesis.header_hash(TEST_CHAIN_ID)),
            PrivateKey::new(),
            vec![],
            TEST_CHAIN_ID,
        );

        assert!(add_block(&accept_bc, block.clone()).is_ok());
        assert!(add_block(&reject_bc, block).is_err());
    }

    #[test]
    fn add_blocks() {
        let genesis = create_genesis(TEST_CHAIN_ID);
        let storage = test_storage(genesis.clone());

        let validator = PrivateKey::new();
        storage.set_account(validator.public_key().address(), Account::new(0));

        let bc = with_validator_and_storage(TEST_CHAIN_ID, AcceptAllValidator, storage);

        let block_count = 100;
        for _i in 1..=block_count {
            bc.build_block(validator.clone(), &TxPool::new(Some(1), TEST_CHAIN_ID))
                .expect("build_block failed");
        }

        assert_eq!(bc.height(), block_count);

        bc.build_block(validator.clone(), &TxPool::new(Some(1), TEST_CHAIN_ID))
            .expect("build_block failed");
        assert_eq!(bc.height(), block_count + 1);
    }

    #[test]
    fn add_block_rejects_when_validator_rejects_tx() {
        #[derive(Debug, Error)]
        enum TxError {
            #[error("tx rejected")]
            Rejected,
        }

        struct RejectingTxValidator;
        impl Validator for RejectingTxValidator {
            type Error = TxError;
            fn validate_tx(&self, _: &Transaction, _: &Account, _: u64) -> Result<(), Self::Error> {
                Err(TxError::Rejected)
            }

            fn validate_block<S: Storage>(
                &self,
                _: &Block,
                _: &S,
                _: u64,
            ) -> Result<(), Self::Error> {
                Ok(())
            }
        }

        let genesis = create_genesis(TEST_CHAIN_ID);
        let storage = test_storage(genesis.clone());

        let key = PrivateKey::new();
        let sender = key.public_key().address();
        storage.set_account(sender, Account::new(10_000_000));
        storage.set_account(Address::zero(), Account::new(0));

        let block_validator = PrivateKey::new();
        storage.set_account(block_validator.public_key().address(), Account::new(0));

        let bc = with_validator_and_storage(TEST_CHAIN_ID, RejectingTxValidator, storage);

        let mut tx = new_tx(Bytes::new(b"any"), key, TEST_CHAIN_ID);
        tx.gas_limit = 50_000;
        tx.gas_price = 1;

        let header = Header {
            version: 1,
            height: 1,
            timestamp: 0,
            gas_used: BLOCK_GAS_LIMIT,
            previous_block: genesis.header_hash(TEST_CHAIN_ID),
            merkle_root: MerkleTree::from_transactions(std::slice::from_ref(&tx), TEST_CHAIN_ID),
            state_root: random_hash(),
            receipt_root: Hash::zero(),
        };
        let block = Block::new(header, block_validator, vec![tx], TEST_CHAIN_ID);

        assert!(matches!(
            bc.apply_block(block),
            Err(StorageError::ValidationFailed(_))
        ));
    }

    #[test]
    fn apply_tx_rejects_missing_account() {
        let genesis = create_genesis(TEST_CHAIN_ID);
        let storage = test_storage(genesis);
        let bc = with_validator_and_storage(TEST_CHAIN_ID, AcceptAllValidator, storage);

        let mut tx = new_tx(Bytes::new(b"data"), PrivateKey::new(), TEST_CHAIN_ID);
        tx.gas_limit = 25_000;
        tx.gas_price = 1;
        let base = bc.storage.state_view();
        let overlay = OverlayState::new(&base);
        let mut tx_overlay = OverlayState::new(&overlay);

        let result = bc.apply_tx(&tx, &overlay, &mut tx_overlay);
        assert!(matches!(result, Err(StorageError::MissingAccount(_))));
    }

    #[test]
    fn apply_tx_rejects_insufficient_balance_for_gas() {
        let genesis = create_genesis(TEST_CHAIN_ID);
        let storage = test_storage(genesis);

        let key = PrivateKey::new();
        let sender = key.public_key().address();
        storage.set_account(sender, Account::new(100));
        storage.set_account(Address::zero(), Account::new(0));

        let bc = with_validator_and_storage(TEST_CHAIN_ID, AcceptAllValidator, storage);

        let mut tx = new_tx(Bytes::new(b"data"), key, TEST_CHAIN_ID);
        tx.gas_limit = 25_000;
        tx.gas_price = 1;

        let base = bc.storage.state_view();
        let overlay = OverlayState::new(&base);
        let mut tx_overlay = OverlayState::new(&overlay);

        let result = bc.apply_tx(&tx, &overlay, &mut tx_overlay);
        assert!(matches!(
            result,
            Err(StorageError::InsufficientBalance { .. })
        ));
    }

    #[test]
    fn apply_tx_rejects_gas_overflow() {
        let genesis = create_genesis(TEST_CHAIN_ID);
        let storage = test_storage(genesis);

        let key = PrivateKey::new();
        let sender = key.public_key().address();
        storage.set_account(sender, Account::new(u128::MAX));
        storage.set_account(Address::zero(), Account::new(0));

        let bc = with_validator_and_storage(TEST_CHAIN_ID, AcceptAllValidator, storage);

        let mut tx = new_tx(Bytes::new(b"data"), key, TEST_CHAIN_ID);
        tx.gas_limit = u64::MAX;
        tx.gas_price = u128::MAX;

        let base = bc.storage.state_view();
        let overlay = OverlayState::new(&base);
        let mut tx_overlay = OverlayState::new(&overlay);

        let result = bc.apply_tx(&tx, &overlay, &mut tx_overlay);
        assert!(matches!(
            result,
            Err(StorageError::ArithmeticOverflow { .. })
        ));
    }

    #[test]
    fn contract_id_is_deterministic() {
        let key = PrivateKey::new();
        let tx1 = new_tx(Bytes::new(b"contract_code"), key.clone(), TEST_CHAIN_ID);
        let tx2 = new_tx(Bytes::new(b"contract_code"), key, TEST_CHAIN_ID);

        let id1 = Blockchain::<AcceptAllValidator, TestStorage>::contract_id(&tx1);
        let id2 = Blockchain::<AcceptAllValidator, TestStorage>::contract_id(&tx2);

        assert_eq!(id1, id2);
    }

    #[test]
    fn intrinsic_gas_units_accounts_for_zero_and_nonzero_bytes() {
        let data = Bytes::new([0, 1, 2, 0]);

        let gas = Blockchain::<AcceptAllValidator, TestStorage>::intrinsic_gas_units(
            TransactionType::TransferFunds,
            &data,
        );

        let expected = 21_000 + 4 + 16 + 16 + 4;
        assert_eq!(gas, expected);
    }

    #[test]
    fn intrinsic_gas_units_includes_deploy_base_cost() {
        let data = Bytes::new([5, 6, 7]);

        let gas = Blockchain::<AcceptAllValidator, TestStorage>::intrinsic_gas_units(
            TransactionType::DeployContract,
            &data,
        );

        let expected = 21_000 + 32_000 + (3 * 16);
        assert_eq!(gas, expected);
    }

    #[test]
    fn code_hash_is_namespaced_and_deterministic() {
        let runtime = b"runtime_code";

        let hash1 = Blockchain::<AcceptAllValidator, TestStorage>::code_hash(runtime);
        let hash2 = Blockchain::<AcceptAllValidator, TestStorage>::code_hash(runtime);
        let raw_hash = Hash::sha3().chain(runtime).finalize();
        let different = Blockchain::<AcceptAllValidator, TestStorage>::code_hash(b"other");
        let different2 = Blockchain::<AcceptAllValidator, TestStorage>::code_hash(b"runtime_c0de");

        assert_eq!(hash1, hash2);
        assert_ne!(hash1, raw_hash);
        assert_ne!(hash1, different);
        assert_ne!(hash1, different2);
        assert_ne!(different, different2);
    }

    #[test]
    fn apply_block_rejects_duplicate_block() {
        let genesis = create_genesis(TEST_CHAIN_ID);
        let storage = test_storage(genesis.clone());
        let bc = with_validator_and_storage(TEST_CHAIN_ID, AcceptAllValidator, storage);

        let block = Block::new(
            create_header(1, genesis.header_hash(TEST_CHAIN_ID)),
            PrivateKey::new(),
            vec![],
            TEST_CHAIN_ID,
        );

        add_block(&bc, block.clone()).unwrap();
        let result = bc.apply_block(block);

        assert!(matches!(
            result,
            Err(StorageError::ValidationFailed(msg)) if msg.contains("already exists")
        ));
    }

    #[test]
    fn apply_block_rejects_state_root_mismatch() {
        let genesis = create_genesis(TEST_CHAIN_ID);
        let storage = test_storage(genesis.clone());

        let block_validator = PrivateKey::new();
        storage.set_account(block_validator.public_key().address(), Account::new(0));

        let bc = with_validator_and_storage(TEST_CHAIN_ID, AcceptAllValidator, storage);

        let header = Header {
            version: 1,
            height: 1,
            timestamp: 0,
            gas_used: BLOCK_GAS_LIMIT,
            previous_block: genesis.header_hash(TEST_CHAIN_ID),
            merkle_root: MerkleTree::from_transactions(&[], TEST_CHAIN_ID),
            state_root: random_hash(),
            receipt_root: Hash::zero(),
        };
        let block = Block::new(header, block_validator, vec![], TEST_CHAIN_ID);

        let result = bc.apply_block(block);
        assert!(matches!(
            result,
            Err(StorageError::ValidationFailed(msg)) if msg.contains("state_root mismatch")
        ));
    }

    fn make_deploy_tx(key: PrivateKey, chain_id: u64) -> Transaction {
        use crate::virtual_machine::assembler::assemble_source;

        let program = assemble_source("MOVE r0, 42").expect("assemble failed");
        let mut tx = new_tx(program.to_bytes(), key, chain_id);
        tx.tx_type = TransactionType::DeployContract;
        tx.gas_limit = 100_000;
        tx.gas_price = 1;
        tx
    }

    #[test]
    fn apply_tx_charges_gas_from_account() {
        let genesis = create_genesis(TEST_CHAIN_ID);
        let storage = test_storage(genesis);

        let key = PrivateKey::new();
        let sender = key.public_key().address();
        let initial_balance = 10_000_000u128;
        storage.set_account(sender, Account::new(initial_balance));
        storage.set_account(Address::zero(), Account::new(0));

        let bc = with_validator_and_storage(TEST_CHAIN_ID, AcceptAllValidator, storage);

        let tx = make_deploy_tx(key, TEST_CHAIN_ID);

        let base = bc.storage.state_view();
        let mut overlay = OverlayState::new(&base);
        let mut tx_overlay = OverlayState::new(&overlay);

        let (account, _, _) = bc
            .apply_tx(&tx, &overlay, &mut tx_overlay)
            .expect("apply_tx failed");
        tx_overlay
            .into_writes()
            .apply_tx_overlay(account, &mut overlay);

        let account_bytes = overlay
            .get(sender)
            .expect("account should exist in overlay");
        let account = Account::from_bytes(&account_bytes).unwrap();

        assert!(account.balance() < initial_balance);
    }

    #[test]
    fn apply_tx_increments_nonce_on_success() {
        let genesis = create_genesis(TEST_CHAIN_ID);
        let storage = test_storage(genesis);

        let key = PrivateKey::new();
        let sender = key.public_key().address();
        storage.set_account(sender, Account::new(10_000_000));
        storage.set_account(Address::zero(), Account::new(0));

        let bc = with_validator_and_storage(TEST_CHAIN_ID, AcceptAllValidator, storage);

        let tx = make_deploy_tx(key, TEST_CHAIN_ID);

        let base = bc.storage.state_view();
        let mut overlay = OverlayState::new(&base);
        let mut tx_overlay = OverlayState::new(&overlay);

        let (account, _, _) = bc
            .apply_tx(&tx, &overlay, &mut tx_overlay)
            .expect("apply_tx failed");
        tx_overlay
            .into_writes()
            .apply_tx_overlay(account, &mut overlay);

        let account_bytes = overlay.get(sender).expect("account should exist");
        let account = Account::from_bytes(&account_bytes).unwrap();

        assert_eq!(account.nonce(), 1);
    }

    #[test]
    fn apply_tx_charges_correct_gas_amount() {
        let genesis = create_genesis(TEST_CHAIN_ID);
        let storage = test_storage(genesis);

        let key = PrivateKey::new();
        let sender = key.public_key().address();
        let initial_balance = 10_000_000u128;
        let gas_price = 10u128;
        storage.set_account(sender, Account::new(initial_balance));
        storage.set_account(Address::zero(), Account::new(0));

        let bc = with_validator_and_storage(TEST_CHAIN_ID, AcceptAllValidator, storage);

        let mut tx = make_deploy_tx(key, TEST_CHAIN_ID);
        tx.gas_price = gas_price;

        let base = bc.storage.state_view();
        let mut overlay = OverlayState::new(&base);
        let mut tx_overlay = OverlayState::new(&overlay);

        let (account, _, _) = bc
            .apply_tx(&tx, &overlay, &mut tx_overlay)
            .expect("apply_tx failed");
        tx_overlay
            .into_writes()
            .apply_tx_overlay(account, &mut overlay);

        let account_bytes = overlay.get(sender).expect("account should exist");
        let account = Account::from_bytes(&account_bytes).unwrap();

        let gas_charged = initial_balance - account.balance();
        assert!(gas_charged > 0);
        assert_eq!(gas_charged % gas_price, 0);
    }

    #[test]
    fn multiple_txs_increment_nonce_sequentially() {
        let genesis = create_genesis(TEST_CHAIN_ID);
        let storage = test_storage(genesis);

        let key = PrivateKey::new();
        let sender = key.public_key().address();
        storage.set_account(sender, Account::new(100_000_000));
        storage.set_account(Address::zero(), Account::new(0));

        let bc = with_validator_and_storage(TEST_CHAIN_ID, AcceptAllValidator, storage);

        let base = bc.storage.state_view();
        let mut overlay = OverlayState::new(&base);

        for i in 0..3 {
            let mut tx = make_deploy_tx(key.clone(), TEST_CHAIN_ID);
            tx.nonce = i;

            let mut tx_overlay = OverlayState::new(&overlay);
            let (account, _, _) = bc
                .apply_tx(&tx, &overlay, &mut tx_overlay)
                .expect("apply_tx failed");

            tx_overlay
                .into_writes()
                .apply_tx_overlay(account, &mut overlay);
        }

        let account_bytes = overlay.get(sender).expect("account should exist");
        let account = Account::from_bytes(&account_bytes).unwrap();

        assert_eq!(account.nonce(), 3);
    }

    #[test]
    fn apply_tx_rejects_gas_limit_below_intrinsic() {
        let genesis = create_genesis(TEST_CHAIN_ID);
        let storage = test_storage(genesis);

        let key = PrivateKey::new();
        let sender = key.public_key().address();
        storage.set_account(sender, Account::new(10_000_000));

        let bc = with_validator_and_storage(TEST_CHAIN_ID, AcceptAllValidator, storage);

        let mut tx = new_tx(Bytes::new(b""), key, TEST_CHAIN_ID);
        tx.gas_limit = 1000; // Below 21_000 intrinsic
        tx.gas_price = 1;

        let base = bc.storage.state_view();
        let overlay = OverlayState::new(&base);
        let mut tx_overlay = OverlayState::new(&overlay);

        let result = bc.apply_tx(&tx, &overlay, &mut tx_overlay);
        assert!(matches!(result, Err(StorageError::VMError(_))));
    }

    fn make_transfer_tx(
        from_key: PrivateKey,
        to: Address,
        amount: u128,
        chain_id: u64,
    ) -> Transaction {
        Transaction::new(
            to,
            None,
            Bytes::new(b""),
            amount,
            0,
            1,
            25_000,
            0,
            from_key,
            chain_id,
            TransactionType::TransferFunds,
        )
    }

    #[test]
    fn apply_tx_transfer_funds_moves_balance() {
        let genesis = create_genesis(TEST_CHAIN_ID);
        let storage = test_storage(genesis);

        let sender_key = PrivateKey::new();
        let sender = sender_key.public_key().address();
        let receiver = PrivateKey::new().public_key().address();

        let sender_initial = 1_000_000u128;
        let receiver_initial = 500u128;
        let transfer_amount = 10_000u128;

        storage.set_account(sender, Account::new(sender_initial));
        storage.set_account(receiver, Account::new(receiver_initial));

        let bc = with_validator_and_storage(TEST_CHAIN_ID, AcceptAllValidator, storage);

        let tx = make_transfer_tx(sender_key, receiver, transfer_amount, TEST_CHAIN_ID);

        let base = bc.storage.state_view();
        let mut overlay = OverlayState::new(&base);
        let mut tx_overlay = OverlayState::new(&overlay);

        let (accounts, gas_used, _) = bc
            .apply_tx(&tx, &overlay, &mut tx_overlay)
            .expect("apply_tx failed");
        tx_overlay
            .into_writes()
            .apply_tx_overlay(accounts, &mut overlay);

        let sender_account = Account::from_bytes(&overlay.get(sender).unwrap()).unwrap();
        let receiver_account = Account::from_bytes(&overlay.get(receiver).unwrap()).unwrap();

        let gas_cost = gas_used as u128 * tx.gas_price;
        assert_eq!(
            sender_account.balance(),
            sender_initial - transfer_amount - gas_cost
        );
        assert_eq!(
            receiver_account.balance(),
            receiver_initial + transfer_amount
        );
    }

    #[test]
    fn apply_tx_transfer_funds_insufficient_balance_fails() {
        let genesis = create_genesis(TEST_CHAIN_ID);
        let storage = test_storage(genesis);

        let sender_key = PrivateKey::new();
        let sender = sender_key.public_key().address();
        let receiver = PrivateKey::new().public_key().address();

        // Only enough for gas, not for transfer
        storage.set_account(sender, Account::new(30_000));
        storage.set_account(receiver, Account::new(0));

        let bc = with_validator_and_storage(TEST_CHAIN_ID, AcceptAllValidator, storage);

        let tx = make_transfer_tx(sender_key, receiver, 50_000, TEST_CHAIN_ID);

        let base = bc.storage.state_view();
        let overlay = OverlayState::new(&base);
        let mut tx_overlay = OverlayState::new(&overlay);

        let result = bc.apply_tx(&tx, &overlay, &mut tx_overlay);
        assert!(matches!(
            result,
            Err(StorageError::InsufficientBalance { .. })
        ));
    }

    #[test]
    fn deploy_contract_creates_contract_account() {
        let genesis = create_genesis(TEST_CHAIN_ID);
        let storage = test_storage(genesis);

        let key = PrivateKey::new();
        let sender = key.public_key().address();
        storage.set_account(sender, Account::new(10_000_000));
        storage.set_account(Address::zero(), Account::new(0));

        let bc = with_validator_and_storage(TEST_CHAIN_ID, AcceptAllValidator, storage);
        let tx = make_deploy_tx(key, TEST_CHAIN_ID);
        let contract_id = Blockchain::<AcceptAllValidator, TestStorage>::contract_id(&tx);

        let base = bc.storage.state_view();
        let mut overlay = OverlayState::new(&base);
        let mut tx_overlay = OverlayState::new(&overlay);

        let (accounts, _, _) = bc
            .apply_tx(&tx, &overlay, &mut tx_overlay)
            .expect("apply_tx failed");
        tx_overlay
            .into_writes()
            .apply_tx_overlay(accounts, &mut overlay);

        let contract_bytes = overlay
            .get(contract_id)
            .expect("contract account should exist");
        let contract = Account::from_bytes(&contract_bytes).unwrap();

        assert!(contract.is_contract());
        assert_eq!(contract.nonce(), 0);
    }

    #[test]
    fn deploy_contract_stores_runtime_bytecode() {
        use crate::virtual_machine::assembler::assemble_source;

        let genesis = create_genesis(TEST_CHAIN_ID);
        let storage = test_storage(genesis);

        let key = PrivateKey::new();
        let sender = key.public_key().address();
        storage.set_account(sender, Account::new(10_000_000));
        storage.set_account(Address::zero(), Account::new(0));

        let bc = with_validator_and_storage(TEST_CHAIN_ID, AcceptAllValidator, storage);

        let program = assemble_source("MOVE r0, 42").expect("assemble failed");
        let mut pg2 = program.clone();
        pg2.init_code = vec![];
        let expected_runtime = program.to_vec();
        let expected_code_hash =
            Blockchain::<AcceptAllValidator, TestStorage>::code_hash(&program.runtime_code);

        let mut tx = new_tx(program.to_bytes(), key, TEST_CHAIN_ID);
        tx.tx_type = TransactionType::DeployContract;
        tx.gas_limit = 100_000;
        tx.gas_price = 1;

        let contract_id = Blockchain::<AcceptAllValidator, TestStorage>::contract_id(&tx);

        let base = bc.storage.state_view();
        let mut overlay = OverlayState::new(&base);
        let mut tx_overlay = OverlayState::new(&overlay);

        let (accounts, _, _) = bc
            .apply_tx(&tx, &overlay, &mut tx_overlay)
            .expect("apply_tx failed");
        tx_overlay
            .into_writes()
            .apply_tx_overlay(accounts, &mut overlay);

        // Verify contract account has correct code_hash
        let contract_bytes = overlay.get(contract_id).expect("contract should exist");
        let contract = Account::from_bytes(&contract_bytes).unwrap();
        assert_eq!(contract.code_hash(), expected_code_hash);

        // Verify runtime bytecode is stored under code_hash
        let stored_code = overlay
            .get(expected_code_hash)
            .expect("runtime code should be stored");
        assert_eq!(stored_code, expected_runtime);
    }

    #[test]
    fn deploy_contract_with_init_and_runtime_sections() {
        use crate::virtual_machine::assembler::assemble_source;

        let genesis = create_genesis(TEST_CHAIN_ID);
        let storage = test_storage(genesis);

        let key = PrivateKey::new();
        let sender = key.public_key().address();
        storage.set_account(sender, Account::new(10_000_000));
        storage.set_account(Address::zero(), Account::new(0));

        let bc = with_validator_and_storage(TEST_CHAIN_ID, AcceptAllValidator, storage);

        let source = r#"
__init__:
MOVE r0, 1
HALT

main:
MOVE r1, 2
"#;
        let program = assemble_source(source).expect("assemble failed");
        assert!(!program.init_code.is_empty());
        assert!(!program.runtime_code.is_empty());

        let expected_code_hash =
            Blockchain::<AcceptAllValidator, TestStorage>::code_hash(&program.runtime_code);

        let mut tx = new_tx(program.to_bytes(), key, TEST_CHAIN_ID);
        tx.tx_type = TransactionType::DeployContract;
        tx.gas_limit = 100_000;
        tx.gas_price = 1;

        let contract_id = Blockchain::<AcceptAllValidator, TestStorage>::contract_id(&tx);

        let base = bc.storage.state_view();
        let mut overlay = OverlayState::new(&base);
        let mut tx_overlay = OverlayState::new(&overlay);

        let (accounts, _, _) = bc
            .apply_tx(&tx, &overlay, &mut tx_overlay)
            .expect("apply_tx failed");
        tx_overlay
            .into_writes()
            .apply_tx_overlay(accounts, &mut overlay);

        // Verify only runtime_code is stored (not init_code)
        let contract_bytes = overlay.get(contract_id).expect("contract should exist");
        let contract = Account::from_bytes(&contract_bytes).unwrap();
        assert_eq!(contract.code_hash(), expected_code_hash);

        let stored_code = overlay.get(expected_code_hash).expect("code should exist");
        let mut pg2 = program.clone();
        pg2.init_code = vec![];
        assert_eq!(stored_code, pg2.to_vec());
    }

    #[test]
    fn build_block_generates_receipts() {
        let genesis = create_genesis(TEST_CHAIN_ID);
        let storage = test_storage(genesis);

        let validator_key = PrivateKey::new();
        let validator_addr = validator_key.public_key().address();
        storage.set_account(validator_addr, Account::new(0));

        let sender_key = PrivateKey::new();
        let sender = sender_key.public_key().address();
        storage.set_account(sender, Account::new(10_000_000));
        storage.set_account(Address::zero(), Account::new(0));

        let bc = with_validator_and_storage(TEST_CHAIN_ID, AcceptAllValidator, storage);
        let tx = make_deploy_tx(sender_key, TEST_CHAIN_ID);

        let pool = TxPool::new(Some(4), TEST_CHAIN_ID);
        let sender_account = bc
            .storage
            .get_account(sender)
            .expect("sender account should exist");
        assert!(pool.append(&sender_account, tx.clone()));

        let block = bc
            .build_block(validator_key, &pool)
            .expect("build_block failed");
        assert_ne!(block.header.receipt_root, Hash::zero());

        let receipts = bc
            .storage
            .get_receipts(block.header_hash(TEST_CHAIN_ID))
            .expect("receipts should be stored");
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].tx_hash, tx.id(TEST_CHAIN_ID));
        assert!(receipts[0].success);
    }

    #[test]
    fn apply_block_validates_receipt_root_mismatch() {
        let genesis = create_genesis(TEST_CHAIN_ID);

        let builder_storage = test_storage(genesis.clone());
        let verifier_storage = test_storage(genesis);

        let validator_key = PrivateKey::new();
        let validator_addr = validator_key.public_key().address();
        builder_storage.set_account(validator_addr, Account::new(0));
        verifier_storage.set_account(validator_addr, Account::new(0));

        let sender_key = PrivateKey::new();
        let sender = sender_key.public_key().address();
        builder_storage.set_account(sender, Account::new(10_000_000));
        verifier_storage.set_account(sender, Account::new(10_000_000));
        builder_storage.set_account(Address::zero(), Account::new(0));
        verifier_storage.set_account(Address::zero(), Account::new(0));

        let builder =
            with_validator_and_storage(TEST_CHAIN_ID, AcceptAllValidator, builder_storage);
        let verifier =
            with_validator_and_storage(TEST_CHAIN_ID, AcceptAllValidator, verifier_storage);

        let tx = make_deploy_tx(sender_key, TEST_CHAIN_ID);
        let pool = TxPool::new(Some(4), TEST_CHAIN_ID);
        let sender_account = builder
            .storage
            .get_account(sender)
            .expect("sender account should exist");
        assert!(pool.append(&sender_account, tx));

        let mut block = builder
            .build_block(validator_key, &pool)
            .expect("build_block failed");
        assert_ne!(block.header.receipt_root, Hash::zero());
        block.header.receipt_root = Hash::zero();

        let result = verifier.apply_block(block);
        assert!(matches!(
            result,
            Err(StorageError::ValidationFailed(msg)) if msg.contains("receipt_root mismatch")
        ));
    }

    #[test]
    fn receipt_cumulative_gas_accumulates() {
        let genesis = create_genesis(TEST_CHAIN_ID);
        let storage = test_storage(genesis);

        let validator_key = PrivateKey::new();
        let validator_addr = validator_key.public_key().address();
        storage.set_account(validator_addr, Account::new(0));

        let sender_key = PrivateKey::new();
        let sender = sender_key.public_key().address();
        let receiver = PrivateKey::new().public_key().address();
        storage.set_account(sender, Account::new(10_000_000));
        storage.set_account(receiver, Account::new(0));

        let bc = with_validator_and_storage(TEST_CHAIN_ID, AcceptAllValidator, storage);

        let tx1 = make_transfer_tx(sender_key.clone(), receiver, 1_000, TEST_CHAIN_ID);
        let mut tx2 = make_transfer_tx(sender_key, receiver, 2_000, TEST_CHAIN_ID);
        tx2.nonce = 1;

        let pool = TxPool::new(Some(8), TEST_CHAIN_ID);
        let sender_account = bc
            .storage
            .get_account(sender)
            .expect("sender account should exist");
        assert!(pool.append(&sender_account, tx1));
        assert!(pool.append(&sender_account, tx2));

        let block = bc
            .build_block(validator_key, &pool)
            .expect("build_block failed");
        let receipts = bc
            .storage
            .get_receipts(block.header_hash(TEST_CHAIN_ID))
            .expect("receipts should be stored");

        assert_eq!(receipts.len(), 2);
        assert_eq!(receipts[0].cumulative_gas_used, receipts[0].gas_used);
        assert_eq!(
            receipts[1].cumulative_gas_used,
            receipts[0].gas_used + receipts[1].gas_used
        );
    }

    #[test]
    fn transfer_tx_receipt_has_empty_return_data() {
        let genesis = create_genesis(TEST_CHAIN_ID);
        let storage = test_storage(genesis);

        let validator_key = PrivateKey::new();
        let validator_addr = validator_key.public_key().address();
        storage.set_account(validator_addr, Account::new(0));

        let sender_key = PrivateKey::new();
        let sender = sender_key.public_key().address();
        let receiver = PrivateKey::new().public_key().address();
        storage.set_account(sender, Account::new(1_000_000));
        storage.set_account(receiver, Account::new(0));

        let bc = with_validator_and_storage(TEST_CHAIN_ID, AcceptAllValidator, storage);
        let tx = make_transfer_tx(sender_key, receiver, 10_000, TEST_CHAIN_ID);

        let pool = TxPool::new(Some(4), TEST_CHAIN_ID);
        let sender_account = bc
            .storage
            .get_account(sender)
            .expect("sender account should exist");
        assert!(pool.append(&sender_account, tx));

        let block = bc
            .build_block(validator_key, &pool)
            .expect("build_block failed");
        let receipts = bc
            .storage
            .get_receipts(block.header_hash(TEST_CHAIN_ID))
            .expect("receipts should be stored");

        assert_eq!(receipts.len(), 1);
        assert!(receipts[0].return_data.is_empty());
    }

    #[test]
    fn receipt_root_zero_for_empty_block() {
        let genesis = create_genesis(TEST_CHAIN_ID);
        let storage = test_storage(genesis);

        let validator_key = PrivateKey::new();
        let validator_addr = validator_key.public_key().address();
        storage.set_account(validator_addr, Account::new(0));

        let bc = with_validator_and_storage(TEST_CHAIN_ID, AcceptAllValidator, storage);
        let pool = TxPool::new(Some(4), TEST_CHAIN_ID);

        let block = bc
            .build_block(validator_key, &pool)
            .expect("build_block failed");
        assert_eq!(block.header.receipt_root, Hash::zero());

        let receipts = bc
            .storage
            .get_receipts(block.header_hash(TEST_CHAIN_ID))
            .expect("receipts should be stored");
        assert!(receipts.is_empty());
    }

    fn make_consensus_tx(
        from_key: PrivateKey,
        nonce: u64,
        tx_type: TransactionType,
        payload: Vec<u8>,
    ) -> Transaction {
        Transaction::new(
            Address::zero(),
            None,
            payload,
            0,
            0,
            1,
            100_000,
            nonce,
            from_key,
            TEST_CHAIN_ID,
            tx_type,
        )
    }

    fn seed_consensus_state(
        storage: &TestStorage,
        state: ConsensusState,
        mut set: ValidatorSetSnapshot,
        records: &[ValidatorRecord],
    ) {
        set.normalize();
        let mut writes = vec![
            (consensus_state_key(), Some(state.to_vec())),
            (validator_set_key(), Some(set.to_vec())),
        ];
        for record in records {
            writes.push((validator_record_key(record.address), Some(record.to_vec())));
        }
        storage.apply_batch(writes);
    }

    #[test]
    fn stake_tx_schedules_activation_and_bonding_transition_activates_later() {
        let genesis = create_genesis(TEST_CHAIN_ID);
        let storage = test_storage(genesis);

        let staker_key = PrivateKey::new();
        let staker = staker_key.public_key().address();
        let initial_balance = 1_000_000u128;
        let stake_amount = 25_000u128;
        storage.set_account(staker, Account::new(initial_balance));

        let bc = with_validator_and_storage(TEST_CHAIN_ID, AcceptAllValidator, storage);

        let tx = make_consensus_tx(
            staker_key,
            0,
            TransactionType::Stake,
            StakeTxData {
                amount: stake_amount,
            }
            .to_vec(),
        );

        let base = bc.storage.state_view();
        let mut overlay = OverlayState::new(&base);
        let mut tx_overlay = OverlayState::new(&overlay);

        let (accounts, _, _) = bc
            .apply_tx(&tx, &overlay, &mut tx_overlay)
            .expect("stake tx should apply");
        tx_overlay
            .into_writes()
            .apply_tx_overlay(accounts, &mut overlay);

        let staker_account = Account::from_bytes(
            &overlay
                .get(staker)
                .expect("staker account should exist after stake tx"),
        )
        .expect("staker account should decode");
        assert_eq!(staker_account.nonce(), 1);
        assert!(
            staker_account.balance() <= initial_balance.saturating_sub(stake_amount),
            "stake amount should be debited in addition to gas"
        );

        let record = ValidatorRecord::decode(
            &mut overlay
                .get(validator_record_key(staker))
                .expect("validator record should be created")
                .as_slice(),
        )
        .expect("validator record should decode");
        assert_eq!(record.active_stake, 0);
        assert_eq!(record.pending_activations.len(), 1);
        assert_eq!(record.pending_activations[0].amount, stake_amount);

        let activate_height = record.pending_activations[0].activate_height;
        let params = default_staking_params();
        assert_eq!(activate_height, 1 + params.bonding_period_blocks);

        let (state_before, set_before) = bc
            .process_scheduled_staking_transitions(activate_height - 1, &mut overlay)
            .expect("scheduled transitions before bonding should succeed");
        assert_eq!(state_before.total_active_stake, 0);
        assert_eq!(set_before.total_active_stake, 0);

        let record_before = ValidatorRecord::decode(
            &mut overlay
                .get(validator_record_key(staker))
                .expect("validator record should remain present")
                .as_slice(),
        )
        .expect("validator record should decode");
        assert_eq!(record_before.active_stake, 0);
        assert_eq!(record_before.pending_activations.len(), 1);

        let (state_after, set_after) = bc
            .process_scheduled_staking_transitions(activate_height, &mut overlay)
            .expect("scheduled transitions at activation height should succeed");
        assert_eq!(state_after.total_active_stake, stake_amount);
        assert_eq!(set_after.total_active_stake, stake_amount);
        assert_eq!(set_after.stake_of(staker), stake_amount);

        let record_after = ValidatorRecord::decode(
            &mut overlay
                .get(validator_record_key(staker))
                .expect("validator record should remain present")
                .as_slice(),
        )
        .expect("validator record should decode");
        assert_eq!(record_after.active_stake, stake_amount);
        assert!(record_after.pending_activations.is_empty());
    }

    #[test]
    fn unstake_and_claim_unbonded_update_validator_and_account_state() {
        let genesis = create_genesis(TEST_CHAIN_ID);
        let storage = test_storage(genesis);

        let staker_key = PrivateKey::new();
        let staker = staker_key.public_key().address();
        let initial_balance = 500_000u128;
        storage.set_account(staker, Account::new(initial_balance));

        let mut set = ValidatorSetSnapshot {
            tracked_validators: vec![staker],
            validators: vec![crate::core::consensus::ActiveValidatorEntry {
                address: staker,
                stake: 40_000,
            }],
            total_active_stake: 0,
        };
        set.normalize();

        let mut record = ValidatorRecord::new(staker);
        record.active_stake = 40_000;

        seed_consensus_state(
            &storage,
            ConsensusState {
                last_processed_height: 0,
                total_active_stake: set.total_active_stake,
                randomness_seed: Hash::zero(),
            },
            set,
            &[record.clone()],
        );

        let bc = with_validator_and_storage(TEST_CHAIN_ID, AcceptAllValidator, storage);

        let unstake_amount = 10_000u128;
        let unstake_tx = make_consensus_tx(
            staker_key.clone(),
            0,
            TransactionType::Unstake,
            UnstakeTxData {
                amount: unstake_amount,
            }
            .to_vec(),
        );

        let base = bc.storage.state_view();
        let mut overlay = OverlayState::new(&base);
        let mut tx_overlay = OverlayState::new(&overlay);
        let (unstake_accounts, unstake_gas_used, _) = bc
            .apply_tx(&unstake_tx, &overlay, &mut tx_overlay)
            .expect("unstake tx should apply");
        tx_overlay
            .into_writes()
            .apply_tx_overlay(unstake_accounts, &mut overlay);

        let account_after_unstake = Account::from_bytes(
            &overlay
                .get(staker)
                .expect("staker account should exist after unstake"),
        )
        .expect("staker account should decode");
        let unstake_gas_cost = unstake_gas_used as u128 * unstake_tx.gas_price;
        assert_eq!(
            account_after_unstake.balance(),
            initial_balance - unstake_gas_cost
        );
        assert_eq!(account_after_unstake.nonce(), 1);

        let record_after_unstake = ValidatorRecord::decode(
            &mut overlay
                .get(validator_record_key(staker))
                .expect("validator record should exist")
                .as_slice(),
        )
        .expect("validator record should decode");
        assert_eq!(record_after_unstake.active_stake, 30_000);
        assert_eq!(record_after_unstake.pending_unbonds.len(), 1);
        assert_eq!(
            record_after_unstake.pending_unbonds[0].amount,
            unstake_amount
        );

        let set_after_unstake = ValidatorSetSnapshot::decode(
            &mut overlay
                .get(validator_set_key())
                .expect("validator set should exist")
                .as_slice(),
        )
        .expect("validator set should decode");
        assert_eq!(set_after_unstake.total_active_stake, 30_000);
        assert_eq!(set_after_unstake.stake_of(staker), 30_000);

        // Make the pending unbond immediately claimable in overlay to test claim flow
        // without producing hundreds of blocks in the unit test.
        let mut claimable_record = record_after_unstake.clone();
        claimable_record.pending_unbonds[0].claim_height = 1;
        overlay.push(validator_record_key(staker), claimable_record.to_vec());

        let claim_tx = make_consensus_tx(
            staker_key,
            1,
            TransactionType::ClaimUnbonded,
            ClaimUnbondedTxData { amount: 0 }.to_vec(),
        );
        let mut claim_tx_overlay = OverlayState::new(&overlay);
        let (claim_accounts, claim_gas_used, _) = bc
            .apply_tx(&claim_tx, &overlay, &mut claim_tx_overlay)
            .expect("claim tx should apply");
        claim_tx_overlay
            .into_writes()
            .apply_tx_overlay(claim_accounts, &mut overlay);

        let claimed_account = Account::from_bytes(
            &overlay
                .get(staker)
                .expect("staker account should exist after claim"),
        )
        .expect("staker account should decode");
        let gas_cost = claim_gas_used as u128 * claim_tx.gas_price;
        assert_eq!(
            claimed_account.balance(),
            account_after_unstake.balance() + unstake_amount - gas_cost
        );
        assert_eq!(claimed_account.nonce(), 2);

        let record_after_claim = ValidatorRecord::decode(
            &mut overlay
                .get(validator_record_key(staker))
                .expect("validator record should exist")
                .as_slice(),
        )
        .expect("validator record should decode");
        assert!(record_after_claim.pending_unbonds.is_empty());
        assert_eq!(record_after_claim.active_stake, 30_000);
    }

    #[test]
    fn build_block_rejects_unselected_proposer_when_consensus_is_active() {
        let genesis = create_genesis(TEST_CHAIN_ID);
        let storage = test_storage(genesis);

        let selected_key = PrivateKey::new();
        let selected_addr = selected_key.public_key().address();
        let wrong_key = PrivateKey::new();
        let wrong_addr = wrong_key.public_key().address();
        storage.set_account(selected_addr, Account::new(0));
        storage.set_account(wrong_addr, Account::new(0));

        let mut selected_record = ValidatorRecord::new(selected_addr);
        selected_record.active_stake = 50_000;

        let set = ValidatorSetSnapshot {
            tracked_validators: vec![selected_addr],
            validators: vec![crate::core::consensus::ActiveValidatorEntry {
                address: selected_addr,
                stake: 50_000,
            }],
            total_active_stake: 50_000,
        };
        seed_consensus_state(
            &storage,
            ConsensusState {
                last_processed_height: 0,
                total_active_stake: 50_000,
                randomness_seed: Hash::sha3().chain(b"seed").finalize(),
            },
            set,
            &[selected_record],
        );

        let bc = with_validator_and_storage(TEST_CHAIN_ID, AcceptAllValidator, storage);
        let pool = TxPool::new(Some(4), TEST_CHAIN_ID);

        let result = bc.build_block(wrong_key, &pool);
        assert!(matches!(
            result,
            Err(StorageError::ValidationFailed(msg)) if msg.contains("unexpected proposer")
        ));
    }

    #[test]
    fn build_block_allows_progress_when_consensus_initialized_but_no_active_stake() {
        let genesis = create_genesis(TEST_CHAIN_ID);
        let storage = test_storage(genesis);

        let validator_key = PrivateKey::new();
        let validator_addr = validator_key.public_key().address();
        storage.set_account(validator_addr, Account::new(0));

        let mut pending_record = ValidatorRecord::new(validator_addr);
        pending_record
            .pending_activations
            .push(crate::core::consensus::PendingActivation {
                amount: 10_000,
                activate_height: default_staking_params().bonding_period_blocks + 1,
            });

        let set = ValidatorSetSnapshot {
            tracked_validators: vec![validator_addr],
            validators: vec![],
            total_active_stake: 0,
        };
        seed_consensus_state(
            &storage,
            ConsensusState {
                last_processed_height: 0,
                total_active_stake: 0,
                randomness_seed: Hash::zero(),
            },
            set,
            &[pending_record],
        );

        let bc = with_validator_and_storage(TEST_CHAIN_ID, AcceptAllValidator, storage);
        let pool = TxPool::new(Some(2), TEST_CHAIN_ID);
        let block = bc
            .build_block(validator_key, &pool)
            .expect("bootstrap grace should allow progress while stake is bonding");

        assert_eq!(block.header.height, 1);
    }

    // ==================== replay_from_last_snapshot Tests ====================

    mod replay_tests {
        use super::*;
        use crate::core::blockchain::Blockchain;
        use crate::core::validator::BlockValidator;
        use crate::network::server::DEV_CHAIN_ID;
        use crate::network::server::tests::test_db;
        use crate::storage::rocksdb_storage::{RocksDbStorage, SNAPSHOT_INTERVAL};
        use crate::storage::txpool::TxPool;

        /// Creates a blockchain with a single validator account.
        fn make_chain(validator_key: &PrivateKey) -> Blockchain<BlockValidator, RocksDbStorage> {
            let validator_account = (validator_key.public_key().address(), Account::new(0));
            let initial = [validator_account];
            let genesis = crate::network::server::Server::<
                crate::network::local_transport::tests::LocalTransport,
            >::genesis_block(DEV_CHAIN_ID, &initial);
            Blockchain::new(DEV_CHAIN_ID, test_db(), genesis, &initial)
                .expect("failed to create chain")
        }

        /// Builds `n` empty blocks using the given validator key.
        fn build_n_blocks(
            chain: &Blockchain<BlockValidator, RocksDbStorage>,
            key: &PrivateKey,
            n: u64,
        ) {
            let pool = TxPool::new(Some(1), DEV_CHAIN_ID);
            for _ in 0..n {
                chain
                    .build_block(key.clone(), &pool)
                    .expect("build_block failed");
            }
        }

        #[test]
        fn replay_restores_height_tip_root_and_account_state() {
            let key = PrivateKey::new();
            let chain = make_chain(&key);
            let validator_addr = key.public_key().address();

            build_n_blocks(&chain, &key, SNAPSHOT_INTERVAL + 2);
            let original_height = chain.height();

            let tip_before = chain.storage_tip();
            let root_before = chain.state_root();
            let balance_before = chain
                .get_account(validator_addr)
                .expect("validator account should exist")
                .balance();

            let reached = chain.replay_from_last_snapshot().expect("replay failed");

            assert_eq!(reached, original_height);
            assert_eq!(chain.height(), original_height);
            assert_eq!(chain.storage_tip(), tip_before);
            assert_eq!(chain.state_root(), root_before);
            assert_eq!(
                chain
                    .get_account(validator_addr)
                    .expect("account missing")
                    .balance(),
                balance_before
            );
        }

        #[test]
        fn replay_fails_without_snapshot() {
            let key = PrivateKey::new();
            let chain = make_chain(&key);

            // Fewer blocks than SNAPSHOT_INTERVAL — no snapshot created.
            build_n_blocks(&chain, &key, 2);

            let result = chain.replay_from_last_snapshot();
            assert!(result.is_err());
        }

        #[test]
        fn replay_succeeds_across_pruning_boundary() {
            let key = PrivateKey::new();
            let chain = make_chain(&key);

            // SNAPSHOT_INTERVAL=10, BLOCK_BODY_RETENTION=30.
            // At height 31 block 1 is pruned. Snapshots exist at 20 and 30.
            // Replay should use snapshot 30 and re-apply blocks 31-35.
            build_n_blocks(&chain, &key, 35);
            let root_before = chain.state_root();

            let reached = chain.replay_from_last_snapshot().expect("replay failed");

            assert_eq!(reached, 35);
            assert_eq!(chain.state_root(), root_before);
        }
    }
}
