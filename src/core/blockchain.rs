//! Core blockchain data structure and block management.

use crate::core::block::{Block, Header};
use crate::core::storage::{
    IterableState, StateStore, StateViewProvider, Storage, StorageError, ThreadSafeMemoryStorage,
};
use crate::core::transaction::Transaction;
use crate::core::validator::{BlockValidator, Validator};
use crate::crypto::key_pair::PrivateKey;
use crate::types::encoding::Encode;
use crate::types::hash::Hash;
use crate::utils::log::Logger;
use crate::virtual_machine::errors::VMError;
use crate::virtual_machine::program::Program;
use crate::virtual_machine::state::{OverlayState, State};
use crate::virtual_machine::vm::{ExecContext, VM};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// The main blockchain structure holding headers and validation logic.
///
/// Generic over validator and storage types for zero-cost abstraction.
pub struct Blockchain<V: Validator, S: Storage + StateStore + IterableState + StateViewProvider> {
    /// Chain identifier.
    pub id: u64,
    /// Block validator for consensus rules.
    validator: V,
    /// Block storage backend.
    storage: S,
    /// Logger for chain operations.
    logger: Logger,
}

impl Blockchain<BlockValidator, ThreadSafeMemoryStorage> {
    /// Creates a new blockchain with default validator and in-memory storage.
    ///
    /// The `id` parameter is the chain identifier used for transaction signing
    /// and verification, preventing replay attacks across different chains.
    pub fn new(id: u64, genesis: Arc<Block>, logger: Logger) -> Self {
        logger.info(&format!(
            "adding a new block to the chain: height={} hash={} transactions={}",
            genesis.header.height,
            genesis.header_hash(id),
            genesis.transactions.len()
        ));

        Self {
            id,
            storage: ThreadSafeMemoryStorage::new(genesis, id),
            validator: BlockValidator,
            logger,
        }
    }
}

impl<V: Validator, S: Storage + StateStore + IterableState + StateViewProvider> Blockchain<V, S> {
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

    /// Builds a new block linked to the current tip.
    ///
    /// Automatically sets the correct `previous_block` hash and `height`.
    pub fn build_block(
        &self,
        validator: PrivateKey,
        transactions: Vec<Transaction>,
    ) -> Result<Arc<Block>, VMError> {
        let base_state = self.storage.state_view();
        let mut overlay = OverlayState::new(&base_state);

        for tx in &transactions {
            let program = Program::from_bytes(tx.data.as_slice())
                .map_err(|e| VMError::DecodeError(e.to_string()))?;
            let mut vm = VM::new(program);

            let contract_bytes = tx.from.to_bytes();
            let ctx = ExecContext {
                chain_id: self.id,
                contract_id: contract_bytes.as_slice(), // TODO: use real smart contract id
            };
            vm.run(&mut overlay, &ctx)?;
        }

        let header = Header {
            version: 1,
            height: self.storage.height() + 1,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0),
            previous_block: self.storage.tip(),
            data_hash: Hash::zero(),
            merkle_root: Hash::zero(),
            state_root: Self::compute_state_root(&self.storage, &overlay),
        };

        Ok(Block::new(header, validator, transactions, self.id))
    }

    /// Attempts to add a block to the chain.
    ///
    /// Returns an error if validation or storage persistence fails.
    pub fn add_block(&self, block: Arc<Block>) -> Result<(), StorageError> {
        let hash = block.header_hash(self.id);
        if self.has_block(hash) {
            return Err(StorageError::ValidationFailed(
                "block already exists".into(),
            ));
        }

        self.validator
            .validate_block(&block, &self.storage, &self.logger, self.id)
            .map_err(|e| StorageError::ValidationFailed(e.to_string()))?;

        self.logger.info(&format!(
            "adding a new block to the chain: height={} hash={} transactions={}",
            block.header.height,
            block.header_hash(self.id),
            block.transactions.len()
        ));

        let base = self.storage.state_view();
        let mut block_overlay = OverlayState::new(&base);

        // Run VM code
        for tx in &block.transactions {
            let program = Program::from_bytes(tx.data.as_slice())
                .map_err(|e| StorageError::VMError(e.to_string()))?;
            let mut vm = VM::new(program);
            let contract_bytes = tx.from.to_bytes();
            let ctx = ExecContext {
                chain_id: self.id,
                contract_id: contract_bytes.as_slice(), // TODO: use real smart contract id
            };

            // Execute tx in its own overlay, reading from current block overlay
            let mut tx_overlay = OverlayState::new(&block_overlay);
            vm.run(&mut tx_overlay, &ctx)
                .map_err(|e| StorageError::VMError(e.to_string()))?;

            // Merge tx writes into block overlay
            for (k, v) in tx_overlay.into_writes() {
                match v {
                    Some(val) => block_overlay.push(k, val),
                    None => block_overlay.delete(k),
                }
            }
        }

        // Compute expected post-state root deterministically
        let computed_root = Self::compute_state_root(&self.storage, &block_overlay);
        if computed_root != block.header.state_root {
            return Err(StorageError::ValidationFailed("state_root mismatch".into()));
        }

        // Commit writes to canonical state store
        self.storage.apply_batch(block_overlay.into_writes());
        self.storage.set_state_root(computed_root);

        self.storage.append_block(block, self.id)
    }

    fn compute_state_root(base: &S, overlay: &OverlayState<'_>) -> Hash {
        use std::collections::BTreeMap;

        // Materialize into deterministic map
        let mut m: BTreeMap<Hash, Vec<u8>> = BTreeMap::new();

        // Dev-only: you need an iterator for base state.
        // In memory you can expose it; for production you replace this with an SMT.
        for (k, v) in base.iter_all() {
            // add iter_all only to dev state
            m.insert(k, v);
        }

        for (k, opt_v) in overlay.writes.iter() {
            match opt_v {
                Some(v) => {
                    m.insert(*k, v.clone());
                }
                None => {
                    m.remove(k);
                }
            }
        }

        // Hash the sorted key-value list
        let mut h = Hash::sha3();
        h.update(b"STATE_ROOT");
        for (k, v) in m {
            k.encode(&mut h);
            v.encode(&mut h);
        }
        h.finalize()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::block::Header;
    use crate::core::storage::tests::{StorageExtForTests, TestStorage};
    use crate::crypto::key_pair::PrivateKey;
    use crate::types::hash::Hash;
    use crate::utils::test_utils::utils::{create_genesis, random_hash};
    use blockchain_derive::Error;

    const TEST_CHAIN_ID: u64 = 93;

    fn test_logger() -> Logger {
        Logger::new("test")
    }

    /// Creates a new blockchain with custom validator and storage.
    pub fn with_validator_and_storage<
        V: Validator,
        S: Storage + StateStore + IterableState + StateViewProvider,
    >(
        id: u64,
        validator: V,
        storage: S,
        logger: Logger,
    ) -> Blockchain<V, S> {
        Blockchain {
            id,
            storage,
            validator,
            logger,
        }
    }

    pub fn add_block_mut<
        V: Validator,
        S: Storage + StateStore + IterableState + StorageExtForTests + StateViewProvider,
    >(
        chain: &mut Blockchain<V, S>,
        block: Arc<Block>,
    ) -> Result<(), StorageError> {
        match chain
            .validator
            .validate_block(&block, &chain.storage, &chain.logger, TEST_CHAIN_ID)
        {
            Ok(_) => {
                chain.logger.info(&format!(
                    "adding a new block to the chain: height={} hash={} transactions={}",
                    block.header.height,
                    block.header_hash(chain.id),
                    block.transactions.len()
                ));

                chain.storage.append_block_mut(block, chain.id);
                Ok(())
            }
            Err(err) => {
                chain.logger.warn(&format!(
                    "block rejected: hash={} error={}",
                    block.header_hash(chain.id),
                    err
                ));
                Err(StorageError::ValidationFailed(err.to_string()))
            }
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
        fn validate_block<S: Storage>(
            &self,
            _block: &Block,
            _storage: &S,
            _logger: &Logger,
            _chain_id: u64,
        ) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    struct RejectAllValidator;
    impl Validator for RejectAllValidator {
        type Error = TestError;
        fn validate_block<S: Storage>(
            &self,
            _block: &Block,
            _storage: &S,
            _logger: &Logger,
            _chain_id: u64,
        ) -> Result<(), Self::Error> {
            Err(TestError::Dummy)
        }
    }

    fn create_header(height: u64, previous: Hash) -> Header {
        Header {
            version: 1,
            height,
            timestamp: 0,
            previous_block: previous,
            data_hash: random_hash(),
            merkle_root: Hash::zero(),
            state_root: random_hash(),
        }
    }

    #[test]
    fn new_creates_blockchain_with_genesis() {
        let block = create_genesis(TEST_CHAIN_ID);
        let hash = block.header_hash(TEST_CHAIN_ID);
        let bc = Blockchain::new(TEST_CHAIN_ID, block, test_logger());
        assert_eq!(bc.height(), 0);
        assert!(bc.get_block(hash).is_some());
    }

    #[test]
    fn height_increases_with_blocks() {
        let genesis = create_genesis(TEST_CHAIN_ID);
        let storage = TestStorage::new(genesis.clone(), TEST_CHAIN_ID);
        let mut bc =
            with_validator_and_storage(TEST_CHAIN_ID, AcceptAllValidator, storage, test_logger());

        let block1 = Block::new(
            create_header(1, bc.storage.tip()),
            PrivateKey::new(),
            vec![],
            TEST_CHAIN_ID,
        );

        assert!(add_block_mut(&mut bc, block1).is_ok());
        assert_eq!(bc.height(), 1);
    }

    #[test]
    fn add_block_respects_validator() {
        let genesis = create_genesis(TEST_CHAIN_ID);
        let mut accept_bc = with_validator_and_storage(
            TEST_CHAIN_ID,
            AcceptAllValidator,
            TestStorage::new(genesis.clone(), TEST_CHAIN_ID),
            test_logger(),
        );
        let mut reject_bc = with_validator_and_storage(
            TEST_CHAIN_ID,
            RejectAllValidator,
            TestStorage::new(genesis.clone(), TEST_CHAIN_ID),
            test_logger(),
        );

        let block = Block::new(
            create_header(1, genesis.header_hash(TEST_CHAIN_ID)),
            PrivateKey::new(),
            vec![],
            TEST_CHAIN_ID,
        );

        assert!(add_block_mut(&mut accept_bc, block.clone()).is_ok());
        assert!(add_block_mut(&mut reject_bc, block).is_err());
    }

    #[test]
    fn add_blocks() {
        let genesis = create_genesis(TEST_CHAIN_ID);
        let mut bc = with_validator_and_storage(
            TEST_CHAIN_ID,
            AcceptAllValidator,
            TestStorage::new(genesis.clone(), TEST_CHAIN_ID),
            test_logger(),
        );

        let block_count = 100;
        for _i in 1..=block_count {
            let block = bc.build_block(PrivateKey::new(), vec![]).expect("VMError:");
            assert!(add_block_mut(&mut bc, block).is_ok());
        }

        assert_eq!(bc.height(), block_count);

        let block = bc.build_block(PrivateKey::new(), vec![]).expect("VMError:");
        assert!(add_block_mut(&mut bc, block).is_ok());
        assert_eq!(bc.height(), block_count + 1);
    }
}
