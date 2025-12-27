//! Core blockchain data structure and block management.

use crate::core::block::{Block, Header};
use crate::core::storage::{Storage, ThreadSafeMemoryStorage};
use crate::core::transaction::Transaction;
use crate::core::validator::{BlockValidator, Validator};
use crate::crypto::key_pair::PrivateKey;
use crate::types::binary_codec::BinaryCodecHash;
use crate::types::hash::Hash;
use crate::utils::log::Logger;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// The main blockchain structure holding headers and validation logic.
///
/// Generic over validator and storage types for zero-cost abstraction.
pub struct Blockchain<V: Validator, S: Storage> {
    /// Block storage backend.
    storage: S,
    /// Block validator for consensus rules.
    validator: V,
    /// Logger for chain operations.
    logger: Logger,
}

impl Blockchain<BlockValidator, ThreadSafeMemoryStorage> {
    /// Creates a new blockchain with default validator and in-memory storage.
    pub fn new(genesis: Arc<Block>, logger: Logger) -> Self {
        logger.info(&format!(
            "adding a new block to the chain: height={} hash={} transactions={}",
            genesis.header.height,
            genesis.header_hash,
            genesis.transactions.len()
        ));

        Self {
            storage: ThreadSafeMemoryStorage::new(genesis),
            validator: BlockValidator,
            logger,
        }
    }
}

impl<V: Validator, S: Storage> Blockchain<V, S> {
    /// Returns the height of the chain.
    pub fn height(&self) -> u32 {
        self.storage.height()
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
    pub fn build_block(&self, validator: PrivateKey, transactions: Vec<Transaction>) -> Arc<Block> {
        let tip = self.storage.tip();
        let height = self.storage.height() + 1;
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);

        let header = Header {
            version: 1,
            height,
            timestamp,
            previous_block: tip,
            data_hash: transactions.hash(),
            merkle_root: Hash::zero(),
        };

        Block::new(header, validator, transactions)
    }

    /// Attempts to add a block to the chain.
    ///
    /// Returns `true` if the block passes validation, `false` otherwise.
    pub fn add_block(&self, block: Arc<Block>) -> bool {
        match self
            .validator
            .validate_block(&block, &self.storage, &self.logger)
        {
            Ok(_) => {
                self.logger.info(&format!(
                    "adding a new block to the chain: height={} hash={} transactions={}",
                    block.header.height,
                    block.header_hash,
                    block.transactions.len()
                ));

                self.storage.append_block(block).is_ok()
            }
            Err(err) => {
                self.logger.warn(&format!(
                    "block rejected: hash={} error={}",
                    block.header_hash, err
                ));
                false
            }
        }
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

    fn test_logger() -> Logger {
        Logger::new("test")
    }

    /// Creates a new blockchain with custom validator and storage.
    pub fn with_validator_and_storage<V: Validator, S: Storage>(
        validator: V,
        storage: S,
        logger: Logger,
    ) -> Blockchain<V, S> {
        Blockchain {
            storage,
            validator,
            logger,
        }
    }

    pub fn add_block_mut<V: Validator, S: Storage + StorageExtForTests>(
        chain: &mut Blockchain<V, S>,
        block: Arc<Block>,
    ) -> bool {
        match chain
            .validator
            .validate_block(&block, &chain.storage, &chain.logger)
        {
            Ok(_) => {
                chain.logger.info(&format!(
                    "adding a new block to the chain: height={} hash={} transactions={}",
                    block.header.height,
                    block.header_hash,
                    block.transactions.len()
                ));

                chain.storage.append_block_mut(block);
                true
            }
            Err(err) => {
                chain.logger.warn(&format!(
                    "block rejected: hash={} error={}",
                    block.header_hash, err
                ));
                false
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
        ) -> Result<(), Self::Error> {
            Err(TestError::Dummy)
        }
    }

    fn create_header(height: u32, previous: Hash) -> Header {
        Header {
            version: 1,
            height,
            timestamp: 0,
            previous_block: previous,
            data_hash: random_hash(),
            merkle_root: Hash::zero(),
        }
    }

    #[test]
    fn new_creates_blockchain_with_genesis() {
        let block = create_genesis();
        let hash = block.header_hash;
        let bc = Blockchain::new(block, test_logger());
        assert_eq!(bc.height(), 0);
        assert!(bc.get_block(hash).is_some());
    }

    #[test]
    fn height_increases_with_blocks() {
        let genesis = create_genesis();
        let storage = TestStorage::new(genesis.clone());
        let mut bc = with_validator_and_storage(AcceptAllValidator, storage, test_logger());

        let block1 = Block::new(
            create_header(1, bc.storage.tip()),
            PrivateKey::new(),
            vec![],
        );

        assert!(add_block_mut(&mut bc, block1));
        assert_eq!(bc.height(), 1);
    }

    #[test]
    fn add_block_respects_validator() {
        let genesis = create_genesis();
        let mut accept_bc = with_validator_and_storage(
            AcceptAllValidator,
            TestStorage::new(genesis.clone()),
            test_logger(),
        );
        let mut reject_bc = with_validator_and_storage(
            RejectAllValidator,
            TestStorage::new(genesis.clone()),
            test_logger(),
        );

        let block = Block::new(
            create_header(1, genesis.header_hash),
            PrivateKey::new(),
            vec![],
        );

        assert!(add_block_mut(&mut accept_bc, block.clone()));
        assert!(!add_block_mut(&mut reject_bc, block));
    }

    #[test]
    fn add_blocks() {
        let genesis = create_genesis();
        let mut bc = with_validator_and_storage(
            AcceptAllValidator,
            TestStorage::new(genesis.clone()),
            test_logger(),
        );

        let block_count = 100;
        for _i in 1..=block_count {
            let block = bc.build_block(PrivateKey::new(), vec![]);
            assert!(add_block_mut(&mut bc, block));
        }

        assert_eq!(bc.height(), block_count);

        let block = bc.build_block(PrivateKey::new(), vec![]);
        assert!(add_block_mut(&mut bc, block));
        assert_eq!(bc.height(), block_count + 1);
    }
}
