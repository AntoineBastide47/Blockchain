//! Core blockchain data structure and block management.

use crate::core::block::{Block, Header};
use crate::core::storage::{InMemoryStorage, Storage};
use crate::core::transaction::Transaction;
use crate::core::validator::{BlockValidator, Validator};
use crate::crypto::key_pair::PrivateKey;
use crate::types::binary_codec::BinaryCodecHash;
use crate::types::hash::Hash;
use crate::{info, warn};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io;

/// The main blockchain structure holding headers and validation logic.
///
/// Generic over validator and storage types for zero-cost abstraction.
pub struct Blockchain<V: Validator, S: Storage> {
    pub storage: S,
    pub validator: V,
}

impl Blockchain<BlockValidator, InMemoryStorage> {
    // TODO: switch to non testing storage protocol
    /// Creates a new blockchain with default validator and in-memory storage.
    pub fn new(genesis: Arc<Block>) -> Self {
        Blockchain {
            storage: InMemoryStorage::new(genesis),
            validator: BlockValidator,
        }
    }
}

impl<V: Validator, S: Storage> Blockchain<V, S> {
    /// Creates a new blockchain with custom validator and storage.
    pub fn with_validator_and_storage(validator: V, storage: S) -> Self {
        Blockchain { storage, validator }
    }

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
    pub fn build_block(
        &self,
        validator: PrivateKey,
        transactions: Vec<Transaction>,
    ) -> io::Result<Arc<Block>> {
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
            data_hash: transactions.hash()?,
            merkle_root: Hash::zero(),
        };

        Block::new(header, validator, transactions)
    }

    /// Attempts to add a block to the chain.
    ///
    /// Returns `true` if the block passes validation, `false` otherwise.
    pub fn add_block(&mut self, block: Arc<Block>) -> bool {
        match self.validator.validate_block(&block, &self.storage) {
            Ok(_) => {
                info!(
                    "adding new block: height={}, hash={}",
                    block.header.height, block.header_hash
                );

                self.storage.append_block(block);
                true
            }
            Err(err) => {
                warn!("block rejected: hash={}, error={}", block.header_hash, err);
                false
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::block::Header;
    use crate::crypto::key_pair::PrivateKey;
    use crate::types::hash::Hash;
    use crate::utils::test_utils::utils::create_genesis;
    use thiserror::Error;

    #[derive(Debug, Error)]
    enum TestError {
        #[error("dummy error")]
        Dummy,
    }

    #[derive(Clone)]
    struct AcceptAllValidator;
    impl Validator for AcceptAllValidator {
        type Error = TestError;
        fn validate_block<S: Storage>(
            &self,
            _block: &Block,
            _storage: &S,
        ) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    #[derive(Clone)]
    struct RejectAllValidator;
    impl Validator for RejectAllValidator {
        type Error = TestError;
        fn validate_block<S: Storage>(
            &self,
            _block: &Block,
            _storage: &S,
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
            data_hash: Hash::random(),
            merkle_root: Hash::zero(),
        }
    }

    #[test]
    fn new_creates_blockchain_with_genesis() {
        let block = create_genesis();
        let hash = block.header_hash;
        let bc = Blockchain::new(block);
        assert_eq!(bc.height(), 0);
        assert!(bc.get_block(hash).is_some());
    }

    #[test]
    fn height_increases_with_blocks() {
        let genesis = create_genesis();
        let storage = InMemoryStorage::new(genesis.clone());
        let mut bc = Blockchain::with_validator_and_storage(AcceptAllValidator, storage);

        let block1 = Block::new(
            create_header(1, genesis.header_hash),
            PrivateKey::new(),
            vec![],
        )
        .unwrap();

        assert!(bc.add_block(block1));
        assert_eq!(bc.height(), 1);
    }

    #[test]
    fn add_block_respects_validator() {
        let genesis = create_genesis();
        let mut accept_bc = Blockchain::with_validator_and_storage(
            AcceptAllValidator,
            InMemoryStorage::new(genesis.clone()),
        );
        let mut reject_bc = Blockchain::with_validator_and_storage(
            RejectAllValidator,
            InMemoryStorage::new(genesis.clone()),
        );

        let block = Block::new(
            create_header(1, genesis.header_hash),
            PrivateKey::new(),
            vec![],
        )
        .unwrap();

        assert!(accept_bc.add_block(block.clone()));
        assert!(!reject_bc.add_block(block));
    }

    #[test]
    fn add_blocks() {
        let genesis = create_genesis();
        let mut bc = Blockchain::with_validator_and_storage(
            AcceptAllValidator,
            InMemoryStorage::new(genesis.clone()),
        );

        let block_count = 100;
        for _i in 1..=block_count {
            let block = bc.build_block(PrivateKey::new(), vec![]).unwrap();
            assert!(bc.add_block(block));
        }

        assert_eq!(bc.height(), block_count);

        let block = bc.build_block(PrivateKey::new(), vec![]).unwrap();
        assert!(bc.add_block(block));
        assert_eq!(bc.height(), block_count + 1);
    }
}
