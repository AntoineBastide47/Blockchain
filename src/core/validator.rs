//! Block validation logic and consensus rules.
//!
//! Provides the [`Validator`] trait for custom validation strategies
//! and [`BlockValidator`] as the default implementation.

use crate::core::block::Block;
use crate::core::storage::Storage;
use std::error::Error;
use std::fmt::Debug;

/// Trait for validating blocks before they are added to the chain.
///
/// Implementations must be thread-safe for concurrent validation.
pub trait Validator: Send + Sync {
    type Error: Debug + Error;

    /// Validates a block against the current chain state.
    ///
    /// # Arguments
    ///
    /// * `block` - The block to validate.
    /// * `storage` - Current chain state for context.
    ///
    /// # Returns
    ///
    /// `true` if the block is valid and can be added to the chain.
    fn validate_block<S: Storage>(&self, block: &Block, storage: &S) -> Result<(), Self::Error>;
}

/// Default block validator implementing consensus rules.
///
/// Validates:
/// - Block height is exactly one greater than current tip.
/// - Previous block hash matches current tip.
/// - Block hash is not already in storage.
/// - Block signature is valid.
#[derive(Clone, Default)]
pub struct BlockValidator;

/// Errors that can occur during block validation operations.
#[derive(Debug, thiserror::Error)]
pub enum BlockValidatorError {
    #[error("invalid block height: expected {expected}, got {actual}")]
    InvalidHeight { expected: u32, actual: u32 },

    #[error("previous block hash mismatch")]
    PreviousHashMismatch,

    #[error("block already exists")]
    BlockExists,

    #[error("invalid block signature")]
    InvalidSignature,
}

impl Validator for BlockValidator {
    type Error = BlockValidatorError;
    fn validate_block<S: Storage>(&self, block: &Block, storage: &S) -> Result<(), Self::Error> {
        let expected_height = storage.height().checked_add(1);
        if expected_height != Some(block.header.height) {
            return Err(BlockValidatorError::InvalidHeight {
                expected: expected_height.unwrap_or(0),
                actual: block.header.height,
            });
        }

        if block.header.previous_block != storage.tip() {
            return Err(BlockValidatorError::PreviousHashMismatch);
        }

        if storage.has_block(block.header_hash) {
            return Err(BlockValidatorError::BlockExists);
        }

        if !block.verify() {
            return Err(BlockValidatorError::InvalidSignature);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::block::{Block, Header};
    use crate::core::storage::InMemoryStorage;
    use crate::crypto::key_pair::PrivateKey;
    use crate::test_utils::utils::create_genesis;
    use crate::types::hash::Hash;
    use std::sync::Arc;

    fn create_block(height: u32, previous: Hash) -> Arc<Block> {
        let header = Header {
            version: 1,
            height,
            timestamp: 0,
            previous_block: previous,
            data_hash: Hash::random(),
            merkle_root: Hash::zero(),
        };
        Block::new(header, PrivateKey::new(), vec![]).unwrap()
    }

    #[test]
    fn valid_block_accepted() {
        let genesis = create_genesis();
        let storage = InMemoryStorage::new(genesis.clone());
        let validator = BlockValidator;

        let block = create_block(1, genesis.header_hash);
        assert!(validator.validate_block(&block, &storage).is_ok());
    }

    #[test]
    fn wrong_height_rejected() {
        let genesis = create_genesis();
        let storage = InMemoryStorage::new(genesis.clone());
        let validator = BlockValidator;

        let block = create_block(5, genesis.header_hash);
        assert!(validator.validate_block(&block, &storage).is_err());
    }

    #[test]
    fn wrong_previous_hash_rejected() {
        let genesis = create_genesis();
        let storage = InMemoryStorage::new(genesis.clone());
        let validator = BlockValidator;

        let block = create_block(1, Hash::random());
        assert!(validator.validate_block(&block, &storage).is_err());
    }

    #[test]
    fn empty_storage_rejected() {
        let storage = EmptyStorage;
        let validator = BlockValidator;

        let block = create_block(0, Hash::zero());
        assert!(validator.validate_block(&block, &storage).is_err());
    }

    struct EmptyStorage;
    impl Storage for EmptyStorage {
        fn has_block(&self, _: Hash) -> bool {
            false
        }
        fn get_header(&self, _: Hash) -> Option<Header> {
            None
        }
        fn get_block(&self, _: Hash) -> Option<Arc<Block>> {
            None
        }
        fn append_block(&mut self, _: Arc<Block>) {}
        fn height(&self) -> u32 {
            0
        }
        fn tip(&self) -> Hash {
            Hash::zero()
        }
    }
}
