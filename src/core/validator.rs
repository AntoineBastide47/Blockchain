//! Block validation logic and consensus rules.
//!
//! Provides the [`Validator`] trait for custom validation strategies
//! and [`BlockValidator`] as the default implementation.

use crate::core::block::Block;
use crate::core::storage::Storage;

/// Trait for validating blocks before they are added to the chain.
///
/// Implementations must be thread-safe for concurrent validation.
pub trait Validator: Send + Sync {
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
    fn validate_block<S: Storage>(&self, block: &Block, storage: &S) -> bool;
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

impl Validator for BlockValidator {
    fn validate_block<S: Storage>(&self, block: &Block, storage: &S) -> bool {
        storage.height().checked_add(1) == Some(block.header.height)
            && block.header.previous_block == storage.tip()
            && !storage.has_block(&block.header_hash)
            && block.verify()
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
        assert!(validator.validate_block(&block, &storage));
    }

    #[test]
    fn wrong_height_rejected() {
        let genesis = create_genesis();
        let storage = InMemoryStorage::new(genesis.clone());
        let validator = BlockValidator;

        let block = create_block(5, genesis.header_hash);
        assert!(!validator.validate_block(&block, &storage));
    }

    #[test]
    fn wrong_previous_hash_rejected() {
        let genesis = create_genesis();
        let storage = InMemoryStorage::new(genesis.clone());
        let validator = BlockValidator;

        let block = create_block(1, Hash::random());
        assert!(!validator.validate_block(&block, &storage));
    }

    #[test]
    fn empty_storage_rejected() {
        let storage = EmptyStorage;
        let validator = BlockValidator;

        let block = create_block(0, Hash::zero());
        assert!(!validator.validate_block(&block, &storage));
    }

    struct EmptyStorage;
    impl Storage for EmptyStorage {
        fn has_block(&self, _: &Hash) -> bool {
            false
        }
        fn get_header(&self, _: &Hash) -> Option<Header> {
            None
        }
        fn get_block(&self, _: &Hash) -> Option<Arc<Block>> {
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
