//! Block validation logic and consensus rules.
//!
//! Provides the [`Validator`] trait for custom validation strategies
//! and [`BlockValidator`] as the default implementation.

use crate::core::block::Block;
use crate::core::transaction::Transaction;
use crate::crypto::key_pair::Address;
use crate::storage::state_store::AccountStorage;
use crate::storage::storage_trait::Storage;
use crate::types::hash::Hash;
use blockchain_derive::Error;
use std::error::Error;
use std::fmt::Debug;

/// Trait for validating blocks before they are added to the chain.
///
/// Implementations must be thread-safe for concurrent validation.
pub trait Validator: Send + Sync {
    type Error: Debug + Error;

    fn validate_tx<S: AccountStorage>(
        &self,
        transaction: &Transaction,
        storage: &S,
        chain_id: u64,
    ) -> Result<(), Self::Error>;

    /// Validates a block against the current chain storage.
    ///
    /// # Arguments
    ///
    /// * `block` - The block to validate.
    /// * `storage` - Current chain storage for context.
    /// * `logger` - Logger for validation messages.
    /// * `chain_id` - Chain identifier for transaction signature verification.
    ///
    /// # Returns
    ///
    /// `Ok(())` if the block is valid and can be added to the chain.
    fn validate_block<S: Storage>(
        &self,
        block: &Block,
        storage: &S,
        chain_id: u64,
    ) -> Result<(), Self::Error>;
}

/// Errors that can occur during block validation operations.
#[derive(Debug, Error)]
pub enum BlockValidatorError {
    #[error("invalid block height: expected {expected}, got {actual}")]
    InvalidHeight { expected: u64, actual: u64 },
    #[error("previous block hash mismatch")]
    PreviousHashMismatch,
    #[error("block already exists")]
    BlockExists,
    #[error("invalid block signature: block={0}")]
    InvalidSignature(Hash),
    #[error("invalid transaction signature in block: block={0}")]
    InvalidTransactionSignature(Hash),
    #[error("invalid merkle root in block: block={0}")]
    InvalidMerkleRoot(Hash),
    #[error("nonce mismatch: expected {expected}, got {actual}")]
    NonceMismatch { expected: u64, actual: u64 },
    #[error("insufficient balance: balance={balance}, required={required}")]
    InsufficientBalance { balance: u128, required: u128 },
    #[error("invalid gas limit")]
    InvalidGasLimit,
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
    type Error = BlockValidatorError;

    fn validate_tx<S: AccountStorage>(
        &self,
        transaction: &Transaction,
        storage: &S,
        chain_id: u64,
    ) -> Result<(), Self::Error> {
        if !transaction.verify(chain_id) {
            return Err(BlockValidatorError::InvalidTransactionSignature(
                transaction.id(chain_id),
            ));
        }

        if transaction.gas_limit == 0 {
            return Err(BlockValidatorError::InvalidGasLimit);
        }

        let sender: Address = transaction.from.address();
        let account = storage.get_account(sender);
        let (balance, expected_nonce) = match account {
            Some(acc) => (acc.balance(), acc.nonce()),
            None => (0, 0),
        };

        if transaction.nonce != expected_nonce {
            return Err(BlockValidatorError::NonceMismatch {
                expected: expected_nonce,
                actual: transaction.nonce,
            });
        }

        let required = transaction.amount.saturating_add(transaction.fee);
        if balance < required {
            return Err(BlockValidatorError::InsufficientBalance { balance, required });
        }

        Ok(())
    }

    fn validate_block<S: Storage>(
        &self,
        block: &Block,
        storage: &S,
        chain_id: u64,
    ) -> Result<(), Self::Error> {
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

        if storage.has_block(block.header_hash(chain_id)) {
            return Err(BlockValidatorError::BlockExists);
        }

        block.verify(chain_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::account::Account;
    use crate::core::block::{Block, Header};
    use crate::core::transaction::TransactionType;
    use crate::crypto::key_pair::PrivateKey;
    use crate::storage::storage_trait::StorageError;
    use crate::storage::test_storage::test::TestStorage;
    use crate::types::bytes::Bytes;
    use crate::types::hash::Hash;
    use crate::utils::test_utils::utils::{create_genesis, create_test_block, new_tx, random_hash};
    use std::sync::Arc;

    const TEST_CHAIN_ID: u64 = 872539;

    #[test]
    fn valid_block_accepted() {
        let genesis = create_genesis(TEST_CHAIN_ID);
        let storage = TestStorage::new(genesis.clone(), TEST_CHAIN_ID);
        let validator = BlockValidator;

        let block = create_test_block(1, genesis.header_hash(TEST_CHAIN_ID), TEST_CHAIN_ID);
        assert!(
            validator
                .validate_block(&block, &storage, TEST_CHAIN_ID)
                .is_ok()
        );
    }

    #[test]
    fn wrong_height_rejected() {
        let genesis = create_genesis(TEST_CHAIN_ID);
        let storage = TestStorage::new(genesis.clone(), TEST_CHAIN_ID);
        let validator = BlockValidator;

        let block = create_test_block(5, genesis.header_hash(TEST_CHAIN_ID), TEST_CHAIN_ID);
        assert!(
            validator
                .validate_block(&block, &storage, TEST_CHAIN_ID)
                .is_err()
        );
    }

    #[test]
    fn wrong_previous_hash_rejected() {
        let genesis = create_genesis(TEST_CHAIN_ID);
        let storage = TestStorage::new(genesis.clone(), TEST_CHAIN_ID);
        let validator = BlockValidator;

        let block = create_test_block(1, random_hash(), TEST_CHAIN_ID);
        assert!(
            validator
                .validate_block(&block, &storage, TEST_CHAIN_ID)
                .is_err()
        );
    }

    #[test]
    fn empty_storage_rejected() {
        let storage = EmptyStorage;
        let validator = BlockValidator;

        let block = create_test_block(0, Hash::zero(), TEST_CHAIN_ID);
        assert!(
            validator
                .validate_block(&block, &storage, TEST_CHAIN_ID)
                .is_err()
        );
    }

    #[test]
    fn validate_tx_accepts_valid_signature() {
        let mut storage = TestStorage::new(create_genesis(TEST_CHAIN_ID), TEST_CHAIN_ID);
        let key = PrivateKey::new();
        let sender = key.public_key().address();
        storage.set_account(sender, Account::new(10_000));

        let tx = Transaction::new(
            Address::zero(),
            None,
            Bytes::new(b"ok"),
            5,
            1,
            0,
            1,
            0,
            key,
            TEST_CHAIN_ID,
            TransactionType::TransferFunds,
        );
        let validator = BlockValidator;
        assert!(validator.validate_tx(&tx, &storage, TEST_CHAIN_ID).is_ok());
    }

    #[test]
    fn validate_tx_rejects_invalid_signature() {
        let storage = TestStorage::new(create_genesis(TEST_CHAIN_ID), TEST_CHAIN_ID);
        let key1 = PrivateKey::new();
        let key2 = PrivateKey::new();
        let mut tx = new_tx(Bytes::new(b"bad"), key1, TEST_CHAIN_ID);
        tx.from = key2.public_key();

        let validator = BlockValidator;
        let err = validator
            .validate_tx(&tx, &storage, TEST_CHAIN_ID)
            .unwrap_err();
        assert!(matches!(
            err,
            BlockValidatorError::InvalidTransactionSignature(..)
        ));
    }

    #[test]
    fn validate_tx_rejects_nonce_mismatch() {
        let mut storage = TestStorage::new(create_genesis(TEST_CHAIN_ID), TEST_CHAIN_ID);
        let key = PrivateKey::new();
        let sender = key.public_key().address();
        storage.set_account(sender, Account::new(100));

        let tx = Transaction::new(
            Address::zero(),
            None,
            Bytes::new(b"payload"),
            0,
            0,
            0,
            1,
            1,
            key,
            TEST_CHAIN_ID,
            TransactionType::TransferFunds,
        );

        let validator = BlockValidator;
        let err = validator
            .validate_tx(&tx, &storage, TEST_CHAIN_ID)
            .unwrap_err();
        assert!(matches!(err, BlockValidatorError::NonceMismatch { .. }));
    }

    #[test]
    fn validate_tx_rejects_insufficient_balance() {
        let mut storage = TestStorage::new(create_genesis(TEST_CHAIN_ID), TEST_CHAIN_ID);
        let key = PrivateKey::new();
        let sender = key.public_key().address();
        storage.set_account(sender, Account::new(5));

        let tx = Transaction::new(
            Address::zero(),
            None,
            Bytes::new(b"pay"),
            10,
            1,
            0,
            1,
            0,
            key,
            TEST_CHAIN_ID,
            TransactionType::TransferFunds,
        );

        let validator = BlockValidator;
        let err = validator
            .validate_tx(&tx, &storage, TEST_CHAIN_ID)
            .unwrap_err();
        assert!(matches!(
            err,
            BlockValidatorError::InsufficientBalance { .. }
        ));
    }

    #[test]
    fn validate_tx_rejects_zero_gas_limit() {
        let mut storage = TestStorage::new(create_genesis(TEST_CHAIN_ID), TEST_CHAIN_ID);
        let key = PrivateKey::new();
        let sender = key.public_key().address();
        storage.set_account(sender, Account::new(100));

        let tx = new_tx(Bytes::new(b"gasless"), key, TEST_CHAIN_ID);
        let validator = BlockValidator;
        let err = validator
            .validate_tx(&tx, &storage, TEST_CHAIN_ID)
            .unwrap_err();
        assert!(matches!(err, BlockValidatorError::InvalidGasLimit));
    }

    struct EmptyStorage;
    impl Storage for EmptyStorage {
        fn new(_genesis: Block, _chain_id: u64) -> Self {
            Self
        }

        fn has_block(&self, _: Hash) -> bool {
            false
        }
        fn get_header(&self, _: Hash) -> Option<Header> {
            None
        }
        fn get_block(&self, _: Hash) -> Option<Arc<Block>> {
            None
        }
        fn append_block(&self, _: Block, _: u64) -> Result<(), StorageError> {
            Ok(())
        }
        fn height(&self) -> u64 {
            0
        }
        fn tip(&self) -> Hash {
            Hash::zero()
        }
    }
}
