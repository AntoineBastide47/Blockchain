//! Core blockchain data structure and block management.

use crate::core::account::Account;
use crate::core::block::{Block, Header};
use crate::core::transaction::{Transaction, TransactionType};
use crate::core::validator::{BlockValidator, Validator};
use crate::crypto::key_pair::{Address, PrivateKey};
use crate::info;
use crate::storage::main_storage::MainStorage;
use crate::storage::state_store::{AccountStorage, VmStorage};
use crate::storage::state_view::{StateView, StateViewProvider};
use crate::storage::storage_trait::{Storage, StorageError};
use crate::types::encoding::{Decode, Encode};
use crate::types::hash::Hash;
use crate::types::merkle_tree::MerkleTree;
use crate::virtual_machine::errors::VMError;
use crate::virtual_machine::program::Program;
use crate::virtual_machine::state::{OverlayState, State};
use crate::virtual_machine::vm::{ExecContext, TRANSACTION_GAS_LIMIT, VM};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

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

impl Blockchain<BlockValidator, MainStorage> {
    /// Creates a new blockchain with default validator and in-memory storage.
    ///
    /// The `id` parameter is the chain identifier used for transaction signing
    /// and verification, preventing replay attacks across different chains.
    pub fn new(id: u64, genesis: Block, initial_accounts: &[(Address, Account)]) -> Self {
        info!(
            "Initializing blockchain with genesis block: height={} hash={} transactions={}",
            genesis.header.height,
            genesis.header_hash(id),
            genesis.transactions.len()
        );

        Self {
            id,
            storage: MainStorage::new(genesis, id, initial_accounts),
            validator: BlockValidator,
        }
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

    /// Computes a deterministic contract identifier from a deployment transaction.
    ///
    /// The ID is derived from the sender, nonce, and bytecode, ensuring each
    /// deployment produces a unique address even with identical code.
    fn contract_id(transaction: &Transaction) -> Hash {
        let mut h = Hash::sha3();
        h.update(b"SMART_CONTRACT");
        transaction.from.encode(&mut h);
        transaction.nonce.encode(&mut h);
        transaction.data.encode(&mut h);
        h.finalize()
    }

    /// Executes a transaction based on its type and updates gas usage.
    ///
    /// Handles different transaction types: fund transfers, contract deployment, and
    /// contract invocation. For deployments, validates gas limits, initializes the VM
    /// with the contract bytecode, executes, and persists the contract account on success.
    fn execute_tx<T: State>(
        &self,
        transaction: &Transaction,
        tx_overlay: &mut OverlayState<T>,
        gas_used: &mut u64,
    ) -> Result<(), VMError> {
        match transaction.tx_type {
            TransactionType::TransferFunds => Err(VMError::OutOfGas { used: 0, limit: 0 }), // TODO
            TransactionType::DeployContract => {
                // TODO:
                // this isn't a deployment just a run of the contract and then the contract is discarded
                // So it needs to be stored on chain and the run data needs to be discarded (not account mutation)
                let program = Program::from_bytes(transaction.data.as_slice())?;

                // Make sure the maximum gas allowed by the user is in the correct range
                let max_gas = transaction.gas_limit;
                if max_gas > TRANSACTION_GAS_LIMIT {
                    return Err(VMError::OutOfGas {
                        used: max_gas,
                        limit: TRANSACTION_GAS_LIMIT,
                    });
                }

                let mut vm = VM::new(program, max_gas)?;
                let contract_id = Self::contract_id(transaction);
                let ctx = ExecContext {
                    chain_id: self.id,
                    contract_id,
                };

                // Execute tx in its own overlay, reading from current block overlay
                let result = vm.run(tx_overlay, &ctx);
                *gas_used = vm.gas_used();
                match result {
                    Ok(_) => {
                        tx_overlay.push(
                            contract_id,
                            Account::from(
                                transaction.nonce + 1,
                                0,
                                contract_id,
                                Account::EMPTY_STORAGE_ROOT,
                            )
                            .to_vec(),
                        );
                        // TODO: persist contract in storage
                        Ok(())
                    }
                    Err(e) => Err(e),
                }
            }
            TransactionType::InvokeContract => Err(VMError::OutOfGas { used: 0, limit: 0 }), // TODO
        }
    }

    /// Validates and executes a single transaction into the provided block overlay.
    ///
    /// Runs validator checks (signature, nonce, balance, gas) before decoding the
    /// program bytes and executing them in a per-tx overlay. The per-tx writes are
    /// merged into `block_overlay` only after successful execution.
    fn apply_tx(
        &self,
        transaction: &Transaction,
        block_overlay: &mut OverlayState<StateView<S>>,
    ) -> Result<(), StorageError> {
        if transaction.gas_price == 0 || transaction.gas_limit == 0 {
            return Err(StorageError::InvalidTransactionGasParams);
        }

        // Make sure an account exists for the sender
        let a_hash = transaction.from.address();
        let mut account = match block_overlay.get(a_hash) {
            Some(b) => Account::from_bytes(&b)?,
            None => self
                .storage
                .get_account(a_hash)
                .ok_or(StorageError::MissingAccount(a_hash))?,
        };

        // Make sure the account has enough funds if the gas limit is attained
        let user_total = transaction
            .gas_price
            .checked_mul(transaction.gas_limit as u128)
            .ok_or(StorageError::ArithmeticOverflow {
                gas_used: transaction.gas_limit,
                gas_price: transaction.gas_price,
            })?;
        if account.balance() < user_total {
            return Err(StorageError::InsufficientBalance {
                actual: account.balance(),
                expected: user_total,
            });
        }

        // Validate the transaction
        self.validator
            .validate_tx(transaction, &account, self.id)
            .map_err(|e| StorageError::ValidationFailed(e.to_string()))?;

        // Execute and compute gas usage
        let mut gas_used: u64 = 0;
        let mut tx_overlay = OverlayState::new(block_overlay);
        let transaction_result = self.execute_tx(transaction, &mut tx_overlay, &mut gas_used);

        // If the transaction failed: charge gas and skip the tx_overlay states
        account.increment_nonce();
        account.charge(transaction.gas_price.checked_mul(gas_used as u128).ok_or(
            StorageError::ArithmeticOverflow {
                gas_used,
                gas_price: transaction.gas_price,
            },
        )?)?;

        // Consume the writes so that block_overlay can be mutated
        let tx_writes = tx_overlay.into_writes();
        block_overlay.push(a_hash, account.to_bytes().to_vec());
        transaction_result?;

        // Merge tx writes into block overlay
        for (k, v) in tx_writes {
            match v {
                Some(val) => block_overlay.push(k, val),
                None => block_overlay.delete(k),
            }
        }

        Ok(())
    }

    /// Appends a block to storage and updates the chain tip (thread-safe).
    ///
    /// Logs an info message to notify the node owner
    fn append_block(&self, block: &Block) -> Result<(), StorageError> {
        self.storage.append_block(block.clone(), self.id)?;

        info!(
            "adding a new block to the chain: height={} hash={} transactions={}",
            block.header.height,
            block.header_hash(self.id),
            block.transactions.len()
        );

        Ok(())
    }

    /// Builds, executes, and commits a new block linked to the current tip.
    ///
    /// Executes all transactions, computes the state root, signs the block,
    /// commits state changes to storage, and appends the block to the chain.
    pub fn build_block(
        &self,
        validator: PrivateKey,
        transactions: Vec<Transaction>,
    ) -> Result<Block, StorageError> {
        // Executes all transactions in the block and computes the resulting state root.
        let base = self.storage.state_view();
        let mut block_overlay = OverlayState::new(&base);
        for tx in &transactions {
            self.apply_tx(tx, &mut block_overlay)?;
        }
        self.storage.apply_batch(block_overlay.into_writes());

        let header = Header {
            version: 1,
            height: self.storage.height() + 1,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0),
            previous_block: self.storage.tip(),
            merkle_root: MerkleTree::from_transactions(&transactions, self.id),
            state_root: self.storage.state_root(),
        };

        let block = Block::new(header, validator, transactions, self.id);
        self.append_block(&block)?;
        Ok(block)
    }

    /// Validates and applies an entire block to the chain state.
    ///
    /// Performs block-level validation, executes each transaction into a block
    /// overlay (after per-tx validation), checks the resulting state_root, then
    /// commits the writes and appends the block.
    pub fn apply_block(&self, block: Block) -> Result<(), StorageError> {
        let hash = block.header_hash(self.id);
        if self.has_block(hash) {
            return Err(StorageError::ValidationFailed(
                "block already exists".into(),
            ));
        }

        self.validator
            .validate_block(&block, &self.storage, self.id)
            .map_err(|e| StorageError::ValidationFailed(e.to_string()))?;

        let base = self.storage.state_view();
        let mut block_overlay = OverlayState::new(&base);

        for tx in &block.transactions {
            self.apply_tx(tx, &mut block_overlay)?;
        }

        // Compute expected post-storage root deterministically
        let writes = block_overlay.into_writes();
        let computed_root = self.storage.preview_root(&writes);
        if computed_root != block.header.state_root {
            return Err(StorageError::ValidationFailed(format!(
                "state_root mismatch: expected {} and got {computed_root}",
                block.header.state_root
            )));
        }

        self.storage.apply_batch(writes);
        self.append_block(&block)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::block::Header;
    use crate::crypto::key_pair::PrivateKey;
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
            Ok(_) => chain.storage.append_block(block, chain.id),
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
            previous_block: previous,
            merkle_root: Hash::zero(),
            state_root: random_hash(),
        }
    }

    fn test_storage(block: Block) -> TestStorage {
        TestStorage::new(block, TEST_CHAIN_ID, &[])
    }

    #[test]
    fn new_creates_blockchain_with_genesis() {
        let block = create_genesis(TEST_CHAIN_ID);
        let hash = block.header_hash(TEST_CHAIN_ID);
        let bc = Blockchain::new(TEST_CHAIN_ID, block, &[]);
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
        let bc = with_validator_and_storage(
            TEST_CHAIN_ID,
            AcceptAllValidator,
            test_storage(genesis.clone()),
        );

        let block_count = 100;
        for _i in 1..=block_count {
            bc.build_block(PrivateKey::new(), vec![])
                .expect("build_block failed");
        }

        assert_eq!(bc.height(), block_count);

        bc.build_block(PrivateKey::new(), vec![])
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

        let bc = with_validator_and_storage(TEST_CHAIN_ID, RejectingTxValidator, storage);

        let mut tx = new_tx(Bytes::new(b"any"), key, TEST_CHAIN_ID);
        tx.gas_limit = 1;
        tx.gas_price = 1;

        let header = Header {
            version: 1,
            height: 1,
            timestamp: 0,
            previous_block: genesis.header_hash(TEST_CHAIN_ID),
            merkle_root: MerkleTree::from_transactions(std::slice::from_ref(&tx), TEST_CHAIN_ID),
            state_root: random_hash(),
        };
        let block = Block::new(header, PrivateKey::new(), vec![tx], TEST_CHAIN_ID);

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
        tx.gas_limit = 1;
        tx.gas_price = 1;
        let base = bc.storage.state_view();
        let mut overlay = OverlayState::new(&base);

        let result = bc.apply_tx(&tx, &mut overlay);
        assert!(matches!(result, Err(StorageError::MissingAccount(_))));
    }

    #[test]
    fn apply_tx_rejects_insufficient_balance_for_gas() {
        let genesis = create_genesis(TEST_CHAIN_ID);
        let storage = test_storage(genesis);

        let key = PrivateKey::new();
        let sender = key.public_key().address();
        storage.set_account(sender, Account::new(100));

        let bc = with_validator_and_storage(TEST_CHAIN_ID, AcceptAllValidator, storage);

        let mut tx = new_tx(Bytes::new(b"data"), key, TEST_CHAIN_ID);
        tx.gas_limit = 1000;
        tx.gas_price = 1;

        let base = bc.storage.state_view();
        let mut overlay = OverlayState::new(&base);

        let result = bc.apply_tx(&tx, &mut overlay);
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

        let bc = with_validator_and_storage(TEST_CHAIN_ID, AcceptAllValidator, storage);

        let mut tx = new_tx(Bytes::new(b"data"), key, TEST_CHAIN_ID);
        tx.gas_limit = u64::MAX;
        tx.gas_price = u128::MAX;

        let base = bc.storage.state_view();
        let mut overlay = OverlayState::new(&base);

        let result = bc.apply_tx(&tx, &mut overlay);
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
    fn contract_id_differs_for_different_data() {
        let key = PrivateKey::new();
        let tx1 = new_tx(Bytes::new(b"code_a"), key.clone(), TEST_CHAIN_ID);
        let tx2 = new_tx(Bytes::new(b"code_b"), key, TEST_CHAIN_ID);

        let id1 = Blockchain::<AcceptAllValidator, TestStorage>::contract_id(&tx1);
        let id2 = Blockchain::<AcceptAllValidator, TestStorage>::contract_id(&tx2);

        assert_ne!(id1, id2);
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
        let bc = with_validator_and_storage(TEST_CHAIN_ID, AcceptAllValidator, storage);

        let header = Header {
            version: 1,
            height: 1,
            timestamp: 0,
            previous_block: genesis.header_hash(TEST_CHAIN_ID),
            merkle_root: MerkleTree::from_transactions(&[], TEST_CHAIN_ID),
            state_root: random_hash(),
        };
        let block = Block::new(header, PrivateKey::new(), vec![], TEST_CHAIN_ID);

        let result = bc.apply_block(block);
        assert!(matches!(
            result,
            Err(StorageError::ValidationFailed(msg)) if msg.contains("state_root mismatch")
        ));
    }

    fn make_deploy_tx(key: PrivateKey, chain_id: u64) -> Transaction {
        use crate::virtual_machine::assembler::assemble_source;

        let program = assemble_source("LOAD_I64 r0, 42").expect("assemble failed");
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

        let bc = with_validator_and_storage(TEST_CHAIN_ID, AcceptAllValidator, storage);

        let tx = make_deploy_tx(key, TEST_CHAIN_ID);

        let base = bc.storage.state_view();
        let mut overlay = OverlayState::new(&base);

        bc.apply_tx(&tx, &mut overlay).expect("apply_tx failed");

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

        let bc = with_validator_and_storage(TEST_CHAIN_ID, AcceptAllValidator, storage);

        let tx = make_deploy_tx(key, TEST_CHAIN_ID);

        let base = bc.storage.state_view();
        let mut overlay = OverlayState::new(&base);

        bc.apply_tx(&tx, &mut overlay).expect("apply_tx failed");

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

        let bc = with_validator_and_storage(TEST_CHAIN_ID, AcceptAllValidator, storage);

        let mut tx = make_deploy_tx(key, TEST_CHAIN_ID);
        tx.gas_price = gas_price;

        let base = bc.storage.state_view();
        let mut overlay = OverlayState::new(&base);

        bc.apply_tx(&tx, &mut overlay).expect("apply_tx failed");

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

        let bc = with_validator_and_storage(TEST_CHAIN_ID, AcceptAllValidator, storage);

        let base = bc.storage.state_view();
        let mut overlay = OverlayState::new(&base);

        for i in 0..3 {
            let mut tx = make_deploy_tx(key.clone(), TEST_CHAIN_ID);
            tx.nonce = i;

            bc.apply_tx(&tx, &mut overlay).expect("apply_tx failed");
        }

        let account_bytes = overlay.get(sender).expect("account should exist");
        let account = Account::from_bytes(&account_bytes).unwrap();

        assert_eq!(account.nonce(), 3);
    }
}
