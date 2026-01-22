//! Core blockchain data structure and block management.

use crate::core::account::Account;
use crate::core::block::{Block, Header};
use crate::core::transaction::{Transaction, TransactionType};
use crate::core::validator::{BLOCK_MAX_BYTES, BlockValidator, BlockValidatorError, Validator};
use crate::crypto::key_pair::{Address, PrivateKey};
use crate::storage::main_storage::MainStorage;
use crate::storage::state_store::{AccountStorage, VmStorage};
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
use crate::virtual_machine::vm::{BLOCK_GAS_LIMIT, ExecContext, TRANSACTION_GAS_LIMIT, VM};
use crate::{info, warn};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_BLOCK_TIME_DRIFT: u64 = 15;

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

    pub fn get_account(&self, address: Address) -> Option<Account> {
        self.storage.get_account(address)
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
    pub fn intrinsic_gas_units(tx_type: TransactionType, data: &Bytes) -> u64 {
        let mut gas = 21_000 + ((tx_type == TransactionType::DeployContract) as u64 * 32_000);
        for b in data {
            gas = gas.saturating_add(4 + (*b != 0) as u64 * 12);
        }
        gas
    }

    /// Executes a transaction based on its type and updates gas usage.
    ///
    /// Handles three transaction types:
    /// - `TransferFunds`: moves native currency between accounts
    /// - `DeployContract`: runs init_code, then persists the contract account and
    ///   runtime bytecode under a namespaced `code_hash` key
    /// - `InvokeContract`: loads stored runtime bytecode and executes
    fn execute_tx<T: State>(
        &self,
        transaction: &Transaction,
        tx_overlay: &mut OverlayState<T>,
        gas_used: &mut u64,
        from: (Address, &mut Account),
        to: (Address, &mut Account),
    ) -> Result<(), StorageError> {
        match transaction.tx_type {
            TransactionType::TransferFunds => {
                if from.0 == to.0 {
                    return Ok(());
                }

                from.1.charge(transaction.amount)?;
                to.1.transfer(transaction.amount)
            }
            TransactionType::DeployContract => {
                let program = DeployProgram::from_bytes(transaction.data.as_slice())?;

                // Compute remaining gas after intrinsic costs
                let max_gas =
                    transaction
                        .gas_limit
                        .checked_sub(*gas_used)
                        .ok_or(VMError::OutOfGas {
                            used: *gas_used,
                            limit: transaction.gas_limit,
                        })?;
                if max_gas > TRANSACTION_GAS_LIMIT {
                    return Err(VMError::OutOfGas {
                        used: max_gas,
                        limit: TRANSACTION_GAS_LIMIT,
                    }
                    .into());
                }

                let mut vm = VM::new_deploy(program.clone(), max_gas)?;
                let contract_id = Self::contract_id(transaction);
                let ctx = ExecContext {
                    chain_id: self.id,
                    contract_id,
                };

                // Run init_code (may call into runtime_code for setup)
                let result = vm.run(tx_overlay, &ctx);
                *gas_used += vm.gas_used();

                match result {
                    Ok(_) => {
                        // Charge sender for amount transferred to contract
                        from.1.charge(transaction.amount)?;

                        // Persist runtime bytecode + heap items under namespaced hash
                        let mut stored_code = Vec::new();
                        program.items.encode(&mut stored_code);
                        stored_code.extend(&program.runtime_code);
                        let code_hash = Self::code_hash(&program.runtime_code);
                        tx_overlay.push(code_hash, stored_code);

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
                        Ok(())
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
                if max_gas > TRANSACTION_GAS_LIMIT {
                    return Err(VMError::OutOfGas {
                        used: max_gas,
                        limit: TRANSACTION_GAS_LIMIT,
                    }
                    .into());
                }

                let contract_id = program.contract_id;
                let contract = self
                    .storage
                    .get_account(contract_id)
                    .ok_or(StorageError::MissingAccount(contract_id))?;
                let stored_code = self
                    .storage
                    .get(contract.code_hash())
                    .ok_or(StorageError::MissingCode(contract_id))?;

                // Decode stored format: max_register + items + runtime_code
                let mut cursor = stored_code.as_slice();
                let items = Vec::<Vec<u8>>::decode(&mut cursor)?;
                let runtime_code = cursor.to_vec();

                let mut vm = VM::new_execute(program, runtime_code, items, max_gas)?;
                let ctx = ExecContext {
                    chain_id: self.id,
                    contract_id,
                };

                // Run runtime_code
                vm.run(tx_overlay, &ctx)?;
                *gas_used += vm.gas_used();

                Ok(())
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
    ) -> Result<(TxAccountChanges, u64), StorageError> {
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

        let get_account = |address: Address| -> Result<Account, StorageError> {
            match block_overlay.get(address) {
                Some(b) => {
                    Account::from_bytes(&b).map_err(|e| StorageError::DecodeError(e.to_string()))
                }
                None => self
                    .storage
                    .get_account(address)
                    .ok_or(StorageError::MissingAccount(address)),
            }
        };

        // Make sure an account exists for the transaction sender and receiver
        let from_hash = transaction.from.address();
        let mut from = get_account(from_hash)?;
        let to_hash = transaction.to;
        let mut to = get_account(to_hash)?;

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
        from.charge(transaction.gas_price.checked_mul(gas_used as u128).ok_or(
            StorageError::ArithmeticOverflow {
                gas_used,
                gas_price: transaction.gas_price,
            },
        )?)?;

        transaction_result?;

        let accounts: TxAccountChanges = if from_hash == to_hash {
            [(from_hash, from.to_vec()), (from_hash, from.to_vec())]
        } else {
            [(from_hash, from.to_vec()), (to_hash, to.to_vec())]
        };
        Ok((accounts, gas_used))
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
        tx_pool: &TxPool,
    ) -> Result<Block, StorageError> {
        // Executes all transactions in the block and computes the resulting state root.
        let mut gas_left = BLOCK_GAS_LIMIT;
        let mut size_left = BLOCK_MAX_BYTES;
        let base = self.storage.state_view();
        let mut block_overlay = OverlayState::new(&base);

        let mut hashes = Vec::<Hash>::new();
        let mut transactions = Vec::<Transaction>::new();

        // Take transactions from the pool while the block gas limit is not reached
        while let (Some(tx), size) = tx_pool.take_one(gas_left, size_left) {
            let hash = tx.id(self.id);
            let mut tx_overlay = OverlayState::new(&block_overlay);

            // Try and apply the transaction to the current state
            match self.apply_tx(&tx, &block_overlay, &mut tx_overlay) {
                Ok((accounts, gas_used)) => {
                    tx_overlay
                        .into_writes()
                        .apply_tx_overlay(accounts, &mut block_overlay);
                    gas_left -= gas_used;
                    size_left -= size;
                    hashes.push(hash);
                    transactions.push(tx);
                }
                Err(e) => warn!("{e}"),
            }
        }

        // Apply the block state changes to the chain
        self.storage.apply_batch(block_overlay.into_writes().0);
        tx_pool.remove_batch(&hashes);

        let header = Header {
            version: 1,
            height: self.storage.height() + 1,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0),
            gas_used: BLOCK_GAS_LIMIT - gas_left,
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
        // Make sure new blocks don't drift to far in the future in date creation
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

        let base = self.storage.state_view();
        let mut block_overlay = OverlayState::new(&base);

        for tx in &block.transactions {
            let mut tx_overlay = OverlayState::new(&block_overlay);
            match self.apply_tx(tx, &block_overlay, &mut tx_overlay) {
                Ok((accounts, _)) => {
                    tx_overlay
                        .into_writes()
                        .apply_tx_overlay(accounts, &mut block_overlay);
                }
                Err(e) => Err(e)?,
            }
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

        self.storage.apply_batch(writes.0);
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
            gas_used: BLOCK_GAS_LIMIT,
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
            bc.build_block(PrivateKey::new(), &TxPool::new(Some(1), TEST_CHAIN_ID))
                .expect("build_block failed");
        }

        assert_eq!(bc.height(), block_count);

        bc.build_block(PrivateKey::new(), &TxPool::new(Some(1), TEST_CHAIN_ID))
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
        let bc = with_validator_and_storage(TEST_CHAIN_ID, AcceptAllValidator, storage);

        let header = Header {
            version: 1,
            height: 1,
            timestamp: 0,
            gas_used: BLOCK_GAS_LIMIT,
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
        storage.set_account(Address::zero(), Account::new(0));

        let bc = with_validator_and_storage(TEST_CHAIN_ID, AcceptAllValidator, storage);

        let tx = make_deploy_tx(key, TEST_CHAIN_ID);

        let base = bc.storage.state_view();
        let mut overlay = OverlayState::new(&base);
        let mut tx_overlay = OverlayState::new(&overlay);

        let (account, _) = bc
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

        let (account, _) = bc
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

        let (account, _) = bc
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
            let (account, _) = bc
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

        let (accounts, gas_used) = bc
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

        let (accounts, _) = bc
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

        let program = assemble_source("LOAD_I64 r0, 42").expect("assemble failed");
        let mut expected_runtime = Vec::new();
        program.items.encode(&mut expected_runtime);
        expected_runtime.extend(program.runtime_code.clone());
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

        let (accounts, _) = bc
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
[ init code ]
LOAD_I64 r0, 1

[ runtime code ]
LOAD_I64 r1, 2
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

        let (accounts, _) = bc
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
        let mut expected = Vec::new();
        program.items.encode(&mut expected);
        expected.extend(program.runtime_code);
        assert_eq!(stored_code, expected);
    }
}
