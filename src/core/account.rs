use crate::storage::storage_trait::StorageError;
use crate::types::encoding::Encode;
use crate::types::hash::{Hash, HashCache};
use blockchain_derive::BinaryCodec;

/// Canonical representation of account state persisted in the state trie.
///
/// This data mirrors the minimal fields required to reconstruct an account and
/// its associated contract data. All fields are encoded deterministically for
/// hashing and network propagation.
#[derive(BinaryCodec, Clone)]
pub struct Account {
    /// Monotonic counter of successful transactions from this account.
    nonce: u64,
    /// Spendable balance denominated in the native currency.
    balance: u128,
    /// Hash of the deployed contract bytecode, or `Hash::zero()` for EOAs.
    code_hash: Hash,
    /// Root hash of the contract storage trie; zero for accounts without storage.
    storage_root: Hash,

    /// Lazily-computed hash of the encoded account to avoid recomputation.
    cached_hash: HashCache,
}

impl Account {
    pub const EMPTY_CODE_HASH: Hash = Hash::zero();
    pub const EMPTY_STORAGE_ROOT: Hash = Hash::zero();

    /// Creates a new externally owned account with the given balance.
    pub fn new(balance: u128) -> Self {
        Self {
            nonce: 0,
            balance,
            code_hash: Self::EMPTY_CODE_HASH,
            storage_root: Self::EMPTY_STORAGE_ROOT,
            cached_hash: HashCache::new(),
        }
    }

    /// Creates an account with explicit field values for contract accounts.
    ///
    /// Use this constructor when restoring an account from storage or when
    /// creating contract accounts that require a specific code hash and storage root.
    pub fn from(nonce: u64, balance: u128, code_hash: Hash, storage_root: Hash) -> Self {
        Self {
            nonce,
            balance,
            code_hash,
            storage_root,
            cached_hash: HashCache::new(),
        }
    }

    /// Returns the account's current balance.
    pub fn balance(&self) -> u128 {
        self.balance
    }

    /// Returns the account's current nonce.
    pub fn nonce(&self) -> u64 {
        self.nonce
    }

    /// Returns true if this account holds contract code.
    pub fn is_contract(&self) -> bool {
        self.code_hash != Self::EMPTY_CODE_HASH
    }

    /// Computes (and caches) a chain-specific hash of the encoded account value.
    pub fn value_hash(&self, chain_id: u64) -> Hash {
        self.cached_hash.get_or_compute(chain_id, || {
            let mut h = Hash::sha3();
            h.update(b"ACCOUNT");
            chain_id.encode(&mut h);
            self.encode(&mut h);
            h.finalize()
        })
    }

    /// Deducts the specified cost from the account balance.
    pub fn charge(&mut self, cost: u128) -> Result<(), StorageError> {
        self.balance = self
            .balance
            .checked_sub(cost)
            .ok_or(StorageError::InsufficientBalance {
                actual: self.balance,
                expected: cost,
            })?;
        self.cached_hash.invalidate();
        Ok(())
    }

    /// Credits the specified amount to the account balance.
    ///
    /// Returns [`StorageError::BalanceOverflow`] if the addition would exceed `u128::MAX`.
    /// Invalidates the cached hash on success.
    pub fn transfer(&mut self, amount: u128) -> Result<(), StorageError> {
        self.balance = self
            .balance
            .checked_add(amount)
            .ok_or(StorageError::BalanceOverflow {
                current: self.balance,
                increment: amount,
                max: u128::MAX,
            })?;
        self.cached_hash.invalidate();
        Ok(())
    }

    /// Increments the nonce of this account
    pub fn increment_nonce(&mut self) {
        self.nonce += 1;
        self.cached_hash.invalidate();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::encoding::Decode;

    #[test]
    fn new_creates_eoa_with_balance() {
        let account = Account::new(1_000_000);
        assert_eq!(account.balance(), 1_000_000);
        assert_eq!(account.nonce(), 0);
        assert!(!account.is_contract());
    }

    #[test]
    fn new_with_zero_balance() {
        let account = Account::new(0);
        assert_eq!(account.balance(), 0);
        assert_eq!(account.nonce(), 0);
    }

    #[test]
    fn new_with_max_balance() {
        let account = Account::new(u128::MAX);
        assert_eq!(account.balance(), u128::MAX);
    }

    #[test]
    fn is_contract_false_for_eoa() {
        let account = Account::new(100);
        assert!(!account.is_contract());
    }

    #[test]
    fn value_hash_deterministic() {
        let account1 = Account::new(500);
        let account2 = Account::new(500);

        assert_eq!(account1.value_hash(1), account2.value_hash(1));
    }

    #[test]
    fn value_hash_different_balances() {
        let account1: Account = Account::new(100);
        let account2 = Account::new(200);

        assert_ne!(account1.value_hash(1), account2.value_hash(1));
    }

    #[test]
    fn value_hash_different_chain_ids() {
        let account = Account::new(500);

        let hash1 = account.value_hash(1);
        let hash2 = account.value_hash(2);
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn value_hash_cached() {
        let account = Account::new(100);

        let hash1 = account.value_hash(1);
        let hash2 = account.value_hash(1);

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn value_hash_cache_invalidates_on_chain_id_change() {
        let account = Account::new(100);

        let hash_chain1 = account.value_hash(1);
        let hash_chain2 = account.value_hash(2);
        let hash_chain1_again = account.value_hash(1);

        assert_ne!(hash_chain1, hash_chain2);
        assert_eq!(hash_chain1, hash_chain1_again);
    }

    #[test]
    fn encode_decode_roundtrip() {
        let account = Account::new(123_456_789);
        let encoded = account.to_vec();
        let decoded = Account::decode(&mut encoded.as_slice()).expect("decode");

        assert_eq!(decoded.balance(), 123_456_789);
        assert_eq!(decoded.nonce(), 0);
        assert!(!decoded.is_contract());
    }

    #[test]
    fn clone_preserves_fields() {
        let account = Account::new(999);
        let cloned = account.clone();

        assert_eq!(cloned.balance(), 999);
        assert_eq!(cloned.nonce(), 0);
    }

    #[test]
    fn empty_code_hash_constant() {
        assert_eq!(Account::EMPTY_CODE_HASH, Hash::zero());
    }

    #[test]
    fn empty_storage_root_constant() {
        assert_eq!(Account::EMPTY_STORAGE_ROOT, Hash::zero());
    }

    #[test]
    fn from_creates_account_with_explicit_fields() {
        let code_hash = Hash::sha3().chain(b"test_code").finalize();
        let storage_root = Hash::sha3().chain(b"test_storage").finalize();

        let account = Account::from(5, 1000, code_hash, storage_root);

        assert_eq!(account.nonce(), 5);
        assert_eq!(account.balance(), 1000);
        assert!(account.is_contract());
    }

    #[test]
    fn from_with_empty_hashes_creates_eoa() {
        let account = Account::from(
            0,
            500,
            Account::EMPTY_CODE_HASH,
            Account::EMPTY_STORAGE_ROOT,
        );

        assert_eq!(account.nonce(), 0);
        assert_eq!(account.balance(), 500);
        assert!(!account.is_contract());
    }

    #[test]
    fn charge_deducts_from_balance() {
        let mut account = Account::new(1000);
        assert!(account.charge(300).is_ok());
        assert_eq!(account.balance(), 700);
    }

    #[test]
    fn charge_exact_balance_succeeds() {
        let mut account = Account::new(500);
        assert!(account.charge(500).is_ok());
        assert_eq!(account.balance(), 0);
    }

    #[test]
    fn charge_insufficient_balance_fails() {
        let mut account = Account::new(100);
        let result = account.charge(101);

        assert!(result.is_err());
        assert_eq!(account.balance(), 100);
    }

    #[test]
    fn charge_invalidates_hash_cache() {
        let account = Account::new(1000);
        let hash_before = account.value_hash(1);

        let mut account = account;
        account.charge(100).unwrap();

        assert_ne!(account.value_hash(1), hash_before);
    }

    #[test]
    fn increment_nonce_increases_by_one() {
        let mut account = Account::new(100);
        assert_eq!(account.nonce(), 0);

        account.increment_nonce();
        assert_eq!(account.nonce(), 1);

        account.increment_nonce();
        assert_eq!(account.nonce(), 2);
    }

    #[test]
    fn increment_nonce_invalidates_hash_cache() {
        let account = Account::new(100);
        let hash_before = account.value_hash(1);

        let mut account = account;
        account.increment_nonce();

        assert_ne!(account.value_hash(1), hash_before);
    }

    #[test]
    fn transfer_adds_to_balance() {
        let mut account = Account::new(1000);
        assert!(account.transfer(500).is_ok());
        assert_eq!(account.balance(), 1500);
    }

    #[test]
    fn transfer_to_max_succeeds() {
        let mut account = Account::new(u128::MAX - 100);
        assert!(account.transfer(100).is_ok());
        assert_eq!(account.balance(), u128::MAX);
    }

    #[test]
    fn transfer_overflow_fails() {
        let mut account = Account::new(u128::MAX);
        let result = account.transfer(1);

        assert!(matches!(result, Err(StorageError::BalanceOverflow { .. })));
        assert_eq!(account.balance(), u128::MAX);
    }

    #[test]
    fn transfer_invalidates_hash_cache() {
        let account = Account::new(100);
        let hash_before = account.value_hash(1);

        let mut account = account;
        account.transfer(50).unwrap();

        assert_ne!(account.value_hash(1), hash_before);
    }
}
