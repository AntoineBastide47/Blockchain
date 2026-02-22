//! Consensus parameters and genesis derivation helpers.
//!
//! Defines chain-level parameters used by consensus, sync, and fork-choice code,
//! plus deterministic genesis allocation/block derivation.

use crate::core::account::Account;
use crate::core::block::{Block, Header};
use crate::crypto::key_pair::{Address, PrivateKey};
use crate::storage::rocksdb_storage::SmtValue;
use crate::types::encoding::Encode;
use crate::types::hash::Hash;
use blockchain_derive::BinaryCodec;
use sparse_merkle_tree::blake2b::Blake2bHasher;
use sparse_merkle_tree::default_store::DefaultStore;
use sparse_merkle_tree::{H256, SparseMerkleTree};

/// Consensus family identifier.
#[derive(Clone, Copy, BinaryCodec)]
pub enum ConsensusKind {
    /// Weighted proof-of-stake with deterministic proposer selection.
    ProofOfStakeV1,
}

/// Staking-related chain parameters.
#[derive(Clone, BinaryCodec)]
pub struct StakingParams {
    /// Minimum stake required to become active.
    pub min_stake: u128,
    /// Blocks between stake transaction inclusion and validator activation.
    pub bonding_period_blocks: u64,
    /// Blocks between unstake request and funds becoming claimable.
    pub unbonding_period_blocks: u64,
    /// Slash amount in basis points (1/100 of a percent) for slashable faults.
    pub slash_bps: u16,
}

/// Fork-choice and finality-related parameters.
#[derive(Clone, BinaryCodec)]
pub struct ForkChoiceParams {
    /// Depth after which reorgs are refused by default.
    pub finality_depth: u64,
}

/// Network sync limits advertised/used by the local node.
#[derive(Clone, BinaryCodec)]
pub struct SyncLimits {
    /// Maximum number of headers in a single response.
    pub max_headers_per_request: u16,
    /// Maximum number of blocks/bodies in a single response.
    pub max_blocks_per_request: u16,
    /// Maximum number of hashes in a locator list.
    pub max_locator_hashes: u16,
}

/// A genesis state allocation entry.
#[derive(Clone, BinaryCodec)]
pub struct GenesisAllocation {
    /// Address to initialize in genesis state.
    pub address: Address,
    /// Full account state for this address.
    pub account: Account,
}

impl GenesisAllocation {
    /// Creates a genesis allocation entry for the given address/account pair.
    pub fn new(address: Address, account: Account) -> Self {
        Self { address, account }
    }
}

/// Genesis configuration and derivation parameters.
#[derive(Clone, BinaryCodec)]
pub struct GenesisSpec {
    /// Allocations to include in the genesis state.
    pub allocations: Vec<GenesisAllocation>,
    /// Deterministic private key bytes used only to sign the genesis block.
    pub genesis_signer_key_bytes: [u8; 32],
}

impl GenesisSpec {
    /// Returns sorted genesis account tuples `(address, account)`.
    ///
    /// Sorting by address ensures deterministic iteration order for any code
    /// that consumes the returned vector.
    pub fn derive_initial_accounts(&self) -> Vec<(Address, Account)> {
        let mut accounts: Vec<(Address, Account)> = self
            .allocations
            .iter()
            .map(|a| (a.address, a.account.clone()))
            .collect();
        accounts.sort_unstable_by_key(|(addr, _)| *addr);
        accounts
    }

    /// Builds the deterministic genesis block for the provided chain ID.
    pub fn build_genesis_block(&self, chain_id: u64) -> Block {
        let mut state = GenesisSmt::new(H256::zero(), DefaultStore::default());
        for (addr, account) in self.derive_initial_accounts() {
            state
                .update(hash_to_h256(&addr), SmtValue(account.to_vec()))
                .expect("genesis SMT update failed");
        }

        let header = Header {
            version: 1,
            height: 0,
            timestamp: 0,
            gas_used: 0,
            previous_block: Hash::zero(),
            merkle_root: Hash::zero(),
            state_root: h256_to_hash(state.root()),
            receipt_root: Hash::zero(),
        };

        let genesis_key = PrivateKey::from_bytes(&self.genesis_signer_key_bytes)
            .expect("genesis_signer_key_bytes must be a valid secp256k1 scalar");

        Block::new(header, genesis_key, vec![], chain_id)
    }
}

/// Chain-wide consensus and sync parameters.
#[derive(Clone, BinaryCodec)]
pub struct ChainParams {
    /// Chain identifier used for signature and hash domain separation.
    pub chain_id: u64,
    /// Consensus family identifier.
    pub consensus: ConsensusKind,
    /// Target block interval in seconds.
    pub block_time_secs: u64,
    /// Staking configuration.
    pub staking: StakingParams,
    /// Fork-choice/finality configuration.
    pub fork_choice: ForkChoiceParams,
    /// Sync request/response limits.
    pub sync_limits: SyncLimits,
    /// Genesis configuration.
    pub genesis: GenesisSpec,
}

impl ChainParams {
    /// Returns deterministic development chain parameters with the given allocations.
    pub fn dev_with_allocations(allocations: Vec<GenesisAllocation>) -> Self {
        Self {
            chain_id: 0,
            consensus: ConsensusKind::ProofOfStakeV1,
            block_time_secs: 6,
            staking: StakingParams {
                min_stake: 1,
                bonding_period_blocks: 32,
                unbonding_period_blocks: 256,
                slash_bps: 500,
            },
            fork_choice: ForkChoiceParams { finality_depth: 64 },
            sync_limits: SyncLimits {
                max_headers_per_request: 500,
                max_blocks_per_request: 100,
                max_locator_hashes: 32,
            },
            genesis: GenesisSpec {
                allocations,
                genesis_signer_key_bytes: [
                    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                    0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a,
                    0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
                ],
            },
        }
    }

    /// Returns deterministic development chain parameters with prebuilt accounts.
    pub fn dev_from_initial_accounts(initial_accounts: &[(Address, Account)]) -> Self {
        let allocations = initial_accounts
            .iter()
            .map(|(address, account)| GenesisAllocation::new(*address, account.clone()))
            .collect();
        Self::dev_with_allocations(allocations)
    }

    /// Computes a domain-separated hash of the chain parameters.
    pub fn hash(&self) -> Hash {
        let mut h = Hash::sha3();
        h.update(b"CHAIN_PARAMS");
        self.encode(&mut h);
        h.finalize()
    }
}

type GenesisSmt = SparseMerkleTree<Blake2bHasher, SmtValue, DefaultStore<SmtValue>>;

fn hash_to_h256(hash: &Hash) -> H256 {
    H256::from(hash.0)
}

fn h256_to_hash(h256: &H256) -> Hash {
    Hash::from_slice(h256.as_slice()).unwrap_or_else(Hash::zero)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_initial_accounts_sorted_by_address() {
        let a1 = Hash::sha3().chain(b"a1").finalize();
        let a2 = Hash::sha3().chain(b"a2").finalize();

        let spec = GenesisSpec {
            allocations: vec![
                GenesisAllocation::new(a2, Account::new(2)),
                GenesisAllocation::new(a1, Account::new(1)),
            ],
            genesis_signer_key_bytes: ChainParams::dev_with_allocations(vec![])
                .genesis
                .genesis_signer_key_bytes,
        };

        let accounts = spec.derive_initial_accounts();
        assert_eq!(accounts[0].0, a1);
        assert_eq!(accounts[1].0, a2);
    }

    #[test]
    fn chain_params_hash_is_deterministic() {
        let p1 = ChainParams::dev_with_allocations(vec![GenesisAllocation::new(
            Hash::sha3().chain(b"addr").finalize(),
            Account::new(42),
        )]);
        let p2 = ChainParams::dev_with_allocations(vec![GenesisAllocation::new(
            Hash::sha3().chain(b"addr").finalize(),
            Account::new(42),
        )]);
        assert_eq!(p1.hash(), p2.hash());
    }

    #[test]
    fn genesis_block_has_zero_receipt_root() {
        let params = ChainParams::dev_with_allocations(vec![]);
        let genesis = params.genesis.build_genesis_block(params.chain_id);
        assert_eq!(genesis.header.receipt_root, Hash::zero());
        assert_eq!(genesis.header.height, 0);
    }
}
