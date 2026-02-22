//! Consensus parameters and genesis derivation helpers.
//!
//! Defines chain-level parameters used by consensus, sync, and fork-choice code,
//! plus deterministic genesis allocation/block derivation.

use crate::core::account::Account;
use crate::core::block::{Block, Header};
use crate::crypto::key_pair::{Address, PrivateKey, PublicKey};
use crate::storage::rocksdb_storage::SmtValue;
use crate::types::encoding::Encode;
use crate::types::hash::Hash;
use crate::types::serializable_signature::SerializableSignature;
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

/// Domain-separated key used to store global consensus state in VM storage.
pub fn consensus_state_key() -> Hash {
    Hash::sha3().chain(b"CONSENSUS:STATE").finalize()
}

/// Domain-separated key used to store the active validator set snapshot.
pub fn validator_set_key() -> Hash {
    Hash::sha3().chain(b"CONSENSUS:VALIDATOR_SET").finalize()
}

/// Domain-separated key used to store a validator record.
pub fn validator_record_key(address: Address) -> Hash {
    let mut h = Hash::sha3();
    h.update(b"CONSENSUS:VALIDATOR:");
    h.update(address.as_slice());
    h.finalize()
}

/// Domain-separated key used to mark slashing evidence as already processed.
pub fn slashing_evidence_seen_key(evidence_id: Hash) -> Hash {
    let mut h = Hash::sha3();
    h.update(b"CONSENSUS:SLASHED_EVIDENCE:");
    h.update(evidence_id.as_slice());
    h.finalize()
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

/// Current lifecycle state of a validator.
#[derive(Clone, Copy, Debug, PartialEq, Eq, BinaryCodec)]
pub enum ValidatorStatus {
    /// Validator is actively participating in proposer selection.
    Active,
    /// Validator exists but has no active stake.
    Inactive,
    /// Validator has pending activation stake not yet active.
    PendingActivation,
    /// Validator has requested unbonding and is waiting for claim.
    Unbonding,
    /// Validator has been slashed and currently has no active stake.
    Slashed,
}

/// Stake amount scheduled to become active at a future height.
#[derive(Clone, Debug, PartialEq, Eq, BinaryCodec)]
pub struct PendingActivation {
    /// Stake amount to activate.
    pub amount: u128,
    /// Height at which this stake becomes active.
    pub activate_height: u64,
}

/// Stake amount scheduled to become claimable after unbonding.
#[derive(Clone, Debug, PartialEq, Eq, BinaryCodec)]
pub struct PendingUnbond {
    /// Stake amount that will be claimable.
    pub amount: u128,
    /// Height at which funds become claimable.
    pub claim_height: u64,
}

/// Persistent validator record tracked in consensus state.
#[derive(Clone, Debug, PartialEq, Eq, BinaryCodec)]
pub struct ValidatorRecord {
    /// Validator address.
    pub address: Address,
    /// Currently active stake used for proposer selection and rewards.
    pub active_stake: u128,
    /// Stake pending activation after bonding period.
    pub pending_activations: Vec<PendingActivation>,
    /// Stake pending claim after unbonding period.
    pub pending_unbonds: Vec<PendingUnbond>,
    /// Cumulative amount slashed from this validator.
    pub slashed_total: u128,
}

impl ValidatorRecord {
    /// Creates an empty validator record for the given address.
    pub fn new(address: Address) -> Self {
        Self {
            address,
            active_stake: 0,
            pending_activations: Vec::new(),
            pending_unbonds: Vec::new(),
            slashed_total: 0,
        }
    }

    /// Returns the validator lifecycle status.
    pub fn status(&self) -> ValidatorStatus {
        if self.active_stake > 0 {
            ValidatorStatus::Active
        } else if !self.pending_unbonds.is_empty() {
            ValidatorStatus::Unbonding
        } else if !self.pending_activations.is_empty() {
            ValidatorStatus::PendingActivation
        } else if self.slashed_total > 0 {
            ValidatorStatus::Slashed
        } else {
            ValidatorStatus::Inactive
        }
    }
}

/// Active validator entry used for weighted proposer selection.
#[derive(Clone, Debug, PartialEq, Eq, BinaryCodec)]
pub struct ActiveValidatorEntry {
    /// Validator address.
    pub address: Address,
    /// Active stake weight.
    pub stake: u128,
}

/// Snapshot of the active validator set used for deterministic leader selection.
#[derive(Clone, Debug, PartialEq, Eq, Default, BinaryCodec)]
pub struct ValidatorSetSnapshot {
    /// All known validator addresses (active or pending), sorted by address.
    pub tracked_validators: Vec<Address>,
    /// Active validators sorted by address for deterministic iteration.
    pub validators: Vec<ActiveValidatorEntry>,
    /// Sum of all active stake in `validators`.
    pub total_active_stake: u128,
}

impl ValidatorSetSnapshot {
    /// Returns an empty validator set snapshot.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Sorts validators by address and recomputes total active stake.
    pub fn normalize(&mut self) {
        self.tracked_validators.sort_unstable();
        self.tracked_validators.dedup();
        self.validators.sort_unstable_by_key(|v| v.address);
        self.validators.retain(|v| v.stake > 0);
        self.total_active_stake = self
            .validators
            .iter()
            .fold(0u128, |acc, v| acc.saturating_add(v.stake));
    }

    /// Returns the active stake for a validator address.
    pub fn stake_of(&self, address: Address) -> u128 {
        self.validators
            .iter()
            .find(|v| v.address == address)
            .map(|v| v.stake)
            .unwrap_or(0)
    }
}

/// Global consensus state persisted in VM storage.
#[derive(Clone, Debug, PartialEq, Eq, BinaryCodec)]
pub struct ConsensusState {
    /// Latest block height for which scheduled transitions were processed.
    pub last_processed_height: u64,
    /// Total active stake used for rewards and proposer selection.
    pub total_active_stake: u128,
    /// Pseudo-randomness seed updated each block.
    pub randomness_seed: Hash,
}

impl Default for ConsensusState {
    fn default() -> Self {
        Self {
            last_processed_height: 0,
            total_active_stake: 0,
            randomness_seed: Hash::zero(),
        }
    }
}

/// Signed header data used as slashable evidence.
#[derive(Clone, Debug, PartialEq, Eq, BinaryCodec)]
pub struct SignedHeaderEvidence {
    /// Conflicting header.
    pub header: Header,
    /// Validator public key that signed the header.
    pub validator: PublicKey,
    /// Signature over the header hash in the block-signing domain.
    pub signature: SerializableSignature,
}

impl SignedHeaderEvidence {
    /// Computes the signed header hash.
    pub fn header_hash(&self, chain_id: u64) -> Hash {
        self.header.header_hash(chain_id)
    }

    /// Verifies the signature for this header.
    pub fn verify(&self, chain_id: u64) -> bool {
        let hash = self.header_hash(chain_id);
        self.validator
            .verify(block_sign_data(chain_id, &hash).as_slice(), self.signature)
    }
}

/// Slashing evidence for double-signing / double-proposing.
#[derive(Clone, Debug, PartialEq, Eq, BinaryCodec)]
pub struct SlashingEvidence {
    /// First signed header.
    pub first: SignedHeaderEvidence,
    /// Second conflicting signed header.
    pub second: SignedHeaderEvidence,
}

impl SlashingEvidence {
    /// Computes a domain-separated identifier for evidence deduplication.
    pub fn evidence_id(&self, chain_id: u64) -> Hash {
        let h1 = self.first.header_hash(chain_id);
        let h2 = self.second.header_hash(chain_id);
        let (a, b) = if h1 <= h2 { (h1, h2) } else { (h2, h1) };
        let mut h = Hash::sha3();
        h.update(b"SLASH_EVIDENCE");
        h.update(a.as_slice());
        h.update(b.as_slice());
        h.finalize()
    }

    /// Returns true if this evidence proves a slashable double-sign fault.
    pub fn is_valid_double_sign(&self, chain_id: u64) -> bool {
        if !self.first.verify(chain_id) || !self.second.verify(chain_id) {
            return false;
        }
        if self.first.validator.address() != self.second.validator.address() {
            return false;
        }
        if self.first.header.height != self.second.header.height {
            return false;
        }
        self.first.header_hash(chain_id) != self.second.header_hash(chain_id)
    }
}

/// Payload for a stake transaction.
#[derive(Clone, Debug, PartialEq, Eq, BinaryCodec)]
pub struct StakeTxData {
    /// Stake amount to lock and activate after the bonding period.
    pub amount: u128,
}

/// Payload for an unstake transaction.
#[derive(Clone, Debug, PartialEq, Eq, BinaryCodec)]
pub struct UnstakeTxData {
    /// Amount of active stake to begin unbonding.
    pub amount: u128,
}

/// Payload for a claim-unbonded transaction.
#[derive(Clone, Debug, PartialEq, Eq, BinaryCodec)]
pub struct ClaimUnbondedTxData {
    /// Optional exact amount to claim. `0` means claim all matured unbonds.
    pub amount: u128,
}

/// Payload for a slashing-evidence transaction.
#[derive(Clone, Debug, PartialEq, Eq, BinaryCodec)]
pub struct SlashingEvidenceTxData {
    /// Slashable evidence to process.
    pub evidence: SlashingEvidence,
}

/// Selects the proposer for a block height using weighted deterministic sampling.
///
/// Returns `None` when the validator set is empty or total active stake is zero.
pub fn select_leader(
    height: u64,
    randomness: Hash,
    validator_set: &ValidatorSetSnapshot,
) -> Option<Address> {
    if validator_set.validators.is_empty() || validator_set.total_active_stake == 0 {
        return None;
    }

    let mut h = Hash::sha3();
    h.update(b"LEADER_SELECT");
    height.encode(&mut h);
    randomness.encode(&mut h);
    let draw = h.finalize();
    let mut buf = [0u8; 16];
    buf.copy_from_slice(&draw.as_slice()[..16]);
    let mut ticket = u128::from_le_bytes(buf) % validator_set.total_active_stake;

    for v in &validator_set.validators {
        if ticket < v.stake {
            return Some(v.address);
        }
        ticket -= v.stake;
    }

    validator_set.validators.last().map(|v| v.address)
}

/// Computes the next consensus randomness seed from the current seed and block hash.
pub fn next_randomness_seed(current_seed: Hash, block_hash: Hash) -> Hash {
    let mut h = Hash::sha3();
    h.update(b"CONSENSUS:RAND");
    h.update(current_seed.as_slice());
    h.update(block_hash.as_slice());
    h.finalize()
}

/// Returns the development-chain staking parameters.
pub fn default_staking_params() -> StakingParams {
    ChainParams::dev_with_allocations(vec![]).staking
}

fn block_sign_data(chain_id: u64, hash: &Hash) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(b"BLOCK");
    chain_id.encode(&mut buf);
    hash.encode(&mut buf);
    buf
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

    #[test]
    fn select_leader_is_deterministic() {
        let mut set = ValidatorSetSnapshot {
            tracked_validators: vec![
                Hash::sha3().chain(b"v2").finalize(),
                Hash::sha3().chain(b"v1").finalize(),
            ],
            validators: vec![
                ActiveValidatorEntry {
                    address: Hash::sha3().chain(b"v2").finalize(),
                    stake: 5,
                },
                ActiveValidatorEntry {
                    address: Hash::sha3().chain(b"v1").finalize(),
                    stake: 10,
                },
            ],
            total_active_stake: 0,
        };
        set.normalize();

        let rand = Hash::sha3().chain(b"rand").finalize();
        let a = select_leader(42, rand, &set);
        let b = select_leader(42, rand, &set);
        assert_eq!(a, b);
        assert!(a.is_some());
    }

    #[test]
    fn select_leader_none_for_empty_set() {
        assert!(select_leader(1, Hash::zero(), &ValidatorSetSnapshot::empty()).is_none());
    }
}
