# Fork Choice + Sync Patch Todos (Grouped Commits)

This file tracks the concrete implementation plan for:

- consensus / proof method (PoS staking + leader selection)
- fork-aware header DAG + best-chain selection + reorgs
- header-first sync (locator-based) + body download + safe catchup
- fork-aware storage and networking extensions
- chain params + genesis derivation

Notes:

- `receipt_root` is already part of `Header`.
- block receipts are already generated/validated in `Blockchain` and stored in RocksDB (`CF_RECEIPTS`).
- all reorg/canonical commit work must be receipt-aware.

## Commit Group 1 (Patches 1-2)

### Patch 1: Consensus / Genesis / Chain Params Module

- [x] Add `src/core/consensus.rs`
- [x] Export `pub mod consensus;` from `src/core/mod.rs`
- [ ] Define:
  - [x] `ConsensusKind`
  - [x] `StakingParams`
  - [x] `ForkChoiceParams`
  - [x] `SyncLimits`
  - [x] `GenesisAllocation`
  - [x] `GenesisSpec`
  - [x] `ChainParams`
- [ ] Add deterministic helpers:
  - [x] `ChainParams::dev_with_allocations(...)`
  - [x] `ChainParams::dev_from_initial_accounts(...)`
  - [x] `ChainParams::hash()`
  - [x] `GenesisSpec::derive_initial_accounts()`
  - [x] `GenesisSpec::build_genesis_block(chain_id)`
- [x] Ensure genesis header sets `receipt_root = Hash::zero()`
- [x] Add unit tests for deterministic hashing/genesis derivation

### Patch 2: Wire `Server` / `main` to `ChainParams`

- [x] Add `chain_params: ChainParams` to `Server<T>`
- [x] Add `Server::new_with_chain_params(...)`
- [x] Keep `Server::new(...)` as compatibility wrapper
- [x] Make `Server::genesis_block(...)` delegate to `ChainParams` genesis derivation
- [x] Update `main.rs` to build `ChainParams` from genesis allocations and call `new_with_chain_params(...)`
- [x] Keep existing tests/call sites compiling
- [x] `cargo check -q`
- [x] Commit: `Add chain params and genesis spec plumbing`

## Commit Group 2 (Patches 3-5)

### Patch 3: Staking / Slashing Transaction Types + Payloads

- [x] Extend `TransactionType` with:
  - [x] `Stake`
  - [x] `Unstake`
  - [x] `ClaimUnbonded`
  - [x] `SubmitSlashingEvidence`
- [x] Add payload structs (recommended in `src/core/consensus.rs`):
  - [x] `StakeTxData`
  - [x] `UnstakeTxData`
  - [x] `ClaimUnbondedTxData`
  - [x] `SlashingEvidenceTxData`
- [x] Add `BinaryCodec` derives + validation helpers
- [x] Update `Blockchain::intrinsic_gas_units(...)` for new tx types
- [x] Add tx serialization / enum tests

### Patch 4: Consensus State Types + Deterministic Leader Selection

- [x] Add consensus state structs in `src/core/consensus.rs`:
  - [x] `ConsensusState`
  - [x] `ValidatorRecord`
  - [x] `ValidatorSetSnapshot`
  - [x] `ActiveValidatorEntry`
  - [x] `PendingActivation`
  - [x] `PendingUnbond`
  - [x] `ValidatorStatus`
  - [x] `SlashingEvidence`
- [x] Add namespaced state key helpers:
  - [x] `consensus_state_key()`
  - [x] `validator_set_key()`
  - [x] `validator_record_key(Address)`
  - [x] `slashing_evidence_seen_key(Hash)`
- [x] Add deterministic leader selection:
  - [x] `select_leader(height, randomness, validator_set)`
- [x] Add total active stake helpers
- [x] Replace placeholder reward inputs in `Blockchain` with consensus-state reads
- [x] Add unit tests for leader selection determinism / edge cases

### Patch 5: Blockchain Execution Integration (Stake/Unstake/Slash + PoS checks)

Status note:

- Consensus state is initialized lazily by staking transactions right now.
- Genesis does not yet embed consensus state (to avoid changing genesis `state_root` in this group).
- Explicit zero-active-stake handling is implemented as a bootstrap grace path while stake is bonding
  (proposer selection skipped, reward remains zero).

- [x] Extend `Blockchain::execute_tx(...)` to handle new tx types
- [x] Add helpers:
  - [x] `apply_stake_tx(...)`
  - [x] `apply_unstake_tx(...)`
  - [x] `apply_claim_unbonded_tx(...)`
  - [x] `apply_slashing_evidence_tx(...)`
  - [x] `process_scheduled_staking_transitions(...)`
- [x] Add proposer selection validation in:
  - [x] `build_block(...)`
  - [x] `apply_block(...)`
- [x] Enforce:
  - [x] min stake
  - [x] bonding delay
  - [x] unbonding delay
  - [x] slashing evidence uniqueness
  - [x] `total_active_stake != 0` handling
- [x] Preserve current receipt generation/validation flow:
  - [x] receipts built during execution
  - [x] `receipt_root` committed in header
  - [x] `BlockValidator::validate_receipt_root(...)` used on apply
- [x] Add tests for staking lifecycle + proposer rejection
- [x] `cargo check -q`
- [x] Commit: `Add PoS staking txs and blockchain consensus state execution`

## Commit Group 3 (Patches 6-8)

### Patch 6: Fork-Aware Storage Schema Groundwork (Receipt-Aware)

- [x] Add new RocksDB CF constants in `src/storage/rocksdb_storage.rs`:
  - [x] `CF_HEADER_META`
  - [x] `CF_CANONICAL_INDEX`
  - [x] `CF_BRANCH_TIPS`
  - [x] `CF_PARENT_CHILDREN`
  - [x] `CF_UNDO`
  - [x] `CF_REORG`
- [x] Keep and preserve `CF_RECEIPTS`
- [x] Add new meta keys:
  - [x] finalized tip/height
  - [x] reorg progress marker
  - [x] explicit canonical tip marker (if separate from `TIP`)
- [x] Add serialized storage structs:
  - [x] `HeaderMetaRecord`
  - [x] `ChainScore`
  - [x] `BranchTipRecord`
  - [x] `UndoRecord`
  - [x] `ReorgProgressRecord`
- [x] Update DB CF registrations in:
  - [x] `src/main.rs`
  - [x] `src/network/server.rs` test DB helper
- [x] Document receipt semantics for reorgs (canonical-only recommended)

### Patch 7: Header DAG Insertion + Canonical Index APIs

- [x] Add header DAG insert APIs:
  - [x] `store_header_dag(...)`
  - [x] `store_headers_dag(...)`
- [x] Persist parent->children links and competing tips
- [x] Compute/store `ChainScore` per header
- [x] Track header metadata flags:
  - [x] `has_body`
  - [x] `has_receipts`
  - [x] `is_canonical` (optional if derived)
- [x] Replace `get_header_by_height(...)` tip-walk with canonical index lookup
- [x] Replace `get_blocks_in_range(...)` tip-walk with canonical index iteration
- [x] Keep existing `Blockchain::store_headers(...)` as wrapper initially
- [x] Add tests for competing branches and canonical height lookups

### Patch 8: Undo Journals + Reorg Primitives (State + Receipts + Canonical Metadata)

- [x] Add new trait(s) for fork/reorg operations (do not bloat `Storage` too much)
- [x] Add undo capture / rollback methods:
  - [x] capture state undo for canonical commits
  - [x] rollback block via undo record
  - [x] LCA lookup
  - [x] canonical hash lookup by height
- [x] Add crash-safe reorg primitives:
  - [x] `begin_reorg(...)`
  - [x] `apply_reorg_disconnect(...)`
  - [x] `apply_reorg_connect(...)`
  - [x] `finish_reorg(...)`
- [x] Persist `REORG_IN_PROGRESS` marker
- [x] Make canonical commit path atomic with:
  - [x] block/header
  - [x] receipts (`CF_RECEIPTS`)
  - [x] state root/state
  - [x] canonical index
  - [x] undo record
- [x] Reorg receipt behavior (canonical-only receipts):
  - [x] delete receipts for disconnected canonical blocks
  - [x] write receipts for newly connected canonical blocks after execution
- [x] Add tests for rollback + reorg + receipt replacement
- [x] `cargo check -q`
- [ ] Commit: `Add fork-aware storage schema, header DAG, and reorg undo primitives`

Status note:

- The current undo journal path is conservative: `append_block(...)` writes metadata-only undo records
  (no state key diffs yet), so `rollback_block_with_undo(...)` is only safe for no-state-change blocks
  unless callers provide explicit state diffs via `capture_undo(...)`.
- Full reorg state rollback for non-empty blocks still needs blockchain/storage integration to pass the
  exact state writes into the canonical commit path.

## Commit Group 4 (Patches 10-12)

### Patch 10: Protocol / Message / RPC Extensions (Fork-Aware Sync)

- [ ] Extend `SendSyncStatusMessage` with:
  - [ ] `genesis_hash`
  - [ ] `chain_params_hash`
  - [ ] `best_header_height`
  - [ ] `best_header_tip`
  - [ ] `finalized_tip`
  - [ ] capability flags
- [ ] Replace height-range `GetHeadersMessage` with locator-based request:
  - [ ] `locators`
  - [ ] `stop_hash`
  - [ ] `limit`
- [ ] Add body-by-hash messages:
  - [ ] `GetBlockBodiesMessage`
  - [ ] `SendBlockBodiesMessage`
- [ ] Update `DecodedMessageData` in `rpc.rs`
- [ ] Update `handle_rpc(...)` decoding in `server.rs`
- [ ] Add/adjust serialization tests
- [ ] No receipt sync messages (receipt root is locally verified from execution)

### Patch 11: `SyncManager` v2 (Locator Headers + Bodies + Retries)

- [ ] Refactor `SyncAction` to locator/body-by-hash actions
- [ ] Add in-flight request tracking:
  - [ ] request kind
  - [ ] peer
  - [ ] timeout
  - [ ] retries
- [ ] Add backoff/failover and peer sync metadata
- [ ] Remove linear-tip-only header validation assumptions from `SyncManager`
- [ ] Add `on_tick(...)` for timeouts/retries
- [ ] Let server/storage validate/store headers; `SyncManager` orchestrates only
- [ ] Expand `sync.rs` state-machine tests

### Patch 12: Server Sync Integration (Locator + DAG + Reorg-Safe Catchup)

- [ ] Update `execute_sync_action(...)` for new sync actions
- [ ] `process_get_sync_status_message(...)` sends new chain params/genesis hashes
- [ ] `process_get_headers_message(...)`:
  - [ ] locator matching
  - [ ] canonical continuation
  - [ ] response caps
- [ ] `process_send_headers_message(...)`:
  - [ ] DAG store headers
  - [ ] schedule missing body downloads by hash
- [ ] Add:
  - [ ] `process_get_block_bodies_message(...)`
  - [ ] `process_send_block_bodies_message(...)`
- [ ] Integrate `Blockchain::ingest_block(...)` / reorg-safe application
- [ ] Preserve `receipt_root` validation through blockchain execution path
- [ ] Update integration tests for new sync flow
- [ ] `cargo check -q`
- [ ] Commit: `Add locator-based header sync and reorg-safe body catchup`

## Commit Group 5 (Patches 13-14)

### Patch 13: Orphans / Stale Forks / Retry Logic / Rate Limiting

- [ ] Add bounded orphan storage for blocks (and optionally headers)
- [ ] Accept non-tip blocks in `process_block(...)` when parent header exists
- [ ] Detect stale/orphan branches and eviction policy
- [ ] Add per-peer rate limits for:
  - [ ] header requests
  - [ ] body requests
  - [ ] snapshot requests
- [ ] Add retry/backoff and peer penalties for malformed/invalid data
- [ ] Add tests for orphan handling + rate limiting + bad peers

### Patch 14: Cleanup, Receipt API Semantics, Finalized Reporting

- [ ] Add `Blockchain::get_receipts(block_hash)` wrapper (storage-backed)
- [ ] Document receipt semantics:
  - [ ] canonical-only receipts (recommended v1)
  - [ ] behavior on reorg / reset / snapshot replay
- [ ] Replace placeholder finalized reporting in sync status with consensus-derived values
- [ ] Expose:
  - [ ] `finalized_height()`
  - [ ] `finalized_tip()`
  - [ ] `best_header_height()`
  - [ ] `best_header_tip()`
- [ ] Remove obsolete range-sync paths if fully migrated
- [ ] Add final regression tests:
  - [ ] receipts replaced on reorg
  - [ ] reorg below finalized depth rejected
  - [ ] invalid body => receipt_root mismatch => peer penalized
- [ ] `cargo check -q`
- [ ] Commit: `Add fork/orphan protections and finalize receipt-aware sync cleanup`

## Global Invariants (Review Checklist)

- [ ] Canonical tip + canonical index are always consistent
- [ ] Every canonical-applied block has matching receipts in `CF_RECEIPTS`
- [ ] `receipt_root` validated on every executed connect path (normal append + reorg connect)
- [ ] Undo journals capture state rollback information (receipts are not used for rollback)
- [ ] Reorg below finalized height is rejected by default
- [ ] Header DAG insertion is idempotent
- [ ] Sync rejects peers with mismatched `genesis_hash` / `chain_params_hash`
- [ ] All inbound/outbound sync batch sizes are capped
- [ ] Orphan/stale caches are bounded by count and memory
