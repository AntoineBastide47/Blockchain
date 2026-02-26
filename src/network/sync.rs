//! Sync state machine for header-first blockchain synchronization.
//!
//! Implements a production-grade sync algorithm:
//! 1. Discover peer status and available snapshots
//! 2. Sync headers first (lightweight, fast)
//! 3. Choose sync mode: snapshot sync (far behind) or block replay (close)
//! 4. Load state from snapshot or replay blocks
//! 5. Verify final state root
//!
//! The sync manager maintains state across multiple message exchanges and
//! produces actions for the server to execute.

use crate::core::block::{Block, Header};
use crate::network::message::{SYNC_CAP_BLOCK_BODIES_BY_HASH, SendSyncStatusMessage};
use crate::storage::rocksdb_storage::SNAPSHOT_INTERVAL;
use crate::types::hash::Hash;
use std::cmp::min;
use std::collections::HashMap;

/// Peer identifier (SHA3 hash of peer's public key).
pub type PeerId = Hash;

/// Information about a connected peer's sync status.
#[derive(Debug, Clone)]
pub struct PeerSyncInfo {
    /// Peer genesis hash (network compatibility check).
    pub genesis_hash: Hash,
    /// Peer chain parameters hash (network compatibility check).
    pub chain_params_hash: Hash,
    /// Peer's current blockchain height.
    pub height: u64,
    /// Peer's current tip hash.
    pub tip: Hash,
    /// Highest known header height.
    pub best_header_height: u64,
    /// Best known header tip hash.
    pub best_header_tip: Hash,
    /// Peer's finalized height.
    pub finalized_height: u64,
    /// Peer's finalized tip hash.
    pub finalized_tip: Hash,
    /// Snapshot heights this peer can serve.
    pub snapshot_heights: Vec<u64>,
    /// Sync protocol capabilities supported by the peer.
    pub capabilities: u64,
}

impl From<SendSyncStatusMessage> for PeerSyncInfo {
    fn from(msg: SendSyncStatusMessage) -> Self {
        Self {
            genesis_hash: msg.genesis_hash,
            chain_params_hash: msg.chain_params_hash,
            height: msg.height,
            tip: msg.tip,
            best_header_height: msg.best_header_height,
            best_header_tip: msg.best_header_tip,
            finalized_height: msg.finalized_height,
            finalized_tip: msg.finalized_tip,
            snapshot_heights: msg.snapshot_heights,
            capabilities: msg.capabilities,
        }
    }
}

/// Current state of the sync process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncState {
    /// Initial state, waiting to discover peers.
    Idle,
    /// Discovering peer capabilities by requesting sync status.
    Discovering,
    /// Syncing headers from peers.
    SyncingHeaders {
        /// Target height we're syncing headers to.
        target_height: u64,
        /// Current highest header we have.
        current_height: u64,
    },
    /// Waiting for a snapshot to be downloaded.
    LoadingSnapshot {
        /// Height of the snapshot being loaded.
        height: u64,
    },
    /// Replaying blocks to rebuild state.
    ReplayingBlocks {
        /// First block height to replay.
        start: u64,
        /// Target block height.
        target: u64,
        /// Current block height being replayed.
        current: u64,
    },
    /// Verifying final state root matches headers.
    Verifying,
    /// Fully synchronized with the network.
    InSync,
}

/// Sync mode determined by how far behind we are.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncMode {
    /// Use snapshot sync when far behind (Δ >= SNAPSHOT_INTERVAL).
    SnapshotSync,
    /// Use block replay when close (Δ < SNAPSHOT_INTERVAL).
    BlockReplay,
    /// Already in sync.
    InSync,
}

/// Actions the sync manager requests the server to perform.
#[derive(Debug, Clone)]
pub enum SyncAction {
    /// Request sync status from a peer.
    RequestSyncStatus { peer: PeerId },
    /// Request headers using locators (server builds locators from local header DAG).
    RequestHeaders { peer: PeerId, limit: u64 },
    /// Request a state snapshot from a peer.
    RequestSnapshot { peer: PeerId, height: u64 },
    /// Request block bodies by hash (server selects missing hashes from stored headers).
    RequestBlockBodies {
        peer: PeerId,
        target: u64,
        limit: u64,
    },
    /// Request block bodies in a range from a peer.
    ///
    /// Compatibility fallback when the peer does not advertise body-by-hash support.
    RequestBlocks { peer: PeerId, start: u64, end: u64 },
    /// Verify the current state root matches the tip header.
    VerifyState,
    /// Sync is complete.
    Done,
    /// No action needed, waiting for response.
    Wait,
}

/// Errors that can occur during sync.
#[derive(Debug, Clone)]
pub enum SyncError {
    /// No peers available for sync.
    NoPeers,
    /// Received unexpected message in current state.
    UnexpectedMessage { state: SyncState, message: String },
    /// Header chain validation failed.
    InvalidHeaderChain { reason: String },
    /// State root mismatch after sync.
    StateRootMismatch { expected: Hash, actual: Hash },
    /// Snapshot import failed.
    SnapshotImportFailed { reason: String },
    /// Block replay failed.
    BlockReplayFailed { height: u64, reason: String },
}

/// Maximum number of headers to request in a single batch.
const MAX_HEADERS_PER_REQUEST: u64 = 500;

/// Maximum number of blocks to request in a single batch.
const MAX_BLOCKS_PER_REQUEST: u64 = 100;
/// Request timeout in sync ticks.
const REQUEST_TIMEOUT_TICKS: u64 = 5;
/// Maximum retries before failing over to another peer.
const MAX_REQUEST_RETRIES: u8 = 2;
/// Temporary backoff applied to peers after repeated timeouts/failures.
const PEER_BACKOFF_TICKS: u64 = 15;

#[derive(Debug, Clone, Default)]
struct PeerRuntimeState {
    backoff_until_tick: u64,
    consecutive_failures: u32,
}

#[derive(Debug, Clone)]
enum InflightRequestKind {
    SyncStatus,
    Headers { limit: u64 },
    Snapshot { height: u64 },
    BlockBodies { target: u64, limit: u64 },
    BlocksRange { start: u64, end: u64 },
}

#[derive(Debug, Clone)]
struct InflightRequest {
    kind: InflightRequestKind,
    peer: PeerId,
    deadline_tick: u64,
    timeout_ticks: u64,
    retries: u8,
}

/// Manages the sync process state machine.
///
/// Tracks peer information, current sync state, and produces actions
/// for the server to execute. The server calls methods on this manager
/// when receiving messages and executes the returned actions.
pub struct SyncManager {
    /// Current sync state.
    state: SyncState,
    /// Information about connected peers.
    peers: HashMap<PeerId, PeerSyncInfo>,
    /// Per-peer runtime sync metadata (timeouts/backoff).
    peer_runtime: HashMap<PeerId, PeerRuntimeState>,
    /// Best peer for syncing (highest chain).
    best_peer: Option<PeerId>,
    /// Our current block height (state has been applied up to this).
    local_height: u64,
    /// Our current header height (maybe ahead of local_height during sync).
    local_header_height: u64,
    /// Our current header tip hash (maybe ahead of local_tip during sync).
    local_header_tip: Hash,
    /// Our current tip hash.
    local_tip: Hash,
    /// Chain identifier (used for header hash validation).
    chain_id: u64,
    /// Expected genesis hash for compatibility checks (`Hash::zero()` disables check).
    expected_genesis_hash: Hash,
    /// Expected chain params hash for compatibility checks (`Hash::zero()` disables check).
    expected_chain_params_hash: Hash,
    /// In-flight sync request waiting for a response.
    in_flight: Option<InflightRequest>,
    /// Logical sync clock used for timeout/retry handling.
    tick: u64,
    /// True if sync failed due to unrecoverable error (e.g., no snapshots available).
    /// Prevents immediate retries until peer status changes.
    sync_failed: bool,
}

impl SyncManager {
    /// Creates a new sync manager.
    pub fn new(
        local_height: u64,
        local_header_height: u64,
        local_tip: Hash,
        local_header_tip: Hash,
        chain_id: u64,
    ) -> Self {
        Self::new_with_network_identity(
            local_height,
            local_header_height,
            local_tip,
            local_header_tip,
            chain_id,
            Hash::zero(),
            Hash::zero(),
        )
    }

    /// Creates a new sync manager with expected network identity hashes.
    pub fn new_with_network_identity(
        local_height: u64,
        local_header_height: u64,
        local_tip: Hash,
        local_header_tip: Hash,
        chain_id: u64,
        expected_genesis_hash: Hash,
        expected_chain_params_hash: Hash,
    ) -> Self {
        Self {
            state: SyncState::Idle,
            peers: HashMap::new(),
            peer_runtime: HashMap::new(),
            best_peer: None,
            local_height,
            local_header_height,
            local_header_tip,
            local_tip,
            chain_id,
            expected_genesis_hash,
            expected_chain_params_hash,
            in_flight: None,
            tick: 0,
            sync_failed: false,
        }
    }

    /// Returns the current sync state.
    pub fn state(&self) -> &SyncState {
        &self.state
    }

    /// Returns true if we are fully synced.
    pub fn is_synced(&self) -> bool {
        matches!(self.state, SyncState::InSync)
    }

    /// Returns true if actively syncing (not idle or in-sync).
    pub fn is_actively_syncing(&self) -> bool {
        !matches!(self.state, SyncState::Idle | SyncState::InSync)
    }

    /// Updates local chain info (called after applying blocks).
    pub fn update_local_state(&mut self, height: u64, header_height: u64, tip: Hash) {
        self.local_height = height;
        self.local_header_height = header_height;
        self.local_tip = tip;
        if header_height <= height {
            self.local_header_tip = tip;
        }
    }

    /// Updates the tracked best header tip hash explicitly.
    pub fn update_local_header_tip(&mut self, header_tip: Hash) {
        self.local_header_tip = header_tip;
    }

    fn is_peer_compatible(&self, info: &PeerSyncInfo) -> bool {
        let genesis_ok = self.expected_genesis_hash == Hash::zero()
            || info.genesis_hash == Hash::zero()
            || info.genesis_hash == self.expected_genesis_hash;
        let params_ok = self.expected_chain_params_hash == Hash::zero()
            || info.chain_params_hash == Hash::zero()
            || info.chain_params_hash == self.expected_chain_params_hash;
        genesis_ok && params_ok
    }

    fn peer_available(&self, peer: PeerId) -> bool {
        self.peer_runtime
            .get(&peer)
            .map(|meta| self.tick >= meta.backoff_until_tick)
            .unwrap_or(true)
    }

    fn clear_peer_failures(&mut self, peer: PeerId) {
        if let Some(meta) = self.peer_runtime.get_mut(&peer) {
            meta.consecutive_failures = 0;
            meta.backoff_until_tick = self.tick;
        }
    }

    fn backoff_peer(&mut self, peer: PeerId) {
        let meta = self.peer_runtime.entry(peer).or_default();
        meta.consecutive_failures = meta.consecutive_failures.saturating_add(1);
        let factor = 1u64 << meta.consecutive_failures.min(4);
        meta.backoff_until_tick = self
            .tick
            .saturating_add(PEER_BACKOFF_TICKS.saturating_mul(factor));
    }

    fn clear_inflight_if<F>(&mut self, peer: PeerId, kind_matches: F)
    where
        F: Fn(&InflightRequestKind) -> bool,
    {
        let should_clear = self
            .in_flight
            .as_ref()
            .map(|req| req.peer == peer && kind_matches(&req.kind))
            .unwrap_or(false);
        if should_clear {
            self.in_flight = None;
        }
    }

    fn track_request(&mut self, action: &SyncAction) {
        let (peer, kind) = match action {
            SyncAction::RequestSyncStatus { peer } => (*peer, InflightRequestKind::SyncStatus),
            SyncAction::RequestHeaders { peer, limit } => {
                (*peer, InflightRequestKind::Headers { limit: *limit })
            }
            SyncAction::RequestSnapshot { peer, height } => {
                (*peer, InflightRequestKind::Snapshot { height: *height })
            }
            SyncAction::RequestBlockBodies {
                peer,
                target,
                limit,
            } => (
                *peer,
                InflightRequestKind::BlockBodies {
                    target: *target,
                    limit: *limit,
                },
            ),
            SyncAction::RequestBlocks { peer, start, end } => (
                *peer,
                InflightRequestKind::BlocksRange {
                    start: *start,
                    end: *end,
                },
            ),
            SyncAction::VerifyState | SyncAction::Done | SyncAction::Wait => return,
        };

        self.in_flight = Some(InflightRequest {
            kind,
            peer,
            deadline_tick: self.tick.saturating_add(REQUEST_TIMEOUT_TICKS),
            timeout_ticks: REQUEST_TIMEOUT_TICKS,
            retries: 0,
        });
    }

    fn tracked(&mut self, action: SyncAction) -> SyncAction {
        self.track_request(&action);
        action
    }

    fn action_from_inflight(&self, req: &InflightRequest) -> SyncAction {
        match req.kind {
            InflightRequestKind::SyncStatus => SyncAction::RequestSyncStatus { peer: req.peer },
            InflightRequestKind::Headers { limit } => SyncAction::RequestHeaders {
                peer: req.peer,
                limit,
            },
            InflightRequestKind::Snapshot { height } => SyncAction::RequestSnapshot {
                peer: req.peer,
                height,
            },
            InflightRequestKind::BlockBodies { target, limit } => SyncAction::RequestBlockBodies {
                peer: req.peer,
                target,
                limit,
            },
            InflightRequestKind::BlocksRange { start, end } => SyncAction::RequestBlocks {
                peer: req.peer,
                start,
                end,
            },
        }
    }

    fn request_headers_action(&mut self, peer: PeerId) -> SyncAction {
        self.tracked(SyncAction::RequestHeaders {
            peer,
            limit: MAX_HEADERS_PER_REQUEST,
        })
    }

    fn request_replay_action(&mut self, peer: PeerId, target: u64) -> SyncAction {
        let caps = self
            .peers
            .get(&peer)
            .map(|p| p.capabilities)
            .unwrap_or_default();
        if caps & SYNC_CAP_BLOCK_BODIES_BY_HASH != 0 {
            return self.tracked(SyncAction::RequestBlockBodies {
                peer,
                target,
                limit: MAX_BLOCKS_PER_REQUEST,
            });
        }

        let start = self.local_height.saturating_add(1);
        let end = min(
            start
                .saturating_add(MAX_BLOCKS_PER_REQUEST)
                .saturating_sub(1),
            target,
        );
        self.tracked(SyncAction::RequestBlocks { peer, start, end })
    }

    fn request_sync_status_action(&mut self, peer: PeerId) -> SyncAction {
        self.tracked(SyncAction::RequestSyncStatus { peer })
    }

    fn restart_discovery(&mut self) -> SyncAction {
        self.state = SyncState::Discovering;
        self.update_best_peer();
        if let Some(peer) = self.best_peer {
            self.request_sync_status_action(peer)
        } else {
            SyncAction::Wait
        }
    }

    /// Called when a new peer connects. Returns action to request their status.
    pub fn on_peer_connected(&mut self, peer: PeerId) -> SyncAction {
        self.peer_runtime.entry(peer).or_default();
        self.request_sync_status_action(peer)
    }

    /// Called when a peer disconnects.
    pub fn on_peer_disconnected(&mut self, peer: PeerId) -> SyncAction {
        self.peers.remove(&peer);
        self.peer_runtime.remove(&peer);
        if self
            .in_flight
            .as_ref()
            .map(|req| req.peer == peer)
            .unwrap_or(false)
        {
            self.in_flight = None;
        }
        if self.best_peer == Some(peer) {
            self.best_peer = None;
            self.update_best_peer();
            // If we were actively syncing from this peer, restart discovery
            if self.is_actively_syncing() {
                return self.restart_discovery();
            }
        }
        SyncAction::Wait
    }

    /// Updates the best peer based on current peer info.
    fn update_best_peer(&mut self) {
        self.best_peer = self
            .peers
            .iter()
            .filter(|(id, _)| self.peer_available(**id))
            .max_by_key(|(_, info)| (info.height, info.best_header_height))
            .map(|(id, _)| *id);
    }

    /// Called when a request/response flow fails with a peer (invalid data, apply error, etc.).
    pub fn on_request_failed(&mut self, peer: PeerId) -> SyncAction {
        if self
            .in_flight
            .as_ref()
            .map(|req| req.peer == peer)
            .unwrap_or(false)
        {
            self.in_flight = None;
        }
        self.backoff_peer(peer);
        if self.is_actively_syncing() {
            return self.restart_discovery();
        }
        SyncAction::Wait
    }

    /// Called when we receive sync status from a peer.
    pub fn on_sync_status(&mut self, peer: PeerId, status: SendSyncStatusMessage) -> SyncAction {
        self.clear_inflight_if(peer, |kind| matches!(kind, InflightRequestKind::SyncStatus));
        let info = PeerSyncInfo::from(status);

        if !self.is_peer_compatible(&info) {
            self.backoff_peer(peer);
            self.peers.remove(&peer);
            self.update_best_peer();
            return SyncAction::Wait;
        }

        // Check if snapshots have become available - clear failed flag
        if self.sync_failed && !info.snapshot_heights.is_empty() {
            self.sync_failed = false;
        }

        self.clear_peer_failures(peer);
        self.peers.insert(peer, info.clone());
        self.update_best_peer();

        // If we're idle or discovering, check if we need to sync
        if matches!(self.state, SyncState::Idle | SyncState::Discovering) {
            return self.decide_and_start_sync();
        }

        SyncAction::Wait
    }

    /// Decides sync mode and starts the sync process.
    fn decide_and_start_sync(&mut self) -> SyncAction {
        let Some(best_peer) = self.best_peer else {
            self.state = SyncState::Idle;
            return SyncAction::Wait;
        };

        let Some(peer_info) = self.peers.get(&best_peer).cloned() else {
            self.state = SyncState::Idle;
            return SyncAction::Wait;
        };

        let target_header_height = peer_info.best_header_height.max(peer_info.height);
        let blocks_in_sync =
            self.local_height >= peer_info.height && self.local_tip == peer_info.tip;
        let headers_in_sync = self.local_header_height >= target_header_height
            && self.local_header_tip == peer_info.best_header_tip;

        // Already in sync?
        if blocks_in_sync && headers_in_sync {
            self.state = SyncState::InSync;
            self.in_flight = None;
            return SyncAction::Done;
        }

        // Always start with header sync
        if !headers_in_sync {
            self.state = SyncState::SyncingHeaders {
                target_height: target_header_height,
                current_height: self.local_header_height,
            };
            return self.request_headers_action(best_peer);
        }

        // Headers are synced, now sync state
        self.start_state_sync(best_peer, &peer_info)
    }

    /// Starts state sync after headers are complete.
    fn start_state_sync(&mut self, peer: PeerId, peer_info: &PeerSyncInfo) -> SyncAction {
        let delta = peer_info.height.saturating_sub(self.local_height);

        if delta == 0 && self.local_tip == peer_info.tip {
            // Already caught up, verify state
            self.state = SyncState::Verifying;
            self.in_flight = None;
            return SyncAction::VerifyState;
        }

        // Decide: snapshot sync or block replay
        if delta >= SNAPSHOT_INTERVAL {
            // Snapshot sync - find best snapshot
            if let Some(&snapshot_height) = peer_info
                .snapshot_heights
                .iter()
                .filter(|&&h| h <= peer_info.finalized_height && h > self.local_height)
                .max()
            {
                self.state = SyncState::LoadingSnapshot {
                    height: snapshot_height,
                };
                return self.tracked(SyncAction::RequestSnapshot {
                    peer,
                    height: snapshot_height,
                });
            }
            // No suitable snapshot, fall through to block replay
        }

        // Block replay
        self.state = SyncState::ReplayingBlocks {
            start: self.local_height + 1,
            target: peer_info.height,
            current: self.local_height,
        };
        self.request_replay_action(peer, peer_info.height)
    }

    /// Called when we receive headers from a peer.
    pub fn on_headers(
        &mut self,
        peer: PeerId,
        headers: &[Header],
    ) -> Result<SyncAction, SyncError> {
        self.clear_inflight_if(peer, |kind| {
            matches!(kind, InflightRequestKind::Headers { .. })
        });
        let SyncState::SyncingHeaders {
            target_height,
            current_height: _,
        } = self.state
        else {
            return Ok(SyncAction::Wait);
        };

        if headers.is_empty() {
            // Peer has no more headers, try state sync
            if let Some(peer_info) = self.peers.get(&peer).cloned() {
                return Ok(self.start_state_sync(peer, &peer_info));
            }
            return Ok(SyncAction::Wait);
        }

        // Header validation/storage is handled by the server + storage layer.
        // We only update our local view and orchestrate the next action.
        if let Some(last) = headers.last() {
            self.local_header_height = self.local_header_height.max(last.height);
            self.local_header_tip = last.header_hash(self.chain_id);
        }

        if self.local_header_height >= target_height {
            // Headers complete, start state sync
            if let Some(peer_info) = self.peers.get(&peer).cloned() {
                return Ok(self.start_state_sync(peer, &peer_info));
            }
            return Ok(SyncAction::Wait);
        }

        // Request more headers
        self.state = SyncState::SyncingHeaders {
            target_height,
            current_height: self.local_header_height,
        };
        Ok(self.request_headers_action(peer))
    }

    /// Called when we receive a snapshot from a peer.
    pub fn on_snapshot_received(&mut self, peer: PeerId, height: u64, success: bool) -> SyncAction {
        let SyncState::LoadingSnapshot { height: expected } = self.state else {
            return SyncAction::Wait;
        };

        if height != expected {
            // Wrong snapshot, ignore
            return SyncAction::Wait;
        }
        self.clear_inflight_if(peer, |kind| {
            matches!(kind, InflightRequestKind::Snapshot { .. })
        });

        if !success {
            // Snapshot failed, try block replay instead
            if let Some(peer_info) = self.peers.get(&peer).cloned() {
                self.state = SyncState::ReplayingBlocks {
                    start: self.local_height + 1,
                    target: peer_info.height,
                    current: self.local_height,
                };
                return self.request_replay_action(peer, peer_info.height);
            }
            return SyncAction::Wait;
        }

        // Snapshot loaded successfully, update local height
        self.local_height = height;
        self.local_header_height = std::cmp::max(self.local_header_height, height);

        // Now replay remaining blocks
        if let Some(peer_info) = self.peers.get(&peer).cloned() {
            if self.local_height >= peer_info.height {
                // Fully caught up
                self.state = SyncState::Verifying;
                return SyncAction::VerifyState;
            }

            self.state = SyncState::ReplayingBlocks {
                start: height + 1,
                target: peer_info.height,
                current: height,
            };
            return self.request_replay_action(peer, peer_info.height);
        }

        SyncAction::Wait
    }

    /// Called when we receive blocks from a peer.
    pub fn on_blocks(
        &mut self,
        peer: PeerId,
        blocks: &[Block],
        last_applied_height: u64,
    ) -> SyncAction {
        self.clear_inflight_if(peer, |kind| {
            matches!(
                kind,
                InflightRequestKind::BlocksRange { .. } | InflightRequestKind::BlockBodies { .. }
            )
        });
        let SyncState::ReplayingBlocks {
            start,
            target,
            current: _,
        } = self.state
        else {
            return SyncAction::Wait;
        };

        if blocks.is_empty() {
            // No more blocks, check if we're done
            if last_applied_height >= target {
                self.local_height = last_applied_height;
                self.state = SyncState::Verifying;
                return SyncAction::VerifyState;
            }
            // Still behind, request next range starting after last applied height.
            self.state = SyncState::ReplayingBlocks {
                start,
                target,
                current: last_applied_height,
            };
            self.local_height = last_applied_height;
            return self.request_replay_action(peer, target);
        }

        // Update our height
        self.local_height = last_applied_height;

        if last_applied_height >= target {
            // Fully caught up
            self.state = SyncState::Verifying;
            return SyncAction::VerifyState;
        }

        // Request more blocks
        self.state = SyncState::ReplayingBlocks {
            start,
            target,
            current: last_applied_height,
        };
        self.request_replay_action(peer, target)
    }

    /// Called after state verification completes.
    pub fn on_verify_complete(&mut self, success: bool) -> SyncAction {
        if success {
            self.state = SyncState::InSync;
            self.in_flight = None;
            SyncAction::Done
        } else {
            // Verification failed, need to resync
            self.restart_discovery()
        }
    }

    /// Force a resync (e.g., when we detect we're behind).
    /// Returns Wait if sync previously failed and conditions haven't changed.
    pub fn trigger_resync(&mut self) -> SyncAction {
        if self.sync_failed {
            // Don't retry until peer status changes (e.g., snapshots become available)
            return SyncAction::Wait;
        }
        self.in_flight = None;
        self.restart_discovery()
    }

    /// Set state to idle due to unrecoverable error (e.g., no snapshots available).
    /// Prevents immediate retries until peer status changes.
    pub fn set_idle_failed(&mut self) {
        self.state = SyncState::Idle;
        self.in_flight = None;
        self.sync_failed = true;
    }

    /// Advances the internal sync clock and handles request timeouts/retries.
    pub fn on_tick(&mut self) -> SyncAction {
        self.tick = self.tick.saturating_add(1);

        let Some(mut req) = self.in_flight.clone() else {
            return SyncAction::Wait;
        };

        if self.tick < req.deadline_tick {
            return SyncAction::Wait;
        }

        if req.retries < MAX_REQUEST_RETRIES {
            req.retries = req.retries.saturating_add(1);
            req.deadline_tick = self.tick.saturating_add(req.timeout_ticks);
            self.in_flight = Some(req.clone());
            return self.action_from_inflight(&req);
        }

        let failed_peer = req.peer;
        self.in_flight = None;
        self.backoff_peer(failed_peer);
        self.restart_discovery()
    }

    /// Get the current sync mode.
    pub fn sync_mode(&self) -> SyncMode {
        match &self.state {
            SyncState::InSync => SyncMode::InSync,
            SyncState::LoadingSnapshot { .. } => SyncMode::SnapshotSync,
            SyncState::ReplayingBlocks { .. } => SyncMode::BlockReplay,
            _ => {
                // During header sync, determine based on delta
                if let Some(info) = self.best_peer.and_then(|p| self.peers.get(&p)) {
                    let delta = info.height.saturating_sub(self.local_height);
                    if delta >= SNAPSHOT_INTERVAL {
                        SyncMode::SnapshotSync
                    } else if delta > 0 {
                        SyncMode::BlockReplay
                    } else {
                        SyncMode::InSync
                    }
                } else {
                    SyncMode::InSync
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_CHAIN_ID: u64 = 0;

    fn make_peer_status_with_caps(
        height: u64,
        snapshots: Vec<u64>,
        capabilities: u64,
    ) -> SendSyncStatusMessage {
        SendSyncStatusMessage {
            version: 1,
            genesis_hash: Hash::zero(),
            chain_params_hash: Hash::zero(),
            height,
            tip: Hash::zero(),
            best_header_height: height,
            best_header_tip: Hash::zero(),
            finalized_height: height,
            finalized_tip: Hash::zero(),
            snapshot_heights: snapshots,
            capabilities,
        }
    }

    fn make_peer_status(height: u64, snapshots: Vec<u64>) -> SendSyncStatusMessage {
        make_peer_status_with_caps(height, snapshots, 0)
    }

    fn make_header(height: u64, previous_block: Hash, timestamp: u64) -> Header {
        Header {
            version: 1,
            height,
            timestamp,
            gas_used: 0,
            previous_block,
            merkle_root: Hash::zero(),
            state_root: Hash::zero(),
            receipt_root: Hash::zero(),
        }
    }

    #[test]
    fn sync_manager_starts_idle() {
        let manager = SyncManager::new(0, 0, Hash::zero(), Hash::zero(), TEST_CHAIN_ID);
        assert!(matches!(manager.state(), SyncState::Idle));
        assert!(!manager.is_synced());
    }

    #[test]
    fn peer_connect_requests_status() {
        let mut manager = SyncManager::new(0, 0, Hash::zero(), Hash::zero(), TEST_CHAIN_ID);
        let peer = Hash::from_slice(&[1u8; 32]).unwrap();

        let action = manager.on_peer_connected(peer);
        assert!(matches!(action, SyncAction::RequestSyncStatus { .. }));
    }

    #[test]
    fn sync_status_triggers_header_sync_when_behind() {
        let mut manager = SyncManager::new(0, 0, Hash::zero(), Hash::zero(), TEST_CHAIN_ID);
        let peer = Hash::from_slice(&[1u8; 32]).unwrap();

        let status = make_peer_status(100, vec![50]);
        let action = manager.on_sync_status(peer, status);

        assert!(matches!(action, SyncAction::RequestHeaders { .. }));
        assert!(matches!(manager.state(), SyncState::SyncingHeaders { .. }));
    }

    #[test]
    fn already_synced_reports_done() {
        let tip = Hash::from_slice(&[1u8; 32]).unwrap();
        let mut manager = SyncManager::new(100, 100, tip, tip, TEST_CHAIN_ID);
        let peer = Hash::from_slice(&[2u8; 32]).unwrap();

        let status = SendSyncStatusMessage {
            version: 1,
            genesis_hash: Hash::zero(),
            chain_params_hash: Hash::zero(),
            height: 100,
            tip,
            best_header_height: 100,
            best_header_tip: tip,
            finalized_height: 100,
            finalized_tip: tip,
            snapshot_heights: vec![],
            capabilities: 0,
        };
        let action = manager.on_sync_status(peer, status);

        assert!(matches!(action, SyncAction::Done));
        assert!(manager.is_synced());
    }

    #[test]
    fn sync_mode_snapshot_when_far_behind() {
        let mut manager = SyncManager::new(0, 0, Hash::zero(), Hash::zero(), TEST_CHAIN_ID);
        let peer = Hash::from_slice(&[1u8; 32]).unwrap();

        // Peer is 100 blocks ahead, which is >= SNAPSHOT_INTERVAL (10)
        let status = make_peer_status(100, vec![50, 90]);
        manager.on_sync_status(peer, status);

        assert_eq!(manager.sync_mode(), SyncMode::SnapshotSync);
    }

    #[test]
    fn sync_mode_block_replay_when_close() {
        let mut manager = SyncManager::new(95, 95, Hash::zero(), Hash::zero(), TEST_CHAIN_ID);
        let peer = Hash::from_slice(&[1u8; 32]).unwrap();

        // Peer is only 5 blocks ahead, < SNAPSHOT_INTERVAL
        let status = make_peer_status(100, vec![50, 90]);
        manager.on_sync_status(peer, status);

        assert_eq!(manager.sync_mode(), SyncMode::BlockReplay);
    }

    #[test]
    fn headers_complete_triggers_state_sync() {
        let mut manager = SyncManager::new(0, 0, Hash::zero(), Hash::zero(), TEST_CHAIN_ID);
        let peer = Hash::from_slice(&[1u8; 32]).unwrap();

        let status = make_peer_status(50, vec![40]);
        manager.on_sync_status(peer, status);

        // Simulate receiving all headers
        manager.local_header_height = 50;
        let headers: Vec<Header> = vec![]; // Empty means done
        let action = manager
            .on_headers(peer, &headers)
            .expect("empty headers ok");

        // Should request snapshot since we're > SNAPSHOT_INTERVAL behind
        assert!(matches!(
            action,
            SyncAction::RequestSnapshot { height: 40, .. }
        ));
    }

    #[test]
    fn snapshot_failure_falls_back_to_block_replay() {
        let mut manager = SyncManager::new(0, 50, Hash::zero(), Hash::zero(), TEST_CHAIN_ID);
        let peer = Hash::from_slice(&[1u8; 32]).unwrap();

        let status = make_peer_status(50, vec![40]);
        manager.peers.insert(peer, PeerSyncInfo::from(status));
        manager.best_peer = Some(peer);
        manager.state = SyncState::LoadingSnapshot { height: 40 };

        let action = manager.on_snapshot_received(peer, 40, false);

        // Should fall back to block replay
        assert!(matches!(action, SyncAction::RequestBlocks { .. }));
        assert!(matches!(manager.state(), SyncState::ReplayingBlocks { .. }));
    }

    // ==================== Peer Management Tests ====================

    #[test]
    fn peer_disconnect_removes_peer_info() {
        let mut manager = SyncManager::new(0, 0, Hash::zero(), Hash::zero(), TEST_CHAIN_ID);
        let peer = Hash::from_slice(&[1u8; 32]).unwrap();

        let status = make_peer_status(100, vec![50]);
        manager.on_sync_status(peer, status);

        assert!(manager.peers.contains_key(&peer));
        manager.on_peer_disconnected(peer);
        assert!(!manager.peers.contains_key(&peer));
    }

    #[test]
    fn peer_disconnect_clears_best_peer_if_matching() {
        let mut manager = SyncManager::new(0, 0, Hash::zero(), Hash::zero(), TEST_CHAIN_ID);
        let peer = Hash::from_slice(&[1u8; 32]).unwrap();

        let status = make_peer_status(100, vec![50]);
        manager.on_sync_status(peer, status);

        assert_eq!(manager.best_peer, Some(peer));
        manager.on_peer_disconnected(peer);
        assert!(manager.best_peer.is_none());
    }

    #[test]
    fn best_peer_updates_to_highest_height() {
        let mut manager = SyncManager::new(0, 0, Hash::zero(), Hash::zero(), TEST_CHAIN_ID);
        let peer1 = Hash::from_slice(&[1u8; 32]).unwrap();
        let peer2 = Hash::from_slice(&[2u8; 32]).unwrap();

        manager.on_sync_status(peer1, make_peer_status(50, vec![]));
        assert_eq!(manager.best_peer, Some(peer1));

        manager.on_sync_status(peer2, make_peer_status(100, vec![]));
        assert_eq!(manager.best_peer, Some(peer2));
    }

    // ==================== State Transition Tests ====================

    #[test]
    fn is_actively_syncing_false_when_idle() {
        let manager = SyncManager::new(0, 0, Hash::zero(), Hash::zero(), TEST_CHAIN_ID);
        assert!(!manager.is_actively_syncing());
    }

    #[test]
    fn is_actively_syncing_true_during_header_sync() {
        let mut manager = SyncManager::new(0, 0, Hash::zero(), Hash::zero(), TEST_CHAIN_ID);
        let peer = Hash::from_slice(&[1u8; 32]).unwrap();

        manager.on_sync_status(peer, make_peer_status(100, vec![]));
        assert!(manager.is_actively_syncing());
    }

    #[test]
    fn is_actively_syncing_false_when_in_sync() {
        let tip = Hash::from_slice(&[1u8; 32]).unwrap();
        let mut manager = SyncManager::new(100, 100, tip, tip, TEST_CHAIN_ID);
        let peer = Hash::from_slice(&[2u8; 32]).unwrap();

        let status = SendSyncStatusMessage {
            version: 1,
            genesis_hash: Hash::zero(),
            chain_params_hash: Hash::zero(),
            height: 100,
            tip,
            best_header_height: 100,
            best_header_tip: tip,
            finalized_height: 100,
            finalized_tip: tip,
            snapshot_heights: vec![],
            capabilities: 0,
        };
        manager.on_sync_status(peer, status);

        assert!(!manager.is_actively_syncing());
    }

    #[test]
    fn update_local_state_updates_all_fields() {
        let mut manager = SyncManager::new(0, 0, Hash::zero(), Hash::zero(), TEST_CHAIN_ID);
        let new_tip = Hash::from_slice(&[5u8; 32]).unwrap();

        manager.update_local_state(50, 60, new_tip);

        assert_eq!(manager.local_height, 50);
        assert_eq!(manager.local_header_height, 60);
        assert_eq!(manager.local_tip, new_tip);
    }

    // ==================== Header Sync Tests ====================

    #[test]
    fn on_headers_requests_more_when_not_complete() {
        let mut manager = SyncManager::new(0, 0, Hash::zero(), Hash::zero(), TEST_CHAIN_ID);
        let peer = Hash::from_slice(&[1u8; 32]).unwrap();

        manager.on_sync_status(peer, make_peer_status(1000, vec![]));

        // Simulate receiving some headers (but not all)
        let header1 = make_header(1, Hash::zero(), 100);
        let header1_hash = header1.header_hash(TEST_CHAIN_ID);
        let header2 = make_header(2, header1_hash, 200);
        let headers = vec![header1, header2];

        let action = manager
            .on_headers(peer, &headers)
            .expect("valid header batch");

        // Should request more headers
        match action {
            SyncAction::RequestHeaders { limit, .. } => {
                assert_eq!(limit, MAX_HEADERS_PER_REQUEST);
                assert_eq!(manager.local_header_height, 2);
            }
            _ => panic!("expected RequestHeaders action"),
        }
    }

    #[test]
    fn block_replay_prefers_body_by_hash_when_peer_supports_capability() {
        let mut manager = SyncManager::new(0, 2, Hash::zero(), Hash::zero(), TEST_CHAIN_ID);
        let peer = Hash::from_slice(&[9u8; 32]).unwrap();

        let action = manager.on_sync_status(
            peer,
            make_peer_status_with_caps(2, vec![], SYNC_CAP_BLOCK_BODIES_BY_HASH),
        );

        assert!(matches!(
            action,
            SyncAction::RequestBlockBodies { target: 2, .. }
        ));
    }

    #[test]
    fn on_tick_retries_then_fails_over_to_another_peer() {
        let mut manager = SyncManager::new(0, 0, Hash::zero(), Hash::zero(), TEST_CHAIN_ID);
        let peer1 = Hash::from_slice(&[1u8; 32]).unwrap();
        let peer2 = Hash::from_slice(&[2u8; 32]).unwrap();

        // Populate both peers; peer1 is best and starts syncing.
        let first_action = manager.on_sync_status(peer1, make_peer_status(20, vec![]));
        let _ = manager.on_sync_status(peer2, make_peer_status(10, vec![]));
        assert!(matches!(first_action, SyncAction::RequestHeaders { peer, .. } if peer == peer1));

        // Advance to the first retry timeout.
        for _ in 0..REQUEST_TIMEOUT_TICKS {
            let action = manager.on_tick();
            if matches!(action, SyncAction::Wait) {
                continue;
            }
            assert!(matches!(action, SyncAction::RequestHeaders { peer, .. } if peer == peer1));
            break;
        }

        // Exhaust retries and expect failover discovery against peer2.
        let mut failover = SyncAction::Wait;
        for _ in 0..((MAX_REQUEST_RETRIES as u64 + 1) * REQUEST_TIMEOUT_TICKS + 2) {
            let action = manager.on_tick();
            if !matches!(action, SyncAction::Wait) {
                failover = action;
            }
        }
        assert!(matches!(
            failover,
            SyncAction::RequestSyncStatus { peer } if peer == peer2
        ));
    }

    #[test]
    fn incompatible_peer_status_is_ignored() {
        let mut manager = SyncManager::new_with_network_identity(
            0,
            0,
            Hash::zero(),
            Hash::zero(),
            TEST_CHAIN_ID,
            Hash::from_slice(&[7u8; 32]).unwrap(),
            Hash::from_slice(&[8u8; 32]).unwrap(),
        );
        let peer = Hash::from_slice(&[3u8; 32]).unwrap();
        let mut status = make_peer_status(100, vec![]);
        status.genesis_hash = Hash::from_slice(&[9u8; 32]).unwrap();
        status.chain_params_hash = Hash::from_slice(&[10u8; 32]).unwrap();

        let action = manager.on_sync_status(peer, status);
        assert!(matches!(action, SyncAction::Wait));
        assert!(!manager.peers.contains_key(&peer));
    }

    #[test]
    fn on_headers_transitions_to_state_sync_when_complete() {
        let mut manager = SyncManager::new(0, 0, Hash::zero(), Hash::zero(), TEST_CHAIN_ID);
        let peer = Hash::from_slice(&[1u8; 32]).unwrap();

        manager.on_sync_status(peer, make_peer_status(2, vec![]));
        manager.local_header_height = 2;

        let action = manager.on_headers(peer, &[]).expect("empty headers ok");

        // Should transition to block sync (since delta < SNAPSHOT_INTERVAL)
        assert!(matches!(action, SyncAction::RequestBlocks { .. }));
    }

    #[test]
    fn headers_complete_no_snapshot_falls_back_to_block_replay_when_far_behind() {
        let mut manager = SyncManager::new(0, 0, Hash::zero(), Hash::zero(), TEST_CHAIN_ID);
        let peer = Hash::from_slice(&[1u8; 32]).unwrap();

        let target_height = SNAPSHOT_INTERVAL * 2;
        manager.on_sync_status(peer, make_peer_status(target_height, vec![]));
        manager.local_header_height = target_height;

        let action = manager.on_headers(peer, &[]).expect("empty headers ok");

        assert!(matches!(action, SyncAction::RequestBlocks { start, .. } if start == 1));
    }

    // ==================== Block Replay Tests ====================

    #[test]
    fn on_blocks_requests_more_when_not_complete() {
        let mut manager = SyncManager::new(0, 0, Hash::zero(), Hash::zero(), TEST_CHAIN_ID);
        let peer = Hash::from_slice(&[1u8; 32]).unwrap();

        let status = make_peer_status(100, vec![]);
        manager.peers.insert(peer, PeerSyncInfo::from(status));
        manager.best_peer = Some(peer);
        manager.state = SyncState::ReplayingBlocks {
            start: 1,
            target: 100,
            current: 0,
        };

        let action = manager.on_blocks(peer, &[], 50);

        // Should request more blocks
        match action {
            SyncAction::RequestBlocks { start, .. } => {
                assert_eq!(start, 51);
            }
            _ => panic!("expected RequestBlocks action"),
        }
    }

    #[test]
    fn on_blocks_completes_when_target_reached() {
        let mut manager = SyncManager::new(0, 0, Hash::zero(), Hash::zero(), TEST_CHAIN_ID);
        let peer = Hash::from_slice(&[1u8; 32]).unwrap();

        let status = make_peer_status(100, vec![]);
        manager.peers.insert(peer, PeerSyncInfo::from(status));
        manager.best_peer = Some(peer);
        manager.state = SyncState::ReplayingBlocks {
            start: 1,
            target: 100,
            current: 90,
        };

        let action = manager.on_blocks(peer, &[], 100);

        // Should move to verification
        assert!(matches!(action, SyncAction::VerifyState));
        assert!(matches!(manager.state(), SyncState::Verifying));
    }

    #[test]
    fn on_blocks_empty_with_target_reached_completes() {
        let mut manager = SyncManager::new(0, 0, Hash::zero(), Hash::zero(), TEST_CHAIN_ID);
        let peer = Hash::from_slice(&[1u8; 32]).unwrap();

        let status = make_peer_status(50, vec![]);
        manager.peers.insert(peer, PeerSyncInfo::from(status));
        manager.best_peer = Some(peer);
        manager.state = SyncState::ReplayingBlocks {
            start: 1,
            target: 50,
            current: 45,
        };

        let action = manager.on_blocks(peer, &[], 50);

        assert!(matches!(action, SyncAction::VerifyState));
    }

    // ==================== Snapshot Sync Tests ====================

    #[test]
    fn on_snapshot_received_wrong_height_ignored() {
        let mut manager = SyncManager::new(0, 50, Hash::zero(), Hash::zero(), TEST_CHAIN_ID);
        let peer = Hash::from_slice(&[1u8; 32]).unwrap();

        manager.state = SyncState::LoadingSnapshot { height: 40 };

        // Receive snapshot for wrong height
        let action = manager.on_snapshot_received(peer, 30, true);

        assert!(matches!(action, SyncAction::Wait));
    }

    #[test]
    fn on_snapshot_received_success_updates_height() {
        let mut manager = SyncManager::new(0, 50, Hash::zero(), Hash::zero(), TEST_CHAIN_ID);
        let peer = Hash::from_slice(&[1u8; 32]).unwrap();

        let status = make_peer_status(50, vec![40]);
        manager.peers.insert(peer, PeerSyncInfo::from(status));
        manager.best_peer = Some(peer);
        manager.state = SyncState::LoadingSnapshot { height: 40 };

        manager.on_snapshot_received(peer, 40, true);

        assert_eq!(manager.local_height, 40);
    }

    #[test]
    fn on_snapshot_received_success_at_target_verifies() {
        let mut manager = SyncManager::new(0, 50, Hash::zero(), Hash::zero(), TEST_CHAIN_ID);
        let peer = Hash::from_slice(&[1u8; 32]).unwrap();

        let status = make_peer_status(40, vec![40]);
        manager.peers.insert(peer, PeerSyncInfo::from(status));
        manager.best_peer = Some(peer);
        manager.state = SyncState::LoadingSnapshot { height: 40 };

        let action = manager.on_snapshot_received(peer, 40, true);

        assert!(matches!(action, SyncAction::VerifyState));
    }

    #[test]
    fn on_snapshot_received_success_continues_to_blocks() {
        let mut manager = SyncManager::new(0, 100, Hash::zero(), Hash::zero(), TEST_CHAIN_ID);
        let peer = Hash::from_slice(&[1u8; 32]).unwrap();

        let status = make_peer_status(100, vec![40]);
        manager.peers.insert(peer, PeerSyncInfo::from(status));
        manager.best_peer = Some(peer);
        manager.state = SyncState::LoadingSnapshot { height: 40 };

        let action = manager.on_snapshot_received(peer, 40, true);

        // Should request remaining blocks
        match action {
            SyncAction::RequestBlocks { start, .. } => {
                assert_eq!(start, 41);
            }
            _ => panic!("expected RequestBlocks action"),
        }
    }

    // ==================== Verification Tests ====================

    #[test]
    fn on_verify_complete_success_sets_in_sync() {
        let mut manager = SyncManager::new(100, 100, Hash::zero(), Hash::zero(), TEST_CHAIN_ID);
        manager.state = SyncState::Verifying;

        let action = manager.on_verify_complete(true);

        assert!(matches!(action, SyncAction::Done));
        assert!(manager.is_synced());
    }

    #[test]
    fn on_verify_complete_failure_resyncs() {
        let mut manager = SyncManager::new(100, 100, Hash::zero(), Hash::zero(), TEST_CHAIN_ID);
        let peer = Hash::from_slice(&[1u8; 32]).unwrap();

        let status = make_peer_status(100, vec![]);
        manager.peers.insert(peer, PeerSyncInfo::from(status));
        manager.best_peer = Some(peer);
        manager.state = SyncState::Verifying;

        let action = manager.on_verify_complete(false);

        // Should restart sync
        assert!(!manager.is_synced());
        // Action depends on state but shouldn't be Done
        assert!(!matches!(action, SyncAction::Done));
    }

    // ==================== Trigger Resync Tests ====================

    #[test]
    fn trigger_resync_requests_status_from_best_peer() {
        let mut manager = SyncManager::new(0, 0, Hash::zero(), Hash::zero(), TEST_CHAIN_ID);
        let peer = Hash::from_slice(&[1u8; 32]).unwrap();

        manager
            .peers
            .insert(peer, PeerSyncInfo::from(make_peer_status(100, vec![])));
        manager.best_peer = Some(peer);

        let action = manager.trigger_resync();

        assert!(matches!(action, SyncAction::RequestSyncStatus { .. }));
        assert!(matches!(manager.state(), SyncState::Discovering));
    }

    #[test]
    fn trigger_resync_waits_if_no_best_peer() {
        let mut manager = SyncManager::new(0, 0, Hash::zero(), Hash::zero(), TEST_CHAIN_ID);

        let action = manager.trigger_resync();

        assert!(matches!(action, SyncAction::Wait));
    }

    #[test]
    fn trigger_resync_waits_if_sync_failed() {
        let mut manager = SyncManager::new(0, 0, Hash::zero(), Hash::zero(), TEST_CHAIN_ID);
        let peer = Hash::from_slice(&[1u8; 32]).unwrap();

        manager
            .peers
            .insert(peer, PeerSyncInfo::from(make_peer_status(100, vec![])));
        manager.best_peer = Some(peer);
        manager.set_idle_failed();

        let action = manager.trigger_resync();

        assert!(matches!(action, SyncAction::Wait));
    }

    #[test]
    fn sync_failed_clears_on_new_snapshots() {
        let mut manager = SyncManager::new(0, 0, Hash::zero(), Hash::zero(), TEST_CHAIN_ID);
        let peer = Hash::from_slice(&[1u8; 32]).unwrap();

        manager.set_idle_failed();
        assert!(manager.sync_failed);

        // Receive status with snapshots
        manager.on_sync_status(peer, make_peer_status(100, vec![50]));

        assert!(!manager.sync_failed);
    }

    // ==================== Sync Mode Tests ====================

    #[test]
    fn sync_mode_in_sync_when_state_is_in_sync() {
        let mut manager = SyncManager::new(100, 100, Hash::zero(), Hash::zero(), TEST_CHAIN_ID);
        manager.state = SyncState::InSync;

        assert_eq!(manager.sync_mode(), SyncMode::InSync);
    }

    #[test]
    fn sync_mode_snapshot_when_loading_snapshot() {
        let mut manager = SyncManager::new(0, 0, Hash::zero(), Hash::zero(), TEST_CHAIN_ID);
        manager.state = SyncState::LoadingSnapshot { height: 50 };

        assert_eq!(manager.sync_mode(), SyncMode::SnapshotSync);
    }

    #[test]
    fn sync_mode_block_replay_when_replaying() {
        let mut manager = SyncManager::new(0, 0, Hash::zero(), Hash::zero(), TEST_CHAIN_ID);
        manager.state = SyncState::ReplayingBlocks {
            start: 1,
            target: 10,
            current: 5,
        };

        assert_eq!(manager.sync_mode(), SyncMode::BlockReplay);
    }

    // ==================== Edge Case Tests ====================

    #[test]
    fn no_peers_available_stays_idle() {
        let mut manager = SyncManager::new(0, 0, Hash::zero(), Hash::zero(), TEST_CHAIN_ID);

        // No peers connected, trigger sync
        let action = manager.trigger_resync();

        assert!(matches!(action, SyncAction::Wait));
        // Will transition to discovering but with no action
    }

    #[test]
    fn multiple_peers_selects_highest() {
        let mut manager = SyncManager::new(0, 0, Hash::zero(), Hash::zero(), TEST_CHAIN_ID);

        let peer1 = Hash::from_slice(&[1u8; 32]).unwrap();
        let peer2 = Hash::from_slice(&[2u8; 32]).unwrap();
        let peer3 = Hash::from_slice(&[3u8; 32]).unwrap();

        manager.on_sync_status(peer1, make_peer_status(50, vec![]));
        manager.on_sync_status(peer2, make_peer_status(100, vec![]));
        manager.on_sync_status(peer3, make_peer_status(75, vec![]));

        assert_eq!(manager.best_peer, Some(peer2));
    }

    #[test]
    fn headers_with_wrong_state_returns_wait() {
        let mut manager = SyncManager::new(0, 0, Hash::zero(), Hash::zero(), TEST_CHAIN_ID);
        let peer = Hash::from_slice(&[1u8; 32]).unwrap();

        // State is Idle, not SyncingHeaders
        let action = manager.on_headers(peer, &[]).expect("wrong state handled");

        assert!(matches!(action, SyncAction::Wait));
    }

    #[test]
    fn blocks_with_wrong_state_returns_wait() {
        let mut manager = SyncManager::new(0, 0, Hash::zero(), Hash::zero(), TEST_CHAIN_ID);
        let peer = Hash::from_slice(&[1u8; 32]).unwrap();

        // State is Idle, not ReplayingBlocks
        let action = manager.on_blocks(peer, &[], 0);

        assert!(matches!(action, SyncAction::Wait));
    }

    #[test]
    fn snapshot_received_with_wrong_state_returns_wait() {
        let mut manager = SyncManager::new(0, 0, Hash::zero(), Hash::zero(), TEST_CHAIN_ID);
        let peer = Hash::from_slice(&[1u8; 32]).unwrap();

        // State is Idle, not LoadingSnapshot
        let action = manager.on_snapshot_received(peer, 40, true);

        assert!(matches!(action, SyncAction::Wait));
    }
}
