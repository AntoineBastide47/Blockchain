//! Blockchain server orchestrating message handling via a transport layer.
//!
//! Processes incoming RPCs from the server's transport in a unified event loop.

use crate::core::account::Account;
use crate::core::block::{Block, Header};
use crate::core::blockchain::Blockchain;
use crate::core::transaction::Transaction;
use crate::core::validator::BlockValidator;
use crate::crypto::key_pair::{Address, PrivateKey};
use crate::network::message::{
    GetBlocksMessage, GetHeadersMessage, GetSnapshotStateMessage, Message, MessageType,
    SendBlocksMessage, SendHeadersMessage, SendSnapshotStateMessage, SendSyncStatusMessage,
    SnapshotEntry,
};
use crate::network::rpc::{DecodedMessage, DecodedMessageData, Rpc, RpcError, RpcProcessor};
use crate::network::sync::{SyncAction, SyncManager, SyncState};
use crate::network::transport::{Multiaddr, PeerId, Transport, TransportError};
use crate::storage::rocksdb_storage::{RocksDbStorage, Smt, SmtValue, h256_to_hash, hash_to_h256};
use crate::storage::storage_trait::StorageError;
use crate::storage::txpool::TxPool;
use crate::types::bytes::Bytes;
use crate::types::encoding::{Decode, Encode};
use crate::types::hash::Hash;
use crate::types::wrapper_types::BoxFuture;
use crate::{error, info, warn};
use sparse_merkle_tree::H256;
use sparse_merkle_tree::default_store::DefaultStore;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::task::JoinHandle;
use tokio::time::interval;

/// Chain identifier for development and testing environments.
///
/// Using chain ID 0 ensures transactions signed for development cannot be
/// replayed on production networks with different chain IDs.
pub const DEV_CHAIN_ID: u64 = 0;

/// Target interval between block productions.
///
/// Validators attempt to produce one block per `BLOCK_TIME` interval. This constant
/// also determines the maximum allowable timestamp drift for incoming blocks.
pub const BLOCK_TIME: Duration = Duration::from_secs(6);

/// Well-known private key bytes used exclusively for signing the genesis block.
/// This key has no authority beyond genesis; it exists solely to produce a
/// deterministic, verifiable genesis block signature across all nodes.
const GENESIS_PRIVATE_KEY_BYTES: [u8; 32] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
];

/// Errors produced by the server while handling RPCs and storage updates.
#[derive(Debug, blockchain_derive::Error)]
pub enum ServerError {
    /// Transaction signature or format failed verification.
    #[error("transaction failed verification: hash={0}")]
    InvalidTransaction(Hash),
    /// Block was rejected by the chain validator or storage layer.
    #[error("block rejected by chain: hash={hash} error={source}")]
    BlockRejected { hash: Hash, source: StorageError },
    /// Underlying transport layer failed.
    #[error("transport error: {0}")]
    Transport(TransportError),
    /// Remote peer's chain height is not ahead of ours; sync skipped.
    #[error("cannot sync with node, block height is to low: theirs {0} <= ours {1}")]
    BlockHeightToLow(u64, u64),
    /// Requested block hash does not exist in storage.
    #[error("block not found for: hash={0}")]
    BlockNotFound(Hash),
    /// Storage layer returned an error.
    #[error("storage error: {0}")]
    Storage(StorageError),
}

impl From<TransportError> for ServerError {
    fn from(err: TransportError) -> Self {
        ServerError::Transport(err)
    }
}

/// Blockchain server managing a single transport layer.
///
/// Processes RPC messages from the transport in an event loop,
/// handling transactions and block creation.
pub struct Server<T: Transport> {
    /// This server's transport layer (its network identity).
    transport: Arc<T>,
    /// If set, this node becomes a validator node.
    private_key: Option<PrivateKey>,
    /// Whether this node participates in block creation.
    is_validator: bool,
    /// Pool of pending transactions awaiting inclusion in a block.
    tx_pool: TxPool,
    /// The local blockchain storage with block validation and persistent storage.
    chain: Blockchain<BlockValidator, RocksDbStorage>,
    /// Genesis accounts used to initialize and potentially reset chain state.
    genesis_accounts: Box<[(Address, Account)]>,
    /// Sync manager handling the synchronization state machine.
    sync_manager: Mutex<SyncManager>,
}

impl<T: Transport> Server<T> {
    /// The genesis block, lazily initialized once and shared across all server instances.
    pub fn genesis_block(chain_id: u64, initial_accounts: &[(Address, Account)]) -> Block {
        let mut state = Smt::new(H256::zero(), DefaultStore::default());
        for (addr, account) in initial_accounts {
            state
                .update(hash_to_h256(addr), SmtValue(account.to_vec()))
                .expect("smt update failed");
        }

        let header = Header {
            version: 1,
            height: 0,
            timestamp: 0,
            gas_used: 0,
            previous_block: Hash::zero(),
            merkle_root: Hash::zero(),
            state_root: h256_to_hash(state.root()),
        };

        let genesis_key = PrivateKey::from_bytes(&GENESIS_PRIVATE_KEY_BYTES)
            .expect("GENESIS_PRIVATE_KEY_BYTES must be a valid secp256k1 scalar");

        Block::new(header, genesis_key, vec![], chain_id)
    }

    /// Creates a new server with full configuration options.
    ///
    /// Sets `is_validator` to true if `private_key` is provided.
    pub async fn new(
        transport: Arc<T>,
        db: Arc<rocksdb::DB>,
        private_key: Option<PrivateKey>,
        transaction_pool_capacity: Option<usize>,
        initial_accounts: &[(Address, Account)],
    ) -> Result<Arc<Self>, StorageError> {
        let is_validator = private_key.is_some();
        let chain_id = DEV_CHAIN_ID;
        let genesis_accounts: Box<[(Address, Account)]> =
            initial_accounts.to_vec().into_boxed_slice();

        let chain = Blockchain::new(
            chain_id,
            db,
            Self::genesis_block(chain_id, &genesis_accounts),
            &genesis_accounts,
        )?;

        let local_height = chain.height();
        let local_header_height = chain.header_height();
        let local_tip = chain.storage_tip();
        let local_header_tip = chain
            .get_header_by_height(local_header_height)
            .map(|h| h.header_hash(chain.id))
            .unwrap_or(local_tip);

        Ok(Arc::new(Self {
            transport,
            private_key,
            is_validator,
            tx_pool: TxPool::new(transaction_pool_capacity, chain_id),
            chain,
            genesis_accounts,
            sync_manager: Mutex::new(SyncManager::new(
                local_height,
                local_header_height,
                local_tip,
                local_header_tip,
                chain_id,
            )),
        }))
    }

    /// Initializes transport and, if applicable, starts the validator loop.
    /// Returns the validator task handle when one is spawned.
    pub async fn start(self: Arc<Self>, sx: Sender<Rpc>) -> Option<JoinHandle<()>> {
        info!("Server starting");
        self.transport.start(sx);

        if self.is_validator {
            let server_thread = self.clone();
            Some(tokio::spawn(
                async move { server_thread.validator_loop().await },
            ))
        } else {
            None
        }
    }

    /// Runs the main RPC processing loop until shutdown is signaled.
    pub async fn run(
        self: Arc<Self>,
        mut rx: Receiver<Rpc>,
        mut shutdown: tokio::sync::oneshot::Receiver<()>,
    ) {
        loop {
            tokio::select! {
                Some(rpc) = rx.recv() => {
                    match handle_rpc(rpc) {
                        Ok(msg) => {
                            if let Err(e) = &self.clone().process_message(msg).await {
                                error!("failed to process rpc: {}", e);
                            }
                        },
                        Err(e) => error!("failed to decode rpc: {}", e)
                    }
                }
                _ = &mut shutdown => {
                    break;
                }
                else => {
                    break;
                }
            }
        }
    }

    /// Stops background tasks and shuts down the transport.
    pub async fn stop(self: Arc<Self>, validator_handle: Option<JoinHandle<()>>) {
        if let Some(handle) = validator_handle {
            handle.abort();
        }

        self.transport.stop().await;
        info!("Server shut down");
    }

    async fn validator_loop(&self) {
        let mut ticker = interval(BLOCK_TIME);
        info!(
            "starting the validator loop: block_time={}",
            BLOCK_TIME.as_secs()
        );

        // Consume the initial ticker storage to force a wait period on startup
        ticker.tick().await;

        loop {
            ticker.tick().await;
            self.create_new_block().await;
        }
    }

    /// Connects to a peer at the given address and initiates the handshake protocol.
    ///
    /// Establishes transport-level connection, then sends a GetSyncStatus message
    /// to synchronize chain state if needed. Returns the peer's identifier.
    pub async fn connect(self: &Arc<Self>, addr: Multiaddr) -> Result<PeerId, ServerError> {
        let peer_id = self.transport.connect(addr).await.ok_or_else(|| {
            ServerError::Transport(TransportError::BroadcastFailed("connection failed".into()))
        })?;

        // Notify sync manager of new peer connection
        let action = {
            let mut sync = self.sync_manager.lock().unwrap();
            sync.on_peer_connected(peer_id)
        };
        self.execute_sync_action(action).await?;

        Ok(peer_id)
    }

    /// Sends a sync status request to the specified peer.
    async fn send_get_sync_status_message(&self, peer_id: PeerId) -> Result<(), TransportError> {
        let rpc = Message::new(MessageType::GetSyncStatus, 0x8u8.to_bytes());
        self.transport
            .send_message(peer_id, self.transport.peer_id(), rpc.to_bytes())
            .await
    }

    /// Returns true if actively syncing (downloading headers/blocks/snapshots).
    fn is_syncing(&self) -> bool {
        let sync = self.sync_manager.lock().unwrap();
        sync.is_actively_syncing()
    }

    /// Executes an action returned by the sync manager.
    async fn execute_sync_action(&self, action: SyncAction) -> Result<(), ServerError> {
        match action {
            SyncAction::RequestSyncStatus { peer } => {
                self.send_get_sync_status_message(peer).await?;
            }
            SyncAction::RequestHeaders { peer, start, end } => {
                let msg = GetHeadersMessage { start, end };
                let message = Message::new(MessageType::GetHeaders, msg.to_bytes());
                self.transport
                    .send_message(peer, self.transport.peer_id(), message.to_bytes())
                    .await
                    .map_err(ServerError::Transport)?;
            }
            SyncAction::RequestSnapshot { peer, height } => {
                let msg = GetSnapshotStateMessage { height };
                let message = Message::new(MessageType::GetSnapshotState, msg.to_bytes());
                self.transport
                    .send_message(peer, self.transport.peer_id(), message.to_bytes())
                    .await
                    .map_err(ServerError::Transport)?;
            }
            SyncAction::RequestBlocks { peer, start, end } => {
                let msg = GetBlocksMessage { start, end };
                let message = Message::new(MessageType::GetBlocks, msg.to_bytes());
                self.transport
                    .send_message(peer, self.transport.peer_id(), message.to_bytes())
                    .await
                    .map_err(ServerError::Transport)?;
            }
            SyncAction::VerifyState => {
                // Verify state root matches header
                let local_tip = self.chain.storage_tip();
                let success = if let Some(header) = self.chain.get_header(local_tip) {
                    header.state_root == self.chain.state_root()
                } else {
                    false
                };

                let next_action = {
                    let mut sync = self.sync_manager.lock().unwrap();
                    sync.on_verify_complete(success)
                };
                // Recursively execute next action
                return Box::pin(self.execute_sync_action(next_action)).await;
            }
            SyncAction::Done | SyncAction::Wait => {}
        }
        Ok(())
    }

    async fn create_new_block(&self) {
        let block = match self
            .chain
            .build_block(self.private_key.clone().unwrap(), &self.tx_pool)
        {
            Ok(b) => b,
            Err(e) => {
                warn!("{e}");
                return;
            }
        };

        if let Err(e) = self
            .broadcast(
                self.transport.peer_id(),
                block.to_bytes(),
                MessageType::Block,
            )
            .await
        {
            warn!("could not broadcast block: {e}");
        }
    }

    /// Validates and adds a transaction to the local pool.
    pub fn add_to_pool(&self, transaction: Transaction) -> Result<(), ServerError> {
        if !transaction.verify(self.chain.id) {
            return Err(ServerError::InvalidTransaction(
                transaction.id(self.chain.id),
            ));
        }

        let hash = transaction.from.address();
        let account = self
            .chain
            .get_account(hash)
            .ok_or(ServerError::Storage(StorageError::MissingAccount(hash)))?;
        self.tx_pool.append(&account, transaction);
        Ok(())
    }

    /// Returns a reference to the server's transport.
    pub fn transport(&self) -> &Arc<T> {
        &self.transport
    }

    /// Returns the account for the given address, if it exists.
    pub fn get_account(&self, address: Address) -> Option<Account> {
        self.chain.get_account(address)
    }

    /// Wraps a payload in a protocol message and broadcasts to all connected peers.
    ///
    /// The `from` peer ID is passed through to exclude the sender from receiving
    /// their own broadcast.
    async fn broadcast(
        &self,
        from: PeerId,
        payload: Bytes,
        msg_type: MessageType,
    ) -> Result<(), TransportError> {
        let msg = Message::new(msg_type, payload);
        self.transport.broadcast(from, msg.to_bytes()).await
    }

    /// Validates and adds a transaction to the pool, then broadcasts to peers.
    ///
    /// Skips duplicate transactions. Returns an error if verification fails.
    async fn process_transaction(
        self: Arc<Self>,
        from: PeerId,
        transaction: Transaction,
    ) -> Result<(), ServerError> {
        if self.is_syncing() {
            return Ok(());
        }

        let tx_id = transaction.id(self.chain.id);

        if self.tx_pool.contains(tx_id) {
            return Ok(());
        }

        if !transaction.verify(self.chain.id) {
            return Err(ServerError::InvalidTransaction(tx_id));
        }

        let bytes = transaction.to_bytes();
        let hash = transaction.from.address();
        let account = self
            .chain
            .get_account(hash)
            .ok_or(ServerError::Storage(StorageError::MissingAccount(hash)))?;
        if self.tx_pool.append(&account, transaction) {
            tokio::spawn(
                async move { self.broadcast(from, bytes, MessageType::Transaction).await },
            );
        }

        Ok(())
    }

    /// Adds a received block to the chain and broadcasts it to peers.
    ///
    /// Returns `Ok` if the block was successfully added, or an error if
    /// validation failed or the block was already present.
    async fn process_block(self: Arc<Self>, from: PeerId, block: Block) -> Result<(), ServerError> {
        if self.is_syncing() {
            let hash = block.header_hash(self.chain.id);
            warn!(
                "ignoring block during sync: height={} hash={hash}",
                block.header.height
            );
            return Ok(());
        }

        let local_tip = self.chain.storage_tip();
        if let Some(header) = self.chain.get_header(local_tip)
            && header.state_root != self.chain.state_root()
        {
            warn!(
                "local state root mismatch before block apply: tip={} header_root={} storage_root={}",
                local_tip,
                header.state_root,
                self.chain.state_root()
            );
            let action = {
                let mut sync = self.sync_manager.lock().unwrap();
                sync.trigger_resync()
            };
            if let Err(e) = self.execute_sync_action(action).await {
                warn!("failed to execute resync action: {e}");
            }
            return Ok(());
        }

        let expected_height = self.chain.height().saturating_add(1);
        if block.header.height != expected_height {
            let hash = block.header_hash(self.chain.id);
            warn!(
                "out-of-order block received: height={} expected={} hash={hash}",
                block.header.height, expected_height
            );
            let action = {
                let mut sync = self.sync_manager.lock().unwrap();
                sync.trigger_resync()
            };
            let _ = self.execute_sync_action(action).await;
            return Ok(());
        }

        let bytes = block.to_bytes();
        let header_hash = block.header_hash(self.chain.id);

        let hashes: Vec<Hash> = block
            .transactions
            .iter()
            .map(|tx| tx.id(self.chain.id))
            .collect();
        self.tx_pool.remove_batch(&hashes);

        self.chain
            .apply_block(block)
            .map_err(|e| ServerError::BlockRejected {
                hash: header_hash,
                source: e,
            })?;

        // Update sync manager with new local state
        {
            let mut sync = self.sync_manager.lock().unwrap();
            sync.update_local_state(
                self.chain.height(),
                self.chain.header_height(),
                self.chain.storage_tip(),
            );
        }

        // Gossip to all peers except origin
        tokio::spawn(async move { self.broadcast(from, bytes, MessageType::Block).await });
        Ok(())
    }

    /// Handles an incoming sync status request by responding with our chain info.
    async fn process_get_sync_status_message(
        self: Arc<Self>,
        from: PeerId,
    ) -> Result<(), ServerError> {
        let snapshot_heights = self
            .chain
            .snapshot_heights()
            .map_err(ServerError::Storage)?;

        let status = SendSyncStatusMessage {
            version: 1,
            height: self.chain.height(),
            tip: self.chain.storage_tip(),
            finalized_height: self.chain.height(), // For now, treat all blocks as finalized
            snapshot_heights,
        };
        let message = Message::new(MessageType::SendSyncStatus, status.to_bytes());

        self.transport
            .send_message(from, self.transport.peer_id(), message.to_bytes())
            .await
            .map_err(ServerError::Transport)
    }

    /// Handles a sync status response from a peer.
    ///
    /// Feeds the status to the sync manager which decides the next sync action.
    async fn process_send_sync_status_message(
        self: Arc<Self>,
        from: PeerId,
        status: SendSyncStatusMessage,
    ) -> Result<(), ServerError> {
        let action = {
            let mut sync = self.sync_manager.lock().unwrap();
            sync.on_sync_status(from, status)
        };
        self.execute_sync_action(action).await
    }

    /// Handles a headers request by walking the chain and sending requested headers.
    async fn process_get_headers_message(
        self: Arc<Self>,
        from: PeerId,
        req: GetHeadersMessage,
    ) -> Result<(), ServerError> {
        let current_header_height = self.chain.header_height();
        let end = if req.end == 0 && req.start > 0 {
            current_header_height
        } else {
            req.end
        };

        // No headers to send; range is invalid
        if req.start > end || end > current_header_height {
            let msg = Message::new(
                MessageType::SendHeaders,
                SendHeadersMessage {
                    headers: Box::new([]),
                }
                .to_bytes(),
            );
            return self
                .transport
                .send_message(from, self.transport.peer_id(), msg.to_bytes())
                .await
                .map_err(ServerError::Transport);
        }

        // Collect headers in range
        let mut headers = Vec::with_capacity((end - req.start + 1) as usize);
        for height in req.start..=end {
            if let Some(header) = self.chain.get_header_by_height(height) {
                headers.push(header);
            } else {
                // Header not found, send what we have
                break;
            }
        }

        let msg = SendHeadersMessage {
            headers: headers.into_boxed_slice(),
        };
        let message = Message::new(MessageType::SendHeaders, msg.to_bytes());
        self.transport
            .send_message(from, self.transport.peer_id(), message.to_bytes())
            .await
            .map_err(ServerError::Transport)
    }

    /// Handles a headers response from a peer.
    async fn process_send_headers_message(
        self: Arc<Self>,
        from: PeerId,
        response: SendHeadersMessage,
    ) -> Result<(), ServerError> {
        // Validate headers first before storing them
        let action = {
            let mut sync = self.sync_manager.lock().unwrap();
            sync.update_local_state(
                self.chain.height(),
                self.chain.header_height(),
                self.chain.storage_tip(),
            );
            sync.on_headers(from, &response.headers)
        };

        let action = match action {
            Ok(action) => action,
            Err(err) => {
                warn!("invalid headers from peer {from}: {err:?}");
                let action = {
                    let mut sync = self.sync_manager.lock().unwrap();
                    sync.trigger_resync()
                };
                return self.execute_sync_action(action).await;
            }
        };

        // Store headers after validation
        if !response.headers.is_empty() {
            self.chain
                .store_headers(&response.headers)
                .map_err(ServerError::Storage)?;
            let mut sync = self.sync_manager.lock().unwrap();
            sync.update_local_state(
                self.chain.height(),
                self.chain.header_height(),
                self.chain.storage_tip(),
            );
        }

        self.execute_sync_action(action).await
    }

    fn empty_blocks_message() -> SendBlocksMessage {
        SendBlocksMessage {
            blocks: Box::new([]),
        }
    }

    /// Handles a block range request by walking the chain and sending requested blocks.
    /// TODO: add a block send limit (ex: 500) to not overload the other node
    async fn process_get_blocks_message(
        self: Arc<Self>,
        from: PeerId,
        req: GetBlocksMessage,
    ) -> Result<(), ServerError> {
        // Check if all the available blocks were requested
        // Note: end=0 means "all blocks to tip" ONLY if start > 0
        // If start=0 and end=0, requester wants just the genesis block
        let current_height = self.chain.height();
        let end = if req.end == 0 && req.start > 0 {
            current_height
        } else {
            req.end
        };

        // No blocks to send; range is invalid or empty
        if req.start > end || end > current_height {
            let msg = Message::new(
                MessageType::SendBlocks,
                Self::empty_blocks_message().to_bytes(),
            );
            return self
                .transport
                .send_message(from, self.transport.peer_id(), msg.to_bytes())
                .await
                .map_err(ServerError::Transport);
        }

        let mut key = self.chain.storage_tip();
        let mut blocks: VecDeque<Block> = VecDeque::with_capacity((end - req.start + 1) as usize);

        // Walk back from tip to end, skip these blocks
        for _ in 0..(current_height - end) {
            match self.chain.get_header(key) {
                None => {
                    let msg = Message::new(
                        MessageType::SendBlocks,
                        Self::empty_blocks_message().to_bytes(),
                    );
                    return self
                        .transport
                        .send_message(from, self.transport.peer_id(), msg.to_bytes())
                        .await
                        .map_err(ServerError::Transport);
                }
                Some(header) => key = header.previous_block,
            };
        }

        // Collect blocks from end down to req.start
        // If we hit a pruned block, return whatever we have (partial sync)
        for _ in req.start..=end {
            match self.chain.get_block(key) {
                None => break,
                Some(block) => {
                    blocks.push_front((*block).clone());
                    key = block.header.previous_block;
                }
            }
        }

        let blocks_msg = SendBlocksMessage {
            blocks: blocks.into_iter().collect::<Vec<_>>().into_boxed_slice(),
        };
        let msg = Message::new(MessageType::SendBlocks, blocks_msg.to_bytes());
        self.transport
            .send_message(from, self.transport.peer_id(), msg.to_bytes())
            .await
            .map_err(ServerError::Transport)
    }

    /// Handles a blocks response by adding each block to the local chain.
    async fn process_send_blocks_message(
        self: Arc<Self>,
        from: PeerId,
        response: SendBlocksMessage,
    ) -> Result<(), ServerError> {
        // Apply all blocks
        let mut last_applied_height = self.chain.height();
        let expected_first = last_applied_height.saturating_add(1);

        // Check if first block is ahead of what we expected (blocks were pruned)
        if let Some(first) = response.blocks.first()
            && first.header.height > expected_first
        {
            error!(
                "blocks {} to {} were pruned by peer, cannot sync without snapshot",
                expected_first,
                first.header.height - 1
            );
            // Mark sync as failed - need snapshot but peer doesn't have one at a useful height
            let mut sync = self.sync_manager.lock().unwrap();
            sync.set_idle_failed();
            return Ok(());
        }

        for block in response.blocks.iter() {
            // Validate expected height
            let expected_height = self.chain.height().saturating_add(1);
            if block.header.height != expected_height {
                warn!(
                    "unexpected block height: got {} expected {}",
                    block.header.height, expected_height
                );
                break;
            }

            if let Err(err) = self.chain.apply_block(block.clone()) {
                let err_str = err.to_string();
                if err_str.contains("block already exists") {
                    // Block already applied, skip and continue
                    last_applied_height = block.header.height;
                    continue;
                }
                // Check if this is a state-related validation error
                if err_str.contains("nonce mismatch")
                    || err_str.contains("insufficient balance")
                    || err_str.contains("account not found")
                {
                    warn!(
                        "block {} replay failed: {err} - state mismatch, attempting genesis reset",
                        block.header.height
                    );
                    // Reset to genesis and retry block sync from the beginning
                    let genesis = Self::genesis_block(DEV_CHAIN_ID, &self.genesis_accounts);
                    if let Err(reset_err) =
                        self.chain.reset_to_genesis(genesis, &self.genesis_accounts)
                    {
                        error!("failed to reset to genesis: {reset_err}");
                        let mut sync = self.sync_manager.lock().unwrap();
                        sync.set_idle_failed();
                        return Ok(());
                    }
                    info!("reset to genesis successful, restarting sync");
                    let action = {
                        let mut sync = self.sync_manager.lock().unwrap();
                        sync.update_local_state(
                            self.chain.height(),
                            self.chain.header_height(),
                            self.chain.storage_tip(),
                        );
                        sync.trigger_resync()
                    };
                    let _ = self.execute_sync_action(action).await;
                    return Ok(());
                }
                warn!("block apply failed during sync: {err}");
                let action = {
                    let mut sync = self.sync_manager.lock().unwrap();
                    sync.trigger_resync()
                };
                let _ = self.execute_sync_action(action).await;
                return Ok(());
            }
            last_applied_height = block.header.height;
        }

        // Update sync manager and get next action
        let action = {
            let mut sync = self.sync_manager.lock().unwrap();
            sync.update_local_state(
                self.chain.height(),
                self.chain.header_height(),
                self.chain.storage_tip(),
            );
            sync.on_blocks(from, &response.blocks, last_applied_height)
        };
        self.execute_sync_action(action).await
    }

    /// Handles a snapshot state request by exporting state at the requested height.
    async fn process_get_snapshot_state_message(
        self: Arc<Self>,
        from: PeerId,
        req: GetSnapshotStateMessage,
    ) -> Result<(), ServerError> {
        // Check if we have a snapshot at this height
        let snapshot_heights = self
            .chain
            .snapshot_heights()
            .map_err(ServerError::Storage)?;

        if !snapshot_heights.contains(&req.height) && req.height != 0 {
            let msg = SendSnapshotStateMessage {
                height: req.height,
                block: Self::genesis_block(DEV_CHAIN_ID, &self.genesis_accounts),
                entries: Box::new([]),
            };
            let message = Message::new(MessageType::SendSnapshotState, msg.to_bytes());
            return self
                .transport
                .send_message(from, self.transport.peer_id(), message.to_bytes())
                .await
                .map_err(ServerError::Transport);
        }

        // Get the block at the snapshot height
        let block = if req.height == 0 {
            Self::genesis_block(DEV_CHAIN_ID, &self.genesis_accounts)
        } else {
            let tip = self
                .chain
                .snapshot_tip(req.height)
                .map_err(ServerError::Storage)?
                .ok_or_else(|| {
                    ServerError::Storage(StorageError::ValidationFailed(
                        "snapshot tip not found".into(),
                    ))
                })?;
            self.chain
                .get_block(tip)
                .ok_or(ServerError::BlockNotFound(tip))?
                .as_ref()
                .clone()
        };

        // Export the snapshot state
        let entries = if req.height == 0 {
            // For genesis, send the initial accounts
            self.genesis_accounts
                .iter()
                .map(|(addr, account)| SnapshotEntry {
                    key: *addr,
                    value: account.to_bytes(),
                })
                .collect::<Vec<_>>()
        } else {
            self.chain
                .export_snapshot(req.height)
                .map_err(ServerError::Storage)?
                .into_iter()
                .map(|(key, value)| SnapshotEntry {
                    key,
                    value: value.into(),
                })
                .collect::<Vec<_>>()
        };

        // Compute the state_root that these entries would produce
        let mut verify_state = Smt::new(H256::zero(), DefaultStore::default());
        for entry in entries.iter() {
            verify_state
                .update(hash_to_h256(&entry.key), SmtValue(entry.value.to_vec()))
                .expect("SMT update failed");
        }

        let computed_root = h256_to_hash(verify_state.root());
        if computed_root != block.header.state_root {
            return Err(ServerError::Storage(StorageError::ValidationFailed(
                format!(
                    "snapshot state root mismatch: computed={} header={}",
                    computed_root, block.header.state_root
                ),
            )));
        }

        let msg = SendSnapshotStateMessage {
            height: req.height,
            block,
            entries: entries.into_boxed_slice(),
        };
        let message = Message::new(MessageType::SendSnapshotState, msg.to_bytes());
        self.transport
            .send_message(from, self.transport.peer_id(), message.to_bytes())
            .await
            .map_err(ServerError::Transport)
    }

    /// Handles a snapshot state response by importing the state and continuing sync.
    async fn process_send_snapshot_state_message(
        self: Arc<Self>,
        from: PeerId,
        response: SendSnapshotStateMessage,
    ) -> Result<(), ServerError> {
        // Check if we're in the LoadingSnapshot state
        let expected_height = {
            let sync = self.sync_manager.lock().unwrap();
            match sync.state() {
                SyncState::LoadingSnapshot { height } => Some(*height),
                _ => None,
            }
        };

        let Some(height) = expected_height else {
            warn!("received unexpected snapshot response");
            return Ok(());
        };

        if response.height != height {
            warn!(
                "snapshot height mismatch: expected={} got={}",
                height, response.height
            );
            let action = {
                let mut sync = self.sync_manager.lock().unwrap();
                sync.on_snapshot_received(from, response.height, false)
            };
            return self.execute_sync_action(action).await;
        }

        // Empty response means peer doesn't have this snapshot
        let success = if response.entries.is_empty() && response.height != 0 {
            info!("peer has no snapshot at height={}", height);
            false
        } else {
            // Convert entries to the format expected by import_snapshot
            let entries: Vec<(Hash, Vec<u8>)> = response
                .entries
                .iter()
                .map(|e| (e.key, e.value.to_vec()))
                .collect();

            // Import the snapshot
            let import_result = if response.height == 0 {
                // For genesis, just reset to genesis
                let genesis = Self::genesis_block(DEV_CHAIN_ID, &self.genesis_accounts);
                self.chain.reset_to_genesis(genesis, &self.genesis_accounts)
            } else {
                self.chain
                    .import_snapshot(response.height, response.block, entries)
            };

            match import_result {
                Ok(()) => {
                    info!(
                        "imported snapshot at height={}, now syncing blocks from {}",
                        response.height,
                        response.height + 1
                    );
                    true
                }
                Err(e) => {
                    warn!("failed to import snapshot: {e}");
                    false
                }
            }
        };

        // Notify sync manager and get next action
        let action = {
            let mut sync = self.sync_manager.lock().unwrap();
            if success {
                sync.update_local_state(
                    self.chain.height(),
                    self.chain.header_height(),
                    self.chain.storage_tip(),
                );
            }
            sync.on_snapshot_received(from, response.height, success)
        };
        self.execute_sync_action(action).await
    }
}

impl<T: Transport> RpcProcessor for Server<T> {
    type Error = ServerError;
    fn process_message(
        self: Arc<Self>,
        decoded_message: DecodedMessage,
    ) -> BoxFuture<Result<(), Self::Error>> {
        Box::pin(async move {
            match decoded_message.data {
                DecodedMessageData::Transaction(tx) => {
                    self.process_transaction(decoded_message.peer_id, tx).await
                }
                DecodedMessageData::Block(block) => {
                    self.process_block(decoded_message.peer_id, block).await
                }
                DecodedMessageData::GetSyncStatus => {
                    self.process_get_sync_status_message(decoded_message.peer_id)
                        .await
                }
                DecodedMessageData::SendSyncStatus(response) => {
                    self.process_send_sync_status_message(decoded_message.peer_id, response)
                        .await
                }
                DecodedMessageData::GetHeaders(request) => {
                    self.process_get_headers_message(decoded_message.peer_id, request)
                        .await
                }
                DecodedMessageData::SendHeaders(response) => {
                    self.process_send_headers_message(decoded_message.peer_id, response)
                        .await
                }
                DecodedMessageData::GetBlocks(request) => {
                    self.process_get_blocks_message(decoded_message.peer_id, request)
                        .await
                }
                DecodedMessageData::SendBlocks(response) => {
                    self.process_send_blocks_message(decoded_message.peer_id, response)
                        .await
                }
                DecodedMessageData::GetSnapshotState(request) => {
                    self.process_get_snapshot_state_message(decoded_message.peer_id, request)
                        .await
                }
                DecodedMessageData::SendSnapshotState(response) => {
                    self.process_send_snapshot_state_message(decoded_message.peer_id, response)
                        .await
                }
            }
        })
    }
}

/// Default RPC handler that deserializes messages based on their type header.
fn handle_rpc(rpc: Rpc) -> Result<DecodedMessage, RpcError> {
    let msg = Message::from_bytes(rpc.payload.as_ref()).map_err(|e| RpcError::Message {
        from: rpc.peer_id,
        details: format!("{e:?}"),
    })?;

    match msg.header {
        MessageType::Transaction => {
            let tx = Transaction::from_bytes(msg.data.as_ref())
                .map_err(|e| RpcError::Transaction(format!("{e:?}")))?;
            Ok(DecodedMessage {
                peer_id: rpc.peer_id,
                data: DecodedMessageData::Transaction(tx),
            })
        }
        MessageType::Block => {
            let block = Block::from_bytes(msg.data.as_ref())
                .map_err(|e| RpcError::Block(format!("{e:?}")))?;
            Ok(DecodedMessage {
                peer_id: rpc.peer_id,
                data: DecodedMessageData::Block(block),
            })
        }
        MessageType::GetSyncStatus => Ok(DecodedMessage {
            peer_id: rpc.peer_id,
            data: DecodedMessageData::GetSyncStatus,
        }),
        MessageType::SendSyncStatus => {
            let status = SendSyncStatusMessage::from_bytes(msg.data.as_ref())
                .map_err(|e| RpcError::Decode(format!("{e:?}")))?;
            Ok(DecodedMessage {
                peer_id: rpc.peer_id,
                data: DecodedMessageData::SendSyncStatus(status),
            })
        }
        MessageType::GetHeaders => {
            let get_headers_msg = GetHeadersMessage::from_bytes(msg.data.as_ref())
                .map_err(|e| RpcError::Decode(format!("{e:?}")))?;
            Ok(DecodedMessage {
                peer_id: rpc.peer_id,
                data: DecodedMessageData::GetHeaders(get_headers_msg),
            })
        }
        MessageType::SendHeaders => {
            let send_headers_msg = SendHeadersMessage::from_bytes(msg.data.as_ref())
                .map_err(|e| RpcError::Decode(format!("{e:?}")))?;
            Ok(DecodedMessage {
                peer_id: rpc.peer_id,
                data: DecodedMessageData::SendHeaders(send_headers_msg),
            })
        }
        MessageType::GetBlocks => {
            let get_blocks_msg = GetBlocksMessage::from_bytes(msg.data.as_ref())
                .map_err(|e| RpcError::Decode(format!("{e:?}")))?;
            Ok(DecodedMessage {
                peer_id: rpc.peer_id,
                data: DecodedMessageData::GetBlocks(get_blocks_msg),
            })
        }
        MessageType::SendBlocks => {
            let send_blocks_msg = SendBlocksMessage::from_bytes(msg.data.as_ref())
                .map_err(|e| RpcError::Decode(format!("{e:?}")))?;
            Ok(DecodedMessage {
                peer_id: rpc.peer_id,
                data: DecodedMessageData::SendBlocks(send_blocks_msg),
            })
        }
        MessageType::GetSnapshotState => {
            let get_snapshot_msg = GetSnapshotStateMessage::from_bytes(msg.data.as_ref())
                .map_err(|e| RpcError::Decode(format!("{e:?}")))?;
            Ok(DecodedMessage {
                peer_id: rpc.peer_id,
                data: DecodedMessageData::GetSnapshotState(get_snapshot_msg),
            })
        }
        MessageType::SendSnapshotState => {
            let send_snapshot_msg = SendSnapshotStateMessage::from_bytes(msg.data.as_ref())
                .map_err(|e| RpcError::Decode(format!("{e:?}")))?;
            Ok(DecodedMessage {
                peer_id: rpc.peer_id,
                data: DecodedMessageData::SendSnapshotState(send_snapshot_msg),
            })
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::crypto::key_pair::PrivateKey;
    use crate::network::local_transport::tests::LocalTransport;
    use crate::network::rpc::Rpc;
    use crate::network::sync::SyncState;
    use crate::storage::rocksdb_storage::{CF_BLOCKS, CF_HEADERS, CF_META, CF_SNAPSHOTS, CF_STATE};
    use crate::utils::test_utils::utils::{new_tx, test_rpc};
    use crate::virtual_machine::vm::BLOCK_GAS_LIMIT;
    use rocksdb::{ColumnFamilyDescriptor, DB, Options};
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicU16, Ordering};
    use tokio::sync::mpsc::channel;

    const TEST_CHAIN_ID: u64 = 10;

    /// Creates a temporary RocksDB instance for testing.
    pub fn test_db() -> Arc<DB> {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);

        let cfs = vec![
            ColumnFamilyDescriptor::new(CF_HEADERS, Options::default()),
            ColumnFamilyDescriptor::new(CF_BLOCKS, Options::default()),
            ColumnFamilyDescriptor::new(CF_META, Options::default()),
            ColumnFamilyDescriptor::new(CF_STATE, Options::default()),
            ColumnFamilyDescriptor::new(CF_SNAPSHOTS, Options::default()),
        ];

        // Leak the tempdir to keep it alive for the duration of the test
        let path = dir.keep();
        Arc::new(DB::open_cf_descriptors(&opts, &path, cfs).expect("failed to open test db"))
    }

    /// Creates a new server with sensible defaults for a non-validator node.
    pub async fn default_server<T: Transport>(transport: Arc<T>) -> Arc<Server<T>> {
        Server::new(transport, test_db(), None, None, &[])
            .await
            .expect("failed to create test server")
    }

    /// Atomic port counter to ensure unique ports across parallel tests.
    static PORT_COUNTER: AtomicU16 = AtomicU16::new(5000);

    /// Allocates a unique port for test isolation.
    fn alloc_port() -> u16 {
        PORT_COUNTER.fetch_add(1, Ordering::Relaxed)
    }

    fn addr() -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], alloc_port()))
    }

    fn build_tx(data: &[u8], key: PrivateKey) -> Transaction {
        new_tx(Bytes::new(data), key, TEST_CHAIN_ID)
    }

    fn build_header_chain(start: u64, end: u64, mut prev_hash: Hash) -> Vec<Header> {
        let mut headers = Vec::with_capacity((end - start + 1) as usize);
        for height in start..=end {
            let header = Header {
                version: 1,
                height,
                timestamp: 0,
                gas_used: 0,
                previous_block: prev_hash,
                merkle_root: Hash::zero(),
                state_root: Hash::zero(),
            };
            prev_hash = header.header_hash(DEV_CHAIN_ID);
            headers.push(header);
        }
        headers
    }

    #[tokio::test]
    async fn server_is_validator_when_private_key_set() {
        let transport = LocalTransport::new(addr());
        let server = Server::new(transport, test_db(), Some(PrivateKey::new()), None, &[])
            .await
            .unwrap();
        assert!(server.is_validator);
    }

    #[tokio::test]
    async fn server_is_not_validator_without_private_key() {
        let transport = LocalTransport::new(addr());
        let server = default_server(transport).await;
        assert!(!server.is_validator);
    }

    #[tokio::test]
    async fn start_returns_validator_handle_when_enabled() {
        let transport = LocalTransport::new(addr());
        let server = Server::new(transport, test_db(), Some(PrivateKey::new()), None, &[])
            .await
            .unwrap();

        let (sx, _rx) = channel::<Rpc>(1);
        let validator_handle = server.clone().start(sx).await;
        assert!(validator_handle.is_some());

        server.stop(validator_handle).await;
    }

    #[tokio::test]
    async fn start_returns_none_for_non_validator() {
        let transport = LocalTransport::new(addr());
        let server = default_server(transport).await;

        let (sx, _rx) = channel::<Rpc>(1);
        let validator_handle = server.clone().start(sx).await;
        assert!(validator_handle.is_none());

        server.stop(validator_handle).await;
    }

    #[test]
    fn handle_rpc_decodes_valid_transaction() {
        let sender = addr();
        let key = PrivateKey::new();
        let tx = build_tx(b"test data", key);
        let tx_bytes = tx.to_bytes();

        let msg = Message::new(MessageType::Transaction, tx_bytes);
        let msg_bytes = msg.to_bytes();

        let rpc = test_rpc(sender, msg_bytes);
        let result = handle_rpc(rpc).expect("should decode successfully");

        match result.data {
            DecodedMessageData::Transaction(decoded_tx) => {
                assert_eq!(decoded_tx.id(TEST_CHAIN_ID), tx.id(TEST_CHAIN_ID));
            }
            _ => panic!("expected Transaction variant"),
        }
    }

    #[test]
    fn handle_rpc_rejects_malformed_payload() {
        let rpc = test_rpc(addr(), vec![0xFF, 0xFF, 0xFF]);
        let result = handle_rpc(rpc);

        assert!(matches!(result, Err(RpcError::Message { .. })));
    }

    #[test]
    fn handle_rpc_rejects_invalid_transaction_data() {
        let msg = Message::new(MessageType::Transaction, vec![0x00, 0x01, 0x02]);
        let msg_bytes = msg.to_bytes();

        let rpc = test_rpc(addr(), msg_bytes);
        let result = handle_rpc(rpc);

        assert!(matches!(result, Err(RpcError::Transaction { .. })));
    }

    fn create_test_block(transactions: Vec<Transaction>) -> Block {
        let header = Header {
            version: 1,
            height: 1,
            timestamp: 1234567890,
            gas_used: BLOCK_GAS_LIMIT,
            previous_block: Hash::zero(),
            merkle_root: Hash::zero(),
            state_root: Hash::zero(),
        };
        Block::new(header, PrivateKey::new(), transactions, TEST_CHAIN_ID)
    }

    #[test]
    fn handle_rpc_decodes_valid_block() {
        let sender = addr();
        let block = create_test_block(vec![]);
        let block_bytes = block.to_bytes();

        let msg = Message::new(MessageType::Block, block_bytes);
        let msg_bytes = msg.to_bytes();

        let rpc = test_rpc(sender, msg_bytes);
        let result = handle_rpc(rpc).expect("should decode successfully");

        match result.data {
            DecodedMessageData::Block(decoded_block) => {
                assert_eq!(
                    decoded_block.header_hash(TEST_CHAIN_ID),
                    block.header_hash(TEST_CHAIN_ID)
                );
                assert_eq!(decoded_block.header.height, 1);
            }
            _ => panic!("expected Block variant"),
        }
    }

    #[test]
    fn handle_rpc_rejects_invalid_block_data() {
        let msg = Message::new(MessageType::Block, vec![0x00, 0x01, 0x02]);
        let msg_bytes = msg.to_bytes();

        let rpc = test_rpc(addr(), msg_bytes);
        let result = handle_rpc(rpc);

        assert!(matches!(result, Err(RpcError::Block { .. })));
    }

    #[test]
    fn handle_rpc_preserves_block_transactions() {
        let key = PrivateKey::new();
        let tx1 = build_tx(b"tx1", key.clone());
        let tx2 = build_tx(b"tx2", key);
        let tx1_hash = tx1.id(TEST_CHAIN_ID);
        let tx2_hash = tx2.id(TEST_CHAIN_ID);

        let block = create_test_block(vec![tx1, tx2]);
        let block_bytes = block.to_bytes();

        let msg = Message::new(MessageType::Block, block_bytes);
        let msg_bytes = msg.to_bytes();

        let rpc = test_rpc(addr(), msg_bytes);
        let result = handle_rpc(rpc).expect("should decode successfully");

        match result.data {
            DecodedMessageData::Block(decoded_block) => {
                assert_eq!(decoded_block.transactions.len(), 2);
                assert_eq!(decoded_block.transactions[0].id(TEST_CHAIN_ID), tx1_hash);
                assert_eq!(decoded_block.transactions[1].id(TEST_CHAIN_ID), tx2_hash);
            }
            _ => panic!("expected Block variant"),
        }
    }

    #[test]
    fn handle_rpc_decodes_block_with_truncated_data() {
        let block = create_test_block(vec![]);
        let mut block_bytes = block.to_bytes();
        let len = block_bytes.len() / 2;

        // Truncate the block data
        block_bytes.make_mut().truncate(len);

        let msg = Message::new(MessageType::Block, block_bytes.to_bytes());
        let msg_bytes = msg.to_bytes();

        let rpc = test_rpc(addr(), msg_bytes);
        let result = handle_rpc(rpc);

        assert!(matches!(result, Err(RpcError::Block { .. })));
    }

    #[test]
    fn handle_rpc_decodes_get_sync_status() {
        let peer = addr();
        let msg = Message::new(MessageType::GetSyncStatus, 0x8u8.to_bytes());
        let rpc = test_rpc(peer, msg.to_bytes());
        let result = handle_rpc(rpc).expect("should decode");

        assert!(matches!(result.data, DecodedMessageData::GetSyncStatus));
    }

    #[test]
    fn handle_rpc_decodes_send_sync_status() {
        let peer = addr();
        let status = SendSyncStatusMessage {
            version: 1,
            height: 100,
            tip: Hash::zero(),
            finalized_height: 100,
            snapshot_heights: vec![],
        };
        let msg = Message::new(MessageType::SendSyncStatus, status.to_bytes());
        let rpc = test_rpc(peer, msg.to_bytes());
        let result = handle_rpc(rpc).expect("should decode");

        match result.data {
            DecodedMessageData::SendSyncStatus(s) => {
                assert_eq!(s.version, 1);
                assert_eq!(s.height, 100);
                assert_eq!(s.tip, Hash::zero());
            }
            _ => panic!("expected SendSyncStatus"),
        }
    }

    #[test]
    fn handle_rpc_decodes_get_blocks() {
        let peer = addr();
        let get_blocks = GetBlocksMessage { start: 5, end: 10 };
        let msg = Message::new(MessageType::GetBlocks, get_blocks.to_bytes());
        let rpc = test_rpc(peer, msg.to_bytes());
        let result = handle_rpc(rpc).expect("should decode");

        match result.data {
            DecodedMessageData::GetBlocks(req) => {
                assert_eq!(req.start, 5);
                assert_eq!(req.end, 10);
            }
            _ => panic!("expected GetBlocks"),
        }
    }

    #[test]
    fn handle_rpc_decodes_send_blocks_empty() {
        let peer = addr();
        let send_blocks = SendBlocksMessage {
            blocks: Box::new([]),
        };
        let msg = Message::new(MessageType::SendBlocks, send_blocks.to_bytes());
        let rpc = test_rpc(peer, msg.to_bytes());
        let result = handle_rpc(rpc).expect("should decode");

        match result.data {
            DecodedMessageData::SendBlocks(resp) => {
                assert!(resp.blocks.is_empty());
            }
            _ => panic!("expected SendBlocks"),
        }
    }

    #[test]
    fn handle_rpc_decodes_get_snapshot_state() {
        let peer = addr();
        let req = GetSnapshotStateMessage { height: 42 };
        let msg = Message::new(MessageType::GetSnapshotState, req.to_bytes());
        let rpc = test_rpc(peer, msg.to_bytes());
        let result = handle_rpc(rpc).expect("should decode");

        match result.data {
            DecodedMessageData::GetSnapshotState(decoded) => {
                assert_eq!(decoded.height, 42);
            }
            _ => panic!("expected GetSnapshotState"),
        }
    }

    #[test]
    fn handle_rpc_decodes_send_snapshot_state() {
        let peer = addr();
        let block = create_test_block(vec![]);
        let entries = vec![SnapshotEntry {
            key: Hash::zero(),
            value: Bytes::new(vec![1, 2, 3]),
        }];
        let resp = SendSnapshotStateMessage {
            height: 1,
            block: block.clone(),
            entries: entries.into_boxed_slice(),
        };
        let msg = Message::new(MessageType::SendSnapshotState, resp.to_bytes());
        let rpc = test_rpc(peer, msg.to_bytes());
        let result = handle_rpc(rpc).expect("should decode");

        match result.data {
            DecodedMessageData::SendSnapshotState(decoded) => {
                assert_eq!(decoded.height, 1);
                assert_eq!(decoded.entries.len(), 1);
                assert_eq!(
                    decoded.block.header_hash(TEST_CHAIN_ID),
                    block.header_hash(TEST_CHAIN_ID)
                );
            }
            _ => panic!("expected SendSnapshotState"),
        }
    }

    #[tokio::test]
    async fn server_connect_establishes_bidirectional_transport() {
        let addr_a = addr();
        let addr_b = addr();
        let tr_a = LocalTransport::new(addr_a);
        let tr_b = LocalTransport::new(addr_b);

        let server_a = default_server(tr_a.clone()).await;
        let _server_b = default_server(tr_b.clone()).await;

        server_a.connect(tr_b.addr()).await.unwrap();

        // Transport-level connection should be bidirectional
        let a_peers = tr_a.peer_ids();
        let b_peers = tr_b.peer_ids();
        assert!(a_peers.contains(&tr_b.peer_id()));
        assert!(b_peers.contains(&tr_a.peer_id()));
    }

    #[tokio::test]
    async fn server_connect_sends_get_sync_status_message() {
        let addr_a = addr();
        let addr_b = addr();
        let tr_a = LocalTransport::new(addr_a);
        let tr_b = LocalTransport::new(addr_b);

        let server_a = default_server(tr_a.clone()).await;
        let _server_b = default_server(tr_b.clone()).await;

        let mut rx_b = tr_b.consume().await;

        server_a.connect(tr_b.addr()).await.unwrap();

        // B should receive a GetSyncStatus message from A
        let rpc = rx_b.recv().await.expect("should receive message");
        let msg = Message::from_bytes(&rpc.payload).expect("should decode message");
        assert!(matches!(msg.header, MessageType::GetSyncStatus));
    }

    #[tokio::test]
    async fn process_get_sync_status_responds_with_send_sync_status() {
        let addr_a = addr();
        let addr_b = addr();
        let tr_a = LocalTransport::new(addr_a);
        let tr_b = LocalTransport::new(addr_b);
        tr_a.connect(tr_b.addr()).await;

        let server_a = default_server(tr_a.clone()).await;

        let mut rx_b = tr_b.consume().await;

        // Process a GetSyncStatus message from B
        server_a
            .clone()
            .process_get_sync_status_message(tr_b.peer_id())
            .await
            .unwrap();

        // B should receive a SendSyncStatus response
        let rpc = rx_b.recv().await.expect("should receive response");
        let msg = Message::from_bytes(&rpc.payload).expect("decode message");
        assert!(matches!(msg.header, MessageType::SendSyncStatus));

        let status = SendSyncStatusMessage::from_bytes(&msg.data).expect("decode status");
        assert_eq!(status.height, 0); // Only genesis block
        assert_eq!(status.tip, server_a.chain.storage_tip());
    }

    #[tokio::test]
    async fn process_send_sync_status_skips_sync_when_both_new_nodes() {
        let tr_a = LocalTransport::new(addr());
        let server_a = default_server(tr_a.clone()).await;

        // Both nodes at height 0 (new nodes) - sync completes immediately
        let status = SendSyncStatusMessage {
            version: 1,
            height: 0,
            tip: server_a.chain.storage_tip(), // Same tip means already in sync
            finalized_height: 0,
            snapshot_heights: vec![],
        };

        let result = server_a
            .clone()
            .process_send_sync_status_message(PeerId::zero(), status)
            .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn process_send_sync_status_requests_headers_when_peer_ahead() {
        let addr_a = addr();
        let addr_b = addr();
        let tr_a = LocalTransport::new(addr_a);
        let tr_b = LocalTransport::new(addr_b);
        tr_a.connect(tr_b.addr()).await;

        let server_a = default_server(tr_a.clone()).await;

        let mut rx_b = tr_b.consume().await;

        // Peer reports height 5, ahead of our genesis-only chain (height 0)
        let status = SendSyncStatusMessage {
            version: 1,
            height: 5,
            tip: Hash::zero(),
            finalized_height: 5,
            snapshot_heights: vec![],
        };

        server_a
            .clone()
            .process_send_sync_status_message(tr_b.peer_id(), status)
            .await
            .unwrap();

        // Should send GetHeaders request to B (header-first sync)
        let rpc = rx_b.recv().await.expect("should receive GetHeaders");
        let msg = Message::from_bytes(&rpc.payload).expect("decode message");
        assert!(matches!(msg.header, MessageType::GetHeaders));

        let get_headers = GetHeadersMessage::from_bytes(&msg.data).expect("decode GetHeaders");
        assert_eq!(get_headers.start, 1); // Start from height 1 (after genesis)
    }

    #[tokio::test]
    async fn process_get_blocks_returns_empty_for_invalid_range() {
        let addr_a = addr();
        let addr_b = addr();
        let tr_a = LocalTransport::new(addr_a);
        let tr_b = LocalTransport::new(addr_b);
        tr_a.connect(tr_b.addr()).await;

        let server_a = default_server(tr_a.clone()).await;

        let mut rx_b = tr_b.consume().await;

        // Request blocks 10-20 when chain only has genesis (height 0)
        let req = GetBlocksMessage { start: 10, end: 20 };
        server_a
            .clone()
            .process_get_blocks_message(tr_b.peer_id(), req)
            .await
            .unwrap();

        let rpc = rx_b.recv().await.expect("should receive response");
        let msg = Message::from_bytes(&rpc.payload).expect("decode message");
        let response = SendBlocksMessage::from_bytes(&msg.data).expect("decode SendBlocks");

        assert!(response.blocks.is_empty());
    }

    #[tokio::test]
    async fn process_get_blocks_returns_empty_for_start_greater_than_end() {
        let addr_a = addr();
        let addr_b = addr();
        let tr_a = LocalTransport::new(addr_a);
        let tr_b = LocalTransport::new(addr_b);
        tr_a.connect(tr_b.addr()).await;

        let server_a = default_server(tr_a.clone()).await;

        let mut rx_b = tr_b.consume().await;

        // Start > end (invalid range)
        let req = GetBlocksMessage { start: 5, end: 2 };
        server_a
            .clone()
            .process_get_blocks_message(tr_b.peer_id(), req)
            .await
            .unwrap();

        let rpc = rx_b.recv().await.expect("should receive response");
        let msg = Message::from_bytes(&rpc.payload).expect("decode message");
        let response = SendBlocksMessage::from_bytes(&msg.data).expect("decode SendBlocks");

        assert!(response.blocks.is_empty());
    }

    #[tokio::test]
    async fn process_send_blocks_adds_blocks_to_chain() {
        let tr_a = LocalTransport::new(addr());
        let tr_b = LocalTransport::new(addr());
        let validator_key = PrivateKey::new();
        let validator_account = (validator_key.public_key().address(), Account::new(0));
        let server_a = Server::new(
            tr_a,
            test_db(),
            Some(validator_key.clone()),
            None,
            std::slice::from_ref(&validator_account),
        )
        .await
        .unwrap();

        // Use a builder server to create valid blocks with correct state_root
        let peer_b = tr_b.peer_id();
        let server_builder = Server::new(
            tr_b,
            test_db(),
            Some(validator_key.clone()),
            None,
            std::slice::from_ref(&validator_account),
        )
        .await
        .unwrap();

        let block = server_builder
            .chain
            .build_block(validator_key, &TxPool::new(Some(1), TEST_CHAIN_ID))
            .expect("build_block failed");

        assert_eq!(server_a.chain.height(), 0);

        let response = SendBlocksMessage {
            blocks: vec![block].into_boxed_slice(),
        };

        server_a
            .clone()
            .process_send_blocks_message(peer_b, response)
            .await
            .unwrap();

        assert_eq!(server_a.chain.height(), 1);
    }

    #[tokio::test]
    async fn process_send_blocks_adds_multiple_blocks_in_order() {
        let tr_a = LocalTransport::new(addr());
        let tr_b = LocalTransport::new(addr());
        let validator_key = PrivateKey::new();
        let validator_account = (validator_key.public_key().address(), Account::new(0));
        let server_a = Server::new(
            tr_a,
            test_db(),
            Some(validator_key.clone()),
            None,
            std::slice::from_ref(&validator_account),
        )
        .await
        .unwrap();

        // Use a builder server to create valid blocks with correct state_root
        let peer_b = tr_b.peer_id();
        let server_builder = Server::new(
            tr_b,
            test_db(),
            Some(validator_key.clone()),
            None,
            std::slice::from_ref(&validator_account),
        )
        .await
        .unwrap();

        // Build block 1
        let block1 = server_builder
            .chain
            .build_block(validator_key.clone(), &TxPool::new(Some(1), TEST_CHAIN_ID))
            .expect("build_block 1 failed");

        // Build block 2
        let block2 = server_builder
            .chain
            .build_block(validator_key, &TxPool::new(Some(1), TEST_CHAIN_ID))
            .expect("build_block 2 failed");

        let response = SendBlocksMessage {
            blocks: vec![block1, block2].into_boxed_slice(),
        };

        server_a
            .clone()
            .process_send_blocks_message(peer_b, response)
            .await
            .unwrap();

        assert_eq!(server_a.chain.height(), 2);
    }

    #[tokio::test]
    async fn late_server_syncs_with_established_chain() {
        let addr_established = addr();
        let addr_late = addr();

        // Create an established server with blocks
        let tr_established = LocalTransport::new(addr_established);
        let validator_key = PrivateKey::new();
        let validator_account = (validator_key.public_key().address(), Account::new(0));
        let server_established = Server::new(
            tr_established.clone(),
            test_db(),
            Some(validator_key.clone()),
            None,
            std::slice::from_ref(&validator_account),
        )
        .await
        .unwrap();

        // Build 3 blocks on the established server
        for _ in 0..3 {
            server_established
                .chain
                .build_block(validator_key.clone(), &TxPool::new(Some(1), TEST_CHAIN_ID))
                .expect("build_block failed");
        }
        assert_eq!(server_established.chain.height(), 3);

        // Create a late-joining server
        let tr_late = LocalTransport::new(addr_late);
        let server_late = Server::new(
            tr_late.clone(),
            test_db(),
            None,
            None,
            std::slice::from_ref(&validator_account),
        )
        .await
        .unwrap();
        assert_eq!(server_late.chain.height(), 0);

        // Connect late server to established (sends GetSyncStatus)
        let mut rx_established = tr_established.consume().await;
        server_late.connect(tr_established.addr()).await.unwrap();

        // Established receives GetSyncStatus from Late
        let rpc = rx_established
            .recv()
            .await
            .expect("should receive GetSyncStatus");
        let msg = Message::from_bytes(&rpc.payload).expect("decode");
        assert!(matches!(msg.header, MessageType::GetSyncStatus));

        // Established processes GetSyncStatus and sends SendSyncStatus
        let mut rx_late = tr_late.consume().await;
        server_established
            .clone()
            .process_get_sync_status_message(tr_late.peer_id())
            .await
            .unwrap();

        // Late receives SendSyncStatus
        let rpc = rx_late.recv().await.expect("should receive SendSyncStatus");
        let msg = Message::from_bytes(&rpc.payload).expect("decode");
        assert!(matches!(msg.header, MessageType::SendSyncStatus));
        let status = SendSyncStatusMessage::from_bytes(&msg.data).expect("decode status");
        assert_eq!(status.height, 3);
        assert_eq!(status.tip, server_established.chain.storage_tip());

        // Late processes SendSyncStatus and sends GetHeaders (header-first sync)
        server_late
            .clone()
            .process_send_sync_status_message(tr_established.peer_id(), status)
            .await
            .unwrap();

        // Established receives GetHeaders
        let rpc = rx_established
            .recv()
            .await
            .expect("should receive GetHeaders");
        let msg = Message::from_bytes(&rpc.payload).expect("decode");
        assert!(matches!(msg.header, MessageType::GetHeaders));
        let get_headers = GetHeadersMessage::from_bytes(&msg.data).expect("decode GetHeaders");
        assert_eq!(get_headers.start, 1);

        // Established processes GetHeaders and sends SendHeaders
        server_established
            .clone()
            .process_get_headers_message(tr_late.peer_id(), get_headers)
            .await
            .unwrap();

        // Late receives SendHeaders
        let rpc = rx_late.recv().await.expect("should receive SendHeaders");
        let msg = Message::from_bytes(&rpc.payload).expect("decode");
        assert!(matches!(msg.header, MessageType::SendHeaders));
        let send_headers = SendHeadersMessage::from_bytes(&msg.data).expect("decode SendHeaders");
        assert_eq!(send_headers.headers.len(), 3);

        // Late processes SendHeaders - this stores headers and triggers block sync
        server_late
            .clone()
            .process_send_headers_message(tr_established.peer_id(), send_headers)
            .await
            .unwrap();

        // Established receives GetBlocks
        let rpc = rx_established
            .recv()
            .await
            .expect("should receive GetBlocks");
        let msg = Message::from_bytes(&rpc.payload).expect("decode");
        assert!(matches!(msg.header, MessageType::GetBlocks));
        let get_blocks = GetBlocksMessage::from_bytes(&msg.data).expect("decode GetBlocks");
        assert_eq!(get_blocks.start, 1);

        // Established processes GetBlocks and sends SendBlocks
        server_established
            .clone()
            .process_get_blocks_message(tr_late.peer_id(), get_blocks)
            .await
            .unwrap();

        // Late receives SendBlocks
        let rpc = rx_late.recv().await.expect("should receive SendBlocks");
        let msg = Message::from_bytes(&rpc.payload).expect("decode");
        assert!(matches!(msg.header, MessageType::SendBlocks));
        let send_blocks = SendBlocksMessage::from_bytes(&msg.data).expect("decode SendBlocks");
        assert_eq!(send_blocks.blocks.len(), 3);

        // Late processes SendBlocks - this should sync all 3 blocks
        server_late
            .clone()
            .process_send_blocks_message(tr_established.peer_id(), send_blocks)
            .await
            .unwrap();

        // Verify late server is now synced
        assert_eq!(server_late.chain.height(), 3);
        assert_eq!(
            server_late.chain.storage_tip(),
            server_established.chain.storage_tip()
        );
    }

    #[tokio::test]
    async fn process_get_blocks_handles_start_zero() {
        let addr_a = addr();
        let addr_b = addr();
        let tr_a = LocalTransport::new(addr_a);
        let tr_b = LocalTransport::new(addr_b);
        tr_a.connect(tr_b.addr()).await;

        let server_a = default_server(tr_a.clone()).await;

        let mut rx_b = tr_b.consume().await;

        // Request with start=0 when chain only has genesis
        let req = GetBlocksMessage { start: 0, end: 0 };
        server_a
            .clone()
            .process_get_blocks_message(tr_b.peer_id(), req)
            .await
            .unwrap();

        let rpc = rx_b.recv().await.expect("should receive response");
        let msg = Message::from_bytes(&rpc.payload).expect("decode message");
        let response = SendBlocksMessage::from_bytes(&msg.data).expect("decode SendBlocks");

        // start=0 should not cause underflow, returns genesis block
        assert_eq!(response.blocks.len(), 1);
        assert_eq!(response.blocks[0].header.height, 0);
    }

    #[tokio::test]
    async fn process_get_blocks_handles_max_start() {
        let addr_a = addr();
        let addr_b = addr();
        let tr_a = LocalTransport::new(addr_a);
        let tr_b = LocalTransport::new(addr_b);
        tr_a.connect(tr_b.addr()).await;

        let server_a = default_server(tr_a.clone()).await;

        let mut rx_b = tr_b.consume().await;

        // Request with start=u64::MAX
        let req = GetBlocksMessage {
            start: u64::MAX,
            end: 0,
        };
        server_a
            .clone()
            .process_get_blocks_message(tr_b.peer_id(), req)
            .await
            .unwrap();

        let rpc = rx_b.recv().await.expect("should receive response");
        let msg = Message::from_bytes(&rpc.payload).expect("decode message");
        let response = SendBlocksMessage::from_bytes(&msg.data).expect("decode SendBlocks");

        // Should return empty - no underflow
        assert!(response.blocks.is_empty());
    }

    #[tokio::test]
    async fn process_get_blocks_handles_max_end() {
        let addr_a = addr();
        let addr_b = addr();
        let tr_a = LocalTransport::new(addr_a);
        let tr_b = LocalTransport::new(addr_b);
        tr_a.connect(tr_b.addr()).await;

        let server_a = default_server(tr_a.clone()).await;

        let mut rx_b = tr_b.consume().await;

        // Request with end=u64::MAX
        let req = GetBlocksMessage {
            start: 1,
            end: u64::MAX,
        };
        server_a
            .clone()
            .process_get_blocks_message(tr_b.peer_id(), req)
            .await
            .unwrap();

        let rpc = rx_b.recv().await.expect("should receive response");
        let msg = Message::from_bytes(&rpc.payload).expect("decode message");
        let response = SendBlocksMessage::from_bytes(&msg.data).expect("decode SendBlocks");

        // Should return empty - end > chain.height()
        assert!(response.blocks.is_empty());
    }

    #[tokio::test]
    async fn process_get_blocks_handles_start_equals_end() {
        let addr_a = addr();
        let addr_b = addr();
        let tr_a = LocalTransport::new(addr_a);
        let tr_b = LocalTransport::new(addr_b);
        tr_a.connect(tr_b.addr()).await;

        let validator_key = PrivateKey::new();
        let validator_account = (validator_key.public_key().address(), Account::new(0));
        let server_a = Server::new(
            tr_a.clone(),
            test_db(),
            Some(validator_key.clone()),
            None,
            &[validator_account],
        )
        .await
        .unwrap();

        // Add 2 blocks
        for _ in 0..2 {
            server_a
                .chain
                .build_block(validator_key.clone(), &TxPool::new(Some(1), TEST_CHAIN_ID))
                .expect("build_block failed");
        }

        let mut rx_b = tr_b.consume().await;

        // Request single block where start == end
        let req = GetBlocksMessage { start: 1, end: 1 };
        server_a
            .clone()
            .process_get_blocks_message(tr_b.peer_id(), req)
            .await
            .unwrap();

        let rpc = rx_b.recv().await.expect("should receive response");
        let msg = Message::from_bytes(&rpc.payload).expect("decode message");
        let response = SendBlocksMessage::from_bytes(&msg.data).expect("decode SendBlocks");

        assert_eq!(response.blocks.len(), 1);
        assert_eq!(response.blocks[0].header.height, 1);
    }

    #[tokio::test]
    async fn process_get_blocks_handles_end_less_than_start() {
        let addr_a = addr();
        let addr_b = addr();
        let tr_a = LocalTransport::new(addr_a);
        let tr_b = LocalTransport::new(addr_b);
        tr_a.connect(tr_b.addr()).await;

        let server_a = default_server(tr_a.clone()).await;

        let mut rx_b = tr_b.consume().await;

        // Request with end < start (invalid range)
        let req = GetBlocksMessage { start: 10, end: 5 };
        server_a
            .clone()
            .process_get_blocks_message(tr_b.peer_id(), req)
            .await
            .unwrap();

        let rpc = rx_b.recv().await.expect("should receive response");
        let msg = Message::from_bytes(&rpc.payload).expect("decode message");
        let response = SendBlocksMessage::from_bytes(&msg.data).expect("decode SendBlocks");

        // Should return empty without panic
        assert!(response.blocks.is_empty());
    }

    #[tokio::test]
    async fn process_get_blocks_handles_start_one_end_zero() {
        let addr_a = addr();
        let addr_b = addr();
        let tr_a = LocalTransport::new(addr_a);
        let tr_b = LocalTransport::new(addr_b);
        tr_a.connect(tr_b.addr()).await;

        let validator_key = PrivateKey::new();
        let validator_account = (validator_key.public_key().address(), Account::new(0));
        let server_a = Server::new(
            tr_a.clone(),
            test_db(),
            Some(validator_key.clone()),
            None,
            &[validator_account],
        )
        .await
        .unwrap();

        // Add 3 blocks
        for _ in 0..3 {
            server_a
                .chain
                .build_block(validator_key.clone(), &TxPool::new(Some(1), TEST_CHAIN_ID))
                .expect("build_block failed");
        }

        let mut rx_b = tr_b.consume().await;

        // This is the typical sync request: start=1, end=0 (all blocks from 1 to tip)
        let req = GetBlocksMessage { start: 1, end: 0 };
        server_a
            .clone()
            .process_get_blocks_message(tr_b.peer_id(), req)
            .await
            .unwrap();

        let rpc = rx_b.recv().await.expect("should receive response");
        let msg = Message::from_bytes(&rpc.payload).expect("decode message");
        let response = SendBlocksMessage::from_bytes(&msg.data).expect("decode SendBlocks");

        // Should return blocks 1, 2, 3
        assert_eq!(response.blocks.len(), 3);
        assert_eq!(response.blocks[0].header.height, 1);
        assert_eq!(response.blocks[1].header.height, 2);
        assert_eq!(response.blocks[2].header.height, 3);
    }

    #[tokio::test]
    async fn process_get_snapshot_state_genesis_includes_accounts() {
        let addr_a = addr();
        let addr_b = addr();
        let tr_a = LocalTransport::new(addr_a);
        let tr_b = LocalTransport::new(addr_b);
        tr_a.connect(tr_b.addr()).await;

        let key = PrivateKey::new();
        let account_addr = key.public_key().address();
        let account = Account::new(999);

        let server_a = Server::new(
            tr_a.clone(),
            test_db(),
            None,
            None,
            &[(account_addr, account.clone())],
        )
        .await
        .unwrap();

        let mut rx_b = tr_b.consume().await;

        let req = GetSnapshotStateMessage { height: 0 };
        server_a
            .clone()
            .process_get_snapshot_state_message(tr_b.peer_id(), req)
            .await
            .unwrap();

        let rpc = rx_b.recv().await.expect("should receive response");
        let msg = Message::from_bytes(&rpc.payload).expect("decode message");
        assert!(matches!(msg.header, MessageType::SendSnapshotState));

        let response = SendSnapshotStateMessage::from_bytes(&msg.data).expect("decode snapshot");
        assert_eq!(response.height, 0);
        assert_eq!(response.entries.len(), 1);
        let entry = &response.entries[0];
        assert_eq!(entry.key, account_addr);
        let mut slice = entry.value.as_ref();
        let decoded = Account::decode(&mut slice).expect("decode account");
        assert_eq!(decoded.balance(), 999);
    }

    #[tokio::test]
    async fn process_get_snapshot_state_missing_snapshot_returns_empty() {
        let addr_a = addr();
        let addr_b = addr();
        let tr_a = LocalTransport::new(addr_a);
        let tr_b = LocalTransport::new(addr_b);
        tr_a.connect(tr_b.addr()).await;

        let server_a = default_server(tr_a.clone()).await;
        let mut rx_b = tr_b.consume().await;

        let req = GetSnapshotStateMessage { height: 5 };
        server_a
            .clone()
            .process_get_snapshot_state_message(tr_b.peer_id(), req)
            .await
            .unwrap();

        let rpc = rx_b.recv().await.expect("should receive response");
        let msg = Message::from_bytes(&rpc.payload).expect("decode message");
        assert!(matches!(msg.header, MessageType::SendSnapshotState));

        let response = SendSnapshotStateMessage::from_bytes(&msg.data).expect("decode snapshot");
        assert_eq!(response.height, 5);
        assert!(response.entries.is_empty());
    }

    #[tokio::test]
    async fn process_send_snapshot_state_imports_snapshot() {
        let addr_a = addr();
        let addr_b = addr();
        let tr_a = LocalTransport::new(addr_a);
        let tr_b = LocalTransport::new(addr_b);
        tr_a.connect(tr_b.addr()).await;

        let server_a = default_server(tr_a.clone()).await;
        let peer = tr_b.peer_id();

        // Trigger header sync state and then transition to snapshot loading
        let status = SendSyncStatusMessage {
            version: 1,
            height: 20,
            tip: Hash::zero(),
            finalized_height: 20,
            snapshot_heights: vec![10],
        };
        server_a
            .clone()
            .process_send_sync_status_message(peer, status)
            .await
            .unwrap();

        let headers = build_header_chain(1, 20, server_a.chain.storage_tip());
        let headers_msg = SendHeadersMessage {
            headers: headers.into_boxed_slice(),
        };
        server_a
            .clone()
            .process_send_headers_message(peer, headers_msg)
            .await
            .unwrap();

        let key = PrivateKey::new();
        let addr = key.public_key().address();
        let account = Account::new(123);

        let mut state = Smt::new(H256::zero(), DefaultStore::default());
        state
            .update(hash_to_h256(&addr), SmtValue(account.to_vec()))
            .expect("SMT update failed");
        let state_root = h256_to_hash(state.root());

        let snap_header = Header {
            version: 1,
            height: 10,
            timestamp: 0,
            gas_used: 0,
            previous_block: Hash::zero(),
            merkle_root: Hash::zero(),
            state_root,
        };
        let block = Block::new(snap_header, PrivateKey::new(), vec![], DEV_CHAIN_ID);
        let response = SendSnapshotStateMessage {
            height: 10,
            block: block.clone(),
            entries: vec![SnapshotEntry {
                key: addr,
                value: account.to_bytes(),
            }]
            .into_boxed_slice(),
        };

        server_a
            .clone()
            .process_send_snapshot_state_message(peer, response)
            .await
            .unwrap();

        assert_eq!(server_a.chain.height(), 10);
        assert_eq!(
            server_a.chain.storage_tip(),
            block.header_hash(DEV_CHAIN_ID)
        );
        let restored = server_a.chain.get_account(addr).expect("account restored");
        assert_eq!(restored.balance(), 123);
    }

    #[tokio::test]
    async fn snapshot_response_wrong_height_is_ignored() {
        let tr_a = LocalTransport::new(addr());
        let tr_b = LocalTransport::new(addr());
        tr_a.connect(tr_b.addr()).await;

        let server_a = default_server(tr_a.clone()).await;
        let peer = tr_b.peer_id();
        let mut rx_b = tr_b.consume().await;

        let status = SendSyncStatusMessage {
            version: 1,
            height: 20,
            tip: Hash::zero(),
            finalized_height: 20,
            snapshot_heights: vec![10],
        };
        server_a
            .clone()
            .process_send_sync_status_message(peer, status)
            .await
            .unwrap();

        let rpc = rx_b.recv().await.expect("GetHeaders");
        let msg = Message::from_bytes(&rpc.payload).expect("decode message");
        assert!(matches!(msg.header, MessageType::GetHeaders));

        let headers = build_header_chain(1, 20, server_a.chain.storage_tip());
        let headers_msg = SendHeadersMessage {
            headers: headers.into_boxed_slice(),
        };
        server_a
            .clone()
            .process_send_headers_message(peer, headers_msg)
            .await
            .unwrap();

        let rpc = rx_b.recv().await.expect("GetSnapshotState");
        let msg = Message::from_bytes(&rpc.payload).expect("decode message");
        assert!(matches!(msg.header, MessageType::GetSnapshotState));

        {
            let sync = server_a.sync_manager.lock().unwrap();
            assert!(matches!(
                sync.state(),
                SyncState::LoadingSnapshot { height: 10 }
            ));
        }

        let wrong_header = Header {
            version: 1,
            height: 9,
            timestamp: 0,
            gas_used: 0,
            previous_block: Hash::zero(),
            merkle_root: Hash::zero(),
            state_root: Hash::zero(),
        };
        let wrong_block = Block::new(wrong_header, PrivateKey::new(), vec![], DEV_CHAIN_ID);
        let response = SendSnapshotStateMessage {
            height: 9,
            block: wrong_block,
            entries: Box::new([]),
        };

        server_a
            .clone()
            .process_send_snapshot_state_message(peer, response)
            .await
            .unwrap();

        assert_eq!(server_a.chain.height(), 0);
        let sync = server_a.sync_manager.lock().unwrap();
        assert!(matches!(
            sync.state(),
            SyncState::LoadingSnapshot { height: 10 }
        ));
    }

    #[tokio::test]
    async fn snapshot_response_empty_entries_falls_back_to_block_replay() {
        let tr_a = LocalTransport::new(addr());
        let tr_b = LocalTransport::new(addr());
        tr_a.connect(tr_b.addr()).await;

        let server_a = default_server(tr_a.clone()).await;
        let peer = tr_b.peer_id();
        let mut rx_b = tr_b.consume().await;

        let status = SendSyncStatusMessage {
            version: 1,
            height: 20,
            tip: Hash::zero(),
            finalized_height: 20,
            snapshot_heights: vec![10],
        };
        server_a
            .clone()
            .process_send_sync_status_message(peer, status)
            .await
            .unwrap();
        let _ = rx_b.recv().await.expect("GetHeaders");

        let headers = build_header_chain(1, 20, server_a.chain.storage_tip());
        let headers_msg = SendHeadersMessage {
            headers: headers.into_boxed_slice(),
        };
        server_a
            .clone()
            .process_send_headers_message(peer, headers_msg)
            .await
            .unwrap();
        let _ = rx_b.recv().await.expect("GetSnapshotState");

        let empty_snapshot = SendSnapshotStateMessage {
            height: 10,
            block: Block::new(
                Header {
                    version: 1,
                    height: 10,
                    timestamp: 0,
                    gas_used: 0,
                    previous_block: Hash::zero(),
                    merkle_root: Hash::zero(),
                    state_root: Hash::zero(),
                },
                PrivateKey::new(),
                vec![],
                DEV_CHAIN_ID,
            ),
            entries: Box::new([]),
        };

        server_a
            .clone()
            .process_send_snapshot_state_message(peer, empty_snapshot)
            .await
            .unwrap();

        assert_eq!(server_a.chain.height(), 0);

        let rpc = rx_b.recv().await.expect("GetBlocks");
        let msg = Message::from_bytes(&rpc.payload).expect("decode message");
        assert!(matches!(msg.header, MessageType::GetBlocks));
        let get_blocks = GetBlocksMessage::from_bytes(&msg.data).expect("decode GetBlocks");
        assert_eq!(get_blocks.start, 1);
    }

    #[tokio::test]
    async fn snapshot_import_state_root_mismatch_requests_blocks() {
        let tr_a = LocalTransport::new(addr());
        let tr_b = LocalTransport::new(addr());
        tr_a.connect(tr_b.addr()).await;

        let server_a = default_server(tr_a.clone()).await;
        let peer = tr_b.peer_id();
        let mut rx_b = tr_b.consume().await;

        let status = SendSyncStatusMessage {
            version: 1,
            height: 20,
            tip: Hash::zero(),
            finalized_height: 20,
            snapshot_heights: vec![10],
        };
        server_a
            .clone()
            .process_send_sync_status_message(peer, status)
            .await
            .unwrap();
        let _ = rx_b.recv().await.expect("GetHeaders");

        let headers = build_header_chain(1, 20, server_a.chain.storage_tip());
        let headers_msg = SendHeadersMessage {
            headers: headers.into_boxed_slice(),
        };
        server_a
            .clone()
            .process_send_headers_message(peer, headers_msg)
            .await
            .unwrap();
        let _ = rx_b.recv().await.expect("GetSnapshotState");

        let key = PrivateKey::new();
        let addr = key.public_key().address();
        let account = Account::new(321);

        let bad_snapshot = SendSnapshotStateMessage {
            height: 10,
            block: Block::new(
                Header {
                    version: 1,
                    height: 10,
                    timestamp: 0,
                    gas_used: 0,
                    previous_block: Hash::zero(),
                    merkle_root: Hash::zero(),
                    state_root: Hash::zero(),
                },
                PrivateKey::new(),
                vec![],
                DEV_CHAIN_ID,
            ),
            entries: vec![SnapshotEntry {
                key: addr,
                value: account.to_bytes(),
            }]
            .into_boxed_slice(),
        };

        server_a
            .clone()
            .process_send_snapshot_state_message(peer, bad_snapshot)
            .await
            .unwrap();

        assert_eq!(server_a.chain.height(), 0);
        let rpc = rx_b.recv().await.expect("GetBlocks");
        let msg = Message::from_bytes(&rpc.payload).expect("decode message");
        assert!(matches!(msg.header, MessageType::GetBlocks));
        let get_blocks = GetBlocksMessage::from_bytes(&msg.data).expect("decode GetBlocks");
        assert_eq!(get_blocks.start, 1);
    }

    #[tokio::test]
    async fn snapshot_height_missing_block_body_returns_error() {
        let tr_a = LocalTransport::new(addr());
        let db = test_db();
        let validator_key = PrivateKey::new();
        let validator_account = (validator_key.public_key().address(), Account::new(0));
        let server_a = Server::new(
            tr_a.clone(),
            db.clone(),
            Some(validator_key.clone()),
            None,
            std::slice::from_ref(&validator_account),
        )
        .await
        .unwrap();

        for _ in 0..10 {
            server_a
                .chain
                .build_block(validator_key.clone(), &TxPool::new(Some(1), TEST_CHAIN_ID))
                .expect("build_block failed");
        }

        let snapshot_height = *server_a
            .chain
            .snapshot_heights()
            .unwrap()
            .last()
            .expect("snapshot height");
        let tip = server_a
            .chain
            .snapshot_tip(snapshot_height)
            .unwrap()
            .expect("snapshot tip");

        let cf_blocks = db.cf_handle(CF_BLOCKS).expect("CF_BLOCKS");
        db.delete_cf(cf_blocks, tip.as_slice())
            .expect("delete block");

        let result = server_a
            .clone()
            .process_get_snapshot_state_message(
                tr_a.peer_id(),
                GetSnapshotStateMessage {
                    height: snapshot_height,
                },
            )
            .await;

        assert!(matches!(result, Err(ServerError::BlockNotFound(h)) if h == tip));
    }

    #[tokio::test]
    async fn replay_after_snapshot_pruned_blocks_marks_sync_failed() {
        let tr_a = LocalTransport::new(addr());
        let tr_b = LocalTransport::new(addr());
        tr_a.connect(tr_b.addr()).await;

        let server_a = default_server(tr_a.clone()).await;
        let peer = tr_b.peer_id();
        let mut rx_b = tr_b.consume().await;

        let status = SendSyncStatusMessage {
            version: 1,
            height: 20,
            tip: Hash::zero(),
            finalized_height: 20,
            snapshot_heights: vec![10],
        };
        server_a
            .clone()
            .process_send_sync_status_message(peer, status)
            .await
            .unwrap();
        let _ = rx_b.recv().await.expect("GetHeaders");

        let headers = build_header_chain(1, 20, server_a.chain.storage_tip());
        let headers_msg = SendHeadersMessage {
            headers: headers.into_boxed_slice(),
        };
        server_a
            .clone()
            .process_send_headers_message(peer, headers_msg)
            .await
            .unwrap();
        let _ = rx_b.recv().await.expect("GetSnapshotState");

        let key = PrivateKey::new();
        let addr = key.public_key().address();
        let account = Account::new(123);
        let mut state = Smt::new(H256::zero(), DefaultStore::default());
        state
            .update(hash_to_h256(&addr), SmtValue(account.to_vec()))
            .expect("SMT update failed");
        let state_root = h256_to_hash(state.root());
        let snap_header = Header {
            version: 1,
            height: 10,
            timestamp: 0,
            gas_used: 0,
            previous_block: Hash::zero(),
            merkle_root: Hash::zero(),
            state_root,
        };
        let block = Block::new(snap_header, PrivateKey::new(), vec![], DEV_CHAIN_ID);
        let response = SendSnapshotStateMessage {
            height: 10,
            block,
            entries: vec![SnapshotEntry {
                key: addr,
                value: account.to_bytes(),
            }]
            .into_boxed_slice(),
        };
        server_a
            .clone()
            .process_send_snapshot_state_message(peer, response)
            .await
            .unwrap();

        // Expect a GetBlocks request (drain)
        let _ = rx_b.recv().await.expect("GetBlocks");

        let header = Header {
            version: 1,
            height: 15,
            timestamp: 0,
            gas_used: BLOCK_GAS_LIMIT,
            previous_block: Hash::zero(),
            merkle_root: Hash::zero(),
            state_root: Hash::zero(),
        };
        let block = Block::new(header, PrivateKey::new(), vec![], DEV_CHAIN_ID);
        let response = SendBlocksMessage {
            blocks: vec![block].into_boxed_slice(),
        };

        server_a
            .clone()
            .process_send_blocks_message(peer, response)
            .await
            .unwrap();

        let mut sync = server_a.sync_manager.lock().unwrap();
        assert!(matches!(sync.state(), SyncState::Idle));
        let action = sync.trigger_resync();
        assert!(matches!(action, SyncAction::Wait));
    }

    #[tokio::test]
    async fn snapshot_sync_converges_state_root_between_peers() {
        let addr_established = addr();
        let addr_late = addr();

        let tr_established = LocalTransport::new(addr_established);
        let tr_late = LocalTransport::new(addr_late);

        let validator_key = PrivateKey::new();
        let validator_account = (validator_key.public_key().address(), Account::new(0));

        let server_established = Server::new(
            tr_established.clone(),
            test_db(),
            Some(validator_key.clone()),
            None,
            std::slice::from_ref(&validator_account),
        )
        .await
        .unwrap();

        // Build enough blocks to create snapshots and prune old bodies (tests use small interval)
        for _ in 0..35 {
            server_established
                .chain
                .build_block(validator_key.clone(), &TxPool::new(Some(1), TEST_CHAIN_ID))
                .expect("build_block failed");
        }

        let snapshot_heights = server_established.chain.snapshot_heights().unwrap();
        assert!(
            snapshot_heights.iter().any(|h| *h > 0),
            "expected at least one snapshot height"
        );
        let expected_snapshot_height = *snapshot_heights.last().unwrap();

        let server_late = Server::new(
            tr_late.clone(),
            test_db(),
            None,
            None,
            std::slice::from_ref(&validator_account),
        )
        .await
        .unwrap();

        let mut rx_established = tr_established.consume().await;
        let mut rx_late = tr_late.consume().await;

        // Late connects to established -> sends GetSyncStatus
        server_late.connect(tr_established.addr()).await.unwrap();

        let rpc = rx_established.recv().await.expect("GetSyncStatus");
        let msg = Message::from_bytes(&rpc.payload).expect("decode message");
        assert!(matches!(msg.header, MessageType::GetSyncStatus));

        // Established responds with SendSyncStatus
        server_established
            .clone()
            .process_get_sync_status_message(tr_late.peer_id())
            .await
            .unwrap();

        let rpc = rx_late.recv().await.expect("SendSyncStatus");
        let msg = Message::from_bytes(&rpc.payload).expect("decode message");
        assert!(matches!(msg.header, MessageType::SendSyncStatus));
        let status = SendSyncStatusMessage::from_bytes(&msg.data).expect("decode status");
        assert!(status.snapshot_heights.contains(&expected_snapshot_height));

        // Late processes status -> requests headers
        server_late
            .clone()
            .process_send_sync_status_message(tr_established.peer_id(), status)
            .await
            .unwrap();

        let rpc = rx_established.recv().await.expect("GetHeaders");
        let msg = Message::from_bytes(&rpc.payload).expect("decode message");
        assert!(matches!(msg.header, MessageType::GetHeaders));
        let get_headers = GetHeadersMessage::from_bytes(&msg.data).expect("decode GetHeaders");

        // Established sends headers
        server_established
            .clone()
            .process_get_headers_message(tr_late.peer_id(), get_headers)
            .await
            .unwrap();

        let rpc = rx_late.recv().await.expect("SendHeaders");
        let msg = Message::from_bytes(&rpc.payload).expect("decode message");
        assert!(matches!(msg.header, MessageType::SendHeaders));
        let send_headers = SendHeadersMessage::from_bytes(&msg.data).expect("decode SendHeaders");

        // Late stores headers -> requests snapshot
        server_late
            .clone()
            .process_send_headers_message(tr_established.peer_id(), send_headers)
            .await
            .unwrap();

        let rpc = rx_established.recv().await.expect("GetSnapshotState");
        let msg = Message::from_bytes(&rpc.payload).expect("decode message");
        assert!(matches!(msg.header, MessageType::GetSnapshotState));
        let get_snapshot =
            GetSnapshotStateMessage::from_bytes(&msg.data).expect("decode GetSnapshotState");
        assert_eq!(get_snapshot.height, expected_snapshot_height);

        // Established sends snapshot
        server_established
            .clone()
            .process_get_snapshot_state_message(tr_late.peer_id(), get_snapshot)
            .await
            .unwrap();

        let rpc = rx_late.recv().await.expect("SendSnapshotState");
        let msg = Message::from_bytes(&rpc.payload).expect("decode message");
        assert!(matches!(msg.header, MessageType::SendSnapshotState));
        let snapshot =
            SendSnapshotStateMessage::from_bytes(&msg.data).expect("decode SendSnapshotState");

        // Late imports snapshot -> requests blocks after snapshot height
        server_late
            .clone()
            .process_send_snapshot_state_message(tr_established.peer_id(), snapshot)
            .await
            .unwrap();

        let rpc = rx_established.recv().await.expect("GetBlocks");
        let msg = Message::from_bytes(&rpc.payload).expect("decode message");
        assert!(matches!(msg.header, MessageType::GetBlocks));
        let get_blocks = GetBlocksMessage::from_bytes(&msg.data).expect("decode GetBlocks");
        assert_eq!(get_blocks.start, expected_snapshot_height + 1);

        // Established sends blocks after snapshot
        server_established
            .clone()
            .process_get_blocks_message(tr_late.peer_id(), get_blocks)
            .await
            .unwrap();

        let rpc = rx_late.recv().await.expect("SendBlocks");
        let msg = Message::from_bytes(&rpc.payload).expect("decode message");
        assert!(matches!(msg.header, MessageType::SendBlocks));
        let send_blocks = SendBlocksMessage::from_bytes(&msg.data).expect("decode SendBlocks");

        // Late applies blocks
        server_late
            .clone()
            .process_send_blocks_message(tr_established.peer_id(), send_blocks)
            .await
            .unwrap();

        // Verify final sync convergence
        assert_eq!(
            server_late.chain.height(),
            server_established.chain.height()
        );
        assert_eq!(
            server_late.chain.storage_tip(),
            server_established.chain.storage_tip()
        );
        assert_eq!(
            server_late.chain.state_root(),
            server_established.chain.state_root()
        );
    }

    #[tokio::test]
    async fn process_send_blocks_detects_pruned_gap_and_marks_sync_failed() {
        let tr_a = LocalTransport::new(addr());
        let tr_b = LocalTransport::new(addr());

        let server_b = default_server(tr_b.clone()).await;

        let header = Header {
            version: 1,
            height: 5,
            timestamp: 0,
            gas_used: BLOCK_GAS_LIMIT,
            previous_block: Hash::zero(),
            merkle_root: Hash::zero(),
            state_root: Hash::zero(),
        };
        let block = Block::new(header, PrivateKey::new(), vec![], DEV_CHAIN_ID);
        let response = SendBlocksMessage {
            blocks: vec![block].into_boxed_slice(),
        };

        server_b
            .clone()
            .process_send_blocks_message(tr_a.peer_id(), response)
            .await
            .unwrap();

        let mut sync = server_b.sync_manager.lock().unwrap();
        assert!(matches!(sync.state(), SyncState::Idle));
        let action = sync.trigger_resync();
        assert!(matches!(action, SyncAction::Wait));
    }
}
