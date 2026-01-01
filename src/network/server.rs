//! Blockchain server orchestrating message handling via a transport layer.
//!
//! Processes incoming RPCs from the server's transport in a unified event loop.

use crate::core::block::{Block, Header};
use crate::core::blockchain::Blockchain;
use crate::core::storage::{StorageError, ThreadSafeMemoryStorage};
use crate::core::transaction::Transaction;
use crate::core::validator::BlockValidator;
use crate::crypto::key_pair::PrivateKey;
use crate::network::local_transport::LocalTransport;
use crate::network::message::{GetBlocksMessage, SendBlocksMessage, SendStatusMessage};
use crate::network::rpc::{
    DecodedMessage, DecodedMessageData, HandleRpcFn, Message, MessageType, Rpc, RpcError,
    RpcProcessor,
};
use crate::network::transport::{Transport, TransportError};
use crate::network::txpool::TxPool;
use crate::types::bytes::Bytes;
use crate::types::encoding::{Decode, Encode};
use crate::types::hash::Hash;
use crate::types::wrapper_types::BoxFuture;
use crate::utils::log::{LogId, Logger};
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::time::interval;

/// Chain identifier for development and testing environments.
///
/// Using chain ID 0 ensures transactions signed for development cannot be
/// replayed on production networks with different chain IDs.
pub const DEV_CHAIN_ID: u64 = 0;

/// Well-known private key bytes used exclusively for signing the genesis block.
/// This key has no authority beyond genesis; it exists solely to produce a
/// deterministic, verifiable genesis block signature across all nodes.
const GENESIS_PRIVATE_KEY_BYTES: [u8; 32] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
];

/// Errors produced by the server while handling RPCs and state updates.
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
pub struct Server {
    /// Logger instance for this server.
    logger: Logger,
    /// Optional custom handler for incoming RPC messages. Uses default handler if `None`.
    rpc_handler: Option<HandleRpcFn>,
    /// This server's transport layer (its network identity).
    transport: Arc<LocalTransport>,
    /// If set, this node becomes a validator node.
    private_key: Option<PrivateKey>,
    /// How often new blocks are created.
    block_time: Duration,
    /// Whether this node participates in block creation.
    is_validator: bool,
    /// Pool of pending transactions awaiting inclusion in a block.
    tx_pool: TxPool,
    /// The local blockchain state with block validation and persistent storage.
    chain: Blockchain<BlockValidator, ThreadSafeMemoryStorage>,
}

impl Server {
    /// The genesis block, lazily initialized once and shared across all server instances.
    pub fn genesis_block(chain_id: u64) -> Arc<Block> {
        let header = Header {
            version: 1,
            height: 0,
            timestamp: 0,
            previous_block: Hash::zero(),
            data_hash: Hash::zero(),
            merkle_root: Hash::zero(),
            state_root: Hash::zero(),
        };

        let genesis_key = PrivateKey::from_bytes(&GENESIS_PRIVATE_KEY_BYTES)
            .expect("GENESIS_PRIVATE_KEY_BYTES must be a valid secp256k1 scalar");

        Block::new(header, genesis_key, vec![], chain_id)
    }

    /// Creates a new server with full configuration options.
    ///
    /// Sets `is_validator` to true if `private_key` is provided.
    pub async fn new(
        id: impl Into<LogId>,
        transport: Arc<LocalTransport>,
        block_time: Duration,
        private_key: Option<PrivateKey>,
        transaction_pool_capacity: Option<usize>,
        rpc_handler: Option<HandleRpcFn>,
    ) -> Arc<Self> {
        let is_validator = private_key.is_some();
        let logger = Logger::new(id);
        let chain_id = DEV_CHAIN_ID;

        Arc::new(Self {
            logger,
            rpc_handler,
            transport,
            private_key,
            is_validator,
            tx_pool: TxPool::new(transaction_pool_capacity),
            block_time,
            chain: Blockchain::new(chain_id, Self::genesis_block(chain_id), logger),
        })
    }

    /// Creates a new server with sensible defaults for a non-validator node.
    pub async fn default(
        id: impl Into<LogId>,
        transport: Arc<LocalTransport>,
        block_time: Duration,
    ) -> Arc<Self> {
        Self::new(id, transport, block_time, None, None, None).await
    }

    /// Starts the server and begins processing incoming messages.
    ///
    /// Initializes the transport and enters the main event loop.
    /// Blocks until the transport channel closes.
    pub async fn start(self: Arc<Self>, sx: Sender<Rpc>, mut rx: Receiver<Rpc>) {
        self.init_transport(sx).await;

        if self.is_validator {
            let server_thread = self.clone();
            tokio::spawn(async move { server_thread.validator_loop().await });
        }

        loop {
            tokio::select! {
                Some(rpc) = rx.recv() => {
                    let result = match &self.rpc_handler {
                        Some(handler) => handler(rpc),
                        None => handle_rpc(rpc),
                    };

                    match result {
                        Ok(msg) => {
                            if let Err(e) = &self.clone().process_message(msg).await {
                                self.logger.error(&format!("failed to process rpc: {}", e));
                            }

                        },
                        Err(e) => self.logger.error(&format!("failed to decode rpc: {}", e))
                    }
                }
                else => {
                    break;
                }
            }
        }

        self.logger.info("Server shut down");
    }

    async fn validator_loop(&self) {
        let mut ticker = interval(self.block_time);
        self.logger.info(&format!(
            "starting the validator loop: block_time={}",
            self.block_time.as_secs()
        ));

        // Consume the initial ticker state to force a wait period on startup
        ticker.tick().await;

        loop {
            ticker.tick().await;
            self.create_new_block().await;
        }
    }

    /// Spawns an async task to forward messages from the transport to the main channel.
    async fn init_transport(&self, sx: Sender<Rpc>) {
        let tr = self.transport.clone();
        tokio::spawn(async move {
            let mut rx = tr.consume().await;
            while let Some(rpc) = rx.recv().await {
                let _ = sx.send(rpc).await;
            }
        });
    }

    /// Connects to another server and initiates the handshake protocol.
    ///
    /// Establishes bidirectional transport-level connection, then sends
    /// a GetStatus message to synchronize chain state if needed.
    pub async fn connect(self: &Arc<Self>, other: &Arc<Server>) -> Result<(), ServerError> {
        self.transport.connect(&other.transport).await;
        self.send_get_status_message(&other.transport).await?;
        Ok(())
    }

    /// Sends a status request to the specified peer transport.
    async fn send_get_status_message(
        &self,
        transport: &Arc<LocalTransport>,
    ) -> Result<(), TransportError> {
        let rpc = Message::new(MessageType::GetStatus, 0x8.to_bytes());
        self.transport
            .send_message(transport.addr(), rpc.to_bytes())
            .await
    }

    async fn create_new_block(&self) {
        match self.chain.build_block(
            self.private_key.clone().unwrap(),
            self.tx_pool.transactions(),
        ) {
            Ok(block) => match self.chain.add_block(block.clone()) {
                Ok(_) => {
                    if let Err(e) = self
                        .broadcast(self.transport.addr(), block.to_bytes(), MessageType::Block)
                        .await
                    {
                        self.logger.warn(&format!("could not broadcast block: {e}"));
                    }
                }
                Err(err) => self
                    .logger
                    .warn(&format!("could not add newly built block: {err}")),
            },
            Err(e) => self.logger.warn(&format!("build block failed: {e}")),
        }
    }

    /// Validates and adds a transaction to the local pool.
    pub fn add_to_pool(&self, transaction: Transaction) -> Result<(), ServerError> {
        if !transaction.verify(self.chain.id) {
            return Err(ServerError::InvalidTransaction(
                transaction.id(self.chain.id),
            ));
        }
        self.tx_pool.append(transaction, self.chain.id);
        Ok(())
    }

    /// Returns a reference to the server's transport.
    pub fn transport(&self) -> &Arc<LocalTransport> {
        &self.transport
    }

    /// Wraps a payload in a protocol message and broadcasts to all connected peers.
    ///
    /// The `from` address is passed through to exclude the sender from receiving
    /// their own broadcast.
    async fn broadcast(
        &self,
        from: String,
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
        from: String,
        transaction: Transaction,
    ) -> Result<(), ServerError> {
        if self.tx_pool.contains(transaction.id(self.chain.id)) {
            self.logger.warn(&format!(
                "({}) attempting to add a new transaction to the pool that already is in it: hash={}",
                self.transport.addr(),
                transaction.id(self.chain.id)
            ));
            return Ok(());
        }

        if !transaction.verify(self.chain.id) {
            return Err(ServerError::InvalidTransaction(
                transaction.id(self.chain.id),
            ));
        }

        // self.logger.info(&format!(
        //     "adding a new transaction to the pool: hash={} pool_size={}",
        //     transaction.tx_id(self.chain.id),
        //     self.tx_pool.length()
        // ));

        let bytes = transaction.to_bytes();
        self.tx_pool.append(transaction, self.chain.id);

        tokio::spawn(async move { self.broadcast(from, bytes, MessageType::Transaction).await });

        Ok(())
    }

    /// Adds a received block to the chain and broadcasts it to peers.
    ///
    /// Returns `Ok` if the block was successfully added, or an error if
    /// validation failed or the block was already present.
    async fn process_block(self: Arc<Self>, from: String, block: Block) -> Result<(), ServerError> {
        let arc_block = Arc::new(block);
        self.chain
            .add_block(arc_block.clone())
            .map_err(|e| ServerError::BlockRejected {
                hash: arc_block.header_hash(self.chain.id),
                source: e,
            })?;

        let hashes: Vec<Hash> = arc_block
            .transactions
            .iter()
            .map(|tx| tx.id(self.chain.id))
            .collect();
        self.tx_pool.remove_batch(&hashes);
        tokio::spawn(async move {
            self.broadcast(from, arc_block.to_bytes(), MessageType::Block)
                .await
        });
        Ok(())
    }

    /// Handles an incoming status request by responding with our chain info.
    async fn process_get_status_message(self: Arc<Self>, from: String) -> Result<(), ServerError> {
        let status = SendStatusMessage {
            id: self.logger.id,
            version: 1,
            current_height: self.chain.height(),
        };
        let message = Message::new(MessageType::SendStatus, status.to_bytes());

        self.transport
            .send_message(from, message.to_bytes())
            .await
            .map_err(ServerError::Transport)
    }

    /// Handles a status response from a peer.
    ///
    /// If the peer's chain is ahead, requests missing blocks to sync.
    async fn process_send_status_message(
        self: Arc<Self>,
        from: String,
        status: SendStatusMessage,
    ) -> Result<(), ServerError> {
        // Skip for 2 new nodes
        if status.current_height == 0 && self.chain.height() == 0 {
            return Ok(());
        }

        if status.current_height <= self.chain.height() {
            return Err(ServerError::BlockHeightToLow(
                status.current_height,
                self.chain.height(),
            ));
        }

        let get_block_msg = GetBlocksMessage {
            start: self.chain.height() + 1,
            end: 0,
        };
        let message = Message::new(MessageType::GetBlocks, get_block_msg.to_bytes());
        self.transport
            .send_message(from, message.to_bytes())
            .await
            .map_err(ServerError::Transport)
    }

    const EMPTY_BLOCKS: SendBlocksMessage = SendBlocksMessage { blocks: Vec::new() };

    /// Handles a block range request by walking the chain and sending requested blocks.
    async fn process_get_blocks_message(
        self: Arc<Self>,
        from: String,
        req: GetBlocksMessage,
    ) -> Result<(), ServerError> {
        // Check if all the available blocks were requested
        let current_height = self.chain.height();
        let end = if req.end == 0 {
            current_height
        } else {
            req.end
        };

        // No blocks to send; range is invalid or empty
        if req.start > end || end > current_height {
            let msg = Message::new(MessageType::SendBlocks, Self::EMPTY_BLOCKS.to_bytes());
            return self
                .transport
                .send_message(from, msg.to_bytes())
                .await
                .map_err(ServerError::Transport);
        }

        let mut key = self.chain.storage_tip();
        let mut blocks: VecDeque<Block> = VecDeque::with_capacity((end - req.start + 1) as usize);

        // Walk back from tip to end, skip these blocks
        for _ in 0..(current_height - end) {
            match self.chain.get_block(key) {
                None => return Err(ServerError::BlockNotFound(key)),
                Some(block) => key = block.header.previous_block,
            }
        }

        // Collect blocks from end down to req.start
        for _ in req.start..=end {
            match self.chain.get_block(key) {
                None => return Err(ServerError::BlockNotFound(key)),
                Some(block) => {
                    blocks.push_front((*block).clone());
                    key = block.header.previous_block;
                }
            }
        }

        let blocks_msg = SendBlocksMessage {
            blocks: blocks.into(),
        };
        let msg = Message::new(MessageType::SendBlocks, blocks_msg.to_bytes());
        self.transport
            .send_message(from, msg.to_bytes())
            .await
            .map_err(ServerError::Transport)
    }

    /// Handles a blocks response by adding each block to the local chain.
    async fn process_send_blocks_message(
        self: Arc<Self>,
        _from: String,
        response: SendBlocksMessage,
    ) -> Result<(), ServerError> {
        for block in response.blocks {
            self.chain
                .add_block(Arc::new(block))
                .map_err(ServerError::Storage)?;
        }

        Ok(())
    }
}

impl RpcProcessor for Server {
    type Error = ServerError;
    fn process_message(
        self: Arc<Self>,
        decoded_message: DecodedMessage,
    ) -> BoxFuture<'static, Result<(), Self::Error>> {
        Box::pin(async move {
            match decoded_message.data {
                DecodedMessageData::Transaction(tx) => {
                    self.process_transaction(decoded_message.from, tx).await
                }
                DecodedMessageData::Block(block) => {
                    self.process_block(decoded_message.from, block).await
                }
                DecodedMessageData::GetStatus => {
                    self.process_get_status_message(decoded_message.from).await
                }
                DecodedMessageData::SendStatus(response) => {
                    self.process_send_status_message(decoded_message.from, response)
                        .await
                }
                DecodedMessageData::GetBlocks(request) => {
                    self.process_get_blocks_message(decoded_message.from, request)
                        .await
                }
                DecodedMessageData::SendBlocks(response) => {
                    self.process_send_blocks_message(decoded_message.from, response)
                        .await
                }
            }
        })
    }
}

/// Default RPC handler that deserializes messages based on their type header.
fn handle_rpc(rpc: Rpc) -> Result<DecodedMessage, RpcError> {
    let msg = Message::from_bytes(rpc.payload.as_ref()).map_err(|e| RpcError::Message {
        from: rpc.from.clone(),
        details: format!("{e:?}"),
    })?;

    match msg.header {
        MessageType::Transaction => {
            let tx = Transaction::from_bytes(msg.data.as_ref())
                .map_err(|e| RpcError::Transaction(format!("{e:?}")))?;
            Ok(DecodedMessage {
                from: rpc.from.clone(),
                data: DecodedMessageData::Transaction(tx),
            })
        }
        MessageType::Block => {
            let block = Block::from_bytes(msg.data.as_ref())
                .map_err(|e| RpcError::Block(format!("{e:?}")))?;
            Ok(DecodedMessage {
                from: rpc.from.clone(),
                data: DecodedMessageData::Block(block),
            })
        }
        MessageType::SendStatus => {
            let status = SendStatusMessage::from_bytes(msg.data.as_ref())
                .map_err(|e| RpcError::Status(format!("{e:?}")))?;
            Ok(DecodedMessage {
                from: rpc.from.clone(),
                data: DecodedMessageData::SendStatus(status),
            })
        }
        MessageType::GetStatus => Ok(DecodedMessage {
            from: rpc.from.clone(),
            data: DecodedMessageData::GetStatus,
        }),
        MessageType::SendBlocks => {
            let send_blocks_msg = SendBlocksMessage::from_bytes(msg.data.as_ref())
                .map_err(|e| RpcError::Status(format!("{e:?}")))?;
            Ok(DecodedMessage {
                from: rpc.from.clone(),
                data: DecodedMessageData::SendBlocks(send_blocks_msg),
            })
        }
        MessageType::GetBlocks => {
            let get_blocks_msg = GetBlocksMessage::from_bytes(msg.data.as_ref())
                .map_err(|e| RpcError::Status(format!("{e:?}")))?;
            Ok(DecodedMessage {
                from: rpc.from.clone(),
                data: DecodedMessageData::GetBlocks(get_blocks_msg),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::key_pair::PrivateKey;

    const TEST_CHAIN_ID: u64 = 10;

    #[tokio::test]
    async fn server_is_validator_when_private_key_set() {
        let transport = LocalTransport::new("validator");
        let server = Server::new(
            "test-validator",
            transport,
            Duration::from_secs(10),
            Some(PrivateKey::new()),
            None,
            None,
        )
        .await;
        assert!(server.is_validator);
    }

    #[tokio::test]
    async fn server_is_not_validator_without_private_key() {
        let transport = LocalTransport::new("node");
        let server = Server::default("test-node", transport, Duration::from_secs(10)).await;
        assert!(!server.is_validator);
    }

    #[test]
    fn handle_rpc_decodes_valid_transaction() {
        let key = PrivateKey::new();
        let tx = Transaction::new(b"test data".as_slice(), key, TEST_CHAIN_ID);
        let tx_bytes = tx.to_bytes();

        let msg = Message::new(MessageType::Transaction, tx_bytes);
        let msg_bytes = msg.to_bytes();

        let rpc = Rpc::new("sender", msg_bytes);
        let result = handle_rpc(rpc).expect("should decode successfully");

        assert_eq!(result.from, "sender");
        match result.data {
            DecodedMessageData::Transaction(decoded_tx) => {
                assert_eq!(decoded_tx.id(TEST_CHAIN_ID), tx.id(TEST_CHAIN_ID));
            }
            _ => panic!("expected Transaction variant"),
        }
    }

    #[test]
    fn handle_rpc_rejects_malformed_payload() {
        let rpc = Rpc::new("bad_sender", vec![0xFF, 0xFF, 0xFF]);
        let result = handle_rpc(rpc);

        assert!(matches!(result, Err(RpcError::Message { .. })));
    }

    #[test]
    fn handle_rpc_rejects_invalid_transaction_data() {
        let msg = Message::new(MessageType::Transaction, vec![0x00, 0x01, 0x02]);
        let msg_bytes = msg.to_bytes();

        let rpc = Rpc::new("sender", msg_bytes);
        let result = handle_rpc(rpc);

        assert!(matches!(result, Err(RpcError::Transaction { .. })));
    }

    fn create_test_block(transactions: Vec<Transaction>) -> Arc<Block> {
        let header = Header {
            version: 1,
            height: 1,
            timestamp: 1234567890,
            previous_block: Hash::zero(),
            data_hash: Hash::zero(),
            merkle_root: Hash::zero(),
            state_root: Hash::zero(),
        };
        Block::new(header, PrivateKey::new(), transactions, TEST_CHAIN_ID)
    }

    #[test]
    fn handle_rpc_decodes_valid_block() {
        let block = create_test_block(vec![]);
        let block_bytes = block.to_bytes();

        let msg = Message::new(MessageType::Block, block_bytes);
        let msg_bytes = msg.to_bytes();

        let rpc = Rpc::new("block_sender", msg_bytes);
        let result = handle_rpc(rpc).expect("should decode successfully");

        assert_eq!(result.from, "block_sender");
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

        let rpc = Rpc::new("sender", msg_bytes);
        let result = handle_rpc(rpc);

        assert!(matches!(result, Err(RpcError::Block { .. })));
    }

    #[test]
    fn handle_rpc_preserves_block_transactions() {
        let key = PrivateKey::new();
        let tx1 = Transaction::new(b"tx1".as_slice(), key.clone(), TEST_CHAIN_ID);
        let tx2 = Transaction::new(b"tx2".as_slice(), key, TEST_CHAIN_ID);
        let tx1_hash = tx1.id(TEST_CHAIN_ID);
        let tx2_hash = tx2.id(TEST_CHAIN_ID);

        let block = create_test_block(vec![tx1, tx2]);
        let block_bytes = block.to_bytes();

        let msg = Message::new(MessageType::Block, block_bytes);
        let msg_bytes = msg.to_bytes();

        let rpc = Rpc::new("sender", msg_bytes);
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

        // Truncate the block data
        block_bytes.truncate(block_bytes.len() / 2);

        let msg = Message::new(MessageType::Block, block_bytes);
        let msg_bytes = msg.to_bytes();

        let rpc = Rpc::new("sender", msg_bytes);
        let result = handle_rpc(rpc);

        assert!(matches!(result, Err(RpcError::Block { .. })));
    }

    #[test]
    fn handle_rpc_decodes_get_status() {
        let msg = Message::new(MessageType::GetStatus, 0x8u8.to_bytes());
        let rpc = Rpc::new("peer", msg.to_bytes());
        let result = handle_rpc(rpc).expect("should decode");

        assert_eq!(result.from, "peer");
        assert!(matches!(result.data, DecodedMessageData::GetStatus));
    }

    #[test]
    fn handle_rpc_decodes_send_status() {
        use crate::utils::log::LogId;

        let status = SendStatusMessage {
            id: LogId::new("node-a"),
            version: 1,
            current_height: 100,
        };
        let msg = Message::new(MessageType::SendStatus, status.to_bytes());
        let rpc = Rpc::new("peer", msg.to_bytes());
        let result = handle_rpc(rpc).expect("should decode");

        assert_eq!(result.from, "peer");
        match result.data {
            DecodedMessageData::SendStatus(s) => {
                assert_eq!(s.id.as_str(), "node-a");
                assert_eq!(s.version, 1);
                assert_eq!(s.current_height, 100);
            }
            _ => panic!("expected SendStatus"),
        }
    }

    #[test]
    fn handle_rpc_decodes_get_blocks() {
        let get_blocks = GetBlocksMessage { start: 5, end: 10 };
        let msg = Message::new(MessageType::GetBlocks, get_blocks.to_bytes());
        let rpc = Rpc::new("peer", msg.to_bytes());
        let result = handle_rpc(rpc).expect("should decode");

        assert_eq!(result.from, "peer");
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
        let send_blocks = SendBlocksMessage { blocks: vec![] };
        let msg = Message::new(MessageType::SendBlocks, send_blocks.to_bytes());
        let rpc = Rpc::new("peer", msg.to_bytes());
        let result = handle_rpc(rpc).expect("should decode");

        assert_eq!(result.from, "peer");
        match result.data {
            DecodedMessageData::SendBlocks(resp) => {
                assert!(resp.blocks.is_empty());
            }
            _ => panic!("expected SendBlocks"),
        }
    }

    #[tokio::test]
    async fn server_connect_establishes_bidirectional_transport() {
        let tr_a = LocalTransport::new("A");
        let tr_b = LocalTransport::new("B");

        let server_a = Server::default("server-a", tr_a.clone(), Duration::from_secs(10)).await;
        let server_b = Server::default("server-b", tr_b.clone(), Duration::from_secs(10)).await;

        server_a.connect(&server_b).await.unwrap();

        // Transport-level connection should be bidirectional
        let a_peers: Vec<String> = tr_a.peers().iter().map(|p| p.addr()).collect();
        let b_peers: Vec<String> = tr_b.peers().iter().map(|p| p.addr()).collect();
        assert!(a_peers.contains(&"B".to_string()));
        assert!(b_peers.contains(&"A".to_string()));
    }

    #[tokio::test]
    async fn server_connect_sends_get_status_message() {
        let tr_a = LocalTransport::new("A");
        let tr_b = LocalTransport::new("B");

        let server_a = Server::default("server-a", tr_a.clone(), Duration::from_secs(10)).await;
        let server_b = Server::default("server-b", tr_b.clone(), Duration::from_secs(10)).await;

        let mut rx_b = tr_b.consume().await;

        server_a.connect(&server_b).await.unwrap();

        // B should receive a GetStatus message from A
        let rpc = rx_b.recv().await.expect("should receive message");
        assert_eq!(rpc.from, "A");

        let msg = Message::from_bytes(&rpc.payload).expect("should decode message");
        assert!(matches!(msg.header, MessageType::GetStatus));
    }

    #[tokio::test]
    async fn process_get_status_responds_with_send_status() {
        let tr_a = LocalTransport::new("A");
        let tr_b = LocalTransport::new("B");
        tr_a.connect(&tr_b).await;

        let server_a = Server::default("server-a", tr_a.clone(), Duration::from_secs(10)).await;

        let mut rx_b = tr_b.consume().await;

        // Process a GetStatus message from B
        server_a
            .clone()
            .process_get_status_message("B".to_string())
            .await
            .unwrap();

        // B should receive a SendStatus response
        let rpc = rx_b.recv().await.expect("should receive response");
        assert_eq!(rpc.from, "A");

        let msg = Message::from_bytes(&rpc.payload).expect("decode message");
        assert!(matches!(msg.header, MessageType::SendStatus));

        let status = SendStatusMessage::from_bytes(&msg.data).expect("decode status");
        assert_eq!(status.current_height, 0); // Only genesis block
    }

    #[tokio::test]
    async fn process_send_status_skips_sync_when_both_new_nodes() {
        let tr_a = LocalTransport::new("A");
        let server_a = Server::default("server-a", tr_a, Duration::from_secs(10)).await;

        // Both nodes at height 0 (new nodes) - sync is skipped
        let status = SendStatusMessage {
            id: LogId::new("peer"),
            version: 1,
            current_height: 0,
        };

        let result = server_a
            .clone()
            .process_send_status_message("B".to_string(), status)
            .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn process_send_status_errors_when_peer_behind() {
        let tr_a = LocalTransport::new("A");
        let server_a = Server::new(
            "server-a",
            tr_a.clone(),
            Duration::from_secs(10),
            Some(PrivateKey::new()),
            None,
            None,
        )
        .await;

        // Add a block to server_a so its height is 1
        let block = server_a
            .chain
            .build_block(PrivateKey::new(), vec![])
            .expect("build_block failed");
        server_a.chain.add_block(block).unwrap();

        // Peer reports height 0, behind our chain (height 1)
        let status = SendStatusMessage {
            id: LogId::new("peer"),
            version: 1,
            current_height: 0,
        };

        let result = server_a
            .clone()
            .process_send_status_message("B".to_string(), status)
            .await;

        assert!(matches!(result, Err(ServerError::BlockHeightToLow(0, 1))));
    }

    #[tokio::test]
    async fn process_send_status_requests_blocks_when_peer_ahead() {
        let tr_a = LocalTransport::new("A");
        let tr_b = LocalTransport::new("B");
        tr_a.connect(&tr_b).await;

        let server_a = Server::default("server-a", tr_a.clone(), Duration::from_secs(10)).await;

        let mut rx_b = tr_b.consume().await;

        // Peer reports height 5, ahead of our genesis-only chain (height 0)
        let status = SendStatusMessage {
            id: LogId::new("peer-b"),
            version: 1,
            current_height: 5,
        };

        server_a
            .clone()
            .process_send_status_message("B".to_string(), status)
            .await
            .unwrap();

        // Should send GetBlocks request to B
        let rpc = rx_b.recv().await.expect("should receive GetBlocks");
        let msg = Message::from_bytes(&rpc.payload).expect("decode message");
        assert!(matches!(msg.header, MessageType::GetBlocks));

        let get_blocks = GetBlocksMessage::from_bytes(&msg.data).expect("decode GetBlocks");
        assert_eq!(get_blocks.start, 1); // Start from height 1 (after genesis)
        assert_eq!(get_blocks.end, 0); // 0 means "to tip"
    }

    #[tokio::test]
    async fn process_get_blocks_returns_empty_for_invalid_range() {
        let tr_a = LocalTransport::new("A");
        let tr_b = LocalTransport::new("B");
        tr_a.connect(&tr_b).await;

        let server_a = Server::default("server-a", tr_a.clone(), Duration::from_secs(10)).await;

        let mut rx_b = tr_b.consume().await;

        // Request blocks 10-20 when chain only has genesis (height 0)
        let req = GetBlocksMessage { start: 10, end: 20 };
        server_a
            .clone()
            .process_get_blocks_message("B".to_string(), req)
            .await
            .unwrap();

        let rpc = rx_b.recv().await.expect("should receive response");
        let msg = Message::from_bytes(&rpc.payload).expect("decode message");
        let response = SendBlocksMessage::from_bytes(&msg.data).expect("decode SendBlocks");

        assert!(response.blocks.is_empty());
    }

    #[tokio::test]
    async fn process_get_blocks_returns_empty_for_start_greater_than_end() {
        let tr_a = LocalTransport::new("A");
        let tr_b = LocalTransport::new("B");
        tr_a.connect(&tr_b).await;

        let server_a = Server::default("server-a", tr_a.clone(), Duration::from_secs(10)).await;

        let mut rx_b = tr_b.consume().await;

        // Start > end (invalid range)
        let req = GetBlocksMessage { start: 5, end: 2 };
        server_a
            .clone()
            .process_get_blocks_message("B".to_string(), req)
            .await
            .unwrap();

        let rpc = rx_b.recv().await.expect("should receive response");
        let msg = Message::from_bytes(&rpc.payload).expect("decode message");
        let response = SendBlocksMessage::from_bytes(&msg.data).expect("decode SendBlocks");

        assert!(response.blocks.is_empty());
    }

    #[tokio::test]
    async fn process_send_blocks_adds_blocks_to_chain() {
        let tr_a = LocalTransport::new("A");
        let tr_b = LocalTransport::new("B");
        let server_a = Server::default("server-a", tr_a, Duration::from_secs(10)).await;

        // Use a builder server to create valid blocks with correct state_root
        let server_builder = Server::new(
            "builder",
            tr_b,
            Duration::from_secs(10),
            Some(PrivateKey::new()),
            None,
            None,
        )
        .await;

        let block = server_builder
            .chain
            .build_block(PrivateKey::new(), vec![])
            .expect("build_block failed");
        server_builder.chain.add_block(block.clone()).unwrap();

        assert_eq!(server_a.chain.height(), 0);

        let response = SendBlocksMessage {
            blocks: vec![(*block).clone()],
        };

        server_a
            .clone()
            .process_send_blocks_message("B".to_string(), response)
            .await
            .unwrap();

        assert_eq!(server_a.chain.height(), 1);
    }

    #[tokio::test]
    async fn process_send_blocks_adds_multiple_blocks_in_order() {
        let tr_a = LocalTransport::new("A");
        let tr_b = LocalTransport::new("B");
        let server_a = Server::default("server-a", tr_a, Duration::from_secs(10)).await;

        // Use a builder server to create valid blocks with correct state_root
        let server_builder = Server::new(
            "builder",
            tr_b,
            Duration::from_secs(10),
            Some(PrivateKey::new()),
            None,
            None,
        )
        .await;

        // Build block 1
        let block1 = server_builder
            .chain
            .build_block(PrivateKey::new(), vec![])
            .expect("build_block 1 failed");
        server_builder.chain.add_block(block1.clone()).unwrap();

        // Build block 2
        let block2 = server_builder
            .chain
            .build_block(PrivateKey::new(), vec![])
            .expect("build_block 2 failed");
        server_builder.chain.add_block(block2.clone()).unwrap();

        let response = SendBlocksMessage {
            blocks: vec![(*block1).clone(), (*block2).clone()],
        };

        server_a
            .clone()
            .process_send_blocks_message("B".to_string(), response)
            .await
            .unwrap();

        assert_eq!(server_a.chain.height(), 2);
    }

    #[tokio::test]
    async fn late_server_syncs_with_established_chain() {
        // Create an established server with blocks
        let tr_established = LocalTransport::new("Established");
        let validator_key = PrivateKey::new();
        let server_established = Server::new(
            "established",
            tr_established.clone(),
            Duration::from_secs(10),
            Some(validator_key.clone()),
            None,
            None,
        )
        .await;

        // Build 3 blocks on the established server
        for _ in 0..3 {
            let block = server_established
                .chain
                .build_block(validator_key.clone(), vec![])
                .expect("build_block failed");
            server_established.chain.add_block(block).unwrap();
        }
        assert_eq!(server_established.chain.height(), 3);

        // Create a late-joining server
        let tr_late = LocalTransport::new("Late");
        let server_late = Server::default("late", tr_late.clone(), Duration::from_secs(10)).await;
        assert_eq!(server_late.chain.height(), 0);

        // Connect late server to established (sends GetStatus)
        let mut rx_established = tr_established.consume().await;
        server_late.connect(&server_established).await.unwrap();

        // Established receives GetStatus from Late
        let rpc = rx_established
            .recv()
            .await
            .expect("should receive GetStatus");
        assert_eq!(rpc.from, "Late");
        let msg = Message::from_bytes(&rpc.payload).expect("decode");
        assert!(matches!(msg.header, MessageType::GetStatus));

        // Established processes GetStatus and sends SendStatus
        let mut rx_late = tr_late.consume().await;
        server_established
            .clone()
            .process_get_status_message("Late".to_string())
            .await
            .unwrap();

        // Late receives SendStatus
        let rpc = rx_late.recv().await.expect("should receive SendStatus");
        let msg = Message::from_bytes(&rpc.payload).expect("decode");
        assert!(matches!(msg.header, MessageType::SendStatus));
        let status = SendStatusMessage::from_bytes(&msg.data).expect("decode status");
        assert_eq!(status.current_height, 3);

        // Late processes SendStatus and sends GetBlocks
        server_late
            .clone()
            .process_send_status_message("Established".to_string(), status)
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
        assert_eq!(get_blocks.end, 0);

        // Established processes GetBlocks and sends SendBlocks
        server_established
            .clone()
            .process_get_blocks_message("Late".to_string(), get_blocks)
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
            .process_send_blocks_message("Established".to_string(), send_blocks)
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
        let tr_a = LocalTransport::new("A");
        let tr_b = LocalTransport::new("B");
        tr_a.connect(&tr_b).await;

        let server_a = Server::default("server-a", tr_a.clone(), Duration::from_secs(10)).await;

        let mut rx_b = tr_b.consume().await;

        // Request with start=0 when chain only has genesis
        let req = GetBlocksMessage { start: 0, end: 0 };
        server_a
            .clone()
            .process_get_blocks_message("B".to_string(), req)
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
        let tr_a = LocalTransport::new("A");
        let tr_b = LocalTransport::new("B");
        tr_a.connect(&tr_b).await;

        let server_a = Server::default("server-a", tr_a.clone(), Duration::from_secs(10)).await;

        let mut rx_b = tr_b.consume().await;

        // Request with start=u64::MAX
        let req = GetBlocksMessage {
            start: u64::MAX,
            end: 0,
        };
        server_a
            .clone()
            .process_get_blocks_message("B".to_string(), req)
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
        let tr_a = LocalTransport::new("A");
        let tr_b = LocalTransport::new("B");
        tr_a.connect(&tr_b).await;

        let server_a = Server::default("server-a", tr_a.clone(), Duration::from_secs(10)).await;

        let mut rx_b = tr_b.consume().await;

        // Request with end=u64::MAX
        let req = GetBlocksMessage {
            start: 1,
            end: u64::MAX,
        };
        server_a
            .clone()
            .process_get_blocks_message("B".to_string(), req)
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
        let tr_a = LocalTransport::new("A");
        let tr_b = LocalTransport::new("B");
        tr_a.connect(&tr_b).await;

        let validator_key = PrivateKey::new();
        let server_a = Server::new(
            "server-a",
            tr_a.clone(),
            Duration::from_secs(10),
            Some(validator_key.clone()),
            None,
            None,
        )
        .await;

        // Add 2 blocks
        for _ in 0..2 {
            let block = server_a
                .chain
                .build_block(validator_key.clone(), vec![])
                .expect("build_block failed");
            server_a.chain.add_block(block).unwrap();
        }

        let mut rx_b = tr_b.consume().await;

        // Request single block where start == end
        let req = GetBlocksMessage { start: 1, end: 1 };
        server_a
            .clone()
            .process_get_blocks_message("B".to_string(), req)
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
        let tr_a = LocalTransport::new("A");
        let tr_b = LocalTransport::new("B");
        tr_a.connect(&tr_b).await;

        let server_a = Server::default("server-a", tr_a.clone(), Duration::from_secs(10)).await;

        let mut rx_b = tr_b.consume().await;

        // Request with end < start (invalid range)
        let req = GetBlocksMessage { start: 10, end: 5 };
        server_a
            .clone()
            .process_get_blocks_message("B".to_string(), req)
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
        let tr_a = LocalTransport::new("A");
        let tr_b = LocalTransport::new("B");
        tr_a.connect(&tr_b).await;

        let validator_key = PrivateKey::new();
        let server_a = Server::new(
            "server-a",
            tr_a.clone(),
            Duration::from_secs(10),
            Some(validator_key.clone()),
            None,
            None,
        )
        .await;

        // Add 3 blocks
        for _ in 0..3 {
            let block = server_a
                .chain
                .build_block(validator_key.clone(), vec![])
                .expect("build_block failed");
            server_a.chain.add_block(block).unwrap();
        }

        let mut rx_b = tr_b.consume().await;

        // This is the typical sync request: start=1, end=0 (all blocks from 1 to tip)
        let req = GetBlocksMessage { start: 1, end: 0 };
        server_a
            .clone()
            .process_get_blocks_message("B".to_string(), req)
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
}
