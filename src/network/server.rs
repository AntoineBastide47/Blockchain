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
use crate::utils::log::Logger;
use std::sync::{Arc, LazyLock};
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

/// The genesis block, lazily initialized once and shared across all server instances.
static GENESIS_BLOCK: LazyLock<Arc<Block>> = LazyLock::new(|| {
    let header = Header {
        version: 1,
        height: 0,
        timestamp: 0,
        previous_block: Hash::zero(),
        data_hash: Hash::zero(),
        merkle_root: Hash::zero(),
    };
    let genesis_key = PrivateKey::from_bytes(&GENESIS_PRIVATE_KEY_BYTES)
        .expect("GENESIS_PRIVATE_KEY_BYTES must be a valid secp256k1 scalar");
    Block::new(header, genesis_key, vec![])
});

/// Errors produced by the server while handling RPCs and state updates.
#[derive(Debug, blockchain_derive::Error)]
pub enum ServerError {
    #[error("transaction failed verification: hash={0}")]
    InvalidTransaction(Hash),

    #[error("block rejected by chain: hash={hash} error={source}")]
    BlockRejected { hash: Hash, source: StorageError },

    #[error("transport error: {0}")]
    Transport(TransportError),
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
    /// Returns the shared genesis block.
    fn genesis_block() -> Arc<Block> {
        Arc::clone(&GENESIS_BLOCK)
    }

    /// Creates a new server with full configuration options.
    ///
    /// Sets `is_validator` to true if `private_key` is provided.
    pub fn new(
        id: impl Into<Arc<str>>,
        transport: Arc<LocalTransport>,
        block_time: Duration,
        private_key: Option<PrivateKey>,
        transaction_pool_capacity: Option<usize>,
        rpc_handler: Option<HandleRpcFn>,
    ) -> Arc<Self> {
        let is_validator = private_key.is_some();
        let logger = Logger::new(id);
        let server = Arc::new(Self {
            logger: logger.clone(),
            rpc_handler,
            transport,
            private_key,
            is_validator,
            tx_pool: TxPool::new(transaction_pool_capacity),
            block_time,
            chain: Blockchain::new(DEV_CHAIN_ID, Self::genesis_block(), logger),
        });

        if is_validator {
            let server_thread = server.clone();
            tokio::spawn(async move { server_thread.validator_loop().await });
        }

        server
    }

    /// Creates a new server with sensible defaults for a non-validator node.
    pub fn default(
        id: impl Into<Arc<str>>,
        transport: Arc<LocalTransport>,
        block_time: Duration,
    ) -> Arc<Self> {
        Self::new(id, transport, block_time, None, None, None)
    }

    /// Starts the server and begins processing incoming messages.
    ///
    /// Initializes the transport and enters the main event loop.
    /// Blocks until the transport channel closes.
    pub async fn start(self: Arc<Self>, sx: Sender<Rpc>, mut rx: Receiver<Rpc>) {
        self.init_transport(sx).await;

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

    async fn create_new_block(&self) {
        let block = self.chain.build_block(
            self.private_key.clone().unwrap(),
            self.tx_pool.transactions(),
        );
        match self.chain.add_block(block.clone()) {
            Ok(_) => {
                self.tx_pool.flush();
                if let Err(e) = self
                    .broadcast_block(self.logger.id.to_string(), block)
                    .await
                {
                    self.logger.warn(&format!("could not broadcast block: {e}"));
                }
            }
            Err(err) => self
                .logger
                .warn(&format!("could not add newly built block: {err}")),
        }
    }

    /// Validates and adds a transaction to the local pool.
    pub fn add_to_pool(&self, transaction: &Transaction) -> Result<(), ServerError> {
        if !transaction.verify(self.chain.id) {
            return Err(ServerError::InvalidTransaction(
                transaction.id(self.chain.id),
            ));
        }
        self.tx_pool.append(transaction.clone(), self.chain.id);
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

    /// Serializes and broadcasts a transaction to all connected peers.
    async fn broadcast_transaction(
        &self,
        from: String,
        transaction: Transaction,
    ) -> Result<(), TransportError> {
        self.broadcast(from, transaction.to_bytes(), MessageType::Transaction)
            .await
    }

    /// Serializes and broadcasts a block to all connected peers.
    async fn broadcast_block(&self, from: String, block: Arc<Block>) -> Result<(), TransportError> {
        self.broadcast(from, block.to_bytes(), MessageType::Block)
            .await
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
        self.tx_pool.append(transaction.clone(), self.chain.id);

        tokio::spawn(async move { self.broadcast_transaction(from, transaction.clone()).await });

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
                hash: arc_block.header_hash,
                source: e,
            })?;

        let hashes: Vec<Hash> = arc_block
            .transactions
            .iter()
            .map(|tx| tx.id(self.chain.id))
            .collect();
        self.tx_pool.remove_batch(&hashes);
        tokio::spawn(async move { self.broadcast_block(from, arc_block).await });
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
        );
        assert!(server.is_validator);
    }

    #[tokio::test]
    async fn server_is_not_validator_without_private_key() {
        let transport = LocalTransport::new("node");
        let server = Server::default("test-node", transport, Duration::from_secs(10));
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
        };
        Block::new(header, PrivateKey::new(), transactions)
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
                assert_eq!(decoded_block.header_hash, block.header_hash);
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
}
