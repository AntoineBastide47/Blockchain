//! Blockchain server orchestrating message handling via a transport layer.
//!
//! Processes incoming RPCs from the server's transport in a unified event loop.

use crate::core::block::{Block, Header};
use crate::core::blockchain::Blockchain;
use crate::core::storage::ThreadSafeMemoryStorage;
use crate::core::transaction::Transaction;
use crate::core::validator::BlockValidator;
use crate::crypto::key_pair::PrivateKey;
use crate::network::local_transport::LocalTransport;
use crate::network::rpc::{
    DecodedMessage, DecodedMessageData, HandleRpcFn, Message, MessageType, Rpc, RpcProcessor,
};
use crate::network::transport::Transport;
use crate::network::txpool::TxPool;
use crate::types::hash::Hash;
use crate::utils::log::Logger;
use borsh::{BorshDeserialize, BorshSerialize};
use std::io::Cursor;
use std::sync::{Arc, LazyLock};
use std::time::Duration;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::time::interval;

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
    Block::new(header, genesis_key, vec![]).expect("genesis block creation must not fail")
});

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
            chain: Blockchain::new(Self::genesis_block(), logger),
        });

        let server_thread = server.clone();
        tokio::spawn(async move { server_thread.validator_loop().await });

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
                        Err(e) => self.logger.error(&format!("failed to process rpc: {}", e))
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

            if self.is_validator {
                self.create_new_block().await;
            }
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
        match self.chain.build_block(
            self.private_key.clone().unwrap(),
            self.tx_pool.transactions(),
            // TODO: when better transactions are implemented, use a complexity function to determine how many transactions can be added to each block
        ) {
            Ok(block) => {
                if self.chain.add_block(block) {
                    self.tx_pool.flush()
                }
            }
            Err(e) => self.logger.error(&format!("{e}")),
        }
    }

    /// Validates and adds a transaction to the local pool.
    pub fn add_to_pool(&self, transaction: &Transaction) -> Result<(), String> {
        if !transaction.verify() {
            return Err(format!(
                "cannot add unverified transaction: hash={}",
                transaction.hash
            ));
        }
        self.tx_pool.append(transaction.clone());
        Ok(())
    }

    /// Returns a reference to the server's transport.
    pub fn transport(&self) -> &Arc<LocalTransport> {
        &self.transport
    }

    /// Serializes and broadcasts a transaction to all connected peers.
    async fn broadcast_transaction(
        &self,
        from: String,
        transaction: Transaction,
    ) -> Result<(), String> {
        let mut buf = Vec::new();
        match transaction.serialize(&mut buf) {
            Ok(_) => {
                let msg = Message::new(MessageType::Transaction, buf);
                let mut buf = Vec::new();

                match msg.serialize(&mut buf) {
                    Ok(_) => self.transport.broadcast(from, buf.into()).await,
                    Err(e) => Err(e.to_string()),
                }
            }
            Err(e) => Err(e.to_string()),
        }
    }

    /// Validates and adds a transaction to the pool, then broadcasts to peers.
    ///
    /// Skips duplicate transactions. Returns an error if verification fails.
    async fn process_transaction(
        self: Arc<Self>,
        from: String,
        transaction: Transaction,
    ) -> Result<(), String> {
        if self.tx_pool.contains(transaction.hash) {
            self.logger.warn(&format!(
                "({}) attempting to add a new transaction to the pool that already is in it: hash={}",
                self.transport.addr(),
                transaction.hash
            ));
            return Ok(());
        }

        if !transaction.verify() {
            return Err(format!(
                "attempting to add a new transaction to the pool that hasn't been verified: hash={}",
                transaction.hash
            ));
        }

        // self.logger.info(&format!(
        //     "adding a new transaction to the pool: hash={} pool_size={}",
        //     transaction.hash,
        //     self.tx_pool.length()
        // ));
        self.tx_pool.append(transaction.clone());

        tokio::spawn(async move { self.broadcast_transaction(from, transaction.clone()).await });

        Ok(())
    }
}

#[async_trait::async_trait]
impl RpcProcessor for Server {
    async fn process_message(
        self: Arc<Self>,
        decoded_message: DecodedMessage,
    ) -> Result<(), String> {
        match decoded_message.data {
            DecodedMessageData::Transaction(tx) => {
                self.process_transaction(decoded_message.from, tx).await
            }
            DecodedMessageData::Block(_) => todo!(),
        }
    }
}

/// Default RPC handler that deserializes messages based on their type header.
fn handle_rpc(rpc: Rpc) -> Result<DecodedMessage, String> {
    let msg = Message::try_from_slice(rpc.payload.as_ref())
        .map_err(|e| format!("failed to decode message from {}: {}", rpc.from, e))?;

    match msg.header {
        MessageType::Transaction => {
            let mut reader = Cursor::new(&msg.data.0);
            let tx = Transaction::deserialize_reader(&mut reader)
                .map_err(|e| format!("failed to decode transaction: {}", e))?;
            Ok(DecodedMessage {
                from: rpc.from.clone(),
                data: DecodedMessageData::Transaction(tx),
            })
        }
        MessageType::Block => Err("message header for block not implemented yet".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::key_pair::PrivateKey;

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
        let tx = Transaction::new(b"test data".as_slice(), key).unwrap();

        let mut tx_bytes = Vec::new();
        tx.serialize(&mut tx_bytes).unwrap();

        let msg = Message::new(MessageType::Transaction, tx_bytes);
        let mut msg_bytes = Vec::new();
        msg.serialize(&mut msg_bytes).unwrap();

        let rpc = Rpc::new("sender", msg_bytes);
        let result = handle_rpc(rpc).expect("should decode successfully");

        assert_eq!(result.from, "sender");
        match result.data {
            DecodedMessageData::Transaction(decoded_tx) => {
                assert_eq!(decoded_tx.hash, tx.hash);
            }
            _ => panic!("expected Transaction variant"),
        }
    }

    #[test]
    fn handle_rpc_rejects_malformed_payload() {
        let rpc = Rpc::new("bad_sender", vec![0xFF, 0xFF, 0xFF]);
        let result = handle_rpc(rpc);

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("failed to decode message"));
    }

    #[test]
    fn handle_rpc_rejects_invalid_transaction_data() {
        let msg = Message::new(MessageType::Transaction, vec![0x00, 0x01, 0x02]);
        let mut msg_bytes = Vec::new();
        msg.serialize(&mut msg_bytes).unwrap();

        let rpc = Rpc::new("sender", msg_bytes);
        let result = handle_rpc(rpc);

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("failed to decode transaction"));
    }
}
