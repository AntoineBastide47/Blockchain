//! Blockchain server orchestrating message handling via a transport layer.
//!
//! Processes incoming RPCs from the server's transport in a unified event loop.

use crate::core::transaction::Transaction;
use crate::crypto::key_pair::PrivateKey;
use crate::network::local_transport::LocalTransport;
use crate::network::rpc::{
    DecodedMessage, DecodedMessageData, HandleRpcFn, Message, MessageType, Rpc, RpcProcessor,
};
use crate::network::transport::Transport;
use crate::network::txpool::TxPool;
use crate::{error, info, warn};
use borsh::{BorshDeserialize, BorshSerialize};
use bytes::Bytes;
use std::io::Cursor;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::time::interval;

/// Configuration options for the server.
pub struct ServerOps {
    /// Optional custom handler for incoming RPC messages. Uses default handler if `None`.
    pub rpc_handler: Option<HandleRpcFn>,
    /// This server's transport layer (its network identity).
    pub transport: Arc<LocalTransport>,
    /// If set, this node becomes a validator node.
    pub private_key: Option<PrivateKey>,
    /// The max capacity of the transaction pool hosted on this node.
    pub transaction_pool_capacity: Option<usize>,
    /// How often new blocks are created.
    pub block_time: Duration,
}

impl ServerOps {
    /// Creates server options with sensible defaults for a non-validator node.
    pub fn default(transport: Arc<LocalTransport>, block_time: Duration) -> Self {
        Self {
            rpc_handler: None,
            transport,
            private_key: None,
            transaction_pool_capacity: None,
            block_time,
        }
    }
}

/// Blockchain server managing a single transport layer.
///
/// Processes RPC messages from the transport in an event loop,
/// handling transactions and block creation.
pub struct Server {
    options: ServerOps,
    is_validator: bool,
    tx_pool: TxPool,
}

impl Server {
    /// Creates a new server with the specified configuration.
    pub fn new(options: ServerOps) -> Self {
        let is_validator = options.private_key.is_some();
        let tx_pool = TxPool::new(options.transaction_pool_capacity);
        Server {
            options,
            is_validator,
            tx_pool,
        }
    }

    /// Starts the server and begins processing incoming messages.
    ///
    /// Initializes the transport and enters the main event loop.
    /// Blocks until the transport channel closes.
    pub async fn start(self: Arc<Self>, sx: Sender<Rpc>, mut rx: Receiver<Rpc>) {
        self.init_transport(sx).await;
        let mut ticker = interval(self.options.block_time);

        loop {
            tokio::select! {
                Some(rpc) = rx.recv() => {
                    let result = match &self.options.rpc_handler {
                        Some(handler) => handler(rpc),
                        None => handle_rpc(rpc),
                    };

                    match result {
                        Ok(msg) => {
                            if let Err(e) = &self.clone().process_message(msg).await {
                                error!("failed to process rpc: {}", e)
                            }

                        },
                        Err(e) => error!("failed to process rpc: {}", e)
                    }
                }
                _ = ticker.tick() => {
                    if self.is_validator {
                        self.create_block().await;
                    }
                }
                else => {
                    break;
                }
            }
        }

        info!("Server shut down");
    }

    /// Spawns an async task to forward messages from the transport to the main channel.
    async fn init_transport(&self, sx: Sender<Rpc>) {
        let tr = self.options.transport.clone();
        tokio::spawn(async move {
            let mut rx = tr.consume().await;
            while let Some(rpc) = rx.recv().await {
                let _ = sx.send(rpc).await;
            }
        });
    }

    async fn create_block(&self) {
        info!(
            "create a block every {} seconds",
            self.options.block_time.as_secs()
        );
    }
    /// Serializes and broadcasts a transaction to all connected peers.
    async fn broadcast_transaction(&self, transaction: Transaction) -> Result<(), String> {
        let mut buf = Vec::new();
        match transaction.serialize(&mut buf) {
            Ok(_) => {
                let msg = Message::new(MessageType::Transaction, buf);
                let mut buf = Vec::new();

                match msg.serialize(&mut buf) {
                    Ok(_) => self.broadcast(buf.into()).await,
                    Err(e) => Err(e.to_string()),
                }
            }
            Err(e) => Err(e.to_string()),
        }
    }

    /// Broadcasts raw payload bytes to all connected peers via the transport layer.
    async fn broadcast(&self, payload: Bytes) -> Result<(), String> {
        self.options.transport.broadcast(payload.into()).await
    }

    /// Validates and adds a transaction to the pool, then broadcasts to peers.
    ///
    /// Skips duplicate transactions. Returns an error if verification fails.
    async fn process_transaction(
        self: Arc<Self>,
        _from: String,
        transaction: Transaction,
    ) -> Result<(), String> {
        if self.tx_pool.contains(transaction.hash) {
            warn!(
                "({}) attempting to add a new transaction to the pool that already is in it: hash={}",
                self.options.transport.addr(),
                transaction.hash
            );
            return Ok(());
        }

        if !transaction.verify() {
            return Err(format!(
                "attempting to add a new transaction to the pool that hasn't been verified: hash={}",
                transaction.hash
            ));
        }

        info!(
            "adding a new transaction to the pool: hash={}",
            transaction.hash
        );
        self.tx_pool.append(transaction.clone());

        tokio::spawn(async move { self.broadcast_transaction(transaction.clone()).await });

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

    #[test]
    fn server_is_validator_when_private_key_set() {
        let transport = LocalTransport::new("validator");
        let mut options = ServerOps::default(transport, Duration::from_secs(10));
        options.private_key = Some(PrivateKey::new());

        let server = Server::new(options);
        assert!(server.is_validator);
    }

    #[test]
    fn server_is_not_validator_without_private_key() {
        let transport = LocalTransport::new("node");
        let options = ServerOps::default(transport, Duration::from_secs(10));

        let server = Server::new(options);
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
