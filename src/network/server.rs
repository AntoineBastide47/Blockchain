//! Blockchain server orchestrating message handling across multiple transports.
//!
//! Aggregates incoming RPCs from all registered transports into a single
//! processing loop for unified message handling.

use crate::core::transaction::Transaction;
use crate::crypto::key_pair::PrivateKey;
use crate::network::transport::{Rpc, Transport};
use crate::network::txpool::TxPool;
use crate::{info, warn};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::channel;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::time::interval;

/// Configuration options for the server.
pub struct ServerOps {
    /// Transport layers to aggregate for message processing.
    pub transports: Vec<Arc<dyn Transport>>,
    /// If set, this node becomes a validator node
    pub private_key: Option<PrivateKey>,
    /// The max capacity of the transaction pool hosted on this node
    pub transaction_pool_capacity: Option<usize>,
    /// How often new block are created
    pub block_time: Duration,
}

/// Blockchain server managing multiple transport layers.
///
/// Multiplexes RPC messages from all transports into a single event loop,
/// enabling centralized message processing regardless of transport type.
pub struct Server {
    options: ServerOps,
    is_validator: bool,
    tx_pool: TxPool,
    sx: Sender<Rpc>,
    rx: Receiver<Rpc>,
}

impl Server {
    /// Creates a new server with the specified configuration.
    pub fn new(options: ServerOps) -> Self {
        let (sx, rx) = channel::<Rpc>(1024);
        let is_validator = options.private_key.is_some();
        let transaction_pool = TxPool::new(options.transaction_pool_capacity);
        Server {
            options,
            is_validator,
            tx_pool: transaction_pool,
            sx,
            rx,
        }
    }

    /// Starts the server and begins processing incoming messages.
    ///
    /// Initializes all transports and enters the main event loop.
    /// Blocks until all transport channels close.
    pub async fn start(&mut self) {
        self.init_transports().await;
        let mut ticker = interval(self.options.block_time);

        loop {
            tokio::select! {
                Some(rpc) = self.rx.recv() => {
                    info!("{} sent: {:?}", rpc.from, rpc.payload);
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

    /// Spawns async tasks to forward messages from each transport to the main channel.
    async fn init_transports(&self) {
        for transport in &self.options.transports {
            // Clone the transport and sender pointers to move them to a new thread
            let tr = transport.clone();
            let sender = self.sx.clone();

            // Create a new thread were we listen to all the rpc's received by each transport
            // on each of their associated thread, and then send them all to the main thread
            // so that non-thread safe rpc's can be handled elegantly
            tokio::spawn(async move {
                let mut rx = tr.consume().await;
                while let Some(rpc) = rx.recv().await {
                    let _ = sender.send(rpc).await;
                }
            });
        }
    }

    async fn create_block(&self) {
        info!(
            "create a block every {} seconds",
            self.options.block_time.as_secs()
        );
    }

    async fn handle_transaction(&self, transaction: Transaction) {
        let verified = transaction.verify();
        if verified && !self.tx_pool.contains(transaction.hash) {
            info!(
                "adding a new transaction to the pool: hash={}",
                transaction.hash
            );
            self.tx_pool.append(transaction);
        } else if !verified {
            warn!(
                "attempting to add a new transaction to the pool that hasn't been verified: hash={}",
                transaction.hash
            );
        } else {
            warn!(
                "attempting to add a new transaction to the pool that already is in it: hash={}",
                transaction.hash
            );
        }
    }
}
