//! Blockchain server orchestrating message handling across multiple transports.
//!
//! Aggregates incoming RPCs from all registered transports into a single
//! processing loop for unified message handling.

use crate::network::transport::{RPC, Transport};
use std::sync::Arc;
use tokio::sync::mpsc::channel;
use tokio::sync::mpsc::{Receiver, Sender};

/// Configuration options for the server.
pub struct ServerOps {
    /// Transport layers to aggregate for message processing.
    pub transports: Vec<Arc<dyn Transport>>,
}

/// Blockchain server managing multiple transport layers.
///
/// Multiplexes RPC messages from all transports into a single event loop,
/// enabling centralized message processing regardless of transport type.
pub struct Server {
    options: ServerOps,
    tx: Sender<RPC>,
    rx: Receiver<RPC>,
}

impl Server {
    /// Creates a new server with the specified configuration.
    pub fn new(options: ServerOps) -> Server {
        let (tx, rx) = channel::<RPC>(1024);
        Server { options, tx, rx }
    }

    /// Starts the server and begins processing incoming messages.
    ///
    /// Initializes all transports and enters the main event loop.
    /// Blocks until all transport channels close.
    pub async fn start(&mut self) {
        self.init_transports().await;

        loop {
            if let Some(rpc) = self.rx.recv().await {
                println!("{} sent: {:?}", rpc.from, rpc.payload);
            } else {
                break;
            }
        }

        println!("Server shut down");
    }

    /// Spawns async tasks to forward messages from each transport to the main channel.
    async fn init_transports(&self) {
        for transport in &self.options.transports {
            // Clone the transport and sender pointers to move them to a new thread
            let tr = transport.clone();
            let sender = self.tx.clone();

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
}
