//! A blockchain implementation in Rust.
//!
//! The main.rs file is mostly used for prototyping as of now.

use crate::core::transaction::Transaction;
use crate::crypto::key_pair::PrivateKey;
use crate::network::local_transport::LocalTransport;
use crate::network::rpc::{Message, MessageType, Rpc};
use crate::network::server::{DEV_CHAIN_ID, Server, ServerError};
use crate::network::transport::{Transport, TransportError};
use crate::types::encoding::Encode;
use crate::utils::log::{self, Logger};
use crate::virtual_machine::assembler::assemble_source;
use blockchain_derive::Error;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::channel;
use tokio::time::sleep;

mod core;
mod crypto;
mod network;
mod types;
mod utils;
mod virtual_machine;

/// Errors that can occur when sending a transaction from the main loop.
#[derive(Debug, Error)]
enum SendTransactionError {
    #[error("failed to add transaction to pool: {0}")]
    AddToPool(ServerError),

    #[error("failed to send over transport: {0}")]
    Transport(TransportError),
}

impl From<ServerError> for SendTransactionError {
    fn from(err: ServerError) -> Self {
        SendTransactionError::AddToPool(err)
    }
}

impl From<TransportError> for SendTransactionError {
    fn from(err: TransportError) -> Self {
        SendTransactionError::Transport(err)
    }
}

#[tokio::main]
async fn main() {
    log::init(log::Level::Info);

    // Create transports
    let tr_local = LocalTransport::new("Local");
    let tr_a = LocalTransport::new("A");
    let tr_b = LocalTransport::new("B");
    let tr_c = LocalTransport::new("C");

    // Create servers
    let main_server = make_server(tr_local, Some(PrivateKey::new())).await;
    let server_a = make_server(tr_a, None).await;
    let server_b = make_server(tr_b, None).await;
    let server_c = make_server(tr_c, None).await;

    // Connect servers (establishes transport connections and initiates handshake)
    main_server.connect(&server_a).await.unwrap();
    server_a.connect(&server_b).await.unwrap();
    server_b.connect(&server_c).await.unwrap();

    // Start remote servers
    let server_a_addr = server_a.transport().addr();
    let server_c_for_late = server_c.clone();
    for server in [server_a, server_b, server_c] {
        tokio::spawn(async move {
            let (sx, rx) = channel::<Rpc>(1024);
            server.start(sx, rx).await;
        });
    }

    // Spawn late-joining server after 12 seconds
    tokio::spawn(async move {
        sleep(Duration::from_secs(12)).await;

        let tr_late = LocalTransport::new("Late");
        let server_late = make_server(tr_late, None).await;
        if let Err(e) = server_late.connect(&server_c_for_late).await {
            eprintln!("Failed to connect late server: {}", e);
            return;
        }

        let (sx, rx) = channel::<Rpc>(1024);
        server_late.start(sx, rx).await;
    });

    // Spawn transaction sender
    let server_for_tx = main_server.clone();
    let logger_for_tx = Logger::new("main");
    tokio::spawn(async move {
        let mut i: u8 = 0;
        loop {
            if let Err(e) = send_transaction(&server_for_tx, server_a_addr.clone()).await {
                logger_for_tx.error(&format!("failed to send transaction {i}: {e}"));
            }
            i += 1;
            sleep(Duration::new(1, 0)).await;
        }
    });

    let (sx, rx) = channel::<Rpc>(1024);
    main_server.start(sx, rx).await;
}

/// Creates a server instance with the given transport and optional validator key.
///
/// If a private key is provided, the server becomes a validator node.
async fn make_server(tr: Arc<LocalTransport>, key: Option<PrivateKey>) -> Arc<Server> {
    let duration = Duration::new(5, 0);
    let id = tr.addr();

    // Server creation for easy testing
    if key.is_some() {
        Server::new(id, tr, duration, key, None, None).await
    } else {
        Server::default(id, tr, duration).await
    }
}

/// Sends a transaction to a peer node via the server.
///
/// Assembles the provided source code into bytecode, signs it with a fresh keypair,
/// adds it to the local pool, and transmits it to the specified peer.
async fn send_transaction(server: &Server, to: String) -> Result<(), SendTransactionError> {
    let key = PrivateKey::new();
    let source = r#"
        LOAD_I64 r0, 10
        LOAD_I64 r1, 32
        ADD r2, r0, r1
    "#;
    let data = assemble_source(source).expect("assembly failed").to_bytes();

    let tx = Transaction::new(data, key, DEV_CHAIN_ID);
    let bytes = tx.to_bytes();
    let msg = Message::new(MessageType::Transaction, bytes);
    server.add_to_pool(tx)?;

    server.transport().send_message(to, msg.to_bytes()).await?;

    Ok(())
}
