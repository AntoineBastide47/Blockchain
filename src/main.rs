//! A blockchain implementation in Rust.
//!
//! The main.rs file is mostly used for prototyping as of now.

use crate::core::transaction::Transaction;
use crate::crypto::key_pair::PrivateKey;
use crate::network::message::{Message, MessageType};
use crate::network::rpc::Rpc;
use crate::network::server::{DEV_CHAIN_ID, Server, ServerError};
use crate::network::tcp_transport::TcpTransport;
use crate::network::transport::{Transport, TransportError};
use crate::types::encoding::Encode;
use crate::utils::log;
use crate::utils::log::Logger;
use crate::virtual_machine::assembler::assemble_source;
use blockchain_derive::Error;
use std::net::SocketAddr;
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

    // Create TCP transports with different ports (mixed IPv4/IPv6)
    // Each transport has its own cryptographic identity for authenticated handshakes
    let tr_main = TcpTransport::new("127.0.0.1:3000".parse().unwrap());
    let tr_a = TcpTransport::new("127.0.0.1:3001".parse().unwrap());
    let tr_b = TcpTransport::new("[::1]:3002".parse().unwrap());
    let tr_c = TcpTransport::new("[::1]:3003".parse().unwrap());

    // Create servers
    let main_server = make_server(tr_main, Some(PrivateKey::new())).await;
    let server_a = make_server(tr_a, None).await;
    let server_b = make_server(tr_b, None).await;
    let server_c = make_server(tr_c, None).await;

    // Start other servers (delayed so main server starts first)
    let server_a_addr = server_a.transport().addr();
    let server_c_for_late = server_c.clone();

    for server in [server_a.clone(), server_b.clone(), server_c.clone()] {
        let (sx, rx) = channel::<Rpc>(1024);
        tokio::spawn(async move {
            server.start(sx, rx).await;
        });
    }

    // Wait for servers to bind
    sleep(Duration::from_millis(1100)).await;

    // Connect servers (establishes TCP connections and initiates handshake)
    main_server.connect(&server_a).await.unwrap();
    server_a.connect(&server_b).await.unwrap();
    server_b.connect(&server_c).await.unwrap();

    // Spawn late-joining server after 12 seconds
    tokio::spawn(async move {
        sleep(Duration::from_secs(12)).await;

        let tr_late = TcpTransport::new("127.0.0.1:3004".parse().unwrap());
        let server_late = make_server(tr_late, None).await;

        // Start the late server first
        let server_late_clone = server_late.clone();
        let (sx, rx) = channel::<Rpc>(1024);
        tokio::spawn(async move {
            server_late_clone.start(sx, rx).await;
        });

        sleep(Duration::from_millis(100)).await;

        if let Err(e) = server_late.connect(&server_c_for_late).await {
            eprintln!("Failed to connect late server: {e}");
        }
    });

    // Spawn transaction sender
    let server_for_tx = main_server.clone();
    let logger_for_tx = Logger::new("main");
    tokio::spawn(async move {
        let mut i: u8 = 0;
        loop {
            if let Err(e) = send_transaction(&server_for_tx, server_a_addr).await {
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
async fn make_server<T: Transport>(tr: Arc<T>, key: Option<PrivateKey>) -> Arc<Server<T>> {
    let duration = Duration::new(5, 0);
    let id = tr.addr();

    // Server creation for easy testing
    if key.is_some() {
        Server::new(id, tr, duration, key, None).await
    } else {
        Server::default(id, tr, duration).await
    }
}

/// Sends a transaction to a peer node via the server.
///
/// Assembles the provided source code into bytecode, signs it with a fresh keypair,
/// adds it to the local pool, and transmits it to the specified peer.
async fn send_transaction<T: Transport>(
    server: &Server<T>,
    to: SocketAddr,
) -> Result<(), SendTransactionError> {
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
