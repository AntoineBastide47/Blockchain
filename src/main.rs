//! A blockchain implementation in Rust.
//!
//! The main.rs file is mostly used for prototyping as of now.

use crate::core::transaction::Transaction;
use crate::crypto::key_pair::PrivateKey;
use crate::network::local_transport::LocalTransport;
use crate::network::rpc::{Message, MessageType, Rpc};
use crate::network::server::Server;
use crate::network::transport::Transport;
use crate::types::encoding::Encode;
use crate::utils::log;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::channel;
use tokio::time::sleep;

mod core;
mod crypto;
mod network;
mod types;
mod utils;

#[tokio::main]
async fn main() {
    // The local node running on our machine
    let tr_local = LocalTransport::new("Local");
    let tr_a = LocalTransport::new("A");
    let tr_b = LocalTransport::new("B");
    let tr_c = LocalTransport::new("C");

    tr_local.connect(&tr_a).await;
    tr_a.connect(&tr_b).await;
    tr_b.connect(&tr_c).await;

    // let connect_tr = tr_c.clone();
    // tokio::spawn(async move {
    //     sleep(Duration::new(7, 0)).await;
    //     let tr_late = LocalTransport::new("Late");
    //     let server_late = make_server(tr_late.clone(), None);
    //     tr_late.connect(&connect_tr).await;
    //     let (sx, rx) = channel::<Rpc>(1024);
    //     server_late.start(sx, rx).await
    // });

    log::init(log::Level::Info);

    let main_server = make_server(tr_local, Some(PrivateKey::new()));
    init_remote_servers(vec![tr_a.clone(), tr_b, tr_c]);

    let server_for_tx = main_server.clone();
    let tr_a_addr = tr_a.addr();
    tokio::spawn(async move {
        let mut i: u8 = 0;
        loop {
            let _ = send_transaction(&server_for_tx, tr_a_addr.clone(), i).await;
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
fn make_server(tr: Arc<LocalTransport>, key: Option<PrivateKey>) -> Arc<Server> {
    let duration = Duration::new(5, 0);
    let id = tr.addr();

    // Server creation for easy testing
    if key.is_some() {
        Server::new(id, tr, duration, key, None, None)
    } else {
        Server::default(id, tr, duration)
    }
}

/// Spawns non-validator server instances for each transport in the background.
fn init_remote_servers(transports: Vec<Arc<LocalTransport>>) {
    for tr in transports {
        tokio::spawn(async move {
            let (sx, rx) = channel::<Rpc>(1024);
            make_server(tr, None).start(sx, rx).await
        });
    }
}

/// Sends a random transaction to a peer node via the server.
///
/// Creates a new transaction with random 32-byte data, signs it with a fresh keypair,
/// adds it to the local pool, and transmits it to the specified peer.
async fn send_transaction(server: &Server, to: String, index: u8) -> Result<(), String> {
    let key = PrivateKey::new();
    let data = vec![index; 32];

    let tx = Transaction::new(data, key);
    let msg = Message::new(MessageType::Transaction, tx.to_bytes());
    server.add_to_pool(&tx)?;

    server
        .transport()
        .send_message(to, msg.to_bytes())
        .await
        .map_err(|e| e.to_string())
}
