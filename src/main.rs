//! A blockchain implementation in Rust.

use crate::core::transaction::Transaction;
use crate::crypto::key_pair::PrivateKey;
use crate::network::local_transport::LocalTransport;
use crate::network::rpc::{Message, MessageType, Rpc};
use crate::network::server::{Server, ServerOps};
use crate::network::transport::{Transport, TransportError};
use crate::utils::log;
use borsh::BorshSerialize;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::channel;

mod core;
mod crypto;
mod network;
mod types;
mod utils;

#[tokio::main]
async fn main() {
    // The local node running on our machine
    let tr_local = LocalTransport::new("Local");
    let tr_remote = LocalTransport::new("Remote");

    tr_local.connect(tr_remote.clone()).await;
    tr_remote.connect(tr_local.clone()).await;

    let tr_local_tokio = tr_local.clone();
    let tr_remote_tokio = tr_remote.clone();
    tokio::spawn(async move {
        loop {
            let _ = send_transaction(tr_remote_tokio.clone(), tr_local_tokio.addr()).await;
            tokio::time::sleep(Duration::new(1, 0)).await;
        }
    });

    let options = ServerOps::default(tr_local, Duration::new(12, 0));
    log::init(log::Level::Info);

    let server = Server::new(options);
    let (sx, rx) = channel::<Rpc>(1024);
    server.start(sx, rx).await;
}

/// Sends a random transaction to a peer node.
///
/// Creates a new transaction with random 32-byte data, signs it with a fresh keypair,
/// wraps it in a protocol message, and transmits it via the transport layer.
async fn send_transaction(tr: Arc<LocalTransport>, to: String) -> Result<(), TransportError> {
    use rand::RngCore;

    let key = PrivateKey::new();
    let mut buf = vec![0u8; 32];
    rand::rng().fill_bytes(&mut buf);
    let data: &[u8] = buf.as_slice();

    let tx = Transaction::new(data, key).map_err(|e| TransportError::SendFailed(e.to_string()))?;

    let mut buf = Vec::new();
    tx.serialize(&mut buf)
        .map_err(|e| TransportError::SendFailed(e.to_string()))?;

    let msg = Message::new(MessageType::Transaction, buf);

    let mut buf = Vec::new();
    msg.serialize(&mut buf)
        .map_err(|e| TransportError::SendFailed(e.to_string()))?;

    tr.send_message(to, buf.into()).await
}
