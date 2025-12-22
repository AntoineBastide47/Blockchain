//! A blockchain implementation in Rust.

use crate::network::local_transport::LocalTransport;
use crate::network::server::{Server, ServerOps};
use crate::network::transport::Transport;
use bytes::Bytes;
use std::time::Duration;

mod core;
mod crypto;
mod network;
mod test_utils;
mod types;

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
            let _ = tr_remote_tokio
                .send_message(tr_local_tokio.addr(), Bytes::from("Hello World"))
                .await;
            tokio::time::sleep(Duration::new(1, 0)).await;
        }
    });

    let options = ServerOps {
        transports: vec![tr_local, tr_remote],
        private_key: None,
        transaction_pool_capacity: None,
        block_time: Duration::new(12, 0),
    };

    let mut server = Server::new(options);
    server.start().await;
}
