//! A blockchain implementation in Rust.
//!
//! Starts a single blockchain node from command-line arguments.
//!
//! # Usage
//! ```text
//! blockchain <listen_addr> [OPTIONS]
//! ```
//!
//! # Arguments
//! - `listen_addr`: Local address to bind (e.g., `127.0.0.1:3000`)
//!
//! # Options
//! - `--name <name>`: Node identifier (defaults to listen address)
//! - `--peer <addr>`: Peer address to connect to on startup
//! - `--validator`: Start as a validator node
//!
//! # Identity
//! Each node's identity keypair is stored encrypted at:
//! `~/.blockchain/{chain_id}/{node_name}/identity.key`
//!
//! The passphrase is read from `NODE_PASSPHRASE` env var, or prompted if not set.

use crate::core::transaction::Transaction;
use crate::crypto::key_pair::{PrivateKey, load_or_generate_validator_key};
use crate::network::libp2p_transport::Libp2pTransport;
use crate::network::message::{Message, MessageType};
use crate::network::rpc::Rpc;
use crate::network::server::{DEV_CHAIN_ID, Server};
use crate::network::transport::Transport;
use crate::types::encoding::Encode;
use crate::virtual_machine::assembler::assemble_source;
use rpassword::prompt_password;
use std::env;
use std::net::SocketAddr;
use std::process;
use std::time::Duration;
use tokio::sync::mpsc::channel;
use tokio::sync::oneshot;
use tokio::time::sleep;
use zeroize::Zeroizing;

mod core;
mod crypto;
mod network;
mod types;
mod utils;
mod virtual_machine;

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 || args[1] == "--help" || args[1] == "-h" {
        print_usage(&args[0]);
        process::exit(if args.len() < 2 { 1 } else { 0 });
    }

    let listen_arg = &args[1];

    let listen_addr = match listen_arg.parse().ok() {
        Some(addr) => addr,
        None => {
            eprintln!("Invalid listen address: {}", listen_arg);
            process::exit(1);
        }
    };

    let mut peer_addr: Option<SocketAddr> = None;
    let mut validator_mode = false;
    let mut node_name: Option<&str> = None;

    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--name" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("--name requires an argument");
                    process::exit(1);
                }
                node_name = Some(&args[i]);
                i += 1;
            }
            "--peer" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("--peer requires an argument");
                    process::exit(1);
                }
                peer_addr = args[i].parse().ok();
                if peer_addr.is_none() {
                    eprintln!("Invalid peer address: {}", args[i]);
                    process::exit(1);
                }
                i += 1;
            }
            "--validator" => {
                validator_mode = true;
                i += 1;
            }
            other => {
                eprintln!("Unexpected argument: {}\n", other);
                print_usage(&args[0]);
                process::exit(1);
            }
        }
    }

    let node_name = node_name.unwrap_or_else(|| listen_arg);

    // Get passphrase from environment or prompt
    let passphrase = Zeroizing::new(env::var("NODE_PASSPHRASE").unwrap_or_else(|_| {
        prompt_password(format!("Enter passphrase for node '{node_name}': ")).unwrap_or_else(|e| {
            error!("{e}");
            process::exit(1);
        })
    }));

    if passphrase.is_empty() {
        eprintln!("Passphrase cannot be empty");
        process::exit(1);
    }

    // Create transport and server
    let transport =
        match Libp2pTransport::new(listen_addr, DEV_CHAIN_ID, node_name, passphrase.as_bytes()) {
            Ok(tr) => tr,
            Err(e) => {
                eprintln!("Failed to create transport: {}", e);
                process::exit(1);
            }
        };

    let validator_key = if validator_mode {
        match load_or_generate_validator_key(DEV_CHAIN_ID, node_name, passphrase.as_bytes()) {
            Ok(key) => Some(key),
            Err(e) => {
                eprintln!("Failed to load or generate validator key: {}", e);
                process::exit(1);
            }
        }
    } else {
        None
    };

    // Start server
    let server = Server::new(transport, Duration::new(5, 0), validator_key, None).await;
    let server_clone = server.clone();
    let (sx, rx) = channel::<Rpc>(1024);
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let server_handle = tokio::spawn(async move {
        let validator_handle = server_clone.clone().start(sx).await;
        server_clone.clone().run(rx, shutdown_rx).await;
        server_clone.stop(validator_handle).await;
    });

    // Wait for server to accept inbound connections before proceeding.
    server.transport().wait_until_listening().await;

    info!(
        "Server '{}' started on {} (peer_id: {})",
        node_name,
        listen_addr,
        server.transport().peer_id()
    );

    // Connect to peer if specified
    if let Some(addr) = peer_addr {
        let multiaddr = socket_addr_to_multiaddr(addr);
        info!("Connecting to peer at {}", addr);

        let max_attempts = 5;
        for attempt in 1..=max_attempts {
            match server.connect(multiaddr.clone()).await {
                Ok(peer_id) => {
                    info!("Connected to peer: {}", peer_id);
                    break;
                }
                Err(e) => {
                    error!(
                        "Failed to connect to peer at {} (attempt {}/{}): {}",
                        addr, attempt, max_attempts, e
                    );
                    if attempt == max_attempts {
                        break;
                    }
                    sleep(Duration::from_millis(500)).await;
                }
            }
        }
    }

    // If validator: periodically craft and broadcast a dummy transaction.
    if validator_mode {
        let server_for_txs = server.clone();
        tokio::spawn(async move {
            let mut counter: u64 = 0;
            loop {
                let source = r#"
                    LOAD_I64 r0, 10
                    LOAD_I64 r1, 32
                    ADD r2, r0, r1
                "#;
                let data = assemble_source(source).expect("assembly failed").to_bytes();

                let tx = Transaction::new(data, PrivateKey::new(), DEV_CHAIN_ID);
                let msg = Message::new(MessageType::Transaction, tx.to_bytes());

                if let Err(e) = server_for_txs.add_to_pool(tx) {
                    warn!("validator tx rejected by local pool: {e}");
                } else if let Err(e) = server_for_txs
                    .transport()
                    .broadcast(server_for_txs.transport().peer_id(), msg.to_bytes())
                    .await
                {
                    warn!("validator tx broadcast failed: {e}");
                }

                counter = counter.wrapping_add(1);
                sleep(Duration::from_secs(1)).await;
            }
        });
    }

    if let Err(e) = tokio::signal::ctrl_c().await {
        eprintln!("Failed to setup Ctrl+C handler: {}", e);
        return;
    }
    info!("Ctrl+C received, shutting down...");
    let _ = shutdown_tx.send(());
    if let Err(e) = server_handle.await {
        eprintln!("Server task error: {:?}", e);
    }
}

const USAGE: &str = "\
Blockchain Node

USAGE:
    {program} <listen_addr> [OPTIONS]

ARGS:
    <listen_addr>    Local address to bind (e.g., 127.0.0.1:3000)

OPTIONS:
    --name <name>    Node identifier (defaults to listen address)
    --peer <addr>    Peer address to connect to on startup
    --validator      Start as a validator node with a new keypair
    -h, --help       Print this help message

ENVIRONMENT:
    NODE_PASSPHRASE    Passphrase for identity key encryption (prompted interactively if not set)

EXAMPLES:
    # Start a single node
    {program} 127.0.0.1:3000

    # Start a validator and connect to existing peer
    {program} 127.0.0.1:3001 --peer 127.0.0.1:3000 --validator

    # Run multiple nodes on same machine
    {program} 127.0.0.1:3000 --name node-a
    {program} 127.0.0.1:3001 --name node-b --peer 127.0.0.1:3000

FILES:
    ~/.blockchain/<chain_id>/<node_name>/identity.key
    ~/.blockchain/<chain_id>/<node_name>/.lock
";

/// Prints usage information to stderr.
fn print_usage(program: &str) {
    eprintln!("{}", USAGE.replace("{program}", program));
}

/// Converts a SocketAddr to a libp2p Multiaddr.
fn socket_addr_to_multiaddr(addr: SocketAddr) -> libp2p::Multiaddr {
    use libp2p::Multiaddr;
    use std::net::IpAddr;

    let mut multiaddr = match addr.ip() {
        IpAddr::V4(ip) => Multiaddr::from(ip),
        IpAddr::V6(ip) => Multiaddr::from(ip),
    };
    multiaddr.push(libp2p::multiaddr::Protocol::Tcp(addr.port()));
    multiaddr
}
