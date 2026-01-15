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

use blockchain::core::account::Account;
use blockchain::core::transaction::{Transaction, TransactionType};
use blockchain::crypto::key_pair::{
    Address, PrivateKey, PublicKey, load_or_generate_validator_key,
};
use blockchain::network::libp2p_transport::Libp2pTransport;
use blockchain::network::message::{Message, MessageType};
use blockchain::network::rpc::Rpc;
use blockchain::network::server::{DEV_CHAIN_ID, Server};
use blockchain::network::transport::Transport;
use blockchain::types::encoding::{Decode, Encode};
use blockchain::virtual_machine::assembler::assemble_file;
use blockchain::virtual_machine::vm::TRANSACTION_GAS_LIMIT;
use blockchain::{error, info, warn};
use rpassword::prompt_password;
use std::env;
use std::net::SocketAddr;
use std::process;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::sync::mpsc::channel;
use tokio::sync::oneshot;
use tokio::time::sleep;
use zeroize::Zeroizing;

// Add your public key here to test as a validator
const GENESIS_VALIDATORS: &[(&[u8], u128)] = &[(
    &[
        95, 169, 138, 128, 215, 203, 132, 243, 127, 227, 2, 228, 236, 243, 221, 50, 71, 174, 227,
        201, 119, 121, 236, 243, 230, 151, 10, 172, 44, 10, 250, 59,
    ],
    10u128.pow(20),
)];

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
            k @ ("--name" | "-n") => {
                i += 1;
                if i >= args.len() {
                    eprintln!("{k} requires an argument");
                    process::exit(1);
                }
                node_name = Some(&args[i]);
                i += 1;
            }
            k @ ("--peer" | "-p") => {
                i += 1;
                if i >= args.len() {
                    eprintln!("{k} requires an argument");
                    process::exit(1);
                }
                peer_addr = args[i].parse().ok();
                if peer_addr.is_none() {
                    eprintln!("Invalid peer address: {}", args[i]);
                    process::exit(1);
                }
                i += 1;
            }
            "--validator" | "-v" => {
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

    let validators: Vec<(Address, Account)> = GENESIS_VALIDATORS
        .iter()
        .map(|(pub_key_bytes, balance)| {
            let pubkey = PublicKey::from_bytes(pub_key_bytes).expect("invalid public key");
            (pubkey.address(), Account::new(*balance))
        })
        .collect();

    let server = Server::new(
        transport,
        Duration::new(5, 0),
        validator_key.clone(),
        None,
        &validators,
    )
    .await;
    let server_clone = server.clone();

    // Start server
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
        static TX_NONCE: AtomicU64 = AtomicU64::new(0);

        let server_for_txs = server.clone();
        tokio::spawn(async move {
            loop {
                let data = assemble_file("main.asm")
                    .expect("assembly failed")
                    .to_bytes();

                let nonce = TX_NONCE.fetch_add(1, Ordering::Relaxed);

                // Build a fully populated transaction for the demo.
                let tx = Transaction::new(
                    PrivateKey::new().public_key().address(),
                    None,
                    data,
                    0,
                    0,
                    10u128.pow(9),
                    TRANSACTION_GAS_LIMIT,
                    nonce,
                    validator_key.clone().unwrap(),
                    DEV_CHAIN_ID,
                    TransactionType::DeployContract,
                );
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
    -n, --name <name>    Node identifier (defaults to listen address)
    -p, --peer <addr>    Peer address to connect to on startup
    -v, --validator      Start as a validator node with a new keypair
    -h, --help           Print this help message

ENVIRONMENT:
    NODE_PASSPHRASE      Passphrase for identity key encryption (prompted interactively if not set)

EXAMPLES:
    # Start a single node
    {program} 127.0.0.1:3000

    # Start a validator and connect to existing peer
    {program} 127.0.0.1:3001 --peer 127.0.0.1:3000 --validator

    # Run multiple nodes on same machine
    {program} 127.0.0.1:3000 --name node-a &
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
