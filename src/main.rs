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
use blockchain::core::blockchain::Blockchain;
use blockchain::core::transaction::{Transaction, TransactionType};
use blockchain::core::validator::BlockValidator;
use blockchain::crypto::key_pair::{Address, PublicKey, load_or_generate_validator_key};
use blockchain::network::libp2p_transport::Libp2pTransport;
use blockchain::network::message::{Message, MessageType};
use blockchain::network::rpc::Rpc;
use blockchain::network::server::{DEV_CHAIN_ID, Server};
use blockchain::network::transport::Transport;
use blockchain::storage::rocksdb_storage::RocksDbStorage;
use blockchain::storage::rocksdb_storage::{
    CF_BLOCKS, CF_HEADERS, CF_META, CF_SNAPSHOTS, CF_STATE,
};
use blockchain::types::encoding::{Decode, Encode};
use blockchain::virtual_machine::assembler::assemble_file;
use blockchain::virtual_machine::program::ExecuteProgram;
use blockchain::virtual_machine::vm::Value;
use blockchain::{error, info, warn};
use rocksdb::{BlockBasedOptions, Cache, ColumnFamilyDescriptor, DB, DBCompressionType, Options};
use rpassword::prompt_password;
use std::env;
use std::fs;
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process;
use std::time::Duration;
use tokio::sync::mpsc::channel;
use tokio::sync::oneshot;
use tokio::time::sleep;
use zeroize::Zeroizing;

// Add your public key here to test as a validator
const GENESIS_VALIDATORS: &[(&[u8], u128)] = &[(
    &[
        239, 30, 167, 202, 168, 240, 126, 255, 50, 105, 78, 37, 127, 228, 70, 28, 221, 252, 253,
        12, 51, 148, 105, 241, 23, 128, 94, 66, 243, 140, 192, 39,
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

    // Initialize RocksDB
    let db = match rocksdb_init(DEV_CHAIN_ID, node_name) {
        Ok(db) => std::sync::Arc::new(db),
        Err(e) => {
            eprintln!("Failed to initialize RocksDB: {}", e);
            process::exit(1);
        }
    };

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

    let server = match Server::new(transport, db, validator_key.clone(), None, &validators).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to create server: {}", e);
            process::exit(1);
        }
    };
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

    // If validator: deploy a contract, then repeatedly invoke it.
    if validator_mode {
        let server_for_txs = server.clone();
        let validator_key_clone = validator_key.clone().unwrap();

        tokio::spawn(async move {
            let sender_addr = validator_key_clone.public_key().address();

            // Deploy contract first
            let deploy_data = assemble_file("../example_contracts/factorial.asm")
                .expect("assembly failed")
                .to_bytes();

            // Get current on-chain nonce
            let deploy_nonce = server_for_txs
                .get_account(sender_addr)
                .map(|acc| acc.nonce())
                .unwrap_or(0);
            let deploy_tx = Transaction::new(
                validator_key_clone.public_key().address(),
                None,
                deploy_data.to_vec(),
                0,
                0,
                10u128.pow(9),
                250_000,
                deploy_nonce,
                validator_key_clone.clone(),
                DEV_CHAIN_ID,
                TransactionType::DeployContract,
            );

            // Compute the contract_id (same as Blockchain::contract_id)
            let contract_id = Blockchain::<BlockValidator, RocksDbStorage>::contract_id(&deploy_tx);

            let msg = Message::new(MessageType::Transaction, deploy_tx.to_bytes());
            if let Err(e) = server_for_txs.add_to_pool(deploy_tx) {
                warn!("deploy tx rejected: {e}");
            } else if let Err(e) = server_for_txs
                .transport()
                .broadcast(server_for_txs.transport().peer_id(), msg.to_bytes())
                .await
            {
                warn!("deploy tx broadcast failed: {e}");
            }

            // Wait for deployment to be mined
            sleep(Duration::from_secs(6)).await;

            // Track the last nonce we submitted to avoid duplicate transactions
            let mut last_submitted_nonce: Option<u64> = None;

            // Now invoke the contract repeatedly
            loop {
                // Get current on-chain nonce
                let chain_nonce = server_for_txs
                    .get_account(sender_addr)
                    .map(|acc| acc.nonce())
                    .unwrap_or(0);

                // Only create a new transaction if the previous one was included
                // (chain_nonce advanced) or we haven't submitted one yet
                if last_submitted_nonce.is_some_and(|n| n >= chain_nonce) {
                    // Previous transaction not yet included, wait
                    sleep(Duration::from_secs(1)).await;
                    continue;
                }

                let exec_program = ExecuteProgram {
                    contract_id,
                    function_id: 0,            // First public function (factorial)
                    args: vec![Value::Int(5)], // Compute 5!
                    arg_items: Vec::new(),
                };

                let invoke_tx = Transaction::new(
                    contract_id,
                    None,
                    exec_program.to_bytes().to_vec(),
                    0,
                    0,
                    10u128.pow(9),
                    50_000,
                    chain_nonce,
                    validator_key_clone.clone(),
                    DEV_CHAIN_ID,
                    TransactionType::InvokeContract,
                );

                let msg = Message::new(MessageType::Transaction, invoke_tx.to_bytes());
                if let Err(e) = server_for_txs.add_to_pool(invoke_tx) {
                    warn!("invoke tx rejected: {e}");
                } else {
                    last_submitted_nonce = Some(chain_nonce);
                    if let Err(e) = server_for_txs
                        .transport()
                        .broadcast(server_for_txs.transport().peer_id(), msg.to_bytes())
                        .await
                    {
                        warn!("invoke tx broadcast failed: {e}");
                    }
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

/// Returns the path to the node's data directory.
///
/// Path: `~/.blockchain/{chain_id}/{node_name}/`
fn node_data_dir(chain_id: u64, node_name: &str) -> io::Result<PathBuf> {
    let home = dirs_next::home_dir()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "home directory not found"))?;
    let node_dir = home
        .join(".blockchain")
        .join(chain_id.to_string())
        .join(node_name);
    fs::create_dir_all(&node_dir)?;
    Ok(node_dir)
}

/// Initializes RocksDB with the required column families.
///
/// Database location: `~/.blockchain/{chain_id}/{node_name}/db/`
///
/// Column families:
/// - `headers`: Block headers indexed by hash
/// - `blocks`: Full blocks indexed by hash
/// - `meta`: Metadata (tip hash, state root)
/// - `state`: SMT key-value pairs
fn rocksdb_init(chain_id: u64, node_name: &str) -> io::Result<DB> {
    let db_path = node_data_dir(chain_id, node_name)?.join("db");

    let parallelism = std::thread::available_parallelism()
        .map(|n| n.get() as i32)
        .unwrap_or(4);

    // Shared block cache (512MB default, reasonable for most machines)
    let cache = Cache::new_lru_cache(512 * 1024 * 1024);

    // DB-wide options
    let mut opts = Options::default();
    opts.create_if_missing(true);
    opts.create_missing_column_families(true);
    opts.increase_parallelism(parallelism);
    opts.set_max_background_jobs(parallelism.min(8));
    opts.set_compression_type(DBCompressionType::Lz4);
    opts.set_write_buffer_size(64 * 1024 * 1024);
    opts.optimize_level_style_compaction(512 * 1024 * 1024);

    // Headers CF: point lookups by hash, write-once read-many
    let headers_opts = cf_options_with_bloom(&cache, 10.0);

    // Blocks CF: large values, point lookups, heavier compression
    let mut blocks_opts = cf_options_with_bloom(&cache, 10.0);
    blocks_opts.set_compression_type(DBCompressionType::Zstd);

    // Meta CF: tiny, frequent access (tip, state root)
    let meta_opts = cf_options_with_bloom(&cache, 10.0);

    // State CF: SMT nodes, high read/write during execution
    let state_opts = cf_options_with_bloom(&cache, 10.0);

    let cfs = vec![
        ColumnFamilyDescriptor::new(CF_HEADERS, headers_opts),
        ColumnFamilyDescriptor::new(CF_BLOCKS, blocks_opts),
        ColumnFamilyDescriptor::new(CF_META, meta_opts),
        ColumnFamilyDescriptor::new(CF_STATE, state_opts),
        ColumnFamilyDescriptor::new(CF_SNAPSHOTS, Options::default()),
    ];

    DB::open_cf_descriptors(&opts, &db_path, cfs)
        .map_err(|e| io::Error::other(format!("failed to open RocksDB: {}", e)))
}

/// Creates column family options with bloom filter and shared block cache.
fn cf_options_with_bloom(cache: &Cache, bits_per_key: f64) -> Options {
    let mut block_opts = BlockBasedOptions::default();
    block_opts.set_block_cache(cache);
    block_opts.set_bloom_filter(bits_per_key, false);

    let mut opts = Options::default();
    opts.set_block_based_table_factory(&block_opts);
    opts
}
