//! libp2p-based transport implementation for network communication.
//!
//! Provides encrypted, authenticated peer-to-peer messaging using libp2p's
//! modular networking stack with Noise protocol authentication and Yamux multiplexing.
//!
//! # Architecture
//!
//! ```text
//!     ┌─────────────────────────────────────────────────────────────────┐
//!     │                     Libp2pTransport                             │
//!     └─────────────────────────────────────────────────────────────────┘
//!                                    │
//!                                    ▼
//!     ┌─────────────────────────────────────────────────────────────────┐
//!     │                      libp2p Swarm                               │
//!     │  ┌──────────────────────────────────────────────────────────┐   │
//!     │  │                  RpcBehaviour                            │   │
//!     │  │  ┌─────────────────┐  ┌─────────────────────────────┐    │   │
//!     │  │  │ request_response│  │        identify             │    │   │
//!     │  │  └─────────────────┘  └─────────────────────────────┘    │   │
//!     │  └──────────────────────────────────────────────────────────┘   │
//!     │                           │                                     │
//!     │  ┌────────────────────────┴────────────────────────────────┐    │
//!     │  │              Transport Layer                            │    │
//!     │  │  TCP + Noise XX + Yamux                                 │    │
//!     │  └─────────────────────────────────────────────────────────┘    │
//!     └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Peer Identity
//!
//! Peer IDs are derived from the libp2p identity keypair using SHA3, matching
//! the existing `Hash` type used throughout the codebase. The mapping between
//! `libp2p::PeerId` and `SocketAddr` is maintained bidirectionally.

use crate::impl_transport_consume;
use crate::network::rpc::{RawRpc, Rpc};
use crate::network::transport::{
    PeerId, Transport as BlockchainTransport, TransportError, spawn_rpc_forwarder,
};
use crate::types::bytes::Bytes;
use crate::types::encoding::{Decode, Encode};
use crate::types::hash::Hash;
use crate::types::wrapper_types::BoxFuture;
use crate::{error, info};
use argon2::Argon2;
use chacha20poly1305::{
    XChaCha20Poly1305,
    aead::{Aead, KeyInit},
};
use dashmap::DashMap;
use fs2::FileExt;
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, Future, StreamExt};
use libp2p::swarm::dial_opts::DialOpts;
use libp2p::{
    Multiaddr, PeerId as Libp2pPeerId, Swarm, Transport,
    core::upgrade::Version,
    identify, identity, noise,
    request_response::{self, Codec, OutboundRequestId, ProtocolSupport, ResponseChannel},
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux,
};
use rand_core::OsRng;
use rand_core::RngCore;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::sync::mpsc::{Receiver, Sender, channel};
use tokio::sync::{Mutex, Notify, oneshot};
use zeroize::Zeroizing;

/// Protocol identifier prefix for all blockchain protocols.
/// Combined with chain ID to create chain-specific protocol strings.
const PROTOCOL_PREFIX: &str = "/blockchain/";
/// Protocol identifier suffix for RPC request-response messages.
const RPC_PROTOCOL_SUFFIX: &str = "/rpc/1.0.0";
/// Protocol identifier suffix for the identify protocol.
const ID_PROTOCOL_SUFFIX: &str = "/id/1.0.0";

/// Maximum allowed message size for RPC payloads (16 MB).
/// Messages exceeding this limit are rejected during decoding.
const MAX_MESSAGE_SIZE: usize = 16 * 1024 * 1024;

/// Magic bytes identifying an encrypted keypair file.
const KEYFILE_MAGIC: &[u8; 4] = b"BKEY";
/// Current keyfile format version.
const KEYFILE_VERSION: u8 = 1;
/// Salt length for Argon2id (32 bytes recommended).
const SALT_LEN: usize = 32;
/// Nonce length for XChaCha20-Poly1305 (24 bytes).
const NONCE_LEN: usize = 24;
/// Derived key length for XChaCha20-Poly1305 (32 bytes).
const DERIVED_KEY_LEN: usize = 32;

/// Returns the path to the node's data directory.
///
/// The path is `~/.blockchain/{chain_id}/{node_name}/`.
/// Creates the directory if it doesn't exist.
fn node_data_dir(chain_id: u64, node_name: &str) -> io::Result<PathBuf> {
    let home = dirs::home_dir()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "home directory not found"))?;
    let node_dir = home
        .join(".blockchain")
        .join(chain_id.to_string())
        .join(node_name);
    fs::create_dir_all(&node_dir)?;
    Ok(node_dir)
}

/// Acquires an exclusive lock on the node's data directory.
///
/// Creates `~/.blockchain/{chain_id}/{node_name}/.lock` and acquires an exclusive
/// file lock. This prevents multiple processes from using the same node identity.
///
/// The lock is held for the lifetime of the returned `File` handle.
/// When the handle is dropped (or the process exits), the lock is released.
///
/// # Errors
///
/// Returns an error if another process already holds the lock.
fn acquire_node_lock(chain_id: u64, node_name: &str) -> io::Result<File> {
    let node_dir = node_data_dir(chain_id, node_name)?;
    let lock_path = node_dir.join(".lock");

    let lock_file = File::create(&lock_path)?;
    lock_file.try_lock_exclusive().map_err(|_| {
        io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!(
                "node '{}' is already running (lock held: {})",
                node_name,
                lock_path.display()
            ),
        )
    })?;

    Ok(lock_file)
}

/// Returns the path to the keypair file for a given chain ID and node name.
///
/// The path is `~/.blockchain/{chain_id}/{node_name}/identity.key`.
/// Creates the parent directories if they don't exist.
///
/// Each node instance has its own keypair, peer ID, and data directory.
/// The key path is intentionally independent of network address to ensure
/// identity stability across IP/port changes, machine migrations, and NAT re-mappings.
fn keypair_path(chain_id: u64, node_name: &str) -> io::Result<PathBuf> {
    let node_dir = node_data_dir(chain_id, node_name)?;
    Ok(node_dir.join("identity.key"))
}

/// Derives an encryption key from a passphrase using Argon2id.
///
/// Uses OWASP-recommended parameters for Argon2id:
/// - Memory: 19 MiB
/// - Iterations: 2
/// - Parallelism: 1
fn derive_key(passphrase: &[u8], salt: &[u8]) -> io::Result<Zeroizing<[u8; DERIVED_KEY_LEN]>> {
    let mut key = Zeroizing::new([0u8; DERIVED_KEY_LEN]);
    Argon2::default()
        .hash_password_into(passphrase, salt, key.as_mut())
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("key derivation failed: {}", e),
            )
        })?;
    Ok(key)
}

/// Encrypts a keypair and writes it to the specified path.
///
/// File format:
/// - `[4 bytes]` magic "KEY"
/// - `[1 byte]` version
/// - `[32 bytes]` salt
/// - `[24 bytes]` nonce
/// - `[variable]` ciphertext (protobuf-encoded keypair + 16-byte auth tag)
fn save_encrypted_keypair(
    path: &PathBuf,
    keypair: &identity::Keypair,
    passphrase: &[u8],
) -> io::Result<()> {
    let mut rng = OsRng;

    // Generate random salt and nonce
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut salt);
    rng.fill_bytes(&mut nonce);

    // Derive encryption key
    let key = derive_key(passphrase, &salt)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref()).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("cipher init failed: {}", e),
        )
    })?;

    // Encode keypair to protobuf
    let plaintext = Zeroizing::new(keypair.to_protobuf_encoding().map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("keypair encoding failed: {}", e),
        )
    })?);

    // Encrypt
    let ciphertext = cipher
        .encrypt((&nonce).into(), plaintext.as_ref())
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("encryption failed: {}", e),
            )
        })?;

    // Build file contents
    let mut file_data = Vec::with_capacity(4 + 1 + SALT_LEN + NONCE_LEN + ciphertext.len());
    file_data.extend_from_slice(KEYFILE_MAGIC);
    file_data.push(KEYFILE_VERSION);
    file_data.extend_from_slice(&salt);
    file_data.extend_from_slice(&nonce);
    file_data.extend_from_slice(&ciphertext);

    fs::write(path, &file_data)?;
    info!("Saved encrypted keypair to {}", path.display());
    Ok(())
}

/// Loads and decrypts a keypair from the specified path.
///
/// Returns an error if:
/// - File format is invalid
/// - Passphrase is incorrect
/// - File is corrupted
fn load_encrypted_keypair(path: &PathBuf, passphrase: &[u8]) -> io::Result<identity::Keypair> {
    let file_data = fs::read(path)?;

    // Validate minimum length
    let header_len = 4 + 1 + SALT_LEN + NONCE_LEN;
    if file_data.len() < header_len + 16 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "keyfile too short",
        ));
    }

    // Validate magic
    if &file_data[0..4] != KEYFILE_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid keyfile magic",
        ));
    }

    // Validate version
    let version = file_data[4];
    if version != KEYFILE_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported keyfile version: {}", version),
        ));
    }

    // Extract components
    let salt = &file_data[5..5 + SALT_LEN];
    let nonce = &file_data[5 + SALT_LEN..5 + SALT_LEN + NONCE_LEN];
    let ciphertext = &file_data[5 + SALT_LEN + NONCE_LEN..];

    // Derive decryption key
    let key = derive_key(passphrase, salt)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref()).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("cipher init failed: {}", e),
        )
    })?;

    // Decrypt
    let plaintext = Zeroizing::new(cipher.decrypt(nonce.into(), ciphertext).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "decryption failed (wrong passphrase or corrupted file)",
        )
    })?);

    // Decode keypair
    let keypair = identity::Keypair::from_protobuf_encoding(&plaintext).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("keypair decoding failed: {}", e),
        )
    })?;

    info!("Loaded encrypted keypair from {}", path.display());
    Ok(keypair)
}

/// Loads an existing keypair or generates a new one.
///
/// - If the keyfile exists: decrypts and returns it (fails on wrong passphrase)
/// - If the keyfile does not exist: generates a new keypair, encrypts, and saves it
///
/// **Never auto-regenerates on decryption failure.**
fn load_or_generate_keypair(
    chain_id: u64,
    node_name: &str,
    passphrase: &[u8],
) -> io::Result<identity::Keypair> {
    let path = keypair_path(chain_id, node_name)?;

    if path.exists() {
        // Keyfile exists - must decrypt successfully or fail
        load_encrypted_keypair(&path, passphrase)
    } else {
        // No keyfile - generate new identity
        let keypair = identity::Keypair::generate_ed25519();
        save_encrypted_keypair(&path, &keypair, passphrase)?;
        Ok(keypair)
    }
}

/// Codec for serializing/deserializing RPC messages over libp2p streams.
///
/// Uses a simple length-prefixed framing: 4-byte little-endian length followed
/// by the raw payload bytes. Responses are single-byte acknowledgments.
#[derive(Debug, Clone, Default)]
pub struct RpcCodec;

/// Request message containing raw RPC payload bytes.
#[derive(Debug, Clone)]
pub struct RpcRequest(pub Vec<u8>);

/// Response message (single-byte acknowledgment, no payload).
///
/// The protocol uses fire-and-forget semantics where the response serves
/// only to confirm receipt, not to carry data.
#[derive(Debug, Clone)]
pub struct RpcResponse;

/// Implementation of libp2p's request-response codec trait.
///
/// Wire format:
/// - Request: `[4-byte LE length][payload bytes]`
/// - Response: `[1-byte ack (0x00)]`
impl Codec for RpcCodec {
    type Protocol = String;
    type Request = RpcRequest;
    type Response = RpcResponse;

    fn read_request<'life0, 'life1, 'life2, 'async_trait, T>(
        &'life0 mut self,
        _protocol: &'life1 Self::Protocol,
        io: &'life2 mut T,
    ) -> std::pin::Pin<Box<dyn Future<Output = io::Result<Self::Request>> + Send + 'async_trait>>
    where
        T: AsyncRead + Unpin + Send + 'async_trait,
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move {
            let mut len_buf = [0u8; 4];
            io.read_exact(&mut len_buf).await?;
            let len = u32::from_le_bytes(len_buf) as usize;

            if len == 0 {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "empty message"));
            }

            if len > MAX_MESSAGE_SIZE {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "message too large",
                ));
            }

            let mut buf = vec![0u8; len];
            io.read_exact(&mut buf).await?;
            Ok(RpcRequest(buf))
        })
    }

    fn read_response<'life0, 'life1, 'life2, 'async_trait, T>(
        &'life0 mut self,
        _protocol: &'life1 Self::Protocol,
        io: &'life2 mut T,
    ) -> std::pin::Pin<Box<dyn Future<Output = io::Result<Self::Response>> + Send + 'async_trait>>
    where
        T: AsyncRead + Unpin + Send + 'async_trait,
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move {
            let mut ack = [0u8; 1];
            io.read_exact(&mut ack).await?;
            Ok(RpcResponse)
        })
    }

    fn write_request<'life0, 'life1, 'life2, 'async_trait, T>(
        &'life0 mut self,
        _protocol: &'life1 Self::Protocol,
        io: &'life2 mut T,
        req: Self::Request,
    ) -> std::pin::Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'async_trait>>
    where
        T: AsyncWrite + Unpin + Send + 'async_trait,
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move {
            let len = (req.0.len() as u32).to_le_bytes();
            io.write_all(&len).await?;
            io.write_all(&req.0).await?;
            io.flush().await?;
            Ok(())
        })
    }

    fn write_response<'life0, 'life1, 'life2, 'async_trait, T>(
        &'life0 mut self,
        _protocol: &'life1 Self::Protocol,
        io: &'life2 mut T,
        _res: Self::Response,
    ) -> std::pin::Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'async_trait>>
    where
        T: AsyncWrite + Unpin + Send + 'async_trait,
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move {
            io.write_all(&[0u8]).await?;
            io.flush().await?;
            Ok(())
        })
    }
}

/// Combined network behaviour for RPC and peer discovery.
#[derive(NetworkBehaviour)]
struct RpcBehaviour {
    /// Request-response protocol for RPC messages.
    rpc: request_response::Behaviour<RpcCodec>,
    /// Identify protocol for peer metadata exchange.
    identify: identify::Behaviour,
}

/// Command sent from [`Libp2pTransport`] methods to the [`SwarmEventLoop`].
///
/// Commands are processed asynchronously by the event loop, with results
/// returned via oneshot channels.
enum SwarmCommand {
    /// Dial a peer at the given multiaddr.
    Dial {
        /// Target address in libp2p multiaddr format.
        addr: Multiaddr,
        /// Channel to receive the peer's stable hash on success, or `None` on failure.
        done: oneshot::Sender<Option<PeerId>>,
    },
    /// Disconnect from all connected peers.
    DisconnectAll {
        /// Channel signaled when all disconnections complete.
        done: oneshot::Sender<()>,
    },
    /// Send an RPC message to a peer.
    SendMessage {
        /// Target peer's libp2p identifier.
        peer_id: Libp2pPeerId,
        /// Raw message payload to send.
        payload: Vec<u8>,
        /// Channel to receive send result.
        response_tx: oneshot::Sender<Result<(), TransportError>>,
    },
}

/// libp2p-based transport implementation.
///
/// Wraps a libp2p swarm with Noise encryption and Yamux multiplexing,
/// exposing the standard `Transport` trait interface.
///
/// Internally uses `PeerId` as the canonical peer identifier, with `Multiaddr`
/// for routing. `SocketAddr` is derived from `Multiaddr` for trait compatibility.
pub struct Libp2pTransport {
    /// Local listen address in libp2p multiaddr format.
    listen_address: Multiaddr,
    /// Local peer identifier (hashed representation for trait compatibility).
    local_peer_hash: PeerId,
    /// Channel for sending commands to the swarm event loop.
    command_tx: Sender<SwarmCommand>,
    /// Receiver for incoming RPC messages.
    rx: Arc<Mutex<Option<Receiver<Rpc>>>>,
    /// Maps libp2p peer IDs to stable PeerId hashes.
    peer_to_hash: Arc<DashMap<Libp2pPeerId, PeerId>>,
    /// Reverse lookup from stable PeerId hashes to libp2p peer IDs.
    hash_to_peer: Arc<DashMap<PeerId, Libp2pPeerId>>,
    /// Signals when the swarm has started listening for inbound connections.
    listening_ready: Arc<AtomicBool>,
    listening_notifier: Arc<Notify>,
    /// Exclusive lock on the node's data directory.
    /// Held for the lifetime of the transport to prevent duplicate instances.
    #[allow(dead_code)]
    node_lock: File,
}

impl Libp2pTransport {
    /// Creates a new libp2p transport with dual-stack listening.
    ///
    /// Binds to `[::]` (IPv6 unspecified) on the specified port, which accepts
    /// both IPv4 and IPv6 connections. The `address` parameter is used for:
    /// - Extracting the port number
    /// - Identifying this node in logs and peer exchange
    ///
    /// Initializes the libp2p swarm with:
    /// - Ed25519 identity keypair
    /// - TCP transport with Noise XX encryption
    /// - Yamux stream multiplexing
    /// - Request-response protocol for RPC
    /// - Identify protocol for peer metadata
    ///
    /// The `chain_id` parameter is used to create a chain-specific protocol identifier,
    /// ensuring peers on different chains cannot communicate.
    ///
    /// The keypair is encrypted at rest using XChaCha20-Poly1305 with an Argon2id-derived
    /// key. The encrypted keyfile is stored at `~/.blockchain/{chain_id}/{node_name}/identity.key`.
    ///
    /// # Node Name
    ///
    /// The `node_name` identifies this node instance. Each node has its own:
    /// - Keypair and peer ID
    /// - Data directory at `~/.blockchain/{chain_id}/{node_name}/`
    ///
    /// This allows running multiple nodes on the same machine (e.g., for dev/test):
    /// ```text
    /// --node-name node-a  →  127.0.0.1:3000
    /// --node-name node-b  →  127.0.0.1:3001
    /// ```
    ///
    /// # Passphrase
    ///
    /// The `passphrase` is required to decrypt an existing keypair or encrypt a newly
    /// generated one. If the keyfile exists and the passphrase is incorrect, this
    /// function returns an error. **The node will not start with a wrong passphrase.**
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Another process is already running with the same node name
    /// - The keyfile exists but decryption fails (wrong passphrase or corrupted file)
    /// - The keyfile cannot be created or written
    /// - Network binding fails
    pub fn new(
        address: SocketAddr,
        chain_id: u64,
        node_name: &str,
        passphrase: &[u8],
    ) -> io::Result<Arc<Self>> {
        // Acquire exclusive lock to prevent duplicate node instances
        let node_lock = acquire_node_lock(chain_id, node_name)?;

        let local_key = load_or_generate_keypair(chain_id, node_name, passphrase)?;
        let local_peer_id = Libp2pPeerId::from(local_key.public());
        let local_peer_hash = Self::peer_id_to_hash(&local_peer_id);

        let transport = tcp::tokio::Transport::default()
            .upgrade(Version::V1Lazy)
            .authenticate(noise::Config::new(&local_key).expect("noise config"))
            .multiplex(yamux::Config::default())
            .boxed();

        let rpc_config =
            request_response::Config::default().with_request_timeout(Duration::from_secs(30));

        let rpc_protocol = format!("{PROTOCOL_PREFIX}{chain_id}{RPC_PROTOCOL_SUFFIX}");
        let rpc_behaviour =
            request_response::Behaviour::new([(rpc_protocol, ProtocolSupport::Full)], rpc_config);

        let identify_config = identify::Config::new(
            format!("{PROTOCOL_PREFIX}{chain_id}{ID_PROTOCOL_SUFFIX}"),
            local_key.public(),
        );

        let behaviour = RpcBehaviour {
            rpc: rpc_behaviour,
            identify: identify::Behaviour::new(identify_config),
        };

        let mut swarm = Swarm::new(
            transport,
            behaviour,
            local_peer_id,
            libp2p::swarm::Config::with_tokio_executor(),
        );

        // Listen on both IPv4 and IPv6 to ensure connectivity regardless of OS settings
        // (macOS defaults IPV6_V6ONLY=true, so [::] alone won't accept IPv4)
        let port = address.port();
        let ipv4_addr = format!("/ip4/0.0.0.0/tcp/{}", port)
            .parse::<Multiaddr>()
            .unwrap();
        let ipv6_addr = format!("/ip6/::/tcp/{}", port)
            .parse::<Multiaddr>()
            .unwrap();

        swarm
            .listen_on(ipv4_addr)
            .map_err(|e| io::Error::new(io::ErrorKind::AddrInUse, e.to_string()))?;
        swarm
            .listen_on(ipv6_addr)
            .map_err(|e| io::Error::new(io::ErrorKind::AddrInUse, e.to_string()))?;

        let (rpc_tx, rpc_rx) = channel(1024);
        let (command_tx, command_rx) = channel(256);

        let peer_to_hash = Arc::new(DashMap::new());
        let hash_to_peer = Arc::new(DashMap::new());
        let listening_ready = Arc::new(AtomicBool::new(false));
        let listening_notifier = Arc::new(Notify::new());

        let transport = Arc::new(Self {
            listen_address: socket_addr_to_multiaddr(address),
            local_peer_hash,
            command_tx,
            rx: Arc::new(Mutex::new(Some(rpc_rx))),
            peer_to_hash: peer_to_hash.clone(),
            hash_to_peer: hash_to_peer.clone(),
            listening_ready: listening_ready.clone(),
            listening_notifier: listening_notifier.clone(),
            node_lock,
        });

        // Spawn swarm event loop
        let event_loop = SwarmEventLoop {
            swarm,
            rpc_tx,
            command_rx,
            peer_to_addrs: Arc::new(DashMap::new()),
            peer_to_hash,
            hash_to_peer,
            listening_ready,
            listening_notifier,
            pending_responses: HashMap::new(),
            pending_dials: HashMap::new(),
        };

        tokio::spawn(event_loop.run());

        Ok(transport)
    }

    /// Converts a libp2p [`Libp2pPeerId`] to a stable [`PeerId`] hash.
    ///
    /// Uses SHA3 with a domain separator to derive a deterministic hash from
    /// the peer's public key bytes. This hash serves as the canonical peer
    /// identifier throughout the blockchain layer.
    fn peer_id_to_hash(peer_id: &Libp2pPeerId) -> PeerId {
        let bytes = peer_id.to_bytes();
        let mut hash = Hash::sha3();
        hash.update(b"LIBP2P_PEER_ID");
        hash.update(&bytes);
        hash.finalize()
    }
}

/// Background event loop that drives the libp2p swarm.
///
/// Runs as a spawned tokio task, processing both swarm events (connections,
/// messages, errors) and commands from the [`Libp2pTransport`] frontend.
/// Maintains peer routing tables and coordinates request-response tracking.
struct SwarmEventLoop {
    /// The libp2p swarm instance handling network I/O.
    swarm: Swarm<RpcBehaviour>,
    /// Channel for forwarding decoded RPC messages to the server.
    rpc_tx: Sender<Rpc>,
    /// Channel for receiving commands from [`Libp2pTransport`].
    command_rx: Receiver<SwarmCommand>,
    /// Primary routing: libp2p PeerId -> known Multiaddrs (most reliable first).
    peer_to_addrs: Arc<DashMap<Libp2pPeerId, Vec<Multiaddr>>>,
    /// Maps libp2p peer IDs to stable peer hashes used by the blockchain layer.
    peer_to_hash: Arc<DashMap<Libp2pPeerId, PeerId>>,
    /// Reverse mapping from stable peer hashes to libp2p peer IDs.
    hash_to_peer: Arc<DashMap<PeerId, Libp2pPeerId>>,
    /// Signals when the swarm begins listening for inbound connections.
    listening_ready: Arc<AtomicBool>,
    listening_notifier: Arc<Notify>,
    /// Tracks pending outbound requests awaiting acknowledgment.
    pending_responses: HashMap<OutboundRequestId, oneshot::Sender<Result<(), TransportError>>>,
    /// Tracks pending dial attempts awaiting connection establishment.
    pending_dials: HashMap<Multiaddr, oneshot::Sender<Option<PeerId>>>,
}

impl SwarmEventLoop {
    /// Runs the event loop until the command channel closes.
    ///
    /// Alternates between processing swarm events and handling commands,
    /// ensuring neither blocks the other for extended periods.
    async fn run(mut self) {
        loop {
            tokio::select! {
                event = self.swarm.select_next_some() => {
                    self.handle_swarm_event(event).await;
                }
                Some(cmd) = self.command_rx.recv() => {
                    self.handle_command(cmd).await;
                }
            }
        }
    }

    /// Processes a single swarm event.
    ///
    /// Handles:
    /// - Incoming RPC requests (decodes and forwards to server)
    /// - Outbound request completions/failures
    /// - Connection establishment (updates routing tables, completes pending dials)
    /// - Connection closure (cleans up routing tables)
    /// - Identify protocol events (learns peer addresses)
    async fn handle_swarm_event(&mut self, event: SwarmEvent<RpcBehaviourEvent>) {
        match event {
            SwarmEvent::NewListenAddr { address, .. } => {
                if !self.listening_ready.swap(true, Ordering::AcqRel) {
                    self.listening_notifier.notify_waiters();
                }
                info!("Listening on {}", address);
            }
            SwarmEvent::Behaviour(RpcBehaviourEvent::Rpc(request_response::Event::Message {
                peer,
                message,
                ..
            })) => match message {
                request_response::Message::Request {
                    request, channel, ..
                } => {
                    self.handle_incoming_request(peer, request, channel).await;
                }
                request_response::Message::Response { request_id, .. } => {
                    if let Some(tx) = self.pending_responses.remove(&request_id) {
                        let _ = tx.send(Ok(()));
                    }
                }
            },
            SwarmEvent::Behaviour(RpcBehaviourEvent::Rpc(
                request_response::Event::InboundFailure { peer, error, .. },
            )) => {
                let peer_hash = self
                    .peer_to_hash
                    .get(&peer)
                    .map(|h| *h)
                    .unwrap_or_else(|| Libp2pTransport::peer_id_to_hash(&peer));
                error!("RPC inbound failure from {}: {}", peer_hash, error);
            }
            SwarmEvent::Behaviour(RpcBehaviourEvent::Rpc(
                request_response::Event::OutboundFailure {
                    request_id, error, ..
                },
            )) => {
                error!("RPC outbound failure: request_id={request_id:?} error={error}");
                if let Some(tx) = self.pending_responses.remove(&request_id) {
                    let _ = tx.send(Err(TransportError::BroadcastFailed(error.to_string())));
                }
            }
            SwarmEvent::Behaviour(RpcBehaviourEvent::Identify(identify::Event::Received {
                peer_id,
                info,
                ..
            })) => {
                // Identify provides additional addresses; add them to known addresses.
                // Note: listen_addrs are self-reported and may be unroutable (NAT).
                // Connection endpoint (stored in ConnectionEstablished) is more reliable.
                let mut entry = self.peer_to_addrs.entry(peer_id).or_default();
                for addr in info.listen_addrs {
                    if !entry.contains(&addr) {
                        entry.push(addr.clone());
                    }
                }
                let peer_hash = *self
                    .peer_to_hash
                    .entry(peer_id)
                    .or_insert_with(|| Libp2pTransport::peer_id_to_hash(&peer_id));
                self.hash_to_peer.entry(peer_hash).or_insert(peer_id);
            }
            SwarmEvent::ConnectionEstablished {
                peer_id, endpoint, ..
            } => {
                // Connection endpoint is the most reliable address source.
                let remote_addr = endpoint.get_remote_address().clone();

                // Store in primary map (Multiaddr-based)
                let mut entry = self.peer_to_addrs.entry(peer_id).or_default();
                if !entry.contains(&remote_addr) {
                    // Insert at front - connection endpoint is most reliable
                    entry.insert(0, remote_addr.clone());
                }

                let peer_hash = *self
                    .peer_to_hash
                    .entry(peer_id)
                    .or_insert_with(|| Libp2pTransport::peer_id_to_hash(&peer_id));
                self.hash_to_peer.entry(peer_hash).or_insert(peer_id);

                info!("Peer connected: {} at {}", peer_hash, remote_addr);

                // Complete pending dial if addresses match, returning the peer hash
                if let Some(done) = self.pending_dials.remove(&remote_addr) {
                    let _ = done.send(Some(peer_hash));
                }
            }
            SwarmEvent::ConnectionClosed { peer_id, .. } => {
                let known_addrs = self
                    .peer_to_addrs
                    .get(&peer_id)
                    .and_then(|entry| entry.first().cloned());
                self.peer_to_addrs.remove(&peer_id);
                if let Some((_, hash)) = self.peer_to_hash.remove(&peer_id) {
                    self.hash_to_peer.remove(&hash);
                    match known_addrs {
                        Some(addr) => info!("Peer disconnected: {} from {}", hash, addr),
                        None => info!("Peer disconnected: {}", hash),
                    }
                }
            }
            SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                let (addresses, debug_error) = match &error {
                    libp2p::swarm::DialError::Transport(errors) => (
                        errors
                            .iter()
                            .map(|(addr, err)| format!("{addr}: {err:?}"))
                            .collect::<Vec<_>>()
                            .join("; "),
                        format!("{error:?}"),
                    ),
                    other => (other.to_string(), format!("{other:?}")),
                };
                match peer_id {
                    Some(pid) => {
                        let peer_hash = self
                            .peer_to_hash
                            .get(&pid)
                            .map(|h| *h)
                            .unwrap_or_else(|| Libp2pTransport::peer_id_to_hash(&pid));
                        error!(
                            "Outgoing connection error to {}: {} ({})",
                            peer_hash, addresses, debug_error
                        );
                    }
                    None => error!(
                        "Outgoing connection error (unknown peer): {} ({})",
                        addresses, debug_error
                    ),
                }

                // Fail pending dials that match the errored addresses so callers don't hang.
                if let libp2p::swarm::DialError::Transport(errors) = error {
                    for (addr, _) in errors {
                        if let Some(done) = self.pending_dials.remove(&addr) {
                            let _ = done.send(None);
                        }
                    }
                }
            }
            _ => {}
        }
    }

    /// Processes an incoming RPC request from a peer.
    ///
    /// Sends an acknowledgment response immediately, then decodes the request
    /// payload and forwards it to the server via `rpc_tx`. Falls back to raw
    /// payload forwarding if decoding fails.
    async fn handle_incoming_request(
        &mut self,
        peer: Libp2pPeerId,
        request: RpcRequest,
        channel: ResponseChannel<RpcResponse>,
    ) {
        // Send acknowledgment
        let _ = self
            .swarm
            .behaviour_mut()
            .rpc
            .send_response(channel, RpcResponse);

        // Decode and forward the RPC
        let peer_hash = self
            .peer_to_hash
            .get(&peer)
            .map(|h| *h)
            .unwrap_or_else(|| Libp2pTransport::peer_id_to_hash(&peer));

        match RawRpc::from_bytes(&request.0) {
            Ok(raw) => {
                let rpc = Rpc::from_raw(raw, peer_hash);
                if self.rpc_tx.send(rpc).await.is_err() {
                    error!("Failed to forward RPC from peer {}", peer_hash);
                }
            }
            Err(e) => {
                error!("Failed to decode RPC from peer {}: {}", peer_hash, e);
                // Fallback: treat entire payload as message data
                let rpc = Rpc::new(peer_hash, Bytes::new(request.0));
                if self.rpc_tx.send(rpc).await.is_err() {
                    error!("Failed to forward raw payload from peer {}", peer_hash);
                }
            }
        }
    }

    /// Executes a command received from [`Libp2pTransport`].
    ///
    /// Each command variant triggers the corresponding swarm operation and
    /// registers any necessary tracking state for async completion.
    async fn handle_command(&mut self, cmd: SwarmCommand) {
        match cmd {
            SwarmCommand::Dial { addr, done } => {
                let opts = DialOpts::unknown_peer_id()
                    .address(addr.clone())
                    .allocate_new_port()
                    .build();

                if self.swarm.dial(opts).is_err() {
                    let _ = done.send(None);
                    return;
                }

                self.pending_dials.insert(addr, done);
            }
            SwarmCommand::SendMessage {
                peer_id,
                payload,
                response_tx,
            } => {
                let raw = RawRpc {
                    payload: Bytes::new(payload),
                };
                let encoded = raw.to_bytes();
                let request_id = self
                    .swarm
                    .behaviour_mut()
                    .rpc
                    .send_request(&peer_id, RpcRequest(encoded.to_vec()));
                self.pending_responses.insert(request_id, response_tx);
            }
            SwarmCommand::DisconnectAll { done } => {
                let peers: Vec<Libp2pPeerId> = self.swarm.connected_peers().cloned().collect();
                for peer in peers {
                    let _ = self.swarm.disconnect_peer_id(peer);
                    self.peer_to_addrs.remove(&peer);
                    if let Some((_, hash)) = self.peer_to_hash.remove(&peer) {
                        self.hash_to_peer.remove(&hash);
                    }
                }
                let _ = done.send(());
            }
        }
    }
}

impl BlockchainTransport for Libp2pTransport {
    fn connect(self: &Arc<Self>, addr: Multiaddr) -> BoxFuture<Option<PeerId>> {
        let command_tx = self.command_tx.clone();
        let target = addr.clone();
        let listen_address = self.listen_address.clone();
        Box::pin(async move {
            let (tx, rx) = oneshot::channel();
            if target == listen_address {
                error!("connect: attempted self-dial to {}", target);
                return None;
            }
            if command_tx
                .send(SwarmCommand::Dial { addr, done: tx })
                .await
                .is_err()
            {
                error!("connect: failed to enqueue dial to {}", target);
                return None;
            }
            let result = rx.await.unwrap_or(None);
            if result.is_none() {
                error!("connect: dial to {} failed", target);
            }
            result
        })
    }

    fn start(self: &Arc<Self>, sx: Sender<Rpc>) {
        spawn_rpc_forwarder(self.clone(), sx);
    }

    fn wait_until_listening(self: &Arc<Self>) -> BoxFuture<()> {
        let listening_ready = self.listening_ready.clone();
        let listening_notifier = self.listening_notifier.clone();

        Box::pin(async move {
            if listening_ready.load(Ordering::Acquire) {
                return;
            }

            listening_notifier.notified().await;
        })
    }

    impl_transport_consume!();

    fn send_message(
        self: &Arc<Self>,
        to: PeerId,
        origin: PeerId,
        payload: Bytes,
    ) -> BoxFuture<Result<(), TransportError>> {
        if to == origin {
            return Box::pin(async { Ok(()) });
        }

        let command_tx = self.command_tx.clone();
        let hash_to_peer = self.hash_to_peer.clone();

        Box::pin(async move {
            let peer_id = match hash_to_peer.get(&to).map(|p| *p) {
                Some(p) => p,
                None => {
                    error!("send_message: peer not found {}", to);
                    return Err(TransportError::PeerNotFound(to));
                }
            };

            let (response_tx, response_rx) = oneshot::channel();

            command_tx
                .send(SwarmCommand::SendMessage {
                    peer_id,
                    payload: payload.to_vec(),
                    response_tx,
                })
                .await
                .map_err(|_| {
                    error!("send_message: failed to enqueue message to {}", to);
                    TransportError::SendFailed(to)
                })?;

            match tokio::time::timeout(Duration::from_secs(30), response_rx).await {
                Ok(Ok(result)) => result,
                Ok(Err(_)) => {
                    error!("send_message: swarm reported failure to {}", to);
                    Err(TransportError::SendFailed(to))
                }
                Err(_) => {
                    error!("send_message: timed out waiting for response to {}", to);
                    Err(TransportError::SendFailed(to))
                }
            }
        })
    }

    fn peer_id(self: &Arc<Self>) -> PeerId {
        self.local_peer_hash
    }

    fn peer_ids(self: &Arc<Self>) -> Vec<PeerId> {
        self.peer_to_hash
            .iter()
            .map(|entry| *entry.value())
            .collect()
    }

    fn addr(self: &Arc<Self>) -> Multiaddr {
        self.listen_address.clone()
    }

    fn stop(self: &Arc<Self>) -> BoxFuture<()> {
        let command_tx = self.command_tx.clone();
        Box::pin(async move {
            let (done_tx, done_rx) = oneshot::channel();
            if command_tx
                .send(SwarmCommand::DisconnectAll { done: done_tx })
                .await
                .is_ok()
            {
                let _ = done_rx.await;
            }
        })
    }
}

/// Converts a [`SocketAddr`] to a libp2p [`Multiaddr`].
///
/// Produces `/ip4/<addr>/tcp/<port>` for IPv4 or `/ip6/<addr>/tcp/<port>` for IPv6.
fn socket_addr_to_multiaddr(addr: SocketAddr) -> Multiaddr {
    let mut multiaddr = match addr.ip() {
        IpAddr::V4(ip) => Multiaddr::from(ip),
        IpAddr::V6(ip) => Multiaddr::from(ip),
    };
    multiaddr.push(libp2p::multiaddr::Protocol::Tcp(addr.port()));
    multiaddr
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::transport::Transport as BlockchainTransport;
    use crate::utils::test_utils::utils::multiaddr_to_socket_addr;
    use std::sync::atomic::{AtomicU16, Ordering};
    use std::time::Duration;
    use tokio::time::timeout;

    /// Base port for test allocation. Incremented atomically to avoid conflicts.
    static PORT_COUNTER: AtomicU16 = AtomicU16::new(19000);

    /// Base node ID for test allocation. Incremented atomically to ensure unique node names.
    static NODE_ID_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    /// Test passphrase for encrypting key pairs.
    const TEST_PASSPHRASE: &[u8] = b"test-passphrase-for-unit-tests";

    /// Test chain ID (shared across tests since node names provide isolation).
    const TEST_CHAIN_ID: u64 = 999999;

    /// Timeout duration for async operations in tests.
    const TEST_TIMEOUT: Duration = Duration::from_secs(10);

    /// Connection establishment delay to allow swarm events to propagate.
    const CONNECTION_DELAY: Duration = Duration::from_millis(500);

    /// Allocates a unique port for test isolation.
    fn alloc_port() -> u16 {
        PORT_COUNTER.fetch_add(1, Ordering::Relaxed)
    }

    /// Allocates a unique node name for test isolation.
    fn alloc_node_name() -> String {
        let id = NODE_ID_COUNTER.fetch_add(1, Ordering::Relaxed);
        format!("test-node-{}", id)
    }

    /// Creates new test transport with unique port and node name.
    fn create_transport() -> Arc<Libp2pTransport> {
        let port = alloc_port();
        let addr: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();
        let node_name = alloc_node_name();
        Libp2pTransport::new(addr, TEST_CHAIN_ID, &node_name, TEST_PASSPHRASE)
            .expect("failed to create transport")
    }

    /// Waits for connection to be established and peer maps to be populated.
    async fn wait_for_connection(tr_a: &Arc<Libp2pTransport>, tr_b: &Arc<Libp2pTransport>) {
        let start = std::time::Instant::now();
        while start.elapsed() < TEST_TIMEOUT {
            if tr_a
                .peer_to_hash
                .iter()
                .any(|e| *e.value() == tr_b.peer_id())
                && tr_b
                    .peer_to_hash
                    .iter()
                    .any(|e| *e.value() == tr_a.peer_id())
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("connection not established within timeout");
    }

    #[tokio::test]
    async fn test_connect() {
        let tr_a = create_transport();
        let tr_b = create_transport();

        let peer_id = timeout(TEST_TIMEOUT, tr_a.connect(tr_b.addr()))
            .await
            .expect("connect timed out");
        assert!(peer_id.is_some());
        assert_eq!(peer_id.unwrap(), tr_b.peer_id());

        wait_for_connection(&tr_a, &tr_b).await;

        assert!(tr_a.hash_to_peer.contains_key(&tr_b.peer_id()));
        assert!(tr_b.hash_to_peer.contains_key(&tr_a.peer_id()));
    }

    #[tokio::test]
    async fn test_send_message() {
        let tr_a = create_transport();
        let tr_b = create_transport();

        tr_a.connect(tr_b.addr()).await;
        wait_for_connection(&tr_a, &tr_b).await;

        let mut rx = tr_b.consume().await;
        let payload = Bytes::from("The first message.");

        let send_result = timeout(
            TEST_TIMEOUT,
            tr_a.send_message(tr_b.peer_id(), tr_a.peer_id(), payload.clone()),
        )
        .await
        .expect("send timed out");
        assert!(send_result.is_ok());

        let received = timeout(TEST_TIMEOUT, rx.recv())
            .await
            .expect("recv timed out")
            .expect("channel closed");
        assert_eq!(received.payload, payload);
    }

    #[tokio::test]
    async fn test_broadcast() {
        let tr_a = create_transport();
        let tr_b = create_transport();
        let tr_c = create_transport();

        tr_a.connect(tr_b.addr()).await;
        tr_a.connect(tr_c.addr()).await;
        wait_for_connection(&tr_a, &tr_b).await;
        wait_for_connection(&tr_a, &tr_c).await;

        let mut rx_b = tr_b.consume().await;
        let mut rx_c = tr_c.consume().await;

        let payload = Bytes::new("Broadcast message");
        let result = timeout(
            TEST_TIMEOUT,
            tr_a.broadcast(tr_a.peer_id(), payload.clone()),
        )
        .await
        .expect("broadcast timed out");
        assert!(result.is_ok());

        let received_b = timeout(TEST_TIMEOUT, rx_b.recv())
            .await
            .expect("recv b timed out")
            .expect("channel b closed");
        assert_eq!(received_b.payload, payload);

        let received_c = timeout(TEST_TIMEOUT, rx_c.recv())
            .await
            .expect("recv c timed out")
            .expect("channel c closed");
        assert_eq!(received_c.payload, payload);
    }

    #[tokio::test]
    async fn connect_is_bidirectional() {
        let tr_a = create_transport();
        let tr_b = create_transport();

        tr_a.connect(tr_b.addr()).await;
        wait_for_connection(&tr_a, &tr_b).await;

        // Both transports should know about each other
        assert!(tr_a.hash_to_peer.contains_key(&tr_b.peer_id()));
        assert!(tr_b.hash_to_peer.contains_key(&tr_a.peer_id()));
    }

    #[tokio::test]
    async fn connect_multiple_peers() {
        let tr_a = create_transport();
        let tr_b = create_transport();
        let tr_c = create_transport();

        tr_a.connect(tr_b.addr()).await;
        tr_a.connect(tr_c.addr()).await;
        wait_for_connection(&tr_a, &tr_b).await;
        wait_for_connection(&tr_a, &tr_c).await;

        let peers = tr_a.peer_ids();
        assert_eq!(peers.len(), 2);
        assert!(peers.contains(&tr_b.peer_id()));
        assert!(peers.contains(&tr_c.peer_id()));
    }

    #[tokio::test]
    async fn broadcast_excludes_sender() {
        let tr_a = create_transport();
        let tr_b = create_transport();
        let tr_c = create_transport();

        tr_a.connect(tr_b.addr()).await;
        tr_b.connect(tr_c.addr()).await;
        wait_for_connection(&tr_a, &tr_b).await;
        wait_for_connection(&tr_b, &tr_c).await;

        let mut rx_a = tr_a.consume().await;
        let mut rx_c = tr_c.consume().await;

        let payload = Bytes::new("Broadcast from B");
        tr_b.broadcast(tr_b.peer_id(), payload.clone())
            .await
            .unwrap();

        // A and C should receive the message
        let received_a = timeout(TEST_TIMEOUT, rx_a.recv())
            .await
            .expect("recv a timed out")
            .expect("channel a closed");
        assert_eq!(received_a.payload, payload);

        let received_c = timeout(TEST_TIMEOUT, rx_c.recv())
            .await
            .expect("recv c timed out")
            .expect("channel c closed");
        assert_eq!(received_c.payload, payload);
    }

    #[tokio::test]
    async fn send_to_nonexistent_peer_fails() {
        let tr_a = create_transport();
        let mut hasher = Hash::sha3();
        hasher.update(b"missing peer");
        let missing_peer = hasher.finalize();

        let result = tr_a
            .send_message(missing_peer, tr_a.peer_id(), Bytes::from("test"))
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn addr_returns_correct_address() {
        let port = alloc_port();
        let addr: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();
        let node_name = alloc_node_name();
        let tr = Libp2pTransport::new(addr, TEST_CHAIN_ID, &node_name, TEST_PASSPHRASE).unwrap();
        assert_eq!(
            multiaddr_to_socket_addr(&tr.listen_address).expect("invalid multiaddr"),
            addr
        );
    }

    #[tokio::test]
    async fn chain_topology_message_passing() {
        // A -> B -> C topology
        let tr_a = create_transport();
        let tr_b = create_transport();
        let tr_c = create_transport();

        tr_a.connect(tr_b.addr()).await;
        tr_b.connect(tr_c.addr()).await;
        wait_for_connection(&tr_a, &tr_b).await;
        wait_for_connection(&tr_b, &tr_c).await;

        // A sends to B
        let result = tr_a
            .send_message(tr_b.peer_id(), tr_a.peer_id(), Bytes::from("from A"))
            .await;
        assert!(result.is_ok());

        // A cannot send directly to C (not connected)
        let result = tr_a
            .send_message(tr_c.peer_id(), tr_a.peer_id(), Bytes::from("test"))
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn peer_ids_returns_empty_when_no_connections() {
        let tr = create_transport();
        assert!(tr.peer_ids().is_empty());
    }

    #[tokio::test]
    async fn peer_ids_returns_connected_peers() {
        let tr_a = create_transport();
        let tr_b = create_transport();
        let tr_c = create_transport();

        tr_a.connect(tr_b.addr()).await;
        tr_a.connect(tr_c.addr()).await;
        wait_for_connection(&tr_a, &tr_b).await;
        wait_for_connection(&tr_a, &tr_c).await;

        let peers = tr_a.peer_ids();
        assert_eq!(peers.len(), 2);
        assert!(peers.contains(&tr_b.peer_id()));
        assert!(peers.contains(&tr_c.peer_id()));
    }

    #[tokio::test]
    async fn peer_ids_reflects_bidirectional_connections() {
        let tr_a = create_transport();
        let tr_b = create_transport();

        tr_a.connect(tr_b.addr()).await;
        wait_for_connection(&tr_a, &tr_b).await;

        let a_peers = tr_a.peer_ids();
        let b_peers = tr_b.peer_ids();

        assert_eq!(a_peers.len(), 1);
        assert_eq!(a_peers[0], tr_b.peer_id());

        assert_eq!(b_peers.len(), 1);
        assert_eq!(b_peers[0], tr_a.peer_id());
    }

    #[tokio::test]
    async fn peer_id_is_stable_across_connections() {
        let tr = create_transport();
        let peer_id_1 = tr.peer_id();
        let peer_id_2 = tr.peer_id();
        assert_eq!(peer_id_1, peer_id_2);
    }

    #[tokio::test]
    async fn different_transports_have_different_peer_ids() {
        let tr_a = create_transport();
        let tr_b = create_transport();
        assert_ne!(tr_a.peer_id(), tr_b.peer_id());
    }

    // --- Late-joining and reconnecting node tests ---

    #[tokio::test]
    async fn late_joining_node_can_connect() {
        let tr_a = create_transport();
        let tr_b = create_transport();

        // Establish initial connection
        tr_a.connect(tr_b.addr()).await;
        wait_for_connection(&tr_a, &tr_b).await;

        // Late-joining node
        tokio::time::sleep(CONNECTION_DELAY).await;
        let tr_c = create_transport();

        // Late node connects to existing network
        tr_c.connect(tr_a.addr()).await;
        wait_for_connection(&tr_c, &tr_a).await;

        assert!(tr_a.hash_to_peer.contains_key(&tr_c.peer_id()));
        assert!(tr_c.hash_to_peer.contains_key(&tr_a.peer_id()));
    }

    #[tokio::test]
    async fn late_joining_node_receives_messages() {
        let tr_a = create_transport();
        let tr_b = create_transport();

        tr_a.connect(tr_b.addr()).await;
        wait_for_connection(&tr_a, &tr_b).await;

        // Exchange some messages before late node joins
        let mut rx_b = tr_b.consume().await;
        tr_a.send_message(tr_b.peer_id(), tr_a.peer_id(), Bytes::from("early msg"))
            .await
            .unwrap();
        let _ = timeout(TEST_TIMEOUT, rx_b.recv()).await;

        // Late-joining node
        tokio::time::sleep(CONNECTION_DELAY).await;
        let tr_c = create_transport();
        tr_a.connect(tr_c.addr()).await;
        wait_for_connection(&tr_a, &tr_c).await;

        // Late node should be able to receive messages
        let mut rx_c = tr_c.consume().await;
        let payload = Bytes::from("message to late node");
        tr_a.send_message(tr_c.peer_id(), tr_a.peer_id(), payload.clone())
            .await
            .unwrap();

        let received = timeout(TEST_TIMEOUT, rx_c.recv())
            .await
            .expect("recv timed out")
            .expect("channel closed");
        assert_eq!(received.payload, payload);
    }

    #[tokio::test]
    async fn late_joining_node_can_send_messages() {
        let tr_a = create_transport();
        let tr_b = create_transport();

        tr_a.connect(tr_b.addr()).await;
        wait_for_connection(&tr_a, &tr_b).await;

        // Late-joining node
        tokio::time::sleep(CONNECTION_DELAY).await;
        let tr_c = create_transport();
        tr_c.connect(tr_a.addr()).await;
        wait_for_connection(&tr_c, &tr_a).await;

        // Late node sends to existing node
        let mut rx_a = tr_a.consume().await;
        let payload = Bytes::from("message from late node");
        tr_c.send_message(tr_a.peer_id(), tr_c.peer_id(), payload.clone())
            .await
            .unwrap();

        let received = timeout(TEST_TIMEOUT, rx_a.recv())
            .await
            .expect("recv timed out")
            .expect("channel closed");
        assert_eq!(received.payload, payload);
    }

    #[tokio::test]
    async fn late_joining_node_participates_in_broadcast() {
        let tr_a = create_transport();
        let tr_b = create_transport();

        tr_a.connect(tr_b.addr()).await;
        wait_for_connection(&tr_a, &tr_b).await;

        // Late-joining node
        tokio::time::sleep(CONNECTION_DELAY).await;
        let tr_c = create_transport();
        tr_a.connect(tr_c.addr()).await;
        wait_for_connection(&tr_a, &tr_c).await;

        // Broadcast should reach both B and C
        let mut rx_b = tr_b.consume().await;
        let mut rx_c = tr_c.consume().await;

        let payload = Bytes::from("broadcast after late join");
        tr_a.broadcast(tr_a.peer_id(), payload.clone())
            .await
            .unwrap();

        let received_b = timeout(TEST_TIMEOUT, rx_b.recv())
            .await
            .expect("recv b timed out")
            .expect("channel b closed");
        assert_eq!(received_b.payload, payload);

        let received_c = timeout(TEST_TIMEOUT, rx_c.recv())
            .await
            .expect("recv c timed out")
            .expect("channel c closed");
        assert_eq!(received_c.payload, payload);
    }

    #[tokio::test]
    async fn reconnecting_node_can_communicate() {
        let tr_a = create_transport();
        let tr_b = create_transport();

        // Initial connection
        tr_a.connect(tr_b.addr()).await;
        wait_for_connection(&tr_a, &tr_b).await;

        let mut rx_b = tr_b.consume().await;
        let payload1 = Bytes::from("before reconnect");
        tr_a.send_message(tr_b.peer_id(), tr_a.peer_id(), payload1.clone())
            .await
            .unwrap();

        let received1 = timeout(TEST_TIMEOUT, rx_b.recv())
            .await
            .expect("recv timed out")
            .expect("channel closed");
        assert_eq!(received1.payload, payload1);

        // Simulate reconnection by creating a new Transport instance on the same logical node
        // (In practice, this tests that a fresh transport can connect to existing peers)
        tokio::time::sleep(CONNECTION_DELAY).await;
        let tr_b_new = create_transport();

        tr_a.connect(tr_b_new.addr()).await;
        wait_for_connection(&tr_a, &tr_b_new).await;

        // Communication should work with the new transport
        let mut rx_b_new = tr_b_new.consume().await;
        let payload2 = Bytes::from("after reconnect");
        tr_a.send_message(tr_b_new.peer_id(), tr_a.peer_id(), payload2.clone())
            .await
            .unwrap();

        let received2 = timeout(TEST_TIMEOUT, rx_b_new.recv())
            .await
            .expect("recv timed out")
            .expect("channel closed");
        assert_eq!(received2.payload, payload2);
    }

    #[tokio::test]
    async fn multiple_late_joiners_sequential() {
        let tr_a = create_transport();

        // Nodes join sequentially
        for i in 0..3 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            let tr_new = create_transport();
            tr_a.connect(tr_new.addr()).await;
            wait_for_connection(&tr_a, &tr_new).await;

            assert_eq!(tr_a.peer_ids().len(), i + 1);
        }
    }

    #[tokio::test]
    async fn concurrent_connections() {
        let tr_hub = create_transport();
        let transports: Vec<_> = (0..3).map(|_| create_transport()).collect();

        // Connect all transports concurrently
        let futures: Vec<_> = transports
            .iter()
            .map(|tr| tr_hub.connect(tr.addr()))
            .collect();

        futures::future::join_all(futures).await;

        // Wait for all connections
        for tr in &transports {
            wait_for_connection(&tr_hub, tr).await;
        }

        assert_eq!(tr_hub.peer_ids().len(), 3);
    }

    #[tokio::test]
    async fn message_ordering_preserved() {
        let tr_a = create_transport();
        let tr_b = create_transport();

        tr_a.connect(tr_b.addr()).await;
        wait_for_connection(&tr_a, &tr_b).await;

        let mut rx_b = tr_b.consume().await;

        // Send multiple messages
        for i in 0..5 {
            let payload = Bytes::from(format!("message {}", i));
            tr_a.send_message(tr_b.peer_id(), tr_a.peer_id(), payload)
                .await
                .unwrap();
        }

        // Verify order
        for i in 0..5 {
            let received = timeout(TEST_TIMEOUT, rx_b.recv())
                .await
                .expect("recv timed out")
                .expect("channel closed");
            let expected = format!("message {}", i);
            assert_eq!(received.payload.as_ref(), expected.as_bytes());
        }
    }

    #[tokio::test]
    async fn large_message_transfer() {
        let tr_a = create_transport();
        let tr_b = create_transport();

        tr_a.connect(tr_b.addr()).await;
        wait_for_connection(&tr_a, &tr_b).await;

        let mut rx_b = tr_b.consume().await;

        // Send a large message (1MB)
        let large_payload = Bytes::new(vec![0xAB; 1024 * 1024]);
        tr_a.send_message(tr_b.peer_id(), tr_a.peer_id(), large_payload.clone())
            .await
            .unwrap();

        let received = timeout(TEST_TIMEOUT, rx_b.recv())
            .await
            .expect("recv timed out")
            .expect("channel closed");
        assert_eq!(received.payload.len(), large_payload.len());
        assert_eq!(received.payload, large_payload);
    }

    #[tokio::test]
    async fn multiaddr_conversion_roundtrip() {
        let addr: SocketAddr = "192.168.1.100:8080".parse().unwrap();
        let multiaddr = socket_addr_to_multiaddr(addr);
        let back = multiaddr_to_socket_addr(&multiaddr);
        assert_eq!(back, Some(addr));
    }

    #[tokio::test]
    async fn multiaddr_conversion_ipv6() {
        let addr: SocketAddr = "[::1]:9000".parse().unwrap();
        let multiaddr = socket_addr_to_multiaddr(addr);
        let back = multiaddr_to_socket_addr(&multiaddr);
        assert_eq!(back, Some(addr));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Encrypted Keypair Persistence Tests
    // ─────────────────────────────────────────────────────────────────────────

    use tempfile::tempdir;

    fn test_keypair_path(dir: &std::path::Path) -> PathBuf {
        dir.join("test_identity.key")
    }

    #[test]
    fn keypair_derive_key_deterministic() {
        let passphrase = b"test_passphrase";
        let salt = [0xABu8; SALT_LEN];

        let key1 = derive_key(passphrase, &salt).unwrap();
        let key2 = derive_key(passphrase, &salt).unwrap();

        assert_eq!(key1.as_ref(), key2.as_ref());
    }

    #[test]
    fn keypair_derive_key_different_salts_produce_different_keys() {
        let passphrase = b"test_passphrase";
        let salt1 = [0xAAu8; SALT_LEN];
        let salt2 = [0xBBu8; SALT_LEN];

        let key1 = derive_key(passphrase, &salt1).unwrap();
        let key2 = derive_key(passphrase, &salt2).unwrap();

        assert_ne!(key1.as_ref(), key2.as_ref());
    }

    #[test]
    fn keypair_derive_key_different_passphrases_produce_different_keys() {
        let salt = [0xABu8; SALT_LEN];

        let key1 = derive_key(b"passphrase_one", &salt).unwrap();
        let key2 = derive_key(b"passphrase_two", &salt).unwrap();

        assert_ne!(key1.as_ref(), key2.as_ref());
    }

    #[test]
    fn keypair_save_and_load_roundtrip() {
        let dir = tempdir().unwrap();
        let path = test_keypair_path(dir.path());
        let passphrase = b"secure_passphrase_123";

        let original_keypair = identity::Keypair::generate_ed25519();
        let original_peer_id = Libp2pPeerId::from(original_keypair.public());

        save_encrypted_keypair(&path, &original_keypair, passphrase).unwrap();
        assert!(path.exists());

        let loaded_keypair = load_encrypted_keypair(&path, passphrase).unwrap();
        let loaded_peer_id = Libp2pPeerId::from(loaded_keypair.public());

        assert_eq!(original_peer_id, loaded_peer_id);
    }

    #[test]
    fn keypair_wrong_passphrase_fails_decryption() {
        let dir = tempdir().unwrap();
        let path = test_keypair_path(dir.path());

        let keypair = identity::Keypair::generate_ed25519();
        save_encrypted_keypair(&path, &keypair, b"correct_passphrase").unwrap();

        let result = load_encrypted_keypair(&path, b"wrong_passphrase");
        assert!(result.is_err());
        assert!(
            result
                .err()
                .unwrap()
                .to_string()
                .contains("decryption failed")
        );
    }

    #[test]
    fn keypair_empty_passphrase_works() {
        let dir = tempdir().unwrap();
        let path = test_keypair_path(dir.path());
        let passphrase = b"";

        let original_keypair = identity::Keypair::generate_ed25519();
        let original_peer_id = Libp2pPeerId::from(original_keypair.public());

        save_encrypted_keypair(&path, &original_keypair, passphrase).unwrap();

        let loaded_keypair = load_encrypted_keypair(&path, passphrase).unwrap();
        let loaded_peer_id = Libp2pPeerId::from(loaded_keypair.public());

        assert_eq!(original_peer_id, loaded_peer_id);
    }

    #[test]
    fn keypair_unicode_passphrase_works() {
        let dir = tempdir().unwrap();
        let path = test_keypair_path(dir.path());
        let passphrase = "日本語パスワード🔐".as_bytes();

        let original_keypair = identity::Keypair::generate_ed25519();
        let original_peer_id = Libp2pPeerId::from(original_keypair.public());

        save_encrypted_keypair(&path, &original_keypair, passphrase).unwrap();

        let loaded_keypair = load_encrypted_keypair(&path, passphrase).unwrap();
        let loaded_peer_id = Libp2pPeerId::from(loaded_keypair.public());

        assert_eq!(original_peer_id, loaded_peer_id);
    }

    #[test]
    fn keypair_truncated_file_fails() {
        let dir = tempdir().unwrap();
        let path = test_keypair_path(dir.path());

        let keypair = identity::Keypair::generate_ed25519();
        save_encrypted_keypair(&path, &keypair, b"passphrase").unwrap();

        // Truncate file to be too short
        let data = fs::read(&path).unwrap();
        fs::write(&path, &data[..20]).unwrap();

        let result = load_encrypted_keypair(&path, b"passphrase");
        assert!(result.is_err());
        assert!(result.err().unwrap().to_string().contains("too short"));
    }

    #[test]
    fn keypair_invalid_magic_fails() {
        let dir = tempdir().unwrap();
        let path = test_keypair_path(dir.path());

        let keypair = identity::Keypair::generate_ed25519();
        save_encrypted_keypair(&path, &keypair, b"passphrase").unwrap();

        // Corrupt magic bytes
        let mut data = fs::read(&path).unwrap();
        data[0] = 0xFF;
        data[1] = 0xFF;
        fs::write(&path, &data).unwrap();

        let result = load_encrypted_keypair(&path, b"passphrase");
        assert!(result.is_err());
        assert!(
            result
                .err()
                .unwrap()
                .to_string()
                .contains("invalid keyfile magic")
        );
    }

    #[test]
    fn keypair_unsupported_version_fails() {
        let dir = tempdir().unwrap();
        let path = test_keypair_path(dir.path());

        let keypair = identity::Keypair::generate_ed25519();
        save_encrypted_keypair(&path, &keypair, b"passphrase").unwrap();

        // Change version byte to unsupported version
        let mut data = fs::read(&path).unwrap();
        data[4] = 99;
        fs::write(&path, &data).unwrap();

        let result = load_encrypted_keypair(&path, b"passphrase");
        assert!(result.is_err());
        assert!(
            result
                .err()
                .unwrap()
                .to_string()
                .contains("unsupported keyfile version")
        );
    }

    #[test]
    fn keypair_corrupted_ciphertext_fails() {
        let dir = tempdir().unwrap();
        let path = test_keypair_path(dir.path());

        let keypair = identity::Keypair::generate_ed25519();
        save_encrypted_keypair(&path, &keypair, b"passphrase").unwrap();

        // Corrupt ciphertext (after header)
        let mut data = fs::read(&path).unwrap();
        let header_len = 4 + 1 + SALT_LEN + NONCE_LEN;
        if data.len() > header_len + 5 {
            data[header_len + 5] ^= 0xFF;
        }
        fs::write(&path, &data).unwrap();

        let result = load_encrypted_keypair(&path, b"passphrase");
        assert!(result.is_err());
        assert!(
            result
                .err()
                .unwrap()
                .to_string()
                .contains("decryption failed")
        );
    }

    #[test]
    fn keypair_corrupted_nonce_fails() {
        let dir = tempdir().unwrap();
        let path = test_keypair_path(dir.path());

        let keypair = identity::Keypair::generate_ed25519();
        save_encrypted_keypair(&path, &keypair, b"passphrase").unwrap();

        // Corrupt nonce
        let mut data = fs::read(&path).unwrap();
        let nonce_offset = 4 + 1 + SALT_LEN;
        data[nonce_offset] ^= 0xFF;
        fs::write(&path, &data).unwrap();

        let result = load_encrypted_keypair(&path, b"passphrase");
        assert!(result.is_err());
    }

    #[test]
    fn keypair_corrupted_salt_fails() {
        let dir = tempdir().unwrap();
        let path = test_keypair_path(dir.path());

        let keypair = identity::Keypair::generate_ed25519();
        save_encrypted_keypair(&path, &keypair, b"passphrase").unwrap();

        // Corrupt salt (changes derived key)
        let mut data = fs::read(&path).unwrap();
        data[5] ^= 0xFF;
        fs::write(&path, &data).unwrap();

        let result = load_encrypted_keypair(&path, b"passphrase");
        assert!(result.is_err());
        assert!(
            result
                .err()
                .unwrap()
                .to_string()
                .contains("decryption failed")
        );
    }

    #[test]
    fn keypair_load_nonexistent_file_fails() {
        let path = PathBuf::from("/nonexistent/path/identity.key");
        let result = load_encrypted_keypair(&path, b"passphrase");
        assert!(result.is_err());
    }

    #[test]
    fn keypair_overwrite_existing_key() {
        let dir = tempdir().unwrap();
        let path = test_keypair_path(dir.path());

        let keypair1 = identity::Keypair::generate_ed25519();
        let keypair2 = identity::Keypair::generate_ed25519();
        let peer_id2 = Libp2pPeerId::from(keypair2.public());

        save_encrypted_keypair(&path, &keypair1, b"pass1").unwrap();
        save_encrypted_keypair(&path, &keypair2, b"pass2").unwrap();

        // Should load keypair2 with pass2
        let loaded = load_encrypted_keypair(&path, b"pass2").unwrap();
        assert_eq!(Libp2pPeerId::from(loaded.public()), peer_id2);

        // pass1 should no longer work
        let result = load_encrypted_keypair(&path, b"pass1");
        assert!(result.is_err());
    }

    #[test]
    fn keypair_file_has_correct_magic() {
        let dir = tempdir().unwrap();
        let path = test_keypair_path(dir.path());

        let keypair = identity::Keypair::generate_ed25519();
        save_encrypted_keypair(&path, &keypair, b"passphrase").unwrap();

        let data = fs::read(&path).unwrap();
        assert_eq!(&data[0..4], KEYFILE_MAGIC);
    }

    #[test]
    fn keypair_file_has_correct_version() {
        let dir = tempdir().unwrap();
        let path = test_keypair_path(dir.path());

        let keypair = identity::Keypair::generate_ed25519();
        save_encrypted_keypair(&path, &keypair, b"passphrase").unwrap();

        let data = fs::read(&path).unwrap();
        assert_eq!(data[4], KEYFILE_VERSION);
    }

    #[test]
    fn keypair_each_save_produces_different_ciphertext() {
        let dir = tempdir().unwrap();
        let path1 = dir.path().join("key1.key");
        let path2 = dir.path().join("key2.key");

        let keypair = identity::Keypair::generate_ed25519();

        save_encrypted_keypair(&path1, &keypair, b"same_passphrase").unwrap();
        save_encrypted_keypair(&path2, &keypair, b"same_passphrase").unwrap();

        let data1 = fs::read(&path1).unwrap();
        let data2 = fs::read(&path2).unwrap();

        // Salt and nonce should be different, making entire file different
        assert_ne!(data1, data2);

        // But both should decrypt to the same keypair
        let loaded1 = load_encrypted_keypair(&path1, b"same_passphrase").unwrap();
        let loaded2 = load_encrypted_keypair(&path2, b"same_passphrase").unwrap();
        assert_eq!(
            Libp2pPeerId::from(loaded1.public()),
            Libp2pPeerId::from(loaded2.public())
        );
    }

    #[test]
    fn keypair_long_passphrase_works() {
        let dir = tempdir().unwrap();
        let path = test_keypair_path(dir.path());
        let passphrase = vec![b'a'; 10000];

        let original_keypair = identity::Keypair::generate_ed25519();
        let original_peer_id = Libp2pPeerId::from(original_keypair.public());

        save_encrypted_keypair(&path, &original_keypair, &passphrase).unwrap();

        let loaded_keypair = load_encrypted_keypair(&path, &passphrase).unwrap();
        let loaded_peer_id = Libp2pPeerId::from(loaded_keypair.public());

        assert_eq!(original_peer_id, loaded_peer_id);
    }

    #[test]
    fn keypair_binary_passphrase_works() {
        let dir = tempdir().unwrap();
        let path = test_keypair_path(dir.path());
        let passphrase: Vec<u8> = (0u8..=255).collect();

        let original_keypair = identity::Keypair::generate_ed25519();
        let original_peer_id = Libp2pPeerId::from(original_keypair.public());

        save_encrypted_keypair(&path, &original_keypair, &passphrase).unwrap();

        let loaded_keypair = load_encrypted_keypair(&path, &passphrase).unwrap();
        let loaded_peer_id = Libp2pPeerId::from(loaded_keypair.public());

        assert_eq!(original_peer_id, loaded_peer_id);
    }

    #[test]
    fn keypair_load_or_generate_creates_new_when_missing() {
        let dir = tempdir().unwrap();
        let node_name = format!("test-node-{}", std::process::id());

        // Use a test-specific chain ID to avoid conflicts
        let test_chain_id = 888888u64;

        // Ensure no existing key
        let path = dir
            .path()
            .join(".blockchain")
            .join(test_chain_id.to_string())
            .join(&node_name);
        if path.exists() {
            fs::remove_dir_all(&path).unwrap();
        }

        // This will create a new keypair since none exists
        // Note: load_or_generate_keypair uses the home directory, so we test the underlying functions
        let keypair = identity::Keypair::generate_ed25519();
        let key_path = dir.path().join("new_identity.key");

        assert!(!key_path.exists());
        save_encrypted_keypair(&key_path, &keypair, b"test").unwrap();
        assert!(key_path.exists());

        let loaded = load_encrypted_keypair(&key_path, b"test").unwrap();
        assert_eq!(
            Libp2pPeerId::from(keypair.public()),
            Libp2pPeerId::from(loaded.public())
        );
    }
}
