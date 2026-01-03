//! TCP-based transport implementation for real network communication.
//!
//! Provides encrypted, authenticated communication over TCP using the Noise Protocol
//! Framework (XX pattern with X25519, ChaChaPoly, SHA256). All messages are
//! length-prefixed and encrypted after the initial handshake.
//!
//! # Connection Model
//!
//! ```text
//!     ┌─────────────────────────────────────────────────────────────────┐
//!     │                      Connection Lifecycle                       │
//!     └─────────────────────────────────────────────────────────────────┘
//!
//!     Node A (initiator)                         Node B (responder)
//!          │                                           │
//!          │  TCP connect ──────────────────────────►  │
//!          │                                           │
//!          │  ◄──────────── Noise XX Handshake ──────► │
//!          │                                           │
//!          │  stores writer for B                      │  stores writer for A
//!          │  spawns read loop                         │  spawns read loop
//!          │                                           │
//!          │  ◄═══════════ Encrypted RPCs ═══════════► │
//!          │                                           │
//! ```
//!
//! - **Outbound connections** store writers keyed by the peer's listen address.
//! - **Inbound connections** trigger a connect-back if no outbound exists.
//! - Writers are removed automatically when the read loop terminates.
//! - All handshakes have a 3-second timeout to prevent resource exhaustion.
//!
//! # Noise XX Handshake
//!
//! Uses the Noise XX pattern for mutual authentication with ephemeral and static keys.
//! The chain ID is bound into the handshake via prologue to prevent cross-chain attacks.
//!
//! ```text
//!     Initiator                                      Responder
//!          │                                              │
//!          │  ── msg1: e, payload(listen_addr) ────────►  │
//!          │                                              │
//!          │  ◄─ msg2: e, ee, s, es, payload(listen_addr) │
//!          │                                              │
//!          │  ── msg3: s, se ──────────────────────────►  │
//!          │                                              │
//!          │         [handshake complete]                 │
//!          │                                              │
//!          │  ◄═══════ encrypted transport msgs ════════► │
//!          │                                              │
//! ```
//!
//! - `e` = ephemeral public key
//! - `s` = static public key
//! - `ee`, `es`, `se` = DH operations between ephemeral/static keys
//! - Payload in msg1/msg2 contains the sender's listen address
//!
//! # Wire Format
//!
//! All messages (handshake and transport) use length-prefixed framing:
//!
//! ```text
//!     ┌──────────────┬─────────────────────────────────┐
//!     │  length (4B) │  payload (up to 65535 bytes)    │
//!     │   u32 LE     │  [encrypted after handshake]    │
//!     └──────────────┴─────────────────────────────────┘
//! ```
//!
//! Listen address encoding within handshake payloads:
//!
//! ```text
//!     IPv4: [0x04][addr: 4 bytes][port: u16 LE]  (7 bytes total)
//!     IPv6: [0x06][addr: 16 bytes][port: u16 LE] (19 bytes total)
//! ```

use crate::impl_transport_consume;
use crate::network::rpc::{RawRpc, Rpc};
use crate::network::transport::{Transport, TransportError, spawn_rpc_forwarder};
use crate::types::array::Array;
use crate::types::bytes::Bytes;
use crate::types::encoding::{Decode, Encode};
use crate::types::hash::Hash;
use crate::types::wrapper_types::BoxFuture;
use dashmap::DashMap;
use dashmap::try_result::TryResult;
use snow::params::NoiseParams;
use snow::{Builder, Keypair, TransportState};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio::sync::mpsc::{Receiver, Sender, channel};
use tokio::time::{Duration, timeout};

/// Address type marker for IPv4 in handshake encoding.
const ADDR_TYPE_V4: u8 = 4;
/// Address type marker for IPv6 in handshake encoding.
const ADDR_TYPE_V6: u8 = 6;

/// Noise protocol pattern: XX with X25519 DH, ChaChaPoly AEAD, SHA256 hash.
const NOISE_PATTERN: &str = "Noise_XX_25519_ChaChaPoly_SHA256";
/// Maximum Noise message size (65535 bytes per spec).
const NOISE_MAX_MSG: usize = 65_535;

/// Parses the Noise protocol parameters from the pattern string.
fn noise_params() -> NoiseParams {
    NOISE_PATTERN.parse().expect("invalid noise params")
}

/// Constructs the Noise prologue for chain-specific domain separation.
///
/// The prologue is hashed into the handshake transcript, binding the session
/// to a specific chain ID and preventing cross-chain replay attacks.
fn noise_prologue(chain_id: u64) -> Vec<u8> {
    let mut p = Vec::with_capacity(16);
    p.extend_from_slice(b"MYCHAIN\0NOISE\0");
    p.extend_from_slice(&chain_id.to_le_bytes());
    p
}

/// Writes a length-prefixed frame to the stream.
///
/// Frame format: `[len: u32 LE][data: len bytes]`.
/// Returns an error if data exceeds [`NOISE_MAX_MSG`].
async fn write_frame<W: AsyncWriteExt + Unpin>(w: &mut W, data: &[u8]) -> io::Result<()> {
    if data.len() > NOISE_MAX_MSG {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "noise msg too large",
        ));
    }
    let len = (data.len() as u32).to_le_bytes();
    w.write_all(&len).await?;
    w.write_all(data).await?;
    w.flush().await
}

/// Reads a length-prefixed frame from the stream.
///
/// Rejects frames with zero length or exceeding [`NOISE_MAX_MSG`].
async fn read_frame<R: AsyncReadExt + Unpin>(r: &mut R) -> io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf).await?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len == 0 || len > NOISE_MAX_MSG {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "bad frame len"));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await?;
    Ok(buf)
}

/// Encodes a socket address for handshake payload.
///
/// # Wire Format
///
/// ```text
/// IPv4: [0x04][addr: 4 bytes][port: u16 LE]  = 7 bytes
/// IPv6: [0x06][addr: 16 bytes][port: u16 LE] = 19 bytes
/// ```
pub fn encode_socket_addr(addr: SocketAddr) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 16 + 2);
    match addr.ip() {
        IpAddr::V4(v4) => {
            out.push(ADDR_TYPE_V4);
            out.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            out.push(ADDR_TYPE_V6);
            out.extend_from_slice(&v6.octets());
        }
    }
    out.extend_from_slice(&addr.port().to_le_bytes());
    out
}

/// Decodes a socket address from handshake payload bytes.
///
/// # Errors
///
/// Returns an error if:
/// - The address type byte is not 0x04 (IPv4) or 0x06 (IPv6)
/// - The byte slice length doesn't match the expected format
pub fn decode_socket_addr(bytes: &[u8]) -> io::Result<SocketAddr> {
    let (ip_len, min_len) = match bytes.first() {
        Some(&ADDR_TYPE_V4) => (4, 1 + 4 + 2),
        Some(&ADDR_TYPE_V6) => (16, 1 + 16 + 2),
        _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "addr type")),
    };

    if bytes.len() != min_len {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "addr length"));
    }

    let ip_bytes = &bytes[1..1 + ip_len];
    let port_bytes = &bytes[1 + ip_len..];

    let ip = match ip_len {
        4 => IpAddr::V4(Ipv4Addr::new(
            ip_bytes[0],
            ip_bytes[1],
            ip_bytes[2],
            ip_bytes[3],
        )),
        16 => IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(ip_bytes).unwrap())),
        _ => unreachable!(),
    };

    let port = u16::from_le_bytes([port_bytes[0], port_bytes[1]]);
    Ok(SocketAddr::new(ip, port))
}

/// Holds the write-side state for an established peer connection.
struct PeerSession {
    /// TCP write half, protected for concurrent access.
    writer: Mutex<OwnedWriteHalf>,
    /// Noise transport state for encrypting outbound messages.
    noise: Arc<Mutex<TransportState>>,
    /// Remote peer's cryptographic identity derived from their static Noise key.
    peer_id: Hash,
}

/// TCP transport for blockchain network communication.
///
/// Provides encrypted peer-to-peer messaging over TCP with Noise Protocol
/// authentication. Each peer is identified by its static Noise public key.
pub struct TcpTransport {
    /// Local address this transport listens on for incoming connections.
    listen_address: SocketAddr,
    /// Noise static keypair for identity and authentication.
    noise_static: Keypair,
    /// Active peer sessions, keyed by peer's listen address.
    writers: DashMap<SocketAddr, Arc<PeerSession>>,
    /// Channel sender for forwarding incoming RPCs to the server.
    tx: Sender<Rpc>,
    /// Channel receiver for incoming RPCs (taken once by [`Transport::consume`]).
    rx: Arc<Mutex<Option<Receiver<Rpc>>>>,
    /// Chain ID bound into handshake prologue for network isolation.
    chain_id: u64,
    /// Maps peer IDs to their socket addresses (IPv4 at index 0, IPv6 at index 1).
    peer_to_socket: DashMap<Hash, Array<SocketAddr, 2>>,
}

impl TcpTransport {
    /// Creates a new TCP transport for the given listen address.
    ///
    /// Generates a fresh Noise static keypair for identity. The transport does not
    /// begin accepting connections until [`Transport::start`] is called.
    pub fn new(address: SocketAddr, chain_id: u64) -> Arc<Self> {
        let (tx, rx) = channel(1024);
        let b = Builder::new(noise_params());
        let noise_static = b
            .generate_keypair()
            .expect("noise keypair generation failed");

        Arc::new(Self {
            listen_address: address,
            noise_static,
            writers: DashMap::new(),
            tx,
            rx: Arc::new(Mutex::new(Some(rx))),
            chain_id,
            peer_to_socket: DashMap::new(),
        })
    }

    /// Initiates an outbound connection to a peer at the given address.
    ///
    /// Performs TCP connect with exponential backoff, executes Noise XX handshake
    /// as initiator, stores the session, and spawns a read loop. Returns `true`
    /// on success, `false` after all retries exhausted.
    pub fn connect_addr(self: &Arc<Self>, addr: SocketAddr) -> BoxFuture<'static, bool> {
        let transport = self.clone();
        let tx = self.tx.clone();
        Box::pin(async move { Self::establish_outbound_connection(transport, addr, tx).await })
    }

    /// Reads encrypted messages from a peer and forwards decoded RPCs.
    ///
    /// Runs until the connection closes or the RPC channel is dropped.
    /// Each frame is decrypted using the Noise transport state before parsing.
    async fn read_loop(
        mut reader: OwnedReadHalf,
        noise: Arc<Mutex<TransportState>>,
        peer_id: Hash,
        tx: Sender<Rpc>,
    ) {
        let mut plain = vec![0u8; NOISE_MAX_MSG];

        loop {
            let frame = match read_frame(&mut reader).await {
                Ok(f) => f,
                Err(_) => return,
            };

            let n = {
                let mut st = noise.lock().await;
                st.read_message(&frame, &mut plain).unwrap_or(0)
            };
            if n == 0 {
                continue;
            }

            let rpc = match RawRpc::from_bytes(&plain[..n]) {
                Ok(r) => Rpc::from_raw(r, peer_id),
                Err(_) => continue,
            };

            if tx.send(rpc).await.is_err() {
                return;
            }
        }
    }

    /// Accepts incoming TCP connections on the listen address.
    ///
    /// Each connection is handled in a spawned task that performs the Noise
    /// handshake as responder, then enters the read loop.
    async fn accept_loop(self: Arc<Self>, tx: Sender<Rpc>) {
        let listener = match TcpListener::bind(self.listen_address).await {
            Ok(l) => l,
            Err(_) => return,
        };

        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let self_clone = self.clone();
                    let tx = tx.clone();
                    tokio::spawn(async move {
                        Self::handle_inbound(self_clone, stream, tx).await;
                    });
                }
                Err(_) => continue,
            }
        }
    }

    /// Executes the Noise XX handshake as initiator (outbound connection).
    ///
    /// Sends msg1 with local listen address, receives msg2 with peer's listen
    /// address, sends msg3 to complete. Returns the transport state, peer's
    /// listen address, and peer's static public key.
    async fn noise_handshake_initiator(
        transport: &TcpTransport,
        reader: &mut OwnedReadHalf,
        writer: &mut OwnedWriteHalf,
    ) -> io::Result<(TransportState, SocketAddr, Vec<u8>, Vec<u8>)> {
        let prologue = noise_prologue(transport.chain_id);
        let mut hs = Builder::new(noise_params())
            .local_private_key(&transport.noise_static.private)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?
            .prologue(&prologue)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?
            .build_initiator()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

        let mut out = vec![0u8; NOISE_MAX_MSG];
        let mut payload = vec![0u8; NOISE_MAX_MSG];

        // msg1: send my listen addr (it may be unencrypted in XX; integrity is enforced by the handshake)
        let p1 = encode_socket_addr(transport.listen_address);
        let n1 = hs
            .write_message(&p1, &mut out)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        write_frame(writer, &out[..n1]).await?;

        // msg2: receive peer listen addr
        let m2 = read_frame(reader).await?;
        let p2n = hs
            .read_message(&m2, &mut payload)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        let peer_listen = decode_socket_addr(&payload[..p2n])?;

        // msg3: finish
        let n3 = hs
            .write_message(&[], &mut out)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        write_frame(writer, &out[..n3]).await?;

        if !hs.is_handshake_finished() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "handshake incomplete",
            ));
        }

        let handshake_hash = hs.get_handshake_hash().to_vec();
        let remote_static = hs.get_remote_static().unwrap_or(&[]).to_vec();
        let ts = hs
            .into_transport_mode()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

        Ok((ts, peer_listen, remote_static, handshake_hash))
    }

    /// Executes the Noise XX handshake as responder (inbound connection).
    ///
    /// Receives msg1 with peer's listen address, sends msg2 with local listen
    /// address, receives msg3 to complete. Returns the transport state, peer's
    /// listen address, and peer's static public key.
    async fn noise_handshake_responder(
        transport: &TcpTransport,
        reader: &mut OwnedReadHalf,
        writer: &mut OwnedWriteHalf,
    ) -> io::Result<(TransportState, SocketAddr, Vec<u8>, Vec<u8>)> {
        let prologue = noise_prologue(transport.chain_id);
        let mut hs = Builder::new(noise_params())
            .local_private_key(&transport.noise_static.private)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?
            .prologue(&prologue)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?
            .build_responder()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

        let mut out = vec![0u8; NOISE_MAX_MSG];
        let mut payload = vec![0u8; NOISE_MAX_MSG];

        // msg1: receive peer listen addr
        let m1 = read_frame(reader).await?;
        let p1n = hs
            .read_message(&m1, &mut payload)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        let peer_listen = decode_socket_addr(&payload[..p1n])?;
        // msg2: send my listen addr
        let p2 = encode_socket_addr(transport.listen_address);
        let n2 = hs
            .write_message(&p2, &mut out)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        write_frame(writer, &out[..n2]).await?;

        // msg3: receive finish
        let m3 = read_frame(reader).await?;
        hs.read_message(&m3, &mut payload)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

        if !hs.is_handshake_finished() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "handshake incomplete",
            ));
        }

        let handshake_hash = hs.get_handshake_hash().to_vec();
        let remote_static = hs.get_remote_static().unwrap_or(&[]).to_vec();
        let ts = hs
            .into_transport_mode()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

        Ok((ts, peer_listen, remote_static, handshake_hash))
    }

    /// Derives a stable peer ID from the peer's static Noise public key.
    ///
    /// The peer ID is a SHA3 hash of the domain-separated static key,
    /// providing a consistent identity across sessions.
    fn peer_id(peer_static: &[u8]) -> Hash {
        let mut hash = Hash::sha3();
        hash.update(b"PEER_ID");
        hash.update(peer_static);
        hash.finalize()
    }

    /// Derives a unique session ID from the peer's static key and handshake hash.
    ///
    /// The session ID binds to both the peer identity and the specific handshake,
    /// ensuring each connection has a cryptographically unique identifier.
    fn session_id(peer_static: &[u8], handshake_hash: &[u8]) -> Hash {
        let mut hash = Hash::sha3();
        hash.update(b"SESSION");
        hash.update(peer_static);
        hash.update(handshake_hash);
        hash.finalize()
    }

    /// Looks up the peer ID associated with a socket address.
    ///
    /// Returns `None` if no peer is known at that address.
    fn socket_to_peer(&self, address: SocketAddr) -> Option<Hash> {
        self.peer_to_socket
            .iter()
            .find(|entry| entry.value().contains(address))
            .map(|entry| *entry.key())
    }

    /// Handles an accepted inbound TCP connection.
    ///
    /// Performs the Noise handshake as responder (3-second timeout), then initiates
    /// a connect-back to the peer if no outbound session exists. Enters read loop
    /// after setup. The inbound writer is not stored to avoid duplicate sessions.
    async fn handle_inbound(self: Arc<Self>, stream: TcpStream, tx: Sender<Rpc>) {
        let peer_ip = match stream.peer_addr() {
            Ok(a) => a.ip(),
            Err(_) => return,
        };

        let (mut reader, mut writer) = stream.into_split();

        let hs_res = timeout(Duration::from_secs(3), async {
            Self::noise_handshake_responder(&self, &mut reader, &mut writer).await
        })
        .await;

        let (ts, claimed_listen, peer_static, handshake_hash) = match hs_res {
            Ok(Ok(v)) => v,
            _ => return,
        };

        let peer_static: [u8; 32] = match peer_static.try_into() {
            Ok(v) => v,
            Err(_) => return,
        };

        let normalized = SocketAddr::new(peer_ip, claimed_listen.port());
        let peer_id = Self::peer_id(&peer_static);
        let mut ok = false;
        for _ in 0..3 {
            match self.peer_to_socket.try_get(&peer_id) {
                TryResult::Present(pair) if !pair.value().contains(normalized) => return,
                TryResult::Locked => tokio::task::yield_now().await,
                _ => {
                    ok = true;
                    break;
                }
            }
        }
        if !ok {
            return;
        }
        match self.socket_to_peer(normalized) {
            Some(peer) if peer != peer_id => return,
            _ => {}
        }

        self.peer_to_socket
            .entry(peer_id)
            .and_modify(|arr| {
                arr.insert_at(normalized.is_ipv6() as usize, normalized);
            })
            .or_insert_with(|| {
                let mut arr = Array::<SocketAddr, 2>::new();
                arr.insert_at(normalized.is_ipv6() as usize, normalized);
                arr
            });

        let _session_id = Self::session_id(&peer_static, &handshake_hash);

        // 1) reject obvious spoofing unless it's loopback-v4/v6 equivalence
        let claimed_ip = claimed_listen.ip();
        let ok = if peer_ip == claimed_ip {
            true
        } else if peer_ip.is_loopback() && claimed_ip.is_loopback() {
            // allow 127.0.0.1 <-> ::1 in local dev
            true
        } else {
            false
        };

        if !ok {
            return;
        }

        // 2) use claimed listen address as canonical key + dial target
        let peer_addr = claimed_listen;

        // If no outbound exists, try to establish it to the claimed listen addr.
        // If it fails, promote the inbound writer under the *same* claimed addr.
        let outbound_ok = if self.writers.contains_key(&peer_addr) {
            true
        } else {
            Self::establish_outbound_connection(self.clone(), peer_addr, tx.clone()).await
        };

        if !outbound_ok {
            let noise = Arc::new(Mutex::new(ts));
            self.writers.entry(peer_addr).or_insert_with(|| {
                Arc::new(PeerSession {
                    writer: Mutex::new(writer),
                    noise,
                    peer_id,
                })
            });
            Self::read_loop(
                reader,
                self.writers.get(&peer_addr).unwrap().noise.clone(),
                peer_id,
                tx,
            )
            .await;
            return;
        }

        // if outbound_ok, drop inbound writer and just read
        let noise = Arc::new(Mutex::new(ts));
        Self::read_loop(reader, noise, peer_id, tx).await;

        // Clean up peer_to_socket when the inbound connection closes
        if let Some(mut entry) = self.peer_to_socket.get_mut(&peer_id) {
            entry.value_mut().remove_value(&normalized);
        }
    }

    /// Establishes an outbound TCP connection with retry logic.
    ///
    /// Retries up to 5 times with exponential backoff (100ms, 200ms, 400ms, ...).
    /// On success, completes Noise handshake as initiator, stores the session,
    /// and spawns a read loop. Session is removed when the read loop exits.
    async fn establish_outbound_connection(
        transport: Arc<Self>,
        target: SocketAddr,
        tx: Sender<Rpc>,
    ) -> bool {
        let mut delay = Duration::from_millis(100);

        for _ in 0..5 {
            let stream = match TcpStream::connect(target).await {
                Ok(s) => s,
                Err(_) => {
                    tokio::time::sleep(delay).await;
                    delay *= 2;
                    continue;
                }
            };

            let (mut reader, mut writer) = stream.into_split();

            let hs_res = timeout(Duration::from_secs(3), async {
                Self::noise_handshake_initiator(&transport, &mut reader, &mut writer).await
            })
            .await;

            let (ts, peer_listen, peer_static, handshake_hash) = match hs_res {
                Ok(Ok(v)) => v,
                _ => {
                    tokio::time::sleep(delay).await;
                    delay *= 2;
                    continue;
                }
            };

            let peer_static: [u8; 32] = match peer_static.try_into() {
                Ok(v) => v,
                Err(_) => return false,
            };
            let peer_id = Self::peer_id(&peer_static);

            let normalized = SocketAddr::new(target.ip(), peer_listen.port());
            match transport.peer_to_socket.get(&peer_id) {
                Some(existing) if !existing.contains(normalized) => return false,
                _ => {}
            }
            if let Some(other_peer) = transport.socket_to_peer(normalized)
                && other_peer != peer_id
            {
                return false;
            }

            transport
                .peer_to_socket
                .entry(peer_id)
                .and_modify(|arr| {
                    arr.insert_at(normalized.is_ipv6() as usize, normalized);
                })
                .or_insert_with(|| {
                    let mut arr = Array::<SocketAddr, 2>::new();
                    arr.insert_at(normalized.is_ipv6() as usize, normalized);
                    arr
                });

            let _session_id = Self::session_id(&peer_static, &handshake_hash);

            let noise = Arc::new(Mutex::new(ts));
            let session = Arc::new(PeerSession {
                writer: Mutex::new(writer),
                noise: noise.clone(),
                peer_id,
            });
            transport.writers.insert(peer_listen, session.clone());

            let transport_ref = transport.clone();
            tokio::spawn(async move {
                Self::read_loop(reader, noise.clone(), peer_id, tx).await;
                transport_ref.writers.remove(&peer_listen);
                if let Some(mut entry) = transport_ref.peer_to_socket.get_mut(&peer_id) {
                    entry.value_mut().remove_value(&peer_listen);
                }
            });

            return true;
        }

        false
    }
}

impl Transport for TcpTransport {
    fn connect(self: &Arc<Self>, other: &Arc<Self>) {
        let fut = self.connect_addr(other.listen_address);
        tokio::spawn(async move {
            fut.await;
        });
    }

    fn connect_async(self: &Arc<Self>, other: &Arc<Self>) -> BoxFuture<'static, bool> {
        self.connect_addr(other.listen_address)
    }

    fn start(self: &Arc<Self>, sx: Sender<Rpc>) {
        let clone = self.clone();
        let tx = self.tx.clone();
        tokio::spawn(async move {
            Self::accept_loop(clone, tx).await;
        });

        spawn_rpc_forwarder(self.clone(), sx);
    }

    impl_transport_consume!();

    fn send_message(
        self: &Arc<Self>,
        to: SocketAddr,
        payload: Bytes,
    ) -> BoxFuture<'static, Result<(), TransportError>> {
        let writers = self.writers.clone();
        let from = self.listen_address;

        Box::pin(async move {
            let session = match writers.get(&to) {
                Some(s) => s.value().clone(),
                None => return Err(TransportError::PeerNotFound(to)),
            };

            let rpc = Rpc::new(session.peer_id, from, payload);
            let plain = rpc.to_raw().to_bytes();

            if plain.len() + 16 > NOISE_MAX_MSG {
                return Err(TransportError::SendFailed(to));
            }

            let mut msg = vec![0u8; plain.len() + 16];
            let msg_len = {
                let mut st = session.noise.lock().await;
                st.write_message(&plain, &mut msg)
                    .map_err(|_| TransportError::SendFailed(to))?
            };

            let mut w = session.writer.lock().await;
            write_frame(&mut *w, &msg[..msg_len])
                .await
                .map_err(|_| TransportError::SendFailed(to))
        })
    }

    fn addr(self: &Arc<Self>) -> SocketAddr {
        self.listen_address
    }

    fn peer_addrs(self: &Arc<Self>) -> Vec<SocketAddr> {
        self.writers.iter().map(|e| *e.key()).collect()
    }
}
