//! TCP-based transport implementation for real network communication.
//!
//! Provides length-prefixed framing over TCP with per-peer connection management.
//! Uses split read/write halves for concurrent IO on each connection.
//!
//! # Connection model
//!
//! - **Outbound connections** store writers keyed by target listen address.
//! - **Inbound connections** only use the read half; writers are dropped.
//!   This prevents duplicate entries when both peers connect to each other.
//! - When accepting an inbound connection, if no outbound connection exists to that
//!   peer, one is established automatically using the claimed listen address.
//! - Writers are removed when the read loop terminates (connection cleanup).
//! - Handshake has a 3-second timeout to prevent resource exhaustion.
//!
//! # Handshake format
//!
//! The handshake is authenticated with Schnorr signatures:
//! ```text
//! [type: u8][addr][port: u16 LE][pubkey: 32][nonce: 32][sig: 64]
//! ```
//! - type=4: IPv4 (4 bytes addr)
//! - type=6: IPv6 (16 bytes addr)
//! - The signature signs the nonce, proving ownership of the public key.

use crate::crypto::key_pair::{PrivateKey, PublicKey};
use crate::impl_transport_consume;
use crate::network::rpc::Rpc;
use crate::network::transport::{Transport, TransportError, spawn_rpc_forwarder};
use crate::types::bytes::Bytes;
use crate::types::encoding::{Decode, Encode};
use crate::types::wrapper_types::BoxFuture;
use dashmap::DashMap;
use rand_core::{OsRng, RngCore};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio::sync::mpsc::{Receiver, Sender, channel};
use tokio::time::{Duration, timeout};

const ADDR_TYPE_V4: u8 = 4;
const ADDR_TYPE_V6: u8 = 6;

/// Handshake data received from a peer.
struct Handshake {
    addr: SocketAddr,
    pubkey: PublicKey,
}

impl Handshake {
    /// Encodes a handshake message: `[type][addr][port][pubkey:32][nonce:32][sig:64]`
    fn encode(addr: SocketAddr, identity: &PrivateKey) -> Vec<u8> {
        let port = addr.port().to_le_bytes();
        let pubkey = identity.public_key();

        // Generate random nonce
        let mut nonce = [0u8; 32];
        OsRng.fill_bytes(&mut nonce);

        // Sign the nonce
        let sig = identity.sign(&nonce);
        let sig_bytes = sig.to_bytes();

        let mut buf = match addr.ip() {
            IpAddr::V4(v4) => {
                let octets = v4.octets();
                let mut b = Vec::with_capacity(7 + 32 + 32 + 64);
                b.push(ADDR_TYPE_V4);
                b.extend_from_slice(&octets);
                b.extend_from_slice(&port);
                b
            }
            IpAddr::V6(v6) => {
                let octets = v6.octets();
                let mut b = Vec::with_capacity(19 + 32 + 32 + 64);
                b.push(ADDR_TYPE_V6);
                b.extend_from_slice(&octets);
                b.extend_from_slice(&port);
                b
            }
        };

        // Append pubkey, nonce, signature
        buf.extend_from_slice(&pubkey.to_bytes());
        buf.extend_from_slice(&nonce);
        buf.extend_from_slice(&sig_bytes);

        buf
    }

    /// Reads and verifies a handshake message from a peer.
    ///
    /// Returns the peer's address and verified public key, or an error if
    /// the handshake is malformed or the signature is invalid.
    async fn read(reader: &mut OwnedReadHalf) -> io::Result<Handshake> {
        // Read address type
        let mut type_buf = [0u8; 1];
        reader.read_exact(&mut type_buf).await?;

        // Read address based on type
        let addr = match type_buf[0] {
            ADDR_TYPE_V4 => {
                let mut buf = [0u8; 6];
                reader.read_exact(&mut buf).await?;
                let ip = Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
                let port = u16::from_le_bytes([buf[4], buf[5]]);
                SocketAddr::from((ip, port))
            }
            ADDR_TYPE_V6 => {
                let mut buf = [0u8; 18];
                reader.read_exact(&mut buf).await?;
                let ip = Ipv6Addr::from(<[u8; 16]>::try_from(&buf[..16]).unwrap());
                let port = u16::from_le_bytes([buf[16], buf[17]]);
                SocketAddr::from((ip, port))
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid address type",
                ));
            }
        };

        // Read pubkey (32 bytes)
        let mut pubkey_bytes = [0u8; 32];
        reader.read_exact(&mut pubkey_bytes).await?;
        let mut pubkey_slice: &[u8] = &pubkey_bytes;
        let pubkey = PublicKey::decode(&mut pubkey_slice)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid public key"))?;

        // Read nonce (32 bytes)
        let mut nonce = [0u8; 32];
        reader.read_exact(&mut nonce).await?;

        // Read signature (64 bytes)
        let mut sig_bytes = [0u8; 64];
        reader.read_exact(&mut sig_bytes).await?;
        let mut sig_slice: &[u8] = &sig_bytes;
        let sig = Decode::decode(&mut sig_slice)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid signature"))?;

        // Verify signature
        if !pubkey.verify(&nonce, sig) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "handshake signature verification failed",
            ));
        }

        Ok(Handshake { addr, pubkey })
    }
}

/// TCP transport for blockchain network communication.
///
/// Manages TCP connections to peers with length-prefixed message framing.
/// Each peer connection is stored as a write half keyed by address.
pub struct TcpTransport {
    /// Address this transport listens on.
    listen_address: SocketAddr,
    /// Cryptographic identity for handshake authentication.
    identity: PrivateKey,
    /// Write halves of peer connections, keyed by peer address.
    writers: DashMap<SocketAddr, Arc<Mutex<OwnedWriteHalf>>>,
    /// Channel sender for incoming RPCs.
    tx: Sender<Rpc>,
    /// Channel receiver for incoming RPCs (taken once by consume).
    rx: Arc<Mutex<Option<Receiver<Rpc>>>>,
}

impl TcpTransport {
    /// Creates a new TCP transport bound to the given address with the specified identity.
    ///
    /// The identity is used for cryptographic authentication during handshakes.
    /// The transport must be started with `start()` before it can accept connections.
    pub fn new(address: SocketAddr) -> Arc<Self> {
        let (tx, rx) = channel(1024);

        Arc::new(Self {
            listen_address: address,
            identity: PrivateKey::new(),
            writers: DashMap::new(),
            tx,
            rx: Arc::new(Mutex::new(Some(rx))),
        })
    }

    /// Returns the public key of this transport's identity.
    pub fn public_key(&self) -> PublicKey {
        self.identity.public_key()
    }

    /// Connects to a remote peer by socket address.
    ///
    /// This is the production API for connecting to peers. The test-oriented
    /// `connect(&Arc<Self>)` method internally calls this.
    pub fn connect_addr(self: &Arc<Self>, addr: SocketAddr) -> BoxFuture<'static, bool> {
        let transport = self.clone();
        let tx = self.tx.clone();
        Box::pin(async move { Self::establish_outbound_connection(transport, addr, tx).await })
    }

    async fn read_loop(mut reader: OwnedReadHalf, tx: Sender<Rpc>) {
        loop {
            let mut len_buf = [0u8; 4];

            match reader.read_exact(&mut len_buf).await {
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                    return;
                }
                Err(_) => {
                    return;
                }
            }

            let len = u32::from_le_bytes(len_buf) as usize;
            if len == 0 || len > 16 * 1024 * 1024 {
                return;
            }

            let mut msg = vec![0u8; len];
            if reader.read_exact(&mut msg).await.is_err() {
                return;
            }

            let rpc = match Rpc::from_bytes(&msg) {
                Ok(rpc) => rpc,
                Err(_) => continue,
            };

            if tx.send(rpc).await.is_err() {
                return;
            }
        }
    }

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

    async fn handle_inbound(self: Arc<Self>, stream: TcpStream, tx: Sender<Rpc>) {
        let (mut reader, _writer) = stream.into_split();

        // Read and verify peer's authenticated handshake with timeout
        let handshake = match timeout(Duration::from_secs(3), Handshake::read(&mut reader)).await {
            Ok(Ok(hs)) => hs,
            _ => return, // Invalid handshake or timeout - reject connection
        };

        // Connect back to peer if we don't have an outbound connection yet
        // Must complete before read loop to ensure we can respond to messages
        if !self.writers.contains_key(&handshake.addr) {
            Self::establish_outbound_connection(self.clone(), handshake.addr, tx.clone()).await;
        }

        Self::read_loop(reader, tx).await;
    }

    async fn send_framed(writer: &Mutex<OwnedWriteHalf>, data: &[u8]) -> io::Result<()> {
        let mut guard = writer.lock().await;
        let len = (data.len() as u32).to_le_bytes();
        guard.write_all(&len).await?;
        guard.write_all(data).await?;
        guard.flush().await
    }

    async fn establish_outbound_connection(
        transport: Arc<Self>,
        target_addr: SocketAddr,
        tx: Sender<Rpc>,
    ) -> bool {
        // Retry connection with exponential backoff (100ms, 200ms, 400ms, 800ms, 1600ms)
        let mut delay = Duration::from_millis(100);
        for _ in 0..5 {
            match TcpStream::connect(target_addr).await {
                Ok(stream) => {
                    let (reader, mut writer) = stream.into_split();

                    // Send authenticated handshake
                    let handshake_buf =
                        Handshake::encode(transport.listen_address, &transport.identity);
                    if writer.write_all(&handshake_buf).await.is_err() {
                        return false;
                    }

                    transport
                        .writers
                        .insert(target_addr, Arc::new(Mutex::new(writer)));

                    // Spawn read loop with cleanup on disconnect
                    let writers = transport.writers.clone();
                    tokio::spawn(async move {
                        Self::read_loop(reader, tx).await;
                        writers.remove(&target_addr);
                    });
                    return true;
                }
                Err(_) => {
                    tokio::time::sleep(delay).await;
                    delay *= 2;
                }
            }
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
        let address = self.listen_address;

        Box::pin(async move {
            let writer = match writers.get(&to) {
                Some(w) => w.value().clone(),
                None => return Err(TransportError::PeerNotFound(to)),
            };

            let rpc = Rpc::new(address, payload);
            let data = rpc.to_bytes();

            Self::send_framed(&writer, &data)
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
