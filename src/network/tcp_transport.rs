//! TCP-based transport implementation for real network communication.
//!
//! Provides length-prefixed framing over TCP with per-peer connection management.
//! Uses split read/write halves for concurrent IO on each connection.

use crate::impl_transport_consume;
use crate::network::rpc::Rpc;
use crate::network::transport::{Transport, TransportError, spawn_rpc_forwarder};
use crate::types::bytes::Bytes;
use crate::types::encoding::{Decode, Encode};
use crate::types::wrapper_types::BoxFuture;
use dashmap::DashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::OwnedWriteHalf;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio::sync::mpsc::{Receiver, Sender, channel};

/// TCP transport for blockchain network communication.
///
/// Manages TCP connections to peers with length-prefixed message framing.
/// Each peer connection is stored as a write half keyed by address.
pub struct TcpTransport {
    /// Address this transport listens on.
    listen_address: SocketAddr,
    /// Write halves of peer connections, keyed by peer address.
    writers: DashMap<SocketAddr, Arc<Mutex<OwnedWriteHalf>>>,
    /// Channel sender for incoming RPCs.
    tx: Sender<Rpc>,
    /// Channel receiver for incoming RPCs (taken once by consume).
    rx: Arc<Mutex<Option<Receiver<Rpc>>>>,
}

impl TcpTransport {
    /// Creates a new TCP transport bound to the given address.
    ///
    /// The transport must be started with `start()` before it can accept connections.
    pub fn new(address: SocketAddr) -> Arc<Self> {
        let (tx, rx) = channel(1024);

        Arc::new(Self {
            listen_address: address,
            writers: DashMap::new(),
            tx,
            rx: Arc::new(Mutex::new(Some(rx))),
        })
    }

    async fn read_loop(mut reader: tokio::net::tcp::OwnedReadHalf, tx: Sender<Rpc>) {
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

    async fn accept_loop(addr: SocketAddr, tx: Sender<Rpc>) {
        let listener = match TcpListener::bind(addr).await {
            Ok(l) => l,
            Err(_) => return,
        };

        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let (reader, _writer) = stream.into_split();
                    let tx = tx.clone();
                    tokio::spawn(async move {
                        Self::read_loop(reader, tx).await;
                    });
                }
                Err(_) => continue,
            }
        }
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
        match TcpStream::connect(target_addr).await {
            Ok(stream) => {
                let (reader, writer) = stream.into_split();
                transport
                    .writers
                    .insert(target_addr, Arc::new(Mutex::new(writer)));
                tokio::spawn(Self::read_loop(reader, tx));
                true
            }
            Err(_) => false,
        }
    }
}

impl Transport for TcpTransport {
    fn connect(self: &Arc<Self>, other: &Arc<Self>) {
        let self_clone = self.clone();
        let other_clone = other.clone();
        let other_addr = other.listen_address;
        let self_addr = self.listen_address;
        let self_tx = self.tx.clone();
        let other_tx = other.tx.clone();

        tokio::spawn(async move {
            Self::establish_outbound_connection(self_clone, other_addr, self_tx).await;
        });
        tokio::spawn(async move {
            Self::establish_outbound_connection(other_clone, self_addr, other_tx).await;
        });
    }

    fn connect_async(self: &Arc<Self>, other: &Arc<Self>) -> BoxFuture<'static, bool> {
        let self_clone = self.clone();
        let other_clone = other.clone();
        let other_addr = other.listen_address;
        let self_addr = self.listen_address;
        let self_tx = self.tx.clone();
        let other_tx = other.tx.clone();

        Box::pin(async move {
            let (a, b) = tokio::join!(
                Self::establish_outbound_connection(self_clone, other_addr, self_tx),
                Self::establish_outbound_connection(other_clone, self_addr, other_tx)
            );
            a && b
        })
    }

    fn start(self: &Arc<Self>, sx: Sender<Rpc>) {
        let addr = self.listen_address;
        let tx = self.tx.clone();
        tokio::spawn(async move {
            Self::accept_loop(addr, tx).await;
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
