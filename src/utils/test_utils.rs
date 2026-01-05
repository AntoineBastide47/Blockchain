//! Test utilities for blockchain testing.

#[cfg(test)]
pub mod utils {
    use crate::core::block::{Block, Header};
    use crate::crypto::key_pair::PrivateKey;
    use crate::network::rpc::Rpc;
    use crate::types::bytes::Bytes;
    use crate::types::hash::{HASH_LEN, Hash};
    use libp2p::Multiaddr;
    use std::net::{IpAddr, SocketAddr};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    /// Generates a unique deterministic hash for testing.
    ///
    /// Each call returns a different hash based on an incrementing counter,
    /// ensuring test reproducibility while avoiding collisions.
    pub fn random_hash() -> Hash {
        let mut buf = vec![0u8; HASH_LEN];
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        buf[..8].copy_from_slice(&n.to_le_bytes());
        let mut value = [0u8; HASH_LEN];
        value.copy_from_slice(buf.as_slice());
        Hash(value)
    }

    /// Creates a genesis block for testing with the given chain ID.
    ///
    /// Uses a random validator key and random data hash to ensure
    /// test isolation between runs.
    pub fn create_genesis(chain_id: u64) -> Arc<Block> {
        let header = Header {
            version: 1,
            height: 0,
            timestamp: 0,
            previous_block: Hash::zero(),
            merkle_root: Hash::zero(),
            state_root: Hash::zero(),
        };
        Block::new(header, PrivateKey::new(), vec![], chain_id)
    }

    /// Creates an RPC message for testing with a zeroed peer ID.
    ///
    /// Bypasses the authenticated peer ID that would normally come from
    /// the Noise handshake, using [`Hash::zero()`] as a placeholder.
    pub fn test_rpc(_from: SocketAddr, payload: impl Into<Bytes>) -> Rpc {
        Rpc {
            payload: payload.into(),
            peer_id: Hash::zero(),
        }
    }

    /// Converts a libp2p Multiaddr to a SocketAddr if possible.
    pub fn multiaddr_to_socket_addr(addr: &Multiaddr) -> Option<SocketAddr> {
        let mut ip = None;
        let mut port = None;

        for protocol in addr.iter() {
            match protocol {
                libp2p::multiaddr::Protocol::Ip4(v4) => ip = Some(IpAddr::V4(v4)),
                libp2p::multiaddr::Protocol::Ip6(v6) => ip = Some(IpAddr::V6(v6)),
                libp2p::multiaddr::Protocol::Tcp(p) => port = Some(p),
                _ => {}
            }
        }

        match (ip, port) {
            (Some(ip), Some(port)) => Some(SocketAddr::new(ip, port)),
            _ => None,
        }
    }

    /// Converts a SocketAddr to a libp2p Multiaddr.
    pub fn socket_addr_to_multiaddr(addr: SocketAddr) -> Multiaddr {
        let mut multiaddr = match addr.ip() {
            IpAddr::V4(ip) => Multiaddr::from(ip),
            IpAddr::V6(ip) => Multiaddr::from(ip),
        };
        multiaddr.push(libp2p::multiaddr::Protocol::Tcp(addr.port()));
        multiaddr
    }
}
