//! Test utilities for blockchain testing.

#[cfg(test)]
pub mod utils {
    use crate::core::block::{Block, Header};
    use crate::core::transaction::{Transaction, TransactionType};
    use crate::crypto::key_pair::{Address, PrivateKey};
    use crate::network::rpc::Rpc;
    use crate::types::bytes::Bytes;
    use crate::types::hash::{HASH_LEN, Hash};
    use crate::virtual_machine::vm::BLOCK_GAS_LIMIT;
    use libp2p::Multiaddr;
    use std::net::{IpAddr, SocketAddr};
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
    pub fn create_genesis(chain_id: u64) -> Block {
        let header = Header {
            version: 1,
            height: 0,
            timestamp: 0,
            gas_used: BLOCK_GAS_LIMIT,
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

    /// Creates a minimal transaction for testing.
    ///
    /// Uses [`TransactionType::TransferFunds`] with zero amount, fee, and nonce.
    /// Gas price and limit are set to 1 to pass validation.
    pub fn new_tx(data: Bytes, key: PrivateKey, chain_id: u64) -> Transaction {
        Transaction::new(
            Address::zero(),
            None,
            data,
            0,
            0,
            1,
            1,
            0,
            key,
            chain_id,
            TransactionType::TransferFunds,
        )
    }

    /// Creates a transaction with zero gas values for testing validation rejection.
    pub fn new_tx_zero_gas(data: Bytes, key: PrivateKey, chain_id: u64) -> Transaction {
        Transaction::new(
            Address::zero(),
            None,
            data,
            0,
            0,
            0,
            0,
            0,
            key,
            chain_id,
            TransactionType::TransferFunds,
        )
    }

    /// Creates an empty block at the specified height for testing.
    ///
    /// Uses a random validator key and fixed timestamp with zero merkle and state roots.
    pub fn create_test_block(height: u64, previous: Hash, chain_id: u64) -> Block {
        let header = Header {
            version: 1,
            height,
            timestamp: 1234567890,
            gas_used: BLOCK_GAS_LIMIT,
            previous_block: previous,
            merkle_root: Hash::zero(),
            state_root: Hash::zero(),
        };
        Block::new(header, PrivateKey::new(), vec![], chain_id)
    }
}
