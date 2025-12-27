//! Test utilities for blockchain testing.

#[cfg(test)]
pub mod utils {
    use crate::core::block::{Block, Header};
    use crate::crypto::key_pair::PrivateKey;
    use crate::types::hash::{HASH_LEN, Hash};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    pub fn random_hash() -> Hash {
        let mut buf = vec![0u8; HASH_LEN];
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        buf[..8].copy_from_slice(&n.to_le_bytes());
        Hash::from_vec(buf)
    }

    pub fn create_genesis() -> Arc<Block> {
        let header = Header {
            version: 1,
            height: 0,
            timestamp: 0,
            previous_block: Hash::zero(),
            data_hash: random_hash(),
            merkle_root: Hash::zero(),
        };
        Block::new(header, PrivateKey::new(), vec![])
    }
}
