//! Test utilities for blockchain testing.

#[cfg(test)]
pub mod utils {
    use crate::core::block::{Block, Header};
    use crate::crypto::key_pair::PrivateKey;
    use crate::types::hash::Hash;
    use std::sync::Arc;

    /// Creates a signed genesis block for testing.
    ///
    /// Returns a block with height 0, zero previous hash,
    /// and a randomly generated data hash.
    #[cfg(test)]
    pub fn create_genesis() -> Arc<Block> {
        let header = Header {
            version: 1,
            height: 0,
            timestamp: 0,
            previous_block: Hash::zero(),
            data_hash: Hash::random(),
            merkle_root: Hash::zero(),
        };
        Block::new(header, PrivateKey::new(), vec![]).unwrap()
    }
}
