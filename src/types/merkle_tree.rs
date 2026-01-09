//! Merkle tree helpers for producing deterministic roots for blocks/transactions.
//!
//! Behavior:
//! - An empty list of leaves yields the all-zero hash (`Hash::zero()`).
//! - Odd layers are padded by duplicating the last leaf before hashing the pair.
//! - Tree construction is performed in-place to minimize allocations.

use crate::core::transaction::Transaction;
use crate::types::hash::Hash;

const EMPTY_VEC_HASH: Hash = Hash::zero();
const MERKLE_NODE_SEPARATION: &[u8] = b"MERKLE_STATE_NODE";

/// Utility functions to build Merkle roots from hashes or transactions.
pub struct MerkleTree;

impl MerkleTree {
    fn hash_pair(left: Hash, right: Hash) -> Hash {
        let mut h = Hash::sha3();
        h.update(MERKLE_NODE_SEPARATION);
        h.update(left.as_slice());
        h.update(right.as_slice());
        h.finalize()
    }

    /// Computes a Merkle root from the provided leaf hashes.
    ///
    /// This performs an in-place reduction; when a level has an odd number
    /// of nodes the last node is duplicated for hashing that pair.
    /// Returns the zero hash when `nodes` is empty.
    pub fn from_raw(mut nodes: Vec<Hash>) -> Hash {
        if nodes.is_empty() {
            return EMPTY_VEC_HASH;
        }

        let mut len = nodes.len();

        while len > 1 {
            let mut write = 0;
            let mut read = 0;

            while read < len {
                let left = nodes[read];
                let right = if read + 1 < len {
                    nodes[read + 1]
                } else {
                    left
                };

                nodes[write] = Self::hash_pair(left, right);

                write += 1;
                read += 2;
            }

            len = write;
        }

        nodes[0]
    }

    /// Computes a Merkle root from transactions, using `tx.id(chain_id)` as leaves.
    ///
    /// Returns the zero hash when `txs` is empty.
    pub fn from_transactions(txs: &[Transaction], chain_id: u64) -> Hash {
        if txs.is_empty() {
            return EMPTY_VEC_HASH;
        }

        let mut nodes = Vec::with_capacity(txs.len());
        for tx in txs {
            nodes.push(tx.id(chain_id));
        }

        Self::from_raw(nodes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::key_pair::PrivateKey;
    use crate::types::bytes::Bytes;

    fn hash_leaf(data: &[u8]) -> Hash {
        let mut h = Hash::sha3();
        h.update(data);
        h.finalize()
    }

    #[test]
    fn empty_returns_zero_hash() {
        assert_eq!(MerkleTree::from_raw(Vec::new()), Hash::zero());
    }

    #[test]
    fn single_leaf_returns_leaf() {
        let leaf = hash_leaf(b"leaf");
        assert_eq!(MerkleTree::from_raw(vec![leaf]), leaf);
    }

    #[test]
    fn even_number_of_leaves_matches_manual_reduction() {
        let a = hash_leaf(b"a");
        let b = hash_leaf(b"b");
        let c = hash_leaf(b"c");
        let d = hash_leaf(b"d");

        let level1 = [MerkleTree::hash_pair(a, b), MerkleTree::hash_pair(c, d)];
        let expected_root = MerkleTree::hash_pair(level1[0], level1[1]);

        assert_eq!(MerkleTree::from_raw(vec![a, b, c, d]), expected_root);
    }

    #[test]
    fn odd_number_of_leaves_duplicates_last_for_padding() {
        let a = hash_leaf(b"a");
        let b = hash_leaf(b"b");
        let c = hash_leaf(b"c");

        let left = MerkleTree::hash_pair(a, b);
        let right = MerkleTree::hash_pair(c, c);
        let expected_root = MerkleTree::hash_pair(left, right);

        assert_eq!(MerkleTree::from_raw(vec![a, b, c]), expected_root);
    }

    #[test]
    fn from_transactions_matches_explicit_id_merkle_root() {
        let chain_id = 7;
        let key1 = PrivateKey::from_bytes(&[1u8; 32]).expect("valid key");
        let key2 = PrivateKey::from_bytes(&[2u8; 32]).expect("valid key");

        let txs = vec![
            Transaction::builder(Bytes::new(b"alpha"), key1, chain_id).build(),
            Transaction::builder(Bytes::new(b"beta"), key2, chain_id).build(),
        ];

        let ids: Vec<Hash> = txs.iter().map(|tx| tx.id(chain_id)).collect();
        let expected = MerkleTree::from_raw(ids);

        assert_eq!(MerkleTree::from_transactions(&txs, chain_id), expected);
    }
}
