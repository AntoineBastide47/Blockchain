//! Transaction execution receipts.
//!
//! Each successfully executed transaction produces a [`Receipt`] recording
//! the execution outcome. Receipts are committed atomically with their block
//! and their hashes form a Merkle tree whose root is stored in the block header.

use crate::types::encoding::Encode;
use crate::types::hash::Hash;
use blockchain_derive::BinaryCodec;

/// Record of a single transaction's execution result within a block.
#[derive(Clone, Debug, PartialEq, Eq, BinaryCodec)]
pub struct Receipt {
    /// Hash of the transaction that produced this receipt.
    pub tx_hash: Hash,
    /// Whether the transaction executed successfully.
    pub success: bool,
    /// Gas consumed by this individual transaction.
    pub gas_used: u64,
    /// Running total of gas consumed by all transactions up to and including this one.
    pub cumulative_gas_used: u64,
    /// Data returned by the transaction execution (empty for transfers).
    pub return_data: Vec<u8>,
}

impl Receipt {
    /// Computes a domain-separated hash of this receipt.
    ///
    /// The `"RECEIPT"` prefix prevents collisions with other hash domains.
    pub fn hash(&self) -> Hash {
        let mut h = Hash::sha3();
        h.update(b"RECEIPT");
        self.encode(&mut h);
        h.finalize()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::encoding::Decode;

    fn sample_receipt() -> Receipt {
        Receipt {
            tx_hash: Hash::sha3().chain(b"tx1").finalize(),
            success: true,
            gas_used: 21_000,
            cumulative_gas_used: 21_000,
            return_data: vec![1, 2, 3],
        }
    }

    #[test]
    fn receipt_encode_decode_roundtrip() {
        let receipt = sample_receipt();
        let bytes = receipt.to_bytes();
        let decoded = Receipt::from_bytes(bytes.as_slice()).expect("decode failed");
        assert_eq!(receipt, decoded);
    }

    #[test]
    fn receipt_hash_deterministic() {
        let receipt = sample_receipt();
        let h1 = receipt.hash();
        let h2 = receipt.hash();
        assert_eq!(h1, h2);
    }

    #[test]
    fn receipt_hash_domain_separated() {
        let receipt = sample_receipt();
        let receipt_hash = receipt.hash();

        // Hash without domain separator should differ
        let mut h = Hash::sha3();
        receipt.encode(&mut h);
        let raw_hash = h.finalize();

        assert_ne!(receipt_hash, raw_hash);
    }

    #[test]
    fn different_receipts_different_hashes() {
        let r1 = sample_receipt();
        let mut r2 = sample_receipt();
        r2.gas_used = 42_000;

        let mut r3 = sample_receipt();
        r3.tx_hash = Hash::sha3().chain(b"tx2").finalize();

        let mut r4 = sample_receipt();
        r4.return_data = vec![4, 5, 6];

        let mut r5 = sample_receipt();
        r5.success = false;

        let hashes = [r1.hash(), r2.hash(), r3.hash(), r4.hash(), r5.hash()];
        for i in 0..hashes.len() {
            for j in (i + 1)..hashes.len() {
                assert_ne!(hashes[i], hashes[j], "receipts {i} and {j} collide");
            }
        }
    }
}
