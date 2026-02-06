//! Transaction structure with reference-counted data storage.

use crate::core::validator::TRANSACTION_MAX_BYTES;
use crate::crypto::key_pair::{Address, PrivateKey, PublicKey, SerializableSignature};
use crate::types::bytes::Bytes;
use crate::types::encoding::Encode;
use crate::types::hash::{Hash, HashCache};
use blockchain_derive::BinaryCodec;

/// Specifies the type of operation a transaction performs.
#[derive(Debug, Clone, Copy, Eq, PartialEq, BinaryCodec)]
pub enum TransactionType {
    /// Native token transfer between accounts.
    TransferFunds,
    /// Smart contract deployment with bytecode in the data field.
    DeployContract,
    /// Invokes an existing smart contract.
    InvokeContract,
}

/// A blockchain transaction containing arbitrary data.
///
/// Uses `Bytes` for zero-copy sharing - transactions are immutable after creation
/// and often referenced by multiple blocks during reorganizations.
#[derive(Debug, Clone, PartialEq, Eq, BinaryCodec)]
#[binary_codec(max_size = TRANSACTION_MAX_BYTES)]
pub struct Transaction {
    /// Sender's public key, also used for signature verification.
    pub from: PublicKey,
    /// Schnorr signature over the transaction hash.
    pub signature: SerializableSignature,

    /// Cached transaction ID, computed lazily on first access, do not use directly.
    cached_id: HashCache,

    /// Recipient account (EOA or contract) for value or call execution.
    pub to: Address,
    /// Optional sponsor that pays gas on behalf of the sender.
    pub gas_sponsor: Option<Address>,
    /// Arbitrary transaction payload (e.g., contract call data or bytecode).
    pub data: Bytes,

    /// Native token amount to transfer to the recipient.
    pub amount: u128,
    /// Additional fee per gas unit paid directly to the block validator.
    ///
    /// Transactions with higher priority fees are selected first during block building,
    /// allowing senders to bid for faster inclusion during network congestion.
    pub priority_fee: u128,

    /// Price per gas unit offered by the sender.
    pub gas_price: u128,
    /// Maximum gas the sender authorizes for execution.
    pub gas_limit: u64,
    /// Monotonic counter preventing replay for this sender.
    pub nonce: u64,

    /// Operation type determining how the transaction is processed.
    pub tx_type: TransactionType,
}

impl Transaction {
    /// Creates a new signed transaction.
    ///
    /// Signs the transaction data with the provided private key, binding it
    /// to the specified chain to prevent cross-chain replay attacks.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        to: Address,
        gas_sponsor: Option<Address>,
        data: impl Into<Bytes>,
        amount: u128,
        priority_fee: u128,
        gas_price: u128,
        gas_limit: u64,
        nonce: u64,
        from: PrivateKey,
        chain_id: u64,
        tx_type: TransactionType,
    ) -> Self {
        let data = data.into();
        let from_pk = from.public_key();

        let signing_hash = Transaction::signing_hash_from_parts(
            chain_id,
            &from_pk,
            &to,
            &gas_sponsor,
            &data,
            amount,
            priority_fee,
            gas_price,
            gas_limit,
            nonce,
            tx_type,
        );

        Transaction {
            from: from_pk,
            signature: from.sign(signing_hash.as_slice()),
            cached_id: HashCache::new(),
            to,
            gas_sponsor,
            data,
            amount,
            priority_fee,
            gas_price,
            gas_limit,
            nonce,
            tx_type,
        }
    }

    /// Returns the bytes that were signed to produce this transaction's signature.
    ///
    /// Used during verification to reconstruct the signed message.
    pub fn signing_bytes(&self, chain_id: u64) -> Hash {
        Self::signing_hash_from_parts(
            chain_id,
            &self.from,
            &self.to,
            &self.gas_sponsor,
            &self.data,
            self.amount,
            self.priority_fee,
            self.gas_price,
            self.gas_limit,
            self.nonce,
            self.tx_type,
        )
    }

    /// Returns the unique transaction identifier.
    ///
    /// Computed from the full transaction including signature, ensuring uniqueness
    /// even for identical payloads signed by different keys. Result is cached.
    pub fn id(&self, chain_id: u64) -> Hash {
        self.cached_id.get_or_compute(chain_id, || {
            let mut h = Hash::sha3();
            h.update(b"TXID");
            chain_id.encode(&mut h);
            self.encode(&mut h);
            h.finalize()
        })
    }

    /// Verifies the transaction signature against the sender's public key.
    ///
    /// Returns `true` if the signature is valid for the given chain ID.
    pub fn verify(&self, chain_id: u64) -> bool {
        let hash = self.signing_bytes(chain_id);
        self.from.verify(hash.as_slice(), self.signature)
    }

    /// Computes the chain-bound signing hash from raw parts without allocations.
    #[allow(clippy::too_many_arguments)]
    fn signing_hash_from_parts(
        chain_id: u64,
        from: &PublicKey,
        recipient: &Address,
        gas_sponsor: &Option<Address>,
        data: &Bytes,
        amount: u128,
        priority_fee: u128,
        gas_price: u128,
        gas_limit: u64,
        nonce: u64,
        tx_type: TransactionType,
    ) -> Hash {
        let mut buf = Hash::sha3();
        buf.update(b"TX");
        chain_id.encode(&mut buf);
        from.encode(&mut buf);
        recipient.encode(&mut buf);
        gas_sponsor.encode(&mut buf);
        data.encode(&mut buf);
        amount.encode(&mut buf);
        priority_fee.encode(&mut buf);
        gas_price.encode(&mut buf);
        gas_limit.encode(&mut buf);
        nonce.encode(&mut buf);
        tx_type.encode(&mut buf);
        buf.finalize()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::validator::TRANSACTION_MAX_BYTES;
    use crate::types::encoding::{Decode, DecodeError};
    use crate::utils::test_utils::utils::new_tx;

    const TEST_CHAIN_ID: u64 = 32;

    #[test]
    fn new_creates_valid_transaction() {
        let key = PrivateKey::new();
        let data = Bytes::new(b"test data");
        let tx = new_tx(data.clone(), key, TEST_CHAIN_ID);

        assert_eq!(tx.data, data);
        assert!(tx.verify(TEST_CHAIN_ID));
    }

    #[test]
    fn verify_fails_with_wrong_public_key() {
        let key1 = PrivateKey::new();
        let key2 = PrivateKey::new();
        let data = Bytes::new(b"payload");

        let tx = new_tx(data, key1, TEST_CHAIN_ID);
        let mut tampered = tx.clone();
        tampered.from = key2.public_key();

        assert!(!tampered.verify(TEST_CHAIN_ID));
    }

    #[test]
    fn verify_fails_with_tampered_data() {
        let key = PrivateKey::new();
        let tx = new_tx(Bytes::new(b"original"), key, TEST_CHAIN_ID);
        let mut tampered = tx.clone();
        tampered.data = Bytes::new(b"tampered");

        assert!(!tampered.verify(TEST_CHAIN_ID));
    }

    #[test]
    fn verify_succeeds_with_empty_data() {
        let key = PrivateKey::new();
        let tx = new_tx(Bytes::new(b""), key, TEST_CHAIN_ID);
        assert!(tx.verify(TEST_CHAIN_ID));
    }

    #[test]
    fn verify_succeeds_with_large_data() {
        let key = PrivateKey::new();
        let large_data = vec![0xAB; 100_000];
        let tx = new_tx(Bytes::new(large_data), key, TEST_CHAIN_ID);
        assert!(tx.verify(TEST_CHAIN_ID));
    }

    #[test]
    fn serialize_deserialize_roundtrip() {
        let key = PrivateKey::new();
        let binary_data: Vec<u8> = (0..=255).collect();
        let tx = new_tx(Bytes::new(binary_data), key, TEST_CHAIN_ID);

        let encoded: Bytes = tx.to_bytes();
        let decoded = Transaction::from_bytes(encoded.as_slice()).expect("deserialization failed");

        assert_eq!(tx, decoded);
        assert!(decoded.verify(TEST_CHAIN_ID));
    }

    #[test]
    fn hash_is_deterministic() {
        let key = PrivateKey::new();
        let tx = new_tx(Bytes::new(b"hash test"), key, TEST_CHAIN_ID);

        let hash1 = tx.id(TEST_CHAIN_ID);
        let hash2 = tx.id(TEST_CHAIN_ID);

        assert_eq!(hash1, hash2, "rehashing twice");
        assert_eq!(tx.id(TEST_CHAIN_ID), hash1);
        assert_eq!(tx.id(TEST_CHAIN_ID), hash2);
    }

    #[test]
    fn same_data_different_keys_have_different_hashes() {
        let key1 = PrivateKey::new();
        let key2 = PrivateKey::new();
        let data = b"identical data";

        let tx1 = new_tx(Bytes::new(data), key1, TEST_CHAIN_ID);
        let tx2 = new_tx(Bytes::new(data), key2, TEST_CHAIN_ID);

        let hash1 = tx1.id(TEST_CHAIN_ID);
        let hash2 = tx2.id(TEST_CHAIN_ID);

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn decode_rejects_oversized_length_prefix() {
        let key = PrivateKey::new();
        let tx = new_tx(Bytes::new(b"small"), key, TEST_CHAIN_ID);

        let mut encoded = tx.to_vec();

        // Replace length prefix with value exceeding TRANSACTION_MAX_BYTES
        let fake_len = (TRANSACTION_MAX_BYTES + 1) as u64;
        encoded[..8].copy_from_slice(&fake_len.to_le_bytes());

        let result = Transaction::from_bytes(&encoded);
        assert!(matches!(
            result,
            Err(DecodeError::LengthOverflow {
                type_name: "Transaction",
                ..
            })
        ));
    }

    #[test]
    fn decode_rejects_trailing_bytes() {
        let key = PrivateKey::new();
        let tx = new_tx(Bytes::new(b"data"), key, TEST_CHAIN_ID);

        let mut encoded = tx.to_vec();
        encoded.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);

        // from_bytes requires all bytes to be consumed
        let result = Transaction::from_bytes(&encoded);
        assert!(matches!(result, Err(DecodeError::InvalidValue)));
    }

    #[test]
    fn decode_fails_on_truncated_input() {
        let key = PrivateKey::new();
        let tx = new_tx(Bytes::new(b"test data"), key, TEST_CHAIN_ID);

        let encoded = tx.to_bytes();

        // Try decoding with progressively shorter input
        for truncate_at in [0, 4, 8, encoded.len() / 2, encoded.len() - 1] {
            let truncated = &encoded[..truncate_at];
            let result = Transaction::from_bytes(truncated);
            assert!(
                result.is_err(),
                "should fail at truncation point {truncate_at}"
            );
        }
    }

    #[test]
    fn decode_fails_on_empty_input() {
        let result = Transaction::from_bytes(&[]);
        assert!(matches!(result, Err(DecodeError::UnexpectedEof)));
    }

    #[test]
    fn encoding_is_deterministic() {
        let key = PrivateKey::new();
        let tx = new_tx(Bytes::new(b"determinism test"), key, TEST_CHAIN_ID);

        let encoded1 = tx.to_bytes();
        let encoded2 = tx.to_bytes();
        let encoded3 = tx.to_bytes();

        assert_eq!(encoded1, encoded2);
        assert_eq!(encoded2, encoded3);
    }

    #[test]
    fn roundtrip_with_empty_data() {
        let key = PrivateKey::new();
        let tx = new_tx(Bytes::new(b""), key, TEST_CHAIN_ID);

        let encoded = tx.to_bytes();
        let decoded = Transaction::from_bytes(encoded.as_slice()).expect("decode failed");

        assert_eq!(tx, decoded);
    }

    #[test]
    fn roundtrip_with_max_safe_data_size() {
        let key = PrivateKey::new();
        // Use a size that's large but won't exceed TRANSACTION_MAX_BYTES when combined
        // with transaction overhead (signature, addresses, etc.)
        let data = vec![0xFF; 90_000];
        let tx = new_tx(Bytes::new(data), key, TEST_CHAIN_ID);

        let encoded = tx.to_bytes();
        let decoded = Transaction::from_bytes(encoded.as_slice()).expect("decode failed");

        assert_eq!(tx, decoded);
        assert!(tx.verify(TEST_CHAIN_ID));
    }

    #[test]
    fn decode_inner_preserves_all_fields() {
        let key = PrivateKey::new();
        let original = new_tx(Bytes::new(b"field preservation test"), key, TEST_CHAIN_ID);

        let encoded = original.to_bytes();
        let decoded = Transaction::from_bytes(encoded.as_slice()).expect("decode failed");

        assert_eq!(original.from, decoded.from);
        assert_eq!(original.signature, decoded.signature);
        assert_eq!(original.to, decoded.to);
        assert_eq!(original.gas_sponsor, decoded.gas_sponsor);
        assert_eq!(original.data, decoded.data);
        assert_eq!(original.amount, decoded.amount);
        assert_eq!(original.priority_fee, decoded.priority_fee);
        assert_eq!(original.gas_price, decoded.gas_price);
        assert_eq!(original.gas_limit, decoded.gas_limit);
        assert_eq!(original.nonce, decoded.nonce);
        assert_eq!(original.tx_type, decoded.tx_type);
    }

    #[test]
    fn multiple_transactions_decode_sequentially() {
        let key = PrivateKey::new();
        let tx1 = new_tx(Bytes::new(b"first"), key.clone(), TEST_CHAIN_ID);
        let tx2 = new_tx(Bytes::new(b"second"), key.clone(), TEST_CHAIN_ID);
        let tx3 = new_tx(Bytes::new(b"third"), key, TEST_CHAIN_ID);

        let mut buffer = Vec::new();
        tx1.encode(&mut buffer);
        tx2.encode(&mut buffer);
        tx3.encode(&mut buffer);

        let mut slice = buffer.as_slice();
        let decoded1 = Transaction::decode(&mut slice).expect("tx1 decode failed");
        let decoded2 = Transaction::decode(&mut slice).expect("tx2 decode failed");
        let decoded3 = Transaction::decode(&mut slice).expect("tx3 decode failed");

        assert!(slice.is_empty(), "all bytes should be consumed");
        assert_eq!(tx1, decoded1);
        assert_eq!(tx2, decoded2);
        assert_eq!(tx3, decoded3);
    }
}
