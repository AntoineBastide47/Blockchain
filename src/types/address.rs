//! 20-byte blockchain addresses derived from public keys.

use blockchain_derive::BinaryCodec;

/// Fixed-size 20-byte address identifying accounts on the blockchain.
///
/// Derived from public keys via SHA3-256 hashing, taking the last 20 bytes.
/// This type is `Copy` for efficient passing in validation and lookup operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq, BinaryCodec)]
pub struct Address(pub [u8; 20]);
