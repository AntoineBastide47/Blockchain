//! Core blockchain data structures.
//!
//! This module contains the fundamental building blocks of the blockchain:
//! - `Block`: Immutable container of transactions with cryptographic linking
//! - `Header`: Block metadata optimized for Copy semantics
//! - `Transaction`: Arbitrary data payload with reference-counted storage
//!
//! All structures use memory-efficient representations tuned for blockchain
//! validation and storage requirements.

pub mod account;
pub mod block;
pub mod blockchain;
pub mod receipt;
pub mod transaction;
pub mod validator;
