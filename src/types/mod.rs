//! Core type definitions for blockchain primitives.
//!
//! This module provides fundamental types used throughout the blockchain:
//! - `Hash`: Fixed-size 32-byte SHA3-256 hashes
//! - `BinaryCodec`: Trait for deterministic serialization and hashing
//!
//! All types are optimized for blockchain workloads with minimal allocations
//! and efficient memory layouts.

pub mod address;
pub mod binary_codec;
pub mod hash;
pub mod serializable_bytes;
pub mod serializable_signature;
