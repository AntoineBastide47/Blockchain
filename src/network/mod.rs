//! Network layer for peer-to-peer communication in the blockchain.
//!
//! Provides transport abstractions and server infrastructure for
//! exchanging messages between blockchain nodes.
//!
//! - [`transport`]: Transport trait and error types
//! - [`libp2p_transport`]: Production libp2p-based transport
//! - [`local_transport`]: In-memory transport for testing
//! - [`message`]: Protocol message types for sync and gossip
//! - [`rpc`]: RPC message handling and processor traits
//! - [`server`]: Main server orchestrating message handling
//! - [`sync`]: Header-first sync state machine for chain synchronization

pub mod libp2p_transport;
pub mod local_transport;
pub mod message;
pub mod rpc;
pub mod server;
pub mod sync;
pub mod transport;
