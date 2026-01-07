//! Network layer for peer-to-peer communication in the blockchain.
//!
//! Provides transport abstractions and server infrastructure for
//! exchanging messages between blockchain nodes.

pub mod libp2p_transport;
pub mod local_transport;
pub mod message;
pub mod rpc;
pub mod server;
pub mod transport;
