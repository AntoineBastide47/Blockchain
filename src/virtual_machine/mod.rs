//! Register-based bytecode virtual machine for smart contract execution.
//!
//! This module provides a simple VM with 256 general-purpose registers and a basic
//! instruction set for arithmetic and comparison operations. The VM executes bytecode
//! assembled from a human-readable assembly format.
//!
//! # Architecture
//!
//! - **Registers**: 256 64-bit integer registers (r0-r255)
//! - **Instruction format**: Variable-length encoded bytecode
//! - **Execution model**: Sequential instruction execution with no branching (yet)
//!
//! # Modules
//!
//! - [`vm`]: Core virtual machine implementation
//! - [`isa`]: Instruction set architecture and bytecode encoding
//! - [`assembler`]: Assembly source to bytecode compilation

mod assembler;
mod isa;
pub mod vm;
