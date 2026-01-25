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
//! - [`isa`]: Instruction set definition and opcode mappings
//! - [`assembler`]: Assembly parsing, IR, and bytecode encoding

pub mod assembler;
pub mod errors;
pub mod isa;
mod isa_static_check;
pub mod operand;
pub mod program;
pub mod state;
pub mod vm;
