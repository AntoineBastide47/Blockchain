//! Register-based bytecode virtual machine for smart contract execution.
//!
//! The VM executes smart-contract bytecode produced by the assembler and is used by
//! the blockchain runtime for both contract deployment and contract invocation.
//!
//! # Architecture
//!
//! - **Registers**: 256 registers storing typed [`vm::Value`]s (`Int`, `Bool`, `Ref`)
//! - **Zero register**: `r0` is hardwired to integer zero (writes are ignored)
//! - **Instruction format**: Variable-length bytecode with compact operand metadata
//! - **Execution model**: Supports arithmetic, branching, calls/returns, calldata,
//!   memory operations, state operations, and hashing
//! - **Gas metering**: Execution is bounded by a gas limit with category profiling
//!
//! # Program model
//!
//! - [`program::DeployProgram`]: contract init/runtime bytecode plus const memory
//! - [`program::ExecuteProgram`]: typed call payload for invoking a deployed contract
//!
//! # Modules
//!
//! - [`assembler`]: Assembly parsing, diagnostics, and bytecode generation
//! - [`errors`]: Assembly and execution error types
//! - [`isa`]: Instruction set definition and opcode mappings
//! - [`operand`]: Compact operand encoding/decoding helpers
//! - [`program`]: Deploy/execute bytecode program formats
//! - [`state`]: VM state trait and overlay state utilities
//! - [`vm`]: Core virtual machine implementation and gas metering

pub mod assembler;
pub mod errors;
pub mod isa;
#[cfg(test)]
mod isa_static_check;
pub mod operand;
pub mod program;
pub mod state;
pub mod vm;
