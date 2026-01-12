use crate::types::encoding::DecodeError;
use blockchain_derive::Error;

/// Errors that can occur during VM execution or assembly.
#[derive(Debug, Error)]
pub enum VMError {
    /// Unknown opcode encountered in bytecode.
    #[error("invalid instruction opcode 0x{opcode:02X} at byte offset {offset}")]
    InvalidInstruction { opcode: u8, offset: usize },
    /// Unrecognized instruction mnemonic during assembly.
    #[error("unknown instruction mnemonic '{name}' during assembly")]
    InvalidInstructionName { name: String },
    /// Wrong number of operands for an instruction.
    #[error("operand count mismatch for {instruction}: expected {expected}, got {actual}")]
    ArityMismatch {
        instruction: String,
        expected: usize,
        actual: usize,
    },
    /// Expected a register operand (e.g., `r0`) but got something else.
    #[error("expected register operand (e.g., r0) but got '{0}'")]
    ExpectedRegister(String),
    /// Register index out of range or malformed.
    #[error("register or reference '{token}' is invalid or malformed")]
    InvalidRegister { token: String },
    /// Register index exceeds the register file size.
    #[error("register index {index} is out of bounds (register file has {available} slots)")]
    InvalidRegisterIndex { index: u8, available: usize },
    #[error("provided argc is out of range, got {actual} expected 0 <= val <= 255")]
    ArgcOutOfRange { actual: String },
    /// Bytecode ended unexpectedly while reading an instruction.
    #[error(
        "unexpected end of bytecode at offset {ip}: needed {requested} more bytes but only {available} remain"
    )]
    UnexpectedEndOfBytecode {
        ip: usize,
        requested: usize,
        available: usize,
    },
    /// Operand type does not match expected type.
    #[error(
        "type mismatch in {instruction} for argument {arg_index}: expected {expected}, got {actual}"
    )]
    TypeMismatchStatic {
        instruction: &'static str,
        arg_index: i32,
        expected: &'static str,
        actual: &'static str,
    },
    /// Operand type does not match expected type.
    #[error(
        "type mismatch in {instruction} for argument {arg_index}: expected {expected}, got {actual}"
    )]
    TypeMismatch {
        instruction: &'static str,
        arg_index: i32,
        expected: &'static str,
        actual: String,
    },
    /// Instruction pointer overflow or out of bounds.
    #[error("instruction pointer {ip} is out of bounds or overflowed")]
    InvalidIP { ip: usize },
    /// Division or modulo by zero.
    #[error("attempted division or modulo by zero during execution")]
    DivisionByZero,
    /// Assembly error with line/column context.
    #[error("assembly error at line {line}, column {offset}: {source}")]
    AssemblyError {
        line: usize,
        offset: usize,
        source: String,
    },
    /// File I/O error during assembly.
    #[error("I/O failure during assembly at {path}: {source}")]
    IoError { path: String, source: String },
    /// Unknown host function called via CALL_HOST instruction.
    #[error("CALL_HOST invoked with unknown function '{name}'")]
    InvalidCallHostFunction { name: String },
    /// Failed to decode program bytecode.
    #[error("failed to decode program bytecode: {reason}")]
    DecodeError { reason: String },
    /// Key not found in storage.
    #[error("storage key '{key}' not found")]
    KeyNotFound { key: String },
    /// State value has invalid format for the expected type.
    #[error("storage value for key '{key}' has invalid format: expected {expected}")]
    InvalidStateValue { key: String, expected: &'static str },
    /// Label defined more than once.
    #[error("duplicate label definition: '{label}'")]
    DuplicateLabel { label: String },
    /// Reference to undefined label.
    #[error("reference to undefined label '{label}'")]
    UndefinedLabel { label: String },
    /// Call to undefined function.
    #[error("call to undefined function '{function}'")]
    UndefinedFunction { function: String },
    /// Return without matching call.
    #[error(
        "RETURN instruction encountered without matching CALL frame (call stack depth {call_depth})"
    )]
    ReturnWithoutCall { call_depth: usize },
    #[error("string #{string_ref} is not valid UTF-8")]
    InvalidUtf8 { string_ref: u32 },
    #[error("parse error at line {line}, column {offset}: {message}")]
    ParseError {
        line: usize,
        offset: usize,
        message: &'static str,
    },
    #[error("invalid hash format: expected {expected_len} bytes but got {actual_len}")]
    InvalidHash {
        expected_len: usize,
        actual_len: usize,
    },
    #[error("jump target is out of bounds: from {from} to {to} max {max}")]
    JumpOutOfBounds { from: usize, to: i64, max: usize },
    #[error("out of gas: used {used}, limit {limit}")]
    OutOfGas { used: u64, limit: u64 },
    #[error("reference out of bounds, max: {max} got: {reference}")]
    ReferenceOutOfBounds { reference: u32, max: usize },
}

impl From<DecodeError> for VMError {
    fn from(value: DecodeError) -> Self {
        VMError::DecodeError {
            reason: value.to_string(),
        }
    }
}
