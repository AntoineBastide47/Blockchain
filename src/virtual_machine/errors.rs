use crate::types::encoding::DecodeError;
use blockchain_derive::Error;

/// Errors that can occur during VM execution or assembly.
#[derive(Debug, Error)]
pub enum VMError {
    /// Unknown opcode encountered in bytecode.
    #[error("invalid instruction opcode 0x{opcode:02X} at byte offset {offset}")]
    InvalidInstruction { opcode: u8, offset: usize },
    /// Unrecognized instruction mnemonic.
    #[error("unknown instruction mnemonic '{name}'")]
    InvalidInstructionName { name: String },
    /// Wrong number of operands for an instruction.
    #[error("operand count mismatch for {instruction}: expected {expected}, got {actual}")]
    ArityMismatch {
        instruction: String,
        expected: u8,
        actual: u8,
    },
    /// Wrong number of operands for an instruction.
    #[error(
        "operand count mismatch for {instruction}: expected between {min} and {max}, got {actual}"
    )]
    ArityMismatchDyn {
        instruction: String,
        min: u8,
        max: u8,
        actual: u8,
    },
    /// Expected a register operand (e.g., `r0`) but got something else.
    #[error("expected register operand (e.g., r0) but got '{0}', did you mean 'r{0}' ?")]
    ExpectedRegister(String),
    /// Register index out of range or malformed.
    #[error("register or reference '{token}' is invalid or malformed")]
    InvalidRegister { token: String },
    /// Register index exceeds the register file size.
    #[error("register index {index} is out of bounds (register file has {available} slots)")]
    InvalidRegisterIndex { index: u8, available: usize },
    /// Argument count is outside the valid 0..=255 range.
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
    #[error("assembly error at line {line}, column {offset}-{offset + length}: {source}")]
    AssemblyError {
        line: usize,
        offset: usize,
        length: usize,
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
    /// Heap reference contains bytes that are not valid UTF-8.
    #[error("string #{string_ref} is not valid UTF-8")]
    InvalidUtf8 { string_ref: u32 },
    /// Token-level parse error with a static message.
    #[error("parse error at line {line}, column {offset}: {message}")]
    ParseError {
        line: usize,
        offset: usize,
        message: &'static str,
    },
    /// Token-level parse error with a dynamic message and span length.
    #[error("parse error at line {line}, column {offset}-{offset+length}: {message}")]
    ParseErrorString {
        line: usize,
        offset: usize,
        length: usize,
        message: String,
    },
    /// Hash value has wrong byte length.
    #[error("invalid hash format: expected {expected_len} bytes but got {actual_len}")]
    InvalidHash {
        expected_len: usize,
        actual_len: usize,
    },
    /// Computed jump target falls outside the bytecode range.
    #[error("jump target is out of bounds: from {from} to {to} max {max}")]
    JumpOutOfBounds { from: usize, to: usize, max: usize },
    /// Dispatch selector exceeds the number of entries in the dispatch table.
    #[error("dispatch selector {selector} out of bounds, table has {count} entries")]
    DispatchOutOfBounds { selector: usize, count: usize },
    /// Gas consumption exceeded the execution limit.
    #[error("out of gas: used {used}, limit {limit}")]
    OutOfGas { used: u64, limit: u64 },
    /// Heap reference index exceeds the number of allocated items.
    #[error("reference out of bounds, max: {max} got: {reference}")]
    ReferenceOutOfBounds { reference: usize, max: usize },
    /// Nested function calls exceeded the maximum call stack depth.
    #[error("call stack overflow got {actual} while max is {max}")]
    CallStackOverflow { max: usize, actual: usize },
    /// Operand tag byte does not correspond to a known type.
    #[error("invalid operand tag got {tag} at offset {offset}")]
    InvalidOperandTag { tag: u8, offset: usize },
    /// Operand type does not match the instruction's expected operand type.
    #[error(
        "invalid operand type for {instruction} argument {argc}, expected 'register or {expected}' got '{actual}'"
    )]
    InvalidOperand {
        instruction: &'static str,
        argc: usize,
        expected: &'static str,
        actual: &'static str,
    },
    /// Comparison between incompatible value types.
    #[error("cannot compare types {type1} and {type2}")]
    InvalidComparison {
        type1: &'static str,
        type2: &'static str,
    },
    /// Memory access exceeded the heap bounds.
    #[error("trying to read out of memory bounds, memory size: {max} read index: {got}")]
    MemoryOOBRead { got: usize, max: usize },
}

impl From<DecodeError> for VMError {
    fn from(value: DecodeError) -> Self {
        VMError::DecodeError {
            reason: value.to_string(),
        }
    }
}
