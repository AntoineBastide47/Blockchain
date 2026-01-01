use blockchain_derive::Error;

/// Errors that can occur during VM execution or assembly.
#[derive(Debug, Error)]
pub enum VMError {
    /// Unknown opcode encountered in bytecode.
    #[error("invalid instruction: {0}")]
    InvalidInstruction(u8),
    /// Unrecognized instruction mnemonic during assembly.
    #[error("invalid instruction name: {0}")]
    InvalidInstructionName(String),
    /// Wrong number of operands for an instruction.
    #[error("arity mismatch")]
    ArityMismatch,
    /// Expected a register operand (e.g., `r0`) but got something else.
    #[error("expected register, got {0}")]
    ExpectedRegister(String),
    /// Register index out of range or malformed.
    #[error("invalid register {0}")]
    InvalidRegister(String),
    /// Failed to parse an immediate value as i64.
    #[error("invalid i64 literal {0}")]
    InvalidI64(String),
    /// Register index exceeds the register file size.
    #[error("register index {0} out of bounds")]
    InvalidRegisterIndex(u8),
    /// Bytecode ended unexpectedly while reading an instruction.
    #[error("unexpected end of bytecode")]
    UnexpectedEndOfBytecode,
    /// Operand type does not match expected type.
    #[error(
        "instruction {instruction} expected argument {arg_index} to be of type {expected} but got {actual}"
    )]
    TypeMismatch {
        instruction: &'static str,
        arg_index: i32,
        expected: &'static str,
        actual: String,
    },
    /// Instruction pointer overflow or out of bounds.
    #[error("invalid instruction pointer")]
    InvalidIP,
    /// Division or modulo by zero.
    #[error("division by zero")]
    DivisionByZero,
    /// Assembly error with line number context.
    #[error("line {line}: {source}")]
    AssemblyError { line: usize, source: String },
    /// File I/O error during assembly.
    #[error("io error: {0}")]
    IoError(String),
    /// Unknown host function called via CALL_HOST instruction.
    #[error("invalid CALL_HOST function name {0}")]
    InvalidCallHostFunction(String),
    /// Failed to decode program bytecode.
    #[error("decoding error: {0}")]
    DecodeError(String),
    /// Key not found in state storage.
    #[error("key not found in state: {0}")]
    KeyNotFound(String),
    /// State value has invalid format for the expected type.
    #[error("invalid state value format")]
    InvalidStateValue,
}
