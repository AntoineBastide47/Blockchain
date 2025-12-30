//! Assembly language parser and bytecode compiler.
//!
//! Converts human-readable assembly source into executable bytecode.
//!
//! # Syntax
//!
//! ```text
//! INSTRUCTION operand1, operand2, ...  ; optional comment
//! ```
//!
//! - Instructions are uppercase (e.g., `LOAD_I64`, `ADD`)
//! - Registers use `r` prefix (e.g., `r0`, `r255`)
//! - Immediates are decimal integers (e.g., `42`, `-1`)
//! - Comments start with `;`
//! - Commas between operands are optional

use crate::virtual_machine::isa::Instruction;
use crate::virtual_machine::vm::VMError;
use std::fs;
use std::path::Path;

/// Read an assembly source file into a string.
pub fn read_source<P: AsRef<Path>>(path: P) -> Result<String, std::io::Error> {
    fs::read_to_string(path)
}

/// Tokenize a single line of assembly.
///
/// Rules:
/// - `;` starts a comment
/// - commas are ignored
/// - whitespace-separated tokens
fn tokenize(line: &str) -> Vec<String> {
    line.split(';')
        .next()
        .unwrap_or("")
        .replace(',', "")
        .split_whitespace()
        .map(|s| s.to_string())
        .collect()
}

/// Parse a register token like `r0`, `r15`
pub(crate) fn parse_reg(tok: &str) -> Result<u8, VMError> {
    tok.strip_prefix('r')
        .ok_or_else(|| VMError::ExpectedRegister(tok.to_string()))?
        .parse::<u8>()
        .map_err(|_| VMError::InvalidRegister(tok.to_string()))
}

/// Parse an i64 immediate
pub(crate) fn parse_i64(tok: &str) -> Result<i64, VMError> {
    tok.parse::<i64>()
        .map_err(|_| VMError::InvalidI64(tok.to_string()))
}

/// Assemble a full source string into bytecode.
pub fn assemble_source(source: &str) -> Result<Vec<u8>, String> {
    let mut bytecode = Vec::new();

    for (line_no, line) in source.lines().enumerate() {
        let tokens = tokenize(line);
        if tokens.is_empty() {
            continue;
        }

        let instr =
            Instruction::parse(tokens).map_err(|e| format!("line {}: {}", line_no + 1, e))?;

        instr.assemble(&mut bytecode);
    }

    Ok(bytecode)
}

/// Convenience: assemble directly from file path
pub fn assemble_file<P: AsRef<Path>>(path: P) -> Result<Vec<u8>, String> {
    let source = read_source(path).map_err(|e| e.to_string())?;
    assemble_source(&source)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_reg_valid() {
        assert_eq!(parse_reg("r0").unwrap(), 0);
        assert_eq!(parse_reg("r255").unwrap(), 255);
        assert_eq!(parse_reg("r42").unwrap(), 42);
    }

    #[test]
    fn parse_reg_missing_prefix() {
        assert!(matches!(parse_reg("0"), Err(VMError::ExpectedRegister(_))));
        assert!(matches!(parse_reg("x0"), Err(VMError::ExpectedRegister(_))));
    }

    #[test]
    fn parse_reg_invalid_number() {
        assert!(matches!(parse_reg("r"), Err(VMError::InvalidRegister(_))));
        assert!(matches!(
            parse_reg("r256"),
            Err(VMError::InvalidRegister(_))
        ));
        assert!(matches!(parse_reg("r-1"), Err(VMError::InvalidRegister(_))));
        assert!(matches!(
            parse_reg("rabc"),
            Err(VMError::InvalidRegister(_))
        ));
    }

    #[test]
    fn parse_i64_valid() {
        assert_eq!(parse_i64("0").unwrap(), 0);
        assert_eq!(parse_i64("-1").unwrap(), -1);
        assert_eq!(parse_i64("9223372036854775807").unwrap(), i64::MAX);
        assert_eq!(parse_i64("-9223372036854775808").unwrap(), i64::MIN);
    }

    #[test]
    fn parse_i64_invalid() {
        assert!(matches!(parse_i64("abc"), Err(VMError::InvalidI64(_))));
        assert!(matches!(parse_i64(""), Err(VMError::InvalidI64(_))));
        assert!(matches!(
            parse_i64("9223372036854775808"),
            Err(VMError::InvalidI64(_))
        ));
    }

    #[test]
    fn assemble_empty_source() {
        let bytecode = assemble_source("").unwrap();
        assert!(bytecode.is_empty());
    }

    #[test]
    fn assemble_comments_and_blank_lines() {
        let source = r#"
            ; this is a comment

            ; another comment
        "#;
        let bytecode = assemble_source(source).unwrap();
        assert!(bytecode.is_empty());
    }

    #[test]
    fn assemble_inline_comment() {
        let source = "LOAD_I64 r0, 42 ; load value";
        let bytecode = assemble_source(source).unwrap();
        assert_eq!(bytecode.len(), 10); // opcode(1) + reg(1) + i64(8)
    }

    #[test]
    fn assemble_single_instruction() {
        let bytecode = assemble_source("LOAD_I64 r0, 42").unwrap();
        assert_eq!(bytecode[0], 0x00); // LOAD_I64 opcode
        assert_eq!(bytecode[1], 0); // r0
        assert_eq!(i64::from_le_bytes(bytecode[2..10].try_into().unwrap()), 42);
    }

    #[test]
    fn assemble_invalid_instruction() {
        let result = assemble_source("INVALID r0");
        assert!(result.is_err());
    }

    #[test]
    fn assemble_wrong_arity() {
        let result = assemble_source("ADD r0, r1"); // missing third register
        assert!(result.is_err());
    }
}
