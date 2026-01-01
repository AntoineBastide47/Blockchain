//! Assembly language parser and bytecode compiler.
//!
//! Converts human-readable assembly source into executable bytecode.
//! Uses [`for_each_instruction!`](crate::for_each_instruction) to generate:
//! - [`AsmInstr`] intermediate representation for parsed instructions
//! - [`AsmInstr::assemble`] for bytecode encoding
//! - `parse_instruction` for tokenized input parsing
//!
//! # Syntax
//!
//! ```text
//! INSTRUCTION operand1, operand2, ...  # optional comment
//! ```
//!
//! - Instructions are uppercase (e.g., `LOAD_I64`, `ADD`)
//! - Registers use `r` prefix (e.g., `r0`, `r255`)
//! - Immediates are decimal integers (e.g., `42`, `-1`)
//! - String literals are double-quoted (e.g., `"hello"`)
//! - Booleans are `true` or `false`
//! - Comments start with `#`
//! - Commas between operands are optional

use crate::define_instructions;
use crate::for_each_instruction;
use crate::virtual_machine::errors::VMError;
use crate::virtual_machine::isa::Instruction;
use crate::virtual_machine::program::Program;
use std::fs;
use std::path::Path;

const COMMENT_CHAR: char = '#';

/// Assembly context for string interning during compilation.
///
/// Tracks string literals encountered during assembly, assigning each
/// a unique index that becomes part of the compiled [`Program`].
pub struct AsmContext {
    /// Accumulated string literals.
    pub strings: Vec<String>,
}

impl AsmContext {
    /// Creates an empty assembly context.
    pub fn new() -> Self {
        Self {
            strings: Vec::new(),
        }
    }

    /// Adds a string to the pool, returning its index.
    pub fn intern_string(&mut self, s: String) -> u32 {
        let id = self.strings.len() as u32;
        self.strings.push(s);
        id
    }
}

/// Tokenize a single line of assembly.
///
/// Rules:
/// - `#` starts a comment
/// - commas are ignored
/// - whitespace-separated tokens
fn tokenize(line: &str) -> Vec<String> {
    let line = line.split(COMMENT_CHAR).next().unwrap_or("");
    let bytes = line.as_bytes();

    let mut out = Vec::with_capacity(8);
    let mut cur = String::with_capacity(line.len().min(64));

    let mut i = 0usize;
    let mut in_str = false;

    // helper: finalize current token
    let flush = |out: &mut Vec<String>, cur: &mut String| {
        if !cur.is_empty() {
            let t = cur.trim();
            if !t.is_empty() {
                out.push(t.to_string());
            }
            cur.clear();
        }
    };

    while i < bytes.len() {
        let b = bytes[i];
        match b {
            b'"' => {
                cur.push('"');
                in_str = !in_str;
                i += 1;
            }
            b',' if !in_str => {
                flush(&mut out, &mut cur);
                i += 1;
            }
            b if !in_str && (b as char).is_whitespace() => {
                flush(&mut out, &mut cur);
                i += 1;
            }
            _ => {
                // push as char; safe because original line is valid UTF-8
                cur.push(bytes[i] as char);
                i += 1;
            }
        }
    }

    flush(&mut out, &mut cur);
    out
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

/// Parse a reference token like `@0`, `@123`.
pub(crate) fn parse_ref_u32(tok: &str) -> Result<u32, VMError> {
    tok.strip_prefix('@')
        .ok_or_else(|| VMError::InvalidRegister(tok.to_string()))?
        .parse::<u32>()
        .map_err(|_| VMError::InvalidRegister(tok.to_string()))
}

/// Parse a boolean literal (`true` or `false`).
pub(crate) fn parse_bool(tok: &str) -> Result<bool, VMError> {
    match tok {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(VMError::TypeMismatch {
            instruction: "bool",
            arg_index: 0,
            expected: "bool",
            actual: tok.to_string(),
        }),
    }
}

macro_rules! define_parse_instruction {
    (
        $(
            $(#[$doc:meta])*
            $name:ident = $opcode:expr, $mnemonic:literal => [
                $( $field:ident : $kind:ident ),* $(,)?
            ]
        ),* $(,)?
    ) => {

        // =========================
        // Assembler IR
        // =========================
        #[derive(Debug, Clone)]
        enum AsmInstr {
            $(
                $name {
                    $( $field: define_instructions!(@ty $kind) ),*
                },
            )*
        }

        impl AsmInstr {
            /// Encodes the assembly instruction into bytecode
            fn assemble(&self, out: &mut Vec<u8>) {
                match self {
                    $(
                        AsmInstr::$name { $( $field ),* } => {
                            out.push($opcode);
                            $(
                                define_instructions!(@emit out, $kind, $field);
                            )*
                        }
                    ),*
                }
            }
        }

        fn instruction_from_str(name: &str) -> Result<Instruction, VMError> {
            match name {
                $( $mnemonic => Ok(Instruction::$name), )*
                _ => Err(VMError::InvalidInstructionName(name.to_string())),
            }
        }

        /// Parse one instruction from tokens into [`AsmInstr`].
        fn parse_instruction(ctx: &mut AsmContext, tokens: &[String]) -> Result<AsmInstr, VMError> {
            if tokens.is_empty() {
                return Err(VMError::ArityMismatch);
            }

            let instr = instruction_from_str(&tokens[0])?;

            match instr {
                $(
                    Instruction::$name => {
                        const EXPECTED: usize = 1 + define_parse_instruction!(@count $( $field ),*);
                        if tokens.len() != EXPECTED {
                            return Err(VMError::ArityMismatch);
                        }

                        let mut it = tokens.iter().skip(1);
                        Ok(AsmInstr::$name {
                            $(
                                $field: define_parse_instruction!(
                                    @parse_operand $kind, it.next().unwrap(), ctx
                                )?,
                            )*
                        })
                    }
                ),*
            }
        }
    };

    // ---------- counting ----------
    (@count $( $x:ident ),* ) => {
        <[()]>::len(&[ $( define_parse_instruction!(@unit $x) ),* ])
    };

    (@unit $x:ident) => { () };

    // ---------- parsing ----------
    (@parse_operand Reg, $tok:expr, $ctx:expr) => {
        parse_reg($tok)
    };

    (@parse_operand ImmI64, $tok:expr, $ctx:expr) => {
        parse_i64($tok)
    };

    (@parse_operand RefU32, $tok:expr, $ctx:expr) => {{
        if let Some(s) = $tok.strip_prefix('"').and_then(|t| t.strip_suffix('"')) {
            Ok($ctx.intern_string(s.to_string()))
        } else {
            parse_ref_u32($tok)
        }
    }};

    (@parse_operand Bool, $tok:expr, $ctx:expr) => {
        parse_bool($tok)
    };
}

for_each_instruction!(define_parse_instruction);

/// Assemble a full source string into bytecode.
pub fn assemble_source(source: impl Into<String>) -> Result<Program, VMError> {
    let mut bytecode = Vec::new();
    let mut asm_context = AsmContext::new();

    for (line_no, line) in source.into().lines().enumerate() {
        let tokens = tokenize(line);
        if tokens.is_empty() {
            continue;
        }

        let instr =
            parse_instruction(&mut asm_context, &tokens).map_err(|e| VMError::AssemblyError {
                line: line_no + 1,
                source: e.to_string(),
            })?;

        instr.assemble(&mut bytecode);
    }

    Ok(Program {
        strings: asm_context.strings,
        bytecode,
    })
}

/// Convenience: assemble directly from file path
pub fn assemble_file<P: AsRef<Path>>(path: P) -> Result<Program, VMError> {
    let source = fs::read_to_string(path).map_err(|e| VMError::IoError(e.to_string()))?;
    assemble_source(source)
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
        let program = assemble_source("").unwrap();
        assert!(program.bytecode.is_empty());
    }

    #[test]
    fn assemble_comments_and_blank_lines() {
        let source = format!(
            r#"
            {COMMENT_CHAR} this is a comment

            {COMMENT_CHAR} another comment
        "#
        );
        let program = assemble_source(source).unwrap();
        assert!(program.bytecode.is_empty());
    }

    #[test]
    fn assemble_inline_comment() {
        let source = format!("LOAD_I64 r0, 42 {COMMENT_CHAR} load value");
        let program = assemble_source(source).unwrap();
        assert_eq!(program.bytecode.len(), 10); // opcode(1) + reg(1) + i64(8)
    }

    #[test]
    fn assemble_single_instruction() {
        let program = assemble_source("LOAD_I64 r0, 42").unwrap();
        assert_eq!(program.bytecode[0], 0x00); // LOAD_I64 opcode
        assert_eq!(program.bytecode[1], 0); // r0
        assert_eq!(
            i64::from_le_bytes(program.bytecode[2..10].try_into().unwrap()),
            42
        );
    }

    #[test]
    fn assemble_invalid_instruction() {
        let err = assemble_source("INVALID r0").unwrap_err();
        assert!(matches!(
            err,
            VMError::AssemblyError { line: 1, ref source } if source.contains("invalid instruction name")
        ));
    }

    #[test]
    fn assemble_wrong_arity() {
        let err = assemble_source("ADD r0, r1").unwrap_err();
        assert!(matches!(
            err,
            VMError::AssemblyError { line: 1, ref source } if source.contains("arity")
        ));
    }

    #[test]
    fn parse_ref_u32_valid() {
        assert_eq!(parse_ref_u32("@0").unwrap(), 0);
        assert_eq!(parse_ref_u32("@123").unwrap(), 123);
    }

    #[test]
    fn parse_ref_u32_invalid() {
        assert!(parse_ref_u32("0").is_err());
        assert!(parse_ref_u32("@abc").is_err());
        assert!(parse_ref_u32("@").is_err());
    }

    #[test]
    fn parse_bool_valid() {
        assert!(parse_bool("true").unwrap());
        assert!(!parse_bool("false").unwrap());
    }

    #[test]
    fn parse_bool_invalid() {
        assert!(parse_bool("TRUE").is_err());
        assert!(parse_bool("1").is_err());
        assert!(parse_bool("").is_err());
    }

    #[test]
    fn assemble_string_literal() {
        let program = assemble_source(r#"LOAD_STR r0, "hello""#).unwrap();
        assert_eq!(program.strings, vec!["hello"]);
        assert_eq!(program.bytecode[0], 0x06); // LOAD_STR opcode
    }

    #[test]
    fn assemble_multiple_strings() {
        let source = r#"
            LOAD_STR r0, "first"
            LOAD_STR r1, "second"
        "#;
        let program = assemble_source(source).unwrap();
        assert_eq!(program.strings, vec!["first", "second"]);
    }

    #[test]
    fn assemble_bool_literal() {
        let program = assemble_source("LOAD_BOOL r0, true").unwrap();
        assert_eq!(program.bytecode[0], 0x03); // LOAD_BOOL opcode
        assert_eq!(program.bytecode[2], 1); // true = 1

        let program = assemble_source("LOAD_BOOL r0, false").unwrap();
        assert_eq!(program.bytecode[0], 0x03); // LOAD_BOOL opcode
        assert_eq!(program.bytecode[2], 0); // false = 0

        let err = assemble_source("LOAD_BOOL r0, 1").unwrap_err();
        assert!(matches!(err, VMError::AssemblyError { .. }));
    }

    #[test]
    fn instruction_parse_empty() {
        assert!(matches!(
            parse_instruction(&mut AsmContext::new(), &[]),
            Err(VMError::ArityMismatch)
        ));
    }

    #[test]
    fn instruction_parse_load_i64() {
        let tokens = vec!["LOAD_I64".into(), "r5".into(), "100".into()];
        let instr = parse_instruction(&mut AsmContext::new(), &tokens).unwrap();
        match instr {
            AsmInstr::LoadI64 { rd, imm } => {
                assert_eq!(rd, 5);
                assert_eq!(imm, 100);
            }
            _ => panic!("wrong instruction type"),
        }
    }

    #[test]
    fn instruction_parse_three_reg() {
        let tokens = vec!["ADD".into(), "r0".into(), "r1".into(), "r2".into()];
        let instr = parse_instruction(&mut AsmContext::new(), &tokens).unwrap();
        match instr {
            AsmInstr::Add { rd, rs1, rs2 } => {
                assert_eq!(rd, 0);
                assert_eq!(rs1, 1);
                assert_eq!(rs2, 2);
            }
            _ => panic!("wrong instruction type"),
        }
    }

    #[test]
    fn instruction_from_str_valid() {
        assert_eq!(
            instruction_from_str("LOAD_I64").unwrap(),
            Instruction::LoadI64
        );
        assert_eq!(instruction_from_str("ADD").unwrap(), Instruction::Add);
        assert_eq!(instruction_from_str("DIV").unwrap(), Instruction::Div);
    }

    #[test]
    fn instruction_from_str_invalid() {
        assert!(matches!(
            instruction_from_str("INVALID"),
            Err(VMError::InvalidInstructionName(_))
        ));
        assert!(matches!(
            instruction_from_str("add"), // case sensitive
            Err(VMError::InvalidInstructionName(_))
        ));
    }

    #[test]
    fn asm_instr_assemble_load_i64() {
        let instr = AsmInstr::LoadI64 { rd: 3, imm: -1 };
        let mut out = Vec::new();
        instr.assemble(&mut out);
        assert_eq!(out[0], 0x00);
        assert_eq!(out[1], 3);
        assert_eq!(i64::from_le_bytes(out[2..10].try_into().unwrap()), -1);
    }

    #[test]
    fn asm_instr_assemble_three_reg() {
        let instr = AsmInstr::Sub {
            rd: 10,
            rs1: 20,
            rs2: 30,
        };
        let mut out = Vec::new();
        instr.assemble(&mut out);
        assert_eq!(out, vec![0x21, 10, 20, 30]);
    }

    #[test]
    fn asm_instr_assemble_two_reg() {
        let instr = AsmInstr::Neg { rd: 1, rs: 2 };
        let mut out = Vec::new();
        instr.assemble(&mut out);
        assert_eq!(out, vec![0x25, 1, 2]);
    }

    #[test]
    fn asm_instr_assemble_bool() {
        let instr = AsmInstr::LoadBool { rd: 0, bool: true };
        let mut out = Vec::new();
        instr.assemble(&mut out);
        assert_eq!(out, vec![0x03, 0, 1]);
    }

    #[test]
    fn asm_instr_assemble_ref() {
        let instr = AsmInstr::LoadStr { rd: 1, str: 0x1234 };
        let mut out = Vec::new();
        instr.assemble(&mut out);
        assert_eq!(out[0], 0x06);
        assert_eq!(out[1], 1);
        assert_eq!(u32::from_le_bytes(out[2..6].try_into().unwrap()), 0x1234);
    }
}
