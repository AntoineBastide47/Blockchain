//! Assembly language parser and bytecode compiler.
//!
//! Converts human-readable assembly source into executable bytecode.
//! Uses [`for_each_instruction!`](for_each_instruction) to generate:
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
use std::collections::HashMap;
use std::fs;
use std::path::Path;

const COMMENT_CHAR: char = '#';
const LABEL_SUFFIX: char = ':';

/// Assembly context for heap items interning and label tracking during compilation.
///
/// Tracks heap items and labels encountered during assembly, assigning each
/// heap items a unique index that becomes part of the compiled [`Program`].
pub struct AsmContext {
    /// Accumulated heap items.
    pub items: Vec<Vec<u8>>,
    /// Label definitions mapping names to bytecode offsets.
    pub labels: HashMap<String, usize>,
    /// The maximal register found
    pub max_register: u8,
}

impl AsmContext {
    /// Creates an empty assembly context.
    pub fn new() -> Self {
        Self {
            items: Vec::new(),
            labels: HashMap::new(),
            max_register: 0,
        }
    }

    /// Adds a string to the pool, returning its index.
    pub fn intern_string(&mut self, s: String) -> u32 {
        let id = self.items.len() as u32;
        self.items.push(s.into_bytes());
        id
    }

    /// Registers a label at the given bytecode offset.
    pub fn define_label(&mut self, name: String, offset: usize) -> Result<(), VMError> {
        if self.labels.contains_key(&name) {
            return Err(VMError::DuplicateLabel { label: name });
        }
        self.labels.insert(name, offset);
        Ok(())
    }

    /// Resolves a label to its bytecode offset.
    pub fn resolve_label(&self, name: &str) -> Result<usize, VMError> {
        self.labels
            .get(name)
            .copied()
            .ok_or(VMError::UndefinedLabel {
                label: name.to_string(),
            })
    }
}

impl Default for AsmContext {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
struct Token {
    text: String,
    /// 1-based column offset in the line.
    offset: usize,
}

/// Tokenize a single line of assembly.
///
/// Rules:
/// - `#` starts a comment
/// - commas are ignored
/// - whitespace-separated tokens
fn tokenize(line_no: usize, line: &str) -> Result<Vec<Token>, VMError> {
    let line = line.split(COMMENT_CHAR).next().unwrap_or("");

    let mut out = Vec::with_capacity(8);
    let mut cur = String::with_capacity(line.len().min(64));
    let mut start_col: Option<usize> = None;
    let mut in_str = false;
    let mut col = 0usize;

    for ch in line.chars() {
        col += 1;

        if ch == COMMENT_CHAR && !in_str {
            break;
        }

        match ch {
            '"' => {
                if start_col.is_none() {
                    start_col = Some(col);
                }
                cur.push(ch);
                in_str = !in_str;
            }
            ',' if !in_str => {
                flush_token(&mut out, &mut cur, &mut start_col);
            }
            c if !in_str && c.is_whitespace() => {
                flush_token(&mut out, &mut cur, &mut start_col);
            }
            _ => {
                if start_col.is_none() {
                    start_col = Some(col);
                }
                cur.push(ch);
            }
        }
    }

    if in_str {
        let offset = start_col.unwrap_or(col + 1);
        return Err(VMError::ParseError {
            line: line_no,
            offset,
            message: "unterminated string literal (missing closing quote)",
        });
    }

    flush_token(&mut out, &mut cur, &mut start_col);
    Ok(out)
}

fn flush_token(out: &mut Vec<Token>, cur: &mut String, start_col: &mut Option<usize>) {
    if cur.is_empty() {
        *start_col = None;
        return;
    }
    let token = cur.trim();
    if !token.is_empty() {
        out.push(Token {
            text: token.to_string(),
            offset: start_col.unwrap_or(1),
        });
    }
    cur.clear();
    *start_col = None;
}

/// Parse a register token like `r0`, `r15`
pub(crate) fn parse_reg(tok: &str) -> Result<u8, VMError> {
    tok.strip_prefix('r')
        .ok_or_else(|| VMError::ExpectedRegister(tok.to_string()))?
        .parse::<u8>()
        .map_err(|_| VMError::InvalidRegister {
            token: tok.to_string(),
        })
}

/// Parse an i64 immediate
pub(crate) fn parse_i64(tok: &str) -> Result<i64, VMError> {
    tok.parse::<i64>().map_err(|_| VMError::InvalidRegister {
        token: tok.to_string(),
    })
}

/// Parse a u8 immediate
pub(crate) fn parse_u8(tok: &str) -> Result<u8, VMError> {
    tok.parse::<u8>().map_err(|_| VMError::ArgcOutOfRange {
        actual: tok.to_string(),
    })
}

/// Parse a reference token like `@0`, `@123`.
pub(crate) fn parse_ref_u32(tok: &str) -> Result<u32, VMError> {
    tok.strip_prefix('@')
        .ok_or_else(|| VMError::InvalidRegister {
            token: tok.to_string(),
        })?
        .parse::<u32>()
        .map_err(|_| VMError::InvalidRegister {
            token: tok.to_string(),
        })
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

/// Parse an i64 immediate or a label reference.
///
/// If `tok` parses as an integer, returns it directly.
/// Otherwise, treats it as a label name and computes a relative offset
/// from `after_instr` (the PC value after decoding the current instruction).
pub(crate) fn parse_i64_or_label(
    tok: &str,
    ctx: &AsmContext,
    after_instr: usize,
) -> Result<i64, VMError> {
    if let Ok(v) = tok.parse::<i64>() {
        return Ok(v);
    }
    let target = ctx.resolve_label(tok)?;
    Ok(target as i64 - after_instr as i64)
}

/// Checks if a token is a label definition (ends with `:`)
fn is_label_def(tok: &str) -> bool {
    tok.ends_with(LABEL_SUFFIX) && tok.len() > 1
}

/// Extracts the label name from a label definition token.
fn label_name(tok: &str) -> &str {
    &tok[..tok.len() - 1]
}

macro_rules! define_parse_instruction {
    (
        $(
            $(#[$doc:meta])*
            $name:ident = $opcode:expr, $mnemonic:literal => [
                $( $field:ident : $kind:ident ),* $(,)?
            ], $gas:expr
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
                _ => Err(VMError::InvalidInstructionName {
                    name: name.to_string(),
                }),
            }
        }

        /// Returns the bytecode size for an instruction (opcode + operands).
        fn instruction_size(instr: Instruction) -> usize {
            match instr {
                $(
                    Instruction::$name => {
                        1usize $( + define_parse_instruction!(@size $kind) )*
                    }
                ),*
            }
        }

        /// Parse one instruction from tokens into [`AsmInstr`].
        ///
        /// `current_offset` is the bytecode offset where this instruction starts,
        /// used for resolving label references to relative offsets.
        fn parse_instruction(
            ctx: &mut AsmContext,
            tokens: &[Token],
            current_offset: usize,
        ) -> Result<AsmInstr, VMError> {
            if tokens.is_empty() {
                return Err(VMError::ArityMismatch {
                    instruction: "<missing opcode>".to_string(),
                    expected: 1,
                    actual: 0,
                });
            }

            let instr = instruction_from_str(&tokens[0].text)?;
            let offset = current_offset + instruction_size(instr);

            match instr {
                $(
                    Instruction::$name => {
                        const EXPECTED: usize = 1 + define_parse_instruction!(@count $( $field ),*);
                        if tokens.len() != EXPECTED {
                            return Err(VMError::ArityMismatch {
                                instruction: tokens[0].text.clone(),
                                expected: EXPECTED - 1,
                                actual: tokens.len() - 1,
                            });
                        }

                        let mut it = tokens.iter().skip(1);
                        Ok(AsmInstr::$name {
                            $(
                                $field: define_parse_instruction!(
                                    @parse_operand $kind, it.next().unwrap(), ctx, offset
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

    // ---------- operand sizes ----------
    (@size Reg)    => { 1usize };
    (@size Bool)   => { 1usize };
    (@size RefU32) => { 4usize };
    (@size ImmU8)  => { 1usize };
    (@size ImmI64) => { 8usize };

    // ---------- parsing ----------
    (@parse_operand Reg, $tok:expr, $ctx:expr, $current_offset:expr) => {{
          let reg = parse_reg(&$tok.text)?;
          if reg > $ctx.max_register {
              $ctx.max_register = reg;
          }
          Ok::<_, VMError>(reg)
      }};

    (@parse_operand ImmU8, $tok:expr, $ctx:expr, $current_offset:expr) => {
        parse_u8(&$tok.text)
    };

    (@parse_operand ImmI64, $tok:expr, $ctx:expr, $current_offset:expr) => {
        parse_i64_or_label(&$tok.text, $ctx, $current_offset)
    };

    (@parse_operand RefU32, $tok:expr, $ctx:expr, $current_offset:expr) => {{
        let tok = &$tok.text;
        if let Some(s) = tok.strip_prefix('"').and_then(|t| t.strip_suffix('"')) {
            Ok($ctx.intern_string(s.to_string()))
        } else {
            parse_ref_u32(tok)
        }
    }};

    (@parse_operand Bool, $tok:expr, $ctx:expr, $current_offset:expr) => {
        parse_bool(&$tok.text)
    };
}

for_each_instruction!(define_parse_instruction);

/// Assemble a full source string into bytecode.
///
/// Uses two-pass assembly:
/// 1. First pass: tokenize lines, record label positions
/// 2. Second pass: parse instructions with label resolution, emit bytecode
pub fn assemble_source(source: impl Into<String>) -> Result<Program, VMError> {
    let source = source.into();
    let mut asm_context = AsmContext::new();

    // First pass: tokenize all lines and collect label definitions
    let mut parsed_lines: Vec<(usize, Vec<Token>)> = Vec::new();
    let mut offset = 0usize;

    for (line_no, line) in source.lines().enumerate() {
        let tokens = tokenize(line_no + 1, line)?;
        if tokens.is_empty() {
            continue;
        }

        // Check if first token is a label definition
        if is_label_def(&tokens[0].text) {
            let name = label_name(&tokens[0].text).to_string();
            asm_context
                .define_label(name, offset)
                .map_err(|e| VMError::AssemblyError {
                    line: line_no + 1,
                    offset: tokens[0].offset,
                    source: e.to_string(),
                })?;

            // If there are more tokens after the label, treat them as an instruction
            if tokens.len() > 1 {
                let instr_tokens: Vec<Token> = tokens[1..].to_vec();
                let instr = instruction_from_str(&instr_tokens[0].text).map_err(|e| {
                    VMError::AssemblyError {
                        line: line_no + 1,
                        offset: instr_tokens[0].offset,
                        source: e.to_string(),
                    }
                })?;
                offset += instruction_size(instr);
                parsed_lines.push((line_no, instr_tokens));
            }
        } else {
            let instr =
                instruction_from_str(&tokens[0].text).map_err(|e| VMError::AssemblyError {
                    line: line_no + 1,
                    offset: tokens[0].offset,
                    source: e.to_string(),
                })?;
            offset += instruction_size(instr);
            parsed_lines.push((line_no, tokens));
        }
    }

    // Second pass: parse instructions and emit bytecode
    let mut bytecode = Vec::new();

    for (line_no, tokens) in parsed_lines {
        let current_offset = bytecode.len();
        let instr = parse_instruction(&mut asm_context, &tokens, current_offset).map_err(|e| {
            VMError::AssemblyError {
                line: line_no + 1,
                offset: tokens.first().map(|t| t.offset).unwrap_or(1),
                source: e.to_string(),
            }
        })?;
        instr.assemble(&mut bytecode);
    }

    Ok(Program {
        max_register: asm_context.max_register,
        items: asm_context.items,
        bytecode,
    })
}

/// Convenience: assemble directly from file path
pub fn assemble_file<P: AsRef<Path>>(path: P) -> Result<Program, VMError> {
    let path_ref = path.as_ref();
    let source = fs::read_to_string(path_ref).map_err(|e| VMError::IoError {
        path: path_ref.display().to_string(),
        source: e.to_string(),
    })?;
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
        assert!(matches!(
            parse_reg("r"),
            Err(VMError::InvalidRegister { token: _ })
        ));
        assert!(matches!(
            parse_reg("r256"),
            Err(VMError::InvalidRegister { token: _ })
        ));
        assert!(matches!(
            parse_reg("r-1"),
            Err(VMError::InvalidRegister { token: _ })
        ));
        assert!(matches!(
            parse_reg("rAbc"),
            Err(VMError::InvalidRegister { token: _ })
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
        assert_eq!(program.bytecode[0], Instruction::LoadI64 as u8);
        assert_eq!(program.bytecode[1], 0);
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
            VMError::AssemblyError { line: 1, offset: _, ref source } if source.contains("unknown instruction")
        ));
    }

    #[test]
    fn assemble_wrong_arity() {
        let err = assemble_source("ADD r0, r1").unwrap_err();
        assert!(matches!(
            err,
            VMError::AssemblyError { line: 1, offset: _, ref source } if source.contains("operand count mismatch")
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
        assert_eq!(program.items, vec!["hello".as_bytes().to_vec()]);
        assert_eq!(program.bytecode[0], Instruction::LoadStr as u8);
    }

    #[test]
    fn assemble_multiple_strings() {
        let source = r#"
            LOAD_STR r0, "first"
            LOAD_STR r1, "second"
        "#;
        let program = assemble_source(source).unwrap();
        assert_eq!(
            program.items,
            vec!["first".as_bytes().to_vec(), "second".as_bytes().to_vec()]
        );
    }

    #[test]
    fn assemble_invalid_string_literal() {
        let source = r#"
            LOAD_STR r0, "first
        "#;
        assert!(assemble_source(source).is_err());

        let source = r#"
            LOAD_STR r0, first
        "#;
        assert!(assemble_source(source).is_err());

        let source = r#"
            LOAD_STR r0, first"
        "#;
        assert!(assemble_source(source).is_err());
    }

    #[test]
    fn assemble_bool_literal() {
        let program = assemble_source("LOAD_BOOL r0, true").unwrap();
        assert_eq!(program.bytecode[0], Instruction::LoadBool as u8);
        assert_eq!(program.bytecode[2], 1);

        let program = assemble_source("LOAD_BOOL r0, false").unwrap();
        assert_eq!(program.bytecode[0], Instruction::LoadBool as u8);
        assert_eq!(program.bytecode[2], 0);

        let err = assemble_source("LOAD_BOOL r0, 1").unwrap_err();
        assert!(matches!(err, VMError::AssemblyError { .. }));
    }

    #[test]
    fn instruction_parse_empty() {
        assert!(matches!(
            parse_instruction(&mut AsmContext::new(), &[], 0),
            Err(VMError::ArityMismatch { .. })
        ));
    }

    #[test]
    fn instruction_parse_load_i64() {
        let tokens = vec![
            Token {
                text: "LOAD_I64".into(),
                offset: 1,
            },
            Token {
                text: "r5".into(),
                offset: 10,
            },
            Token {
                text: "100".into(),
                offset: 14,
            },
        ];
        let instr = parse_instruction(&mut AsmContext::new(), &tokens, 0).unwrap();
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
        let tokens = vec![
            Token {
                text: "ADD".into(),
                offset: 1,
            },
            Token {
                text: "r0".into(),
                offset: 5,
            },
            Token {
                text: "r1".into(),
                offset: 9,
            },
            Token {
                text: "r2".into(),
                offset: 13,
            },
        ];
        let instr = parse_instruction(&mut AsmContext::new(), &tokens, 0).unwrap();
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
            Err(VMError::InvalidInstructionName { .. })
        ));
        assert!(matches!(
            instruction_from_str("add"), // case-sensitive
            Err(VMError::InvalidInstructionName { .. })
        ));
    }

    #[test]
    fn asm_instr_assemble_load_i64() {
        let instr = AsmInstr::LoadI64 { rd: 3, imm: -1 };
        let mut out = Vec::new();
        instr.assemble(&mut out);
        assert_eq!(out[0], Instruction::LoadI64 as u8);
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
        assert_eq!(out, vec![Instruction::Sub as u8, 10, 20, 30]);
    }

    #[test]
    fn asm_instr_assemble_two_reg() {
        let instr = AsmInstr::Neg { rd: 1, rs: 2 };
        let mut out = Vec::new();
        instr.assemble(&mut out);
        assert_eq!(out, vec![Instruction::Neg as u8, 1, 2]);
    }

    #[test]
    fn asm_instr_assemble_bool() {
        let instr = AsmInstr::LoadBool { rd: 0, bool: true };
        let mut out = Vec::new();
        instr.assemble(&mut out);
        assert_eq!(out, vec![Instruction::LoadBool as u8, 0, 1]);
    }

    #[test]
    fn asm_instr_assemble_ref() {
        let instr = AsmInstr::LoadStr { rd: 1, str: 0x1234 };
        let mut out = Vec::new();
        instr.assemble(&mut out);
        assert_eq!(out[0], Instruction::LoadStr as u8);
        assert_eq!(out[1], 1);
        assert_eq!(u32::from_le_bytes(out[2..6].try_into().unwrap()), 0x1234);
    }

    // ==================== Labels ====================

    #[test]
    fn duplicate_label_error() {
        let source = "dup: LOAD_I64 r0, 1\ndup: LOAD_I64 r1, 2";
        let err = assemble_source(source).unwrap_err();
        assert!(matches!(
            err,
            VMError::AssemblyError { line: 2, offset: _, ref source } if source.contains("duplicate")
        ));
    }

    #[test]
    fn undefined_label_error() {
        let source = "JAL r0, missing";
        let err = assemble_source(source).unwrap_err();
        assert!(matches!(
            err,
            VMError::AssemblyError { line: 1, offset: _, ref source } if source.contains("undefined")
        ));
    }

    #[test]
    fn is_label_def_valid() {
        assert!(is_label_def("start:"));
        assert!(is_label_def("_loop:"));
        assert!(is_label_def("label123:"));
    }

    #[test]
    fn is_label_def_invalid() {
        assert!(!is_label_def(":"));
        assert!(!is_label_def("label"));
        assert!(!is_label_def(""));
    }

    #[test]
    fn parse_u8_valid() {
        assert_eq!(parse_u8("0").unwrap(), 0);
        assert_eq!(parse_u8("255").unwrap(), 255);
        assert_eq!(parse_u8("42").unwrap(), 42);
    }

    #[test]
    fn parse_u8_invalid() {
        assert!(parse_u8("256").is_err());
        assert!(parse_u8("-1").is_err());
        assert!(parse_u8("abc").is_err());
        assert!(parse_u8("").is_err());
    }

    #[test]
    fn assemble_call_host_argc_u8() {
        // CALL_HOST: opcode(1) + dst(1) + fn_id(4) + argc(1) + argv(1) = 8 bytes
        let program = assemble_source(r#"CALL_HOST r0, "test_fn", 3, r1"#).unwrap();
        assert_eq!(program.bytecode[0], Instruction::CallHost as u8);
        assert_eq!(program.bytecode[1], 0); // dst = r0
        assert_eq!(program.bytecode[6], 3); // argc = 3 (single byte)
        assert_eq!(program.bytecode[7], 1); // argv = r1
        assert_eq!(program.bytecode.len(), 8);
    }

    #[test]
    fn assemble_call_argc_u8() {
        // CALL: opcode(1) + dst(1) + fn_id(4) + argc(1) + argv(1) = 8 bytes
        let program = assemble_source("my_func:\nCALL r0, my_func, 5, r2").unwrap();
        assert_eq!(program.bytecode[0], Instruction::Call as u8);
        assert_eq!(program.bytecode[1], 0); // dst = r0
        assert_eq!(program.bytecode[10], 5); // argc = 5 (single byte)
        assert_eq!(program.bytecode[11], 2); // argv = r2
        assert_eq!(program.bytecode.len(), 12);
    }

    #[test]
    fn assemble_call_argc_max_u8() {
        let program = assemble_source(r#"CALL_HOST r0, "fn", 255, r0"#).unwrap();
        assert_eq!(program.bytecode[6], 255); // max u8 value
    }

    #[test]
    fn assemble_call_argc_overflow() {
        // 256 exceeds u8 range
        let err = assemble_source(r#"CALL_HOST r0, "fn", 256, r0"#).unwrap_err();
        assert!(matches!(err, VMError::AssemblyError { .. }));
    }
}
