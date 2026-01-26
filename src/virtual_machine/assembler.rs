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
//! - Instructions are uppercase (e.g., `MOVE`, `ADD`)
//! - Registers use `r` prefix (e.g., `r0`, `r255`)
//! - Immediates are decimal integers (e.g., `42`, `-1`)
//! - String literals are double-quoted (e.g., `"hello"`)
//! - Booleans are `true` or `false`
//! - Comments start with `#`
//! - Commas between operands are optional

use crate::for_each_instruction;
use crate::utils::log::SHOW_TYPE;
use crate::virtual_machine::errors::VMError;
use crate::virtual_machine::isa::Instruction;
use crate::virtual_machine::operand::SrcOperand;
use crate::virtual_machine::program::DeployProgram;
use crate::{define_instructions, error};
use std::collections::{HashMap, HashSet};
use std::fmt::Write;
use std::fs;
use std::path::Path;
use std::sync::atomic::Ordering;

const COMMENT_CHAR: char = '#';
const LABEL_SUFFIX: char = ':';
const SECTION_INIT: &str = "[ init code ]";
const SECTION_RUNTIME: &str = "[ runtime code ]";

/// Tracks line offset introduced by dispatcher code insertion.
#[derive(Debug, Clone, Copy)]
struct DispatcherInfo {
    /// Line number (1-indexed) after which dispatcher was inserted.
    insert_after: usize,
    /// Number of lines added by the dispatcher.
    lines_added: usize,
}

impl DispatcherInfo {
    /// Adjusts a processed-source line number back to original source line number.
    fn adjust_line(&self, processed_line: usize) -> usize {
        if processed_line > self.insert_after {
            processed_line.saturating_sub(self.lines_added)
        } else {
            processed_line
        }
    }
}

/// Formats a compiler-style diagnostic for assembly failures.
fn render_assembly_diagnostic(
    file: &str,
    source: &str,
    line: usize,
    offset: usize,
    length: usize,
    message: &str,
) {
    error!("{message}");
    eprintln!(" --> {file}:{line}:{offset}");

    if let Some(raw_line) = source.lines().nth(line.saturating_sub(1)) {
        let underline = " ".repeat(offset.saturating_sub(1));
        let carets = "^".repeat(length.max(1));
        eprintln!("{:>4} | {}", line, raw_line.trim_end_matches('\r'));
        eprint!("     |");
        SHOW_TYPE.store(false, Ordering::Relaxed);
        error!(" {}{} {}", underline, carets, message);
        SHOW_TYPE.store(true, Ordering::Relaxed);
    }
}

/// Emit helpful diagnostics to stderr for multiple assembly errors.
///
/// If dispatcher info is provided, adjusts line numbers for errors occurring
/// after the dispatcher insertion point.
fn log_assembly_errors(
    file: &str,
    source: &str,
    errors: &[VMError],
    dispatcher: Option<DispatcherInfo>,
) {
    for err in errors {
        log_assembly_error_adjusted(file, source, err, dispatcher);
    }
    if errors.len() > 1 {
        error!("aborting due to {} previous errors", errors.len());
    }
}

/// Adjusts line numbers in an error based on dispatcher offset.
fn adjust_error_line(err: VMError, dispatcher: Option<DispatcherInfo>) -> VMError {
    let Some(info) = dispatcher else {
        return err;
    };
    match err {
        VMError::AssemblyError {
            line,
            offset,
            length,
            source,
        } => VMError::AssemblyError {
            line: info.adjust_line(line),
            offset,
            length,
            source,
        },
        VMError::ParseError {
            line,
            offset,
            message,
        } => VMError::ParseError {
            line: info.adjust_line(line),
            offset,
            message,
        },
        VMError::ParseErrorString {
            line,
            offset,
            length,
            message,
        } => VMError::ParseErrorString {
            line: info.adjust_line(line),
            offset,
            length,
            message,
        },
        other => other,
    }
}

/// Logs a single assembly error, adjusting line number if dispatcher info is provided.
fn log_assembly_error_adjusted(
    file: &str,
    source: &str,
    err: &VMError,
    dispatcher: Option<DispatcherInfo>,
) {
    // Extract line/offset/length/message, adjusting line if needed
    let location = match err {
        VMError::AssemblyError {
            line,
            offset,
            length,
            source: msg,
        } => {
            let adjusted_line = dispatcher.map_or(*line, |d| d.adjust_line(*line));
            Some((adjusted_line, *offset, *length, msg.clone()))
        }
        VMError::ParseError {
            line,
            offset,
            message,
        } => {
            let adjusted_line = dispatcher.map_or(*line, |d| d.adjust_line(*line));
            Some((adjusted_line, *offset, 1, message.to_string()))
        }
        VMError::ParseErrorString {
            line,
            offset,
            length,
            message,
        } => {
            let adjusted_line = dispatcher.map_or(*line, |d| d.adjust_line(*line));
            Some((adjusted_line, *offset, *length, message.to_string()))
        }
        _ => None,
    };

    if let Some((line, offset, length, message)) = location {
        render_assembly_diagnostic(file, source, line, offset, length, &message);
    } else {
        error!("{err}");
    }
}

/// Represents which section of the assembly we're currently parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Section {
    /// Before any section marker - code goes to runtime by default.
    None,
    /// Inside `[ init code ]` section.
    Init,
    /// Inside `[ runtime code ]` section.
    Runtime,
}

/// Assembly context for heap items interning and label tracking during compilation.
///
/// Tracks heap items and labels encountered during assembly, assigning each
/// heap items a unique index that becomes part of the compiled [`DeployProgram`].
pub struct AsmContext {
    /// Accumulated heap items.
    pub items: Vec<Vec<u8>>,
    /// Label definitions mapping names to global bytecode offsets (init || runtime).
    pub(crate) labels: HashMap<String, usize>,
}

impl AsmContext {
    /// Creates an empty assembly context.
    pub fn new() -> Self {
        Self {
            items: Vec::new(),
            labels: HashMap::new(),
        }
    }

    /// Adds a string to the pool, returning its index.
    /// Returns existing index if the string was already interned.
    pub fn intern_string(&mut self, s: String) -> u32 {
        let bytes = s.into_bytes();
        if let Some(idx) = self.items.iter().position(|item| *item == bytes) {
            return idx as u32;
        }
        let id = self.items.len() as u32;
        self.items.push(bytes);
        id
    }

    /// Registers a label at the given global bytecode offset.
    pub(crate) fn define_label(&mut self, name: String, offset: usize) -> Result<(), VMError> {
        if self.labels.contains_key(&name) {
            return Err(VMError::DuplicateLabel { label: name });
        }
        self.labels.insert(name, offset);
        Ok(())
    }

    /// Resolves a label to its global bytecode offset.
    pub(crate) fn resolve_label(&self, name: &str) -> Result<usize, VMError> {
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
struct Token<'a> {
    text: &'a str,
    /// 1-based column offset in the line.
    offset: usize,
}

/// Represents a parsed function label from assembly source.
///
/// Labels define entry points in assembly code with optional parameter specifications.
/// The format is: `[pub] name[(argc, rN)]:` where:
/// - `pub` marks the label as a public entry point
/// - `argc` is the number of arguments the function expects
/// - `rN` specifies the first register containing arguments
#[derive(Debug)]
#[allow(dead_code)]
pub struct Label<'a> {
    /// Whether this label is marked as public (`pub` prefix).
    pub public: bool,
    /// The label identifier.
    pub name: &'a str,
    /// Number of arguments the function expects (0 if no parameter spec).
    pub argc: u8,
    /// First register containing arguments (0 if no parameter spec).
    pub argr: u8,
}

/// Returns true if the byte is a valid identifier character.
///
/// Valid characters are: `a-z`, `A-Z`, `0-9`, and `_`.
fn is_ident_char(c: u8) -> bool {
    (c | 0x20).is_ascii_lowercase() || c.is_ascii_digit() || c == b'_'
}

/// Parses a label definition line into a [`Label`] struct.
///
/// Accepts labels in these formats:
/// - `name:` - simple label
/// - `pub name:` - public label
/// - `name(N, rM):` - label with N arguments starting at register rM
/// - `pub name(N, rM):` - public label with parameter specification
///
/// Leading spaces are allowed. Returns an error if the line does not
/// contain a valid label definition.
fn tokenize_label(line_no: usize, line: &str) -> Result<Label<'_>, VMError> {
    let bytes = line.as_bytes();
    let mut i = 0;

    // skip leading spaces
    while i < bytes.len() && bytes[i] == b' ' {
        i += 1;
    }

    // pub
    let public = bytes.get(i..i + 4) == Some(b"pub ");
    if public {
        i += 4;
    }

    // name
    let start = i;
    while i < bytes.len() && is_ident_char(bytes[i]) {
        i += 1;
    }

    if start == i {
        return Err(VMError::ParseError {
            line: line_no,
            offset: i,
            message: "expected label name",
        });
    }

    let name = &line[start..i];

    if i >= bytes.len() {
        return Err(VMError::ParseError {
            line: line_no,
            offset: i,
            message: "unexpected end of label, expected '(' or ':'",
        });
    }

    // no args
    if bytes[i] == LABEL_SUFFIX as u8 {
        return Ok(Label {
            public,
            name,
            argc: 0,
            argr: 0,
        });
    }

    // args
    if bytes[i] != b'(' {
        return Err(VMError::ParseError {
            line: line_no,
            offset: i,
            message: "expected '(' or ':' after label name",
        });
    }
    i += 1;

    let arg_start = i;
    while i < bytes.len() && bytes[i] != b')' {
        i += 1;
    }

    if i >= bytes.len() {
        return Err(VMError::ParseError {
            line: line_no,
            offset: i,
            message: "unclosed '(' in label parameters",
        });
    }

    let arg_data = &line[arg_start..i];
    i += 1;

    if i >= bytes.len() || bytes[i] != b':' {
        return Err(VMError::ParseError {
            line: line_no,
            offset: i,
            message: "expected ':' after label parameters",
        });
    }

    let mut j = 0;
    let ab = arg_data.as_bytes();

    while j < ab.len() && ab[j] == b' ' {
        j += 1;
    }
    let n_start = j;

    while j < ab.len() && ab[j].is_ascii_digit() {
        j += 1;
    }
    let argc = parse_u8(&arg_data[n_start..j]).map_err(|e| VMError::ParseErrorString {
        line: line_no,
        offset: arg_start + n_start + 1,
        length: j - n_start,
        message: e.to_string(),
    })?;

    while j < ab.len() && ab[j] == b' ' {
        j += 1;
    }
    if j >= ab.len() || ab[j] != b',' {
        return Err(VMError::ParseError {
            line: line_no,
            offset: arg_start + j,
            message: "expected 'N, rM' format in label parameters",
        });
    }
    j += 1;

    while j < ab.len() && ab[j] == b' ' {
        j += 1;
    }
    if j >= ab.len() || ab[j] != b'r' {
        return Err(VMError::ParseError {
            line: line_no,
            offset: arg_start + j,
            message: "expected register 'rN' in label parameters",
        });
    }
    j += 1;

    let r_start = j;
    while j < ab.len() && ab[j].is_ascii_digit() {
        j += 1;
    }
    let argr = parse_u8(&arg_data[r_start..j]).map_err(|e| VMError::ParseErrorString {
        line: line_no,
        offset: arg_start + r_start + 1,
        length: j - r_start,
        message: e.to_string(),
    })?;

    while j < ab.len() {
        if ab[j] != b' ' {
            return Err(VMError::ParseError {
                line: line_no,
                offset: arg_start + j,
                message: "unexpected character after label parameters",
            });
        }
        j += 1;
    }

    Ok(Label {
        public,
        name,
        argc,
        argr,
    })
}

/// Tokenize a single line of assembly.
///
/// Rules:
/// - `#` starts a comment
/// - commas are ignored
/// - whitespace-separated tokens
fn tokenize(line_no: usize, line: &str) -> Result<Vec<Token<'_>>, VMError> {
    let mut out = Vec::with_capacity(8);

    let mut start: Option<usize> = None;
    let mut start_col: usize = 0;
    let mut in_str = false;

    let bytes = line.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        let b = bytes[i];

        // comment start
        if b == COMMENT_CHAR as u8 && !in_str {
            break;
        }

        match b {
            b'"' => {
                if start.is_none() {
                    start = Some(i);
                    start_col = i + 1;
                }
                in_str = !in_str;
                i += 1;
            }

            b',' | b' ' | b'\t' if !in_str => {
                if let Some(s) = start {
                    let text = &line[s..i];
                    let text = text.trim();
                    if !text.is_empty() {
                        out.push(Token {
                            text,
                            offset: start_col,
                        });
                    }
                    start = None;
                }
                i += 1;
            }

            _ => {
                if start.is_none() {
                    start = Some(i);
                    start_col = i + 1;
                }
                i += 1;
            }
        }
    }

    if in_str {
        return Err(VMError::ParseError {
            line: line_no,
            offset: start_col,
            message: "unterminated string literal (missing closing quote)",
        });
    }

    if let Some(s) = start {
        let text = line[s..i].trim();
        if !text.is_empty() {
            out.push(Token {
                text,
                offset: start_col,
            });
        }
    }

    Ok(out)
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

/// Parses an i64 immediate or a label reference.
///
/// If `tok` parses as an integer, returns it directly. Otherwise, resolves
/// `tok` as a label name and computes a PC-relative offset in the global
/// address space (init || runtime).
pub(crate) fn parse_i64_or_label(
    tok: &str,
    ctx: &AsmContext,
    current_global_offset: usize,
) -> Result<i64, VMError> {
    if let Ok(v) = tok.parse::<i64>() {
        return Ok(v);
    }
    let target = ctx.resolve_label(tok)?;
    Ok(target as i64 - current_global_offset as i64)
}

fn parse_src(
    tok: &str,
    ctx: &mut AsmContext,
    current_offset: usize,
) -> Result<SrcOperand, VMError> {
    // Register: r0, r1, ...
    if let Ok(reg) = parse_reg(tok) {
        return Ok(SrcOperand::Reg(reg));
    }
    // Bool literals
    if tok == "true" {
        return Ok(SrcOperand::Bool(true));
    }
    if tok == "false" {
        return Ok(SrcOperand::Bool(false));
    }
    // String literal
    if let Some(s) = tok.strip_prefix('"').and_then(|t| t.strip_suffix('"')) {
        return Ok(SrcOperand::Ref(ctx.intern_string(s.to_string())));
    }
    // i64 or label
    Ok(SrcOperand::I64(parse_i64_or_label(
        tok,
        ctx,
        current_offset,
    )?))
}

/// Extracts the token text that caused an error, if available.
fn error_token_text(err: &VMError) -> Option<&str> {
    match err {
        VMError::ExpectedRegister(tok) => Some(tok),
        VMError::InvalidRegister { token } => Some(token),
        VMError::ArgcOutOfRange { actual } => Some(actual),
        VMError::TypeMismatch { actual, .. } => Some(actual),
        VMError::UndefinedLabel { label } => Some(label),
        VMError::UndefinedFunction { function } => Some(function),
        _ => None,
    }
}

/// Checks if a line appears to be a label definition attempt.
///
/// Returns `true` for valid patterns like `name:`, `pub name:`, `name(N, rM):`,
/// and also for malformed attempts like `pub name(` so that `tokenize_label`
/// can produce a proper error message.
fn is_label_def(line: &str) -> bool {
    let trimmed = line.trim_start();
    let is_pub = trimmed.starts_with("pub ");
    let after_pub = trimmed.strip_prefix("pub ").unwrap_or(trimmed);

    // Find identifier start
    let bytes = after_pub.as_bytes();
    if bytes.is_empty() || !is_ident_char(bytes[0]) {
        return false;
    }

    // Skip identifier
    let mut i = 0;
    while i < bytes.len() && is_ident_char(bytes[i]) {
        i += 1;
    }

    // `pub name...` is always a label attempt
    if is_pub {
        return true;
    }

    if i >= bytes.len() {
        return false;
    }

    // After identifier: `:` or `(` indicates label
    bytes[i] == LABEL_SUFFIX as u8 || bytes[i] == b'('
}

/// Computes the encoded size of a Src operand from its token text.
///
/// Determines the operand type by inspecting the token:
/// - Register (r0, r1, ...): tag(1) + reg(1) = 2 bytes
/// - Bool (true/false): tag(1) + bool(1) = 2 bytes
/// - String literal ("..."): tag(1) + ref(4) = 5 bytes
/// - Number or label: tag(1) + i64(8) = 9 bytes
fn src_size_from_token(tok: &str) -> usize {
    if tok.starts_with('r') && tok.len() > 1 && tok[1..].chars().all(|c| c.is_ascii_digit())
        || tok == "true"
        || tok == "false"
    {
        2 // tag + (register or bool)
    } else if tok.starts_with('"') {
        5 // tag + u32 ref
    } else {
        9 // tag + i64 (numbers and labels)
    }
}

/// Checks if a line is a section marker and returns the section type if so.
fn parse_section_marker(line: &str) -> Option<Section> {
    let trimmed = line.trim();
    if trimmed.eq_ignore_ascii_case(SECTION_INIT) {
        Some(Section::Init)
    } else if trimmed.eq_ignore_ascii_case(SECTION_RUNTIME) {
        Some(Section::Runtime)
    } else {
        None
    }
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

        /// Returns the bytecode size for an instruction from its tokens.
        ///
        /// Tokens should include the instruction mnemonic followed by operands.
        /// Size depends on operand types, which are determined by inspecting tokens.
        fn instruction_size_from_tokens(tokens: &[Token]) -> Result<usize, VMError> {
            if tokens.is_empty() {
                return Err(VMError::ArityMismatch {
                    instruction: "<missing opcode>".to_string(),
                    expected: 1,
                    actual: 0,
                });
            }

            let instr = instruction_from_str(tokens[0].text)?;
            let mut tok_iter = tokens.iter().skip(1);
            Ok(match instr {
                $(
                    Instruction::$name => {
                        const EXPECTED: usize = 1 + define_parse_instruction!(@count $( $field ),*);
                        if tokens.len() != EXPECTED {
                            return Err(VMError::ArityMismatch {
                                instruction: tokens[0].text.to_string(),
                                expected: EXPECTED - 1,
                                actual: tokens.len() - 1,
                            });
                        }
                        1usize $( + define_parse_instruction!(@token_size $kind, tok_iter) )*
                    }
                ),*
            })
        }

        /// Parse one instruction from tokens into [`AsmInstr`].
        ///
        /// `current_global_offset` is the global bytecode offset (in init || runtime space)
        /// where this instruction starts, used for resolving label references to relative offsets.
        fn parse_instruction(
            ctx: &mut AsmContext,
            tokens: &[Token],
            current_global_offset: usize,
        ) -> Result<AsmInstr, VMError> {
            if tokens.is_empty() {
                return Err(VMError::ArityMismatch {
                    instruction: "<missing opcode>".to_string(),
                    expected: 1,
                    actual: 0,
                });
            }

            let instr = instruction_from_str(&tokens[0].text)?;
            let offset = current_global_offset + instruction_size_from_tokens(tokens)?;

            match instr {
                $(
                    Instruction::$name => {
                        const EXPECTED: usize = 1 + define_parse_instruction!(@count $( $field ),*);
                        if tokens.len() != EXPECTED {
                            return Err(VMError::ArityMismatch {
                                instruction: tokens[0].text.to_string(),
                                expected: EXPECTED - 1,
                                actual: tokens.len() - 1,
                            });
                        }

                        define_parse_instruction!(
                            @construct ctx offset tokens; $name $( $field : $kind ),*
                        )
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

    // ---------- operand sizes from tokens ----------
    (@token_size Reg, $iter:ident) => { { $iter.next(); 1usize } };
    (@token_size RefU32, $iter:ident) => { { $iter.next(); 4usize } };
    (@token_size ImmU8, $iter:ident) => { { $iter.next(); 1usize } };
    (@token_size ImmI64, $iter:ident) => { { $iter.next(); 8usize } };
    (@token_size Src, $iter:ident) => { { src_size_from_token($iter.next().unwrap().text) } };

    // ---------- parsing ----------
    (@construct $ctx:ident $offset:ident $tokens:ident; $name:ident) => {
        Ok(AsmInstr::$name { })
    };

    (@construct $ctx:ident $offset:ident $tokens:ident; $name:ident $( $field:ident : $kind:ident ),+ ) => {{
        let mut it = $tokens.iter().skip(1);
        Ok(AsmInstr::$name {
            $(
                $field: define_parse_instruction!(
                    @parse_operand $kind, it.next().unwrap(), $ctx, $offset
                )?,
            )*
        })
    }};

    (@parse_operand Reg, $tok:expr, $ctx:expr, $current_offset:expr) => {{
          parse_reg(&$tok.text)
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

    (@parse_operand Src, $tok:expr, $ctx:expr, $current_offset:expr) => {
        parse_src(&$tok.text, $ctx, $current_offset)
    };
}

for_each_instruction!(define_parse_instruction);

/// Extracts all labels from assembly source, identifying public entry points.
///
/// Scans the source for label definitions and returns:
/// - A set of public label names (those prefixed with `pub`)
/// - A vector of all parsed [`Label`] structs
///
/// Also updates `insert_point` to the line number of the `[ runtime code ]`
/// section marker, which is used for dispatcher insertion.
pub fn extract_public_labels<'a>(
    source: &'a str,
    insert_point: &mut usize,
) -> Result<(HashSet<&'a str>, Vec<Label<'a>>), VMError> {
    let mut public_labels: HashSet<&str> = HashSet::new();
    let mut public_label_data: Vec<Label> = Vec::new();

    // First pass: scan source to find public labels and the runtime section marker
    for (line_no, line) in source.lines().enumerate() {
        // Check for section markers first
        if let Some(section) = parse_section_marker(line) {
            if section == Section::Runtime {
                *insert_point = line_no;
            }
            continue;
        }

        if is_label_def(line) {
            // Check if this is a public label definition (`pub label_name(N, reg):`)
            let label = tokenize_label(line_no + 1, line)?;
            if label.public {
                public_labels.insert(label.name);
            }
            public_label_data.push(label);
        }
    }

    Ok((public_labels, public_label_data))
}

/// Preprocesses assembly source to generate a dispatcher for public entry points.
///
/// Scans the source for labels prefixed with `pub` and generates a jump table
/// (`__resolver_jump_table`) that dispatches to public functions based on a
/// selector in `r0`. The generated dispatcher is inserted at the start of the
/// `[ runtime code ]` section.
///
/// Collects tokenization errors into the provided vector and continues processing.
/// Returns the processed source and optional dispatcher info for line adjustment.
fn assemble_source_step_1<'a>(
    source: &'a str,
    errors: &mut Vec<VMError>,
) -> (
    Option<String>,
    Option<DispatcherInfo>,
    Option<Vec<Label<'a>>>,
) {
    // Track where to insert the dispatcher (line number of `[ runtime code ]`)
    let mut insert_point = 0usize;
    // Collect all public label names (including trailing ':')
    let (public_labels, public_label_data) = match extract_public_labels(source, &mut insert_point)
    {
        Ok(p) => p,
        Err(e) => {
            errors.push(e);
            return (None, None, None);
        }
    };

    if public_labels.is_empty() {
        return (None, None, None);
    }

    let mut base = String::new();
    let mut labels: Vec<&str> = public_labels.iter().copied().collect();
    labels.sort();
    let has_multiple = labels.len() > 1;
    if has_multiple {
        // Jump over the entries while capturing the base address (r254) of
        // `__dispatch_header` via the JAL return address. Entries sit right
        // after this instruction so the captured address is the entry base.
        base.push_str("JAL r254, __dispatch_header\n");
    }

    for label in labels.iter() {
        let name = label.strip_suffix(':').unwrap_or(label);
        // Use CALL0 to keep per-entry size minimal (11 bytes with HALT) while leaving
        // argument registers untouched for the callee.
        writeln!(base, "CALL0 r0, {name}\nHALT\n").unwrap();
    }

    if has_multiple {
        base.push_str("__dispatch_header:\n");
        base.push_str("MUL r253, r0, 11\n"); // byte offset into table
        base.push_str("ADD r253, r253, r254\n"); // absolute addr of target entry
        base.push_str("JALR r255, r253, 0\n");
        base.push_str("HALT\n");
    }

    // Count lines added by dispatcher (+1 for the extra newline after base)
    let lines_added = base.lines().count() + 1;

    // Reassemble source with dispatcher inserted at the runtime section marker
    let mut out = String::with_capacity(source.len() + base.len());
    for (i, line) in source.lines().enumerate() {
        out.push_str(line.split(COMMENT_CHAR).next().unwrap_or("").trim());
        out.push('\n');
        // Insert dispatcher just after the `[ runtime code ]` line
        if i == insert_point {
            out.push_str(&base);
            out.push('\n');
        }
    }

    let dispatcher_info = DispatcherInfo {
        insert_after: insert_point + 1, // 1-indexed, after the section marker
        lines_added,
    };

    (Some(out), Some(dispatcher_info), Some(public_label_data))
}

/// Performs two-pass assembly on preprocessed source.
///
/// Pass 1: Tokenizes all lines, detects `[ init code ]` / `[ runtime code ]` sections,
/// computes instruction sizes, and records label positions as global offsets in the
/// concatenated address space (init || runtime).
///
/// Pass 2: Parses instructions with label resolution and emits bytecode.
///
/// Collects all errors into the provided vector and continues processing where possible.
fn assemble_source_step_2(
    source: String,
    _label_data: Vec<Label>,
    errors: &mut Vec<VMError>,
) -> Option<DeployProgram> {
    let mut asm_context = AsmContext::new();

    // First pass: tokenize all lines, detect sections, compute global offsets
    // We track (line_no, tokens, section) for each instruction line
    let mut parsed_lines: Vec<(usize, Vec<Token>, Section)> = Vec::new();
    let mut current_section = Section::None;

    // Track sizes separately for init and runtime sections
    let mut init_size = 0usize;
    let mut runtime_size = 0usize;

    // Temporary label storage: (name, global_offset, line_no, tok_offset)
    // (name, section, local_offset, line_no, tok_offset, tok_len)
    let mut pending_labels: Vec<(String, Section, usize, usize, usize, usize)> = Vec::new();

    for (line_no, line) in source.lines().enumerate() {
        // Check for section markers first
        if let Some(section) = parse_section_marker(line) {
            current_section = section;
            continue;
        }

        // Determine which section this code belongs to
        let effective_section = match current_section {
            Section::None | Section::Runtime => Section::Runtime,
            Section::Init => Section::Init,
        };

        // Get the offset pointer for the current section
        let local_offset = match effective_section {
            Section::Init => &mut init_size,
            Section::Runtime | Section::None => &mut runtime_size,
        };

        // Check if first token is a label definition
        let mut instr_start = 0;
        if is_label_def(line) {
            let label = match tokenize_label(line_no + 1, line) {
                Ok(l) => l,
                Err(e) => {
                    errors.push(e);
                    continue;
                }
            };

            pending_labels.push((
                label.name.to_string(),
                effective_section,
                *local_offset,
                line_no + 1,
                if label.public { 4 } else { 0 },
                label.name.len(),
            ));

            // If there are more tokens after the label, treat them as an instruction
            instr_start = line.find(':').unwrap() + 1;
        }

        let tokens = match tokenize(line_no + 1, &line[instr_start..]) {
            Ok(t) => t,
            Err(e) => {
                errors.push(e);
                continue;
            }
        };
        if tokens.is_empty() {
            continue;
        }

        match instruction_size_from_tokens(&tokens) {
            Ok(size) => {
                *local_offset += size;
                parsed_lines.push((line_no, tokens, effective_section));
            }
            Err(e) => {
                errors.push(VMError::AssemblyError {
                    line: line_no + 1,
                    offset: tokens[0].offset,
                    length: tokens[0].text.len(),
                    source: e.to_string(),
                });
            }
        }
    }

    // Register labels with global offsets (init || runtime address space).
    for (name, section, local_offset, line_no, tok_offset, tok_len) in pending_labels {
        let global_offset = match section {
            Section::Init => local_offset,
            Section::Runtime | Section::None => init_size + local_offset,
        };
        if let Err(e) = asm_context.define_label(name, global_offset) {
            errors.push(VMError::AssemblyError {
                line: line_no,
                offset: tok_offset,
                length: tok_len,
                source: e.to_string(),
            });
        }
    }

    // Second pass: parse instructions and emit bytecode to separate vectors
    let mut init_bytecode = Vec::new();
    let mut runtime_bytecode = Vec::new();

    for (line_no, tokens, section) in parsed_lines {
        let bytecode = match section {
            Section::Init => &mut init_bytecode,
            Section::Runtime | Section::None => &mut runtime_bytecode,
        };

        // Compute global offset for label resolution
        let global_offset = match section {
            Section::Init => bytecode.len(),
            Section::Runtime | Section::None => init_size + bytecode.len(),
        };

        match parse_instruction(&mut asm_context, &tokens, global_offset) {
            Ok(instr) => instr.assemble(bytecode),
            Err(e) => {
                // Find the token that caused the error for accurate cursor positioning
                let error_tok =
                    error_token_text(&e).and_then(|text| tokens.iter().find(|t| t.text == text));
                let (offset, length) =
                    error_tok
                        .map(|t| (t.offset, t.text.len()))
                        .unwrap_or_else(|| {
                            tokens
                                .first()
                                .map(|t| (t.offset, t.text.len()))
                                .unwrap_or((1, 1))
                        });
                errors.push(VMError::AssemblyError {
                    line: line_no + 1,
                    offset,
                    length,
                    source: e.to_string(),
                });
            }
        }
    }

    if errors.is_empty() {
        Some(DeployProgram {
            init_code: init_bytecode,
            runtime_code: runtime_bytecode,
            items: asm_context.items,
        })
    } else {
        None
    }
}

/// Assemble a full source string into bytecode.
///
/// Uses two-pass assembly:
/// 1. First pass: tokenize lines, record label positions, detect sections
/// 2. Second pass: parse instructions with label resolution, emit bytecode
///
/// Section markers `[ init code ]` and `[ runtime code ]` split the source:
/// - Code between `[ init code ]` and `[ runtime code ]` goes to `init_code`
/// - Code after `[ runtime code ]` goes to `runtime_code`
/// - Code before any section marker goes to `runtime_code` by default
///
/// Labels are computed for a concatenated view (init_code + runtime_code) so that
/// init_code can call into runtime_code. The VM should run the concatenated bytecode,
/// starting at ip=0 for deployment and ip=init_code.len() for runtime calls.
pub fn assemble_source(source: impl Into<String>) -> Result<DeployProgram, VMError> {
    assemble_source_with_name(source.into(), "<source>")
}

/// Assembles source with an associated filename for error diagnostics.
///
/// Runs both assembly passes and logs compiler-style diagnostics to stderr
/// on failure, including source location information for all errors found.
fn assemble_source_with_name(source: String, source_name: &str) -> Result<DeployProgram, VMError> {
    let mut errors = Vec::new();

    let (processed, dispatcher_info, label_data) = assemble_source_step_1(&source, &mut errors);
    if processed.is_none() && !errors.is_empty() {
        // Use original source for error display, with line adjustment for dispatcher
        log_assembly_errors(source_name, &source, &errors, dispatcher_info);
        // Return the first error with adjusted line number
        let first_err = errors.into_iter().next().unwrap();
        return Err(adjust_error_line(first_err, dispatcher_info));
    }

    let not_empty = processed.is_some();
    let result = assemble_source_step_2(
        if not_empty {
            processed.unwrap()
        } else {
            source.clone()
        },
        if not_empty {
            label_data.unwrap()
        } else {
            vec![]
        },
        &mut errors,
    );
    if !errors.is_empty() {
        // Use original source for error display, with line adjustment for dispatcher
        log_assembly_errors(source_name, &source, &errors, dispatcher_info);
        // Return the first error with adjusted line number
        let first_err = errors.into_iter().next().unwrap();
        return Err(adjust_error_line(first_err, dispatcher_info));
    }

    result.ok_or_else(|| VMError::AssemblyError {
        line: 0,
        offset: 0,
        length: 1,
        source: "assembly failed".to_string(),
    })
}

/// Convenience: assemble directly from file path
pub fn assemble_file<P: AsRef<Path>>(path: P) -> Result<DeployProgram, VMError> {
    let path_ref = path.as_ref();
    let source = fs::read_to_string(path_ref).map_err(|e| VMError::IoError {
        path: path_ref.display().to_string(),
        source: e.to_string(),
    })?;
    assemble_source_with_name(source, &path_ref.display().to_string())
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
        assert!(program.runtime_code.is_empty());
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
        assert!(program.runtime_code.is_empty());
    }

    #[test]
    fn assemble_inline_comment() {
        let source = format!("MOVE r0, 42 {COMMENT_CHAR} load value");
        let program = assemble_source(source).unwrap();
        assert_eq!(program.runtime_code.len(), 11); // opcode(1) + reg(1) + tag(1) + i64(8)
    }

    #[test]
    fn assemble_invalid_instruction() {
        let err = assemble_source("INVALID r0").unwrap_err();
        assert!(matches!(
            err,
            VMError::AssemblyError { line: 1, offset: _, ref source,.. } if source.contains("unknown instruction")
        ));
    }

    #[test]
    fn assemble_wrong_arity() {
        let err = assemble_source("ADD r0, r1").unwrap_err();
        assert!(matches!(
            err,
            VMError::AssemblyError { line: 1, offset: _, ref source,.. } if source.contains("operand count mismatch")
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
    fn assemble_multiple_strings() {
        let source = r#"
            MOVE r0, "first"
            MOVE r1, "second"
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
            MOVE r0, "first
        "#;
        assert!(assemble_source(source).is_err());

        let source = r#"
            MOVE r0, first
        "#;
        assert!(assemble_source(source).is_err());

        let source = r#"
            MOVE r0, first"
        "#;
        assert!(assemble_source(source).is_err());
    }

    #[test]
    fn instruction_parse_empty() {
        assert!(matches!(
            parse_instruction(&mut AsmContext::new(), &[], 0),
            Err(VMError::ArityMismatch { .. })
        ));
    }

    #[test]
    fn instruction_parse_three_reg() {
        let tokens = vec![
            Token {
                text: "ADD",
                offset: 1,
            },
            Token {
                text: "r0",
                offset: 5,
            },
            Token {
                text: "r1",
                offset: 9,
            },
            Token {
                text: "r2",
                offset: 13,
            },
        ];
        let instr = parse_instruction(&mut AsmContext::new(), &tokens, 0).unwrap();
        match instr {
            AsmInstr::Add { rd, rs1, rs2 } => {
                assert_eq!(rd, 0);
                assert_eq!(rs1, SrcOperand::Reg(1));
                assert_eq!(rs2, SrcOperand::Reg(2));
            }
            _ => panic!("wrong instruction type"),
        }
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
    fn asm_instr_assemble_three_reg() {
        let instr = AsmInstr::Sub {
            rd: 10,
            rs1: SrcOperand::I64(20),
            rs2: SrcOperand::I64(30),
        };
        let mut out = Vec::new();
        instr.assemble(&mut out);
        let mut expected = vec![Instruction::Sub as u8, 10, 2];
        expected.extend_from_slice(&20i64.to_le_bytes());
        expected.push(2);
        expected.extend_from_slice(&30i64.to_le_bytes());
        assert_eq!(out, expected);
    }

    #[test]
    fn asm_instr_assemble_two_reg() {
        let instr = AsmInstr::Neg {
            rd: 1,
            rs: SrcOperand::I64(2),
        };
        let mut out = Vec::new();
        instr.assemble(&mut out);
        let mut expected = vec![Instruction::Neg as u8, 1, 2];
        expected.extend_from_slice(&2i64.to_le_bytes());
        assert_eq!(out, expected);
    }

    // ==================== Labels ====================

    #[test]
    fn duplicate_label_error() {
        let source = "dup: MOVE r0, 1\ndup: MOVE r1, 2";
        let err = assemble_source(source).unwrap_err();
        assert!(matches!(
            err,
            VMError::AssemblyError { line: 2, offset: _, ref source,.. } if source.contains("duplicate")
        ));
    }

    #[test]
    fn undefined_label_error() {
        let source = "JAL r0, missing";
        let err = assemble_source(source).unwrap_err();
        assert!(matches!(
            err,
            VMError::AssemblyError { line: 1, offset: _, ref source,.. } if source.contains("undefined")
        ));
    }

    #[test]
    fn is_label_def_valid() {
        // Simple labels
        assert!(is_label_def("start:"));
        assert!(is_label_def("_loop:"));
        assert!(is_label_def("label123:"));
        // Public labels
        assert!(is_label_def("pub start:"));
        assert!(is_label_def("pub _func:"));
        // Labels with params
        assert!(is_label_def("func(1, r2):"));
        assert!(is_label_def("pub func(1, r2):"));
        // Labels with instructions after
        assert!(is_label_def("start: MOVE r0, 1"));
        assert!(is_label_def("pub func(1, r2): MOVE r0, 1"));
        // Leading whitespace
        assert!(is_label_def("    start:"));
        assert!(is_label_def("  pub func(1, r2):"));
    }

    #[test]
    fn is_label_def_invalid() {
        assert!(!is_label_def(":"));
        assert!(!is_label_def("label"));
        assert!(!is_label_def(""));
        assert!(!is_label_def("MOVE r0, 1"));
        assert!(!is_label_def("pub"));
    }

    #[test]
    fn is_label_def_malformed_attempts() {
        // These are malformed but still recognized as label attempts
        // so tokenize_label can produce proper error messages
        assert!(is_label_def("func(1, r2)")); // missing `:` after `)`
        assert!(is_label_def("pub func(1, r2")); // missing `):`
        assert!(is_label_def("pub func")); // `pub` prefix = label attempt
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
        assert_eq!(program.runtime_code[0], Instruction::CallHost as u8);
        assert_eq!(program.runtime_code[1], 0); // dst = r0
        assert_eq!(program.runtime_code[6], 3); // argc = 3 (single byte)
        assert_eq!(program.runtime_code[7], 1); // argv = r1
        assert_eq!(program.runtime_code.len(), 8);
    }

    #[test]
    fn assemble_call_argc_u8() {
        // CALL: opcode(1) + dst(1) + fn_id(8) + argc(1) + argv(1) = 12 bytes
        let program = assemble_source("my_func:\nCALL r0, my_func, 5, r2").unwrap();
        assert_eq!(program.runtime_code[0], Instruction::Call as u8);
        assert_eq!(program.runtime_code[1], 0); // dst = r0
        assert_eq!(program.runtime_code[10], 5); // argc = 5 (single byte)
        assert_eq!(program.runtime_code[11], 2); // argv = r2
        assert_eq!(program.runtime_code.len(), 12);
    }

    #[test]
    fn assemble_call_argc_max_u8() {
        let program = assemble_source(r#"CALL_HOST r0, "fn", 255, r0"#).unwrap();
        assert_eq!(program.runtime_code[6], 255); // max u8 value
    }

    #[test]
    fn assemble_call_argc_overflow() {
        // 256 exceeds u8 range
        let err = assemble_source(r#"CALL_HOST r0, "fn", 256, r0"#).unwrap_err();
        assert!(matches!(err, VMError::AssemblyError { .. }));
    }

    // ==================== Sections ====================

    #[test]
    fn parse_section_marker_valid() {
        assert_eq!(parse_section_marker("[ init code ]"), Some(Section::Init));
        assert_eq!(
            parse_section_marker("[ runtime code ]"),
            Some(Section::Runtime)
        );
        assert_eq!(
            parse_section_marker("  [ init code ]  "),
            Some(Section::Init)
        );
        assert_eq!(parse_section_marker("[ INIT CODE ]"), Some(Section::Init));
    }

    #[test]
    fn parse_section_marker_invalid() {
        assert_eq!(parse_section_marker("init code"), None);
        assert_eq!(parse_section_marker("[init code]"), None);
        assert_eq!(parse_section_marker("[ unknown ]"), None);
        assert_eq!(parse_section_marker("MOVE r0, 1"), None);
    }

    #[test]
    fn assemble_no_sections_defaults_to_runtime() {
        let program = assemble_source("MOVE r0, 1").unwrap();
        assert!(program.init_code.is_empty());
        assert!(!program.runtime_code.is_empty());
    }

    #[test]
    fn assemble_init_section_only() {
        let source = "[ init code ]\nMOVE r0, 42";
        let program = assemble_source(source).unwrap();
        assert_eq!(program.init_code.len(), 11);
        assert!(program.runtime_code.is_empty());
    }

    #[test]
    fn assemble_runtime_section_only() {
        let source = "[ runtime code ]\nMOVE r0, 42";
        let program = assemble_source(source).unwrap();
        assert!(program.init_code.is_empty());
        assert_eq!(program.runtime_code.len(), 11);
    }

    #[test]
    fn assemble_both_sections() {
        let source = r#"
[ init code ]
MOVE r0, 1
MOVE r1, 2

[ runtime code ]
MOVE r2, 3
"#;
        let program = assemble_source(source).unwrap();
        assert_eq!(program.init_code.len(), 22); // 2 MOVE instructions
        assert_eq!(program.runtime_code.len(), 11); // 1 MOVE instruction
    }

    #[test]
    fn assemble_labels_within_sections() {
        let source = r#"
[ init code ]
start: MOVE r0, 1

[ runtime code ]
func: MOVE r1, 2
"#;
        let program = assemble_source(source).unwrap();
        assert!(!program.init_code.is_empty());
        assert!(!program.runtime_code.is_empty());
    }

    #[test]
    fn assemble_empty_init_section() {
        let source = "[ init code ]\n[ runtime code ]\nMOVE r0, 1";
        let program = assemble_source(source).unwrap();
        assert!(program.init_code.is_empty());
        assert_eq!(program.runtime_code.len(), 11);
    }

    #[test]
    fn assemble_strings_across_sections() {
        let source = r#"
[ init code ]
MOVE r0, "init"

[ runtime code ]
MOVE r1, "runtime"
"#;
        let program = assemble_source(source).unwrap();
        assert_eq!(program.items.len(), 2);
        assert_eq!(program.items[0], b"init");
        assert_eq!(program.items[1], b"runtime");
    }

    // ==================== Label Tokenization ====================

    #[test]
    fn tokenize_label_simple() {
        let label = tokenize_label(1, "name:").unwrap();
        assert!(!label.public);
        assert_eq!(label.name, "name");
        assert_eq!(label.argc, 0);
        assert_eq!(label.argr, 0);
    }

    #[test]
    fn tokenize_label_public() {
        let label = tokenize_label(1, "pub name:").unwrap();
        assert!(label.public);
        assert_eq!(label.name, "name");
        assert_eq!(label.argc, 0);
        assert_eq!(label.argr, 0);
    }

    #[test]
    fn tokenize_label_with_params() {
        let label = tokenize_label(1, "func(3, r5):").unwrap();
        assert!(!label.public);
        assert_eq!(label.name, "func");
        assert_eq!(label.argc, 3);
        assert_eq!(label.argr, 5);
    }

    #[test]
    fn tokenize_label_public_with_params() {
        let label = tokenize_label(1, "pub func(10, r0):").unwrap();
        assert!(label.public);
        assert_eq!(label.name, "func");
        assert_eq!(label.argc, 10);
        assert_eq!(label.argr, 0);
    }

    #[test]
    fn tokenize_label_max_params() {
        let label = tokenize_label(1, "f(255, r255):").unwrap();
        assert_eq!(label.argc, 255);
        assert_eq!(label.argr, 255);
    }

    #[test]
    fn tokenize_label_leading_spaces() {
        let label = tokenize_label(1, "    name:").unwrap();
        assert_eq!(label.name, "name");

        let label = tokenize_label(1, "  pub func(1, r2):").unwrap();
        assert!(label.public);
        assert_eq!(label.name, "func");
    }

    #[test]
    fn tokenize_label_underscore_and_numbers() {
        let label = tokenize_label(1, "_private:").unwrap();
        assert_eq!(label.name, "_private");

        let label = tokenize_label(1, "func123:").unwrap();
        assert_eq!(label.name, "func123");

        let label = tokenize_label(1, "_123_abc_:").unwrap();
        assert_eq!(label.name, "_123_abc_");
    }

    #[test]
    fn tokenize_label_params_with_spaces() {
        let label = tokenize_label(1, "f( 1 , r2 ):").unwrap();
        assert_eq!(label.argc, 1);
        assert_eq!(label.argr, 2);

        let label = tokenize_label(1, "f(  5  ,  r10  ):").unwrap();
        assert_eq!(label.argc, 5);
        assert_eq!(label.argr, 10);
    }

    #[test]
    fn tokenize_label_missing_name() {
        let err = tokenize_label(1, ":").unwrap_err();
        assert!(matches!(err, VMError::ParseError { line: 1, .. }));

        let err = tokenize_label(1, "pub :").unwrap_err();
        assert!(matches!(err, VMError::ParseError { line: 1, .. }));
    }

    #[test]
    fn tokenize_label_missing_colon() {
        let err = tokenize_label(1, "name").unwrap_err();
        assert!(matches!(err, VMError::ParseError { line: 1, .. }));

        let err = tokenize_label(1, "pub name").unwrap_err();
        assert!(matches!(err, VMError::ParseError { line: 1, .. }));
    }

    #[test]
    fn tokenize_label_unclosed_paren() {
        let err = tokenize_label(1, "f(1, r2").unwrap_err();
        assert!(matches!(err, VMError::ParseError { line: 1, .. }));
    }

    #[test]
    fn tokenize_label_missing_colon_after_params() {
        let err = tokenize_label(1, "f(1, r2)").unwrap_err();
        assert!(matches!(err, VMError::ParseError { line: 1, .. }));

        let err = tokenize_label(1, "f(1, r2)x").unwrap_err();
        assert!(matches!(err, VMError::ParseError { line: 1, .. }));
    }

    #[test]
    fn tokenize_label_invalid_param_format() {
        // Missing comma
        let err = tokenize_label(1, "f(1 r2):").unwrap_err();
        assert!(matches!(err, VMError::ParseError { line: 1, .. }));

        // Missing register prefix
        let err = tokenize_label(1, "f(1, 2):").unwrap_err();
        assert!(matches!(err, VMError::ParseError { line: 1, .. }));

        // Empty params
        let err = tokenize_label(1, "f():").unwrap_err();
        assert!(matches!(err, VMError::ParseErrorString { line: 1, .. }));
    }

    #[test]
    fn tokenize_label_argc_overflow() {
        let err = tokenize_label(1, "f(256, r0):").unwrap_err();
        assert!(matches!(err, VMError::ParseErrorString { line: 1, .. }));

        let err = tokenize_label(1, "f(999, r0):").unwrap_err();
        assert!(matches!(err, VMError::ParseErrorString { line: 1, .. }));
    }

    #[test]
    fn tokenize_label_argr_overflow() {
        let err = tokenize_label(1, "f(0, r256):").unwrap_err();
        assert!(matches!(err, VMError::ParseErrorString { line: 1, .. }));

        let err = tokenize_label(1, "f(1, r999):").unwrap_err();
        assert!(matches!(err, VMError::ParseErrorString { line: 1, .. }));
    }

    #[test]
    fn tokenize_label_extra_chars_in_params() {
        let err = tokenize_label(1, "f(1, r2 x):").unwrap_err();
        assert!(matches!(err, VMError::ParseError { line: 1, .. }));
    }

    #[test]
    fn tokenize_label_invalid_char_after_name() {
        let err = tokenize_label(1, "name!:").unwrap_err();
        assert!(matches!(err, VMError::ParseError { line: 1, .. }));

        let err = tokenize_label(1, "name@(1, r2):").unwrap_err();
        assert!(matches!(err, VMError::ParseError { line: 1, .. }));
    }

    #[test]
    fn tokenize_label_preserves_line_number() {
        let err = tokenize_label(42, ":").unwrap_err();
        assert!(matches!(err, VMError::ParseError { line: 42, .. }));

        let err = tokenize_label(100, "f(999, r0):").unwrap_err();
        assert!(matches!(err, VMError::ParseErrorString { line: 100, .. }));
    }
}
