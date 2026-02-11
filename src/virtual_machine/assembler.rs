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
//!
//! # Opcode/Metadata Encoding (Src/Addr v2)
//!
//! This assembler targets an opcode format where the high bit indicates whether
//! an instruction carries one metadata byte immediately after the opcode:
//!
//! ```text
//! opcode: 0xZ[ooooooo]
//!           ^ Z = 1 => one metadata byte follows
//! ```
//!
//! Metadata now uses mixed-radix state encoding:
//!
//! ```text
//! Src states (radix 8): Reg, Ref_1, Ref_2, Ref_4, I64_1, I64_2, I64_4, I64_8
//! Addr states (radix 2): Reg, U32
//! Len states (radix 3): 1B, 2B, 4B (used by ImmI32 and RefU32)
//! ```
//!
//! - `3-dyn Src`: `meta = s0 + 8*s1 + 64*s2` (fits in one byte)
//! - `2-dyn arithmetic`: `meta = (concat << 7) | (s0 + 8*s1)`
//! - `3-dyn Addr` (e.g. `MEM_COPY`): `meta = a0 + 2*a1 + 4*a2`
//!
//! Booleans are not a dedicated dynamic Src state; immediates are encoded via
//! compact i64 states.

use crate::for_each_instruction;
use crate::types::encoding::Encode;
use crate::utils::log::SHOW_TYPE;
use crate::virtual_machine::errors::VMError;
use crate::virtual_machine::isa::Instruction;
use crate::virtual_machine::operand::{
    AddrMetadataState, AddrOperand, ImmI32MetadataState, MetadataSlotEncoding, SrcMetadataState,
    SrcOperand, encode_i32_compact, encode_i64_compact, encode_metadata_byte, encode_u32_compact,
    metadata_consume_addr_state, metadata_consume_imm_i32_state, metadata_consume_src_state,
    metadata_i64_len_and_code, metadata_payload_value,
};
use crate::virtual_machine::program::DeployProgram;
use crate::virtual_machine::vm::HOST_FUNCTIONS;
use crate::{define_instructions, error};
use std::collections::{HashMap, HashSet};
use std::fmt::Write;
use std::fs;
use std::path::Path;
use std::sync::atomic::Ordering;

const COMMENT_CHAR: char = '#';
const LABEL_SUFFIX: char = ':';
const INIT_LABEL: &str = "__init__";
const DISPATCH_WIDTHS_PER_BYTE: usize = 4;

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
    /// Initialization code section (`__init__` label and its internal labels).
    Init,
    /// Runtime code section (default).
    Runtime,
}

/// Assembly context for heap items interning and label tracking during compilation.
///
/// Tracks heap items and labels encountered during assembly, assigning each
/// heap items a unique index that becomes part of the compiled [`DeployProgram`].
struct AsmContext {
    /// Maps interned byte sequences to their offset in `memory`.
    items: HashMap<Vec<u8>, u32>,
    /// Const memory buffer containing length-prefixed interned items.
    memory: Vec<u8>,
    /// Label definitions mapping names to global bytecode offsets (init || runtime).
    labels: HashMap<String, usize>,
}

impl AsmContext {
    /// Creates an empty assembly context.
    pub fn new() -> Self {
        Self {
            items: HashMap::new(),
            memory: Vec::new(),
            labels: HashMap::new(),
        }
    }

    /// Interns a string literal into const memory.
    ///
    /// Returns the byte offset of the string. If already interned, returns the existing offset.
    pub fn intern_string(&mut self, s: String) -> u32 {
        let bytes = s.to_vec();
        if let Some((_, idx)) = self.items.iter().find(|item| *item.0 == bytes) {
            return *idx;
        }
        let id = self.memory.len() as u32;
        self.memory.extend_from_slice(&bytes);
        self.items.insert(bytes, id);
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
#[derive(Debug, Clone)]
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
    let argc = parse_u8(&arg_data[n_start..j], line_no, arg_start + n_start + 1)?;

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
    let argr = parse_u8(&arg_data[r_start..j], line_no, arg_start + r_start + 1)?;

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

/// Parse a reference token like `@0`, `@123`.
fn parse_ref_u32(tok: &str) -> Result<u32, VMError> {
    tok.strip_prefix('@')
        .ok_or_else(|| VMError::InvalidRegister {
            token: tok.to_string(),
        })?
        .parse::<u32>()
        .map_err(|_| VMError::InvalidRegister {
            token: tok.to_string(),
        })
}

macro_rules! define_parse_int {
    (
        $(
             $vis:vis $name:ident : $ty:ty
        ),+ $(,)?
    ) => {
        $(
            $vis fn $name(
                tok: &str,
                line: usize,
                current_global_offset: usize,
            ) -> Result<$ty, VMError> {
                let (s, radix) = if let Some(hex) = tok.strip_prefix("0x") {
                    (hex, 16)
                } else if let Some(bin) = tok.strip_prefix("0b") {
                    (bin, 2)
                } else {
                    (tok, 10)
                };

                <$ty>::from_str_radix(s, radix).map_err(|_| VMError::ParseErrorString {
                    line,
                    offset: current_global_offset,
                    length: tok.len(),
                    message: format!(
                        "invalid {} literal '{}'",
                        stringify!($ty),
                        tok
                    ),
                })
            }
        )+
    };
}

define_parse_int! {
    parse_u8: u8,
    parse_u32: u32,
    parse_i32: i32,
    pub(crate) parse_i64: i64,
}

/// Parses an i32 immediate or a label reference.
///
/// If `tok` parses as an integer, returns it directly. Otherwise, resolves
/// `tok` as a label name and computes a PC-relative offset in the global
/// address space (init || runtime).
fn parse_i32_or_label(
    tok: &str,
    ctx: &AsmContext,
    line: usize,
    current_global_offset: usize,
) -> Result<i32, VMError> {
    if let Ok(v) = parse_i32(tok, line, current_global_offset) {
        return Ok(v);
    }
    let target = ctx.resolve_label(tok)?;
    Ok(target as i32 - current_global_offset as i32)
}

/// Parses an i64 immediate or a label reference.
///
/// If `tok` parses as an integer, returns it directly. Otherwise, resolves
/// `tok` as a label name and computes a PC-relative offset in the global
/// address space (init || runtime).
fn parse_i64_or_label(
    tok: &str,
    ctx: &AsmContext,
    line: usize,
    current_global_offset: usize,
) -> Result<i64, VMError> {
    if let Ok(v) = parse_i64(tok, line, current_global_offset) {
        return Ok(v);
    }
    let target = ctx.resolve_label(tok)?;
    Ok(target as i64 - current_global_offset as i64)
}

/// Returns the number of packed width bytes needed for `entry_count` dispatch entries.
fn dispatch_width_table_len(entry_count: usize) -> usize {
    entry_count.div_ceil(DISPATCH_WIDTHS_PER_BYTE)
}

/// Returns the bit shift for the 2-bit width code at `entry_index`.
fn dispatch_width_shift(entry_index: usize) -> u8 {
    6 - ((entry_index % DISPATCH_WIDTHS_PER_BYTE) as u8 * 2)
}

/// Stores one 2-bit width code into the packed dispatch width table.
fn dispatch_pack_width_code(width_table: &mut [u8], entry_index: usize, code: u8) {
    let packed_index = entry_index / DISPATCH_WIDTHS_PER_BYTE;
    let shift = dispatch_width_shift(entry_index);
    width_table[packed_index] |= (code & 0b11) << shift;
}

/// Parses and validates dispatch arity, returning entry count.
fn dispatch_count_from_tokens(tokens: &[Token]) -> Result<u8, VMError> {
    if tokens.len() < 2 {
        return Err(VMError::ArityMismatch {
            instruction: tokens[0].text.to_string(),
            expected: 2,
            actual: tokens.len() as u8 - 1,
        });
    }
    let count = tokens[1]
        .text
        .parse::<u8>()
        .map_err(|_| VMError::InvalidInstructionName {
            name: tokens[1].text.to_string(),
        })?;
    let expected = 2 + count as usize * 2;
    if tokens.len() != expected {
        return Err(VMError::ArityMismatch {
            instruction: tokens[0].text.to_string(),
            expected: expected as u8 - 1,
            actual: tokens.len() as u8 - 1,
        });
    }
    Ok(count)
}

/// Validates dispatch argument registers (`argr`) for each entry.
fn validate_dispatch_entry_registers(tokens: &[Token], count: u8) -> Result<(), VMError> {
    for i in 0..count as usize {
        parse_reg(tokens[3 + i * 2].text)?;
    }
    Ok(())
}

/// Parses a dispatch offset token as numeric i64 or a label-relative i64.
fn dispatch_offset_from_token_with_end(
    tok: &str,
    ctx: &AsmContext,
    instruction_end: usize,
) -> Result<i64, VMError> {
    if let Ok(v) = parse_i64(tok, 0, instruction_end) {
        return Ok(v);
    }
    let target = ctx.resolve_label(tok)?;
    Ok(target as i64 - instruction_end as i64)
}

/// Returns encoded byte length for one dispatch offset using compact i64 encoding.
fn dispatch_offset_size_from_token_with_end(
    tok: &str,
    ctx: &AsmContext,
    instruction_end: usize,
) -> Result<usize, VMError> {
    let offset = dispatch_offset_from_token_with_end(tok, ctx, instruction_end)?;
    Ok(metadata_i64_len_and_code(offset).0 as usize)
}

/// Computes relaxed DISPATCH size using packed offset width codes plus compact offsets.
fn dispatch_size_from_tokens_relaxed(
    ctx: &mut AsmContext,
    tokens: &[Token],
    current_global_offset: usize,
) -> Result<usize, VMError> {
    let count = dispatch_count_from_tokens(tokens)?;
    validate_dispatch_entry_registers(tokens, count)?;

    let width_table_len = dispatch_width_table_len(count as usize);
    // Initial guess: legacy 4-byte offsets.
    let mut size = 2usize + width_table_len + count as usize * (4 + 1);

    for _ in 0..8 {
        let instruction_end = current_global_offset + size;
        let mut payload_size = 0usize;
        for i in 0..count as usize {
            let len = dispatch_offset_size_from_token_with_end(
                tokens[2 + i * 2].text,
                ctx,
                instruction_end,
            )?;
            payload_size += len + 1; // offset payload + argr
        }
        let new_size = 2usize + width_table_len + payload_size;
        if new_size == size {
            break;
        }
        size = new_size;
    }

    Ok(size)
}

fn parse_src(
    tok: &str,
    ctx: &mut AsmContext,
    line: usize,
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
        line,
        current_offset,
    )?))
}

/// Parses an address operand token.
///
/// Accepts either a register (`r0`, `r1`, ...) or an immediate u32 value
/// (decimal or `0x` prefixed hex).
fn parse_addr(tok: &str, line: usize, current_offset: usize) -> Result<AddrOperand, VMError> {
    // Register: r0, r1, ...
    if let Ok(reg) = parse_reg(tok) {
        return Ok(AddrOperand::Reg(reg));
    }
    // number or hex
    Ok(AddrOperand::U32(parse_u32(tok, line, current_offset)?))
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

/// Returns `true` when `tok` matches the register pattern `r<digits>`.
fn is_register_token(tok: &str) -> bool {
    tok.starts_with('r') && tok.len() > 1 && tok[1..].chars().all(|c| c.is_ascii_digit())
}

/// Emits the payload bytes for a [`SrcOperand`] using metadata-based encoding.
fn emit_src_payload_from_metadata(
    out: &mut Vec<u8>,
    operand: &SrcOperand,
    metadata_cursor: &mut u16,
) {
    let state =
        metadata_consume_src_state(metadata_cursor).expect("invalid Src metadata state cursor");

    if let Some(len) = state.i64_len() {
        let value = match operand {
            SrcOperand::I64(value) => *value,
            SrcOperand::Bool(value) => i64::from(*value),
            _ => panic!("metadata state {state:?} expects i64 Src payload"),
        };
        let bytes = encode_i64_compact(value, len)
            .expect("metadata i64 length must be valid for Src payload");
        out.extend_from_slice(&bytes);
    } else if let Some(len) = state.ref_len() {
        let value = match operand {
            SrcOperand::Ref(value) => *value,
            _ => panic!("metadata state {state:?} expects Ref Src payload"),
        };
        let bytes = encode_u32_compact(value, len)
            .expect("metadata ref length must be valid for Src payload");
        out.extend_from_slice(&bytes);
    } else {
        match (state, operand) {
            (SrcMetadataState::Reg, SrcOperand::Reg(reg)) => out.push(*reg),
            _ => panic!("metadata state {state:?} does not match Src operand {operand:?}"),
        }
    }
}

/// Emits the payload bytes for an [`AddrOperand`] using metadata-based encoding.
fn emit_addr_payload_from_metadata(
    out: &mut Vec<u8>,
    operand: &AddrOperand,
    metadata_cursor: &mut u16,
) {
    let state =
        metadata_consume_addr_state(metadata_cursor).expect("invalid Addr metadata state cursor");
    match (state, operand) {
        (AddrMetadataState::Reg, AddrOperand::Reg(reg)) => out.push(*reg),
        (AddrMetadataState::U32, AddrOperand::U32(value)) => {
            out.extend_from_slice(&value.to_le_bytes());
        }
        _ => panic!("metadata state {state:?} does not match Addr operand {operand:?}"),
    }
}

/// Returns compact Ref metadata state for a u32 value.
fn src_ref_metadata_state_from_value(value: u32) -> SrcMetadataState {
    if value <= u8::MAX as u32 {
        SrcMetadataState::RefLen1
    } else if value <= u16::MAX as u32 {
        SrcMetadataState::RefLen2
    } else {
        SrcMetadataState::RefLen4
    }
}

/// Returns Src metadata state for a token.
fn src_metadata_state_from_token(tok: &str, ctx: &mut AsmContext) -> SrcMetadataState {
    if is_register_token(tok) {
        return SrcMetadataState::Reg;
    }
    if tok == "true" || tok == "false" {
        return SrcMetadataState::I64Len1;
    }
    if let Some(s) = tok.strip_prefix('"').and_then(|t| t.strip_suffix('"')) {
        let reference = ctx.intern_string(s.to_string());
        return src_ref_metadata_state_from_value(reference);
    }

    if let Ok(value) = parse_i64(tok, 0, 0) {
        // Reserve 1-byte i64 payload value space for bool literals.
        if value == 0 || value == 1 {
            return SrcMetadataState::I64Len2;
        }
        let (_, len_code) = metadata_i64_len_and_code(value);
        return SrcMetadataState::from_i64_len_code(len_code);
    }

    // Label-derived i64 immediates are fixed to 8 bytes.
    SrcMetadataState::I64Len8
}

/// Returns metadata slot encoding for a Src token.
fn src_metadata_slot_from_token(tok: &str, ctx: &mut AsmContext) -> MetadataSlotEncoding {
    MetadataSlotEncoding::src(src_metadata_state_from_token(tok, ctx))
}

/// Returns metadata slot encoding for an Addr token.
fn addr_metadata_slot_from_token(tok: &str) -> MetadataSlotEncoding {
    if is_register_token(tok) {
        MetadataSlotEncoding::addr(AddrMetadataState::Reg)
    } else {
        MetadataSlotEncoding::addr(AddrMetadataState::U32)
    }
}

/// Computes Src payload size under metadata encoding (no per-operand tag bytes).
fn src_size_from_token_metadata(tok: &str, ctx: &mut AsmContext) -> usize {
    src_metadata_state_from_token(tok, ctx).payload_len()
}

/// Computes Addr payload size under metadata encoding (no per-operand tag bytes).
fn addr_size_from_token_metadata(tok: &str) -> usize {
    if is_register_token(tok) { 1 } else { 4 }
}

/// Returns ImmI32 metadata state for a token.
fn imm_i32_metadata_state_from_token(tok: &str) -> ImmI32MetadataState {
    if let Ok(value) = parse_i32(tok, 0, 0) {
        ImmI32MetadataState::from_value(value)
    } else {
        // Label-derived offsets use fixed i32 payload width.
        ImmI32MetadataState::Len4
    }
}

/// Returns ImmI32 metadata state for a token using a resolved instruction end offset.
///
/// This enables label-based branch/call relaxation (`target - instruction_end`)
/// to choose compact ImmI32 payload sizes when possible.
fn imm_i32_metadata_state_from_token_with_end(
    tok: &str,
    ctx: &AsmContext,
    instruction_end: usize,
) -> ImmI32MetadataState {
    if let Ok(value) = parse_i32(tok, 0, 0) {
        return ImmI32MetadataState::from_value(value);
    }
    if let Ok(target) = ctx.resolve_label(tok)
        && let Ok(relative) = i32::try_from(target as i64 - instruction_end as i64)
    {
        return ImmI32MetadataState::from_value(relative);
    }
    ImmI32MetadataState::Len4
}

/// Returns metadata slot encoding for an ImmI32 token using relaxed label offsets.
fn imm_i32_metadata_slot_from_token_with_end(
    tok: &str,
    ctx: &AsmContext,
    instruction_end: usize,
) -> MetadataSlotEncoding {
    MetadataSlotEncoding::imm_i32(imm_i32_metadata_state_from_token_with_end(
        tok,
        ctx,
        instruction_end,
    ))
}

/// Computes ImmI32 payload size under metadata encoding.
fn imm_i32_size_from_token_metadata(tok: &str) -> usize {
    imm_i32_metadata_state_from_token(tok).payload_len()
}

/// Computes ImmI32 payload size under metadata encoding with relaxed label offsets.
fn imm_i32_size_from_token_metadata_with_end(
    tok: &str,
    ctx: &AsmContext,
    instruction_end: usize,
) -> usize {
    imm_i32_metadata_state_from_token_with_end(tok, ctx, instruction_end).payload_len()
}

/// Returns compact len state for a RefU32 value.
fn ref_u32_metadata_state_from_value(value: u32) -> ImmI32MetadataState {
    if value <= u8::MAX as u32 {
        ImmI32MetadataState::Len1
    } else if value <= u16::MAX as u32 {
        ImmI32MetadataState::Len2
    } else {
        ImmI32MetadataState::Len4
    }
}

/// Returns RefU32 compact len state for a token and syncs string interning.
fn ref_u32_metadata_state_from_token(tok: &str, ctx: &mut AsmContext) -> ImmI32MetadataState {
    if let Some(s) = tok.strip_prefix('"').and_then(|t| t.strip_suffix('"')) {
        return ref_u32_metadata_state_from_value(ctx.intern_string(s.to_string()));
    }
    if let Ok(value) = parse_ref_u32(tok) {
        return ref_u32_metadata_state_from_value(value);
    }
    // Parse errors are surfaced by operand parsing; keep sizing deterministic here.
    ImmI32MetadataState::Len4
}

/// Returns metadata slot encoding for a RefU32 token.
fn ref_u32_metadata_slot_from_token(tok: &str, ctx: &mut AsmContext) -> MetadataSlotEncoding {
    MetadataSlotEncoding::imm_i32(ref_u32_metadata_state_from_token(tok, ctx))
}

/// Computes RefU32 payload size under metadata encoding.
fn ref_u32_size_from_token_metadata(tok: &str, ctx: &mut AsmContext) -> usize {
    ref_u32_metadata_state_from_token(tok, ctx).payload_len()
}

/// Emits compact u32 payload bytes using metadata state from the current slot.
fn emit_ref_u32_payload_from_metadata(out: &mut Vec<u8>, value: &u32, metadata_cursor: &mut u16) {
    let state = metadata_consume_imm_i32_state(metadata_cursor)
        .expect("invalid RefU32 metadata state cursor");
    let len = state.payload_len() as u8;
    let bytes =
        encode_u32_compact(*value, len).expect("metadata u32 length must be valid for payload");
    out.extend_from_slice(&bytes);
}

/// Emits compact i32 payload bytes using metadata state from the current slot.
fn emit_imm_i32_payload_from_metadata(out: &mut Vec<u8>, value: &i32, metadata_cursor: &mut u16) {
    let state = metadata_consume_imm_i32_state(metadata_cursor)
        .expect("invalid ImmI32 metadata state cursor");
    let len = state.payload_len() as u8;
    let bytes =
        encode_i32_compact(*value, len).expect("metadata i32 length must be valid for payload");
    out.extend_from_slice(&bytes);
}

/// Returns line content without inline comments and surrounding spaces.
fn strip_comment_and_trim(line: &str) -> &str {
    line.split(COMMENT_CHAR).next().unwrap_or("").trim()
}

/// Returns true if the line contains code or a label definition.
fn is_code_line(line: &str) -> bool {
    !strip_comment_and_trim(line).is_empty()
}

/// Updates the current section based on a parsed label.
///
/// `__init__` switches to init section. Any non-internal label switches to runtime.
/// Internal labels (`__*`) inherit the current section.
fn advance_section_for_label(current: Section, label_name: &str) -> Section {
    if label_name == INIT_LABEL {
        Section::Init
    } else if label_name.starts_with("__") {
        current
    } else {
        Section::Runtime
    }
}

/// Step 0: normalizes source by moving all `__init__` section lines to the top.
///
/// Also validates that the final instruction in `__init__` is `HALT`.
fn assemble_source_step_0(source: &str, errors: &mut Vec<VMError>) -> Option<String> {
    let mut in_init = false;
    let mut has_init = false;
    let mut line_is_init = Vec::new();
    let mut last_init_instr: Option<(usize, usize, String)> = None; // (line, offset, mnemonic)

    for (line_no, line) in source.lines().enumerate() {
        let mut is_init_line = in_init;
        let mut instr_start = 0usize;

        if is_code_line(line) && is_label_def(line) {
            let label = match tokenize_label(line_no + 1, line) {
                Ok(l) => l,
                Err(e) => {
                    errors.push(e);
                    return None;
                }
            };
            if label.name == INIT_LABEL {
                has_init = true;
                in_init = true;
                is_init_line = true;
            }
            instr_start = line.find(':').unwrap_or(0).saturating_add(1);
        }

        if is_init_line && is_code_line(line) {
            let tokens = match tokenize(line_no + 1, &line[instr_start..]) {
                Ok(t) => t,
                Err(e) => {
                    errors.push(e);
                    return None;
                }
            };
            if let Some(tok) = tokens.first() {
                last_init_instr = Some((line_no + 1, tok.offset, tok.text.to_string()));
                if tok.text == Instruction::Halt.mnemonic() {
                    in_init = false;
                }
            }
        }

        line_is_init.push(is_init_line);
    }

    if has_init {
        match last_init_instr {
            Some((_, _, mnemonic)) if mnemonic == Instruction::Halt.mnemonic() => {}
            Some((line, offset, mnemonic)) => {
                errors.push(VMError::AssemblyError {
                    line,
                    offset,
                    length: mnemonic.len().max(1),
                    source: "label '__init__' must end with HALT".to_string(),
                });
                return None;
            }
            None => {
                errors.push(VMError::AssemblyError {
                    line: 1,
                    offset: 1,
                    length: INIT_LABEL.len(),
                    source: "label '__init__' must end with HALT".to_string(),
                });
                return None;
            }
        }
    }

    let lines: Vec<&str> = source.lines().collect();
    let mut out = String::with_capacity(source.len());
    for (idx, line) in lines.iter().enumerate() {
        if line_is_init[idx] {
            out.push_str(line);
            out.push('\n');
        }
    }
    for (idx, line) in lines.iter().enumerate() {
        if !line_is_init[idx] {
            out.push_str(line);
            out.push('\n');
        }
    }
    Some(out)
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
                    concat: bool,
                    metadata: Option<u8>,
                    $( $field: define_instructions!(@ty $kind) ),*
                },
            )*
            /// Variadic dispatcher: entries are (target_offset_i32, argr).
            Dispatch {
                entries: Vec<(i64, u8)>,
            },
        }

        impl AsmInstr {
            /// Encodes the assembly instruction into bytecode
            fn assemble(&self, out: &mut Vec<u8>) {
                match self {
                    $(
                        AsmInstr::$name {
                            concat,
                            metadata,
                            $( $field ),*
                        } => {
                            // Z bit is driven by metadata presence at encode time.
                            out.push(Instruction::$name.encode_opcode(metadata.is_some()));
                            if let Some(metadata) = metadata {
                                out.push(*metadata);
                            }

                            let concat = *concat;
                            let concat_capable =
                                define_parse_instruction!(@concat_capable $name $( $kind ),*);
                            let mut metadata_cursor = metadata.map_or(0u16, |m| {
                                metadata_payload_value(m, concat_capable)
                            });
                            let _ = &mut metadata_cursor;
                            define_parse_instruction!(
                                @emit_fields_with_concat out, metadata_cursor, concat;
                                $( $field : $kind ),*
                            );
                        }
                    ),*
                    AsmInstr::Dispatch { entries } => {
                        out.push(Instruction::Dispatch as u8);
                        out.push(entries.len() as u8);
                        let width_table_len = dispatch_width_table_len(entries.len());
                        let width_table_start = out.len();
                        out.resize(width_table_start + width_table_len, 0u8);

                        for (entry_index, (offset, argr)) in entries.iter().enumerate() {
                            let (len, code) = metadata_i64_len_and_code(*offset);
                            dispatch_pack_width_code(
                                &mut out[width_table_start..width_table_start + width_table_len],
                                entry_index,
                                code,
                            );
                            let bytes = encode_i64_compact(*offset, len)
                                .expect("dispatch offset compact length must be valid");
                            out.extend_from_slice(&bytes);
                            out.push(*argr);
                        }
                    }
                }
            }
        }

        fn instruction_from_str(name: &str) -> Result<Instruction, VMError> {
            match name {
                $( $mnemonic => Ok(Instruction::$name), )*
                "DISPATCH" => Ok(Instruction::Dispatch),
                _ => Err(VMError::InvalidInstructionName {
                    name: name.to_string(),
                }),
            }
        }

        /// Returns the bytecode size for an instruction from its tokens.
        ///
        /// Tokens should include the instruction mnemonic followed by operands.
        /// Size depends on operand types, which are determined by inspecting tokens.
        fn instruction_size_from_tokens(
            mut ctx: &mut AsmContext,
            tokens: &[Token],
        ) -> Result<usize, VMError> {
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
                        let concat = define_parse_instruction!(
                            @check_arity tokens, $name; $( $field ),* ; $( $kind ),*
                        );
                        if concat {
                            parse_reg(tokens[1].text)?;
                            let rs2_size = src_size_from_token_metadata(tokens[2].text, ctx);
                            1usize + 1 + 1 + rs2_size
                        } else {
                            let payload_size =
                                0usize $( + define_parse_instruction!(@token_size $kind, tok_iter, ctx) )*;
                            let metadata_slots: Vec<MetadataSlotEncoding> = {
                                let mut slots = Vec::new();
                                let _ = &mut slots;
                                define_parse_instruction!(
                                    @collect_metadata_slots_from_tokens tokens, slots, ctx, 0usize;
                                    $( $kind ),*
                                );
                                slots
                            };
                            let metadata_size = if metadata_slots.is_empty() {
                                0usize
                            } else {
                                usize::from(encode_metadata_byte(false, &metadata_slots)? != 0)
                            };
                            1usize + metadata_size + payload_size
                        }
                    }
                ),*
                Instruction::Dispatch => {
                    let count = dispatch_count_from_tokens(tokens)?;
                    validate_dispatch_entry_registers(tokens, count)?;
                    let width_table_len = dispatch_width_table_len(count as usize);
                    // Labels may not resolve in pass 1; use len4 fallback for non-numeric offsets.
                    let mut payload_size = 0usize;
                    for i in 0..count as usize {
                        let off_len = if let Ok(value) = parse_i64(tokens[2 + i * 2].text, 0, 0) {
                            metadata_i64_len_and_code(value).0 as usize
                        } else {
                            4usize
                        };
                        payload_size += off_len + 1; // offset + argr
                    }
                    2 + width_table_len + payload_size
                }
            })
        }

        /// Returns instruction size using current label offsets for ImmI32 relaxation.
        ///
        /// This pass computes compact ImmI32 widths for label-based operands by
        /// iterating on the instruction end offset until size reaches a fixed point.
        fn instruction_size_from_tokens_relaxed(
            mut ctx: &mut AsmContext,
            tokens: &[Token],
            current_global_offset: usize,
        ) -> Result<usize, VMError> {
            if tokens.is_empty() {
                return Err(VMError::ArityMismatch {
                    instruction: "<missing opcode>".to_string(),
                    expected: 1,
                    actual: 0,
                });
            }

            let instr = instruction_from_str(tokens[0].text)?;
            Ok(match instr {
                $(
                    Instruction::$name => {
                        let concat = define_parse_instruction!(
                            @check_arity tokens, $name; $( $field ),* ; $( $kind ),*
                        );
                        if concat {
                            parse_reg(tokens[1].text)?;
                            let rs2_size = src_size_from_token_metadata(tokens[2].text, ctx);
                            1usize + 1 + 1 + rs2_size
                        } else {
                            let mut size = {
                                let mut tok_iter = tokens.iter().skip(1);
                                let _ = &mut tok_iter;
                                let payload_size =
                                    0usize $( + define_parse_instruction!(@token_size $kind, tok_iter, ctx) )*;
                                let metadata_slots: Vec<MetadataSlotEncoding> = {
                                    let mut slots = Vec::new();
                                    let _ = &mut slots;
                                    define_parse_instruction!(
                                        @collect_metadata_slots_from_tokens
                                        tokens, slots, ctx, current_global_offset;
                                        $( $kind ),*
                                    );
                                    slots
                                };
                                let metadata_size = if metadata_slots.is_empty() {
                                    0usize
                                } else {
                                    usize::from(encode_metadata_byte(false, &metadata_slots)? != 0)
                                };
                                1usize + metadata_size + payload_size
                            };

                            for _ in 0..4 {
                                let instruction_end = current_global_offset + size;
                                let _ = instruction_end;
                                let mut tok_iter = tokens.iter().skip(1);
                                let _ = &mut tok_iter;
                                let payload_size = 0usize $(
                                    + define_parse_instruction!(
                                        @token_size_relaxed $kind,
                                        tok_iter,
                                        ctx,
                                        current_global_offset,
                                        size
                                    )
                                )*;
                                let metadata_slots: Vec<MetadataSlotEncoding> = {
                                    let mut slots = Vec::new();
                                    let _ = &mut slots;
                                    define_parse_instruction!(
                                        @collect_metadata_slots_from_tokens
                                        tokens, slots, ctx, instruction_end;
                                        $( $kind ),*
                                    );
                                    slots
                                };
                                let metadata_size = if metadata_slots.is_empty() {
                                    0usize
                                } else {
                                    usize::from(encode_metadata_byte(false, &metadata_slots)? != 0)
                                };
                                let new_size = 1usize + metadata_size + payload_size;
                                if new_size == size {
                                    break;
                                }
                                size = new_size;
                            }

                            size
                        }
                    }
                ),*
                Instruction::Dispatch => {
                    dispatch_size_from_tokens_relaxed(ctx, tokens, current_global_offset)?
                }
            })
        }

        /// Returns encoded payload sizes grouped per instruction operand.
        ///
        /// Group sizes are aligned with emitted operand payloads (not raw bytes),
        /// so audit output can separate arguments with commas.
        fn instruction_operand_group_sizes_from_tokens(
            mut ctx: &mut AsmContext,
            tokens: &[Token],
            current_global_offset: usize,
        ) -> Result<Vec<usize>, VMError> {
            if tokens.is_empty() {
                return Err(VMError::ArityMismatch {
                    instruction: "<missing opcode>".to_string(),
                    expected: 1,
                    actual: 0,
                });
            }

            let instr = instruction_from_str(tokens[0].text)?;
            Ok(match instr {
                $(
                    Instruction::$name => {
                        let concat = define_parse_instruction!(
                            @check_arity tokens, $name; $( $field ),* ; $( $kind ),*
                        );
                        if concat {
                            parse_reg(tokens[1].text)?;
                            vec![1usize, src_size_from_token_metadata(tokens[2].text, ctx)]
                        } else {
                            let instruction_end = current_global_offset
                                + instruction_size_from_tokens_relaxed(
                                    ctx,
                                    tokens,
                                    current_global_offset,
                                )?;
                            let _ = instruction_end;
                            let mut groups = Vec::new();
                            let _ = &mut groups;
                            define_parse_instruction!(
                                @collect_operand_group_sizes_from_tokens
                                tokens, groups, ctx, instruction_end;
                                $( $kind ),*
                            );
                            groups
                        }
                    }
                ),*
                Instruction::Dispatch => {
                    let count = dispatch_count_from_tokens(tokens)?;
                    validate_dispatch_entry_registers(tokens, count)?;
                    let total_size =
                        dispatch_size_from_tokens_relaxed(ctx, tokens, current_global_offset)?;
                    let instruction_end = current_global_offset + total_size;

                    let width_table_len = dispatch_width_table_len(count as usize);
                    let mut groups = Vec::with_capacity(2 + count as usize * 2);
                    groups.push(1); // count
                    if width_table_len > 0 {
                        groups.push(width_table_len); // packed width codes
                    }
                    for i in 0..count as usize {
                        let off_len = dispatch_offset_size_from_token_with_end(
                            tokens[2 + i * 2].text,
                            ctx,
                            instruction_end,
                        )?;
                        groups.push(off_len); // compact offset payload
                        groups.push(1); // argr
                    }
                    groups
                }
            })
        }

        /// Parse one instruction from tokens into [`AsmInstr`].
        ///
        /// `current_global_offset` is the global bytecode offset (in init || runtime space)
        /// where this instruction starts, used for resolving label references to relative offsets.
        fn parse_instruction(
            mut ctx: &mut AsmContext,
            tokens: &[Token],
            line: usize,
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
            let offset =
                current_global_offset + instruction_size_from_tokens_relaxed(ctx, tokens, current_global_offset)?;

            match instr {
                $(
                    Instruction::$name => {
                        let concat = define_parse_instruction!(
                            @check_arity tokens, $name; $( $field ),* ; $( $kind ),*
                        );
                        let mut metadata_slots: Vec<MetadataSlotEncoding> = Vec::new();
                        if concat {
                            metadata_slots.push(MetadataSlotEncoding::src(SrcMetadataState::Reg));
                            metadata_slots.push(src_metadata_slot_from_token(tokens[2].text, ctx));
                        } else {
                            define_parse_instruction!(
                                @collect_metadata_slots_from_tokens tokens, metadata_slots, ctx, offset;
                                $( $kind ),*
                            );
                        }
                        let metadata = if metadata_slots.is_empty() {
                            None
                        } else {
                            let encoded = encode_metadata_byte(concat, &metadata_slots)?;
                            (encoded != 0).then_some(encoded)
                        };

                        define_parse_instruction!(
                            @construct_with_concat ctx line offset tokens, concat, metadata;
                            $name $( $field : $kind ),*
                        )
                    }
                ),*
                Instruction::Dispatch => {
                    let count = dispatch_count_from_tokens(tokens)?;
                    let mut entries = Vec::with_capacity(count as usize);
                    for i in 0..count as usize {
                        let target = parse_i64_or_label(
                            &tokens[2 + i * 2].text, ctx, line, offset,
                        )?;
                        let argr = parse_reg(&tokens[3 + i * 2].text)?;
                        entries.push((target, argr));
                    }
                    Ok(AsmInstr::Dispatch { entries })
                }
            }
        }
    };

    // ---------- counting ----------
    (@count $( $x:ident ),* ) => { <[()]>::len(&[ $( define_parse_instruction!(@unit $x) ),* ]) };
    (@unit $x:ident) => { () };
    (@dynamic Reg) => { 0usize };
    (@dynamic ImmU8) => { 0usize };
    (@dynamic RefU32) => { 1usize };
    (@dynamic ImmI32) => { 1usize };
    (@dynamic ImmU32) => { 0usize };
    (@dynamic Addr) => { 1usize };
    (@dynamic Src) => { 1usize };
    (@concat_capable $name:ident Reg, Src, Src) => { Instruction::$name.supports_concat_compact() };
    (@concat_capable $name:ident $( $kind:ident ),* ) => { false };

    // ---------- arity check ----------
    (@check_arity $tokens:ident, $name:ident; $( $field:ident ),* ; $( $kind:ident ),* ) => {{
        const EXPECTED: usize = 1 + define_parse_instruction!(@count $( $field ),*);
        const COMPACT_EXPECTED: usize = EXPECTED.saturating_sub(1);
        let concat =
            define_parse_instruction!(@concat_capable $name $( $kind ),*)
                && $tokens.len() == COMPACT_EXPECTED;
        if !concat && $tokens.len() != EXPECTED {
            return Err(VMError::ArityMismatch {
                instruction: $tokens[0].text.to_string(),
                expected: EXPECTED as u8 - 1,
                actual: $tokens.len() as u8 - 1,
            });
        }
        concat
    }};

    // ---------- operand sizes from tokens ----------
    (@token_size Reg, $iter:ident, $ctx:ident) => {{ let _ = &mut $ctx; $iter.next(); 1usize }};
    (@token_size ImmU8, $iter:ident, $ctx:ident) => {{ let _ = &mut $ctx; $iter.next(); 1usize }};

    (@token_size RefU32, $iter:ident, $ctx:ident) => {{
        ref_u32_size_from_token_metadata($iter.next().unwrap().text, $ctx)
    }};
    (@token_size ImmI32, $iter:ident, $ctx:ident) => {{
        let _ = &mut $ctx;
        imm_i32_size_from_token_metadata($iter.next().unwrap().text)
    }};
    (@token_size ImmU32, $iter:ident, $ctx:ident) => {{ let _ = &mut $ctx; $iter.next(); 4usize }};

    (@token_size Addr, $iter:ident, $ctx:ident) => {{
        let _ = &mut $ctx;
        addr_size_from_token_metadata($iter.next().unwrap().text)
    }};
    (@token_size Src, $iter:ident, $ctx:ident) => {{
        let tok = $iter.next().unwrap();
        src_size_from_token_metadata(tok.text, $ctx)
    }};

    // ---------- relaxed operand sizes ----------
    (@token_size_relaxed Reg, $iter:ident, $ctx:ident, $base:expr, $size:expr) => {{
        let _ = (&mut $ctx, $base, $size);
        $iter.next();
        1usize
    }};
    (@token_size_relaxed ImmU8, $iter:ident, $ctx:ident, $base:expr, $size:expr) => {{
        let _ = (&mut $ctx, $base, $size);
        $iter.next();
        1usize
    }};
    (@token_size_relaxed RefU32, $iter:ident, $ctx:ident, $base:expr, $size:expr) => {{
        let _ = ($base, $size);
        ref_u32_size_from_token_metadata($iter.next().unwrap().text, $ctx)
    }};
    (@token_size_relaxed ImmI32, $iter:ident, $ctx:ident, $base:expr, $size:expr) => {{
        imm_i32_size_from_token_metadata_with_end(
            $iter.next().unwrap().text,
            $ctx,
            $base + $size,
        )
    }};
    (@token_size_relaxed ImmU32, $iter:ident, $ctx:ident, $base:expr, $size:expr) => {{
        let _ = (&mut $ctx, $base, $size);
        $iter.next();
        4usize
    }};
    (@token_size_relaxed Addr, $iter:ident, $ctx:ident, $base:expr, $size:expr) => {{
        let _ = (&mut $ctx, $base, $size);
        addr_size_from_token_metadata($iter.next().unwrap().text)
    }};
    (@token_size_relaxed Src, $iter:ident, $ctx:ident, $base:expr, $size:expr) => {{
        let _ = ($base, $size);
        let tok = $iter.next().unwrap();
        src_size_from_token_metadata(tok.text, $ctx)
    }};

    // ---------- metadata collection ----------
    (@collect_metadata_slot Addr, $iter:ident, $slots:ident, $ctx:ident, $offset_end:expr) => {{
        let _ = (&mut $ctx, $offset_end);
        let tok = $iter.next().unwrap();
        $slots.push(addr_metadata_slot_from_token(tok.text));
    }};
    (@collect_metadata_slot Src, $iter:ident, $slots:ident, $ctx:ident, $offset_end:expr) => {{
        let _ = (&mut $ctx, $offset_end);
        let tok = $iter.next().unwrap();
        $slots.push(src_metadata_slot_from_token(tok.text, $ctx));
    }};
    (@collect_metadata_slot ImmI32, $iter:ident, $slots:ident, $ctx:ident, $offset_end:expr) => {{
        let tok = $iter.next().unwrap();
        $slots.push(imm_i32_metadata_slot_from_token_with_end(
            tok.text,
            $ctx,
            $offset_end,
        ));
    }};
    (@collect_metadata_slot RefU32, $iter:ident, $slots:ident, $ctx:ident, $offset_end:expr) => {{
        let _ = $offset_end;
        let tok = $iter.next().unwrap();
        $slots.push(ref_u32_metadata_slot_from_token(tok.text, $ctx));
    }};
    (@collect_metadata_slot $_kind:ident, $iter:ident, $slots:ident, $ctx:ident, $offset_end:expr) => {{
        let _ = (&mut $ctx, $offset_end);
        let _ = $iter.next();
    }};
    (@collect_metadata_slots_from_tokens $tokens:ident, $slots:ident, $ctx:ident, $offset_end:expr; ) => {};
    (@collect_metadata_slots_from_tokens $tokens:ident, $slots:ident, $ctx:ident, $offset_end:expr; $( $kind:ident ),+ ) => {{
        let mut meta_iter = $tokens.iter().skip(1);
        $(
            define_parse_instruction!(
                @collect_metadata_slot $kind, meta_iter, $slots, $ctx, $offset_end
            );
        )*
    }};

    // ---------- operand group sizes ----------
    (@collect_operand_group_size Reg, $iter:ident, $groups:ident, $ctx:ident, $offset_end:expr) => {{
        let _ = (&mut $ctx, $offset_end);
        let _ = $iter.next();
        $groups.push(1usize);
    }};
    (@collect_operand_group_size ImmU8, $iter:ident, $groups:ident, $ctx:ident, $offset_end:expr) => {{
        let _ = (&mut $ctx, $offset_end);
        let _ = $iter.next();
        $groups.push(1usize);
    }};
    (@collect_operand_group_size ImmU32, $iter:ident, $groups:ident, $ctx:ident, $offset_end:expr) => {{
        let _ = (&mut $ctx, $offset_end);
        let _ = $iter.next();
        $groups.push(4usize);
    }};
    (@collect_operand_group_size Addr, $iter:ident, $groups:ident, $ctx:ident, $offset_end:expr) => {{
        let _ = $offset_end;
        let tok = $iter.next().unwrap();
        $groups.push(addr_size_from_token_metadata(tok.text));
    }};
    (@collect_operand_group_size Src, $iter:ident, $groups:ident, $ctx:ident, $offset_end:expr) => {{
        let _ = $offset_end;
        let tok = $iter.next().unwrap();
        $groups.push(src_size_from_token_metadata(tok.text, $ctx));
    }};
    (@collect_operand_group_size ImmI32, $iter:ident, $groups:ident, $ctx:ident, $offset_end:expr) => {{
        let tok = $iter.next().unwrap();
        $groups.push(imm_i32_size_from_token_metadata_with_end(
            tok.text,
            $ctx,
            $offset_end,
        ));
    }};
    (@collect_operand_group_size RefU32, $iter:ident, $groups:ident, $ctx:ident, $offset_end:expr) => {{
        let _ = $offset_end;
        let tok = $iter.next().unwrap();
        $groups.push(ref_u32_size_from_token_metadata(tok.text, $ctx));
    }};
    (@collect_operand_group_sizes_from_tokens $tokens:ident, $groups:ident, $ctx:ident, $offset_end:expr; ) => {};
    (@collect_operand_group_sizes_from_tokens $tokens:ident, $groups:ident, $ctx:ident, $offset_end:expr; $( $kind:ident ),+ ) => {{
        let mut group_iter = $tokens.iter().skip(1);
        $(
            define_parse_instruction!(
                @collect_operand_group_size $kind, group_iter, $groups, $ctx, $offset_end
            );
        )*
    }};

    // ---------- emission ----------
    (@emit_operand $out:ident, $metadata_cursor:ident, Reg, $value:ident) => {{
        let _ = &mut $metadata_cursor;
        $out.push(*$value);
    }};
    (@emit_operand $out:ident, $metadata_cursor:ident, ImmU8, $value:ident) => {{
        let _ = &mut $metadata_cursor;
        $out.push(*$value);
    }};
    (@emit_operand $out:ident, $metadata_cursor:ident, RefU32, $value:ident) => {{
        emit_ref_u32_payload_from_metadata($out, $value, &mut $metadata_cursor);
    }};
    (@emit_operand $out:ident, $metadata_cursor:ident, ImmI32, $value:ident) => {{
        emit_imm_i32_payload_from_metadata($out, $value, &mut $metadata_cursor);
    }};
    (@emit_operand $out:ident, $metadata_cursor:ident, ImmU32, $value:ident) => {{
        let _ = &mut $metadata_cursor;
        $out.extend_from_slice(&$value.to_le_bytes());
    }};
    (@emit_operand $out:ident, $metadata_cursor:ident, Addr, $value:ident) => {{
        emit_addr_payload_from_metadata($out, $value, &mut $metadata_cursor);
    }};
    (@emit_operand $out:ident, $metadata_cursor:ident, Src, $value:ident) => {{
        emit_src_payload_from_metadata($out, $value, &mut $metadata_cursor);
    }};

    (@emit_fields $out:ident, $metadata_cursor:ident; ) => {};
    (@emit_fields $out:ident, $metadata_cursor:ident;
        $field:ident : $kind:ident $(, $rest_field:ident : $rest_kind:ident )*
    ) => {{
        define_parse_instruction!(@emit_operand $out, $metadata_cursor, $kind, $field);
        define_parse_instruction!(@emit_fields $out, $metadata_cursor; $( $rest_field : $rest_kind ),*);
    }};

    (@emit_fields_with_concat $out:ident, $metadata_cursor:ident, $concat:expr;
        $rd:ident : Reg, $rs1:ident : Src, $rs2:ident : Src
    ) => {{
        define_parse_instruction!(@emit_operand $out, $metadata_cursor, Reg, $rd);
        if !$concat {
            define_parse_instruction!(@emit_operand $out, $metadata_cursor, Src, $rs1);
        } else {
            let _ = metadata_consume_src_state(&mut $metadata_cursor)
                .expect("concat metadata must encode implicit rs1 state");
        }
        define_parse_instruction!(@emit_operand $out, $metadata_cursor, Src, $rs2);
    }};
    (@emit_fields_with_concat $out:ident, $metadata_cursor:ident, $concat:expr;
        $( $field:ident : $kind:ident ),*
    ) => {{
        let _ = $concat;
        define_parse_instruction!(@emit_fields $out, $metadata_cursor; $( $field : $kind ),*);
    }};

    // ---------- parsing ----------
    (@construct $ctx:ident $line:ident $offset:ident $tokens:ident, $concat:expr, $metadata:expr; $name:ident) => {
        Ok(AsmInstr::$name {
            concat: $concat,
            metadata: $metadata,
        })
    };

    (@construct $ctx:ident $line:ident $offset:ident $tokens:ident, $concat:expr, $metadata:expr; $name:ident $( $field:ident : $kind:ident ),+ ) => {{
        let mut it = $tokens.iter().skip(1);
        Ok(AsmInstr::$name {
            concat: $concat,
            metadata: $metadata,
            $(
                $field: define_parse_instruction!(
                    @parse_operand $kind, it.next().unwrap(), $ctx, $line, $offset
                )?,
            )*
        })
    }};

    (@construct_with_concat $ctx:ident $line:ident $offset:ident $tokens:ident, $concat:expr, $metadata:expr; $name:ident $rd:ident : Reg, $rs1:ident : Src, $rs2:ident : Src) => {{
        if $concat {
            let $rd = parse_reg($tokens[1].text)?;
            let $rs2 = parse_src($tokens[2].text, $ctx, $line, $offset)?;
            Ok(AsmInstr::$name {
                concat: true,
                metadata: $metadata,
                $rd,
                $rs1: SrcOperand::Reg($rd),
                $rs2,
            })
        } else {
            define_parse_instruction!(
                @construct $ctx $line $offset $tokens, $concat, $metadata;
                $name $rd : Reg, $rs1 : Src, $rs2 : Src
            )
        }
    }};
    (@construct_with_concat $ctx:ident $line:ident $offset:ident $tokens:ident, $concat:expr, $metadata:expr; $name:ident $( $field:ident : $kind:ident ),* ) => {{
        define_parse_instruction!(
            @construct $ctx $line $offset $tokens, $concat, $metadata;
            $name $( $field : $kind ),*
        )
    }};

    (@parse_operand Reg, $tok:expr, $ctx:expr, $line:ident, $offset:expr) => { parse_reg(&$tok.text) };
    (@parse_operand ImmU8, $tok:expr, $ctx:expr, $line:ident, $offset:expr) => { parse_u8(&$tok.text, $line, $offset) };

    (@parse_operand ImmI32, $tok:expr, $ctx:expr, $line:ident, $offset:expr) => { parse_i32_or_label(&$tok.text, $ctx, $line, $offset) };
    (@parse_operand ImmU32, $tok:expr, $ctx:expr, $line:ident, $offset:expr) => { parse_u32(&$tok.text, $line, $offset) };
    (@parse_operand RefU32, $tok:expr, $ctx:expr, $line:ident, $offset:expr) => {{
        let tok = &$tok.text;
        if let Some(s) = tok.strip_prefix('"').and_then(|t| t.strip_suffix('"')) {
            Ok($ctx.intern_string(s.to_string()))
        } else {
            parse_ref_u32(tok)
        }
    }};

    (@parse_operand Addr, $tok:expr, $ctx:expr, $line:ident, $offset:expr) => { parse_addr(&$tok.text, $line, $offset) };
    (@parse_operand Src, $tok:expr, $ctx:expr, $line:ident, $offset:expr) => { parse_src(&$tok.text, $ctx, $line, $offset) };
}

for_each_instruction!(define_parse_instruction);

/// Extracts all labels from assembly source, identifying public entry points.
///
/// Scans the source for label definitions and returns:
/// - A set of public label names (those prefixed with `pub`)
/// - A vector of all parsed [`Label`] structs
///
/// Also updates `insert_point` to the line number where runtime code starts,
/// used for dispatcher insertion.
pub fn extract_label_data<'a>(
    source: &'a str,
    insert_point: &mut usize,
) -> Result<(HashSet<&'a str>, Vec<Label<'a>>), VMError> {
    let mut public_labels: HashSet<&str> = HashSet::new();
    let mut label_data: Vec<Label> = Vec::new();
    let mut current_section = Section::Runtime;
    let mut runtime_insert: Option<usize> = None;

    // First pass: scan source to find public labels and runtime start.
    for (line_no, line) in source.lines().enumerate() {
        if !is_code_line(line) {
            continue;
        }

        if is_label_def(line) {
            let label = tokenize_label(line_no + 1, line)?;
            current_section = advance_section_for_label(current_section, label.name);

            if current_section == Section::Runtime && runtime_insert.is_none() {
                runtime_insert = Some(line_no);
            }

            // Skip compiler generated internal labels from dispatcher metadata.
            if label.name.starts_with("__") {
                continue;
            }

            // Check if this is a public label definition (`pub label_name(N, reg):`)
            if label.public {
                public_labels.insert(label.name);
            }
            label_data.push(label);
        } else if current_section == Section::Runtime && runtime_insert.is_none() {
            runtime_insert = Some(line_no);
        }
    }

    *insert_point = runtime_insert.unwrap_or(0);
    Ok((public_labels, label_data))
}

/// Preprocesses assembly source to generate a dispatcher for public entry points.
///
/// Scans the source for labels prefixed with `pub` and generates a jump table
/// (`__resolver_jump_table`) that dispatches to public functions based on a
/// selector in `r0`. The generated dispatcher is inserted at runtime start.
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
    // Track where to insert the dispatcher (line number where runtime starts).
    let mut insert_point = 0usize;
    // Collect all public label names (including trailing ':')
    let (public_labels, label_data) = match extract_label_data(source, &mut insert_point) {
        Ok(p) => p,
        Err(e) => {
            errors.push(e);
            return (None, None, None);
        }
    };

    if public_labels.is_empty() {
        return (None, None, Some(label_data));
    }

    let mut base = String::new();
    let mut label_names: Vec<&str> = public_labels.iter().copied().collect();
    label_names.sort();

    let mut labels = Vec::<Label>::with_capacity(label_names.len());
    for name in label_names {
        for label in &label_data {
            if label.name == name {
                labels.push(label.clone())
            }
        }
    }

    // Emit a single DISPATCH instruction with all public entry points.
    // Format: DISPATCH count, label0, r{argr0}, label1, r{argr1}, ...
    write!(base, "DISPATCH {}", labels.len()).unwrap();
    for label in labels.iter() {
        write!(base, ", {}, r{}", label.name, label.argr).unwrap();
    }
    base.push('\n');

    // Count lines added by dispatcher (+1 for the extra newline after base)
    let lines_added = base.lines().count() + 1;

    // Reassemble source with dispatcher inserted at runtime start.
    let mut out = String::with_capacity(source.len() + base.len());
    for (i, line) in source.lines().enumerate() {
        // Insert dispatcher just before the first runtime line.
        if i == insert_point {
            out.push_str(&base);
            out.push('\n');
        }
        out.push_str(line);
        out.push('\n');
    }

    // If source had no lines, still prepend dispatcher.
    if source.lines().next().is_none() {
        out.push_str(&base);
    }

    let dispatcher_info = DispatcherInfo {
        insert_after: insert_point + 1,
        lines_added,
    };

    (Some(out), Some(dispatcher_info), Some(label_data))
}

/// Validates that a `CALL` source argument count matches the target label's declared argc.
fn validate_call_argc_against_label(
    tokens: &[Token],
    label_data: &[Label],
    line_no: usize,
    argc: u8,
) -> Result<(), VMError> {
    let func_name = tokens[2].text;
    for label in label_data {
        if label.name == func_name && label.argc != argc {
            return Err(VMError::ParseErrorString {
                line: line_no + 1,
                offset: tokens[0].offset,
                length: tokens[0].text.len(),
                message: if argc == 1 {
                    format!(
                        "function '{}' expects {} argument, but 1 was provided",
                        label.name, label.argc
                    )
                } else {
                    format!(
                        "function '{}' expects {} argument, but {} were provided",
                        label.name, label.argc, argc
                    )
                },
            });
        }
    }
    Ok(())
}

/// Validates that a `CALL_HOST` source argument count matches host function arity.
fn validate_call_host_argc(tokens: &[Token], line_no: usize, argc: u8) -> Result<(), VMError> {
    let Some(tok) = tokens.get(2) else {
        return Ok(());
    };
    let Some(func_name) = tok
        .text
        .strip_prefix('"')
        .and_then(|name| name.strip_suffix('"'))
    else {
        // Raw refs like @12 cannot be validated at assembly time.
        return Ok(());
    };

    let Some((_, expected)) = HOST_FUNCTIONS.iter().find(|(name, _)| *name == func_name) else {
        return Err(VMError::ParseErrorString {
            line: line_no + 1,
            offset: tok.offset,
            length: tok.text.len(),
            message: format!("unknown host function '{func_name}'"),
        });
    };
    if *expected != argc {
        return Err(VMError::ParseErrorString {
            line: line_no + 1,
            offset: tokens[0].offset,
            length: tokens[0].text.len(),
            message: if argc == 1 {
                format!(
                    "host function '{}' expects {} argument, but 1 was provided",
                    func_name, *expected
                )
            } else {
                format!(
                    "host function '{}' expects {} argument, but {} were provided",
                    func_name, *expected, argc
                )
            },
        });
    }
    Ok(())
}

/// Normalizes `CALL` and `CALL_HOST` source forms:
/// - Source must include `argc` for validation.
/// - Bytecode form omits `argc`, so this strips it before instruction parsing.
fn normalize_call_tokens<'a>(
    tokens: &[Token<'a>],
    label_data: &[Label<'a>],
    line_no: usize,
) -> Result<Vec<Token<'a>>, VMError> {
    if tokens.is_empty() {
        return Ok(Vec::new());
    }

    let opcode = tokens[0].text;
    if opcode == "CALL0" || opcode == "CALL1" || opcode == "CALL_HOST0" || opcode == "CALL_HOST1" {
        return Err(VMError::ParseErrorString {
            line: line_no + 1,
            offset: tokens[0].offset,
            length: tokens[0].text.len(),
            message: format!(
                "'{}' was removed; use '{}' with explicit argc",
                opcode,
                if opcode.starts_with("CALL_HOST") {
                    "CALL_HOST dst, fn, argc, argv"
                } else {
                    "CALL dst, fn, argc, argv"
                }
            ),
        });
    }

    if opcode == Instruction::Call.mnemonic() {
        if tokens.len() != 5 {
            return Err(VMError::ArityMismatch {
                instruction: tokens[0].text.to_string(),
                expected: 4,
                actual: tokens.len() as u8 - 1,
            });
        }
        let argc = parse_u8(tokens[3].text, line_no + 1, tokens[3].offset)?;
        validate_call_argc_against_label(tokens, label_data, line_no, argc)?;
        return Ok(vec![
            tokens[0].clone(),
            tokens[1].clone(),
            tokens[2].clone(),
            tokens[4].clone(),
        ]);
    }

    if opcode == Instruction::CallHost.mnemonic() {
        if tokens.len() != 5 {
            return Err(VMError::ArityMismatch {
                instruction: tokens[0].text.to_string(),
                expected: 4,
                actual: tokens.len() as u8 - 1,
            });
        }
        let argc = parse_u8(tokens[3].text, line_no + 1, tokens[3].offset)?;
        validate_call_host_argc(tokens, line_no, argc)?;
        return Ok(vec![
            tokens[0].clone(),
            tokens[1].clone(),
            tokens[2].clone(),
            tokens[4].clone(),
        ]);
    }

    Ok(tokens.to_vec())
}

/// Intermediate result from pass 1, consumed by pass 2 (step 3).
struct Pass1Result<'a> {
    /// Tokenized instruction lines with line numbers and section classification.
    parsed_lines: Vec<ParsedLine<'a>>,
    /// Assembly context with labels defined and ready for resolution.
    asm_context: AsmContext,
    /// Total init section bytecode size, used to compute global offsets for runtime.
    init_size: usize,
    /// Number of instructions in init section.
    init_instr_count: usize,
    /// Number of instructions in runtime section.
    runtime_instr_count: usize,
    /// Label anchors used by relaxation to recompute offsets.
    label_anchors: Vec<LabelAnchor>,
}

/// One tokenized instruction line tracked through sizing/relaxation/emission.
struct ParsedLine<'a> {
    /// Zero-based source line number.
    line_no: usize,
    /// Tokenized instruction + operands.
    tokens: Vec<Token<'a>>,
    /// Section where this instruction belongs.
    section: Section,
    /// Instruction index within its section.
    section_index: usize,
}

/// Label anchor at a section-local instruction boundary.
struct LabelAnchor {
    /// Label identifier.
    name: String,
    /// Section where the label is defined.
    section: Section,
    /// Instruction boundary index within that section.
    section_index: usize,
}

/// Pass 1: tokenizes source, classifies sections, computes sizes, and registers labels.
///
/// Tokenizes all lines, classifies lines into init/runtime using `__init__`,
/// computes instruction sizes, and records label positions as global offsets in the
/// concatenated address space (init || runtime).
///
/// Collects errors into the provided vector and continues processing where possible.
fn assemble_source_step_2<'a>(
    source: &'a str,
    label_data: Vec<Label<'a>>,
    errors: &mut Vec<VMError>,
) -> Pass1Result<'a> {
    let mut asm_context = AsmContext::new();

    // First pass: tokenize all lines, detect sections, compute global offsets
    // We track (line_no, tokens, section) for each instruction line
    let mut parsed_lines: Vec<ParsedLine> = Vec::new();
    let mut current_section = Section::Runtime;
    let mut saw_runtime_code = false;
    let mut init_instr_count = 0usize;
    let mut runtime_instr_count = 0usize;

    // Track sizes separately for init and runtime sections
    let mut init_size = 0usize;
    let mut runtime_size = 0usize;

    // Temporary label storage: (name, global_offset, line_no, tok_offset)
    // (name, section, local_offset, section_index, line_no, tok_offset, tok_len)
    let mut pending_labels: Vec<(String, Section, usize, usize, usize, usize, usize)> = Vec::new();

    for (line_no, line) in source.lines().enumerate() {
        if !is_code_line(line) {
            continue;
        }
        let mut effective_section = current_section;

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

            let next_section = advance_section_for_label(current_section, label.name);
            if label.name == INIT_LABEL && saw_runtime_code {
                errors.push(VMError::AssemblyError {
                    line: line_no + 1,
                    offset: if label.public { 5 } else { 1 },
                    length: INIT_LABEL.len(),
                    source: "label '__init__' must appear before runtime code".to_string(),
                });
                continue;
            }
            effective_section = next_section;
            current_section = next_section;

            // Get the offset pointer for the current section
            let local_offset = match effective_section {
                Section::Init => &mut init_size,
                Section::Runtime => &mut runtime_size,
            };

            pending_labels.push((
                label.name.to_string(),
                effective_section,
                *local_offset,
                match effective_section {
                    Section::Init => init_instr_count,
                    Section::Runtime => runtime_instr_count,
                },
                line_no + 1,
                if label.public { 4 } else { 0 },
                label.name.len(),
            ));

            // If there are more tokens after the label, treat them as an instruction
            instr_start = line.find(':').unwrap() + 1;
        }
        let raw_tokens = match tokenize(line_no + 1, &line[instr_start..]) {
            Ok(t) => t,
            Err(e) => {
                errors.push(e);
                continue;
            }
        };
        if raw_tokens.is_empty() {
            continue;
        }
        let tokens = match normalize_call_tokens(&raw_tokens, &label_data, line_no) {
            Ok(t) => t,
            Err(e) => {
                errors.push(e);
                continue;
            }
        };

        // Dispatcher is always runtime code; force section when injected before
        // the first runtime label after an `__init__` block.
        if effective_section == Section::Init && tokens[0].text == Instruction::Dispatch.mnemonic()
        {
            effective_section = Section::Runtime;
            current_section = Section::Runtime;
        }

        // Get the offset pointer for the current section.
        let local_offset = match effective_section {
            Section::Init => &mut init_size,
            Section::Runtime => &mut runtime_size,
        };

        if effective_section == Section::Runtime {
            saw_runtime_code = true;
        }

        match instruction_size_from_tokens(&mut asm_context, &tokens) {
            Ok(size) => {
                *local_offset += size;
                let section_index = match effective_section {
                    Section::Init => {
                        let idx = init_instr_count;
                        init_instr_count += 1;
                        idx
                    }
                    Section::Runtime => {
                        let idx = runtime_instr_count;
                        runtime_instr_count += 1;
                        idx
                    }
                };
                parsed_lines.push(ParsedLine {
                    line_no,
                    tokens,
                    section: effective_section,
                    section_index,
                });
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
    let mut label_anchors = Vec::with_capacity(pending_labels.len());
    for (name, section, local_offset, section_index, line_no, tok_offset, tok_len) in pending_labels
    {
        let global_offset = match section {
            Section::Init => local_offset,
            Section::Runtime => init_size + local_offset,
        };
        label_anchors.push(LabelAnchor {
            name: name.clone(),
            section,
            section_index,
        });
        if let Err(e) = asm_context.define_label(name, global_offset) {
            errors.push(VMError::AssemblyError {
                line: line_no,
                offset: tok_offset,
                length: tok_len,
                source: e.to_string(),
            });
        }
    }

    Pass1Result {
        parsed_lines,
        asm_context,
        init_size,
        init_instr_count,
        runtime_instr_count,
        label_anchors,
    }
}

/// Computes section instruction sizes under the provided label map.
fn relaxed_instruction_sizes(
    pass1: &mut Pass1Result<'_>,
    labels: &HashMap<String, usize>,
) -> Result<(Vec<usize>, Vec<usize>, usize), VMError> {
    pass1.asm_context.labels = labels.clone();

    let mut init_sizes = vec![0usize; pass1.init_instr_count];
    let mut runtime_sizes = vec![0usize; pass1.runtime_instr_count];

    let mut init_local_offset = 0usize;
    for parsed in pass1
        .parsed_lines
        .iter()
        .filter(|line| line.section == Section::Init)
    {
        let size = instruction_size_from_tokens_relaxed(
            &mut pass1.asm_context,
            &parsed.tokens,
            init_local_offset,
        )?;
        init_sizes[parsed.section_index] = size;
        init_local_offset += size;
    }
    let init_total = init_local_offset;

    let mut runtime_local_offset = 0usize;
    for parsed in pass1
        .parsed_lines
        .iter()
        .filter(|line| line.section == Section::Runtime)
    {
        let size = instruction_size_from_tokens_relaxed(
            &mut pass1.asm_context,
            &parsed.tokens,
            init_total + runtime_local_offset,
        )?;
        runtime_sizes[parsed.section_index] = size;
        runtime_local_offset += size;
    }

    Ok((init_sizes, runtime_sizes, init_total))
}

/// Builds label offsets from section-local instruction sizes and recorded anchors.
fn relaxed_label_offsets(
    pass1: &Pass1Result<'_>,
    init_sizes: &[usize],
    runtime_sizes: &[usize],
    init_total: usize,
) -> HashMap<String, usize> {
    let mut init_prefix = Vec::with_capacity(init_sizes.len() + 1);
    init_prefix.push(0usize);
    for size in init_sizes {
        init_prefix.push(init_prefix.last().copied().unwrap() + *size);
    }

    let mut runtime_prefix = Vec::with_capacity(runtime_sizes.len() + 1);
    runtime_prefix.push(0usize);
    for size in runtime_sizes {
        runtime_prefix.push(runtime_prefix.last().copied().unwrap() + *size);
    }

    let mut labels = HashMap::with_capacity(pass1.label_anchors.len());
    for anchor in &pass1.label_anchors {
        let global_offset = match anchor.section {
            Section::Init => init_prefix[anchor.section_index],
            Section::Runtime => init_total + runtime_prefix[anchor.section_index],
        };
        labels.insert(anchor.name.clone(), global_offset);
    }
    labels
}

/// Compacts eligible `rd, rs1, rs2` instructions into `rd, rs2` form.
///
/// This enables concat metadata (`A=1`) without requiring source-level compact syntax.
/// Only instructions that explicitly support concat compaction are rewritten.
fn apply_concat_compaction(pass1: &mut Pass1Result<'_>) {
    for parsed in &mut pass1.parsed_lines {
        // Full form only: opcode + rd + rs1 + rs2.
        if parsed.tokens.len() != 4 {
            continue;
        }

        let Ok(instr) = instruction_from_str(parsed.tokens[0].text) else {
            continue;
        };
        if !instr.supports_concat_compact() {
            continue;
        }

        let Ok(rd) = parse_reg(parsed.tokens[1].text) else {
            continue;
        };
        let Ok(rs1) = parse_reg(parsed.tokens[2].text) else {
            continue;
        };

        if rd == rs1 {
            // Keep opcode, rd, rs2
            parsed.tokens.remove(2);
        }
    }
}

/// Step 2.5: relaxes label-based ImmI32 widths to compact encodings.
///
/// Runs a fixed-point layout loop: recompute instruction sizes using current
/// label offsets, rebuild label offsets from new sizes, repeat until stable.
fn assemble_source_step_2_5_relax(pass1: &mut Pass1Result<'_>, errors: &mut Vec<VMError>) {
    const MAX_RELAX_PASSES: usize = 16;

    // Apply concat compaction before layout relaxation.
    apply_concat_compaction(pass1);

    let mut labels = pass1.asm_context.labels.clone();
    let mut last_init_total = pass1.init_size;

    for _ in 0..MAX_RELAX_PASSES {
        let (init_sizes, runtime_sizes, init_total) =
            match relaxed_instruction_sizes(pass1, &labels) {
                Ok(layout) => layout,
                Err(err) => {
                    errors.push(VMError::AssemblyError {
                        line: 1,
                        offset: 1,
                        length: 1,
                        source: err.to_string(),
                    });
                    return;
                }
            };

        let new_labels = relaxed_label_offsets(pass1, &init_sizes, &runtime_sizes, init_total);
        last_init_total = init_total;

        if new_labels == labels {
            labels = new_labels;
            break;
        }
        labels = new_labels;
    }

    pass1.init_size = last_init_total;
    pass1.asm_context.labels = labels;
}

/// Pass 2: parses instructions with label resolution and emits bytecode.
///
/// Consumes the result of pass 1 (step 2), resolves label references to
/// PC-relative offsets, and emits bytecode into separate init and runtime vectors.
///
/// Collects errors into the provided vector and continues processing where possible.
fn assemble_source_step_3(
    pass1: Pass1Result<'_>,
    errors: &mut Vec<VMError>,
) -> Option<DeployProgram> {
    let Pass1Result {
        parsed_lines,
        mut asm_context,
        init_size,
        init_instr_count: _,
        runtime_instr_count: _,
        label_anchors: _,
    } = pass1;

    let mut init_bytecode = Vec::new();
    let mut runtime_bytecode = Vec::new();

    for ParsedLine {
        line_no,
        tokens,
        section,
        section_index: _,
    } in parsed_lines
    {
        let bytecode = match section {
            Section::Init => &mut init_bytecode,
            Section::Runtime => &mut runtime_bytecode,
        };

        // Compute global offset for label resolution
        let global_offset = match section {
            Section::Init => bytecode.len(),
            Section::Runtime => init_size + bytecode.len(),
        };

        match parse_instruction(&mut asm_context, &tokens, line_no + 1, global_offset) {
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
            memory: asm_context.memory,
        })
    } else {
        None
    }
}

/// Assemble a full source string into bytecode.
///
/// Uses two-pass assembly:
/// 1. First pass: tokenize lines, record label positions, classify init/runtime
/// 2. Second pass: parse instructions with label resolution, emit bytecode
///
/// The reserved label `__init__:` marks initialization code. Runtime code is the
/// default section and starts at the first non-init label/instruction.
///
/// Labels are computed for a concatenated view (init_code + runtime_code) so that
/// init_code can call into runtime_code. The VM should run the concatenated bytecode,
/// starting at ip=0 for deployment and ip=init_code.len() for runtime calls.
pub fn assemble_source(source: impl Into<String>) -> Result<DeployProgram, VMError> {
    assemble_source_with_name(source.into(), "<source>")
}

/// Formats instruction bytes as hex with metadata highlighted in brackets.
///
/// Groups payload bytes by operand and separates groups with commas.
/// Example: `C9 [0001_0010] 04, 00 00, 66`
fn format_audit_bytes(bytes: &[u8], operand_groups: &[usize]) -> String {
    if bytes.is_empty() {
        return String::new();
    }
    let has_metadata = Instruction::decode_opcode(bytes[0])
        .map(|(_, has_meta)| has_meta)
        .unwrap_or(false);

    let mut out = format!("{:02X}", bytes[0]);
    let payload_start = if has_metadata && bytes.len() > 1 {
        out.push(' ');
        out.push_str(&format!("[{:04b}_{:04b}]", bytes[1] >> 4, bytes[1] & 0x0F));
        2usize
    } else {
        1usize
    };

    let payload = if payload_start <= bytes.len() {
        &bytes[payload_start..]
    } else {
        &[]
    };
    if payload.is_empty() {
        return out;
    }

    let mut groups = Vec::new();
    let mut cursor = 0usize;
    for &len in operand_groups {
        if len == 0 || cursor + len > payload.len() {
            break;
        }
        let mut segment = String::new();
        for (idx, byte) in payload[cursor..cursor + len].iter().enumerate() {
            if idx > 0 {
                segment.push(' ');
            }
            segment.push_str(&format!("{:02X}", byte));
        }
        groups.push(segment);
        cursor += len;
    }
    if cursor < payload.len() {
        let mut segment = String::new();
        for (idx, byte) in payload[cursor..].iter().enumerate() {
            if idx > 0 {
                segment.push(' ');
            }
            segment.push_str(&format!("{:02X}", byte));
        }
        groups.push(segment);
    }
    if !groups.is_empty() {
        out.push(' ');
        out.push_str(&groups.join(", "));
    }

    out
}

/// Returns byte index where inline comment starts, ignoring `#` inside strings.
fn comment_start_index(line: &str) -> usize {
    let bytes = line.as_bytes();
    let mut in_str = false;
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => in_str = !in_str,
            b'#' if !in_str => return i,
            _ => {}
        }
        i += 1;
    }
    line.len()
}

/// Replaces only the instruction segment of a source line with encoded bytes.
///
/// Keeps labels, indentation, and inline comments intact.
fn render_audit_line_in_place(line: &str, encoded: &str) -> String {
    let comment_idx = comment_start_index(line);
    let (code_part, comment_part) = line.split_at(comment_idx);

    let mut instr_start = 0usize;
    if is_code_line(code_part)
        && is_label_def(code_part)
        && let Some(colon) = code_part.find(':')
    {
        instr_start = colon + 1;
    }

    let instr_segment = &code_part[instr_start..];
    let instr_bytes = instr_segment.as_bytes();
    let mut leading = 0usize;
    while leading < instr_bytes.len()
        && (instr_bytes[leading] == b' ' || instr_bytes[leading] == b'\t')
    {
        leading += 1;
    }
    let mut trailing = instr_bytes.len();
    while trailing > leading
        && (instr_bytes[trailing - 1] == b' ' || instr_bytes[trailing - 1] == b'\t')
    {
        trailing -= 1;
    }

    let mut out = String::with_capacity(line.len() + encoded.len());
    out.push_str(&code_part[..instr_start]);
    out.push_str(&instr_segment[..leading]);
    out.push_str(encoded);
    out.push_str(&instr_segment[trailing..]);
    out.push_str(comment_part);
    out
}

/// Rebuilds source text with instruction lines replaced by encoded byte strings.
fn render_audit_source_in_place(source: &str, line_bytes: &[Option<String>]) -> String {
    let mut out = String::with_capacity(source.len());
    for (line_no, line) in source.lines().enumerate() {
        if line_no > 0 {
            out.push('\n');
        }
        if let Some(encoded) = line_bytes.get(line_no).and_then(|v| v.as_ref()) {
            out.push_str(&render_audit_line_in_place(line, encoded));
        } else {
            out.push_str(line);
        }
    }
    if source.ends_with('\n') {
        out.push('\n');
    }
    out
}

/// Assembles source and renders an audit view with bytecode in place of instructions.
///
/// Each instruction is rendered using the post-optimization instruction stream
/// (after step 2.5 relaxation/compaction), so output matches emitted bytecode.
pub fn assemble_source_audit(source: impl Into<String>) -> Result<String, VMError> {
    let source = source.into();
    let mut errors = Vec::new();

    let normalized = assemble_source_step_0(&source, &mut errors);
    if normalized.is_none() {
        return Err(errors.into_iter().next().unwrap_or(VMError::AssemblyError {
            line: 0,
            offset: 0,
            length: 1,
            source: "assembly failed".to_string(),
        }));
    }
    let normalized_source = normalized.unwrap_or_else(|| source.clone());

    let (processed, dispatcher_info, label_data) =
        assemble_source_step_1(&normalized_source, &mut errors);
    if processed.is_none() && !errors.is_empty() {
        let err = errors.into_iter().next().unwrap_or(VMError::AssemblyError {
            line: 0,
            offset: 0,
            length: 1,
            source: "assembly failed".to_string(),
        });
        return Err(adjust_error_line(err, dispatcher_info));
    }

    let final_source = processed.unwrap_or_else(|| normalized_source.clone());
    let mut pass1 =
        assemble_source_step_2(&final_source, label_data.unwrap_or_default(), &mut errors);
    if !errors.is_empty() {
        let err = errors.remove(0);
        return Err(adjust_error_line(err, dispatcher_info));
    }

    assemble_source_step_2_5_relax(&mut pass1, &mut errors);
    if !errors.is_empty() {
        let err = errors.remove(0);
        return Err(adjust_error_line(err, dispatcher_info));
    }

    let Pass1Result {
        parsed_lines,
        mut asm_context,
        init_size,
        init_instr_count: _,
        runtime_instr_count: _,
        label_anchors: _,
    } = pass1;

    let mut init_byte_len = 0usize;
    let mut runtime_byte_len = 0usize;
    let mut line_bytes = vec![None; final_source.lines().count()];

    for ParsedLine {
        line_no,
        tokens,
        section,
        section_index: _,
    } in parsed_lines
    {
        let global_offset = match section {
            Section::Init => init_byte_len,
            Section::Runtime => init_size + runtime_byte_len,
        };

        let instr = parse_instruction(&mut asm_context, &tokens, line_no + 1, global_offset)
            .map_err(|e| VMError::AssemblyError {
                line: line_no + 1,
                offset: tokens.first().map(|t| t.offset).unwrap_or(1),
                length: tokens.first().map(|t| t.text.len()).unwrap_or(1),
                source: e.to_string(),
            })?;
        let operand_groups =
            instruction_operand_group_sizes_from_tokens(&mut asm_context, &tokens, global_offset)
                .map_err(|e| VMError::AssemblyError {
                line: line_no + 1,
                offset: tokens.first().map(|t| t.offset).unwrap_or(1),
                length: tokens.first().map(|t| t.text.len()).unwrap_or(1),
                source: e.to_string(),
            })?;

        let mut bytes = Vec::new();
        instr.assemble(&mut bytes);
        if let Some(slot) = line_bytes.get_mut(line_no) {
            *slot = Some(format_audit_bytes(&bytes, &operand_groups));
        }

        match section {
            Section::Init => init_byte_len += bytes.len(),
            Section::Runtime => runtime_byte_len += bytes.len(),
        }
    }

    Ok(render_audit_source_in_place(&final_source, &line_bytes))
}

/// Logs accumulated assembly errors and returns the first one (line-adjusted).
///
/// Returns `Ok(())` when `errors` is empty, allowing callers to use `?` for
/// early exit on failure.
fn flush_assembly_errors(
    errors: &mut Vec<VMError>,
    source_name: &str,
    source: &str,
    dispatcher: Option<DispatcherInfo>,
) -> Result<(), VMError> {
    if errors.is_empty() {
        return Ok(());
    }
    log_assembly_errors(source_name, source, errors, dispatcher);
    let first_err = errors.drain(..).next().unwrap();
    Err(adjust_error_line(first_err, dispatcher))
}

/// Assembles source with an associated filename for error diagnostics.
///
/// Runs both assembly passes and logs compiler-style diagnostics to stderr
/// on failure, including source location information for all errors found.
fn assemble_source_with_name(source: String, source_name: &str) -> Result<DeployProgram, VMError> {
    let mut errors = Vec::new();

    let normalized = assemble_source_step_0(&source, &mut errors);
    if normalized.is_none() {
        flush_assembly_errors(&mut errors, source_name, &source, None)?;
    }
    let normalized_source = normalized.unwrap_or_else(|| source.clone());

    let (processed, dispatcher_info, label_data) =
        assemble_source_step_1(&normalized_source, &mut errors);
    if processed.is_none() {
        flush_assembly_errors(
            &mut errors,
            source_name,
            &normalized_source,
            dispatcher_info,
        )?;
    }

    let final_source = processed.unwrap_or_else(|| normalized_source.clone());
    let mut pass1 =
        assemble_source_step_2(&final_source, label_data.unwrap_or_default(), &mut errors);
    flush_assembly_errors(
        &mut errors,
        source_name,
        &normalized_source,
        dispatcher_info,
    )?;

    assemble_source_step_2_5_relax(&mut pass1, &mut errors);
    flush_assembly_errors(
        &mut errors,
        source_name,
        &normalized_source,
        dispatcher_info,
    )?;

    let result = assemble_source_step_3(pass1, &mut errors);
    flush_assembly_errors(
        &mut errors,
        source_name,
        &normalized_source,
        dispatcher_info,
    )?;

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

/// Convenience: render in-place audit view from a file.
pub fn assemble_file_audit<P: AsRef<Path>>(path: P) -> Result<String, VMError> {
    let path_ref = path.as_ref();
    let source = fs::read_to_string(path_ref).map_err(|e| VMError::IoError {
        path: path_ref.display().to_string(),
        source: e.to_string(),
    })?;
    assemble_source_audit(source)
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
        assert_eq!(program.runtime_code.len(), 4); // opcode(1) + metadata(1) + reg(1) + i64(1)
    }

    #[test]
    fn assemble_audit_keeps_labels_and_comments() {
        let source = r#"
start: ADD r1, r1, r2 # add
# keep this comment
MOVE r3, 42
"#;
        let audit = assemble_source_audit(source).unwrap();
        let lines: Vec<&str> = audit.lines().collect();
        assert!(lines[1].starts_with("start: "));
        assert!(lines[1].contains("# add"));
        assert!(!lines[1].contains("ADD r1"));
        assert_eq!(lines[2], "# keep this comment");
        assert!(!lines[3].contains("MOVE r3, 42"));
    }

    #[test]
    fn assemble_audit_ignores_hash_inside_strings() {
        let source = r#"MOVE r0, "a#b" # trailing comment"#;
        let audit = assemble_source_audit(source).unwrap();
        assert!(audit.contains("# trailing comment"));
        assert!(!audit.contains("#b\" # trailing comment"));
    }

    #[test]
    fn format_audit_bytes_groups_by_operand() {
        assert_eq!(
            format_audit_bytes(&[0xC9, 0x12, 0x04, 0x00, 0x00, 0x66], &[1, 2, 1]),
            "C9 [0001_0010] 04, 00 00, 66"
        );
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
        let err = assemble_source("BEQ r0, r1").unwrap_err();
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
            program.memory,
            DeployProgram::items_to_memory(vec!["first".into(), "second".into()])
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
            parse_instruction(&mut AsmContext::new(), &[], 0, 0),
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
        let instr = parse_instruction(&mut AsmContext::new(), &tokens, 0, 0).unwrap();
        match instr {
            AsmInstr::Add {
                concat,
                metadata,
                rd,
                rs1,
                rs2,
            } => {
                assert!(!concat);
                assert_eq!(metadata, None);
                assert_eq!(rd, 0);
                assert_eq!(rs1, SrcOperand::Reg(1));
                assert_eq!(rs2, SrcOperand::Reg(2));
            }
            _ => panic!("wrong instruction type"),
        }
    }

    #[test]
    fn instruction_parse_compact_concat() {
        let tokens = vec![
            Token {
                text: "ADD",
                offset: 1,
            },
            Token {
                text: "r7",
                offset: 5,
            },
            Token {
                text: "r2",
                offset: 9,
            },
        ];
        let instr = parse_instruction(&mut AsmContext::new(), &tokens, 0, 0).unwrap();
        match instr {
            AsmInstr::Add {
                concat,
                metadata,
                rd,
                rs1,
                rs2,
            } => {
                assert!(concat);
                assert_eq!(metadata, Some(0b1000_0000));
                assert_eq!(rd, 7);
                assert_eq!(rs1, SrcOperand::Reg(7));
                assert_eq!(rs2, SrcOperand::Reg(2));
            }
            _ => panic!("wrong instruction type"),
        }
    }

    #[test]
    fn compact_concat_reduces_size_by_one_byte() {
        let full = vec![
            Token {
                text: "ADD",
                offset: 1,
            },
            Token {
                text: "r1",
                offset: 5,
            },
            Token {
                text: "r1",
                offset: 9,
            },
            Token {
                text: "r0",
                offset: 13,
            },
        ];
        let compact = vec![
            Token {
                text: "ADD",
                offset: 1,
            },
            Token {
                text: "r1",
                offset: 5,
            },
            Token {
                text: "r0",
                offset: 9,
            },
        ];
        let mut ctx = AsmContext::new();
        let full_size = instruction_size_from_tokens(&mut ctx, &full).unwrap();
        let compact_size = instruction_size_from_tokens(&mut ctx, &compact).unwrap();
        // Full form defaults to no metadata; compact form uses concat metadata.
        assert_eq!(full_size, compact_size);
    }

    #[test]
    fn compact_immi32_reduces_size_for_small_values() {
        let small = vec![
            Token {
                text: "JUMP",
                offset: 1,
            },
            Token {
                text: "1",
                offset: 6,
            },
        ];
        let large = vec![
            Token {
                text: "JUMP",
                offset: 1,
            },
            Token {
                text: "70000",
                offset: 6,
            },
        ];
        let label = vec![
            Token {
                text: "JUMP",
                offset: 1,
            },
            Token {
                text: "loop",
                offset: 6,
            },
        ];

        let mut ctx = AsmContext::new();
        let small_size = instruction_size_from_tokens(&mut ctx, &small).unwrap();
        let large_size = instruction_size_from_tokens(&mut ctx, &large).unwrap();
        let label_size = instruction_size_from_tokens(&mut ctx, &label).unwrap();

        assert_eq!(small_size, 2); // opcode + i32_1 payload (default Len1, no metadata)
        assert_eq!(large_size, 6); // opcode + metadata + i32_4 payload
        assert_eq!(label_size, 6); // unresolved labels keep i32_4 payload
    }

    #[test]
    fn compact_ref_u32_reduces_size_for_small_values() {
        let small = vec![
            Token {
                text: "CALL_HOST",
                offset: 1,
            },
            Token {
                text: "r0",
                offset: 12,
            },
            Token {
                text: "@1",
                offset: 16,
            },
            Token {
                text: "r1",
                offset: 20,
            },
        ];
        let medium = vec![
            Token {
                text: "CALL_HOST",
                offset: 1,
            },
            Token {
                text: "r0",
                offset: 12,
            },
            Token {
                text: "@300",
                offset: 16,
            },
            Token {
                text: "r1",
                offset: 20,
            },
        ];
        let large = vec![
            Token {
                text: "CALL_HOST",
                offset: 1,
            },
            Token {
                text: "r0",
                offset: 12,
            },
            Token {
                text: "@70000",
                offset: 16,
            },
            Token {
                text: "r1",
                offset: 20,
            },
        ];

        let mut ctx = AsmContext::new();
        let small_size = instruction_size_from_tokens(&mut ctx, &small).unwrap();
        let medium_size = instruction_size_from_tokens(&mut ctx, &medium).unwrap();
        let large_size = instruction_size_from_tokens(&mut ctx, &large).unwrap();

        assert_eq!(small_size, 4); // opcode + dst + u32_1 + argv (default Len1, no metadata)
        assert_eq!(medium_size, 6); // opcode + metadata + dst + u32_2 + argv
        assert_eq!(large_size, 8); // opcode + metadata + dst + u32_4 + argv
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
            concat: false,
            metadata: Some(0b0010_0100),
            rd: 10,
            rs1: SrcOperand::I64(20),
            rs2: SrcOperand::I64(30),
        };
        let mut out = Vec::new();
        instr.assemble(&mut out);
        let expected = vec![Instruction::Sub as u8, 0b0010_0100, 10, 20, 30];
        assert_eq!(out, expected);
    }

    #[test]
    fn asm_instr_assemble_two_reg() {
        let instr = AsmInstr::Neg {
            concat: false,
            metadata: Some(0b0000_0100),
            rd: 1,
            rs: SrcOperand::I64(2),
        };
        let mut out = Vec::new();
        instr.assemble(&mut out);
        let expected = vec![Instruction::Neg as u8, 0b0000_0100, 1, 2];
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
        assert_eq!(parse_u8("0", 0, 0).unwrap(), 0);
        assert_eq!(parse_u8("255", 0, 0).unwrap(), 255);
        assert_eq!(parse_u8("42", 0, 0).unwrap(), 42);
    }

    #[test]
    fn parse_u8_invalid() {
        assert!(parse_u8("256", 0, 0).is_err());
        assert!(parse_u8("-1", 0, 0).is_err());
        assert!(parse_u8("abc", 0, 0).is_err());
        assert!(parse_u8("", 0, 0).is_err());
    }

    #[test]
    fn assemble_call_host_argc_u8() {
        // CALL_HOST source keeps argc for validation, bytecode omits it.
        // With RefU32 Len1 default, metadata is omitted.
        let program = assemble_source(r#"CALL_HOST r0, "len", 1, r1"#).unwrap();
        let (instr, has_metadata) = Instruction::decode_opcode(program.runtime_code[0]).unwrap();
        assert_eq!(instr, Instruction::CallHost);
        assert!(!has_metadata);
        assert_eq!(program.runtime_code[1], 0); // dst = r0
        assert_eq!(program.runtime_code[2], 0); // fn_id = @0
        assert_eq!(program.runtime_code[3], 1); // argv = r1
        assert_eq!(program.runtime_code.len(), 4);
    }

    #[test]
    fn assemble_call_argc_u8() {
        // CALL source keeps argc for validation, bytecode omits it.
        // Label-based fn_id is relaxed after step 2.5 and may use 1/2/4 bytes.
        let program = assemble_source("my_func(5, r2):\nCALL r0, my_func, 5, r2").unwrap();
        let (instr, has_metadata) = Instruction::decode_opcode(program.runtime_code[0]).unwrap();
        assert_eq!(instr, Instruction::Call);
        let dst_index = if has_metadata {
            assert!(matches!(
                program.runtime_code[1],
                x if x == ImmI32MetadataState::Len2 as u8 || x == ImmI32MetadataState::Len4 as u8
            ));
            2usize
        } else {
            // Len1 is default, so metadata byte is omitted.
            1usize
        };
        assert_eq!(program.runtime_code[dst_index], 0); // dst = r0
        assert_eq!(*program.runtime_code.last().unwrap(), 2); // argv = r2
        assert!((4..=8).contains(&program.runtime_code.len()));
    }

    #[test]
    fn assemble_eq_reg_reg_reg_omits_zero_metadata() {
        let program = assemble_source("EQ r3, r1, r2").unwrap();
        assert_eq!(
            program.runtime_code,
            vec![Instruction::Eq.encode_opcode(false), 3, 1, 2]
        );
    }

    #[test]
    fn assemble_call_argc_max_u8() {
        let source = "f(255, r0):\nRET r0\nCALL r0, f, 255, r0";
        assert!(assemble_source(source).is_ok());
    }

    #[test]
    fn assemble_call_argc_overflow() {
        // 256 exceeds u8 range
        let err = assemble_source("f(1, r0):\nRET r0\nCALL r0, f, 256, r0").unwrap_err();
        assert!(matches!(err, VMError::ParseErrorString { .. }));
    }

    // ==================== Sections ====================

    #[test]
    fn assemble_defaults_to_runtime_when_no_init_label() {
        let program = assemble_source("MOVE r0, 1").unwrap();
        assert!(program.init_code.is_empty());
        assert!(!program.runtime_code.is_empty());
    }

    #[test]
    fn assemble_init_label_only() {
        let source = "__init__:\nMOVE r0, 42\nHALT";
        let program = assemble_source(source).unwrap();
        assert_eq!(program.init_code.len(), 5);
        assert!(program.runtime_code.is_empty());
    }

    #[test]
    fn assemble_runtime_only_label() {
        let source = "main:\nMOVE r0, 42";
        let program = assemble_source(source).unwrap();
        assert!(program.init_code.is_empty());
        assert_eq!(program.runtime_code.len(), 4);
    }

    #[test]
    fn assemble_init_then_runtime_by_label() {
        let source = r#"
__init__:
MOVE r0, 1
MOVE r1, 2
HALT

        main:
MOVE r2, 3
"#;
        let program = assemble_source(source).unwrap();
        assert_eq!(program.init_code.len(), 10); // 2 MOVE + HALT instructions
        assert_eq!(program.runtime_code.len(), 4); // 1 MOVE instruction
    }

    #[test]
    fn assemble_internal_labels_inherit_current_section() {
        let source = r#"
__init__:
__init_loop: MOVE r0, 1
HALT

main:
__rt_loop: MOVE r1, 2
"#;
        let program = assemble_source(source).unwrap();
        assert!(!program.init_code.is_empty());
        assert!(!program.runtime_code.is_empty());
    }

    #[test]
    fn assemble_strings_across_init_and_runtime() {
        let source = r#"
__init__:
MOVE r0, "init"
HALT

main:
MOVE r1, "runtime"
"#;
        let program = assemble_source(source).unwrap();
        assert_eq!(program.memory.len(), 8 + 4 + 8 + 7);
        assert_eq!(&program.memory[8..12], b"init");
        assert_eq!(&program.memory[20..27], b"runtime");
    }

    #[test]
    fn init_label_after_runtime_is_hoisted() {
        let source = "main:\nMOVE r0, 1\n__init__:\nMOVE r1, 2\nHALT";
        let program = assemble_source(source).unwrap();
        assert_eq!(program.init_code.len(), 5);
        assert!(program.runtime_code.len() >= 4);
    }

    #[test]
    fn init_must_end_with_halt() {
        let source = "__init__:\nMOVE r0, 1\nRET r0\nmain:\nMOVE r1, 2";
        let err = assemble_source(source).unwrap_err();
        assert!(matches!(
            err,
            VMError::AssemblyError { ref source, .. } if source.contains("__init__") && source.contains("HALT")
        ));
    }

    #[test]
    fn init_end_with_halt_is_valid() {
        let source = "__init__:\nMOVE r0, 1\nHALT\nmain:\nMOVE r1, 2";
        let program = assemble_source(source).unwrap();
        assert!(!program.init_code.is_empty());
        assert!(!program.runtime_code.is_empty());
    }

    #[test]
    fn dispatcher_is_emitted_in_runtime_when_init_exists() {
        let source = r#"
__init__:
MOVE r0, 1
HALT

pub factorial(1, r1):
RET r1
"#;
        let program = assemble_source(source).unwrap();
        assert_eq!(program.init_code[0], Instruction::Move as u8);
        assert_eq!(program.runtime_code[0], Instruction::Dispatch as u8);
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

    // ==================== Call argc validation ====================

    #[test]
    fn call0_removed() {
        let source = "add(2, r0):\nRET r0\nCALL0 r1, add";
        let err = assemble_source(source).unwrap_err();
        assert!(matches!(err, VMError::ParseErrorString { .. }));
    }

    #[test]
    fn call1_removed() {
        let source = "add(2, r0):\nRET r0\nCALL1 r1, add, r2";
        let err = assemble_source(source).unwrap_err();
        assert!(matches!(err, VMError::ParseErrorString { .. }));
    }

    #[test]
    fn call_argc_mismatch() {
        let source = "add(2, r0):\nRET r0\nCALL r1, add, 3, r2";
        let err = assemble_source(source).unwrap_err();
        assert!(matches!(err, VMError::ParseErrorString { .. }));
    }

    #[test]
    fn call_argc_correct() {
        let source = "add(2, r0):\nADD r0, r0, r1\nRET r0\nCALL r1, add, 2, r2";
        assert!(assemble_source(source).is_ok());
    }

    #[test]
    fn call_host0_removed() {
        let source = r#"CALL_HOST0 r0, "len""#;
        let err = assemble_source(source).unwrap_err();
        assert!(matches!(err, VMError::ParseErrorString { .. }));
    }

    #[test]
    fn call_host1_removed() {
        let source = r#"CALL_HOST1 r0, "slice", r1"#;
        let err = assemble_source(source).unwrap_err();
        assert!(matches!(err, VMError::ParseErrorString { .. }));
    }

    #[test]
    fn call_host_argc_mismatch() {
        let source = r#"CALL_HOST r0, "len", 2, r1"#;
        let err = assemble_source(source).unwrap_err();
        assert!(matches!(err, VMError::ParseErrorString { .. }));
    }

    #[test]
    fn call_host_argc_correct() {
        let source = r#"MOVE r1, "hello"
CALL_HOST r0, "len", 1, r1"#;
        assert!(assemble_source(source).is_ok());
    }
}
