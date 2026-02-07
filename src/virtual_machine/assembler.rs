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
use crate::types::encoding::Encode;
use crate::utils::log::SHOW_TYPE;
use crate::virtual_machine::errors::VMError;
use crate::virtual_machine::isa::Instruction;
use crate::virtual_machine::operand::{AddrOperand, SrcOperand};
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
    let argc = parse_u8_or_hex(&arg_data[n_start..j], line_no, arg_start + n_start + 1)?;

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
    let argr = parse_u8_or_hex(&arg_data[r_start..j], line_no, arg_start + r_start + 1)?;

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

macro_rules! define_parse_int_or_hex {
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

define_parse_int_or_hex! {
    parse_u8_or_hex: u8,
    parse_u32_or_hex: u32,
    parse_i32_or_hex: i32,
    pub(crate) parse_i64_or_hex: i64,
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
    if let Ok(v) = parse_i32_or_hex(tok, line, current_global_offset) {
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
    if let Ok(v) = parse_i64_or_hex(tok, line, current_global_offset) {
        return Ok(v);
    }
    let target = ctx.resolve_label(tok)?;
    Ok(target as i64 - current_global_offset as i64)
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
    Ok(AddrOperand::U32(parse_u32_or_hex(
        tok,
        line,
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

/// Computes the encoded size of an Addr operand from its token text.
///
/// - Register (r0, r1, ...): tag(1) + reg(1) = 2 bytes
/// - Immediate u32: tag(1) + u32(4) = 5 bytes
fn addr_size_from_token(tok: &str) -> usize {
    if tok.starts_with('r') && tok.len() > 1 && tok[1..].chars().all(|c| c.is_ascii_digit()) {
        2 // tag + register
    } else {
        5 // tag + u32
    }
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
                        AsmInstr::$name { $( $field ),* } => {
                            out.push($opcode);
                            $(
                                define_instructions!(@emit out, $kind, $field);
                            )*
                        }
                    ),*
                    AsmInstr::Dispatch { entries } => {
                        out.push(Instruction::Dispatch as u8);
                        out.push(entries.len() as u8);
                        for (offset, argr) in entries {
                            out.extend_from_slice(&(*offset as i32).to_le_bytes());
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
                                expected: EXPECTED as u8 - 1,
                                actual: tokens.len() as u8 - 1,
                            });
                        }
                        1usize $( + define_parse_instruction!(@token_size $kind, tok_iter) )*
                    }
                ),*
                Instruction::Dispatch => {
                    // DISPATCH count, label0, reg0, label1, reg1, ...
                    // Token layout: ["DISPATCH", count, (label, reg)*]
                    if tokens.len() < 2 {
                        return Err(VMError::ArityMismatch {
                            instruction: tokens[0].text.to_string(),
                            expected: 2,
                            actual: tokens.len() as u8 - 1,
                        });
                    }
                    let count = tokens[1].text.parse::<u8>().map_err(|_| {
                        VMError::InvalidInstructionName { name: tokens[1].text.to_string() }
                    })?;
                    let expected = 2 + count as usize * 2;
                    if tokens.len() != expected {
                        return Err(VMError::ArityMismatch {
                            instruction: tokens[0].text.to_string(),
                            expected: expected as u8 - 1,
                            actual: tokens.len() as u8 - 1,
                        });
                    }
                    // opcode(1) + count(1) + count * (i32(4) + reg(1))
                    2 + count as usize * 5
                }
            })
        }

        /// Parse one instruction from tokens into [`AsmInstr`].
        ///
        /// `current_global_offset` is the global bytecode offset (in init || runtime space)
        /// where this instruction starts, used for resolving label references to relative offsets.
        fn parse_instruction(
            ctx: &mut AsmContext,
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
            let offset = current_global_offset + instruction_size_from_tokens(tokens)?;

            match instr {
                $(
                    Instruction::$name => {
                        const EXPECTED: usize = 1 + define_parse_instruction!(@count $( $field ),*);
                        if tokens.len() != EXPECTED {
                            return Err(VMError::ArityMismatch {
                                instruction: tokens[0].text.to_string(),
                                expected: EXPECTED as u8 - 1,
                                actual: tokens.len() as u8 - 1,
                            });
                        }

                        define_parse_instruction!(
                            @construct ctx line offset tokens; $name $( $field : $kind ),*
                        )
                    }
                ),*
                Instruction::Dispatch => {
                    if tokens.len() < 2 {
                        return Err(VMError::ArityMismatch {
                            instruction: tokens[0].text.to_string(),
                            expected: 2,
                            actual: tokens.len() as u8 - 1,
                        });
                    }
                    let count = parse_u8_or_hex(&tokens[1].text, line, offset)?;
                    let expected = 2 + count as usize * 2;
                    if tokens.len() != expected {
                        return Err(VMError::ArityMismatch {
                            instruction: tokens[0].text.to_string(),
                            expected: expected as u8 - 1,
                            actual: tokens.len() as u8 - 1,
                        });
                    }
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

    // ---------- operand sizes from tokens ----------
    (@token_size Reg, $iter:ident) => { { $iter.next(); 1usize } };
    (@token_size ImmU8, $iter:ident) => { { $iter.next(); 1usize } };

    (@token_size RefU32, $iter:ident) => { { $iter.next(); 4usize } };
    (@token_size ImmI32, $iter:ident) => { { $iter.next(); 4usize } };
    (@token_size ImmU32, $iter:ident) => { { $iter.next(); 4usize } };

    (@token_size Addr, $iter:ident) => { addr_size_from_token($iter.next().unwrap().text) };
    (@token_size Src, $iter:ident) => { src_size_from_token($iter.next().unwrap().text) };

    // ---------- parsing ----------
    (@construct $ctx:ident $line:ident $offset:ident $tokens:ident; $name:ident) => { Ok(AsmInstr::$name { }) };

    (@construct $ctx:ident $line:ident $offset:ident $tokens:ident; $name:ident $( $field:ident : $kind:ident ),+ ) => {{
        let mut it = $tokens.iter().skip(1);
        Ok(AsmInstr::$name {
            $(
                $field: define_parse_instruction!(
                    @parse_operand $kind, it.next().unwrap(), $ctx, $line, $offset
                )?,
            )*
        })
    }};

    (@parse_operand Reg, $tok:expr, $ctx:expr, $line:ident, $offset:expr) => { parse_reg(&$tok.text) };
    (@parse_operand ImmU8, $tok:expr, $ctx:expr, $line:ident, $offset:expr) => { parse_u8_or_hex(&$tok.text, $line, $offset) };

    (@parse_operand ImmI32, $tok:expr, $ctx:expr, $line:ident, $offset:expr) => { parse_i32_or_label(&$tok.text, $ctx, $line, $offset) };
    (@parse_operand ImmU32, $tok:expr, $ctx:expr, $line:ident, $offset:expr) => { parse_u32_or_hex(&$tok.text, $line, $offset) };
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
        out.push_str(line.split(COMMENT_CHAR).next().unwrap_or(""));
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

/// Validates that a `CALL` instruction's argument count matches the target label's declared argc.
fn check_call_argc(
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

/// Validates that a `CALL_HOST` instruction's argument count matches the host function's expected argc.
fn check_call_host_argc(tokens: &[Token], line_no: usize, argc: u8) -> Result<(), VMError> {
    let func_name = &tokens[2].text[1..tokens[2].text.len() - 1];
    for (name, func_argc) in HOST_FUNCTIONS {
        if *name == func_name && *func_argc != argc {
            return Err(VMError::ParseErrorString {
                line: line_no + 1,
                offset: tokens[0].offset,
                length: tokens[0].text.len(),
                message: if argc == 1 {
                    format!(
                        "host function '{}' expects {} argument, but 1 was provided",
                        *name, *func_argc
                    )
                } else {
                    format!(
                        "host function '{}' expects {} argument, but {} were provided",
                        *name, *func_argc, argc
                    )
                },
            });
        }
    }
    Ok(())
}

/// Extracts the argument count from a call instruction token by matching against the
/// zero-arg, one-arg, and n-arg instruction variants.
fn extract_argc(
    tokens: &[Token],
    line_no: usize,
    instr_0: Instruction,
    instr_1: Instruction,
    instr_n: Instruction,
) -> Result<u8, VMError> {
    Ok(match tokens[0] {
        Token { text, .. } if text == instr_0.mnemonic() => 0,
        Token { text, .. } if text == instr_1.mnemonic() => 1,
        Token { text, .. } if text == instr_n.mnemonic() => {
            parse_u8_or_hex(tokens[3].text, line_no + 1, tokens[3].offset)?
        }
        _ => 0,
    })
}

/// Performs two-pass assembly on preprocessed source.
///
/// Pass 1: Tokenizes all lines, classifies lines into init/runtime using `__init__`,
/// computes instruction sizes, and records label positions as global offsets in the
/// concatenated address space (init || runtime).
///
/// Pass 2: Parses instructions with label resolution and emits bytecode.
///
/// Collects all errors into the provided vector and continues processing where possible.
fn assemble_source_step_2(
    source: String,
    label_data: Vec<Label>,
    errors: &mut Vec<VMError>,
) -> Option<DeployProgram> {
    let mut asm_context = AsmContext::new();

    // First pass: tokenize all lines, detect sections, compute global offsets
    // We track (line_no, tokens, section) for each instruction line
    let mut parsed_lines: Vec<(usize, Vec<Token>, Section)> = Vec::new();
    let mut current_section = Section::Runtime;
    let mut saw_runtime_code = false;

    // Track sizes separately for init and runtime sections
    let mut init_size = 0usize;
    let mut runtime_size = 0usize;

    // Temporary label storage: (name, global_offset, line_no, tok_offset)
    // (name, section, local_offset, line_no, tok_offset, tok_len)
    let mut pending_labels: Vec<(String, Section, usize, usize, usize, usize)> = Vec::new();

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

        // Validate CALL and CALL_HOST argc
        match tokens[0] {
            Token { text, .. }
                if text == Instruction::Call0.mnemonic()
                    || text == Instruction::Call1.mnemonic()
                    || text == Instruction::Call.mnemonic() =>
            {
                let argc = match extract_argc(
                    &tokens,
                    line_no,
                    Instruction::Call0,
                    Instruction::Call1,
                    Instruction::Call,
                ) {
                    Ok(n) => n,
                    Err(e) => {
                        errors.push(e);
                        continue;
                    }
                };

                if let Err(e) = check_call_argc(&tokens, &label_data, line_no, argc) {
                    errors.push(e);
                    continue;
                }
            }
            Token { text, .. }
                if text == Instruction::CallHost0.mnemonic()
                    || text == Instruction::CallHost1.mnemonic()
                    || text == Instruction::CallHost.mnemonic() =>
            {
                let argc = match extract_argc(
                    &tokens,
                    line_no,
                    Instruction::CallHost0,
                    Instruction::CallHost1,
                    Instruction::CallHost,
                ) {
                    Ok(n) => n,
                    Err(e) => {
                        errors.push(e);
                        continue;
                    }
                };

                if let Err(e) = check_call_host_argc(&tokens, line_no, argc) {
                    errors.push(e);
                    continue;
                }
            }
            _ => {}
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
            Section::Runtime => init_size + local_offset,
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

/// Assembles source with an associated filename for error diagnostics.
///
/// Runs both assembly passes and logs compiler-style diagnostics to stderr
/// on failure, including source location information for all errors found.
fn assemble_source_with_name(source: String, source_name: &str) -> Result<DeployProgram, VMError> {
    let mut errors = Vec::new();
    let normalized = assemble_source_step_0(&source, &mut errors);
    if normalized.is_none() && !errors.is_empty() {
        log_assembly_errors(source_name, &source, &errors, None);
        return Err(errors.into_iter().next().unwrap());
    }
    let normalized_source = normalized.unwrap_or_else(|| source.clone());

    let (processed, dispatcher_info, label_data) =
        assemble_source_step_1(&normalized_source, &mut errors);
    if processed.is_none() && !errors.is_empty() {
        log_assembly_errors(source_name, &normalized_source, &errors, dispatcher_info);
        // Return the first error with adjusted line number
        let first_err = errors.into_iter().next().unwrap();
        return Err(adjust_error_line(first_err, dispatcher_info));
    }

    let result = assemble_source_step_2(
        processed.unwrap_or_else(|| normalized_source.clone()),
        label_data.unwrap_or_default(),
        &mut errors,
    );
    if !errors.is_empty() {
        log_assembly_errors(source_name, &normalized_source, &errors, dispatcher_info);
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
        assert_eq!(parse_u8_or_hex("0", 0, 0).unwrap(), 0);
        assert_eq!(parse_u8_or_hex("255", 0, 0).unwrap(), 255);
        assert_eq!(parse_u8_or_hex("42", 0, 0).unwrap(), 42);
    }

    #[test]
    fn parse_u8_invalid() {
        assert!(parse_u8_or_hex("256", 0, 0).is_err());
        assert!(parse_u8_or_hex("-1", 0, 0).is_err());
        assert!(parse_u8_or_hex("abc", 0, 0).is_err());
        assert!(parse_u8_or_hex("", 0, 0).is_err());
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
        // CALL: opcode(1) + dst(1) + fn_id(4) + argc(1) + argv(1) = 8 bytes
        let program = assemble_source("my_func(5, r2):\nCALL r0, my_func, 5, r2").unwrap();
        assert_eq!(program.runtime_code[0], Instruction::Call as u8);
        assert_eq!(program.runtime_code[1], 0); // dst = r0
        assert_eq!(program.runtime_code[6], 5); // argc = 5 (single byte)
        assert_eq!(program.runtime_code[7], 2); // argv = r2
        assert_eq!(program.runtime_code.len(), 8);
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
        assert_eq!(program.init_code.len(), 12);
        assert!(program.runtime_code.is_empty());
    }

    #[test]
    fn assemble_runtime_only_label() {
        let source = "main:\nMOVE r0, 42";
        let program = assemble_source(source).unwrap();
        assert!(program.init_code.is_empty());
        assert_eq!(program.runtime_code.len(), 11);
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
        assert_eq!(program.init_code.len(), 23); // 2 MOVE + HALT instructions
        assert_eq!(program.runtime_code.len(), 11); // 1 MOVE instruction
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
        assert_eq!(program.init_code.len(), 12);
        assert!(program.runtime_code.len() >= 11);
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
    fn call0_argc_mismatch() {
        let source = "add(2, r0):\nRET r0\nCALL0 r1, add";
        let err = assemble_source(source).unwrap_err();
        assert!(matches!(err, VMError::ParseErrorString { .. }));
    }

    #[test]
    fn call1_argc_mismatch() {
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
    fn call_host0_argc_mismatch() {
        let source = r#"CALL_HOST0 r0, "len""#;
        let err = assemble_source(source).unwrap_err();
        assert!(matches!(err, VMError::ParseErrorString { .. }));
    }

    #[test]
    fn call_host1_argc_mismatch() {
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
CALL_HOST1 r0, "len", r1"#;
        assert!(assemble_source(source).is_ok());
    }
}
