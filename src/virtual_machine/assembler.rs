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
use crate::virtual_machine::program::DeployProgram;
use std::collections::{HashMap, HashSet};
use std::fmt::Write;
use std::fs;
use std::path::Path;

const COMMENT_CHAR: char = '#';
const LABEL_SUFFIX: char = ':';
const SECTION_INIT: &str = "[ init code ]";
const SECTION_RUNTIME: &str = "[ runtime code ]";

/// Return the line/column/message triple for assembly-related errors.
fn assembly_error_location(err: &VMError) -> Option<(usize, usize, String)> {
    match err {
        VMError::AssemblyError {
            line,
            offset,
            source,
        } => Some((*line, *offset, source.clone())),
        VMError::ParseError {
            line,
            offset,
            message,
        } => Some((*line, *offset, message.to_string())),
        _ => None,
    }
}

/// Formats a compiler-style diagnostic for assembly failures.
fn render_assembly_diagnostic(
    file: &str,
    source: &str,
    line: usize,
    offset: usize,
    message: &str,
) -> String {
    let mut diag = String::new();
    let _ = writeln!(diag, "error: {message}");
    let _ = writeln!(diag, " --> {file}:{line}:{offset}");

    if let Some(raw_line) = source.lines().nth(line.saturating_sub(1)) {
        let line_text = raw_line.trim_end_matches('\r');
        let underline = " ".repeat(offset.saturating_sub(1));
        let _ = writeln!(diag, "  |");
        let _ = writeln!(diag, "{:>4} | {}", line, line_text);
        let _ = writeln!(diag, "  | {}^", underline);
    }

    diag
}

/// Emit a helpful diagnostic to stderr for assembly errors.
fn log_assembly_error(file: &str, source: &str, err: &VMError) {
    if let Some((line, offset, message)) = assembly_error_location(err) {
        eprintln!(
            "{}",
            render_assembly_diagnostic(file, source, line, offset, &message)
        );
    } else {
        eprintln!("error: {err}");
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
    pub fn intern_string(&mut self, s: String) -> u32 {
        let id = self.items.len() as u32;
        self.items.push(s.into_bytes());
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

/// Checks if a token is a label definition (ends with `:`)
fn is_label_def(tok: &str) -> bool {
    tok.ends_with(LABEL_SUFFIX) && tok.len() > 1
}

/// Extracts the label name from a label definition token.
fn label_name(tok: &str) -> &str {
    &tok[..tok.len() - 1]
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
            let offset = current_global_offset + instruction_size(instr);

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

    // ---------- operand sizes ----------
    (@size Reg)    => { 1usize };
    (@size Bool)   => { 1usize };
    (@size RefU32) => { 4usize };
    (@size ImmU8)  => { 1usize };
    (@size ImmI64) => { 8usize };

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

    (@parse_operand Bool, $tok:expr, $ctx:expr, $current_offset:expr) => {
        parse_bool(&$tok.text)
    };
}

for_each_instruction!(define_parse_instruction);

/// Preprocesses assembly source to generate a dispatcher for public entry points.
///
/// Scans the source for labels prefixed with `pub` and generates a jump table
/// (`__resolver_jump_table`) that dispatches to public functions based on a
/// selector in `r0`. The generated dispatcher is inserted at the start of the
/// `[ runtime code ]` section.
fn assemble_source_step_1(source: String) -> Result<String, VMError> {
    // Track where to insert the dispatcher (line number of `[ runtime code ]`)
    let mut insert_point = 0usize;
    // Collect all public label names (including trailing ':')
    let mut public_labels: HashSet<&str> = HashSet::new();

    // First pass: scan source to find public labels and the runtime section marker
    for (line_no, line) in source.lines().enumerate() {
        // Check for section markers first
        if let Some(section) = parse_section_marker(line) {
            if section == Section::Runtime {
                insert_point = line_no;
            }
            continue;
        }

        let tokens = tokenize(line_no + 1, line)?;
        if tokens.is_empty() {
            continue;
        }

        let (is_pub, label_idx) = if tokens[0].text == "pub" && tokens.len() > 1 {
            (true, 1)
        } else {
            (false, 0)
        };

        // Check if this is a public label definition (`pub label_name:`)
        if tokens.len() > label_idx && is_pub && is_label_def(tokens[label_idx].text) {
            public_labels.insert(tokens[label_idx].text);
        }
    }

    if public_labels.is_empty() {
        return Ok(source);
    }

    let mut base = String::new();
    let mut labels: Vec<&str> = public_labels.iter().copied().collect();
    labels.sort();
    let has_multiple = labels.len() > 1;
    if has_multiple {
        // Jump over the entries while capturing the base address (r252) of
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
        base.push_str("MULI r253, r0, 11\n"); // byte offset into table
        base.push_str("ADD r253, r253, r254\n"); // absolute addr of target entry
        base.push_str("JALR r255, r253, 0\n");
        base.push_str("HALT\n");
    }

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

    Ok(out)
}

/// Performs two-pass assembly on preprocessed source.
///
/// Pass 1: Tokenizes all lines, detects `[ init code ]` / `[ runtime code ]` sections,
/// computes instruction sizes, and records label positions as global offsets in the
/// concatenated address space (init || runtime).
///
/// Pass 2: Parses instructions with label resolution and emits bytecode.
fn assemble_source_step_2(source: String) -> Result<DeployProgram, VMError> {
    let mut asm_context = AsmContext::new();

    // First pass: tokenize all lines, detect sections, compute global offsets
    // We track (line_no, tokens, section) for each instruction line
    let mut parsed_lines: Vec<(usize, Vec<Token>, Section)> = Vec::new();
    let mut current_section = Section::None;

    // Track sizes separately for init and runtime sections
    let mut init_size = 0usize;
    let mut runtime_size = 0usize;

    // Temporary label storage: (name, global_offset, line_no, tok_offset)
    let mut pending_labels: Vec<(String, Section, usize, usize, usize)> = Vec::new();

    for (line_no, line) in source.lines().enumerate() {
        // Check for section markers first
        if let Some(section) = parse_section_marker(line) {
            current_section = section;
            continue;
        }

        let tokens = tokenize(line_no + 1, line)?;
        if tokens.is_empty() {
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

        // Detect pub prefix and label position
        let label_idx = if tokens[0].text == "pub" && tokens.len() > 1 {
            1
        } else {
            0
        };

        // Check if first token is a label definition
        if tokens.len() > label_idx && is_label_def(tokens[label_idx].text) {
            let name = label_name(tokens[label_idx].text).to_string();
            pending_labels.push((
                name,
                effective_section,
                *local_offset,
                line_no + 1,
                tokens[0].offset,
            ));

            // If there are more tokens after the label, treat them as an instruction
            let instr_start = label_idx + 1;
            if tokens.len() > instr_start {
                let instr_tokens: Vec<Token> = tokens[instr_start..].to_vec();
                let instr = instruction_from_str(instr_tokens[0].text).map_err(|e| {
                    VMError::AssemblyError {
                        line: line_no + 1,
                        offset: instr_tokens[0].offset,
                        source: e.to_string(),
                    }
                })?;
                *local_offset += instruction_size(instr);
                parsed_lines.push((line_no, instr_tokens, effective_section));
            }
        } else {
            let instr =
                instruction_from_str(tokens[0].text).map_err(|e| VMError::AssemblyError {
                    line: line_no + 1,
                    offset: tokens[0].offset,
                    source: e.to_string(),
                })?;
            *local_offset += instruction_size(instr);
            parsed_lines.push((line_no, tokens, effective_section));
        }
    }

    // Register labels with global offsets (init || runtime address space).
    for (name, section, local_offset, line_no, tok_offset) in pending_labels {
        let global_offset = match section {
            Section::Init => local_offset,
            Section::Runtime | Section::None => init_size + local_offset,
        };
        asm_context
            .define_label(name, global_offset)
            .map_err(|e| VMError::AssemblyError {
                line: line_no,
                offset: tok_offset,
                source: e.to_string(),
            })?;
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

        let instr = parse_instruction(&mut asm_context, &tokens, global_offset).map_err(|e| {
            VMError::AssemblyError {
                line: line_no + 1,
                offset: tokens.first().map(|t| t.offset).unwrap_or(1),
                source: e.to_string(),
            }
        })?;
        instr.assemble(bytecode);
    }

    Ok(DeployProgram {
        init_code: init_bytecode,
        runtime_code: runtime_bytecode,
        items: asm_context.items,
    })
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
/// Runs both assembly passes and logs a compiler-style diagnostic to stderr
/// on failure, including source location information.
fn assemble_source_with_name(source: String, source_name: &str) -> Result<DeployProgram, VMError> {
    let mut processed = None;
    let result = (|| {
        let dispatcher = assemble_source_step_1(source.clone())?;
        processed = Some(dispatcher.clone());
        assemble_source_step_2(dispatcher)
    })();

    if let Err(err) = &result {
        let display_source = processed.as_deref().unwrap_or(&source);
        log_assembly_error(source_name, display_source, err);
    }

    result
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
        let source = format!("LOAD_I64 r0, 42 {COMMENT_CHAR} load value");
        let program = assemble_source(source).unwrap();
        assert_eq!(program.runtime_code.len(), 10); // opcode(1) + reg(1) + i64(8)
    }

    #[test]
    fn assemble_single_instruction() {
        let program = assemble_source("LOAD_I64 r0, 42").unwrap();
        assert_eq!(program.runtime_code[0], Instruction::LoadI64 as u8);
        assert_eq!(program.runtime_code[1], 0);
        assert_eq!(
            i64::from_le_bytes(program.runtime_code[2..10].try_into().unwrap()),
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
        assert_eq!(program.runtime_code[0], Instruction::LoadStr as u8);
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
        assert_eq!(program.runtime_code[0], Instruction::LoadBool as u8);
        assert_eq!(program.runtime_code[2], 1);

        let program = assemble_source("LOAD_BOOL r0, false").unwrap();
        assert_eq!(program.runtime_code[0], Instruction::LoadBool as u8);
        assert_eq!(program.runtime_code[2], 0);

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
                text: "LOAD_I64",
                offset: 1,
            },
            Token {
                text: "r5",
                offset: 10,
            },
            Token {
                text: "100",
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

    #[test]
    fn instruction_parse_addi_and_beqi() {
        // ADDI rd, rs, imm
        let tokens = [
            Token {
                text: "ADDI",
                offset: 1,
            },
            Token {
                text: "r1",
                offset: 6,
            },
            Token {
                text: "r2",
                offset: 10,
            },
            Token {
                text: "5",
                offset: 14,
            },
        ];
        let instr = parse_instruction(&mut AsmContext::new(), &tokens, 0).unwrap();
        match instr {
            AsmInstr::AddI { rd, rs, imm } => {
                assert_eq!((rd, rs, imm), (1, 2, 5));
            }
            other => panic!("unexpected instr: {other:?}"),
        }

        // BEQI rs, imm, offset
        let tokens = [
            Token {
                text: "BEQI",
                offset: 1,
            },
            Token {
                text: "r3",
                offset: 6,
            },
            Token {
                text: "0",
                offset: 10,
            },
            Token {
                text: "12",
                offset: 12,
            },
        ];
        let instr = parse_instruction(&mut AsmContext::new(), &tokens, 0).unwrap();
        match instr {
            AsmInstr::BeqI { rs, imm, offset } => {
                assert_eq!((rs, imm, offset), (3, 0, 12));
            }
            other => panic!("unexpected instr: {other:?}"),
        }
    }

    #[test]
    fn asm_instr_assemble_addi_and_orxori() {
        let addi = AsmInstr::AddI {
            rd: 4,
            rs: 5,
            imm: -7,
        };
        let mut out = Vec::new();
        addi.assemble(&mut out);
        assert_eq!(out[0], Instruction::AddI as u8);
        assert_eq!(out[1], 4);
        assert_eq!(out[2], 5);
        assert_eq!(i64::from_le_bytes(out[3..11].try_into().unwrap()), -7);

        let xori = AsmInstr::XorI {
            rd: 1,
            rs: 2,
            imm: 1,
        };
        out.clear();
        xori.assemble(&mut out);
        assert_eq!(out[0], Instruction::XorI as u8);
        assert_eq!(out[1], 1);
        assert_eq!(out[2], 2);
        assert_eq!(i64::from_le_bytes(out[3..11].try_into().unwrap()), 1);
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
        assert_eq!(program.runtime_code[0], Instruction::CallHost as u8);
        assert_eq!(program.runtime_code[1], 0); // dst = r0
        assert_eq!(program.runtime_code[6], 3); // argc = 3 (single byte)
        assert_eq!(program.runtime_code[7], 1); // argv = r1
        assert_eq!(program.runtime_code.len(), 8);
    }

    #[test]
    fn assemble_call_argc_u8() {
        // CALL: opcode(1) + dst(1) + fn_id(4) + argc(1) + argv(1) = 8 bytes
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
        assert_eq!(parse_section_marker("LOAD_I64 r0, 1"), None);
    }

    #[test]
    fn assemble_no_sections_defaults_to_runtime() {
        let program = assemble_source("LOAD_I64 r0, 1").unwrap();
        assert!(program.init_code.is_empty());
        assert!(!program.runtime_code.is_empty());
    }

    #[test]
    fn assemble_init_section_only() {
        let source = "[ init code ]\nLOAD_I64 r0, 42";
        let program = assemble_source(source).unwrap();
        assert_eq!(program.init_code.len(), 10);
        assert!(program.runtime_code.is_empty());
    }

    #[test]
    fn assemble_runtime_section_only() {
        let source = "[ runtime code ]\nLOAD_I64 r0, 42";
        let program = assemble_source(source).unwrap();
        assert!(program.init_code.is_empty());
        assert_eq!(program.runtime_code.len(), 10);
    }

    #[test]
    fn assemble_both_sections() {
        let source = r#"
[ init code ]
LOAD_I64 r0, 1
LOAD_I64 r1, 2

[ runtime code ]
LOAD_I64 r2, 3
"#;
        let program = assemble_source(source).unwrap();
        assert_eq!(program.init_code.len(), 20); // 2 LOAD_I64 instructions
        assert_eq!(program.runtime_code.len(), 10); // 1 LOAD_I64 instruction
    }

    #[test]
    fn assemble_labels_within_sections() {
        let source = r#"
[ init code ]
start: LOAD_I64 r0, 1

[ runtime code ]
func: LOAD_I64 r1, 2
"#;
        let program = assemble_source(source).unwrap();
        assert!(!program.init_code.is_empty());
        assert!(!program.runtime_code.is_empty());
    }

    #[test]
    fn assemble_empty_init_section() {
        let source = "[ init code ]\n[ runtime code ]\nLOAD_I64 r0, 1";
        let program = assemble_source(source).unwrap();
        assert!(program.init_code.is_empty());
        assert_eq!(program.runtime_code.len(), 10);
    }

    #[test]
    fn assemble_strings_across_sections() {
        let source = r#"
[ init code ]
LOAD_STR r0, "init"

[ runtime code ]
LOAD_STR r1, "runtime"
"#;
        let program = assemble_source(source).unwrap();
        assert_eq!(program.items.len(), 2);
        assert_eq!(program.items[0], b"init");
        assert_eq!(program.items[1], b"runtime");
    }
}
