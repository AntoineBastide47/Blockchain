//! Core virtual machine implementation.
//!
//! The VM executes bytecode using a register-based architecture with 256 registers.
//! Register `r0` is hardwired to integer zero (writes are ignored).
//! All arithmetic uses wrapping semantics to prevent overflow panics.

use crate::error;
use crate::types::encoding::{Encode, EncodeSink};
use crate::types::hash::{HASH_LEN, Hash};
use crate::utils::log::SHOW_TYPE;
use crate::virtual_machine::assembler::parse_i64;
use crate::virtual_machine::errors::VMError;
use crate::virtual_machine::isa::{Instruction, OPCODE_METADATA_FLAG};
use crate::virtual_machine::operand::{
    AddrMetadataState, AddrOperand, SrcMetadataState, SrcOperand, decode_i32_compact,
    decode_i32_compact_unchecked, decode_i64_compact, decode_i64_compact_unchecked,
    decode_u32_compact, decode_u32_compact_unchecked, metadata_concat_flag,
    metadata_consume_addr_state, metadata_consume_addr_state_unchecked,
    metadata_consume_imm_i32_state, metadata_consume_imm_i32_state_unchecked,
    metadata_consume_src_state, metadata_consume_src_state_unchecked, metadata_len_from_code,
    metadata_payload_value,
};
use crate::virtual_machine::program::{DeployProgram, ExecuteProgram};
use crate::virtual_machine::state::State;
use std::sync::atomic::Ordering;

mod context;
mod gas;
mod heap;
mod registers;

pub use context::ExecContext;
pub use gas::{BLOCK_GAS_LIMIT, GasCategory, GasProfile};
use heap::Heap;
use registers::Registers;
pub use registers::Value;

/// Size of a VM word in bytes (64-bit).
const WORD_SIZE: usize = 8;
/// Half word size (32-bit) for 32-bit memory loads.
const HALF_WORD_SIZE: usize = WORD_SIZE / 2;
/// Quarter word size (16-bit) for 16-bit memory loads.
const QUARTER_WORD_SIZE: usize = WORD_SIZE / 4;
/// Single byte size for 8-bit memory loads.
const BYTE_SIZE: usize = WORD_SIZE / 8;
/// Number of dispatch entry width codes packed in one byte.
const DISPATCH_WIDTHS_PER_BYTE: usize = 4;

/// Defines host function name constants and a lookup table of `(name, argc)` pairs.
macro_rules! host_functions {
      ($($const_name:ident = $name:literal => $argc:literal),* $(,)?) => {
          $(pub const $const_name: &str = $name;)*
          pub const HOST_FUNCTIONS: &[(&str, u8)] = &[$(($name, $argc)),*];
      };
  }

host_functions! {
    CALLER  = "caller"  => 0,
    LEN     = "len"     => 1,
    CONCAT  = "concat"  => 2,
    COMPARE = "compare" => 2,
    SLICE   = "slice"   => 3,
}

/// Returns the expected argument count for a host function by name.
///
/// # Panics
///
/// Panics if `name` does not match any registered host function.
pub fn host_func_argc(name: &str) -> u8 {
    HOST_FUNCTIONS
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, c)| *c)
        .unwrap()
}

/// Reads `len` bytes from `data` starting at `cursor`, advancing the cursor.
///
/// Returns an error if reading would exceed the data bounds.
fn read_bytes<'a>(
    data: &'a [u8],
    cursor: &mut usize,
    len: usize,
    ip: usize,
) -> Result<&'a [u8], VMError> {
    let deref = *cursor;
    let end = deref + len;
    if end > data.len() {
        return Err(VMError::UnexpectedEndOfBytecode {
            ip,
            requested: len,
            available: data.len().saturating_sub(deref),
        });
    }
    let slice = &data[deref..end];
    *cursor = end;
    Ok(slice)
}

/// Reads a single byte from `data` at `cursor`, advancing the cursor.
fn read_u8(data: &[u8], cursor: &mut usize, ip: usize) -> Result<u8, VMError> {
    let deref = *cursor;
    if deref >= data.len() {
        return Err(VMError::UnexpectedEndOfBytecode {
            ip,
            requested: 1,
            available: data.len().saturating_sub(deref),
        });
    }
    *cursor += 1;
    Ok(data[deref])
}

/// Reads `len` bytes from `data` starting at `cursor` without bounds checking.
///
/// # Safety
///
/// The caller must guarantee that `data[*cursor..*cursor + len]` is in bounds.
#[inline(always)]
unsafe fn read_bytes_unchecked<'a>(data: &'a [u8], cursor: &mut usize, len: usize) -> &'a [u8] {
    let start = *cursor;
    *cursor = start + len;
    unsafe { data.get_unchecked(start..start + len) }
}

/// Returns the number of packed width bytes for a DISPATCH table.
fn dispatch_width_table_len(entry_count: usize) -> usize {
    entry_count.div_ceil(DISPATCH_WIDTHS_PER_BYTE)
}

/// Returns one 2-bit width code from packed DISPATCH width bytes.
fn dispatch_width_code_at(width_table: &[u8], entry_index: usize) -> Result<u8, VMError> {
    let packed_index = entry_index / DISPATCH_WIDTHS_PER_BYTE;
    let packed = *width_table
        .get(packed_index)
        .ok_or_else(|| VMError::DecodeError {
            reason: format!("dispatch width table missing entry {}", entry_index),
        })?;
    let shift = 6 - ((entry_index % DISPATCH_WIDTHS_PER_BYTE) as u8 * 2);
    Ok((packed >> shift) & 0b11)
}

/// Returns true when the instruction uses compact concat form.
fn metadata_concat_for_instruction(metadata: Option<u8>, instr: Instruction) -> bool {
    instr.supports_concat_compact() && metadata.is_some_and(metadata_concat_flag)
}

/// Decodes a [`SrcOperand`] from the bytecode stream using metadata encoding.
///
/// Used by the debug instruction decoder (non-hot path). Retains full validation.
fn decode_src_operand_from_stream(
    data: &[u8],
    cursor: &mut usize,
    instr_offset: usize,
    metadata_cursor: &mut u16,
) -> Result<SrcOperand, VMError> {
    let state = metadata_consume_src_state(metadata_cursor)?;
    match state {
        SrcMetadataState::Reg => Ok(SrcOperand::Reg(read_u8(data, cursor, instr_offset)?)),
        SrcMetadataState::I64Len1
        | SrcMetadataState::I64Len2
        | SrcMetadataState::I64Len4
        | SrcMetadataState::I64Len8 => {
            let len = state.i64_len().unwrap() as usize;
            let payload = read_bytes(data, cursor, len, instr_offset)?;
            let value = decode_i64_compact(payload, len as u8)?;
            if matches!(state, SrcMetadataState::I64Len1) && (value == 0 || value == 1) {
                Ok(SrcOperand::Bool(value != 0))
            } else {
                Ok(SrcOperand::I64(value))
            }
        }
        _ => {
            let len = state
                .ref_len()
                .expect("Src ref metadata state must include len");
            let payload = read_bytes(data, cursor, len as usize, instr_offset)?;
            let value = decode_u32_compact(payload, len)?;
            Ok(SrcOperand::Ref(value))
        }
    }
}

/// Decodes a [`SrcOperand`] from the bytecode stream without validation.
///
/// # Safety
///
/// The bytecode must be well-formed (produced by the assembler). The caller must
/// guarantee that all reads within `data[*cursor..]` are in bounds.
#[inline(always)]
unsafe fn decode_src_operand_from_stream_unchecked(
    data: &[u8],
    cursor: &mut usize,
    instr_offset: usize,
    metadata_cursor: &mut u16,
) -> Result<SrcOperand, VMError> {
    let state = unsafe { metadata_consume_src_state_unchecked(metadata_cursor) };
    let len = state.payload_len();
    if *cursor + len > data.len() {
        return Err(VMError::UnexpectedEndOfBytecode {
            ip: instr_offset,
            requested: len,
            available: data.len().saturating_sub(*cursor),
        });
    }
    Ok(match state {
        SrcMetadataState::Reg => {
            let reg = unsafe { *data.get_unchecked(*cursor) };
            *cursor += 1;
            SrcOperand::Reg(reg)
        }
        SrcMetadataState::I64Len1
        | SrcMetadataState::I64Len2
        | SrcMetadataState::I64Len4
        | SrcMetadataState::I64Len8 => {
            let byte_len = unsafe { state.i64_len().unwrap_unchecked() };
            let payload = unsafe { read_bytes_unchecked(data, cursor, byte_len as usize) };
            let value = unsafe { decode_i64_compact_unchecked(payload, byte_len) };
            if matches!(state, SrcMetadataState::I64Len1) && (value == 0 || value == 1) {
                SrcOperand::Bool(value != 0)
            } else {
                SrcOperand::I64(value)
            }
        }
        _ => {
            let byte_len = unsafe { state.ref_len().unwrap_unchecked() };
            let payload = unsafe { read_bytes_unchecked(data, cursor, byte_len as usize) };
            let value = unsafe { decode_u32_compact_unchecked(payload, byte_len) };
            SrcOperand::Ref(value)
        }
    })
}

/// Decodes an [`AddrOperand`] from the bytecode stream using metadata encoding.
///
/// Used by the debug instruction decoder (non-hot path). Retains full validation.
fn decode_addr_operand_from_stream(
    data: &[u8],
    cursor: &mut usize,
    instr_offset: usize,
    metadata_cursor: &mut u16,
) -> Result<AddrOperand, VMError> {
    let state = metadata_consume_addr_state(metadata_cursor)?;
    match state {
        AddrMetadataState::Reg => Ok(AddrOperand::Reg(read_u8(data, cursor, instr_offset)?)),
        _ => {
            let len = state
                .u32_len()
                .expect("Addr u32 metadata state must include len");
            let payload = read_bytes(data, cursor, len as usize, instr_offset)?;
            let value = decode_u32_compact(payload, len)?;
            Ok(AddrOperand::U32(value))
        }
    }
}

/// Decodes an [`AddrOperand`] from the bytecode stream without validation.
///
/// # Safety
///
/// The bytecode must be well-formed (produced by the assembler). The caller must
/// guarantee that all reads within `data[*cursor..]` are in bounds.
#[inline(always)]
unsafe fn decode_addr_operand_from_stream_unchecked(
    data: &[u8],
    cursor: &mut usize,
    instr_offset: usize,
    metadata_cursor: &mut u16,
) -> Result<AddrOperand, VMError> {
    let state = unsafe { metadata_consume_addr_state_unchecked(metadata_cursor) };
    let len = state.payload_len();
    if *cursor + len > data.len() {
        return Err(VMError::UnexpectedEndOfBytecode {
            ip: instr_offset,
            requested: len,
            available: data.len().saturating_sub(*cursor),
        });
    }
    Ok(match state {
        AddrMetadataState::Reg => {
            let reg = unsafe { *data.get_unchecked(*cursor) };
            *cursor += 1;
            AddrOperand::Reg(reg)
        }
        _ => {
            let byte_len = unsafe { state.u32_len().unwrap_unchecked() };
            let payload = unsafe { read_bytes_unchecked(data, cursor, byte_len as usize) };
            let value = unsafe { decode_u32_compact_unchecked(payload, byte_len) };
            AddrOperand::U32(value)
        }
    })
}

/// Decodes a compact [`i32`] immediate from the bytecode stream using metadata encoding.
///
/// Used by the debug instruction decoder (non-hot path). Retains full validation.
fn decode_i32_operand_from_stream(
    data: &[u8],
    cursor: &mut usize,
    instr_offset: usize,
    metadata_cursor: &mut u16,
) -> Result<i32, VMError> {
    let state = metadata_consume_imm_i32_state(metadata_cursor)?;
    let len = state.payload_len();
    let payload = read_bytes(data, cursor, len, instr_offset)?;
    decode_i32_compact(payload, len as u8)
}

/// Decodes a compact [`i32`] immediate from the bytecode stream without validation.
///
/// # Safety
///
/// The bytecode must be well-formed (produced by the assembler). The caller must
/// guarantee that all reads within `data[*cursor..]` are in bounds.
#[inline(always)]
unsafe fn decode_i32_operand_from_stream_unchecked(
    data: &[u8],
    cursor: &mut usize,
    instr_offset: usize,
    metadata_cursor: &mut u16,
) -> Result<i32, VMError> {
    let state = unsafe { metadata_consume_imm_i32_state_unchecked(metadata_cursor) };
    let len = state.payload_len();
    if *cursor + len > data.len() {
        return Err(VMError::UnexpectedEndOfBytecode {
            ip: instr_offset,
            requested: len,
            available: data.len().saturating_sub(*cursor),
        });
    }
    let payload = unsafe { read_bytes_unchecked(data, cursor, len) };
    Ok(unsafe { decode_i32_compact_unchecked(payload, len as u8) })
}

/// Decodes a compact [`u32`] reference from the bytecode stream using metadata encoding.
///
/// Used by the debug instruction decoder (non-hot path). Retains full validation.
fn decode_ref_u32_operand_from_stream(
    data: &[u8],
    cursor: &mut usize,
    instr_offset: usize,
    metadata_cursor: &mut u16,
) -> Result<u32, VMError> {
    let state = metadata_consume_imm_i32_state(metadata_cursor)?;
    let len = state.payload_len();
    let payload = read_bytes(data, cursor, len, instr_offset)?;
    decode_u32_compact(payload, len as u8)
}

/// Decodes a compact [`u32`] reference from the bytecode stream without validation.
///
/// # Safety
///
/// The bytecode must be well-formed (produced by the assembler). The caller must
/// guarantee that all reads within `data[*cursor..]` are in bounds.
#[inline(always)]
unsafe fn decode_ref_u32_operand_from_stream_unchecked(
    data: &[u8],
    cursor: &mut usize,
    instr_offset: usize,
    metadata_cursor: &mut u16,
) -> Result<u32, VMError> {
    let state = unsafe { metadata_consume_imm_i32_state_unchecked(metadata_cursor) };
    let len = state.payload_len();
    if *cursor + len > data.len() {
        return Err(VMError::UnexpectedEndOfBytecode {
            ip: instr_offset,
            requested: len,
            available: data.len().saturating_sub(*cursor),
        });
    }
    let payload = unsafe { read_bytes_unchecked(data, cursor, len) };
    Ok(unsafe { decode_u32_compact_unchecked(payload, len as u8) })
}

macro_rules! define_instruction_decoder {
    (
        $(
            $(#[$doc:meta])*
            $name:ident = $opcode:expr, $mnemonic:literal => [
                $( $field:ident : $kind:ident ),* $(,)?
            ], $gas:expr
        ),* $(,)?
    ) => {
        fn decode_instruction_at(data: &[u8], start: usize) -> Result<(String, usize), VMError> {
            if start >= data.len() {
                return Err(VMError::UnexpectedEndOfBytecode {
                    ip: start,
                    requested: 1,
                    available: 0,
                });
            }

            let opcode = data[start];
            let (instr, has_metadata) = Instruction::decode_opcode(opcode)?;
            let mut cursor = start + 1;
            let metadata = if has_metadata {
                Some(read_u8(data, &mut cursor, start)?)
            } else {
                None
            };
            let concat = metadata_concat_for_instruction(metadata, instr);
            let mut metadata_cursor = metadata.map_or(0u16, |value| {
                metadata_payload_value(value, instr.supports_concat_compact())
            });

            let text = match instr {
                $(
                    Instruction::$name => {
                        define_instruction_decoder!(
                            @decode data, cursor, start, metadata_cursor, concat, $mnemonic;
                            $( $kind ),*
                        )?
                    }
                ),*
                Instruction::Dispatch => {
                    let count = read_u8(data, &mut cursor, start)?;
                    let width_table_len = dispatch_width_table_len(count as usize);
                    let width_table = read_bytes(data, &mut cursor, width_table_len, start)?;
                    let mut parts = Vec::new();
                    parts.push(count.to_string());
                    for entry_index in 0..count as usize {
                        let width_code = dispatch_width_code_at(width_table, entry_index)?;
                        let offset_len = metadata_len_from_code(width_code) as usize;
                        let bytes = read_bytes(data, &mut cursor, offset_len, start)?;
                        let offset = decode_i64_compact(bytes, offset_len as u8)?;
                        let argr = read_u8(data, &mut cursor, start)?;
                        parts.push(offset.to_string());
                        parts.push(format!("r{}", argr));
                    }
                    format!("DISPATCH {}", parts.join(", "))
                }
            };

            Ok((text, cursor - start))
        }
    };

    (@decode $data:ident, $cursor:ident, $start:ident, $metadata_cursor:ident, $concat:expr, $mnemonic:expr; ) => {
        Ok::<_, VMError>($mnemonic.to_string())
    };

    (@decode $data:ident, $cursor:ident, $start:ident, $metadata_cursor:ident, $concat:expr, $mnemonic:expr; Reg, Src, Src ) => {{
        let mut parts = Vec::new();
        let rd = define_instruction_decoder!(@read $data, $cursor, $start, $metadata_cursor, Reg)?;
        parts.push(rd);
        if !$concat {
            let rs1 = define_instruction_decoder!(@read $data, $cursor, $start, $metadata_cursor, Src)?;
            parts.push(rs1);
        } else {
            let _ = metadata_consume_src_state(&mut $metadata_cursor)?;
        }
        let rs2 = define_instruction_decoder!(@read $data, $cursor, $start, $metadata_cursor, Src)?;
        parts.push(rs2);
        Ok::<_, VMError>(format!("{} {}", $mnemonic, parts.join(", ")))
    }};

    (@decode $data:ident, $cursor:ident, $start:ident, $metadata_cursor:ident, $concat:expr, $mnemonic:expr; $( $kind:ident ),+ ) => {{
        let mut parts = Vec::new();
        $(
            let val = define_instruction_decoder!(@read $data, $cursor, $start, $metadata_cursor, $kind)?;
            parts.push(val);
        )*
        let _ = $concat;
        Ok::<_, VMError>(format!("{} {}", $mnemonic, parts.join(", ")))
    }};

    (@read $data:ident, $cursor:ident, $start:ident, $metadata_cursor:ident, Reg) => {{
        let _ = &mut $metadata_cursor;
        let v = read_u8($data, &mut $cursor, $start)?;
        Ok::<String, VMError>(format!("r{}", v))
    }};

    (@read $data:ident, $cursor:ident, $start:ident, $metadata_cursor:ident, ImmU8) => {{
        let _ = &mut $metadata_cursor;
        let v = read_u8($data, &mut $cursor, $start)?;
        Ok::<String, VMError>(v.to_string())
    }};

    (@read $data:ident, $cursor:ident, $start:ident, $metadata_cursor:ident, RefU32) => {{
        let value = decode_ref_u32_operand_from_stream(
            $data,
            &mut $cursor,
            $start,
            &mut $metadata_cursor,
        )?;
        Ok::<String, VMError>(format!("@{}", value))
    }};

    (@read $data:ident, $cursor:ident, $start:ident, $metadata_cursor:ident, ImmI32) => {{
        let value =
            decode_i32_operand_from_stream($data, &mut $cursor, $start, &mut $metadata_cursor)?;
        Ok::<String, VMError>(value.to_string())
    }};

    (@read $data:ident, $cursor:ident, $start:ident, $metadata_cursor:ident, ImmU32) => {{
        let _ = &mut $metadata_cursor;
        let bytes = read_bytes($data, &mut $cursor, 4, $start)?;
        Ok::<String, VMError>(u32::from_le_bytes(bytes.try_into().unwrap()).to_string())
    }};

    (@read $data:ident, $cursor:ident, $start:ident, $metadata_cursor:ident, ImmI64) => {{
        let _ = &mut $metadata_cursor;
        let bytes = read_bytes($data, &mut $cursor, 8, $start)?;
        Ok::<String, VMError>(i64::from_le_bytes(bytes.try_into().unwrap()).to_string())
    }};

    (@read $data:ident, $cursor:ident, $start:ident, $metadata_cursor:ident, Addr) => {{
      let operand = decode_addr_operand_from_stream(
          $data,
          &mut $cursor,
          $start,
          &mut $metadata_cursor,
      )?;
      Ok::<String, VMError>(match operand {
          AddrOperand::Reg(r) => format!("r{}", r),
          AddrOperand::U32(v) => v.to_string(),
      })
    }};

    (@read $data:ident, $cursor:ident, $start:ident, $metadata_cursor:ident, Src) => {{
      let operand = decode_src_operand_from_stream(
          $data,
          &mut $cursor,
          $start,
          &mut $metadata_cursor,
      )?;
      Ok::<String, VMError>(match operand {
          SrcOperand::Reg(r) => format!("r{}", r),
          SrcOperand::I64(i) => i.to_string(),
          SrcOperand::Ref(r) => format!("@{}", r),
          SrcOperand::Bool(b) => if b { "true".to_string() } else { "false".to_string() },
      })
    }};
}

crate::for_each_instruction!(define_instruction_decoder);

/// Maximum depth of the call stack to prevent unbounded recursion.
const MAX_CALL_STACK_LEN: usize = 1024;
/// Gas cost per byte when writing to state storage.
const STORE_BYTE_COST: u64 = 10;
/// Gas cost per byte when reading from state storage.
const READ_BYTE_COST: u64 = 5;

macro_rules! exec_vm {
    // Entry point: gas cost is derived from the variant's const base_gas().
    (
        vm = $vm:ident,
        state = $state:ident,
        ctx = $ctx:ident,
        instr = $instr:ident,
        { $( $variant:ident => $handler:ident $args:tt ),* $(,)? }
    ) => {{
        match $instr {
            $(
                Instruction::$variant => {
                    $vm.charge_opcode_gas(Instruction::$variant.base_gas())?;
                    exec_vm!(@call $vm, $state, $ctx, $instr, $handler, $args)
                }
            ),*
        }
    }};

    // Handler with storage and chain_id (semicolon separator)
    (@call $vm:ident, $state:ident, $ctx:ident, $instr:expr, $handler:ident,
        (state, ctx; $( $field:ident : $kind:ident ),* $(,)? )
    ) => {{
        $( let $field = exec_vm!(@read $vm, $kind)?; )*
        $vm.$handler($instr, $state, $ctx, $( $field ),*)
    }};

    // Compact concat form: when metadata A=1, rs1 is omitted and equals rd.
    (@call $vm:ident, $state:ident, $ctx:ident, $instr:expr, $handler:ident,
        (rd: Reg, rs1: Src, rs2: Src $(,)? )
    ) => {{
        let rd = exec_vm!(@read $vm, Reg)?;
        let rs1 = if $vm.operand_concat_flag() {
            $vm.consume_concat_src_slot();
            SrcOperand::Reg(rd)
        } else {
            exec_vm!(@read $vm, Src)?
        };
        let rs2 = exec_vm!(@read $vm, Src)?;
        $vm.$handler($instr, rd, rs1, rs2)
    }};

    // Handler without storage (no semicolon)
    (@call $vm:ident, $state:ident, $ctx:ident, $instr:expr, $handler:ident,
        ( $( $field:ident : $kind:ident ),* $(,)? )
    ) => {{
        $( let $field = exec_vm!(@read $vm, $kind)?; )*
        $vm.$handler($instr, $( $field ),*)
    }};

    // Decode a u8 register index
    (@read $vm:ident, Reg) => {{
        $vm.read_u8_operand()
    }};

    // Decode a u8 immediate (1 byte)
    (@read $vm:ident, ImmU8) => {{
        $vm.read_u8_operand()
    }};

    // Decode an i32 immediate (compact width from metadata)
    (@read $vm:ident, ImmI32) => {{
        $vm.read_imm_i32()
    }};

    // Decode an u32 immediate (little-endian, 4 bytes)
    (@read $vm:ident, ImmU32) => {{
        let bytes = $vm.read_exact(4)?;
        Ok::<u32, VMError>(u32::from_le_bytes(bytes.try_into().unwrap()))
    }};

    // Decode an i64 immediate (little-endian, 8 bytes)
    (@read $vm:ident, ImmI64) => {{
        let bytes = $vm.read_exact(8)?;
        Ok::<i64, VMError>(i64::from_le_bytes(bytes.try_into().unwrap()))
    }};

    // Decode a compact u32 reference (metadata-selected width).
    (@read $vm:ident, RefU32) => {{
        $vm.read_ref_u32()
    }};

    // Decode a u32 (little-endian, 4 bytes)
    (@read $vm:ident, Addr) => {{
        $vm.read_addr_operand()
    }};

    // Decode a bool (1 byte, 0 = false, nonzero = true)
    (@read $vm:ident, Src) => {{
        $vm.read_src_operand()
    }};

    // -----------------------------------------------------------------------
    // Table dispatch: generates one handler fn per variant + a [fn; 128] table.
    // -----------------------------------------------------------------------

    // Entry point: builds the dispatch table inside a generic context.
    // $S is the State type parameter from the enclosing generic function.
    (
        @table $S:ident,
        { $( $variant:ident => $handler:ident $args:tt ),* $(,)? }
    ) => {{
        use crate::virtual_machine::isa::{Instruction, OPCODE_BASE_MASK};

        type Handler<$S> = fn(&mut VM, &mut $S, &ExecContext) -> Result<(), VMError>;

        #[cold]
        fn invalid_opcode<$S: State>(
            vm: &mut VM, _: &mut $S, _: &ExecContext,
        ) -> Result<(), VMError> {
            Err(VMError::InvalidInstruction { opcode: 0xFF, offset: vm.instr_offset })
        }

        $(
            #[allow(non_snake_case, unused_variables)]
            fn $variant<$S: State>(
                vm: &mut VM, state: &mut $S, ctx: &ExecContext,
            ) -> Result<(), VMError> {
                vm.charge_opcode_gas(Instruction::$variant.base_gas())?;
                exec_vm!(@table_call vm, state, ctx, Instruction::$variant, $handler, $args)
            }
        )*

        let mut table: [Handler<$S>; 128] = [invalid_opcode::<$S>; 128];
        $(
            table[(Instruction::$variant as u8 & OPCODE_BASE_MASK) as usize] = $variant::<$S>;
        )*
        table
    }};

    // Table call variants — mirror the @call rules but for standalone fns.

    (@table_call $vm:ident, $state:ident, $ctx:ident, $instr:expr, $handler:ident,
        (state, ctx; $( $field:ident : $kind:ident ),* $(,)? )
    ) => {{
        $( let $field = exec_vm!(@read $vm, $kind)?; )*
        $vm.$handler($instr, $state, $ctx, $( $field ),*)
    }};

    (@table_call $vm:ident, $state:ident, $ctx:ident, $instr:expr, $handler:ident,
        (rd: Reg, rs1: Src, rs2: Src $(,)? )
    ) => {{
        let rd = exec_vm!(@read $vm, Reg)?;
        let rs1 = if $vm.operand_concat_flag() {
            $vm.consume_concat_src_slot();
            SrcOperand::Reg(rd)
        } else {
            exec_vm!(@read $vm, Src)?
        };
        let rs2 = exec_vm!(@read $vm, Src)?;
        $vm.$handler($instr, rd, rs1, rs2)
    }};

    (@table_call $vm:ident, $state:ident, $ctx:ident, $instr:expr, $handler:ident,
        ( $( $field:ident : $kind:ident ),* $(,)? )
    ) => {{
        $( let $field = exec_vm!(@read $vm, $kind)?; )*
        $vm.$handler($instr, $( $field ),*)
    }};
}

///
/// Executes compiled bytecode sequentially, reading instructions from the
/// instruction pointer until the end of the bytecode is reached.
///
/// The VM stores concatenated init_code + runtime_code. During deployment,
/// execution starts at ip=0 (init_code). For runtime calls, execution starts
/// at ip=init_size (runtime_code). This allows init_code to call into runtime_code.
///
/// # TODO potential before 1.0.0:
/// 1) 🔴 Add a deterministic optimizer do make the assembly code more performant
///
/// # TODO after 1.0.0:
/// 1) 🔴 Add a smart contract language to not require assembly written smart contracts
/// 2) 🔴 Add list and map support
/// 3) 🔴 Add a deterministic compiler to convert the language to assembly
/// 4) 🔴 Add an LSP for smoother smart contract writing experience
pub struct VM {
    /// Concatenated bytecode (init_code + runtime_code).
    data: Vec<u8>,
    /// Instruction pointer (current position in bytecode).
    ip: usize,
    /// Start offset of the currently executing instruction (for error reporting).
    instr_offset: usize,
    /// Per-instruction metadata byte read when opcode Z flag is set.
    operand_metadata: Option<u8>,
    /// Mixed-radix metadata cursor for dynamic Src/Addr decoding.
    operand_metadata_cursor: u16,
    /// Register file (256 registers).
    registers: Registers,
    /// Heap for const and execution memory.
    heap: Heap,
    /// Call stack storing return addresses for function calls.
    call_stack: Vec<usize>,
    /// Total gas consumed during execution.
    gas_used: u64,
    /// Maximum gas allowed for this execution; exceeding it triggers `OutOfGas`.
    max_gas: u64,
    /// Gas consumption breakdown by category.
    gas_profile: GasProfile,
    /// Arguments passed to the program, loaded into registers by `CALLDATA_LOAD`.
    args: Vec<Value>,
    /// Root dispatcher selector for runtime entry.
    dispatch_selector: i64,
    /// The data returned by the VM's execution
    return_data: Vec<u8>,
}

/// impl block for basic VM functions
impl VM {
    /// Creates a VM for deploying a contract.
    ///
    /// Concatenates init_code + runtime_code for execution. Use [`run`](Self::run)
    /// to execute from ip=0. For runtime calls, use [`new_execute`](Self::new_execute).
    ///
    /// Returns `OutOfGas` if the base deployment cost exceeds `max_gas`.
    pub fn new_deploy(
        program: DeployProgram,
        max_gas: u64,
        constructor_args: Vec<Value>,
        constructor_items: Vec<Vec<u8>>,
    ) -> Result<Self, VMError> {
        let init_size = program.init_code.len();
        let total_bytes = init_size + program.runtime_code.len();

        // Concatenate init_code + runtime_code
        let mut data = program.init_code;
        data.extend(program.runtime_code);

        let mut heap = Heap::new(program.memory);
        let ref_offsets: Vec<u32> = constructor_items
            .into_iter()
            .map(|item| heap.append(item))
            .collect();

        let args: Vec<Value> = constructor_args
            .into_iter()
            .map(|arg| match arg {
                Value::Ref(r) => Value::Ref(ref_offsets[r as usize]),
                other => other,
            })
            .collect();

        let mut vm = Self {
            data,
            ip: 0,
            instr_offset: 0,
            operand_metadata: None,
            operand_metadata_cursor: 0,
            registers: Registers::new(),
            heap,
            call_stack: Vec::new(),
            gas_used: 0,
            max_gas,
            gas_profile: GasProfile::new(),
            args,
            dispatch_selector: 0,
            return_data: Vec::new(),
        };

        vm.charge_gas_categorized(20_000 + total_bytes as u64 * 200, GasCategory::Deploy)?;
        Ok(vm)
    }

    /// Creates a VM for executing a function call on a deployed contract.
    ///
    /// Stores the function selector for `DISPATCH` and prepares call arguments.
    /// Heap items from the stored contract and any argument refs are merged so
    /// `Value::Ref` indices resolve correctly.
    pub fn new_execute(
        execute: ExecuteProgram,
        deploy: DeployProgram,
        max_gas: u64,
    ) -> Result<Self, VMError> {
        // Build a VM for runtime execution, seeding registers with typed args and extending
        // the heap with any argument-owned items referenced via Value::Ref.
        // Labels are resolved as PC-relative offsets, so init_size is not needed.
        let mut heap = Heap::new(deploy.memory);
        let ref_offsets: Vec<u32> = execute
            .arg_items
            .into_iter()
            .map(|item| heap.append(item))
            .collect();

        // Remap refs from sequential indices to actual heap byte offsets
        let args: Vec<Value> = execute
            .args
            .into_iter()
            .map(|arg| match arg {
                Value::Ref(r) => Value::Ref(ref_offsets[r as usize]),
                other => other,
            })
            .collect();

        let vm = Self {
            data: deploy.runtime_code,
            ip: 0,
            instr_offset: 0,
            operand_metadata: None,
            operand_metadata_cursor: 0,
            registers: Registers::new(),
            heap,
            call_stack: Vec::new(),
            gas_used: 0,
            max_gas,
            gas_profile: GasProfile::new(),
            args,
            dispatch_selector: execute.function_id,
            return_data: Vec::new(),
        };
        Ok(vm)
    }

    /// Serializes call arguments into raw calldata bytes.
    ///
    /// `Bool` and `Int` values are encoded using the VM's `Encode` format.
    /// `Ref` values are expanded into their heap bytes (or empty if missing),
    /// matching the layout expected by `CALLDATA_COPY` and `CALLDATA_LEN`.
    fn args_to_vec(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        for arg in &self.args {
            match arg {
                Value::Bool(b) => b.encode(&mut buf),
                Value::Int(i) => i.encode(&mut buf),
                Value::Ref(r) => buf.write(self.heap.get_raw_ref(*r).unwrap_or(&[])),
            }
        }
        buf
    }

    /// Formats a runtime error with bytecode context and call stack.
    fn log_runtime_error(&self, err: &VMError) {
        error!("VM runtime failure: {err}");

        if let Some(ip) = self.error_ip(err) {
            eprintln!("   --> bytecode:{ip}");
            self.disassembly_snippet(ip, err);
            self.bytecode_snippet(ip, err);
        }

        eprintln!("note: gas used {} of {}", self.gas_used, self.max_gas);
        if self.call_stack.is_empty() {
            eprintln!("note: call stack is empty");
        } else {
            eprintln!("note: call stack (most recent first):");
            for (depth, return_addr) in self.call_stack.iter().rev().enumerate() {
                eprintln!("  {depth}: return to ip {return_addr}");
            }
        }

        error!("aborting due to previous error");
    }

    /// Returns a hex dump of bytecode around the given instruction pointer.
    fn bytecode_snippet(&self, ip: usize, err: &VMError) {
        if self.data.is_empty() {
            return;
        }

        let window = 8usize;
        let start = ip.saturating_sub(window);
        let end = (ip + window + 1).min(self.data.len());

        let mut rendered = String::new();
        let mut caret_col = 0usize;
        for (idx, byte) in self.data[start..end].iter().enumerate() {
            if idx > 0 {
                rendered.push(' ');
            }
            if start + idx == ip {
                caret_col = rendered.len();
            }
            rendered.push_str(&format!("{:02X}", byte));
        }

        if caret_col == 0 && ip >= end {
            caret_col = rendered.len();
        }

        eprintln!(
            "    | window [{}..{}) of {} bytes",
            start,
            end,
            self.data.len()
        );
        eprintln!("    | {rendered}");
        eprint!("    |");
        SHOW_TYPE.store(false, Ordering::Relaxed);
        error!(" {}^^ {}", " ".repeat(caret_col), err);
        SHOW_TYPE.store(true, Ordering::Relaxed);
    }

    /// Disassembles the entire bytecode into (offset, text, size) tuples.
    fn disassembly_listing(&self) -> Vec<(usize, String, usize)> {
        let mut listing = Vec::new();
        let mut pos = 0usize;
        while pos < self.data.len() {
            match decode_instruction_at(&self.data, pos) {
                Ok((text, size)) => {
                    listing.push((pos, text, size));
                    pos = pos.saturating_add(size.max(1));
                }
                Err(_) => break,
            }
        }
        listing
    }

    /// Returns a few disassembled instructions around the given IP.
    fn disassembly_snippet(&self, ip: usize, err: &VMError) {
        let listing = self.disassembly_listing();
        if listing.is_empty() {
            return;
        }

        let target_idx = listing
            .iter()
            .position(|(offset, _, size)| (*offset..offset + *size).contains(&ip))
            .or_else(|| listing.iter().rposition(|(offset, _, _)| *offset <= ip));

        if let Some(idx) = target_idx {
            let start = idx.saturating_sub(2);
            let end = (idx + 3).min(listing.len());

            eprintln!("    | assembly around ip {ip}:");
            for (i, (offset, text, _)) in listing[start..end].iter().enumerate() {
                let is_target = start + i == idx;
                let marker = if is_target { "-->" } else { "   " };
                eprintln!("{marker} {:>6}: {}", offset, text);
                if is_target {
                    SHOW_TYPE.store(false, Ordering::Relaxed);
                    error!("            {} {}", "^".repeat(text.len()), err);
                    SHOW_TYPE.store(true, Ordering::Relaxed);
                }
            }
        }
    }

    /// Extracts the instruction pointer associated with a VM error, if available.
    fn error_ip(&self, err: &VMError) -> Option<usize> {
        match err {
            VMError::InvalidInstruction { offset, .. } => Some(*offset),
            VMError::UnexpectedEndOfBytecode { ip, .. } => Some(*ip),
            VMError::InvalidIP { ip } => Some(*ip),
            VMError::JumpOutOfBounds { from, .. } => Some(*from),
            VMError::ReturnWithoutCall { .. } => Some(self.instr_offset),
            VMError::OutOfGas { .. } => Some(self.instr_offset),
            _ => Some(self.instr_offset),
        }
    }

    /// Derives a unique storage key from chain ID, contract ID, and user-provided key.
    ///
    /// The key is hashed to ensure uniform distribution and prevent collisions
    /// between different contracts or chains.
    fn make_state_key(
        &mut self,
        chain_id: u64,
        contract_id: &Hash,
        user_key: &[u8],
    ) -> Result<Hash, VMError> {
        let prefix = b"STATE";
        let id = &chain_id.to_le_bytes();
        self.charge_gas_categorized(
            (prefix.len() + id.len() + HASH_LEN + user_key.len()) as u64,
            GasCategory::StateKeyDerivation,
        )?;
        Ok(Hash::sha3()
            .chain(prefix)
            .chain(id)
            .chain(contract_id.as_slice())
            .chain(user_key)
            .finalize())
    }

    /// Returns the total gas consumed during execution.
    pub fn gas_used(&self) -> u64 {
        self.gas_used
    }

    /// Returns the gas profile for this execution.
    pub fn gas_profile(&self) -> GasProfile {
        self.gas_profile.clone()
    }

    /// Returns the return data buffer for this execution.
    pub fn return_data(self) -> Vec<u8> {
        self.return_data
    }

    /// Adds gas to the running total with category tracking.
    ///
    /// Returns [`VMError::OutOfGas`] if the cumulative usage exceeds self.max_gas.
    fn charge_gas_categorized(
        &mut self,
        increment: u64,
        category: GasCategory,
    ) -> Result<(), VMError> {
        self.gas_profile.add(category, increment);

        self.gas_used = self.gas_used.saturating_add(increment);
        if self.gas_used > self.max_gas {
            return Err(VMError::OutOfGas {
                used: self.gas_used,
                limit: self.max_gas,
            });
        }

        Ok(())
    }

    /// Charges the base gas cost for an opcode with a compile-time-known cost.
    #[inline(always)]
    fn charge_opcode_gas(&mut self, cost: u64) -> Result<(), VMError> {
        self.gas_profile.add(GasCategory::OpcodeBase, cost);
        self.gas_used = self.gas_used.saturating_add(cost);
        if self.gas_used > self.max_gas {
            return Err(VMError::OutOfGas {
                used: self.gas_used,
                limit: self.max_gas,
            });
        }
        Ok(())
    }

    /// Charges gas for a function call based on argument count and call stack depth.
    ///
    /// Cost formula: `argc * arg_gas_cost + call_depth * depth_gas_cost`
    fn charge_call(&mut self, call_depth: usize, depth_gas_cost: u64) -> Result<(), VMError> {
        self.charge_gas_categorized(
            call_depth as u64 * depth_gas_cost,
            GasCategory::CallOverhead,
        )
    }
}

#[cfg(test)]
mod tests;

impl VM {
    /// Extracts a boolean from a [`SrcOperand`], reading from the register file if needed.
    fn bool_from_operand(
        &self,
        src_operand: SrcOperand,
        instruction: Instruction,
        argc: usize,
    ) -> Result<bool, VMError> {
        Ok(match src_operand {
            SrcOperand::Reg(idx) => self.registers.get_bool(idx, instruction)?,
            SrcOperand::Bool(b) => b,
            _ => {
                return Err(VMError::InvalidOperand {
                    instruction: instruction.mnemonic(),
                    argc,
                    expected: SrcOperand::Bool(false).to_string(),
                    actual: src_operand.to_string(),
                });
            }
        })
    }

    /// Extracts a heap reference from a [`SrcOperand`], reading from the register file if needed.
    fn ref_from_operand(
        &self,
        src_operand: SrcOperand,
        instruction: Instruction,
        argc: usize,
    ) -> Result<u32, VMError> {
        Ok(match src_operand {
            SrcOperand::Reg(idx) => self.registers.get_ref(idx, instruction)?,
            SrcOperand::Ref(r) => r,
            _ => {
                return Err(VMError::InvalidOperand {
                    instruction: instruction.mnemonic(),
                    argc,
                    expected: SrcOperand::Ref(0).to_string(),
                    actual: src_operand.to_string(),
                });
            }
        })
    }

    /// Extracts an i64 from a [`SrcOperand`], reading from the register file if needed.
    fn int_from_operand(
        &self,
        src_operand: SrcOperand,
        instruction: Instruction,
        argc: usize,
    ) -> Result<i64, VMError> {
        Ok(match src_operand {
            SrcOperand::Reg(idx) => self.registers.get_int(idx, instruction)?,
            SrcOperand::I64(i) => i,
            _ => {
                return Err(VMError::InvalidOperand {
                    instruction: instruction.mnemonic(),
                    argc,
                    expected: SrcOperand::I64(0).to_string(),
                    actual: src_operand.to_string(),
                });
            }
        })
    }

    /// Converts a [`SrcOperand`] to a [`Value`], reading from the register file if needed.
    fn value_from_operand(&self, src_operand: SrcOperand) -> Result<Value, VMError> {
        Ok(match src_operand {
            SrcOperand::Reg(idx) => *self.registers.get(idx),
            SrcOperand::Bool(b) => Value::Bool(b),
            SrcOperand::I64(i) => Value::Int(i),
            SrcOperand::Ref(r) => Value::Ref(r),
        })
    }

    /// Serializes a [`SrcOperand`] to its raw byte representation for storage keys.
    fn bytes_from_operand(&mut self, src_operand: SrcOperand) -> Result<Vec<u8>, VMError> {
        Ok(match src_operand {
            SrcOperand::Reg(idx) => match self.registers.get(idx) {
                Value::Bool(b) => vec![*b as u8],
                Value::Ref(r) => self.heap_get_data(*r)?.to_vec(),
                Value::Int(i) => i.to_le_bytes().to_vec(),
            },
            SrcOperand::Bool(b) => vec![b as u8],
            SrcOperand::I64(i) => i.to_le_bytes().to_vec(),
            SrcOperand::Ref(r) => self.heap_get_data(r)?.to_vec(),
        })
    }
}

/// impl block for VM wrapper functions to charge gas
impl VM {
    /// Stores an item on the heap and returns its reference index.
    ///
    /// Charges gas proportional to the item's byte length.
    fn heap_index(&mut self, item: Vec<u8>) -> Result<u32, VMError> {
        self.charge_gas_categorized(item.len() as u64, GasCategory::HeapAllocation)?;
        Ok(self.heap.append(item))
    }

    /// Retrieves raw bytes from the heap by reference index with gas charging.
    fn heap_get_data(&mut self, id: u32) -> Result<&[u8], VMError> {
        let data = self.heap.get_data(id)?;
        self.charge_gas_categorized(data.len() as u64, GasCategory::HeapAllocation)?;
        self.heap.get_data(id)
    }

    /// Retrieves a string from the heap by reference index with gas charging.
    ///
    /// Charges gas proportional to the string's byte length.
    /// Returns [`VMError::InvalidUtf8`] if the bytes are not valid UTF-8.
    fn heap_get_string(&mut self, id: u32) -> Result<String, VMError> {
        let size = self.heap.get_raw_ref(id)?.len();
        self.charge_gas_categorized(size as u64, GasCategory::HeapAllocation)?;
        self.heap.get_string(id)
    }

    /// Writes a value to state storage with gas metering.
    ///
    /// Charges gas proportional to the key and value size using [`STORE_BYTE_COST`].
    fn state_push<S: State>(
        &mut self,
        state: &mut S,
        key: Hash,
        item: Vec<u8>,
    ) -> Result<(), VMError> {
        // Charge extra gas for creating a new state key
        self.charge_gas_categorized(
            20_000 * (!state.contains_key(key)) as u64,
            GasCategory::StateStore,
        )?;

        let byte_cost = (HASH_LEN as u64)
            .checked_add(item.len() as u64)
            .ok_or(VMError::OutOfGas {
                used: self.gas_used,
                limit: self.max_gas,
            })?
            .checked_mul(STORE_BYTE_COST)
            .ok_or(VMError::OutOfGas {
                used: self.gas_used,
                limit: self.max_gas,
            })?;
        self.charge_gas_categorized(byte_cost, GasCategory::StateStore)?;

        state.push(key, item);
        Ok(())
    }

    /// Reads a value from state storage with gas metering.
    ///
    /// Charges gas proportional to the value size using [`READ_BYTE_COST`].
    /// Returns [`VMError::KeyNotFound`] if the key does not exist.
    fn state_get<S: State>(&mut self, state: &mut S, key: Hash) -> Result<Vec<u8>, VMError> {
        let item = state.get(key).ok_or(VMError::KeyNotFound {
            key: key.to_string(),
        })?;
        self.charge_gas_categorized(item.len() as u64 * READ_BYTE_COST, GasCategory::StateRead)?;
        Ok(item)
    }
}

/// impl block for VM execution functions
impl VM {
    /// Executes bytecode using function-pointer table dispatch.
    ///
    /// Uses an indirect call through a `[fn; 128]` dispatch table.
    /// Each opcode maps to its own function pointer,
    /// giving the CPU separate branch-prediction slots per call site.
    pub fn run<S: State>(&mut self, state: &mut S, ctx: &ExecContext) -> Result<(), VMError> {
        use crate::virtual_machine::isa::OPCODE_BASE_MASK;

        let table = exec_vm! {
            @table S,
            {
                // Move, Casts and Misc
                Noop => op_noop(),
                Move => op_move(rd: Reg, rs: Src),
                CMove => op_cmove(rd: Reg, cond: Reg, r1: Src, r2: Src),
                I64ToBool => op_i64_to_bool(rd: Reg, rs: Src),
                BoolToI64 => op_bool_to_i64(rd: Reg, rs: Src),
                StrToI64 => op_str_to_i64(rd: Reg, rs: Src),
                I64ToStr => op_i64_to_str(rd: Reg, rs: Src),
                StrToBool => op_str_to_bool(rd: Reg, rs: Src),
                BoolToStr => op_bool_to_str(rd: Reg, rs: Src),
                // Store and Load
                DeleteState => op_delete_state(state, ctx; rd: Src),
                HasState =>  op_has_state(state, ctx; rd: Reg, key: Src),
                StoreBytes => op_store_bytes(state, ctx; key: Src, value: Src),
                LoadBytes => op_load_bytes(state, ctx; rd: Reg, key: Src),
                LoadI64 => op_load_i64(state, ctx; rd: Reg, key: Src),
                LoadBool => op_load_bool(state, ctx; rd: Reg, key: Src),
                LoadStr => op_load_str(state, ctx; rd: Reg, key: Src),
                LoadHash => op_load_hash(state, ctx; rd: Reg, key: Src),
                Sha3 => op_sha3(dst: Reg, argc: ImmU8, argv: Reg),
                // Integer arithmetic
                Add => op_add(rd: Reg, rs1: Src, rs2: Src),
                Sub => op_sub(rd: Reg, rs1: Src, rs2: Src),
                Mul => op_mul(rd: Reg, rs1: Src, rs2: Src),
                Div => op_div(rd: Reg, rs1: Src, rs2: Src),
                Mod => op_mod(rd: Reg, rs1: Src, rs2: Src),
                Neg => op_neg(rd: Reg, rs: Src),
                Abs => op_abs(rd: Reg, rs: Src),
                Min => op_min(rd: Reg, rs1: Src, rs2: Src),
                Max => op_max(rd: Reg, rs1: Src, rs2: Src),
                Shl => op_shl(rd: Reg, rs1: Src, rs2: Src),
                Shr => op_shr(rd: Reg, rs1: Src, rs2: Src),
                Inc => op_inc(rd: Reg),
                Dec => op_dec(rd: Reg),
                // Boolean / comparison
                Not => op_not(rd: Reg, rs: Src),
                And => op_and(rd: Reg, rs1: Src, rs2: Src),
                Or => op_or(rd: Reg, rs1: Src, rs2: Src),
                Xor => op_xor(rd: Reg, rs1: Src, rs2: Src),
                Eq => op_eq(rd: Reg, rs1: Src, rs2: Src),
                Ne => op_ne(rd: Reg, rs1: Src, rs2: Src),
                Lt => op_lt(rd: Reg, rs1: Src, rs2: Src),
                Le => op_le(rd: Reg, rs1: Src, rs2: Src),
                Gt => op_gt(rd: Reg, rs1: Src, rs2: Src),
                Ge => op_ge(rd: Reg, rs1: Src, rs2: Src),
                // Control Flow
                CallHost => op_call_host(state, ctx; dst: Reg, fn_id: RefU32, argv: Reg),
                CallHost0 => op_call_host0(state, ctx; dst: Reg, fn_id: RefU32),
                Call => op_call(offset: ImmI32),
                Jal => op_jal(rd: Reg, offset: ImmI32),
                Jalr => op_jalr(rd: Reg, rs: Reg, offset: ImmI32),
                Beq => op_beq(rs1: Src, rs2: Src, offset: ImmI32),
                Bne => op_bne(rs1: Src, rs2: Src, offset: ImmI32),
                Blt => op_blt(rs1: Src, rs2: Src, offset: ImmI32),
                Bge => op_bge(rs1: Src, rs2: Src, offset: ImmI32),
                Bltu => op_bltu(rs1: Src, rs2: Src, offset: ImmI32),
                Bgeu => op_bgeu(rs1: Src, rs2: Src, offset: ImmI32),
                Jump => op_jump(offset: ImmI32),
                Ret => op_ret(),
                Halt => op_halt(),
                Return => op_return(addr: Addr, len: Addr),
                // Data and Memory access
                CallDataLoad => op_call_data_load(rd: Reg),
                CallDataCopy => op_call_data_copy(dst: Addr),
                CallDataLen => op_call_data_len(rd: Reg),
                MemLoad => op_memload(rd: Reg, addr: Addr),
                MemStore => op_memstore(addr: Addr, rs: Src),
                MemCpy => op_memcpy(dst: Addr, src: Addr, len: Addr),
                MemSet => op_memset(dst: Addr, len: Addr, val: ImmU8),
                MemLen => op_memlen(dst: Reg),
                MemLoad8U => op_memload_8u(rd: Reg, addr: Addr),
                MemLoad8S => op_memload_8s(rd: Reg, addr: Addr),
                MemLoad16U => op_memload_16u(rd: Reg, addr: Addr),
                MemLoad16S => op_memload_16s(rd: Reg, addr: Addr),
                MemLoad32U => op_memload_32u(rd: Reg, addr: Addr),
                MemLoad32S => op_memload_32s(rd: Reg, addr: Addr),
                // Special Op Codes
                Dispatch => op_dispatch(),
            }
        };

        let result = (|| {
            while self.ip < self.data.len() {
                self.instr_offset = self.ip;
                let opcode = unsafe { *self.data.get_unchecked(self.instr_offset) };
                self.ip += 1;

                let has_metadata = (opcode & OPCODE_METADATA_FLAG) != 0;
                let base = (opcode & OPCODE_BASE_MASK) as usize;

                // Still need Instruction for metadata setup (supports_concat_compact).
                let instr = Instruction::decode_opcode(opcode)
                    .map_err(|_| VMError::InvalidInstruction {
                        opcode,
                        offset: self.instr_offset,
                    })?
                    .0;

                let metadata = if has_metadata {
                    Some(self.read_u8_operand()?)
                } else {
                    None
                };
                self.set_operand_metadata(metadata, instr);

                table[base](self, state, ctx)?;
            }
            Ok(())
        })();

        if let Err(err) = &result {
            self.log_runtime_error(err);
        }

        result
    }

    /// Reads exactly `count` bytes from the bytecode at the current IP.
    ///
    /// Advances the instruction pointer by `count` bytes.
    fn read_exact(&mut self, count: usize) -> Result<&[u8], VMError> {
        let start = self.ip;
        let end = start + count;
        if end > self.data.len() {
            return Err(VMError::UnexpectedEndOfBytecode {
                ip: self.instr_offset,
                requested: count,
                available: self.data.len().saturating_sub(self.ip),
            });
        }
        let slice = unsafe { self.data.get_unchecked(start..end) };

        self.ip = end;
        Ok(slice)
    }

    /// Reads a single byte operand from bytecode at the current IP.
    #[inline(always)]
    fn read_u8_operand(&mut self) -> Result<u8, VMError> {
        if self.ip >= self.data.len() {
            return Err(VMError::UnexpectedEndOfBytecode {
                ip: self.instr_offset,
                requested: 1,
                available: self.data.len().saturating_sub(self.ip),
            });
        }
        let byte = unsafe { *self.data.get_unchecked(self.ip) };
        self.ip += 1;
        Ok(byte)
    }

    /// Stores per-instruction metadata and resets the mixed-radix decode cursor.
    fn set_operand_metadata(&mut self, metadata: Option<u8>, instr: Instruction) {
        self.operand_metadata = metadata;
        self.operand_metadata_cursor = metadata.map_or(0u16, |value| {
            metadata_payload_value(value, instr.supports_concat_compact())
        });
    }

    /// Returns `true` when the current instruction's metadata has the concat flag set.
    fn operand_concat_flag(&self) -> bool {
        self.operand_metadata.is_some_and(metadata_concat_flag)
    }

    /// Consumes the implicit `rs1` Src metadata slot used by compact concat form.
    fn consume_concat_src_slot(&mut self) {
        unsafe {
            metadata_consume_src_state_unchecked(&mut self.operand_metadata_cursor);
        }
    }

    /// Reads the next [`SrcOperand`] from the bytecode at the current instruction pointer.
    #[inline(always)]
    fn read_src_operand(&mut self) -> Result<SrcOperand, VMError> {
        if self.operand_metadata.is_none() {
            return Ok(SrcOperand::Reg(self.read_u8_operand()?));
        }
        // SAFETY: metadata cursor arithmetic is sound for assembler-produced
        // bytecode. Bounds are checked before unchecked slice access.
        unsafe {
            decode_src_operand_from_stream_unchecked(
                &self.data,
                &mut self.ip,
                self.instr_offset,
                &mut self.operand_metadata_cursor,
            )
        }
    }

    /// Reads the next [`AddrOperand`] from the bytecode at the current instruction pointer.
    #[inline(always)]
    fn read_addr_operand(&mut self) -> Result<AddrOperand, VMError> {
        if self.operand_metadata.is_none() {
            return Ok(AddrOperand::Reg(self.read_u8_operand()?));
        }
        // SAFETY: metadata cursor arithmetic is sound for assembler-produced bytecode.
        unsafe {
            decode_addr_operand_from_stream_unchecked(
                &self.data,
                &mut self.ip,
                self.instr_offset,
                &mut self.operand_metadata_cursor,
            )
        }
    }

    /// Reads the next compact i32 immediate from bytecode at current IP.
    #[inline(always)]
    fn read_imm_i32(&mut self) -> Result<i32, VMError> {
        if self.operand_metadata.is_none() {
            return Ok((self.read_u8_operand()? as i8) as i32);
        }
        // SAFETY: metadata cursor arithmetic is sound for assembler-produced bytecode.
        unsafe {
            decode_i32_operand_from_stream_unchecked(
                &self.data,
                &mut self.ip,
                self.instr_offset,
                &mut self.operand_metadata_cursor,
            )
        }
    }

    /// Reads the next compact u32 reference from bytecode at current IP.
    #[inline(always)]
    fn read_ref_u32(&mut self) -> Result<u32, VMError> {
        if self.operand_metadata.is_none() {
            return Ok(self.read_u8_operand()? as u32);
        }
        // SAFETY: metadata cursor arithmetic is sound for assembler-produced bytecode.
        unsafe {
            decode_ref_u32_operand_from_stream_unchecked(
                &self.data,
                &mut self.ip,
                self.instr_offset,
                &mut self.operand_metadata_cursor,
            )
        }
    }

    fn op_noop(&self, _instr: Instruction) -> Result<(), VMError> {
        Ok(())
    }

    fn op_move(&mut self, _instr: Instruction, dst: u8, src: SrcOperand) -> Result<(), VMError> {
        let v: Value = match src {
            SrcOperand::Reg(idx) => *self.registers.get(idx),
            SrcOperand::Bool(b) => Value::Bool(b),
            SrcOperand::I64(i) => Value::Int(i),
            SrcOperand::Ref(r) => Value::Ref(r),
        };
        self.registers.set(dst, v);
        Ok(())
    }

    /// Conditional move: `dst = cond ? r1 : r2`.
    ///
    /// If `cond` is truthy (non-zero integer or `true`), moves `r1` to `dst`;
    /// otherwise moves `r2` to `dst`. Reference operands for `cond` are rejected.
    fn op_cmove(
        &mut self,
        instr: Instruction,
        dst: u8,
        cond: u8,
        r1: SrcOperand,
        r2: SrcOperand,
    ) -> Result<(), VMError> {
        let v: bool = match *self.registers.get(cond) {
            Value::Bool(b) => b,
            Value::Ref(_) => {
                return Err(VMError::TypeMismatchStatic {
                    instruction: instr.mnemonic(),
                    arg_index: 2,
                    expected: "Boolean or Integer",
                    actual: "Reference",
                });
            }
            Value::Int(i) => i != 0,
        };

        let value = if v { r1 } else { r2 };
        self.op_move(instr, dst, value)
    }

    fn op_i64_to_bool(
        &mut self,
        instr: Instruction,
        dst: u8,
        src: SrcOperand,
    ) -> Result<(), VMError> {
        let v = self.int_from_operand(src, instr, 1)?;
        self.registers.set(dst, Value::Bool(v != 0));
        Ok(())
    }

    fn op_bool_to_i64(
        &mut self,
        instr: Instruction,
        dst: u8,
        src: SrcOperand,
    ) -> Result<(), VMError> {
        let v = self.bool_from_operand(src, instr, 1)?;
        self.registers.set(dst, Value::Int(if v { 1 } else { 0 }));
        Ok(())
    }

    fn op_str_to_i64(
        &mut self,
        instr: Instruction,
        dst: u8,
        src: SrcOperand,
    ) -> Result<(), VMError> {
        let reg = self.ref_from_operand(src, instr, 1)?;
        let str = self.heap_get_string(reg)?;
        self.registers.set(dst, Value::Int(parse_i64(&str, 0, 0)?));
        Ok(())
    }

    /// Returns the number of characters in the decimal string representation of `n`.
    const fn digits_i64(n: i64) -> u64 {
        let mut x = n;
        let mut extra = 0;
        if x < 0 {
            extra = 1;
            x = -x;
        }
        let x = x as u64;
        let d = if x < 10 {
            1
        } else if x < 100 {
            2
        } else if x < 1_000 {
            3
        } else if x < 10_000 {
            4
        } else if x < 100_000 {
            5
        } else if x < 1_000_000 {
            6
        } else if x < 10_000_000 {
            7
        } else if x < 100_000_000 {
            8
        } else if x < 1_000_000_000 {
            9
        } else if x < 10_000_000_000 {
            10
        } else if x < 100_000_000_000 {
            11
        } else if x < 1_000_000_000_000 {
            12
        } else if x < 10_000_000_000_000 {
            13
        } else if x < 100_000_000_000_000 {
            14
        } else if x < 1_000_000_000_000_000 {
            15
        } else if x < 10_000_000_000_000_000 {
            16
        } else if x < 100_000_000_000_000_000 {
            17
        } else if x < 1_000_000_000_000_000_000 {
            18
        } else if x < 10_000_000_000_000_000_000 {
            19
        } else {
            20
        };
        (d + extra) as u64
    }

    fn op_i64_to_str(
        &mut self,
        instr: Instruction,
        dst: u8,
        src: SrcOperand,
    ) -> Result<(), VMError> {
        let reg = self.int_from_operand(src, instr, 1)?;
        // Charge gas manually before allocation instead of using heap_index()
        self.charge_gas_categorized(Self::digits_i64(reg), GasCategory::HeapAllocation)?;
        let str_ref = self.heap.append(reg.to_string().into_bytes());
        self.registers.set(dst, Value::Ref(str_ref));
        Ok(())
    }

    fn op_str_to_bool(
        &mut self,
        instr: Instruction,
        dst: u8,
        src: SrcOperand,
    ) -> Result<(), VMError> {
        let reg = self.ref_from_operand(src, instr, 1)?;
        let str = self.heap_get_string(reg)?;
        let b = if str == "true" {
            true
        } else if str == "false" {
            false
        } else {
            return Err(VMError::TypeMismatch {
                instruction: instr.mnemonic(),
                arg_index: 1,
                expected: "\"true\" or \"false\"",
                actual: str,
            });
        };
        self.registers.set(dst, Value::Bool(b));
        Ok(())
    }

    fn op_bool_to_str(
        &mut self,
        instr: Instruction,
        dst: u8,
        src: SrcOperand,
    ) -> Result<(), VMError> {
        let reg = self.bool_from_operand(src, instr, 1)?;
        // Charge gas manually before allocation instead of using heap_index()
        self.charge_gas_categorized(if reg { 4 } else { 5 }, GasCategory::HeapAllocation)?;
        let str = (if reg { "true" } else { "false" }).to_string();
        let bool_ref = self.heap.append(str.into_bytes());
        self.registers.set(dst, Value::Ref(bool_ref));
        Ok(())
    }

    fn op_delete_state<S: State>(
        &mut self,
        _instr: Instruction,
        state: &mut S,
        ctx: &ExecContext,
        key: SrcOperand,
    ) -> Result<(), VMError> {
        let key_ref = self.bytes_from_operand(key)?;
        let key = self.make_state_key(ctx.chain_id, &ctx.contract_id, &key_ref)?;
        state.delete(key);
        Ok(())
    }

    fn op_has_state<S: State>(
        &mut self,
        _instr: Instruction,
        state: &mut S,
        ctx: &ExecContext,
        dst: u8,
        key: SrcOperand,
    ) -> Result<(), VMError> {
        let key_ref = self.bytes_from_operand(key)?;
        let key = self.make_state_key(ctx.chain_id, &ctx.contract_id, &key_ref)?;
        self.registers
            .set(dst, Value::Bool(state.contains_key(key)));
        Ok(())
    }

    fn op_store_bytes<S: State>(
        &mut self,
        _instr: Instruction,
        state: &mut S,
        ctx: &ExecContext,
        key: SrcOperand,
        value: SrcOperand,
    ) -> Result<(), VMError> {
        let key_ref = self.bytes_from_operand(key)?;
        let val = self.bytes_from_operand(value)?;
        let key = self.make_state_key(ctx.chain_id, &ctx.contract_id, &key_ref)?;
        self.state_push(state, key, val)
    }

    fn load_state_bytes<S: State>(
        &mut self,
        state: &mut S,
        ctx: &ExecContext,
        key: SrcOperand,
    ) -> Result<(Vec<u8>, Vec<u8>), VMError> {
        let key_ref = self.bytes_from_operand(key)?;
        let state_key = self.make_state_key(ctx.chain_id, &ctx.contract_id, &key_ref)?;
        Ok((key_ref, self.state_get(state, state_key)?))
    }

    fn op_load_bytes<S: State>(
        &mut self,
        _instr: Instruction,
        state: &mut S,
        ctx: &ExecContext,
        dst: u8,
        key: SrcOperand,
    ) -> Result<(), VMError> {
        let (_, value) = self.load_state_bytes(state, ctx, key)?;
        let index = self.heap_index(value)?;
        self.registers.set(dst, Value::Ref(index));
        Ok(())
    }

    fn op_load_i64<S: State>(
        &mut self,
        _instr: Instruction,
        state: &mut S,
        ctx: &ExecContext,
        dst: u8,
        key: SrcOperand,
    ) -> Result<(), VMError> {
        let (key, value) = self.load_state_bytes(state, ctx, key)?;
        let bytes: [u8; 8] = value.try_into().map_err(|_| VMError::InvalidStateValue {
            key: format!("{:?}", key),
            expected: "8 bytes for i64",
        })?;
        self.registers
            .set(dst, Value::Int(i64::from_le_bytes(bytes)));
        Ok(())
    }

    fn op_load_bool<S: State>(
        &mut self,
        _instr: Instruction,
        state: &mut S,
        ctx: &ExecContext,
        dst: u8,
        key: SrcOperand,
    ) -> Result<(), VMError> {
        let (key, value) = self.load_state_bytes(state, ctx, key)?;
        if value.len() != 1 {
            return Err(VMError::InvalidStateValue {
                key: format!("{:?}", key),
                expected: "1 byte for bool",
            });
        }
        self.registers.set(dst, Value::Bool(value[0] != 0));
        Ok(())
    }

    fn op_load_str<S: State>(
        &mut self,
        _instr: Instruction,
        state: &mut S,
        ctx: &ExecContext,
        dst: u8,
        key: SrcOperand,
    ) -> Result<(), VMError> {
        let (_, value) = self.load_state_bytes(state, ctx, key)?;
        let str_ref = self.heap_index(value)?;
        self.registers.set(dst, Value::Ref(str_ref));
        Ok(())
    }

    fn op_load_hash<S: State>(
        &mut self,
        _instr: Instruction,
        state: &mut S,
        ctx: &ExecContext,
        dst: u8,
        key: SrcOperand,
    ) -> Result<(), VMError> {
        let (_, value) = self.load_state_bytes(state, ctx, key)?;
        let hash_ref = self.heap_index(value)?;
        self.registers.set(dst, Value::Ref(hash_ref));
        Ok(())
    }

    fn op_sha3(&mut self, _instr: Instruction, dst: u8, argc: u8, argv: u8) -> Result<(), VMError> {
        let mut hasher = Hash::sha3();
        let mut hashed_bytes = 0usize;

        for i in 0..argc {
            let idx = argv.wrapping_add(i);
            match *self.registers.get(idx) {
                Value::Bool(b) => {
                    hasher.update(&[b as u8]);
                    hashed_bytes += 1;
                }
                Value::Int(v) => {
                    let bytes = v.to_le_bytes();
                    hasher.update(&bytes);
                    hashed_bytes += bytes.len();
                }
                Value::Ref(r) => {
                    let bytes = self.heap.get_data(r)?;
                    hasher.update(bytes);
                    hashed_bytes += bytes.len();
                }
            }
        }

        self.charge_gas_categorized(hashed_bytes as u64, GasCategory::HostFunction)?;

        let hash = hasher.finalize();
        let hash_ref = self.heap_index(hash.to_vec())?;
        self.registers.set(dst, Value::Ref(hash_ref));
        Ok(())
    }

    fn op_add(
        &mut self,
        instr: Instruction,
        dst: u8,
        a: SrcOperand,
        b: SrcOperand,
    ) -> Result<(), VMError> {
        let va = self.int_from_operand(a, instr, 1)?;
        let vb = self.int_from_operand(b, instr, 2)?;
        self.registers.set(dst, Value::Int(va.wrapping_add(vb)));
        Ok(())
    }

    fn op_sub(
        &mut self,
        instr: Instruction,
        dst: u8,
        a: SrcOperand,
        b: SrcOperand,
    ) -> Result<(), VMError> {
        let va = self.int_from_operand(a, instr, 1)?;
        let vb = self.int_from_operand(b, instr, 2)?;
        self.registers.set(dst, Value::Int(va.wrapping_sub(vb)));
        Ok(())
    }

    fn op_mul(
        &mut self,
        instr: Instruction,
        dst: u8,
        a: SrcOperand,
        b: SrcOperand,
    ) -> Result<(), VMError> {
        let va = self.int_from_operand(a, instr, 1)?;
        let vb = self.int_from_operand(b, instr, 2)?;
        self.registers.set(dst, Value::Int(va.wrapping_mul(vb)));
        Ok(())
    }

    fn op_div(
        &mut self,
        instr: Instruction,
        dst: u8,
        a: SrcOperand,
        b: SrcOperand,
    ) -> Result<(), VMError> {
        let va = self.int_from_operand(a, instr, 1)?;
        let vb = self.int_from_operand(b, instr, 2)?;
        if vb == 0 {
            return Err(VMError::DivisionByZero);
        }
        self.registers.set(dst, Value::Int(va.wrapping_div(vb)));
        Ok(())
    }

    fn op_mod(
        &mut self,
        instr: Instruction,
        dst: u8,
        a: SrcOperand,
        b: SrcOperand,
    ) -> Result<(), VMError> {
        let va = self.int_from_operand(a, instr, 1)?;
        let vb = self.int_from_operand(b, instr, 2)?;
        if vb == 0 {
            return Err(VMError::DivisionByZero);
        }
        self.registers.set(dst, Value::Int(va.wrapping_rem(vb)));
        Ok(())
    }

    fn op_neg(&mut self, instr: Instruction, dst: u8, src: SrcOperand) -> Result<(), VMError> {
        let v = self.int_from_operand(src, instr, 1)?;
        self.registers.set(dst, Value::Int(v.wrapping_neg()));
        Ok(())
    }

    fn op_abs(&mut self, instr: Instruction, dst: u8, src: SrcOperand) -> Result<(), VMError> {
        let v = self.int_from_operand(src, instr, 1)?;
        self.registers.set(dst, Value::Int(v.wrapping_abs()));
        Ok(())
    }

    fn op_min(
        &mut self,
        instr: Instruction,
        dst: u8,
        a: SrcOperand,
        b: SrcOperand,
    ) -> Result<(), VMError> {
        let va = self.int_from_operand(a, instr, 1)?;
        let vb = self.int_from_operand(b, instr, 2)?;
        self.registers.set(dst, Value::Int(va.min(vb)));
        Ok(())
    }

    fn op_max(
        &mut self,
        instr: Instruction,
        dst: u8,
        a: SrcOperand,
        b: SrcOperand,
    ) -> Result<(), VMError> {
        let va = self.int_from_operand(a, instr, 1)?;
        let vb = self.int_from_operand(b, instr, 2)?;
        self.registers.set(dst, Value::Int(va.max(vb)));
        Ok(())
    }

    fn op_shl(
        &mut self,
        instr: Instruction,
        dst: u8,
        a: SrcOperand,
        b: SrcOperand,
    ) -> Result<(), VMError> {
        let va = self.int_from_operand(a, instr, 1)?;
        let vb = self.int_from_operand(b, instr, 2)?;
        self.registers
            .set(dst, Value::Int(va.wrapping_shl(vb as u32)));
        Ok(())
    }

    fn op_shr(
        &mut self,
        instr: Instruction,
        dst: u8,
        a: SrcOperand,
        b: SrcOperand,
    ) -> Result<(), VMError> {
        let va = self.int_from_operand(a, instr, 1)?;
        let vb = self.int_from_operand(b, instr, 2)?;
        self.registers
            .set(dst, Value::Int(va.wrapping_shr(vb as u32)));
        Ok(())
    }

    fn op_inc(&mut self, instr: Instruction, dst: u8) -> Result<(), VMError> {
        let r = self.registers.get_int(dst, instr)?;
        self.registers.set(dst, Value::Int(r.wrapping_add(1)));
        Ok(())
    }

    fn op_dec(&mut self, instr: Instruction, dst: u8) -> Result<(), VMError> {
        let r = self.registers.get_int(dst, instr)?;
        self.registers.set(dst, Value::Int(r.wrapping_sub(1)));
        Ok(())
    }

    fn op_not(&mut self, instr: Instruction, dst: u8, src: SrcOperand) -> Result<(), VMError> {
        let v = self.bool_from_operand(src, instr, 1)?;
        self.registers.set(dst, Value::Bool(!v));
        Ok(())
    }

    fn op_and(
        &mut self,
        instr: Instruction,
        dst: u8,
        a: SrcOperand,
        b: SrcOperand,
    ) -> Result<(), VMError> {
        let va = self.bool_from_operand(a, instr, 1)?;
        let vb = self.bool_from_operand(b, instr, 2)?;
        self.registers.set(dst, Value::Bool(va && vb));
        Ok(())
    }

    fn op_or(
        &mut self,
        instr: Instruction,
        dst: u8,
        a: SrcOperand,
        b: SrcOperand,
    ) -> Result<(), VMError> {
        let va = self.bool_from_operand(a, instr, 1)?;
        let vb = self.bool_from_operand(b, instr, 2)?;
        self.registers.set(dst, Value::Bool(va || vb));
        Ok(())
    }

    fn op_xor(
        &mut self,
        instr: Instruction,
        dst: u8,
        a: SrcOperand,
        b: SrcOperand,
    ) -> Result<(), VMError> {
        let va = self.bool_from_operand(a, instr, 1)?;
        let vb = self.bool_from_operand(b, instr, 2)?;
        self.registers.set(dst, Value::Bool(va ^ vb));
        Ok(())
    }

    fn op_eq(
        &mut self,
        _instr: Instruction,
        dst: u8,
        a: SrcOperand,
        b: SrcOperand,
    ) -> Result<(), VMError> {
        let va = self.value_from_operand(a)?;
        let vb = self.value_from_operand(b)?;
        self.registers.set(dst, Value::Bool(Value::equals(va, vb)?));
        Ok(())
    }

    fn op_ne(
        &mut self,
        _instr: Instruction,
        dst: u8,
        a: SrcOperand,
        b: SrcOperand,
    ) -> Result<(), VMError> {
        let va = self.value_from_operand(a)?;
        let vb = self.value_from_operand(b)?;
        self.registers
            .set(dst, Value::Bool(!Value::equals(va, vb)?));
        Ok(())
    }

    fn op_lt(
        &mut self,
        instr: Instruction,
        dst: u8,
        a: SrcOperand,
        b: SrcOperand,
    ) -> Result<(), VMError> {
        let va = self.int_from_operand(a, instr, 1)?;
        let vb = self.int_from_operand(b, instr, 2)?;
        self.registers.set(dst, Value::Bool(va < vb));
        Ok(())
    }

    fn op_gt(
        &mut self,
        instr: Instruction,
        dst: u8,
        a: SrcOperand,
        b: SrcOperand,
    ) -> Result<(), VMError> {
        let va = self.int_from_operand(a, instr, 1)?;
        let vb = self.int_from_operand(b, instr, 2)?;
        self.registers.set(dst, Value::Bool(va > vb));
        Ok(())
    }

    fn op_le(
        &mut self,
        instr: Instruction,
        dst: u8,
        a: SrcOperand,
        b: SrcOperand,
    ) -> Result<(), VMError> {
        let va = self.int_from_operand(a, instr, 1)?;
        let vb = self.int_from_operand(b, instr, 2)?;
        self.registers.set(dst, Value::Bool(va <= vb));
        Ok(())
    }

    fn op_ge(
        &mut self,
        instr: Instruction,
        dst: u8,
        a: SrcOperand,
        b: SrcOperand,
    ) -> Result<(), VMError> {
        let va = self.int_from_operand(a, instr, 1)?;
        let vb = self.int_from_operand(b, instr, 2)?;
        self.registers.set(dst, Value::Bool(va >= vb));
        Ok(())
    }

    fn op_call_host<S: State>(
        &mut self,
        _: Instruction,
        _: &mut S,
        ctx: &ExecContext,
        dst: u8,
        fn_id: u32,
        argv: u8,
    ) -> Result<(), VMError> {
        self.charge_call(self.call_stack.len(), 10)?;
        let fn_name = self.heap_get_string(fn_id)?;
        let argc = HOST_FUNCTIONS
            .iter()
            .find_map(|(name, argc)| (*name == fn_name).then_some(*argc))
            .ok_or(VMError::InvalidCallHostFunction {
                name: fn_name.clone(),
            })?;
        let args: Vec<Value> = (0..argc)
            .map(|i| *self.registers.get(argv.wrapping_add(i)))
            .collect::<_>();

        /// Converts the given value to an u32 (ref), returns an error if it isn't a Value::Ref
        fn get_ref(val: Value) -> Result<u32, VMError> {
            match val {
                Value::Ref(r) => Ok(r),
                other => Err(VMError::TypeMismatchStatic {
                    instruction: "CALL_HOST reg, \"len\"",
                    arg_index: 0,
                    expected: "Ref",
                    actual: other.type_name(),
                }),
            }
        }

        /// Converts the given value to an i64, returns an error if it isn't a Value::Int
        fn get_i64(val: Value) -> Result<i64, VMError> {
            match val {
                Value::Int(i) => Ok(i),
                other => Err(VMError::TypeMismatchStatic {
                    instruction: "CALL_HOST reg, \"len\"",
                    arg_index: 0,
                    expected: "Ref",
                    actual: other.type_name(),
                }),
            }
        }

        match fn_name.as_str() {
            LEN => {
                let str_ref = get_ref(args[0])?;
                let len = self.heap.get_data(str_ref)?.len();
                self.charge_gas_categorized(len as u64, GasCategory::HostFunction)?;
                self.registers.set(dst, Value::Int(len as i64));
                Ok(())
            }
            SLICE => {
                let str_ref = get_ref(args[0])?;
                let start = get_i64(args[1])? as usize;
                let end = get_i64(args[2])? as usize;

                let len = self.heap.get_data(str_ref)?.len();
                self.charge_gas_categorized(len as u64, GasCategory::HostFunction)?;

                let data = self.heap.get_data(str_ref)?;
                let end = end.min(data.len());
                let start = start.min(end);

                let sliced = data[start..end].to_vec();
                let new_ref = self.heap_index(sliced)?;
                self.registers.set(dst, Value::Ref(new_ref));
                Ok(())
            }
            CONCAT => {
                let ref1 = get_ref(args[0])?;
                let ref2 = get_ref(args[1])?;

                let len1 = self.heap.get_data(ref1)?.len();
                let len2 = self.heap.get_data(ref2)?.len();
                self.charge_gas_categorized((len1 + len2) as u64, GasCategory::HostFunction)?;

                let mut result = self.heap.get_data(ref1)?.to_vec();
                result.extend_from_slice(self.heap.get_data(ref2)?);

                let new_ref = self.heap_index(result)?;
                self.registers.set(dst, Value::Ref(new_ref));
                Ok(())
            }
            COMPARE => {
                let ref1 = get_ref(args[0])?;
                let ref2 = get_ref(args[1])?;

                let len1 = self.heap.get_data(ref1)?.len();
                let len2 = self.heap.get_data(ref2)?.len();
                self.charge_gas_categorized((len1 + len2) as u64, GasCategory::HostFunction)?;

                let s1 = self.heap.get_data(ref1)?;
                let s2 = self.heap.get_data(ref2)?;
                let cmp = match s1.cmp(s2) {
                    std::cmp::Ordering::Less => -1,
                    std::cmp::Ordering::Equal => 0,
                    std::cmp::Ordering::Greater => 1,
                };
                self.registers.set(dst, Value::Int(cmp));
                Ok(())
            }
            CALLER => {
                let reference = self.heap_index(ctx.caller.to_vec())?;
                self.registers.set(dst, Value::Ref(reference));
                Ok(())
            }
            _ => Err(VMError::InvalidCallHostFunction { name: fn_name }),
        }
    }

    fn op_call_host0<S: State>(
        &mut self,
        instr: Instruction,
        state: &mut S,
        ctx: &ExecContext,
        dst: u8,
        fn_id: u32,
    ) -> Result<(), VMError> {
        self.op_call_host(instr, state, ctx, dst, fn_id, 0)
    }

    fn op_call(&mut self, instr: Instruction, offset: i32) -> Result<(), VMError> {
        self.charge_call(self.call_stack.len(), 10)?;

        if self.call_stack.len() >= MAX_CALL_STACK_LEN {
            return Err(VMError::CallStackOverflow {
                max: MAX_CALL_STACK_LEN,
                actual: self.call_stack.len(),
            });
        }

        self.call_stack.push(self.ip);
        self.op_jump(instr, offset)
    }

    fn op_jal(&mut self, instr: Instruction, rd: u8, offset: i32) -> Result<(), VMError> {
        self.registers.set(rd, Value::Int(self.ip as i64));
        self.op_jump(instr, offset)
    }

    fn op_jalr(&mut self, instr: Instruction, rd: u8, rs: u8, offset: i32) -> Result<(), VMError> {
        let base = self.registers.get_int(rs, instr)?;
        self.registers.set(rd, Value::Int(self.ip as i64));
        self.ip = base as usize;
        self.op_jump(instr, offset)
    }

    fn op_beq(
        &mut self,
        instr: Instruction,
        rs1: SrcOperand,
        rs2: SrcOperand,
        offset: i32,
    ) -> Result<(), VMError> {
        let va = self.value_from_operand(rs1)?;
        let vb = self.value_from_operand(rs2)?;

        if Value::equals(va, vb)? {
            self.op_jump(instr, offset)?;
        }
        Ok(())
    }

    fn op_bne(
        &mut self,
        instr: Instruction,
        rs1: SrcOperand,
        rs2: SrcOperand,
        offset: i32,
    ) -> Result<(), VMError> {
        let va = self.value_from_operand(rs1)?;
        let vb = self.value_from_operand(rs2)?;

        if !Value::equals(va, vb)? {
            self.op_jump(instr, offset)?;
        }
        Ok(())
    }

    fn op_blt(
        &mut self,
        instr: Instruction,
        rs1: SrcOperand,
        rs2: SrcOperand,
        offset: i32,
    ) -> Result<(), VMError> {
        let a = self.int_from_operand(rs1, instr, 1)?;
        let b = self.int_from_operand(rs2, instr, 2)?;
        if a < b {
            self.op_jump(instr, offset)?;
        }
        Ok(())
    }

    fn op_bge(
        &mut self,
        instr: Instruction,
        rs1: SrcOperand,
        rs2: SrcOperand,
        offset: i32,
    ) -> Result<(), VMError> {
        let a = self.int_from_operand(rs1, instr, 1)?;
        let b = self.int_from_operand(rs2, instr, 2)?;
        if a >= b {
            self.op_jump(instr, offset)?;
        }
        Ok(())
    }

    fn op_bltu(
        &mut self,
        instr: Instruction,
        rs1: SrcOperand,
        rs2: SrcOperand,
        offset: i32,
    ) -> Result<(), VMError> {
        let a = self.int_from_operand(rs1, instr, 1)? as u64;
        let b = self.int_from_operand(rs2, instr, 1)? as u64;
        if a < b {
            self.op_jump(instr, offset)?;
        }
        Ok(())
    }

    fn op_bgeu(
        &mut self,
        instr: Instruction,
        rs1: SrcOperand,
        rs2: SrcOperand,
        offset: i32,
    ) -> Result<(), VMError> {
        let a = self.int_from_operand(rs1, instr, 1)? as u64;
        let b = self.int_from_operand(rs2, instr, 1)? as u64;
        if a >= b {
            self.op_jump(instr, offset)?;
        }
        Ok(())
    }

    fn op_jump(&mut self, _instr: Instruction, offset: i32) -> Result<(), VMError> {
        let new_ip = self.ip as i32 + offset;
        if new_ip < 0 || new_ip as usize > self.data.len() {
            return Err(VMError::JumpOutOfBounds {
                from: self.ip,
                to: new_ip as usize,
                max: self.data.len(),
            });
        }
        self.ip = new_ip as usize;
        Ok(())
    }

    fn op_ret(&mut self, _instr: Instruction) -> Result<(), VMError> {
        let return_addr = self.call_stack.pop().ok_or(VMError::ReturnWithoutCall {
            call_depth: self.call_stack.len(),
        })?;
        self.ip = return_addr;
        Ok(())
    }

    fn op_halt(&mut self, _instr: Instruction) -> Result<(), VMError> {
        // Move IP to the end to exit the execution loop cleanly.
        self.ip = self.data.len();
        Ok(())
    }

    fn op_return(
        &mut self,
        instr: Instruction,
        addr: AddrOperand,
        len: AddrOperand,
    ) -> Result<(), VMError> {
        let (addr, from_ref) = self.addr_operand_to_u32_with_ref(instr, addr)?;
        if from_ref {
            self.return_data = self.heap_get_data(addr)?.to_vec();
        } else {
            let addr = addr as usize;
            let len = self.addr_operand_to_u32(instr, len)? as usize;
            if addr + len > self.heap.len() {
                return Err(VMError::MemoryOOBRead {
                    got: addr + len,
                    max: self.heap.len(),
                });
            }
            // SAFETY: `addr + len <= self.heap.len()` is validated above.
            self.return_data = unsafe { self.heap.exec_slice_unchecked(addr, len) }.to_vec();
        }
        self.op_halt(instr)
    }

    fn op_call_data_load(&mut self, _instr: Instruction, dst: u8) -> Result<(), VMError> {
        for (i, arg) in self.args.iter().enumerate() {
            self.registers.set(dst + i as u8, *arg);
        }
        Ok(())
    }

    fn op_call_data_copy(&mut self, instr: Instruction, dst: AddrOperand) -> Result<(), VMError> {
        let bytes = self.args_to_vec();
        let len = bytes.len() as u32;
        self.op_memset(instr, dst.clone(), AddrOperand::U32(len), 0x00)?;
        let dst = self.addr_operand_to_u32(instr, dst)? as usize;
        // SAFETY: `op_memset` expanded memory to cover `dst + len`, and `len == bytes.len()`.
        unsafe { self.heap.exec_slice_unchecked_mut(dst, bytes.len()) }.copy_from_slice(&bytes);
        Ok(())
    }

    fn op_call_data_len(&mut self, _instr: Instruction, dst: u8) -> Result<(), VMError> {
        let size = self.args_to_vec().len();
        self.registers.set(dst, Value::Int(size as i64));
        Ok(())
    }

    /// Ensures execution memory spans `[base, base + len)`.
    ///
    /// Memory grows in word-sized chunks and charges gas proportional to the
    /// number of bytes expanded.
    fn expand_memory(&mut self, base: usize, len: usize) -> Result<(), VMError> {
        let needed = base.saturating_add(len);
        let aligned = needed.div_ceil(WORD_SIZE) * WORD_SIZE;
        if self.heap.len() < aligned {
            let expanded = aligned - self.heap.len();
            self.charge_gas_categorized(expanded as u64 * 5, GasCategory::Memory)?;
            self.heap.resize(self.heap.exec_offset + aligned, 0);
        }

        Ok(())
    }

    /// Resolves an address operand to a concrete u32 value.
    ///
    /// For immediate addresses, returns the value directly. For register addresses,
    /// reads the integer value from the register and truncates to u32.
    fn addr_operand_to_u32(&self, instr: Instruction, addr: AddrOperand) -> Result<u32, VMError> {
        Ok(self.addr_operand_to_u32_with_ref(instr, addr)?.0)
    }

    fn addr_operand_to_u32_with_ref(
        &self,
        instr: Instruction,
        addr: AddrOperand,
    ) -> Result<(u32, bool), VMError> {
        Ok(match addr {
            AddrOperand::U32(u) => (u, false),
            AddrOperand::Reg(r) => match self.registers.get(r) {
                Value::Ref(r) => (*r, true),
                Value::Int(_) => (self.registers.get_int(r, instr)? as u32, false),
                other => {
                    return Err(VMError::TypeMismatchStatic {
                        instruction: instr.mnemonic(),
                        arg_index: r as i32,
                        expected: "Int",
                        actual: other.type_name(),
                    });
                }
            },
        })
    }

    /// Loads `COUNT` bytes from memory into a register with sign/zero extension.
    ///
    /// Reads `COUNT` bytes from the heap at the given address and extends to 64-bit.
    /// If `unsigned` is true, zero-extends; otherwise sign-extends based on the
    /// most significant bit of the loaded value.
    fn memload<const COUNT: usize>(
        &mut self,
        instr: Instruction,
        rd: u8,
        addr: AddrOperand,
        unsigned: bool,
    ) -> Result<(), VMError> {
        let addr = self.addr_operand_to_u32(instr, addr)? as usize;
        if addr + COUNT > self.heap.len() {
            return Err(VMError::MemoryOOBRead {
                got: addr + COUNT,
                max: self.heap.len(),
            });
        }

        // SAFETY: `addr + COUNT <= self.heap.len()` is validated above.
        let mut result: [u8; WORD_SIZE] = [0u8; WORD_SIZE];
        result[..COUNT].copy_from_slice(unsafe { self.heap.exec_slice_unchecked(addr, COUNT) });
        // Sign or Zero extend the bytes
        let extension: u8 = if !unsigned && (result[COUNT - 1] >> 7) != 0 {
            0xFF
        } else {
            0
        };
        result[COUNT..].fill(extension);

        self.registers
            .set(rd, Value::Int(i64::from_le_bytes(result)));
        Ok(())
    }

    fn op_memload(&mut self, instr: Instruction, rd: u8, addr: AddrOperand) -> Result<(), VMError> {
        self.memload::<WORD_SIZE>(instr, rd, addr, true)
    }

    fn op_memstore(
        &mut self,
        instr: Instruction,
        addr: AddrOperand,
        rs: SrcOperand,
    ) -> Result<(), VMError> {
        let addr = self.addr_operand_to_u32(instr, addr)? as usize;
        self.expand_memory(addr, WORD_SIZE)?;

        let value = self.int_from_operand(rs, instr, 2)?;
        let data = value.to_le_bytes();
        // SAFETY: `expand_memory(addr, WORD_SIZE)` guarantees `addr + WORD_SIZE <= self.heap.len()`.
        unsafe { self.heap.exec_slice_unchecked_mut(addr, WORD_SIZE) }.copy_from_slice(&data);

        Ok(())
    }

    fn op_memcpy(
        &mut self,
        instr: Instruction,
        dst: AddrOperand,
        src: AddrOperand,
        len: AddrOperand,
    ) -> Result<(), VMError> {
        let len = self.addr_operand_to_u32(instr, len)? as usize;
        if len == 0 {
            return Ok(());
        }

        let dst = self.addr_operand_to_u32(instr, dst)? as usize;
        let src = self.addr_operand_to_u32(instr, src)? as usize;
        self.expand_memory(dst, len)?;

        if self.heap.len() < src.saturating_add(len) {
            return Err(VMError::MemoryOOBRead {
                got: src.saturating_add(len),
                max: self.heap.len(),
            });
        }

        self.charge_gas_categorized(len as u64 * 3, GasCategory::Memory)?;
        // SAFETY: `expand_memory(dst, len)` guarantees dst bounds; `src + len <= self.heap.len()` is checked above.
        unsafe { self.heap.exec_copy_within_unchecked(src, dst, len) };

        Ok(())
    }

    fn op_memset(
        &mut self,
        instr: Instruction,
        dst: AddrOperand,
        len: AddrOperand,
        val: u8,
    ) -> Result<(), VMError> {
        let len = self.addr_operand_to_u32(instr, len)? as usize;
        if len == 0 {
            return Ok(());
        }

        let dst = self.addr_operand_to_u32(instr, dst)? as usize;
        self.expand_memory(dst, len)?;
        self.charge_gas_categorized(len as u64 * 3, GasCategory::Memory)?;
        // SAFETY: `expand_memory(dst, len)` guarantees `dst + len <= self.heap.len()`.
        unsafe { self.heap.exec_fill_unchecked(dst, len, val) };
        Ok(())
    }

    fn op_memlen(&mut self, _instr: Instruction, dst: u8) -> Result<(), VMError> {
        self.registers.set(dst, Value::Int(self.heap.len() as i64));
        Ok(())
    }

    /// Dispatches to a public function by selector index.
    ///
    /// Reads an inline table of `(offset, argr)` entries from bytecode.
    /// Offset widths are compact and selected per-entry via packed
    /// `AABB_CCDD` width-code bytes after the entry count.
    /// Uses the execute-program selector, loads call arguments via
    /// `CALLDATA_LOAD` semantics into the entry's `argr`, calls the target
    /// function, and halts.
    fn op_dispatch(&mut self, instr: Instruction) -> Result<(), VMError> {
        let count = self.read_u8_operand()? as usize;
        let selector = self.dispatch_selector as usize;
        if selector >= count {
            return Err(VMError::DispatchOutOfBounds { selector, count });
        }
        let width_table_len = dispatch_width_table_len(count);
        let width_table = self.read_exact(width_table_len)?.to_vec();

        let mut selected: Option<(i32, u8)> = None;
        for entry_index in 0..count {
            let width_code = dispatch_width_code_at(&width_table, entry_index)?;
            let offset_len = metadata_len_from_code(width_code) as usize;
            let offset_bytes = self.read_exact(offset_len)?;
            let offset_i64 = decode_i64_compact(offset_bytes, offset_len as u8)?;
            let offset = i32::try_from(offset_i64).map_err(|_| VMError::DecodeError {
                reason: format!("dispatch offset {offset_i64} is out of i32 range"),
            })?;
            let argr = self.read_u8_operand()?;
            if entry_index == selector {
                selected = Some((offset, argr));
            }
        }

        let (offset, argr) = selected.expect("selector validated against count");
        // Load call arguments into registers starting at argr
        self.op_call_data_load(instr, argr)?;
        // Push a call frame whose return address is past all bytecode,
        // so RET will cause the main loop to exit cleanly (like HALT).
        self.call_stack.push(self.data.len());
        // Jump to the target function
        self.op_jump(instr, offset)
    }

    fn op_memload_8u(
        &mut self,
        instr: Instruction,
        rd: u8,
        addr: AddrOperand,
    ) -> Result<(), VMError> {
        self.memload::<BYTE_SIZE>(instr, rd, addr, true)
    }

    fn op_memload_8s(
        &mut self,
        instr: Instruction,
        rd: u8,
        addr: AddrOperand,
    ) -> Result<(), VMError> {
        self.memload::<BYTE_SIZE>(instr, rd, addr, false)
    }

    fn op_memload_16u(
        &mut self,
        instr: Instruction,
        rd: u8,
        addr: AddrOperand,
    ) -> Result<(), VMError> {
        self.memload::<QUARTER_WORD_SIZE>(instr, rd, addr, true)
    }

    fn op_memload_16s(
        &mut self,
        instr: Instruction,
        rd: u8,
        addr: AddrOperand,
    ) -> Result<(), VMError> {
        self.memload::<QUARTER_WORD_SIZE>(instr, rd, addr, false)
    }

    fn op_memload_32u(
        &mut self,
        instr: Instruction,
        rd: u8,
        addr: AddrOperand,
    ) -> Result<(), VMError> {
        self.memload::<HALF_WORD_SIZE>(instr, rd, addr, true)
    }

    fn op_memload_32s(
        &mut self,
        instr: Instruction,
        rd: u8,
        addr: AddrOperand,
    ) -> Result<(), VMError> {
        self.memload::<HALF_WORD_SIZE>(instr, rd, addr, false)
    }
}
