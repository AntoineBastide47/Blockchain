//! Core virtual machine implementation.
//!
//! The VM executes bytecode using a register-based architecture with 256 general-purpose
//! registers. All arithmetic uses wrapping semantics to prevent overflow panics.

use crate::error;
use crate::types::encoding::{Decode, Encode, EncodeSink};
use crate::types::hash::{HASH_LEN, Hash};
use crate::utils::log::SHOW_TYPE;
use crate::virtual_machine::assembler::parse_i64_or_hex;
use crate::virtual_machine::errors::VMError;
use crate::virtual_machine::isa::Instruction;
use crate::virtual_machine::operand::{AddrOperand, SrcOperand};
use crate::virtual_machine::program::{DeployProgram, ExecuteProgram};
use crate::virtual_machine::state::State;
use blockchain_derive::BinaryCodec;
use std::ops::{Index, IndexMut, RangeBounds};
use std::sync::atomic::Ordering;

/// Size of a VM word in bytes (64-bit).
const WORD_SIZE: usize = 8;
/// Half word size (32-bit) for 32-bit memory loads.
const HALF_WORD_SIZE: usize = WORD_SIZE / 2;
/// Quarter word size (16-bit) for 16-bit memory loads.
const QUARTER_WORD_SIZE: usize = WORD_SIZE / 4;
/// Single byte size for 8-bit memory loads.
const BYTE_SIZE: usize = WORD_SIZE / 8;

/// Defines host function name constants and a lookup table of `(name, argc)` pairs.
macro_rules! host_functions {
      ($($const_name:ident = $name:literal => $argc:literal),* $(,)?) => {
          $(pub const $const_name: &str = $name;)*
          pub const HOST_FUNCTIONS: &[(&str, u8)] = &[$(($name, $argc)),*];
      };
  }

host_functions! {
    LEN     = "len"     => 1,
    HASH    = "hash"    => 1,
    SLICE   = "slice"   => 3,
    CONCAT  = "concat"  => 2,
    COMPARE = "compare" => 2,
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
    let end = cursor
        .checked_add(len)
        .ok_or(VMError::InvalidIP { ip: *cursor })?;
    if end > data.len() {
        return Err(VMError::UnexpectedEndOfBytecode {
            ip,
            requested: len,
            available: data.len().saturating_sub(*cursor),
        });
    }
    let slice = &data[*cursor..end];
    *cursor = end;
    Ok(slice)
}

/// Reads a single byte from `data` at `cursor`, advancing the cursor.
fn read_u8(data: &[u8], cursor: &mut usize, ip: usize) -> Result<u8, VMError> {
    Ok(*read_bytes(data, cursor, 1, ip)?.first().unwrap())
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
            let instr = Instruction::try_from(opcode)?;
            let mut cursor = start + 1;

            let text = match instr {
                $(
                    Instruction::$name => {
                        define_instruction_decoder!(
                            @decode data cursor start $mnemonic; $( $kind ),*
                        )?
                    }
                ),*
                Instruction::Dispatch => {
                    let count = read_u8(data, &mut cursor, start)?;
                    let mut parts = Vec::new();
                    parts.push(count.to_string());
                    for _ in 0..count {
                        let bytes = read_bytes(data, &mut cursor, 4, start)?;
                        let offset = i32::from_le_bytes(bytes.try_into().unwrap());
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

    (@decode $data:ident $cursor:ident $start:ident $mnemonic:expr; ) => {
        Ok::<_, VMError>($mnemonic.to_string())
    };

    (@decode $data:ident $cursor:ident $start:ident $mnemonic:expr; $( $kind:ident ),+ ) => {{
        let mut parts = Vec::new();
        $(
            let val = define_instruction_decoder!(@read $data $cursor $start $kind)?;
            parts.push(val);
        )*
        Ok::<_, VMError>(format!("{} {}", $mnemonic, parts.join(", ")))
    }};

    (@read $data:ident $cursor:ident $start:ident Reg) => {{
        let v = read_u8($data, &mut $cursor, $start)?;
        Ok::<String, VMError>(format!("r{}", v))
    }};

    (@read $data:ident $cursor:ident $start:ident ImmU8) => {{
        let v = read_u8($data, &mut $cursor, $start)?;
        Ok::<String, VMError>(v.to_string())
    }};

    (@read $data:ident $cursor:ident $start:ident RefU32) => {{
        let bytes = read_bytes($data, &mut $cursor, 4, $start)?;
        Ok::<String, VMError>(format!("@{}", u32::from_le_bytes(bytes.try_into().unwrap())))
    }};

    (@read $data:ident $cursor:ident $start:ident ImmI32) => {{
        let bytes = read_bytes($data, &mut $cursor, 4, $start)?;
        Ok::<String, VMError>(i32::from_le_bytes(bytes.try_into().unwrap()).to_string())
    }};

    (@read $data:ident $cursor:ident $start:ident ImmU32) => {{
        let bytes = read_bytes($data, &mut $cursor, 4, $start)?;
        Ok::<String, VMError>(u32::from_le_bytes(bytes.try_into().unwrap()).to_string())
    }};

    (@read $data:ident $cursor:ident $start:ident ImmI64) => {{
        let bytes = read_bytes($data, &mut $cursor, 8, $start)?;
        Ok::<String, VMError>(i64::from_le_bytes(bytes.try_into().unwrap()).to_string())
    }};

    (@read $data:ident $cursor:ident $start:ident Addr) => {{let tag = read_u8($data, &mut $cursor, $start)?;
      match tag {
          0 => define_instruction_decoder!(@read $data $cursor $start Reg),
          1 => {
              let b = read_bytes($data, &mut $cursor, 4, $start)?;
              Ok::<String, VMError>(u32::from_le_bytes(b.try_into().unwrap()).to_string())
          }
          _ => Err(VMError::InvalidOperandTag { tag, offset: $start })
      }
    }};

    (@read $data:ident $cursor:ident $start:ident Src) => {{
      let tag = read_u8($data, &mut $cursor, $start)?;
      match tag {
          0 => define_instruction_decoder!(@read $data $cursor $start Reg),
          1 => {
              let b = read_u8($data, &mut $cursor, $start)?;
              Ok::<String, VMError>(if b == 0 { "false" } else { "true" }.to_string())
          }
          2 => define_instruction_decoder!(@read $data $cursor $start ImmI64),
          3 => define_instruction_decoder!(@read $data $cursor $start RefU32),
          _ => Err(VMError::InvalidOperandTag { tag, offset: $start })
      }
  }};
}

crate::for_each_instruction!(define_instruction_decoder);

/// Categories of gas consumption for profiling and debugging.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum GasCategory {
    /// Intrinsic cost of the transaction
    Intrinsic,
    /// Initial contract deployment cost (base + bytecode size).
    Deploy,
    /// Base cost for executing opcodes.
    OpcodeBase,
    /// Cost for deriving state storage keys.
    StateKeyDerivation,
    /// Cost for writing to state storage.
    StateStore,
    /// Cost for reading from state storage.
    StateRead,
    /// Cost for heap allocations (strings, hashes).
    HeapAllocation,
    /// Cost for function call overhead (arguments, stack depth).
    CallOverhead,
    /// Cost for host function execution.
    HostFunction,
    /// Cost for memory interactions.
    Memory,
}

impl GasCategory {
    pub const fn as_str(&self) -> &'static str {
        match self {
            GasCategory::Intrinsic => "Intrinsic",
            GasCategory::Deploy => "Deployment",
            GasCategory::OpcodeBase => "Opcode Base",
            GasCategory::StateKeyDerivation => "State Key Derivation",
            GasCategory::StateStore => "State Store",
            GasCategory::StateRead => "State Read",
            GasCategory::HeapAllocation => "Heap Allocation",
            GasCategory::CallOverhead => "Call Overhead",
            GasCategory::HostFunction => "Host Function",
            GasCategory::Memory => "Memory",
        }
    }
}

/// Gas consumption profile for debugging and optimization.
///
/// Tracks how gas is distributed across different execution categories,
/// enabling developers to identify expensive operations in their contracts.
#[derive(Clone, Debug, Default)]
pub struct GasProfile {
    intrinsic: u64,
    deploy: u64,
    opcode_base: u64,
    state_key_derivation: u64,
    state_store: u64,
    state_read: u64,
    heap_allocation: u64,
    call_overhead: u64,
    host_function: u64,
    memory: u64,
}

impl GasProfile {
    /// Creates a new empty gas profile.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds gas to the specified category.
    pub fn add(&mut self, category: GasCategory, amount: u64) {
        match category {
            GasCategory::Intrinsic => self.intrinsic = self.intrinsic.saturating_add(amount),
            GasCategory::Deploy => self.deploy = self.deploy.saturating_add(amount),
            GasCategory::OpcodeBase => self.opcode_base = self.opcode_base.saturating_add(amount),
            GasCategory::StateKeyDerivation => {
                self.state_key_derivation = self.state_key_derivation.saturating_add(amount)
            }
            GasCategory::StateStore => self.state_store = self.state_store.saturating_add(amount),
            GasCategory::StateRead => self.state_read = self.state_read.saturating_add(amount),
            GasCategory::HeapAllocation => {
                self.heap_allocation = self.heap_allocation.saturating_add(amount)
            }
            GasCategory::CallOverhead => {
                self.call_overhead = self.call_overhead.saturating_add(amount)
            }
            GasCategory::HostFunction => {
                self.host_function = self.host_function.saturating_add(amount)
            }
            GasCategory::Memory => self.memory = self.memory.saturating_add(amount),
        }
    }

    /// Returns the total gas across all categories.
    pub fn total(&self) -> u64 {
        self.deploy
            .saturating_add(self.intrinsic)
            .saturating_add(self.opcode_base)
            .saturating_add(self.state_key_derivation)
            .saturating_add(self.state_store)
            .saturating_add(self.state_read)
            .saturating_add(self.heap_allocation)
            .saturating_add(self.call_overhead)
            .saturating_add(self.host_function)
            .saturating_add(self.memory)
    }

    /// Returns an iterator over all categories and their gas costs.
    pub fn iter(&self) -> impl Iterator<Item = (GasCategory, u64)> {
        [
            (GasCategory::Intrinsic, self.intrinsic),
            (GasCategory::Deploy, self.deploy),
            (GasCategory::OpcodeBase, self.opcode_base),
            (GasCategory::StateKeyDerivation, self.state_key_derivation),
            (GasCategory::StateStore, self.state_store),
            (GasCategory::StateRead, self.state_read),
            (GasCategory::HeapAllocation, self.heap_allocation),
            (GasCategory::CallOverhead, self.call_overhead),
            (GasCategory::HostFunction, self.host_function),
            (GasCategory::Memory, self.memory),
        ]
        .into_iter()
    }
}

/// Maximum cumulative gas allowed for all transactions in a block.
pub const BLOCK_GAS_LIMIT: u64 = 30_000_000;

/// Maximum depth of the call stack to prevent unbounded recursion.
const MAX_CALL_STACK_LEN: usize = 1024;
/// Gas cost per byte when writing to state storage.
const STORE_BYTE_COST: u64 = 10;
/// Gas cost per byte when reading from state storage.
const READ_BYTE_COST: u64 = 5;

/// Runtime value stored in registers and used for typed call arguments.
#[derive(Clone, Copy, Debug, Eq, PartialEq, BinaryCodec)]
pub enum Value {
    /// Boolean value.
    Bool(bool),
    /// Reference to a heap-allocated object.
    Ref(u32),
    /// 64-bit signed integer.
    Int(i64),
}

impl Value {
    /// Returns the type name for error messages.
    pub fn type_name(&self) -> &'static str {
        match self {
            Value::Bool(_) => "Boolean",
            Value::Ref(_) => "Reference",
            Value::Int(_) => "Integer",
        }
    }

    pub fn equals(va: Value, vb: Value) -> Result<bool, VMError> {
        Ok(match (va, vb) {
            (Value::Bool(b1), Value::Bool(b2)) => b1 == b2,
            (Value::Ref(r1), Value::Ref(r2)) => r1 == r2,
            (Value::Int(i1), Value::Int(i2)) => i1 == i2,
            _ => {
                return Err(VMError::InvalidComparison {
                    type1: va.type_name(),
                    type2: vb.type_name(),
                });
            }
        })
    }
}

/// Register file holding VM storage.
///
/// Provides 256 registers, each capable of storing a single [`Value`].
/// Registers are lazily initialized (start as `None`).
struct Registers {
    regs: Vec<Value>,
}

impl Registers {
    /// Creates a new register file with `count` registers.
    pub fn new() -> Self {
        Self {
            regs: vec![Value::Int(0); 256],
        }
    }

    /// Returns a reference to the value in register `idx`.
    ///
    /// Returns [`VMError::InvalidRegisterIndex`] if `idx` is out of bounds.
    pub fn get(&self, idx: u8) -> Result<&Value, VMError> {
        self.regs
            .get(idx as usize)
            .ok_or(VMError::InvalidRegisterIndex {
                index: idx,
                available: self.regs.len(),
            })
    }

    /// Returns the boolean value in register `idx`.
    ///
    /// Returns [`VMError::TypeMismatch`] if the value is not a boolean.
    pub fn get_bool(&self, idx: u8, instr: &'static str) -> Result<bool, VMError> {
        match self.get(idx)? {
            Value::Bool(v) => Ok(*v),
            other => Err(VMError::TypeMismatchStatic {
                instruction: instr,
                arg_index: idx as i32,
                expected: "Bool",
                actual: other.type_name(),
            }),
        }
    }

    /// Returns the reference value in register `idx`.
    ///
    /// Returns [`VMError::TypeMismatch`] if the value is not a reference.
    pub fn get_ref(&self, idx: u8, instr: &'static str) -> Result<u32, VMError> {
        match self.get(idx)? {
            Value::Ref(v) => Ok(*v),
            other => Err(VMError::TypeMismatchStatic {
                instruction: instr,
                arg_index: idx as i32,
                expected: "Ref",
                actual: other.type_name(),
            }),
        }
    }

    /// Returns the integer value in register `idx`.
    ///
    /// Returns [`VMError::TypeMismatch`] if the value is not an integer.
    pub fn get_int(&self, idx: u8, instr: &'static str) -> Result<i64, VMError> {
        match self.get(idx)? {
            Value::Int(v) => Ok(*v),
            other => Err(VMError::TypeMismatchStatic {
                instruction: instr,
                arg_index: idx as i32,
                expected: "Int",
                actual: other.type_name(),
            }),
        }
    }

    /// Stores a value into register `idx`.
    ///
    /// Returns [`VMError::InvalidRegisterIndex`] if `idx` is out of bounds.
    pub fn set(&mut self, idx: u8, v: Value) -> Result<(), VMError> {
        let available = self.regs.len();
        let slot = self
            .regs
            .get_mut(idx as usize)
            .ok_or(VMError::InvalidRegisterIndex {
                index: idx,
                available,
            })?;
        *slot = v;
        Ok(())
    }
}

/// Unified memory for the VM, combining constant and execution regions.
///
/// Memory layout: `[const region][execution region]`
/// - **Const region**: Interned string literals and other constant data loaded from the program.
/// - **Execution region**: Dynamic memory allocated during transaction execution.
///
/// The `exec_offset` marks the boundary between const and execution memory. Indexing
/// operations (`[]`) access only the execution region for memory instructions.
struct Heap {
    /// Raw memory buffer containing both const and execution regions.
    memory: Vec<u8>,
    /// Byte offset where execution memory begins (equals const region size).
    exec_offset: usize,
}

impl Heap {
    /// Creates a new heap with the given const memory.
    ///
    /// The execution region starts empty, immediately after the const region.
    fn new(memory: Vec<u8>) -> Self {
        Self {
            exec_offset: memory.len(),
            memory,
        }
    }

    /// Appends an item to memory with length-prefix encoding.
    ///
    /// Returns the byte offset where the item was stored.
    fn append(&mut self, item: Vec<u8>) -> u32 {
        let index = self.memory.len();
        item.encode(&mut self.memory);
        index as u32
    }

    /// Returns a reference to the raw [`Vec<u8>`] stored at the given index.
    /// Includes the length prefix.
    fn get_raw_ref(&self, reference: u32) -> Result<&[u8], VMError> {
        let reference = reference as usize;
        self.memory
            .get(reference)
            .ok_or(VMError::ReferenceOutOfBounds {
                reference,
                max: self.memory.len() - 1,
            })?;
        let data: [u8; WORD_SIZE] = self.memory[reference..reference + WORD_SIZE]
            .try_into()
            .unwrap();
        let size = usize::from_le_bytes(data);

        let bound = reference + WORD_SIZE + size;
        if bound > self.memory.len() {
            return Err(VMError::MemoryOOBRead {
                got: bound,
                max: self.memory.len(),
            });
        }

        Ok(&self.memory[reference..bound])
    }

    /// Returns just the data bytes stored at the given index (without length prefix).
    fn get_data(&self, reference: u32) -> Result<&[u8], VMError> {
        let raw = self.get_raw_ref(reference)?;
        Ok(&raw[WORD_SIZE..])
    }

    /// Returns the size of the execution memory region in bytes.
    fn len(&self) -> usize {
        self.memory.len().saturating_sub(self.exec_offset)
    }

    /// Resizes the total memory buffer to `new_len`, filling new bytes with `value`.
    fn resize(&mut self, new_len: usize, value: u8) {
        self.memory.resize(new_len, value);
    }

    /// Copies bytes within the memory buffer from `src` range to `dest` offset.
    fn copy_within<R: RangeBounds<usize>>(&mut self, src: R, dest: usize) {
        self.memory.copy_within(src, dest);
    }

    /// Retrieves a string by its reference index.
    fn get_string(&self, id: u32) -> Result<String, VMError> {
        let mut bytes = self.get_raw_ref(id)?;
        String::decode(&mut bytes).map_err(|_| VMError::InvalidUtf8 { string_ref: id })
    }

    /// Returns a slice of the execution memory (memory after exec_offset).
    #[cfg(test)]
    fn exec_memory(&self) -> &[u8] {
        &self.memory[self.exec_offset..]
    }
}

/// Indexes into the execution memory region (not the const region).
impl<T> Index<T> for Heap
where
    [u8]: Index<T>,
{
    type Output = <[u8] as Index<T>>::Output;

    fn index(&self, index: T) -> &Self::Output {
        &self.memory[self.exec_offset..][index]
    }
}

/// Mutably indexes into the execution memory region (not the const region).
impl<T> IndexMut<T> for Heap
where
    [u8]: IndexMut<T>,
{
    fn index_mut(&mut self, index: T) -> &mut Self::Output {
        &mut self.memory[self.exec_offset..][index]
    }
}

macro_rules! exec_vm {
    // Entry point
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
                    let instr_name = $instr.mnemonic();
                    exec_vm!(@call $vm, $state, $ctx, instr_name, $handler, $args)
                }
            ),*
        }
    }};

    // Handler with storage and chain_id (semicolon separator)
    (@call $vm:ident, $state:ident, $ctx:ident, $instr_name:expr, $handler:ident,
        (state, ctx; $( $field:ident : $kind:ident ),* $(,)? )
    ) => {{
        $( let $field = exec_vm!(@read $vm, $kind)?; )*
        $vm.$handler($instr_name, $state, $ctx, $( $field ),*)
    }};

    // Handler without storage (no semicolon)
    (@call $vm:ident, $state:ident, $ctx:ident, $instr_name:expr, $handler:ident,
        ( $( $field:ident : $kind:ident ),* $(,)? )
    ) => {{
        $( let $field = exec_vm!(@read $vm, $kind)?; )*
        $vm.$handler($instr_name, $( $field ),*)
    }};

    // Decode a u8 register index
    (@read $vm:ident, Reg) => {{
        Ok::<u8, VMError>($vm.read_exact(1)?[0])
    }};

    // Decode a u8 immediate (1 byte)
    (@read $vm:ident, ImmU8) => {{
        Ok::<u8, VMError>($vm.read_exact(1)?[0])
    }};

    // Decode an i32 immediate (little-endian, 4 bytes)
    (@read $vm:ident, ImmI32) => {{
        let bytes = $vm.read_exact(4)?;
        Ok::<i32, VMError>(i32::from_le_bytes(bytes.try_into().unwrap()))
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

    // Decode a u32 reference (little-endian, 4 bytes)
    (@read $vm:ident, RefU32) => {{
        let bytes = $vm.read_exact(4)?;
        Ok::<u32, VMError>(u32::from_le_bytes(bytes.try_into().unwrap()))
    }};

    // Decode a u32 (little-endian, 4 bytes)
    (@read $vm:ident, Addr) => {{
        let tag = $vm.read_exact(1)?[0];
        match tag {
            0 => Ok::<AddrOperand, VMError>(AddrOperand::Reg(exec_vm!(@read $vm, Reg)?)),
            1 => Ok::<AddrOperand, VMError>(AddrOperand::U32(exec_vm!(@read $vm, RefU32)?)),
            _ => Err(VMError::InvalidOperandTag { tag, offset: $vm.ip })
        }
    }};

    // Decode a bool (1 byte, 0 = false, nonzero = true)
    (@read $vm:ident, Src) => {{
        let tag = $vm.read_exact(1)?[0];
        match tag {
            0 => Ok::<SrcOperand, VMError>(SrcOperand::Reg(exec_vm!(@read $vm, Reg)?)),
            1 => Ok::<SrcOperand, VMError>(SrcOperand::Bool(exec_vm!(@read $vm, Reg)? == 1)),
            2 => Ok::<SrcOperand, VMError>(SrcOperand::I64(exec_vm!(@read $vm, ImmI64)?)),
            3 => Ok::<SrcOperand, VMError>(SrcOperand::Ref(exec_vm!(@read $vm, RefU32)?)),
            _ => Err(VMError::InvalidOperandTag { tag, offset: $vm.ip })
        }
    }};
}

/// Execution context passed to the VM during contract execution.
///
/// Contains chain and contract identifiers used to namespace storage keys,
/// as well as gas metering configuration.
pub struct ExecContext {
    /// Chain identifier for storage key derivation.
    pub chain_id: u64,
    /// Contract identifier for storage key derivation.
    pub contract_id: Hash,
}

/// Call stack frame storing return address and destination register.
#[derive(Clone, Debug)]
struct CallFrame {
    /// Return address (bytecode offset to resume after call).
    return_addr: usize,
    /// Destination register for return value.
    dst_reg: u8,
}

/// Bytecode virtual machine.
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
    /// Register file (256 registers).
    registers: Registers,
    /// Heap for const and execution memory.
    heap: Heap,
    /// Call stack for function calls.
    call_stack: Vec<CallFrame>,
    /// Total gas consumed during execution.
    gas_used: u64,
    /// Maximum gas allowed for this execution; exceeding it triggers `OutOfGas`.
    max_gas: u64,
    /// Gas consumption breakdown by category.
    gas_profile: GasProfile,
    /// Arguments passed to the program, loaded into registers by `CALLDATA_LOAD`.
    args: Vec<Value>,
}

/// impl block for basic VM functions
impl VM {
    /// Creates a VM for deploying a contract.
    ///
    /// Concatenates init_code + runtime_code for execution. Use [`run`](Self::run)
    /// to execute from ip=0. For runtime calls, use [`new_execute`](Self::new_execute).
    ///
    /// Returns `OutOfGas` if the base deployment cost exceeds `max_gas`.
    pub fn new_deploy(program: DeployProgram, max_gas: u64) -> Result<Self, VMError> {
        let init_size = program.init_code.len();
        let total_bytes = init_size + program.runtime_code.len();

        // Concatenate init_code + runtime_code
        let mut data = program.init_code;
        data.extend(program.runtime_code);

        let mut vm = Self {
            data,
            ip: 0,
            instr_offset: 0,
            registers: Registers::new(),
            heap: Heap::new(program.memory),
            call_stack: Vec::new(),
            gas_used: 0,
            max_gas,
            gas_profile: GasProfile::new(),
            args: vec![],
        };

        vm.charge_gas_categorized(20_000 + total_bytes as u64 * 200, GasCategory::Deploy)?;
        Ok(vm)
    }

    /// Creates a VM for executing a function call on a deployed contract.
    ///
    /// Seeds `r0` with the function selector and subsequent registers with the
    /// provided arguments. Heap items from the stored contract and any argument
    /// refs are merged so `Value::Ref` indices resolve correctly.
    pub fn new_execute(
        execute: ExecuteProgram,
        deploy: DeployProgram,
        max_gas: u64,
    ) -> Result<Self, VMError> {
        // Build a VM for runtime execution, seeding registers with typed args and extending
        // the heap with any argument-owned items referenced via Value::Ref.
        // Labels are resolved as PC-relative offsets, so init_size is not needed.
        let mut heap = Heap::new(deploy.memory);
        let heap_arg_base = heap.memory.len() as u32;
        for item in execute.arg_items {
            heap.append(item);
        }

        // Pre-remap refs to point to their actual heap locations
        let args: Vec<Value> = execute
            .args
            .into_iter()
            .map(|arg| match arg {
                Value::Ref(r) => Value::Ref(heap_arg_base + r),
                other => other,
            })
            .collect();

        let mut vm = Self {
            data: deploy.runtime_code,
            ip: 0,
            instr_offset: 0,
            registers: Registers::new(),
            heap,
            call_stack: Vec::new(),
            gas_used: 0,
            max_gas,
            gas_profile: GasProfile::new(),
            args,
        };

        vm.registers.set(0, Value::Int(execute.function_id))?;
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
            for (depth, frame) in self.call_stack.iter().rev().enumerate() {
                eprintln!(
                    "  {depth}: return to ip {} -> r{}",
                    frame.return_addr, frame.dst_reg
                );
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

    /// Charges the base gas cost for the given instruction.
    fn charge_base(&mut self, instruction: Instruction) -> Result<(), VMError> {
        self.charge_gas_categorized(instruction.base_gas(), GasCategory::OpcodeBase)
    }

    /// Charges gas for a function call based on argument count and call stack depth.
    ///
    /// Cost formula: `argc * arg_gas_cost + call_depth * depth_gas_cost`
    fn charge_call(
        &mut self,
        argc: u8,
        arg_gas_cost: u64,
        call_depth: usize,
        depth_gas_cost: u64,
    ) -> Result<(), VMError> {
        self.charge_gas_categorized(
            argc as u64 * arg_gas_cost + call_depth as u64 * depth_gas_cost,
            GasCategory::CallOverhead,
        )
    }
}

impl VM {
    fn bool_from_operand(
        &self,
        src_operand: SrcOperand,
        instruction: &'static str,
        argc: usize,
    ) -> Result<bool, VMError> {
        Ok(match src_operand {
            SrcOperand::Reg(idx) => self.registers.get_bool(idx, instruction)?,
            SrcOperand::Bool(b) => b,
            _ => {
                return Err(VMError::InvalidOperand {
                    instruction,
                    argc,
                    expected: SrcOperand::Bool(false).to_string(),
                    actual: src_operand.to_string(),
                });
            }
        })
    }

    fn ref_from_operand(
        &self,
        src_operand: SrcOperand,
        instruction: &'static str,
        argc: usize,
    ) -> Result<u32, VMError> {
        Ok(match src_operand {
            SrcOperand::Reg(idx) => self.registers.get_ref(idx, instruction)?,
            SrcOperand::Ref(r) => r,
            _ => {
                return Err(VMError::InvalidOperand {
                    instruction,
                    argc,
                    expected: SrcOperand::Ref(0).to_string(),
                    actual: src_operand.to_string(),
                });
            }
        })
    }

    fn int_from_operand(
        &self,
        src_operand: SrcOperand,
        instruction: &'static str,
        argc: usize,
    ) -> Result<i64, VMError> {
        Ok(match src_operand {
            SrcOperand::Reg(idx) => self.registers.get_int(idx, instruction)?,
            SrcOperand::I64(i) => i,
            _ => {
                return Err(VMError::InvalidOperand {
                    instruction,
                    argc,
                    expected: SrcOperand::I64(0).to_string(),
                    actual: src_operand.to_string(),
                });
            }
        })
    }

    fn value_from_operand(&self, src_operand: SrcOperand) -> Result<Value, VMError> {
        Ok(match src_operand {
            SrcOperand::Reg(idx) => *self.registers.get(idx)?,
            SrcOperand::Bool(b) => Value::Bool(b),
            SrcOperand::I64(i) => Value::Int(i),
            SrcOperand::Ref(r) => Value::Ref(r),
        })
    }

    fn bytes_from_operand(&mut self, src_operand: SrcOperand) -> Result<Vec<u8>, VMError> {
        Ok(match src_operand {
            SrcOperand::Reg(idx) => match self.registers.get(idx)? {
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
    /// Executes the bytecode from ip=0.
    ///
    /// For deployment, init_code runs first and may call into runtime_code.
    /// For contract calls, use [`new_execute`](Self::new_execute) and then `run`.
    pub fn run<S: State>(&mut self, state: &mut S, ctx: &ExecContext) -> Result<(), VMError> {
        let result = (|| {
            while self.ip < self.data.len() {
                self.instr_offset = self.ip;
                let opcode = self.data[self.instr_offset];
                self.ip += 1;

                let instr =
                    Instruction::try_from(opcode).map_err(|_| VMError::InvalidInstruction {
                        opcode,
                        offset: self.instr_offset,
                    })?;
                self.charge_base(instr)?;
                self.exec(instr, state, ctx)?;
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
        let end = self
            .ip
            .checked_add(count)
            .ok_or(VMError::InvalidIP { ip: self.ip })?;
        let available = self.data.len().saturating_sub(start);

        let slice = self
            .data
            .get(start..end)
            .ok_or(VMError::UnexpectedEndOfBytecode {
                ip: start,
                requested: count,
                available,
            })?;

        self.ip = end;
        Ok(slice)
    }

    /// Executes a single instruction.
    fn exec<S: State>(
        &mut self,
        instruction: Instruction,
        state: &mut S,
        ctx: &ExecContext,
    ) -> Result<(), VMError> {
        exec_vm! {
            vm = self,
            state = state,
            ctx = ctx,
            instr = instruction,
            {
                // Move, Casts and Misc
                Noop => op_noop(),
                Move => op_move(rd: Reg, rs: Src),
                CMove => op_cmove(rd: Reg, cond: Src, r1: Src, r2: Src),
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
                CallHost => op_call_host(dst: Reg, fn_id: RefU32, argc: ImmU8, argv: Reg),
                CallHost0 => op_call_host0(dst: Reg, fn_id: RefU32),
                CallHost1 => op_call_host1(dst: Reg, fn_id: RefU32, arg: Src),
                Call => op_call(dst: Reg, offset: ImmI32, argc: ImmU8, argv: Reg),
                Call0 => op_call0(dst: Reg, fn_id: ImmI32),
                Call1 => op_call1(dst: Reg, fn_id: ImmI32, arg: Reg),
                Jal => op_jal(rd: Reg, offset: ImmI32),
                Jalr => op_jalr(rd: Reg, rs: Reg, offset: ImmI32),
                Beq => op_beq(rs1: Src, rs2: Src, offset: ImmI32),
                Bne => op_bne(rs1: Src, rs2: Src, offset: ImmI32),
                Blt => op_blt(rs1: Src, rs2: Src, offset: ImmI32),
                Bge => op_bge(rs1: Src, rs2: Src, offset: ImmI32),
                Bltu => op_bltu(rs1: Src, rs2: Src, offset: ImmI32),
                Bgeu => op_bgeu(rs1: Src, rs2: Src, offset: ImmI32),
                Jump => op_jump(offset: ImmI32),
                Ret => op_ret(rs: Reg),
                Halt => op_halt(),
                // Data and Memory access
                CallDataLoad => op_call_data_load(rd: Reg),
                CallDataCopy => op_call_data_copy(dst: Addr),
                CallDataLen => op_call_data_len(rd: Reg),
                MemLoad => op_memload(rd: Reg, addr: Addr),
                MemStore => op_memstore(addr: Addr, rs: Src),
                MemCpy => op_memcpy(dst: Addr, src: Addr, len: Addr),
                MemSet => op_memset(dst: Addr, len: Addr, val: ImmU8),
                MemLoad8U => op_memload_8u(rd: Reg, addr: Addr),
                MemLoad8S => op_memload_8s(rd: Reg, addr: Addr),
                MemLoad16U => op_memload_16u(rd: Reg, addr: Addr),
                MemLoad16S => op_memload_16s(rd: Reg, addr: Addr),
                MemLoad32U => op_memload_32u(rd: Reg, addr: Addr),
                MemLoad32S => op_memload_32s(rd: Reg, addr: Addr),
                // Special Op Codes
                Dispatch => op_dispatch(),
            }
        }
    }

    fn op_noop(&self, _instr: &'static str) -> Result<(), VMError> {
        Ok(())
    }

    fn op_move(&mut self, _instr: &'static str, dst: u8, src: SrcOperand) -> Result<(), VMError> {
        let v: Value = match src {
            SrcOperand::Reg(idx) => *self.registers.get(idx)?,
            SrcOperand::Bool(b) => Value::Bool(b),
            SrcOperand::I64(i) => Value::Int(i),
            SrcOperand::Ref(r) => Value::Ref(r),
        };
        self.registers.set(dst, v)
    }

    /// Conditional move: `dst = cond ? r1 : r2`.
    ///
    /// If `cond` is truthy (non-zero integer or `true`), moves `r1` to `dst`;
    /// otherwise moves `r2` to `dst`. Reference operands for `cond` are rejected.
    fn op_cmove(
        &mut self,
        instr: &'static str,
        dst: u8,
        cond: SrcOperand,
        r1: SrcOperand,
        r2: SrcOperand,
    ) -> Result<(), VMError> {
        let v: bool = match cond {
            SrcOperand::Reg(idx) => match *self.registers.get(idx)? {
                Value::Bool(b) => b,
                Value::Ref(_) => {
                    return Err(VMError::TypeMismatchStatic {
                        instruction: instr,
                        arg_index: 2,
                        expected: "Boolean or Integer",
                        actual: "Reference",
                    });
                }
                Value::Int(i) => i != 0,
            },
            SrcOperand::Bool(b) => b,
            SrcOperand::I64(i) => i != 0,
            SrcOperand::Ref(_) => {
                return Err(VMError::TypeMismatchStatic {
                    instruction: instr,
                    arg_index: 2,
                    expected: "Boolean or Integer",
                    actual: "Reference",
                });
            }
        };

        let value = if v { r1 } else { r2 };
        self.op_move(instr, dst, value)
    }

    fn op_i64_to_bool(
        &mut self,
        instr: &'static str,
        dst: u8,
        src: SrcOperand,
    ) -> Result<(), VMError> {
        let v = self.int_from_operand(src, instr, 1)?;
        self.registers.set(dst, Value::Bool(v != 0))
    }

    fn op_bool_to_i64(
        &mut self,
        instr: &'static str,
        dst: u8,
        src: SrcOperand,
    ) -> Result<(), VMError> {
        let v = self.bool_from_operand(src, instr, 1)?;
        self.registers.set(dst, Value::Int(if v { 1 } else { 0 }))
    }

    fn op_str_to_i64(
        &mut self,
        instr: &'static str,
        dst: u8,
        src: SrcOperand,
    ) -> Result<(), VMError> {
        let reg = self.ref_from_operand(src, instr, 1)?;
        let str = self.heap_get_string(reg)?;
        self.registers
            .set(dst, Value::Int(parse_i64_or_hex(&str, 0, 0)?))
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
        instr: &'static str,
        dst: u8,
        src: SrcOperand,
    ) -> Result<(), VMError> {
        let reg = self.int_from_operand(src, instr, 1)?;
        // Charge gas manually before allocation instead of using heap_index()
        self.charge_gas_categorized(Self::digits_i64(reg), GasCategory::HeapAllocation)?;
        let str_ref = self.heap.append(reg.to_string().into_bytes());
        self.registers.set(dst, Value::Ref(str_ref))
    }

    fn op_str_to_bool(
        &mut self,
        instr: &'static str,
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
                instruction: instr,
                arg_index: 1,
                expected: "\"true\" or \"false\"",
                actual: str,
            });
        };
        self.registers.set(dst, Value::Bool(b))
    }

    fn op_bool_to_str(
        &mut self,
        instr: &'static str,
        dst: u8,
        src: SrcOperand,
    ) -> Result<(), VMError> {
        let reg = self.bool_from_operand(src, instr, 1)?;
        // Charge gas manually before allocation instead of using heap_index()
        self.charge_gas_categorized(if reg { 4 } else { 5 }, GasCategory::HeapAllocation)?;
        let str = (if reg { "true" } else { "false" }).to_string();
        let bool_ref = self.heap.append(str.into_bytes());
        self.registers.set(dst, Value::Ref(bool_ref))
    }

    fn op_delete_state<S: State>(
        &mut self,
        _instr: &'static str,
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
        _instr: &'static str,
        state: &mut S,
        ctx: &ExecContext,
        dst: u8,
        key: SrcOperand,
    ) -> Result<(), VMError> {
        let key_ref = self.bytes_from_operand(key)?;
        let key = self.make_state_key(ctx.chain_id, &ctx.contract_id, &key_ref)?;
        self.registers
            .set(dst, Value::Bool(state.contains_key(key)))
    }

    fn op_store_bytes<S: State>(
        &mut self,
        _instr: &'static str,
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
        _instr: &'static str,
        state: &mut S,
        ctx: &ExecContext,
        dst: u8,
        key: SrcOperand,
    ) -> Result<(), VMError> {
        let (_, value) = self.load_state_bytes(state, ctx, key)?;
        let index = self.heap_index(value)?;
        self.registers.set(dst, Value::Ref(index))
    }

    fn op_load_i64<S: State>(
        &mut self,
        _instr: &'static str,
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
            .set(dst, Value::Int(i64::from_le_bytes(bytes)))
    }

    fn op_load_bool<S: State>(
        &mut self,
        _instr: &'static str,
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
        self.registers.set(dst, Value::Bool(value[0] != 0))
    }

    fn op_load_str<S: State>(
        &mut self,
        _instr: &'static str,
        state: &mut S,
        ctx: &ExecContext,
        dst: u8,
        key: SrcOperand,
    ) -> Result<(), VMError> {
        let (_, value) = self.load_state_bytes(state, ctx, key)?;
        let str_ref = self.heap_index(value)?;
        self.registers.set(dst, Value::Ref(str_ref))
    }

    fn op_load_hash<S: State>(
        &mut self,
        _instr: &'static str,
        state: &mut S,
        ctx: &ExecContext,
        dst: u8,
        key: SrcOperand,
    ) -> Result<(), VMError> {
        let (_, value) = self.load_state_bytes(state, ctx, key)?;
        let hash_ref = self.heap_index(value)?;
        self.registers.set(dst, Value::Ref(hash_ref))
    }

    fn op_add(
        &mut self,
        instr: &'static str,
        dst: u8,
        a: SrcOperand,
        b: SrcOperand,
    ) -> Result<(), VMError> {
        let va = self.int_from_operand(a, instr, 1)?;
        let vb = self.int_from_operand(b, instr, 2)?;
        self.registers.set(dst, Value::Int(va.wrapping_add(vb)))
    }

    fn op_sub(
        &mut self,
        instr: &'static str,
        dst: u8,
        a: SrcOperand,
        b: SrcOperand,
    ) -> Result<(), VMError> {
        let va = self.int_from_operand(a, instr, 1)?;
        let vb = self.int_from_operand(b, instr, 2)?;
        self.registers.set(dst, Value::Int(va.wrapping_sub(vb)))
    }

    fn op_mul(
        &mut self,
        instr: &'static str,
        dst: u8,
        a: SrcOperand,
        b: SrcOperand,
    ) -> Result<(), VMError> {
        let va = self.int_from_operand(a, instr, 1)?;
        let vb = self.int_from_operand(b, instr, 2)?;
        self.registers.set(dst, Value::Int(va.wrapping_mul(vb)))
    }

    fn op_div(
        &mut self,
        instr: &'static str,
        dst: u8,
        a: SrcOperand,
        b: SrcOperand,
    ) -> Result<(), VMError> {
        let va = self.int_from_operand(a, instr, 1)?;
        let vb = self.int_from_operand(b, instr, 2)?;
        if vb == 0 {
            return Err(VMError::DivisionByZero);
        }
        self.registers.set(dst, Value::Int(va.wrapping_div(vb)))
    }

    fn op_mod(
        &mut self,
        instr: &'static str,
        dst: u8,
        a: SrcOperand,
        b: SrcOperand,
    ) -> Result<(), VMError> {
        let va = self.int_from_operand(a, instr, 1)?;
        let vb = self.int_from_operand(b, instr, 2)?;
        if vb == 0 {
            return Err(VMError::DivisionByZero);
        }
        self.registers.set(dst, Value::Int(va.wrapping_rem(vb)))
    }

    fn op_neg(&mut self, instr: &'static str, dst: u8, src: SrcOperand) -> Result<(), VMError> {
        let v = self.int_from_operand(src, instr, 1)?;
        self.registers.set(dst, Value::Int(v.wrapping_neg()))
    }

    fn op_abs(&mut self, instr: &'static str, dst: u8, src: SrcOperand) -> Result<(), VMError> {
        let v = self.int_from_operand(src, instr, 1)?;
        self.registers.set(dst, Value::Int(v.wrapping_abs()))
    }

    fn op_min(
        &mut self,
        instr: &'static str,
        dst: u8,
        a: SrcOperand,
        b: SrcOperand,
    ) -> Result<(), VMError> {
        let va = self.int_from_operand(a, instr, 1)?;
        let vb = self.int_from_operand(b, instr, 2)?;
        self.registers.set(dst, Value::Int(va.min(vb)))
    }

    fn op_max(
        &mut self,
        instr: &'static str,
        dst: u8,
        a: SrcOperand,
        b: SrcOperand,
    ) -> Result<(), VMError> {
        let va = self.int_from_operand(a, instr, 1)?;
        let vb = self.int_from_operand(b, instr, 2)?;
        self.registers.set(dst, Value::Int(va.max(vb)))
    }

    fn op_shl(
        &mut self,
        instr: &'static str,
        dst: u8,
        a: SrcOperand,
        b: SrcOperand,
    ) -> Result<(), VMError> {
        let va = self.int_from_operand(a, instr, 1)?;
        let vb = self.int_from_operand(b, instr, 2)?;
        self.registers
            .set(dst, Value::Int(va.wrapping_shl(vb as u32)))
    }

    fn op_shr(
        &mut self,
        instr: &'static str,
        dst: u8,
        a: SrcOperand,
        b: SrcOperand,
    ) -> Result<(), VMError> {
        let va = self.int_from_operand(a, instr, 1)?;
        let vb = self.int_from_operand(b, instr, 2)?;
        self.registers
            .set(dst, Value::Int(va.wrapping_shr(vb as u32)))
    }

    fn op_inc(&mut self, instr: &'static str, dst: u8) -> Result<(), VMError> {
        let r = self.registers.get_int(dst, instr)?;
        self.registers.set(dst, Value::Int(r.wrapping_add(1)))
    }

    fn op_dec(&mut self, instr: &'static str, dst: u8) -> Result<(), VMError> {
        let r = self.registers.get_int(dst, instr)?;
        self.registers.set(dst, Value::Int(r.wrapping_sub(1)))
    }

    fn op_not(&mut self, instr: &'static str, dst: u8, src: SrcOperand) -> Result<(), VMError> {
        let v = self.bool_from_operand(src, instr, 1)?;
        self.registers.set(dst, Value::Bool(!v))
    }

    fn op_and(
        &mut self,
        instr: &'static str,
        dst: u8,
        a: SrcOperand,
        b: SrcOperand,
    ) -> Result<(), VMError> {
        let va = self.bool_from_operand(a, instr, 1)?;
        let vb = self.bool_from_operand(b, instr, 2)?;
        self.registers.set(dst, Value::Bool(va && vb))
    }

    fn op_or(
        &mut self,
        instr: &'static str,
        dst: u8,
        a: SrcOperand,
        b: SrcOperand,
    ) -> Result<(), VMError> {
        let va = self.bool_from_operand(a, instr, 1)?;
        let vb = self.bool_from_operand(b, instr, 2)?;
        self.registers.set(dst, Value::Bool(va || vb))
    }

    fn op_xor(
        &mut self,
        instr: &'static str,
        dst: u8,
        a: SrcOperand,
        b: SrcOperand,
    ) -> Result<(), VMError> {
        let va = self.bool_from_operand(a, instr, 1)?;
        let vb = self.bool_from_operand(b, instr, 2)?;
        self.registers.set(dst, Value::Bool(va ^ vb))
    }

    fn op_eq(
        &mut self,
        _instr: &'static str,
        dst: u8,
        a: SrcOperand,
        b: SrcOperand,
    ) -> Result<(), VMError> {
        let va = self.value_from_operand(a)?;
        let vb = self.value_from_operand(b)?;
        self.registers.set(dst, Value::Bool(Value::equals(va, vb)?))
    }

    fn op_ne(
        &mut self,
        _instr: &'static str,
        dst: u8,
        a: SrcOperand,
        b: SrcOperand,
    ) -> Result<(), VMError> {
        let va = self.value_from_operand(a)?;
        let vb = self.value_from_operand(b)?;
        self.registers
            .set(dst, Value::Bool(!Value::equals(va, vb)?))
    }

    fn op_lt(
        &mut self,
        instr: &'static str,
        dst: u8,
        a: SrcOperand,
        b: SrcOperand,
    ) -> Result<(), VMError> {
        let va = self.int_from_operand(a, instr, 1)?;
        let vb = self.int_from_operand(b, instr, 2)?;
        self.registers.set(dst, Value::Bool(va < vb))
    }

    fn op_gt(
        &mut self,
        instr: &'static str,
        dst: u8,
        a: SrcOperand,
        b: SrcOperand,
    ) -> Result<(), VMError> {
        let va = self.int_from_operand(a, instr, 1)?;
        let vb = self.int_from_operand(b, instr, 2)?;
        self.registers.set(dst, Value::Bool(va > vb))
    }

    fn op_le(
        &mut self,
        instr: &'static str,
        dst: u8,
        a: SrcOperand,
        b: SrcOperand,
    ) -> Result<(), VMError> {
        let va = self.int_from_operand(a, instr, 1)?;
        let vb = self.int_from_operand(b, instr, 2)?;
        self.registers.set(dst, Value::Bool(va <= vb))
    }

    fn op_ge(
        &mut self,
        instr: &'static str,
        dst: u8,
        a: SrcOperand,
        b: SrcOperand,
    ) -> Result<(), VMError> {
        let va = self.int_from_operand(a, instr, 1)?;
        let vb = self.int_from_operand(b, instr, 2)?;
        self.registers.set(dst, Value::Bool(va >= vb))
    }

    fn op_call_host(
        &mut self,
        _instr: &'static str,
        dst: u8,
        fn_id: u32,
        argc: u8,
        argv: u8,
    ) -> Result<(), VMError> {
        self.charge_call(argc, 5, self.call_stack.len(), 10)?;
        let fn_name = self.heap_get_string(fn_id)?;
        let args: Vec<Value> = (0..argc)
            .map(|i| self.registers.get(argv.wrapping_add(i)).copied())
            .collect::<Result<_, _>>()?;

        /// Returns an error if actual != expected
        fn arg_len_check(expected: u8, actual: u8, name: &str) -> Result<(), VMError> {
            if actual != expected {
                return Err(VMError::ArityMismatch {
                    instruction: format!("CALL_HOST reg, \"{name}\""),
                    expected,
                    actual,
                });
            }
            Ok(())
        }

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
            SLICE => {
                arg_len_check(host_func_argc(SLICE), args.len() as u8, SLICE)?;
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
                self.registers.set(dst, Value::Ref(new_ref))
            }
            CONCAT => {
                arg_len_check(host_func_argc(CONCAT), args.len() as u8, CONCAT)?;
                let ref1 = get_ref(args[0])?;
                let ref2 = get_ref(args[1])?;

                let len1 = self.heap.get_data(ref1)?.len();
                let len2 = self.heap.get_data(ref2)?.len();
                self.charge_gas_categorized((len1 + len2) as u64, GasCategory::HostFunction)?;

                let mut result = self.heap.get_data(ref1)?.to_vec();
                result.extend_from_slice(self.heap.get_data(ref2)?);

                let new_ref = self.heap_index(result)?;
                self.registers.set(dst, Value::Ref(new_ref))
            }
            COMPARE => {
                arg_len_check(host_func_argc(COMPARE), args.len() as u8, COMPARE)?;
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
                self.registers.set(dst, Value::Int(cmp))
            }
            _ => Err(VMError::InvalidCallHostFunction { name: fn_name }),
        }
    }

    fn op_call_host0(&mut self, instr: &'static str, dst: u8, fn_id: u32) -> Result<(), VMError> {
        self.op_call_host(instr, dst, fn_id, 0, 0)
    }

    fn op_call_host1(
        &mut self,
        instr: &'static str,
        dst: u8,
        fn_id: u32,
        arg: SrcOperand,
    ) -> Result<(), VMError> {
        self.charge_call(1, 5, self.call_stack.len(), 10)?;
        let fn_name = self.heap_get_string(fn_id)?;

        match fn_name.as_str() {
            LEN => {
                let str_ref = self.ref_from_operand(arg, instr, 1)?;
                let len = self.heap.get_data(str_ref)?.len();
                self.charge_gas_categorized(len as u64, GasCategory::HostFunction)?;
                self.registers.set(dst, Value::Int(len as i64))
            }
            HASH => {
                let value = self.value_from_operand(arg)?;
                let len = match value {
                    Value::Bool(_) => 1,
                    Value::Int(_) => 8,
                    Value::Ref(r) => self.heap.get_data(r)?.len(),
                };
                self.charge_gas_categorized(len as u64, GasCategory::HostFunction)?;

                let hash = match value {
                    Value::Bool(b) => Hash::sha3().chain(&[b as u8]).finalize(),
                    Value::Ref(r) => Hash::sha3().chain(self.heap.get_data(r)?).finalize(),
                    Value::Int(i) => Hash::sha3().chain(&i.to_le_bytes()).finalize(),
                };
                let new_ref = self.heap_index(hash.to_vec())?;
                self.registers.set(dst, Value::Ref(new_ref))
            }
            _ => Err(VMError::InvalidCallHostFunction { name: fn_name }),
        }
    }

    fn op_call(
        &mut self,
        instr: &'static str,
        dst: u8,
        offset: i32,
        argc: u8,
        _argv: u8,
    ) -> Result<(), VMError> {
        self.charge_call(argc, 5, self.call_stack.len(), 10)?;

        if self.call_stack.len() >= MAX_CALL_STACK_LEN {
            return Err(VMError::CallStackOverflow {
                max: MAX_CALL_STACK_LEN,
                actual: self.call_stack.len(),
            });
        }

        self.call_stack.push(CallFrame {
            return_addr: self.ip,
            dst_reg: dst,
        });

        self.op_jump(instr, offset)
    }

    fn op_call0(&mut self, instr: &'static str, dst: u8, fn_id: i32) -> Result<(), VMError> {
        self.op_call(instr, dst, fn_id, 0, 0)
    }

    fn op_call1(
        &mut self,
        instr: &'static str,
        dst: u8,
        fn_id: i32,
        arg: u8,
    ) -> Result<(), VMError> {
        self.op_call(instr, dst, fn_id, 1, arg)
    }

    fn op_jal(&mut self, instr: &'static str, rd: u8, offset: i32) -> Result<(), VMError> {
        self.registers.set(rd, Value::Int(self.ip as i64))?;
        self.op_jump(instr, offset)
    }

    fn op_jalr(&mut self, instr: &'static str, rd: u8, rs: u8, offset: i32) -> Result<(), VMError> {
        let base = self.registers.get_int(rs, instr)?;
        self.registers.set(rd, Value::Int(self.ip as i64))?;
        self.ip = base as usize;
        self.op_jump(instr, offset)
    }

    fn op_beq(
        &mut self,
        instr: &'static str,
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
        instr: &'static str,
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
        instr: &'static str,
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
        instr: &'static str,
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
        instr: &'static str,
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
        instr: &'static str,
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

    fn op_jump(&mut self, _instr: &'static str, offset: i32) -> Result<(), VMError> {
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

    fn op_ret(&mut self, _instr: &'static str, rs: u8) -> Result<(), VMError> {
        let frame = self.call_stack.pop().ok_or(VMError::ReturnWithoutCall {
            call_depth: self.call_stack.len(),
        })?;

        let ret_val = *self.registers.get(rs)?;
        self.registers.set(frame.dst_reg, ret_val)?;
        self.ip = frame.return_addr;
        Ok(())
    }

    fn op_halt(&mut self, _instr: &'static str) -> Result<(), VMError> {
        // Move IP to the end to exit the execution loop cleanly.
        self.ip = self.data.len();
        Ok(())
    }

    fn op_call_data_load(&mut self, _instr: &'static str, dst: u8) -> Result<(), VMError> {
        for (i, arg) in self.args.iter().enumerate() {
            self.registers.set(dst + i as u8, *arg)?;
        }
        Ok(())
    }

    fn op_call_data_copy(&mut self, instr: &'static str, dst: AddrOperand) -> Result<(), VMError> {
        let bytes = self.args_to_vec();
        let len = bytes.len() as u32;
        self.op_memset(instr, dst.clone(), AddrOperand::U32(len), 0x00)?;
        let dst = self.addr_operand_to_u32(instr, dst)? as usize;
        self.heap[dst..dst + bytes.len()].copy_from_slice(&bytes);
        Ok(())
    }

    fn op_call_data_len(&mut self, _instr: &'static str, dst: u8) -> Result<(), VMError> {
        let size = self.args_to_vec().len();
        self.registers.set(dst, Value::Int(size as i64))
    }

    /// Ensures execution memory spans `[base, base + len)`.
    ///
    /// Memory grows in word-sized chunks and charges gas proportional to the
    /// number of bytes expanded.
    fn expand_memory(&mut self, base: usize, len: usize) -> Result<(), VMError> {
        let max = base.saturating_add(len);
        if self.heap.len() < max {
            let expanded = max.saturating_sub(self.heap.len()) * WORD_SIZE;
            self.charge_gas_categorized(expanded as u64 * 5, GasCategory::Memory)?;
            self.heap
                .resize(self.heap.len().saturating_add(expanded), 0);
        }

        Ok(())
    }

    /// Resolves an address operand to a concrete u32 value.
    ///
    /// For immediate addresses, returns the value directly. For register addresses,
    /// reads the integer value from the register and truncates to u32.
    fn addr_operand_to_u32(&self, instr: &'static str, addr: AddrOperand) -> Result<u32, VMError> {
        Ok(match addr {
            AddrOperand::U32(u) => u,
            AddrOperand::Reg(r) => self.registers.get_int(r, instr)? as u32,
        })
    }

    /// Loads `COUNT` bytes from memory into a register with sign/zero extension.
    ///
    /// Reads `COUNT` bytes from the heap at the given address and extends to 64-bit.
    /// If `unsigned` is true, zero-extends; otherwise sign-extends based on the
    /// most significant bit of the loaded value.
    fn memload<const COUNT: usize>(
        &mut self,
        instr: &'static str,
        rd: u8,
        addr: AddrOperand,
        unsigned: bool,
    ) -> Result<(), VMError> {
        let addr = self.addr_operand_to_u32(instr, addr)? as usize;
        if addr + WORD_SIZE > self.heap.len() {
            return Err(VMError::MemoryOOBRead {
                got: addr + WORD_SIZE,
                max: self.heap.len(),
            });
        }

        // Load the requested number of bytes
        let mut result: [u8; WORD_SIZE] = [0u8; WORD_SIZE];
        result[..COUNT].copy_from_slice(&self.heap[addr..addr + COUNT]);
        // Sign or Zero extend the bytes
        let extension: u8 = if !unsigned && (result[COUNT - 1] >> 7) != 0 {
            0xFF
        } else {
            0
        };
        result[COUNT..].fill(extension);

        self.registers
            .set(rd, Value::Int(i64::from_le_bytes(result)))
    }

    fn op_memload(
        &mut self,
        instr: &'static str,
        rd: u8,
        addr: AddrOperand,
    ) -> Result<(), VMError> {
        self.memload::<WORD_SIZE>(instr, rd, addr, true)
    }

    fn op_memstore(
        &mut self,
        instr: &'static str,
        addr: AddrOperand,
        rs: SrcOperand,
    ) -> Result<(), VMError> {
        let addr = self.addr_operand_to_u32(instr, addr)? as usize;
        error!("{} {} {}", addr, self.heap.len(), self.ip);
        self.expand_memory(addr, WORD_SIZE)?;

        let value = self.int_from_operand(rs, instr, 2)?;
        let data = value.to_le_bytes();
        self.heap[addr..addr + WORD_SIZE].copy_from_slice(&data);

        Ok(())
    }

    fn op_memcpy(
        &mut self,
        instr: &'static str,
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
        self.heap.copy_within(src..src + len, dst);

        Ok(())
    }

    fn op_memset(
        &mut self,
        instr: &'static str,
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
        self.heap[dst..dst + len].fill(val);
        Ok(())
    }

    /// Dispatches to a public function by selector index.
    ///
    /// Reads an inline table of `(offset_i32, argr)` entries from bytecode.
    /// Uses `r0` as the selector index, loads call arguments via `CALLDATA_LOAD`
    /// semantics into the entry's `argr`, calls the target function, and halts.
    fn op_dispatch(&mut self, instr: &'static str) -> Result<(), VMError> {
        let count = self.read_exact(1)?[0] as usize;
        let selector = match self.registers.get(0)? {
            Value::Int(i) => *i as usize,
            other => {
                return Err(VMError::TypeMismatch {
                    instruction: instr,
                    arg_index: 0,
                    expected: "Integer",
                    actual: other.type_name().to_string(),
                });
            }
        };
        if selector >= count {
            return Err(VMError::DispatchOutOfBounds { selector, count });
        }
        // Skip entries before the selected one (each entry = 4 + 1 = 5 bytes)
        if selector > 0 {
            self.read_exact(selector * 5)?;
        }
        // Read the selected entry
        let entry_bytes = self.read_exact(5)?;
        let offset = i32::from_le_bytes(entry_bytes[0..4].try_into().unwrap());
        let argr = entry_bytes[4];
        // Skip remaining entries
        let remaining = count - selector - 1;
        if remaining > 0 {
            self.read_exact(remaining * 5)?;
        }
        // Load call arguments into registers starting at argr
        self.op_call_data_load(instr, argr)?;
        // Push a call frame whose return address is past all bytecode,
        // so RET will cause the main loop to exit cleanly (like HALT).
        self.call_stack.push(CallFrame {
            return_addr: self.data.len(),
            dst_reg: 0,
        });
        // Jump to the target function
        self.op_jump(instr, offset)
    }

    fn op_memload_8u(
        &mut self,
        instr: &'static str,
        rd: u8,
        addr: AddrOperand,
    ) -> Result<(), VMError> {
        self.memload::<BYTE_SIZE>(instr, rd, addr, true)
    }

    fn op_memload_8s(
        &mut self,
        instr: &'static str,
        rd: u8,
        addr: AddrOperand,
    ) -> Result<(), VMError> {
        self.memload::<BYTE_SIZE>(instr, rd, addr, false)
    }

    fn op_memload_16u(
        &mut self,
        instr: &'static str,
        rd: u8,
        addr: AddrOperand,
    ) -> Result<(), VMError> {
        self.memload::<QUARTER_WORD_SIZE>(instr, rd, addr, true)
    }

    fn op_memload_16s(
        &mut self,
        instr: &'static str,
        rd: u8,
        addr: AddrOperand,
    ) -> Result<(), VMError> {
        self.memload::<QUARTER_WORD_SIZE>(instr, rd, addr, false)
    }

    fn op_memload_32u(
        &mut self,
        instr: &'static str,
        rd: u8,
        addr: AddrOperand,
    ) -> Result<(), VMError> {
        self.memload::<HALF_WORD_SIZE>(instr, rd, addr, true)
    }

    fn op_memload_32s(
        &mut self,
        instr: &'static str,
        rd: u8,
        addr: AddrOperand,
    ) -> Result<(), VMError> {
        self.memload::<HALF_WORD_SIZE>(instr, rd, addr, false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::virtual_machine::assembler::assemble_source;
    use crate::virtual_machine::program::{DeployProgram, ExecuteProgram};
    use crate::virtual_machine::state::tests::TestState;

    impl VM {
        /// Creates a new VM instance with the given program and gas limits.
        ///
        /// Immediately charges `init_cost` gas. Returns `OutOfGas` if `init_cost` exceeds `max_gas`.
        pub fn new_with_init(
            program: DeployProgram,
            init_cost: u64,
            max_gas: u64,
        ) -> Result<Self, VMError> {
            let mut data = program.init_code;
            data.extend(program.runtime_code);

            let mut vm = Self {
                data,
                ip: 0,
                instr_offset: 0,
                registers: Registers::new(),
                heap: Heap::new(program.memory),
                call_stack: Vec::new(),
                gas_used: 0,
                max_gas,
                gas_profile: GasProfile::new(),
                args: vec![],
            };

            vm.charge_gas_categorized(init_cost, GasCategory::Deploy)?;
            Ok(vm)
        }

        /// Returns a slice of the execution memory.
        fn exec_memory(&self) -> &[u8] {
            self.heap.exec_memory()
        }
    }

    impl Heap {
        /// Retrieves a hash by its reference index.
        fn get_hash(&self, id: u32) -> Result<Hash, VMError> {
            let bytes = self.get_raw_ref(id)?;
            match Hash::from_slice(&bytes[WORD_SIZE..]) {
                None => Err(VMError::InvalidHash {
                    expected_len: HASH_LEN,
                    actual_len: bytes.len(),
                }),
                Some(hash) => Ok(hash),
            }
        }
    }

    const EXECUTION_CONTEXT: &ExecContext = &ExecContext {
        chain_id: 62845383663927,
        contract_id: Hash::zero(),
    };

    fn run_vm(source: &str) -> VM {
        let program = assemble_source(source).expect("assembly failed");
        let mut vm = VM::new_with_init(program, 0, BLOCK_GAS_LIMIT).expect("vm new failed");
        vm.run(&mut TestState::new(), EXECUTION_CONTEXT)
            .expect("vm run failed");
        vm
    }

    fn run_and_get_int(source: &str, reg: u8) -> i64 {
        run_vm(source).registers.get_int(reg, "").unwrap()
    }

    fn run_and_get_bool(source: &str, reg: u8) -> bool {
        run_vm(source).registers.get_bool(reg, "").unwrap()
    }

    fn run_and_get_str(source: &str, reg: u8) -> String {
        let vm = run_vm(source);
        let r = vm.registers.get_ref(reg, "").unwrap();
        vm.heap.get_string(r).unwrap()
    }

    fn run_expect_err(source: &str) -> VMError {
        let program = match assemble_source(source) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let mut vm = VM::new_with_init(program, 0, BLOCK_GAS_LIMIT).expect("vm new failed");
        vm.run(&mut TestState::new(), EXECUTION_CONTEXT)
            .expect_err("expected error")
    }

    fn run_vm_with_state(source: &str) -> TestState {
        let program = assemble_source(source).expect("assembly failed");
        let mut vm = VM::new_with_init(program, 0, BLOCK_GAS_LIMIT).expect("vm new failed");
        let mut state = TestState::new();
        vm.run(&mut state, EXECUTION_CONTEXT)
            .expect("vm run failed");
        state
    }

    // ==================== Loads ====================

    #[test]
    fn load_i64() {
        assert_eq!(run_and_get_int("MOVE r0, 42", 0), 42);
        assert_eq!(run_and_get_int("MOVE r0, -1", 0), -1);
        assert_eq!(run_and_get_int("MOVE r0, 0", 0), 0);
    }

    #[test]
    fn load_bool() {
        assert!(run_and_get_bool("MOVE r0, true", 0));
        assert!(!run_and_get_bool("MOVE r0, false", 0));
    }

    #[test]
    fn load_str() {
        let vm = run_vm(r#"MOVE r0, "hello""#);
        let ref_id = vm.registers.get_ref(0, "").unwrap();
        assert_eq!(vm.heap.get_string(ref_id).unwrap(), "hello");
    }

    #[test]
    fn load_hash() {
        let vm = run_vm(r#"MOVE r0, "00000000000000000000000000000000""#);
        let ref_id = vm.registers.get_ref(0, "").unwrap();
        let expected = Hash::from_slice(b"00000000000000000000000000000000").unwrap();
        assert_eq!(vm.heap.get_hash(ref_id).unwrap(), expected);
    }

    #[test]
    fn noop_does_not_modify_registers() {
        let vm = run_vm("MOVE r0, 7\nNOOP");
        assert_eq!(vm.registers.get_int(0, "").unwrap(), 7);
    }

    // ==================== Moves / Casts ====================

    #[test]
    fn move_int() {
        assert_eq!(run_and_get_int("MOVE r0, 99\nMOVE r1, r0", 1), 99);
    }

    #[test]
    fn move_bool() {
        assert!(run_and_get_bool("MOVE r0, true\nMOVE r1, r0", 1));
    }

    #[test]
    fn i64_to_bool() {
        assert!(run_and_get_bool("MOVE r0, 1\nI64_TO_BOOL r1, r0", 1));
        assert!(run_and_get_bool("MOVE r0, -5\nI64_TO_BOOL r1, r0", 1));
        assert!(!run_and_get_bool("MOVE r0, 0\nI64_TO_BOOL r1, r0", 1));
    }

    #[test]
    fn bool_to_i64() {
        assert_eq!(run_and_get_int("MOVE r0, true\nBOOL_TO_I64 r1, r0", 1), 1);
        assert_eq!(run_and_get_int("MOVE r0, false\nBOOL_TO_I64 r1, r0", 1), 0);
    }

    #[test]
    fn str_to_i64_parses_numbers() {
        assert_eq!(
            run_and_get_int(
                r#"
                MOVE r0, "12345"
                STR_TO_I64 r1, r0
            "#,
                1
            ),
            12345
        );
        assert_eq!(
            run_and_get_int(
                r#"
                MOVE r0, "-7"
                STR_TO_I64 r1, r0
            "#,
                1
            ),
            -7
        );
    }

    #[test]
    fn str_to_i64_rejects_non_numbers() {
        assert!(matches!(
            run_expect_err(
                r#"
                MOVE r0, "abc"
                STR_TO_I64 r1, r0
            "#
            ),
            VMError::ParseErrorString { .. }
        ));
    }

    #[test]
    fn i64_to_str_round_trips() {
        assert_eq!(
            run_and_get_int("MOVE r0, -99\nI64_TO_STR r1, r0\nSTR_TO_I64 r2, r1", 2),
            -99
        );
        assert_eq!(run_and_get_str("MOVE r0, -99\nI64_TO_STR r1, r0", 1), "-99");
    }

    #[test]
    fn str_to_bool_accepts_true_and_false() {
        assert!(run_and_get_bool(
            r#"
            MOVE r0, "true"
            STR_TO_BOOL r1, r0
            "#,
            1
        ));
        assert!(!run_and_get_bool(
            r#"
            MOVE r0, "false"
            STR_TO_BOOL r1, r0
            "#,
            1
        ));
    }

    #[test]
    fn str_to_bool_rejects_other_strings() {
        assert!(matches!(
            run_expect_err(
                r#"
                MOVE r0, "notabool"
                STR_TO_BOOL r1, r0
            "#
            ),
            VMError::TypeMismatch {
                instruction: "STR_TO_BOOL",
                ..
            }
        ));
    }

    #[test]
    fn bool_to_str_round_trips() {
        assert_eq!(
            run_and_get_str("MOVE r0, true\nBOOL_TO_STR r1, r0", 1),
            "true"
        );
        assert!(run_and_get_bool(
            "MOVE r0, true\nBOOL_TO_STR r1, r0\nSTR_TO_BOOL r2, r1",
            2
        ));
        assert!(!run_and_get_bool(
            "MOVE r0, false\nBOOL_TO_STR r1, r0\nSTR_TO_BOOL r2, r1",
            2
        ));
    }

    // ==================== Arithmetic ====================

    #[test]
    fn add() {
        assert_eq!(
            run_and_get_int("MOVE r0, 10\nMOVE r1, 32\nADD r2, r0, r1", 2),
            42
        );
    }

    #[test]
    fn add_wrapping() {
        let source = "MOVE r0, 9223372036854775807\nMOVE r1, 1\nADD r2, r0, r1";
        assert_eq!(run_and_get_int(source, 2), i64::MIN);
    }

    #[test]
    fn sub() {
        assert_eq!(
            run_and_get_int("MOVE r0, 50\nMOVE r1, 8\nSUB r2, r0, r1", 2),
            42
        );
    }

    #[test]
    fn mul() {
        assert_eq!(
            run_and_get_int("MOVE r0, 6\nMOVE r1, 7\nMUL r2, r0, r1", 2),
            42
        );
    }

    #[test]
    fn div() {
        assert_eq!(
            run_and_get_int("MOVE r0, 84\nMOVE r1, 2\nDIV r2, r0, r1", 2),
            42
        );
    }

    #[test]
    fn div_by_zero() {
        assert!(matches!(
            run_expect_err("MOVE r0, 1\nMOVE r1, 0\nDIV r2, r0, r1"),
            VMError::DivisionByZero
        ));
    }

    #[test]
    fn modulo() {
        assert_eq!(
            run_and_get_int("MOVE r0, 47\nMOVE r1, 5\nMOD r2, r0, r1", 2),
            2
        );
    }

    #[test]
    fn mod_by_zero() {
        assert!(matches!(
            run_expect_err("MOVE r0, 1\nMOVE r1, 0\nMOD r2, r0, r1"),
            VMError::DivisionByZero
        ));
    }

    #[test]
    fn neg() {
        assert_eq!(run_and_get_int("MOVE r0, 42\nNEG r1, r0", 1), -42);
    }

    #[test]
    fn abs() {
        assert_eq!(run_and_get_int("MOVE r0, -42\nABS r1, r0", 1), 42);
        assert_eq!(run_and_get_int("MOVE r0, 42\nABS r1, r0", 1), 42);
    }

    #[test]
    fn min() {
        assert_eq!(
            run_and_get_int("MOVE r0, 10\nMOVE r1, 5\nMIN r2, r0, r1", 2),
            5
        );
    }

    #[test]
    fn max() {
        assert_eq!(
            run_and_get_int("MOVE r0, 10\nMOVE r1, 5\nMAX r2, r0, r1", 2),
            10
        );
    }

    #[test]
    fn shl() {
        assert_eq!(
            run_and_get_int("MOVE r0, 1\nMOVE r1, 4\nSHL r2, r0, r1", 2),
            16
        );
    }

    #[test]
    fn shr() {
        assert_eq!(
            run_and_get_int("MOVE r0, 16\nMOVE r1, 2\nSHR r2, r0, r1", 2),
            4
        );
        // Arithmetic shift preserves sign
        assert_eq!(
            run_and_get_int("MOVE r0, -16\nMOVE r1, 2\nSHR r2, r0, r1", 2),
            -4
        );
    }

    #[test]
    fn inc() {
        assert_eq!(run_and_get_int("MOVE r0, 0\nINC r0", 0), 1);
        assert_eq!(run_and_get_int("MOVE r0, 41\nINC r0", 0), 42);
        assert_eq!(run_and_get_int("MOVE r0, -1\nINC r0", 0), 0);
    }

    #[test]
    fn dec() {
        assert_eq!(run_and_get_int("MOVE r0, 1\nDEC r0", 0), 0);
        assert_eq!(run_and_get_int("MOVE r0, 43\nDEC r0", 0), 42);
        assert_eq!(run_and_get_int("MOVE r0, 0\nDEC r0", 0), -1);
    }

    #[test]
    fn inc_wrapping() {
        let source = "MOVE r0, 9223372036854775807\nINC r0";
        assert_eq!(run_and_get_int(source, 0), i64::MIN);
    }

    #[test]
    fn dec_wrapping() {
        let source = "MOVE r0, -9223372036854775808\nDEC r0";
        assert_eq!(run_and_get_int(source, 0), i64::MAX);
    }

    #[test]
    fn inc_type_error() {
        assert!(matches!(
            run_expect_err("MOVE r0, true\nINC r0"),
            VMError::TypeMismatchStatic { .. }
        ));
    }

    #[test]
    fn dec_type_error() {
        assert!(matches!(
            run_expect_err("MOVE r0, true\nDEC r0"),
            VMError::TypeMismatchStatic { .. }
        ));
    }

    #[test]
    fn immediate_arithmetic_and_logic() {
        assert_eq!(run_and_get_int("MOVE r0, 5\nADD r1, r0, -2", 1), 3);
        assert_eq!(run_and_get_int("MOVE r0, 10\nSUB r1, r0, 4", 1), 6);
        assert_eq!(run_and_get_int("MOVE r0, 6\nMUL r1, r0, 7", 1), 42);
        assert_eq!(run_and_get_int("MOVE r0, 1\nSHL r1, r0, 3", 1), 8);
        assert_eq!(run_and_get_int("MOVE r0, 16\nSHR r1, r0, 2", 1), 4);
        assert!(run_and_get_bool("MOVE r0, true\nAND r1, r0, true", 1));
        assert!(run_and_get_bool("MOVE r0, false\nOR r1, r0, true", 1));
        assert!(!run_and_get_bool("MOVE r0, true\nXOR r1, r0, true", 1));
    }

    #[test]
    fn immediate_comparisons() {
        assert!(run_and_get_bool("MOVE r0, 7\nEQ r1, r0, 7", 1));
        assert!(run_and_get_bool("MOVE r0, 7\nLT r1, r0, 10", 1));
        assert!(run_and_get_bool("MOVE r0, 7\nGE r1, r0, 7", 1));
        assert!(run_and_get_bool("MOVE r0, 7\nLE r1, r0, 7", 1));
        assert!(run_and_get_bool("MOVE r0, 7\nGT r1, r0, 5", 1));
    }

    #[test]
    fn immediate_branches() {
        let source = r#"
MOVE r0, 0
BEQ r0, 0, target
MOVE r1, 1
HALT
target:
MOVE r1, 42
"#;
        assert_eq!(run_and_get_int(source, 1), 42);

        let source = r#"
MOVE r0, 5
BNE r0, 5, target
MOVE r1, 99
HALT
target:
MOVE r1, 1
"#;
        assert_eq!(run_and_get_int(source, 1), 99);

        let source = r#"
MOVE r0, 3
BLT r0, 5, target
MOVE r1, 0
HALT
target:
MOVE r1, 77
"#;
        assert_eq!(run_and_get_int(source, 1), 77);

        let source = r#"
MOVE r0, -1
BGEU r0, 0, target
MOVE r1, 0
HALT
target:
MOVE r1, 123
"#;
        assert_eq!(run_and_get_int(source, 1), 123);

        let source = r#"
MOVE r0, -5
BGE r0, -10, target
MOVE r1, 0
HALT
target:
MOVE r1, 9
"#;
        assert_eq!(run_and_get_int(source, 1), 9);

        let source = r#"
MOVE r0, 1
BLTU r0, 5, target
MOVE r1, 0
HALT
target:
MOVE r1, 11
"#;
        assert_eq!(run_and_get_int(source, 1), 11);
    }

    // ==================== Src Operand Encoding ====================

    #[test]
    fn src_operand_i64_both_positions() {
        // Both operands as immediate i64
        assert_eq!(run_and_get_int("ADD r0, 10, 32", 0), 42);
        assert_eq!(run_and_get_int("SUB r0, 50, 8", 0), 42);
        assert_eq!(run_and_get_int("MUL r0, 6, 7", 0), 42);
    }

    #[test]
    fn src_operand_i64_first_position() {
        // First operand immediate, second register
        assert_eq!(run_and_get_int("MOVE r1, 32\nADD r0, 10, r1", 0), 42);
        assert_eq!(run_and_get_int("MOVE r1, 8\nSUB r0, 50, r1", 0), 42);
    }

    #[test]
    fn src_operand_bool_immediate() {
        // Boolean immediates in logic operations
        assert!(run_and_get_bool("AND r0, true, true", 0));
        assert!(!run_and_get_bool("AND r0, true, false", 0));
        assert!(run_and_get_bool("OR r0, false, true", 0));
        assert!(!run_and_get_bool("OR r0, false, false", 0));
        assert!(run_and_get_bool("XOR r0, true, false", 0));
        assert!(!run_and_get_bool("XOR r0, true, true", 0));
    }

    #[test]
    fn src_operand_bool_mixed() {
        // Mix of register and immediate bool
        assert!(run_and_get_bool("MOVE r1, true\nAND r0, r1, true", 0));
        assert!(run_and_get_bool("MOVE r1, true\nAND r0, true, r1", 0));
        assert!(!run_and_get_bool("MOVE r1, false\nOR r0, r1, false", 0));
    }

    #[test]
    fn src_operand_string_ref_comparison() {
        // String refs in EQ/NE
        assert!(run_and_get_bool(r#"EQ r0, "hello", "hello""#, 0));
        assert!(!run_and_get_bool(r#"EQ r0, "hello", "world""#, 0));
        assert!(run_and_get_bool(r#"NE r0, "foo", "bar""#, 0));
        assert!(!run_and_get_bool(r#"NE r0, "same", "same""#, 0));
    }

    #[test]
    fn src_operand_string_ref_mixed() {
        // Mix register and immediate string
        assert!(run_and_get_bool(
            r#"MOVE r1, "test"
EQ r0, r1, "test""#,
            0
        ));
        assert!(run_and_get_bool(
            r#"MOVE r1, "test"
EQ r0, "test", r1"#,
            0
        ));
    }

    #[test]
    fn src_operand_branch_both_immediate() {
        // Both branch operands as immediate
        let source = r#"
BEQ 5, 5, target
MOVE r0, 0
HALT
target:
MOVE r0, 1
"#;
        assert_eq!(run_and_get_int(source, 0), 1);

        let source = r#"
BNE 5, 6, target
MOVE r0, 0
HALT
target:
MOVE r0, 1
"#;
        assert_eq!(run_and_get_int(source, 0), 1);

        let source = r#"
BLT 3, 5, target
MOVE r0, 0
HALT
target:
MOVE r0, 1
"#;
        assert_eq!(run_and_get_int(source, 0), 1);
    }

    #[test]
    fn src_operand_branch_bool_immediate() {
        let source = r#"
BEQ true, true, target
MOVE r0, 0
HALT
target:
MOVE r0, 1
"#;
        assert_eq!(run_and_get_int(source, 0), 1);

        let source = r#"
BNE true, false, target
MOVE r0, 0
HALT
target:
MOVE r0, 1
"#;
        assert_eq!(run_and_get_int(source, 0), 1);
    }

    #[test]
    fn src_operand_move_all_types() {
        // MOVE with immediate i64
        assert_eq!(run_and_get_int("MOVE r0, 42", 0), 42);
        assert_eq!(run_and_get_int("MOVE r0, -100", 0), -100);

        // MOVE with immediate bool
        assert!(run_and_get_bool("MOVE r0, true", 0));
        assert!(!run_and_get_bool("MOVE r0, false", 0));

        // MOVE with immediate string
        assert_eq!(run_and_get_str(r#"MOVE r0, "hello""#, 0), "hello");

        // MOVE from register
        assert_eq!(run_and_get_int("MOVE r0, 99\nMOVE r1, r0", 1), 99);
    }

    #[test]
    fn src_operand_store_immediate_key() {
        // Store with immediate string key
        let vm = run_vm(
            r#"STORE "mykey", 123
LOAD_I64 r0, "mykey""#,
        );
        assert_eq!(vm.registers.get_int(0, "").unwrap(), 123);
    }

    #[test]
    fn src_operand_store_immediate_value() {
        // Store with immediate value
        let vm = run_vm(
            r#"MOVE r0, "counter"
STORE r0, 999
LOAD_I64 r1, r0"#,
        );
        assert_eq!(vm.registers.get_int(1, "").unwrap(), 999);
    }

    #[test]
    fn src_operand_store_both_immediate() {
        // Both key and value immediate
        let vm = run_vm(
            r#"STORE "flag", true
LOAD_BOOL r0, "flag""#,
        );
        assert!(vm.registers.get_bool(0, "").unwrap());
    }

    #[test]
    fn src_operand_cast_immediate() {
        // Cast from immediate value
        assert!(run_and_get_bool("I64_TO_BOOL r0, 1", 0));
        assert!(!run_and_get_bool("I64_TO_BOOL r0, 0", 0));
        assert_eq!(run_and_get_int("BOOL_TO_I64 r0, true", 0), 1);
        assert_eq!(run_and_get_int("BOOL_TO_I64 r0, false", 0), 0);
    }

    #[test]
    fn src_operand_not_immediate() {
        assert!(!run_and_get_bool("NOT r0, true", 0));
        assert!(run_and_get_bool("NOT r0, false", 0));
    }

    #[test]
    fn src_operand_neg_abs_immediate() {
        assert_eq!(run_and_get_int("NEG r0, 42", 0), -42);
        assert_eq!(run_and_get_int("NEG r0, -42", 0), 42);
        assert_eq!(run_and_get_int("ABS r0, -42", 0), 42);
        assert_eq!(run_and_get_int("ABS r0, 42", 0), 42);
    }

    #[test]
    fn src_operand_min_max_immediate() {
        assert_eq!(run_and_get_int("MIN r0, 10, 5", 0), 5);
        assert_eq!(run_and_get_int("MIN r0, 5, 10", 0), 5);
        assert_eq!(run_and_get_int("MAX r0, 10, 5", 0), 10);
        assert_eq!(run_and_get_int("MAX r0, 5, 10", 0), 10);
    }

    #[test]
    fn src_operand_shift_immediate() {
        assert_eq!(run_and_get_int("SHL r0, 1, 4", 0), 16);
        assert_eq!(run_and_get_int("SHR r0, 16, 2", 0), 4);
        // Mix: first immediate, second register
        assert_eq!(run_and_get_int("MOVE r1, 3\nSHL r0, 1, r1", 0), 8);
        // Mix: first register, second immediate
        assert_eq!(run_and_get_int("MOVE r1, 32\nSHR r0, r1, 2", 0), 8);
    }

    // ==================== Boolean ====================

    #[test]
    fn not() {
        assert!(!run_and_get_bool("MOVE r0, true\nNOT r1, r0", 1));
        assert!(run_and_get_bool("MOVE r0, false\nNOT r1, r0", 1));
    }

    #[test]
    fn and() {
        assert!(run_and_get_bool(
            "MOVE r0, true\nMOVE r1, true\nAND r2, r0, r1",
            2
        ));
        assert!(!run_and_get_bool(
            "MOVE r0, true\nMOVE r1, false\nAND r2, r0, r1",
            2
        ));
    }

    #[test]
    fn or() {
        assert!(run_and_get_bool(
            "MOVE r0, false\nMOVE r1, true\nOR r2, r0, r1",
            2
        ));
        assert!(!run_and_get_bool(
            "MOVE r0, false\nMOVE r1, false\nOR r2, r0, r1",
            2
        ));
    }

    #[test]
    fn xor() {
        assert!(run_and_get_bool(
            "MOVE r0, true\nMOVE r1, false\nXOR r2, r0, r1",
            2
        ));
        assert!(!run_and_get_bool(
            "MOVE r0, true\nMOVE r1, true\nXOR r2, r0, r1",
            2
        ));
    }

    // ==================== Comparison ====================

    #[test]
    fn eq() {
        assert!(run_and_get_bool("MOVE r0, 5\nMOVE r1, 5\nEQ r2, r0, r1", 2));
        assert!(!run_and_get_bool(
            "MOVE r0, 5\nMOVE r1, 6\nEQ r2, r0, r1",
            2
        ));
    }

    #[test]
    fn ne() {
        assert!(run_and_get_bool("MOVE r0, 5\nMOVE r1, 6\nNE r2, r0, r1", 2));
        assert!(!run_and_get_bool(
            "MOVE r0, 5\nMOVE r1, 5\nNE r2, r0, r1",
            2
        ));
    }

    #[test]
    fn ne_with_bool() {
        assert!(run_and_get_bool(
            "MOVE r0, true\nMOVE r1, false\nNE r2, r0, r1",
            2
        ));
        assert!(!run_and_get_bool(
            "MOVE r0, true\nMOVE r1, true\nNE r2, r0, r1",
            2
        ));
    }

    #[test]
    fn ne_with_string() {
        assert!(run_and_get_bool(
            r#"MOVE r0, "hello"
MOVE r1, "world"
NE r2, r0, r1"#,
            2
        ));
        assert!(!run_and_get_bool(
            r#"MOVE r0, "same"
MOVE r1, "same"
NE r2, r0, r1"#,
            2
        ));
    }

    #[test]
    fn lt() {
        assert!(run_and_get_bool("MOVE r0, 3\nMOVE r1, 5\nLT r2, r0, r1", 2));
        assert!(!run_and_get_bool(
            "MOVE r0, 5\nMOVE r1, 3\nLT r2, r0, r1",
            2
        ));
    }

    #[test]
    fn le() {
        assert!(run_and_get_bool("MOVE r0, 3\nMOVE r1, 5\nLE r2, r0, r1", 2));
        assert!(run_and_get_bool("MOVE r0, 5\nMOVE r1, 5\nLE r2, r0, r1", 2));
        assert!(!run_and_get_bool(
            "MOVE r0, 6\nMOVE r1, 5\nLE r2, r0, r1",
            2
        ));
    }

    #[test]
    fn gt() {
        assert!(run_and_get_bool(
            "MOVE r0, 10\nMOVE r1, 5\nGT r2, r0, r1",
            2
        ));
        assert!(!run_and_get_bool(
            "MOVE r0, 5\nMOVE r1, 10\nGT r2, r0, r1",
            2
        ));
    }

    #[test]
    fn ge() {
        assert!(run_and_get_bool(
            "MOVE r0, 10\nMOVE r1, 5\nGE r2, r0, r1",
            2
        ));
        assert!(run_and_get_bool("MOVE r0, 5\nMOVE r1, 5\nGE r2, r0, r1", 2));
        assert!(!run_and_get_bool(
            "MOVE r0, 4\nMOVE r1, 5\nGE r2, r0, r1",
            2
        ));
    }

    // ==================== Type Errors ====================

    #[test]
    fn type_mismatch_int_for_bool() {
        let source = "MOVE r0, 1\nNOT r1, r0";
        assert!(matches!(
            run_expect_err(source),
            VMError::TypeMismatchStatic { .. }
        ));
    }

    #[test]
    fn type_mismatch_bool_for_int() {
        let source = "MOVE r0, true\nMOVE r1, true\nADD r2, r0, r1";
        assert!(matches!(
            run_expect_err(source),
            VMError::TypeMismatchStatic { .. }
        ));
    }

    #[test]
    fn invalid_operand_for_int_op() {
        let source = r#"ADD r0, "hi", 1"#;
        assert!(matches!(
            run_expect_err(source),
            VMError::InvalidOperand {
                instruction: "ADD",
                ..
            }
        ));
    }

    #[test]
    fn invalid_comparison_types() {
        let source = "EQ r0, 1, true";
        assert!(matches!(
            run_expect_err(source),
            VMError::InvalidComparison { .. }
        ));
    }

    // ==================== Error Cases ====================

    #[test]
    fn read_uninitialized_register() {
        assert_eq!(run_and_get_int("ADD r2, r0, r1", 2), 0);
    }

    #[test]
    fn invalid_opcode() {
        let mut vm = VM::new_with_init(
            DeployProgram::new(vec![], vec![], vec![0xFE]),
            0,
            BLOCK_GAS_LIMIT,
        )
        .expect("vm new failed");
        assert!(matches!(
            vm.run(&mut TestState::new(), EXECUTION_CONTEXT),
            Err(VMError::InvalidInstruction { opcode: 0xFE, .. })
        ));
    }

    #[test]
    fn invalid_operand_tag() {
        let bytecode = vec![Instruction::Move as u8, 0, 9];
        let mut vm = VM::new_with_init(
            DeployProgram::new(vec![], vec![], bytecode),
            0,
            BLOCK_GAS_LIMIT,
        )
        .expect("vm new failed");
        let err = vm
            .run(&mut TestState::new(), EXECUTION_CONTEXT)
            .expect_err("expected error");
        assert!(matches!(err, VMError::InvalidOperandTag { tag: 9, .. }));
    }

    #[test]
    fn truncated_bytecode() {
        let mut vm = VM::new_with_init(
            DeployProgram::new(vec![], vec![], vec![0x01, 0x00]),
            0,
            BLOCK_GAS_LIMIT,
        )
        .expect("vm new failed");
        assert!(matches!(
            vm.run(&mut TestState::new(), EXECUTION_CONTEXT),
            Err(VMError::UnexpectedEndOfBytecode { .. })
        ));
    }

    // ==================== Gas Limits ====================

    #[test]
    fn vm_new_charges_init_cost() {
        let vm = VM::new_with_init(
            DeployProgram::new(vec![], vec![], vec![]),
            100,
            BLOCK_GAS_LIMIT,
        )
        .unwrap();
        assert_eq!(vm.gas_used(), 100);
    }

    #[test]
    fn vm_new_fails_when_init_cost_exceeds_max_gas() {
        let result = VM::new_with_init(DeployProgram::new(vec![], vec![], vec![]), 1000, 500);
        assert!(matches!(
            result,
            Err(VMError::OutOfGas {
                used: 1000,
                limit: 500
            })
        ));
    }

    #[test]
    fn vm_new_succeeds_when_init_cost_equals_max_gas() {
        let vm = VM::new_with_init(DeployProgram::new(vec![], vec![], vec![]), 500, 500).unwrap();
        assert_eq!(vm.gas_used(), 500);
    }

    #[test]
    fn vm_respects_custom_max_gas() {
        let program = assemble_source(
            r#"
            MOVE r0, 1
            MOVE r1, 2
            ADD r2, r0, r1
            ADD r2, r1, r2
        "#,
        )
        .expect("assembly failed");

        let mut vm = VM::new_with_init(program, 0, 5).unwrap();
        let result = vm.run(&mut TestState::new(), EXECUTION_CONTEXT);

        assert!(matches!(result, Err(VMError::OutOfGas { .. })));
    }

    // ==================== Stores ====================

    fn make_test_key(user_key: &[u8]) -> Result<Hash, VMError> {
        VM::new_with_init(
            DeployProgram::new(vec![], vec![], vec![]),
            0,
            BLOCK_GAS_LIMIT,
        )
        .expect("vm new failed")
        .make_state_key(
            EXECUTION_CONTEXT.chain_id,
            &EXECUTION_CONTEXT.contract_id,
            user_key,
        )
    }

    #[test]
    fn store_i64() {
        let state = run_vm_with_state(
            r#"MOVE r0, "counter"
MOVE r1, 42
STORE r0, r1"#,
        );
        let key = make_test_key(b"counter").unwrap();
        let value = state.get(key).expect("key not found");
        assert_eq!(i64::from_le_bytes(value.try_into().unwrap()), 42);
    }

    #[test]
    fn store_i64_inline_key() {
        let vm = run_vm(
            r#"STORE "counter", 42
LOAD_I64 r0, "counter""#,
        );
        assert_eq!(vm.registers.get_int(0, "").unwrap(), 42);
    }

    #[test]
    fn store_str() {
        let state = run_vm_with_state(
            r#"MOVE r0, "name"
MOVE r1, "alice"
STORE r0, r1"#,
        );
        let key = make_test_key(b"name").unwrap();
        let value = state.get(key).expect("key not found");
        assert_eq!(value, b"alice");
    }

    #[test]
    fn store_hash() {
        let state = run_vm_with_state(
            r#"MOVE r0, "hash_key"
MOVE r1, "00000000000000000000000000000000"
STORE r0, r1"#,
        );
        let key = make_test_key(b"hash_key").unwrap();
        let value = state.get(key).expect("key not found");
        let expected = Hash::from_slice(b"00000000000000000000000000000000").unwrap();
        assert_eq!(value, expected.to_vec());
    }

    #[test]
    fn store_bool() {
        let state = run_vm_with_state(
            r#"MOVE r0, "flag"
MOVE r1, true
STORE r0, r1"#,
        );
        let key = make_test_key(b"flag").unwrap();
        let value = state.get(key).expect("key not found");
        assert_eq!(value, &[1u8]);
    }

    #[test]
    fn store_overwrites_previous_value() {
        let state = run_vm_with_state(
            r#"MOVE r0, "x"
MOVE r1, 100
STORE r0, r1
MOVE r2, 200
STORE r0, r2"#,
        );
        let key = make_test_key(b"x").unwrap();
        let value = state.get(key).expect("key not found");
        assert_eq!(i64::from_le_bytes(value.try_into().unwrap()), 200);
    }

    #[test]
    fn store_then_load_bytes() {
        let vm = run_vm(
            r#"MOVE r0, "blob"
MOVE r1, "hello"
STORE r0, r1
LOAD r2, r0"#,
        );
        let ref_id = vm.registers.get_ref(2, "").unwrap();
        assert_eq!(vm.heap.get_data(ref_id).unwrap(), b"hello");
    }

    // ==================== State Loads ====================

    fn run_vm_on_state(source: &str, state: &mut TestState) -> VM {
        let program = assemble_source(source).expect("assembly failed");
        let mut vm = VM::new_with_init(program, 0, BLOCK_GAS_LIMIT).expect("vm new failed");
        vm.run(state, EXECUTION_CONTEXT).expect("vm run failed");
        vm
    }

    #[test]
    fn load_i64_state() {
        let key = make_test_key(b"counter").unwrap();
        let mut state = TestState::with_data(vec![(key, 42i64.to_le_bytes().to_vec())]);
        let vm = run_vm_on_state(
            r#"MOVE r0, "counter"
LOAD_I64 r1, r0"#,
            &mut state,
        );
        assert_eq!(vm.registers.get_int(1, "").unwrap(), 42);
    }

    #[test]
    fn load_i64_state_negative() {
        let key = make_test_key(b"neg").unwrap();
        let mut state = TestState::with_data(vec![(key, (-999i64).to_le_bytes().to_vec())]);
        let vm = run_vm_on_state(
            r#"MOVE r0, "neg"
LOAD_I64 r1, r0"#,
            &mut state,
        );
        assert_eq!(vm.registers.get_int(1, "").unwrap(), -999);
    }

    #[test]
    fn load_i64_state_key_not_found() {
        let program = assemble_source(
            r#"MOVE r0, "missing"
LOAD_I64 r1, r0"#,
        )
        .expect("assembly failed");
        let mut vm = VM::new_with_init(program, 0, BLOCK_GAS_LIMIT).expect("vm new failed");
        let err = vm
            .run(&mut TestState::new(), EXECUTION_CONTEXT)
            .expect_err("expected error");
        assert!(matches!(err, VMError::KeyNotFound { .. }));
    }

    #[test]
    fn load_bool_state_true() {
        let key = make_test_key(b"flag").unwrap();
        let mut state = TestState::with_data(vec![(key, vec![1u8])]);
        let vm = run_vm_on_state(
            r#"MOVE r0, "flag"
LOAD_BOOL r1, r0"#,
            &mut state,
        );
        assert!(vm.registers.get_bool(1, "").unwrap());
    }

    #[test]
    fn load_bool_state_false() {
        let key = make_test_key(b"flag").unwrap();
        let mut state = TestState::with_data(vec![(key, vec![0u8])]);
        let vm = run_vm_on_state(
            r#"MOVE r0, "flag"
LOAD_BOOL r1, r0"#,
            &mut state,
        );
        assert!(!vm.registers.get_bool(1, "").unwrap());
    }

    #[test]
    fn load_bool_state_key_not_found() {
        let program = assemble_source(
            r#"MOVE r0, "missing"
LOAD_BOOL r1, r0"#,
        )
        .expect("assembly failed");
        let mut vm = VM::new_with_init(program, 0, BLOCK_GAS_LIMIT).expect("vm new failed");
        let err = vm
            .run(&mut TestState::new(), EXECUTION_CONTEXT)
            .expect_err("expected error");
        assert!(matches!(err, VMError::KeyNotFound { .. }));
    }

    #[test]
    fn has_state_reports_presence() {
        let key = make_test_key(b"present").unwrap();
        let mut state = TestState::with_data(vec![(key, vec![1u8])]);
        let vm = run_vm_on_state(
            r#"MOVE r0, "present"
MOVE r1, "missing"
HAS_STATE r2, r0
HAS_STATE r3, r1"#,
            &mut state,
        );
        assert!(vm.registers.get_bool(2, "").unwrap());
        assert!(!vm.registers.get_bool(3, "").unwrap());
    }

    #[test]
    fn load_str_state() {
        let key = make_test_key(b"name").unwrap();
        let mut state = TestState::with_data(vec![(key, b"alice".to_vec())]);
        let vm = run_vm_on_state(
            r#"MOVE r0, "name"
LOAD_STR r1, r0"#,
            &mut state,
        );
        let ref_id = vm.registers.get_ref(1, "").unwrap();
        assert_eq!(vm.heap.get_string(ref_id).unwrap(), "alice");
    }

    #[test]
    fn load_str_state_empty() {
        let key = make_test_key(b"empty").unwrap();
        let mut state = TestState::with_data(vec![(key, vec![])]);
        let vm = run_vm_on_state(
            r#"MOVE r0, "empty"
LOAD_STR r1, r0"#,
            &mut state,
        );
        let ref_id = vm.registers.get_ref(1, "").unwrap();
        assert_eq!(vm.heap.get_string(ref_id).unwrap(), "");
    }

    #[test]
    fn load_hash_state() {
        let key = make_test_key(b"hash_key").unwrap();
        let expected = Hash::from_slice(b"11111111111111111111111111111111").unwrap();
        let mut state = TestState::with_data(vec![(key, expected.to_vec())]);
        let vm = run_vm_on_state(
            r#"MOVE r0, "hash_key"
LOAD_HASH r1, r0"#,
            &mut state,
        );
        let ref_id = vm.registers.get_ref(1, "").unwrap();
        assert_eq!(vm.heap.get_hash(ref_id).unwrap(), expected);
    }

    #[test]
    fn load_str_state_key_not_found() {
        let program = assemble_source(
            r#"MOVE r0, "missing"
LOAD_STR r1, r0"#,
        )
        .expect("assembly failed");
        let mut vm = VM::new_with_init(program, 0, BLOCK_GAS_LIMIT).expect("vm new failed");
        let err = vm
            .run(&mut TestState::new(), EXECUTION_CONTEXT)
            .expect_err("expected error");
        assert!(matches!(err, VMError::KeyNotFound { .. }));
    }

    #[test]
    fn store_then_load_i64() {
        let vm = run_vm(
            r#"MOVE r0, "x"
MOVE r1, 123
STORE r0, r1
LOAD_I64 r2, r0"#,
        );
        assert_eq!(vm.registers.get_int(2, "").unwrap(), 123);
    }

    #[test]
    fn store_then_load_bool() {
        let vm = run_vm(
            r#"MOVE r0, "b"
MOVE r1, true
STORE r0, r1
LOAD_BOOL r2, r0"#,
        );
        assert!(vm.registers.get_bool(2, "").unwrap());
    }

    #[test]
    fn store_then_load_str() {
        let vm = run_vm(
            r#"MOVE r0, "s"
MOVE r1, "hello"
STORE r0, r1
LOAD_STR r2, r0"#,
        );
        let ref_id = vm.registers.get_ref(2, "").unwrap();
        assert_eq!(vm.heap.get_string(ref_id).unwrap(), "hello");
    }

    #[test]
    fn store_then_load_hash() {
        let vm = run_vm(
            r#"MOVE r0, "hash_key"
MOVE r1, "22222222222222222222222222222222"
STORE r0, r1
LOAD_HASH r2, r0"#,
        );
        let ref_id = vm.registers.get_ref(2, "").unwrap();
        let expected = Hash::from_slice(b"22222222222222222222222222222222").unwrap();
        assert_eq!(vm.heap.get_hash(ref_id).unwrap(), expected);
    }

    // ==================== Control Flow ====================

    #[test]
    fn jal_saves_return_address() {
        // JAL saves the address after the instruction to rd
        // JAL r0, 0 means jump to current position (no-op) but save return addr
        let vm = run_vm("JAL r0, 0");
        // After JAL (6 bytes: opcode + reg + i32), ip should be saved as 6
        assert_eq!(vm.registers.get_int(0, "").unwrap(), 6);
    }

    #[test]
    fn jal_forward_jump() {
        // Jump over MOVE r1, 99 to reach MOVE r2, 42
        let source = r#"
            JAL r0, skip
            MOVE r1, 99
            skip: MOVE r2, 42
        "#;
        let vm = run_vm(source);
        // r1 should still be zero (skipped)
        assert_eq!(vm.registers.get(1).unwrap(), &Value::Int(0));
        // r2 should be 42
        assert_eq!(vm.registers.get_int(2, "").unwrap(), 42);
    }

    #[test]
    fn jump_skips_instructions() {
        // MOVE is 11 bytes, so jump forward by 11 to skip the following load
        let vm = run_vm("MOVE r0, 1\nJUMP 11\nMOVE r0, 99");
        assert_eq!(vm.registers.get_int(0, "").unwrap(), 1);
    }

    #[test]
    fn beq_taken() {
        // Branch taken when equal
        let source = r#"
            MOVE r0, 5
            MOVE r1, 5
            BEQ r0, r1, skip
            MOVE r2, 99
            skip: MOVE r3, 42
        "#;
        let vm = run_vm(source);
        assert_eq!(vm.registers.get(2).unwrap(), &Value::Int(0));
        assert_eq!(vm.registers.get_int(3, "").unwrap(), 42);
    }

    #[test]
    fn beq_not_taken() {
        // Branch not taken when not equal
        let source = r#"
            MOVE r0, 5
            MOVE r1, 6
            BEQ r0, r1, skip
            MOVE r2, 99
            skip: MOVE r3, 42
        "#;
        let vm = run_vm(source);
        assert_eq!(vm.registers.get_int(2, "").unwrap(), 99);
        assert_eq!(vm.registers.get_int(3, "").unwrap(), 42);
    }

    #[test]
    fn bne_taken() {
        let source = r#"
            MOVE r0, 5
            MOVE r1, 6
            BNE r0, r1, skip
            MOVE r2, 99
            skip: MOVE r3, 42
        "#;
        let vm = run_vm(source);
        assert_eq!(vm.registers.get(2).unwrap(), &Value::Int(0));
        assert_eq!(vm.registers.get_int(3, "").unwrap(), 42);
    }

    #[test]
    fn bne_not_taken() {
        let source = r#"
            MOVE r0, 5
            MOVE r1, 5
            BNE r0, r1, skip
            MOVE r2, 99
            skip: MOVE r3, 42
        "#;
        let vm = run_vm(source);
        assert_eq!(vm.registers.get_int(2, "").unwrap(), 99);
    }

    #[test]
    fn blt_taken() {
        let source = r#"
            MOVE r0, 3
            MOVE r1, 5
            BLT r0, r1, skip
            MOVE r2, 99
            skip: MOVE r3, 42
        "#;
        let vm = run_vm(source);
        assert_eq!(vm.registers.get(2).unwrap(), &Value::Int(0));
        assert_eq!(vm.registers.get_int(3, "").unwrap(), 42);
    }

    #[test]
    fn blt_not_taken() {
        let source = r#"
            MOVE r0, 5
            MOVE r1, 3
            BLT r0, r1, skip
            MOVE r2, 99
            skip: MOVE r3, 42
        "#;
        let vm = run_vm(source);
        assert_eq!(vm.registers.get_int(2, "").unwrap(), 99);
    }

    #[test]
    fn blt_signed() {
        // -1 < 1 in signed comparison
        let source = r#"
            MOVE r0, -1
            MOVE r1, 1
            BLT r0, r1, skip
            MOVE r2, 99
            skip: MOVE r3, 42
        "#;
        let vm = run_vm(source);
        assert_eq!(vm.registers.get(2).unwrap(), &Value::Int(0));
    }

    #[test]
    fn bge_taken() {
        let source = r#"
            MOVE r0, 5
            MOVE r1, 5
            BGE r0, r1, skip
            MOVE r2, 99
            skip: MOVE r3, 42
        "#;
        let vm = run_vm(source);
        assert_eq!(vm.registers.get(2).unwrap(), &Value::Int(0));
    }

    #[test]
    fn bge_greater() {
        let source = r#"
            MOVE r0, 7
            MOVE r1, 5
            BGE r0, r1, skip
            MOVE r2, 99
            skip: MOVE r3, 42
        "#;
        let vm = run_vm(source);
        assert_eq!(vm.registers.get(2).unwrap(), &Value::Int(0));
    }

    #[test]
    fn bltu_unsigned() {
        // -1 as u64 is MAX, so -1 > 1 in unsigned comparison
        let source = r#"
            MOVE r0, -1
            MOVE r1, 1
            BLTU r0, r1, skip
            MOVE r2, 99
            skip: MOVE r3, 42
        "#;
        let vm = run_vm(source);
        // Branch NOT taken because -1 as u64 > 1
        assert_eq!(vm.registers.get_int(2, "").unwrap(), 99);
    }

    #[test]
    fn bgeu_unsigned() {
        // -1 as u64 is MAX, so -1 >= 1 in unsigned comparison
        let source = r#"
            MOVE r0, -1
            MOVE r1, 1
            BGEU r0, r1, skip
            MOVE r2, 99
            skip: MOVE r3, 42
        "#;
        let vm = run_vm(source);
        // Branch taken because -1 as u64 > 1
        assert_eq!(vm.registers.get(2).unwrap(), &Value::Int(0));
    }

    #[test]
    fn halt_stops_execution() {
        let source = r#"
            MOVE r0, 1
            HALT
            MOVE r0, 99
        "#;
        let vm = run_vm(source);
        assert_eq!(vm.registers.get_int(0, "").unwrap(), 1);
    }

    #[test]
    fn loop_with_backward_branch() {
        // Simple loop: count from 0 to 3
        let source = r#"
            MOVE r0, 0
            MOVE r1, 1
            MOVE r2, 3
            loop:
            ADD r0, r0, r1
            BLT r0, r2, loop
        "#;
        let vm = run_vm(source);
        // r0 should be 3 after loop exits
        assert_eq!(vm.registers.get_int(0, "").unwrap(), 3);
    }

    #[test]
    fn jalr_indirect_jump() {
        // JALR jumps to address in register + offset
        // MOVE: 11 bytes (opcode + reg + src_tag + i64), JALR: 7 bytes (opcode + reg + reg + i32)
        // Offsets: MOVE[0-10], JALR[11-17], MOVE r2[18-28], MOVE r3[29-39]
        let source = r#"
            MOVE r1, 28
            JALR r0, r1, 1
            MOVE r2, 99
            MOVE r3, 42
        "#;
        let vm = run_vm(source);
        // Should skip MOVE r2, 99 and execute MOVE r3, 42
        assert_eq!(vm.registers.get(2).unwrap(), &Value::Int(0));
        assert_eq!(vm.registers.get_int(3, "").unwrap(), 42);
    }

    // ==================== Function Calls ====================

    #[test]
    fn call_and_ret_simple() {
        // Call a function that returns a constant
        let source = r#"
            JAL r0, main
            main:
            CALL0 r1, double
            JAL r0, end
            double:
            MOVE r10, 42
            RET r10
            end:
        "#;
        let vm = run_vm(source);
        assert_eq!(vm.registers.get_int(1, "").unwrap(), 42);
    }

    #[test]
    fn call_nested() {
        // Nested function calls
        let source = r#"
            JAL r0, main
            main:
            CALL0 r1, outer
            JAL r0, end
            outer:
            CALL0 r2, inner
            RET r2
            inner:
            MOVE r10, 99
            RET r10
            end:
        "#;
        let vm = run_vm(source);
        assert_eq!(vm.registers.get_int(1, "").unwrap(), 99);
    }

    #[test]
    fn call_undefined_function() {
        let source = r#"CALL0 r0, nonexistent"#;
        let err = run_expect_err(source);
        assert!(matches!(err, VMError::AssemblyError { .. }));
    }

    #[test]
    fn ret_without_call() {
        let source = "MOVE r0, 1\nRET r0";
        let err = run_expect_err(source);
        assert!(matches!(err, VMError::ReturnWithoutCall { .. }));
    }

    #[test]
    fn call_preserves_registers() {
        let source = r#"
            JAL r0, main
            main:
            MOVE r5, 100
            CALL0 r1, func
            ADD r2, r1, r5
            JAL r0, end
            func:
            MOVE r10, 50
            RET r10
            end:
        "#;
        let vm = run_vm(source);
        // r1 = 50 (return value), r5 = 100, r2 = 150
        assert_eq!(vm.registers.get_int(2, "").unwrap(), 150);
    }

    #[test]
    fn counter_steps_loop() {
        let prog = r#"
        # increment counter N times, where N is stored under "steps"
        main:
            MOVE r0, "counter"
            MOVE r1, "steps"

            LOAD_I64 r2, r0     # acc = counter
            LOAD_I64 r3, r1     # limit = steps
            MOVE r4, 0            # i = 0
            MOVE r5, 1            # inc = 1

        loop:
            ADD r2, r2, r5            # acc += 1
            ADD r4, r4, r5            # i++
            BLT r4, r3, loop          # loop while i < limit

        STORE r0, r2              # update counter
        "#;

        let mut state = TestState::new();
        let program = assemble_source(prog).expect("assembly failed");
        let mut vm = VM::new_with_init(program, 0, BLOCK_GAS_LIMIT).expect("vm new failed");

        let key_counter = vm
            .make_state_key(
                EXECUTION_CONTEXT.chain_id,
                &EXECUTION_CONTEXT.contract_id,
                b"counter",
            )
            .unwrap();
        let key_steps = vm
            .make_state_key(
                EXECUTION_CONTEXT.chain_id,
                &EXECUTION_CONTEXT.contract_id,
                b"steps",
            )
            .unwrap();

        state.push(key_counter, 5i64.to_le_bytes().to_vec());
        state.push(key_steps, 3i64.to_le_bytes().to_vec());

        vm.run(&mut state, EXECUTION_CONTEXT)
            .expect("vm run failed");

        let out = state.get(key_counter).unwrap();
        assert_eq!(i64::from_le_bytes(out.try_into().unwrap()), 8);
    }

    // ==================== Call Stack Poisoning ====================

    #[test]
    fn deeply_nested_calls() {
        // Chain of nested function calls to stress the call stack
        let source = r#"
            JAL r0, main
            main:
            CALL0 r1, f1
            JAL r0, end
            f1:
            CALL0 r2, f2
            RET r2
            f2:
            CALL0 r3, f3
            RET r3
            f3:
            CALL0 r4, f4
            RET r4
            f4:
            CALL0 r5, f5
            RET r5
            f5:
            MOVE r10, 777
            RET r10
            end:
        "#;
        let vm = run_vm(source);
        assert_eq!(vm.registers.get_int(1, "").unwrap(), 777);
    }

    #[test]
    fn call_stack_unwind_on_multiple_returns() {
        // Each function returns, properly unwinding the stack
        let source = r#"
            JAL r0, main
            main:
            MOVE r10, 1
            CALL0 r1, add_ten
            CALL0 r2, add_ten
            CALL0 r3, add_ten
            ADD r4, r1, r2
            ADD r4, r4, r3
            JAL r0, end
            add_ten:
            MOVE r20, 10
            RET r20
            end:
        "#;
        let vm = run_vm(source);
        // Three calls each return 10, sum should be 30
        assert_eq!(vm.registers.get_int(4, "").unwrap(), 30);
    }

    #[test]
    fn call_overwrites_dst_register_with_return_value() {
        // Verify that the destination register is correctly overwritten
        let source = r#"
            JAL r0, main
            main:
            MOVE r5, 999
            CALL0 r5, get_42
            JAL r0, end
            get_42:
            MOVE r10, 42
            RET r10
            end:
        "#;
        let vm = run_vm(source);
        // r5 should be overwritten with 42, not 999
        assert_eq!(vm.registers.get_int(5, "").unwrap(), 42);
    }

    #[test]
    fn return_from_recursive_call() {
        // Simple recursion: count down from 3 to 0
        let source = r#"
            JAL r0, main
            main:
            MOVE r1, 3
            CALL0 r2, countdown
            JAL r0, end

            countdown:
            MOVE r10, 0
            MOVE r11, 1
            BEQ r1, r10, done
            SUB r1, r1, r11
            CALL0 r12, countdown
            done:
            RET r1

            end:
        "#;
        let vm = run_vm(source);
        // After countdown, r1 should be 0
        assert_eq!(vm.registers.get_int(2, "").unwrap(), 0);
    }

    #[test]
    fn multiple_ret_without_call_fails() {
        // First RET succeeds, second RET should fail
        let source = r#"
            JAL r0, main
            main:
            CALL0 r1, func
            JAL r0, end
            func:
            MOVE r10, 1
            RET r10
            RET r10
            end:
        "#;
        // This should succeed because the second RET is never reached
        let vm = run_vm(source);
        assert_eq!(vm.registers.get_int(1, "").unwrap(), 1);
    }

    #[test]
    fn ret_with_empty_stack_fails() {
        // Direct RET without any CALL
        let source = "MOVE r0, 42\nRET r0";
        let err = run_expect_err(source);
        assert!(matches!(err, VMError::ReturnWithoutCall { .. }));
    }

    #[test]
    fn call_then_jal_then_ret_fails() {
        // CALL pushes frame, but JAL jumps away and RET finds wrong context
        let source = r#"
            JAL r0, main
            main:
            CALL0 r1, func
            JAL r0, end
            func:
            JAL r0, escape
            escape:
            MOVE r10, 1
            RET r10
            end:
        "#;
        // This should work because RET still finds the call frame
        let vm = run_vm(source);
        assert_eq!(vm.registers.get_int(1, "").unwrap(), 1);
    }

    #[test]
    fn call_stack_isolation_between_calls() {
        // Ensure sequential calls don't interfere with each other
        let source = r#"
            JAL r0, main
            main:
            CALL0 r1, ret_10
            CALL0 r2, ret_20
            CALL0 r3, ret_30
            JAL r0, end
            ret_10:
            MOVE r10, 10
            RET r10
            ret_20:
            MOVE r10, 20
            RET r10
            ret_30:
            MOVE r10, 30
            RET r10
            end:
        "#;
        let vm = run_vm(source);
        assert_eq!(vm.registers.get_int(1, "").unwrap(), 10);
        assert_eq!(vm.registers.get_int(2, "").unwrap(), 20);
        assert_eq!(vm.registers.get_int(3, "").unwrap(), 30);
    }

    #[test]
    fn call_with_same_dst_as_return_reg() {
        // Return value goes to same register used inside function
        let source = r#"
            JAL r0, main
            main:
            CALL0 r10, func
            JAL r0, end
            func:
            MOVE r10, 42
            RET r10
            end:
        "#;
        let vm = run_vm(source);
        // r10 should have return value 42
        assert_eq!(vm.registers.get_int(10, "").unwrap(), 42);
    }

    #[test]
    fn nested_call_return_value_propagation() {
        // Return value flows through nested calls
        let source = r#"
            JAL r0, main
            main:
            CALL0 r1, outer
            JAL r0, end
            outer:
            CALL0 r2, middle
            MOVE r3, 1
            ADD r2, r2, r3
            RET r2
            middle:
            CALL0 r4, inner
            MOVE r5, 1
            ADD r4, r4, r5
            RET r4
            inner:
            MOVE r6, 1
            RET r6
            end:
        "#;
        let vm = run_vm(source);
        // inner returns 1, middle adds 1 = 2, outer adds 1 = 3
        assert_eq!(vm.registers.get_int(1, "").unwrap(), 3);
    }

    #[test]
    fn call_stack_empty_after_balanced_calls() {
        // After all returns, call stack should be empty
        let source = r#"
            JAL r0, main
            main:
            CALL0 r1, a
            CALL0 r2, b
            JAL r0, end
            a:
            MOVE r10, 1
            RET r10
            b:
            MOVE r10, 2
            RET r10
            end:
        "#;
        let vm = run_vm(source);
        // Call stack should be empty after execution
        assert!(vm.call_stack.is_empty());
    }

    #[test]
    fn return_zero_value() {
        // Return the Zero value from an uninitialized register
        let source = r#"
            JAL r0, main
            main:
            CALL0 r1, ret_zero
            JAL r0, end
            ret_zero:
            RET r50
            end:
        "#;
        let vm = run_vm(source);
        assert_eq!(vm.registers.get(1).unwrap(), &Value::Int(0));
    }

    #[test]
    fn return_bool_value() {
        // Return a boolean value
        let source = r#"
            JAL r0, main
            main:
            CALL0 r1, ret_bool
            JAL r0, end
            ret_bool:
            MOVE r10, true
            RET r10
            end:
        "#;
        let vm = run_vm(source);
        assert_eq!(vm.registers.get(1).unwrap(), &Value::Bool(true));
    }

    #[test]
    fn return_ref_value() {
        // Return a string reference
        let source = r#"
            JAL r0, main
            main:
            CALL0 r1, ret_str
            JAL r0, end
            ret_str:
            MOVE r10, "hello"
            RET r10
            end:
        "#;
        let vm = run_vm(source);
        let ref_id = match vm.registers.get(1).unwrap() {
            Value::Ref(r) => *r,
            other => panic!("expected Ref, got {:?}", other),
        };
        assert_eq!(vm.heap.get_string(ref_id).unwrap(), "hello");
    }

    #[test]
    fn new_execute_stores_args_for_calldata_load() {
        let args = vec![Value::Ref(0), Value::Int(7), Value::Bool(true)];
        let exec = ExecuteProgram::new(Hash::zero(), 3, args.clone(), vec![b"hello".to_vec()]);
        let deploy = DeployProgram::new(vec![], vec![], vec![]);
        let vm = VM::new_execute(exec, deploy, BLOCK_GAS_LIMIT).unwrap();

        // r0 holds the function selector
        assert_eq!(vm.registers.get_int(0, "").unwrap(), 3);
        // Args are stored for later CALLDATA_LOAD, not preloaded into registers
        assert_eq!(vm.args, args);
        // heap_arg_base points to start of arg items (no base items)
        assert_eq!(vm.heap.exec_offset, 0);
        // The arg item was appended to the heap at heap_arg_base
        assert_eq!(vm.heap.get_string(0).unwrap(), "hello");
    }

    // ==================== Host Functions ====================

    // --- len ---

    #[test]
    fn host_len_empty_string() {
        let source = r#"
            MOVE r1, ""
            CALL_HOST1 r0, "len", r1
        "#;
        assert_eq!(run_and_get_int(source, 0), 0);
    }

    #[test]
    fn host_len_ascii_string() {
        let source = r#"
            MOVE r1, "hello"
            CALL_HOST1 r0, "len", r1
        "#;
        assert_eq!(run_and_get_int(source, 0), 5);
    }

    #[test]
    fn host_len_single_char() {
        let source = r#"
            MOVE r1, "x"
            CALL_HOST1 r0, "len", r1
        "#;
        assert_eq!(run_and_get_int(source, 0), 1);
    }

    #[test]
    fn host_len_wrong_arg_count() {
        let source = r#"
            MOVE r1, "test"
            MOVE r2, "extra"
            CALL_HOST r0, "len", 2, r1
        "#;
        assert!(matches!(
            run_expect_err(source),
            VMError::ParseErrorString { .. }
        ));
    }

    #[test]
    fn host_len_wrong_type() {
        let source = r#"
            MOVE r1, 42
            CALL_HOST1 r0, "len", r1
        "#;
        assert!(matches!(
            run_expect_err(source),
            VMError::TypeMismatchStatic { .. }
        ));
    }

    // --- slice ---

    #[test]
    fn host_slice_middle() {
        let source = r#"
            MOVE r1, "hello world"
            MOVE r2, 0
            MOVE r3, 5
            CALL_HOST r0, "slice", 3, r1
        "#;
        let vm = run_vm(source);
        let ref_id = vm.registers.get_ref(0, "").unwrap();
        assert_eq!(vm.heap.get_string(ref_id).unwrap(), "hello");
    }

    #[test]
    fn host_slice_from_offset() {
        let source = r#"
            MOVE r1, "hello world"
            MOVE r2, 6
            MOVE r3, 11
            CALL_HOST r0, "slice", 3, r1
        "#;
        let vm = run_vm(source);
        let ref_id = vm.registers.get_ref(0, "").unwrap();
        assert_eq!(vm.heap.get_string(ref_id).unwrap(), "world");
    }

    #[test]
    fn host_slice_empty_result() {
        let source = r#"
            MOVE r1, "hello"
            MOVE r2, 2
            MOVE r3, 2
            CALL_HOST r0, "slice", 3, r1
        "#;
        let vm = run_vm(source);
        let ref_id = vm.registers.get_ref(0, "").unwrap();
        assert_eq!(vm.heap.get_string(ref_id).unwrap(), "");
    }

    #[test]
    fn host_slice_full_string() {
        let source = r#"
            MOVE r1, "abc"
            MOVE r2, 0
            MOVE r3, 3
            CALL_HOST r0, "slice", 3, r1
        "#;
        let vm = run_vm(source);
        let ref_id = vm.registers.get_ref(0, "").unwrap();
        assert_eq!(vm.heap.get_string(ref_id).unwrap(), "abc");
    }

    #[test]
    fn host_slice_clamps_end_beyond_length() {
        let source = r#"
            MOVE r1, "short"
            MOVE r2, 0
            MOVE r3, 100
            CALL_HOST r0, "slice", 3, r1
        "#;
        let vm = run_vm(source);
        let ref_id = vm.registers.get_ref(0, "").unwrap();
        assert_eq!(vm.heap.get_string(ref_id).unwrap(), "short");
    }

    #[test]
    fn host_slice_clamps_start_beyond_end() {
        let source = r#"
            MOVE r1, "hello"
            MOVE r2, 10
            MOVE r3, 5
            CALL_HOST r0, "slice", 3, r1
        "#;
        let vm = run_vm(source);
        let ref_id = vm.registers.get_ref(0, "").unwrap();
        assert_eq!(vm.heap.get_string(ref_id).unwrap(), "");
    }

    #[test]
    fn host_slice_wrong_arg_count() {
        let source = r#"
            MOVE r1, "test"
            MOVE r2, 0
            CALL_HOST r0, "slice", 2, r1
        "#;
        assert!(matches!(
            run_expect_err(source),
            VMError::ParseErrorString { .. }
        ));
    }

    // --- concat ---

    #[test]
    fn host_concat_two_strings() {
        let source = r#"
            MOVE r1, "hello"
            MOVE r2, " world"
            CALL_HOST r0, "concat", 2, r1
        "#;
        let vm = run_vm(source);
        let ref_id = vm.registers.get_ref(0, "").unwrap();
        assert_eq!(vm.heap.get_string(ref_id).unwrap(), "hello world");
    }

    #[test]
    fn host_concat_empty_left() {
        let source = r#"
            MOVE r1, ""
            MOVE r2, "world"
            CALL_HOST r0, "concat", 2, r1
        "#;
        let vm = run_vm(source);
        let ref_id = vm.registers.get_ref(0, "").unwrap();
        assert_eq!(vm.heap.get_string(ref_id).unwrap(), "world");
    }

    #[test]
    fn host_concat_empty_right() {
        let source = r#"
            MOVE r1, "hello"
            MOVE r2, ""
            CALL_HOST r0, "concat", 2, r1
        "#;
        let vm = run_vm(source);
        let ref_id = vm.registers.get_ref(0, "").unwrap();
        assert_eq!(vm.heap.get_string(ref_id).unwrap(), "hello");
    }

    #[test]
    fn host_concat_both_empty() {
        let source = r#"
            MOVE r1, ""
            MOVE r2, ""
            CALL_HOST r0, "concat", 2, r1
        "#;
        let vm = run_vm(source);
        let ref_id = vm.registers.get_ref(0, "").unwrap();
        assert_eq!(vm.heap.get_string(ref_id).unwrap(), "");
    }

    #[test]
    fn host_concat_wrong_arg_count() {
        let source = r#"
            MOVE r1, "only one"
            CALL_HOST r0, "concat", 1, r1
        "#;
        assert!(matches!(
            run_expect_err(source),
            VMError::ParseErrorString { .. }
        ));
    }

    #[test]
    fn host_concat_wrong_type() {
        let source = r#"
            MOVE r1, "str"
            MOVE r2, 42
            CALL_HOST r0, "concat", 2, r1
        "#;
        assert!(matches!(
            run_expect_err(source),
            VMError::TypeMismatchStatic { .. }
        ));
    }

    // --- compare ---

    #[test]
    fn host_compare_equal() {
        let source = r#"
            MOVE r1, "abc"
            MOVE r2, "abc"
            CALL_HOST r0, "compare", 2, r1
        "#;
        assert_eq!(run_and_get_int(source, 0), 0);
    }

    #[test]
    fn host_compare_less_than() {
        let source = r#"
            MOVE r1, "abc"
            MOVE r2, "abd"
            CALL_HOST r0, "compare", 2, r1
        "#;
        assert_eq!(run_and_get_int(source, 0), -1);
    }

    #[test]
    fn host_compare_greater_than() {
        let source = r#"
            MOVE r1, "abd"
            MOVE r2, "abc"
            CALL_HOST r0, "compare", 2, r1
        "#;
        assert_eq!(run_and_get_int(source, 0), 1);
    }

    #[test]
    fn host_compare_prefix_shorter() {
        let source = r#"
            MOVE r1, "ab"
            MOVE r2, "abc"
            CALL_HOST r0, "compare", 2, r1
        "#;
        assert_eq!(run_and_get_int(source, 0), -1);
    }

    #[test]
    fn host_compare_prefix_longer() {
        let source = r#"
            MOVE r1, "abc"
            MOVE r2, "ab"
            CALL_HOST r0, "compare", 2, r1
        "#;
        assert_eq!(run_and_get_int(source, 0), 1);
    }

    #[test]
    fn host_compare_empty_strings() {
        let source = r#"
            MOVE r1, ""
            MOVE r2, ""
            CALL_HOST r0, "compare", 2, r1
        "#;
        assert_eq!(run_and_get_int(source, 0), 0);
    }

    #[test]
    fn host_compare_empty_vs_nonempty() {
        let source = r#"
            MOVE r1, ""
            MOVE r2, "a"
            CALL_HOST r0, "compare", 2, r1
        "#;
        assert_eq!(run_and_get_int(source, 0), -1);
    }

    #[test]
    fn host_compare_wrong_arg_count() {
        let source = r#"
            MOVE r1, "only"
            CALL_HOST r0, "compare", 1, r1
        "#;
        assert!(matches!(
            run_expect_err(source),
            VMError::ParseErrorString { .. }
        ));
    }

    // --- hash ---

    #[test]
    fn host_hash_returns_ref() {
        let source = r#"
            MOVE r1, "hello"
            CALL_HOST1 r0, "hash", r1
        "#;
        let vm = run_vm(source);
        assert!(matches!(vm.registers.get(0).unwrap(), Value::Ref(_)));
    }

    #[test]
    fn host_hash_consistent() {
        let source = r#"
            MOVE r1, "test"
            CALL_HOST1 r1, "hash", r1
            MOVE r2, "test"
            CALL_HOST1 r2, "hash", r2
            CALL_HOST r0, "compare", 2, r1
        "#;
        assert_eq!(run_and_get_int(source, 0), 0);
    }

    #[test]
    fn host_hash_different_inputs() {
        let source = r#"
            MOVE r1, "abc"
            CALL_HOST1 r2, "hash", r1
            MOVE r3, "abd"
            CALL_HOST1 r4, "hash", r3
            CALL_HOST r0, "compare", 2, r2
        "#;
        // Different inputs should produce different hashes
        assert_ne!(run_and_get_int(source, 0), 0);
    }

    #[test]
    fn host_hash_empty_string() {
        let source = r#"
            MOVE r1, ""
            CALL_HOST1 r0, "hash", r1
        "#;
        let vm = run_vm(source);
        let ref_id = vm.registers.get_ref(0, "").unwrap();
        let hash_bytes = &vm.heap.get_hash(ref_id).unwrap();
        // Verify against known SHA3-256 of empty string
        let expected = Hash::sha3().chain(b"").finalize();
        assert_eq!(hash_bytes.as_slice(), expected.as_slice());
    }

    #[test]
    fn host_hash_known_value() {
        let source = r#"
            MOVE r1, "hello"
            CALL_HOST1 r0, "hash", r1
        "#;
        let vm = run_vm(source);
        let ref_id = vm.registers.get_ref(0, "").unwrap();
        let hash_bytes = vm.heap.get_hash(ref_id).unwrap();
        let expected = Hash::sha3().chain(b"hello").finalize();
        assert_eq!(hash_bytes.as_slice(), expected.as_slice());
    }

    #[test]
    fn host_hash_wrong_arg_count() {
        let source = r#"
            MOVE r1, "a"
            MOVE r2, "b"
            CALL_HOST r0, "hash", 2, r1
        "#;
        assert!(matches!(
            run_expect_err(source),
            VMError::ParseErrorString { .. }
        ));
    }

    #[test]
    fn host_hash_wrong_type() {
        let source = r#"
            MOVE r1, 123
            CALL_HOST1 r0, "hash", r1
        "#;
        let vm = run_vm(source);
        let ref_id = vm.registers.get_ref(0, "").unwrap();
        let hash_bytes = vm.heap.get_hash(ref_id).unwrap();
        let reg = vm.registers.get_int(1, "").unwrap();
        let expected = Hash::sha3().chain(&reg.to_le_bytes()).finalize();
        assert_eq!(hash_bytes.as_slice(), expected.as_slice());
    }

    // --- invalid host function ---

    #[test]
    fn host_invalid_function() {
        let source = r#"
            MOVE r1, "arg"
            CALL_HOST r0, "nonexistent", 1, r1
        "#;
        assert!(matches!(
            run_expect_err(source),
            VMError::InvalidCallHostFunction { .. }
        ));
    }

    // --- CallHost0 ---

    #[test]
    fn call_host0_invalid_function() {
        let source = r#"CALL_HOST0 r0, "nonexistent""#;
        assert!(matches!(
            run_expect_err(source),
            VMError::InvalidCallHostFunction { .. }
        ));
    }

    // --- CallHost1 ---

    #[test]
    fn call_host1_len() {
        let source = r#"
            MOVE r1, "test"
            CALL_HOST1 r0, "len", r1
        "#;
        assert_eq!(run_and_get_int(source, 0), 4);
    }

    #[test]
    fn call_host1_len_with_immediate_string() {
        let source = r#"CALL_HOST1 r0, "len", "hello world""#;
        assert_eq!(run_and_get_int(source, 0), 11);
    }

    #[test]
    fn call_host1_hash_with_immediate_string() {
        let source = r#"CALL_HOST1 r0, "hash", "test""#;
        let vm = run_vm(source);
        let ref_id = vm.registers.get_ref(0, "").unwrap();
        let hash_bytes = vm.heap.get_hash(ref_id).unwrap();
        let expected = Hash::sha3().chain(b"test").finalize();
        assert_eq!(hash_bytes.as_slice(), expected.as_slice());
    }

    #[test]
    fn call_host1_hash_with_immediate_bool() {
        let source = "CALL_HOST1 r0, \"hash\", true";
        let vm = run_vm(source);
        let ref_id = vm.registers.get_ref(0, "").unwrap();
        let hash_bytes = vm.heap.get_hash(ref_id).unwrap();
        let expected = Hash::sha3().chain(&[1u8]).finalize();
        assert_eq!(hash_bytes.as_slice(), expected.as_slice());
    }

    #[test]
    fn call_host1_hash_with_immediate_int() {
        let source = "CALL_HOST1 r0, \"hash\", 42";
        let vm = run_vm(source);
        let ref_id = vm.registers.get_ref(0, "").unwrap();
        let hash_bytes = vm.heap.get_hash(ref_id).unwrap();
        let expected = Hash::sha3().chain(&42i64.to_le_bytes()).finalize();
        assert_eq!(hash_bytes.as_slice(), expected.as_slice());
    }

    #[test]
    fn call_host1_invalid_function() {
        let source = r#"CALL_HOST1 r0, "nonexistent", "arg""#;
        assert!(matches!(
            run_expect_err(source),
            VMError::InvalidCallHostFunction { .. }
        ));
    }

    // --- Call1 ---

    #[test]
    fn call1_basic() {
        let source = r#"
            JUMP skip_fn
            my_func(1, r0):
                MOVE r0, 100
                RET r0
            skip_fn:
            MOVE r2, 99
            CALL1 r1, my_func, r2
        "#;
        assert_eq!(run_and_get_int(source, 1), 100);
    }

    // ==================== CallDataLoad ====================

    fn run_vm_with_args(source: &str, args: Vec<Value>, arg_items: Vec<Vec<u8>>) -> VM {
        let program = assemble_source(source).expect("assembly failed");
        let mut data = program.init_code;
        data.extend(program.runtime_code);

        let mut heap = Heap::new(program.memory);
        for item in arg_items {
            heap.append(item);
        }

        let mut vm = VM {
            data,
            ip: 0,
            instr_offset: 0,
            registers: Registers::new(),
            heap,
            call_stack: Vec::new(),
            gas_used: 0,
            max_gas: BLOCK_GAS_LIMIT,
            gas_profile: GasProfile::new(),
            args,
        };

        vm.run(&mut TestState::new(), EXECUTION_CONTEXT)
            .expect("vm run failed");
        vm
    }

    fn expected_calldata(args: &[Value], arg_items: &[Vec<u8>]) -> Vec<u8> {
        let mut heap = Heap::new(vec![]);
        for item in arg_items {
            heap.append(item.clone());
        }

        let mut buf = Vec::new();
        for arg in args {
            match arg {
                Value::Bool(b) => b.encode(&mut buf),
                Value::Int(i) => i.encode(&mut buf),
                Value::Ref(r) => buf.write(heap.get_raw_ref(*r).unwrap_or(&[])),
            }
        }
        buf
    }

    #[test]
    fn calldata_load_int_args() {
        let vm = run_vm_with_args(
            "CALLDATA_LOAD r1",
            vec![Value::Int(10), Value::Int(20)],
            vec![],
        );
        assert_eq!(vm.registers.get_int(1, "").unwrap(), 10);
        assert_eq!(vm.registers.get_int(2, "").unwrap(), 20);
    }

    #[test]
    fn calldata_load_mixed_args() {
        let vm = run_vm_with_args(
            "CALLDATA_LOAD r0",
            vec![Value::Int(42), Value::Bool(true)],
            vec![],
        );
        assert_eq!(vm.registers.get_int(0, "").unwrap(), 42);
        assert!(vm.registers.get_bool(1, "").unwrap());
    }

    #[test]
    fn calldata_load_remaps_refs() {
        // arg_items inserts one heap item; Value::Ref(0) should be remapped to heap_arg_base.
        let vm = run_vm_with_args(
            "CALLDATA_LOAD r0",
            vec![Value::Ref(0)],
            vec![b"hello".to_vec()],
        );
        let r = vm.registers.get_ref(0, "").unwrap();
        assert_eq!(vm.heap.get_string(r).unwrap(), "hello");
    }

    #[test]
    fn calldata_load_no_args_is_noop() {
        // With no args, registers should remain at their default (Int(0)).
        let vm = run_vm_with_args("CALLDATA_LOAD r5\nMOVE r0, 1", vec![], vec![]);
        assert_eq!(vm.registers.get_int(0, "").unwrap(), 1);
    }

    #[test]
    fn calldata_load_at_high_register() {
        let vm = run_vm_with_args(
            "CALLDATA_LOAD r250",
            vec![Value::Int(7), Value::Int(8)],
            vec![],
        );
        assert_eq!(vm.registers.get_int(250, "").unwrap(), 7);
        assert_eq!(vm.registers.get_int(251, "").unwrap(), 8);
    }

    #[test]
    fn calldata_len_and_copy_match_serialized_args() {
        let args = vec![Value::Int(42), Value::Bool(true), Value::Ref(0)];
        let arg_items = vec![b"hi".to_vec()];
        let expected = expected_calldata(&args, &arg_items);
        let vm = run_vm_with_args("CALLDATA_LEN r0\nCALLDATA_COPY 64", args, arg_items);
        assert!(!expected.is_empty());
        assert_eq!(vm.registers.get_int(0, "").unwrap(), expected.len() as i64);
        assert_eq!(
            &vm.exec_memory()[64..64 + expected.len()],
            expected.as_slice()
        );
    }

    // ==================== host_func_argc ====================

    #[test]
    fn host_func_argc_known_functions() {
        assert_eq!(host_func_argc("len"), 1);
        assert_eq!(host_func_argc("hash"), 1);
        assert_eq!(host_func_argc("slice"), 3);
        assert_eq!(host_func_argc("concat"), 2);
        assert_eq!(host_func_argc("compare"), 2);
    }

    #[test]
    #[should_panic]
    fn host_func_argc_unknown_panics() {
        host_func_argc("nonexistent");
    }

    #[test]
    fn expand_mem_test() {
        let mut vm = run_vm("");
        vm.expand_memory(0, 8).unwrap();
        assert_eq!(vm.exec_memory().len(), 64);
    }

    #[test]
    fn memstore_test() {
        let code = r#"
        MEM_STORE 0, 1
        MEM_STORE 64, 2
        "#;
        let vm = run_vm(code);
        assert_eq!(vm.exec_memory().len(), 128);
    }

    #[test]
    fn memload_test() {
        let code = r#"
        MEM_STORE 0, 12
        MEM_LOAD r0, 0
        "#;
        let vm = run_vm(code);
        assert_eq!(vm.exec_memory().len(), 64);
        assert_eq!(&vm.exec_memory()[..8], &12i64.to_le_bytes());
        assert_eq!(vm.registers.get(0).unwrap(), &Value::Int(12));
    }

    #[test]
    fn memset_test() {
        let code = r#"
        MEM_SET 0, 64, 255
        "#;
        let vm = run_vm(code);
        assert_eq!(vm.exec_memory().len(), 512);
        assert_eq!(&vm.exec_memory()[..64], &[255u8; 64]);
    }

    #[test]
    fn memcpy_test() {
        let code = r#"
        MEM_SET 0, 64, 255
        MEM_COPY 128, 0, 64
        "#;
        let vm = run_vm(code);
        assert_eq!(vm.exec_memory().len(), 512);
        assert_eq!(&vm.exec_memory()[0..64], &[255u8; 64]);
        assert_eq!(&vm.exec_memory()[64..128], &[0u8; 64]);
        assert_eq!(&vm.exec_memory()[128..192], &[255u8; 64]);
    }

    #[test]
    fn memload_oob() {
        let err = run_expect_err("MEM_LOAD r0, 0");
        assert!(matches!(err, VMError::MemoryOOBRead { .. }));
    }

    #[test]
    fn memcpy_overlapping_forward() {
        // dst < src: copy [8..24] to [0..16], should work correctly
        let code = r#"
        MEM_SET 0, 24, 0
        MEM_SET 8, 16, 171
        MEM_COPY 0, 8, 16
        "#;
        let vm = run_vm(code);
        assert_eq!(&vm.exec_memory()[0..16], &[171u8; 16]);
        assert_eq!(&vm.exec_memory()[16..24], &[171u8; 8]);
    }

    #[test]
    fn memcpy_overlapping_backward() {
        // dst > src: copy [0..16] to [8..24], should work correctly
        let code = r#"
        MEM_SET 0, 16, 205
        MEM_COPY 8, 0, 16
        "#;
        let vm = run_vm(code);
        assert_eq!(&vm.exec_memory()[0..8], &[205u8; 8]);
        assert_eq!(&vm.exec_memory()[8..24], &[205u8; 16]);
    }

    #[test]
    fn memcpy_oob_read() {
        let code = r#"
        MEM_SET 0, 8, 0
        MEM_COPY 16, 64, 8
        "#;
        let err = run_expect_err(code);
        assert!(matches!(err, VMError::MemoryOOBRead { .. }));
    }

    #[test]
    fn memset_zero_length() {
        let vm = run_vm("MEM_SET 0, 0, 255");
        assert_eq!(vm.exec_memory().len(), 0);
    }

    #[test]
    fn memcpy_zero_length() {
        let code = r#"
        MEM_SET 0, 8, 170
        MEM_COPY 0, 0, 0
        "#;
        let vm = run_vm(code);
        assert_eq!(&vm.exec_memory()[..8], &[170u8; 8]);
    }

    #[test]
    fn expand_memory_alignment() {
        // Storing at offset 1 should expand by (9 needed bytes) * WORD_SIZE = 72
        let mut vm = run_vm("");
        vm.expand_memory(1, 8).unwrap();
        assert_eq!(vm.exec_memory().len(), 72);
    }

    #[test]
    fn memset_hex_addr_and_len() {
        let code = "MEM_SET 0x10, 0x20, 0xAB";
        let vm = run_vm(code);
        assert_eq!(vm.exec_memory().len(), 384);
        assert_eq!(&vm.exec_memory()[0x10..0x30], &[0xABu8; 0x20]);
    }

    #[test]
    fn memcpy_hex_params() {
        let code = r#"
        MEM_SET 0x00, 0x10, 0xFF
        MEM_COPY 0x20, 0x00, 0x10
        "#;
        let vm = run_vm(code);
        assert_eq!(&vm.exec_memory()[0x00..0x10], &[0xFFu8; 0x10]);
        assert_eq!(&vm.exec_memory()[0x20..0x30], &[0xFFu8; 0x10]);
    }

    #[test]
    fn memstore_hex_addr() {
        let code = "MEM_STORE 0x40, 0x1234";
        let vm = run_vm(code);
        assert_eq!(vm.exec_memory().len(), 576);
        assert_eq!(&vm.exec_memory()[0x40..0x48], &0x1234i64.to_le_bytes());
    }

    #[test]
    fn memload_hex_addr() {
        let code = r#"
        MEM_STORE 0x08, 0xDEAD
        MEM_LOAD r0, 0x08
        "#;
        let vm = run_vm(code);
        assert_eq!(vm.registers.get(0).unwrap(), &Value::Int(0xDEAD));
    }

    #[test]
    fn memload_8u_hex_addr() {
        let code = r#"
        MEM_STORE 0x08, 0xDEAD
        MEM_LOAD_8U r0, 0x08
        "#;
        let vm = run_vm(code);
        assert_eq!(vm.registers.get(0).unwrap(), &Value::Int(0xAD));
    }

    #[test]
    fn memload_8s_hex_addr() {
        let code = r#"
        MEM_STORE 0x08, 0xDEAD
        MEM_LOAD_8S r0, 0x08
        "#;
        let vm = run_vm(code);

        assert_eq!(
            vm.registers.get(0).unwrap(),
            &Value::Int(0xFFFFFFFFFFFFFFADu64 as i64)
        );
    }

    #[test]
    fn memload_8s_hex_addr2() {
        let code = r#"
        MEM_STORE 0x08, 0xDE7D
        MEM_LOAD_8S r0, 0x08
        "#;
        let vm = run_vm(code);

        assert_eq!(vm.registers.get(0).unwrap(), &Value::Int(0x7Du64 as i64));
    }

    // ==================== 16-bit memory loads ====================

    #[test]
    fn memload_16u_zero_extends() {
        let code = r#"
        MEM_STORE 0x00, 0xFFFF
        MEM_LOAD_16U r0, 0x00
        "#;
        let vm = run_vm(code);
        assert_eq!(vm.registers.get(0).unwrap(), &Value::Int(0xFFFF));
    }

    #[test]
    fn memload_16s_sign_extends_negative() {
        let code = r#"
        MEM_STORE 0x00, 0x8000
        MEM_LOAD_16S r0, 0x00
        "#;
        let vm = run_vm(code);
        assert_eq!(
            vm.registers.get(0).unwrap(),
            &Value::Int(0xFFFFFFFFFFFF8000u64 as i64)
        );
    }

    #[test]
    fn memload_16s_no_extend_positive() {
        let code = r#"
        MEM_STORE 0x00, 0x7FFF
        MEM_LOAD_16S r0, 0x00
        "#;
        let vm = run_vm(code);
        assert_eq!(vm.registers.get(0).unwrap(), &Value::Int(0x7FFF));
    }

    // ==================== 32-bit memory loads ====================

    #[test]
    fn memload_32u_zero_extends() {
        let code = r#"
        MEM_STORE 0x00, 0xFFFFFFFF
        MEM_LOAD_32U r0, 0x00
        "#;
        let vm = run_vm(code);
        assert_eq!(vm.registers.get(0).unwrap(), &Value::Int(0xFFFFFFFF));
    }

    #[test]
    fn memload_32s_sign_extends_negative() {
        let code = r#"
        MEM_STORE 0x00, 0x80000000
        MEM_LOAD_32S r0, 0x00
        "#;
        let vm = run_vm(code);
        assert_eq!(
            vm.registers.get(0).unwrap(),
            &Value::Int(0xFFFFFFFF80000000u64 as i64)
        );
    }

    #[test]
    fn memload_32s_no_extend_positive() {
        let code = r#"
        MEM_STORE 0x00, 0x7FFFFFFF
        MEM_LOAD_32S r0, 0x00
        "#;
        let vm = run_vm(code);
        assert_eq!(vm.registers.get(0).unwrap(), &Value::Int(0x7FFFFFFF));
    }

    // ==================== Register-based addressing ====================

    #[test]
    fn memstore_register_addr() {
        let code = r#"
        MOVE r1, 0x10
        MEM_STORE r1, 0xABCD
        MEM_LOAD r0, 0x10
        "#;
        let vm = run_vm(code);
        assert_eq!(vm.registers.get(0).unwrap(), &Value::Int(0xABCD));
    }

    #[test]
    fn memload_register_addr() {
        let code = r#"
        MEM_STORE 0x20, 0x1234
        MOVE r1, 0x20
        MEM_LOAD r0, r1
        "#;
        let vm = run_vm(code);
        assert_eq!(vm.registers.get(0).unwrap(), &Value::Int(0x1234));
    }

    #[test]
    fn memcpy_register_addrs() {
        let code = r#"
        MEM_SET 0x00, 8, 0xAA
        MOVE r1, 0x10
        MOVE r2, 0x00
        MOVE r3, 8
        MEM_COPY r1, r2, r3
        MEM_LOAD r0, 0x10
        "#;
        let vm = run_vm(code);
        assert_eq!(
            vm.registers.get(0).unwrap(),
            &Value::Int(i64::from_le_bytes([0xAA; 8]))
        );
    }

    #[test]
    fn memset_register_addrs() {
        let code = r#"
        MOVE r1, 0x08
        MOVE r2, 8
        MEM_SET r1, r2, 0xFF
        MEM_LOAD r0, 0x08
        "#;
        let vm = run_vm(code);
        assert_eq!(
            vm.registers.get(0).unwrap(),
            &Value::Int(i64::from_le_bytes([0xFF; 8]))
        );
    }

    #[test]
    fn memload_8u_register_addr() {
        let code = r#"
        MEM_STORE 0x00, 0xABCD
        MOVE r1, 0x00
        MEM_LOAD_8U r0, r1
        "#;
        let vm = run_vm(code);
        assert_eq!(vm.registers.get(0).unwrap(), &Value::Int(0xCD));
    }

    #[test]
    fn memload_16s_register_addr() {
        let code = r#"
        MEM_STORE 0x00, 0x8001
        MOVE r1, 0x00
        MEM_LOAD_16S r0, r1
        "#;
        let vm = run_vm(code);
        assert_eq!(
            vm.registers.get(0).unwrap(),
            &Value::Int(0xFFFFFFFFFFFF8001u64 as i64)
        );
    }

    // ==================== CMOVE instruction ====================

    #[test]
    fn cmove_true_condition() {
        let code = r#"
        MOVE r1, 100
        MOVE r2, 200
        CMOVE r0, true, r1, r2
        "#;
        let vm = run_vm(code);
        assert_eq!(vm.registers.get(0).unwrap(), &Value::Int(100));
    }

    #[test]
    fn cmove_false_condition() {
        let code = r#"
        MOVE r1, 100
        MOVE r2, 200
        CMOVE r0, false, r1, r2
        "#;
        let vm = run_vm(code);
        assert_eq!(vm.registers.get(0).unwrap(), &Value::Int(200));
    }

    #[test]
    fn cmove_nonzero_int_is_true() {
        let code = r#"
        MOVE r1, 100
        MOVE r2, 200
        CMOVE r0, 1, r1, r2
        "#;
        let vm = run_vm(code);
        assert_eq!(vm.registers.get(0).unwrap(), &Value::Int(100));
    }

    #[test]
    fn cmove_zero_int_is_false() {
        let code = r#"
        MOVE r1, 100
        MOVE r2, 200
        CMOVE r0, 0, r1, r2
        "#;
        let vm = run_vm(code);
        assert_eq!(vm.registers.get(0).unwrap(), &Value::Int(200));
    }

    #[test]
    fn cmove_negative_int_is_true() {
        let code = r#"
        MOVE r1, 100
        MOVE r2, 200
        CMOVE r0, -1, r1, r2
        "#;
        let vm = run_vm(code);
        assert_eq!(vm.registers.get(0).unwrap(), &Value::Int(100));
    }

    #[test]
    fn cmove_register_condition_true() {
        let code = r#"
        MOVE r3, 5
        MOVE r1, 100
        MOVE r2, 200
        CMOVE r0, r3, r1, r2
        "#;
        let vm = run_vm(code);
        assert_eq!(vm.registers.get(0).unwrap(), &Value::Int(100));
    }

    #[test]
    fn cmove_register_condition_false() {
        let code = r#"
        MOVE r3, 0
        MOVE r1, 100
        MOVE r2, 200
        CMOVE r0, r3, r1, r2
        "#;
        let vm = run_vm(code);
        assert_eq!(vm.registers.get(0).unwrap(), &Value::Int(200));
    }

    #[test]
    fn cmove_bool_register_condition() {
        let code = r#"
        MOVE r3, true
        MOVE r1, 100
        MOVE r2, 200
        CMOVE r0, r3, r1, r2
        "#;
        let vm = run_vm(code);
        assert_eq!(vm.registers.get(0).unwrap(), &Value::Int(100));
    }

    #[test]
    fn cmove_immediate_operands() {
        let code = "CMOVE r0, true, 42, 99";
        let vm = run_vm(code);
        assert_eq!(vm.registers.get(0).unwrap(), &Value::Int(42));
    }
}
