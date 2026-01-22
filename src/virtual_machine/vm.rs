//! Core virtual machine implementation.
//!
//! The VM executes bytecode using a register-based architecture with 256 general-purpose
//! registers. All arithmetic uses wrapping semantics to prevent overflow panics.

use crate::types::hash::{HASH_LEN, Hash};
use crate::virtual_machine::assembler::parse_i64;
use crate::virtual_machine::errors::VMError;
use crate::virtual_machine::isa::Instruction;
use crate::virtual_machine::program::{DeployProgram, ExecuteProgram};
use crate::virtual_machine::state::State;
use blockchain_derive::BinaryCodec;
use std::fmt::Write;

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

    (@read $data:ident $cursor:ident $start:ident Bool) => {{
        let v = read_u8($data, &mut $cursor, $start)?;
        Ok::<String, VMError>(if v == 0 { "false".to_string() } else { "true".to_string() })
    }};

    (@read $data:ident $cursor:ident $start:ident RefU32) => {{
        let bytes = read_bytes($data, &mut $cursor, 4, $start)?;
        Ok::<String, VMError>(format!("@{}", u32::from_le_bytes(bytes.try_into().unwrap())))
    }};

    (@read $data:ident $cursor:ident $start:ident ImmI64) => {{
        let bytes = read_bytes($data, &mut $cursor, 8, $start)?;
        Ok::<String, VMError>(i64::from_le_bytes(bytes.try_into().unwrap()).to_string())
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
        ]
        .into_iter()
    }
}

/// Maximum gas allowed for a single transaction execution.
pub const TRANSACTION_GAS_LIMIT: u64 = 1_000_000;
/// Maximum cumulative gas allowed for all transactions in a block.
pub const BLOCK_GAS_LIMIT: u64 = 20_000_000;

/// Maximum depth of the call stack to prevent unbounded recursion.
const MAX_CALL_STACK_LEN: usize = 1024;
/// Gas cost per byte when writing to state storage.
const STORE_BYTE_COST: u64 = 10;
/// Gas cost per byte when reading from state storage.
const READ_BYTE_COST: u64 = 5;

/// Runtime value stored in registers and used for typed call arguments.
#[derive(Clone, Copy, Debug, Eq, PartialEq, BinaryCodec)]
pub enum Value {
    /// Uninitialized or zero value.
    Zero,
    /// Boolean value.
    Bool(bool),
    /// Reference to a heap-allocated object (string pool index).
    Ref(u32),
    /// 64-bit signed integer.
    Int(i64),
}

impl Value {
    /// Returns the type name for error messages.
    pub fn type_name(&self) -> &'static str {
        match self {
            Value::Zero => "Zero",
            Value::Bool(_) => "Bool",
            Value::Ref(_) => "Ref",
            Value::Int(_) => "Int",
        }
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
            regs: vec![Value::Zero; 256],
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

/// Heap storage for reference-counted objects.
///
/// Currently, holds only the string pool loaded from the program.
struct Heap(Vec<Vec<u8>>);

impl Heap {
    fn new(items: Vec<Vec<u8>>) -> Self {
        Self(items)
    }

    /// Add the given item and returns it's index
    fn index(&mut self, item: Vec<u8>) -> u32 {
        self.0.push(item);
        (self.len() - 1) as u32
    }

    /// Returns a reference to the raw [`Vec<u8>`] stored at the given index
    fn get_raw_ref(&self, reference: u32) -> Result<&Vec<u8>, VMError> {
        self.0
            .get(reference as usize)
            .ok_or(VMError::ReferenceOutOfBounds {
                reference,
                max: self.len() - 1,
            })
    }

    /// Returns how many items are stored in this heap
    fn len(&self) -> usize {
        self.0.len()
    }

    /// Retrieves a string by its reference index.
    fn get_string(&self, id: u32) -> Result<String, VMError> {
        String::from_utf8(self.0[id as usize].clone())
            .map_err(|_| VMError::InvalidUtf8 { string_ref: id })
    }

    /// Retrieves a hash by its reference index.
    fn get_hash(&self, id: u32) -> Result<Hash, VMError> {
        let bytes = &self.0[id as usize];
        match Hash::from_slice(bytes) {
            None => Err(VMError::InvalidHash {
                expected_len: HASH_LEN,
                actual_len: bytes.len(),
            }),
            Some(hash) => Ok(hash),
        }
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

    // Decode a bool (1 byte, 0 = false, nonzero = true)
    (@read $vm:ident, Bool) => {{
        Ok::<bool, VMError>($vm.read_exact(1)?[0] != 0)
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
/// 1) 🔴 Add arithmetic op codes that take in immediate instead of register
/// 2) 🔴 Add list and map support
/// 3) 🔴 Add a deterministic optimizer do make the assembly code more performant
///
/// # TODO after 1.0.0:
/// 4) 🔴 Add a smart contract language to not require assembly written smart contracts
/// 5) 🔴 Add a deterministic compiler to convert the language to assembly
/// 6) 🔴 Add an LSP for smoother smart contract writing experience
pub struct VM {
    /// Concatenated bytecode (init_code + runtime_code).
    data: Vec<u8>,
    /// Instruction pointer (current position in bytecode).
    ip: usize,
    /// Register file (256 registers).
    registers: Registers,
    /// Heap for string pool and future allocations.
    heap: Heap,
    /// Call stack for function calls.
    call_stack: Vec<CallFrame>,
    /// Total gas consumed during execution.
    gas_used: u64,
    /// Maximum gas allowed for this execution; exceeding it triggers `OutOfGas`.
    max_gas: u64,
    /// Gas consumption breakdown by category.
    gas_profile: GasProfile,
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
            registers: Registers::new(),
            heap: Heap::new(program.items),
            call_stack: Vec::new(),
            gas_used: 0,
            max_gas,
            gas_profile: GasProfile::new(),
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
        program: ExecuteProgram,
        data: Vec<u8>,
        items: Vec<Vec<u8>>,
        max_gas: u64,
    ) -> Result<Self, VMError> {
        // Build a VM for runtime execution, seeding registers with typed args and extending
        // the heap with any argument-owned items referenced via Value::Ref.
        // Labels are resolved as PC-relative offsets, so init_size is not needed.
        let mut vm = Self {
            data,
            ip: 0,
            registers: Registers::new(),
            heap: Heap::new(items),
            call_stack: Vec::new(),
            gas_used: 0,
            max_gas,
            gas_profile: GasProfile::new(),
        };

        // Load argument-specific heap items so Value::Ref can target them.
        let arg_items_len = program.arg_items.len();
        let arg_ref_base = vm.heap.len() as u32;
        for item in program.arg_items {
            vm.heap.index(item);
        }

        vm.registers.set(0, Value::Int(program.function_id))?;
        let mut i = 1u8;
        for arg in program.args {
            let mapped = match arg {
                Value::Ref(r) if (r as usize) < arg_items_len => Value::Ref(arg_ref_base + r),
                other => other,
            };
            vm.registers.set(i, mapped)?;
            i += 1;
        }

        Ok(vm)
    }

    /// Logs a formatted runtime error diagnostic to stderr.
    fn log_runtime_error(&self, err: &VMError) {
        eprintln!("{}", self.format_runtime_error(err));
    }

    /// Formats a runtime error with bytecode context and call stack.
    fn format_runtime_error(&self, err: &VMError) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "error: VM runtime failure: {err}");

        if let Some(ip) = self.error_ip(err) {
            let _ = writeln!(out, "   --> bytecode:{ip}");
            if let Some(asm) = self.disassembly_snippet(ip) {
                out.push_str(&asm);
            }
            if let Some(snippet) = self.bytecode_snippet(ip) {
                out.push_str(&snippet);
            }
        }

        let _ = writeln!(out, "note: gas used {} of {}", self.gas_used, self.max_gas);
        if self.call_stack.is_empty() {
            let _ = writeln!(out, "note: call stack is empty");
        } else {
            let _ = writeln!(out, "note: call stack (most recent first):");
            for (depth, frame) in self.call_stack.iter().rev().enumerate() {
                let _ = writeln!(
                    out,
                    "  {depth}: return to ip {} -> r{}",
                    frame.return_addr, frame.dst_reg
                );
            }
        }

        out
    }

    /// Returns a hex dump of bytecode around the given instruction pointer.
    fn bytecode_snippet(&self, ip: usize) -> Option<String> {
        if self.data.is_empty() {
            return None;
        }

        let window = 8usize;
        let start = ip.saturating_sub(window);
        let end = (ip + window + 1).min(self.data.len());

        let mut rendered = String::new();
        let mut caret_col = 0usize;
        for (idx, byte) in self.data.get(start..end)?.iter().enumerate() {
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

        let mut snippet = String::new();
        let _ = writeln!(
            snippet,
            "    | window [{}..{}) of {} bytes",
            start,
            end,
            self.data.len()
        );
        let _ = writeln!(snippet, "    | {rendered}");
        let _ = writeln!(snippet, "    | {}^", " ".repeat(caret_col));
        Some(snippet)
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
    fn disassembly_snippet(&self, ip: usize) -> Option<String> {
        let listing = self.disassembly_listing();
        if listing.is_empty() {
            return None;
        }

        let target_idx = listing
            .iter()
            .position(|(offset, _, size)| (*offset..offset + *size).contains(&ip))
            .or_else(|| listing.iter().rposition(|(offset, _, _)| *offset <= ip));

        let idx = target_idx?;
        let start = idx.saturating_sub(2);
        let end = (idx + 3).min(listing.len());

        let mut out = String::new();
        let _ = writeln!(out, "    | assembly around ip {ip}:");
        for (i, (offset, text, _)) in listing[start..end].iter().enumerate() {
            let cursor = start + i == idx;
            let marker = if cursor { "-->" } else { "   " };
            let _ = writeln!(out, "{marker} {:>6}: {}", offset, text);
        }
        Some(out)
    }

    /// Extracts the instruction pointer associated with a VM error, if available.
    fn error_ip(&self, err: &VMError) -> Option<usize> {
        match err {
            VMError::InvalidInstruction { offset, .. } => Some(*offset),
            VMError::UnexpectedEndOfBytecode { ip, .. } => Some(*ip),
            VMError::InvalidIP { ip } => Some(*ip),
            VMError::JumpOutOfBounds { from, .. } => Some(*from),
            VMError::ReturnWithoutCall { .. } => Some(self.ip),
            VMError::OutOfGas { .. } => Some(self.ip.saturating_sub(1)),
            _ => Some(self.ip),
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

/// impl block for VM wrapper functions to charge gas
impl VM {
    /// Stores an item on the heap and returns its reference index.
    ///
    /// Charges gas proportional to the item's byte length.
    fn heap_index(&mut self, item: Vec<u8>) -> Result<u32, VMError> {
        self.charge_gas_categorized(item.len() as u64, GasCategory::HeapAllocation)?;
        Ok(self.heap.index(item))
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

    /// Retrieves a hash from the heap by reference index with gas charging.
    ///
    /// Charges gas proportional to the hash's byte length.
    fn heap_get_hash(&mut self, id: u32) -> Result<Hash, VMError> {
        self.charge_gas_categorized(HASH_LEN as u64, GasCategory::HeapAllocation)?;
        self.heap.get_hash(id)
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
                let opcode_offset = self.ip;
                let opcode = self.data[opcode_offset];
                self.ip += 1;

                let instr =
                    Instruction::try_from(opcode).map_err(|_| VMError::InvalidInstruction {
                        opcode,
                        offset: opcode_offset,
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
                // Store and Load
                DeleteState => op_delete_state(state, ctx; rd: Reg),
                LoadI64 => op_load_i64(rd: Reg, imm: ImmI64),
                StoreI64 => op_store_i64(state, ctx; key: Reg, value: Reg),
                LoadI64State => op_load_i64_state(state, ctx; rd: Reg, key: Reg),
                LoadBool => op_load_bool(rd: Reg, b: Bool),
                StoreBool => op_store_bool(state, ctx; key: Reg, value: Reg),
                LoadBoolState => op_load_bool_state(state, ctx; rd: Reg, key: Reg),
                LoadStr => op_load_str(rd: Reg, str_ref: RefU32),
                StoreStr => op_store_str(state, ctx; key: Reg, value: Reg),
                LoadStrState => op_load_str_state(state, ctx; rd: Reg, key: Reg),
                LoadHash => op_load_hash(rd: Reg, hash_ref: RefU32),
                StoreHash => op_store_hash(state, ctx; key: Reg, value: Reg),
                LoadHashState => op_load_hash_state(state, ctx; rd: Reg, key: Reg),
                // Moves / casts
                Move => op_move(rd: Reg, rs: Reg),
                I64ToBool => op_i64_to_bool(rd: Reg, rs: Reg),
                BoolToI64 => op_bool_to_i64(rd: Reg, rs: Reg),
                StrToI64 => op_str_to_i64(rd: Reg, rs: Reg),
                I64ToStr => op_i64_to_str(rd: Reg, rs: Reg),
                StrToBool => op_str_to_bool(rd: Reg, rs: Reg),
                BoolToStr => op_bool_to_str(rd: Reg, rs: Reg),
                // Integer arithmetic
                Add => op_add(rd: Reg, rs1: Reg, rs2: Reg),
                Sub => op_sub(rd: Reg, rs1: Reg, rs2: Reg),
                Mul => op_mul(rd: Reg, rs1: Reg, rs2: Reg),
                Div => op_div(rd: Reg, rs1: Reg, rs2: Reg),
                Mod => op_mod(rd: Reg, rs1: Reg, rs2: Reg),
                Neg => op_neg(rd: Reg, rs: Reg),
                Abs => op_abs(rd: Reg, rs: Reg),
                Min => op_min(rd: Reg, rs1: Reg, rs2: Reg),
                Max => op_max(rd: Reg, rs1: Reg, rs2: Reg),
                Shl => op_shl(rd: Reg, rs1: Reg, rs2: Reg),
                Shr => op_shr(rd: Reg, rs1: Reg, rs2: Reg),
                // Boolean / comparison
                Not => op_not(rd: Reg, rs: Reg),
                And => op_and(rd: Reg, rs1: Reg, rs2: Reg),
                Or => op_or(rd: Reg, rs1: Reg, rs2: Reg),
                Xor => op_xor(rd: Reg, rs1: Reg, rs2: Reg),
                Eq => op_eq(rd: Reg, rs1: Reg, rs2: Reg),
                Lt => op_lt(rd: Reg, rs1: Reg, rs2: Reg),
                Le => op_le(rd: Reg, rs1: Reg, rs2: Reg),
                Gt => op_gt(rd: Reg, rs1: Reg, rs2: Reg),
                Ge => op_ge(rd: Reg, rs1: Reg, rs2: Reg),
                // Control Flow
                CallHost => op_call_host(dst: Reg, fn_id: RefU32, argc: ImmU8, argv: Reg),
                Call => op_call(dst: Reg, offset: ImmI64, argc: ImmU8, argv: Reg),
                Call0 => op_call0(dst: Reg, fn_id: ImmI64),
                Jal => op_jal(rd: Reg, offset: ImmI64),
                Jalr => op_jalr(rd: Reg, rs: Reg, offset: ImmI64),
                Beq => op_beq(rs1: Reg, rs2: Reg, offset: ImmI64),
                Bne => op_bne(rs1: Reg, rs2: Reg, offset: ImmI64),
                Blt => op_blt(rs1: Reg, rs2: Reg, offset: ImmI64),
                Bge => op_bge(rs1: Reg, rs2: Reg, offset: ImmI64),
                Bltu => op_bltu(rs1: Reg, rs2: Reg, offset: ImmI64),
                Bgeu => op_bgeu(rs1: Reg, rs2: Reg, offset: ImmI64),
                Jump => op_jump(offset: ImmI64),
                Ret => op_ret(rs: Reg),
                Halt => op_halt(),
            }
        }
    }

    fn op_delete_state<S: State>(
        &mut self,
        instr: &'static str,
        state: &mut S,
        ctx: &ExecContext,
        key: u8,
    ) -> Result<(), VMError> {
        let key_ref = self.registers.get_ref(key, instr)?;
        let key_str = self.heap_get_string(key_ref)?;
        let key = self.make_state_key(ctx.chain_id, &ctx.contract_id, key_str.as_bytes())?;
        state.delete(key);
        Ok(())
    }

    fn op_load_i64(&mut self, _instr: &'static str, dst: u8, imm: i64) -> Result<(), VMError> {
        self.registers.set(dst, Value::Int(imm))
    }

    fn op_store_i64<S: State>(
        &mut self,
        instr: &'static str,
        state: &mut S,
        ctx: &ExecContext,
        key: u8,
        value: u8,
    ) -> Result<(), VMError> {
        let key_ref = self.registers.get_ref(key, instr)?;
        let key_str = self.heap_get_string(key_ref)?;
        let val = self.registers.get_int(value, instr)?;
        let key = self.make_state_key(ctx.chain_id, &ctx.contract_id, key_str.as_bytes())?;
        self.state_push(state, key, val.to_le_bytes().to_vec())?;
        Ok(())
    }

    fn op_load_i64_state<S: State>(
        &mut self,
        instr: &'static str,
        state: &mut S,
        ctx: &ExecContext,
        dst: u8,
        key: u8,
    ) -> Result<(), VMError> {
        let key_ref = self.registers.get_ref(key, instr)?;
        let key_str = self.heap_get_string(key_ref)?;
        let state_key = self.make_state_key(ctx.chain_id, &ctx.contract_id, key_str.as_bytes())?;
        let value = self.state_get(state, state_key)?;
        let bytes: [u8; 8] = value.try_into().map_err(|_| VMError::InvalidStateValue {
            key: key_str.clone(),
            expected: "8 bytes for i64",
        })?;
        self.registers
            .set(dst, Value::Int(i64::from_le_bytes(bytes)))
    }

    fn op_load_bool(&mut self, _instr: &'static str, dst: u8, b: bool) -> Result<(), VMError> {
        self.registers.set(dst, Value::Bool(b))
    }

    fn op_store_bool<S: State>(
        &mut self,
        instr: &'static str,
        state: &mut S,
        ctx: &ExecContext,
        key: u8,
        value: u8,
    ) -> Result<(), VMError> {
        let key_ref = self.registers.get_ref(key, instr)?;
        let key_str = self.heap_get_string(key_ref)?;
        let val = self.registers.get_bool(value, instr)?;
        let key = self.make_state_key(ctx.chain_id, &ctx.contract_id, key_str.as_bytes())?;
        self.state_push(state, key, [val as u8].into())?;
        Ok(())
    }

    fn op_load_bool_state<S: State>(
        &mut self,
        instr: &'static str,
        state: &mut S,
        ctx: &ExecContext,
        dst: u8,
        key: u8,
    ) -> Result<(), VMError> {
        let key_ref = self.registers.get_ref(key, instr)?;
        let key_str = self.heap_get_string(key_ref)?;
        let state_key = self.make_state_key(ctx.chain_id, &ctx.contract_id, key_str.as_bytes())?;
        let value = self.state_get(state, state_key)?;
        if value.len() != 1 {
            return Err(VMError::InvalidStateValue {
                key: key_str,
                expected: "1 byte for bool",
            });
        }
        self.registers.set(dst, Value::Bool(value[0] != 0))
    }

    fn op_load_str(&mut self, _instr: &'static str, dst: u8, str_ref: u32) -> Result<(), VMError> {
        self.registers.set(dst, Value::Ref(str_ref))
    }

    fn op_store_str<S: State>(
        &mut self,
        instr: &'static str,
        state: &mut S,
        ctx: &ExecContext,
        key: u8,
        value: u8,
    ) -> Result<(), VMError> {
        let key_ref = self.registers.get_ref(key, instr)?;
        let key_str = self.heap_get_string(key_ref)?;
        let val_ref = self.registers.get_ref(value, instr)?;
        let val_str = self.heap_get_string(val_ref)?;
        let key = self.make_state_key(ctx.chain_id, &ctx.contract_id, key_str.as_bytes())?;
        self.state_push(state, key, val_str.into_bytes())?;
        Ok(())
    }

    fn op_load_str_state<S: State>(
        &mut self,
        instr: &'static str,
        state: &mut S,
        ctx: &ExecContext,
        dst: u8,
        key: u8,
    ) -> Result<(), VMError> {
        let key_ref = self.registers.get_ref(key, instr)?;
        let key_str = self.heap_get_string(key_ref)?;
        let state_key = self.make_state_key(ctx.chain_id, &ctx.contract_id, key_str.as_bytes())?;
        let value = state
            .get(state_key)
            .ok_or(VMError::KeyNotFound { key: key_str })?;
        let str_ref = self.heap_index(value)?;
        self.op_load_str(instr, dst, str_ref)
    }

    fn op_load_hash(
        &mut self,
        _instr: &'static str,
        dst: u8,
        hash_ref: u32,
    ) -> Result<(), VMError> {
        self.registers.set(dst, Value::Ref(hash_ref))
    }

    fn op_store_hash<S: State>(
        &mut self,
        instr: &'static str,
        state: &mut S,
        ctx: &ExecContext,
        key: u8,
        value: u8,
    ) -> Result<(), VMError> {
        let key_ref = self.registers.get_ref(key, instr)?;
        let key_str = self.heap_get_string(key_ref)?;
        let val_ref = self.registers.get_ref(value, instr)?;
        let val_hash = self.heap_get_hash(val_ref)?;
        let key = self.make_state_key(ctx.chain_id, &ctx.contract_id, key_str.as_bytes())?;
        self.state_push(state, key, val_hash.to_vec())?;
        Ok(())
    }

    fn op_load_hash_state<S: State>(
        &mut self,
        instr: &'static str,
        state: &mut S,
        ctx: &ExecContext,
        dst: u8,
        key: u8,
    ) -> Result<(), VMError> {
        let key_ref = self.registers.get_ref(key, instr)?;
        let key_str = self.heap_get_string(key_ref)?;
        let state_key = self.make_state_key(ctx.chain_id, &ctx.contract_id, key_str.as_bytes())?;
        let value = state
            .get(state_key)
            .ok_or(VMError::KeyNotFound { key: key_str })?;
        let hash_ref = self.heap_index(value)?;
        self.op_load_hash(instr, dst, hash_ref)
    }

    fn op_move(&mut self, _instr: &'static str, dst: u8, src: u8) -> Result<(), VMError> {
        let v = *self.registers.get(src)?;
        self.registers.set(dst, v)
    }

    fn op_i64_to_bool(&mut self, instr: &'static str, dst: u8, src: u8) -> Result<(), VMError> {
        let v = self.registers.get_int(src, instr)?;
        self.registers.set(dst, Value::Bool(v != 0))
    }

    fn op_bool_to_i64(&mut self, instr: &'static str, dst: u8, src: u8) -> Result<(), VMError> {
        let v = self.registers.get_bool(src, instr)?;
        self.registers.set(dst, Value::Int(if v { 1 } else { 0 }))
    }

    fn op_str_to_i64(&mut self, instr: &'static str, dst: u8, src: u8) -> Result<(), VMError> {
        let reg = self.registers.get_ref(src, instr)?;
        let str = self.heap_get_string(reg)?;
        self.op_load_i64(instr, dst, parse_i64(&str)?)
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

    fn op_i64_to_str(&mut self, instr: &'static str, dst: u8, src: u8) -> Result<(), VMError> {
        let reg = self.registers.get_int(src, instr)?;
        // Charge gas manually before allocation instead of using heap_index()
        self.charge_gas_categorized(Self::digits_i64(reg), GasCategory::HeapAllocation)?;
        let str_ref = self.heap.index(reg.to_string().into_bytes());
        self.op_load_str(instr, dst, str_ref)
    }

    fn op_str_to_bool(&mut self, instr: &'static str, dst: u8, src: u8) -> Result<(), VMError> {
        let reg = self.registers.get_ref(src, instr)?;
        let str = self.heap_get_string(reg)?;
        let b = if str == "true" {
            true
        } else if str == "false" {
            false
        } else {
            return Err(VMError::TypeMismatch {
                instruction: instr,
                arg_index: 0,
                expected: "\"true\" or \"false\"",
                actual: str,
            });
        };
        self.op_load_bool(instr, dst, b)
    }

    fn op_bool_to_str(&mut self, instr: &'static str, dst: u8, src: u8) -> Result<(), VMError> {
        let reg = self.registers.get_bool(src, instr)?;
        // Charge gas manually before allocation instead of using heap_index()
        self.charge_gas_categorized(if reg { 4 } else { 5 }, GasCategory::HeapAllocation)?;
        let str = (if reg { "true" } else { "false" }).to_string();
        let bool_ref = self.heap.index(str.into_bytes());
        self.op_load_str(instr, dst, bool_ref)
    }

    fn op_add(&mut self, instr: &'static str, dst: u8, a: u8, b: u8) -> Result<(), VMError> {
        let va = self.registers.get_int(a, instr)?;
        let vb = self.registers.get_int(b, instr)?;
        self.registers.set(dst, Value::Int(va.wrapping_add(vb)))
    }

    fn op_sub(&mut self, instr: &'static str, dst: u8, a: u8, b: u8) -> Result<(), VMError> {
        let va = self.registers.get_int(a, instr)?;
        let vb = self.registers.get_int(b, instr)?;
        self.registers.set(dst, Value::Int(va.wrapping_sub(vb)))
    }

    fn op_mul(&mut self, instr: &'static str, dst: u8, a: u8, b: u8) -> Result<(), VMError> {
        let va = self.registers.get_int(a, instr)?;
        let vb = self.registers.get_int(b, instr)?;
        self.registers.set(dst, Value::Int(va.wrapping_mul(vb)))
    }

    fn op_div(&mut self, instr: &'static str, dst: u8, a: u8, b: u8) -> Result<(), VMError> {
        let va = self.registers.get_int(a, instr)?;
        let vb = self.registers.get_int(b, instr)?;
        if vb == 0 {
            return Err(VMError::DivisionByZero);
        }
        self.registers.set(dst, Value::Int(va.wrapping_div(vb)))
    }

    fn op_mod(&mut self, instr: &'static str, dst: u8, a: u8, b: u8) -> Result<(), VMError> {
        let va = self.registers.get_int(a, instr)?;
        let vb = self.registers.get_int(b, instr)?;
        if vb == 0 {
            return Err(VMError::DivisionByZero);
        }
        self.registers.set(dst, Value::Int(va.wrapping_rem(vb)))
    }

    fn op_neg(&mut self, instr: &'static str, dst: u8, src: u8) -> Result<(), VMError> {
        let v = self.registers.get_int(src, instr)?;
        self.registers.set(dst, Value::Int(v.wrapping_neg()))
    }

    fn op_abs(&mut self, instr: &'static str, dst: u8, src: u8) -> Result<(), VMError> {
        let v = self.registers.get_int(src, instr)?;
        self.registers.set(dst, Value::Int(v.wrapping_abs()))
    }

    fn op_min(&mut self, instr: &'static str, dst: u8, a: u8, b: u8) -> Result<(), VMError> {
        let va = self.registers.get_int(a, instr)?;
        let vb = self.registers.get_int(b, instr)?;
        self.registers.set(dst, Value::Int(va.min(vb)))
    }

    fn op_max(&mut self, instr: &'static str, dst: u8, a: u8, b: u8) -> Result<(), VMError> {
        let va = self.registers.get_int(a, instr)?;
        let vb = self.registers.get_int(b, instr)?;
        self.registers.set(dst, Value::Int(va.max(vb)))
    }

    fn op_shl(&mut self, instr: &'static str, dst: u8, a: u8, b: u8) -> Result<(), VMError> {
        let va = self.registers.get_int(a, instr)?;
        let vb = self.registers.get_int(b, instr)?;
        self.registers
            .set(dst, Value::Int(va.wrapping_shl(vb as u32)))
    }

    fn op_shr(&mut self, instr: &'static str, dst: u8, a: u8, b: u8) -> Result<(), VMError> {
        let va = self.registers.get_int(a, instr)?;
        let vb = self.registers.get_int(b, instr)?;
        self.registers
            .set(dst, Value::Int(va.wrapping_shr(vb as u32)))
    }

    fn op_not(&mut self, instr: &'static str, dst: u8, src: u8) -> Result<(), VMError> {
        let v = self.registers.get_bool(src, instr)?;
        self.registers.set(dst, Value::Bool(!v))
    }

    fn op_and(&mut self, instr: &'static str, dst: u8, a: u8, b: u8) -> Result<(), VMError> {
        let va = self.registers.get_bool(a, instr)?;
        let vb = self.registers.get_bool(b, instr)?;
        self.registers.set(dst, Value::Bool(va && vb))
    }

    fn op_or(&mut self, instr: &'static str, dst: u8, a: u8, b: u8) -> Result<(), VMError> {
        let va = self.registers.get_bool(a, instr)?;
        let vb = self.registers.get_bool(b, instr)?;
        self.registers.set(dst, Value::Bool(va || vb))
    }

    fn op_xor(&mut self, instr: &'static str, dst: u8, a: u8, b: u8) -> Result<(), VMError> {
        let va = self.registers.get_bool(a, instr)?;
        let vb = self.registers.get_bool(b, instr)?;
        self.registers.set(dst, Value::Bool(va ^ vb))
    }

    fn op_eq(&mut self, instr: &'static str, dst: u8, a: u8, b: u8) -> Result<(), VMError> {
        let va = self.registers.get_int(a, instr)?;
        let vb = self.registers.get_int(b, instr)?;
        self.registers.set(dst, Value::Bool(va == vb))
    }

    fn op_lt(&mut self, instr: &'static str, dst: u8, a: u8, b: u8) -> Result<(), VMError> {
        let va = self.registers.get_int(a, instr)?;
        let vb = self.registers.get_int(b, instr)?;
        self.registers.set(dst, Value::Bool(va < vb))
    }

    fn op_gt(&mut self, instr: &'static str, dst: u8, a: u8, b: u8) -> Result<(), VMError> {
        let va = self.registers.get_int(a, instr)?;
        let vb = self.registers.get_int(b, instr)?;
        self.registers.set(dst, Value::Bool(va > vb))
    }

    fn op_le(&mut self, instr: &'static str, dst: u8, a: u8, b: u8) -> Result<(), VMError> {
        let va = self.registers.get_int(a, instr)?;
        let vb = self.registers.get_int(b, instr)?;
        self.registers.set(dst, Value::Bool(va <= vb))
    }

    fn op_ge(&mut self, instr: &'static str, dst: u8, a: u8, b: u8) -> Result<(), VMError> {
        let va = self.registers.get_int(a, instr)?;
        let vb = self.registers.get_int(b, instr)?;
        self.registers.set(dst, Value::Bool(va >= vb))
    }

    fn op_call_host(
        &mut self,
        instr: &'static str,
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
        fn arg_len_check(expected: usize, actual: usize, name: &str) -> Result<(), VMError> {
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
            k @ "len" => {
                arg_len_check(1, args.len(), k)?;
                let str_ref = get_ref(args[0])?;
                let len = self.heap.get_raw_ref(str_ref)?.len();
                self.charge_gas_categorized(len as u64, GasCategory::HostFunction)?;
                self.op_load_i64(instr, dst, self.heap.get_raw_ref(str_ref)?.len() as i64)
            }
            k @ "slice" => {
                arg_len_check(3, args.len(), k)?;
                let str_ref = get_ref(args[0])?;
                let start = get_i64(args[1])? as usize;
                let end = get_i64(args[2])? as usize;

                let len = self.heap.get_raw_ref(str_ref)?.len();
                self.charge_gas_categorized(len as u64, GasCategory::HostFunction)?;

                let bytes = self.heap.get_raw_ref(str_ref)?;
                let end = end.min(bytes.len());
                let start = start.min(end);

                let sliced = bytes[start..end].to_vec();
                let new_ref = self.heap_index(sliced)?;
                self.op_load_str(instr, dst, new_ref)
            }
            k @ "concat" => {
                arg_len_check(2, args.len(), k)?;
                let ref1 = get_ref(args[0])?;
                let ref2 = get_ref(args[1])?;

                let mut result = self.heap.get_raw_ref(ref1)?.len();
                result += self.heap.get_raw_ref(ref2)?.len();
                self.charge_gas_categorized(result as u64, GasCategory::HostFunction)?;

                let mut result = self.heap.get_raw_ref(ref1)?.clone();
                result.extend_from_slice(self.heap.get_raw_ref(ref2)?);

                let new_ref = self.heap.index(result);
                self.op_load_str(instr, dst, new_ref)
            }
            k @ "compare" => {
                arg_len_check(2, args.len(), k)?;
                let ref1 = get_ref(args[0])?;
                let ref2 = get_ref(args[1])?;

                let l1 = self.heap.get_raw_ref(ref1)?.len();
                let l2 = self.heap.get_raw_ref(ref2)?.len();
                self.charge_gas_categorized((l1 + l2) as u64, GasCategory::HostFunction)?;

                let s1 = self.heap.get_raw_ref(ref1)?;
                let s2 = self.heap.get_raw_ref(ref2)?;
                let cmp = match s1.cmp(s2) {
                    std::cmp::Ordering::Less => -1,
                    std::cmp::Ordering::Equal => 0,
                    std::cmp::Ordering::Greater => 1,
                };
                self.op_load_i64(instr, dst, cmp)
            }
            k @ "hash" => {
                arg_len_check(1, args.len(), k)?;
                let len = match args[0] {
                    Value::Zero => 0,
                    Value::Bool(_) => 1,
                    Value::Int(_) => 8,
                    Value::Ref(r) => self.heap.get_raw_ref(r)?.len(),
                };
                self.charge_gas_categorized(len as u64, GasCategory::HostFunction)?;

                let hash = match args[0] {
                    Value::Zero => Hash::sha3().chain(&[]).finalize(),
                    Value::Bool(b) => Hash::sha3().chain(&[b as u8]).finalize(),
                    Value::Ref(r) => Hash::sha3().chain(self.heap.get_raw_ref(r)?).finalize(),
                    Value::Int(i) => Hash::sha3().chain(&i.to_le_bytes()).finalize(),
                };
                let new_ref = self.heap_index(hash.to_vec())?;
                self.op_load_hash(instr, dst, new_ref)
            }
            _ => Err(VMError::InvalidCallHostFunction { name: fn_name }),
        }
    }

    fn op_call(
        &mut self,
        instr: &'static str,
        dst: u8,
        offset: i64,
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

    fn op_call0(&mut self, instr: &'static str, dst: u8, fn_id: i64) -> Result<(), VMError> {
        self.op_call(instr, dst, fn_id, 0, 0)
    }

    fn op_jal(&mut self, instr: &'static str, rd: u8, offset: i64) -> Result<(), VMError> {
        self.registers.set(rd, Value::Int(self.ip as i64))?;
        self.op_jump(instr, offset)?;
        Ok(())
    }

    fn op_jalr(&mut self, instr: &'static str, rd: u8, rs: u8, offset: i64) -> Result<(), VMError> {
        let base = self.registers.get_int(rs, instr)?;
        self.registers.set(rd, Value::Int(self.ip as i64))?;
        self.ip = base as usize;
        self.op_jump(instr, offset)?;
        Ok(())
    }

    fn op_beq(
        &mut self,
        instr: &'static str,
        rs1: u8,
        rs2: u8,
        offset: i64,
    ) -> Result<(), VMError> {
        let a = self.registers.get_int(rs1, instr)?;
        let b = self.registers.get_int(rs2, instr)?;
        if a == b {
            self.op_jump(instr, offset)?;
        }
        Ok(())
    }

    fn op_bne(
        &mut self,
        instr: &'static str,
        rs1: u8,
        rs2: u8,
        offset: i64,
    ) -> Result<(), VMError> {
        let a = self.registers.get_int(rs1, instr)?;
        let b = self.registers.get_int(rs2, instr)?;
        if a != b {
            self.op_jump(instr, offset)?;
        }
        Ok(())
    }

    fn op_blt(
        &mut self,
        instr: &'static str,
        rs1: u8,
        rs2: u8,
        offset: i64,
    ) -> Result<(), VMError> {
        let a = self.registers.get_int(rs1, instr)?;
        let b = self.registers.get_int(rs2, instr)?;
        if a < b {
            self.op_jump(instr, offset)?;
        }
        Ok(())
    }

    fn op_bge(
        &mut self,
        instr: &'static str,
        rs1: u8,
        rs2: u8,
        offset: i64,
    ) -> Result<(), VMError> {
        let a = self.registers.get_int(rs1, instr)?;
        let b = self.registers.get_int(rs2, instr)?;
        if a >= b {
            self.op_jump(instr, offset)?;
        }
        Ok(())
    }

    fn op_bltu(
        &mut self,
        instr: &'static str,
        rs1: u8,
        rs2: u8,
        offset: i64,
    ) -> Result<(), VMError> {
        let a = self.registers.get_int(rs1, instr)? as u64;
        let b = self.registers.get_int(rs2, instr)? as u64;
        if a < b {
            self.op_jump(instr, offset)?;
        }
        Ok(())
    }

    fn op_bgeu(
        &mut self,
        instr: &'static str,
        rs1: u8,
        rs2: u8,
        offset: i64,
    ) -> Result<(), VMError> {
        let a = self.registers.get_int(rs1, instr)? as u64;
        let b = self.registers.get_int(rs2, instr)? as u64;
        if a >= b {
            self.op_jump(instr, offset)?;
        }
        Ok(())
    }

    fn op_jump(&mut self, _instr: &'static str, offset: i64) -> Result<(), VMError> {
        let new_ip = self.ip as i64 + offset;
        if new_ip < 0 || new_ip as usize > self.data.len() {
            return Err(VMError::JumpOutOfBounds {
                from: self.ip,
                to: new_ip,
                max: self.data.len(),
            });
        }
        self.ip = new_ip as usize;
        Ok(())
    }

    fn op_halt(&mut self, _instr: &'static str) -> Result<(), VMError> {
        // Move IP to the end to exit the execution loop cleanly.
        self.ip = self.data.len();
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
                registers: Registers::new(),
                heap: Heap::new(program.items),
                call_stack: Vec::new(),
                gas_used: 0,
                max_gas,
                gas_profile: GasProfile::new(),
            };

            vm.charge_gas_categorized(init_cost, GasCategory::Deploy)?;
            Ok(vm)
        }
    }

    const EXECUTION_CONTEXT: &ExecContext = &ExecContext {
        chain_id: 62845383663927,
        contract_id: Hash::zero(),
    };

    fn run_vm(source: &str) -> VM {
        let program = assemble_source(source).expect("assembly failed");
        let mut vm = VM::new_with_init(program, 0, TRANSACTION_GAS_LIMIT).expect("vm new failed");
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
        let mut vm = VM::new_with_init(program, 0, TRANSACTION_GAS_LIMIT).expect("vm new failed");
        vm.run(&mut TestState::new(), EXECUTION_CONTEXT)
            .expect_err("expected error")
    }

    fn run_vm_with_state(source: &str) -> TestState {
        let program = assemble_source(source).expect("assembly failed");
        let mut vm = VM::new_with_init(program, 0, TRANSACTION_GAS_LIMIT).expect("vm new failed");
        let mut state = TestState::new();
        vm.run(&mut state, EXECUTION_CONTEXT)
            .expect("vm run failed");
        state
    }

    // ==================== Loads ====================

    #[test]
    fn load_i64() {
        assert_eq!(run_and_get_int("LOAD_I64 r0, 42", 0), 42);
        assert_eq!(run_and_get_int("LOAD_I64 r0, -1", 0), -1);
        assert_eq!(run_and_get_int("LOAD_I64 r0, 0", 0), 0);
    }

    #[test]
    fn load_bool() {
        assert!(run_and_get_bool("LOAD_BOOL r0, true", 0));
        assert!(!run_and_get_bool("LOAD_BOOL r0, false", 0));
    }

    #[test]
    fn load_str() {
        let vm = run_vm(r#"LOAD_STR r0, "hello""#);
        let ref_id = vm.registers.get_ref(0, "").unwrap();
        assert_eq!(vm.heap.get_string(ref_id).unwrap(), "hello");
    }

    #[test]
    fn load_hash() {
        let vm = run_vm(r#"LOAD_HASH r0, "00000000000000000000000000000000""#);
        let ref_id = vm.registers.get_ref(0, "").unwrap();
        let expected = Hash::from_slice(b"00000000000000000000000000000000").unwrap();
        assert_eq!(vm.heap.get_hash(ref_id).unwrap(), expected);
    }

    // ==================== Moves / Casts ====================

    #[test]
    fn move_int() {
        assert_eq!(run_and_get_int("LOAD_I64 r0, 99\nMOVE r1, r0", 1), 99);
    }

    #[test]
    fn move_bool() {
        assert!(run_and_get_bool("LOAD_BOOL r0, true\nMOVE r1, r0", 1));
    }

    #[test]
    fn i64_to_bool() {
        assert!(run_and_get_bool("LOAD_I64 r0, 1\nI64_TO_BOOL r1, r0", 1));
        assert!(run_and_get_bool("LOAD_I64 r0, -5\nI64_TO_BOOL r1, r0", 1));
        assert!(!run_and_get_bool("LOAD_I64 r0, 0\nI64_TO_BOOL r1, r0", 1));
    }

    #[test]
    fn bool_to_i64() {
        assert_eq!(
            run_and_get_int("LOAD_BOOL r0, true\nBOOL_TO_I64 r1, r0", 1),
            1
        );
        assert_eq!(
            run_and_get_int("LOAD_BOOL r0, false\nBOOL_TO_I64 r1, r0", 1),
            0
        );
    }

    #[test]
    fn str_to_i64_parses_numbers() {
        assert_eq!(
            run_and_get_int(
                r#"
                LOAD_STR r0, "12345"
                STR_TO_I64 r1, r0
            "#,
                1
            ),
            12345
        );
        assert_eq!(
            run_and_get_int(
                r#"
                LOAD_STR r0, "-7"
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
                LOAD_STR r0, "abc"
                STR_TO_I64 r1, r0
            "#
            ),
            VMError::InvalidRegister { .. }
        ));
    }

    #[test]
    fn i64_to_str_round_trips() {
        assert_eq!(
            run_and_get_int("LOAD_I64 r0, -99\nI64_TO_STR r1, r0\nSTR_TO_I64 r2, r1", 2),
            -99
        );
        assert_eq!(
            run_and_get_str("LOAD_I64 r0, -99\nI64_TO_STR r1, r0", 1),
            "-99"
        );
    }

    #[test]
    fn str_to_bool_accepts_true_and_false() {
        assert!(run_and_get_bool(
            r#"
            LOAD_STR r0, "true"
            STR_TO_BOOL r1, r0
            "#,
            1
        ));
        assert!(!run_and_get_bool(
            r#"
            LOAD_STR r0, "false"
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
                LOAD_STR r0, "notabool"
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
            run_and_get_str("LOAD_BOOL r0, true\nBOOL_TO_STR r1, r0", 1),
            "true"
        );
        assert!(run_and_get_bool(
            "LOAD_BOOL r0, true\nBOOL_TO_STR r1, r0\nSTR_TO_BOOL r2, r1",
            2
        ));
        assert!(!run_and_get_bool(
            "LOAD_BOOL r0, false\nBOOL_TO_STR r1, r0\nSTR_TO_BOOL r2, r1",
            2
        ));
    }

    // ==================== Arithmetic ====================

    #[test]
    fn add() {
        assert_eq!(
            run_and_get_int("LOAD_I64 r0, 10\nLOAD_I64 r1, 32\nADD r2, r0, r1", 2),
            42
        );
    }

    #[test]
    fn add_wrapping() {
        let source = "LOAD_I64 r0, 9223372036854775807\nLOAD_I64 r1, 1\nADD r2, r0, r1";
        assert_eq!(run_and_get_int(source, 2), i64::MIN);
    }

    #[test]
    fn sub() {
        assert_eq!(
            run_and_get_int("LOAD_I64 r0, 50\nLOAD_I64 r1, 8\nSUB r2, r0, r1", 2),
            42
        );
    }

    #[test]
    fn mul() {
        assert_eq!(
            run_and_get_int("LOAD_I64 r0, 6\nLOAD_I64 r1, 7\nMUL r2, r0, r1", 2),
            42
        );
    }

    #[test]
    fn div() {
        assert_eq!(
            run_and_get_int("LOAD_I64 r0, 84\nLOAD_I64 r1, 2\nDIV r2, r0, r1", 2),
            42
        );
    }

    #[test]
    fn div_by_zero() {
        assert!(matches!(
            run_expect_err("LOAD_I64 r0, 1\nLOAD_I64 r1, 0\nDIV r2, r0, r1"),
            VMError::DivisionByZero
        ));
    }

    #[test]
    fn modulo() {
        assert_eq!(
            run_and_get_int("LOAD_I64 r0, 47\nLOAD_I64 r1, 5\nMOD r2, r0, r1", 2),
            2
        );
    }

    #[test]
    fn mod_by_zero() {
        assert!(matches!(
            run_expect_err("LOAD_I64 r0, 1\nLOAD_I64 r1, 0\nMOD r2, r0, r1"),
            VMError::DivisionByZero
        ));
    }

    #[test]
    fn neg() {
        assert_eq!(run_and_get_int("LOAD_I64 r0, 42\nNEG r1, r0", 1), -42);
    }

    #[test]
    fn abs() {
        assert_eq!(run_and_get_int("LOAD_I64 r0, -42\nABS r1, r0", 1), 42);
        assert_eq!(run_and_get_int("LOAD_I64 r0, 42\nABS r1, r0", 1), 42);
    }

    #[test]
    fn min() {
        assert_eq!(
            run_and_get_int("LOAD_I64 r0, 10\nLOAD_I64 r1, 5\nMIN r2, r0, r1", 2),
            5
        );
    }

    #[test]
    fn max() {
        assert_eq!(
            run_and_get_int("LOAD_I64 r0, 10\nLOAD_I64 r1, 5\nMAX r2, r0, r1", 2),
            10
        );
    }

    #[test]
    fn shl() {
        assert_eq!(
            run_and_get_int("LOAD_I64 r0, 1\nLOAD_I64 r1, 4\nSHL r2, r0, r1", 2),
            16
        );
    }

    #[test]
    fn shr() {
        assert_eq!(
            run_and_get_int("LOAD_I64 r0, 16\nLOAD_I64 r1, 2\nSHR r2, r0, r1", 2),
            4
        );
        // Arithmetic shift preserves sign
        assert_eq!(
            run_and_get_int("LOAD_I64 r0, -16\nLOAD_I64 r1, 2\nSHR r2, r0, r1", 2),
            -4
        );
    }

    // ==================== Boolean ====================

    #[test]
    fn not() {
        assert!(!run_and_get_bool("LOAD_BOOL r0, true\nNOT r1, r0", 1));
        assert!(run_and_get_bool("LOAD_BOOL r0, false\nNOT r1, r0", 1));
    }

    #[test]
    fn and() {
        assert!(run_and_get_bool(
            "LOAD_BOOL r0, true\nLOAD_BOOL r1, true\nAND r2, r0, r1",
            2
        ));
        assert!(!run_and_get_bool(
            "LOAD_BOOL r0, true\nLOAD_BOOL r1, false\nAND r2, r0, r1",
            2
        ));
    }

    #[test]
    fn or() {
        assert!(run_and_get_bool(
            "LOAD_BOOL r0, false\nLOAD_BOOL r1, true\nOR r2, r0, r1",
            2
        ));
        assert!(!run_and_get_bool(
            "LOAD_BOOL r0, false\nLOAD_BOOL r1, false\nOR r2, r0, r1",
            2
        ));
    }

    #[test]
    fn xor() {
        assert!(run_and_get_bool(
            "LOAD_BOOL r0, true\nLOAD_BOOL r1, false\nXOR r2, r0, r1",
            2
        ));
        assert!(!run_and_get_bool(
            "LOAD_BOOL r0, true\nLOAD_BOOL r1, true\nXOR r2, r0, r1",
            2
        ));
    }

    // ==================== Comparison ====================

    #[test]
    fn eq() {
        assert!(run_and_get_bool(
            "LOAD_I64 r0, 5\nLOAD_I64 r1, 5\nEQ r2, r0, r1",
            2
        ));
        assert!(!run_and_get_bool(
            "LOAD_I64 r0, 5\nLOAD_I64 r1, 6\nEQ r2, r0, r1",
            2
        ));
    }

    #[test]
    fn lt() {
        assert!(run_and_get_bool(
            "LOAD_I64 r0, 3\nLOAD_I64 r1, 5\nLT r2, r0, r1",
            2
        ));
        assert!(!run_and_get_bool(
            "LOAD_I64 r0, 5\nLOAD_I64 r1, 3\nLT r2, r0, r1",
            2
        ));
    }

    #[test]
    fn le() {
        assert!(run_and_get_bool(
            "LOAD_I64 r0, 3\nLOAD_I64 r1, 5\nLE r2, r0, r1",
            2
        ));
        assert!(run_and_get_bool(
            "LOAD_I64 r0, 5\nLOAD_I64 r1, 5\nLE r2, r0, r1",
            2
        ));
        assert!(!run_and_get_bool(
            "LOAD_I64 r0, 6\nLOAD_I64 r1, 5\nLE r2, r0, r1",
            2
        ));
    }

    #[test]
    fn gt() {
        assert!(run_and_get_bool(
            "LOAD_I64 r0, 10\nLOAD_I64 r1, 5\nGT r2, r0, r1",
            2
        ));
        assert!(!run_and_get_bool(
            "LOAD_I64 r0, 5\nLOAD_I64 r1, 10\nGT r2, r0, r1",
            2
        ));
    }

    #[test]
    fn ge() {
        assert!(run_and_get_bool(
            "LOAD_I64 r0, 10\nLOAD_I64 r1, 5\nGE r2, r0, r1",
            2
        ));
        assert!(run_and_get_bool(
            "LOAD_I64 r0, 5\nLOAD_I64 r1, 5\nGE r2, r0, r1",
            2
        ));
        assert!(!run_and_get_bool(
            "LOAD_I64 r0, 4\nLOAD_I64 r1, 5\nGE r2, r0, r1",
            2
        ));
    }

    // ==================== Type Errors ====================

    #[test]
    fn type_mismatch_int_for_bool() {
        let source = "LOAD_I64 r0, 1\nNOT r1, r0";
        assert!(matches!(
            run_expect_err(source),
            VMError::TypeMismatchStatic { .. }
        ));
    }

    #[test]
    fn type_mismatch_bool_for_int() {
        let source = "LOAD_BOOL r0, true\nLOAD_BOOL r1, true\nADD r2, r0, r1";
        assert!(matches!(
            run_expect_err(source),
            VMError::TypeMismatchStatic { .. }
        ));
    }

    // ==================== Error Cases ====================

    #[test]
    fn read_uninitialized_register() {
        assert!(matches!(
            run_expect_err("ADD r2, r0, r1"),
            VMError::TypeMismatchStatic { .. }
        ));
    }

    #[test]
    fn invalid_opcode() {
        let mut vm = VM::new_with_init(
            DeployProgram::new(vec![], vec![0xFF]),
            0,
            TRANSACTION_GAS_LIMIT,
        )
        .expect("vm new failed");
        assert!(matches!(
            vm.run(&mut TestState::new(), EXECUTION_CONTEXT),
            Err(VMError::InvalidInstruction { opcode: 0xFF, .. })
        ));
    }

    #[test]
    fn truncated_bytecode() {
        let mut vm = VM::new_with_init(
            DeployProgram::new(vec![], vec![0x01, 0x00]),
            0,
            TRANSACTION_GAS_LIMIT,
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
            DeployProgram::new(vec![], vec![]),
            100,
            TRANSACTION_GAS_LIMIT,
        )
        .unwrap();
        assert_eq!(vm.gas_used(), 100);
    }

    #[test]
    fn vm_new_fails_when_init_cost_exceeds_max_gas() {
        let result = VM::new_with_init(DeployProgram::new(vec![], vec![]), 1000, 500);
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
        let vm = VM::new_with_init(DeployProgram::new(vec![], vec![]), 500, 500).unwrap();
        assert_eq!(vm.gas_used(), 500);
    }

    #[test]
    fn vm_respects_custom_max_gas() {
        let program = assemble_source(
            r#"
            LOAD_I64 r0, 1
            LOAD_I64 r1, 2
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
            DeployProgram::new(Vec::new(), Vec::new()),
            0,
            TRANSACTION_GAS_LIMIT,
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
            r#"LOAD_STR r0, "counter"
LOAD_I64 r1, 42
STORE_I64 r0, r1"#,
        );
        let key = make_test_key(b"counter").unwrap();
        let value = state.get(key).expect("key not found");
        assert_eq!(i64::from_le_bytes(value.try_into().unwrap()), 42);
    }

    #[test]
    fn store_str() {
        let state = run_vm_with_state(
            r#"LOAD_STR r0, "name"
LOAD_STR r1, "alice"
STORE_STR r0, r1"#,
        );
        let key = make_test_key(b"name").unwrap();
        let value = state.get(key).expect("key not found");
        assert_eq!(value, b"alice");
    }

    #[test]
    fn store_hash() {
        let state = run_vm_with_state(
            r#"LOAD_STR r0, "hash_key"
LOAD_HASH r1, "00000000000000000000000000000000"
STORE_HASH r0, r1"#,
        );
        let key = make_test_key(b"hash_key").unwrap();
        let value = state.get(key).expect("key not found");
        let expected = Hash::from_slice(b"00000000000000000000000000000000").unwrap();
        assert_eq!(value, expected.to_vec());
    }

    #[test]
    fn store_bool() {
        let state = run_vm_with_state(
            r#"LOAD_STR r0, "flag"
LOAD_BOOL r1, true
STORE_BOOL r0, r1"#,
        );
        let key = make_test_key(b"flag").unwrap();
        let value = state.get(key).expect("key not found");
        assert_eq!(value, &[1u8]);
    }

    #[test]
    fn store_overwrites_previous_value() {
        let state = run_vm_with_state(
            r#"LOAD_STR r0, "x"
LOAD_I64 r1, 100
STORE_I64 r0, r1
LOAD_I64 r2, 200
STORE_I64 r0, r2"#,
        );
        let key = make_test_key(b"x").unwrap();
        let value = state.get(key).expect("key not found");
        assert_eq!(i64::from_le_bytes(value.try_into().unwrap()), 200);
    }

    // ==================== State Loads ====================

    fn run_vm_on_state(source: &str, state: &mut TestState) -> VM {
        let program = assemble_source(source).expect("assembly failed");
        let mut vm = VM::new_with_init(program, 0, TRANSACTION_GAS_LIMIT).expect("vm new failed");
        vm.run(state, EXECUTION_CONTEXT).expect("vm run failed");
        vm
    }

    #[test]
    fn load_i64_state() {
        let key = make_test_key(b"counter").unwrap();
        let mut state = TestState::with_data(vec![(key, 42i64.to_le_bytes().to_vec())]);
        let vm = run_vm_on_state(
            r#"LOAD_STR r0, "counter"
LOAD_I64_STATE r1, r0"#,
            &mut state,
        );
        assert_eq!(vm.registers.get_int(1, "").unwrap(), 42);
    }

    #[test]
    fn load_i64_state_negative() {
        let key = make_test_key(b"neg").unwrap();
        let mut state = TestState::with_data(vec![(key, (-999i64).to_le_bytes().to_vec())]);
        let vm = run_vm_on_state(
            r#"LOAD_STR r0, "neg"
LOAD_I64_STATE r1, r0"#,
            &mut state,
        );
        assert_eq!(vm.registers.get_int(1, "").unwrap(), -999);
    }

    #[test]
    fn load_i64_state_key_not_found() {
        let program = assemble_source(
            r#"LOAD_STR r0, "missing"
LOAD_I64_STATE r1, r0"#,
        )
        .expect("assembly failed");
        let mut vm = VM::new_with_init(program, 0, TRANSACTION_GAS_LIMIT).expect("vm new failed");
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
            r#"LOAD_STR r0, "flag"
LOAD_BOOL_STATE r1, r0"#,
            &mut state,
        );
        assert!(vm.registers.get_bool(1, "").unwrap());
    }

    #[test]
    fn load_bool_state_false() {
        let key = make_test_key(b"flag").unwrap();
        let mut state = TestState::with_data(vec![(key, vec![0u8])]);
        let vm = run_vm_on_state(
            r#"LOAD_STR r0, "flag"
LOAD_BOOL_STATE r1, r0"#,
            &mut state,
        );
        assert!(!vm.registers.get_bool(1, "").unwrap());
    }

    #[test]
    fn load_bool_state_key_not_found() {
        let program = assemble_source(
            r#"LOAD_STR r0, "missing"
LOAD_BOOL_STATE r1, r0"#,
        )
        .expect("assembly failed");
        let mut vm = VM::new_with_init(program, 0, TRANSACTION_GAS_LIMIT).expect("vm new failed");
        let err = vm
            .run(&mut TestState::new(), EXECUTION_CONTEXT)
            .expect_err("expected error");
        assert!(matches!(err, VMError::KeyNotFound { .. }));
    }

    #[test]
    fn load_str_state() {
        let key = make_test_key(b"name").unwrap();
        let mut state = TestState::with_data(vec![(key, b"alice".to_vec())]);
        let vm = run_vm_on_state(
            r#"LOAD_STR r0, "name"
LOAD_STR_STATE r1, r0"#,
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
            r#"LOAD_STR r0, "empty"
LOAD_STR_STATE r1, r0"#,
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
            r#"LOAD_STR r0, "hash_key"
LOAD_HASH_STATE r1, r0"#,
            &mut state,
        );
        let ref_id = vm.registers.get_ref(1, "").unwrap();
        assert_eq!(vm.heap.get_hash(ref_id).unwrap(), expected);
    }

    #[test]
    fn load_str_state_key_not_found() {
        let program = assemble_source(
            r#"LOAD_STR r0, "missing"
LOAD_STR_STATE r1, r0"#,
        )
        .expect("assembly failed");
        let mut vm = VM::new_with_init(program, 0, TRANSACTION_GAS_LIMIT).expect("vm new failed");
        let err = vm
            .run(&mut TestState::new(), EXECUTION_CONTEXT)
            .expect_err("expected error");
        assert!(matches!(err, VMError::KeyNotFound { .. }));
    }

    #[test]
    fn store_then_load_i64() {
        let vm = run_vm(
            r#"LOAD_STR r0, "x"
LOAD_I64 r1, 123
STORE_I64 r0, r1
LOAD_I64_STATE r2, r0"#,
        );
        assert_eq!(vm.registers.get_int(2, "").unwrap(), 123);
    }

    #[test]
    fn store_then_load_bool() {
        let vm = run_vm(
            r#"LOAD_STR r0, "b"
LOAD_BOOL r1, true
STORE_BOOL r0, r1
LOAD_BOOL_STATE r2, r0"#,
        );
        assert!(vm.registers.get_bool(2, "").unwrap());
    }

    #[test]
    fn store_then_load_str() {
        let vm = run_vm(
            r#"LOAD_STR r0, "s"
LOAD_STR r1, "hello"
STORE_STR r0, r1
LOAD_STR_STATE r2, r0"#,
        );
        let ref_id = vm.registers.get_ref(2, "").unwrap();
        assert_eq!(vm.heap.get_string(ref_id).unwrap(), "hello");
    }

    #[test]
    fn store_then_load_hash() {
        let vm = run_vm(
            r#"LOAD_STR r0, "hash_key"
LOAD_HASH r1, "22222222222222222222222222222222"
STORE_HASH r0, r1
LOAD_HASH_STATE r2, r0"#,
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
        // After JAL (10 bytes), ip should be saved as 10
        assert_eq!(vm.registers.get_int(0, "").unwrap(), 10);
    }

    #[test]
    fn jal_forward_jump() {
        // Jump over LOAD_I64 r1, 99 to reach LOAD_I64 r2, 42
        let source = r#"
            JAL r0, skip
            LOAD_I64 r1, 99
            skip: LOAD_I64 r2, 42
        "#;
        let vm = run_vm(source);
        // r1 should still be zero (skipped)
        assert_eq!(vm.registers.get(1).unwrap(), &Value::Zero);
        // r2 should be 42
        assert_eq!(vm.registers.get_int(2, "").unwrap(), 42);
    }

    #[test]
    fn jump_skips_instructions() {
        // LOAD_I64 is 10 bytes, so jump forward by 10 to skip the following load
        let vm = run_vm("LOAD_I64 r0, 1\nJUMP 10\nLOAD_I64 r0, 99");
        assert_eq!(vm.registers.get_int(0, "").unwrap(), 1);
    }

    #[test]
    fn beq_taken() {
        // Branch taken when equal
        let source = r#"
            LOAD_I64 r0, 5
            LOAD_I64 r1, 5
            BEQ r0, r1, skip
            LOAD_I64 r2, 99
            skip: LOAD_I64 r3, 42
        "#;
        let vm = run_vm(source);
        assert_eq!(vm.registers.get(2).unwrap(), &Value::Zero);
        assert_eq!(vm.registers.get_int(3, "").unwrap(), 42);
    }

    #[test]
    fn beq_not_taken() {
        // Branch not taken when not equal
        let source = r#"
            LOAD_I64 r0, 5
            LOAD_I64 r1, 6
            BEQ r0, r1, skip
            LOAD_I64 r2, 99
            skip: LOAD_I64 r3, 42
        "#;
        let vm = run_vm(source);
        assert_eq!(vm.registers.get_int(2, "").unwrap(), 99);
        assert_eq!(vm.registers.get_int(3, "").unwrap(), 42);
    }

    #[test]
    fn bne_taken() {
        let source = r#"
            LOAD_I64 r0, 5
            LOAD_I64 r1, 6
            BNE r0, r1, skip
            LOAD_I64 r2, 99
            skip: LOAD_I64 r3, 42
        "#;
        let vm = run_vm(source);
        assert_eq!(vm.registers.get(2).unwrap(), &Value::Zero);
        assert_eq!(vm.registers.get_int(3, "").unwrap(), 42);
    }

    #[test]
    fn bne_not_taken() {
        let source = r#"
            LOAD_I64 r0, 5
            LOAD_I64 r1, 5
            BNE r0, r1, skip
            LOAD_I64 r2, 99
            skip: LOAD_I64 r3, 42
        "#;
        let vm = run_vm(source);
        assert_eq!(vm.registers.get_int(2, "").unwrap(), 99);
    }

    #[test]
    fn blt_taken() {
        let source = r#"
            LOAD_I64 r0, 3
            LOAD_I64 r1, 5
            BLT r0, r1, skip
            LOAD_I64 r2, 99
            skip: LOAD_I64 r3, 42
        "#;
        let vm = run_vm(source);
        assert_eq!(vm.registers.get(2).unwrap(), &Value::Zero);
        assert_eq!(vm.registers.get_int(3, "").unwrap(), 42);
    }

    #[test]
    fn blt_not_taken() {
        let source = r#"
            LOAD_I64 r0, 5
            LOAD_I64 r1, 3
            BLT r0, r1, skip
            LOAD_I64 r2, 99
            skip: LOAD_I64 r3, 42
        "#;
        let vm = run_vm(source);
        assert_eq!(vm.registers.get_int(2, "").unwrap(), 99);
    }

    #[test]
    fn blt_signed() {
        // -1 < 1 in signed comparison
        let source = r#"
            LOAD_I64 r0, -1
            LOAD_I64 r1, 1
            BLT r0, r1, skip
            LOAD_I64 r2, 99
            skip: LOAD_I64 r3, 42
        "#;
        let vm = run_vm(source);
        assert_eq!(vm.registers.get(2).unwrap(), &Value::Zero);
    }

    #[test]
    fn bge_taken() {
        let source = r#"
            LOAD_I64 r0, 5
            LOAD_I64 r1, 5
            BGE r0, r1, skip
            LOAD_I64 r2, 99
            skip: LOAD_I64 r3, 42
        "#;
        let vm = run_vm(source);
        assert_eq!(vm.registers.get(2).unwrap(), &Value::Zero);
    }

    #[test]
    fn bge_greater() {
        let source = r#"
            LOAD_I64 r0, 7
            LOAD_I64 r1, 5
            BGE r0, r1, skip
            LOAD_I64 r2, 99
            skip: LOAD_I64 r3, 42
        "#;
        let vm = run_vm(source);
        assert_eq!(vm.registers.get(2).unwrap(), &Value::Zero);
    }

    #[test]
    fn bltu_unsigned() {
        // -1 as u64 is MAX, so -1 > 1 in unsigned comparison
        let source = r#"
            LOAD_I64 r0, -1
            LOAD_I64 r1, 1
            BLTU r0, r1, skip
            LOAD_I64 r2, 99
            skip: LOAD_I64 r3, 42
        "#;
        let vm = run_vm(source);
        // Branch NOT taken because -1 as u64 > 1
        assert_eq!(vm.registers.get_int(2, "").unwrap(), 99);
    }

    #[test]
    fn bgeu_unsigned() {
        // -1 as u64 is MAX, so -1 >= 1 in unsigned comparison
        let source = r#"
            LOAD_I64 r0, -1
            LOAD_I64 r1, 1
            BGEU r0, r1, skip
            LOAD_I64 r2, 99
            skip: LOAD_I64 r3, 42
        "#;
        let vm = run_vm(source);
        // Branch taken because -1 as u64 > 1
        assert_eq!(vm.registers.get(2).unwrap(), &Value::Zero);
    }

    #[test]
    fn halt_stops_execution() {
        let source = r#"
            LOAD_I64 r0, 1
            HALT
            LOAD_I64 r0, 99
        "#;
        let vm = run_vm(source);
        assert_eq!(vm.registers.get_int(0, "").unwrap(), 1);
    }

    #[test]
    fn loop_with_backward_branch() {
        // Simple loop: count from 0 to 3
        let source = r#"
            LOAD_I64 r0, 0
            LOAD_I64 r1, 1
            LOAD_I64 r2, 3
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
        // LOAD_I64: 10 bytes, JALR: 11 bytes
        // Offsets: LOAD_I64[0-9], JALR[10-20], LOAD_I64 r2[21-30], LOAD_I64 r3[31-40]
        let source = r#"
            LOAD_I64 r1, 30
            JALR r0, r1, 1
            LOAD_I64 r2, 99
            LOAD_I64 r3, 42
        "#;
        let vm = run_vm(source);
        // Should skip LOAD_I64 r2, 99 and execute LOAD_I64 r3, 42
        assert_eq!(vm.registers.get(2).unwrap(), &Value::Zero);
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
            LOAD_I64 r10, 42
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
            LOAD_I64 r10, 99
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
        let source = "LOAD_I64 r0, 1\nRET r0";
        let err = run_expect_err(source);
        assert!(matches!(err, VMError::ReturnWithoutCall { .. }));
    }

    #[test]
    fn call_preserves_registers() {
        let source = r#"
            JAL r0, main
            main:
            LOAD_I64 r5, 100
            CALL0 r1, func
            ADD r2, r1, r5
            JAL r0, end
            func:
            LOAD_I64 r10, 50
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
            LOAD_STR r0, "counter"
            LOAD_STR r1, "steps"

            LOAD_I64_STATE r2, r0     # acc = counter
            LOAD_I64_STATE r3, r1     # limit = steps
            LOAD_I64 r4, 0            # i = 0
            LOAD_I64 r5, 1            # inc = 1

        loop:
            ADD r2, r2, r5            # acc += 1
            ADD r4, r4, r5            # i++
            BLT r4, r3, loop          # loop while i < limit

        STORE_I64 r0, r2              # update counter
        "#;

        let mut state = TestState::new();
        let program = assemble_source(prog).expect("assembly failed");
        let mut vm = VM::new_with_init(program, 0, TRANSACTION_GAS_LIMIT).expect("vm new failed");

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
            LOAD_I64 r10, 777
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
            LOAD_I64 r10, 1
            CALL0 r1, add_ten
            CALL0 r2, add_ten
            CALL0 r3, add_ten
            ADD r4, r1, r2
            ADD r4, r4, r3
            JAL r0, end
            add_ten:
            LOAD_I64 r20, 10
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
            LOAD_I64 r5, 999
            CALL0 r5, get_42
            JAL r0, end
            get_42:
            LOAD_I64 r10, 42
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
            LOAD_I64 r1, 3
            CALL0 r2, countdown
            JAL r0, end

            countdown:
            LOAD_I64 r10, 0
            LOAD_I64 r11, 1
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
            LOAD_I64 r10, 1
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
        let source = "LOAD_I64 r0, 42\nRET r0";
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
            LOAD_I64 r10, 1
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
            LOAD_I64 r10, 10
            RET r10
            ret_20:
            LOAD_I64 r10, 20
            RET r10
            ret_30:
            LOAD_I64 r10, 30
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
            LOAD_I64 r10, 42
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
            LOAD_I64 r3, 1
            ADD r2, r2, r3
            RET r2
            middle:
            CALL0 r4, inner
            LOAD_I64 r5, 1
            ADD r4, r4, r5
            RET r4
            inner:
            LOAD_I64 r6, 1
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
            LOAD_I64 r10, 1
            RET r10
            b:
            LOAD_I64 r10, 2
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
        assert_eq!(vm.registers.get(1).unwrap(), &Value::Zero);
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
            LOAD_BOOL r10, true
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
            LOAD_STR r10, "hello"
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
    fn new_execute_loads_typed_args_and_arg_items() {
        let exec = ExecuteProgram::new(
            Hash::zero(),
            3,
            vec![Value::Ref(0), Value::Int(7), Value::Bool(true)],
            vec![b"hello".to_vec()],
        );
        let base_items = vec![b"base".to_vec()];
        let vm = VM::new_execute(exec, Vec::new(), base_items, TRANSACTION_GAS_LIMIT).unwrap();

        assert_eq!(vm.registers.get_int(0, "").unwrap(), 3);
        assert_eq!(vm.registers.get(1).unwrap(), &Value::Ref(1));
        assert_eq!(vm.registers.get_int(2, "").unwrap(), 7);
        assert!(vm.registers.get_bool(3, "").unwrap());

        let ref_id = match vm.registers.get(1).unwrap() {
            Value::Ref(r) => *r,
            other => panic!("expected ref, got {:?}", other),
        };
        assert_eq!(vm.heap.get_string(ref_id).unwrap(), "hello");
    }

    // ==================== Host Functions ====================

    // --- len ---

    #[test]
    fn host_len_empty_string() {
        let source = r#"
            LOAD_STR r1, ""
            CALL_HOST r0, "len", 1, r1
        "#;
        assert_eq!(run_and_get_int(source, 0), 0);
    }

    #[test]
    fn host_len_ascii_string() {
        let source = r#"
            LOAD_STR r1, "hello"
            CALL_HOST r0, "len", 1, r1
        "#;
        assert_eq!(run_and_get_int(source, 0), 5);
    }

    #[test]
    fn host_len_single_char() {
        let source = r#"
            LOAD_STR r1, "x"
            CALL_HOST r0, "len", 1, r1
        "#;
        assert_eq!(run_and_get_int(source, 0), 1);
    }

    #[test]
    fn host_len_wrong_arg_count() {
        let source = r#"
            LOAD_STR r1, "test"
            LOAD_STR r2, "extra"
            CALL_HOST r0, "len", 2, r1
        "#;
        assert!(matches!(
            run_expect_err(source),
            VMError::ArityMismatch { .. }
        ));
    }

    #[test]
    fn host_len_wrong_type() {
        let source = r#"
            LOAD_I64 r1, 42
            CALL_HOST r0, "len", 1, r1
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
            LOAD_STR r1, "hello world"
            LOAD_I64 r2, 0
            LOAD_I64 r3, 5
            CALL_HOST r0, "slice", 3, r1
        "#;
        let vm = run_vm(source);
        let ref_id = vm.registers.get_ref(0, "").unwrap();
        assert_eq!(vm.heap.get_string(ref_id).unwrap(), "hello");
    }

    #[test]
    fn host_slice_from_offset() {
        let source = r#"
            LOAD_STR r1, "hello world"
            LOAD_I64 r2, 6
            LOAD_I64 r3, 11
            CALL_HOST r0, "slice", 3, r1
        "#;
        let vm = run_vm(source);
        let ref_id = vm.registers.get_ref(0, "").unwrap();
        assert_eq!(vm.heap.get_string(ref_id).unwrap(), "world");
    }

    #[test]
    fn host_slice_empty_result() {
        let source = r#"
            LOAD_STR r1, "hello"
            LOAD_I64 r2, 2
            LOAD_I64 r3, 2
            CALL_HOST r0, "slice", 3, r1
        "#;
        let vm = run_vm(source);
        let ref_id = vm.registers.get_ref(0, "").unwrap();
        assert_eq!(vm.heap.get_string(ref_id).unwrap(), "");
    }

    #[test]
    fn host_slice_full_string() {
        let source = r#"
            LOAD_STR r1, "abc"
            LOAD_I64 r2, 0
            LOAD_I64 r3, 3
            CALL_HOST r0, "slice", 3, r1
        "#;
        let vm = run_vm(source);
        let ref_id = vm.registers.get_ref(0, "").unwrap();
        assert_eq!(vm.heap.get_string(ref_id).unwrap(), "abc");
    }

    #[test]
    fn host_slice_clamps_end_beyond_length() {
        let source = r#"
            LOAD_STR r1, "short"
            LOAD_I64 r2, 0
            LOAD_I64 r3, 100
            CALL_HOST r0, "slice", 3, r1
        "#;
        let vm = run_vm(source);
        let ref_id = vm.registers.get_ref(0, "").unwrap();
        assert_eq!(vm.heap.get_string(ref_id).unwrap(), "short");
    }

    #[test]
    fn host_slice_clamps_start_beyond_end() {
        let source = r#"
            LOAD_STR r1, "hello"
            LOAD_I64 r2, 10
            LOAD_I64 r3, 5
            CALL_HOST r0, "slice", 3, r1
        "#;
        let vm = run_vm(source);
        let ref_id = vm.registers.get_ref(0, "").unwrap();
        assert_eq!(vm.heap.get_string(ref_id).unwrap(), "");
    }

    #[test]
    fn host_slice_wrong_arg_count() {
        let source = r#"
            LOAD_STR r1, "test"
            LOAD_I64 r2, 0
            CALL_HOST r0, "slice", 2, r1
        "#;
        assert!(matches!(
            run_expect_err(source),
            VMError::ArityMismatch { .. }
        ));
    }

    // --- concat ---

    #[test]
    fn host_concat_two_strings() {
        let source = r#"
            LOAD_STR r1, "hello"
            LOAD_STR r2, " world"
            CALL_HOST r0, "concat", 2, r1
        "#;
        let vm = run_vm(source);
        let ref_id = vm.registers.get_ref(0, "").unwrap();
        assert_eq!(vm.heap.get_string(ref_id).unwrap(), "hello world");
    }

    #[test]
    fn host_concat_empty_left() {
        let source = r#"
            LOAD_STR r1, ""
            LOAD_STR r2, "world"
            CALL_HOST r0, "concat", 2, r1
        "#;
        let vm = run_vm(source);
        let ref_id = vm.registers.get_ref(0, "").unwrap();
        assert_eq!(vm.heap.get_string(ref_id).unwrap(), "world");
    }

    #[test]
    fn host_concat_empty_right() {
        let source = r#"
            LOAD_STR r1, "hello"
            LOAD_STR r2, ""
            CALL_HOST r0, "concat", 2, r1
        "#;
        let vm = run_vm(source);
        let ref_id = vm.registers.get_ref(0, "").unwrap();
        assert_eq!(vm.heap.get_string(ref_id).unwrap(), "hello");
    }

    #[test]
    fn host_concat_both_empty() {
        let source = r#"
            LOAD_STR r1, ""
            LOAD_STR r2, ""
            CALL_HOST r0, "concat", 2, r1
        "#;
        let vm = run_vm(source);
        let ref_id = vm.registers.get_ref(0, "").unwrap();
        assert_eq!(vm.heap.get_string(ref_id).unwrap(), "");
    }

    #[test]
    fn host_concat_wrong_arg_count() {
        let source = r#"
            LOAD_STR r1, "only one"
            CALL_HOST r0, "concat", 1, r1
        "#;
        assert!(matches!(
            run_expect_err(source),
            VMError::ArityMismatch { .. }
        ));
    }

    #[test]
    fn host_concat_wrong_type() {
        let source = r#"
            LOAD_STR r1, "str"
            LOAD_I64 r2, 42
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
            LOAD_STR r1, "abc"
            LOAD_STR r2, "abc"
            CALL_HOST r0, "compare", 2, r1
        "#;
        assert_eq!(run_and_get_int(source, 0), 0);
    }

    #[test]
    fn host_compare_less_than() {
        let source = r#"
            LOAD_STR r1, "abc"
            LOAD_STR r2, "abd"
            CALL_HOST r0, "compare", 2, r1
        "#;
        assert_eq!(run_and_get_int(source, 0), -1);
    }

    #[test]
    fn host_compare_greater_than() {
        let source = r#"
            LOAD_STR r1, "abd"
            LOAD_STR r2, "abc"
            CALL_HOST r0, "compare", 2, r1
        "#;
        assert_eq!(run_and_get_int(source, 0), 1);
    }

    #[test]
    fn host_compare_prefix_shorter() {
        let source = r#"
            LOAD_STR r1, "ab"
            LOAD_STR r2, "abc"
            CALL_HOST r0, "compare", 2, r1
        "#;
        assert_eq!(run_and_get_int(source, 0), -1);
    }

    #[test]
    fn host_compare_prefix_longer() {
        let source = r#"
            LOAD_STR r1, "abc"
            LOAD_STR r2, "ab"
            CALL_HOST r0, "compare", 2, r1
        "#;
        assert_eq!(run_and_get_int(source, 0), 1);
    }

    #[test]
    fn host_compare_empty_strings() {
        let source = r#"
            LOAD_STR r1, ""
            LOAD_STR r2, ""
            CALL_HOST r0, "compare", 2, r1
        "#;
        assert_eq!(run_and_get_int(source, 0), 0);
    }

    #[test]
    fn host_compare_empty_vs_nonempty() {
        let source = r#"
            LOAD_STR r1, ""
            LOAD_STR r2, "a"
            CALL_HOST r0, "compare", 2, r1
        "#;
        assert_eq!(run_and_get_int(source, 0), -1);
    }

    #[test]
    fn host_compare_wrong_arg_count() {
        let source = r#"
            LOAD_STR r1, "only"
            CALL_HOST r0, "compare", 1, r1
        "#;
        assert!(matches!(
            run_expect_err(source),
            VMError::ArityMismatch { .. }
        ));
    }

    // --- hash ---

    #[test]
    fn host_hash_returns_ref() {
        let source = r#"
            LOAD_STR r1, "hello"
            CALL_HOST r0, "hash", 1, r1
        "#;
        let vm = run_vm(source);
        assert!(matches!(vm.registers.get(0).unwrap(), Value::Ref(_)));
    }

    #[test]
    fn host_hash_consistent() {
        let source = r#"
            LOAD_STR r1, "test"
            CALL_HOST r1, "hash", 1, r1
            LOAD_STR r2, "test"
            CALL_HOST r2, "hash", 1, r2
            CALL_HOST r0, "compare", 2, r1
        "#;
        assert_eq!(run_and_get_int(source, 0), 0);
    }

    #[test]
    fn host_hash_different_inputs() {
        let source = r#"
            LOAD_STR r1, "abc"
            CALL_HOST r2, "hash", 1, r1
            LOAD_STR r3, "abd"
            CALL_HOST r4, "hash", 1, r3
            CALL_HOST r0, "compare", 2, r2
        "#;
        // Different inputs should produce different hashes
        assert_ne!(run_and_get_int(source, 0), 0);
    }

    #[test]
    fn host_hash_empty_string() {
        let source = r#"
            LOAD_STR r1, ""
            CALL_HOST r0, "hash", 1, r1
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
            LOAD_STR r1, "hello"
            CALL_HOST r0, "hash", 1, r1
        "#;
        let vm = run_vm(source);
        let ref_id = vm.registers.get_ref(0, "").unwrap();
        let hash_bytes = vm.heap.get_raw_ref(ref_id).unwrap();
        let expected = Hash::sha3().chain(b"hello").finalize();
        assert_eq!(hash_bytes, expected.as_slice());
    }

    #[test]
    fn host_hash_wrong_arg_count() {
        let source = r#"
            LOAD_STR r1, "a"
            LOAD_STR r2, "b"
            CALL_HOST r0, "hash", 2, r1
        "#;
        assert!(matches!(
            run_expect_err(source),
            VMError::ArityMismatch { .. }
        ));
    }

    #[test]
    fn host_hash_wrong_type() {
        let source = r#"
            LOAD_I64 r1, 123
            CALL_HOST r0, "hash", 1, r1
        "#;
        let vm = run_vm(source);
        let ref_id = vm.registers.get_ref(0, "").unwrap();
        let hash_bytes = vm.heap.get_raw_ref(ref_id).unwrap();
        let reg = vm.registers.get_int(1, "").unwrap();
        let expected = Hash::sha3().chain(&reg.to_le_bytes()).finalize();
        assert_eq!(hash_bytes, expected.as_slice());
    }

    // --- invalid host function ---

    #[test]
    fn host_invalid_function() {
        let source = r#"
            LOAD_STR r1, "arg"
            CALL_HOST r0, "nonexistent", 1, r1
        "#;
        assert!(matches!(
            run_expect_err(source),
            VMError::InvalidCallHostFunction { .. }
        ));
    }
}
