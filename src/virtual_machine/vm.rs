//! Core virtual machine implementation.
//!
//! The VM executes bytecode using a register-based architecture with 256 general-purpose
//! registers. All arithmetic uses wrapping semantics to prevent overflow panics.

use crate::error;
use crate::types::bytes::Bytes;
use crate::types::hash::{HASH_LEN, Hash};
use crate::virtual_machine::assembler::parse_i64;
use crate::virtual_machine::errors::VMError;
use crate::virtual_machine::isa::Instruction;
use crate::virtual_machine::program::Program;
use crate::virtual_machine::state::State;
use std::collections::HashMap;

/// Maximum gas allowed for a single transaction execution.
pub const TRANSACTION_GAS_LIMIT: u64 = 1_000_000;
/// Maximum cumulative gas allowed for all transactions in a block.
pub const BLOCK_GAS_LIMIT: u64 = 20_000_000;

/// Runtime value stored in registers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Value {
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
    pub fn new(count: usize) -> Self {
        Self {
            regs: vec![Value::Zero; count],
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

    /// Returns a reference to the raw Vec<u8> stored at the given index
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
pub struct ExecContext<'a> {
    /// Chain identifier for storage key derivation.
    pub chain_id: u64,
    /// Contract identifier for storage key derivation.
    pub contract_id: &'a [u8],
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
/// # TODO for 0.14.0:
/// 1) 🟢 Add full control flow for function support
/// 2) 🟢 Add string and hash support
///
/// # TODO potential before 1.0.0:
/// 3) 🔴 Add arithmetic op codes that take in immediate instead of register
/// 4) 🔴 Add list and map support
/// 5) 🔴 Add a deterministic optimizer do make the assembly code more performant
///
/// # TODO after 1.0.0:
/// 6) 🔴 Add a smart contract language to not require assembly written smart contracts
/// 7) 🔴 Add a deterministic compiler to convert the language to assembly
/// 8) 🔴 Add an LSP for smoother smart contract writing experience
pub struct VM {
    /// Bytecode to execute.
    data: Bytes,
    /// Instruction pointer (current position in bytecode).
    ip: usize,
    /// Register file (256 max registers).
    registers: Registers,
    /// Heap for string pool and future allocations.
    heap: Heap,
    /// Function labels mapping names to bytecode offsets.
    labels: HashMap<String, usize>,
    /// Call stack for function calls.
    call_stack: Vec<CallFrame>,
    /// Total gas consumed during execution.
    gas_used: u64,
}

impl VM {
    /// Creates a new VM instance with the given program and default gas calculator.
    pub fn new(program: Program) -> Self {
        Self {
            data: program.bytecode.into(),
            ip: 0,
            registers: Registers::new(program.max_register as usize + 1),
            heap: Heap::new(program.items),
            labels: program.labels,
            call_stack: Vec::new(),
            gas_used: 0,
        }
    }

    /// Derives a unique storage key from chain ID, contract ID, and user-provided key.
    ///
    /// The key is hashed to ensure uniform distribution and prevent collisions
    /// between different contracts or chains.
    fn make_state_key(
        &mut self,
        chain_id: u64,
        contract_id: &[u8],
        user_key: &[u8],
    ) -> Result<Hash, VMError> {
        self.charge_gas(5 + 8 + (contract_id.len() + user_key.len()) as u64)?;
        Ok(Hash::sha3()
            .chain(b"STATE")
            .chain(&chain_id.to_le_bytes())
            .chain(contract_id)
            .chain(user_key)
            .finalize())
    }

    /// Adds gas to the running total and checks against the transaction limit.
    ///
    /// Returns [`VMError::OutOfGas`] if the cumulative usage exceeds [`TRANSACTION_GAS_LIMIT`].
    fn charge_gas(&mut self, increment: u64) -> Result<(), VMError> {
        self.gas_used = self.gas_used.saturating_add(increment);

        if self.gas_used > TRANSACTION_GAS_LIMIT {
            return Err(VMError::OutOfGas {
                used: self.gas_used,
                limit: TRANSACTION_GAS_LIMIT,
            });
        }

        Ok(())
    }

    /// Charges the base gas cost for the given instruction.
    fn charge_base(&mut self, instruction: Instruction) -> Result<(), VMError> {
        self.charge_gas(instruction.base_gas())
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
        self.charge_gas(argc as u64 * arg_gas_cost + call_depth as u64 * depth_gas_cost)
    }

    /// Returns the gas cost for accessing a register based on its index tier.
    ///
    /// Lower registers (0-31) are free, higher registers cost progressively more
    /// to encourage efficient register allocation.
    ///
    /// Try and mimic real cpu costs
    /// * r0 - r31 : x0-x31 => free to use as much as required
    /// * r32 - r63 : L1 cache => costs more than a register
    /// * r64 - r127: L2 cache => costs more than the L1 cache
    /// * r128 - r255: L3 cache => costs more than the L2 cache
    fn register_gas_fee(register: u8) -> u64 {
        match register {
            0..=31 => 0,
            32..=63 => 1,
            64..=127 => 2,
            128..=255 => 4,
        }
    }

    /// Charges gas for accessing the specified register.
    fn charge_register(&mut self, register: u8) -> Result<(), VMError> {
        self.charge_gas(Self::register_gas_fee(register))
    }
}

impl VM {
    /// Returns the value in register `idx` with gas charging.
    ///
    /// Returns [`VMError::InvalidRegisterIndex`] if `idx` is out of bounds.
    pub fn registers_set(&mut self, idx: u8, v: Value) -> Result<(), VMError> {
        self.charge_register(idx)?;
        self.registers.set(idx, v)
    }

    /// Returns the value in register `idx` with gas charging.
    ///
    /// Returns [`VMError::InvalidRegisterIndex`] if `idx` is out of bounds.
    pub fn registers_get(&mut self, idx: u8) -> Result<&Value, VMError> {
        self.charge_register(idx)?;
        self.registers.get(idx)
    }

    /// Returns the boolean value in register `idx` with gas charging.
    ///
    /// Returns [`VMError::TypeMismatch`] if the value is not a boolean.
    pub fn registers_get_bool(&mut self, idx: u8, instr: &'static str) -> Result<bool, VMError> {
        self.charge_register(idx)?;
        self.registers.get_bool(idx, instr)
    }

    /// Returns the reference value in register `idx` with gas charging.
    ///
    /// Returns [`VMError::TypeMismatch`] if the value is not a reference.
    pub fn registers_get_ref(&mut self, idx: u8, instr: &'static str) -> Result<u32, VMError> {
        self.charge_register(idx)?;
        self.registers.get_ref(idx, instr)
    }

    /// Returns the integer value in register `idx` with gas charging.
    ///
    /// Returns [`VMError::TypeMismatch`] if the value is not an integer.
    pub fn registers_get_int(&mut self, idx: u8, instr: &'static str) -> Result<i64, VMError> {
        self.charge_register(idx)?;
        self.registers.get_int(idx, instr)
    }

    /// Stores an item on the heap and returns its reference index.
    ///
    /// Charges gas proportional to the item's byte length.
    pub fn heap_index(&mut self, item: Vec<u8>) -> Result<u32, VMError> {
        self.charge_gas(item.len() as u64)?;
        Ok(self.heap.index(item))
    }

    /// Retrieves a string from the heap by reference index with gas charging.
    ///
    /// Charges gas proportional to the string's byte length.
    /// Returns [`VMError::InvalidUtf8`] if the bytes are not valid UTF-8.
    pub fn heap_get_string(&mut self, id: u32) -> Result<String, VMError> {
        let size = self.heap.get_raw_ref(id)?.len();
        self.charge_gas(size as u64)?;
        self.heap.get_string(id)
    }

    /// Retrieves a string from the heap by reference index with gas charging.
    ///
    /// Charges gas proportional to the string's byte length.
    /// Returns [`VMError::InvalidUtf8`] if the bytes are not valid UTF-8.
    pub fn heap_get_hash(&mut self, id: u32) -> Result<Hash, VMError> {
        self.charge_gas(HASH_LEN as u64)?;
        self.heap.get_hash(id)
    }
}

impl VM {
    /// Executes the bytecode until completion or error.
    ///
    /// Runs instructions sequentially until the instruction pointer reaches
    /// the end of the bytecode buffer. If a gas limit is set in the context,
    /// execution halts with [`VMError::OutOfGas`] when exceeded.
    pub fn run<S: State>(&mut self, state: &mut S, ctx: &ExecContext) -> Result<(), VMError> {
        while self.ip < self.data.len() {
            let opcode_offset = self.ip;
            let opcode = self.data[opcode_offset];
            self.ip += 1;

            let instr = Instruction::try_from(opcode).map_err(|_| VMError::InvalidInstruction {
                opcode,
                offset: opcode_offset,
            })?;
            self.charge_base(instr)?;
            self.exec(instr, state, ctx)?;
        }
        error!(
            "Used: {} registers and {} gas.",
            self.registers.regs.len(),
            self.gas_used
        );
        Ok(())
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
                Call => op_call(dst: Reg, fn_id: RefU32, argc: ImmU8, argv: Reg),
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
        let key_ref = self.registers_get_ref(key, instr)?;
        let key_str = self.heap_get_string(key_ref)?;
        let key = self.make_state_key(ctx.chain_id, ctx.contract_id, key_str.as_bytes())?;
        state.delete(key);
        Ok(())
    }

    fn op_load_i64(&mut self, _instr: &'static str, dst: u8, imm: i64) -> Result<(), VMError> {
        self.registers_set(dst, Value::Int(imm))
    }

    fn op_store_i64<S: State>(
        &mut self,
        instr: &'static str,
        state: &mut S,
        ctx: &ExecContext,
        key: u8,
        value: u8,
    ) -> Result<(), VMError> {
        let key_ref = self.registers_get_ref(key, instr)?;
        let key_str = self.heap_get_string(key_ref)?;
        let val = self.registers_get_int(value, instr)?;
        let key = self.make_state_key(ctx.chain_id, ctx.contract_id, key_str.as_bytes())?;
        state.push(key, val.to_le_bytes().to_vec());
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
        let key_ref = self.registers_get_ref(key, instr)?;
        let key_str = self.heap_get_string(key_ref)?;
        let state_key = self.make_state_key(ctx.chain_id, ctx.contract_id, key_str.as_bytes())?;
        let value = state.get(state_key).ok_or(VMError::KeyNotFound {
            key: key_str.clone(),
        })?;
        let bytes: [u8; 8] = value.try_into().map_err(|_| VMError::InvalidStateValue {
            key: key_str.clone(),
            expected: "8 bytes for i64",
        })?;
        self.registers
            .set(dst, Value::Int(i64::from_le_bytes(bytes)))
    }

    fn op_load_bool(&mut self, _instr: &'static str, dst: u8, b: bool) -> Result<(), VMError> {
        self.registers_set(dst, Value::Bool(b))
    }

    fn op_store_bool<S: State>(
        &mut self,
        instr: &'static str,
        state: &mut S,
        ctx: &ExecContext,
        key: u8,
        value: u8,
    ) -> Result<(), VMError> {
        let key_ref = self.registers_get_ref(key, instr)?;
        let key_str = self.heap_get_string(key_ref)?;
        let val = self.registers_get_bool(value, instr)?;
        let key = self.make_state_key(ctx.chain_id, ctx.contract_id, key_str.as_bytes())?;
        state.push(key, [val as u8].into());
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
        let key_ref = self.registers_get_ref(key, instr)?;
        let key_str = self.heap_get_string(key_ref)?;
        let state_key = self.make_state_key(ctx.chain_id, ctx.contract_id, key_str.as_bytes())?;
        let value = state.get(state_key).ok_or(VMError::KeyNotFound {
            key: key_str.clone(),
        })?;
        if value.len() != 1 {
            return Err(VMError::InvalidStateValue {
                key: key_str,
                expected: "1 byte for bool",
            });
        }
        self.registers_set(dst, Value::Bool(value[0] != 0))
    }

    fn op_load_str(&mut self, _instr: &'static str, dst: u8, str_ref: u32) -> Result<(), VMError> {
        self.registers_set(dst, Value::Ref(str_ref))
    }

    fn op_store_str<S: State>(
        &mut self,
        instr: &'static str,
        state: &mut S,
        ctx: &ExecContext,
        key: u8,
        value: u8,
    ) -> Result<(), VMError> {
        let key_ref = self.registers_get_ref(key, instr)?;
        let key_str = self.heap_get_string(key_ref)?;
        let val_ref = self.registers_get_ref(value, instr)?;
        let val_str = self.heap_get_string(val_ref)?;
        let key = self.make_state_key(ctx.chain_id, ctx.contract_id, key_str.as_bytes())?;
        state.push(key, val_str.into_bytes());
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
        let key_ref = self.registers_get_ref(key, instr)?;
        let key_str = self.heap_get_string(key_ref)?;
        let state_key = self.make_state_key(ctx.chain_id, ctx.contract_id, key_str.as_bytes())?;
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
        self.registers_set(dst, Value::Ref(hash_ref))
    }

    fn op_store_hash<S: State>(
        &mut self,
        instr: &'static str,
        state: &mut S,
        ctx: &ExecContext,
        key: u8,
        value: u8,
    ) -> Result<(), VMError> {
        let key_ref = self.registers_get_ref(key, instr)?;
        let key_str = self.heap_get_string(key_ref)?;
        let val_ref = self.registers_get_ref(value, instr)?;
        let val_hash = self.heap_get_hash(val_ref)?;
        let key = self.make_state_key(ctx.chain_id, ctx.contract_id, key_str.as_bytes())?;
        state.push(key, val_hash.to_vec());
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
        let key_ref = self.registers_get_ref(key, instr)?;
        let key_str = self.heap_get_string(key_ref)?;
        let state_key = self.make_state_key(ctx.chain_id, ctx.contract_id, key_str.as_bytes())?;
        let value = state
            .get(state_key)
            .ok_or(VMError::KeyNotFound { key: key_str })?;
        let hash_ref = self.heap_index(value)?;
        self.op_load_hash(instr, dst, hash_ref)
    }

    fn op_move(&mut self, _instr: &'static str, dst: u8, src: u8) -> Result<(), VMError> {
        let v = *self.registers_get(src)?;
        self.registers_set(dst, v)
    }

    fn op_i64_to_bool(&mut self, instr: &'static str, dst: u8, src: u8) -> Result<(), VMError> {
        let v = self.registers_get_int(src, instr)?;
        self.registers_set(dst, Value::Bool(v != 0))
    }

    fn op_bool_to_i64(&mut self, instr: &'static str, dst: u8, src: u8) -> Result<(), VMError> {
        let v = self.registers_get_bool(src, instr)?;
        self.registers_set(dst, Value::Int(if v { 1 } else { 0 }))
    }

    fn op_str_to_i64(&mut self, instr: &'static str, dst: u8, src: u8) -> Result<(), VMError> {
        let reg = self.registers_get_ref(src, instr)?;
        let str = self.heap_get_string(reg)?;
        self.op_load_i64(instr, dst, parse_i64(&str)?)
    }

    fn op_i64_to_str(&mut self, instr: &'static str, dst: u8, src: u8) -> Result<(), VMError> {
        let reg = self.registers_get_int(src, instr)?;
        let str_ref = self.heap_index(reg.to_string().into_bytes())?;
        self.op_load_str(instr, dst, str_ref)
    }

    fn op_str_to_bool(&mut self, instr: &'static str, dst: u8, src: u8) -> Result<(), VMError> {
        let reg = self.registers_get_ref(src, instr)?;
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
        let reg = self.registers_get_bool(src, instr)?;
        let str = (if reg { "true" } else { "false" }).to_string();
        let bool_ref = self.heap_index(str.into_bytes())?;
        self.op_load_str(instr, dst, bool_ref)
    }

    fn op_add(&mut self, instr: &'static str, dst: u8, a: u8, b: u8) -> Result<(), VMError> {
        let va = self.registers_get_int(a, instr)?;
        let vb = self.registers_get_int(b, instr)?;
        self.registers_set(dst, Value::Int(va.wrapping_add(vb)))
    }

    fn op_sub(&mut self, instr: &'static str, dst: u8, a: u8, b: u8) -> Result<(), VMError> {
        let va = self.registers_get_int(a, instr)?;
        let vb = self.registers_get_int(b, instr)?;
        self.registers_set(dst, Value::Int(va.wrapping_sub(vb)))
    }

    fn op_mul(&mut self, instr: &'static str, dst: u8, a: u8, b: u8) -> Result<(), VMError> {
        let va = self.registers_get_int(a, instr)?;
        let vb = self.registers_get_int(b, instr)?;
        self.registers_set(dst, Value::Int(va.wrapping_mul(vb)))
    }

    fn op_div(&mut self, instr: &'static str, dst: u8, a: u8, b: u8) -> Result<(), VMError> {
        let va = self.registers_get_int(a, instr)?;
        let vb = self.registers_get_int(b, instr)?;
        if vb == 0 {
            return Err(VMError::DivisionByZero);
        }
        self.registers_set(dst, Value::Int(va.wrapping_div(vb)))
    }

    fn op_mod(&mut self, instr: &'static str, dst: u8, a: u8, b: u8) -> Result<(), VMError> {
        let va = self.registers_get_int(a, instr)?;
        let vb = self.registers_get_int(b, instr)?;
        if vb == 0 {
            return Err(VMError::DivisionByZero);
        }
        self.registers_set(dst, Value::Int(va.wrapping_rem(vb)))
    }

    fn op_neg(&mut self, instr: &'static str, dst: u8, src: u8) -> Result<(), VMError> {
        let v = self.registers_get_int(src, instr)?;
        self.registers_set(dst, Value::Int(v.wrapping_neg()))
    }

    fn op_abs(&mut self, instr: &'static str, dst: u8, src: u8) -> Result<(), VMError> {
        let v = self.registers_get_int(src, instr)?;
        self.registers_set(dst, Value::Int(v.wrapping_abs()))
    }

    fn op_min(&mut self, instr: &'static str, dst: u8, a: u8, b: u8) -> Result<(), VMError> {
        let va = self.registers_get_int(a, instr)?;
        let vb = self.registers_get_int(b, instr)?;
        self.registers_set(dst, Value::Int(va.min(vb)))
    }

    fn op_max(&mut self, instr: &'static str, dst: u8, a: u8, b: u8) -> Result<(), VMError> {
        let va = self.registers_get_int(a, instr)?;
        let vb = self.registers_get_int(b, instr)?;
        self.registers_set(dst, Value::Int(va.max(vb)))
    }

    fn op_shl(&mut self, instr: &'static str, dst: u8, a: u8, b: u8) -> Result<(), VMError> {
        let va = self.registers_get_int(a, instr)?;
        let vb = self.registers_get_int(b, instr)?;
        self.registers
            .set(dst, Value::Int(va.wrapping_shl(vb as u32)))
    }

    fn op_shr(&mut self, instr: &'static str, dst: u8, a: u8, b: u8) -> Result<(), VMError> {
        let va = self.registers_get_int(a, instr)?;
        let vb = self.registers_get_int(b, instr)?;
        self.registers
            .set(dst, Value::Int(va.wrapping_shr(vb as u32)))
    }

    fn op_not(&mut self, instr: &'static str, dst: u8, src: u8) -> Result<(), VMError> {
        let v = self.registers_get_bool(src, instr)?;
        self.registers_set(dst, Value::Bool(!v))
    }

    fn op_and(&mut self, instr: &'static str, dst: u8, a: u8, b: u8) -> Result<(), VMError> {
        let va = self.registers_get_bool(a, instr)?;
        let vb = self.registers_get_bool(b, instr)?;
        self.registers_set(dst, Value::Bool(va && vb))
    }

    fn op_or(&mut self, instr: &'static str, dst: u8, a: u8, b: u8) -> Result<(), VMError> {
        let va = self.registers_get_bool(a, instr)?;
        let vb = self.registers_get_bool(b, instr)?;
        self.registers_set(dst, Value::Bool(va || vb))
    }

    fn op_xor(&mut self, instr: &'static str, dst: u8, a: u8, b: u8) -> Result<(), VMError> {
        let va = self.registers_get_bool(a, instr)?;
        let vb = self.registers_get_bool(b, instr)?;
        self.registers_set(dst, Value::Bool(va ^ vb))
    }

    fn op_eq(&mut self, instr: &'static str, dst: u8, a: u8, b: u8) -> Result<(), VMError> {
        let va = self.registers_get_int(a, instr)?;
        let vb = self.registers_get_int(b, instr)?;
        self.registers_set(dst, Value::Bool(va == vb))
    }

    fn op_lt(&mut self, instr: &'static str, dst: u8, a: u8, b: u8) -> Result<(), VMError> {
        let va = self.registers_get_int(a, instr)?;
        let vb = self.registers_get_int(b, instr)?;
        self.registers_set(dst, Value::Bool(va < vb))
    }

    fn op_gt(&mut self, instr: &'static str, dst: u8, a: u8, b: u8) -> Result<(), VMError> {
        let va = self.registers_get_int(a, instr)?;
        let vb = self.registers_get_int(b, instr)?;
        self.registers_set(dst, Value::Bool(va > vb))
    }

    fn op_le(&mut self, instr: &'static str, dst: u8, a: u8, b: u8) -> Result<(), VMError> {
        let va = self.registers_get_int(a, instr)?;
        let vb = self.registers_get_int(b, instr)?;
        self.registers_set(dst, Value::Bool(va <= vb))
    }

    fn op_ge(&mut self, instr: &'static str, dst: u8, a: u8, b: u8) -> Result<(), VMError> {
        let va = self.registers_get_int(a, instr)?;
        let vb = self.registers_get_int(b, instr)?;
        self.registers_set(dst, Value::Bool(va >= vb))
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
            .map(|i| self.registers_get(argv.wrapping_add(i)).copied())
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
                self.charge_gas(len as u64)?;
                self.op_load_i64(instr, dst, self.heap.get_raw_ref(str_ref)?.len() as i64)
            }
            k @ "slice" => {
                arg_len_check(3, args.len(), k)?;
                let str_ref = get_ref(args[0])?;
                let start = get_i64(args[1])? as usize;
                let end = get_i64(args[2])? as usize;

                let len = self.heap.get_raw_ref(str_ref)?.len();
                self.charge_gas(len as u64)?;

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
                self.charge_gas(result as u64)?;

                let mut result = self.heap.get_raw_ref(ref1)?.clone();
                result.extend_from_slice(self.heap.get_raw_ref(ref2)?);

                let new_ref = self.heap_index(result)?;
                self.op_load_str(instr, dst, new_ref)
            }
            k @ "compare" => {
                arg_len_check(2, args.len(), k)?;
                let ref1 = get_ref(args[0])?;
                let ref2 = get_ref(args[1])?;

                let l1 = self.heap.get_raw_ref(ref1)?.len();
                let l2 = self.heap.get_raw_ref(ref2)?.len();
                self.charge_gas((l1 + l2) as u64)?;

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
                    Value::Ref(r) => self.heap.get_raw_ref(r)?.len(),
                    Value::Int(_) => 8,
                };
                self.charge_gas(len as u64)?;

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
        _instr: &'static str,
        dst: u8,
        fn_id: u32,
        argc: u8,
        _argv: u8,
    ) -> Result<(), VMError> {
        self.charge_call(argc, 5, self.call_stack.len(), 10)?;
        let fn_name = self.heap_get_string(fn_id)?;
        let target = *self
            .labels
            .get(&fn_name)
            .ok_or(VMError::UndefinedFunction { function: fn_name })?;

        self.call_stack.push(CallFrame {
            return_addr: self.ip,
            dst_reg: dst,
        });

        self.ip = target;
        Ok(())
    }

    fn op_jal(&mut self, _instr: &'static str, rd: u8, offset: i64) -> Result<(), VMError> {
        self.registers_set(rd, Value::Int(self.ip as i64))?;
        self.op_jump(_instr, offset)?;
        Ok(())
    }

    fn op_jalr(&mut self, instr: &'static str, rd: u8, rs: u8, offset: i64) -> Result<(), VMError> {
        let base = self.registers_get_int(rs, instr)?;
        self.registers_set(rd, Value::Int(self.ip as i64))?;
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
        let a = self.registers_get_int(rs1, instr)?;
        let b = self.registers_get_int(rs2, instr)?;
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
        let a = self.registers_get_int(rs1, instr)?;
        let b = self.registers_get_int(rs2, instr)?;
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
        let a = self.registers_get_int(rs1, instr)?;
        let b = self.registers_get_int(rs2, instr)?;
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
        let a = self.registers_get_int(rs1, instr)?;
        let b = self.registers_get_int(rs2, instr)?;
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
        let a = self.registers_get_int(rs1, instr)? as u64;
        let b = self.registers_get_int(rs2, instr)? as u64;
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
        let a = self.registers_get_int(rs1, instr)? as u64;
        let b = self.registers_get_int(rs2, instr)? as u64;
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

    fn op_ret(&mut self, _instr: &'static str, rs: u8) -> Result<(), VMError> {
        let frame = self.call_stack.pop().ok_or(VMError::ReturnWithoutCall {
            call_depth: self.call_stack.len(),
        })?;

        let ret_val = *self.registers_get(rs)?;
        self.registers_set(frame.dst_reg, ret_val)?;
        self.ip = frame.return_addr;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::virtual_machine::assembler::assemble_source;
    use crate::virtual_machine::state::tests::TestState;

    const EXECUTION_CONTEXT: &ExecContext = &ExecContext {
        chain_id: 62845383663927,
        contract_id: &[3, 5, 2, 3, 9, 1],
    };

    fn run_vm(source: &str) -> VM {
        let program = assemble_source(source).expect("assembly failed");
        let mut vm = VM::new(program);
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
        let program = assemble_source(source).expect("assembly failed");
        let mut vm = VM::new(program);
        vm.run(&mut TestState::new(), EXECUTION_CONTEXT)
            .expect_err("expected error")
    }

    fn run_vm_with_state(source: &str) -> TestState {
        let program = assemble_source(source).expect("assembly failed");
        let mut vm = VM::new(program);
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
        let mut vm = VM::new(Program::new(vec![], vec![0xFF]));
        assert!(matches!(
            vm.run(&mut TestState::new(), EXECUTION_CONTEXT),
            Err(VMError::InvalidInstruction { opcode: 0xFF, .. })
        ));
    }

    #[test]
    fn truncated_bytecode() {
        let mut vm = VM::new(Program::new(vec![], vec![0x01, 0x00]));
        assert!(matches!(
            vm.run(&mut TestState::new(), EXECUTION_CONTEXT),
            Err(VMError::UnexpectedEndOfBytecode { .. })
        ));
    }

    // ==================== Stores ====================

    fn make_test_key(user_key: &[u8]) -> Result<Hash, VMError> {
        VM::new(Program::new(Vec::new(), Vec::new())).make_state_key(
            EXECUTION_CONTEXT.chain_id,
            EXECUTION_CONTEXT.contract_id,
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
        let mut vm = VM::new(program);
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
        let mut vm = VM::new(program);
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
        let mut vm = VM::new(program);
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
        let mut vm = VM::new(program);
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
            CALL r1, "double", 0, r0
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
            CALL r1, "outer", 0, r0
            JAL r0, end
            outer:
            CALL r2, "inner", 0, r0
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
        let source = r#"CALL r0, "nonexistent", 0, r0"#;
        let err = run_expect_err(source);
        assert!(matches!(err, VMError::UndefinedFunction { .. }));
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
            CALL r1, "func", 0, r0
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
        let mut vm = VM::new(program);

        let key_counter = vm
            .make_state_key(
                EXECUTION_CONTEXT.chain_id,
                EXECUTION_CONTEXT.contract_id,
                b"counter",
            )
            .unwrap();
        let key_steps = vm
            .make_state_key(
                EXECUTION_CONTEXT.chain_id,
                EXECUTION_CONTEXT.contract_id,
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
            CALL r1, "f1", 0, r0
            JAL r0, end
            f1:
            CALL r2, "f2", 0, r0
            RET r2
            f2:
            CALL r3, "f3", 0, r0
            RET r3
            f3:
            CALL r4, "f4", 0, r0
            RET r4
            f4:
            CALL r5, "f5", 0, r0
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
            CALL r1, "add_ten", 0, r0
            CALL r2, "add_ten", 0, r0
            CALL r3, "add_ten", 0, r0
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
            CALL r5, "get_42", 0, r0
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
            CALL r2, "countdown", 0, r0
            JAL r0, end

            countdown:
            LOAD_I64 r10, 0
            LOAD_I64 r11, 1
            BEQ r1, r10, done
            SUB r1, r1, r11
            CALL r12, "countdown", 0, r0
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
            CALL r1, "func", 0, r0
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
            CALL r1, "func", 0, r0
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
            CALL r1, "ret_10", 0, r0
            CALL r2, "ret_20", 0, r0
            CALL r3, "ret_30", 0, r0
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
            CALL r10, "func", 0, r0
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
            CALL r1, "outer", 0, r0
            JAL r0, end
            outer:
            CALL r2, "middle", 0, r0
            LOAD_I64 r3, 1
            ADD r2, r2, r3
            RET r2
            middle:
            CALL r4, "inner", 0, r0
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
            CALL r1, "a", 0, r0
            CALL r2, "b", 0, r0
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
            CALL r1, "ret_zero", 0, r0
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
            CALL r1, "ret_bool", 0, r0
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
            CALL r1, "ret_str", 0, r0
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
