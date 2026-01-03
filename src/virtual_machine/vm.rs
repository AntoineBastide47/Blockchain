//! Core virtual machine implementation.
//!
//! The VM executes bytecode using a register-based architecture with 256 general-purpose
//! registers. All arithmetic uses wrapping semantics to prevent overflow panics.

use crate::types::bytes::Bytes;
use crate::types::hash::Hash;
use crate::virtual_machine::errors::VMError;
use crate::virtual_machine::isa::Instruction;
use crate::virtual_machine::program::Program;
use crate::virtual_machine::state::State;

/// Runtime value stored in registers.
#[derive(Clone, Debug, Eq, PartialEq)]
enum Value {
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

/// Register file holding VM state.
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
            .ok_or(VMError::InvalidRegisterIndex(idx))
    }

    /// Returns the boolean value in register `idx`.
    ///
    /// Returns [`VMError::TypeMismatch`] if the value is not a boolean.
    pub fn get_bool(&self, idx: u8, instr: &'static str) -> Result<bool, VMError> {
        match self.get(idx)? {
            Value::Bool(v) => Ok(*v),
            other => Err(VMError::TypeMismatch {
                instruction: instr,
                arg_index: idx as i32,
                expected: "Bool",
                actual: other.type_name().to_string(),
            }),
        }
    }

    /// Returns the reference value in register `idx`.
    ///
    /// Returns [`VMError::TypeMismatch`] if the value is not a reference.
    pub fn get_ref(&self, idx: u8, instr: &'static str) -> Result<u32, VMError> {
        match self.get(idx)? {
            Value::Ref(v) => Ok(*v),
            other => Err(VMError::TypeMismatch {
                instruction: instr,
                arg_index: idx as i32,
                expected: "Ref",
                actual: other.type_name().to_string(),
            }),
        }
    }

    /// Returns the integer value in register `idx`.
    ///
    /// Returns [`VMError::TypeMismatch`] if the value is not an integer.
    pub fn get_int(&self, idx: u8, instr: &'static str) -> Result<i64, VMError> {
        match self.get(idx)? {
            Value::Int(v) => Ok(*v),
            other => Err(VMError::TypeMismatch {
                instruction: instr,
                arg_index: idx as i32,
                expected: "Int",
                actual: other.type_name().to_string(),
            }),
        }
    }

    /// Stores a value into register `idx`.
    ///
    /// Returns [`VMError::InvalidRegisterIndex`] if `idx` is out of bounds.
    pub fn set(&mut self, idx: u8, v: Value) -> Result<(), VMError> {
        let slot = self
            .regs
            .get_mut(idx as usize)
            .ok_or(VMError::InvalidRegisterIndex(idx))?;
        *slot = v;
        Ok(())
    }
}

/// Heap storage for reference-counted objects.
///
/// Currently, holds only the string pool loaded from the program.
struct Heap {
    /// String pool (indices correspond to `Ref` values).
    strings: Vec<String>,
}

impl Heap {
    /// Retrieves a string by its reference index.
    fn get_string(&self, id: u32) -> &str {
        &self.strings[id as usize]
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
            $( Instruction::$variant => exec_vm!(@call $vm, $state, $ctx, $handler, $args) ),*
        }
    }};

    // Handler with state and chain_id (semicolon separator)
    (@call $vm:ident, $state:ident, $ctx:ident, $handler:ident,
        (state, ctx; $( $field:ident : $kind:ident ),* $(,)? )
    ) => {{
        $( let $field = exec_vm!(@read $vm, $kind)?; )*
        $vm.$handler($state, $ctx, $( $field ),*)
    }};

    // Handler without state (no semicolon)
    (@call $vm:ident, $state:ident, $ctx:ident, $handler:ident,
        ( $( $field:ident : $kind:ident ),* $(,)? )
    ) => {{
        $( let $field = exec_vm!(@read $vm, $kind)?; )*
        $vm.$handler($( $field ),*)
    }};

    // Decode a u8 register index
    (@read $vm:ident, Reg) => {{
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
/// Contains chain and contract identifiers used to namespace state keys.
pub struct ExecContext<'a> {
    /// Chain identifier for state key derivation.
    pub chain_id: u64,
    /// Contract identifier for state key derivation.
    pub contract_id: &'a [u8],
}

/// Bytecode virtual machine.
///
/// Executes compiled bytecode sequentially, reading instructions from the
/// instruction pointer until the end of the bytecode is reached.
///
/// # TODO:
/// 1) Add full string, hash, list and map support
/// 2) Add full control flow for function support
/// 3) Add a smart contract language to not require assembly written smart contracts
/// 4) Add a deterministic compiler to convert the language to assembly
/// 5) Add a deterministic optimizer do make the assembly code more performant
/// 6) Add an LSP for smoother smart contract writing experience
pub struct VM {
    /// Bytecode to execute.
    data: Bytes,
    /// Instruction pointer (current position in bytecode).
    ip: usize,
    /// Register file (256 registers).
    registers: Registers,
    /// Heap for string pool and future allocations.
    heap: Heap,
}

impl VM {
    /// Creates a new VM instance with the given bytecode.
    pub fn new(program: Program) -> Self {
        Self {
            data: program.bytecode.into(),
            ip: 0,
            registers: Registers::new(256),
            heap: Heap {
                strings: program.strings,
            },
        }
    }

    /// Executes the bytecode until completion or error.
    ///
    /// Runs instructions sequentially until the instruction pointer reaches
    /// the end of the bytecode buffer.
    pub fn run(&mut self, state: &mut dyn State, ctx: &ExecContext) -> Result<(), VMError> {
        while self.ip < self.data.len() {
            let opcode = self.data[self.ip];
            self.ip += 1;
            let instr = Instruction::try_from(opcode)?;
            self.exec(instr, state, ctx)?;
        }
        Ok(())
    }

    /// Reads exactly `count` bytes from the bytecode at the current IP.
    ///
    /// Advances the instruction pointer by `count` bytes.
    fn read_exact(&mut self, count: usize) -> Result<&[u8], VMError> {
        let start = self.ip;
        let end = self.ip.checked_add(count).ok_or(VMError::InvalidIP)?;

        let slice = self
            .data
            .get(start..end)
            .ok_or(VMError::UnexpectedEndOfBytecode)?;

        self.ip = end;
        Ok(slice)
    }

    /// Executes a single instruction.
    fn exec(
        &mut self,
        instruction: Instruction,
        state: &mut dyn State,
        ctx: &ExecContext,
    ) -> Result<(), VMError> {
        exec_vm! {
            vm = self,
            state = state,
            ctx = ctx,
            instr = instruction,
            {
                // Store and Load
                LoadI64 => op_load_i64(rd: Reg, imm: ImmI64),
                StoreI64 => op_store_i64(state, ctx; key: Reg, value: Reg),
                LoadI64State => op_load_i64_state(state, ctx; rd: Reg, key: Reg),
                LoadBool => op_load_bool(rd: Reg, b: Bool),
                StoreBool => op_store_bool(state, ctx; key: Reg, value: Reg),
                LoadBoolState => op_load_bool_state(state, ctx; rd: Reg, key: Reg),
                LoadStr => op_load_str(rd: Reg, str_ref: RefU32),
                StoreStr => op_store_str(state, ctx; key: Reg, value: Reg),
                LoadStrState => op_load_str_state(state, ctx; rd: Reg, key: Reg),
                // Moves / casts
                Move => op_move(rd: Reg, rs: Reg),
                I64ToBool => op_i64_to_bool(rd: Reg, rs: Reg),
                BoolToI64 => op_bool_to_i64(rd: Reg, rs: Reg),
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
                CallHost => op_call_host(dst: Reg, fn_id: RefU32, argc: ImmI64, argv: Reg),
            }
        }
    }

    /// Derives a unique state key from chain ID, contract ID, and user-provided key.
    ///
    /// The key is hashed to ensure uniform distribution and prevent collisions
    /// between different contracts or chains.
    fn make_state_key(chain_id: u64, contract_id: &[u8], user_key: &[u8]) -> Hash {
        let mut h = Hash::sha3();
        h.update(b"STATE");
        h.update(&chain_id.to_le_bytes());
        h.update(contract_id);
        h.update(user_key);
        h.finalize()
    }

    fn op_load_i64(&mut self, dst: u8, imm: i64) -> Result<(), VMError> {
        self.registers.set(dst, Value::Int(imm))
    }

    fn op_store_i64(
        &mut self,
        state: &mut dyn State,
        ctx: &ExecContext,
        key: u8,
        value: u8,
    ) -> Result<(), VMError> {
        let key_ref = self.registers.get_ref(key, "STORE_I64")?;
        let key_str = self.heap.get_string(key_ref).to_owned();
        let val = self.registers.get_int(value, "STORE_I64")?;
        let key = Self::make_state_key(ctx.chain_id, ctx.contract_id, key_str.as_bytes());
        state.push(key, val.to_le_bytes().to_vec());
        Ok(())
    }

    fn op_load_i64_state(
        &mut self,
        state: &mut dyn State,
        ctx: &ExecContext,
        dst: u8,
        key: u8,
    ) -> Result<(), VMError> {
        let key_ref = self.registers.get_ref(key, "LOAD_I64_STATE")?;
        let key_str = self.heap.get_string(key_ref);
        let state_key = Self::make_state_key(ctx.chain_id, ctx.contract_id, key_str.as_bytes());
        let value = state
            .get(state_key)
            .ok_or_else(|| VMError::KeyNotFound(key_str.to_string()))?;
        let bytes: [u8; 8] = value.try_into().map_err(|_| VMError::InvalidStateValue)?;
        self.registers
            .set(dst, Value::Int(i64::from_le_bytes(bytes)))
    }

    fn op_load_bool(&mut self, dst: u8, b: bool) -> Result<(), VMError> {
        self.registers.set(dst, Value::Bool(b))
    }

    fn op_store_bool(
        &mut self,
        state: &mut dyn State,
        ctx: &ExecContext,
        key: u8,
        value: u8,
    ) -> Result<(), VMError> {
        let key_ref = self.registers.get_ref(key, "STORE_BOOL")?;
        let key_str = self.heap.get_string(key_ref).to_owned();
        let val = self.registers.get_bool(value, "STORE_BOOL")?;
        let key = Self::make_state_key(ctx.chain_id, ctx.contract_id, key_str.as_bytes());
        state.push(key, [val as u8].into());
        Ok(())
    }

    fn op_load_bool_state(
        &mut self,
        state: &mut dyn State,
        ctx: &ExecContext,
        dst: u8,
        key: u8,
    ) -> Result<(), VMError> {
        let key_ref = self.registers.get_ref(key, "LOAD_BOOL_STATE")?;
        let key_str = self.heap.get_string(key_ref);
        let state_key = Self::make_state_key(ctx.chain_id, ctx.contract_id, key_str.as_bytes());
        let value = state
            .get(state_key)
            .ok_or_else(|| VMError::KeyNotFound(key_str.to_string()))?;
        if value.len() != 1 {
            return Err(VMError::InvalidStateValue);
        }
        self.registers.set(dst, Value::Bool(value[0] != 0))
    }

    fn op_load_str(&mut self, dst: u8, str_ref: u32) -> Result<(), VMError> {
        self.registers.set(dst, Value::Ref(str_ref))
    }

    fn op_store_str(
        &mut self,
        state: &mut dyn State,
        ctx: &ExecContext,
        key: u8,
        value: u8,
    ) -> Result<(), VMError> {
        let key_ref = self.registers.get_ref(key, "STORE_STR")?;
        let key_str = self.heap.get_string(key_ref).to_owned();
        let val_ref = self.registers.get_ref(value, "STORE_STR")?;
        let val_str = self.heap.get_string(val_ref);
        let key = Self::make_state_key(ctx.chain_id, ctx.contract_id, key_str.as_bytes());
        state.push(key, val_str.as_bytes().into());
        Ok(())
    }

    fn op_load_str_state(
        &mut self,
        state: &mut dyn State,
        ctx: &ExecContext,
        dst: u8,
        key: u8,
    ) -> Result<(), VMError> {
        let key_ref = self.registers.get_ref(key, "LOAD_STR_STATE")?;
        let key_str = self.heap.get_string(key_ref);
        let state_key = Self::make_state_key(ctx.chain_id, ctx.contract_id, key_str.as_bytes());
        let value = state
            .get(state_key)
            .ok_or_else(|| VMError::KeyNotFound(key_str.to_string()))?;
        let str_val = String::from_utf8(value).map_err(|_| VMError::InvalidStateValue)?;
        let str_idx = self.heap.strings.len() as u32;
        self.heap.strings.push(str_val);
        self.registers.set(dst, Value::Ref(str_idx))
    }

    fn op_move(&mut self, dst: u8, src: u8) -> Result<(), VMError> {
        let v = self.registers.get(src)?.clone();
        self.registers.set(dst, v)
    }

    fn op_i64_to_bool(&mut self, dst: u8, src: u8) -> Result<(), VMError> {
        let v = self.registers.get_int(src, "I64_TO_BOOL")?;
        self.registers.set(dst, Value::Bool(v != 0))
    }

    fn op_bool_to_i64(&mut self, dst: u8, src: u8) -> Result<(), VMError> {
        let v = self.registers.get_bool(src, "BOOL_TO_I64")?;
        self.registers.set(dst, Value::Int(if v { 1 } else { 0 }))
    }

    fn op_add(&mut self, dst: u8, a: u8, b: u8) -> Result<(), VMError> {
        let va = self.registers.get_int(a, "ADD")?;
        let vb = self.registers.get_int(b, "ADD")?;
        self.registers.set(dst, Value::Int(va.wrapping_add(vb)))
    }

    fn op_sub(&mut self, dst: u8, a: u8, b: u8) -> Result<(), VMError> {
        let va = self.registers.get_int(a, "SUB")?;
        let vb = self.registers.get_int(b, "SUB")?;
        self.registers.set(dst, Value::Int(va.wrapping_sub(vb)))
    }

    fn op_mul(&mut self, dst: u8, a: u8, b: u8) -> Result<(), VMError> {
        let va = self.registers.get_int(a, "MUL")?;
        let vb = self.registers.get_int(b, "MUL")?;
        self.registers.set(dst, Value::Int(va.wrapping_mul(vb)))
    }

    fn op_div(&mut self, dst: u8, a: u8, b: u8) -> Result<(), VMError> {
        let va = self.registers.get_int(a, "DIV")?;
        let vb = self.registers.get_int(b, "DIV")?;
        if vb == 0 {
            return Err(VMError::DivisionByZero);
        }
        self.registers.set(dst, Value::Int(va.wrapping_div(vb)))
    }

    fn op_mod(&mut self, dst: u8, a: u8, b: u8) -> Result<(), VMError> {
        let va = self.registers.get_int(a, "MOD")?;
        let vb = self.registers.get_int(b, "MOD")?;
        if vb == 0 {
            return Err(VMError::DivisionByZero);
        }
        self.registers.set(dst, Value::Int(va.wrapping_rem(vb)))
    }

    fn op_neg(&mut self, dst: u8, src: u8) -> Result<(), VMError> {
        let v = self.registers.get_int(src, "NEG")?;
        self.registers.set(dst, Value::Int(v.wrapping_neg()))
    }

    fn op_abs(&mut self, dst: u8, src: u8) -> Result<(), VMError> {
        let v = self.registers.get_int(src, "ABS")?;
        self.registers.set(dst, Value::Int(v.wrapping_abs()))
    }

    fn op_min(&mut self, dst: u8, a: u8, b: u8) -> Result<(), VMError> {
        let va = self.registers.get_int(a, "MIN")?;
        let vb = self.registers.get_int(b, "MIN")?;
        self.registers.set(dst, Value::Int(va.min(vb)))
    }

    fn op_max(&mut self, dst: u8, a: u8, b: u8) -> Result<(), VMError> {
        let va = self.registers.get_int(a, "MAX")?;
        let vb = self.registers.get_int(b, "MAX")?;
        self.registers.set(dst, Value::Int(va.max(vb)))
    }

    fn op_shl(&mut self, dst: u8, a: u8, b: u8) -> Result<(), VMError> {
        let va = self.registers.get_int(a, "SHL")?;
        let vb = self.registers.get_int(b, "SHL")?;
        self.registers
            .set(dst, Value::Int(va.wrapping_shl(vb as u32)))
    }

    fn op_shr(&mut self, dst: u8, a: u8, b: u8) -> Result<(), VMError> {
        let va = self.registers.get_int(a, "SHR")?;
        let vb = self.registers.get_int(b, "SHR")?;
        self.registers
            .set(dst, Value::Int(va.wrapping_shr(vb as u32)))
    }

    fn op_not(&mut self, dst: u8, src: u8) -> Result<(), VMError> {
        let v = self.registers.get_bool(src, "NOT")?;
        self.registers.set(dst, Value::Bool(!v))
    }

    fn op_and(&mut self, dst: u8, a: u8, b: u8) -> Result<(), VMError> {
        let va = self.registers.get_bool(a, "AND")?;
        let vb = self.registers.get_bool(b, "AND")?;
        self.registers.set(dst, Value::Bool(va && vb))
    }

    fn op_or(&mut self, dst: u8, a: u8, b: u8) -> Result<(), VMError> {
        let va = self.registers.get_bool(a, "OR")?;
        let vb = self.registers.get_bool(b, "OR")?;
        self.registers.set(dst, Value::Bool(va || vb))
    }

    fn op_xor(&mut self, dst: u8, a: u8, b: u8) -> Result<(), VMError> {
        let va = self.registers.get_bool(a, "XOR")?;
        let vb = self.registers.get_bool(b, "XOR")?;
        self.registers.set(dst, Value::Bool(va ^ vb))
    }

    fn op_eq(&mut self, dst: u8, a: u8, b: u8) -> Result<(), VMError> {
        let va = self.registers.get_int(a, "EQ")?;
        let vb = self.registers.get_int(b, "EQ")?;
        self.registers.set(dst, Value::Bool(va == vb))
    }

    fn op_lt(&mut self, dst: u8, a: u8, b: u8) -> Result<(), VMError> {
        let va = self.registers.get_int(a, "LT")?;
        let vb = self.registers.get_int(b, "LT")?;
        self.registers.set(dst, Value::Bool(va < vb))
    }

    fn op_gt(&mut self, dst: u8, a: u8, b: u8) -> Result<(), VMError> {
        let va = self.registers.get_int(a, "GT")?;
        let vb = self.registers.get_int(b, "GT")?;
        self.registers.set(dst, Value::Bool(va > vb))
    }

    fn op_le(&mut self, dst: u8, a: u8, b: u8) -> Result<(), VMError> {
        let va = self.registers.get_int(a, "LE")?;
        let vb = self.registers.get_int(b, "LE")?;
        self.registers.set(dst, Value::Bool(va <= vb))
    }

    fn op_ge(&mut self, dst: u8, a: u8, b: u8) -> Result<(), VMError> {
        let va = self.registers.get_int(a, "GE")?;
        let vb = self.registers.get_int(b, "GE")?;
        self.registers.set(dst, Value::Bool(va >= vb))
    }

    fn op_call_host(&mut self, _dst: u8, fn_id: u32, argc: i64, argv: u8) -> Result<(), VMError> {
        let fn_name = self.heap.get_string(fn_id);
        let _args: Vec<&Value> = (0..argc as u8)
            .map(|i| self.registers.get(argv.wrapping_add(i)))
            .collect::<Result<_, _>>()?;

        // match fn_name {
        //     _ => Err(VMError::InvalidCallHostFunction(fn_name.to_string())),
        // }

        Err(VMError::InvalidCallHostFunction(fn_name.to_string()))
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
        assert_eq!(vm.heap.get_string(ref_id), "hello");
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
            VMError::TypeMismatch { .. }
        ));
    }

    #[test]
    fn type_mismatch_bool_for_int() {
        let source = "LOAD_BOOL r0, true\nLOAD_BOOL r1, true\nADD r2, r0, r1";
        assert!(matches!(
            run_expect_err(source),
            VMError::TypeMismatch { .. }
        ));
    }

    // ==================== Error Cases ====================

    #[test]
    fn read_uninitialized_register() {
        assert!(matches!(
            run_expect_err("ADD r2, r0, r1"),
            VMError::TypeMismatch { .. }
        ));
    }

    #[test]
    fn invalid_opcode() {
        let mut vm = VM::new(Program::new(vec![], vec![0xFF]));
        assert!(matches!(
            vm.run(&mut TestState::new(), EXECUTION_CONTEXT),
            Err(VMError::InvalidInstruction(0xFF))
        ));
    }

    #[test]
    fn truncated_bytecode() {
        let mut vm = VM::new(Program::new(vec![], vec![0x00, 0x00]));
        assert!(matches!(
            vm.run(&mut TestState::new(), EXECUTION_CONTEXT),
            Err(VMError::UnexpectedEndOfBytecode)
        ));
    }

    // ==================== Stores ====================

    fn make_test_key(user_key: &[u8]) -> Hash {
        VM::make_state_key(
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
        let key = make_test_key(b"counter");
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
        let key = make_test_key(b"name");
        let value = state.get(key).expect("key not found");
        assert_eq!(value, b"alice");
    }

    #[test]
    fn store_bool() {
        let state = run_vm_with_state(
            r#"LOAD_STR r0, "flag"
LOAD_BOOL r1, true
STORE_BOOL r0, r1"#,
        );
        let key = make_test_key(b"flag");
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
        let key = make_test_key(b"x");
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
        let key = make_test_key(b"counter");
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
        let key = make_test_key(b"neg");
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
        assert!(matches!(err, VMError::KeyNotFound(_)));
    }

    #[test]
    fn load_bool_state_true() {
        let key = make_test_key(b"flag");
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
        let key = make_test_key(b"flag");
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
        assert!(matches!(err, VMError::KeyNotFound(_)));
    }

    #[test]
    fn load_str_state() {
        let key = make_test_key(b"name");
        let mut state = TestState::with_data(vec![(key, b"alice".to_vec())]);
        let vm = run_vm_on_state(
            r#"LOAD_STR r0, "name"
LOAD_STR_STATE r1, r0"#,
            &mut state,
        );
        let ref_id = vm.registers.get_ref(1, "").unwrap();
        assert_eq!(vm.heap.get_string(ref_id), "alice");
    }

    #[test]
    fn load_str_state_empty() {
        let key = make_test_key(b"empty");
        let mut state = TestState::with_data(vec![(key, vec![])]);
        let vm = run_vm_on_state(
            r#"LOAD_STR r0, "empty"
LOAD_STR_STATE r1, r0"#,
            &mut state,
        );
        let ref_id = vm.registers.get_ref(1, "").unwrap();
        assert_eq!(vm.heap.get_string(ref_id), "");
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
        assert!(matches!(err, VMError::KeyNotFound(_)));
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
        assert_eq!(vm.heap.get_string(ref_id), "hello");
    }
}
