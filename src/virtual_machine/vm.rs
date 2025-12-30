//! Core virtual machine implementation.
//!
//! The VM executes bytecode using a register-based architecture with 256 general-purpose
//! registers. All arithmetic uses wrapping semantics to prevent overflow panics.

use crate::types::bytes::Bytes;
use crate::virtual_machine::isa::Instruction;
use blockchain_derive::Error;

/// Errors that can occur during VM execution or assembly.
#[derive(Debug, Error)]
pub enum VMError {
    /// Unknown opcode encountered in bytecode.
    #[error("invalid instruction: {0}")]
    InvalidInstruction(u8),
    /// Unrecognized instruction mnemonic during assembly.
    #[error("invalid instruction name: {0}")]
    InvalidInstructionName(String),
    /// Wrong number of operands for an instruction.
    #[error("arity mismatch")]
    ArityMismatch,
    /// Expected a register operand (e.g., `r0`) but got something else.
    #[error("expected register, got {0}")]
    ExpectedRegister(String),
    /// Register index out of range or malformed.
    #[error("invalid register {0}")]
    InvalidRegister(String),
    /// Failed to parse an immediate value as i64.
    #[error("invalid i64 literal {0}")]
    InvalidI64(String),
    /// Attempted to read from an uninitialized register.
    #[error("stack underflow: attempting to remove a value from empty stack")]
    StackUnderflow,
    /// Register index exceeds the register file size.
    #[error("stack overflow: attempting to read beyond the stack size")]
    StackOverflow,
    /// Operand type does not match expected type.
    #[error(
        "instruction {instruction} expected argument {arg_index} to be of type {expected} but got {actual}"
    )]
    TypeMismatch {
        instruction: &'static str,
        arg_index: i32,
        expected: &'static str,
        actual: &'static str,
    },
    /// Instruction pointer overflow or out of bounds.
    #[error("invalid instruction pointer")]
    InvalidIP,
    /// Division or modulo by zero.
    #[error("division by zero")]
    DivisionByZero,
}

/// Runtime value stored in registers.
#[derive(Clone, Debug, Eq, PartialEq)]
enum Value {
    /// 64-bit signed integer.
    Int(i64),
}

/// Register file holding VM state.
///
/// Provides 256 registers, each capable of storing a single [`Value`].
/// Registers are lazily initialized (start as `None`).
struct Registers {
    regs: Vec<Option<Value>>,
}

impl Registers {
    /// Creates a new register file with `count` registers.
    pub fn new(count: usize) -> Self {
        Self {
            regs: vec![None; count],
        }
    }

    /// Returns a reference to the value in register `idx`.
    ///
    /// Returns [`VMError::StackUnderflow`] if the register is uninitialized.
    pub fn get(&self, idx: u8) -> Result<&Value, VMError> {
        self.regs
            .get(idx as usize)
            .and_then(|v| v.as_ref())
            .ok_or(VMError::StackUnderflow)
    }

    /// Returns the integer value in register `idx`.
    ///
    /// Returns [`VMError::StackUnderflow`] if uninitialized.
    pub fn get_int(&self, idx: u8, _instr: &'static str) -> Result<i64, VMError> {
        match self.get(idx)? {
            Value::Int(v) => Ok(*v),
            /*
            other => Err(VMError::TypeMismatch {
                instruction: instr,
                arg_index: idx as i32,
                expected: "Int",
                actual: other.type_name(),
            }),
             */
        }
    }

    /// Stores a value into register `idx`.
    ///
    /// Returns [`VMError::StackOverflow`] if `idx` is out of bounds.
    pub fn set(&mut self, idx: u8, v: Value) -> Result<(), VMError> {
        let slot = self
            .regs
            .get_mut(idx as usize)
            .ok_or(VMError::StackOverflow)?;
        *slot = Some(v);
        Ok(())
    }
}

/// Bytecode virtual machine.
///
/// Executes compiled bytecode sequentially, reading instructions from the
/// instruction pointer until the end of the bytecode is reached.
pub struct VM {
    /// Bytecode to execute.
    data: Bytes,
    /// Instruction pointer (current position in bytecode).
    ip: usize,
    /// Register file (256 registers).
    registers: Registers,
}

macro_rules! exec_vm {
    // Entry: list instructions and map to handler method names
    (
        vm = $vm:ident,
        instr = $instr:ident,
        {
            $(
                $variant:ident => $handler:ident ( $( $field:ident : $kind:ident ),* $(,)? )
            ),* $(,)?
        }
    ) => {{
        match $instr {
            $(
                Instruction::$variant => {
                    $( let $field = exec_vm!(@read $vm, $kind)?; )*
                    $vm.$handler( $( $field ),* )
                }
            ),*
        }
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
}

impl VM {
    /// Creates a new VM instance with the given bytecode.
    pub fn new(data: Bytes) -> Self {
        Self {
            data,
            ip: 0,
            registers: Registers::new(256),
        }
    }

    /// Executes the bytecode until completion or error.
    ///
    /// Runs instructions sequentially until the instruction pointer reaches
    /// the end of the bytecode buffer.
    pub fn run(&mut self) -> Result<(), VMError> {
        while self.ip < self.data.len() {
            let opcode = self.data[self.ip];
            self.ip += 1;
            let instr = Instruction::try_from(opcode)?;
            self.exec(instr)?;
        }
        Ok(())
    }

    /// Reads exactly `count` bytes from the bytecode at the current IP.
    ///
    /// Advances the instruction pointer by `count` bytes.
    fn read_exact(&mut self, count: usize) -> Result<&[u8], VMError> {
        let start = self.ip;
        let end = self.ip.checked_add(count).ok_or(VMError::InvalidIP)?;

        let slice = self.data.get(start..end).ok_or(VMError::StackOverflow)?;

        self.ip = end;
        Ok(slice)
    }

    /// Executes a single instruction.
    pub fn exec(&mut self, instruction: Instruction) -> Result<(), VMError> {
        exec_vm! {
            vm = self,
            instr = instruction,
            {
                LoadI64 => op_load_i64(rd: Reg, imm: ImmI64),
                Move => op_move(rd: Reg, rs: Reg),
                Add => op_add(rd: Reg, rs1: Reg, rs2: Reg),
                Sub => op_sub(rd: Reg, rs1: Reg, rs2: Reg),
                Mul => op_mul(rd: Reg, rs1: Reg, rs2: Reg),
                Div => op_div(rd: Reg, rs1: Reg, rs2: Reg),
                Mod => op_mod(rd: Reg, rs1: Reg, rs2: Reg),
                Neg => op_neg(rd: Reg, rs: Reg),
                Eq => op_eq(rd: Reg, rs1: Reg, rs2: Reg),
                Lt => op_lt(rd: Reg, rs1: Reg, rs2: Reg),
                Gt => op_gt(rd: Reg, rs1: Reg, rs2: Reg),
            }
        }
    }

    fn op_load_i64(&mut self, dst: u8, imm: i64) -> Result<(), VMError> {
        self.registers.set(dst, Value::Int(imm))
    }

    fn op_move(&mut self, dst: u8, src: u8) -> Result<(), VMError> {
        let v = self.registers.get_int(src, "MOVE")?;
        self.registers.set(dst, Value::Int(v))
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

    fn op_eq(&mut self, dst: u8, a: u8, b: u8) -> Result<(), VMError> {
        let va = self.registers.get_int(a, "EQ")?;
        let vb = self.registers.get_int(b, "EQ")?;
        self.registers
            .set(dst, Value::Int(if va == vb { 1 } else { 0 }))
    }

    fn op_lt(&mut self, dst: u8, a: u8, b: u8) -> Result<(), VMError> {
        let va = self.registers.get_int(a, "LT")?;
        let vb = self.registers.get_int(b, "LT")?;
        self.registers
            .set(dst, Value::Int(if va < vb { 1 } else { 0 }))
    }

    fn op_gt(&mut self, dst: u8, a: u8, b: u8) -> Result<(), VMError> {
        let va = self.registers.get_int(a, "GT")?;
        let vb = self.registers.get_int(b, "GT")?;
        self.registers
            .set(dst, Value::Int(if va > vb { 1 } else { 0 }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::virtual_machine::assembler::assemble_source;

    fn run_and_get(source: &str, reg: u8) -> i64 {
        let bytecode = assemble_source(source).expect("assembly failed");
        let mut vm = VM::new(Bytes::new(bytecode));
        vm.run().expect("vm run failed");
        vm.registers.get_int(reg, "").expect("register read failed")
    }

    fn run_expect_err(source: &str) -> VMError {
        let bytecode = assemble_source(source).expect("assembly failed");
        let mut vm = VM::new(Bytes::new(bytecode));
        vm.run().expect_err("expected error")
    }

    #[test]
    fn op_load_i64() {
        assert_eq!(run_and_get("LOAD_I64 r0, 42", 0), 42);
        assert_eq!(run_and_get("LOAD_I64 r0, -1", 0), -1);
        assert_eq!(run_and_get("LOAD_I64 r0, 0", 0), 0);
    }

    #[test]
    fn op_move() {
        let source = r#"
            LOAD_I64 r0, 99
            MOVE r1, r0
        "#;
        assert_eq!(run_and_get(source, 1), 99);
    }

    #[test]
    fn op_add() {
        let source = r#"
            LOAD_I64 r0, 10
            LOAD_I64 r1, 32
            ADD r2, r0, r1
        "#;
        assert_eq!(run_and_get(source, 2), 42);
    }

    #[test]
    fn op_add_wrapping() {
        let source = r#"
            LOAD_I64 r0, 9223372036854775807
            LOAD_I64 r1, 1
            ADD r2, r0, r1
        "#;
        assert_eq!(run_and_get(source, 2), i64::MIN);
    }

    #[test]
    fn op_sub() {
        let source = r#"
            LOAD_I64 r0, 50
            LOAD_I64 r1, 8
            SUB r2, r0, r1
        "#;
        assert_eq!(run_and_get(source, 2), 42);
    }

    #[test]
    fn op_mul() {
        let source = r#"
            LOAD_I64 r0, 6
            LOAD_I64 r1, 7
            MUL r2, r0, r1
        "#;
        assert_eq!(run_and_get(source, 2), 42);
    }

    #[test]
    fn op_div() {
        let source = r#"
            LOAD_I64 r0, 84
            LOAD_I64 r1, 2
            DIV r2, r0, r1
        "#;
        assert_eq!(run_and_get(source, 2), 42);
    }

    #[test]
    fn op_div_by_zero() {
        let source = r#"
            LOAD_I64 r0, 1
            LOAD_I64 r1, 0
            DIV r2, r0, r1
        "#;
        assert!(matches!(run_expect_err(source), VMError::DivisionByZero));
    }

    #[test]
    fn op_mod() {
        let source = r#"
            LOAD_I64 r0, 47
            LOAD_I64 r1, 5
            MOD r2, r0, r1
        "#;
        assert_eq!(run_and_get(source, 2), 2);
    }

    #[test]
    fn op_mod_by_zero() {
        let source = r#"
            LOAD_I64 r0, 1
            LOAD_I64 r1, 0
            MOD r2, r0, r1
        "#;
        assert!(matches!(run_expect_err(source), VMError::DivisionByZero));
    }

    #[test]
    fn op_neg() {
        let source = r#"
            LOAD_I64 r0, 42
            NEG r1, r0
        "#;
        assert_eq!(run_and_get(source, 1), -42);
    }

    #[test]
    fn op_eq_true() {
        let source = r#"
            LOAD_I64 r0, 5
            LOAD_I64 r1, 5
            EQ r2, r0, r1
        "#;
        assert_eq!(run_and_get(source, 2), 1);
    }

    #[test]
    fn op_eq_false() {
        let source = r#"
            LOAD_I64 r0, 5
            LOAD_I64 r1, 6
            EQ r2, r0, r1
        "#;
        assert_eq!(run_and_get(source, 2), 0);
    }

    #[test]
    fn op_lt_true() {
        let source = r#"
            LOAD_I64 r0, 3
            LOAD_I64 r1, 5
            LT r2, r0, r1
        "#;
        assert_eq!(run_and_get(source, 2), 1);
    }

    #[test]
    fn op_lt_false() {
        let source = r#"
            LOAD_I64 r0, 5
            LOAD_I64 r1, 3
            LT r2, r0, r1
        "#;
        assert_eq!(run_and_get(source, 2), 0);
    }

    #[test]
    fn op_gt_true() {
        let source = r#"
            LOAD_I64 r0, 10
            LOAD_I64 r1, 5
            GT r2, r0, r1
        "#;
        assert_eq!(run_and_get(source, 2), 1);
    }

    #[test]
    fn op_gt_false() {
        let source = r#"
            LOAD_I64 r0, 5
            LOAD_I64 r1, 10
            GT r2, r0, r1
        "#;
        assert_eq!(run_and_get(source, 2), 0);
    }

    #[test]
    fn read_uninitialized_register() {
        let source = "ADD r2, r0, r1";
        assert!(matches!(run_expect_err(source), VMError::StackUnderflow));
    }

    #[test]
    fn invalid_opcode() {
        let mut vm = VM::new(Bytes::new(vec![0xFF]));
        assert!(matches!(vm.run(), Err(VMError::InvalidInstruction(0xFF))));
    }

    #[test]
    fn truncated_bytecode() {
        let mut vm = VM::new(Bytes::new(vec![0x00, 0x00])); // LOAD_I64 needs 10 bytes
        assert!(matches!(vm.run(), Err(VMError::StackOverflow)));
    }
}
