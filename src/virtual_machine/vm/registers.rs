use crate::virtual_machine::errors::VMError;
use crate::virtual_machine::isa::Instruction;
use blockchain_derive::BinaryCodec;

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

    /// Returns `true` when two values of the same type are equal.
    ///
    /// Returns [`VMError::InvalidComparison`] if the types differ.
    pub fn equals(va: Value, vb: Value) -> Result<bool, VMError> {
        Ok(match (va, vb) {
            (Value::Bool(b1), Value::Bool(b2)) => b1 == b2,
            (Value::Ref(r1), Value::Ref(r2)) => r1 == r2,
            (Value::Int(i1), Value::Int(i2)) => i1 == i2,
            (Value::Bool(b), Value::Int(i)) | (Value::Int(i), Value::Bool(b)) => b as i64 == i,
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
/// Provides 256 registers, each capable of storing a single [`Value`], except
/// `r0` which is hardwired to integer zero.
pub(super) struct Registers {
    regs: Vec<Value>,
}

impl Registers {
    /// Index of the hardwired zero register.
    const ZERO_REG: u8 = 0;

    /// Creates a new register file with `count` registers.
    pub(super) fn new() -> Self {
        Self {
            regs: vec![Value::Int(0); 256],
        }
    }

    /// Returns a reference to the value in register `idx`.
    ///
    /// Returns [`VMError::InvalidRegisterIndex`] if `idx` is out of bounds.
    pub(super) fn get(&self, idx: u8) -> &Value {
        // Unsafe can be used here for performance since we can't get an out of index
        // read due to having u8::MAX registers and indexing with a u8
        unsafe { self.regs.get_unchecked(idx as usize) }
    }

    /// Returns the boolean value in register `idx`.
    ///
    /// Returns [`VMError::TypeMismatch`] if the value is not a boolean.
    pub(super) fn get_bool(&self, idx: u8, instr: Instruction) -> Result<bool, VMError> {
        match self.get(idx) {
            Value::Bool(v) => Ok(*v),
            other => Err(VMError::TypeMismatchStatic {
                instruction: instr.mnemonic(),
                arg_index: idx as i32,
                expected: "Bool",
                actual: other.type_name(),
            }),
        }
    }

    /// Returns the reference value in register `idx`.
    ///
    /// Returns [`VMError::TypeMismatch`] if the value is not a reference.
    pub(super) fn get_ref(&self, idx: u8, instr: Instruction) -> Result<u32, VMError> {
        match self.get(idx) {
            Value::Ref(v) => Ok(*v),
            other => Err(VMError::TypeMismatchStatic {
                instruction: instr.mnemonic(),
                arg_index: idx as i32,
                expected: "Ref",
                actual: other.type_name(),
            }),
        }
    }

    /// Returns the integer value in register `idx`.
    ///
    /// Returns [`VMError::TypeMismatch`] if the value is not an integer.
    pub(super) fn get_int(&self, idx: u8, instr: Instruction) -> Result<i64, VMError> {
        match self.get(idx) {
            Value::Int(v) => Ok(*v),
            other => Err(VMError::TypeMismatchStatic {
                instruction: instr.mnemonic(),
                arg_index: idx as i32,
                expected: "Int",
                actual: other.type_name(),
            }),
        }
    }

    /// Stores a value into register `idx`.
    ///
    /// Returns [`VMError::InvalidRegisterIndex`] if `idx` is out of bounds.
    pub(super) fn set(&mut self, idx: u8, v: Value) {
        if idx == Self::ZERO_REG {
            // r0 is hardwired to integer zero; writes are discarded.
            return;
        }
        // Unsafe can be used here for performance since we can't get an out of index
        // write due to having u8::MAX registers and indexing with a u8
        unsafe {
            let slot = self.regs.get_unchecked_mut(idx as usize);
            *slot = v;
        }
    }
}
