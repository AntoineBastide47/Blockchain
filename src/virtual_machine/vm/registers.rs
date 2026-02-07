use crate::virtual_machine::errors::VMError;
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
pub(super) struct Registers {
    regs: Vec<Value>,
}

impl Registers {
    /// Creates a new register file with `count` registers.
    pub(super) fn new() -> Self {
        Self {
            regs: vec![Value::Int(0); 256],
        }
    }

    /// Returns a reference to the value in register `idx`.
    ///
    /// Returns [`VMError::InvalidRegisterIndex`] if `idx` is out of bounds.
    pub(super) fn get(&self, idx: u8) -> Result<&Value, VMError> {
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
    pub(super) fn get_bool(&self, idx: u8, instr: &'static str) -> Result<bool, VMError> {
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
    pub(super) fn get_ref(&self, idx: u8, instr: &'static str) -> Result<u32, VMError> {
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
    pub(super) fn get_int(&self, idx: u8, instr: &'static str) -> Result<i64, VMError> {
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
    pub(super) fn set(&mut self, idx: u8, v: Value) -> Result<(), VMError> {
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
