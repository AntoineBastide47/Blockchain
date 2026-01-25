use crate::virtual_machine::errors::VMError;

#[derive(Clone, Debug, PartialEq)]
pub enum SrcOperand {
    Reg(u8),
    Bool(bool),
    I64(i64),
    Ref(u32),
}

impl SrcOperand {
    pub const fn size(&self) -> usize {
        1 + match self {
            SrcOperand::Reg(_) => 1,
            SrcOperand::Bool(_) => 1,
            SrcOperand::I64(_) => 8,
            SrcOperand::Ref(_) => 4,
        }
    }

    pub const fn to_string(&self) -> &'static str {
        match self {
            SrcOperand::Reg(_) => "Register",
            SrcOperand::Bool(_) => "Boolean",
            SrcOperand::I64(_) => "Integer",
            SrcOperand::Ref(_) => "Reference",
        }
    }
}

#[repr(u8)]
pub enum OperandTag {
    Register = 0,
    Boolean = 1,
    I64 = 2,
    Ref = 3,
}

impl TryFrom<u8> for OperandTag {
    type Error = VMError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Register),
            1 => Ok(Self::Boolean),
            2 => Ok(Self::I64),
            3 => Ok(Self::Ref),
            _ => Err(VMError::InvalidOperandTag {
                tag: value,
                offset: 0,
            }),
        }
    }
}
