use crate::virtual_machine::errors::VMError;

#[derive(Clone, Debug, PartialEq, Eq)]
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

/// Address operand for memory operations.
///
/// Can be either an immediate 32-bit address or a register containing the address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AddrOperand {
    /// Immediate 32-bit address value.
    U32(u32),
    /// Register index containing the address.
    Reg(u8),
}

impl AddrOperand {
    /// Returns the encoded byte size of this operand (tag byte + payload).
    pub const fn size(&self) -> usize {
        1 + match self {
            AddrOperand::Reg(_) => 1,
            AddrOperand::U32(_) => 4,
        }
    }

    /// Returns a human-readable type name for error messages.
    pub const fn to_string(&self) -> &'static str {
        match self {
            AddrOperand::Reg(_) => "Register",
            AddrOperand::U32(_) => "Integer",
        }
    }
}

#[repr(u8)]
#[derive(Debug)]
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn src_operand_size_reg() {
        assert_eq!(SrcOperand::Reg(0).size(), 2);
        assert_eq!(SrcOperand::Reg(255).size(), 2);
    }

    #[test]
    fn src_operand_size_bool() {
        assert_eq!(SrcOperand::Bool(true).size(), 2);
        assert_eq!(SrcOperand::Bool(false).size(), 2);
    }

    #[test]
    fn src_operand_size_i64() {
        assert_eq!(SrcOperand::I64(0).size(), 9);
        assert_eq!(SrcOperand::I64(i64::MAX).size(), 9);
        assert_eq!(SrcOperand::I64(i64::MIN).size(), 9);
    }

    #[test]
    fn src_operand_size_ref() {
        assert_eq!(SrcOperand::Ref(0).size(), 5);
        assert_eq!(SrcOperand::Ref(u32::MAX).size(), 5);
    }

    #[test]
    fn src_operand_to_string() {
        assert_eq!(SrcOperand::Reg(0).to_string(), "Register");
        assert_eq!(SrcOperand::Bool(true).to_string(), "Boolean");
        assert_eq!(SrcOperand::I64(42).to_string(), "Integer");
        assert_eq!(SrcOperand::Ref(100).to_string(), "Reference");
    }

    #[test]
    fn operand_tag_try_from_valid() {
        assert_eq!(OperandTag::try_from(0).unwrap() as u8, 0);
        assert_eq!(OperandTag::try_from(1).unwrap() as u8, 1);
        assert_eq!(OperandTag::try_from(2).unwrap() as u8, 2);
        assert_eq!(OperandTag::try_from(3).unwrap() as u8, 3);
    }

    #[test]
    fn operand_tag_try_from_invalid() {
        for tag in 4..=255u8 {
            let err = OperandTag::try_from(tag).unwrap_err();
            assert!(matches!(err, VMError::InvalidOperandTag { tag: t, .. } if t == tag));
        }
    }

    #[test]
    fn addr_operand_size() {
        assert_eq!(AddrOperand::Reg(0).size(), 2);
        assert_eq!(AddrOperand::Reg(255).size(), 2);
        assert_eq!(AddrOperand::U32(0).size(), 5);
        assert_eq!(AddrOperand::U32(u32::MAX).size(), 5);
    }

    #[test]
    fn addr_operand_to_string() {
        assert_eq!(AddrOperand::Reg(0).to_string(), "Register");
        assert_eq!(AddrOperand::U32(42).to_string(), "Integer");
    }
}
