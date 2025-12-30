//! Instruction Set Architecture (ISA) definitions.
//!
//! Defines the VM's instruction set using a declarative macro that generates:
//! - The [`Instruction`] enum with opcode mappings
//! - The [`AsmInstr`] intermediate representation for assembly
//! - Bytecode encoding/decoding logic
//!
//! # Instruction Format
//!
//! Instructions use variable-length encoding:
//! - Opcode: 1 byte
//! - Register operand: 1 byte (register index 0-255)
//! - Immediate i64: 8 bytes (little-endian)

use crate::virtual_machine::assembler::{parse_i64, parse_reg};
use crate::virtual_machine::vm::VMError;

/// Operand type specifier for instruction definitions.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Operand {
    /// Register operand (encoded as 1 byte).
    Reg,
    /// 64-bit signed immediate value (encoded as 8 bytes, little-endian).
    ImmI64,
}

macro_rules! define_instructions {
    (
        $(
            $(#[$doc:meta])*
            $name:ident = $opcode:expr, $mnemonic:literal => [
                $( $field:ident : $kind:ident ),* $(,)?
            ]
        ),* $(,)?
    ) => {
        // =========================
        // VM instruction enum
        // =========================
        #[derive(Copy, Clone, Debug, Eq, PartialEq)]
        pub enum Instruction {
            $(
                $(#[$doc])*
                $name = $opcode,
            )*
        }

        impl Instruction {
            pub fn type_name(&self) -> &'static str {
                match self {
                    $( Instruction::$name => $mnemonic, )*
                }
            }

            pub fn from_str(name: &str) -> Result<Self, VMError> {
                match name {
                    $( $mnemonic => Ok(Instruction::$name), )*
                    _ => Err(VMError::InvalidInstructionName(name.to_string())),
                }
            }

            /// Parse one instruction from tokens into `AsmInstr`
            pub fn parse(tokens: Vec<String>) -> Result<AsmInstr, VMError> {
                if tokens.is_empty() {
                    return Err(VMError::ArityMismatch);
                }

                let instr = Instruction::from_str(&tokens[0])?;

                match instr {
                    $(
                        Instruction::$name => {
                            const EXPECTED: usize = 1 + define_instructions!(@count $( $field ),*);
                            if tokens.len() != EXPECTED {
                                return Err(VMError::ArityMismatch);
                            }

                            let mut it = tokens.iter().skip(1);
                            Ok(AsmInstr::$name {
                                $(
                                    $field: define_instructions!(@parse_operand $kind, it.next().unwrap())?,
                                )*
                            })
                        }
                    ),*
                }
            }
        }

        impl TryFrom<u8> for Instruction {
            type Error = VMError;

            fn try_from(value: u8) -> Result<Self, Self::Error> {
                match value {
                    $( $opcode => Ok(Instruction::$name), )*
                    _ => Err(VMError::InvalidInstruction(value)),
                }
            }
        }

        // =========================
        // Assembler IR
        // =========================
        #[derive(Debug, Clone)]
        pub enum AsmInstr {
            $(
                $name {
                    $( $field: define_instructions!(@ty $kind) ),*
                },
            )*
        }

        // =========================
        // Bytecode encoder
        // =========================
        impl AsmInstr {
            pub fn assemble(&self, out: &mut Vec<u8>) {
                match self {
                    $(
                        AsmInstr::$name { $( $field ),* } => {
                            out.push($opcode);
                            $(
                                define_instructions!(@emit out, $kind, $field);
                            )*
                        }
                    ),*
                }
            }
        }
    };

    // ---------- helpers ----------
    (@ty Reg)    => { u8 };
    (@ty ImmI64) => { i64 };

    (@emit $out:ident, Reg, $v:ident) => {
        $out.push(*$v);
    };

    (@emit $out:ident, ImmI64, $v:ident) => {
        $out.extend_from_slice(&$v.to_le_bytes());
    };

    (@count $( $x:ident ),* ) => {
        <[()]>::len(&[ $( define_instructions!(@unit $x) ),* ])
    };

    (@unit $x:ident) => { () };

    (@parse_operand Reg, $tok:expr) => {
        parse_reg($tok)
    };

    (@parse_operand ImmI64, $tok:expr) => {
        parse_i64($tok)
    };
}

define_instructions! {
    /// LOAD_I64 rd, imm64 ; rd = imm64
    LoadI64 = 0x00, "LOAD_I64" => [rd: Reg, imm: ImmI64],
    /// MOVE rd, rs ; rd = rs
    Move = 0x01, "MOVE" => [rd: Reg, rs: Reg],
    /// ADD rd, rs1, rs2 ; rd = rs1 + rs2
    Add = 0x02, "ADD" => [rd: Reg, rs1: Reg, rs2: Reg],
    /// SUB rd, rs1, rs2 ; rd = rs1 - rs2
    Sub = 0x03, "SUB" => [rd: Reg, rs1: Reg, rs2: Reg],
    /// MUL rd, rs1, rs2 ; rd = rs1 * rs2
    Mul = 0x04, "MUL" => [rd: Reg, rs1: Reg, rs2: Reg],
    /// DIV rd, rs1, rs2 ; rd = rs1 / rs2 (trap on division by zero)
    Div = 0x05, "DIV" => [rd: Reg, rs1: Reg, rs2: Reg],
    /// MOD rd, rs1, rs2 ; rd = rs1 % rs2
    Mod = 0x06, "MOD" => [rd: Reg, rs1: Reg, rs2: Reg],
    /// NEG rd, rs ; rd = -rs
    Neg = 0x07, "NEG" => [rd: Reg, rs: Reg],
    /// EQ rd, rs1, rs2 ; rd = (rs1 == rs2)
    Eq = 0x08, "EQ" => [rd: Reg, rs1: Reg, rs2: Reg],
    /// LT rd, rs1, rs2 ; rd = (rs1 < rs2)
    Lt = 0x09, "LT" => [rd: Reg, rs1: Reg, rs2: Reg],
    /// GT rd, rs1, rs2 ; rd = (rs1 > rs2)
    Gt = 0x0A, "GT" => [rd: Reg, rs1: Reg, rs2: Reg],
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instruction_type_name() {
        assert_eq!(Instruction::LoadI64.type_name(), "LOAD_I64");
        assert_eq!(Instruction::Add.type_name(), "ADD");
        assert_eq!(Instruction::Gt.type_name(), "GT");
    }

    #[test]
    fn instruction_from_str_valid() {
        assert_eq!(
            Instruction::from_str("LOAD_I64").unwrap(),
            Instruction::LoadI64
        );
        assert_eq!(Instruction::from_str("ADD").unwrap(), Instruction::Add);
        assert_eq!(Instruction::from_str("DIV").unwrap(), Instruction::Div);
    }

    #[test]
    fn instruction_from_str_invalid() {
        assert!(matches!(
            Instruction::from_str("INVALID"),
            Err(VMError::InvalidInstructionName(_))
        ));
        assert!(matches!(
            Instruction::from_str("add"), // case sensitive
            Err(VMError::InvalidInstructionName(_))
        ));
    }

    #[test]
    fn instruction_try_from_valid() {
        assert_eq!(Instruction::try_from(0x00).unwrap(), Instruction::LoadI64);
        assert_eq!(Instruction::try_from(0x02).unwrap(), Instruction::Add);
        assert_eq!(Instruction::try_from(0x0A).unwrap(), Instruction::Gt);
    }

    #[test]
    fn instruction_try_from_invalid() {
        assert!(matches!(
            Instruction::try_from(0xFF),
            Err(VMError::InvalidInstruction(0xFF))
        ));
    }

    #[test]
    fn instruction_parse_empty() {
        assert!(matches!(
            Instruction::parse(vec![]),
            Err(VMError::ArityMismatch)
        ));
    }

    #[test]
    fn instruction_parse_load_i64() {
        let tokens = vec!["LOAD_I64".into(), "r5".into(), "100".into()];
        let instr = Instruction::parse(tokens).unwrap();
        match instr {
            AsmInstr::LoadI64 { rd, imm } => {
                assert_eq!(rd, 5);
                assert_eq!(imm, 100);
            }
            _ => panic!("wrong instruction type"),
        }
    }

    #[test]
    fn instruction_parse_three_reg() {
        let tokens = vec!["ADD".into(), "r0".into(), "r1".into(), "r2".into()];
        let instr = Instruction::parse(tokens).unwrap();
        match instr {
            AsmInstr::Add { rd, rs1, rs2 } => {
                assert_eq!(rd, 0);
                assert_eq!(rs1, 1);
                assert_eq!(rs2, 2);
            }
            _ => panic!("wrong instruction type"),
        }
    }

    #[test]
    fn asm_instr_assemble_load_i64() {
        let instr = AsmInstr::LoadI64 { rd: 3, imm: -1 };
        let mut out = Vec::new();
        instr.assemble(&mut out);
        assert_eq!(out[0], 0x00);
        assert_eq!(out[1], 3);
        assert_eq!(i64::from_le_bytes(out[2..10].try_into().unwrap()), -1);
    }

    #[test]
    fn asm_instr_assemble_three_reg() {
        let instr = AsmInstr::Sub {
            rd: 10,
            rs1: 20,
            rs2: 30,
        };
        let mut out = Vec::new();
        instr.assemble(&mut out);
        assert_eq!(out, vec![0x03, 10, 20, 30]);
    }

    #[test]
    fn asm_instr_assemble_two_reg() {
        let instr = AsmInstr::Neg { rd: 1, rs: 2 };
        let mut out = Vec::new();
        instr.assemble(&mut out);
        assert_eq!(out, vec![0x07, 1, 2]);
    }
}
