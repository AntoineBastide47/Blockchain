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
//! - Reference u32: 4 bytes (little-endian, index into string pool)
//! - Boolean: 1 byte (0 = false, nonzero = true)

use crate::virtual_machine::assembler::{
    AsmContext, parse_bool, parse_i64, parse_ref_u32, parse_reg,
};
use crate::virtual_machine::vm::VMError;

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
            pub fn from_str(name: &str) -> Result<Self, VMError> {
                match name {
                    $( $mnemonic => Ok(Instruction::$name), )*
                    _ => Err(VMError::InvalidInstructionName(name.to_string())),
                }
            }

            /// Parse one instruction from tokens into `AsmInstr`
            pub fn parse(ctx: &mut AsmContext, tokens: &[String]) -> Result<AsmInstr, VMError> {
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
                                    $field: define_instructions!(
                                        @parse_operand $kind, it.next().unwrap(), ctx
                                    )?,
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

    // ---------- types ----------
    (@ty Reg)    => { u8 };
    (@ty ImmI64) => { i64 };
    (@ty RefU32) => { u32 };
    (@ty Bool)   => { bool };

    // ---------- encoding ----------
    (@emit $out:ident, Reg, $v:ident) => {
        $out.push(*$v);
    };

    (@emit $out:ident, ImmI64, $v:ident) => {
        $out.extend_from_slice(&$v.to_le_bytes());
    };

    (@emit $out:ident, RefU32, $v:ident) => {
        $out.extend_from_slice(&$v.to_le_bytes());
    };

    (@emit $out:ident, Bool, $v:ident) => {
        $out.push(if *$v { 1 } else { 0 });
    };

    // ---------- counting ----------
    (@count $( $x:ident ),* ) => {
        <[()]>::len(&[ $( define_instructions!(@unit $x) ),* ])
    };

    (@unit $x:ident) => { () };

    // ---------- parsing ----------
    (@parse_operand Reg, $tok:expr, $ctx:expr) => {
        parse_reg($tok)
    };

    (@parse_operand ImmI64, $tok:expr, $ctx:expr) => {
        parse_i64($tok)
    };

    (@parse_operand RefU32, $tok:expr, $ctx:expr) => {{
        if let Some(s) = $tok.strip_prefix('"').and_then(|t| t.strip_suffix('"')) {
            Ok($ctx.intern_string(s.to_string()))
        } else {
            parse_ref_u32($tok)
        }
    }};


    (@parse_operand Bool, $tok:expr, $ctx:expr) => {
        parse_bool($tok)
    };
}

define_instructions! {
    // =========================
    // Loads / constants
    // =========================
    /// LOAD_I64 rd, imm64 ; rd = imm64
    LoadI64 = 0x00, "LOAD_I64" => [rd: Reg, imm: ImmI64],
    /// LOAD_STR rd, ref ; rd = ref
    LoadStr = 0x01, "LOAD_STR" => [rd: Reg, str: RefU32],
    /// LOAD_BOOL rd, true|false ; rd = true|false
    LoadBool = 0x02, "LOAD_BOOL" => [rd: Reg, bool: Bool],
    // =========================
    // Moves / casts
    // =========================
    /// MOVE rd, rs ; rd = rs
    Move = 0x10, "MOVE" => [rd: Reg, rs: Reg],
    /// I64_TO_BOOL rd, rs ; rd = (rs != 0)
    I64ToBool = 0x11, "I64_TO_BOOL" => [rd: Reg, rs: Reg],
    /// BOOL_TO_I64 rd, rs ; rd = rs as i64 (false=0, true=1)
    BoolToI64 = 0x12, "BOOL_TO_I64" => [rd: Reg, rs: Reg],
    // =========================
    // Integer arithmetic
    // =========================
    /// ADD rd, rs1, rs2 ; rd = rs1 + rs2
    Add = 0x20, "ADD" => [rd: Reg, rs1: Reg, rs2: Reg],
    /// SUB rd, rs1, rs2 ; rd = rs1 - rs2
    Sub = 0x21, "SUB" => [rd: Reg, rs1: Reg, rs2: Reg],
    /// MUL rd, rs1, rs2 ; rd = rs1 * rs2
    Mul = 0x22, "MUL" => [rd: Reg, rs1: Reg, rs2: Reg],
    /// DIV rd, rs1, rs2 ; rd = rs1 / rs2 (trap on division by zero)
    Div = 0x23, "DIV" => [rd: Reg, rs1: Reg, rs2: Reg],
    /// MOD rd, rs1, rs2 ; rd = rs1 % rs2
    Mod = 0x24, "MOD" => [rd: Reg, rs1: Reg, rs2: Reg],
    /// NEG rd, rs ; rd = -rs
    Neg = 0x25, "NEG" => [rd: Reg, rs: Reg],
    /// ABS rd, rs ; rd = |rs|
    Abs = 0x26, "ABS" => [rd: Reg, rs: Reg],
    /// MIN rd, rs1, rs2 ; rd = min(rs1, rs2)
    Min = 0x27, "MIN" => [rd: Reg, rs1: Reg, rs2: Reg],
    /// MAX rd, rs1, rs2 ; rd = max(rs1, rs2)
    Max = 0x28, "MAX" => [rd: Reg, rs1: Reg, rs2: Reg],
    /// SHL rd, rs1, rs2 ; rd = rs1 << rs2
    Shl = 0x29, "SHL" => [rd: Reg, rs1: Reg, rs2: Reg],
    /// SHR rd, rs1, rs2 ; rd = rs1 >> rs2 (arithmetic shift)
    Shr = 0x2A, "SHR" => [rd: Reg, rs1: Reg, rs2: Reg],
    // =========================
    // Boolean / comparison
    // =========================
    /// NOT rd, rs ; rd = !rs (logical negation)
    Not = 0x30, "NOT" => [rd: Reg, rs: Reg],
    /// AND rd, rs1, rs2 ; rd = rs1 & rs2 (bitwise and)
    And = 0x31, "AND" => [rd: Reg, rs1: Reg, rs2: Reg],
    /// OR rd, rs1, rs2 ; rd = rs1 | rs2 (bitwise or)
    Or = 0x32, "OR" => [rd: Reg, rs1: Reg, rs2: Reg],
    /// XOR rd, rs1, rs2 ; rd = rs1 ^ rs2 (bitwise xor)
    Xor = 0x33, "XOR" => [rd: Reg, rs1: Reg, rs2: Reg],
    /// EQ rd, rs1, rs2 ; rd = (rs1 == rs2)
    Eq = 0x34, "EQ" => [rd: Reg, rs1: Reg, rs2: Reg],
    /// LT rd, rs1, rs2 ; rd = (rs1 < rs2)
    Lt = 0x35, "LT" => [rd: Reg, rs1: Reg, rs2: Reg],
    /// LE rd, rs1, rs2 ; rd = (rs1 <= rs2)
    Le = 0x37, "LE" => [rd: Reg, rs1: Reg, rs2: Reg],
    /// GT rd, rs1, rs2 ; rd = (rs1 > rs2)
    Gt = 0x38, "GT" => [rd: Reg, rs1: Reg, rs2: Reg],
    /// GE rd, rs1, rs2 ; rd = (rs1 >= rs2)
    Ge = 0x39, "GE" => [rd: Reg, rs1: Reg, rs2: Reg],
    // =========================
    // Control Flow
    // =========================
    /// CALL dst, fn, argc, argv ; call function fn with argc args from regs[argv..] ; return -> dst
    CallHost = 0x40, "CALL_HOST" => [dst: Reg, fn_id: RefU32, argc: ImmI64, argv: Reg],
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(Instruction::try_from(0x20).unwrap(), Instruction::Add);
        assert_eq!(Instruction::try_from(0x38).unwrap(), Instruction::Gt);
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
            Instruction::parse(&mut AsmContext::new(), &[]),
            Err(VMError::ArityMismatch)
        ));
    }

    #[test]
    fn instruction_parse_load_i64() {
        let tokens = vec!["LOAD_I64".into(), "r5".into(), "100".into()];
        let instr = Instruction::parse(&mut AsmContext::new(), &tokens).unwrap();
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
        let instr = Instruction::parse(&mut AsmContext::new(), &tokens).unwrap();
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
        assert_eq!(out, vec![0x21, 10, 20, 30]);
    }

    #[test]
    fn asm_instr_assemble_two_reg() {
        let instr = AsmInstr::Neg { rd: 1, rs: 2 };
        let mut out = Vec::new();
        instr.assemble(&mut out);
        assert_eq!(out, vec![0x25, 1, 2]);
    }

    #[test]
    fn asm_instr_assemble_bool() {
        let instr = AsmInstr::LoadBool { rd: 0, bool: true };
        let mut out = Vec::new();
        instr.assemble(&mut out);
        assert_eq!(out, vec![0x02, 0, 1]);
    }

    #[test]
    fn asm_instr_assemble_ref() {
        let instr = AsmInstr::LoadStr { rd: 1, str: 0x1234 };
        let mut out = Vec::new();
        instr.assemble(&mut out);
        assert_eq!(out[0], 0x01);
        assert_eq!(out[1], 1);
        assert_eq!(u32::from_le_bytes(out[2..6].try_into().unwrap()), 0x1234);
    }
}
