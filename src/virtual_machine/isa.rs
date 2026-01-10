//! Instruction Set Architecture (ISA) definitions.
//!
//! Defines the VM's instruction set. The [`for_each_instruction!`] macro holds
//! the canonical instruction definitions and invokes a callback macro for code
//! generation. This enables multiple modules to generate instruction-related
//! code without duplicating definitions.
//!
//! This module generates:
//! - The [`Instruction`] enum with opcode mappings
//! - `TryFrom<u8>` for decoding opcodes
//!
//! See [`assembler`](super::assembler) for assembly-related code generation
//! (`AsmInstr`, parsing, bytecode encoding).
//!
//! # Bytecode Format
//!
//! Instructions use variable-length encoding:
//! - Opcode: 1 byte
//! - Register operand: 1 byte (register index 0-255)
//! - Immediate i64: 8 bytes (little-endian)
//! - Reference u32: 4 bytes (little-endian, index into string pool)
//! - Boolean: 1 byte (0 = false, nonzero = true)

use crate::virtual_machine::errors::VMError;

/// Invokes a callback macro with the complete instruction definition list.
///
/// This macro enables code generation for instructions in multiple modules
/// without duplicating the instruction definitions.
#[macro_export]
macro_rules! for_each_instruction {
    ($callback:ident) => {
        $callback! {
            // =========================
            // Store and Load
            // =========================
            /// DELETE_STATE key ; delete's the value at key in storage
            DeleteState = 0x00, "DELETE_STATE" => [key: Reg],
            /// LOAD_I64 rd, imm64 ; rd = imm64
            LoadI64 = 0x01, "LOAD_I64" => [rd: Reg, imm: ImmI64],
            /// STORE_I64 key, value ; store i64 value at key in storage
            StoreI64 = 0x02, "STORE_I64" => [key: Reg, value: Reg],
            /// LOAD_I64_STATE dst, key ; loads the i64 stored as key from storage
            LoadI64State = 0x03, "LOAD_I64_STATE" => [rd: Reg, key: Reg],
            /// LOAD_BOOL rd, true|false ; rd = true|false
            LoadBool = 0x04, "LOAD_BOOL" => [rd: Reg, bool: Bool],
            /// STORE_BOOL key, value ; store bool value at key in storage
            StoreBool = 0x05, "STORE_BOOL" => [key: Reg, value: Reg],
            /// LOAD_BOOL_STATE dst, key ; loads the boolean stored as key from storage
            LoadBoolState = 0x06, "LOAD_BOOL_STATE" => [rd: Reg, key: Reg],
            /// LOAD_STR rd, ref ; rd = ref
            LoadStr = 0x07, "LOAD_STR" => [rd: Reg, str: RefU32],
            /// STORE_STR key, value ; store string value at key in storage
            StoreStr = 0x08, "STORE_STR" => [key: Reg, value: Reg],
            /// LOAD_STR_STATE dst, key ; loads the string stored as key from storage
            LoadStrState = 0x09, "LOAD_STR_STATE" => [rd: Reg, key: Reg],
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
            /// CALL_HOST dst, fn, argc, argv ; call host function fn with argc args from regs[argv..] ; return -> dst
            CallHost = 0x40, "CALL_HOST" => [dst: Reg, fn_id: RefU32, argc: ImmI64, argv: Reg],
            /// CALL dst, fn, argc, argv ; call function fn with argc args from regs[argv..] ; return -> dst
            Call = 0x41, "CALL" => [dst: Reg, fn_id: RefU32, argc: ImmI64, argv: Reg],
            /// JAL rd, offset ; rd = PC + instr_size; PC += offset (jump and link)
            Jal = 0x42, "JAL" => [rd: Reg, offset: ImmI64],
            /// JALR rd, rs, offset ; rd = PC + instr_size; PC = rs + offset (jump and link register)
            Jalr = 0x43, "JALR" => [rd: Reg, rs: Reg, offset: ImmI64],
            /// BEQ rs1, rs2, offset ; if rs1 == rs2 then PC += offset
            Beq = 0x44, "BEQ" => [rs1: Reg, rs2: Reg, offset: ImmI64],
            /// BNE rs1, rs2, offset ; if rs1 != rs2 then PC += offset
            Bne = 0x45, "BNE" => [rs1: Reg, rs2: Reg, offset: ImmI64],
            /// BLT rs1, rs2, offset ; if rs1 < rs2 (signed) then PC += offset
            Blt = 0x46, "BLT" => [rs1: Reg, rs2: Reg, offset: ImmI64],
            /// BGE rs1, rs2, offset ; if rs1 >= rs2 (signed) then PC += offset
            Bge = 0x47, "BGE" => [rs1: Reg, rs2: Reg, offset: ImmI64],
            /// BLTU rs1, rs2, offset ; if rs1 < rs2 (unsigned) then PC += offset
            Bltu = 0x48, "BLTU" => [rs1: Reg, rs2: Reg, offset: ImmI64],
            /// BGEU rs1, rs2, offset ; if rs1 >= rs2 (unsigned) then PC += offset
            Bgeu = 0x49, "BGEU" => [rs1: Reg, rs2: Reg, offset: ImmI64],
            /// RET rs ; return from function call with value in rs
            Ret = 0x4A, "RET" => [rs: Reg],
        }
    };
}

#[macro_export]
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

        impl TryFrom<u8> for Instruction {
            type Error = VMError;

            fn try_from(value: u8) -> Result<Self, Self::Error> {
                match value {
                    $( $opcode => Ok(Instruction::$name), )*
                    _ => Err(VMError::InvalidInstruction(value)),
                }
            }
        }
    };

    // ---------- types ----------
    (@ty Reg)    => { u8 };
    (@ty Bool)   => { bool };
    (@ty RefU32) => { u32 };
    (@ty ImmI64) => { i64 };

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
}

for_each_instruction!(define_instructions);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instruction_try_from_valid() {
        assert_eq!(
            Instruction::try_from(0x00).unwrap(),
            Instruction::DeleteState
        );
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
}
