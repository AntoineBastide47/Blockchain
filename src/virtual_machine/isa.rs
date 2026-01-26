//! Instruction Set Architecture (ISA) definitions.
//!
//! Defines the VM's instruction set. The [`for_each_instruction!`](crate::for_each_instruction) macro holds
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
            /// MOVE rd, rs ; rd = rs
            Move = 0x00, "MOVE" => [rd: Reg, rs: Src], 1,
            /// DELETE_STATE key ; deletes the value at key in storage
            DeleteState = 0x01, "DELETE_STATE" => [key: Src], 2000,
            /// STORE_I64 key, value ; store i64 value at key in storage
            StoreI64 = 0x02, "STORE_I64" => [key: Src, value: Src], 2000,
            /// LOAD_I64_STATE dst, key ; loads the i64 stored as key from storage
            LoadI64State = 0x03, "LOAD_I64_STATE" => [rd: Reg, key: Src], 50,
            /// STORE_BOOL key, value ; store bool value at key in storage
            StoreBool = 0x04, "STORE_BOOL" => [key: Src, value: Src], 2000,
            /// LOAD_BOOL_STATE dst, key ; loads the boolean stored as key from storage
            LoadBoolState = 0x05, "LOAD_BOOL_STATE" => [rd: Reg, key: Src], 50,
            /// STORE_STR key, value ; store string value at key in storage
            StoreStr = 0x06, "STORE_STR" => [key: Src, value: Src], 2000,
            /// LOAD_STR_STATE dst, key ; loads the string stored as key from storage
            LoadStrState = 0x07, "LOAD_STR_STATE" => [rd: Reg, key: Src], 50,
            /// STORE_HASH key, value ; store string value at key in storage
            StoreHash = 0x08, "STORE_HASH" => [key: Src, value: Src], 2000,
            /// LOAD_HASH_STATE dst, key ; loads the string stored as key from storage
            LoadHashState = 0x09, "LOAD_HASH_STATE" => [rd: Reg, key: Src], 50,
            // =========================
            // Casts
            // =========================
            /// I64_TO_BOOL rd, rs ; rd = (rs != 0)
            I64ToBool = 0x10, "I64_TO_BOOL" => [rd: Reg, rs: Src], 1,
            /// BOOL_TO_I64 rd, rs ; rd = rs as i64 (false=0, true=1)
            BoolToI64 = 0x11, "BOOL_TO_I64" => [rd: Reg, rs: Src], 1,
            /// STR_TO_I64 rd, rs ; rd = parse_i64(rs)
            StrToI64 = 0x12, "STR_TO_I64" => [rd: Reg, rs: Src], 30,
            /// I64_TO_STR rd, rs ; rd = rs formatted as string
            I64ToStr = 0x13, "I64_TO_STR" => [rd: Reg, rs: Src], 30,
            /// STR_TO_BOOL rd, rs ; rd = parse_bool(rs)
            StrToBool = 0x14, "STR_TO_BOOL" => [rd: Reg, rs: Src], 20,
            /// BOOL_TO_STR rd, rs ; rd = rs formatted as string
            BoolToStr = 0x15, "BOOL_TO_STR" => [rd: Reg, rs: Src], 20,
            // =========================
            // Integer arithmetic
            // =========================
            /// ADD rd, rs1, rs2 ; rd = rs1 + rs2
            Add = 0x20, "ADD" => [rd: Reg, rs1: Src, rs2: Src], 3,
            /// SUB rd, rs1, rs2 ; rd = rs1 - rs2
            Sub = 0x21, "SUB" => [rd: Reg, rs1: Src, rs2: Src], 3,
            /// MUL rd, rs1, rs2 ; rd = rs1 * rs2
            Mul = 0x22, "MUL" => [rd: Reg, rs1: Src, rs2: Src], 5,
            /// DIV rd, rs1, rs2 ; rd = rs1 / rs2 (trap on division by zero)
            Div = 0x23, "DIV" => [rd: Reg, rs1: Src, rs2: Src], 10,
            /// MOD rd, rs1, rs2 ; rd = rs1 % rs2
            Mod = 0x24, "MOD" => [rd: Reg, rs1: Src, rs2: Src], 10,
            /// NEG rd, rs ; rd = -rs
            Neg = 0x25, "NEG" => [rd: Reg, rs: Src], 2,
            /// ABS rd, rs ; rd = |rs|
            Abs = 0x26, "ABS" => [rd: Reg, rs: Src], 2,
            /// MIN rd, rs1, rs2 ; rd = min(rs1, rs2)
            Min = 0x27, "MIN" => [rd: Reg, rs1: Src, rs2: Src], 3,
            /// MAX rd, rs1, rs2 ; rd = max(rs1, rs2)
            Max = 0x28, "MAX" => [rd: Reg, rs1: Src, rs2: Src], 3,
            /// SHL rd, rs1, rs2 ; rd = rs1 << rs2
            Shl = 0x29, "SHL" => [rd: Reg, rs1: Src, rs2: Src], 3,
            /// SHR rd, rs1, rs2 ; rd = rs1 >> rs2 (arithmetic shift)
            Shr = 0x2A, "SHR" => [rd: Reg, rs1: Src, rs2: Src], 3,
            /// INC rd ; rd = rd++
            Inc = 0x2B, "INC" => [rd: Reg], 1,
            /// Dec rd ; rd = rd--
            Dec = 0x2C, "DEC" => [rd: Reg], 1,
            // =========================
            // Boolean / comparison
            // =========================
            /// NOT rd, rs ; rd = !rs (logical negation)
            Not = 0x30, "NOT" => [rd: Reg, rs: Src], 1,
            /// AND rd, rs1, rs2 ; rd = rs1 & rs2 (bitwise and)
            And = 0x31, "AND" => [rd: Reg, rs1: Src, rs2: Src], 2,
            /// OR rd, rs1, rs2 ; rd = rs1 | rs2 (bitwise or)
            Or = 0x32, "OR" => [rd: Reg, rs1: Src, rs2: Src], 2,
            /// XOR rd, rs1, rs2 ; rd = rs1 ^ rs2 (bitwise xor)
            Xor = 0x33, "XOR" => [rd: Reg, rs1: Src, rs2: Src], 2,
            /// EQ rd, rs1, rs2 ; rd = (rs1 == rs2)
            Eq = 0x34, "EQ" => [rd: Reg, rs1: Src, rs2: Src], 3,
            /// NE rd, rs1, rs2 ; rd = (rs1 != rs2)
            Ne = 0x35, "NE" => [rd: Reg, rs1: Src, rs2: Src], 3,
            /// LT rd, rs1, rs2 ; rd = (rs1 < rs2)
            Lt = 0x36, "LT" => [rd: Reg, rs1: Src, rs2: Src], 3,
            /// LE rd, rs1, rs2 ; rd = (rs1 <= rs2)
            Le = 0x37, "LE" => [rd: Reg, rs1: Src, rs2: Src], 3,
            /// GT rd, rs1, rs2 ; rd = (rs1 > rs2)
            Gt = 0x38, "GT" => [rd: Reg, rs1: Src, rs2: Src], 3,
            /// GE rd, rs1, rs2 ; rd = (rs1 >= rs2)
            Ge = 0x39, "GE" => [rd: Reg, rs1: Src, rs2: Src], 3,
            // =========================
            // Control Flow
            // =========================
            /// CALL_HOST dst, fn, argc, argv ; call host function fn with argc args from regs[argv...] ; return -> dst
            CallHost = 0x40, "CALL_HOST" => [dst: Reg, fn_id: RefU32, argc: ImmU8, argv: Reg], 100,
            /// CALL_HOST0 dst, fn ; call host function fn without any arguments ; return -> dst
            CallHost0 = 0x41, "CALL_HOST0" => [dst: Reg, fn_id: RefU32], 100,
            /// CALL_HOST1 dst, fn, arg ; call host function fn with a single argument ; return -> dst
            CallHost1 = 0x42, "CALL_HOST1" => [dst: Reg, fn_id: RefU32, arg: Src], 100,
            /// CALL dst, fn, argc, argv ; call function fn with argc args from regs[argv...] ; return -> dst
            Call = 0x43, "CALL" => [dst: Reg, fn_id: ImmI64, argc: ImmU8, argv: Reg], 50,
            /// CALL0 dst, fn ; call function fn without any arguments ; return -> dst
            Call0 = 0x44, "CALL0" => [dst: Reg, fn_id: ImmI64], 50,
            /// CALL1 dst, fn, arg ; call function fn with a single argument ; return -> dst
            Call1 = 0x45, "CALL1" => [dst: Reg, fn_id: ImmI64, arg: Reg], 50,
            /// JAL rd, offset ; rd = PC + instr_size; PC += offset (jump and link)
            Jal = 0x46, "JAL" => [rd: Reg, offset: ImmI64], 5,
            /// JALR rd, rs, offset ; rd = PC + instr_size; PC = rs + offset (jump and link register)
            Jalr = 0x47, "JALR" => [rd: Reg, rs: Reg, offset: ImmI64], 5,
            /// BEQ rs1, rs2, offset ; if rs1 == rs2 then PC += offset
            Beq = 0x48, "BEQ" => [rs1: Src, rs2: Src, offset: ImmI64], 5,
            /// BNE rs1, rs2, offset ; if rs1 != rs2 then PC += offset
            Bne = 0x49, "BNE" => [rs1: Src, rs2: Src, offset: ImmI64], 5,
            /// BLT rs1, rs2, offset ; if rs1 < rs2 (signed) then PC += offset
            Blt = 0x4A, "BLT" => [rs1: Src, rs2: Src, offset: ImmI64], 5,
            /// BGE rs1, rs2, offset ; if rs1 >= rs2 (signed) then PC += offset
            Bge = 0x4B, "BGE" => [rs1: Src, rs2: Src, offset: ImmI64], 5,
            /// BLTU rs1, rs2, offset ; if rs1 < rs2 (unsigned) then PC += offset
            Bltu = 0x4C, "BLTU" => [rs1: Src, rs2: Src, offset: ImmI64], 5,
            /// BGEU rs1, rs2, offset ; if rs1 >= rs2 (unsigned) then PC += offset
            Bgeu = 0x4D, "BGEU" => [rs1: Src, rs2: Src, offset: ImmI64], 5,
            /// JUMP offset ; PC += offset (unconditional jump)
            Jump = 0x4E, "JUMP" => [offset: ImmI64], 5,
            /// RET rs ; return from function call with value in rs
            Ret = 0x4F, "RET" => [rs: Reg], 5,
            /// HALT ; stop execution immediately
            Halt = 0x50, "HALT" => [], 1,
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
            ], $gas:expr
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
                    _ => Err(VMError::InvalidInstruction {
                        opcode: value,
                        offset: 0,
                    }),
                }
            }
        }

        impl Instruction {
            /// Returns the assembly mnemonic for this instruction.
            pub const fn mnemonic(&self) -> &'static str {
                match self {
                    $( Instruction::$name => $mnemonic, )*
                }
            }

            /// Returns the base gas cost for this instruction.
            pub const fn base_gas(&self) -> u64 {
                match self {
                    $( Instruction::$name => $gas, )*
                }
            }
        }
    };

    // ---------- types ----------
    (@ty Reg)    => { u8 };
    (@ty ImmU8)  => { u8 };
    (@ty RefU32) => { u32 };
    (@ty ImmI64) => { i64 };
    (@ty Src) => { SrcOperand };

    // ---------- encoding ----------
    (@emit $out:ident, Reg, $v:ident) => {
        $out.push(*$v);
    };

    (@emit $out:ident, ImmU8, $v:ident) => {
        $out.push(*$v);
    };

    (@emit $out:ident, ImmI64, $v:ident) => {
        $out.extend_from_slice(&$v.to_le_bytes());
    };

    (@emit $out:ident, RefU32, $v:ident) => {
        $out.extend_from_slice(&$v.to_le_bytes());
    };

    (@emit $out:ident, Src, $v:ident) => {
      match $v {
          SrcOperand::Reg(r) => {
              $out.push(0); // TAG_REG
              $out.push(*r);
          }
          SrcOperand::Bool(b) => {
              $out.push(1); // TAG_BOOL
              $out.push(if *b { 1 } else { 0 });
          }
          SrcOperand::I64(i) => {
              $out.push(2); // TAG_INT
              $out.extend_from_slice(&i.to_le_bytes());
          }
          SrcOperand::Ref(r) => {
              $out.push(3); // TAG_REF
              $out.extend_from_slice(&r.to_le_bytes());
          }
      }
    };
}

for_each_instruction!(define_instructions);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instruction_try_from_invalid() {
        assert!(matches!(
            Instruction::try_from(0xFF),
            Err(VMError::InvalidInstruction { opcode: 0xFF, .. })
        ));
    }
}
