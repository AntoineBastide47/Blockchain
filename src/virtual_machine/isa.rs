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

/// High bit in opcode byte indicating that one metadata byte follows.
pub const OPCODE_METADATA_FLAG: u8 = 0b1000_0000;
/// Mask extracting the 7-bit base opcode from `0xZ[ooooooo]`.
pub const OPCODE_BASE_MASK: u8 = 0b0111_1111;

/// Invokes a callback macro with the complete instruction definition list.
///
/// This macro enables code generation for instructions in multiple modules
/// without duplicating the instruction definitions.
#[macro_export]
macro_rules! for_each_instruction {
    ($callback:ident) => {
        $callback! {
            // =========================
            // Move, Casts and Misc
            // =========================
            /// NOOP ;
            Noop = 0x00, "NOOP" => [], 1,
            /// MOVE rd, rs ; rd = rs
            Move = 0x01, "MOVE" => [rd: Reg, rs: Src], 1,
            /// CMOVE rd, cond, r1, r2 ; rd = (cond != 0) ? r1 : r2
            CMove = 0x02, "CMOVE" => [rd: Reg, cond: Reg, r1: Src, r2: Src], 5,
            /// I64_TO_BOOL rd, rs ; rd = (rs != 0)
            I64ToBool = 0x03, "I64_TO_BOOL" => [rd: Reg, rs: Src], 1,
            /// BOOL_TO_I64 rd, rs ; rd = rs as i64 (false=0, true=1)
            BoolToI64 = 0x04, "BOOL_TO_I64" => [rd: Reg, rs: Src], 1,
            /// STR_TO_I64 rd, rs ; rd = parse_i64(rs)
            StrToI64 = 0x05, "STR_TO_I64" => [rd: Reg, rs: Src], 30,
            /// I64_TO_STR rd, rs ; rd = rs formatted as string
            I64ToStr = 0x06, "I64_TO_STR" => [rd: Reg, rs: Src], 30,
            /// STR_TO_BOOL rd, rs ; rd = parse_bool(rs)
            StrToBool = 0x07, "STR_TO_BOOL" => [rd: Reg, rs: Src], 20,
            /// BOOL_TO_STR rd, rs ; rd = rs formatted as string
            BoolToStr = 0x08, "BOOL_TO_STR" => [rd: Reg, rs: Src], 20,
            // =========================
            // Store and Load
            // =========================
            /// DELETE_STATE key ; deletes the value at key in storage
            DeleteState = 0x10, "DELETE_STATE" => [key: Src], 2000,
            /// HAS_STATE rd, key ; sets rd to true if the state has the key src, to false if not
            HasState = 0x11, "HAS_STATE" => [rd: Reg, key: Src], 50,
            /// STORE key, value ; store the bytes in rs at key in storage
            StoreBytes = 0x12, "STORE" => [key: Src, rs: Src], 2000,
            /// LOAD dst, key ; loads the bytes stored at key from storage
            LoadBytes = 0x13, "LOAD" => [rd: Reg, key: Src], 50,
            /// LOAD_I64 dst, key ; loads the i64 stored at key from storage
            LoadI64 = 0x14, "LOAD_I64" => [rd: Reg, key: Src], 50,
            /// LOAD_BOOL dst, key ; loads the boolean stored at key from storage
            LoadBool = 0x15, "LOAD_BOOL" => [rd: Reg, key: Src], 50,
            /// LOAD_STR dst, key ; loads the string stored at key from storage
            LoadStr = 0x16, "LOAD_STR" => [rd: Reg, key: Src], 50,
            /// LOAD_HASH dst, key ; loads the string stored at key from storage
            LoadHash = 0x17, "LOAD_HASH" => [rd: Reg, key: Src], 50,
            /// SHA3 dst, argc, argv ; dst = sha3(concat(regs[argv..argv+argc]))
            Sha3 = 0x18, "SHA3" => [dst: Reg, argc: ImmU8, argv: Reg], 100,
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
            /// CALL_HOST dst, fn, argv ; call host function fn with args from regs[argv...] ; return -> dst
            CallHost = 0x40, "CALL_HOST" => [dst: Reg, fn_id: RefU32, argv: Reg], 100,
            /// CALL_HOST0 dst, fn ; call host function fn with no args ; return -> dst
            CallHost0 = 0x41, "CALL_HOST0" => [dst: Reg, fn_id: RefU32], 100,
            /// CALL dst, fn, argv ; call function fn with args from regs[argv...] ; return -> dst
            Call = 0x42, "CALL" => [dst: Reg, fn_id: ImmI32, argv: Reg], 50,
            /// CALL0 dst, fn ; call function fn with no args ; return -> dst
            Call0 = 0x43, "CALL0" => [dst: Reg, fn_id: ImmI32], 50,
            /// JAL rd, offset ; rd = PC + instr_size; PC += offset (jump and link)
            Jal = 0x44, "JAL" => [rd: Reg, offset: ImmI32], 5,
            /// JALR rd, rs, offset ; rd = PC + instr_size; PC = rs + offset (jump and link register)
            Jalr = 0x45, "JALR" => [rd: Reg, rs: Reg, offset: ImmI32], 5,
            /// BEQ rs1, rs2, offset ; if rs1 == rs2 then PC += offset
            Beq = 0x46, "BEQ" => [rs1: Src, rs2: Src, offset: ImmI32], 5,
            /// BNE rs1, rs2, offset ; if rs1 != rs2 then PC += offset
            Bne = 0x47, "BNE" => [rs1: Src, rs2: Src, offset: ImmI32], 5,
            /// BLT rs1, rs2, offset ; if rs1 < rs2 (signed) then PC += offset
            Blt = 0x48, "BLT" => [rs1: Src, rs2: Src, offset: ImmI32], 5,
            /// BGE rs1, rs2, offset ; if rs1 >= rs2 (signed) then PC += offset
            Bge = 0x49, "BGE" => [rs1: Src, rs2: Src, offset: ImmI32], 5,
            /// BLTU rs1, rs2, offset ; if rs1 < rs2 (unsigned) then PC += offset
            Bltu = 0x4A, "BLTU" => [rs1: Src, rs2: Src, offset: ImmI32], 5,
            /// BGEU rs1, rs2, offset ; if rs1 >= rs2 (unsigned) then PC += offset
            Bgeu = 0x4B, "BGEU" => [rs1: Src, rs2: Src, offset: ImmI32], 5,
            /// JUMP offset ; PC += offset (unconditional jump)
            Jump = 0x4C, "JUMP" => [offset: ImmI32], 5,
            /// RET rs ; return from function call with value in rs
            Ret = 0x4D, "RET" => [rs: Reg], 5,
            /// HALT ; stop execution immediately
            Halt = 0x4E, "HALT" => [], 1,
            // =========================
            // Data and Memory access
            // =========================
            /// CALLDATA_LOAD rd ; load call arguments into registers starting at rd
            CallDataLoad = 0x50, "CALLDATA_LOAD" => [rd: Reg], 3,
            /// CALLDATA_COPY dst ; copy serialized call arguments to memory at dst
            CallDataCopy = 0x51, "CALLDATA_COPY" => [dst: Addr], 5,
            /// CALLDATA_LEN rd ; rd = size in bytes of raw calldata
            CallDataLen = 0x52, "CALLDATA_LEN" => [rd: Reg], 1,
            /// MEM_LOAD rd, addr ; rd = memory[addr .. addr + 8]
            MemLoad = 0x53, "MEM_LOAD" => [rd: Reg, addr: Addr], 5,
            /// MEM_STORE addr, rs ; memory[addr .. addr + WORD_SIZE] = rs
            MemStore = 0x54, "MEM_STORE" => [addr: Addr, rs: Src], 5,
            /// MEM_COPY dst, src, len ; memory[dst .. dst+len] = memory[src .. src+len]
            MemCpy = 0x55, "MEM_COPY" => [dst: Addr, src: Addr, len: Addr], 5,
            /// MEM_SET dst, val, len ; for i in 0..len: memory[dst+i] = val
            MemSet = 0x56, "MEM_SET" => [dst: Addr, len: Addr, val: ImmU8], 5,
            /// MEM_LOAD_8U rd, addr ; rd = memory[addr .. addr + 1], zero extended
            MemLoad8U = 0x57, "MEM_LOAD_8U" => [rd: Reg, addr: Addr], 2,
            /// MEM_LOAD_8S rd, addr ; rd = memory[addr .. addr + 1], sign extended
            MemLoad8S = 0x58, "MEM_LOAD_8S" => [rd: Reg, addr: Addr], 2,
            /// MEM_LOAD_16U rd, addr ; rd = memory[addr .. addr + 2], zero extended
            MemLoad16U = 0x59, "MEM_LOAD_16U" => [rd: Reg, addr: Addr], 3,
            /// MEM_LOAD_16S rd, addr ; rd = memory[addr .. addr + 2], sign extended
            MemLoad16S = 0x5A, "MEM_LOAD_16S" => [rd: Reg, addr: Addr], 3,
            /// MEM_LOAD_32U rd, addr ; rd = memory[addr .. addr + 4], zero extended
            MemLoad32U = 0x5B, "MEM_LOAD_32U" => [rd: Reg, addr: Addr], 4,
            /// MEM_LOAD_32S rd, addr ; rd = memory[addr .. addr + 4], sign extended
            MemLoad32S = 0x5C, "MEM_LOAD_32S" => [rd: Reg, addr: Addr], 4,
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
        #[repr(u8)]
        #[derive(Copy, Clone, Debug, Eq, PartialEq)]
        pub enum Instruction {
            $(
                $(#[$doc])*
                $name = define_instructions!(@opcode_value $opcode; $( $kind ),*),
            )*
            /// DISPATCH count, (offset, argr)... ; dispatch to public function by selector index
            Dispatch = 0x7F,
        }

        impl TryFrom<u8> for Instruction {
            type Error = VMError;

            fn try_from(value: u8) -> Result<Self, Self::Error> {
                match value {
                    $( v if v == define_instructions!(@opcode_value $opcode; $( $kind ),*) => Ok(Instruction::$name), )*
                    0x7F => Ok(Instruction::Dispatch),
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
                    Instruction::Dispatch => "DISPATCH",
                }
            }

            /// Returns the base gas cost for this instruction.
            pub const fn base_gas(&self) -> u64 {
                match self {
                    $( Instruction::$name => $gas, )*
                    Instruction::Dispatch => 10,
                }
            }

            /// Returns true when this instruction accepts compact concat form
            /// (`rd, rs2` with metadata A=1 representing `rd, rd, rs2`).
            pub const fn supports_concat_compact(self) -> bool {
                matches!(
                    self,
                    Instruction::Add
                        | Instruction::Sub
                        | Instruction::Mul
                        | Instruction::Div
                        | Instruction::Mod
                        | Instruction::Min
                        | Instruction::Max
                        | Instruction::Shl
                        | Instruction::Shr
                        | Instruction::And
                        | Instruction::Or
                        | Instruction::Xor
                        | Instruction::Eq
                        | Instruction::Ne
                        | Instruction::Lt
                        | Instruction::Le
                        | Instruction::Gt
                        | Instruction::Ge
                )
            }

            /// Returns true when this instruction may carry one operand metadata byte.
            pub const fn supports_operand_metadata(self) -> bool {
                match self {
                    $( Instruction::$name => define_instructions!(@has_dynamic $( $kind ),*), )*
                    Instruction::Dispatch => false,
                }
            }

            /// Encodes this instruction opcode with an optional metadata flag.
            ///
            /// The resulting byte uses `0xZ[ooooooo]` where:
            /// - `ooooooo` is the 7-bit opcode value
            /// - `Z=1` means one metadata byte follows the opcode
            pub const fn encode_opcode(self, has_metadata: bool) -> u8 {
                let base = (self as u8) & OPCODE_BASE_MASK;
                if has_metadata {
                    base | OPCODE_METADATA_FLAG
                } else {
                    base
                }
            }

            /// Decodes an opcode byte into `(instruction, has_metadata)`.
            ///
            /// This strips the metadata flag bit and decodes the base opcode.
            pub fn decode_opcode(opcode: u8) -> Result<(Self, bool), VMError> {
                let has_metadata = (opcode & OPCODE_METADATA_FLAG) != 0;
                let instruction = match opcode & OPCODE_BASE_MASK {
                    $( v if v == (($opcode as u8) & OPCODE_BASE_MASK) => Instruction::$name, )*
                    0x7F => Instruction::Dispatch,
                    _ => {
                        return Err(VMError::InvalidInstruction { opcode, offset: 0 });
                    }
                };
                if has_metadata && !instruction.supports_operand_metadata() {
                    return Err(VMError::InvalidInstruction { opcode, offset: 0 });
                }
                Ok((instruction, has_metadata))
            }
        }
    };

    // ---------- opcode helpers ----------
    (@opcode_value $opcode:expr; $( $kind:ident ),* ) => {
        (($opcode as u8) & OPCODE_BASE_MASK) | define_instructions!(@opcode_metadata_flag $( $kind ),*)
    };
    (@opcode_metadata_flag) => { 0u8 };
    (@opcode_metadata_flag Src $(, $rest:ident )* ) => { OPCODE_METADATA_FLAG };
    (@opcode_metadata_flag Addr $(, $rest:ident )* ) => { OPCODE_METADATA_FLAG };
    (@opcode_metadata_flag ImmI32 $(, $rest:ident )* ) => { OPCODE_METADATA_FLAG };
    (@opcode_metadata_flag RefU32 $(, $rest:ident )* ) => { OPCODE_METADATA_FLAG };
    (@opcode_metadata_flag $other:ident $(, $rest:ident )* ) => {
        define_instructions!(@opcode_metadata_flag $( $rest ),*)
    };
    (@has_dynamic) => { false };
    (@has_dynamic Src $(, $rest:ident )* ) => { true };
    (@has_dynamic Addr $(, $rest:ident )* ) => { true };
    (@has_dynamic ImmI32 $(, $rest:ident )* ) => { true };
    (@has_dynamic RefU32 $(, $rest:ident )* ) => { true };
    (@has_dynamic $other:ident $(, $rest:ident )* ) => {
        define_instructions!(@has_dynamic $( $rest ),*)
    };

    // ---------- types ----------
    (@ty Reg)    => { u8 };
    (@ty ImmU8)  => { u8 };
    (@ty RefU32) => { u32 };
    (@ty ImmI32) => { i32 };
    (@ty ImmU32) => { u32 };
    (@ty Addr) => { AddrOperand };
    (@ty Src) => { SrcOperand };

    // ---------- encoding ----------
    (@emit $out:ident, Reg, $v:ident) => { $out.push(*$v); };
    (@emit $out:ident, ImmU8, $v:ident) => { $out.push(*$v); };

    (@emit $out:ident, RefU32, $v:ident) => { $out.extend_from_slice(&$v.to_le_bytes()); };
    (@emit $out:ident, ImmI32, $v:ident) => { $out.extend_from_slice(&$v.to_le_bytes()); };
    (@emit $out:ident, ImmU32, $v:ident) => { $out.extend_from_slice(&$v.to_le_bytes()); };

    (@emit $out:ident, Addr, $v:ident) => {
        match $v {
            AddrOperand::Reg(r) => {
                $out.push(0); // TAG_REG
                $out.push(*r)
            },
            AddrOperand::U32(u) => {
                $out.push(1); // TAG_U32
                $out.extend_from_slice(&u.to_le_bytes());
            },
        }
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
