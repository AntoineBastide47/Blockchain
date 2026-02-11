//! Static checks for ISA stability.
//!
//! These tests ensure that instruction definitions (opcodes, mnemonics, gas costs)
//! remain unchanged across updates. Any modification to the ISA will cause these
//! tests to fail, providing a safety net against accidental changes.

#[cfg(test)]
mod tests {
    use crate::virtual_machine::isa::{Instruction, OPCODE_BASE_MASK, OPCODE_METADATA_FLAG};

    /// Verifies that all instruction opcodes match their expected values.
    #[test]
    fn instruction_opcodes_unchanged() {
        // Move, Casts and Misc
        assert_eq!((Instruction::Noop as u8) & OPCODE_BASE_MASK, 0x00);
        assert_eq!((Instruction::Move as u8) & OPCODE_BASE_MASK, 0x01);
        assert_eq!((Instruction::CMove as u8) & OPCODE_BASE_MASK, 0x02);
        assert_eq!((Instruction::I64ToBool as u8) & OPCODE_BASE_MASK, 0x03);
        assert_eq!((Instruction::BoolToI64 as u8) & OPCODE_BASE_MASK, 0x04);
        assert_eq!((Instruction::StrToI64 as u8) & OPCODE_BASE_MASK, 0x05);
        assert_eq!((Instruction::I64ToStr as u8) & OPCODE_BASE_MASK, 0x06);
        assert_eq!((Instruction::StrToBool as u8) & OPCODE_BASE_MASK, 0x07);
        assert_eq!((Instruction::BoolToStr as u8) & OPCODE_BASE_MASK, 0x08);

        // Store and Load
        assert_eq!((Instruction::DeleteState as u8) & OPCODE_BASE_MASK, 0x10);
        assert_eq!((Instruction::HasState as u8) & OPCODE_BASE_MASK, 0x11);
        assert_eq!((Instruction::StoreBytes as u8) & OPCODE_BASE_MASK, 0x12);
        assert_eq!((Instruction::LoadBytes as u8) & OPCODE_BASE_MASK, 0x13);
        assert_eq!((Instruction::LoadI64 as u8) & OPCODE_BASE_MASK, 0x14);
        assert_eq!((Instruction::LoadBool as u8) & OPCODE_BASE_MASK, 0x15);
        assert_eq!((Instruction::LoadStr as u8) & OPCODE_BASE_MASK, 0x16);
        assert_eq!((Instruction::LoadHash as u8) & OPCODE_BASE_MASK, 0x17);
        assert_eq!((Instruction::Sha3 as u8) & OPCODE_BASE_MASK, 0x18);

        // Integer arithmetic
        assert_eq!((Instruction::Add as u8) & OPCODE_BASE_MASK, 0x20);
        assert_eq!((Instruction::Sub as u8) & OPCODE_BASE_MASK, 0x21);
        assert_eq!((Instruction::Mul as u8) & OPCODE_BASE_MASK, 0x22);
        assert_eq!((Instruction::Div as u8) & OPCODE_BASE_MASK, 0x23);
        assert_eq!((Instruction::Mod as u8) & OPCODE_BASE_MASK, 0x24);
        assert_eq!((Instruction::Neg as u8) & OPCODE_BASE_MASK, 0x25);
        assert_eq!((Instruction::Abs as u8) & OPCODE_BASE_MASK, 0x26);
        assert_eq!((Instruction::Min as u8) & OPCODE_BASE_MASK, 0x27);
        assert_eq!((Instruction::Max as u8) & OPCODE_BASE_MASK, 0x28);
        assert_eq!((Instruction::Shl as u8) & OPCODE_BASE_MASK, 0x29);
        assert_eq!((Instruction::Shr as u8) & OPCODE_BASE_MASK, 0x2A);
        assert_eq!((Instruction::Inc as u8) & OPCODE_BASE_MASK, 0x2B);
        assert_eq!((Instruction::Dec as u8) & OPCODE_BASE_MASK, 0x2C);

        // Boolean / comparison
        assert_eq!((Instruction::Not as u8) & OPCODE_BASE_MASK, 0x30);
        assert_eq!((Instruction::And as u8) & OPCODE_BASE_MASK, 0x31);
        assert_eq!((Instruction::Or as u8) & OPCODE_BASE_MASK, 0x32);
        assert_eq!((Instruction::Xor as u8) & OPCODE_BASE_MASK, 0x33);
        assert_eq!((Instruction::Eq as u8) & OPCODE_BASE_MASK, 0x34);
        assert_eq!((Instruction::Ne as u8) & OPCODE_BASE_MASK, 0x35);
        assert_eq!((Instruction::Lt as u8) & OPCODE_BASE_MASK, 0x36);
        assert_eq!((Instruction::Le as u8) & OPCODE_BASE_MASK, 0x37);
        assert_eq!((Instruction::Gt as u8) & OPCODE_BASE_MASK, 0x38);
        assert_eq!((Instruction::Ge as u8) & OPCODE_BASE_MASK, 0x39);

        // Control Flow
        assert_eq!((Instruction::CallHost as u8) & OPCODE_BASE_MASK, 0x40);
        assert_eq!((Instruction::Call as u8) & OPCODE_BASE_MASK, 0x43);
        assert_eq!((Instruction::Jal as u8) & OPCODE_BASE_MASK, 0x46);
        assert_eq!((Instruction::Jalr as u8) & OPCODE_BASE_MASK, 0x47);
        assert_eq!((Instruction::Beq as u8) & OPCODE_BASE_MASK, 0x48);
        assert_eq!((Instruction::Bne as u8) & OPCODE_BASE_MASK, 0x49);
        assert_eq!((Instruction::Blt as u8) & OPCODE_BASE_MASK, 0x4A);
        assert_eq!((Instruction::Bge as u8) & OPCODE_BASE_MASK, 0x4B);
        assert_eq!((Instruction::Bltu as u8) & OPCODE_BASE_MASK, 0x4C);
        assert_eq!((Instruction::Bgeu as u8) & OPCODE_BASE_MASK, 0x4D);
        assert_eq!((Instruction::Jump as u8) & OPCODE_BASE_MASK, 0x4E);
        assert_eq!((Instruction::Ret as u8) & OPCODE_BASE_MASK, 0x4F);
        assert_eq!((Instruction::Halt as u8) & OPCODE_BASE_MASK, 0x50);

        // Data and Memory access
        assert_eq!((Instruction::CallDataLoad as u8) & OPCODE_BASE_MASK, 0x51);
        assert_eq!((Instruction::CallDataCopy as u8) & OPCODE_BASE_MASK, 0x52);
        assert_eq!((Instruction::CallDataLen as u8) & OPCODE_BASE_MASK, 0x53);
        assert_eq!((Instruction::MemLoad as u8) & OPCODE_BASE_MASK, 0x54);
        assert_eq!((Instruction::MemStore as u8) & OPCODE_BASE_MASK, 0x55);
        assert_eq!((Instruction::MemCpy as u8) & OPCODE_BASE_MASK, 0x56);
        assert_eq!((Instruction::MemSet as u8) & OPCODE_BASE_MASK, 0x57);
        assert_eq!((Instruction::MemLoad8U as u8) & OPCODE_BASE_MASK, 0x58);
        assert_eq!((Instruction::MemLoad8S as u8) & OPCODE_BASE_MASK, 0x59);
        assert_eq!((Instruction::MemLoad16U as u8) & OPCODE_BASE_MASK, 0x5A);
        assert_eq!((Instruction::MemLoad16S as u8) & OPCODE_BASE_MASK, 0x5B);
        assert_eq!((Instruction::MemLoad32U as u8) & OPCODE_BASE_MASK, 0x5C);
        assert_eq!((Instruction::MemLoad32S as u8) & OPCODE_BASE_MASK, 0x5D);

        // Special Dispatch instruction
        assert_eq!((Instruction::Dispatch as u8) & OPCODE_BASE_MASK, 0x7F);
    }

    /// Verifies metadata-flag (opcode Z bit) assignment for representative opcodes.
    #[test]
    fn instruction_metadata_flags_unchanged() {
        // No dynamic Src/Addr/ImmI32/RefU32 operands => no metadata flag.
        assert_eq!((Instruction::Noop as u8) & OPCODE_METADATA_FLAG, 0);
        assert_eq!((Instruction::Halt as u8) & OPCODE_METADATA_FLAG, 0);
        assert_eq!((Instruction::CallDataLoad as u8) & OPCODE_METADATA_FLAG, 0);
        assert_eq!((Instruction::CallDataLen as u8) & OPCODE_METADATA_FLAG, 0);
        assert_eq!((Instruction::Dispatch as u8) & OPCODE_METADATA_FLAG, 0);

        // Any Src/Addr/ImmI32/RefU32 operand in ISA => metadata flag present in opcode.
        assert_ne!((Instruction::Move as u8) & OPCODE_METADATA_FLAG, 0);
        assert_ne!((Instruction::DeleteState as u8) & OPCODE_METADATA_FLAG, 0);
        assert_ne!((Instruction::Add as u8) & OPCODE_METADATA_FLAG, 0);
        assert_ne!((Instruction::CallHost as u8) & OPCODE_METADATA_FLAG, 0);
        assert_ne!((Instruction::Call as u8) & OPCODE_METADATA_FLAG, 0);
        assert_ne!((Instruction::Jal as u8) & OPCODE_METADATA_FLAG, 0);
        assert_ne!((Instruction::Jalr as u8) & OPCODE_METADATA_FLAG, 0);
        assert_ne!((Instruction::Beq as u8) & OPCODE_METADATA_FLAG, 0);
        assert_ne!((Instruction::Jump as u8) & OPCODE_METADATA_FLAG, 0);
        assert_ne!((Instruction::LoadBytes as u8) & OPCODE_METADATA_FLAG, 0);
        assert_ne!((Instruction::CallDataCopy as u8) & OPCODE_METADATA_FLAG, 0);
        assert_ne!((Instruction::MemLoad as u8) & OPCODE_METADATA_FLAG, 0);
        assert_ne!((Instruction::MemStore as u8) & OPCODE_METADATA_FLAG, 0);
        assert_ne!((Instruction::MemCpy as u8) & OPCODE_METADATA_FLAG, 0);
        assert_eq!((Instruction::Sha3 as u8) & OPCODE_METADATA_FLAG, 0);
    }

    /// Verifies that all instruction mnemonics match their expected values.
    #[test]
    fn instruction_mnemonics_unchanged() {
        // Move, Casts and Misc
        assert_eq!(Instruction::Noop.mnemonic(), "NOOP");
        assert_eq!(Instruction::Move.mnemonic(), "MOVE");
        assert_eq!(Instruction::CMove.mnemonic(), "CMOVE");
        assert_eq!(Instruction::I64ToBool.mnemonic(), "I64_TO_BOOL");
        assert_eq!(Instruction::BoolToI64.mnemonic(), "BOOL_TO_I64");
        assert_eq!(Instruction::StrToI64.mnemonic(), "STR_TO_I64");
        assert_eq!(Instruction::I64ToStr.mnemonic(), "I64_TO_STR");
        assert_eq!(Instruction::StrToBool.mnemonic(), "STR_TO_BOOL");
        assert_eq!(Instruction::BoolToStr.mnemonic(), "BOOL_TO_STR");

        // Store and Load
        assert_eq!(Instruction::DeleteState.mnemonic(), "DELETE_STATE");
        assert_eq!(Instruction::HasState.mnemonic(), "HAS_STATE");
        assert_eq!(Instruction::StoreBytes.mnemonic(), "STORE");
        assert_eq!(Instruction::LoadBytes.mnemonic(), "LOAD");
        assert_eq!(Instruction::LoadI64.mnemonic(), "LOAD_I64");
        assert_eq!(Instruction::LoadBool.mnemonic(), "LOAD_BOOL");
        assert_eq!(Instruction::LoadStr.mnemonic(), "LOAD_STR");
        assert_eq!(Instruction::LoadHash.mnemonic(), "LOAD_HASH");
        assert_eq!(Instruction::Sha3.mnemonic(), "SHA3");

        // Integer arithmetic
        assert_eq!(Instruction::Add.mnemonic(), "ADD");
        assert_eq!(Instruction::Sub.mnemonic(), "SUB");
        assert_eq!(Instruction::Mul.mnemonic(), "MUL");
        assert_eq!(Instruction::Div.mnemonic(), "DIV");
        assert_eq!(Instruction::Mod.mnemonic(), "MOD");
        assert_eq!(Instruction::Neg.mnemonic(), "NEG");
        assert_eq!(Instruction::Abs.mnemonic(), "ABS");
        assert_eq!(Instruction::Min.mnemonic(), "MIN");
        assert_eq!(Instruction::Max.mnemonic(), "MAX");
        assert_eq!(Instruction::Shl.mnemonic(), "SHL");
        assert_eq!(Instruction::Shr.mnemonic(), "SHR");
        assert_eq!(Instruction::Inc.mnemonic(), "INC");
        assert_eq!(Instruction::Dec.mnemonic(), "DEC");

        // Boolean / comparison
        assert_eq!(Instruction::Not.mnemonic(), "NOT");
        assert_eq!(Instruction::And.mnemonic(), "AND");
        assert_eq!(Instruction::Or.mnemonic(), "OR");
        assert_eq!(Instruction::Xor.mnemonic(), "XOR");
        assert_eq!(Instruction::Eq.mnemonic(), "EQ");
        assert_eq!(Instruction::Ne.mnemonic(), "NE");
        assert_eq!(Instruction::Lt.mnemonic(), "LT");
        assert_eq!(Instruction::Le.mnemonic(), "LE");
        assert_eq!(Instruction::Gt.mnemonic(), "GT");
        assert_eq!(Instruction::Ge.mnemonic(), "GE");

        // Control Flow
        assert_eq!(Instruction::CallHost.mnemonic(), "CALL_HOST");
        assert_eq!(Instruction::Call.mnemonic(), "CALL");
        assert_eq!(Instruction::Jal.mnemonic(), "JAL");
        assert_eq!(Instruction::Jalr.mnemonic(), "JALR");
        assert_eq!(Instruction::Beq.mnemonic(), "BEQ");
        assert_eq!(Instruction::Bne.mnemonic(), "BNE");
        assert_eq!(Instruction::Blt.mnemonic(), "BLT");
        assert_eq!(Instruction::Bge.mnemonic(), "BGE");
        assert_eq!(Instruction::Bltu.mnemonic(), "BLTU");
        assert_eq!(Instruction::Bgeu.mnemonic(), "BGEU");
        assert_eq!(Instruction::Jump.mnemonic(), "JUMP");
        assert_eq!(Instruction::Ret.mnemonic(), "RET");
        assert_eq!(Instruction::Halt.mnemonic(), "HALT");

        // Data and Memory access
        assert_eq!(Instruction::CallDataLoad.mnemonic(), "CALLDATA_LOAD");
        assert_eq!(Instruction::CallDataCopy.mnemonic(), "CALLDATA_COPY");
        assert_eq!(Instruction::CallDataLen.mnemonic(), "CALLDATA_LEN");
        assert_eq!(Instruction::MemLoad.mnemonic(), "MEM_LOAD");
        assert_eq!(Instruction::MemStore.mnemonic(), "MEM_STORE");
        assert_eq!(Instruction::MemCpy.mnemonic(), "MEM_COPY");
        assert_eq!(Instruction::MemSet.mnemonic(), "MEM_SET");
        assert_eq!(Instruction::MemLoad8U.mnemonic(), "MEM_LOAD_8U");
        assert_eq!(Instruction::MemLoad8S.mnemonic(), "MEM_LOAD_8S");
        assert_eq!(Instruction::MemLoad16U.mnemonic(), "MEM_LOAD_16U");
        assert_eq!(Instruction::MemLoad16S.mnemonic(), "MEM_LOAD_16S");
        assert_eq!(Instruction::MemLoad32U.mnemonic(), "MEM_LOAD_32U");
        assert_eq!(Instruction::MemLoad32S.mnemonic(), "MEM_LOAD_32S");

        // Special Dispatch instruction
        assert_eq!(Instruction::Dispatch.mnemonic(), "DISPATCH");
    }

    /// Verifies that all instruction base gas costs match their expected values.
    #[test]
    fn instruction_gas_costs_unchanged() {
        // Move, Casts and Misc
        assert_eq!(Instruction::Noop.base_gas(), 1);
        assert_eq!(Instruction::Move.base_gas(), 1);
        assert_eq!(Instruction::CMove.base_gas(), 5);
        assert_eq!(Instruction::I64ToBool.base_gas(), 1);
        assert_eq!(Instruction::BoolToI64.base_gas(), 1);
        assert_eq!(Instruction::StrToI64.base_gas(), 30);
        assert_eq!(Instruction::I64ToStr.base_gas(), 30);
        assert_eq!(Instruction::StrToBool.base_gas(), 20);
        assert_eq!(Instruction::BoolToStr.base_gas(), 20);

        // Store and Load
        assert_eq!(Instruction::DeleteState.base_gas(), 2000);
        assert_eq!(Instruction::HasState.base_gas(), 50);
        assert_eq!(Instruction::StoreBytes.base_gas(), 2000);
        assert_eq!(Instruction::LoadBytes.base_gas(), 50);
        assert_eq!(Instruction::LoadI64.base_gas(), 50);
        assert_eq!(Instruction::LoadBool.base_gas(), 50);
        assert_eq!(Instruction::LoadStr.base_gas(), 50);
        assert_eq!(Instruction::LoadHash.base_gas(), 50);
        assert_eq!(Instruction::Sha3.base_gas(), 100);

        // Integer arithmetic
        assert_eq!(Instruction::Add.base_gas(), 3);
        assert_eq!(Instruction::Sub.base_gas(), 3);
        assert_eq!(Instruction::Mul.base_gas(), 5);
        assert_eq!(Instruction::Div.base_gas(), 10);
        assert_eq!(Instruction::Mod.base_gas(), 10);
        assert_eq!(Instruction::Neg.base_gas(), 2);
        assert_eq!(Instruction::Abs.base_gas(), 2);
        assert_eq!(Instruction::Min.base_gas(), 3);
        assert_eq!(Instruction::Max.base_gas(), 3);
        assert_eq!(Instruction::Shl.base_gas(), 3);
        assert_eq!(Instruction::Shr.base_gas(), 3);
        assert_eq!(Instruction::Inc.base_gas(), 1);
        assert_eq!(Instruction::Dec.base_gas(), 1);

        // Boolean / comparison
        assert_eq!(Instruction::Not.base_gas(), 1);
        assert_eq!(Instruction::And.base_gas(), 2);
        assert_eq!(Instruction::Or.base_gas(), 2);
        assert_eq!(Instruction::Xor.base_gas(), 2);
        assert_eq!(Instruction::Eq.base_gas(), 3);
        assert_eq!(Instruction::Ne.base_gas(), 3);
        assert_eq!(Instruction::Lt.base_gas(), 3);
        assert_eq!(Instruction::Le.base_gas(), 3);
        assert_eq!(Instruction::Gt.base_gas(), 3);
        assert_eq!(Instruction::Ge.base_gas(), 3);

        // Control Flow
        assert_eq!(Instruction::CallHost.base_gas(), 100);
        assert_eq!(Instruction::Call.base_gas(), 50);
        assert_eq!(Instruction::Jal.base_gas(), 5);
        assert_eq!(Instruction::Jalr.base_gas(), 5);
        assert_eq!(Instruction::Beq.base_gas(), 5);
        assert_eq!(Instruction::Bne.base_gas(), 5);
        assert_eq!(Instruction::Blt.base_gas(), 5);
        assert_eq!(Instruction::Bge.base_gas(), 5);
        assert_eq!(Instruction::Bltu.base_gas(), 5);
        assert_eq!(Instruction::Bgeu.base_gas(), 5);
        assert_eq!(Instruction::Jump.base_gas(), 5);
        assert_eq!(Instruction::Ret.base_gas(), 5);
        assert_eq!(Instruction::Halt.base_gas(), 1);

        // Data and Memory access
        assert_eq!(Instruction::CallDataLoad.base_gas(), 3);
        assert_eq!(Instruction::CallDataCopy.base_gas(), 5);
        assert_eq!(Instruction::CallDataLen.base_gas(), 1);
        assert_eq!(Instruction::MemLoad.base_gas(), 5);
        assert_eq!(Instruction::MemStore.base_gas(), 5);
        assert_eq!(Instruction::MemCpy.base_gas(), 5);
        assert_eq!(Instruction::MemSet.base_gas(), 5);
        assert_eq!(Instruction::MemLoad8U.base_gas(), 2);
        assert_eq!(Instruction::MemLoad8S.base_gas(), 2);
        assert_eq!(Instruction::MemLoad16U.base_gas(), 3);
        assert_eq!(Instruction::MemLoad16S.base_gas(), 3);
        assert_eq!(Instruction::MemLoad32U.base_gas(), 4);
        assert_eq!(Instruction::MemLoad32S.base_gas(), 4);

        // Special Dispatch instruction
        assert_eq!(Instruction::Dispatch.base_gas(), 10);
    }

    /// Verifies the total instruction count has not changed.
    #[test]
    fn instruction_count_unchanged() {
        const EXPECTED_COUNT: usize = 68;

        // Count by verifying TryFrom succeeds for expected opcodes
        let mut count = 0;
        for byte in 0..=0xFF_u8 {
            count += Instruction::try_from(byte).is_ok() as usize;
        }

        assert_eq!(
            count, EXPECTED_COUNT,
            "instruction count changed: expected {}, found {}",
            EXPECTED_COUNT, count
        );
    }
}
