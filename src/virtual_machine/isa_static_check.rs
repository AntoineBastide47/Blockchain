//! Static checks for ISA stability.
//!
//! These tests ensure that instruction definitions (opcodes, mnemonics, gas costs)
//! remain unchanged across updates. Any modification to the ISA will cause these
//! tests to fail, providing a safety net against accidental changes.

#[cfg(test)]
mod tests {
    use crate::virtual_machine::isa::Instruction;

    /// Verifies that all instruction opcodes match their expected values.
    #[test]
    fn instruction_opcodes_unchanged() {
        // Store and Load
        assert_eq!(Instruction::Move as u8, 0x00);
        assert_eq!(Instruction::DeleteState as u8, 0x01);
        assert_eq!(Instruction::StoreI64 as u8, 0x02);
        assert_eq!(Instruction::LoadI64State as u8, 0x03);
        assert_eq!(Instruction::StoreBool as u8, 0x04);
        assert_eq!(Instruction::LoadBoolState as u8, 0x05);
        assert_eq!(Instruction::StoreStr as u8, 0x06);
        assert_eq!(Instruction::LoadStrState as u8, 0x07);
        assert_eq!(Instruction::StoreHash as u8, 0x08);
        assert_eq!(Instruction::LoadHashState as u8, 0x09);

        // Casts
        assert_eq!(Instruction::I64ToBool as u8, 0x10);
        assert_eq!(Instruction::BoolToI64 as u8, 0x11);
        assert_eq!(Instruction::StrToI64 as u8, 0x12);
        assert_eq!(Instruction::I64ToStr as u8, 0x13);
        assert_eq!(Instruction::StrToBool as u8, 0x14);
        assert_eq!(Instruction::BoolToStr as u8, 0x15);

        // Integer arithmetic
        assert_eq!(Instruction::Add as u8, 0x20);
        assert_eq!(Instruction::Sub as u8, 0x21);
        assert_eq!(Instruction::Mul as u8, 0x22);
        assert_eq!(Instruction::Div as u8, 0x23);
        assert_eq!(Instruction::Mod as u8, 0x24);
        assert_eq!(Instruction::Neg as u8, 0x25);
        assert_eq!(Instruction::Abs as u8, 0x26);
        assert_eq!(Instruction::Min as u8, 0x27);
        assert_eq!(Instruction::Max as u8, 0x28);
        assert_eq!(Instruction::Shl as u8, 0x29);
        assert_eq!(Instruction::Shr as u8, 0x2A);
        assert_eq!(Instruction::Inc as u8, 0x2B);
        assert_eq!(Instruction::Dec as u8, 0x2C);

        // Boolean / comparison
        assert_eq!(Instruction::Not as u8, 0x30);
        assert_eq!(Instruction::And as u8, 0x31);
        assert_eq!(Instruction::Or as u8, 0x32);
        assert_eq!(Instruction::Xor as u8, 0x33);
        assert_eq!(Instruction::Eq as u8, 0x34);
        assert_eq!(Instruction::Ne as u8, 0x35);
        assert_eq!(Instruction::Lt as u8, 0x36);
        assert_eq!(Instruction::Le as u8, 0x37);
        assert_eq!(Instruction::Gt as u8, 0x38);
        assert_eq!(Instruction::Ge as u8, 0x39);

        // Control Flow
        assert_eq!(Instruction::CallHost as u8, 0x40);
        assert_eq!(Instruction::CallHost0 as u8, 0x41);
        assert_eq!(Instruction::CallHost1 as u8, 0x42);
        assert_eq!(Instruction::Call as u8, 0x43);
        assert_eq!(Instruction::Call0 as u8, 0x44);
        assert_eq!(Instruction::Call1 as u8, 0x45);
        assert_eq!(Instruction::Jal as u8, 0x46);
        assert_eq!(Instruction::Jalr as u8, 0x47);
        assert_eq!(Instruction::Beq as u8, 0x48);
        assert_eq!(Instruction::Bne as u8, 0x49);
        assert_eq!(Instruction::Blt as u8, 0x4A);
        assert_eq!(Instruction::Bge as u8, 0x4B);
        assert_eq!(Instruction::Bltu as u8, 0x4C);
        assert_eq!(Instruction::Bgeu as u8, 0x4D);
        assert_eq!(Instruction::Jump as u8, 0x4E);
        assert_eq!(Instruction::Ret as u8, 0x4F);
        assert_eq!(Instruction::Halt as u8, 0x50);

        // Data access
        assert_eq!(Instruction::CallDataLoad as u8, 0x51);
    }

    /// Verifies that all instruction mnemonics match their expected values.
    #[test]
    fn instruction_mnemonics_unchanged() {
        // Store and Load
        assert_eq!(Instruction::Move.mnemonic(), "MOVE");
        assert_eq!(Instruction::DeleteState.mnemonic(), "DELETE_STATE");
        assert_eq!(Instruction::StoreI64.mnemonic(), "STORE_I64");
        assert_eq!(Instruction::LoadI64State.mnemonic(), "LOAD_I64_STATE");
        assert_eq!(Instruction::StoreBool.mnemonic(), "STORE_BOOL");
        assert_eq!(Instruction::LoadBoolState.mnemonic(), "LOAD_BOOL_STATE");
        assert_eq!(Instruction::StoreStr.mnemonic(), "STORE_STR");
        assert_eq!(Instruction::LoadStrState.mnemonic(), "LOAD_STR_STATE");
        assert_eq!(Instruction::StoreHash.mnemonic(), "STORE_HASH");
        assert_eq!(Instruction::LoadHashState.mnemonic(), "LOAD_HASH_STATE");

        // Casts
        assert_eq!(Instruction::I64ToBool.mnemonic(), "I64_TO_BOOL");
        assert_eq!(Instruction::BoolToI64.mnemonic(), "BOOL_TO_I64");
        assert_eq!(Instruction::StrToI64.mnemonic(), "STR_TO_I64");
        assert_eq!(Instruction::I64ToStr.mnemonic(), "I64_TO_STR");
        assert_eq!(Instruction::StrToBool.mnemonic(), "STR_TO_BOOL");
        assert_eq!(Instruction::BoolToStr.mnemonic(), "BOOL_TO_STR");

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
        assert_eq!(Instruction::CallHost0.mnemonic(), "CALL_HOST0");
        assert_eq!(Instruction::CallHost1.mnemonic(), "CALL_HOST1");
        assert_eq!(Instruction::Call.mnemonic(), "CALL");
        assert_eq!(Instruction::Call0.mnemonic(), "CALL0");
        assert_eq!(Instruction::Call1.mnemonic(), "CALL1");
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

        // Data access
        assert_eq!(Instruction::CallDataLoad.mnemonic(), "CALLDATA_LOAD");
    }

    /// Verifies that all instruction base gas costs match their expected values.
    #[test]
    fn instruction_gas_costs_unchanged() {
        // Store and Load
        assert_eq!(Instruction::Move.base_gas(), 1);
        assert_eq!(Instruction::DeleteState.base_gas(), 2000);
        assert_eq!(Instruction::StoreI64.base_gas(), 2000);
        assert_eq!(Instruction::LoadI64State.base_gas(), 50);
        assert_eq!(Instruction::StoreBool.base_gas(), 2000);
        assert_eq!(Instruction::LoadBoolState.base_gas(), 50);
        assert_eq!(Instruction::StoreStr.base_gas(), 2000);
        assert_eq!(Instruction::LoadStrState.base_gas(), 50);
        assert_eq!(Instruction::StoreHash.base_gas(), 2000);
        assert_eq!(Instruction::LoadHashState.base_gas(), 50);

        // Casts
        assert_eq!(Instruction::I64ToBool.base_gas(), 1);
        assert_eq!(Instruction::BoolToI64.base_gas(), 1);
        assert_eq!(Instruction::StrToI64.base_gas(), 30);
        assert_eq!(Instruction::I64ToStr.base_gas(), 30);
        assert_eq!(Instruction::StrToBool.base_gas(), 20);
        assert_eq!(Instruction::BoolToStr.base_gas(), 20);

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
        assert_eq!(Instruction::CallHost0.base_gas(), 100);
        assert_eq!(Instruction::CallHost1.base_gas(), 100);
        assert_eq!(Instruction::Call.base_gas(), 50);
        assert_eq!(Instruction::Call0.base_gas(), 50);
        assert_eq!(Instruction::Call1.base_gas(), 50);
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

        // Data access
        assert_eq!(Instruction::CallDataLoad.base_gas(), 3);
    }

    /// Verifies the total instruction count has not changed.
    #[test]
    fn instruction_count_unchanged() {
        const EXPECTED_COUNT: usize = 57;

        // Count by verifying TryFrom succeeds for expected opcodes
        let mut count = 0;
        for byte in 0..=0xFF_u8 {
            if Instruction::try_from(byte).is_ok() {
                count += 1;
            }
        }

        assert_eq!(
            count, EXPECTED_COUNT,
            "instruction count changed: expected {}, found {}",
            EXPECTED_COUNT, count
        );
    }
}
