use super::*;
use crate::virtual_machine::assembler::assemble_source;
use crate::virtual_machine::program::{DeployProgram, ExecuteProgram};
use crate::virtual_machine::state::tests::TestState;

impl VM {
    /// Creates a new VM instance with the given program and gas limits.
    ///
    /// Immediately charges `init_cost` gas. Returns `OutOfGas` if `init_cost` exceeds `max_gas`.
    pub fn new_with_init(
        program: DeployProgram,
        init_cost: u64,
        max_gas: u64,
    ) -> Result<Self, VMError> {
        let mut data = program.init_code;
        data.extend(program.runtime_code);

        let mut vm = Self {
            data,
            ip: 0,
            instr_offset: 0,
            operand_metadata: None,
            operand_metadata_cursor: 0,
            registers: Registers::new(),
            heap: Heap::new(program.memory),
            call_stack: Vec::new(),
            gas_used: 0,
            max_gas,
            gas_profile: GasProfile::new(),
            args: vec![],
            dispatch_selector: 0,
        };

        vm.charge_gas_categorized(init_cost, GasCategory::Deploy)?;
        Ok(vm)
    }

    /// Returns a slice of the execution memory.
    fn exec_memory(&self) -> &[u8] {
        self.heap.exec_memory()
    }
}

impl Heap {
    /// Retrieves a hash by its reference index.
    fn get_hash(&self, id: u32) -> Result<Hash, VMError> {
        let bytes = self.get_raw_ref(id)?;
        match Hash::from_slice(&bytes[WORD_SIZE..]) {
            None => Err(VMError::InvalidHash {
                expected_len: HASH_LEN,
                actual_len: bytes.len(),
            }),
            Some(hash) => Ok(hash),
        }
    }
}

const EXECUTION_CONTEXT: &ExecContext = &ExecContext {
    chain_id: 62845383663927,
    contract_id: Hash::zero(),
    caller: Hash::zero(),
};

const LEGACY_R0_ALIAS: u8 = 10;

fn test_reg(reg: u8) -> u8 {
    if reg == 0 { LEGACY_R0_ALIAS } else { reg }
}

fn run_vm(source: &str) -> VM {
    let program = assemble_source(source).expect("assembly failed");
    let mut vm = VM::new_with_init(program, 0, BLOCK_GAS_LIMIT).expect("vm new failed");
    vm.run(&mut TestState::new(), EXECUTION_CONTEXT)
        .expect("vm run failed");
    vm
}

fn run_and_get_int(source: &str, reg: u8) -> i64 {
    run_vm(source).registers.get_int(test_reg(reg), "").unwrap()
}

fn run_and_get_bool(source: &str, reg: u8) -> bool {
    run_vm(source)
        .registers
        .get_bool(test_reg(reg), "")
        .unwrap()
}

fn run_and_get_str(source: &str, reg: u8) -> String {
    let vm = run_vm(source);
    let r = vm.registers.get_ref(test_reg(reg), "").unwrap();
    vm.heap.get_string(r).unwrap()
}

fn run_expect_err(source: &str) -> VMError {
    let program = match assemble_source(source) {
        Ok(p) => p,
        Err(e) => return e,
    };
    let mut vm = VM::new_with_init(program, 0, BLOCK_GAS_LIMIT).expect("vm new failed");
    vm.run(&mut TestState::new(), EXECUTION_CONTEXT)
        .expect_err("expected error")
}

fn run_vm_with_state(source: &str) -> TestState {
    let program = assemble_source(source).expect("assembly failed");
    let mut vm = VM::new_with_init(program, 0, BLOCK_GAS_LIMIT).expect("vm new failed");
    let mut state = TestState::new();
    vm.run(&mut state, EXECUTION_CONTEXT)
        .expect("vm run failed");
    state
}

// ==================== Loads ====================

#[test]
fn load_i64() {
    assert_eq!(run_and_get_int("MOVE r10, 42", 0), 42);
    assert_eq!(run_and_get_int("MOVE r10, -1", 0), -1);
    assert_eq!(run_and_get_int("MOVE r10, 0", 0), 0);
}

#[test]
fn r0_is_hardwired_zero() {
    let vm = run_vm(
        r#"
            MOVE r0, 42
            INC r0
            DEC r0
            MOVE r1, r0
        "#,
    );
    assert_eq!(vm.registers.get_int(0, "").unwrap(), 0);
    assert_eq!(vm.registers.get_int(1, "").unwrap(), 0);
}

#[test]
fn load_bool() {
    assert!(run_and_get_bool("MOVE r10, true", 0));
    assert!(!run_and_get_bool("MOVE r10, false", 0));
}

#[test]
fn load_str() {
    let vm = run_vm(r#"MOVE r10, "hello""#);
    let ref_id = vm.registers.get_ref(10, "").unwrap();
    assert_eq!(vm.heap.get_string(ref_id).unwrap(), "hello");
}

#[test]
fn load_hash() {
    let vm = run_vm(r#"MOVE r10, "00000000000000000000000000000000""#);
    let ref_id = vm.registers.get_ref(10, "").unwrap();
    let expected = Hash::from_slice(b"00000000000000000000000000000000").unwrap();
    assert_eq!(vm.heap.get_hash(ref_id).unwrap(), expected);
}

#[test]
fn sha3_single_string_arg() {
    let vm = run_vm(
        r#"
            MOVE r2, "hello"
            SHA3 r10, 1, r2
        "#,
    );
    let ref_id = vm.registers.get_ref(10, "").unwrap();
    let expected = Hash::sha3().chain(b"hello").finalize();
    assert_eq!(vm.heap.get_hash(ref_id).unwrap(), expected);
}

#[test]
fn sha3_multiple_args_from_argv_range() {
    let vm = run_vm(
        r#"
            MOVE r2, "ab"
            MOVE r3, 42
            MOVE r4, true
            SHA3 r10, 3, r2
        "#,
    );
    let ref_id = vm.registers.get_ref(10, "").unwrap();
    let expected = Hash::sha3()
        .chain(b"ab")
        .chain(&42i64.to_le_bytes())
        .chain(&[1u8])
        .finalize();
    assert_eq!(vm.heap.get_hash(ref_id).unwrap(), expected);
}

#[test]
fn noop_does_not_modify_registers() {
    let vm = run_vm("MOVE r10, 7\nNOOP");
    assert_eq!(vm.registers.get_int(10, "").unwrap(), 7);
}

// ==================== Moves / Casts ====================

#[test]
fn move_int() {
    assert_eq!(run_and_get_int("MOVE r10, 99\nMOVE r1, r10", 1), 99);
}

#[test]
fn move_bool() {
    assert!(run_and_get_bool("MOVE r10, true\nMOVE r1, r10", 1));
}

#[test]
fn i64_to_bool() {
    assert!(run_and_get_bool("MOVE r10, 1\nI64_TO_BOOL r1, r10", 1));
    assert!(run_and_get_bool("MOVE r10, -5\nI64_TO_BOOL r1, r10", 1));
    assert!(!run_and_get_bool("MOVE r10, 0\nI64_TO_BOOL r1, r10", 1));
}

#[test]
fn bool_to_i64() {
    assert_eq!(run_and_get_int("MOVE r10, true\nBOOL_TO_I64 r1, r10", 1), 1);
    assert_eq!(
        run_and_get_int("MOVE r10, false\nBOOL_TO_I64 r1, r10", 1),
        0
    );
}

#[test]
fn str_to_i64_parses_numbers() {
    assert_eq!(
        run_and_get_int(
            r#"
                MOVE r10, "12345"
                STR_TO_I64 r1, r10
            "#,
            1
        ),
        12345
    );
    assert_eq!(
        run_and_get_int(
            r#"
                MOVE r10, "-7"
                STR_TO_I64 r1, r10
            "#,
            1
        ),
        -7
    );
}

#[test]
fn str_to_i64_rejects_non_numbers() {
    assert!(matches!(
        run_expect_err(
            r#"
                MOVE r10, "abc"
                STR_TO_I64 r1, r10
            "#
        ),
        VMError::ParseErrorString { .. }
    ));
}

#[test]
fn i64_to_str_round_trips() {
    assert_eq!(
        run_and_get_int("MOVE r10, -99\nI64_TO_STR r1, r10\nSTR_TO_I64 r2, r1", 2),
        -99
    );
    assert_eq!(
        run_and_get_str("MOVE r10, -99\nI64_TO_STR r1, r10", 1),
        "-99"
    );
}

#[test]
fn str_to_bool_accepts_true_and_false() {
    assert!(run_and_get_bool(
        r#"
            MOVE r10, "true"
            STR_TO_BOOL r1, r10
            "#,
        1
    ));
    assert!(!run_and_get_bool(
        r#"
            MOVE r10, "false"
            STR_TO_BOOL r1, r10
            "#,
        1
    ));
}

#[test]
fn str_to_bool_rejects_other_strings() {
    assert!(matches!(
        run_expect_err(
            r#"
                MOVE r10, "notabool"
                STR_TO_BOOL r1, r10
            "#
        ),
        VMError::TypeMismatch {
            instruction: "STR_TO_BOOL",
            ..
        }
    ));
}

#[test]
fn bool_to_str_round_trips() {
    assert_eq!(
        run_and_get_str("MOVE r10, true\nBOOL_TO_STR r1, r10", 1),
        "true"
    );
    assert!(run_and_get_bool(
        "MOVE r10, true\nBOOL_TO_STR r1, r10\nSTR_TO_BOOL r2, r1",
        2
    ));
    assert!(!run_and_get_bool(
        "MOVE r10, false\nBOOL_TO_STR r1, r10\nSTR_TO_BOOL r2, r1",
        2
    ));
}

// ==================== Arithmetic ====================

#[test]
fn add() {
    assert_eq!(
        run_and_get_int("MOVE r10, 10\nMOVE r1, 32\nADD r2, r10, r1", 2),
        42
    );
}

#[test]
fn add_wrapping() {
    let source = "MOVE r10, 9223372036854775807\nMOVE r1, 1\nADD r2, r10, r1";
    assert_eq!(run_and_get_int(source, 2), i64::MIN);
}

#[test]
fn sub() {
    assert_eq!(
        run_and_get_int("MOVE r10, 50\nMOVE r1, 8\nSUB r2, r10, r1", 2),
        42
    );
}

#[test]
fn mul() {
    assert_eq!(
        run_and_get_int("MOVE r10, 6\nMOVE r1, 7\nMUL r2, r10, r1", 2),
        42
    );
}

#[test]
fn div() {
    assert_eq!(
        run_and_get_int("MOVE r10, 84\nMOVE r1, 2\nDIV r2, r10, r1", 2),
        42
    );
}

#[test]
fn div_by_zero() {
    assert!(matches!(
        run_expect_err("MOVE r10, 1\nMOVE r1, 0\nDIV r2, r10, r1"),
        VMError::DivisionByZero
    ));
}

#[test]
fn modulo() {
    assert_eq!(
        run_and_get_int("MOVE r10, 47\nMOVE r1, 5\nMOD r2, r10, r1", 2),
        2
    );
}

#[test]
fn mod_by_zero() {
    assert!(matches!(
        run_expect_err("MOVE r10, 1\nMOVE r1, 0\nMOD r2, r10, r1"),
        VMError::DivisionByZero
    ));
}

#[test]
fn neg() {
    assert_eq!(run_and_get_int("MOVE r10, 42\nNEG r1, r10", 1), -42);
}

#[test]
fn abs() {
    assert_eq!(run_and_get_int("MOVE r10, -42\nABS r1, r10", 1), 42);
    assert_eq!(run_and_get_int("MOVE r10, 42\nABS r1, r10", 1), 42);
}

#[test]
fn min() {
    assert_eq!(
        run_and_get_int("MOVE r10, 10\nMOVE r1, 5\nMIN r2, r10, r1", 2),
        5
    );
}

#[test]
fn max() {
    assert_eq!(
        run_and_get_int("MOVE r10, 10\nMOVE r1, 5\nMAX r2, r10, r1", 2),
        10
    );
}

#[test]
fn shl() {
    assert_eq!(
        run_and_get_int("MOVE r10, 1\nMOVE r1, 4\nSHL r2, r10, r1", 2),
        16
    );
}

#[test]
fn shr() {
    assert_eq!(
        run_and_get_int("MOVE r10, 16\nMOVE r1, 2\nSHR r2, r10, r1", 2),
        4
    );
    // Arithmetic shift preserves sign
    assert_eq!(
        run_and_get_int("MOVE r10, -16\nMOVE r1, 2\nSHR r2, r10, r1", 2),
        -4
    );
}

#[test]
fn inc() {
    assert_eq!(run_and_get_int("MOVE r10, 0\nINC r10", 0), 1);
    assert_eq!(run_and_get_int("MOVE r10, 41\nINC r10", 0), 42);
    assert_eq!(run_and_get_int("MOVE r10, -1\nINC r10", 0), 0);
}

#[test]
fn dec() {
    assert_eq!(run_and_get_int("MOVE r10, 1\nDEC r10", 0), 0);
    assert_eq!(run_and_get_int("MOVE r10, 43\nDEC r10", 0), 42);
    assert_eq!(run_and_get_int("MOVE r10, 0\nDEC r10", 0), -1);
}

#[test]
fn inc_wrapping() {
    let source = "MOVE r10, 9223372036854775807\nINC r10";
    assert_eq!(run_and_get_int(source, 0), i64::MIN);
}

#[test]
fn dec_wrapping() {
    let source = "MOVE r10, -9223372036854775808\nDEC r10";
    assert_eq!(run_and_get_int(source, 0), i64::MAX);
}

#[test]
fn inc_type_error() {
    assert!(matches!(
        run_expect_err("MOVE r10, true\nINC r10"),
        VMError::TypeMismatchStatic { .. }
    ));
}

#[test]
fn dec_type_error() {
    assert!(matches!(
        run_expect_err("MOVE r10, true\nDEC r10"),
        VMError::TypeMismatchStatic { .. }
    ));
}

// ==================== Src Operand Encoding ====================

#[test]
fn src_operand_move_all_types() {
    // MOVE with immediate i64
    assert_eq!(run_and_get_int("MOVE r10, 42", 0), 42);
    assert_eq!(run_and_get_int("MOVE r10, -100", 0), -100);

    // MOVE with immediate bool
    assert!(run_and_get_bool("MOVE r10, true", 0));
    assert!(!run_and_get_bool("MOVE r10, false", 0));

    // MOVE with immediate string
    assert_eq!(run_and_get_str(r#"MOVE r10, "hello""#, 0), "hello");

    // MOVE from register
    assert_eq!(run_and_get_int("MOVE r10, 99\nMOVE r1, r10", 1), 99);
}

#[test]
fn src_operand_store_immediate_key() {
    // Store with immediate string key
    let vm = run_vm(
        r#"STORE "mykey", 123
LOAD_I64 r10, "mykey""#,
    );
    assert_eq!(vm.registers.get_int(10, "").unwrap(), 123);
}

#[test]
fn src_operand_store_immediate_value() {
    // Store with immediate value
    let vm = run_vm(
        r#"MOVE r10, "counter"
STORE r10, 999
LOAD_I64 r1, r10"#,
    );
    assert_eq!(vm.registers.get_int(1, "").unwrap(), 999);
}

#[test]
fn src_operand_store_both_immediate() {
    // Both key and value immediate
    let vm = run_vm(
        r#"STORE "flag", true
LOAD_BOOL r10, "flag""#,
    );
    assert!(vm.registers.get_bool(10, "").unwrap());
}

#[test]
fn src_operand_cast_immediate() {
    // Cast from immediate value
    assert!(run_and_get_bool("I64_TO_BOOL r10, 1", 0));
    assert!(!run_and_get_bool("I64_TO_BOOL r10, 0", 0));
    assert_eq!(run_and_get_int("BOOL_TO_I64 r10, true", 0), 1);
    assert_eq!(run_and_get_int("BOOL_TO_I64 r10, false", 0), 0);
}

#[test]
fn src_operand_not_immediate() {
    assert!(!run_and_get_bool("MOVE r1, true\nNOT r10, r1", 0));
    assert!(run_and_get_bool("MOVE r1, false\nNOT r10, r1", 0));
}

#[test]
fn src_operand_neg_abs_immediate() {
    assert_eq!(run_and_get_int("MOVE r1, 42\nNEG r10, r1", 0), -42);
    assert_eq!(run_and_get_int("MOVE r1, -42\nNEG r10, r1", 0), 42);
    assert_eq!(run_and_get_int("MOVE r1, -42\nABS r10, r1", 0), 42);
    assert_eq!(run_and_get_int("MOVE r1, 42\nABS r10, r1", 0), 42);
}

// ==================== Boolean ====================

#[test]
fn not() {
    assert!(!run_and_get_bool("MOVE r10, true\nNOT r1, r10", 1));
    assert!(run_and_get_bool("MOVE r10, false\nNOT r1, r10", 1));
}

#[test]
fn and() {
    assert!(run_and_get_bool(
        "MOVE r10, true\nMOVE r1, true\nAND r2, r10, r1",
        2
    ));
    assert!(!run_and_get_bool(
        "MOVE r10, true\nMOVE r1, false\nAND r2, r10, r1",
        2
    ));
}

#[test]
fn or() {
    assert!(run_and_get_bool(
        "MOVE r10, false\nMOVE r1, true\nOR r2, r10, r1",
        2
    ));
    assert!(!run_and_get_bool(
        "MOVE r10, false\nMOVE r1, false\nOR r2, r10, r1",
        2
    ));
}

#[test]
fn xor() {
    assert!(run_and_get_bool(
        "MOVE r10, true\nMOVE r1, false\nXOR r2, r10, r1",
        2
    ));
    assert!(!run_and_get_bool(
        "MOVE r10, true\nMOVE r1, true\nXOR r2, r10, r1",
        2
    ));
}

// ==================== Comparison ====================

#[test]
fn eq() {
    assert!(run_and_get_bool(
        "MOVE r10, 5\nMOVE r1, 5\nEQ r2, r10, r1",
        2
    ));
    assert!(!run_and_get_bool(
        "MOVE r10, 5\nMOVE r1, 6\nEQ r2, r10, r1",
        2
    ));
}

#[test]
fn ne() {
    assert!(run_and_get_bool(
        "MOVE r10, 5\nMOVE r1, 6\nNE r2, r10, r1",
        2
    ));
    assert!(!run_and_get_bool(
        "MOVE r10, 5\nMOVE r1, 5\nNE r2, r10, r1",
        2
    ));
}

#[test]
fn lt() {
    assert!(run_and_get_bool(
        "MOVE r10, 3\nMOVE r1, 5\nLT r2, r10, r1",
        2
    ));
    assert!(!run_and_get_bool(
        "MOVE r10, 5\nMOVE r1, 3\nLT r2, r10, r1",
        2
    ));
}

#[test]
fn le() {
    assert!(run_and_get_bool(
        "MOVE r10, 3\nMOVE r1, 5\nLE r2, r10, r1",
        2
    ));
    assert!(run_and_get_bool(
        "MOVE r10, 5\nMOVE r1, 5\nLE r2, r10, r1",
        2
    ));
    assert!(!run_and_get_bool(
        "MOVE r10, 6\nMOVE r1, 5\nLE r2, r10, r1",
        2
    ));
}

#[test]
fn gt() {
    assert!(run_and_get_bool(
        "MOVE r10, 10\nMOVE r1, 5\nGT r2, r10, r1",
        2
    ));
    assert!(!run_and_get_bool(
        "MOVE r10, 5\nMOVE r1, 10\nGT r2, r10, r1",
        2
    ));
}

#[test]
fn ge() {
    assert!(run_and_get_bool(
        "MOVE r10, 10\nMOVE r1, 5\nGE r2, r10, r1",
        2
    ));
    assert!(run_and_get_bool(
        "MOVE r10, 5\nMOVE r1, 5\nGE r2, r10, r1",
        2
    ));
    assert!(!run_and_get_bool(
        "MOVE r10, 4\nMOVE r1, 5\nGE r2, r10, r1",
        2
    ));
}

// ==================== Type Errors ====================

#[test]
fn type_mismatch_int_for_bool() {
    let source = "MOVE r10, 1\nNOT r1, r10";
    assert!(matches!(
        run_expect_err(source),
        VMError::TypeMismatchStatic { .. }
    ));
}

#[test]
fn type_mismatch_bool_for_int() {
    let source = "MOVE r10, true\nMOVE r1, true\nADD r2, r10, r1";
    assert!(matches!(
        run_expect_err(source),
        VMError::TypeMismatchStatic { .. }
    ));
}

#[test]
fn invalid_operand_for_int_op() {
    let source = r#"MOVE r10, "hi"
MOVE r1, 1
ADD r2, r10, r1"#;
    assert!(matches!(
        run_expect_err(source),
        VMError::TypeMismatchStatic { .. }
    ));
}

// ==================== Error Cases ====================

#[test]
fn read_uninitialized_register() {
    assert_eq!(run_and_get_int("ADD r2, r10, r1", 2), 0);
}

#[test]
fn invalid_opcode() {
    let mut vm = VM::new_with_init(
        DeployProgram::new(vec![], vec![], vec![0xFE]),
        0,
        BLOCK_GAS_LIMIT,
    )
    .expect("vm new failed");
    assert!(matches!(
        vm.run(&mut TestState::new(), EXECUTION_CONTEXT),
        Err(VMError::InvalidInstruction { opcode: 0xFE, .. })
    ));
}

#[test]
fn invalid_operand_tag() {
    // Metadata uses mixed-radix states; this malformed payload truncates Addr decoding.
    let bytecode = vec![Instruction::MemLoad as u8, 0b0000_1000, 0];
    let mut vm = VM::new_with_init(
        DeployProgram::new(vec![], vec![], bytecode),
        0,
        BLOCK_GAS_LIMIT,
    )
    .expect("vm new failed");
    let err = vm
        .run(&mut TestState::new(), EXECUTION_CONTEXT)
        .expect_err("expected error");
    assert!(matches!(err, VMError::UnexpectedEndOfBytecode { .. }));
}

#[test]
fn truncated_bytecode() {
    let mut vm = VM::new_with_init(
        DeployProgram::new(vec![], vec![], vec![Instruction::Move as u8, 0x00]),
        0,
        BLOCK_GAS_LIMIT,
    )
    .expect("vm new failed");
    assert!(matches!(
        vm.run(&mut TestState::new(), EXECUTION_CONTEXT),
        Err(VMError::UnexpectedEndOfBytecode { .. })
    ));
}

// ==================== Gas Limits ====================

#[test]
fn vm_new_charges_init_cost() {
    let vm = VM::new_with_init(
        DeployProgram::new(vec![], vec![], vec![]),
        100,
        BLOCK_GAS_LIMIT,
    )
    .unwrap();
    assert_eq!(vm.gas_used(), 100);
}

#[test]
fn vm_new_fails_when_init_cost_exceeds_max_gas() {
    let result = VM::new_with_init(DeployProgram::new(vec![], vec![], vec![]), 1000, 500);
    assert!(matches!(
        result,
        Err(VMError::OutOfGas {
            used: 1000,
            limit: 500
        })
    ));
}

#[test]
fn vm_new_succeeds_when_init_cost_equals_max_gas() {
    let vm = VM::new_with_init(DeployProgram::new(vec![], vec![], vec![]), 500, 500).unwrap();
    assert_eq!(vm.gas_used(), 500);
}

#[test]
fn vm_respects_custom_max_gas() {
    let program = assemble_source(
        r#"
            MOVE r10, 1
            MOVE r1, 2
            ADD r2, r10, r1
            ADD r2, r1, r2
        "#,
    )
    .expect("assembly failed");

    let mut vm = VM::new_with_init(program, 0, 5).unwrap();
    let result = vm.run(&mut TestState::new(), EXECUTION_CONTEXT);

    assert!(matches!(result, Err(VMError::OutOfGas { .. })));
}

// ==================== Stores ====================

fn make_test_key(user_key: &[u8]) -> Result<Hash, VMError> {
    VM::new_with_init(
        DeployProgram::new(vec![], vec![], vec![]),
        0,
        BLOCK_GAS_LIMIT,
    )
    .expect("vm new failed")
    .make_state_key(
        EXECUTION_CONTEXT.chain_id,
        &EXECUTION_CONTEXT.contract_id,
        user_key,
    )
}

#[test]
fn store_i64() {
    let state = run_vm_with_state(
        r#"MOVE r10, "counter"
MOVE r1, 42
STORE r10, r1"#,
    );
    let key = make_test_key(b"counter").unwrap();
    let value = state.get(key).expect("key not found");
    assert_eq!(i64::from_le_bytes(value.try_into().unwrap()), 42);
}

#[test]
fn store_i64_inline_key() {
    let vm = run_vm(
        r#"STORE "counter", 42
LOAD_I64 r10, "counter""#,
    );
    assert_eq!(vm.registers.get_int(10, "").unwrap(), 42);
}

#[test]
fn store_str() {
    let state = run_vm_with_state(
        r#"MOVE r10, "name"
MOVE r1, "alice"
STORE r10, r1"#,
    );
    let key = make_test_key(b"name").unwrap();
    let value = state.get(key).expect("key not found");
    assert_eq!(value, b"alice");
}

#[test]
fn store_hash() {
    let state = run_vm_with_state(
        r#"MOVE r10, "hash_key"
MOVE r1, "00000000000000000000000000000000"
STORE r10, r1"#,
    );
    let key = make_test_key(b"hash_key").unwrap();
    let value = state.get(key).expect("key not found");
    let expected = Hash::from_slice(b"00000000000000000000000000000000").unwrap();
    assert_eq!(value, expected.to_vec());
}

#[test]
fn store_bool() {
    let state = run_vm_with_state(
        r#"MOVE r10, "flag"
MOVE r1, true
STORE r10, r1"#,
    );
    let key = make_test_key(b"flag").unwrap();
    let value = state.get(key).expect("key not found");
    assert_eq!(value, &[1u8]);
}

#[test]
fn store_overwrites_previous_value() {
    let state = run_vm_with_state(
        r#"MOVE r10, "x"
MOVE r1, 100
STORE r10, r1
MOVE r2, 200
STORE r10, r2"#,
    );
    let key = make_test_key(b"x").unwrap();
    let value = state.get(key).expect("key not found");
    assert_eq!(i64::from_le_bytes(value.try_into().unwrap()), 200);
}

#[test]
fn store_then_load_bytes() {
    let vm = run_vm(
        r#"MOVE r10, "blob"
MOVE r1, "hello"
STORE r10, r1
LOAD r2, r10"#,
    );
    let ref_id = vm.registers.get_ref(2, "").unwrap();
    assert_eq!(vm.heap.get_data(ref_id).unwrap(), b"hello");
}

// ==================== State Loads ====================

fn run_vm_on_state(source: &str, state: &mut TestState) -> VM {
    let program = assemble_source(source).expect("assembly failed");
    let mut vm = VM::new_with_init(program, 0, BLOCK_GAS_LIMIT).expect("vm new failed");
    vm.run(state, EXECUTION_CONTEXT).expect("vm run failed");
    vm
}

#[test]
fn load_i64_state() {
    let key = make_test_key(b"counter").unwrap();
    let mut state = TestState::with_data(vec![(key, 42i64.to_le_bytes().to_vec())]);
    let vm = run_vm_on_state(
        r#"MOVE r10, "counter"
LOAD_I64 r1, r10"#,
        &mut state,
    );
    assert_eq!(vm.registers.get_int(1, "").unwrap(), 42);
}

#[test]
fn load_i64_state_negative() {
    let key = make_test_key(b"neg").unwrap();
    let mut state = TestState::with_data(vec![(key, (-999i64).to_le_bytes().to_vec())]);
    let vm = run_vm_on_state(
        r#"MOVE r10, "neg"
LOAD_I64 r1, r10"#,
        &mut state,
    );
    assert_eq!(vm.registers.get_int(1, "").unwrap(), -999);
}

#[test]
fn load_i64_state_key_not_found() {
    let program = assemble_source(
        r#"MOVE r10, "missing"
LOAD_I64 r1, r10"#,
    )
    .expect("assembly failed");
    let mut vm = VM::new_with_init(program, 0, BLOCK_GAS_LIMIT).expect("vm new failed");
    let err = vm
        .run(&mut TestState::new(), EXECUTION_CONTEXT)
        .expect_err("expected error");
    assert!(matches!(err, VMError::KeyNotFound { .. }));
}

#[test]
fn load_bool_state_true() {
    let key = make_test_key(b"flag").unwrap();
    let mut state = TestState::with_data(vec![(key, vec![1u8])]);
    let vm = run_vm_on_state(
        r#"MOVE r10, "flag"
LOAD_BOOL r1, r10"#,
        &mut state,
    );
    assert!(vm.registers.get_bool(1, "").unwrap());
}

#[test]
fn load_bool_state_false() {
    let key = make_test_key(b"flag").unwrap();
    let mut state = TestState::with_data(vec![(key, vec![0u8])]);
    let vm = run_vm_on_state(
        r#"MOVE r10, "flag"
LOAD_BOOL r1, r10"#,
        &mut state,
    );
    assert!(!vm.registers.get_bool(1, "").unwrap());
}

#[test]
fn load_bool_state_key_not_found() {
    let program = assemble_source(
        r#"MOVE r10, "missing"
LOAD_BOOL r1, r10"#,
    )
    .expect("assembly failed");
    let mut vm = VM::new_with_init(program, 0, BLOCK_GAS_LIMIT).expect("vm new failed");
    let err = vm
        .run(&mut TestState::new(), EXECUTION_CONTEXT)
        .expect_err("expected error");
    assert!(matches!(err, VMError::KeyNotFound { .. }));
}

#[test]
fn has_state_reports_presence() {
    let key = make_test_key(b"present").unwrap();
    let mut state = TestState::with_data(vec![(key, vec![1u8])]);
    let vm = run_vm_on_state(
        r#"MOVE r10, "present"
MOVE r1, "missing"
HAS_STATE r2, r10
HAS_STATE r3, r1"#,
        &mut state,
    );
    assert!(vm.registers.get_bool(2, "").unwrap());
    assert!(!vm.registers.get_bool(3, "").unwrap());
}

#[test]
fn load_str_state() {
    let key = make_test_key(b"name").unwrap();
    let mut state = TestState::with_data(vec![(key, b"alice".to_vec())]);
    let vm = run_vm_on_state(
        r#"MOVE r10, "name"
LOAD_STR r1, r10"#,
        &mut state,
    );
    let ref_id = vm.registers.get_ref(1, "").unwrap();
    assert_eq!(vm.heap.get_string(ref_id).unwrap(), "alice");
}

#[test]
fn load_str_state_empty() {
    let key = make_test_key(b"empty").unwrap();
    let mut state = TestState::with_data(vec![(key, vec![])]);
    let vm = run_vm_on_state(
        r#"MOVE r10, "empty"
LOAD_STR r1, r10"#,
        &mut state,
    );
    let ref_id = vm.registers.get_ref(1, "").unwrap();
    assert_eq!(vm.heap.get_string(ref_id).unwrap(), "");
}

#[test]
fn load_hash_state() {
    let key = make_test_key(b"hash_key").unwrap();
    let expected = Hash::from_slice(b"11111111111111111111111111111111").unwrap();
    let mut state = TestState::with_data(vec![(key, expected.to_vec())]);
    let vm = run_vm_on_state(
        r#"MOVE r10, "hash_key"
LOAD_HASH r1, r10"#,
        &mut state,
    );
    let ref_id = vm.registers.get_ref(1, "").unwrap();
    assert_eq!(vm.heap.get_hash(ref_id).unwrap(), expected);
}

#[test]
fn load_str_state_key_not_found() {
    let program = assemble_source(
        r#"MOVE r10, "missing"
LOAD_STR r1, r10"#,
    )
    .expect("assembly failed");
    let mut vm = VM::new_with_init(program, 0, BLOCK_GAS_LIMIT).expect("vm new failed");
    let err = vm
        .run(&mut TestState::new(), EXECUTION_CONTEXT)
        .expect_err("expected error");
    assert!(matches!(err, VMError::KeyNotFound { .. }));
}

#[test]
fn store_then_load_i64() {
    let vm = run_vm(
        r#"MOVE r10, "x"
MOVE r1, 123
STORE r10, r1
LOAD_I64 r2, r10"#,
    );
    assert_eq!(vm.registers.get_int(2, "").unwrap(), 123);
}

#[test]
fn store_then_load_bool() {
    let vm = run_vm(
        r#"MOVE r10, "b"
MOVE r1, true
STORE r10, r1
LOAD_BOOL r2, r10"#,
    );
    assert!(vm.registers.get_bool(2, "").unwrap());
}

#[test]
fn store_then_load_str() {
    let vm = run_vm(
        r#"MOVE r10, "s"
MOVE r1, "hello"
STORE r10, r1
LOAD_STR r2, r10"#,
    );
    let ref_id = vm.registers.get_ref(2, "").unwrap();
    assert_eq!(vm.heap.get_string(ref_id).unwrap(), "hello");
}

#[test]
fn store_then_load_hash() {
    let vm = run_vm(
        r#"MOVE r10, "hash_key"
MOVE r1, "22222222222222222222222222222222"
STORE r10, r1
LOAD_HASH r2, r10"#,
    );
    let ref_id = vm.registers.get_ref(2, "").unwrap();
    let expected = Hash::from_slice(b"22222222222222222222222222222222").unwrap();
    assert_eq!(vm.heap.get_hash(ref_id).unwrap(), expected);
}

// ==================== Control Flow ====================

#[test]
fn jal_saves_return_address() {
    // JAL saves the address after the instruction to rd
    // JAL r10, 0 means jump to current position (no-op) but save return addr
    let vm = run_vm("JAL r10, 0");
    // After JAL (3 bytes: opcode + reg + i32_1), ip should be saved as 3.
    assert_eq!(vm.registers.get_int(10, "").unwrap(), 3);
}

#[test]
fn jal_forward_jump() {
    // Jump over MOVE r1, 99 to reach MOVE r2, 42
    let source = r#"
            JAL r10, skip
            MOVE r1, 99
            skip: MOVE r2, 42
        "#;
    let vm = run_vm(source);
    // r1 should still be zero (skipped)
    assert_eq!(vm.registers.get(1).unwrap(), &Value::Int(0));
    // r2 should be 42
    assert_eq!(vm.registers.get_int(2, "").unwrap(), 42);
}

#[test]
fn jump_skips_instructions() {
    let vm = run_vm(
        r#"
            MOVE r10, 1
            JUMP done
            MOVE r10, 99
            done:
        "#,
    );
    assert_eq!(vm.registers.get_int(10, "").unwrap(), 1);
}

#[test]
fn beq_taken() {
    // Branch taken when equal
    let source = r#"
            MOVE r10, 5
            MOVE r1, 5
            BEQ r10, r1, skip
            MOVE r2, 99
            skip: MOVE r3, 42
        "#;
    let vm = run_vm(source);
    assert_eq!(vm.registers.get(2).unwrap(), &Value::Int(0));
    assert_eq!(vm.registers.get_int(3, "").unwrap(), 42);
}

#[test]
fn beq_not_taken() {
    // Branch not taken when not equal
    let source = r#"
            MOVE r10, 5
            MOVE r1, 6
            BEQ r10, r1, skip
            MOVE r2, 99
            skip: MOVE r3, 42
        "#;
    let vm = run_vm(source);
    assert_eq!(vm.registers.get_int(2, "").unwrap(), 99);
    assert_eq!(vm.registers.get_int(3, "").unwrap(), 42);
}

#[test]
fn bne_taken() {
    let source = r#"
            MOVE r10, 5
            MOVE r1, 6
            BNE r10, r1, skip
            MOVE r2, 99
            skip: MOVE r3, 42
        "#;
    let vm = run_vm(source);
    assert_eq!(vm.registers.get(2).unwrap(), &Value::Int(0));
    assert_eq!(vm.registers.get_int(3, "").unwrap(), 42);
}

#[test]
fn bne_not_taken() {
    let source = r#"
            MOVE r10, 5
            MOVE r1, 5
            BNE r10, r1, skip
            MOVE r2, 99
            skip: MOVE r3, 42
        "#;
    let vm = run_vm(source);
    assert_eq!(vm.registers.get_int(2, "").unwrap(), 99);
}

#[test]
fn blt_taken() {
    let source = r#"
            MOVE r10, 3
            MOVE r1, 5
            BLT r10, r1, skip
            MOVE r2, 99
            skip: MOVE r3, 42
        "#;
    let vm = run_vm(source);
    assert_eq!(vm.registers.get(2).unwrap(), &Value::Int(0));
    assert_eq!(vm.registers.get_int(3, "").unwrap(), 42);
}

#[test]
fn blt_not_taken() {
    let source = r#"
            MOVE r10, 5
            MOVE r1, 3
            BLT r10, r1, skip
            MOVE r2, 99
            skip: MOVE r3, 42
        "#;
    let vm = run_vm(source);
    assert_eq!(vm.registers.get_int(2, "").unwrap(), 99);
}

#[test]
fn blt_signed() {
    // -1 < 1 in signed comparison
    let source = r#"
            MOVE r10, -1
            MOVE r1, 1
            BLT r10, r1, skip
            MOVE r2, 99
            skip: MOVE r3, 42
        "#;
    let vm = run_vm(source);
    assert_eq!(vm.registers.get(2).unwrap(), &Value::Int(0));
}

#[test]
fn bge_taken() {
    let source = r#"
            MOVE r10, 5
            MOVE r1, 5
            BGE r10, r1, skip
            MOVE r2, 99
            skip: MOVE r3, 42
        "#;
    let vm = run_vm(source);
    assert_eq!(vm.registers.get(2).unwrap(), &Value::Int(0));
}

#[test]
fn bge_greater() {
    let source = r#"
            MOVE r10, 7
            MOVE r1, 5
            BGE r10, r1, skip
            MOVE r2, 99
            skip: MOVE r3, 42
        "#;
    let vm = run_vm(source);
    assert_eq!(vm.registers.get(2).unwrap(), &Value::Int(0));
}

#[test]
fn bltu_unsigned() {
    // -1 as u64 is MAX, so -1 > 1 in unsigned comparison
    let source = r#"
            MOVE r10, -1
            MOVE r1, 1
            BLTU r10, r1, skip
            MOVE r2, 99
            skip: MOVE r3, 42
        "#;
    let vm = run_vm(source);
    // Branch NOT taken because -1 as u64 > 1
    assert_eq!(vm.registers.get_int(2, "").unwrap(), 99);
}

#[test]
fn bgeu_unsigned() {
    // -1 as u64 is MAX, so -1 >= 1 in unsigned comparison
    let source = r#"
            MOVE r10, -1
            MOVE r1, 1
            BGEU r10, r1, skip
            MOVE r2, 99
            skip: MOVE r3, 42
        "#;
    let vm = run_vm(source);
    // Branch taken because -1 as u64 > 1
    assert_eq!(vm.registers.get(2).unwrap(), &Value::Int(0));
}

#[test]
fn halt_stops_execution() {
    let source = r#"
            MOVE r10, 1
            HALT
            MOVE r10, 99
        "#;
    let vm = run_vm(source);
    assert_eq!(vm.registers.get_int(10, "").unwrap(), 1);
}

#[test]
fn loop_with_backward_branch() {
    // Simple loop: count from 0 to 3
    let source = r#"
            MOVE r10, 0
            MOVE r1, 1
            MOVE r2, 3
            loop:
            ADD r10, r10, r1
            BLT r10, r2, loop
        "#;
    let vm = run_vm(source);
    // r10 should be 3 after loop exits
    assert_eq!(vm.registers.get_int(10, "").unwrap(), 3);
}

#[test]
fn jalr_indirect_jump() {
    let source = r#"
            JAL r1, setup
            target:
            MOVE r3, 42
            JUMP end
            setup:
            JALR r10, r1, 0
            MOVE r2, 99
            end:
        "#;
    let vm = run_vm(source);
    // Should skip MOVE r2, 99 and execute MOVE r3, 42.
    assert_eq!(vm.registers.get(2).unwrap(), &Value::Int(0));
    assert_eq!(vm.registers.get_int(3, "").unwrap(), 42);
}

// ==================== Function Calls ====================

#[test]
fn call_and_ret_simple() {
    // Call a function that returns a constant
    let source = r#"
            JAL r10, main
            main:
            CALL r1, double, 0, r10
            JAL r10, end
            double:
            MOVE r10, 42
            RET r10
            end:
        "#;
    let vm = run_vm(source);
    assert_eq!(vm.registers.get_int(1, "").unwrap(), 42);
}

#[test]
fn call_nested() {
    // Nested function calls
    let source = r#"
            JAL r10, main
            main:
            CALL r1, outer, 0, r10
            JAL r10, end
            outer:
            CALL r2, inner, 0, r10
            RET r2
            inner:
            MOVE r10, 99
            RET r10
            end:
        "#;
    let vm = run_vm(source);
    assert_eq!(vm.registers.get_int(1, "").unwrap(), 99);
}

#[test]
fn call_undefined_function() {
    let source = r#"CALL r10, nonexistent, 0, r10"#;
    let err = run_expect_err(source);
    assert!(matches!(err, VMError::AssemblyError { .. }));
}

#[test]
fn ret_without_call() {
    let source = "MOVE r10, 1\nRET r10";
    let err = run_expect_err(source);
    assert!(matches!(err, VMError::ReturnWithoutCall { .. }));
}

#[test]
fn call_preserves_registers() {
    let source = r#"
            JAL r10, main
            main:
            MOVE r5, 100
            CALL r1, func, 0, r10
            ADD r2, r1, r5
            JAL r10, end
            func:
            MOVE r10, 50
            RET r10
            end:
        "#;
    let vm = run_vm(source);
    // r1 = 50 (return value), r5 = 100, r2 = 150
    assert_eq!(vm.registers.get_int(2, "").unwrap(), 150);
}

#[test]
fn counter_steps_loop() {
    let prog = r#"
        # increment counter N times, where N is stored under "steps"
        main:
            MOVE r10, "counter"
            MOVE r1, "steps"

            LOAD_I64 r2, r10     # acc = counter
            LOAD_I64 r3, r1     # limit = steps
            MOVE r4, 0            # i = 0
            MOVE r5, 1            # inc = 1

        loop:
            ADD r2, r2, r5            # acc += 1
            ADD r4, r4, r5            # i++
            BLT r4, r3, loop          # loop while i < limit

        STORE r10, r2              # update counter
        "#;

    let mut state = TestState::new();
    let program = assemble_source(prog).expect("assembly failed");
    let mut vm = VM::new_with_init(program, 0, BLOCK_GAS_LIMIT).expect("vm new failed");

    let key_counter = vm
        .make_state_key(
            EXECUTION_CONTEXT.chain_id,
            &EXECUTION_CONTEXT.contract_id,
            b"counter",
        )
        .unwrap();
    let key_steps = vm
        .make_state_key(
            EXECUTION_CONTEXT.chain_id,
            &EXECUTION_CONTEXT.contract_id,
            b"steps",
        )
        .unwrap();

    state.push(key_counter, 5i64.to_le_bytes().to_vec());
    state.push(key_steps, 3i64.to_le_bytes().to_vec());

    vm.run(&mut state, EXECUTION_CONTEXT)
        .expect("vm run failed");

    let out = state.get(key_counter).unwrap();
    assert_eq!(i64::from_le_bytes(out.try_into().unwrap()), 8);
}

// ==================== Call Stack Poisoning ====================

#[test]
fn deeply_nested_calls() {
    // Chain of nested function calls to stress the call stack
    let source = r#"
            JAL r10, main
            main:
            CALL r1, f1, 0, r10
            JAL r10, end
            f1:
            CALL r2, f2, 0, r10
            RET r2
            f2:
            CALL r3, f3, 0, r10
            RET r3
            f3:
            CALL r4, f4, 0, r10
            RET r4
            f4:
            CALL r5, f5, 0, r10
            RET r5
            f5:
            MOVE r10, 777
            RET r10
            end:
        "#;
    let vm = run_vm(source);
    assert_eq!(vm.registers.get_int(1, "").unwrap(), 777);
}

#[test]
fn call_stack_unwind_on_multiple_returns() {
    // Each function returns, properly unwinding the stack
    let source = r#"
            JAL r10, main
            main:
            MOVE r10, 1
            CALL r1, add_ten, 0, r10
            CALL r2, add_ten, 0, r10
            CALL r3, add_ten, 0, r10
            ADD r4, r1, r2
            ADD r4, r4, r3
            JAL r10, end
            add_ten:
            MOVE r20, 10
            RET r20
            end:
        "#;
    let vm = run_vm(source);
    // Three calls each return 10, sum should be 30
    assert_eq!(vm.registers.get_int(4, "").unwrap(), 30);
}

#[test]
fn call_overwrites_dst_register_with_return_value() {
    // Verify that the destination register is correctly overwritten
    let source = r#"
            JAL r10, main
            main:
            MOVE r5, 999
            CALL r5, get_42, 0, r10
            JAL r10, end
            get_42:
            MOVE r10, 42
            RET r10
            end:
        "#;
    let vm = run_vm(source);
    // r5 should be overwritten with 42, not 999
    assert_eq!(vm.registers.get_int(5, "").unwrap(), 42);
}

#[test]
fn return_from_recursive_call() {
    // Simple recursion: count down from 3 to 0
    let source = r#"
            JAL r10, main
            main:
            MOVE r1, 3
            CALL r2, countdown, 0, r10
            JAL r10, end

            countdown:
            MOVE r10, 0
            MOVE r11, 1
            BEQ r1, r10, done
            SUB r1, r1, r11
            CALL r12, countdown, 0, r10
            done:
            RET r1

            end:
        "#;
    let vm = run_vm(source);
    // After countdown, r1 should be 0
    assert_eq!(vm.registers.get_int(2, "").unwrap(), 0);
}

#[test]
fn multiple_ret_without_call_fails() {
    // First RET succeeds, second RET should fail
    let source = r#"
            JAL r10, main
            main:
            CALL r1, func, 0, r10
            JAL r10, end
            func:
            MOVE r10, 1
            RET r10
            RET r10
            end:
        "#;
    // This should succeed because the second RET is never reached
    let vm = run_vm(source);
    assert_eq!(vm.registers.get_int(1, "").unwrap(), 1);
}

#[test]
fn ret_with_empty_stack_fails() {
    // Direct RET without any CALL
    let source = "MOVE r10, 42\nRET r10";
    let err = run_expect_err(source);
    assert!(matches!(err, VMError::ReturnWithoutCall { .. }));
}

#[test]
fn call_then_jal_then_ret_fails() {
    // CALL pushes frame, but JAL jumps away and RET finds wrong context
    let source = r#"
            JAL r10, main
            main:
            CALL r1, func, 0, r10
            JAL r10, end
            func:
            JAL r10, escape
            escape:
            MOVE r10, 1
            RET r10
            end:
        "#;
    // This should work because RET still finds the call frame
    let vm = run_vm(source);
    assert_eq!(vm.registers.get_int(1, "").unwrap(), 1);
}

#[test]
fn call_stack_isolation_between_calls() {
    // Ensure sequential calls don't interfere with each other
    let source = r#"
            JAL r10, main
            main:
            CALL r1, ret_10, 0, r10
            CALL r2, ret_20, 0, r10
            CALL r3, ret_30, 0, r10
            JAL r10, end
            ret_10:
            MOVE r10, 10
            RET r10
            ret_20:
            MOVE r10, 20
            RET r10
            ret_30:
            MOVE r10, 30
            RET r10
            end:
        "#;
    let vm = run_vm(source);
    assert_eq!(vm.registers.get_int(1, "").unwrap(), 10);
    assert_eq!(vm.registers.get_int(2, "").unwrap(), 20);
    assert_eq!(vm.registers.get_int(3, "").unwrap(), 30);
}

#[test]
fn call_with_same_dst_as_return_reg() {
    // Return value goes to same register used inside function
    let source = r#"
            JAL r9, main
            main:
            CALL r10, func, 0, r10
            JAL r9, end
            func:
            MOVE r10, 42
            RET r10
            end:
        "#;
    let vm = run_vm(source);
    // r10 should have return value 42
    assert_eq!(vm.registers.get_int(10, "").unwrap(), 42);
}

#[test]
fn nested_call_return_value_propagation() {
    // Return value flows through nested calls
    let source = r#"
            JAL r10, main
            main:
            CALL r1, outer, 0, r10
            JAL r10, end
            outer:
            CALL r2, middle, 0, r10
            MOVE r3, 1
            ADD r2, r2, r3
            RET r2
            middle:
            CALL r4, inner, 0, r10
            MOVE r5, 1
            ADD r4, r4, r5
            RET r4
            inner:
            MOVE r6, 1
            RET r6
            end:
        "#;
    let vm = run_vm(source);
    // inner returns 1, middle adds 1 = 2, outer adds 1 = 3
    assert_eq!(vm.registers.get_int(1, "").unwrap(), 3);
}

#[test]
fn call_stack_empty_after_balanced_calls() {
    // After all returns, call stack should be empty
    let source = r#"
            JAL r10, main
            main:
            CALL r1, a, 0, r10
            CALL r2, b, 0, r10
            JAL r10, end
            a:
            MOVE r10, 1
            RET r10
            b:
            MOVE r10, 2
            RET r10
            end:
        "#;
    let vm = run_vm(source);
    // Call stack should be empty after execution
    assert!(vm.call_stack.is_empty());
}

#[test]
fn return_zero_value() {
    // Return the Zero value from an uninitialized register
    let source = r#"
            JAL r10, main
            main:
            CALL r1, ret_zero, 0, r10
            JAL r10, end
            ret_zero:
            RET r50
            end:
        "#;
    let vm = run_vm(source);
    assert_eq!(vm.registers.get(1).unwrap(), &Value::Int(0));
}

#[test]
fn return_bool_value() {
    // Return a boolean value
    let source = r#"
            JAL r10, main
            main:
            CALL r1, ret_bool, 0, r10
            JAL r10, end
            ret_bool:
            MOVE r10, true
            RET r10
            end:
        "#;
    let vm = run_vm(source);
    assert_eq!(vm.registers.get(1).unwrap(), &Value::Bool(true));
}

#[test]
fn return_ref_value() {
    // Return a string reference
    let source = r#"
            JAL r10, main
            main:
            CALL r1, ret_str, 0, r10
            JAL r10, end
            ret_str:
            MOVE r10, "hello"
            RET r10
            end:
        "#;
    let vm = run_vm(source);
    let ref_id = match vm.registers.get(1).unwrap() {
        Value::Ref(r) => *r,
        other => panic!("expected Ref, got {:?}", other),
    };
    assert_eq!(vm.heap.get_string(ref_id).unwrap(), "hello");
}

#[test]
fn new_execute_stores_args_for_calldata_load() {
    let args = vec![Value::Ref(0), Value::Int(7), Value::Bool(true)];
    let exec = ExecuteProgram::new(Hash::zero(), 3, args.clone(), vec![b"hello".to_vec()]);
    let deploy = DeployProgram::new(vec![], vec![], vec![]);
    let vm = VM::new_execute(exec, deploy, BLOCK_GAS_LIMIT).unwrap();

    // r0 is hardwired to zero
    assert_eq!(vm.registers.get_int(0, "").unwrap(), 0);
    // function selector is stored separately for DISPATCH
    assert_eq!(vm.dispatch_selector, 3);
    // Args are stored for later CALLDATA_LOAD, not preloaded into registers
    assert_eq!(vm.args, args);
    // heap_arg_base points to start of arg items (no base items)
    assert_eq!(vm.heap.exec_offset, 0);
    // The arg item was appended to the heap at heap_arg_base
    assert_eq!(vm.heap.get_string(0).unwrap(), "hello");
}

// ==================== Host Functions ====================

// --- len ---

#[test]
fn host_len_empty_string() {
    let source = r#"
            MOVE r1, ""
            CALL_HOST r10, "len", 1, r1
        "#;
    assert_eq!(run_and_get_int(source, 0), 0);
}

#[test]
fn host_len_ascii_string() {
    let source = r#"
            MOVE r1, "hello"
            CALL_HOST r10, "len", 1, r1
        "#;
    assert_eq!(run_and_get_int(source, 0), 5);
}

#[test]
fn host_len_single_char() {
    let source = r#"
            MOVE r1, "x"
            CALL_HOST r10, "len", 1, r1
        "#;
    assert_eq!(run_and_get_int(source, 0), 1);
}

#[test]
fn host_len_wrong_arg_count() {
    let source = r#"
            MOVE r1, "test"
            MOVE r2, "extra"
            CALL_HOST r10, "len", 2, r1
        "#;
    assert!(matches!(
        run_expect_err(source),
        VMError::ParseErrorString { .. }
    ));
}

#[test]
fn host_len_wrong_type() {
    let source = r#"
            MOVE r1, 42
            CALL_HOST r10, "len", 1, r1
        "#;
    assert!(matches!(
        run_expect_err(source),
        VMError::TypeMismatchStatic { .. }
    ));
}

// --- slice ---

#[test]
fn host_slice_middle() {
    let source = r#"
            MOVE r1, "hello world"
            MOVE r2, 0
            MOVE r3, 5
            CALL_HOST r10, "slice", 3, r1
        "#;
    let vm = run_vm(source);
    let ref_id = vm.registers.get_ref(10, "").unwrap();
    assert_eq!(vm.heap.get_string(ref_id).unwrap(), "hello");
}

#[test]
fn host_slice_from_offset() {
    let source = r#"
            MOVE r1, "hello world"
            MOVE r2, 6
            MOVE r3, 11
            CALL_HOST r10, "slice", 3, r1
        "#;
    let vm = run_vm(source);
    let ref_id = vm.registers.get_ref(10, "").unwrap();
    assert_eq!(vm.heap.get_string(ref_id).unwrap(), "world");
}

#[test]
fn host_slice_empty_result() {
    let source = r#"
            MOVE r1, "hello"
            MOVE r2, 2
            MOVE r3, 2
            CALL_HOST r10, "slice", 3, r1
        "#;
    let vm = run_vm(source);
    let ref_id = vm.registers.get_ref(10, "").unwrap();
    assert_eq!(vm.heap.get_string(ref_id).unwrap(), "");
}

#[test]
fn host_slice_full_string() {
    let source = r#"
            MOVE r1, "abc"
            MOVE r2, 0
            MOVE r3, 3
            CALL_HOST r10, "slice", 3, r1
        "#;
    let vm = run_vm(source);
    let ref_id = vm.registers.get_ref(10, "").unwrap();
    assert_eq!(vm.heap.get_string(ref_id).unwrap(), "abc");
}

#[test]
fn host_slice_clamps_end_beyond_length() {
    let source = r#"
            MOVE r1, "short"
            MOVE r2, 0
            MOVE r3, 100
            CALL_HOST r10, "slice", 3, r1
        "#;
    let vm = run_vm(source);
    let ref_id = vm.registers.get_ref(10, "").unwrap();
    assert_eq!(vm.heap.get_string(ref_id).unwrap(), "short");
}

#[test]
fn host_slice_clamps_start_beyond_end() {
    let source = r#"
            MOVE r1, "hello"
            MOVE r2, 10
            MOVE r3, 5
            CALL_HOST r10, "slice", 3, r1
        "#;
    let vm = run_vm(source);
    let ref_id = vm.registers.get_ref(10, "").unwrap();
    assert_eq!(vm.heap.get_string(ref_id).unwrap(), "");
}

#[test]
fn host_slice_wrong_arg_count() {
    let source = r#"
            MOVE r1, "test"
            MOVE r2, 0
            CALL_HOST r10, "slice", 2, r1
        "#;
    assert!(matches!(
        run_expect_err(source),
        VMError::ParseErrorString { .. }
    ));
}

// --- concat ---

#[test]
fn host_concat_two_strings() {
    let source = r#"
            MOVE r1, "hello"
            MOVE r2, " world"
            CALL_HOST r10, "concat", 2, r1
        "#;
    let vm = run_vm(source);
    let ref_id = vm.registers.get_ref(10, "").unwrap();
    assert_eq!(vm.heap.get_string(ref_id).unwrap(), "hello world");
}

#[test]
fn host_concat_empty_left() {
    let source = r#"
            MOVE r1, ""
            MOVE r2, "world"
            CALL_HOST r10, "concat", 2, r1
        "#;
    let vm = run_vm(source);
    let ref_id = vm.registers.get_ref(10, "").unwrap();
    assert_eq!(vm.heap.get_string(ref_id).unwrap(), "world");
}

#[test]
fn host_concat_empty_right() {
    let source = r#"
            MOVE r1, "hello"
            MOVE r2, ""
            CALL_HOST r10, "concat", 2, r1
        "#;
    let vm = run_vm(source);
    let ref_id = vm.registers.get_ref(10, "").unwrap();
    assert_eq!(vm.heap.get_string(ref_id).unwrap(), "hello");
}

#[test]
fn host_concat_both_empty() {
    let source = r#"
            MOVE r1, ""
            MOVE r2, ""
            CALL_HOST r10, "concat", 2, r1
        "#;
    let vm = run_vm(source);
    let ref_id = vm.registers.get_ref(10, "").unwrap();
    assert_eq!(vm.heap.get_string(ref_id).unwrap(), "");
}

#[test]
fn host_concat_wrong_arg_count() {
    let source = r#"
            MOVE r1, "only one"
            CALL_HOST r10, "concat", 1, r1
        "#;
    assert!(matches!(
        run_expect_err(source),
        VMError::ParseErrorString { .. }
    ));
}

#[test]
fn host_concat_wrong_type() {
    let source = r#"
            MOVE r1, "str"
            MOVE r2, 42
            CALL_HOST r10, "concat", 2, r1
        "#;
    assert!(matches!(
        run_expect_err(source),
        VMError::TypeMismatchStatic { .. }
    ));
}

// --- compare ---

#[test]
fn host_compare_equal() {
    let source = r#"
            MOVE r1, "abc"
            MOVE r2, "abc"
            CALL_HOST r10, "compare", 2, r1
        "#;
    assert_eq!(run_and_get_int(source, 0), 0);
}

#[test]
fn host_compare_less_than() {
    let source = r#"
            MOVE r1, "abc"
            MOVE r2, "abd"
            CALL_HOST r10, "compare", 2, r1
        "#;
    assert_eq!(run_and_get_int(source, 0), -1);
}

#[test]
fn host_compare_greater_than() {
    let source = r#"
            MOVE r1, "abd"
            MOVE r2, "abc"
            CALL_HOST r10, "compare", 2, r1
        "#;
    assert_eq!(run_and_get_int(source, 0), 1);
}

#[test]
fn host_compare_prefix_shorter() {
    let source = r#"
            MOVE r1, "ab"
            MOVE r2, "abc"
            CALL_HOST r10, "compare", 2, r1
        "#;
    assert_eq!(run_and_get_int(source, 0), -1);
}

#[test]
fn host_compare_prefix_longer() {
    let source = r#"
            MOVE r1, "abc"
            MOVE r2, "ab"
            CALL_HOST r10, "compare", 2, r1
        "#;
    assert_eq!(run_and_get_int(source, 0), 1);
}

#[test]
fn host_compare_empty_strings() {
    let source = r#"
            MOVE r1, ""
            MOVE r2, ""
            CALL_HOST r10, "compare", 2, r1
        "#;
    assert_eq!(run_and_get_int(source, 0), 0);
}

#[test]
fn host_compare_empty_vs_nonempty() {
    let source = r#"
            MOVE r1, ""
            MOVE r2, "a"
            CALL_HOST r10, "compare", 2, r1
        "#;
    assert_eq!(run_and_get_int(source, 0), -1);
}

#[test]
fn host_compare_wrong_arg_count() {
    let source = r#"
            MOVE r1, "only"
            CALL_HOST r10, "compare", 1, r1
        "#;
    assert!(matches!(
        run_expect_err(source),
        VMError::ParseErrorString { .. }
    ));
}

// --- invalid host function ---

#[test]
fn host_invalid_function() {
    let source = r#"
            MOVE r1, "arg"
            CALL_HOST r10, "nonexistent", 1, r1
        "#;
    assert!(matches!(
        run_expect_err(source),
        VMError::ParseErrorString { .. }
    ));
}

#[test]
fn host_hash_is_now_invalid_function() {
    let source = r#"
            MOVE r1, "arg"
            CALL_HOST r10, "hash", 1, r1
        "#;
    assert!(matches!(
        run_expect_err(source),
        VMError::ParseErrorString { .. }
    ));
}

// --- removed call host aliases ---

#[test]
fn call_host0_is_rejected() {
    let source = r#"CALL_HOST0 r10, "nonexistent""#;
    assert!(matches!(
        run_expect_err(source),
        VMError::ParseErrorString { .. }
    ));
}

// --- call_host ---

#[test]
fn call_host_len() {
    let source = r#"
            MOVE r1, "test"
            CALL_HOST r10, "len", 1, r1
        "#;
    assert_eq!(run_and_get_int(source, 0), 4);
}

#[test]
fn call_host_len_with_immediate_string() {
    let source = r#"
            MOVE r1, "hello world"
            CALL_HOST r10, "len", 1, r1
        "#;
    assert_eq!(run_and_get_int(source, 0), 11);
}

#[test]
fn call_host_invalid_function_with_string_arg() {
    let source = r#"
            MOVE r1, "arg"
            CALL_HOST r10, "nonexistent", 1, r1
        "#;
    assert!(matches!(
        run_expect_err(source),
        VMError::ParseErrorString { .. }
    ));
}

#[test]
fn call_host_hash_is_now_invalid_function_with_string_arg() {
    let source = r#"
            MOVE r1, "arg"
            CALL_HOST r10, "hash", 1, r1
        "#;
    assert!(matches!(
        run_expect_err(source),
        VMError::ParseErrorString { .. }
    ));
}

// --- removed call aliases ---

#[test]
fn call_basic_with_explicit_argc_and_argv() {
    let source = r#"
            JUMP skip_fn
            my_func(1, r10):
                MOVE r10, 100
                RET r10
            skip_fn:
            MOVE r2, 99
            CALL r1, my_func, 1, r2
        "#;
    assert_eq!(run_and_get_int(source, 1), 100);
}

#[test]
fn call_with_argument_register_preloaded() {
    let source = r#"
            JUMP skip_fn
            my_func(1, r255):
                RET r255
            skip_fn:
            MOVE r255, 42
            CALL r1, my_func, 1, r255
        "#;
    assert_eq!(run_and_get_int(source, 1), 42);
}

#[test]
fn call_to_public_function_uses_declared_arity_validation() {
    let source = r#"
            __init__:
            MOVE r127, 42
            CALL r9, foo, 1, r127
            HALT

            pub foo(1, r127):
                RET r127
        "#;
    assert_eq!(run_and_get_int(source, 9), 42);
}

// ==================== CallDataLoad ====================

fn run_vm_with_args(source: &str, args: Vec<Value>, arg_items: Vec<Vec<u8>>) -> VM {
    let program = assemble_source(source).expect("assembly failed");
    let mut data = program.init_code;
    data.extend(program.runtime_code);

    let mut heap = Heap::new(program.memory);
    for item in arg_items {
        heap.append(item);
    }

    let mut vm = VM {
        data,
        ip: 0,
        instr_offset: 0,
        operand_metadata: None,
        operand_metadata_cursor: 0,
        registers: Registers::new(),
        heap,
        call_stack: Vec::new(),
        gas_used: 0,
        max_gas: BLOCK_GAS_LIMIT,
        gas_profile: GasProfile::new(),
        args,
        dispatch_selector: 0,
    };

    vm.run(&mut TestState::new(), EXECUTION_CONTEXT)
        .expect("vm run failed");
    vm
}

fn expected_calldata(args: &[Value], arg_items: &[Vec<u8>]) -> Vec<u8> {
    let mut heap = Heap::new(vec![]);
    for item in arg_items {
        heap.append(item.clone());
    }

    let mut buf = Vec::new();
    for arg in args {
        match arg {
            Value::Bool(b) => b.encode(&mut buf),
            Value::Int(i) => i.encode(&mut buf),
            Value::Ref(r) => buf.write(heap.get_raw_ref(*r).unwrap_or(&[])),
        }
    }
    buf
}

#[test]
fn calldata_load_int_args() {
    let vm = run_vm_with_args(
        "CALLDATA_LOAD r1",
        vec![Value::Int(10), Value::Int(20)],
        vec![],
    );
    assert_eq!(vm.registers.get_int(1, "").unwrap(), 10);
    assert_eq!(vm.registers.get_int(2, "").unwrap(), 20);
}

#[test]
fn calldata_load_mixed_args() {
    let vm = run_vm_with_args(
        "CALLDATA_LOAD r10",
        vec![Value::Int(42), Value::Bool(true)],
        vec![],
    );
    assert_eq!(vm.registers.get_int(10, "").unwrap(), 42);
    assert!(vm.registers.get_bool(11, "").unwrap());
}

#[test]
fn calldata_load_remaps_refs() {
    // arg_items inserts one heap item; Value::Ref(0) should be remapped to heap_arg_base.
    let vm = run_vm_with_args(
        "CALLDATA_LOAD r10",
        vec![Value::Ref(0)],
        vec![b"hello".to_vec()],
    );
    let r = vm.registers.get_ref(10, "").unwrap();
    assert_eq!(vm.heap.get_string(r).unwrap(), "hello");
}

#[test]
fn calldata_load_no_args_is_noop() {
    // With no args, registers should remain at their default (Int(0)).
    let vm = run_vm_with_args("CALLDATA_LOAD r5\nMOVE r10, 1", vec![], vec![]);
    assert_eq!(vm.registers.get_int(10, "").unwrap(), 1);
}

#[test]
fn calldata_load_at_high_register() {
    let vm = run_vm_with_args(
        "CALLDATA_LOAD r250",
        vec![Value::Int(7), Value::Int(8)],
        vec![],
    );
    assert_eq!(vm.registers.get_int(250, "").unwrap(), 7);
    assert_eq!(vm.registers.get_int(251, "").unwrap(), 8);
}

#[test]
fn calldata_len_and_copy_match_serialized_args() {
    let args = vec![Value::Int(42), Value::Bool(true), Value::Ref(0)];
    let arg_items = vec![b"hi".to_vec()];
    let expected = expected_calldata(&args, &arg_items);
    let vm = run_vm_with_args("CALLDATA_LEN r10\nCALLDATA_COPY 64", args, arg_items);
    assert!(!expected.is_empty());
    assert_eq!(vm.registers.get_int(10, "").unwrap(), expected.len() as i64);
    assert_eq!(
        &vm.exec_memory()[64..64 + expected.len()],
        expected.as_slice()
    );
}

// ==================== host_func_argc ====================

#[test]
fn host_func_argc_known_functions() {
    assert_eq!(host_func_argc("caller"), 0);
    assert_eq!(host_func_argc("len"), 1);
    assert_eq!(host_func_argc("slice"), 3);
    assert_eq!(host_func_argc("concat"), 2);
    assert_eq!(host_func_argc("compare"), 2);
}

#[test]
#[should_panic]
fn host_func_argc_unknown_panics() {
    host_func_argc("nonexistent");
}

#[test]
fn expand_mem_test() {
    let mut vm = run_vm("");
    vm.expand_memory(0, 8).unwrap();
    assert_eq!(vm.exec_memory().len(), 64);
}

#[test]
fn memstore_test() {
    let code = r#"
        MEM_STORE 0, 1
        MEM_STORE 64, 2
        "#;
    let vm = run_vm(code);
    assert_eq!(vm.exec_memory().len(), 128);
}

#[test]
fn memload_test() {
    let code = r#"
        MEM_STORE 0, 12
        MEM_LOAD r10, 0
        "#;
    let vm = run_vm(code);
    assert_eq!(vm.exec_memory().len(), 64);
    assert_eq!(&vm.exec_memory()[..8], &12i64.to_le_bytes());
    assert_eq!(vm.registers.get(10).unwrap(), &Value::Int(12));
}

#[test]
fn memset_test() {
    let code = r#"
        MEM_SET 0, 64, 255
        "#;
    let vm = run_vm(code);
    assert_eq!(vm.exec_memory().len(), 512);
    assert_eq!(&vm.exec_memory()[..64], &[255u8; 64]);
}

#[test]
fn memcpy_test() {
    let code = r#"
        MEM_SET 0, 64, 255
        MEM_COPY 128, 0, 64
        "#;
    let vm = run_vm(code);
    assert_eq!(&vm.exec_memory()[128..192], &[255u8; 64]);
}

#[test]
fn memload_oob() {
    let err = run_expect_err("MEM_LOAD r10, 0");
    assert!(matches!(err, VMError::MemoryOOBRead { .. }));
}

#[test]
fn memcpy_overlapping_forward() {
    let code = r#"
        MEM_SET 0, 24, 0
        MEM_SET 8, 16, 171
        MEM_COPY 0, 8, 16
        "#;
    let vm = run_vm(code);
    assert_eq!(&vm.exec_memory()[0..16], &[171u8; 16]);
}

#[test]
fn memcpy_overlapping_backward() {
    let code = r#"
        MEM_SET 0, 16, 205
        MEM_COPY 8, 0, 16
        "#;
    let vm = run_vm(code);
    assert_eq!(&vm.exec_memory()[8..24], &[205u8; 16]);
}

#[test]
fn memcpy_oob_read() {
    let code = r#"
        MEM_SET 0, 8, 0
        MEM_COPY 16, 64, 8
        "#;
    assert!(matches!(
        run_expect_err(code),
        VMError::MemoryOOBRead { .. }
    ));
}

#[test]
fn memset_zero_length() {
    let vm = run_vm("MEM_SET 0, 0, 255");
    assert_eq!(vm.exec_memory().len(), 0);
}

#[test]
fn memcpy_zero_length() {
    let code = r#"
        MEM_SET 0, 8, 170
        MEM_COPY 0, 0, 0
        "#;
    let vm = run_vm(code);
    assert_eq!(&vm.exec_memory()[..8], &[170u8; 8]);
}

#[test]
fn expand_memory_alignment() {
    // Storing at offset 1 should expand by (9 needed bytes) * WORD_SIZE = 72
    let mut vm = run_vm("");
    vm.expand_memory(1, 8).unwrap();
    assert_eq!(vm.exec_memory().len(), 72);
}

#[test]
fn memset_hex_addr_and_len() {
    let code = "MEM_SET 0x10, 0x20, 0xAB";
    let vm = run_vm(code);
    assert_eq!(vm.exec_memory().len(), 384);
    assert_eq!(&vm.exec_memory()[0x10..0x30], &[0xABu8; 0x20]);
}

#[test]
fn memcpy_hex_params() {
    let code = r#"
        MEM_SET 0x00, 0x10, 0xFF
        MEM_COPY 0x20, 0x00, 0x10
        "#;
    let vm = run_vm(code);
    assert_eq!(&vm.exec_memory()[0x20..0x30], &[0xFFu8; 0x10]);
}

#[test]
fn memstore_hex_addr() {
    let code = "MEM_STORE 0x40, 0x1234";
    let vm = run_vm(code);
    assert_eq!(vm.exec_memory().len(), 576);
    assert_eq!(&vm.exec_memory()[0x40..0x48], &0x1234i64.to_le_bytes());
}

#[test]
fn memload_hex_addr() {
    let code = r#"
        MEM_STORE 0x08, 0xDEAD
        MEM_LOAD r10, 0x08
        "#;
    let vm = run_vm(code);
    assert_eq!(vm.registers.get(10).unwrap(), &Value::Int(0xDEAD));
}

#[test]
fn memload_8u_hex_addr() {
    let code = r#"
        MEM_STORE 0x08, 0xDEAD
        MEM_LOAD_8U r10, 0x08
        "#;
    let vm = run_vm(code);
    assert_eq!(vm.registers.get(10).unwrap(), &Value::Int(0xAD));
}

#[test]
fn memload_8s_hex_addr() {
    let code = r#"
        MEM_STORE 0x08, 0xDEAD
        MEM_LOAD_8S r10, 0x08
        "#;
    let vm = run_vm(code);

    assert_eq!(
        vm.registers.get(10).unwrap(),
        &Value::Int(0xFFFFFFFFFFFFFFADu64 as i64)
    );
}

#[test]
fn memload_8s_hex_addr2() {
    let code = r#"
        MEM_STORE 0x08, 0xDE7D
        MEM_LOAD_8S r10, 0x08
        "#;
    let vm = run_vm(code);

    assert_eq!(vm.registers.get(10).unwrap(), &Value::Int(0x7Du64 as i64));
}

// ==================== 16-bit memory loads ====================

#[test]
fn memload_16u_zero_extends() {
    let code = r#"
        MEM_STORE 0x00, 0xFFFF
        MEM_LOAD_16U r10, 0x00
        "#;
    let vm = run_vm(code);
    assert_eq!(vm.registers.get(10).unwrap(), &Value::Int(0xFFFF));
}

#[test]
fn memload_16s_sign_extends_negative() {
    let code = r#"
        MEM_STORE 0x00, 0x8000
        MEM_LOAD_16S r10, 0x00
        "#;
    let vm = run_vm(code);
    assert_eq!(
        vm.registers.get(10).unwrap(),
        &Value::Int(0xFFFFFFFFFFFF8000u64 as i64)
    );
}

#[test]
fn memload_16s_no_extend_positive() {
    let code = r#"
        MEM_STORE 0x00, 0x7FFF
        MEM_LOAD_16S r10, 0x00
        "#;
    let vm = run_vm(code);
    assert_eq!(vm.registers.get(10).unwrap(), &Value::Int(0x7FFF));
}

// ==================== 32-bit memory loads ====================

#[test]
fn memload_32u_zero_extends() {
    let code = r#"
        MEM_STORE 0x00, 0xFFFFFFFF
        MEM_LOAD_32U r10, 0x00
        "#;
    let vm = run_vm(code);
    assert_eq!(vm.registers.get(10).unwrap(), &Value::Int(0xFFFFFFFF));
}

#[test]
fn memload_32s_sign_extends_negative() {
    let code = r#"
        MEM_STORE 0x00, 0x80000000
        MEM_LOAD_32S r10, 0x00
        "#;
    let vm = run_vm(code);
    assert_eq!(
        vm.registers.get(10).unwrap(),
        &Value::Int(0xFFFFFFFF80000000u64 as i64)
    );
}

#[test]
fn memload_32s_no_extend_positive() {
    let code = r#"
        MEM_STORE 0x00, 0x7FFFFFFF
        MEM_LOAD_32S r10, 0x00
        "#;
    let vm = run_vm(code);
    assert_eq!(vm.registers.get(10).unwrap(), &Value::Int(0x7FFFFFFF));
}

// ==================== Register-based addressing ====================

#[test]
fn memstore_register_addr() {
    let code = r#"
        MOVE r1, 0x10
        MEM_STORE r1, 0xABCD
        MEM_LOAD r10, 0x10
        "#;
    let vm = run_vm(code);
    assert_eq!(vm.registers.get(10).unwrap(), &Value::Int(0xABCD));
}

#[test]
fn memload_register_addr() {
    let code = r#"
        MEM_STORE 0x20, 0x1234
        MOVE r1, 0x20
        MEM_LOAD r10, r1
        "#;
    let vm = run_vm(code);
    assert_eq!(vm.registers.get(10).unwrap(), &Value::Int(0x1234));
}

#[test]
fn memcpy_register_addrs() {
    let code = r#"
        MEM_SET 0x00, 8, 0xAA
        MOVE r1, 0x10
        MOVE r2, 0x00
        MOVE r3, 8
        MEM_COPY r1, r2, r3
        MEM_LOAD r10, 0x10
        "#;
    let vm = run_vm(code);
    assert_eq!(
        vm.registers.get(10).unwrap(),
        &Value::Int(i64::from_le_bytes([0xAA; 8]))
    );
}

#[test]
fn memset_register_addrs() {
    let code = r#"
        MOVE r1, 0x08
        MOVE r2, 8
        MEM_SET r1, r2, 0xFF
        MEM_LOAD r10, 0x08
        "#;
    let vm = run_vm(code);
    assert_eq!(
        vm.registers.get(10).unwrap(),
        &Value::Int(i64::from_le_bytes([0xFF; 8]))
    );
}

#[test]
fn memload_8u_register_addr() {
    let code = r#"
        MEM_STORE 0x00, 0xABCD
        MOVE r1, 0x00
        MEM_LOAD_8U r10, r1
        "#;
    let vm = run_vm(code);
    assert_eq!(vm.registers.get(10).unwrap(), &Value::Int(0xCD));
}

#[test]
fn memload_16s_register_addr() {
    let code = r#"
        MEM_STORE 0x00, 0x8001
        MOVE r1, 0x00
        MEM_LOAD_16S r10, r1
        "#;
    let vm = run_vm(code);
    assert_eq!(
        vm.registers.get(10).unwrap(),
        &Value::Int(0xFFFFFFFFFFFF8001u64 as i64)
    );
}

// ==================== CMOVE instruction ====================

#[test]
fn cmove_true_condition() {
    let code = r#"
        MOVE r3, true
        MOVE r1, 100
        MOVE r2, 200
        CMOVE r4, r3, r1, r2
        "#;
    let vm = run_vm(code);
    assert_eq!(vm.registers.get(4).unwrap(), &Value::Int(100));
}

#[test]
fn cmove_false_condition() {
    let code = r#"
        MOVE r3, false
        MOVE r1, 100
        MOVE r2, 200
        CMOVE r4, r3, r1, r2
        "#;
    let vm = run_vm(code);
    assert_eq!(vm.registers.get(4).unwrap(), &Value::Int(200));
}

#[test]
fn cmove_nonzero_int_is_true() {
    let code = r#"
        MOVE r3, 1
        MOVE r1, 100
        MOVE r2, 200
        CMOVE r4, r3, r1, r2
        "#;
    let vm = run_vm(code);
    assert_eq!(vm.registers.get(4).unwrap(), &Value::Int(100));
}

#[test]
fn cmove_zero_int_is_false() {
    let code = r#"
        MOVE r3, 0
        MOVE r1, 100
        MOVE r2, 200
        CMOVE r4, r3, r1, r2
        "#;
    let vm = run_vm(code);
    assert_eq!(vm.registers.get(4).unwrap(), &Value::Int(200));
}

#[test]
fn cmove_negative_int_is_true() {
    let code = r#"
        MOVE r3, -1
        MOVE r1, 100
        MOVE r2, 200
        CMOVE r4, r3, r1, r2
        "#;
    let vm = run_vm(code);
    assert_eq!(vm.registers.get(4).unwrap(), &Value::Int(100));
}

#[test]
fn cmove_register_condition_true() {
    let code = r#"
        MOVE r3, 5
        MOVE r1, 100
        MOVE r2, 200
        CMOVE r4, r3, r1, r2
        "#;
    let vm = run_vm(code);
    assert_eq!(vm.registers.get(4).unwrap(), &Value::Int(100));
}

#[test]
fn cmove_register_condition_false() {
    let code = r#"
        MOVE r3, 0
        MOVE r1, 100
        MOVE r2, 200
        CMOVE r4, r3, r1, r2
        "#;
    let vm = run_vm(code);
    assert_eq!(vm.registers.get(4).unwrap(), &Value::Int(200));
}

#[test]
fn cmove_bool_register_condition() {
    let code = r#"
        MOVE r3, true
        MOVE r1, 100
        MOVE r2, 200
        CMOVE r4, r3, r1, r2
        "#;
    let vm = run_vm(code);
    assert_eq!(vm.registers.get(4).unwrap(), &Value::Int(100));
}

#[test]
fn cmove_immediate_operands() {
    let code = "MOVE r3, true\nCMOVE r4, r3, 42, 99";
    let vm = run_vm(code);
    assert_eq!(vm.registers.get(4).unwrap(), &Value::Int(42));
}
