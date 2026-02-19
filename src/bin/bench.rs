//! VM benchmark binary.
//!
//! Measures assembly + execution time for representative contracts.
//! Run with: `cargo run --release --bin bench`

use std::time::{Duration, Instant};

use blockchain::types::hash::Hash;
use blockchain::virtual_machine::assembler::assemble_source;
use blockchain::virtual_machine::program::{DeployProgram, ExecuteProgram};
use blockchain::virtual_machine::state::State;
use blockchain::virtual_machine::vm::{BLOCK_GAS_LIMIT, ExecContext, VM, Value};

use std::collections::BTreeMap;

struct BenchState {
    data: BTreeMap<Hash, Vec<u8>>,
}

impl BenchState {
    fn new() -> Self {
        Self {
            data: BTreeMap::new(),
        }
    }
}

impl State for BenchState {
    fn contains_key(&self, key: Hash) -> bool {
        self.data.contains_key(&key)
    }
    fn get(&self, key: Hash) -> Option<Vec<u8>> {
        self.data.get(&key).cloned()
    }
    fn push(&mut self, key: Hash, value: Vec<u8>) {
        self.data.insert(key, value);
    }
    fn delete(&mut self, key: Hash) {
        self.data.remove(&key);
    }
}

const CTX: ExecContext = ExecContext {
    chain_id: 62845383663927,
    contract_id: Hash::zero(),
    caller: Hash::zero(),
};

// ---------------------------------------------------------------------------
// Benchmark harness
// ---------------------------------------------------------------------------

struct BenchResult {
    name: &'static str,
    iterations: u64,
    total: Duration,
    gas_used: u64,
    /// Estimated number of instructions executed per run (None to omit column).
    est_instructions: Option<u64>,
}

impl BenchResult {
    fn avg(&self) -> Duration {
        self.total / self.iterations as u32
    }

    fn print(&self) {
        let avg = self.avg();
        let ns_per_op = avg.as_nanos();
        let ns_per_instr = self
            .est_instructions
            .filter(|&n| n > 0)
            .map(|n| format!("{:>8.1}", ns_per_op as f64 / n as f64))
            .unwrap_or_else(|| "       -".to_string());
        println!(
            "  {:<30} {:>7} iters {:>10.3} us/iter {:>12} gas  {} ns/instr",
            self.name,
            self.iterations,
            ns_per_op as f64 / 1000.0,
            self.gas_used,
            ns_per_instr,
        );
    }
}

/// Runs `f` for at least `min_duration`, returning aggregated results.
fn bench<F>(
    name: &'static str,
    min_duration: Duration,
    est_instructions: Option<u64>,
    mut f: F,
) -> BenchResult
where
    F: FnMut() -> u64,
{
    // Warmup
    for _ in 0..5 {
        f();
    }

    let mut iterations = 0u64;
    let mut last_gas = 0u64;
    let start = Instant::now();
    while start.elapsed() < min_duration {
        last_gas = f();
        iterations += 1;
    }
    let total = start.elapsed();

    BenchResult {
        name,
        iterations,
        total,
        gas_used: last_gas,
        est_instructions,
    }
}

/// Assembles, deploys (runs init code), returns gas_used.
fn deploy_gas(prog: &DeployProgram) -> u64 {
    let mut vm =
        VM::new_deploy(prog.clone(), BLOCK_GAS_LIMIT, vec![], vec![]).expect("vm new failed");
    vm.run(&mut BenchState::new(), &CTX).expect("deploy failed");
    vm.gas_used()
}

// ---------------------------------------------------------------------------
// Benchmark definitions
// ---------------------------------------------------------------------------

const FACTORIAL_ASM: &str = r#"
__init__:
    MOVE r1, 5
    HALT

pub factorial(1, r1):
    INC r3
    __fact_loop:
        MUL r3, r3, r1
        DEC r1
        BGE r1, 1, __fact_loop
    MEM_STORE 0x00, r3
    RETURN 0x00, 8
"#;

const TIGHT_LOOP_ASM: &str = r#"
__init__:
    MOVE r1, 100000
    MOVE r2, 0
    __loop:
        INC r2
        DEC r1
        BGE r1, 1, __loop
    HALT
"#;

const ARITHMETIC_MIX_ASM: &str = r#"
__init__:
    MOVE r1, 10000
    MOVE r2, 1
    MOVE r3, 2
    MOVE r4, 3
    __loop:
        ADD r5, r2, r3
        MUL r6, r5, r4
        SUB r7, r6, r2
        DIV r8, r7, r3
        MOD r9, r8, r4
        SHL r2, r9, 1
        SHR r3, r6, 2
        ADD r4, r7, 1
        DEC r1
        BGE r1, 1, __loop
    HALT
"#;

const BRANCH_HEAVY_ASM: &str = r#"
__init__:
    MOVE r1, 50000
    MOVE r2, 0
    MOVE r3, 1
    __loop:
        BLT r2, r3, __inc
        __dec:
            DEC r2
            JUMP __cont
        __inc:
            INC r2
            INC r3
        __cont:
        DEC r1
        BGE r1, 1, __loop
    HALT
"#;

const CALL_OVERHEAD_ASM: &str = r#"
__init__:
    MOVE r1, 10000
    __loop:
        CALL noop_fn
        DEC r1
        BGE r1, 1, __loop
    HALT

noop_fn:
    RET
"#;

const MEMORY_ASM: &str = r#"
__init__:
    MOVE r1, 5000
    MOVE r2, 42
    __loop:
        MEM_STORE r1, r2
        MEM_LOAD r3, r1
        DEC r1
        BGE r1, 1, __loop
    HALT
"#;

// ---------------------------------------------------------------------------
// Estimated instruction counts per run (setup + N * body)
// ---------------------------------------------------------------------------

// factorial(N): dispatch(~2) + INC + N*(MUL+DEC+BGE) + MEM_STORE + RETURN
fn factorial_instrs(n: u64) -> u64 {
    2 + 1 + n * 3 + 2
}
// tight_loop: 2 MOVE + 100K*(INC+DEC+BGE) + HALT
const TIGHT_LOOP_INSTRS: u64 = 3 + 100_000 * 3;
// arithmetic_mix: 4 MOVE + 10K*(8 ALU + DEC + BGE) + HALT
const ARITH_MIX_INSTRS: u64 = 5 + 10_000 * 10;
// branch_heavy: 3 MOVE + 50K*(BLT + 2 body + DEC + BGE) + HALT
const BRANCH_INSTRS: u64 = 4 + 50_000 * 5;
// call_overhead: MOVE + 10K*(CALL + RET + DEC + BGE) + HALT
const CALL_INSTRS: u64 = 2 + 10_000 * 4;
// memory: 2 MOVE + 5K*(MEM_STORE + MEM_LOAD + DEC + BGE) + HALT
const MEM_INSTRS: u64 = 3 + 5_000 * 4;

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() {
    let min = Duration::from_secs(2);

    println!("VM Benchmarks (each runs for >= 2s)\n");
    println!(
        "  {:<30} {:>7}       {:>14} {:>12}  {:>10}",
        "benchmark", "iters", "avg time", "gas/run", "ns/instr"
    );
    println!("  {}", "-".repeat(82));

    // Pre-assemble programs (assembly cost excluded from benchmark)
    let factorial_prog = assemble_source(FACTORIAL_ASM).expect("asm");
    let tight_prog = assemble_source(TIGHT_LOOP_ASM).expect("asm");
    let arith_prog = assemble_source(ARITHMETIC_MIX_ASM).expect("asm");
    let branch_prog = assemble_source(BRANCH_HEAVY_ASM).expect("asm");
    let call_prog = assemble_source(CALL_OVERHEAD_ASM).expect("asm");
    let mem_prog = assemble_source(MEMORY_ASM).expect("asm");

    // 1. Factorial variants
    for &n in &[10u64, 100, 1000] {
        let name: &'static str = match n {
            10 => "factorial(10)",
            100 => "factorial(100)",
            1000 => "factorial(1000)",
            _ => unreachable!(),
        };
        let prog = factorial_prog.clone();
        let r = bench(name, min, Some(factorial_instrs(n)), || {
            let exec = ExecuteProgram::new(
                Hash::zero(),
                0, // only one pub fn: "factorial" = selector 0
                vec![Value::Int(n as i64)],
                vec![],
            );
            let mut vm = VM::new_execute(exec, prog.clone(), BLOCK_GAS_LIMIT).expect("exec");
            vm.run(&mut BenchState::new(), &CTX).expect("run");
            vm.gas_used()
        });
        r.print();
    }

    // 2. Tight loop (100K iterations)
    let r = bench("tight_loop(100K)", min, Some(TIGHT_LOOP_INSTRS), || {
        deploy_gas(&tight_prog)
    });
    r.print();

    // 3. Arithmetic mix (10K iterations)
    let r = bench("arithmetic_mix(10K)", min, Some(ARITH_MIX_INSTRS), || {
        deploy_gas(&arith_prog)
    });
    r.print();

    // 4. Branch-heavy (50K iterations)
    let r = bench("branch_heavy(50K)", min, Some(BRANCH_INSTRS), || {
        deploy_gas(&branch_prog)
    });
    r.print();

    // 5. CALL overhead (10K calls)
    let r = bench("call_overhead(10K)", min, Some(CALL_INSTRS), || {
        deploy_gas(&call_prog)
    });
    r.print();

    // 6. Memory load/store (5K iterations)
    let r = bench("mem_load_store(5K)", min, Some(MEM_INSTRS), || {
        deploy_gas(&mem_prog)
    });
    r.print();

    println!();
}
