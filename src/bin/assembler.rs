//! Assembly to bytecode compiler CLI.
//!
//! Reads assembly source files and compiles them to executable bytecode.
//!
//! # Usage
//! ```text
//! assembler <input.asm> [OPTIONS]
//! ```
//!
//! # Arguments
//! - `input.asm`: Assembly source file to compile
//!
//! # Options
//! - `-o, --output <file>`: Optional output file path
//! - `-a, --audit [file]`: Print in-place audit view (or write to file)
//! - `-p, --predict [price] [func(args)...]`: Estimate gas costs (price defaults to 1)
//!
//! # Gas Prediction
//! The `-p` flag enables gas cost estimation for:
//! - **Deployment**: Always predicted when `-p` is used
//! - **Execution**: Predicted only for explicitly specified function calls
//!
//! Function call syntax: `func(arg1,arg2,...)` where args are integers.
//! Public functions are ordered alphabetically for the dispatcher.
//!
//! # Examples
//! ```text
//! assembler program.asm
//! assembler program.asm -o output.bin
//! assembler program.asm -p
//! assembler program.asm -p 100 factorial(5)
//! ```

use blockchain::core::blockchain::Blockchain;
use blockchain::core::transaction::TransactionType;
use blockchain::core::validator::BlockValidator;
use blockchain::storage::rocksdb_storage::RocksDbStorage;
use blockchain::storage::state_store::{StateStore, VmStorage};
use blockchain::storage::state_view::{StateView, StateViewProvider};
use blockchain::types::hash::Hash;
use blockchain::utils::log::SHOW_TIMESTAMP;
use blockchain::virtual_machine::assembler::{
    assemble_file, assemble_file_audit, extract_label_data,
};
use blockchain::virtual_machine::program::ExecuteProgram;
use blockchain::virtual_machine::state::OverlayState;
use blockchain::virtual_machine::vm::{BLOCK_GAS_LIMIT, ExecContext, GasCategory, VM, Value};
use blockchain::{error, info, warn};
use std::env;
use std::fs;
use std::path::Path;
use std::process;
use std::sync::atomic::Ordering;
use std::time::Instant;

struct EmptyStorage;

impl StateStore for EmptyStorage {
    fn preview_root(&self, _: &[(Hash, Option<Vec<u8>>)]) -> Hash {
        Hash::zero()
    }

    fn apply_batch(&self, _: Vec<(Hash, Option<Vec<u8>>)>) {}

    fn state_root(&self) -> Hash {
        Hash::zero()
    }
}

impl VmStorage for EmptyStorage {
    fn contains_key(&self, _: Hash) -> bool {
        false
    }
    fn get(&self, _: Hash) -> Option<Vec<u8>> {
        None
    }
}

impl StateViewProvider for EmptyStorage {
    fn state_view(&self) -> StateView<'_, Self> {
        StateView::new(self)
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 || args[1] == "--help" || args[1] == "-h" {
        print_usage(&args[0]);
        process::exit(if args.len() < 2 { 1 } else { 0 });
    }

    let input_path = &args[1];
    let mut output_path: Option<String> = None;
    let mut audit_output_path: Option<String> = None;
    let mut audit = false;
    let mut predict = false;
    let mut gas_price = 0u64;
    let mut predict_calls: Vec<(String, Vec<i64>)> = Vec::new();

    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            k @ ("--output" | "-o") => {
                i += 1;
                if i >= args.len() {
                    error!("{k} requires an argument");
                    process::exit(1);
                }
                output_path = Some(args[i].clone());
                i += 1;
            }
            "--audit" | "-a" => {
                audit = true;
                i += 1;
                // Optional output audit file path.
                if i < args.len() && !args[i].starts_with('-') && !args[i].contains('(') {
                    audit_output_path = Some(args[i].clone());
                    i += 1;
                }
            }
            "--predict" | "-p" => {
                predict = true;
                i += 1;
                // Check if next arg exists and is a valid number (gas price)
                if i < args.len() && !args[i].starts_with('-') && !args[i].contains('(') {
                    gas_price = args[i].parse::<u64>().unwrap_or_else(|_| {
                        error!("Invalid gas price: '{}' is not a valid number", args[i]);
                        process::exit(1);
                    });
                    if gas_price == 0 {
                        error!("Gas price must be greater than 0");
                        process::exit(1);
                    }
                    i += 1;
                } else {
                    gas_price = 1;
                }
                // Collect function calls: func(arg1,arg2,...)
                while i < args.len() && !args[i].starts_with('-') {
                    if let Some((name, args_str)) = parse_function_call(&args[i]) {
                        predict_calls.push((name, args_str));
                    } else {
                        error!(
                            "Invalid function call syntax: '{}'. Expected: func(arg1,arg2,...)",
                            args[i]
                        );
                        process::exit(1);
                    }
                    i += 1;
                }
            }
            other => {
                error!("Unexpected argument: {}\n", other);
                print_usage(&args[0]);
                process::exit(1);
            }
        }
    }

    if !Path::new(input_path).exists() {
        error!("Input file does not exist: {}", input_path);
        process::exit(1);
    }

    if audit && output_path.is_some() {
        error!("--audit/-a cannot be combined with --output/-o");
        process::exit(1);
    }

    if let Some(ref path) = output_path
        && let Some(parent) = Path::new(&path).parent()
        && !parent.as_os_str().is_empty()
        && !parent.exists()
    {
        error!("Output directory does not exist: {}", parent.display());
        process::exit(1);
    }

    if let Some(ref path) = audit_output_path
        && let Some(parent) = Path::new(&path).parent()
        && !parent.as_os_str().is_empty()
        && !parent.exists()
    {
        error!(
            "Audit output directory does not exist: {}",
            parent.display()
        );
        process::exit(1);
    }

    SHOW_TIMESTAMP.store(false, Ordering::Relaxed);

    if audit {
        let audit_listing = match assemble_file_audit(input_path) {
            Ok(v) => v,
            Err(e) => {
                error!("Assembly audit failed: {}", e);
                process::exit(1);
            }
        };

        if let Some(path) = audit_output_path {
            if let Err(e) = fs::write(&path, audit_listing.as_bytes()) {
                error!("Failed to write audit file: {}", e);
                process::exit(1);
            }
            info!("Wrote audit listing to {}", path);
        } else {
            println!("{audit_listing}");
        }
        if !predict {
            return;
        }
    }

    let assemble_start = Instant::now();
    let program = match assemble_file(input_path) {
        Ok(p) => p,
        Err(e) => {
            error!("Assembly failed: {}", e);
            process::exit(1);
        }
    };
    let assemble_elapsed = assemble_start.elapsed();

    let program_bytes = program.to_bytes();

    if let Some(ref path) = output_path
        && let Err(e) = fs::write(path, program_bytes.as_slice())
    {
        error!("Failed to write output file: {}", e);
        process::exit(1);
    }

    match output_path {
        None => {
            info!(
                "Assembled {} ({} bytes) in {:?}",
                input_path,
                program_bytes.len(),
                assemble_elapsed
            );
        }
        Some(ref path) => {
            info!(
                "Assembled {} -> {} ({} bytes) in {:?}",
                input_path,
                path,
                program_bytes.len(),
                assemble_elapsed
            );
        }
    }

    if predict {
        let ms = EmptyStorage {};
        let base = ms.state_view();
        let ctx = ExecContext {
            chain_id: 0,
            contract_id: Hash::zero(),
            caller: Hash::zero(),
        };

        // === Deployment cost prediction ===
        let deploy_intrinsic = Blockchain::<BlockValidator, RocksDbStorage>::intrinsic_gas_units(
            TransactionType::DeployContract,
            &program_bytes,
        );

        if deploy_intrinsic > BLOCK_GAS_LIMIT {
            error!(
                "Intrinsic gas ({}) exceeds transaction limit ({})",
                deploy_intrinsic, BLOCK_GAS_LIMIT
            );
            process::exit(1);
        }

        let mut vm = VM::new_deploy(program.clone(), BLOCK_GAS_LIMIT - deploy_intrinsic)
            .unwrap_or_else(|e| {
                error!("{e}");
                process::exit(1)
            });

        let mut overlay = OverlayState::new(&base);
        vm.run(&mut overlay, &ctx)
            .unwrap_or_else(|_| process::exit(1));

        let mut deploy_profile = vm.gas_profile();
        deploy_profile.add(GasCategory::Intrinsic, deploy_intrinsic);
        print_gas_profile(&deploy_profile, "Deployment Gas Profile", gas_price);

        // === Execution cost prediction for specified functions ===
        if !predict_calls.is_empty() {
            // Read source to extract public function names for index resolution
            let source = fs::read_to_string(input_path).unwrap_or_else(|e| {
                error!("Failed to read source file: {}", e);
                process::exit(1);
            });
            let mut insert_point = 0usize;
            let public_functions: Vec<&str> = extract_label_data(&source, &mut insert_point)
                .unwrap()
                .0
                .iter()
                .copied()
                .collect();

            // Validate and build list of (fn_name, fn_index, args) to predict
            let mut calls_to_predict: Vec<(String, usize, Vec<i64>)> = Vec::new();
            for (name, args) in &predict_calls {
                if let Some(idx) = public_functions.iter().position(|f| f == name) {
                    calls_to_predict.push((name.clone(), idx, args.clone()));
                } else {
                    error!(
                        "Function '{}' not found. Available: {}",
                        name,
                        public_functions.join(", ")
                    );
                    process::exit(1);
                }
            }

            for (fn_name, fn_idx, user_args) in calls_to_predict {
                // Build arguments from user-provided values only
                let args: Vec<Value> = user_args.iter().map(|&v| Value::Int(v)).collect();

                let exec_program = ExecuteProgram::new(Hash::zero(), fn_idx as i64, args, vec![]);
                let exec_data = exec_program.to_bytes();

                let exec_intrinsic =
                    Blockchain::<BlockValidator, RocksDbStorage>::intrinsic_gas_units(
                        TransactionType::InvokeContract,
                        &exec_data,
                    );

                if exec_intrinsic > BLOCK_GAS_LIMIT {
                    warn!(
                        "Function '{}': intrinsic gas ({}) exceeds limit, skipping",
                        fn_name, exec_intrinsic
                    );
                    continue;
                }

                let exec_start = Instant::now();
                let mut vm = VM::new_execute(
                    exec_program,
                    program.clone(),
                    BLOCK_GAS_LIMIT - exec_intrinsic,
                )
                .unwrap_or_else(|e| {
                    warn!("Function '{}': failed to create VM: {}", fn_name, e);
                    process::exit(1)
                });

                let mut overlay = OverlayState::new(&base);
                if let Err(e) = vm.run(&mut overlay, &ctx) {
                    warn!("Function '{}': execution failed: {}", fn_name, e);
                    continue;
                }
                let exec_elapsed = exec_start.elapsed();

                let mut exec_profile = vm.gas_profile();
                exec_profile.add(GasCategory::Intrinsic, exec_intrinsic);

                // Format title with arguments if provided
                let args_str = if user_args.is_empty() {
                    String::new()
                } else {
                    user_args
                        .iter()
                        .map(|v| v.to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                };
                print_gas_profile(
                    &exec_profile,
                    &format!(
                        "Estimted {}({}) in {:?}, Gas Profile",
                        fn_name, args_str, exec_elapsed
                    ),
                    gas_price,
                );
            }
        }

        warn!("Actual costs will depend on chain state and function arguments.");
    }
}

/// Parses a function call specification like "func(1,2,3)" or "func()".
///
/// Returns the function name and a vector of i64 arguments.
fn parse_function_call(s: &str) -> Option<(String, Vec<i64>)> {
    let open = s.find('(')?;
    let close = s.rfind(')')?;
    if close <= open || close != s.len() - 1 {
        return None;
    }

    let name = s[..open].trim().to_string();
    if name.is_empty() {
        return None;
    }

    let args_str = s[open + 1..close].trim();
    let args = if args_str.is_empty() {
        Vec::new()
    } else {
        args_str
            .split(',')
            .map(|a| {
                a.trim()
                    .parse::<i64>()
                    .map_err(|_| format!("invalid argument: {}", a))
            })
            .collect::<Result<Vec<_>, _>>()
            .ok()?
    };

    Some((name, args))
}

fn format_with_commas(n: u64) -> String {
    let s = n.to_string();
    let mut result = String::with_capacity(s.len() + s.len() / 3);
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            result.push(',');
        }
        result.push(c);
    }
    result
}

/// Prints a gas profile breakdown to stdout.
fn print_gas_profile(
    profile: &blockchain::virtual_machine::vm::GasProfile,
    title: &str,
    gas_price: u64,
) {
    let total_u = profile.total();
    let total = total_u as f64;

    let cat_w = 2 + profile
        .iter()
        .map(|(c, _)| c.as_str().chars().count())
        .max()
        .unwrap_or(0)
        .max("total".chars().count());

    let amt_w = profile
        .iter()
        .map(|(_, a)| format_with_commas(a).chars().count())
        .max()
        .unwrap_or(0)
        .max(format_with_commas(total_u).chars().count());

    let dash_w = cat_w + 1 + amt_w + 2 + "( 100.0%)".len();

    println!("\n{title}:");
    println!("{}", "-".repeat(dash_w));

    let mut entries: Vec<_> = profile.iter().filter(|(_, amount)| *amount > 0).collect();
    entries.sort_by(|a, b| b.1.cmp(&a.1));

    for (category, amount) in entries {
        let percent = if total > 0.0 {
            (amount as f64 / total) * 100.0
        } else {
            0.0
        };

        let line = format!(
            "{:<cat_w$} {:>amt_w$} ({:>5.1}%)",
            category.as_str(),
            format_with_commas(amount),
            percent,
            cat_w = cat_w,
            amt_w = amt_w,
        );
        println!("{line}");
    }

    println!("{}", "-".repeat(dash_w));

    let total_line = format!(
        "{:<cat_w$} {:>amt_w$} ({:>5.1}%)",
        "total",
        format_with_commas(total_u),
        100.0,
        cat_w = cat_w,
        amt_w = amt_w,
    );
    println!("{total_line}");

    info!(
        "Estimated cost: {}",
        format_with_commas(total_u * gas_price)
    );
}

const USAGE: &str = "\
Bytecode Assembler

USAGE:
    {program} <input.asm> [OPTIONS]

ARGS:
    <input.asm>    Assembly source file to bytecode

OPTIONS:
    -o, --output <file>                   Optional output file path
    -a, --audit [file]                    Print in-place audit view
    -p, --predict [price] [func(args...)...] Estimate gas costs
    -h, --help                            Print this help message

DESCRIPTION:
    The -p/--predict option estimates gas costs for:
    - Deployment: always predicted when -p is used
    - Execution: predicted only for explicitly specified function calls

    Function call syntax: func(arg1,arg2,...) where args are integers.
    Public functions are ordered alphabetically for the dispatcher.

EXAMPLES:
    # Compile to default output name
    {program} program.asm

    # Compile and save the output
    {program} program.asm -o output.bin

    # Print audit listing to stdout
    {program} program.asm -a

    # Write audit listing to file
    {program} program.asm --audit audit.txt

    # Predict deployment only (price = 1)
    {program} program.asm -p

    # Predict deployment only with custom price
    {program} program.asm -p 100

    # Predict deployment + specific function execution
    {program} program.asm -p 100 'factorial(5)'

    # Predict deployment + multiple function executions
    {program} program.asm -p 100 'factorial(5)' 'factorial(10)'
";

fn print_usage(program: &str) {
    info!("{}", USAGE.replace("{program}", program));
}
