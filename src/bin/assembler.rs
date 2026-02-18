//! Assembly to bytecode compiler CLI.
//!
//! Reads assembly source files and compiles them to executable bytecode.
//!
//! # Usage
//! ```text
//! assembler [COMMAND] <input.asm> [OPTIONS]
//! ```
//!
//! # Commands
//! - `build`: Compile and print summary (default, no file output)
//! - `output [file]`: Compile and write bytecode (defaults to `<input>.bin`)
//! - `audit [file]`: Generate audit listing (defaults to `<input>.audit.txt`)
//! - `predict [price] [func(args)...]`: Estimate gas costs
//!
//! # Examples
//! ```text
//! assembler program.asm
//! assembler build program.asm
//! assembler output program.asm
//! assembler output program.asm out.bin
//! assembler audit program.asm
//! assembler audit program.asm out.txt
//! assembler predict program.asm 100 'transfer("addr",100)'
//! ```

use blockchain::core::blockchain::Blockchain;
use blockchain::core::transaction::TransactionType;
use blockchain::core::validator::BlockValidator;
use blockchain::storage::rocksdb_storage::RocksDbStorage;
use blockchain::storage::state_store::{StateStore, VmStorage};
use blockchain::storage::state_view::{StateView, StateViewProvider};
use blockchain::types::bytes::Bytes;
use blockchain::types::encoding::Encode;
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

/// Parsed function call arguments for gas prediction.
struct CallArgs {
    values: Vec<Value>,
    items: Vec<Vec<u8>>,
}

/// Parsed CLI command.
enum Command {
    /// Compile and print info, no file output.
    Build,
    /// Compile and write bytecode to file.
    Output { path: Option<String> },
    /// Generate and write audit listing to file.
    Audit { path: Option<String> },
    /// Estimate gas costs.
    Predict {
        gas_price: u64,
        calls: Vec<(String, CallArgs)>,
    },
}

/// Parses CLI arguments into input path and command.
///
/// Format: `assembler [COMMAND] <input.asm> [OPTIONS]`
/// Defaults to `build` if the first argument is not a known command.
fn parse_args(args: &[String]) -> (&str, Command) {
    if args.len() < 2 {
        print_usage(&args[0]);
        process::exit(1);
    }

    let (command_str, input_path, rest) = match args[1].as_str() {
        "help" => {
            print_usage(&args[0]);
            process::exit(0);
        }
        cmd @ ("build" | "output" | "audit" | "predict") => {
            if args.len() < 3 {
                error!("'{}' requires an input file", cmd);
                process::exit(1);
            }
            (cmd, &args[2], &args[3..])
        }
        _ => ("build", &args[1], &args[2..]),
    };

    if !Path::new(input_path.as_str()).exists() {
        error!("Input file does not exist: {}", input_path);
        process::exit(1);
    }

    match command_str {
        "build" => {
            if !rest.is_empty() {
                error!("'build' takes no arguments");
                process::exit(1);
            }
            (input_path, Command::Build)
        }
        "output" => {
            let path = parse_optional_path(rest);
            (input_path, Command::Output { path })
        }
        "audit" => {
            let path = parse_optional_path(rest);
            (input_path, Command::Audit { path })
        }
        "predict" => {
            let (gas_price, calls) = parse_predict_args(rest);
            (input_path, Command::Predict { gas_price, calls })
        }
        _ => unreachable!(),
    }
}

/// Parses an optional file path from remaining args. Exits on unexpected extra args.
fn parse_optional_path(args: &[String]) -> Option<String> {
    if args.is_empty() {
        return None;
    }
    if args.len() > 1 {
        error!("Unexpected argument: {}", args[1]);
        process::exit(1);
    }
    let path = &args[0];
    if let Some(parent) = Path::new(path.as_str()).parent()
        && !parent.as_os_str().is_empty()
        && !parent.exists()
    {
        error!("Output directory does not exist: {}", parent.display());
        process::exit(1);
    }
    Some(path.clone())
}

/// Parses predict subcommand args: `[price] [func(args)...]`.
fn parse_predict_args(args: &[String]) -> (u64, Vec<(String, CallArgs)>) {
    let mut i = 0;

    let gas_price = if i < args.len() && !args[i].contains('(') {
        let price = args[i].parse::<u64>().unwrap_or_else(|_| {
            error!("Invalid gas price: '{}' is not a valid number", args[i]);
            process::exit(1);
        });
        if price == 0 {
            error!("Gas price must be greater than 0");
            process::exit(1);
        }
        i += 1;
        price
    } else {
        1
    };

    let mut calls = Vec::new();
    while i < args.len() {
        if let Some(call) = parse_function_call(&args[i]) {
            calls.push(call);
        } else {
            error!(
                "Invalid function call syntax: '{}'. Expected: func(arg1,arg2,...)",
                args[i]
            );
            process::exit(1);
        }
        i += 1;
    }

    (gas_price, calls)
}

fn main() {
    SHOW_TIMESTAMP.store(false, Ordering::Relaxed);

    let args: Vec<String> = env::args().collect();
    let (input_path, command) = parse_args(&args);

    match command {
        Command::Build => cmd_build(input_path),
        Command::Output { path } => cmd_output(input_path, path),
        Command::Audit { path } => cmd_audit(input_path, path),
        Command::Predict { gas_price, calls } => cmd_predict(input_path, gas_price, calls),
    }
}

/// Derives output path by replacing the file extension.
fn output_path_for(input: &str, new_ext: &str) -> String {
    let p = Path::new(input);
    p.with_extension(new_ext).display().to_string()
}

/// Result of assembling a source file.
struct AssembleResult {
    program: blockchain::virtual_machine::program::DeployProgram,
    program_bytes: Vec<u8>,
    public_functions: Vec<String>,
}

/// Assembles a source file, logs build info, and returns the result.
fn assemble(input_path: &str) -> AssembleResult {
    let assemble_start = Instant::now();
    let program = match assemble_file(input_path) {
        Ok(p) => p,
        Err(e) => {
            error!("Assembly failed: {}", e);
            process::exit(1);
        }
    };
    let elapsed = assemble_start.elapsed();

    let program_bytes = program.to_vec();

    let source = fs::read_to_string(input_path).unwrap_or_else(|e| {
        error!("Failed to read source file: {}", e);
        process::exit(1);
    });
    let mut insert_point = 0usize;
    let public_functions: Vec<String> = extract_label_data(&source, &mut insert_point)
        .unwrap()
        .names
        .into_iter()
        .map(|s| s.to_string())
        .collect();

    let code_size = program.init_code.len() + program.runtime_code.len();
    let heap_size = program.memory.len();
    info!(
        "Assembled {} (code: {} + heap: {} + encoding: 24 = {} bytes) in {:?}",
        input_path,
        code_size,
        heap_size,
        program_bytes.len(),
        elapsed
    );

    AssembleResult {
        program,
        program_bytes,
        public_functions,
    }
}

/// Compiles assembly and prints summary. No file output.
fn cmd_build(input_path: &str) {
    let result = assemble(input_path);
    log_pub_fn_mapping(&result.public_functions);
}

/// Compiles assembly and writes bytecode to file.
///
/// Defaults to `<input>.bin` if no path is given.
fn cmd_output(input_path: &str, path: Option<String>) {
    let result = assemble(input_path);
    let output = path.unwrap_or_else(|| output_path_for(input_path, "bin"));

    if let Err(e) = fs::write(&output, result.program_bytes.as_slice()) {
        error!("Failed to write output file: {}", e);
        process::exit(1);
    }
    info!("Wrote bytecode to {}", output);
}

/// Generates audit listing and writes it to file.
///
/// Defaults to `<input>.audit.txt` if no path is given.
fn cmd_audit(input_path: &str, path: Option<String>) {
    let _ = assemble(input_path);

    let audit_listing = match assemble_file_audit(input_path) {
        Ok(v) => v,
        Err(e) => {
            error!("Assembly audit failed: {}", e);
            process::exit(1);
        }
    };

    let output = path.unwrap_or_else(|| output_path_for(input_path, "audit.txt"));
    if let Err(e) = fs::write(&output, audit_listing.as_bytes()) {
        error!("Failed to write audit file: {}", e);
        process::exit(1);
    }
    info!("Wrote audit listing to {}", output);
}

/// Predicts gas costs for deployment and specified function calls.
fn cmd_predict(input_path: &str, gas_price: u64, predict_calls: Vec<(String, CallArgs)>) {
    let result = assemble(input_path);
    let public_functions = &result.public_functions;

    // Extract __init__ args if provided
    let mut runtime_calls = Vec::new();
    let mut init_args = CallArgs {
        values: Vec::new(),
        items: Vec::new(),
    };
    for (name, args) in predict_calls {
        if name == "__init__" {
            init_args = args;
        } else {
            runtime_calls.push((name, args));
        }
    }

    let ms = EmptyStorage {};
    let base = ms.state_view();
    let ctx = ExecContext {
        chain_id: 0,
        contract_id: Hash::zero(),
        caller: Hash::zero(),
    };

    let deploy_intrinsic = Blockchain::<BlockValidator, RocksDbStorage>::intrinsic_gas_units(
        TransactionType::DeployContract,
        &Bytes::new(result.program_bytes),
    );

    if deploy_intrinsic > BLOCK_GAS_LIMIT {
        error!(
            "Intrinsic gas ({}) exceeds transaction limit ({})",
            deploy_intrinsic, BLOCK_GAS_LIMIT
        );
        process::exit(1);
    }

    let mut vm = VM::new_deploy(
        result.program.clone(),
        BLOCK_GAS_LIMIT - deploy_intrinsic,
        init_args.values,
        init_args.items,
    )
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

    if !runtime_calls.is_empty() {
        let mut calls_to_predict: Vec<(String, usize, CallArgs)> = Vec::new();
        for (name, call_args) in runtime_calls {
            if let Some(idx) = public_functions.iter().position(|f| *f == name) {
                calls_to_predict.push((name, idx, call_args));
            } else {
                error!(
                    "Function '{}' not found. Available: {}",
                    name,
                    public_functions.join(", ")
                );
                process::exit(1);
            }
        }

        for (fn_name, fn_idx, call_args) in calls_to_predict {
            let args_display = format_call_args(&call_args);
            let exec_program = ExecuteProgram::new(
                Hash::zero(),
                fn_idx as i64,
                call_args.values,
                call_args.items,
            );
            let exec_data = exec_program.to_bytes();

            let exec_intrinsic = Blockchain::<BlockValidator, RocksDbStorage>::intrinsic_gas_units(
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
                result.program.clone(),
                BLOCK_GAS_LIMIT - exec_intrinsic,
            )
            .unwrap_or_else(|e| {
                warn!("Function '{}': failed to create VM: {}", fn_name, e);
                process::exit(1)
            });

            if let Err(e) = vm.run(&mut overlay, &ctx) {
                warn!("Function '{}': execution failed: {}", fn_name, e);
                continue;
            }
            let exec_elapsed = exec_start.elapsed();

            let mut exec_profile = vm.gas_profile();
            exec_profile.add(GasCategory::Intrinsic, exec_intrinsic);

            print_gas_profile(
                &exec_profile,
                &format!(
                    "Estimated {}({}) in {:?}, Gas Profile",
                    fn_name, args_display, exec_elapsed
                ),
                gas_price,
            );
        }
    }

    warn!("Actual costs will depend on chain state.");
}

fn log_pub_fn_mapping(functions: &[impl AsRef<str>]) {
    info!("Public function mapping:");
    eprintln!("{{");
    for i in 0..functions.len() {
        eprint!("  \"{}\": {i}", functions[i].as_ref());
        if i != functions.len() - 1 {
            eprintln!(",");
        } else {
            eprintln!();
        }
    }
    eprintln!("}}");
}

/// Parses a function call specification like `func(1,"hello",true)` or `func()`.
///
/// Supports integer, boolean, and double-quoted string arguments.
/// Strings are stored in `CallArgs::items` and referenced via `Value::Ref`.
fn parse_function_call(s: &str) -> Option<(String, CallArgs)> {
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
    if args_str.is_empty() {
        return Some((
            name,
            CallArgs {
                values: Vec::new(),
                items: Vec::new(),
            },
        ));
    }

    let mut values = Vec::new();
    let mut items: Vec<Vec<u8>> = Vec::new();

    for arg in args_str.split(',') {
        let arg = arg.trim();
        if arg == "true" {
            values.push(Value::Bool(true));
        } else if arg == "false" {
            values.push(Value::Bool(false));
        } else if let Some(s) = arg.strip_prefix('"').and_then(|a| a.strip_suffix('"')) {
            let idx = items.len() as u32;
            items.push(s.as_bytes().to_vec());
            values.push(Value::Ref(idx));
        } else if let Ok(v) = arg.parse::<i64>() {
            values.push(Value::Int(v));
        } else {
            return None;
        }
    }

    Some((name, CallArgs { values, items }))
}

/// Formats call arguments for display in gas profile titles.
fn format_call_args(args: &CallArgs) -> String {
    args.values
        .iter()
        .map(|v| match v {
            Value::Int(n) => n.to_string(),
            Value::Bool(b) => b.to_string(),
            Value::Ref(idx) => {
                if let Some(bytes) = args.items.get(*idx as usize) {
                    format!("\"{}\"", String::from_utf8_lossy(bytes))
                } else {
                    format!("@{idx}")
                }
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
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
    {program} [COMMAND] <input.asm> [OPTIONS]

ARGS:
    <input.asm>    Assembly source file

COMMANDS:
    help                                 Print this help message
    build                                Compile and print summary (default)
    output [file]                        Compile and write bytecode
    audit  [file]                        Generate audit listing
    predict [price] [func(args)...]      Estimate gas costs

DESCRIPTION:
    If no command is given, defaults to 'help' (no file output).

    Default output paths when no file is specified:
    - output:  <input>.bin
    - audit:   <input>.audit.txt

    The 'predict' command estimates gas costs for:
    - Deployment: always predicted
    - Execution: predicted only for explicitly specified function calls

    Function call syntax: func(arg1,arg2,...) where args can be:
    - Integers: 42, -1, 0
    - Booleans: true, false
    - Strings:  \"hello\"
    Public functions are ordered alphabetically for the dispatcher.

EXAMPLES:
    {program} program.asm
    {program} build program.asm
    {program} output program.asm
    {program} output program.asm out.bin
    {program} audit program.asm
    {program} audit program.asm out.txt
    {program} predict program.asm
    {program} predict program.asm 100
    {program} predict program.asm 100 'transfer(\"addr\",100)'
    {program} predict program.asm 100 'factorial(5)' 'factorial(10)'
";

fn print_usage(program: &str) {
    info!("{}", USAGE.replace("{program}", program));
}
