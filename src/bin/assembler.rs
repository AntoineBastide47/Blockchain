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
//! - `-o, --output <file>`: Output file path (defaults to `<input>.bin`)
//! - `-p, --predict [price]`: Estimate deployment gas cost (price defaults to 1)
//!
//! # Examples
//! ```text
//! assembler program.asm
//! assembler program.asm -o output.bin
//! assembler program.asm -p
//! assembler program.asm -p 100
//! ```

use blockchain::core::blockchain::Blockchain;
use blockchain::core::transaction::TransactionType;
use blockchain::core::validator::BlockValidator;
use blockchain::network::libp2p_transport::Libp2pTransport;
use blockchain::network::server::Server;
use blockchain::storage::main_storage::MainStorage;
use blockchain::storage::state_view::StateViewProvider;
use blockchain::storage::storage_trait::Storage;
use blockchain::types::hash::Hash;
use blockchain::virtual_machine::assembler::assemble_file;
use blockchain::virtual_machine::state::OverlayState;
use blockchain::virtual_machine::vm::{ExecContext, GasCategory, TRANSACTION_GAS_LIMIT, VM};
use blockchain::{error, info, warn};
use std::env;
use std::fs;
use std::path::Path;
use std::process;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 || args[1] == "--help" || args[1] == "-h" {
        print_usage(&args[0]);
        process::exit(if args.len() < 2 { 1 } else { 0 });
    }

    let input_path = &args[1];
    let mut output_path: Option<String> = None;
    let mut predict = false;
    let mut gas_price = 0u64;

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
            "--predict" | "-p" => {
                predict = true;
                // Check if next arg exists and is a valid number (not another flag)
                if i + 1 < args.len() && !args[i + 1].starts_with('-') {
                    i += 1;
                    gas_price = args[i].parse::<u64>().unwrap_or_else(|_| {
                        error!("Invalid gas price: '{}' is not a valid number", args[i]);
                        process::exit(1);
                    });
                    if gas_price == 0 {
                        error!("Gas price must be greater than 0");
                        process::exit(1);
                    }
                } else {
                    gas_price = 1;
                }
                i += 1;
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

    let output_path = output_path.unwrap_or_else(|| {
        let p = Path::new(input_path);
        let stem = p.file_stem().unwrap_or_default().to_string_lossy();
        let parent = p.parent().unwrap_or(Path::new("."));
        parent
            .join(format!("{}.bin", stem))
            .to_string_lossy()
            .into_owned()
    });

    if let Some(parent) = Path::new(&output_path).parent()
        && !parent.as_os_str().is_empty()
        && !parent.exists()
    {
        error!("Output directory does not exist: {}", parent.display());
        process::exit(1);
    }

    let program = match assemble_file(input_path) {
        Ok(p) => p,
        Err(e) => {
            error!("Assembly failed: {}", e);
            process::exit(1);
        }
    };

    let bytecode = program.to_bytes();

    if let Err(e) = fs::write(&output_path, bytecode.to_vec()) {
        error!("Failed to write output file: {}", e);
        process::exit(1);
    }

    info!(
        "Compiled {} -> {} ({} bytes)",
        input_path,
        output_path,
        bytecode.len()
    );

    if predict {
        let intrinsic = Blockchain::<BlockValidator, MainStorage>::intrinsic_gas_units(
            TransactionType::DeployContract,
            &program.to_bytes(),
        );

        if intrinsic > TRANSACTION_GAS_LIMIT {
            error!(
                "Intrinsic gas ({}) exceeds transaction limit ({})",
                intrinsic, TRANSACTION_GAS_LIMIT
            );
            process::exit(1);
        }

        let mut vm = VM::new(program, TRANSACTION_GAS_LIMIT - intrinsic).unwrap_or_else(|e| {
            error!("{e}");
            process::exit(1)
        });

        let ms = MainStorage::new(Server::<Libp2pTransport>::genesis_block(0, &[]), 0, &[]);
        let base = ms.state_view();
        let mut overlay = OverlayState::new(&base);

        let ctx = ExecContext {
            chain_id: 0,
            contract_id: Hash::zero(),
        };

        vm.run(&mut overlay, &ctx).unwrap_or_else(|e| {
            error!("{e}");
            process::exit(1)
        });

        let mut profile = vm.gas_profile();
        profile.add(GasCategory::Intrinsic, intrinsic);

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

        println!("Gas Profile:");
        println!("{}", "-".repeat(dash_w));

        for (category, amount) in profile.iter() {
            if amount == 0 {
                continue;
            }

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
            "Estimated deployment cost: {}",
            format_with_commas(total_u * gas_price)
        );
        warn!("Actual cost will depend on chain state.");
    }
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

const USAGE: &str = "\
Assembly Compiler

USAGE:
    {program} <input.asm> [OPTIONS]

ARGS:
    <input.asm>    Assembly source file to compile

OPTIONS:
    -o, --output <file>     Output file path (defaults to <input>.bin)
    -p, --predict [price]   Estimate deployment gas cost (price defaults to 1)
    -h, --help              Print this help message

EXAMPLES:
    # Compile to default output name
    {program} program.asm

    # Compile with explicit output
    {program} program.asm -o output.bin

    # Compile and estimate gas cost (price = 1)
    {program} program.asm -p

    # Compile and estimate gas cost with custom price
    {program} program.asm -p 100
";

fn print_usage(program: &str) {
    info!("{}", USAGE.replace("{program}", program));
}
