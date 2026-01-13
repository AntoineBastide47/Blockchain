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
//!
//! # Examples
//! ```text
//! assembler program.asm
//! assembler program.asm -o output.bin
//! ```

use blockchain::virtual_machine::assembler::assemble_file;
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

    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            k @ ("--output" | "-o") => {
                i += 1;
                if i >= args.len() {
                    eprintln!("{k} requires an argument");
                    process::exit(1);
                }
                output_path = Some(args[i].clone());
                i += 1;
            }
            other => {
                eprintln!("Unexpected argument: {}\n", other);
                print_usage(&args[0]);
                process::exit(1);
            }
        }
    }

    if !Path::new(input_path).exists() {
        eprintln!("Input file does not exist: {}", input_path);
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
        eprintln!("Output directory does not exist: {}", parent.display());
        process::exit(1);
    }

    let program = match assemble_file(input_path) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Assembly failed: {}", e);
            process::exit(1);
        }
    };

    let bytecode = program.to_bytes();

    if let Err(e) = fs::write(&output_path, bytecode.to_vec()) {
        eprintln!("Failed to write output file: {}", e);
        process::exit(1);
    }

    println!(
        "Compiled {} -> {} ({} bytes)",
        input_path,
        output_path,
        bytecode.len()
    );
}

const USAGE: &str = "\
Assembly Compiler

USAGE:
    {program} <input.asm> [OPTIONS]

ARGS:
    <input.asm>    Assembly source file to compile

OPTIONS:
    -o, --output <file>    Output file path (defaults to <input>.bin)
    -h, --help             Print this help message

EXAMPLES:
    # Compile to default output name
    {program} program.asm

    # Compile with explicit output
    {program} program.asm -o output.bin
";

fn print_usage(program: &str) {
    eprintln!("{}", USAGE.replace("{program}", program));
}
