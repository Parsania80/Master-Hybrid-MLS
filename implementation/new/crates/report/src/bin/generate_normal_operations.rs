#![forbid(unsafe_code)]

//! Generate the fixed minimal Task 64 normal-operation table.

use std::{env, path::PathBuf, process::ExitCode};

use report::normal_operations::generate_normal_operation_artifacts;

#[derive(Debug)]
struct Cli {
    repetitions: u32,
    output: PathBuf,
    report: PathBuf,
}

fn main() -> ExitCode {
    let cli = match parse_command() {
        Ok(Some(cli)) => cli,
        Ok(None) => {
            print_usage();
            return ExitCode::SUCCESS;
        }
        Err(error) => {
            eprintln!("generate_normal_operations: {error}\n");
            print_usage();
            return ExitCode::FAILURE;
        }
    };
    match generate_normal_operation_artifacts(cli.repetitions, &cli.output, &cli.report) {
        Ok(paths) => {
            println!("Generated Task 64 minimal normal-operation evidence.");
            println!(
                "Machine-readable artifacts: {}, {}",
                paths.normal_operations_csv.display(),
                paths.normal_operations_json.display()
            );
            println!(
                "Markdown table: {}",
                paths.normal_operations_markdown.display()
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("generate_normal_operations: generation failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn parse_command() -> Result<Option<Cli>, String> {
    let mut repetitions = None;
    let mut output = None;
    let mut report = None;
    let mut arguments = env::args().skip(1);
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--help" | "-h" => return Ok(None),
            "--repetitions" => {
                repetitions = Some(parse_u32(
                    next_value(&mut arguments, "--repetitions")?,
                    "--repetitions",
                )?)
            }
            "--output" => output = Some(PathBuf::from(next_value(&mut arguments, "--output")?)),
            "--report" => report = Some(PathBuf::from(next_value(&mut arguments, "--report")?)),
            _ => return Err(format!("unrecognized argument `{argument}`")),
        }
    }
    Ok(Some(Cli {
        repetitions: repetitions.ok_or_else(|| "--repetitions is required".to_owned())?,
        output: output.ok_or_else(|| "--output is required".to_owned())?,
        report: report.ok_or_else(|| "--report is required".to_owned())?,
    }))
}

fn next_value(
    arguments: &mut impl Iterator<Item = String>,
    option: &str,
) -> Result<String, String> {
    arguments
        .next()
        .ok_or_else(|| format!("{option} requires a value"))
}

fn parse_u32(value: String, option: &str) -> Result<u32, String> {
    value
        .parse()
        .map_err(|_| format!("{option} must be an unsigned integer"))
}

fn print_usage() {
    println!(
        "Usage: generate_normal_operations --repetitions <N> --output output/<run> --report report/<run>\n\
         \n\
         Generates real arity-2 baseline/fork rows plus deterministic educational arity-4/8 update rows. The educational rows are visibly labeled and are not live MLS protocol measurements."
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_numeric_repetitions() {
        assert!(parse_u32("none".to_owned(), "--repetitions").is_err());
    }
}
