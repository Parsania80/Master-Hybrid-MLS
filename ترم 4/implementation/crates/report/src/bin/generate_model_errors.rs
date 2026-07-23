#![forbid(unsafe_code)]

//! Generate minimal Task 66 byte/time model and percentage-error artifacts.

use std::{env, path::PathBuf, process::ExitCode};

use report::model_errors::generate_model_error_artifacts;

#[derive(Debug)]
struct Cli {
    environment_json: PathBuf,
    normal_operations_csv: PathBuf,
    transition_maturity_json: PathBuf,
    timing_samples: u32,
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
            eprintln!("generate_model_errors: {error}\n");
            print_usage();
            return ExitCode::FAILURE;
        }
    };
    match generate_model_error_artifacts(
        &cli.environment_json,
        &cli.normal_operations_csv,
        &cli.transition_maturity_json,
        cli.timing_samples,
        &cli.output,
        &cli.report,
    ) {
        Ok(paths) => {
            println!("Generated Task 66 model/error evidence.");
            println!(
                "Machine-readable artifacts: {}, {}",
                paths.model_errors_csv.display(),
                paths.model_errors_json.display()
            );
            println!("Markdown table: {}", paths.model_errors_markdown.display());
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("generate_model_errors: generation failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn parse_command() -> Result<Option<Cli>, String> {
    let mut environment_json = None;
    let mut normal_operations_csv = None;
    let mut transition_maturity_json = None;
    let mut timing_samples = Some(25_u32);
    let mut output = None;
    let mut report = None;
    let mut arguments = env::args().skip(1);
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--help" | "-h" => return Ok(None),
            "--environment-json" => {
                environment_json = Some(PathBuf::from(next_value(
                    &mut arguments,
                    "--environment-json",
                )?))
            }
            "--normal-operations-csv" => {
                normal_operations_csv = Some(PathBuf::from(next_value(
                    &mut arguments,
                    "--normal-operations-csv",
                )?))
            }
            "--transition-maturity-json" => {
                transition_maturity_json = Some(PathBuf::from(next_value(
                    &mut arguments,
                    "--transition-maturity-json",
                )?))
            }
            "--timing-samples" => {
                timing_samples = Some(parse_u32(next_value(&mut arguments, "--timing-samples")?)?)
            }
            "--output" => output = Some(PathBuf::from(next_value(&mut arguments, "--output")?)),
            "--report" => report = Some(PathBuf::from(next_value(&mut arguments, "--report")?)),
            _ => return Err(format!("unrecognized argument `{argument}`")),
        }
    }
    Ok(Some(Cli {
        environment_json: environment_json
            .ok_or_else(|| "--environment-json is required".to_owned())?,
        normal_operations_csv: normal_operations_csv
            .ok_or_else(|| "--normal-operations-csv is required".to_owned())?,
        transition_maturity_json: transition_maturity_json
            .ok_or_else(|| "--transition-maturity-json is required".to_owned())?,
        timing_samples: timing_samples.ok_or_else(|| "--timing-samples is required".to_owned())?,
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

fn parse_u32(value: String) -> Result<u32, String> {
    value
        .parse()
        .map_err(|_| "--timing-samples must be an unsigned integer".to_owned())
}

fn print_usage() {
    println!(
        "Usage: generate_model_errors --environment-json output/<task63-run>/environment.json --normal-operations-csv output/<task64-run>/normal_operations.csv --transition-maturity-json output/<task65-run>/transition_maturity.json --output output/<run> --report report/<run> [--timing-samples <N>]\n\
         \n\
         Generates direct fixed-width byte models and local median primitive timing models. Full real MLS rows remain explicitly unavailable when their completed public evidence lacks a valid decomposition."
    );
}
