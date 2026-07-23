#![forbid(unsafe_code)]

//! Generate the create-new final Task 67 thesis-table dataset.

use std::{env, path::PathBuf, process::ExitCode};

use report::thesis_tables::generate_thesis_table_artifacts;

#[derive(Debug)]
struct Cli {
    comparison_csv: PathBuf,
    environment_json: PathBuf,
    normal_operations_csv: PathBuf,
    transition_maturity_json: PathBuf,
    model_errors_json: PathBuf,
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
            eprintln!("generate_thesis_tables: {error}\n");
            print_usage();
            return ExitCode::FAILURE;
        }
    };
    match generate_thesis_table_artifacts(
        &cli.comparison_csv,
        &cli.environment_json,
        &cli.normal_operations_csv,
        &cli.transition_maturity_json,
        &cli.model_errors_json,
        &cli.output,
        &cli.report,
    ) {
        Ok(paths) => {
            println!("Generated Task 67 final thesis tables.");
            println!(
                "Machine-readable artifacts: {}, {}",
                paths.thesis_tables_csv.display(),
                paths.thesis_tables_json.display()
            );
            println!(
                "Markdown tables: {}",
                paths.thesis_tables_markdown.display()
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("generate_thesis_tables: generation failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn parse_command() -> Result<Option<Cli>, String> {
    let mut comparison_csv = None;
    let mut environment_json = None;
    let mut normal_operations_csv = None;
    let mut transition_maturity_json = None;
    let mut model_errors_json = None;
    let mut output = None;
    let mut report = None;
    let mut arguments = env::args().skip(1);
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--help" | "-h" => return Ok(None),
            "--comparison-csv" => {
                comparison_csv = Some(PathBuf::from(next_value(
                    &mut arguments,
                    "--comparison-csv",
                )?))
            }
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
            "--model-errors-json" => {
                model_errors_json = Some(PathBuf::from(next_value(
                    &mut arguments,
                    "--model-errors-json",
                )?))
            }
            "--output" => output = Some(PathBuf::from(next_value(&mut arguments, "--output")?)),
            "--report" => report = Some(PathBuf::from(next_value(&mut arguments, "--report")?)),
            _ => return Err(format!("unrecognized argument `{argument}`")),
        }
    }
    Ok(Some(Cli {
        comparison_csv: required(comparison_csv, "--comparison-csv")?,
        environment_json: required(environment_json, "--environment-json")?,
        normal_operations_csv: required(normal_operations_csv, "--normal-operations-csv")?,
        transition_maturity_json: required(transition_maturity_json, "--transition-maturity-json")?,
        model_errors_json: required(model_errors_json, "--model-errors-json")?,
        output: required(output, "--output")?,
        report: required(report, "--report")?,
    }))
}

fn required(value: Option<PathBuf>, name: &str) -> Result<PathBuf, String> {
    value.ok_or_else(|| format!("{name} is required"))
}

fn next_value(
    arguments: &mut impl Iterator<Item = String>,
    option: &str,
) -> Result<String, String> {
    arguments
        .next()
        .ok_or_else(|| format!("{option} requires a value"))
}

fn print_usage() {
    println!("Usage: generate_thesis_tables --comparison-csv output/<task62-run>/mode_comparison.csv --environment-json output/<task63-run>/environment.json --normal-operations-csv output/<task64-run>/normal_operations.csv --transition-maturity-json output/<task65-run>/transition_maturity.json --model-errors-json output/<task66-run>/model_errors.json --output output/<run> --report report/<run>");
}
