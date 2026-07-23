#![forbid(unsafe_code)]

//! Generate the minimal Task 65 transition-maturity and TreeCover table.

use std::{env, path::PathBuf, process::ExitCode};

use report::transition_tables::generate_transition_table_artifacts;

#[derive(Debug)]
struct Cli {
    task61_summary: PathBuf,
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
            eprintln!("generate_transition_tables: {error}\n");
            print_usage();
            return ExitCode::FAILURE;
        }
    };
    match generate_transition_table_artifacts(&cli.task61_summary, &cli.output, &cli.report) {
        Ok(paths) => {
            println!("Generated Task 65 transition-maturity evidence.");
            println!(
                "Machine-readable artifacts: {}, {}",
                paths.transition_maturity_csv.display(),
                paths.transition_maturity_json.display()
            );
            println!(
                "Markdown table: {}",
                paths.transition_maturity_markdown.display()
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("generate_transition_tables: generation failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn parse_command() -> Result<Option<Cli>, String> {
    let mut task61_summary = None;
    let mut output = None;
    let mut report = None;
    let mut arguments = env::args().skip(1);
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--help" | "-h" => return Ok(None),
            "--task61-summary" => {
                task61_summary = Some(PathBuf::from(next_value(
                    &mut arguments,
                    "--task61-summary",
                )?))
            }
            "--output" => output = Some(PathBuf::from(next_value(&mut arguments, "--output")?)),
            "--report" => report = Some(PathBuf::from(next_value(&mut arguments, "--report")?)),
            _ => return Err(format!("unrecognized argument `{argument}`")),
        }
    }
    Ok(Some(Cli {
        task61_summary: task61_summary.ok_or_else(|| "--task61-summary is required".to_owned())?,
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

fn print_usage() {
    println!(
        "Usage: generate_transition_tables --task61-summary output/<task61-run>/summary.json --output output/<run> --report report/<run>\n\
         \n\
         Reuses public real 2-to-4 Task 61 facts and adds an explicitly educational 4-to-8 canonical-codec topology replay. It does not claim an octal MLS transition or authenticated TreeCover secret retirement."
    );
}
