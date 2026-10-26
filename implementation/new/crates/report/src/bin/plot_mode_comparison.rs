#![forbid(unsafe_code)]

//! Generate minimal Task 62 SVGs from a completed real comparison CSV.

use std::{env, path::PathBuf, process::ExitCode};

use report::comparison::generate_mode_comparison_plot_artifacts;

#[derive(Debug)]
struct Cli {
    comparison_csv: PathBuf,
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
            eprintln!("plot_mode_comparison: {error}\n");
            print_usage();
            return ExitCode::FAILURE;
        }
    };
    match generate_mode_comparison_plot_artifacts(&cli.comparison_csv, &cli.output, &cli.report) {
        Ok(paths) => {
            println!("Generated Task 62 plot-ready comparison artifacts.");
            println!("Plot data: {}", paths.plot_data_csv.display());
            println!(
                "SVG charts: {}, {}, {}, {}",
                paths.bytes_svg.display(),
                paths.lifecycle_svg.display(),
                paths.hybrid_counts_svg.display(),
                paths.transition_svg.display()
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("plot_mode_comparison: generation failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn parse_command() -> Result<Option<Cli>, String> {
    let mut comparison_csv = None;
    let mut output = None;
    let mut report = None;
    let mut arguments = env::args().skip(1);
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--help" | "-h" => return Ok(None),
            "--comparison-csv" => {
                comparison_csv = Some(PathBuf::from(argument_value(
                    &mut arguments,
                    "--comparison-csv",
                )?))
            }
            "--output" => output = Some(PathBuf::from(argument_value(&mut arguments, "--output")?)),
            "--report" => report = Some(PathBuf::from(argument_value(&mut arguments, "--report")?)),
            _ => return Err(format!("unrecognized argument `{argument}`")),
        }
    }
    Ok(Some(Cli {
        comparison_csv: comparison_csv.ok_or_else(|| "--comparison-csv is required".to_owned())?,
        output: output.ok_or_else(|| "--output is required".to_owned())?,
        report: report.ok_or_else(|| "--report is required".to_owned())?,
    }))
}

fn argument_value(
    arguments: &mut impl Iterator<Item = String>,
    option: &str,
) -> Result<String, String> {
    arguments
        .next()
        .ok_or_else(|| format!("{option} requires a value"))
}

fn print_usage() {
    println!(
        "Usage: plot_mode_comparison --comparison-csv output/<run>/mode_comparison.csv --output output/<run> --report report/<run>\n\
         \n\
         Reads a completed Task 62 real comparison CSV and creates a separate plot-data CSV plus four dependency-free SVGs. Existing output files are never overwritten."
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_value_is_rejected() {
        assert!(argument_value(&mut std::iter::empty(), "--output").is_err());
    }
}
