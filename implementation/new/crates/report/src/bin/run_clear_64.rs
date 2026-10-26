#![forbid(unsafe_code)]

use std::{env, path::PathBuf, process::ExitCode};

use report::clear_64::generate_clear_64_report;

struct Cli {
    seed: u64,
    output: PathBuf,
    report: PathBuf,
}

fn main() -> ExitCode {
    let cli = match parse_cli(env::args().skip(1)) {
        Ok(cli) => cli,
        Err(error) => {
            eprintln!("run_clear_64: {error}\n");
            print_usage();
            return ExitCode::from(2);
        }
    };
    match generate_clear_64_report(cli.seed, &cli.output, &cli.report) {
        Ok(paths) => {
            println!("Clear 64-member report complete.");
            println!("Summary CSV: {}", paths.summary_csv.display());
            println!("Event CSV: {}", paths.events_csv.display());
            println!("Markdown: {}", paths.report_markdown.display());
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("run_clear_64: {error}");
            ExitCode::FAILURE
        }
    }
}

fn parse_cli(arguments: impl Iterator<Item = String>) -> Result<Cli, String> {
    let mut seed = 42_u64;
    let mut output = None;
    let mut report = None;
    let mut arguments = arguments;
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--seed" => {
                seed = next_value(&mut arguments, "--seed")?
                    .parse()
                    .map_err(|_| "--seed must be an unsigned integer".to_owned())?;
            }
            "--output" => output = Some(PathBuf::from(next_value(&mut arguments, "--output")?)),
            "--report" => report = Some(PathBuf::from(next_value(&mut arguments, "--report")?)),
            "--help" | "-h" => return Err("help requested".to_owned()),
            _ => return Err(format!("unknown argument: {argument}")),
        }
    }
    Ok(Cli {
        seed,
        output: output.ok_or_else(|| "--output is required".to_owned())?,
        report: report.ok_or_else(|| "--report is required".to_owned())?,
    })
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
    eprintln!(
        "Usage: run_clear_64 [--seed <PUBLIC_SEED>] --output output/<run> --report report/<run>"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_required_paths_and_seed() {
        let cli = parse_cli(
            [
                "--seed",
                "7",
                "--output",
                "output/example",
                "--report",
                "report/example",
            ]
            .into_iter()
            .map(str::to_owned),
        )
        .expect("valid CLI");
        assert_eq!(cli.seed, 7);
        assert_eq!(cli.output, PathBuf::from("output/example"));
        assert_eq!(cli.report, PathBuf::from("report/example"));
    }

    #[test]
    fn rejects_unknown_or_incomplete_arguments() {
        assert!(parse_cli(["--unknown"].into_iter().map(str::to_owned)).is_err());
        assert!(parse_cli(["--output"].into_iter().map(str::to_owned)).is_err());
    }
}
