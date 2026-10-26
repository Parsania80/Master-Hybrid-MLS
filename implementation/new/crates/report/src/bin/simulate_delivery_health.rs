#![forbid(unsafe_code)]

//! Run the public adaptive delivery-health simulation.

use std::{env, path::PathBuf, process::ExitCode};

use report::delivery_health::{generate_delivery_health_report, DeliveryHealthConfig};

#[derive(Debug, Eq, PartialEq)]
struct Cli {
    initial_arity: u8,
    target_arity: u8,
    initial_members: u32,
    seed: u64,
    maximum_commits: u32,
    output: PathBuf,
    report: PathBuf,
}

fn main() -> ExitCode {
    let cli = match parse_cli(env::args().skip(1)) {
        Ok(Some(cli)) => cli,
        Ok(None) => {
            print_usage();
            return ExitCode::SUCCESS;
        }
        Err(error) => {
            eprintln!("simulate_delivery_health: {error}\n");
            print_usage();
            return ExitCode::from(2);
        }
    };
    let config = DeliveryHealthConfig {
        initial_arity: cli.initial_arity,
        target_arity: cli.target_arity,
        initial_member_count: cli.initial_members,
        random_seed: cli.seed,
        maximum_post_transition_commits: cli.maximum_commits,
    };
    match generate_delivery_health_report(config, &cli.output, &cli.report) {
        Ok(paths) => {
            println!("Adaptive delivery-health simulation complete.");
            println!("Summary CSV: {}", paths.summary_csv.display());
            println!("Event CSV: {}", paths.events_csv.display());
            println!("Markdown: {}", paths.report_markdown.display());
            println!(
                "Delivery-cost chart: {}",
                paths.delivery_cost_chart.display()
            );
            println!(
                "Delivery-health chart: {}",
                paths.delivery_health_chart.display()
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("simulate_delivery_health: {error}");
            ExitCode::FAILURE
        }
    }
}

fn parse_cli(arguments: impl Iterator<Item = String>) -> Result<Option<Cli>, String> {
    let mut initial_arity = None;
    let mut target_arity = None;
    let mut initial_members = None;
    let mut seed = 42_u64;
    let mut maximum_commits = 128_u32;
    let mut output = None;
    let mut report = None;
    let mut arguments = arguments;
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--help" | "-h" => return Ok(None),
            "--initial-arity" => {
                initial_arity = Some(parse_u8(
                    next_value(&mut arguments, "--initial-arity")?,
                    "--initial-arity",
                )?)
            }
            "--target-arity" => {
                target_arity = Some(parse_u8(
                    next_value(&mut arguments, "--target-arity")?,
                    "--target-arity",
                )?)
            }
            "--initial-members" => {
                initial_members = Some(parse_u32(
                    next_value(&mut arguments, "--initial-members")?,
                    "--initial-members",
                )?)
            }
            "--seed" => {
                seed = parse_u64(next_value(&mut arguments, "--seed")?, "--seed")?;
            }
            "--maximum-commits" => {
                maximum_commits = parse_u32(
                    next_value(&mut arguments, "--maximum-commits")?,
                    "--maximum-commits",
                )?;
            }
            "--output" => output = Some(PathBuf::from(next_value(&mut arguments, "--output")?)),
            "--report" => report = Some(PathBuf::from(next_value(&mut arguments, "--report")?)),
            _ => return Err(format!("unknown argument: {argument}")),
        }
    }
    Ok(Some(Cli {
        initial_arity: initial_arity.ok_or_else(|| "--initial-arity is required".to_owned())?,
        target_arity: target_arity.ok_or_else(|| "--target-arity is required".to_owned())?,
        initial_members: initial_members
            .ok_or_else(|| "--initial-members is required".to_owned())?,
        seed,
        maximum_commits,
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

fn parse_u8(value: String, option: &str) -> Result<u8, String> {
    value
        .parse()
        .map_err(|_| format!("{option} must be an unsigned 8-bit integer"))
}

fn parse_u32(value: String, option: &str) -> Result<u32, String> {
    value
        .parse()
        .map_err(|_| format!("{option} must be an unsigned integer"))
}

fn parse_u64(value: String, option: &str) -> Result<u64, String> {
    value
        .parse()
        .map_err(|_| format!("{option} must be an unsigned integer"))
}

fn print_usage() {
    println!(
        "Usage: simulate_delivery_health \
         --initial-arity <2|4> --target-arity <4|8> --initial-members <N> \
         [--seed <PUBLIC_SEED>] [--maximum-commits <N>] \
         --output output/<run> --report report/<run>\n\
         \n\
         Initial members must exceed the initial arity and be at most 4096. The supported 2-to-4 path executes authenticated real-fork operations, records complete serialized Commit bytes, and writes post-transition delivery-cost and health charts."
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_required_values_and_defaults() {
        let cli = parse_cli(
            [
                "--initial-arity",
                "2",
                "--target-arity",
                "4",
                "--initial-members",
                "128",
                "--output",
                "output/example",
                "--report",
                "report/example",
            ]
            .into_iter()
            .map(str::to_owned),
        )
        .expect("valid CLI")
        .expect("run");
        assert_eq!(cli.initial_arity, 2);
        assert_eq!(cli.target_arity, 4);
        assert_eq!(cli.initial_members, 128);
        assert_eq!(cli.seed, 42);
        assert_eq!(cli.maximum_commits, 128);
    }

    #[test]
    fn rejects_missing_and_non_numeric_values() {
        assert!(parse_cli(["--initial-arity", "two"].into_iter().map(str::to_owned)).is_err());
        assert!(parse_cli(["--target-arity", "4"].into_iter().map(str::to_owned)).is_err());
    }
}
