#![forbid(unsafe_code)]

//! Generate the Task 62 real three-mode comparison artifacts.

use std::{env, fs, path::PathBuf, process::ExitCode};

use report::comparison::{generate_mode_comparison, ComparisonWorkloadShape};

#[derive(Debug)]
struct Cli {
    baseline_config: PathBuf,
    mkyber_config: PathBuf,
    adaptive_config: PathBuf,
    initial_members: u32,
    maximum_members: u32,
    operations: u32,
    regions: u32,
    output: PathBuf,
    report: PathBuf,
}

enum Command {
    Run(Cli),
    Help,
    Version,
}

fn main() -> ExitCode {
    let cli = match parse_command() {
        Ok(Command::Run(cli)) => cli,
        Ok(Command::Help) => {
            print_usage();
            return ExitCode::SUCCESS;
        }
        Ok(Command::Version) => {
            println!("compare_modes {}", env!("CARGO_PKG_VERSION"));
            return ExitCode::SUCCESS;
        }
        Err(error) => {
            eprintln!("compare_modes: {error}\n");
            print_usage();
            return ExitCode::FAILURE;
        }
    };
    let baseline = match read_config(&cli.baseline_config, "--baseline-config") {
        Ok(value) => value,
        Err(error) => return fail(error),
    };
    let mkyber = match read_config(&cli.mkyber_config, "--mkyber-config") {
        Ok(value) => value,
        Err(error) => return fail(error),
    };
    let adaptive = match read_config(&cli.adaptive_config, "--adaptive-config") {
        Ok(value) => value,
        Err(error) => return fail(error),
    };
    match generate_mode_comparison(
        &baseline,
        &mkyber,
        &adaptive,
        ComparisonWorkloadShape {
            initial_member_count: cli.initial_members,
            maximum_member_count: cli.maximum_members,
            operation_count: cli.operations,
            region_count: cli.regions,
        },
        &cli.output,
        &cli.report,
    ) {
        Ok(paths) => {
            println!("Generated a real three-mode update-only comparison.");
            println!(
                "Machine-readable artifacts: {}, {}",
                paths.comparison_csv.display(),
                paths.comparison_json.display()
            );
            println!("Markdown report: {}", paths.comparison_markdown.display());
            println!("All three selected workload clients executed. Lifecycle timing remains environment-dependent; Task 63 collects repeated CPU and peak-RSS evidence.");
            ExitCode::SUCCESS
        }
        Err(error) => fail(format!("comparison failed: {error}")),
    }
}

fn fail(error: String) -> ExitCode {
    eprintln!("compare_modes: {error}");
    ExitCode::FAILURE
}

fn read_config(path: &PathBuf, option: &str) -> Result<String, String> {
    fs::read_to_string(path).map_err(|_| format!("{option} could not be read"))
}

fn parse_command() -> Result<Command, String> {
    let mut baseline_config = None;
    let mut mkyber_config = None;
    let mut adaptive_config = None;
    let mut initial_members = None;
    let mut maximum_members = None;
    let mut operations = None;
    let mut regions = None;
    let mut output = None;
    let mut report = None;
    let mut arguments = env::args().skip(1);
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--help" | "-h" => return Ok(Command::Help),
            "--version" | "-V" => return Ok(Command::Version),
            "--baseline-config" => {
                baseline_config = Some(PathBuf::from(argument_value(
                    &mut arguments,
                    "--baseline-config",
                )?))
            }
            "--mkyber-config" => {
                mkyber_config = Some(PathBuf::from(argument_value(
                    &mut arguments,
                    "--mkyber-config",
                )?))
            }
            "--adaptive-config" => {
                adaptive_config = Some(PathBuf::from(argument_value(
                    &mut arguments,
                    "--adaptive-config",
                )?))
            }
            "--initial-members" => {
                initial_members = Some(parse_u32(
                    &argument_value(&mut arguments, "--initial-members")?,
                    "--initial-members",
                )?)
            }
            "--maximum-members" => {
                maximum_members = Some(parse_u32(
                    &argument_value(&mut arguments, "--maximum-members")?,
                    "--maximum-members",
                )?)
            }
            "--operations" => {
                operations = Some(parse_u32(
                    &argument_value(&mut arguments, "--operations")?,
                    "--operations",
                )?)
            }
            "--regions" => {
                regions = Some(parse_u32(
                    &argument_value(&mut arguments, "--regions")?,
                    "--regions",
                )?)
            }
            "--output" => output = Some(PathBuf::from(argument_value(&mut arguments, "--output")?)),
            "--report" => report = Some(PathBuf::from(argument_value(&mut arguments, "--report")?)),
            _ => return Err(format!("unrecognized argument `{argument}`")),
        }
    }
    Ok(Command::Run(Cli {
        baseline_config: baseline_config
            .ok_or_else(|| "--baseline-config is required".to_owned())?,
        mkyber_config: mkyber_config.ok_or_else(|| "--mkyber-config is required".to_owned())?,
        adaptive_config: adaptive_config
            .ok_or_else(|| "--adaptive-config is required".to_owned())?,
        initial_members: initial_members
            .ok_or_else(|| "--initial-members is required".to_owned())?,
        maximum_members: maximum_members
            .ok_or_else(|| "--maximum-members is required".to_owned())?,
        operations: operations.ok_or_else(|| "--operations is required".to_owned())?,
        regions: regions.ok_or_else(|| "--regions is required".to_owned())?,
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

fn parse_u32(value: &str, option: &str) -> Result<u32, String> {
    value
        .parse()
        .map_err(|_| format!("{option} must be an unsigned integer"))
}

fn print_usage() {
    println!(
        "Usage: compare_modes --baseline-config configs/<baseline>.toml --mkyber-config configs/<mkyber>.toml --adaptive-config configs/<adaptive>.toml --initial-members <N> --maximum-members <N> --operations <N> --regions <N> --output output/<run> --report report/<run>\n\
         \n\
         The three TOML files must select their named modes and share group, transition, and execution controls. Task 62 accepts only zero-warmup update-only workloads with equal initial and maximum membership. It runs all three real clients; use 128 members and at least three updates to obtain the proven adaptive transition and post-transition update."
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_missing_required_arguments() {
        assert!(parse_u32("invalid", "--operations").is_err());
    }
}
