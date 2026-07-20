#![forbid(unsafe_code)]

//! Builds the fixed-size baseline MLS group required by the thesis bootstrap.
//!
//! The `--seed` parameter is public scheduling input only. It never supplies
//! cryptographic randomness. `--output` receives the complete public artifact
//! set: snapshot, JSON summary, CSV commit records, and Markdown report.

use std::{env, path::PathBuf, process::ExitCode};

use adaptive_hybrid_mls::bootstrap::{
    bootstrap_128, bootstrap_summary, public_bootstrap_snapshot,
    validate_snapshot_output_directory, verify_bootstrap_128, write_bootstrap_artifacts,
    BootstrapOptions, BOOTSTRAP_MEMBER_COUNT,
};

/// Parsed public command-line arguments for the bootstrap executable.
#[derive(Debug)]
struct Cli {
    /// Fixed thesis bootstrap group size. Values other than 128 are rejected.
    members: usize,
    /// Public seed for the deterministic committer schedule, not cryptographic entropy.
    seed: u64,
    /// Relative `output/<run>` location for public bootstrap artifacts.
    output: PathBuf,
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
            println!("bootstrap_128 {}", env!("CARGO_PKG_VERSION"));
            return ExitCode::SUCCESS;
        }
        Err(error) => {
            eprintln!("bootstrap_128: {error}\n");
            print_usage();
            return ExitCode::FAILURE;
        }
    };
    let options = BootstrapOptions {
        members: cli.members,
        schedule_seed: cli.seed,
    };
    if let Err(error) = validate_snapshot_output_directory(&cli.output) {
        eprintln!("bootstrap_128: {error}");
        return ExitCode::FAILURE;
    }
    match bootstrap_128(&options) {
        Ok((mut clients, result)) => match verify_bootstrap_128(&mut clients) {
            Ok(verification) => {
                let snapshot = public_bootstrap_snapshot(&options, &result, &verification);
                let summary = bootstrap_summary(&options, &result, &verification, &cli.output);
                drop(clients);
                match (snapshot, summary) {
                    (Ok(snapshot), Ok(summary)) => {
                        match write_bootstrap_artifacts(
                            &cli.output,
                            &snapshot,
                            &summary,
                            &result.commit_records,
                        ) {
                            Ok(artifact_paths) => {
                                println!(
                "Verified {} baseline MLS members after {} Add commits at epoch {} using {} distinct committers.",
                BOOTSTRAP_MEMBER_COUNT,
                result.add_commit_count,
                verification.epoch,
                result
                    .committer_indices
                    .iter()
                    .collect::<std::collections::BTreeSet<_>>()
                    .len()
            );
                                println!(
                "Wrote public snapshot, summary, commit CSV, and report under {}.",
                cli.output.display()
            );
                                println!(
                                    "Artifacts: {}, {}, {}, {}",
                                    artifact_paths.snapshot.display(),
                                    artifact_paths.summary.display(),
                                    artifact_paths.commits.display(),
                                    artifact_paths.report.display()
                                );
                                ExitCode::SUCCESS
                            }
                            Err(error) => {
                                eprintln!("bootstrap_128 artifact write failed: {error}");
                                ExitCode::FAILURE
                            }
                        }
                    }
                    (Err(error), _) | (_, Err(error)) => {
                        eprintln!("bootstrap_128 artifact construction failed: {error}");
                        ExitCode::FAILURE
                    }
                }
            }
            Err(error) => {
                drop(clients);
                eprintln!("bootstrap_128 verification failed: {error}");
                ExitCode::FAILURE
            }
        },
        Err(error) => {
            eprintln!("bootstrap_128 failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn parse_command() -> Result<Command, String> {
    let mut members = BOOTSTRAP_MEMBER_COUNT;
    let mut seed = None;
    let mut output = None;
    let mut arguments = env::args().skip(1);

    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--help" | "-h" => return Ok(Command::Help),
            "--version" | "-V" => return Ok(Command::Version),
            "--members" => {
                let value = argument_value(&mut arguments, "--members")?;
                members = value
                    .parse()
                    .map_err(|_| "--members must be an unsigned integer".to_owned())?;
            }
            "--seed" => {
                let value = argument_value(&mut arguments, "--seed")?;
                seed = Some(
                    value
                        .parse()
                        .map_err(|_| "--seed must be an unsigned integer".to_owned())?,
                );
            }
            "--output" => {
                output = Some(PathBuf::from(argument_value(&mut arguments, "--output")?));
            }
            _ => return Err(format!("unrecognized argument `{argument}`")),
        }
    }

    Ok(Command::Run(Cli {
        members,
        seed: seed.ok_or_else(|| "--seed is required".to_owned())?,
        output: output.ok_or_else(|| "--output is required".to_owned())?,
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
        "Usage: bootstrap_128 [--members 128] --seed <PUBLIC_SCHEDULE_SEED> --output <DIRECTORY>\n\
         \n\
         Creates and fully delivers baseline MLS Add commits for exactly 128 members.\n\
         The seed controls public committer scheduling only; it is not cryptographic entropy.\n\
         Writes public snapshot, summary JSON, commit CSV, and report under output/<run>."
    );
}
