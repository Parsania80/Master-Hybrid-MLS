#![forbid(unsafe_code)]

//! Validate a public bootstrap snapshot and optionally create a fresh baseline group.
//!
//! This Task 51 command cannot restore MLS private state from a public
//! snapshot. `--recreate` creates a new verified baseline group with the same
//! public committer schedule and writes a public manifest; transition
//! workloads and reports are deliberately deferred to Tasks 52 through 55.

use std::{env, path::PathBuf, process::ExitCode};

use adaptive_hybrid_mls::evaluate::{
    load_snapshot_recreation_plan, recreate_fresh_baseline, write_fresh_recreation_manifest,
    TRANSITION_RECREATION_FILE_NAME,
};

#[derive(Debug)]
struct Cli {
    snapshot: PathBuf,
    output: Option<PathBuf>,
    recreate: bool,
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
            println!("evaluate_transition {}", env!("CARGO_PKG_VERSION"));
            return ExitCode::SUCCESS;
        }
        Err(error) => {
            eprintln!("evaluate_transition: {error}\n");
            print_usage();
            return ExitCode::FAILURE;
        }
    };

    let plan = match load_snapshot_recreation_plan(&cli.snapshot) {
        Ok(plan) => plan,
        Err(error) => {
            eprintln!("evaluate_transition: {error}");
            return ExitCode::FAILURE;
        }
    };
    if !cli.recreate {
        println!(
            "Validated public bootstrap snapshot at epoch {}. No MLS state was restored and no workload was run.",
            plan.source_epoch
        );
        return ExitCode::SUCCESS;
    }

    let output = cli.output.expect("parser requires output with --recreate");
    match recreate_fresh_baseline(&plan) {
        Ok(recreation) => match write_fresh_recreation_manifest(&output, &recreation) {
            Ok(()) => {
                println!(
                    "Created and verified a fresh {}-member baseline group at epoch {}.",
                    recreation.recreated.member_count, recreation.recreated.epoch
                );
                println!(
                    "Wrote public fresh-recreation manifest under {} ({}).",
                    output.display(),
                    TRANSITION_RECREATION_FILE_NAME
                );
                println!(
                    "This is not an exact source-state restore; Tasks 52 through 55 own workloads, transition execution, metrics, and reports."
                );
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("evaluate_transition: {error}");
                ExitCode::FAILURE
            }
        },
        Err(error) => {
            eprintln!("evaluate_transition: {error}");
            ExitCode::FAILURE
        }
    }
}

fn parse_command() -> Result<Command, String> {
    let mut snapshot = None;
    let mut output = None;
    let mut recreate = false;
    let mut arguments = env::args().skip(1);
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--help" | "-h" => return Ok(Command::Help),
            "--version" | "-V" => return Ok(Command::Version),
            "--snapshot" => {
                snapshot = Some(PathBuf::from(argument_value(&mut arguments, "--snapshot")?))
            }
            "--output" => output = Some(PathBuf::from(argument_value(&mut arguments, "--output")?)),
            "--recreate" => recreate = true,
            _ => return Err(format!("unrecognized argument `{argument}`")),
        }
    }
    if recreate && output.is_none() {
        return Err("--recreate requires --output output/<run>".to_owned());
    }
    if !recreate && output.is_some() {
        return Err("--output requires --recreate".to_owned());
    }
    Ok(Command::Run(Cli {
        snapshot: snapshot.ok_or_else(|| "--snapshot is required".to_owned())?,
        output,
        recreate,
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
        "Usage: evaluate_transition --snapshot <PUBLIC_SNAPSHOT> [--recreate --output output/<run>]\n\
         \n\
         Without --recreate, validates a public bootstrap snapshot only.\n\
         With --recreate, builds a fresh verified baseline group with the same public committer schedule\n\
         and writes transition_recreation.json. It cannot restore original private MLS state and runs no workload."
    );
}
