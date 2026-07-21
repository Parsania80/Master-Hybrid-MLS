#![forbid(unsafe_code)]

//! Execute one unchanged-baseline workload and write Task 55 public artifacts.

use std::{env, path::PathBuf, process::ExitCode};

use report::generation::generate_baseline_report;
use simulation::{BaselineWorkloadConfig, CommitterStrategy, CommitterWeight, WorkloadProfile};

#[derive(Debug)]
struct Cli {
    group_id: Vec<u8>,
    initial_members: u32,
    maximum_members: u32,
    operations: u32,
    regions: u32,
    workload: WorkloadProfile,
    committer: CommitterStrategy,
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
            println!("generate_baseline_report {}", env!("CARGO_PKG_VERSION"));
            return ExitCode::SUCCESS;
        }
        Err(error) => {
            eprintln!("generate_baseline_report: {error}\n");
            print_usage();
            return ExitCode::FAILURE;
        }
    };
    let workload = BaselineWorkloadConfig {
        group_id: cli.group_id,
        initial_member_count: cli.initial_members,
        maximum_member_count: cli.maximum_members,
        operation_count: cli.operations,
        region_count: cli.regions,
        committer_strategy: cli.committer,
        workload_profile: cli.workload,
    };
    match generate_baseline_report(&workload, &cli.output, &cli.report) {
        Ok(paths) => {
            println!(
                "Generated {} accepted baseline-commit records.",
                workload.operation_count
            );
            println!(
                "Machine-readable artifacts: {}, {}, {}, {}",
                paths.commits_csv.display(),
                paths.epochs_csv.display(),
                paths.transition_events_csv.display(),
                paths.summary_json.display(),
            );
            println!("Markdown report: {}", paths.report_markdown.display());
            println!("Experimental metrics remain explicitly unavailable unless real instrumentation records them.");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("generate_baseline_report: {error}");
            ExitCode::FAILURE
        }
    }
}

fn parse_command() -> Result<Command, String> {
    let mut group_id = None;
    let mut initial_members = None;
    let mut maximum_members = None;
    let mut operations = None;
    let mut regions = None;
    let mut workload = None;
    let mut committer = None;
    let mut output = None;
    let mut report = None;
    let mut arguments = env::args().skip(1);
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--help" | "-h" => return Ok(Command::Help),
            "--version" | "-V" => return Ok(Command::Version),
            "--group-id" => {
                group_id = Some(argument_value(&mut arguments, "--group-id")?.into_bytes())
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
            "--workload" => {
                workload = Some(parse_workload(&argument_value(
                    &mut arguments,
                    "--workload",
                )?)?)
            }
            "--committer" => {
                committer = Some(parse_committer(&argument_value(
                    &mut arguments,
                    "--committer",
                )?)?)
            }
            "--output" => output = Some(PathBuf::from(argument_value(&mut arguments, "--output")?)),
            "--report" => report = Some(PathBuf::from(argument_value(&mut arguments, "--report")?)),
            _ => return Err(format!("unrecognized argument `{argument}`")),
        }
    }
    let group_id = group_id.ok_or_else(|| "--group-id is required".to_owned())?;
    if group_id.is_empty() {
        return Err("--group-id must be non-empty".to_owned());
    }
    Ok(Command::Run(Cli {
        group_id,
        initial_members: initial_members
            .ok_or_else(|| "--initial-members is required".to_owned())?,
        maximum_members: maximum_members
            .ok_or_else(|| "--maximum-members is required".to_owned())?,
        operations: operations.ok_or_else(|| "--operations is required".to_owned())?,
        regions: regions.ok_or_else(|| "--regions is required".to_owned())?,
        workload: workload.ok_or_else(|| "--workload is required".to_owned())?,
        committer: committer.ok_or_else(|| "--committer is required".to_owned())?,
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

fn parse_workload(value: &str) -> Result<WorkloadProfile, String> {
    match value {
        "update-only" => Ok(WorkloadProfile::UpdateOnly),
        "mixed" => Ok(WorkloadProfile::Mixed),
        "removal-heavy" => Ok(WorkloadProfile::RemovalHeavy),
        _ => {
            if let Some(region) = value.strip_prefix("region-skewed:") {
                return Ok(WorkloadProfile::RegionSkewed {
                    preferred_region: parse_u32(region, "region-skewed region")?,
                });
            }
            if let Some(seed) = value.strip_prefix("uniform:") {
                return Ok(WorkloadProfile::Uniform {
                    seed: seed
                        .parse()
                        .map_err(|_| "uniform seed must be an unsigned integer".to_owned())?,
                });
            }
            Err("--workload must be update-only, mixed, removal-heavy, region-skewed:<REGION>, or uniform:<SEED>".to_owned())
        }
    }
}

fn parse_committer(value: &str) -> Result<CommitterStrategy, String> {
    match value {
        "round-robin" => Ok(CommitterStrategy::RoundRobin),
        "leaf-region-balanced" => Ok(CommitterStrategy::LeafRegionBalanced),
        _ => {
            if let Some(seed) = value.strip_prefix("seeded-random:") {
                return Ok(CommitterStrategy::SeededRandom {
                    seed: parse_u64(seed, "seeded-random seed")?,
                });
            }
            if let Some(members) = value.strip_prefix("fixed-list:") {
                return Ok(CommitterStrategy::FixedList {
                    member_indexes: parse_member_list(members)?,
                });
            }
            if let Some(specification) = value.strip_prefix("weighted-random:") {
                return parse_weighted_committer(specification);
            }
            Err("--committer must be round-robin, leaf-region-balanced, seeded-random:<SEED>, fixed-list:<MEMBER,...>, or weighted-random:<SEED>:<MEMBER>=<WEIGHT>,...".to_owned())
        }
    }
}

fn parse_u64(value: &str, name: &str) -> Result<u64, String> {
    value
        .parse()
        .map_err(|_| format!("{name} must be an unsigned integer"))
}

fn parse_member_list(value: &str) -> Result<Vec<u32>, String> {
    if value.is_empty() {
        return Err("fixed-list requires at least one member index".to_owned());
    }
    value
        .split(',')
        .map(|member| parse_u32(member, "fixed-list member index"))
        .collect()
}

fn parse_weighted_committer(value: &str) -> Result<CommitterStrategy, String> {
    let (seed, entries) = value
        .split_once(':')
        .ok_or_else(|| "weighted-random requires <SEED>:<MEMBER>=<WEIGHT>,...".to_owned())?;
    if entries.is_empty() {
        return Err("weighted-random requires at least one member weight".to_owned());
    }
    let weights = entries
        .split(',')
        .map(|entry| {
            let (member_index, weight) = entry
                .split_once('=')
                .ok_or_else(|| "weighted-random entries must be <MEMBER>=<WEIGHT>".to_owned())?;
            Ok(CommitterWeight {
                member_index: parse_u32(member_index, "weighted-random member index")?,
                weight: parse_u32(weight, "weighted-random weight")?,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok(CommitterStrategy::WeightedRandom {
        seed: parse_u64(seed, "weighted-random seed")?,
        weights,
    })
}

fn print_usage() {
    println!(
        "Usage: generate_baseline_report --group-id <PUBLIC_ID> --initial-members <N> --maximum-members <N> --operations <N> --regions <N> --workload <PROFILE> --committer <STRATEGY> --output output/<run> --report report/<run>\n\
         \n\
         Workloads: update-only | mixed | removal-heavy | region-skewed:<REGION> | uniform:<SEED>\n\
         Committers: round-robin | leaf-region-balanced | seeded-random:<SEED> | fixed-list:<MEMBER,...> | weighted-random:<SEED>:<MEMBER>=<WEIGHT>,...\n\
         All inputs are public. The command writes create-new redacted artifacts and never treats unavailable experimental metrics as zero."
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_all_workload_families() {
        assert!(matches!(
            parse_workload("update-only"),
            Ok(WorkloadProfile::UpdateOnly)
        ));
        assert!(matches!(
            parse_workload("mixed"),
            Ok(WorkloadProfile::Mixed)
        ));
        assert!(matches!(
            parse_workload("removal-heavy"),
            Ok(WorkloadProfile::RemovalHeavy)
        ));
        assert!(matches!(
            parse_workload("region-skewed:2"),
            Ok(WorkloadProfile::RegionSkewed {
                preferred_region: 2
            })
        ));
        assert!(matches!(
            parse_workload("uniform:42"),
            Ok(WorkloadProfile::Uniform { seed: 42 })
        ));
    }

    #[test]
    fn parses_all_committer_strategies() {
        assert!(matches!(
            parse_committer("round-robin"),
            Ok(CommitterStrategy::RoundRobin)
        ));
        assert!(matches!(
            parse_committer("leaf-region-balanced"),
            Ok(CommitterStrategy::LeafRegionBalanced)
        ));
        assert!(matches!(
            parse_committer("seeded-random:42"),
            Ok(CommitterStrategy::SeededRandom { seed: 42 })
        ));
        assert!(matches!(
            parse_committer("fixed-list:0,1"),
            Ok(CommitterStrategy::FixedList { member_indexes }) if member_indexes == [0, 1]
        ));
        assert!(matches!(
            parse_committer("weighted-random:7:0=1,1=2"),
            Ok(CommitterStrategy::WeightedRandom { seed: 7, weights })
                if weights == [
                    CommitterWeight { member_index: 0, weight: 1 },
                    CommitterWeight { member_index: 1, weight: 2 },
                ]
        ));
    }
}
