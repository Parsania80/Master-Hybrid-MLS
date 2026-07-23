#![forbid(unsafe_code)]

//! Collect minimal Task 63 Linux environment and direct-child peak-RSS evidence.

use std::{env, ffi::OsString, path::PathBuf, process::ExitCode};

use report::environment::{collect_linux_environment, LinuxEnvironmentCollectionConfig};

#[derive(Debug)]
struct Cli {
    output: PathBuf,
    label: String,
    repetitions: u32,
    program: PathBuf,
    arguments: Vec<OsString>,
}

fn main() -> ExitCode {
    let cli = match parse_command() {
        Ok(Some(cli)) => cli,
        Ok(None) => {
            print_usage();
            return ExitCode::SUCCESS;
        }
        Err(error) => {
            eprintln!("collect_environment: {error}\n");
            print_usage();
            return ExitCode::FAILURE;
        }
    };
    match collect_linux_environment(&LinuxEnvironmentCollectionConfig {
        output_directory: cli.output,
        run_label: cli.label,
        repetitions: cli.repetitions,
        program: cli.program,
        arguments: cli.arguments,
    }) {
        Ok(paths) => {
            println!("Generated Task 63 Linux environment evidence.");
            println!("Environment JSON: {}", paths.environment_json.display());
            println!("Environment CSV: {}", paths.environment_csv.display());
            println!("Peak RSS CSV: {}", paths.peak_rss_csv.display());
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("collect_environment: collection failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn parse_command() -> Result<Option<Cli>, String> {
    let mut output = None;
    let mut label = None;
    let mut repetitions = None;
    let mut arguments = env::args_os().skip(1);
    while let Some(argument) = arguments.next() {
        if argument == "--help" || argument == "-h" {
            return Ok(None);
        }
        if argument == "--" {
            let program = arguments.next().ok_or_else(|| {
                "-- must be followed by the direct workload executable".to_owned()
            })?;
            return Ok(Some(Cli {
                output: output.ok_or_else(|| "--output is required".to_owned())?,
                label: label.ok_or_else(|| "--label is required".to_owned())?,
                repetitions: repetitions.ok_or_else(|| "--repetitions is required".to_owned())?,
                program: PathBuf::from(program),
                arguments: arguments.collect(),
            }));
        }
        match argument.to_str() {
            Some("--output") => {
                output = Some(PathBuf::from(next_value(&mut arguments, "--output")?))
            }
            Some("--label") => {
                label = Some(os_string_to_string(
                    next_value(&mut arguments, "--label")?,
                    "--label",
                )?)
            }
            Some("--repetitions") => {
                repetitions = Some(parse_u32(
                    next_value(&mut arguments, "--repetitions")?,
                    "--repetitions",
                )?)
            }
            _ => return Err("options must precede -- <direct-workload> [arguments...]".to_owned()),
        }
    }
    Err("-- <direct-workload> [arguments...] is required".to_owned())
}

fn next_value(
    arguments: &mut impl Iterator<Item = OsString>,
    option: &str,
) -> Result<OsString, String> {
    arguments
        .next()
        .ok_or_else(|| format!("{option} requires a value"))
}

fn os_string_to_string(value: OsString, option: &str) -> Result<String, String> {
    value
        .into_string()
        .map_err(|_| format!("{option} must be valid UTF-8"))
}

fn parse_u32(value: OsString, option: &str) -> Result<u32, String> {
    os_string_to_string(value, option)?
        .parse()
        .map_err(|_| format!("{option} must be an unsigned integer"))
}

fn print_usage() {
    println!(
        "Usage: collect_environment --output output/<run> --label <public-label> --repetitions <N> -- <direct-workload> [arguments...]\n\
         \n\
         Linux only. Reads public OS/runtime facts and samples the directly launched process's /proc/<pid>/status VmHWM every 10 ms. Arguments are never serialized, so invoke the actual workload executable rather than cargo or another launcher. Existing evidence is never overwritten."
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_numeric_repetitions() {
        assert!(parse_u32(OsString::from("many"), "--repetitions").is_err());
    }
}
