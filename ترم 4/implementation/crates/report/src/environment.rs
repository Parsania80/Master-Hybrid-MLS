#![forbid(unsafe_code)]

//! Minimal Linux environment and per-run peak-RSS evidence for Task 63.
//!
//! This is intentionally not a general monitoring framework. It reads stable
//! public Linux files and samples only the directly launched child process's
//! `VmHWM` field while that process remains alive. Command arguments are never
//! serialized into the public artifacts.

use std::{
    ffi::OsString,
    fs,
    path::PathBuf,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use csv::WriterBuilder;
use experimental_mls_adapter::{
    CLASSICAL_MLS_HPKE_PROFILE, EDUCATIONAL_MKYBER_PROFILE, OPENMLS_HYBRID_UPSTREAM_REVISION,
};
use serde::Serialize;
use thiserror::Error;

use crate::generation::{validate_artifact_directory, write_new, ReportArtifactError};

/// Version of the public Task 63 environment artifact schema.
pub const ENVIRONMENT_SCHEMA_VERSION: u16 = 1;
/// Canonical public environment JSON name.
pub const ENVIRONMENT_JSON_FILE_NAME: &str = "environment.json";
/// Canonical public long-form environment CSV name.
pub const ENVIRONMENT_CSV_FILE_NAME: &str = "environment.csv";
/// Canonical public per-run peak-RSS CSV name.
pub const PEAK_RSS_CSV_FILE_NAME: &str = "peak_rss.csv";

/// Explicit controls for one direct-child RSS collection.
#[derive(Clone, Debug)]
pub struct LinuxEnvironmentCollectionConfig {
    /// Create-new machine-readable output directory below `output/`.
    pub output_directory: PathBuf,
    /// Public descriptive name for all repeated runs; command arguments are not recorded.
    pub run_label: String,
    /// Number of sequential direct-child executions.
    pub repetitions: u32,
    /// Direct executable to launch and sample.
    pub program: PathBuf,
    /// Opaque child arguments; passed to the process but never serialized.
    pub arguments: Vec<OsString>,
}

/// Locations of the three Task 63 public artifacts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnvironmentArtifactPaths {
    /// Complete public environment manifest.
    pub environment_json: PathBuf,
    /// Long-form public implementation-environment values.
    pub environment_csv: PathBuf,
    /// Per-direct-child process peak-RSS observations.
    pub peak_rss_csv: PathBuf,
}

/// Errors from the deliberately Linux-only collector.
#[derive(Debug, Error)]
pub enum EnvironmentCollectionError {
    /// This minimal collector intentionally has no cross-platform fallback.
    #[error("Task 63 environment collection requires Linux /proc and /etc/os-release")]
    UnsupportedPlatform,
    /// A required public control is invalid.
    #[error("Task 63 collection controls are invalid")]
    InvalidControls,
    /// A required Linux field was absent or could not be parsed.
    #[error("required Linux field `{field}` was absent or invalid")]
    InvalidLinuxField {
        /// Stable public field name.
        field: &'static str,
    },
    /// `rustc --version --verbose` could not execute or return success.
    #[error("could not collect the installed Rust toolchain version")]
    RustVersion,
    /// A required public Linux file could not be read.
    #[error("could not read required public Linux system information")]
    LinuxInfo(#[source] std::io::Error),
    /// The direct workload child could not be started.
    #[error("could not start the direct workload child")]
    Spawn(#[source] std::io::Error),
    /// The direct workload child returned a non-success status.
    #[error("a direct workload child returned a non-success status")]
    ChildFailed,
    /// Artifact safe-path/create-new/encoding failure.
    #[error("environment artifact output failed")]
    Artifact(#[from] ReportArtifactError),
    /// CSV encoding failure.
    #[error("environment CSV serialization failed")]
    Csv(#[source] csv::Error),
    /// JSON encoding failure.
    #[error("environment JSON serialization failed")]
    Json(#[source] serde_json::Error),
}

#[derive(Clone, Debug, Serialize)]
struct EnvironmentManifest {
    schema_version: u16,
    collected_at_unix_seconds: u64,
    run_label: String,
    configured_repetitions: u32,
    direct_child_rss_method: &'static str,
    command_argument_policy: &'static str,
    rust_version_verbose: String,
    openmls_hybrid_upstream_revision: &'static str,
    classical_mls_hpke_profile: &'static str,
    educational_mkyber_profile: &'static str,
    cpu_model: String,
    installed_memory_kib: u64,
    operating_system: String,
    kernel_release: String,
    runs: Vec<PeakRssRun>,
}

#[derive(Clone, Debug, Serialize)]
struct EnvironmentCsvRow {
    schema_version: u16,
    field: &'static str,
    value: String,
    unit: &'static str,
    collection_method: &'static str,
    provenance: &'static str,
}

#[derive(Clone, Debug, Serialize)]
struct PeakRssRun {
    run_index: u32,
    run_label: String,
    elapsed_nanoseconds: u128,
    peak_rss_kib: Option<u64>,
    value_state: &'static str,
    reason: Option<&'static str>,
    collection_method: &'static str,
    program_basename: String,
}

/// Collects the required public Linux facts and repeated direct-child peak RSS.
///
/// `VmHWM` is sampled from `/proc/<pid>/status` while the direct child lives.
/// It excludes descendants, so callers must pass the actual workload executable
/// rather than a launcher that exits before its child process.
pub fn collect_linux_environment(
    config: &LinuxEnvironmentCollectionConfig,
) -> Result<EnvironmentArtifactPaths, EnvironmentCollectionError> {
    if !cfg!(target_os = "linux") {
        return Err(EnvironmentCollectionError::UnsupportedPlatform);
    }
    if config.repetitions == 0
        || config.run_label.trim().is_empty()
        || config.program.as_os_str().is_empty()
    {
        return Err(EnvironmentCollectionError::InvalidControls);
    }
    validate_artifact_directory(&config.output_directory, "output", "environment evidence")?;
    let paths = EnvironmentArtifactPaths {
        environment_json: config.output_directory.join(ENVIRONMENT_JSON_FILE_NAME),
        environment_csv: config.output_directory.join(ENVIRONMENT_CSV_FILE_NAME),
        peak_rss_csv: config.output_directory.join(PEAK_RSS_CSV_FILE_NAME),
    };
    for path in [
        &paths.environment_json,
        &paths.environment_csv,
        &paths.peak_rss_csv,
    ] {
        if path.exists() {
            return Err(EnvironmentCollectionError::Artifact(
                ReportArtifactError::ArtifactAlreadyExists,
            ));
        }
    }

    let manifest = EnvironmentManifest {
        schema_version: ENVIRONMENT_SCHEMA_VERSION,
        collected_at_unix_seconds: unix_seconds(),
        run_label: config.run_label.clone(),
        configured_repetitions: config.repetitions,
        direct_child_rss_method: "sample /proc/<direct-child-pid>/status VmHWM (KiB) every 10 ms while the child is alive",
        command_argument_policy: "child arguments are intentionally not serialized",
        rust_version_verbose: rust_version_verbose()?,
        openmls_hybrid_upstream_revision: OPENMLS_HYBRID_UPSTREAM_REVISION,
        classical_mls_hpke_profile: CLASSICAL_MLS_HPKE_PROFILE,
        educational_mkyber_profile: EDUCATIONAL_MKYBER_PROFILE,
        cpu_model: proc_cpu_model()?,
        installed_memory_kib: proc_mem_total_kib()?,
        operating_system: os_release_pretty_name()?,
        kernel_release: proc_kernel_release()?,
        runs: collect_peak_rss_runs(config)?,
    };
    fs::create_dir_all(&config.output_directory)
        .map_err(|error| EnvironmentCollectionError::Artifact(ReportArtifactError::Write(error)))?;
    write_new(
        &paths.environment_json,
        &serde_json::to_vec_pretty(&manifest).map_err(EnvironmentCollectionError::Json)?,
    )?;
    write_new(&paths.environment_csv, &environment_csv(&manifest)?)?;
    write_new(&paths.peak_rss_csv, &peak_rss_csv(&manifest.runs)?)?;
    Ok(paths)
}

fn collect_peak_rss_runs(
    config: &LinuxEnvironmentCollectionConfig,
) -> Result<Vec<PeakRssRun>, EnvironmentCollectionError> {
    let program_basename = config
        .program
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("direct-workload")
        .to_owned();
    let mut runs = Vec::with_capacity(usize::try_from(config.repetitions).expect("u32 fits usize"));
    for run_index in 1..=config.repetitions {
        let mut child = Command::new(&config.program)
            .args(&config.arguments)
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(EnvironmentCollectionError::Spawn)?;
        let started = Instant::now();
        let mut peak_rss_kib = None;
        loop {
            if let Some(value) = proc_vm_hwm_kib(child.id())? {
                peak_rss_kib = Some(peak_rss_kib.unwrap_or(0).max(value));
            }
            if let Some(status) = child
                .try_wait()
                .map_err(EnvironmentCollectionError::Spawn)?
            {
                if !status.success() {
                    return Err(EnvironmentCollectionError::ChildFailed);
                }
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        let (value_state, reason) = match peak_rss_kib {
            Some(_) => ("observed", None),
            None => ("unavailable", Some("ProcessExitedBeforeProcSample")),
        };
        runs.push(PeakRssRun {
            run_index,
            run_label: config.run_label.clone(),
            elapsed_nanoseconds: started.elapsed().as_nanos(),
            peak_rss_kib,
            value_state,
            reason,
            collection_method: "sampled direct-child /proc/<pid>/status VmHWM",
            program_basename: program_basename.clone(),
        });
    }
    Ok(runs)
}

fn rust_version_verbose() -> Result<String, EnvironmentCollectionError> {
    let output = Command::new("rustc")
        .args(["--version", "--verbose"])
        .output()
        .map_err(|_| EnvironmentCollectionError::RustVersion)?;
    if !output.status.success() {
        return Err(EnvironmentCollectionError::RustVersion);
    }
    String::from_utf8(output.stdout)
        .map(|value| value.trim().to_owned())
        .map_err(|_| EnvironmentCollectionError::RustVersion)
}

fn proc_cpu_model() -> Result<String, EnvironmentCollectionError> {
    proc_value("/proc/cpuinfo", "model name")
}

fn proc_mem_total_kib() -> Result<u64, EnvironmentCollectionError> {
    let value = proc_value("/proc/meminfo", "MemTotal")?;
    value
        .split_whitespace()
        .next()
        .ok_or(EnvironmentCollectionError::InvalidLinuxField { field: "MemTotal" })?
        .parse()
        .map_err(|_| EnvironmentCollectionError::InvalidLinuxField { field: "MemTotal" })
}

fn proc_kernel_release() -> Result<String, EnvironmentCollectionError> {
    proc_value("/proc/sys/kernel/osrelease", "")
}

fn proc_value(path: &str, key: &'static str) -> Result<String, EnvironmentCollectionError> {
    let content = fs::read_to_string(path).map_err(EnvironmentCollectionError::LinuxInfo)?;
    if key.is_empty() {
        return Ok(content.trim().to_owned());
    }
    content
        .lines()
        .find_map(|line| {
            line.split_once(':')
                .filter(|(name, _)| name.trim() == key)
                .map(|(_, value)| value.trim().to_owned())
        })
        .ok_or(EnvironmentCollectionError::InvalidLinuxField { field: key })
}

fn os_release_pretty_name() -> Result<String, EnvironmentCollectionError> {
    let content =
        fs::read_to_string("/etc/os-release").map_err(EnvironmentCollectionError::LinuxInfo)?;
    content
        .lines()
        .find_map(|line| line.strip_prefix("PRETTY_NAME=").map(unquote_os_release))
        .ok_or(EnvironmentCollectionError::InvalidLinuxField {
            field: "PRETTY_NAME",
        })
}

fn unquote_os_release(value: &str) -> String {
    value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .unwrap_or(value)
        .to_owned()
}

fn proc_vm_hwm_kib(pid: u32) -> Result<Option<u64>, EnvironmentCollectionError> {
    let path = format!("/proc/{pid}/status");
    let content = match fs::read_to_string(path) {
        Ok(content) => content,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(EnvironmentCollectionError::LinuxInfo(error)),
    };
    let Some(value) = content
        .lines()
        .find_map(|line| line.strip_prefix("VmHWM:"))
        .and_then(|value| value.split_whitespace().next())
    else {
        // `spawn` can expose a direct child in /proc before it has completed
        // exec and installed memory accounting. The polling loop will retry.
        return Ok(None);
    };
    value
        .parse()
        .map(Some)
        .map_err(|_| EnvironmentCollectionError::InvalidLinuxField { field: "VmHWM" })
}

fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn environment_csv(manifest: &EnvironmentManifest) -> Result<Vec<u8>, EnvironmentCollectionError> {
    let rows = [
        environment_row(
            "rust_version_verbose",
            &manifest.rust_version_verbose,
            "text",
            "rustc --version --verbose",
            "installed Rust toolchain",
        ),
        environment_row(
            "openmls_hybrid_upstream_revision",
            manifest.openmls_hybrid_upstream_revision,
            "git revision",
            "compiled fork constant",
            "experimental-mls-adapter",
        ),
        environment_row(
            "classical_mls_hpke_profile",
            manifest.classical_mls_hpke_profile,
            "profile",
            "compiled adapter constant",
            "experimental-mls-adapter",
        ),
        environment_row(
            "educational_mkyber_profile",
            manifest.educational_mkyber_profile,
            "profile",
            "compiled mKyber constant",
            "mkyber",
        ),
        environment_row(
            "cpu_model",
            &manifest.cpu_model,
            "text",
            "/proc/cpuinfo model name",
            "Linux kernel",
        ),
        environment_row(
            "installed_memory",
            &manifest.installed_memory_kib.to_string(),
            "KiB",
            "/proc/meminfo MemTotal",
            "Linux kernel",
        ),
        environment_row(
            "operating_system",
            &manifest.operating_system,
            "text",
            "/etc/os-release PRETTY_NAME",
            "operating system",
        ),
        environment_row(
            "kernel_release",
            &manifest.kernel_release,
            "text",
            "/proc/sys/kernel/osrelease",
            "Linux kernel",
        ),
        environment_row(
            "configured_repetitions",
            &manifest.configured_repetitions.to_string(),
            "runs",
            "collector CLI control",
            "Task 63 configuration",
        ),
    ];
    let mut writer = WriterBuilder::new()
        .has_headers(true)
        .from_writer(Vec::new());
    for row in rows {
        writer
            .serialize(row)
            .map_err(EnvironmentCollectionError::Csv)?;
    }
    writer
        .into_inner()
        .map_err(|error| EnvironmentCollectionError::Csv(error.into_error().into()))
}

fn environment_row(
    field: &'static str,
    value: &str,
    unit: &'static str,
    collection_method: &'static str,
    provenance: &'static str,
) -> EnvironmentCsvRow {
    EnvironmentCsvRow {
        schema_version: ENVIRONMENT_SCHEMA_VERSION,
        field,
        value: value.to_owned(),
        unit,
        collection_method,
        provenance,
    }
}

fn peak_rss_csv(runs: &[PeakRssRun]) -> Result<Vec<u8>, EnvironmentCollectionError> {
    let mut writer = WriterBuilder::new()
        .has_headers(true)
        .from_writer(Vec::new());
    for run in runs {
        writer
            .serialize(run)
            .map_err(EnvironmentCollectionError::Csv)?;
    }
    writer
        .into_inner()
        .map_err(|error| EnvironmentCollectionError::Csv(error.into_error().into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_quoted_os_release_value() {
        assert_eq!(unquote_os_release("\"Example Linux\""), "Example Linux");
    }

    #[test]
    fn parses_memory_value_without_the_kib_suffix() {
        let value = "12345 kB";
        assert_eq!(value.split_whitespace().next(), Some("12345"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn reads_live_direct_child_high_water_rss() {
        let mut child = Command::new("/bin/sleep")
            .arg("1")
            .spawn()
            .expect("sleep child");
        thread::sleep(Duration::from_millis(20));
        assert!(proc_vm_hwm_kib(child.id()).expect("VmHWM parse").is_some());
        child.wait().expect("sleep exit");
    }
}
