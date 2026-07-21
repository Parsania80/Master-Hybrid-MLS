#![forbid(unsafe_code)]

//! Reproducible, availability-aware three-mode comparison artifacts.
//!
//! The maintained workspace can execute only unchanged baseline MLS. This
//! module therefore preserves real baseline observations while recording the
//! two requested experimental modes as unavailable until an OpenMLS fork
//! injects their authenticated behavior.

use std::{
    fmt::Write as FmtWrite,
    path::{Path, PathBuf},
};

use csv::WriterBuilder;
use experiment_config::{ConfigError, ExperimentConfig, ExperimentMode};
use serde::Serialize;
use thiserror::Error;

use crate::generation::{validate_artifact_directory, write_new, ReportArtifactError};
use simulation::{
    execute_baseline_workload, BaselineWorkloadConfig, CommitterStrategy, WorkloadExecutionError,
    WorkloadProfile,
};

/// Version of the public Task 57 comparison artifact family.
pub const MODE_COMPARISON_SCHEMA_VERSION: u16 = 1;
/// Name of the machine-readable comparison table.
pub const MODE_COMPARISON_CSV_FILE_NAME: &str = "mode_comparison.csv";
/// Name of the machine-readable comparison manifest.
pub const MODE_COMPARISON_JSON_FILE_NAME: &str = "mode_comparison.json";
/// Name of the human-readable comparison report.
pub const MODE_COMPARISON_MARKDOWN_FILE_NAME: &str = "mode_comparison.md";

const EXPERIMENTAL_FORK_REASON: &str = "RequiresExperimentalOpenMlsFork";
const BASELINE_MODE: &str = "baseline-binary-mls";
const MKYBER_MODE: &str = "binary-mls-with-mkyber";
const ADAPTIVE_MODE: &str = "adaptive-binary-to-quaternary-mls";

/// Public workload shape shared by every selected mode configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ComparisonWorkloadShape {
    /// Initial valid baseline members. At least two are required.
    pub initial_member_count: u32,
    /// Maximum valid baseline members after Add operations.
    pub maximum_member_count: u32,
    /// Accepted operations attempted in every independent repetition.
    pub operation_count: u32,
    /// Stable public region labels used by the deterministic scheduler.
    pub region_count: u32,
}

/// Public paths generated for one mode-comparison request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModeComparisonArtifactPaths {
    /// Long-form per-mode measurement status and numeric observations.
    pub comparison_csv: PathBuf,
    /// Complete safe public comparison manifest and raw baseline run facts.
    pub comparison_json: PathBuf,
    /// Human-readable limitations and reproducibility report.
    pub comparison_markdown: PathBuf,
}

/// Errors from comparison validation, baseline execution, or artifact output.
#[derive(Debug, Error)]
pub enum ModeComparisonError {
    /// A supplied public TOML configuration is malformed.
    #[error("{mode} configuration is invalid")]
    Configuration {
        /// Expected public selected mode.
        mode: &'static str,
        /// Detailed typed public configuration error.
        #[source]
        source: ConfigError,
    },
    /// The three supplied files are not a like-for-like configuration comparison.
    #[error("the three mode configurations differ in {field}")]
    NonComparableConfigurations {
        /// Public control group that differs.
        field: &'static str,
    },
    /// There would be no post-warmup observations to report.
    #[error("operation count must exceed configured warmup accepted commits")]
    NoPostWarmupObservations,
    /// The maintained RFC 9420 baseline could not execute and converge.
    #[error("baseline repetition failed")]
    Workload(#[source] WorkloadExecutionError),
    /// A public integer count could not be represented in the artifact schema.
    #[error("public comparison count overflowed")]
    CountOverflow,
    /// Report-artifact safe-path/create-new/encoding failure.
    #[error("comparison artifact output failed")]
    Artifact(#[from] ReportArtifactError),
    /// The comparison CSV could not be encoded.
    #[error("comparison CSV serialization failed")]
    Csv(#[source] csv::Error),
    /// The comparison JSON could not be encoded.
    #[error("comparison JSON serialization failed")]
    Json(#[source] serde_json::Error),
}

#[derive(Clone, Debug, Serialize)]
struct BaselineRun {
    run_index: u32,
    workload_seed: u64,
    committer_seed: u64,
    accepted_post_warmup_commits: u32,
    baseline_commit_bytes: u128,
    welcome_bytes: u128,
    accepted_lifecycle_nanoseconds: u128,
}

#[derive(Clone, Debug, Serialize)]
struct ComparisonRow {
    mode: &'static str,
    run_index: Option<u32>,
    measurement: &'static str,
    unit: &'static str,
    value_state: &'static str,
    numeric_value: Option<u128>,
    reason: Option<&'static str>,
    provenance: &'static str,
}

#[derive(Serialize)]
struct ComparisonManifest<'a> {
    schema_version: u16,
    selected_modes: [&'static str; 3],
    status: &'static str,
    baseline_configuration_toml: &'a str,
    mkyber_configuration_toml: &'a str,
    adaptive_configuration_toml: &'a str,
    workload_shape: ComparisonWorkloadShapeJson,
    seed_derivation: &'static str,
    baseline_runs: &'a [BaselineRun],
    unavailable_comparisons: [&'static str; 3],
}

#[derive(Serialize)]
struct ComparisonWorkloadShapeJson {
    initial_member_count: u32,
    maximum_member_count: u32,
    operation_count: u32,
    region_count: u32,
}

/// Executes reproducible baseline repetitions and writes an availability-aware
/// comparison of all three roadmap modes.
///
/// Configurations are parsed with the typed public schema and must select the
/// expected mode while sharing group, transition, and execution controls. The
/// configured workload seed derives public run-local uniform-workload and
/// committer seeds. It never reconstructs MLS private-key entropy.
pub fn generate_mode_comparison(
    baseline_configuration_toml: &str,
    mkyber_configuration_toml: &str,
    adaptive_configuration_toml: &str,
    workload_shape: ComparisonWorkloadShape,
    output_directory: &Path,
    report_directory: &Path,
) -> Result<ModeComparisonArtifactPaths, ModeComparisonError> {
    let baseline = parse_expected_mode(
        baseline_configuration_toml,
        ExperimentMode::BaselineBinaryMls,
        BASELINE_MODE,
    )?;
    let mkyber = parse_expected_mode(
        mkyber_configuration_toml,
        ExperimentMode::BinaryMlsWithMkyber,
        MKYBER_MODE,
    )?;
    let adaptive = parse_expected_mode(
        adaptive_configuration_toml,
        ExperimentMode::AdaptiveBinaryToQuaternaryMls,
        ADAPTIVE_MODE,
    )?;
    validate_comparable(&baseline, &mkyber, &adaptive)?;
    if workload_shape.operation_count <= baseline.execution.warmup_accepted_commits {
        return Err(ModeComparisonError::NoPostWarmupObservations);
    }
    validate_artifact_directory(output_directory, "output", "comparison machine-readable")?;
    validate_artifact_directory(report_directory, "report", "comparison Markdown")?;

    let mut baseline_runs = Vec::new();
    for run_index in 1..=baseline.execution.repetitions {
        let (workload_seed, committer_seed) =
            derive_run_seeds(baseline.execution.workload_seed, run_index);
        let workload = BaselineWorkloadConfig {
            group_id: format!(
                "task57-baseline-{}-{run_index}",
                baseline.execution.workload_seed
            )
            .into_bytes(),
            initial_member_count: workload_shape.initial_member_count,
            maximum_member_count: workload_shape.maximum_member_count,
            operation_count: workload_shape.operation_count,
            region_count: workload_shape.region_count,
            committer_strategy: CommitterStrategy::SeededRandom {
                seed: committer_seed,
            },
            workload_profile: WorkloadProfile::Uniform {
                seed: workload_seed,
            },
        };
        let execution =
            execute_baseline_workload(&workload).map_err(ModeComparisonError::Workload)?;
        let retained = execution.accepted_operations.iter().skip(
            usize::try_from(baseline.execution.warmup_accepted_commits)
                .map_err(|_| ModeComparisonError::CountOverflow)?,
        );
        let mut accepted_post_warmup_commits = 0_u32;
        let mut baseline_commit_bytes = 0_u128;
        let mut welcome_bytes = 0_u128;
        let mut accepted_lifecycle_nanoseconds = 0_u128;
        for operation in retained {
            accepted_post_warmup_commits = accepted_post_warmup_commits
                .checked_add(1)
                .ok_or(ModeComparisonError::CountOverflow)?;
            baseline_commit_bytes = baseline_commit_bytes
                .checked_add(u128::from(operation.measurement.emitted_commit_bytes))
                .ok_or(ModeComparisonError::CountOverflow)?;
            welcome_bytes = welcome_bytes
                .checked_add(u128::from(
                    operation.measurement.emitted_welcome_bytes.unwrap_or(0),
                ))
                .ok_or(ModeComparisonError::CountOverflow)?;
            accepted_lifecycle_nanoseconds = accepted_lifecycle_nanoseconds
                .checked_add(operation.measurement.accepted_lifecycle_elapsed_nanoseconds)
                .ok_or(ModeComparisonError::CountOverflow)?;
        }
        baseline_runs.push(BaselineRun {
            run_index,
            workload_seed,
            committer_seed,
            accepted_post_warmup_commits,
            baseline_commit_bytes,
            welcome_bytes,
            accepted_lifecycle_nanoseconds,
        });
    }

    let paths = ModeComparisonArtifactPaths {
        comparison_csv: output_directory.join(MODE_COMPARISON_CSV_FILE_NAME),
        comparison_json: output_directory.join(MODE_COMPARISON_JSON_FILE_NAME),
        comparison_markdown: report_directory.join(MODE_COMPARISON_MARKDOWN_FILE_NAME),
    };
    for path in [
        &paths.comparison_csv,
        &paths.comparison_json,
        &paths.comparison_markdown,
    ] {
        if path.exists() {
            return Err(ModeComparisonError::Artifact(
                ReportArtifactError::ArtifactAlreadyExists,
            ));
        }
    }
    std::fs::create_dir_all(output_directory)
        .map_err(|error| ModeComparisonError::Artifact(ReportArtifactError::Write(error)))?;
    std::fs::create_dir_all(report_directory)
        .map_err(|error| ModeComparisonError::Artifact(ReportArtifactError::Write(error)))?;
    let rows = comparison_rows(&baseline_runs);
    let manifest = ComparisonManifest {
        schema_version: MODE_COMPARISON_SCHEMA_VERSION,
        selected_modes: [BASELINE_MODE, MKYBER_MODE, ADAPTIVE_MODE],
        status: "partial: baseline executable; experimental modes unavailable",
        baseline_configuration_toml,
        mkyber_configuration_toml,
        adaptive_configuration_toml,
        workload_shape: ComparisonWorkloadShapeJson {
            initial_member_count: workload_shape.initial_member_count,
            maximum_member_count: workload_shape.maximum_member_count,
            operation_count: workload_shape.operation_count,
            region_count: workload_shape.region_count,
        },
        seed_derivation: "For run index r (one-based): uniform workload seed = workload_seed XOR 0x5457_3537_0000_0000 XOR r; seeded committer seed = workload_seed XOR 0x434f_4d50_0000_0000 XOR r. These are public scheduling seeds only, never MLS key-generation entropy.",
        baseline_runs: &baseline_runs,
        unavailable_comparisons: [
            "Bandwidth outcome: unavailable because BinaryMlsWithMkyber does not execute in an OpenMLS fork.",
            "mKyber CPU overhead: unavailable because the mKyber path is not injected into accepted MLS commits.",
            "Adaptive 2-to-4 break-even point: unavailable because no authenticated transition, candidate emission, or transition preflight executes.",
        ],
    };

    write_new(&paths.comparison_csv, &comparison_csv(&rows)?)?;
    write_new(
        &paths.comparison_json,
        &serde_json::to_vec_pretty(&manifest).map_err(ModeComparisonError::Json)?,
    )?;
    write_new(
        &paths.comparison_markdown,
        comparison_markdown(&manifest, &rows).as_bytes(),
    )?;
    Ok(paths)
}

fn parse_expected_mode(
    toml: &str,
    expected: ExperimentMode,
    mode_name: &'static str,
) -> Result<ExperimentConfig, ModeComparisonError> {
    let config = ExperimentConfig::parse_toml(toml).map_err(|source| {
        ModeComparisonError::Configuration {
            mode: mode_name,
            source,
        }
    })?;
    if config.mode != expected {
        return Err(ModeComparisonError::Configuration {
            mode: mode_name,
            source: ConfigError::Invalid {
                field: "mode",
                reason: "does not select the expected comparison mode",
            },
        });
    }
    Ok(config)
}

fn validate_comparable(
    baseline: &ExperimentConfig,
    mkyber: &ExperimentConfig,
    adaptive: &ExperimentConfig,
) -> Result<(), ModeComparisonError> {
    for candidate in [mkyber, adaptive] {
        if candidate.group != baseline.group {
            return Err(ModeComparisonError::NonComparableConfigurations { field: "group" });
        }
        if candidate.transition != baseline.transition {
            return Err(ModeComparisonError::NonComparableConfigurations {
                field: "transition",
            });
        }
        if candidate.execution != baseline.execution {
            return Err(ModeComparisonError::NonComparableConfigurations { field: "execution" });
        }
    }
    Ok(())
}

fn derive_run_seeds(workload_seed: u64, run_index: u32) -> (u64, u64) {
    let index = u64::from(run_index);
    (
        workload_seed ^ 0x5457_3537_0000_0000 ^ index,
        workload_seed ^ 0x434f_4d50_0000_0000 ^ index,
    )
}

fn comparison_rows(baseline_runs: &[BaselineRun]) -> Vec<ComparisonRow> {
    let mut rows = Vec::new();
    for run in baseline_runs {
        rows.extend([
            observed_row(run.run_index, "accepted_post_warmup_commits", "commits", u128::from(run.accepted_post_warmup_commits), "accepted unchanged baseline commits after configured warmup"),
            observed_row(run.run_index, "baseline_commit_bytes", "bytes", run.baseline_commit_bytes, "actual serialized RFC 9420 Commit bytes after configured warmup"),
            observed_row(run.run_index, "welcome_bytes", "bytes", run.welcome_bytes, "actual serialized Welcome bytes after configured warmup; zero is observed when no retained Add emitted a Welcome"),
            observed_row(run.run_index, "accepted_lifecycle_nanoseconds", "nanoseconds", run.accepted_lifecycle_nanoseconds, "monotonic end-to-end baseline lifecycle timing after configured warmup; environment-dependent"),
        ]);
    }
    for mode in [MKYBER_MODE, ADAPTIVE_MODE] {
        rows.extend([
            unavailable_row(mode, "bandwidth_outcome", "bytes"),
            unavailable_row(mode, "mkyber_cpu_overhead", "nanoseconds"),
            unavailable_row(mode, "break_even_point", "bytes"),
        ]);
    }
    rows
}

fn observed_row(
    run_index: u32,
    measurement: &'static str,
    unit: &'static str,
    numeric_value: u128,
    provenance: &'static str,
) -> ComparisonRow {
    ComparisonRow {
        mode: BASELINE_MODE,
        run_index: Some(run_index),
        measurement,
        unit,
        value_state: "observed",
        numeric_value: Some(numeric_value),
        reason: None,
        provenance,
    }
}

fn unavailable_row(
    mode: &'static str,
    measurement: &'static str,
    unit: &'static str,
) -> ComparisonRow {
    ComparisonRow {
        mode,
        run_index: None,
        measurement,
        unit,
        value_state: "unavailable",
        numeric_value: None,
        reason: Some(EXPERIMENTAL_FORK_REASON),
        provenance: "No authenticated experimental OpenMLS-fork execution exists; unavailable is not zero or an estimate.",
    }
}

fn comparison_csv(rows: &[ComparisonRow]) -> Result<Vec<u8>, ModeComparisonError> {
    let mut writer = WriterBuilder::new()
        .has_headers(true)
        .from_writer(Vec::new());
    for row in rows {
        writer.serialize(row).map_err(ModeComparisonError::Csv)?;
    }
    writer
        .into_inner()
        .map_err(|error| ModeComparisonError::Csv(error.into_error().into()))
}

fn comparison_markdown(manifest: &ComparisonManifest<'_>, rows: &[ComparisonRow]) -> String {
    let mut report = String::new();
    writeln!(report, "# Task 57 Reproducible Mode Comparison").expect("string write");
    writeln!(report).expect("string write");
    writeln!(report, "**Status:** {}.", manifest.status).expect("string write");
    writeln!(report).expect("string write");
    writeln!(report, "## Reproducibility inputs").expect("string write");
    writeln!(report).expect("string write");
    writeln!(report, "- Schema version: {}", manifest.schema_version).expect("string write");
    writeln!(report, "- Modes: {}", manifest.selected_modes.join(", ")).expect("string write");
    writeln!(
        report,
        "- Workload: {} initial members, maximum {}, {} accepted operations, {} regions.",
        manifest.workload_shape.initial_member_count,
        manifest.workload_shape.maximum_member_count,
        manifest.workload_shape.operation_count,
        manifest.workload_shape.region_count
    )
    .expect("string write");
    writeln!(report, "- {}", manifest.seed_derivation).expect("string write");
    writeln!(report).expect("string write");
    writeln!(report, "## Observed baseline repetitions").expect("string write");
    writeln!(report).expect("string write");
    writeln!(report, "| Run | Retained commits | Commit bytes | Welcome bytes | Lifecycle ns |\n|---:|---:|---:|---:|---:|").expect("string write");
    for run in manifest.baseline_runs {
        writeln!(
            report,
            "| {} | {} | {} | {} | {} |",
            run.run_index,
            run.accepted_post_warmup_commits,
            run.baseline_commit_bytes,
            run.welcome_bytes,
            run.accepted_lifecycle_nanoseconds
        )
        .expect("string write");
    }
    writeln!(report).expect("string write");
    writeln!(report, "The baseline values are measured unchanged-RFC-9420 observations. Lifecycle timings are environment-dependent and must not be interpreted as stable performance claims.").expect("string write");
    writeln!(report).expect("string write");
    writeln!(report, "## Comparison outcome").expect("string write");
    writeln!(report).expect("string write");
    for unavailable in manifest.unavailable_comparisons {
        writeln!(report, "- {unavailable}").expect("string write");
    }
    writeln!(report).expect("string write");
    writeln!(report, "No baseline-to-experimental bandwidth delta, mKyber CPU overhead, or adaptive break-even result is reported because doing so would require values for unexecuted modes.").expect("string write");
    writeln!(report).expect("string write");
    writeln!(report, "## Threats to validity").expect("string write");
    writeln!(report).expect("string write");
    for threat in [
        "The experimental mKyber delivery and adaptive transition implementations are isolated boundaries, not injected into an authenticated OpenMLS Commit path.",
        "The baseline harness is an in-process convergence test; it does not model network latency, transport loss, distributed scheduling, or heterogeneous hardware.",
        "Fresh MLS key material uses operating-system randomness, so public workload seeds reproduce logical scheduling but not private cryptographic state.",
        "The sample records raw independent runs only; no pooled-commit inference or experimental performance conclusion is justified.",
    ] {
        writeln!(report, "- {threat}").expect("string write");
    }
    writeln!(report).expect("string write");
    writeln!(report, "## Exact public configuration files").expect("string write");
    writeln!(report).expect("string write");
    for (name, config) in [
        (BASELINE_MODE, manifest.baseline_configuration_toml),
        (MKYBER_MODE, manifest.mkyber_configuration_toml),
        (ADAPTIVE_MODE, manifest.adaptive_configuration_toml),
    ] {
        writeln!(report, "### {name}\n\n```toml\n{config}\n```").expect("string write");
    }
    writeln!(
        report,
        "## Machine-readable row count\n\n{} rows in `{}`.",
        rows.len(),
        MODE_COMPARISON_CSV_FILE_NAME
    )
    .expect("string write");
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::Builder;

    fn config(mode: &str) -> String {
        format!(
            r#"mode = "{mode}"

[group]
target_group_size = 4
current_arity = 2
candidate_arity = 4

[transition]
window_accepted_commits = 2
stable_epoch_count = 1
q_min = 1
theta_new_micro = 700000
theta_old_micro = 500000
delta_bytes = 1

[execution]
warmup_accepted_commits = 1
repetitions = 2
workload_seed = 42

[output]
output_directory = "output/unused"
report_directory = "report/unused"
"#
        )
    }

    fn relative_test_path(directory: &tempfile::TempDir) -> PathBuf {
        directory
            .path()
            .strip_prefix(std::env::current_dir().expect("test working directory"))
            .expect("temporary directory below working directory")
            .to_path_buf()
    }

    #[test]
    fn writes_observed_baseline_and_typed_unavailable_experimental_rows() {
        fs::create_dir_all("output").expect("output parent");
        fs::create_dir_all("report").expect("report parent");
        let output = Builder::new()
            .prefix("task57-output-")
            .tempdir_in("output")
            .expect("output tempdir");
        let report = Builder::new()
            .prefix("task57-report-")
            .tempdir_in("report")
            .expect("report tempdir");
        let paths = generate_mode_comparison(
            &config("baseline-binary-mls"),
            &config("binary-mls-with-mkyber"),
            &config("adaptive-binary-to-quaternary-mls"),
            ComparisonWorkloadShape {
                initial_member_count: 2,
                maximum_member_count: 3,
                operation_count: 3,
                region_count: 2,
            },
            &relative_test_path(&output),
            &relative_test_path(&report),
        )
        .expect("comparison artifacts");

        let csv = fs::read_to_string(paths.comparison_csv).expect("comparison CSV");
        assert!(csv.contains("baseline_commit_bytes"));
        assert!(csv.contains(EXPERIMENTAL_FORK_REASON));
        let json = fs::read_to_string(paths.comparison_json).expect("comparison JSON");
        assert!(json.contains("baseline_runs"));
        let markdown = fs::read_to_string(paths.comparison_markdown).expect("comparison Markdown");
        assert!(markdown.contains("Threats to validity"));
        assert!(markdown.contains("No baseline-to-experimental bandwidth delta"));
    }

    #[test]
    fn rejects_non_comparable_public_controls() {
        let baseline = config("baseline-binary-mls");
        let mkyber = config("binary-mls-with-mkyber").replace("q_min = 1", "q_min = 2");
        let adaptive = config("adaptive-binary-to-quaternary-mls");
        assert!(matches!(
            generate_mode_comparison(
                &baseline,
                &mkyber,
                &adaptive,
                ComparisonWorkloadShape {
                    initial_member_count: 2,
                    maximum_member_count: 3,
                    operation_count: 3,
                    region_count: 2,
                },
                Path::new("output/task57-invalid"),
                Path::new("report/task57-invalid"),
            ),
            Err(ModeComparisonError::NonComparableConfigurations {
                field: "transition"
            })
        ));
    }
}
