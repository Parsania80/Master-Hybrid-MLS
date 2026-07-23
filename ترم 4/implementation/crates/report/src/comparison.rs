#![forbid(unsafe_code)]

//! Reproducible, availability-aware three-mode comparison artifacts.
//!
//! Every selected mode executes a real workload through its own supported
//! adapter boundary. The comparison is intentionally update-only because the
//! current fork clients do not yet expose experimental Add/Remove workloads.

use std::{
    fmt::Write as FmtWrite,
    path::{Path, PathBuf},
};

use csv::WriterBuilder;
use experiment_config::{ConfigError, ExperimentConfig, ExperimentMode};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::generation::{validate_artifact_directory, write_new, ReportArtifactError};
use experimental_mls_adapter::{
    execute_experimental_adaptive_workload_with_policy, execute_experimental_binary_workload,
    ExperimentalAdaptiveCommitPhase, ExperimentalAdaptiveTransitionPolicy,
    ExperimentalBinaryWorkloadError,
};
use simulation::{
    execute_baseline_workload, BaselineWorkloadConfig, CommitterStrategy, WorkloadExecutionError,
    WorkloadProfile,
};

/// Version of the public Task 62 comparison artifact family.
pub const MODE_COMPARISON_SCHEMA_VERSION: u16 = 1;
/// Name of the machine-readable comparison table.
pub const MODE_COMPARISON_CSV_FILE_NAME: &str = "mode_comparison.csv";
/// Name of the machine-readable comparison manifest.
pub const MODE_COMPARISON_JSON_FILE_NAME: &str = "mode_comparison.json";
/// Name of the human-readable comparison report.
pub const MODE_COMPARISON_MARKDOWN_FILE_NAME: &str = "mode_comparison.md";
/// Name of the long-form Task 62 chart input derived from comparison rows.
pub const MODE_COMPARISON_PLOT_DATA_FILE_NAME: &str = "mode_comparison_plot_data.csv";
/// Public real-mode Commit-byte SVG chart.
pub const MODE_COMPARISON_BYTES_SVG_FILE_NAME: &str = "mode_comparison_bytes.svg";
/// Public real-mode lifecycle-observation SVG chart.
pub const MODE_COMPARISON_LIFECYCLE_SVG_FILE_NAME: &str = "mode_comparison_lifecycle.svg";
/// Public hybrid-delivery-count SVG chart.
pub const MODE_COMPARISON_HYBRID_COUNTS_SVG_FILE_NAME: &str = "mode_comparison_hybrid_counts.svg";
/// Public adaptive transition-fact SVG chart.
pub const MODE_COMPARISON_TRANSITION_SVG_FILE_NAME: &str = "mode_comparison_transition.svg";

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
    /// Complete safe public comparison manifest and raw three-mode run facts.
    pub comparison_json: PathBuf,
    /// Human-readable limitations and reproducibility report.
    pub comparison_markdown: PathBuf,
}

/// Locations of Task 62 plot-ready and SVG artifacts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModeComparisonPlotArtifactPaths {
    /// Long-form, typed source points for the four Task 62 charts.
    pub plot_data_csv: PathBuf,
    /// Real Commit-byte comparison chart.
    pub bytes_svg: PathBuf,
    /// Environment-dependent lifecycle-observation comparison chart.
    pub lifecycle_svg: PathBuf,
    /// Real hybrid delivery-count comparison chart.
    pub hybrid_counts_svg: PathBuf,
    /// Real adaptive transition-fact chart.
    pub transition_svg: PathBuf,
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
    /// The real binary-with-mKyber fork workload could not execute and converge.
    #[error("binary-with-mKyber repetition failed: {0}")]
    Mkyber(#[source] ExperimentalBinaryWorkloadError),
    /// The real adaptive fork workload could not execute and converge.
    #[error("adaptive repetition failed: {0}")]
    Adaptive(#[source] ExperimentalBinaryWorkloadError),
    /// Task 62 compares the three currently supported update-only clients.
    #[error("Task 62 supports only update-only workloads with zero warmup")]
    UnsupportedComparisonWorkload,
    /// The public group shape cannot satisfy the configured adaptive target.
    #[error("comparison initial member count must equal the configured target group size")]
    TargetGroupSizeMismatch,
    /// The current experimental clients do not change membership after setup.
    #[error("comparison maximum member count must equal initial member count")]
    MembershipChangingComparisonUnsupported,
    /// A successful adaptive execution omitted its required transition fact.
    #[error("adaptive execution omitted its required transition measurement")]
    MissingAdaptiveTransition,
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
    /// An existing public comparison CSV could not be read.
    #[error("comparison CSV input could not be read")]
    Read(#[source] std::io::Error),
    /// The public comparison CSV has an unsupported mode, metric, or value state.
    #[error("comparison CSV input is invalid for Task 62 chart generation")]
    InvalidPlotInput,
}

#[derive(Clone, Debug, Serialize)]
struct ModeRun {
    mode: &'static str,
    run_index: u32,
    emitted_commit_count: u32,
    emitted_commit_bytes: u128,
    welcome_bytes: u128,
    accepted_lifecycle_nanoseconds: u128,
    mkyber_common_ciphertext_count: Option<u128>,
    mkyber_recipient_ciphertext_count: Option<u128>,
    classical_hpke_encapsulation_count: Option<u128>,
    adaptive: Option<AdaptiveRunFacts>,
}

#[derive(Clone, Debug, Serialize)]
struct AdaptiveRunFacts {
    selected_policy: &'static str,
    impactful_commit_count: u32,
    matched_window_saving_bytes: i128,
    amortized_preflight_saving_bytes: i128,
    transition_preflight_bytes: u64,
    actual_transition_bytes: u64,
    post_transition_update_count: u32,
    retirement_status: &'static str,
}

#[derive(Clone, Debug, Serialize)]
struct ComparisonRow {
    mode: &'static str,
    run_index: Option<u32>,
    measurement: &'static str,
    unit: &'static str,
    value_state: &'static str,
    numeric_value: Option<i128>,
    reason: Option<&'static str>,
    provenance: &'static str,
}

#[derive(Debug, Deserialize)]
struct ComparisonCsvRow {
    mode: String,
    run_index: Option<u32>,
    measurement: String,
    unit: String,
    value_state: String,
    numeric_value: Option<i128>,
    reason: Option<String>,
    provenance: String,
}

/// One typed point consumed by a Task 62 SVG chart.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ModeComparisonPlotDataRow {
    /// Task 62 plot-data schema version.
    pub schema_version: u16,
    /// Stable chart family.
    pub chart: &'static str,
    /// Stable real-mode name.
    pub mode: String,
    /// Public independent repetition index when available.
    pub run_index: Option<u32>,
    /// Stable source comparison measurement name.
    pub measurement: String,
    /// Unit of the numeric point.
    pub unit: String,
    /// `observed` or the explicit source availability state.
    pub value_state: String,
    /// Numeric data only when actually observed.
    pub numeric_value: Option<i128>,
    /// Explicit reason when numeric data is absent.
    pub reason: Option<String>,
    /// Source-row provenance.
    pub provenance: String,
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
    runs: &'a [ModeRun],
    limitations: [&'static str; 3],
}

#[derive(Serialize)]
struct ComparisonWorkloadShapeJson {
    initial_member_count: u32,
    maximum_member_count: u32,
    operation_count: u32,
    region_count: u32,
}

/// Executes reproducible update-only repetitions through all three real
/// workload clients and writes their public comparison artifacts.
///
/// Configurations are parsed with the typed public schema and must select the
/// expected mode while sharing group, transition, and execution controls. The
/// configured workload seed separates public run group identifiers while the
/// committer schedule is fixed round-robin. It never reconstructs MLS
/// private-key entropy.
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
    if baseline.execution.warmup_accepted_commits != 0 {
        return Err(ModeComparisonError::UnsupportedComparisonWorkload);
    }
    if workload_shape.operation_count < 3 {
        return Err(ModeComparisonError::UnsupportedComparisonWorkload);
    }
    if workload_shape.initial_member_count != baseline.group.target_group_size {
        return Err(ModeComparisonError::TargetGroupSizeMismatch);
    }
    if workload_shape.maximum_member_count != workload_shape.initial_member_count {
        return Err(ModeComparisonError::MembershipChangingComparisonUnsupported);
    }
    if workload_shape.operation_count <= baseline.execution.warmup_accepted_commits {
        return Err(ModeComparisonError::NoPostWarmupObservations);
    }
    validate_artifact_directory(output_directory, "output", "comparison machine-readable")?;
    validate_artifact_directory(report_directory, "report", "comparison Markdown")?;

    let mut runs = Vec::new();
    for run_index in 1..=baseline.execution.repetitions {
        let workload = |mode: &str| BaselineWorkloadConfig {
            group_id: format!(
                "task62-{mode}-{}-{run_index}",
                baseline.execution.workload_seed
            )
            .into_bytes(),
            initial_member_count: workload_shape.initial_member_count,
            maximum_member_count: workload_shape.maximum_member_count,
            operation_count: workload_shape.operation_count,
            region_count: workload_shape.region_count,
            committer_strategy: CommitterStrategy::RoundRobin,
            workload_profile: WorkloadProfile::UpdateOnly,
        };
        let execution = execute_baseline_workload(&workload("baseline"))
            .map_err(ModeComparisonError::Workload)?;
        let baseline_run = ModeRun {
            mode: BASELINE_MODE,
            run_index,
            emitted_commit_count: u32::try_from(execution.accepted_operations.len())
                .map_err(|_| ModeComparisonError::CountOverflow)?,
            emitted_commit_bytes: execution.accepted_operations.iter().try_fold(
                0_u128,
                |sum, operation| {
                    sum.checked_add(u128::from(operation.measurement.emitted_commit_bytes))
                        .ok_or(ModeComparisonError::CountOverflow)
                },
            )?,
            welcome_bytes: execution.accepted_operations.iter().try_fold(
                0_u128,
                |sum, operation| {
                    sum.checked_add(u128::from(
                        operation.measurement.emitted_welcome_bytes.unwrap_or(0),
                    ))
                    .ok_or(ModeComparisonError::CountOverflow)
                },
            )?,
            accepted_lifecycle_nanoseconds: execution.accepted_operations.iter().try_fold(
                0_u128,
                |sum, operation| {
                    sum.checked_add(operation.measurement.accepted_lifecycle_elapsed_nanoseconds)
                        .ok_or(ModeComparisonError::CountOverflow)
                },
            )?,
            mkyber_common_ciphertext_count: None,
            mkyber_recipient_ciphertext_count: None,
            classical_hpke_encapsulation_count: None,
            adaptive: None,
        };
        let execution = execute_experimental_binary_workload(&workload("mkyber"))
            .map_err(ModeComparisonError::Mkyber)?;
        let mkyber_run = ModeRun {
            mode: MKYBER_MODE,
            run_index,
            emitted_commit_count: u32::try_from(execution.accepted_operations.len())
                .map_err(|_| ModeComparisonError::CountOverflow)?,
            emitted_commit_bytes: execution.accepted_operations.iter().try_fold(
                0_u128,
                |sum, operation| {
                    sum.checked_add(u128::from(operation.measurement.emitted_commit_bytes))
                        .ok_or(ModeComparisonError::CountOverflow)
                },
            )?,
            welcome_bytes: 0,
            accepted_lifecycle_nanoseconds: execution.accepted_operations.iter().try_fold(
                0_u128,
                |sum, operation| {
                    sum.checked_add(operation.measurement.accepted_lifecycle_elapsed_nanoseconds)
                        .ok_or(ModeComparisonError::CountOverflow)
                },
            )?,
            mkyber_common_ciphertext_count: Some(execution.accepted_operations.iter().try_fold(
                0_u128,
                |sum, operation| {
                    sum.checked_add(u128::from(
                        operation.measurement.mkyber_common_ciphertext_count,
                    ))
                    .ok_or(ModeComparisonError::CountOverflow)
                },
            )?),
            mkyber_recipient_ciphertext_count: Some(
                execution
                    .accepted_operations
                    .iter()
                    .try_fold(0_u128, |sum, operation| {
                        sum.checked_add(u128::from(
                            operation.measurement.mkyber_recipient_ciphertext_count,
                        ))
                        .ok_or(ModeComparisonError::CountOverflow)
                    })?,
            ),
            classical_hpke_encapsulation_count: Some(
                execution
                    .accepted_operations
                    .iter()
                    .try_fold(0_u128, |sum, operation| {
                        sum.checked_add(u128::from(
                            operation.measurement.classical_hpke_encapsulation_count,
                        ))
                        .ok_or(ModeComparisonError::CountOverflow)
                    })?,
            ),
            adaptive: None,
        };
        let execution = execute_experimental_adaptive_workload_with_policy(
            &workload("adaptive"),
            ExperimentalAdaptiveTransitionPolicy::MatchedPerCommitSaving,
        )
        .map_err(ModeComparisonError::Adaptive)?;
        let (mkyber_common, mkyber_recipient, classical_hpke) =
            sum_adaptive_hybrid_counts(&execution.accepted_operations)?;
        let transition = execution
            .accepted_operations
            .iter()
            .find_map(|operation| operation.transition.as_ref())
            .ok_or(ModeComparisonError::MissingAdaptiveTransition)?;
        let adaptive_run = ModeRun {
            mode: ADAPTIVE_MODE,
            run_index,
            emitted_commit_count: u32::try_from(execution.accepted_operations.len())
                .map_err(|_| ModeComparisonError::CountOverflow)?,
            emitted_commit_bytes: execution.accepted_operations.iter().try_fold(
                0_u128,
                |sum, operation| {
                    sum.checked_add(u128::from(operation.emitted_commit_bytes))
                        .ok_or(ModeComparisonError::CountOverflow)
                },
            )?,
            welcome_bytes: 0,
            accepted_lifecycle_nanoseconds: execution.accepted_operations.iter().try_fold(
                0_u128,
                |sum, operation| {
                    sum.checked_add(operation.accepted_lifecycle_elapsed_nanoseconds)
                        .ok_or(ModeComparisonError::CountOverflow)
                },
            )?,
            mkyber_common_ciphertext_count: Some(mkyber_common),
            mkyber_recipient_ciphertext_count: Some(mkyber_recipient),
            classical_hpke_encapsulation_count: Some(classical_hpke),
            adaptive: Some(AdaptiveRunFacts {
                selected_policy: "matched-per-commit-saving",
                impactful_commit_count: transition.preflight_savings.impactful_commit_count(),
                matched_window_saving_bytes: i128::from(
                    transition.preflight_savings.sum_current_bytes(),
                ) - i128::from(
                    transition.preflight_savings.sum_candidate_estimated_bytes(),
                ),
                amortized_preflight_saving_bytes: transition
                    .preflight_savings
                    .direct_saving_bytes(),
                transition_preflight_bytes: u64::try_from(transition.preflight.estimated_bytes())
                    .map_err(|_| ModeComparisonError::CountOverflow)?,
                actual_transition_bytes: u64::try_from(transition.byte_comparison.actual_bytes())
                    .map_err(|_| ModeComparisonError::CountOverflow)?,
                post_transition_update_count: u32::try_from(
                    execution
                        .accepted_operations
                        .iter()
                        .filter(|operation| {
                            operation.phase == ExperimentalAdaptiveCommitPhase::QuaternaryUpdate
                        })
                        .count(),
                )
                .map_err(|_| ModeComparisonError::CountOverflow)?,
                retirement_status: "UnsupportedNoAuthenticatedRetirementCommit",
            }),
        };
        runs.extend([baseline_run, mkyber_run, adaptive_run]);
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
    let rows = comparison_rows(&runs)?;
    let manifest = ComparisonManifest {
        schema_version: MODE_COMPARISON_SCHEMA_VERSION,
        selected_modes: [BASELINE_MODE, MKYBER_MODE, ADAPTIVE_MODE],
        status: "complete: all three selected update-only workload clients executed",
        baseline_configuration_toml,
        mkyber_configuration_toml,
        adaptive_configuration_toml,
        workload_shape: ComparisonWorkloadShapeJson {
            initial_member_count: workload_shape.initial_member_count,
            maximum_member_count: workload_shape.maximum_member_count,
            operation_count: workload_shape.operation_count,
            region_count: workload_shape.region_count,
        },
        seed_derivation: "Each mode uses the same public workload_seed in a distinct public group identifier and the fixed round-robin committer schedule. The seed separates repetitions only; it never provides MLS key-generation entropy.",
        runs: &runs,
        limitations: [
            "Lifecycle elapsed time is an in-process, environment-dependent observation; Task 63 owns repeated CPU and peak-RSS measurement.",
            "The selected matched-per-Commit policy can authorize a transition before its measured preflight cost is amortized; both values remain separate observed rows.",
            "TreeCover retirement is explicitly UnsupportedNoAuthenticatedRetirementCommit; no private-key erasure is claimed.",
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

/// Reads a completed Task 62 public comparison CSV and writes a minimal
/// plot-ready CSV plus four dependency-free SVG charts.
///
/// This is deliberately a second create-new step: it cannot rewrite the real
/// measurement CSV, and it accepts only the fixed public Task 62 row family.
pub fn generate_mode_comparison_plot_artifacts(
    comparison_csv: &Path,
    output_directory: &Path,
    report_directory: &Path,
) -> Result<ModeComparisonPlotArtifactPaths, ModeComparisonError> {
    validate_artifact_directory(output_directory, "output", "comparison plot data")?;
    validate_artifact_directory(report_directory, "report", "comparison SVG")?;
    let source = std::fs::read(comparison_csv).map_err(ModeComparisonError::Read)?;
    let mut reader = csv::Reader::from_reader(source.as_slice());
    let source_rows = reader
        .deserialize::<ComparisonCsvRow>()
        .collect::<Result<Vec<_>, _>>()
        .map_err(ModeComparisonError::Csv)?;
    let rows = comparison_plot_rows(&source_rows)?;
    let paths = ModeComparisonPlotArtifactPaths {
        plot_data_csv: output_directory.join(MODE_COMPARISON_PLOT_DATA_FILE_NAME),
        bytes_svg: report_directory.join(MODE_COMPARISON_BYTES_SVG_FILE_NAME),
        lifecycle_svg: report_directory.join(MODE_COMPARISON_LIFECYCLE_SVG_FILE_NAME),
        hybrid_counts_svg: report_directory.join(MODE_COMPARISON_HYBRID_COUNTS_SVG_FILE_NAME),
        transition_svg: report_directory.join(MODE_COMPARISON_TRANSITION_SVG_FILE_NAME),
    };
    for path in [
        &paths.plot_data_csv,
        &paths.bytes_svg,
        &paths.lifecycle_svg,
        &paths.hybrid_counts_svg,
        &paths.transition_svg,
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
    write_new(&paths.plot_data_csv, &comparison_plot_csv(&rows)?)?;
    write_new(
        &paths.bytes_svg,
        comparison_bar_svg(
            "Task 62 real Commit bytes",
            "bytes",
            chart_observations(&rows, "commit_bytes"),
            false,
            0,
        )
        .as_bytes(),
    )?;
    write_new(
        &paths.lifecycle_svg,
        comparison_bar_svg(
            "Task 62 accepted lifecycle observations",
            "nanoseconds (environment-dependent)",
            chart_observations(&rows, "lifecycle"),
            false,
            0,
        )
        .as_bytes(),
    )?;
    write_new(
        &paths.hybrid_counts_svg,
        comparison_bar_svg(
            "Task 62 authenticated hybrid delivery counts",
            "count",
            chart_observations(&rows, "hybrid_counts"),
            false,
            0,
        )
        .as_bytes(),
    )?;
    write_new(
        &paths.transition_svg,
        comparison_transition_svg(&rows).as_bytes(),
    )?;
    Ok(paths)
}

fn comparison_plot_rows(
    source_rows: &[ComparisonCsvRow],
) -> Result<Vec<ModeComparisonPlotDataRow>, ModeComparisonError> {
    let mut rows = Vec::new();
    for source in source_rows {
        if !matches!(
            source.mode.as_str(),
            BASELINE_MODE | MKYBER_MODE | ADAPTIVE_MODE
        ) || source.run_index != Some(1)
            || !matches!(source.value_state.as_str(), "observed" | "unavailable")
        {
            return Err(ModeComparisonError::InvalidPlotInput);
        }
        let chart = match source.measurement.as_str() {
            "emitted_commit_bytes" => "commit_bytes",
            "accepted_lifecycle_nanoseconds" => "lifecycle",
            "mkyber_common_ciphertext_count"
            | "mkyber_recipient_ciphertext_count"
            | "classical_hpke_encapsulation_count" => "hybrid_counts",
            "matched_window_saving_bytes"
            | "amortized_preflight_saving_bytes"
            | "transition_preflight_bytes"
            | "actual_transition_bytes"
            | "post_transition_update_count"
            | "amortized_break_even" => "adaptive_transition",
            _ => continue,
        };
        if chart == "adaptive_transition" && source.mode != ADAPTIVE_MODE {
            return Err(ModeComparisonError::InvalidPlotInput);
        }
        if source.value_state == "observed" && source.numeric_value.is_none() {
            return Err(ModeComparisonError::InvalidPlotInput);
        }
        if source.value_state == "unavailable" && source.numeric_value.is_some() {
            return Err(ModeComparisonError::InvalidPlotInput);
        }
        rows.push(ModeComparisonPlotDataRow {
            schema_version: MODE_COMPARISON_SCHEMA_VERSION,
            chart,
            mode: source.mode.clone(),
            run_index: source.run_index,
            measurement: source.measurement.clone(),
            unit: source.unit.clone(),
            value_state: source.value_state.clone(),
            numeric_value: source.numeric_value,
            reason: source.reason.clone(),
            provenance: source.provenance.clone(),
        });
    }
    if rows.is_empty()
        || !rows.iter().any(|row| row.chart == "commit_bytes")
        || !rows.iter().any(|row| row.chart == "adaptive_transition")
    {
        return Err(ModeComparisonError::InvalidPlotInput);
    }
    Ok(rows)
}

fn comparison_plot_csv(rows: &[ModeComparisonPlotDataRow]) -> Result<Vec<u8>, ModeComparisonError> {
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

fn chart_observations(
    rows: &[ModeComparisonPlotDataRow],
    chart: &str,
) -> Vec<(&'static str, i128)> {
    rows.iter()
        .filter(|row| row.chart == chart && row.value_state == "observed")
        .filter(|row| {
            !(chart == "adaptive_transition" && row.measurement == "post_transition_update_count")
        })
        .filter_map(|row| {
            row.numeric_value
                .map(|value| (comparison_plot_label(&row.mode, &row.measurement), value))
        })
        .collect()
}

fn comparison_transition_svg(rows: &[ModeComparisonPlotDataRow]) -> String {
    let points = chart_observations(rows, "adaptive_transition");
    let unavailable_count = rows
        .iter()
        .filter(|row| row.chart == "adaptive_transition" && row.numeric_value.is_none())
        .count();
    let post_transition_updates = rows
        .iter()
        .find(|row| row.measurement == "post_transition_update_count")
        .and_then(|row| row.numeric_value)
        .unwrap_or(0);
    let mut svg = comparison_bar_svg(
        "Task 62 adaptive transition byte facts",
        "bytes",
        points,
        true,
        unavailable_count,
    );
    let note = format!(
        "<text x=\"48\" y=\"92\" class=\"label\">real post-transition updates: {post_transition_updates}</text>\n"
    );
    svg = svg.replacen("<line ", &format!("{note}<line "), 1);
    svg
}

fn comparison_plot_label(mode: &str, measurement: &str) -> &'static str {
    match (mode, measurement) {
        (BASELINE_MODE, "emitted_commit_bytes") => "baseline",
        (MKYBER_MODE, "emitted_commit_bytes") => "mKyber",
        (ADAPTIVE_MODE, "emitted_commit_bytes") => "adaptive incl. transition",
        (BASELINE_MODE, "accepted_lifecycle_nanoseconds") => "baseline",
        (MKYBER_MODE, "accepted_lifecycle_nanoseconds") => "mKyber",
        (ADAPTIVE_MODE, "accepted_lifecycle_nanoseconds") => "adaptive incl. transition",
        (MKYBER_MODE, "mkyber_common_ciphertext_count") => "mKyber common",
        (MKYBER_MODE, "mkyber_recipient_ciphertext_count") => "mKyber recipient",
        (MKYBER_MODE, "classical_hpke_encapsulation_count") => "mKyber HPKE",
        (ADAPTIVE_MODE, "mkyber_common_ciphertext_count") => "adaptive common",
        (ADAPTIVE_MODE, "mkyber_recipient_ciphertext_count") => "adaptive recipient",
        (ADAPTIVE_MODE, "classical_hpke_encapsulation_count") => "adaptive HPKE",
        (ADAPTIVE_MODE, "matched_window_saving_bytes") => "matched saving",
        (ADAPTIVE_MODE, "amortized_preflight_saving_bytes") => "amortized saving",
        (ADAPTIVE_MODE, "transition_preflight_bytes") => "preflight",
        (ADAPTIVE_MODE, "actual_transition_bytes") => "actual transition",
        (ADAPTIVE_MODE, "post_transition_update_count") => "post-transition updates",
        _ => "validated Task 62 row",
    }
}

fn comparison_bar_svg(
    title: &str,
    unit: &str,
    points: Vec<(&str, i128)>,
    signed: bool,
    unavailable_count: usize,
) -> String {
    let mut svg = String::new();
    let max_absolute = points
        .iter()
        .map(|(_, value)| value.unsigned_abs())
        .max()
        .unwrap_or(1)
        .max(1);
    let baseline = if signed { 276_i128 } else { 420_i128 };
    let usable_height = if signed { 144_i128 } else { 300_i128 };
    writeln!(svg, r#"<svg xmlns="http://www.w3.org/2000/svg" width="960" height="540" viewBox="0 0 960 540" role="img" aria-label="{title}">"#).expect("string write");
    writeln!(svg, "<style>.title{{font:700 22px sans-serif;fill:#111827}}.label{{font:14px sans-serif;fill:#374151}}.value{{font:13px monospace;fill:#111827}}.note{{font:13px sans-serif;fill:#92400e}}</style>").expect("string write");
    writeln!(svg, "<rect width=\"960\" height=\"540\" fill=\"#ffffff\"/>").expect("string write");
    writeln!(
        svg,
        "<text x=\"48\" y=\"42\" class=\"title\">{title}</text>"
    )
    .expect("string write");
    writeln!(
        svg,
        "<text x=\"48\" y=\"68\" class=\"label\">unit: {unit}</text>"
    )
    .expect("string write");
    writeln!(svg, "<line x1=\"48\" y1=\"{baseline}\" x2=\"912\" y2=\"{baseline}\" stroke=\"#9ca3af\" stroke-width=\"1\"/>").expect("string write");
    let width = 96_i128;
    let gap = 24_i128;
    for (index, (label, value)) in points.iter().enumerate() {
        let index = i128::try_from(index).expect("small fixed chart index");
        let x = 72 + index * (width + gap);
        let scaled = value
            .unsigned_abs()
            .saturating_mul(u128::try_from(usable_height).expect("positive chart height"))
            / max_absolute;
        let height = i128::try_from(scaled.max(1)).expect("bounded chart height");
        let y = if *value < 0 {
            baseline
        } else {
            baseline - height
        };
        let color = if *value < 0 { "#dc2626" } else { "#2563eb" };
        writeln!(svg, "<rect x=\"{x}\" y=\"{y}\" width=\"{width}\" height=\"{height}\" rx=\"4\" fill=\"{color}\"/>").expect("string write");
        writeln!(
            svg,
            "<text x=\"{x}\" y=\"{}\" class=\"value\">{value}</text>",
            if *value < 0 { y + height + 18 } else { y - 8 }
        )
        .expect("string write");
        writeln!(
            svg,
            "<text x=\"{x}\" y=\"{}\" class=\"label\">{label}</text>",
            baseline + 28
        )
        .expect("string write");
    }
    if unavailable_count > 0 {
        writeln!(svg, "<rect x=\"48\" y=\"472\" width=\"864\" height=\"42\" rx=\"6\" fill=\"#fff7ed\" stroke=\"#c2410c\"/>").expect("string write");
        writeln!(svg, "<text x=\"64\" y=\"498\" class=\"note\">{unavailable_count} explicit unavailable fact is retained in plot data and is not plotted as zero.</text>").expect("string write");
    }
    writeln!(svg, "</svg>").expect("string write");
    svg
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

fn sum_adaptive_hybrid_counts(
    operations: &[experimental_mls_adapter::AcceptedExperimentalAdaptiveOperation],
) -> Result<(u128, u128, u128), ModeComparisonError> {
    operations
        .iter()
        .try_fold((0_u128, 0_u128, 0_u128), |totals, operation| {
            let counts = operation.hybrid_delivery_counts();
            Ok((
                totals
                    .0
                    .checked_add(u128::from(counts.1))
                    .ok_or(ModeComparisonError::CountOverflow)?,
                totals
                    .1
                    .checked_add(u128::from(counts.2))
                    .ok_or(ModeComparisonError::CountOverflow)?,
                totals
                    .2
                    .checked_add(u128::from(counts.3))
                    .ok_or(ModeComparisonError::CountOverflow)?,
            ))
        })
}

fn comparison_rows(runs: &[ModeRun]) -> Result<Vec<ComparisonRow>, ModeComparisonError> {
    let mut rows = Vec::new();
    for run in runs {
        rows.extend([
            observed_row(run.mode, run.run_index, "emitted_commit_count", "commits", i128::from(run.emitted_commit_count), "actual emitted accepted Commit count; the adaptive count includes its separate authenticated transition Commit"),
            observed_row(run.mode, run.run_index, "emitted_commit_bytes", "bytes", i128_from_u128(run.emitted_commit_bytes)?, "actual serialized Commit bytes from the selected real workload client"),
            observed_row(run.mode, run.run_index, "welcome_bytes", "bytes", i128_from_u128(run.welcome_bytes)?, "actual serialized Welcome bytes; zero is observed for these update-only workloads"),
            observed_row(run.mode, run.run_index, "accepted_lifecycle_nanoseconds", "nanoseconds", i128_from_u128(run.accepted_lifecycle_nanoseconds)?, "monotonic accepted lifecycle observation; environment-dependent and not a CPU benchmark"),
        ]);
        if let Some(count) = run.mkyber_common_ciphertext_count {
            rows.extend([
                observed_row(
                    run.mode,
                    run.run_index,
                    "mkyber_common_ciphertext_count",
                    "ciphertexts",
                    i128_from_u128(count)?,
                    "actual authenticated hybrid UpdatePath common ciphertext count",
                ),
                observed_row(
                    run.mode,
                    run.run_index,
                    "mkyber_recipient_ciphertext_count",
                    "ciphertexts",
                    i128_from_u128(
                        run.mkyber_recipient_ciphertext_count
                            .expect("mKyber counts are populated together"),
                    )?,
                    "actual authenticated hybrid UpdatePath recipient ciphertext count",
                ),
                observed_row(
                    run.mode,
                    run.run_index,
                    "classical_hpke_encapsulation_count",
                    "encapsulations",
                    i128_from_u128(
                        run.classical_hpke_encapsulation_count
                            .expect("hybrid counts are populated together"),
                    )?,
                    "actual authenticated hybrid UpdatePath classical HPKE encapsulation count",
                ),
            ]);
        }
        if let Some(adaptive) = &run.adaptive {
            rows.extend([
                observed_row(run.mode, run.run_index, "matched_window_saving_bytes", "bytes", adaptive.matched_window_saving_bytes, "exact matched normal-binary minus candidate window bytes; selected authorization policy excludes preflight"),
                observed_row(run.mode, run.run_index, "amortized_preflight_saving_bytes", "bytes", adaptive.amortized_preflight_saving_bytes, "exact matched saving minus measured transition preflight; retained even when negative"),
                observed_row(run.mode, run.run_index, "transition_preflight_bytes", "bytes", i128::from(adaptive.transition_preflight_bytes), "estimated from a separate real probe because the fork has no side-effect-free preview API"),
                observed_row(run.mode, run.run_index, "actual_transition_bytes", "bytes", i128::from(adaptive.actual_transition_bytes), "actual serialized authenticated transition Commit bytes in the measured group"),
                observed_row(run.mode, run.run_index, "post_transition_update_count", "updates", i128::from(adaptive.post_transition_update_count), "real quaternary self-updates accepted after the transition"),
                observed_row(run.mode, run.run_index, "impactful_commit_count", "commits", i128::from(adaptive.impactful_commit_count), "matched normal-binary observations used by policy evaluation"),
            ]);
            if adaptive.amortized_preflight_saving_bytes < 0 {
                rows.push(unavailable_row(
                    run.mode,
                    Some(run.run_index),
                    "amortized_break_even",
                    "observations",
                    "NotAmortizedInMeasuredRun",
                    "the real run did not repay transition preflight; unavailable is not zero",
                ));
            }
        }
    }
    for run_index in
        1..=u32::try_from(runs.len() / 3).map_err(|_| ModeComparisonError::CountOverflow)?
    {
        let baseline = runs
            .iter()
            .find(|run| run.run_index == run_index && run.mode == BASELINE_MODE)
            .ok_or(ModeComparisonError::CountOverflow)?;
        for mode in [MKYBER_MODE, ADAPTIVE_MODE] {
            let candidate = runs
                .iter()
                .find(|run| run.run_index == run_index && run.mode == mode)
                .ok_or(ModeComparisonError::CountOverflow)?;
            rows.extend([
                observed_row(mode, run_index, "commit_byte_delta_vs_baseline", "bytes", i128_from_u128(candidate.emitted_commit_bytes)? - i128_from_u128(baseline.emitted_commit_bytes)?, "same public schedule repetition; adaptive value intentionally includes the actual transition Commit"),
                observed_row(mode, run_index, "lifecycle_delta_vs_baseline", "nanoseconds", i128_from_u128(candidate.accepted_lifecycle_nanoseconds)? - i128_from_u128(baseline.accepted_lifecycle_nanoseconds)?, "same public schedule repetition; environment-dependent lifecycle observation, not a CPU benchmark"),
            ]);
        }
    }
    Ok(rows)
}

fn observed_row(
    mode: &'static str,
    run_index: u32,
    measurement: &'static str,
    unit: &'static str,
    numeric_value: i128,
    provenance: &'static str,
) -> ComparisonRow {
    ComparisonRow {
        mode,
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
    run_index: Option<u32>,
    measurement: &'static str,
    unit: &'static str,
    reason: &'static str,
    provenance: &'static str,
) -> ComparisonRow {
    ComparisonRow {
        mode,
        run_index,
        measurement,
        unit,
        value_state: "unavailable",
        numeric_value: None,
        reason: Some(reason),
        provenance,
    }
}

fn i128_from_u128(value: u128) -> Result<i128, ModeComparisonError> {
    i128::try_from(value).map_err(|_| ModeComparisonError::CountOverflow)
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
    writeln!(report, "# Task 62 Real Three-Mode Comparison").expect("string write");
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
    writeln!(report, "## Observed workload runs").expect("string write");
    writeln!(report).expect("string write");
    writeln!(report, "| Mode | Run | Emitted commits | Commit bytes | Welcome bytes | Lifecycle ns |\n|---|---:|---:|---:|---:|---:|").expect("string write");
    for run in manifest.runs {
        writeln!(
            report,
            "| {} | {} | {} | {} | {} | {} |",
            run.mode,
            run.run_index,
            run.emitted_commit_count,
            run.emitted_commit_bytes,
            run.welcome_bytes,
            run.accepted_lifecycle_nanoseconds
        )
        .expect("string write");
    }
    writeln!(report).expect("string write");
    writeln!(report, "All values above are observed from the selected real workload clients. Adaptive Commit bytes deliberately include its separately emitted, authenticated transition Commit, so the byte delta does not hide transition cost.").expect("string write");
    writeln!(report).expect("string write");
    writeln!(report, "## Adaptive transition facts").expect("string write");
    writeln!(report).expect("string write");
    writeln!(report, "| Run | Policy | Impactful commits | Matched saving | Amortized preflight saving | Preflight bytes | Actual transition bytes | Post-transition updates | Retirement |\n|---:|---|---:|---:|---:|---:|---:|---:|---|").expect("string write");
    for run in manifest.runs.iter().filter(|run| run.mode == ADAPTIVE_MODE) {
        let facts = run.adaptive.as_ref().expect("adaptive run has facts");
        writeln!(
            report,
            "| {} | {} | {} | {} | {} | {} | {} | {} | {} |",
            run.run_index,
            facts.selected_policy,
            facts.impactful_commit_count,
            facts.matched_window_saving_bytes,
            facts.amortized_preflight_saving_bytes,
            facts.transition_preflight_bytes,
            facts.actual_transition_bytes,
            facts.post_transition_update_count,
            facts.retirement_status
        )
        .expect("string write");
    }
    writeln!(report).expect("string write");
    writeln!(report, "The selected policy is `matched-per-commit-saving`. Its authorization result is distinct from the amortized-preflight result and the report preserves both; a negative amortized value is not relabeled as a break-even point.").expect("string write");
    writeln!(report).expect("string write");
    writeln!(report, "## Threats to validity").expect("string write");
    writeln!(report).expect("string write");
    for threat in manifest.limitations.into_iter().chain([
        "The baseline harness is an in-process convergence test; it does not model network latency, transport loss, distributed scheduling, or heterogeneous hardware.",
        "Fresh MLS key material uses operating-system randomness, so public workload seeds reproduce logical scheduling but not private cryptographic state.",
        "The sample records raw independent runs only; no pooled-commit inference or general performance conclusion is justified.",
    ]) {
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

    fn config(mode: &str) -> String {
        format!(
            r#"mode = "{mode}"

[group]
target_group_size = 128
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
warmup_accepted_commits = 0
repetitions = 1
workload_seed = 42

[output]
output_directory = "output/unused"
report_directory = "report/unused"
"#
        )
    }

    #[test]
    fn emits_signed_real_comparison_rows() {
        let baseline = ModeRun {
            mode: BASELINE_MODE,
            run_index: 1,
            emitted_commit_count: 3,
            emitted_commit_bytes: 100,
            welcome_bytes: 0,
            accepted_lifecycle_nanoseconds: 10,
            mkyber_common_ciphertext_count: None,
            mkyber_recipient_ciphertext_count: None,
            classical_hpke_encapsulation_count: None,
            adaptive: None,
        };
        let mkyber = ModeRun {
            mode: MKYBER_MODE,
            emitted_commit_bytes: 120,
            mkyber_common_ciphertext_count: Some(3),
            mkyber_recipient_ciphertext_count: Some(9),
            classical_hpke_encapsulation_count: Some(9),
            ..baseline.clone()
        };
        let adaptive = ModeRun {
            mode: ADAPTIVE_MODE,
            emitted_commit_count: 4,
            emitted_commit_bytes: 90,
            accepted_lifecycle_nanoseconds: 12,
            mkyber_common_ciphertext_count: Some(2),
            mkyber_recipient_ciphertext_count: Some(6),
            classical_hpke_encapsulation_count: Some(6),
            adaptive: Some(AdaptiveRunFacts {
                selected_policy: "matched-per-commit-saving",
                impactful_commit_count: 2,
                matched_window_saving_bytes: 7,
                amortized_preflight_saving_bytes: -3,
                transition_preflight_bytes: 10,
                actual_transition_bytes: 12,
                post_transition_update_count: 1,
                retirement_status: "UnsupportedNoAuthenticatedRetirementCommit",
            }),
            ..baseline.clone()
        };
        let rows = comparison_rows(&[baseline, mkyber, adaptive]).expect("rows");
        assert!(rows
            .iter()
            .any(|row| row.measurement == "commit_byte_delta_vs_baseline"
                && row.mode == MKYBER_MODE
                && row.numeric_value == Some(20)));
        assert!(rows.iter().any(
            |row| row.measurement == "amortized_break_even" && row.value_state == "unavailable"
        ));
    }

    #[test]
    fn plot_rows_keep_non_amortized_break_even_unavailable() {
        let rows = comparison_plot_rows(&[
            ComparisonCsvRow {
                mode: BASELINE_MODE.to_owned(),
                run_index: Some(1),
                measurement: "emitted_commit_bytes".to_owned(),
                unit: "bytes".to_owned(),
                value_state: "observed".to_owned(),
                numeric_value: Some(100),
                reason: None,
                provenance: "test".to_owned(),
            },
            ComparisonCsvRow {
                mode: ADAPTIVE_MODE.to_owned(),
                run_index: Some(1),
                measurement: "matched_window_saving_bytes".to_owned(),
                unit: "bytes".to_owned(),
                value_state: "observed".to_owned(),
                numeric_value: Some(7),
                reason: None,
                provenance: "test".to_owned(),
            },
            ComparisonCsvRow {
                mode: ADAPTIVE_MODE.to_owned(),
                run_index: Some(1),
                measurement: "amortized_break_even".to_owned(),
                unit: "observations".to_owned(),
                value_state: "unavailable".to_owned(),
                numeric_value: None,
                reason: Some("NotAmortizedInMeasuredRun".to_owned()),
                provenance: "test".to_owned(),
            },
        ])
        .expect("plot rows");
        assert!(rows.iter().any(|row| {
            row.measurement == "amortized_break_even"
                && row.value_state == "unavailable"
                && row.numeric_value.is_none()
        }));
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
                    initial_member_count: 128,
                    maximum_member_count: 128,
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
