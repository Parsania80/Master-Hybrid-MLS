#![forbid(unsafe_code)]

//! Task 55 public artifact generation.
//!
//! The generator writes only public Task 54 observations. It preserves every
//! unavailable measurement as unavailable, writes files with create-new
//! semantics, and keeps machine-readable output separate from the Markdown
//! report directory.

use std::{
    collections::BTreeSet,
    fmt::Write as FmtWrite,
    fs::{self, OpenOptions},
    io::Write,
    path::{Component, Path, PathBuf},
};

use csv::WriterBuilder;
use serde::Serialize;
use thiserror::Error;

use crate::{
    MetricAvailability, MetricUnavailableReason, PerCommitMetricRecord, PerCommitSchemaError,
};
use simulation::{
    execute_baseline_workload, BaselineWorkloadConfig, BaselineWorkloadExecution,
    CommitterStrategy, WorkloadExecutionError, WorkloadOperation, WorkloadProfile,
};

/// Version of the public Task 55 artifact family.
pub const REPORT_ARTIFACT_SCHEMA_VERSION: u16 = 1;

/// Canonical Task 55 machine-readable artifact names.
pub const COMMITS_CSV_FILE_NAME: &str = "commits.csv";
/// Canonical Task 55 machine-readable artifact names.
pub const EPOCHS_CSV_FILE_NAME: &str = "epochs.csv";
/// Canonical Task 55 machine-readable artifact names.
pub const TRANSITION_EVENTS_CSV_FILE_NAME: &str = "transition_events.csv";
/// Canonical Task 55 machine-readable artifact names.
pub const SUMMARY_JSON_FILE_NAME: &str = "summary.json";
/// Canonical Task 55 human-readable artifact name.
pub const REPORT_MARKDOWN_FILE_NAME: &str = "report.md";

/// The report subjects required by the thesis plan.
///
/// Each subject has a matching numbered Markdown section. A baseline run may
/// truthfully mark a subject unavailable, but it may not silently omit one.
pub const REQUIRED_REPORT_SUBJECTS: [&str; 27] = [
    "Artifact schema and provenance",
    "Execution mode and research boundary",
    "Public workload configuration",
    "Public group identity and lifecycle",
    "Accepted operation sequence",
    "Committer identity and placement",
    "Membership evolution",
    "Baseline Commit byte observations",
    "Welcome byte observations",
    "Commit delivery and Welcome joins",
    "Accepted lifecycle timing",
    "Current binary topology metrics",
    "Candidate quaternary topology metrics",
    "Recipient-resolution metrics",
    "Candidate byte-comparison metrics",
    "Crypto-count and timing metrics",
    "Policy window facts",
    "Impactful-commit classification",
    "Transition-start evaluation",
    "Transition state",
    "Transition preflight and realized bytes",
    "Savings and Delta",
    "TreeCover maturity",
    "TreeCover retirement",
    "Measured versus estimated provenance",
    "Unavailable-data interpretation",
    "Security limitations and redaction boundary",
];

const BASELINE_MODE: &str = "baseline-binary-mls";
const EXPERIMENTAL_LIMITATION: &str = "This report contains an unchanged RFC 9420 baseline workload only. Experimental mKyber, hybrid UpdatePath, adaptive transition, TreeCover, and security properties are unavailable unless a real typed instrumentation boundary records them. This educational thesis software is not production cryptography and does not establish interoperability, a security proof, or X-Wing/C2PRI coverage.";

/// Public locations for a generated Task 55 artifact set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReportArtifactPaths {
    /// Raw per-commit records under `output/<run>`.
    pub commits_csv: PathBuf,
    /// Per-epoch public observations under `output/<run>`.
    pub epochs_csv: PathBuf,
    /// Transition facts or an explicit unavailable row under `output/<run>`.
    pub transition_events_csv: PathBuf,
    /// Safe public summary under `output/<run>`.
    pub summary_json: PathBuf,
    /// Human-readable report under `report/<run>`.
    pub report_markdown: PathBuf,
}

/// Errors while constructing or writing public Task 55 artifacts.
#[derive(Debug, Error)]
pub enum ReportArtifactError {
    /// The unchanged baseline workload could not execute and converge.
    #[error("baseline workload execution failed")]
    Workload(#[source] WorkloadExecutionError),
    /// The Task 54 conversion rejected invalid public accepted-commit facts.
    #[error("per-commit report schema construction failed")]
    Schema(#[source] PerCommitSchemaError),
    /// The requested artifact directory is outside the safe public boundary.
    #[error(
        "{kind} artifact directory must be a non-empty relative path below {required_prefix}/"
    )]
    UnsafeArtifactDirectory {
        /// The public directory role that failed validation.
        kind: &'static str,
        /// Required first path component.
        required_prefix: &'static str,
    },
    /// An evidence file already exists and must not be overwritten.
    #[error("a report artifact already exists")]
    ArtifactAlreadyExists,
    /// A public record could not be encoded as CSV.
    #[error("report CSV serialization failed")]
    Csv(#[source] csv::Error),
    /// A public record could not be encoded as JSON.
    #[error("report JSON serialization failed")]
    Json(#[source] serde_json::Error),
    /// A public artifact could not be written.
    #[error("report artifact write failed")]
    Write(#[source] std::io::Error),
}

/// Runs one unchanged-baseline workload and writes its public artifact family.
pub fn generate_baseline_report(
    workload: &BaselineWorkloadConfig,
    output_directory: &Path,
    report_directory: &Path,
) -> Result<ReportArtifactPaths, ReportArtifactError> {
    let execution = execute_baseline_workload(workload).map_err(ReportArtifactError::Workload)?;
    write_baseline_report_artifacts(workload, &execution, output_directory, report_directory)
}

/// Writes public Task 55 artifacts from an already accepted baseline workload.
///
/// This function performs no MLS operation. The caller may use it to report a
/// previously executed, converged workload while preserving Task 54's exact
/// record conversion and validation.
pub fn write_baseline_report_artifacts(
    workload: &BaselineWorkloadConfig,
    execution: &BaselineWorkloadExecution,
    output_directory: &Path,
    report_directory: &Path,
) -> Result<ReportArtifactPaths, ReportArtifactError> {
    validate_artifact_directory(output_directory, "output", "machine-readable")?;
    validate_artifact_directory(report_directory, "report", "Markdown")?;
    let records = PerCommitMetricRecord::from_baseline_workload(workload, execution)
        .map_err(ReportArtifactError::Schema)?;
    let paths = ReportArtifactPaths {
        commits_csv: output_directory.join(COMMITS_CSV_FILE_NAME),
        epochs_csv: output_directory.join(EPOCHS_CSV_FILE_NAME),
        transition_events_csv: output_directory.join(TRANSITION_EVENTS_CSV_FILE_NAME),
        summary_json: output_directory.join(SUMMARY_JSON_FILE_NAME),
        report_markdown: report_directory.join(REPORT_MARKDOWN_FILE_NAME),
    };
    for path in [
        &paths.commits_csv,
        &paths.epochs_csv,
        &paths.transition_events_csv,
        &paths.summary_json,
        &paths.report_markdown,
    ] {
        if path.exists() {
            return Err(ReportArtifactError::ArtifactAlreadyExists);
        }
    }
    fs::create_dir_all(output_directory).map_err(ReportArtifactError::Write)?;
    fs::create_dir_all(report_directory).map_err(ReportArtifactError::Write)?;

    write_new(&paths.commits_csv, &commits_csv(&records)?)?;
    write_new(&paths.epochs_csv, &epochs_csv(&records)?)?;
    write_new(
        &paths.transition_events_csv,
        &transition_events_csv(&records)?,
    )?;
    write_new(
        &paths.summary_json,
        &summary_json(workload, execution, &records)?,
    )?;
    write_new(
        &paths.report_markdown,
        &markdown_report(workload, execution, &records)?,
    )?;
    Ok(paths)
}

pub(crate) fn validate_artifact_directory(
    path: &Path,
    required_prefix: &'static str,
    kind: &'static str,
) -> Result<(), ReportArtifactError> {
    let mut components = path.components();
    if !matches!(components.next(), Some(Component::Normal(prefix)) if prefix == required_prefix)
        || components.next().is_none()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(ReportArtifactError::UnsafeArtifactDirectory {
            kind,
            required_prefix,
        });
    }
    Ok(())
}

pub(crate) fn write_new(path: &Path, bytes: &[u8]) -> Result<(), ReportArtifactError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(ReportArtifactError::Write)?;
    file.write_all(bytes).map_err(ReportArtifactError::Write)
}

#[derive(Serialize)]
struct CommitCsvRow {
    schema_version: u16,
    group_id_hex: String,
    sequence: u32,
    epoch_before: u64,
    epoch_after: u64,
    operation: String,
    operation_member_index: Option<u32>,
    committer_member_index: u32,
    committer_leaf_index: u32,
    committer_leaf_region: u32,
    active_member_count_after: u32,
    emitted_baseline_commit_bytes: u64,
    emitted_welcome_bytes: Option<u64>,
    direct_commit_delivery_count: u32,
    welcome_join_count: u32,
    accepted_lifecycle_elapsed_nanoseconds: u128,
    current_binary_topology: String,
    candidate_quaternary_topology: String,
    recipient_resolutions: String,
    candidate_byte_comparison: String,
    crypto_counts: String,
    policy_window: String,
    transition: String,
    retirement: String,
}

fn commits_csv(records: &[PerCommitMetricRecord]) -> Result<Vec<u8>, ReportArtifactError> {
    let mut writer = WriterBuilder::new()
        .has_headers(true)
        .from_writer(Vec::new());
    for record in records {
        writer
            .serialize(CommitCsvRow {
                schema_version: record.schema_version,
                group_id_hex: hex::encode(&record.identity.group_id),
                sequence: record.identity.sequence,
                epoch_before: record.identity.epoch_before,
                epoch_after: record.identity.epoch_after,
                operation: operation_name(record.operation).to_owned(),
                operation_member_index: operation_member_index(record.operation),
                committer_member_index: record.identity.committer_member_index,
                committer_leaf_index: record.identity.committer_leaf_index,
                committer_leaf_region: record.identity.committer_leaf_region,
                active_member_count_after: record.identity.active_member_count_after,
                emitted_baseline_commit_bytes: record.bytes.emitted_baseline_commit_bytes,
                emitted_welcome_bytes: record.bytes.emitted_welcome_bytes,
                direct_commit_delivery_count: record.direct_commit_delivery_count,
                welcome_join_count: record.welcome_join_count,
                accepted_lifecycle_elapsed_nanoseconds: record
                    .timing
                    .accepted_lifecycle_elapsed_nanoseconds,
                current_binary_topology: json_value(&record.topology.current_binary)?,
                candidate_quaternary_topology: json_value(&record.topology.candidate_quaternary)?,
                recipient_resolutions: json_value(&record.topology.recipient_resolutions)?,
                candidate_byte_comparison: json_value(&record.bytes.comparison)?,
                crypto_counts: json_value(&record.crypto_counts)?,
                policy_window: json_value(&record.policy_window)?,
                transition: json_value(&record.transition)?,
                retirement: json_value(&record.retirement)?,
            })
            .map_err(ReportArtifactError::Csv)?;
    }
    into_csv_bytes(writer)
}

#[derive(Serialize)]
struct EpochCsvRow {
    sequence: u32,
    epoch_after: u64,
    operation: String,
    active_member_count_after: u32,
    emitted_baseline_commit_bytes: u64,
    emitted_welcome_bytes: Option<u64>,
    direct_commit_delivery_count: u32,
    welcome_join_count: u32,
    accepted_lifecycle_elapsed_nanoseconds: u128,
    transition_availability: String,
    retirement_availability: String,
}

fn epochs_csv(records: &[PerCommitMetricRecord]) -> Result<Vec<u8>, ReportArtifactError> {
    let mut writer = WriterBuilder::new()
        .has_headers(true)
        .from_writer(Vec::new());
    for record in records {
        writer
            .serialize(EpochCsvRow {
                sequence: record.identity.sequence,
                epoch_after: record.identity.epoch_after,
                operation: operation_name(record.operation).to_owned(),
                active_member_count_after: record.identity.active_member_count_after,
                emitted_baseline_commit_bytes: record.bytes.emitted_baseline_commit_bytes,
                emitted_welcome_bytes: record.bytes.emitted_welcome_bytes,
                direct_commit_delivery_count: record.direct_commit_delivery_count,
                welcome_join_count: record.welcome_join_count,
                accepted_lifecycle_elapsed_nanoseconds: record
                    .timing
                    .accepted_lifecycle_elapsed_nanoseconds,
                transition_availability: availability_label(&record.transition).to_owned(),
                retirement_availability: availability_label(&record.retirement).to_owned(),
            })
            .map_err(ReportArtifactError::Csv)?;
    }
    into_csv_bytes(writer)
}

#[derive(Serialize)]
struct TransitionEventCsvRow {
    record_kind: &'static str,
    sequence: Option<u32>,
    epoch_after: Option<u64>,
    availability: &'static str,
    reason: Option<&'static str>,
}

fn transition_events_csv(
    records: &[PerCommitMetricRecord],
) -> Result<Vec<u8>, ReportArtifactError> {
    let mut writer = WriterBuilder::new()
        .has_headers(true)
        .from_writer(Vec::new());
    let observed_records = records
        .iter()
        .filter(|record| matches!(record.transition, MetricAvailability::Observed(_)))
        .count();
    if observed_records == 0 {
        writer
            .serialize(TransitionEventCsvRow {
                record_kind: "availability",
                sequence: None,
                epoch_after: None,
                availability: "unavailable",
                reason: Some("TransitionNotStarted"),
            })
            .map_err(ReportArtifactError::Csv)?;
    } else {
        for record in records
            .iter()
            .filter(|record| matches!(record.transition, MetricAvailability::Observed(_)))
        {
            writer
                .serialize(TransitionEventCsvRow {
                    record_kind: "transition",
                    sequence: Some(record.identity.sequence),
                    epoch_after: Some(record.identity.epoch_after),
                    availability: "observed",
                    reason: None,
                })
                .map_err(ReportArtifactError::Csv)?;
        }
    }
    into_csv_bytes(writer)
}

fn into_csv_bytes(writer: csv::Writer<Vec<u8>>) -> Result<Vec<u8>, ReportArtifactError> {
    writer
        .into_inner()
        .map_err(|error| ReportArtifactError::Csv(error.into_error().into()))
}

fn json_value<T: Serialize>(value: &T) -> Result<String, ReportArtifactError> {
    serde_json::to_string(value).map_err(ReportArtifactError::Json)
}

#[derive(Serialize)]
struct SummaryDocument<'a> {
    schema_version: u16,
    mode: &'static str,
    workload: WorkloadSummary,
    final_state: FinalStateSummary,
    aggregate: AggregateSummary,
    measurement_availability: Vec<MetricFamilyAvailability>,
    required_report_subjects: [&'static str; 27],
    limitations: Vec<&'static str>,
    per_commit_records: &'a [PerCommitMetricRecord],
}

#[derive(Serialize)]
struct WorkloadSummary {
    group_id_hex: String,
    initial_member_count: u32,
    maximum_member_count: u32,
    requested_operation_count: u32,
    region_count: u32,
    committer_strategy: String,
    workload_profile: String,
}

#[derive(Serialize)]
struct FinalStateSummary {
    final_epoch: u64,
    final_member_count: u32,
    final_active_committer_counts: Vec<FinalCommitterCount>,
}

#[derive(Serialize)]
struct FinalCommitterCount {
    member_index: u32,
    accepted_commit_count: u32,
}

#[derive(Serialize)]
struct AggregateSummary {
    accepted_commit_count: u32,
    total_baseline_commit_bytes: u64,
    total_welcome_bytes: u64,
    welcome_count: u32,
    total_direct_commit_deliveries: u64,
    total_welcome_joins: u64,
    total_accepted_lifecycle_elapsed_nanoseconds: u128,
}

#[derive(Serialize)]
struct MetricFamilyAvailability {
    family: &'static str,
    observed_record_count: u32,
    unavailable_record_count: u32,
    unavailable_reasons: Vec<&'static str>,
}

fn summary_json(
    workload: &BaselineWorkloadConfig,
    execution: &BaselineWorkloadExecution,
    records: &[PerCommitMetricRecord],
) -> Result<Vec<u8>, ReportArtifactError> {
    let document = SummaryDocument {
        schema_version: REPORT_ARTIFACT_SCHEMA_VERSION,
        mode: BASELINE_MODE,
        workload: workload_summary(workload),
        final_state: FinalStateSummary {
            final_epoch: execution.final_epoch,
            final_member_count: execution.final_member_count,
            final_active_committer_counts: execution
                .final_active_committer_counts
                .iter()
                .map(|count| FinalCommitterCount {
                    member_index: count.member_index,
                    accepted_commit_count: count.accepted_commit_count,
                })
                .collect(),
        },
        aggregate: aggregate_summary(records),
        measurement_availability: availability_summary(records),
        required_report_subjects: REQUIRED_REPORT_SUBJECTS,
        limitations: vec![
            EXPERIMENTAL_LIMITATION,
            "Unavailable values are neither zero nor estimates. They indicate that no matching trusted instrumentation supplied a value.",
            "No private MLS state, private keys, shared secrets, path secrets, AEAD keys, raw entropy, or reconstructible secret seed is serialized.",
        ],
        per_commit_records: records,
    };
    let mut bytes = serde_json::to_vec_pretty(&document).map_err(ReportArtifactError::Json)?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn workload_summary(workload: &BaselineWorkloadConfig) -> WorkloadSummary {
    WorkloadSummary {
        group_id_hex: hex::encode(&workload.group_id),
        initial_member_count: workload.initial_member_count,
        maximum_member_count: workload.maximum_member_count,
        requested_operation_count: workload.operation_count,
        region_count: workload.region_count,
        committer_strategy: committer_strategy_name(&workload.committer_strategy),
        workload_profile: workload_profile_name(workload.workload_profile),
    }
}

fn aggregate_summary(records: &[PerCommitMetricRecord]) -> AggregateSummary {
    AggregateSummary {
        accepted_commit_count: u32::try_from(records.len()).unwrap_or(u32::MAX),
        total_baseline_commit_bytes: records
            .iter()
            .map(|record| record.bytes.emitted_baseline_commit_bytes)
            .sum(),
        total_welcome_bytes: records
            .iter()
            .filter_map(|record| record.bytes.emitted_welcome_bytes)
            .sum(),
        welcome_count: u32::try_from(
            records
                .iter()
                .filter(|record| record.bytes.emitted_welcome_bytes.is_some())
                .count(),
        )
        .unwrap_or(u32::MAX),
        total_direct_commit_deliveries: records
            .iter()
            .map(|record| u64::from(record.direct_commit_delivery_count))
            .sum(),
        total_welcome_joins: records
            .iter()
            .map(|record| u64::from(record.welcome_join_count))
            .sum(),
        total_accepted_lifecycle_elapsed_nanoseconds: records
            .iter()
            .map(|record| record.timing.accepted_lifecycle_elapsed_nanoseconds)
            .sum(),
    }
}

fn availability_summary(records: &[PerCommitMetricRecord]) -> Vec<MetricFamilyAvailability> {
    vec![
        summarize_availability(records, "current_binary_topology", |record| {
            &record.topology.current_binary
        }),
        summarize_availability(records, "candidate_quaternary_topology", |record| {
            &record.topology.candidate_quaternary
        }),
        summarize_availability(records, "recipient_resolutions", |record| {
            &record.topology.recipient_resolutions
        }),
        summarize_availability(records, "candidate_byte_comparison", |record| {
            &record.bytes.comparison
        }),
        summarize_availability(records, "crypto_counts", |record| &record.crypto_counts),
        summarize_availability(records, "policy_window", |record| &record.policy_window),
        summarize_availability(records, "transition", |record| &record.transition),
        summarize_availability(records, "retirement", |record| &record.retirement),
    ]
}

fn summarize_availability<T>(
    records: &[PerCommitMetricRecord],
    family: &'static str,
    select: impl Fn(&PerCommitMetricRecord) -> &MetricAvailability<T>,
) -> MetricFamilyAvailability {
    let mut observed = 0_u32;
    let mut unavailable = 0_u32;
    let mut reasons = BTreeSet::new();
    for record in records {
        match select(record) {
            MetricAvailability::Observed(_) => observed += 1,
            MetricAvailability::Unavailable(reason) => {
                unavailable += 1;
                reasons.insert(unavailable_reason_name(*reason));
            }
        }
    }
    MetricFamilyAvailability {
        family,
        observed_record_count: observed,
        unavailable_record_count: unavailable,
        unavailable_reasons: reasons.into_iter().collect(),
    }
}

fn markdown_report(
    workload: &BaselineWorkloadConfig,
    execution: &BaselineWorkloadExecution,
    records: &[PerCommitMetricRecord],
) -> Result<Vec<u8>, ReportArtifactError> {
    let aggregate = aggregate_summary(records);
    let availability = availability_summary(records);
    let mut markdown = String::new();
    writeln!(markdown, "# Adaptive Hybrid MLS Task 55 Report").expect("string write");
    writeln!(markdown).expect("string write");
    writeln!(
        markdown,
        "Schema: `adaptive-hybrid-mls/report-v{REPORT_ARTIFACT_SCHEMA_VERSION}`  "
    )
    .expect("string write");
    writeln!(markdown, "Mode: `{BASELINE_MODE}`  ").expect("string write");
    writeln!(
        markdown,
        "Group identifier (public hex): `{}`",
        hex::encode(&workload.group_id)
    )
    .expect("string write");
    writeln!(markdown).expect("string write");
    writeln!(markdown, "> {EXPERIMENTAL_LIMITATION}").expect("string write");
    for (index, subject) in REQUIRED_REPORT_SUBJECTS.iter().enumerate() {
        writeln!(markdown, "\n## {}. {subject}\n", index + 1).expect("string write");
        write_subject(
            &mut markdown,
            index,
            workload,
            execution,
            &aggregate,
            &availability,
            records,
        )?;
    }
    Ok(markdown.into_bytes())
}

fn write_subject(
    markdown: &mut String,
    index: usize,
    workload: &BaselineWorkloadConfig,
    execution: &BaselineWorkloadExecution,
    aggregate: &AggregateSummary,
    availability: &[MetricFamilyAvailability],
    records: &[PerCommitMetricRecord],
) -> Result<(), ReportArtifactError> {
    match index {
        0 => writeln!(markdown, "Artifact schema version `{REPORT_ARTIFACT_SCHEMA_VERSION}`; `commits.csv`, `epochs.csv`, `transition_events.csv`, and `summary.json` are public machine-readable provenance.").expect("string write"),
        1 => writeln!(markdown, "The run uses the unchanged baseline adapter only. Non-standard components remain research-only and unavailable in this result.").expect("string write"),
        2 => writeln!(markdown, "Initial members: {}; maximum members: {}; requested operations: {}; regions: {}; workload: `{}`; committer strategy: `{}`.", workload.initial_member_count, workload.maximum_member_count, workload.operation_count, workload.region_count, workload_profile_name(workload.workload_profile), committer_strategy_name(&workload.committer_strategy)).expect("string write"),
        3 => writeln!(markdown, "Accepted commits: {}; final epoch: {}; final active members: {}.", aggregate.accepted_commit_count, execution.final_epoch, execution.final_member_count).expect("string write"),
        4 => writeln!(markdown, "Sequences are one-based and contiguous; each accepted record advances the public MLS epoch by exactly one. See `commits.csv`.").expect("string write"),
        5 => writeln!(markdown, "`commits.csv` records public committer member, leaf, and region labels for every accepted commit.").expect("string write"),
        6 => writeln!(markdown, "`epochs.csv` records the post-commit active-member count for each accepted epoch.").expect("string write"),
        7 => writeln!(markdown, "Measured emitted baseline Commit bytes total {} across {} accepted commits.", aggregate.total_baseline_commit_bytes, aggregate.accepted_commit_count).expect("string write"),
        8 => writeln!(markdown, "{} Add operations emitted a Welcome; measured Welcome bytes total {}.", aggregate.welcome_count, aggregate.total_welcome_bytes).expect("string write"),
        9 => writeln!(markdown, "Observed direct Commit deliveries total {}; Welcome joins total {}.", aggregate.total_direct_commit_deliveries, aggregate.total_welcome_joins).expect("string write"),
        10 => writeln!(markdown, "Observed accepted lifecycle time totals {} ns. Timing is environment-dependent and is not a reproducible performance claim.", aggregate.total_accepted_lifecycle_elapsed_nanoseconds).expect("string write"),
        11..=16 | 18..=23 => write_availability_subject(markdown, index, availability)?,
        17 => writeln!(markdown, "No Task 35 policy window is attached to this baseline-only run, so no impactful-commit classification is claimed.").expect("string write"),
        24 => writeln!(markdown, "Baseline Commit and Welcome sizes are measured emitted bytes. Every candidate, policy, transition, and retirement value is retained as typed unavailable rather than relabeled as measured or estimated.").expect("string write"),
        25 => writeln!(markdown, "Unavailable does not mean zero, success, failure, or an estimate. It means no matching trusted instrumentation supplied a value for this record.").expect("string write"),
        26 => writeln!(markdown, "SEC-01 through SEC-10 remain unresolved for experimental claims. The artifacts contain no private MLS keys, mKyber keys, shared/path secrets, AEAD material, raw entropy, or reconstructible secret seed.").expect("string write"),
        _ => return Err(ReportArtifactError::Json(serde_json::Error::io(std::io::Error::other("unknown report subject")))),
    }
    if index == 4 && records.is_empty() {
        writeln!(markdown, "No accepted records were supplied.").expect("string write");
    }
    Ok(())
}

fn write_availability_subject(
    markdown: &mut String,
    subject_index: usize,
    availability: &[MetricFamilyAvailability],
) -> Result<(), ReportArtifactError> {
    let family = match subject_index {
        11 => "current_binary_topology",
        12 => "candidate_quaternary_topology",
        13 => "recipient_resolutions",
        14 => "candidate_byte_comparison",
        15 => "crypto_counts",
        16 => "policy_window",
        18..=22 => "transition",
        23 => "retirement",
        _ => {
            return Err(ReportArtifactError::Json(serde_json::Error::io(
                std::io::Error::other("unknown availability subject"),
            )))
        }
    };
    let value = availability
        .iter()
        .find(|value| value.family == family)
        .expect("all report availability families are present");
    writeln!(
        markdown,
        "Observed records: {}; unavailable records: {}; reasons: {}.",
        value.observed_record_count,
        value.unavailable_record_count,
        if value.unavailable_reasons.is_empty() {
            "none".to_owned()
        } else {
            value.unavailable_reasons.join(", ")
        }
    )
    .expect("string write");
    Ok(())
}

fn operation_name(operation: WorkloadOperation) -> &'static str {
    match operation {
        WorkloadOperation::Update => "update",
        WorkloadOperation::Add { .. } => "add",
        WorkloadOperation::Remove { .. } => "remove",
    }
}

fn operation_member_index(operation: WorkloadOperation) -> Option<u32> {
    match operation {
        WorkloadOperation::Update => None,
        WorkloadOperation::Add { member_index } | WorkloadOperation::Remove { member_index } => {
            Some(member_index)
        }
    }
}

fn committer_strategy_name(strategy: &CommitterStrategy) -> String {
    match strategy {
        CommitterStrategy::RoundRobin => "round-robin".to_owned(),
        CommitterStrategy::SeededRandom { seed } => format!("seeded-random:{seed}"),
        CommitterStrategy::FixedList { member_indexes } => format!("fixed-list:{member_indexes:?}"),
        CommitterStrategy::WeightedRandom { seed, weights } => {
            format!("weighted-random:{seed}:{weights:?}")
        }
        CommitterStrategy::LeafRegionBalanced => "leaf-region-balanced".to_owned(),
    }
}

fn workload_profile_name(profile: WorkloadProfile) -> String {
    match profile {
        WorkloadProfile::UpdateOnly => "update-only".to_owned(),
        WorkloadProfile::Mixed => "mixed".to_owned(),
        WorkloadProfile::RemovalHeavy => "removal-heavy".to_owned(),
        WorkloadProfile::RegionSkewed { preferred_region } => {
            format!("region-skewed:{preferred_region}")
        }
        WorkloadProfile::Uniform { seed } => format!("uniform:{seed}"),
    }
}

fn availability_label<T>(availability: &MetricAvailability<T>) -> &'static str {
    match availability {
        MetricAvailability::Observed(_) => "Observed",
        MetricAvailability::Unavailable(reason) => unavailable_reason_name(*reason),
    }
}

fn unavailable_reason_name(reason: MetricUnavailableReason) -> &'static str {
    match reason {
        MetricUnavailableReason::NotInstrumented => "NotInstrumented",
        MetricUnavailableReason::NotApplicable => "NotApplicable",
        MetricUnavailableReason::RequiresExperimentalFork => "RequiresExperimentalFork",
        MetricUnavailableReason::PolicyWindowNotAttached => "PolicyWindowNotAttached",
        MetricUnavailableReason::TransitionNotStarted => "TransitionNotStarted",
        MetricUnavailableReason::TreeCoverNotRetired => "TreeCoverNotRetired",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::Builder;

    fn config() -> BaselineWorkloadConfig {
        BaselineWorkloadConfig {
            group_id: b"task-55-report".to_vec(),
            initial_member_count: 2,
            maximum_member_count: 3,
            operation_count: 3,
            region_count: 2,
            committer_strategy: CommitterStrategy::RoundRobin,
            workload_profile: WorkloadProfile::Mixed,
        }
    }

    fn temporary_artifact_directory(parent: &str, prefix: &str) -> tempfile::TempDir {
        fs::create_dir_all(parent).expect("test artifact parent directory");
        Builder::new()
            .prefix(prefix)
            .tempdir_in(parent)
            .expect("test artifact directory")
    }

    fn relative_test_path(directory: &tempfile::TempDir) -> PathBuf {
        directory
            .path()
            .strip_prefix(std::env::current_dir().expect("test working directory"))
            .expect("temporary directory below the test working directory")
            .to_path_buf()
    }

    #[test]
    fn writes_the_complete_public_baseline_artifact_family() {
        let output = temporary_artifact_directory("output", "task55-output-");
        let report = temporary_artifact_directory("report", "task55-report-");
        let paths = generate_baseline_report(
            &config(),
            &relative_test_path(&output),
            &relative_test_path(&report),
        )
        .expect("report generation");

        for path in [
            &paths.commits_csv,
            &paths.epochs_csv,
            &paths.transition_events_csv,
            &paths.summary_json,
            &paths.report_markdown,
        ] {
            assert!(path.is_file(), "missing {}", path.display());
        }
        let commits = fs::read_to_string(&paths.commits_csv).expect("commits CSV");
        assert!(commits.contains("candidate_quaternary_topology"));
        assert!(commits.contains("RequiresExperimentalFork"));
        let transition_events =
            fs::read_to_string(&paths.transition_events_csv).expect("transition events CSV");
        assert!(transition_events.contains("TransitionNotStarted"));
        let summary = fs::read_to_string(&paths.summary_json).expect("summary JSON");
        assert!(summary.contains("required_report_subjects"));
        assert!(summary.contains("per_commit_records"));
        let markdown = fs::read_to_string(&paths.report_markdown).expect("Markdown report");
        assert_eq!(
            markdown.matches("## ").count(),
            REQUIRED_REPORT_SUBJECTS.len()
        );
        assert!(markdown.contains("SEC-01 through SEC-10"));
        for prohibited in [
            "private_key_hex",
            "shared_secret_hex",
            "path_secret_hex",
            "aead_key_hex",
            "raw_entropy_hex",
        ] {
            assert!(!summary.contains(prohibited), "summary leaked {prohibited}");
            assert!(!markdown.contains(prohibited), "report leaked {prohibited}");
        }
    }

    #[test]
    fn rejects_unsafe_or_overwriting_artifact_locations() {
        let execution = execute_baseline_workload(&config()).expect("baseline workload");
        assert!(matches!(
            write_baseline_report_artifacts(
                &config(),
                &execution,
                Path::new("../output/bad"),
                Path::new("report/valid"),
            ),
            Err(ReportArtifactError::UnsafeArtifactDirectory { .. })
        ));

        let output = temporary_artifact_directory("output", "task55-output-existing-");
        let report = temporary_artifact_directory("report", "task55-report-existing-");
        let output_path = relative_test_path(&output);
        let report_path = relative_test_path(&report);
        let first =
            write_baseline_report_artifacts(&config(), &execution, &output_path, &report_path)
                .expect("first artifact set");
        assert!(first.summary_json.is_file());
        assert!(matches!(
            write_baseline_report_artifacts(&config(), &execution, &output_path, &report_path),
            Err(ReportArtifactError::ArtifactAlreadyExists)
        ));
    }
}
