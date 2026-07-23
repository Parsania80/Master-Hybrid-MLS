#![forbid(unsafe_code)]

//! Final minimal Task 67 thesis-table dataset.
//!
//! The generator copies only public, completed Task 62--66 artifacts into one
//! availability-aware long-form schema. It deliberately does not rerun an MLS
//! workload or manufacture an unavailable number.

use std::{
    fmt::Write as FmtWrite,
    fs,
    path::{Path, PathBuf},
};

use csv::{ReaderBuilder, WriterBuilder};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::generation::{validate_artifact_directory, write_new, ReportArtifactError};

/// Version of the final Task 67 long-form schema.
pub const THESIS_TABLE_SCHEMA_VERSION: u16 = 1;
/// Canonical long-form final dataset name.
pub const THESIS_TABLES_CSV_FILE_NAME: &str = "thesis_tables.csv";
/// Canonical final manifest name.
pub const THESIS_TABLES_JSON_FILE_NAME: &str = "thesis_tables.json";
/// Canonical human-readable final table name.
pub const THESIS_TABLES_MARKDOWN_FILE_NAME: &str = "thesis_tables.md";

/// Public output paths for one final thesis-table dataset.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ThesisTableArtifactPaths {
    /// One long-form public CSV for all completed table cells.
    pub thesis_tables_csv: PathBuf,
    /// Complete public provenance manifest.
    pub thesis_tables_json: PathBuf,
    /// Grouped human-readable Markdown tables.
    pub thesis_tables_markdown: PathBuf,
}

/// Errors from final thesis-table generation and validation.
#[derive(Debug, Error)]
pub enum ThesisTableError {
    /// A required public source artifact could not be read.
    #[error("required Task 62--66 public source artifact could not be read")]
    Read(#[source] std::io::Error),
    /// A required source CSV was malformed.
    #[error("required Task 62--66 public source CSV was malformed")]
    CsvRead(#[source] csv::Error),
    /// A required source JSON was malformed.
    #[error("required Task 62--66 public source JSON was malformed")]
    JsonRead(#[source] serde_json::Error),
    /// A completed source artifact lacked a required public row.
    #[error("required Task 62--66 public source row was absent")]
    MissingSourceRow,
    /// A public final cell had no stable label or provenance.
    #[error("final thesis-table cell lacks required label or provenance")]
    IncompleteCell,
    /// A numeric/text value and availability state were inconsistent.
    #[error("final thesis-table cell has an inconsistent availability state")]
    InvalidAvailability,
    /// A final public value resembled forbidden secret material.
    #[error("final thesis-table cell was rejected by the secret-output guard")]
    PotentialSecretMaterial,
    /// Artifact safe-path/create-new failure.
    #[error("final thesis-table artifact output failed")]
    Artifact(#[from] ReportArtifactError),
    /// Final CSV encoding failed.
    #[error("final thesis-table CSV encoding failed")]
    CsvWrite(#[source] csv::Error),
    /// Final JSON encoding failed.
    #[error("final thesis-table JSON encoding failed")]
    JsonWrite(#[source] serde_json::Error),
}

#[derive(Clone, Debug, Deserialize)]
struct EnvironmentInput {
    rust_version_verbose: String,
    openmls_hybrid_upstream_revision: String,
    classical_mls_hpke_profile: String,
    educational_mkyber_profile: String,
    cpu_model: String,
    installed_memory_kib: u64,
    operating_system: String,
    kernel_release: String,
    configured_repetitions: u32,
    runs: Vec<EnvironmentRunInput>,
}

#[derive(Clone, Debug, Deserialize)]
struct EnvironmentRunInput {
    run_index: u32,
    elapsed_nanoseconds: u128,
    peak_rss_kib: Option<u64>,
    value_state: String,
    reason: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct ComparisonInputRow {
    mode: String,
    run_index: Option<u32>,
    measurement: String,
    unit: String,
    value_state: String,
    numeric_value: Option<i128>,
    reason: Option<String>,
    provenance: String,
}

#[derive(Clone, Debug, Deserialize)]
struct NormalInputRow {
    arity: u8,
    operation: String,
    provenance: String,
    serialized_message_bytes: u64,
    mean_elapsed_nanoseconds: u128,
    repetitions: u32,
    classical_encapsulation_count: Option<u32>,
    classical_count_reason: Option<String>,
    mkyber_common_encapsulation_count: u32,
    mkyber_recipient_component_count: u32,
    process_peak_rss_kib: Option<u64>,
    process_peak_rss_state: String,
}

#[derive(Clone, Debug, Deserialize)]
struct TransitionInputManifest {
    rows: Vec<TransitionInputRow>,
}

#[derive(Clone, Debug, Deserialize)]
struct TransitionInputRow {
    transition: String,
    provenance: String,
    member_count: u32,
    transition_bytes: u64,
    cumulative_bytes_to_maturity_evaluation: u64,
    impactful_updates_until_retirement_condition: u32,
    c_leaf_bytes: u64,
    c_new_bytes: u64,
    c_old_bytes: u64,
    c_ideal_bytes: u64,
    aggregate_counterfactual_bytes: u64,
    h_new_cost: String,
    h_old_cost: String,
    threshold_decision: String,
    threshold_trigger: String,
    break_even_updates: Option<u32>,
    break_even_reason: Option<String>,
    logical_treecover_retirement_epoch: Option<u64>,
    treecover_retirement_state: String,
}

#[derive(Clone, Debug, Deserialize)]
struct ModelInputManifest {
    timing_samples: u32,
    primitive_timing_medians: PrimitiveTimingInput,
    rows: Vec<ModelInputRow>,
}

#[derive(Clone, Debug, Deserialize)]
struct PrimitiveTimingInput {
    mkyber_three_recipient_encapsulation_nanoseconds: u128,
    deterministic_byte_write_calibration_nanoseconds: u128,
    deterministic_byte_write_calibration_bytes: u64,
}

#[derive(Clone, Debug, Deserialize)]
struct ModelInputRow {
    source_task: String,
    measurement: String,
    provenance: String,
    arity: Option<u8>,
    path_length_or_delivery_count: Option<u32>,
    recipient_count: Option<u32>,
    measured_bytes: Option<u64>,
    modeled_bytes: Option<u64>,
    size_absolute_difference_bytes: Option<u64>,
    error_size_percent_micro: Option<u128>,
    size_unavailable_reason: Option<String>,
    measured_elapsed_nanoseconds: Option<u128>,
    estimated_elapsed_nanoseconds: Option<u128>,
    time_absolute_difference_nanoseconds: Option<u128>,
    error_time_percent_micro: Option<u128>,
    time_unavailable_reason: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
struct ThesisTableManifest {
    schema_version: u16,
    source_artifacts: SourceArtifacts,
    rows: Vec<ThesisTableRow>,
    scope_note: &'static str,
}

#[derive(Clone, Debug, Serialize)]
struct SourceArtifacts {
    task62_comparison_csv: String,
    task63_environment_json: String,
    task64_normal_operations_csv: String,
    task65_transition_maturity_json: String,
    task66_model_errors_json: String,
}

/// One final table cell. `persian_label_key` is intentionally separate from
/// the stable English machine field so a thesis layout can translate labels
/// without parsing or changing the data schema.
#[derive(Clone, Debug, Serialize)]
pub struct ThesisTableRow {
    /// Stable schema version.
    pub schema_version: u16,
    /// Stable table family, such as `environment` or `model_errors`.
    pub table: &'static str,
    /// Human-readable English table name.
    pub table_label: &'static str,
    /// Stable key reserved for a Persian thesis label.
    pub persian_label_key: String,
    /// Stable source-record identity.
    pub record_key: String,
    /// Stable machine-readable cell name.
    pub field: String,
    /// Human-readable English field name.
    pub field_label: String,
    /// Stable key reserved for a Persian field label.
    pub persian_field_label_key: String,
    /// `observed`, `educational`, `counterfactual`, `modelled`, or `unavailable`.
    pub value_state: String,
    /// Numeric value when the state is available.
    pub numeric_value: Option<i128>,
    /// Public text value when the state is available.
    pub text_value: Option<String>,
    /// Unit or `text`.
    pub unit: String,
    /// Explicit reason only when value state is unavailable.
    pub reason: Option<String>,
    /// Measurement provenance, never inferred by consumers.
    pub provenance: String,
    /// Relative source artifact that supplied the cell.
    pub source_artifact: String,
}

/// Generates create-new final CSV, JSON, and Markdown artifacts.
pub fn generate_thesis_table_artifacts(
    comparison_csv: &Path,
    environment_json: &Path,
    normal_operations_csv: &Path,
    transition_maturity_json: &Path,
    model_errors_json: &Path,
    output_directory: &Path,
    report_directory: &Path,
) -> Result<ThesisTableArtifactPaths, ThesisTableError> {
    validate_artifact_directory(output_directory, "output", "final thesis-table evidence")?;
    validate_artifact_directory(report_directory, "report", "final thesis tables")?;
    let paths = ThesisTableArtifactPaths {
        thesis_tables_csv: output_directory.join(THESIS_TABLES_CSV_FILE_NAME),
        thesis_tables_json: output_directory.join(THESIS_TABLES_JSON_FILE_NAME),
        thesis_tables_markdown: report_directory.join(THESIS_TABLES_MARKDOWN_FILE_NAME),
    };
    for path in [
        &paths.thesis_tables_csv,
        &paths.thesis_tables_json,
        &paths.thesis_tables_markdown,
    ] {
        if path.exists() {
            return Err(ThesisTableError::Artifact(
                ReportArtifactError::ArtifactAlreadyExists,
            ));
        }
    }

    let environment = read_json::<EnvironmentInput>(environment_json)?;
    let comparison = read_csv::<ComparisonInputRow>(comparison_csv)?;
    let normal = read_csv::<NormalInputRow>(normal_operations_csv)?;
    let transition = read_json::<TransitionInputManifest>(transition_maturity_json)?;
    let model = read_json::<ModelInputManifest>(model_errors_json)?;
    if comparison.is_empty()
        || normal.is_empty()
        || transition.rows.len() != 2
        || model.rows.is_empty()
    {
        return Err(ThesisTableError::MissingSourceRow);
    }
    let sources = SourceArtifacts {
        task62_comparison_csv: source_path(comparison_csv),
        task63_environment_json: source_path(environment_json),
        task64_normal_operations_csv: source_path(normal_operations_csv),
        task65_transition_maturity_json: source_path(transition_maturity_json),
        task66_model_errors_json: source_path(model_errors_json),
    };
    let mut rows = Vec::new();
    append_environment_rows(&mut rows, &environment, &sources.task63_environment_json)?;
    append_comparison_rows(&mut rows, &comparison, &sources.task62_comparison_csv)?;
    append_normal_rows(&mut rows, &normal, &sources.task64_normal_operations_csv)?;
    append_transition_rows(
        &mut rows,
        &transition.rows,
        &sources.task65_transition_maturity_json,
    )?;
    append_model_rows(&mut rows, &model, &sources.task66_model_errors_json)?;
    validate_rows(&rows)?;
    let manifest = ThesisTableManifest {
        schema_version: THESIS_TABLE_SCHEMA_VERSION,
        source_artifacts: sources,
        rows,
        scope_note: "Final Task 67 dataset built only from completed Task 62--66 public artifacts. Stable English field names and independent Persian-ready label keys are separate. Every unavailable value carries a reason; zero remains numeric only when observed/modelled as zero. This educational thesis dataset is not an interoperability, security, production, or CPU-benchmark claim.",
    };
    fs::create_dir_all(output_directory)
        .map_err(|error| ThesisTableError::Artifact(ReportArtifactError::Write(error)))?;
    fs::create_dir_all(report_directory)
        .map_err(|error| ThesisTableError::Artifact(ReportArtifactError::Write(error)))?;
    write_new(
        &paths.thesis_tables_csv,
        &thesis_tables_csv(&manifest.rows)?,
    )?;
    write_new(
        &paths.thesis_tables_json,
        &serde_json::to_vec_pretty(&manifest).map_err(ThesisTableError::JsonWrite)?,
    )?;
    write_new(
        &paths.thesis_tables_markdown,
        thesis_tables_markdown(&manifest).as_bytes(),
    )?;
    Ok(paths)
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, ThesisTableError> {
    let bytes = fs::read(path).map_err(ThesisTableError::Read)?;
    serde_json::from_slice(&bytes).map_err(ThesisTableError::JsonRead)
}

fn read_csv<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<Vec<T>, ThesisTableError> {
    let file = fs::File::open(path).map_err(ThesisTableError::Read)?;
    let mut reader = ReaderBuilder::new().from_reader(file);
    reader
        .deserialize()
        .collect::<Result<Vec<_>, _>>()
        .map_err(ThesisTableError::CsvRead)
}

fn source_path(path: &Path) -> String {
    path.display().to_string()
}

fn append_environment_rows(
    rows: &mut Vec<ThesisTableRow>,
    input: &EnvironmentInput,
    source: &str,
) -> Result<(), ThesisTableError> {
    let record = "task63_environment";
    append_text(
        rows,
        "environment",
        "Implementation environment",
        record,
        "rust_version",
        &input.rust_version_verbose,
        "text",
        "observed",
        "Task63 Linux environment collector",
        source,
    );
    append_text(
        rows,
        "environment",
        "Implementation environment",
        record,
        "openmls_hybrid_revision",
        &input.openmls_hybrid_upstream_revision,
        "git revision",
        "observed",
        "compiled experimental fork constant",
        source,
    );
    append_text(
        rows,
        "environment",
        "Implementation environment",
        record,
        "classical_mls_hpke_profile",
        &input.classical_mls_hpke_profile,
        "profile",
        "observed",
        "compiled adapter constant",
        source,
    );
    append_text(
        rows,
        "environment",
        "Implementation environment",
        record,
        "educational_mkyber_profile",
        &input.educational_mkyber_profile,
        "profile",
        "observed",
        "compiled mKyber constant",
        source,
    );
    append_text(
        rows,
        "environment",
        "Implementation environment",
        record,
        "cpu_model",
        &input.cpu_model,
        "text",
        "observed",
        "Linux public system information",
        source,
    );
    append_number(
        rows,
        "environment",
        "Implementation environment",
        record,
        "installed_memory",
        i128::from(input.installed_memory_kib),
        "KiB",
        "observed",
        "Linux public system information",
        source,
    );
    append_text(
        rows,
        "environment",
        "Implementation environment",
        record,
        "operating_system",
        &input.operating_system,
        "text",
        "observed",
        "Linux public system information",
        source,
    );
    append_text(
        rows,
        "environment",
        "Implementation environment",
        record,
        "kernel_release",
        &input.kernel_release,
        "text",
        "observed",
        "Linux public system information",
        source,
    );
    append_number(
        rows,
        "environment",
        "Implementation environment",
        record,
        "configured_repetitions",
        i128::from(input.configured_repetitions),
        "runs",
        "observed",
        "Task63 collector control",
        source,
    );
    for run in &input.runs {
        let run_record = format!("task63_run_{}", run.run_index);
        append_number(
            rows,
            "environment",
            "Implementation environment",
            &run_record,
            "elapsed_nanoseconds",
            i128::try_from(run.elapsed_nanoseconds)
                .map_err(|_| ThesisTableError::MissingSourceRow)?,
            "nanoseconds",
            &run.value_state,
            "direct child elapsed observation",
            source,
        );
        match run.peak_rss_kib {
            Some(value) => append_number(
                rows,
                "environment",
                "Implementation environment",
                &run_record,
                "peak_rss",
                i128::from(value),
                "KiB",
                &run.value_state,
                "sampled direct child VmHWM",
                source,
            ),
            None => append_unavailable(
                rows,
                "environment",
                "Implementation environment",
                &run_record,
                "peak_rss",
                "KiB",
                run.reason.as_deref().unwrap_or("PeakRssUnavailable"),
                "Task63 Linux collector",
                source,
            ),
        }
    }
    Ok(())
}

fn append_comparison_rows(
    rows: &mut Vec<ThesisTableRow>,
    input: &[ComparisonInputRow],
    source: &str,
) -> Result<(), ThesisTableError> {
    for row in input {
        let record = format!("{}_run_{}", row.mode, row.run_index.unwrap_or(0));
        match row.numeric_value {
            Some(value) => append_number(
                rows,
                "mode_comparison",
                "Three-mode comparison",
                &record,
                &row.measurement,
                value,
                &row.unit,
                &row.value_state,
                &row.provenance,
                source,
            ),
            None => append_unavailable(
                rows,
                "mode_comparison",
                "Three-mode comparison",
                &record,
                &row.measurement,
                &row.unit,
                row.reason
                    .as_deref()
                    .ok_or(ThesisTableError::MissingSourceRow)?,
                &row.provenance,
                source,
            ),
        }
    }
    Ok(())
}

fn append_normal_rows(
    rows: &mut Vec<ThesisTableRow>,
    input: &[NormalInputRow],
    source: &str,
) -> Result<(), ThesisTableError> {
    for row in input {
        let record = format!("{}_arity{}_{}", row.provenance, row.arity, row.operation);
        let state = if row.provenance == "educational_codec" {
            "educational"
        } else {
            "observed"
        };
        append_number(
            rows,
            "normal_operations",
            "Normal operations",
            &record,
            "arity",
            i128::from(row.arity),
            "arity",
            state,
            &row.provenance,
            source,
        );
        append_text(
            rows,
            "normal_operations",
            "Normal operations",
            &record,
            "operation",
            &row.operation,
            "text",
            state,
            &row.provenance,
            source,
        );
        append_number(
            rows,
            "normal_operations",
            "Normal operations",
            &record,
            "serialized_message_bytes",
            i128::from(row.serialized_message_bytes),
            "bytes",
            state,
            &row.provenance,
            source,
        );
        append_number(
            rows,
            "normal_operations",
            "Normal operations",
            &record,
            "mean_elapsed_nanoseconds",
            i128::try_from(row.mean_elapsed_nanoseconds)
                .map_err(|_| ThesisTableError::MissingSourceRow)?,
            "nanoseconds",
            state,
            &row.provenance,
            source,
        );
        append_number(
            rows,
            "normal_operations",
            "Normal operations",
            &record,
            "repetitions",
            i128::from(row.repetitions),
            "runs",
            state,
            &row.provenance,
            source,
        );
        match row.classical_encapsulation_count {
            Some(value) => append_number(
                rows,
                "normal_operations",
                "Normal operations",
                &record,
                "classical_encapsulation_count",
                i128::from(value),
                "encapsulations",
                state,
                &row.provenance,
                source,
            ),
            None => append_unavailable(
                rows,
                "normal_operations",
                "Normal operations",
                &record,
                "classical_encapsulation_count",
                "encapsulations",
                row.classical_count_reason
                    .as_deref()
                    .ok_or(ThesisTableError::MissingSourceRow)?,
                &row.provenance,
                source,
            ),
        }
        append_number(
            rows,
            "normal_operations",
            "Normal operations",
            &record,
            "mkyber_common_ciphertext_count",
            i128::from(row.mkyber_common_encapsulation_count),
            "ciphertexts",
            state,
            &row.provenance,
            source,
        );
        append_number(
            rows,
            "normal_operations",
            "Normal operations",
            &record,
            "mkyber_recipient_component_count",
            i128::from(row.mkyber_recipient_component_count),
            "components",
            state,
            &row.provenance,
            source,
        );
        match row.process_peak_rss_kib {
            Some(value) => append_number(
                rows,
                "normal_operations",
                "Normal operations",
                &record,
                "process_peak_rss",
                i128::from(value),
                "KiB",
                &row.process_peak_rss_state,
                "whole process VmHWM after row",
                source,
            ),
            None => append_unavailable(
                rows,
                "normal_operations",
                "Normal operations",
                &record,
                "process_peak_rss",
                "KiB",
                &row.process_peak_rss_state,
                "whole process VmHWM after row",
                source,
            ),
        }
    }
    Ok(())
}

fn append_transition_rows(
    rows: &mut Vec<ThesisTableRow>,
    input: &[TransitionInputRow],
    source: &str,
) -> Result<(), ThesisTableError> {
    for row in input {
        let record = row.transition.as_str();
        for (field, value, unit) in [
            ("member_count", i128::from(row.member_count), "members"),
            (
                "transition_bytes",
                i128::from(row.transition_bytes),
                "bytes",
            ),
            (
                "cumulative_bytes_to_maturity_evaluation",
                i128::from(row.cumulative_bytes_to_maturity_evaluation),
                "bytes",
            ),
            (
                "impactful_updates_until_retirement_condition",
                i128::from(row.impactful_updates_until_retirement_condition),
                "updates",
            ),
            ("c_leaf", i128::from(row.c_leaf_bytes), "bytes"),
            ("c_new", i128::from(row.c_new_bytes), "bytes"),
            ("c_old", i128::from(row.c_old_bytes), "bytes"),
            ("c_ideal", i128::from(row.c_ideal_bytes), "bytes"),
            (
                "aggregate_counterfactual",
                i128::from(row.aggregate_counterfactual_bytes),
                "bytes",
            ),
        ] {
            let state = transition_value_state(&row.provenance, field);
            append_number(
                rows,
                "transition_maturity",
                "Transition maturity and TreeCover",
                record,
                field,
                value,
                unit,
                state,
                &row.provenance,
                source,
            );
        }
        append_text(
            rows,
            "transition_maturity",
            "Transition maturity and TreeCover",
            record,
            "h_new_cost",
            &row.h_new_cost,
            "rational",
            transition_value_state(&row.provenance, "h_new_cost"),
            &row.provenance,
            source,
        );
        append_text(
            rows,
            "transition_maturity",
            "Transition maturity and TreeCover",
            record,
            "h_old_cost",
            &row.h_old_cost,
            "rational",
            transition_value_state(&row.provenance, "h_old_cost"),
            &row.provenance,
            source,
        );
        append_text(
            rows,
            "transition_maturity",
            "Transition maturity and TreeCover",
            record,
            "threshold_decision",
            &row.threshold_decision,
            "text",
            transition_value_state(&row.provenance, "threshold_decision"),
            &row.provenance,
            source,
        );
        append_text(
            rows,
            "transition_maturity",
            "Transition maturity and TreeCover",
            record,
            "threshold_trigger",
            &row.threshold_trigger,
            "text",
            transition_value_state(&row.provenance, "threshold_trigger"),
            &row.provenance,
            source,
        );
        match row.break_even_updates {
            Some(value) => append_number(
                rows,
                "transition_maturity",
                "Transition maturity and TreeCover",
                record,
                "break_even_updates",
                i128::from(value),
                "updates",
                transition_value_state(&row.provenance, "break_even_updates"),
                &row.provenance,
                source,
            ),
            None => append_unavailable(
                rows,
                "transition_maturity",
                "Transition maturity and TreeCover",
                record,
                "break_even_updates",
                "updates",
                row.break_even_reason
                    .as_deref()
                    .ok_or(ThesisTableError::MissingSourceRow)?,
                &row.provenance,
                source,
            ),
        }
        match row.logical_treecover_retirement_epoch {
            Some(value) => append_number(
                rows,
                "transition_maturity",
                "Transition maturity and TreeCover",
                record,
                "logical_treecover_retirement_epoch",
                i128::from(value),
                "epoch",
                transition_value_state(&row.provenance, "logical_treecover_retirement_epoch"),
                &row.provenance,
                source,
            ),
            None => append_unavailable(
                rows,
                "transition_maturity",
                "Transition maturity and TreeCover",
                record,
                "logical_treecover_retirement_epoch",
                "epoch",
                &row.treecover_retirement_state,
                &row.provenance,
                source,
            ),
        }
        append_text(
            rows,
            "transition_maturity",
            "Transition maturity and TreeCover",
            record,
            "treecover_retirement_state",
            &row.treecover_retirement_state,
            "text",
            transition_value_state(&row.provenance, "treecover_retirement_state"),
            &row.provenance,
            source,
        );
    }
    Ok(())
}

fn transition_value_state(provenance: &str, field: &str) -> &'static str {
    if provenance.starts_with("educational") {
        return "educational";
    }
    match field {
        "member_count"
        | "transition_bytes"
        | "cumulative_bytes_to_maturity_evaluation"
        | "impactful_updates_until_retirement_condition"
        | "treecover_retirement_state" => "observed",
        _ => "counterfactual",
    }
}

fn append_model_rows(
    rows: &mut Vec<ThesisTableRow>,
    input: &ModelInputManifest,
    source: &str,
) -> Result<(), ThesisTableError> {
    append_number(
        rows,
        "model_errors",
        "Analytical models and errors",
        "primitive_timing",
        "timing_samples",
        i128::from(input.timing_samples),
        "samples",
        "observed",
        "Task66 local timing calibration",
        source,
    );
    append_number(
        rows,
        "model_errors",
        "Analytical models and errors",
        "primitive_timing",
        "mkyber_three_recipient_encapsulation_median",
        i128::try_from(
            input
                .primitive_timing_medians
                .mkyber_three_recipient_encapsulation_nanoseconds,
        )
        .map_err(|_| ThesisTableError::MissingSourceRow)?,
        "nanoseconds",
        "observed",
        "Task66 local timing calibration",
        source,
    );
    append_number(
        rows,
        "model_errors",
        "Analytical models and errors",
        "primitive_timing",
        "deterministic_byte_write_calibration_median",
        i128::try_from(
            input
                .primitive_timing_medians
                .deterministic_byte_write_calibration_nanoseconds,
        )
        .map_err(|_| ThesisTableError::MissingSourceRow)?,
        "nanoseconds",
        "observed",
        "Task66 local timing calibration",
        source,
    );
    append_number(
        rows,
        "model_errors",
        "Analytical models and errors",
        "primitive_timing",
        "deterministic_byte_write_calibration_bytes",
        i128::from(
            input
                .primitive_timing_medians
                .deterministic_byte_write_calibration_bytes,
        ),
        "bytes",
        "observed",
        "Task66 local timing calibration",
        source,
    );
    for row in &input.rows {
        let state = if row.provenance == "educational_codec" {
            "educational"
        } else {
            "modelled"
        };
        append_optional_number(
            rows,
            "model_errors",
            "Analytical models and errors",
            &row.measurement,
            "arity",
            row.arity.map(i128::from),
            "arity",
            state,
            "NoModelArity",
            &row.provenance,
            source,
        );
        append_optional_number(
            rows,
            "model_errors",
            "Analytical models and errors",
            &row.measurement,
            "path_length_or_delivery_count",
            row.path_length_or_delivery_count.map(i128::from),
            "count",
            state,
            "NoPublicPathLength",
            &row.provenance,
            source,
        );
        append_optional_number(
            rows,
            "model_errors",
            "Analytical models and errors",
            &row.measurement,
            "recipient_count",
            row.recipient_count.map(i128::from),
            "recipients",
            state,
            "NoPublicRecipientCount",
            &row.provenance,
            source,
        );
        append_optional_number(
            rows,
            "model_errors",
            "Analytical models and errors",
            &row.measurement,
            "measured_bytes",
            row.measured_bytes.map(i128::from),
            "bytes",
            "observed",
            "NoMeasuredBytes",
            &row.provenance,
            source,
        );
        append_optional_number(
            rows,
            "model_errors",
            "Analytical models and errors",
            &row.measurement,
            "modeled_bytes",
            row.modeled_bytes.map(i128::from),
            "bytes",
            state,
            row.size_unavailable_reason
                .as_deref()
                .unwrap_or("NoByteModel"),
            &row.provenance,
            source,
        );
        append_optional_number(
            rows,
            "model_errors",
            "Analytical models and errors",
            &row.measurement,
            "size_absolute_difference",
            row.size_absolute_difference_bytes.map(i128::from),
            "bytes",
            state,
            row.size_unavailable_reason
                .as_deref()
                .unwrap_or("NoByteModel"),
            &row.provenance,
            source,
        );
        append_optional_number(
            rows,
            "model_errors",
            "Analytical models and errors",
            &row.measurement,
            "error_size_percent_micro",
            optional_u128_to_i128(row.error_size_percent_micro)?,
            "micro-percent",
            state,
            row.size_unavailable_reason
                .as_deref()
                .unwrap_or("NoByteModel"),
            &row.provenance,
            source,
        );
        append_optional_number(
            rows,
            "model_errors",
            "Analytical models and errors",
            &row.measurement,
            "measured_elapsed",
            optional_u128_to_i128(row.measured_elapsed_nanoseconds)?,
            "nanoseconds",
            "observed",
            "NoMeasuredElapsedTime",
            &row.provenance,
            source,
        );
        append_optional_number(
            rows,
            "model_errors",
            "Analytical models and errors",
            &row.measurement,
            "estimated_elapsed",
            optional_u128_to_i128(row.estimated_elapsed_nanoseconds)?,
            "nanoseconds",
            state,
            row.time_unavailable_reason
                .as_deref()
                .unwrap_or("NoTimeModel"),
            &row.provenance,
            source,
        );
        append_optional_number(
            rows,
            "model_errors",
            "Analytical models and errors",
            &row.measurement,
            "time_absolute_difference",
            optional_u128_to_i128(row.time_absolute_difference_nanoseconds)?,
            "nanoseconds",
            state,
            row.time_unavailable_reason
                .as_deref()
                .unwrap_or("NoTimeModel"),
            &row.provenance,
            source,
        );
        append_optional_number(
            rows,
            "model_errors",
            "Analytical models and errors",
            &row.measurement,
            "error_time_percent_micro",
            optional_u128_to_i128(row.error_time_percent_micro)?,
            "micro-percent",
            state,
            row.time_unavailable_reason
                .as_deref()
                .unwrap_or("NoTimeModel"),
            &row.provenance,
            source,
        );
        append_text(
            rows,
            "model_errors",
            "Analytical models and errors",
            &row.measurement,
            "source_task",
            &row.source_task,
            "text",
            state,
            &row.provenance,
            source,
        );
    }
    Ok(())
}

fn optional_u128_to_i128(value: Option<u128>) -> Result<Option<i128>, ThesisTableError> {
    value
        .map(|value| i128::try_from(value).map_err(|_| ThesisTableError::MissingSourceRow))
        .transpose()
}

// The flat parameters keep each source-to-cell mapping readable and auditable.
#[allow(clippy::too_many_arguments)]
fn append_optional_number(
    rows: &mut Vec<ThesisTableRow>,
    table: &'static str,
    table_label: &'static str,
    record: &str,
    field: &str,
    value: Option<i128>,
    unit: &str,
    state: &str,
    unavailable_reason: &str,
    provenance: &str,
    source: &str,
) {
    match value {
        Some(value) => append_number(
            rows,
            table,
            table_label,
            record,
            field,
            value,
            unit,
            state,
            provenance,
            source,
        ),
        None => append_unavailable(
            rows,
            table,
            table_label,
            record,
            field,
            unit,
            unavailable_reason,
            provenance,
            source,
        ),
    }
}

// The flat parameters keep each source-to-cell mapping readable and auditable.
#[allow(clippy::too_many_arguments)]
fn append_number(
    rows: &mut Vec<ThesisTableRow>,
    table: &'static str,
    table_label: &'static str,
    record: &str,
    field: &str,
    value: i128,
    unit: &str,
    state: &str,
    provenance: &str,
    source: &str,
) {
    rows.push(new_row(
        table,
        table_label,
        record,
        field,
        state,
        Some(value),
        None,
        unit,
        None,
        provenance,
        source,
    ));
}

// The flat parameters keep each source-to-cell mapping readable and auditable.
#[allow(clippy::too_many_arguments)]
fn append_text(
    rows: &mut Vec<ThesisTableRow>,
    table: &'static str,
    table_label: &'static str,
    record: &str,
    field: &str,
    value: &str,
    unit: &str,
    state: &str,
    provenance: &str,
    source: &str,
) {
    rows.push(new_row(
        table,
        table_label,
        record,
        field,
        state,
        None,
        Some(value.to_owned()),
        unit,
        None,
        provenance,
        source,
    ));
}

// The flat parameters keep each source-to-cell mapping readable and auditable.
#[allow(clippy::too_many_arguments)]
fn append_unavailable(
    rows: &mut Vec<ThesisTableRow>,
    table: &'static str,
    table_label: &'static str,
    record: &str,
    field: &str,
    unit: &str,
    reason: &str,
    provenance: &str,
    source: &str,
) {
    rows.push(new_row(
        table,
        table_label,
        record,
        field,
        "unavailable",
        None,
        None,
        unit,
        Some(reason.to_owned()),
        provenance,
        source,
    ));
}

// The flat parameters keep each source-to-cell mapping readable and auditable.
#[allow(clippy::too_many_arguments)]
fn new_row(
    table: &'static str,
    table_label: &'static str,
    record: &str,
    field: &str,
    state: &str,
    numeric_value: Option<i128>,
    text_value: Option<String>,
    unit: &str,
    reason: Option<String>,
    provenance: &str,
    source: &str,
) -> ThesisTableRow {
    ThesisTableRow {
        schema_version: THESIS_TABLE_SCHEMA_VERSION,
        table,
        table_label,
        persian_label_key: format!("table_{table}"),
        record_key: record.to_owned(),
        field: field.to_owned(),
        field_label: field.replace('_', " "),
        persian_field_label_key: format!("{table}_{field}"),
        value_state: state.to_owned(),
        numeric_value,
        text_value,
        unit: unit.to_owned(),
        reason,
        provenance: provenance.to_owned(),
        source_artifact: source.to_owned(),
    }
}

fn validate_rows(rows: &[ThesisTableRow]) -> Result<(), ThesisTableError> {
    if rows.is_empty() {
        return Err(ThesisTableError::MissingSourceRow);
    }
    for row in rows {
        if row.table.is_empty()
            || row.field.is_empty()
            || row.persian_label_key.is_empty()
            || row.persian_field_label_key.is_empty()
            || row.provenance.is_empty()
            || row.source_artifact.is_empty()
        {
            return Err(ThesisTableError::IncompleteCell);
        }
        let value_count =
            usize::from(row.numeric_value.is_some()) + usize::from(row.text_value.is_some());
        if row.value_state == "unavailable" {
            if value_count != 0 || row.reason.as_deref().is_none_or(str::is_empty) {
                return Err(ThesisTableError::InvalidAvailability);
            }
        } else if value_count != 1 || row.reason.is_some() {
            return Err(ThesisTableError::InvalidAvailability);
        }
        for value in [
            &row.record_key,
            &row.field,
            &row.provenance,
            &row.source_artifact,
        ] {
            if contains_secret_marker(value) {
                return Err(ThesisTableError::PotentialSecretMaterial);
            }
        }
        if row
            .text_value
            .as_deref()
            .is_some_and(contains_secret_marker)
        {
            return Err(ThesisTableError::PotentialSecretMaterial);
        }
    }
    Ok(())
}

fn contains_secret_marker(value: &str) -> bool {
    let lowered = value.to_ascii_lowercase();
    [
        "private_key",
        "shared_secret",
        "path_secret",
        "aead_key",
        "raw_entropy",
    ]
    .iter()
    .any(|marker| lowered.contains(marker))
}

fn thesis_tables_csv(rows: &[ThesisTableRow]) -> Result<Vec<u8>, ThesisTableError> {
    let mut writer = WriterBuilder::new().has_headers(true).from_writer(vec![]);
    for row in rows {
        writer.serialize(row).map_err(ThesisTableError::CsvWrite)?;
    }
    writer
        .into_inner()
        .map_err(|error| ThesisTableError::CsvWrite(error.into_error().into()))
}

fn thesis_tables_markdown(manifest: &ThesisTableManifest) -> String {
    let mut document = String::new();
    writeln!(document, "# Final thesis-table dataset\n").expect("string write");
    writeln!(document, "Each stable `field` has a separate `persian_field_label_key`; unavailable cells carry a reason rather than a fabricated zero.\n").expect("string write");
    for (table, heading) in [
        ("environment", "Implementation environment"),
        ("mode_comparison", "Three-mode comparison"),
        ("normal_operations", "Normal operations"),
        ("transition_maturity", "Transition maturity and TreeCover"),
        ("model_errors", "Analytical models and percentage errors"),
    ] {
        writeln!(document, "## {heading}\n").expect("string write");
        writeln!(
            document,
            "| Record | Field | Value | Unit | State | Provenance |\n|---|---|---|---|---|---|"
        )
        .expect("string write");
        for row in manifest.rows.iter().filter(|row| row.table == table) {
            let value = row.numeric_value.map_or_else(
                || {
                    row.text_value.clone().unwrap_or_else(|| {
                        row.reason
                            .clone()
                            .unwrap_or_else(|| "Unavailable".to_owned())
                    })
                },
                |value| value.to_string(),
            );
            writeln!(
                document,
                "| {} | {} | {} | {} | {} | {} |",
                row.record_key,
                row.field,
                value.replace('|', "/").replace('\n', " "),
                row.unit,
                row.value_state,
                row.provenance
            )
            .expect("string write");
        }
        writeln!(document).expect("string write");
    }
    document
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation_rejects_blank_unavailable_and_secret_markers() {
        let mut missing_reason = new_row(
            "environment",
            "Environment",
            "record",
            "field",
            "unavailable",
            None,
            None,
            "text",
            None,
            "public",
            "output/source",
        );
        assert!(validate_rows(&[missing_reason.clone()]).is_err());
        missing_reason.reason = Some("Unavailable".to_owned());
        missing_reason.text_value = Some("private_key".to_owned());
        assert!(validate_rows(&[missing_reason]).is_err());
    }

    #[test]
    fn validation_accepts_numeric_zero_as_a_real_value() {
        let row = new_row(
            "normal_operations",
            "Normal",
            "row",
            "mkyber_count",
            "observed",
            Some(0),
            None,
            "ciphertexts",
            None,
            "real_baseline",
            "output/source",
        );
        assert!(validate_rows(&[row]).is_ok());
    }
}
