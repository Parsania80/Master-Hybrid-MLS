#![forbid(unsafe_code)]

//! Minimal Task 66 analytical models and percentage-error artifacts.
//!
//! This is intentionally a small, transparent calculation layer. It models
//! only public fixed-width hybrid fields and the deterministic educational
//! codec. Full real MLS framing or lifecycle time is never guessed when the
//! completed artifacts lack a trustworthy model boundary.

use std::{
    fmt::Write as FmtWrite,
    fs,
    hint::black_box,
    path::{Path, PathBuf},
    time::Instant,
};

use csv::{ReaderBuilder, WriterBuilder};
use mkyber::{
    EducationalMkyber512Reference, MkyberDomain, RecipientId, RecipientPublicKey, RecipientSet,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::generation::{validate_artifact_directory, write_new, ReportArtifactError};

/// Version of the public Task 66 model/error schema.
pub const MODEL_ERROR_SCHEMA_VERSION: u16 = 1;
/// Machine-readable model/error rows.
pub const MODEL_ERRORS_CSV_FILE_NAME: &str = "model_errors.csv";
/// Complete public model/error manifest.
pub const MODEL_ERRORS_JSON_FILE_NAME: &str = "model_errors.json";
/// Human-readable model/error table.
pub const MODEL_ERRORS_MARKDOWN_FILE_NAME: &str = "model_errors.md";

const PERCENT_MICRO_SCALE: u128 = 1_000_000;
const EDUCATIONAL_HEADER_BYTES: u64 = 16;
const EDUCATIONAL_DELIVERY_INDEX_BYTES: u64 = 4;
const EDUCATIONAL_COMMON_BYTES: u64 = 704;
const EDUCATIONAL_RECIPIENT_INDEX_BYTES: u64 = 4;
const CLASSICAL_ENCAPSULATION_BYTES: u64 = 32;
const MKYBER_RECIPIENT_BYTES: u64 = 48;
const ENCRYPTED_PATH_SECRET_BYTES: u64 = 48;
const HYBRID_PATH_HEADER_BYTES: u64 = 744;
const HYBRID_RECIPIENT_RECORD_BYTES: u64 = EDUCATIONAL_RECIPIENT_INDEX_BYTES
    + CLASSICAL_ENCAPSULATION_BYTES
    + MKYBER_RECIPIENT_BYTES
    + ENCRYPTED_PATH_SECRET_BYTES;
const BYTE_WRITE_CALIBRATION_BYTES: usize = 16_384;
const TIMING_DOMAIN: MkyberDomain = MkyberDomain::new([66; 32]);

/// Paths written by one Task 66 invocation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelErrorArtifactPaths {
    /// Long-form model/error rows.
    pub model_errors_csv: PathBuf,
    /// Complete public model/error manifest.
    pub model_errors_json: PathBuf,
    /// Compact human-readable model/error table.
    pub model_errors_markdown: PathBuf,
}

/// Fail-closed errors from model/error generation.
#[derive(Debug, Error)]
pub enum ModelErrorError {
    /// At least one calibration sample is necessary for a median.
    #[error("timing sample count must be positive")]
    ZeroTimingSamples,
    /// A supplied public Task 64 CSV could not be read.
    #[error("Task 64 normal-operation CSV could not be read")]
    ReadNormal(#[source] std::io::Error),
    /// A supplied public Task 64 CSV was malformed.
    #[error("Task 64 normal-operation CSV was malformed")]
    NormalCsv(#[source] csv::Error),
    /// A required public Task 64 row was absent.
    #[error("Task 64 normal-operation CSV did not contain the required row")]
    MissingNormalRow,
    /// A supplied public Task 65 manifest could not be read.
    #[error("Task 65 transition-maturity manifest could not be read")]
    ReadTransition(#[source] std::io::Error),
    /// A supplied public Task 65 manifest was malformed.
    #[error("Task 65 transition-maturity manifest was malformed")]
    TransitionJson(#[source] serde_json::Error),
    /// A required public Task 65 row was absent.
    #[error("Task 65 transition-maturity manifest did not contain the required row")]
    MissingTransitionRow,
    /// A supplied public Task 63 environment record could not be read.
    #[error("Task 63 environment record could not be read")]
    ReadEnvironment(#[source] std::io::Error),
    /// A supplied public Task 63 environment record was malformed.
    #[error("Task 63 environment record was malformed")]
    EnvironmentJson(#[source] serde_json::Error),
    /// Educational mKyber calibration failed.
    #[error("mKyber timing calibration failed")]
    Mkyber(#[from] mkyber::MkyberError),
    /// A checked model calculation overflowed.
    #[error("Task 66 model calculation overflowed")]
    Overflow,
    /// A percentage error cannot divide by a zero measured value.
    #[error("percentage error has a zero measured denominator")]
    ZeroMeasuredDenominator,
    /// Artifact safe-path/create-new failure.
    #[error("Task 66 artifact output failed")]
    Artifact(#[from] ReportArtifactError),
    /// CSV encoding failed.
    #[error("Task 66 CSV encoding failed")]
    CsvWrite(#[source] csv::Error),
    /// JSON encoding failed.
    #[error("Task 66 JSON encoding failed")]
    JsonWrite(#[source] serde_json::Error),
}

#[derive(Clone, Debug, Deserialize)]
struct NormalOperationInputRow {
    arity: u8,
    operation: String,
    provenance: String,
    serialized_message_bytes: u64,
    mean_elapsed_nanoseconds: u128,
    mkyber_common_encapsulation_count: u32,
    mkyber_recipient_component_count: u32,
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
    c_new_bytes: u64,
}

#[derive(Clone, Debug, Deserialize)]
struct EnvironmentInput {
    run_label: String,
    rust_version_verbose: String,
    cpu_model: String,
}

struct ModeledRowInput {
    source_task: &'static str,
    measurement: &'static str,
    provenance: String,
    arity: Option<u8>,
    path_length_or_delivery_count: Option<u32>,
    recipient_count: Option<u32>,
    measured_bytes: u64,
    modeled_bytes: u64,
    measured_elapsed_nanoseconds: Option<u128>,
    estimated_elapsed_nanoseconds: Option<u128>,
    byte_formula: &'static str,
    time_formula: &'static str,
}

#[derive(Clone, Debug, Serialize)]
struct ModelErrorManifest {
    schema_version: u16,
    environment_json_path: String,
    environment_run_label: String,
    environment_rust_release: String,
    environment_cpu_model: String,
    normal_operations_csv_path: String,
    transition_maturity_json_path: String,
    timing_samples: u32,
    primitive_timing_medians: PrimitiveTimingMedians,
    rows: Vec<ModelErrorRow>,
    scope_note: &'static str,
}

/// Public median primitive timings used only by the stated simple formulas.
#[derive(Clone, Debug, Serialize)]
pub struct PrimitiveTimingMedians {
    /// Median time for one educational mKyber encapsulation to three recipients.
    pub mkyber_three_recipient_encapsulation_nanoseconds: u128,
    /// Median time to deterministically produce the fixed byte-calibration buffer.
    pub deterministic_byte_write_calibration_nanoseconds: u128,
    /// Number of bytes in each byte-write calibration sample.
    pub deterministic_byte_write_calibration_bytes: u64,
    /// Scope of the local timing values.
    pub timing_scope: &'static str,
}

/// One byte/time model row. Missing modeled values always have an explicit reason.
#[derive(Clone, Debug, Serialize)]
pub struct ModelErrorRow {
    /// Stable schema version.
    pub schema_version: u16,
    /// Evidence task supplying the measured input.
    pub source_task: &'static str,
    /// Stable row identity.
    pub measurement: &'static str,
    /// Real, educational, or counterfactual provenance.
    pub provenance: String,
    /// Tree arity represented by this formula when applicable.
    pub arity: Option<u8>,
    /// Public path height/delivery count used by this model.
    pub path_length_or_delivery_count: Option<u32>,
    /// Public recipient count used by this model.
    pub recipient_count: Option<u32>,
    /// Observed or exact-counterfactual byte value.
    pub measured_bytes: Option<u64>,
    /// Formula result for bytes.
    pub modeled_bytes: Option<u64>,
    /// `abs(B_measured - B_model)`.
    pub size_absolute_difference_bytes: Option<u64>,
    /// `Error_size` in percent scaled by 1,000,000.
    pub error_size_percent_micro: Option<u128>,
    /// Exact reason when a byte model cannot be made honestly.
    pub size_unavailable_reason: Option<&'static str>,
    /// Observed elapsed time, when the source supplied one.
    pub measured_elapsed_nanoseconds: Option<u128>,
    /// Formula result for elapsed time.
    pub estimated_elapsed_nanoseconds: Option<u128>,
    /// `abs(T_measured - T_estimated)`.
    pub time_absolute_difference_nanoseconds: Option<u128>,
    /// `Error_time` in percent scaled by 1,000,000.
    pub error_time_percent_micro: Option<u128>,
    /// Exact reason when a time model cannot be made honestly.
    pub time_unavailable_reason: Option<&'static str>,
    /// Direct formula and required assumptions.
    pub byte_formula: &'static str,
    /// Direct formula and required assumptions.
    pub time_formula: &'static str,
}

/// Generates create-new Task 66 artifacts from completed public evidence.
pub fn generate_model_error_artifacts(
    environment_json: &Path,
    normal_operations_csv: &Path,
    transition_maturity_json: &Path,
    timing_samples: u32,
    output_directory: &Path,
    report_directory: &Path,
) -> Result<ModelErrorArtifactPaths, ModelErrorError> {
    if timing_samples == 0 {
        return Err(ModelErrorError::ZeroTimingSamples);
    }
    validate_artifact_directory(output_directory, "output", "model/error evidence")?;
    validate_artifact_directory(report_directory, "report", "model/error table")?;
    let paths = ModelErrorArtifactPaths {
        model_errors_csv: output_directory.join(MODEL_ERRORS_CSV_FILE_NAME),
        model_errors_json: output_directory.join(MODEL_ERRORS_JSON_FILE_NAME),
        model_errors_markdown: report_directory.join(MODEL_ERRORS_MARKDOWN_FILE_NAME),
    };
    for path in [
        &paths.model_errors_csv,
        &paths.model_errors_json,
        &paths.model_errors_markdown,
    ] {
        if path.exists() {
            return Err(ModelErrorError::Artifact(
                ReportArtifactError::ArtifactAlreadyExists,
            ));
        }
    }

    let environment = read_environment(environment_json)?;
    let normal_rows = read_normal_rows(normal_operations_csv)?;
    let transition_rows = read_transition_rows(transition_maturity_json)?;
    let timing = primitive_timing_medians(timing_samples)?;
    let baseline_update = normal_row(&normal_rows, 2, "update", "real_baseline")?;
    let fork_update = normal_row(&normal_rows, 2, "update", "real_fork")?;
    let quaternary = normal_row(&normal_rows, 4, "update", "educational_codec")?;
    let octal = normal_row(&normal_rows, 8, "update", "educational_codec")?;
    let two_to_four = transition_row(&transition_rows, "2-to-4")?;
    let four_to_eight = transition_row(&transition_rows, "4-to-8")?;
    let rows = vec![
        unavailable_real_baseline_row(baseline_update),
        fork_update_row(baseline_update, fork_update, &timing)?,
        educational_update_row(quaternary, &timing)?,
        educational_update_row(octal, &timing)?,
        real_transition_row(two_to_four),
        educational_transition_component_row(four_to_eight)?,
    ];
    let manifest = ModelErrorManifest {
        schema_version: MODEL_ERROR_SCHEMA_VERSION,
        environment_json_path: environment_json.display().to_string(),
        environment_run_label: environment.run_label,
        environment_rust_release: environment
            .rust_version_verbose
            .lines()
            .next()
            .unwrap_or("unknown")
            .to_owned(),
        environment_cpu_model: environment.cpu_model,
        normal_operations_csv_path: normal_operations_csv.display().to_string(),
        transition_maturity_json_path: transition_maturity_json.display().to_string(),
        timing_samples,
        primitive_timing_medians: timing,
        rows,
        scope_note: "Task 66 is a minimal analytical aid, not a predictor of full MLS behavior. Byte models count only explicitly documented fixed-width fields. Timing models use local median primitive observations and intentionally remain unavailable for full real MLS rows lacking a faithful public decomposition. Percent fields are integer micro-percent: divide by 1,000,000 for percent.",
    };
    fs::create_dir_all(output_directory)
        .map_err(|error| ModelErrorError::Artifact(ReportArtifactError::Write(error)))?;
    fs::create_dir_all(report_directory)
        .map_err(|error| ModelErrorError::Artifact(ReportArtifactError::Write(error)))?;
    write_new(&paths.model_errors_csv, &model_errors_csv(&manifest.rows)?)?;
    write_new(
        &paths.model_errors_json,
        &serde_json::to_vec_pretty(&manifest).map_err(ModelErrorError::JsonWrite)?,
    )?;
    write_new(
        &paths.model_errors_markdown,
        model_errors_markdown(&manifest).as_bytes(),
    )?;
    Ok(paths)
}

fn read_normal_rows(path: &Path) -> Result<Vec<NormalOperationInputRow>, ModelErrorError> {
    let file = fs::File::open(path).map_err(ModelErrorError::ReadNormal)?;
    let mut reader = ReaderBuilder::new().from_reader(file);
    reader
        .deserialize()
        .collect::<Result<Vec<_>, _>>()
        .map_err(ModelErrorError::NormalCsv)
}

fn read_environment(path: &Path) -> Result<EnvironmentInput, ModelErrorError> {
    let bytes = fs::read(path).map_err(ModelErrorError::ReadEnvironment)?;
    serde_json::from_slice(&bytes).map_err(ModelErrorError::EnvironmentJson)
}

fn read_transition_rows(path: &Path) -> Result<Vec<TransitionInputRow>, ModelErrorError> {
    let bytes = fs::read(path).map_err(ModelErrorError::ReadTransition)?;
    Ok(serde_json::from_slice::<TransitionInputManifest>(&bytes)
        .map_err(ModelErrorError::TransitionJson)?
        .rows)
}

fn normal_row<'a>(
    rows: &'a [NormalOperationInputRow],
    arity: u8,
    operation: &str,
    provenance: &str,
) -> Result<&'a NormalOperationInputRow, ModelErrorError> {
    rows.iter()
        .find(|row| {
            row.arity == arity && row.operation == operation && row.provenance == provenance
        })
        .ok_or(ModelErrorError::MissingNormalRow)
}

fn transition_row<'a>(
    rows: &'a [TransitionInputRow],
    transition: &str,
) -> Result<&'a TransitionInputRow, ModelErrorError> {
    rows.iter()
        .find(|row| row.transition == transition)
        .ok_or(ModelErrorError::MissingTransitionRow)
}

fn primitive_timing_medians(samples: u32) -> Result<PrimitiveTimingMedians, ModelErrorError> {
    let backend = EducationalMkyber512Reference;
    let recipients = RecipientSet::new(
        TIMING_DOMAIN,
        (1..=3_u32)
            .map(|index| {
                let pair = backend.keygen_with_os_rng(TIMING_DOMAIN)?;
                Ok(RecipientPublicKey {
                    recipient: RecipientId::new(index),
                    key: pair.public_key().clone(),
                })
            })
            .collect::<Result<Vec<_>, mkyber::MkyberError>>()?,
    )?;
    let mkyber = median_duration(samples, || {
        backend.encapsulate_with_os_rng(&recipients).map(|value| {
            black_box(value);
        })
    })?;
    let byte_write = median_duration(samples, || {
        black_box(deterministic_byte_work(BYTE_WRITE_CALIBRATION_BYTES));
        Ok(())
    })?;
    Ok(PrimitiveTimingMedians {
        mkyber_three_recipient_encapsulation_nanoseconds: mkyber,
        deterministic_byte_write_calibration_nanoseconds: byte_write,
        deterministic_byte_write_calibration_bytes: u64::try_from(BYTE_WRITE_CALIBRATION_BYTES)
            .map_err(|_| ModelErrorError::Overflow)?,
        timing_scope: "release-build Instant elapsed median over local primitive samples; environment-dependent, not a CPU benchmark",
    })
}

fn median_duration(
    samples: u32,
    mut operation: impl FnMut() -> Result<(), mkyber::MkyberError>,
) -> Result<u128, ModelErrorError> {
    let mut values =
        Vec::with_capacity(usize::try_from(samples).map_err(|_| ModelErrorError::Overflow)?);
    for _ in 0..samples {
        let started = Instant::now();
        operation()?;
        values.push(started.elapsed().as_nanos());
    }
    values.sort_unstable();
    values
        .get(values.len() / 2)
        .copied()
        .filter(|value| *value > 0)
        .ok_or(ModelErrorError::Overflow)
}

fn deterministic_byte_work(length: usize) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(length);
    for offset in 0..length {
        let offset = u32::try_from(offset).expect("fixed calibration length fits u32");
        bytes.push(offset.to_le_bytes()[0]);
    }
    bytes
}

fn unavailable_real_baseline_row(row: &NormalOperationInputRow) -> ModelErrorRow {
    ModelErrorRow {
        schema_version: MODEL_ERROR_SCHEMA_VERSION,
        source_task: "Task64",
        measurement: "arity2_real_baseline_update",
        provenance: row.provenance.clone(),
        arity: Some(2),
        path_length_or_delivery_count: None,
        recipient_count: None,
        measured_bytes: Some(row.serialized_message_bytes),
        modeled_bytes: None,
        size_absolute_difference_bytes: None,
        error_size_percent_micro: None,
        size_unavailable_reason: Some("NoPublicFullRfcMlsFramingModel"),
        measured_elapsed_nanoseconds: Some(row.mean_elapsed_nanoseconds),
        estimated_elapsed_nanoseconds: None,
        time_absolute_difference_nanoseconds: None,
        error_time_percent_micro: None,
        time_unavailable_reason: Some("NoComparablePrimitiveTimingDecomposition"),
        byte_formula:
            "Unavailable: completed evidence has no public full RFC MLS framing decomposition",
        time_formula:
            "Unavailable: full accepted MLS lifecycle has no comparable primitive decomposition",
    }
}

fn fork_update_row(
    baseline: &NormalOperationInputRow,
    fork: &NormalOperationInputRow,
    timing: &PrimitiveTimingMedians,
) -> Result<ModelErrorRow, ModelErrorError> {
    let common = u64::from(fork.mkyber_common_encapsulation_count);
    let recipients = u64::from(fork.mkyber_recipient_component_count);
    let modeled_bytes = baseline
        .serialized_message_bytes
        .checked_add(
            common
                .checked_mul(EDUCATIONAL_COMMON_BYTES)
                .ok_or(ModelErrorError::Overflow)?,
        )
        .and_then(|value| {
            value.checked_add(recipients.checked_mul(
                CLASSICAL_ENCAPSULATION_BYTES
                    + MKYBER_RECIPIENT_BYTES
                    + ENCRYPTED_PATH_SECRET_BYTES,
            )?)
        })
        .ok_or(ModelErrorError::Overflow)?;
    let estimated_time = baseline
        .mean_elapsed_nanoseconds
        .checked_add(
            u128::from(common)
                .checked_mul(timing.mkyber_three_recipient_encapsulation_nanoseconds)
                .ok_or(ModelErrorError::Overflow)?,
        )
        .ok_or(ModelErrorError::Overflow)?;
    modeled_row(ModeledRowInput {
        source_task: "Task64",
        measurement: "arity2_real_fork_update",
        provenance: fork.provenance.clone(),
        arity: Some(2),
        path_length_or_delivery_count: Some(fork.mkyber_common_encapsulation_count),
        recipient_count: Some(fork.mkyber_recipient_component_count),
        measured_bytes: fork.serialized_message_bytes,
        modeled_bytes,
        measured_elapsed_nanoseconds: Some(fork.mean_elapsed_nanoseconds),
        estimated_elapsed_nanoseconds: Some(estimated_time),
        byte_formula: "B_model = B_baseline + common_count*704 + recipient_count*(32 + 48 + 48); it intentionally excludes unmodeled replacement/framing fields",
        time_formula: "T_estimated = T_baseline + common_count*median(mKyber encapsulation to 3 recipients); public counts do not expose per-path recipient partitioning",
    })
}

fn educational_update_row(
    row: &NormalOperationInputRow,
    timing: &PrimitiveTimingMedians,
) -> Result<ModelErrorRow, ModelErrorError> {
    let arity = u64::from(row.arity);
    let delivery_count = arity
        .checked_sub(1)
        .and_then(|value| value.checked_mul(2))
        .ok_or(ModelErrorError::Overflow)?;
    let recipient_count = arity
        .checked_mul(arity)
        .and_then(|value| value.checked_sub(1))
        .ok_or(ModelErrorError::Overflow)?;
    let modeled_bytes = educational_codec_bytes(delivery_count, recipient_count)?;
    let estimated_time = proportional_byte_time(modeled_bytes, timing)?;
    modeled_row(ModeledRowInput {
        source_task: "Task64",
        measurement: if row.arity == 4 {
            "arity4_educational_update"
        } else {
            "arity8_educational_update"
        },
        provenance: row.provenance.clone(),
        arity: Some(row.arity),
        path_length_or_delivery_count: Some(
            u32::try_from(delivery_count).map_err(|_| ModelErrorError::Overflow)?,
        ),
        recipient_count: Some(
            u32::try_from(recipient_count).map_err(|_| ModelErrorError::Overflow)?,
        ),
        measured_bytes: row.serialized_message_bytes,
        modeled_bytes,
        measured_elapsed_nanoseconds: Some(row.mean_elapsed_nanoseconds),
        estimated_elapsed_nanoseconds: Some(estimated_time),
        byte_formula: "B_model = 16 + deliveries*(4 + 704) + recipients*(4 + 32 + 48), where deliveries=(arity-1)*height and height=2",
        time_formula: "T_estimated = B_model*median(deterministic byte-write calibration)/16,384; it models only educational byte production",
    })
}

fn real_transition_row(row: &TransitionInputRow) -> ModelErrorRow {
    ModelErrorRow {
        schema_version: MODEL_ERROR_SCHEMA_VERSION,
        source_task: "Task65",
        measurement: "real_2to4_transition_commit",
        provenance: row.provenance.clone(),
        arity: Some(4),
        path_length_or_delivery_count: None,
        recipient_count: Some(row.member_count),
        measured_bytes: Some(row.transition_bytes),
        modeled_bytes: None,
        size_absolute_difference_bytes: None,
        error_size_percent_micro: None,
        size_unavailable_reason: Some("NoPublicFullTransitionCommitFramingModel"),
        measured_elapsed_nanoseconds: None,
        estimated_elapsed_nanoseconds: None,
        time_absolute_difference_nanoseconds: None,
        error_time_percent_micro: None,
        time_unavailable_reason: Some("NoTransitionElapsedMeasurementInTask65"),
        byte_formula: "Unavailable: Task 65 records a real authenticated Commit but no complete public transition-framing model",
        time_formula: "Unavailable: Task 65 has no transition elapsed-time observation",
    }
}

fn educational_transition_component_row(
    row: &TransitionInputRow,
) -> Result<ModelErrorRow, ModelErrorError> {
    let (delivery_count, recipients_per_target) = match row.transition.as_str() {
        "4-to-8" => (8_u64, 8_u64),
        _ => return Err(ModelErrorError::MissingTransitionRow),
    };
    if row.c_new_bytes != row.transition_bytes {
        return Err(ModelErrorError::MissingTransitionRow);
    }
    let modeled_bytes = hybrid_delivery_bytes(delivery_count, recipients_per_target)?;
    modeled_row(ModeledRowInput {
        source_task: "Task65",
        measurement: "educational_4to8_transition_delivery_component",
        provenance: row.provenance.clone(),
        arity: Some(8),
        path_length_or_delivery_count: Some(
            u32::try_from(delivery_count).map_err(|_| ModelErrorError::Overflow)?,
        ),
        recipient_count: Some(
            u32::try_from(recipients_per_target).map_err(|_| ModelErrorError::Overflow)?,
        ),
        measured_bytes: row.transition_bytes,
        modeled_bytes,
        measured_elapsed_nanoseconds: None,
        estimated_elapsed_nanoseconds: None,
        byte_formula: "B_model = delivery_targets*(744 + recipients_per_target*(4 + 32 + 48 + 48)); exact canonical hybrid delivery-component field count",
        time_formula: "Unavailable: this is a Task 65 counterfactual delivery component, not an elapsed protocol operation",
    })
}

fn modeled_row(input: ModeledRowInput) -> Result<ModelErrorRow, ModelErrorError> {
    let (size_absolute_difference_bytes, error_size_percent_micro) = error_values(
        u128::from(input.measured_bytes),
        u128::from(input.modeled_bytes),
    )?;
    let (time_absolute_difference_nanoseconds, error_time_percent_micro, time_unavailable_reason) =
        match (
            input.measured_elapsed_nanoseconds,
            input.estimated_elapsed_nanoseconds,
        ) {
            (Some(measured), Some(estimated)) => {
                let (difference, percent) = error_values(measured, estimated)?;
                (Some(difference), Some(percent), None)
            }
            _ => (None, None, Some("NoComparableElapsedMeasurement")),
        };
    Ok(ModelErrorRow {
        schema_version: MODEL_ERROR_SCHEMA_VERSION,
        source_task: input.source_task,
        measurement: input.measurement,
        provenance: input.provenance,
        arity: input.arity,
        path_length_or_delivery_count: input.path_length_or_delivery_count,
        recipient_count: input.recipient_count,
        measured_bytes: Some(input.measured_bytes),
        modeled_bytes: Some(input.modeled_bytes),
        size_absolute_difference_bytes: Some(
            u64::try_from(size_absolute_difference_bytes).map_err(|_| ModelErrorError::Overflow)?,
        ),
        error_size_percent_micro: Some(error_size_percent_micro),
        size_unavailable_reason: None,
        measured_elapsed_nanoseconds: input.measured_elapsed_nanoseconds,
        estimated_elapsed_nanoseconds: input.estimated_elapsed_nanoseconds,
        time_absolute_difference_nanoseconds,
        error_time_percent_micro,
        time_unavailable_reason,
        byte_formula: input.byte_formula,
        time_formula: input.time_formula,
    })
}

fn educational_codec_bytes(
    delivery_count: u64,
    recipient_count: u64,
) -> Result<u64, ModelErrorError> {
    EDUCATIONAL_HEADER_BYTES
        .checked_add(
            delivery_count
                .checked_mul(EDUCATIONAL_DELIVERY_INDEX_BYTES + EDUCATIONAL_COMMON_BYTES)
                .ok_or(ModelErrorError::Overflow)?,
        )
        .and_then(|value| {
            value.checked_add(recipient_count.checked_mul(
                EDUCATIONAL_RECIPIENT_INDEX_BYTES
                    + CLASSICAL_ENCAPSULATION_BYTES
                    + MKYBER_RECIPIENT_BYTES,
            )?)
        })
        .ok_or(ModelErrorError::Overflow)
}

fn hybrid_delivery_bytes(
    delivery_count: u64,
    recipients_per_target: u64,
) -> Result<u64, ModelErrorError> {
    delivery_count
        .checked_mul(
            HYBRID_PATH_HEADER_BYTES
                .checked_add(
                    recipients_per_target
                        .checked_mul(HYBRID_RECIPIENT_RECORD_BYTES)
                        .ok_or(ModelErrorError::Overflow)?,
                )
                .ok_or(ModelErrorError::Overflow)?,
        )
        .ok_or(ModelErrorError::Overflow)
}

fn proportional_byte_time(
    modeled_bytes: u64,
    timing: &PrimitiveTimingMedians,
) -> Result<u128, ModelErrorError> {
    u128::from(modeled_bytes)
        .checked_mul(timing.deterministic_byte_write_calibration_nanoseconds)
        .and_then(|value| {
            value.checked_div(u128::from(
                timing.deterministic_byte_write_calibration_bytes,
            ))
        })
        .filter(|value| *value > 0)
        .ok_or(ModelErrorError::Overflow)
}

fn error_values(measured: u128, modeled: u128) -> Result<(u128, u128), ModelErrorError> {
    if measured == 0 {
        return Err(ModelErrorError::ZeroMeasuredDenominator);
    }
    let difference = measured.abs_diff(modeled);
    let percent = difference
        .checked_mul(100)
        .and_then(|value| value.checked_mul(PERCENT_MICRO_SCALE))
        .and_then(|value| value.checked_div(measured))
        .ok_or(ModelErrorError::Overflow)?;
    Ok((difference, percent))
}

fn model_errors_csv(rows: &[ModelErrorRow]) -> Result<Vec<u8>, ModelErrorError> {
    let mut writer = WriterBuilder::new().has_headers(true).from_writer(vec![]);
    for row in rows {
        writer.serialize(row).map_err(ModelErrorError::CsvWrite)?;
    }
    writer
        .into_inner()
        .map_err(|error| ModelErrorError::CsvWrite(error.into_error().into()))
}

fn percent_text(value: Option<u128>) -> String {
    value.map_or_else(
        || "Unavailable".to_owned(),
        |micro| {
            format!(
                "{}.{:06}%",
                micro / PERCENT_MICRO_SCALE,
                micro % PERCENT_MICRO_SCALE
            )
        },
    )
}

fn model_errors_markdown(manifest: &ModelErrorManifest) -> String {
    let mut document = String::new();
    writeln!(
        document,
        "# Task 66 minimal analytical models and percentage errors\n"
    )
    .expect("string write");
    writeln!(
        document,
        "Environment reference: `{}` ({}, {}).\n",
        manifest.environment_json_path,
        manifest.environment_rust_release,
        manifest.environment_cpu_model
    )
    .expect("string write");
    writeln!(document, "| Measurement | Provenance | Measured B | B_model | Error_size | Measured T ns | T_estimated ns | Error_time |\n|---|---|---:|---:|---:|---:|---:|---:|").expect("string write");
    for row in &manifest.rows {
        writeln!(
            document,
            "| {} | {} | {} | {} | {} | {} | {} | {} |",
            row.measurement,
            row.provenance,
            optional_text(row.measured_bytes),
            optional_text(row.modeled_bytes),
            percent_text(row.error_size_percent_micro),
            optional_text(row.measured_elapsed_nanoseconds),
            optional_text(row.estimated_elapsed_nanoseconds),
            percent_text(row.error_time_percent_micro),
        )
        .expect("string write");
    }
    writeln!(document, "\n## Formulas and limits\n").expect("string write");
    writeln!(document, "`Error_size = abs(B_measured - B_model) / B_measured * 100`; `Error_time = abs(T_measured - T_estimated) / T_measured * 100`. CSV/JSON encode each percentage as integer micro-percent, so `1_000_000 = 1%`.\n").expect("string write");
    writeln!(document, "Primitive medians ({} samples): mKyber three-recipient encapsulation = {} ns; deterministic 16,384-byte write = {} ns. They are local release-build observations, not CPU benchmarks.\n", manifest.timing_samples, manifest.primitive_timing_medians.mkyber_three_recipient_encapsulation_nanoseconds, manifest.primitive_timing_medians.deterministic_byte_write_calibration_nanoseconds).expect("string write");
    for row in &manifest.rows {
        writeln!(
            document,
            "- `{}` byte model: {}",
            row.measurement, row.byte_formula
        )
        .expect("string write");
        writeln!(document, "  Time model: {}", row.time_formula).expect("string write");
        if let Some(reason) = row.size_unavailable_reason {
            writeln!(document, "  Byte result unavailable: {reason}.").expect("string write");
        }
        if let Some(reason) = row.time_unavailable_reason {
            writeln!(document, "  Time result unavailable: {reason}.").expect("string write");
        }
    }
    document
}

fn optional_text(value: Option<impl ToString>) -> String {
    value.map_or_else(|| "Unavailable".to_owned(), |value| value.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn educational_byte_models_match_task64_serializer_shapes() {
        assert_eq!(educational_codec_bytes(6, 15).expect("arity four"), 5_524);
        assert_eq!(
            educational_codec_bytes(14, 63).expect("arity eight"),
            15_220
        );
    }

    #[test]
    fn hybrid_component_model_matches_task65_octal_delivery() {
        assert_eq!(
            hybrid_delivery_bytes(8, 8).expect("octal component"),
            14_400
        );
    }

    #[test]
    fn percentage_is_exact_micro_percent_and_rejects_zero_denominator() {
        assert_eq!(error_values(4, 3).expect("defined"), (1, 25_000_000));
        assert!(error_values(0, 1).is_err());
    }
}
