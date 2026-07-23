#![forbid(unsafe_code)]

//! Minimal Task 64 normal-operation evidence.
//!
//! Binary rows execute the existing real baseline or fork workloads. Arity-4
//! and arity-8 updates use only the small deterministic educational codec in
//! this module; they are not OpenMLS protocol messages or interoperability
//! claims.

use std::{
    fmt::Write as FmtWrite,
    fs,
    path::{Path, PathBuf},
    time::Instant,
};

use csv::WriterBuilder;
use experimental_mls_adapter::{
    execute_experimental_binary_workload, ExperimentalBinaryWorkloadError,
};
use serde::Serialize;
use simulation::{
    execute_baseline_workload, BaselineWorkloadConfig, CommitterStrategy, WorkloadExecutionError,
    WorkloadOperation, WorkloadProfile,
};
use thiserror::Error;

use crate::{
    environment::{current_linux_process_peak_rss_kib, EnvironmentCollectionError},
    generation::{validate_artifact_directory, write_new, ReportArtifactError},
};

/// Version of the Task 64 normal-operation schema.
pub const NORMAL_OPERATION_SCHEMA_VERSION: u16 = 1;
/// Machine-readable normal-operation table name.
pub const NORMAL_OPERATIONS_CSV_FILE_NAME: &str = "normal_operations.csv";
/// Complete machine-readable normal-operation manifest name.
pub const NORMAL_OPERATIONS_JSON_FILE_NAME: &str = "normal_operations.json";
/// Human-readable normal-operation table name.
pub const NORMAL_OPERATIONS_MARKDOWN_FILE_NAME: &str = "normal_operations.md";

/// Public output paths for one Task 64 evidence set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalOperationArtifactPaths {
    /// Long-form thesis-table rows.
    pub normal_operations_csv: PathBuf,
    /// Complete public manifest.
    pub normal_operations_json: PathBuf,
    /// Compact human-readable table.
    pub normal_operations_markdown: PathBuf,
}

/// Errors from minimal normal-operation collection.
#[derive(Debug, Error)]
pub enum NormalOperationError {
    /// At least one repetition is required for a meaningful timing mean.
    #[error("normal-operation repetitions must be positive")]
    ZeroRepetitions,
    /// The real unchanged baseline workload failed.
    #[error("real baseline normal-operation workload failed")]
    Baseline(#[source] WorkloadExecutionError),
    /// The real binary-with-mKyber workload failed.
    #[error("real binary-with-mKyber normal-operation workload failed")]
    Fork(#[source] ExperimentalBinaryWorkloadError),
    /// The requested real operation was not present in its accepted workload.
    #[error("real workload did not produce the required accepted operation")]
    MissingOperation,
    /// A measured structural byte count changed between requested repetitions.
    #[error("measured message bytes changed between repetitions")]
    InconsistentBytes,
    /// A public count or timing mean overflowed.
    #[error("normal-operation public count overflowed")]
    Overflow,
    /// Linux RSS collection failed.
    #[error("normal-operation RSS collection failed")]
    Rss(#[source] EnvironmentCollectionError),
    /// Artifact safe-path/create-new failure.
    #[error("normal-operation artifact output failed")]
    Artifact(#[from] ReportArtifactError),
    /// CSV encoding failure.
    #[error("normal-operation CSV encoding failed")]
    Csv(#[source] csv::Error),
    /// JSON encoding failure.
    #[error("normal-operation JSON encoding failed")]
    Json(#[source] serde_json::Error),
}

#[derive(Clone, Debug, Serialize)]
struct NormalOperationManifest {
    schema_version: u16,
    repetitions: u32,
    rows: Vec<NormalOperationRow>,
    scope_note: &'static str,
}

/// One normal-operation table row with explicit real/educational provenance.
#[derive(Clone, Debug, Serialize)]
pub struct NormalOperationRow {
    /// Stable schema version.
    pub schema_version: u16,
    /// Binary, quaternary, or octal arity.
    pub arity: u8,
    /// `update`, `add`, or `remove`.
    pub operation: &'static str,
    /// `real_baseline`, `real_fork`, or `educational_codec`.
    pub provenance: &'static str,
    /// Actual serialized real Commit size or deterministic educational-codec size.
    pub serialized_message_bytes: u64,
    /// Integer mean over the configured repetitions, rounded down.
    pub mean_elapsed_nanoseconds: u128,
    /// Number of repetitions contributing to this row.
    pub repetitions: u32,
    /// Actual classical HPKE encapsulations, or explicit unavailable state.
    pub classical_encapsulation_count: Option<u32>,
    /// Reason when the classical count is absent.
    pub classical_count_reason: Option<&'static str>,
    /// Actual mKyber common encapsulations; a baseline zero is observed absence.
    pub mkyber_common_encapsulation_count: u32,
    /// Public mKyber recipient-component count.
    pub mkyber_recipient_component_count: u32,
    /// Current process high-water RSS after this row, if Linux exposes it.
    pub process_peak_rss_kib: Option<u64>,
    /// Explicit state for the RSS field.
    pub process_peak_rss_state: &'static str,
    /// Method and limits for byte/count/timing/RSS facts.
    pub measurement_method: &'static str,
}

/// Generates the fixed, minimal Task 64 table and writes create-new artifacts.
pub fn generate_normal_operation_artifacts(
    repetitions: u32,
    output_directory: &Path,
    report_directory: &Path,
) -> Result<NormalOperationArtifactPaths, NormalOperationError> {
    if repetitions == 0 {
        return Err(NormalOperationError::ZeroRepetitions);
    }
    validate_artifact_directory(output_directory, "output", "normal-operation evidence")?;
    validate_artifact_directory(report_directory, "report", "normal-operation table")?;
    let paths = NormalOperationArtifactPaths {
        normal_operations_csv: output_directory.join(NORMAL_OPERATIONS_CSV_FILE_NAME),
        normal_operations_json: output_directory.join(NORMAL_OPERATIONS_JSON_FILE_NAME),
        normal_operations_markdown: report_directory.join(NORMAL_OPERATIONS_MARKDOWN_FILE_NAME),
    };
    for path in [
        &paths.normal_operations_csv,
        &paths.normal_operations_json,
        &paths.normal_operations_markdown,
    ] {
        if path.exists() {
            return Err(NormalOperationError::Artifact(
                ReportArtifactError::ArtifactAlreadyExists,
            ));
        }
    }
    let rows = vec![
        real_baseline_row("update", repetitions)?,
        real_fork_update_row(repetitions)?,
        real_baseline_row("add", repetitions)?,
        real_baseline_row("remove", repetitions)?,
        educational_update_row(4, repetitions)?,
        educational_update_row(8, repetitions)?,
    ];
    let manifest = NormalOperationManifest {
        schema_version: NORMAL_OPERATION_SCHEMA_VERSION,
        repetitions,
        rows,
        scope_note: "Arity-2 baseline and mKyber rows are real in-process MLS/fork workload observations. Arity-4/8 rows are deterministic educational codec observations only; they do not claim a live quaternary/octal MLS implementation. Process RSS is a whole-process VmHWM observation after each row, not a per-operation allocation profile.",
    };
    fs::create_dir_all(output_directory)
        .map_err(|error| NormalOperationError::Artifact(ReportArtifactError::Write(error)))?;
    fs::create_dir_all(report_directory)
        .map_err(|error| NormalOperationError::Artifact(ReportArtifactError::Write(error)))?;
    write_new(
        &paths.normal_operations_csv,
        &normal_operations_csv(&manifest.rows)?,
    )?;
    write_new(
        &paths.normal_operations_json,
        &serde_json::to_vec_pretty(&manifest).map_err(NormalOperationError::Json)?,
    )?;
    write_new(
        &paths.normal_operations_markdown,
        normal_operations_markdown(&manifest).as_bytes(),
    )?;
    Ok(paths)
}

fn real_baseline_row(
    requested_operation: &'static str,
    repetitions: u32,
) -> Result<NormalOperationRow, NormalOperationError> {
    let mut bytes = None;
    let mut elapsed_total = 0_u128;
    for repetition in 1..=repetitions {
        let operation_count = match requested_operation {
            "update" => 1,
            "add" => 2,
            "remove" => 3,
            _ => return Err(NormalOperationError::MissingOperation),
        };
        let execution = execute_baseline_workload(&BaselineWorkloadConfig {
            group_id: format!("task64-baseline-{requested_operation}-{repetition}").into_bytes(),
            initial_member_count: 4,
            maximum_member_count: 5,
            operation_count,
            region_count: 2,
            committer_strategy: CommitterStrategy::RoundRobin,
            workload_profile: if requested_operation == "update" {
                WorkloadProfile::UpdateOnly
            } else {
                WorkloadProfile::Mixed
            },
        })
        .map_err(NormalOperationError::Baseline)?;
        let accepted = execution
            .accepted_operations
            .iter()
            .find(|accepted| operation_name(accepted.operation) == requested_operation)
            .ok_or(NormalOperationError::MissingOperation)?;
        retain_bytes(&mut bytes, accepted.measurement.emitted_commit_bytes)?;
        elapsed_total = elapsed_total
            .checked_add(accepted.measurement.accepted_lifecycle_elapsed_nanoseconds)
            .ok_or(NormalOperationError::Overflow)?;
    }
    let (peak_rss_kib, process_peak_rss_state) = current_rss()?;
    Ok(NormalOperationRow {
        schema_version: NORMAL_OPERATION_SCHEMA_VERSION,
        arity: 2,
        operation: requested_operation,
        provenance: "real_baseline",
        serialized_message_bytes: bytes.ok_or(NormalOperationError::MissingOperation)?,
        mean_elapsed_nanoseconds: elapsed_total / u128::from(repetitions),
        repetitions,
        classical_encapsulation_count: None,
        classical_count_reason: Some("NotInstrumentedInBaselineWorkload"),
        mkyber_common_encapsulation_count: 0,
        mkyber_recipient_component_count: 0,
        process_peak_rss_kib: peak_rss_kib,
        process_peak_rss_state,
        measurement_method: "real unchanged-baseline MLS accepted operation; mKyber count is observed zero because baseline has no mKyber path; classical HPKE count is not instrumented",
    })
}

fn real_fork_update_row(repetitions: u32) -> Result<NormalOperationRow, NormalOperationError> {
    let mut bytes = None;
    let mut elapsed_total = 0_u128;
    let mut classical = None;
    let mut mkyber_common = None;
    let mut mkyber_recipient = None;
    for repetition in 1..=repetitions {
        let execution = execute_experimental_binary_workload(&BaselineWorkloadConfig {
            group_id: format!("task64-fork-update-{repetition}").into_bytes(),
            initial_member_count: 4,
            maximum_member_count: 4,
            operation_count: 1,
            region_count: 2,
            committer_strategy: CommitterStrategy::RoundRobin,
            workload_profile: WorkloadProfile::UpdateOnly,
        })
        .map_err(NormalOperationError::Fork)?;
        let accepted = execution
            .accepted_operations
            .first()
            .ok_or(NormalOperationError::MissingOperation)?;
        retain_bytes(&mut bytes, accepted.measurement.emitted_commit_bytes)?;
        retain_count(
            &mut classical,
            accepted.measurement.classical_hpke_encapsulation_count,
        )?;
        retain_count(
            &mut mkyber_common,
            accepted.measurement.mkyber_common_ciphertext_count,
        )?;
        retain_count(
            &mut mkyber_recipient,
            accepted.measurement.mkyber_recipient_ciphertext_count,
        )?;
        elapsed_total = elapsed_total
            .checked_add(accepted.measurement.accepted_lifecycle_elapsed_nanoseconds)
            .ok_or(NormalOperationError::Overflow)?;
    }
    let (peak_rss_kib, process_peak_rss_state) = current_rss()?;
    Ok(NormalOperationRow {
        schema_version: NORMAL_OPERATION_SCHEMA_VERSION,
        arity: 2,
        operation: "update",
        provenance: "real_fork",
        serialized_message_bytes: bytes.ok_or(NormalOperationError::MissingOperation)?,
        mean_elapsed_nanoseconds: elapsed_total / u128::from(repetitions),
        repetitions,
        classical_encapsulation_count: classical,
        classical_count_reason: None,
        mkyber_common_encapsulation_count: mkyber_common.ok_or(NormalOperationError::MissingOperation)?,
        mkyber_recipient_component_count: mkyber_recipient.ok_or(NormalOperationError::MissingOperation)?,
        process_peak_rss_kib: peak_rss_kib,
        process_peak_rss_state,
        measurement_method: "real fork-native binary hybrid UpdatePath accepted operation with public delivery counts",
    })
}

fn educational_update_row(
    arity: u8,
    repetitions: u32,
) -> Result<NormalOperationRow, NormalOperationError> {
    let mut bytes = None;
    let mut elapsed_total = 0_u128;
    let mut counts = None;
    for _ in 1..=repetitions {
        let started = Instant::now();
        let encoded = educational_update_codec(arity)?;
        let elapsed = started.elapsed().as_nanos();
        retain_bytes(
            &mut bytes,
            u64::try_from(encoded.bytes.len()).map_err(|_| NormalOperationError::Overflow)?,
        )?;
        if let Some(existing) = counts {
            if existing != encoded.counts {
                return Err(NormalOperationError::InconsistentBytes);
            }
        } else {
            counts = Some(encoded.counts);
        }
        elapsed_total = elapsed_total
            .checked_add(elapsed)
            .ok_or(NormalOperationError::Overflow)?;
    }
    let counts = counts.ok_or(NormalOperationError::MissingOperation)?;
    let (peak_rss_kib, process_peak_rss_state) = current_rss()?;
    Ok(NormalOperationRow {
        schema_version: NORMAL_OPERATION_SCHEMA_VERSION,
        arity,
        operation: "update",
        provenance: "educational_codec",
        serialized_message_bytes: bytes.ok_or(NormalOperationError::MissingOperation)?,
        mean_elapsed_nanoseconds: elapsed_total / u128::from(repetitions),
        repetitions,
        classical_encapsulation_count: Some(counts.classical_hpke_encapsulations),
        classical_count_reason: None,
        mkyber_common_encapsulation_count: counts.mkyber_common_encapsulations,
        mkyber_recipient_component_count: counts.mkyber_recipient_components,
        process_peak_rss_kib: peak_rss_kib,
        process_peak_rss_state,
        measurement_method: "deterministic educational tree-route serializer using documented public component lengths; not a live MLS protocol or cryptographic execution",
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct EducationalCodecCounts {
    classical_hpke_encapsulations: u32,
    mkyber_common_encapsulations: u32,
    mkyber_recipient_components: u32,
}

struct EducationalCodecMessage {
    bytes: Vec<u8>,
    counts: EducationalCodecCounts,
}

fn educational_update_codec(arity: u8) -> Result<EducationalCodecMessage, NormalOperationError> {
    let member_count = match arity {
        4 => 16_u32,
        8 => 64_u32,
        _ => return Err(NormalOperationError::MissingOperation),
    };
    let height = 2_u8;
    let deliveries = u32::from(arity - 1)
        .checked_mul(u32::from(height))
        .ok_or(NormalOperationError::Overflow)?;
    let recipients = member_count
        .checked_sub(1)
        .ok_or(NormalOperationError::Overflow)?;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"T64\0");
    bytes.extend_from_slice(&[1, arity, height, 1]);
    bytes.extend_from_slice(&member_count.to_be_bytes());
    bytes.extend_from_slice(&deliveries.to_be_bytes());
    for delivery in 0..deliveries {
        bytes.extend_from_slice(&delivery.to_be_bytes());
        append_deterministic_bytes(&mut bytes, 704, delivery);
    }
    for recipient in 1..=recipients {
        bytes.extend_from_slice(&recipient.to_be_bytes());
        append_deterministic_bytes(&mut bytes, 32, recipient);
        append_deterministic_bytes(&mut bytes, 48, recipient.wrapping_add(deliveries));
    }
    Ok(EducationalCodecMessage {
        bytes,
        counts: EducationalCodecCounts {
            classical_hpke_encapsulations: recipients,
            mkyber_common_encapsulations: deliveries,
            mkyber_recipient_components: recipients,
        },
    })
}

fn append_deterministic_bytes(bytes: &mut Vec<u8>, length: usize, domain: u32) {
    for offset in 0..length {
        let offset = u32::try_from(offset).expect("fixed educational field length fits u32");
        bytes.push(domain.wrapping_add(offset).to_le_bytes()[0]);
    }
}

fn retain_bytes(slot: &mut Option<u64>, value: u64) -> Result<(), NormalOperationError> {
    if let Some(existing) = slot {
        if *existing != value {
            return Err(NormalOperationError::InconsistentBytes);
        }
    } else {
        *slot = Some(value);
    }
    Ok(())
}

fn retain_count(slot: &mut Option<u32>, value: u32) -> Result<(), NormalOperationError> {
    if let Some(existing) = slot {
        if *existing != value {
            return Err(NormalOperationError::InconsistentBytes);
        }
    } else {
        *slot = Some(value);
    }
    Ok(())
}

fn current_rss() -> Result<(Option<u64>, &'static str), NormalOperationError> {
    let value = current_linux_process_peak_rss_kib().map_err(NormalOperationError::Rss)?;
    Ok(match value {
        Some(value) => (Some(value), "observed"),
        None => (None, "unavailable"),
    })
}

fn operation_name(operation: WorkloadOperation) -> &'static str {
    match operation {
        WorkloadOperation::Update => "update",
        WorkloadOperation::Add { .. } => "add",
        WorkloadOperation::Remove { .. } => "remove",
    }
}

fn normal_operations_csv(rows: &[NormalOperationRow]) -> Result<Vec<u8>, NormalOperationError> {
    let mut writer = WriterBuilder::new()
        .has_headers(true)
        .from_writer(Vec::new());
    for row in rows {
        writer.serialize(row).map_err(NormalOperationError::Csv)?;
    }
    writer
        .into_inner()
        .map_err(|error| NormalOperationError::Csv(error.into_error().into()))
}

fn normal_operations_markdown(manifest: &NormalOperationManifest) -> String {
    let mut report = String::new();
    writeln!(report, "# Task 64 Minimal Normal-Operation Table").expect("string write");
    writeln!(report).expect("string write");
    writeln!(report, "Repetitions: {}.", manifest.repetitions).expect("string write");
    writeln!(report).expect("string write");
    writeln!(report, "| Arity | Operation | Provenance | Bytes | Mean ns | Classical encapsulations | mKyber common | mKyber recipient components | Peak RSS KiB |\n|---:|---|---|---:|---:|---:|---:|---:|---:|").expect("string write");
    for row in &manifest.rows {
        let classical = row
            .classical_encapsulation_count
            .map(|value| value.to_string())
            .unwrap_or_else(|| {
                row.classical_count_reason
                    .unwrap_or("Unavailable")
                    .to_owned()
            });
        let rss = row
            .process_peak_rss_kib
            .map(|value| value.to_string())
            .unwrap_or_else(|| row.process_peak_rss_state.to_owned());
        writeln!(
            report,
            "| {} | {} | {} | {} | {} | {} | {} | {} | {} |",
            row.arity,
            row.operation,
            row.provenance,
            row.serialized_message_bytes,
            row.mean_elapsed_nanoseconds,
            classical,
            row.mkyber_common_encapsulation_count,
            row.mkyber_recipient_component_count,
            rss
        )
        .expect("string write");
    }
    writeln!(report).expect("string write");
    writeln!(report, "{ }", manifest.scope_note).expect("string write");
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn educational_codec_has_documented_delivery_counts() {
        let quaternary = educational_update_codec(4).expect("quaternary codec");
        let octal = educational_update_codec(8).expect("octal codec");
        assert_eq!(quaternary.counts.mkyber_common_encapsulations, 6);
        assert_eq!(quaternary.counts.classical_hpke_encapsulations, 15);
        assert_eq!(octal.counts.mkyber_common_encapsulations, 14);
        assert_eq!(octal.counts.classical_hpke_encapsulations, 63);
        assert!(octal.bytes.len() > quaternary.bytes.len());
    }
}
