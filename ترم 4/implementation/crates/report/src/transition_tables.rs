#![forbid(unsafe_code)]

//! Minimal Task 65 transition-maturity evidence.
//!
//! The 2-to-4 row reuses public bytes emitted by the real Task 61 workload.
//! Its four delivery costs are a deterministic canonical-codec replay, not
//! additional wire observations. The 4-to-8 row is entirely educational: the
//! project has no live octal MLS transition or authenticated retirement Commit.

use std::{
    fmt::Write as FmtWrite,
    fs,
    path::{Path, PathBuf},
};

use csv::WriterBuilder;
use hybrid_path_secret::{
    HybridPathCiphertext, HybridRecipientCiphertext, PathNodeIndex, RecipientNodeIndex,
    CLASSICAL_ENCAPSULATION_BYTES, ENCRYPTED_PATH_SECRET_BYTES,
};
use metrics::{
    evaluate_treecover_retirement, CounterfactualDeliveryInput, DeliveryCostAvailability,
    MaturityCostEvaluation, RecipientTargetSet, RecipientTargetSetCostMeasurement,
    TargetSetMaturity, TargetSetMaturityScore, TreeCoverRetirementDecision,
    TreeCoverRetirementThresholds,
};
use mkyber::{
    MkyberCommonCiphertext, MkyberDomain, MkyberRecipientCiphertext, COMMON_CIPHERTEXT_BYTES,
    RECIPIENT_CIPHERTEXT_BYTES,
};
use serde::Serialize;
use thiserror::Error;

use crate::generation::{validate_artifact_directory, write_new, ReportArtifactError};

/// Version of the public Task 65 transition-table schema.
pub const TRANSITION_TABLE_SCHEMA_VERSION: u16 = 1;
/// Machine-readable long-form table name.
pub const TRANSITION_MATURITY_CSV_FILE_NAME: &str = "transition_maturity.csv";
/// Complete public manifest name.
pub const TRANSITION_MATURITY_JSON_FILE_NAME: &str = "transition_maturity.json";
/// Human-readable table name.
pub const TRANSITION_MATURITY_MARKDOWN_FILE_NAME: &str = "transition_maturity.md";

const DOMAIN: MkyberDomain = MkyberDomain::new([65; 32]);

/// Public locations for one Task 65 evidence set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransitionTableArtifactPaths {
    /// Long-form machine-readable rows.
    pub transition_maturity_csv: PathBuf,
    /// Complete public manifest.
    pub transition_maturity_json: PathBuf,
    /// Compact human-readable table.
    pub transition_maturity_markdown: PathBuf,
}

/// Errors from Task 65 generation.
#[derive(Debug, Error)]
pub enum TransitionTableError {
    /// The supplied public Task 61 summary could not be read.
    #[error("Task 61 public summary could not be read")]
    ReadSummary(#[source] std::io::Error),
    /// The supplied summary was not valid JSON.
    #[error("Task 61 public summary was not valid JSON")]
    SummaryJson(#[source] serde_json::Error),
    /// The required public transition facts were absent or inconsistent.
    #[error("Task 61 public summary did not contain the required transition facts")]
    MissingTransitionFacts,
    /// A checked byte calculation overflowed.
    #[error("Task 65 public byte calculation overflowed")]
    Overflow,
    /// The canonical hybrid codec or existing maturity formula rejected replay input.
    #[error("Task 65 canonical-codec maturity replay failed")]
    Metrics(#[from] metrics::MeasurementError),
    /// Artifact safe-path/create-new failure.
    #[error("Task 65 artifact output failed")]
    Artifact(#[from] ReportArtifactError),
    /// CSV encoding failed.
    #[error("Task 65 CSV encoding failed")]
    Csv(#[source] csv::Error),
    /// JSON encoding failed.
    #[error("Task 65 JSON encoding failed")]
    Json(#[source] serde_json::Error),
}

#[derive(Clone, Debug, Serialize)]
struct TransitionTableManifest {
    schema_version: u16,
    task61_summary_path: String,
    rows: Vec<TransitionMaturityRow>,
    scope_note: &'static str,
}

/// One transition/maturity/TreeCover row. Every unavailable numeric has a reason.
#[derive(Clone, Debug, Serialize)]
pub struct TransitionMaturityRow {
    /// Stable schema version.
    pub schema_version: u16,
    /// `2-to-4` or `4-to-8`.
    pub transition: &'static str,
    /// Public provenance classification for the whole row.
    pub provenance: &'static str,
    /// Members represented by this target-set replay.
    pub member_count: u32,
    /// Actual 2-to-4 Commit bytes, or an educational delivery-component count.
    pub transition_bytes: u64,
    /// Bytes through the first maturity-evaluation point, with its method stated below.
    pub cumulative_bytes_to_maturity_evaluation: u64,
    /// Number of post-transition impactful updates before the retirement condition is evaluated.
    pub impactful_updates_until_retirement_condition: u32,
    /// Exact canonical-codec counterfactual `C_leaf` bytes.
    pub c_leaf_bytes: u64,
    /// Exact canonical-codec counterfactual `C_new` bytes.
    pub c_new_bytes: u64,
    /// Exact canonical-codec counterfactual `C_old` bytes.
    pub c_old_bytes: u64,
    /// Exact canonical-codec counterfactual `C_ideal` bytes.
    pub c_ideal_bytes: u64,
    /// Sum of the four counterfactual costs, not a network message.
    pub aggregate_counterfactual_bytes: u64,
    /// Exact clamped global `h_new_cost` rational.
    pub h_new_cost: String,
    /// Exact clamped global `h_old_cost` rational.
    pub h_old_cost: String,
    /// Result of the existing Task 48 threshold rule.
    pub threshold_decision: String,
    /// True side(s) of the OR rule, or an explicit blocker.
    pub threshold_trigger: String,
    /// A modelled/educational break-even update count when meaningful.
    pub break_even_updates: Option<u32>,
    /// Reason when no break-even count is meaningful.
    pub break_even_reason: Option<&'static str>,
    /// Real authenticated retirement epoch only; Task 61 deliberately has none.
    pub logical_treecover_retirement_epoch: Option<u64>,
    /// Explicit retirement lifecycle state.
    pub treecover_retirement_state: &'static str,
    /// Short reproducibility and interpretation statement.
    pub measurement_method: &'static str,
}

#[derive(Clone, Copy, Debug)]
struct RealTwoToFourFacts {
    transition_bytes: u64,
    matched_normal_bytes: u64,
    matched_window_saving_bytes: i64,
    impactful_observation_count: u32,
    post_transition_update_bytes: u64,
    member_count: u32,
}

#[derive(Clone, Debug)]
struct CostReplay {
    c_leaf: u64,
    c_new: u64,
    c_old: u64,
    c_ideal: u64,
    h_new: ScoreText,
    h_old: ScoreText,
    decision: DecisionText,
}

#[derive(Clone, Debug)]
struct ScoreText(String);

#[derive(Clone, Debug)]
struct DecisionText {
    decision: String,
    trigger: String,
}

/// Public result of the canonical 2-to-4 delivery-cost replay for one target size.
///
/// These values are deterministic serializer/formula outputs. They are not
/// emitted MLS Commit sizes and do not prove live TreeCover retirement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalCostReplay {
    /// Independent leaf-delivery cost.
    pub c_leaf_bytes: u64,
    /// Active quaternary-tree delivery cost.
    pub c_new_bytes: u64,
    /// Old binary TreeCover delivery cost.
    pub c_old_bytes: u64,
    /// Ideal mature-quaternary delivery cost.
    pub c_ideal_bytes: u64,
    /// Exact clamped `h_new_cost` rational.
    pub h_new_cost: String,
    /// Exact clamped `h_old_cost` rational.
    pub h_old_cost: String,
    /// Existing Task 48 formula decision.
    pub threshold_decision: String,
    /// Side of the Task 48 OR rule that produced the decision.
    pub threshold_trigger: String,
}

/// Replays the canonical thesis 2-to-4 costs for `member_count` recipients.
pub fn canonical_two_to_four_cost_replay(
    member_count: u32,
) -> Result<CanonicalCostReplay, TransitionTableError> {
    let replay = cost_replay(member_count, 2, 4, 8)?;
    Ok(CanonicalCostReplay {
        c_leaf_bytes: replay.c_leaf,
        c_new_bytes: replay.c_new,
        c_old_bytes: replay.c_old,
        c_ideal_bytes: replay.c_ideal,
        h_new_cost: replay.h_new.0,
        h_old_cost: replay.h_old.0,
        threshold_decision: replay.decision.decision,
        threshold_trigger: replay.decision.trigger,
    })
}

/// Generates create-new Task 65 artifacts from a public Task 61 summary.
pub fn generate_transition_table_artifacts(
    task61_summary: &Path,
    output_directory: &Path,
    report_directory: &Path,
) -> Result<TransitionTableArtifactPaths, TransitionTableError> {
    validate_artifact_directory(output_directory, "output", "transition maturity evidence")?;
    validate_artifact_directory(report_directory, "report", "transition maturity table")?;
    let paths = TransitionTableArtifactPaths {
        transition_maturity_csv: output_directory.join(TRANSITION_MATURITY_CSV_FILE_NAME),
        transition_maturity_json: output_directory.join(TRANSITION_MATURITY_JSON_FILE_NAME),
        transition_maturity_markdown: report_directory.join(TRANSITION_MATURITY_MARKDOWN_FILE_NAME),
    };
    for path in [
        &paths.transition_maturity_csv,
        &paths.transition_maturity_json,
        &paths.transition_maturity_markdown,
    ] {
        if path.exists() {
            return Err(TransitionTableError::Artifact(
                ReportArtifactError::ArtifactAlreadyExists,
            ));
        }
    }

    let summary = fs::read(task61_summary).map_err(TransitionTableError::ReadSummary)?;
    let facts = real_two_to_four_facts(
        &serde_json::from_slice(&summary).map_err(TransitionTableError::SummaryJson)?,
    )?;
    let two_to_four = cost_replay(facts.member_count, 2, 4, 8)?;
    let four_to_eight = cost_replay(64, 4, 8, 16)?;
    let real_cumulative = facts
        .matched_normal_bytes
        .checked_add(facts.transition_bytes)
        .and_then(|value| value.checked_add(facts.post_transition_update_bytes))
        .ok_or(TransitionTableError::Overflow)?;
    let educational_cumulative = four_to_eight
        .c_new
        .checked_mul(2)
        .ok_or(TransitionTableError::Overflow)?;
    let rows = vec![
        TransitionMaturityRow {
            schema_version: TRANSITION_TABLE_SCHEMA_VERSION,
            transition: "2-to-4",
            provenance: "real_fork_bytes_plus_canonical_codec_replay",
            member_count: facts.member_count,
            transition_bytes: facts.transition_bytes,
            cumulative_bytes_to_maturity_evaluation: real_cumulative,
            impactful_updates_until_retirement_condition: 1,
            c_leaf_bytes: two_to_four.c_leaf,
            c_new_bytes: two_to_four.c_new,
            c_old_bytes: two_to_four.c_old,
            c_ideal_bytes: two_to_four.c_ideal,
            aggregate_counterfactual_bytes: aggregate_cost(&two_to_four)?,
            h_new_cost: two_to_four.h_new.0,
            h_old_cost: two_to_four.h_old.0,
            threshold_decision: two_to_four.decision.decision,
            threshold_trigger: two_to_four.decision.trigger,
            break_even_updates: modelled_break_even_updates(&facts),
            break_even_reason: None,
            logical_treecover_retirement_epoch: None,
            treecover_retirement_state: "UnsupportedNoAuthenticatedRetirementCommit",
            measurement_method: "transition/cumulative bytes are real Task 61 observations (two normal updates + transition + one converged quaternary update); C/h values are exact canonical-hybrid-codec counterfactual replay; Task 48 retirement authorization is not a live secret-erasure claim",
        },
        TransitionMaturityRow {
            schema_version: TRANSITION_TABLE_SCHEMA_VERSION,
            transition: "4-to-8",
            provenance: "educational_canonical_codec_topology_replay",
            member_count: 64,
            transition_bytes: four_to_eight.c_new,
            cumulative_bytes_to_maturity_evaluation: educational_cumulative,
            impactful_updates_until_retirement_condition: 1,
            c_leaf_bytes: four_to_eight.c_leaf,
            c_new_bytes: four_to_eight.c_new,
            c_old_bytes: four_to_eight.c_old,
            c_ideal_bytes: four_to_eight.c_ideal,
            aggregate_counterfactual_bytes: aggregate_cost(&four_to_eight)?,
            h_new_cost: four_to_eight.h_new.0,
            h_old_cost: four_to_eight.h_old.0,
            threshold_decision: four_to_eight.decision.decision,
            threshold_trigger: four_to_eight.decision.trigger,
            break_even_updates: None,
            break_even_reason: Some("UndefinedNoLiveOctalTransitionCommit"),
            logical_treecover_retirement_epoch: Some(2),
            treecover_retirement_state: "EducationalLogicalEpochOnlyNoLiveSecretErasure",
            measurement_method: "deterministic 64-member 4-to-8 routing partition replay; transition_bytes is only the exact canonical delivery component, cumulative bytes is two such components through one logical post-transition evaluation; no octal MLS Commit, convergence, private-key lifecycle, or secret erasure is implemented",
        },
    ];
    let manifest = TransitionTableManifest {
        schema_version: TRANSITION_TABLE_SCHEMA_VERSION,
        task61_summary_path: task61_summary.display().to_string(),
        rows,
        scope_note: "Task 65 deliberately separates real Task 61 byte observations from canonical-codec counterfactual costs. The existing maturity rule is evaluated exactly, but Task 61 has no authenticated TreeCover-retirement Commit; therefore an authorized formula result never proves actual fork private-key deletion. The 4-to-8 row is educational topology arithmetic, not a live protocol measurement.",
    };
    fs::create_dir_all(output_directory)
        .map_err(|error| TransitionTableError::Artifact(ReportArtifactError::Write(error)))?;
    fs::create_dir_all(report_directory)
        .map_err(|error| TransitionTableError::Artifact(ReportArtifactError::Write(error)))?;
    write_new(
        &paths.transition_maturity_csv,
        &transition_maturity_csv(&manifest.rows)?,
    )?;
    write_new(
        &paths.transition_maturity_json,
        &serde_json::to_vec_pretty(&manifest).map_err(TransitionTableError::Json)?,
    )?;
    write_new(
        &paths.transition_maturity_markdown,
        transition_maturity_markdown(&manifest).as_bytes(),
    )?;
    Ok(paths)
}

fn real_two_to_four_facts(
    value: &serde_json::Value,
) -> Result<RealTwoToFourFacts, TransitionTableError> {
    let transition = find_object(value, |object| {
        object.contains_key("preflight_bytes")
            && object.contains_key("actual_transition_bytes")
            && object.contains_key("matched_normal_bytes")
            && object.contains_key("matched_window_saving_bytes")
            && object.contains_key("treecover_member_count")
    })
    .ok_or(TransitionTableError::MissingTransitionFacts)?;
    let transition_bytes = u64_field(transition, "actual_transition_bytes")?;
    if u64_field(transition, "preflight_bytes")? != transition_bytes {
        return Err(TransitionTableError::MissingTransitionFacts);
    }
    let matched_normal_bytes = u64_field(transition, "matched_normal_bytes")?;
    let matched_window_saving_bytes = i64_field(transition, "matched_window_saving_bytes")?;
    if matched_window_saving_bytes <= 0 {
        return Err(TransitionTableError::MissingTransitionFacts);
    }
    let impactful_observation_count = find_object(value, |object| {
        object
            .get("normal_binary_bytes")
            .and_then(serde_json::Value::as_u64)
            == Some(matched_normal_bytes)
            && object.contains_key("compact_candidate_bytes")
            && object.contains_key("impactful_commit_count")
    })
    .and_then(|object| u32_field(object, "impactful_commit_count").ok())
    .filter(|count| *count > 0)
    .ok_or(TransitionTableError::MissingTransitionFacts)?;
    let post_transition_update_bytes = find_object(value, |object| {
        object
            .get("adaptive")
            .and_then(|adaptive| adaptive.get("Observed"))
            .and_then(|observed| observed.get("phase"))
            .and_then(serde_json::Value::as_str)
            == Some("QuaternaryUpdate")
    })
    .and_then(|record| {
        record
            .get("bytes")
            .and_then(|bytes| bytes.get("emitted_baseline_commit_bytes"))
            .and_then(serde_json::Value::as_u64)
    })
    .ok_or(TransitionTableError::MissingTransitionFacts)?;
    Ok(RealTwoToFourFacts {
        transition_bytes,
        matched_normal_bytes,
        matched_window_saving_bytes,
        impactful_observation_count,
        post_transition_update_bytes,
        member_count: u32_field(transition, "treecover_member_count")?,
    })
}

fn find_object(
    value: &serde_json::Value,
    predicate: impl Fn(&serde_json::Map<String, serde_json::Value>) -> bool + Copy,
) -> Option<&serde_json::Map<String, serde_json::Value>> {
    match value {
        serde_json::Value::Object(object) => {
            if predicate(object) {
                Some(object)
            } else {
                object
                    .values()
                    .find_map(|child| find_object(child, predicate))
            }
        }
        serde_json::Value::Array(values) => values
            .iter()
            .find_map(|child| find_object(child, predicate)),
        _ => None,
    }
}

fn u64_field(
    object: &serde_json::Map<String, serde_json::Value>,
    name: &str,
) -> Result<u64, TransitionTableError> {
    object
        .get(name)
        .and_then(serde_json::Value::as_u64)
        .ok_or(TransitionTableError::MissingTransitionFacts)
}

fn u32_field(
    object: &serde_json::Map<String, serde_json::Value>,
    name: &str,
) -> Result<u32, TransitionTableError> {
    u64_field(object, name)?
        .try_into()
        .map_err(|_| TransitionTableError::MissingTransitionFacts)
}

fn i64_field(
    object: &serde_json::Map<String, serde_json::Value>,
    name: &str,
) -> Result<i64, TransitionTableError> {
    object
        .get(name)
        .and_then(serde_json::Value::as_i64)
        .ok_or(TransitionTableError::MissingTransitionFacts)
}

fn cost_replay(
    member_count: u32,
    old_partition_size: u32,
    new_partition_size: u32,
    ideal_partition_size: u32,
) -> Result<CostReplay, TransitionTableError> {
    let recipients = (1..=member_count).collect::<Vec<_>>();
    let leaf = route_ciphertexts(&recipients, 1, 10)?;
    let new = route_ciphertexts(&recipients, new_partition_size, 1_000)?;
    let old = route_ciphertexts(&recipients, old_partition_size, 2_000)?;
    let ideal = route_ciphertexts(&recipients, ideal_partition_size, 3_000)?;
    let binding_byte = u8::try_from(member_count).map_err(|_| TransitionTableError::Overflow)?;
    let cost = RecipientTargetSetCostMeasurement::measure(
        RecipientTargetSet::new(recipients)?,
        [binding_byte; 32],
        CounterfactualDeliveryInput::Serialized(&leaf),
        CounterfactualDeliveryInput::Serialized(&new),
        CounterfactualDeliveryInput::Serialized(&old),
        CounterfactualDeliveryInput::Serialized(&ideal),
    )?;
    let c_leaf = cost_bytes(cost.c_leaf())?;
    let c_new = cost_bytes(cost.c_new())?;
    let c_old = cost_bytes(cost.c_old())?;
    let c_ideal = cost_bytes(cost.c_ideal())?;
    let maturity = MaturityCostEvaluation::from_costs(vec![cost])?;
    let (h_new, h_old) = maturity_text(&maturity)?;
    let retirement =
        evaluate_treecover_retirement(&maturity, TreeCoverRetirementThresholds::thesis_defaults())?;
    let decision = match retirement.decision() {
        TreeCoverRetirementDecision::Retire(trigger) => DecisionText {
            decision: "RetireAuthorizedByFormula".to_owned(),
            trigger: match (trigger.new_tree_maturity(), trigger.old_treecover_cost()) {
                (true, true) => "NewTreeMaturityAndOldTreeCoverCost".to_owned(),
                (true, false) => "NewTreeMaturity".to_owned(),
                (false, true) => "OldTreeCoverCost".to_owned(),
                (false, false) => return Err(TransitionTableError::MissingTransitionFacts),
            },
        },
        TreeCoverRetirementDecision::Keep(blocker) => DecisionText {
            decision: "KeepTreeCover".to_owned(),
            trigger: format!("Blocker:{blocker:?}"),
        },
    };
    Ok(CostReplay {
        c_leaf,
        c_new,
        c_old,
        c_ideal,
        h_new: ScoreText(h_new),
        h_old: ScoreText(h_old),
        decision,
    })
}

fn route_ciphertexts(
    recipients: &[u32],
    partition_size: u32,
    path_start: u32,
) -> Result<Vec<HybridPathCiphertext>, TransitionTableError> {
    let width = usize::try_from(partition_size).map_err(|_| TransitionTableError::Overflow)?;
    recipients
        .chunks(width)
        .enumerate()
        .map(|(position, partition)| {
            let recipient_records = partition
                .iter()
                .enumerate()
                .map(|(offset, recipient)| {
                    let fill = u8::try_from(offset).map_err(|_| TransitionTableError::Overflow)?;
                    Ok(HybridRecipientCiphertext::new(
                        RecipientNodeIndex::new(*recipient),
                        [fill; CLASSICAL_ENCAPSULATION_BYTES],
                        MkyberRecipientCiphertext::from_bytes(&[fill; RECIPIENT_CIPHERTEXT_BYTES])
                            .map_err(|_| TransitionTableError::MissingTransitionFacts)?,
                        [fill; ENCRYPTED_PATH_SECRET_BYTES],
                    ))
                })
                .collect::<Result<Vec<_>, TransitionTableError>>()?;
            let path_offset =
                u32::try_from(position).map_err(|_| TransitionTableError::Overflow)?;
            HybridPathCiphertext::new(
                PathNodeIndex::new(
                    path_start
                        .checked_add(path_offset)
                        .ok_or(TransitionTableError::Overflow)?,
                ),
                DOMAIN,
                MkyberCommonCiphertext::from_bytes(&[7; COMMON_CIPHERTEXT_BYTES])
                    .map_err(|_| TransitionTableError::MissingTransitionFacts)?,
                recipient_records,
            )
            .map_err(|_| TransitionTableError::MissingTransitionFacts)
        })
        .collect()
}

fn cost_bytes(cost: DeliveryCostAvailability) -> Result<u64, TransitionTableError> {
    let DeliveryCostAvailability::Measured(cost) = cost else {
        return Err(TransitionTableError::MissingTransitionFacts);
    };
    u64::try_from(cost.provenance().measured_bytes()).map_err(|_| TransitionTableError::Overflow)
}

fn maturity_text(
    maturity: &MaturityCostEvaluation,
) -> Result<(String, String), TransitionTableError> {
    let TargetSetMaturity::Evaluated { h_new, h_old, .. } = maturity
        .target_sets()
        .first()
        .ok_or(TransitionTableError::MissingTransitionFacts)?
    else {
        return Err(TransitionTableError::MissingTransitionFacts);
    };
    Ok((score_text(*h_new)?, score_text(*h_old)?))
}

fn score_text(score: TargetSetMaturityScore) -> Result<String, TransitionTableError> {
    let TargetSetMaturityScore::Defined(score) = score else {
        return Err(TransitionTableError::MissingTransitionFacts);
    };
    let clamped = score.clamped();
    Ok(format!("{}/{}", clamped.numerator(), clamped.denominator()))
}

fn aggregate_cost(replay: &CostReplay) -> Result<u64, TransitionTableError> {
    replay
        .c_leaf
        .checked_add(replay.c_new)
        .and_then(|value| value.checked_add(replay.c_old))
        .and_then(|value| value.checked_add(replay.c_ideal))
        .ok_or(TransitionTableError::Overflow)
}

fn modelled_break_even_updates(facts: &RealTwoToFourFacts) -> Option<u32> {
    let saving = u64::try_from(facts.matched_window_saving_bytes).ok()?;
    let windows = facts.transition_bytes.checked_add(saving.checked_sub(1)?)? / saving;
    let updates = windows.checked_mul(u64::from(facts.impactful_observation_count))?;
    updates.try_into().ok()
}

fn transition_maturity_csv(
    rows: &[TransitionMaturityRow],
) -> Result<Vec<u8>, TransitionTableError> {
    let mut writer = WriterBuilder::new().has_headers(true).from_writer(vec![]);
    for row in rows {
        writer.serialize(row).map_err(TransitionTableError::Csv)?;
    }
    writer
        .into_inner()
        .map_err(|error| TransitionTableError::Csv(error.into_error().into()))
}

fn transition_maturity_markdown(manifest: &TransitionTableManifest) -> String {
    let mut document = String::new();
    writeln!(
        document,
        "# Task 65 transition maturity and TreeCover table\n"
    )
    .expect("string write");
    writeln!(document, "Source: `{}`.\n", manifest.task61_summary_path).expect("string write");
    writeln!(document, "| Transition | Provenance | Transition bytes | Cumulative bytes | Impacts to condition | C_leaf / C_new / C_old / C_ideal | h_new / h_old | Formula decision | Break-even updates | TreeCover retirement |\n|---|---|---:|---:|---:|---:|---|---|---:|---|").expect("string write");
    for row in &manifest.rows {
        writeln!(
            document,
            "| {} | {} | {} | {} | {} | {} / {} / {} / {} | {} / {} | {} ({}) | {} | {} |",
            row.transition,
            row.provenance,
            row.transition_bytes,
            row.cumulative_bytes_to_maturity_evaluation,
            row.impactful_updates_until_retirement_condition,
            row.c_leaf_bytes,
            row.c_new_bytes,
            row.c_old_bytes,
            row.c_ideal_bytes,
            row.h_new_cost,
            row.h_old_cost,
            row.threshold_decision,
            row.threshold_trigger,
            row.break_even_updates.map_or_else(
                || row.break_even_reason.unwrap_or("Undefined").to_owned(),
                |value| value.to_string()
            ),
            row.treecover_retirement_state,
        )
        .expect("string write");
    }
    writeln!(document, "\n## Interpretation\n").expect("string write");
    writeln!(document, "- 2→4 transition and cumulative bytes are real recorded Task 61 facts. `C_*` values are exact canonical-hybrid-codec counterfactual delivery bytes, so they are not emitted MLS Commit sizes.").expect("string write");
    writeln!(document, "- The Task 48 formula may authorize retirement, but Task 61 reports `UnsupportedNoAuthenticatedRetirementCommit`. No actual TreeCover secret erasure is claimed.").expect("string write");
    writeln!(document, "- 4→8 is an educational 64-member topology replay only. Its logical epoch is an explanatory table value, not an implemented octal protocol state.").expect("string write");
    document
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_uses_existing_formula_and_authorizes_new_tree_maturity() {
        let replay = cost_replay(128, 2, 4, 8).expect("canonical replay");
        assert_eq!(replay.h_new.0, "6/7");
        assert_eq!(replay.h_old.0, "4/7");
        assert_eq!(replay.decision.decision, "RetireAuthorizedByFormula");
        assert_eq!(replay.decision.trigger, "NewTreeMaturity");
    }

    #[test]
    fn public_32_member_replay_exposes_requested_costs_and_maturity() {
        let replay = canonical_two_to_four_cost_replay(32).expect("32-member replay");
        assert!(replay.c_leaf_bytes > replay.c_old_bytes);
        assert!(replay.c_old_bytes > replay.c_new_bytes);
        assert!(replay.c_new_bytes > replay.c_ideal_bytes);
        assert_eq!(replay.h_new_cost, "6/7");
        assert_eq!(replay.h_old_cost, "4/7");
        assert_eq!(replay.threshold_decision, "RetireAuthorizedByFormula");
        assert_eq!(replay.threshold_trigger, "NewTreeMaturity");
    }

    #[test]
    fn break_even_counts_complete_matched_windows() {
        assert_eq!(
            modelled_break_even_updates(&RealTwoToFourFacts {
                transition_bytes: 25_629,
                matched_normal_bytes: 58_114,
                matched_window_saving_bytes: 7_256,
                impactful_observation_count: 2,
                post_transition_update_bytes: 25_429,
                member_count: 128,
            }),
            Some(8)
        );
    }
}
