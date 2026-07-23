#![forbid(unsafe_code)]

//! Minimal 64-member thesis report with one summary row and an event trace.
//!
//! Real RFC MLS supplies Update/Add/Remove evidence. A separate real
//! experimental fork run supplies normal-binary, transition, and quaternary
//! Update evidence. Exact topology-derived routes supply canonical
//! counterfactual costs; direct maturity evaluation remains a separate step.
//! The fork's missing authenticated TreeCover-retirement Commit stays explicit.

use std::{
    fmt::Write as FmtWrite,
    fs,
    path::{Path, PathBuf},
};

use csv::WriterBuilder;
use experimental_mls_adapter::{
    execute_experimental_adaptive_workload_until_first_post_transition,
    ExperimentalAdaptiveCommitPhase, ExperimentalAdaptiveTransitionPolicy,
    ExperimentalBinaryWorkloadError,
};
use serde::Serialize;
use simulation::{
    execute_baseline_workload, BaselineWorkloadConfig, CommitterStrategy, WorkloadExecutionError,
    WorkloadOperation, WorkloadProfile,
};
use thiserror::Error;

use crate::generation::{validate_artifact_directory, write_new, ReportArtifactError};
use crate::topology_routes::{
    measure_exact_topology_routes, ExactTopologyAggregateCost, ExactTopologyRouteError,
};

/// Fixed group size for the requested clear experiment.
pub const CLEAR_REPORT_MEMBER_COUNT: u32 = 64;
/// Primary one-row summary CSV.
pub const CLEAR_REPORT_CSV_FILE_NAME: &str = "clear_report.csv";
/// Per-event trace CSV.
pub const CLEAR_EVENTS_CSV_FILE_NAME: &str = "clear_events.csv";
/// Human-readable interpretation.
pub const CLEAR_REPORT_MARKDOWN_FILE_NAME: &str = "clear_report.md";

const CLEAR_REPORT_SCHEMA_VERSION: u16 = 5;
const CLEAR_ADAPTIVE_OPERATION_LIMIT: u32 = 128;
const LIVE_RETIREMENT_STATE: &str = "UnsupportedNoAuthenticatedRetirementCommit";
const CORRECTED_COST_PROVENANCE: &str =
    "observed_outer_commit_remainder_plus_authenticated_topology_exact_cover_canonical_codec";
const MATURITY_UNAVAILABLE_REASON: &str = "DirectMaturityCalculationPendingTask83";

/// Paths created by one clear 64-member run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClearReportArtifactPaths {
    /// One-row CSV with every requested count.
    pub summary_csv: PathBuf,
    /// Ordered real/modelled event trace.
    pub events_csv: PathBuf,
    /// Human-readable report.
    pub report_markdown: PathBuf,
}

/// Failures from the clear 64-member report.
#[derive(Debug, Error)]
pub enum ClearReportError {
    /// Real baseline MLS Update/Add/Remove execution failed.
    #[error("the real 64-member baseline MLS workload failed: {0}")]
    Baseline(#[source] WorkloadExecutionError),
    /// Real adaptive fork execution failed.
    #[error("the real 64-member adaptive workload failed: {0}")]
    Adaptive(#[source] ExperimentalBinaryWorkloadError),
    /// A required operation or phase was missing.
    #[error("the 64-member run did not produce every required operation or phase")]
    MissingRequiredEvent,
    /// A public byte/count sum overflowed.
    #[error("a 64-member public byte or count calculation overflowed")]
    Overflow,
    /// Exact topology-route materialization or accounting failed.
    #[error("the exact topology-route measurement failed")]
    TopologyRoute,
    /// Safe-path, create-new, or filesystem output failed.
    #[error("the clear report artifact output failed")]
    Artifact(#[from] ReportArtifactError),
    /// CSV serialization failed.
    #[error("the clear report CSV serialization failed")]
    Csv(#[source] csv::Error),
}

impl From<ExactTopologyRouteError> for ClearReportError {
    fn from(_: ExactTopologyRouteError) -> Self {
        Self::TopologyRoute
    }
}

#[derive(Clone, Debug, Serialize)]
struct ClearReportSummary {
    schema_version: u16,
    member_count: u32,
    random_committer_seed: u64,
    cost_measurement_state: &'static str,
    cost_unavailable_reason: Option<&'static str>,
    maturity_unavailable_reason: Option<&'static str>,
    c_ideal_bytes: Option<u64>,
    c_leaf_bytes: Option<u64>,
    c_new_bytes: Option<u64>,
    c_old_bytes: Option<u64>,
    h_new_cost: Option<String>,
    h_old_cost: Option<String>,
    retirement_formula_decision: &'static str,
    retirement_formula_trigger: &'static str,
    estimated_commits_to_retirement_condition: Option<u32>,
    live_treecover_retirement_state: &'static str,
    baseline_update_commit_bytes: u64,
    baseline_add_commit_bytes: u64,
    baseline_add_welcome_bytes: u64,
    baseline_remove_commit_bytes: u64,
    normal_binary_commit_count: u32,
    normal_binary_commit_bytes: u64,
    transition_commit_count: u32,
    transition_commit_bytes: u64,
    quaternary_commit_count: u32,
    quaternary_commit_bytes: u64,
    total_adaptive_commit_bytes: u64,
    logical_retirement_after_adaptive_commit_sequence: Option<u32>,
    real_operation_provenance: &'static str,
    cost_provenance: &'static str,
}

#[derive(Clone, Debug, Serialize)]
struct ClearEventRow {
    event_index: u32,
    scope: &'static str,
    commit_sequence: Option<u32>,
    phase: &'static str,
    operation: String,
    committer_member_index: Option<u32>,
    epoch_before: Option<u64>,
    epoch_after: Option<u64>,
    active_member_count: u32,
    commit_bytes: u64,
    welcome_bytes: u64,
    cumulative_commit_bytes: u64,
    authenticated_tree_version: Option<u32>,
    active_tree_height: Option<u8>,
    active_tree_leaf_capacity: Option<u32>,
    active_tree_occupied_leaf_count: Option<u32>,
    old_treecover_version: Option<u32>,
    old_treecover_eligible_member_count: Option<u32>,
    old_treecover_eligible_node_count: Option<u32>,
    committer_quaternary_leaf_ordinal: Option<u32>,
    recipient_set_index: Option<u32>,
    recipient_tree: Option<&'static str>,
    path_node_index: Option<u32>,
    recipient_node_indices: Option<String>,
    cover_variant: Option<&'static str>,
    cover_node_count: Option<u32>,
    cover_nodes: Option<String>,
    route_payload_bytes: Option<u64>,
    common_outer_commit_bytes: Option<u64>,
    aggregate_cost_bytes: Option<u64>,
    state: &'static str,
    provenance: &'static str,
}

/// Runs and writes the requested minimal 64-member report.
pub fn generate_clear_64_report(
    random_seed: u64,
    output_directory: &Path,
    report_directory: &Path,
) -> Result<ClearReportArtifactPaths, ClearReportError> {
    validate_artifact_directory(output_directory, "output", "clear report evidence")?;
    validate_artifact_directory(report_directory, "report", "clear report Markdown")?;
    let paths = ClearReportArtifactPaths {
        summary_csv: output_directory.join(CLEAR_REPORT_CSV_FILE_NAME),
        events_csv: output_directory.join(CLEAR_EVENTS_CSV_FILE_NAME),
        report_markdown: report_directory.join(CLEAR_REPORT_MARKDOWN_FILE_NAME),
    };
    for path in [
        &paths.summary_csv,
        &paths.events_csv,
        &paths.report_markdown,
    ] {
        if path.exists() {
            return Err(ClearReportError::Artifact(
                ReportArtifactError::ArtifactAlreadyExists,
            ));
        }
    }

    let baseline = execute_baseline_workload(&BaselineWorkloadConfig {
        group_id: format!("clear-64-baseline-{random_seed}").into_bytes(),
        initial_member_count: CLEAR_REPORT_MEMBER_COUNT,
        maximum_member_count: CLEAR_REPORT_MEMBER_COUNT + 1,
        operation_count: 3,
        region_count: 4,
        committer_strategy: CommitterStrategy::SeededRandom { seed: random_seed },
        workload_profile: WorkloadProfile::Mixed,
    })
    .map_err(ClearReportError::Baseline)?;
    let adaptive = execute_experimental_adaptive_workload_until_first_post_transition(
        &BaselineWorkloadConfig {
            group_id: format!("clear-64-adaptive-{random_seed}").into_bytes(),
            initial_member_count: CLEAR_REPORT_MEMBER_COUNT,
            maximum_member_count: CLEAR_REPORT_MEMBER_COUNT,
            operation_count: CLEAR_ADAPTIVE_OPERATION_LIMIT,
            region_count: 4,
            committer_strategy: CommitterStrategy::SeededRandom { seed: random_seed },
            workload_profile: WorkloadProfile::UpdateOnly,
        },
        ExperimentalAdaptiveTransitionPolicy::MatchedPerCommitSaving,
    )
    .map_err(ClearReportError::Adaptive)?;
    let baseline_update = baseline
        .accepted_operations
        .iter()
        .find(|event| matches!(event.operation, WorkloadOperation::Update))
        .ok_or(ClearReportError::MissingRequiredEvent)?;
    let baseline_add = baseline
        .accepted_operations
        .iter()
        .find(|event| matches!(event.operation, WorkloadOperation::Add { .. }))
        .ok_or(ClearReportError::MissingRequiredEvent)?;
    let baseline_remove = baseline
        .accepted_operations
        .iter()
        .find(|event| matches!(event.operation, WorkloadOperation::Remove { .. }))
        .ok_or(ClearReportError::MissingRequiredEvent)?;

    let normal_binary = adaptive
        .accepted_operations
        .iter()
        .filter(|event| event.phase == ExperimentalAdaptiveCommitPhase::NormalBinaryUpdate)
        .collect::<Vec<_>>();
    let transitions = adaptive
        .accepted_operations
        .iter()
        .filter(|event| event.phase == ExperimentalAdaptiveCommitPhase::Transition)
        .collect::<Vec<_>>();
    let quaternary = adaptive
        .accepted_operations
        .iter()
        .filter(|event| event.phase == ExperimentalAdaptiveCommitPhase::QuaternaryUpdate)
        .collect::<Vec<_>>();
    if normal_binary.is_empty() || transitions.len() != 1 || quaternary.is_empty() {
        return Err(ClearReportError::MissingRequiredEvent);
    }
    let normal_binary_bytes = sum_adaptive_bytes(&normal_binary)?;
    let transition_bytes = sum_adaptive_bytes(&transitions)?;
    let quaternary_bytes = sum_adaptive_bytes(&quaternary)?;
    let total_adaptive_commit_bytes = normal_binary_bytes
        .checked_add(transition_bytes)
        .and_then(|value| value.checked_add(quaternary_bytes))
        .ok_or(ClearReportError::Overflow)?;
    let cost_event = quaternary
        .last()
        .ok_or(ClearReportError::MissingRequiredEvent)?;
    let cost_snapshot = cost_event
        .topology_snapshot
        .as_ref()
        .ok_or(ClearReportError::MissingRequiredEvent)?;
    let costs = measure_exact_topology_routes(cost_snapshot, cost_event.emitted_commit_bytes)?;
    let summary = ClearReportSummary {
        schema_version: CLEAR_REPORT_SCHEMA_VERSION,
        member_count: CLEAR_REPORT_MEMBER_COUNT,
        random_committer_seed: random_seed,
        cost_measurement_state: "exact-counterfactual",
        cost_unavailable_reason: None,
        maturity_unavailable_reason: Some(MATURITY_UNAVAILABLE_REASON),
        c_ideal_bytes: Some(costs.c_ideal_bytes),
        c_leaf_bytes: Some(costs.c_leaf_bytes),
        c_new_bytes: Some(costs.c_new_bytes),
        c_old_bytes: Some(costs.c_old_bytes),
        h_new_cost: None,
        h_old_cost: None,
        retirement_formula_decision: "NotEvaluated",
        retirement_formula_trigger: MATURITY_UNAVAILABLE_REASON,
        estimated_commits_to_retirement_condition: None,
        live_treecover_retirement_state: LIVE_RETIREMENT_STATE,
        baseline_update_commit_bytes: baseline_update.measurement.emitted_commit_bytes,
        baseline_add_commit_bytes: baseline_add.measurement.emitted_commit_bytes,
        baseline_add_welcome_bytes: baseline_add
            .measurement
            .emitted_welcome_bytes
            .ok_or(ClearReportError::MissingRequiredEvent)?,
        baseline_remove_commit_bytes: baseline_remove.measurement.emitted_commit_bytes,
        normal_binary_commit_count: count_events(&normal_binary)?,
        normal_binary_commit_bytes: normal_binary_bytes,
        transition_commit_count: 1,
        transition_commit_bytes: transition_bytes,
        quaternary_commit_count: count_events(&quaternary)?,
        quaternary_commit_bytes: quaternary_bytes,
        total_adaptive_commit_bytes,
        logical_retirement_after_adaptive_commit_sequence: None,
        real_operation_provenance:
            "real_rfc_baseline_mixed_plus_separate_real_adaptive_fork_update_run",
        cost_provenance: CORRECTED_COST_PROVENANCE,
    };
    let events = event_rows(&baseline.accepted_operations, &adaptive.accepted_operations)?;

    fs::create_dir_all(output_directory)
        .map_err(|error| ClearReportError::Artifact(ReportArtifactError::Write(error)))?;
    fs::create_dir_all(report_directory)
        .map_err(|error| ClearReportError::Artifact(ReportArtifactError::Write(error)))?;
    write_new(&paths.summary_csv, &summary_csv(&summary)?)?;
    write_new(&paths.events_csv, &events_csv(&events)?)?;
    write_new(
        &paths.report_markdown,
        clear_markdown(&summary, &events).as_bytes(),
    )?;
    Ok(paths)
}

fn sum_adaptive_bytes(
    events: &[&experimental_mls_adapter::AcceptedExperimentalAdaptiveOperation],
) -> Result<u64, ClearReportError> {
    events.iter().try_fold(0_u64, |sum, event| {
        sum.checked_add(event.emitted_commit_bytes)
            .ok_or(ClearReportError::Overflow)
    })
}

fn count_events<T>(events: &[T]) -> Result<u32, ClearReportError> {
    events
        .len()
        .try_into()
        .map_err(|_| ClearReportError::Overflow)
}

fn event_rows(
    baseline: &[simulation::AcceptedWorkloadOperation],
    adaptive: &[experimental_mls_adapter::AcceptedExperimentalAdaptiveOperation],
) -> Result<Vec<ClearEventRow>, ClearReportError> {
    let mut rows = Vec::new();
    let mut event_index = 1_u32;
    let mut baseline_cumulative = 0_u64;
    for event in baseline {
        baseline_cumulative = baseline_cumulative
            .checked_add(event.measurement.emitted_commit_bytes)
            .ok_or(ClearReportError::Overflow)?;
        rows.push(ClearEventRow {
            event_index,
            scope: "real_baseline_membership_operations",
            commit_sequence: Some(event.sequence),
            phase: "binary",
            operation: operation_text(event.operation),
            committer_member_index: Some(event.committer_member_index),
            epoch_before: Some(event.epoch_before),
            epoch_after: Some(event.epoch_after),
            active_member_count: event.active_member_count,
            commit_bytes: event.measurement.emitted_commit_bytes,
            welcome_bytes: event.measurement.emitted_welcome_bytes.unwrap_or(0),
            cumulative_commit_bytes: baseline_cumulative,
            authenticated_tree_version: None,
            active_tree_height: None,
            active_tree_leaf_capacity: None,
            active_tree_occupied_leaf_count: None,
            old_treecover_version: None,
            old_treecover_eligible_member_count: None,
            old_treecover_eligible_node_count: None,
            committer_quaternary_leaf_ordinal: None,
            recipient_set_index: None,
            recipient_tree: None,
            path_node_index: None,
            recipient_node_indices: None,
            cover_variant: None,
            cover_node_count: None,
            cover_nodes: None,
            route_payload_bytes: None,
            common_outer_commit_bytes: None,
            aggregate_cost_bytes: None,
            state: "observed",
            provenance: "real_rfc_baseline",
        });
        event_index = next_index(event_index)?;
    }

    let mut adaptive_cumulative = 0_u64;
    for event in adaptive {
        adaptive_cumulative = adaptive_cumulative
            .checked_add(event.emitted_commit_bytes)
            .ok_or(ClearReportError::Overflow)?;
        rows.push(ClearEventRow {
            event_index,
            scope: "real_adaptive_update_only",
            commit_sequence: Some(event.sequence),
            phase: adaptive_phase(event.phase),
            operation: if event.phase == ExperimentalAdaptiveCommitPhase::Transition {
                "transition-2-to-4".to_owned()
            } else {
                "update".to_owned()
            },
            committer_member_index: Some(event.committer_member_index),
            epoch_before: Some(event.epoch_before),
            epoch_after: Some(event.epoch_after),
            active_member_count: event.active_member_count,
            commit_bytes: event.emitted_commit_bytes,
            welcome_bytes: 0,
            cumulative_commit_bytes: adaptive_cumulative,
            authenticated_tree_version: None,
            active_tree_height: None,
            active_tree_leaf_capacity: None,
            active_tree_occupied_leaf_count: None,
            old_treecover_version: None,
            old_treecover_eligible_member_count: None,
            old_treecover_eligible_node_count: None,
            committer_quaternary_leaf_ordinal: None,
            recipient_set_index: None,
            recipient_tree: None,
            path_node_index: None,
            recipient_node_indices: None,
            cover_variant: None,
            cover_node_count: None,
            cover_nodes: None,
            route_payload_bytes: None,
            common_outer_commit_bytes: None,
            aggregate_cost_bytes: None,
            state: "observed",
            provenance: "real_experimental_fork",
        });
        event_index = next_index(event_index)?;
        if let Some(snapshot) = &event.topology_snapshot {
            let active = snapshot.transition_trees.active();
            let active_topology = active.topology();
            let treecover = snapshot.transition_trees.treecover();
            let eligible_member_count = u32::try_from(
                treecover
                    .members()
                    .iter()
                    .filter(|member| member.eligible)
                    .count(),
            )
            .map_err(|_| ClearReportError::Overflow)?;
            let eligible_node_count = u32::try_from(
                treecover
                    .eligible_node_count()
                    .map_err(|_| ClearReportError::MissingRequiredEvent)?,
            )
            .map_err(|_| ClearReportError::Overflow)?;
            let occupied_leaf_count = u32::try_from(active_topology.occupied_leaf_count())
                .map_err(|_| ClearReportError::Overflow)?;
            for (set_index, recipient_set) in
                snapshot.commit_topology.recipient_sets().iter().enumerate()
            {
                rows.push(ClearEventRow {
                    event_index,
                    scope: "authenticated_topology_recipient_set",
                    commit_sequence: Some(event.sequence),
                    phase: "quaternary-topology",
                    operation: "authenticated-recipient-set".to_owned(),
                    committer_member_index: Some(event.committer_member_index),
                    epoch_before: Some(event.epoch_before),
                    epoch_after: Some(snapshot.epoch),
                    active_member_count: event.active_member_count,
                    commit_bytes: 0,
                    welcome_bytes: 0,
                    cumulative_commit_bytes: adaptive_cumulative,
                    authenticated_tree_version: Some(active.tree_version()),
                    active_tree_height: Some(active_topology.height()),
                    active_tree_leaf_capacity: Some(active_topology.leaf_capacity()),
                    active_tree_occupied_leaf_count: Some(occupied_leaf_count),
                    old_treecover_version: Some(treecover.version()),
                    old_treecover_eligible_member_count: Some(eligible_member_count),
                    old_treecover_eligible_node_count: Some(eligible_node_count),
                    committer_quaternary_leaf_ordinal: Some(
                        snapshot.committer_quaternary_leaf_ordinal,
                    ),
                    recipient_set_index: Some(
                        u32::try_from(set_index).map_err(|_| ClearReportError::Overflow)?,
                    ),
                    recipient_tree: Some(recipient_set.delivery_tree().as_str()),
                    path_node_index: Some(recipient_set.path_node_index()),
                    recipient_node_indices: Some(join_node_indices(
                        recipient_set.recipient_node_indices(),
                    )),
                    cover_variant: None,
                    cover_node_count: None,
                    cover_nodes: None,
                    route_payload_bytes: Some(u64::from(recipient_set.canonical_delivery_bytes())),
                    common_outer_commit_bytes: None,
                    aggregate_cost_bytes: None,
                    state: "authenticated-observed-public-indexes-and-byte-length",
                    provenance:
                        "accepted_signed_commit_plus_authenticated_group_context_and_codec_length",
                });
                event_index = next_index(event_index)?;
            }
            for (variant, cover) in [
                ("C_leaf", &snapshot.exact_covers.c_leaf),
                ("C_new", &snapshot.exact_covers.c_new),
                ("C_old", &snapshot.exact_covers.c_old),
                ("C_ideal", &snapshot.exact_covers.c_ideal),
            ] {
                rows.push(ClearEventRow {
                    event_index,
                    scope: "exact_topology_cover",
                    commit_sequence: Some(event.sequence),
                    phase: "topology-cover",
                    operation: format!("derive-{variant}"),
                    committer_member_index: Some(event.committer_member_index),
                    epoch_before: Some(event.epoch_before),
                    epoch_after: Some(snapshot.epoch),
                    active_member_count: event.active_member_count,
                    commit_bytes: 0,
                    welcome_bytes: 0,
                    cumulative_commit_bytes: adaptive_cumulative,
                    authenticated_tree_version: Some(active.tree_version()),
                    active_tree_height: Some(active_topology.height()),
                    active_tree_leaf_capacity: Some(active_topology.leaf_capacity()),
                    active_tree_occupied_leaf_count: Some(occupied_leaf_count),
                    old_treecover_version: Some(treecover.version()),
                    old_treecover_eligible_member_count: Some(eligible_member_count),
                    old_treecover_eligible_node_count: Some(eligible_node_count),
                    committer_quaternary_leaf_ordinal: Some(
                        snapshot.committer_quaternary_leaf_ordinal,
                    ),
                    recipient_set_index: None,
                    recipient_tree: None,
                    path_node_index: None,
                    recipient_node_indices: None,
                    cover_variant: Some(variant),
                    cover_node_count: Some(
                        u32::try_from(cover.len()).map_err(|_| ClearReportError::Overflow)?,
                    ),
                    cover_nodes: Some(format_cover_nodes(cover)),
                    route_payload_bytes: None,
                    common_outer_commit_bytes: None,
                    aggregate_cost_bytes: None,
                    state: "exact-counterfactual-public-topology",
                    provenance: "authenticated_topology_minimal_disjoint_cover",
                });
                event_index = next_index(event_index)?;
            }
            let route_costs = measure_exact_topology_routes(snapshot, event.emitted_commit_bytes)?;
            for set in &route_costs.recipient_sets {
                for (variant, cover, route_bytes) in [
                    ("C_leaf", &set.covers.c_leaf, set.c_leaf_route_bytes),
                    ("C_new", &set.covers.c_new, set.c_new_route_bytes),
                    ("C_old", &set.covers.c_old, set.c_old_route_bytes),
                    ("C_ideal", &set.covers.c_ideal, set.c_ideal_route_bytes),
                ] {
                    rows.push(ClearEventRow {
                        event_index,
                        scope: "exact_topology_route_cost",
                        commit_sequence: Some(event.sequence),
                        phase: "topology-route",
                        operation: format!("serialize-{variant}"),
                        committer_member_index: Some(event.committer_member_index),
                        epoch_before: Some(event.epoch_before),
                        epoch_after: Some(snapshot.epoch),
                        active_member_count: event.active_member_count,
                        commit_bytes: 0,
                        welcome_bytes: 0,
                        cumulative_commit_bytes: adaptive_cumulative,
                        authenticated_tree_version: Some(active.tree_version()),
                        active_tree_height: Some(active_topology.height()),
                        active_tree_leaf_capacity: Some(active_topology.leaf_capacity()),
                        active_tree_occupied_leaf_count: Some(occupied_leaf_count),
                        old_treecover_version: Some(treecover.version()),
                        old_treecover_eligible_member_count: Some(eligible_member_count),
                        old_treecover_eligible_node_count: Some(eligible_node_count),
                        committer_quaternary_leaf_ordinal: Some(
                            snapshot.committer_quaternary_leaf_ordinal,
                        ),
                        recipient_set_index: Some(set.recipient_set_index),
                        recipient_tree: Some("counterfactual_exact_cover"),
                        path_node_index: Some(set.path_node_index),
                        recipient_node_indices: None,
                        cover_variant: Some(variant),
                        cover_node_count: Some(
                            u32::try_from(cover.len())
                                .map_err(|_| ClearReportError::Overflow)?,
                        ),
                        cover_nodes: Some(format_cover_nodes(cover)),
                        route_payload_bytes: Some(route_bytes),
                        common_outer_commit_bytes: None,
                        aggregate_cost_bytes: None,
                        state: "exact-counterfactual-canonical-codec",
                        provenance:
                            "same_public_payload_binding_authenticated_topology_canonical_hybrid_tls",
                    });
                    event_index = next_index(event_index)?;
                }
            }
            for (variant, node_count, route_bytes, aggregate_bytes) in
                aggregate_cost_rows(&route_costs)?
            {
                rows.push(ClearEventRow {
                    event_index,
                    scope: "aggregate_topology_route_cost",
                    commit_sequence: Some(event.sequence),
                    phase: "topology-route-aggregate",
                    operation: format!("aggregate-{variant}"),
                    committer_member_index: Some(event.committer_member_index),
                    epoch_before: Some(event.epoch_before),
                    epoch_after: Some(snapshot.epoch),
                    active_member_count: event.active_member_count,
                    commit_bytes: event.emitted_commit_bytes,
                    welcome_bytes: 0,
                    cumulative_commit_bytes: adaptive_cumulative,
                    authenticated_tree_version: Some(active.tree_version()),
                    active_tree_height: Some(active_topology.height()),
                    active_tree_leaf_capacity: Some(active_topology.leaf_capacity()),
                    active_tree_occupied_leaf_count: Some(occupied_leaf_count),
                    old_treecover_version: Some(treecover.version()),
                    old_treecover_eligible_member_count: Some(eligible_member_count),
                    old_treecover_eligible_node_count: Some(eligible_node_count),
                    committer_quaternary_leaf_ordinal: Some(
                        snapshot.committer_quaternary_leaf_ordinal,
                    ),
                    recipient_set_index: None,
                    recipient_tree: Some("all_authenticated_path_level_sets"),
                    path_node_index: None,
                    recipient_node_indices: None,
                    cover_variant: Some(variant),
                    cover_node_count: Some(node_count),
                    cover_nodes: None,
                    route_payload_bytes: Some(route_bytes),
                    common_outer_commit_bytes: Some(route_costs.common_outer_commit_bytes),
                    aggregate_cost_bytes: Some(aggregate_bytes),
                    state: "mixed-observed-outer-exact-counterfactual-route",
                    provenance: CORRECTED_COST_PROVENANCE,
                });
                event_index = next_index(event_index)?;
            }
        }
    }

    let last = adaptive
        .iter()
        .find(|event| event.phase == ExperimentalAdaptiveCommitPhase::QuaternaryUpdate)
        .ok_or(ClearReportError::MissingRequiredEvent)?;
    rows.push(ClearEventRow {
        event_index,
        scope: "treecover_retirement_evaluation",
        commit_sequence: None,
        phase: "retirement-unavailable",
        operation: "await-direct-maturity-calculation".to_owned(),
        committer_member_index: None,
        epoch_before: Some(last.epoch_after),
        epoch_after: None,
        active_member_count: last.active_member_count,
        commit_bytes: 0,
        welcome_bytes: 0,
        cumulative_commit_bytes: adaptive_cumulative,
        authenticated_tree_version: None,
        active_tree_height: None,
        active_tree_leaf_capacity: None,
        active_tree_occupied_leaf_count: None,
        old_treecover_version: None,
        old_treecover_eligible_member_count: None,
        old_treecover_eligible_node_count: None,
        committer_quaternary_leaf_ordinal: None,
        recipient_set_index: None,
        recipient_tree: None,
        path_node_index: None,
        recipient_node_indices: None,
        cover_variant: None,
        cover_node_count: None,
        cover_nodes: None,
        route_payload_bytes: None,
        common_outer_commit_bytes: None,
        aggregate_cost_bytes: None,
        state: "unavailable",
        provenance: MATURITY_UNAVAILABLE_REASON,
    });
    Ok(rows)
}

fn next_index(value: u32) -> Result<u32, ClearReportError> {
    value.checked_add(1).ok_or(ClearReportError::Overflow)
}

fn join_node_indices(indices: &[u32]) -> String {
    indices
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(";")
}

fn format_cover_nodes(nodes: &[transition_tree::ExactCoverNode]) -> String {
    nodes
        .iter()
        .map(|node| {
            format!(
                "{}:{}:{}[{}]",
                node.arity,
                node.depth,
                node.ordinal,
                join_node_indices(&node.recipient_quaternary_leaf_ordinals)
            )
        })
        .collect::<Vec<_>>()
        .join("|")
}

type AggregateCostRow = (&'static str, u32, u64, u64);

fn aggregate_cost_rows(
    costs: &ExactTopologyAggregateCost,
) -> Result<[AggregateCostRow; 4], ClearReportError> {
    Ok([
        (
            "C_leaf",
            sum_cover_node_counts(&costs.recipient_sets, |set| set.c_leaf_node_count)?,
            costs.c_leaf_route_bytes,
            costs.c_leaf_bytes,
        ),
        (
            "C_new",
            sum_cover_node_counts(&costs.recipient_sets, |set| set.c_new_node_count)?,
            costs.c_new_route_bytes,
            costs.c_new_bytes,
        ),
        (
            "C_old",
            sum_cover_node_counts(&costs.recipient_sets, |set| set.c_old_node_count)?,
            costs.c_old_route_bytes,
            costs.c_old_bytes,
        ),
        (
            "C_ideal",
            sum_cover_node_counts(&costs.recipient_sets, |set| set.c_ideal_node_count)?,
            costs.c_ideal_route_bytes,
            costs.c_ideal_bytes,
        ),
    ])
}

fn sum_cover_node_counts(
    sets: &[crate::topology_routes::ExactTopologyRouteSetCost],
    select: impl Fn(&crate::topology_routes::ExactTopologyRouteSetCost) -> u32,
) -> Result<u32, ClearReportError> {
    sets.iter().try_fold(0_u32, |sum, set| {
        sum.checked_add(select(set))
            .ok_or(ClearReportError::Overflow)
    })
}

fn operation_text(operation: WorkloadOperation) -> String {
    match operation {
        WorkloadOperation::Update => "update".to_owned(),
        WorkloadOperation::Add { member_index } => format!("add:{member_index}"),
        WorkloadOperation::Remove { member_index } => format!("remove:{member_index}"),
    }
}

fn adaptive_phase(phase: ExperimentalAdaptiveCommitPhase) -> &'static str {
    match phase {
        ExperimentalAdaptiveCommitPhase::NormalBinaryUpdate => "normal-binary",
        ExperimentalAdaptiveCommitPhase::Transition => "transition",
        ExperimentalAdaptiveCommitPhase::QuaternaryUpdate => "quaternary",
    }
}

fn summary_csv(summary: &ClearReportSummary) -> Result<Vec<u8>, ClearReportError> {
    let mut writer = WriterBuilder::new().has_headers(true).from_writer(vec![]);
    writer.serialize(summary).map_err(ClearReportError::Csv)?;
    writer
        .into_inner()
        .map_err(|error| ClearReportError::Csv(error.into_error().into()))
}

fn events_csv(events: &[ClearEventRow]) -> Result<Vec<u8>, ClearReportError> {
    let mut writer = WriterBuilder::new().has_headers(true).from_writer(vec![]);
    for event in events {
        writer.serialize(event).map_err(ClearReportError::Csv)?;
    }
    writer
        .into_inner()
        .map_err(|error| ClearReportError::Csv(error.into_error().into()))
}

fn clear_markdown(summary: &ClearReportSummary, events: &[ClearEventRow]) -> String {
    let mut document = String::new();
    writeln!(document, "# Clear 64-member MLS transition report\n").expect("string write");
    writeln!(
        document,
        "Random committer seed: `{}`. Initial members: `{}`.\n",
        summary.random_committer_seed, summary.member_count
    )
    .expect("string write");
    writeln!(document, "## Requested values\n").expect("string write");
    writeln!(
        document,
        "| C_ideal | C_leaf | C_new | C_old | h_new_cost | h_old_cost | Estimated commits to retirement condition |\n|---:|---:|---:|---:|---|---|---:|\n| {} | {} | {} | {} | {} | {} | {} |\n",
        optional_u64(summary.c_ideal_bytes),
        optional_u64(summary.c_leaf_bytes),
        optional_u64(summary.c_new_bytes),
        optional_u64(summary.c_old_bytes),
        optional_text(summary.h_new_cost.as_deref()),
        optional_text(summary.h_old_cost.as_deref()),
        optional_u32(summary.estimated_commits_to_retirement_condition),
    )
    .expect("string write");
    writeln!(document, "## Bytes by real adaptive phase\n").expect("string write");
    writeln!(
        document,
        "| Normal binary | Transition | Quaternary | Total |\n|---:|---:|---:|---:|\n| {} ({} commits) | {} | {} ({} commits) | {} |\n",
        summary.normal_binary_commit_bytes,
        summary.normal_binary_commit_count,
        summary.transition_commit_bytes,
        summary.quaternary_commit_bytes,
        summary.quaternary_commit_count,
        summary.total_adaptive_commit_bytes,
    )
    .expect("string write");
    writeln!(document, "## Real baseline membership operations\n").expect("string write");
    writeln!(
        document,
        "| Update Commit | Add Commit | Add Welcome | Remove Commit |\n|---:|---:|---:|---:|\n| {} | {} | {} | {} |\n",
        summary.baseline_update_commit_bytes,
        summary.baseline_add_commit_bytes,
        summary.baseline_add_welcome_bytes,
        summary.baseline_remove_commit_bytes,
    )
    .expect("string write");
    writeln!(document, "## Event trace\n").expect("string write");
    writeln!(
        document,
        "| Event | Scope | Phase | Operation | Committer | Members | Commit bytes | State |\n|---:|---|---|---|---:|---:|---:|---|"
    )
    .expect("string write");
    for event in events {
        writeln!(
            document,
            "| {} | {} | {} | {} | {} | {} | {} | {} |",
            event.event_index,
            event.scope,
            event.phase,
            event.operation,
            event
                .committer_member_index
                .map_or_else(|| "—".to_owned(), |value| value.to_string()),
            event.active_member_count,
            event.commit_bytes,
            event.state,
        )
        .expect("string write");
    }
    writeln!(document, "\n## Authenticated topology and recipient sets\n").expect("string write");
    writeln!(document, "| Epoch | Tree version | Active height/capacity/occupied | Old cover version/eligible members/eligible nodes | Committer quaternary leaf | Recipient tree | Path node | Signed route bytes | Recipient node indexes |\n|---:|---:|---|---|---:|---|---:|---:|---|").expect("string write");
    for event in events
        .iter()
        .filter(|event| event.scope == "authenticated_topology_recipient_set")
    {
        writeln!(
            document,
            "| {} | {} | {}/{}/{} | {}/{}/{} | {} | {} | {} | {} | {} |",
            optional_u64(event.epoch_after),
            optional_u32(event.authenticated_tree_version),
            optional_u8(event.active_tree_height),
            optional_u32(event.active_tree_leaf_capacity),
            optional_u32(event.active_tree_occupied_leaf_count),
            optional_u32(event.old_treecover_version),
            optional_u32(event.old_treecover_eligible_member_count),
            optional_u32(event.old_treecover_eligible_node_count),
            optional_u32(event.committer_quaternary_leaf_ordinal),
            event.recipient_tree.unwrap_or("unavailable"),
            optional_u32(event.path_node_index),
            optional_u64(event.route_payload_bytes),
            event
                .recipient_node_indices
                .as_deref()
                .unwrap_or("unavailable"),
        )
        .expect("string write");
    }
    writeln!(document, "\n## Exact topology-derived covers\n").expect("string write");
    writeln!(
        document,
        "Node encoding: `arity:depth:ordinal[covered quaternary recipient ordinals]`.\n"
    )
    .expect("string write");
    writeln!(
        document,
        "| Alternative | Node count | Exact disjoint nodes |\n|---|---:|---|"
    )
    .expect("string write");
    for event in events
        .iter()
        .filter(|event| event.scope == "exact_topology_cover")
    {
        writeln!(
            document,
            "| {} | {} | {} |",
            event.cover_variant.unwrap_or("unavailable"),
            optional_u32(event.cover_node_count),
            event
                .cover_nodes
                .as_deref()
                .unwrap_or("unavailable")
                .replace('|', "<br>"),
        )
        .expect("string write");
    }
    writeln!(document, "\n## Per-set canonical route costs\n").expect("string write");
    writeln!(
        document,
        "| Recipient set | Path node | Alternative | Recipients | Cover nodes | Route bytes |\n|---:|---:|---|---:|---:|---:|"
    )
    .expect("string write");
    for event in events
        .iter()
        .filter(|event| event.scope == "exact_topology_route_cost")
    {
        let recipient_count = event
            .cover_nodes
            .as_deref()
            .map(count_encoded_cover_recipients)
            .unwrap_or(0);
        writeln!(
            document,
            "| {} | {} | {} | {} | {} | {} |",
            optional_u32(event.recipient_set_index),
            optional_u32(event.path_node_index),
            event.cover_variant.unwrap_or("unavailable"),
            recipient_count,
            optional_u32(event.cover_node_count),
            optional_u64(event.route_payload_bytes),
        )
        .expect("string write");
    }
    writeln!(document, "\n## Aggregate corrected costs\n").expect("string write");
    writeln!(
        document,
        "| Alternative | Cover nodes | Common outer Commit bytes | Route bytes | Total cost bytes |\n|---|---:|---:|---:|---:|"
    )
    .expect("string write");
    for event in events
        .iter()
        .filter(|event| event.scope == "aggregate_topology_route_cost")
    {
        writeln!(
            document,
            "| {} | {} | {} | {} | {} |",
            event.cover_variant.unwrap_or("unavailable"),
            optional_u32(event.cover_node_count),
            optional_u64(event.common_outer_commit_bytes),
            optional_u64(event.route_payload_bytes),
            optional_u64(event.aggregate_cost_bytes),
        )
        .expect("string write");
    }
    writeln!(document, "\n## Interpretation\n").expect("string write");
    writeln!(
        document,
        "- Update/Add/Remove rows are real RFC MLS operations on a 64-member starting group."
    )
    .expect("string write");
    writeln!(document, "- Normal-binary, transition, and quaternary rows are a separate real 64-member experimental-fork Update-only run with seeded-random committers.").expect("string write");
    writeln!(document, "- `C_leaf`, `C_new`, `C_old`, and `C_ideal` use exact minimal disjoint covers derived from authenticated topology. Every route carries the same public logical-payload binding and is measured by the production hybrid TLS serializer.").expect("string write");
    writeln!(
        document,
        "- Each corrected `C_*` total is the observed emitted outer Commit minus its signed canonical hybrid deliveries, plus the corresponding exact-counterfactual route bytes. The common outer remainder is counted once, not once per cover node or recipient set."
    )
    .expect("string write");
    writeln!(document, "- The former fixed-width 1/2/4/8 partition replay remains educational-only and is not used by this report.").expect("string write");
    writeln!(
        document,
        "- `h_new_cost`, `h_old_cost`, `t`, and formula retirement remain unavailable: `{}`.",
        optional_text(summary.maturity_unavailable_reason)
    )
    .expect("string write");
    writeln!(
        document,
        "- No retirement formula was evaluated. Live retirement is `{}`. No TreeCover secret deletion is claimed.",
        summary.live_treecover_retirement_state
    )
    .expect("string write");
    document
}

fn optional_u64(value: Option<u64>) -> String {
    value.map_or_else(|| "unavailable".to_owned(), |value| value.to_string())
}

fn optional_u32(value: Option<u32>) -> String {
    value.map_or_else(|| "unavailable".to_owned(), |value| value.to_string())
}

fn optional_u8(value: Option<u8>) -> String {
    value.map_or_else(|| "unavailable".to_owned(), |value| value.to_string())
}

fn optional_text(value: Option<&str>) -> &str {
    value.unwrap_or("unavailable")
}

fn count_encoded_cover_recipients(nodes: &str) -> usize {
    nodes
        .split('|')
        .filter_map(|node| node.split_once('[').map(|(_, recipients)| recipients))
        .map(|recipients| recipients.trim_end_matches(']'))
        .filter(|recipients| !recipients.is_empty())
        .map(|recipients| recipients.split(';').count())
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_csv_publishes_corrected_costs_but_keeps_maturity_unavailable() {
        let summary = ClearReportSummary {
            schema_version: CLEAR_REPORT_SCHEMA_VERSION,
            member_count: CLEAR_REPORT_MEMBER_COUNT,
            random_committer_seed: 42,
            cost_measurement_state: "exact-counterfactual",
            cost_unavailable_reason: None,
            maturity_unavailable_reason: Some(MATURITY_UNAVAILABLE_REASON),
            c_ideal_bytes: Some(22_085),
            c_leaf_bytes: Some(62_261),
            c_new_bytes: Some(22_085),
            c_old_bytes: Some(19_853),
            h_new_cost: None,
            h_old_cost: None,
            retirement_formula_decision: "NotEvaluated",
            retirement_formula_trigger: MATURITY_UNAVAILABLE_REASON,
            estimated_commits_to_retirement_condition: None,
            live_treecover_retirement_state: LIVE_RETIREMENT_STATE,
            baseline_update_commit_bytes: 1,
            baseline_add_commit_bytes: 2,
            baseline_add_welcome_bytes: 3,
            baseline_remove_commit_bytes: 4,
            normal_binary_commit_count: 2,
            normal_binary_commit_bytes: 5,
            transition_commit_count: 1,
            transition_commit_bytes: 6,
            quaternary_commit_count: 1,
            quaternary_commit_bytes: 7,
            total_adaptive_commit_bytes: 18,
            logical_retirement_after_adaptive_commit_sequence: None,
            real_operation_provenance: "real",
            cost_provenance: CORRECTED_COST_PROVENANCE,
        };
        let csv =
            String::from_utf8(summary_csv(&summary).expect("summary CSV")).expect("UTF-8 summary");
        assert!(csv.contains(
            "cost_measurement_state,cost_unavailable_reason,maturity_unavailable_reason"
        ));
        assert!(csv.contains("c_ideal_bytes,c_leaf_bytes,c_new_bytes,c_old_bytes"));
        assert!(csv.contains("h_new_cost,h_old_cost"));
        assert!(csv.contains("normal_binary_commit_bytes"));
        assert!(csv.contains("baseline_add_commit_bytes"));
        assert!(csv.contains("22085,62261,22085,19853"));
        assert!(csv.contains(MATURITY_UNAVAILABLE_REASON));
        assert!(csv.contains("NotEvaluated"));
        assert!(!csv.contains("RetireAuthorizedByFormula"));
        assert!(csv.contains(LIVE_RETIREMENT_STATE));

        let markdown = clear_markdown(&summary, &[]);
        assert!(markdown.contains("| 22085 | 62261 | 22085 | 19853 |"));
        assert!(markdown.contains(MATURITY_UNAVAILABLE_REASON));
        assert!(markdown.contains("No retirement formula was evaluated"));
        assert!(!markdown.contains("authorizes logical retirement"));
    }

    #[test]
    fn event_labels_keep_membership_and_adaptive_scopes_distinct() {
        assert_eq!(operation_text(WorkloadOperation::Update), "update");
        assert_eq!(
            operation_text(WorkloadOperation::Add { member_index: 32 }),
            "add:32"
        );
        assert_eq!(
            adaptive_phase(ExperimentalAdaptiveCommitPhase::QuaternaryUpdate),
            "quaternary"
        );
        assert_eq!(join_node_indices(&[0, 1, 3, 4]), "0;1;3;4");
    }
}
