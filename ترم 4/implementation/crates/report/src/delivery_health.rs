#![forbid(unsafe_code)]
#![allow(dead_code)]

//! Public node-value health simulation for adaptive delivery.
//!
//! This module models the operator-defined delivery-target counts. One usable
//! internal node costs one send regardless of how many active leaves it
//! covers. It does not retain, derive, or erase real MLS key material.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write as FmtWrite,
    fs,
    path::{Path, PathBuf},
};

use csv::WriterBuilder;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::Serialize;
use thiserror::Error;

use crate::generation::{validate_artifact_directory, write_new, ReportArtifactError};
use experimental_mls_adapter::{
    execute_experimental_delivery_health_workload, ExperimentalBinaryWorkloadError,
    ExperimentalDeliveryHealthOperation,
};

/// Version of the public delivery-health simulation schema.
pub const DELIVERY_HEALTH_SCHEMA_VERSION: u16 = 6;
/// One-row summary CSV.
pub const DELIVERY_HEALTH_SUMMARY_FILE_NAME: &str = "summary.csv";
/// Ordered simulated Commit trace.
pub const DELIVERY_HEALTH_EVENTS_FILE_NAME: &str = "events.csv";
/// Clean human-readable report requested by the operator.
pub const DELIVERY_HEALTH_REPORT_FILE_NAME: &str = "report.md";

const PRE_TRANSITION_UPDATE_COUNT: u32 = 2;
const THETA_NEW_NUMERATOR: i64 = 7;
const THETA_NEW_DENOMINATOR: i64 = 10;
const THETA_OLD_NUMERATOR: i64 = 1;
const THETA_OLD_DENOMINATOR: i64 = 2;
const MAX_SIMULATED_MEMBERS: u32 = 4_096;
const HYBRID_PATH_HEADER_BYTES: u64 = 744;
const HYBRID_RECIPIENT_RECORD_BYTES: u64 = 132;

/// Public controls for one deterministic simulation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeliveryHealthConfig {
    /// Old active-tree arity: `2` or `4`.
    pub initial_arity: u8,
    /// Candidate-tree arity: `4` or `8`, exactly double the initial arity.
    pub target_arity: u8,
    /// Initial active clients.
    pub initial_member_count: u32,
    /// Public deterministic operation/committer seed.
    pub random_seed: u64,
    /// Maximum post-transition Update/Remove Commits.
    pub maximum_post_transition_commits: u32,
}

impl DeliveryHealthConfig {
    /// Validates supported arities and bounded simulation size.
    pub fn validate(self) -> Result<(), DeliveryHealthError> {
        if !matches!((self.initial_arity, self.target_arity), (2, 4) | (4, 8)) {
            return Err(DeliveryHealthError::UnsupportedArityPair);
        }
        if !(2..=MAX_SIMULATED_MEMBERS).contains(&self.initial_member_count) {
            return Err(DeliveryHealthError::InvalidMemberCount);
        }
        if self.initial_member_count <= u32::from(self.initial_arity) {
            return Err(DeliveryHealthError::NewArityCannotWin);
        }
        if self.maximum_post_transition_commits == 0 {
            return Err(DeliveryHealthError::ZeroCommitLimit);
        }
        Ok(())
    }
}

/// Paths created by one delivery-health run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeliveryHealthArtifactPaths {
    /// Final one-row public summary.
    pub summary_csv: PathBuf,
    /// Every simulated Commit and exact count.
    pub events_csv: PathBuf,
    /// Clean Markdown report.
    pub report_markdown: PathBuf,
}

/// Failures from configuration, checked tree arithmetic, or artifact output.
#[derive(Debug, Error)]
pub enum DeliveryHealthError {
    /// Only `2 -> 4` and `4 -> 8` are supported.
    #[error("initial/target arity must be 2/4 or 4/8")]
    UnsupportedArityPair,
    /// The member count is outside the resource-bounded simulation range.
    #[error("initial members must be between 2 and 4096")]
    InvalidMemberCount,
    /// The bounded pre-transition byte model cannot favor the target arity.
    #[error("initial members must exceed the initial arity so the target arity can win")]
    NewArityCannotWin,
    /// At least one post-transition Commit must be permitted.
    #[error("maximum post-transition commits must be positive")]
    ZeroCommitLimit,
    /// Tree coordinate or public count arithmetic overflowed.
    #[error("delivery-health tree arithmetic overflowed")]
    Overflow,
    /// No valid random committer or deletion target remained.
    #[error("delivery-health workload could not select a valid active member")]
    NoEligibleMember,
    /// A required fixed member-to-leaf assignment was absent.
    #[error("delivery-health member mapping is incomplete")]
    MissingMemberMapping,
    /// The maturity denominator was not positive.
    #[error("C_leaf must be greater than C_ideal")]
    NonPositiveDenominator,
    /// Create-new public artifact output failed.
    #[error("delivery-health artifact output failed")]
    Artifact(#[from] ReportArtifactError),
    /// CSV serialization failed.
    #[error("delivery-health CSV serialization failed")]
    Csv(#[source] csv::Error),
    /// The authenticated real fork workload rejected or could not complete.
    #[error("the real fork delivery-health workload failed: {0}")]
    RealFork(#[from] ExperimentalBinaryWorkloadError),
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct TreeNode {
    depth: u8,
    ordinal: u32,
}

#[derive(Clone, Copy, Debug)]
struct TreeLayout {
    arity: u8,
    height: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Member {
    id: u32,
    old_leaf: u32,
    new_leaf: u32,
}

#[derive(Clone, Copy, Debug)]
struct Rational {
    numerator: i64,
    denominator: i64,
}

impl Rational {
    fn text(self) -> String {
        let divisor =
            greatest_common_divisor(self.numerator.unsigned_abs(), self.denominator as u64);
        format!(
            "{}/{}",
            self.numerator / divisor as i64,
            self.denominator / divisor as i64
        )
    }

    fn decimal(self) -> String {
        format!("{:.6}", self.numerator as f64 / self.denominator as f64)
    }
}

#[derive(Clone, Copy, Debug)]
struct DeliveryCounts {
    c_leaf: u32,
    c_new: u32,
    c_old: u32,
    c_real: u32,
    c_ideal: u32,
    h_new: Rational,
    h_old: Rational,
    retire_new: bool,
    retire_old: bool,
}

#[derive(Clone, Copy)]
struct MeasuredEventFacts {
    sequence: u32,
    phase: &'static str,
    operation: &'static str,
    committer: u32,
    removed: Option<u32>,
    t: u32,
    retirement_condition: &'static str,
}

#[derive(Clone, Debug, Serialize)]
struct DeliveryHealthEvent {
    schema_version: u16,
    commit_sequence: u32,
    phase: &'static str,
    operation: &'static str,
    committer_member_index: u32,
    committer_target_node_index: u32,
    removed_member_index: Option<u32>,
    active_member_count: u32,
    impactful_commits_since_transition: Option<u32>,
    new_usable_internal_node_count: Option<u32>,
    old_usable_internal_node_count: Option<u32>,
    c_leaf: Option<u32>,
    c_new: Option<u32>,
    c_old: Option<u32>,
    c_real: Option<u32>,
    c_ideal: Option<u32>,
    h_new_exact: Option<String>,
    h_new_decimal: Option<String>,
    h_old_exact: Option<String>,
    h_old_decimal: Option<String>,
    real_new_arity_probe_bytes: Option<u64>,
    real_old_arity_probe_bytes: Option<u64>,
    real_probe_saving_new_minus_old_bytes: Option<i64>,
    bytes_sent: Option<u64>,
    retirement_condition: &'static str,
}

#[derive(Clone, Debug, Serialize)]
struct DeliveryHealthSummary {
    schema_version: u16,
    provenance: &'static str,
    initial_arity: u8,
    target_arity: u8,
    initial_member_count: u32,
    final_member_count: u32,
    random_seed: u64,
    pre_transition_operation_count: u32,
    post_transition_commit_count: u32,
    add_commit_count: u32,
    update_commit_count: u32,
    remove_commit_count: u32,
    transition_commit_sequence: u32,
    full_transition_commit_bytes_state: &'static str,
    retirement_condition_met: bool,
    retirement_after_impactful_commit: Option<u32>,
    retirement_trigger: &'static str,
    final_c_leaf: u32,
    final_c_new: u32,
    final_c_old: u32,
    final_c_real: u32,
    final_c_ideal: u32,
    final_h_new_exact: String,
    final_h_new_decimal: String,
    final_h_old_exact: String,
    final_h_old_decimal: String,
    average_c_new: String,
    average_c_old: String,
    average_c_real: String,
    average_h_newcost: String,
    average_h_oldcost: String,
    average_bytes_sent: String,
    live_protocol_retirement_state: &'static str,
}

struct SimulationResult {
    summary: DeliveryHealthSummary,
    events: Vec<DeliveryHealthEvent>,
}

fn simulate_real(config: DeliveryHealthConfig) -> Result<SimulationResult, DeliveryHealthError> {
    if (config.initial_arity, config.target_arity) != (2, 4) {
        return Err(DeliveryHealthError::UnsupportedArityPair);
    }
    let execution_config = simulation::BaselineWorkloadConfig {
        group_id: b"task86-real-delivery-health".to_vec(),
        initial_member_count: config.initial_member_count,
        maximum_member_count: config
            .initial_member_count
            .checked_add(16)
            .ok_or(DeliveryHealthError::Overflow)?,
        operation_count: config.maximum_post_transition_commits,
        region_count: 2,
        committer_strategy: simulation::CommitterStrategy::RoundRobin,
        workload_profile: simulation::WorkloadProfile::Mixed,
    };
    let execution = execute_experimental_delivery_health_workload(
        &execution_config,
        config.random_seed,
        config.maximum_post_transition_commits,
    )?;
    let mut events = Vec::new();
    for observation in &execution.pre_transition_observations {
        events.push(DeliveryHealthEvent {
            schema_version: DELIVERY_HEALTH_SCHEMA_VERSION,
            commit_sequence: observation.sequence,
            phase: "pre-transition",
            operation: match observation.operation {
                ExperimentalDeliveryHealthOperation::Add => "add",
                ExperimentalDeliveryHealthOperation::Update => "update",
                ExperimentalDeliveryHealthOperation::Remove => "remove",
            },
            committer_member_index: observation.committer_member_index,
            committer_target_node_index: observation.committer_member_index,
            removed_member_index: None,
            active_member_count: observation.active_member_count,
            impactful_commits_since_transition: None,
            new_usable_internal_node_count: None,
            old_usable_internal_node_count: None,
            c_leaf: None,
            c_new: None,
            c_old: None,
            c_real: None,
            c_ideal: None,
            h_new_exact: None,
            h_new_decimal: None,
            h_old_exact: None,
            h_old_decimal: None,
            real_new_arity_probe_bytes: observation.new_arity_real_probe_bytes,
            real_old_arity_probe_bytes: observation.old_arity_real_probe_bytes,
            real_probe_saving_new_minus_old_bytes: observation
                .real_probe_saving_new_minus_old_bytes,
            bytes_sent: Some(observation.emitted_commit_bytes),
            retirement_condition: observation
                .real_probe_saving_new_minus_old_bytes
                .map(real_probe_decision)
                .unwrap_or("Unavailable"),
        });
    }
    let transition_health = execution.transition.health;
    events.push(DeliveryHealthEvent {
        schema_version: DELIVERY_HEALTH_SCHEMA_VERSION,
        commit_sequence: execution.transition.sequence,
        phase: "transition",
        operation: "transition",
        committer_member_index: execution.transition.committer_member_index,
        committer_target_node_index: execution.transition.committer_quaternary_leaf_ordinal,
        removed_member_index: None,
        active_member_count: config.initial_member_count,
        impactful_commits_since_transition: Some(0),
        new_usable_internal_node_count: Some(0),
        old_usable_internal_node_count: None,
        c_leaf: Some(transition_health.c_leaf),
        c_new: Some(transition_health.c_new),
        c_old: Some(transition_health.c_old),
        c_real: Some(transition_health.c_real),
        c_ideal: Some(transition_health.c_ideal),
        h_new_exact: Some(fraction_text(transition_health.h_new)),
        h_new_decimal: Some(fraction_decimal(transition_health.h_new)),
        h_old_exact: Some(fraction_text(transition_health.h_old)),
        h_old_decimal: Some(fraction_decimal(transition_health.h_old)),
        real_new_arity_probe_bytes: None,
        real_old_arity_probe_bytes: None,
        real_probe_saving_new_minus_old_bytes: None,
        bytes_sent: Some(execution.transition.emitted_commit_bytes),
        retirement_condition: "NotEvaluatedAtTransition",
    });
    for observation in &execution.post_transition_observations {
        let health = observation.health;
        let operation = match observation.operation {
            ExperimentalDeliveryHealthOperation::Add => "add",
            ExperimentalDeliveryHealthOperation::Update => "update",
            ExperimentalDeliveryHealthOperation::Remove => "remove",
        };
        events.push(DeliveryHealthEvent {
            schema_version: DELIVERY_HEALTH_SCHEMA_VERSION,
            commit_sequence: observation.sequence,
            phase: "post-transition",
            operation,
            committer_member_index: observation.committer_member_index,
            committer_target_node_index: observation.committer_quaternary_leaf_ordinal,
            removed_member_index: observation.removed_member_index,
            active_member_count: observation.active_member_count,
            impactful_commits_since_transition: Some(observation.impactful_commit_count),
            new_usable_internal_node_count: Some(observation.usable_new_node_count),
            old_usable_internal_node_count: Some(observation.usable_old_node_count),
            c_leaf: Some(health.c_leaf),
            c_new: Some(health.c_new),
            c_old: Some(health.c_old),
            c_real: Some(health.c_real),
            c_ideal: Some(health.c_ideal),
            h_new_exact: Some(fraction_text(health.h_new)),
            h_new_decimal: Some(fraction_decimal(health.h_new)),
            h_old_exact: Some(fraction_text(health.h_old)),
            h_old_decimal: Some(fraction_decimal(health.h_old)),
            real_new_arity_probe_bytes: None,
            real_old_arity_probe_bytes: None,
            real_probe_saving_new_minus_old_bytes: None,
            bytes_sent: Some(observation.emitted_commit_bytes),
            retirement_condition: retirement_trigger_text_flags(
                health.retire_new,
                health.retire_old,
            ),
        });
    }
    let retirement_health = execution
        .post_transition_observations
        .last()
        .ok_or(DeliveryHealthError::NoEligibleMember)?
        .health;
    let retirement = &execution.retirement;
    events.push(DeliveryHealthEvent {
        schema_version: DELIVERY_HEALTH_SCHEMA_VERSION,
        commit_sequence: retirement.sequence,
        phase: "retirement",
        operation: "retirement",
        committer_member_index: retirement.committer_member_index,
        committer_target_node_index: execution
            .post_transition_observations
            .last()
            .map(|observation| observation.committer_quaternary_leaf_ordinal)
            .unwrap_or_default(),
        removed_member_index: None,
        active_member_count: execution.final_member_count,
        impactful_commits_since_transition: Some(retirement.evidence.impactful_commit_count()),
        new_usable_internal_node_count: Some(
            execution
                .post_transition_observations
                .last()
                .map(|observation| observation.usable_new_node_count)
                .unwrap_or_default(),
        ),
        old_usable_internal_node_count: Some(0),
        c_leaf: Some(retirement_health.c_leaf),
        c_new: Some(retirement_health.c_new),
        c_old: Some(retirement_health.c_old),
        c_real: Some(retirement_health.c_real),
        c_ideal: Some(retirement_health.c_ideal),
        h_new_exact: Some(fraction_text(retirement_health.h_new)),
        h_new_decimal: Some(fraction_decimal(retirement_health.h_new)),
        h_old_exact: Some(fraction_text(retirement_health.h_old)),
        h_old_decimal: Some(fraction_decimal(retirement_health.h_old)),
        real_new_arity_probe_bytes: None,
        real_old_arity_probe_bytes: None,
        real_probe_saving_new_minus_old_bytes: None,
        bytes_sent: Some(retirement.emitted_commit_bytes),
        retirement_condition: "AuthenticatedRetirementCommitAccepted",
    });
    let final_health = execution
        .post_transition_observations
        .last()
        .ok_or(DeliveryHealthError::NoEligibleMember)?
        .health;
    let averages = calculate_post_transition_averages(&events)?;
    let update_commit_count = execution
        .post_transition_observations
        .iter()
        .filter(|observation| observation.operation == ExperimentalDeliveryHealthOperation::Update)
        .count() as u32;
    let add_commit_count = execution
        .pre_transition_observations
        .iter()
        .filter(|observation| observation.operation == ExperimentalDeliveryHealthOperation::Add)
        .count() as u32
        + execution
            .post_transition_observations
            .iter()
            .filter(|observation| observation.operation == ExperimentalDeliveryHealthOperation::Add)
            .count() as u32;
    let remove_commit_count = execution
        .post_transition_observations
        .iter()
        .filter(|observation| observation.operation == ExperimentalDeliveryHealthOperation::Remove)
        .count() as u32;
    Ok(SimulationResult {
        summary: DeliveryHealthSummary {
            schema_version: DELIVERY_HEALTH_SCHEMA_VERSION,
            provenance: "real_fork_authenticated_delivery_health_and_atomic_treecover_erasure",
            initial_arity: 2,
            target_arity: 4,
            initial_member_count: execution.initial_member_count,
            final_member_count: execution.final_member_count,
            random_seed: execution.random_seed,
            pre_transition_operation_count: execution.pre_transition_observations.len() as u32,
            post_transition_commit_count: execution.post_transition_observations.len() as u32,
            add_commit_count,
            update_commit_count,
            remove_commit_count,
            transition_commit_sequence: execution.transition.sequence,
            full_transition_commit_bytes_state: "ObservedRealForkCommitBytes",
            retirement_condition_met: true,
            retirement_after_impactful_commit: Some(retirement.evidence.impactful_commit_count()),
            retirement_trigger: retirement_trigger_text_flags(
                retirement.evidence.retire_new(),
                retirement.evidence.retire_old(),
            ),
            final_c_leaf: final_health.c_leaf,
            final_c_new: final_health.c_new,
            final_c_old: final_health.c_old,
            final_c_real: final_health.c_real,
            final_c_ideal: final_health.c_ideal,
            final_h_new_exact: fraction_text(final_health.h_new),
            final_h_new_decimal: fraction_decimal(final_health.h_new),
            final_h_old_exact: fraction_text(final_health.h_old),
            final_h_old_decimal: fraction_decimal(final_health.h_old),
            average_c_new: averages.c_new,
            average_c_old: averages.c_old,
            average_c_real: averages.c_real,
            average_h_newcost: averages.h_new,
            average_h_oldcost: averages.h_old,
            average_bytes_sent: averages.bytes_sent,
            live_protocol_retirement_state:
                "AuthenticatedAtomicRetirementCommitAndTreeCoverKeyErasure",
        },
        events,
    })
}

fn fraction_text(fraction: transition_tree::DeliveryHealthFraction) -> String {
    format!("{}/{}", fraction.numerator(), fraction.denominator())
}

fn fraction_decimal(fraction: transition_tree::DeliveryHealthFraction) -> String {
    format!(
        "{:.6}",
        fraction.numerator() as f64 / fraction.denominator() as f64
    )
}

/// Runs the deterministic Update/Remove simulation and writes create-new
/// public CSV plus `report.md` artifacts.
pub fn generate_delivery_health_report(
    config: DeliveryHealthConfig,
    output_directory: &Path,
    report_directory: &Path,
) -> Result<DeliveryHealthArtifactPaths, DeliveryHealthError> {
    config.validate()?;
    validate_artifact_directory(output_directory, "output", "delivery-health evidence")?;
    validate_artifact_directory(report_directory, "report", "delivery-health report")?;
    let paths = DeliveryHealthArtifactPaths {
        summary_csv: output_directory.join(DELIVERY_HEALTH_SUMMARY_FILE_NAME),
        events_csv: output_directory.join(DELIVERY_HEALTH_EVENTS_FILE_NAME),
        report_markdown: report_directory.join(DELIVERY_HEALTH_REPORT_FILE_NAME),
    };
    for path in [
        &paths.summary_csv,
        &paths.events_csv,
        &paths.report_markdown,
    ] {
        if path.exists() {
            return Err(DeliveryHealthError::Artifact(
                ReportArtifactError::ArtifactAlreadyExists,
            ));
        }
    }

    let result = simulate_real(config)?;
    fs::create_dir_all(output_directory)
        .map_err(|error| DeliveryHealthError::Artifact(ReportArtifactError::Write(error)))?;
    fs::create_dir_all(report_directory)
        .map_err(|error| DeliveryHealthError::Artifact(ReportArtifactError::Write(error)))?;
    write_new(&paths.summary_csv, &summary_csv(&result.summary)?)?;
    write_new(&paths.events_csv, &events_csv(&result.events)?)?;
    write_new(&paths.report_markdown, markdown(config, &result).as_bytes())?;
    Ok(paths)
}

fn simulate(config: DeliveryHealthConfig) -> Result<SimulationResult, DeliveryHealthError> {
    let old_layout = TreeLayout::new(config.initial_arity, config.initial_member_count)?;
    let new_layout = TreeLayout::new(config.target_arity, config.initial_member_count)?;
    let mut rng = ChaCha20Rng::seed_from_u64(config.random_seed);
    let mut members = transition_members(config.initial_member_count);
    let mut events = Vec::new();
    let mut sequence = 1_u32;

    for _ in 0..PRE_TRANSITION_UPDATE_COUNT {
        let committer = *random_member(&members, &mut rng)?;
        let old_arity_bytes =
            modeled_arity_probe_bytes(member_count(&members)?, config.initial_arity)?;
        let new_arity_bytes =
            modeled_arity_probe_bytes(member_count(&members)?, config.target_arity)?;
        let saving = signed_difference(new_arity_bytes, old_arity_bytes)?;
        if saving >= 0 {
            return Err(DeliveryHealthError::NewArityCannotWin);
        }
        events.push(DeliveryHealthEvent {
            schema_version: DELIVERY_HEALTH_SCHEMA_VERSION,
            commit_sequence: sequence,
            phase: "pre-transition",
            operation: "update",
            committer_member_index: committer.id,
            committer_target_node_index: committer.new_leaf,
            removed_member_index: None,
            active_member_count: member_count(&members)?,
            impactful_commits_since_transition: None,
            new_usable_internal_node_count: None,
            old_usable_internal_node_count: None,
            c_leaf: None,
            c_new: None,
            c_old: None,
            c_real: None,
            c_ideal: None,
            h_new_exact: None,
            h_new_decimal: None,
            h_old_exact: None,
            h_old_decimal: None,
            real_new_arity_probe_bytes: None,
            real_old_arity_probe_bytes: None,
            real_probe_saving_new_minus_old_bytes: None,
            bytes_sent: Some(old_arity_bytes),
            retirement_condition: "NewArityWins",
        });
        sequence = checked_next(sequence)?;
    }

    let transition_committer = random_member(&members, &mut rng)?.id;
    let mut old_usable = all_populated_internal_nodes(old_layout, &members, TreeKind::Old)?;
    let mut new_usable = BTreeSet::new();
    let transition_counts = calculate_counts(
        old_layout,
        new_layout,
        &members,
        transition_committer,
        &new_usable,
        &old_usable,
    )?;
    let transition_delivery_bytes =
        modeled_delivery_bytes(transition_counts.c_real, member_count(&members)?)?;
    let transition_sequence = sequence;
    events.push(measured_event(
        MeasuredEventFacts {
            sequence,
            phase: "transition",
            operation: "transition",
            committer: transition_committer,
            removed: None,
            t: 0,
            retirement_condition: "NotEvaluatedAtTransition",
        },
        &members,
        &new_usable,
        &old_usable,
        transition_counts,
        transition_delivery_bytes,
    )?);
    sequence = checked_next(sequence)?;

    let mut update_count = 0_u32;
    let mut remove_count = 0_u32;
    let mut final_counts = transition_counts;
    let mut retirement_after = None;
    let mut retirement_trigger = "CommitLimitReached";

    for t in 1..=config.maximum_post_transition_commits {
        let remove = members.len() > 2 && rng.gen_bool(0.5);
        let committer_id = random_member(&members, &mut rng)?.id;
        let mut removed_id = None;
        let operation = if remove {
            let target_id = random_other_member(&members, committer_id, &mut rng)?.id;
            let target = member_by_id(&members, target_id)?;
            remove_ancestors(&mut old_usable, old_layout, target.old_leaf)?;
            remove_ancestors(&mut new_usable, new_layout, target.new_leaf)?;
            members.retain(|member| member.id != target_id);
            removed_id = Some(target_id);
            remove_count = remove_count
                .checked_add(1)
                .ok_or(DeliveryHealthError::Overflow)?;
            "remove"
        } else {
            update_count = update_count
                .checked_add(1)
                .ok_or(DeliveryHealthError::Overflow)?;
            "update"
        };
        let committer = member_by_id(&members, committer_id)?;
        add_ancestors(&mut new_usable, new_layout, committer.new_leaf)?;
        final_counts = calculate_counts(
            old_layout,
            new_layout,
            &members,
            committer_id,
            &new_usable,
            &old_usable,
        )?;
        let bytes_sent = modeled_delivery_bytes(final_counts.c_real, member_count(&members)?)?;
        let trigger = retirement_trigger_text(final_counts);
        events.push(measured_event(
            MeasuredEventFacts {
                sequence,
                phase: "post-transition",
                operation,
                committer: committer_id,
                removed: removed_id,
                t,
                retirement_condition: trigger,
            },
            &members,
            &new_usable,
            &old_usable,
            final_counts,
            bytes_sent,
        )?);
        sequence = checked_next(sequence)?;
        if final_counts.retire_new || final_counts.retire_old {
            retirement_after = Some(t);
            retirement_trigger = trigger;
            break;
        }
    }

    let post_transition_commit_count =
        retirement_after.unwrap_or(config.maximum_post_transition_commits);
    let averages = calculate_post_transition_averages(&events)?;
    Ok(SimulationResult {
        summary: DeliveryHealthSummary {
            schema_version: DELIVERY_HEALTH_SCHEMA_VERSION,
            provenance: "public_node_value_availability_simulation_not_live_mls_key_erasure",
            initial_arity: config.initial_arity,
            target_arity: config.target_arity,
            initial_member_count: config.initial_member_count,
            final_member_count: member_count(&members)?,
            random_seed: config.random_seed,
            pre_transition_operation_count: PRE_TRANSITION_UPDATE_COUNT,
            post_transition_commit_count,
            add_commit_count: 0,
            update_commit_count: update_count,
            remove_commit_count: remove_count,
            transition_commit_sequence: transition_sequence,
            full_transition_commit_bytes_state: "UnavailableSimulationHasNoFullMlsCommit",
            retirement_condition_met: retirement_after.is_some(),
            retirement_after_impactful_commit: retirement_after,
            retirement_trigger,
            final_c_leaf: final_counts.c_leaf,
            final_c_new: final_counts.c_new,
            final_c_old: final_counts.c_old,
            final_c_real: final_counts.c_real,
            final_c_ideal: final_counts.c_ideal,
            final_h_new_exact: final_counts.h_new.text(),
            final_h_new_decimal: final_counts.h_new.decimal(),
            final_h_old_exact: final_counts.h_old.text(),
            final_h_old_decimal: final_counts.h_old.decimal(),
            average_c_new: averages.c_new,
            average_c_old: averages.c_old,
            average_c_real: averages.c_real,
            average_h_newcost: averages.h_new,
            average_h_oldcost: averages.h_old,
            average_bytes_sent: averages.bytes_sent,
            live_protocol_retirement_state: "UnsupportedSimulationOnly",
        },
        events,
    })
}

#[derive(Clone, Copy)]
enum TreeKind {
    Old,
    New,
}

impl TreeLayout {
    fn new(arity: u8, member_count: u32) -> Result<Self, DeliveryHealthError> {
        let mut height = 0_u8;
        let mut capacity = 1_u32;
        while capacity < member_count {
            capacity = capacity
                .checked_mul(u32::from(arity))
                .ok_or(DeliveryHealthError::Overflow)?;
            height = height.checked_add(1).ok_or(DeliveryHealthError::Overflow)?;
        }
        Ok(Self { arity, height })
    }

    fn span(self, depth: u8) -> Result<u32, DeliveryHealthError> {
        if depth > self.height {
            return Err(DeliveryHealthError::Overflow);
        }
        u32::from(self.arity)
            .checked_pow(u32::from(self.height - depth))
            .ok_or(DeliveryHealthError::Overflow)
    }

    fn contains(self, node: TreeNode, leaf: u32) -> Result<bool, DeliveryHealthError> {
        let span = self.span(node.depth)?;
        let start = node
            .ordinal
            .checked_mul(span)
            .ok_or(DeliveryHealthError::Overflow)?;
        let end = start
            .checked_add(span)
            .ok_or(DeliveryHealthError::Overflow)?;
        Ok((start..end).contains(&leaf))
    }

    fn ancestors(self, leaf: u32) -> Result<Vec<TreeNode>, DeliveryHealthError> {
        (0..self.height)
            .map(|depth| {
                Ok(TreeNode {
                    depth,
                    ordinal: leaf / self.span(depth)?,
                })
            })
            .collect()
    }

    fn children(self, node: TreeNode) -> Result<Vec<TreeNode>, DeliveryHealthError> {
        if node.depth >= self.height {
            return Ok(Vec::new());
        }
        let first = node
            .ordinal
            .checked_mul(u32::from(self.arity))
            .ok_or(DeliveryHealthError::Overflow)?;
        (0..u32::from(self.arity))
            .map(|offset| {
                Ok(TreeNode {
                    depth: node
                        .depth
                        .checked_add(1)
                        .ok_or(DeliveryHealthError::Overflow)?,
                    ordinal: first
                        .checked_add(offset)
                        .ok_or(DeliveryHealthError::Overflow)?,
                })
            })
            .collect()
    }
}

fn transition_members(member_count: u32) -> Vec<Member> {
    let mut identifiers = (0..member_count).collect::<Vec<_>>();
    identifiers.sort_by_key(|id| format!("member-{id}").into_bytes());
    let new_leaf_by_id = identifiers
        .into_iter()
        .enumerate()
        .map(|(ordinal, id)| (id, ordinal as u32))
        .collect::<BTreeMap<_, _>>();
    (0..member_count)
        .map(|id| Member {
            id,
            old_leaf: id,
            new_leaf: new_leaf_by_id[&id],
        })
        .collect()
}

fn all_populated_internal_nodes(
    layout: TreeLayout,
    members: &[Member],
    kind: TreeKind,
) -> Result<BTreeSet<TreeNode>, DeliveryHealthError> {
    let mut nodes = BTreeSet::new();
    for member in members {
        let leaf = member_leaf(*member, kind);
        add_ancestors(&mut nodes, layout, leaf)?;
    }
    Ok(nodes)
}

fn add_ancestors(
    nodes: &mut BTreeSet<TreeNode>,
    layout: TreeLayout,
    leaf: u32,
) -> Result<(), DeliveryHealthError> {
    nodes.extend(layout.ancestors(leaf)?);
    Ok(())
}

fn remove_ancestors(
    nodes: &mut BTreeSet<TreeNode>,
    layout: TreeLayout,
    leaf: u32,
) -> Result<(), DeliveryHealthError> {
    for node in layout.ancestors(leaf)? {
        nodes.remove(&node);
    }
    Ok(())
}

fn calculate_counts(
    old_layout: TreeLayout,
    new_layout: TreeLayout,
    members: &[Member],
    committer_id: u32,
    new_usable: &BTreeSet<TreeNode>,
    old_usable: &BTreeSet<TreeNode>,
) -> Result<DeliveryCounts, DeliveryHealthError> {
    let committer = member_by_id(members, committer_id)?;
    let new_required =
        required_sibling_nodes(new_layout, committer.new_leaf, members, TreeKind::New)?;
    let c_ideal = u32::try_from(new_required.len()).map_err(|_| DeliveryHealthError::Overflow)?;
    let mut c_new = 0_u32;
    let mut c_real = 0_u32;
    for node in new_required {
        let targets = members_under_node(new_layout, node, members, TreeKind::New)?;
        let new_node_usable = node.depth < new_layout.height && new_usable.contains(&node);
        c_new = c_new
            .checked_add(if new_node_usable {
                1
            } else {
                u32::try_from(targets.len()).map_err(|_| DeliveryHealthError::Overflow)?
            })
            .ok_or(DeliveryHealthError::Overflow)?;
        c_real = c_real
            .checked_add(if new_node_usable {
                1
            } else {
                cover_targets_with_old(
                    old_layout,
                    TreeNode {
                        depth: 0,
                        ordinal: 0,
                    },
                    members,
                    &targets,
                    old_usable,
                )?
            })
            .ok_or(DeliveryHealthError::Overflow)?;
    }

    let old_required =
        required_sibling_nodes(old_layout, committer.old_leaf, members, TreeKind::Old)?;
    let mut c_old = 0_u32;
    for node in old_required {
        c_old = c_old
            .checked_add(node_or_leaf_fallback_count(
                old_layout,
                node,
                members,
                TreeKind::Old,
                old_usable,
            )?)
            .ok_or(DeliveryHealthError::Overflow)?;
    }

    let c_leaf = member_count(members)?;
    let denominator = i64::from(c_leaf) - i64::from(c_ideal);
    if denominator <= 0 {
        return Err(DeliveryHealthError::NonPositiveDenominator);
    }
    let h_new = Rational {
        numerator: i64::from(c_leaf) - i64::from(c_new),
        denominator,
    };
    let h_old = Rational {
        numerator: i64::from(c_leaf) - i64::from(c_old),
        denominator,
    };
    let (retire_new, retire_old) = retirement_conditions(h_new, h_old);
    Ok(DeliveryCounts {
        c_leaf,
        c_new,
        c_old,
        c_real,
        c_ideal,
        h_new,
        h_old,
        retire_new,
        retire_old,
    })
}

fn retirement_conditions(h_new: Rational, h_old: Rational) -> (bool, bool) {
    (
        h_new.numerator * THETA_NEW_DENOMINATOR > THETA_NEW_NUMERATOR * h_new.denominator,
        h_old.numerator * THETA_OLD_DENOMINATOR < THETA_OLD_NUMERATOR * h_old.denominator,
    )
}

fn required_sibling_nodes(
    layout: TreeLayout,
    committer_leaf: u32,
    members: &[Member],
    kind: TreeKind,
) -> Result<Vec<TreeNode>, DeliveryHealthError> {
    let mut required = Vec::new();
    for parent_depth in 0..layout.height {
        let child_depth = parent_depth
            .checked_add(1)
            .ok_or(DeliveryHealthError::Overflow)?;
        let child_span = layout.span(child_depth)?;
        let path_child = committer_leaf / child_span;
        let parent = path_child / u32::from(layout.arity);
        let first_child = parent
            .checked_mul(u32::from(layout.arity))
            .ok_or(DeliveryHealthError::Overflow)?;
        for offset in 0..u32::from(layout.arity) {
            let ordinal = first_child
                .checked_add(offset)
                .ok_or(DeliveryHealthError::Overflow)?;
            if ordinal == path_child {
                continue;
            }
            let node = TreeNode {
                depth: child_depth,
                ordinal,
            };
            if !members_under_node(layout, node, members, kind)?.is_empty() {
                required.push(node);
            }
        }
    }
    Ok(required)
}

fn node_or_leaf_fallback_count(
    layout: TreeLayout,
    node: TreeNode,
    members: &[Member],
    kind: TreeKind,
    usable: &BTreeSet<TreeNode>,
) -> Result<u32, DeliveryHealthError> {
    let contained = members_under_node(layout, node, members, kind)?;
    if node.depth < layout.height && usable.contains(&node) {
        return Ok(1);
    }
    u32::try_from(contained.len()).map_err(|_| DeliveryHealthError::Overflow)
}

fn cover_targets_with_old(
    layout: TreeLayout,
    node: TreeNode,
    members: &[Member],
    targets: &BTreeSet<u32>,
    usable: &BTreeSet<TreeNode>,
) -> Result<u32, DeliveryHealthError> {
    let contained = members_under_node(layout, node, members, TreeKind::Old)?;
    if contained.is_disjoint(targets) {
        return Ok(0);
    }
    if node.depth < layout.height && usable.contains(&node) && contained.is_subset(targets) {
        return Ok(1);
    }
    if node.depth == layout.height {
        return Ok(1);
    }
    layout.children(node)?.iter().try_fold(0_u32, |sum, child| {
        sum.checked_add(cover_targets_with_old(
            layout, *child, members, targets, usable,
        )?)
        .ok_or(DeliveryHealthError::Overflow)
    })
}

fn members_under_node(
    layout: TreeLayout,
    node: TreeNode,
    members: &[Member],
    kind: TreeKind,
) -> Result<BTreeSet<u32>, DeliveryHealthError> {
    let mut member_ids = BTreeSet::new();
    for member in members {
        if layout.contains(node, member_leaf(*member, kind))? {
            member_ids.insert(member.id);
        }
    }
    Ok(member_ids)
}

fn member_leaf(member: Member, kind: TreeKind) -> u32 {
    match kind {
        TreeKind::Old => member.old_leaf,
        TreeKind::New => member.new_leaf,
    }
}

fn member_by_id(members: &[Member], id: u32) -> Result<Member, DeliveryHealthError> {
    members
        .iter()
        .find(|member| member.id == id)
        .copied()
        .ok_or(DeliveryHealthError::MissingMemberMapping)
}

fn random_member<'a>(
    members: &'a [Member],
    rng: &mut impl Rng,
) -> Result<&'a Member, DeliveryHealthError> {
    if members.is_empty() {
        return Err(DeliveryHealthError::NoEligibleMember);
    }
    Ok(&members[rng.gen_range(0..members.len())])
}

fn random_other_member<'a>(
    members: &'a [Member],
    excluded_id: u32,
    rng: &mut impl Rng,
) -> Result<&'a Member, DeliveryHealthError> {
    let eligible = members
        .iter()
        .filter(|member| member.id != excluded_id)
        .collect::<Vec<_>>();
    if eligible.is_empty() {
        return Err(DeliveryHealthError::NoEligibleMember);
    }
    Ok(eligible[rng.gen_range(0..eligible.len())])
}

fn measured_event(
    facts: MeasuredEventFacts,
    members: &[Member],
    new_usable: &BTreeSet<TreeNode>,
    old_usable: &BTreeSet<TreeNode>,
    counts: DeliveryCounts,
    bytes_sent: u64,
) -> Result<DeliveryHealthEvent, DeliveryHealthError> {
    let committer = member_by_id(members, facts.committer)?;
    Ok(DeliveryHealthEvent {
        schema_version: DELIVERY_HEALTH_SCHEMA_VERSION,
        commit_sequence: facts.sequence,
        phase: facts.phase,
        operation: facts.operation,
        committer_member_index: facts.committer,
        committer_target_node_index: committer.new_leaf,
        removed_member_index: facts.removed,
        active_member_count: member_count(members)?,
        impactful_commits_since_transition: Some(facts.t),
        new_usable_internal_node_count: Some(node_count(new_usable)?),
        old_usable_internal_node_count: Some(node_count(old_usable)?),
        c_leaf: Some(counts.c_leaf),
        c_new: Some(counts.c_new),
        c_old: Some(counts.c_old),
        c_real: Some(counts.c_real),
        c_ideal: Some(counts.c_ideal),
        h_new_exact: Some(counts.h_new.text()),
        h_new_decimal: Some(counts.h_new.decimal()),
        h_old_exact: Some(counts.h_old.text()),
        h_old_decimal: Some(counts.h_old.decimal()),
        real_new_arity_probe_bytes: None,
        real_old_arity_probe_bytes: None,
        real_probe_saving_new_minus_old_bytes: None,
        bytes_sent: Some(bytes_sent),
        retirement_condition: facts.retirement_condition,
    })
}

fn retirement_trigger_text(counts: DeliveryCounts) -> &'static str {
    retirement_trigger_text_flags(counts.retire_new, counts.retire_old)
}

fn retirement_trigger_text_flags(retire_new: bool, retire_old: bool) -> &'static str {
    match (retire_new, retire_old) {
        (true, true) => "NewHealthAndOldDegradation",
        (true, false) => "NewHealth",
        (false, true) => "OldDegradation",
        (false, false) => "KeepTreeCover",
    }
}

fn member_count(members: &[Member]) -> Result<u32, DeliveryHealthError> {
    u32::try_from(members.len()).map_err(|_| DeliveryHealthError::Overflow)
}

fn node_count(nodes: &BTreeSet<TreeNode>) -> Result<u32, DeliveryHealthError> {
    u32::try_from(nodes.len()).map_err(|_| DeliveryHealthError::Overflow)
}

fn checked_next(value: u32) -> Result<u32, DeliveryHealthError> {
    value.checked_add(1).ok_or(DeliveryHealthError::Overflow)
}

const fn real_probe_decision(saving_new_minus_old_bytes: i64) -> &'static str {
    if saving_new_minus_old_bytes < 0 {
        "NewArityWins"
    } else if saving_new_minus_old_bytes > 0 {
        "OldArityWins"
    } else {
        "EqualRealBytes"
    }
}

struct PostTransitionAverages {
    c_new: String,
    c_old: String,
    c_real: String,
    h_new: String,
    h_old: String,
    bytes_sent: String,
}

fn modeled_arity_probe_bytes(active_members: u32, arity: u8) -> Result<u64, DeliveryHealthError> {
    let arity = u32::from(arity);
    let delivery_targets = active_members
        .checked_add(arity.checked_sub(1).ok_or(DeliveryHealthError::Overflow)?)
        .ok_or(DeliveryHealthError::Overflow)?
        / arity;
    modeled_delivery_bytes(delivery_targets, active_members)
}

fn modeled_delivery_bytes(
    delivery_targets: u32,
    active_members: u32,
) -> Result<u64, DeliveryHealthError> {
    u64::from(delivery_targets)
        .checked_mul(HYBRID_PATH_HEADER_BYTES)
        .and_then(|headers| {
            u64::from(active_members)
                .checked_mul(HYBRID_RECIPIENT_RECORD_BYTES)
                .and_then(|records| headers.checked_add(records))
        })
        .ok_or(DeliveryHealthError::Overflow)
}

fn signed_difference(left: u64, right: u64) -> Result<i64, DeliveryHealthError> {
    let left = i64::try_from(left).map_err(|_| DeliveryHealthError::Overflow)?;
    let right = i64::try_from(right).map_err(|_| DeliveryHealthError::Overflow)?;
    left.checked_sub(right).ok_or(DeliveryHealthError::Overflow)
}

fn calculate_post_transition_averages(
    events: &[DeliveryHealthEvent],
) -> Result<PostTransitionAverages, DeliveryHealthError> {
    let evaluated = events
        .iter()
        .filter(|event| event.phase == "post-transition")
        .collect::<Vec<_>>();
    let count = u64::try_from(evaluated.len()).map_err(|_| DeliveryHealthError::Overflow)?;
    if count == 0 {
        return Err(DeliveryHealthError::ZeroCommitLimit);
    }
    let mut c_new_sum = 0_u64;
    let mut c_old_sum = 0_u64;
    let mut c_real_sum = 0_u64;
    let mut bytes_sum = 0_u64;
    let mut h_new_sum = 0_f64;
    let mut h_old_sum = 0_f64;
    for event in evaluated {
        let c_leaf = event.c_leaf.ok_or(DeliveryHealthError::Overflow)?;
        let c_new = event.c_new.ok_or(DeliveryHealthError::Overflow)?;
        let c_old = event.c_old.ok_or(DeliveryHealthError::Overflow)?;
        let c_real = event.c_real.ok_or(DeliveryHealthError::Overflow)?;
        let c_ideal = event.c_ideal.ok_or(DeliveryHealthError::Overflow)?;
        let denominator = f64::from(c_leaf) - f64::from(c_ideal);
        if denominator <= 0.0 {
            return Err(DeliveryHealthError::NonPositiveDenominator);
        }
        c_new_sum = c_new_sum
            .checked_add(u64::from(c_new))
            .ok_or(DeliveryHealthError::Overflow)?;
        c_old_sum = c_old_sum
            .checked_add(u64::from(c_old))
            .ok_or(DeliveryHealthError::Overflow)?;
        c_real_sum = c_real_sum
            .checked_add(u64::from(c_real))
            .ok_or(DeliveryHealthError::Overflow)?;
        bytes_sum = bytes_sum
            .checked_add(event.bytes_sent.ok_or(DeliveryHealthError::Overflow)?)
            .ok_or(DeliveryHealthError::Overflow)?;
        h_new_sum += (f64::from(c_leaf) - f64::from(c_new)) / denominator;
        h_old_sum += (f64::from(c_leaf) - f64::from(c_old)) / denominator;
    }
    Ok(PostTransitionAverages {
        c_new: format!("{:.6}", c_new_sum as f64 / count as f64),
        c_old: format!("{:.6}", c_old_sum as f64 / count as f64),
        c_real: format!("{:.6}", c_real_sum as f64 / count as f64),
        h_new: format!("{:.6}", h_new_sum / count as f64),
        h_old: format!("{:.6}", h_old_sum / count as f64),
        bytes_sent: format!("{:.6}", bytes_sum as f64 / count as f64),
    })
}

fn greatest_common_divisor(mut left: u64, mut right: u64) -> u64 {
    while right != 0 {
        let remainder = left % right;
        left = right;
        right = remainder;
    }
    left.max(1)
}

fn summary_csv(summary: &DeliveryHealthSummary) -> Result<Vec<u8>, DeliveryHealthError> {
    let mut writer = WriterBuilder::new().has_headers(true).from_writer(vec![]);
    writer
        .serialize(summary)
        .map_err(DeliveryHealthError::Csv)?;
    writer
        .into_inner()
        .map_err(|error| DeliveryHealthError::Csv(error.into_error().into()))
}

fn events_csv(events: &[DeliveryHealthEvent]) -> Result<Vec<u8>, DeliveryHealthError> {
    let mut writer = WriterBuilder::new().has_headers(true).from_writer(vec![]);
    for event in events {
        writer.serialize(event).map_err(DeliveryHealthError::Csv)?;
    }
    writer
        .into_inner()
        .map_err(|error| DeliveryHealthError::Csv(error.into_error().into()))
}

fn markdown(config: DeliveryHealthConfig, result: &SimulationResult) -> String {
    let summary = &result.summary;
    let mut document = String::new();
    writeln!(document, "# Adaptive delivery-health simulation\n").expect("string write");
    writeln!(
        document,
        "Initial arity: `{}`. Target arity: `{}`. Initial clients: `{}`. Public random seed: `{}`.\n",
        config.initial_arity,
        config.target_arity,
        config.initial_member_count,
        config.random_seed
    )
    .expect("string write");

    writeln!(document, "## Pre-transition byte comparison\n").expect("string write");
    writeln!(document, "The byte comparison uses observed complete serialized Commit wires. `Actual emitted binary Commit bytes` records the live binary Add/Update/Remove Commit. For each row, `Matched fresh binary probe Commit bytes` records a fresh binary Commit with the same active-member count, committer ordinal, operation, and removal target where applicable. `Real quaternary probe Commit bytes` is the authenticated fresh quaternary probe; Add/Remove counterfactual probes remain unavailable. `Real saving` is quaternary minus matched fresh binary, so a negative value means the quaternary Commit is smaller. Before measured Updates, both fresh probes populate their occupied internal nodes; warm-up bytes are excluded. After transition the quaternary tree is authoritative: its CommitSecret and GroupContext tree hash are derived from the quaternary root, the ordinary binary UpdatePath-node vector is empty, and the wire carries exactly `ceil(log4(active clients))` quaternary parent records (four at 128 clients). Retained binary TreeCover values are delivery fallback only and are erased by authenticated retirement. The probes are observed wire data, but they are not merged into the live binary workload state.\n").expect("string write");
    writeln!(
        document,
        "| Commit | Operation | Committer node index | Active clients | Actual emitted binary Commit bytes | Real quaternary probe Commit bytes | Matched fresh binary probe Commit bytes | Real saving | Real decision |\n|---:|---|---:|---:|---:|---:|---:|---:|---|"
    )
    .expect("string write");
    for event in result
        .events
        .iter()
        .filter(|event| event.phase == "pre-transition")
    {
        writeln!(
            document,
            "| {} | {} | {} | {} | {} | {} | {} | {} | {} |",
            event.commit_sequence,
            event.operation,
            event.committer_target_node_index,
            event.active_member_count,
            optional_u64(event.bytes_sent),
            optional_u64(event.real_new_arity_probe_bytes),
            optional_u64(event.real_old_arity_probe_bytes),
            optional_i64(event.real_probe_saving_new_minus_old_bytes),
            event.retirement_condition,
        )
        .expect("string write");
    }

    let transition = result
        .events
        .iter()
        .find(|event| event.phase == "transition")
        .expect("simulation always contains transition");
    writeln!(document, "\n## Transition cost\n").expect("string write");
    writeln!(
        document,
        "| Transition Commit | Committer node index | C_real delivery targets | Full MLS transition Commit bytes |\n|---:|---:|---:|---|\n| {} | {} | {} | {} |\n",
        summary.transition_commit_sequence,
        transition.committer_target_node_index,
        optional_u32(transition.c_real),
        summary.full_transition_commit_bytes_state,
    )
    .expect("string write");
    writeln!(document, "The transition row is the observed full serialized Commit from the experimental fork. Endpoint health uses the retained authenticated availability snapshot after that Commit.\n").expect("string write");

    writeln!(document, "## Post-transition commits\n").expect("string write");
    writeln!(
        document,
        "| Committer node index | Operation type | Usable new nodes | Usable old nodes | C_new endpoint cost | C_old endpoint cost | C_real endpoint cost | h_newcost | h_oldcost | Bytes sent |\n|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|"
    )
    .expect("string write");
    for event in result
        .events
        .iter()
        .filter(|event| event.phase == "post-transition")
    {
        writeln!(
            document,
            "| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |",
            event.committer_target_node_index,
            event.operation,
            optional_u32(event.new_usable_internal_node_count),
            optional_u32(event.old_usable_internal_node_count),
            optional_u32(event.c_new),
            optional_u32(event.c_old),
            optional_u32(event.c_real),
            health_display(event.h_new_exact.as_deref(), event.h_new_decimal.as_deref()),
            health_display(event.h_old_exact.as_deref(), event.h_old_decimal.as_deref()),
            optional_u64(event.bytes_sent),
        )
        .expect("string write");
    }

    writeln!(document, "\n## Transition-end result\n").expect("string write");
    writeln!(
        document,
        "TreeCover is deleted when `h_newcost > 0.7` or `h_oldcost < 0.5`. The condition was **{}** after `{}` post-transition Commit(s); trigger: `{}`. Adds: `{}`. Updates: `{}`. Removes: `{}`. Final clients: `{}`.\n",
        if summary.retirement_condition_met {
            "met"
        } else {
            "not met"
        },
        summary.post_transition_commit_count,
        summary.retirement_trigger,
        summary.add_commit_count,
        summary.update_commit_count,
        summary.remove_commit_count,
        summary.final_member_count,
    )
    .expect("string write");

    writeln!(document, "\n## Counting rules\n").expect("string write");
    writeln!(document, "- `Committer node index` is the committer's target-tree leaf ordinal, not its member identifier.").expect("string write");
    writeln!(document, "- `C_leaf` is the current active-client count, matching the operator's worst-case convention.").expect("string write");
    writeln!(document, "- `C_new` and `C_old` are committer-specific recipient-entry costs, not counts of healthy keys. Better coverage makes these costs decrease toward `C_ideal`; the corresponding health fractions increase. Costs can differ between rows because the random committer path changes.").expect("string write");
    writeln!(document, "- `Usable new nodes` and `Usable old nodes` expose availability separately. Update does not invalidate old nodes. Remove invalidates the removed member's known old and stale-new paths before refreshing the removing committer's new path, so its net usable-new count is not guaranteed to increase.").expect("string write");
    writeln!(document, "- `C_new` evaluates every required target-tree sibling using only the new tree: one send for a usable new-tree node; otherwise one direct send to every active leaf beneath that required node. Old TreeCover values never contribute to `C_new` or `h_newcost`.").expect("string write");
    writeln!(document, "- `C_old` places the same committer in the old TreeCover and recursively selects safe usable old nodes. A missing required old node is split into safe child subtrees, so the count reflects TreeCover recipient entries rather than logical client leaves.").expect("string write");
    writeln!(document, "- `C_real` models actual delivery priority for each required target set: use one usable new-tree node; otherwise use the smallest usable old-TreeCover cover; otherwise send directly to uncovered active leaves. `C_real` does not enter either health formula.").expect("string write");
    writeln!(document, "- `C_ideal` counts the non-empty target-tree sibling nodes when every required internal value is usable.").expect("string write");
    writeln!(document, "- The new tree starts with no usable internal values. An `update` populates the target-tree internal nodes on its committer path. A `remove` invalidates old and new direct-path ancestors known by the removed member, removes that client, then refreshes the removing committer's new-tree path.").expect("string write");
    writeln!(document, "- Operation labels are `add`, `remove`, or `update`; binary operations are randomized across all three, while the post-transition frozen mapping safely permits only `remove` and `update`. A removal never selects its committer as the target.").expect("string write");
    writeln!(document, "\n## Boundary\n").expect("string write");
    writeln!(document, "These rows are real experimental-fork observations. Each accepted Commit was authenticated, atomically merged, and followed by a ciphertext-free retained-availability snapshot. The final row is a signed authenticated retirement Commit; its transaction deletes the retained TreeCover key envelope and exposes only redacted deletion counts. This remains thesis-local experimental software, not an interoperability or production-security claim.").expect("string write");

    writeln!(document, "\n## Post-transition averages\n").expect("string write");
    writeln!(
        document,
        "| Average C_new | Average C_old | Average C_real | Average h_newcost | Average h_oldcost | Average bytes sent |\n|---:|---:|---:|---:|---:|---:|\n| {} | {} | {} | {} | {} | {} |\n",
        summary.average_c_new,
        summary.average_c_old,
        summary.average_c_real,
        summary.average_h_newcost,
        summary.average_h_oldcost,
        summary.average_bytes_sent,
    )
    .expect("string write");
    document
}

fn optional_u32(value: Option<u32>) -> String {
    value.map_or_else(|| "—".to_owned(), |value| value.to_string())
}

fn optional_u64(value: Option<u64>) -> String {
    value.map_or_else(|| "—".to_owned(), |value| value.to_string())
}

fn health_display(exact: Option<&str>, decimal: Option<&str>) -> String {
    match (exact, decimal) {
        (Some(exact), Some(decimal)) => format!("{exact} ({decimal})"),
        _ => "—".to_owned(),
    }
}

fn optional_i64(value: Option<i64>) -> String {
    value.map_or_else(|| "—".to_owned(), |value| value.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(initial_arity: u8, target_arity: u8, members: u32) -> DeliveryHealthConfig {
        DeliveryHealthConfig {
            initial_arity,
            target_arity,
            initial_member_count: members,
            random_seed: 42,
            maximum_post_transition_commits: 128,
        }
    }

    #[test]
    fn ideal_128_member_quaternary_path_is_three_plus_three_plus_three_plus_one() {
        let members = transition_members(128);
        let layout = TreeLayout::new(4, 128).expect("layout");
        let committer = member_by_id(&members, 0).expect("committer");
        let required = required_sibling_nodes(layout, committer.new_leaf, &members, TreeKind::New)
            .expect("ideal siblings");
        assert_eq!(required.len(), 10);
    }

    #[test]
    fn health_routes_use_only_their_own_tree_then_direct_leaf_fallback() {
        let members = transition_members(64);
        let old_layout = TreeLayout::new(2, 64).expect("old layout");
        let new_layout = TreeLayout::new(4, 64).expect("new layout");
        let old_usable =
            all_populated_internal_nodes(old_layout, &members, TreeKind::Old).expect("old nodes");
        let counts = calculate_counts(
            old_layout,
            new_layout,
            &members,
            10,
            &BTreeSet::new(),
            &old_usable,
        )
        .expect("counts");
        assert_eq!(counts.c_leaf, 64);
        assert_eq!(counts.c_ideal, 9);
        assert_eq!(counts.c_new, 63);
        assert_eq!(counts.c_old, 6);
        assert_eq!(counts.c_real, 21);

        let fully_mature_new =
            all_populated_internal_nodes(new_layout, &members, TreeKind::New).expect("new nodes");
        let mature_counts = calculate_counts(
            old_layout,
            new_layout,
            &members,
            10,
            &fully_mature_new,
            &old_usable,
        )
        .expect("mature counts");
        assert_eq!(mature_counts.c_new, mature_counts.c_ideal);
        assert_eq!(mature_counts.c_real, mature_counts.c_ideal);

        let leaf_fallback_counts = calculate_counts(
            old_layout,
            new_layout,
            &members,
            10,
            &BTreeSet::new(),
            &BTreeSet::new(),
        )
        .expect("leaf fallback counts");
        assert_eq!(leaf_fallback_counts.c_new, 63);
        assert_eq!(leaf_fallback_counts.c_old, 63);
        assert_eq!(leaf_fallback_counts.c_real, 63);
    }

    #[test]
    fn one_remove_invalidates_seven_old_values_and_falls_directly_to_leaves() {
        let mut members = transition_members(128);
        let old_layout = TreeLayout::new(2, 128).expect("old layout");
        let new_layout = TreeLayout::new(4, 128).expect("new layout");
        let mut old_usable =
            all_populated_internal_nodes(old_layout, &members, TreeKind::Old).expect("old nodes");
        let mut new_usable = BTreeSet::new();

        remove_ancestors(&mut old_usable, old_layout, 120).expect("remove old path");
        members.retain(|member| member.id != 120);
        let committer = member_by_id(&members, 92).expect("committer");
        add_ancestors(&mut new_usable, new_layout, committer.new_leaf).expect("new path");

        assert_eq!(old_usable.len(), 120);
        let counts = calculate_counts(
            old_layout,
            new_layout,
            &members,
            committer.id,
            &new_usable,
            &old_usable,
        )
        .expect("counts");
        assert_eq!(counts.c_leaf, 127);
        assert_eq!(counts.c_ideal, 10);
        assert_eq!(counts.c_new, 126);
        assert_eq!(counts.c_old, 37);
        assert_eq!(counts.c_real, 37);
        assert_eq!(
            modeled_delivery_bytes(counts.c_real, counts.c_leaf).expect("real-route bytes"),
            44_292
        );
        assert_eq!(counts.h_new.text(), "1/117");
        assert_eq!(counts.h_new.decimal(), "0.008547");
        assert_eq!(counts.h_old.text(), "10/13");
        assert_eq!(counts.h_old.decimal(), "0.769231");
    }

    #[test]
    fn removal_invalidates_old_path_and_never_targets_committer() {
        let result = simulate(config(2, 4, 64)).expect("simulation");
        for event in &result.events {
            assert_ne!(
                event.removed_member_index,
                Some(event.committer_member_index)
            );
        }
        let transition = result
            .events
            .iter()
            .find(|event| event.phase == "transition")
            .expect("transition");
        let first_remove = result
            .events
            .iter()
            .find(|event| event.operation == "remove")
            .expect("seed-42 remove");
        assert!(
            first_remove.old_usable_internal_node_count < transition.old_usable_internal_node_count
        );
        assert!(result.summary.post_transition_commit_count >= 1);
        assert_eq!(
            result.summary.live_protocol_retirement_state,
            "UnsupportedSimulationOnly"
        );
    }

    #[test]
    fn supported_pairs_and_resource_bounds_fail_closed() {
        assert!(config(2, 4, 64).validate().is_ok());
        assert!(config(4, 8, 128).validate().is_ok());
        assert!(matches!(
            config(2, 8, 64).validate(),
            Err(DeliveryHealthError::UnsupportedArityPair)
        ));
        assert!(matches!(
            config(2, 4, 1).validate(),
            Err(DeliveryHealthError::InvalidMemberCount)
        ));
        assert!(matches!(
            config(2, 4, 2).validate(),
            Err(DeliveryHealthError::NewArityCannotWin)
        ));
    }

    #[test]
    fn byte_tables_averages_and_strict_threshold_match_the_report_contract() {
        assert_eq!(
            modeled_arity_probe_bytes(128, 2).expect("old bytes"),
            64_512
        );
        assert_eq!(
            modeled_arity_probe_bytes(128, 4).expect("new bytes"),
            40_704
        );
        assert_eq!(signed_difference(40_704, 64_512).expect("saving"), -23_808);
        assert_eq!(
            retirement_conditions(
                Rational {
                    numerator: 7,
                    denominator: 10,
                },
                Rational {
                    numerator: 1,
                    denominator: 2,
                },
            ),
            (false, false)
        );
        assert_eq!(
            retirement_conditions(
                Rational {
                    numerator: 701,
                    denominator: 1_000,
                },
                Rational {
                    numerator: 1,
                    denominator: 2,
                },
            ),
            (true, false)
        );

        let config = config(2, 4, 128);
        let result = simulate(config).expect("simulation");
        let report = markdown(config, &result);
        assert!(report.contains(
            "| Committer node index | Operation type | C_new | C_old | C_real | h_newcost | h_oldcost | Bytes sent |"
        ));
        assert!(report.contains(
            "| Average C_new | Average C_old | Average C_real | Average h_newcost | Average h_oldcost | Average bytes sent |"
        ));
        assert!(!report.contains("Modeled saving"));
        assert!(report.contains("Real quaternary probe Commit bytes"));
        assert!(report.contains("Matched fresh binary probe Commit bytes"));
        assert!(report.contains("h_newcost > 0.7"));
        assert!(report.contains("1/117 (0.008547)"));
        assert!(report.contains("10/13 (0.769231)"));
    }
}
