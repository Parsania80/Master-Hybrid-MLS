#![forbid(unsafe_code)]

//! Safe report-generation boundary.
//!
//! Report code must redact secret material and label all experimental results.

pub mod comparison;
pub mod generation;
pub mod plots;

use arity_state::ArityState;
use experimental_mls_adapter::{
    AcceptedExperimentalBinaryOperation, ExperimentalBinaryWorkloadExecution,
};
use metrics::{
    CommitByteMetrics, CryptoMetrics, CryptoOperation, CryptoOperationMetrics,
    RecipientResolutionMetrics, TopologyMetrics,
};
use serde::Serialize;
use simulation::{BaselineWorkloadConfig, BaselineWorkloadExecution, WorkloadOperation};
use thiserror::Error;
use transition_auth::{AppliedTransitionState, RetiredTransitionState};
use transition_policy::{
    AcceptedCommitRecord, PolicyWindow, PolicyWindowConfig, TransitionStartEvaluation,
};

/// Version of the public per-commit schema introduced by Task 54.
pub const PER_COMMIT_SCHEMA_VERSION: u16 = 1;

/// A metric value that is observed or deliberately represented as unavailable.
///
/// Unavailable is never equivalent to zero, an empty value, or a failed
/// operation. This preserves the distinction between an absent measurement
/// seam and a real observed outcome.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub enum MetricAvailability<T> {
    /// A value was actually observed at the documented instrumentation boundary.
    Observed(T),
    /// No trustworthy value exists for this record at its current boundary.
    Unavailable(MetricUnavailableReason),
}

/// Why a per-commit metric has no observed value.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum MetricUnavailableReason {
    /// No safe instrumentation seam exists in the maintained implementation.
    NotInstrumented,
    /// The selected mode does not use the metric's underlying construction.
    NotApplicable,
    /// Producing the value requires the future experimental MLS fork.
    RequiresExperimentalFork,
    /// No Task 35 policy window was attached to this baseline run.
    PolicyWindowNotAttached,
    /// No authenticated transition has started for this record.
    TransitionNotStarted,
    /// No authenticated TreeCover retirement has occurred for this record.
    TreeCoverNotRetired,
}

/// Stable public identity and placement of one accepted commit.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CommitIdentity {
    /// Public group identifier supplied to the fresh baseline run.
    pub group_id: Vec<u8>,
    /// One-based accepted commit sequence in that run.
    pub sequence: u32,
    /// Public MLS epoch before staging the commit.
    pub epoch_before: u64,
    /// Public MLS epoch after every valid member converged.
    pub epoch_after: u64,
    /// Stable public workload member index of the committer.
    pub committer_member_index: u32,
    /// Public MLS leaf index of the committer before staging.
    pub committer_leaf_index: u32,
    /// Public workload region of the committer before staging.
    pub committer_leaf_region: u32,
    /// Number of active valid members after the commit.
    pub active_member_count_after: u32,
}

/// Actual baseline byte observations plus an explicit candidate-comparison state.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CommitByteObservation {
    /// Actual serialized length of the emitted outer baseline Commit.
    pub emitted_baseline_commit_bytes: u64,
    /// Actual serialized Welcome length when this Add emitted a Welcome.
    pub emitted_welcome_bytes: Option<u64>,
    /// Task 32 current-versus-candidate byte provenance when both sides exist.
    pub comparison: MetricAvailability<CommitByteMetrics>,
}

/// Actual end-to-end timing for an accepted baseline commit.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CommitTimingObservation {
    /// Monotonic time for staging, delivery, merge/join, and convergence verification.
    pub accepted_lifecycle_elapsed_nanoseconds: u128,
}

/// Actual counts from canonical binary-with-mKyber UpdatePath deliveries.
///
/// These are public per-Commit counts captured before optional MLS private
/// framing encryption. They do not contain any ciphertext, key, or secret.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct HybridDeliveryObservation {
    /// Number of hybrid UpdatePath deliveries in the accepted Commit.
    pub hybrid_path_delivery_count: u32,
    /// One-per-delivery mKyber common ciphertext components.
    pub mkyber_common_ciphertext_count: u32,
    /// Per-recipient mKyber ciphertext components.
    pub mkyber_recipient_ciphertext_count: u32,
    /// Per-recipient classical HPKE encapsulations.
    pub classical_hpke_encapsulation_count: u32,
}

/// The three topology and recipient-resolution measurement families.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CommitTopologyObservation {
    /// Public metrics for the current binary topology.
    pub current_binary: MetricAvailability<TopologyMetrics>,
    /// Public metrics for the candidate quaternary topology.
    pub candidate_quaternary: MetricAvailability<TopologyMetrics>,
    /// Canonical recipient-resolution records for UpdatePath levels.
    pub recipient_resolutions: MetricAvailability<Vec<RecipientResolutionMetrics>>,
}

/// Public Task 35/38 window and start-evaluation facts for one commit.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PolicyWindowObservation {
    /// Validated policy controls used for the window.
    pub configuration: PolicyWindowConfig,
    /// Newly retained raw accepted-commit record.
    pub accepted_record: AcceptedCommitRecord,
    /// Current number of post-warmup records in `W_e`.
    pub window_length: u32,
    /// Current impactful-record count `q_e`.
    pub impactful_commit_count: u32,
    /// Current successful-removal total `r_e`.
    pub successful_removal_count: u64,
    /// Five-condition start evaluation when this post-warmup commit was evaluated.
    pub start_evaluation: Option<TransitionStartEvaluation>,
}

/// Authenticated transition state available for one commit after future-fork integration.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TransitionObservation {
    /// Canonical public private-use extension state.
    pub arity_state: ArityState,
    /// Recipient-visible public application state when an educational transition applied.
    pub applied_state: Option<AppliedTransitionState>,
}

/// Authenticated TreeCover-retirement state available after a retirement commit.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RetirementObservation {
    /// Public retirement state staged identically for each educational member.
    pub retired_state: RetiredTransitionState,
}

/// Complete public schema for one accepted logical commit.
///
/// The baseline constructor below fills only directly observed baseline facts.
/// Future experimental instrumentation must replace unavailable values with
/// observations; it must never substitute zeroes or estimates implicitly.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PerCommitMetricRecord {
    /// Schema version for future CSV, JSON, and Markdown generators.
    pub schema_version: u16,
    /// Commit identity, epochs, committer placement, and membership fact.
    pub identity: CommitIdentity,
    /// Actual workload operation after Task 53 feasibility fallback.
    pub operation: WorkloadOperation,
    /// Current/candidate topology and recipient-resolution measurements.
    pub topology: CommitTopologyObservation,
    /// Emitted baseline bytes and candidate-comparison provenance state.
    pub bytes: CommitByteObservation,
    /// Per-operation crypto counts and timings when hooks observed them.
    pub crypto_counts: MetricAvailability<CryptoMetrics>,
    /// Public mKyber/HPKE delivery-component counts when a fork Commit was observed.
    pub hybrid_delivery: MetricAvailability<HybridDeliveryObservation>,
    /// End-to-end accepted-commit timing.
    pub timing: CommitTimingObservation,
    /// Window, `q_e`, `r_e`, and start-evaluation facts.
    pub policy_window: MetricAvailability<PolicyWindowObservation>,
    /// Authenticated arity/transition facts.
    pub transition: MetricAvailability<TransitionObservation>,
    /// Authenticated TreeCover-retirement facts.
    pub retirement: MetricAvailability<RetirementObservation>,
    /// Existing members that processed and merged the Commit message.
    pub direct_commit_delivery_count: u32,
    /// New members that joined through a Welcome rather than the Commit message.
    pub welcome_join_count: u32,
}

/// Errors while converting an accepted baseline workload into Task 54 records.
#[derive(Debug, Error, Eq, PartialEq)]
pub enum PerCommitSchemaError {
    /// A reportable workload needs a non-empty public group identifier.
    #[error("the reportable workload group identifier is empty")]
    EmptyGroupId,
    /// Accepted workload records must have one-based contiguous sequences.
    #[error("accepted workload sequences are not one-based and contiguous")]
    NonContiguousSequence,
    /// Each accepted commit must advance the public MLS epoch by exactly one.
    #[error("an accepted workload record does not advance its epoch by one")]
    InvalidEpochAdvance,
}

impl PerCommitMetricRecord {
    /// Converts fully converged Task 53 baseline outcomes into complete schema records.
    ///
    /// This conversion intentionally has no policy evaluator, candidate topology,
    /// crypto hook, experimental transition, or retirement input. Those sections
    /// are retained as explicit unavailable values rather than fabricated data.
    pub fn from_baseline_workload(
        config: &BaselineWorkloadConfig,
        execution: &BaselineWorkloadExecution,
    ) -> Result<Vec<Self>, PerCommitSchemaError> {
        if config.group_id.is_empty() {
            return Err(PerCommitSchemaError::EmptyGroupId);
        }

        execution
            .accepted_operations
            .iter()
            .enumerate()
            .map(|(offset, accepted)| {
                let sequence = u32::try_from(offset + 1)
                    .map_err(|_| PerCommitSchemaError::NonContiguousSequence)?;
                if accepted.sequence != sequence {
                    return Err(PerCommitSchemaError::NonContiguousSequence);
                }
                if accepted.epoch_before.checked_add(1) != Some(accepted.epoch_after) {
                    return Err(PerCommitSchemaError::InvalidEpochAdvance);
                }
                Ok(Self {
                    schema_version: PER_COMMIT_SCHEMA_VERSION,
                    identity: CommitIdentity {
                        group_id: config.group_id.clone(),
                        sequence: accepted.sequence,
                        epoch_before: accepted.epoch_before,
                        epoch_after: accepted.epoch_after,
                        committer_member_index: accepted.committer_member_index,
                        committer_leaf_index: accepted.committer_leaf_index,
                        committer_leaf_region: accepted.committer_leaf_region,
                        active_member_count_after: accepted.active_member_count,
                    },
                    operation: accepted.operation,
                    topology: CommitTopologyObservation {
                        current_binary: MetricAvailability::Unavailable(
                            MetricUnavailableReason::NotInstrumented,
                        ),
                        candidate_quaternary: MetricAvailability::Unavailable(
                            MetricUnavailableReason::RequiresExperimentalFork,
                        ),
                        recipient_resolutions: MetricAvailability::Unavailable(
                            MetricUnavailableReason::RequiresExperimentalFork,
                        ),
                    },
                    bytes: CommitByteObservation {
                        emitted_baseline_commit_bytes: accepted.measurement.emitted_commit_bytes,
                        emitted_welcome_bytes: accepted.measurement.emitted_welcome_bytes,
                        comparison: MetricAvailability::Unavailable(
                            MetricUnavailableReason::RequiresExperimentalFork,
                        ),
                    },
                    timing: CommitTimingObservation {
                        accepted_lifecycle_elapsed_nanoseconds: accepted
                            .measurement
                            .accepted_lifecycle_elapsed_nanoseconds,
                    },
                    crypto_counts: MetricAvailability::Unavailable(
                        MetricUnavailableReason::NotInstrumented,
                    ),
                    hybrid_delivery: MetricAvailability::Unavailable(
                        MetricUnavailableReason::RequiresExperimentalFork,
                    ),
                    policy_window: MetricAvailability::Unavailable(
                        MetricUnavailableReason::PolicyWindowNotAttached,
                    ),
                    transition: MetricAvailability::Unavailable(
                        MetricUnavailableReason::TransitionNotStarted,
                    ),
                    retirement: MetricAvailability::Unavailable(
                        MetricUnavailableReason::TreeCoverNotRetired,
                    ),
                    direct_commit_delivery_count: accepted.measurement.direct_commit_delivery_count,
                    welcome_join_count: accepted.measurement.welcome_join_count,
                })
            })
            .collect()
    }

    /// Converts accepted normal-binary fork outcomes into Task 54 records.
    ///
    /// The shared workload controls preserve baseline comparability. Only
    /// emitted Commit bytes, lifecycle timing, and hybrid delivery counts are
    /// observed here; transition/candidate/retirement facts remain typed
    /// unavailable until their dedicated integrations exist.
    pub fn from_experimental_binary_workload(
        config: &BaselineWorkloadConfig,
        execution: &ExperimentalBinaryWorkloadExecution,
    ) -> Result<Vec<Self>, PerCommitSchemaError> {
        if config.group_id.is_empty() {
            return Err(PerCommitSchemaError::EmptyGroupId);
        }
        execution
            .accepted_operations
            .iter()
            .enumerate()
            .map(|(offset, accepted)| experimental_binary_record(config, accepted, offset))
            .collect()
    }

    /// Attaches observed policy-window facts after a policy evaluator has run.
    pub fn with_policy_window(mut self, window: PolicyWindowObservation) -> Self {
        self.policy_window = MetricAvailability::Observed(window);
        self
    }

    /// Builds a policy-window observation from the existing policy boundary.
    pub fn policy_window_observation(
        window: &PolicyWindow,
        accepted_record: AcceptedCommitRecord,
        start_evaluation: Option<TransitionStartEvaluation>,
    ) -> Result<PolicyWindowObservation, transition_policy::PolicyError> {
        Ok(PolicyWindowObservation {
            configuration: window.config(),
            accepted_record,
            window_length: window.window_len(),
            impactful_commit_count: window.q_e(),
            successful_removal_count: window.r_e()?,
            start_evaluation,
        })
    }

    /// Attaches observed authenticated transition facts after future-fork integration.
    pub fn with_transition(mut self, transition: TransitionObservation) -> Self {
        self.transition = MetricAvailability::Observed(transition);
        self
    }

    /// Attaches observed authenticated TreeCover-retirement facts.
    pub fn with_retirement(mut self, retirement: RetirementObservation) -> Self {
        self.retirement = MetricAvailability::Observed(retirement);
        self
    }
}

fn experimental_binary_record(
    config: &BaselineWorkloadConfig,
    accepted: &AcceptedExperimentalBinaryOperation,
    offset: usize,
) -> Result<PerCommitMetricRecord, PerCommitSchemaError> {
    let sequence =
        u32::try_from(offset + 1).map_err(|_| PerCommitSchemaError::NonContiguousSequence)?;
    if accepted.sequence != sequence {
        return Err(PerCommitSchemaError::NonContiguousSequence);
    }
    if accepted.epoch_before.checked_add(1) != Some(accepted.epoch_after) {
        return Err(PerCommitSchemaError::InvalidEpochAdvance);
    }
    let measurement = &accepted.measurement;
    let crypto_counts = CryptoMetrics::new(vec![
        CryptoOperationMetrics::counted(
            CryptoOperation::ClassicalEncapsulation,
            measurement.classical_hpke_encapsulation_count,
        ),
        CryptoOperationMetrics::counted(
            CryptoOperation::MkyberEncapsulation,
            measurement.mkyber_common_ciphertext_count,
        ),
    ])
    .expect("fixed canonical experimental crypto metric order");
    Ok(PerCommitMetricRecord {
        schema_version: PER_COMMIT_SCHEMA_VERSION,
        identity: CommitIdentity {
            group_id: config.group_id.clone(),
            sequence: accepted.sequence,
            epoch_before: accepted.epoch_before,
            epoch_after: accepted.epoch_after,
            committer_member_index: accepted.committer_member_index,
            committer_leaf_index: accepted.committer_leaf_index,
            committer_leaf_region: accepted.committer_leaf_region,
            active_member_count_after: accepted.active_member_count,
        },
        operation: accepted.operation,
        topology: CommitTopologyObservation {
            current_binary: MetricAvailability::Unavailable(
                MetricUnavailableReason::NotInstrumented,
            ),
            candidate_quaternary: MetricAvailability::Unavailable(
                MetricUnavailableReason::NotApplicable,
            ),
            recipient_resolutions: MetricAvailability::Unavailable(
                MetricUnavailableReason::NotInstrumented,
            ),
        },
        bytes: CommitByteObservation {
            emitted_baseline_commit_bytes: measurement.emitted_commit_bytes,
            emitted_welcome_bytes: measurement.emitted_welcome_bytes,
            comparison: MetricAvailability::Unavailable(MetricUnavailableReason::NotApplicable),
        },
        crypto_counts: MetricAvailability::Observed(crypto_counts),
        hybrid_delivery: MetricAvailability::Observed(HybridDeliveryObservation {
            hybrid_path_delivery_count: measurement.hybrid_path_delivery_count,
            mkyber_common_ciphertext_count: measurement.mkyber_common_ciphertext_count,
            mkyber_recipient_ciphertext_count: measurement.mkyber_recipient_ciphertext_count,
            classical_hpke_encapsulation_count: measurement.classical_hpke_encapsulation_count,
        }),
        timing: CommitTimingObservation {
            accepted_lifecycle_elapsed_nanoseconds: measurement
                .accepted_lifecycle_elapsed_nanoseconds,
        },
        policy_window: MetricAvailability::Unavailable(
            MetricUnavailableReason::PolicyWindowNotAttached,
        ),
        transition: MetricAvailability::Unavailable(MetricUnavailableReason::TransitionNotStarted),
        retirement: MetricAvailability::Unavailable(MetricUnavailableReason::TreeCoverNotRetired),
        direct_commit_delivery_count: measurement.direct_commit_delivery_count,
        welcome_join_count: measurement.welcome_join_count,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use simulation::{
        execute_baseline_workload, BaselineCommitMeasurement, CommitterStrategy, WorkloadProfile,
    };

    fn config() -> BaselineWorkloadConfig {
        BaselineWorkloadConfig {
            group_id: b"task-54-schema".to_vec(),
            initial_member_count: 2,
            maximum_member_count: 3,
            operation_count: 3,
            region_count: 2,
            committer_strategy: CommitterStrategy::RoundRobin,
            workload_profile: WorkloadProfile::Mixed,
        }
    }

    #[test]
    fn baseline_workload_records_keep_only_observed_baseline_facts() {
        let config = config();
        let execution = execute_baseline_workload(&config).expect("baseline workload");
        let records = PerCommitMetricRecord::from_baseline_workload(&config, &execution)
            .expect("schema records");

        assert_eq!(records.len(), 3);
        assert!(records
            .iter()
            .all(|record| record.schema_version == PER_COMMIT_SCHEMA_VERSION));
        assert!(records
            .iter()
            .all(|record| record.bytes.emitted_baseline_commit_bytes != 0));
        assert!(matches!(
            records[0].topology.current_binary,
            MetricAvailability::Unavailable(MetricUnavailableReason::NotInstrumented)
        ));
        assert!(matches!(
            records[0].transition,
            MetricAvailability::Unavailable(MetricUnavailableReason::TransitionNotStarted)
        ));
        assert!(records.iter().any(|record| record.welcome_join_count == 1));
    }

    #[test]
    fn experimental_binary_records_attach_observed_hybrid_delivery_counts() {
        let mut config = config();
        config.group_id = b"task-59-schema".to_vec();
        config.workload_profile = WorkloadProfile::UpdateOnly;
        config.operation_count = 2;
        config.maximum_member_count = 2;
        let execution = experimental_mls_adapter::execute_experimental_binary_workload(&config)
            .expect("accepted experimental binary workload");
        let records = PerCommitMetricRecord::from_experimental_binary_workload(&config, &execution)
            .expect("experimental schema records");

        assert_eq!(records.len(), 2);
        assert!(records.iter().all(|record| matches!(
            &record.hybrid_delivery,
            MetricAvailability::Observed(observation)
                if observation.mkyber_common_ciphertext_count > 0
                    && observation.mkyber_recipient_ciphertext_count > 0
                    && observation.classical_hpke_encapsulation_count
                        == observation.mkyber_recipient_ciphertext_count
        )));
        assert!(records
            .iter()
            .all(|record| matches!(&record.crypto_counts, MetricAvailability::Observed(_))));
    }

    #[test]
    fn schema_rejects_noncontiguous_or_nonadvancing_public_records() {
        let config = config();
        let execution = BaselineWorkloadExecution {
            accepted_operations: vec![simulation::AcceptedWorkloadOperation {
                sequence: 2,
                committer_member_index: 0,
                committer_leaf_index: 0,
                committer_leaf_region: 0,
                operation: WorkloadOperation::Update,
                epoch_before: 7,
                epoch_after: 7,
                active_member_count: 2,
                measurement: BaselineCommitMeasurement {
                    emitted_commit_bytes: 1,
                    emitted_welcome_bytes: None,
                    direct_commit_delivery_count: 1,
                    welcome_join_count: 0,
                    accepted_lifecycle_elapsed_nanoseconds: 0,
                },
            }],
            final_active_committer_counts: Vec::new(),
            final_epoch: 7,
            final_member_count: 2,
        };
        assert_eq!(
            PerCommitMetricRecord::from_baseline_workload(&config, &execution),
            Err(PerCommitSchemaError::NonContiguousSequence)
        );
        let mut nonadvancing = execution;
        nonadvancing.accepted_operations[0].sequence = 1;
        assert_eq!(
            PerCommitMetricRecord::from_baseline_workload(&config, &nonadvancing),
            Err(PerCommitSchemaError::InvalidEpochAdvance)
        );
    }

    #[test]
    fn serialised_schema_has_every_required_measurement_family() {
        let config = config();
        let execution = execute_baseline_workload(&config).expect("baseline workload");
        let record = PerCommitMetricRecord::from_baseline_workload(&config, &execution)
            .expect("schema records")
            .remove(0);
        let value = serde_json::to_value(record).expect("public JSON");
        let object = value.as_object().expect("record object");
        for field in [
            "identity",
            "topology",
            "bytes",
            "crypto_counts",
            "timing",
            "policy_window",
            "transition",
            "retirement",
        ] {
            assert!(object.contains_key(field), "missing {field}");
        }
    }
}
