#![forbid(unsafe_code)]

//! Isolated activation boundary for the local experimental OpenMLS fork.
//!
//! This crate deliberately links the separately named fork without exposing
//! it through the unchanged baseline adapter. Its public workload client is
//! deliberately restricted to normal binary mKyber self-updates accepted by
//! the fork's atomic application boundary. The created groups nevertheless
//! require the private-use ArityState capability so Task 60 transition Commits
//! can be authenticated by every member.

use std::{collections::BTreeMap, time::Instant};

use adaptive_tree::{BinaryLeafMember, BinaryToQuaternaryLeafMapping, ShadowQuaternaryTree};
use arity_state::{
    hash_canonical_public_bytes, ArityPolicySnapshot, ArityState, MappingHash,
    TransitionEvaluationState, TreeCoverBinding,
};
use mkyber::MkyberDomain;
use openmls_hybrid::{
    experimental_hybrid::{mkyber_recipient_capabilities, ExperimentalHybridCommitMetrics},
    prelude::{
        BasicCredential, Ciphersuite, CredentialWithKey, Extension, ExtensionType, Extensions,
        GroupContext, GroupId, KeyPackage, LeafNodeParameters, MlsGroup, MlsGroupCreateConfig,
        MlsGroupJoinConfig, MlsMessageBodyIn, MlsMessageIn, ProcessedMessageContent,
        RequiredCapabilitiesExtension, StagedCommit, StagedWelcome, UnknownExtension,
    },
};
use openmls_hybrid_basic_credential::SignatureKeyPair;
use openmls_hybrid_rust_crypto::OpenMlsRustCrypto;
use simulation::{
    build_committer_schedule, BaselineWorkloadConfig, CommitterSelection, EligibleCommitter,
    WorkloadOperation, WorkloadProfile,
};
use thiserror::Error;
use tls_codec::{Deserialize as TlsDeserializeTrait, Serialize as TlsSerializeTrait};
use transition_policy::{
    CommitImpactFacts, DeltaThreshold, ImpactfulCommitByteCosts, PolicyTransitionState,
    PolicyWindow, PolicyWindowConfig, PreflightSavings, TransitionByteComparison,
    TransitionByteComponent, TransitionByteRange, TransitionPreflightMeasurement,
    TransitionStartConfig, TransitionStartEvaluation, TransitionStartEvaluator,
};
use transition_tree::DeliveryOnlyTreeCover;

/// Exact upstream OpenMLS revision used by the local fork.
pub const OPENMLS_HYBRID_UPSTREAM_REVISION: &str = "47dbedecad0c1fd8eb5368d582250ebfcc1e1ce6";

/// Confirms that the opt-in fork package is linked into this isolated boundary.
pub fn fork_ciphersuite_type_name() -> &'static str {
    std::any::type_name::<openmls_hybrid::prelude::Ciphersuite>()
}

/// Public direct observations from one accepted binary-with-mKyber Commit.
///
/// The counts are extracted from the emitted, authenticated hybrid UpdatePath
/// deliveries. They contain no secret or ciphertext values.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExperimentalBinaryCommitMeasurement {
    /// Serialized byte length of the emitted outer experimental Commit.
    pub emitted_commit_bytes: u64,
    /// No Welcome is emitted by the currently supported self-update-only client.
    pub emitted_welcome_bytes: Option<u64>,
    /// Existing valid members that atomically processed the Commit.
    pub direct_commit_delivery_count: u32,
    /// New members that joined through a Welcome for this operation.
    pub welcome_join_count: u32,
    /// End-to-end accepted Commit lifecycle time, including convergence check.
    pub accepted_lifecycle_elapsed_nanoseconds: u128,
    /// Number of authenticated hybrid UpdatePath deliveries in the Commit.
    pub hybrid_path_delivery_count: u32,
    /// Number of one-per-delivery mKyber common ciphertext components.
    pub mkyber_common_ciphertext_count: u32,
    /// Number of per-recipient mKyber ciphertext components.
    pub mkyber_recipient_ciphertext_count: u32,
    /// Number of per-recipient classical HPKE encapsulations.
    pub classical_hpke_encapsulation_count: u32,
}

/// One accepted and converged binary-with-mKyber workload operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcceptedExperimentalBinaryOperation {
    /// One-based accepted workload sequence.
    pub sequence: u32,
    /// Stable public workload member identifier of the committer.
    pub committer_member_index: u32,
    /// Public MLS leaf index before staging.
    pub committer_leaf_index: u32,
    /// Public workload region label before staging.
    pub committer_leaf_region: u32,
    /// Actual supported operation, always a self-update for Task 59.
    pub operation: WorkloadOperation,
    /// Public MLS epoch before staging.
    pub epoch_before: u64,
    /// Public MLS epoch after all valid members converge.
    pub epoch_after: u64,
    /// Active member count after acceptance.
    pub active_member_count: u32,
    /// Direct public measurements from the accepted Commit.
    pub measurement: ExperimentalBinaryCommitMeasurement,
}

/// Safe public result of a converged experimental binary workload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExperimentalBinaryWorkloadExecution {
    /// Accepted operations in contiguous sequence order.
    pub accepted_operations: Vec<AcceptedExperimentalBinaryOperation>,
    /// Final converged public MLS epoch.
    pub final_epoch: u64,
    /// Final valid member count.
    pub final_member_count: u32,
}

/// The real application phase of one accepted adaptive Commit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExperimentalAdaptiveCommitPhase {
    /// A normal binary hybrid self-update that supplies the policy observation.
    NormalBinaryUpdate,
    /// The authenticated `Normal -> Transitioning` GroupContext Commit.
    Transition,
    /// A hybrid self-update accepted under quaternary epoch authority.
    QuaternaryUpdate,
}

/// Public observed and estimated facts attached to the real transition Commit.
///
/// The preflight is an estimate obtained from a separately executed real probe
/// transition. The `actual_bytes` comparison is the emitted transition Commit
/// from this workload. The probe is necessary because the current fork has no
/// side-effect-free transition preview API.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExperimentalAdaptiveTransitionMeasurement {
    /// Explicitly estimated preflight from a real, separately executed probe Commit.
    pub preflight: TransitionPreflightMeasurement,
    /// Observed estimate-versus-actual byte comparison for this transition.
    pub byte_comparison: TransitionByteComparison,
    /// Exact saving calculation: current normal wire is observed and the
    /// quaternary candidate is the real probe wire, therefore estimated.
    pub preflight_savings: PreflightSavings,
    /// Number of public members frozen in the authenticated delivery-only TreeCover.
    pub treecover_member_count: u32,
    /// Public immutable quaternary topology derived from the transition mapping.
    pub quaternary_topology: ShadowQuaternaryTree,
    /// The five-condition decision that authorized this transition.
    pub start_evaluation: TransitionStartEvaluation,
}

/// One accepted and converged adaptive workload Commit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcceptedExperimentalAdaptiveOperation {
    /// One-based Commit sequence including the transition Commit.
    pub sequence: u32,
    /// Which real adaptive boundary accepted this Commit.
    pub phase: ExperimentalAdaptiveCommitPhase,
    /// Stable public workload member identifier of the committer.
    pub committer_member_index: u32,
    /// Public MLS leaf index before staging.
    pub committer_leaf_index: u32,
    /// Public workload region before staging.
    pub committer_leaf_region: u32,
    /// Public MLS epoch before staging.
    pub epoch_before: u64,
    /// Public MLS epoch after convergence.
    pub epoch_after: u64,
    /// Active member count after acceptance.
    pub active_member_count: u32,
    /// Serialized emitted Commit length from this accepted operation.
    pub emitted_commit_bytes: u64,
    /// Existing valid members that atomically processed the Commit.
    pub direct_commit_delivery_count: u32,
    /// End-to-end accepted lifecycle time including convergence checks.
    pub accepted_lifecycle_elapsed_nanoseconds: u128,
    /// Hybrid delivery counts where the fork exposes them for an UpdatePath.
    pub hybrid_delivery: Option<ExperimentalHybridCommitMetrics>,
    /// Public authenticated ArityState after this Commit.
    pub arity_state: ArityState,
    /// The post-warmup policy record, when this phase updates the policy window.
    pub policy_record: Option<transition_policy::AcceptedCommitRecord>,
    /// Real transition-only measurements.
    pub transition: Option<ExperimentalAdaptiveTransitionMeasurement>,
}

/// Explicit lifecycle result for the old TreeCover at the end of a run.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExperimentalAdaptiveRetirementStatus {
    /// The fork has no authenticated atomic `Transitioning -> Normal` retirement Commit.
    UnsupportedNoAuthenticatedRetirementCommit,
}

/// Safe public result of a real adaptive transition and quaternary-update run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExperimentalAdaptiveWorkloadExecution {
    /// Every accepted normal, transition, and quaternary Commit in order.
    pub accepted_operations: Vec<AcceptedExperimentalAdaptiveOperation>,
    /// Final converged public MLS epoch.
    pub final_epoch: u64,
    /// Final valid member count.
    pub final_member_count: u32,
    /// Explicit unsupported retirement boundary, never a fabricated erasure fact.
    pub retirement_status: ExperimentalAdaptiveRetirementStatus,
}

/// Errors from the Task 59 binary-with-mKyber workload boundary.
#[derive(Debug, Error)]
pub enum ExperimentalBinaryWorkloadError {
    /// The shared public workload controls are invalid for this client.
    #[error("the experimental workload has invalid public controls")]
    InvalidControls,
    /// Task 59 deliberately supports only real binary hybrid self-updates.
    #[error("Task 59 accepts only the update-only workload profile")]
    UnsupportedWorkloadProfile,
    /// The fork rejected a required operation or an emitted wire value.
    #[error("the experimental fork rejected a required binary workload operation")]
    Fork,
    /// A public count cannot be represented safely.
    #[error("an experimental workload measurement count overflowed")]
    CountOverflow,
    /// A supposed hybrid Commit did not contain accepted hybrid delivery evidence.
    #[error("an accepted experimental Commit did not contain a hybrid UpdatePath delivery")]
    MissingHybridDelivery,
    /// Valid members did not converge after an atomic Commit application.
    #[error("valid experimental workload members did not converge")]
    DivergentPublicState,
    /// The real probe estimate did not authorize the configured adaptive transition.
    #[error(
        "the measured adaptive policy did not authorize a transition: binary {current_binary_update_bytes} bytes, quaternary candidate {quaternary_candidate_bytes} bytes, preflight {transition_preflight_bytes} bytes"
    )]
    TransitionNotAuthorized {
        /// Observed outer byte length of the measured normal binary UpdatePath Commit.
        current_binary_update_bytes: u64,
        /// Observed outer byte length of the real fresh-group quaternary probe Commit.
        quaternary_candidate_bytes: u64,
        /// Explicitly estimated transition preflight byte length from the real probe.
        transition_preflight_bytes: u64,
    },
}

struct ExperimentalWorkloadMember {
    member_index: u32,
    leaf_region: u32,
    provider: OpenMlsRustCrypto,
    signer: SignatureKeyPair,
    group: MlsGroup,
}

struct AcceptedRecordInput {
    sequence: u32,
    epoch_before: u64,
    epoch_after: u64,
    active_member_count: u32,
    emitted_commit_bytes: u64,
    direct_commit_delivery_count: u32,
    elapsed_nanoseconds: u128,
    metrics: ExperimentalHybridCommitMetrics,
}

/// Executes a reproducible normal-binary mKyber workload from the same public
/// controls used by the baseline scheduler.
///
/// The public group ID, member/region counts, committer strategy, and operation
/// count are shared controls. `UpdateOnly` is intentionally the only supported
/// profile: every record is an accepted fork Commit merged through Task 58's
/// atomic sender/receiver APIs. mKyber keys and Commit randomness remain
/// OS-backed protocol entropy; the public schedule is reproducible, not the
/// cryptographic bytes or timing samples.
pub fn execute_experimental_binary_workload(
    config: &BaselineWorkloadConfig,
) -> Result<ExperimentalBinaryWorkloadExecution, ExperimentalBinaryWorkloadError> {
    validate_controls(config)?;
    let mut members = create_initial_group(config)?;
    let mut accepted_operations = Vec::new();
    let mut committer_counts = BTreeMap::<u32, u32>::new();

    for sequence in 1..=config.operation_count {
        let eligible = members
            .iter()
            .map(|member| EligibleCommitter {
                member_index: member.member_index,
                // Sequential Add operations preserve this stable initial leaf
                // placement; Task 59 performs no Add/Remove after setup.
                leaf_index: member.member_index,
                leaf_region: member.leaf_region,
            })
            .collect::<Vec<_>>();
        let schedule =
            build_committer_schedule(&eligible, config.committer_strategy.clone(), sequence)
                .map_err(|_| ExperimentalBinaryWorkloadError::InvalidControls)?;
        let selection = schedule
            .selections
            .last()
            .ok_or(ExperimentalBinaryWorkloadError::InvalidControls)?;
        let committer_position = members
            .iter()
            .position(|member| member.member_index == selection.member_index)
            .ok_or(ExperimentalBinaryWorkloadError::DivergentPublicState)?;
        let epoch_before = members[committer_position].group.epoch().as_u64();
        let started = Instant::now();
        let (wire, hybrid_metrics) = stage_self_update(&mut members[committer_position])?;
        if hybrid_metrics.hybrid_path_delivery_count() == 0 {
            return Err(ExperimentalBinaryWorkloadError::MissingHybridDelivery);
        }
        let direct_commit_delivery_count =
            deliver_to_receivers(&mut members, committer_position, &wire)?;
        let committer = &mut members[committer_position];
        committer
            .group
            .merge_pending_commit_experimental_atomic(&committer.provider)
            .map_err(|_| ExperimentalBinaryWorkloadError::Fork)?;
        let epoch_after = converged_epoch(&members)?;
        if epoch_after
            != epoch_before
                .checked_add(1)
                .ok_or(ExperimentalBinaryWorkloadError::CountOverflow)?
        {
            return Err(ExperimentalBinaryWorkloadError::DivergentPublicState);
        }
        *committer_counts.entry(selection.member_index).or_default() += 1;
        accepted_operations.push(record_accepted_operation(
            selection,
            AcceptedRecordInput {
                sequence,
                epoch_before,
                epoch_after,
                active_member_count: u32::try_from(members.len())
                    .map_err(|_| ExperimentalBinaryWorkloadError::CountOverflow)?,
                emitted_commit_bytes: u64::try_from(wire.len())
                    .map_err(|_| ExperimentalBinaryWorkloadError::CountOverflow)?,
                direct_commit_delivery_count,
                elapsed_nanoseconds: started.elapsed().as_nanos(),
                metrics: hybrid_metrics,
            },
        ));
    }

    Ok(ExperimentalBinaryWorkloadExecution {
        final_epoch: converged_epoch(&members)?,
        final_member_count: u32::try_from(members.len())
            .map_err(|_| ExperimentalBinaryWorkloadError::CountOverflow)?,
        accepted_operations,
    })
}

/// Executes a real adaptive workload through a measured binary-to-quaternary
/// transition.
///
/// The supplied controls remain comparable with the baseline and Task 59
/// client. This first adaptive client supports update-only workloads with at
/// least two requested updates. It retains real normal-binary observations
/// until the policy authorizes the transition or the configured schedule is
/// exhausted. Any remaining scheduled updates execute through the fork's
/// quaternary atomic APIs.
///
/// The policy's candidate and transition-preflight byte inputs come from a
/// separate real probe run because the fork currently lacks a side-effect-free
/// transition preview. They are retained as estimates and compared with the
/// real emitted transition; they are never relabeled as observations from the
/// measured group. Old TreeCover retirement is explicitly unsupported because
/// the fork has no authenticated retirement Commit API.
pub fn execute_experimental_adaptive_workload(
    config: &BaselineWorkloadConfig,
) -> Result<ExperimentalAdaptiveWorkloadExecution, ExperimentalBinaryWorkloadError> {
    validate_controls(config)?;
    if config.operation_count < 2 {
        return Err(ExperimentalBinaryWorkloadError::InvalidControls);
    }

    let probe = measure_adaptive_probe(config)?;
    let preflight = TransitionPreflightMeasurement::from_serialized_outer_message(
        &probe.transition_wire,
        &[TransitionByteRange::new(
            TransitionByteComponent::BaseCommit,
            0,
            probe.transition_wire.len(),
        )],
    )
    .map_err(|_| ExperimentalBinaryWorkloadError::Fork)?;
    let policy_extensions = adaptive_normal_arity_extensions(config, preflight)?;
    let mut members = create_initial_group_with_extensions(config, policy_extensions)?;
    let member_count =
        u32::try_from(members.len()).map_err(|_| ExperimentalBinaryWorkloadError::CountOverflow)?;
    let mut accepted_operations = Vec::new();
    let mut policy_window = PolicyWindow::new(adaptive_policy_window_config()?);
    let mut sequence = 1_u32;

    let normal_selection = select_committer(&members, config, 1)?;
    let normal_position = member_position(&members, normal_selection.member_index)?;
    let normal_epoch_before = members[normal_position].group.epoch().as_u64();
    let normal_started = Instant::now();
    let (normal_wire, normal_hybrid_metrics) = stage_self_update(&mut members[normal_position])?;
    let normal_deliveries = deliver_to_receivers(&mut members, normal_position, &normal_wire)?;
    merge_sender_binary(&mut members[normal_position])?;
    let normal_epoch_after = converged_epoch(&members)?;
    ensure_epoch_advance(normal_epoch_before, normal_epoch_after)?;
    let policy_outcome = policy_window
        .append_accepted(
            normal_epoch_after,
            CommitImpactFacts {
                path_delivery_changed: true,
                recipient_resolution_changed: true,
                ..CommitImpactFacts::default()
            },
        )
        .map_err(|_| ExperimentalBinaryWorkloadError::Fork)?;
    let policy_record = policy_outcome.record;
    accepted_operations.push(AcceptedExperimentalAdaptiveOperation {
        sequence,
        phase: ExperimentalAdaptiveCommitPhase::NormalBinaryUpdate,
        committer_member_index: normal_selection.member_index,
        committer_leaf_index: normal_selection.leaf_index,
        committer_leaf_region: normal_selection.leaf_region,
        epoch_before: normal_epoch_before,
        epoch_after: normal_epoch_after,
        active_member_count: member_count,
        emitted_commit_bytes: u64::try_from(normal_wire.len())
            .map_err(|_| ExperimentalBinaryWorkloadError::CountOverflow)?,
        direct_commit_delivery_count: normal_deliveries,
        accepted_lifecycle_elapsed_nanoseconds: normal_started.elapsed().as_nanos(),
        hybrid_delivery: Some(normal_hybrid_metrics),
        arity_state: arity_state_from_group(&members[0].group)?,
        policy_record: Some(policy_record.clone()),
        transition: None,
    });
    sequence = sequence
        .checked_add(1)
        .ok_or(ExperimentalBinaryWorkloadError::CountOverflow)?;

    let normal_candidate_bytes = probe
        .quaternary_update_bytes_by_member
        .get(&normal_selection.member_index)
        .copied()
        .ok_or(ExperimentalBinaryWorkloadError::Fork)?;
    let mut last_candidate_bytes = normal_candidate_bytes;
    let mut costs = vec![ImpactfulCommitByteCosts::new(
        u64::try_from(normal_wire.len())
            .map_err(|_| ExperimentalBinaryWorkloadError::CountOverflow)?,
        normal_candidate_bytes,
    )];
    let mut last_current_bytes = costs[0].current_bytes();
    let mut transition_selection = None;
    let mut transition_position = None;
    let mut transition_workload_sequence = None;
    let mut transition_record = policy_record;
    let mut transition_savings = None;
    let mut transition_evaluation = None;
    for workload_sequence in 2..=config.operation_count {
        let selection = select_committer(&members, config, workload_sequence)?;
        let candidate_bytes = probe
            .quaternary_update_bytes_by_member
            .get(&selection.member_index)
            .copied()
            .ok_or(ExperimentalBinaryWorkloadError::Fork)?;
        let position = member_position(&members, selection.member_index)?;
        let epoch_before = members[position].group.epoch().as_u64();
        let started = Instant::now();
        let (wire, hybrid_metrics) = stage_self_update(&mut members[position])?;
        let deliveries = deliver_to_receivers(&mut members, position, &wire)?;
        merge_sender_binary(&mut members[position])?;
        let epoch_after = converged_epoch(&members)?;
        ensure_epoch_advance(epoch_before, epoch_after)?;
        last_current_bytes = u64::try_from(wire.len())
            .map_err(|_| ExperimentalBinaryWorkloadError::CountOverflow)?;
        last_candidate_bytes = candidate_bytes;
        costs.push(ImpactfulCommitByteCosts::new(
            last_current_bytes,
            candidate_bytes,
        ));
        let record = policy_window
            .append_accepted(
                epoch_after,
                CommitImpactFacts {
                    path_delivery_changed: true,
                    recipient_resolution_changed: true,
                    ..CommitImpactFacts::default()
                },
            )
            .map_err(|_| ExperimentalBinaryWorkloadError::Fork)?
            .record;
        accepted_operations.push(AcceptedExperimentalAdaptiveOperation {
            sequence,
            phase: ExperimentalAdaptiveCommitPhase::NormalBinaryUpdate,
            committer_member_index: selection.member_index,
            committer_leaf_index: selection.leaf_index,
            committer_leaf_region: selection.leaf_region,
            epoch_before,
            epoch_after,
            active_member_count: member_count,
            emitted_commit_bytes: last_current_bytes,
            direct_commit_delivery_count: deliveries,
            accepted_lifecycle_elapsed_nanoseconds: started.elapsed().as_nanos(),
            hybrid_delivery: Some(hybrid_metrics),
            arity_state: arity_state_from_group(&members[0].group)?,
            policy_record: Some(record.clone()),
            transition: None,
        });
        sequence = sequence
            .checked_add(1)
            .ok_or(ExperimentalBinaryWorkloadError::CountOverflow)?;
        let normal = arity_state_from_group(&members[0].group)?;
        let savings = PreflightSavings::from_impactful_costs(
            &costs,
            normal.policy().transition_preflight_bytes(),
        )
        .map_err(|_| ExperimentalBinaryWorkloadError::Fork)?;
        let evaluation = TransitionStartEvaluator::new(adaptive_start_config(&normal)?)
            .evaluate_post_warmup(
                &record,
                PolicyTransitionState::Normal,
                member_count,
                &policy_window,
                Some(savings),
            )
            .map_err(|_| ExperimentalBinaryWorkloadError::Fork)?;
        if evaluation.is_triggered() {
            transition_selection = Some(selection);
            transition_position = Some(position);
            transition_workload_sequence = Some(workload_sequence);
            transition_record = record;
            transition_savings = Some(savings);
            transition_evaluation = Some(evaluation);
            break;
        }
    }
    let normal = arity_state_from_group(&members[0].group)?;
    let Some(second_selection) = transition_selection else {
        return Err(ExperimentalBinaryWorkloadError::TransitionNotAuthorized {
            current_binary_update_bytes: last_current_bytes,
            quaternary_candidate_bytes: last_candidate_bytes,
            transition_preflight_bytes: u64::try_from(preflight.estimated_bytes())
                .map_err(|_| ExperimentalBinaryWorkloadError::CountOverflow)?,
        });
    };
    let second_position = transition_position.ok_or(ExperimentalBinaryWorkloadError::Fork)?;
    let transition_workload_sequence =
        transition_workload_sequence.ok_or(ExperimentalBinaryWorkloadError::Fork)?;
    let _policy_record = transition_record;
    let savings = transition_savings.ok_or(ExperimentalBinaryWorkloadError::Fork)?;
    let evaluation = transition_evaluation.ok_or(ExperimentalBinaryWorkloadError::Fork)?;
    let mapping = transition_mapping_from_group(&members[0].group)?;
    let treecover = DeliveryOnlyTreeCover::from_mapping(1, &mapping)
        .map_err(|_| ExperimentalBinaryWorkloadError::Fork)?;
    let next_state = normal
        .begin_transition(
            &evaluation,
            policy_window.q_e(),
            MappingHash::new(hash_canonical_public_bytes(
                &mapping
                    .canonical_bytes()
                    .map_err(|_| ExperimentalBinaryWorkloadError::Fork)?,
            )),
            TreeCoverBinding::new(
                treecover.version(),
                treecover
                    .hash()
                    .map_err(|_| ExperimentalBinaryWorkloadError::Fork)?,
            )
            .map_err(|_| ExperimentalBinaryWorkloadError::Fork)?,
        )
        .map_err(|_| ExperimentalBinaryWorkloadError::Fork)?;
    let transition_committer_position = second_position;
    let transition_epoch_before = members[transition_committer_position]
        .group
        .epoch()
        .as_u64();
    let transition_started = Instant::now();
    let (transition_commit, _, _) = {
        let ExperimentalWorkloadMember {
            provider,
            signer,
            group,
            ..
        } = &mut members[transition_committer_position];
        group
            .begin_experimental_transition(provider, signer, next_state.clone())
            .map_err(|_| ExperimentalBinaryWorkloadError::Fork)?
    };
    let transition_wire = transition_commit
        .tls_serialize_detached()
        .map_err(|_| ExperimentalBinaryWorkloadError::Fork)?;
    let transition_deliveries = deliver_transition_to_receivers(
        &mut members,
        transition_committer_position,
        &transition_wire,
    )?;
    merge_sender_transition(&mut members[transition_committer_position])?;
    let transition_epoch_after = converged_epoch(&members)?;
    ensure_epoch_advance(transition_epoch_before, transition_epoch_after)?;
    let quaternary_topology = ShadowQuaternaryTree::from_mapping(mapping)
        .map_err(|_| ExperimentalBinaryWorkloadError::Fork)?;
    let transition_measurement = ExperimentalAdaptiveTransitionMeasurement {
        preflight,
        byte_comparison: preflight.compare_actual_outer_message(&transition_wire),
        preflight_savings: savings,
        treecover_member_count: u32::try_from(treecover.members().len())
            .map_err(|_| ExperimentalBinaryWorkloadError::CountOverflow)?,
        quaternary_topology,
        start_evaluation: evaluation,
    };
    accepted_operations.push(AcceptedExperimentalAdaptiveOperation {
        sequence,
        phase: ExperimentalAdaptiveCommitPhase::Transition,
        committer_member_index: second_selection.member_index,
        committer_leaf_index: second_selection.leaf_index,
        committer_leaf_region: second_selection.leaf_region,
        epoch_before: transition_epoch_before,
        epoch_after: transition_epoch_after,
        active_member_count: member_count,
        emitted_commit_bytes: u64::try_from(transition_wire.len())
            .map_err(|_| ExperimentalBinaryWorkloadError::CountOverflow)?,
        direct_commit_delivery_count: transition_deliveries,
        accepted_lifecycle_elapsed_nanoseconds: transition_started.elapsed().as_nanos(),
        hybrid_delivery: None,
        arity_state: arity_state_from_group(&members[0].group)?,
        policy_record: None,
        transition: Some(transition_measurement),
    });
    sequence = sequence
        .checked_add(1)
        .ok_or(ExperimentalBinaryWorkloadError::CountOverflow)?;

    for workload_sequence in transition_workload_sequence.saturating_add(1)..=config.operation_count
    {
        let selection = select_committer(&members, config, workload_sequence)?;
        let committer_position = member_position(&members, selection.member_index)?;
        let epoch_before = members[committer_position].group.epoch().as_u64();
        let started = Instant::now();
        let (wire, hybrid_metrics) = stage_self_update(&mut members[committer_position])?;
        let direct_commit_delivery_count =
            deliver_quaternary_to_receivers(&mut members, committer_position, &wire)?;
        merge_sender_quaternary(&mut members[committer_position])?;
        let epoch_after = converged_epoch(&members)?;
        ensure_epoch_advance(epoch_before, epoch_after)?;
        accepted_operations.push(AcceptedExperimentalAdaptiveOperation {
            sequence,
            phase: ExperimentalAdaptiveCommitPhase::QuaternaryUpdate,
            committer_member_index: selection.member_index,
            committer_leaf_index: selection.leaf_index,
            committer_leaf_region: selection.leaf_region,
            epoch_before,
            epoch_after,
            active_member_count: member_count,
            emitted_commit_bytes: u64::try_from(wire.len())
                .map_err(|_| ExperimentalBinaryWorkloadError::CountOverflow)?,
            direct_commit_delivery_count,
            accepted_lifecycle_elapsed_nanoseconds: started.elapsed().as_nanos(),
            hybrid_delivery: Some(hybrid_metrics),
            arity_state: arity_state_from_group(&members[0].group)?,
            policy_record: None,
            transition: None,
        });
        sequence = sequence
            .checked_add(1)
            .ok_or(ExperimentalBinaryWorkloadError::CountOverflow)?;
    }

    Ok(ExperimentalAdaptiveWorkloadExecution {
        final_epoch: converged_epoch(&members)?,
        final_member_count: member_count,
        accepted_operations,
        retirement_status:
            ExperimentalAdaptiveRetirementStatus::UnsupportedNoAuthenticatedRetirementCommit,
    })
}

struct AdaptiveProbe {
    transition_wire: Vec<u8>,
    quaternary_update_bytes_by_member: BTreeMap<u32, u64>,
}

fn measure_adaptive_probe(
    config: &BaselineWorkloadConfig,
) -> Result<AdaptiveProbe, ExperimentalBinaryWorkloadError> {
    // Each candidate comes from a fresh real transition because the fork has
    // no side-effect-free preview. The sender/path pairing must match the
    // corresponding normal observation; a single fixed candidate would make
    // a round-robin policy comparison invalid.
    let mut transition_wire = None;
    let mut quaternary_update_bytes_by_member = BTreeMap::new();
    for candidate_member_index in 0..config.initial_member_count {
        let (candidate_transition_wire, candidate_update_wire) =
            measure_adaptive_probe_candidate(config, candidate_member_index)?;
        if transition_wire.is_none() {
            transition_wire = Some(candidate_transition_wire);
        }
        if quaternary_update_bytes_by_member
            .insert(
                candidate_member_index,
                u64::try_from(candidate_update_wire.len())
                    .map_err(|_| ExperimentalBinaryWorkloadError::CountOverflow)?,
            )
            .is_some()
        {
            return Err(ExperimentalBinaryWorkloadError::Fork);
        }
    }
    Ok(AdaptiveProbe {
        transition_wire: transition_wire.ok_or(ExperimentalBinaryWorkloadError::Fork)?,
        quaternary_update_bytes_by_member,
    })
}

fn measure_adaptive_probe_candidate(
    config: &BaselineWorkloadConfig,
    candidate_member_index: u32,
) -> Result<(Vec<u8>, Vec<u8>), ExperimentalBinaryWorkloadError> {
    let mut members =
        create_initial_group_with_extensions(config, adaptive_probe_arity_extensions(config)?)?;
    let selection = select_committer(&members, config, 1)?;
    let position = member_position(&members, selection.member_index)?;
    let next_state = probe_transition_state(&members[0].group)?;
    let (transition_commit, _, _) = {
        let ExperimentalWorkloadMember {
            provider,
            signer,
            group,
            ..
        } = &mut members[position];
        group
            .begin_experimental_transition(provider, signer, next_state)
            .map_err(|_| ExperimentalBinaryWorkloadError::Fork)?
    };
    let transition_wire = transition_commit
        .tls_serialize_detached()
        .map_err(|_| ExperimentalBinaryWorkloadError::Fork)?;
    let _ = deliver_transition_to_receivers(&mut members, position, &transition_wire)?;
    merge_sender_transition(&mut members[position])?;
    let _ = converged_epoch(&members)?;
    let update_position = member_position(&members, candidate_member_index)?;
    let (quaternary_update_wire, _) = stage_self_update(&mut members[update_position])?;
    Ok((transition_wire, quaternary_update_wire))
}

fn validate_controls(
    config: &BaselineWorkloadConfig,
) -> Result<(), ExperimentalBinaryWorkloadError> {
    if config.group_id.is_empty()
        || config.initial_member_count < 2
        || config.maximum_member_count < config.initial_member_count
        || config.region_count == 0
    {
        return Err(ExperimentalBinaryWorkloadError::InvalidControls);
    }
    if config.workload_profile != WorkloadProfile::UpdateOnly {
        return Err(ExperimentalBinaryWorkloadError::UnsupportedWorkloadProfile);
    }
    Ok(())
}

fn create_initial_group(
    config: &BaselineWorkloadConfig,
) -> Result<Vec<ExperimentalWorkloadMember>, ExperimentalBinaryWorkloadError> {
    create_initial_group_with_extensions(config, normal_binary_arity_extensions())
}

fn create_initial_group_with_extensions(
    config: &BaselineWorkloadConfig,
    extensions: Extensions<GroupContext>,
) -> Result<Vec<ExperimentalWorkloadMember>, ExperimentalBinaryWorkloadError> {
    let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    let domain = MkyberDomain::new([0x59; 32]);
    let mut members = Vec::new();
    let provider = OpenMlsRustCrypto::default();
    let signer = SignatureKeyPair::new(ciphersuite.signature_algorithm())
        .map_err(|_| ExperimentalBinaryWorkloadError::Fork)?;
    let identity = workload_identity(0);
    let creator_credential = credential(&identity, &signer);
    let group = MlsGroup::new_with_group_id_experimental_mkyber(
        &provider,
        &signer,
        &experimental_group_config_with_extensions(extensions),
        GroupId::from_slice(&config.group_id),
        creator_credential,
        domain,
    )
    .map_err(|_| ExperimentalBinaryWorkloadError::Fork)?;
    members.push(ExperimentalWorkloadMember {
        member_index: 0,
        leaf_region: 0,
        provider,
        signer,
        group,
    });

    for member_index in 1..config.initial_member_count {
        let provider = OpenMlsRustCrypto::default();
        let signer = SignatureKeyPair::new(ciphersuite.signature_algorithm())
            .map_err(|_| ExperimentalBinaryWorkloadError::Fork)?;
        let identity = workload_identity(member_index);
        let bundle = KeyPackage::builder()
            .build_with_experimental_mkyber(
                ciphersuite,
                &provider,
                &signer,
                credential(&identity, &signer),
                domain,
            )
            .map_err(|_| ExperimentalBinaryWorkloadError::Fork)?;
        let (commit, welcome, _) = {
            let ExperimentalWorkloadMember {
                provider,
                signer,
                group,
                ..
            } = &mut members[0];
            group
                .add_members(
                    provider,
                    signer,
                    core::slice::from_ref(bundle.key_package()),
                )
                .map_err(|_| ExperimentalBinaryWorkloadError::Fork)?
        };
        let wire = commit
            .tls_serialize_detached()
            .map_err(|_| ExperimentalBinaryWorkloadError::Fork)?;
        let _ = deliver_to_receivers(&mut members, 0, &wire)?;
        {
            let ExperimentalWorkloadMember {
                provider, group, ..
            } = &mut members[0];
            group
                .merge_pending_commit_experimental_atomic(provider)
                .map_err(|_| ExperimentalBinaryWorkloadError::Fork)?;
        }
        let welcome = parse_welcome(&welcome)?;
        let group = StagedWelcome::new_from_welcome(
            &provider,
            &MlsGroupJoinConfig::builder()
                .use_ratchet_tree_extension(true)
                .build(),
            welcome,
            None,
        )
        .map_err(|_| ExperimentalBinaryWorkloadError::Fork)?
        .into_group(&provider)
        .map_err(|_| ExperimentalBinaryWorkloadError::Fork)?;
        members.push(ExperimentalWorkloadMember {
            member_index,
            leaf_region: member_index % config.region_count,
            provider,
            signer,
            group,
        });
        let _ = converged_epoch(&members)?;
    }
    Ok(members)
}

fn select_committer(
    members: &[ExperimentalWorkloadMember],
    config: &BaselineWorkloadConfig,
    sequence: u32,
) -> Result<CommitterSelection, ExperimentalBinaryWorkloadError> {
    let eligible = members
        .iter()
        .map(|member| EligibleCommitter {
            member_index: member.member_index,
            leaf_index: member.member_index,
            leaf_region: member.leaf_region,
        })
        .collect::<Vec<_>>();
    build_committer_schedule(&eligible, config.committer_strategy.clone(), sequence)
        .map_err(|_| ExperimentalBinaryWorkloadError::InvalidControls)?
        .selections
        .last()
        .cloned()
        .ok_or(ExperimentalBinaryWorkloadError::InvalidControls)
}

fn member_position(
    members: &[ExperimentalWorkloadMember],
    member_index: u32,
) -> Result<usize, ExperimentalBinaryWorkloadError> {
    members
        .iter()
        .position(|member| member.member_index == member_index)
        .ok_or(ExperimentalBinaryWorkloadError::DivergentPublicState)
}

fn ensure_epoch_advance(
    epoch_before: u64,
    epoch_after: u64,
) -> Result<(), ExperimentalBinaryWorkloadError> {
    if epoch_before.checked_add(1) == Some(epoch_after) {
        Ok(())
    } else {
        Err(ExperimentalBinaryWorkloadError::DivergentPublicState)
    }
}

fn merge_sender_binary(
    member: &mut ExperimentalWorkloadMember,
) -> Result<(), ExperimentalBinaryWorkloadError> {
    member
        .group
        .merge_pending_commit_experimental_atomic(&member.provider)
        .map_err(|_| ExperimentalBinaryWorkloadError::Fork)
}

fn merge_sender_transition(
    member: &mut ExperimentalWorkloadMember,
) -> Result<(), ExperimentalBinaryWorkloadError> {
    member
        .group
        .merge_pending_commit_experimental_transition_atomic(&member.provider)
        .map_err(|_| ExperimentalBinaryWorkloadError::Fork)
}

fn merge_sender_quaternary(
    member: &mut ExperimentalWorkloadMember,
) -> Result<(), ExperimentalBinaryWorkloadError> {
    member
        .group
        .merge_pending_commit_experimental_quaternary_atomic(&member.provider)
        .map_err(|_| ExperimentalBinaryWorkloadError::Fork)
}

fn stage_self_update(
    member: &mut ExperimentalWorkloadMember,
) -> Result<(Vec<u8>, ExperimentalHybridCommitMetrics), ExperimentalBinaryWorkloadError> {
    let bundle = member
        .group
        .self_update(
            &member.provider,
            &member.signer,
            LeafNodeParameters::default(),
        )
        .map_err(|_| ExperimentalBinaryWorkloadError::Fork)?;
    let metrics = bundle
        .experimental_hybrid_metrics()
        .ok_or(ExperimentalBinaryWorkloadError::MissingHybridDelivery)?;
    let (commit, _, _) = bundle.into_contents();
    let wire = commit
        .tls_serialize_detached()
        .map_err(|_| ExperimentalBinaryWorkloadError::Fork)?;
    Ok((wire, metrics))
}

fn deliver_to_receivers(
    members: &mut [ExperimentalWorkloadMember],
    committer_position: usize,
    wire: &[u8],
) -> Result<u32, ExperimentalBinaryWorkloadError> {
    let mut count = 0_u32;
    for (position, member) in members.iter_mut().enumerate() {
        if position == committer_position {
            continue;
        }
        let staged = staged_commit_from_wire(&mut member.group, &member.provider, wire)?;
        member
            .group
            .merge_staged_commit_experimental_atomic(&member.provider, staged)
            .map_err(|_| ExperimentalBinaryWorkloadError::Fork)?;
        count = count
            .checked_add(1)
            .ok_or(ExperimentalBinaryWorkloadError::CountOverflow)?;
    }
    Ok(count)
}

fn deliver_transition_to_receivers(
    members: &mut [ExperimentalWorkloadMember],
    committer_position: usize,
    wire: &[u8],
) -> Result<u32, ExperimentalBinaryWorkloadError> {
    let mut count = 0_u32;
    for (position, member) in members.iter_mut().enumerate() {
        if position == committer_position {
            continue;
        }
        let staged = staged_commit_from_wire(&mut member.group, &member.provider, wire)?;
        member
            .group
            .merge_staged_commit_experimental_transition_atomic(&member.provider, staged)
            .map_err(|_| ExperimentalBinaryWorkloadError::Fork)?;
        count = count
            .checked_add(1)
            .ok_or(ExperimentalBinaryWorkloadError::CountOverflow)?;
    }
    Ok(count)
}

fn deliver_quaternary_to_receivers(
    members: &mut [ExperimentalWorkloadMember],
    committer_position: usize,
    wire: &[u8],
) -> Result<u32, ExperimentalBinaryWorkloadError> {
    let mut count = 0_u32;
    for (position, member) in members.iter_mut().enumerate() {
        if position == committer_position {
            continue;
        }
        let staged = staged_commit_from_wire(&mut member.group, &member.provider, wire)?;
        member
            .group
            .merge_staged_commit_experimental_quaternary_atomic(&member.provider, staged)
            .map_err(|_| ExperimentalBinaryWorkloadError::Fork)?;
        count = count
            .checked_add(1)
            .ok_or(ExperimentalBinaryWorkloadError::CountOverflow)?;
    }
    Ok(count)
}

fn staged_commit_from_wire(
    group: &mut MlsGroup,
    provider: &OpenMlsRustCrypto,
    wire: &[u8],
) -> Result<StagedCommit, ExperimentalBinaryWorkloadError> {
    let message = MlsMessageIn::tls_deserialize_exact(wire)
        .map_err(|_| ExperimentalBinaryWorkloadError::Fork)?
        .try_into_protocol_message()
        .map_err(|_| ExperimentalBinaryWorkloadError::Fork)?;
    let processed = group
        .process_message(provider, message)
        .map_err(|_| ExperimentalBinaryWorkloadError::Fork)?;
    let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content() else {
        return Err(ExperimentalBinaryWorkloadError::Fork);
    };
    Ok(*staged)
}

fn parse_welcome(
    welcome: &openmls_hybrid::prelude::MlsMessageOut,
) -> Result<openmls_hybrid::prelude::Welcome, ExperimentalBinaryWorkloadError> {
    match MlsMessageIn::tls_deserialize_exact(
        welcome
            .tls_serialize_detached()
            .map_err(|_| ExperimentalBinaryWorkloadError::Fork)?,
    )
    .map_err(|_| ExperimentalBinaryWorkloadError::Fork)?
    .extract()
    {
        MlsMessageBodyIn::Welcome(welcome) => Ok(welcome),
        _ => Err(ExperimentalBinaryWorkloadError::Fork),
    }
}

fn converged_epoch(
    members: &[ExperimentalWorkloadMember],
) -> Result<u64, ExperimentalBinaryWorkloadError> {
    let first = members
        .first()
        .ok_or(ExperimentalBinaryWorkloadError::InvalidControls)?;
    let epoch = first.group.epoch().as_u64();
    let tree = first.group.export_ratchet_tree();
    if members.iter().skip(1).any(|member| {
        member.group.epoch().as_u64() != epoch || member.group.export_ratchet_tree() != tree
    }) {
        return Err(ExperimentalBinaryWorkloadError::DivergentPublicState);
    }
    Ok(epoch)
}

fn record_accepted_operation(
    selection: &CommitterSelection,
    input: AcceptedRecordInput,
) -> AcceptedExperimentalBinaryOperation {
    AcceptedExperimentalBinaryOperation {
        sequence: input.sequence,
        committer_member_index: selection.member_index,
        committer_leaf_index: selection.leaf_index,
        committer_leaf_region: selection.leaf_region,
        operation: WorkloadOperation::Update,
        epoch_before: input.epoch_before,
        epoch_after: input.epoch_after,
        active_member_count: input.active_member_count,
        measurement: ExperimentalBinaryCommitMeasurement {
            emitted_commit_bytes: input.emitted_commit_bytes,
            emitted_welcome_bytes: None,
            direct_commit_delivery_count: input.direct_commit_delivery_count,
            welcome_join_count: 0,
            accepted_lifecycle_elapsed_nanoseconds: input.elapsed_nanoseconds,
            hybrid_path_delivery_count: input.metrics.hybrid_path_delivery_count(),
            mkyber_common_ciphertext_count: input.metrics.mkyber_common_ciphertext_count(),
            mkyber_recipient_ciphertext_count: input.metrics.mkyber_recipient_ciphertext_count(),
            classical_hpke_encapsulation_count: input.metrics.classical_hpke_encapsulation_count(),
        },
    }
}

fn workload_identity(member_index: u32) -> Vec<u8> {
    format!("experimental-workload-member-{member_index}").into_bytes()
}

fn credential(identity: &[u8], signer: &SignatureKeyPair) -> CredentialWithKey {
    CredentialWithKey {
        credential: BasicCredential::new(identity.to_vec()).into(),
        signature_key: signer.public().into(),
    }
}

fn experimental_group_config_with_extensions(
    extensions: Extensions<GroupContext>,
) -> MlsGroupCreateConfig {
    MlsGroupCreateConfig::builder()
        .ciphersuite(Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519)
        .capabilities(mkyber_recipient_capabilities())
        .use_ratchet_tree_extension(true)
        .with_group_context_extensions(extensions)
        .build()
}

fn normal_binary_arity_extensions() -> Extensions<GroupContext> {
    let window = PolicyWindowConfig::new(20, 2, 1).expect("fixed valid policy window");
    let preflight = TransitionPreflightMeasurement::from_serialized_outer_message(
        &[0_u8; 100],
        &[TransitionByteRange::new(
            TransitionByteComponent::BaseCommit,
            0,
            100,
        )],
    )
    .expect("fixed valid transition preflight");
    let resolved = DeltaThreshold::PercentOfTransitionMicro(25_000_000)
        .resolve_for_preflight(preflight)
        .expect("fixed resolvable transition threshold");
    let start = TransitionStartConfig::new(2, 4, 128, 1, resolved.resolved_bytes())
        .expect("fixed valid transition controls");
    let policy = ArityPolicySnapshot::from_policy_inputs(window, start, resolved)
        .expect("fixed consistent arity policy");
    let state = ArityState::normal(2, 4, 0, policy, TransitionEvaluationState::new(0, 0, 0))
        .expect("fixed valid normal binary state");
    Extensions::from_vec(vec![
        Extension::Unknown(
            state.extension_type(),
            UnknownExtension(
                state
                    .extension_value_bytes()
                    .expect("fixed canonical ArityState encoding"),
            ),
        ),
        Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(
            &[ExtensionType::Unknown(
                arity_state::ADAPTIVE_HYBRID_TREE_STATE_EXTENSION_TYPE,
            )],
            &[],
            &[],
        )),
    ])
    .expect("unique authenticated experimental extensions")
}

fn adaptive_policy_window_config() -> Result<PolicyWindowConfig, ExperimentalBinaryWorkloadError> {
    PolicyWindowConfig::new(20, 0, 1).map_err(|_| ExperimentalBinaryWorkloadError::Fork)
}

fn adaptive_normal_arity_extensions(
    config: &BaselineWorkloadConfig,
    preflight: TransitionPreflightMeasurement,
) -> Result<Extensions<GroupContext>, ExperimentalBinaryWorkloadError> {
    let window = adaptive_policy_window_config()?;
    let resolved = DeltaThreshold::Bytes(0)
        .resolve_for_preflight(preflight)
        .map_err(|_| ExperimentalBinaryWorkloadError::Fork)?;
    let start = TransitionStartConfig::new(
        2,
        4,
        config.initial_member_count,
        1,
        resolved.resolved_bytes(),
    )
    .map_err(|_| ExperimentalBinaryWorkloadError::Fork)?;
    arity_extensions_from_policy(window, start, resolved)
}

fn adaptive_probe_arity_extensions(
    config: &BaselineWorkloadConfig,
) -> Result<Extensions<GroupContext>, ExperimentalBinaryWorkloadError> {
    let probe_preflight = TransitionPreflightMeasurement::from_serialized_outer_message(
        &[0_u8; 100],
        &[TransitionByteRange::new(
            TransitionByteComponent::BaseCommit,
            0,
            100,
        )],
    )
    .map_err(|_| ExperimentalBinaryWorkloadError::Fork)?;
    let window = adaptive_policy_window_config()?;
    let resolved = DeltaThreshold::PercentOfTransitionMicro(25_000_000)
        .resolve_for_preflight(probe_preflight)
        .map_err(|_| ExperimentalBinaryWorkloadError::Fork)?;
    let start = TransitionStartConfig::new(
        2,
        4,
        config.initial_member_count,
        1,
        resolved.resolved_bytes(),
    )
    .map_err(|_| ExperimentalBinaryWorkloadError::Fork)?;
    arity_extensions_from_policy(window, start, resolved)
}

fn arity_extensions_from_policy(
    window: PolicyWindowConfig,
    start: TransitionStartConfig,
    resolved: transition_policy::ResolvedDeltaThreshold,
) -> Result<Extensions<GroupContext>, ExperimentalBinaryWorkloadError> {
    let policy = ArityPolicySnapshot::from_policy_inputs(window, start, resolved)
        .map_err(|_| ExperimentalBinaryWorkloadError::Fork)?;
    let state = ArityState::normal(2, 4, 0, policy, TransitionEvaluationState::new(0, 0, 0))
        .map_err(|_| ExperimentalBinaryWorkloadError::Fork)?;
    Extensions::from_vec(vec![
        Extension::Unknown(
            state.extension_type(),
            UnknownExtension(
                state
                    .extension_value_bytes()
                    .map_err(|_| ExperimentalBinaryWorkloadError::Fork)?,
            ),
        ),
        Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(
            &[ExtensionType::Unknown(
                arity_state::ADAPTIVE_HYBRID_TREE_STATE_EXTENSION_TYPE,
            )],
            &[],
            &[],
        )),
    ])
    .map_err(|_| ExperimentalBinaryWorkloadError::Fork)
}

fn arity_state_from_group(group: &MlsGroup) -> Result<ArityState, ExperimentalBinaryWorkloadError> {
    let extension = group
        .extensions()
        .unknown(arity_state::ADAPTIVE_HYBRID_TREE_STATE_EXTENSION_TYPE)
        .ok_or(ExperimentalBinaryWorkloadError::Fork)?;
    ArityState::from_extension_value(&extension.0)
        .map_err(|_| ExperimentalBinaryWorkloadError::Fork)
}

fn transition_mapping_from_group(
    group: &MlsGroup,
) -> Result<BinaryToQuaternaryLeafMapping, ExperimentalBinaryWorkloadError> {
    BinaryToQuaternaryLeafMapping::from_binary_members(
        group
            .members()
            .map(|member| BinaryLeafMember {
                member_id: member.credential.serialized_content().to_vec(),
                binary_leaf_index: member.index.u32(),
            })
            .collect(),
    )
    .map_err(|_| ExperimentalBinaryWorkloadError::Fork)
}

fn adaptive_start_config(
    normal: &ArityState,
) -> Result<TransitionStartConfig, ExperimentalBinaryWorkloadError> {
    TransitionStartConfig::new(
        normal.active_arity(),
        normal.candidate_arity(),
        normal.policy().target_group_size(),
        normal.policy().stable_epoch_count(),
        normal.policy().resolved_delta_bytes(),
    )
    .map_err(|_| ExperimentalBinaryWorkloadError::Fork)
}

fn probe_transition_state(group: &MlsGroup) -> Result<ArityState, ExperimentalBinaryWorkloadError> {
    let normal = arity_state_from_group(group)?;
    let mapping = transition_mapping_from_group(group)?;
    let treecover = DeliveryOnlyTreeCover::from_mapping(1, &mapping)
        .map_err(|_| ExperimentalBinaryWorkloadError::Fork)?;
    let mut window = PolicyWindow::new(adaptive_policy_window_config()?);
    let record = window
        .append_accepted(
            group.epoch().as_u64(),
            CommitImpactFacts {
                transition_state_changed: true,
                ..CommitImpactFacts::default()
            },
        )
        .map_err(|_| ExperimentalBinaryWorkloadError::Fork)?
        .record;
    let savings = PreflightSavings::from_impactful_costs(
        &[ImpactfulCommitByteCosts::new(201, 75)],
        normal.policy().transition_preflight_bytes(),
    )
    .map_err(|_| ExperimentalBinaryWorkloadError::Fork)?;
    let evaluation = TransitionStartEvaluator::new(adaptive_start_config(&normal)?)
        .evaluate_post_warmup(
            &record,
            PolicyTransitionState::Normal,
            u32::try_from(group.members().count())
                .map_err(|_| ExperimentalBinaryWorkloadError::CountOverflow)?,
            &window,
            Some(savings),
        )
        .map_err(|_| ExperimentalBinaryWorkloadError::Fork)?;
    if !evaluation.is_triggered() {
        return Err(ExperimentalBinaryWorkloadError::TransitionNotAuthorized {
            current_binary_update_bytes: 0,
            quaternary_candidate_bytes: 0,
            transition_preflight_bytes: normal.policy().transition_preflight_bytes(),
        });
    }
    normal
        .begin_transition(
            &evaluation,
            window.q_e(),
            MappingHash::new(hash_canonical_public_bytes(
                &mapping
                    .canonical_bytes()
                    .map_err(|_| ExperimentalBinaryWorkloadError::Fork)?,
            )),
            TreeCoverBinding::new(
                treecover.version(),
                treecover
                    .hash()
                    .map_err(|_| ExperimentalBinaryWorkloadError::Fork)?,
            )
            .map_err(|_| ExperimentalBinaryWorkloadError::Fork)?,
        )
        .map_err(|_| ExperimentalBinaryWorkloadError::Fork)
}

#[cfg(test)]
mod tests {
    use adaptive_tree::{BinaryLeafMember, BinaryToQuaternaryLeafMapping};
    use arity_state::{
        hash_canonical_public_bytes, ArityLifecycle, ArityPolicySnapshot, ArityState, MappingHash,
        TransitionEvaluationState, TreeCoverBinding,
    };
    use hybrid_path_secret::{
        open_hybrid_path_level_with_provider, seal_hybrid_path_level_with_provider,
        ClassicalHpkeKeyPair, HybridPathCiphertext, HybridPathLevelContext, HybridPathLevelError,
        HybridPathRecipientPrivate, HybridPathRecipientPublic, HybridPathSecret,
        HybridRecipientCiphertext, PathNodeIndex, RecipientNodeIndex, TreeArity,
        MLS_PATH_SECRET_BYTES,
    };
    use mkyber::{
        EducationalMkyber512Reference, MkyberCommonCiphertext, MkyberDomain,
        MkyberRecipientCiphertext, MultiRecipientKem, RecipientId, RecipientPublicKey,
        RecipientSet,
    };
    use openmls_hybrid::{
        experimental_hybrid::{
            mkyber_recipient_capabilities, required_mkyber_recipient_capabilities,
            supports_mkyber_recipient_capabilities, ExperimentalHybridDeliveryError,
            ExperimentalHybridPathDelivery, ExperimentalMkyberError,
            ExperimentalMkyberNodeKeyStore, ExperimentalMkyberNodePublicKey,
            ExperimentalNodeKeyError, ExperimentalResolutionNodeId, ForkClassicalHpkeProvider,
            MkyberRecipientKeyMaterial, MKYBER_RECIPIENT_KEY_MATERIAL_BYTES,
            MKYBER_RECIPIENT_KEY_MATERIAL_VERSION,
        },
        prelude::{
            ApplyUpdatePathError, BasicCredential, Capabilities, Ciphersuite, CredentialWithKey,
            ExperimentalUpdatePathTestMutation, Extension, ExtensionType, Extensions, GroupContext,
            KeyPackage, LeafNodeParameters, MlsGroup, MlsGroupCreateConfig, MlsGroupJoinConfig,
            MlsMessageBodyIn, MlsMessageBodyOut, MlsMessageIn, OpenMlsProvider,
            ProcessMessageError, ProcessedMessageContent, RequiredCapabilitiesExtension,
            StageCommitError, StagedCommit, StagedWelcome, UnknownExtension,
        },
        treesync::{EncryptionKey, ParentNode},
    };
    use openmls_hybrid_basic_credential::SignatureKeyPair;
    use openmls_hybrid_rust_crypto::OpenMlsRustCrypto;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;
    use tls_codec::{Deserialize as TlsDeserializeTrait, Serialize as TlsSerializeTrait};
    use transition_policy::{
        CommitImpactFacts, DeltaThreshold, ImpactfulCommitByteCosts, PolicyTransitionState,
        PolicyWindow, PolicyWindowConfig, PreflightSavings, TransitionByteComponent,
        TransitionByteRange, TransitionPreflightMeasurement, TransitionStartConfig,
        TransitionStartEvaluator,
    };
    use transition_tree::{ActiveQuaternaryTree, DeliveryOnlyTreeCover};

    use super::{fork_ciphersuite_type_name, OPENMLS_HYBRID_UPSTREAM_REVISION};

    #[test]
    fn reproducible_binary_workload_records_only_accepted_hybrid_commits() {
        let config = simulation::BaselineWorkloadConfig {
            group_id: b"task-59-binary-workload".to_vec(),
            initial_member_count: 2,
            maximum_member_count: 2,
            operation_count: 11,
            region_count: 2,
            committer_strategy: simulation::CommitterStrategy::RoundRobin,
            workload_profile: simulation::WorkloadProfile::UpdateOnly,
        };
        let execution = super::execute_experimental_binary_workload(&config)
            .expect("accepted experimental binary workload");

        assert_eq!(execution.accepted_operations.len(), 11);
        assert_eq!(execution.final_member_count, 2);
        assert!(execution.accepted_operations.iter().all(|accepted| {
            accepted.operation == simulation::WorkloadOperation::Update
                && accepted.epoch_after == accepted.epoch_before + 1
                && accepted.measurement.emitted_commit_bytes > 0
                && accepted.measurement.hybrid_path_delivery_count > 0
                && accepted.measurement.mkyber_common_ciphertext_count > 0
                && accepted.measurement.mkyber_recipient_ciphertext_count > 0
                && accepted.measurement.classical_hpke_encapsulation_count
                    == accepted.measurement.mkyber_recipient_ciphertext_count
        }));
    }

    #[test]
    fn eleven_normal_observations_remain_below_real_amortization_boundary() {
        let config = simulation::BaselineWorkloadConfig {
            group_id: b"task-61-adaptive-workload".to_vec(),
            initial_member_count: 5,
            maximum_member_count: 5,
            operation_count: 11,
            region_count: 2,
            committer_strategy: simulation::CommitterStrategy::RoundRobin,
            workload_profile: simulation::WorkloadProfile::UpdateOnly,
        };
        let probe = super::measure_adaptive_probe(&config).expect("real adaptive probe");
        assert!(!probe.transition_wire.is_empty());
        assert_eq!(probe.quaternary_update_bytes_by_member.len(), 5);
        let error = super::execute_experimental_adaptive_workload(&config)
            .expect_err("eleven normal observations must not authorize transition");
        assert!(matches!(
            error,
            super::ExperimentalBinaryWorkloadError::TransitionNotAuthorized {
                current_binary_update_bytes: 6_355,
                quaternary_candidate_bytes: 5_841,
                transition_preflight_bytes: 6_041,
            }
        ));
    }

    #[test]
    fn fifteen_observation_round_robin_workload_rejects_non_saving_member_path() {
        let config = simulation::BaselineWorkloadConfig {
            group_id: b"task-61-adaptive-workload-after-amortization".to_vec(),
            initial_member_count: 5,
            maximum_member_count: 5,
            operation_count: 15,
            region_count: 2,
            committer_strategy: simulation::CommitterStrategy::RoundRobin,
            workload_profile: simulation::WorkloadProfile::UpdateOnly,
        };
        let error = super::execute_experimental_adaptive_workload(&config)
            .expect_err("a non-saving matched path must not authorize transition");
        assert!(matches!(
            error,
            super::ExperimentalBinaryWorkloadError::TransitionNotAuthorized {
                current_binary_update_bytes: 2_946,
                quaternary_candidate_bytes: 4_188,
                transition_preflight_bytes: 6_060,
            }
        ));
    }

    #[test]
    fn links_the_expected_named_fork() {
        assert!(fork_ciphersuite_type_name().contains("Ciphersuite"));
        assert_eq!(OPENMLS_HYBRID_UPSTREAM_REVISION.len(), 40);
    }

    #[test]
    fn mkyber_recipient_material_is_canonical_and_capability_gated() {
        let material = MkyberRecipientKeyMaterial::from_parts([0x42; 32], [0x24; 768])
            .expect("fixed-size public material must parse");
        let extensions = material
            .key_package_extensions()
            .expect("private-use key package extension must be valid");

        assert_eq!(
            MkyberRecipientKeyMaterial::from_key_package_extensions(&extensions)
                .expect("canonical extension must round-trip"),
            material
        );
        assert!(supports_mkyber_recipient_capabilities(
            &mkyber_recipient_capabilities()
        ));
        assert!(!supports_mkyber_recipient_capabilities(
            &openmls_hybrid::prelude::Capabilities::default()
        ));
    }

    #[test]
    fn mkyber_recipient_material_rejects_wrong_version_and_length() {
        let mut wrong_version = vec![0_u8; MKYBER_RECIPIENT_KEY_MATERIAL_BYTES];
        wrong_version[..2]
            .copy_from_slice(&(MKYBER_RECIPIENT_KEY_MATERIAL_VERSION + 1).to_be_bytes());
        let extensions = Extensions::<KeyPackage>::single(Extension::Unknown(
            required_mkyber_recipient_capabilities()[1].into(),
            UnknownExtension(wrong_version),
        ))
        .expect("private-use key package extension must be valid");

        assert_eq!(
            MkyberRecipientKeyMaterial::from_key_package_extensions(&extensions),
            Err(ExperimentalMkyberError::UnsupportedVersion(
                MKYBER_RECIPIENT_KEY_MATERIAL_VERSION + 1
            ))
        );
        assert_eq!(
            MkyberRecipientKeyMaterial::from_extension_value(&[0_u8; 3]),
            Err(ExperimentalMkyberError::InvalidEncodingLength {
                expected: MKYBER_RECIPIENT_KEY_MATERIAL_BYTES,
                actual: 3,
            })
        );
    }

    #[test]
    fn hybrid_delivery_accepts_only_exact_canonical_bytes_for_its_path_node() {
        let ciphertext = HybridPathCiphertext::new(
            PathNodeIndex::new(3),
            MkyberDomain::new([0x42; 32]),
            MkyberCommonCiphertext::from_bytes(&[0x11; 704]).expect("fixed-size common component"),
            vec![HybridRecipientCiphertext::new(
                RecipientNodeIndex::new(7),
                [0x22; 32],
                MkyberRecipientCiphertext::from_bytes(&[0x33; 48])
                    .expect("fixed-size recipient component"),
                [0x44; 48],
            )],
        )
        .expect("canonical fixture");
        let canonical_bytes = ciphertext
            .commit_authenticated_bytes()
            .expect("canonical serialization");

        let delivery =
            ExperimentalHybridPathDelivery::from_canonical_bytes(3, canonical_bytes.clone())
                .expect("matching canonical delivery");
        assert_eq!(delivery.path_node_index(), 3);
        assert_eq!(delivery.canonical_bytes(), canonical_bytes);
        assert_eq!(
            ExperimentalHybridPathDelivery::from_canonical_bytes(4, canonical_bytes),
            Err(ExperimentalHybridDeliveryError::PathNodeMismatch {
                expected: 4,
                actual: 3,
            })
        );
    }

    #[test]
    fn fork_classical_provider_executes_hybrid_delivery_without_upstream_provider_types() {
        let backend = EducationalMkyber512Reference;
        let domain = MkyberDomain::new([0x52; 32]);
        let mut randomness = ChaCha20Rng::from_seed([0x53; 32]);
        let (mkyber_public, mkyber_private) = backend
            .keygen(domain, &mut randomness)
            .expect("deterministic test mKyber key generation")
            .into_parts();
        let (classical_public, classical_private) = ClassicalHpkeKeyPair::generate_with_os_rng()
            .expect("classical key generation")
            .into_parts();
        let context = HybridPathLevelContext::new(
            b"fork-provider-test".to_vec(),
            9,
            1,
            TreeArity::Binary,
            PathNodeIndex::new(4),
            domain,
            [0x54; 32],
        );
        let path_secret = HybridPathSecret::from_bytes(&[0x55; MLS_PATH_SECRET_BYTES])
            .expect("fixed-size path secret");
        let recipient_public = HybridPathRecipientPublic::new(
            RecipientNodeIndex::new(6),
            mkyber_public,
            classical_public,
        );
        let recipient_private = HybridPathRecipientPrivate::new(
            RecipientNodeIndex::new(6),
            mkyber_private,
            classical_private,
        );
        let provider = ForkClassicalHpkeProvider::default();

        let ciphertext = seal_hybrid_path_level_with_provider(
            &provider,
            &backend,
            &mut randomness,
            &context,
            &path_secret,
            &[recipient_public],
        )
        .expect("fork provider must seal");
        let opened = open_hybrid_path_level_with_provider(
            &provider,
            &backend,
            &context,
            &ciphertext,
            &recipient_private,
        )
        .expect("fork provider must open");

        assert_eq!(opened.as_bytes(), path_secret.as_bytes());
    }

    #[test]
    fn quaternary_parent_delivery_rejects_a_recipient_outside_its_mapped_sibling_resolution() {
        let mapping = BinaryToQuaternaryLeafMapping::from_binary_members(
            [
                &b"alice"[..],
                &b"bob"[..],
                &b"charlie"[..],
                &b"dave"[..],
                &b"eve"[..],
            ]
            .into_iter()
            .enumerate()
            .map(|(binary_leaf_index, member_id)| BinaryLeafMember {
                member_id: member_id.to_vec(),
                binary_leaf_index: binary_leaf_index as u32,
            })
            .collect(),
        )
        .expect("five-member canonical mapping");
        let tree = ActiveQuaternaryTree::from_mapping(2, mapping).expect("mapped tree");
        let bob_path = tree
            .topology()
            .leaf_path_for_member(b"bob")
            .expect("Bob mapped path");
        let charlie_path = tree
            .topology()
            .leaf_path_for_member(b"charlie")
            .expect("Charlie mapped path");
        let eve_path = tree
            .topology()
            .leaf_path_for_member(b"eve")
            .expect("Eve mapped path");
        assert_eq!(bob_path[0], charlie_path[0]);
        assert_ne!(bob_path[1], charlie_path[1]);
        assert_ne!(bob_path[0], eve_path[0]);
        let backend = EducationalMkyber512Reference;
        let domain = MkyberDomain::new([0x56; 32]);
        let mut randomness = ChaCha20Rng::from_seed([0x57; 32]);
        let provider = ForkClassicalHpkeProvider::default();
        let context = HybridPathLevelContext::new(
            b"mapped-quaternary-sibling".to_vec(),
            11,
            2,
            TreeArity::Quaternary,
            PathNodeIndex::new(1),
            domain,
            [0x58; 32],
        );
        let path_secret = HybridPathSecret::from_bytes(&[0x59; MLS_PATH_SECRET_BYTES])
            .expect("fixed-size path secret");

        // In this five-member mapping Bob's depth-one sibling resolution is
        // separate from Eve's root sibling resolution. Only the latter is
        // represented in this root-parent delivery.
        let (authorized_public, authorized_private) = backend
            .keygen(domain, &mut randomness)
            .expect("authorized mKyber key generation")
            .into_parts();
        let (authorized_classical_public, authorized_classical_private) =
            ClassicalHpkeKeyPair::generate_with_os_rng()
                .expect("authorized classical key generation")
                .into_parts();
        let (_nonrecipient_public, nonrecipient_private) = backend
            .keygen(domain, &mut randomness)
            .expect("non-recipient mKyber key generation")
            .into_parts();
        let (_nonrecipient_classical_public, nonrecipient_classical_private) =
            ClassicalHpkeKeyPair::generate_with_os_rng()
                .expect("non-recipient classical key generation")
                .into_parts();
        let authorized = HybridPathRecipientPublic::new(
            RecipientNodeIndex::new(4),
            authorized_public,
            authorized_classical_public,
        );
        let nonrecipient = HybridPathRecipientPrivate::new(
            RecipientNodeIndex::new(1),
            nonrecipient_private,
            nonrecipient_classical_private,
        );
        let ciphertext = seal_hybrid_path_level_with_provider(
            &provider,
            &backend,
            &mut randomness,
            &context,
            &path_secret,
            &[authorized],
        )
        .expect("root sibling delivery");

        assert_eq!(
            ciphertext
                .recipients()
                .iter()
                .map(|record| record.recipient_node_index().as_u32())
                .collect::<Vec<_>>(),
            vec![4],
            "the root-parent payload must exclude the depth-one sibling recipient"
        );
        assert!(
            matches!(
                open_hybrid_path_level_with_provider(
                    &provider,
                    &backend,
                    &context,
                    &ciphertext,
                    &nonrecipient,
                ),
                Err(HybridPathLevelError::RecipientNotFound)
            ),
            "a recipient outside the mapped sibling resolution must not open this parent"
        );

        let authorized_private = HybridPathRecipientPrivate::new(
            RecipientNodeIndex::new(4),
            authorized_private,
            authorized_classical_private,
        );
        assert_eq!(
            open_hybrid_path_level_with_provider(
                &provider,
                &backend,
                &context,
                &ciphertext,
                &authorized_private,
            )
            .expect("mapped sibling recipient opens its parent")
            .as_bytes(),
            path_secret.as_bytes()
        );
    }

    #[test]
    fn node_key_store_separates_leaf_and_parent_lifecycle() {
        let domain = MkyberDomain::new([0x61; 32]);
        let leaf = ExperimentalResolutionNodeId::new(0);
        let parent = ExperimentalResolutionNodeId::new(1);
        let mut store = ExperimentalMkyberNodeKeyStore::default();
        let leaf_public = store
            .generate_for_node(leaf, domain)
            .expect("leaf key generation");
        let parent_public = store
            .generate_for_node(parent, domain)
            .expect("parent key generation");
        let parent_recipient = RecipientId::new(parent.as_u32());
        let recipient_set = RecipientSet::new(
            domain,
            vec![RecipientPublicKey {
                recipient: parent_recipient,
                key: parent_public
                    .to_mkyber_key()
                    .expect("typed parent public key"),
            }],
        )
        .expect("single parent recipient");
        let backend = EducationalMkyber512Reference;
        let encapsulation = backend
            .encapsulate_with_os_rng(&recipient_set)
            .expect("parent public key must encapsulate");
        let recovered = backend
            .decapsulate(
                &store
                    .private_key_for(parent)
                    .expect("matching parent private key"),
                &encapsulation.ciphertext,
                parent_recipient,
            )
            .expect("matching parent private key must decapsulate");
        let leaf_canonical = leaf_public.canonical_bytes().expect("canonical leaf key");

        assert_eq!(store.retained_key_count(), 2);
        assert_eq!(recovered.as_bytes(), encapsulation.shared_secret.as_bytes());
        assert_eq!(leaf_canonical.len(), 800);
        assert_eq!(
            leaf_public,
            ExperimentalMkyberNodePublicKey::from_canonical_bytes(&leaf_canonical)
                .expect("exact leaf public key"),
        );
        assert_eq!(
            ExperimentalMkyberNodePublicKey::from_canonical_bytes(&leaf_canonical[..799]),
            Err(ExperimentalNodeKeyError::InvalidPublicEncoding)
        );
        assert_eq!(
            store.generate_for_node(parent, domain),
            Err(ExperimentalNodeKeyError::DuplicatePrivateKey(1))
        );
        assert_ne!(
            leaf_public
                .to_mkyber_key()
                .expect("typed leaf key")
                .as_bytes(),
            parent_public
                .to_mkyber_key()
                .expect("typed parent key")
                .as_bytes(),
        );
        assert_eq!(
            store
                .private_key_for(parent)
                .expect("parent private key")
                .domain(),
            domain
        );
        assert!(store.retire_node(parent));
        assert_eq!(store.retained_key_count(), 1);
        assert!(matches!(
            store.private_key_for(parent),
            Err(ExperimentalNodeKeyError::MissingPrivateKey(1))
        ));
    }

    #[test]
    fn node_public_key_is_bound_to_experimental_tree_key_state() {
        let domain = MkyberDomain::new([0x71; 32]);
        let mut store = ExperimentalMkyberNodeKeyStore::default();
        let node_key = store
            .generate_for_node(ExperimentalResolutionNodeId::new(5), domain)
            .expect("node key generation");
        let plain_key = EncryptionKey::from(vec![0x72; 32]);
        let bound_key = plain_key
            .clone()
            .with_experimental_mkyber_key(node_key.clone());
        let encoded_key = bound_key
            .tls_serialize_detached()
            .expect("experimental tree key serialization");
        let decoded_key = EncryptionKey::tls_deserialize_exact(&encoded_key)
            .expect("experimental tree key deserialization");
        let parent = ParentNode::from(bound_key.clone());
        let encoded_parent = parent
            .tls_serialize_detached()
            .expect("experimental parent serialization");
        let decoded_parent = ParentNode::tls_deserialize_exact(&encoded_parent)
            .expect("experimental parent deserialization");

        assert_ne!(
            plain_key
                .tls_serialize_detached()
                .expect("plain tree key serialization"),
            encoded_key
        );
        assert_eq!(
            decoded_key
                .experimental_mkyber_key()
                .expect("decoded key material"),
            &node_key
        );
        assert_eq!(decoded_parent, parent);
    }

    #[test]
    fn experimental_key_package_binds_signed_leaf_and_extension_to_one_mkyber_pair() {
        let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
        let provider = OpenMlsRustCrypto::default();
        let signer = SignatureKeyPair::new(ciphersuite.signature_algorithm())
            .expect("supported signature key generation");
        let credential_with_key = CredentialWithKey {
            credential: BasicCredential::new(b"experimental-key-package".to_vec()).into(),
            signature_key: signer.public().into(),
        };
        let domain = MkyberDomain::new([0x81; 32]);
        let bundle = KeyPackage::builder()
            .build_with_experimental_mkyber(
                ciphersuite,
                &provider,
                &signer,
                credential_with_key,
                domain,
            )
            .expect("experimental KeyPackage build");
        let signed_material = MkyberRecipientKeyMaterial::from_key_package(bundle.key_package())
            .expect("signed KeyPackage material");
        let leaf_material = bundle
            .key_package()
            .leaf_node()
            .encryption_key()
            .experimental_mkyber_key()
            .expect("bound leaf material");

        assert_eq!(signed_material.domain(), domain);
        assert_eq!(
            signed_material.public_key().as_bytes(),
            leaf_material
                .to_mkyber_key()
                .expect("bound leaf mKyber public key")
                .as_bytes(),
        );
        assert!(supports_mkyber_recipient_capabilities(
            bundle.key_package().leaf_node().capabilities()
        ));
        let recipient = RecipientId::new(12);
        let recipient_set = RecipientSet::new(
            domain,
            vec![RecipientPublicKey {
                recipient,
                key: signed_material.public_key().clone(),
            }],
        )
        .expect("single recipient set");
        let backend = EducationalMkyber512Reference;
        let encapsulation = backend
            .encapsulate_with_os_rng(&recipient_set)
            .expect("signed public key encapsulation");
        let recovered = backend
            .decapsulate(
                &bundle
                    .experimental_mkyber_private_key()
                    .expect("private bundle key reconstruction")
                    .expect("matched private bundle key"),
                &encapsulation.ciphertext,
                recipient,
            )
            .expect("matched private bundle key decapsulation");
        assert_eq!(recovered.as_bytes(), encapsulation.shared_secret.as_bytes());
    }

    fn experimental_binary_pair() -> (
        OpenMlsRustCrypto,
        SignatureKeyPair,
        MlsGroup,
        OpenMlsRustCrypto,
        SignatureKeyPair,
        MlsGroup,
    ) {
        experimental_binary_pair_with_policy_controls(128, 2)
    }

    fn experimental_binary_pair_with_policy_controls(
        target_group_size: u32,
        warmup_accepted_commits: u32,
    ) -> (
        OpenMlsRustCrypto,
        SignatureKeyPair,
        MlsGroup,
        OpenMlsRustCrypto,
        SignatureKeyPair,
        MlsGroup,
    ) {
        let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
        let domain = MkyberDomain::new([0x91; 32]);
        let alice_provider = OpenMlsRustCrypto::default();
        let bob_provider = OpenMlsRustCrypto::default();
        let alice_signer =
            SignatureKeyPair::new(ciphersuite.signature_algorithm()).expect("Alice signer");
        let bob_signer =
            SignatureKeyPair::new(ciphersuite.signature_algorithm()).expect("Bob signer");
        let alice_credential = CredentialWithKey {
            credential: BasicCredential::new(b"experimental-alice".to_vec()).into(),
            signature_key: alice_signer.public().into(),
        };
        let bob_credential = CredentialWithKey {
            credential: BasicCredential::new(b"experimental-bob".to_vec()).into(),
            signature_key: bob_signer.public().into(),
        };
        let config = MlsGroupCreateConfig::builder()
            .ciphersuite(ciphersuite)
            .capabilities(mkyber_recipient_capabilities())
            .use_ratchet_tree_extension(true)
            .with_group_context_extensions(normal_binary_arity_extensions_with_controls(
                target_group_size,
                warmup_accepted_commits,
            ))
            .build();
        let mut alice = MlsGroup::new_with_group_id_experimental_mkyber(
            &alice_provider,
            &alice_signer,
            &config,
            openmls_hybrid::prelude::GroupId::from_slice(b"experimental-round-trip"),
            alice_credential,
            domain,
        )
        .expect("experimental group creation");
        let bob_bundle = KeyPackage::builder()
            .build_with_experimental_mkyber(
                ciphersuite,
                &bob_provider,
                &bob_signer,
                bob_credential,
                domain,
            )
            .expect("Bob experimental KeyPackage");
        let (_add_commit, welcome, _) = alice
            .add_members(
                &alice_provider,
                &alice_signer,
                core::slice::from_ref(bob_bundle.key_package()),
            )
            .expect("experimental add");
        alice
            .merge_pending_commit_experimental_atomic(&alice_provider)
            .expect("Alice merges add");
        let welcome = match MlsMessageIn::tls_deserialize_exact(
            welcome
                .tls_serialize_detached()
                .expect("welcome serialization"),
        )
        .expect("welcome parsing")
        .extract()
        {
            MlsMessageBodyIn::Welcome(welcome) => welcome,
            _ => panic!("expected Welcome"),
        };
        let bob = StagedWelcome::new_from_welcome(
            &bob_provider,
            &MlsGroupJoinConfig::builder()
                .use_ratchet_tree_extension(true)
                .build(),
            welcome,
            None,
        )
        .expect("Bob staged Welcome")
        .into_group(&bob_provider)
        .expect("Bob joins");
        (
            alice_provider,
            alice_signer,
            alice,
            bob_provider,
            bob_signer,
            bob,
        )
    }

    fn normal_binary_arity_extensions() -> Extensions<GroupContext> {
        normal_binary_arity_extensions_with_controls(128, 2)
    }

    fn normal_binary_arity_extensions_with_controls(
        target_group_size: u32,
        warmup_accepted_commits: u32,
    ) -> Extensions<GroupContext> {
        let window =
            PolicyWindowConfig::new(20, warmup_accepted_commits, 1).expect("valid policy window");
        let preflight = TransitionPreflightMeasurement::from_serialized_outer_message(
            &[0_u8; 100],
            &[TransitionByteRange::new(
                TransitionByteComponent::BaseCommit,
                0,
                100,
            )],
        )
        .expect("valid transition preflight");
        let resolved = DeltaThreshold::PercentOfTransitionMicro(25_000_000)
            .resolve_for_preflight(preflight)
            .expect("resolved test threshold");
        let start =
            TransitionStartConfig::new(2, 4, target_group_size, 1, resolved.resolved_bytes())
                .expect("valid transition controls");
        let policy = ArityPolicySnapshot::from_policy_inputs(window, start, resolved)
            .expect("self-consistent policy snapshot");
        let state = ArityState::normal(2, 4, 0, policy, TransitionEvaluationState::new(0, 0, 0))
            .expect("valid normal binary state");
        Extensions::from_vec(vec![
            Extension::Unknown(
                state.extension_type(),
                UnknownExtension(
                    state
                        .extension_value_bytes()
                        .expect("canonical ArityState encoding"),
                ),
            ),
            Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(
                &[ExtensionType::Unknown(
                    arity_state::ADAPTIVE_HYBRID_TREE_STATE_EXTENSION_TYPE,
                )],
                &[],
                &[],
            )),
        ])
        .expect("unique authenticated experimental extensions")
    }

    fn hybrid_self_update_wire(
        bob: &mut MlsGroup,
        bob_provider: &OpenMlsRustCrypto,
        bob_signer: &SignatureKeyPair,
        leaf_node_parameters: LeafNodeParameters,
    ) -> Vec<u8> {
        let update = bob
            .self_update(bob_provider, bob_signer, leaf_node_parameters)
            .expect("Bob stages hybrid self-update");
        let (update_commit, _, _) = update.into_contents();
        update_commit
            .tls_serialize_detached()
            .expect("update serialization")
    }

    fn hybrid_self_update_wire_with_test_mutation(
        bob: &mut MlsGroup,
        bob_provider: &OpenMlsRustCrypto,
        bob_signer: &SignatureKeyPair,
        mutation: ExperimentalUpdatePathTestMutation,
    ) -> Vec<u8> {
        let update = bob
            .commit_builder()
            .leaf_node_parameters(LeafNodeParameters::default())
            .load_psks(bob_provider.storage())
            .expect("Bob loads self-update PSKs")
            .with_experimental_update_path_test_mutation(mutation)
            .build(
                bob_provider.rand(),
                bob_provider.crypto(),
                bob_signer,
                |_| true,
            )
            .expect("Bob builds signed mutated hybrid self-update")
            .stage_commit(bob_provider)
            .expect("Bob stages signed mutated hybrid self-update");
        let (update_commit, _, _) = update.into_contents();
        update_commit
            .tls_serialize_detached()
            .expect("mutated update serialization")
    }

    fn staged_commit_from_wire(
        group: &mut MlsGroup,
        provider: &OpenMlsRustCrypto,
        wire: &[u8],
    ) -> StagedCommit {
        let protocol_message = MlsMessageIn::tls_deserialize_exact(wire)
            .expect("Commit parsing")
            .try_into_protocol_message()
            .expect("protocol message");
        let processed = group
            .process_message(provider, protocol_message)
            .expect("hybrid Commit processing");
        let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content() else {
            panic!("expected staged Commit");
        };
        *staged
    }

    fn arity_state_from_group(group: &MlsGroup) -> ArityState {
        let extension = group
            .extensions()
            .unknown(arity_state::ADAPTIVE_HYBRID_TREE_STATE_EXTENSION_TYPE)
            .expect("authenticated ArityState extension");
        ArityState::from_extension_value(&extension.0).expect("valid authenticated ArityState")
    }

    fn transition_mapping_from_group(group: &MlsGroup) -> BinaryToQuaternaryLeafMapping {
        BinaryToQuaternaryLeafMapping::from_binary_members(
            group
                .members()
                .map(|member| BinaryLeafMember {
                    member_id: member.credential.serialized_content().to_vec(),
                    binary_leaf_index: member.index.u32(),
                })
                .collect(),
        )
        .expect("canonical transition mapping")
    }

    fn triggered_transition_state(group: &MlsGroup) -> ArityState {
        let normal = arity_state_from_group(group);
        let mapping = transition_mapping_from_group(group);
        let treecover =
            DeliveryOnlyTreeCover::from_mapping(1, &mapping).expect("delivery-only TreeCover");
        let window_config = PolicyWindowConfig::new(
            normal.policy().window_accepted_commits(),
            normal.policy().warmup_accepted_commits(),
            normal.policy().q_min(),
        )
        .expect("stored valid policy window");
        let start_config = TransitionStartConfig::new(
            normal.active_arity(),
            normal.candidate_arity(),
            normal.policy().target_group_size(),
            normal.policy().stable_epoch_count(),
            normal.policy().resolved_delta_bytes(),
        )
        .expect("stored valid transition start config");
        let mut window = PolicyWindow::new(window_config);
        let record = window
            .append_accepted(
                group.epoch().as_u64(),
                CommitImpactFacts {
                    transition_state_changed: true,
                    ..CommitImpactFacts::default()
                },
            )
            .expect("accepted post-warmup transition observation")
            .record;
        let savings = PreflightSavings::from_impactful_costs(
            &[ImpactfulCommitByteCosts::new(201, 75)],
            normal.policy().transition_preflight_bytes(),
        )
        .expect("exact preflight saving");
        let evaluation = TransitionStartEvaluator::new(start_config)
            .evaluate_post_warmup(
                &record,
                PolicyTransitionState::Normal,
                group.members().count() as u32,
                &window,
                Some(savings),
            )
            .expect("transition start evaluation");
        assert!(evaluation.is_triggered());
        let mapping_bytes = mapping.canonical_bytes().expect("mapping bytes");
        normal
            .begin_transition(
                &evaluation,
                window.q_e(),
                MappingHash::new(hash_canonical_public_bytes(&mapping_bytes)),
                TreeCoverBinding::new(
                    treecover.version(),
                    treecover.hash().expect("TreeCover hash"),
                )
                .expect("versioned TreeCover binding"),
            )
            .expect("triggered transition state")
    }

    #[test]
    fn experimental_transition_commit_authenticates_mapping_treecover_and_quaternary_root_delivery()
    {
        let (alice_provider, alice_signer, mut alice, bob_provider, _bob_signer, mut bob) =
            experimental_binary_pair_with_policy_controls(2, 0);
        let next_state = triggered_transition_state(&alice);

        let (commit, welcome, _) = alice
            .begin_experimental_transition(&alice_provider, &alice_signer, next_state.clone())
            .expect("sender stages authenticated transition Commit");
        assert!(welcome.is_none());
        let wire = commit
            .tls_serialize_detached()
            .expect("transition Commit serialization");
        let staged = staged_commit_from_wire(&mut bob, &bob_provider, &wire);

        bob.merge_staged_commit_experimental_transition_atomic(&bob_provider, staged)
            .expect("receiver opens and atomically merges quaternary root delivery");
        alice
            .merge_pending_commit_experimental_transition_atomic(&alice_provider)
            .expect("sender atomically merges transition Commit");

        assert_eq!(alice.epoch(), bob.epoch());
        assert_eq!(alice.export_ratchet_tree(), bob.export_ratchet_tree());
        assert_eq!(arity_state_from_group(&alice), next_state);
        assert_eq!(arity_state_from_group(&bob), next_state);
        let alice_authority = alice
            .experimental_quaternary_epoch_secret_status()
            .expect("Alice persisted quaternary authority");
        let bob_authority = bob
            .experimental_quaternary_epoch_secret_status()
            .expect("Bob persisted quaternary authority");
        assert_eq!(alice_authority, bob_authority);
        assert_eq!(alice_authority.epoch(), alice.epoch().as_u64());
        assert_eq!(alice_authority.tree_version(), next_state.tree_version());
        assert_ne!(alice_authority.root_public_key_hash(), &[0; 32]);
        let ArityLifecycle::Transitioning(transitioning) = next_state.lifecycle() else {
            panic!("expected transitioning state");
        };
        assert_eq!(
            alice_authority.mapping_hash(),
            transitioning.mapping_hash().as_bytes()
        );
        assert!(matches!(
            next_state.lifecycle(),
            ArityLifecycle::Transitioning(_)
        ));
    }

    #[test]
    fn quaternary_authority_is_persisted_and_rotated_by_an_authenticated_update_path() {
        let (alice_provider, alice_signer, mut alice, bob_provider, bob_signer, mut bob) =
            experimental_binary_pair_with_policy_controls(2, 0);
        let next_state = triggered_transition_state(&alice);
        let (transition_commit, _, _) = alice
            .begin_experimental_transition(&alice_provider, &alice_signer, next_state)
            .expect("sender stages authenticated transition Commit");
        let transition_wire = transition_commit
            .tls_serialize_detached()
            .expect("transition Commit serialization");
        let staged_transition = staged_commit_from_wire(&mut bob, &bob_provider, &transition_wire);
        bob.merge_staged_commit_experimental_transition_atomic(&bob_provider, staged_transition)
            .expect("receiver merges transition Commit");
        alice
            .merge_pending_commit_experimental_transition_atomic(&alice_provider)
            .expect("sender merges transition Commit");
        let authority_before = alice
            .experimental_quaternary_epoch_secret_status()
            .expect("transition authority");
        let root_public_key_hash_before = *authority_before.root_public_key_hash();

        let update_wire = hybrid_self_update_wire(
            &mut bob,
            &bob_provider,
            &bob_signer,
            LeafNodeParameters::default(),
        );
        let staged_update = staged_commit_from_wire(&mut alice, &alice_provider, &update_wire);
        alice
            .merge_staged_commit_experimental_quaternary_atomic(&alice_provider, staged_update)
            .expect("receiver merges authority-rotating UpdatePath");
        bob.merge_pending_commit_experimental_quaternary_atomic(&bob_provider)
            .expect("sender merges authority-rotating UpdatePath");

        let alice_authority = alice
            .experimental_quaternary_epoch_secret_status()
            .expect("rotated Alice authority");
        let bob_authority = bob
            .experimental_quaternary_epoch_secret_status()
            .expect("rotated Bob authority");
        assert_eq!(alice_authority, bob_authority);
        assert_eq!(alice_authority.epoch(), alice.epoch().as_u64());
        assert_eq!(alice_authority.epoch(), authority_before.epoch() + 1);
        assert_ne!(
            alice_authority.root_public_key_hash(),
            &root_public_key_hash_before,
            "the replacement epoch must retire the previous root key pair"
        );
        assert_eq!(alice.export_ratchet_tree(), bob.export_ratchet_tree());

        let reloaded_alice = MlsGroup::load(alice_provider.storage(), alice.group_id())
            .expect("Alice storage read")
            .expect("Alice stored group");
        assert_eq!(
            reloaded_alice.experimental_quaternary_epoch_secret_status(),
            Some(alice_authority)
        );
        assert_eq!(
            reloaded_alice
                .experimental_quaternary_epoch_secret_status()
                .expect("reloaded root status")
                .root_public_key_hash(),
            alice_authority.root_public_key_hash(),
            "the persisted root key pair must survive reload without exposing private bytes"
        );
    }

    #[test]
    fn signed_quaternary_commit_rejects_wrong_parent_metadata_and_recipient_without_mutation() {
        for mutation in [
            ExperimentalUpdatePathTestMutation::WrongFirstQuaternaryRecipient,
            ExperimentalUpdatePathTestMutation::WrongFirstQuaternaryParentOrdinal,
        ] {
            let (alice_provider, alice_signer, mut alice, bob_provider, bob_signer, mut bob) =
                experimental_binary_pair_with_policy_controls(2, 0);
            let transition_state = triggered_transition_state(&alice);
            let (transition_commit, _, _) = alice
                .begin_experimental_transition(&alice_provider, &alice_signer, transition_state)
                .expect("Alice stages transition");
            let transition_wire = transition_commit
                .tls_serialize_detached()
                .expect("transition wire");
            let staged_transition =
                staged_commit_from_wire(&mut bob, &bob_provider, &transition_wire);
            bob.merge_staged_commit_experimental_transition_atomic(
                &bob_provider,
                staged_transition,
            )
            .expect("Bob merges transition");
            alice
                .merge_pending_commit_experimental_transition_atomic(&alice_provider)
                .expect("Alice merges transition");

            let wire = hybrid_self_update_wire_with_test_mutation(
                &mut bob,
                &bob_provider,
                &bob_signer,
                mutation,
            );
            let epoch_before = alice.epoch();
            let tree_before = alice.export_ratchet_tree();
            let state_before = arity_state_from_group(&alice);
            let authority_before = alice.experimental_quaternary_epoch_secret_status();
            let protocol_message = MlsMessageIn::tls_deserialize_exact(&wire)
                .expect("signed mutated Commit parsing")
                .try_into_protocol_message()
                .expect("signed mutated protocol message");

            assert!(matches!(
                alice.process_message(&alice_provider, protocol_message),
                Err(ProcessMessageError::InvalidCommit(
                    StageCommitError::UpdatePathError(
                        ApplyUpdatePathError::UnableToDecrypt | ApplyUpdatePathError::PathMismatch
                    )
                ))
            ));
            assert_eq!(alice.epoch(), epoch_before);
            assert_eq!(alice.export_ratchet_tree(), tree_before);
            assert_eq!(arity_state_from_group(&alice), state_before);
            assert_eq!(
                alice.experimental_quaternary_epoch_secret_status(),
                authority_before
            );
        }
    }

    #[test]
    fn signed_quaternary_commit_rejects_missing_capabilities_without_mutation() {
        let (alice_provider, alice_signer, mut alice, bob_provider, bob_signer, mut bob) =
            experimental_binary_pair_with_policy_controls(2, 0);
        let transition_state = triggered_transition_state(&alice);
        let (transition_commit, _, _) = alice
            .begin_experimental_transition(&alice_provider, &alice_signer, transition_state)
            .expect("Alice stages transition");
        let transition_wire = transition_commit
            .tls_serialize_detached()
            .expect("transition wire");
        let staged_transition = staged_commit_from_wire(&mut bob, &bob_provider, &transition_wire);
        bob.merge_staged_commit_experimental_transition_atomic(&bob_provider, staged_transition)
            .expect("Bob merges transition");
        alice
            .merge_pending_commit_experimental_transition_atomic(&alice_provider)
            .expect("Alice merges transition");

        let wire = hybrid_self_update_wire(
            &mut bob,
            &bob_provider,
            &bob_signer,
            LeafNodeParameters::builder()
                .with_capabilities(Capabilities::new(
                    None,
                    None,
                    Some(&[required_mkyber_recipient_capabilities()[0]]),
                    None,
                    None,
                ))
                .build(),
        );
        let epoch_before = alice.epoch();
        let tree_before = alice.export_ratchet_tree();
        let state_before = arity_state_from_group(&alice);
        let authority_before = alice.experimental_quaternary_epoch_secret_status();
        let protocol_message = MlsMessageIn::tls_deserialize_exact(&wire)
            .expect("capability Commit parsing")
            .try_into_protocol_message()
            .expect("capability protocol message");

        assert!(matches!(
            alice.process_message(&alice_provider, protocol_message),
            Err(ProcessMessageError::InvalidCommit(
                StageCommitError::UpdatePathError(
                    ApplyUpdatePathError::MissingExperimentalCapability
                )
            ))
        ));
        assert_eq!(alice.epoch(), epoch_before);
        assert_eq!(alice.export_ratchet_tree(), tree_before);
        assert_eq!(arity_state_from_group(&alice), state_before);
        assert_eq!(
            alice.experimental_quaternary_epoch_secret_status(),
            authority_before
        );
    }

    #[test]
    fn signed_quaternary_commit_rejects_tamper_without_mutation() {
        let (alice_provider, alice_signer, mut alice, bob_provider, bob_signer, mut bob) =
            experimental_binary_pair_with_policy_controls(2, 0);
        let transition_state = triggered_transition_state(&alice);
        let (transition_commit, _, _) = alice
            .begin_experimental_transition(&alice_provider, &alice_signer, transition_state)
            .expect("Alice stages transition");
        let transition_wire = transition_commit
            .tls_serialize_detached()
            .expect("transition wire");
        let staged_transition = staged_commit_from_wire(&mut bob, &bob_provider, &transition_wire);
        bob.merge_staged_commit_experimental_transition_atomic(&bob_provider, staged_transition)
            .expect("Bob merges transition");
        alice
            .merge_pending_commit_experimental_transition_atomic(&alice_provider)
            .expect("Alice merges transition");

        let wire = hybrid_self_update_wire(
            &mut bob,
            &bob_provider,
            &bob_signer,
            LeafNodeParameters::default(),
        );
        let mut tampered_wire = wire.clone();
        let last_byte = tampered_wire
            .last_mut()
            .expect("serialized quaternary Commit is non-empty");
        *last_byte ^= 0x01;
        let epoch_before = alice.epoch();
        let tree_before = alice.export_ratchet_tree();
        let state_before = arity_state_from_group(&alice);
        let authority_before = alice.experimental_quaternary_epoch_secret_status();
        let tampered_message = MlsMessageIn::tls_deserialize_exact(&tampered_wire)
            .expect("tampered quaternary Commit remains syntactically valid")
            .try_into_protocol_message()
            .expect("tampered quaternary protocol message");

        assert!(alice
            .process_message(&alice_provider, tampered_message)
            .is_err());
        assert_eq!(alice.epoch(), epoch_before);
        assert_eq!(alice.export_ratchet_tree(), tree_before);
        assert_eq!(arity_state_from_group(&alice), state_before);
        assert_eq!(
            alice.experimental_quaternary_epoch_secret_status(),
            authority_before
        );
    }

    #[test]
    fn signed_quaternary_commit_replay_is_rejected_without_group_state_mutation() {
        let (alice_provider, alice_signer, mut alice, bob_provider, bob_signer, mut bob) =
            experimental_binary_pair_with_policy_controls(2, 0);
        let transition_state = triggered_transition_state(&alice);
        let (transition_commit, _, _) = alice
            .begin_experimental_transition(&alice_provider, &alice_signer, transition_state)
            .expect("Alice stages transition");
        let transition_wire = transition_commit
            .tls_serialize_detached()
            .expect("transition wire");
        let staged_transition = staged_commit_from_wire(&mut bob, &bob_provider, &transition_wire);
        bob.merge_staged_commit_experimental_transition_atomic(&bob_provider, staged_transition)
            .expect("Bob merges transition");
        alice
            .merge_pending_commit_experimental_transition_atomic(&alice_provider)
            .expect("Alice merges transition");

        let wire = hybrid_self_update_wire(
            &mut bob,
            &bob_provider,
            &bob_signer,
            LeafNodeParameters::default(),
        );
        let staged = staged_commit_from_wire(&mut alice, &alice_provider, &wire);
        alice
            .merge_staged_commit_experimental_quaternary_atomic(&alice_provider, staged)
            .expect("Alice merges valid quaternary Commit");
        bob.merge_pending_commit_experimental_quaternary_atomic(&bob_provider)
            .expect("Bob merges valid quaternary Commit");
        let epoch_before = alice.epoch();
        let tree_before = alice.export_ratchet_tree();
        let state_before = arity_state_from_group(&alice);
        let authority_before = alice.experimental_quaternary_epoch_secret_status();
        let replay_message = MlsMessageIn::tls_deserialize_exact(&wire)
            .expect("replay quaternary Commit parsing")
            .try_into_protocol_message()
            .expect("replay quaternary protocol message");

        assert!(alice
            .process_message(&alice_provider, replay_message)
            .is_err());
        assert_eq!(alice.epoch(), epoch_before);
        assert_eq!(alice.export_ratchet_tree(), tree_before);
        assert_eq!(arity_state_from_group(&alice), state_before);
        assert_eq!(
            alice.experimental_quaternary_epoch_secret_status(),
            authority_before
        );
    }

    #[test]
    fn binary_atomic_merge_rejects_a_transition_without_mutating_receiver_state() {
        let (alice_provider, alice_signer, mut alice, bob_provider, _bob_signer, mut bob) =
            experimental_binary_pair_with_policy_controls(2, 0);
        let next_state = triggered_transition_state(&alice);
        let (commit, _, _) = alice
            .begin_experimental_transition(&alice_provider, &alice_signer, next_state)
            .expect("sender stages authenticated transition Commit");
        let wire = commit
            .tls_serialize_detached()
            .expect("transition Commit serialization");
        let staged = staged_commit_from_wire(&mut bob, &bob_provider, &wire);
        let epoch_before = bob.epoch();
        let tree_before = bob.export_ratchet_tree();
        let state_before = arity_state_from_group(&bob);

        assert!(bob
            .merge_staged_commit_experimental_atomic(&bob_provider, staged)
            .is_err());
        assert_eq!(bob.epoch(), epoch_before);
        assert_eq!(bob.export_ratchet_tree(), tree_before);
        assert_eq!(arity_state_from_group(&bob), state_before);
    }

    #[test]
    fn experimental_binary_self_update_round_trips_through_tree_sync() {
        let (alice_provider, alice_signer, mut alice, bob_provider, bob_signer, mut bob) =
            experimental_binary_pair();
        let update_wire = hybrid_self_update_wire(
            &mut bob,
            &bob_provider,
            &bob_signer,
            LeafNodeParameters::default(),
        );
        let protocol_message = MlsMessageIn::tls_deserialize_exact(&update_wire)
            .expect("update parsing")
            .try_into_protocol_message()
            .expect("protocol message");
        let staged = alice
            .process_message(&alice_provider, protocol_message)
            .expect("Alice processes hybrid self-update");
        let ProcessedMessageContent::StagedCommitMessage(staged) = staged.into_content() else {
            panic!("expected staged Commit");
        };
        alice
            .merge_staged_commit_experimental_atomic(&alice_provider, *staged)
            .expect("Alice merges hybrid self-update");
        bob.merge_pending_commit_experimental_atomic(&bob_provider)
            .expect("Bob merges self-update");

        assert_eq!(alice.epoch(), bob.epoch());
        assert_eq!(alice.export_ratchet_tree(), bob.export_ratchet_tree());
        let alice_context = match alice
            .export_group_info(alice_provider.crypto(), &alice_signer, false)
            .expect("Alice GroupInfo")
            .body()
        {
            MlsMessageBodyOut::GroupInfo(group_info) => group_info
                .group_context()
                .tls_serialize_detached()
                .expect("Alice GroupContext serialization"),
            _ => panic!("expected Alice GroupInfo"),
        };
        let bob_context = match bob
            .export_group_info(bob_provider.crypto(), &bob_signer, false)
            .expect("Bob GroupInfo")
            .body()
        {
            MlsMessageBodyOut::GroupInfo(group_info) => group_info
                .group_context()
                .tls_serialize_detached()
                .expect("Bob GroupContext serialization"),
            _ => panic!("expected Bob GroupInfo"),
        };
        assert_eq!(alice_context, bob_context);
    }

    #[test]
    fn mapped_quaternary_parent_delivery_converges_three_members_and_reloads() {
        let (alice_provider, alice_signer, mut alice, bob_provider, bob_signer, mut bob) =
            experimental_binary_pair_with_policy_controls(3, 0);
        let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
        let domain = MkyberDomain::new([0x91; 32]);
        let charlie_provider = OpenMlsRustCrypto::default();
        let charlie_signer =
            SignatureKeyPair::new(ciphersuite.signature_algorithm()).expect("Charlie signer");
        let charlie_credential = CredentialWithKey {
            credential: BasicCredential::new(b"experimental-charlie".to_vec()).into(),
            signature_key: charlie_signer.public().into(),
        };
        let charlie_bundle = KeyPackage::builder()
            .build_with_experimental_mkyber(
                ciphersuite,
                &charlie_provider,
                &charlie_signer,
                charlie_credential,
                domain,
            )
            .expect("Charlie experimental KeyPackage");
        let (add_commit, welcome, _) = alice
            .add_members(
                &alice_provider,
                &alice_signer,
                core::slice::from_ref(charlie_bundle.key_package()),
            )
            .expect("Alice adds Charlie");
        let add_wire = add_commit
            .tls_serialize_detached()
            .expect("add Commit serialization");
        let bob_staged = staged_commit_from_wire(&mut bob, &bob_provider, &add_wire);
        alice
            .merge_pending_commit_experimental_atomic(&alice_provider)
            .expect("Alice atomically merges Charlie add");
        bob.merge_staged_commit_experimental_atomic(&bob_provider, bob_staged)
            .expect("Bob atomically merges Charlie add");

        let welcome = match MlsMessageIn::tls_deserialize_exact(
            welcome
                .tls_serialize_detached()
                .expect("Charlie Welcome serialization"),
        )
        .expect("Charlie Welcome parsing")
        .extract()
        {
            MlsMessageBodyIn::Welcome(welcome) => welcome,
            _ => panic!("expected Charlie Welcome"),
        };
        let mut charlie = StagedWelcome::new_from_welcome(
            &charlie_provider,
            &MlsGroupJoinConfig::builder()
                .use_ratchet_tree_extension(true)
                .build(),
            welcome,
            None,
        )
        .expect("Charlie staged Welcome")
        .into_group(&charlie_provider)
        .expect("Charlie joins");

        let transition_state = triggered_transition_state(&alice);
        let (transition_commit, _, _) = alice
            .begin_experimental_transition(&alice_provider, &alice_signer, transition_state)
            .expect("Alice stages mapped transition");
        let transition_wire = transition_commit
            .tls_serialize_detached()
            .expect("mapped transition serialization");
        let bob_transition = staged_commit_from_wire(&mut bob, &bob_provider, &transition_wire);
        let charlie_transition =
            staged_commit_from_wire(&mut charlie, &charlie_provider, &transition_wire);
        bob.merge_staged_commit_experimental_transition_atomic(&bob_provider, bob_transition)
            .expect("Bob atomically merges mapped transition");
        charlie
            .merge_staged_commit_experimental_transition_atomic(
                &charlie_provider,
                charlie_transition,
            )
            .expect("Charlie atomically merges mapped transition");
        alice
            .merge_pending_commit_experimental_transition_atomic(&alice_provider)
            .expect("Alice atomically merges mapped transition");
        for group in [&alice, &bob, &charlie] {
            assert_eq!(
                group
                    .experimental_quaternary_epoch_secret_status()
                    .expect("mapped transition authority")
                    .parent_key_count(),
                1,
                "three members occupy one quaternary root parent"
            );
        }

        let update_wire = hybrid_self_update_wire(
            &mut bob,
            &bob_provider,
            &bob_signer,
            LeafNodeParameters::default(),
        );
        let alice_staged = staged_commit_from_wire(&mut alice, &alice_provider, &update_wire);
        let charlie_staged = staged_commit_from_wire(&mut charlie, &charlie_provider, &update_wire);
        alice
            .merge_staged_commit_experimental_quaternary_atomic(&alice_provider, alice_staged)
            .expect("Alice atomically merges Bob update");
        charlie
            .merge_staged_commit_experimental_quaternary_atomic(&charlie_provider, charlie_staged)
            .expect("Charlie atomically merges Bob update");
        bob.merge_pending_commit_experimental_quaternary_atomic(&bob_provider)
            .expect("Bob atomically merges own update");

        assert_eq!(alice.epoch(), bob.epoch());
        assert_eq!(bob.epoch(), charlie.epoch());
        assert_eq!(alice.export_ratchet_tree(), bob.export_ratchet_tree());
        assert_eq!(bob.export_ratchet_tree(), charlie.export_ratchet_tree());
        assert_eq!(alice.extensions(), bob.extensions());
        assert_eq!(bob.extensions(), charlie.extensions());
        for group in [&alice, &bob, &charlie] {
            assert_eq!(
                group
                    .experimental_quaternary_epoch_secret_status()
                    .expect("mapped parent authority")
                    .parent_key_count(),
                1,
            );
        }

        for (provider, group) in [
            (&alice_provider, &alice),
            (&bob_provider, &bob),
            (&charlie_provider, &charlie),
        ] {
            let reloaded = MlsGroup::load(provider.storage(), group.group_id())
                .expect("group reload storage access")
                .expect("stored group");
            assert_eq!(reloaded.epoch(), group.epoch());
            assert_eq!(reloaded.export_ratchet_tree(), group.export_ratchet_tree());
            assert_eq!(reloaded.extensions(), group.extensions());
        }
    }

    #[test]
    fn mapped_quaternary_parent_path_delivers_root_and_child_for_five_members() {
        let (alice_provider, alice_signer, mut alice, bob_provider, bob_signer, mut bob) =
            experimental_binary_pair_with_policy_controls(5, 0);
        let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
        let domain = MkyberDomain::new([0x91; 32]);

        let charlie_provider = OpenMlsRustCrypto::default();
        let charlie_signer =
            SignatureKeyPair::new(ciphersuite.signature_algorithm()).expect("Charlie signer");
        let charlie_bundle = KeyPackage::builder()
            .build_with_experimental_mkyber(
                ciphersuite,
                &charlie_provider,
                &charlie_signer,
                CredentialWithKey {
                    credential: BasicCredential::new(b"experimental-charlie".to_vec()).into(),
                    signature_key: charlie_signer.public().into(),
                },
                domain,
            )
            .expect("Charlie experimental KeyPackage");
        let (charlie_add, charlie_welcome, _) = alice
            .add_members(
                &alice_provider,
                &alice_signer,
                core::slice::from_ref(charlie_bundle.key_package()),
            )
            .expect("Alice adds Charlie");
        let charlie_add_wire = charlie_add
            .tls_serialize_detached()
            .expect("Charlie add wire");
        let bob_charlie_add = staged_commit_from_wire(&mut bob, &bob_provider, &charlie_add_wire);
        alice
            .merge_pending_commit_experimental_atomic(&alice_provider)
            .expect("Alice merges Charlie add");
        bob.merge_staged_commit_experimental_atomic(&bob_provider, bob_charlie_add)
            .expect("Bob merges Charlie add");
        let mut charlie = StagedWelcome::new_from_welcome(
            &charlie_provider,
            &MlsGroupJoinConfig::builder()
                .use_ratchet_tree_extension(true)
                .build(),
            match MlsMessageIn::tls_deserialize_exact(
                charlie_welcome
                    .tls_serialize_detached()
                    .expect("Charlie Welcome wire"),
            )
            .expect("Charlie Welcome parsing")
            .extract()
            {
                MlsMessageBodyIn::Welcome(welcome) => welcome,
                _ => panic!("expected Charlie Welcome"),
            },
            None,
        )
        .expect("Charlie staged Welcome")
        .into_group(&charlie_provider)
        .expect("Charlie joins");

        let dave_provider = OpenMlsRustCrypto::default();
        let dave_signer =
            SignatureKeyPair::new(ciphersuite.signature_algorithm()).expect("Dave signer");
        let dave_bundle = KeyPackage::builder()
            .build_with_experimental_mkyber(
                ciphersuite,
                &dave_provider,
                &dave_signer,
                CredentialWithKey {
                    credential: BasicCredential::new(b"experimental-dave".to_vec()).into(),
                    signature_key: dave_signer.public().into(),
                },
                domain,
            )
            .expect("Dave experimental KeyPackage");
        let (dave_add, dave_welcome, _) = alice
            .add_members(
                &alice_provider,
                &alice_signer,
                core::slice::from_ref(dave_bundle.key_package()),
            )
            .expect("Alice adds Dave");
        let dave_add_wire = dave_add.tls_serialize_detached().expect("Dave add wire");
        let bob_dave_add = staged_commit_from_wire(&mut bob, &bob_provider, &dave_add_wire);
        let charlie_dave_add =
            staged_commit_from_wire(&mut charlie, &charlie_provider, &dave_add_wire);
        alice
            .merge_pending_commit_experimental_atomic(&alice_provider)
            .expect("Alice merges Dave add");
        bob.merge_staged_commit_experimental_atomic(&bob_provider, bob_dave_add)
            .expect("Bob merges Dave add");
        charlie
            .merge_staged_commit_experimental_atomic(&charlie_provider, charlie_dave_add)
            .expect("Charlie merges Dave add");
        let mut dave = StagedWelcome::new_from_welcome(
            &dave_provider,
            &MlsGroupJoinConfig::builder()
                .use_ratchet_tree_extension(true)
                .build(),
            match MlsMessageIn::tls_deserialize_exact(
                dave_welcome
                    .tls_serialize_detached()
                    .expect("Dave Welcome wire"),
            )
            .expect("Dave Welcome parsing")
            .extract()
            {
                MlsMessageBodyIn::Welcome(welcome) => welcome,
                _ => panic!("expected Dave Welcome"),
            },
            None,
        )
        .expect("Dave staged Welcome")
        .into_group(&dave_provider)
        .expect("Dave joins");

        let eve_provider = OpenMlsRustCrypto::default();
        let eve_signer =
            SignatureKeyPair::new(ciphersuite.signature_algorithm()).expect("Eve signer");
        let eve_bundle = KeyPackage::builder()
            .build_with_experimental_mkyber(
                ciphersuite,
                &eve_provider,
                &eve_signer,
                CredentialWithKey {
                    credential: BasicCredential::new(b"experimental-eve".to_vec()).into(),
                    signature_key: eve_signer.public().into(),
                },
                domain,
            )
            .expect("Eve experimental KeyPackage");
        let (eve_add, eve_welcome, _) = alice
            .add_members(
                &alice_provider,
                &alice_signer,
                core::slice::from_ref(eve_bundle.key_package()),
            )
            .expect("Alice adds Eve");
        let eve_add_wire = eve_add.tls_serialize_detached().expect("Eve add wire");
        let bob_eve_add = staged_commit_from_wire(&mut bob, &bob_provider, &eve_add_wire);
        let charlie_eve_add =
            staged_commit_from_wire(&mut charlie, &charlie_provider, &eve_add_wire);
        let dave_eve_add = staged_commit_from_wire(&mut dave, &dave_provider, &eve_add_wire);
        alice
            .merge_pending_commit_experimental_atomic(&alice_provider)
            .expect("Alice merges Eve add");
        bob.merge_staged_commit_experimental_atomic(&bob_provider, bob_eve_add)
            .expect("Bob merges Eve add");
        charlie
            .merge_staged_commit_experimental_atomic(&charlie_provider, charlie_eve_add)
            .expect("Charlie merges Eve add");
        dave.merge_staged_commit_experimental_atomic(&dave_provider, dave_eve_add)
            .expect("Dave merges Eve add");
        let mut eve = StagedWelcome::new_from_welcome(
            &eve_provider,
            &MlsGroupJoinConfig::builder()
                .use_ratchet_tree_extension(true)
                .build(),
            match MlsMessageIn::tls_deserialize_exact(
                eve_welcome
                    .tls_serialize_detached()
                    .expect("Eve Welcome wire"),
            )
            .expect("Eve Welcome parsing")
            .extract()
            {
                MlsMessageBodyIn::Welcome(welcome) => welcome,
                _ => panic!("expected Eve Welcome"),
            },
            None,
        )
        .expect("Eve staged Welcome")
        .into_group(&eve_provider)
        .expect("Eve joins");

        let transition_state = triggered_transition_state(&alice);
        let (transition_commit, _, _) = alice
            .begin_experimental_transition(&alice_provider, &alice_signer, transition_state)
            .expect("Alice stages five-member transition");
        let transition_wire = transition_commit
            .tls_serialize_detached()
            .expect("transition wire");
        let bob_transition = staged_commit_from_wire(&mut bob, &bob_provider, &transition_wire);
        let charlie_transition =
            staged_commit_from_wire(&mut charlie, &charlie_provider, &transition_wire);
        let dave_transition = staged_commit_from_wire(&mut dave, &dave_provider, &transition_wire);
        let eve_transition = staged_commit_from_wire(&mut eve, &eve_provider, &transition_wire);
        for (group, provider, staged) in [
            (&mut bob, &bob_provider, bob_transition),
            (&mut charlie, &charlie_provider, charlie_transition),
            (&mut dave, &dave_provider, dave_transition),
            (&mut eve, &eve_provider, eve_transition),
        ] {
            group
                .merge_staged_commit_experimental_transition_atomic(provider, staged)
                .expect("receiver merges five-member transition");
        }
        alice
            .merge_pending_commit_experimental_transition_atomic(&alice_provider)
            .expect("Alice merges five-member transition");

        let update_wire = hybrid_self_update_wire(
            &mut bob,
            &bob_provider,
            &bob_signer,
            LeafNodeParameters::default(),
        );
        let alice_update = staged_commit_from_wire(&mut alice, &alice_provider, &update_wire);
        let charlie_update = staged_commit_from_wire(&mut charlie, &charlie_provider, &update_wire);
        let dave_update = staged_commit_from_wire(&mut dave, &dave_provider, &update_wire);
        let eve_update = staged_commit_from_wire(&mut eve, &eve_provider, &update_wire);
        for (group, provider, staged) in [
            (&mut alice, &alice_provider, alice_update),
            (&mut charlie, &charlie_provider, charlie_update),
            (&mut dave, &dave_provider, dave_update),
            (&mut eve, &eve_provider, eve_update),
        ] {
            group
                .merge_staged_commit_experimental_quaternary_atomic(provider, staged)
                .expect("receiver merges mapped root and child path");
        }
        bob.merge_pending_commit_experimental_quaternary_atomic(&bob_provider)
            .expect("Bob merges mapped root and child path");
        for group in [&alice, &bob, &charlie, &dave, &eve] {
            assert_eq!(
                group
                    .experimental_quaternary_epoch_secret_status()
                    .expect("five-member mapped authority")
                    .parent_key_count(),
                2,
                "five members require root plus one depth-1 parent for Bob's mapped path"
            );
        }
    }

    #[test]
    fn experimental_atomic_receiver_merge_rolls_back_every_storage_mutation() {
        let (control_provider, _alice_signer, mut control, bob_provider, bob_signer, mut bob) =
            experimental_binary_pair();
        let control_wire = hybrid_self_update_wire(
            &mut bob,
            &bob_provider,
            &bob_signer,
            LeafNodeParameters::default(),
        );
        let control_staged =
            staged_commit_from_wire(&mut control, &control_provider, &control_wire);
        control_provider.storage().set_transaction_failure_at(None);
        control
            .merge_staged_commit_experimental_atomic(&control_provider, control_staged)
            .expect("control receiver merge");
        let mutation_count = control_provider.storage().last_transaction_mutation_count();
        assert!(mutation_count > 0);

        for failure_at in 0..mutation_count {
            let (alice_provider, _alice_signer, mut alice, bob_provider, bob_signer, mut bob) =
                experimental_binary_pair();
            let update_wire = hybrid_self_update_wire(
                &mut bob,
                &bob_provider,
                &bob_signer,
                LeafNodeParameters::default(),
            );
            let staged = staged_commit_from_wire(&mut alice, &alice_provider, &update_wire);
            let before_epoch = alice.epoch();
            let before_tree = alice.export_ratchet_tree();
            let before_extensions = alice.extensions().clone();
            let before_storage = alice_provider.storage().values.read().unwrap().clone();
            alice_provider
                .storage()
                .set_transaction_failure_at(Some(failure_at));

            assert!(alice
                .merge_staged_commit_experimental_atomic(&alice_provider, staged)
                .is_err());
            assert_eq!(alice.epoch(), before_epoch);
            assert_eq!(alice.export_ratchet_tree(), before_tree);
            assert_eq!(alice.extensions(), &before_extensions);
            assert_eq!(
                *alice_provider.storage().values.read().unwrap(),
                before_storage
            );
            let reloaded = MlsGroup::load(alice_provider.storage(), alice.group_id())
                .expect("failed transaction remains loadable")
                .expect("stored pre-merge group");
            assert_eq!(reloaded.epoch(), before_epoch);
            assert_eq!(reloaded.export_ratchet_tree(), before_tree);
            assert_eq!(reloaded.extensions(), &before_extensions);
        }
    }

    #[test]
    fn experimental_atomic_pending_merge_rolls_back_every_storage_mutation() {
        let (_alice_provider, _alice_signer, _alice, control_provider, control_signer, mut control) =
            experimental_binary_pair();
        let _control_wire = hybrid_self_update_wire(
            &mut control,
            &control_provider,
            &control_signer,
            LeafNodeParameters::default(),
        );
        control_provider.storage().set_transaction_failure_at(None);
        control
            .merge_pending_commit_experimental_atomic(&control_provider)
            .expect("control pending merge");
        let mutation_count = control_provider.storage().last_transaction_mutation_count();
        assert!(mutation_count > 0);

        for failure_at in 0..mutation_count {
            let (_alice_provider, _alice_signer, _alice, bob_provider, bob_signer, mut bob) =
                experimental_binary_pair();
            let _update_wire = hybrid_self_update_wire(
                &mut bob,
                &bob_provider,
                &bob_signer,
                LeafNodeParameters::default(),
            );
            let before_epoch = bob.epoch();
            let before_tree = bob.export_ratchet_tree();
            let before_extensions = bob.extensions().clone();
            let before_storage = bob_provider.storage().values.read().unwrap().clone();
            assert!(bob.pending_commit().is_some());
            bob_provider
                .storage()
                .set_transaction_failure_at(Some(failure_at));

            assert!(bob
                .merge_pending_commit_experimental_atomic(&bob_provider)
                .is_err());
            assert_eq!(bob.epoch(), before_epoch);
            assert_eq!(bob.export_ratchet_tree(), before_tree);
            assert_eq!(bob.extensions(), &before_extensions);
            assert!(bob.pending_commit().is_some());
            assert_eq!(
                *bob_provider.storage().values.read().unwrap(),
                before_storage
            );
            let reloaded = MlsGroup::load(bob_provider.storage(), bob.group_id())
                .expect("failed pending transaction remains loadable")
                .expect("stored pending group");
            assert_eq!(reloaded.epoch(), before_epoch);
            assert_eq!(reloaded.export_ratchet_tree(), before_tree);
            assert_eq!(reloaded.extensions(), &before_extensions);
            assert!(reloaded.pending_commit().is_some());
        }
    }

    #[test]
    fn transition_atomic_receiver_merge_rolls_back_every_storage_mutation() {
        let (alice_provider, alice_signer, mut alice, bob_provider, _bob_signer, mut bob) =
            experimental_binary_pair_with_policy_controls(2, 0);
        let transition_state = triggered_transition_state(&alice);
        let (transition_commit, _, _) = alice
            .begin_experimental_transition(&alice_provider, &alice_signer, transition_state)
            .expect("Alice stages control transition");
        let transition_wire = transition_commit
            .tls_serialize_detached()
            .expect("control transition wire");
        let control_staged = staged_commit_from_wire(&mut bob, &bob_provider, &transition_wire);
        bob_provider.storage().set_transaction_failure_at(None);
        bob.merge_staged_commit_experimental_transition_atomic(&bob_provider, control_staged)
            .expect("control transition receiver merge");
        let mutation_count = bob_provider.storage().last_transaction_mutation_count();
        assert!(mutation_count > 0);

        for failure_at in 0..mutation_count {
            let (alice_provider, alice_signer, mut alice, bob_provider, _bob_signer, mut bob) =
                experimental_binary_pair_with_policy_controls(2, 0);
            let transition_state = triggered_transition_state(&alice);
            let (transition_commit, _, _) = alice
                .begin_experimental_transition(&alice_provider, &alice_signer, transition_state)
                .expect("Alice stages transition");
            let transition_wire = transition_commit
                .tls_serialize_detached()
                .expect("transition wire");
            let staged = staged_commit_from_wire(&mut bob, &bob_provider, &transition_wire);
            let before_epoch = bob.epoch();
            let before_tree = bob.export_ratchet_tree();
            let before_extensions = bob.extensions().clone();
            let before_authority = bob.experimental_quaternary_epoch_secret_status();
            let before_storage = bob_provider.storage().values.read().unwrap().clone();
            bob_provider
                .storage()
                .set_transaction_failure_at(Some(failure_at));

            assert!(bob
                .merge_staged_commit_experimental_transition_atomic(&bob_provider, staged)
                .is_err());
            assert_eq!(bob.epoch(), before_epoch);
            assert_eq!(bob.export_ratchet_tree(), before_tree);
            assert_eq!(bob.extensions(), &before_extensions);
            assert_eq!(
                bob.experimental_quaternary_epoch_secret_status(),
                before_authority
            );
            assert_eq!(
                *bob_provider.storage().values.read().unwrap(),
                before_storage
            );
            let reloaded = MlsGroup::load(bob_provider.storage(), bob.group_id())
                .expect("failed transition transaction remains loadable")
                .expect("stored pre-transition group");
            assert_eq!(reloaded.epoch(), before_epoch);
            assert_eq!(reloaded.export_ratchet_tree(), before_tree);
            assert_eq!(reloaded.extensions(), &before_extensions);
            assert_eq!(
                reloaded.experimental_quaternary_epoch_secret_status(),
                before_authority
            );
        }
    }

    #[test]
    fn transition_atomic_pending_merge_rolls_back_every_storage_mutation() {
        let (control_provider, control_signer, mut control, _bob_provider, _bob_signer, _bob) =
            experimental_binary_pair_with_policy_controls(2, 0);
        let transition_state = triggered_transition_state(&control);
        let (_control_commit, _, _) = control
            .begin_experimental_transition(&control_provider, &control_signer, transition_state)
            .expect("control sender stages transition");
        control_provider.storage().set_transaction_failure_at(None);
        control
            .merge_pending_commit_experimental_transition_atomic(&control_provider)
            .expect("control transition pending merge");
        let mutation_count = control_provider.storage().last_transaction_mutation_count();
        assert!(mutation_count > 0);

        for failure_at in 0..mutation_count {
            let (alice_provider, alice_signer, mut alice, _bob_provider, _bob_signer, _bob) =
                experimental_binary_pair_with_policy_controls(2, 0);
            let transition_state = triggered_transition_state(&alice);
            let (_transition_commit, _, _) = alice
                .begin_experimental_transition(&alice_provider, &alice_signer, transition_state)
                .expect("Alice stages transition");
            let before_epoch = alice.epoch();
            let before_tree = alice.export_ratchet_tree();
            let before_extensions = alice.extensions().clone();
            let before_authority = alice.experimental_quaternary_epoch_secret_status();
            let before_storage = alice_provider.storage().values.read().unwrap().clone();
            assert!(alice.pending_commit().is_some());
            alice_provider
                .storage()
                .set_transaction_failure_at(Some(failure_at));

            assert!(alice
                .merge_pending_commit_experimental_transition_atomic(&alice_provider)
                .is_err());
            assert_eq!(alice.epoch(), before_epoch);
            assert_eq!(alice.export_ratchet_tree(), before_tree);
            assert_eq!(alice.extensions(), &before_extensions);
            assert_eq!(
                alice.experimental_quaternary_epoch_secret_status(),
                before_authority
            );
            assert!(alice.pending_commit().is_some());
            assert_eq!(
                *alice_provider.storage().values.read().unwrap(),
                before_storage
            );
            let reloaded = MlsGroup::load(alice_provider.storage(), alice.group_id())
                .expect("failed transition pending transaction remains loadable")
                .expect("stored pending transition group");
            assert_eq!(reloaded.epoch(), before_epoch);
            assert_eq!(reloaded.export_ratchet_tree(), before_tree);
            assert_eq!(reloaded.extensions(), &before_extensions);
            assert_eq!(
                reloaded.experimental_quaternary_epoch_secret_status(),
                before_authority
            );
            assert!(reloaded.pending_commit().is_some());
        }
    }

    #[test]
    fn experimental_binary_commit_rejects_tampered_wire_without_mutation() {
        let (alice_provider, _alice_signer, mut alice, bob_provider, bob_signer, mut bob) =
            experimental_binary_pair();
        let mut update_wire = hybrid_self_update_wire(
            &mut bob,
            &bob_provider,
            &bob_signer,
            LeafNodeParameters::default(),
        );
        let before_epoch = alice.epoch();
        let before_tree = alice.export_ratchet_tree();
        let last_byte = update_wire.last_mut().expect("non-empty Commit wire");
        *last_byte ^= 0x01;
        let protocol_message = MlsMessageIn::tls_deserialize_exact(&update_wire)
            .expect("tampered fixed-length wire remains parseable")
            .try_into_protocol_message()
            .expect("tampered Commit remains a protocol message");

        assert!(alice
            .process_message(&alice_provider, protocol_message)
            .is_err());
        assert_eq!(alice.epoch(), before_epoch);
        assert_eq!(alice.export_ratchet_tree(), before_tree);
    }

    #[test]
    fn experimental_binary_commit_rejects_malformed_wire_without_mutation() {
        let (_alice_provider, _alice_signer, alice, bob_provider, bob_signer, mut bob) =
            experimental_binary_pair();
        let mut update_wire = hybrid_self_update_wire(
            &mut bob,
            &bob_provider,
            &bob_signer,
            LeafNodeParameters::default(),
        );
        let before_epoch = alice.epoch();
        let before_tree = alice.export_ratchet_tree();
        update_wire.pop().expect("non-empty Commit wire");

        assert!(MlsMessageIn::tls_deserialize_exact(&update_wire).is_err());
        assert_eq!(alice.epoch(), before_epoch);
        assert_eq!(alice.export_ratchet_tree(), before_tree);
    }

    #[test]
    fn experimental_binary_commit_rejects_non_member_receiver_without_mutation() {
        let (_alice_provider, _alice_signer, _alice, bob_provider, bob_signer, mut bob) =
            experimental_binary_pair();
        let update_wire = hybrid_self_update_wire(
            &mut bob,
            &bob_provider,
            &bob_signer,
            LeafNodeParameters::default(),
        );
        let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
        let mallory_provider = OpenMlsRustCrypto::default();
        let mallory_signer =
            SignatureKeyPair::new(ciphersuite.signature_algorithm()).expect("Mallory signer");
        let mallory_credential = CredentialWithKey {
            credential: BasicCredential::new(b"experimental-mallory".to_vec()).into(),
            signature_key: mallory_signer.public().into(),
        };
        let mut mallory = MlsGroup::new_with_group_id_experimental_mkyber(
            &mallory_provider,
            &mallory_signer,
            &MlsGroupCreateConfig::builder()
                .ciphersuite(ciphersuite)
                .use_ratchet_tree_extension(true)
                .with_group_context_extensions(normal_binary_arity_extensions())
                .build(),
            openmls_hybrid::prelude::GroupId::from_slice(b"non-member-receiver"),
            mallory_credential,
            MkyberDomain::new([0x91; 32]),
        )
        .expect("Mallory experimental group creation");
        let before_epoch = mallory.epoch();
        let before_tree = mallory.export_ratchet_tree();
        let protocol_message = MlsMessageIn::tls_deserialize_exact(&update_wire)
            .expect("non-member Commit parsing")
            .try_into_protocol_message()
            .expect("non-member protocol message");

        assert!(mallory
            .process_message(&mallory_provider, protocol_message)
            .is_err());
        assert_eq!(mallory.epoch(), before_epoch);
        assert_eq!(mallory.export_ratchet_tree(), before_tree);
    }

    #[test]
    fn experimental_binary_commit_replay_is_rejected_without_mutation() {
        let (alice_provider, _alice_signer, mut alice, bob_provider, bob_signer, mut bob) =
            experimental_binary_pair();
        let update_wire = hybrid_self_update_wire(
            &mut bob,
            &bob_provider,
            &bob_signer,
            LeafNodeParameters::default(),
        );
        let protocol_message = MlsMessageIn::tls_deserialize_exact(&update_wire)
            .expect("update parsing")
            .try_into_protocol_message()
            .expect("protocol message");
        let staged = alice
            .process_message(&alice_provider, protocol_message)
            .expect("Alice processes hybrid self-update");
        let ProcessedMessageContent::StagedCommitMessage(staged) = staged.into_content() else {
            panic!("expected staged Commit");
        };
        alice
            .merge_staged_commit_experimental_atomic(&alice_provider, *staged)
            .expect("Alice merges hybrid self-update");
        bob.merge_pending_commit_experimental_atomic(&bob_provider)
            .expect("Bob merges self-update");
        let before_epoch = alice.epoch();
        let before_tree = alice.export_ratchet_tree();
        let replay = MlsMessageIn::tls_deserialize_exact(&update_wire)
            .expect("replay parsing")
            .try_into_protocol_message()
            .expect("replay protocol message");

        assert!(alice.process_message(&alice_provider, replay).is_err());
        assert_eq!(alice.epoch(), before_epoch);
        assert_eq!(alice.export_ratchet_tree(), before_tree);
    }

    #[test]
    fn experimental_binary_commit_rejects_missing_sender_capabilities_without_mutation() {
        let (alice_provider, _alice_signer, mut alice, bob_provider, bob_signer, mut bob) =
            experimental_binary_pair();
        let update_wire = hybrid_self_update_wire(
            &mut bob,
            &bob_provider,
            &bob_signer,
            LeafNodeParameters::builder()
                .with_capabilities(Capabilities::new(
                    None,
                    None,
                    Some(&[required_mkyber_recipient_capabilities()[0]]),
                    None,
                    None,
                ))
                .build(),
        );
        let before_epoch = alice.epoch();
        let before_tree = alice.export_ratchet_tree();
        let protocol_message = MlsMessageIn::tls_deserialize_exact(&update_wire)
            .expect("capability-rejection Commit parsing")
            .try_into_protocol_message()
            .expect("capability-rejection protocol message");

        assert!(matches!(
            alice
                .process_message(&alice_provider, protocol_message)
                .expect_err("missing experimental capabilities must be rejected"),
            ProcessMessageError::InvalidCommit(StageCommitError::UpdatePathError(
                ApplyUpdatePathError::MissingExperimentalCapability
            ))
        ));
        assert_eq!(alice.epoch(), before_epoch);
        assert_eq!(alice.export_ratchet_tree(), before_tree);
    }

    #[test]
    fn experimental_mkyber_epoch_keypairs_replace_only_when_self_update_merges() {
        let (_alice_provider, _alice_signer, _alice, bob_provider, bob_signer, mut bob) =
            experimental_binary_pair();
        let old_epoch = bob.epoch();
        let old_leaf_key = bob
            .own_leaf_node()
            .expect("Bob own leaf")
            .encryption_key()
            .clone();
        let old_mkyber_keypair_count = bob
            .experimental_mkyber_epoch_keypair_count(&bob_provider, old_epoch)
            .expect("old epoch mKyber key-pair status");
        assert!(old_mkyber_keypair_count > 0);

        let _update_wire = hybrid_self_update_wire(
            &mut bob,
            &bob_provider,
            &bob_signer,
            LeafNodeParameters::default(),
        );
        assert_eq!(bob.epoch(), old_epoch);
        assert_eq!(
            bob.experimental_mkyber_epoch_keypair_count(&bob_provider, old_epoch)
                .expect("pending self-update retains old epoch key pairs"),
            old_mkyber_keypair_count
        );

        bob.merge_pending_commit_experimental_atomic(&bob_provider)
            .expect("Bob merges self-update");
        let new_epoch = bob.epoch();
        let new_leaf_key = bob
            .own_leaf_node()
            .expect("Bob updated own leaf")
            .encryption_key();

        assert_ne!(new_epoch, old_epoch);
        assert_ne!(new_leaf_key, &old_leaf_key);
        assert_eq!(
            bob.experimental_mkyber_epoch_keypair_count(&bob_provider, old_epoch)
                .expect("retired epoch key-pair status"),
            0
        );
        assert!(
            bob.experimental_mkyber_epoch_keypair_count(&bob_provider, new_epoch)
                .expect("new epoch mKyber key-pair status")
                > 0
        );
    }
}
