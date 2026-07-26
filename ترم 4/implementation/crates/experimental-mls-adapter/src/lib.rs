#![forbid(unsafe_code)]

//! Isolated activation boundary for the local experimental OpenMLS fork.
//!
//! This crate deliberately links the separately named fork without exposing
//! it through the unchanged baseline adapter. Its public workload client is
//! deliberately restricted to normal binary mKyber self-updates accepted by
//! the fork's atomic application boundary. The created groups nevertheless
//! require the private-use ArityState capability so Task 60 transition Commits
//! can be authenticated by every member.

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    time::Instant,
};

use adaptive_tree::{BinaryLeafMember, BinaryToQuaternaryLeafMapping, ShadowQuaternaryTree};
use arity_state::{
    hash_canonical_public_bytes, ArityLifecycle, ArityPolicySnapshot, ArityState, MappingHash,
    TransitionEvaluationState, TreeCoverBinding,
};
use mkyber::{EducationalMkyber512Reference, MkyberDomain};
use openmls_hybrid::{
    experimental_hybrid::{
        mkyber_recipient_capabilities, ExperimentalHybridCommitMetrics,
        ExperimentalHybridCommitTopology, ExperimentalHybridDeliveryTree,
        ExperimentalTreeCoverRetirementEvidence,
    },
    prelude::{
        BasicCredential, Ciphersuite, CredentialWithKey, Extension, ExtensionType, Extensions,
        GroupContext, GroupId, KeyPackage, LeafNodeParameters, MlsGroup, MlsGroupCreateConfig,
        MlsGroupJoinConfig, MlsMessageBodyIn, MlsMessageIn, ProcessedMessageContent,
        RequiredCapabilitiesExtension, StagedCommit, StagedWelcome, UnknownExtension,
    },
};
use openmls_hybrid_basic_credential::SignatureKeyPair;
use openmls_hybrid_rust_crypto::OpenMlsRustCrypto;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
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
use transition_tree::{
    DeliveryEndpointHealth, DeliveryNodeAvailability, DeliveryOnlyTreeCover, ExactRecipientCovers,
    QuaternaryNode, TransitionTrees,
};

/// Exact upstream OpenMLS revision used by the local fork.
pub const OPENMLS_HYBRID_UPSTREAM_REVISION: &str = "47dbedecad0c1fd8eb5368d582250ebfcc1e1ce6";
/// Fixed classical MLS/HPKE suite used by the baseline and hybrid clients.
pub const CLASSICAL_MLS_HPKE_PROFILE: &str =
    "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519; DHKEM(X25519, HKDF-SHA256); AES-128-GCM";
/// Educational mKyber backend profile; it is not a production KEM claim.
pub const EDUCATIONAL_MKYBER_PROFILE: &str = EducationalMkyber512Reference::PROFILE_LABEL;

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

/// Selects which real byte comparison can authorize an adaptive transition.
///
/// Both modes compare only matched sender/path observations in the current
/// impactful window, and require the compact candidate total to be strictly
/// smaller than the observed normal-binary total. The amortized mode also
/// requires that the observed savings repay the measured transition preflight.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExperimentalAdaptiveTransitionPolicy {
    /// Use ADR 0006's exact amortized calculation, including the real measured
    /// transition-preflight bytes.
    AmortizeTransitionPreflight,
    /// Authorize from the exact matched per-Commit saving alone. This does not
    /// claim that the transition Commit itself has been amortized.
    MatchedPerCommitSaving,
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

/// Authenticated public topology and recipient sets for one accepted
/// post-transition Update Commit.
///
/// The tree bindings come from the accepted GroupContext `ArityState`; the
/// recipient sets come from the same signed Commit. This contains no
/// ciphertext, public-key bytes, private keys, or path secrets.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedAdaptiveTopologySnapshot {
    /// Public MLS group identifier.
    pub group_id: Vec<u8>,
    /// Converged epoch that accepted the signed recipient sets.
    pub epoch: u64,
    /// Stable public workload member identifier of the committer.
    pub committer_member_index: u32,
    /// Committer ordinal in the authenticated active-quaternary mapping.
    pub committer_quaternary_leaf_ordinal: u32,
    /// Active `T_new` and eligible delivery-only `T_old`, validated against
    /// the authenticated mapping and TreeCover hashes.
    pub transition_trees: TransitionTrees,
    /// Ciphertext-free path-level recipient sets extracted from the signed
    /// UpdatePath.
    pub commit_topology: ExperimentalHybridCommitTopology,
    /// Exact topology-derived alternatives for the same authenticated
    /// recipient set. No byte cost is assigned at this stage.
    pub exact_covers: ExactRecipientCovers,
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
    /// Authenticated public topology for a post-transition Update Commit.
    pub topology_snapshot: Option<AuthenticatedAdaptiveTopologySnapshot>,
}

impl AcceptedExperimentalAdaptiveOperation {
    /// Returns public hybrid delivery counts, or zeroes for a transition
    /// Commit that intentionally has no hybrid UpdatePath delivery.
    pub fn hybrid_delivery_counts(&self) -> (u32, u32, u32, u32) {
        let metrics = self.hybrid_delivery.unwrap_or_default();
        (
            metrics.hybrid_path_delivery_count(),
            metrics.mkyber_common_ciphertext_count(),
            metrics.mkyber_recipient_ciphertext_count(),
            metrics.classical_hpke_encapsulation_count(),
        )
    }
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
    /// The authorization comparison selected for this execution.
    pub transition_policy: ExperimentalAdaptiveTransitionPolicy,
    /// Every accepted normal, transition, and quaternary Commit in order.
    pub accepted_operations: Vec<AcceptedExperimentalAdaptiveOperation>,
    /// Final converged public MLS epoch.
    pub final_epoch: u64,
    /// Final valid member count.
    pub final_member_count: u32,
    /// Explicit unsupported retirement boundary, never a fabricated erasure fact.
    pub retirement_status: ExperimentalAdaptiveRetirementStatus,
}

/// Supported real post-transition operation in the delivery-health workload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExperimentalDeliveryHealthOperation {
    /// A real accepted binary Add Commit before transition.
    Add,
    /// A real accepted quaternary self-update.
    Update,
    /// A real accepted quaternary Remove Commit.
    Remove,
}

/// One real normal-binary Commit and its matched real quaternary probe.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExperimentalPreTransitionHealthObservation {
    /// One-based accepted Commit sequence.
    pub sequence: u32,
    /// Accepted binary Add, Update, or Remove operation.
    pub operation: ExperimentalDeliveryHealthOperation,
    /// Active members after this accepted binary Commit.
    pub active_member_count: u32,
    /// Stable public workload member identifier.
    pub committer_member_index: u32,
    /// Observed full serialized binary Add, Update, or Remove Commit bytes.
    pub emitted_commit_bytes: u64,
    /// Healthy-path byte model for the current binary arity.
    pub old_arity_modeled_bytes: u64,
    /// Healthy-path byte model for the candidate quaternary arity.
    pub new_arity_modeled_bytes: u64,
    /// Real serialized quaternary Update Commit from a fresh matched probe.
    ///
    /// This is an observed counterfactual probe, not a Commit merged into the
    /// still-binary workload state.
    pub new_arity_real_probe_bytes: Option<u64>,
    /// Real serialized binary Update Commit from the same fresh matched probe
    /// used for the quaternary candidate.
    pub old_arity_real_probe_bytes: Option<u64>,
    /// Signed real-probe `new - old` byte difference against the matched
    /// fresh binary probe, not against the possibly-mutated workload row.
    pub real_probe_saving_new_minus_old_bytes: Option<i64>,
    /// Signed modeled `new - old` byte difference.
    pub saving_new_minus_old_bytes: i64,
}

/// Real accepted transition Commit plus its initial retained availability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExperimentalDeliveryHealthTransition {
    /// One-based accepted Commit sequence.
    pub sequence: u32,
    /// Stable public workload member identifier.
    pub committer_member_index: u32,
    /// Committer ordinal in the authenticated frozen mapping.
    pub committer_quaternary_leaf_ordinal: u32,
    /// Observed full serialized MLS Commit bytes.
    pub emitted_commit_bytes: u64,
    /// Retained endpoint health immediately after transition acceptance.
    pub health: DeliveryEndpointHealth,
}

/// One accepted real post-transition Commit and its converged availability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExperimentalDeliveryHealthObservation {
    /// One-based accepted Commit sequence.
    pub sequence: u32,
    /// Number of impactful Commits since transition.
    pub impactful_commit_count: u32,
    /// Accepted Add, Update, or Remove operation.
    pub operation: ExperimentalDeliveryHealthOperation,
    /// Stable public workload member identifier.
    pub committer_member_index: u32,
    /// Committer ordinal in the authenticated frozen mapping.
    pub committer_quaternary_leaf_ordinal: u32,
    /// Removed stable member identifier, only for Remove.
    pub removed_member_index: Option<u32>,
    /// Active members after acceptance.
    pub active_member_count: u32,
    /// Usable old public parent values after acceptance.
    pub usable_old_node_count: u32,
    /// Accumulated usable new public parent values after acceptance.
    pub usable_new_node_count: u32,
    /// Observed full serialized MLS Commit bytes.
    pub emitted_commit_bytes: u64,
    /// Exact endpoint counts and strict health decision.
    pub health: DeliveryEndpointHealth,
}

/// Accepted authenticated retirement and redacted erasure evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExperimentalAuthenticatedRetirement {
    /// One-based accepted retirement Commit sequence.
    pub sequence: u32,
    /// Stable public workload member identifier.
    pub committer_member_index: u32,
    /// Epoch after every survivor accepted the retirement Commit.
    pub epoch: u64,
    /// Observed full serialized retirement Commit bytes.
    pub emitted_commit_bytes: u64,
    /// Signed strict-threshold observation.
    pub evidence: ExperimentalTreeCoverRetirementEvidence,
    /// Old public-value records deleted with the persisted envelope.
    pub erased_old_node_count: u32,
    /// Locally retained old private pairs dropped and zeroized per survivor.
    pub erased_local_old_private_node_count: u32,
}

/// Complete safe public result for interactive real delivery-health reporting.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExperimentalDeliveryHealthExecution {
    /// Fixed public random seed used only for operation selection.
    pub random_seed: u64,
    /// Initial active group size.
    pub initial_member_count: u32,
    /// Final active group size.
    pub final_member_count: u32,
    /// Real normal-versus-probe observations that authorized transition.
    pub pre_transition_observations: Vec<ExperimentalPreTransitionHealthObservation>,
    /// Real authenticated transition observation.
    pub transition: ExperimentalDeliveryHealthTransition,
    /// Real accepted Update/Remove observations through the strict trigger.
    pub post_transition_observations: Vec<ExperimentalDeliveryHealthObservation>,
    /// Real authenticated atomic retirement and erasure status.
    pub retirement: ExperimentalAuthenticatedRetirement,
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
    /// A post-transition Commit did not expose its signed public recipient sets.
    #[error("an accepted post-transition Commit did not expose authenticated recipient sets")]
    MissingAuthenticatedRecipientSets,
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
    /// A real on-demand quaternary candidate probe failed.
    #[error("the adaptive candidate probe for member {member_index} failed during {stage}")]
    AdaptiveProbe {
        /// Stable public workload member identifier being measured.
        member_index: u32,
        /// Public, value-free probe stage.
        stage: &'static str,
    },
    /// A probe failure with a bounded public fork error description.
    #[error(
        "the adaptive candidate probe for member {member_index} failed during {stage}: {detail}"
    )]
    AdaptiveProbeFailure {
        /// Stable public workload member identifier being measured.
        member_index: u32,
        /// Public lifecycle stage.
        stage: &'static str,
        /// Public error category supplied by the fork.
        detail: String,
    },
    /// A measured adaptive workload operation failed at a public lifecycle stage.
    #[error(
        "adaptive {phase} operation {sequence} for member {member_index} failed during {stage}"
    )]
    AdaptiveOperation {
        /// One-based public workload sequence.
        sequence: u32,
        /// Stable public workload member identifier.
        member_index: u32,
        /// Public phase label.
        phase: &'static str,
        /// Public, value-free lifecycle stage.
        stage: &'static str,
    },
    /// A real delivery-health operation failed at a public lifecycle stage.
    #[error("delivery-health operation {sequence} failed during {stage}")]
    DeliveryHealthOperation {
        /// One-based public Commit sequence.
        sequence: u32,
        /// Public, value-free lifecycle stage.
        stage: &'static str,
    },
    /// A delivery-health operation failed with a bounded public fork error.
    #[error("delivery-health operation {sequence} failed during {stage}: {detail}")]
    DeliveryHealthOperationFailure {
        /// One-based public Commit sequence.
        sequence: u32,
        /// Public lifecycle stage.
        stage: &'static str,
        /// Public error category supplied by the fork.
        detail: String,
    },
    /// The bounded real delivery-health schedule did not reach strict retirement.
    #[error("the real delivery-health schedule reached its limit without retirement")]
    RetirementNotAuthorized,
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
        let (wire, hybrid_metrics, _) = stage_self_update(&mut members[committer_position])?;
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

/// Executes the bounded real `2 -> 4` delivery-health workload.
///
/// Two accepted normal-binary Commits are compared with matched real
/// quaternary probes. After the authenticated transition, random seeded
/// Update/Remove Commits consume the fork's ciphertext-free availability
/// snapshot. The first strict health trigger is then carried inside and
/// authenticated by a retirement Commit that atomically drops the retained
/// TreeCover key envelope.
pub fn execute_experimental_delivery_health_workload(
    config: &BaselineWorkloadConfig,
    random_seed: u64,
    maximum_post_transition_commits: u32,
) -> Result<ExperimentalDeliveryHealthExecution, ExperimentalBinaryWorkloadError> {
    validate_delivery_health_controls(config)?;
    if maximum_post_transition_commits == 0 {
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
    let extensions = adaptive_normal_arity_extensions(config, preflight)?;
    let mut members = create_initial_group_with_extensions(config, extensions)?;
    let initial_member_count =
        u32::try_from(members.len()).map_err(|_| ExperimentalBinaryWorkloadError::CountOverflow)?;
    let mut rng = ChaCha20Rng::seed_from_u64(random_seed);
    // Delivery-health authorization observes the latest matched saving after
    // the minimum five-Commit trace; the broader adaptive policy window is
    // retained for the other workload APIs.
    let mut policy_window = PolicyWindow::new(
        PolicyWindowConfig::new(1, 0, 1).map_err(|_| ExperimentalBinaryWorkloadError::Fork)?,
    );
    let mut costs = VecDeque::new();
    let mut pre_transition_observations = Vec::new();
    let mut sequence = 1_u32;
    let mut transition_selection = None;
    let mut transition_member_index = None;
    let mut transition_evaluation = None;
    let mut last_current_bytes = 0_u64;
    let mut last_candidate_bytes = 0_u64;
    let mut winning_cost = None;
    let mut real_quaternary_probe_cache = BTreeMap::<(u32, u32, u8, u32), Option<u64>>::new();
    let mut real_binary_probe_cache = BTreeMap::<(u32, u32), Option<u64>>::new();
    let mut binary_update_count = 0_u32;
    // Keep a short authenticated observation window so the public report
    // demonstrates the mixed workload before the first eligible transition.
    const MINIMUM_BINARY_OBSERVATIONS: usize = 5;
    let mut next_member_index = members
        .iter()
        .map(|member| member.member_index)
        .max()
        .and_then(|index| index.checked_add(1))
        .ok_or(ExperimentalBinaryWorkloadError::CountOverflow)?;

    for _workload_sequence in 1..=maximum_post_transition_commits {
        let position = rng.gen_range(0..members.len());
        let selection = CommitterSelection {
            sequence,
            member_index: members[position].member_index,
            leaf_index: members[position].group.own_leaf_index().u32(),
            leaf_region: members[position].leaf_region,
        };
        let operation_roll = rng.gen_range(0..3_u8);
        let below_member_limit = u32::try_from(members.len())
            .map_err(|_| ExperimentalBinaryWorkloadError::CountOverflow)?
            < config.maximum_member_count;
        let binary_add_limit = initial_member_count.saturating_add(4);
        let operation = if below_member_limit
            && next_member_index < binary_add_limit
            && (sequence == 1 || operation_roll == 0)
        {
            ExperimentalDeliveryHealthOperation::Add
        } else if operation_roll == 1 && members.len() > 3 {
            ExperimentalDeliveryHealthOperation::Remove
        } else {
            ExperimentalDeliveryHealthOperation::Update
        };
        if operation == ExperimentalDeliveryHealthOperation::Update {
            binary_update_count = binary_update_count
                .checked_add(1)
                .ok_or(ExperimentalBinaryWorkloadError::CountOverflow)?;
        }
        let epoch_before = members[position].group.epoch().as_u64();
        let committer_ordinal_before =
            u32::try_from(position).map_err(|_| ExperimentalBinaryWorkloadError::CountOverflow)?;
        let mut pending_add = None;
        let mut removed_member_index = None;
        let mut removed_ordinal = None;
        let wire = match operation {
            ExperimentalDeliveryHealthOperation::Add => {
                let pending = stage_binary_add(
                    &mut members,
                    position,
                    next_member_index,
                    config.region_count,
                )?;
                next_member_index = next_member_index
                    .checked_add(1)
                    .ok_or(ExperimentalBinaryWorkloadError::CountOverflow)?;
                pending_add = Some(pending.1);
                pending.0
            }
            ExperimentalDeliveryHealthOperation::Remove => {
                let target_position = {
                    let mut target = rng.gen_range(0..members.len() - 1);
                    if target >= position {
                        target += 1;
                    }
                    target
                };
                removed_ordinal = Some(
                    u32::try_from(target_position)
                        .map_err(|_| ExperimentalBinaryWorkloadError::CountOverflow)?,
                );
                let target_leaf = members[target_position]
                    .group
                    .members()
                    .find(|member| {
                        member.credential.serialized_content()
                            == workload_identity(members[target_position].member_index).as_slice()
                    })
                    .map(|member| member.index)
                    .ok_or(ExperimentalBinaryWorkloadError::Fork)?;
                removed_member_index = Some(members[target_position].member_index);
                let (commit, _, _) = {
                    let member = &mut members[position];
                    member
                        .group
                        .remove_members(&member.provider, &member.signer, &[target_leaf])
                        .map_err(|_| ExperimentalBinaryWorkloadError::Fork)?
                };
                commit
                    .tls_serialize_detached()
                    .map_err(|_| ExperimentalBinaryWorkloadError::Fork)?
            }
            ExperimentalDeliveryHealthOperation::Update => {
                stage_self_update(&mut members[position])?.0
            }
        };
        deliver_to_receivers(&mut members, position, &wire).map_err(|_| {
            ExperimentalBinaryWorkloadError::DeliveryHealthOperation {
                sequence,
                stage: "binary-receiver-application",
            }
        })?;
        merge_sender_binary(&mut members[position]).map_err(|_| {
            ExperimentalBinaryWorkloadError::DeliveryHealthOperation {
                sequence,
                stage: "binary-sender-application",
            }
        })?;
        if let Some(pending) = pending_add {
            members.push(complete_binary_add(pending).map_err(|_| {
                ExperimentalBinaryWorkloadError::DeliveryHealthOperation {
                    sequence,
                    stage: "binary-add-welcome",
                }
            })?);
            members.sort_unstable_by_key(|member| member.member_index);
        }
        if let Some(removed_member_index) = removed_member_index {
            members.retain(|member| member.member_index != removed_member_index);
        }
        let epoch_after = converged_epoch(&members)?;
        ensure_epoch_advance(epoch_before, epoch_after)?;
        let emitted_commit_bytes = u64::try_from(wire.len())
            .map_err(|_| ExperimentalBinaryWorkloadError::CountOverflow)?;
        let active_member_count = u32::try_from(members.len())
            .map_err(|_| ExperimentalBinaryWorkloadError::CountOverflow)?;
        let pre_probe_member_count = match operation {
            ExperimentalDeliveryHealthOperation::Add => active_member_count
                .checked_sub(1)
                .ok_or(ExperimentalBinaryWorkloadError::CountOverflow)?,
            ExperimentalDeliveryHealthOperation::Remove => active_member_count
                .checked_add(1)
                .ok_or(ExperimentalBinaryWorkloadError::CountOverflow)?,
            ExperimentalDeliveryHealthOperation::Update => active_member_count,
        };
        let operation_tag = match operation {
            ExperimentalDeliveryHealthOperation::Add => 0,
            ExperimentalDeliveryHealthOperation::Update => 1,
            ExperimentalDeliveryHealthOperation::Remove => 2,
        };
        let probe_key = (
            pre_probe_member_count,
            committer_ordinal_before,
            operation_tag,
            removed_ordinal.unwrap_or(u32::MAX),
        );
        let real_candidate_bytes = if let Some(bytes) = real_quaternary_probe_cache.get(&probe_key)
        {
            *bytes
        } else {
            let bytes = measure_real_quaternary_probe_bytes(
                config,
                pre_probe_member_count,
                committer_ordinal_before,
                operation,
                removed_ordinal,
            )?;
            real_quaternary_probe_cache.insert(probe_key, bytes);
            bytes
        };
        let matched_binary_probe_bytes =
            if matches!(operation, ExperimentalDeliveryHealthOperation::Update) {
                let binary_probe_key = (pre_probe_member_count, committer_ordinal_before);
                if let Some(bytes) = real_binary_probe_cache.get(&binary_probe_key) {
                    *bytes
                } else {
                    let bytes = Some(measure_real_binary_probe_bytes(
                        config,
                        pre_probe_member_count,
                        committer_ordinal_before,
                    )?);
                    real_binary_probe_cache.insert(binary_probe_key, bytes);
                    bytes
                }
            } else {
                Some(measure_real_binary_probe_operation_bytes(
                    config,
                    pre_probe_member_count,
                    committer_ordinal_before,
                    operation,
                    removed_ordinal,
                )?)
            };
        let real_probe_saving = real_candidate_bytes
            .zip(matched_binary_probe_bytes)
            .map(|(candidate, matched_binary)| {
                i64::try_from(candidate)
                    .map_err(|_| ExperimentalBinaryWorkloadError::CountOverflow)?
                    .checked_sub(
                        i64::try_from(matched_binary)
                            .map_err(|_| ExperimentalBinaryWorkloadError::CountOverflow)?,
                    )
                    .ok_or(ExperimentalBinaryWorkloadError::CountOverflow)
            })
            .transpose()?;
        let current_bytes = healthy_path_model_bytes(2, active_member_count)?;
        let candidate_bytes = healthy_path_model_bytes(4, active_member_count)?;
        let saving = i64::try_from(candidate_bytes)
            .map_err(|_| ExperimentalBinaryWorkloadError::CountOverflow)?
            .checked_sub(
                i64::try_from(current_bytes)
                    .map_err(|_| ExperimentalBinaryWorkloadError::CountOverflow)?,
            )
            .ok_or(ExperimentalBinaryWorkloadError::CountOverflow)?;
        let append = policy_window
            .append_accepted(
                epoch_after,
                CommitImpactFacts {
                    path_delivery_changed: true,
                    recipient_resolution_changed: true,
                    ..CommitImpactFacts::default()
                },
            )
            .map_err(|_| ExperimentalBinaryWorkloadError::Fork)?;
        costs.push_back(ImpactfulCommitByteCosts::new(
            current_bytes,
            candidate_bytes,
        ));
        if saving < 0 {
            winning_cost = Some(ImpactfulCommitByteCosts::new(
                current_bytes,
                candidate_bytes,
            ));
        }
        if append.evicted_epoch_after.is_some() {
            costs.pop_front();
        }
        pre_transition_observations.push(ExperimentalPreTransitionHealthObservation {
            sequence,
            operation,
            active_member_count,
            committer_member_index: selection.member_index,
            emitted_commit_bytes,
            old_arity_modeled_bytes: current_bytes,
            new_arity_modeled_bytes: candidate_bytes,
            new_arity_real_probe_bytes: real_candidate_bytes,
            old_arity_real_probe_bytes: matched_binary_probe_bytes,
            saving_new_minus_old_bytes: saving,
            real_probe_saving_new_minus_old_bytes: real_probe_saving,
        });
        last_current_bytes = current_bytes;
        last_candidate_bytes = candidate_bytes;
        sequence = sequence
            .checked_add(1)
            .ok_or(ExperimentalBinaryWorkloadError::CountOverflow)?;
        let normal = arity_state_from_group(&members[0].group)?;
        let _savings = PreflightSavings::from_impactful_costs(
            costs.make_contiguous(),
            normal.policy().transition_preflight_bytes(),
        )
        .map_err(|_| ExperimentalBinaryWorkloadError::Fork)?;
        let authorization_savings = if pre_transition_observations.len()
            >= MINIMUM_BINARY_OBSERVATIONS
        {
            winning_cost
                .map(|cost| PreflightSavings::from_impactful_costs(std::slice::from_ref(&cost), 0))
                .transpose()
                .map_err(|_| ExperimentalBinaryWorkloadError::Fork)?
        } else {
            Some(
                PreflightSavings::from_impactful_costs(costs.make_contiguous(), 0)
                    .map_err(|_| ExperimentalBinaryWorkloadError::Fork)?,
            )
        };
        let evaluation = TransitionStartEvaluator::new(adaptive_start_config(&normal)?)
            .evaluate_post_warmup(
                &append.record,
                PolicyTransitionState::Normal,
                initial_member_count,
                &policy_window,
                authorization_savings,
            )
            .map_err(|_| ExperimentalBinaryWorkloadError::Fork)?;
        if pre_transition_observations.len() >= MINIMUM_BINARY_OBSERVATIONS
            && binary_update_count > 0
            && evaluation.is_triggered()
        {
            transition_member_index = Some(selection.member_index);
            transition_selection = Some(selection);
            transition_evaluation = Some(evaluation);
            break;
        }
    }
    let normal = arity_state_from_group(&members[0].group)?;
    let _savings = PreflightSavings::from_impactful_costs(
        costs.make_contiguous(),
        normal.policy().transition_preflight_bytes(),
    )
    .map_err(|_| ExperimentalBinaryWorkloadError::Fork)?;
    let evaluation =
        transition_evaluation.ok_or(ExperimentalBinaryWorkloadError::TransitionNotAuthorized {
            current_binary_update_bytes: last_current_bytes,
            quaternary_candidate_bytes: last_candidate_bytes,
            transition_preflight_bytes: u64::try_from(preflight.estimated_bytes())
                .map_err(|_| ExperimentalBinaryWorkloadError::CountOverflow)?,
        })?;
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
    let transition_member_index =
        transition_member_index.ok_or(ExperimentalBinaryWorkloadError::Fork)?;
    let transition_position = member_position(&members, transition_member_index)?;
    let transition_selection = transition_selection.ok_or(ExperimentalBinaryWorkloadError::Fork)?;
    let transition_epoch_before = members[transition_position].group.epoch().as_u64();
    let (transition_commit, _, _) = {
        let member = &mut members[transition_position];
        member
            .group
            .begin_experimental_transition(&member.provider, &member.signer, next_state)
            .map_err(|_| ExperimentalBinaryWorkloadError::Fork)?
    };
    let transition_wire = transition_commit
        .tls_serialize_detached()
        .map_err(|_| ExperimentalBinaryWorkloadError::Fork)?;
    deliver_transition_to_receivers(&mut members, transition_position, &transition_wire)?;
    merge_sender_transition(&mut members[transition_position])?;
    let transition_epoch_after = converged_epoch(&members)?;
    ensure_epoch_advance(transition_epoch_before, transition_epoch_after)?;
    let transition_state = arity_state_from_group(&members[0].group)?;
    let transition_health = health_for_member(&members[0].group, transition_selection.leaf_index)?;
    let transition_ordinal = transition_health.0;
    let transition_health = transition_health.1;
    let transition = ExperimentalDeliveryHealthTransition {
        sequence,
        committer_member_index: transition_selection.member_index,
        committer_quaternary_leaf_ordinal: transition_ordinal,
        emitted_commit_bytes: u64::try_from(transition_wire.len())
            .map_err(|_| ExperimentalBinaryWorkloadError::CountOverflow)?,
        health: transition_health,
    };
    sequence = sequence
        .checked_add(1)
        .ok_or(ExperimentalBinaryWorkloadError::CountOverflow)?;

    let mut post_transition_observations = Vec::new();
    let mut retirement = None;
    for impactful_commit_count in 1..=maximum_post_transition_commits {
        if members.len() < 2 {
            return Err(ExperimentalBinaryWorkloadError::InvalidControls);
        }
        let committer_position = rng.gen_range(0..members.len());
        let committer_member_index = members[committer_position].member_index;
        let committer_leaf_index = members[committer_position].group.own_leaf_index().u32();
        let remove = members.len() > 2 && rng.gen_bool(0.5);
        let mut removed_member_index = None;
        let wire = if remove {
            let mut target_position = rng.gen_range(0..members.len() - 1);
            if target_position >= committer_position {
                target_position += 1;
            }
            let target_leaf = members[target_position]
                .group
                .members()
                .find(|member| {
                    member.credential.serialized_content()
                        == workload_identity(members[target_position].member_index).as_slice()
                })
                .map(|member| member.index)
                .ok_or(ExperimentalBinaryWorkloadError::Fork)?;
            removed_member_index = Some(members[target_position].member_index);
            let (commit, _, _) = {
                let member = &mut members[committer_position];
                member
                    .group
                    .remove_members(&member.provider, &member.signer, &[target_leaf])
                    .map_err(|_| ExperimentalBinaryWorkloadError::Fork)?
            };
            commit
                .tls_serialize_detached()
                .map_err(|_| ExperimentalBinaryWorkloadError::Fork)?
        } else {
            stage_self_update(&mut members[committer_position])
                .map_err(
                    |error| ExperimentalBinaryWorkloadError::DeliveryHealthOperationFailure {
                        sequence,
                        stage: "post-transition-stage",
                        detail: error.to_string(),
                    },
                )?
                .0
        };
        deliver_quaternary_to_receivers(&mut members, committer_position, &wire).map_err(
            |error| ExperimentalBinaryWorkloadError::DeliveryHealthOperationFailure {
                sequence,
                stage: "post-transition-receiver-application",
                detail: error.to_string(),
            },
        )?;
        merge_sender_quaternary(&mut members[committer_position]).map_err(|error| {
            ExperimentalBinaryWorkloadError::DeliveryHealthOperationFailure {
                sequence,
                stage: "post-transition-sender-application",
                detail: error.to_string(),
            }
        })?;
        if let Some(removed_member_index) = removed_member_index {
            members.retain(|member| member.member_index != removed_member_index);
        }
        let epoch = converged_epoch(&members)?;
        let health = health_for_member(&members[0].group, committer_leaf_index)?;
        let snapshot = members[0]
            .group
            .experimental_transition_node_availability_snapshot()
            .ok_or(ExperimentalBinaryWorkloadError::Fork)?;
        let operation = if removed_member_index.is_some() {
            ExperimentalDeliveryHealthOperation::Remove
        } else {
            ExperimentalDeliveryHealthOperation::Update
        };
        let emitted_commit_bytes = u64::try_from(wire.len())
            .map_err(|_| ExperimentalBinaryWorkloadError::CountOverflow)?;
        let observation = ExperimentalDeliveryHealthObservation {
            sequence,
            impactful_commit_count,
            operation,
            committer_member_index,
            committer_quaternary_leaf_ordinal: health.0,
            removed_member_index,
            active_member_count: u32::try_from(members.len())
                .map_err(|_| ExperimentalBinaryWorkloadError::CountOverflow)?,
            usable_old_node_count: u32::try_from(snapshot.usable_old_parent_indices().len())
                .map_err(|_| ExperimentalBinaryWorkloadError::CountOverflow)?,
            usable_new_node_count: u32::try_from(snapshot.usable_new_parent_nodes().len())
                .map_err(|_| ExperimentalBinaryWorkloadError::CountOverflow)?,
            emitted_commit_bytes,
            health: health.1,
        };
        post_transition_observations.push(observation);
        sequence = sequence
            .checked_add(1)
            .ok_or(ExperimentalBinaryWorkloadError::CountOverflow)?;
        if impactful_commit_count >= 5 && (health.1.retire_new || health.1.retire_old) {
            let prior_state = arity_state_from_group(&members[0].group)?;
            let ArityLifecycle::Transitioning(transitioning) = prior_state.lifecycle() else {
                return Err(ExperimentalBinaryWorkloadError::DeliveryHealthOperation {
                    sequence,
                    stage: "retirement-prior-state",
                });
            };
            let next_tree_version = prior_state
                .tree_version()
                .checked_add(1)
                .ok_or(ExperimentalBinaryWorkloadError::CountOverflow)?;
            let next_state = ArityState::normal(
                4,
                4,
                next_tree_version,
                prior_state.policy(),
                prior_state.evaluation(),
            )
            .map_err(|_| ExperimentalBinaryWorkloadError::Fork)?;
            let evidence = ExperimentalTreeCoverRetirementEvidence::new(
                prior_state.tree_version(),
                transitioning.transition_epoch(),
                epoch,
                impactful_commit_count,
                health.1.c_leaf,
                health.1.c_new,
                health.1.c_old,
                health.1.c_real,
                health.1.c_ideal,
                health.1.h_new.numerator(),
                health.1.h_new.denominator(),
                health.1.h_old.numerator(),
                health.1.h_old.denominator(),
            )
            .map_err(
                |_| ExperimentalBinaryWorkloadError::DeliveryHealthOperation {
                    sequence,
                    stage: "retirement-evidence",
                },
            )?;
            let retire_position = members
                .iter()
                .position(|member| member.member_index == committer_member_index)
                .ok_or(ExperimentalBinaryWorkloadError::Fork)?;
            let (retirement_commit, _, _) = {
                let member = &mut members[retire_position];
                member
                    .group
                    .retire_experimental_treecover(
                        &member.provider,
                        &member.signer,
                        next_state,
                        evidence,
                    )
                    .map_err(|error| {
                        ExperimentalBinaryWorkloadError::DeliveryHealthOperationFailure {
                            sequence,
                            stage: "retirement-commit-creation",
                            detail: error.to_string(),
                        }
                    })?
            };
            let retirement_wire = retirement_commit.tls_serialize_detached().map_err(|_| {
                ExperimentalBinaryWorkloadError::DeliveryHealthOperation {
                    sequence,
                    stage: "retirement-serialization",
                }
            })?;
            let retirement_sender_leaf = members[retire_position].group.own_leaf_index().u32();
            deliver_retirement_to_receivers(
                &mut members,
                retire_position,
                retirement_sender_leaf,
                &retirement_wire,
            )
            .map_err(|detail| {
                ExperimentalBinaryWorkloadError::DeliveryHealthOperationFailure {
                    sequence,
                    stage: "retirement-receiver-application",
                    detail,
                }
            })?;
            merge_sender_retirement(&mut members[retire_position]).map_err(|_| {
                ExperimentalBinaryWorkloadError::DeliveryHealthOperation {
                    sequence,
                    stage: "retirement-sender-application",
                }
            })?;
            let retirement_epoch = converged_epoch(&members).map_err(|_| {
                ExperimentalBinaryWorkloadError::DeliveryHealthOperation {
                    sequence,
                    stage: "retirement-convergence",
                }
            })?;
            let status = members[0]
                .group
                .experimental_treecover_retirement_status()
                .ok_or(ExperimentalBinaryWorkloadError::DeliveryHealthOperation {
                    sequence,
                    stage: "retirement-status",
                })?;
            let public_retirement_status = (status.evidence(), status.erased_old_node_count());
            if members.iter().any(|member| {
                member
                    .group
                    .experimental_transition_node_availability_snapshot()
                    .is_some()
                    || member.group.experimental_treecover_retirement_status().map(
                        |member_status| {
                            (
                                member_status.evidence(),
                                member_status.erased_old_node_count(),
                            )
                        },
                    ) != Some(public_retirement_status)
            }) {
                return Err(ExperimentalBinaryWorkloadError::DivergentPublicState);
            }
            retirement = Some(ExperimentalAuthenticatedRetirement {
                sequence,
                committer_member_index,
                epoch: retirement_epoch,
                emitted_commit_bytes: u64::try_from(retirement_wire.len())
                    .map_err(|_| ExperimentalBinaryWorkloadError::CountOverflow)?,
                evidence: status.evidence(),
                erased_old_node_count: status.erased_old_node_count(),
                erased_local_old_private_node_count: status.erased_local_old_private_node_count(),
            });
            break;
        }
    }
    let retirement = retirement.ok_or(ExperimentalBinaryWorkloadError::RetirementNotAuthorized)?;
    let _ = transition_state;
    Ok(ExperimentalDeliveryHealthExecution {
        random_seed,
        initial_member_count,
        final_member_count: u32::try_from(members.len())
            .map_err(|_| ExperimentalBinaryWorkloadError::CountOverflow)?,
        pre_transition_observations,
        transition,
        post_transition_observations,
        retirement,
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
/// measured group. Retirement is handled by the dedicated authenticated
/// TreeCover retirement Commit path.
pub fn execute_experimental_adaptive_workload(
    config: &BaselineWorkloadConfig,
) -> Result<ExperimentalAdaptiveWorkloadExecution, ExperimentalBinaryWorkloadError> {
    execute_experimental_adaptive_workload_with_policy(
        config,
        ExperimentalAdaptiveTransitionPolicy::AmortizeTransitionPreflight,
    )
}

/// Executes a real adaptive workload using an explicit transition
/// authorization comparison.
///
/// `MatchedPerCommitSaving` intentionally excludes transition-preflight bytes
/// only from the authorization decision. The returned transition measurement
/// always retains the full amortized preflight calculation for reporting and
/// comparison with `AmortizeTransitionPreflight`.
pub fn execute_experimental_adaptive_workload_with_policy(
    config: &BaselineWorkloadConfig,
    transition_policy: ExperimentalAdaptiveTransitionPolicy,
) -> Result<ExperimentalAdaptiveWorkloadExecution, ExperimentalBinaryWorkloadError> {
    execute_experimental_adaptive_workload_with_completion(config, transition_policy, false)
}

/// Executes a bounded real adaptive workload and stops immediately after the
/// first accepted post-transition quaternary update.
///
/// `config.operation_count` remains the maximum number of scheduled workload
/// updates available to authorize the transition and produce that maturity
/// observation. The result contains every Commit accepted before this
/// completion condition; no later scheduled update is executed or hidden.
pub fn execute_experimental_adaptive_workload_until_first_post_transition(
    config: &BaselineWorkloadConfig,
    transition_policy: ExperimentalAdaptiveTransitionPolicy,
) -> Result<ExperimentalAdaptiveWorkloadExecution, ExperimentalBinaryWorkloadError> {
    execute_experimental_adaptive_workload_with_completion(config, transition_policy, true)
}

fn execute_experimental_adaptive_workload_with_completion(
    config: &BaselineWorkloadConfig,
    transition_policy: ExperimentalAdaptiveTransitionPolicy,
    stop_after_first_quaternary_update: bool,
) -> Result<ExperimentalAdaptiveWorkloadExecution, ExperimentalBinaryWorkloadError> {
    validate_controls(config)?;
    if config.operation_count < 2 {
        return Err(ExperimentalBinaryWorkloadError::InvalidControls);
    }

    let mut probe = measure_adaptive_probe(config)?;
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
    let (normal_wire, normal_hybrid_metrics, _) = stage_self_update(&mut members[normal_position])?;
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
        topology_snapshot: None,
    });
    sequence = sequence
        .checked_add(1)
        .ok_or(ExperimentalBinaryWorkloadError::CountOverflow)?;

    let normal_candidate_bytes =
        probe.quaternary_update_bytes(config, normal_selection.member_index)?;
    let mut last_candidate_bytes = normal_candidate_bytes;
    let mut costs = VecDeque::from([ImpactfulCommitByteCosts::new(
        u64::try_from(normal_wire.len())
            .map_err(|_| ExperimentalBinaryWorkloadError::CountOverflow)?,
        normal_candidate_bytes,
    )]);
    let mut last_current_bytes = costs
        .front()
        .ok_or(ExperimentalBinaryWorkloadError::Fork)?
        .current_bytes();
    let mut transition_selection = None;
    let mut transition_position = None;
    let mut transition_workload_sequence = None;
    let mut transition_record = policy_record;
    let mut transition_savings = None;
    let mut transition_evaluation = None;
    for workload_sequence in 2..=config.operation_count {
        let selection = select_committer(&members, config, workload_sequence)?;
        let candidate_bytes = probe.quaternary_update_bytes(config, selection.member_index)?;
        let operation_error = |stage| ExperimentalBinaryWorkloadError::AdaptiveOperation {
            sequence: workload_sequence,
            member_index: selection.member_index,
            phase: "normal-binary",
            stage,
        };
        let position = member_position(&members, selection.member_index)
            .map_err(|_| operation_error("committer-position"))?;
        let epoch_before = members[position].group.epoch().as_u64();
        let started = Instant::now();
        let (wire, hybrid_metrics, _) = stage_self_update(&mut members[position])
            .map_err(|_| operation_error("sender-stage"))?;
        let deliveries = deliver_to_receivers(&mut members, position, &wire)
            .map_err(|_| operation_error("receiver-application"))?;
        merge_sender_binary(&mut members[position])
            .map_err(|_| operation_error("sender-application"))?;
        let epoch_after = converged_epoch(&members).map_err(|_| operation_error("convergence"))?;
        ensure_epoch_advance(epoch_before, epoch_after)
            .map_err(|_| operation_error("epoch-advance"))?;
        last_current_bytes = u64::try_from(wire.len())
            .map_err(|_| ExperimentalBinaryWorkloadError::CountOverflow)?;
        last_candidate_bytes = candidate_bytes;
        costs.push_back(ImpactfulCommitByteCosts::new(
            last_current_bytes,
            candidate_bytes,
        ));
        let append_outcome = policy_window
            .append_accepted(
                epoch_after,
                CommitImpactFacts {
                    path_delivery_changed: true,
                    recipient_resolution_changed: true,
                    ..CommitImpactFacts::default()
                },
            )
            .map_err(|_| operation_error("policy-window"))?;
        if append_outcome.evicted_epoch_after.is_some() {
            costs
                .pop_front()
                .ok_or_else(|| operation_error("cost-window-eviction"))?;
        }
        if u32::try_from(costs.len()).ok() != Some(policy_window.q_e()) {
            return Err(operation_error("cost-window-synchronization"));
        }
        let record = append_outcome.record;
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
            arity_state: arity_state_from_group(&members[0].group)
                .map_err(|_| operation_error("arity-state-observation"))?,
            policy_record: Some(record.clone()),
            transition: None,
            topology_snapshot: None,
        });
        sequence = sequence
            .checked_add(1)
            .ok_or(ExperimentalBinaryWorkloadError::CountOverflow)?;
        let normal = arity_state_from_group(&members[0].group)
            .map_err(|_| operation_error("arity-state-policy-input"))?;
        let savings = PreflightSavings::from_impactful_costs(
            costs.make_contiguous(),
            normal.policy().transition_preflight_bytes(),
        )
        .map_err(|_| operation_error("savings"))?;
        let authorization_savings = match transition_policy {
            ExperimentalAdaptiveTransitionPolicy::AmortizeTransitionPreflight => savings,
            ExperimentalAdaptiveTransitionPolicy::MatchedPerCommitSaving => {
                PreflightSavings::from_impactful_costs(costs.make_contiguous(), 0)
                    .map_err(|_| operation_error("matched-savings"))?
            }
        };
        let start_config =
            adaptive_start_config(&normal).map_err(|_| operation_error("start-config"))?;
        let evaluation = TransitionStartEvaluator::new(start_config)
            .evaluate_post_warmup(
                &record,
                PolicyTransitionState::Normal,
                member_count,
                &policy_window,
                Some(authorization_savings),
            )
            .map_err(|_| operation_error("start-evaluation"))?;
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
        topology_snapshot: None,
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
        let (wire, hybrid_metrics, commit_topology) =
            stage_self_update(&mut members[committer_position])?;
        let direct_commit_delivery_count =
            deliver_quaternary_to_receivers(&mut members, committer_position, &wire)?;
        merge_sender_quaternary(&mut members[committer_position])?;
        let epoch_after = converged_epoch(&members)?;
        ensure_epoch_advance(epoch_before, epoch_after)?;
        let topology_snapshot = authenticated_topology_snapshot(
            &members,
            selection.member_index,
            selection.leaf_index,
            epoch_after,
            commit_topology,
        )?;
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
            topology_snapshot: Some(topology_snapshot),
        });
        sequence = sequence
            .checked_add(1)
            .ok_or(ExperimentalBinaryWorkloadError::CountOverflow)?;
        if stop_after_first_quaternary_update {
            break;
        }
    }

    Ok(ExperimentalAdaptiveWorkloadExecution {
        transition_policy,
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

impl AdaptiveProbe {
    fn quaternary_update_bytes(
        &mut self,
        config: &BaselineWorkloadConfig,
        candidate_member_index: u32,
    ) -> Result<u64, ExperimentalBinaryWorkloadError> {
        if let Some(bytes) = self
            .quaternary_update_bytes_by_member
            .get(&candidate_member_index)
        {
            return Ok(*bytes);
        }
        let (candidate_transition_wire, candidate_update_wire) =
            measure_adaptive_probe_candidate(config, candidate_member_index)?;
        if candidate_transition_wire.len() != self.transition_wire.len() {
            return Err(ExperimentalBinaryWorkloadError::AdaptiveProbe {
                member_index: candidate_member_index,
                stage: "transition-size-consistency",
            });
        }
        let candidate_bytes = u64::try_from(candidate_update_wire.len())
            .map_err(|_| ExperimentalBinaryWorkloadError::CountOverflow)?;
        self.quaternary_update_bytes_by_member
            .insert(candidate_member_index, candidate_bytes);
        Ok(candidate_bytes)
    }
}

fn measure_adaptive_probe(
    config: &BaselineWorkloadConfig,
) -> Result<AdaptiveProbe, ExperimentalBinaryWorkloadError> {
    // Establish preflight and the first matched candidate only. Later
    // committer/path candidates are measured on demand so a configured upper
    // bound does not execute unused future probes.
    let candidate_member_index = adaptive_probe_member_index(config, 1)?;
    let (transition_wire, candidate_update_wire) =
        measure_adaptive_probe_candidate(config, candidate_member_index)?;
    let mut quaternary_update_bytes_by_member = BTreeMap::new();
    quaternary_update_bytes_by_member.insert(
        candidate_member_index,
        u64::try_from(candidate_update_wire.len())
            .map_err(|_| ExperimentalBinaryWorkloadError::CountOverflow)?,
    );
    Ok(AdaptiveProbe {
        transition_wire,
        quaternary_update_bytes_by_member,
    })
}

fn measure_real_binary_probe_bytes(
    config: &BaselineWorkloadConfig,
    initial_member_count: u32,
    committer_ordinal: u32,
) -> Result<u64, ExperimentalBinaryWorkloadError> {
    measure_real_binary_probe_operation_bytes(
        config,
        initial_member_count,
        committer_ordinal,
        ExperimentalDeliveryHealthOperation::Update,
        None,
    )
}

fn measure_real_binary_probe_operation_bytes(
    config: &BaselineWorkloadConfig,
    initial_member_count: u32,
    committer_ordinal: u32,
    operation: ExperimentalDeliveryHealthOperation,
    removed_ordinal: Option<u32>,
) -> Result<u64, ExperimentalBinaryWorkloadError> {
    if initial_member_count < 2 || committer_ordinal >= initial_member_count {
        return Err(ExperimentalBinaryWorkloadError::InvalidControls);
    }
    let mut probe_config = config.clone();
    probe_config.initial_member_count = initial_member_count;
    probe_config.maximum_member_count = initial_member_count.saturating_add(1);
    probe_config.operation_count = 1;
    let extensions = adaptive_probe_arity_extensions(&probe_config)?;
    let mut members = create_initial_group_with_extensions(&probe_config, extensions)?;
    warm_binary_probe_tree(&mut members)?;
    let position = usize::try_from(committer_ordinal)
        .map_err(|_| ExperimentalBinaryWorkloadError::CountOverflow)?;
    let wire = match operation {
        ExperimentalDeliveryHealthOperation::Add => {
            stage_binary_add(
                &mut members,
                position,
                initial_member_count,
                config.region_count,
            )?
            .0
        }
        ExperimentalDeliveryHealthOperation::Update => stage_self_update(&mut members[position])?.0,
        ExperimentalDeliveryHealthOperation::Remove => {
            let mut target_position = usize::try_from(
                removed_ordinal.ok_or(ExperimentalBinaryWorkloadError::InvalidControls)?,
            )
            .map_err(|_| ExperimentalBinaryWorkloadError::CountOverflow)?;
            if target_position >= members.len() || target_position == position {
                target_position = if position != 0 { 0 } else { 1 };
            }
            let target_leaf = members[target_position]
                .group
                .members()
                .find(|member| {
                    member.credential.serialized_content()
                        == workload_identity(members[target_position].member_index).as_slice()
                })
                .map(|member| member.index)
                .ok_or(ExperimentalBinaryWorkloadError::Fork)?;
            let (commit, _, _) = {
                let member = &mut members[position];
                member
                    .group
                    .remove_members(&member.provider, &member.signer, &[target_leaf])
                    .map_err(|_| ExperimentalBinaryWorkloadError::Fork)?
            };
            commit
                .tls_serialize_detached()
                .map_err(|_| ExperimentalBinaryWorkloadError::Fork)?
        }
    };
    u64::try_from(wire.len()).map_err(|_| ExperimentalBinaryWorkloadError::CountOverflow)
}

/// Populates every occupied binary parent by accepting one Update from the
/// first leaf of each bottom-level sibling pair. Setup bytes are not measured.
fn warm_binary_probe_tree(
    members: &mut [ExperimentalWorkloadMember],
) -> Result<(), ExperimentalBinaryWorkloadError> {
    for committer_position in (0..members.len()).step_by(2) {
        let wire = stage_self_update(&mut members[committer_position])?.0;
        deliver_to_receivers(members, committer_position, &wire)?;
        merge_sender_binary(&mut members[committer_position])?;
        converged_epoch(members)?;
    }
    Ok(())
}

fn measure_real_quaternary_probe_bytes(
    config: &BaselineWorkloadConfig,
    initial_member_count: u32,
    committer_ordinal: u32,
    operation: ExperimentalDeliveryHealthOperation,
    removed_ordinal: Option<u32>,
) -> Result<Option<u64>, ExperimentalBinaryWorkloadError> {
    if !matches!(operation, ExperimentalDeliveryHealthOperation::Update) {
        return Ok(None);
    }
    if initial_member_count < 2 || committer_ordinal >= initial_member_count {
        return Err(ExperimentalBinaryWorkloadError::InvalidControls);
    }
    let mut probe_config = config.clone();
    probe_config.initial_member_count = initial_member_count;
    probe_config.maximum_member_count = initial_member_count.saturating_add(1);
    probe_config.operation_count = 1;
    let (_, candidate_wire) = measure_real_quaternary_probe_candidate(
        &probe_config,
        committer_ordinal,
        operation,
        removed_ordinal,
        true,
    )?;
    u64::try_from(candidate_wire.len())
        .map(Some)
        .map_err(|_| ExperimentalBinaryWorkloadError::CountOverflow)
}

fn adaptive_probe_member_index(
    config: &BaselineWorkloadConfig,
    sequence: u32,
) -> Result<u32, ExperimentalBinaryWorkloadError> {
    let eligible = (0..config.initial_member_count)
        .map(|member_index| EligibleCommitter {
            member_index,
            leaf_index: member_index,
            leaf_region: member_index % config.region_count,
        })
        .collect::<Vec<_>>();
    build_committer_schedule(&eligible, config.committer_strategy.clone(), sequence)
        .map_err(|_| ExperimentalBinaryWorkloadError::InvalidControls)?
        .selections
        .last()
        .map(|selection| selection.member_index)
        .ok_or(ExperimentalBinaryWorkloadError::InvalidControls)
}

fn measure_adaptive_probe_candidate(
    config: &BaselineWorkloadConfig,
    candidate_member_index: u32,
) -> Result<(Vec<u8>, Vec<u8>), ExperimentalBinaryWorkloadError> {
    measure_real_quaternary_probe_candidate(
        config,
        candidate_member_index,
        ExperimentalDeliveryHealthOperation::Update,
        None,
        false,
    )
}

fn measure_real_quaternary_probe_candidate(
    config: &BaselineWorkloadConfig,
    candidate_member_index: u32,
    operation: ExperimentalDeliveryHealthOperation,
    removed_ordinal: Option<u32>,
    require_healthy_tree: bool,
) -> Result<(Vec<u8>, Vec<u8>), ExperimentalBinaryWorkloadError> {
    let extensions = adaptive_probe_arity_extensions(config).map_err(|_| {
        ExperimentalBinaryWorkloadError::AdaptiveProbe {
            member_index: candidate_member_index,
            stage: "arity-state",
        }
    })?;
    let mut members = create_initial_group_with_extensions(config, extensions).map_err(|_| {
        ExperimentalBinaryWorkloadError::AdaptiveProbe {
            member_index: candidate_member_index,
            stage: "initial-group",
        }
    })?;
    let selection = select_committer(&members, config, 1).map_err(|_| {
        ExperimentalBinaryWorkloadError::AdaptiveProbe {
            member_index: candidate_member_index,
            stage: "transition-committer",
        }
    })?;
    let position = member_position(&members, selection.member_index).map_err(|_| {
        ExperimentalBinaryWorkloadError::AdaptiveProbe {
            member_index: candidate_member_index,
            stage: "transition-committer-position",
        }
    })?;
    let next_state = probe_transition_state(&members[0].group).map_err(|_| {
        ExperimentalBinaryWorkloadError::AdaptiveProbe {
            member_index: candidate_member_index,
            stage: "transition-state",
        }
    })?;
    let (transition_commit, _, _) = {
        let ExperimentalWorkloadMember {
            provider,
            signer,
            group,
            ..
        } = &mut members[position];
        group
            .begin_experimental_transition(provider, signer, next_state)
            .map_err(
                |error| ExperimentalBinaryWorkloadError::AdaptiveProbeFailure {
                    member_index: candidate_member_index,
                    stage: "transition-stage",
                    detail: error.to_string(),
                },
            )?
    };
    let transition_wire = transition_commit.tls_serialize_detached().map_err(|_| {
        ExperimentalBinaryWorkloadError::AdaptiveProbe {
            member_index: candidate_member_index,
            stage: "transition-serialization",
        }
    })?;
    let _ = deliver_transition_to_receivers(&mut members, position, &transition_wire).map_err(
        |error| ExperimentalBinaryWorkloadError::AdaptiveProbeFailure {
            member_index: candidate_member_index,
            stage: "transition-receiver-application",
            detail: error.to_string(),
        },
    )?;
    merge_sender_transition(&mut members[position]).map_err(|_| {
        ExperimentalBinaryWorkloadError::AdaptiveProbe {
            member_index: candidate_member_index,
            stage: "transition-sender-application",
        }
    })?;
    let _ =
        converged_epoch(&members).map_err(|_| ExperimentalBinaryWorkloadError::AdaptiveProbe {
            member_index: candidate_member_index,
            stage: "transition-convergence",
        })?;
    if require_healthy_tree {
        warm_quaternary_probe_tree(&mut members, position).map_err(|_| {
            ExperimentalBinaryWorkloadError::AdaptiveProbe {
                member_index: candidate_member_index,
                stage: "quaternary-health-warmup",
            }
        })?;
    }
    let update_position = member_position(&members, candidate_member_index).map_err(|_| {
        ExperimentalBinaryWorkloadError::AdaptiveProbe {
            member_index: candidate_member_index,
            stage: "candidate-committer-position",
        }
    })?;
    let operation_wire = match operation {
        ExperimentalDeliveryHealthOperation::Add => {
            let new_member_index = config.initial_member_count;
            stage_binary_add(
                &mut members,
                update_position,
                new_member_index,
                config.region_count,
            )
            .map_err(|_| ExperimentalBinaryWorkloadError::AdaptiveProbe {
                member_index: candidate_member_index,
                stage: "quaternary-add-stage",
            })?
            .0
        }
        ExperimentalDeliveryHealthOperation::Update => {
            stage_self_update(&mut members[update_position])
                .map_err(
                    |error| ExperimentalBinaryWorkloadError::AdaptiveProbeFailure {
                        member_index: candidate_member_index,
                        stage: "quaternary-update-stage",
                        detail: error.to_string(),
                    },
                )?
                .0
        }
        ExperimentalDeliveryHealthOperation::Remove => {
            let mut target_position = usize::try_from(removed_ordinal.ok_or(
                ExperimentalBinaryWorkloadError::AdaptiveProbe {
                    member_index: candidate_member_index,
                    stage: "quaternary-remove-target",
                },
            )?)
            .map_err(|_| ExperimentalBinaryWorkloadError::CountOverflow)?;
            if target_position >= members.len() || target_position == update_position {
                target_position = if update_position != 0 { 0 } else { 1 };
            }
            let target_leaf = members[target_position]
                .group
                .members()
                .find(|member| {
                    member.credential.serialized_content()
                        == workload_identity(members[target_position].member_index).as_slice()
                })
                .map(|member| member.index)
                .ok_or(ExperimentalBinaryWorkloadError::Fork)?;
            let (commit, _, _) = {
                let member = &mut members[update_position];
                member
                    .group
                    .remove_members(&member.provider, &member.signer, &[target_leaf])
                    .map_err(|_| ExperimentalBinaryWorkloadError::Fork)?
            };
            commit
                .tls_serialize_detached()
                .map_err(|_| ExperimentalBinaryWorkloadError::Fork)?
        }
    };
    Ok((transition_wire, operation_wire))
}

/// Populates every occupied quaternary internal node before measuring the
/// candidate Commit. These setup Updates are accepted by every member but are
/// intentionally excluded from the measured wire comparison.
fn warm_quaternary_probe_tree(
    members: &mut [ExperimentalWorkloadMember],
    start_position: usize,
) -> Result<(), ExperimentalBinaryWorkloadError> {
    let snapshot = members
        .first()
        .and_then(|member| {
            member
                .group
                .experimental_transition_node_availability_snapshot()
        })
        .ok_or(ExperimentalBinaryWorkloadError::Fork)?;
    let topology = ShadowQuaternaryTree::from_mapping(snapshot.frozen_mapping().clone())
        .map_err(|_| ExperimentalBinaryWorkloadError::Fork)?;
    let target_nodes = topology
        .mapping()
        .assignments
        .iter()
        .flat_map(|assignment| topology.nodes_for_member(&assignment.member_id).ok())
        .map(|nodes| {
            let internal_count = nodes.len().saturating_sub(1);
            nodes.into_iter().take(internal_count)
        })
        .flatten()
        .map(|node| (node.depth, node.ordinal))
        .collect::<BTreeSet<_>>();

    // One Update from any leaf populates every quaternary parent on that
    // leaf's path. Therefore one representative per occupied bottom-level
    // parent is sufficient to populate every occupied internal node. Walking
    // every member in ordinal order revisits the same bottom-level parent four
    // times and makes the real probe unnecessarily expensive.
    let mut representative_by_bottom_parent = BTreeMap::<u32, usize>::new();
    for assignment in &topology.mapping().assignments {
        let position = members
            .iter()
            .position(|member| workload_identity(member.member_index) == assignment.member_id)
            .ok_or(ExperimentalBinaryWorkloadError::Fork)?;
        let bottom_parent_ordinal = assignment.quaternary_leaf_ordinal / 4;
        if position == start_position {
            representative_by_bottom_parent.insert(bottom_parent_ordinal, position);
        } else {
            representative_by_bottom_parent
                .entry(bottom_parent_ordinal)
                .or_insert(position);
        }
    }
    let mut warmup_positions = representative_by_bottom_parent
        .into_values()
        .collect::<Vec<_>>();
    if let Some(start_offset) = warmup_positions
        .iter()
        .position(|position| *position == start_position)
    {
        warmup_positions.rotate_left(start_offset);
    }

    for committer_position in warmup_positions {
        let available = members[0]
            .group
            .experimental_transition_node_availability_snapshot()
            .ok_or(ExperimentalBinaryWorkloadError::Fork)?
            .usable_new_parent_nodes()
            .iter()
            .map(|node| (node.depth(), node.ordinal()))
            .collect::<BTreeSet<_>>();
        if target_nodes.is_subset(&available) {
            return Ok(());
        }
        let wire = stage_self_update(&mut members[committer_position])
            .map_err(|_| ExperimentalBinaryWorkloadError::Fork)?
            .0;
        deliver_quaternary_to_receivers(members, committer_position, &wire)?;
        merge_sender_quaternary(&mut members[committer_position])?;
        converged_epoch(members)?;
    }
    let available = members[0]
        .group
        .experimental_transition_node_availability_snapshot()
        .ok_or(ExperimentalBinaryWorkloadError::Fork)?
        .usable_new_parent_nodes()
        .iter()
        .map(|node| (node.depth(), node.ordinal()))
        .collect::<BTreeSet<_>>();
    target_nodes
        .is_subset(&available)
        .then_some(())
        .ok_or(ExperimentalBinaryWorkloadError::Fork)
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

fn validate_delivery_health_controls(
    config: &BaselineWorkloadConfig,
) -> Result<(), ExperimentalBinaryWorkloadError> {
    if config.group_id.is_empty()
        || config.initial_member_count < 3
        || config.maximum_member_count < config.initial_member_count
        || config.region_count == 0
    {
        return Err(ExperimentalBinaryWorkloadError::InvalidControls);
    }
    Ok(())
}

fn healthy_path_model_bytes(
    arity: u8,
    member_count: u32,
) -> Result<u64, ExperimentalBinaryWorkloadError> {
    if arity < 2 || member_count == 0 {
        return Err(ExperimentalBinaryWorkloadError::InvalidControls);
    }
    let mut height = 0_u64;
    let mut capacity = 1_u64;
    while capacity < u64::from(member_count) {
        capacity = capacity
            .checked_mul(u64::from(arity))
            .ok_or(ExperimentalBinaryWorkloadError::CountOverflow)?;
        height = height
            .checked_add(1)
            .ok_or(ExperimentalBinaryWorkloadError::CountOverflow)?;
    }
    let per_level = 1_504_u64
        .checked_add(
            80_u64
                .checked_mul(u64::from(arity - 1))
                .ok_or(ExperimentalBinaryWorkloadError::CountOverflow)?,
        )
        .ok_or(ExperimentalBinaryWorkloadError::CountOverflow)?;
    per_level
        .checked_mul(height)
        .ok_or(ExperimentalBinaryWorkloadError::CountOverflow)
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

    let mut pending_joiners = Vec::new();
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
        pending_joiners.push((member_index, provider, signer, bundle));
    }
    let key_packages = pending_joiners
        .iter()
        .map(|(_, _, _, bundle)| bundle.key_package().clone())
        .collect::<Vec<_>>();
    let (commit, welcome, _) = {
        let ExperimentalWorkloadMember {
            provider,
            signer,
            group,
            ..
        } = &mut members[0];
        group
            .add_members(provider, signer, &key_packages)
            .map_err(|_| ExperimentalBinaryWorkloadError::Fork)?
    };
    let _commit_wire = commit
        .tls_serialize_detached()
        .map_err(|_| ExperimentalBinaryWorkloadError::Fork)?;
    {
        let ExperimentalWorkloadMember {
            provider, group, ..
        } = &mut members[0];
        group
            .merge_pending_commit_experimental_atomic(provider)
            .map_err(|_| ExperimentalBinaryWorkloadError::Fork)?;
    }
    let welcome_wire = welcome
        .tls_serialize_detached()
        .map_err(|_| ExperimentalBinaryWorkloadError::Fork)?;
    for (member_index, provider, signer, _) in pending_joiners {
        let welcome = parse_welcome_wire(&welcome_wire)?;
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
    }
    let _ = converged_epoch(&members)?;
    Ok(members)
}

struct PendingBinaryAdd {
    member_index: u32,
    leaf_region: u32,
    provider: OpenMlsRustCrypto,
    signer: SignatureKeyPair,
    welcome_wire: Vec<u8>,
}

fn stage_binary_add(
    members: &mut [ExperimentalWorkloadMember],
    committer_position: usize,
    member_index: u32,
    region_count: u32,
) -> Result<(Vec<u8>, PendingBinaryAdd), ExperimentalBinaryWorkloadError> {
    let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    let provider = OpenMlsRustCrypto::default();
    let signer = SignatureKeyPair::new(ciphersuite.signature_algorithm())
        .map_err(|_| ExperimentalBinaryWorkloadError::Fork)?;
    let identity = workload_identity(member_index);
    let key_package = KeyPackage::builder()
        .build_with_experimental_mkyber(
            ciphersuite,
            &provider,
            &signer,
            credential(&identity, &signer),
            MkyberDomain::new([0x59; 32]),
        )
        .map_err(|_| ExperimentalBinaryWorkloadError::Fork)?;
    let (commit, welcome, _) = {
        let member = &mut members[committer_position];
        member
            .group
            .add_members(
                &member.provider,
                &member.signer,
                core::slice::from_ref(key_package.key_package()),
            )
            .map_err(
                |error| ExperimentalBinaryWorkloadError::DeliveryHealthOperationFailure {
                    sequence: member_index,
                    stage: "binary-add-openmls",
                    detail: error.to_string(),
                },
            )?
    };
    let commit_wire = commit
        .tls_serialize_detached()
        .map_err(|_| ExperimentalBinaryWorkloadError::Fork)?;
    let welcome_wire = welcome
        .tls_serialize_detached()
        .map_err(|_| ExperimentalBinaryWorkloadError::Fork)?;
    Ok((
        commit_wire,
        PendingBinaryAdd {
            member_index,
            leaf_region: member_index % region_count,
            provider,
            signer,
            welcome_wire,
        },
    ))
}

fn complete_binary_add(
    pending: PendingBinaryAdd,
) -> Result<ExperimentalWorkloadMember, ExperimentalBinaryWorkloadError> {
    let welcome = match MlsMessageIn::tls_deserialize_exact(&pending.welcome_wire)
        .map_err(|_| ExperimentalBinaryWorkloadError::Fork)?
        .extract()
    {
        MlsMessageBodyIn::Welcome(welcome) => welcome,
        _ => return Err(ExperimentalBinaryWorkloadError::Fork),
    };
    let group = StagedWelcome::new_from_welcome(
        &pending.provider,
        &MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .build(),
        welcome,
        None,
    )
    .map_err(|_| ExperimentalBinaryWorkloadError::Fork)?
    .into_group(&pending.provider)
    .map_err(|_| ExperimentalBinaryWorkloadError::Fork)?;
    Ok(ExperimentalWorkloadMember {
        member_index: pending.member_index,
        leaf_region: pending.leaf_region,
        provider: pending.provider,
        signer: pending.signer,
        group,
    })
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

fn merge_sender_retirement(
    member: &mut ExperimentalWorkloadMember,
) -> Result<(), ExperimentalBinaryWorkloadError> {
    member
        .group
        .merge_pending_commit_experimental_retirement_atomic(&member.provider)
        .map_err(|_| ExperimentalBinaryWorkloadError::Fork)
}

fn stage_self_update(
    member: &mut ExperimentalWorkloadMember,
) -> Result<
    (
        Vec<u8>,
        ExperimentalHybridCommitMetrics,
        ExperimentalHybridCommitTopology,
    ),
    ExperimentalBinaryWorkloadError,
> {
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
    let topology = bundle
        .experimental_hybrid_topology()
        .cloned()
        .ok_or(ExperimentalBinaryWorkloadError::MissingAuthenticatedRecipientSets)?;
    let (commit, _, _) = bundle.into_contents();
    let wire = commit
        .tls_serialize_detached()
        .map_err(|_| ExperimentalBinaryWorkloadError::Fork)?;
    Ok((wire, metrics, topology))
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
            .map_err(
                |error| ExperimentalBinaryWorkloadError::AdaptiveProbeFailure {
                    member_index: member.member_index,
                    stage: "transition-receiver-merge",
                    detail: error.to_string(),
                },
            )?;
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

fn deliver_retirement_to_receivers(
    members: &mut [ExperimentalWorkloadMember],
    committer_position: usize,
    sender_leaf_index: u32,
    wire: &[u8],
) -> Result<u32, String> {
    let mut count = 0_u32;
    for (position, member) in members.iter_mut().enumerate() {
        if position == committer_position {
            continue;
        }
        let message = MlsMessageIn::tls_deserialize_exact(wire)
            .map_err(|_| "retirement message deserialization failed".to_owned())?
            .try_into_protocol_message()
            .map_err(|_| "retirement message conversion failed".to_owned())?;
        let sender_debug = match &message {
            openmls_hybrid::prelude::ProtocolMessage::PublicMessage(public) => {
                format!("{:?}", public.sender())
            }
            openmls_hybrid::prelude::ProtocolMessage::PrivateMessage(_) => {
                "private-message".to_owned()
            }
        };
        let processed = member
            .group
            .process_message(&member.provider, message)
            .map_err(|error| {
                format!(
                    "sender={sender_debug}, sender_leaf={sender_leaf_index}, receiver_own_leaf={}, receiver_tree_leaves={:?}, {error}",
                    member.group.own_leaf_index().u32()
                    , member.group.members().map(|entry| entry.index.u32()).collect::<Vec<_>>()
                )
            })?;
        let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content() else {
            return Err("retirement message was not a staged Commit".to_owned());
        };
        member
            .group
            .merge_staged_commit_experimental_retirement_atomic(&member.provider, *staged)
            .map_err(|error| error.to_string())?;
        count = count
            .checked_add(1)
            .ok_or_else(|| "retirement receiver count overflowed".to_owned())?;
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

fn health_for_member(
    group: &MlsGroup,
    committer_leaf_index: u32,
) -> Result<(u32, DeliveryEndpointHealth), ExperimentalBinaryWorkloadError> {
    let state = arity_state_from_group(group)?;
    let snapshot = group
        .experimental_transition_node_availability_snapshot()
        .ok_or(ExperimentalBinaryWorkloadError::Fork)?;
    let mapping = snapshot.frozen_mapping().clone();
    let committer_ordinal = mapping
        .assignments
        .iter()
        .find(|assignment| assignment.binary_leaf_index == committer_leaf_index)
        .map(|assignment| assignment.quaternary_leaf_ordinal)
        .ok_or(ExperimentalBinaryWorkloadError::Fork)?;
    let treecover = DeliveryOnlyTreeCover::from_mapping(snapshot.treecover_version(), &mapping)
        .map_err(|_| ExperimentalBinaryWorkloadError::Fork)?;
    let trees = TransitionTrees::from_transitioning_state(&state, mapping, treecover)
        .map_err(|_| ExperimentalBinaryWorkloadError::Fork)?;
    let availability = DeliveryNodeAvailability {
        active_quaternary_leaf_ordinals: snapshot.active_quaternary_leaf_ordinals().to_vec(),
        usable_old_parent_indices: snapshot.usable_old_parent_indices().to_vec(),
        usable_new_parent_nodes: snapshot
            .usable_new_parent_nodes()
            .iter()
            .map(|node| QuaternaryNode {
                depth: node.depth(),
                ordinal: node.ordinal(),
            })
            .collect(),
    };
    let health = trees
        .delivery_endpoint_health(committer_ordinal, &availability)
        .map_err(|_| ExperimentalBinaryWorkloadError::Fork)?;
    Ok((committer_ordinal, health))
}

fn parse_welcome_wire(
    wire: &[u8],
) -> Result<openmls_hybrid::prelude::Welcome, ExperimentalBinaryWorkloadError> {
    match MlsMessageIn::tls_deserialize_exact(wire)
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
            ), ExtensionType::Unknown(
                openmls_hybrid::experimental_hybrid::TREECOVER_RETIREMENT_EVIDENCE_EXTENSION_TYPE,
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
            ), ExtensionType::Unknown(
                openmls_hybrid::experimental_hybrid::TREECOVER_RETIREMENT_EVIDENCE_EXTENSION_TYPE,
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

fn authenticated_topology_snapshot(
    members: &[ExperimentalWorkloadMember],
    committer_member_index: u32,
    committer_binary_leaf_index: u32,
    epoch: u64,
    commit_topology: ExperimentalHybridCommitTopology,
) -> Result<AuthenticatedAdaptiveTopologySnapshot, ExperimentalBinaryWorkloadError> {
    let group = &members
        .first()
        .ok_or(ExperimentalBinaryWorkloadError::InvalidControls)?
        .group;
    if group.epoch().as_u64() != epoch {
        return Err(ExperimentalBinaryWorkloadError::DivergentPublicState);
    }
    let arity_state = arity_state_from_group(group)?;
    let mapping = transition_mapping_from_group(group)?;
    let committer_quaternary_leaf_ordinal = mapping
        .assignments
        .iter()
        .find(|assignment| assignment.binary_leaf_index == committer_binary_leaf_index)
        .map(|assignment| assignment.quaternary_leaf_ordinal)
        .ok_or(ExperimentalBinaryWorkloadError::MissingAuthenticatedRecipientSets)?;
    let treecover = DeliveryOnlyTreeCover::from_mapping(1, &mapping)
        .map_err(|_| ExperimentalBinaryWorkloadError::Fork)?;
    let transition_trees =
        TransitionTrees::from_transitioning_state(&arity_state, mapping.clone(), treecover)
            .map_err(|_| ExperimentalBinaryWorkloadError::Fork)?;

    let expected_recipients = mapping
        .assignments
        .iter()
        .map(|assignment| assignment.quaternary_leaf_ordinal)
        .filter(|ordinal| *ordinal != committer_quaternary_leaf_ordinal)
        .collect::<BTreeSet<_>>();
    let mut observed_recipients = BTreeSet::new();
    if commit_topology.recipient_sets().is_empty() {
        return Err(ExperimentalBinaryWorkloadError::MissingAuthenticatedRecipientSets);
    }
    for recipient_set in commit_topology.recipient_sets() {
        if recipient_set.delivery_tree() != ExperimentalHybridDeliveryTree::ActiveQuaternaryTree
            || recipient_set.recipient_node_indices().is_empty()
        {
            return Err(ExperimentalBinaryWorkloadError::MissingAuthenticatedRecipientSets);
        }
        for recipient in recipient_set.recipient_node_indices() {
            if recipient & 0x8000_0000 != 0 {
                let depth = ((recipient >> 24) & 0x7f) as u8;
                let ordinal = recipient & 0x00ff_ffff;
                let max_binary_leaf = mapping
                    .assignments
                    .iter()
                    .map(|assignment| assignment.binary_leaf_index)
                    .max()
                    .ok_or(ExperimentalBinaryWorkloadError::InvalidControls)?;
                let mut binary_height = 0_u8;
                let mut capacity = 1_u32;
                while capacity <= max_binary_leaf {
                    capacity = capacity
                        .checked_mul(2)
                        .ok_or(ExperimentalBinaryWorkloadError::CountOverflow)?;
                    binary_height = binary_height
                        .checked_add(1)
                        .ok_or(ExperimentalBinaryWorkloadError::CountOverflow)?;
                }
                if depth >= binary_height {
                    return Err(ExperimentalBinaryWorkloadError::MissingAuthenticatedRecipientSets);
                }
                let divisor = 2_u32
                    .checked_pow(u32::from(binary_height - depth))
                    .ok_or(ExperimentalBinaryWorkloadError::CountOverflow)?;
                let covered = mapping.assignments.iter().filter(|assignment| {
                    assignment.binary_leaf_index / divisor == ordinal
                        && expected_recipients.contains(&assignment.quaternary_leaf_ordinal)
                });
                let mut covered_any = false;
                for assignment in covered {
                    covered_any = true;
                    if !observed_recipients.insert(assignment.quaternary_leaf_ordinal) {
                        return Err(
                            ExperimentalBinaryWorkloadError::MissingAuthenticatedRecipientSets,
                        );
                    }
                }
                if !covered_any {
                    return Err(ExperimentalBinaryWorkloadError::MissingAuthenticatedRecipientSets);
                }
                continue;
            }
            let depth = (recipient >> 24) as u8;
            let ordinal = recipient & 0x00ff_ffff;
            if depth > 0 && depth < transition_trees.active().topology().height() {
                let divisor = 4_u32
                    .checked_pow(u32::from(
                        transition_trees.active().topology().height() - depth,
                    ))
                    .ok_or(ExperimentalBinaryWorkloadError::CountOverflow)?;
                for covered in expected_recipients
                    .iter()
                    .copied()
                    .filter(|leaf| *leaf / divisor == ordinal)
                {
                    if covered == committer_quaternary_leaf_ordinal
                        || !observed_recipients.insert(covered)
                    {
                        return Err(
                            ExperimentalBinaryWorkloadError::MissingAuthenticatedRecipientSets,
                        );
                    }
                }
            } else if *recipient == committer_quaternary_leaf_ordinal
                || !observed_recipients.insert(*recipient)
            {
                return Err(ExperimentalBinaryWorkloadError::MissingAuthenticatedRecipientSets);
            }
        }
    }
    if observed_recipients != expected_recipients {
        return Err(ExperimentalBinaryWorkloadError::MissingAuthenticatedRecipientSets);
    }
    let exact_covers = transition_trees
        .exact_recipient_covers(&observed_recipients.iter().copied().collect::<Vec<_>>())
        .map_err(|_| ExperimentalBinaryWorkloadError::Fork)?;

    Ok(AuthenticatedAdaptiveTopologySnapshot {
        group_id: group.group_id().as_slice().to_vec(),
        epoch,
        committer_member_index,
        committer_quaternary_leaf_ordinal,
        transition_trees,
        commit_topology,
        exact_covers,
    })
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
            ExperimentalHybridDeliveryTree, ExperimentalHybridPathDelivery,
            ExperimentalMkyberError, ExperimentalMkyberNodeKeyStore,
            ExperimentalMkyberNodePublicKey, ExperimentalNodeKeyError,
            ExperimentalResolutionNodeId, ForkClassicalHpkeProvider, MkyberRecipientKeyMaterial,
            MKYBER_RECIPIENT_KEY_MATERIAL_BYTES, MKYBER_RECIPIENT_KEY_MATERIAL_VERSION,
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
    fn healthy_path_model_matches_reference_table() {
        assert_eq!(super::healthy_path_model_bytes(2, 128).unwrap(), 11_088);
        assert_eq!(super::healthy_path_model_bytes(4, 128).unwrap(), 6_976);
        assert_eq!(super::healthy_path_model_bytes(8, 128).unwrap(), 6_192);
        assert_eq!(super::healthy_path_model_bytes(2, 129).unwrap(), 12_672);
        assert_eq!(super::healthy_path_model_bytes(4, 129).unwrap(), 6_976);
        assert_eq!(super::healthy_path_model_bytes(8, 129).unwrap(), 6_192);
        assert_eq!(super::healthy_path_model_bytes(2, 512).unwrap(), 14_256);
        assert_eq!(super::healthy_path_model_bytes(4, 512).unwrap(), 8_720);
        assert_eq!(super::healthy_path_model_bytes(8, 512).unwrap(), 6_192);
    }

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
    fn eleven_observations_can_authorize_a_smaller_native_quaternary_commit() {
        let config = simulation::BaselineWorkloadConfig {
            group_id: b"task-61-adaptive-workload".to_vec(),
            initial_member_count: 5,
            maximum_member_count: 5,
            operation_count: 11,
            region_count: 2,
            committer_strategy: simulation::CommitterStrategy::RoundRobin,
            workload_profile: simulation::WorkloadProfile::UpdateOnly,
        };
        let mut probe = super::measure_adaptive_probe(&config).expect("real adaptive probe");
        assert!(!probe.transition_wire.is_empty());
        assert_eq!(probe.quaternary_update_bytes_by_member.len(), 1);
        let second_member =
            super::adaptive_probe_member_index(&config, 2).expect("second scheduled member");
        let _ = probe
            .quaternary_update_bytes(&config, second_member)
            .expect("second on-demand candidate");
        assert_eq!(probe.quaternary_update_bytes_by_member.len(), 2);
        let execution = super::execute_experimental_adaptive_workload(&config)
            .expect("native quaternary saving authorizes transition");
        let binary_bytes = execution
            .accepted_operations
            .iter()
            .filter(|operation| {
                operation.phase == super::ExperimentalAdaptiveCommitPhase::NormalBinaryUpdate
            })
            .map(|operation| operation.emitted_commit_bytes)
            .collect::<Vec<_>>();
        let quaternary_bytes = execution
            .accepted_operations
            .iter()
            .filter(|operation| {
                operation.phase == super::ExperimentalAdaptiveCommitPhase::QuaternaryUpdate
            })
            .map(|operation| operation.emitted_commit_bytes)
            .collect::<Vec<_>>();
        assert!(!binary_bytes.is_empty());
        assert!(!quaternary_bytes.is_empty());
        assert!(
            quaternary_bytes.iter().sum::<u64>() * (binary_bytes.len() as u64)
                < binary_bytes.iter().sum::<u64>() * (quaternary_bytes.len() as u64)
        );
    }

    #[test]
    fn fifteen_observation_round_robin_workload_accepts_native_quaternary_saving() {
        let config = simulation::BaselineWorkloadConfig {
            group_id: b"task-61-adaptive-workload-after-amortization".to_vec(),
            initial_member_count: 5,
            maximum_member_count: 5,
            operation_count: 15,
            region_count: 2,
            committer_strategy: simulation::CommitterStrategy::RoundRobin,
            workload_profile: simulation::WorkloadProfile::UpdateOnly,
        };
        let execution = super::execute_experimental_adaptive_workload(&config)
            .expect("native quaternary matched path authorizes transition");
        assert!(execution.accepted_operations.iter().any(|operation| {
            operation.phase == super::ExperimentalAdaptiveCommitPhase::Transition
        }));
        assert!(execution.accepted_operations.iter().any(|operation| {
            operation.phase == super::ExperimentalAdaptiveCommitPhase::QuaternaryUpdate
        }));
    }

    #[test]
    #[ignore = "expensive real 128-member rejection-only measurement"]
    fn one_hundred_twenty_eight_member_carrier_measurement_rejects_before_transition() {
        let config = simulation::BaselineWorkloadConfig {
            group_id: b"task-61-adaptive-128-measurement".to_vec(),
            initial_member_count: 128,
            maximum_member_count: 128,
            operation_count: 2,
            region_count: 2,
            committer_strategy: simulation::CommitterStrategy::RoundRobin,
            workload_profile: simulation::WorkloadProfile::UpdateOnly,
        };
        let error = super::execute_experimental_adaptive_workload(&config)
            .expect_err("two 128-member observations must not authorize transition");
        assert!(matches!(
            error,
            super::ExperimentalBinaryWorkloadError::TransitionNotAuthorized {
                current_binary_update_bytes: 29_062,
                quaternary_candidate_bytes: 25_434,
                transition_preflight_bytes: 25_634,
            }
        ));
    }

    #[test]
    #[ignore = "expensive real 128-member per-Commit transition and post-transition measurement"]
    fn one_hundred_twenty_eight_member_matched_per_commit_policy_transitions_and_converges() {
        let config = simulation::BaselineWorkloadConfig {
            group_id: b"task-61-adaptive-128-measurement".to_vec(),
            initial_member_count: 128,
            maximum_member_count: 128,
            operation_count: 3,
            region_count: 2,
            committer_strategy: simulation::CommitterStrategy::RoundRobin,
            workload_profile: simulation::WorkloadProfile::UpdateOnly,
        };
        let execution = super::execute_experimental_adaptive_workload_with_policy(
            &config,
            super::ExperimentalAdaptiveTransitionPolicy::MatchedPerCommitSaving,
        )
        .expect("matched per-Commit saving must authorize a real transition");

        assert_eq!(
            execution.transition_policy,
            super::ExperimentalAdaptiveTransitionPolicy::MatchedPerCommitSaving
        );
        assert_eq!(execution.final_member_count, 128);
        assert_eq!(execution.accepted_operations.len(), 4);
        assert_eq!(
            execution
                .accepted_operations
                .iter()
                .map(|operation| operation.phase)
                .collect::<Vec<_>>(),
            vec![
                super::ExperimentalAdaptiveCommitPhase::NormalBinaryUpdate,
                super::ExperimentalAdaptiveCommitPhase::NormalBinaryUpdate,
                super::ExperimentalAdaptiveCommitPhase::Transition,
                super::ExperimentalAdaptiveCommitPhase::QuaternaryUpdate,
            ]
        );
        assert!(execution
            .accepted_operations
            .windows(2)
            .all(|operations| operations[0].epoch_after == operations[1].epoch_before));

        let transition = execution
            .accepted_operations
            .iter()
            .find_map(|operation| operation.transition.as_ref())
            .expect("accepted transition measurement");
        let post_transition = execution
            .accepted_operations
            .last()
            .expect("post-transition quaternary update");
        eprintln!(
            "128-member matched-per-Commit result: normal_sum={} candidate_sum={} matched_window_saving={} preflight_bytes={} amortized_saving={} transition_bytes={} post_quaternary_update_bytes={}",
            transition.preflight_savings.sum_current_bytes(),
            transition.preflight_savings.sum_candidate_estimated_bytes(),
            transition.preflight_savings.average_difference().numerator(),
            transition.preflight_savings.transition_preflight_bytes(),
            transition.preflight_savings.direct_saving_bytes(),
            transition.byte_comparison.actual_bytes(),
            post_transition.emitted_commit_bytes,
        );
    }

    #[test]
    #[ignore = "real 32-member rejection-only measurement"]
    fn thirty_two_member_carrier_measurement_rejects_before_transition() {
        let config = simulation::BaselineWorkloadConfig {
            group_id: b"task-61-adaptive-32-measurement".to_vec(),
            initial_member_count: 32,
            maximum_member_count: 32,
            operation_count: 2,
            region_count: 2,
            committer_strategy: simulation::CommitterStrategy::RoundRobin,
            workload_profile: simulation::WorkloadProfile::UpdateOnly,
        };
        let error = super::execute_experimental_adaptive_workload(&config)
            .expect_err("two 32-member observations must not authorize transition");
        assert!(matches!(
            error,
            super::ExperimentalBinaryWorkloadError::TransitionNotAuthorized {
                current_binary_update_bytes: 13_221,
                quaternary_candidate_bytes: 11_083,
                transition_preflight_bytes: 11_283,
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

    #[allow(clippy::type_complexity)]
    fn experimental_binary_triple_with_policy_controls(
        target_group_size: u32,
        warmup_accepted_commits: u32,
    ) -> (
        OpenMlsRustCrypto,
        SignatureKeyPair,
        MlsGroup,
        OpenMlsRustCrypto,
        SignatureKeyPair,
        MlsGroup,
        OpenMlsRustCrypto,
        SignatureKeyPair,
        MlsGroup,
    ) {
        let (alice_provider, alice_signer, mut alice, bob_provider, bob_signer, mut bob) =
            experimental_binary_pair_with_policy_controls(
                target_group_size,
                warmup_accepted_commits,
            );
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
        let (add_commit, welcome, _) = alice
            .add_members(
                &alice_provider,
                &alice_signer,
                core::slice::from_ref(charlie_bundle.key_package()),
            )
            .expect("Alice adds Charlie");
        let add_wire = add_commit
            .tls_serialize_detached()
            .expect("Charlie add Commit serialization");
        let bob_staged = staged_commit_from_wire(&mut bob, &bob_provider, &add_wire);
        bob.merge_staged_commit_experimental_atomic(&bob_provider, bob_staged)
            .expect("Bob merges Charlie add");
        alice
            .merge_pending_commit_experimental_atomic(&alice_provider)
            .expect("Alice merges Charlie add");
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
        let charlie = StagedWelcome::new_from_welcome(
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
        (
            alice_provider,
            alice_signer,
            alice,
            bob_provider,
            bob_signer,
            bob,
            charlie_provider,
            charlie_signer,
            charlie,
        )
    }

    fn transitioned_experimental_pair() -> (
        OpenMlsRustCrypto,
        SignatureKeyPair,
        MlsGroup,
        OpenMlsRustCrypto,
        SignatureKeyPair,
        MlsGroup,
    ) {
        let (alice_provider, alice_signer, mut alice, bob_provider, bob_signer, mut bob) =
            experimental_binary_pair_with_policy_controls(2, 0);
        let transition_state = triggered_transition_state(&alice);
        let (transition_commit, _, _) = alice
            .begin_experimental_transition(&alice_provider, &alice_signer, transition_state)
            .expect("Alice stages transition");
        let transition_wire = transition_commit
            .tls_serialize_detached()
            .expect("transition serialization");
        let bob_transition = staged_commit_from_wire(&mut bob, &bob_provider, &transition_wire);
        bob.merge_staged_commit_experimental_transition_atomic(&bob_provider, bob_transition)
            .expect("Bob merges transition");
        alice
            .merge_pending_commit_experimental_transition_atomic(&alice_provider)
            .expect("Alice merges transition");
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
        let topology = update
            .experimental_hybrid_topology()
            .expect("signed public recipient-set topology");
        assert!(!topology.recipient_sets().is_empty());
        let expected_tree = match arity_state_from_group(bob).lifecycle() {
            ArityLifecycle::Normal => ExperimentalHybridDeliveryTree::BinaryTree,
            ArityLifecycle::Transitioning(_) => {
                let mapping = bob
                    .experimental_transition_node_availability_snapshot()
                    .expect("retained native quaternary mapping")
                    .frozen_mapping()
                    .clone();
                let expected_height = adaptive_tree::ShadowQuaternaryTree::from_mapping(mapping)
                    .expect("native quaternary topology")
                    .height();
                assert_eq!(topology.binary_update_path_node_count(), 0);
                assert_eq!(
                    topology.quaternary_update_path_node_count(),
                    u32::from(expected_height)
                );
                ExperimentalHybridDeliveryTree::ActiveQuaternaryTree
            }
        };
        assert!(topology
            .recipient_sets()
            .iter()
            .all(
                |recipient_set| recipient_set.delivery_tree() == expected_tree
                    && !recipient_set.recipient_node_indices().is_empty()
                    && recipient_set.canonical_delivery_bytes() > 0
            ));
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
    fn retained_transition_nodes_survive_update_and_invalidate_old_direct_path_on_remove() {
        let (
            alice_provider,
            alice_signer,
            mut alice,
            bob_provider,
            bob_signer,
            mut bob,
            charlie_provider,
            _charlie_signer,
            mut charlie,
        ) = experimental_binary_triple_with_policy_controls(3, 0);

        let transition_state = triggered_transition_state(&alice);
        let (transition_commit, _, _) = alice
            .begin_experimental_transition(&alice_provider, &alice_signer, transition_state.clone())
            .expect("Alice stages three-member transition");
        let transition_wire = transition_commit
            .tls_serialize_detached()
            .expect("transition serialization");
        let bob_transition = staged_commit_from_wire(&mut bob, &bob_provider, &transition_wire);
        let charlie_transition =
            staged_commit_from_wire(&mut charlie, &charlie_provider, &transition_wire);
        bob.merge_staged_commit_experimental_transition_atomic(&bob_provider, bob_transition)
            .expect("Bob merges transition");
        charlie
            .merge_staged_commit_experimental_transition_atomic(
                &charlie_provider,
                charlie_transition,
            )
            .expect("Charlie merges transition");
        alice
            .merge_pending_commit_experimental_transition_atomic(&alice_provider)
            .expect("Alice merges transition");

        let initial = alice
            .experimental_transition_node_availability_status()
            .expect("initial retained transition state");
        let initial_snapshot = alice
            .experimental_transition_node_availability_snapshot()
            .expect("initial retained availability snapshot");
        assert_eq!(initial.active_member_count(), 3);
        assert_eq!(initial.usable_new_node_count(), 1);
        assert!(initial.usable_old_node_count() > 0);
        assert_eq!(
            initial_snapshot.active_quaternary_leaf_ordinals(),
            &[0, 1, 2]
        );
        assert_eq!(initial_snapshot.usable_new_parent_nodes().len(), 1);
        assert_eq!(
            initial_snapshot.usable_old_parent_indices().len(),
            initial.usable_old_node_count() as usize
        );
        let ArityLifecycle::Transitioning(transitioning) = transition_state.lifecycle() else {
            panic!("expected transitioning state");
        };
        assert_eq!(
            initial.mapping_hash(),
            transitioning.mapping_hash().as_bytes()
        );
        for group in [&bob, &charlie] {
            let status = group
                .experimental_transition_node_availability_status()
                .expect("receiver retained transition state");
            assert_eq!(status.active_member_count(), initial.active_member_count());
            assert_eq!(status.mapping_hash(), initial.mapping_hash());
            assert_eq!(status.treecover_hash(), initial.treecover_hash());
            assert_eq!(
                status.usable_old_node_count(),
                initial.usable_old_node_count()
            );
            assert_eq!(status.usable_new_node_count(), 1);
            assert_eq!(
                group
                    .experimental_transition_node_availability_snapshot()
                    .expect("receiver availability snapshot"),
                initial_snapshot
            );
        }

        let dave_provider = OpenMlsRustCrypto::default();
        let dave_signer = SignatureKeyPair::new(
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519.signature_algorithm(),
        )
        .expect("Dave signer");
        let dave_bundle = KeyPackage::builder()
            .build_with_experimental_mkyber(
                Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
                &dave_provider,
                &dave_signer,
                CredentialWithKey {
                    credential: BasicCredential::new(b"experimental-dave".to_vec()).into(),
                    signature_key: dave_signer.public().into(),
                },
                MkyberDomain::new([0x91; 32]),
            )
            .expect("Dave experimental KeyPackage");
        let epoch_before_rejected_add = alice.epoch();
        assert!(
            alice
                .add_members(
                    &alice_provider,
                    &alice_signer,
                    core::slice::from_ref(dave_bundle.key_package()),
                )
                .is_err(),
            "post-transition Add must fail against the frozen mapping"
        );
        assert_eq!(alice.epoch(), epoch_before_rejected_add);
        assert_eq!(
            alice.experimental_transition_node_availability_status(),
            Some(initial)
        );

        let charlie_leaf = charlie.own_leaf_index();
        let (remove_commit, welcome, _) = bob
            .remove_members(&bob_provider, &bob_signer, &[charlie_leaf])
            .expect("Bob stages post-transition Charlie Remove");
        assert!(welcome.is_none());
        let remove_wire = remove_commit
            .tls_serialize_detached()
            .expect("Remove serialization");
        let alice_remove = staged_commit_from_wire(&mut alice, &alice_provider, &remove_wire);
        let charlie_remove = staged_commit_from_wire(&mut charlie, &charlie_provider, &remove_wire);
        alice
            .merge_staged_commit_experimental_quaternary_atomic(&alice_provider, alice_remove)
            .expect("Alice merges post-transition Remove");
        charlie
            .merge_staged_commit_experimental_quaternary_atomic(&charlie_provider, charlie_remove)
            .expect("Charlie accepts self-removal");
        bob.merge_pending_commit_experimental_quaternary_atomic(&bob_provider)
            .expect("Bob merges post-transition Remove");

        let alice_after_remove = alice
            .experimental_transition_node_availability_status()
            .expect("Alice retained state after Remove");
        let bob_after_remove = bob
            .experimental_transition_node_availability_status()
            .expect("Bob retained state after Remove");
        let alice_snapshot_after_remove = alice
            .experimental_transition_node_availability_snapshot()
            .expect("Alice availability after Remove");
        let bob_snapshot_after_remove = bob
            .experimental_transition_node_availability_snapshot()
            .expect("Bob availability after Remove");
        assert_eq!(alice_after_remove.active_member_count(), 2);
        assert_eq!(bob_after_remove.active_member_count(), 2);
        assert_eq!(
            initial.usable_old_node_count() - alice_after_remove.usable_old_node_count(),
            1,
            "the sparse three-member tree retains one non-blank value on Charlie's old direct path"
        );
        assert_eq!(
            alice_after_remove.usable_old_node_count(),
            bob_after_remove.usable_old_node_count()
        );
        assert_eq!(alice_after_remove.usable_new_node_count(), 1);
        assert_eq!(
            alice_after_remove.usable_new_node_count(),
            bob_after_remove.usable_new_node_count()
        );
        assert_eq!(alice_after_remove.mapping_hash(), initial.mapping_hash());
        assert_eq!(bob_after_remove.mapping_hash(), initial.mapping_hash());
        assert_eq!(alice_snapshot_after_remove, bob_snapshot_after_remove);
        assert_eq!(
            alice_snapshot_after_remove.active_quaternary_leaf_ordinals(),
            &[0, 1]
        );
        assert_eq!(
            alice_snapshot_after_remove
                .usable_old_parent_indices()
                .len(),
            alice_after_remove.usable_old_node_count() as usize
        );
        assert_eq!(
            alice_snapshot_after_remove.usable_new_parent_nodes().len(),
            alice_after_remove.usable_new_node_count() as usize
        );
        assert_eq!(
            alice_snapshot_after_remove.frozen_mapping(),
            initial_snapshot.frozen_mapping(),
            "Remove must preserve the complete frozen mapping and leave a hole"
        );
        assert_eq!(alice.epoch(), bob.epoch());
        assert_eq!(alice.export_ratchet_tree(), bob.export_ratchet_tree());

        let reloaded_alice = MlsGroup::load(alice_provider.storage(), alice.group_id())
            .expect("Alice storage read")
            .expect("stored Alice group");
        assert_eq!(
            reloaded_alice.experimental_transition_node_availability_status(),
            Some(alice_after_remove)
        );
        assert_eq!(
            reloaded_alice.experimental_transition_node_availability_snapshot(),
            Some(alice_snapshot_after_remove)
        );

        let update_wire = hybrid_self_update_wire(
            &mut alice,
            &alice_provider,
            &alice_signer,
            LeafNodeParameters::default(),
        );
        let bob_update = staged_commit_from_wire(&mut bob, &bob_provider, &update_wire);
        bob.merge_staged_commit_experimental_quaternary_atomic(&bob_provider, bob_update)
            .expect("Bob merges Update through frozen mapping hole");
        alice
            .merge_pending_commit_experimental_quaternary_atomic(&alice_provider)
            .expect("Alice merges Update through frozen mapping hole");
        assert_eq!(alice.epoch(), bob.epoch());
        assert_eq!(alice.export_ratchet_tree(), bob.export_ratchet_tree());
        assert_eq!(
            alice.experimental_transition_node_availability_snapshot(),
            bob.experimental_transition_node_availability_snapshot()
        );
        assert_eq!(
            alice
                .experimental_transition_node_availability_status()
                .expect("Alice final retained state")
                .active_member_count(),
            2
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
            let availability_before = alice.experimental_transition_node_availability_status();
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
            assert_eq!(
                alice.experimental_transition_node_availability_status(),
                availability_before
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
        let availability_before = alice.experimental_transition_node_availability_status();
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
        assert_eq!(
            alice.experimental_transition_node_availability_status(),
            availability_before
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
        let availability_before = alice.experimental_transition_node_availability_status();
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
        assert_eq!(
            alice.experimental_transition_node_availability_status(),
            availability_before
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
        let availability_before = alice.experimental_transition_node_availability_status();
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
        assert_eq!(
            alice.experimental_transition_node_availability_status(),
            availability_before
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
        for group in [&alice, &bob, &charlie, &dave] {
            assert_eq!(
                group
                    .experimental_quaternary_epoch_secret_status()
                    .expect("five-member mapped authority")
                    .parent_key_count(),
                2,
                "five members require root plus one depth-1 parent for Bob's mapped path"
            );
        }
        assert_eq!(
            eve.experimental_quaternary_epoch_secret_status()
                .expect("five-member mapped authority")
                .parent_key_count(),
            1,
            "Eve retains only the root private key outside Bob's depth-1 subtree"
        );
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
    fn quaternary_receiver_merge_rolls_back_retained_nodes_on_every_storage_failure() {
        let (control_provider, _control_signer, mut control, bob_provider, bob_signer, mut bob) =
            transitioned_experimental_pair();
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
            .merge_staged_commit_experimental_quaternary_atomic(&control_provider, control_staged)
            .expect("control quaternary receiver merge");
        let mutation_count = control_provider.storage().last_transaction_mutation_count();
        assert!(mutation_count > 0);

        for failure_at in 0..mutation_count {
            let (alice_provider, _alice_signer, mut alice, bob_provider, bob_signer, mut bob) =
                transitioned_experimental_pair();
            let update_wire = hybrid_self_update_wire(
                &mut bob,
                &bob_provider,
                &bob_signer,
                LeafNodeParameters::default(),
            );
            let staged = staged_commit_from_wire(&mut alice, &alice_provider, &update_wire);
            let before_epoch = alice.epoch();
            let before_tree = alice.export_ratchet_tree();
            let before_availability = alice.experimental_transition_node_availability_status();
            let before_storage = alice_provider.storage().values.read().unwrap().clone();
            alice_provider
                .storage()
                .set_transaction_failure_at(Some(failure_at));

            assert!(alice
                .merge_staged_commit_experimental_quaternary_atomic(&alice_provider, staged)
                .is_err());
            assert_eq!(alice.epoch(), before_epoch);
            assert_eq!(alice.export_ratchet_tree(), before_tree);
            assert_eq!(
                alice.experimental_transition_node_availability_status(),
                before_availability
            );
            assert_eq!(
                *alice_provider.storage().values.read().unwrap(),
                before_storage
            );
            let reloaded = MlsGroup::load(alice_provider.storage(), alice.group_id())
                .expect("failed quaternary transaction remains loadable")
                .expect("stored pre-merge group");
            assert_eq!(
                reloaded.experimental_transition_node_availability_status(),
                before_availability
            );
        }
    }

    #[test]
    fn quaternary_pending_merge_rolls_back_retained_nodes_on_every_storage_failure() {
        let (_alice_provider, _alice_signer, _alice, control_provider, control_signer, mut control) =
            transitioned_experimental_pair();
        let _control_wire = hybrid_self_update_wire(
            &mut control,
            &control_provider,
            &control_signer,
            LeafNodeParameters::default(),
        );
        control_provider.storage().set_transaction_failure_at(None);
        control
            .merge_pending_commit_experimental_quaternary_atomic(&control_provider)
            .expect("control quaternary pending merge");
        let mutation_count = control_provider.storage().last_transaction_mutation_count();
        assert!(mutation_count > 0);

        for failure_at in 0..mutation_count {
            let (_alice_provider, _alice_signer, _alice, bob_provider, bob_signer, mut bob) =
                transitioned_experimental_pair();
            let _update_wire = hybrid_self_update_wire(
                &mut bob,
                &bob_provider,
                &bob_signer,
                LeafNodeParameters::default(),
            );
            let before_epoch = bob.epoch();
            let before_tree = bob.export_ratchet_tree();
            let before_availability = bob.experimental_transition_node_availability_status();
            let before_storage = bob_provider.storage().values.read().unwrap().clone();
            bob_provider
                .storage()
                .set_transaction_failure_at(Some(failure_at));

            assert!(bob
                .merge_pending_commit_experimental_quaternary_atomic(&bob_provider)
                .is_err());
            assert_eq!(bob.epoch(), before_epoch);
            assert_eq!(bob.export_ratchet_tree(), before_tree);
            assert_eq!(
                bob.experimental_transition_node_availability_status(),
                before_availability
            );
            assert!(bob.pending_commit().is_some());
            assert_eq!(
                *bob_provider.storage().values.read().unwrap(),
                before_storage
            );
            let reloaded = MlsGroup::load(bob_provider.storage(), bob.group_id())
                .expect("failed quaternary pending transaction remains loadable")
                .expect("stored pending group");
            assert_eq!(
                reloaded.experimental_transition_node_availability_status(),
                before_availability
            );
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
