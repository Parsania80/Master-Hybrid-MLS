#![forbid(unsafe_code)]

//! Canonical thesis-local state for the private-use adaptive-tree extension.
//!
//! This crate validates and serializes only public `ArityState` metadata. A
//! later experimental OpenMLS fork must carry the returned value in an
//! authenticated GroupContext extension; this crate does not construct MLS
//! proposals, authenticate a commit, mutate a group, derive secrets, or model
//! TreeCover routing.

use sha2::{Digest, Sha256};
use thiserror::Error;
use transition_policy::{
    DeltaThreshold, PolicyWindowConfig, ResolvedDeltaThreshold, TransitionStartConfig,
    TransitionStartEvaluation,
};

use serde::Serialize;

/// Private-use MLS extension type reserved by ADR 0005.
pub const ADAPTIVE_HYBRID_TREE_STATE_EXTENSION_TYPE: u16 = 0xF001;
/// Supported canonical `ArityState` value version.
pub const ARITY_STATE_VERSION: u16 = 1;

const STATE_MAGIC: [u8; 4] = *b"AHAS";
const NORMAL_STATE_TAG: u8 = 0;
const TRANSITIONING_STATE_TAG: u8 = 1;
const DELTA_BYTES_TAG: u8 = 0;
const DELTA_PERCENT_TAG: u8 = 1;

/// A SHA-256 digest of the complete canonical leaf-mapping bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct MappingHash([u8; 32]);

impl MappingHash {
    /// Constructs a typed mapping digest from public bytes.
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the public digest bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// A SHA-256 digest of the complete canonical TreeCover public state.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct TreeCoverHash([u8; 32]);

impl TreeCoverHash {
    /// Constructs a typed TreeCover digest from public bytes.
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the public digest bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Hashes canonical public mapping or TreeCover bytes with SHA-256.
///
/// The caller is responsible for passing the complete, already validated
/// canonical representation of the relevant public object.
pub fn hash_canonical_public_bytes(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// The public controls that governed a recorded transition start decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct ArityPolicySnapshot {
    window_accepted_commits: u32,
    warmup_accepted_commits: u32,
    q_min: u32,
    target_group_size: u32,
    stable_epoch_count: u32,
    configured_delta: DeltaThreshold,
    resolved_delta_bytes: u64,
    transition_preflight_bytes: u64,
    configuration_digest: [u8; 32],
}

impl ArityPolicySnapshot {
    /// Creates a self-consistent snapshot from the existing public policy controls.
    pub fn from_policy_inputs(
        window: PolicyWindowConfig,
        start: TransitionStartConfig,
        resolved_delta: ResolvedDeltaThreshold,
    ) -> Result<Self, ArityStateError> {
        if window.window_accepted_commits == 0 {
            return Err(ArityStateError::ZeroWindowLength);
        }
        if window.q_min == 0 {
            return Err(ArityStateError::ZeroImpactMinimum);
        }
        if resolved_delta.resolved_bytes() != start.delta_bytes {
            return Err(ArityStateError::ResolvedDeltaMismatch);
        }

        let mut snapshot = Self {
            window_accepted_commits: window.window_accepted_commits,
            warmup_accepted_commits: window.warmup_accepted_commits,
            q_min: window.q_min,
            target_group_size: start.target_group_size,
            stable_epoch_count: start.stable_epoch_count,
            configured_delta: resolved_delta.configured(),
            resolved_delta_bytes: resolved_delta.resolved_bytes(),
            transition_preflight_bytes: resolved_delta.transition_preflight_bytes(),
            configuration_digest: [0_u8; 32],
        };
        snapshot.validate_controls()?;
        snapshot.configuration_digest = hash_canonical_public_bytes(&snapshot.controls_bytes());
        Ok(snapshot)
    }

    /// Returns the bounded accepted-commit window length.
    pub const fn window_accepted_commits(&self) -> u32 {
        self.window_accepted_commits
    }

    /// Returns the number of accepted commits excluded as warmup.
    pub const fn warmup_accepted_commits(&self) -> u32 {
        self.warmup_accepted_commits
    }

    /// Returns the required current-window impactful count.
    pub const fn q_min(&self) -> u32 {
        self.q_min
    }

    /// Returns the required public group size.
    pub const fn target_group_size(&self) -> u32 {
        self.target_group_size
    }

    /// Returns the required consecutive at-target accepted epochs.
    pub const fn stable_epoch_count(&self) -> u32 {
        self.stable_epoch_count
    }

    /// Returns the configured byte-or-percent Delta form.
    pub const fn configured_delta(&self) -> DeltaThreshold {
        self.configured_delta
    }

    /// Returns the resolved integer byte Delta used by the start gate.
    pub const fn resolved_delta_bytes(&self) -> u64 {
        self.resolved_delta_bytes
    }

    /// Returns the preflight bytes used to resolve the Delta form.
    pub const fn transition_preflight_bytes(&self) -> u64 {
        self.transition_preflight_bytes
    }

    /// Returns the SHA-256 digest of the complete public control snapshot.
    pub const fn configuration_digest(&self) -> &[u8; 32] {
        &self.configuration_digest
    }

    fn validate_controls(&self) -> Result<(), ArityStateError> {
        if self.window_accepted_commits == 0 {
            return Err(ArityStateError::ZeroWindowLength);
        }
        if self.q_min == 0 {
            return Err(ArityStateError::ZeroImpactMinimum);
        }
        if self.target_group_size == 0 {
            return Err(ArityStateError::ZeroTargetGroupSize);
        }
        if self.stable_epoch_count == 0 {
            return Err(ArityStateError::ZeroStableEpochCount);
        }
        Ok(())
    }

    fn controls_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(45);
        bytes.extend_from_slice(&self.window_accepted_commits.to_be_bytes());
        bytes.extend_from_slice(&self.warmup_accepted_commits.to_be_bytes());
        bytes.extend_from_slice(&self.q_min.to_be_bytes());
        bytes.extend_from_slice(&self.target_group_size.to_be_bytes());
        bytes.extend_from_slice(&self.stable_epoch_count.to_be_bytes());
        match self.configured_delta {
            DeltaThreshold::Bytes(value) => {
                bytes.push(DELTA_BYTES_TAG);
                bytes.extend_from_slice(&value.to_be_bytes());
            }
            DeltaThreshold::PercentOfTransitionMicro(value) => {
                bytes.push(DELTA_PERCENT_TAG);
                bytes.extend_from_slice(&u64::from(value).to_be_bytes());
            }
        }
        bytes.extend_from_slice(&self.resolved_delta_bytes.to_be_bytes());
        bytes.extend_from_slice(&self.transition_preflight_bytes.to_be_bytes());
        bytes
    }
}

/// The latest public start-policy observation retained in authenticated state.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct TransitionEvaluationState {
    last_evaluated_epoch: u64,
    consecutive_target_epochs: u32,
    impactful_commit_count: u32,
}

impl TransitionEvaluationState {
    /// Constructs the public state from a completed start-policy evaluation.
    pub fn from_evaluation(
        evaluation: &TransitionStartEvaluation,
        impactful_commit_count: u32,
    ) -> Self {
        Self {
            last_evaluated_epoch: evaluation.epoch_after(),
            consecutive_target_epochs: evaluation.consecutive_target_epochs(),
            impactful_commit_count,
        }
    }

    /// Constructs an initial or externally recovered public observation.
    pub const fn new(
        last_evaluated_epoch: u64,
        consecutive_target_epochs: u32,
        impactful_commit_count: u32,
    ) -> Self {
        Self {
            last_evaluated_epoch,
            consecutive_target_epochs,
            impactful_commit_count,
        }
    }

    /// Returns the epoch after the latest evaluated accepted commit.
    pub const fn last_evaluated_epoch(&self) -> u64 {
        self.last_evaluated_epoch
    }

    /// Returns the current consecutive at-target accepted epoch count.
    pub const fn consecutive_target_epochs(&self) -> u32 {
        self.consecutive_target_epochs
    }

    /// Returns `q_e` from the current accepted-commit window.
    pub const fn impactful_commit_count(&self) -> u32 {
        self.impactful_commit_count
    }
}

/// The frozen public TreeCover identity carried while transitioning.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct TreeCoverBinding {
    version: u32,
    hash: TreeCoverHash,
}

impl TreeCoverBinding {
    /// Creates a non-zero versioned public TreeCover binding.
    pub const fn new(version: u32, hash: TreeCoverHash) -> Result<Self, ArityStateError> {
        if version == 0 {
            return Err(ArityStateError::ZeroTreeCoverVersion);
        }
        Ok(Self { version, hash })
    }

    /// Returns the TreeCover representation version.
    pub const fn version(&self) -> u32 {
        self.version
    }

    /// Returns the digest of the complete public TreeCover state.
    pub const fn hash(&self) -> TreeCoverHash {
        self.hash
    }
}

/// State-specific fields carried only while the delivery-only TreeCover exists.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct TransitioningState {
    transition_epoch: u64,
    mapping_hash: MappingHash,
    treecover: TreeCoverBinding,
}

impl TransitioningState {
    /// Returns the epoch after the dedicated transition commit.
    pub const fn transition_epoch(&self) -> u64 {
        self.transition_epoch
    }

    /// Returns the deterministic leaf-mapping digest.
    pub const fn mapping_hash(&self) -> MappingHash {
        self.mapping_hash
    }

    /// Returns the frozen delivery-only TreeCover binding.
    pub const fn treecover(&self) -> TreeCoverBinding {
        self.treecover
    }
}

/// Authenticated-state lifecycle represented by the private-use extension.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum ArityLifecycle {
    /// No TreeCover exists and no transition is active.
    Normal,
    /// The quaternary tree is active and the binary TreeCover is delivery-only.
    Transitioning(TransitioningState),
}

/// Versioned canonical metadata intended for extension `0xF001`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ArityState {
    state_version: u16,
    active_arity: u8,
    candidate_arity: u8,
    tree_version: u32,
    policy: ArityPolicySnapshot,
    evaluation: TransitionEvaluationState,
    lifecycle: ArityLifecycle,
}

impl ArityState {
    /// Creates validated normal-state metadata before a transition begins.
    pub fn normal(
        active_arity: u8,
        candidate_arity: u8,
        tree_version: u32,
        policy: ArityPolicySnapshot,
        evaluation: TransitionEvaluationState,
    ) -> Result<Self, ArityStateError> {
        let state = Self {
            state_version: ARITY_STATE_VERSION,
            active_arity,
            candidate_arity,
            tree_version,
            policy,
            evaluation,
            lifecycle: ArityLifecycle::Normal,
        };
        state.validate()?;
        Ok(state)
    }

    /// Begins the dedicated transition only from a normal state and a fully
    /// satisfied Task 38 evaluation.
    ///
    /// This returns public metadata only. A future fork must authenticate the
    /// returned extension value in the same atomic MLS commit that changes the
    /// active tree.
    pub fn begin_transition(
        &self,
        evaluation: &TransitionStartEvaluation,
        impactful_commit_count: u32,
        mapping_hash: MappingHash,
        treecover: TreeCoverBinding,
    ) -> Result<Self, ArityStateError> {
        self.validate()?;
        if !matches!(self.lifecycle, ArityLifecycle::Normal) {
            return Err(ArityStateError::TransitionAlreadyActive);
        }
        if self.active_arity != 2 {
            return Err(ArityStateError::TransitionStartRequiresBinaryArity);
        }
        if !evaluation.is_triggered() {
            return Err(ArityStateError::TransitionEvaluationNotTriggered);
        }
        let evaluation =
            TransitionEvaluationState::from_evaluation(evaluation, impactful_commit_count);
        if evaluation.consecutive_target_epochs < self.policy.stable_epoch_count {
            return Err(ArityStateError::InsufficientStableEpochs);
        }
        if evaluation.impactful_commit_count < self.policy.q_min {
            return Err(ArityStateError::InsufficientImpactfulCommits);
        }
        let transition_epoch = evaluation
            .last_evaluated_epoch
            .checked_add(1)
            .ok_or(ArityStateError::TransitionEpochOverflow)?;
        let tree_version = self
            .tree_version
            .checked_add(1)
            .ok_or(ArityStateError::TreeVersionOverflow)?;
        let state = Self {
            state_version: ARITY_STATE_VERSION,
            active_arity: self.candidate_arity,
            candidate_arity: self.candidate_arity,
            tree_version,
            policy: self.policy,
            evaluation,
            lifecycle: ArityLifecycle::Transitioning(TransitioningState {
                transition_epoch,
                mapping_hash,
                treecover,
            }),
        };
        state.validate()?;
        Ok(state)
    }

    /// Decodes and validates a canonical extension value.
    pub fn from_extension_value(bytes: &[u8]) -> Result<Self, ArityStateError> {
        let mut reader = ByteReader::new(bytes);
        if reader.take_array::<4>()? != STATE_MAGIC {
            return Err(ArityStateError::MalformedEncoding);
        }
        let state_version = u16::from_be_bytes(reader.take_array()?);
        let active_arity = reader.take_u8()?;
        let candidate_arity = reader.take_u8()?;
        let tree_version = u32::from_be_bytes(reader.take_array()?);
        let window_accepted_commits = u32::from_be_bytes(reader.take_array()?);
        let warmup_accepted_commits = u32::from_be_bytes(reader.take_array()?);
        let q_min = u32::from_be_bytes(reader.take_array()?);
        let target_group_size = u32::from_be_bytes(reader.take_array()?);
        let stable_epoch_count = u32::from_be_bytes(reader.take_array()?);
        let delta_tag = reader.take_u8()?;
        let delta_value = u64::from_be_bytes(reader.take_array()?);
        let configured_delta = match delta_tag {
            DELTA_BYTES_TAG => DeltaThreshold::Bytes(delta_value),
            DELTA_PERCENT_TAG => DeltaThreshold::PercentOfTransitionMicro(
                u32::try_from(delta_value).map_err(|_| ArityStateError::MalformedEncoding)?,
            ),
            _ => return Err(ArityStateError::MalformedEncoding),
        };
        let resolved_delta_bytes = u64::from_be_bytes(reader.take_array()?);
        let transition_preflight_bytes = u64::from_be_bytes(reader.take_array()?);
        let configuration_digest = reader.take_array()?;
        let policy = ArityPolicySnapshot {
            window_accepted_commits,
            warmup_accepted_commits,
            q_min,
            target_group_size,
            stable_epoch_count,
            configured_delta,
            resolved_delta_bytes,
            transition_preflight_bytes,
            configuration_digest,
        };
        let evaluation = TransitionEvaluationState {
            last_evaluated_epoch: u64::from_be_bytes(reader.take_array()?),
            consecutive_target_epochs: u32::from_be_bytes(reader.take_array()?),
            impactful_commit_count: u32::from_be_bytes(reader.take_array()?),
        };
        let lifecycle = match reader.take_u8()? {
            NORMAL_STATE_TAG => ArityLifecycle::Normal,
            TRANSITIONING_STATE_TAG => ArityLifecycle::Transitioning(TransitioningState {
                transition_epoch: u64::from_be_bytes(reader.take_array()?),
                mapping_hash: MappingHash(reader.take_array()?),
                treecover: TreeCoverBinding::new(
                    u32::from_be_bytes(reader.take_array()?),
                    TreeCoverHash(reader.take_array()?),
                )?,
            }),
            _ => return Err(ArityStateError::MalformedEncoding),
        };
        if !reader.is_empty() {
            return Err(ArityStateError::TrailingData);
        }
        let state = Self {
            state_version,
            active_arity,
            candidate_arity,
            tree_version,
            policy,
            evaluation,
            lifecycle,
        };
        state.validate()?;
        Ok(state)
    }

    /// Serializes the complete canonical value for extension `0xF001`.
    pub fn extension_value_bytes(&self) -> Result<Vec<u8>, ArityStateError> {
        self.validate()?;
        let mut bytes = Vec::with_capacity(128);
        bytes.extend_from_slice(&STATE_MAGIC);
        bytes.extend_from_slice(&self.state_version.to_be_bytes());
        bytes.push(self.active_arity);
        bytes.push(self.candidate_arity);
        bytes.extend_from_slice(&self.tree_version.to_be_bytes());
        bytes.extend_from_slice(&self.policy.controls_bytes());
        bytes.extend_from_slice(&self.policy.configuration_digest);
        bytes.extend_from_slice(&self.evaluation.last_evaluated_epoch.to_be_bytes());
        bytes.extend_from_slice(&self.evaluation.consecutive_target_epochs.to_be_bytes());
        bytes.extend_from_slice(&self.evaluation.impactful_commit_count.to_be_bytes());
        match self.lifecycle {
            ArityLifecycle::Normal => bytes.push(NORMAL_STATE_TAG),
            ArityLifecycle::Transitioning(transitioning) => {
                bytes.push(TRANSITIONING_STATE_TAG);
                bytes.extend_from_slice(&transitioning.transition_epoch.to_be_bytes());
                bytes.extend_from_slice(transitioning.mapping_hash.as_bytes());
                bytes.extend_from_slice(&transitioning.treecover.version.to_be_bytes());
                bytes.extend_from_slice(transitioning.treecover.hash.as_bytes());
            }
        }
        Ok(bytes)
    }

    /// Returns the fixed private-use extension type.
    pub const fn extension_type(&self) -> u16 {
        ADAPTIVE_HYBRID_TREE_STATE_EXTENSION_TYPE
    }

    /// Returns the canonical state value version.
    pub const fn state_version(&self) -> u16 {
        self.state_version
    }

    /// Returns the active tree arity.
    pub const fn active_arity(&self) -> u8 {
        self.active_arity
    }

    /// Returns the candidate tree arity.
    pub const fn candidate_arity(&self) -> u8 {
        self.candidate_arity
    }

    /// Returns the authenticated logical tree version.
    pub const fn tree_version(&self) -> u32 {
        self.tree_version
    }

    /// Returns the public policy snapshot.
    pub const fn policy(&self) -> ArityPolicySnapshot {
        self.policy
    }

    /// Returns the latest public evaluation state.
    pub const fn evaluation(&self) -> TransitionEvaluationState {
        self.evaluation
    }

    /// Returns the lifecycle and, while transitioning, its immutable bindings.
    pub const fn lifecycle(&self) -> ArityLifecycle {
        self.lifecycle
    }

    /// Validates version, policy digest, arity/lifecycle, and state-machine invariants.
    pub fn validate(&self) -> Result<(), ArityStateError> {
        if self.state_version != ARITY_STATE_VERSION {
            return Err(ArityStateError::UnsupportedStateVersion);
        }
        self.policy.validate_controls()?;
        if self.policy.configuration_digest
            != hash_canonical_public_bytes(&self.policy.controls_bytes())
        {
            return Err(ArityStateError::PolicyConfigurationDigestMismatch);
        }
        if !matches!(self.active_arity, 2 | 4) {
            return Err(ArityStateError::UnsupportedActiveArity);
        }
        if self.candidate_arity != 4 {
            return Err(ArityStateError::UnsupportedCandidateArity);
        }

        match self.lifecycle {
            ArityLifecycle::Normal => {
                if self.active_arity == 2 && self.tree_version != 0 {
                    return Err(ArityStateError::BinaryNormalRequiresInitialTreeVersion);
                }
                if self.active_arity == 4 && self.tree_version == 0 {
                    return Err(ArityStateError::QuaternaryNormalRequiresTreeVersion);
                }
                Ok(())
            }
            ArityLifecycle::Transitioning(transitioning) => {
                if self.active_arity != 4 {
                    return Err(ArityStateError::TransitioningStateRequiresQuaternaryArity);
                }
                if self.tree_version == 0 {
                    return Err(ArityStateError::TransitioningStateRequiresTreeVersion);
                }
                if transitioning.transition_epoch
                    != self
                        .evaluation
                        .last_evaluated_epoch
                        .checked_add(1)
                        .ok_or(ArityStateError::TransitionEpochOverflow)?
                {
                    return Err(ArityStateError::TransitionEpochMismatch);
                }
                if self.evaluation.consecutive_target_epochs < self.policy.stable_epoch_count {
                    return Err(ArityStateError::InsufficientStableEpochs);
                }
                if self.evaluation.impactful_commit_count < self.policy.q_min {
                    return Err(ArityStateError::InsufficientImpactfulCommits);
                }
                Ok(())
            }
        }
    }
}

/// Errors from public canonical adaptive-state construction and validation.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ArityStateError {
    /// The stored state version is not supported by this implementation.
    #[error("the ArityState version is unsupported")]
    UnsupportedStateVersion,
    /// A normal or transitioning state names an unsupported active arity.
    #[error("the active tree arity is unsupported")]
    UnsupportedActiveArity,
    /// This thesis revision supports only quaternary candidate arity.
    #[error("the candidate tree arity is unsupported")]
    UnsupportedCandidateArity,
    /// The accepted-commit window must be positive.
    #[error("the accepted-commit window length must be positive")]
    ZeroWindowLength,
    /// The impactful-commit minimum must be positive.
    #[error("the impactful-commit minimum must be positive")]
    ZeroImpactMinimum,
    /// The group-size target must be positive.
    #[error("the transition target group size must be positive")]
    ZeroTargetGroupSize,
    /// The stable epoch count must be positive.
    #[error("the stable epoch count must be positive")]
    ZeroStableEpochCount,
    /// The resolved Delta does not match the value supplied to the evaluator.
    #[error("the resolved Delta does not match the transition start configuration")]
    ResolvedDeltaMismatch,
    /// A TreeCover state must have an explicit non-zero representation version.
    #[error("the TreeCover version must be positive")]
    ZeroTreeCoverVersion,
    /// A transition cannot be started while an earlier transition is active.
    #[error("an adaptive transition is already active")]
    TransitionAlreadyActive,
    /// The thesis's first migration can only start from binary normal state.
    #[error("the first adaptive transition requires active binary arity")]
    TransitionStartRequiresBinaryArity,
    /// All Task 38 start gates must be satisfied before state transition.
    #[error("the transition start evaluation did not trigger")]
    TransitionEvaluationNotTriggered,
    /// The retained evaluation does not meet the recorded stable-size threshold.
    #[error("the transition evaluation has insufficient stable epochs")]
    InsufficientStableEpochs,
    /// The retained evaluation does not meet the recorded impactful threshold.
    #[error("the transition evaluation has insufficient impactful commits")]
    InsufficientImpactfulCommits,
    /// Incrementing the logical tree version exceeded the public range.
    #[error("the logical tree version exceeds the supported range")]
    TreeVersionOverflow,
    /// The evaluation epoch cannot produce a following transition epoch.
    #[error("the transition epoch exceeds the supported range")]
    TransitionEpochOverflow,
    /// A transitioning state did not use the dedicated epoch after evaluation.
    #[error("the transition epoch does not follow the recorded evaluation epoch")]
    TransitionEpochMismatch,
    /// Transitioning requires the new active quaternary arity.
    #[error("a transitioning state requires active quaternary arity")]
    TransitioningStateRequiresQuaternaryArity,
    /// Transitioning requires a non-zero logical tree version.
    #[error("a transitioning state requires a non-zero logical tree version")]
    TransitioningStateRequiresTreeVersion,
    /// A normal binary state exists only before the first tree-version increment.
    #[error("a normal binary state requires the initial tree version")]
    BinaryNormalRequiresInitialTreeVersion,
    /// A normal quaternary state can only exist after a completed transition.
    #[error("a normal quaternary state requires a non-zero tree version")]
    QuaternaryNormalRequiresTreeVersion,
    /// The stored digest does not match the complete public policy controls.
    #[error("the policy configuration digest does not match the state controls")]
    PolicyConfigurationDigestMismatch,
    /// Canonical bytes were malformed or truncated.
    #[error("the ArityState extension value is malformed")]
    MalformedEncoding,
    /// Canonical bytes include unconsumed trailing data.
    #[error("the ArityState extension value has trailing data")]
    TrailingData,
}

struct ByteReader<'a> {
    remaining: &'a [u8],
}

impl<'a> ByteReader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    fn take_array<const N: usize>(&mut self) -> Result<[u8; N], ArityStateError> {
        let bytes = self
            .remaining
            .get(..N)
            .ok_or(ArityStateError::MalformedEncoding)?;
        let array = bytes
            .try_into()
            .map_err(|_| ArityStateError::MalformedEncoding)?;
        self.remaining = &self.remaining[N..];
        Ok(array)
    }

    fn take_u8(&mut self) -> Result<u8, ArityStateError> {
        Ok(self.take_array::<1>()?[0])
    }

    const fn is_empty(&self) -> bool {
        self.remaining.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use transition_policy::{
        CommitImpactFacts, PolicyWindow, PolicyWindowConfig, TransitionStartEvaluator,
    };

    fn snapshot() -> ArityPolicySnapshot {
        let window = PolicyWindowConfig::new(20, 2, 1).expect("valid policy window");
        let preflight =
            transition_policy::TransitionPreflightMeasurement::from_serialized_outer_message(
                &[0_u8; 100],
                &[transition_policy::TransitionByteRange::new(
                    transition_policy::TransitionByteComponent::BaseCommit,
                    0,
                    100,
                )],
            )
            .expect("valid preflight");
        let resolved = DeltaThreshold::PercentOfTransitionMicro(25_000_000)
            .resolve_for_preflight(preflight)
            .expect("Delta resolves");
        let start = TransitionStartConfig::new(2, 4, 128, 1, resolved.resolved_bytes())
            .expect("valid start controls");
        ArityPolicySnapshot::from_policy_inputs(window, start, resolved)
            .expect("self-consistent snapshot")
    }

    fn normal_state() -> ArityState {
        ArityState::normal(2, 4, 0, snapshot(), TransitionEvaluationState::new(7, 0, 0))
            .expect("valid normal state")
    }

    fn triggered_evaluation() -> (TransitionStartEvaluation, u32) {
        let mut window =
            PolicyWindow::new(PolicyWindowConfig::new(20, 0, 1).expect("valid window"));
        let record = window
            .append_accepted(
                7,
                CommitImpactFacts {
                    path_delivery_changed: true,
                    ..CommitImpactFacts::default()
                },
            )
            .expect("accepted record")
            .record;
        let mut evaluator = TransitionStartEvaluator::new(
            TransitionStartConfig::new(2, 4, 128, 1, 25).expect("valid start controls"),
        );
        let savings = transition_policy::PreflightSavings::from_impactful_costs(
            &[transition_policy::ImpactfulCommitByteCosts::new(201, 75)],
            100,
        )
        .expect("valid savings");
        let evaluation = evaluator
            .evaluate_post_warmup(
                &record,
                transition_policy::PolicyTransitionState::Normal,
                128,
                &window,
                Some(savings),
            )
            .expect("triggering evaluation");
        assert!(evaluation.is_triggered());
        (evaluation, window.q_e())
    }

    fn transition_state() -> ArityState {
        let (evaluation, q_e) = triggered_evaluation();
        normal_state()
            .begin_transition(
                &evaluation,
                q_e,
                MappingHash::new(hash_canonical_public_bytes(b"canonical mapping")),
                TreeCoverBinding::new(
                    1,
                    TreeCoverHash::new(hash_canonical_public_bytes(b"canonical treecover")),
                )
                .expect("valid TreeCover binding"),
            )
            .expect("valid transition state")
    }

    #[test]
    fn normal_and_transitioning_states_round_trip_canonically() {
        let normal = normal_state();
        assert_eq!(
            normal.extension_type(),
            ADAPTIVE_HYBRID_TREE_STATE_EXTENSION_TYPE
        );
        assert_eq!(
            ArityState::from_extension_value(&normal.extension_value_bytes().expect("encode")),
            Ok(normal)
        );

        let transitioning = transition_state();
        assert_eq!(transitioning.active_arity(), 4);
        assert_eq!(transitioning.tree_version(), 1);
        assert_eq!(
            ArityState::from_extension_value(
                &transitioning.extension_value_bytes().expect("encode")
            ),
            Ok(transitioning)
        );
    }

    #[test]
    fn state_machine_requires_a_triggered_evaluation_and_blocks_a_second_transition() {
        let normal = normal_state();
        let mut window =
            PolicyWindow::new(PolicyWindowConfig::new(20, 0, 1).expect("valid window"));
        let record = window
            .append_accepted(7, CommitImpactFacts::default())
            .expect("accepted record")
            .record;
        let mut evaluator = TransitionStartEvaluator::new(
            TransitionStartConfig::new(2, 4, 128, 1, 25).expect("valid start controls"),
        );
        let blocked = evaluator
            .evaluate_post_warmup(
                &record,
                transition_policy::PolicyTransitionState::Normal,
                127,
                &window,
                None,
            )
            .expect("blocked evaluation is still recorded");
        let binding = TreeCoverBinding::new(1, TreeCoverHash::new([3_u8; 32]))
            .expect("valid TreeCover binding");
        assert_eq!(
            normal.begin_transition(
                &blocked,
                window.q_e(),
                MappingHash::new([2_u8; 32]),
                binding
            ),
            Err(ArityStateError::TransitionEvaluationNotTriggered)
        );

        let transitioning = transition_state();
        let (triggered, q_e) = triggered_evaluation();
        assert_eq!(
            transitioning.begin_transition(&triggered, q_e, MappingHash::new([4_u8; 32]), binding,),
            Err(ArityStateError::TransitionAlreadyActive)
        );

        let quaternary_normal =
            ArityState::normal(4, 4, 1, snapshot(), TransitionEvaluationState::new(7, 1, 1))
                .expect("valid post-retirement normal state");
        assert_eq!(
            quaternary_normal.begin_transition(
                &triggered,
                q_e,
                MappingHash::new([5_u8; 32]),
                binding,
            ),
            Err(ArityStateError::TransitionStartRequiresBinaryArity)
        );
    }

    #[test]
    fn decoding_rejects_tampered_policy_digest_impossible_lifecycle_and_trailing_bytes() {
        let state = transition_state();
        let mut bytes = state.extension_value_bytes().expect("encode");
        let digest_offset = 4 + 2 + 1 + 1 + 4 + 45;
        bytes[digest_offset] ^= 1;
        assert_eq!(
            ArityState::from_extension_value(&bytes),
            Err(ArityStateError::PolicyConfigurationDigestMismatch)
        );

        let mut impossible = state.extension_value_bytes().expect("encode");
        impossible[6] = 2;
        assert_eq!(
            ArityState::from_extension_value(&impossible),
            Err(ArityStateError::TransitioningStateRequiresQuaternaryArity)
        );

        let mut trailing = normal_state().extension_value_bytes().expect("encode");
        trailing.push(0);
        assert_eq!(
            ArityState::from_extension_value(&trailing),
            Err(ArityStateError::TrailingData)
        );
    }

    #[test]
    fn snapshot_rejects_a_delta_that_does_not_match_the_start_gate() {
        let window = PolicyWindowConfig::new(20, 0, 1).expect("valid window");
        let resolved = DeltaThreshold::Bytes(10)
            .resolve_for_preflight(
                transition_policy::TransitionPreflightMeasurement::from_serialized_outer_message(
                    &[0_u8; 1],
                    &[transition_policy::TransitionByteRange::new(
                        transition_policy::TransitionByteComponent::BaseCommit,
                        0,
                        1,
                    )],
                )
                .expect("valid preflight"),
            )
            .expect("resolved Delta");
        let mismatched = TransitionStartConfig::new(2, 4, 128, 1, 11).expect("valid controls");
        assert_eq!(
            ArityPolicySnapshot::from_policy_inputs(window, mismatched, resolved),
            Err(ArityStateError::ResolvedDeltaMismatch)
        );
    }
}
