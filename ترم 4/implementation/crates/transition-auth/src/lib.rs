#![forbid(unsafe_code)]

//! Fail-closed validation of transition metadata extracted from GroupContext.
//!
//! A future experimental MLS fork must supply these values only after normal
//! MLS authentication has verified and staged a GroupContext containing the
//! private-use extension. This crate never parses MLS messages, verifies MLS
//! signatures, or mutates a group; it validates exact public cross-boundary
//! consistency before a caller receives usable transition-tree state.

use arity_state::{
    ArityLifecycle, ArityState, ArityStateError, ADAPTIVE_HYBRID_TREE_STATE_EXTENSION_TYPE,
};
use hybrid_path_secret::HybridKdfContext;
use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;
use transition_tree::{DeliveryOnlyTreeCover, TransitionTreeError, TransitionTrees};

use adaptive_tree::BinaryToQuaternaryLeafMapping;

const METADATA_COMMITMENT_LABEL: &[u8] = b"Adaptive-Hybrid-MLS-Transition-Metadata-v1";

/// Public facts extracted from an already MLS-authenticated GroupContext.
///
/// Construction hashes the exact complete GroupContext bytes under the fixed
/// SHA-256 ciphersuite used by this thesis. It does not itself validate an MLS
/// signature or prove the supplied group ID and epoch were parsed from those
/// bytes; a future fork must make that extraction atomic with MLS validation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AuthenticatedGroupContext {
    group_id: Vec<u8>,
    epoch: u64,
    group_context_hash: [u8; 32],
}

impl AuthenticatedGroupContext {
    /// Creates a binding from facts supplied by a verified MLS GroupContext.
    pub fn from_verified_group_context_bytes(
        group_id: Vec<u8>,
        epoch: u64,
        complete_group_context_bytes: &[u8],
    ) -> Result<Self, TransitionAuthenticationError> {
        if group_id.is_empty() {
            return Err(TransitionAuthenticationError::EmptyGroupId);
        }
        if complete_group_context_bytes.is_empty() {
            return Err(TransitionAuthenticationError::EmptyGroupContext);
        }
        Ok(Self {
            group_id,
            epoch,
            group_context_hash: Sha256::digest(complete_group_context_bytes).into(),
        })
    }

    /// Returns the authenticated public group identifier.
    pub fn group_id(&self) -> &[u8] {
        &self.group_id
    }

    /// Returns the authenticated MLS epoch.
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Returns the SHA-256 hash of the exact complete GroupContext bytes.
    pub const fn group_context_hash(&self) -> &[u8; 32] {
        &self.group_context_hash
    }
}

/// Untrusted transition metadata extracted from the GroupContext extension list.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TransitionMetadataEnvelope {
    group_context: AuthenticatedGroupContext,
    extension_type: u16,
    extension_value: Vec<u8>,
    mapping: BinaryToQuaternaryLeafMapping,
    treecover: DeliveryOnlyTreeCover,
}

impl TransitionMetadataEnvelope {
    /// Retains exact public extension bytes and the independently supplied
    /// mapping/TreeCover objects for fail-closed pre-apply validation.
    pub fn new(
        group_context: AuthenticatedGroupContext,
        extension_type: u16,
        extension_value: Vec<u8>,
        mapping: BinaryToQuaternaryLeafMapping,
        treecover: DeliveryOnlyTreeCover,
    ) -> Self {
        Self {
            group_context,
            extension_type,
            extension_value,
            mapping,
            treecover,
        }
    }

    /// Validates all transition metadata before any future state mutation.
    ///
    /// The supplied hybrid context must be built from the same authenticated
    /// GroupContext facts. On success, the returned object contains only
    /// validated public state and has no mutation API.
    pub fn validate_pre_apply(
        self,
        hybrid_context: &HybridKdfContext,
    ) -> Result<PreApplyValidatedTransition, TransitionAuthenticationError> {
        if self.extension_type != ADAPTIVE_HYBRID_TREE_STATE_EXTENSION_TYPE {
            return Err(TransitionAuthenticationError::UnexpectedExtensionType {
                observed: self.extension_type,
            });
        }
        let state = ArityState::from_extension_value(&self.extension_value)?;
        if state.extension_value_bytes()? != self.extension_value {
            return Err(TransitionAuthenticationError::NonCanonicalExtensionValue);
        }
        let transitioning = match state.lifecycle() {
            ArityLifecycle::Transitioning(value) => value,
            ArityLifecycle::Normal => {
                return Err(TransitionAuthenticationError::StateIsNotTransitioning)
            }
        };
        if transitioning.transition_epoch() != self.group_context.epoch() {
            return Err(TransitionAuthenticationError::TransitionEpochMismatch {
                state_epoch: transitioning.transition_epoch(),
                group_context_epoch: self.group_context.epoch(),
            });
        }
        let trees =
            TransitionTrees::from_transitioning_state(&state, self.mapping, self.treecover)?;
        validate_hybrid_context(&self.group_context, &state, hybrid_context)?;
        let metadata_commitment = metadata_commitment(
            self.group_context.group_context_hash(),
            self.extension_type,
            &self.extension_value,
        );
        Ok(PreApplyValidatedTransition {
            group_context: self.group_context,
            state,
            trees,
            metadata_commitment,
        })
    }
}

/// Immutable public transition data that passed all pre-apply consistency checks.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PreApplyValidatedTransition {
    group_context: AuthenticatedGroupContext,
    state: ArityState,
    trees: TransitionTrees,
    metadata_commitment: [u8; 32],
}

impl PreApplyValidatedTransition {
    /// Returns the validated GroupContext binding.
    pub const fn group_context(&self) -> &AuthenticatedGroupContext {
        &self.group_context
    }

    /// Returns the validated transitioning ArityState.
    pub const fn state(&self) -> &ArityState {
        &self.state
    }

    /// Returns the validated separate active-tree and TreeCover state.
    pub const fn trees(&self) -> &TransitionTrees {
        &self.trees
    }

    /// Returns a public commitment to GroupContext hash and exact extension value.
    pub const fn metadata_commitment(&self) -> &[u8; 32] {
        &self.metadata_commitment
    }
}

/// Errors raised before a future transition commit may mutate state.
#[derive(Debug, Error, Eq, PartialEq)]
pub enum TransitionAuthenticationError {
    /// A caller attempted to bind an empty group identifier.
    #[error("the verified GroupContext group identifier is empty")]
    EmptyGroupId,
    /// A caller did not provide complete GroupContext bytes for its hash.
    #[error("the verified GroupContext bytes are empty")]
    EmptyGroupContext,
    /// The extracted extension type differs from ADR 0005's private-use type.
    #[error("unexpected transition extension type {observed:#06x}")]
    UnexpectedExtensionType {
        /// Observed public extension type.
        observed: u16,
    },
    /// The canonical ArityState value was invalid.
    #[error("the ArityState extension value is invalid")]
    ArityState(#[from] ArityStateError),
    /// Re-encoding a decoded state did not reproduce the exact supplied bytes.
    #[error("the ArityState extension value is not canonical")]
    NonCanonicalExtensionValue,
    /// The extension state was normal rather than an active transition.
    #[error("the ArityState is not transitioning")]
    StateIsNotTransitioning,
    /// The state transition epoch differs from the authenticated GroupContext epoch.
    #[error("the transition epoch does not match the GroupContext epoch")]
    TransitionEpochMismatch {
        /// Epoch in the decoded transition state.
        state_epoch: u64,
        /// Epoch authenticated by MLS GroupContext.
        group_context_epoch: u64,
    },
    /// Mapping, TreeCover, version, or active-arity validation failed.
    #[error("the transition tree state is inconsistent")]
    TransitionTree(#[from] TransitionTreeError),
    /// Hybrid delivery context uses a different public group identifier.
    #[error("the hybrid context group identifier does not match GroupContext")]
    HybridGroupIdMismatch,
    /// Hybrid delivery context uses a different MLS epoch.
    #[error("the hybrid context epoch does not match GroupContext")]
    HybridEpochMismatch,
    /// Hybrid delivery context uses a different adaptive tree version.
    #[error("the hybrid context tree version does not match ArityState")]
    HybridTreeVersionMismatch,
    /// Hybrid delivery context uses a different active arity.
    #[error("the hybrid context arity does not match ArityState")]
    HybridArityMismatch,
    /// Hybrid delivery context uses a different authenticated GroupContext hash.
    #[error("the hybrid context GroupContext hash does not match")]
    HybridGroupContextHashMismatch,
}

fn validate_hybrid_context(
    group_context: &AuthenticatedGroupContext,
    state: &ArityState,
    hybrid_context: &HybridKdfContext,
) -> Result<(), TransitionAuthenticationError> {
    if hybrid_context.group_id() != group_context.group_id() {
        return Err(TransitionAuthenticationError::HybridGroupIdMismatch);
    }
    if hybrid_context.epoch() != group_context.epoch() {
        return Err(TransitionAuthenticationError::HybridEpochMismatch);
    }
    if hybrid_context.tree_version() != state.tree_version() {
        return Err(TransitionAuthenticationError::HybridTreeVersionMismatch);
    }
    if hybrid_context.current_arity().as_u8() != state.active_arity() {
        return Err(TransitionAuthenticationError::HybridArityMismatch);
    }
    if hybrid_context.group_context_hash() != group_context.group_context_hash() {
        return Err(TransitionAuthenticationError::HybridGroupContextHashMismatch);
    }
    Ok(())
}

fn metadata_commitment(
    group_context_hash: &[u8; 32],
    extension_type: u16,
    extension_value: &[u8],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(METADATA_COMMITMENT_LABEL);
    hasher.update(group_context_hash);
    hasher.update(extension_type.to_be_bytes());
    hasher.update(extension_value);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use adaptive_tree::{BinaryLeafMember, BinaryToQuaternaryLeafMapping};
    use arity_state::{
        hash_canonical_public_bytes, ArityPolicySnapshot, MappingHash, TransitionEvaluationState,
        TreeCoverBinding,
    };
    use hybrid_path_secret::{PathNodeIndex, RecipientNodeIndex, TreeArity};
    use mkyber::MkyberDomain;
    use transition_policy::{
        CommitImpactFacts, DeltaThreshold, PolicyTransitionState, PolicyWindow, PolicyWindowConfig,
        TransitionByteComponent, TransitionByteRange, TransitionPreflightMeasurement,
        TransitionStartConfig, TransitionStartEvaluator,
    };

    fn mapping() -> BinaryToQuaternaryLeafMapping {
        BinaryToQuaternaryLeafMapping::from_binary_members(vec![
            BinaryLeafMember {
                member_id: b"alice".to_vec(),
                binary_leaf_index: 0,
            },
            BinaryLeafMember {
                member_id: b"bob".to_vec(),
                binary_leaf_index: 1,
            },
        ])
        .expect("canonical mapping")
    }

    fn state_and_cover(
        mapping: &BinaryToQuaternaryLeafMapping,
    ) -> (ArityState, DeliveryOnlyTreeCover) {
        let preflight = TransitionPreflightMeasurement::from_serialized_outer_message(
            &[0_u8; 100],
            &[TransitionByteRange::new(
                TransitionByteComponent::BaseCommit,
                0,
                100,
            )],
        )
        .expect("preflight");
        let delta = DeltaThreshold::Bytes(25)
            .resolve_for_preflight(preflight)
            .expect("Delta");
        let window_config = PolicyWindowConfig::new(20, 0, 1).expect("window");
        let start = TransitionStartConfig::new(2, 4, 128, 1, 25).expect("start");
        let policy =
            ArityPolicySnapshot::from_policy_inputs(window_config, start, delta).expect("policy");
        let normal = ArityState::normal(2, 4, 0, policy, TransitionEvaluationState::new(7, 0, 0))
            .expect("normal");
        let cover = DeliveryOnlyTreeCover::from_mapping(1, mapping).expect("cover");
        let mut window = PolicyWindow::new(window_config);
        let record = window
            .append_accepted(
                7,
                CommitImpactFacts {
                    path_delivery_changed: true,
                    ..CommitImpactFacts::default()
                },
            )
            .expect("record")
            .record;
        let mut evaluator = TransitionStartEvaluator::new(start);
        let savings = transition_policy::PreflightSavings::from_impactful_costs(
            &[transition_policy::ImpactfulCommitByteCosts::new(201, 75)],
            100,
        )
        .expect("savings");
        let evaluation = evaluator
            .evaluate_post_warmup(
                &record,
                PolicyTransitionState::Normal,
                128,
                &window,
                Some(savings),
            )
            .expect("evaluation");
        assert!(evaluation.is_triggered());
        let state = normal
            .begin_transition(
                &evaluation,
                window.q_e(),
                MappingHash::new(hash_canonical_public_bytes(
                    &mapping.canonical_bytes().expect("mapping bytes"),
                )),
                TreeCoverBinding::new(cover.version(), cover.hash().expect("cover hash"))
                    .expect("binding"),
            )
            .expect("transition state");
        (state, cover)
    }

    fn valid_parts() -> (
        AuthenticatedGroupContext,
        ArityState,
        BinaryToQuaternaryLeafMapping,
        DeliveryOnlyTreeCover,
        HybridKdfContext,
    ) {
        let mapping = mapping();
        let (state, cover) = state_and_cover(&mapping);
        let group_context = AuthenticatedGroupContext::from_verified_group_context_bytes(
            b"group".to_vec(),
            8,
            b"complete authenticated GroupContext including extension",
        )
        .expect("group context binding");
        let hybrid = HybridKdfContext::new(
            b"group".to_vec(),
            8,
            1,
            TreeArity::Quaternary,
            PathNodeIndex::new(0),
            RecipientNodeIndex::new(0),
            MkyberDomain::new([9_u8; 32]),
            *group_context.group_context_hash(),
        );
        (group_context, state, mapping, cover, hybrid)
    }

    fn valid_envelope() -> (TransitionMetadataEnvelope, HybridKdfContext) {
        let (group_context, state, mapping, cover, hybrid) = valid_parts();
        (
            TransitionMetadataEnvelope::new(
                group_context,
                ADAPTIVE_HYBRID_TREE_STATE_EXTENSION_TYPE,
                state.extension_value_bytes().expect("extension bytes"),
                mapping,
                cover,
            ),
            hybrid,
        )
    }

    #[test]
    fn validates_complete_metadata_before_exposing_transition_trees() {
        let (envelope, hybrid) = valid_envelope();
        let validated = envelope
            .validate_pre_apply(&hybrid)
            .expect("complete matching metadata");
        assert_eq!(validated.state().tree_version(), 1);
        assert_eq!(validated.trees().active().arity(), 4);
        assert_eq!(validated.group_context().epoch(), 8);
        assert_ne!(*validated.metadata_commitment(), [0_u8; 32]);
    }

    #[test]
    fn rejects_extension_state_mapping_and_treecover_inconsistencies() {
        let (group_context, state, mapping, cover, hybrid) = valid_parts();
        assert_eq!(
            TransitionMetadataEnvelope::new(
                group_context.clone(),
                0xF002,
                state.extension_value_bytes().expect("extension bytes"),
                mapping.clone(),
                cover.clone(),
            )
            .validate_pre_apply(&hybrid),
            Err(TransitionAuthenticationError::UnexpectedExtensionType { observed: 0xF002 })
        );

        let mut unknown_version = state.extension_value_bytes().expect("extension bytes");
        unknown_version[4] = 0;
        unknown_version[5] = 2;
        assert!(matches!(
            TransitionMetadataEnvelope::new(
                group_context.clone(),
                ADAPTIVE_HYBRID_TREE_STATE_EXTENSION_TYPE,
                unknown_version,
                mapping.clone(),
                cover.clone(),
            )
            .validate_pre_apply(&hybrid),
            Err(TransitionAuthenticationError::ArityState(
                ArityStateError::UnsupportedStateVersion
            ))
        ));

        let wrong_epoch_context = AuthenticatedGroupContext::from_verified_group_context_bytes(
            b"group".to_vec(),
            9,
            b"different complete authenticated GroupContext",
        )
        .expect("other group context binding");
        let wrong_epoch_hybrid = HybridKdfContext::new(
            b"group".to_vec(),
            9,
            1,
            TreeArity::Quaternary,
            PathNodeIndex::new(0),
            RecipientNodeIndex::new(0),
            MkyberDomain::new([9_u8; 32]),
            *wrong_epoch_context.group_context_hash(),
        );
        assert_eq!(
            TransitionMetadataEnvelope::new(
                wrong_epoch_context,
                ADAPTIVE_HYBRID_TREE_STATE_EXTENSION_TYPE,
                state.extension_value_bytes().expect("extension bytes"),
                mapping.clone(),
                cover.clone(),
            )
            .validate_pre_apply(&wrong_epoch_hybrid),
            Err(TransitionAuthenticationError::TransitionEpochMismatch {
                state_epoch: 8,
                group_context_epoch: 9,
            })
        );

        let normal = ArityState::normal(
            2,
            4,
            0,
            state.policy(),
            TransitionEvaluationState::new(7, 0, 0),
        )
        .expect("normal state");
        assert_eq!(
            TransitionMetadataEnvelope::new(
                group_context.clone(),
                ADAPTIVE_HYBRID_TREE_STATE_EXTENSION_TYPE,
                normal
                    .extension_value_bytes()
                    .expect("normal extension bytes"),
                mapping.clone(),
                cover.clone(),
            )
            .validate_pre_apply(&hybrid),
            Err(TransitionAuthenticationError::StateIsNotTransitioning)
        );

        let changed_mapping = BinaryToQuaternaryLeafMapping::from_binary_members(vec![
            BinaryLeafMember {
                member_id: b"alice".to_vec(),
                binary_leaf_index: 0,
            },
            BinaryLeafMember {
                member_id: b"bob".to_vec(),
                binary_leaf_index: 2,
            },
        ])
        .expect("changed mapping");
        assert_eq!(
            TransitionMetadataEnvelope::new(
                group_context.clone(),
                ADAPTIVE_HYBRID_TREE_STATE_EXTENSION_TYPE,
                state.extension_value_bytes().expect("extension bytes"),
                changed_mapping,
                cover.clone(),
            )
            .validate_pre_apply(&hybrid),
            Err(TransitionAuthenticationError::TransitionTree(
                TransitionTreeError::MappingHashMismatch
            ))
        );

        let other_cover = DeliveryOnlyTreeCover::from_mapping(2, &mapping).expect("other cover");
        assert_eq!(
            TransitionMetadataEnvelope::new(
                group_context,
                ADAPTIVE_HYBRID_TREE_STATE_EXTENSION_TYPE,
                state.extension_value_bytes().expect("extension bytes"),
                mapping,
                other_cover,
            )
            .validate_pre_apply(&hybrid),
            Err(TransitionAuthenticationError::TransitionTree(
                TransitionTreeError::TreeCoverVersionMismatch
            ))
        );
    }

    #[test]
    fn rejects_group_context_epoch_tree_version_arity_and_hash_replays() {
        let (envelope, hybrid) = valid_envelope();
        let wrong_group = HybridKdfContext::new(
            b"other".to_vec(),
            hybrid.epoch(),
            hybrid.tree_version(),
            hybrid.current_arity(),
            hybrid.path_node_index(),
            hybrid.recipient_node_index(),
            hybrid.mkyber_domain(),
            *hybrid.group_context_hash(),
        );
        assert_eq!(
            envelope.clone().validate_pre_apply(&wrong_group),
            Err(TransitionAuthenticationError::HybridGroupIdMismatch)
        );

        let wrong_epoch = HybridKdfContext::new(
            hybrid.group_id().to_vec(),
            9,
            hybrid.tree_version(),
            hybrid.current_arity(),
            hybrid.path_node_index(),
            hybrid.recipient_node_index(),
            hybrid.mkyber_domain(),
            *hybrid.group_context_hash(),
        );
        assert_eq!(
            envelope.clone().validate_pre_apply(&wrong_epoch),
            Err(TransitionAuthenticationError::HybridEpochMismatch)
        );

        let wrong_tree_version = HybridKdfContext::new(
            hybrid.group_id().to_vec(),
            hybrid.epoch(),
            2,
            hybrid.current_arity(),
            hybrid.path_node_index(),
            hybrid.recipient_node_index(),
            hybrid.mkyber_domain(),
            *hybrid.group_context_hash(),
        );
        assert_eq!(
            envelope.clone().validate_pre_apply(&wrong_tree_version),
            Err(TransitionAuthenticationError::HybridTreeVersionMismatch)
        );

        let wrong_arity = HybridKdfContext::new(
            hybrid.group_id().to_vec(),
            hybrid.epoch(),
            hybrid.tree_version(),
            TreeArity::Binary,
            hybrid.path_node_index(),
            hybrid.recipient_node_index(),
            hybrid.mkyber_domain(),
            *hybrid.group_context_hash(),
        );
        assert_eq!(
            envelope.clone().validate_pre_apply(&wrong_arity),
            Err(TransitionAuthenticationError::HybridArityMismatch)
        );

        let wrong_hash = HybridKdfContext::new(
            hybrid.group_id().to_vec(),
            hybrid.epoch(),
            hybrid.tree_version(),
            hybrid.current_arity(),
            hybrid.path_node_index(),
            hybrid.recipient_node_index(),
            hybrid.mkyber_domain(),
            [8_u8; 32],
        );
        assert_eq!(
            envelope.validate_pre_apply(&wrong_hash),
            Err(TransitionAuthenticationError::HybridGroupContextHashMismatch)
        );
    }
}
