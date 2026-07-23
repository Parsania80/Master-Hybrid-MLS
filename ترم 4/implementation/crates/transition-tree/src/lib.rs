#![forbid(unsafe_code)]

//! Separate public active-quaternary and delivery-only-binary transition state.
//!
//! The active quaternary topology delegates deterministic public membership
//! replay to `adaptive-tree`. The frozen binary TreeCover retains only routing
//! eligibility. Neither type holds secret bytes, and only the active side has
//! an epoch-secret-authority marker; actual TreeKEM secret derivation remains
//! future fork work.

use std::collections::{BTreeMap, BTreeSet};

use adaptive_tree::{
    AdaptiveTreeError, BinaryToQuaternaryLeafMapping, ShadowOperation, ShadowQuaternaryTree,
};
use arity_state::{
    hash_canonical_public_bytes, ArityLifecycle, ArityState, MappingHash, TreeCoverHash,
};
use serde::Serialize;
use thiserror::Error;

const TREECOVER_MAGIC: [u8; 4] = *b"AHTC";

/// The sole public authority that a future fork may connect to epoch-secret work.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum EpochSecretAuthority {
    /// The active quaternary tree is the only permitted source.
    ActiveQuaternary,
}

/// A public binary node retained only for TreeCover routing.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct BinaryCoverNode {
    /// Root-relative depth, with the root at zero.
    pub depth: u8,
    /// Left-to-right node ordinal at `depth`.
    pub ordinal: u32,
}

/// A member frozen into the pre-transition binary delivery cover.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TreeCoverMember {
    /// Bytewise-canonical public member identifier.
    pub member_id: Vec<u8>,
    /// Frozen pre-transition binary leaf ordinal.
    pub binary_leaf_index: u32,
    /// Whether delivery through the old cover remains permitted.
    pub eligible: bool,
}

/// Frozen, delivery-only binary routing overlay.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DeliveryOnlyTreeCover {
    version: u32,
    members: Vec<TreeCoverMember>,
}

impl DeliveryOnlyTreeCover {
    /// Freezes every member in the canonical transition mapping as eligible.
    pub fn from_mapping(
        version: u32,
        mapping: &BinaryToQuaternaryLeafMapping,
    ) -> Result<Self, TransitionTreeError> {
        if version == 0 {
            return Err(TransitionTreeError::ZeroTreeCoverVersion);
        }
        mapping.validate()?;
        let cover = Self {
            version,
            members: mapping
                .assignments
                .iter()
                .map(|assignment| TreeCoverMember {
                    member_id: assignment.member_id.clone(),
                    binary_leaf_index: assignment.binary_leaf_index,
                    eligible: true,
                })
                .collect(),
        };
        cover.validate()?;
        Ok(cover)
    }

    /// Returns the immutable TreeCover representation version.
    pub const fn version(&self) -> u32 {
        self.version
    }

    /// Returns the frozen member records in canonical identifier order.
    pub fn members(&self) -> &[TreeCoverMember] {
        &self.members
    }

    /// Returns whether this pre-transition member is currently cover-eligible.
    pub fn is_eligible(&self, member_id: &[u8]) -> bool {
        self.members
            .iter()
            .find(|member| member.member_id == member_id)
            .is_some_and(|member| member.eligible)
    }

    /// Returns whether this member existed before the transition.
    pub fn contains_frozen_member(&self, member_id: &[u8]) -> bool {
        self.members
            .iter()
            .any(|member| member.member_id == member_id)
    }

    /// Returns eligible frozen binary leaf ordinals in ascending order.
    pub fn eligible_binary_leaf_indexes(&self) -> Vec<u32> {
        let mut indexes = self
            .members
            .iter()
            .filter(|member| member.eligible)
            .map(|member| member.binary_leaf_index)
            .collect::<Vec<_>>();
        indexes.sort_unstable();
        indexes
    }

    /// Returns every binary routing node that has at least one eligible member.
    pub fn eligible_routing_nodes(&self) -> Result<Vec<BinaryCoverNode>, TransitionTreeError> {
        let leaves = self.eligible_binary_leaf_indexes();
        if leaves.is_empty() {
            return Ok(Vec::new());
        }
        let height = binary_height(*leaves.last().expect("non-empty leaves"))?;
        let mut nodes = BTreeSet::new();
        for leaf in leaves {
            nodes.insert(BinaryCoverNode {
                depth: 0,
                ordinal: 0,
            });
            for depth in 1..=height {
                let shift = u32::from(height - depth);
                nodes.insert(BinaryCoverNode {
                    depth,
                    ordinal: leaf >> shift,
                });
            }
        }
        Ok(nodes.into_iter().collect())
    }

    /// Returns the number of old-cover routing nodes with eligible members.
    pub fn eligible_node_count(&self) -> Result<usize, TransitionTreeError> {
        Ok(self.eligible_routing_nodes()?.len())
    }

    /// Returns canonical public bytes whose digest binds this exact cover state.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, TransitionTreeError> {
        self.validate()?;
        let count = u32::try_from(self.members.len())
            .map_err(|_| TransitionTreeError::TreeCoverMemberCountOverflow)?;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&TREECOVER_MAGIC);
        bytes.extend_from_slice(&self.version.to_be_bytes());
        bytes.extend_from_slice(&count.to_be_bytes());
        for member in &self.members {
            let member_id_length = u16::try_from(member.member_id.len())
                .map_err(|_| TransitionTreeError::TreeCoverMemberIdTooLong)?;
            bytes.extend_from_slice(&member_id_length.to_be_bytes());
            bytes.extend_from_slice(&member.member_id);
            bytes.extend_from_slice(&member.binary_leaf_index.to_be_bytes());
            bytes.push(u8::from(member.eligible));
        }
        Ok(bytes)
    }

    /// Returns the SHA-256 digest of the canonical public TreeCover state.
    pub fn hash(&self) -> Result<TreeCoverHash, TransitionTreeError> {
        Ok(TreeCoverHash::new(hash_canonical_public_bytes(
            &self.canonical_bytes()?,
        )))
    }

    fn mark_ineligible(&self, member_id: &[u8]) -> Self {
        let mut members = self.members.clone();
        if let Some(member) = members
            .iter_mut()
            .find(|member| member.member_id == member_id)
        {
            member.eligible = false;
        }
        Self {
            version: self.version,
            members,
        }
    }

    fn validate(&self) -> Result<(), TransitionTreeError> {
        if self.version == 0 {
            return Err(TransitionTreeError::ZeroTreeCoverVersion);
        }
        if self.members.is_empty() {
            return Err(TransitionTreeError::EmptyTreeCover);
        }
        for member in &self.members {
            if member.member_id.is_empty() {
                return Err(TransitionTreeError::EmptyTreeCoverMemberId);
            }
        }
        for pair in self.members.windows(2) {
            if pair[0].member_id >= pair[1].member_id {
                return Err(TransitionTreeError::NonCanonicalTreeCoverMembers);
            }
        }
        let mut leaves = self
            .members
            .iter()
            .map(|member| member.binary_leaf_index)
            .collect::<Vec<_>>();
        leaves.sort_unstable();
        if leaves.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(TransitionTreeError::DuplicateTreeCoverLeaf);
        }
        Ok(())
    }
}

/// Public active quaternary topology after a transition.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ActiveQuaternaryTree {
    topology: ShadowQuaternaryTree,
    tree_version: u32,
}

impl ActiveQuaternaryTree {
    /// Creates the active quaternary topology from the frozen transition mapping.
    pub fn from_mapping(
        tree_version: u32,
        mapping: BinaryToQuaternaryLeafMapping,
    ) -> Result<Self, TransitionTreeError> {
        if tree_version == 0 {
            return Err(TransitionTreeError::ZeroActiveTreeVersion);
        }
        Ok(Self {
            topology: ShadowQuaternaryTree::from_mapping(mapping)?,
            tree_version,
        })
    }

    /// Returns the active quaternary arity.
    pub const fn arity(&self) -> u8 {
        self.topology.arity()
    }

    /// Returns the authenticated logical tree version.
    pub const fn tree_version(&self) -> u32 {
        self.tree_version
    }

    /// Returns the only permitted future epoch-secret authority.
    pub const fn epoch_secret_authority(&self) -> EpochSecretAuthority {
        EpochSecretAuthority::ActiveQuaternary
    }

    /// Returns the public active quaternary topology.
    pub const fn topology(&self) -> &ShadowQuaternaryTree {
        &self.topology
    }

    fn replay(&self, operation: ShadowOperation) -> Result<Self, TransitionTreeError> {
        let replay = self.topology.replay(operation)?;
        Ok(Self {
            topology: replay.tree,
            tree_version: self.tree_version,
        })
    }
}

/// A public logical operation applied to the active topology during transition.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub enum TransitionTreeOperation {
    /// Update an existing active member without topology or TreeCover change.
    Update { member_id: Vec<u8> },
    /// Add an active quaternary member with no retroactive TreeCover membership.
    Add { member_id: Vec<u8> },
    /// Remove an active member and revoke old-cover eligibility if it was frozen.
    Remove { member_id: Vec<u8> },
}

/// Public result of replaying one operation against separate transition trees.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TransitionTreeReplay {
    /// The operation replayed.
    pub operation: TransitionTreeOperation,
    /// Whether active quaternary topology changed.
    pub active_topology_changed: bool,
    /// Whether a frozen TreeCover member became ineligible.
    pub treecover_eligibility_changed: bool,
    /// Separate resulting active and delivery-only state.
    pub trees: TransitionTrees,
}

/// Separate active-quaternary and frozen-binary state for one transition version.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TransitionTrees {
    active: ActiveQuaternaryTree,
    treecover: DeliveryOnlyTreeCover,
}

/// One node in an exact disjoint delivery cover.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ExactCoverNode {
    /// Tree arity used to interpret the node coordinate.
    pub arity: u8,
    /// Root-relative depth, with the root at zero.
    pub depth: u8,
    /// Left-to-right node ordinal at this depth.
    pub ordinal: u32,
    /// Active-quaternary recipient leaf ordinals covered by this node.
    pub recipient_quaternary_leaf_ordinals: Vec<u32>,
}

/// Exact topology-derived alternatives for one authenticated recipient set.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ExactRecipientCovers {
    /// Singleton active-tree leaves, one per recipient.
    pub c_leaf: Vec<ExactCoverNode>,
    /// Minimal populated-node cover in the current active quaternary tree.
    pub c_new: Vec<ExactCoverNode>,
    /// Minimal eligible-node cover in the frozen binary TreeCover.
    pub c_old: Vec<ExactCoverNode>,
    /// Minimal cover in the fully populated mature target-arity topology.
    pub c_ideal: Vec<ExactCoverNode>,
}

impl TransitionTrees {
    /// Builds separate trees only from a validated transitioning `ArityState`.
    ///
    /// The state is not considered MLS-authenticated until Task 43 injects it
    /// into a successfully applied GroupContext extension.
    pub fn from_transitioning_state(
        state: &ArityState,
        mapping: BinaryToQuaternaryLeafMapping,
        treecover: DeliveryOnlyTreeCover,
    ) -> Result<Self, TransitionTreeError> {
        state.validate()?;
        let transitioning = match state.lifecycle() {
            ArityLifecycle::Transitioning(value) => value,
            ArityLifecycle::Normal => return Err(TransitionTreeError::StateIsNotTransitioning),
        };
        let mapping_hash =
            MappingHash::new(hash_canonical_public_bytes(&mapping.canonical_bytes()?));
        if mapping_hash != transitioning.mapping_hash() {
            return Err(TransitionTreeError::MappingHashMismatch);
        }
        if treecover.version() != transitioning.treecover().version() {
            return Err(TransitionTreeError::TreeCoverVersionMismatch);
        }
        if treecover.hash()? != transitioning.treecover().hash() {
            return Err(TransitionTreeError::TreeCoverHashMismatch);
        }
        let active = ActiveQuaternaryTree::from_mapping(state.tree_version(), mapping)?;
        if active.arity() != state.active_arity() {
            return Err(TransitionTreeError::ActiveArityMismatch);
        }
        Ok(Self { active, treecover })
    }

    /// Returns the active quaternary topology, the only future secret authority.
    pub const fn active(&self) -> &ActiveQuaternaryTree {
        &self.active
    }

    /// Returns the separate frozen delivery-only binary cover.
    pub const fn treecover(&self) -> &DeliveryOnlyTreeCover {
        &self.treecover
    }

    /// Returns the sole permitted future epoch-secret authority.
    pub const fn epoch_secret_authority(&self) -> EpochSecretAuthority {
        self.active.epoch_secret_authority()
    }

    /// Derives exact, disjoint alternative covers for active-quaternary
    /// recipient leaf ordinals.
    ///
    /// Current-new and ideal covers are equal when every occupied current-tree
    /// node is populated, as in the present full transition mapping. This
    /// function selects nodes only; Task 82 assigns canonical route bytes.
    pub fn exact_recipient_covers(
        &self,
        recipient_quaternary_leaf_ordinals: &[u32],
    ) -> Result<ExactRecipientCovers, TransitionTreeError> {
        let topology = self.active.topology();
        let occupied = topology.occupied_leaf_ordinals();
        let occupied_set = occupied.iter().copied().collect::<BTreeSet<_>>();
        let targets = recipient_quaternary_leaf_ordinals
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        if targets.is_empty() {
            return Err(TransitionTreeError::EmptyRecipientSet);
        }
        if targets.len() != recipient_quaternary_leaf_ordinals.len() {
            return Err(TransitionTreeError::DuplicateRecipientLeaf);
        }
        if !targets.is_subset(&occupied_set) {
            return Err(TransitionTreeError::RecipientOutsideActiveTree);
        }

        let active_members = topology
            .mapping()
            .assignments
            .iter()
            .map(|assignment| {
                (
                    assignment.quaternary_leaf_ordinal,
                    assignment.quaternary_leaf_ordinal,
                )
            })
            .collect::<BTreeMap<_, _>>();
        if active_members.len() != occupied_set.len() {
            return Err(TransitionTreeError::ActiveTopologyMappingIncomplete);
        }
        let c_leaf = targets
            .iter()
            .map(|recipient| ExactCoverNode {
                arity: topology.arity(),
                depth: topology.height(),
                ordinal: *recipient,
                recipient_quaternary_leaf_ordinals: vec![*recipient],
            })
            .collect::<Vec<_>>();
        let c_new = minimal_exact_cover(
            topology.arity(),
            topology.height(),
            &active_members,
            &targets,
        )?;

        let assignment_by_member = topology
            .mapping()
            .assignments
            .iter()
            .map(|assignment| {
                (
                    assignment.member_id.as_slice(),
                    assignment.quaternary_leaf_ordinal,
                )
            })
            .collect::<BTreeMap<_, _>>();
        let mut old_members = BTreeMap::new();
        for member in self
            .treecover
            .members()
            .iter()
            .filter(|member| member.eligible)
        {
            let quaternary_ordinal = assignment_by_member
                .get(member.member_id.as_slice())
                .copied()
                .ok_or(TransitionTreeError::TreeCoverMemberOutsideActiveMapping)?;
            if old_members
                .insert(member.binary_leaf_index, quaternary_ordinal)
                .is_some()
            {
                return Err(TransitionTreeError::DuplicateTreeCoverLeaf);
            }
        }
        let old_target_ordinals = old_members.values().copied().collect::<BTreeSet<_>>();
        if !targets.is_subset(&old_target_ordinals) {
            return Err(TransitionTreeError::RecipientUnavailableInOldTreeCover);
        }
        let old_height = binary_height(
            *old_members
                .keys()
                .next_back()
                .ok_or(TransitionTreeError::RecipientUnavailableInOldTreeCover)?,
        )?;
        let c_old = minimal_exact_cover(2, old_height, &old_members, &targets)?;
        let c_ideal = minimal_exact_cover(
            topology.arity(),
            topology.height(),
            &active_members,
            &targets,
        )?;

        validate_exact_cover(&c_leaf, &targets)?;
        validate_exact_cover(&c_new, &targets)?;
        validate_exact_cover(&c_old, &targets)?;
        validate_exact_cover(&c_ideal, &targets)?;
        Ok(ExactRecipientCovers {
            c_leaf,
            c_new,
            c_old,
            c_ideal,
        })
    }

    /// Replays a public operation without converting TreeCover into an active tree.
    pub fn replay(
        &self,
        operation: TransitionTreeOperation,
    ) -> Result<TransitionTreeReplay, TransitionTreeError> {
        let shadow_operation = match &operation {
            TransitionTreeOperation::Update { member_id } => ShadowOperation::Update {
                member_id: member_id.clone(),
            },
            TransitionTreeOperation::Add { member_id } => ShadowOperation::Add {
                member_id: member_id.clone(),
            },
            TransitionTreeOperation::Remove { member_id } => ShadowOperation::Remove {
                member_id: member_id.clone(),
            },
        };
        let active = self.active.replay(shadow_operation)?;
        let (treecover, treecover_eligibility_changed) = match &operation {
            TransitionTreeOperation::Remove { member_id }
                if self.treecover.is_eligible(member_id) =>
            {
                (self.treecover.mark_ineligible(member_id), true)
            }
            _ => (self.treecover.clone(), false),
        };
        Ok(TransitionTreeReplay {
            active_topology_changed: !matches!(operation, TransitionTreeOperation::Update { .. }),
            operation,
            treecover_eligibility_changed,
            trees: Self { active, treecover },
        })
    }
}

/// Errors from constructing or replaying separate transition-tree state.
#[derive(Debug, Error, Eq, PartialEq)]
pub enum TransitionTreeError {
    /// The source deterministic mapping was invalid.
    #[error("the deterministic leaf mapping is invalid")]
    AdaptiveTree(#[from] AdaptiveTreeError),
    /// The supplied public ArityState was invalid.
    #[error("the ArityState is invalid")]
    ArityState(#[from] arity_state::ArityStateError),
    /// TreeCover version zero is not a versioned frozen cover.
    #[error("the TreeCover version must be positive")]
    ZeroTreeCoverVersion,
    /// A frozen cover must start from at least one mapped member.
    #[error("the TreeCover cannot be empty")]
    EmptyTreeCover,
    /// A frozen cover member identifier is empty.
    #[error("a TreeCover member identifier is empty")]
    EmptyTreeCoverMemberId,
    /// Frozen members must be strictly bytewise canonical.
    #[error("TreeCover members are not in canonical order")]
    NonCanonicalTreeCoverMembers,
    /// More than one frozen member used the same binary leaf.
    #[error("a TreeCover binary leaf occurs more than once")]
    DuplicateTreeCoverLeaf,
    /// A member identifier cannot fit the project-local canonical encoding.
    #[error("a TreeCover member identifier exceeds the supported length")]
    TreeCoverMemberIdTooLong,
    /// The frozen member count exceeds the supported canonical representation.
    #[error("the TreeCover member count exceeds the supported range")]
    TreeCoverMemberCountOverflow,
    /// The binary cover height cannot fit the public node representation.
    #[error("the TreeCover binary height exceeds the supported range")]
    BinaryCoverHeightOverflow,
    /// Active quaternary state must carry a non-zero logical tree version.
    #[error("the active quaternary tree version must be positive")]
    ZeroActiveTreeVersion,
    /// Separate transition trees require a transitioning state.
    #[error("the ArityState is not transitioning")]
    StateIsNotTransitioning,
    /// The supplied mapping differs from the mapping digest in ArityState.
    #[error("the deterministic mapping hash does not match ArityState")]
    MappingHashMismatch,
    /// The supplied TreeCover version differs from ArityState.
    #[error("the TreeCover version does not match ArityState")]
    TreeCoverVersionMismatch,
    /// The supplied TreeCover contents differ from ArityState.
    #[error("the TreeCover hash does not match ArityState")]
    TreeCoverHashMismatch,
    /// The reconstructed active topology has an unexpected arity.
    #[error("the active quaternary tree arity does not match ArityState")]
    ActiveArityMismatch,
    /// A cost alternative needs at least one recipient.
    #[error("an exact cover requires a non-empty recipient set")]
    EmptyRecipientSet,
    /// Recipient leaf ordinals must be unique.
    #[error("an exact cover recipient leaf occurs more than once")]
    DuplicateRecipientLeaf,
    /// A recipient does not occupy the authenticated active topology.
    #[error("an exact cover recipient is outside the active tree")]
    RecipientOutsideActiveTree,
    /// The active topology's public mapping does not describe every occupant.
    #[error("the active topology mapping is incomplete")]
    ActiveTopologyMappingIncomplete,
    /// An eligible old-cover member is not present in the active mapping.
    #[error("an eligible TreeCover member is outside the active mapping")]
    TreeCoverMemberOutsideActiveMapping,
    /// At least one recipient cannot be reached through the eligible old cover.
    #[error("a recipient is unavailable in the eligible old TreeCover")]
    RecipientUnavailableInOldTreeCover,
    /// Cover arithmetic exceeded the supported public index range.
    #[error("exact cover topology arithmetic overflowed")]
    ExactCoverOverflow,
    /// An internally derived cover did not cover every target exactly once.
    #[error("an exact cover failed its disjoint recipient invariant")]
    InvalidExactCover,
}

fn minimal_exact_cover(
    arity: u8,
    height: u8,
    occupied_leaf_to_recipient: &BTreeMap<u32, u32>,
    targets: &BTreeSet<u32>,
) -> Result<Vec<ExactCoverNode>, TransitionTreeError> {
    let mut cover = Vec::new();
    select_cover_node(
        arity,
        height,
        0,
        0,
        occupied_leaf_to_recipient,
        targets,
        &mut cover,
    )?;
    Ok(cover)
}

fn select_cover_node(
    arity: u8,
    height: u8,
    depth: u8,
    ordinal: u32,
    occupied_leaf_to_recipient: &BTreeMap<u32, u32>,
    targets: &BTreeSet<u32>,
    cover: &mut Vec<ExactCoverNode>,
) -> Result<(), TransitionTreeError> {
    let remaining_depth = height
        .checked_sub(depth)
        .ok_or(TransitionTreeError::ExactCoverOverflow)?;
    let width = u32::from(arity)
        .checked_pow(u32::from(remaining_depth))
        .ok_or(TransitionTreeError::ExactCoverOverflow)?;
    let start = ordinal
        .checked_mul(width)
        .ok_or(TransitionTreeError::ExactCoverOverflow)?;
    let end = start
        .checked_add(width)
        .ok_or(TransitionTreeError::ExactCoverOverflow)?;
    let descendants = occupied_leaf_to_recipient
        .range(start..end)
        .map(|(_, recipient)| *recipient)
        .collect::<Vec<_>>();
    if descendants.is_empty() {
        return Ok(());
    }
    if descendants
        .iter()
        .all(|recipient| targets.contains(recipient))
    {
        cover.push(ExactCoverNode {
            arity,
            depth,
            ordinal,
            recipient_quaternary_leaf_ordinals: descendants,
        });
        return Ok(());
    }
    if depth == height {
        return Ok(());
    }
    let child_depth = depth
        .checked_add(1)
        .ok_or(TransitionTreeError::ExactCoverOverflow)?;
    for branch in 0..u32::from(arity) {
        let child_ordinal = ordinal
            .checked_mul(u32::from(arity))
            .and_then(|value| value.checked_add(branch))
            .ok_or(TransitionTreeError::ExactCoverOverflow)?;
        select_cover_node(
            arity,
            height,
            child_depth,
            child_ordinal,
            occupied_leaf_to_recipient,
            targets,
            cover,
        )?;
    }
    Ok(())
}

fn validate_exact_cover(
    cover: &[ExactCoverNode],
    targets: &BTreeSet<u32>,
) -> Result<(), TransitionTreeError> {
    let mut observed = BTreeSet::new();
    for node in cover {
        if node.recipient_quaternary_leaf_ordinals.is_empty() {
            return Err(TransitionTreeError::InvalidExactCover);
        }
        for recipient in &node.recipient_quaternary_leaf_ordinals {
            if !observed.insert(*recipient) {
                return Err(TransitionTreeError::InvalidExactCover);
            }
        }
    }
    if &observed != targets {
        return Err(TransitionTreeError::InvalidExactCover);
    }
    Ok(())
}

fn binary_height(max_leaf_index: u32) -> Result<u8, TransitionTreeError> {
    let required = u64::from(max_leaf_index) + 1;
    let mut capacity = 1_u64;
    let mut height = 0_u8;
    while capacity < required {
        capacity = capacity
            .checked_mul(2)
            .ok_or(TransitionTreeError::BinaryCoverHeightOverflow)?;
        height = height
            .checked_add(1)
            .ok_or(TransitionTreeError::BinaryCoverHeightOverflow)?;
    }
    Ok(height)
}

#[cfg(test)]
mod tests {
    use super::*;
    use adaptive_tree::{BinaryLeafMember, ShadowQuaternaryTree};
    use arity_state::{ArityPolicySnapshot, TransitionEvaluationState, TreeCoverBinding};
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
                binary_leaf_index: 2,
            },
        ])
        .expect("canonical mapping")
    }

    fn triggered_state(
        mapping: &BinaryToQuaternaryLeafMapping,
        treecover: &DeliveryOnlyTreeCover,
    ) -> ArityState {
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
            .expect("resolved Delta");
        let window_config = PolicyWindowConfig::new(20, 0, 1).expect("window config");
        let start_config = TransitionStartConfig::new(2, 4, 128, 1, 25).expect("start config");
        let policy = ArityPolicySnapshot::from_policy_inputs(window_config, start_config, delta)
            .expect("policy snapshot");
        let normal = ArityState::normal(2, 4, 0, policy, TransitionEvaluationState::new(7, 0, 0))
            .expect("normal state");
        let mut window = PolicyWindow::new(window_config);
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
        let mut evaluator = TransitionStartEvaluator::new(start_config);
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
        normal
            .begin_transition(
                &evaluation,
                window.q_e(),
                MappingHash::new(hash_canonical_public_bytes(
                    &mapping.canonical_bytes().expect("mapping bytes"),
                )),
                TreeCoverBinding::new(treecover.version(), treecover.hash().expect("cover hash"))
                    .expect("TreeCover binding"),
            )
            .expect("transition state")
    }

    fn trees() -> TransitionTrees {
        let mapping = mapping();
        let treecover = DeliveryOnlyTreeCover::from_mapping(1, &mapping).expect("TreeCover");
        let state = triggered_state(&mapping, &treecover);
        TransitionTrees::from_transitioning_state(&state, mapping, treecover)
            .expect("separate transition trees")
    }

    fn full_64_trees() -> TransitionTrees {
        let mapping = BinaryToQuaternaryLeafMapping::from_binary_members(
            (0..64)
                .map(|index| BinaryLeafMember {
                    member_id: format!("member-{index:02}").into_bytes(),
                    binary_leaf_index: index,
                })
                .collect(),
        )
        .expect("full canonical mapping");
        let treecover = DeliveryOnlyTreeCover::from_mapping(1, &mapping).expect("full TreeCover");
        let state = triggered_state(&mapping, &treecover);
        TransitionTrees::from_transitioning_state(&state, mapping, treecover)
            .expect("full transition trees")
    }

    #[test]
    fn transition_trees_bind_separate_public_states_and_one_secret_authority() {
        let trees = trees();
        assert_eq!(trees.active().arity(), 4);
        assert_eq!(trees.active().tree_version(), 1);
        assert_eq!(trees.active().topology().occupied_leaf_count(), 2);
        assert_eq!(
            trees.epoch_secret_authority(),
            EpochSecretAuthority::ActiveQuaternary
        );
        assert_eq!(trees.treecover().eligible_binary_leaf_indexes(), vec![0, 2]);
        assert_eq!(trees.treecover().eligible_node_count(), Ok(5));
    }

    #[test]
    fn full_64_tree_minus_committer_has_exact_minimal_covers() {
        let trees = full_64_trees();
        let recipients = (0..64).filter(|ordinal| *ordinal != 2).collect::<Vec<_>>();
        let covers = trees
            .exact_recipient_covers(&recipients)
            .expect("exact recipient covers");

        assert_eq!(covers.c_leaf.len(), 63);
        assert_eq!(covers.c_new.len(), 9);
        assert_eq!(covers.c_old.len(), 6);
        assert_eq!(covers.c_ideal.len(), 9);
        assert_eq!(covers.c_new, covers.c_ideal);
        for cover in [
            &covers.c_leaf,
            &covers.c_new,
            &covers.c_old,
            &covers.c_ideal,
        ] {
            let flattened = cover
                .iter()
                .flat_map(|node| node.recipient_quaternary_leaf_ordinals.iter().copied())
                .collect::<BTreeSet<_>>();
            assert_eq!(flattened, recipients.iter().copied().collect());
            assert!(cover
                .iter()
                .all(|node| { !node.recipient_quaternary_leaf_ordinals.contains(&2) }));
        }
    }

    #[test]
    fn exact_cover_rejects_empty_duplicate_and_unknown_recipients() {
        let trees = full_64_trees();
        assert_eq!(
            trees.exact_recipient_covers(&[]),
            Err(TransitionTreeError::EmptyRecipientSet)
        );
        assert_eq!(
            trees.exact_recipient_covers(&[1, 1]),
            Err(TransitionTreeError::DuplicateRecipientLeaf)
        );
        assert_eq!(
            trees.exact_recipient_covers(&[64]),
            Err(TransitionTreeError::RecipientOutsideActiveTree)
        );
    }

    #[test]
    fn additions_never_join_treecover_and_removals_revoke_only_frozen_eligibility() {
        let initial = trees();
        let added = initial
            .replay(TransitionTreeOperation::Add {
                member_id: b"charlie".to_vec(),
            })
            .expect("add replay");
        assert!(added.active_topology_changed);
        assert!(!added.treecover_eligibility_changed);
        assert_eq!(added.trees.active().topology().occupied_leaf_count(), 3);
        assert!(!added.trees.treecover().contains_frozen_member(b"charlie"));

        let removed_frozen = added
            .trees
            .replay(TransitionTreeOperation::Remove {
                member_id: b"alice".to_vec(),
            })
            .expect("remove frozen replay");
        assert!(removed_frozen.active_topology_changed);
        assert!(removed_frozen.treecover_eligibility_changed);
        assert!(!removed_frozen.trees.treecover().is_eligible(b"alice"));
        assert_eq!(
            removed_frozen
                .trees
                .treecover()
                .eligible_binary_leaf_indexes(),
            vec![2]
        );

        let removed_added = removed_frozen
            .trees
            .replay(TransitionTreeOperation::Remove {
                member_id: b"charlie".to_vec(),
            })
            .expect("remove added replay");
        assert!(!removed_added.treecover_eligibility_changed);
        assert_eq!(
            removed_added
                .trees
                .treecover()
                .eligible_binary_leaf_indexes(),
            vec![2]
        );
    }

    #[test]
    fn state_binding_rejects_different_mapping_cover_and_non_transitioning_state() {
        let mapping = mapping();
        let cover = DeliveryOnlyTreeCover::from_mapping(1, &mapping).expect("cover");
        let state = triggered_state(&mapping, &cover);
        let changed_mapping = BinaryToQuaternaryLeafMapping::from_binary_members(vec![
            BinaryLeafMember {
                member_id: b"alice".to_vec(),
                binary_leaf_index: 0,
            },
            BinaryLeafMember {
                member_id: b"bob".to_vec(),
                binary_leaf_index: 1,
            },
        ])
        .expect("different mapping");
        assert_eq!(
            TransitionTrees::from_transitioning_state(&state, changed_mapping, cover.clone()),
            Err(TransitionTreeError::MappingHashMismatch)
        );

        let changed_cover = DeliveryOnlyTreeCover::from_mapping(2, &mapping).expect("other cover");
        assert_eq!(
            TransitionTrees::from_transitioning_state(&state, mapping.clone(), changed_cover),
            Err(TransitionTreeError::TreeCoverVersionMismatch)
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
            TransitionTrees::from_transitioning_state(&normal, mapping, cover),
            Err(TransitionTreeError::StateIsNotTransitioning)
        );
    }

    #[test]
    fn treecover_canonical_bytes_change_with_eligibility_without_changing_version() {
        let initial = trees();
        let before = initial.treecover().hash().expect("before hash");
        let removed = initial
            .replay(TransitionTreeOperation::Remove {
                member_id: b"bob".to_vec(),
            })
            .expect("remove replay");
        assert_eq!(removed.trees.treecover().version(), 1);
        assert_ne!(
            removed.trees.treecover().hash().expect("after hash"),
            before
        );
        assert_eq!(
            removed.trees.active().epoch_secret_authority(),
            EpochSecretAuthority::ActiveQuaternary
        );

        let shadow = ShadowQuaternaryTree::from_mapping(mapping()).expect("shadow topology");
        assert_eq!(shadow.arity(), removed.trees.active().arity());
    }
}
