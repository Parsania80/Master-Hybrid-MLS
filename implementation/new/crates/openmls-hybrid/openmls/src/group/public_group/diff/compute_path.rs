use std::collections::HashSet;

#[cfg(feature = "experimental-hybrid")]
use std::collections::{BTreeMap, BTreeSet};

use openmls_traits::{crypto::OpenMlsCrypto, random::OpenMlsRand, signatures::Signer};
use serde::{Deserialize, Serialize};
use tls_codec::Serialize as _;

#[cfg(feature = "experimental-hybrid")]
use crate::treesync::node::parent_node::ExperimentalQuaternaryParentPosition;
use crate::{
    binary_tree::LeafNodeIndex,
    ciphersuite::Secret,
    credentials::CredentialWithKey,
    error::LibraryError,
    extensions::Extensions,
    group::{errors::CreateCommitError, GroupContext},
    messages::PathSecret,
    schedule::CommitSecret,
    treesync::{
        node::{
            encryption_keys::EncryptionKeyPair,
            leaf_node::{Capabilities, LeafNodeParameters, UpdateLeafNodeParams},
            parent_node::PlainUpdatePathNode,
        },
        treekem::UpdatePath,
    },
};
#[cfg(feature = "experimental-hybrid")]
use adaptive_tree::BinaryToQuaternaryLeafMapping;
#[cfg(feature = "experimental-hybrid")]
use arity_state::{ArityLifecycle, ArityState};

use super::PublicGroupDiff;

#[cfg(feature = "experimental-hybrid")]
const OLD_TREECOVER_RECIPIENT_FLAG: u32 = 0x8000_0000;

#[cfg(feature = "experimental-hybrid")]
fn frozen_binary_height(mapping: &BinaryToQuaternaryLeafMapping) -> Result<u8, LibraryError> {
    let max_leaf = mapping
        .assignments
        .iter()
        .map(|assignment| assignment.binary_leaf_index)
        .max()
        .ok_or_else(|| LibraryError::custom("frozen transition mapping is empty"))?;
    let mut height = 0_u8;
    let mut capacity = 1_u32;
    while capacity <= max_leaf {
        capacity = capacity
            .checked_mul(2)
            .ok_or_else(|| LibraryError::custom("binary TreeCover capacity overflow"))?;
        height = height
            .checked_add(1)
            .ok_or_else(|| LibraryError::custom("binary TreeCover height overflow"))?;
    }
    Ok(height)
}

#[cfg(feature = "experimental-hybrid")]
fn frozen_binary_parent_index(
    height: u8,
    depth: u8,
    ordinal: u32,
) -> Result<Option<u32>, LibraryError> {
    if depth >= height {
        return Ok(None);
    }
    let level = height
        .checked_sub(depth)
        .ok_or_else(|| LibraryError::custom("binary TreeCover depth underflow"))?;
    let stride = 1_u32
        .checked_shl(u32::from(level) + 1)
        .ok_or_else(|| LibraryError::custom("binary TreeCover stride overflow"))?;
    let offset = 1_u32
        .checked_shl(u32::from(level))
        .and_then(|value| value.checked_sub(1))
        .ok_or_else(|| LibraryError::custom("binary TreeCover offset overflow"))?;
    let tree_index = ordinal
        .checked_mul(stride)
        .and_then(|value| value.checked_add(offset))
        .ok_or_else(|| LibraryError::custom("binary TreeCover index overflow"))?;
    tree_index
        .checked_sub(1)
        .map(|index| Some(index / 2))
        .ok_or_else(|| LibraryError::custom("binary TreeCover parent index underflow"))
}

#[cfg(feature = "experimental-hybrid")]
#[allow(clippy::too_many_arguments)]
fn append_old_treecover_recipients(
    height: u8,
    depth: u8,
    ordinal: u32,
    frozen_binary_to_quaternary: &BTreeMap<u32, u32>,
    target_quaternary_leaves: &BTreeSet<u32>,
    old_public_nodes: &BTreeMap<u32, crate::treesync::node::encryption_keys::EncryptionKey>,
    leaf_public_keys: &BTreeMap<u32, crate::treesync::node::encryption_keys::EncryptionKey>,
    recipients: &mut Vec<(u32, crate::treesync::node::encryption_keys::EncryptionKey)>,
) -> Result<(), LibraryError> {
    let remaining = height
        .checked_sub(depth)
        .ok_or_else(|| LibraryError::custom("binary TreeCover depth exceeds height"))?;
    let width = 1_u32
        .checked_shl(u32::from(remaining))
        .ok_or_else(|| LibraryError::custom("binary TreeCover width overflow"))?;
    let start = ordinal
        .checked_mul(width)
        .ok_or_else(|| LibraryError::custom("binary TreeCover range overflow"))?;
    let end = start
        .checked_add(width)
        .ok_or_else(|| LibraryError::custom("binary TreeCover range overflow"))?;
    let descendants = frozen_binary_to_quaternary
        .range(start..end)
        .map(|(_, quaternary_leaf)| *quaternary_leaf)
        .collect::<Vec<_>>();
    let targeted = descendants
        .iter()
        .filter(|leaf| target_quaternary_leaves.contains(leaf))
        .count();
    if targeted == 0 {
        return Ok(());
    }

    if targeted == descendants.len() {
        if let Some(parent_index) = frozen_binary_parent_index(height, depth, ordinal)? {
            if let Some(public_key) = old_public_nodes.get(&parent_index) {
                if depth > 0x7f || ordinal > 0x00ff_ffff {
                    return Err(LibraryError::custom(
                        "binary TreeCover recipient coordinate is not encodable",
                    ));
                }
                recipients.push((
                    OLD_TREECOVER_RECIPIENT_FLAG | (u32::from(depth) << 24) | ordinal,
                    public_key.clone(),
                ));
                return Ok(());
            }
        }
    }

    if depth == height {
        let quaternary_leaf = frozen_binary_to_quaternary
            .get(&ordinal)
            .copied()
            .ok_or_else(|| LibraryError::custom("binary TreeCover leaf is not mapped"))?;
        let public_key = leaf_public_keys
            .get(&quaternary_leaf)
            .cloned()
            .ok_or_else(|| LibraryError::custom("active fallback leaf key is unavailable"))?;
        recipients.push((quaternary_leaf, public_key));
        return Ok(());
    }

    let child_depth = depth
        .checked_add(1)
        .ok_or_else(|| LibraryError::custom("binary TreeCover child depth overflow"))?;
    for branch in 0..2_u32 {
        let child_ordinal = ordinal
            .checked_mul(2)
            .and_then(|value| value.checked_add(branch))
            .ok_or_else(|| LibraryError::custom("binary TreeCover child ordinal overflow"))?;
        append_old_treecover_recipients(
            height,
            child_depth,
            child_ordinal,
            frozen_binary_to_quaternary,
            target_quaternary_leaves,
            old_public_nodes,
            leaf_public_keys,
            recipients,
        )?;
    }
    Ok(())
}

/// Can be used to denote the type of a commit.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) enum CommitType {
    External(CredentialWithKey),
    Member,
}

/// A helper struct which contains the values resulting from the preparation of
/// a commit with path.
#[derive(Default)]
pub(crate) struct PathComputationResult {
    pub(crate) commit_secret: Option<CommitSecret>,
    pub(crate) encrypted_path: Option<UpdatePath>,
    pub(crate) plain_path: Option<Vec<PlainUpdatePathNode>>,
    pub(crate) new_keypairs: Vec<EncryptionKeyPair>,
    /// Matched private material for the feature-gated quaternary root. It is
    /// persisted in `GroupEpochSecrets`, not the binary TreeKEM key list.
    #[cfg(feature = "experimental-hybrid")]
    pub(crate) experimental_quaternary_parent_keypairs: Vec<EncryptionKeyPair>,
    #[cfg(feature = "experimental-hybrid")]
    pub(crate) experimental_quaternary_parent_public_nodes: Vec<(
        u8,
        u32,
        crate::treesync::node::encryption_keys::EncryptionKey,
    )>,
}

impl PublicGroupDiff<'_> {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn compute_path(
        &mut self,
        rand: &impl OpenMlsRand,
        crypto: &impl OpenMlsCrypto,
        leaf_index: LeafNodeIndex,
        exclusion_list: HashSet<&LeafNodeIndex>,
        commit_type: &CommitType,
        leaf_node_params: &LeafNodeParameters,
        signer: &impl Signer,
        gc_extensions: Option<Extensions<GroupContext>>,
        #[cfg(feature = "experimental-hybrid")] frozen_transition_mapping: Option<
            &BinaryToQuaternaryLeafMapping,
        >,
        #[cfg(feature = "experimental-hybrid")] _retained_quaternary_public_nodes: &[(
            u8,
            u32,
            crate::treesync::node::encryption_keys::EncryptionKey,
        )],
        #[cfg(feature = "experimental-hybrid")] retained_old_treecover_public_nodes: &[(
            u32,
            crate::treesync::node::encryption_keys::EncryptionKey,
        )],
    ) -> Result<PathComputationResult, CreateCommitError> {
        let ciphersuite = self.group_context().ciphersuite();
        #[cfg(feature = "experimental-hybrid")]
        let prior_experimental_arity_state = self
            .group_context()
            .extensions()
            .unknown(crate::experimental_hybrid::ADAPTIVE_HYBRID_TREE_STATE_EXTENSION_TYPE)
            .and_then(|extension| ArityState::from_extension_value(&extension.0).ok());
        #[cfg(feature = "experimental-hybrid")]
        let prior_group_context = self
            .group_context()
            .tls_serialize_detached()
            .map_err(LibraryError::missing_bound_check)?;

        let leaf_node_params = if let CommitType::External(credential_with_key) = commit_type {
            let capabilities = match leaf_node_params.capabilities() {
                Some(c) => c.to_owned(),
                None => Capabilities::default(),
            };

            let extensions = match leaf_node_params.extensions() {
                Some(e) => e.to_owned(),
                None => Extensions::default(),
            };

            UpdateLeafNodeParams {
                credential_with_key: credential_with_key.clone(),
                capabilities,
                extensions,
            }
        } else {
            let leaf = self
                .diff
                .leaf(leaf_index)
                .ok_or_else(|| LibraryError::custom("Couldn't find own leaf"))?;

            let credential_with_key = match leaf_node_params.credential_with_key() {
                Some(cwk) => cwk.to_owned(),
                None => CredentialWithKey {
                    credential: leaf.credential().clone(),
                    signature_key: leaf.signature_key().clone(),
                },
            };

            let capabilities = match leaf_node_params.capabilities() {
                Some(c) => c.to_owned(),
                None => leaf.capabilities().clone(),
            };

            let extensions = match leaf_node_params.extensions() {
                Some(e) => e.to_owned(),
                None => leaf.extensions().clone(),
            };

            UpdateLeafNodeParams {
                credential_with_key,
                capabilities,
                extensions,
            }
        };

        // Once a transition has been installed, the quaternary tree is the
        // path and key-schedule authority.  The transition-start Commit itself
        // remains binary so it can install the frozen mapping and old-tree
        // delivery envelope atomically.
        #[cfg(feature = "experimental-hybrid")]
        if let Some(arity_state) = prior_experimental_arity_state
            .as_ref()
            .filter(|state| matches!(state.lifecycle(), ArityLifecycle::Transitioning(_)))
        {
            let mapping = frozen_transition_mapping.ok_or_else(|| {
                LibraryError::custom(
                    "native quaternary authority requires the frozen transition mapping",
                )
            })?;
            let delivery_plan = self.experimental_quaternary_delivery_plan(
                leaf_index,
                leaf_index,
                arity_state,
                Some(mapping),
            )?;
            if delivery_plan.parent_nodes.is_empty() {
                return Err(LibraryError::custom(
                    "native quaternary authority requires a non-empty direct path",
                )
                .into());
            }
            let domain = self
                .diff
                .leaf(leaf_index)
                .and_then(|leaf| leaf.encryption_key().experimental_mkyber_key())
                .map(|key| key.domain())
                .ok_or_else(|| {
                    LibraryError::custom("native quaternary sender lacks an mKyber leaf key")
                })?;

            // Start at the leaf-side parent and derive upward.  The stored
            // ordering is root-to-leaf to match the authenticated topology.
            let mut leaf_to_root = Vec::with_capacity(delivery_plan.parent_nodes.len());
            let mut next_secret = PathSecret::from(
                Secret::random(ciphersuite, rand).map_err(LibraryError::unexpected_crypto_error)?,
            );
            for path_index in 0..delivery_plan.parent_nodes.len() {
                let current_secret = next_secret;
                next_secret = if path_index + 1 < delivery_plan.parent_nodes.len() {
                    current_secret.derive_path_secret(crypto, ciphersuite)?
                } else {
                    // This value is the CommitSecret source immediately above
                    // the quaternary root.
                    current_secret.derive_path_secret(crypto, ciphersuite)?
                };
                leaf_to_root.push(current_secret);
            }
            leaf_to_root.reverse();
            let commit_secret: CommitSecret = next_secret.into();

            let mut native_plain_path = Vec::with_capacity(delivery_plan.parent_nodes.len());
            let mut experimental_quaternary_parent_keypairs =
                Vec::with_capacity(delivery_plan.parent_nodes.len());
            for (parent, path_secret) in
                delivery_plan.parent_nodes.iter().copied().zip(leaf_to_root)
            {
                let keypair = path_secret.derive_experimental_quaternary_parent_keypair(
                    crypto,
                    ciphersuite,
                    domain,
                    arity_state.tree_version(),
                    parent.depth,
                    parent.ordinal,
                )?;
                native_plain_path.push(PlainUpdatePathNode::native_quaternary(
                    keypair.public_key().clone(),
                    path_secret,
                ));
                experimental_quaternary_parent_keypairs.push(keypair);
            }

            let provisional_parent_paths = delivery_plan
                .parent_nodes
                .iter()
                .zip(&experimental_quaternary_parent_keypairs)
                .map(|(parent, keypair)| {
                    crate::treesync::treekem::ExperimentalQuaternaryParentPath::new(
                        arity_state.tree_version(),
                        parent.depth,
                        parent.ordinal,
                        keypair.public_key().clone(),
                        Vec::new(),
                    )
                })
                .collect::<Vec<_>>();
            let quaternary_parent_hash = crate::experimental_hybrid::quaternary_path_parent_hash(
                crypto,
                ciphersuite,
                &provisional_parent_paths,
            )?;
            let leaf_keypair = self.diff.apply_own_quaternary_update_leaf(
                rand,
                crypto,
                signer,
                ciphersuite,
                commit_type,
                self.group_context().group_id().clone(),
                leaf_index,
                leaf_node_params,
                &quaternary_parent_hash,
            )?;
            let leaf_node = self
                .diff
                .leaf(leaf_index)
                .ok_or_else(|| LibraryError::custom("Couldn't find own quaternary leaf"))?
                .clone();
            let mut encrypted_path = UpdatePath::new(leaf_node, Vec::new());
            encrypted_path.set_experimental_quaternary_parent_paths(provisional_parent_paths);
            self.update_group_context_with_quaternary_authority(
                crypto,
                gc_extensions,
                mapping,
                _retained_quaternary_public_nodes,
                &encrypted_path,
            )?;
            let serialized_group_context = self
                .group_context()
                .tls_serialize_detached()
                .map_err(LibraryError::missing_bound_check)?;
            let retirement_uses_prior_context = self
                .group_context()
                .extensions()
                .unknown(crate::experimental_hybrid::ADAPTIVE_HYBRID_TREE_STATE_EXTENSION_TYPE)
                .and_then(|extension| ArityState::from_extension_value(&extension.0).ok())
                .is_some_and(|state| matches!(state.lifecycle(), ArityLifecycle::Normal));
            let hybrid_group_context = if retirement_uses_prior_context {
                &prior_group_context
            } else {
                &serialized_group_context
            };

            // Prefer prior-epoch quaternary sibling resolutions. Until those
            // are populated, use the retained old binary TreeCover, splitting
            // unavailable or unsafe nodes down to active leaf recipients. The
            // fallback affects neither the authority hash nor CommitSecret.
            let healthy_parent_delivery = _retained_quaternary_public_nodes.len()
                >= delivery_plan.occupied_parent_node_count
                && delivery_plan
                    .recipient_targets
                    .iter()
                    .all(|(_, _, resolution_node, _)| {
                        resolution_node.depth == delivery_plan.parent_nodes.len() as u8
                            || _retained_quaternary_public_nodes.iter().any(
                                |(depth, ordinal, _)| {
                                    (*depth, *ordinal)
                                        == (resolution_node.depth, resolution_node.ordinal)
                                },
                            )
                    });
            let frozen_binary_height = frozen_binary_height(mapping)?;
            let frozen_binary_to_quaternary = mapping
                .assignments
                .iter()
                .map(|assignment| {
                    (
                        assignment.binary_leaf_index,
                        assignment.quaternary_leaf_ordinal,
                    )
                })
                .collect::<BTreeMap<_, _>>();
            let old_public_nodes = retained_old_treecover_public_nodes
                .iter()
                .cloned()
                .collect::<BTreeMap<_, _>>();
            let leaf_public_keys = delivery_plan
                .recipient_targets
                .iter()
                .map(|(leaf_ordinal, _, _, public_key)| (*leaf_ordinal, public_key.clone()))
                .collect::<BTreeMap<_, _>>();
            let mut parent_paths = Vec::with_capacity(delivery_plan.parent_nodes.len());
            for ((parent, plain_node), expected_keypair) in delivery_plan
                .parent_nodes
                .iter()
                .copied()
                .zip(&native_plain_path)
                .zip(&experimental_quaternary_parent_keypairs)
            {
                let mut recipients = Vec::new();
                if healthy_parent_delivery {
                    for (leaf_ordinal, sender_parent, resolution_node, leaf_key) in
                        &delivery_plan.recipient_targets
                    {
                        if *sender_parent != parent {
                            continue;
                        }
                        let retained_resolution =
                            _retained_quaternary_public_nodes
                                .iter()
                                .find(|(depth, ordinal, _)| {
                                    (*depth, *ordinal)
                                        == (resolution_node.depth, resolution_node.ordinal)
                                });
                        let (recipient_index, recipient_key) =
                            if let Some((depth, ordinal, public_key)) = retained_resolution {
                                (
                                    crate::experimental_hybrid::quaternary_parent_node_index(
                                        *depth, *ordinal,
                                    )?,
                                    public_key.clone(),
                                )
                            } else {
                                (*leaf_ordinal, leaf_key.clone())
                            };
                        if !recipients
                            .iter()
                            .any(|(index, _)| *index == recipient_index)
                        {
                            recipients.push((recipient_index, recipient_key));
                        }
                    }
                } else {
                    let target_quaternary_leaves = delivery_plan
                        .recipient_targets
                        .iter()
                        .filter(|(_, sender_parent, _, _)| *sender_parent == parent)
                        .map(|(leaf_ordinal, _, _, _)| *leaf_ordinal)
                        .collect::<BTreeSet<_>>();
                    append_old_treecover_recipients(
                        frozen_binary_height,
                        0,
                        0,
                        &frozen_binary_to_quaternary,
                        &target_quaternary_leaves,
                        &old_public_nodes,
                        &leaf_public_keys,
                        &mut recipients,
                    )?;
                }
                recipients.sort_unstable_by_key(|(recipient_index, _)| *recipient_index);
                if recipients.windows(2).any(|pair| pair[0].0 == pair[1].0) {
                    return Err(LibraryError::custom(
                        "native quaternary delivery contains a duplicate recipient",
                    )
                    .into());
                }
                let position = ExperimentalQuaternaryParentPosition {
                    tree_version: arity_state.tree_version(),
                    depth: parent.depth,
                    ordinal: parent.ordinal,
                    domain,
                };
                if recipients.is_empty() {
                    parent_paths.push(
                        crate::treesync::treekem::ExperimentalQuaternaryParentPath::new(
                            position.tree_version,
                            position.depth,
                            position.ordinal,
                            expected_keypair.public_key().clone(),
                            Vec::new(),
                        ),
                    );
                    continue;
                }
                let (parent_path, keypair) = plain_node
                    .encrypt_experimental_quaternary_parent_from_secret(
                        crypto,
                        ciphersuite,
                        &recipients,
                        hybrid_group_context,
                        position,
                        plain_node.path_secret(),
                    )?;
                if keypair.public_key() != expected_keypair.public_key() {
                    return Err(LibraryError::custom(
                        "native quaternary path public/private derivation mismatch",
                    )
                    .into());
                }
                parent_paths.push(parent_path);
            }
            encrypted_path.set_experimental_quaternary_parent_paths(parent_paths);
            let experimental_quaternary_parent_public_nodes = delivery_plan
                .parent_nodes
                .iter()
                .zip(&experimental_quaternary_parent_keypairs)
                .map(|(node, keypair)| (node.depth, node.ordinal, keypair.public_key().clone()))
                .collect();
            return Ok(PathComputationResult {
                commit_secret: Some(commit_secret),
                encrypted_path: Some(encrypted_path),
                // Native quaternary Add is intentionally not enabled by the
                // frozen mapping, so no MLS Welcome path secret is exposed.
                plain_path: None,
                new_keypairs: vec![leaf_keypair],
                experimental_quaternary_parent_keypairs,
                experimental_quaternary_parent_public_nodes,
            });
        }

        // Derive and apply an update path based on the previously
        // generated new leaf.
        let (plain_path, new_keypairs, commit_secret) = self.diff.apply_own_update_path(
            rand,
            crypto,
            signer,
            ciphersuite,
            commit_type,
            self.group_context().group_id().clone(),
            leaf_index,
            leaf_node_params,
        )?;

        // After we've processed the path, we can update the group context s.t.
        // the updated group context is used for path secret encryption. Note
        // that we have not yet updated the confirmed transcript hash.
        self.update_group_context(crypto, gc_extensions)?;

        let serialized_group_context = self
            .group_context()
            .tls_serialize_detached()
            .map_err(LibraryError::missing_bound_check)?;

        // Encrypt the path to the correct recipient nodes.
        let encrypted_path = self.diff.encrypt_path(
            crypto,
            ciphersuite,
            &plain_path,
            &serialized_group_context,
            &exclusion_list,
            leaf_index,
        )?;
        let leaf_node = self
            .diff
            .leaf(leaf_index)
            .ok_or_else(|| LibraryError::custom("Couldn't find own leaf"))?
            .clone();
        let mut encrypted_path = UpdatePath::new(leaf_node.clone(), encrypted_path);
        #[cfg(feature = "experimental-hybrid")]
        let mut experimental_quaternary_parent_keypairs = Vec::new();
        #[cfg(feature = "experimental-hybrid")]
        let mut experimental_quaternary_parent_public_nodes = Vec::new();

        #[cfg(feature = "experimental-hybrid")]
        if let Some(extension) = self
            .group_context()
            .extensions()
            .unknown(crate::experimental_hybrid::ADAPTIVE_HYBRID_TREE_STATE_EXTENSION_TYPE)
        {
            let next_arity_state =
                ArityState::from_extension_value(&extension.0).map_err(|_| {
                    LibraryError::custom("invalid authenticated experimental ArityState")
                })?;
            let delivery_arity_state = if matches!(
                next_arity_state.lifecycle(),
                ArityLifecycle::Transitioning(_)
            ) {
                Some(next_arity_state.clone())
            } else {
                prior_experimental_arity_state
                    .clone()
                    .filter(|state| matches!(state.lifecycle(), ArityLifecycle::Transitioning(_)))
            };
            if let Some(arity_state) = delivery_arity_state.as_ref() {
                let domain = encrypted_path
                    .leaf_node()
                    .encryption_key()
                    .experimental_mkyber_key()
                    .ok_or_else(|| {
                        LibraryError::custom("experimental quaternary sender lacks mKyber leaf key")
                    })?
                    .domain();
                let delivery_plan = self.experimental_quaternary_delivery_plan(
                    leaf_index,
                    leaf_index,
                    arity_state,
                    frozen_transition_mapping,
                )?;
                let root_path = plain_path.last().ok_or_else(|| {
                    LibraryError::custom(
                        "experimental quaternary authority requires a non-empty MLS UpdatePath",
                    )
                })?;
                let root_recipients = delivery_plan
                    .recipient_targets
                    .iter()
                    .map(|(leaf_ordinal, _, _, key)| (*leaf_ordinal, key.clone()))
                    .collect::<Vec<_>>();
                let hybrid_group_context =
                    if matches!(next_arity_state.lifecycle(), ArityLifecycle::Normal)
                        && prior_experimental_arity_state
                            .as_ref()
                            .is_some_and(|state| {
                                matches!(state.lifecycle(), ArityLifecycle::Transitioning(_))
                            })
                    {
                        &prior_group_context
                    } else {
                        &serialized_group_context
                    };
                let mut parent_paths = Vec::new();
                let healthy_parent_delivery = delivery_plan.parent_nodes.len() <= plain_path.len()
                    && _retained_quaternary_public_nodes.len()
                        >= delivery_plan.occupied_parent_node_count
                    && delivery_plan.parent_nodes.iter().all(|parent| {
                        delivery_plan
                            .recipient_targets
                            .iter()
                            .filter(|(_, sender_parent, _, _)| sender_parent == parent)
                            .all(|(_, _, resolution_node, _)| {
                                resolution_node.depth == delivery_plan.parent_nodes.len() as u8
                                    || _retained_quaternary_public_nodes.iter().any(
                                        |(depth, ordinal, _)| {
                                            (*depth, *ordinal)
                                                == (resolution_node.depth, resolution_node.ordinal)
                                        },
                                    )
                            })
                    });
                if healthy_parent_delivery {
                    for (path_index, parent) in
                        delivery_plan.parent_nodes.iter().copied().enumerate()
                    {
                        let source_index = plain_path
                            .len()
                            .checked_sub(path_index + 1)
                            .ok_or_else(|| {
                                LibraryError::custom(
                                    "experimental quaternary path is deeper than MLS UpdatePath",
                                )
                            })?;
                        let source_secret = plain_path[source_index].path_secret();
                        let mut recipients = Vec::new();
                        for (_, sender_parent, resolution_node, leaf_key) in
                            delivery_plan.recipient_targets.iter()
                        {
                            if *sender_parent != parent {
                                continue;
                            }
                            let recipient_index = if resolution_node.depth
                                == delivery_plan.parent_nodes.len() as u8
                            {
                                resolution_node.ordinal
                            } else {
                                crate::experimental_hybrid::quaternary_parent_node_index(
                                    resolution_node.depth,
                                    resolution_node.ordinal,
                                )?
                            };
                            if recipients
                                .iter()
                                .any(|(index, _)| *index == recipient_index)
                            {
                                continue;
                            }
                            let recipient_key = if resolution_node.depth
                                == delivery_plan.parent_nodes.len() as u8
                            {
                                leaf_key.clone()
                            } else {
                                _retained_quaternary_public_nodes
                                    .iter()
                                    .find(|(depth, ordinal, _)| {
                                        (*depth, *ordinal)
                                            == (resolution_node.depth, resolution_node.ordinal)
                                    })
                                    .map(|(_, _, key)| key.clone())
                                    .ok_or_else(|| {
                                        LibraryError::custom(
                                            "healthy quaternary path lacks sibling public key",
                                        )
                                    })?
                            };
                            recipients.push((recipient_index, recipient_key));
                        }
                        let position = ExperimentalQuaternaryParentPosition {
                            tree_version: arity_state.tree_version(),
                            depth: parent.depth,
                            ordinal: parent.ordinal,
                            domain,
                        };
                        let (parent_path, keypair) = root_path
                            .encrypt_experimental_quaternary_parent_from_secret(
                                crypto,
                                ciphersuite,
                                &recipients,
                                hybrid_group_context,
                                position,
                                source_secret,
                            )?;
                        parent_paths.push(parent_path);
                        experimental_quaternary_parent_keypairs.push(keypair);
                    }
                } else if delivery_plan.parent_nodes.len() > plain_path.len() {
                    let root_parent = delivery_plan.parent_nodes[0];
                    let position = ExperimentalQuaternaryParentPosition {
                        tree_version: arity_state.tree_version(),
                        depth: root_parent.depth,
                        ordinal: root_parent.ordinal,
                        domain,
                    };
                    let (root_parent_path, root_keypair) = root_path
                        .encrypt_experimental_quaternary_parent_from_secret(
                            crypto,
                            ciphersuite,
                            &root_recipients,
                            hybrid_group_context,
                            position,
                            root_path.path_secret(),
                        )?;
                    parent_paths.push(root_parent_path);
                    experimental_quaternary_parent_keypairs.push(root_keypair);
                    for parent in delivery_plan.parent_nodes.iter().copied().skip(1) {
                        let parent_secret = root_path
                            .path_secret()
                            .derive_experimental_quaternary_parent_secret(
                                crypto,
                                ciphersuite,
                                domain,
                                arity_state.tree_version(),
                                parent.depth,
                                parent.ordinal,
                            )?;
                        experimental_quaternary_parent_keypairs.push(
                            parent_secret.derive_experimental_quaternary_parent_keypair(
                                crypto,
                                ciphersuite,
                                domain,
                                arity_state.tree_version(),
                                parent.depth,
                                parent.ordinal,
                            )?,
                        );
                    }
                } else {
                    for (path_index, parent) in
                        delivery_plan.parent_nodes.iter().copied().enumerate()
                    {
                        let source_index = plain_path.len() - path_index - 1;
                        let position = ExperimentalQuaternaryParentPosition {
                            tree_version: arity_state.tree_version(),
                            depth: parent.depth,
                            ordinal: parent.ordinal,
                            domain,
                        };
                        let (parent_path, keypair) = root_path
                            .encrypt_experimental_quaternary_parent_from_secret(
                                crypto,
                                ciphersuite,
                                &root_recipients,
                                hybrid_group_context,
                                position,
                                plain_path[source_index].path_secret(),
                            )?;
                        parent_paths.push(parent_path);
                        experimental_quaternary_parent_keypairs.push(keypair);
                    }
                }
                if experimental_quaternary_parent_keypairs.is_empty() {
                    return Err(LibraryError::custom(
                        "experimental quaternary authority requires a non-empty parent path",
                    )
                    .into());
                }
                experimental_quaternary_parent_public_nodes = delivery_plan
                    .parent_nodes
                    .iter()
                    .zip(&experimental_quaternary_parent_keypairs)
                    .map(|(node, keypair)| (node.depth, node.ordinal, keypair.public_key().clone()))
                    .collect();
                encrypted_path = UpdatePath::new(
                    leaf_node,
                    plain_path
                        .iter()
                        .map(PlainUpdatePathNode::compact_quaternary_update_path_node)
                        .collect(),
                );
                encrypted_path.set_experimental_quaternary_parent_paths(parent_paths);
            }
        }
        Ok(PathComputationResult {
            commit_secret: Some(commit_secret),
            encrypted_path: Some(encrypted_path),
            plain_path: Some(plain_path),
            new_keypairs,
            #[cfg(feature = "experimental-hybrid")]
            experimental_quaternary_parent_keypairs,
            #[cfg(feature = "experimental-hybrid")]
            experimental_quaternary_parent_public_nodes,
        })
    }
}
