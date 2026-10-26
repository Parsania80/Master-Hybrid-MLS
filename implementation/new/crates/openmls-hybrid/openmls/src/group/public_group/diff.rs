//! # Public group diffs
//!
//! This module contains the [`PublicGroupDiff`] struct, as well as the
//! [`StagedPublicGroupDiff`] and associated functions and types.
use std::collections::HashSet;
#[cfg(feature = "experimental-hybrid")]
use std::collections::{BTreeMap, BTreeSet};

use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::types::Ciphersuite;
use serde::{Deserialize, Serialize};
use tls_codec::Serialize as TlsSerialize;

#[cfg(feature = "extensions-draft-08")]
use super::errors::ApplyAppDataUpdateError;

use super::PublicGroup;
#[cfg(feature = "experimental-hybrid")]
use crate::treesync::node::encryption_keys::EncryptionKey;
use crate::{
    binary_tree::{array_representation::TreeSize, LeafNodeIndex},
    error::LibraryError,
    extensions::Extensions,
    framing::{mls_auth_content::AuthenticatedContent, public_message::InterimTranscriptHashInput},
    group::GroupContext,
    messages::{proposals::AddProposal, ConfirmationTag, EncryptedGroupSecrets},
    schedule::{psk::PreSharedKeyId, CommitSecret, JoinerSecret},
    treesync::{
        diff::{StagedTreeSyncDiff, TreeSyncDiff},
        errors::{ApplyUpdatePathError, TreeSyncFromNodesError},
        node::{
            encryption_keys::EncryptionKeyPair, leaf_node::LeafNode,
            parent_node::PlainUpdatePathNode,
        },
        treekem::{DecryptPathParams, UpdatePath},
        RatchetTree, TreeSync,
    },
};
#[cfg(feature = "experimental-hybrid")]
use adaptive_tree::{BinaryLeafMember, BinaryToQuaternaryLeafMapping, QuaternaryNode};
#[cfg(feature = "experimental-hybrid")]
use arity_state::{hash_canonical_public_bytes, ArityLifecycle, ArityState};
#[cfg(feature = "experimental-hybrid")]
use transition_tree::ActiveQuaternaryTree;

pub(crate) mod apply_proposals;
pub(crate) mod compute_path;

/// The authenticated mapping-derived quaternary delivery coordinates for one
/// MLS UpdatePath sender and receiver.
#[cfg(feature = "experimental-hybrid")]
pub(crate) struct ExperimentalQuaternaryDeliveryPlan {
    pub(crate) parent_nodes: Vec<QuaternaryNode>,
    pub(crate) recipient_leaf_ordinal: u32,
    pub(crate) recipient_parent_node: Option<QuaternaryNode>,
    pub(crate) recipient_resolution_node: Option<QuaternaryNode>,
    pub(crate) recipient_targets: Vec<(u32, QuaternaryNode, QuaternaryNode, EncryptionKey)>,
    pub(crate) occupied_parent_node_count: usize,
}

pub(crate) struct PublicGroupDiff<'a> {
    diff: TreeSyncDiff<'a>,
    group_context: GroupContext,
    interim_transcript_hash: Vec<u8>,
    // Most recent confirmation tag. Kept here for verification purposes.
    confirmation_tag: ConfirmationTag,
}

impl<'a> PublicGroupDiff<'a> {
    /// Create a new [`PublicGroupDiff`] based on the given [`PublicGroup`].
    pub(super) fn new(public_group: &'a PublicGroup) -> PublicGroupDiff<'a> {
        Self {
            diff: public_group.treesync().empty_diff(),
            group_context: public_group.group_context().clone(),
            interim_transcript_hash: public_group.interim_transcript_hash().to_vec(),
            confirmation_tag: public_group.confirmation_tag().clone(),
        }
    }

    /// Turn this [`PublicGroupDiff`] into a [`StagedPublicGroupDiff`], thus
    /// freezing it until it is merged with the original [`PublicGroup`].
    pub(crate) fn into_staged_diff(
        self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
    ) -> Result<StagedPublicGroupDiff, LibraryError> {
        let staged_diff = self.diff.into_staged_diff(crypto, ciphersuite)?;
        Ok(StagedPublicGroupDiff {
            staged_diff,
            group_context: self.group_context,
            interim_transcript_hash: self.interim_transcript_hash,
            confirmation_tag: self.confirmation_tag,
        })
    }

    /// Prepare the [`EncryptedGroupSecrets`] for a number of `invited_members`
    /// based on this [`PublicGroupDiff`]. If a slice of [`PlainUpdatePathNode`]
    /// is given, they are included in the [`GroupSecrets`] of the path.
    ///
    /// Returns an error if
    ///  - the own node is outside the tree
    ///  - the invited members are not part of the tree yet
    ///  - the leaf index of a new member is identical to the own leaf index
    ///  - the plain path does not contain the correct secrets
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn encrypt_group_secrets(
        &self,
        joiner_secret: &JoinerSecret,
        invited_members: Vec<(LeafNodeIndex, AddProposal)>,
        plain_path_option: Option<&[PlainUpdatePathNode]>,
        presharedkeys: &[PreSharedKeyId],
        encrypted_group_info: &[u8],
        crypto: &impl OpenMlsCrypto,
        leaf_index: LeafNodeIndex,
    ) -> Result<Vec<EncryptedGroupSecrets>, LibraryError> {
        self.diff.encrypt_group_secrets(
            joiner_secret,
            invited_members,
            plain_path_option,
            presharedkeys,
            encrypted_group_info,
            crypto,
            leaf_index,
        )
    }

    /// Returns the tree size
    pub(crate) fn tree_size(&self) -> TreeSize {
        self.diff.tree_size()
    }

    /// Returns a vector of all nodes in the tree resulting from merging this
    /// diff.
    pub(crate) fn export_ratchet_tree(&self) -> RatchetTree {
        self.diff.export_ratchet_tree()
    }

    /// Decrypt an [`UpdatePath`] originating from the given
    /// `sender_leaf_index`. The `group_context` is used in the decryption
    /// process and the `exclusion_list` is used to determine the position of
    /// the ciphertext in the `UpdatePath` that we can decrypt.
    ///
    /// Returns the [`CommitSecret`] resulting from their derivation. Returns an
    /// error if the `sender_leaf_index` is outside of the tree.
    ///
    /// ValSem203: Path secrets must decrypt correctly
    /// ValSem204: Public keys from Path must be verified and match the private keys from the direct path
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn decrypt_path(
        &self,
        crypto: &impl OpenMlsCrypto,
        owned_keys: &[&EncryptionKeyPair],
        own_leaf_index: LeafNodeIndex,
        sender_leaf_index: LeafNodeIndex,
        update_path: &UpdatePath,
        exclusion_list: &HashSet<&LeafNodeIndex>,
        #[cfg(feature = "experimental-hybrid")] frozen_transition_mapping: Option<
            &BinaryToQuaternaryLeafMapping,
        >,
    ) -> Result<(Vec<EncryptionKeyPair>, CommitSecret, Vec<EncryptionKeyPair>), ApplyUpdatePathError>
    {
        #[cfg(feature = "experimental-hybrid")]
        let expected_quaternary_delivery_plan = self
            .group_context()
            .extensions()
            .unknown(crate::experimental_hybrid::ADAPTIVE_HYBRID_TREE_STATE_EXTENSION_TYPE)
            .map(|extension| {
                let state = ArityState::from_extension_value(&extension.0).map_err(|_| {
                    ApplyUpdatePathError::LibraryError(LibraryError::custom(
                        "invalid authenticated experimental ArityState",
                    ))
                })?;
                if matches!(state.lifecycle(), ArityLifecycle::Transitioning(_)) {
                    self.experimental_quaternary_delivery_plan(
                        sender_leaf_index,
                        own_leaf_index,
                        &state,
                        frozen_transition_mapping,
                    )
                    .map(Some)
                    .map_err(ApplyUpdatePathError::LibraryError)
                } else {
                    Ok(None)
                }
            })
            .transpose()?
            .flatten();
        let params = DecryptPathParams {
            update_path: update_path.nodes(),
            sender_leaf_encryption_key: update_path.leaf_node().encryption_key(),
            #[cfg(feature = "experimental-hybrid")]
            sender_leaf_capabilities: update_path.leaf_node().capabilities(),
            #[cfg(feature = "experimental-hybrid")]
            experimental_quaternary_parent_paths: update_path
                .experimental_quaternary_parent_paths(),
            #[cfg(feature = "experimental-hybrid")]
            expected_quaternary_tree_version: expected_quaternary_delivery_plan
                .as_ref()
                .map(|_| self.group_context().extensions())
                .and_then(|extensions| {
                    extensions.unknown(
                        crate::experimental_hybrid::ADAPTIVE_HYBRID_TREE_STATE_EXTENSION_TYPE,
                    )
                })
                .and_then(|extension| ArityState::from_extension_value(&extension.0).ok())
                .map(|state| state.tree_version()),
            #[cfg(feature = "experimental-hybrid")]
            expected_quaternary_parent_nodes: expected_quaternary_delivery_plan.as_ref().map(
                |plan| {
                    plan.parent_nodes
                        .iter()
                        .map(|node| (node.depth, node.ordinal))
                        .collect()
                },
            ),
            #[cfg(feature = "experimental-hybrid")]
            recipient_quaternary_leaf_ordinal: expected_quaternary_delivery_plan
                .as_ref()
                .map(|plan| plan.recipient_leaf_ordinal),
            #[cfg(feature = "experimental-hybrid")]
            recipient_quaternary_parent_node: expected_quaternary_delivery_plan
                .as_ref()
                .and_then(|plan| plan.recipient_parent_node)
                .map(|node| (node.depth, node.ordinal)),
            #[cfg(feature = "experimental-hybrid")]
            recipient_quaternary_resolution_node: expected_quaternary_delivery_plan
                .as_ref()
                .and_then(|plan| plan.recipient_resolution_node)
                .map(|node| (node.depth, node.ordinal)),
            sender_leaf_index,
            exclusion_list,
            group_context: &self
                .group_context()
                .tls_serialize_detached()
                .map_err(LibraryError::missing_bound_check)?,
        };
        self.diff.decrypt_path(
            crypto,
            self.group_context().ciphersuite(),
            params,
            owned_keys,
            own_leaf_index,
        )
    }

    /// Return a reference to the leaf with the given index.
    pub(crate) fn leaf(&self, index: LeafNodeIndex) -> Option<&LeafNode> {
        self.diff.leaf(index)
    }

    /// Derives the sender path and receiver address exclusively from the
    /// authenticated transitioning membership mapping.
    #[cfg(feature = "experimental-hybrid")]
    pub(crate) fn experimental_quaternary_delivery_plan(
        &self,
        sender_leaf_index: LeafNodeIndex,
        recipient_leaf_index: LeafNodeIndex,
        state: &ArityState,
        frozen_transition_mapping: Option<&BinaryToQuaternaryLeafMapping>,
    ) -> Result<ExperimentalQuaternaryDeliveryPlan, LibraryError> {
        let ArityLifecycle::Transitioning(transitioning) = state.lifecycle() else {
            return Err(LibraryError::custom(
                "experimental quaternary delivery requires transitioning ArityState",
            ));
        };
        let mut member_ids = BTreeMap::new();
        let mut leaf_keys = BTreeMap::new();
        for (leaf_index, member_id, encryption_key) in self.diff.full_leaf_member_records() {
            member_ids.insert(leaf_index.u32(), member_id);
            leaf_keys.insert(leaf_index.u32(), encryption_key);
        }
        let mapping = if let Some(mapping) = frozen_transition_mapping {
            if member_ids.values().any(|member_id| {
                !mapping
                    .assignments
                    .iter()
                    .any(|assignment| &assignment.member_id == member_id)
            }) {
                return Err(LibraryError::custom(
                    "current experimental member is absent from frozen mapping",
                ));
            }
            mapping.clone()
        } else {
            BinaryToQuaternaryLeafMapping::from_binary_members(
                member_ids
                    .iter()
                    .map(|(binary_leaf_index, member_id)| BinaryLeafMember {
                        member_id: member_id.clone(),
                        binary_leaf_index: *binary_leaf_index,
                    })
                    .collect(),
            )
            .map_err(|_| LibraryError::custom("invalid experimental quaternary member mapping"))?
        };
        let mapping_bytes = mapping
            .canonical_bytes()
            .map_err(|_| LibraryError::custom("experimental quaternary mapping encoding failed"))?;
        if hash_canonical_public_bytes(&mapping_bytes) != *transitioning.mapping_hash().as_bytes() {
            return Err(LibraryError::custom(
                "experimental quaternary mapping does not match authenticated ArityState",
            ));
        }
        let tree = ActiveQuaternaryTree::from_mapping(state.tree_version(), mapping.clone())
            .map_err(|_| {
                LibraryError::custom("experimental quaternary topology derivation failed")
            })?;
        let sender_member_id = member_ids.get(&sender_leaf_index.u32()).ok_or_else(|| {
            LibraryError::custom("experimental quaternary sender is absent from mapping")
        })?;
        let recipient_member_id = member_ids.get(&recipient_leaf_index.u32()).ok_or_else(|| {
            LibraryError::custom("experimental quaternary recipient is absent from members")
        })?;
        let recipient_assignment = mapping
            .assignments
            .iter()
            .find(|assignment| &assignment.member_id == recipient_member_id)
            .ok_or_else(|| {
                LibraryError::custom("experimental quaternary recipient is absent from mapping")
            })?;
        let sender_path = tree
            .topology()
            .leaf_path_for_member(sender_member_id)
            .map_err(|_| {
                LibraryError::custom("experimental quaternary sender path derivation failed")
            })?;
        let recipient_path = tree
            .topology()
            .leaf_path_for_member(recipient_member_id)
            .map_err(|_| {
                LibraryError::custom("experimental quaternary recipient path derivation failed")
            })?;
        let parent_nodes: Vec<QuaternaryNode> = tree
            .topology()
            .nodes_for_member(sender_member_id)
            .map_err(|_| {
                LibraryError::custom("experimental quaternary sender path derivation failed")
            })?
            .into_iter()
            .take(usize::from(tree.topology().height()))
            .collect();
        let recipient_parent_node = sender_path
            .iter()
            .zip(&recipient_path)
            .position(|(sender_branch, recipient_branch)| sender_branch != recipient_branch)
            .and_then(|depth| parent_nodes.get(depth).copied());
        let recipient_nodes = tree
            .topology()
            .nodes_for_member(recipient_member_id)
            .map_err(|_| {
                LibraryError::custom("experimental quaternary recipient path derivation failed")
            })?;
        let recipient_resolution_node = sender_path
            .iter()
            .zip(&recipient_path)
            .position(|(sender_branch, recipient_branch)| sender_branch != recipient_branch)
            .and_then(|depth| recipient_nodes.get(depth + 1).copied());
        let mut recipient_targets = member_ids
            .iter()
            .filter(|(binary_leaf_index, _)| **binary_leaf_index != sender_leaf_index.u32())
            .map(|(binary_leaf_index, member_id)| {
                let assignment = mapping
                    .assignments
                    .iter()
                    .find(|assignment| &assignment.member_id == member_id)
                    .ok_or_else(|| {
                        LibraryError::custom(
                            "experimental quaternary recipient is absent from frozen mapping",
                        )
                    })?;
                let path = tree
                    .topology()
                    .leaf_path_for_member(member_id)
                    .map_err(|_| {
                        LibraryError::custom(
                            "experimental quaternary recipient path derivation failed",
                        )
                    })?;
                let divergence_depth = sender_path
                    .iter()
                    .zip(path)
                    .position(|(sender_branch, recipient_branch)| {
                        sender_branch != &recipient_branch
                    })
                    .ok_or_else(|| {
                        LibraryError::custom(
                            "experimental quaternary recipient has no sibling-resolution parent",
                        )
                    })?;
                let parent = parent_nodes.get(divergence_depth).copied().ok_or_else(|| {
                    LibraryError::custom(
                        "experimental quaternary recipient parent is outside sender path",
                    )
                })?;
                let recipient_node = tree
                    .topology()
                    .nodes_for_member(member_id)
                    .map_err(|_| {
                        LibraryError::custom(
                            "experimental quaternary recipient path derivation failed",
                        )
                    })?
                    .get(divergence_depth + 1)
                    .copied()
                    .ok_or_else(|| {
                        LibraryError::custom(
                            "experimental quaternary recipient resolution is missing",
                        )
                    })?;
                let key = leaf_keys.get(binary_leaf_index).cloned().ok_or_else(|| {
                    LibraryError::custom("experimental quaternary recipient has no MLS leaf key")
                })?;
                Ok((
                    assignment.quaternary_leaf_ordinal,
                    parent,
                    recipient_node,
                    key,
                ))
            })
            .collect::<Result<Vec<_>, LibraryError>>()?;
        // The member index map is ordered by binary leaf, while the hybrid
        // codec requires canonical increasing quaternary recipient ordinals.
        recipient_targets.sort_by_key(|(leaf_ordinal, _, _, _)| *leaf_ordinal);
        let occupied_parent_node_count = mapping
            .assignments
            .iter()
            .map(|assignment| {
                tree.topology()
                    .nodes_for_member(&assignment.member_id)
                    .map(|nodes| {
                        nodes
                            .into_iter()
                            .take(usize::from(tree.topology().height()))
                    })
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| LibraryError::custom("experimental occupied parent derivation failed"))?
            .into_iter()
            .flatten()
            .map(|node| (node.depth, node.ordinal))
            .collect::<BTreeSet<_>>()
            .len();
        Ok(ExperimentalQuaternaryDeliveryPlan {
            parent_nodes,
            recipient_leaf_ordinal: recipient_assignment.quaternary_leaf_ordinal,
            recipient_parent_node,
            recipient_resolution_node,
            recipient_targets,
            occupied_parent_node_count,
        })
    }

    /// Set the given path as the direct path of the `sender_leaf_index` and
    /// replace the [`LeafNode`] in the corresponding leaf with the given one.
    ///
    /// Returns an error if the `sender_leaf_index` is outside of the tree.
    /// ValSem202: Path must be the right length
    pub(crate) fn apply_received_update_path(
        &mut self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        sender_leaf_index: LeafNodeIndex,
        update_path: &UpdatePath,
    ) -> Result<(), ApplyUpdatePathError> {
        self.diff
            .apply_received_update_path(crypto, ciphersuite, sender_leaf_index, update_path)
    }

    /// Advances the prospective GroupContext with the native quaternary tree
    /// as its sole parent-tree authority.
    #[cfg(feature = "experimental-hybrid")]
    pub(crate) fn update_group_context_with_quaternary_authority(
        &mut self,
        crypto: &impl OpenMlsCrypto,
        extensions: Option<Extensions<GroupContext>>,
        mapping: &BinaryToQuaternaryLeafMapping,
        retained_parent_nodes: &[(u8, u32, EncryptionKey)],
        update_path: &UpdatePath,
    ) -> Result<(), LibraryError> {
        if !update_path.nodes().is_empty() {
            return Err(LibraryError::custom(
                "native quaternary authority cannot serialize binary UpdatePath nodes",
            ));
        }
        let parent_paths = update_path.experimental_quaternary_parent_paths();
        let tree_version = parent_paths
            .first()
            .map(|parent| parent.tree_version())
            .ok_or_else(|| {
                LibraryError::custom("native quaternary authority has no public parent path")
            })?;
        if parent_paths
            .iter()
            .any(|parent| parent.tree_version() != tree_version)
        {
            return Err(LibraryError::custom(
                "native quaternary parent path mixes tree versions",
            ));
        }

        let records = self.diff.full_leaf_member_records();
        let active_member_ids = records
            .iter()
            .map(|(_, member_id, _)| member_id.as_slice())
            .collect::<BTreeSet<_>>();
        let tree = ActiveQuaternaryTree::from_mapping(tree_version, mapping.clone())
            .map_err(|_| LibraryError::custom("native quaternary topology derivation failed"))?;
        let mut parent_nodes = retained_parent_nodes.to_vec();
        for assignment in &mapping.assignments {
            if active_member_ids.contains(assignment.member_id.as_slice()) {
                continue;
            }
            let removed_path = tree
                .topology()
                .nodes_for_member(&assignment.member_id)
                .map_err(|_| {
                    LibraryError::custom("removed member is absent from quaternary topology")
                })?
                .into_iter()
                .take(usize::from(tree.topology().height()))
                .map(|node| (node.depth, node.ordinal))
                .collect::<BTreeSet<_>>();
            parent_nodes.retain(|(depth, ordinal, _)| !removed_path.contains(&(*depth, *ordinal)));
        }
        for parent in parent_paths {
            if let Some(node) = parent_nodes.iter_mut().find(|(depth, ordinal, _)| {
                (*depth, *ordinal) == (parent.parent_depth(), parent.parent_ordinal())
            }) {
                node.2 = parent.public_key().clone();
            } else {
                parent_nodes.push((
                    parent.parent_depth(),
                    parent.parent_ordinal(),
                    parent.public_key().clone(),
                ));
            }
        }
        let leaves = records
            .into_iter()
            .map(|(leaf_index, member_id, public_key)| (leaf_index.u32(), member_id, public_key))
            .collect();
        let tree_hash = crate::experimental_hybrid::quaternary_authority_tree_hash(
            crypto,
            self.group_context().ciphersuite(),
            tree_version,
            mapping,
            leaves,
            parent_nodes,
        )?;
        self.group_context.update_tree_hash(tree_hash);
        self.group_context.increment_epoch();
        if let Some(extensions) = extensions {
            self.group_context.set_extensions(extensions);
        }
        Ok(())
    }

    /// Update the interim transcript hash of the diff and store the
    /// confirmation tag s.t. it can later be merged back into the original
    /// group.
    pub(crate) fn update_interim_transcript_hash(
        &mut self,
        ciphersuite: Ciphersuite,
        crypto: &impl OpenMlsCrypto,
        confirmation_tag: ConfirmationTag,
    ) -> Result<(), LibraryError> {
        let interim_transcript_hash = {
            let input = InterimTranscriptHashInput::from(&confirmation_tag);

            input.calculate_interim_transcript_hash(
                crypto,
                ciphersuite,
                self.group_context.confirmed_transcript_hash(),
            )?
        };

        self.confirmation_tag = confirmation_tag;
        self.interim_transcript_hash = interim_transcript_hash;

        Ok(())
    }

    /// Update the [`GroupContext`] of the diff. This includes tree hash
    /// computation and epoch incrementation, but this does _not_ update the
    /// confirmed transcript hash.
    pub(crate) fn update_group_context(
        &mut self,
        crypto: &impl OpenMlsCrypto,
        extensions: Option<Extensions<GroupContext>>,
    ) -> Result<(), LibraryError> {
        // Calculate tree hash
        let new_tree_hash = self
            .diff
            .compute_tree_hashes(crypto, self.group_context().ciphersuite())?;
        self.group_context.update_tree_hash(new_tree_hash);
        self.group_context.increment_epoch();
        if let Some(extensions) = extensions {
            self.group_context.set_extensions(extensions);
        }
        Ok(())
    }

    /// Update the confirmed transcript hash of the diff's [`GroupContext`]
    /// using the given `interim_transcript_hash`, as well as the
    /// `commit_content`.
    pub(crate) fn update_confirmed_transcript_hash(
        &mut self,
        crypto: &impl OpenMlsCrypto,
        commit_content: &AuthenticatedContent,
    ) -> Result<(), LibraryError> {
        self.group_context.update_confirmed_transcript_hash(
            crypto,
            &self.interim_transcript_hash,
            commit_content,
        )
    }

    pub(crate) fn group_context(&self) -> &GroupContext {
        &self.group_context
    }
}

/// The staged version of a [`PublicGroupDiff`], which means it can no longer be
/// modified. Its only use is to merge it into the original [`PublicGroup`].
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "test-utils"), derive(Clone, PartialEq))]
pub(crate) struct StagedPublicGroupDiff {
    pub(super) staged_diff: StagedTreeSyncDiff,
    pub(super) group_context: GroupContext,
    pub(super) interim_transcript_hash: Vec<u8>,
    pub(super) confirmation_tag: ConfirmationTag,
}

impl StagedPublicGroupDiff {
    /// Get the staged [`GroupContext`].
    pub(crate) fn group_context(&self) -> &GroupContext {
        &self.group_context
    }

    /// Export the staged [`RatchetTree`]
    pub(crate) fn export_ratchet_tree(
        &self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        original_tree: RatchetTree,
    ) -> Result<RatchetTree, TreeSyncFromNodesError> {
        let original_tree_sync = TreeSync::from_ratchet_tree(crypto, ciphersuite, original_tree)?;
        Ok(self
            .staged_diff
            .export_ratchet_tree(original_tree_sync.tree()))
    }
}
