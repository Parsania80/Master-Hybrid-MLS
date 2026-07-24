use std::collections::HashSet;

use openmls_traits::{crypto::OpenMlsCrypto, random::OpenMlsRand, signatures::Signer};
use serde::{Deserialize, Serialize};
use tls_codec::Serialize as _;

#[cfg(feature = "experimental-hybrid")]
use crate::treesync::node::parent_node::ExperimentalQuaternaryParentPosition;
use crate::{
    binary_tree::LeafNodeIndex,
    credentials::CredentialWithKey,
    error::LibraryError,
    extensions::Extensions,
    group::{errors::CreateCommitError, GroupContext},
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
                let root_position = ExperimentalQuaternaryParentPosition {
                    tree_version: arity_state.tree_version(),
                    depth: 0,
                    ordinal: 0,
                    domain,
                };
                let root_recipients = delivery_plan
                    .recipient_targets
                    .iter()
                    .map(|(leaf_ordinal, _, key)| (*leaf_ordinal, key.clone()))
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
                let (root_parent_path, root_keypair) = root_path
                    .encrypt_experimental_quaternary_parent(
                        crypto,
                        ciphersuite,
                        &root_recipients,
                        hybrid_group_context,
                        root_position,
                    )?;
                experimental_quaternary_parent_keypairs.push(root_keypair);
                for parent in delivery_plan.parent_nodes.into_iter().skip(1) {
                    experimental_quaternary_parent_keypairs.push(
                        root_path.derive_compact_quaternary_parent_keypair(
                            crypto,
                            ciphersuite,
                            ExperimentalQuaternaryParentPosition {
                                tree_version: arity_state.tree_version(),
                                depth: parent.depth,
                                ordinal: parent.ordinal,
                                domain,
                            },
                        )?,
                    );
                }
                if experimental_quaternary_parent_keypairs.is_empty() {
                    return Err(LibraryError::custom(
                        "experimental quaternary authority requires a non-empty parent path",
                    )
                    .into());
                }
                encrypted_path = UpdatePath::new(
                    leaf_node,
                    plain_path
                        .iter()
                        .map(PlainUpdatePathNode::compact_quaternary_update_path_node)
                        .collect(),
                );
                encrypted_path.set_experimental_quaternary_parent_paths(vec![root_parent_path]);
            }
        }
        Ok(PathComputationResult {
            commit_secret: Some(commit_secret),
            encrypted_path: Some(encrypted_path),
            plain_path: Some(plain_path),
            new_keypairs,
            #[cfg(feature = "experimental-hybrid")]
            experimental_quaternary_parent_keypairs,
        })
    }
}
