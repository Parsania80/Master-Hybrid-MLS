use std::collections::HashSet;

use openmls_traits::{crypto::OpenMlsCrypto, random::OpenMlsRand, signatures::Signer};
use serde::{Deserialize, Serialize};
use tls_codec::Serialize as _;

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
    ) -> Result<PathComputationResult, CreateCommitError> {
        let ciphersuite = self.group_context().ciphersuite();

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
        let mut encrypted_path = UpdatePath::new(leaf_node, encrypted_path);

        #[cfg(feature = "experimental-hybrid")]
        if let Some(extension) = self
            .group_context()
            .extensions()
            .unknown(crate::experimental_hybrid::ADAPTIVE_HYBRID_TREE_STATE_EXTENSION_TYPE)
        {
            let arity_state = ArityState::from_extension_value(&extension.0).map_err(|_| {
                LibraryError::custom("invalid authenticated experimental ArityState")
            })?;
            if matches!(arity_state.lifecycle(), ArityLifecycle::Transitioning(_)) {
                let domain = encrypted_path
                    .leaf_node()
                    .encryption_key()
                    .experimental_mkyber_key()
                    .ok_or_else(|| {
                        LibraryError::custom("experimental quaternary sender lacks mKyber leaf key")
                    })?
                    .domain();
                let recipient_leaf_keys = self
                    .full_leaf_encryption_keys()
                    .into_iter()
                    .filter(|(recipient_leaf_index, _)| *recipient_leaf_index != leaf_index)
                    .map(|(recipient_leaf_index, key)| (recipient_leaf_index.u32(), key))
                    .collect::<Vec<_>>();
                let root_path = plain_path.last().ok_or_else(|| {
                    LibraryError::custom(
                        "experimental quaternary authority requires a non-empty MLS UpdatePath",
                    )
                })?;
                encrypted_path.set_experimental_quaternary_parent_path(
                    root_path.encrypt_experimental_quaternary_root(
                        crypto,
                        ciphersuite,
                        &recipient_leaf_keys,
                        &serialized_group_context,
                        arity_state.tree_version(),
                        domain,
                    )?,
                );
            }
        }
        Ok(PathComputationResult {
            commit_secret: Some(commit_secret),
            encrypted_path: Some(encrypted_path),
            plain_path: Some(plain_path),
            new_keypairs,
        })
    }
}
