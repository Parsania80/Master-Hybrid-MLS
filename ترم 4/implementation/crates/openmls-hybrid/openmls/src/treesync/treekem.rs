//! Module to encrypt and decrypt update paths for a [`TreeSyncDiff`] instance.
//!
//! # About
//!
//! This module contains structs and functions to encrypt and decrypt path
//! updates for a [`TreeSyncDiff`] instance.
use std::collections::HashSet;

use openmls_traits::{
    crypto::OpenMlsCrypto,
    types::{Ciphersuite, HpkeCiphertext},
};
#[cfg(not(target_arch = "wasm32"))]
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
#[cfg(feature = "experimental-hybrid")]
use tls_codec::VLBytes;
use tls_codec::{TlsDeserialize, TlsDeserializeBytes, TlsSerialize, TlsSize};

use super::{
    diff::TreeSyncDiff,
    errors::UpdatePathError,
    node::{
        encryption_keys::{EncryptionKey, EncryptionKeyPair},
        leaf_node::{LeafNodeIn, TreePosition, VerifiableLeafNode},
        parent_node::{ParentNode, PlainUpdatePathNode},
    },
    ApplyUpdatePathError, LeafNode,
};
#[cfg(feature = "experimental-hybrid")]
use crate::ciphersuite::Secret;
#[cfg(feature = "experimental-hybrid")]
use crate::experimental_hybrid::{
    binary_hybrid_context, quaternary_hybrid_context, supports_mkyber_recipient_capabilities,
    ExperimentalHybridPathDelivery, ForkClassicalHpkeProvider,
};
#[cfg(feature = "experimental-hybrid")]
use crate::treesync::node::leaf_node::Capabilities;
use crate::{
    binary_tree::array_representation::LeafNodeIndex,
    ciphersuite::{hpke, signable::Verifiable},
    error::LibraryError,
    messages::{proposals::AddProposal, EncryptedGroupSecrets, GroupSecrets, PathSecret},
    schedule::{psk::PreSharedKeyId, CommitSecret, JoinerSecret},
    treesync::node::NodeReference,
};
#[cfg(feature = "experimental-hybrid")]
use hybrid_path_secret::{
    open_hybrid_path_level_with_provider, ClassicalHpkePrivateKey, HybridPathRecipientPrivate,
    RecipientNodeIndex,
};
#[cfg(all(
    feature = "experimental-hybrid",
    any(test, feature = "experimental-test-utils")
))]
use hybrid_path_secret::{HybridPathCiphertext, HybridRecipientCiphertext};
#[cfg(feature = "experimental-hybrid")]
use mkyber::EducationalMkyber512Reference;

impl TreeSyncDiff<'_> {
    /// Encrypt the given `path` to the nodes in the copath resolution of the
    /// owner of this [`TreeSyncDiff`]. The `group_context` is used in the
    /// encryption of the nodes, while the `exclusion_list` is used to filter
    /// target leaves from the encryption targets. The given [`LeafNode`] is
    /// included in the resulting [`UpdatePath`].
    ///
    /// Returns the encrypted path (i.e. an [`UpdatePath`] instance).
    pub(crate) fn encrypt_path(
        &self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        path: &[PlainUpdatePathNode],
        group_context: &[u8],
        exclusion_list: &HashSet<&LeafNodeIndex>,
        own_leaf_index: LeafNodeIndex,
    ) -> Result<Vec<UpdatePathNode>, LibraryError> {
        // Copath resolutions with the corresponding public keys.
        let copath_resolutions = self
            .filtered_copath_resolutions(own_leaf_index, exclusion_list)
            .into_iter()
            .map(|resolution| {
                resolution
                    .into_iter()
                    .map(|(node_index, node_ref)| match node_ref {
                        NodeReference::Leaf(leaf) => {
                            (node_index.u32(), leaf.encryption_key().clone())
                        }
                        NodeReference::Parent(parent) => {
                            (node_index.u32(), parent.encryption_key().clone())
                        }
                    })
                    .collect::<Vec<(u32, EncryptionKey)>>()
            })
            .collect::<Vec<Vec<(u32, EncryptionKey)>>>();

        // There should be as many copath resolutions.
        debug_assert_eq!(copath_resolutions.len(), path.len());

        // Encrypt the secrets

        #[cfg(not(target_arch = "wasm32"))]
        let resolved_path = path.par_iter().zip(copath_resolutions.par_iter());
        #[cfg(target_arch = "wasm32")]
        let resolved_path = path.iter().zip(copath_resolutions.iter());

        resolved_path
            .map(|(node, resolution)| node.encrypt(crypto, ciphersuite, resolution, group_context))
            .collect::<Result<Vec<UpdatePathNode>, LibraryError>>()
    }

    /// Decrypt an [`UpdatePath`] originating from the given
    /// `sender_leaf_index`. The `group_context` is used in the decryption
    /// process and the `exclusion_list` is used to determine the position of
    /// the ciphertext in the `UpdatePath` that we can decrypt.
    ///
    /// Returns a vector containing the decrypted [`ParentNode`] instances, as
    /// well as the [`CommitSecret`] resulting from their derivation. Returns an
    /// error if the `sender_leaf_index` is outside of the tree.
    ///
    /// ValSem203: Path secrets must decrypt correctly
    /// ValSem204: Public keys from Path must be verified and match the private keys from the direct path
    pub(crate) fn decrypt_path(
        &self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        params: DecryptPathParams,
        owned_keys: &[&EncryptionKeyPair],
        own_leaf_index: LeafNodeIndex,
    ) -> Result<(Vec<EncryptionKeyPair>, CommitSecret, Vec<EncryptionKeyPair>), ApplyUpdatePathError>
    {
        let path_position = self
            .subtree_root_position(params.sender_leaf_index, own_leaf_index)
            .map_err(|_| ApplyUpdatePathError::MissingOwnLeaf)?;

        #[cfg(feature = "experimental-hybrid")]
        let compact_quaternary_carrier = params.expected_quaternary_tree_version.is_some()
            && params.expected_quaternary_parent_nodes.is_some()
            && params.recipient_quaternary_leaf_ordinal.is_some()
            && params.recipient_quaternary_parent_node.is_some()
            && !params.experimental_quaternary_parent_paths.is_empty()
            && (params.update_path.is_empty()
                || params.update_path.iter().all(|node| {
                    node.encrypted_path_secrets.is_empty()
                        && node.experimental_hybrid_delivery().is_none()
                }));

        #[cfg(feature = "experimental-hybrid")]
        if compact_quaternary_carrier {
            if !supports_mkyber_recipient_capabilities(params.sender_leaf_capabilities) {
                return Err(ApplyUpdatePathError::MissingExperimentalCapability);
            }
            let expected_tree_version = params
                .expected_quaternary_tree_version
                .ok_or(ApplyUpdatePathError::UnableToDecrypt)?;
            let expected_nodes = params
                .expected_quaternary_parent_nodes
                .as_ref()
                .ok_or(ApplyUpdatePathError::UnableToDecrypt)?;
            let recipient_leaf_ordinal = params
                .recipient_quaternary_leaf_ordinal
                .ok_or(ApplyUpdatePathError::UnableToDecrypt)?;
            if expected_nodes.is_empty() {
                return Err(ApplyUpdatePathError::UnableToDecrypt);
            }
            if params.experimental_quaternary_parent_paths.len() == expected_nodes.len() {
                let recipient_parent_node = params
                    .recipient_quaternary_parent_node
                    .ok_or(ApplyUpdatePathError::UnableToDecrypt)?;
                let recipient_resolution_node = params
                    .recipient_quaternary_resolution_node
                    .ok_or(ApplyUpdatePathError::UnableToDecrypt)?;
                let divergence = expected_nodes
                    .iter()
                    .position(|position| *position == recipient_parent_node)
                    .ok_or(ApplyUpdatePathError::UnableToDecrypt)?;
                let parent_path = params
                    .experimental_quaternary_parent_paths
                    .get(divergence)
                    .ok_or(ApplyUpdatePathError::UnableToDecrypt)?;
                parent_path
                    .validate_version()
                    .map_err(ApplyUpdatePathError::LibraryError)?;
                if parent_path.tree_version() != expected_tree_version
                    || (parent_path.parent_depth(), parent_path.parent_ordinal())
                        != recipient_parent_node
                {
                    return Err(ApplyUpdatePathError::UnableToDecrypt);
                }
                let parent_mkyber_key = parent_path
                    .public_key()
                    .experimental_mkyber_key()
                    .ok_or(ApplyUpdatePathError::UnableToDecrypt)?;
                let context = quaternary_hybrid_context(
                    crypto,
                    ciphersuite,
                    params.group_context,
                    expected_tree_version,
                    parent_path.parent_depth(),
                    parent_path.parent_ordinal(),
                    parent_mkyber_key.domain(),
                )
                .map_err(ApplyUpdatePathError::LibraryError)?;
                let delivery = ExperimentalHybridPathDelivery::from_canonical_bytes(
                    crate::experimental_hybrid::quaternary_parent_node_index(
                        parent_path.parent_depth(),
                        parent_path.parent_ordinal(),
                    )
                    .map_err(ApplyUpdatePathError::LibraryError)?,
                    parent_path.delivery().to_vec(),
                )
                .map_err(|_| ApplyUpdatePathError::UnableToDecrypt)?;
                let ciphertext =
                    hybrid_path_secret::HybridPathCiphertext::from_commit_authenticated_bytes(
                        delivery.canonical_bytes(),
                    )
                    .map_err(|_| ApplyUpdatePathError::UnableToDecrypt)?;
                let node_recipient_index =
                    if recipient_resolution_node.0 == expected_nodes.len() as u8 {
                        recipient_resolution_node.1
                    } else {
                        crate::experimental_hybrid::quaternary_parent_node_index(
                            recipient_resolution_node.0,
                            recipient_resolution_node.1,
                        )
                        .map_err(ApplyUpdatePathError::LibraryError)?
                    };
                // The sender can address this receiver through either its
                // retained quaternary resolution node or its direct leaf
                // fallback. Trying every recipient index in the ciphertext
                // here makes native quaternary delivery quadratic in the
                // group size and attempts unrelated private keys against
                // unrelated recipient records.
                let mut recipient_indexes = if node_recipient_index == recipient_leaf_ordinal {
                    vec![recipient_leaf_ordinal]
                } else {
                    vec![node_recipient_index, recipient_leaf_ordinal]
                };
                // Old binary TreeCover fallback recipients use the high bit
                // and carry their binary depth/ordinal below it. Only these
                // compact fallback entries are additionally considered; the
                // receiver never scans unrelated leaf or quaternary records.
                recipient_indexes.extend(
                    ciphertext
                        .recipients()
                        .iter()
                        .map(|record| record.recipient_node_index().as_u32())
                        .filter(|recipient_index| recipient_index & 0x8000_0000 != 0),
                );
                recipient_indexes.sort_unstable();
                recipient_indexes.dedup();
                let opened_secret = recipient_indexes
                    .into_iter()
                    .find_map(|recipient_index| {
                        owned_keys.iter().find_map(|keypair| {
                            let mkyber_private =
                                keypair.experimental_mkyber_private_key().ok().flatten()?;
                            let classical_private = ClassicalHpkePrivateKey::from_bytes(
                                keypair.private_key().classical_private_key(),
                            )
                            .ok()?;
                            open_hybrid_path_level_with_provider(
                                &ForkClassicalHpkeProvider::default(),
                                &EducationalMkyber512Reference,
                                &context,
                                &ciphertext,
                                &HybridPathRecipientPrivate::new(
                                    RecipientNodeIndex::new(recipient_index),
                                    mkyber_private,
                                    classical_private,
                                ),
                            )
                            .ok()
                        })
                    })
                    .ok_or(ApplyUpdatePathError::UnableToDecrypt)?;
                let mut current_secret =
                    PathSecret::from(Secret::from_slice(opened_secret.as_bytes()));
                let mut quaternary_keypairs = Vec::with_capacity(divergence + 1);
                for index in (0..=divergence).rev() {
                    let (depth, ordinal) = expected_nodes[index];
                    let keypair = current_secret
                        .derive_experimental_quaternary_parent_keypair(
                            crypto,
                            ciphersuite,
                            parent_mkyber_key.domain(),
                            expected_tree_version,
                            depth,
                            ordinal,
                        )
                        .map_err(ApplyUpdatePathError::LibraryError)?;
                    let expected_public = params
                        .experimental_quaternary_parent_paths
                        .get(index)
                        .ok_or(ApplyUpdatePathError::UnableToDecrypt)?
                        .public_key();
                    if keypair.public_key() != expected_public {
                        return Err(ApplyUpdatePathError::PathMismatch);
                    }
                    quaternary_keypairs.push(keypair);
                    if index != 0 {
                        current_secret = current_secret
                            .derive_path_secret(crypto, ciphersuite)
                            .map_err(ApplyUpdatePathError::LibraryError)?;
                    }
                }
                quaternary_keypairs.reverse();
                let root_secret = current_secret;
                if params.update_path.is_empty() {
                    let commit_secret: CommitSecret = root_secret
                        .derive_path_secret(crypto, ciphersuite)
                        .map_err(ApplyUpdatePathError::LibraryError)?
                        .into();
                    return Ok((Vec::new(), commit_secret, quaternary_keypairs));
                }
                let root_index = self
                    .filtered_direct_path(params.sender_leaf_index)
                    .last()
                    .copied()
                    .ok_or(ApplyUpdatePathError::PathLengthMismatch)?;
                let (derived_path, _, keypairs, commit_secret) = ParentNode::derive_path(
                    crypto,
                    ciphersuite,
                    root_secret,
                    vec![root_index],
                    params
                        .sender_leaf_encryption_key
                        .experimental_mkyber_key()
                        .map(|key| key.domain()),
                )?;
                let (_, derived_root) = derived_path
                    .last()
                    .ok_or(ApplyUpdatePathError::PathLengthMismatch)?;
                let compact_root = params
                    .update_path
                    .last()
                    .ok_or(ApplyUpdatePathError::PathLengthMismatch)?;
                if compact_root.encryption_key() != derived_root.encryption_key() {
                    return Err(ApplyUpdatePathError::PathMismatch);
                }
                return Ok((keypairs, commit_secret, quaternary_keypairs));
            }
            if params.experimental_quaternary_parent_paths.len() != 1 {
                return Err(ApplyUpdatePathError::UnableToDecrypt);
            }
            let root_delivery = &params.experimental_quaternary_parent_paths[0];
            root_delivery
                .validate_version()
                .map_err(ApplyUpdatePathError::LibraryError)?;
            if root_delivery.tree_version() != expected_tree_version
                || root_delivery.parent_depth() != 0
                || root_delivery.parent_ordinal() != 0
            {
                return Err(ApplyUpdatePathError::UnableToDecrypt);
            }
            let root_mkyber_key = root_delivery
                .public_key()
                .experimental_mkyber_key()
                .ok_or(ApplyUpdatePathError::UnableToDecrypt)?;
            let context = quaternary_hybrid_context(
                crypto,
                ciphersuite,
                params.group_context,
                expected_tree_version,
                0,
                0,
                root_mkyber_key.domain(),
            )
            .map_err(ApplyUpdatePathError::LibraryError)?;
            let delivery = ExperimentalHybridPathDelivery::from_canonical_bytes(
                crate::experimental_hybrid::quaternary_parent_node_index(0, 0)
                    .map_err(ApplyUpdatePathError::LibraryError)?,
                root_delivery.delivery().to_vec(),
            )
            .map_err(|_| ApplyUpdatePathError::UnableToDecrypt)?;
            let ciphertext =
                hybrid_path_secret::HybridPathCiphertext::from_commit_authenticated_bytes(
                    delivery.canonical_bytes(),
                )
                .map_err(|_| ApplyUpdatePathError::UnableToDecrypt)?;
            let recipient_leaf_key = self
                .leaf(own_leaf_index)
                .ok_or(ApplyUpdatePathError::MissingOwnLeaf)?
                .encryption_key();
            let recipient_keypair = owned_keys
                .iter()
                .find(|keypair| keypair.public_key() == recipient_leaf_key)
                .ok_or(ApplyUpdatePathError::UnableToDecrypt)?;
            let root_secret = open_hybrid_path_level_with_provider(
                &ForkClassicalHpkeProvider::default(),
                &EducationalMkyber512Reference,
                &context,
                &ciphertext,
                &HybridPathRecipientPrivate::new(
                    RecipientNodeIndex::new(recipient_leaf_ordinal),
                    recipient_keypair
                        .experimental_mkyber_private_key()
                        .map_err(|_| ApplyUpdatePathError::UnableToDecrypt)?
                        .ok_or(ApplyUpdatePathError::UnableToDecrypt)?,
                    ClassicalHpkePrivateKey::from_bytes(
                        recipient_keypair.private_key().classical_private_key(),
                    )
                    .map_err(|_| ApplyUpdatePathError::UnableToDecrypt)?,
                ),
            )
            .map_err(|_| ApplyUpdatePathError::UnableToDecrypt)?;
            let root_secret = PathSecret::from(Secret::from_slice(root_secret.as_bytes()));
            let mut quaternary_keypairs = Vec::with_capacity(expected_nodes.len());
            for (depth, ordinal) in expected_nodes {
                let keypair = if *depth == 0 && *ordinal == 0 {
                    root_secret.derive_experimental_quaternary_parent_keypair(
                        crypto,
                        ciphersuite,
                        root_mkyber_key.domain(),
                        expected_tree_version,
                        *depth,
                        *ordinal,
                    )
                } else {
                    root_secret
                        .derive_experimental_quaternary_parent_secret(
                            crypto,
                            ciphersuite,
                            root_mkyber_key.domain(),
                            expected_tree_version,
                            *depth,
                            *ordinal,
                        )
                        .and_then(|secret| {
                            secret.derive_experimental_quaternary_parent_keypair(
                                crypto,
                                ciphersuite,
                                root_mkyber_key.domain(),
                                expected_tree_version,
                                *depth,
                                *ordinal,
                            )
                        })
                };
                let keypair = keypair.map_err(ApplyUpdatePathError::LibraryError)?;
                if (*depth, *ordinal) == (0, 0)
                    && keypair.public_key() != root_delivery.public_key()
                {
                    return Err(ApplyUpdatePathError::PathMismatch);
                }
                quaternary_keypairs.push(keypair);
            }
            if params.update_path.is_empty() {
                let commit_secret: CommitSecret = root_secret
                    .derive_path_secret(crypto, ciphersuite)
                    .map_err(ApplyUpdatePathError::LibraryError)?
                    .into();
                return Ok((Vec::new(), commit_secret, quaternary_keypairs));
            }
            let root_index = self
                .filtered_direct_path(params.sender_leaf_index)
                .last()
                .copied()
                .ok_or(ApplyUpdatePathError::PathLengthMismatch)?;
            let (derived_path, _, keypairs, commit_secret) = ParentNode::derive_path(
                crypto,
                ciphersuite,
                root_secret,
                vec![root_index],
                params
                    .sender_leaf_encryption_key
                    .experimental_mkyber_key()
                    .map(|key| key.domain()),
            )?;
            let (_, derived_root) = derived_path
                .last()
                .ok_or(ApplyUpdatePathError::PathLengthMismatch)?;
            let compact_root = params
                .update_path
                .last()
                .ok_or(ApplyUpdatePathError::PathLengthMismatch)?;
            if compact_root.encryption_key() != derived_root.encryption_key() {
                return Err(ApplyUpdatePathError::PathMismatch);
            }
            if quaternary_keypairs.len() != expected_nodes.len() {
                return Err(ApplyUpdatePathError::UnableToDecrypt);
            }
            return Ok((keypairs, commit_secret, quaternary_keypairs));
        }

        let update_path_node = params
            .update_path
            .get(path_position)
            // We know the update path has the right length through validation, therefore there must be an element at this position
            .ok_or(ApplyUpdatePathError::PathLengthMismatch)?;

        let (decryption_key, resolution_position, recipient_node_index) = self
            .decryption_key(
                params.sender_leaf_index,
                params.exclusion_list,
                owned_keys,
                own_leaf_index,
            )
            .map_err(|_| ApplyUpdatePathError::MissingSender)?;

        #[cfg(feature = "experimental-hybrid")]
        let path_secret =
            if let Some(delivery_bytes) = update_path_node.experimental_hybrid_delivery() {
                if !supports_mkyber_recipient_capabilities(params.sender_leaf_capabilities) {
                    return Err(ApplyUpdatePathError::MissingExperimentalCapability);
                }
                if update_path_node
                    .encryption_key()
                    .experimental_mkyber_key()
                    .is_none()
                    || !update_path_node.encrypted_path_secrets.is_empty()
                {
                    return Err(ApplyUpdatePathError::UnableToDecrypt);
                }
                let path_node_index =
                    self.filtered_direct_path(params.sender_leaf_index)[path_position].u32();
                let delivery = ExperimentalHybridPathDelivery::from_canonical_bytes(
                    path_node_index,
                    delivery_bytes.to_vec(),
                )
                .map_err(|_| ApplyUpdatePathError::UnableToDecrypt)?;
                let ciphertext =
                    hybrid_path_secret::HybridPathCiphertext::from_commit_authenticated_bytes(
                        delivery.canonical_bytes(),
                    )
                    .map_err(|_| ApplyUpdatePathError::UnableToDecrypt)?;
                let domain = params
                    .sender_leaf_encryption_key
                    .experimental_mkyber_key()
                    .ok_or(ApplyUpdatePathError::UnableToDecrypt)?
                    .domain();
                let context = binary_hybrid_context(
                    crypto,
                    ciphersuite,
                    params.group_context,
                    path_node_index,
                    domain,
                )
                .map_err(ApplyUpdatePathError::LibraryError)?;
                let private_mkyber_key = decryption_key
                    .experimental_mkyber_private_key()
                    .map_err(|_| ApplyUpdatePathError::UnableToDecrypt)?
                    .ok_or(ApplyUpdatePathError::UnableToDecrypt)?;
                let classical_private_key =
                    ClassicalHpkePrivateKey::from_bytes(decryption_key.classical_private_key())
                        .map_err(|_| ApplyUpdatePathError::UnableToDecrypt)?;
                let secret = open_hybrid_path_level_with_provider(
                    &ForkClassicalHpkeProvider::default(),
                    &EducationalMkyber512Reference,
                    &context,
                    &ciphertext,
                    &HybridPathRecipientPrivate::new(
                        RecipientNodeIndex::new(recipient_node_index),
                        private_mkyber_key,
                        classical_private_key,
                    ),
                )
                .map_err(|_| ApplyUpdatePathError::UnableToDecrypt)?;
                PathSecret::from(Secret::from_slice(secret.as_bytes()))
            } else {
                if update_path_node
                    .encryption_key()
                    .experimental_mkyber_key()
                    .is_some()
                {
                    return Err(ApplyUpdatePathError::UnableToDecrypt);
                }
                let ciphertext = update_path_node
                    .encrypted_path_secrets(resolution_position)
                    .ok_or(ApplyUpdatePathError::MissingCiphertext)?;
                PathSecret::decrypt(
                    crypto,
                    ciphersuite,
                    ciphertext,
                    decryption_key,
                    params.group_context,
                )
                .map_err(|_| ApplyUpdatePathError::UnableToDecrypt)?
            };
        #[cfg(not(feature = "experimental-hybrid"))]
        let path_secret = {
            let ciphertext = update_path_node
                .encrypted_path_secrets(resolution_position)
                .ok_or(ApplyUpdatePathError::MissingCiphertext)?;
            PathSecret::decrypt(
                crypto,
                ciphersuite,
                ciphertext,
                decryption_key,
                params.group_context,
            )
            .map_err(|_| ApplyUpdatePathError::UnableToDecrypt)?
        };

        let common_path =
            self.filtered_common_direct_path(own_leaf_index, params.sender_leaf_index);
        let (derived_path, plain_update_path, keypairs, commit_secret) = ParentNode::derive_path(
            crypto,
            ciphersuite,
            path_secret,
            common_path,
            #[cfg(feature = "experimental-hybrid")]
            params
                .sender_leaf_encryption_key
                .experimental_mkyber_key()
                .map(|key| key.domain()),
        )?;
        // We now check that the encryption keys in the update path and in the
        // derived path match up. In experimental mode this includes the
        // authenticated domain-bound mKyber public material.
        // ValSem204: Public keys from Path must be verified and match the private keys from the direct path
        for (update_parent_node, (_, derived_parent_node)) in params
            .update_path
            .iter()
            .skip(path_position)
            .zip(derived_path.iter())
        {
            if update_parent_node.encryption_key() != derived_parent_node.encryption_key() {
                return Err(ApplyUpdatePathError::PathMismatch);
            }
        }

        #[cfg(feature = "experimental-hybrid")]
        let mut experimental_quaternary_parent_keypairs = Vec::new();
        #[cfg(not(feature = "experimental-hybrid"))]
        let experimental_quaternary_parent_keypairs = Vec::new();
        #[cfg(feature = "experimental-hybrid")]
        match (
            params.expected_quaternary_tree_version,
            params.expected_quaternary_parent_nodes,
            params.recipient_quaternary_leaf_ordinal,
            params.recipient_quaternary_parent_node,
        ) {
            (None, None, None, None) if params.experimental_quaternary_parent_paths.is_empty() => {}
            (
                Some(expected_tree_version),
                Some(expected_nodes),
                Some(recipient_leaf_ordinal),
                Some(recipient_parent_node),
            ) => {
                if expected_nodes.is_empty()
                    || params.experimental_quaternary_parent_paths.len() != expected_nodes.len()
                {
                    return Err(ApplyUpdatePathError::UnableToDecrypt);
                }
                let recipient_leaf_key = self
                    .leaf(own_leaf_index)
                    .ok_or(ApplyUpdatePathError::MissingOwnLeaf)?
                    .encryption_key();
                let recipient_keypair = owned_keys
                    .iter()
                    .find(|keypair| keypair.public_key() == recipient_leaf_key)
                    .ok_or(ApplyUpdatePathError::UnableToDecrypt)?;
                let binary_root_path_secret = plain_update_path
                    .last()
                    .ok_or(ApplyUpdatePathError::PathLengthMismatch)?
                    .path_secret();
                for (parent_path, (parent_depth, parent_ordinal)) in params
                    .experimental_quaternary_parent_paths
                    .iter()
                    .zip(expected_nodes)
                {
                    parent_path
                        .validate_version()
                        .map_err(ApplyUpdatePathError::LibraryError)?;
                    if parent_path.tree_version() != expected_tree_version
                        || parent_path.parent_depth() != parent_depth
                        || parent_path.parent_ordinal() != parent_ordinal
                    {
                        return Err(ApplyUpdatePathError::UnableToDecrypt);
                    }
                    let parent_mkyber_key = parent_path
                        .public_key()
                        .experimental_mkyber_key()
                        .ok_or(ApplyUpdatePathError::UnableToDecrypt)?;
                    let context = quaternary_hybrid_context(
                        crypto,
                        ciphersuite,
                        params.group_context,
                        expected_tree_version,
                        parent_depth,
                        parent_ordinal,
                        parent_mkyber_key.domain(),
                    )
                    .map_err(ApplyUpdatePathError::LibraryError)?;
                    let delivery = ExperimentalHybridPathDelivery::from_canonical_bytes(
                        crate::experimental_hybrid::quaternary_parent_node_index(
                            parent_depth,
                            parent_ordinal,
                        )
                        .map_err(ApplyUpdatePathError::LibraryError)?,
                        parent_path.delivery().to_vec(),
                    )
                    .map_err(|_| ApplyUpdatePathError::UnableToDecrypt)?;
                    let ciphertext =
                        hybrid_path_secret::HybridPathCiphertext::from_commit_authenticated_bytes(
                            delivery.canonical_bytes(),
                        )
                        .map_err(|_| ApplyUpdatePathError::UnableToDecrypt)?;
                    let expected_secret = if parent_depth == 0 && parent_ordinal == 0 {
                        None
                    } else {
                        Some(
                            binary_root_path_secret
                                .derive_experimental_quaternary_parent_secret(
                                    crypto,
                                    ciphersuite,
                                    parent_mkyber_key.domain(),
                                    expected_tree_version,
                                    parent_depth,
                                    parent_ordinal,
                                )
                                .map_err(ApplyUpdatePathError::LibraryError)?,
                        )
                    };
                    let expected_secret =
                        expected_secret.as_ref().unwrap_or(binary_root_path_secret);
                    let derived_parent_keypair = expected_secret
                        .derive_experimental_quaternary_parent_keypair(
                            crypto,
                            ciphersuite,
                            parent_mkyber_key.domain(),
                            expected_tree_version,
                            parent_depth,
                            parent_ordinal,
                        )
                        .map_err(ApplyUpdatePathError::LibraryError)?;
                    if derived_parent_keypair.public_key() != parent_path.public_key() {
                        return Err(ApplyUpdatePathError::PathMismatch);
                    }
                    if (parent_depth, parent_ordinal) == recipient_parent_node {
                        let opened_secret = open_hybrid_path_level_with_provider(
                            &ForkClassicalHpkeProvider::default(),
                            &EducationalMkyber512Reference,
                            &context,
                            &ciphertext,
                            &HybridPathRecipientPrivate::new(
                                RecipientNodeIndex::new(recipient_leaf_ordinal),
                                recipient_keypair
                                    .experimental_mkyber_private_key()
                                    .map_err(|_| ApplyUpdatePathError::UnableToDecrypt)?
                                    .ok_or(ApplyUpdatePathError::UnableToDecrypt)?,
                                ClassicalHpkePrivateKey::from_bytes(
                                    recipient_keypair.private_key().classical_private_key(),
                                )
                                .map_err(|_| ApplyUpdatePathError::UnableToDecrypt)?,
                            ),
                        )
                        .map_err(|_| ApplyUpdatePathError::UnableToDecrypt)?;
                        if opened_secret.as_bytes() != expected_secret.path_secret.as_slice() {
                            return Err(ApplyUpdatePathError::PathMismatch);
                        }
                    }
                    experimental_quaternary_parent_keypairs.push(derived_parent_keypair);
                }
            }
            _ => return Err(ApplyUpdatePathError::UnableToDecrypt),
        }

        Ok((
            keypairs,
            commit_secret,
            experimental_quaternary_parent_keypairs,
        ))
    }

    /// Prepare the [`EncryptedGroupSecrets`] for a number of `invited_members`
    /// based on a [`TreeSyncDiff`]. If a slice of [`PlainUpdatePathNode`] is
    /// given, they are included in the [`GroupSecrets`] of the path.
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
        encryptor_leaf_index: LeafNodeIndex,
    ) -> Result<Vec<EncryptedGroupSecrets>, LibraryError> {
        let mut encrypted_group_secrets_vec = vec![];
        for (leaf_index, add_proposal) in invited_members {
            let key_package = add_proposal.key_package;

            let direct_path_position = self
                .subtree_root_position(encryptor_leaf_index, leaf_index)
                // This can only fail if the nodes are outside the tree or identical
                .map_err(|_| LibraryError::custom("Unexpected error in subtree_root_position"))?;

            // If a plain path was given, there have to be secrets for every new member.
            let path_secret_option = if let Some(plain_path) = plain_path_option {
                Some(
                    plain_path
                        .get(direct_path_position)
                        .map(|pupn| pupn.path_secret())
                        // This only fails if the supplied plain path is invalid
                        .ok_or_else(|| LibraryError::custom("Invalid plain path"))?,
                )
            } else {
                None
            };

            // Create the GroupSecrets object for the respective member.
            let group_secrets_bytes =
                GroupSecrets::new_encoded(joiner_secret, path_secret_option, presharedkeys)
                    .map_err(LibraryError::missing_bound_check)?;
            let ciphertext = hpke::encrypt_with_label(
                key_package.hpke_init_key().as_slice(),
                "Welcome",
                encrypted_group_info,
                &group_secrets_bytes,
                key_package.ciphersuite(),
                crypto,
            )
            .map_err(|_| {
                LibraryError::custom(
                    "Error while encrypting group secrets. \
                     This could have really only been a missing bounds check in \
                     the serialization",
                )
            })?;
            let encrypted_group_secrets =
                EncryptedGroupSecrets::new(key_package.hash_ref(crypto)?, ciphertext);
            encrypted_group_secrets_vec.push(encrypted_group_secrets);
        }
        Ok(encrypted_group_secrets_vec)
    }
}

pub(crate) struct DecryptPathParams<'a> {
    pub(crate) update_path: &'a [UpdatePathNode],
    /// The authenticated new leaf encryption key carried by the UpdatePath.
    /// Its mKyber domain selects deterministic experimental parent derivation.
    pub(crate) sender_leaf_encryption_key: &'a EncryptionKey,
    /// Capabilities authenticated in the incoming UpdatePath leaf.
    #[cfg(feature = "experimental-hybrid")]
    pub(crate) sender_leaf_capabilities: &'a Capabilities,
    /// Authenticated mapping-derived quaternary parent deliveries from the enclosing UpdatePath.
    #[cfg(feature = "experimental-hybrid")]
    pub(crate) experimental_quaternary_parent_paths: &'a [ExperimentalQuaternaryParentPath],
    /// Quaternary tree version authenticated in the prospective GroupContext.
    #[cfg(feature = "experimental-hybrid")]
    pub(crate) expected_quaternary_tree_version: Option<u32>,
    /// Ordered authenticated quaternary parent positions for the sender path.
    #[cfg(feature = "experimental-hybrid")]
    pub(crate) expected_quaternary_parent_nodes: Option<Vec<(u8, u32)>>,
    /// Mapping-derived quaternary leaf ordinal used for hybrid recipient lookup.
    #[cfg(feature = "experimental-hybrid")]
    pub(crate) recipient_quaternary_leaf_ordinal: Option<u32>,
    /// The one sender-path parent whose sibling resolution contains this receiver.
    #[cfg(feature = "experimental-hybrid")]
    pub(crate) recipient_quaternary_parent_node: Option<(u8, u32)>,
    /// The co-path resolution node whose prior-epoch key this receiver owns.
    #[cfg(feature = "experimental-hybrid")]
    pub(crate) recipient_quaternary_resolution_node: Option<(u8, u32)>,
    pub(crate) sender_leaf_index: LeafNodeIndex,
    pub(crate) exclusion_list: &'a HashSet<&'a LeafNodeIndex>,
    pub(crate) group_context: &'a [u8],
}

/// 8.6. Update Paths
///
/// ```text
/// struct {
///     HPKEPublicKey public_key;
///     HPKECiphertext encrypted_path_secret<V>;
/// } UpdatePathNode;
/// ```
#[derive(
    Debug,
    Eq,
    PartialEq,
    Clone,
    Serialize,
    Deserialize,
    TlsDeserialize,
    TlsDeserializeBytes,
    TlsSerialize,
    TlsSize,
)]
pub struct UpdatePathNode {
    pub(super) public_key: EncryptionKey,
    pub(super) encrypted_path_secrets: Vec<HpkeCiphertext>,
    #[cfg(feature = "experimental-hybrid")]
    pub(super) experimental_hybrid_delivery: Option<VLBytes>,
}

/// Feature-gated authenticated quaternary root-parent delivery carried by an
/// experimental MLS UpdatePath.
///
/// The parent public key and hybrid ciphertext are covered by the surrounding
/// Commit signature. This is intentionally a fork-local non-RFC wire field.
#[cfg(feature = "experimental-hybrid")]
#[derive(
    Debug,
    Eq,
    PartialEq,
    Clone,
    Serialize,
    Deserialize,
    TlsDeserialize,
    TlsDeserializeBytes,
    TlsSerialize,
    TlsSize,
)]
pub(crate) struct ExperimentalQuaternaryParentPath {
    version: u16,
    tree_version: u32,
    parent_depth: u8,
    parent_ordinal: u32,
    public_key: EncryptionKey,
    delivery: VLBytes,
}

#[cfg(feature = "experimental-hybrid")]
impl ExperimentalQuaternaryParentPath {
    pub(crate) const VERSION: u16 = 1;

    pub(crate) fn new(
        tree_version: u32,
        parent_depth: u8,
        parent_ordinal: u32,
        public_key: EncryptionKey,
        delivery: Vec<u8>,
    ) -> Self {
        Self {
            version: Self::VERSION,
            tree_version,
            parent_depth,
            parent_ordinal,
            public_key,
            delivery: delivery.into(),
        }
    }

    pub(crate) const fn tree_version(&self) -> u32 {
        self.tree_version
    }

    pub(crate) const fn parent_depth(&self) -> u8 {
        self.parent_depth
    }

    pub(crate) const fn parent_ordinal(&self) -> u32 {
        self.parent_ordinal
    }

    pub(crate) fn public_key(&self) -> &EncryptionKey {
        &self.public_key
    }

    pub(crate) fn delivery(&self) -> &[u8] {
        self.delivery.as_ref()
    }

    pub(crate) fn validate_version(&self) -> Result<(), LibraryError> {
        if self.version != Self::VERSION || self.tree_version == 0 {
            return Err(LibraryError::custom(
                "invalid experimental quaternary parent path version",
            ));
        }
        Ok(())
    }
}

impl UpdatePathNode {
    /// Return the `encrypted_path_secrets`.
    fn encrypted_path_secrets(&self, ciphertext_index: usize) -> Option<&HpkeCiphertext> {
        self.encrypted_path_secrets.get(ciphertext_index)
    }

    pub(crate) fn encryption_key(&self) -> &EncryptionKey {
        &self.public_key
    }

    #[cfg(feature = "experimental-hybrid")]
    pub(crate) fn experimental_hybrid_delivery(&self) -> Option<&[u8]> {
        self.experimental_hybrid_delivery
            .as_ref()
            .map(AsRef::as_ref)
    }

    /// Flip the last byte of every `encrypted_path_secret` in this node.
    #[cfg(test)]
    fn flip_last_byte(&mut self) {
        let mut new_eps_vec = Vec::new();
        for eps in self.encrypted_path_secrets.as_slice() {
            let mut new_eps = eps.clone();
            let mut last_bits = new_eps
                .ciphertext
                .pop()
                .expect("An unexpected error occurred.");
            last_bits ^= 0xff;
            new_eps.ciphertext.push(last_bits);
            new_eps_vec.push(new_eps);
        }
        self.encrypted_path_secrets = new_eps_vec;
    }

    /// Flip the last byte of the public key in this node.
    #[cfg(test)]
    fn flip_last_pk_byte(&mut self) {
        use tls_codec::{Deserialize, Serialize};

        let mut new_pk_serialized = self
            .public_key
            .tls_serialize_detached()
            .expect("error serializing public key");
        let mut last_bits = new_pk_serialized
            .pop()
            .expect("An unexpected error occurred.");
        last_bits ^= 0xff;
        new_pk_serialized.push(last_bits);
        self.public_key = EncryptionKey::tls_deserialize(&mut new_pk_serialized.as_slice())
            .expect("error deserializing pk");
    }
}

/// 8.6. Update Paths
///
/// ```text
/// struct {
///     LeafNode leaf_node;
///     UpdatePathNode nodes<V>;
/// } UpdatePath;
/// ```
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, TlsSerialize, TlsSize)]
pub struct UpdatePath {
    leaf_node: LeafNode,
    nodes: Vec<UpdatePathNode>,
    #[cfg(feature = "experimental-hybrid")]
    experimental_quaternary_parent_paths: Vec<ExperimentalQuaternaryParentPath>,
}

impl UpdatePath {
    /// Generate a new update path.
    pub(crate) fn new(leaf_node: LeafNode, nodes: Vec<UpdatePathNode>) -> Self {
        Self {
            leaf_node,
            nodes,
            #[cfg(feature = "experimental-hybrid")]
            experimental_quaternary_parent_paths: Vec::new(),
        }
    }

    /// Return the `leaf_node` of this [`UpdatePath`].
    pub(crate) fn leaf_node(&self) -> &LeafNode {
        &self.leaf_node
    }

    /// Return the `nodes` of this [`UpdatePath`].
    pub(crate) fn nodes(&self) -> &[UpdatePathNode] {
        &self.nodes
    }

    #[cfg(feature = "experimental-hybrid")]
    pub(crate) fn set_experimental_quaternary_parent_paths(
        &mut self,
        parent_paths: Vec<ExperimentalQuaternaryParentPath>,
    ) {
        self.experimental_quaternary_parent_paths = parent_paths;
    }

    #[cfg(feature = "experimental-hybrid")]
    pub(crate) fn experimental_quaternary_parent_paths(
        &self,
    ) -> &[ExperimentalQuaternaryParentPath] {
        &self.experimental_quaternary_parent_paths
    }

    /// Replaces the first parent delivery recipient in a signed-real-Commit
    /// rejection fixture. This is unavailable outside test utilities.
    #[cfg(all(
        feature = "experimental-hybrid",
        any(test, feature = "experimental-test-utils")
    ))]
    pub(crate) fn test_replace_first_quaternary_recipient(&mut self) -> Result<(), LibraryError> {
        let parent_path = self
            .experimental_quaternary_parent_paths
            .first_mut()
            .ok_or_else(|| LibraryError::custom("missing experimental quaternary parent path"))?;
        let node_index = crate::experimental_hybrid::quaternary_parent_node_index(
            parent_path.parent_depth,
            parent_path.parent_ordinal,
        )?;
        let delivery = ExperimentalHybridPathDelivery::from_canonical_bytes(
            node_index,
            parent_path.delivery.as_ref().to_vec(),
        )
        .map_err(|_| LibraryError::custom("invalid experimental quaternary parent delivery"))?;
        let ciphertext =
            HybridPathCiphertext::from_commit_authenticated_bytes(delivery.canonical_bytes())
                .map_err(|_| LibraryError::custom("invalid experimental quaternary ciphertext"))?;
        let mut replaced = false;
        let recipients = ciphertext
            .recipients()
            .iter()
            .map(|record| {
                if !replaced {
                    replaced = true;
                    HybridRecipientCiphertext::new(
                        RecipientNodeIndex::new(u32::MAX),
                        *record.classical_encapsulation(),
                        record.mkyber_recipient().clone(),
                        *record.encrypted_path_secret(),
                    )
                } else {
                    record.clone()
                }
            })
            .collect();
        let ciphertext = HybridPathCiphertext::new(
            ciphertext.path_node_index(),
            ciphertext.mkyber_domain(),
            ciphertext.mkyber_common().clone(),
            recipients,
        )
        .map_err(|_| LibraryError::custom("invalid experimental quaternary recipient fixture"))?;
        let delivery = ExperimentalHybridPathDelivery::from_canonical_bytes(
            node_index,
            ciphertext.commit_authenticated_bytes().map_err(|_| {
                LibraryError::custom("experimental quaternary fixture encoding failed")
            })?,
        )
        .map_err(|_| LibraryError::custom("invalid experimental quaternary recipient fixture"))?;
        parent_path.delivery = delivery.canonical_bytes().to_vec().into();
        Ok(())
    }

    /// Changes the first parent coordinate after path derivation in a signed
    /// real-Commit rejection fixture.
    #[cfg(all(
        feature = "experimental-hybrid",
        any(test, feature = "experimental-test-utils")
    ))]
    pub(crate) fn test_increment_first_quaternary_parent_ordinal(&mut self) {
        if let Some(parent_path) = self.experimental_quaternary_parent_paths.first_mut() {
            parent_path.parent_ordinal = parent_path.parent_ordinal.saturating_add(1);
        }
    }

    #[cfg(test)]
    /// Flip the last bytes of the ciphertexts of all contained nodes.
    pub fn flip_eps_bytes(&mut self) {
        let mut new_nodes = Vec::new();
        for node in self.nodes.as_slice() {
            let mut new_node = node.clone();
            new_node.flip_last_byte();
            new_nodes.push(new_node);
        }
        self.nodes = new_nodes;
    }

    #[cfg(test)]
    /// Set the path key package.
    pub fn set_leaf_node(&mut self, leaf_node: LeafNode) {
        self.leaf_node = leaf_node
    }

    #[cfg(test)]
    /// Remove and return the last node in the update path. Returns `None` if
    /// the path is empty.
    pub fn pop(&mut self) -> Option<UpdatePathNode> {
        self.nodes.pop()
    }

    #[cfg(test)]
    /// Flip the last bytes of the public key in the last node in the path.
    pub fn flip_node_bytes(&mut self) {
        let mut last_node = self.nodes.pop().expect("path empty");
        last_node.flip_last_pk_byte();
        self.nodes.push(last_node)
    }
}

#[derive(
    Debug,
    PartialEq,
    Eq,
    Clone,
    Serialize,
    Deserialize,
    TlsSerialize,
    TlsDeserialize,
    TlsDeserializeBytes,
    TlsSize,
)]
pub struct UpdatePathIn {
    leaf_node: LeafNodeIn,
    nodes: Vec<UpdatePathNode>,
    #[cfg(feature = "experimental-hybrid")]
    experimental_quaternary_parent_paths: Vec<ExperimentalQuaternaryParentPath>,
}

impl UpdatePathIn {
    /// Return the `leaf_node` of this [`UpdatePath`].
    pub(crate) fn leaf_node(&self) -> &LeafNodeIn {
        &self.leaf_node
    }

    /// Return a verified [`UpdatePath`].
    pub(crate) fn into_verified(
        self,
        ciphersuite: Ciphersuite,
        crypto: &impl OpenMlsCrypto,
        tree_position: TreePosition,
    ) -> Result<UpdatePath, UpdatePathError> {
        let leaf_node_in = self.leaf_node().clone();
        let verifiable_leaf_node = leaf_node_in.into_verifiable_leaf_node();

        // [valn1207](https://validation.openmls.tech/#valn1207)
        match verifiable_leaf_node {
            // https://validation.openmls.tech/#valn1208
            VerifiableLeafNode::Commit(mut commit_leaf_node) => {
                let pk = &commit_leaf_node
                    .signature_key()
                    .clone()
                    .into_signature_public_key_enriched(ciphersuite.signature_algorithm());
                commit_leaf_node.add_tree_position(tree_position);

                let leaf_node: LeafNode = commit_leaf_node.verify(crypto, pk)?;
                Ok(UpdatePath {
                    leaf_node,
                    nodes: self.nodes,
                    #[cfg(feature = "experimental-hybrid")]
                    experimental_quaternary_parent_paths: self.experimental_quaternary_parent_paths,
                })
            }
            VerifiableLeafNode::Update(_) | VerifiableLeafNode::KeyPackage(_) => {
                Err(UpdatePathError::InvalidType)
            }
        }
    }
}

// The following `From` implementation( breaks abstraction layers and MUST
// NOT be made available outside of tests or "test-utils".
#[cfg(any(feature = "test-utils", test))]
impl From<UpdatePathIn> for UpdatePath {
    fn from(update_path_in: UpdatePathIn) -> Self {
        Self {
            leaf_node: update_path_in.leaf_node.into(),
            nodes: update_path_in.nodes,
            #[cfg(feature = "experimental-hybrid")]
            experimental_quaternary_parent_paths: update_path_in
                .experimental_quaternary_parent_paths,
        }
    }
}

impl From<UpdatePath> for UpdatePathIn {
    fn from(update_path: UpdatePath) -> Self {
        Self {
            leaf_node: update_path.leaf_node.into(),
            nodes: update_path.nodes,
            #[cfg(feature = "experimental-hybrid")]
            experimental_quaternary_parent_paths: update_path.experimental_quaternary_parent_paths,
        }
    }
}
