//! This module contains the [`ParentNode`] struct, its implementation, as well
//! as the [`PlainUpdatePathNode`], a helper struct for the creation of
//! [`UpdatePathNode`] instances.
use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::types::{Ciphersuite, HpkeCiphertext};
#[cfg(not(target_arch = "wasm32"))]
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use thiserror::*;
use tls_codec::{TlsDeserialize, TlsDeserializeBytes, TlsSerialize, TlsSize, VLBytes};

use super::encryption_keys::{EncryptionKey, EncryptionKeyPair};
#[cfg(feature = "experimental-hybrid")]
use crate::experimental_hybrid::{
    binary_hybrid_context, quaternary_hybrid_context, quaternary_parent_node_index,
    ExperimentalHybridPathDelivery, ForkClassicalHpkeProvider,
};
#[cfg(feature = "experimental-hybrid")]
use crate::treesync::treekem::ExperimentalQuaternaryParentPath;
use crate::{
    binary_tree::array_representation::{LeafNodeIndex, ParentNodeIndex},
    error::LibraryError,
    messages::PathSecret,
    schedule::CommitSecret,
    treesync::{hashes::ParentHashInput, treekem::UpdatePathNode},
};
#[cfg(feature = "experimental-hybrid")]
use hybrid_path_secret::{
    seal_hybrid_path_level_with_provider, ClassicalHpkePublicKey, HybridPathRecipientPublic,
    HybridPathSecret, RecipientNodeIndex,
};
#[cfg(feature = "experimental-hybrid")]
use mkyber::EducationalMkyber512Reference;

/// This struct implements the MLS parent node. It contains its public key,
/// parent hash and unmerged leaves. Additionally, it may contain the private
/// key corresponding to the public key.
#[derive(
    Debug,
    Eq,
    PartialEq,
    Clone,
    Serialize,
    Deserialize,
    TlsSerialize,
    TlsDeserialize,
    TlsDeserializeBytes,
    TlsSize,
)]
pub struct ParentNode {
    pub(super) encryption_key: EncryptionKey,
    pub(super) parent_hash: VLBytes,
    pub(super) unmerged_leaves: UnmergedLeaves,
}

impl From<EncryptionKey> for ParentNode {
    fn from(public_key: EncryptionKey) -> Self {
        Self {
            encryption_key: public_key,
            parent_hash: vec![].into(),
            unmerged_leaves: UnmergedLeaves::new(),
        }
    }
}

/// Helper struct for the encryption of a [`ParentNode`].
#[cfg_attr(test, derive(Clone))]
#[derive(Debug)]
pub(crate) struct PlainUpdatePathNode {
    node_index: u32,
    public_key: EncryptionKey,
    path_secret: PathSecret,
}

/// Authenticated coordinates and mKyber domain for one experimental
/// quaternary parent-path record.
#[cfg(feature = "experimental-hybrid")]
#[derive(Clone, Copy)]
pub(crate) struct ExperimentalQuaternaryParentPosition {
    pub(crate) tree_version: u32,
    pub(crate) depth: u8,
    pub(crate) ordinal: u32,
    pub(crate) domain: mkyber::MkyberDomain,
}

impl PlainUpdatePathNode {
    /// Emits an authenticated public-only binary node for the compact
    /// experimental quaternary carrier. Its path secret is replaced by the
    /// signed quaternary-root delivery.
    #[cfg(feature = "experimental-hybrid")]
    pub(crate) fn compact_quaternary_update_path_node(&self) -> UpdatePathNode {
        UpdatePathNode {
            public_key: self.public_key.clone(),
            encrypted_path_secrets: Vec::new(),
            experimental_hybrid_delivery: None,
        }
    }

    /// Derives a deterministic quaternary parent pair from the binary root
    /// path secret without adding a second ciphertext delivery.
    #[cfg(feature = "experimental-hybrid")]
    pub(crate) fn derive_compact_quaternary_parent_keypair(
        &self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        position: ExperimentalQuaternaryParentPosition,
    ) -> Result<EncryptionKeyPair, LibraryError> {
        if position.depth == 0 && position.ordinal == 0 {
            return self
                .path_secret
                .derive_experimental_quaternary_parent_keypair(
                    crypto,
                    ciphersuite,
                    position.domain,
                    position.tree_version,
                    position.depth,
                    position.ordinal,
                );
        }
        self.path_secret
            .derive_experimental_quaternary_parent_secret(
                crypto,
                ciphersuite,
                position.domain,
                position.tree_version,
                position.depth,
                position.ordinal,
            )?
            .derive_experimental_quaternary_parent_keypair(
                crypto,
                ciphersuite,
                position.domain,
                position.tree_version,
                position.depth,
                position.ordinal,
            )
    }

    /// Encrypt this node and return the resulting [`UpdatePathNode`].
    pub(in crate::treesync) fn encrypt(
        &self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        public_keys: &[(u32, EncryptionKey)],
        group_context: &[u8],
    ) -> Result<UpdatePathNode, LibraryError> {
        #[cfg(feature = "experimental-hybrid")]
        if let Some(node_mkyber_key) = self.public_key.experimental_mkyber_key() {
            if !public_keys.is_empty() {
                let context = binary_hybrid_context(
                    crypto,
                    ciphersuite,
                    group_context,
                    self.node_index,
                    node_mkyber_key.domain(),
                )?;
                let recipients = public_keys
                    .iter()
                    .map(|(node_index, public_key)| {
                        let mkyber_public_key = public_key
                            .experimental_mkyber_key()
                            .ok_or_else(|| {
                                LibraryError::custom(
                                    "experimental hybrid recipient lacks mKyber key",
                                )
                            })?
                            .to_mkyber_key()
                            .map_err(|_| {
                                LibraryError::custom(
                                    "invalid experimental hybrid recipient mKyber key",
                                )
                            })?;
                        let classical_public_key = ClassicalHpkePublicKey::from_bytes(
                            public_key.as_slice(),
                        )
                        .map_err(|_| {
                            LibraryError::custom("invalid experimental hybrid recipient HPKE key")
                        })?;
                        Ok(HybridPathRecipientPublic::new(
                            RecipientNodeIndex::new(*node_index),
                            mkyber_public_key,
                            classical_public_key,
                        ))
                    })
                    .collect::<Result<Vec<_>, LibraryError>>()?;
                let path_secret =
                    HybridPathSecret::from_bytes(self.path_secret.path_secret.as_slice()).map_err(
                        |_| LibraryError::custom("invalid experimental hybrid path secret length"),
                    )?;
                let mut randomness = rand::rngs::OsRng;
                let ciphertext = seal_hybrid_path_level_with_provider(
                    &ForkClassicalHpkeProvider::default(),
                    &EducationalMkyber512Reference,
                    &mut randomness,
                    &context,
                    &path_secret,
                    &recipients,
                )
                .map_err(|_| {
                    LibraryError::custom("experimental hybrid UpdatePath encryption failed")
                })?;
                let delivery = ExperimentalHybridPathDelivery::from_canonical_bytes(
                    self.node_index,
                    ciphertext.commit_authenticated_bytes().map_err(|_| {
                        LibraryError::custom("experimental hybrid UpdatePath encoding failed")
                    })?,
                )
                .map_err(|_| {
                    LibraryError::custom("invalid experimental hybrid UpdatePath delivery")
                })?;
                return Ok(UpdatePathNode {
                    public_key: self.public_key.clone(),
                    encrypted_path_secrets: Vec::new(),
                    experimental_hybrid_delivery: Some(delivery.canonical_bytes().to_vec().into()),
                });
            }
        }

        #[cfg(target_arch = "wasm32")]
        let public_keys = public_keys.iter();
        #[cfg(not(target_arch = "wasm32"))]
        let public_keys = public_keys.par_iter();

        public_keys
            .map(|(_, pk)| {
                self.path_secret
                    .encrypt(crypto, ciphersuite, pk, group_context)
            })
            .collect::<Result<Vec<HpkeCiphertext>, LibraryError>>()
            .map(|encrypted_path_secrets| UpdatePathNode {
                public_key: self.public_key.clone(),
                encrypted_path_secrets,
                #[cfg(feature = "experimental-hybrid")]
                experimental_hybrid_delivery: None,
            })
    }

    /// Encrypts one authenticated experimental quaternary parent secret
    /// to every non-committer MLS leaf. The payload is intentionally a
    /// feature-gated UpdatePath field, so the enclosing Commit signature
    /// authenticates both the public parent key and recipient ciphertext.
    #[cfg(feature = "experimental-hybrid")]
    pub(crate) fn encrypt_experimental_quaternary_parent(
        &self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        recipient_leaf_keys: &[(u32, EncryptionKey)],
        group_context: &[u8],
        position: ExperimentalQuaternaryParentPosition,
    ) -> Result<(ExperimentalQuaternaryParentPath, EncryptionKeyPair), LibraryError> {
        if recipient_leaf_keys.is_empty() {
            return Err(LibraryError::custom(
                "experimental quaternary parent has no recipient leaves",
            ));
        }
        let parent_path_secret = if position.depth == 0 && position.ordinal == 0 {
            None
        } else {
            Some(
                self.path_secret
                    .derive_experimental_quaternary_parent_secret(
                        crypto,
                        ciphersuite,
                        position.domain,
                        position.tree_version,
                        position.depth,
                        position.ordinal,
                    )?,
            )
        };
        let parent_secret_source = parent_path_secret.as_ref().unwrap_or(&self.path_secret);
        let parent_keypair = parent_secret_source.derive_experimental_quaternary_parent_keypair(
            crypto,
            ciphersuite,
            position.domain,
            position.tree_version,
            position.depth,
            position.ordinal,
        )?;
        let context = quaternary_hybrid_context(
            crypto,
            ciphersuite,
            group_context,
            position.tree_version,
            position.depth,
            position.ordinal,
            position.domain,
        )?;
        let recipients = recipient_leaf_keys
            .iter()
            .map(|(leaf_index, public_key)| {
                let mkyber_public_key = public_key
                    .experimental_mkyber_key()
                    .ok_or_else(|| {
                        LibraryError::custom("experimental quaternary recipient lacks mKyber key")
                    })?
                    .to_mkyber_key()
                    .map_err(|_| {
                        LibraryError::custom("invalid experimental quaternary recipient mKyber key")
                    })?;
                let classical_public_key =
                    ClassicalHpkePublicKey::from_bytes(public_key.as_slice()).map_err(|_| {
                        LibraryError::custom("invalid experimental quaternary recipient HPKE key")
                    })?;
                Ok(HybridPathRecipientPublic::new(
                    RecipientNodeIndex::new(*leaf_index),
                    mkyber_public_key,
                    classical_public_key,
                ))
            })
            .collect::<Result<Vec<_>, LibraryError>>()?;
        let path_secret = HybridPathSecret::from_bytes(parent_secret_source.path_secret.as_slice())
            .map_err(|_| {
                LibraryError::custom("invalid experimental quaternary path secret length")
            })?;
        let mut randomness = rand::rngs::OsRng;
        let ciphertext = seal_hybrid_path_level_with_provider(
            &ForkClassicalHpkeProvider::default(),
            &EducationalMkyber512Reference,
            &mut randomness,
            &context,
            &path_secret,
            &recipients,
        )
        .map_err(|_| {
            LibraryError::custom("experimental quaternary UpdatePath encryption failed")
        })?;
        let delivery = ExperimentalHybridPathDelivery::from_canonical_bytes(
            quaternary_parent_node_index(position.depth, position.ordinal)?,
            ciphertext.commit_authenticated_bytes().map_err(|_| {
                LibraryError::custom("experimental quaternary UpdatePath encoding failed")
            })?,
        )
        .map_err(|_| LibraryError::custom("invalid experimental quaternary UpdatePath delivery"))?;
        let parent_path = ExperimentalQuaternaryParentPath::new(
            position.tree_version,
            position.depth,
            position.ordinal,
            parent_keypair.public_key().clone(),
            delivery.canonical_bytes().to_vec(),
        );
        Ok((parent_path, parent_keypair))
    }

    /// Return a reference to the `path_secret` of this node.
    pub(in crate::treesync) fn path_secret(&self) -> &PathSecret {
        &self.path_secret
    }

    #[cfg(test)]
    pub(crate) fn new(public_key: EncryptionKey, path_secret: PathSecret) -> Self {
        Self {
            public_key,
            path_secret,
        }
    }
}

/// The result of a path derivation result containing the vector of
/// [`ParentNode`], as well as [`PlainUpdatePathNode`] instance and a
/// [`CommitSecret`].
pub(in crate::treesync) type PathDerivationResult = (
    Vec<(ParentNodeIndex, ParentNode)>,
    Vec<PlainUpdatePathNode>,
    Vec<EncryptionKeyPair>,
    CommitSecret,
);

impl ParentNode {
    /// Derives a path from the given path secret, where the `node_secret` of
    /// the first node is immediately derived from the given `path_secret`.
    ///
    /// Returns the resulting vector of [`ParentNode`] instances, as well as the
    /// intermediary [`PathSecret`]s, and the [`CommitSecret`].
    pub(crate) fn derive_path(
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        path_secret: PathSecret,
        path_indices: Vec<ParentNodeIndex>,
        #[cfg(feature = "experimental-hybrid")] experimental_mkyber_domain: Option<
            mkyber::MkyberDomain,
        >,
    ) -> Result<PathDerivationResult, LibraryError> {
        let mut next_path_secret = path_secret;
        let mut path_secrets = Vec::with_capacity(path_indices.len());

        for _ in 0..path_indices.len() {
            let path_secret = next_path_secret;
            // Derive the next path secret.
            next_path_secret = path_secret.derive_path_secret(crypto, ciphersuite)?;
            path_secrets.push(path_secret);
        }

        type PathDerivationResults = (
            Vec<((ParentNodeIndex, ParentNode), EncryptionKeyPair)>,
            Vec<PlainUpdatePathNode>,
        );

        // Iterate over the path secrets and derive a key pair

        #[cfg(not(target_arch = "wasm32"))]
        let path_secrets = path_secrets.into_par_iter();
        #[cfg(target_arch = "wasm32")]
        let path_secrets = path_secrets.into_iter();

        let (path_with_keypairs, update_path_nodes): PathDerivationResults = path_secrets
            .zip(path_indices)
            .map(|(path_secret, index)| {
                // Derive a key pair from the path secret. This includes the
                // intermediate derivation of a node secret.
                let keypair = path_secret.derive_key_pair(crypto, ciphersuite)?;
                #[cfg(feature = "experimental-hybrid")]
                let keypair = match experimental_mkyber_domain {
                    Some(domain) => keypair.with_experimental_mkyber_keypair(
                        path_secret.derive_experimental_mkyber_keypair(
                            crypto,
                            ciphersuite,
                            domain,
                            index.u32(),
                        )?,
                    )?,
                    None => keypair,
                };
                let parent_node = ParentNode::from(keypair.public_key().clone());
                // Store the current path secret and the derived public key for
                // later encryption.
                let update_path_node = PlainUpdatePathNode {
                    node_index: index.u32(),
                    public_key: keypair.public_key().clone(),
                    path_secret,
                };
                Ok((((index, parent_node), keypair), update_path_node))
            })
            .collect::<Result<
                Vec<(
                    ((ParentNodeIndex, ParentNode), EncryptionKeyPair),
                    PlainUpdatePathNode,
                )>,
                LibraryError,
            >>()?
            .into_iter()
            .unzip();

        let (path, keypairs) = path_with_keypairs.into_iter().unzip();

        let commit_secret = next_path_secret.into();
        Ok((path, update_path_nodes, keypairs, commit_secret))
    }

    /// Return a reference to the `public_key` of this node.
    pub(crate) fn encryption_key(&self) -> &EncryptionKey {
        &self.encryption_key
    }

    /// Get the list of unmerged leaves.
    pub(crate) fn unmerged_leaves(&self) -> &[LeafNodeIndex] {
        self.unmerged_leaves.list()
    }

    /// Set the list of unmerged leaves.
    pub(in crate::treesync) fn set_unmerged_leaves(&mut self, unmerged_leaves: Vec<LeafNodeIndex>) {
        self.unmerged_leaves.set_list(unmerged_leaves);
    }

    /// Add a [`LeafNodeIndex`] to the node's list of unmerged leaves.
    pub(in crate::treesync) fn add_unmerged_leaf(&mut self, leaf_index: LeafNodeIndex) {
        self.unmerged_leaves.add(leaf_index);
    }

    /// Compute the parent hash value of this node.
    pub(in crate::treesync) fn compute_parent_hash(
        &self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        original_child_resolution: &[u8],
    ) -> Result<Vec<u8>, LibraryError> {
        let parent_hash_input = ParentHashInput::new(
            self.encryption_key.key(),
            self.parent_hash(),
            original_child_resolution,
        );
        parent_hash_input.hash(crypto, ciphersuite)
    }

    /// Set the `parent_hash` of this node.
    pub(in crate::treesync) fn set_parent_hash(&mut self, parent_hash: Vec<u8>) {
        self.parent_hash = parent_hash.into()
    }

    /// Get the parent hash value of this node.
    pub(crate) fn parent_hash(&self) -> &[u8] {
        self.parent_hash.as_slice()
    }
}

/// A helper struct that maintains a sorted list of unmerged leaves.
#[derive(Debug, Eq, PartialEq, Clone, Serialize, Deserialize, TlsSize, TlsSerialize)]
pub(in crate::treesync) struct UnmergedLeaves {
    list: Vec<LeafNodeIndex>,
}

impl UnmergedLeaves {
    pub(in crate::treesync) fn new() -> Self {
        Self { list: Vec::new() }
    }

    pub(in crate::treesync) fn add(&mut self, leaf_index: LeafNodeIndex) {
        // The list of unmerged leaves must be sorted. This is enforced upon
        // deserialization. We can therefore safely insert the new leaf at the
        // correct position.
        let position = self.list.binary_search(&leaf_index).unwrap_or_else(|e| e);
        self.list.insert(position, leaf_index);
    }

    pub(in crate::treesync) fn list(&self) -> &[LeafNodeIndex] {
        self.list.as_slice()
    }

    /// Set the list of unmerged leaves.
    pub(in crate::treesync) fn set_list(&mut self, list: Vec<LeafNodeIndex>) {
        self.list = list;
    }
}

#[derive(Error, Debug)]
pub(in crate::treesync) enum UnmergedLeavesError {
    /// The list of leaves is not sorted.
    #[error("The list of leaves is not sorted.")]
    NotSorted,
}

impl TryFrom<Vec<LeafNodeIndex>> for UnmergedLeaves {
    type Error = UnmergedLeavesError;

    fn try_from(list: Vec<LeafNodeIndex>) -> Result<Self, Self::Error> {
        // The list of unmerged leaves must be sorted.
        if !list.windows(2).all(|e| e[0] < e[1]) {
            return Err(UnmergedLeavesError::NotSorted);
        }
        Ok(Self { list })
    }
}
