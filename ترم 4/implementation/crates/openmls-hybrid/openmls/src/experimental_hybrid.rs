//! Thesis-local experimental mKyber recipient capability and key material.
//!
//! This module defines only public KeyPackage material.  It does not alter an
//! UpdatePath, derive a path secret, or make an experimental commit available.
//! The private-use values are intentionally not standardized or interoperable.

use std::{collections::BTreeMap, fmt};

use hybrid_path_secret::{
    ClassicalHpkePrivateKey, ClassicalHpkeProvider, ClassicalHpkePublicKey,
    ClassicalHpkeSenderOutput, ClassicalSharedSecret, HybridPathCiphertext, HybridPathLevelError,
    CLASSICAL_ENCAPSULATION_BYTES, CLASSICAL_SHARED_SECRET_BYTES,
};
use mkyber::{
    EducationalMkyber512Reference, MkyberDecapsulationKey, MkyberDomain, MkyberEncapsulationKey,
    DECAPSULATION_KEY_BYTES, ENCAPSULATION_KEY_BYTES,
};
use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;
use tls_codec::{TlsDeserialize, TlsDeserializeBytes, TlsSerialize, TlsSize};
use zeroize::Zeroize;

use crate::prelude::{Ciphersuite, OpenMlsCrypto, OpenMlsProvider};
use crate::{
    error::LibraryError,
    extensions::{
        errors::InvalidExtensionError, Extension, ExtensionType, Extensions, UnknownExtension,
    },
    group::GroupContext,
    key_packages::KeyPackage,
    treesync::node::leaf_node::Capabilities,
};
use tls_codec::Deserialize as TlsDeserializeTrait;

/// Private-use GroupContext extension carrying authenticated adaptive-tree state.
///
/// This remains required for every experimental member by ADR 0005.  This
/// module only advertises it; a later UpdatePath implementation must validate
/// and authenticate its value through the MLS commit path.
pub const ADAPTIVE_HYBRID_TREE_STATE_EXTENSION_TYPE: u16 = 0xF001;

/// Private-use KeyPackage extension carrying one mKyber recipient public key.
pub const MKYBER_RECIPIENT_KEY_PACKAGE_EXTENSION_TYPE: u16 = 0xF002;

/// Private-use GroupContext extension carrying the exact public observation
/// that authorized one TreeCover retirement Commit.
pub const TREECOVER_RETIREMENT_EVIDENCE_EXTENSION_TYPE: u16 = 0xF003;

/// Supported canonical retirement-evidence version.
pub const TREECOVER_RETIREMENT_EVIDENCE_VERSION: u16 = 1;

/// Exact byte length of the fixed version-1 retirement evidence.
pub const TREECOVER_RETIREMENT_EVIDENCE_BYTES: usize = 63;

/// Supported canonical mKyber recipient-key extension value version.
pub const MKYBER_RECIPIENT_KEY_MATERIAL_VERSION: u16 = 1;

/// Number of public bytes in a version-1 mKyber recipient-key extension value.
pub const MKYBER_RECIPIENT_KEY_MATERIAL_BYTES: usize =
    2 + core::mem::size_of::<[u8; 32]>() + ENCAPSULATION_KEY_BYTES;

/// Errors returned while handling experimental mKyber recipient public material.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ExperimentalMkyberError {
    /// The KeyPackage does not carry the required recipient-key extension.
    #[error("the key package has no mKyber recipient-key extension")]
    MissingRecipientKeyMaterial,
    /// The KeyPackage did not advertise all required experimental extensions.
    #[error("the key package does not advertise all required experimental capabilities")]
    MissingExperimentalCapability,
    /// The extension value is not the exact fixed-size version-1 encoding.
    #[error("the mKyber recipient-key extension has {actual} bytes; expected {expected} bytes")]
    InvalidEncodingLength {
        /// Expected fixed byte length.
        expected: usize,
        /// Actual supplied byte length.
        actual: usize,
    },
    /// The extension uses a version this fork does not support.
    #[error("unsupported mKyber recipient-key extension version {0}")]
    UnsupportedVersion(u16),
    /// A fixed-size public key could not be reconstructed.
    #[error("the mKyber recipient public key is invalid")]
    InvalidPublicKey,
}

/// Errors returned while validating authenticated TreeCover-retirement evidence.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ExperimentalTreeCoverRetirementError {
    /// The fixed version-1 encoding has the wrong length.
    #[error("the TreeCover retirement evidence has an invalid length")]
    InvalidEncodingLength,
    /// The evidence uses an unsupported version.
    #[error("the TreeCover retirement evidence has an unsupported version")]
    UnsupportedVersion,
    /// Counts, fractions, epochs, or trigger bits are not canonical.
    #[error("the TreeCover retirement evidence is invalid")]
    InvalidEvidence,
}

/// Exact public endpoint-health observation authenticated by a retirement Commit.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExperimentalTreeCoverRetirementEvidence {
    tree_version: u32,
    transition_epoch: u64,
    observation_epoch: u64,
    impactful_commit_count: u32,
    c_leaf: u32,
    c_new: u32,
    c_old: u32,
    c_real: u32,
    c_ideal: u32,
    h_new_numerator: u32,
    h_new_denominator: u32,
    h_old_numerator: u32,
    h_old_denominator: u32,
    trigger_mask: u8,
}

impl ExperimentalTreeCoverRetirementEvidence {
    /// Constructs and validates one canonical strict-threshold observation.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tree_version: u32,
        transition_epoch: u64,
        observation_epoch: u64,
        impactful_commit_count: u32,
        c_leaf: u32,
        c_new: u32,
        c_old: u32,
        c_real: u32,
        c_ideal: u32,
        h_new_numerator: u32,
        h_new_denominator: u32,
        h_old_numerator: u32,
        h_old_denominator: u32,
    ) -> Result<Self, ExperimentalTreeCoverRetirementError> {
        let retire_new = u64::from(h_new_numerator) * 10 > u64::from(h_new_denominator) * 7;
        let retire_old = u64::from(h_old_numerator) * 2 < u64::from(h_old_denominator);
        let evidence = Self {
            tree_version,
            transition_epoch,
            observation_epoch,
            impactful_commit_count,
            c_leaf,
            c_new,
            c_old,
            c_real,
            c_ideal,
            h_new_numerator,
            h_new_denominator,
            h_old_numerator,
            h_old_denominator,
            trigger_mask: u8::from(retire_new) | (u8::from(retire_old) << 1),
        };
        evidence.validate()?;
        Ok(evidence)
    }

    /// Parses the exact fixed-width extension value.
    pub fn from_extension_value(
        bytes: &[u8],
    ) -> Result<Self, ExperimentalTreeCoverRetirementError> {
        if bytes.len() != TREECOVER_RETIREMENT_EVIDENCE_BYTES {
            return Err(ExperimentalTreeCoverRetirementError::InvalidEncodingLength);
        }
        let version = u16::from_be_bytes(
            bytes[0..2]
                .try_into()
                .map_err(|_| ExperimentalTreeCoverRetirementError::InvalidEncodingLength)?,
        );
        if version != TREECOVER_RETIREMENT_EVIDENCE_VERSION {
            return Err(ExperimentalTreeCoverRetirementError::UnsupportedVersion);
        }
        let mut offset = 2;
        let mut take_u32 = || {
            let value = bytes
                .get(offset..offset + 4)
                .and_then(|value| value.try_into().ok())
                .map(u32::from_be_bytes)
                .ok_or(ExperimentalTreeCoverRetirementError::InvalidEncodingLength)?;
            offset += 4;
            Ok(value)
        };
        let tree_version = take_u32()?;
        let transition_epoch = u64::from_be_bytes(
            bytes[offset..offset + 8]
                .try_into()
                .map_err(|_| ExperimentalTreeCoverRetirementError::InvalidEncodingLength)?,
        );
        offset += 8;
        let observation_epoch = u64::from_be_bytes(
            bytes[offset..offset + 8]
                .try_into()
                .map_err(|_| ExperimentalTreeCoverRetirementError::InvalidEncodingLength)?,
        );
        offset += 8;
        let mut take_remaining_u32 = || {
            let value = bytes
                .get(offset..offset + 4)
                .and_then(|value| value.try_into().ok())
                .map(u32::from_be_bytes)
                .ok_or(ExperimentalTreeCoverRetirementError::InvalidEncodingLength)?;
            offset += 4;
            Ok(value)
        };
        let evidence = Self {
            tree_version,
            transition_epoch,
            observation_epoch,
            impactful_commit_count: take_remaining_u32()?,
            c_leaf: take_remaining_u32()?,
            c_new: take_remaining_u32()?,
            c_old: take_remaining_u32()?,
            c_real: take_remaining_u32()?,
            c_ideal: take_remaining_u32()?,
            h_new_numerator: take_remaining_u32()?,
            h_new_denominator: take_remaining_u32()?,
            h_old_numerator: take_remaining_u32()?,
            h_old_denominator: take_remaining_u32()?,
            trigger_mask: *bytes
                .get(offset)
                .ok_or(ExperimentalTreeCoverRetirementError::InvalidEncodingLength)?,
        };
        evidence.validate()?;
        Ok(evidence)
    }

    /// Returns the exact canonical extension value.
    pub fn extension_value_bytes(self) -> Result<Vec<u8>, ExperimentalTreeCoverRetirementError> {
        self.validate()?;
        let mut bytes = Vec::with_capacity(TREECOVER_RETIREMENT_EVIDENCE_BYTES);
        bytes.extend_from_slice(&TREECOVER_RETIREMENT_EVIDENCE_VERSION.to_be_bytes());
        bytes.extend_from_slice(&self.tree_version.to_be_bytes());
        bytes.extend_from_slice(&self.transition_epoch.to_be_bytes());
        bytes.extend_from_slice(&self.observation_epoch.to_be_bytes());
        for value in [
            self.impactful_commit_count,
            self.c_leaf,
            self.c_new,
            self.c_old,
            self.c_real,
            self.c_ideal,
            self.h_new_numerator,
            self.h_new_denominator,
            self.h_old_numerator,
            self.h_old_denominator,
        ] {
            bytes.extend_from_slice(&value.to_be_bytes());
        }
        bytes.push(self.trigger_mask);
        debug_assert_eq!(bytes.len(), TREECOVER_RETIREMENT_EVIDENCE_BYTES);
        Ok(bytes)
    }

    /// Returns the active tree version before retirement.
    pub const fn tree_version(self) -> u32 {
        self.tree_version
    }

    /// Returns the epoch that began the transition.
    pub const fn transition_epoch(self) -> u64 {
        self.transition_epoch
    }

    /// Returns the accepted Commit epoch whose availability authorized retirement.
    pub const fn observation_epoch(self) -> u64 {
        self.observation_epoch
    }

    /// Returns the number of impactful post-transition Commits.
    pub const fn impactful_commit_count(self) -> u32 {
        self.impactful_commit_count
    }

    /// Returns endpoint counts in `(leaf, new, old, real, ideal)` order.
    pub const fn endpoint_counts(self) -> (u32, u32, u32, u32, u32) {
        (
            self.c_leaf,
            self.c_new,
            self.c_old,
            self.c_real,
            self.c_ideal,
        )
    }

    /// Returns the reduced new-tree health fraction.
    pub const fn h_new(self) -> (u32, u32) {
        (self.h_new_numerator, self.h_new_denominator)
    }

    /// Returns the reduced old-TreeCover health fraction.
    pub const fn h_old(self) -> (u32, u32) {
        (self.h_old_numerator, self.h_old_denominator)
    }

    /// Returns whether strict new-tree health authorized retirement.
    pub const fn retire_new(self) -> bool {
        self.trigger_mask & 1 != 0
    }

    /// Returns whether strict old-TreeCover degradation authorized retirement.
    pub const fn retire_old(self) -> bool {
        self.trigger_mask & 2 != 0
    }

    fn validate(self) -> Result<(), ExperimentalTreeCoverRetirementError> {
        let denominator = self
            .c_leaf
            .checked_sub(self.c_ideal)
            .filter(|value| *value > 0)
            .ok_or(ExperimentalTreeCoverRetirementError::InvalidEvidence)?;
        let expected_new = self
            .c_leaf
            .checked_sub(self.c_new)
            .ok_or(ExperimentalTreeCoverRetirementError::InvalidEvidence)?;
        let expected_old = self
            .c_leaf
            .checked_sub(self.c_old)
            .ok_or(ExperimentalTreeCoverRetirementError::InvalidEvidence)?;
        let new_divisor = greatest_common_divisor(expected_new, denominator);
        let old_divisor = greatest_common_divisor(expected_old, denominator);
        let retire_new =
            u64::from(self.h_new_numerator) * 10 > u64::from(self.h_new_denominator) * 7;
        let retire_old = u64::from(self.h_old_numerator) * 2 < u64::from(self.h_old_denominator);
        let expected_mask = u8::from(retire_new) | (u8::from(retire_old) << 1);
        if self.tree_version == 0
            || self.transition_epoch > self.observation_epoch
            || self.impactful_commit_count == 0
            || self.c_real > self.c_leaf
            || self.h_new_denominator == 0
            || self.h_old_denominator == 0
            || self.h_new_numerator != expected_new / new_divisor
            || self.h_new_denominator != denominator / new_divisor
            || self.h_old_numerator != expected_old / old_divisor
            || self.h_old_denominator != denominator / old_divisor
            || expected_mask == 0
            || self.trigger_mask != expected_mask
        {
            return Err(ExperimentalTreeCoverRetirementError::InvalidEvidence);
        }
        Ok(())
    }
}

fn greatest_common_divisor(mut left: u32, mut right: u32) -> u32 {
    while right != 0 {
        let remainder = left % right;
        left = right;
        right = remainder;
    }
    left.max(1)
}

/// Public tree-array node identifier for one experimental TreeKEM resolution key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ExperimentalResolutionNodeId(u32);

impl ExperimentalResolutionNodeId {
    /// Creates an identifier from the public TreeKEM node index.
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    /// Returns the public TreeKEM node index.
    pub const fn as_u32(self) -> u32 {
        self.0
    }
}

/// Public mKyber material bound to one TreeKEM resolution node.
///
/// This is distinct from the signed KeyPackage extension: the same shape is
/// required for parent nodes, which have no KeyPackage. The feature-gated
/// TreeSync `EncryptionKey` stores this value beside the corresponding
/// classical TreeKEM public key.
#[derive(
    Clone, PartialEq, Eq, Hash, TlsSerialize, TlsDeserialize, TlsDeserializeBytes, TlsSize,
)]
pub struct ExperimentalMkyberNodePublicKey {
    domain: [u8; 32],
    public_key: [u8; ENCAPSULATION_KEY_BYTES],
}

impl ExperimentalMkyberNodePublicKey {
    /// Converts a typed mKyber encapsulation key into serializable public node material.
    pub fn from_mkyber_key(public_key: &MkyberEncapsulationKey) -> Self {
        Self {
            domain: *public_key.domain().as_bytes(),
            public_key: *public_key.as_bytes(),
        }
    }

    /// Reconstructs the typed public mKyber key for a hybrid sender operation.
    pub fn to_mkyber_key(&self) -> Result<MkyberEncapsulationKey, ExperimentalMkyberError> {
        MkyberEncapsulationKey::from_bytes(MkyberDomain::new(self.domain), &self.public_key)
            .map_err(|_| ExperimentalMkyberError::InvalidPublicKey)
    }

    /// Returns the strict canonical public-node serialization.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ExperimentalNodeKeyError> {
        let mut bytes =
            Vec::with_capacity(core::mem::size_of_val(&self.domain) + ENCAPSULATION_KEY_BYTES);
        bytes.extend_from_slice(&self.domain);
        bytes.extend_from_slice(&self.public_key);
        Ok(bytes)
    }

    /// Parses exact canonical public-node serialization with no trailing data.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ExperimentalNodeKeyError> {
        let expected_length = core::mem::size_of::<[u8; 32]>() + ENCAPSULATION_KEY_BYTES;
        if bytes.len() != expected_length {
            return Err(ExperimentalNodeKeyError::InvalidPublicEncoding);
        }
        let (domain, public_key) = bytes.split_at(core::mem::size_of::<[u8; 32]>());
        let domain = domain
            .try_into()
            .map_err(|_| ExperimentalNodeKeyError::InvalidPublicEncoding)?;
        let public_key = public_key
            .try_into()
            .map_err(|_| ExperimentalNodeKeyError::InvalidPublicEncoding)?;
        Ok(Self { domain, public_key })
    }

    /// Returns the public mKyber domain.
    pub const fn domain(&self) -> MkyberDomain {
        MkyberDomain::new(self.domain)
    }
}

impl fmt::Debug for ExperimentalMkyberNodePublicKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExperimentalMkyberNodePublicKey")
            .field("domain", &self.domain())
            .field("public_key_bytes", &ENCAPSULATION_KEY_BYTES)
            .finish()
    }
}

impl Serialize for ExperimentalMkyberNodePublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("ExperimentalMkyberNodePublicKey", 2)?;
        state.serialize_field("domain", &self.domain)?;
        state.serialize_field("public_key", self.public_key.as_slice())?;
        state.end()
    }
}

#[derive(Deserialize)]
struct ExperimentalMkyberNodePublicKeySerde {
    domain: [u8; 32],
    public_key: Vec<u8>,
}

impl<'de> Deserialize<'de> for ExperimentalMkyberNodePublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = ExperimentalMkyberNodePublicKeySerde::deserialize(deserializer)?;
        let mut bytes =
            Vec::with_capacity(core::mem::size_of_val(&wire.domain) + wire.public_key.len());
        bytes.extend_from_slice(&wire.domain);
        bytes.extend_from_slice(&wire.public_key);
        Self::from_canonical_bytes(&bytes).map_err(serde::de::Error::custom)
    }
}

/// Errors returned by experimental node-key lifecycle operations.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ExperimentalNodeKeyError {
    /// The requested public encoding was malformed or had trailing data.
    #[error("the mKyber node public-key encoding is invalid")]
    InvalidPublicEncoding,
    /// A private mKyber node key was requested after retirement or before creation.
    #[error("no mKyber private key is available for resolution node {0}")]
    MissingPrivateKey(u32),
    /// A new key would overwrite live private material for the same node.
    #[error("mKyber private material already exists for resolution node {0}")]
    DuplicatePrivateKey(u32),
    /// The educational mKyber backend could not create or reconstruct key material.
    #[error("mKyber node-key operation failed")]
    Mkyber,
}

/// Private mKyber node material retained only in the local fork lifecycle store.
///
/// It is not debug-formatted. Its fixed-size bytes are zeroized when the record
/// is retired or dropped. It is crate-visible solely so `EncryptionKeyPair` can
/// persist a matching private record through the existing private-key store.
#[derive(Clone, TlsSerialize, TlsDeserialize, TlsDeserializeBytes, TlsSize)]
pub(crate) struct ExperimentalMkyberNodePrivateKey {
    domain: [u8; 32],
    private_key: [u8; DECAPSULATION_KEY_BYTES],
}

impl ExperimentalMkyberNodePrivateKey {
    pub(crate) fn from_mkyber_key(
        private_key: MkyberDecapsulationKey,
    ) -> Result<Self, ExperimentalNodeKeyError> {
        let domain = *private_key.domain().as_bytes();
        let private_key = private_key
            .as_bytes()
            .try_into()
            .map_err(|_| ExperimentalNodeKeyError::Mkyber)?;
        Ok(Self {
            domain,
            private_key,
        })
    }

    pub(crate) fn to_mkyber_key(&self) -> Result<MkyberDecapsulationKey, ExperimentalNodeKeyError> {
        MkyberDecapsulationKey::from_bytes(
            MkyberDomain::new(self.domain),
            self.private_key.to_vec(),
        )
        .map_err(|_| ExperimentalNodeKeyError::Mkyber)
    }
}

impl Serialize for ExperimentalMkyberNodePrivateKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("ExperimentalMkyberNodePrivateKey", 2)?;
        state.serialize_field("domain", &self.domain)?;
        state.serialize_field("private_key", self.private_key.as_slice())?;
        state.end()
    }
}

#[derive(Deserialize)]
struct ExperimentalMkyberNodePrivateKeySerde {
    domain: [u8; 32],
    private_key: Vec<u8>,
}

impl<'de> Deserialize<'de> for ExperimentalMkyberNodePrivateKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = ExperimentalMkyberNodePrivateKeySerde::deserialize(deserializer)?;
        let private_key = wire
            .private_key
            .try_into()
            .map_err(|_| serde::de::Error::custom("invalid mKyber private-key length"))?;
        Ok(Self {
            domain: wire.domain,
            private_key,
        })
    }
}

impl Drop for ExperimentalMkyberNodePrivateKey {
    fn drop(&mut self) {
        self.private_key.zeroize();
    }
}

impl fmt::Debug for ExperimentalMkyberNodePrivateKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExperimentalMkyberNodePrivateKey")
            .field("domain", &MkyberDomain::new(self.domain))
            .field("private_key", &"<redacted>")
            .finish()
    }
}

/// Local private-key lifecycle for experimental leaf and parent resolution nodes.
///
/// The public key returned from generation belongs in the authenticated fork
/// tree. This store retains only its matching private decapsulation material.
/// A TreeSync integration must insert, persist, and retire records atomically
/// with the corresponding public tree mutation.
#[derive(Default, Debug)]
pub struct ExperimentalMkyberNodeKeyStore {
    private_keys: BTreeMap<ExperimentalResolutionNodeId, ExperimentalMkyberNodePrivateKey>,
}

impl ExperimentalMkyberNodeKeyStore {
    /// Generates and records a fresh mKyber pair for one leaf or parent node.
    pub fn generate_for_node(
        &mut self,
        node_id: ExperimentalResolutionNodeId,
        domain: MkyberDomain,
    ) -> Result<ExperimentalMkyberNodePublicKey, ExperimentalNodeKeyError> {
        if self.private_keys.contains_key(&node_id) {
            return Err(ExperimentalNodeKeyError::DuplicatePrivateKey(
                node_id.as_u32(),
            ));
        }
        let (public_key, private_key) = EducationalMkyber512Reference
            .keygen_with_os_rng(domain)
            .map_err(|_| ExperimentalNodeKeyError::Mkyber)?
            .into_parts();
        let public_key = ExperimentalMkyberNodePublicKey::from_mkyber_key(&public_key);
        self.private_keys.insert(
            node_id,
            ExperimentalMkyberNodePrivateKey::from_mkyber_key(private_key)?,
        );
        Ok(public_key)
    }

    /// Returns a typed private key for one local hybrid receiver operation.
    pub fn private_key_for(
        &self,
        node_id: ExperimentalResolutionNodeId,
    ) -> Result<MkyberDecapsulationKey, ExperimentalNodeKeyError> {
        self.private_keys
            .get(&node_id)
            .ok_or(ExperimentalNodeKeyError::MissingPrivateKey(
                node_id.as_u32(),
            ))?
            .to_mkyber_key()
    }

    /// Retires one private key record and zeroizes its stored bytes on drop.
    pub fn retire_node(&mut self, node_id: ExperimentalResolutionNodeId) -> bool {
        self.private_keys.remove(&node_id).is_some()
    }

    /// Returns the number of locally retained private node keys.
    pub fn retained_key_count(&self) -> usize {
        self.private_keys.len()
    }
}

/// Errors returned while admitting canonical hybrid delivery bytes into the fork.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ExperimentalHybridDeliveryError {
    /// The supplied bytes are not one exact canonical hybrid path ciphertext.
    #[error("the hybrid path delivery bytes are malformed or non-canonical")]
    InvalidCanonicalEncoding,
    /// The delivery's embedded node index differs from the enclosing UpdatePath node.
    #[error("the hybrid path delivery node index {actual} does not match expected {expected}")]
    PathNodeMismatch {
        /// Node index supplied by the enclosing experimental UpdatePath node.
        expected: u32,
        /// Node index authenticated inside the hybrid delivery bytes.
        actual: u32,
    },
}

/// Canonical public hybrid delivery bytes for one experimental UpdatePath node.
///
/// This is a fork-owned value, intended to replace the standard
/// `encrypted_path_secret` vector within an experimental UpdatePath node. It
/// stores no parsed upstream OpenMLS type, no mKyber private key, and no path
/// secret. Its constructor validates the canonical hybrid wire value before it
/// can enter fork state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExperimentalHybridPathDelivery {
    path_node_index: u32,
    canonical_bytes: Vec<u8>,
}

/// Public aggregate counts from one emitted experimental hybrid Commit.
///
/// Each hybrid UpdatePath delivery contains exactly one common mKyber
/// ciphertext and one recipient mKyber/classical-HPKE pair per recipient.
/// This type deliberately keeps counts only; it never contains a delivery,
/// ciphertext, key, or path secret.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ExperimentalHybridCommitMetrics {
    hybrid_path_delivery_count: u32,
    mkyber_common_ciphertext_count: u32,
    mkyber_recipient_ciphertext_count: u32,
    classical_hpke_encapsulation_count: u32,
}

/// Public tree namespace used by one authenticated hybrid delivery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExperimentalHybridDeliveryTree {
    /// RFC MLS binary TreeKEM node indexes.
    BinaryTree,
    /// Experimental active-quaternary leaf ordinals.
    ActiveQuaternaryTree,
}

impl ExperimentalHybridDeliveryTree {
    /// Returns a stable public report label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BinaryTree => "binary_tree",
            Self::ActiveQuaternaryTree => "active_quaternary_tree",
        }
    }
}

/// Ciphertext-free public recipient set from one signed UpdatePath delivery.
///
/// The surrounding Commit authenticates the source delivery. This record
/// retains only public node indexes and never retains ciphertext or key bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExperimentalHybridRecipientSet {
    delivery_tree: ExperimentalHybridDeliveryTree,
    path_node_index: u32,
    recipient_node_indices: Vec<u32>,
    canonical_delivery_bytes: u32,
}

impl ExperimentalHybridRecipientSet {
    pub(crate) fn new(
        delivery_tree: ExperimentalHybridDeliveryTree,
        path_node_index: u32,
        recipient_node_indices: Vec<u32>,
        canonical_delivery_bytes: u32,
    ) -> Self {
        Self {
            delivery_tree,
            path_node_index,
            recipient_node_indices,
            canonical_delivery_bytes,
        }
    }

    /// Returns the tree namespace in which the indexes are interpreted.
    pub const fn delivery_tree(&self) -> ExperimentalHybridDeliveryTree {
        self.delivery_tree
    }

    /// Returns the authenticated sender-path node index.
    pub const fn path_node_index(&self) -> u32 {
        self.path_node_index
    }

    /// Returns the authenticated public recipient node indexes.
    pub fn recipient_node_indices(&self) -> &[u32] {
        &self.recipient_node_indices
    }

    /// Returns the exact canonical hybrid-delivery length authenticated by the
    /// surrounding signed Commit.
    pub const fn canonical_delivery_bytes(&self) -> u32 {
        self.canonical_delivery_bytes
    }
}

/// Ciphertext-free public recipient sets extracted from one signed Commit.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ExperimentalHybridCommitTopology {
    recipient_sets: Vec<ExperimentalHybridRecipientSet>,
}

impl ExperimentalHybridCommitTopology {
    pub(crate) fn new(recipient_sets: Vec<ExperimentalHybridRecipientSet>) -> Self {
        Self { recipient_sets }
    }

    /// Returns each path-level recipient set in authenticated wire order.
    pub fn recipient_sets(&self) -> &[ExperimentalHybridRecipientSet] {
        &self.recipient_sets
    }
}

impl ExperimentalHybridCommitMetrics {
    pub(crate) fn record_delivery(&mut self, recipient_count: usize) -> Result<(), LibraryError> {
        let recipient_count = u32::try_from(recipient_count)
            .map_err(|_| LibraryError::custom("experimental hybrid delivery count overflowed"))?;
        self.hybrid_path_delivery_count = self
            .hybrid_path_delivery_count
            .checked_add(1)
            .ok_or_else(|| LibraryError::custom("experimental hybrid delivery count overflowed"))?;
        self.mkyber_common_ciphertext_count = self
            .mkyber_common_ciphertext_count
            .checked_add(1)
            .ok_or_else(|| LibraryError::custom("experimental hybrid delivery count overflowed"))?;
        self.mkyber_recipient_ciphertext_count = self
            .mkyber_recipient_ciphertext_count
            .checked_add(recipient_count)
            .ok_or_else(|| LibraryError::custom("experimental hybrid delivery count overflowed"))?;
        self.classical_hpke_encapsulation_count = self
            .classical_hpke_encapsulation_count
            .checked_add(recipient_count)
            .ok_or_else(|| LibraryError::custom("experimental hybrid delivery count overflowed"))?;
        Ok(())
    }

    /// Returns the count of hybrid UpdatePath deliveries.
    pub const fn hybrid_path_delivery_count(self) -> u32 {
        self.hybrid_path_delivery_count
    }

    /// Returns the count of one-per-delivery mKyber common ciphertexts.
    pub const fn mkyber_common_ciphertext_count(self) -> u32 {
        self.mkyber_common_ciphertext_count
    }

    /// Returns the count of per-recipient mKyber ciphertext components.
    pub const fn mkyber_recipient_ciphertext_count(self) -> u32 {
        self.mkyber_recipient_ciphertext_count
    }

    /// Returns the count of per-recipient classical HPKE encapsulations.
    pub const fn classical_hpke_encapsulation_count(self) -> u32 {
        self.classical_hpke_encapsulation_count
    }
}

/// Classical HPKE execution provider bound to the local OpenMLS fork types.
///
/// It implements the provider-neutral hybrid interface without exposing its
/// local provider or trait objects to the upstream hybrid-wire crate.
#[derive(Debug, Default)]
pub struct ForkClassicalHpkeProvider(openmls_rust_crypto::OpenMlsRustCrypto);

/// Builds the fixed binary-tree hybrid context from authenticated GroupContext bytes.
#[cfg(feature = "experimental-hybrid")]
pub(crate) fn binary_hybrid_context(
    crypto: &impl OpenMlsCrypto,
    ciphersuite: Ciphersuite,
    serialized_group_context: &[u8],
    path_node_index: u32,
    domain: MkyberDomain,
) -> Result<hybrid_path_secret::HybridPathLevelContext, LibraryError> {
    if ciphersuite != Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 {
        return Err(LibraryError::custom(
            "unsupported experimental hybrid ciphersuite",
        ));
    }
    let group_context = GroupContext::tls_deserialize_exact(serialized_group_context)
        .map_err(|_| LibraryError::custom("invalid experimental hybrid GroupContext"))?;
    if group_context.ciphersuite() != ciphersuite {
        return Err(LibraryError::custom(
            "experimental hybrid GroupContext ciphersuite mismatch",
        ));
    }
    let group_context_hash = crypto
        .hash(ciphersuite.hash_algorithm(), serialized_group_context)
        .map_err(LibraryError::unexpected_crypto_error)?;
    let group_context_hash = group_context_hash.as_slice().try_into().map_err(|_| {
        LibraryError::custom("invalid experimental hybrid GroupContext hash length")
    })?;
    Ok(hybrid_path_secret::HybridPathLevelContext::new(
        group_context.group_id().as_slice().to_vec(),
        group_context.epoch().as_u64(),
        0,
        hybrid_path_secret::TreeArity::Binary,
        hybrid_path_secret::PathNodeIndex::new(path_node_index),
        domain,
        group_context_hash,
    ))
}

/// Builds the domain-separated quaternary-root hybrid context from an
/// authenticated GroupContext. The current experimental carrier remains the
/// binary MLS UpdatePath, but this context commits the delivered secret to the
/// target quaternary parent and adaptive tree version.
#[cfg(feature = "experimental-hybrid")]
pub(crate) fn quaternary_hybrid_context(
    crypto: &impl OpenMlsCrypto,
    ciphersuite: Ciphersuite,
    serialized_group_context: &[u8],
    tree_version: u32,
    parent_depth: u8,
    parent_ordinal: u32,
    domain: MkyberDomain,
) -> Result<hybrid_path_secret::HybridPathLevelContext, LibraryError> {
    let parent_node_index = quaternary_parent_node_index(parent_depth, parent_ordinal)?;
    if ciphersuite != Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 {
        return Err(LibraryError::custom(
            "unsupported experimental hybrid ciphersuite",
        ));
    }
    let group_context = GroupContext::tls_deserialize_exact(serialized_group_context)
        .map_err(|_| LibraryError::custom("invalid experimental hybrid GroupContext"))?;
    if group_context.ciphersuite() != ciphersuite {
        return Err(LibraryError::custom(
            "experimental hybrid GroupContext ciphersuite mismatch",
        ));
    }
    let group_context_hash = crypto
        .hash(ciphersuite.hash_algorithm(), serialized_group_context)
        .map_err(LibraryError::unexpected_crypto_error)?;
    let group_context_hash = group_context_hash.as_slice().try_into().map_err(|_| {
        LibraryError::custom("invalid experimental hybrid GroupContext hash length")
    })?;
    Ok(hybrid_path_secret::HybridPathLevelContext::new(
        group_context.group_id().as_slice().to_vec(),
        group_context.epoch().as_u64(),
        tree_version,
        hybrid_path_secret::TreeArity::Quaternary,
        hybrid_path_secret::PathNodeIndex::new(parent_node_index),
        domain,
        group_context_hash,
    ))
}

/// Encodes an unambiguous quaternary parent address for the hybrid delivery
/// context and canonical ciphertext. The root is `(0, 0) -> 0`; no parent
/// ordinal can occupy the high eight depth bits.
#[cfg(feature = "experimental-hybrid")]
pub(crate) fn quaternary_parent_node_index(
    parent_depth: u8,
    parent_ordinal: u32,
) -> Result<u32, LibraryError> {
    if parent_ordinal > 0x00ff_ffff {
        return Err(LibraryError::custom(
            "experimental quaternary parent ordinal exceeds wire range",
        ));
    }
    Ok((u32::from(parent_depth) << 24) | parent_ordinal)
}

impl ClassicalHpkeProvider for ForkClassicalHpkeProvider {
    fn setup_sender_and_export(
        &self,
        recipient_public_key: &ClassicalHpkePublicKey,
        info: &[u8],
        exporter_context: &[u8],
    ) -> Result<ClassicalHpkeSenderOutput, HybridPathLevelError> {
        let (encapsulation, shared_secret) = self
            .0
            .crypto()
            .hpke_setup_sender_and_export(
                Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519.hpke_config(),
                recipient_public_key.as_bytes(),
                info,
                exporter_context,
                CLASSICAL_SHARED_SECRET_BYTES,
            )
            .map_err(|_| HybridPathLevelError::ClassicalHpke)?;
        let encapsulation = encapsulation.as_slice().try_into().map_err(|_| {
            HybridPathLevelError::InvalidClassicalEncapsulationLength(encapsulation.len())
        })?;
        let shared_secret = ClassicalSharedSecret::from_bytes(&shared_secret)
            .map_err(|_| HybridPathLevelError::Kdf)?;
        Ok(ClassicalHpkeSenderOutput::new(encapsulation, shared_secret))
    }

    fn setup_receiver_and_export(
        &self,
        encapsulation: &[u8; CLASSICAL_ENCAPSULATION_BYTES],
        recipient_private_key: &ClassicalHpkePrivateKey,
        info: &[u8],
        exporter_context: &[u8],
    ) -> Result<ClassicalSharedSecret, HybridPathLevelError> {
        let shared_secret = self
            .0
            .crypto()
            .hpke_setup_receiver_and_export(
                Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519.hpke_config(),
                encapsulation,
                recipient_private_key.as_bytes(),
                info,
                exporter_context,
                CLASSICAL_SHARED_SECRET_BYTES,
            )
            .map_err(|_| HybridPathLevelError::ClassicalHpke)?;
        ClassicalSharedSecret::from_bytes(&shared_secret).map_err(|_| HybridPathLevelError::Kdf)
    }
}

impl ExperimentalHybridPathDelivery {
    /// Validates and retains exact canonical hybrid bytes for one path node.
    pub fn from_canonical_bytes(
        expected_path_node_index: u32,
        canonical_bytes: Vec<u8>,
    ) -> Result<Self, ExperimentalHybridDeliveryError> {
        let ciphertext = HybridPathCiphertext::from_commit_authenticated_bytes(&canonical_bytes)
            .map_err(|_| ExperimentalHybridDeliveryError::InvalidCanonicalEncoding)?;
        let actual_path_node_index = ciphertext.path_node_index().as_u32();
        if actual_path_node_index != expected_path_node_index {
            return Err(ExperimentalHybridDeliveryError::PathNodeMismatch {
                expected: expected_path_node_index,
                actual: actual_path_node_index,
            });
        }
        if ciphertext
            .commit_authenticated_bytes()
            .map_err(|_| ExperimentalHybridDeliveryError::InvalidCanonicalEncoding)?
            != canonical_bytes
        {
            return Err(ExperimentalHybridDeliveryError::InvalidCanonicalEncoding);
        }

        Ok(Self {
            path_node_index: expected_path_node_index,
            canonical_bytes,
        })
    }

    /// Returns the enclosing experimental UpdatePath-node index.
    pub const fn path_node_index(&self) -> u32 {
        self.path_node_index
    }

    /// Returns the validated canonical bytes that the enclosing MLS Commit must authenticate.
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }
}

/// Public mKyber encapsulation key associated with one experimental recipient.
///
/// The canonical extension value is exactly `version || domain || public_key`,
/// where `version` is a two-byte big-endian integer, `domain` is 32 bytes, and
/// `public_key` is the 768-byte thesis-local mKyber512 encapsulation key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MkyberRecipientKeyMaterial {
    public_key: MkyberEncapsulationKey,
}

impl MkyberRecipientKeyMaterial {
    /// Creates material from a typed public mKyber encapsulation key.
    pub const fn new(public_key: MkyberEncapsulationKey) -> Self {
        Self { public_key }
    }

    /// Creates material from canonical public domain and key bytes.
    pub fn from_parts(
        domain: [u8; 32],
        public_key: [u8; ENCAPSULATION_KEY_BYTES],
    ) -> Result<Self, ExperimentalMkyberError> {
        MkyberEncapsulationKey::from_bytes(MkyberDomain::new(domain), &public_key)
            .map(Self::new)
            .map_err(|_| ExperimentalMkyberError::InvalidPublicKey)
    }

    /// Returns the typed public mKyber encapsulation key.
    pub const fn public_key(&self) -> &MkyberEncapsulationKey {
        &self.public_key
    }

    /// Returns the typed public mKyber domain identifier.
    pub const fn domain(&self) -> MkyberDomain {
        self.public_key.domain()
    }

    /// Returns the canonical 768-byte public mKyber encapsulation key.
    pub const fn public_key_bytes(&self) -> &[u8; ENCAPSULATION_KEY_BYTES] {
        self.public_key.as_bytes()
    }

    /// Encodes the strict version-1 private-use extension value.
    pub fn to_extension_value(&self) -> [u8; MKYBER_RECIPIENT_KEY_MATERIAL_BYTES] {
        let mut encoded = [0_u8; MKYBER_RECIPIENT_KEY_MATERIAL_BYTES];
        encoded[..2].copy_from_slice(&MKYBER_RECIPIENT_KEY_MATERIAL_VERSION.to_be_bytes());
        encoded[2..34].copy_from_slice(self.domain().as_bytes());
        encoded[34..].copy_from_slice(self.public_key_bytes());
        encoded
    }

    /// Decodes one strict version-1 private-use extension value.
    pub fn from_extension_value(value: &[u8]) -> Result<Self, ExperimentalMkyberError> {
        if value.len() != MKYBER_RECIPIENT_KEY_MATERIAL_BYTES {
            return Err(ExperimentalMkyberError::InvalidEncodingLength {
                expected: MKYBER_RECIPIENT_KEY_MATERIAL_BYTES,
                actual: value.len(),
            });
        }

        let version = u16::from_be_bytes([value[0], value[1]]);
        if version != MKYBER_RECIPIENT_KEY_MATERIAL_VERSION {
            return Err(ExperimentalMkyberError::UnsupportedVersion(version));
        }

        let mut domain = [0_u8; 32];
        domain.copy_from_slice(&value[2..34]);
        let mut public_key = [0_u8; ENCAPSULATION_KEY_BYTES];
        public_key.copy_from_slice(&value[34..]);
        Self::from_parts(domain, public_key)
    }

    /// Returns this material as the private-use KeyPackage extension.
    pub fn as_key_package_extension(&self) -> Extension {
        Extension::Unknown(
            MKYBER_RECIPIENT_KEY_PACKAGE_EXTENSION_TYPE,
            UnknownExtension(self.to_extension_value().to_vec()),
        )
    }

    /// Returns a KeyPackage extension list containing only this public key.
    ///
    /// Callers that need other KeyPackage extensions must combine them with
    /// [`Extensions::from_vec`] and preserve this unique private-use type.
    pub fn key_package_extensions(&self) -> Result<Extensions<KeyPackage>, InvalidExtensionError> {
        Extensions::single(self.as_key_package_extension())
    }

    /// Extracts strict public mKyber material from KeyPackage extensions.
    pub fn from_key_package_extensions(
        extensions: &Extensions<KeyPackage>,
    ) -> Result<Self, ExperimentalMkyberError> {
        let extension = extensions
            .unknown(MKYBER_RECIPIENT_KEY_PACKAGE_EXTENSION_TYPE)
            .ok_or(ExperimentalMkyberError::MissingRecipientKeyMaterial)?;
        Self::from_extension_value(&extension.0)
    }

    /// Extracts material only when the KeyPackage advertises every required
    /// experimental extension capability.
    pub fn from_key_package(key_package: &KeyPackage) -> Result<Self, ExperimentalMkyberError> {
        if !supports_mkyber_recipient_capabilities(key_package.leaf_node().capabilities()) {
            return Err(ExperimentalMkyberError::MissingExperimentalCapability);
        }

        Self::from_key_package_extensions(key_package.extensions())
    }
}

/// Returns the extension types every experimental mKyber recipient must advertise.
pub const fn required_mkyber_recipient_capabilities() -> [ExtensionType; 3] {
    [
        ExtensionType::Unknown(ADAPTIVE_HYBRID_TREE_STATE_EXTENSION_TYPE),
        ExtensionType::Unknown(MKYBER_RECIPIENT_KEY_PACKAGE_EXTENSION_TYPE),
        ExtensionType::Unknown(TREECOVER_RETIREMENT_EVIDENCE_EXTENSION_TYPE),
    ]
}

/// Returns default MLS capabilities augmented for an experimental mKyber recipient.
pub fn mkyber_recipient_capabilities() -> Capabilities {
    Capabilities::new(
        None,
        None,
        Some(&required_mkyber_recipient_capabilities()),
        None,
        None,
    )
}

/// Adds the required experimental capabilities without discarding caller configuration.
pub(crate) fn ensure_mkyber_recipient_capabilities(capabilities: &mut Capabilities) {
    for extension_type in required_mkyber_recipient_capabilities() {
        capabilities.add_extension_capability(extension_type);
    }
}

/// Returns whether capabilities advertise all extensions required by this fork.
pub fn supports_mkyber_recipient_capabilities(capabilities: &Capabilities) -> bool {
    required_mkyber_recipient_capabilities()
        .iter()
        .all(|required| capabilities.extensions().contains(required))
}
