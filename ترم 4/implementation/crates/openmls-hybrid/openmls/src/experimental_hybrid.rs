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
    ENCAPSULATION_KEY_BYTES,
};
use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;
use tls_codec::{TlsDeserialize, TlsDeserializeBytes, TlsSerialize, TlsSize};
use zeroize::Zeroize;

use crate::prelude::{Ciphersuite, OpenMlsCrypto, OpenMlsProvider};
use crate::{
    extensions::{
        errors::InvalidExtensionError, Extension, ExtensionType, Extensions, UnknownExtension,
    },
    key_packages::KeyPackage,
    treesync::node::leaf_node::Capabilities,
};

/// Private-use GroupContext extension carrying authenticated adaptive-tree state.
///
/// This remains required for every experimental member by ADR 0005.  This
/// module only advertises it; a later UpdatePath implementation must validate
/// and authenticate its value through the MLS commit path.
pub const ADAPTIVE_HYBRID_TREE_STATE_EXTENSION_TYPE: u16 = 0xF001;

/// Private-use KeyPackage extension carrying one mKyber recipient public key.
pub const MKYBER_RECIPIENT_KEY_PACKAGE_EXTENSION_TYPE: u16 = 0xF002;

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
/// It is not debug-formatted. Its byte vector is zeroized when the record is
/// retired or dropped. A future storage integration may serialize this internal
/// record only through the existing private key-store boundary.
struct ExperimentalMkyberNodePrivateKey {
    domain: MkyberDomain,
    private_key: Vec<u8>,
}

impl ExperimentalMkyberNodePrivateKey {
    fn from_mkyber_key(private_key: MkyberDecapsulationKey) -> Self {
        Self {
            domain: private_key.domain(),
            private_key: private_key.as_bytes().to_vec(),
        }
    }

    fn to_mkyber_key(&self) -> Result<MkyberDecapsulationKey, ExperimentalNodeKeyError> {
        MkyberDecapsulationKey::from_bytes(self.domain, self.private_key.clone())
            .map_err(|_| ExperimentalNodeKeyError::Mkyber)
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
            .field("domain", &self.domain)
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
            ExperimentalMkyberNodePrivateKey::from_mkyber_key(private_key),
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

/// Classical HPKE execution provider bound to the local OpenMLS fork types.
///
/// It implements the provider-neutral hybrid interface without exposing its
/// local provider or trait objects to the upstream hybrid-wire crate.
#[derive(Debug, Default)]
pub struct ForkClassicalHpkeProvider(openmls_rust_crypto::OpenMlsRustCrypto);

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
pub const fn required_mkyber_recipient_capabilities() -> [ExtensionType; 2] {
    [
        ExtensionType::Unknown(ADAPTIVE_HYBRID_TREE_STATE_EXTENSION_TYPE),
        ExtensionType::Unknown(MKYBER_RECIPIENT_KEY_PACKAGE_EXTENSION_TYPE),
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

/// Returns whether capabilities advertise all extensions required by this fork.
pub fn supports_mkyber_recipient_capabilities(capabilities: &Capabilities) -> bool {
    required_mkyber_recipient_capabilities()
        .iter()
        .all(|required| capabilities.extensions().contains(required))
}
