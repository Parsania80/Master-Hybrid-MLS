//! Thesis-local experimental mKyber recipient capability and key material.
//!
//! This module defines only public KeyPackage material.  It does not alter an
//! UpdatePath, derive a path secret, or make an experimental commit available.
//! The private-use values are intentionally not standardized or interoperable.

use mkyber::{MkyberDomain, MkyberEncapsulationKey, ENCAPSULATION_KEY_BYTES};
use thiserror::Error;

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
