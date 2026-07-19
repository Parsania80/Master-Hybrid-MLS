#![forbid(unsafe_code)]

//! Authenticated wire boundary for experimental hybrid path-secret delivery.
//!
//! `HybridPathCiphertext` is the thesis-local, versioned UpdatePath-node
//! payload from ADR 0004. Its canonical bytes must be covered by the outer
//! experimental MLS commit authentication. The later hybrid AEAD must also
//! authenticate its canonical context. This crate does not implement the KDF,
//! AEAD, or OpenMLS fork integration yet.

use core::fmt;

use mkyber::{MkyberCommonCiphertext, MkyberDomain, MkyberRecipientCiphertext};
use thiserror::Error;
use tls_codec::{
    Deserialize as TlsDeserializeTrait, Serialize as TlsSerializeTrait, TlsDeserialize,
    TlsSerialize, TlsSize, TlsVecU16,
};

/// Version of the thesis-local hybrid UpdatePath wire value.
pub const HYBRID_PATH_CIPHERTEXT_VERSION: u16 = 1;
/// DHKEM(X25519, HKDF-SHA256) encapsulation size in the fixed ciphersuite.
pub const CLASSICAL_ENCAPSULATION_BYTES: usize = 32;
/// AES-128-GCM ciphertext size for one 32-byte MLS path secret plus its tag.
pub const ENCRYPTED_PATH_SECRET_BYTES: usize = 48;

/// Public path-node index for one experimental UpdatePath level.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PathNodeIndex(u32);

impl PathNodeIndex {
    /// Creates a public path-node index.
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    /// Returns the canonical numeric node index.
    pub const fn as_u32(self) -> u32 {
        self.0
    }
}

/// Public recipient-node index for one hybrid recipient record.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RecipientNodeIndex(u32);

impl RecipientNodeIndex {
    /// Creates a public recipient-node index.
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    /// Returns the canonical numeric node index.
    pub const fn as_u32(self) -> u32 {
        self.0
    }
}

/// One strictly ordered hybrid delivery record for a recipient node.
#[derive(Clone, PartialEq, Eq)]
pub struct HybridRecipientCiphertext {
    recipient_node_index: RecipientNodeIndex,
    classical_encapsulation: [u8; CLASSICAL_ENCAPSULATION_BYTES],
    mkyber_recipient: MkyberRecipientCiphertext,
    encrypted_path_secret: [u8; ENCRYPTED_PATH_SECRET_BYTES],
}

impl HybridRecipientCiphertext {
    /// Creates one recipient record from fixed-size public wire artifacts.
    pub const fn new(
        recipient_node_index: RecipientNodeIndex,
        classical_encapsulation: [u8; CLASSICAL_ENCAPSULATION_BYTES],
        mkyber_recipient: MkyberRecipientCiphertext,
        encrypted_path_secret: [u8; ENCRYPTED_PATH_SECRET_BYTES],
    ) -> Self {
        Self {
            recipient_node_index,
            classical_encapsulation,
            mkyber_recipient,
            encrypted_path_secret,
        }
    }

    /// Returns the public recipient-node binding.
    pub const fn recipient_node_index(&self) -> RecipientNodeIndex {
        self.recipient_node_index
    }

    /// Returns the fixed-size public classical encapsulation.
    pub const fn classical_encapsulation(&self) -> &[u8; CLASSICAL_ENCAPSULATION_BYTES] {
        &self.classical_encapsulation
    }

    /// Returns the recipient-specific public mKyber component.
    pub const fn mkyber_recipient(&self) -> &MkyberRecipientCiphertext {
        &self.mkyber_recipient
    }

    /// Returns the public AEAD ciphertext for the MLS path secret.
    pub const fn encrypted_path_secret(&self) -> &[u8; ENCRYPTED_PATH_SECRET_BYTES] {
        &self.encrypted_path_secret
    }
}

impl fmt::Debug for HybridRecipientCiphertext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HybridRecipientCiphertext")
            .field("recipient_node_index", &self.recipient_node_index)
            .field(
                "classical_encapsulation_bytes",
                &CLASSICAL_ENCAPSULATION_BYTES,
            )
            .field(
                "mkyber_recipient_bytes",
                &self.mkyber_recipient.as_bytes().len(),
            )
            .field("encrypted_path_secret_bytes", &ENCRYPTED_PATH_SECRET_BYTES)
            .finish()
    }
}

/// A versioned hybrid ciphertext set for one experimental UpdatePath node.
#[derive(Clone, PartialEq, Eq)]
pub struct HybridPathCiphertext {
    path_node_index: PathNodeIndex,
    mkyber_domain: MkyberDomain,
    mkyber_common: MkyberCommonCiphertext,
    recipients: Vec<HybridRecipientCiphertext>,
}

impl HybridPathCiphertext {
    /// Validates and constructs a canonical hybrid path ciphertext.
    ///
    /// Recipient records must be non-empty and strictly increasing by their
    /// recipient-node index. The common component is held once per path node.
    pub fn new(
        path_node_index: PathNodeIndex,
        mkyber_domain: MkyberDomain,
        mkyber_common: MkyberCommonCiphertext,
        recipients: Vec<HybridRecipientCiphertext>,
    ) -> Result<Self, HybridPathCiphertextError> {
        validate_recipient_order(&recipients)?;
        Ok(Self {
            path_node_index,
            mkyber_domain,
            mkyber_common,
            recipients,
        })
    }

    /// Returns the fixed hybrid wire version.
    pub const fn wire_version(&self) -> u16 {
        HYBRID_PATH_CIPHERTEXT_VERSION
    }

    /// Returns the path-node binding that the outer commit must authenticate.
    pub const fn path_node_index(&self) -> PathNodeIndex {
        self.path_node_index
    }

    /// Returns the public mKyber domain identifier.
    pub const fn mkyber_domain(&self) -> MkyberDomain {
        self.mkyber_domain
    }

    /// Returns the one common mKyber component for this path node.
    pub const fn mkyber_common(&self) -> &MkyberCommonCiphertext {
        &self.mkyber_common
    }

    /// Returns recipients in their canonical strictly increasing order.
    pub fn recipients(&self) -> &[HybridRecipientCiphertext] {
        &self.recipients
    }

    /// Returns canonical TLS bytes that the experimental MLS commit must cover.
    ///
    /// These bytes are not KDF input and are not an AEAD authentication tag.
    /// Task 20 defines the separate canonical AEAD associated-data context.
    pub fn commit_authenticated_bytes(&self) -> Result<Vec<u8>, HybridPathCiphertextError> {
        self.to_wire()
            .tls_serialize_detached()
            .map_err(|_| HybridPathCiphertextError::Codec)
    }

    /// Parses exact canonical TLS bytes before any future secret derivation.
    pub fn from_commit_authenticated_bytes(
        bytes: &[u8],
    ) -> Result<Self, HybridPathCiphertextError> {
        let wire = WireHybridPathCiphertext::tls_deserialize_exact(bytes)
            .map_err(|_| HybridPathCiphertextError::Codec)?;
        if wire.wire_version != HYBRID_PATH_CIPHERTEXT_VERSION {
            return Err(HybridPathCiphertextError::UnsupportedWireVersion(
                wire.wire_version,
            ));
        }

        let common = MkyberCommonCiphertext::from_bytes(&wire.mkyber_common)
            .map_err(|_| HybridPathCiphertextError::Codec)?;
        let recipients = wire
            .recipients
            .into_vec()
            .into_iter()
            .map(|recipient| {
                let mkyber_recipient =
                    MkyberRecipientCiphertext::from_bytes(&recipient.mkyber_recipient)
                        .map_err(|_| HybridPathCiphertextError::Codec)?;
                Ok(HybridRecipientCiphertext::new(
                    RecipientNodeIndex::new(recipient.recipient_node_index),
                    recipient.classical_encapsulation,
                    mkyber_recipient,
                    recipient.encrypted_path_secret,
                ))
            })
            .collect::<Result<Vec<_>, HybridPathCiphertextError>>()?;

        Self::new(
            PathNodeIndex::new(wire.path_node_index),
            MkyberDomain::new(wire.mkyber_domain),
            common,
            recipients,
        )
    }

    /// Validates public node indices against an externally supplied tree size.
    ///
    /// The caller supplies the current tree-node count because this wire type
    /// intentionally does not own mutable tree topology state.
    pub fn validate_node_bounds(
        &self,
        tree_node_count: u32,
    ) -> Result<(), HybridPathCiphertextError> {
        if tree_node_count == 0 {
            return Err(HybridPathCiphertextError::InvalidTreeNodeCount);
        }
        if self.path_node_index.as_u32() >= tree_node_count {
            return Err(HybridPathCiphertextError::NodeIndexOutOfRange(
                self.path_node_index.as_u32(),
            ));
        }
        for recipient in &self.recipients {
            if recipient.recipient_node_index().as_u32() >= tree_node_count {
                return Err(HybridPathCiphertextError::NodeIndexOutOfRange(
                    recipient.recipient_node_index().as_u32(),
                ));
            }
        }
        Ok(())
    }

    fn to_wire(&self) -> WireHybridPathCiphertext {
        WireHybridPathCiphertext {
            wire_version: HYBRID_PATH_CIPHERTEXT_VERSION,
            path_node_index: self.path_node_index.as_u32(),
            mkyber_domain: *self.mkyber_domain.as_bytes(),
            mkyber_common: *self.mkyber_common.as_bytes(),
            recipients: self
                .recipients
                .iter()
                .map(|recipient| WireHybridRecipientCiphertext {
                    recipient_node_index: recipient.recipient_node_index().as_u32(),
                    classical_encapsulation: *recipient.classical_encapsulation(),
                    mkyber_recipient: *recipient.mkyber_recipient().as_bytes(),
                    encrypted_path_secret: *recipient.encrypted_path_secret(),
                })
                .collect::<Vec<_>>()
                .into(),
        }
    }
}

impl fmt::Debug for HybridPathCiphertext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HybridPathCiphertext")
            .field("wire_version", &HYBRID_PATH_CIPHERTEXT_VERSION)
            .field("path_node_index", &self.path_node_index)
            .field("mkyber_domain", &self.mkyber_domain)
            .field(
                "common_component_bytes",
                &self.mkyber_common.as_bytes().len(),
            )
            .field("recipient_count", &self.recipients.len())
            .finish()
    }
}

/// Redacted validation and decoding errors for the hybrid wire boundary.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum HybridPathCiphertextError {
    /// Recipient records are required to carry one delivery per path node.
    #[error("hybrid path ciphertext must have at least one recipient")]
    EmptyRecipientSet,
    /// Recipient node indexes must be strictly increasing for canonical wire form.
    #[error("hybrid recipient node indexes are not strictly increasing")]
    NonCanonicalRecipientOrder,
    /// The wire version is not supported by this thesis-local implementation.
    #[error("unsupported hybrid path ciphertext version")]
    UnsupportedWireVersion(u16),
    /// The caller has no topology against which to validate public node indexes.
    #[error("tree node count must be non-zero")]
    InvalidTreeNodeCount,
    /// A public node index is beyond the current tree-node count.
    #[error("hybrid node index is out of range")]
    NodeIndexOutOfRange(u32),
    /// TLS decoding or encoding failed without exposing wire contents.
    #[error("invalid hybrid path ciphertext encoding")]
    Codec,
}

#[derive(Clone, TlsSerialize, TlsDeserialize, TlsSize)]
struct WireHybridRecipientCiphertext {
    recipient_node_index: u32,
    classical_encapsulation: [u8; CLASSICAL_ENCAPSULATION_BYTES],
    mkyber_recipient: [u8; mkyber::RECIPIENT_CIPHERTEXT_BYTES],
    encrypted_path_secret: [u8; ENCRYPTED_PATH_SECRET_BYTES],
}

#[derive(Clone, TlsSerialize, TlsDeserialize, TlsSize)]
struct WireHybridPathCiphertext {
    wire_version: u16,
    path_node_index: u32,
    mkyber_domain: [u8; 32],
    mkyber_common: [u8; mkyber::COMMON_CIPHERTEXT_BYTES],
    recipients: TlsVecU16<WireHybridRecipientCiphertext>,
}

fn validate_recipient_order(
    recipients: &[HybridRecipientCiphertext],
) -> Result<(), HybridPathCiphertextError> {
    if recipients.is_empty() {
        return Err(HybridPathCiphertextError::EmptyRecipientSet);
    }
    if recipients.windows(2).any(|pair| {
        pair[0].recipient_node_index().as_u32() >= pair[1].recipient_node_index().as_u32()
    }) {
        return Err(HybridPathCiphertextError::NonCanonicalRecipientOrder);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const DOMAIN: MkyberDomain = MkyberDomain::new([7; 32]);

    fn common(fill: u8) -> MkyberCommonCiphertext {
        MkyberCommonCiphertext::from_bytes(&[fill; mkyber::COMMON_CIPHERTEXT_BYTES])
            .expect("exact-size common component")
    }

    fn recipient(index: u32, fill: u8) -> HybridRecipientCiphertext {
        HybridRecipientCiphertext::new(
            RecipientNodeIndex::new(index),
            [fill; CLASSICAL_ENCAPSULATION_BYTES],
            MkyberRecipientCiphertext::from_bytes(&[fill; mkyber::RECIPIENT_CIPHERTEXT_BYTES])
                .expect("exact-size recipient component"),
            [fill; ENCRYPTED_PATH_SECRET_BYTES],
        )
    }

    fn ciphertext() -> HybridPathCiphertext {
        HybridPathCiphertext::new(
            PathNodeIndex::new(3),
            DOMAIN,
            common(1),
            vec![recipient(4, 2), recipient(9, 3)],
        )
        .expect("strictly ordered recipients must construct")
    }

    #[test]
    fn canonical_tls_round_trip_has_one_common_component() {
        let ciphertext = ciphertext();
        let encoded = ciphertext
            .commit_authenticated_bytes()
            .expect("canonical TLS encoding must succeed");
        let decoded = HybridPathCiphertext::from_commit_authenticated_bytes(&encoded)
            .expect("canonical TLS decoding must succeed");

        assert_eq!(decoded, ciphertext);
        assert_eq!(encoded.len(), 1_008);
        assert_eq!(decoded.recipients().len(), 2);
        assert_eq!(
            decoded.mkyber_common().as_bytes().len(),
            mkyber::COMMON_CIPHERTEXT_BYTES
        );
    }

    #[test]
    fn rejects_empty_duplicate_and_unordered_recipient_records() {
        assert_eq!(
            HybridPathCiphertext::new(PathNodeIndex::new(0), DOMAIN, common(0), vec![]),
            Err(HybridPathCiphertextError::EmptyRecipientSet)
        );
        assert_eq!(
            HybridPathCiphertext::new(
                PathNodeIndex::new(0),
                DOMAIN,
                common(0),
                vec![recipient(2, 1), recipient(2, 2)],
            ),
            Err(HybridPathCiphertextError::NonCanonicalRecipientOrder)
        );
        assert_eq!(
            HybridPathCiphertext::new(
                PathNodeIndex::new(0),
                DOMAIN,
                common(0),
                vec![recipient(9, 1), recipient(2, 2)],
            ),
            Err(HybridPathCiphertextError::NonCanonicalRecipientOrder)
        );
    }

    #[test]
    fn rejects_unknown_versions_and_trailing_wire_data() {
        let mut encoded = ciphertext()
            .commit_authenticated_bytes()
            .expect("canonical TLS encoding must succeed");
        encoded[1] = 2;
        assert_eq!(
            HybridPathCiphertext::from_commit_authenticated_bytes(&encoded),
            Err(HybridPathCiphertextError::UnsupportedWireVersion(2))
        );

        let mut trailing = ciphertext()
            .commit_authenticated_bytes()
            .expect("canonical TLS encoding must succeed");
        trailing.push(0);
        assert_eq!(
            HybridPathCiphertext::from_commit_authenticated_bytes(&trailing),
            Err(HybridPathCiphertextError::Codec)
        );
    }

    #[test]
    fn validates_public_node_bounds_before_secret_derivation() {
        let ciphertext = ciphertext();
        assert_eq!(
            ciphertext.validate_node_bounds(0),
            Err(HybridPathCiphertextError::InvalidTreeNodeCount)
        );
        assert_eq!(
            ciphertext.validate_node_bounds(9),
            Err(HybridPathCiphertextError::NodeIndexOutOfRange(9))
        );
        assert!(ciphertext.validate_node_bounds(10).is_ok());
    }

    #[test]
    fn every_hybrid_field_changes_commit_authenticated_bytes() {
        let original = ciphertext()
            .commit_authenticated_bytes()
            .expect("canonical TLS encoding must succeed");
        let alternatives = [
            HybridPathCiphertext::new(
                PathNodeIndex::new(4),
                DOMAIN,
                common(1),
                vec![recipient(4, 2), recipient(9, 3)],
            ),
            HybridPathCiphertext::new(
                PathNodeIndex::new(3),
                MkyberDomain::new([8; 32]),
                common(1),
                vec![recipient(4, 2), recipient(9, 3)],
            ),
            HybridPathCiphertext::new(
                PathNodeIndex::new(3),
                DOMAIN,
                common(4),
                vec![recipient(4, 2), recipient(9, 3)],
            ),
            HybridPathCiphertext::new(
                PathNodeIndex::new(3),
                DOMAIN,
                common(1),
                vec![recipient(5, 2), recipient(9, 3)],
            ),
            HybridPathCiphertext::new(
                PathNodeIndex::new(3),
                DOMAIN,
                common(1),
                vec![recipient(4, 5), recipient(9, 3)],
            ),
        ];

        for alternative in alternatives {
            assert!(
                alternative
                    .expect("alternative wire value must be canonical")
                    .commit_authenticated_bytes()
                    .expect("canonical TLS encoding must succeed")
                    != original,
                "every authenticated hybrid field must affect the encoded wire value"
            );
        }
    }
}
