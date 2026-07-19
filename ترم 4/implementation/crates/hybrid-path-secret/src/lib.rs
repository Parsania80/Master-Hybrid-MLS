#![forbid(unsafe_code)]

//! Authenticated wire boundary for experimental hybrid path-secret delivery.
//!
//! `HybridPathCiphertext` is the thesis-local, versioned UpdatePath-node
//! payload from ADR 0004. Its canonical bytes must be covered by the outer
//! experimental MLS commit authentication. The later hybrid AEAD must also
//! authenticate its canonical context. This crate does not implement the KDF,
//! AEAD, or OpenMLS fork integration yet.

use core::fmt;

use mkyber::{MkyberCommonCiphertext, MkyberDomain, MkyberRecipientCiphertext, MkyberSharedSecret};
use thiserror::Error;
use tls_codec::{
    Deserialize as TlsDeserializeTrait, Serialize as TlsSerializeTrait, TlsByteVecU16,
    TlsByteVecU8, TlsDeserialize, TlsSerialize, TlsSize, TlsVecU16,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

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

/// Version of the canonical hybrid KDF context.
pub const HYBRID_KDF_CONTEXT_VERSION: u16 = 1;
/// The only MLS ciphersuite permitted by ADR 0003.
pub const HYBRID_MLS_CIPHERSUITE: u16 = 0x0001;
/// Fixed ASCII label bound into every hybrid KDF context.
pub const HYBRID_KDF_LABEL: &[u8] = b"Adaptive-Hybrid-TreeKEM-PathSecret-v1";
/// X25519 DHKEM shared-secret size for the selected ciphersuite.
pub const CLASSICAL_SHARED_SECRET_BYTES: usize = 32;
/// mKyber512 thesis-profile shared-secret size.
pub const PQ_SHARED_SECRET_BYTES: usize = 32;

/// Active tree arity bound into the canonical hybrid KDF context.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum TreeArity {
    /// Ordinary binary TreeKEM topology.
    Binary = 2,
    /// Experimental quaternary topology.
    Quaternary = 4,
}

impl TreeArity {
    /// Returns the canonical numeric arity.
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

impl TryFrom<u8> for TreeArity {
    type Error = HybridKdfError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            2 => Ok(Self::Binary),
            4 => Ok(Self::Quaternary),
            _ => Err(HybridKdfError::UnsupportedTreeArity(value)),
        }
    }
}

/// Canonical public context bound to the hybrid KDF and AEAD associated data.
///
/// The context never carries ciphertext bytes, shared secrets, private keys,
/// randomness, or a reproducible experiment seed.
#[derive(Clone, PartialEq, Eq)]
pub struct HybridKdfContext {
    group_id: Vec<u8>,
    epoch: u64,
    tree_version: u32,
    current_arity: TreeArity,
    path_node_index: PathNodeIndex,
    recipient_node_index: RecipientNodeIndex,
    mkyber_domain: MkyberDomain,
    group_context_hash: [u8; 32],
}

impl HybridKdfContext {
    /// Constructs the complete public hybrid KDF context.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        group_id: Vec<u8>,
        epoch: u64,
        tree_version: u32,
        current_arity: TreeArity,
        path_node_index: PathNodeIndex,
        recipient_node_index: RecipientNodeIndex,
        mkyber_domain: MkyberDomain,
        group_context_hash: [u8; 32],
    ) -> Self {
        Self {
            group_id,
            epoch,
            tree_version,
            current_arity,
            path_node_index,
            recipient_node_index,
            mkyber_domain,
            group_context_hash,
        }
    }

    /// Returns canonical TLS bytes for the KDF context.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, HybridKdfError> {
        self.to_wire()
            .tls_serialize_detached()
            .map_err(|_| HybridKdfError::Codec)
    }

    /// Parses exact canonical TLS bytes and validates fixed fields.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, HybridKdfError> {
        let wire = WireHybridKdfContext::tls_deserialize_exact(bytes)
            .map_err(|_| HybridKdfError::Codec)?;
        if wire.context_version != HYBRID_KDF_CONTEXT_VERSION {
            return Err(HybridKdfError::UnsupportedContextVersion(
                wire.context_version,
            ));
        }
        if wire.label.as_slice() != HYBRID_KDF_LABEL {
            return Err(HybridKdfError::InvalidContextLabel);
        }
        if wire.ciphersuite != HYBRID_MLS_CIPHERSUITE {
            return Err(HybridKdfError::UnsupportedCiphersuite(wire.ciphersuite));
        }

        Ok(Self::new(
            wire.group_id.into_vec(),
            wire.epoch,
            wire.tree_version,
            TreeArity::try_from(wire.current_arity)?,
            PathNodeIndex::new(wire.path_node_index),
            RecipientNodeIndex::new(wire.recipient_node_index),
            MkyberDomain::new(wire.mkyber_domain),
            wire.group_context_hash,
        ))
    }

    /// Returns AEAD associated data for the exact supported hybrid wire version.
    pub fn aead_associated_data(&self, wire_version: u16) -> Result<Vec<u8>, HybridKdfError> {
        if wire_version != HYBRID_PATH_CIPHERTEXT_VERSION {
            return Err(HybridKdfError::UnsupportedHybridWireVersion(wire_version));
        }
        let mut associated_data = self.canonical_bytes()?;
        associated_data.extend_from_slice(&wire_version.to_be_bytes());
        Ok(associated_data)
    }

    /// Returns the public group identifier bytes.
    pub fn group_id(&self) -> &[u8] {
        &self.group_id
    }

    /// Returns the MLS epoch bound to this delivery.
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Returns the authenticated adaptive-tree version.
    pub const fn tree_version(&self) -> u32 {
        self.tree_version
    }

    /// Returns the active tree arity.
    pub const fn current_arity(&self) -> TreeArity {
        self.current_arity
    }

    /// Returns the path-node binding.
    pub const fn path_node_index(&self) -> PathNodeIndex {
        self.path_node_index
    }

    /// Returns the recipient-node binding.
    pub const fn recipient_node_index(&self) -> RecipientNodeIndex {
        self.recipient_node_index
    }

    /// Returns the public mKyber domain identifier.
    pub const fn mkyber_domain(&self) -> MkyberDomain {
        self.mkyber_domain
    }

    /// Returns the authenticated GroupContext hash.
    pub const fn group_context_hash(&self) -> &[u8; 32] {
        &self.group_context_hash
    }

    fn to_wire(&self) -> WireHybridKdfContext {
        WireHybridKdfContext {
            context_version: HYBRID_KDF_CONTEXT_VERSION,
            label: HYBRID_KDF_LABEL.into(),
            ciphersuite: HYBRID_MLS_CIPHERSUITE,
            group_id: self.group_id.as_slice().into(),
            epoch: self.epoch,
            tree_version: self.tree_version,
            current_arity: self.current_arity.as_u8(),
            path_node_index: self.path_node_index.as_u32(),
            recipient_node_index: self.recipient_node_index.as_u32(),
            mkyber_domain: *self.mkyber_domain.as_bytes(),
            group_context_hash: self.group_context_hash,
        }
    }
}

impl fmt::Debug for HybridKdfContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HybridKdfContext")
            .field("context_version", &HYBRID_KDF_CONTEXT_VERSION)
            .field("ciphersuite", &HYBRID_MLS_CIPHERSUITE)
            .field("group_id_bytes", &self.group_id.len())
            .field("epoch", &self.epoch)
            .field("tree_version", &self.tree_version)
            .field("current_arity", &self.current_arity)
            .field("path_node_index", &self.path_node_index)
            .field("recipient_node_index", &self.recipient_node_index)
            .field("mkyber_domain", &self.mkyber_domain)
            .field("group_context_hash_bytes", &self.group_context_hash.len())
            .finish()
    }
}

/// Fixed-size classical secret material accepted by the hybrid KDF builder.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ClassicalSharedSecret([u8; CLASSICAL_SHARED_SECRET_BYTES]);

impl ClassicalSharedSecret {
    /// Parses exact-size DHKEM(X25519) shared-secret material.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, HybridKdfError> {
        let bytes = bytes
            .try_into()
            .map_err(|_| HybridKdfError::InvalidClassicalSharedSecretLength(bytes.len()))?;
        Ok(Self(bytes))
    }

    /// Returns bytes only to the hybrid KDF builder.
    pub fn as_bytes(&self) -> &[u8; CLASSICAL_SHARED_SECRET_BYTES] {
        &self.0
    }
}

impl fmt::Debug for ClassicalSharedSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ClassicalSharedSecret")
            .field(&"<redacted>")
            .finish()
    }
}

/// Secret hybrid-KDF input, exactly `ss_classical || ss_pq || context`.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct HybridKdfInput(Vec<u8>);

impl HybridKdfInput {
    /// Returns the secret input only to the later HKDF extract operation.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for HybridKdfInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("HybridKdfInput")
            .field(&"<redacted>")
            .finish()
    }
}

/// Builds exactly the ADR 0003 hybrid KDF input.
///
/// Raw classical or PQ ciphertext bytes cannot enter this API. They belong on
/// the authenticated wire only and are intentionally absent from the output.
pub fn build_hybrid_kdf_input(
    classical_shared_secret: &ClassicalSharedSecret,
    pq_shared_secret: &MkyberSharedSecret,
    context: &HybridKdfContext,
) -> Result<HybridKdfInput, HybridKdfError> {
    if pq_shared_secret.as_bytes().len() != PQ_SHARED_SECRET_BYTES {
        return Err(HybridKdfError::InvalidPqSharedSecretLength(
            pq_shared_secret.as_bytes().len(),
        ));
    }
    let context_bytes = context.canonical_bytes()?;
    let mut input = Vec::with_capacity(
        CLASSICAL_SHARED_SECRET_BYTES + PQ_SHARED_SECRET_BYTES + context_bytes.len(),
    );
    input.extend_from_slice(classical_shared_secret.as_bytes());
    input.extend_from_slice(pq_shared_secret.as_bytes());
    input.extend_from_slice(&context_bytes);
    Ok(HybridKdfInput(input))
}

/// Redacted errors for canonical context and hybrid-KDF input validation.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum HybridKdfError {
    /// A context version outside the thesis-local profile was received.
    #[error("unsupported hybrid KDF context version")]
    UnsupportedContextVersion(u16),
    /// The serialized context label differs from the fixed ASCII label.
    #[error("invalid hybrid KDF context label")]
    InvalidContextLabel,
    /// The serialized ciphersuite differs from the fixed MLS suite.
    #[error("unsupported hybrid MLS ciphersuite")]
    UnsupportedCiphersuite(u16),
    /// The active arity is neither binary nor quaternary.
    #[error("unsupported hybrid tree arity")]
    UnsupportedTreeArity(u8),
    /// AEAD associated data must bind a supported hybrid wire version.
    #[error("unsupported hybrid path ciphertext version")]
    UnsupportedHybridWireVersion(u16),
    /// Classical secret material must be exactly 32 bytes.
    #[error("invalid classical shared-secret length")]
    InvalidClassicalSharedSecretLength(usize),
    /// The mKyber thesis-profile shared secret must be exactly 32 bytes.
    #[error("invalid mKyber shared-secret length")]
    InvalidPqSharedSecretLength(usize),
    /// TLS encoding or decoding failed without exposing context bytes.
    #[error("invalid hybrid KDF context encoding")]
    Codec,
}

#[derive(Clone, TlsSerialize, TlsDeserialize, TlsSize)]
struct WireHybridKdfContext {
    context_version: u16,
    label: TlsByteVecU8,
    ciphersuite: u16,
    group_id: TlsByteVecU16,
    epoch: u64,
    tree_version: u32,
    current_arity: u8,
    path_node_index: u32,
    recipient_node_index: u32,
    mkyber_domain: [u8; 32],
    group_context_hash: [u8; 32],
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

    fn kdf_context() -> HybridKdfContext {
        HybridKdfContext::new(
            b"thesis-group".to_vec(),
            17,
            3,
            TreeArity::Quaternary,
            PathNodeIndex::new(5),
            RecipientNodeIndex::new(8),
            DOMAIN,
            [9; 32],
        )
    }

    #[test]
    fn canonical_kdf_context_round_trips_and_binds_wire_version_in_aad() {
        let context = kdf_context();
        let encoded = context
            .canonical_bytes()
            .expect("canonical KDF context encoding must succeed");
        let decoded = HybridKdfContext::from_canonical_bytes(&encoded)
            .expect("canonical KDF context decoding must succeed");
        let associated_data = context
            .aead_associated_data(HYBRID_PATH_CIPHERTEXT_VERSION)
            .expect("supported wire version must build associated data");

        assert_eq!(decoded, context);
        assert_eq!(&associated_data[..encoded.len()], encoded.as_slice());
        assert_eq!(&associated_data[encoded.len()..], &[0, 1]);
        assert_eq!(
            context.aead_associated_data(2),
            Err(HybridKdfError::UnsupportedHybridWireVersion(2))
        );
    }

    #[test]
    fn every_kdf_context_field_changes_its_canonical_encoding() {
        let original = kdf_context()
            .canonical_bytes()
            .expect("canonical KDF context encoding must succeed");
        let alternatives = [
            HybridKdfContext::new(
                b"another-group".to_vec(),
                17,
                3,
                TreeArity::Quaternary,
                PathNodeIndex::new(5),
                RecipientNodeIndex::new(8),
                DOMAIN,
                [9; 32],
            ),
            HybridKdfContext::new(
                b"thesis-group".to_vec(),
                18,
                3,
                TreeArity::Quaternary,
                PathNodeIndex::new(5),
                RecipientNodeIndex::new(8),
                DOMAIN,
                [9; 32],
            ),
            HybridKdfContext::new(
                b"thesis-group".to_vec(),
                17,
                4,
                TreeArity::Quaternary,
                PathNodeIndex::new(5),
                RecipientNodeIndex::new(8),
                DOMAIN,
                [9; 32],
            ),
            HybridKdfContext::new(
                b"thesis-group".to_vec(),
                17,
                3,
                TreeArity::Binary,
                PathNodeIndex::new(5),
                RecipientNodeIndex::new(8),
                DOMAIN,
                [9; 32],
            ),
            HybridKdfContext::new(
                b"thesis-group".to_vec(),
                17,
                3,
                TreeArity::Quaternary,
                PathNodeIndex::new(6),
                RecipientNodeIndex::new(8),
                DOMAIN,
                [9; 32],
            ),
            HybridKdfContext::new(
                b"thesis-group".to_vec(),
                17,
                3,
                TreeArity::Quaternary,
                PathNodeIndex::new(5),
                RecipientNodeIndex::new(9),
                DOMAIN,
                [9; 32],
            ),
            HybridKdfContext::new(
                b"thesis-group".to_vec(),
                17,
                3,
                TreeArity::Quaternary,
                PathNodeIndex::new(5),
                RecipientNodeIndex::new(8),
                MkyberDomain::new([10; 32]),
                [9; 32],
            ),
            HybridKdfContext::new(
                b"thesis-group".to_vec(),
                17,
                3,
                TreeArity::Quaternary,
                PathNodeIndex::new(5),
                RecipientNodeIndex::new(8),
                DOMAIN,
                [10; 32],
            ),
        ];

        for alternative in alternatives {
            assert!(
                alternative
                    .canonical_bytes()
                    .expect("canonical KDF context encoding must succeed")
                    != original,
                "every KDF context field must affect canonical encoding"
            );
        }
    }

    #[test]
    fn hybrid_kdf_input_is_exactly_secrets_followed_by_canonical_context() {
        let classical = ClassicalSharedSecret::from_bytes(&[0xa5; CLASSICAL_SHARED_SECRET_BYTES])
            .expect("exact-size classical secret must construct");
        let pq = MkyberSharedSecret::from_bytes(vec![0x5a; PQ_SHARED_SECRET_BYTES])
            .expect("non-empty PQ secret must construct");
        let context = kdf_context();
        let context_bytes = context
            .canonical_bytes()
            .expect("canonical KDF context encoding must succeed");
        let input = build_hybrid_kdf_input(&classical, &pq, &context)
            .expect("valid hybrid KDF inputs must construct");
        let input_bytes = input.as_bytes();

        assert_eq!(
            input_bytes.len(),
            CLASSICAL_SHARED_SECRET_BYTES + PQ_SHARED_SECRET_BYTES + context_bytes.len()
        );
        assert!(input_bytes[..CLASSICAL_SHARED_SECRET_BYTES] == [0xa5; 32]);
        assert!(
            input_bytes[CLASSICAL_SHARED_SECRET_BYTES
                ..CLASSICAL_SHARED_SECRET_BYTES + PQ_SHARED_SECRET_BYTES]
                == [0x5a; 32]
        );
        assert!(
            input_bytes[CLASSICAL_SHARED_SECRET_BYTES + PQ_SHARED_SECRET_BYTES..] == context_bytes
        );
    }

    #[test]
    fn rejects_malformed_context_profile_and_wrong_secret_lengths() {
        assert!(matches!(
            ClassicalSharedSecret::from_bytes(&[0; CLASSICAL_SHARED_SECRET_BYTES - 1]),
            Err(HybridKdfError::InvalidClassicalSharedSecretLength(31))
        ));

        let classical = ClassicalSharedSecret::from_bytes(&[0; CLASSICAL_SHARED_SECRET_BYTES])
            .expect("exact-size classical secret must construct");
        let short_pq = MkyberSharedSecret::from_bytes(vec![0; PQ_SHARED_SECRET_BYTES - 1])
            .expect("non-empty malformed PQ secret must construct at abstraction boundary");
        assert!(matches!(
            build_hybrid_kdf_input(&classical, &short_pq, &kdf_context()),
            Err(HybridKdfError::InvalidPqSharedSecretLength(31))
        ));

        let mut bad_version = kdf_context().to_wire();
        bad_version.context_version = 2;
        let bytes = bad_version
            .tls_serialize_detached()
            .expect("test wire context must serialize");
        assert_eq!(
            HybridKdfContext::from_canonical_bytes(&bytes),
            Err(HybridKdfError::UnsupportedContextVersion(2))
        );

        let mut bad_label = kdf_context().to_wire();
        bad_label.label = b"wrong-label".as_slice().into();
        let bytes = bad_label
            .tls_serialize_detached()
            .expect("test wire context must serialize");
        assert_eq!(
            HybridKdfContext::from_canonical_bytes(&bytes),
            Err(HybridKdfError::InvalidContextLabel)
        );

        let mut bad_suite = kdf_context().to_wire();
        bad_suite.ciphersuite = 0x0002;
        let bytes = bad_suite
            .tls_serialize_detached()
            .expect("test wire context must serialize");
        assert_eq!(
            HybridKdfContext::from_canonical_bytes(&bytes),
            Err(HybridKdfError::UnsupportedCiphersuite(0x0002))
        );

        let mut bad_arity = kdf_context().to_wire();
        bad_arity.current_arity = 3;
        let bytes = bad_arity
            .tls_serialize_detached()
            .expect("test wire context must serialize");
        assert_eq!(
            HybridKdfContext::from_canonical_bytes(&bytes),
            Err(HybridKdfError::UnsupportedTreeArity(3))
        );
    }
}
