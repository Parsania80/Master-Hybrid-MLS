#![forbid(unsafe_code)]

//! Authenticated wire boundary for experimental hybrid path-secret delivery.
//!
//! `HybridPathCiphertext` is the thesis-local, versioned UpdatePath-node
//! payload from ADR 0004. Its canonical bytes must be covered by the outer
//! experimental MLS commit authentication. The later hybrid AEAD must also
//! authenticate its canonical context. This crate does not implement the KDF,
//! AEAD, or OpenMLS fork integration yet.

use core::fmt;

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes128Gcm, Nonce,
};
use hkdf::Hkdf;
use mkyber::{
    MkyberCiphertextSet, MkyberCommonCiphertext, MkyberDecapsulationKey, MkyberDomain,
    MkyberEncapsulationKey, MkyberRecipientCiphertext, MkyberSharedSecret, MultiRecipientKem,
    RecipientCiphertext, RecipientId, RecipientPublicKey, RecipientSet,
};
use openmls::prelude::{Ciphersuite, OpenMlsCrypto, OpenMlsProvider, OpenMlsRand};
use openmls_rust_crypto::OpenMlsRustCrypto;
use sha2::Sha256;
use thiserror::Error;
use tls_codec::{
    Deserialize as TlsDeserializeTrait, Serialize as TlsSerializeTrait, TlsByteVecU16,
    TlsByteVecU8, TlsDeserialize, TlsSerialize, TlsSize, TlsVecU16,
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

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

/// Builds the exact KDF input and records public exclusion provenance.
///
/// `ciphertext` is accepted only to measure its already-serialized public
/// fields. Its bytes are never passed to [`build_hybrid_kdf_input`], HKDF, or
/// an HKDF `info` value. This separate API makes that exclusion observable in
/// tests and future byte-cost instrumentation without exposing secret values.
pub fn build_hybrid_kdf_input_with_instrumentation(
    ciphertext: &HybridPathCiphertext,
    classical_shared_secret: &ClassicalSharedSecret,
    pq_shared_secret: &MkyberSharedSecret,
    context: &HybridKdfContext,
) -> Result<(HybridKdfInput, HybridKdfInputInstrumentation), HybridKdfError> {
    if ciphertext.path_node_index() != context.path_node_index()
        || ciphertext.mkyber_domain() != context.mkyber_domain()
    {
        return Err(HybridKdfError::CiphertextContextMismatch);
    }
    let recipient = ciphertext
        .recipients()
        .iter()
        .find(|recipient| recipient.recipient_node_index() == context.recipient_node_index())
        .ok_or(HybridKdfError::CiphertextRecipientNotFound)?;
    let context_bytes = context.canonical_bytes()?;
    let commit_authenticated_bytes = ciphertext
        .commit_authenticated_bytes()
        .map_err(|_| HybridKdfError::Codec)?;
    let input = build_hybrid_kdf_input(classical_shared_secret, pq_shared_secret, context)?;

    Ok((
        input,
        HybridKdfInputInstrumentation {
            kdf_input_bytes: CLASSICAL_SHARED_SECRET_BYTES
                + PQ_SHARED_SECRET_BYTES
                + context_bytes.len(),
            classical_shared_secret_bytes: CLASSICAL_SHARED_SECRET_BYTES,
            pq_shared_secret_bytes: PQ_SHARED_SECRET_BYTES,
            context_bytes: context_bytes.len(),
            serialized_commit_authenticated_bytes: commit_authenticated_bytes.len(),
            serialized_classical_encapsulation_bytes: recipient.classical_encapsulation().len(),
            serialized_mkyber_common_bytes: ciphertext.mkyber_common().as_bytes().len(),
            serialized_mkyber_recipient_bytes: recipient.mkyber_recipient().as_bytes().len(),
            serialized_encrypted_path_secret_bytes: recipient.encrypted_path_secret().len(),
        },
    ))
}

/// Public byte provenance for one instrumented hybrid KDF input.
///
/// Only the two secret lengths and canonical context contribute to `IKM`.
/// Wire-field lengths are measured from the supplied canonical ciphertext so
/// reports can prove that the mKyber common/recipient components are present
/// on wire yet absent from the KDF boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HybridKdfInputInstrumentation {
    kdf_input_bytes: usize,
    classical_shared_secret_bytes: usize,
    pq_shared_secret_bytes: usize,
    context_bytes: usize,
    serialized_commit_authenticated_bytes: usize,
    serialized_classical_encapsulation_bytes: usize,
    serialized_mkyber_common_bytes: usize,
    serialized_mkyber_recipient_bytes: usize,
    serialized_encrypted_path_secret_bytes: usize,
}

impl HybridKdfInputInstrumentation {
    /// Returns the exact number of secret/context bytes entering `IKM`.
    pub const fn kdf_input_bytes(self) -> usize {
        self.kdf_input_bytes
    }

    /// Returns the fixed classical shared-secret contribution to `IKM`.
    pub const fn classical_shared_secret_bytes(self) -> usize {
        self.classical_shared_secret_bytes
    }

    /// Returns the fixed mKyber shared-secret contribution to `IKM`.
    pub const fn pq_shared_secret_bytes(self) -> usize {
        self.pq_shared_secret_bytes
    }

    /// Returns the canonical context contribution to `IKM`.
    pub const fn context_bytes(self) -> usize {
        self.context_bytes
    }

    /// Returns complete canonical hybrid wire bytes authenticated by a future commit.
    pub const fn serialized_commit_authenticated_bytes(self) -> usize {
        self.serialized_commit_authenticated_bytes
    }

    /// Returns the serialized classical encapsulation bytes, excluded from `IKM`.
    pub const fn serialized_classical_encapsulation_bytes(self) -> usize {
        self.serialized_classical_encapsulation_bytes
    }

    /// Returns serialized common mKyber ciphertext bytes, excluded from `IKM`.
    pub const fn serialized_mkyber_common_bytes(self) -> usize {
        self.serialized_mkyber_common_bytes
    }

    /// Returns serialized recipient mKyber ciphertext bytes, excluded from `IKM`.
    pub const fn serialized_mkyber_recipient_bytes(self) -> usize {
        self.serialized_mkyber_recipient_bytes
    }

    /// Returns serialized AEAD ciphertext bytes, excluded from `IKM`.
    pub const fn serialized_encrypted_path_secret_bytes(self) -> usize {
        self.serialized_encrypted_path_secret_bytes
    }

    /// Returns zero: no classical encapsulation bytes enter `IKM`.
    pub const fn classical_encapsulation_bytes_in_kdf(self) -> usize {
        0
    }

    /// Returns zero: no common mKyber ciphertext bytes enter `IKM`.
    pub const fn mkyber_common_bytes_in_kdf(self) -> usize {
        0
    }

    /// Returns zero: no recipient mKyber ciphertext bytes enter `IKM`.
    pub const fn mkyber_recipient_bytes_in_kdf(self) -> usize {
        0
    }

    /// Returns zero: no encrypted path-secret bytes enter `IKM`.
    pub const fn encrypted_path_secret_bytes_in_kdf(self) -> usize {
        0
    }
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
    /// The public ciphertext is bound to a different path node or mKyber domain.
    #[error("hybrid ciphertext does not match the KDF context")]
    CiphertextContextMismatch,
    /// The public ciphertext does not contain the context's recipient node.
    #[error("hybrid ciphertext does not contain the KDF recipient")]
    CiphertextRecipientNotFound,
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

/// Exact MLS path-secret size delivered by the experimental wrapper.
pub const MLS_PATH_SECRET_BYTES: usize = 32;

const CLASSICAL_HPKE_INFO_SUFFIX: &[u8] = b"/classical-hpke-export";
const AEAD_KEY_INFO_SUFFIX: &[u8] = b"/aead-key";
const AEAD_NONCE_INFO_SUFFIX: &[u8] = b"/aead-nonce";

/// Public DHKEM(X25519) recipient key for the fixed MLS ciphersuite.
#[derive(Clone, PartialEq, Eq)]
pub struct ClassicalHpkePublicKey([u8; CLASSICAL_ENCAPSULATION_BYTES]);

impl ClassicalHpkePublicKey {
    /// Parses a fixed-size X25519 HPKE public key.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, HybridPathLevelError> {
        let bytes = bytes
            .try_into()
            .map_err(|_| HybridPathLevelError::InvalidClassicalPublicKeyLength(bytes.len()))?;
        Ok(Self(bytes))
    }

    /// Returns public HPKE key bytes only to the HPKE setup operation.
    pub const fn as_bytes(&self) -> &[u8; CLASSICAL_ENCAPSULATION_BYTES] {
        &self.0
    }
}

impl fmt::Debug for ClassicalHpkePublicKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ClassicalHpkePublicKey")
            .field(&CLASSICAL_ENCAPSULATION_BYTES)
            .finish()
    }
}

/// Secret DHKEM(X25519) recipient key for the fixed MLS ciphersuite.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ClassicalHpkePrivateKey([u8; CLASSICAL_ENCAPSULATION_BYTES]);

impl ClassicalHpkePrivateKey {
    /// Parses a fixed-size X25519 HPKE private key.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, HybridPathLevelError> {
        let bytes = bytes
            .try_into()
            .map_err(|_| HybridPathLevelError::InvalidClassicalPrivateKeyLength(bytes.len()))?;
        Ok(Self(bytes))
    }

    /// Returns private HPKE key bytes only to the HPKE receive operation.
    pub fn as_bytes(&self) -> &[u8; CLASSICAL_ENCAPSULATION_BYTES] {
        &self.0
    }
}

impl fmt::Debug for ClassicalHpkePrivateKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ClassicalHpkePrivateKey")
            .field(&"<redacted>")
            .finish()
    }
}

/// Classical HPKE sender output consumed by the hybrid KDF and wire encoder.
pub struct ClassicalHpkeSenderOutput {
    encapsulation: [u8; CLASSICAL_ENCAPSULATION_BYTES],
    shared_secret: ClassicalSharedSecret,
}

impl ClassicalHpkeSenderOutput {
    /// Creates an output from an exact-size public encapsulation and secret exporter output.
    pub const fn new(
        encapsulation: [u8; CLASSICAL_ENCAPSULATION_BYTES],
        shared_secret: ClassicalSharedSecret,
    ) -> Self {
        Self {
            encapsulation,
            shared_secret,
        }
    }

    /// Consumes this output without cloning secret material.
    pub fn into_parts(self) -> ([u8; CLASSICAL_ENCAPSULATION_BYTES], ClassicalSharedSecret) {
        (self.encapsulation, self.shared_secret)
    }
}

impl fmt::Debug for ClassicalHpkeSenderOutput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClassicalHpkeSenderOutput")
            .field("encapsulation_bytes", &CLASSICAL_ENCAPSULATION_BYTES)
            .field("shared_secret", &"<redacted>")
            .finish()
    }
}

/// Byte-level classical HPKE operations used by hybrid path-secret delivery.
///
/// Implementations own the OpenMLS provider and type universe they use. The
/// trait deliberately accepts and returns only fixed-size byte wrappers, so a
/// separately named OpenMLS fork can execute the same hybrid construction
/// without exchanging upstream provider types.
pub trait ClassicalHpkeProvider {
    /// Sets up a sender and exports the fixed 32-byte classical secret.
    fn setup_sender_and_export(
        &self,
        recipient_public_key: &ClassicalHpkePublicKey,
        info: &[u8],
        exporter_context: &[u8],
    ) -> Result<ClassicalHpkeSenderOutput, HybridPathLevelError>;

    /// Sets up a receiver and exports the fixed 32-byte classical secret.
    fn setup_receiver_and_export(
        &self,
        encapsulation: &[u8; CLASSICAL_ENCAPSULATION_BYTES],
        recipient_private_key: &ClassicalHpkePrivateKey,
        info: &[u8],
        exporter_context: &[u8],
    ) -> Result<ClassicalSharedSecret, HybridPathLevelError>;
}

/// Classical HPKE provider for the unchanged crates.io OpenMLS baseline.
#[derive(Debug, Default)]
pub struct UpstreamClassicalHpkeProvider;

impl ClassicalHpkeProvider for UpstreamClassicalHpkeProvider {
    fn setup_sender_and_export(
        &self,
        recipient_public_key: &ClassicalHpkePublicKey,
        info: &[u8],
        exporter_context: &[u8],
    ) -> Result<ClassicalHpkeSenderOutput, HybridPathLevelError> {
        let provider = OpenMlsRustCrypto::default();
        let (encapsulation, shared_secret) = provider
            .crypto()
            .hpke_setup_sender_and_export(
                hybrid_hpke_config(),
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
        let provider = OpenMlsRustCrypto::default();
        let shared_secret = provider
            .crypto()
            .hpke_setup_receiver_and_export(
                hybrid_hpke_config(),
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

/// Matching classical HPKE material for one experimental recipient node.
pub struct ClassicalHpkeKeyPair {
    public_key: ClassicalHpkePublicKey,
    private_key: ClassicalHpkePrivateKey,
}

impl ClassicalHpkeKeyPair {
    /// Generates a DHKEM(X25519) pair from operating-system-backed provider randomness.
    pub fn generate_with_os_rng() -> Result<Self, HybridPathLevelError> {
        let provider = OpenMlsRustCrypto::default();
        let ikm = Zeroizing::new(
            provider
                .rand()
                .random_array::<CLASSICAL_SHARED_SECRET_BYTES>()
                .map_err(|_| HybridPathLevelError::ClassicalHpke)?,
        );
        let key_pair = provider
            .crypto()
            .derive_hpke_keypair(hybrid_hpke_config(), &ikm[..])
            .map_err(|_| HybridPathLevelError::ClassicalHpke)?;
        Ok(Self {
            public_key: ClassicalHpkePublicKey::from_bytes(&key_pair.public)?,
            private_key: ClassicalHpkePrivateKey::from_bytes(&key_pair.private)?,
        })
    }

    /// Consumes the pair without cloning private key material.
    pub fn into_parts(self) -> (ClassicalHpkePublicKey, ClassicalHpkePrivateKey) {
        (self.public_key, self.private_key)
    }
}

impl fmt::Debug for ClassicalHpkeKeyPair {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClassicalHpkeKeyPair")
            .field("public_key", &self.public_key)
            .field("private_key", &"<redacted>")
            .finish()
    }
}

/// Zeroized MLS path secret delivered at one experimental path level.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct HybridPathSecret([u8; MLS_PATH_SECRET_BYTES]);

impl HybridPathSecret {
    /// Parses an exact-size MLS path secret.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, HybridPathLevelError> {
        let bytes = bytes
            .try_into()
            .map_err(|_| HybridPathLevelError::InvalidPathSecretLength(bytes.len()))?;
        Ok(Self(bytes))
    }

    /// Returns secret bytes only to hybrid delivery operations.
    pub fn as_bytes(&self) -> &[u8; MLS_PATH_SECRET_BYTES] {
        &self.0
    }
}

impl fmt::Debug for HybridPathSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("HybridPathSecret")
            .field(&"<redacted>")
            .finish()
    }
}

/// Public values shared by all recipients at one experimental UpdatePath level.
#[derive(Clone, PartialEq, Eq)]
pub struct HybridPathLevelContext {
    group_id: Vec<u8>,
    epoch: u64,
    tree_version: u32,
    current_arity: TreeArity,
    path_node_index: PathNodeIndex,
    mkyber_domain: MkyberDomain,
    group_context_hash: [u8; 32],
}

impl HybridPathLevelContext {
    /// Creates context shared by all recipient records for one path node.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        group_id: Vec<u8>,
        epoch: u64,
        tree_version: u32,
        current_arity: TreeArity,
        path_node_index: PathNodeIndex,
        mkyber_domain: MkyberDomain,
        group_context_hash: [u8; 32],
    ) -> Self {
        Self {
            group_id,
            epoch,
            tree_version,
            current_arity,
            path_node_index,
            mkyber_domain,
            group_context_hash,
        }
    }

    /// Builds the recipient-specific canonical KDF context.
    pub fn kdf_context(&self, recipient_node_index: RecipientNodeIndex) -> HybridKdfContext {
        HybridKdfContext::new(
            self.group_id.clone(),
            self.epoch,
            self.tree_version,
            self.current_arity,
            self.path_node_index,
            recipient_node_index,
            self.mkyber_domain,
            self.group_context_hash,
        )
    }

    /// Returns the public path-node binding.
    pub const fn path_node_index(&self) -> PathNodeIndex {
        self.path_node_index
    }

    /// Returns the public mKyber domain.
    pub const fn mkyber_domain(&self) -> MkyberDomain {
        self.mkyber_domain
    }
}

impl fmt::Debug for HybridPathLevelContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HybridPathLevelContext")
            .field("group_id_bytes", &self.group_id.len())
            .field("epoch", &self.epoch)
            .field("tree_version", &self.tree_version)
            .field("current_arity", &self.current_arity)
            .field("path_node_index", &self.path_node_index)
            .field("mkyber_domain", &self.mkyber_domain)
            .field("group_context_hash_bytes", &self.group_context_hash.len())
            .finish()
    }
}

/// Public hybrid delivery key material for one co-path resolution node.
#[derive(Clone)]
pub struct HybridPathRecipientPublic {
    recipient_node_index: RecipientNodeIndex,
    mkyber_public_key: MkyberEncapsulationKey,
    classical_public_key: ClassicalHpkePublicKey,
}

impl HybridPathRecipientPublic {
    /// Creates one public recipient binding.
    pub fn new(
        recipient_node_index: RecipientNodeIndex,
        mkyber_public_key: MkyberEncapsulationKey,
        classical_public_key: ClassicalHpkePublicKey,
    ) -> Self {
        Self {
            recipient_node_index,
            mkyber_public_key,
            classical_public_key,
        }
    }

    /// Returns the public node index used by the wire record and mKyber recipient ID.
    pub const fn recipient_node_index(&self) -> RecipientNodeIndex {
        self.recipient_node_index
    }
}

impl fmt::Debug for HybridPathRecipientPublic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HybridPathRecipientPublic")
            .field("recipient_node_index", &self.recipient_node_index)
            .field("mkyber_public_key", &self.mkyber_public_key)
            .field("classical_public_key", &self.classical_public_key)
            .finish()
    }
}

/// Private hybrid delivery key material for one recipient resolution node.
pub struct HybridPathRecipientPrivate {
    recipient_node_index: RecipientNodeIndex,
    mkyber_private_key: MkyberDecapsulationKey,
    classical_private_key: ClassicalHpkePrivateKey,
}

impl HybridPathRecipientPrivate {
    /// Creates one private recipient binding.
    pub fn new(
        recipient_node_index: RecipientNodeIndex,
        mkyber_private_key: MkyberDecapsulationKey,
        classical_private_key: ClassicalHpkePrivateKey,
    ) -> Self {
        Self {
            recipient_node_index,
            mkyber_private_key,
            classical_private_key,
        }
    }

    /// Returns the public node index associated with this private material.
    pub const fn recipient_node_index(&self) -> RecipientNodeIndex {
        self.recipient_node_index
    }
}

impl fmt::Debug for HybridPathRecipientPrivate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HybridPathRecipientPrivate")
            .field("recipient_node_index", &self.recipient_node_index)
            .field("mkyber_private_key", &"<redacted>")
            .field("classical_private_key", &"<redacted>")
            .finish()
    }
}

/// Builds one complete hybrid ciphertext set for an experimental UpdatePath level.
///
/// The caller supplies precisely the co-path resolution nodes. The mKyber
/// backend encapsulates once for that set, while HPKE derives one classical
/// exporter secret and one encrypted path-secret record per recipient node.
pub fn seal_hybrid_path_level(
    backend: &impl MultiRecipientKem,
    randomness: &mut dyn mkyber::MkyberRandom,
    context: &HybridPathLevelContext,
    path_secret: &HybridPathSecret,
    recipients: &[HybridPathRecipientPublic],
) -> Result<HybridPathCiphertext, HybridPathLevelError> {
    seal_hybrid_path_level_with_provider(
        &UpstreamClassicalHpkeProvider,
        backend,
        randomness,
        context,
        path_secret,
        recipients,
    )
}

/// Builds one complete hybrid ciphertext set with a caller-selected classical HPKE provider.
pub fn seal_hybrid_path_level_with_provider(
    classical_provider: &impl ClassicalHpkeProvider,
    backend: &impl MultiRecipientKem,
    randomness: &mut dyn mkyber::MkyberRandom,
    context: &HybridPathLevelContext,
    path_secret: &HybridPathSecret,
    recipients: &[HybridPathRecipientPublic],
) -> Result<HybridPathCiphertext, HybridPathLevelError> {
    validate_recipient_public_keys(context, recipients)?;
    let recipient_set = RecipientSet::new(
        context.mkyber_domain(),
        recipients
            .iter()
            .map(|recipient| RecipientPublicKey {
                recipient: RecipientId::new(recipient.recipient_node_index().as_u32()),
                key: recipient.mkyber_public_key.clone(),
            })
            .collect(),
    )
    .map_err(|_| HybridPathLevelError::Mkyber)?;
    let encapsulation = backend
        .encapsulate(&recipient_set, randomness)
        .map_err(|_| HybridPathLevelError::Mkyber)?;
    let mut records = Vec::with_capacity(recipients.len());

    for recipient in recipients {
        let recipient_context = context.kdf_context(recipient.recipient_node_index());
        let context_bytes = recipient_context
            .canonical_bytes()
            .map_err(|_| HybridPathLevelError::Kdf)?;
        let classical_info = hybrid_info(CLASSICAL_HPKE_INFO_SUFFIX, &context_bytes);
        let (classical_encapsulation, classical_shared_secret) = classical_provider
            .setup_sender_and_export(
                &recipient.classical_public_key,
                &classical_info,
                &context_bytes,
            )?
            .into_parts();
        let input = build_hybrid_kdf_input(
            &classical_shared_secret,
            &encapsulation.shared_secret,
            &recipient_context,
        )
        .map_err(|_| HybridPathLevelError::Kdf)?;
        let encrypted_path_secret = encrypt_path_secret(path_secret, &input, &recipient_context)?;
        let mkyber_recipient = encapsulation
            .ciphertext
            .recipient_component(RecipientId::new(recipient.recipient_node_index().as_u32()))
            .map_err(|_| HybridPathLevelError::Mkyber)?
            .clone();
        records.push(HybridRecipientCiphertext::new(
            recipient.recipient_node_index(),
            classical_encapsulation,
            mkyber_recipient,
            encrypted_path_secret,
        ));
    }

    HybridPathCiphertext::new(
        context.path_node_index(),
        context.mkyber_domain(),
        encapsulation.ciphertext.common().clone(),
        records,
    )
    .map_err(|_| HybridPathLevelError::InvalidCiphertext)
}

/// Opens one recipient record from a complete experimental UpdatePath level.
pub fn open_hybrid_path_level(
    backend: &impl MultiRecipientKem,
    context: &HybridPathLevelContext,
    ciphertext: &HybridPathCiphertext,
    recipient: &HybridPathRecipientPrivate,
) -> Result<HybridPathSecret, HybridPathLevelError> {
    open_hybrid_path_level_with_provider(
        &UpstreamClassicalHpkeProvider,
        backend,
        context,
        ciphertext,
        recipient,
    )
}

/// Opens one recipient record with a caller-selected classical HPKE provider.
pub fn open_hybrid_path_level_with_provider(
    classical_provider: &impl ClassicalHpkeProvider,
    backend: &impl MultiRecipientKem,
    context: &HybridPathLevelContext,
    ciphertext: &HybridPathCiphertext,
    recipient: &HybridPathRecipientPrivate,
) -> Result<HybridPathSecret, HybridPathLevelError> {
    if ciphertext.path_node_index() != context.path_node_index()
        || ciphertext.mkyber_domain() != context.mkyber_domain()
        || recipient.mkyber_private_key.domain() != context.mkyber_domain()
    {
        return Err(HybridPathLevelError::ContextMismatch);
    }
    let record = ciphertext
        .recipients()
        .iter()
        .find(|record| record.recipient_node_index() == recipient.recipient_node_index())
        .ok_or(HybridPathLevelError::RecipientNotFound)?;
    let recipient_id = RecipientId::new(recipient.recipient_node_index().as_u32());
    let mkyber_ciphertext = MkyberCiphertextSet::new(
        ciphertext.mkyber_domain(),
        ciphertext.mkyber_common().clone(),
        vec![RecipientCiphertext {
            recipient: recipient_id,
            component: record.mkyber_recipient().clone(),
        }],
    )
    .map_err(|_| HybridPathLevelError::Mkyber)?;
    let pq_shared_secret = backend
        .decapsulate(
            &recipient.mkyber_private_key,
            &mkyber_ciphertext,
            recipient_id,
        )
        .map_err(|_| HybridPathLevelError::Mkyber)?;
    let recipient_context = context.kdf_context(recipient.recipient_node_index());
    let context_bytes = recipient_context
        .canonical_bytes()
        .map_err(|_| HybridPathLevelError::Kdf)?;
    let classical_info = hybrid_info(CLASSICAL_HPKE_INFO_SUFFIX, &context_bytes);
    let classical_shared_secret = classical_provider.setup_receiver_and_export(
        record.classical_encapsulation(),
        &recipient.classical_private_key,
        &classical_info,
        &context_bytes,
    )?;
    let input = build_hybrid_kdf_input(
        &classical_shared_secret,
        &pq_shared_secret,
        &recipient_context,
    )
    .map_err(|_| HybridPathLevelError::Kdf)?;
    decrypt_path_secret(record.encrypted_path_secret(), &input, &recipient_context)
}

fn encrypt_path_secret(
    path_secret: &HybridPathSecret,
    input: &HybridKdfInput,
    context: &HybridKdfContext,
) -> Result<[u8; ENCRYPTED_PATH_SECRET_BYTES], HybridPathLevelError> {
    let aead = derive_aead_material(input, context)?;
    let associated_data = context
        .aead_associated_data(HYBRID_PATH_CIPHERTEXT_VERSION)
        .map_err(|_| HybridPathLevelError::Kdf)?;
    let cipher =
        Aes128Gcm::new_from_slice(&aead.key[..]).map_err(|_| HybridPathLevelError::Aead)?;
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&aead.nonce[..]),
            Payload {
                msg: path_secret.as_bytes(),
                aad: &associated_data,
            },
        )
        .map_err(|_| HybridPathLevelError::Aead)?;
    ciphertext
        .as_slice()
        .try_into()
        .map_err(|_| HybridPathLevelError::Aead)
}

fn decrypt_path_secret(
    encrypted_path_secret: &[u8; ENCRYPTED_PATH_SECRET_BYTES],
    input: &HybridKdfInput,
    context: &HybridKdfContext,
) -> Result<HybridPathSecret, HybridPathLevelError> {
    let aead = derive_aead_material(input, context)?;
    let associated_data = context
        .aead_associated_data(HYBRID_PATH_CIPHERTEXT_VERSION)
        .map_err(|_| HybridPathLevelError::Kdf)?;
    let cipher =
        Aes128Gcm::new_from_slice(&aead.key[..]).map_err(|_| HybridPathLevelError::Aead)?;
    let path_secret = cipher
        .decrypt(
            Nonce::from_slice(&aead.nonce[..]),
            Payload {
                msg: encrypted_path_secret,
                aad: &associated_data,
            },
        )
        .map_err(|_| HybridPathLevelError::Aead)?;
    HybridPathSecret::from_bytes(&path_secret).map_err(|_| HybridPathLevelError::Aead)
}

struct HybridAeadMaterial {
    key: Zeroizing<[u8; 16]>,
    nonce: Zeroizing<[u8; 12]>,
}

fn derive_aead_material(
    input: &HybridKdfInput,
    context: &HybridKdfContext,
) -> Result<HybridAeadMaterial, HybridPathLevelError> {
    let context_bytes = context
        .canonical_bytes()
        .map_err(|_| HybridPathLevelError::Kdf)?;
    let hkdf = Hkdf::<Sha256>::new(Some(&[0_u8; 32]), input.as_bytes());
    let mut key = Zeroizing::new([0_u8; 16]);
    let mut nonce = Zeroizing::new([0_u8; 12]);
    hkdf.expand(
        &hybrid_info(AEAD_KEY_INFO_SUFFIX, &context_bytes),
        &mut key[..],
    )
    .map_err(|_| HybridPathLevelError::Kdf)?;
    hkdf.expand(
        &hybrid_info(AEAD_NONCE_INFO_SUFFIX, &context_bytes),
        &mut nonce[..],
    )
    .map_err(|_| HybridPathLevelError::Kdf)?;
    Ok(HybridAeadMaterial { key, nonce })
}

fn hybrid_info(suffix: &[u8], context_bytes: &[u8]) -> Vec<u8> {
    let mut info = Vec::with_capacity(HYBRID_KDF_LABEL.len() + suffix.len() + context_bytes.len());
    info.extend_from_slice(HYBRID_KDF_LABEL);
    info.extend_from_slice(suffix);
    info.extend_from_slice(context_bytes);
    info
}

fn hybrid_hpke_config() -> openmls::prelude::HpkeConfig {
    Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519.hpke_config()
}

fn validate_recipient_public_keys(
    context: &HybridPathLevelContext,
    recipients: &[HybridPathRecipientPublic],
) -> Result<(), HybridPathLevelError> {
    if recipients.is_empty() {
        return Err(HybridPathLevelError::EmptyRecipientSet);
    }
    if recipients.windows(2).any(|pair| {
        pair[0].recipient_node_index().as_u32() >= pair[1].recipient_node_index().as_u32()
    }) {
        return Err(HybridPathLevelError::NonCanonicalRecipientOrder);
    }
    if recipients
        .iter()
        .any(|recipient| recipient.mkyber_public_key.domain() != context.mkyber_domain())
    {
        return Err(HybridPathLevelError::ContextMismatch);
    }
    Ok(())
}

/// Redacted failures from the experimental path-level delivery boundary.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum HybridPathLevelError {
    /// One UpdatePath level requires at least one co-path resolution recipient.
    #[error("hybrid path level requires at least one recipient")]
    EmptyRecipientSet,
    /// Public recipient node indexes must have canonical increasing order.
    #[error("hybrid path recipients are not in canonical order")]
    NonCanonicalRecipientOrder,
    /// A classical HPKE public key has an invalid public length.
    #[error("invalid classical HPKE public-key length")]
    InvalidClassicalPublicKeyLength(usize),
    /// A classical HPKE private key has an invalid secret length.
    #[error("invalid classical HPKE private-key length")]
    InvalidClassicalPrivateKeyLength(usize),
    /// The provider returned a classical encapsulation outside the fixed profile.
    #[error("invalid classical HPKE encapsulation length")]
    InvalidClassicalEncapsulationLength(usize),
    /// MLS path secrets must be exactly 32 bytes.
    #[error("invalid MLS path-secret length")]
    InvalidPathSecretLength(usize),
    /// Public path, domain, or recipient bindings disagree.
    #[error("hybrid path-level context mismatch")]
    ContextMismatch,
    /// The selected recipient does not have a canonical delivery record.
    #[error("hybrid path-level recipient not found")]
    RecipientNotFound,
    /// The mKyber backend rejected public or private material.
    #[error("mKyber path-level operation failed")]
    Mkyber,
    /// The approved classical HPKE provider rejected the operation.
    #[error("classical HPKE path-level operation failed")]
    ClassicalHpke,
    /// The canonical hybrid KDF input or expansion failed.
    #[error("hybrid path-level key derivation failed")]
    Kdf,
    /// AES-GCM encryption, decryption, or ciphertext sizing failed.
    #[error("hybrid path-level AEAD operation failed")]
    Aead,
    /// The constructed public wire value was non-canonical.
    #[error("invalid hybrid path-level ciphertext")]
    InvalidCiphertext,
}

#[cfg(test)]
mod tests {
    use super::*;
    use mkyber::EducationalMkyber512Reference;
    use proptest::prelude::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

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

    fn path_level_context(domain: MkyberDomain) -> HybridPathLevelContext {
        HybridPathLevelContext::new(
            b"task-twenty-one-group".to_vec(),
            23,
            6,
            TreeArity::Binary,
            PathNodeIndex::new(11),
            domain,
            [12; 32],
        )
    }

    fn hybrid_recipient(
        backend: &EducationalMkyber512Reference,
        randomness: &mut ChaCha20Rng,
        domain: MkyberDomain,
        node_index: u32,
    ) -> (HybridPathRecipientPublic, HybridPathRecipientPrivate) {
        let mkyber_pair = backend
            .keygen(domain, randomness)
            .expect("test mKyber key generation must succeed");
        let (mkyber_public_key, mkyber_private_key) = mkyber_pair.into_parts();
        let classical_pair = ClassicalHpkeKeyPair::generate_with_os_rng()
            .expect("test HPKE key generation must succeed");
        let (classical_public_key, classical_private_key) = classical_pair.into_parts();
        let recipient_node_index = RecipientNodeIndex::new(node_index);
        (
            HybridPathRecipientPublic::new(
                recipient_node_index,
                mkyber_public_key,
                classical_public_key,
            ),
            HybridPathRecipientPrivate::new(
                recipient_node_index,
                mkyber_private_key,
                classical_private_key,
            ),
        )
    }

    #[test]
    fn hybrid_path_level_delivers_one_mkyber_shared_secret_to_every_recipient() {
        let backend = EducationalMkyber512Reference;
        let domain = MkyberDomain::new([13; 32]);
        let mut randomness = ChaCha20Rng::from_seed([14; 32]);
        let (bob_public, bob_private) = hybrid_recipient(&backend, &mut randomness, domain, 4);
        let (charlie_public, charlie_private) =
            hybrid_recipient(&backend, &mut randomness, domain, 9);
        let context = path_level_context(domain);
        let path_secret = HybridPathSecret::from_bytes(&[15; MLS_PATH_SECRET_BYTES])
            .expect("exact-size test path secret must construct");

        let ciphertext = seal_hybrid_path_level(
            &backend,
            &mut randomness,
            &context,
            &path_secret,
            &[bob_public, charlie_public],
        )
        .expect("valid co-path recipients must seal");
        let bob_path_secret = open_hybrid_path_level(&backend, &context, &ciphertext, &bob_private)
            .expect("Bob must open the path secret");
        let charlie_path_secret =
            open_hybrid_path_level(&backend, &context, &ciphertext, &charlie_private)
                .expect("Charlie must open the path secret");

        assert_eq!(ciphertext.recipients().len(), 2);
        assert_eq!(
            ciphertext.mkyber_common().as_bytes().len(),
            mkyber::COMMON_CIPHERTEXT_BYTES
        );
        assert!(bob_path_secret.as_bytes() == path_secret.as_bytes());
        assert!(charlie_path_secret.as_bytes() == path_secret.as_bytes());
    }

    #[test]
    fn hybrid_path_level_rejects_unsorted_or_cross_domain_recipient_material() {
        let backend = EducationalMkyber512Reference;
        let domain = MkyberDomain::new([16; 32]);
        let mut randomness = ChaCha20Rng::from_seed([17; 32]);
        let (late_public, _) = hybrid_recipient(&backend, &mut randomness, domain, 9);
        let (early_public, _) = hybrid_recipient(&backend, &mut randomness, domain, 4);
        let path_secret = HybridPathSecret::from_bytes(&[18; MLS_PATH_SECRET_BYTES])
            .expect("exact-size test path secret must construct");

        assert_eq!(
            seal_hybrid_path_level(
                &backend,
                &mut randomness,
                &path_level_context(domain),
                &path_secret,
                &[late_public, early_public],
            ),
            Err(HybridPathLevelError::NonCanonicalRecipientOrder)
        );

        let other_domain = MkyberDomain::new([19; 32]);
        let (cross_domain_public, _) =
            hybrid_recipient(&backend, &mut randomness, other_domain, 12);
        assert_eq!(
            seal_hybrid_path_level(
                &backend,
                &mut randomness,
                &path_level_context(domain),
                &path_secret,
                &[cross_domain_public],
            ),
            Err(HybridPathLevelError::ContextMismatch)
        );
    }

    fn instrumentation_context() -> HybridKdfContext {
        HybridKdfContext::new(
            b"instrumented-group".to_vec(),
            29,
            7,
            TreeArity::Binary,
            PathNodeIndex::new(3),
            RecipientNodeIndex::new(4),
            DOMAIN,
            [20; 32],
        )
    }

    fn instrumented_ciphertext(
        common_fill: u8,
        first_recipient_mkyber_fill: u8,
    ) -> HybridPathCiphertext {
        HybridPathCiphertext::new(
            PathNodeIndex::new(3),
            DOMAIN,
            common(common_fill),
            vec![
                HybridRecipientCiphertext::new(
                    RecipientNodeIndex::new(4),
                    [2; CLASSICAL_ENCAPSULATION_BYTES],
                    MkyberRecipientCiphertext::from_bytes(
                        &[first_recipient_mkyber_fill; mkyber::RECIPIENT_CIPHERTEXT_BYTES],
                    )
                    .expect("exact-size mKyber recipient component"),
                    [2; ENCRYPTED_PATH_SECRET_BYTES],
                ),
                recipient(9, 3),
            ],
        )
        .expect("instrumented recipients must be canonical")
    }

    #[test]
    fn instrumentation_proves_pq_ciphertext_is_authenticated_but_excluded_from_kdf_input() {
        let classical = ClassicalSharedSecret::from_bytes(&[0x21; CLASSICAL_SHARED_SECRET_BYTES])
            .expect("exact-size classical secret must construct");
        let pq = MkyberSharedSecret::from_bytes(vec![0x22; PQ_SHARED_SECRET_BYTES])
            .expect("exact-size PQ secret must construct");
        let context = instrumentation_context();
        let original = instrumented_ciphertext(1, 2);
        let changed_common = instrumented_ciphertext(3, 2);
        let changed_recipient = instrumented_ciphertext(1, 4);

        let (original_input, original_measurement) =
            build_hybrid_kdf_input_with_instrumentation(&original, &classical, &pq, &context)
                .expect("matching ciphertext must instrument");
        let (common_input, common_measurement) =
            build_hybrid_kdf_input_with_instrumentation(&changed_common, &classical, &pq, &context)
                .expect("changed common component remains syntactically valid");
        let (recipient_input, recipient_measurement) = build_hybrid_kdf_input_with_instrumentation(
            &changed_recipient,
            &classical,
            &pq,
            &context,
        )
        .expect("changed recipient component remains syntactically valid");

        assert!(original_input.as_bytes() == common_input.as_bytes());
        assert!(original_input.as_bytes() == recipient_input.as_bytes());
        assert!(
            original
                .commit_authenticated_bytes()
                .expect("canonical wire encoding must succeed")
                != changed_common
                    .commit_authenticated_bytes()
                    .expect("canonical wire encoding must succeed")
        );
        assert!(
            original
                .commit_authenticated_bytes()
                .expect("canonical wire encoding must succeed")
                != changed_recipient
                    .commit_authenticated_bytes()
                    .expect("canonical wire encoding must succeed")
        );

        assert_eq!(
            original_measurement.kdf_input_bytes(),
            CLASSICAL_SHARED_SECRET_BYTES
                + PQ_SHARED_SECRET_BYTES
                + original_measurement.context_bytes()
        );
        assert_eq!(
            original_measurement.serialized_mkyber_common_bytes(),
            mkyber::COMMON_CIPHERTEXT_BYTES
        );
        assert_eq!(
            original_measurement.serialized_mkyber_recipient_bytes(),
            mkyber::RECIPIENT_CIPHERTEXT_BYTES
        );
        assert!(original_measurement.serialized_commit_authenticated_bytes() > 0);
        assert_eq!(
            original_measurement.classical_encapsulation_bytes_in_kdf(),
            0
        );
        assert_eq!(original_measurement.mkyber_common_bytes_in_kdf(), 0);
        assert_eq!(original_measurement.mkyber_recipient_bytes_in_kdf(), 0);
        assert_eq!(original_measurement.encrypted_path_secret_bytes_in_kdf(), 0);
        assert_eq!(original_measurement, common_measurement);
        assert_eq!(original_measurement, recipient_measurement);
    }

    #[test]
    fn instrumentation_rejects_ciphertext_context_and_recipient_mismatches() {
        let classical = ClassicalSharedSecret::from_bytes(&[0x23; CLASSICAL_SHARED_SECRET_BYTES])
            .expect("exact-size classical secret must construct");
        let pq = MkyberSharedSecret::from_bytes(vec![0x24; PQ_SHARED_SECRET_BYTES])
            .expect("exact-size PQ secret must construct");
        let ciphertext = instrumented_ciphertext(1, 2);
        let wrong_path = HybridKdfContext::new(
            b"instrumented-group".to_vec(),
            29,
            7,
            TreeArity::Binary,
            PathNodeIndex::new(5),
            RecipientNodeIndex::new(4),
            DOMAIN,
            [20; 32],
        );
        let wrong_recipient = HybridKdfContext::new(
            b"instrumented-group".to_vec(),
            29,
            7,
            TreeArity::Binary,
            PathNodeIndex::new(3),
            RecipientNodeIndex::new(5),
            DOMAIN,
            [20; 32],
        );

        assert!(matches!(
            build_hybrid_kdf_input_with_instrumentation(&ciphertext, &classical, &pq, &wrong_path),
            Err(HybridKdfError::CiphertextContextMismatch)
        ));
        assert!(matches!(
            build_hybrid_kdf_input_with_instrumentation(
                &ciphertext,
                &classical,
                &pq,
                &wrong_recipient
            ),
            Err(HybridKdfError::CiphertextRecipientNotFound)
        ));
    }

    fn sealed_path_level_fixture() -> (
        EducationalMkyber512Reference,
        HybridPathLevelContext,
        HybridPathCiphertext,
        HybridPathRecipientPrivate,
        HybridPathRecipientPrivate,
    ) {
        let backend = EducationalMkyber512Reference;
        let domain = MkyberDomain::new([25; 32]);
        let mut randomness = ChaCha20Rng::from_seed([26; 32]);
        let (bob_public, bob_private) = hybrid_recipient(&backend, &mut randomness, domain, 4);
        let (charlie_public, charlie_private) =
            hybrid_recipient(&backend, &mut randomness, domain, 9);
        let context = HybridPathLevelContext::new(
            b"task-twenty-three-group".to_vec(),
            31,
            8,
            TreeArity::Quaternary,
            PathNodeIndex::new(12),
            domain,
            [27; 32],
        );
        let path_secret = HybridPathSecret::from_bytes(&[28; MLS_PATH_SECRET_BYTES])
            .expect("exact-size test path secret must construct");
        let ciphertext = seal_hybrid_path_level(
            &backend,
            &mut randomness,
            &context,
            &path_secret,
            &[bob_public, charlie_public],
        )
        .expect("valid co-path recipients must seal");
        (backend, context, ciphertext, bob_private, charlie_private)
    }

    fn replace_first_recipient(
        ciphertext: &HybridPathCiphertext,
        replacement: HybridRecipientCiphertext,
    ) -> HybridPathCiphertext {
        let mut recipients = ciphertext.recipients().to_vec();
        recipients[0] = replacement;
        HybridPathCiphertext::new(
            ciphertext.path_node_index(),
            ciphertext.mkyber_domain(),
            ciphertext.mkyber_common().clone(),
            recipients,
        )
        .expect("replacement must preserve canonical recipient order")
    }

    #[test]
    fn every_serialized_delivery_component_tamper_fails_without_path_secret_output() {
        let (backend, context, ciphertext, bob_private, _) = sealed_path_level_fixture();
        let first = &ciphertext.recipients()[0];

        let mut changed_classical = *first.classical_encapsulation();
        changed_classical[0] ^= 1;
        let classical_tamper = replace_first_recipient(
            &ciphertext,
            HybridRecipientCiphertext::new(
                first.recipient_node_index(),
                changed_classical,
                first.mkyber_recipient().clone(),
                *first.encrypted_path_secret(),
            ),
        );

        let mut changed_common = *ciphertext.mkyber_common().as_bytes();
        changed_common[0] ^= 1;
        let common_tamper = HybridPathCiphertext::new(
            ciphertext.path_node_index(),
            ciphertext.mkyber_domain(),
            MkyberCommonCiphertext::from_bytes(&changed_common)
                .expect("exact-size common component must construct"),
            ciphertext.recipients().to_vec(),
        )
        .expect("common-component replacement must remain canonical");

        let mut changed_recipient = *first.mkyber_recipient().as_bytes();
        changed_recipient[0] ^= 1;
        let recipient_tamper = replace_first_recipient(
            &ciphertext,
            HybridRecipientCiphertext::new(
                first.recipient_node_index(),
                *first.classical_encapsulation(),
                MkyberRecipientCiphertext::from_bytes(&changed_recipient)
                    .expect("exact-size recipient component must construct"),
                *first.encrypted_path_secret(),
            ),
        );

        let mut changed_aead = *first.encrypted_path_secret();
        changed_aead[0] ^= 1;
        let aead_tamper = replace_first_recipient(
            &ciphertext,
            HybridRecipientCiphertext::new(
                first.recipient_node_index(),
                *first.classical_encapsulation(),
                first.mkyber_recipient().clone(),
                changed_aead,
            ),
        );

        for tampered in [
            classical_tamper,
            common_tamper,
            recipient_tamper,
            aead_tamper,
        ] {
            assert!(
                open_hybrid_path_level(&backend, &context, &tampered, &bob_private).is_err(),
                "every altered delivery field must fail before returning a path secret"
            );
        }
    }

    #[test]
    fn only_intended_recipients_can_open_a_hybrid_path_level() {
        let (backend, context, ciphertext, bob_private, charlie_private) =
            sealed_path_level_fixture();
        let domain = context.mkyber_domain();
        let mut randomness = ChaCha20Rng::from_seed([29; 32]);
        let (_, non_recipient_private) = hybrid_recipient(&backend, &mut randomness, domain, 15);

        assert!(
            open_hybrid_path_level(&backend, &context, &ciphertext, &bob_private).is_ok(),
            "intended Bob recipient must open"
        );
        assert!(
            open_hybrid_path_level(&backend, &context, &ciphertext, &charlie_private).is_ok(),
            "intended Charlie recipient must open"
        );
        assert!(matches!(
            open_hybrid_path_level(&backend, &context, &ciphertext, &non_recipient_private),
            Err(HybridPathLevelError::RecipientNotFound)
        ));
    }

    #[test]
    fn group_epoch_tree_and_node_replays_fail_before_path_secret_output() {
        let (backend, context, ciphertext, bob_private, _) = sealed_path_level_fixture();
        let domain = context.mkyber_domain();
        let changed_contexts = [
            HybridPathLevelContext::new(
                b"another-group".to_vec(),
                31,
                8,
                TreeArity::Quaternary,
                PathNodeIndex::new(12),
                domain,
                [27; 32],
            ),
            HybridPathLevelContext::new(
                b"task-twenty-three-group".to_vec(),
                32,
                8,
                TreeArity::Quaternary,
                PathNodeIndex::new(12),
                domain,
                [27; 32],
            ),
            HybridPathLevelContext::new(
                b"task-twenty-three-group".to_vec(),
                31,
                9,
                TreeArity::Quaternary,
                PathNodeIndex::new(12),
                domain,
                [27; 32],
            ),
            HybridPathLevelContext::new(
                b"task-twenty-three-group".to_vec(),
                31,
                8,
                TreeArity::Quaternary,
                PathNodeIndex::new(13),
                domain,
                [27; 32],
            ),
        ];

        for replay_context in changed_contexts {
            assert!(
                open_hybrid_path_level(&backend, &replay_context, &ciphertext, &bob_private)
                    .is_err(),
                "a group, epoch, tree-version, or path-node replay must fail"
            );
        }
    }

    proptest! {
        #[test]
        fn arbitrary_common_component_mutation_changes_authenticated_wire_but_not_fixed_input(
            byte_index in 0usize..mkyber::COMMON_CIPHERTEXT_BYTES,
            mask in 1u8..=u8::MAX,
        ) {
            let classical = ClassicalSharedSecret::from_bytes(&[0x31; CLASSICAL_SHARED_SECRET_BYTES])
                .expect("exact-size classical secret must construct");
            let pq = MkyberSharedSecret::from_bytes(vec![0x32; PQ_SHARED_SECRET_BYTES])
                .expect("exact-size PQ secret must construct");
            let context = instrumentation_context();
            let original = instrumented_ciphertext(1, 2);
            let mut changed_common = *original.mkyber_common().as_bytes();
            changed_common[byte_index] ^= mask;
            let changed = HybridPathCiphertext::new(
                original.path_node_index(),
                original.mkyber_domain(),
                MkyberCommonCiphertext::from_bytes(&changed_common)
                    .expect("exact-size common component must construct"),
                original.recipients().to_vec(),
            )
            .expect("changed common component must preserve canonical wire form");

            let (original_input, _) = build_hybrid_kdf_input_with_instrumentation(
                &original,
                &classical,
                &pq,
                &context,
            )
            .expect("original ciphertext must instrument");
            let (changed_input, _) = build_hybrid_kdf_input_with_instrumentation(
                &changed,
                &classical,
                &pq,
                &context,
            )
            .expect("changed ciphertext must instrument");

            prop_assert!(original_input.as_bytes() == changed_input.as_bytes());
            prop_assert!(
                original.commit_authenticated_bytes().expect("original wire must encode")
                    != changed.commit_authenticated_bytes().expect("changed wire must encode")
            );
        }

        #[test]
        fn arbitrary_recipient_component_mutation_changes_authenticated_wire_but_not_fixed_input(
            byte_index in 0usize..mkyber::RECIPIENT_CIPHERTEXT_BYTES,
            mask in 1u8..=u8::MAX,
        ) {
            let classical = ClassicalSharedSecret::from_bytes(&[0x33; CLASSICAL_SHARED_SECRET_BYTES])
                .expect("exact-size classical secret must construct");
            let pq = MkyberSharedSecret::from_bytes(vec![0x34; PQ_SHARED_SECRET_BYTES])
                .expect("exact-size PQ secret must construct");
            let context = instrumentation_context();
            let original = instrumented_ciphertext(1, 2);
            let first = &original.recipients()[0];
            let mut changed_recipient = *first.mkyber_recipient().as_bytes();
            changed_recipient[byte_index] ^= mask;
            let changed = replace_first_recipient(
                &original,
                HybridRecipientCiphertext::new(
                    first.recipient_node_index(),
                    *first.classical_encapsulation(),
                    MkyberRecipientCiphertext::from_bytes(&changed_recipient)
                        .expect("exact-size recipient component must construct"),
                    *first.encrypted_path_secret(),
                ),
            );

            let (original_input, _) = build_hybrid_kdf_input_with_instrumentation(
                &original,
                &classical,
                &pq,
                &context,
            )
            .expect("original ciphertext must instrument");
            let (changed_input, _) = build_hybrid_kdf_input_with_instrumentation(
                &changed,
                &classical,
                &pq,
                &context,
            )
            .expect("changed ciphertext must instrument");

            prop_assert!(original_input.as_bytes() == changed_input.as_bytes());
            prop_assert!(
                original.commit_authenticated_bytes().expect("original wire must encode")
                    != changed.commit_authenticated_bytes().expect("changed wire must encode")
            );
        }
    }
}
