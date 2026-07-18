#![forbid(unsafe_code)]

//! Specification-driven, reference-only mKyber512 abstraction.
//!
//! The public sizes in this module come from the mKyber paper as recorded in
//! ADR 0002. This is not ML-KEM, Kyber, amKyber, a production implementation,
//! or an interoperability claim. No cryptographic backend is implemented yet.

use core::fmt;

use rand_core::{CryptoRng, RngCore};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// mKyber512 encapsulation-key size in bytes.
pub const ENCAPSULATION_KEY_BYTES: usize = 768;
/// mKyber512 common ciphertext-component size in bytes.
pub const COMMON_CIPHERTEXT_BYTES: usize = 704;
/// mKyber512 per-recipient ciphertext-component size in bytes.
pub const RECIPIENT_CIPHERTEXT_BYTES: usize = 48;

/// A secure randomness source accepted by a backend implementation.
///
/// Deterministic test RNGs may implement this trait only in isolated tests;
/// production key generation and encapsulation require OS-backed randomness.
pub trait MkyberRandom: RngCore + CryptoRng {}

impl<T> MkyberRandom for T where T: RngCore + CryptoRng {}

/// Typed, public mKyber matrix/domain identifier.
///
/// This identifier is not a seed, shared secret, or private key. It must be
/// authenticated by the experimental protocol before a future backend uses it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MkyberDomain([u8; 32]);

impl MkyberDomain {
    /// Creates a domain from its canonical public identifier.
    pub const fn new(identifier: [u8; 32]) -> Self {
        Self(identifier)
    }

    /// Returns the canonical public identifier.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Public recipient identifier within a ciphertext set.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RecipientId(u32);

impl RecipientId {
    /// Creates a public recipient identifier.
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    /// Returns the public numeric identifier.
    pub const fn as_u32(self) -> u32 {
        self.0
    }
}

/// Public mKyber512 encapsulation key bound to one mKyber domain.
#[derive(Clone, PartialEq, Eq)]
pub struct MkyberEncapsulationKey {
    domain: MkyberDomain,
    bytes: [u8; ENCAPSULATION_KEY_BYTES],
}

impl MkyberEncapsulationKey {
    /// Parses an exact-size public encapsulation key.
    pub fn from_bytes(domain: MkyberDomain, bytes: &[u8]) -> Result<Self, MkyberError> {
        let bytes = copy_exact::<ENCAPSULATION_KEY_BYTES>(bytes, PublicField::EncapsulationKey)?;
        Ok(Self { domain, bytes })
    }

    /// Returns the public domain bound to this key.
    pub const fn domain(&self) -> MkyberDomain {
        self.domain
    }

    /// Returns the canonical public key bytes.
    pub const fn as_bytes(&self) -> &[u8; ENCAPSULATION_KEY_BYTES] {
        &self.bytes
    }
}

impl fmt::Debug for MkyberEncapsulationKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MkyberEncapsulationKey")
            .field("domain", &self.domain)
            .field("byte_len", &ENCAPSULATION_KEY_BYTES)
            .finish()
    }
}

/// Private decapsulation key bound to one mKyber domain.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MkyberDecapsulationKey {
    #[zeroize(skip)]
    domain: MkyberDomain,
    bytes: Vec<u8>,
}

impl MkyberDecapsulationKey {
    /// Creates a backend-defined private decapsulation key.
    ///
    /// The exact private-key representation remains a backend responsibility.
    /// Empty secret material is rejected; callers must never log this value.
    pub fn from_bytes(domain: MkyberDomain, bytes: Vec<u8>) -> Result<Self, MkyberError> {
        if bytes.is_empty() {
            return Err(MkyberError::EmptySecretMaterial);
        }
        Ok(Self { domain, bytes })
    }

    /// Returns the public domain bound to this private key.
    pub const fn domain(&self) -> MkyberDomain {
        self.domain
    }

    /// Returns private bytes only for a backend cryptographic operation.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl fmt::Debug for MkyberDecapsulationKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MkyberDecapsulationKey")
            .field("domain", &self.domain)
            .field("material", &"<redacted>")
            .finish()
    }
}

/// A matching public/private mKyber key pair produced by a backend.
pub struct MkyberKeyPair {
    public_key: MkyberEncapsulationKey,
    private_key: MkyberDecapsulationKey,
}

impl MkyberKeyPair {
    /// Combines matching public and private material from a backend.
    pub fn new(
        public_key: MkyberEncapsulationKey,
        private_key: MkyberDecapsulationKey,
    ) -> Result<Self, MkyberError> {
        if public_key.domain() != private_key.domain() {
            return Err(MkyberError::DomainMismatch);
        }
        Ok(Self {
            public_key,
            private_key,
        })
    }

    /// Returns the public encapsulation key.
    pub fn public_key(&self) -> &MkyberEncapsulationKey {
        &self.public_key
    }

    /// Returns the private decapsulation key for a backend operation.
    pub fn private_key(&self) -> &MkyberDecapsulationKey {
        &self.private_key
    }
}

impl fmt::Debug for MkyberKeyPair {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MkyberKeyPair")
            .field("public_key", &self.public_key)
            .field("private_key", &"<redacted>")
            .finish()
    }
}

/// Public recipient/key pair selected for one multi-recipient encapsulation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecipientPublicKey {
    /// Public recipient identifier.
    pub recipient: RecipientId,
    /// Public mKyber encapsulation key.
    pub key: MkyberEncapsulationKey,
}

/// A validated, non-empty recipient set for one mKyber domain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecipientSet {
    domain: MkyberDomain,
    recipients: Vec<RecipientPublicKey>,
}

impl RecipientSet {
    /// Validates a non-empty set with unique identifiers and one domain.
    pub fn new(
        domain: MkyberDomain,
        recipients: Vec<RecipientPublicKey>,
    ) -> Result<Self, MkyberError> {
        if recipients.is_empty() {
            return Err(MkyberError::EmptyRecipientSet);
        }
        for (position, recipient) in recipients.iter().enumerate() {
            if recipient.key.domain() != domain {
                return Err(MkyberError::DomainMismatch);
            }
            if recipients[..position]
                .iter()
                .any(|previous| previous.recipient == recipient.recipient)
            {
                return Err(MkyberError::DuplicateRecipient(recipient.recipient));
            }
        }
        Ok(Self { domain, recipients })
    }

    /// Returns the shared public mKyber domain.
    pub const fn domain(&self) -> MkyberDomain {
        self.domain
    }

    /// Returns the validated public recipients in caller-supplied order.
    pub fn recipients(&self) -> &[RecipientPublicKey] {
        &self.recipients
    }
}

/// The exact-size common mKyber ciphertext component shared by all recipients.
#[derive(Clone, PartialEq, Eq)]
pub struct MkyberCommonCiphertext([u8; COMMON_CIPHERTEXT_BYTES]);

impl MkyberCommonCiphertext {
    /// Parses an exact-size common ciphertext component.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, MkyberError> {
        Ok(Self(copy_exact::<COMMON_CIPHERTEXT_BYTES>(
            bytes,
            PublicField::CommonCiphertext,
        )?))
    }

    /// Returns the canonical public ciphertext bytes.
    pub const fn as_bytes(&self) -> &[u8; COMMON_CIPHERTEXT_BYTES] {
        &self.0
    }
}

impl fmt::Debug for MkyberCommonCiphertext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MkyberCommonCiphertext")
            .field("byte_len", &COMMON_CIPHERTEXT_BYTES)
            .finish()
    }
}

/// The exact-size mKyber ciphertext component for one recipient.
#[derive(Clone, PartialEq, Eq)]
pub struct MkyberRecipientCiphertext([u8; RECIPIENT_CIPHERTEXT_BYTES]);

impl MkyberRecipientCiphertext {
    /// Parses an exact-size recipient ciphertext component.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, MkyberError> {
        Ok(Self(copy_exact::<RECIPIENT_CIPHERTEXT_BYTES>(
            bytes,
            PublicField::RecipientCiphertext,
        )?))
    }

    /// Returns the canonical public ciphertext bytes.
    pub const fn as_bytes(&self) -> &[u8; RECIPIENT_CIPHERTEXT_BYTES] {
        &self.0
    }
}

impl fmt::Debug for MkyberRecipientCiphertext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MkyberRecipientCiphertext")
            .field("byte_len", &RECIPIENT_CIPHERTEXT_BYTES)
            .finish()
    }
}

/// One recipient-bound component in a multi-recipient ciphertext set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecipientCiphertext {
    /// Public recipient identifier.
    pub recipient: RecipientId,
    /// Public ciphertext component for that recipient.
    pub component: MkyberRecipientCiphertext,
}

/// The public ciphertext output shared by one mKyber recipient set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MkyberCiphertextSet {
    domain: MkyberDomain,
    common: MkyberCommonCiphertext,
    recipients: Vec<RecipientCiphertext>,
}

impl MkyberCiphertextSet {
    /// Validates a public ciphertext set with unique recipient identifiers.
    pub fn new(
        domain: MkyberDomain,
        common: MkyberCommonCiphertext,
        recipients: Vec<RecipientCiphertext>,
    ) -> Result<Self, MkyberError> {
        if recipients.is_empty() {
            return Err(MkyberError::EmptyRecipientSet);
        }
        for (position, recipient) in recipients.iter().enumerate() {
            if recipients[..position]
                .iter()
                .any(|previous| previous.recipient == recipient.recipient)
            {
                return Err(MkyberError::DuplicateRecipient(recipient.recipient));
            }
        }
        Ok(Self {
            domain,
            common,
            recipients,
        })
    }

    /// Returns the public domain bound to this ciphertext set.
    pub const fn domain(&self) -> MkyberDomain {
        self.domain
    }

    /// Returns the common component encoded once per recipient set.
    pub const fn common(&self) -> &MkyberCommonCiphertext {
        &self.common
    }

    /// Returns a recipient component or a typed non-recipient error.
    pub fn recipient_component(
        &self,
        recipient: RecipientId,
    ) -> Result<&MkyberRecipientCiphertext, MkyberError> {
        self.recipients
            .iter()
            .find(|entry| entry.recipient == recipient)
            .map(|entry| &entry.component)
            .ok_or(MkyberError::RecipientNotFound)
    }
}

/// A backend-produced mKyber shared secret.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MkyberSharedSecret(Vec<u8>);

impl MkyberSharedSecret {
    /// Creates non-empty backend-produced shared-secret material.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, MkyberError> {
        if bytes.is_empty() {
            return Err(MkyberError::EmptySecretMaterial);
        }
        Ok(Self(bytes))
    }

    /// Returns shared-secret bytes only for a subsequent cryptographic combiner.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for MkyberSharedSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("MkyberSharedSecret")
            .field(&"<redacted>")
            .finish()
    }
}

/// Sender-side result from a multi-recipient encapsulation.
pub struct MkyberEncapsulation {
    /// Public ciphertext components to serialize and authenticate.
    pub ciphertext: MkyberCiphertextSet,
    /// Secret to pass to the later experimental hybrid combiner.
    pub shared_secret: MkyberSharedSecret,
}

impl fmt::Debug for MkyberEncapsulation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MkyberEncapsulation")
            .field("ciphertext", &self.ciphertext)
            .field("shared_secret", &"<redacted>")
            .finish()
    }
}

/// Backend-independent mKyber operations required by the thesis protocol.
///
/// Implementations must reject domain mismatch, malformed input, and a missing
/// recipient component. An implementation must not substitute ordinary ML-KEM,
/// Kyber, amKyber, or an incompatible parameter set.
pub trait MultiRecipientKem: Send + Sync {
    /// Generates a domain-bound public/private key pair.
    fn keygen(
        &self,
        domain: MkyberDomain,
        randomness: &mut dyn MkyberRandom,
    ) -> Result<MkyberKeyPair, MkyberError>;

    /// Encapsulates once for a validated recipient set.
    fn encapsulate(
        &self,
        recipients: &RecipientSet,
        randomness: &mut dyn MkyberRandom,
    ) -> Result<MkyberEncapsulation, MkyberError>;

    /// Extracts the recipient-specific component from a ciphertext set.
    fn extract_recipient_component(
        &self,
        ciphertext: &MkyberCiphertextSet,
        recipient: RecipientId,
    ) -> Result<MkyberRecipientCiphertext, MkyberError>;

    /// Decapsulates one recipient component from the domain-bound ciphertext set.
    fn decapsulate(
        &self,
        private_key: &MkyberDecapsulationKey,
        ciphertext: &MkyberCiphertextSet,
        recipient: RecipientId,
    ) -> Result<MkyberSharedSecret, MkyberError>;
}

/// Public field category included in a malformed-length error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublicField {
    /// Public mKyber encapsulation key.
    EncapsulationKey,
    /// Public common ciphertext component.
    CommonCiphertext,
    /// Public recipient ciphertext component.
    RecipientCiphertext,
}

/// Redacted errors for the mKyber abstraction boundary.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum MkyberError {
    /// A public fixed-size field has an invalid serialized length.
    #[error("invalid {field:?} length: expected {expected} bytes, got {actual}")]
    InvalidLength {
        /// Public field category.
        field: PublicField,
        /// Required public byte length.
        expected: usize,
        /// Observed public byte length.
        actual: usize,
    },
    /// Recipient set creation received no recipients.
    #[error("recipient set must not be empty")]
    EmptyRecipientSet,
    /// A public recipient identifier occurred more than once.
    #[error("recipient identifier is duplicated")]
    DuplicateRecipient(RecipientId),
    /// A requested recipient does not occur in this ciphertext set.
    #[error("recipient component is unavailable")]
    RecipientNotFound,
    /// Public domain-bound inputs do not belong to one domain.
    #[error("mKyber domain mismatch")]
    DomainMismatch,
    /// A backend attempted to construct empty secret material.
    #[error("secret material must not be empty")]
    EmptySecretMaterial,
    /// A backend rejected public input without exposing sensitive internals.
    #[error("mKyber backend rejected the operation")]
    BackendRejected,
}

fn copy_exact<const SIZE: usize>(
    bytes: &[u8],
    field: PublicField,
) -> Result<[u8; SIZE], MkyberError> {
    bytes.try_into().map_err(|_| MkyberError::InvalidLength {
        field,
        expected: SIZE,
        actual: bytes.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const DOMAIN: MkyberDomain = MkyberDomain::new([7; 32]);

    #[test]
    fn fixed_size_public_artifacts_reject_wrong_lengths() {
        assert_eq!(
            MkyberEncapsulationKey::from_bytes(DOMAIN, &[0; ENCAPSULATION_KEY_BYTES - 1]),
            Err(MkyberError::InvalidLength {
                field: PublicField::EncapsulationKey,
                expected: ENCAPSULATION_KEY_BYTES,
                actual: ENCAPSULATION_KEY_BYTES - 1,
            })
        );
        assert!(MkyberCommonCiphertext::from_bytes(&[0; COMMON_CIPHERTEXT_BYTES]).is_ok());
        assert!(MkyberRecipientCiphertext::from_bytes(&[0; RECIPIENT_CIPHERTEXT_BYTES]).is_ok());
    }

    #[test]
    fn recipient_set_rejects_mixed_domains_and_duplicates() {
        let key = MkyberEncapsulationKey::from_bytes(DOMAIN, &[0; ENCAPSULATION_KEY_BYTES])
            .expect("exact-size key must parse");
        let other_domain = MkyberDomain::new([8; 32]);
        let other_key =
            MkyberEncapsulationKey::from_bytes(other_domain, &[0; ENCAPSULATION_KEY_BYTES])
                .expect("exact-size key must parse");
        assert_eq!(
            RecipientSet::new(
                DOMAIN,
                vec![RecipientPublicKey {
                    recipient: RecipientId::new(1),
                    key: other_key,
                }],
            ),
            Err(MkyberError::DomainMismatch)
        );
        assert_eq!(
            RecipientSet::new(
                DOMAIN,
                vec![
                    RecipientPublicKey {
                        recipient: RecipientId::new(1),
                        key: key.clone(),
                    },
                    RecipientPublicKey {
                        recipient: RecipientId::new(1),
                        key,
                    },
                ],
            ),
            Err(MkyberError::DuplicateRecipient(RecipientId::new(1)))
        );
    }

    #[test]
    fn ciphertext_set_extracts_only_its_registered_recipient() {
        let common = MkyberCommonCiphertext::from_bytes(&[0; COMMON_CIPHERTEXT_BYTES])
            .expect("exact-size common component must parse");
        let recipient = MkyberRecipientCiphertext::from_bytes(&[0; RECIPIENT_CIPHERTEXT_BYTES])
            .expect("exact-size recipient component must parse");
        let ciphertext = MkyberCiphertextSet::new(
            DOMAIN,
            common,
            vec![RecipientCiphertext {
                recipient: RecipientId::new(3),
                component: recipient,
            }],
        )
        .expect("valid recipient set must construct");
        assert!(ciphertext.recipient_component(RecipientId::new(3)).is_ok());
        assert_eq!(
            ciphertext.recipient_component(RecipientId::new(4)),
            Err(MkyberError::RecipientNotFound)
        );
    }

    #[test]
    fn secret_debug_output_is_redacted() {
        let secret = MkyberSharedSecret::from_bytes(vec![42; 32])
            .expect("non-empty secret material must be accepted");
        assert!(!format!("{secret:?}").contains("42"));
    }
}
