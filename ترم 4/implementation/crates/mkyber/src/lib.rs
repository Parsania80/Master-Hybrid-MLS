#![forbid(unsafe_code)]

//! Specification-driven, reference-only mKyber512 abstraction.
//!
//! The public sizes in this module come from the mKyber paper as recorded in
//! ADR 0002. This is not ML-KEM, Kyber, amKyber, a production implementation,
//! or an interoperability claim. `EducationalMkyber512Reference` implements
//! the thesis-local profile fixed in ADR 0002; it is educational reference code
//! only and is not recommended for business or production use.

use core::fmt;

use rand_core::{CryptoRng, RngCore};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Digest, Sha3_256, Shake128, Shake256,
};
use subtle::ConstantTimeEq;
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

/// Educational thesis reference backend for the `mkyber512-thesis-v1` profile.
///
/// This implements the paper-level construction with the concrete mappings
/// recorded in ADR 0002. It is deliberately replaceable, uses schoolbook ring
/// arithmetic for reviewability, has no side-channel-resistance claim, and is
/// neither a production backend nor an mKyber interoperability implementation.
#[derive(Clone, Copy, Debug, Default)]
pub struct EducationalMkyber512Reference;

impl EducationalMkyber512Reference {
    /// Stable identifier for the thesis-local reference profile.
    pub const PROFILE_LABEL: &'static str = "mkyber512-thesis-v1";
}

impl MultiRecipientKem for EducationalMkyber512Reference {
    fn keygen(
        &self,
        domain: MkyberDomain,
        randomness: &mut dyn MkyberRandom,
    ) -> Result<MkyberKeyPair, MkyberError> {
        let mut entropy = [0_u8; 64];
        randomness.fill_bytes(&mut entropy);
        let secret_seed = hash32(TAG_KEYGEN_SECRET, &[&entropy]);
        let error_seed = hash32(TAG_KEYGEN_ERROR, &[&entropy]);
        let mut fallback = hash32(TAG_KEYGEN_FALLBACK, &[&entropy]);
        entropy.zeroize();

        let matrix = expand_matrix(domain);
        let mut secret = sample_polyvec(&secret_seed, 0, ETA1, TAG_KEYGEN_SECRET);
        let mut error = sample_polyvec(&error_seed, 0, ETA1, TAG_KEYGEN_ERROR);
        let mut public = add_polyvec(&matrix_times_vec(&matrix, &secret), &error);
        let public_bytes = pack_polyvec_12(&public);
        let public_key = MkyberEncapsulationKey::from_bytes(domain, &public_bytes)?;

        let secret_bytes = pack_polyvec_12(&secret);
        let mut private_bytes = Vec::with_capacity(REFERENCE_SECRET_KEY_BYTES);
        private_bytes.extend_from_slice(&secret_bytes);
        private_bytes.extend_from_slice(&public_bytes);
        private_bytes.extend_from_slice(&fallback);
        debug_assert_eq!(private_bytes.len(), REFERENCE_SECRET_KEY_BYTES);

        secret.zeroize();
        error.zeroize();
        public.zeroize();
        fallback.zeroize();

        let private_key = MkyberDecapsulationKey::from_bytes(domain, private_bytes)?;
        MkyberKeyPair::new(public_key, private_key)
    }

    fn encapsulate(
        &self,
        recipients: &RecipientSet,
        randomness: &mut dyn MkyberRandom,
    ) -> Result<MkyberEncapsulation, MkyberError> {
        let domain = recipients.domain();
        let mut entropy = [0_u8; 32];
        randomness.fill_bytes(&mut entropy);
        let mut message_hash = hash32(TAG_MESSAGE, &[&entropy]);
        entropy.zeroize();
        let mut message = [0_u8; MESSAGE_BYTES];
        message.copy_from_slice(&message_hash[..MESSAGE_BYTES]);
        message_hash.zeroize();

        let key_prime = hash32(TAG_KEY_PRIME, &[&message]);
        let g1_seed = hash32(TAG_G1, &[domain.as_bytes(), &message]);
        let matrix = expand_matrix(domain);
        let mut randomness_vector = sample_polyvec(&g1_seed, 0, ETA1, TAG_PRF1);
        let mut common_error = sample_polyvec(&g1_seed, K as u8, ETA2, TAG_PRF1);
        let mut common = add_polyvec(
            &row_times_matrix(&randomness_vector, &matrix),
            &common_error,
        );
        let common_component = pack_common(&common)?;

        let mut recipient_components = Vec::with_capacity(recipients.recipients().len());
        for recipient in recipients.recipients() {
            let mut recipient_public = unpack_polyvec_12(recipient.key.as_bytes())?;
            let g2_seed = hash32(
                TAG_G2,
                &[domain.as_bytes(), recipient.key.as_bytes(), &message],
            );
            let mut recipient_error = sample_poly(&g2_seed, 0, ETA2, TAG_PRF2);
            let mut value = add_poly(
                &add_poly(
                    &inner_product(&randomness_vector, &recipient_public),
                    &recipient_error,
                ),
                &encode_message(&message),
            );
            let component = pack_recipient(&value)?;
            recipient_components.push(RecipientCiphertext {
                recipient: recipient.recipient,
                component,
            });
            recipient_public.zeroize();
            recipient_error.zeroize();
            value.zeroize();
        }

        let ciphertext = MkyberCiphertextSet::new(domain, common_component, recipient_components)?;
        let shared_secret = MkyberSharedSecret::from_bytes(normal_shared_secret(
            &key_prime,
            domain,
            ciphertext.common(),
        ))?;

        message.zeroize();
        randomness_vector.zeroize();
        common_error.zeroize();
        common.zeroize();

        Ok(MkyberEncapsulation {
            ciphertext,
            shared_secret,
        })
    }

    fn extract_recipient_component(
        &self,
        ciphertext: &MkyberCiphertextSet,
        recipient: RecipientId,
    ) -> Result<MkyberRecipientCiphertext, MkyberError> {
        Ok(ciphertext.recipient_component(recipient)?.clone())
    }

    fn decapsulate(
        &self,
        private_key: &MkyberDecapsulationKey,
        ciphertext: &MkyberCiphertextSet,
        recipient: RecipientId,
    ) -> Result<MkyberSharedSecret, MkyberError> {
        if private_key.domain() != ciphertext.domain() {
            return Err(MkyberError::DomainMismatch);
        }

        let component = ciphertext.recipient_component(recipient)?;
        let (mut secret, mut public, mut fallback) = parse_reference_private_key(private_key)?;
        let mut common = unpack_common(ciphertext.common())?;
        let mut recipient_value = unpack_recipient(component)?;
        let mut message_poly = subtract_poly(&recipient_value, &inner_product(&common, &secret));
        let mut message = decode_message(&message_poly);
        let key_prime = hash32(TAG_KEY_PRIME, &[&message]);
        let g1_seed = hash32(TAG_G1, &[ciphertext.domain().as_bytes(), &message]);
        let matrix = expand_matrix(ciphertext.domain());
        let mut randomness_vector = sample_polyvec(&g1_seed, 0, ETA1, TAG_PRF1);
        let mut common_error = sample_polyvec(&g1_seed, K as u8, ETA2, TAG_PRF1);
        let mut expected_common = add_polyvec(
            &row_times_matrix(&randomness_vector, &matrix),
            &common_error,
        );
        let expected_common_component = pack_common(&expected_common)?;
        let g2_seed = hash32(
            TAG_G2,
            &[
                ciphertext.domain().as_bytes(),
                &pack_polyvec_12(&public),
                &message,
            ],
        );
        let mut recipient_error = sample_poly(&g2_seed, 0, ETA2, TAG_PRF2);
        let mut expected_value = add_poly(
            &add_poly(
                &inner_product(&randomness_vector, &public),
                &recipient_error,
            ),
            &encode_message(&message),
        );
        let expected_component = pack_recipient(&expected_value)?;

        let common_matches = expected_common_component
            .as_bytes()
            .ct_eq(ciphertext.common().as_bytes());
        let recipient_matches = expected_component.as_bytes().ct_eq(component.as_bytes());
        let valid = (common_matches & recipient_matches).unwrap_u8() == 1;
        let output = if valid {
            normal_shared_secret(&key_prime, ciphertext.domain(), ciphertext.common())
        } else {
            fallback_shared_secret(
                &fallback,
                ciphertext.domain(),
                ciphertext.common(),
                component,
            )
        };

        secret.zeroize();
        public.zeroize();
        fallback.zeroize();
        common.zeroize();
        recipient_value.zeroize();
        message_poly.zeroize();
        message.zeroize();
        randomness_vector.zeroize();
        common_error.zeroize();
        expected_common.zeroize();
        recipient_error.zeroize();
        expected_value.zeroize();

        MkyberSharedSecret::from_bytes(output)
    }
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

const Q: i32 = 3329;
const N: usize = 256;
const K: usize = 2;
const ETA1: usize = 3;
const ETA2: usize = 2;
const DU: usize = 11;
const DV: usize = 3;
const MESSAGE_BYTES: usize = 16;
const REFERENCE_SECRET_KEY_BYTES: usize = ENCAPSULATION_KEY_BYTES * 2 + 32;

const TAG_MATRIX: &[u8] = b"mkyber512-thesis-v1/matrix";
const TAG_KEYGEN_SECRET: &[u8] = b"mkyber512-thesis-v1/keygen-secret";
const TAG_KEYGEN_ERROR: &[u8] = b"mkyber512-thesis-v1/keygen-error";
const TAG_KEYGEN_FALLBACK: &[u8] = b"mkyber512-thesis-v1/keygen-fallback";
const TAG_MESSAGE: &[u8] = b"mkyber512-thesis-v1/message";
const TAG_KEY_PRIME: &[u8] = b"mkyber512-thesis-v1/key-prime";
const TAG_G1: &[u8] = b"mkyber512-thesis-v1/g1";
const TAG_G2: &[u8] = b"mkyber512-thesis-v1/g2";
const TAG_PRF1: &[u8] = b"mkyber512-thesis-v1/prf1";
const TAG_PRF2: &[u8] = b"mkyber512-thesis-v1/prf2";
const TAG_NORMAL_KDF: &[u8] = b"mkyber512-thesis-v1/kdf-normal";
const TAG_FALLBACK_KDF: &[u8] = b"mkyber512-thesis-v1/kdf-fallback";

type Poly = [i16; N];
type PolyVec = [Poly; K];
type Matrix = [[Poly; K]; K];

fn hash32(tag: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    Digest::update(&mut hasher, tag);
    for part in parts {
        Digest::update(&mut hasher, part);
    }
    hasher.finalize().into()
}

fn shake256(tag: &[u8], parts: &[&[u8]], output: &mut [u8]) {
    let mut hasher = Shake256::default();
    Update::update(&mut hasher, tag);
    for part in parts {
        Update::update(&mut hasher, part);
    }
    hasher.finalize_xof().read(output);
}

fn expand_matrix(domain: MkyberDomain) -> Matrix {
    core::array::from_fn(|row| {
        core::array::from_fn(|column| {
            let row = [row as u8];
            let column = [column as u8];
            let mut hasher = Shake128::default();
            Update::update(&mut hasher, TAG_MATRIX);
            Update::update(&mut hasher, domain.as_bytes());
            Update::update(&mut hasher, &row);
            Update::update(&mut hasher, &column);
            let mut reader = hasher.finalize_xof();
            let mut polynomial = [0_i16; N];
            let mut position = 0;
            while position < N {
                let mut stream = [0_u8; 3];
                reader.read(&mut stream);
                let low = u16::from(stream[0]) | (u16::from(stream[1] & 0x0f) << 8);
                let high = u16::from(stream[1] >> 4) | (u16::from(stream[2]) << 4);
                if low < Q as u16 {
                    polynomial[position] = low as i16;
                    position += 1;
                }
                if position < N && high < Q as u16 {
                    polynomial[position] = high as i16;
                    position += 1;
                }
            }
            polynomial
        })
    })
}

fn sample_polyvec(seed: &[u8; 32], nonce_base: u8, eta: usize, tag: &[u8]) -> PolyVec {
    core::array::from_fn(|index| sample_poly(seed, nonce_base + index as u8, eta, tag))
}

fn sample_poly(seed: &[u8; 32], nonce: u8, eta: usize, tag: &[u8]) -> Poly {
    let mut stream = vec![0_u8; (N * 2 * eta).div_ceil(8)];
    let nonce = [nonce];
    shake256(tag, &[seed, &nonce], &mut stream);
    let mut polynomial = [0_i16; N];
    for (coefficient, value) in polynomial.iter_mut().enumerate() {
        let first = bit_count(&stream, coefficient * 2 * eta, eta);
        let second = bit_count(&stream, coefficient * 2 * eta + eta, eta);
        *value = first as i16 - second as i16;
    }
    stream.zeroize();
    polynomial
}

fn bit_count(bytes: &[u8], start: usize, count: usize) -> u8 {
    (start..start + count)
        .map(|position| (bytes[position / 8] >> (position % 8)) & 1)
        .sum()
}

fn matrix_times_vec(matrix: &Matrix, vector: &PolyVec) -> PolyVec {
    core::array::from_fn(|row| {
        let mut output = [0_i16; N];
        for column in 0..K {
            output = add_poly(
                &output,
                &multiply_poly(&matrix[row][column], &vector[column]),
            );
        }
        output
    })
}

fn row_times_matrix(vector: &PolyVec, matrix: &Matrix) -> PolyVec {
    core::array::from_fn(|column| {
        let mut output = [0_i16; N];
        for row in 0..K {
            output = add_poly(&output, &multiply_poly(&vector[row], &matrix[row][column]));
        }
        output
    })
}

fn inner_product(left: &PolyVec, right: &PolyVec) -> Poly {
    let mut output = [0_i16; N];
    for index in 0..K {
        output = add_poly(&output, &multiply_poly(&left[index], &right[index]));
    }
    output
}

fn add_polyvec(left: &PolyVec, right: &PolyVec) -> PolyVec {
    core::array::from_fn(|index| add_poly(&left[index], &right[index]))
}

fn add_poly(left: &Poly, right: &Poly) -> Poly {
    core::array::from_fn(|index| mod_q(i32::from(left[index]) + i32::from(right[index])))
}

fn subtract_poly(left: &Poly, right: &Poly) -> Poly {
    core::array::from_fn(|index| mod_q(i32::from(left[index]) - i32::from(right[index])))
}

fn multiply_poly(left: &Poly, right: &Poly) -> Poly {
    let mut accumulator = [0_i64; N];
    for (left_index, left_value) in left.iter().enumerate() {
        for (right_index, right_value) in right.iter().enumerate() {
            let product = i64::from(*left_value) * i64::from(*right_value);
            let index = left_index + right_index;
            if index < N {
                accumulator[index] += product;
            } else {
                accumulator[index - N] -= product;
            }
        }
    }
    core::array::from_fn(|index| mod_q((accumulator[index] % i64::from(Q)) as i32))
}

fn mod_q(value: i32) -> i16 {
    let reduced = value % Q;
    (if reduced < 0 { reduced + Q } else { reduced }) as i16
}

fn encode_message(message: &[u8; MESSAGE_BYTES]) -> Poly {
    core::array::from_fn(|index| {
        if index < MESSAGE_BYTES * 8 && ((message[index / 8] >> (index % 8)) & 1) == 1 {
            ((Q + 1) / 2) as i16
        } else {
            0
        }
    })
}

fn decode_message(polynomial: &Poly) -> [u8; MESSAGE_BYTES] {
    let mut message = [0_u8; MESSAGE_BYTES];
    for index in 0..MESSAGE_BYTES * 8 {
        let coefficient = i32::from(polynomial[index]);
        let bit = (((coefficient << 1) + Q / 2) / Q) & 1;
        message[index / 8] |= (bit as u8) << (index % 8);
    }
    message
}

fn pack_polyvec_12(vector: &PolyVec) -> [u8; ENCAPSULATION_KEY_BYTES] {
    let mut output = [0_u8; ENCAPSULATION_KEY_BYTES];
    for (vector_index, polynomial) in vector.iter().enumerate() {
        for pair in 0..N / 2 {
            let first = mod_q(i32::from(polynomial[2 * pair])) as u16;
            let second = mod_q(i32::from(polynomial[2 * pair + 1])) as u16;
            let offset = vector_index * 384 + pair * 3;
            output[offset] = first as u8;
            output[offset + 1] = ((first >> 8) as u8) | ((second as u8) << 4);
            output[offset + 2] = (second >> 4) as u8;
        }
    }
    output
}

fn unpack_polyvec_12(bytes: &[u8]) -> Result<PolyVec, MkyberError> {
    if bytes.len() != ENCAPSULATION_KEY_BYTES {
        return Err(MkyberError::BackendRejected);
    }
    let mut vector = [[0_i16; N]; K];
    for (vector_index, polynomial) in vector.iter_mut().enumerate() {
        for pair in 0..N / 2 {
            let offset = vector_index * 384 + pair * 3;
            let first = u16::from(bytes[offset]) | (u16::from(bytes[offset + 1] & 0x0f) << 8);
            let second = u16::from(bytes[offset + 1] >> 4) | (u16::from(bytes[offset + 2]) << 4);
            if first >= Q as u16 || second >= Q as u16 {
                return Err(MkyberError::BackendRejected);
            }
            polynomial[2 * pair] = first as i16;
            polynomial[2 * pair + 1] = second as i16;
        }
    }
    Ok(vector)
}

fn pack_common(vector: &PolyVec) -> Result<MkyberCommonCiphertext, MkyberError> {
    let mut bytes = Vec::with_capacity(COMMON_CIPHERTEXT_BYTES);
    for polynomial in vector {
        bytes.extend_from_slice(&pack_compressed(polynomial, DU, N));
    }
    MkyberCommonCiphertext::from_bytes(&bytes)
}

fn unpack_common(component: &MkyberCommonCiphertext) -> Result<PolyVec, MkyberError> {
    let bytes = component.as_bytes();
    let polynomial_bytes = N * DU / 8;
    Ok(core::array::from_fn(|index| {
        unpack_compressed(
            &bytes[index * polynomial_bytes..(index + 1) * polynomial_bytes],
            DU,
            N,
        )
    }))
}

fn pack_recipient(polynomial: &Poly) -> Result<MkyberRecipientCiphertext, MkyberError> {
    MkyberRecipientCiphertext::from_bytes(&pack_compressed(polynomial, DV, MESSAGE_BYTES * 8))
}

fn unpack_recipient(component: &MkyberRecipientCiphertext) -> Result<Poly, MkyberError> {
    let mut polynomial = [0_i16; N];
    let unpacked = unpack_compressed(component.as_bytes(), DV, MESSAGE_BYTES * 8);
    polynomial[..MESSAGE_BYTES * 8].copy_from_slice(&unpacked[..MESSAGE_BYTES * 8]);
    Ok(polynomial)
}

fn pack_compressed(polynomial: &Poly, bits: usize, coefficient_count: usize) -> Vec<u8> {
    let mut output = vec![0_u8; coefficient_count * bits / 8];
    let mut accumulator = 0_u32;
    let mut accumulator_bits = 0_usize;
    let mut offset = 0;
    for coefficient in polynomial.iter().take(coefficient_count) {
        let compressed = (((u32::try_from(*coefficient).expect("canonical coefficient") << bits)
            + (Q as u32 / 2))
            / Q as u32)
            & ((1_u32 << bits) - 1);
        accumulator |= compressed << accumulator_bits;
        accumulator_bits += bits;
        while accumulator_bits >= 8 {
            output[offset] = accumulator as u8;
            offset += 1;
            accumulator >>= 8;
            accumulator_bits -= 8;
        }
    }
    debug_assert_eq!(offset, output.len());
    output
}

fn unpack_compressed(bytes: &[u8], bits: usize, coefficient_count: usize) -> Poly {
    let mut polynomial = [0_i16; N];
    let mut accumulator = 0_u32;
    let mut accumulator_bits = 0_usize;
    let mut offset = 0;
    for coefficient in polynomial.iter_mut().take(coefficient_count) {
        while accumulator_bits < bits {
            accumulator |= u32::from(bytes[offset]) << accumulator_bits;
            offset += 1;
            accumulator_bits += 8;
        }
        let compressed = accumulator & ((1_u32 << bits) - 1);
        accumulator >>= bits;
        accumulator_bits -= bits;
        *coefficient = (((compressed * Q as u32) + (1 << (bits - 1))) >> bits) as i16;
    }
    polynomial
}

fn parse_reference_private_key(
    private_key: &MkyberDecapsulationKey,
) -> Result<(PolyVec, PolyVec, [u8; 32]), MkyberError> {
    let bytes = private_key.as_bytes();
    if bytes.len() != REFERENCE_SECRET_KEY_BYTES {
        return Err(MkyberError::BackendRejected);
    }
    let secret = unpack_polyvec_12(&bytes[..ENCAPSULATION_KEY_BYTES])?;
    let public = unpack_polyvec_12(&bytes[ENCAPSULATION_KEY_BYTES..ENCAPSULATION_KEY_BYTES * 2])?;
    let fallback: [u8; 32] = bytes[ENCAPSULATION_KEY_BYTES * 2..]
        .try_into()
        .map_err(|_| MkyberError::BackendRejected)?;
    Ok((secret, public, fallback))
}

fn normal_shared_secret(
    key_prime: &[u8; 32],
    domain: MkyberDomain,
    common: &MkyberCommonCiphertext,
) -> Vec<u8> {
    hash32(
        TAG_NORMAL_KDF,
        &[key_prime, domain.as_bytes(), common.as_bytes()],
    )
    .to_vec()
}

fn fallback_shared_secret(
    fallback: &[u8; 32],
    domain: MkyberDomain,
    common: &MkyberCommonCiphertext,
    recipient: &MkyberRecipientCiphertext,
) -> Vec<u8> {
    hash32(
        TAG_FALLBACK_KDF,
        &[
            fallback,
            domain.as_bytes(),
            common.as_bytes(),
            recipient.as_bytes(),
        ],
    )
    .to_vec()
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

    struct TestRng(u64);

    impl RngCore for TestRng {
        fn next_u32(&mut self) -> u32 {
            self.next_u64() as u32
        }

        fn next_u64(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            self.0
        }

        fn fill_bytes(&mut self, destination: &mut [u8]) {
            for chunk in destination.chunks_mut(8) {
                let bytes = self.next_u64().to_le_bytes();
                chunk.copy_from_slice(&bytes[..chunk.len()]);
            }
        }

        fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(destination);
            Ok(())
        }
    }

    impl CryptoRng for TestRng {}

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

    #[test]
    fn educational_reference_backend_agrees_for_two_recipients() {
        let backend = EducationalMkyber512Reference;
        let mut rng = TestRng(1);
        let alice = backend
            .keygen(DOMAIN, &mut rng)
            .expect("reference key generation must succeed");
        let bob = backend
            .keygen(DOMAIN, &mut rng)
            .expect("reference key generation must succeed");
        let recipients = RecipientSet::new(
            DOMAIN,
            vec![
                RecipientPublicKey {
                    recipient: RecipientId::new(1),
                    key: alice.public_key().clone(),
                },
                RecipientPublicKey {
                    recipient: RecipientId::new(2),
                    key: bob.public_key().clone(),
                },
            ],
        )
        .expect("same-domain recipients must construct");

        let encapsulation = backend
            .encapsulate(&recipients, &mut rng)
            .expect("reference encapsulation must succeed");
        assert_eq!(
            encapsulation.ciphertext.common().as_bytes().len(),
            COMMON_CIPHERTEXT_BYTES
        );
        assert_eq!(
            encapsulation
                .ciphertext
                .recipient_component(RecipientId::new(1))
                .expect("alice component")
                .as_bytes()
                .len(),
            RECIPIENT_CIPHERTEXT_BYTES
        );

        let alice_secret = backend
            .decapsulate(
                alice.private_key(),
                &encapsulation.ciphertext,
                RecipientId::new(1),
            )
            .expect("alice decapsulation must succeed");
        let bob_secret = backend
            .decapsulate(
                bob.private_key(),
                &encapsulation.ciphertext,
                RecipientId::new(2),
            )
            .expect("bob decapsulation must succeed");
        assert_eq!(
            alice_secret.as_bytes(),
            encapsulation.shared_secret.as_bytes()
        );
        assert_eq!(
            bob_secret.as_bytes(),
            encapsulation.shared_secret.as_bytes()
        );
    }

    #[test]
    fn educational_reference_backend_uses_fallback_for_tampered_component() {
        let backend = EducationalMkyber512Reference;
        let mut rng = TestRng(2);
        let key_pair = backend
            .keygen(DOMAIN, &mut rng)
            .expect("reference key generation must succeed");
        let recipients = RecipientSet::new(
            DOMAIN,
            vec![RecipientPublicKey {
                recipient: RecipientId::new(9),
                key: key_pair.public_key().clone(),
            }],
        )
        .expect("recipient set must construct");
        let encapsulation = backend
            .encapsulate(&recipients, &mut rng)
            .expect("reference encapsulation must succeed");
        let mut tampered_bytes = *encapsulation
            .ciphertext
            .recipient_component(RecipientId::new(9))
            .expect("recipient component")
            .as_bytes();
        tampered_bytes[0] ^= 1;
        let tampered = MkyberCiphertextSet::new(
            DOMAIN,
            encapsulation.ciphertext.common().clone(),
            vec![RecipientCiphertext {
                recipient: RecipientId::new(9),
                component: MkyberRecipientCiphertext::from_bytes(&tampered_bytes)
                    .expect("fixed-size tampered component"),
            }],
        )
        .expect("tampered ciphertext shape must remain valid");
        let fallback = backend
            .decapsulate(key_pair.private_key(), &tampered, RecipientId::new(9))
            .expect("invalid ciphertext must produce fallback secret");
        assert_ne!(fallback.as_bytes(), encapsulation.shared_secret.as_bytes());
    }

    #[test]
    fn educational_reference_backend_is_deterministic_for_test_rng() {
        let backend = EducationalMkyber512Reference;
        let mut first_rng = TestRng(3);
        let mut second_rng = TestRng(3);
        let first = backend
            .keygen(DOMAIN, &mut first_rng)
            .expect("first key generation must succeed");
        let second = backend
            .keygen(DOMAIN, &mut second_rng)
            .expect("second key generation must succeed");
        assert_eq!(
            first.public_key().as_bytes(),
            second.public_key().as_bytes()
        );
    }

    #[test]
    fn educational_reference_backend_rejects_cross_domain_and_non_recipient_inputs() {
        let backend = EducationalMkyber512Reference;
        let mut rng = TestRng(4);
        let alice = backend
            .keygen(DOMAIN, &mut rng)
            .expect("reference key generation must succeed");
        let other_domain = MkyberDomain::new([8; 32]);
        let bob = backend
            .keygen(other_domain, &mut rng)
            .expect("reference key generation must succeed");
        let other_recipients = RecipientSet::new(
            other_domain,
            vec![RecipientPublicKey {
                recipient: RecipientId::new(4),
                key: bob.public_key().clone(),
            }],
        )
        .expect("recipient set must construct");
        let other_ciphertext = backend
            .encapsulate(&other_recipients, &mut rng)
            .expect("reference encapsulation must succeed");
        assert!(matches!(
            backend.decapsulate(
                alice.private_key(),
                &other_ciphertext.ciphertext,
                RecipientId::new(4),
            ),
            Err(MkyberError::DomainMismatch)
        ));

        let recipients = RecipientSet::new(
            DOMAIN,
            vec![RecipientPublicKey {
                recipient: RecipientId::new(5),
                key: alice.public_key().clone(),
            }],
        )
        .expect("recipient set must construct");
        let ciphertext = backend
            .encapsulate(&recipients, &mut rng)
            .expect("reference encapsulation must succeed");
        assert!(matches!(
            backend.decapsulate(
                alice.private_key(),
                &ciphertext.ciphertext,
                RecipientId::new(6),
            ),
            Err(MkyberError::RecipientNotFound)
        ));
    }

    #[test]
    fn educational_reference_backend_rejects_non_canonical_public_key() {
        let backend = EducationalMkyber512Reference;
        let malformed_key =
            MkyberEncapsulationKey::from_bytes(DOMAIN, &[0xff; ENCAPSULATION_KEY_BYTES])
                .expect("fixed-size public bytes reach backend validation");
        let recipients = RecipientSet::new(
            DOMAIN,
            vec![RecipientPublicKey {
                recipient: RecipientId::new(8),
                key: malformed_key,
            }],
        )
        .expect("recipient set validates domain and identifier only");
        let mut rng = TestRng(5);
        assert!(matches!(
            backend.encapsulate(&recipients, &mut rng),
            Err(MkyberError::BackendRejected)
        ));
    }
}
