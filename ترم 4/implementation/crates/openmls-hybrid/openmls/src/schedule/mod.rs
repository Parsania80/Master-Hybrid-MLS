//! # Key Schedule
//!
//! This module defines types and implementations for key schedule operations.
//! It provides the [`EpochAuthenticator`] and [`ResumptionPskSecret`] types.
//!
//! ## Internal Documentation
//!
//! The key schedule is described in Section 8 of the MLS specification. It
//! evolves in epochs, with new key material injected in each epoch.
//!
//! The key schedule flow (from Section 8 of the MLS specification) is as follows:
//
// ```text
//                  init_secret_[n-1]
//                         |
//                         V
//    commit_secret -> KDF.Extract
//                         |
//                         V
//                   DeriveSecret(., "joiner")
//                         |
//                         V
//                    joiner_secret
//                         |
//                         V
// psk_secret (or 0) -> KDF.Extract (= intermediary_secret)
//                         |
//                         +--> DeriveSecret(., "welcome")
//                         |    = welcome_secret
//                         |
//                         V
//                   ExpandWithLabel(., "epoch", GroupContext_[n], KDF.Nh)
//                         |
//                         V
//                    epoch_secret
//                         |
//                         +--> DeriveSecret(., <label>)
//                         |    = <secret>
//                         |
//                         V
//                   DeriveSecret(., "init")
//                         |
//                         V
//                   init_secret_[n]
// ```
//
// Each secret in the key schedule (except welcome_secret) has its own struct to
// prevent confusion or out-of-order derivation. This ensures clarity and safety
// in the key schedule operations.
//
// ## Key schedule structure
// The spec's key schedule isn't a single linear process. The `joiner_secret`
// serves as both an intermediate and output value, which violates key schedule
// principles. The actual key schedule begins with the `joiner_secret`, as seen
// when initializing a group from a welcome message.
//
// The `joiner_secret` is computed as
//
// ```text
//     DeriveSecret(KDF.Extract(init_secret_[n-1], commit_secret), "joiner")
// ```
//
// or
//
// ```text
//                  init_secret_[n-1]
//                         |
//                         V
//    commit_secret -> KDF.Extract
//                         |
//                         V
//                   DeriveSecret(., "joiner")
//                         |
//                         V
//                    joiner_secret
// ```
//
// The key schedule continues with `joiner_secret` and `psk_secret`. The graph
// below includes `GroupContext_[n]` as input, which is omitted in the spec. The
// derivation of secrets from `epoch_secret` is simplified for clarity.
//
// ```text
//                    joiner_secret
//                         |
//                         V
// psk_secret (or 0) -> KDF.Extract
//                         |
//                         +--> DeriveSecret(., "welcome")
//                         |    = welcome_secret
//                         |
//                         V
// GroupContext_[n] -> ExpandWithLabel(., "epoch", GroupContext_[n], KDF.Nh)
//                         |
//                         V
//                    epoch_secret
//                         |
//                         v
//                 DeriveSecret(., <label>)
//                     = <secret>
// ```
//
// with
//
// ```text
// | secret                  | label           |
// |:------------------------|:----------------|
// | `init_secret`           | "init"          |
// | `sender_data_secret`    | "sender data"   |
// | `encryption_secret`     | "encryption"    |
// | `exporter_secret`       | "exporter"      |
// | `epoch_authenticator`   | "authentication"|
// | `external_secret`       | "external"      |
// | `confirmation_key`      | "confirm"       |
// | `membership_key`        | "membership"    |
// | `resumption_psk`        | "resumption"    |
// ```

use openmls_traits::{crypto::OpenMlsCrypto, types::*};
use serde::{Deserialize, Serialize};
#[cfg(feature = "experimental-hybrid")]
use tls_codec::Serialize as _;
use tls_codec::{TlsDeserialize, TlsDeserializeBytes, TlsSerialize, TlsSize};

use crate::{
    binary_tree::array_representation::{LeafNodeIndex, TreeSize},
    ciphersuite::{AeadKey, AeadNonce, HpkePrivateKey, Mac, Secret},
    error::LibraryError,
    framing::{mls_content::AuthenticatedContentTbm, MembershipTag},
    group::GroupContext,
    messages::{ConfirmationTag, PathSecret},
    tree::secret_tree::SecretTree,
    versions::ProtocolVersion,
};

#[cfg(feature = "experimental-hybrid")]
use crate::{
    binary_tree::array_representation::direct_path,
    treesync::node::encryption_keys::{EncryptionKey, EncryptionKeyPair},
};
#[cfg(feature = "experimental-hybrid")]
use adaptive_tree::BinaryToQuaternaryLeafMapping;
#[cfg(feature = "experimental-hybrid")]
use arity_state::{hash_canonical_public_bytes, ArityLifecycle, ArityState};
#[cfg(feature = "experimental-hybrid")]
use transition_tree::{ActiveQuaternaryTree, DeliveryOnlyTreeCover};

// Public
pub mod errors;
#[cfg(feature = "extensions-draft-08")]
mod pprf;
pub mod psk;

#[cfg(feature = "extensions-draft-08")]
pub use pprf::PprfError;

// Crate
#[cfg(feature = "extensions-draft-08")]
pub(crate) mod application_export_tree;
pub(crate) mod message_secrets;

// Private
use errors::*;
use message_secrets::MessageSecrets;
use openmls_traits::random::OpenMlsRand;
use psk::PskSecret;

// Tests and kats
#[cfg(any(feature = "test-utils", test))]
pub mod tests_and_kats;

// Public types
pub use psk::{ExternalPsk, PreSharedKeyId, Psk};

/// A group secret that can be used among members to prove that a member was
/// part of a group in a given epoch.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "test-utils"), derive(Eq, PartialEq))]
pub struct ResumptionPskSecret {
    secret: Secret,
}

impl ResumptionPskSecret {
    /// Derive an `ResumptionPsk` from an `EpochSecret`.
    fn new(
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        epoch_secret: &EpochSecret,
    ) -> Result<Self, CryptoError> {
        let secret = epoch_secret
            .secret
            .derive_secret(crypto, ciphersuite, "resumption")?;
        Ok(Self { secret })
    }

    /// Returns the secret as a slice.
    pub fn as_slice(&self) -> &[u8] {
        self.secret.as_slice()
    }
}

/// A secret that can be used among members to make sure everyone has the same
/// group state.
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "test-utils"), derive(Eq, PartialEq, Clone))]
pub struct EpochAuthenticator {
    secret: Secret,
}

impl EpochAuthenticator {
    /// Derive an `EpochAuthenticator` from an `EpochSecret`.
    fn new(
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        epoch_secret: &EpochSecret,
    ) -> Result<Self, CryptoError> {
        let secret = epoch_secret
            .secret
            .derive_secret(crypto, ciphersuite, "authentication")?;
        Ok(Self { secret })
    }

    /// Returns the secret as a slice.
    pub fn as_slice(&self) -> &[u8] {
        self.secret.as_slice()
    }
}

// Crate-only types

#[derive(Debug, Default, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq))]
#[cfg_attr(any(feature = "test-utils", test), derive(Clone))]
pub(crate) struct CommitSecret {
    secret: Secret,
}

impl From<PathSecret> for CommitSecret {
    fn from(path_secret: PathSecret) -> Self {
        CommitSecret {
            secret: path_secret.secret(),
        }
    }
}

impl CommitSecret {
    /// Create a CommitSecret consisting of an all-zero string of length
    /// `hash_length`.
    pub(crate) fn zero_secret(ciphersuite: Ciphersuite) -> Self {
        CommitSecret {
            secret: Secret::zero(ciphersuite),
        }
    }

    #[cfg(any(feature = "test-utils", test))]
    pub(crate) fn random(ciphersuite: Ciphersuite, rng: &impl OpenMlsRand) -> Self {
        Self {
            secret: Secret::random(ciphersuite, rng).expect("Not enough randomness."),
        }
    }

    #[cfg(any(feature = "test-utils", test))]
    pub(crate) fn as_slice(&self) -> &[u8] {
        self.secret.as_slice()
    }
}

/// The `InitSecret` is used to connect the next epoch to the current one.
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "test-utils"), derive(PartialEq, Clone))]
pub(crate) struct InitSecret {
    secret: Secret,
}

impl From<Secret> for InitSecret {
    fn from(secret: Secret) -> Self {
        Self { secret }
    }
}

/// Creates a string from the given MLS `ProtocolVersion` for the computation of
/// the `init_secret` when creating or processing a commit with an external init
/// proposal.
fn hpke_info_from_version(version: ProtocolVersion) -> &'static str {
    match version {
        ProtocolVersion::Mls10 => "MLS 1.0 external init secret",
        _ => "<OpenMLS reserved; Don't use this.>",
    }
}

impl InitSecret {
    /// Derive an `InitSecret` from an `EpochSecret`.
    fn new(
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        epoch_secret: EpochSecret,
    ) -> Result<Self, CryptoError> {
        let secret = epoch_secret
            .secret
            .derive_secret(crypto, ciphersuite, "init")?;
        log_crypto!(trace, "Init secret: {:x?}", secret);
        Ok(InitSecret { secret })
    }

    /// Sample a fresh, random `InitSecret` for the creation of a new group.
    pub(crate) fn random(
        ciphersuite: Ciphersuite,
        rand: &impl OpenMlsRand,
    ) -> Result<Self, CryptoError> {
        Ok(InitSecret {
            secret: Secret::random(ciphersuite, rand)?,
        })
    }

    /// Create an `InitSecret` and the corresponding `kem_output` from a group info.
    pub(crate) fn from_group_context(
        crypto: &impl OpenMlsCrypto,
        group_context: &GroupContext,
        external_pub: &[u8],
    ) -> Result<(Self, Vec<u8>), KeyScheduleError> {
        let ciphersuite = group_context.ciphersuite();
        let version = group_context.protocol_version();
        let (kem_output, raw_init_secret) = crypto.hpke_setup_sender_and_export(
            ciphersuite.hpke_config(),
            external_pub,
            &[],
            hpke_info_from_version(version).as_bytes(),
            ciphersuite.hash_length(),
        )?;
        Ok((
            InitSecret {
                secret: Secret::from_slice(&raw_init_secret),
            },
            kem_output,
        ))
    }

    /// Create an `InitSecret` from a `kem_output`.
    pub(crate) fn from_kem_output(
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        version: ProtocolVersion,
        external_priv: &HpkePrivateKey,
        kem_output: &[u8],
    ) -> Result<Self, LibraryError> {
        let raw_init_secret = crypto
            .hpke_setup_receiver_and_export(
                ciphersuite.hpke_config(),
                kem_output,
                external_priv,
                &[],
                hpke_info_from_version(version).as_bytes(),
                ciphersuite.hash_length(),
            )
            .map_err(LibraryError::unexpected_crypto_error)?;
        Ok(InitSecret {
            secret: Secret::from_slice(&raw_init_secret),
        })
    }

    #[cfg(any(feature = "test-utils", test))]
    pub(crate) fn clone(&self) -> Self {
        Self {
            secret: self.secret.clone(),
        }
    }

    #[cfg(any(feature = "test-utils", test))]
    pub(crate) fn as_slice(&self) -> &[u8] {
        self.secret.as_slice()
    }
}

#[derive(Debug, TlsDeserialize, TlsDeserializeBytes, TlsSerialize, TlsSize)]
pub(crate) struct JoinerSecret {
    secret: Secret,
}

impl JoinerSecret {
    /// Derive a `JoinerSecret` from an optional `CommitSecret` and an
    /// `EpochSecrets` object, which contains the necessary `InitSecret`. The
    /// `CommitSecret` needs to be present if the current commit is not a
    /// partial commit.
    pub(crate) fn new(
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        commit_secret_option: impl Into<Option<CommitSecret>>,
        init_secret: &InitSecret,
        serialized_group_context: &[u8],
    ) -> Result<Self, CryptoError> {
        let intermediate_secret = init_secret.secret.hkdf_extract(
            crypto,
            ciphersuite,
            commit_secret_option.into().as_ref().map(|cs| &cs.secret),
        )?;
        let secret = intermediate_secret.kdf_expand_label(
            crypto,
            ciphersuite,
            "joiner",
            serialized_group_context,
            ciphersuite.hash_length(),
        )?;
        log_crypto!(trace, "Joiner secret: {:x?}", secret);
        Ok(JoinerSecret { secret })
    }

    #[cfg(any(feature = "test-utils", test))]
    pub(crate) fn as_slice(&self) -> &[u8] {
        self.secret.as_slice()
    }

    #[cfg(test)]
    pub(crate) fn random(ciphersuite: Ciphersuite, rand: &impl OpenMlsRand) -> Self {
        Self {
            secret: Secret::random(ciphersuite, rand).expect("Not enough randomness."),
        }
    }
}

// Different states of the key schedule
#[derive(Debug, PartialEq)]
enum State {
    Initial,
    Context,
    Done,
}

pub(crate) struct KeySchedule {
    ciphersuite: Ciphersuite,
    intermediate_secret: Option<IntermediateSecret>,
    epoch_secret: Option<EpochSecret>,
    state: State,
}

pub(crate) struct EpochSecretsResult {
    pub(crate) epoch_secrets: EpochSecrets,
    #[cfg(feature = "extensions-draft-08")]
    pub(crate) application_exporter: ApplicationExportSecret,
}

impl KeySchedule {
    /// Initialize the key schedule and return it.
    pub(crate) fn init(
        ciphersuite: Ciphersuite,
        crypto: &impl OpenMlsCrypto,
        joiner_secret: &JoinerSecret,
        psk: PskSecret,
    ) -> Result<Self, LibraryError> {
        log::debug!("Initializing the key schedule with {ciphersuite:?} ...");
        log_crypto!(
            trace,
            "  joiner_secret: {:x?}",
            joiner_secret.secret.as_slice()
        );
        let intermediate_secret = IntermediateSecret::new(crypto, ciphersuite, joiner_secret, psk)
            .map_err(LibraryError::unexpected_crypto_error)?;
        Ok(Self {
            ciphersuite,
            intermediate_secret: Some(intermediate_secret),
            epoch_secret: None,
            state: State::Initial,
        })
    }

    /// Derive the welcome secret.
    /// Note that this has to be called before the context is added.
    pub(crate) fn welcome(
        &self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
    ) -> Result<WelcomeSecret, KeyScheduleError> {
        if self.state != State::Initial || self.intermediate_secret.is_none() {
            log::error!("Trying to derive a welcome secret while not in the initial state.");
            return Err(KeyScheduleError::InvalidState(ErrorState::Init));
        }

        // We can return a library error here, because there must be a mistake in the state machine
        let intermediate_secret = self
            .intermediate_secret
            .as_ref()
            .ok_or_else(|| LibraryError::custom("state machine error"))?;

        Ok(WelcomeSecret::new(
            crypto,
            ciphersuite,
            intermediate_secret,
        )?)
    }

    /// Add the group context to the key schedule.
    pub(crate) fn add_context(
        &mut self,
        crypto: &impl OpenMlsCrypto,
        serialized_group_context: &[u8],
    ) -> Result<(), KeyScheduleError> {
        log::trace!("Adding context to key schedule. {serialized_group_context:?}");
        if self.state != State::Initial || self.intermediate_secret.is_none() {
            log::error!(
                "Trying to add context to the key schedule while not in the initial state."
            );
            return Err(KeyScheduleError::InvalidState(ErrorState::Init));
        }
        self.state = State::Context;

        // We can return a library error here, because there must be a mistake in the state machine
        let intermediate_secret = self
            .intermediate_secret
            .take()
            .ok_or_else(|| LibraryError::custom("state machine error"))?;

        log_crypto!(
            trace,
            "  intermediate_secret: {:x?}",
            intermediate_secret.secret.as_slice()
        );

        self.epoch_secret = Some(EpochSecret::new(
            self.ciphersuite,
            crypto,
            intermediate_secret,
            serialized_group_context,
        )?);
        self.intermediate_secret = None;
        Ok(())
    }

    /// Derive the epoch secrets.
    /// If the `with_init_secret` argument is `true`, the init secret is derived and
    /// part of the `EpochSecrets`. Otherwise not.
    pub(crate) fn epoch_secrets(
        &mut self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
    ) -> Result<EpochSecretsResult, KeyScheduleError> {
        if self.state != State::Context || self.epoch_secret.is_none() {
            log::error!("Trying to derive the epoch secrets while not in the right state.");
            return Err(KeyScheduleError::InvalidState(ErrorState::Context));
        }
        self.state = State::Done;

        let epoch_secret = match self.epoch_secret.take() {
            Some(epoch_secret) => epoch_secret,
            // We can return a library error here, because there must be a mistake in the state machine
            None => return Err(LibraryError::custom("state machine error").into()),
        };

        let res = EpochSecretsResult {
            #[cfg(feature = "extensions-draft-08")]
            application_exporter: ApplicationExportSecret::new(crypto, ciphersuite, &epoch_secret)?,
            epoch_secrets: EpochSecrets::new(crypto, ciphersuite, epoch_secret)?,
        };

        Ok(res)
    }
}

/// The intermediate secret includes the optional PSK and is used to later
/// derive the welcome secret and epoch secret
struct IntermediateSecret {
    secret: Secret,
}

impl IntermediateSecret {
    /// Derive an `IntermediateSecret` from a `JoinerSecret` and an optional
    /// PSK.
    fn new(
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        joiner_secret: &JoinerSecret,
        psk: PskSecret,
    ) -> Result<Self, CryptoError> {
        log_crypto!(trace, "PSK input: {:x?}", psk.as_slice());
        let secret = joiner_secret
            .secret
            .hkdf_extract(crypto, ciphersuite, psk.secret())?;
        log_crypto!(trace, "Intermediate secret: {:x?}", secret);
        Ok(Self { secret })
    }
}

pub(crate) struct WelcomeSecret {
    secret: Secret,
}

impl WelcomeSecret {
    /// Derive a `WelcomeSecret` from to decrypt a `Welcome` message.
    fn new(
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        intermediate_secret: &IntermediateSecret,
    ) -> Result<Self, CryptoError> {
        let secret = intermediate_secret
            .secret
            .derive_secret(crypto, ciphersuite, "welcome")?;
        log_crypto!(trace, "Welcome secret: {:x?}", secret);
        Ok(WelcomeSecret { secret })
    }

    /// Derive an `AeadKey` and an `AeadNonce` from the `WelcomeSecret`,
    /// consuming it in the process.
    pub(crate) fn derive_welcome_key_nonce(
        self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
    ) -> Result<(AeadKey, AeadNonce), CryptoError> {
        let welcome_nonce = self.derive_aead_nonce(crypto, ciphersuite)?;
        let welcome_key = self.derive_aead_key(crypto, ciphersuite)?;
        Ok((welcome_key, welcome_nonce))
    }

    /// Derive a new AEAD key from a `WelcomeSecret`.
    fn derive_aead_key(
        &self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
    ) -> Result<AeadKey, CryptoError> {
        log::trace!("WelcomeSecret.derive_aead_key with {ciphersuite}");
        let aead_secret = self.secret.kdf_expand_label(
            crypto,
            ciphersuite,
            "key",
            b"",
            ciphersuite.aead_key_length(),
        )?;
        Ok(AeadKey::from_secret(aead_secret, ciphersuite))
    }

    /// Derive a new AEAD nonce from a `WelcomeSecret`.
    fn derive_aead_nonce(
        &self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
    ) -> Result<AeadNonce, CryptoError> {
        let nonce_secret = self.secret.kdf_expand_label(
            crypto,
            ciphersuite,
            "nonce",
            b"",
            ciphersuite.aead_nonce_length(),
        )?;
        Ok(AeadNonce::from_secret(nonce_secret))
    }

    #[cfg(any(feature = "test-utils", test))]
    pub(crate) fn as_slice(&self) -> &[u8] {
        self.secret.as_slice()
    }
}

/// An intermediate secret in the key schedule, the `EpochSecret` is used to
/// create an `EpochSecrets` object and is finally consumed when creating that
/// epoch's `InitSecret`.
struct EpochSecret {
    secret: Secret,
}

impl EpochSecret {
    /// Derive an `EpochSecret` from a `JoinerSecret`
    fn new(
        ciphersuite: Ciphersuite,
        crypto: &impl OpenMlsCrypto,
        intermediate_secret: IntermediateSecret,
        serialized_group_context: &[u8],
    ) -> Result<Self, CryptoError> {
        let secret = intermediate_secret.secret.kdf_expand_label(
            crypto,
            ciphersuite,
            "epoch",
            serialized_group_context,
            ciphersuite.hash_length(),
        )?;
        log_crypto!(trace, "Epoch secret: {:x?}", secret);
        Ok(EpochSecret { secret })
    }
}

/// The `EncryptionSecret` is used to create a `SecretTree`.
#[cfg_attr(test, derive(Clone))]
pub(crate) struct EncryptionSecret {
    secret: Secret,
}

impl EncryptionSecret {
    /// Derive an encryption secret from a reference to an `EpochSecret`.
    fn new(
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        epoch_secret: &EpochSecret,
    ) -> Result<Self, CryptoError> {
        Ok(EncryptionSecret {
            secret: epoch_secret
                .secret
                .derive_secret(crypto, ciphersuite, "encryption")?,
        })
    }

    /// Create a `SecretTree` from the `encryption_secret` contained in the
    /// `EpochSecrets`. The `encryption_secret` is consumed, allowing us to achieve FS.
    pub(crate) fn create_secret_tree(
        self,
        treesize: TreeSize,
        own_index: LeafNodeIndex,
    ) -> SecretTree {
        SecretTree::new(self, treesize, own_index)
    }

    pub(crate) fn consume_secret(self) -> Secret {
        self.secret
    }

    /// Create a random `EncryptionSecret`. For testing purposes only.
    #[cfg(test)]
    pub(crate) fn random(ciphersuite: Ciphersuite, rng: &impl OpenMlsRand) -> Self {
        EncryptionSecret {
            secret: Secret::random(ciphersuite, rng).expect("Not enough randomness."),
        }
    }

    #[cfg(any(feature = "test-utils", test))]
    pub(crate) fn as_slice(&self) -> &[u8] {
        self.secret.as_slice()
    }

    #[cfg(any(feature = "test-utils", test))]
    /// Create a new secret from a byte vector.
    pub(crate) fn from_slice(bytes: &[u8]) -> Self {
        Self {
            secret: Secret::from_slice(bytes),
        }
    }
}

/// A secret that we can derive secrets from, that are used outside of OpenMLS.
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "test-utils"), derive(PartialEq, Clone))]
pub(crate) struct ExporterSecret {
    secret: Secret,
}

impl ExporterSecret {
    /// Derive an `ExporterSecret` from an `EpochSecret`.
    fn new(
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        epoch_secret: &EpochSecret,
    ) -> Result<Self, CryptoError> {
        let secret = epoch_secret
            .secret
            .derive_secret(crypto, ciphersuite, "exporter")?;
        Ok(ExporterSecret { secret })
    }

    #[cfg(any(feature = "test-utils", test))]
    pub(crate) fn as_slice(&self) -> &[u8] {
        self.secret.as_slice()
    }

    /// Derive a `Secret` from the exporter secret. We return `Vec<u8>` here, so
    /// it can be used outside of OpenMLS. This function is made available for
    /// use from the outside through [`MlsGroup::export_secret`].
    pub(crate) fn derive_exported_secret(
        &self,
        ciphersuite: Ciphersuite,
        crypto: &impl OpenMlsCrypto,
        label: &str,
        context: &[u8],
        key_length: usize,
    ) -> Result<Vec<u8>, CryptoError> {
        let context_hash = &crypto.hash(ciphersuite.hash_algorithm(), context)?;
        Ok(self
            .secret
            .derive_secret(crypto, ciphersuite, label)?
            .kdf_expand_label(crypto, ciphersuite, "exported", context_hash, key_length)?
            .as_slice()
            .to_vec())
    }
}

/// A secret that we can derive secrets from, that are used outside of OpenMLS.
/// In contrast to `[ExporterSecret]`, the `[ApplicationExportSecret]` is not
/// persisted. It can be deleted after use to achieve forward secrecy.
#[cfg(feature = "extensions-draft-08")]
#[derive(Debug, Serialize, Deserialize, Clone)]
#[cfg_attr(any(test, feature = "test-utils"), derive(PartialEq))]
pub struct ApplicationExportSecret {
    secret: Secret,
}

#[cfg(feature = "extensions-draft-08")]
impl ApplicationExportSecret {
    /// Derive an `ExporterSecret` from an `EpochSecret`.
    fn new(
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        epoch_secret: &EpochSecret,
    ) -> Result<Self, CryptoError> {
        let secret =
            epoch_secret
                .secret
                .derive_secret(crypto, ciphersuite, "application_export")?;
        Ok(ApplicationExportSecret { secret })
    }
}

/// A secret used when joining a group with an external Commit.
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "test-utils"), derive(PartialEq, Clone))]
pub(crate) struct ExternalSecret {
    secret: Secret,
}

impl ExternalSecret {
    /// Derive an `ExternalSecret` from an `EpochSecret`.
    fn new(
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        epoch_secret: &EpochSecret,
    ) -> Result<Self, CryptoError> {
        let secret = epoch_secret
            .secret
            .derive_secret(crypto, ciphersuite, "external")?;
        Ok(Self { secret })
    }

    /// Derive the external keypair for External Commits
    pub(crate) fn derive_external_keypair(
        &self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
    ) -> Result<HpkeKeyPair, CryptoError> {
        crypto.derive_hpke_keypair(ciphersuite.hpke_config(), self.secret.as_slice())
    }

    #[cfg(any(feature = "test-utils", test))]
    pub(crate) fn as_slice(&self) -> &[u8] {
        self.secret.as_slice()
    }
}

/// The confirmation key is used to calculate the `ConfirmationTag`.
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "test-utils"), derive(PartialEq, Clone))]
pub(crate) struct ConfirmationKey {
    secret: Secret,
}

impl ConfirmationKey {
    /// Derive an `ConfirmationKey` from an `EpochSecret`.
    fn new(
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        epoch_secret: &EpochSecret,
    ) -> Result<Self, CryptoError> {
        log::debug!("Computing confirmation key.");
        log_crypto!(
            trace,
            "  epoch_secret {:x?}",
            epoch_secret.secret.as_slice()
        );
        let secret = epoch_secret
            .secret
            .derive_secret(crypto, ciphersuite, "confirm")?;
        Ok(Self { secret })
    }

    /// Create a new confirmation tag.
    ///
    /// >  11.2. Commit
    ///
    /// ```text
    /// PublicMessage.confirmation_tag =
    ///     MAC(confirmation_key, GroupContext.confirmed_transcript_hash)
    /// ```
    pub(crate) fn tag(
        &self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        confirmed_transcript_hash: &[u8],
    ) -> Result<ConfirmationTag, CryptoError> {
        log::debug!("Computing confirmation tag.");
        log_crypto!(trace, "  confirmation key {:x?}", self.secret.as_slice());
        log_crypto!(trace, "  transcript hash  {:x?}", confirmed_transcript_hash);
        Ok(ConfirmationTag(Mac::new(
            crypto,
            ciphersuite,
            &self.secret,
            confirmed_transcript_hash,
        )?))
    }
}

#[cfg(test)]
impl ConfirmationKey {
    pub(crate) fn from_secret(secret: Secret) -> Self {
        Self { secret }
    }
}

#[cfg(any(feature = "test-utils", test))]
impl ConfirmationKey {
    pub(crate) fn random(ciphersuite: Ciphersuite, rng: &impl OpenMlsRand) -> Self {
        Self {
            secret: Secret::random(ciphersuite, rng).expect("Not enough randomness."),
        }
    }

    pub(crate) fn as_slice(&self) -> &[u8] {
        self.secret.as_slice()
    }
}

/// The membership key is used to calculate the `MembershipTag`.
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "test-utils"), derive(PartialEq, Clone))]
pub(crate) struct MembershipKey {
    secret: Secret,
}

impl MembershipKey {
    /// Derive an `MembershipKey` from an `EpochSecret`.
    fn new(
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        epoch_secret: &EpochSecret,
    ) -> Result<Self, CryptoError> {
        let secret = epoch_secret
            .secret
            .derive_secret(crypto, ciphersuite, "membership")?;
        Ok(Self { secret })
    }

    /// Create a new membership tag.
    ///
    /// 9.1 Content Authentication
    ///
    /// ```text
    /// membership_tag = MAC(membership_key, MLSPlaintextTBM);
    /// ```
    pub(crate) fn tag_message(
        &self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        tbm_payload: AuthenticatedContentTbm,
    ) -> Result<MembershipTag, LibraryError> {
        Ok(MembershipTag(
            Mac::new(
                crypto,
                ciphersuite,
                &self.secret,
                &tbm_payload
                    .into_bytes()
                    .map_err(LibraryError::missing_bound_check)?,
            )
            .map_err(LibraryError::unexpected_crypto_error)?,
        ))
    }

    #[cfg(any(feature = "test-utils", test))]
    pub(crate) fn from_secret(secret: Secret) -> Self {
        Self { secret }
    }

    #[cfg(any(feature = "test-utils", test))]
    pub(crate) fn as_slice(&self) -> &[u8] {
        self.secret.as_slice()
    }

    #[cfg(any(feature = "test-utils", test))]
    pub(crate) fn random(ciphersuite: Ciphersuite, rng: &impl OpenMlsRand) -> Self {
        Self {
            secret: Secret::random(ciphersuite, rng).expect("Not enough randomness."),
        }
    }
}

// Get a ciphertext sample of `hash_length` from the ciphertext.
fn ciphertext_sample(ciphersuite: Ciphersuite, ciphertext: &[u8]) -> &[u8] {
    let sample_length = ciphersuite.hash_length();
    log::debug!("Getting ciphertext sample of length {sample_length:?}");
    if ciphertext.len() <= sample_length {
        ciphertext
    } else {
        &ciphertext[0..sample_length]
    }
}

/// A key that can be used to derive an `AeadKey` and an `AeadNonce`.
#[derive(Serialize, Deserialize)]
#[cfg_attr(
    any(feature = "test-utils", feature = "crypto-debug", test),
    derive(Debug, Clone, PartialEq)
)]
pub(crate) struct SenderDataSecret {
    secret: Secret,
}

impl SenderDataSecret {
    /// Derive an `ExporterSecret` from an `EpochSecret`.
    fn new(
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        epoch_secret: &EpochSecret,
    ) -> Result<Self, CryptoError> {
        let secret = epoch_secret
            .secret
            .derive_secret(crypto, ciphersuite, "sender data")?;
        Ok(SenderDataSecret { secret })
    }

    /// Derive a new AEAD key from a `SenderDataSecret`.
    pub(crate) fn derive_aead_key(
        &self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        ciphertext: &[u8],
    ) -> Result<AeadKey, CryptoError> {
        let ciphertext_sample = ciphertext_sample(ciphersuite, ciphertext);
        log::debug!("SenderDataSecret::derive_aead_key ciphertext sample: {ciphertext_sample:x?}");
        let secret = self.secret.kdf_expand_label(
            crypto,
            ciphersuite,
            "key",
            ciphertext_sample,
            ciphersuite.aead_key_length(),
        )?;
        Ok(AeadKey::from_secret(secret, ciphersuite))
    }

    /// Derive a new AEAD nonce from a `SenderDataSecret`.
    pub(crate) fn derive_aead_nonce(
        &self,
        ciphersuite: Ciphersuite,
        crypto: &impl OpenMlsCrypto,
        ciphertext: &[u8],
    ) -> Result<AeadNonce, CryptoError> {
        let ciphertext_sample = ciphertext_sample(ciphersuite, ciphertext);
        log::debug!(
            "SenderDataSecret::derive_aead_nonce ciphertext sample: {ciphertext_sample:x?}"
        );
        let nonce_secret = self.secret.kdf_expand_label(
            crypto,
            ciphersuite,
            "nonce",
            ciphertext_sample,
            ciphersuite.aead_nonce_length(),
        )?;
        Ok(AeadNonce::from_secret(nonce_secret))
    }

    #[cfg(any(feature = "test-utils", test))]
    pub(crate) fn random(ciphersuite: Ciphersuite, rng: &impl OpenMlsRand) -> Self {
        Self {
            secret: Secret::random(ciphersuite, rng).expect("Not enough randomness."),
        }
    }

    #[cfg(any(feature = "test-utils", test))]
    pub(crate) fn as_slice(&self) -> &[u8] {
        self.secret.as_slice()
    }

    #[cfg(any(feature = "test-utils", test))]
    /// Create a new secret from a byte vector.
    pub(crate) fn from_slice(bytes: &[u8]) -> Self {
        Self {
            secret: Secret::from_slice(bytes),
        }
    }
}

/// The `EpochSecrets` contain keys (or secrets), which are accessible outside
/// of the `KeySchedule` and which don't get consumed immediately upon first
/// use.
///
/// | Secret                  | Label           |
/// |:------------------------|:----------------|
/// | `init_secret`           | "init"          |
/// | `sender_data_secret`    | "sender data"   |
/// | `encryption_secret`     | "encryption"    |
/// | `exporter_secret`       | "exporter"      |
/// | `epoch_authenticator`   | "authentication"|
/// | `external_secret`       | "external"      |
/// | `confirmation_key`      | "confirm"       |
/// | `membership_key`        | "membership"    |
/// | `resumption_psk`        | "resumption"    |
pub(crate) struct EpochSecrets {
    init_secret: InitSecret,
    sender_data_secret: SenderDataSecret,
    encryption_secret: EncryptionSecret,
    exporter_secret: ExporterSecret,
    epoch_authenticator: EpochAuthenticator,
    external_secret: ExternalSecret,
    confirmation_key: ConfirmationKey,
    membership_key: MembershipKey,
    resumption_psk: ResumptionPskSecret,
}

impl std::fmt::Debug for EpochSecrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EpochSecrets { *** }")
    }
}

#[cfg(not(test))]
impl PartialEq for EpochSecrets {
    fn eq(&self, _other: &Self) -> bool {
        false
    }
}

// In tests we allow comparing secrets.
#[cfg(test)]
impl PartialEq for EpochSecrets {
    fn eq(&self, other: &Self) -> bool {
        self.sender_data_secret == other.sender_data_secret
            && self.exporter_secret == other.exporter_secret
            && self.epoch_authenticator == other.epoch_authenticator
            && self.external_secret == other.external_secret
            && self.confirmation_key == other.confirmation_key
            && self.membership_key == other.membership_key
            && self.resumption_psk == other.resumption_psk
    }
}

impl EpochSecrets {
    /// Get the sender_data secret.
    #[cfg(any(feature = "test-utils", test))]
    pub(crate) fn sender_data_secret(&self) -> &SenderDataSecret {
        &self.sender_data_secret
    }

    /// Get the confirmation key.
    pub(crate) fn confirmation_key(&self) -> &ConfirmationKey {
        &self.confirmation_key
    }

    /// Epoch authenticator
    #[cfg(any(feature = "test-utils", test))]
    pub(crate) fn epoch_authenticator(&self) -> &EpochAuthenticator {
        &self.epoch_authenticator
    }

    /// Exporter secret
    #[cfg(any(feature = "test-utils", test))]
    pub(crate) fn exporter_secret(&self) -> &ExporterSecret {
        &self.exporter_secret
    }

    /// Membership key
    #[cfg(any(feature = "test-utils", test))]
    pub(crate) fn membership_key(&self) -> &MembershipKey {
        &self.membership_key
    }

    /// External secret
    pub(crate) fn external_secret(&self) -> &ExternalSecret {
        &self.external_secret
    }

    /// External secret
    #[cfg(any(feature = "test-utils", test))]
    pub(crate) fn resumption_psk(&self) -> &ResumptionPskSecret {
        &self.resumption_psk
    }

    /// Init secret
    #[cfg(any(feature = "test-utils", test))]
    pub(crate) fn init_secret(&self) -> &InitSecret {
        &self.init_secret
    }

    /// Encryption secret
    #[cfg(any(feature = "test-utils", test))]
    pub(crate) fn encryption_secret(&self) -> &EncryptionSecret {
        &self.encryption_secret
    }

    /// Derive `EpochSecrets` from an `EpochSecret`.
    /// If the `with_init_secret` argument is `true`, the init secret is derived and
    /// part of the `EpochSecrets`. Otherwise not.
    fn new(
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        epoch_secret: EpochSecret,
    ) -> Result<Self, CryptoError> {
        log::debug!("Computing EpochSecrets from epoch secret with {ciphersuite}");
        log_crypto!(
            trace,
            "  epoch_secret: {:x?}",
            epoch_secret.secret.as_slice()
        );
        let sender_data_secret = SenderDataSecret::new(crypto, ciphersuite, &epoch_secret)?;
        let encryption_secret = EncryptionSecret::new(crypto, ciphersuite, &epoch_secret)?;
        let exporter_secret = ExporterSecret::new(crypto, ciphersuite, &epoch_secret)?;
        let epoch_authenticator = EpochAuthenticator::new(crypto, ciphersuite, &epoch_secret)?;
        let external_secret = ExternalSecret::new(crypto, ciphersuite, &epoch_secret)?;
        let confirmation_key = ConfirmationKey::new(crypto, ciphersuite, &epoch_secret)?;
        let membership_key = MembershipKey::new(crypto, ciphersuite, &epoch_secret)?;
        let resumption_psk = ResumptionPskSecret::new(crypto, ciphersuite, &epoch_secret)?;

        log::trace!("  Computing init secret.");
        let init_secret = InitSecret::new(crypto, ciphersuite, epoch_secret)?;

        Ok(EpochSecrets {
            init_secret,
            sender_data_secret,
            encryption_secret,
            exporter_secret,
            epoch_authenticator,
            external_secret,
            confirmation_key,
            membership_key,
            resumption_psk,
        })
    }

    /// This function initializes the `EpochSecrets` from an all-zero
    /// epoch-secret with the exception of the `init_secret`, which is populated
    /// with the given `InitSecret`. This is meant to be used in the case of an
    /// external init.
    pub(crate) fn with_init_secret(
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        init_secret: InitSecret,
    ) -> Result<Self, CryptoError> {
        let epoch_secret = EpochSecret {
            secret: Secret::zero(ciphersuite),
        };
        let mut epoch_secrets = Self::new(crypto, ciphersuite, epoch_secret)?;
        epoch_secrets.init_secret = init_secret;
        Ok(epoch_secrets)
    }

    /// Splits `EpochSecrets` into two different categories:
    ///  - [`GroupEpochSecrets`]: These secrets are only used within the same epoch
    ///  - [`MessageSecrets`]: These secrets are potentially also used for past epochs
    ///    to decrypt and validate messages
    pub(crate) fn split_secrets(
        self,
        serialized_context: Vec<u8>,
        treesize: TreeSize,
        own_index: LeafNodeIndex,
    ) -> (GroupEpochSecrets, MessageSecrets) {
        let secret_tree = self
            .encryption_secret
            .create_secret_tree(treesize, own_index);
        (
            GroupEpochSecrets {
                init_secret: self.init_secret,
                exporter_secret: self.exporter_secret,
                epoch_authenticator: self.epoch_authenticator,
                external_secret: self.external_secret,
                resumption_psk: self.resumption_psk,
                #[cfg(feature = "experimental-hybrid")]
                experimental_quaternary_epoch_secret: None,
                #[cfg(feature = "experimental-hybrid")]
                experimental_transition_node_state: None,
            },
            MessageSecrets::new(
                self.sender_data_secret,
                self.membership_key,
                self.confirmation_key,
                serialized_context,
                secret_tree,
            ),
        )
    }
}

#[derive(Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "test-utils"), derive(Clone, PartialEq))]
pub(crate) struct GroupEpochSecrets {
    init_secret: InitSecret,
    exporter_secret: ExporterSecret,
    epoch_authenticator: EpochAuthenticator,
    external_secret: ExternalSecret,
    resumption_psk: ResumptionPskSecret,
    #[cfg(feature = "experimental-hybrid")]
    #[serde(default)]
    experimental_quaternary_epoch_secret: Option<ExperimentalQuaternaryEpochSecret>,
    #[cfg(feature = "experimental-hybrid")]
    #[serde(default)]
    experimental_transition_node_state: Option<ExperimentalTransitionNodeState>,
}

impl std::fmt::Debug for GroupEpochSecrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("GroupEpochSecrets { *** }")
    }
}

#[cfg(not(any(test, feature = "test-utils")))]
impl PartialEq for GroupEpochSecrets {
    fn eq(&self, _other: &Self) -> bool {
        false
    }
}

impl GroupEpochSecrets {
    /// Init secret
    pub(crate) fn init_secret(&self) -> &InitSecret {
        &self.init_secret
    }

    /// Epoch authenticator
    pub(crate) fn epoch_authenticator(&self) -> &EpochAuthenticator {
        &self.epoch_authenticator
    }

    /// Exporter secret
    pub(crate) fn exporter_secret(&self) -> &ExporterSecret {
        &self.exporter_secret
    }

    /// External secret
    pub(crate) fn external_secret(&self) -> &ExternalSecret {
        &self.external_secret
    }

    /// External secret
    pub(crate) fn resumption_psk(&self) -> &ResumptionPskSecret {
        &self.resumption_psk
    }

    /// Derives and persists the fork-local quaternary authority for one
    /// authenticated transitioning epoch.
    ///
    /// The authority is derived only from the newly established MLS exporter
    /// secret and complete provisional GroupContext. An accepted MLS UpdatePath
    /// must therefore advance the MLS epoch before this authority can rotate.
    /// This method never exposes secret bytes.
    #[cfg(feature = "experimental-hybrid")]
    pub(crate) fn activate_experimental_quaternary_epoch_secret(
        &mut self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        serialized_group_context: &[u8],
        epoch: u64,
        state: &arity_state::ArityState,
        mut parent_keypairs: Vec<EncryptionKeyPair>,
    ) -> Result<(), LibraryError> {
        state
            .validate()
            .map_err(|_| LibraryError::custom("invalid experimental transition ArityState"))?;
        if state.active_arity() != 4 || state.candidate_arity() != 4 || state.tree_version() == 0 {
            return Err(LibraryError::custom(
                "experimental quaternary authority requires active quaternary ArityState",
            ));
        }
        let arity_state::ArityLifecycle::Transitioning(transitioning) = state.lifecycle() else {
            return Err(LibraryError::custom(
                "experimental quaternary authority requires transitioning ArityState",
            ));
        };
        if transitioning.transition_epoch() > epoch {
            return Err(LibraryError::custom(
                "experimental quaternary authority precedes its transition epoch",
            ));
        }
        let root_keypair = parent_keypairs.first().ok_or_else(|| {
            LibraryError::custom("experimental quaternary authority requires parent key pairs")
        })?;
        let public_mkyber_key = root_keypair
            .public_key()
            .experimental_mkyber_key()
            .ok_or_else(|| {
                LibraryError::custom("experimental quaternary root lacks mKyber public key")
            })?;
        let private_mkyber_key = root_keypair
            .experimental_mkyber_private_key()
            .map_err(|_| {
                LibraryError::custom("experimental quaternary root has invalid mKyber private key")
            })?
            .ok_or_else(|| {
                LibraryError::custom("experimental quaternary root lacks mKyber private key")
            })?;
        if private_mkyber_key.domain() != public_mkyber_key.domain() {
            return Err(LibraryError::custom(
                "experimental quaternary root mKyber domains do not match",
            ));
        }
        let serialized_root_public_key = root_keypair
            .public_key()
            .tls_serialize_detached()
            .map_err(LibraryError::missing_bound_check)?;
        let root_public_key_hash = crypto
            .hash(ciphersuite.hash_algorithm(), &serialized_root_public_key)
            .map_err(LibraryError::unexpected_crypto_error)?;
        let root_public_key_hash = root_public_key_hash.as_slice().try_into().map_err(|_| {
            LibraryError::custom("invalid experimental quaternary root public-key hash length")
        })?;
        let secret = self
            .exporter_secret
            .derive_exported_secret(
                ciphersuite,
                crypto,
                "experimental quaternary epoch authority",
                serialized_group_context,
                ciphersuite.hash_length(),
            )
            .map_err(LibraryError::unexpected_crypto_error)?;
        self.experimental_quaternary_epoch_secret = Some(ExperimentalQuaternaryEpochSecret {
            epoch,
            tree_version: state.tree_version(),
            mapping_hash: *transitioning.mapping_hash().as_bytes(),
            secret: Secret::from_slice(&secret),
            root_keypair: Some(parent_keypairs.remove(0)),
            root_public_key_hash,
            additional_parent_keypairs: parent_keypairs,
        });
        Ok(())
    }

    /// Returns public metadata for the persisted experimental quaternary
    /// authority without exposing secret bytes.
    #[cfg(feature = "experimental-hybrid")]
    pub(crate) fn experimental_quaternary_epoch_secret_status(
        &self,
    ) -> Option<ExperimentalQuaternaryEpochSecretStatus> {
        self.experimental_quaternary_epoch_secret
            .as_ref()
            .map(ExperimentalQuaternaryEpochSecret::status)
    }

    #[cfg(feature = "experimental-hybrid")]
    pub(crate) fn experimental_quaternary_parent_keypairs(
        &self,
    ) -> Result<Vec<EncryptionKeyPair>, LibraryError> {
        let authority = self
            .experimental_quaternary_epoch_secret
            .as_ref()
            .ok_or_else(|| {
                LibraryError::custom("experimental group has no quaternary epoch authority")
            })?;
        let root = authority.root_keypair.as_ref().ok_or_else(|| {
            LibraryError::custom("experimental quaternary authority has no root key pair")
        })?;
        Ok(std::iter::once(root.clone())
            .chain(authority.additional_parent_keypairs.iter().cloned())
            .collect())
    }

    #[cfg(feature = "experimental-hybrid")]
    pub(crate) fn install_experimental_transition_node_state(
        &mut self,
        state: ExperimentalTransitionNodeState,
    ) {
        self.experimental_transition_node_state = Some(state);
    }

    #[cfg(feature = "experimental-hybrid")]
    pub(crate) fn experimental_transition_node_state(
        &self,
    ) -> Option<&ExperimentalTransitionNodeState> {
        self.experimental_transition_node_state.as_ref()
    }

    #[cfg(feature = "experimental-hybrid")]
    pub(crate) fn experimental_transition_mapping(&self) -> Option<&BinaryToQuaternaryLeafMapping> {
        self.experimental_transition_node_state
            .as_ref()
            .map(|state| &state.mapping)
    }

    #[cfg(feature = "experimental-hybrid")]
    pub(crate) fn experimental_transition_node_availability_status(
        &self,
    ) -> Option<ExperimentalTransitionNodeAvailabilityStatus> {
        self.experimental_transition_node_state
            .as_ref()
            .map(ExperimentalTransitionNodeState::status)
    }

    #[cfg(feature = "experimental-hybrid")]
    pub(crate) fn experimental_transition_node_availability_snapshot(
        &self,
    ) -> Option<ExperimentalTransitionNodeAvailabilitySnapshot> {
        self.experimental_transition_node_state
            .as_ref()
            .map(ExperimentalTransitionNodeState::snapshot)
    }

    /// Checks that the persisted quaternary root record still has matched
    /// public/private mKyber material. This touches no secret bytes and lets a
    /// reload reject an obsolete authority record that predates root storage.
    #[cfg(feature = "experimental-hybrid")]
    pub(crate) fn validate_experimental_quaternary_root_keypair(&self) -> Result<(), LibraryError> {
        let authority = self
            .experimental_quaternary_epoch_secret
            .as_ref()
            .ok_or_else(|| {
                LibraryError::custom("experimental group has no quaternary epoch authority")
            })?;
        let root_keypair = authority.root_keypair.as_ref().ok_or_else(|| {
            LibraryError::custom("experimental quaternary authority has no persisted root key pair")
        })?;
        let public_mkyber_key = root_keypair
            .public_key()
            .experimental_mkyber_key()
            .ok_or_else(|| {
                LibraryError::custom(
                    "persisted experimental quaternary root lacks mKyber public key",
                )
            })?;
        let private_mkyber_key = root_keypair
            .experimental_mkyber_private_key()
            .map_err(|_| {
                LibraryError::custom(
                    "persisted experimental quaternary root has invalid mKyber private key",
                )
            })?
            .ok_or_else(|| {
                LibraryError::custom(
                    "persisted experimental quaternary root lacks mKyber private key",
                )
            })?;
        if private_mkyber_key.domain() != public_mkyber_key.domain() {
            return Err(LibraryError::custom(
                "persisted experimental quaternary root mKyber domains do not match",
            ));
        }
        for parent_keypair in &authority.additional_parent_keypairs {
            let public_mkyber_key = parent_keypair
                .public_key()
                .experimental_mkyber_key()
                .ok_or_else(|| {
                    LibraryError::custom(
                        "persisted experimental quaternary parent lacks mKyber public key",
                    )
                })?;
            let private_mkyber_key = parent_keypair
                .experimental_mkyber_private_key()
                .map_err(|_| {
                    LibraryError::custom(
                        "persisted experimental quaternary parent has invalid mKyber private key",
                    )
                })?
                .ok_or_else(|| {
                    LibraryError::custom(
                        "persisted experimental quaternary parent lacks mKyber private key",
                    )
                })?;
            if private_mkyber_key.domain() != public_mkyber_key.domain() {
                return Err(LibraryError::custom(
                    "persisted experimental quaternary parent mKyber domains do not match",
                ));
            }
        }
        Ok(())
    }
}

/// Redacted public metadata for a persisted experimental quaternary authority.
#[cfg(feature = "experimental-hybrid")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExperimentalQuaternaryEpochSecretStatus {
    epoch: u64,
    tree_version: u32,
    mapping_hash: [u8; 32],
    root_public_key_hash: [u8; 32],
    parent_key_count: u32,
}

#[cfg(feature = "experimental-hybrid")]
impl ExperimentalQuaternaryEpochSecretStatus {
    /// Returns the MLS epoch that produced this authority.
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Returns the authenticated active quaternary tree version.
    pub const fn tree_version(&self) -> u32 {
        self.tree_version
    }

    /// Returns the authenticated deterministic mapping digest.
    pub const fn mapping_hash(&self) -> &[u8; 32] {
        &self.mapping_hash
    }

    /// Returns a digest of the persisted root public key, never private bytes.
    pub const fn root_public_key_hash(&self) -> &[u8; 32] {
        &self.root_public_key_hash
    }

    /// Returns the number of persisted quaternary parent private pairs.
    pub const fn parent_key_count(&self) -> u32 {
        self.parent_key_count
    }
}

#[cfg(feature = "experimental-hybrid")]
#[derive(Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "test-utils"), derive(Clone, PartialEq))]
struct ExperimentalQuaternaryEpochSecret {
    epoch: u64,
    tree_version: u32,
    mapping_hash: [u8; 32],
    secret: Secret,
    #[serde(default)]
    root_keypair: Option<EncryptionKeyPair>,
    #[serde(default)]
    root_public_key_hash: [u8; 32],
    #[serde(default)]
    additional_parent_keypairs: Vec<EncryptionKeyPair>,
}

#[cfg(feature = "experimental-hybrid")]
impl std::fmt::Debug for ExperimentalQuaternaryEpochSecret {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ExperimentalQuaternaryEpochSecret { *** }")
    }
}

#[cfg(feature = "experimental-hybrid")]
impl ExperimentalQuaternaryEpochSecret {
    const fn status(&self) -> ExperimentalQuaternaryEpochSecretStatus {
        ExperimentalQuaternaryEpochSecretStatus {
            epoch: self.epoch,
            tree_version: self.tree_version,
            mapping_hash: self.mapping_hash,
            root_public_key_hash: self.root_public_key_hash,
            parent_key_count: 1 + self.additional_parent_keypairs.len() as u32,
        }
    }
}

/// Redacted public metadata for retained old/new transition-node availability.
#[cfg(feature = "experimental-hybrid")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExperimentalTransitionNodeAvailabilityStatus {
    tree_version: u32,
    mapping_hash: [u8; 32],
    treecover_hash: [u8; 32],
    active_member_count: u32,
    usable_old_node_count: u32,
    usable_new_node_count: u32,
    local_old_private_node_count: u32,
    retained_new_private_node_count: u32,
}

/// One ciphertext-free retained new-tree parent coordinate.
#[cfg(feature = "experimental-hybrid")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExperimentalTransitionNodeCoordinate {
    depth: u8,
    ordinal: u32,
}

#[cfg(feature = "experimental-hybrid")]
impl ExperimentalTransitionNodeCoordinate {
    /// Returns the root-relative depth, where the root is zero.
    pub const fn depth(&self) -> u8 {
        self.depth
    }

    /// Returns the left-to-right ordinal at this depth.
    pub const fn ordinal(&self) -> u32 {
        self.ordinal
    }
}

/// Ciphertext-free topology and availability retained by a transitioning group.
#[cfg(feature = "experimental-hybrid")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExperimentalTransitionNodeAvailabilitySnapshot {
    tree_version: u32,
    mapping_hash: [u8; 32],
    treecover_version: u32,
    treecover_hash: [u8; 32],
    frozen_mapping: BinaryToQuaternaryLeafMapping,
    active_quaternary_leaf_ordinals: Vec<u32>,
    usable_old_parent_indices: Vec<u32>,
    usable_new_parent_nodes: Vec<ExperimentalTransitionNodeCoordinate>,
}

#[cfg(feature = "experimental-hybrid")]
impl ExperimentalTransitionNodeAvailabilitySnapshot {
    /// Returns the authenticated active quaternary tree version.
    pub const fn tree_version(&self) -> u32 {
        self.tree_version
    }

    /// Returns the digest of the frozen mapping.
    pub const fn mapping_hash(&self) -> &[u8; 32] {
        &self.mapping_hash
    }

    /// Returns the initial frozen TreeCover version.
    pub const fn treecover_version(&self) -> u32 {
        self.treecover_version
    }

    /// Returns the digest of the initial frozen TreeCover.
    pub const fn treecover_hash(&self) -> &[u8; 32] {
        &self.treecover_hash
    }

    /// Returns the complete authenticated transition mapping, including holes.
    pub const fn frozen_mapping(&self) -> &BinaryToQuaternaryLeafMapping {
        &self.frozen_mapping
    }

    /// Returns the sorted quaternary leaf ordinals that remain active.
    pub fn active_quaternary_leaf_ordinals(&self) -> &[u32] {
        &self.active_quaternary_leaf_ordinals
    }

    /// Returns sorted usable parent indices in the frozen binary TreeCover.
    pub fn usable_old_parent_indices(&self) -> &[u32] {
        &self.usable_old_parent_indices
    }

    /// Returns sorted usable parent coordinates in the active quaternary tree.
    pub fn usable_new_parent_nodes(&self) -> &[ExperimentalTransitionNodeCoordinate] {
        &self.usable_new_parent_nodes
    }
}

#[cfg(feature = "experimental-hybrid")]
impl ExperimentalTransitionNodeAvailabilityStatus {
    /// Returns the authenticated active quaternary tree version.
    pub const fn tree_version(&self) -> u32 {
        self.tree_version
    }

    /// Returns the digest of the frozen binary-to-quaternary mapping.
    pub const fn mapping_hash(&self) -> &[u8; 32] {
        &self.mapping_hash
    }

    /// Returns the digest of the initial frozen binary TreeCover.
    pub const fn treecover_hash(&self) -> &[u8; 32] {
        &self.treecover_hash
    }

    /// Returns the number of members that remain active.
    pub const fn active_member_count(&self) -> u32 {
        self.active_member_count
    }

    /// Returns the number of old public parent values not invalidated by Remove.
    pub const fn usable_old_node_count(&self) -> u32 {
        self.usable_old_node_count
    }

    /// Returns the number of accumulated new quaternary parent values.
    pub const fn usable_new_node_count(&self) -> u32 {
        self.usable_new_node_count
    }

    /// Returns the number of usable old parents with locally retained private material.
    pub const fn local_old_private_node_count(&self) -> u32 {
        self.local_old_private_node_count
    }

    /// Returns the number of new parents with locally retained private material.
    pub const fn retained_new_private_node_count(&self) -> u32 {
        self.retained_new_private_node_count
    }
}

#[cfg(feature = "experimental-hybrid")]
#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "test-utils"), derive(PartialEq))]
pub(crate) struct ExperimentalTransitionNodeState {
    tree_version: u32,
    mapping_hash: [u8; 32],
    treecover_version: u32,
    treecover_hash: [u8; 32],
    mapping: BinaryToQuaternaryLeafMapping,
    old_tree_size: u32,
    active_member_ids: Vec<Vec<u8>>,
    old_nodes: Vec<RetainedOldNodeValue>,
    new_nodes: Vec<RetainedNewNodeValue>,
}

#[cfg(feature = "experimental-hybrid")]
impl std::fmt::Debug for ExperimentalTransitionNodeState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ExperimentalTransitionNodeState { *** }")
    }
}

#[cfg(feature = "experimental-hybrid")]
#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "test-utils"), derive(PartialEq))]
struct RetainedOldNodeValue {
    node_index: u32,
    public_key: EncryptionKey,
    local_keypair: Option<EncryptionKeyPair>,
    usable: bool,
}

#[cfg(feature = "experimental-hybrid")]
#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "test-utils"), derive(PartialEq))]
struct RetainedNewNodeValue {
    depth: u8,
    ordinal: u32,
    keypair: EncryptionKeyPair,
}

#[cfg(feature = "experimental-hybrid")]
impl ExperimentalTransitionNodeState {
    pub(crate) const fn mapping(&self) -> &BinaryToQuaternaryLeafMapping {
        &self.mapping
    }

    pub(crate) fn new(
        state: &ArityState,
        mapping: BinaryToQuaternaryLeafMapping,
        old_tree_size: u32,
        mut old_public_nodes: Vec<(u32, EncryptionKey)>,
        old_keypairs: Vec<EncryptionKeyPair>,
    ) -> Result<Self, LibraryError> {
        let ArityLifecycle::Transitioning(transitioning) = state.lifecycle() else {
            return Err(LibraryError::custom(
                "retained transition nodes require transitioning ArityState",
            ));
        };
        let mapping_bytes = mapping
            .canonical_bytes()
            .map_err(|_| LibraryError::custom("retained transition mapping is invalid"))?;
        let mapping_hash = hash_canonical_public_bytes(&mapping_bytes);
        if mapping_hash != *transitioning.mapping_hash().as_bytes() {
            return Err(LibraryError::custom(
                "retained transition mapping hash mismatch",
            ));
        }
        let treecover =
            DeliveryOnlyTreeCover::from_mapping(transitioning.treecover().version(), &mapping)
                .map_err(|_| LibraryError::custom("retained TreeCover derivation failed"))?;
        let treecover_hash = treecover
            .hash()
            .map_err(|_| LibraryError::custom("retained TreeCover hash failed"))?;
        if treecover_hash != transitioning.treecover().hash() {
            return Err(LibraryError::custom(
                "retained transition TreeCover hash mismatch",
            ));
        }
        old_public_nodes.sort_by_key(|(node_index, _)| *node_index);
        if old_public_nodes
            .windows(2)
            .any(|nodes| nodes[0].0 == nodes[1].0)
        {
            return Err(LibraryError::custom(
                "retained old transition nodes contain duplicate indices",
            ));
        }
        let old_nodes = old_public_nodes
            .into_iter()
            .map(|(node_index, public_key)| {
                let local_keypair = old_keypairs
                    .iter()
                    .find(|keypair| keypair.public_key() == &public_key)
                    .cloned();
                RetainedOldNodeValue {
                    node_index,
                    public_key,
                    local_keypair,
                    usable: true,
                }
            })
            .collect();
        let active_member_ids = mapping
            .assignments
            .iter()
            .map(|assignment| assignment.member_id.clone())
            .collect();
        let retained = Self {
            tree_version: state.tree_version(),
            mapping_hash,
            treecover_version: transitioning.treecover().version(),
            treecover_hash: *treecover_hash.as_bytes(),
            mapping,
            old_tree_size,
            active_member_ids,
            old_nodes,
            new_nodes: Vec::new(),
        };
        retained.validate(state)?;
        Ok(retained)
    }

    pub(crate) fn validate(&self, state: &ArityState) -> Result<(), LibraryError> {
        let ArityLifecycle::Transitioning(transitioning) = state.lifecycle() else {
            return Err(LibraryError::custom(
                "retained transition nodes require transitioning ArityState",
            ));
        };
        let mapping_bytes = self
            .mapping
            .canonical_bytes()
            .map_err(|_| LibraryError::custom("retained transition mapping is invalid"))?;
        if self.tree_version != state.tree_version()
            || self.mapping_hash != hash_canonical_public_bytes(&mapping_bytes)
            || self.mapping_hash != *transitioning.mapping_hash().as_bytes()
            || self.treecover_version != transitioning.treecover().version()
            || self.treecover_hash != *transitioning.treecover().hash().as_bytes()
        {
            return Err(LibraryError::custom(
                "retained transition nodes are not bound to ArityState",
            ));
        }
        let treecover = DeliveryOnlyTreeCover::from_mapping(self.treecover_version, &self.mapping)
            .map_err(|_| LibraryError::custom("retained TreeCover derivation failed"))?;
        if treecover
            .hash()
            .map_err(|_| LibraryError::custom("retained TreeCover hash failed"))?
            .as_bytes()
            != &self.treecover_hash
        {
            return Err(LibraryError::custom(
                "retained transition TreeCover does not match its mapping",
            ));
        }
        let old_tree_size = TreeSize::new(self.old_tree_size);
        if self.old_tree_size == 0
            || old_tree_size.u32() != self.old_tree_size
            || self
                .mapping
                .assignments
                .iter()
                .any(|assignment| assignment.binary_leaf_index >= old_tree_size.leaf_count())
            || self
                .old_nodes
                .iter()
                .any(|node| node.node_index >= old_tree_size.parent_count())
        {
            return Err(LibraryError::custom(
                "retained old transition topology is invalid",
            ));
        }
        let active_tree =
            ActiveQuaternaryTree::from_mapping(self.tree_version, self.mapping.clone())
                .map_err(|_| LibraryError::custom("retained active topology derivation failed"))?;
        let active_height = active_tree.topology().height();
        if self
            .active_member_ids
            .windows(2)
            .any(|ids| ids[0] >= ids[1])
            || self.active_member_ids.iter().any(|member_id| {
                !self
                    .mapping
                    .assignments
                    .iter()
                    .any(|assignment| &assignment.member_id == member_id)
            })
            || self
                .old_nodes
                .windows(2)
                .any(|nodes| nodes[0].node_index >= nodes[1].node_index)
            || self.new_nodes.windows(2).any(|nodes| {
                (nodes[0].depth, nodes[0].ordinal) >= (nodes[1].depth, nodes[1].ordinal)
            })
            || self.new_nodes.iter().any(|node| {
                node.depth >= active_height
                    || 4_u32
                        .checked_pow(u32::from(node.depth))
                        .is_none_or(|width| node.ordinal >= width)
            })
        {
            return Err(LibraryError::custom(
                "retained transition node state is not canonical",
            ));
        }
        if self.old_nodes.iter().any(|node| {
            node.local_keypair
                .as_ref()
                .is_some_and(|keypair| keypair.public_key() != &node.public_key)
        }) {
            return Err(LibraryError::custom(
                "retained old transition key pair does not match its public value",
            ));
        }
        for keypair in self
            .old_nodes
            .iter()
            .filter_map(|node| node.local_keypair.as_ref())
            .chain(self.new_nodes.iter().map(|node| &node.keypair))
        {
            let public = keypair
                .public_key()
                .experimental_mkyber_key()
                .ok_or_else(|| {
                    LibraryError::custom("retained transition key lacks mKyber public material")
                })?;
            let private = keypair
                .experimental_mkyber_private_key()
                .map_err(|_| {
                    LibraryError::custom("retained transition mKyber private key is invalid")
                })?
                .ok_or_else(|| {
                    LibraryError::custom("retained transition key lacks mKyber private material")
                })?;
            if public.domain() != private.domain() {
                return Err(LibraryError::custom(
                    "retained transition mKyber key domains do not match",
                ));
            }
        }
        Ok(())
    }

    pub(crate) fn reconcile_after_commit(
        &mut self,
        state: &ArityState,
        mut current_member_ids: Vec<Vec<u8>>,
        committer_member_id: &[u8],
        parent_keypairs: Vec<EncryptionKeyPair>,
    ) -> Result<(), LibraryError> {
        current_member_ids.sort();
        if current_member_ids.windows(2).any(|ids| ids[0] == ids[1]) {
            return Err(LibraryError::custom(
                "post-transition membership contains duplicate identifiers",
            ));
        }
        if current_member_ids
            .iter()
            .any(|id| self.active_member_ids.binary_search(id).is_err())
        {
            return Err(LibraryError::custom(
                "post-transition Add or member remapping is not supported",
            ));
        }
        let removed_member_ids = self
            .active_member_ids
            .iter()
            .filter(|id| current_member_ids.binary_search(id).is_err())
            .cloned()
            .collect::<Vec<_>>();
        let old_tree_size = TreeSize::new(self.old_tree_size);
        let tree = ActiveQuaternaryTree::from_mapping(self.tree_version, self.mapping.clone())
            .map_err(|_| LibraryError::custom("retained active topology derivation failed"))?;
        for removed_member_id in removed_member_ids {
            let binary_leaf_index = self
                .mapping
                .assignments
                .iter()
                .find(|assignment| assignment.member_id == removed_member_id)
                .map(|assignment| assignment.binary_leaf_index)
                .ok_or_else(|| {
                    LibraryError::custom("removed member is absent from frozen mapping")
                })?;
            for parent in direct_path(LeafNodeIndex::new(binary_leaf_index), old_tree_size) {
                if let Some(node) = self
                    .old_nodes
                    .iter_mut()
                    .find(|node| node.node_index == parent.u32())
                {
                    node.usable = false;
                    node.local_keypair = None;
                }
            }
            let removed_new_path = tree
                .topology()
                .nodes_for_member(&removed_member_id)
                .map_err(|_| LibraryError::custom("removed member is absent from active topology"))?
                .into_iter()
                .take(usize::from(tree.topology().height()))
                .map(|node| (node.depth, node.ordinal))
                .collect::<Vec<_>>();
            self.new_nodes
                .retain(|node| !removed_new_path.contains(&(node.depth, node.ordinal)));
        }
        if current_member_ids
            .binary_search_by(|id| id.as_slice().cmp(committer_member_id))
            .is_err()
        {
            return Err(LibraryError::custom(
                "post-transition committer is not an active member",
            ));
        }
        let positions = tree
            .topology()
            .nodes_for_member(committer_member_id)
            .map_err(|_| LibraryError::custom("committer is absent from frozen mapping"))?
            .into_iter()
            .take(usize::from(tree.topology().height()))
            .collect::<Vec<_>>();
        if positions.len() != parent_keypairs.len() {
            return Err(LibraryError::custom(
                "quaternary parent key count does not match committer path",
            ));
        }
        for (position, keypair) in positions.into_iter().zip(parent_keypairs) {
            if let Some(node) = self
                .new_nodes
                .iter_mut()
                .find(|node| node.depth == position.depth && node.ordinal == position.ordinal)
            {
                node.keypair = keypair;
            } else {
                self.new_nodes.push(RetainedNewNodeValue {
                    depth: position.depth,
                    ordinal: position.ordinal,
                    keypair,
                });
            }
        }
        self.new_nodes
            .sort_by_key(|node| (node.depth, node.ordinal));
        self.active_member_ids = current_member_ids;
        self.validate(state)
    }

    fn status(&self) -> ExperimentalTransitionNodeAvailabilityStatus {
        ExperimentalTransitionNodeAvailabilityStatus {
            tree_version: self.tree_version,
            mapping_hash: self.mapping_hash,
            treecover_hash: self.treecover_hash,
            active_member_count: self.active_member_ids.len() as u32,
            usable_old_node_count: self.old_nodes.iter().filter(|node| node.usable).count() as u32,
            usable_new_node_count: self.new_nodes.len() as u32,
            local_old_private_node_count: self
                .old_nodes
                .iter()
                .filter(|node| node.usable && node.local_keypair.is_some())
                .count() as u32,
            retained_new_private_node_count: self.new_nodes.len() as u32,
        }
    }

    fn snapshot(&self) -> ExperimentalTransitionNodeAvailabilitySnapshot {
        let mut active_quaternary_leaf_ordinals = self
            .mapping
            .assignments
            .iter()
            .filter(|assignment| {
                self.active_member_ids
                    .binary_search(&assignment.member_id)
                    .is_ok()
            })
            .map(|assignment| assignment.quaternary_leaf_ordinal)
            .collect::<Vec<_>>();
        active_quaternary_leaf_ordinals.sort_unstable();
        ExperimentalTransitionNodeAvailabilitySnapshot {
            tree_version: self.tree_version,
            mapping_hash: self.mapping_hash,
            treecover_version: self.treecover_version,
            treecover_hash: self.treecover_hash,
            frozen_mapping: self.mapping.clone(),
            active_quaternary_leaf_ordinals,
            usable_old_parent_indices: self
                .old_nodes
                .iter()
                .filter(|node| node.usable)
                .map(|node| node.node_index)
                .collect(),
            usable_new_parent_nodes: self
                .new_nodes
                .iter()
                .map(|node| ExperimentalTransitionNodeCoordinate {
                    depth: node.depth,
                    ordinal: node.ordinal,
                })
                .collect(),
        }
    }
}
