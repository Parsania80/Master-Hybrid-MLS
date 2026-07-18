#![forbid(unsafe_code)]

//! Adapter for the unchanged upstream OpenMLS RFC 9420 baseline.
//!
//! This crate deliberately fixes the baseline to ciphersuite `0x0001` and
//! delegates message construction, UpdatePath processing, and application
//! encryption to `openmls` 0.8.1. It contains no mKyber, hybrid KDF,
//! experimental extension, adaptive-tree, or fork behavior.

use openmls::prelude::{tls_codec::Deserialize, *};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use thiserror::Error;

/// The only ciphersuite accepted by the first baseline implementation.
pub const BASELINE_CIPHERSUITE: Ciphersuite =
    Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

/// Errors returned by the baseline boundary.
///
/// Detailed upstream errors are intentionally not exposed here because this
/// public boundary must not encourage logging cryptographic state.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum BaselineError {
    /// An identity or group identifier is empty.
    #[error("the identity and group identifier must be non-empty")]
    EmptyIdentifier,
    /// An operation needs a group that has been created or joined first.
    #[error("no MLS group is initialized for this client")]
    GroupNotInitialized,
    /// An upstream MLS operation rejected the supplied public input or state.
    #[error("the upstream OpenMLS baseline operation failed")]
    OpenMls,
}

/// Public wire artifacts emitted by a successfully staged MLS commit.
///
/// `welcome` is present only when OpenMLS creates one. The sender must call
/// [`BaselineClient::merge_pending_commit`] after distributing `commit`.
#[derive(Debug, PartialEq, Eq)]
pub struct OutboundCommit {
    /// Serialized RFC 9420 Commit message.
    pub commit: Vec<u8>,
    /// Serialized RFC 9420 Welcome message for newly added members, if any.
    pub welcome: Option<Vec<u8>>,
}

/// The result of applying one serialized inbound MLS message.
#[derive(Debug, PartialEq, Eq)]
pub enum InboundEvent {
    /// A decrypted application payload.
    ApplicationMessage(Vec<u8>),
    /// A valid proposal stored for a later commit.
    ProposalStored,
    /// A valid staged commit whose UpdatePath and epoch transition were merged.
    CommitMerged,
}

/// Safe-to-report baseline group metadata.
#[derive(Debug, PartialEq, Eq)]
pub struct BaselineState {
    /// Public MLS group identifier.
    pub group_id: Vec<u8>,
    /// Current MLS epoch.
    pub epoch: u64,
    /// Number of currently active group members.
    pub member_count: usize,
}

/// A single baseline MLS member and its local OpenMLS state.
///
/// The provider and signer remain private so application code exchanges only
/// public MLS wire messages through this adapter.
pub struct BaselineClient {
    provider: OpenMlsRustCrypto,
    signer: SignatureKeyPair,
    credential: CredentialWithKey,
    group: Option<MlsGroup>,
}

impl BaselineClient {
    /// Creates an ungrouped member with a Basic credential for `identity`.
    pub fn new(identity: impl AsRef<[u8]>) -> Result<Self, BaselineError> {
        let identity = identity.as_ref();
        if identity.is_empty() {
            return Err(BaselineError::EmptyIdentifier);
        }

        let provider = OpenMlsRustCrypto::default();
        let signer = SignatureKeyPair::new(BASELINE_CIPHERSUITE.signature_algorithm())
            .map_err(|_| BaselineError::OpenMls)?;
        let credential = CredentialWithKey {
            credential: BasicCredential::new(identity.to_vec()).into(),
            signature_key: signer.to_public_vec().into(),
        };

        Ok(Self {
            provider,
            signer,
            credential,
            group: None,
        })
    }

    /// Builds a public KeyPackage using the fixed baseline ciphersuite.
    pub fn key_package(&self) -> Result<KeyPackageBundle, BaselineError> {
        KeyPackage::builder()
            .build(
                BASELINE_CIPHERSUITE,
                &self.provider,
                &self.signer,
                self.credential.clone(),
            )
            .map_err(|_| BaselineError::OpenMls)
    }

    /// Creates a new RFC 9420 group with the fixed baseline ciphersuite.
    pub fn create_group(&mut self, group_id: impl AsRef<[u8]>) -> Result<(), BaselineError> {
        let group_id = group_id.as_ref();
        if group_id.is_empty() {
            return Err(BaselineError::EmptyIdentifier);
        }

        let config = MlsGroupCreateConfig::builder()
            .ciphersuite(BASELINE_CIPHERSUITE)
            .use_ratchet_tree_extension(true)
            .build();
        let group = MlsGroup::new_with_group_id(
            &self.provider,
            &self.signer,
            &config,
            GroupId::from_slice(group_id),
            self.credential.clone(),
        )
        .map_err(|_| BaselineError::OpenMls)?;
        self.group = Some(group);
        Ok(())
    }

    /// Joins a group from an RFC 9420 Welcome created by [`Self::add_members`].
    pub fn join_from_welcome(&mut self, welcome_bytes: &[u8]) -> Result<(), BaselineError> {
        let welcome = match MlsMessageIn::tls_deserialize_exact(welcome_bytes)
            .map_err(|_| BaselineError::OpenMls)?
            .extract()
        {
            MlsMessageBodyIn::Welcome(welcome) => welcome,
            _ => return Err(BaselineError::OpenMls),
        };
        let config = MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .build();
        let staged_welcome =
            StagedWelcome::new_from_welcome(&self.provider, &config, welcome, None)
                .map_err(|_| BaselineError::OpenMls)?;
        self.group = Some(
            staged_welcome
                .into_group(&self.provider)
                .map_err(|_| BaselineError::OpenMls)?,
        );
        Ok(())
    }

    /// Stages a normal Add commit and returns its serialized public artifacts.
    ///
    /// OpenMLS creates the required UpdatePath. The local sender state remains
    /// pending until [`Self::merge_pending_commit`] is called.
    pub fn add_members(
        &mut self,
        key_packages: &[KeyPackage],
    ) -> Result<OutboundCommit, BaselineError> {
        let provider = &self.provider;
        let signer = &self.signer;
        let group = self
            .group
            .as_mut()
            .ok_or(BaselineError::GroupNotInitialized)?;
        let (commit, welcome, _) = group
            .add_members(provider, signer, key_packages)
            .map_err(|_| BaselineError::OpenMls)?;
        Ok(OutboundCommit {
            commit: serialize_message(&commit)?,
            welcome: Some(serialize_message(&welcome)?),
        })
    }

    /// Stages a standard self-update commit with the upstream UpdatePath.
    pub fn self_update(&mut self) -> Result<OutboundCommit, BaselineError> {
        let provider = &self.provider;
        let signer = &self.signer;
        let group = self
            .group
            .as_mut()
            .ok_or(BaselineError::GroupNotInitialized)?;
        let bundle = group
            .self_update(provider, signer, LeafNodeParameters::default())
            .map_err(|_| BaselineError::OpenMls)?;
        let (commit, welcome, _) = bundle.into_contents();
        Ok(OutboundCommit {
            commit: serialize_message(&commit)?,
            welcome: welcome.map(serialize_welcome).transpose()?,
        })
    }

    /// Merges the caller's locally staged commit after distributing it.
    pub fn merge_pending_commit(&mut self) -> Result<(), BaselineError> {
        let provider = &self.provider;
        let group = self
            .group
            .as_mut()
            .ok_or(BaselineError::GroupNotInitialized)?;
        group
            .merge_pending_commit(provider)
            .map_err(|_| BaselineError::OpenMls)
    }

    /// Encrypts one application payload using upstream OpenMLS.
    pub fn create_application_message(&mut self, payload: &[u8]) -> Result<Vec<u8>, BaselineError> {
        let provider = &self.provider;
        let signer = &self.signer;
        let group = self
            .group
            .as_mut()
            .ok_or(BaselineError::GroupNotInitialized)?;
        let message = group
            .create_message(provider, signer, payload)
            .map_err(|_| BaselineError::OpenMls)?;
        serialize_message(&message)
    }

    /// Processes one serialized RFC 9420 wire message.
    ///
    /// Valid proposals are retained for a later commit. Valid commits are
    /// immediately merged only after OpenMLS has validated their UpdatePath,
    /// authentication, and epoch transition.
    pub fn process_message(&mut self, wire_bytes: &[u8]) -> Result<InboundEvent, BaselineError> {
        let protocol_message = MlsMessageIn::tls_deserialize_exact(wire_bytes)
            .map_err(|_| BaselineError::OpenMls)?
            .try_into_protocol_message()
            .map_err(|_| BaselineError::OpenMls)?;
        let processed = {
            let provider = &self.provider;
            let group = self
                .group
                .as_mut()
                .ok_or(BaselineError::GroupNotInitialized)?;
            group
                .process_message(provider, protocol_message)
                .map_err(|_| BaselineError::OpenMls)?
        };

        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(message) => {
                Ok(InboundEvent::ApplicationMessage(message.into_bytes()))
            }
            ProcessedMessageContent::ProposalMessage(proposal)
            | ProcessedMessageContent::ExternalJoinProposalMessage(proposal) => {
                let storage = self.provider.storage();
                let group = self
                    .group
                    .as_mut()
                    .ok_or(BaselineError::GroupNotInitialized)?;
                group
                    .store_pending_proposal(storage, *proposal)
                    .map_err(|_| BaselineError::OpenMls)?;
                Ok(InboundEvent::ProposalStored)
            }
            ProcessedMessageContent::StagedCommitMessage(commit) => {
                let provider = &self.provider;
                let group = self
                    .group
                    .as_mut()
                    .ok_or(BaselineError::GroupNotInitialized)?;
                group
                    .merge_staged_commit(provider, *commit)
                    .map_err(|_| BaselineError::OpenMls)?;
                Ok(InboundEvent::CommitMerged)
            }
        }
    }

    /// Returns metadata suitable for convergence checks and safe reports.
    pub fn state(&self) -> Result<BaselineState, BaselineError> {
        let group = self.group_ref()?;
        Ok(BaselineState {
            group_id: group.group_id().as_slice().to_vec(),
            epoch: group.epoch().as_u64(),
            member_count: group.members().count(),
        })
    }

    fn group_ref(&self) -> Result<&MlsGroup, BaselineError> {
        self.group
            .as_ref()
            .ok_or(BaselineError::GroupNotInitialized)
    }
}

fn serialize_message(message: &MlsMessageOut) -> Result<Vec<u8>, BaselineError> {
    message.to_bytes().map_err(|_| BaselineError::OpenMls)
}

fn serialize_welcome(welcome: Welcome) -> Result<Vec<u8>, BaselineError> {
    serialize_message(&MlsMessageOut::from_welcome(
        welcome,
        ProtocolVersion::Mls10,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn baseline_add_application_and_updatepath_commit_converge() {
        let mut alice = BaselineClient::new(b"alice").expect("Alice identity must be valid");
        let mut bob = BaselineClient::new(b"bob").expect("Bob identity must be valid");
        alice
            .create_group(b"baseline-task-nine")
            .expect("group creation must succeed");

        let bob_key_package = bob.key_package().expect("key package must be created");
        let add = alice
            .add_members(core::slice::from_ref(bob_key_package.key_package()))
            .expect("add commit must be staged");
        alice
            .merge_pending_commit()
            .expect("sender must merge its add commit");
        bob.join_from_welcome(add.welcome.as_deref().expect("add has welcome"))
            .expect("Bob must join from welcome");

        let application = alice
            .create_application_message(b"baseline application payload")
            .expect("application message must be encrypted");
        assert_eq!(
            bob.process_message(&application)
                .expect("application message must decrypt"),
            InboundEvent::ApplicationMessage(b"baseline application payload".to_vec())
        );

        let update = bob.self_update().expect("self update must be staged");
        assert_eq!(
            alice
                .process_message(&update.commit)
                .expect("Alice must validate and merge Bob's UpdatePath"),
            InboundEvent::CommitMerged
        );
        bob.merge_pending_commit()
            .expect("Bob must merge its self update");

        assert_eq!(
            alice.state().expect("Alice state"),
            bob.state().expect("Bob state")
        );
        assert_eq!(alice.state().expect("Alice state").epoch, 2);
    }

    #[test]
    fn operations_require_an_initialized_group() {
        let mut client = BaselineClient::new(b"alice").expect("identity must be valid");
        assert_eq!(
            client.create_application_message(b"not yet"),
            Err(BaselineError::GroupNotInitialized)
        );
    }
}
