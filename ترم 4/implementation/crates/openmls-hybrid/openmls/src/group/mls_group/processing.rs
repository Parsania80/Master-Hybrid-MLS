//! Processing functions of an [`MlsGroup`] for incoming messages.

use std::mem;

use errors::{CommitToPendingProposalsError, MergePendingCommitError};
use openmls_traits::{crypto::OpenMlsCrypto, signatures::Signer, storage::StorageProvider as _};

use crate::{
    framing::mls_content::FramedContentBody,
    group::{errors::MergeCommitError, StageCommitError, ValidationError},
    messages::group_info::GroupInfo,
    storage::OpenMlsProvider,
    tree::sender_ratchet::SenderRatchetConfiguration,
};

#[cfg(feature = "experimental-hybrid")]
use crate::experimental_hybrid::{
    ExperimentalTreeCoverRetirementEvidence, TREECOVER_RETIREMENT_EVIDENCE_EXTENSION_TYPE,
};
#[cfg(feature = "experimental-hybrid")]
use crate::schedule::ExperimentalTransitionNodeState;
#[cfg(feature = "experimental-hybrid")]
use crate::storage::TransactionalStorageProvider;
#[cfg(feature = "experimental-hybrid")]
use adaptive_tree::{BinaryLeafMember, BinaryToQuaternaryLeafMapping};
#[cfg(feature = "experimental-hybrid")]
use arity_state::{hash_canonical_public_bytes, ArityLifecycle, ArityState};
#[cfg(feature = "experimental-hybrid")]
use openmls_traits::storage::CURRENT_VERSION;
#[cfg(feature = "experimental-hybrid")]
use transition_tree::DeliveryOnlyTreeCover;

#[cfg(feature = "experimental-hybrid")]
type ExperimentalTransitionCommitResult<StorageError> = Result<
    (MlsMessageOut, Option<MlsMessageOut>, Option<GroupInfo>),
    crate::group::errors::CreateGroupContextExtProposalError<StorageError>,
>;

#[cfg(feature = "extensions-draft-08")]
use crate::{
    component::{ComponentData, ComponentId},
    extensions::AppDataDictionary,
    messages::proposals_in::{ProposalIn, ProposalOrRefIn},
};

#[cfg(feature = "extensions-draft-08")]
use std::collections::BTreeMap;

use super::{errors::ProcessMessageError, *};

#[cfg(feature = "extensions-draft-08")]
/// Keeps the old dictionary as well as the values that are being overwritten
pub struct AppDataDictionaryUpdater<'a> {
    old_dict: Option<&'a AppDataDictionary>,
    new_entries: Option<AppDataUpdates>,
}

/// A diff of update values that can be provided to [`MlsGroup::process_unverified_message_with_app_data_updates`] or [`CommitBuilder::with_app_data_dictionary_updates`]
///
/// [`CommitBuilder::with_app_data_dictionary_updates`]: crate::group::CommitBuilder::with_app_data_dictionary_updates
#[cfg(feature = "extensions-draft-08")]
#[derive(Default, Debug)]
pub struct AppDataUpdates(BTreeMap<ComponentId, Option<Vec<u8>>>);

#[cfg(feature = "extensions-draft-08")]
impl IntoIterator for AppDataUpdates {
    type Item = (ComponentId, Option<Vec<u8>>);

    type IntoIter = <BTreeMap<ComponentId, Option<Vec<u8>>> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

#[cfg(feature = "extensions-draft-08")]
impl AppDataUpdates {
    /// Returns the number of changes.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns whether there are changes.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

#[cfg(feature = "extensions-draft-08")]
impl<'a> AppDataDictionaryUpdater<'a> {
    /// Creates a new [`AppDataDictionaryUpdater`].
    pub fn new(old_dict: Option<&'a AppDataDictionary>) -> Self {
        Self {
            old_dict,
            new_entries: None,
        }
    }

    /// Looks up the old value for a component.
    pub fn old_value(&self, component_id: ComponentId) -> Option<&[u8]> {
        self.old_dict?.get(&component_id)
    }

    /// Helper method that returns a mutable reference to the
    /// [`AppDataUpdates`], creating the struct if it does not exist.
    fn new_entries_mut(&mut self) -> &mut AppDataUpdates {
        self.new_entries
            .get_or_insert_with(|| AppDataUpdates(BTreeMap::new()))
    }

    /// Sets a value in the new_entries. if we already have data for that component id, overwrite
    /// it. Else add it in the right position.
    pub fn set(&mut self, component_data: ComponentData) {
        let (id, data) = component_data.into_parts();

        self.new_entries_mut().0.insert(id, Some(data.into()));
    }

    /// Flags an entry in the dictionary for removal
    pub fn remove(&mut self, id: &ComponentId) {
        self.new_entries_mut().0.insert(*id, None);
    }

    /// Consumes the updater and returns just the changes, so we can pass them into
    /// process_unverified_message.
    /// Only returns Some if we actually called set.
    pub fn changes(self) -> Option<AppDataUpdates> {
        self.new_entries
    }
}

impl MlsGroup {
    /// Parses incoming messages from the DS. Checks for syntactic errors and
    /// makes some semantic checks as well. If the input is an encrypted
    /// message, it will be decrypted. This processing function does syntactic
    /// and semantic validation of the message. It returns a [ProcessedMessage]
    /// enum.
    ///
    /// # Errors:
    /// Returns an [`ProcessMessageError`] when the validation checks fail
    /// with the exact reason of the failure.
    pub fn process_message<Provider: OpenMlsProvider>(
        &mut self,
        provider: &Provider,
        message: impl Into<ProtocolMessage>,
    ) -> Result<ProcessedMessage, ProcessMessageError<Provider::StorageError>> {
        let unverified_message = self.unprotect_message(provider, message)?;

        // Check if the commit contains AppDataUpdate proposals - if so, the caller
        // must use process_unverified_message_with_app_data_updates instead
        #[cfg(feature = "extensions-draft-08")]
        if let Some(proposals) = unverified_message.committed_proposals() {
            for proposal_or_ref in proposals {
                if let ProposalOrRefIn::Proposal(proposal) = proposal_or_ref {
                    if matches!(proposal.as_ref(), ProposalIn::AppDataUpdate(_)) {
                        return Err(ProcessMessageError::FoundAppDataUpdateProposal);
                    }
                }
            }
        }
        self.process_unverified_message(provider, unverified_message)
    }

    #[cfg(feature = "extensions-draft-08")]
    /// Returns a new helper struct for updating the app data
    pub fn app_data_dictionary_updater<'a>(&'a self) -> AppDataDictionaryUpdater<'a> {
        AppDataDictionaryUpdater::new(self.context().app_data_dict())
    }

    /// Parses and deprotects incoming messages from the DS. Checks for syntactic errors, but only
    /// performs limited semantic checks.
    pub fn unprotect_message<Provider: OpenMlsProvider>(
        &mut self,
        provider: &Provider,
        message: impl Into<ProtocolMessage>,
    ) -> Result<UnverifiedMessage, ProcessMessageError<Provider::StorageError>> {
        // Make sure we are still a member of the group
        if !self.is_active() {
            return Err(ProcessMessageError::GroupStateError(
                MlsGroupStateError::UseAfterEviction,
            ));
        }
        let message = message.into();

        // Check that handshake messages are compatible with the incoming wire format policy
        if !message.is_external()
            && message.is_handshake_message()
            && !self
                .configuration()
                .wire_format_policy()
                .incoming()
                .is_compatible_with(message.wire_format())
        {
            return Err(ProcessMessageError::IncompatibleWireFormat);
        }

        // Parse the message
        let sender_ratchet_configuration = *self.configuration().sender_ratchet_configuration();

        // Check if this message will modify the secret tree when decrypting a
        // private message
        let will_modify_secret_tree = matches!(message, ProtocolMessage::PrivateMessage(_));

        // Checks the following semantic validation:
        //  - ValSem002
        //  - ValSem003
        //  - ValSem006
        //  - ValSem007 MembershipTag presence
        let decrypted_message =
            self.decrypt_message(provider.crypto(), message, &sender_ratchet_configuration)?;

        // Persist the secret tree if it was modified to ensure forward secrecy
        if will_modify_secret_tree {
            provider
                .storage()
                .write_message_secrets(self.group_id(), &self.message_secrets_store)
                .map_err(ProcessMessageError::StorageError)?;
        }

        let unverified_message = self
            .public_group
            .parse_message(decrypted_message, &self.message_secrets_store)
            .map_err(ProcessMessageError::from)?;

        Ok(unverified_message)
    }

    /// Stores a standalone proposal in the internal [ProposalStore]
    pub fn store_pending_proposal<Storage: StorageProvider>(
        &mut self,
        storage: &Storage,
        proposal: QueuedProposal,
    ) -> Result<(), Storage::Error> {
        storage.queue_proposal(self.group_id(), &proposal.proposal_reference(), &proposal)?;
        // Store the proposal in in the internal ProposalStore
        self.proposal_store_mut().add(proposal);

        Ok(())
    }

    /// Returns true if there are pending proposals queued in the proposal store.
    pub fn has_pending_proposals(&self) -> bool {
        !self.proposal_store().is_empty()
    }

    /// Creates a Commit message that covers the pending proposals that are
    /// currently stored in the group's [ProposalStore]. The Commit message is
    /// created even if there are no valid pending proposals.
    ///
    /// Returns an error if there is a pending commit. Otherwise it returns a
    /// tuple of `Commit, Option<Welcome>, Option<GroupInfo>`, where `Commit`
    /// and [`Welcome`] are MlsMessages of the type [`MlsMessageOut`].
    ///
    /// [`Welcome`]: crate::messages::Welcome
    // FIXME: #1217
    #[allow(clippy::type_complexity)]
    pub fn commit_to_pending_proposals<Provider: OpenMlsProvider>(
        &mut self,
        provider: &Provider,
        signer: &impl Signer,
    ) -> Result<
        (MlsMessageOut, Option<MlsMessageOut>, Option<GroupInfo>),
        CommitToPendingProposalsError<Provider::StorageError>,
    > {
        self.is_operational()?;

        // Build and stage the commit using the commit builder
        // TODO #751
        let (commit, welcome, group_info) = self
            .commit_builder()
            // This forces committing to the proposals in the proposal store:
            .consume_proposal_store(true)
            .load_psks(provider.storage())?
            .build(provider.rand(), provider.crypto(), signer, |_| true)?
            .stage_commit(provider)?
            .into_contents();

        Ok((
            commit,
            // Turn the [`Welcome`] to an [`MlsMessageOut`], if there is one
            welcome.map(|welcome| MlsMessageOut::from_welcome(welcome, self.version())),
            group_info,
        ))
    }

    /// Merge a [StagedCommit] into the group after inspection. As this advances
    /// the epoch of the group, it also clears any pending commits.
    pub fn merge_staged_commit<Provider: OpenMlsProvider>(
        &mut self,
        provider: &Provider,
        staged_commit: StagedCommit,
    ) -> Result<(), MergeCommitError<Provider::StorageError>> {
        self.merge_staged_commit_with_storage(provider.storage(), staged_commit)
    }

    fn merge_staged_commit_with_storage<Storage: StorageProvider>(
        &mut self,
        storage: &Storage,
        staged_commit: StagedCommit,
    ) -> Result<(), MergeCommitError<Storage::Error>> {
        // Check if we were removed from the group
        if staged_commit.self_removed() {
            self.group_state = MlsGroupState::Inactive;
        }
        storage
            .write_group_state(self.group_id(), &self.group_state)
            .map_err(MergeCommitError::StorageError)?;

        // Merge staged commit
        self.merge_commit(storage, staged_commit)?;

        // Extract and store the resumption psk for the current epoch
        let resumption_psk = self.group_epoch_secrets().resumption_psk();
        self.resumption_psk_store
            .add(self.context().epoch(), resumption_psk.clone());
        storage
            .write_resumption_psk_store(self.group_id(), &self.resumption_psk_store)
            .map_err(MergeCommitError::StorageError)?;

        // Delete own KeyPackageBundles
        self.own_leaf_nodes.clear();
        storage
            .delete_own_leaf_nodes(self.group_id())
            .map_err(MergeCommitError::StorageError)?;

        // Delete a potential pending commit
        self.clear_pending_commit(storage)
            .map_err(MergeCommitError::StorageError)?;

        Ok(())
    }

    /// Atomically applies one validated binary hybrid staged commit to an
    /// isolated storage snapshot and publishes memory only after storage
    /// publication succeeds.
    ///
    /// The authenticated GroupContext must carry a canonical normal binary
    /// `ArityState` before and after the merge. Transitioning/quaternary state
    /// is intentionally deferred to the dedicated transition implementation.
    #[cfg(feature = "experimental-hybrid")]
    pub fn merge_staged_commit_experimental_atomic<Provider>(
        &mut self,
        provider: &Provider,
        staged_commit: StagedCommit,
    ) -> Result<(), MergeCommitError<Provider::StorageError>>
    where
        Provider: OpenMlsProvider,
        Provider::Storage: TransactionalStorageProvider<CURRENT_VERSION>,
    {
        self.validate_experimental_binary_arity_state()?;
        let storage = provider.storage();
        let transaction = storage
            .begin_transaction()
            .map_err(MergeCommitError::StorageError)?;
        let mut candidate = Self::load(&transaction, self.group_id())
            .map_err(MergeCommitError::StorageError)?
            .ok_or_else(|| LibraryError::custom("experimental group is missing from storage"))?;
        candidate.aad.clone_from(&self.aad);
        candidate.merge_staged_commit_with_storage(&transaction, staged_commit)?;
        candidate.validate_experimental_binary_arity_state()?;
        storage
            .commit_transaction(transaction)
            .map_err(MergeCommitError::StorageError)?;
        *self = candidate;
        Ok(())
    }

    /// Merges the pending [`StagedCommit`] if there is one, and
    /// clears the field by setting it to `None`.
    pub fn merge_pending_commit<Provider: OpenMlsProvider>(
        &mut self,
        provider: &Provider,
    ) -> Result<(), MergePendingCommitError<Provider::StorageError>> {
        self.merge_pending_commit_with_storage(provider.storage())
    }

    fn merge_pending_commit_with_storage<Storage: StorageProvider>(
        &mut self,
        storage: &Storage,
    ) -> Result<(), MergePendingCommitError<Storage::Error>> {
        match &self.group_state {
            MlsGroupState::PendingCommit(_) => {
                let old_state = mem::replace(&mut self.group_state, MlsGroupState::Operational);
                if let MlsGroupState::PendingCommit(pending_commit_state) = old_state {
                    self.merge_staged_commit_with_storage(storage, (*pending_commit_state).into())?;
                }
                Ok(())
            }
            MlsGroupState::Inactive => Err(MlsGroupStateError::UseAfterEviction)?,
            MlsGroupState::Operational => Ok(()),
        }
    }

    /// Atomically applies this member's pending binary hybrid commit.
    #[cfg(feature = "experimental-hybrid")]
    pub fn merge_pending_commit_experimental_atomic<Provider>(
        &mut self,
        provider: &Provider,
    ) -> Result<(), MergePendingCommitError<Provider::StorageError>>
    where
        Provider: OpenMlsProvider,
        Provider::Storage: TransactionalStorageProvider<CURRENT_VERSION>,
    {
        self.validate_experimental_binary_arity_state()
            .map_err(MlsGroupStateError::from)?;
        let storage = provider.storage();
        let transaction = storage.begin_transaction().map_err(|error| {
            MergePendingCommitError::MergeCommitError(MergeCommitError::StorageError(error))
        })?;
        let mut candidate = Self::load(&transaction, self.group_id())
            .map_err(|error| {
                MergePendingCommitError::MergeCommitError(MergeCommitError::StorageError(error))
            })?
            .ok_or_else(|| {
                MlsGroupStateError::LibraryError(LibraryError::custom(
                    "experimental group is missing from storage",
                ))
            })?;
        candidate.aad.clone_from(&self.aad);
        candidate.merge_pending_commit_with_storage(&transaction)?;
        candidate
            .validate_experimental_binary_arity_state()
            .map_err(MlsGroupStateError::from)?;
        storage.commit_transaction(transaction).map_err(|error| {
            MergePendingCommitError::MergeCommitError(MergeCommitError::StorageError(error))
        })?;
        *self = candidate;
        Ok(())
    }

    /// Creates a real MLS GroupContext-extension Commit that begins this
    /// thesis-local binary-to-quaternary transition.
    ///
    /// The caller provides the policy-evaluated next `ArityState`; this method
    /// derives the deterministic mapping and frozen delivery-only TreeCover
    /// from the current authenticated MLS membership and accepts the state
    /// only when both committed hashes match. Sender application must use
    /// [`Self::merge_pending_commit_experimental_transition_atomic`].
    #[cfg(feature = "experimental-hybrid")]
    pub fn begin_experimental_transition<Provider>(
        &mut self,
        provider: &Provider,
        signer: &impl Signer,
        next_state: ArityState,
    ) -> ExperimentalTransitionCommitResult<Provider::StorageError>
    where
        Provider: OpenMlsProvider,
    {
        self.validate_experimental_binary_arity_state()?;
        let current_state = self.experimental_arity_state()?;
        let mapping = self.experimental_transition_mapping()?;
        self.validate_experimental_transition_target(
            self.epoch().as_u64(),
            &current_state,
            &mapping,
            &next_state,
        )?;
        let extensions = self.experimental_extensions_with_arity_state(&next_state)?;
        self.update_group_context_extensions(provider, extensions, signer)
    }

    /// Atomically applies a receiver's validated dedicated transition Commit.
    #[cfg(feature = "experimental-hybrid")]
    pub fn merge_staged_commit_experimental_transition_atomic<Provider>(
        &mut self,
        provider: &Provider,
        staged_commit: StagedCommit,
    ) -> Result<(), MergeCommitError<Provider::StorageError>>
    where
        Provider: OpenMlsProvider,
        Provider::Storage: TransactionalStorageProvider<CURRENT_VERSION>,
    {
        let prior_epoch = self.epoch().as_u64();
        let prior_state = self.experimental_arity_state()?;
        let prior_mapping = self.experimental_transition_mapping()?;
        self.validate_experimental_binary_arity_state()?;
        let storage = provider.storage();
        let transaction = storage
            .begin_transaction()
            .map_err(MergeCommitError::StorageError)?;
        let old_keypairs = self
            .read_epoch_keypairs(&transaction)
            .map_err(MergeCommitError::StorageError)?;
        let old_tree_size = self.public_group.tree_size().u32();
        let old_public_nodes = self.public_group.experimental_parent_node_values();
        let mut candidate = Self::load(&transaction, self.group_id())
            .map_err(MergeCommitError::StorageError)?
            .ok_or_else(|| LibraryError::custom("experimental group is missing from storage"))?;
        candidate.aad.clone_from(&self.aad);
        candidate.merge_staged_commit_with_storage(&transaction, staged_commit)?;
        let next_state = candidate.experimental_arity_state()?;
        candidate.validate_experimental_transition_target(
            prior_epoch,
            &prior_state,
            &prior_mapping,
            &next_state,
        )?;
        let retained_state = ExperimentalTransitionNodeState::new(
            &next_state,
            prior_mapping,
            old_tree_size,
            old_public_nodes,
            old_keypairs,
        )?;
        candidate
            .group_epoch_secrets
            .install_experimental_transition_node_state(retained_state);
        transaction
            .write_group_epoch_secrets(candidate.group_id(), &candidate.group_epoch_secrets)
            .map_err(MergeCommitError::StorageError)?;
        candidate.validate_experimental_quaternary_epoch_authority()?;
        storage
            .commit_transaction(transaction)
            .map_err(MergeCommitError::StorageError)?;
        *self = candidate;
        Ok(())
    }

    /// Atomically applies this sender's pending dedicated transition Commit.
    #[cfg(feature = "experimental-hybrid")]
    pub fn merge_pending_commit_experimental_transition_atomic<Provider>(
        &mut self,
        provider: &Provider,
    ) -> Result<(), MergePendingCommitError<Provider::StorageError>>
    where
        Provider: OpenMlsProvider,
        Provider::Storage: TransactionalStorageProvider<CURRENT_VERSION>,
    {
        let prior_epoch = self.epoch().as_u64();
        let prior_state = self
            .experimental_arity_state()
            .map_err(MlsGroupStateError::from)?;
        let prior_mapping = self
            .experimental_transition_mapping()
            .map_err(MlsGroupStateError::from)?;
        self.validate_experimental_binary_arity_state()
            .map_err(MlsGroupStateError::from)?;
        let storage = provider.storage();
        let transaction = storage.begin_transaction().map_err(|error| {
            MergePendingCommitError::MergeCommitError(MergeCommitError::StorageError(error))
        })?;
        let old_keypairs = self.read_epoch_keypairs(&transaction).map_err(|error| {
            MergePendingCommitError::MergeCommitError(MergeCommitError::StorageError(error))
        })?;
        let old_tree_size = self.public_group.tree_size().u32();
        let old_public_nodes = self.public_group.experimental_parent_node_values();
        let mut candidate = Self::load(&transaction, self.group_id())
            .map_err(|error| {
                MergePendingCommitError::MergeCommitError(MergeCommitError::StorageError(error))
            })?
            .ok_or_else(|| {
                MlsGroupStateError::LibraryError(LibraryError::custom(
                    "experimental group is missing from storage",
                ))
            })?;
        candidate.aad.clone_from(&self.aad);
        candidate.merge_pending_commit_with_storage(&transaction)?;
        let next_state = candidate
            .experimental_arity_state()
            .map_err(MlsGroupStateError::from)?;
        candidate
            .validate_experimental_transition_target(
                prior_epoch,
                &prior_state,
                &prior_mapping,
                &next_state,
            )
            .map_err(MlsGroupStateError::from)?;
        let retained_state = ExperimentalTransitionNodeState::new(
            &next_state,
            prior_mapping,
            old_tree_size,
            old_public_nodes,
            old_keypairs,
        )
        .map_err(MlsGroupStateError::from)?;
        candidate
            .group_epoch_secrets
            .install_experimental_transition_node_state(retained_state);
        transaction
            .write_group_epoch_secrets(candidate.group_id(), &candidate.group_epoch_secrets)
            .map_err(|error| {
                MergePendingCommitError::MergeCommitError(MergeCommitError::StorageError(error))
            })?;
        candidate
            .validate_experimental_quaternary_epoch_authority()
            .map_err(MlsGroupStateError::from)?;
        storage.commit_transaction(transaction).map_err(|error| {
            MergePendingCommitError::MergeCommitError(MergeCommitError::StorageError(error))
        })?;
        *self = candidate;
        Ok(())
    }

    /// Creates the authenticated `Transitioning -> Normal` TreeCover
    /// retirement Commit.
    ///
    /// The signed GroupContext carries both the successor `ArityState` and the
    /// exact strict-threshold observation that authorized retirement.
    #[cfg(feature = "experimental-hybrid")]
    pub fn retire_experimental_treecover<Provider>(
        &mut self,
        provider: &Provider,
        signer: &impl Signer,
        next_state: ArityState,
        evidence: ExperimentalTreeCoverRetirementEvidence,
    ) -> ExperimentalTransitionCommitResult<Provider::StorageError>
    where
        Provider: OpenMlsProvider,
    {
        self.validate_experimental_quaternary_epoch_authority()?;
        let prior_state = self.experimental_arity_state()?;
        self.validate_experimental_retirement_target(
            self.epoch().as_u64(),
            &prior_state,
            &next_state,
            evidence,
        )?;
        let extensions = self.experimental_extensions_with_retirement(&next_state, evidence)?;
        self.update_group_context_extensions(provider, extensions, signer)
    }

    /// Atomically applies a receiver's authenticated retirement Commit,
    /// activates the normal-quaternary epoch authority, then deletes the
    /// complete retained TreeCover envelope before publication.
    #[cfg(feature = "experimental-hybrid")]
    pub fn merge_staged_commit_experimental_retirement_atomic<Provider>(
        &mut self,
        provider: &Provider,
        staged_commit: StagedCommit,
    ) -> Result<(), MergeCommitError<Provider::StorageError>>
    where
        Provider: OpenMlsProvider,
        Provider::Storage: TransactionalStorageProvider<CURRENT_VERSION>,
    {
        let prior_epoch = self.epoch().as_u64();
        let prior_state = self.experimental_arity_state()?;
        self.validate_experimental_quaternary_epoch_authority()?;
        let retained = self
            .group_epoch_secrets()
            .experimental_transition_node_state()
            .cloned()
            .ok_or_else(|| {
                LibraryError::custom("experimental retirement has no retained TreeCover")
            })?;
        let ArityLifecycle::Transitioning(transitioning) = prior_state.lifecycle() else {
            return Err(
                LibraryError::custom("experimental retirement is not transitioning").into(),
            );
        };
        let mapping_hash = *transitioning.mapping_hash().as_bytes();
        let storage = provider.storage();
        let transaction = storage
            .begin_transaction()
            .map_err(MergeCommitError::StorageError)?;
        let mut candidate = Self::load(&transaction, self.group_id())
            .map_err(MergeCommitError::StorageError)?
            .ok_or_else(|| LibraryError::custom("experimental group is missing from storage"))?;
        candidate.aad.clone_from(&self.aad);
        candidate.merge_staged_commit_with_storage(&transaction, staged_commit)?;
        let next_state = candidate.experimental_arity_state()?;
        let evidence = candidate.experimental_treecover_retirement_evidence()?;
        candidate.validate_experimental_retirement_target(
            prior_epoch,
            &prior_state,
            &next_state,
            evidence,
        )?;
        candidate.activate_experimental_retired_authority(
            provider,
            &transaction,
            &next_state,
            mapping_hash,
        )?;
        candidate
            .group_epoch_secrets
            .install_experimental_treecover_retirement_status(retained.retirement_status(evidence));
        transaction
            .write_group_epoch_secrets(candidate.group_id(), &candidate.group_epoch_secrets)
            .map_err(MergeCommitError::StorageError)?;
        candidate.validate_experimental_retired_quaternary_state()?;
        storage
            .commit_transaction(transaction)
            .map_err(MergeCommitError::StorageError)?;
        *self = candidate;
        Ok(())
    }

    /// Atomically applies the sender's pending authenticated retirement Commit.
    #[cfg(feature = "experimental-hybrid")]
    pub fn merge_pending_commit_experimental_retirement_atomic<Provider>(
        &mut self,
        provider: &Provider,
    ) -> Result<(), MergePendingCommitError<Provider::StorageError>>
    where
        Provider: OpenMlsProvider,
        Provider::Storage: TransactionalStorageProvider<CURRENT_VERSION>,
    {
        let prior_epoch = self.epoch().as_u64();
        let prior_state = self
            .experimental_arity_state()
            .map_err(MlsGroupStateError::from)?;
        self.validate_experimental_quaternary_epoch_authority()
            .map_err(MlsGroupStateError::from)?;
        let retained = self
            .group_epoch_secrets()
            .experimental_transition_node_state()
            .cloned()
            .ok_or_else(|| {
                MlsGroupStateError::LibraryError(LibraryError::custom(
                    "experimental retirement has no retained TreeCover",
                ))
            })?;
        let ArityLifecycle::Transitioning(transitioning) = prior_state.lifecycle() else {
            return Err(MlsGroupStateError::LibraryError(LibraryError::custom(
                "experimental retirement is not transitioning",
            ))
            .into());
        };
        let mapping_hash = *transitioning.mapping_hash().as_bytes();
        let storage = provider.storage();
        let transaction = storage.begin_transaction().map_err(|error| {
            MergePendingCommitError::MergeCommitError(MergeCommitError::StorageError(error))
        })?;
        let mut candidate = Self::load(&transaction, self.group_id())
            .map_err(|error| {
                MergePendingCommitError::MergeCommitError(MergeCommitError::StorageError(error))
            })?
            .ok_or_else(|| {
                MlsGroupStateError::LibraryError(LibraryError::custom(
                    "experimental group is missing from storage",
                ))
            })?;
        candidate.aad.clone_from(&self.aad);
        candidate.merge_pending_commit_with_storage(&transaction)?;
        let next_state = candidate
            .experimental_arity_state()
            .map_err(MlsGroupStateError::from)?;
        let evidence = candidate
            .experimental_treecover_retirement_evidence()
            .map_err(MlsGroupStateError::from)?;
        candidate
            .validate_experimental_retirement_target(
                prior_epoch,
                &prior_state,
                &next_state,
                evidence,
            )
            .map_err(MlsGroupStateError::from)?;
        candidate
            .activate_experimental_retired_authority(
                provider,
                &transaction,
                &next_state,
                mapping_hash,
            )
            .map_err(MlsGroupStateError::from)?;
        candidate
            .group_epoch_secrets
            .install_experimental_treecover_retirement_status(retained.retirement_status(evidence));
        transaction
            .write_group_epoch_secrets(candidate.group_id(), &candidate.group_epoch_secrets)
            .map_err(|error| {
                MergePendingCommitError::MergeCommitError(MergeCommitError::StorageError(error))
            })?;
        candidate
            .validate_experimental_retired_quaternary_state()
            .map_err(MlsGroupStateError::from)?;
        storage.commit_transaction(transaction).map_err(|error| {
            MergePendingCommitError::MergeCommitError(MergeCommitError::StorageError(error))
        })?;
        *self = candidate;
        Ok(())
    }

    /// Returns redacted metadata for the active, persisted experimental
    /// quaternary epoch authority. Secret bytes are never exposed.
    #[cfg(feature = "experimental-hybrid")]
    pub fn experimental_quaternary_epoch_secret_status(
        &self,
    ) -> Option<crate::schedule::ExperimentalQuaternaryEpochSecretStatus> {
        self.group_epoch_secrets()
            .experimental_quaternary_epoch_secret_status()
    }

    /// Returns redacted availability counters for retained transition nodes.
    #[cfg(feature = "experimental-hybrid")]
    pub fn experimental_transition_node_availability_status(
        &self,
    ) -> Option<crate::schedule::ExperimentalTransitionNodeAvailabilityStatus> {
        self.group_epoch_secrets()
            .experimental_transition_node_availability_status()
    }

    /// Returns ciphertext-free retained topology and usable-node coordinates.
    #[cfg(feature = "experimental-hybrid")]
    pub fn experimental_transition_node_availability_snapshot(
        &self,
    ) -> Option<crate::schedule::ExperimentalTransitionNodeAvailabilitySnapshot> {
        self.group_epoch_secrets()
            .experimental_transition_node_availability_snapshot()
    }

    /// Returns redacted proof that the persisted TreeCover envelope was erased.
    #[cfg(feature = "experimental-hybrid")]
    pub fn experimental_treecover_retirement_status(
        &self,
    ) -> Option<crate::schedule::ExperimentalTreeCoverRetirementStatus> {
        self.group_epoch_secrets()
            .experimental_treecover_retirement_status()
    }

    /// Atomically applies a staged UpdatePath while the fork-local
    /// quaternary authority is active.
    ///
    /// The inherited MLS binary UpdatePath remains the authenticated delivery
    /// carrier for this milestone. A successful path advances the MLS epoch,
    /// then the candidate derives and persists a fresh quaternary authority
    /// from that new epoch's exporter secret and GroupContext.
    #[cfg(feature = "experimental-hybrid")]
    pub fn merge_staged_commit_experimental_quaternary_atomic<Provider>(
        &mut self,
        provider: &Provider,
        staged_commit: StagedCommit,
    ) -> Result<(), MergeCommitError<Provider::StorageError>>
    where
        Provider: OpenMlsProvider,
        Provider::Storage: TransactionalStorageProvider<CURRENT_VERSION>,
    {
        self.validate_experimental_quaternary_epoch_authority()?;
        let self_removed = staged_commit.self_removed();
        let committer_member_id = staged_commit
            .update_path_leaf_node()
            .map(|leaf| leaf.credential().serialized_content().to_vec())
            .ok_or_else(|| {
                LibraryError::custom(
                    "experimental quaternary commit requires an authenticated UpdatePath",
                )
            })?;
        let mut retained_state = self
            .group_epoch_secrets()
            .experimental_transition_node_state()
            .cloned()
            .ok_or_else(|| {
                LibraryError::custom("experimental group has no retained transition node state")
            })?;
        let storage = provider.storage();
        let transaction = storage
            .begin_transaction()
            .map_err(MergeCommitError::StorageError)?;
        let mut candidate = Self::load(&transaction, self.group_id())
            .map_err(MergeCommitError::StorageError)?
            .ok_or_else(|| LibraryError::custom("experimental group is missing from storage"))?;
        candidate.aad.clone_from(&self.aad);
        candidate.merge_staged_commit_with_storage(&transaction, staged_commit)?;
        if self_removed {
            storage
                .commit_transaction(transaction)
                .map_err(MergeCommitError::StorageError)?;
            *self = candidate;
            return Ok(());
        }
        let next_state = candidate.experimental_arity_state()?;
        let current_member_ids = candidate
            .members()
            .map(|member| member.credential.serialized_content().to_vec())
            .collect();
        let parent_keypairs = candidate
            .group_epoch_secrets()
            .experimental_quaternary_parent_keypairs()?;
        retained_state.reconcile_after_commit(
            &next_state,
            current_member_ids,
            &committer_member_id,
            parent_keypairs,
        )?;
        candidate
            .group_epoch_secrets
            .install_experimental_transition_node_state(retained_state);
        transaction
            .write_group_epoch_secrets(candidate.group_id(), &candidate.group_epoch_secrets)
            .map_err(MergeCommitError::StorageError)?;
        candidate.validate_experimental_quaternary_epoch_authority()?;
        storage
            .commit_transaction(transaction)
            .map_err(MergeCommitError::StorageError)?;
        *self = candidate;
        Ok(())
    }

    /// Atomically applies this member's pending UpdatePath while the
    /// fork-local quaternary authority is active.
    #[cfg(feature = "experimental-hybrid")]
    pub fn merge_pending_commit_experimental_quaternary_atomic<Provider>(
        &mut self,
        provider: &Provider,
    ) -> Result<(), MergePendingCommitError<Provider::StorageError>>
    where
        Provider: OpenMlsProvider,
        Provider::Storage: TransactionalStorageProvider<CURRENT_VERSION>,
    {
        self.validate_experimental_quaternary_epoch_authority()
            .map_err(MlsGroupStateError::from)?;
        let committer_member_id = self
            .pending_commit()
            .and_then(StagedCommit::update_path_leaf_node)
            .map(|leaf| leaf.credential().serialized_content().to_vec())
            .ok_or_else(|| {
                MlsGroupStateError::LibraryError(LibraryError::custom(
                    "experimental quaternary pending commit requires an authenticated UpdatePath",
                ))
            })?;
        let mut retained_state = self
            .group_epoch_secrets()
            .experimental_transition_node_state()
            .cloned()
            .ok_or_else(|| {
                MlsGroupStateError::LibraryError(LibraryError::custom(
                    "experimental group has no retained transition node state",
                ))
            })?;
        let storage = provider.storage();
        let transaction = storage.begin_transaction().map_err(|error| {
            MergePendingCommitError::MergeCommitError(MergeCommitError::StorageError(error))
        })?;
        let mut candidate = Self::load(&transaction, self.group_id())
            .map_err(|error| {
                MergePendingCommitError::MergeCommitError(MergeCommitError::StorageError(error))
            })?
            .ok_or_else(|| {
                MlsGroupStateError::LibraryError(LibraryError::custom(
                    "experimental group is missing from storage",
                ))
            })?;
        candidate.aad.clone_from(&self.aad);
        candidate.merge_pending_commit_with_storage(&transaction)?;
        let next_state = candidate
            .experimental_arity_state()
            .map_err(MlsGroupStateError::from)?;
        let current_member_ids = candidate
            .members()
            .map(|member| member.credential.serialized_content().to_vec())
            .collect();
        let parent_keypairs = candidate
            .group_epoch_secrets()
            .experimental_quaternary_parent_keypairs()
            .map_err(MlsGroupStateError::from)?;
        retained_state
            .reconcile_after_commit(
                &next_state,
                current_member_ids,
                &committer_member_id,
                parent_keypairs,
            )
            .map_err(MlsGroupStateError::from)?;
        candidate
            .group_epoch_secrets
            .install_experimental_transition_node_state(retained_state);
        transaction
            .write_group_epoch_secrets(candidate.group_id(), &candidate.group_epoch_secrets)
            .map_err(|error| {
                MergePendingCommitError::MergeCommitError(MergeCommitError::StorageError(error))
            })?;
        candidate
            .validate_experimental_quaternary_epoch_authority()
            .map_err(MlsGroupStateError::from)?;
        storage.commit_transaction(transaction).map_err(|error| {
            MergePendingCommitError::MergeCommitError(MergeCommitError::StorageError(error))
        })?;
        *self = candidate;
        Ok(())
    }

    #[cfg(feature = "experimental-hybrid")]
    fn validate_experimental_binary_arity_state(&self) -> Result<(), LibraryError> {
        let state = self.experimental_arity_state()?;
        if state.active_arity() != 2
            || state.candidate_arity() != 4
            || state.tree_version() != 0
            || !matches!(state.lifecycle(), ArityLifecycle::Normal)
        {
            return Err(LibraryError::custom(
                "experimental atomic binary merge requires normal 2-to-4 ArityState",
            ));
        }
        Ok(())
    }

    #[cfg(feature = "experimental-hybrid")]
    fn validate_experimental_quaternary_epoch_authority(&self) -> Result<(), LibraryError> {
        let state = self.experimental_arity_state()?;
        let ArityLifecycle::Transitioning(transitioning) = state.lifecycle() else {
            return Err(LibraryError::custom(
                "experimental quaternary merge requires transitioning ArityState",
            ));
        };
        let status = self
            .experimental_quaternary_epoch_secret_status()
            .ok_or_else(|| {
                LibraryError::custom("experimental group has no quaternary epoch authority")
            })?;
        self.group_epoch_secrets()
            .validate_experimental_quaternary_root_keypair()?;
        let retained_state = self
            .group_epoch_secrets()
            .experimental_transition_node_state()
            .ok_or_else(|| {
                LibraryError::custom("experimental group has no retained transition node state")
            })?;
        retained_state.validate(&state)?;
        if status.epoch() != self.epoch().as_u64()
            || status.tree_version() != state.tree_version()
            || status.mapping_hash() != transitioning.mapping_hash().as_bytes()
        {
            return Err(LibraryError::custom(
                "experimental quaternary epoch authority is not bound to GroupContext",
            ));
        }
        let mapping = retained_state.mapping();
        let mapping_bytes = mapping
            .canonical_bytes()
            .map_err(|_| LibraryError::custom("experimental transition mapping encoding failed"))?;
        if &hash_canonical_public_bytes(&mapping_bytes) != status.mapping_hash() {
            return Err(LibraryError::custom(
                "experimental quaternary authority mapping hash mismatch",
            ));
        }
        let treecover =
            DeliveryOnlyTreeCover::from_mapping(transitioning.treecover().version(), mapping)
                .map_err(|_| {
                    LibraryError::custom("experimental transition TreeCover derivation failed")
                })?;
        if treecover
            .hash()
            .map_err(|_| LibraryError::custom("experimental transition TreeCover hash failed"))?
            != transitioning.treecover().hash()
        {
            return Err(LibraryError::custom(
                "experimental quaternary authority TreeCover hash mismatch",
            ));
        }
        Ok(())
    }

    #[cfg(feature = "experimental-hybrid")]
    fn validate_experimental_retirement_target(
        &self,
        prior_epoch: u64,
        prior_state: &ArityState,
        next_state: &ArityState,
        evidence: ExperimentalTreeCoverRetirementEvidence,
    ) -> Result<(), LibraryError> {
        let ArityLifecycle::Transitioning(transitioning) = prior_state.lifecycle() else {
            return Err(LibraryError::custom(
                "experimental retirement requires transitioning ArityState",
            ));
        };
        if !matches!(next_state.lifecycle(), ArityLifecycle::Normal)
            || next_state.active_arity() != 4
            || next_state.candidate_arity() != 4
            || next_state.policy() != prior_state.policy()
            || next_state.evaluation() != prior_state.evaluation()
            || prior_state
                .tree_version()
                .checked_add(1)
                .is_none_or(|version| next_state.tree_version() != version)
            || evidence.tree_version() != prior_state.tree_version()
            || evidence.transition_epoch() != transitioning.transition_epoch()
            || evidence.observation_epoch() != prior_epoch
        {
            return Err(LibraryError::custom(
                "experimental retirement target is not bound to the accepted observation",
            ));
        }
        Ok(())
    }

    #[cfg(feature = "experimental-hybrid")]
    fn experimental_treecover_retirement_evidence(
        &self,
    ) -> Result<ExperimentalTreeCoverRetirementEvidence, LibraryError> {
        let extension = self
            .extensions()
            .unknown(TREECOVER_RETIREMENT_EVIDENCE_EXTENSION_TYPE)
            .ok_or_else(|| {
                LibraryError::custom("experimental group has no authenticated retirement evidence")
            })?;
        ExperimentalTreeCoverRetirementEvidence::from_extension_value(&extension.0)
            .map_err(|_| LibraryError::custom("experimental retirement evidence is invalid"))
    }

    #[cfg(feature = "experimental-hybrid")]
    fn activate_experimental_retired_authority<Provider, Storage>(
        &mut self,
        provider: &Provider,
        storage: &Storage,
        state: &ArityState,
        mapping_hash: [u8; 32],
    ) -> Result<(), LibraryError>
    where
        Provider: OpenMlsProvider,
        Storage: openmls_traits::storage::StorageProvider<
            CURRENT_VERSION,
            Error = Provider::StorageError,
        >,
    {
        let root_public = self
            .public_group
            .experimental_root_parent_value()
            .ok_or_else(|| LibraryError::custom("retirement Commit has no binary root value"))?;
        let root_keypair = self
            .read_epoch_keypairs(storage)
            .map_err(|_| LibraryError::custom("retirement root key lookup failed"))?
            .into_iter()
            .find(|keypair| keypair.public_key() == &root_public)
            .ok_or_else(|| {
                LibraryError::custom("retirement Commit has no matching binary root key pair")
            })?;
        let serialized_context = self
            .context()
            .tls_serialize_detached()
            .map_err(LibraryError::missing_bound_check)?;
        self.group_epoch_secrets
            .activate_experimental_retired_quaternary_epoch_secret(
                provider.crypto(),
                self.ciphersuite(),
                &serialized_context,
                self.epoch().as_u64(),
                state,
                mapping_hash,
                root_keypair,
            )
    }

    #[cfg(feature = "experimental-hybrid")]
    fn validate_experimental_retired_quaternary_state(&self) -> Result<(), LibraryError> {
        let state = self.experimental_arity_state()?;
        if !matches!(state.lifecycle(), ArityLifecycle::Normal)
            || state.active_arity() != 4
            || state.candidate_arity() != 4
            || state.tree_version() < 2
            || self
                .group_epoch_secrets()
                .experimental_transition_node_state()
                .is_some()
            || self.experimental_treecover_retirement_status().is_none()
        {
            return Err(LibraryError::custom(
                "experimental retired quaternary state is invalid",
            ));
        }
        let evidence = self.experimental_treecover_retirement_evidence()?;
        let authority = self
            .experimental_quaternary_epoch_secret_status()
            .ok_or_else(|| {
                LibraryError::custom("retired quaternary state has no epoch authority")
            })?;
        self.group_epoch_secrets()
            .validate_experimental_quaternary_root_keypair()?;
        if evidence.observation_epoch().checked_add(1) != Some(self.epoch().as_u64())
            || evidence.tree_version().checked_add(1) != Some(state.tree_version())
            || authority.epoch() != self.epoch().as_u64()
            || authority.tree_version() != state.tree_version()
        {
            return Err(LibraryError::custom(
                "retired quaternary authority is not bound to its Commit",
            ));
        }
        Ok(())
    }

    #[cfg(feature = "experimental-hybrid")]
    fn experimental_arity_state(&self) -> Result<ArityState, LibraryError> {
        let extension = self
            .extensions()
            .unknown(crate::experimental_hybrid::ADAPTIVE_HYBRID_TREE_STATE_EXTENSION_TYPE)
            .ok_or_else(|| {
                LibraryError::custom("experimental group has no authenticated ArityState")
            })?;
        ArityState::from_extension_value(&extension.0)
            .map_err(|_| LibraryError::custom("experimental group has invalid ArityState"))
    }

    #[cfg(feature = "experimental-hybrid")]
    fn experimental_transition_mapping(
        &self,
    ) -> Result<BinaryToQuaternaryLeafMapping, LibraryError> {
        let members = self
            .members()
            .map(|member| BinaryLeafMember {
                member_id: member.credential.serialized_content().to_vec(),
                binary_leaf_index: member.index.u32(),
            })
            .collect();
        BinaryToQuaternaryLeafMapping::from_binary_members(members).map_err(|_| {
            LibraryError::custom("experimental transition cannot derive a canonical mapping")
        })
    }

    #[cfg(feature = "experimental-hybrid")]
    fn validate_experimental_transition_target(
        &self,
        prior_epoch: u64,
        prior_state: &ArityState,
        prior_mapping: &BinaryToQuaternaryLeafMapping,
        next_state: &ArityState,
    ) -> Result<(), LibraryError> {
        if next_state.policy() != prior_state.policy()
            || next_state.active_arity() != 4
            || next_state.candidate_arity() != 4
            || next_state.tree_version() != 1
        {
            return Err(LibraryError::custom(
                "experimental transition state is not canonical 2-to-4",
            ));
        }
        let ArityLifecycle::Transitioning(transitioning) = next_state.lifecycle() else {
            return Err(LibraryError::custom(
                "experimental transition state is not transitioning",
            ));
        };
        if next_state.evaluation().last_evaluated_epoch() != prior_epoch
            || transitioning.transition_epoch()
                != prior_epoch
                    .checked_add(1)
                    .ok_or_else(|| LibraryError::custom("experimental transition epoch overflow"))?
        {
            return Err(LibraryError::custom(
                "experimental transition epoch is not bound to the Commit",
            ));
        }
        let mapping = self.experimental_transition_mapping()?;
        if &mapping != prior_mapping {
            return Err(LibraryError::custom(
                "experimental transition Commit changes MLS membership",
            ));
        }
        let mapping_bytes = mapping
            .canonical_bytes()
            .map_err(|_| LibraryError::custom("experimental transition mapping encoding failed"))?;
        if transitioning.mapping_hash().as_bytes() != &hash_canonical_public_bytes(&mapping_bytes) {
            return Err(LibraryError::custom(
                "experimental transition mapping hash mismatch",
            ));
        }
        let treecover =
            DeliveryOnlyTreeCover::from_mapping(transitioning.treecover().version(), &mapping)
                .map_err(|_| {
                    LibraryError::custom("experimental transition TreeCover derivation failed")
                })?;
        if treecover
            .hash()
            .map_err(|_| LibraryError::custom("experimental transition TreeCover hash failed"))?
            != transitioning.treecover().hash()
        {
            return Err(LibraryError::custom(
                "experimental transition TreeCover hash mismatch",
            ));
        }
        Ok(())
    }

    #[cfg(feature = "experimental-hybrid")]
    fn experimental_extensions_with_arity_state(
        &self,
        state: &ArityState,
    ) -> Result<crate::extensions::Extensions<GroupContext>, LibraryError> {
        let mut extensions = self
            .extensions()
            .iter()
            .filter(|extension| {
                extension.extension_type()
                    != crate::experimental_hybrid::ADAPTIVE_HYBRID_TREE_STATE_EXTENSION_TYPE.into()
            })
            .cloned()
            .collect::<Vec<_>>();
        extensions.push(crate::extensions::Extension::Unknown(
            state.extension_type(),
            crate::extensions::UnknownExtension(state.extension_value_bytes().map_err(|_| {
                LibraryError::custom("experimental transition state encoding failed")
            })?),
        ));
        crate::extensions::Extensions::from_vec(extensions)
            .map_err(|_| LibraryError::custom("experimental transition extension set is invalid"))
    }

    #[cfg(feature = "experimental-hybrid")]
    fn experimental_extensions_with_retirement(
        &self,
        state: &ArityState,
        evidence: ExperimentalTreeCoverRetirementEvidence,
    ) -> Result<crate::extensions::Extensions<GroupContext>, LibraryError> {
        let mut extensions = self
            .extensions()
            .iter()
            .filter(|extension| {
                let extension_type = extension.extension_type();
                extension_type
                    != crate::experimental_hybrid::ADAPTIVE_HYBRID_TREE_STATE_EXTENSION_TYPE.into()
                    && extension_type != TREECOVER_RETIREMENT_EVIDENCE_EXTENSION_TYPE.into()
            })
            .cloned()
            .collect::<Vec<_>>();
        extensions.push(crate::extensions::Extension::Unknown(
            state.extension_type(),
            crate::extensions::UnknownExtension(state.extension_value_bytes().map_err(|_| {
                LibraryError::custom("experimental retirement state encoding failed")
            })?),
        ));
        extensions.push(crate::extensions::Extension::Unknown(
            TREECOVER_RETIREMENT_EVIDENCE_EXTENSION_TYPE,
            crate::extensions::UnknownExtension(evidence.extension_value_bytes().map_err(
                |_| LibraryError::custom("experimental retirement evidence encoding failed"),
            )?),
        ));
        crate::extensions::Extensions::from_vec(extensions)
            .map_err(|_| LibraryError::custom("experimental retirement extension set is invalid"))
    }

    /// Helper function to read decryption keypairs.
    pub(super) fn read_decryption_keypairs(
        &self,
        provider: &impl OpenMlsProvider,
        own_leaf_nodes: &[LeafNode],
    ) -> Result<(Vec<EncryptionKeyPair>, Vec<EncryptionKeyPair>), StageCommitError> {
        // All keys from the previous epoch are potential decryption keypairs.
        let mut old_epoch_keypairs = self.read_epoch_keypairs(provider.storage()).map_err(|e| {
            log::error!("Error reading epoch keypairs: {e:?}");
            StageCommitError::MissingDecryptionKey
        })?;
        #[cfg(feature = "experimental-hybrid")]
        if let Some(retained) = self
            .group_epoch_secrets()
            .experimental_transition_node_state()
        {
            for keypair in retained.local_old_keypairs() {
                if !old_epoch_keypairs
                    .iter()
                    .any(|existing| existing.public_key() == keypair.public_key())
                {
                    old_epoch_keypairs.push(keypair);
                }
            }
        }

        // If we are processing an update proposal that originally came from
        // us, the keypair corresponding to the leaf in the update is also a
        // potential decryption keypair.
        let leaf_node_keypairs = own_leaf_nodes
            .iter()
            .map(|leaf_node| {
                EncryptionKeyPair::read(provider, leaf_node.encryption_key())
                    .ok_or(StageCommitError::MissingDecryptionKey)
            })
            .collect::<Result<Vec<EncryptionKeyPair>, StageCommitError>>()?;

        Ok((old_epoch_keypairs, leaf_node_keypairs))
    }

    /// This function processes a message that may contain AppDataUpdate proposals.
    /// Process these first an create an AppDataUpdates, then pass that into this function.
    #[cfg(feature = "extensions-draft-08")]
    pub fn process_unverified_message_with_app_data_updates<Provider: OpenMlsProvider>(
        &self,
        provider: &Provider,
        unverified_message: UnverifiedMessage,
        app_data_dict_updates: Option<AppDataUpdates>,
    ) -> Result<ProcessedMessage, ProcessMessageError<Provider::StorageError>> {
        // Checks the following semantic validation:
        //  - ValSem010
        //  - ValSem246 (as part of ValSem010)
        //  - https://validation.openmls.tech/#valn1302
        //  - https://validation.openmls.tech/#valn1304
        let (content, credential) =
            unverified_message.verify(self.ciphersuite(), provider.crypto(), self.version())?;

        match content.sender() {
            Sender::Member(_) | Sender::NewMemberProposal | Sender::NewMemberCommit => self
                .process_internal_authenticated_content_with_app_data_updates(
                    provider,
                    content,
                    credential,
                    app_data_dict_updates,
                ),
            Sender::External(_) => {
                self.process_external_authenticated_content(provider, content, credential)
            }
        }
    }

    /// This processing function does most of the semantic verifications.
    /// It returns a [ProcessedMessage] enum.
    ///
    /// Note: If you expect `AppDataUpdate` proposals, use
    /// `process_unverified_message_with_app_data_updates` instead!
    ///
    /// Checks the following semantic validation:
    ///  - ValSem008
    ///  - ValSem010
    ///  - ValSem101
    ///  - ValSem102
    ///  - ValSem104
    ///  - ValSem106
    ///  - ValSem107
    ///  - ValSem108
    ///  - ValSem110
    ///  - ValSem111
    ///  - ValSem112
    ///  - ValSem113: All Proposals: The proposal type must be supported by all
    ///    members of the group
    ///  - ValSem200
    ///  - ValSem201
    ///  - ValSem202: Path must be the right length
    ///  - ValSem203: Path secrets must decrypt correctly
    ///  - ValSem204: Public keys from Path must be verified and match the
    ///    private keys from the direct path
    ///  - ValSem205
    pub(crate) fn process_unverified_message<Provider: OpenMlsProvider>(
        &self,
        provider: &Provider,
        unverified_message: UnverifiedMessage,
    ) -> Result<ProcessedMessage, ProcessMessageError<Provider::StorageError>> {
        // Checks the following semantic validation:
        //  - ValSem010
        //  - ValSem246 (as part of ValSem010)
        //  - https://validation.openmls.tech/#valn1302
        //  - https://validation.openmls.tech/#valn1304
        let (content, credential) =
            unverified_message.verify(self.ciphersuite(), provider.crypto(), self.version())?;

        match content.sender() {
            Sender::Member(_) | Sender::NewMemberProposal | Sender::NewMemberCommit => {
                self.process_internal_authenticated_content(provider, content, credential)
            }
            Sender::External(_) => {
                self.process_external_authenticated_content(provider, content, credential)
            }
        }
    }

    /// This processing function does most of the semantic verifications.
    /// It returns a [ProcessedMessage] enum.
    /// Checks the following semantic validation:
    ///  - ValSem008
    ///  - ValSem010
    ///  - ValSem101
    ///  - ValSem102
    ///  - ValSem104
    ///  - ValSem106
    ///  - ValSem107
    ///  - ValSem108
    ///  - ValSem110
    ///  - ValSem111
    ///  - ValSem112
    ///  - ValSem113: All Proposals: The proposal type must be supported by all
    ///    members of the group
    ///  - ValSem200
    ///  - ValSem201
    ///  - ValSem202: Path must be the right length
    ///  - ValSem203: Path secrets must decrypt correctly
    ///  - ValSem204: Public keys from Path must be verified and match the
    ///    private keys from the direct path
    ///  - ValSem205
    #[cfg(feature = "extensions-draft-08")]
    fn process_internal_authenticated_content_with_app_data_updates<Provider: OpenMlsProvider>(
        &self,
        provider: &Provider,
        content: AuthenticatedContent,
        credential: Credential,
        app_data_dict_updates: Option<AppDataUpdates>,
    ) -> Result<ProcessedMessage, ProcessMessageError<Provider::StorageError>> {
        let sender = content.sender().clone();
        let authenticated_data = content.authenticated_data().to_owned();
        let epoch = content.epoch();

        let content = match content.content() {
            FramedContentBody::Application(application_message) => {
                ProcessedMessageContent::ApplicationMessage(ApplicationMessage::new(
                    application_message.as_slice().to_owned(),
                ))
            }
            FramedContentBody::Proposal(_) => {
                let proposal = Box::new(QueuedProposal::from_authenticated_content_by_ref(
                    self.ciphersuite(),
                    provider.crypto(),
                    content,
                )?);

                if matches!(sender, Sender::NewMemberProposal) {
                    ProcessedMessageContent::ExternalJoinProposalMessage(proposal)
                } else {
                    ProcessedMessageContent::ProposalMessage(proposal)
                }
            }
            FramedContentBody::Commit(_) => {
                // Since this is a commit, we need to load the private key material we need for decryption.
                let (old_epoch_keypairs, leaf_node_keypairs) =
                    self.read_decryption_keypairs(provider, &self.own_leaf_nodes)?;

                let staged_commit = self.stage_commit_with_app_data_updates(
                    &content,
                    old_epoch_keypairs,
                    leaf_node_keypairs,
                    app_data_dict_updates,
                    provider,
                )?;

                ProcessedMessageContent::StagedCommitMessage(Box::new(staged_commit))
            }
        };

        Ok(ProcessedMessage::new(
            self.group_id().clone(),
            epoch,
            sender,
            authenticated_data,
            content,
            credential,
        ))
    }

    fn process_internal_authenticated_content<Provider: OpenMlsProvider>(
        &self,
        provider: &Provider,
        content: AuthenticatedContent,
        credential: Credential,
    ) -> Result<ProcessedMessage, ProcessMessageError<Provider::StorageError>> {
        let sender = content.sender().clone();
        let authenticated_data = content.authenticated_data().to_owned();
        let epoch = content.epoch();

        let content = match content.content() {
            FramedContentBody::Application(application_message) => {
                ProcessedMessageContent::ApplicationMessage(ApplicationMessage::new(
                    application_message.as_slice().to_owned(),
                ))
            }
            FramedContentBody::Proposal(_) => {
                let proposal = Box::new(QueuedProposal::from_authenticated_content_by_ref(
                    self.ciphersuite(),
                    provider.crypto(),
                    content,
                )?);

                if matches!(sender, Sender::NewMemberProposal) {
                    ProcessedMessageContent::ExternalJoinProposalMessage(proposal)
                } else {
                    ProcessedMessageContent::ProposalMessage(proposal)
                }
            }
            FramedContentBody::Commit(_) => {
                // Since this is a commit, we need to load the private key material we need for decryption.
                let (old_epoch_keypairs, leaf_node_keypairs) =
                    self.read_decryption_keypairs(provider, &self.own_leaf_nodes)?;

                let staged_commit =
                    self.stage_commit(&content, old_epoch_keypairs, leaf_node_keypairs, provider)?;

                ProcessedMessageContent::StagedCommitMessage(Box::new(staged_commit))
            }
        };

        Ok(ProcessedMessage::new(
            self.group_id().clone(),
            epoch,
            sender,
            authenticated_data,
            content,
            credential,
        ))
    }

    ///  - ValSem240
    ///  - ValSem241
    ///  - ValSem242
    ///  - ValSem244
    ///  - ValSem246 (as part of ValSem010)
    fn process_external_authenticated_content<Provider: OpenMlsProvider>(
        &self,
        provider: &Provider,
        content: AuthenticatedContent,
        credential: Credential,
    ) -> Result<ProcessedMessage, ProcessMessageError<Provider::StorageError>> {
        let sender = content.sender().clone();
        let data = content.authenticated_data().to_owned();

        debug_assert!(matches!(sender, Sender::External(_)));

        // https://validation.openmls.tech/#valn1501
        match content.content() {
            FramedContentBody::Application(_) => {
                Err(ProcessMessageError::UnauthorizedExternalApplicationMessage)
            }
            // TODO: https://validation.openmls.tech/#valn1502
            FramedContentBody::Proposal(Proposal::GroupContextExtensions(_)) => {
                let content = ProcessedMessageContent::ProposalMessage(Box::new(
                    QueuedProposal::from_authenticated_content_by_ref(
                        self.ciphersuite(),
                        provider.crypto(),
                        content,
                    )?,
                ));
                Ok(ProcessedMessage::new(
                    self.group_id().clone(),
                    self.context().epoch(),
                    sender,
                    data,
                    content,
                    credential,
                ))
            }

            FramedContentBody::Proposal(Proposal::Remove(_)) => {
                let content = ProcessedMessageContent::ProposalMessage(Box::new(
                    QueuedProposal::from_authenticated_content_by_ref(
                        self.ciphersuite(),
                        provider.crypto(),
                        content,
                    )?,
                ));
                Ok(ProcessedMessage::new(
                    self.group_id().clone(),
                    self.context().epoch(),
                    sender,
                    data,
                    content,
                    credential,
                ))
            }
            FramedContentBody::Proposal(Proposal::Add(_)) => {
                let content = ProcessedMessageContent::ProposalMessage(Box::new(
                    QueuedProposal::from_authenticated_content_by_ref(
                        self.ciphersuite(),
                        provider.crypto(),
                        content,
                    )?,
                ));
                Ok(ProcessedMessage::new(
                    self.group_id().clone(),
                    self.context().epoch(),
                    sender,
                    data,
                    content,
                    credential,
                ))
            }
            // TODO #151/#106
            FramedContentBody::Proposal(_) => Err(ProcessMessageError::UnsupportedProposalType),
            FramedContentBody::Commit(_) => {
                Err(ProcessMessageError::UnauthorizedExternalCommitMessage)
            }
        }
    }

    /// Performs framing validation and, if necessary, decrypts the given message.
    ///
    /// Returns the [`DecryptedMessage`] if processing is successful, or a
    /// [`ValidationError`] if it is not.
    ///
    /// Checks the following semantic validation:
    ///  - ValSem002
    ///  - ValSem003
    ///  - ValSem006
    ///  - ValSem007 MembershipTag presence
    ///  - https://validation.openmls.tech/#valn1202
    pub(crate) fn decrypt_message(
        &mut self,
        crypto: &impl OpenMlsCrypto,
        message: ProtocolMessage,
        sender_ratchet_configuration: &SenderRatchetConfiguration,
    ) -> Result<DecryptedMessage, ValidationError> {
        // Checks the following semantic validation:
        //  - ValSem002
        //  - ValSem003
        self.public_group.validate_framing(&message)?;

        let epoch = message.epoch();

        // Checks the following semantic validation:
        //  - ValSem006
        //  - ValSem007 MembershipTag presence
        match message {
            ProtocolMessage::PublicMessage(public_message) => {
                // If the message is older than the current epoch, we need to fetch the correct secret tree first.
                let message_secrets =
                    self.message_secrets_for_epoch(epoch).map_err(|e| match e {
                        SecretTreeError::TooDistantInThePast => ValidationError::NoPastEpochData,
                        _ => LibraryError::custom(
                            "Unexpected error while retrieving message secrets for epoch.",
                        )
                        .into(),
                    })?;
                DecryptedMessage::from_inbound_public_message(
                    *public_message,
                    message_secrets,
                    message_secrets.serialized_context().to_vec(),
                    crypto,
                    self.ciphersuite(),
                )
            }
            ProtocolMessage::PrivateMessage(ciphertext) => {
                // If the message is older than the current epoch, we need to fetch the correct secret tree first
                DecryptedMessage::from_inbound_ciphertext(
                    ciphertext,
                    crypto,
                    self,
                    sender_ratchet_configuration,
                )
            }
        }
    }
}
