//! Construction of the baseline 128-member MLS bootstrap group.
//!
//! The public scheduling seed chooses only which existing member stages each
//! Add commit. OpenMLS continues to use its provider's operating-system-backed
//! entropy for credentials, KeyPackages, and MLS cryptographic operations.
//! This module deliberately writes no snapshot or report artifacts; Tasks 27
//! and 28 define the safe artifact boundary and output formats.

use mls_adapter::{BaselineClient, BaselineError, BaselineState, InboundEvent};
use thiserror::Error;

/// The exact group size required by the thesis bootstrap experiment.
pub const BOOTSTRAP_MEMBER_COUNT: usize = 128;
/// The maintained baseline adapter always creates an RFC 9420 binary tree.
pub const BASELINE_TREE_ARITY: u8 = 2;
/// A complete binary tree holding 128 leaves has seven levels above a leaf.
pub const BOOTSTRAP_BINARY_TREE_HEIGHT: u8 = 7;

/// Public, non-secret options for the baseline bootstrap operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapOptions {
    /// Must be [`BOOTSTRAP_MEMBER_COUNT`] for the first executable.
    pub members: usize,
    /// Public seed used only for the deterministic committer schedule.
    pub schedule_seed: u64,
}

impl BootstrapOptions {
    /// Validates the fixed-scope bootstrap configuration.
    pub fn validate(&self) -> Result<(), BootstrapError> {
        if self.members != BOOTSTRAP_MEMBER_COUNT {
            return Err(BootstrapError::UnsupportedMemberCount {
                requested: self.members,
                required: BOOTSTRAP_MEMBER_COUNT,
            });
        }
        Ok(())
    }
}

/// Public results from a successful construction. No private MLS state,
/// secrets, key packages, or entropy are retained here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapResult {
    /// Number of Add commits staged and delivered after group creation.
    pub add_commit_count: usize,
    /// Public indexes of the members that staged each Add commit.
    pub committer_indices: Vec<usize>,
}

/// Safe public facts established by a successful 128-member verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapVerification {
    /// Common epoch after the 127 successful Add commits.
    pub epoch: u64,
    /// Fixed arity of the standard RFC 9420 baseline tree.
    pub tree_arity: u8,
    /// Derived height for its fully occupied 128-leaf binary tree.
    pub tree_height: u8,
    /// Authenticated public MLS GroupContext shared by all members.
    pub group_context: Vec<u8>,
    /// Authenticated public RFC 9420 tree hash shared by all members.
    pub tree_hash: Vec<u8>,
}

/// Failures encountered while constructing and delivering bootstrap commits.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum BootstrapError {
    /// Task 25 intentionally supports only the thesis's 128-member group.
    #[error("bootstrap_128 requires exactly {required} members, but received {requested}")]
    UnsupportedMemberCount {
        /// The user-supplied count.
        requested: usize,
        /// The fixed required count.
        required: usize,
    },
    /// The maintained baseline adapter rejected an MLS operation.
    #[error("the baseline MLS operation failed")]
    Baseline,
    /// A delivered commit did not produce the expected upstream merge event.
    #[error("a valid recipient did not merge the delivered commit")]
    CommitDelivery,
    /// A newly added member did not receive the expected Welcome artifact.
    #[error("an Add commit did not contain an MLS Welcome message")]
    MissingWelcome,
}

impl From<BaselineError> for BootstrapError {
    fn from(_: BaselineError) -> Self {
        Self::Baseline
    }
}

/// Fail-closed errors from the Task 26 bootstrap verifier.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum BootstrapVerificationError {
    /// The caller did not provide the complete fixed-size client set.
    #[error("verification requires exactly 128 initialized clients")]
    ClientCount,
    /// An upstream MLS operation failed while reading public state or delivering
    /// the verification application message.
    #[error("the baseline MLS verification operation failed")]
    Baseline,
    /// A member's public MLS state differs from the first member's state.
    #[error("members do not share an identical authenticated public MLS state")]
    DivergentState,
    /// The public group member count is not exactly 128.
    #[error("the MLS group does not contain exactly 128 active members")]
    MemberCount,
    /// The 128 active members do not occupy every expected binary-tree leaf.
    #[error("the MLS tree does not have exactly the expected occupied leaves")]
    LeafOccupancy,
    /// A baseline application message did not decrypt to its expected payload.
    #[error("a baseline application message did not decrypt for every recipient")]
    ApplicationDelivery,
}

impl From<BaselineError> for BootstrapVerificationError {
    fn from(_: BaselineError) -> Self {
        Self::Baseline
    }
}

/// Builds the fixed-size group and delivers each Add commit to every current
/// member. The returned client vector remains private to the caller so Task 26
/// can perform its separate convergence and cleanup verification.
pub fn bootstrap_128(
    options: &BootstrapOptions,
) -> Result<(Vec<BaselineClient>, BootstrapResult), BootstrapError> {
    options.validate()?;

    let mut clients = Vec::with_capacity(options.members);
    for member_index in 0..options.members {
        clients.push(BaselineClient::new(member_identity(member_index))?);
    }

    clients[0].create_group(b"adaptive-hybrid-mls-bootstrap-128")?;

    let mut committer_indices = Vec::with_capacity(options.members - 1);
    for joining_index in 1..options.members {
        let committer_index = committer_for_add(options.schedule_seed, joining_index);
        let key_package = clients[joining_index].key_package()?;
        let outbound = clients[committer_index]
            .add_members(core::slice::from_ref(key_package.key_package()))?;

        for (recipient_index, recipient) in clients[..joining_index].iter_mut().enumerate() {
            if recipient_index != committer_index
                && recipient.process_message(&outbound.commit)? != InboundEvent::CommitMerged
            {
                return Err(BootstrapError::CommitDelivery);
            }
        }
        clients[committer_index].merge_pending_commit()?;
        let welcome = outbound
            .welcome
            .as_deref()
            .ok_or(BootstrapError::MissingWelcome)?;
        clients[joining_index].join_from_welcome(welcome)?;
        committer_indices.push(committer_index);
    }

    Ok((
        clients,
        BootstrapResult {
            add_commit_count: options.members - 1,
            committer_indices,
        },
    ))
}

/// Verifies all Task 26 public bootstrap invariants and application delivery.
///
/// On success the return value contains public state only. The caller must
/// promptly drop the supplied clients; this function neither serializes nor
/// exposes their private MLS state, private keys, or secret-tree material.
pub fn verify_bootstrap_128(
    clients: &mut [BaselineClient],
) -> Result<BootstrapVerification, BootstrapVerificationError> {
    if clients.len() != BOOTSTRAP_MEMBER_COUNT {
        return Err(BootstrapVerificationError::ClientCount);
    }

    let expected_leaf_indices: Vec<u32> = (0..BOOTSTRAP_MEMBER_COUNT as u32).collect();
    let reference_state = clients[0].state()?;
    verify_public_state(&reference_state, &expected_leaf_indices)?;
    for client in &clients[1..] {
        let state = client.state()?;
        if state != reference_state {
            return Err(BootstrapVerificationError::DivergentState);
        }
    }

    let payload = b"bootstrap-128 application delivery verification";
    let message = clients[0].create_application_message(payload)?;
    for recipient in &mut clients[1..] {
        if recipient.process_message(&message)?
            != InboundEvent::ApplicationMessage(payload.to_vec())
        {
            return Err(BootstrapVerificationError::ApplicationDelivery);
        }
    }

    Ok(BootstrapVerification {
        epoch: reference_state.epoch,
        tree_arity: BASELINE_TREE_ARITY,
        tree_height: BOOTSTRAP_BINARY_TREE_HEIGHT,
        group_context: reference_state.group_context,
        tree_hash: reference_state.tree_hash,
    })
}

fn verify_public_state(
    state: &BaselineState,
    expected_leaf_indices: &[u32],
) -> Result<(), BootstrapVerificationError> {
    if state.member_count != BOOTSTRAP_MEMBER_COUNT {
        return Err(BootstrapVerificationError::MemberCount);
    }
    if state.member_leaf_indices != expected_leaf_indices {
        return Err(BootstrapVerificationError::LeafOccupancy);
    }
    Ok(())
}

fn member_identity(member_index: usize) -> Vec<u8> {
    format!("bootstrap-member-{member_index:03}").into_bytes()
}

fn committer_for_add(schedule_seed: u64, joining_index: usize) -> usize {
    let active_members = joining_index;
    let offset = (schedule_seed % active_members as u64) as usize;
    (joining_index - 1 + offset) % active_members
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_any_group_size_other_than_the_thesis_bootstrap_size() {
        assert_eq!(
            BootstrapOptions {
                members: BOOTSTRAP_MEMBER_COUNT - 1,
                schedule_seed: 42,
            }
            .validate(),
            Err(BootstrapError::UnsupportedMemberCount {
                requested: BOOTSTRAP_MEMBER_COUNT - 1,
                required: BOOTSTRAP_MEMBER_COUNT,
            })
        );
    }

    #[test]
    fn public_seed_selects_only_existing_committers() {
        for joining_index in 1..BOOTSTRAP_MEMBER_COUNT {
            assert!(committer_for_add(42, joining_index) < joining_index);
        }
    }

    #[test]
    fn public_schedule_uses_multiple_committers_when_the_group_allows_it() {
        let committers: std::collections::BTreeSet<_> = (1..BOOTSTRAP_MEMBER_COUNT)
            .map(|joining_index| committer_for_add(42, joining_index))
            .collect();
        assert!(committers.len() > 1);
    }

    #[test]
    #[ignore = "run in release mode as the 128-member bootstrap acceptance test"]
    fn bootstrap_128_converges_on_public_state_and_delivers_an_application_message() {
        let options = BootstrapOptions {
            members: BOOTSTRAP_MEMBER_COUNT,
            schedule_seed: 42,
        };
        let (mut clients, result) = bootstrap_128(&options).expect("bootstrap must succeed");
        let verification = verify_bootstrap_128(&mut clients).expect("verification must succeed");

        assert_eq!(result.add_commit_count, 127);
        assert_eq!(verification.epoch, 127);
        assert_eq!(verification.tree_arity, BASELINE_TREE_ARITY);
        assert_eq!(verification.tree_height, BOOTSTRAP_BINARY_TREE_HEIGHT);
        assert!(!verification.group_context.is_empty());
        assert!(!verification.tree_hash.is_empty());
        drop(clients);
    }
}
