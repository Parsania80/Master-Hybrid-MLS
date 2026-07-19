//! Construction of the baseline 128-member MLS bootstrap group.
//!
//! The public scheduling seed chooses only which existing member stages each
//! Add commit. OpenMLS continues to use its provider's operating-system-backed
//! entropy for credentials, KeyPackages, and MLS cryptographic operations.
//! This module deliberately writes no snapshot or report artifacts; Tasks 27
//! and 28 define the safe artifact boundary and output formats.

use mls_adapter::{BaselineClient, BaselineError, InboundEvent};
use thiserror::Error;

/// The exact group size required by the thesis bootstrap experiment.
pub const BOOTSTRAP_MEMBER_COUNT: usize = 128;

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
}
