#![forbid(unsafe_code)]

//! Reproducible accepted-commit window and impact classification for ADR 0006.
//!
//! This crate receives only public facts from commits already accepted by a
//! future simulator. It does not create MLS messages, validate MLS state,
//! derive secrets, calculate savings, or start a transition.

use std::collections::VecDeque;

use serde::Serialize;
use thiserror::Error;

/// Public configuration for one transition-policy observation window.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct PolicyWindowConfig {
    /// Maximum accepted post-warmup commits retained in `W_e`.
    pub window_accepted_commits: u32,
    /// Initial accepted commits retained only in the raw audit trail.
    pub warmup_accepted_commits: u32,
    /// Minimum impactful records required by the later start condition.
    pub q_min: u32,
}

impl PolicyWindowConfig {
    /// Validates public policy-window controls.
    pub const fn new(
        window_accepted_commits: u32,
        warmup_accepted_commits: u32,
        q_min: u32,
    ) -> Result<Self, PolicyError> {
        if window_accepted_commits == 0 {
            return Err(PolicyError::ZeroWindowLength);
        }
        if q_min == 0 {
            return Err(PolicyError::ZeroImpactMinimum);
        }
        Ok(Self {
            window_accepted_commits,
            warmup_accepted_commits,
            q_min,
        })
    }
}

/// Public facts that determine whether an accepted commit is impactful.
///
/// Counts represent only successfully applied membership changes. The caller
/// must obtain these facts after all valid members have converged.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct CommitImpactFacts {
    /// The commit has UpdatePath or path-secret delivery work.
    pub path_delivery_changed: bool,
    /// Successfully added members.
    pub successful_additions: u32,
    /// Successfully removed members.
    pub successful_removals: u32,
    /// Candidate occupied or blank-node structure changed.
    pub new_tree_population_changed: bool,
    /// Frozen binary TreeCover eligibility changed.
    pub treecover_validity_changed: bool,
    /// A relevant co-path recipient-resolution set changed.
    pub recipient_resolution_changed: bool,
    /// Authenticated arity, mapping, version, or state changed.
    pub transition_state_changed: bool,
}

/// A sorted ADR 0006 reason that makes an accepted commit impactful.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum ImpactReason {
    /// UpdatePath or path-secret delivery work changed.
    PathDelivery,
    /// One or more members were successfully added or removed.
    Membership,
    /// Candidate occupancy or blank-node structure changed.
    NewTreePopulation,
    /// Frozen TreeCover eligibility changed.
    TreecoverValidity,
    /// A co-path recipient-resolution set changed.
    RecipientResolution,
    /// Authenticated arity/mapping/version/state changed.
    TransitionState,
}

/// Explicit classification used for `q_e` inclusion and reporting.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub enum ImpactClassification {
    /// The record contributes one to `q_e`; reasons are sorted and non-empty.
    Impactful(Vec<ImpactReason>),
    /// The record remains in `W_e` but contributes neither to `q_e` nor a
    /// saving sum.
    None,
}

impl ImpactClassification {
    /// Returns true exactly when this record contributes to `q_e`.
    pub const fn is_impactful(&self) -> bool {
        matches!(self, Self::Impactful(_))
    }

    /// Returns sorted reasons for an impactful record, or an empty slice.
    pub fn reasons(&self) -> &[ImpactReason] {
        match self {
            Self::Impactful(reasons) => reasons,
            Self::None => &[],
        }
    }
}

/// Classifies an accepted commit using the complete ADR 0006 reason set.
pub fn is_impactful_commit(facts: CommitImpactFacts) -> ImpactClassification {
    let mut reasons = Vec::with_capacity(6);
    if facts.path_delivery_changed {
        reasons.push(ImpactReason::PathDelivery);
    }
    if facts.successful_additions != 0 || facts.successful_removals != 0 {
        reasons.push(ImpactReason::Membership);
    }
    if facts.new_tree_population_changed {
        reasons.push(ImpactReason::NewTreePopulation);
    }
    if facts.treecover_validity_changed {
        reasons.push(ImpactReason::TreecoverValidity);
    }
    if facts.recipient_resolution_changed {
        reasons.push(ImpactReason::RecipientResolution);
    }
    if facts.transition_state_changed {
        reasons.push(ImpactReason::TransitionState);
    }

    if reasons.is_empty() {
        ImpactClassification::None
    } else {
        ImpactClassification::Impactful(reasons)
    }
}

/// Why an accepted record is excluded from policy counts or retained in `W_e`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub enum PolicyRecordDisposition {
    /// The accepted record belongs to warmup and is excluded from `W_e`.
    WarmupExcluded,
    /// The record is in the post-warmup window with its explicit impact state.
    Window(ImpactClassification),
}

/// One public accepted-commit record retained for audit and policy evaluation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AcceptedCommitRecord {
    epoch_after: u64,
    successful_removals: u32,
    disposition: PolicyRecordDisposition,
}

impl AcceptedCommitRecord {
    /// Returns the accepted epoch after this commit was applied.
    pub const fn epoch_after(&self) -> u64 {
        self.epoch_after
    }

    /// Returns successful removals counted toward `r_e` when in `W_e`.
    pub const fn successful_removals(&self) -> u32 {
        self.successful_removals
    }

    /// Returns its explicit warmup/window and impact disposition.
    pub const fn disposition(&self) -> &PolicyRecordDisposition {
        &self.disposition
    }

    /// Returns impact classification when this record is in `W_e`.
    pub const fn impact_classification(&self) -> Option<&ImpactClassification> {
        match &self.disposition {
            PolicyRecordDisposition::WarmupExcluded => None,
            PolicyRecordDisposition::Window(classification) => Some(classification),
        }
    }
}

/// Result of appending one already-accepted public commit fact set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyAppendOutcome {
    /// The immutable record added to the raw audit trail.
    pub record: AcceptedCommitRecord,
    /// The oldest post-warmup epoch evicted from the bounded `W_e`, if any.
    pub evicted_epoch_after: Option<u64>,
}

/// Bounded ADR 0006 policy window plus its complete raw accepted-record trail.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyWindow {
    config: PolicyWindowConfig,
    raw_records: Vec<AcceptedCommitRecord>,
    window_records: VecDeque<AcceptedCommitRecord>,
    last_epoch_after: Option<u64>,
}

impl PolicyWindow {
    /// Creates an empty policy window with validated public controls.
    pub const fn new(config: PolicyWindowConfig) -> Self {
        Self {
            config,
            raw_records: Vec::new(),
            window_records: VecDeque::new(),
            last_epoch_after: None,
        }
    }

    /// Appends one commit that has already been accepted and converged.
    ///
    /// The first `warmup_accepted_commits` records are retained but never enter
    /// `W_e`. Every later record enters `W_e`, including an explicit
    /// non-impactful record, and oldest records are evicted past the bound.
    pub fn append_accepted(
        &mut self,
        epoch_after: u64,
        facts: CommitImpactFacts,
    ) -> Result<PolicyAppendOutcome, PolicyError> {
        if self
            .last_epoch_after
            .is_some_and(|last_epoch| epoch_after <= last_epoch)
        {
            return Err(PolicyError::NonIncreasingAcceptedEpoch);
        }

        let accepted_count = u32::try_from(self.raw_records.len() + 1)
            .map_err(|_| PolicyError::AcceptedCommitCountOverflow)?;
        let disposition = if accepted_count <= self.config.warmup_accepted_commits {
            PolicyRecordDisposition::WarmupExcluded
        } else {
            PolicyRecordDisposition::Window(is_impactful_commit(facts))
        };
        let record = AcceptedCommitRecord {
            epoch_after,
            successful_removals: facts.successful_removals,
            disposition,
        };
        self.last_epoch_after = Some(epoch_after);
        self.raw_records.push(record.clone());

        let evicted_epoch_after =
            if matches!(record.disposition, PolicyRecordDisposition::Window(_)) {
                self.window_records.push_back(record.clone());
                if self.window_records.len() > self.config.window_accepted_commits as usize {
                    self.window_records
                        .pop_front()
                        .map(|evicted| evicted.epoch_after)
                } else {
                    None
                }
            } else {
                None
            };

        Ok(PolicyAppendOutcome {
            record,
            evicted_epoch_after,
        })
    }

    /// Returns immutable raw records, including warmup and evicted records.
    pub fn raw_records(&self) -> &[AcceptedCommitRecord] {
        &self.raw_records
    }

    /// Iterates current `W_e` records ordered by increasing `epoch_after`.
    pub fn window_records(&self) -> impl ExactSizeIterator<Item = &AcceptedCommitRecord> {
        self.window_records.iter()
    }

    /// Returns the current number of records in `W_e`.
    pub fn window_len(&self) -> u32 {
        self.window_records.len() as u32
    }

    /// Returns `q_e`, the impactful-record count in the current `W_e`.
    pub fn q_e(&self) -> u32 {
        self.window_records
            .iter()
            .filter(|record| {
                record
                    .impact_classification()
                    .is_some_and(ImpactClassification::is_impactful)
            })
            .count() as u32
    }

    /// Returns `r_e`, the successful-removal count in the current `W_e`.
    pub fn r_e(&self) -> Result<u64, PolicyError> {
        self.window_records.iter().try_fold(0_u64, |total, record| {
            total
                .checked_add(u64::from(record.successful_removals()))
                .ok_or(PolicyError::RemovalCountOverflow)
        })
    }

    /// Returns whether the current `q_e` meets the configured minimum.
    pub fn meets_q_min(&self) -> bool {
        self.q_e() >= self.config.q_min
    }

    /// Returns the immutable public controls.
    pub const fn config(&self) -> PolicyWindowConfig {
        self.config
    }
}

/// One disjoint diagnostic component in the ADR 0006 transition-byte partition.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum TransitionByteComponent {
    /// Existing outer-commit framing and fields not specific to the transition.
    BaseCommit,
    /// Serialized metadata needed to introduce the new tree.
    NewTreeMetadata,
    /// Canonical deterministic binary-to-quaternary leaf mapping bytes.
    DeterministicLeafMapping,
    /// Serialized authenticated tree-version metadata.
    TreeVersionMetadata,
    /// Serialized initial delivery-only TreeCover metadata.
    TreecoverInitialization,
    /// Any remaining transition-only serialized field.
    OtherTransitionOnly,
}

/// One half-open byte range assigned to a transition-byte component.
///
/// Ranges identify bytes in a caller-supplied canonical outer transition
/// message. They contain no key, secret, or live MLS reference.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransitionByteRange {
    component: TransitionByteComponent,
    start: usize,
    end: usize,
}

impl TransitionByteRange {
    /// Creates a non-empty half-open range for one diagnostic component.
    pub const fn new(component: TransitionByteComponent, start: usize, end: usize) -> Self {
        Self {
            component,
            start,
            end,
        }
    }

    /// Returns the assigned partition component.
    pub const fn component(&self) -> TransitionByteComponent {
        self.component
    }

    /// Returns the half-open range start.
    pub const fn start(&self) -> usize {
        self.start
    }

    /// Returns the half-open range end.
    pub const fn end(&self) -> usize {
        self.end
    }
}

/// Public exact byte counts for a disjoint transition-message partition.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct TransitionByteComponents {
    base_commit_bytes: usize,
    new_tree_metadata_bytes: usize,
    deterministic_leaf_mapping_bytes: usize,
    tree_version_metadata_bytes: usize,
    treecover_initialization_bytes: usize,
    other_transition_only_bytes: usize,
}

impl TransitionByteComponents {
    const fn zero() -> Self {
        Self {
            base_commit_bytes: 0,
            new_tree_metadata_bytes: 0,
            deterministic_leaf_mapping_bytes: 0,
            tree_version_metadata_bytes: 0,
            treecover_initialization_bytes: 0,
            other_transition_only_bytes: 0,
        }
    }

    fn add(
        &mut self,
        component: TransitionByteComponent,
        byte_count: usize,
    ) -> Result<(), PolicyError> {
        let destination = match component {
            TransitionByteComponent::BaseCommit => &mut self.base_commit_bytes,
            TransitionByteComponent::NewTreeMetadata => &mut self.new_tree_metadata_bytes,
            TransitionByteComponent::DeterministicLeafMapping => {
                &mut self.deterministic_leaf_mapping_bytes
            }
            TransitionByteComponent::TreeVersionMetadata => &mut self.tree_version_metadata_bytes,
            TransitionByteComponent::TreecoverInitialization => {
                &mut self.treecover_initialization_bytes
            }
            TransitionByteComponent::OtherTransitionOnly => &mut self.other_transition_only_bytes,
        };
        *destination = destination
            .checked_add(byte_count)
            .ok_or(PolicyError::TransitionByteCountOverflow)?;
        Ok(())
    }

    /// Returns existing outer-commit bytes included once in the partition.
    pub const fn base_commit_bytes(&self) -> usize {
        self.base_commit_bytes
    }

    /// Returns serialized new-tree metadata bytes.
    pub const fn new_tree_metadata_bytes(&self) -> usize {
        self.new_tree_metadata_bytes
    }

    /// Returns deterministic leaf-mapping bytes.
    pub const fn deterministic_leaf_mapping_bytes(&self) -> usize {
        self.deterministic_leaf_mapping_bytes
    }

    /// Returns serialized tree-version metadata bytes.
    pub const fn tree_version_metadata_bytes(&self) -> usize {
        self.tree_version_metadata_bytes
    }

    /// Returns serialized TreeCover initialization bytes.
    pub const fn treecover_initialization_bytes(&self) -> usize {
        self.treecover_initialization_bytes
    }

    /// Returns remaining transition-only bytes.
    pub const fn other_transition_only_bytes(&self) -> usize {
        self.other_transition_only_bytes
    }

    /// Returns the checked component sum.
    pub fn total_bytes(&self) -> Result<usize, PolicyError> {
        [
            self.base_commit_bytes,
            self.new_tree_metadata_bytes,
            self.deterministic_leaf_mapping_bytes,
            self.tree_version_metadata_bytes,
            self.treecover_initialization_bytes,
            self.other_transition_only_bytes,
        ]
        .into_iter()
        .try_fold(0usize, |total, bytes| {
            total
                .checked_add(bytes)
                .ok_or(PolicyError::TransitionByteCountOverflow)
        })
    }
}

/// Provenance for `B_transition_preflight`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum TransitionPreflightMethod {
    /// A caller supplied an exact canonical serialized outer-message partition.
    /// The count remains an estimate because the candidate transition was not
    /// emitted or merged by a live MLS group.
    CanonicalOuterMessagePartition,
}

/// A non-mutating `B_transition_preflight` measurement.
///
/// `measured_bytes` is the observed canonical outer byte length. It is also
/// recorded as `estimated_bytes` because it is a preflight estimate, not an
/// accepted transition Commit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct TransitionPreflightMeasurement {
    measured_bytes: usize,
    estimated_bytes: usize,
    method: TransitionPreflightMethod,
    components: TransitionByteComponents,
}

impl TransitionPreflightMeasurement {
    /// Measures a caller-supplied canonical outer transition message.
    ///
    /// Every outer-message byte must appear in exactly one provided component
    /// range. This makes the diagnostic partition disjoint and prevents
    /// metadata from being added on top of an already-counted outer message.
    /// The input slice is read only and not retained.
    pub fn from_serialized_outer_message(
        outer_message: &[u8],
        ranges: &[TransitionByteRange],
    ) -> Result<Self, PolicyError> {
        if outer_message.is_empty() {
            return Err(PolicyError::EmptyTransitionOuterMessage);
        }
        if ranges.is_empty() {
            return Err(PolicyError::MissingTransitionBytePartition);
        }

        let mut ranges = ranges.to_vec();
        ranges.sort_unstable_by_key(TransitionByteRange::start);
        let mut expected_start = 0usize;
        let mut components = TransitionByteComponents::zero();
        for range in ranges {
            if range.start >= range.end || range.end > outer_message.len() {
                return Err(PolicyError::InvalidTransitionByteRange);
            }
            if range.start != expected_start {
                return Err(PolicyError::IncompleteOrOverlappingTransitionPartition);
            }
            let byte_count = range.end - range.start;
            components.add(range.component, byte_count)?;
            expected_start = range.end;
        }
        if expected_start != outer_message.len() || components.total_bytes()? != outer_message.len()
        {
            return Err(PolicyError::IncompleteOrOverlappingTransitionPartition);
        }

        Ok(Self {
            measured_bytes: outer_message.len(),
            estimated_bytes: outer_message.len(),
            method: TransitionPreflightMethod::CanonicalOuterMessagePartition,
            components,
        })
    }

    /// Returns the observed canonical outer-message byte length.
    pub const fn measured_bytes(&self) -> usize {
        self.measured_bytes
    }

    /// Returns `B_transition_preflight` as an explicitly labeled estimate.
    pub const fn estimated_bytes(&self) -> usize {
        self.estimated_bytes
    }

    /// Returns why this count is a preflight estimate.
    pub const fn method(&self) -> TransitionPreflightMethod {
        self.method
    }

    /// Returns the disjoint diagnostic byte partition.
    pub const fn components(&self) -> TransitionByteComponents {
        self.components
    }

    /// Compares the preflight estimate with a later actual serialized outer
    /// transition message without changing either message or live state.
    pub fn compare_actual_outer_message(
        &self,
        actual_outer_message: &[u8],
    ) -> TransitionByteComparison {
        TransitionByteComparison {
            preflight_bytes: self.estimated_bytes,
            actual_bytes: actual_outer_message.len(),
        }
    }
}

/// A reportable preflight-versus-actual outer-message byte comparison.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct TransitionByteComparison {
    preflight_bytes: usize,
    actual_bytes: usize,
}

impl TransitionByteComparison {
    /// Returns the stored preflight estimate.
    pub const fn preflight_bytes(&self) -> usize {
        self.preflight_bytes
    }

    /// Returns the later actual outer-message length.
    pub const fn actual_bytes(&self) -> usize {
        self.actual_bytes
    }

    /// Returns whether preflight and actual bytes match exactly.
    pub const fn matches(&self) -> bool {
        self.preflight_bytes == self.actual_bytes
    }

    /// Returns `actual - preflight` without signed-integer conversion.
    pub const fn delta_bytes(&self) -> TransitionByteDelta {
        if self.actual_bytes == self.preflight_bytes {
            TransitionByteDelta::Equal
        } else if self.actual_bytes > self.preflight_bytes {
            TransitionByteDelta::ActualLargerBy(self.actual_bytes - self.preflight_bytes)
        } else {
            TransitionByteDelta::PreflightLargerBy(self.preflight_bytes - self.actual_bytes)
        }
    }
}

/// Directional, overflow-free difference between actual and preflight bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum TransitionByteDelta {
    /// Actual and preflight byte counts match.
    Equal,
    /// Actual bytes exceed preflight bytes by this amount.
    ActualLargerBy(usize),
    /// Preflight bytes exceed actual bytes by this amount.
    PreflightLargerBy(usize),
}

/// Errors from public transition-policy recording.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum PolicyError {
    /// `W_e` must retain at least one post-warmup accepted record.
    #[error("the accepted-commit window length must be positive")]
    ZeroWindowLength,
    /// The later `q_e` start condition requires a positive threshold.
    #[error("the impactful-commit minimum must be positive")]
    ZeroImpactMinimum,
    /// Accepted commit records must be supplied in strict epoch order.
    #[error("accepted commit epochs must be strictly increasing")]
    NonIncreasingAcceptedEpoch,
    /// The raw public accepted-record count exceeded the supported range.
    #[error("the accepted commit count exceeds the supported range")]
    AcceptedCommitCountOverflow,
    /// The sum defining `r_e` exceeded the supported range.
    #[error("the successful removal count exceeds the supported range")]
    RemovalCountOverflow,
    /// A preflight cannot measure an empty outer transition message.
    #[error("the serialized outer transition message is empty")]
    EmptyTransitionOuterMessage,
    /// A preflight needs at least one diagnostic component range.
    #[error("the transition byte partition is missing")]
    MissingTransitionBytePartition,
    /// A component range is empty or outside the serialized outer message.
    #[error("a transition byte component range is invalid")]
    InvalidTransitionByteRange,
    /// Component ranges must form an exact non-overlapping outer-message partition.
    #[error("the transition byte partition is incomplete or overlapping")]
    IncompleteOrOverlappingTransitionPartition,
    /// A component sum exceeded the supported byte-count representation.
    #[error("the transition byte count exceeds the supported range")]
    TransitionByteCountOverflow,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> PolicyWindowConfig {
        PolicyWindowConfig::new(2, 1, 2).expect("valid public controls")
    }

    #[test]
    fn classification_is_complete_sorted_and_explicit_when_empty() {
        let classification = is_impactful_commit(CommitImpactFacts {
            path_delivery_changed: true,
            successful_additions: 1,
            new_tree_population_changed: true,
            recipient_resolution_changed: true,
            ..CommitImpactFacts::default()
        });
        assert_eq!(
            classification,
            ImpactClassification::Impactful(vec![
                ImpactReason::PathDelivery,
                ImpactReason::Membership,
                ImpactReason::NewTreePopulation,
                ImpactReason::RecipientResolution,
            ])
        );
        assert_eq!(
            is_impactful_commit(CommitImpactFacts::default()),
            ImpactClassification::None
        );
    }

    #[test]
    fn warmup_window_eviction_and_qe_re_follow_adr_order() {
        let mut window = PolicyWindow::new(config());
        let warmup = window
            .append_accepted(
                1,
                CommitImpactFacts {
                    successful_removals: 1,
                    ..CommitImpactFacts::default()
                },
            )
            .expect("accepted warmup record");
        assert_eq!(
            warmup.record.disposition(),
            &PolicyRecordDisposition::WarmupExcluded
        );
        assert_eq!(window.window_len(), 0);
        assert_eq!(window.q_e(), 0);
        assert_eq!(window.r_e(), Ok(0));

        window
            .append_accepted(2, CommitImpactFacts::default())
            .expect("non-impactful window record");
        window
            .append_accepted(
                3,
                CommitImpactFacts {
                    successful_removals: 2,
                    ..CommitImpactFacts::default()
                },
            )
            .expect("impactful removal record");
        assert_eq!(window.q_e(), 1);
        assert_eq!(window.r_e(), Ok(2));
        assert!(!window.meets_q_min());

        let eviction = window
            .append_accepted(
                4,
                CommitImpactFacts {
                    path_delivery_changed: true,
                    ..CommitImpactFacts::default()
                },
            )
            .expect("impactful delivery record");
        assert_eq!(eviction.evicted_epoch_after, Some(2));
        assert_eq!(window.q_e(), 2);
        assert_eq!(window.r_e(), Ok(2));
        assert!(window.meets_q_min());

        let eviction = window
            .append_accepted(5, CommitImpactFacts::default())
            .expect("non-impactful record remains in the window");
        assert_eq!(eviction.evicted_epoch_after, Some(3));
        assert_eq!(window.q_e(), 1);
        assert_eq!(window.r_e(), Ok(0));
        assert_eq!(window.raw_records().len(), 5);
        assert_eq!(
            window
                .window_records()
                .map(AcceptedCommitRecord::epoch_after)
                .collect::<Vec<_>>(),
            vec![4, 5]
        );
    }

    #[test]
    fn only_strictly_increasing_accepted_epochs_are_recorded() {
        let mut window = PolicyWindow::new(config());
        window
            .append_accepted(7, CommitImpactFacts::default())
            .expect("first accepted epoch");
        assert_eq!(
            window.append_accepted(7, CommitImpactFacts::default()),
            Err(PolicyError::NonIncreasingAcceptedEpoch)
        );
        assert_eq!(
            window.append_accepted(6, CommitImpactFacts::default()),
            Err(PolicyError::NonIncreasingAcceptedEpoch)
        );
    }

    #[test]
    fn configuration_rejects_zero_window_or_q_min() {
        assert_eq!(
            PolicyWindowConfig::new(0, 0, 1),
            Err(PolicyError::ZeroWindowLength)
        );
        assert_eq!(
            PolicyWindowConfig::new(1, 0, 0),
            Err(PolicyError::ZeroImpactMinimum)
        );
    }

    #[test]
    fn transition_preflight_measures_an_exact_disjoint_outer_partition() {
        let outer = [0_u8; 17];
        let measurement = TransitionPreflightMeasurement::from_serialized_outer_message(
            &outer,
            &[
                TransitionByteRange::new(TransitionByteComponent::BaseCommit, 0, 3),
                TransitionByteRange::new(TransitionByteComponent::NewTreeMetadata, 3, 5),
                TransitionByteRange::new(TransitionByteComponent::DeterministicLeafMapping, 5, 10),
                TransitionByteRange::new(TransitionByteComponent::TreeVersionMetadata, 10, 11),
                TransitionByteRange::new(TransitionByteComponent::TreecoverInitialization, 11, 15),
                TransitionByteRange::new(TransitionByteComponent::OtherTransitionOnly, 15, 17),
            ],
        )
        .expect("exact outer-message partition");

        assert_eq!(measurement.measured_bytes(), 17);
        assert_eq!(measurement.estimated_bytes(), 17);
        assert_eq!(
            measurement.method(),
            TransitionPreflightMethod::CanonicalOuterMessagePartition
        );
        let components = measurement.components();
        assert_eq!(components.base_commit_bytes(), 3);
        assert_eq!(components.new_tree_metadata_bytes(), 2);
        assert_eq!(components.deterministic_leaf_mapping_bytes(), 5);
        assert_eq!(components.tree_version_metadata_bytes(), 1);
        assert_eq!(components.treecover_initialization_bytes(), 4);
        assert_eq!(components.other_transition_only_bytes(), 2);
        assert_eq!(components.total_bytes(), Ok(17));
    }

    #[test]
    fn transition_preflight_rejects_empty_gapped_and_overlapping_partitions() {
        let outer = [0_u8; 8];
        assert_eq!(
            TransitionPreflightMeasurement::from_serialized_outer_message(&[], &[]),
            Err(PolicyError::EmptyTransitionOuterMessage)
        );
        assert_eq!(
            TransitionPreflightMeasurement::from_serialized_outer_message(&outer, &[]),
            Err(PolicyError::MissingTransitionBytePartition)
        );
        assert_eq!(
            TransitionPreflightMeasurement::from_serialized_outer_message(
                &outer,
                &[
                    TransitionByteRange::new(TransitionByteComponent::BaseCommit, 0, 2),
                    TransitionByteRange::new(TransitionByteComponent::OtherTransitionOnly, 3, 8),
                ],
            ),
            Err(PolicyError::IncompleteOrOverlappingTransitionPartition)
        );
        assert_eq!(
            TransitionPreflightMeasurement::from_serialized_outer_message(
                &outer,
                &[
                    TransitionByteRange::new(TransitionByteComponent::BaseCommit, 0, 5),
                    TransitionByteRange::new(TransitionByteComponent::OtherTransitionOnly, 4, 8),
                ],
            ),
            Err(PolicyError::IncompleteOrOverlappingTransitionPartition)
        );
    }

    #[test]
    fn transition_preflight_reports_later_actual_byte_mismatches() {
        let preflight = TransitionPreflightMeasurement::from_serialized_outer_message(
            &[0_u8; 4],
            &[TransitionByteRange::new(
                TransitionByteComponent::BaseCommit,
                0,
                4,
            )],
        )
        .expect("valid preflight");
        let matching = preflight.compare_actual_outer_message(&[0_u8; 4]);
        let larger = preflight.compare_actual_outer_message(&[0_u8; 6]);
        let smaller = preflight.compare_actual_outer_message(&[0_u8; 2]);

        assert!(matching.matches());
        assert_eq!(matching.delta_bytes(), TransitionByteDelta::Equal);
        assert!(!larger.matches());
        assert_eq!(larger.delta_bytes(), TransitionByteDelta::ActualLargerBy(2));
        assert_eq!(
            smaller.delta_bytes(),
            TransitionByteDelta::PreflightLargerBy(2)
        );
    }
}
