#![forbid(unsafe_code)]

//! Typed measurement-record boundary.
//!
//! This crate preserves the distinction between an emitted baseline MLS commit
//! and a shadow candidate estimate. It does not construct, authenticate, or
//! merge an experimental MLS commit.

use core::ops::Range;
use std::time::{Duration, Instant};

use adaptive_tree::ShadowQuaternaryTree;
use hybrid_path_secret::HybridPathCiphertext;
use serde::Serialize;
use thiserror::Error;

/// Why a byte value has its measured or estimated status.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum ByteEstimationMethod {
    /// The complete value was emitted by the unchanged baseline MLS adapter.
    EmittedOuterMlsCommit,
    /// A byte range was observed in that emitted outer commit and is declared
    /// unchanged by the caller's future experimental fork boundary.
    MeasuredUnchangedOuterFraming,
    /// A candidate topology payload was serialized by the production hybrid
    /// TLS codec. Its enclosing candidate MLS commit remains an estimate.
    ShadowExactCodec,
}

/// Provenance for one serialized byte value.
///
/// `estimated_bytes` is `None` only for a complete emitted outer MLS commit.
/// For every candidate component and candidate total it equals the exact
/// codec-driven counterfactual count and remains explicitly labeled as an
/// estimate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct SerializedByteProvenance {
    measured_bytes: usize,
    estimated_bytes: Option<usize>,
    estimation_method: ByteEstimationMethod,
}

impl SerializedByteProvenance {
    const fn emitted_outer_commit(measured_bytes: usize) -> Self {
        Self {
            measured_bytes,
            estimated_bytes: None,
            estimation_method: ByteEstimationMethod::EmittedOuterMlsCommit,
        }
    }

    const fn candidate_component(measured_bytes: usize, method: ByteEstimationMethod) -> Self {
        Self {
            measured_bytes,
            estimated_bytes: Some(measured_bytes),
            estimation_method: method,
        }
    }

    /// Returns actual bytes observed at the named serializer boundary.
    pub const fn measured_bytes(self) -> usize {
        self.measured_bytes
    }

    /// Returns the candidate estimate, when this is not an emitted outer MLS
    /// message.
    pub const fn estimated_bytes(self) -> Option<usize> {
        self.estimated_bytes
    }

    /// Returns the provenance method.
    pub const fn estimation_method(self) -> ByteEstimationMethod {
        self.estimation_method
    }
}

/// `B_i(2)`: one complete outer RFC 9420 Commit emitted by the baseline.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MeasuredCurrentCommit {
    wire_bytes: Vec<u8>,
    provenance: SerializedByteProvenance,
}

impl MeasuredCurrentCommit {
    /// Records the byte length of an already-emitted baseline outer commit.
    ///
    /// Call this with `OutboundCommit::commit` at the MLS adapter boundary.
    pub fn from_emitted_outer_commit(wire_bytes: Vec<u8>) -> Result<Self, MeasurementError> {
        if wire_bytes.is_empty() {
            return Err(MeasurementError::EmptyEmittedCommit);
        }
        let provenance = SerializedByteProvenance::emitted_outer_commit(wire_bytes.len());
        Ok(Self {
            wire_bytes,
            provenance,
        })
    }

    /// Returns `B_i(2)` provenance.
    pub const fn provenance(&self) -> SerializedByteProvenance {
        self.provenance
    }

    /// Selects a disjoint, actually observed range that a future fork has
    /// established remains unchanged in its candidate outer framing.
    pub fn unchanged_outer_framing(
        &self,
        range: Range<usize>,
    ) -> Result<UnchangedOuterFraming, MeasurementError> {
        if range.start >= range.end || range.end > self.wire_bytes.len() {
            return Err(MeasurementError::InvalidOuterFramingRange);
        }
        Ok(UnchangedOuterFraming {
            range: range.clone(),
            provenance: SerializedByteProvenance::candidate_component(
                range.end - range.start,
                ByteEstimationMethod::MeasuredUnchangedOuterFraming,
            ),
        })
    }
}

/// An observed byte range from an emitted current commit that is explicitly
/// retained by a candidate estimate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnchangedOuterFraming {
    range: Range<usize>,
    provenance: SerializedByteProvenance,
}

impl UnchangedOuterFraming {
    /// Returns the source range within `B_i(2)`.
    pub fn source_range(&self) -> Range<usize> {
        self.range.clone()
    }

    /// Returns its measured-and-estimated provenance.
    pub const fn provenance(&self) -> SerializedByteProvenance {
        self.provenance
    }
}

/// One candidate topology-dependent payload serialized by the hybrid TLS
/// codec for a single UpdatePath level.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CandidateHybridPathComponent {
    path_node_index: u32,
    recipient_count: usize,
    provenance: SerializedByteProvenance,
}

impl CandidateHybridPathComponent {
    fn from_ciphertext(ciphertext: &HybridPathCiphertext) -> Result<Self, MeasurementError> {
        let bytes = ciphertext
            .commit_authenticated_bytes()
            .map_err(|_| MeasurementError::HybridCodec)?;
        Ok(Self {
            path_node_index: ciphertext.path_node_index().as_u32(),
            recipient_count: ciphertext.recipients().len(),
            provenance: SerializedByteProvenance::candidate_component(
                bytes.len(),
                ByteEstimationMethod::ShadowExactCodec,
            ),
        })
    }

    /// Returns the public UpdatePath node index.
    pub const fn path_node_index(&self) -> u32 {
        self.path_node_index
    }

    /// Returns the canonical recipient-record count.
    pub const fn recipient_count(&self) -> usize {
        self.recipient_count
    }

    /// Returns codec-bound candidate byte provenance.
    pub const fn provenance(&self) -> SerializedByteProvenance {
        self.provenance
    }
}

/// `B_hat_i(4)`: a shadow candidate byte estimate for one logical operation.
///
/// The total is the disjoint sum of caller-designated unchanged bytes from a
/// real emitted commit and actual canonical hybrid TLS payloads. It is never
/// an emitted MLS message and therefore always remains an estimate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CandidateCommitEstimate {
    unchanged_outer_framing: Vec<UnchangedOuterFraming>,
    hybrid_path_components: Vec<CandidateHybridPathComponent>,
    provenance: SerializedByteProvenance,
}

impl CandidateCommitEstimate {
    /// Builds `B_hat_i(4)` from disjoint real framing ranges and candidate
    /// hybrid payloads serialized through the production TLS codec.
    ///
    /// The caller must supply every unchanged framing field and every replaced
    /// topology-dependent level exactly once. This boundary cannot determine
    /// those fork-specific fields before an experimental MLS serializer exists.
    pub fn shadow_exact_codec(
        unchanged_outer_framing: Vec<UnchangedOuterFraming>,
        hybrid_path_levels: &[HybridPathCiphertext],
    ) -> Result<Self, MeasurementError> {
        if unchanged_outer_framing.is_empty() || hybrid_path_levels.is_empty() {
            return Err(MeasurementError::MissingCandidateComponent);
        }
        validate_disjoint_ranges(&unchanged_outer_framing)?;

        let hybrid_path_components = hybrid_path_levels
            .iter()
            .map(CandidateHybridPathComponent::from_ciphertext)
            .collect::<Result<Vec<_>, _>>()?;
        let byte_count = unchanged_outer_framing
            .iter()
            .map(|component| component.provenance.measured_bytes())
            .chain(
                hybrid_path_components
                    .iter()
                    .map(|component| component.provenance.measured_bytes()),
            )
            .try_fold(0usize, |sum, bytes| {
                sum.checked_add(bytes)
                    .ok_or(MeasurementError::ByteCountOverflow)
            })?;

        Ok(Self {
            unchanged_outer_framing,
            hybrid_path_components,
            provenance: SerializedByteProvenance::candidate_component(
                byte_count,
                ByteEstimationMethod::ShadowExactCodec,
            ),
        })
    }

    /// Returns the retained real framing components.
    pub fn unchanged_outer_framing(&self) -> &[UnchangedOuterFraming] {
        &self.unchanged_outer_framing
    }

    /// Returns each topology-dependent hybrid codec component.
    pub fn hybrid_path_components(&self) -> &[CandidateHybridPathComponent] {
        &self.hybrid_path_components
    }

    /// Returns `B_hat_i(4)` provenance.
    pub const fn provenance(&self) -> SerializedByteProvenance {
        self.provenance
    }
}

fn validate_disjoint_ranges(components: &[UnchangedOuterFraming]) -> Result<(), MeasurementError> {
    let mut ranges = components
        .iter()
        .map(|component| component.range.clone())
        .collect::<Vec<_>>();
    ranges.sort_unstable_by_key(|range| range.start);
    if ranges.windows(2).any(|pair| pair[0].end > pair[1].start) {
        return Err(MeasurementError::OverlappingOuterFramingRanges);
    }
    Ok(())
}

/// Errors at the public measurement boundary.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum MeasurementError {
    /// An emitted MLS Commit must contain at least one serialized byte.
    #[error("the emitted outer MLS commit is empty")]
    EmptyEmittedCommit,
    /// A retained framing range is empty or outside the emitted commit.
    #[error("the unchanged outer framing range is invalid")]
    InvalidOuterFramingRange,
    /// A candidate estimate needs both retained framing and a codec payload.
    #[error("the candidate estimate is missing a required byte component")]
    MissingCandidateComponent,
    /// Retained ranges would count the same current bytes more than once.
    #[error("unchanged outer framing ranges overlap")]
    OverlappingOuterFramingRanges,
    /// Canonical hybrid TLS serialization failed.
    #[error("the canonical hybrid TLS codec failed")]
    HybridCodec,
    /// The aggregate byte count cannot fit in the supported representation.
    #[error("the serialized byte count overflows the supported range")]
    ByteCountOverflow,
    /// A complete-tree topology count cannot fit in the public representation.
    #[error("the complete-tree topology count overflows the supported range")]
    TopologyCountOverflow,
    /// An occupied leaf is outside the complete tree's leaf range.
    #[error("an occupied leaf ordinal is outside the complete tree")]
    OccupiedLeafOutOfRange,
    /// Occupied leaf ordinals must be strictly ascending.
    #[error("occupied leaf ordinals are not in canonical ascending order")]
    NonCanonicalOccupiedLeafOrder,
    /// Recipient-resolution node indexes must be strictly ascending.
    #[error("recipient-resolution node indexes are not in canonical ascending order")]
    NonCanonicalRecipientOrder,
    /// Per-operation crypto metrics must be strictly ordered and unique.
    #[error("crypto-operation metrics are not in canonical ascending order")]
    NonCanonicalCryptoOperationOrder,
    /// Current/candidate byte records have the wrong measurement statuses.
    #[error("current and candidate byte provenance is inconsistent")]
    InvalidCommitByteProvenance,
    /// A Task 33 comparison must be binary current versus quaternary candidate.
    #[error("the topology comparison arities are invalid")]
    InvalidComparisonArity,
    /// Path-level recipient-resolution metrics must be strictly ordered.
    #[error("recipient-resolution metrics are not in canonical path-node order")]
    NonCanonicalResolutionOrder,
}

/// The only complete-tree arities in the thesis comparison.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum TopologyArity {
    /// The unchanged RFC 9420 TreeKEM baseline topology.
    Binary,
    /// The public shadow quaternary candidate topology.
    Quaternary,
}

impl TopologyArity {
    /// Returns the numeric tree arity.
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::Binary => 2,
            Self::Quaternary => 4,
        }
    }

    const fn as_u32(self) -> u32 {
        self.as_u8() as u32
    }
}

/// Public complete-tree topology metrics for one accepted-operation side.
///
/// A populated node is any complete-tree node with at least one occupied leaf
/// in its subtree. A blank node has no occupied descendant. The direct path is
/// counted from a leaf's parent through the root, so it has `height` nodes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TopologyMetrics {
    arity: TopologyArity,
    height: u8,
    leaf_capacity: u32,
    occupied_leaf_count: u32,
    blank_leaf_count: u32,
    populated_node_count: u32,
    blank_node_count: u32,
    direct_path_node_count: u32,
}

impl TopologyMetrics {
    /// Derives complete-tree metrics from canonical ascending occupied leaves.
    pub fn from_complete_tree(
        arity: TopologyArity,
        height: u8,
        occupied_leaf_ordinals: &[u32],
    ) -> Result<Self, MeasurementError> {
        let leaf_capacity = complete_leaf_capacity(arity, height)?;
        if occupied_leaf_ordinals
            .iter()
            .any(|ordinal| *ordinal >= leaf_capacity)
        {
            return Err(MeasurementError::OccupiedLeafOutOfRange);
        }
        if occupied_leaf_ordinals
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        {
            return Err(MeasurementError::NonCanonicalOccupiedLeafOrder);
        }

        let populated_node_count = populated_node_count(arity, height, occupied_leaf_ordinals)?;
        let total_node_count = complete_node_count(arity, height)?;
        let blank_node_count = total_node_count
            .checked_sub(populated_node_count)
            .ok_or(MeasurementError::TopologyCountOverflow)?;
        let occupied_leaf_count = u32::try_from(occupied_leaf_ordinals.len())
            .map_err(|_| MeasurementError::TopologyCountOverflow)?;

        Ok(Self {
            arity,
            height,
            leaf_capacity,
            occupied_leaf_count,
            blank_leaf_count: leaf_capacity - occupied_leaf_count,
            populated_node_count,
            blank_node_count,
            direct_path_node_count: u32::from(height),
        })
    }

    /// Derives candidate topology metrics from the immutable Task 30/31 tree.
    pub fn from_shadow_quaternary(tree: &ShadowQuaternaryTree) -> Result<Self, MeasurementError> {
        Self::from_complete_tree(
            TopologyArity::Quaternary,
            tree.height(),
            &tree.occupied_leaf_ordinals(),
        )
    }

    /// Returns the topology arity.
    pub const fn arity(&self) -> TopologyArity {
        self.arity
    }

    /// Returns the complete-tree height.
    pub const fn height(&self) -> u8 {
        self.height
    }

    /// Returns the number of leaves in the complete tree.
    pub const fn leaf_capacity(&self) -> u32 {
        self.leaf_capacity
    }

    /// Returns the number of occupied leaves.
    pub const fn occupied_leaf_count(&self) -> u32 {
        self.occupied_leaf_count
    }

    /// Returns the number of unoccupied leaves.
    pub const fn blank_leaf_count(&self) -> u32 {
        self.blank_leaf_count
    }

    /// Returns the number of nodes on at least one occupied-leaf route.
    pub const fn populated_node_count(&self) -> u32 {
        self.populated_node_count
    }

    /// Returns the number of complete-tree nodes with no occupied descendant.
    pub const fn blank_node_count(&self) -> u32 {
        self.blank_node_count
    }

    /// Returns the leaf-parent-to-root direct-path node count.
    pub const fn direct_path_node_count(&self) -> u32 {
        self.direct_path_node_count
    }
}

/// One public co-path resolution and its recipient count.
///
/// Empty resolutions are valid observations. Non-empty recipient node indexes
/// must be strictly ascending, matching the canonical hybrid wire ordering.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RecipientResolutionMetrics {
    path_node_index: u32,
    resolution_node_count: u32,
    recipient_count: u32,
}

impl RecipientResolutionMetrics {
    /// Records one canonical public recipient-resolution list.
    pub fn from_recipient_nodes(
        path_node_index: u32,
        recipient_node_indexes: &[u32],
    ) -> Result<Self, MeasurementError> {
        if recipient_node_indexes
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        {
            return Err(MeasurementError::NonCanonicalRecipientOrder);
        }
        let count = u32::try_from(recipient_node_indexes.len())
            .map_err(|_| MeasurementError::TopologyCountOverflow)?;
        Ok(Self {
            path_node_index,
            resolution_node_count: count,
            recipient_count: count,
        })
    }

    /// Returns the public UpdatePath node index.
    pub const fn path_node_index(&self) -> u32 {
        self.path_node_index
    }

    /// Returns the number of public resolution nodes.
    pub const fn resolution_node_count(&self) -> u32 {
        self.resolution_node_count
    }

    /// Returns the number of recipient delivery records required.
    pub const fn recipient_count(&self) -> u32 {
        self.recipient_count
    }
}

/// A cryptographic operation that can be counted and timed without retaining
/// secret inputs, keys, ciphertext contents, or outputs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum CryptoOperation {
    /// Classical HPKE sender-side encapsulation/exporter-secret derivation.
    ClassicalEncapsulation,
    /// Classical HPKE recipient-side decapsulation/exporter-secret derivation.
    ClassicalDecapsulation,
    /// One mKyber multi-recipient encapsulation.
    MkyberEncapsulation,
    /// One mKyber recipient decapsulation.
    MkyberDecapsulation,
    /// One hybrid HKDF extract/expand operation.
    HybridKdf,
    /// One AES-GCM path-secret encryption.
    PathSecretAeadSeal,
    /// One AES-GCM path-secret decryption.
    PathSecretAeadOpen,
}

/// Why a requested crypto metric has no measured value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum MetricUnavailableReason {
    /// The implementation seam has not yet added this measurement hook.
    NotInstrumented,
    /// The active protocol mode does not use this operation.
    NotApplicable,
}

/// An observed crypto-operation count and monotonic elapsed duration.
///
/// A zero invocation count has no timing value. A non-zero operation always
/// carries the duration actually supplied by an instrumentation hook; zero
/// elapsed nanoseconds is preserved if the monotonic clock resolved it that
/// way and is never fabricated by this API.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct ObservedCryptoOperationMetrics {
    operation: CryptoOperation,
    invocation_count: u32,
    elapsed_nanoseconds: Option<u128>,
}

impl ObservedCryptoOperationMetrics {
    /// Records an actually observed aggregate operation count and duration.
    pub fn new(operation: CryptoOperation, invocation_count: u32, elapsed: Duration) -> Self {
        Self {
            operation,
            invocation_count,
            elapsed_nanoseconds: (invocation_count != 0).then_some(elapsed.as_nanos()),
        }
    }

    /// Records that the operation did not occur, with no fabricated timing.
    pub const fn not_performed(operation: CryptoOperation) -> Self {
        Self {
            operation,
            invocation_count: 0,
            elapsed_nanoseconds: None,
        }
    }

    /// Returns the operation kind.
    pub const fn operation(&self) -> CryptoOperation {
        self.operation
    }

    /// Returns the number of invocations observed.
    pub const fn invocation_count(&self) -> u32 {
        self.invocation_count
    }

    /// Returns elapsed nanoseconds, or `None` when no operation occurred.
    pub const fn elapsed_nanoseconds(&self) -> Option<u128> {
        self.elapsed_nanoseconds
    }
}

/// One crypto metric that is observed or explicitly unavailable.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum CryptoOperationMetrics {
    /// A count and monotonic duration were observed.
    Observed(ObservedCryptoOperationMetrics),
    /// No hook or no applicable operation exists in the current mode.
    Unavailable {
        /// The operation that lacks a value.
        operation: CryptoOperation,
        /// The explicit reason no value exists.
        reason: MetricUnavailableReason,
    },
}

impl CryptoOperationMetrics {
    /// Measures exactly one invocation around `operation` using a monotonic clock.
    pub fn measure<T>(operation: CryptoOperation, action: impl FnOnce() -> T) -> (T, Self) {
        let started = Instant::now();
        let result = action();
        let observed = ObservedCryptoOperationMetrics::new(operation, 1, started.elapsed());
        (result, Self::Observed(observed))
    }

    /// Returns the operation kind regardless of availability.
    pub const fn operation(&self) -> CryptoOperation {
        match self {
            Self::Observed(metrics) => metrics.operation(),
            Self::Unavailable { operation, .. } => *operation,
        }
    }
}

/// Canonical set of crypto-operation metrics for one logical operation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CryptoMetrics {
    operations: Vec<CryptoOperationMetrics>,
}

impl CryptoMetrics {
    /// Validates a strictly ascending, duplicate-free operation metric list.
    pub fn new(operations: Vec<CryptoOperationMetrics>) -> Result<Self, MeasurementError> {
        if operations
            .windows(2)
            .any(|pair| pair[0].operation() >= pair[1].operation())
        {
            return Err(MeasurementError::NonCanonicalCryptoOperationOrder);
        }
        Ok(Self { operations })
    }

    /// Returns the canonical per-operation metrics.
    pub fn operations(&self) -> &[CryptoOperationMetrics] {
        &self.operations
    }
}

/// Byte provenance paired for one logical operation without retaining wire data.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct CommitByteMetrics {
    current: SerializedByteProvenance,
    candidate: SerializedByteProvenance,
}

impl CommitByteMetrics {
    /// Extracts byte provenance from Task 32 measurements.
    pub fn new(
        current: &MeasuredCurrentCommit,
        candidate: &CandidateCommitEstimate,
    ) -> Result<Self, MeasurementError> {
        let current_provenance = current.provenance();
        let candidate_provenance = candidate.provenance();
        if current_provenance.estimated_bytes().is_some()
            || candidate_provenance.estimated_bytes().is_none()
        {
            return Err(MeasurementError::InvalidCommitByteProvenance);
        }
        Ok(Self {
            current: current_provenance,
            candidate: candidate_provenance,
        })
    }

    /// Returns measured `B_i(2)` provenance.
    pub const fn current(&self) -> SerializedByteProvenance {
        self.current
    }

    /// Returns estimated `B_hat_i(4)` provenance.
    pub const fn candidate(&self) -> SerializedByteProvenance {
        self.candidate
    }
}

/// Typed public metrics for one logical operation's current/candidate comparison.
///
/// It is not an accepted-commit report: epoch identifiers, impact
/// classification, transition state, and output serialization are deferred to
/// later tasks. No secret-bearing data is accepted or retained.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct LogicalOperationMetrics {
    current_topology: TopologyMetrics,
    candidate_topology: TopologyMetrics,
    recipient_resolutions: Vec<RecipientResolutionMetrics>,
    byte_metrics: CommitByteMetrics,
    crypto_metrics: CryptoMetrics,
}

impl LogicalOperationMetrics {
    /// Combines canonical public topology, recipient, byte, and crypto facts.
    pub fn new(
        current_topology: TopologyMetrics,
        candidate_topology: TopologyMetrics,
        recipient_resolutions: Vec<RecipientResolutionMetrics>,
        byte_metrics: CommitByteMetrics,
        crypto_metrics: CryptoMetrics,
    ) -> Result<Self, MeasurementError> {
        if current_topology.arity() != TopologyArity::Binary
            || candidate_topology.arity() != TopologyArity::Quaternary
        {
            return Err(MeasurementError::InvalidComparisonArity);
        }
        if recipient_resolutions
            .windows(2)
            .any(|pair| pair[0].path_node_index() >= pair[1].path_node_index())
        {
            return Err(MeasurementError::NonCanonicalResolutionOrder);
        }
        Ok(Self {
            current_topology,
            candidate_topology,
            recipient_resolutions,
            byte_metrics,
            crypto_metrics,
        })
    }

    /// Returns the measured binary topology facts.
    pub const fn current_topology(&self) -> &TopologyMetrics {
        &self.current_topology
    }

    /// Returns the shadow quaternary topology facts.
    pub const fn candidate_topology(&self) -> &TopologyMetrics {
        &self.candidate_topology
    }

    /// Returns canonical recipient-resolution metrics per path level.
    pub fn recipient_resolutions(&self) -> &[RecipientResolutionMetrics] {
        &self.recipient_resolutions
    }

    /// Returns current/candidate byte provenance.
    pub const fn byte_metrics(&self) -> &CommitByteMetrics {
        &self.byte_metrics
    }

    /// Returns crypto count/timing metrics.
    pub const fn crypto_metrics(&self) -> &CryptoMetrics {
        &self.crypto_metrics
    }
}

fn complete_leaf_capacity(arity: TopologyArity, height: u8) -> Result<u32, MeasurementError> {
    (0..height).try_fold(1_u32, |capacity, _| {
        capacity
            .checked_mul(arity.as_u32())
            .ok_or(MeasurementError::TopologyCountOverflow)
    })
}

fn complete_node_count(arity: TopologyArity, height: u8) -> Result<u32, MeasurementError> {
    let mut level_nodes = 1_u32;
    let mut total = 1_u32;
    for _ in 0..height {
        level_nodes = level_nodes
            .checked_mul(arity.as_u32())
            .ok_or(MeasurementError::TopologyCountOverflow)?;
        total = total
            .checked_add(level_nodes)
            .ok_or(MeasurementError::TopologyCountOverflow)?;
    }
    Ok(total)
}

fn populated_node_count(
    arity: TopologyArity,
    height: u8,
    occupied_leaf_ordinals: &[u32],
) -> Result<u32, MeasurementError> {
    let mut nodes = Vec::with_capacity(
        occupied_leaf_ordinals
            .len()
            .checked_mul(usize::from(height) + 1)
            .ok_or(MeasurementError::TopologyCountOverflow)?,
    );
    for leaf in occupied_leaf_ordinals {
        let mut ordinal = *leaf;
        for depth_from_leaf in 0..=height {
            nodes.push((height - depth_from_leaf, ordinal));
            ordinal /= arity.as_u32();
        }
    }
    nodes.sort_unstable();
    nodes.dedup();
    u32::try_from(nodes.len()).map_err(|_| MeasurementError::TopologyCountOverflow)
}

#[cfg(test)]
mod tests {
    use super::*;
    use adaptive_tree::{BinaryLeafMember, BinaryToQuaternaryLeafMapping};
    use hybrid_path_secret::{
        HybridRecipientCiphertext, PathNodeIndex, RecipientNodeIndex,
        CLASSICAL_ENCAPSULATION_BYTES, ENCRYPTED_PATH_SECRET_BYTES,
    };
    use mkyber::{
        MkyberCommonCiphertext, MkyberDomain, MkyberRecipientCiphertext, COMMON_CIPHERTEXT_BYTES,
        RECIPIENT_CIPHERTEXT_BYTES,
    };

    const DOMAIN: MkyberDomain = MkyberDomain::new([9; 32]);

    fn ciphertext(recipient_count: u32) -> HybridPathCiphertext {
        let recipients = (0..recipient_count)
            .map(|index| {
                HybridRecipientCiphertext::new(
                    RecipientNodeIndex::new(index + 1),
                    [index as u8; CLASSICAL_ENCAPSULATION_BYTES],
                    MkyberRecipientCiphertext::from_bytes(
                        &[index as u8; RECIPIENT_CIPHERTEXT_BYTES],
                    )
                    .expect("fixed recipient component"),
                    [index as u8; ENCRYPTED_PATH_SECRET_BYTES],
                )
            })
            .collect();
        HybridPathCiphertext::new(
            PathNodeIndex::new(8),
            DOMAIN,
            MkyberCommonCiphertext::from_bytes(&[7; COMMON_CIPHERTEXT_BYTES])
                .expect("fixed common component"),
            recipients,
        )
        .expect("canonical recipients")
    }

    fn shadow_tree() -> ShadowQuaternaryTree {
        let mapping = BinaryToQuaternaryLeafMapping::from_binary_members(vec![
            BinaryLeafMember {
                member_id: b"bob".to_vec(),
                binary_leaf_index: 3,
            },
            BinaryLeafMember {
                member_id: b"alice".to_vec(),
                binary_leaf_index: 0,
            },
        ])
        .expect("canonical mapping");
        ShadowQuaternaryTree::from_mapping(mapping).expect("shadow tree")
    }

    #[test]
    fn emitted_current_bytes_are_measured_not_estimated() {
        let current = MeasuredCurrentCommit::from_emitted_outer_commit(vec![1; 120])
            .expect("non-empty commit");
        assert_eq!(current.provenance().measured_bytes(), 120);
        assert_eq!(current.provenance().estimated_bytes(), None);
        assert_eq!(
            current.provenance().estimation_method(),
            ByteEstimationMethod::EmittedOuterMlsCommit
        );
    }

    #[test]
    fn candidate_bytes_are_a_disjoint_codec_bound_estimate() {
        let current = MeasuredCurrentCommit::from_emitted_outer_commit(vec![1; 120])
            .expect("non-empty commit");
        let level = ciphertext(2);
        let canonical_payload_bytes = level
            .commit_authenticated_bytes()
            .expect("hybrid TLS codec")
            .len();
        let candidate = CandidateCommitEstimate::shadow_exact_codec(
            vec![
                current.unchanged_outer_framing(0..12).expect("first range"),
                current
                    .unchanged_outer_framing(30..40)
                    .expect("second range"),
            ],
            &[level],
        )
        .expect("candidate estimate");

        assert_eq!(
            candidate.provenance().measured_bytes(),
            22 + canonical_payload_bytes
        );
        assert_eq!(
            candidate.provenance().estimated_bytes(),
            Some(22 + canonical_payload_bytes)
        );
        assert_eq!(
            candidate.provenance().estimation_method(),
            ByteEstimationMethod::ShadowExactCodec
        );
        assert_eq!(candidate.hybrid_path_components()[0].recipient_count(), 2);
        assert_eq!(
            candidate.hybrid_path_components()[0]
                .provenance()
                .measured_bytes(),
            canonical_payload_bytes
        );
    }

    #[test]
    fn overlapping_retained_current_ranges_are_rejected() {
        let current = MeasuredCurrentCommit::from_emitted_outer_commit(vec![1; 80])
            .expect("non-empty commit");
        assert_eq!(
            CandidateCommitEstimate::shadow_exact_codec(
                vec![
                    current.unchanged_outer_framing(0..20).expect("first range"),
                    current
                        .unchanged_outer_framing(10..30)
                        .expect("second range"),
                ],
                &[ciphertext(1)],
            ),
            Err(MeasurementError::OverlappingOuterFramingRanges)
        );
    }

    #[test]
    fn candidate_requires_real_framing_and_a_codec_payload() {
        assert_eq!(
            CandidateCommitEstimate::shadow_exact_codec(vec![], &[ciphertext(1)]),
            Err(MeasurementError::MissingCandidateComponent)
        );
    }

    #[test]
    fn topology_metrics_count_populated_and_blank_nodes_from_public_leaves() {
        let binary = TopologyMetrics::from_complete_tree(TopologyArity::Binary, 2, &[0, 3])
            .expect("canonical binary leaves");
        let candidate = TopologyMetrics::from_shadow_quaternary(&shadow_tree())
            .expect("shadow topology metrics");

        assert_eq!(binary.leaf_capacity(), 4);
        assert_eq!(binary.occupied_leaf_count(), 2);
        assert_eq!(binary.blank_leaf_count(), 2);
        assert_eq!(binary.populated_node_count(), 5);
        assert_eq!(binary.blank_node_count(), 2);
        assert_eq!(binary.direct_path_node_count(), 2);
        assert_eq!(candidate.arity(), TopologyArity::Quaternary);
        assert_eq!(candidate.height(), 1);
        assert_eq!(candidate.populated_node_count(), 3);
        assert_eq!(candidate.blank_node_count(), 2);
    }

    #[test]
    fn topology_and_recipient_inputs_must_be_canonical() {
        assert_eq!(
            TopologyMetrics::from_complete_tree(TopologyArity::Binary, 1, &[1, 0]),
            Err(MeasurementError::NonCanonicalOccupiedLeafOrder)
        );
        assert_eq!(
            RecipientResolutionMetrics::from_recipient_nodes(7, &[9, 4]),
            Err(MeasurementError::NonCanonicalRecipientOrder)
        );
    }

    #[test]
    fn crypto_metrics_preserve_unavailable_and_no_operation_timing_states() {
        let (value, measured) = CryptoOperationMetrics::measure(CryptoOperation::HybridKdf, || 42);
        let absent =
            ObservedCryptoOperationMetrics::not_performed(CryptoOperation::MkyberDecapsulation);
        assert_eq!(value, 42);
        assert_eq!(measured.operation(), CryptoOperation::HybridKdf);
        assert_eq!(
            match measured {
                CryptoOperationMetrics::Observed(observed) => observed.invocation_count(),
                CryptoOperationMetrics::Unavailable { .. } => 0,
            },
            1
        );
        assert_eq!(absent.elapsed_nanoseconds(), None);
        assert_eq!(absent.invocation_count(), 0);

        let unavailable = CryptoOperationMetrics::Unavailable {
            operation: CryptoOperation::PathSecretAeadSeal,
            reason: MetricUnavailableReason::NotInstrumented,
        };
        let metrics =
            CryptoMetrics::new(vec![measured, unavailable]).expect("canonical operation order");
        assert_eq!(metrics.operations().len(), 2);
    }

    #[test]
    fn logical_operation_record_keeps_all_public_metric_families_typed() {
        let current =
            MeasuredCurrentCommit::from_emitted_outer_commit(vec![1; 120]).expect("emitted commit");
        let candidate = CandidateCommitEstimate::shadow_exact_codec(
            vec![current.unchanged_outer_framing(0..20).expect("framing")],
            &[ciphertext(2)],
        )
        .expect("candidate estimate");
        let byte_metrics = CommitByteMetrics::new(&current, &candidate).expect("byte provenance");
        let crypto_metrics = CryptoMetrics::new(vec![CryptoOperationMetrics::Unavailable {
            operation: CryptoOperation::ClassicalEncapsulation,
            reason: MetricUnavailableReason::NotInstrumented,
        }])
        .expect("canonical crypto metric");
        let record = LogicalOperationMetrics::new(
            TopologyMetrics::from_complete_tree(TopologyArity::Binary, 2, &[0, 3])
                .expect("binary topology"),
            TopologyMetrics::from_shadow_quaternary(&shadow_tree()).expect("candidate topology"),
            vec![
                RecipientResolutionMetrics::from_recipient_nodes(3, &[4, 9])
                    .expect("first resolution"),
                RecipientResolutionMetrics::from_recipient_nodes(8, &[]).expect("empty resolution"),
            ],
            byte_metrics,
            crypto_metrics,
        )
        .expect("typed logical operation record");

        assert_eq!(record.current_topology().direct_path_node_count(), 2);
        assert_eq!(record.candidate_topology().direct_path_node_count(), 1);
        assert_eq!(record.recipient_resolutions()[0].recipient_count(), 2);
        assert_eq!(record.recipient_resolutions()[1].resolution_node_count(), 0);
        assert_eq!(record.byte_metrics().current().estimated_bytes(), None);
        assert!(record
            .byte_metrics()
            .candidate()
            .estimated_bytes()
            .is_some());
    }
}
