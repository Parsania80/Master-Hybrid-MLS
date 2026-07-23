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

/// One canonical recipient target set `S` for a transition-end cost comparison.
///
/// The set is public, strictly ascending by recipient-node index, and may be
/// empty. Empty sets are recorded because ADR 0006 excludes them from later
/// maturity aggregation rather than silently discarding them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RecipientTargetSet {
    recipient_node_indexes: Vec<u32>,
}

impl RecipientTargetSet {
    /// Creates a canonical public recipient target set.
    pub fn new(recipient_node_indexes: Vec<u32>) -> Result<Self, MeasurementError> {
        if recipient_node_indexes
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        {
            return Err(MeasurementError::NonCanonicalTargetSet);
        }
        Ok(Self {
            recipient_node_indexes,
        })
    }

    /// Returns the target recipients in canonical ascending order.
    pub fn recipient_node_indexes(&self) -> &[u32] {
        &self.recipient_node_indexes
    }

    /// Returns whether this is an empty target set excluded from maturity aggregation.
    pub const fn is_empty(&self) -> bool {
        self.recipient_node_indexes.is_empty()
    }
}

/// The delivery construction whose exact canonical ciphertext bytes are counted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum CounterfactualDeliveryKind {
    /// One independently serialized delivery for every target leaf.
    Leaf,
    /// Delivery through currently populated new-quaternary routing targets.
    New,
    /// Delivery through eligible frozen binary TreeCover routing targets.
    Old,
    /// Delivery through a fully mature quaternary routing topology.
    Ideal,
}

/// Why a counterfactual route has no byte cost for a non-empty target set.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum DeliveryCostUnavailableReason {
    /// The empty target set is intentionally excluded from maturity aggregation.
    EmptyTargetSet,
    /// The old TreeCover has no eligible route for this target set.
    NoEligibleOldTreeCoverRoute,
    /// The requested routing construction has not been materialized by the caller.
    RouteNotMaterialized,
}

/// Caller input for one counterfactual route.
///
/// Available routes must use actual `HybridPathCiphertext` values. The metric
/// retains only their public canonical byte counts, never ciphertext bytes.
#[derive(Clone, Copy, Debug)]
pub enum CounterfactualDeliveryInput<'a> {
    /// One or more canonical serialized delivery targets.
    Serialized(&'a [HybridPathCiphertext]),
    /// An explicit absence rather than a fabricated byte value.
    Unavailable(DeliveryCostUnavailableReason),
}

/// Exact component bytes for one counterfactual delivery construction.
///
/// These bytes are measured from the canonical hybrid TLS serializer, but are
/// not an observed full MLS Commit. Their provenance is consequently
/// `ShadowExactCodec` rather than an emitted outer-MLS value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct SerializedDeliveryCost {
    kind: CounterfactualDeliveryKind,
    delivery_target_count: u32,
    recipient_count: u32,
    provenance: SerializedByteProvenance,
}

impl SerializedDeliveryCost {
    /// Returns the delivery construction this cost represents.
    pub const fn kind(&self) -> CounterfactualDeliveryKind {
        self.kind
    }

    /// Returns the number of individually serialized routing targets counted.
    pub const fn delivery_target_count(&self) -> u32 {
        self.delivery_target_count
    }

    /// Returns the number of distinct target recipients covered exactly once.
    pub const fn recipient_count(&self) -> u32 {
        self.recipient_count
    }

    /// Returns exact serializer-byte provenance.
    pub const fn provenance(&self) -> SerializedByteProvenance {
        self.provenance
    }
}

/// A counterfactual cost that was measured or explicitly unavailable.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum DeliveryCostAvailability {
    /// Exact canonical hybrid TLS bytes were counted.
    Measured(SerializedDeliveryCost),
    /// No valid byte value exists for this construction and target set.
    Unavailable(DeliveryCostUnavailableReason),
}

/// The four Task 46 costs for one target set and one logical payload binding.
///
/// `logical_payload_binding` is a public, caller-supplied identifier for the
/// same logical payload across all four counterfactual constructions. This
/// crate cannot infer equality of encrypted plaintexts from ciphertext bytes;
/// a future fork must bind the identifier to its authenticated transition
/// input. It must not contain secret material.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RecipientTargetSetCostMeasurement {
    target_set: RecipientTargetSet,
    logical_payload_binding: [u8; 32],
    leaf: DeliveryCostAvailability,
    new: DeliveryCostAvailability,
    old: DeliveryCostAvailability,
    ideal: DeliveryCostAvailability,
}

impl RecipientTargetSetCostMeasurement {
    /// Measures `C_leaf`, `C_new`, `C_old`, and `C_ideal` for one target set.
    ///
    /// Each available input must cover exactly the supplied target recipients.
    /// `Leaf` additionally requires one single-recipient ciphertext per
    /// target. No unavailable route is converted into a byte count.
    pub fn measure(
        target_set: RecipientTargetSet,
        logical_payload_binding: [u8; 32],
        leaf: CounterfactualDeliveryInput<'_>,
        new: CounterfactualDeliveryInput<'_>,
        old: CounterfactualDeliveryInput<'_>,
        ideal: CounterfactualDeliveryInput<'_>,
    ) -> Result<Self, MeasurementError> {
        let leaf =
            measure_counterfactual_route(&target_set, CounterfactualDeliveryKind::Leaf, leaf)?;
        let new = measure_counterfactual_route(&target_set, CounterfactualDeliveryKind::New, new)?;
        let old = measure_counterfactual_route(&target_set, CounterfactualDeliveryKind::Old, old)?;
        let ideal =
            measure_counterfactual_route(&target_set, CounterfactualDeliveryKind::Ideal, ideal)?;
        Ok(Self {
            target_set,
            logical_payload_binding,
            leaf,
            new,
            old,
            ideal,
        })
    }

    /// Returns the public recipient set `S` for these four values.
    pub const fn target_set(&self) -> &RecipientTargetSet {
        &self.target_set
    }

    /// Returns the caller-supplied public same-logical-payload binding.
    pub const fn logical_payload_binding(&self) -> &[u8; 32] {
        &self.logical_payload_binding
    }

    /// Returns `C_leaf(S)`.
    pub const fn c_leaf(&self) -> DeliveryCostAvailability {
        self.leaf
    }

    /// Returns `C_new(S)`.
    pub const fn c_new(&self) -> DeliveryCostAvailability {
        self.new
    }

    /// Returns `C_old(S)`.
    pub const fn c_old(&self) -> DeliveryCostAvailability {
        self.old
    }

    /// Returns `C_ideal(S)`.
    pub const fn c_ideal(&self) -> DeliveryCostAvailability {
        self.ideal
    }
}

/// An exact signed rational value with a positive normalized denominator.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct SignedRational {
    numerator: i128,
    denominator: i128,
}

impl SignedRational {
    fn new(numerator: i128, denominator: i128) -> Result<Self, MeasurementError> {
        if denominator <= 0 {
            return Err(MeasurementError::InvalidMaturityDenominator);
        }
        let divisor = greatest_common_divisor(numerator.unsigned_abs(), denominator as u128);
        let divisor = i128::try_from(divisor).map_err(|_| MeasurementError::MaturityOverflow)?;
        Ok(Self {
            numerator: numerator
                .checked_div(divisor)
                .ok_or(MeasurementError::MaturityOverflow)?,
            denominator: denominator
                .checked_div(divisor)
                .ok_or(MeasurementError::MaturityOverflow)?,
        })
    }

    const fn zero() -> Self {
        Self {
            numerator: 0,
            denominator: 1,
        }
    }

    const fn one() -> Self {
        Self {
            numerator: 1,
            denominator: 1,
        }
    }

    /// Returns the exact signed numerator.
    pub const fn numerator(&self) -> i128 {
        self.numerator
    }

    /// Returns the positive exact denominator.
    pub const fn denominator(&self) -> i128 {
        self.denominator
    }

    fn checked_cmp(&self, other: &Self) -> Result<std::cmp::Ordering, MeasurementError> {
        let left = self
            .numerator
            .checked_mul(other.denominator)
            .ok_or(MeasurementError::MaturityOverflow)?;
        let right = other
            .numerator
            .checked_mul(self.denominator)
            .ok_or(MeasurementError::MaturityOverflow)?;
        Ok(left.cmp(&right))
    }
}

/// Why a raw maturity ratio was or was not clamped to the unit interval.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum MaturityClampReason {
    /// The raw ratio was already in the inclusive interval `[0, 1]`.
    InRange,
    /// The raw ratio was negative and was clamped to zero.
    BelowZero,
    /// The raw ratio exceeded one and was clamped to one.
    AboveOne,
}

/// One exact raw maturity ratio and the clamped ratio used by later thresholds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct MaturityScore {
    raw: SignedRational,
    clamped: SignedRational,
    clamp_reason: MaturityClampReason,
}

impl MaturityScore {
    fn from_raw(raw: SignedRational) -> Self {
        if raw.numerator < 0 {
            Self {
                raw,
                clamped: SignedRational::zero(),
                clamp_reason: MaturityClampReason::BelowZero,
            }
        } else if raw.numerator > raw.denominator {
            Self {
                raw,
                clamped: SignedRational::one(),
                clamp_reason: MaturityClampReason::AboveOne,
            }
        } else {
            Self {
                raw,
                clamped: raw,
                clamp_reason: MaturityClampReason::InRange,
            }
        }
    }

    /// Returns the exact unbounded formula result.
    pub const fn raw(&self) -> SignedRational {
        self.raw
    }

    /// Returns the exact result after clamping to `[0, 1]`.
    pub const fn clamped(&self) -> SignedRational {
        self.clamped
    }

    /// Returns why the threshold value was or was not clamped.
    pub const fn clamp_reason(&self) -> MaturityClampReason {
        self.clamp_reason
    }
}

/// Why one non-empty target set has no usable maturity ratio.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum MaturityUndefinedReason {
    /// A formula input was explicitly unavailable rather than numerically measured.
    UnavailableCost {
        /// The missing delivery construction.
        kind: CounterfactualDeliveryKind,
        /// Why no byte cost exists.
        reason: DeliveryCostUnavailableReason,
    },
    /// `C_leaf - C_ideal` was zero or negative, so the ratio is undefined.
    NonPositiveDenominator {
        /// Exact `C_leaf` bytes.
        c_leaf_bytes: usize,
        /// Exact `C_ideal` bytes.
        c_ideal_bytes: usize,
    },
}

/// A per-target result for one maturity formula.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum TargetSetMaturityScore {
    /// The target set had a valid exact raw and clamped ratio.
    Defined(MaturityScore),
    /// The non-empty target set cannot contribute a maturity ratio.
    Undefined(MaturityUndefinedReason),
}

/// Maturity facts for one target set, or a recorded empty-set exclusion.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub enum TargetSetMaturity {
    /// An empty target set is recorded and excluded from aggregation.
    ExcludedEmpty {
        /// The empty target set.
        target_set: RecipientTargetSet,
    },
    /// Both formula results for one non-empty target set.
    Evaluated {
        /// The non-empty target set.
        target_set: RecipientTargetSet,
        /// `h_new_raw(S)` and its clamped threshold value.
        h_new: TargetSetMaturityScore,
        /// `h_old_raw(S)` and its clamped threshold value.
        h_old: TargetSetMaturityScore,
    },
}

impl TargetSetMaturity {
    /// Returns the recorded public target set.
    pub const fn target_set(&self) -> &RecipientTargetSet {
        match self {
            Self::ExcludedEmpty { target_set } | Self::Evaluated { target_set, .. } => target_set,
        }
    }
}

/// Why a global conservative maturity value is unavailable.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum GlobalMaturityUndefinedReason {
    /// No non-empty target set was supplied.
    NoNonEmptyTargetSets,
    /// At least one non-empty target set had no value for this formula.
    UndefinedNonEmptyTargetSet,
}

/// A conservative global maturity result and the target-set record that selected it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum GlobalMaturityCost {
    /// A conservative clamped value was selected from all non-empty target sets.
    Defined {
        /// Index in `MaturityCostEvaluation::target_sets` that selected this value.
        target_set_index: usize,
        /// Exact raw/clamped score for that target set.
        score: MaturityScore,
    },
    /// No safe aggregate value exists.
    Undefined(GlobalMaturityUndefinedReason),
}

/// Checked per-target and global `h_new_cost`/`h_old_cost` maturity facts.
///
/// `h_new_cost` is the minimum clamped new-tree score over all non-empty
/// target sets. `h_old_cost` is the maximum clamped old-TreeCover score. Empty
/// sets remain visible but do not participate. Later retirement logic must
/// treat any undefined non-empty target set as a blocker.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct MaturityCostEvaluation {
    target_sets: Vec<TargetSetMaturity>,
    h_new_cost: GlobalMaturityCost,
    h_old_cost: GlobalMaturityCost,
    has_undefined_nonempty_target_set: bool,
}

impl MaturityCostEvaluation {
    /// Evaluates checked raw and clamped maturity facts for canonical target-set costs.
    pub fn from_costs(
        measurements: Vec<RecipientTargetSetCostMeasurement>,
    ) -> Result<Self, MeasurementError> {
        validate_maturity_measurement_order(&measurements)?;
        let mut target_sets = Vec::with_capacity(measurements.len());
        let mut h_new_candidates = Vec::new();
        let mut h_old_candidates = Vec::new();
        let mut has_nonempty_target_set = false;
        let mut has_undefined_nonempty_target_set = false;

        for measurement in measurements {
            if measurement.target_set().is_empty() {
                target_sets.push(TargetSetMaturity::ExcludedEmpty {
                    target_set: measurement.target_set,
                });
                continue;
            }
            has_nonempty_target_set = true;
            let h_new = calculate_maturity_score(
                measurement.c_leaf(),
                measurement.c_new(),
                measurement.c_ideal(),
                CounterfactualDeliveryKind::New,
            )?;
            let h_old = calculate_maturity_score(
                measurement.c_leaf(),
                measurement.c_old(),
                measurement.c_ideal(),
                CounterfactualDeliveryKind::Old,
            )?;
            if matches!(h_new, TargetSetMaturityScore::Undefined(_))
                || matches!(h_old, TargetSetMaturityScore::Undefined(_))
            {
                has_undefined_nonempty_target_set = true;
            }
            let index = target_sets.len();
            if let TargetSetMaturityScore::Defined(score) = h_new {
                h_new_candidates.push((index, score));
            }
            if let TargetSetMaturityScore::Defined(score) = h_old {
                h_old_candidates.push((index, score));
            }
            target_sets.push(TargetSetMaturity::Evaluated {
                target_set: measurement.target_set,
                h_new,
                h_old,
            });
        }

        let h_new_cost = aggregate_maturity(&h_new_candidates, has_nonempty_target_set, true)?;
        let h_old_cost = aggregate_maturity(&h_old_candidates, has_nonempty_target_set, false)?;
        Ok(Self {
            target_sets,
            h_new_cost,
            h_old_cost,
            has_undefined_nonempty_target_set,
        })
    }

    /// Returns every target-set result, including empty-set exclusions.
    pub fn target_sets(&self) -> &[TargetSetMaturity] {
        &self.target_sets
    }

    /// Returns the conservative minimum `h_new_cost` result.
    pub const fn h_new_cost(&self) -> GlobalMaturityCost {
        self.h_new_cost
    }

    /// Returns the conservative maximum `h_old_cost` result.
    pub const fn h_old_cost(&self) -> GlobalMaturityCost {
        self.h_old_cost
    }

    /// Returns whether any non-empty target set was undefined for either formula.
    pub const fn has_undefined_nonempty_target_set(&self) -> bool {
        self.has_undefined_nonempty_target_set
    }
}

/// Fixed-point scale for a threshold in the inclusive unit interval.
pub const MATURITY_THRESHOLD_SCALE: u32 = 1_000_000;

/// One exact fixed-point retirement threshold in `[0, 1]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct MaturityThreshold {
    micro_units: u32,
}

impl MaturityThreshold {
    /// Creates a threshold where `1_000_000` represents exactly one.
    pub fn new(micro_units: u32) -> Result<Self, MeasurementError> {
        if micro_units > MATURITY_THRESHOLD_SCALE {
            return Err(MeasurementError::MaturityThresholdOutOfRange);
        }
        Ok(Self { micro_units })
    }

    /// Returns the exact fixed-point unit-interval value.
    pub const fn micro_units(&self) -> u32 {
        self.micro_units
    }

    fn compare_score(&self, score: MaturityScore) -> Result<std::cmp::Ordering, MeasurementError> {
        let clamped = score.clamped();
        let left = clamped
            .numerator()
            .checked_mul(i128::from(MATURITY_THRESHOLD_SCALE))
            .ok_or(MeasurementError::MaturityOverflow)?;
        let right = i128::from(self.micro_units)
            .checked_mul(clamped.denominator())
            .ok_or(MeasurementError::MaturityOverflow)?;
        Ok(left.cmp(&right))
    }
}

/// The two fixed-point thresholds in the thesis retirement rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct TreeCoverRetirementThresholds {
    theta_new: MaturityThreshold,
    theta_old: MaturityThreshold,
}

impl TreeCoverRetirementThresholds {
    /// Creates explicit thresholds for the new-tree and old-TreeCover conditions.
    pub const fn new(theta_new: MaturityThreshold, theta_old: MaturityThreshold) -> Self {
        Self {
            theta_new,
            theta_old,
        }
    }

    /// Returns the default `theta_new = 0.70` and `theta_old = 0.50` values.
    pub fn thesis_defaults() -> Self {
        Self {
            theta_new: MaturityThreshold {
                micro_units: 700_000,
            },
            theta_old: MaturityThreshold {
                micro_units: 500_000,
            },
        }
    }

    /// Returns `theta_new` for the inclusive `h_new_cost >= theta_new` condition.
    pub const fn theta_new(&self) -> MaturityThreshold {
        self.theta_new
    }

    /// Returns `theta_old` for the strict `h_old_cost < theta_old` condition.
    pub const fn theta_old(&self) -> MaturityThreshold {
        self.theta_old
    }
}

/// Which side or sides of the exact OR retirement rule were true.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct TreeCoverRetirementTriggers {
    new_tree_maturity: bool,
    old_treecover_cost: bool,
}

impl TreeCoverRetirementTriggers {
    /// Constructs an authorized trigger set when at least one side of the OR rule held.
    ///
    /// This is primarily useful to consumers that deserialize or otherwise
    /// receive a previously evaluated decision. New protocol decisions should
    /// normally come from [`evaluate_treecover_retirement`].
    pub const fn new(new_tree_maturity: bool, old_treecover_cost: bool) -> Option<Self> {
        if new_tree_maturity || old_treecover_cost {
            Some(Self {
                new_tree_maturity,
                old_treecover_cost,
            })
        } else {
            None
        }
    }

    /// Returns whether `h_new_cost >= theta_new` was true.
    pub const fn new_tree_maturity(&self) -> bool {
        self.new_tree_maturity
    }

    /// Returns whether `h_old_cost < theta_old` was true.
    pub const fn old_treecover_cost(&self) -> bool {
        self.old_treecover_cost
    }
}

/// Why Task 48 did not authorize a future TreeCover retirement.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum TreeCoverRetirementBlocker {
    /// A non-empty target set had unavailable or invalid maturity input.
    UndefinedNonEmptyTargetSet,
    /// One global maturity aggregate was unavailable even though no target-specific blocker was retained.
    UndefinedGlobalMaturity,
    /// Both defined conditions were false; the OR rule did not trigger.
    ThresholdsNotMet,
}

/// Typed result of evaluating the Task 48 OR rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum TreeCoverRetirementDecision {
    /// A future Task 49 transition may consider retiring the old TreeCover.
    Retire(TreeCoverRetirementTriggers),
    /// Retirement is not authorized at this measurement boundary.
    Keep(TreeCoverRetirementBlocker),
}

impl TreeCoverRetirementDecision {
    /// Constructs an authorized retirement decision only when an OR trigger is present.
    ///
    /// Callers evaluating new data should use [`evaluate_treecover_retirement`]
    /// so undefined inputs remain visible as blockers.
    pub const fn retire(new_tree_maturity: bool, old_treecover_cost: bool) -> Option<Self> {
        match TreeCoverRetirementTriggers::new(new_tree_maturity, old_treecover_cost) {
            Some(triggers) => Some(Self::Retire(triggers)),
            None => None,
        }
    }
}

/// Exact retirement-threshold facts without any state mutation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct TreeCoverRetirementEvaluation {
    thresholds: TreeCoverRetirementThresholds,
    new_tree_condition: Option<bool>,
    old_treecover_condition: Option<bool>,
    decision: TreeCoverRetirementDecision,
}

impl TreeCoverRetirementEvaluation {
    /// Returns the exact thresholds used by this evaluation.
    pub const fn thresholds(&self) -> TreeCoverRetirementThresholds {
        self.thresholds
    }

    /// Returns `Some(h_new_cost >= theta_new)` when `h_new_cost` was defined.
    pub const fn new_tree_condition(&self) -> Option<bool> {
        self.new_tree_condition
    }

    /// Returns `Some(h_old_cost < theta_old)` when `h_old_cost` was defined.
    pub const fn old_treecover_condition(&self) -> Option<bool> {
        self.old_treecover_condition
    }

    /// Returns the non-mutating retirement decision.
    pub const fn decision(&self) -> TreeCoverRetirementDecision {
        self.decision
    }
}

/// Evaluates `h_new_cost >= theta_new OR h_old_cost < theta_old` exactly.
///
/// Any undefined non-empty target set blocks the rule before either threshold
/// can authorize retirement. This function neither changes TreeCover state nor
/// emits a protocol message; Task 49 owns authenticated retirement.
pub fn evaluate_treecover_retirement(
    maturity: &MaturityCostEvaluation,
    thresholds: TreeCoverRetirementThresholds,
) -> Result<TreeCoverRetirementEvaluation, MeasurementError> {
    if maturity.has_undefined_nonempty_target_set() {
        return Ok(TreeCoverRetirementEvaluation {
            thresholds,
            new_tree_condition: None,
            old_treecover_condition: None,
            decision: TreeCoverRetirementDecision::Keep(
                TreeCoverRetirementBlocker::UndefinedNonEmptyTargetSet,
            ),
        });
    }
    let GlobalMaturityCost::Defined {
        score: new_score, ..
    } = maturity.h_new_cost()
    else {
        return Ok(TreeCoverRetirementEvaluation {
            thresholds,
            new_tree_condition: None,
            old_treecover_condition: None,
            decision: TreeCoverRetirementDecision::Keep(
                TreeCoverRetirementBlocker::UndefinedGlobalMaturity,
            ),
        });
    };
    let GlobalMaturityCost::Defined {
        score: old_score, ..
    } = maturity.h_old_cost()
    else {
        return Ok(TreeCoverRetirementEvaluation {
            thresholds,
            new_tree_condition: None,
            old_treecover_condition: None,
            decision: TreeCoverRetirementDecision::Keep(
                TreeCoverRetirementBlocker::UndefinedGlobalMaturity,
            ),
        });
    };
    let new_tree_condition = !thresholds.theta_new().compare_score(new_score)?.is_lt();
    let old_treecover_condition = thresholds.theta_old().compare_score(old_score)?.is_lt();
    let decision = if new_tree_condition || old_treecover_condition {
        TreeCoverRetirementDecision::Retire(TreeCoverRetirementTriggers {
            new_tree_maturity: new_tree_condition,
            old_treecover_cost: old_treecover_condition,
        })
    } else {
        TreeCoverRetirementDecision::Keep(TreeCoverRetirementBlocker::ThresholdsNotMet)
    };
    Ok(TreeCoverRetirementEvaluation {
        thresholds,
        new_tree_condition: Some(new_tree_condition),
        old_treecover_condition: Some(old_treecover_condition),
        decision,
    })
}

fn calculate_maturity_score(
    leaf: DeliveryCostAvailability,
    route: DeliveryCostAvailability,
    ideal: DeliveryCostAvailability,
    route_kind: CounterfactualDeliveryKind,
) -> Result<TargetSetMaturityScore, MeasurementError> {
    let c_leaf = measured_cost_bytes(leaf, CounterfactualDeliveryKind::Leaf)?;
    let c_route = measured_cost_bytes(route, route_kind)?;
    let c_ideal = measured_cost_bytes(ideal, CounterfactualDeliveryKind::Ideal)?;
    let (c_leaf, c_route, c_ideal) = match (c_leaf, c_route, c_ideal) {
        (Ok(leaf), Ok(route), Ok(ideal)) => (leaf, route, ideal),
        (Err(reason), _, _) | (_, Err(reason), _) | (_, _, Err(reason)) => {
            return Ok(TargetSetMaturityScore::Undefined(reason));
        }
    };
    if c_leaf <= c_ideal {
        return Ok(TargetSetMaturityScore::Undefined(
            MaturityUndefinedReason::NonPositiveDenominator {
                c_leaf_bytes: c_leaf,
                c_ideal_bytes: c_ideal,
            },
        ));
    }
    let leaf = i128::try_from(c_leaf).map_err(|_| MeasurementError::MaturityOverflow)?;
    let route = i128::try_from(c_route).map_err(|_| MeasurementError::MaturityOverflow)?;
    let ideal = i128::try_from(c_ideal).map_err(|_| MeasurementError::MaturityOverflow)?;
    let numerator = leaf
        .checked_sub(route)
        .ok_or(MeasurementError::MaturityOverflow)?;
    let denominator = leaf
        .checked_sub(ideal)
        .ok_or(MeasurementError::MaturityOverflow)?;
    Ok(TargetSetMaturityScore::Defined(MaturityScore::from_raw(
        SignedRational::new(numerator, denominator)?,
    )))
}

fn measured_cost_bytes(
    availability: DeliveryCostAvailability,
    kind: CounterfactualDeliveryKind,
) -> Result<Result<usize, MaturityUndefinedReason>, MeasurementError> {
    match availability {
        DeliveryCostAvailability::Measured(cost) => Ok(Ok(cost.provenance().measured_bytes())),
        DeliveryCostAvailability::Unavailable(reason) => {
            Ok(Err(MaturityUndefinedReason::UnavailableCost {
                kind,
                reason,
            }))
        }
    }
}

fn aggregate_maturity(
    candidates: &[(usize, MaturityScore)],
    has_nonempty_target_set: bool,
    select_minimum: bool,
) -> Result<GlobalMaturityCost, MeasurementError> {
    if !has_nonempty_target_set {
        return Ok(GlobalMaturityCost::Undefined(
            GlobalMaturityUndefinedReason::NoNonEmptyTargetSets,
        ));
    }
    let Some(&(mut selected_index, mut selected_score)) = candidates.first() else {
        return Ok(GlobalMaturityCost::Undefined(
            GlobalMaturityUndefinedReason::UndefinedNonEmptyTargetSet,
        ));
    };
    for &(index, score) in &candidates[1..] {
        let ordering = score.clamped().checked_cmp(&selected_score.clamped())?;
        if (select_minimum && ordering.is_lt()) || (!select_minimum && ordering.is_gt()) {
            selected_index = index;
            selected_score = score;
        }
    }
    Ok(GlobalMaturityCost::Defined {
        target_set_index: selected_index,
        score: selected_score,
    })
}

fn validate_maturity_measurement_order(
    measurements: &[RecipientTargetSetCostMeasurement],
) -> Result<(), MeasurementError> {
    if measurements.windows(2).any(|pair| {
        pair[0].target_set().recipient_node_indexes()
            >= pair[1].target_set().recipient_node_indexes()
    }) {
        return Err(MeasurementError::NonCanonicalMaturityTargetSetOrder);
    }
    Ok(())
}

fn greatest_common_divisor(mut left: u128, mut right: u128) -> u128 {
    while right != 0 {
        let remainder = left % right;
        left = right;
        right = remainder;
    }
    left
}

fn measure_counterfactual_route(
    target_set: &RecipientTargetSet,
    kind: CounterfactualDeliveryKind,
    input: CounterfactualDeliveryInput<'_>,
) -> Result<DeliveryCostAvailability, MeasurementError> {
    match input {
        CounterfactualDeliveryInput::Unavailable(reason) => {
            if target_set.is_empty() && reason != DeliveryCostUnavailableReason::EmptyTargetSet {
                return Err(MeasurementError::EmptyTargetSetWrongUnavailableReason);
            }
            Ok(DeliveryCostAvailability::Unavailable(reason))
        }
        CounterfactualDeliveryInput::Serialized(ciphertexts) => {
            if target_set.is_empty() {
                return Err(MeasurementError::EmptyTargetSetHasSerializedCost);
            }
            if ciphertexts.is_empty() {
                return Err(MeasurementError::EmptyCounterfactualRoute);
            }
            if kind == CounterfactualDeliveryKind::Leaf
                && (ciphertexts.len() != target_set.recipient_node_indexes().len()
                    || ciphertexts
                        .iter()
                        .any(|ciphertext| ciphertext.recipients().len() != 1))
            {
                return Err(MeasurementError::LeafDeliveryIsNotIndependent);
            }

            let mut recipient_nodes = Vec::new();
            let mut byte_count = 0usize;
            for ciphertext in ciphertexts {
                let bytes = ciphertext
                    .commit_authenticated_bytes()
                    .map_err(|_| MeasurementError::HybridCodec)?;
                byte_count = byte_count
                    .checked_add(bytes.len())
                    .ok_or(MeasurementError::ByteCountOverflow)?;
                recipient_nodes.extend(
                    ciphertext
                        .recipients()
                        .iter()
                        .map(|recipient| recipient.recipient_node_index().as_u32()),
                );
            }
            recipient_nodes.sort_unstable();
            if recipient_nodes.windows(2).any(|pair| pair[0] == pair[1]) {
                return Err(MeasurementError::DuplicateCounterfactualRecipient);
            }
            if recipient_nodes != target_set.recipient_node_indexes() {
                return Err(MeasurementError::CounterfactualRecipientSetMismatch);
            }
            let delivery_target_count = u32::try_from(ciphertexts.len())
                .map_err(|_| MeasurementError::TopologyCountOverflow)?;
            let recipient_count = u32::try_from(recipient_nodes.len())
                .map_err(|_| MeasurementError::TopologyCountOverflow)?;
            Ok(DeliveryCostAvailability::Measured(SerializedDeliveryCost {
                kind,
                delivery_target_count,
                recipient_count,
                provenance: SerializedByteProvenance::candidate_component(
                    byte_count,
                    ByteEstimationMethod::ShadowExactCodec,
                ),
            }))
        }
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
    /// Task 46 target recipients must be strictly ascending and duplicate-free.
    #[error("recipient target-set indexes are not in canonical ascending order")]
    NonCanonicalTargetSet,
    /// A non-empty target set needs at least one serialized delivery target.
    #[error("the counterfactual delivery route is empty")]
    EmptyCounterfactualRoute,
    /// Independent leaf delivery requires one singleton ciphertext per target.
    #[error("leaf delivery is not independently serialized per target")]
    LeafDeliveryIsNotIndependent,
    /// A recipient occurred in more than one serialized route target.
    #[error("a counterfactual recipient occurs more than once")]
    DuplicateCounterfactualRecipient,
    /// Serialized route recipients did not exactly cover the named target set.
    #[error("counterfactual route recipients do not match the target set")]
    CounterfactualRecipientSetMismatch,
    /// An empty target set must not receive a fabricated serialized byte cost.
    #[error("an empty target set has a serialized delivery cost")]
    EmptyTargetSetHasSerializedCost,
    /// Empty target sets must use their explicit exclusion reason.
    #[error("an empty target set has the wrong unavailable reason")]
    EmptyTargetSetWrongUnavailableReason,
    /// A maturity ratio requires a positive denominator.
    #[error("the maturity ratio denominator is invalid")]
    InvalidMaturityDenominator,
    /// Checked maturity arithmetic exceeded the supported signed representation.
    #[error("maturity arithmetic overflows the supported representation")]
    MaturityOverflow,
    /// Target-set cost measurements must be in canonical ascending set order.
    #[error("maturity target-set measurements are not in canonical order")]
    NonCanonicalMaturityTargetSetOrder,
    /// A fixed-point maturity threshold exceeded the inclusive unit interval.
    #[error("the maturity threshold is outside the unit interval")]
    MaturityThresholdOutOfRange,
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
/// A zero invocation count has no timing value. A non-zero operation carries
/// a duration only when an instrumentation hook measured that operation;
/// count-only observations preserve their actual count without inventing a
/// per-operation duration.
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

    /// Records an actual aggregate count when no per-operation timing hook is
    /// available. This is distinct from an unavailable count and never uses a
    /// fabricated zero-duration sample.
    pub const fn counted(operation: CryptoOperation, invocation_count: u32) -> Self {
        Self {
            operation,
            invocation_count,
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

    /// Records a measured count with no operation-specific timing sample.
    pub const fn counted(operation: CryptoOperation, invocation_count: u32) -> Self {
        Self::Observed(ObservedCryptoOperationMetrics::counted(
            operation,
            invocation_count,
        ))
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

    fn ciphertext_for_recipients(
        path_node_index: u32,
        recipient_node_indexes: &[u32],
    ) -> HybridPathCiphertext {
        let recipients = recipient_node_indexes
            .iter()
            .enumerate()
            .map(|(position, recipient_node_index)| {
                let fill = u8::try_from(position).expect("small test recipient position");
                HybridRecipientCiphertext::new(
                    RecipientNodeIndex::new(*recipient_node_index),
                    [fill; CLASSICAL_ENCAPSULATION_BYTES],
                    MkyberRecipientCiphertext::from_bytes(&[fill; RECIPIENT_CIPHERTEXT_BYTES])
                        .expect("fixed recipient component"),
                    [fill; ENCRYPTED_PATH_SECRET_BYTES],
                )
            })
            .collect();
        HybridPathCiphertext::new(
            PathNodeIndex::new(path_node_index),
            DOMAIN,
            MkyberCommonCiphertext::from_bytes(&[7; COMMON_CIPHERTEXT_BYTES])
                .expect("fixed common component"),
            recipients,
        )
        .expect("canonical recipients")
    }

    fn serialized_bytes(ciphertexts: &[HybridPathCiphertext]) -> usize {
        ciphertexts
            .iter()
            .map(|ciphertext| {
                ciphertext
                    .commit_authenticated_bytes()
                    .expect("hybrid TLS codec")
                    .len()
            })
            .sum()
    }

    fn measured_costs(
        recipient_nodes: &[u32],
        new_partitions: &[&[u32]],
        old_partitions: &[&[u32]],
        ideal_partitions: &[&[u32]],
        binding: u8,
    ) -> RecipientTargetSetCostMeasurement {
        let leaf = recipient_nodes
            .iter()
            .enumerate()
            .map(|(position, recipient)| {
                ciphertext_for_recipients(
                    10 + u32::try_from(position).expect("small test path index"),
                    &[*recipient],
                )
            })
            .collect::<Vec<_>>();
        let new = new_partitions
            .iter()
            .enumerate()
            .map(|(position, recipients)| {
                ciphertext_for_recipients(
                    30 + u32::try_from(position).expect("small test path index"),
                    recipients,
                )
            })
            .collect::<Vec<_>>();
        let old = old_partitions
            .iter()
            .enumerate()
            .map(|(position, recipients)| {
                ciphertext_for_recipients(
                    50 + u32::try_from(position).expect("small test path index"),
                    recipients,
                )
            })
            .collect::<Vec<_>>();
        let ideal = ideal_partitions
            .iter()
            .enumerate()
            .map(|(position, recipients)| {
                ciphertext_for_recipients(
                    70 + u32::try_from(position).expect("small test path index"),
                    recipients,
                )
            })
            .collect::<Vec<_>>();
        RecipientTargetSetCostMeasurement::measure(
            RecipientTargetSet::new(recipient_nodes.to_vec()).expect("canonical target set"),
            [binding; 32],
            CounterfactualDeliveryInput::Serialized(&leaf),
            CounterfactualDeliveryInput::Serialized(&new),
            CounterfactualDeliveryInput::Serialized(&old),
            CounterfactualDeliveryInput::Serialized(&ideal),
        )
        .expect("test partitions cover the target set")
    }

    fn maturity_from_scores(
        h_new_numerator: i128,
        h_new_denominator: i128,
        h_old_numerator: i128,
        h_old_denominator: i128,
        has_undefined_nonempty_target_set: bool,
    ) -> MaturityCostEvaluation {
        let h_new = MaturityScore::from_raw(
            SignedRational::new(h_new_numerator, h_new_denominator).expect("new rational"),
        );
        let h_old = MaturityScore::from_raw(
            SignedRational::new(h_old_numerator, h_old_denominator).expect("old rational"),
        );
        MaturityCostEvaluation {
            target_sets: vec![],
            h_new_cost: GlobalMaturityCost::Defined {
                target_set_index: 0,
                score: h_new,
            },
            h_old_cost: GlobalMaturityCost::Defined {
                target_set_index: 0,
                score: h_old,
            },
            has_undefined_nonempty_target_set,
        }
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

    #[test]
    fn target_set_costs_count_actual_canonical_bytes_for_all_four_constructions() {
        let targets = RecipientTargetSet::new(vec![1, 2, 3]).expect("canonical target set");
        let leaf = vec![
            ciphertext_for_recipients(10, &[1]),
            ciphertext_for_recipients(11, &[2]),
            ciphertext_for_recipients(12, &[3]),
        ];
        let new = vec![ciphertext_for_recipients(20, &[1, 2, 3])];
        let old = vec![
            ciphertext_for_recipients(30, &[1, 2]),
            ciphertext_for_recipients(31, &[3]),
        ];
        let ideal = vec![ciphertext_for_recipients(40, &[1, 2, 3])];
        let costs = RecipientTargetSetCostMeasurement::measure(
            targets,
            [42; 32],
            CounterfactualDeliveryInput::Serialized(&leaf),
            CounterfactualDeliveryInput::Serialized(&new),
            CounterfactualDeliveryInput::Serialized(&old),
            CounterfactualDeliveryInput::Serialized(&ideal),
        )
        .expect("every route covers the same target set");

        let expected = [
            serialized_bytes(&leaf),
            serialized_bytes(&new),
            serialized_bytes(&old),
            serialized_bytes(&ideal),
        ];
        for (availability, expected_bytes, expected_kind, expected_targets) in [
            (
                costs.c_leaf(),
                expected[0],
                CounterfactualDeliveryKind::Leaf,
                3,
            ),
            (
                costs.c_new(),
                expected[1],
                CounterfactualDeliveryKind::New,
                1,
            ),
            (
                costs.c_old(),
                expected[2],
                CounterfactualDeliveryKind::Old,
                2,
            ),
            (
                costs.c_ideal(),
                expected[3],
                CounterfactualDeliveryKind::Ideal,
                1,
            ),
        ] {
            let DeliveryCostAvailability::Measured(cost) = availability else {
                panic!("all four routes must have actual canonical serializer bytes");
            };
            assert_eq!(cost.kind(), expected_kind);
            assert_eq!(cost.delivery_target_count(), expected_targets);
            assert_eq!(cost.recipient_count(), 3);
            assert_eq!(cost.provenance().measured_bytes(), expected_bytes);
            assert_eq!(cost.provenance().estimated_bytes(), Some(expected_bytes));
            assert_eq!(
                cost.provenance().estimation_method(),
                ByteEstimationMethod::ShadowExactCodec
            );
        }
        assert_eq!(costs.target_set().recipient_node_indexes(), &[1, 2, 3]);
        assert_eq!(costs.logical_payload_binding(), &[42; 32]);
    }

    #[test]
    fn unavailable_empty_and_inconsistent_routes_are_never_fabricated_as_costs() {
        let targets = RecipientTargetSet::new(vec![1, 2]).expect("canonical target set");
        let leaf = vec![
            ciphertext_for_recipients(10, &[1]),
            ciphertext_for_recipients(11, &[2]),
        ];
        let shared = vec![ciphertext_for_recipients(20, &[1, 2])];
        let costs = RecipientTargetSetCostMeasurement::measure(
            targets,
            [43; 32],
            CounterfactualDeliveryInput::Serialized(&leaf),
            CounterfactualDeliveryInput::Serialized(&shared),
            CounterfactualDeliveryInput::Unavailable(
                DeliveryCostUnavailableReason::NoEligibleOldTreeCoverRoute,
            ),
            CounterfactualDeliveryInput::Serialized(&shared),
        )
        .expect("unavailable old cover is explicit");
        assert_eq!(
            costs.c_old(),
            DeliveryCostAvailability::Unavailable(
                DeliveryCostUnavailableReason::NoEligibleOldTreeCoverRoute
            )
        );

        let empty = RecipientTargetSet::new(vec![]).expect("empty target set is recorded");
        let excluded = RecipientTargetSetCostMeasurement::measure(
            empty,
            [44; 32],
            CounterfactualDeliveryInput::Unavailable(DeliveryCostUnavailableReason::EmptyTargetSet),
            CounterfactualDeliveryInput::Unavailable(DeliveryCostUnavailableReason::EmptyTargetSet),
            CounterfactualDeliveryInput::Unavailable(DeliveryCostUnavailableReason::EmptyTargetSet),
            CounterfactualDeliveryInput::Unavailable(DeliveryCostUnavailableReason::EmptyTargetSet),
        )
        .expect("empty target set is explicit rather than discarded");
        assert!(excluded.target_set().is_empty());
        assert!(matches!(
            excluded.c_leaf(),
            DeliveryCostAvailability::Unavailable(DeliveryCostUnavailableReason::EmptyTargetSet)
        ));

        assert_eq!(
            RecipientTargetSet::new(vec![2, 1]),
            Err(MeasurementError::NonCanonicalTargetSet)
        );
        let duplicate = vec![
            ciphertext_for_recipients(30, &[1]),
            ciphertext_for_recipients(31, &[1, 2]),
        ];
        assert_eq!(
            RecipientTargetSetCostMeasurement::measure(
                RecipientTargetSet::new(vec![1, 2]).expect("canonical target set"),
                [45; 32],
                CounterfactualDeliveryInput::Serialized(&leaf),
                CounterfactualDeliveryInput::Serialized(&duplicate),
                CounterfactualDeliveryInput::Serialized(&shared),
                CounterfactualDeliveryInput::Serialized(&shared),
            ),
            Err(MeasurementError::DuplicateCounterfactualRecipient)
        );
        assert_eq!(
            RecipientTargetSetCostMeasurement::measure(
                RecipientTargetSet::new(vec![1, 2]).expect("canonical target set"),
                [46; 32],
                CounterfactualDeliveryInput::Serialized(&shared),
                CounterfactualDeliveryInput::Serialized(&shared),
                CounterfactualDeliveryInput::Serialized(&shared),
                CounterfactualDeliveryInput::Serialized(&shared),
            ),
            Err(MeasurementError::LeafDeliveryIsNotIndependent)
        );
    }

    #[test]
    fn maturity_costs_preserve_raw_clamps_and_conservative_min_max_aggregation() {
        let empty = RecipientTargetSetCostMeasurement::measure(
            RecipientTargetSet::new(vec![]).expect("empty target set"),
            [50; 32],
            CounterfactualDeliveryInput::Unavailable(DeliveryCostUnavailableReason::EmptyTargetSet),
            CounterfactualDeliveryInput::Unavailable(DeliveryCostUnavailableReason::EmptyTargetSet),
            CounterfactualDeliveryInput::Unavailable(DeliveryCostUnavailableReason::EmptyTargetSet),
            CounterfactualDeliveryInput::Unavailable(DeliveryCostUnavailableReason::EmptyTargetSet),
        )
        .expect("empty target set");
        let first = measured_costs(&[1, 2], &[&[1, 2]], &[&[1], &[2]], &[&[1, 2]], 51);
        let second = measured_costs(
            &[4, 5, 6],
            &[&[4, 5], &[6]],
            &[&[4, 5, 6]],
            &[&[4, 5, 6]],
            52,
        );
        let evaluation = MaturityCostEvaluation::from_costs(vec![empty, first, second])
            .expect("canonical target-set order");

        assert!(!evaluation.has_undefined_nonempty_target_set());
        assert!(matches!(
            evaluation.target_sets()[0],
            TargetSetMaturity::ExcludedEmpty { .. }
        ));
        let GlobalMaturityCost::Defined {
            target_set_index,
            score,
        } = evaluation.h_new_cost()
        else {
            panic!("new maturity must be defined");
        };
        assert_eq!(target_set_index, 2);
        assert_eq!(score.raw(), SignedRational::new(1, 2).expect("rational"));
        assert_eq!(
            score.clamped(),
            SignedRational::new(1, 2).expect("rational")
        );
        assert_eq!(score.clamp_reason(), MaturityClampReason::InRange);

        let GlobalMaturityCost::Defined {
            target_set_index,
            score,
        } = evaluation.h_old_cost()
        else {
            panic!("old maturity must be defined");
        };
        assert_eq!(target_set_index, 2);
        assert_eq!(score.raw(), SignedRational::one());
        assert_eq!(score.clamped(), SignedRational::one());
    }

    #[test]
    fn undefined_nonempty_sets_block_maturity_without_numeric_fallbacks() {
        let unavailable_old = RecipientTargetSetCostMeasurement::measure(
            RecipientTargetSet::new(vec![1, 2]).expect("target set"),
            [53; 32],
            CounterfactualDeliveryInput::Serialized(&[
                ciphertext_for_recipients(10, &[1]),
                ciphertext_for_recipients(11, &[2]),
            ]),
            CounterfactualDeliveryInput::Serialized(&[ciphertext_for_recipients(20, &[1, 2])]),
            CounterfactualDeliveryInput::Unavailable(
                DeliveryCostUnavailableReason::NoEligibleOldTreeCoverRoute,
            ),
            CounterfactualDeliveryInput::Serialized(&[ciphertext_for_recipients(30, &[1, 2])]),
        )
        .expect("explicit unavailable old route");
        let unavailable =
            MaturityCostEvaluation::from_costs(vec![unavailable_old]).expect("one target set");
        assert!(unavailable.has_undefined_nonempty_target_set());
        assert!(matches!(
            unavailable.h_old_cost(),
            GlobalMaturityCost::Undefined(
                GlobalMaturityUndefinedReason::UndefinedNonEmptyTargetSet
            )
        ));
        let unavailable_retirement = evaluate_treecover_retirement(
            &unavailable,
            TreeCoverRetirementThresholds::thesis_defaults(),
        )
        .expect("unavailable route is an explicit blocker");
        assert_eq!(unavailable_retirement.new_tree_condition(), None);
        assert_eq!(unavailable_retirement.old_treecover_condition(), None);
        assert_eq!(
            unavailable_retirement.decision(),
            TreeCoverRetirementDecision::Keep(
                TreeCoverRetirementBlocker::UndefinedNonEmptyTargetSet
            )
        );

        let denominator_zero = measured_costs(&[4, 5], &[&[4, 5]], &[&[4, 5]], &[&[4], &[5]], 54);
        let denominator =
            MaturityCostEvaluation::from_costs(vec![denominator_zero]).expect("one target set");
        assert!(denominator.has_undefined_nonempty_target_set());
        let TargetSetMaturity::Evaluated { h_new, h_old, .. } = &denominator.target_sets()[0]
        else {
            panic!("non-empty target set must be evaluated");
        };
        assert!(matches!(
            h_new,
            TargetSetMaturityScore::Undefined(
                MaturityUndefinedReason::NonPositiveDenominator { .. }
            )
        ));
        assert!(matches!(
            h_old,
            TargetSetMaturityScore::Undefined(
                MaturityUndefinedReason::NonPositiveDenominator { .. }
            )
        ));
        let denominator_retirement = evaluate_treecover_retirement(
            &denominator,
            TreeCoverRetirementThresholds::thesis_defaults(),
        )
        .expect("division-by-zero-style denominator is an explicit blocker");
        assert_eq!(denominator_retirement.new_tree_condition(), None);
        assert_eq!(denominator_retirement.old_treecover_condition(), None);
        assert_eq!(
            denominator_retirement.decision(),
            TreeCoverRetirementDecision::Keep(
                TreeCoverRetirementBlocker::UndefinedNonEmptyTargetSet
            )
        );

        let empty = MaturityCostEvaluation::from_costs(vec![]).expect("empty input is explicit");
        assert!(matches!(
            empty.h_new_cost(),
            GlobalMaturityCost::Undefined(GlobalMaturityUndefinedReason::NoNonEmptyTargetSets)
        ));
    }

    #[test]
    fn maturity_clamps_out_of_range_raw_values_and_rejects_noncanonical_measurement_order() {
        let above_one = measured_costs(
            &[1, 2, 3],
            &[&[1, 2, 3]],
            &[&[1, 2, 3]],
            &[&[1, 2], &[3]],
            55,
        );
        let evaluation =
            MaturityCostEvaluation::from_costs(vec![above_one]).expect("one target set");
        let GlobalMaturityCost::Defined { score, .. } = evaluation.h_new_cost() else {
            panic!("new maturity must be defined");
        };
        assert_eq!(score.raw(), SignedRational::new(2, 1).expect("rational"));
        assert_eq!(score.clamped(), SignedRational::one());
        assert_eq!(score.clamp_reason(), MaturityClampReason::AboveOne);

        let below_zero = MaturityScore::from_raw(SignedRational::new(-1, 3).expect("rational"));
        assert_eq!(below_zero.clamped(), SignedRational::zero());
        assert_eq!(below_zero.clamp_reason(), MaturityClampReason::BelowZero);

        let first = measured_costs(&[1, 2], &[&[1, 2]], &[&[1, 2]], &[&[1, 2]], 56);
        let second = measured_costs(&[4, 5], &[&[4, 5]], &[&[4, 5]], &[&[4, 5]], 57);
        assert_eq!(
            MaturityCostEvaluation::from_costs(vec![second, first]),
            Err(MeasurementError::NonCanonicalMaturityTargetSetOrder)
        );
    }

    #[test]
    fn retirement_rule_uses_or_with_independent_new_and_old_triggers() {
        let thresholds = TreeCoverRetirementThresholds::thesis_defaults();
        assert_eq!(thresholds.theta_new().micro_units(), 700_000);
        assert_eq!(thresholds.theta_old().micro_units(), 500_000);

        let new_only =
            evaluate_treecover_retirement(&maturity_from_scores(7, 10, 1, 2, false), thresholds)
                .expect("threshold comparison");
        assert_eq!(new_only.new_tree_condition(), Some(true));
        assert_eq!(new_only.old_treecover_condition(), Some(false));
        assert_eq!(
            new_only.decision(),
            TreeCoverRetirementDecision::Retire(TreeCoverRetirementTriggers {
                new_tree_maturity: true,
                old_treecover_cost: false,
            })
        );

        let old_only =
            evaluate_treecover_retirement(&maturity_from_scores(1, 2, 49, 100, false), thresholds)
                .expect("threshold comparison");
        assert_eq!(old_only.new_tree_condition(), Some(false));
        assert_eq!(old_only.old_treecover_condition(), Some(true));
        assert_eq!(
            old_only.decision(),
            TreeCoverRetirementDecision::Retire(TreeCoverRetirementTriggers {
                new_tree_maturity: false,
                old_treecover_cost: true,
            })
        );

        let both =
            evaluate_treecover_retirement(&maturity_from_scores(7, 10, 49, 100, false), thresholds)
                .expect("threshold comparison");
        assert_eq!(both.new_tree_condition(), Some(true));
        assert_eq!(both.old_treecover_condition(), Some(true));
        assert_eq!(
            both.decision(),
            TreeCoverRetirementDecision::Retire(TreeCoverRetirementTriggers {
                new_tree_maturity: true,
                old_treecover_cost: true,
            })
        );

        let neither =
            evaluate_treecover_retirement(&maturity_from_scores(69, 100, 1, 2, false), thresholds)
                .expect("threshold comparison");
        assert_eq!(neither.new_tree_condition(), Some(false));
        assert_eq!(neither.old_treecover_condition(), Some(false));
        assert_eq!(
            neither.decision(),
            TreeCoverRetirementDecision::Keep(TreeCoverRetirementBlocker::ThresholdsNotMet)
        );
    }

    #[test]
    fn retirement_rule_blocks_undefined_data_and_rejects_invalid_thresholds() {
        let blocked = evaluate_treecover_retirement(
            &maturity_from_scores(1, 1, 0, 1, true),
            TreeCoverRetirementThresholds::thesis_defaults(),
        )
        .expect("undefined result is a normal blocker");
        assert_eq!(blocked.new_tree_condition(), None);
        assert_eq!(blocked.old_treecover_condition(), None);
        assert_eq!(
            blocked.decision(),
            TreeCoverRetirementDecision::Keep(
                TreeCoverRetirementBlocker::UndefinedNonEmptyTargetSet
            )
        );
        assert_eq!(
            MaturityThreshold::new(MATURITY_THRESHOLD_SCALE + 1),
            Err(MeasurementError::MaturityThresholdOutOfRange)
        );
        assert_eq!(TreeCoverRetirementTriggers::new(false, false), None);
        assert_eq!(TreeCoverRetirementDecision::retire(false, false), None);
    }
}
