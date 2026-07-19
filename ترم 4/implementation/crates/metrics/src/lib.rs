#![forbid(unsafe_code)]

//! Typed measurement-record boundary.
//!
//! This crate preserves the distinction between an emitted baseline MLS commit
//! and a shadow candidate estimate. It does not construct, authenticate, or
//! merge an experimental MLS commit.

use core::ops::Range;

use hybrid_path_secret::HybridPathCiphertext;
use thiserror::Error;

/// Why a byte value has its measured or estimated status.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
}

#[cfg(test)]
mod tests {
    use super::*;
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
}
