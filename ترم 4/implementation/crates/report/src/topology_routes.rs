#![forbid(unsafe_code)]

//! Exact topology-route serialization for the clear transition report.
//!
//! The authenticated Commit supplies public recipient sets and exact canonical
//! delivery lengths. Each alternative reuses one public logical-payload
//! binding, partitions the same recipients according to an exact topology
//! cover, and passes concrete fixed-width hybrid ciphertext values through the
//! production TLS codec. Only byte counts and public topology are retained.

use experimental_mls_adapter::AuthenticatedAdaptiveTopologySnapshot;
use hybrid_path_secret::{
    HybridPathCiphertext, HybridRecipientCiphertext, PathNodeIndex, RecipientNodeIndex,
    CLASSICAL_ENCAPSULATION_BYTES, ENCRYPTED_PATH_SECRET_BYTES,
};
use metrics::{
    CounterfactualDeliveryInput, DeliveryCostAvailability, MeasurementError, RecipientTargetSet,
    RecipientTargetSetCostMeasurement,
};
use mkyber::{
    MkyberCommonCiphertext, MkyberDomain, MkyberRecipientCiphertext, COMMON_CIPHERTEXT_BYTES,
    RECIPIENT_CIPHERTEXT_BYTES,
};
use thiserror::Error;
use transition_tree::{ExactCoverNode, ExactRecipientCovers, TransitionTreeError};

/// Exact route-only costs for one authenticated path-level recipient set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ExactTopologyRouteSetCost {
    pub(crate) recipient_set_index: u32,
    pub(crate) path_node_index: u32,
    pub(crate) recipient_count: u32,
    pub(crate) observed_delivery_bytes: u64,
    pub(crate) c_leaf_node_count: u32,
    pub(crate) c_new_node_count: u32,
    pub(crate) c_old_node_count: u32,
    pub(crate) c_ideal_node_count: u32,
    pub(crate) c_leaf_route_bytes: u64,
    pub(crate) c_new_route_bytes: u64,
    pub(crate) c_old_route_bytes: u64,
    pub(crate) c_ideal_route_bytes: u64,
    pub(crate) covers: ExactRecipientCovers,
}

/// One Commit's four aggregate alternatives.
///
/// `common_outer_commit_bytes` is the emitted outer Commit length minus the
/// exact signed hybrid-delivery lengths. It is added once to each sum of
/// path-level route bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ExactTopologyAggregateCost {
    pub(crate) common_outer_commit_bytes: u64,
    pub(crate) observed_route_payload_bytes: u64,
    pub(crate) c_leaf_route_bytes: u64,
    pub(crate) c_new_route_bytes: u64,
    pub(crate) c_old_route_bytes: u64,
    pub(crate) c_ideal_route_bytes: u64,
    pub(crate) c_leaf_bytes: u64,
    pub(crate) c_new_bytes: u64,
    pub(crate) c_old_bytes: u64,
    pub(crate) c_ideal_bytes: u64,
    pub(crate) recipient_sets: Vec<ExactTopologyRouteSetCost>,
}

/// Fail-closed errors from exact route materialization and accounting.
#[derive(Debug, Error)]
pub(crate) enum ExactTopologyRouteError {
    #[error("the accepted Commit contains no authenticated recipient set")]
    MissingRecipientSet,
    #[error("an authenticated recipient set is not canonically ordered")]
    NonCanonicalRecipientSet,
    #[error("the exact topology cover could not be derived")]
    Cover(#[source] TransitionTreeError),
    #[error("the canonical hybrid route could not be materialized")]
    HybridCodec,
    #[error("the canonical route measurement rejected its coverage")]
    Measurement(#[source] MeasurementError),
    #[error("the reconstructed observed route length differs from the signed delivery length")]
    ObservedRouteLengthMismatch,
    #[error("the signed hybrid route is larger than its emitted outer Commit")]
    RouteExceedsOuterCommit,
    #[error("an exact topology-route byte or count calculation overflowed")]
    Overflow,
}

/// Serializes all four alternatives for every authenticated path-level set and
/// adds the observed invariant outer Commit bytes once per alternative.
pub(crate) fn measure_exact_topology_routes(
    snapshot: &AuthenticatedAdaptiveTopologySnapshot,
    emitted_outer_commit_bytes: u64,
) -> Result<ExactTopologyAggregateCost, ExactTopologyRouteError> {
    let recipient_sets = snapshot.commit_topology.recipient_sets();
    if recipient_sets.is_empty() {
        return Err(ExactTopologyRouteError::MissingRecipientSet);
    }

    let observed_route_payload_bytes =
        recipient_sets
            .iter()
            .try_fold(0_u64, |sum, recipient_set| {
                sum.checked_add(u64::from(recipient_set.canonical_delivery_bytes()))
                    .ok_or(ExactTopologyRouteError::Overflow)
            })?;
    let common_outer_commit_bytes = emitted_outer_commit_bytes
        .checked_sub(observed_route_payload_bytes)
        .ok_or(ExactTopologyRouteError::RouteExceedsOuterCommit)?;

    let mut measured_sets = Vec::with_capacity(recipient_sets.len());
    for (set_index, recipient_set) in recipient_sets.iter().enumerate() {
        if recipient_set
            .recipient_node_indices()
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        {
            return Err(ExactTopologyRouteError::NonCanonicalRecipientSet);
        }
        let covers = snapshot
            .transition_trees
            .exact_recipient_covers(recipient_set.recipient_node_indices())
            .map_err(ExactTopologyRouteError::Cover)?;
        measured_sets.push(measure_recipient_set(
            u32::try_from(set_index).map_err(|_| ExactTopologyRouteError::Overflow)?,
            recipient_set.path_node_index(),
            recipient_set.recipient_node_indices(),
            u64::from(recipient_set.canonical_delivery_bytes()),
            &covers,
            logical_payload_binding(snapshot, set_index, recipient_set.path_node_index())?,
        )?);
    }

    let c_leaf_route_bytes = sum_route_bytes(&measured_sets, |set| set.c_leaf_route_bytes)?;
    let c_new_route_bytes = sum_route_bytes(&measured_sets, |set| set.c_new_route_bytes)?;
    let c_old_route_bytes = sum_route_bytes(&measured_sets, |set| set.c_old_route_bytes)?;
    let c_ideal_route_bytes = sum_route_bytes(&measured_sets, |set| set.c_ideal_route_bytes)?;

    Ok(ExactTopologyAggregateCost {
        common_outer_commit_bytes,
        observed_route_payload_bytes,
        c_leaf_route_bytes,
        c_new_route_bytes,
        c_old_route_bytes,
        c_ideal_route_bytes,
        c_leaf_bytes: add_outer(common_outer_commit_bytes, c_leaf_route_bytes)?,
        c_new_bytes: add_outer(common_outer_commit_bytes, c_new_route_bytes)?,
        c_old_bytes: add_outer(common_outer_commit_bytes, c_old_route_bytes)?,
        c_ideal_bytes: add_outer(common_outer_commit_bytes, c_ideal_route_bytes)?,
        recipient_sets: measured_sets,
    })
}

fn measure_recipient_set(
    recipient_set_index: u32,
    path_node_index: u32,
    recipients: &[u32],
    observed_delivery_bytes: u64,
    covers: &ExactRecipientCovers,
    logical_payload_binding: [u8; 32],
) -> Result<ExactTopologyRouteSetCost, ExactTopologyRouteError> {
    let leaf = materialize_route(path_node_index, logical_payload_binding, &covers.c_leaf)?;
    let new = materialize_route(path_node_index, logical_payload_binding, &covers.c_new)?;
    let old = materialize_route(path_node_index, logical_payload_binding, &covers.c_old)?;
    let ideal = materialize_route(path_node_index, logical_payload_binding, &covers.c_ideal)?;

    let observed =
        materialize_observed_route(path_node_index, logical_payload_binding, recipients)?;
    let reconstructed_observed_bytes = observed
        .commit_authenticated_bytes()
        .map_err(|_| ExactTopologyRouteError::HybridCodec)?
        .len();
    if u64::try_from(reconstructed_observed_bytes).map_err(|_| ExactTopologyRouteError::Overflow)?
        != observed_delivery_bytes
    {
        return Err(ExactTopologyRouteError::ObservedRouteLengthMismatch);
    }

    let measurement = RecipientTargetSetCostMeasurement::measure(
        RecipientTargetSet::new(recipients.to_vec())
            .map_err(ExactTopologyRouteError::Measurement)?,
        logical_payload_binding,
        CounterfactualDeliveryInput::Serialized(&leaf),
        CounterfactualDeliveryInput::Serialized(&new),
        CounterfactualDeliveryInput::Serialized(&old),
        CounterfactualDeliveryInput::Serialized(&ideal),
    )
    .map_err(ExactTopologyRouteError::Measurement)?;

    Ok(ExactTopologyRouteSetCost {
        recipient_set_index,
        path_node_index,
        recipient_count: u32::try_from(recipients.len())
            .map_err(|_| ExactTopologyRouteError::Overflow)?,
        observed_delivery_bytes,
        c_leaf_node_count: node_count(&covers.c_leaf)?,
        c_new_node_count: node_count(&covers.c_new)?,
        c_old_node_count: node_count(&covers.c_old)?,
        c_ideal_node_count: node_count(&covers.c_ideal)?,
        c_leaf_route_bytes: measured_bytes(measurement.c_leaf())?,
        c_new_route_bytes: measured_bytes(measurement.c_new())?,
        c_old_route_bytes: measured_bytes(measurement.c_old())?,
        c_ideal_route_bytes: measured_bytes(measurement.c_ideal())?,
        covers: covers.clone(),
    })
}

fn materialize_route(
    path_node_index: u32,
    logical_payload_binding: [u8; 32],
    cover: &[ExactCoverNode],
) -> Result<Vec<HybridPathCiphertext>, ExactTopologyRouteError> {
    cover
        .iter()
        .enumerate()
        .map(|(cover_position, node)| {
            materialize_delivery(
                path_node_index,
                logical_payload_binding,
                cover_position,
                &node.recipient_quaternary_leaf_ordinals,
            )
        })
        .collect()
}

fn materialize_observed_route(
    path_node_index: u32,
    logical_payload_binding: [u8; 32],
    recipients: &[u32],
) -> Result<HybridPathCiphertext, ExactTopologyRouteError> {
    materialize_delivery(path_node_index, logical_payload_binding, 0, recipients)
}

fn materialize_delivery(
    path_node_index: u32,
    logical_payload_binding: [u8; 32],
    cover_position: usize,
    recipients: &[u32],
) -> Result<HybridPathCiphertext, ExactTopologyRouteError> {
    let position_byte =
        u8::try_from(cover_position % 256).map_err(|_| ExactTopologyRouteError::Overflow)?;
    let recipient_records = recipients
        .iter()
        .enumerate()
        .map(|(recipient_position, recipient)| {
            let fill = position_byte
                ^ u8::try_from(recipient_position % 256)
                    .map_err(|_| ExactTopologyRouteError::Overflow)?;
            Ok(HybridRecipientCiphertext::new(
                RecipientNodeIndex::new(*recipient),
                [fill; CLASSICAL_ENCAPSULATION_BYTES],
                MkyberRecipientCiphertext::from_bytes(&[fill; RECIPIENT_CIPHERTEXT_BYTES])
                    .map_err(|_| ExactTopologyRouteError::HybridCodec)?,
                [fill; ENCRYPTED_PATH_SECRET_BYTES],
            ))
        })
        .collect::<Result<Vec<_>, ExactTopologyRouteError>>()?;
    HybridPathCiphertext::new(
        PathNodeIndex::new(path_node_index),
        MkyberDomain::new(logical_payload_binding),
        MkyberCommonCiphertext::from_bytes(&[position_byte; COMMON_CIPHERTEXT_BYTES])
            .map_err(|_| ExactTopologyRouteError::HybridCodec)?,
        recipient_records,
    )
    .map_err(|_| ExactTopologyRouteError::HybridCodec)
}

fn logical_payload_binding(
    snapshot: &AuthenticatedAdaptiveTopologySnapshot,
    set_index: usize,
    path_node_index: u32,
) -> Result<[u8; 32], ExactTopologyRouteError> {
    let mut binding = [0_u8; 32];
    binding[..8].copy_from_slice(b"T82ROUTE");
    binding[8..16].copy_from_slice(&snapshot.epoch.to_be_bytes());
    binding[16..20].copy_from_slice(&snapshot.committer_member_index.to_be_bytes());
    binding[20..24].copy_from_slice(&path_node_index.to_be_bytes());
    binding[24..28].copy_from_slice(
        &u32::try_from(set_index)
            .map_err(|_| ExactTopologyRouteError::Overflow)?
            .to_be_bytes(),
    );
    binding[28..32].copy_from_slice(
        &snapshot
            .transition_trees
            .active()
            .tree_version()
            .to_be_bytes(),
    );
    Ok(binding)
}

fn measured_bytes(availability: DeliveryCostAvailability) -> Result<u64, ExactTopologyRouteError> {
    let DeliveryCostAvailability::Measured(cost) = availability else {
        return Err(ExactTopologyRouteError::HybridCodec);
    };
    u64::try_from(cost.provenance().measured_bytes()).map_err(|_| ExactTopologyRouteError::Overflow)
}

fn node_count(nodes: &[ExactCoverNode]) -> Result<u32, ExactTopologyRouteError> {
    u32::try_from(nodes.len()).map_err(|_| ExactTopologyRouteError::Overflow)
}

fn sum_route_bytes(
    sets: &[ExactTopologyRouteSetCost],
    select: impl Fn(&ExactTopologyRouteSetCost) -> u64,
) -> Result<u64, ExactTopologyRouteError> {
    sets.iter().try_fold(0_u64, |sum, set| {
        sum.checked_add(select(set))
            .ok_or(ExactTopologyRouteError::Overflow)
    })
}

fn add_outer(outer: u64, route: u64) -> Result<u64, ExactTopologyRouteError> {
    outer
        .checked_add(route)
        .ok_or(ExactTopologyRouteError::Overflow)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cover_node(ordinal: u32, recipients: Vec<u32>) -> ExactCoverNode {
        ExactCoverNode {
            arity: 4,
            depth: 1,
            ordinal,
            recipient_quaternary_leaf_ordinals: recipients,
        }
    }

    #[test]
    fn canonical_routes_repeat_common_bytes_per_exact_cover_node() {
        let recipients = vec![0, 1, 3];
        let covers = ExactRecipientCovers {
            c_leaf: vec![
                cover_node(0, vec![0]),
                cover_node(1, vec![1]),
                cover_node(3, vec![3]),
            ],
            c_new: vec![cover_node(0, recipients.clone())],
            c_old: vec![cover_node(0, vec![0, 1]), cover_node(1, vec![3])],
            c_ideal: vec![cover_node(0, recipients.clone())],
        };
        let set = measure_recipient_set(0, 7, &recipients, 1_140, &covers, [42; 32])
            .expect("exact route costs");

        assert_eq!(set.c_leaf_route_bytes, 2_628);
        assert_eq!(set.c_new_route_bytes, 1_140);
        assert_eq!(set.c_old_route_bytes, 1_884);
        assert_eq!(set.c_ideal_route_bytes, 1_140);
        assert_eq!(set.observed_delivery_bytes, 1_140);
    }

    #[test]
    fn seed_42_cover_shape_has_expected_canonical_route_bytes() {
        let recipients = (0..64).filter(|ordinal| *ordinal != 2).collect::<Vec<_>>();
        let c_leaf = recipients
            .iter()
            .map(|recipient| cover_node(*recipient, vec![*recipient]))
            .collect();
        let c_new = vec![
            cover_node(0, vec![0]),
            cover_node(1, vec![1]),
            cover_node(3, vec![3]),
            cover_node(4, (4..8).collect()),
            cover_node(8, (8..12).collect()),
            cover_node(12, (12..16).collect()),
            cover_node(16, (16..32).collect()),
            cover_node(32, (32..48).collect()),
            cover_node(48, (48..64).collect()),
        ];
        let c_old = vec![
            cover_node(0, vec![0, 1, 12, 23, 34, 45, 56, 61]),
            cover_node(1, vec![62, 63]),
            cover_node(2, vec![3]),
            cover_node(3, (4..8).collect()),
            cover_node(
                4,
                vec![8, 9, 10, 11, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 24, 25],
            ),
            cover_node(
                5,
                vec![
                    26, 27, 28, 29, 30, 31, 32, 33, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 46, 47,
                    48, 49, 50, 51, 52, 53, 54, 55, 57, 58, 59, 60,
                ],
            ),
        ];
        let covers = ExactRecipientCovers {
            c_leaf,
            c_new: c_new.clone(),
            c_old,
            c_ideal: c_new,
        };
        let set = measure_recipient_set(0, 0, &recipients, 9_060, &covers, [42; 32])
            .expect("seed-42 exact route costs");

        assert_eq!(set.c_leaf_route_bytes, 55_188);
        assert_eq!(set.c_new_route_bytes, 15_012);
        assert_eq!(set.c_old_route_bytes, 12_780);
        assert_eq!(set.c_ideal_route_bytes, 15_012);
        let outer = 16_133_u64 - set.observed_delivery_bytes;
        assert_eq!(outer, 7_073);
        assert_eq!(outer + set.c_leaf_route_bytes, 62_261);
        assert_eq!(outer + set.c_new_route_bytes, 22_085);
        assert_eq!(outer + set.c_old_route_bytes, 19_853);
        assert_eq!(outer + set.c_ideal_route_bytes, 22_085);
    }
}
