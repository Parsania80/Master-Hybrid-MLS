#![forbid(unsafe_code)]

//! Deterministic, non-mutating topology for the experimental 2-to-4 analysis.
//!
//! This crate does not implement an MLS transition, TreeCover, or path-secret
//! derivation. It maps already occupied binary leaves to a shadow quaternary
//! topology and replays only public logical operations by returning a new
//! topology, never by mutating an MLS group or consuming randomness.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Version of the canonical binary-to-quaternary mapping format.
pub const LEAF_MAPPING_VERSION: u16 = 1;
const MAPPING_MAGIC: [u8; 4] = *b"AHLM";
const QUATERNARY_ARITY: u8 = 4;

/// An occupied member at a public RFC 9420 binary leaf index.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BinaryLeafMember {
    /// Bytewise canonical public member identifier.
    pub member_id: Vec<u8>,
    /// Public source leaf index in the binary MLS tree.
    pub binary_leaf_index: u32,
}

/// One deterministic assignment in a versioned leaf map.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LeafAssignment {
    /// Bytewise canonical public member identifier.
    pub member_id: Vec<u8>,
    /// Public source leaf index in the binary MLS tree.
    pub binary_leaf_index: u32,
    /// Left-to-right candidate leaf ordinal in the quaternary tree.
    pub quaternary_leaf_ordinal: u32,
}

/// Canonical mapping from occupied binary leaves to a quaternary shadow tree.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BinaryToQuaternaryLeafMapping {
    /// Canonical mapping encoding version.
    pub version: u16,
    /// Assignments in strictly increasing bytewise `member_id` order.
    pub assignments: Vec<LeafAssignment>,
}

/// Read-only quaternary topology derived from one validated mapping.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ShadowQuaternaryTree {
    mapping: BinaryToQuaternaryLeafMapping,
    occupants: Vec<ShadowOccupant>,
    height: u8,
    leaf_capacity: u32,
}

/// A public member occupying one candidate quaternary leaf.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ShadowOccupant {
    /// Canonical public member identifier.
    pub member_id: Vec<u8>,
    /// Candidate leaf ordinal currently assigned to this member.
    pub quaternary_leaf_ordinal: u32,
    /// Source binary leaf at the frozen transition mapping, if any.
    pub binary_leaf_index: Option<u32>,
}

/// A public logical operation replayed only against a shadow topology.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub enum ShadowOperation {
    /// A normal UpdatePath operation: membership and topology do not change.
    Update {
        /// Canonical public member identifier of the committer.
        member_id: Vec<u8>,
    },
    /// A membership addition: assign the lowest vacant candidate leaf.
    Add {
        /// Canonical public member identifier of the new member.
        member_id: Vec<u8>,
    },
    /// A membership removal: vacate the member's leaf without renumbering.
    Remove {
        /// Canonical public member identifier of the removed member.
        member_id: Vec<u8>,
    },
}

/// Public outcome of a non-mutating logical-operation replay.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ShadowReplay {
    /// The operation replayed against the source shadow tree.
    pub operation: ShadowOperation,
    /// Population before replay.
    pub population_before: usize,
    /// Population after replay.
    pub population_after: usize,
    /// Whether candidate occupancy or capacity changed.
    pub topology_changed: bool,
    /// Candidate leaf assigned by an Add operation, if any.
    pub assigned_leaf_ordinal: Option<u32>,
    /// Candidate leaf vacated by a Remove operation, if any.
    pub vacated_leaf_ordinal: Option<u32>,
    /// Immutable counterfactual topology after the replay.
    pub tree: ShadowQuaternaryTree,
}

/// A public node address in a quaternary tree.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct QuaternaryNode {
    /// Root-relative depth, where the root is depth zero.
    pub depth: u8,
    /// Left-to-right ordinal among nodes at this depth.
    pub ordinal: u32,
}

/// Errors from parsing or constructing public shadow topology.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum AdaptiveTreeError {
    /// A mapping needs at least one occupied member.
    #[error("the shadow tree requires at least one occupied member")]
    EmptyPopulation,
    /// Canonical member identifiers cannot be empty.
    #[error("a canonical member identifier is empty")]
    EmptyMemberId,
    /// More than one occupied source leaf named the same member.
    #[error("a canonical member identifier occurs more than once")]
    DuplicateMemberId,
    /// More than one member occupied the same source binary leaf.
    #[error("a source binary leaf index occurs more than once")]
    DuplicateBinaryLeaf,
    /// A mapping used a version this implementation does not understand.
    #[error("the leaf mapping version is unsupported")]
    UnsupportedMappingVersion,
    /// Mapping assignments are not in their canonical order or use incorrect
    /// candidate ordinals.
    #[error("the leaf mapping assignments are not canonical")]
    NonCanonicalMapping,
    /// Canonical mapping bytes are malformed or truncated.
    #[error("the canonical leaf mapping bytes are malformed")]
    MalformedEncoding,
    /// Canonical mapping bytes include unconsumed trailing data.
    #[error("the canonical leaf mapping bytes have trailing data")]
    TrailingData,
    /// The candidate tree size exceeded the public index representation.
    #[error("the candidate tree capacity overflows the supported range")]
    CapacityOverflow,
    /// A requested member is absent from the shadow mapping.
    #[error("the member is absent from the shadow tree")]
    MemberNotFound,
    /// An Add replay named a member already in the shadow tree.
    #[error("the member is already present in the shadow tree")]
    MemberAlreadyPresent,
}

impl BinaryToQuaternaryLeafMapping {
    /// Sorts occupied members by bytewise canonical identifier and assigns
    /// quaternary leaf ordinals `0..n` in left-to-right order.
    pub fn from_binary_members(
        mut members: Vec<BinaryLeafMember>,
    ) -> Result<Self, AdaptiveTreeError> {
        validate_members(&members)?;
        members.sort_by(|left, right| left.member_id.cmp(&right.member_id));

        let assignments = members
            .into_iter()
            .enumerate()
            .map(|(ordinal, member)| LeafAssignment {
                member_id: member.member_id,
                binary_leaf_index: member.binary_leaf_index,
                quaternary_leaf_ordinal: ordinal as u32,
            })
            .collect();
        let mapping = Self {
            version: LEAF_MAPPING_VERSION,
            assignments,
        };
        mapping.validate()?;
        Ok(mapping)
    }

    /// Validates the version, canonical order, source uniqueness, and exact
    /// left-to-right ordinal assignment.
    pub fn validate(&self) -> Result<(), AdaptiveTreeError> {
        if self.version != LEAF_MAPPING_VERSION {
            return Err(AdaptiveTreeError::UnsupportedMappingVersion);
        }
        let members = self
            .assignments
            .iter()
            .map(|assignment| BinaryLeafMember {
                member_id: assignment.member_id.clone(),
                binary_leaf_index: assignment.binary_leaf_index,
            })
            .collect::<Vec<_>>();
        validate_members(&members)?;
        for (ordinal, assignment) in self.assignments.iter().enumerate() {
            if assignment.quaternary_leaf_ordinal != ordinal as u32
                || ordinal > 0 && self.assignments[ordinal - 1].member_id >= assignment.member_id
            {
                return Err(AdaptiveTreeError::NonCanonicalMapping);
            }
        }
        Ok(())
    }

    /// Serializes the complete mapping in the project-local canonical format.
    /// The bytes are intended for a later authenticated transition extension;
    /// they are not an RFC 9420 MLS extension by themselves.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, AdaptiveTreeError> {
        self.validate()?;
        let count = u32::try_from(self.assignments.len())
            .map_err(|_| AdaptiveTreeError::CapacityOverflow)?;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&MAPPING_MAGIC);
        bytes.extend_from_slice(&self.version.to_be_bytes());
        bytes.extend_from_slice(&count.to_be_bytes());
        for assignment in &self.assignments {
            let member_id_length = u16::try_from(assignment.member_id.len())
                .map_err(|_| AdaptiveTreeError::CapacityOverflow)?;
            bytes.extend_from_slice(&member_id_length.to_be_bytes());
            bytes.extend_from_slice(&assignment.member_id);
            bytes.extend_from_slice(&assignment.binary_leaf_index.to_be_bytes());
            bytes.extend_from_slice(&assignment.quaternary_leaf_ordinal.to_be_bytes());
        }
        Ok(bytes)
    }

    /// Decodes and validates canonical mapping bytes.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, AdaptiveTreeError> {
        let mut reader = ByteReader::new(bytes);
        if reader.take_array::<4>()? != MAPPING_MAGIC {
            return Err(AdaptiveTreeError::MalformedEncoding);
        }
        let version = u16::from_be_bytes(reader.take_array()?);
        let count = u32::from_be_bytes(reader.take_array()?);
        if count as usize > reader.remaining() / 10 {
            return Err(AdaptiveTreeError::MalformedEncoding);
        }
        let mut assignments = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let member_id_length = u16::from_be_bytes(reader.take_array()?) as usize;
            let member_id = reader.take(member_id_length)?.to_vec();
            let binary_leaf_index = u32::from_be_bytes(reader.take_array()?);
            let quaternary_leaf_ordinal = u32::from_be_bytes(reader.take_array()?);
            assignments.push(LeafAssignment {
                member_id,
                binary_leaf_index,
                quaternary_leaf_ordinal,
            });
        }
        if !reader.is_empty() {
            return Err(AdaptiveTreeError::TrailingData);
        }
        let mapping = Self {
            version,
            assignments,
        };
        mapping.validate()?;
        Ok(mapping)
    }
}

impl ShadowQuaternaryTree {
    /// Builds an immutable candidate topology from a validated mapping.
    pub fn from_mapping(mapping: BinaryToQuaternaryLeafMapping) -> Result<Self, AdaptiveTreeError> {
        mapping.validate()?;
        let height = quaternary_height(mapping.assignments.len())?;
        let leaf_capacity = quaternary_capacity(height)?;
        let occupants = mapping
            .assignments
            .iter()
            .map(|assignment| ShadowOccupant {
                member_id: assignment.member_id.clone(),
                quaternary_leaf_ordinal: assignment.quaternary_leaf_ordinal,
                binary_leaf_index: Some(assignment.binary_leaf_index),
            })
            .collect();
        Ok(Self {
            mapping,
            occupants,
            height,
            leaf_capacity,
        })
    }

    /// Returns the fixed candidate arity, four.
    pub const fn arity(&self) -> u8 {
        QUATERNARY_ARITY
    }

    /// Returns the minimum complete-tree height accommodating the population.
    pub const fn height(&self) -> u8 {
        self.height
    }

    /// Returns the complete candidate tree's leaf capacity.
    pub const fn leaf_capacity(&self) -> u32 {
        self.leaf_capacity
    }

    /// Returns the number of occupied candidate leaves.
    pub fn occupied_leaf_count(&self) -> usize {
        self.occupants.len()
    }

    /// Returns the validated canonical mapping without exposing mutable state.
    pub fn mapping(&self) -> &BinaryToQuaternaryLeafMapping {
        &self.mapping
    }

    /// Returns the root-to-leaf base-four path for one mapped member.
    pub fn leaf_path_for_member(&self, member_id: &[u8]) -> Result<Vec<u8>, AdaptiveTreeError> {
        let occupant = self
            .occupants
            .iter()
            .find(|occupant| occupant.member_id == member_id)
            .ok_or(AdaptiveTreeError::MemberNotFound)?;
        leaf_path(occupant.quaternary_leaf_ordinal, self.height)
    }

    /// Returns the public root-to-leaf node addresses for one mapped member.
    pub fn nodes_for_member(
        &self,
        member_id: &[u8],
    ) -> Result<Vec<QuaternaryNode>, AdaptiveTreeError> {
        let path = self.leaf_path_for_member(member_id)?;
        let mut ordinal = 0_u32;
        let mut nodes = Vec::with_capacity(path.len() + 1);
        nodes.push(QuaternaryNode { depth: 0, ordinal });
        for (index, branch) in path.iter().enumerate() {
            ordinal = ordinal
                .checked_mul(QUATERNARY_ARITY as u32)
                .and_then(|value| value.checked_add(*branch as u32))
                .ok_or(AdaptiveTreeError::CapacityOverflow)?;
            nodes.push(QuaternaryNode {
                depth: index as u8 + 1,
                ordinal,
            });
        }
        Ok(nodes)
    }

    /// Returns candidate leaf ordinals in ascending public order.
    pub fn occupied_leaf_ordinals(&self) -> Vec<u32> {
        let mut ordinals = self
            .occupants
            .iter()
            .map(|occupant| occupant.quaternary_leaf_ordinal)
            .collect::<Vec<_>>();
        ordinals.sort_unstable();
        ordinals
    }

    /// Replays a public logical operation by returning a separate immutable
    /// candidate topology. It never mutates `self`, reads MLS state, or uses
    /// random input.
    pub fn replay(&self, operation: ShadowOperation) -> Result<ShadowReplay, AdaptiveTreeError> {
        match &operation {
            ShadowOperation::Update { member_id } => {
                self.require_present(member_id)?;
                Ok(ShadowReplay {
                    operation,
                    population_before: self.occupied_leaf_count(),
                    population_after: self.occupied_leaf_count(),
                    topology_changed: false,
                    assigned_leaf_ordinal: None,
                    vacated_leaf_ordinal: None,
                    tree: self.clone(),
                })
            }
            ShadowOperation::Add { member_id } => {
                validate_member_id(member_id)?;
                if self.find_occupant(member_id).is_some() {
                    return Err(AdaptiveTreeError::MemberAlreadyPresent);
                }
                let (height, leaf_capacity) = self.capacity_for_add()?;
                let assigned_leaf_ordinal = self.lowest_vacant_leaf(leaf_capacity)?;
                let mut occupants = self.occupants.clone();
                occupants.push(ShadowOccupant {
                    member_id: member_id.clone(),
                    quaternary_leaf_ordinal: assigned_leaf_ordinal,
                    binary_leaf_index: None,
                });
                let tree = self.with_occupants(occupants, height, leaf_capacity)?;
                Ok(ShadowReplay {
                    operation,
                    population_before: self.occupied_leaf_count(),
                    population_after: tree.occupied_leaf_count(),
                    topology_changed: true,
                    assigned_leaf_ordinal: Some(assigned_leaf_ordinal),
                    vacated_leaf_ordinal: None,
                    tree,
                })
            }
            ShadowOperation::Remove { member_id } => {
                let removed = self.require_present(member_id)?;
                let occupants = self
                    .occupants
                    .iter()
                    .filter(|occupant| occupant.member_id.as_slice() != member_id.as_slice())
                    .cloned()
                    .collect();
                let tree = self.with_occupants(occupants, self.height, self.leaf_capacity)?;
                Ok(ShadowReplay {
                    operation,
                    population_before: self.occupied_leaf_count(),
                    population_after: tree.occupied_leaf_count(),
                    topology_changed: true,
                    assigned_leaf_ordinal: None,
                    vacated_leaf_ordinal: Some(removed.quaternary_leaf_ordinal),
                    tree,
                })
            }
        }
    }

    fn find_occupant(&self, member_id: &[u8]) -> Option<&ShadowOccupant> {
        self.occupants
            .iter()
            .find(|occupant| occupant.member_id == member_id)
    }

    fn require_present(&self, member_id: &[u8]) -> Result<&ShadowOccupant, AdaptiveTreeError> {
        validate_member_id(member_id)?;
        self.find_occupant(member_id)
            .ok_or(AdaptiveTreeError::MemberNotFound)
    }

    fn capacity_for_add(&self) -> Result<(u8, u32), AdaptiveTreeError> {
        if self.occupied_leaf_count() < self.leaf_capacity as usize {
            return Ok((self.height, self.leaf_capacity));
        }
        let height = self
            .height
            .checked_add(1)
            .ok_or(AdaptiveTreeError::CapacityOverflow)?;
        Ok((height, quaternary_capacity(height)?))
    }

    fn lowest_vacant_leaf(&self, capacity: u32) -> Result<u32, AdaptiveTreeError> {
        let occupied = self.occupied_leaf_ordinals();
        (0..capacity)
            .find(|candidate| occupied.binary_search(candidate).is_err())
            .ok_or(AdaptiveTreeError::CapacityOverflow)
    }

    fn with_occupants(
        &self,
        occupants: Vec<ShadowOccupant>,
        height: u8,
        leaf_capacity: u32,
    ) -> Result<Self, AdaptiveTreeError> {
        validate_occupants(&occupants, leaf_capacity)?;
        Ok(Self {
            mapping: self.mapping.clone(),
            occupants,
            height,
            leaf_capacity,
        })
    }
}

fn validate_members(members: &[BinaryLeafMember]) -> Result<(), AdaptiveTreeError> {
    if members.is_empty() {
        return Err(AdaptiveTreeError::EmptyPopulation);
    }
    for member in members {
        validate_member_id(&member.member_id)?;
    }
    let mut member_ids = members
        .iter()
        .map(|member| member.member_id.as_slice())
        .collect::<Vec<_>>();
    member_ids.sort_unstable();
    if member_ids.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(AdaptiveTreeError::DuplicateMemberId);
    }
    let mut leaf_indexes = members
        .iter()
        .map(|member| member.binary_leaf_index)
        .collect::<Vec<_>>();
    leaf_indexes.sort_unstable();
    if leaf_indexes.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(AdaptiveTreeError::DuplicateBinaryLeaf);
    }
    Ok(())
}

fn validate_member_id(member_id: &[u8]) -> Result<(), AdaptiveTreeError> {
    if member_id.is_empty() {
        return Err(AdaptiveTreeError::EmptyMemberId);
    }
    Ok(())
}

fn validate_occupants(
    occupants: &[ShadowOccupant],
    leaf_capacity: u32,
) -> Result<(), AdaptiveTreeError> {
    if occupants.is_empty() {
        return Err(AdaptiveTreeError::EmptyPopulation);
    }
    let mut member_ids = Vec::with_capacity(occupants.len());
    let mut leaf_ordinals = Vec::with_capacity(occupants.len());
    for occupant in occupants {
        validate_member_id(&occupant.member_id)?;
        if occupant.quaternary_leaf_ordinal >= leaf_capacity {
            return Err(AdaptiveTreeError::CapacityOverflow);
        }
        member_ids.push(occupant.member_id.as_slice());
        leaf_ordinals.push(occupant.quaternary_leaf_ordinal);
    }
    member_ids.sort_unstable();
    if member_ids.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(AdaptiveTreeError::DuplicateMemberId);
    }
    leaf_ordinals.sort_unstable();
    if leaf_ordinals.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(AdaptiveTreeError::NonCanonicalMapping);
    }
    Ok(())
}

fn quaternary_height(population: usize) -> Result<u8, AdaptiveTreeError> {
    if population == 0 {
        return Err(AdaptiveTreeError::EmptyPopulation);
    }
    let mut height = 0_u8;
    let mut capacity = 1_usize;
    while capacity < population {
        capacity = capacity
            .checked_mul(QUATERNARY_ARITY as usize)
            .ok_or(AdaptiveTreeError::CapacityOverflow)?;
        height = height
            .checked_add(1)
            .ok_or(AdaptiveTreeError::CapacityOverflow)?;
    }
    Ok(height)
}

fn quaternary_capacity(height: u8) -> Result<u32, AdaptiveTreeError> {
    (0..height).try_fold(1_u32, |capacity, _| {
        capacity
            .checked_mul(QUATERNARY_ARITY as u32)
            .ok_or(AdaptiveTreeError::CapacityOverflow)
    })
}

fn leaf_path(ordinal: u32, height: u8) -> Result<Vec<u8>, AdaptiveTreeError> {
    if ordinal >= quaternary_capacity(height)? {
        return Err(AdaptiveTreeError::CapacityOverflow);
    }
    let mut path = vec![0_u8; height as usize];
    let mut remaining = ordinal;
    for branch in path.iter_mut().rev() {
        *branch = (remaining % QUATERNARY_ARITY as u32) as u8;
        remaining /= QUATERNARY_ARITY as u32;
    }
    Ok(path)
}

struct ByteReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> ByteReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], AdaptiveTreeError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(AdaptiveTreeError::MalformedEncoding)?;
        let output = self
            .bytes
            .get(self.offset..end)
            .ok_or(AdaptiveTreeError::MalformedEncoding)?;
        self.offset = end;
        Ok(output)
    }

    fn take_array<const N: usize>(&mut self) -> Result<[u8; N], AdaptiveTreeError> {
        self.take(N)?
            .try_into()
            .map_err(|_| AdaptiveTreeError::MalformedEncoding)
    }

    fn is_empty(&self) -> bool {
        self.offset == self.bytes.len()
    }

    fn remaining(&self) -> usize {
        self.bytes.len() - self.offset
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn member(member_id: &[u8], binary_leaf_index: u32) -> BinaryLeafMember {
        BinaryLeafMember {
            member_id: member_id.to_vec(),
            binary_leaf_index,
        }
    }

    #[test]
    fn mapping_sorts_member_ids_bytewise_and_assigns_left_to_right() {
        let mapping = BinaryToQuaternaryLeafMapping::from_binary_members(vec![
            member(b"charlie", 7),
            member(b"alice", 12),
            member(b"bob", 2),
        ])
        .expect("valid mapping");

        assert_eq!(mapping.assignments[0].member_id, b"alice");
        assert_eq!(mapping.assignments[0].binary_leaf_index, 12);
        assert_eq!(mapping.assignments[1].member_id, b"bob");
        assert_eq!(mapping.assignments[1].quaternary_leaf_ordinal, 1);
        assert_eq!(mapping.assignments[2].member_id, b"charlie");
        assert_eq!(mapping.assignments[2].quaternary_leaf_ordinal, 2);
    }

    #[test]
    fn canonical_mapping_bytes_are_order_independent_and_round_trip() {
        let left = BinaryToQuaternaryLeafMapping::from_binary_members(vec![
            member(b"beta", 3),
            member(b"alpha", 9),
        ])
        .expect("valid mapping");
        let right = BinaryToQuaternaryLeafMapping::from_binary_members(vec![
            member(b"alpha", 9),
            member(b"beta", 3),
        ])
        .expect("valid mapping");
        let bytes = left.canonical_bytes().expect("canonical bytes");

        assert_eq!(bytes, right.canonical_bytes().expect("canonical bytes"));
        assert_eq!(
            BinaryToQuaternaryLeafMapping::from_canonical_bytes(&bytes)
                .expect("canonical round trip"),
            left
        );
    }

    #[test]
    fn mapping_rejects_empty_and_duplicate_public_inputs() {
        assert_eq!(
            BinaryToQuaternaryLeafMapping::from_binary_members(Vec::new()),
            Err(AdaptiveTreeError::EmptyPopulation)
        );
        assert_eq!(
            BinaryToQuaternaryLeafMapping::from_binary_members(vec![
                member(b"alice", 1),
                member(b"alice", 2),
            ]),
            Err(AdaptiveTreeError::DuplicateMemberId)
        );
        assert_eq!(
            BinaryToQuaternaryLeafMapping::from_binary_members(vec![
                member(b"alice", 1),
                member(b"bob", 1),
            ]),
            Err(AdaptiveTreeError::DuplicateBinaryLeaf)
        );
    }

    #[test]
    fn canonical_mapping_rejects_malformed_and_trailing_bytes() {
        let mapping = BinaryToQuaternaryLeafMapping::from_binary_members(vec![member(b"alice", 1)])
            .expect("valid mapping");
        let mut bytes = mapping.canonical_bytes().expect("canonical bytes");
        bytes.push(0);
        assert_eq!(
            BinaryToQuaternaryLeafMapping::from_canonical_bytes(&bytes),
            Err(AdaptiveTreeError::TrailingData)
        );
        assert_eq!(
            BinaryToQuaternaryLeafMapping::from_canonical_bytes(&MAPPING_MAGIC),
            Err(AdaptiveTreeError::MalformedEncoding)
        );
    }

    #[test]
    fn immutable_shadow_tree_has_the_expected_128_member_shape() {
        let members = (0..128)
            .map(|index| member(format!("member-{index:03}").as_bytes(), index))
            .collect();
        let mapping = BinaryToQuaternaryLeafMapping::from_binary_members(members)
            .expect("valid 128-member mapping");
        let shadow = ShadowQuaternaryTree::from_mapping(mapping).expect("shadow tree");
        let before = shadow.clone();

        assert_eq!(shadow.arity(), 4);
        assert_eq!(shadow.height(), 4);
        assert_eq!(shadow.leaf_capacity(), 256);
        assert_eq!(shadow.occupied_leaf_count(), 128);
        assert_eq!(
            shadow
                .leaf_path_for_member(b"member-127")
                .expect("mapped member"),
            vec![1, 3, 3, 3]
        );
        assert_eq!(
            shadow.nodes_for_member(b"member-127").expect("node path"),
            vec![
                QuaternaryNode {
                    depth: 0,
                    ordinal: 0
                },
                QuaternaryNode {
                    depth: 1,
                    ordinal: 1
                },
                QuaternaryNode {
                    depth: 2,
                    ordinal: 7
                },
                QuaternaryNode {
                    depth: 3,
                    ordinal: 31
                },
                QuaternaryNode {
                    depth: 4,
                    ordinal: 127
                },
            ]
        );
        assert_eq!(shadow, before);
    }

    #[test]
    fn replay_returns_a_new_tree_without_renumbering_existing_members() {
        let mapping = BinaryToQuaternaryLeafMapping::from_binary_members(vec![
            member(b"alice", 2),
            member(b"bob", 9),
        ])
        .expect("valid mapping");
        let shadow = ShadowQuaternaryTree::from_mapping(mapping).expect("shadow tree");
        let before = shadow.clone();

        let update = shadow
            .replay(ShadowOperation::Update {
                member_id: b"alice".to_vec(),
            })
            .expect("update replay");
        assert!(!update.topology_changed);
        assert_eq!(update.tree, shadow);

        let removal = shadow
            .replay(ShadowOperation::Remove {
                member_id: b"bob".to_vec(),
            })
            .expect("remove replay");
        assert_eq!(removal.vacated_leaf_ordinal, Some(1));
        assert_eq!(removal.tree.occupied_leaf_ordinals(), vec![0]);

        let addition = removal
            .tree
            .replay(ShadowOperation::Add {
                member_id: b"charlie".to_vec(),
            })
            .expect("add replay");
        assert_eq!(addition.assigned_leaf_ordinal, Some(1));
        assert_eq!(addition.tree.occupied_leaf_ordinals(), vec![0, 1]);
        assert_eq!(shadow, before);
    }

    #[test]
    fn replay_expands_only_when_the_candidate_tree_is_full() {
        let members = (0..4)
            .map(|index| member(format!("member-{index}").as_bytes(), index))
            .collect();
        let shadow = ShadowQuaternaryTree::from_mapping(
            BinaryToQuaternaryLeafMapping::from_binary_members(members).expect("valid mapping"),
        )
        .expect("shadow tree");
        assert_eq!(shadow.height(), 1);
        assert_eq!(shadow.leaf_capacity(), 4);

        let addition = shadow
            .replay(ShadowOperation::Add {
                member_id: b"new-member".to_vec(),
            })
            .expect("add replay");
        assert_eq!(addition.assigned_leaf_ordinal, Some(4));
        assert_eq!(addition.tree.height(), 2);
        assert_eq!(addition.tree.leaf_capacity(), 16);
        assert_eq!(shadow.leaf_capacity(), 4);
    }
}
