#![forbid(unsafe_code)]

//! Deterministic workload and convergence-simulation boundary.
//!
//! Task 52 provides public, deterministic committer schedules only. Task 53
//! applies logical workloads and Task 54 records complete per-commit metrics.

use std::collections::{BTreeMap, BTreeSet};

use rand::{distributions::Distribution, distributions::WeightedIndex, Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use thiserror::Error;

/// One active public member eligible to commit in a future workload.
///
/// Inputs must be sorted by `member_index`; leaf indexes and regions are
/// public topology labels, never secret-tree values.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EligibleCommitter {
    /// Stable public experiment member identifier.
    pub member_index: u32,
    /// Current public leaf index for topology-aware scheduling.
    pub leaf_index: u32,
    /// Public leaf-region label chosen by the workload configuration.
    pub leaf_region: u32,
}

/// One non-zero public weight for weighted-random scheduling.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitterWeight {
    /// Public member to select when this weighted entry is drawn.
    pub member_index: u32,
    /// Relative positive selection weight.
    pub weight: u32,
}

/// The five supported public committer scheduling policies.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CommitterStrategy {
    /// Cycle active members in canonical member-index order.
    RoundRobin,
    /// Uniformly select active members with a public deterministic seed.
    SeededRandom {
        /// Public schedule seed; it is not cryptographic entropy.
        seed: u64,
    },
    /// Cycle an explicit non-empty, duplicate-free member list in supplied order.
    FixedList {
        /// Explicit public member-index cycle.
        member_indexes: Vec<u32>,
    },
    /// Draw from explicit positive member weights using a public deterministic seed.
    WeightedRandom {
        /// Public schedule seed; it is not cryptographic entropy.
        seed: u64,
        /// Canonically ordered member weights.
        weights: Vec<CommitterWeight>,
    },
    /// Balance selections across leaf regions, then across members in each region.
    LeafRegionBalanced,
}

/// One planned committer selection before any MLS operation is attempted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitterSelection {
    /// One-based sequence number in this schedule.
    pub sequence: u32,
    /// Selected public member identifier.
    pub member_index: u32,
    /// Selected member's public current leaf index.
    pub leaf_index: u32,
    /// Selected member's public leaf-region label.
    pub leaf_region: u32,
}

/// Actual count of selections for one eligible member, including zero.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemberSelectionDistribution {
    /// Eligible public member identifier.
    pub member_index: u32,
    /// Current public leaf index retained for topology provenance.
    pub leaf_index: u32,
    /// Current public leaf-region label.
    pub leaf_region: u32,
    /// Number of emitted schedule selections for this member.
    pub selection_count: u32,
}

/// Actual count of selections for one eligible leaf region, including zero.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegionSelectionDistribution {
    /// Public leaf-region label.
    pub leaf_region: u32,
    /// Number of active public members in this region.
    pub eligible_member_count: u32,
    /// Number of emitted schedule selections in this region.
    pub selection_count: u32,
}

/// A complete deterministic schedule and its actual public distribution facts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitterSchedule {
    /// Selected strategy, retained for report provenance.
    pub strategy: CommitterStrategy,
    /// Planned selections before Task 53 applies any operation.
    pub selections: Vec<CommitterSelection>,
    /// Zero-inclusive actual selection count for every eligible member.
    pub member_distribution: Vec<MemberSelectionDistribution>,
    /// Zero-inclusive actual selection count for every eligible region.
    pub region_distribution: Vec<RegionSelectionDistribution>,
}

/// Errors from validating public scheduling input or building a schedule.
#[derive(Debug, Error, Eq, PartialEq)]
pub enum CommitterScheduleError {
    /// At least one active public member is required.
    #[error("committer scheduling requires at least one eligible member")]
    EmptyEligibleMembers,
    /// Candidate members must be strictly ordered by public member index.
    #[error("eligible members must be in strictly increasing member-index order")]
    NonCanonicalMemberOrder,
    /// Two public members claim the same current leaf index.
    #[error("eligible members contain a duplicate leaf index")]
    DuplicateLeafIndex,
    /// The fixed strategy requires a cycle with at least one member.
    #[error("the fixed committer list is empty")]
    EmptyFixedList,
    /// The fixed strategy names a member absent from the active set.
    #[error("the fixed committer list names a member that is not eligible")]
    FixedMemberNotEligible,
    /// The fixed strategy names the same member more than once.
    #[error("the fixed committer list contains a duplicate member")]
    DuplicateFixedMember,
    /// Weighted scheduling requires at least one weighted member.
    #[error("the weighted committer list is empty")]
    EmptyWeightedList,
    /// Weighted entries must be strictly ordered by public member index.
    #[error("weighted members must be in strictly increasing member-index order")]
    NonCanonicalWeightOrder,
    /// Weighted scheduling names a member absent from the active set.
    #[error("the weighted committer list names a member that is not eligible")]
    WeightedMemberNotEligible,
    /// Zero weights are ambiguous and prohibited.
    #[error("committer weights must be positive")]
    ZeroWeight,
    /// The public weight sum cannot be represented safely.
    #[error("committer weight total overflowed")]
    WeightTotalOverflow,
    /// The requested schedule cannot be represented or allocated safely.
    #[error("the requested committer schedule is too large")]
    ScheduleTooLarge,
}

/// Builds a deterministic public committer schedule without mutating MLS state.
pub fn build_committer_schedule(
    eligible_members: &[EligibleCommitter],
    strategy: CommitterStrategy,
    selection_count: u32,
) -> Result<CommitterSchedule, CommitterScheduleError> {
    validate_eligible_members(eligible_members)?;
    let selection_count_usize =
        usize::try_from(selection_count).map_err(|_| CommitterScheduleError::ScheduleTooLarge)?;
    let mut selected_indexes = Vec::new();
    selected_indexes
        .try_reserve(selection_count_usize)
        .map_err(|_| CommitterScheduleError::ScheduleTooLarge)?;

    match &strategy {
        CommitterStrategy::RoundRobin => {
            for sequence in 0..selection_count_usize {
                selected_indexes.push(sequence % eligible_members.len());
            }
        }
        CommitterStrategy::SeededRandom { seed } => {
            let mut rng = ChaCha20Rng::seed_from_u64(*seed);
            for _ in 0..selection_count_usize {
                selected_indexes.push(rng.gen_range(0..eligible_members.len()));
            }
        }
        CommitterStrategy::FixedList { member_indexes } => {
            let cycle = fixed_cycle(eligible_members, member_indexes)?;
            for sequence in 0..selection_count_usize {
                selected_indexes.push(cycle[sequence % cycle.len()]);
            }
        }
        CommitterStrategy::WeightedRandom { seed, weights } => {
            let (weighted_indexes, distribution) =
                weighted_distribution(eligible_members, weights)?;
            let mut rng = ChaCha20Rng::seed_from_u64(*seed);
            for _ in 0..selection_count_usize {
                selected_indexes.push(weighted_indexes[distribution.sample(&mut rng)]);
            }
        }
        CommitterStrategy::LeafRegionBalanced => {
            selected_indexes =
                leaf_region_balanced_indexes(eligible_members, selection_count_usize)?;
        }
    }

    schedule_from_indexes(eligible_members, strategy, selected_indexes)
}

fn validate_eligible_members(
    eligible_members: &[EligibleCommitter],
) -> Result<(), CommitterScheduleError> {
    if eligible_members.is_empty() {
        return Err(CommitterScheduleError::EmptyEligibleMembers);
    }
    if eligible_members
        .windows(2)
        .any(|pair| pair[0].member_index >= pair[1].member_index)
    {
        return Err(CommitterScheduleError::NonCanonicalMemberOrder);
    }
    let mut leaves = BTreeSet::new();
    if eligible_members
        .iter()
        .any(|member| !leaves.insert(member.leaf_index))
    {
        return Err(CommitterScheduleError::DuplicateLeafIndex);
    }
    Ok(())
}

fn fixed_cycle(
    eligible_members: &[EligibleCommitter],
    member_indexes: &[u32],
) -> Result<Vec<usize>, CommitterScheduleError> {
    if member_indexes.is_empty() {
        return Err(CommitterScheduleError::EmptyFixedList);
    }
    let positions = member_positions(eligible_members);
    let mut seen = BTreeSet::new();
    member_indexes
        .iter()
        .map(|member_index| {
            if !seen.insert(*member_index) {
                return Err(CommitterScheduleError::DuplicateFixedMember);
            }
            positions
                .get(member_index)
                .copied()
                .ok_or(CommitterScheduleError::FixedMemberNotEligible)
        })
        .collect()
}

fn weighted_distribution(
    eligible_members: &[EligibleCommitter],
    weights: &[CommitterWeight],
) -> Result<(Vec<usize>, WeightedIndex<u32>), CommitterScheduleError> {
    if weights.is_empty() {
        return Err(CommitterScheduleError::EmptyWeightedList);
    }
    if weights
        .windows(2)
        .any(|pair| pair[0].member_index >= pair[1].member_index)
    {
        return Err(CommitterScheduleError::NonCanonicalWeightOrder);
    }
    let positions = member_positions(eligible_members);
    let mut total = 0_u64;
    let mut indexes = Vec::with_capacity(weights.len());
    let mut values = Vec::with_capacity(weights.len());
    for weighted_member in weights {
        if weighted_member.weight == 0 {
            return Err(CommitterScheduleError::ZeroWeight);
        }
        total = total
            .checked_add(u64::from(weighted_member.weight))
            .ok_or(CommitterScheduleError::WeightTotalOverflow)?;
        indexes.push(
            positions
                .get(&weighted_member.member_index)
                .copied()
                .ok_or(CommitterScheduleError::WeightedMemberNotEligible)?,
        );
        values.push(weighted_member.weight);
    }
    let distribution =
        WeightedIndex::new(values).map_err(|_| CommitterScheduleError::WeightTotalOverflow)?;
    Ok((indexes, distribution))
}

fn leaf_region_balanced_indexes(
    eligible_members: &[EligibleCommitter],
    selection_count: usize,
) -> Result<Vec<usize>, CommitterScheduleError> {
    let mut regions: BTreeMap<u32, Vec<usize>> = BTreeMap::new();
    for (index, member) in eligible_members.iter().enumerate() {
        regions.entry(member.leaf_region).or_default().push(index);
    }
    for candidates in regions.values_mut() {
        candidates.sort_unstable_by_key(|index| {
            (
                eligible_members[*index].leaf_index,
                eligible_members[*index].member_index,
            )
        });
    }
    let mut region_counts = BTreeMap::<u32, u32>::new();
    let mut member_counts = vec![0_u32; eligible_members.len()];
    let mut selected = Vec::new();
    selected
        .try_reserve(selection_count)
        .map_err(|_| CommitterScheduleError::ScheduleTooLarge)?;
    for _ in 0..selection_count {
        let (&region, candidates) = regions
            .iter()
            .min_by_key(|(region, _)| (region_counts.get(region).copied().unwrap_or(0), **region))
            .expect("non-empty eligible members create at least one region");
        let &member_index = candidates
            .iter()
            .min_by_key(|index| {
                (
                    member_counts[**index],
                    eligible_members[**index].leaf_index,
                    eligible_members[**index].member_index,
                )
            })
            .expect("each region has at least one eligible member");
        *region_counts.entry(region).or_default() += 1;
        member_counts[member_index] += 1;
        selected.push(member_index);
    }
    Ok(selected)
}

fn schedule_from_indexes(
    eligible_members: &[EligibleCommitter],
    strategy: CommitterStrategy,
    selected_indexes: Vec<usize>,
) -> Result<CommitterSchedule, CommitterScheduleError> {
    let mut member_counts = vec![0_u32; eligible_members.len()];
    let mut region_counts = BTreeMap::<u32, u32>::new();
    let selections = selected_indexes
        .into_iter()
        .enumerate()
        .map(|(offset, selected_index)| {
            let member = eligible_members
                .get(selected_index)
                .expect("strategy indexes are constructed from eligible members");
            member_counts[selected_index] += 1;
            *region_counts.entry(member.leaf_region).or_default() += 1;
            Ok(CommitterSelection {
                sequence: u32::try_from(offset + 1)
                    .map_err(|_| CommitterScheduleError::ScheduleTooLarge)?,
                member_index: member.member_index,
                leaf_index: member.leaf_index,
                leaf_region: member.leaf_region,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let member_distribution = eligible_members
        .iter()
        .zip(member_counts)
        .map(|(member, selection_count)| MemberSelectionDistribution {
            member_index: member.member_index,
            leaf_index: member.leaf_index,
            leaf_region: member.leaf_region,
            selection_count,
        })
        .collect();
    let region_member_counts =
        eligible_members
            .iter()
            .fold(BTreeMap::new(), |mut counts, member| {
                *counts.entry(member.leaf_region).or_insert(0_u32) += 1;
                counts
            });
    let region_distribution = region_member_counts
        .into_iter()
        .map(
            |(leaf_region, eligible_member_count)| RegionSelectionDistribution {
                leaf_region,
                eligible_member_count,
                selection_count: region_counts.get(&leaf_region).copied().unwrap_or(0),
            },
        )
        .collect();
    Ok(CommitterSchedule {
        strategy,
        selections,
        member_distribution,
        region_distribution,
    })
}

fn member_positions(eligible_members: &[EligibleCommitter]) -> BTreeMap<u32, usize> {
    eligible_members
        .iter()
        .enumerate()
        .map(|(index, member)| (member.member_index, index))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn members() -> Vec<EligibleCommitter> {
        vec![
            EligibleCommitter {
                member_index: 0,
                leaf_index: 0,
                leaf_region: 0,
            },
            EligibleCommitter {
                member_index: 1,
                leaf_index: 1,
                leaf_region: 0,
            },
            EligibleCommitter {
                member_index: 2,
                leaf_index: 2,
                leaf_region: 1,
            },
            EligibleCommitter {
                member_index: 3,
                leaf_index: 3,
                leaf_region: 1,
            },
        ]
    }

    fn selected_members(schedule: &CommitterSchedule) -> Vec<u32> {
        schedule
            .selections
            .iter()
            .map(|selection| selection.member_index)
            .collect()
    }

    #[test]
    fn round_robin_cycles_canonical_members_and_reports_zero_inclusive_distribution() {
        let schedule = build_committer_schedule(&members(), CommitterStrategy::RoundRobin, 5)
            .expect("canonical round robin");
        assert_eq!(selected_members(&schedule), vec![0, 1, 2, 3, 0]);
        assert_eq!(
            schedule
                .member_distribution
                .iter()
                .map(|entry| entry.selection_count)
                .collect::<Vec<_>>(),
            vec![2, 1, 1, 1]
        );
        assert_eq!(
            schedule
                .region_distribution
                .iter()
                .map(|entry| (
                    entry.leaf_region,
                    entry.eligible_member_count,
                    entry.selection_count
                ))
                .collect::<Vec<_>>(),
            vec![(0, 2, 3), (1, 2, 2)]
        );
    }

    #[test]
    fn seeded_fixed_and_weighted_strategies_are_reproducible_and_constrained_to_eligible_members() {
        let seeded_first =
            build_committer_schedule(&members(), CommitterStrategy::SeededRandom { seed: 42 }, 12)
                .expect("seeded schedule");
        let seeded_second =
            build_committer_schedule(&members(), CommitterStrategy::SeededRandom { seed: 42 }, 12)
                .expect("same seeded schedule");
        assert_eq!(seeded_first, seeded_second);

        let fixed = build_committer_schedule(
            &members(),
            CommitterStrategy::FixedList {
                member_indexes: vec![3, 1],
            },
            5,
        )
        .expect("fixed schedule");
        assert_eq!(selected_members(&fixed), vec![3, 1, 3, 1, 3]);

        let weighted = build_committer_schedule(
            &members(),
            CommitterStrategy::WeightedRandom {
                seed: 7,
                weights: vec![
                    CommitterWeight {
                        member_index: 0,
                        weight: 1,
                    },
                    CommitterWeight {
                        member_index: 2,
                        weight: 9,
                    },
                ],
            },
            20,
        )
        .expect("weighted schedule");
        assert!(selected_members(&weighted)
            .into_iter()
            .all(|member_index| member_index == 0 || member_index == 2));
    }

    #[test]
    fn leaf_region_balanced_interleaves_regions_then_balances_their_members() {
        let schedule =
            build_committer_schedule(&members(), CommitterStrategy::LeafRegionBalanced, 5)
                .expect("region-balanced schedule");
        assert_eq!(selected_members(&schedule), vec![0, 2, 1, 3, 0]);
        assert_eq!(
            schedule
                .region_distribution
                .iter()
                .map(|entry| entry.selection_count)
                .collect::<Vec<_>>(),
            vec![3, 2]
        );
    }

    #[test]
    fn scheduling_rejects_noncanonical_or_unsafe_public_inputs() {
        assert_eq!(
            build_committer_schedule(&[], CommitterStrategy::RoundRobin, 1),
            Err(CommitterScheduleError::EmptyEligibleMembers)
        );
        let mut unordered = members();
        unordered.swap(0, 1);
        assert_eq!(
            build_committer_schedule(&unordered, CommitterStrategy::RoundRobin, 1),
            Err(CommitterScheduleError::NonCanonicalMemberOrder)
        );
        assert_eq!(
            build_committer_schedule(
                &members(),
                CommitterStrategy::FixedList {
                    member_indexes: vec![1, 1],
                },
                1,
            ),
            Err(CommitterScheduleError::DuplicateFixedMember)
        );
        assert_eq!(
            build_committer_schedule(
                &members(),
                CommitterStrategy::WeightedRandom {
                    seed: 1,
                    weights: vec![CommitterWeight {
                        member_index: 1,
                        weight: 0,
                    }],
                },
                1,
            ),
            Err(CommitterScheduleError::ZeroWeight)
        );
    }
}
