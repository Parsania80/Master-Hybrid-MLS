#![forbid(unsafe_code)]

//! Deterministic workload and convergence-simulation boundary.
//!
//! Task 52 provides public, deterministic committer schedules only. Task 53
//! applies logical workloads and Task 54 records complete per-commit metrics.

use std::collections::{BTreeMap, BTreeSet};

use rand::{distributions::Distribution, distributions::WeightedIndex, Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use thiserror::Error;

use mls_adapter::{BaselineClient, BaselineError, BaselineState, InboundEvent, OutboundCommit};

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

/// The public logical operation requested by a Task 53 workload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkloadOperation {
    /// A standard MLS self-update by the selected committer.
    Update,
    /// A standard MLS Add of the named new stable member index.
    Add {
        /// Stable public member index allocated by the harness.
        member_index: u32,
    },
    /// A standard MLS Remove of one active stable member index.
    Remove {
        /// Stable public member index removed by the commit.
        member_index: u32,
    },
}

/// The five deterministic Task 53 workload families.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkloadProfile {
    /// Every accepted operation is a self-update.
    UpdateOnly,
    /// Repeats update, add, remove; infeasible membership operations become updates.
    Mixed,
    /// Prefers three removes for each update; infeasible removes add when possible.
    RemovalHeavy,
    /// Uses the mixed operation cycle and prefers committers in one public region.
    RegionSkewed {
        /// Preferred public leaf-region label.
        preferred_region: u32,
    },
    /// Uniformly draws update/add/remove requests from a public deterministic seed.
    Uniform {
        /// Public workload seed; it is not cryptographic entropy.
        seed: u64,
    },
}

/// Public configuration for one in-process baseline workload execution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BaselineWorkloadConfig {
    /// Non-empty public group identifier for the fresh baseline group.
    pub group_id: Vec<u8>,
    /// Initial active members; Task 53 requires at least two.
    pub initial_member_count: u32,
    /// Maximum active members permitted by Add workload operations.
    pub maximum_member_count: u32,
    /// Number of accepted workload commits to attempt.
    pub operation_count: u32,
    /// Number of deterministic public regions used for stable member labels.
    pub region_count: u32,
    /// Task 52 committer selector applied against current active members.
    pub committer_strategy: CommitterStrategy,
    /// Task 53 logical workload family.
    pub workload_profile: WorkloadProfile,
}

/// One accepted, fully delivered baseline workload commit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcceptedWorkloadOperation {
    /// One-based accepted-workload sequence number.
    pub sequence: u32,
    /// Public stable index of the member that staged the commit.
    pub committer_member_index: u32,
    /// Actual logical operation applied by the harness after feasibility checks.
    pub operation: WorkloadOperation,
    /// Public epoch before the accepted commit.
    pub epoch_before: u64,
    /// Public epoch after all valid members accepted the commit.
    pub epoch_after: u64,
    /// Active members after the accepted commit.
    pub active_member_count: u32,
}

/// Actual committer use count from an executed workload, including zero for final active members.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutedCommitterCount {
    /// Stable public member index.
    pub member_index: u32,
    /// Number of accepted commits staged by this member.
    pub accepted_commit_count: u32,
}

/// Safe public outcome of a fully converged baseline workload execution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BaselineWorkloadExecution {
    /// Every accepted and fully delivered operation in order.
    pub accepted_operations: Vec<AcceptedWorkloadOperation>,
    /// Actual public committer use counts for final active members.
    pub final_active_committer_counts: Vec<ExecutedCommitterCount>,
    /// Final converged public MLS epoch.
    pub final_epoch: u64,
    /// Final number of valid active members.
    pub final_member_count: u32,
}

/// Errors from Task 53 baseline workload planning or execution.
#[derive(Debug, Error)]
pub enum WorkloadExecutionError {
    /// The fresh group identifier must be non-empty.
    #[error("the workload group identifier is empty")]
    EmptyGroupId,
    /// At least two active members are required to preserve a valid committer during removal.
    #[error("the workload requires at least two initial members")]
    InitialMemberCountTooSmall,
    /// Maximum membership must permit the initial public group.
    #[error("the maximum member count is below the initial member count")]
    MaximumMemberCountTooSmall,
    /// Public region labels require a positive region count.
    #[error("the workload region count must be positive")]
    ZeroRegionCount,
    /// A stable public member index could not be allocated.
    #[error("the workload member index overflowed")]
    MemberIndexOverflow,
    /// Task 52 could not select an active public committer.
    #[error("the workload committer schedule is invalid")]
    Schedule(#[from] CommitterScheduleError),
    /// The maintained baseline adapter rejected an MLS operation.
    #[error("the baseline MLS operation failed")]
    Baseline(#[from] BaselineError),
    /// A valid member did not merge an expected delivered commit.
    #[error("a valid workload member did not merge the delivered commit")]
    CommitDelivery,
    /// An Add commit did not contain the expected Welcome.
    #[error("an Add workload commit did not contain a Welcome")]
    MissingWelcome,
    /// Public member identities and leaves cannot be reconciled with harness members.
    #[error("the public MLS member state is inconsistent with the workload harness")]
    PublicStateMembershipMismatch,
    /// Valid members do not share identical public MLS state after a commit.
    #[error("valid workload members did not converge on public MLS state")]
    DivergentPublicState,
}

struct ActiveWorkloadMember {
    member_index: u32,
    identity: Vec<u8>,
    leaf_region: u32,
    client: BaselineClient,
}

/// Executes a deterministic Task 53 workload using the unchanged baseline adapter.
///
/// Every accepted outbound commit is delivered to each remaining valid member,
/// merged by its sender, and followed by an exact public-state convergence
/// check. The harness is in-process educational test infrastructure only; it
/// does not provide distributed delivery or experimental MLS behavior.
pub fn execute_baseline_workload(
    config: &BaselineWorkloadConfig,
) -> Result<BaselineWorkloadExecution, WorkloadExecutionError> {
    validate_workload_config(config)?;
    let mut members = create_initial_workload_group(config)?;
    let mut next_member_index = config.initial_member_count;
    let mut uniform_rng = match config.workload_profile {
        WorkloadProfile::Uniform { seed } => Some(ChaCha20Rng::seed_from_u64(seed)),
        _ => None,
    };
    let mut accepted_operations = Vec::new();
    accepted_operations
        .try_reserve(usize::try_from(config.operation_count).unwrap_or(usize::MAX))
        .map_err(|_| WorkloadExecutionError::MemberIndexOverflow)?;
    let mut committer_counts = BTreeMap::<u32, u32>::new();

    for sequence in 1..=config.operation_count {
        let state_before = converged_state(&members)?;
        let eligible =
            eligible_members_for_profile(&members, &state_before, config.workload_profile)?;
        let schedule =
            build_committer_schedule(&eligible, config.committer_strategy.clone(), sequence)?;
        let selection = schedule
            .selections
            .last()
            .expect("a schedule with positive sequence count has one selection");
        let committer_position = members
            .iter()
            .position(|member| member.member_index == selection.member_index)
            .ok_or(WorkloadExecutionError::PublicStateMembershipMismatch)?;
        let requested = requested_operation(
            sequence,
            config.workload_profile,
            members.len() as u32,
            config.maximum_member_count,
            uniform_rng.as_mut(),
        );
        let operation = apply_operation(
            &mut members,
            committer_position,
            requested,
            &mut next_member_index,
            config.region_count,
        )?;
        let state_after = converged_state(&members)?;
        if state_after.epoch
            != state_before
                .epoch
                .checked_add(1)
                .ok_or(WorkloadExecutionError::MemberIndexOverflow)?
        {
            return Err(WorkloadExecutionError::DivergentPublicState);
        }
        *committer_counts.entry(selection.member_index).or_default() += 1;
        accepted_operations.push(AcceptedWorkloadOperation {
            sequence,
            committer_member_index: selection.member_index,
            operation,
            epoch_before: state_before.epoch,
            epoch_after: state_after.epoch,
            active_member_count: u32::try_from(members.len())
                .map_err(|_| WorkloadExecutionError::MemberIndexOverflow)?,
        });
    }

    let final_state = converged_state(&members)?;
    let final_active_committer_counts = members
        .iter()
        .map(|member| ExecutedCommitterCount {
            member_index: member.member_index,
            accepted_commit_count: committer_counts
                .get(&member.member_index)
                .copied()
                .unwrap_or(0),
        })
        .collect();
    Ok(BaselineWorkloadExecution {
        accepted_operations,
        final_active_committer_counts,
        final_epoch: final_state.epoch,
        final_member_count: u32::try_from(members.len())
            .map_err(|_| WorkloadExecutionError::MemberIndexOverflow)?,
    })
}

fn validate_workload_config(config: &BaselineWorkloadConfig) -> Result<(), WorkloadExecutionError> {
    if config.group_id.is_empty() {
        return Err(WorkloadExecutionError::EmptyGroupId);
    }
    if config.initial_member_count < 2 {
        return Err(WorkloadExecutionError::InitialMemberCountTooSmall);
    }
    if config.maximum_member_count < config.initial_member_count {
        return Err(WorkloadExecutionError::MaximumMemberCountTooSmall);
    }
    if config.region_count == 0 {
        return Err(WorkloadExecutionError::ZeroRegionCount);
    }
    Ok(())
}

fn create_initial_workload_group(
    config: &BaselineWorkloadConfig,
) -> Result<Vec<ActiveWorkloadMember>, WorkloadExecutionError> {
    let mut members = Vec::new();
    for member_index in 0..config.initial_member_count {
        let identity = workload_identity(member_index);
        let client = BaselineClient::new(&identity)?;
        members.push(ActiveWorkloadMember {
            member_index,
            identity,
            leaf_region: member_index % config.region_count,
            client,
        });
    }
    members[0].client.create_group(&config.group_id)?;
    for joining_position in 1..members.len() {
        let key_package = members[joining_position].client.key_package()?;
        let outbound = members[0]
            .client
            .add_members(core::slice::from_ref(key_package.key_package()))?;
        deliver_commit(
            &mut members[..=joining_position],
            0,
            Some(joining_position),
            &outbound,
        )?;
        members[0].client.merge_pending_commit()?;
        let welcome = outbound
            .welcome
            .as_deref()
            .ok_or(WorkloadExecutionError::MissingWelcome)?;
        members[joining_position]
            .client
            .join_from_welcome(welcome)?;
        let _ = converged_state(&members[..=joining_position])?;
    }
    Ok(members)
}

fn eligible_members_for_profile(
    members: &[ActiveWorkloadMember],
    state: &BaselineState,
    profile: WorkloadProfile,
) -> Result<Vec<EligibleCommitter>, WorkloadExecutionError> {
    if state.member_identities.len() != state.member_leaf_indices.len()
        || state.member_count != members.len()
    {
        return Err(WorkloadExecutionError::PublicStateMembershipMismatch);
    }
    let mut eligible = Vec::with_capacity(members.len());
    for (identity, leaf_index) in state
        .member_identities
        .iter()
        .zip(&state.member_leaf_indices)
    {
        let member = members
            .iter()
            .find(|member| member.identity == *identity)
            .ok_or(WorkloadExecutionError::PublicStateMembershipMismatch)?;
        eligible.push(EligibleCommitter {
            member_index: member.member_index,
            leaf_index: *leaf_index,
            leaf_region: member.leaf_region,
        });
    }
    eligible.sort_unstable_by_key(|member| member.member_index);
    if let WorkloadProfile::RegionSkewed { preferred_region } = profile {
        let preferred: Vec<_> = eligible
            .iter()
            .filter(|member| member.leaf_region == preferred_region)
            .cloned()
            .collect();
        if !preferred.is_empty() {
            return Ok(preferred);
        }
    }
    Ok(eligible)
}

fn requested_operation(
    sequence: u32,
    profile: WorkloadProfile,
    member_count: u32,
    maximum_member_count: u32,
    uniform_rng: Option<&mut ChaCha20Rng>,
) -> WorkloadOperation {
    let requested = match profile {
        WorkloadProfile::UpdateOnly => WorkloadOperation::Update,
        WorkloadProfile::Mixed | WorkloadProfile::RegionSkewed { .. } => match (sequence - 1) % 3 {
            0 => WorkloadOperation::Update,
            1 => WorkloadOperation::Add { member_index: 0 },
            _ => WorkloadOperation::Remove { member_index: 0 },
        },
        WorkloadProfile::RemovalHeavy => match (sequence - 1) % 4 {
            3 => WorkloadOperation::Update,
            _ => WorkloadOperation::Remove { member_index: 0 },
        },
        WorkloadProfile::Uniform { .. } => match uniform_rng
            .expect("uniform profile initializes a deterministic RNG")
            .gen_range(0..3)
        {
            0 => WorkloadOperation::Update,
            1 => WorkloadOperation::Add { member_index: 0 },
            _ => WorkloadOperation::Remove { member_index: 0 },
        },
    };
    match requested {
        WorkloadOperation::Add { .. } if member_count >= maximum_member_count => {
            WorkloadOperation::Update
        }
        WorkloadOperation::Remove { .. } if member_count <= 2 => {
            if member_count < maximum_member_count {
                WorkloadOperation::Add { member_index: 0 }
            } else {
                WorkloadOperation::Update
            }
        }
        _ => requested,
    }
}

fn apply_operation(
    members: &mut Vec<ActiveWorkloadMember>,
    committer_position: usize,
    requested: WorkloadOperation,
    next_member_index: &mut u32,
    region_count: u32,
) -> Result<WorkloadOperation, WorkloadExecutionError> {
    match requested {
        WorkloadOperation::Update => {
            let outbound = members[committer_position].client.self_update()?;
            deliver_commit(members, committer_position, None, &outbound)?;
            members[committer_position].client.merge_pending_commit()?;
            Ok(WorkloadOperation::Update)
        }
        WorkloadOperation::Add { .. } => {
            let member_index = *next_member_index;
            *next_member_index = next_member_index
                .checked_add(1)
                .ok_or(WorkloadExecutionError::MemberIndexOverflow)?;
            let identity = workload_identity(member_index);
            let mut client = BaselineClient::new(&identity)?;
            let key_package = client.key_package()?;
            let outbound = members[committer_position]
                .client
                .add_members(core::slice::from_ref(key_package.key_package()))?;
            deliver_commit(members, committer_position, None, &outbound)?;
            members[committer_position].client.merge_pending_commit()?;
            let welcome = outbound
                .welcome
                .as_deref()
                .ok_or(WorkloadExecutionError::MissingWelcome)?;
            client.join_from_welcome(welcome)?;
            members.push(ActiveWorkloadMember {
                member_index,
                identity,
                leaf_region: member_index % region_count,
                client,
            });
            members.sort_unstable_by_key(|member| member.member_index);
            Ok(WorkloadOperation::Add { member_index })
        }
        WorkloadOperation::Remove { .. } => {
            let target_position = members
                .iter()
                .enumerate()
                .filter(|(position, _)| *position != committer_position)
                .min_by_key(|(_, member)| member.member_index)
                .map(|(position, _)| position)
                .ok_or(WorkloadExecutionError::DivergentPublicState)?;
            let target_identity = members[target_position].identity.clone();
            let target_member_index = members[target_position].member_index;
            let outbound = members[committer_position]
                .client
                .remove_members_by_identity(&[target_identity])?;
            deliver_commit(
                members,
                committer_position,
                Some(target_position),
                &outbound,
            )?;
            members[committer_position].client.merge_pending_commit()?;
            members.remove(target_position);
            Ok(WorkloadOperation::Remove {
                member_index: target_member_index,
            })
        }
    }
}

fn deliver_commit(
    members: &mut [ActiveWorkloadMember],
    committer_position: usize,
    excluded_position: Option<usize>,
    outbound: &OutboundCommit,
) -> Result<(), WorkloadExecutionError> {
    for (position, member) in members.iter_mut().enumerate() {
        if position == committer_position || Some(position) == excluded_position {
            continue;
        }
        if member.client.process_message(&outbound.commit)? != InboundEvent::CommitMerged {
            return Err(WorkloadExecutionError::CommitDelivery);
        }
    }
    Ok(())
}

fn converged_state(
    members: &[ActiveWorkloadMember],
) -> Result<BaselineState, WorkloadExecutionError> {
    let (first, rest) = members
        .split_first()
        .ok_or(WorkloadExecutionError::PublicStateMembershipMismatch)?;
    let reference = first.client.state()?;
    for member in rest {
        let state = member.client.state()?;
        if !same_public_state(&reference, &state) {
            return Err(WorkloadExecutionError::DivergentPublicState);
        }
    }
    Ok(reference)
}

fn same_public_state(left: &BaselineState, right: &BaselineState) -> bool {
    left.group_id == right.group_id
        && left.epoch == right.epoch
        && left.member_count == right.member_count
        && left.member_leaf_indices == right.member_leaf_indices
        && left.member_identities == right.member_identities
        && left.ratchet_tree == right.ratchet_tree
        && left.group_context == right.group_context
        && left.tree_hash == right.tree_hash
}

fn workload_identity(member_index: u32) -> Vec<u8> {
    format!("workload-member-{member_index:03}").into_bytes()
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

    fn workload_config(
        profile: WorkloadProfile,
        initial_member_count: u32,
    ) -> BaselineWorkloadConfig {
        BaselineWorkloadConfig {
            group_id: b"task-53-workload".to_vec(),
            initial_member_count,
            maximum_member_count: 5,
            operation_count: 5,
            region_count: 2,
            committer_strategy: CommitterStrategy::RoundRobin,
            workload_profile: profile,
        }
    }

    #[test]
    fn update_only_workload_delivers_each_commit_and_preserves_membership() {
        let execution = execute_baseline_workload(&workload_config(WorkloadProfile::UpdateOnly, 3))
            .expect("fully delivered update workload");
        assert_eq!(execution.accepted_operations.len(), 5);
        assert!(execution
            .accepted_operations
            .iter()
            .all(|record| record.operation == WorkloadOperation::Update));
        assert_eq!(execution.final_member_count, 3);
        assert_eq!(execution.final_epoch, 7);
    }

    #[test]
    fn mixed_and_removal_heavy_workloads_apply_real_membership_commits() {
        let mixed = execute_baseline_workload(&workload_config(WorkloadProfile::Mixed, 3))
            .expect("fully delivered mixed workload");
        assert!(mixed
            .accepted_operations
            .iter()
            .any(|record| matches!(record.operation, WorkloadOperation::Add { .. })));
        assert!(mixed
            .accepted_operations
            .iter()
            .any(|record| matches!(record.operation, WorkloadOperation::Remove { .. })));

        let removal_heavy =
            execute_baseline_workload(&workload_config(WorkloadProfile::RemovalHeavy, 3))
                .expect("fully delivered removal-heavy workload");
        assert!(removal_heavy
            .accepted_operations
            .iter()
            .any(|record| matches!(record.operation, WorkloadOperation::Remove { .. })));
        assert!(removal_heavy
            .accepted_operations
            .iter()
            .all(|record| record.epoch_after == record.epoch_before + 1));
    }

    #[test]
    fn region_skewed_and_uniform_workloads_are_publicly_deterministic() {
        let mut skewed = workload_config(
            WorkloadProfile::RegionSkewed {
                preferred_region: 1,
            },
            4,
        );
        skewed.operation_count = 3;
        let skewed_execution = execute_baseline_workload(&skewed).expect("region-skewed workload");
        assert!(
            skewed_execution
                .accepted_operations
                .iter()
                .all(|record| record.committer_member_index == 1
                    || record.committer_member_index == 3)
        );

        let uniform = workload_config(WorkloadProfile::Uniform { seed: 42 }, 3);
        let first = execute_baseline_workload(&uniform).expect("uniform workload");
        let second = execute_baseline_workload(&uniform).expect("same uniform workload");
        assert_eq!(first, second);
    }

    #[test]
    fn workload_configuration_rejects_unsafe_group_shapes() {
        let mut config = workload_config(WorkloadProfile::UpdateOnly, 1);
        assert!(matches!(
            execute_baseline_workload(&config),
            Err(WorkloadExecutionError::InitialMemberCountTooSmall)
        ));
        config.initial_member_count = 3;
        config.maximum_member_count = 2;
        assert!(matches!(
            execute_baseline_workload(&config),
            Err(WorkloadExecutionError::MaximumMemberCountTooSmall)
        ));
        config.maximum_member_count = 5;
        config.region_count = 0;
        assert!(matches!(
            execute_baseline_workload(&config),
            Err(WorkloadExecutionError::ZeroRegionCount)
        ));
    }
}
