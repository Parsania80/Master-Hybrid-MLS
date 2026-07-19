# ADR 0011: Accepted-Commit Policy Window

**Status:** Accepted on 2026-07-19
**Decision scope:** Task 35 `W_e`, `q_e`, `r_e`, warmup handling, and impact classification

## Context

ADR 0006 defines a bounded window of accepted post-warmup commits and six reasons that make a commit impactful. The transition-policy crate previously had no implementation, which left ambiguity about whether warmup or non-impactful commits were discarded, how evictions affected removal counts, and whether rejected/local-only messages could enter the policy state.

## Decision

1. `PolicyWindow` accepts only public facts for commits that a future simulator has already validated, applied to all valid members, and confirmed convergent. There is no API for rejected messages, locally staged but unaccepted commits, or application messages.
2. `PolicyWindowConfig` requires positive `window_accepted_commits` and `q_min`; warmup may be zero. It owns the configured window length, warmup count, and later `q_min` condition without evaluating the complete transition-start rule.
3. Accepted epochs must be strictly increasing. Every accepted record remains in the append-only in-memory raw audit trail. The first `warmup_accepted_commits` are marked `WarmupExcluded` and do not enter `W_e`.
4. Every later accepted record enters `W_e`, including `ImpactClassification::None`. The window is ordered by `epoch_after` and evicts only the oldest post-warmup record when its configured bound is exceeded.
5. `is_impactful_commit` emits a deterministic sorted reason list: `path_delivery`, `membership`, `new_tree_population`, `treecover_validity`, `recipient_resolution`, and `transition_state`. Membership is present exactly when a successful addition or removal occurred. No reason produces explicit `None`.
6. `q_e` is recalculated as the impactful-record count in the current window. `r_e` is the checked sum of successful removals in that same current window. Thus warmup records and evicted records never contribute, while a current non-impactful record contributes to neither count but remains observable.
7. This implementation does not calculate savings, Delta, group-size stability, transition preflight, transition state, TreeCover, or an actual start decision. Those are later tasks.

## Consequences

- A public workload sequence produces deterministic policy-window records and counts.
- The raw trail preserves warmup and later-evicted records for reporting without allowing either to distort current policy values.
- `q_e < q_min` can be queried, but no transition can start from this crate yet.
- The policy model does not establish that a candidate MLS operation is valid, convergent, interoperable, or secure.

## Verification

- Unit tests cover all reason codes, sorted classification, explicit non-impactful classification, warmup exclusion, eviction, `q_e`, `r_e`, and strict epoch ordering.
- Locked offline formatting, checking, strict Clippy, and transition-policy tests must pass.
