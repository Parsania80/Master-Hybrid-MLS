# ADR 0006: Define Reproducible Transition Measurement Semantics

**Status:** Accepted on 2026-07-18
**Decision scope:** Experiment units, transition-policy formulas, shadow estimation, maturity aggregation, and statistics

## Context

The thesis specifies formulas for starting a `2 -> 4` transition and retiring the old binary TreeCover, but leaves several implementation-critical terms open: what a sliding window contains, what makes a commit impactful, whether transition costs double-count fields, how recipient sets are aggregated, and how warmups and repeated runs are summarized.

This ADR resolves those terms before code exists. It applies only to `AdaptiveBinaryToQuaternaryMls`; it does not alter normal MLS baseline behavior or turn estimates into claims of protocol interoperability.

## Decision

### 1. Experiment unit, time, and reproducibility

- An **accepted commit** is a commit that has passed validation and has been applied by all currently valid simulated members with convergent group state. Rejected, locally generated-but-not-accepted, and application messages do not increment experiment epoch counters or enter a policy window.
- The policy window `W_e` is the last `window_accepted_commits` accepted commits after warmup, ordered by `epoch_after`. Its default length is `20`; it is configurable as a positive integer.
- The default warmup is `10` accepted commits after group creation or snapshot load. Warmup records are retained in raw output but excluded from transition policy and aggregate timing statistics. This prevents bootstrap/setup work from changing a transition decision.
- Each configuration runs `30` independent deterministic repetitions by default. A run derives a workload seed from the public experiment seed, configuration digest, and run index. Secret key generation and KEM randomness use separate secret entropy and must never be reconstructed from the published workload seed.
- Time uses a monotonic clock and release builds. A timing record is `null` when its operation did not occur; it is never fabricated as zero.

### 2. Logical operations and impactful commits

Each accepted commit records its requested logical operation and the before/after public topology. `is_impactful_commit` returns true if at least one of these reason codes applies:

| Reason code | Condition |
|---|---|
| `path_delivery` | The commit contains an UpdatePath or otherwise changes path-secret delivery work. |
| `membership` | At least one member is successfully added or removed. |
| `new_tree_population` | The candidate quaternary tree's occupied or blank-node structure changes. |
| `treecover_validity` | The frozen old binary TreeCover gains or loses an eligible delivery member. |
| `recipient_resolution` | Any relevant co-path resolution recipient set changes. |
| `transition_state` | Authenticated arity, tree version, mapping, or transition state changes. |

The stored `impactful_reason` is a sorted, non-empty set of these codes. A commit with none is retained as `impactful=false` with `impactful_reason=none`; it remains in `W_e` but not in `q_e` or a saving sum. This makes policy behavior reproducible even when non-impactful commits occur between samples.

`q_e` is the number of impactful commits in `W_e`. `r_e` is the count of successfully removed members in `W_e`, counting each removal once even if several are in one commit. A transition-start decision is false when `q_e < q_min`, including `q_e = 0`.

### 3. Cost definitions and the start formula

All byte values are non-negative integer byte counts from the canonical serializer. An implementation must record `measured_bytes`, `estimated_bytes`, and `estimation_method` for every value that is not an emitted outer MLS message.

For each impactful commit `i` while arity 2 is active:

- `B_i(2)` / `B_current` is the actual byte length of the complete emitted outer commit, measured once by serializing the real message at the adapter boundary.
- `B_hat_i(4)` / `B_candidate_hat` is a shadow estimate for the same logical operation. A non-mutating clone replays the operation against the deterministic quaternary topology and uses the production hybrid TLS codec for all topology-dependent fields. The unchanged outer framing is measured from the real commit. Its method value is `shadow_exact_codec`; it is still an estimate because the candidate message is not emitted or merged by a real MLS group.
- The shadow replay receives the same public member operation, recipient ordering, configuration, and public workload event identifier as the real operation. It does not receive or emit a live secret.

Store exact integer sums rather than policy floats:

```text
sum_current = sum(B_i(2))
sum_candidate = sum(B_hat_i(4))
B_bar_current = sum_current / q_e
B_hat_bar_candidate = sum_candidate / q_e
Saving_preflight(2 -> 4) = sum_current - sum_candidate - B_transition_preflight
```

The displayed average values are rational values rendered only for reports. The equivalent average form is displayed as `q_e * (B_bar_current - B_hat_bar_candidate) - B_transition_preflight`; tests compare it using exact numerator arithmetic, not binary floating point.

### 4. Transition cost and Delta

The start decision must know migration cost before a real transition commit can exist. Therefore it uses `B_transition_preflight`: a byte count from a non-mutating, same-codec transition-commit preflight on a clone of the accepted state. The actual accepted transition commit records `B_transition_actual` and the report recomputes `Saving_realized` with that value. A mismatch between preflight and actual bytes is a reportable measurement defect; it does not get silently overwritten.

`B_transition_preflight` and `B_transition_actual` each count an outer transition message exactly once. Their diagnostic component fields form a disjoint partition:

```text
B_transition = base_commit_bytes
             + new_tree_metadata_bytes
             + deterministic_leaf_mapping_bytes
             + tree_version_metadata_bytes
             + treecover_initialization_bytes
             + other_transition_only_bytes
```

The sum must equal the complete serialized outer transition message plus any separately transmitted transition-only message. A field that is already part of the outer message is counted in one partition component only, never added again as metadata.

Exactly one Delta form is required in configuration:

- `delta_bytes`: an integer number of bytes; or
- `delta_percent_of_transition`: a decimal percentage represented as fixed-point micro-percent and evaluated as `Delta = percent * B_transition_preflight`.

Providing both or neither is a configuration error. `Saving_preflight > Delta` is strict, as required by the thesis. `Delta` is not hard-coded.

### 5. Transition-start lifecycle

After every accepted post-warmup commit, append the record, evict oldest records beyond `W_e`, calculate policy values, and evaluate the following in order:

1. `transition_state == Normal`;
2. `candidate_arity == 2 * current_arity` (the initial experiment permits only `2 -> 4`);
3. `group_size >= target_group_size` for `stable_epoch_count` consecutive accepted post-commit epochs;
4. `q_e >= q_min`;
5. `Saving_preflight(2 -> 4) > Delta`.

Defaults are `target_group_size=128`, `stable_epoch_count=5`, and `q_min=5`. A false condition is stored by name. The first epoch at which all five conditions are true is reported. The next accepted operation is a dedicated transition commit; it establishes authenticated `ArityState`, deterministic mapping, the active quaternary tree, and the delivery-only TreeCover. This separation prevents the measurement commit from ambiguously being both a normal workload event and a state migration.

### 6. Deterministic leaf mapping and TreeCover

At transition start, form a canonical list of currently occupied members ordered by the bytewise canonical `MemberId` encoding. Map list position `j` to the quaternary leaf at breadth-first, left-to-right position `j`. Serialize the complete mapping once in the transition message, hash it in `ArityState`, and use that hash in the hybrid context.

The new quaternary tree is the only active secret-producing tree after the transition commit. The TreeCover is a frozen, delivery-only binary routing overlay derived from the pre-transition binary tree. It contains no second active root and cannot derive an epoch secret. Removals mark the corresponding cover member ineligible; additions receive a deterministic lowest available quaternary leaf and no retroactive TreeCover membership. `TreeCover_node_count` counts only cover routing nodes with at least one currently eligible member.

### 7. Transition-end target sets and aggregation

For every relevant recipient set `S` addressed by a hybrid UpdatePath level during transition, calculate byte costs with the same logical payload and canonical serializer:

- `C_leaf(S)`: independent leaf-by-leaf delivery;
- `C_new(S)`: delivery through currently populated nodes in the new quaternary tree;
- `C_old(S)`: delivery through eligible nodes in the old binary TreeCover; and
- `C_ideal(S)`: delivery through a fully mature quaternary tree using the same member set.

These are exact serializer-driven counterfactual delivery costs, not network observations. Empty target sets are recorded and excluded from maturity aggregation. Negative costs, unavailable routes, or `C_leaf <= C_ideal` produce `Undefined` maturity with a reason; they cannot make a global retirement decision.

For a valid non-empty `S`, compute raw scores:

```text
h_new_raw(S) = (C_leaf(S) - C_new(S)) / (C_leaf(S) - C_ideal(S))
h_old_raw(S) = (C_leaf(S) - C_old(S)) / (C_leaf(S) - C_ideal(S))
```

Record raw values and clamp them to `[0, 1]` for threshold comparison, including a clamp reason. Global values are conservative:

```text
h_new_cost = min_S(h_new_clamped(S))
h_old_cost = max_S(h_old_clamped(S))
```

Thus `h_new_cost >= theta_new` means every relevant set has sufficient new-tree maturity, while `h_old_cost < theta_old` means even the best remaining TreeCover set is below the old-cover threshold. Any undefined non-empty set blocks retirement and is reported for recovery; it is never converted to a favorable score.

The global retirement rule is exactly:

```text
DropTreeCover = h_new_cost >= theta_new OR h_old_cost < theta_old
```

Defaults are `theta_new=0.70` and `theta_old=0.50`, stored as fixed-point values. On retirement, record epoch and triggering side(s), erase eligible old secrets where applicable, set transition state to `Normal`, increment `tree_version`, and verify member convergence.

### 8. Statistics and report aggregation

Aggregate experiment results at the independent-run level, not by pooling commits across repetitions. For each configuration and metric, report per-run summaries and then mean, median, minimum, maximum, sample standard deviation, p50, p95, and p99 across runs.

- Standard deviation is the sample standard deviation with denominator `n - 1`; for fewer than two valid runs it is `null`.
- Percentiles use Hyndman-Fan type 7 linear interpolation; `p50` is the same estimator as the median.
- Raw per-commit records remain available for within-run plots but are not treated as independent repetitions.
- A report states warmup count, policy-window length, repetitions requested/completed, excluded records, and every estimation method.

## Consequences

- Transition decisions are deterministic for a configuration and public workload event sequence.
- Candidate and preflight costs are honestly labeled estimates, while emitted message sizes remain measured facts.
- The global retirement rule cannot be triggered by one favorable recipient set while another still lacks a usable new-tree route.
- A later implementation that changes any definition in this ADR must issue a superseding ADR and mark old results as non-comparable.

## Verification Criteria

- Unit tests cover impact classification, window eviction, `q_e`/`r_e`, strict Delta validation, integer equivalence of both saving forms, and preflight-versus-actual transition-byte reporting.
- Property tests cover canonical member ordering, mapping determinism, TreeCover eligibility, empty/undefined target sets, clamping reasons, conservative aggregate scores, and OR-based retirement.
- Integration tests run multiple deterministic repetitions, verify all members converge after every accepted commit, and confirm that reports distinguish measured from estimated bytes.

