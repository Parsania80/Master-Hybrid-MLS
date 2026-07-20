# ADR 0012: Non-Mutating Transition Preflight Byte Partition

**Status:** Accepted on 2026-07-20
**Decision scope:** Task 36 `B_transition_preflight` measurement and actual-byte mismatch reporting

## Context

ADR 0006 requires transition preflight bytes before any real transition Commit exists, with a disjoint partition that counts an outer transition message exactly once. The authenticated `ArityState`, TreeCover, and experimental OpenMLS transition serializer are still deferred. It would be misleading to synthesize a transition size from constants, reuse a live MLS group, or add metadata sizes on top of an already-counted outer message.

## Decision

1. `TransitionPreflightMeasurement` accepts only a caller-supplied canonical serialized outer transition-message byte slice and a list of diagnostic ranges. It reads the slice without retaining it or receiving an MLS client, mutable group state, secret, key, randomness, or ciphertext body.
2. Ranges must be non-empty, in bounds, and after sorting form one exact contiguous, non-overlapping partition of every outer-message byte. Missing, gapped, overlapping, and out-of-range ranges fail closed.
3. Each range belongs to exactly one ADR 0006 component: `base_commit`, `new_tree_metadata`, `deterministic_leaf_mapping`, `tree_version_metadata`, `treecover_initialization`, or `other_transition_only`. A component may measure zero bytes when no range is assigned, but the complete outer message always has a non-empty exact partition.
4. `B_transition_preflight` equals both the observed canonical outer-message byte length and the checked sum of all six diagnostic component counts. It is labeled `CanonicalOuterMessagePartition` and remains an estimate because a candidate transition Commit has not been emitted or merged by a live MLS group.
5. `compare_actual_outer_message` records a later actual outer-message byte length and an explicit directional delta. A mismatch is reportable; the preflight value is never overwritten.
6. Until the experimental transition serializer exists, the caller is responsible for producing the canonical preflight outer byte message from a non-mutating clone of accepted state. This boundary cannot prove the source was a clone. The later serializer/integration must use the same partition definitions or supersede this ADR.

## Consequences

- Transition policy can consume a typed, partitioned preflight estimate without mutating live state.
- Diagnostic components cannot double-count bytes already present in the serialized outer message.
- No fixed size, live transition behavior, MLS acceptance, convergence, interoperability, or security property is claimed.
- Task 37 can use the preflight total in exact integer savings formulas; a later actual transition must preserve mismatch evidence.

## Verification

- Unit tests check an exact six-component partition and its sum.
- Unit tests reject empty, gapped, and overlapping partitions.
- Unit tests record equal, larger, and smaller later actual-message comparisons.
- Locked offline formatting, checking, strict Clippy, and transition-policy tests must pass.
