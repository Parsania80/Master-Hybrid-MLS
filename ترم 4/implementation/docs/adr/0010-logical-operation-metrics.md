# ADR 0010: Typed Logical-Operation Metrics

**Status:** Accepted on 2026-07-19
**Decision scope:** Task 33 public topology, recipient, crypto-count, timing, and byte metric records

## Context

Tasks 30 through 32 provide an immutable candidate topology and a measured-versus-estimated byte boundary. The thesis also requires tree height, direct paths, resolutions, blanks, populated nodes, recipient counts, crypto-operation counts, and timings. Existing code cannot yet execute an experimental MLS Commit or observe all fork-only values, so a record format must not turn unavailable values into zero or infer secret-bearing data.

## Decision

1. `TopologyMetrics` derives facts only from a complete binary or quaternary tree's height and a strictly ascending list of public occupied leaf ordinals. It records leaf capacity, occupied and blank leaves, populated nodes, blank nodes, and direct-path nodes. A populated node has at least one occupied descendant; a blank node has none. The direct path is leaf parent through root and therefore contains exactly `height` nodes.
2. `TopologyMetrics::from_shadow_quaternary` consumes the immutable Task 30/31 shadow tree. Baseline topology callers supply their independently observed canonical occupied binary leaves; this task does not parse or mutate an OpenMLS private tree.
3. `RecipientResolutionMetrics` records one public path-node index and a canonical strictly ascending recipient-resolution node list. The resolution-node count and recipient count equal that list length. Empty lists remain valid observations for later target-set analysis.
4. `CryptoOperationMetrics` has an observed form and an explicit unavailable form. Observed metrics carry an invocation count and monotonic elapsed nanoseconds; zero invocations carry `None` timing. Unavailable uses `NotInstrumented` or `NotApplicable`, never a fabricated zero count or duration. `measure` provides a narrow monotonic timer around exactly one caller-supplied operation and retains no input or output material.
5. `CryptoMetrics` and recipient-resolution lists are canonical ordered, duplicate-free collections. This makes comparisons and later report serialization deterministic.
6. `CommitByteMetrics` copies only Task 32 provenance values, never serialized Commit bytes. `LogicalOperationMetrics` combines measured binary topology, shadow quaternary topology, recipient resolutions, byte provenance, and crypto metrics. It enforces the `2 -> 4` comparison but deliberately omits epoch, accepted-commit identity, impact classification, transition state, and report output fields; those belong to later tasks.

## Consequences

- All Task 33 values are public facts, explicit estimates, or explicit unavailability states.
- Metrics retain no private keys, shared secrets, path secrets, randomness, ciphertext bodies, or live MLS state.
- Later fork instrumentation must provide actual recipient-resolution and crypto-operation observations rather than filling placeholders. A later per-commit schema may embed `LogicalOperationMetrics` without changing its definitions.
- The records are not evidence that a candidate MLS message is valid, accepted, convergent, interoperable, or secure.

## Verification

- Unit tests derive binary and quaternary populated/blank-node counts from public leaves.
- Unit tests reject non-canonical topology, recipient, and crypto ordering.
- Unit tests distinguish observed timing, zero-operation `None` timing, and unavailable metrics.
- Unit tests compose every metric family into one typed logical-operation record while preserving Task 32 current/candidate provenance.
