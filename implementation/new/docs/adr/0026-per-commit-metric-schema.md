# ADR 0026: Per-Commit Metric Schema

**Status:** Accepted on 2026-07-20
**Decision scope:** Task 54 public identity, topology, crypto-count, byte, timing, policy-window, transition, and retirement records

## Context

Tasks 32 and 33 define individual byte-provenance, topology, recipient-resolution, and crypto-measurement types. Tasks 35 through 50 define policy, transition, and retirement facts. Task 53 can now execute an unchanged OpenMLS baseline workload, but it previously returned no common per-commit reporting record and could not truthfully fabricate fork-only observations.

## Decision

1. `report::PerCommitMetricRecord` version 1 is the one public record boundary for a fully accepted logical commit. It has named sections for identity, operation, topology, bytes, crypto counts, timing, policy window, transition, retirement, and actual Commit/Welcome delivery counts.
2. Every unavailable family is represented by `MetricAvailability::Unavailable(reason)`. It is never serialized as zero, an empty vector, or a synthetic estimate. Reasons distinguish a missing hook, non-applicability, the future experimental fork boundary, missing policy attachment, no transition, and no retirement.
3. Task 53 now records only direct baseline observations: outer Commit bytes, optional Welcome bytes, direct Commit deliveries, Welcome joins, the committer's public pre-commit leaf and region, and monotonic elapsed time from staging through delivery, merge/join, and convergence verification. The timing value is deliberately nondeterministic and is not part of workload-schedule reproducibility comparisons.
4. An unchanged-baseline conversion fills the candidate topology, recipient resolutions, candidate byte comparison, and crypto metrics as unavailable. It also records no policy, transition, or retirement fact until the corresponding existing subsystem is actually attached.
5. The schema has opt-in attachment methods and public wrapper types for real `PolicyWindow`, transition, and retirement observations. Future experimental instrumentation may replace an unavailable value only with the appropriate already-observed typed fact.
6. The schema retains no Commit bytes, Welcome bytes, private MLS state, private keys, shared secrets, path secrets, ciphertext bodies, entropy, or reconstructed seed material. Task 55 owns file generation from these public records.

## Consequences

- The report layer can generate deterministic structural output while preserving environment-dependent elapsed timing as an observation.
- A baseline workload has real byte and delivery facts but no claimed experimental topology, mKyber operation count, transition, or retirement result.
- This record is a thesis-local measurement schema. It does not make the experimental protocol valid, interoperable, convergent in a network, secure, or suitable for business or production use.

## Verification

- Report tests execute a real mixed baseline workload and verify nonzero emitted Commit bytes, Welcome joins, and explicit unavailable experimental sections.
- Tests reject non-contiguous sequences and records that fail to advance epoch by exactly one.
- JSON-shape tests require every named measurement family.
- Focused locked-offline format, check, strict Clippy, simulation/report tests, and the full workspace gate pass.
