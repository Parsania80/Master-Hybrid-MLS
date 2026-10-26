# ADR 0009: Byte Provenance for Shadow Commit Estimates

**Status:** Accepted on 2026-07-19
**Decision scope:** Task 32 current/candidate commit-byte records and component accounting

## Context

ADR 0006 defines `B_i(2)` as a real emitted outer MLS Commit and `B_hat_i(4)` as a shadow estimate for the same logical operation. The unchanged baseline adapter emits only the former. The experimental hybrid TLS codec can serialize topology-dependent path payloads, but no experimental OpenMLS fork or candidate outer Commit serializer exists yet.

Treating a baseline Commit length as a quaternary Commit length, or adding a complete baseline Commit to a hybrid payload, would either mislabel an estimate as a measurement or double-count bytes. Task 32 therefore needs an explicit provenance boundary before policy or report code exists.

## Decision

1. `MeasuredCurrentCommit::from_emitted_outer_commit` records `B_i(2)` only from a non-empty serialized `OutboundCommit::commit` emitted by the unchanged MLS adapter. Its provenance is `EmittedOuterMlsCommit`, stores `measured_bytes`, and has no estimate.
2. A candidate estimate may retain only named byte ranges extracted from that exact emitted commit. Each `UnchangedOuterFraming` range is bounds-checked, non-empty, and its ranges must be pairwise disjoint. These are measured inputs but are marked with an estimate because their presence in a candidate message is a fork-specific assumption.
3. Each topology-dependent candidate UpdatePath level is measured by serializing a `HybridPathCiphertext` through its production canonical TLS codec. Its exact codec size, path-node index, and recipient-record count are retained as a `CandidateHybridPathComponent` with method `ShadowExactCodec`.
4. `B_hat_i(4)` is the checked integer sum of the retained unchanged framing ranges and all candidate hybrid TLS payloads. Both its `measured_bytes` input total and its equal `estimated_bytes` are recorded; the method remains `ShadowExactCodec` because no candidate MLS Commit was emitted or merged.
5. Construction fails without at least one retained framing component and one hybrid payload, or if retained source ranges overlap. The API intentionally cannot infer which baseline fields a future fork leaves unchanged or which candidate levels replace which UpdatePath fields; that binding remains a later fork/integration responsibility.
6. This task does not parse an OpenMLS Commit into semantic framing fields, execute an MLS candidate operation, derive secrets, measure transition commits, or claim convergence, interoperability, or a security property.

## Consequences

- `B_i(2)` remains a measured fact at the real adapter boundary.
- Candidate payload byte counts are codec-bound observations, while `B_hat_i(4)` remains visibly an estimate.
- Every candidate total has a disjoint component provenance trail suitable for later per-commit records and reports.
- A later experimental outer serializer must supersede or extend this ADR to compare its emitted candidate Commit length with this estimate; it must not silently relabel old estimates as measurements.

## Verification

- Unit tests distinguish measured current bytes from candidate estimates.
- Unit tests serialize real hybrid TLS payloads, verify their exact contribution, reject overlapping retained ranges, and reject incomplete candidate accounting.
- The locked offline workspace format, check, strict Clippy, unit-test, and doc-test gates must pass.
