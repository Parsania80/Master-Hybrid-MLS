# ADR 0025: Baseline Workload Execution

**Status:** Accepted on 2026-07-20
**Decision scope:** Task 53 in-process workload families and valid-commit delivery

## Decision

1. Task 53 creates a fresh in-process group of at least two `BaselineClient` instances. All clients use the unchanged OpenMLS baseline adapter; no mKyber, experimental extension, TreeCover, or forked UpdatePath is involved.
2. `UpdateOnly` requests only self-updates. `Mixed` and `RegionSkewed` cycle update/add/remove. `RemovalHeavy` requests three removes for each update. `Uniform` draws update/add/remove requests from a public deterministic ChaCha20 schedule seed.
3. An Add request at the configured maximum becomes an update. A Remove request at two members becomes an Add if capacity permits, otherwise an update. These actual fallbacks are retained in the public accepted-operation record.
4. `RegionSkewed` restricts Task 52 committer candidates to the preferred public region when that region has active members, otherwise it falls back to all active members. New members receive `member_index mod region_count` as their public region label.
5. For every operation, the sender stages an upstream Add, Remove, or self-update commit; every currently valid non-sender member processes it; the sender merges its pending commit; an Add recipient joins from its Welcome; and a removed member is excluded from delivery. The harness then compares group ID, epoch, membership, public identity/leaf association, ratchet tree, GroupContext, and tree hash for all valid members.
6. Workload execution returns only public operation/epoch/member-count and final-active-committer facts. It is in-process educational evidence, not distributed delivery, crash recovery, load testing, or a security proof.

## Verification

- Tests cover all five workload families, real Add/Remove/update application, epoch increments, convergence, deterministic uniform behavior, region preference, and invalid group shape rejection.
- Focused locked-offline format, check, strict Clippy, adapter tests, and simulation tests pass.
