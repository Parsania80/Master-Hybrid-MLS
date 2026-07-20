# ADR 0024: Public Committer Scheduling

**Status:** Accepted on 2026-07-20
**Decision scope:** Task 52 deterministic committer selection before workload execution

## Decision

1. A schedule accepts only non-empty active public members sorted strictly by `member_index`, with unique current public leaf indexes. Each member carries a public `leaf_region` label supplied by future workload/topology code.
2. `RoundRobin` cycles canonical member order. `SeededRandom` uses `ChaCha20Rng` from a public schedule seed for uniform active-member draws. The seed is reproducibility input only and is never MLS or mKyber entropy.
3. `FixedList` cycles an explicit non-empty, duplicate-free list of active members in the supplied order. `WeightedRandom` draws only explicit, positive, canonically ordered weights for active members with a public seed.
4. `LeafRegionBalanced` chooses the least-selected region, breaking ties by region label; inside that region it chooses the least-selected member, breaking ties by leaf index then member index. This produces deterministic region interleaving and member balancing without changing topology.
5. Every completed schedule retains every emitted selection and zero-inclusive actual counts for every eligible member and region. These are planned committer facts only, not accepted commits, timing data, or workload outcomes.
6. The scheduler mutates no MLS group, secret tree, adaptive tree, or policy window. Task 53 owns workload execution; Task 54 owns per-commit reporting.

## Verification

- Unit tests cover round-robin sequencing and distributions, seeded reproducibility, fixed-list ordering, weighted eligibility, leaf-region balancing, and malformed/duplicate/zero-weight input rejection.
- Locked-offline format, check, strict Clippy, and simulation tests pass.
