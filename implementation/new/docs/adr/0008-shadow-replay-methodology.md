# ADR 0008: Define Non-Mutating Shadow Replay Methodology

**Status:** Accepted on 2026-07-19
**Decision scope:** Public logical-operation replay for candidate 2-to-4 topology analysis

## Context

The transition-start estimate must compare a real accepted binary MLS operation with the same logical operation under a quaternary candidate topology. Reusing a live MLS group, secret-tree state, private keys, ciphertexts, or random input would make that comparison stateful, non-reproducible, and unsafe.

## Decision

1. Build the initial shadow tree from the validated version-1 mapping in ADR 0006. That initial mapping is frozen: existing member identifiers retain their assigned quaternary leaf ordinals and are never renumbered by replay.
2. A replay accepts only one public logical operation: `Update(member_id)`, `Add(member_id)`, or `Remove(member_id)`. Canonical public `MemberId` bytes identify every operation target.
3. `Update` verifies that the member exists and returns an equal shadow tree. It changes neither occupancy nor capacity.
4. `Remove` verifies that the member exists, returns a new shadow tree with that leaf vacant, and does not renumber other members.
5. `Add` verifies that the member is absent, assigns the lowest vacant quaternary leaf ordinal, and returns a new shadow tree. If every candidate leaf is occupied, increase the complete candidate tree height by one and retain existing ordinals.
6. Every replay returns public before/after population, topology-change status, optional assigned/vacated leaf ordinal, and the new immutable tree. It takes no RNG input and has no API that references an MLS client or mutates a live group.
7. This replay is a topology counterfactual only. It does not derive secrets, emit protocol messages, estimate bytes, select recipients, implement TreeCover, or establish authenticated transition state. Task 32 will combine this public topology with the production codec for explicitly labeled candidate byte estimates.

## Consequences

- The same initial mapping and public operation sequence always produce the same shadow topology and replay record.
- A real baseline operation remains the only source of live MLS state and emitted-message measurements.
- The candidate result is not proof that a quaternary MLS group would accept or converge on a corresponding commit; it remains an estimate boundary until later experimental integration and tests.

## Verification

- Unit tests cover update identity, removal holes, lowest-vacant addition, capacity expansion, non-renumbering, and source-tree immutability.
- The full workspace regression suite must continue to pass with the unchanged baseline adapter.
