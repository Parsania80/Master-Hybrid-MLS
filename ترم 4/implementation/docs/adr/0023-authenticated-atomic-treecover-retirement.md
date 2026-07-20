# ADR 0023: Authenticated Atomic TreeCover Retirement

**Status:** Accepted on 2026-07-20
**Decision scope:** Task 49 educational retirement boundary

## Decision

1. TreeCover retirement is considered only after a future experimental fork supplies facts extracted from one already MLS-authenticated GroupContext/Commit transaction: the exact normal-state `0xF001` extension value and the Task 48 decision. The local `TreeCoverRetirementEnvelope` does not parse MLS, verify an MLS signature, or independently prove that extraction.
2. The envelope must contain a canonical `Normal` state with active and candidate arity `4`, the same group identifier, an epoch exactly one after the member's applied transition, and a logical tree version exactly one greater. A `Keep` decision, unknown extension type, malformed/noncanonical state, group mismatch, epoch mismatch, or version mismatch rejects retirement.
3. A successful public retirement record retains the authenticated epoch, exact Task 48 trigger side(s), post-retirement GroupContext hash, prior transition commitment, and a separate commitment over the normal-state extension and trigger bits. The member state is now normal quaternary at the incremented version.
4. All educational members are validated and staged before any member snapshot is replaced. Any failure leaves every supplied member's retirement snapshot unchanged. This is only in-process harness atomicity.
5. `DeliveryOnlyTreeCover` contains no old epoch/path secret material. The harness records `NoSecretMaterialInEducationalHarness` rather than falsely claiming erasure. A future MLS fork must replace this marker with actual, reviewed zeroization of its obsolete secret store after its authenticated state transaction commits.

## Verification

- Tests prove three member snapshots converge to epoch 9, tree version 2, normal quaternary state, and the recorded new-tree trigger.
- Rejection tests prove a wrong extension type and a missing prior transition leave every supplied retirement snapshot unchanged.
- Focused offline format, check, strict Clippy, and metrics/transition-auth tests pass.
