# ADR 0019: Transition Convergence and Atomic Harness

**Status:** Accepted on 2026-07-20
**Decision scope:** Task 44 educational convergence and rejection behavior after Task 43 pre-apply validation

## Context

ADR 0018 intentionally stops before state mutation: it validates public transition metadata supplied by a future experimental MLS fork. Task 44 needs observable evidence that matching inputs yield matching member state and that an error after one recipient has resolved cannot partially replace another member's public transition state. The repository still has no experimental OpenMLS fork, authenticated transition Commit, or distributed commit coordinator.

## Decision

1. `transition-auth` provides `EducationalTransitionMember` only for the first thesis `2 -> 4` transition. Each member retains public pre-transition group ID and epoch plus an optional applied public transition snapshot.
2. `apply_transition_to_members` takes one metadata envelope, one shared hybrid path-level context/ciphertext, a one-to-one ordered private recipient list, and a caller-selected mKyber backend. It rejects a length mismatch before staging.
3. For every member, the harness first performs Task 43 validation against that recipient's canonical KDF context, verifies the local expected post-transition epoch, first tree version, and quaternary arity, then opens that recipient's hybrid path secret.
4. The harness records no public member mutation while staging. Only after every stage succeeds does it install an equal public `AppliedTransitionState` for every supplied member and return the recipient-specific secrets to the caller. The public snapshots retain no path secret.
5. Tests run two independently constructed scenarios labelled by Alice and Bob as the external committer source and resolve one shared path secret through three recipient nodes. They require equal applied public state and equal recovered secrets.
6. Tests also reject divergent extension metadata, a non-recipient substituted after an earlier recipient has staged successfully, and a tampered common mKyber component. In every case all supplied members remain in their original public state.

## Consequences

- The harness makes the intended local ordering explicit: validate, resolve every recipient, then replace all public snapshots.
- It avoids a false claim that Task 43's immutable pre-apply object by itself supplied atomic application or convergence evidence.
- The positional member/recipient relation is a test-harness input, not an authenticated MLS identity-to-node binding.
- This is not a transition wire format, an OpenMLS modification, outer-Commit authentication, distributed atomic commit protocol, network delivery guarantee, secret-tree derivation, or a security/interoperability proof. A future fork must authenticate the complete Commit and make extraction, validation, secret-tree update, and group-state merge atomic.

## Verification

- Focused locked-offline tests cover multiple committer scenarios, three recipient resolutions, equal public snapshots, equal private path secrets, divergent metadata, late recipient-resolution failure, and tampered ciphertext without snapshot mutation.
- The Phase 8 gate in Task 45 must run locked-offline formatting, checking, strict Clippy, all-target tests, documentation tests, release build, metadata, baseline regression, and diff validation.
