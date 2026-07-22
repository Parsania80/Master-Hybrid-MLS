# ADR 0040: Authenticated Atomic Transition-Commit Boundary

**Status:** Accepted on 2026-07-22  
**Decision scope:** First real MLS Commit boundary for the experimental binary-to-quaternary transition

## Context

`ArityState` already defines the public `Normal -> Transitioning` state
machine, deterministic binary-to-quaternary mapping binding, and frozen
delivery-only TreeCover binding. Until this decision, those values were not
authenticated by a real experimental MLS Commit. Task 58 also deliberately
rejects every non-normal state, so it cannot apply a transition Commit.

The imported fork still uses its inherited binary TreeKEM tree and epoch-secret
derivation. A public quaternary topology marker must therefore not be described
as an active quaternary epoch-secret authority until the fork actually derives,
stores, and uses that authority.

## Decision

1. Start a transition with the standard MLS GroupContext-extensions Commit
   mechanism. Its authenticated GroupContext carries the replacement private-use
   `0xF001` `ArityState` value.
2. Require every experimental group member to advertise `0xF001` through the
   MLS `RequiredCapabilities` extension. The existing mKyber capability helper
   supplies this capability to the creator and experimental KeyPackages.
3. Before staging, derive the canonical mapping from the current public MLS
   members using each credential's serialized content and public leaf index.
   The sender accepts the supplied target state only when its mapping hash and
   TreeCover hash/version match the derived values.
4. Apply sender pending Commits and receiver staged Commits through separate
   Task 58 transactional APIs. Each creates a candidate from the isolated
   storage snapshot, merges there, re-derives the candidate public mapping, and
   validates the target state before storage publication and in-memory
   replacement.
5. Bind transition evaluation to the *pre-Commit* epoch. The candidate group
   naturally has the next epoch after merge; validating against that candidate
   epoch would incorrectly reject a valid `transition_epoch = prior + 1`.
6. The dedicated transition Commit cannot add or remove a member. Candidate
   membership must produce exactly the pre-Commit mapping, preventing a
   membership change from being smuggled into the transition boundary.

## Failure Semantics

- Missing, malformed, non-canonical, wrong-policy, wrong-epoch, wrong-mapping,
  wrong-TreeCover, or membership-changing target state fails before atomic
  publication.
- The normal binary atomic merge rejects a transition Commit and leaves the
  receiver's public group state unchanged; callers must use the dedicated
  transition API.
- As with ADR 0039, message-ratchet effects of receiving and staging a Commit
  occur before the merge API and are outside the storage transaction.

## Verification Criteria

- A real two-member experimental MLS group creates, authenticates, sends,
  receives, and atomically applies a `Normal -> Transitioning` GroupContext
  Commit. Both members converge on epoch, ratchet tree, and exact `ArityState`.
- The normal binary atomic merge rejects the same staged transition Commit
  without changing the receiver epoch, ratchet tree, or authenticated state.
- Locked/offline adapter tests cover the round trip and rejection boundary.

## Explicit Non-Claims and Remaining Work

This decision authenticates and atomically applies public transition metadata
only. The inherited live MLS TreeKEM remains binary; `ActiveQuaternaryTree` is
still a public model and not a real epoch-secret authority. Task 60 remains
current until fork-native quaternary secret derivation/storage, multi-member
transition convergence, full rejection coverage, and transition-specific
storage-fault coverage exist. No adaptive workload or three-mode measurement is
available from this boundary.
