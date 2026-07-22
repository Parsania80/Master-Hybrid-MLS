# ADR 0040: Authenticated Atomic Transition-Commit Boundary

**Status:** Accepted on 2026-07-22  
**Decision scope:** First real MLS Commit boundary for the experimental binary-to-quaternary transition

## Context

`ArityState` already defines the public `Normal -> Transitioning` state
machine, deterministic binary-to-quaternary mapping binding, and frozen
delivery-only TreeCover binding. Until this decision, those values were not
authenticated by a real experimental MLS Commit. Task 58 also deliberately
rejects every non-normal state, so it cannot apply a transition Commit.

The imported fork still uses its inherited binary TreeKEM public tree and
epoch-secret derivation. A public quaternary topology marker must therefore not
be described as a quaternary TreeKEM implementation merely because the fork
also derives an experimental quaternary authority from a later MLS epoch.

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
7. When the authenticated provisional state is `Transitioning`, derive a
   fork-local quaternary epoch authority from the newly established MLS exporter
   secret using label `experimental quaternary epoch authority` and the complete
   provisional GroupContext as context. Persist it inside the existing
   `GroupEpochSecrets` envelope, which Task 58 already writes atomically.
8. Require an MLS UpdatePath for every transitioning epoch that installs or
   rotates this authority. Sender and receiver derive the same redacted public
   status from the accepted candidate, and dedicated atomic APIs reject a
   missing, stale, or GroupContext/mapping/TreeCover-mismatched authority.
9. Carry an ordered feature-gated, fork-local quaternary parent-path vector
   inside the authenticated MLS `UpdatePath`. Each record contains version,
   adaptive tree version, `(depth, ordinal)`, matched public classical/mKyber
   parent key, and canonical hybrid recipient delivery. The vector is covered
   by the surrounding Commit signature; it is explicitly not an RFC MLS
   encoding.
10. Rebuild the canonical mapping from the prospective authenticated MLS
    leaves. It determines the sender's root-to-leaf quaternary parents and
    each recipient's quaternary leaf ordinal. The receiver independently
    rebuilds and requires the same ordered coordinates before opening delivery.
11. Bind every parent to the complete GroupContext and a collision-free packed
    depth/ordinal index. The root reuses the binary root source secret for its
    direct equality check; each non-root parent derives a separate source
    secret with label `quaternary TreeKEM path` bound to domain, version, and
    position. Each non-sender leaf is placed only in the parent at its first
    divergent branch from the sender, yielding the exact mapped sibling
    resolution for every parent delivery.
12. Store every matched parent private pair in the candidate
    `GroupEpochSecrets` envelope together with the quaternary epoch authority.
    The existing atomic merge writes this envelope before replacing live state;
    each later epoch replaces and drops the prior parent-path set. Public
    status exposes only the root public-key digest and parent count.

## Failure Semantics

- Missing, malformed, non-canonical, wrong-policy, wrong-epoch, wrong-mapping,
  wrong-TreeCover, or membership-changing target state fails before atomic
  publication.
- The normal binary atomic merge rejects a transition Commit and leaves the
  receiver's public group state unchanged; callers must use the dedicated
  transition API.
- The persisted authority secret and root private key are never returned. Its
  status contains only epoch, tree version, mapping digest, and a root public-
  key digest, and reloads only through the existing `GroupEpochSecrets`
  storage lifecycle.
- A transitioning receiver rejects a missing mapped parent record, unsupported
  parent position/version/tree version, malformed delivery, an absent mapped
  sibling recipient, failed hybrid open, a public-key mismatch, or a secret
  mismatch before the staged Commit reaches the atomic merge boundary. It
  validates every mapped parent public key but opens only its divergence-parent
  ciphertext.
- As with ADR 0039, message-ratchet effects of receiving and staging a Commit
  occur before the merge API and are outside the storage transaction.

## Verification Criteria

- A real two-member experimental MLS group creates, authenticates, sends,
  receives, and atomically applies a `Normal -> Transitioning` GroupContext
  Commit. Both members converge on epoch, ratchet tree, and exact `ArityState`.
- The normal binary atomic merge rejects the same staged transition Commit
  without changing the receiver epoch, ratchet tree, or authenticated state.
- A subsequent real hybrid MLS self-update rotates the stored authority at both
  members; the public status converges and survives a storage reload.
- The transition Commit and subsequent self-update both carry authenticated
  mapping-derived quaternary parent-path records. Each parent delivery contains
  only its mapped sibling-resolution leaves; receivers validate every position
  and derived public key, and open only their divergence parent, including the
  root-secret equality check.
- Three members converge through the root-only mapped path; five members
  converge through root plus a depth-1 parent, with both pairs persisted.
- Locked/offline adapter tests cover the round trip and rejection boundary.

## Explicit Non-Claims and Remaining Work

This decision now has authenticated, receiver-validated mapped parent-path
delivery restricted to exact quaternary sibling resolutions and an atomic
private-pair lifecycle, while its MLS carrier and public TreeKEM remain binary.
It does not yet cover all membership/path-shape and real-Commit rejection
cases, injected transition storage faults, or replace the MLS
application/message key schedule. Task 60 remains current until those
boundaries exist. No adaptive workload or three-mode measurement is available
from this boundary.
