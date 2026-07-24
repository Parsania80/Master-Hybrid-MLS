# ADR 0046: Authenticated Retained Transition Node State

**Status:** Accepted on 2026-07-24  
**Decision scope:** Task 85 retained old/new node availability and post-transition Remove

## Context

The authenticated transitioning `ArityState` binds the complete mapping and
initial TreeCover hashes. The existing fork nevertheless reconstructs that
mapping from current MLS leaves on every quaternary Commit. A valid Remove
therefore changes the reconstructed hash and is rejected. Epoch rollover also
replaces the compact quaternary parent-pair set and deletes the prior binary
epoch keypair record, so neither old TreeCover values nor cumulative new-tree
availability survive as transition-scoped state.

## Decision

1. Persist one redacted transition-node state inside `GroupEpochSecrets`. It is
   serialized and published by the existing Task 58 transaction together with
   the accepted MLS epoch.
2. Bind the retained state to the original authenticated mapping hash,
   TreeCover version/hash, and adaptive tree version. Store the complete
   canonical mapping privately in the envelope so later epochs can validate
   holes without renumbering surviving members.
3. Freeze every non-blank pre-transition binary parent public value. Attach a
   local private keypair only when the member possessed the matching epoch
   keypair. This reuses the existing matched `EncryptionKeyPair` type and its
   redacted/zeroizing private mKyber material.
4. Start retained new-tree delivery availability empty. After each accepted
   post-transition Update/Remove path, replace retained values at that
   committer's authenticated quaternary parent coordinates and keep unrelated
   prior coordinates.
5. Validate post-transition delivery against the frozen mapping plus current
   active-member holes. A current member must occur exactly once in the frozen
   mapping; Task 85 rejects post-transition Add and remapping.
6. After an accepted Remove, find the removed member in the frozen mapping and
   invalidate every binary parent on its complete old direct path. Remove any
   matching retained local private pairs in the same candidate state. Also
   discard retained new-tree coordinates on the removed member's frozen path
   before installing the removing committer's fresh authenticated path.
7. Reconcile the candidate MLS membership with the prior retained active set
   after the normal staged/pending merge but before transaction publication.
   A member may remain active or become removed; an unknown or resurrected
   member fails closed.
8. Expose only redacted/ciphertext-free observations: binding hashes/version,
   active member and usable old/new node counts, local retained private-pair
   counts, the public frozen mapping, active leaf ordinals, usable old parent
   indices, and usable new parent coordinates. No public API returns a private
   key, ciphertext, or secret value.
9. Keep the carrier and public TreeKEM binary. Task 85 establishes real
   authenticated retained state and real atomic Remove application; Task 86
   will connect accepted facts to endpoint counts, byte reports, and an
   authenticated retirement Commit.

## Failure Semantics

- Missing, malformed, stale, hash-mismatched, remapped, added, or resurrected
  membership fails before transaction publication.
- A failed sender or receiver storage mutation preserves the old live group,
  exact storage snapshot, retained old/new availability, and quaternary
  authority.
- A removed member follows the inherited inactive-group behavior and is not
  treated as a surviving holder of transition values.

## Verification

- A real transitioning group reloads with the same frozen mapping and retained
  old values.
- A post-transition Update accumulates new parent coordinates without changing
  old availability.
- A real post-transition Remove converges at all surviving members, preserves
  fixed leaf assignments, invalidates the retained values on the removed
  member's old/stale-new paths, and installs the committer's fresh new path.
- Post-transition Add/remapping, tamper, replay, and injected storage failures
  are rejected without retained-state mutation.
- Locked/offline format, strict Clippy, focused adapter tests, baseline
  isolation checks, and diff validation pass with bounded build resources.
