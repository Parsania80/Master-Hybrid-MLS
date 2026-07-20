# ADR 0017: Separate Active Quaternary Tree and Delivery-Only TreeCover

**Status:** Accepted on 2026-07-20
**Decision scope:** Task 42 transition topology, frozen binary cover eligibility, and single epoch-secret authority

## Context

After the dedicated `2 -> 4` transition, ADR 0006 requires the new quaternary tree to be the only active secret-producing tree. The pre-transition binary structure must remain available only as a frozen delivery cover for members who existed at the transition. Reusing a generic tree object for both roles would make it too easy to derive or imply epoch-secret authority from two roots.

## Decision

1. The new internal `transition-tree` crate stores `ActiveQuaternaryTree` and `DeliveryOnlyTreeCover` as separate types inside `TransitionTrees`.
2. `ActiveQuaternaryTree` is initialized from the canonical Task 30 mapping and uses the existing deterministic topology engine for public `Update`, `Add`, and `Remove` replay. It is the sole `EpochSecretAuthority::ActiveQuaternary` marker. The crate stores no secret bytes and does not implement actual TreeKEM derivation.
3. `DeliveryOnlyTreeCover` freezes the transition mapping's canonical member identifiers and binary leaf indexes. It has its own versioned `AHTC` canonical public encoding, SHA-256 digest, eligible-member query, and binary routing-node calculation. It has no epoch-secret API or authority marker.
4. `TransitionTrees::from_transitioning_state` validates the supplied `ArityState`, deterministic mapping hash, TreeCover version, TreeCover hash, and active arity before exposing separate state. This does not by itself authenticate state in MLS; it checks a supplied canonical state value.
5. During transition, Update preserves both topologies. Add changes only the active quaternary topology and never creates TreeCover membership. Remove changes active topology and makes a frozen member ineligible in the TreeCover; removing a post-transition addition does not alter TreeCover eligibility.
6. `eligible_routing_nodes` counts only binary nodes that have at least one currently eligible frozen member. If no frozen member remains eligible, it returns an empty node set.
7. Any eligibility mutation changes the canonical TreeCover hash while retaining its representation version. Task 43 must carry and authenticate the resulting hash in the full GroupContext extension before a live group applies such a change. Retirement and deletion of the cover remain Task 49.

## Consequences

- The public API represents exactly one possible epoch-secret source: the active quaternary tree.
- The old binary cover cannot silently acquire post-transition additions or act as an active tree through this crate.
- These structures are public topology and routing metadata only; they do not emit MLS messages, authenticate commits, derive secrets, prove atomicity, or establish convergence/interoperability/security claims.

## Verification

- Unit tests cover ArityState/mapping/TreeCover binding mismatch rejection, one authority marker, binary routing-node counting, no TreeCover membership for additions, frozen-member eligibility revocation, unchanged cover for added-member removal, and hash change after eligibility mutation.
- Locked offline formatting, checking, strict Clippy, and focused crate tests must pass.
