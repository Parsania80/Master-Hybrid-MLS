# ADR 0005: Authenticate Adaptive Tree State Through a Private-Use GroupContext Extension

**Status:** Accepted on 2026-07-18
**Decision scope:** Extension type, authenticated transition state, and capability policy

## Context

Adaptive binary-to-quaternary behavior requires all members to agree on arity and transition metadata. RFC 9420 GroupContext extensions are mandatory for all members once in use, and IANA reserves extension types `0xF000` through `0xFFFF` for private use. This is the appropriate authenticated state channel, but it cannot carry the required per-level hybrid ciphertext. See [RFC 9420](https://www.rfc-editor.org/rfc/rfc9420) and the [IANA MLS registry](https://www.iana.org/assignments/mls/mls.xhtml).

## Decision

1. Reserve private-use extension type `0xF001` for this thesis only, named `adaptive_hybrid_tree_state`. It is never advertised as a standardized or interoperable extension.
2. Encode a version-1 `ArityState` in that extension with: state version, active arity, candidate arity, transition state, tree version, transition-policy configuration digest, deterministic leaf-mapping hash, and TreeCover version/hash. The full mapping and private material are not placed in the extension.
3. Update `ArityState` only through a GroupContextExtensions proposal committed by MLS. All members must advertise support for `0xF001` before they are added to an experimental group, and a received commit is rejected if its state cannot be decoded, validated, or reconciled with the transition operation.
4. Bind the resulting authenticated GroupContext hash and extension state to ADR 0003's `HybridKdfContext` and to ADR 0004's hybrid AEAD associated data.
5. Do not use this extension as a ciphertext transport. The `HybridPathCiphertext` remains inside the forked UpdatePath node.

## Consequences

- Arity, tree-version, mapping, and TreeCover disagreement become commit-processing failures instead of local policy divergence.
- The extension can reveal experimental topology/state information when conveyed in MLS-visible protocol data; it is authenticated state, not a confidentiality mechanism.
- The private-use code point prevents accidental standards claims but can collide with another private deployment, so groups using it are strictly thesis-local.

## Rejected Alternatives

| Alternative | Reason rejected |
|---|---|
| Local configuration only | Members could derive different trees from the same MLS epoch. |
| An unauthenticated application message | It is not tied to the commit that changes tree state. |
| A standard extension code point | No standard allocation exists for this research behavior. |
| Store the hybrid ciphertext in the extension | It violates the UpdatePath placement requirement and bloats group context. |

## Verification Criteria

- Tests reject unsupported capability, unknown version, malformed state, wrong mapping hash, wrong TreeCover hash, and cross-group/epoch/tree-version replay.
- Every successful experimental commit produces equal `ArityState` and GroupContext hash at all valid members.
- Baseline groups do not negotiate or process extension `0xF001`.
