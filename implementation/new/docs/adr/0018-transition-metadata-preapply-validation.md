# ADR 0018: Transition Metadata Pre-Apply Validation

**Status:** Accepted on 2026-07-20
**Decision scope:** Task 43 GroupContext-bound metadata consistency and fail-closed handoff

## Context

Tasks 41 and 42 define canonical public transition state, mapping, and TreeCover data, but their separate validation cannot prove that all values came from one authenticated MLS GroupContext. A future experimental fork must reject inconsistent values before it stages or merges a transition. The current repository has no experimental OpenMLS fork and must not claim to perform MLS signature or commit authentication itself.

## Decision

1. The internal `transition-auth` crate accepts an `AuthenticatedGroupContext` only as facts extracted from an already MLS-authenticated complete GroupContext by a future fork. It records group ID, epoch, and SHA-256 hash of the exact GroupContext bytes for the thesis's fixed SHA-256 ciphersuite. Its constructor does not verify MLS signatures or parse GroupContext bytes.
2. `TransitionMetadataEnvelope` carries that binding, the exact extracted extension type/value, canonical leaf mapping, and canonical TreeCover state. `validate_pre_apply` never mutates live state.
3. Validation requires extension type `0xF001`, exact canonical `ArityState` bytes, a `Transitioning` lifecycle, and transition epoch equal to the authenticated GroupContext epoch.
4. Validation reconstructs `TransitionTrees`, thereby rejecting mapping hash, TreeCover version, TreeCover hash, active-arity, and state inconsistencies before trees are exposed.
5. The supplied `HybridKdfContext` must exactly match the authenticated GroupContext group ID, epoch, and hash, and the decoded state tree version and active arity. This binds future hybrid KDF/AEAD usage to the same public metadata.
6. A public SHA-256 metadata commitment over a fixed label, GroupContext hash, extension type, and exact extension value is returned only after validation. It is an audit commitment, not a signature, MAC, replacement for MLS authentication, or proof that an arbitrary caller extracted the extension from GroupContext bytes.
7. The future fork must construct this envelope only from a successfully authenticated, staged GroupContext extension list and must apply the validated state atomically with its transition Commit. Task 44 will test convergence and atomic failure behavior.

## Consequences

- Public mismatch failures occur before callers obtain active/TreeCover state through this boundary.
- Replay or substitution across group ID, epoch, tree version, arity, GroupContext hash, mapping, or TreeCover state fails deterministically at this layer.
- The boundary does not add an independent authentication primitive, emit a proposal/commit, validate MLS signatures, alter baseline OpenMLS behavior, or establish interoperability/security claims.

## Verification

- Unit tests accept matching facts and reject wrong extension type/state version/state lifecycle, transition epoch, mapping hash, TreeCover version, hybrid group ID, epoch, tree version, arity, and GroupContext hash.
- Locked offline formatting, checking, strict Clippy, and focused crate tests must pass.
