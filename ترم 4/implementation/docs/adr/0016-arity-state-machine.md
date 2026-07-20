# ADR 0016: ArityState Canonical State Machine

**Status:** Accepted on 2026-07-20
**Decision scope:** Task 41 public `ArityState` representation, start-state validation, and extension-value boundary

## Context

ADR 0005 reserves private-use extension `0xF001` for adaptive-tree metadata, and Tasks 35 through 40 now produce the public policy inputs that determine whether a transition may start. Before a fork can apply a transition atomically, members need one canonical representation of the policy thresholds, latest evaluation facts, tree version, deterministic mapping identity, TreeCover identity, and lifecycle. Local configuration or an unstructured report record could create split-brain state.

## Decision

1. The new internal `arity-state` crate defines version-1 `ArityState` for extension type `0xF001`. Its project-local value encoding starts with `AHAS` and state version `1`; decoding rejects malformed, unknown, and trailing data.
2. Every state stores active/candidate arity, logical tree version, a full public `ArityPolicySnapshot`, and `TransitionEvaluationState`. The snapshot contains the accepted-commit window and warmup lengths, `q_min`, target size, stable epoch count, configured byte-or-micro-percent Delta form, resolved Delta bytes, and the preflight bytes used for that resolution. Its SHA-256 digest is encoded and rechecked against the canonical controls.
3. The public evaluation state records the latest evaluated epoch, consecutive target-size epochs, and current-window impactful count. This preserves the threshold inputs that justified a dedicated transition rather than treating a report as authorization.
4. `Normal` has no mapping or TreeCover binding. For this thesis's first migration, a binary normal state has tree version zero. A quaternary normal state requires a non-zero tree version and is reserved for the later retirement path.
5. `Transitioning` requires active/candidate quaternary arity, a non-zero incremented tree version, the epoch immediately after the triggering evaluation, a SHA-256 digest of complete canonical mapping bytes, and a non-zero-version TreeCover binding with a SHA-256 digest of complete canonical TreeCover public bytes.
6. `begin_transition` accepts only a normal binary state and a Task 38 evaluation whose five conditions are all satisfied. It independently verifies retained stable and impactful counts, increments tree version, and rejects a second start. Retirement and a return to `Normal` remain Task 49 work.
7. This crate emits and validates a canonical *extension value*, not a live MLS extension proposal or authenticated commit. Task 43 must place the value into the full GroupContext extension list, bind it to the authenticated GroupContext hash and hybrid context, preserve required extensions, and reject mismatches atomically.

## Consequences

- State serialization and transition authorization inputs are deterministic public data, suitable for comparison by every experimental member once integrated.
- Hash values authenticate only through their future MLS-carried extension; hash calculation and local validation alone are not commit authentication.
- The crate contains no private keys, MLS client, random input, TreeCover routing data, secret derivation, or transition message construction.
- This is thesis-local research metadata. It does not establish a convergent transition, RFC 9420 interoperability, atomic fork behavior, or any security proof.

## Verification

- Unit tests cover normal/transitioning canonical round trips, triggered-only start, duplicate-start rejection, post-retirement normal rejection for a new first transition, policy-Delta consistency, policy-digest tampering, impossible lifecycle arity, and trailing bytes.
- Locked offline formatting, checking, strict Clippy, and focused crate tests must pass.
