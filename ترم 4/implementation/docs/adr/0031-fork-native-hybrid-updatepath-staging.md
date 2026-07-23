# ADR 0031: Stage a Fork-Native Hybrid UpdatePath API Before Wire Replacement

**Status:** Accepted on 2026-07-22
**Decision scope:** First live-fork integration sequence and type-universe boundary

## Context

ADR 0030 imports and compiles the isolated `openmls-hybrid` package. The existing `hybrid-path-secret` crate owns canonical hybrid wire bytes and the thesis-local sender/receiver engine, but its execution APIs are typed against crates.io OpenMLS and its RustCrypto provider. The fork has separate local trait/provider types. Passing those types across the boundary would either fail to compile or silently encourage a mixed upstream/fork state model.

The fork's `UpdatePathNode` currently serializes only standard HPKE ciphertexts and its private TreeSync functions directly encrypt/decrypt `PathSecret` values. A detached hybrid sidecar would violate ADR 0001 and ADR 0005 because hybrid delivery must replace the corresponding node's path-secret representation and remain covered by the same outer Commit authentication.

## Decision

1. Keep the compiled `experimental-mls-adapter` as an isolated activation boundary; `mls-adapter` remains upstream-only.
2. Before changing `UpdatePathNode`, add fork-native experimental capability/key material and a narrow adapter that accepts canonical public hybrid wire bytes without passing upstream OpenMLS provider types into the fork.
3. Replace—not augment—the experimental `UpdatePathNode` delivery representation behind `experimental-hybrid`. The standard wire and behavior remain unchanged when the feature is disabled.
4. Implement fork sender and receiver paths together: canonical serialization, capability checks, context binding, decapsulation/AEAD failure, GroupContext extension validation, and staged atomic TreeSync/GroupContext mutation must all reject before merge on failure.
5. Attach the existing typed metric/report instrumentation only after accepted experimental commits expose real values. Until then Task 57 continues to mark experimental results unavailable.

## Consequences

- The next code change is a capability/key-material and fork-native interface task, not a superficial CSV/report change.
- A full mKyber experimental path needs separate fork-owned provider integration or a provider-agnostic refactor of the existing hybrid execution engine.
- Adaptive 2-to-4 behavior remains a later layer after binary-with-mKyber commits converge and reject tampering correctly.

## Verification Criteria

- The parent lock contains only the local fork activation packages plus existing approved dependencies; inactive upstream test/CLI/SQLite tooling is not activated.
- `experimental-mls-adapter` builds, tests, and passes strict Clippy with `experimental-hybrid` enabled.
- The upstream baseline regression still passes while metadata includes both distinct package identities.
- No experimental report row becomes numeric before a real accepted fork Commit records it.
