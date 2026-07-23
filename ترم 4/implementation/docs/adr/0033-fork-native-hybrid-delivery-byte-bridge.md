# ADR 0033: Fork-Native Hybrid Delivery Byte Bridge

**Status:** Accepted on 2026-07-22
**Decision scope:** Canonical hybrid delivery admission before experimental UpdatePath wire replacement

## Context

ADR 0032 provides signed public mKyber recipient keys, but the existing
`hybrid-path-secret` sender/receiver engine is compiled against crates.io
OpenMLS traits and RustCrypto provider types. The local `openmls-hybrid` fork
uses distinct local trait/provider package identities. Passing those types into
the fork would violate ADR 0031's type-universe boundary.

The existing hybrid crate does own a provider-independent public wire boundary:
`HybridPathCiphertext::commit_authenticated_bytes()` and its exact parser.
Those bytes contain no private mKyber or HPKE key, shared secret, path secret,
or provider object. They can therefore be admitted into the fork only after
strict canonical validation and node-index binding.

## Decision

1. Under `experimental-hybrid`, `openmls-hybrid` depends on the existing
   internal `hybrid-path-secret` crate only to parse and re-serialize canonical
   public wire bytes. No crates.io OpenMLS trait or provider type appears in the
   fork-facing API.
2. `ExperimentalHybridPathDelivery` stores only validated canonical bytes and
   its enclosing path-node index. Construction parses exact bytes, compares the
   embedded `PathNodeIndex` with the enclosing node index, re-serializes, and
   rejects any mismatch or non-canonical encoding.
3. This type is a pre-node component, not a detached transport sidecar. The
   next fork change must make it the experimental replacement for a
   `UpdatePathNode` path-secret delivery field, so the ordinary outer MLS Commit
   signature authenticates it.
4. No sender, receiver, TreeSync mutation, GroupContext mutation, or report
   metric is enabled by this bridge. Those operations require a fork-native
   provider implementation or a reviewed provider-agnostic refactor, followed
   by sender/receiver atomic application tests.

## Consequences

- The fork has one narrow, validated way to carry canonical hybrid public
  delivery data without exchanging incompatible OpenMLS type-universe values.
- The active dependency graph gains only edges to existing internal
  `hybrid-path-secret` and `mkyber` crates; it introduces no package version or
  network fetch.
- A malformed, trailing, alternate, or wrong-node ciphertext is rejected before
  it can become experimental fork state.
- Task 57 remains unavailable for experimental modes until this value is
  actually placed in, authenticated by, and successfully opened from a live
  forked Commit.

## Verification Criteria

- A canonical hybrid fixture is admitted only when its embedded and enclosing
  path-node indexes match.
- A node-index mismatch is rejected.
- Isolated adapter tests, strict Clippy, formatting, and unchanged baseline
  regression pass with the locked offline graph.
