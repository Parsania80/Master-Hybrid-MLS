# ADR 0001: Use OpenMLS for the Baseline and a Separate Experimental Fork

**Status:** Accepted on 2026-07-18
**Decision scope:** MLS implementation selection and fork/module boundary

## Context

The thesis needs an unchanged RFC 9420 binary MLS baseline and a deliberately non-standard mode that changes UpdatePath encryption, decryption, and serialization. The completed [candidate comparison](../research/MLS-CANDIDATE-COMPARISON.md) found that both OpenMLS and `mls-rs` require an internal TreeKEM fork for the latter; neither public extension API can place the required hybrid ciphertext inside UpdatePath.

OpenMLS 0.8.1 is the current upstream release selected for this research snapshot. It implements RFC 9420 and supports the mandatory-to-implement ciphersuite selected in ADR 0003. The upstream [release](https://github.com/openmls/openmls/releases/tag/openmls-v0.8.1) and [API documentation](https://docs.rs/openmls/0.8.1/openmls/) are the source of record for this pin.

## Decision

1. The standard `BaselineBinaryMls` mode uses the upstream crate `openmls = "=0.8.1"`, without any Cargo-wide patch or experimental feature.
2. The experimental `BinaryMlsWithMkyber` and `AdaptiveBinaryToQuaternaryMls` modes use a separately named local fork, `openmls-hybrid`, based initially on the signed `openmls-v0.8.1` tag (`47dbede`).
3. The fork changes only the experimental UpdatePath codec, hybrid send/receive path, experimental extension validation, and measurement hooks. It must retain upstream tests and expose an `experimental-hybrid` feature that is disabled by default.
4. `crates/mls-adapter` owns mode selection behind a project trait. Baseline tests instantiate the upstream dependency directly; experimental tests explicitly instantiate the fork. The two paths must coexist in one workspace without a global `[patch.crates-io]` replacement.
5. Every fork commit must identify its upstream base revision and retain the upstream license and notices. A rebase onto a later upstream security release is a deliberate maintenance task, not an automatic dependency update.

## Consequences

- Baseline interoperability and regression checks remain meaningful because upstream code is exercised unchanged.
- The non-standard protocol surface is visible, reviewable, and unable to silently alter baseline behavior.
- The project accepts ongoing fork-maintenance cost and does not claim that experimental commits interoperate with stock RFC 9420 implementations.
- `mls-rs` remains a researched alternative, but is not an approved dependency for this workspace.

## Rejected Alternatives

| Alternative | Reason rejected |
|---|---|
| Use `mls-rs` as the primary base | Its public UpdatePath types do not remove the need to change internal creation and application logic; the comparison found the OpenMLS boundary more isolated. |
| Patch `openmls` globally | It would cause baseline tests to exercise altered code and make accidental protocol drift difficult to detect. |
| Send a hybrid ciphertext sidecar | The thesis requires the ciphertext to be carried in the corresponding UpdatePath level, not in a detached protocol. |
| Modify only application code | The needed TreeKEM operations and codecs are internal to the MLS implementation. |

## Verification Criteria

- Cargo metadata must show both an unmodified `openmls` 0.8.1 baseline dependency and a separately named experimental fork.
- Baseline integration tests must pass using upstream `openmls` alone.
- A fork-diff review must show no non-experimental change outside the stated boundary.
