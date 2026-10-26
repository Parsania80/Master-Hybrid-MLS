# ADR 0030: Bootstrap the Local OpenMLS Hybrid Fork

**Status:** Accepted on 2026-07-22
**Decision scope:** Fork provenance, source isolation, and activation boundary

## Context

ADR 0001 requires the experimental modes to use a separately named local fork
of OpenMLS 0.8.1, based on `openmls-v0.8.1` commit
`47dbedecad0c1fd8eb5368d582250ebfcc1e1ce6`. The repository previously had
only the crates.io baseline and isolated experimental boundaries, so no code
could modify OpenMLS's private UpdatePath and TreeSync internals.

## Decision

1. Import the complete upstream source tree into `crates/openmls-hybrid`, retaining its MIT `LICENSE`, notices, and sibling crates.
2. Rename only the fork leaf package to `openmls-hybrid` and add an empty, opt-in `experimental-hybrid` feature. The parent workspace's upstream `openmls = 0.8.1` dependency remains unchanged and is the sole baseline implementation.
3. Keep the fork's upstream workspace separate. Its retained sibling traits and crypto-provider crates are required because a forked core cannot safely exchange those types with the independently compiled crates.io packages.
4. Attach the fork only through the isolated `experimental-mls-adapter`; do not expose it through `mls-adapter`, simulation, reporting, or mode comparison until the fork implements the required authenticated UpdatePath, GroupContext extension, and atomic transition paths.
5. This bootstrap does not implement mKyber delivery, a 2-to-4 secret tree, TreeCover, capability negotiation, or a live experimental Commit. It cannot make Task 57 experimental values available.

## Consequences

- The exact upstream base is now local and reviewable without changing the RFC 9420 baseline.
- `experimental-hybrid` is disabled by default and has no behavior until later fork commits add narrowly reviewed code.
- The reviewed active parent graph adds only the local fork/adapter identities and the existing approved dependency set; inactive upstream test, CLI, SQLite, wasm, and benchmark tooling remains outside the active parent lock.

## Verification Criteria

- The public tag resolves to the required upstream commit before import.
- The fork retains `LICENSE` and `FORK-PROVENANCE.md` names the exact base.
- Parent Cargo metadata retains the crates.io `openmls` baseline and does not activate the fork.
- The isolated adapter must compile with the approved locked graph, run its link test and strict Clippy, and demonstrate that baseline tests still use only crates.io OpenMLS.
