# ADR 0007: Lock the Rust Toolchain and Direct Dependency Allowlist

**Status:** Accepted on 2026-07-18
**Decision scope:** Compiler, direct crates, features, licenses, and dependency-resolution policy

## Context

The implementation has not yet been scaffolded, so a `Cargo.lock` cannot exist without prematurely creating the workspace. The project nevertheless needs a fixed compiler and a reviewed direct-dependency allowlist before Task 8 creates `Cargo.toml`.

The local compatibility gate verified Rust 1.93.1 on `x86_64-pc-windows-msvc`, including `rustfmt` and Clippy. OpenMLS 0.8.1, its matching RustCrypto provider 0.5.1, and their shared TLS codec 0.4.2 were fetched and inspected. Package versions, licenses, yanked state, and declared Rust-version metadata for the remaining direct crates were read from crates.io on 2026-07-18.

## Decision

### Toolchain

- `rust-toolchain.toml` pins Rust `1.93.1`, minimal profile, `rustfmt`, and Clippy.
- The initial workspace manifest must set `rust-version = "1.93.1"`, `edition = "2021"`, and resolver `3`.
- The supported development target for the first acceptance run is `x86_64-pc-windows-msvc`. Cross-platform support is not claimed until each target is built and tested.

### Approved direct runtime dependencies

All production dependencies use an exact `=` version requirement. The feature selections below are the only approved features unless a later ADR changes this allowlist.

| Crate | Exact version | Approved purpose | License |
|---|---:|---|---|
| `openmls` | 0.8.1 | Unchanged RFC 9420 baseline; `default-features = false`, `openmls_rust_crypto` only | MIT |
| `openmls_rust_crypto` | 0.5.1 | Matching OpenMLS RustCrypto provider | MIT |
| `tls_codec` | 0.4.2 | Canonical TLS encoding for forked experimental wire data; `derive`, `mls` | Apache-2.0 OR MIT |
| `hkdf` | 0.12.4 | ADR 0003 hybrid KDF | MIT OR Apache-2.0 |
| `sha2` | 0.10.9 | SHA-256 / HKDF support | MIT OR Apache-2.0 |
| `sha3` | 0.10.8 | mKyber reference SHAKE primitives only | MIT OR Apache-2.0 |
| `aes-gcm` | 0.10.3 | Experimental AES-128-GCM path-secret wrapper | Apache-2.0 OR MIT |
| `rand` | 0.8.5 | OS-backed non-test randomness | MIT OR Apache-2.0 |
| `rand_chacha` | 0.3.1 | Isolated deterministic workload/test RNG | MIT OR Apache-2.0 |
| `rand_core` | 0.6.4 | RNG trait boundary for the mKyber abstraction | MIT OR Apache-2.0 |
| `zeroize` | 1.9.0 | Best-effort secret clearing; `derive` only | Apache-2.0 OR MIT |
| `subtle` | 2.6.1 | Constant-time selection/equality helpers where applicable | BSD-3-Clause |
| `thiserror` | 2.0.18 | Typed public errors without secret-bearing debug output | MIT OR Apache-2.0 |
| `serde` | 1.0.228 | Typed configuration and safe public records; `derive` | MIT OR Apache-2.0 |
| `serde_json` | 1.0.150 | JSON reports and safe snapshots | MIT OR Apache-2.0 |
| `toml` | 1.1.3+spec-1.1.0 | TOML configuration | MIT OR Apache-2.0 |
| `clap` | 4.6.2 | CLI parsing; `derive` only | MIT OR Apache-2.0 |
| `csv` | 1.4.0 | CSV reports | Unlicense/MIT |
| `hex` | 0.4.3 | Encoding public hashes and identifiers only | MIT OR Apache-2.0 |

### Approved development dependencies

| Crate | Exact version | Approved purpose | License |
|---|---:|---|---|
| `proptest` | 1.11.0 | Property tests for mapping, formulas, codecs, and state transitions | MIT OR Apache-2.0 |
| `tempfile` | 3.27.0 | Isolated report/config test directories | MIT OR Apache-2.0 |

### Feature and provenance constraints

- Do not enable OpenMLS `content-debug`, `crypto-debug`, `test-utils`, SQLite, libcrux, or JavaScript features in normal or release builds. Test-only feature use requires a documented reason and must not reach experiment binaries.
- `openmls-hybrid` is a local, separately named fork based on the `openmls-v0.8.1` tag. It is not a crates.io dependency and must retain upstream license/notice material.
- No ML-KEM, Kyber, mKyber, native-code, database, telemetry, plotting, statistics, or logging crate is approved by this ADR. In particular, ordinary ML-KEM remains prohibited as an mKyber substitute.
- All manifest versions must be exact. `Cargo.lock` is generated and committed in Task 8; direct or transitive updates require an explicit review, lockfile diff, and `SESSION-LOG.md` entry.
- Cargo audit/advisory review is a later acceptance gate once a lockfile exists. Passing compilation does not constitute cryptographic audit or side-channel review.

## Compatibility Gate Results

| Check | Result |
|---|---|
| `rustc -Vv` | Rust 1.93.1, commit `01f6ddf7588f42ae2d7eb0a2f21d44e8e96674cf`, host `x86_64-pc-windows-msvc` |
| `cargo -V` | Cargo 1.93.1 |
| Formatting/lint components | `rustfmt` 1.8.0-stable and Clippy 0.1.93 installed |
| Pinned-channel bootstrap | `rust-toolchain.toml` syntax was statically verified. Rustup's exact-channel acquisition exceeded the local 30-second command limit, so repository-level compiler invocation must be rechecked once Rustup completes that download. |
| OpenMLS availability | `cargo info openmls@0.8.1` succeeded; MIT; feature `openmls_rust_crypto` available |
| Provider availability | `cargo info openmls_rust_crypto@0.5.1` succeeded; MIT |
| Codec alignment | Inspected manifests show OpenMLS 0.8.1 and its provider both require `tls_codec` 0.4.2 |
| Allowlist package metadata | All listed exact releases were non-yanked and have licenses compatible with this thesis workspace; their declared Rust versions, when present, are no greater than 1.85 |
| Cargo resolution | Deferred to Task 8 because no `Cargo.toml` or workspace exists yet; creating one here would violate the roadmap boundary |

## Consequences

- Task 8 can create the workspace with a reproducible compiler and a closed direct-dependency set.
- Exact direct requirements and the committed lockfile prevent unreviewed dependency drift, while still allowing Cargo to resolve required transitive dependencies.
- The allowlist intentionally does not solve the mKyber implementation problem; ADR 0002 and `SECURITY.md` continue to govern that research-only component.

## Verification Criteria

- Opening the repository selects Rust 1.93.1 with `rustfmt` and Clippy.
- Task 8 reproduces the listed direct requirements in `Cargo.toml`, generates `Cargo.lock`, and passes `cargo metadata --locked`.
- A lockfile review confirms no prohibited direct crate or OpenMLS debug feature is enabled.
