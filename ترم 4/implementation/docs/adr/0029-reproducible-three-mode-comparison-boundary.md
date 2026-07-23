# ADR 0029: Reproducible Three-Mode Comparison Boundary

**Status:** Accepted on 2026-07-22
**Decision scope:** Task 57 public comparison inputs, baseline repetitions, availability states, and validity limits

## Context

Task 57 requires a comparison of unchanged baseline MLS, binary MLS with mKyber delivery, and an adaptive binary-to-quaternary mode. The repository contains typed public configuration, a deterministic unchanged-baseline workload harness, isolated mKyber/hybrid delivery code, adaptive-tree/policy code, and report artifacts. It does not inject mKyber delivery, authenticated `ArityState`, candidate message emission, or a live transition into an OpenMLS Commit path. Executing an experimental mode or deriving a numeric delta from isolated components would therefore be a false protocol and performance claim.

## Decision

1. `report::comparison` accepts three public TOML files. Each must select its expected mode and the files must have exactly equal public group, transition, and execution controls. Output-path fields may differ because they are not a measurement control.
2. The runner executes only `BaselineBinaryMls`. For each configured independent repetition, it derives public uniform-workload and seeded-committer values by XORing the public workload seed, a fixed ASCII-domain constant, and the one-based run index. The derivation is public scheduling metadata only; MLS key generation continues to use operating-system entropy.
3. The runner excludes `warmup_accepted_commits` from its raw run aggregates. It records actual baseline Commit/Welcome bytes and monotonic accepted-lifecycle timing after warmup. A real retained no-Welcome result is zero bytes; it is not an unavailable value.
4. `BinaryMlsWithMkyber` and `AdaptiveBinaryToQuaternaryMls` receive typed `unavailable` comparison rows with reason `RequiresExperimentalOpenMlsFork`. Bandwidth outcome, mKyber CPU overhead, and adaptive break-even point have null numeric values. No estimate, zero, or percentage is substituted.
5. The create-new artifact set is `mode_comparison.csv`, `mode_comparison.json`, and `mode_comparison.md`. The JSON and Markdown retain the exact public TOML inputs, seed derivation, raw independent baseline runs, comparison status, and threats to validity.

## Consequences

- The checked-in Task 57 configuration triplet can be rerun and audited without exposing secret key material.
- Baseline data can be compared against future experimental outputs only after the same authenticated fork instrumentation executes all modes under equivalent controls.
- This partial runner is not a completed three-mode experiment and does not establish a bandwidth advantage, CPU overhead, break-even point, security property, interoperability property, or external validity.

## Verification Criteria

- Unit tests reject non-comparable controls and verify observed baseline rows plus typed unavailable experimental rows.
- The strict CLI parses all three public configurations and writes create-new output/report artifacts.
- Focused locked-offline formatting, report tests, and strict Clippy pass on the pinned Rust toolchain.
