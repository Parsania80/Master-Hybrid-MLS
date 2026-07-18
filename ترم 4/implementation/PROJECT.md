# Adaptive Hybrid MLS TreeKEM Research Prototype

## Tech Stack

- Language: stable Rust. The repository must pin the toolchain and minimum supported Rust version after dependency selection; the available development host currently has Rust 1.93.1.
- Build and workspace management: Cargo workspace with `rustfmt` and Clippy as mandatory quality gates.
- Baseline MLS: upstream `openmls = "=0.8.1"` using `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`; a separately named, feature-gated `openmls-hybrid` fork is permitted only for experimental modes. See ADR 0001 and ADR 0003.
- Baseline protocol: RFC 9420 binary TreeKEM behavior must remain available, isolated, and independently testable.
- Experimental post-quantum component: mKyber512 parameters from the cited multi-recipient KEM research paper, isolated behind a replaceable `MultiRecipientKem` trait. Ordinary ML-KEM is not an acceptable substitute for mKyber.
- Experimental hybrid construction: classical MLS/HPKE plus reference-only mKyber512, HKDF-SHA256, and AES-128-GCM as defined in ADR 0002 and ADR 0003; experimental modes are non-interoperable research code.
- Configuration and outputs: TOML input; CSV, JSON, Markdown, and optional SVG output; filesystem storage only and no database.
- Randomness: deterministic seeded RNG only for tests and reproducible experiments; operating-system cryptographic RNG for non-experiment operation.
- Supporting crates: none are approved yet. CLI, serialization, error, metrics, statistics, zeroization, testing, and plotting dependencies must be added here and pinned before use.
- Dependency rule: `Cargo.lock` is committed for reproducibility. No language, framework, library, or new crate may be introduced until this section is updated and the choice is recorded in `SESSION-LOG.md`.

## Architecture

- Current state: documentation initialization only. No Cargo workspace, Rust source, configuration, tests, or generated results exist yet.
- `/agent.md`: Human-agent operating protocol and documentation rules.
- `/PROJECT.md`: Single source of truth for scope, architecture, dependency lock, and progress.
- `/SESSION-LOG.md`: Append-only audit trail for actions, commands, results, decisions, and limitations.
- `/README.md`: Plain-language project purpose, status, security warning, and high-level usage.
- `/SECURITY.md`: Mandatory security boundary, non-standard protocol inventory, threat model, interoperability limits, and unresolved thesis assumptions.
- `/docs/research/MLS-CANDIDATE-COMPARISON.md`: Completed Task 2 source-level comparison of OpenMLS and `mls-rs`; this is evidence for a future ADR, not a dependency selection.
- `/docs/research/MKYBER-IMPLEMENTATION-AUDIT.md`: Completed Task 3 audit of the paper parameters, available implementations, licenses, test-vector status, and reuse boundary.
- `/docs/adr`: Accepted architecture decisions for the MLS base/fork boundary, mKyber strategy, ciphersuite/KDF/AEAD, hybrid wire encoding, and extension authentication.
- `/Cargo.toml` and `/Cargo.lock` (planned): Stable-Rust workspace definition and exact reproducible dependency resolution.
- `/configs` (planned): Default, update-only, removal-heavy, and other experiment configurations. CLI values override TOML values through one validated configuration model.
- `/crates/mls-adapter` (planned): Thin adapter around the selected maintained MLS library. Standard binary MLS behavior remains unchanged and independently testable.
- `/crates/mkyber` (planned): Experimental mKyber512 implementation or audited adapter behind `MultiRecipientKem`; common and per-recipient ciphertext components remain distinct.
- `/crates/hybrid-path-secret` (planned): Experimental authenticated wire structure and domain-separated path-key derivation combining the classical and mKyber shared secrets.
- `/crates/adaptive-tree` (planned): Binary active tree, quaternary shadow/new tree, deterministic leaf mapping, `ArityState`, and old binary `TreeCover`, with old and new state strictly separated.
- `/crates/transition-policy` (planned): Sliding evaluation window, impactful-commit classification, transition-start savings formulas, maturity formulas, edge-case handling, and OR-based retirement rule.
- `/crates/metrics` (planned): Typed counters, serialized byte measurements, timings, transition values, and measured-versus-estimated provenance.
- `/crates/simulation` (planned): Deterministic member population, workload generation, committer strategies, commit broadcast/application, and convergence checks.
- `/crates/report` (planned): Plot-ready CSV, JSON summaries, Markdown reports, descriptive statistics, and optional SVG charts.
- `/src/bin/bootstrap_128.rs` (planned): Build and verify a valid 128-member baseline binary MLS group and emit safe public experiment artifacts.
- `/src/bin/evaluate_transition.rs` (planned): Run controlled multi-committer workloads, evaluate 2-to-4 transition policy, and generate complete reports.
- `/tests` (planned): Baseline, hybrid-path, tamper/replay, transition-start, transition-end, property, regression, and 128-member convergence tests.
- `/output` and `/report` (planned): Generated artifacts only; reports must never contain private keys, shared secrets, path secrets, AEAD keys, raw entropy, or a seed capable of reconstructing secret key material.
- Data flow: validated configuration and separate public experiment seed/secret entropy feed the simulator; the MLS adapter executes the unchanged baseline path; experimental modes add mKyber delivery and hybrid key derivation; the shadow quaternary tree evaluates the same logical operation without mutating group state; transition policy consumes measured serialized costs; metrics and reports receive only safe observations.
- Supported modes: `BaselineBinaryMls`, `BinaryMlsWithMkyber`, and `AdaptiveBinaryToQuaternaryMls`.
- Transition invariant: while transitioning, the quaternary tree produces fresh secrets and the old binary tree is delivery-only `TreeCover`; epoch secrets are derived from exactly one active root.
- Authentication invariant: arity, transition state, tree version, deterministic leaf mapping, TreeCover version, node indices, and group-context binding are authenticated and checked for member convergence.
- Hybrid KDF invariant: the input is `ss_classical || ss_pq || domain_separation_context`; mKyber ciphertext bytes are transmitted and authenticated but explicitly excluded from the KDF input. The context includes the label `Adaptive-Hybrid-TreeKEM-PathSecret-v1`, ciphersuite, group, epoch, tree version, current arity, path-node index, recipient-node index, and authenticated group-context hash.
- Research boundary: every non-standard component is experimental and not production cryptography. Experimental modes must not claim RFC 9420 interoperability, a formal security proof, or automatic coverage by the X-Wing C2PRI argument.
- Measurement invariant: use actual serialized message sizes whenever possible. Any unavoidable estimate records `measured_bytes`, `estimated_bytes`, and `estimation_method`; fake or unexplained constants are forbidden.

## Roadmap

### Part 1: Ecosystem Research and Architecture Decisions

| # | Task | Status | Notes |
|---|------|--------|-------|
| 1 | Capture the complete thesis requirements, audit the greenfield directory, and initialize governed documentation | ✅ Done | No implementation artifacts exist; documentation status must not imply otherwise. |
| 2 | Compare maintained Rust MLS candidates and identify the least invasive UpdatePath, extension, serialization, and instrumentation seams | ✅ Done | Both require an experimental fork for UpdatePath changes; OpenMLS is the preliminary recommendation for Task 4. See `docs/research/MLS-CANDIDATE-COMPARISON.md`. |
| 3 | Audit the mKyber paper, parameter set, available implementations, licenses, test vectors, and reuse options | ✅ Done | No compatible maintained Rust backend was found. The relevant public C WIP is parameter-incompatible and lacks an explicit repository license for its modifications; see `docs/research/MKYBER-IMPLEMENTATION-AUDIT.md`. |
| 4 | Write ADRs for the selected MLS base, mKyber strategy, ciphersuite/KDF/AEAD choices, wire encoding, extension authentication, and fork/module boundary | ✅ Done | ADRs 0001-0005 pin OpenMLS 0.8.1, the reference-only mKyber strategy, hybrid KDF/AEAD, wire constraints, and private-use authenticated state. |
| 5 | Specify every non-standard protocol change, threat, interoperability limitation, and unresolved thesis assumption in `SECURITY.md` | ✅ Done | `SECURITY.md` documents the experimental boundary, KDF ciphertext exclusion, X-Wing/C2PRI limitation, redaction rules, and SEC-01 through SEC-10 closure criteria. |
| 6 | Resolve measurement semantics and ambiguities before scaffolding | 🔄 Current | Define window length, Delta precedence, pre-transition cost measurement, effective commits, target-set aggregation, leaf mapping, TreeCover construction, warmups, repetitions, and standard-deviation convention. |
| 7 | Lock the toolchain and approved dependencies, then run the Phase 1 documentation and compatibility gate | ⬜ Todo | Record exact commands, results, changed files, and remaining limitations. |

### Part 2: Baseline Binary MLS

| # | Task | Status | Notes |
|---|------|--------|-------|
| 8 | Scaffold the Cargo workspace and crate boundaries without experimental behavior in the baseline path | ⬜ Todo | Preserve dependency and feature isolation. |
| 9 | Implement the maintained-library adapter for normal RFC 9420 proposals, commits, UpdatePath processing, and application messages | ⬜ Todo | Baseline behavior must remain unchanged. |
| 10 | Create a small group, add/remove/update members through valid MLS operations, and deliver each commit to every valid member | ⬜ Todo | Use multiple valid committers. |
| 11 | Add independent baseline integration/regression tests for convergence, tree hashes, epochs, group contexts, and message encryption/decryption | ⬜ Todo | Retain upstream baseline tests where a fork is required. |
| 12 | Pass the Phase 2 formatting, strict lint, unit, integration, and baseline regression gate | ⬜ Todo | Log exact commands and raw outcome summaries. |

### Part 3: Experimental mKyber Abstraction

| # | Task | Status | Notes |
|---|------|--------|-------|
| 13 | Define the replaceable `MultiRecipientKem` trait and typed errors | ⬜ Todo | Cover keygen, set encapsulation, per-recipient extraction, and decapsulation. |
| 14 | Integrate an audited compatible backend or implement a clearly labeled reference-only mKyber512 research backend | ⬜ Todo | Reference code is unsuitable for production and must remain replaceable. |
| 15 | Separate common and per-recipient ciphertext components and instrument their real serialized byte costs | ⬜ Todo | Do not report ordinary ML-KEM costs as mKyber measurements. |
| 16 | Implement deterministic test mode, OS-RNG production path, secret redaction, and zeroization where applicable | ⬜ Todo | A published experiment seed must never reconstruct private key material. |
| 17 | Add known-answer/unit/property tests for recipient agreement, non-recipient failure, malformed ciphertexts, and deterministic reproducibility | ⬜ Todo | Include common and per-recipient tamper cases. |
| 18 | Pass the Phase 3 formatting, strict lint, test, and standalone benchmark gate | ⬜ Todo | Report exact mKyber implementation status honestly. |

### Part 4: Experimental Hybrid Path-Secret Delivery

| # | Task | Status | Notes |
|---|------|--------|-------|
| 19 | Define and authenticate `HybridPathCiphertext` with classical, PQ common, PQ recipient, encrypted-secret, and node-index fields | ⬜ Todo | PQ ciphertext is present on the wire. |
| 20 | Implement canonical domain-separation context encoding and the hybrid KDF input builder | ⬜ Todo | Bind all mandatory MLS/tree fields and reject ambiguous encodings. |
| 21 | Integrate classical HPKE and one mKyber shared secret per co-path resolution into each experimental UpdatePath level | ⬜ Todo | Baseline mode bypasses this module. |
| 22 | Prove by focused tests/instrumentation that PQ ciphertext is excluded from KDF input while still serialized and authenticated | ⬜ Todo | Never expose the underlying secrets in logs or fixtures. |
| 23 | Add recipient/non-recipient, tamper, and cross-group/epoch/tree-version/node replay tests | ⬜ Todo | Classical, PQ common, PQ recipient, and AEAD changes must fail safely. |
| 24 | Pass the Phase 4 formatting, strict lint, integration, property, and regression gate | ⬜ Todo | Re-run unchanged baseline tests. |

### Part 5: Reproducible 128-Member Bootstrap

| # | Task | Status | Notes |
|---|------|--------|-------|
| 25 | Implement `bootstrap_128.rs` using valid Add proposals/commits and full commit delivery | ⬜ Todo | Support exactly the documented CLI and multiple committers. |
| 26 | Verify 128 members, binary arity, height 7, occupied leaves, common epoch/context/tree hash, application messages, and secret cleanup | ⬜ Todo | Fail the run rather than emit a success report on any mismatch. |
| 27 | Design a safe reproducible snapshot that separates public scheduling seed from secret key-generation entropy | ⬜ Todo | Persist public tree, metadata, public key packages, and configuration only. |
| 28 | Generate bootstrap summary JSON, commit CSV, and Markdown report under the requested output directory | ⬜ Todo | Reconcile directory and filename conventions in the CLI contract. |
| 29 | Pass the Phase 5 tests and a release-mode 128-member acceptance run | ⬜ Todo | Archive exact configuration, compiler/dependency versions, command, and safe outputs. |

### Part 6: Shadow Quaternary Tree and Cost Measurement

| # | Task | Status | Notes |
|---|------|--------|-------|
| 30 | Implement deterministic binary-to-quaternary leaf mapping and a non-mutating shadow tree | ⬜ Todo | Mapping/version metadata must be canonical and later authenticated. |
| 31 | Replay each logical operation against the shadow tree without changing real MLS state or consuming mismatched randomness | ⬜ Todo | Define reproducible counterfactual methodology in an ADR. |
| 32 | Measure real `B_i(2)` and candidate `B_hat_i(4)` with component-level serialized byte provenance | ⬜ Todo | Label every measurement versus estimate. |
| 33 | Track tree heights, direct paths, resolutions, blanks, populated nodes, recipient counts, and crypto operation/timing metrics | ⬜ Todo | Use typed per-commit records. |
| 34 | Pass the Phase 6 determinism, measurement-consistency, formatting, lint, and test gate | ⬜ Todo | Re-run baseline and hybrid regression suites. |

### Part 7: Transition-Start Policy

| # | Task | Status | Notes |
|---|------|--------|-------|
| 35 | Implement configurable sliding window `W_e`, `q_e`, `r_e`, and explicit `is_impactful_commit` classification | ⬜ Todo | Store the inclusion or exclusion reason for every accepted commit. |
| 36 | Measure `B_transition` from serialized transition-only protocol data without mutating the live group during evaluation | ⬜ Todo | Include commit, new-tree, leaf-map, version, TreeCover, and other transition-only bytes. |
| 37 | Implement the average and direct savings formulas with checked integer/rational rounding | ⬜ Todo | Property-test their equivalence. |
| 38 | Implement every start condition and record the exact blocking/triggering condition | ⬜ Todo | Defaults: size 128 for 5 epochs, `q_min=5`, candidate arity twice current, and positive thresholded saving. |
| 39 | Support configurable Delta in bytes or as a percentage of `B_transition`, plus TOML/CLI overrides | ⬜ Todo | Define mutual exclusion and precedence during Phase 1. |
| 40 | Pass start-gating, positive-trigger, formula-equivalence, formatting, lint, and regression tests | ⬜ Todo | Transition must never start early. |

### Part 8: Authenticated Transition State and TreeCover

| # | Task | Status | Notes |
|---|------|--------|-------|
| 41 | Implement authenticated `ArityState` and `Normal`/`Transitioning` state-machine validation | ⬜ Todo | Include thresholds, evaluation state, transition epoch, impactful count, and tree version. |
| 42 | Implement the new active quaternary tree and old binary delivery-only `TreeCover` as separate state | ⬜ Todo | Never derive an epoch secret from two roots. |
| 43 | Authenticate transition metadata and reject arity, version, state, mapping, group-context-hash, or TreeCover-version inconsistencies | ⬜ Todo | Validate before state mutation. |
| 44 | Verify all members converge after transition commits and divergent/tampered commits fail atomically | ⬜ Todo | Cover multiple committers and recipient resolutions. |
| 45 | Pass the Phase 8 formatting, strict lint, state-machine, rejection, convergence, and regression gate | ⬜ Todo | Record unresolved security limitations. |

### Part 9: Transition Maturity and TreeCover Retirement

| # | Task | Status | Notes |
|---|------|--------|-------|
| 46 | Measure actual `C_leaf`, `C_new`, `C_old`, and `C_ideal` for each defined recipient target set | ⬜ Todo | Preserve raw component costs and availability state. |
| 47 | Implement `h_new_cost` and `h_old_cost` with checked zero/negative/empty/unavailable handling | ⬜ Todo | Record raw values, clamped values, and every clamp reason. |
| 48 | Implement `h_new_cost >= theta_new OR h_old_cost < theta_old` with defaults 0.70 and 0.50 | ⬜ Todo | Tests must distinguish OR from AND and trigger each side independently. |
| 49 | Retire TreeCover, record epoch/trigger, erase applicable old secrets, return to `Normal`, increment version, and verify convergence | ⬜ Todo | Retirement must be authenticated and atomic. |
| 50 | Pass edge-case, threshold-boundary, retirement, erasure, formatting, lint, and regression tests | ⬜ Todo | Include unavailable-cover and division-by-zero cases. |

### Part 10: Transition Evaluation, Reports, and Thesis Acceptance

| # | Task | Status | Notes |
|---|------|--------|-------|
| 51 | Implement `evaluate_transition.rs` with snapshot/recreate support and the documented CLI | ⬜ Todo | Continue until retirement or configured maximum commits. |
| 52 | Implement round-robin, seeded-random, fixed-list, weighted-random, and leaf-region-balanced committer strategies | ⬜ Todo | Report actual member/region distribution. |
| 53 | Implement update-only, mixed, removal-heavy, region-skewed, and uniform workloads | ⬜ Todo | Apply every accepted commit to all valid members and verify convergence. |
| 54 | Record the complete required per-commit identity, topology, crypto-count, byte, timing, window, transition, and retirement schema | ⬜ Todo | No fake values; unavailable metrics are explicit. |
| 55 | Generate `commits.csv`, `epochs.csv`, `transition_events.csv`, `summary.json`, and `report.md` | ⬜ Todo | Include all 27 required report subjects and mandatory security limitation. |
| 56 | Generate plot-ready data and, if practical, SVG charts for bytes, costs, savings, maturity, TreeCover size, and timings | ⬜ Todo | Charts are derived from the same typed records as CSV. |
| 57 | Compare baseline, binary-with-mKyber, and adaptive 2-to-4 modes under reproducible configurations | ⬜ Todo | Report bandwidth outcome, mKyber CPU overhead, break-even point, and threats to validity. |
| 58 | Complete unit, integration, property, regression, strict Clippy, format, test, and release-experiment acceptance gates | ⬜ Todo | `cargo clippy` treats warnings as errors. |
| 59 | Deliver README usage, `SECURITY.md`, implementation-to-formula mapping, example 128-member outputs, and complete/partial/unsupported checklist | ⬜ Todo | Do not claim unsupported functionality or security properties. |
| 60 | Perform final reproducibility review from a clean checkout and freeze thesis experiment metadata | ⬜ Todo | Record exact toolchain, lockfile, commands, seed policy, artifacts, and hashes. |

---

**Current:** Part 1, Task 6 — Resolve measurement semantics and ambiguities before scaffolding.

**Next:** Part 1, Task 7 — Lock the toolchain and approved dependencies, then run the Phase 1 documentation and compatibility gate.
