# Adaptive Hybrid MLS TreeKEM Research Prototype

## Tech Stack

- Language: Rust 1.93.1, pinned by `rust-toolchain.toml`; the initial workspace will set `rust-version = "1.93.1"`, edition 2021, and resolver 3. See ADR 0007.
- Build and workspace management: Cargo workspace with `rustfmt` and Clippy as mandatory quality gates.
- Baseline MLS: upstream `openmls = "=0.8.1"` using `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`; a separately named, feature-gated `openmls-hybrid` fork is permitted only for experimental modes. See ADR 0001 and ADR 0003.
- Baseline credential signer: `openmls_basic_credential = "=0.5.0"`, the upstream MIT Basic Credential signer implementation required to construct the unchanged OpenMLS baseline; no test or debug feature is enabled. See ADR 0007.
- Baseline protocol: RFC 9420 binary TreeKEM behavior must remain available, isolated, and independently testable.
- Experimental post-quantum component: a paper-based mKyber512 educational reference profile, isolated behind a replaceable `MultiRecipientKem` trait. Ordinary ML-KEM is not an acceptable substitute for mKyber.
- Experimental hybrid construction: classical MLS/HPKE plus reference-only mKyber512, HKDF-SHA256, and AES-128-GCM as defined in ADR 0002 and ADR 0003; experimental modes are non-interoperable research code.
- Configuration and outputs: TOML input; CSV, JSON, Markdown, and optional SVG output; filesystem storage only and no database.
- Randomness: deterministic seeded RNG only for tests and reproducible experiments; operating-system cryptographic RNG for non-experiment operation.
- Approved direct crates: exact versions and feature limits for OpenMLS, its RustCrypto provider, TLS codec, hybrid primitives, RNGs, zeroization, serialization, CLI, reports, and tests are locked in ADR 0007. No other direct crate is approved without a new ADR and log entry.
- Dependency rule: `Cargo.lock` is committed for reproducibility. No language, framework, library, or new crate may be introduced until this section is updated and the choice is recorded in `SESSION-LOG.md`.

## Architecture

- Current state: stable-Rust workspace with a Phase 2-gated maintained-library baseline MLS adapter, independent baseline regression coverage, a validated public configuration schema, a paper-based educational mKyber512 reference backend, a standalone reference timing smoke benchmark, and an experimental hybrid path-level delivery boundary. It creates a single mKyber encapsulation per co-path set, derives per-recipient classical HPKE exporter secrets, builds the canonical hybrid input, AES-GCM wraps the path secret, emits public KDF-exclusion provenance from real canonical wire fields, and rejects tested ciphertext tampering, non-recipients, and context replays. OpenMLS-fork injection, adaptive transition, experiment runner, and generated results remain unimplemented.
- `/agent.md`: Human-agent operating protocol and documentation rules.
- `/PROJECT.md`: Single source of truth for scope, architecture, dependency lock, and progress.
- `/SESSION-LOG.md`: Append-only audit trail for actions, commands, results, decisions, and limitations.
- `/README.md`: Plain-language project purpose, status, security warning, and high-level usage.
- `/SECURITY.md`: Mandatory security boundary, non-standard protocol inventory, threat model, interoperability limits, and unresolved thesis assumptions.
- `/docs/research/MLS-CANDIDATE-COMPARISON.md`: Completed Task 2 source-level comparison of OpenMLS and `mls-rs`; this is evidence for a future ADR, not a dependency selection.
- `/docs/research/MKYBER-IMPLEMENTATION-AUDIT.md`: Completed Task 3 audit of the paper parameters, available implementations, licenses, test-vector status, and reuse boundary.
- `/docs/adr`: Accepted architecture decisions for the MLS base/fork boundary, mKyber strategy, ciphersuite/KDF/AEAD, hybrid wire encoding, and extension authentication.
- `/docs/adr/0006-measurement-semantics.md`: Accepted definitions for experiment windows, impactful commits, byte-cost provenance, migration accounting, target-set aggregation, and statistics.
- `/docs/adr/0007-toolchain-and-dependency-lock.md`: Accepted Rust toolchain pin, direct dependency allowlist, feature restrictions, license record, and compatibility-gate outcome.
- `/rust-toolchain.toml`: Exact Rust compiler pin with required formatting and lint components.
- `/Cargo.toml` and `/Cargo.lock`: Stable-Rust workspace definition and exact reproducible dependency resolution.
- `/configs`: Configuration guidance; runnable workload configurations are deferred until the policy and CLI tasks.
- `/crates/experiment-config`: Validated public configuration schema with no implicit Delta and safe relative output paths.
- `/crates/mls-adapter`: Upstream OpenMLS 0.8.1 baseline adapter for group creation/join, standard Add/remove/self-update commits, validated inbound messages, and application messages; no experimental behavior is present.
- `/crates/mkyber`: Reference-only `mkyber512-thesis-v1` backend plus typed artifact/error boundary; it has no author-compatible interoperability claim or ML-KEM fallback.
- `/crates/mkyber/src/bin/mkyber_benchmark.rs`: Release-mode standalone timing smoke benchmark for the educational backend; prints only public component byte costs and environment-dependent timing aggregates.
- `/crates/hybrid-path-secret`: Canonical, validated hybrid wire/context boundary plus the Task 21 sender/receiver engine and Task 22 KDF-exclusion instrumentation. It performs one mKyber encapsulation per level, a context-bound 32-byte HPKE exporter-secret derivation per recipient, canonical hybrid KDF input/expansion, and AES-128-GCM path-secret wrapping. Its value-free provenance records actual serialized common/recipient ciphertext lengths and their zero KDF contribution. It is ready for a future experimental fork injection; baseline code does not import it.
- `/crates/adaptive-tree`: Canonical version-1 binary-to-quaternary mapping and immutable public shadow topology with public logical-operation replay; cost estimation and TreeCover remain deferred.
- `/crates/arity-state`: Canonical Task 41 public metadata for private-use extension `0xF001`. It validates policy/evaluation snapshots and the `Normal`/`Transitioning` state machine, but does not yet inject or authenticate a live MLS extension.
- `/crates/transition-tree`: Task 42 separate public active-quaternary topology and frozen delivery-only binary TreeCover. It validates Task 41 mapping/cover bindings and exposes only the active quaternary epoch-secret-authority marker; it has no secret derivation or live MLS mutation.
- `/crates/transition-auth`: Tasks 43/44 fail-closed pre-apply transition metadata and educational batch-application harness. It consumes future-fork supplied, already MLS-authenticated GroupContext facts, stages every recipient's hybrid resolution before replacing public member snapshots, and rejects inconsistent inputs without partial harness mutation; it does not authenticate or process an MLS Commit itself.
- `/crates/transition-policy`: Task 35/39 policy boundary. It retains an auditable raw accepted-commit trail, bounds post-warmup `W_e`, derives `q_e`/`r_e`, measures canonical transition preflight bytes, computes exact rational savings, resolves typed byte-or-fixed-point-percent Delta thresholds conservatively, and evaluates all start gates with explicit public blockers; transition execution remains deferred.
- `/crates/metrics`: Typed Task 32/33 measurement boundary. It measures emitted baseline Commit bytes, derives explicitly estimated candidate path payload sizes from the canonical hybrid TLS codec, and records public topology, recipient-resolution, crypto-count, and monotonic timing facts without retaining wire or secret values.
- `/crates/simulation`: Empty deterministic workload and convergence-simulation boundary.
- `/crates/report`: Empty safe report-generation boundary.
- `/src/bin/bootstrap_128.rs` (planned): Build and verify a valid 128-member baseline binary MLS group and emit safe public experiment artifacts.
- `/src/bin/evaluate_transition.rs` (planned): Run controlled multi-committer workloads, evaluate 2-to-4 transition policy, and generate complete reports.
- `/tests/baseline_regression.rs`: Independent baseline integration tests for epoch, authenticated GroupContext, RFC tree hash, multi-committer convergence, and application-message delivery.
- `/tests` (planned additions): Hybrid-path, tamper/replay, transition-start, transition-end, property, and 128-member convergence tests.
- `/output` and `/report` (planned): Generated artifacts only; reports must never contain private keys, shared secrets, path secrets, AEAD keys, raw entropy, or a seed capable of reconstructing secret key material.
- Data flow: validated configuration and separate public experiment seed/secret entropy feed the simulator; the MLS adapter executes the unchanged baseline path; experimental modes add mKyber delivery and hybrid key derivation; the shadow quaternary tree evaluates the same logical operation without mutating group state; transition policy consumes measured serialized costs; metrics and reports receive only safe observations.
- Supported modes: `BaselineBinaryMls`, `BinaryMlsWithMkyber`, and `AdaptiveBinaryToQuaternaryMls`.
- Transition invariant: while transitioning, the quaternary tree produces fresh secrets and the old binary tree is delivery-only `TreeCover`; epoch secrets are derived from exactly one active root.
- Authentication invariant: arity, transition state, tree version, deterministic leaf mapping, TreeCover version, node indices, and group-context binding are authenticated and checked for member convergence.
- Hybrid KDF invariant: the input is `ss_classical || ss_pq || domain_separation_context`, where this implementation's `ss_classical` is a 32-byte context-bound HPKE exporter output. mKyber ciphertext bytes are transmitted and authenticated but explicitly excluded from the KDF input. The context includes the label `Adaptive-Hybrid-TreeKEM-PathSecret-v1`, ciphersuite, group, epoch, tree version, current arity, path-node index, recipient-node index, and authenticated group-context hash.
- Research boundary: every non-standard component is experimental thesis software for educational use only and is not recommended for business or production use. Experimental modes must not claim RFC 9420 interoperability, a formal security proof, or automatic coverage by the X-Wing C2PRI argument.
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
| 6 | Resolve measurement semantics and ambiguities before scaffolding | ✅ Done | ADR 0006 defines windows, Delta precedence, preflight/actual transition costs, impactful commits, target-set aggregation, mapping/TreeCover rules, warmups, repetitions, and statistics. |
| 7 | Lock the toolchain and approved dependencies, then run the Phase 1 documentation and compatibility gate | ✅ Done | Rust 1.93.1 and the exact direct dependency allowlist are locked in ADR 0007; Cargo resolution is intentionally deferred until Task 8 creates the workspace. |

### Part 2: Baseline Binary MLS

| # | Task | Status | Notes |
|---|------|--------|-------|
| 8 | Scaffold the Cargo workspace and crate boundaries without experimental behavior in the baseline path | ✅ Done | Workspace, exact lockfile, safe output/report layout, and validated public configuration schema exist; no protocol behavior is implemented. |
| 9 | Implement the maintained-library adapter for normal RFC 9420 proposals, commits, UpdatePath processing, and application messages | ✅ Done | `mls-adapter` uses upstream OpenMLS 0.8.1 only, fixes ciphersuite 0x0001, serializes standard messages, and covers Add/Welcome, application, and self-update UpdatePath convergence. |
| 10 | Create a small group, add/remove/update members through valid MLS operations, and deliver each commit to every valid member | ✅ Done | A three-member, four-epoch test uses Alice, Bob, and Charlie as committers; every remaining valid member receives each Add, self-update, and Remove commit. |
| 11 | Add independent baseline integration/regression tests for convergence, tree hashes, epochs, group contexts, and message encryption/decryption | ✅ Done | Black-box tests compare exact authenticated GroupContext bytes, RFC tree hashes, epochs, membership, and application delivery after valid commits. |
| 12 | Pass the Phase 2 formatting, strict lint, unit, integration, and baseline regression gate | ✅ Done | Rust 1.93.1; locked offline format/check/Clippy/test/doc-test/release-build/metadata and OpenMLS feature audit all passed; 8 tests passed. |

### Part 3: Experimental mKyber Abstraction

| # | Task | Status | Notes |
|---|------|--------|-------|
| 13 | Define the replaceable `MultiRecipientKem` trait and typed errors | ✅ Done | Defines domain-bound key/ciphertext/recipient types, fixed public component sizes, zeroized redacted secret wrappers, and object-safe keygen/encapsulation/extraction/decapsulation operations. |
| 14 | Implement the paper-based, clearly labeled mKyber512 educational reference backend | ✅ Done | `mkyber512-thesis-v1` implements the paper parameters, exact 768/704/48-byte artifacts, shared-domain validation, multi-recipient agreement, and fallback selection. It is thesis-local reference code only: no business/production, interoperability, audit, or security-proof claim. |
| 15 | Separate common and per-recipient ciphertext components and instrument their real serialized byte costs | ✅ Done | `MkyberMeasuredComponentCosts` records ADR 0006 provenance (`measured_bytes`, no estimate, and method) from emitted canonical arrays: 704-byte common, 48 bytes per recipient, and their component-only total. Domain/recipient identifiers and future hybrid/MLS framing are deliberately excluded until their serializers exist. |
| 16 | Implement deterministic test mode, OS-RNG production path, secret redaction, and zeroization where applicable | ✅ Done | Deterministic RNG is private to unit tests; normal reference callers use explicit `OsRng` entry points. Durable secret wrappers use `ZeroizeOnDrop`; scoped guards clear temporary entropy, seeds, decoded messages, noise, and packed secret-key bytes. No stronger memory-erasure or side-channel claim is made. |
| 17 | Add known-answer/unit/property tests for recipient agreement, non-recipient failure, malformed ciphertexts, and deterministic reproducibility | ✅ Done | Added deterministic end-to-end public-artifact reproducibility, a project-owned public regression digest, common and per-recipient tamper/fallback checks, malformed public/private inputs, and exhaustive 768-case recipient-component bit-flip coverage. These are not official KATs. |
| 18 | Pass the Phase 3 formatting, strict lint, test, and standalone benchmark gate | ✅ Done | Locked offline format/check/strict Clippy/workspace tests/metadata passed. The release standalone benchmark identifies `EducationalMkyber512Reference`, paper parameters, actual 704/48-byte components, and environment-dependent timing aggregates without secret output. |

#### Task 14 paper-based reference checklist

Source: `C:\Users\Parsania\Documents\GitHub\Master-Hybrid-MLS\ترم 4\پایان نامه\related_works\3-4\how-multi-recipient-kems.pdf`, Section 3 and Table 1. Every paper-specified item below is required; this checklist does not turn paper omissions into a published standard.

1. Fix the mKyber512 paper parameters: `q=3329`, `n=256`, `k=2`, `eta1=3`, `eta2=2`, `du=11`, `dv=3`, 16-byte message, 768-byte encapsulation key, 704-byte common `u`, and 48-byte recipient `v_i`.
2. Model the public mKyber domain as a shared matrix seed `seedA` expanded by an XOF into `A`; all recipient keys in one encapsulation set must use that same domain, and keys from another domain must fail validation.
3. Implement paper key generation: sample secret/error values, compute `b = A * s + e`, expose `b` as the 768-byte encapsulation key, and retain the secret material plus public/fallback material required by decapsulation. Do not substitute ordinary Kyber/ML-KEM/amKyber key generation.
4. Implement paper encapsulation for a non-empty, duplicate-free recipient set: choose a 16-byte message, derive `K'`, derive shared `r,e'` from `G1`/`PRF1`, compute and compress the common `u = r * A + e'`, derive recipient-specific coins/noise with `G2(ek_i,msg)` and `PRF2`, then compute and compress each `v_i = r * b_i + e''_i + Encode(msg)`.
5. Implement paper decapsulation: decompress `(u,v_i)`, recover and decode the message with `v_i - u * s_i`, deterministically re-encrypt the recipient component, compare the reconstructed component with the received component without exposing secret-dependent diagnostics, and select `KDF(K',ct_i)` only on a match or the paper's fallback-key KDF otherwise.
6. Encode the multi-recipient ciphertext as one 704-byte common component plus one 48-byte component per recipient. Implement the paper's 128-coefficient recipient-component reduction and 3-bit compression, preserving canonical ordering and rejecting malformed lengths, duplicate recipients, wrong-recipient components, and domain mismatches.
7. Before code assigns concrete bytes to `H`, `G1`, `G2`, `PRF1`, `PRF2`, `KDF`, matrix expansion, coefficient selection/order, packing, compression rounding, NTT representation, secret-key layout, or fallback serialization, record each choice in the thesis-local reference profile and ADR. The paper abstracts or simplifies these details, so such choices must be labelled thesis-local rather than author-standardized mKyber512 interoperability behavior.
8. Keep operating-system randomness for normal reference runs and isolated deterministic randomness only for tests. Zeroize private/shared-secret buffers, redact secret-bearing debug output, and never place secrets or reconstructible entropy in logs, fixtures, or reports.
9. Add self-consistency tests for key generation, multi-recipient agreement, extraction, malformed inputs, common/recipient tampering, wrong recipient, domain mismatch, re-encryption failure/fallback selection, exact 768/704/48-byte serialization, and deterministic test reproducibility. These are project regression tests, not official known-answer tests.
10. Label the implementation, benchmarks, reports, and generated vectors as `educational thesis reference only`. Do not recommend it for business or production use; do not claim mKyber512 interoperability, an audit, side-channel resistance, IND-CCA security for the implementation, or any formal security proof.

### Part 4: Experimental Hybrid Path-Secret Delivery

| # | Task | Status | Notes |
|---|------|--------|-------|
| 19 | Define and authenticate `HybridPathCiphertext` with classical, PQ common, PQ recipient, encrypted-secret, and node-index fields | ✅ Done | Canonical TLS codec has version, path node, domain, one 704-byte common component, ordered recipient records with 32-byte classical encapsulation, 48-byte mKyber recipient component, and 48-byte encrypted path-secret field. It exposes bytes that a future experimental commit must authenticate; KDF/AEAD/fork integration remain deferred. |
| 20 | Implement canonical domain-separation context encoding and the hybrid KDF input builder | ✅ Done | `HybridKdfContext` canonically TLS-encodes/validates the fixed version, label, ciphersuite, group/epoch/tree bindings, node indexes, mKyber domain, and GroupContext hash. The redacted, zeroized builder forms only `ss_classical || ss_pq || TLSEncode(context)` after exact 32-byte validation; it excludes ciphertext APIs and does not implement HKDF/AES-GCM. |
| 21 | Integrate classical HPKE and one mKyber shared secret per co-path resolution into each experimental UpdatePath level | ✅ Done | `hybrid-path-secret` now emits/opens complete experimental path-level payloads: one mKyber encapsulation/common component per co-path set, one 32-byte context-bound HPKE exporter secret and encapsulation per recipient, exact hybrid KDF input, and AES-128-GCM path-secret wrapping. It is an isolated fork-input boundary; no OpenMLS fork has been injected and baseline mode bypasses it. |
| 22 | Prove by focused tests/instrumentation that PQ ciphertext is excluded from KDF input while still serialized and authenticated | ✅ Done | Value-free instrumentation measures actual canonical common (704-byte) and recipient (48-byte) mKyber wire fields while recording zero KDF contribution. Focused tests mutate each component, show commit-authenticated bytes change, and show KDF input remains exactly unchanged for fixed secrets/context. This is code-level regression evidence, not a cryptographic proof. |
| 23 | Add recipient/non-recipient, tamper, and cross-group/epoch/tree-version/node replay tests | ✅ Done | Tests verify intended recipient delivery and non-recipient rejection; alterations to classical encapsulation, mKyber common/recipient components, or AES-GCM ciphertext fail without path-secret output; changed group, epoch, tree version, or path node replays also fail. These are code-level tests of the isolated boundary, not a proof. |
| 24 | Pass the Phase 4 formatting, strict lint, integration, property, and regression gate | ✅ Done | Rust 1.93.1 locked-offline format/check/strict Clippy/all-target tests/doc tests/release build/metadata passed. Two bounded public-byte properties supplement hybrid regression tests; the unchanged baseline regressions passed. OpenMLS feature audit shows only `openmls_rust_crypto`, with no prohibited OpenMLS debug/test/libcrux/SQLite/JavaScript feature. |

### Part 5: Reproducible 128-Member Bootstrap

| # | Task | Status | Notes |
|---|------|--------|-------|
| 25 | Implement `bootstrap_128.rs` using valid Add proposals/commits and full commit delivery | ✅ Done | The standard-library CLI accepts `--members 128 --seed 42 --output output/bootstrap-128`; the seed selects only the public committer schedule. A release run created 127 Add commits, delivered every commit to all prior members, joined each new member from its Welcome, and used 22 valid committers. Snapshot/report files remain deferred to Tasks 27–28. |
| 26 | Verify 128 members, binary arity, height 7, occupied leaves, common epoch/context/tree hash, application messages, and secret cleanup | ✅ Done | The fail-closed release verifier confirms epoch 127, 128 members, baseline binary arity 2, height 7, actual occupied leaf indexes `0..127`, identical GroupContext/tree hash, and one application message decrypted by every other member. It returns public facts only and the CLI drops private client state; this is lifecycle cleanup, not a proof of upstream process-memory zeroization. |
| 27 | Design a safe reproducible snapshot that separates public scheduling seed from secret key-generation entropy | ✅ Done | `bootstrap_public_snapshot.json` is versioned and create-new under `output/<run>`. It contains only public schedule/configuration metadata, authenticated GroupContext/tree hash, TLS public RatchetTree, occupied leaves, and the 127 actual Add KeyPackages; the creator is represented by its public tree leaf. The public seed cannot reconstruct OS-generated key entropy. |
| 28 | Generate bootstrap summary JSON, commit CSV, and Markdown report under the requested output directory | ✅ Done | Canonical create-new artifacts under `output/<run>` are `bootstrap_public_snapshot.json`, `bootstrap_128_summary.json`, `bootstrap_128_commits.csv`, and `bootstrap_128_report.md`. The CSV records only public per-commit identity/epoch/byte/delivery counts; a release run produced 127 rows for epochs 0→127 and 510,718 measured Commit bytes. |
| 29 | Pass the Phase 5 tests and a release-mode 128-member acceptance run | ✅ Done | Rust 1.93.1 locked-offline format/check/strict Clippy/all-target tests/doc tests/release build/metadata passed. A release acceptance test (9.17s) and fresh 128-member artifact run passed; public summary provenance archives the exact command, compiler, package, and direct dependency versions. |

### Part 6: Shadow Quaternary Tree and Cost Measurement

| # | Task | Status | Notes |
|---|------|--------|-------|
| 30 | Implement deterministic binary-to-quaternary leaf mapping and a non-mutating shadow tree | ✅ Done | Version-1 mapping follows ADR 0006: bytewise-sort canonical `MemberId`, assign left-to-right quaternary ordinals, and encode complete canonical bytes. The immutable shadow tree has public topology only; 128 members yield arity 4, height 4, capacity 256, and 128 occupied leaves. Authentication and live transition are deferred. |
| 31 | Replay each logical operation against the shadow tree without changing real MLS state or consuming mismatched randomness | ✅ Done | ADR 0008 defines immutable public `Update`/`Add`/`Remove` replay. Updates preserve topology, removals leave holes, and additions use the lowest vacant leaf; growth occurs only when capacity is full. Replays take no RNG, live MLS state, or secret input. |
| 32 | Measure real `B_i(2)` and candidate `B_hat_i(4)` with component-level serialized byte provenance | ✅ Done | ADR 0009 records the emitted baseline Commit as measured and computes a `shadow_exact_codec` estimate from disjoint retained baseline framing plus canonical hybrid TLS payloads. A candidate MLS Commit is still not emitted. |
| 33 | Track tree heights, direct paths, resolutions, blanks, populated nodes, recipient counts, and crypto operation/timing metrics | ✅ Done | ADR 0010 defines typed public topology/resolution records, measured or explicitly unavailable crypto timing/count records, and a `2 -> 4` logical-operation aggregate that preserves Task 32 byte provenance. |
| 34 | Pass the Phase 6 determinism, measurement-consistency, formatting, lint, and test gate | ✅ Done | Rust 1.93.1 locked-offline format/check/strict Clippy, focused baseline (3), hybrid (18), adaptive-tree (7), and metrics (8) suites, full workspace tests (61 passed; 1 release-only ignored), doc tests, and diff validation passed. |

### Part 7: Transition-Start Policy

| # | Task | Status | Notes |
|---|------|--------|-------|
| 35 | Implement configurable sliding window `W_e`, `q_e`, `r_e`, and explicit `is_impactful_commit` classification | ✅ Done | ADR 0011 adds a typed accepted-commit trail. Warmup records are explicit and excluded; all post-warmup records enter bounded `W_e`, including explicit non-impactful records; `q_e` and checked `r_e` derive only from current-window records. |
| 36 | Measure `B_transition` from serialized transition-only protocol data without mutating the live group during evaluation | ✅ Done | ADR 0012 records `B_transition_preflight` from an exact disjoint partition of caller-provided canonical outer bytes, exposes all six diagnostic components, and reports later actual-byte mismatches without overwriting preflight. It remains an estimate until a transition serializer exists. |
| 37 | Implement the average and direct savings formulas with checked integer/rational rounding | ✅ Done | ADR 0013 stores exact sums and rational averages, computes signed direct and average-form preflight savings without floats, exposes report-only rounding, and property-tests formula equivalence. |
| 38 | Implement every start condition and record the exact blocking/triggering condition | ✅ Done | ADR 0014 evaluates all five ADR 0006 gates after each post-warmup accepted record: normal state, `2 -> 4`, stable target size, `q_e >= q_min`, and strict exact saving above Delta. Every blocker is retained; no transition is emitted. |
| 39 | Support configurable Delta in bytes or as a percentage of `B_transition`, plus TOML/CLI overrides | ✅ Done | ADR 0015 maps exactly one TOML form to a typed policy threshold. Percentage values use checked micro-percent fixed point and ceiling byte resolution against the current preflight; the typed future-CLI override replaces, never combines with, TOML. |
| 40 | Pass start-gating, positive-trigger, formula-equivalence, formatting, lint, and regression tests | ✅ Done | Phase 7 passed Rust 1.93.1 locked-offline format/check/strict Clippy/all-target tests/doc tests/release build/metadata, baseline regression, and diff validation. The policy suite proves all blockers, delayed positive trigger, strict byte/percent Delta boundaries, and bounded direct/rational formula equivalence. |

### Part 8: Authenticated Transition State and TreeCover

| # | Task | Status | Notes |
|---|------|--------|-------|
| 41 | Implement authenticated `ArityState` and `Normal`/`Transitioning` state-machine validation | ✅ Done | ADR 0016 defines a canonical `0xF001` extension value with threshold/evaluation snapshots, policy digest, mapping/TreeCover bindings, and strict first-transition validation. Commit-level authentication/injection remains Task 43. |
| 42 | Implement the new active quaternary tree and old binary delivery-only `TreeCover` as separate state | ✅ Done | ADR 0017 provides separate active/carry-only types, validates state/map/cover hashes, keeps only quaternary as the epoch-secret authority, and gives additions/removals their required distinct cover effects. |
| 43 | Authenticate transition metadata and reject arity, version, state, mapping, group-context-hash, or TreeCover-version inconsistencies | ✅ Done | ADR 0018 adds a fail-closed pre-apply validator for future-fork supplied MLS-authenticated GroupContext facts, exact `0xF001` state, tree bindings, and hybrid context. It performs no MLS signature/commit authentication itself. |
| 44 | Verify all members converge after transition commits and divergent/tampered commits fail atomically | ✅ Done | ADR 0019 adds an educational batch harness: all recipient-specific validation/open operations stage before any public member snapshot changes. Tests cover independent Alice/Bob committer scenarios, three resolution nodes, divergent metadata, late recipient-resolution failure, and tampered hybrid ciphertext. |
| 45 | Pass the Phase 8 formatting, strict lint, state-machine, rejection, convergence, and regression gate | 🔄 Current | Record unresolved security limitations. |

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

**Current:** Part 8, Task 45 — Pass the Phase 8 formatting, strict lint, state-machine, rejection, convergence, and regression gate.

**Next:** Part 9, Task 46 — Measure actual `C_leaf`, `C_new`, `C_old`, and `C_ideal` for each defined recipient target set.
