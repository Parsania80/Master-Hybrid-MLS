# Adaptive Hybrid MLS TreeKEM Research Prototype

## What is this?

This repository is intended to become a reproducible Rust research prototype for a thesis experiment. It will compare normal binary Messaging Layer Security (MLS), binary MLS augmented with experimental mKyber delivery, and an experimental adaptive transition from a binary tree to a quaternary tree.

## Why does it exist?

The experiment studies whether changing TreeKEM arity can reduce measured communication cost enough to justify a real transition cost, and when an old binary delivery cover can be retired safely according to the thesis formulas.

## What problem does it solve?

The planned software will create a valid 128-member baseline MLS group, replay controlled multi-member workloads, measure real serialized costs, evaluate transition start and end rules, verify member convergence, and generate reproducible CSV, JSON, and Markdown reports.

## Current status

The Rust workspace pins the approved dependencies and contains an unchanged OpenMLS 0.8.1 baseline adapter. It can create and join a standard group, stage and merge normal Add/remove/self-update commits from multiple members, process standard messages, and encrypt application data. Independent regression tests verify epoch, authenticated GroupContext, RFC tree-hash convergence, and application delivery. The Phase 2 quality gate has passed on Rust 1.93.1. The mKyber crate also implements `EducationalMkyber512Reference`, the paper-based `mkyber512-thesis-v1` profile: it validates the shared domain, emits exact 768/704/48-byte artifacts, and tests multi-recipient agreement, malformed input rejection, deterministic public-artifact reproducibility, and common/recipient tampering. A project-owned public regression digest is not an official KAT or interoperability vector. Normal reference calls use dedicated OS-RNG entry points; deterministic entropy is private to unit tests. Long-lived private keys and shared secrets are zeroized on drop, while temporary secret material uses scoped guards. It records component-only byte costs from actual serialized arrays: the 704-byte common component, each 48-byte recipient component, and their sum. The hybrid crate now performs complete isolated experimental path-level delivery: one mKyber encapsulation for the co-path recipient set, a context-bound 32-byte HPKE exporter secret and encapsulation per recipient, the canonical hybrid KDF input/expansion, and AES-128-GCM path-secret wrapping. Its Task 22 instrumentation records actual public ciphertext lengths but zero KDF contribution; focused tests mutate PQ components to establish regression evidence that wire/authentication changes do not alter `IKM` for fixed secrets/context. It is not yet injected into an OpenMLS fork; the unchanged baseline never uses it. This is thesis-local educational reference code, not an author-approved profile or vector corpus; it makes no interoperability, audit, side-channel, security-proof, business, or production claim. Adaptive transition and a runnable experiment remain unimplemented. `SECURITY.md` records the non-standard protocol changes, threat model, interoperability boundary, X-Wing/C2PRI limitation, and unresolved assumptions. See `PROJECT.md`, `SECURITY.md`, `docs/adr/`, and `SESSION-LOG.md` for the authoritative decisions and audit trail.

## How to use it

Run `cargo +stable test --workspace --all-targets --locked --offline` to verify the baseline and educational mKyber reference tests. Run `cargo +stable run -p mkyber --bin mkyber_benchmark --release --locked --offline` for the standalone reference timing smoke benchmark. It prints only the reference profile/parameters, actual public 704/48-byte component costs, and environment-dependent timing averages; it is not a production benchmark, security evaluation, or thesis experiment result. There is not yet a user-facing CLI, 128-member bootstrap, or experiment runner.

## Security and interoperability warning

This is educational thesis research software, not production cryptography, and it is not recommended for business or production use. All mKyber, hybrid path-secret, adaptive-tree, and TreeCover behavior is non-standard and experimental. Experimental modes must not claim RFC 9420 interoperability or a formal security proof.

The thesis specifically requires the post-quantum ciphertext to be transmitted and authenticated while excluding it from the hybrid KDF input. That omission is an experimental design choice and is not automatically covered by the X-Wing C2PRI security argument. Reports must never contain shared secrets, path secrets, private keys, AEAD keys, raw entropy, or seed material that reconstructs private state.
