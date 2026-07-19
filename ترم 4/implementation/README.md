# Adaptive Hybrid MLS TreeKEM Research Prototype

## What is this?

This repository is intended to become a reproducible Rust research prototype for a thesis experiment. It will compare normal binary Messaging Layer Security (MLS), binary MLS augmented with experimental mKyber delivery, and an experimental adaptive transition from a binary tree to a quaternary tree.

## Why does it exist?

The experiment studies whether changing TreeKEM arity can reduce measured communication cost enough to justify a real transition cost, and when an old binary delivery cover can be retired safely according to the thesis formulas.

## What problem does it solve?

The planned software will create a valid 128-member baseline MLS group, replay controlled multi-member workloads, measure real serialized costs, evaluate transition start and end rules, verify member convergence, and generate reproducible CSV, JSON, and Markdown reports.

## Current status

The Rust workspace pins the approved dependencies and contains an unchanged OpenMLS 0.8.1 baseline adapter. It can create and join a standard group, stage and merge normal Add/remove/self-update commits from multiple members, process standard messages, and encrypt application data. Independent regression tests verify epoch, authenticated GroupContext, RFC tree-hash convergence, and application delivery. The Phase 2 quality gate has passed on Rust 1.93.1. The mKyber crate also implements `EducationalMkyber512Reference`, the paper-based `mkyber512-thesis-v1` profile: it validates the shared domain, emits exact 768/704/48-byte artifacts, and has project self-consistency tests for multi-recipient agreement and fallback selection. Normal reference calls use dedicated OS-RNG entry points; deterministic entropy is private to unit tests. Long-lived private keys and shared secrets are zeroized on drop, while temporary secret material uses scoped guards. It now records component-only byte costs from actual serialized arrays: the 704-byte common component, each 48-byte recipient component, and their sum. Each record preserves `measured_bytes`, no estimate, and its non-estimate method. Recipient identifiers, domains, and future hybrid/MLS framing are not yet included because no canonical outer serializer exists. This is thesis-local educational reference code, not an author-approved profile or vector corpus; it makes no interoperability, audit, side-channel, security-proof, business, or production claim. Hybrid path-secret delivery, adaptive transition, and a runnable experiment remain unimplemented. `SECURITY.md` records the non-standard protocol changes, threat model, interoperability boundary, X-Wing/C2PRI limitation, and unresolved assumptions. See `PROJECT.md`, `SECURITY.md`, `docs/adr/`, and `SESSION-LOG.md` for the authoritative decisions and audit trail.

## How to use it

Run `cargo +stable test --workspace --all-targets --locked --offline` to verify the baseline and educational mKyber reference tests. There is not yet a user-facing CLI, 128-member bootstrap, or experiment runner.

## Security and interoperability warning

This is educational thesis research software, not production cryptography, and it is not recommended for business or production use. All mKyber, hybrid path-secret, adaptive-tree, and TreeCover behavior is non-standard and experimental. Experimental modes must not claim RFC 9420 interoperability or a formal security proof.

The thesis specifically requires the post-quantum ciphertext to be transmitted and authenticated while excluding it from the hybrid KDF input. That omission is an experimental design choice and is not automatically covered by the X-Wing C2PRI security argument. Reports must never contain shared secrets, path secrets, private keys, AEAD keys, raw entropy, or seed material that reconstructs private state.
