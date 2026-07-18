# Adaptive Hybrid MLS TreeKEM Research Prototype

## What is this?

This repository is intended to become a reproducible Rust research prototype for a thesis experiment. It will compare normal binary Messaging Layer Security (MLS), binary MLS augmented with experimental mKyber delivery, and an experimental adaptive transition from a binary tree to a quaternary tree.

## Why does it exist?

The experiment studies whether changing TreeKEM arity can reduce measured communication cost enough to justify a real transition cost, and when an old binary delivery cover can be retired safely according to the thesis formulas.

## What problem does it solve?

The planned software will create a valid 128-member baseline MLS group, replay controlled multi-member workloads, measure real serialized costs, evaluate transition start and end rules, verify member convergence, and generate reproducible CSV, JSON, and Markdown reports.

## Current status

The Rust workspace is scaffolded and pins the approved dependencies, but it contains no MLS group lifecycle, mKyber implementation, hybrid path-secret delivery, adaptive transition, or runnable experiment yet. ADRs select OpenMLS 0.8.1 for the unchanged future baseline, a separately gated experimental fork for hybrid modes, and a reference-only mKyber512 strategy. `SECURITY.md` records the non-standard protocol changes, threat model, interoperability boundary, X-Wing/C2PRI limitation, and unresolved assumptions. See `PROJECT.md`, `SECURITY.md`, `docs/adr/`, and `SESSION-LOG.md` for the authoritative decisions and audit trail.

## How to use it

There is nothing to build or run yet. The current task is to select a maintained Rust MLS foundation and a defensible extension boundary before scaffolding code. Reproducible Cargo commands will be added only after the toolchain and dependencies are pinned.

## Security and interoperability warning

This is thesis research software, not production cryptography. All mKyber, hybrid path-secret, adaptive-tree, and TreeCover behavior is non-standard and experimental. Experimental modes must not claim RFC 9420 interoperability or a formal security proof.

The thesis specifically requires the post-quantum ciphertext to be transmitted and authenticated while excluding it from the hybrid KDF input. That omission is an experimental design choice and is not automatically covered by the X-Wing C2PRI security argument. Reports must never contain shared secrets, path secrets, private keys, AEAD keys, raw entropy, or seed material that reconstructs private state.
