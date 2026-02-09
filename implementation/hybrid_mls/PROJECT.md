# Hybrid MLS Implementation Project

## Status
- [x] Project Initialization
- [x] Dependency Selection (x25519, ml-kem, ed25519, ml-dsa)
- [x] **Part 1: Hybrid Primitives** (Encryption & Signatures)
- [x] **Part 2: Tree Structures** (Nodes & KeyPackages, Parent Hashes, Resolution)
- [ ] Part 3: The Engine (Proposals & Commits) — in progress
- [ ] Part 4: Path Updates (The Math) — in progress
- [ ] Part 5: Security Properties
- [ ] Part 6: Key Schedule
- [ ] Part 7: Delivery Service (HTTP + Auth + UI) — storage + HTTP skeleton + signed-request verification done; login/session in progress; keypackage publish/fetch + app message endpoints added; DS server binary + client CLI support app messages; UI pending

## Current Module: src/crypto.rs, src/tree.rs, src/ds
Implementing Path Updates with Hybrid KEM + HPKE-style encryption, plus DS storage.

## Project Goal
Implement a Hybrid Post-Quantum MLS (RFC 9420) library in Rust with a supporting Delivery Service.

## Tech Stack Lock
- Rust 2021
- x25519-dalek, ml-kem, ed25519-dalek, ml-dsa
- sha3, chacha20poly1305
- axum, tokio, serde, serde_json, base64
- reqwest, clap, serde_urlencoded
- rusqlite (for DS storage)

## Architecture
- `src/crypto.rs`: Hybrid KEM + signatures, serialization, HPKE-style path secret encryption
- `src/tree.rs`: Ratchet tree, proposals/commits, path updates, encoding/decoding
- `src/ds/*`: Delivery Service storage (SQLite + disk spool) and HTTP skeleton; auth/UI pending
- `src/bin/ds_server.rs`: Axum server entrypoint for DS APIs
- `src/bin/ds_client.rs`: CLI for DS register/login/proposals/commits/keypackages/app-messages
