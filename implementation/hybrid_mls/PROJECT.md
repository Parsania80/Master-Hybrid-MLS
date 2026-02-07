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

## Current Module: src/crypto.rs & src/tree.rs
Implementing Path Updates with Hybrid KEM + HPKE-style encryption.
