# Hybrid Post-Quantum MLS (Rust)

This repository implements a Hybrid Messaging Layer Security (MLS) protocol in Rust, based on RFC 9420 and TreeKEM. The hybrid design combines classic (X25519/Ed25519) and post-quantum (ML-KEM-768/ML-DSA-65) cryptography so the system remains secure if either component remains unbroken.

**Goals**
- Implement MLS group key establishment and updates using a single integrated hybrid ratchet tree.
- Provide hybrid KEM and hybrid signature primitives (no FFI, pure Rust).
- Enforce “dual verification” so a signature is valid only if both classic and PQ signatures verify.

**Status**
- Progress tracking is maintained in `PROJECT.md`.

**Architecture**
- `src/crypto.rs` implements hybrid KEM, hybrid signatures, serialization helpers, and HPKE-style path secret encryption.
- `src/tree.rs` implements the ratchet tree, parent hashes, node resolution, proposals/commits, and path update logic.

**Hybrid Cryptography Stack**

| Use | Classic | PQ | Crate |
| --- | --- | --- | --- |
| KEM | X25519 | ML-KEM-768 | `x25519-dalek`, `ml-kem` |
| Signatures | Ed25519 | ML-DSA-65 | `ed25519-dalek`, `ml-dsa` |

**Path Update (Current Focus)**
1. Sender derives a sequence of path secrets up the direct path.
2. For each copath resolution node, the sender performs hybrid KEM.
3. The KEM shared secret is used to encrypt the path secret with an AEAD.
4. Receivers decapsulate and decrypt to recover the path secret, then derive higher secrets.

Path update payloads are now serializable via `PathUpdate::encode()` and can be attached to commits with `Commit::encode_with_path_update(...)`.
Receivers can apply a commit and consume a path update in one step via `RatchetTree::apply_commit_with_path_update(...)`.
`PathUpdate::decode(...)` and `PathSecretCiphertext::decode(...)` are available for parsing received payloads.
`Commit::decode(...)` and `Commit::decode_with_path_update(...)` parse commit payloads and (optionally) attached path updates.
Unit tests now cover commit encode/decode round-trips with and without path update payloads.

Unit tests now cover `apply_commit_with_path_update` for both success and wrong-leaf failure cases.

**Build and Test**
```bash
cargo check
cargo test
```

**Example Program**
Run a minimal in-memory flow (group creation + Add commit + path update processing):
```bash
cargo run --example minimal
```
This runs an in-memory flow and prints the derived path secrets on the receiver side. The example is deterministic and not production-safe.

**How to Use (Conceptual Flow)**
This is a library-only implementation. There is no network or server component yet. The typical MLS flow is:
1. Each client generates a `KeyPackage`.
2. A group creator builds a `Commit` with `Add` proposals and a path update.
3. The commit is distributed to all members, who update their local ratchet trees.

**5 VM Example (1 Delivery Service + 4 Users)**
Yes, that model is correct for MLS. The Delivery Service (DS) is **not** a group member. It only transports messages.

Example layout:
- VM1: Delivery Service (stores and forwards MLS proposals and commits)
- VM2–VM5: Group members (users)

Conceptual steps:
1. Each user VM generates a `KeyPackage` and uploads it to the DS.
2. A creator VM fetches key packages and builds a `Commit` with `Add` proposals.
3. The creator VM sends the commit to the DS.
4. The DS distributes the commit to all member VMs.
5. Each member applies the commit and updates its ratchet tree locally.

**Security Notes**
- This is a research prototype, not production-ready.
- Cryptographic encoding and ciphersuite details still need RFC‑compatible finalization.
