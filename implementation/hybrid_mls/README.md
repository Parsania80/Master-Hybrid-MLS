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

**Delivery Service (Planned)**
- HTTP server with disk-backed message store and in-memory index.
- Configurable limits: max storage bytes (default 20 GiB) and min proposals per commit (default 10).
- Hybrid authentication: DS has classic+PQ signing keys; users register classic+PQ public keys.
- Web UI: sign up/sign in, group list, group actions (Add/Remove/Update), and event logs.

**Delivery Service (Part 1 Implemented)**
- Disk-backed storage with SQLite metadata + file spool per group.
- Storage quota and eviction: oldest messages are deleted when `max_bytes` is exceeded.
- Config in `src/ds/config.rs` with `DEFAULT_MAX_BYTES = 20 * 1024 * 1024 * 1024`.

**Key Generation & Message Routing (RFC 9420)**
- Clients generate their own KeyPackages and publish public keys to the DS directory.
- The DS provides a group channel; it forwards MLS messages to group members, who decrypt locally.

**Delivery Service (Part 2 In Progress)**
- Axum HTTP API skeleton with request/response types.
- All API requests include a `signature` field (hybrid signing enforced later).
- Proposal/commit payloads are base64-encoded in HTTP JSON.
- Commit submission enforces a configurable minimum pending proposals (default 10).
- Signed-request verification is enforced for proposals, commits, and message listing.
- KeyPackage publish/fetch endpoints are available.
- Signing input uses `tag|username|group_id|SHA3(payload)`; path updates include `SHA3(path_update)` when present.
- Application message endpoints are available for store/list/fetch (signed requests).
- Deployment split: DS runs the HTTP server + storage; users run a separate client app (CLI/UI) that generates keys and processes commits.
- Login/session endpoints exist (SQLite-backed) but need client wiring and UI.
- Unit tests now cover DS storage/auth and signature verification helpers.

**Delivery Service Client CLI (New)**
The CLI is a prototype tool to register users, submit proposals/commits, and fetch messages from the DS.

Example usage:
```bash
cargo run --bin ds_client -- register --base-url http://127.0.0.1:3000 --username alice --password secret
cargo run --bin ds_client -- login --base-url http://127.0.0.1:3000 --username alice --password secret
cargo run --bin ds_client -- submit-proposal --base-url http://127.0.0.1:3000 --group-id group1 --proposal-file /path/to/proposal.bin
cargo run --bin ds_client -- submit-commit --base-url http://127.0.0.1:3000 --group-id group1 --commit-file /path/to/commit.bin --path-update-file /path/to/path.bin
cargo run --bin ds_client -- list-messages --base-url http://127.0.0.1:3000 --group-id group1 --limit 50
cargo run --bin ds_client -- publish-key-package --base-url http://127.0.0.1:3000 --keypackage-file /path/to/keypackage.bin
cargo run --bin ds_client -- fetch-key-package --base-url http://127.0.0.1:3000 --target alice --out /path/to/keypackage.bin
```
The client stores signing keys in `ds-client.json` by default. This is for development only.

Last updated: 2026-02-08 21:55
