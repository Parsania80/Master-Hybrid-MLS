# Hybrid MLS Implementation Project

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
- `src/client_state.rs`: Client-side group state model and persistence (epoch/tree/pending proposals)
- `src/envelope.rs`: Message envelope metadata for proposal/commit/path payloads (group_id, epoch, sender_leaf)
- `src/key_schedule.rs`: Epoch secret tree and persisted key schedule state for per-epoch root-secret tracking
- `src/ds/*`: Delivery Service storage (SQLite + disk spool), auth, and HTTP API
- `src/bin/ds_server.rs`: Axum server entrypoint for DS APIs
- `src/bin/ds_client.rs`: CLI for DS auth, key packages, proposals, commits, sync/apply, and app message flows
- `scripts/local-1ds-4clients-*.sh`: local orchestration scripts for DS/client lifecycle
- `scripts/local-1ds-4clients-demo.sh`: end-to-end local demo (A adds B, B adds C, A removes C) with logs

## Roadmap

### Part 1: Hybrid Primitives
| # | Task | Status | Notes |
|---|------|--------|-------|
| 1 | Implement hybrid KEM key types and serialization | ✅ Done | Implemented in `src/crypto.rs`. |
| 2 | Implement dual-sign / dual-verify identity signatures | ✅ Done | Ed25519 + ML-DSA enforced together. |
| 3 | Implement HPKE-style path secret encrypt/decrypt helpers | ✅ Done | `encrypt_path_secret` and `decrypt_path_secret` present and tested. |

### Part 2: Tree Structures
| # | Task | Status | Notes |
|---|------|--------|-------|
| 1 | Implement integrated ratchet tree indexing and node model | ✅ Done | Leaf/parent/blank model implemented in `src/tree.rs`. |
| 2 | Implement parent hash computation and update propagation | ✅ Done | Parent hash logic and recomputation implemented. |
| 3 | Implement tree resolution and direct path helpers | ✅ Done | `direct_path`, `filtered_direct_path`, `resolution` implemented. |
| 4 | Add encode/decode coverage for tree and commit payloads | ✅ Done | Round-trip tests exist. |

### Part 3: Engine (Proposals & Commits)
| # | Task | Status | Notes |
|---|------|--------|-------|
| 1 | Implement proposal/commit core types and application rules | ✅ Done | Add/Update/Remove commit flow exists in `src/tree.rs`. |
| 2 | Add proposal validation rules (bounds/duplicate/conflict checks) | ✅ Done | Commit validation and constraints implemented. |
| 3 | Build client-side proposal and commit creation commands | ✅ Done | `create-*proposal` and `create-commit` in `src/bin/ds_client.rs`. |
| 4 | Implement receiver-side commit apply and join-from-commit flow | ✅ Done | `apply-received-commit` and `join-from-commit` implemented. |
| 5 | Harden multi-client sync semantics and edge-case validation | ✅ Done | Completed: strict commit metadata checks, DS message ID dedup/sanitization, metadata-based path-update matching, persisted replay markers, explicit stop-on-future-epoch-gap behavior, strict receiver policy for missing/mismatched path updates, and DS-backed replay/negative coverage in `fetch-and-apply-latest`. |
| 6 | Add integration tests for 3+ member real commit chains | ✅ Done | DS-backed 3-member cryptographic commit-chain sync tests cover both `A update -> B/C sync -> B update -> A/C sync` and `A adds C -> B update -> A removes C`, with path-update decapsulation and surviving-member convergence assertions. |

### Part 4: Path Updates (Math)
| # | Task | Status | Notes |
|---|------|--------|-------|
| 1 | Derive path secrets and direct-path hybrid ciphertexts | ✅ Done | Implemented in tree path update builder/processor. |
| 2 | Wire receiver decapsulation and derived secret extraction | ✅ Done | `apply_commit_with_path_update` implemented and tested. |
| 3 | Align derivation labels/contexts with RFC 9420 style schedule inputs | ✅ Done | Added MLS 1.0-style labeled derivation framing plus README RFC mapping notes/table for current labels vs target RFC terms/sections. |
| 4 | Add negative tests for tampered path ciphertext/metadata | ✅ Done | Added unit negatives for tampered path payload, tampered KEM ciphertext, resolution/ciphertext-count mismatch, path-update metadata mismatches (group/sender/epoch), malformed commit/path envelope decoding (truncated/trailing bytes), malformed `PathSecretCiphertext` field decoding (classic length, PQ length, corrupted level counts), plus DS-backed malformed commit/path/proposal submission tests over HTTP with receiver sync skip/rejection assertions. |

### Part 5: Security Properties
| # | Task | Status | Notes |
|---|------|--------|-------|
| 1 | Enforce and test forward secrecy behavior across updates | ✅ Done | Added baseline unit tests (stale receiver key + removed-member rejection) plus DS-backed HTTP sync integrations proving (a) stale receiver private material fails while rotated receiver private succeeds, and (b) a removed member cannot apply the subsequent commit stream. |
| 2 | Enforce and test post-compromise security recovery | ✅ Done | Added DS-backed PCS recovery-chain tests: (a) 2-member chain where compromised old receiver private fails after self-update while recovered key converges, and (b) 3-member chain `A adds C -> C self-update -> A next commit` where old compromised C key fails and recovered C key succeeds. |
| 3 | Add misuse/attack test matrix (replay, malformed commits, bad signatures) | ✅ Done | Added DS-backed misuse matrix baseline: invalid-signature rejection for `submit-proposal`, `submit-commit`, `list-messages`, and `fetch-group-message`; malformed commit payload with valid envelope metadata skipping without blocking valid commits; replay permutation where duplicated old commit is skipped while newer epoch commits apply; plus malformed `path_update` misuse cases that preserve envelope metadata and trigger strict receiver rejection (decode-fail and tampered-ciphertext apply-fail). |

### Part 6: Key Schedule
| # | Task | Status | Notes |
|---|------|--------|-------|
| 1 | Define epoch secret tree and key schedule state structure | ✅ Done | Added `src/key_schedule.rs` with persisted epoch-secret nodes (`epoch`, `parent_epoch`, `root_secret`), deterministic labeled derivation, and binary encode/decode; wired into `ClientGroupState` (v3) with v1/v2 backward-compatible bootstrap and CLI epoch-advance hooks. |
| 2 | Derive handshake/application/exporter secrets from root secret | ✅ Done | Added `EpochDerivedSecrets` derivation (`handshake`, `application`, `exporter`) from epoch root secret with MLS-labeled separation and epoch/group context; exposed via `KeyScheduleState`, `ClientGroupState`, and `ds_client show-derived-secrets` debug output for demo/inspection. |
| 3 | Connect schedule advancement to commit application | ✅ Done | Added strict consistency checks in all commit-apply paths (`create-commit`, `apply-received-commit`, `join-from-commit`, `fetch-and-apply-latest`) enforcing `key_schedule.current_epoch == group epoch` and well-formed epoch-chain invariants before/after persistence; added mismatch/tamper regression tests plus DS-backed integration coverage that rejects tampered inconsistent local state transitions during sync. |
| 4 | Add deterministic schedule test vectors | ✅ Done | Added fixed-input/fixed-output key-schedule vectors in `src/key_schedule.rs` (`deterministic_vector_alpha_matches_expected`, `deterministic_vector_beta_matches_expected`) covering init/root/handshake/application/exporter secrets across epochs. |

### Part 7: Delivery Service (HTTP + Auth + UI)
| # | Task | Status | Notes |
|---|------|--------|-------|
| 1 | Implement DS storage and eviction policy | ✅ Done | SQLite metadata + disk spool + max-byte eviction implemented. |
| 2 | Implement signed HTTP endpoints for auth/proposals/commits/messages | ✅ Done | Core endpoints and signature checks implemented in `src/ds/http.rs`. |
| 3 | Implement keypackage publish/fetch and app-message transport | ✅ Done | Endpoints + CLI wiring implemented. |
| 4 | Finalize DS session lifecycle and policy enforcement | ✅ Done | Session-aware auth policy is now enforced across DS endpoints (`session_id` required, session ownership/expiry validation, login-time purge, logout endpoint). CLI now carries `session_id` across signed requests and supports explicit logout; DS-backed e2e suite is green after session-policy and misuse assertion updates. Configurable session TTL and per-user session rotation limits are now implemented and tested. |
| 5 | Build operator/user web UI for sign-in and group actions | ✅ Done | Added DS UI skeleton routes (`/ui/login`, `/ui/groups`, `/ui/groups/:group_id`) plus a local `ds_ui_gateway` binary that serves signed UI flows and forwards requests to the DS. |
| 6 | Add multi-VM deployment/test guide and automation | ⬜ Todo | Convert local demo into repeatable 5-VM procedure. |

### Part 8: UI and Admin Demo
| # | Task | Status | Notes |
|---|------|--------|-------|
| 1 | User login + logout UX | ✅ Done | Logout on all pages, `/ui/login` default, and local session status shown. |
| 2 | KeyPackage UX (simple flow) | ✅ Done | One-click generate + publish, optional manual publish with clear feedback, and stored receiver private file path. |
| 3 | KeyPackage selection/share UX | ✅ Done | Local keypackage library with list/copy/use/publish actions. |
| 4 | Group list + membership UX | ✅ Done | Groups list now supports add, refresh, filter/search, forget, and auto-track on group open. |
| 5 | Group page action menu | ✅ Done | Actions menu now creates Add/Remove/Update proposals using local group state and submits to DS. |
| 6 | Tree structure view | ✅ Done | Group UI now renders local ratchet tree nodes (leaf/parent/blank) with short key fingerprints and metadata. |
| 7 | Admin account bootstrap | 🔄 Current | Ensure `admin/admin@123` exists in DB on startup; admin sees all users and groups. |
| 8 | Admin demo index | ⬜ Todo | Admin “Demo” menu lists demos, allows create/open; demos stored under `ui-state/demo/<id>`. |
| 9 | Admin demo UI layout | ⬜ Todo | Two-column layout: right tree view; left split into actions (top) and logs (bottom). |
| 10 | Admin demo actions | ⬜ Todo | Add/Remove/Update actions with inputs (adder, added; remover; updater) and deterministic flow. |
| 11 | Admin demo logging | ⬜ Todo | Timestamped MLS-style step logs with separators; logs persisted in `ui-state/demo/<id>`. |
| 12 | Admin demo persistence | ⬜ Todo | Demo state reload on open; “new demo” initializes A-only tree and clean logs. |

---
Current: `Part 8 / Task 7 - Admin account bootstrap`
Next: `Part 8 / Task 8 - Admin demo index`
