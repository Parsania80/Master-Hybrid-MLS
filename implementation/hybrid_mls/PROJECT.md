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
- `protocl-actions/*`: Protocol action documentation templates and code/RFC-mapped flow notes for professor/demo review
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
| 3 | Implement tree resolution and direct path helpers | ✅ Done | `direct_path`, `filtered_direct_path`, `resolution` implemented; direct-path/copath public ordering aligned to leaf-to-root semantics in `src/tree.rs` with regression tests. |
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
| 4 | Finalize DS session lifecycle and policy enforcement | ✅ Done | Session-aware auth policy is now enforced across DS endpoints (`session_id` required, session ownership/expiry validation, login-time purge, logout endpoint). CLI now carries `session_id` across signed requests and supports explicit logout; DS-backed e2e suite is green after session-policy and misuse assertion updates. Configurable session TTL and per-user session rotation limits are now implemented and tested. Hybrid signature/keypackage verification now executes in a dedicated large-stack worker to prevent runtime stack overflow under local demo load. |
| 5 | Build operator/user web UI for sign-in and group actions | ✅ Done | Added DS UI skeleton routes (`/ui/login`, `/ui/groups`, `/ui/groups/:group_id`) plus a local `ds_ui_gateway` binary that serves signed UI flows and forwards requests to the DS. |
| 6 | Add multi-VM deployment/test guide and automation | ⬜ Todo | Convert local demo into repeatable 5-VM procedure. |

### Part 8: UI and Admin Demo
| # | Task | Status | Notes |
|---|------|--------|-------|
| 1 | User login + logout UX | ✅ Done | Logout on all pages, `/ui/login` default, and local session status shown. |
| 2 | KeyPackage UX (simple flow) | ✅ Done | One-click generate + publish, optional manual publish with clear feedback, and stored receiver private file path. |
| 3 | KeyPackage selection/share UX | ✅ Done | Local keypackage library with list/copy/use/publish actions. |
| 4 | Group list + membership UX | ✅ Done | Groups list now supports add, refresh, filter/search, forget, and auto-track on group open. |
| 5 | Group page action menu | ✅ Done | Actions menu now creates Add/Remove/Update proposals, supports Create+Submit Commit from pending proposals, and includes Sync+Apply Latest to consume DS commit/path-update streams into local state. Added stack-safe large-stack worker execution for UI/DS hybrid signing and keypackage verification in proposal flow, plus UI+DS end-to-end test coverage for register/bootstrap/add/commit/sync/relogin group visibility. Top-bar Sync + Apply Latest is now available and auto-sync runs on groups/group page load for logged-in users. Added MLS-aligned joiner-onboarding endpoint/button (`join-from-latest`) that reconstructs a pre-commit base tree from ordered base-member keypackages, applies the matched Add commit + path update, and persists local state. |
| 6 | Tree structure view | ✅ Done | Group UI now renders local ratchet tree nodes (leaf/parent/blank) with short key fingerprints and metadata. |
| 7 | Admin account bootstrap | ✅ Done | DS now bootstraps deterministic `admin/admin@123` on storage open, exposes signed admin-only APIs for listing all users/groups (`/v1/admin/users`, `/v1/admin/groups`), and UI gateway includes `/ui/admin` with admin panel + integration tests. |
| 8 | Admin demo index | ✅ Done | Added admin demo index flow in UI gateway: admin panel now lists demos, supports creating new demos, and supports opening demo detail pages; persisted under `ui-state/demo/<id>` with index + manifest files. |
| 9 | Admin demo UI layout | ✅ Done | Added `/ui/admin/demos/:demo_id` two-pane layout: right tree panel, left split into actions (top) and logs (bottom), responsive collapse for smaller screens, with demo metadata wiring. |
| 10 | Admin demo actions | ✅ Done | Wired demo action APIs and UI controls for Add/Remove/Update (`adder/added`, `remover/removed`, `updater`) with deterministic state transitions, epoch bumping, member reindexing, and persisted demo state updates. |
| 11 | Admin demo logging | ✅ Done | Added timestamped MLS-style log entries for init/Add/Remove/Update transitions with `--------------------` separators; log entries persist in `ui-state/demo/<id>/state.json` and render in demo UI. |
| 12 | Admin demo persistence | ✅ Done | Enforced persisted demo state usage across reloads and strict missing-state handling (no implicit reset). Added UI “Reload Demo” control and end-to-end integration test covering restart/reload persistence, clean new-demo initialization, and missing-demo action rejection without orphan state writes. |

### Part 9: RFC 9420 Welcome (Hybrid)
| # | Task | Status | Notes |
|---|------|--------|-------|
| 1 | Define Welcome/GroupInfo/GroupSecrets hybrid wire structures and codecs | ✅ Done | Added `src/welcome.rs` with strict codecs for `Welcome`, `EncryptedGroupSecrets`, `GroupSecrets`, and `GroupInfo`; includes round-trip + malformed decode tests. |
| 2 | Implement hybrid HPKE-style encryption for Welcome secrets | ✅ Done | Added `EncryptedGroupSecrets::encrypt_for_recipient` and `decrypt_group_secrets` using hybrid KEM encapsulation/decapsulation + HPKE-style AEAD payload protection with group/epoch/key-ref bound context. Added round-trip/wrong-recipient/tamper tests. |
| 3 | Committer flow: generate Welcome when commit contains Add proposals | ✅ Done | `ds_client create-commit` now generates Welcome when pending proposals include Add; output is written to `--welcome-out` or `<commit_out>.welcome`. UI `commit-from-pending` now returns optional `welcome_b64` for Add commits. Added unit tests for no-Add and Add+decryptable GroupSecrets cases. |
| 4 | DS transport for Welcome messages | ✅ Done | DS commit submit API now accepts optional `welcome_bytes` and persists it as `kind=welcome`; signed list/fetch supports `kind=welcome`; UI and CLI commit submit paths now sign+send optional Welcome payloads. Added DS transport round-trip test for commit/path/welcome and CLI-driven DS-backed integration test validating `list-messages --kind welcome`. |
| 5 | CLI join-from-welcome command | ✅ Done | Added `ds_client join-from-welcome` consuming `welcome+commit+path_update+receiver_private` with base pre-commit members; validates decryptable GroupSecrets, checks Welcome GroupInfo consistency (`group_id`, `epoch`, `tree_hash`, `signer_leaf`), and persists joined state. |
| 6 | Sync integration: auto-consume Welcome before commit/path apply | ✅ Done | `fetch-and-apply-latest` now supports unknown-group bootstrap from DS Welcome stream (`--group-id`, `--base-member-keypackage`, `--receiver-private-file`) and then continues normal commit/path sync. Added DS-backed integration test for auto-bootstrap plus negative coverage (wrong base members, wrong receiver key, tampered welcome). |
| 7 | UI onboarding migration from commit-scan to Welcome-first | ✅ Done | `join-from-latest` now resolves onboarding material from DS `welcome+commit+path_update`, reconstructs joiner state, validates Welcome decryptability + path-secret consistency + GroupInfo (`group_id`, `epoch`, `signer_leaf`, `tree_hash`), then persists state and performs catch-up sync. |
| 8 | RFC 9420 compliance note + test vectors for Welcome flow | ✅ Done | Added README RFC mapping note for Welcome wire objects and key-schedule linkage; added deterministic vectors in `src/welcome.rs` (fixed GroupSecrets encoding bytes + fixed Welcome-encoding digest with strict decode) and `src/bin/ds_client.rs` (fixed joiner-secret derivation vector for deterministic commit/path material). Added DS-backed integration test to assert Welcome payload byte stability across submit/fetch round-trip (`tests/ds_fetch_apply_e2e.rs`). |

### Part 10: RFC 9420 Post-Welcome Compliance Hardening (Hybrid)
| # | Task | Status | Notes |
|---|------|--------|-------|
| 1 | Implement MLS wire objects (`MLSMessage`, `PublicMessage`, `PrivateMessage`) | ✅ Done | Added `src/mls_wire.rs` with strict codecs for `MlsMessage` (version + wire_format framing), `PublicMessage`, and `PrivateMessage`; includes content-type framing (`Proposal`/`Commit`/`Application` + project `PathUpdate` extension), envelope conversion helpers, and malformed decode tests. |
| 2 | Implement `AuthenticatedContent` and framing signatures | ✅ Done | Added `src/authenticated_content.rs` with `AuthenticatedContentTbs`/`AuthenticatedContent` sign+verify codecs over `PublicMessage` framing and envelope conversion helpers. Proposal/commit/path DS request signing inputs now prefer authenticated-content hashes (with payload-hash fallback for malformed legacy/misuse test payloads). |
| 3 | Implement transcript hash pipeline | ✅ Done | Added `src/transcript.rs` with confirmed/interim transcript state, proposal/commit update helpers, and deterministic vectors. Integrated transcript persistence into `ClientGroupState` v4 serialization and wired commit epoch advance to update transcript state. Welcome generation now uses predicted confirmed transcript hash; joiner Welcome validation now checks GroupInfo confirmed transcript hash against reconstructed local transcript state. |
| 4 | Implement confirmation tag verification | ✅ Done | Added transcript confirmation-tag derivation/verification helpers (`src/transcript.rs`) and integrated them into Welcome flow. Confirmation tags now use an explicit `confirmation_key` stage derived from `epoch_secret` (instead of direct root-secret input) plus confirmed transcript hash; joiner-side Welcome validation verifies against local transcript/key-schedule state and rejects mismatches. |
| 5 | Implement membership tag verification | ✅ Done | Added membership-key/tag derivation and verification in `src/authenticated_content.rs` (`derive_membership_key`, `derive_membership_tag`, `verify_with_membership_tag`) with canonical signature input excluding membership tag. Membership key derivation now consumes `epoch_secret` chain stage; added membership-tag sign/verify tamper tests and client-state membership key derivation helpers/rotation test. |
| 6 | Extend proposal set: `PreSharedKey` | ✅ Done | Added `Proposal::PreSharedKey { psk_id }` in `src/tree.rs` with strict wire tag/codec support, validation (`EmptyPreSharedKeyId`, `DuplicatePreSharedKey`), commit-apply integration (state-neutral for tree topology), unit coverage, and DS-backed mixed-batch integration tests (`Update+PSK`, `Remove+PSK`) in `tests/ds_fetch_apply_e2e.rs`. |
| 7 | Extend proposal set: `ReInit` | ✅ Done | Added `Proposal::ReInit { group_id, version, cipher_suite, extensions }` with strict wire codec + validation rules (`DuplicateReInit`, empty group id, mixed-proposal rejection, unsupported version/cipher suite), state-neutral commit apply semantics, and DS-backed commit/sync coverage in `tests/ds_fetch_apply_e2e.rs`. |
| 8 | Extend proposal set: `GroupContextExtensions` | ✅ Done | Added `Proposal::GroupContextExtensions { extensions }` wire codec + validation (`DuplicateGroupContextExtensions`, `ReInitAndGroupContextExtensionsConflict`), state-neutral tree apply semantics, and client-state application rule (`group_context_extensions` persisted in state v5 and applied on commit ingest). Includes DS-backed mixed `Update+GroupContextExtensions` integration coverage. |
| 9 | Add proposal validation matrix for new proposal families | ✅ Done | DS-backed negative rejection tests now cover invalid commit proposal sets for `DuplicateGroupContextExtensions`, `ReInit+GroupContextExtensions` conflict, `DuplicateReInit`, and unsupported `ReInit` parameters (version/cipher suite) through real submit/sync paths. |
| 10 | Implement full RFC-style key schedule chain | ✅ Done | Key-schedule chain now derives/stores `commit_secret`, `joiner_secret`, `welcome_secret`, `epoch_secret`, and `root_secret` per epoch (v2 encoding + v1 decode compatibility). Welcome/commit flows use chain secrets explicitly, tag helpers use stage keys from `epoch_secret`, deterministic vectors pin outputs, and DS-backed tests cover persisted reload + replay/no-op stability across single and multi-epoch chains. |
| 11 | Align key schedule labels/contexts to RFC names | ✅ Done | Completed RFC-style label/context alignment with persisted `group_context_hash` binding, rebaselined deterministic vectors, DS-backed stage-key stability tests, and README context-input mapping table (`group_context_hash`, `confirm`, `membership`, `sender_data`). |
| 12 | Implement RFC-style application message protection | ✅ Done | Added `src/application_message.rs` for RFC-style `PrivateMessage` protect/unprotect (`encrypted_sender_data` + application ciphertext) bound to group/epoch/content-type/authenticated-data context; wired CLI/UI app message send/fetch to use local `ClientGroupState` encryption/decryption; added unit tests and DS-backed integration test `app_private_message_ds_roundtrip_with_group_state`. |
| 13 | Add DS-backed protocol state-machine guards | ✅ Done | Added DS submission guards for proposal/commit/path payload consistency (`proposal_group_mismatch`, `missing_path_update`, path metadata mismatches), commit-epoch monotonic checks (`stale_or_duplicate_commit_epoch`, `commit_epoch_gap`), and receiver-side strict transition guard rejecting multi-member no-op commits. DS-backed suite was rebaselined to this stricter policy and is green (`tests/ds_fetch_apply_e2e.rs`: 42 passed). |
| 14 | Relax and harden commit policy for multiple Add proposals | ✅ Done | Removed single-Add restriction and replaced it with robust Add-target checks: invalid Add keypackage rejection, existing-member identity rejection, and duplicate Add target rejection (identity/init-key). Added unit + DS-backed integration coverage. |
| 15 | Add RFC conformance test matrix and vectors | ✅ Done | Completed deterministic fixture suite: `AuthenticatedContent`, `PublicMessage`/`PrivateMessage`, and `ProposalEnvelope`/`CommitEnvelope`/`PathUpdateEnvelope` binary fixtures; added fixture hash manifest validation (`tests/vector_manifest.rs` + `tests/vectors/MANIFEST.sha3`), malformed fixture corpus, and DS-backed byte-stability round-trip assertions. |

### Part 11: RFC Tree Semantics Bug Fixes (UI/Admin Demo)
| # | Task | Status | Notes |
|---|------|--------|-------|
| 1 | Replace demo member-list model with explicit tree model (leaf/node indices + blank nodes) | ✅ Done | Migrated admin demo persistence from `members` vector to explicit `leaf_slots` topology (`Vec<Option<...>>`) with legacy state migration support and derived `leaf_count`/`node_count` in detail API. |
| 2 | Enforce RFC-style Add placement in demo flow | ✅ Done | Formalized Add placement via explicit helper (`reused leftmost blank` vs `extend tree`), updated MLS-style logs accordingly, and added strict unit/integration tests for blank-reuse before extension and stable leaf-index behavior after add. |
| 3 | Enforce RFC-style Remove behavior in demo flow | ✅ Done | Remove now follows explicit blank+trim policy: blank target leaf, truncate only trailing blank leaves (no compaction/reindex), and emit deterministic truncation/no-truncation logs. Added strict unit + DS-backed integration coverage. |
| 4 | Render real binary tree in admin demo UI from node topology | ✅ Done | Replaced star renderer with topology-driven left-balanced binary render based on leaf span (`leaf_count`), parent/child edges, and explicit blank/internal node visualization; tree header now reports epoch/leaves/nodes. |
| 5 | Show both `LeafIndex` and `NodeIndex` in UI labels | ✅ Done | Tree nodes now render explicit index labels (`Lx / Ny` for leaves, `Ny` for parents) with root marker, key-generation/user tags, and polished legend text clarifying `LeafIndex` vs `NodeIndex` semantics including even-node leaf rule. |
| 6 | Align demo logs with exact RFC-style tree operations | ✅ Done | Admin demo logs now use RFC-style wording across init/Add/Remove/Update/Commit entries with explicit `GroupContext.epoch`, `LeafIndex`, and `NodeIndex` semantics plus trim/no-trim outcomes. |
| 7 | Add regression tests for demo tree semantics | ✅ Done | Completed coverage for add-reuse-blank, remove-without-reindex, index stability across epochs, and binary layout invariants via new unit + DS-backed integration tests in `src/bin/ds_ui_gateway.rs`. |
| 8 | Add migration/compatibility for existing demo state files | ✅ Done | Added migration hardening for legacy `members` state: duplicate `leaf_index` and empty-username legacy records are now rejected; added DS-backed integration coverage that injects legacy state, verifies migrated detail API topology, and confirms persistence rewrites to new `leaf_slots` schema after action apply. |

### Part 12: RFC 9420 TreeKEM Secret-Lineage Alignment (Core Crypto Fix)
| # | Task | Status | Notes |
|---|------|--------|-------|
| 1 | Define explicit `leaf_secret` / `path_secret` / `node_secret` data model and invariants | ✅ Done | Added explicit TreeKEM secret model in `src/tree.rs` (`LeafSecret`, `DirectPathSecretLevel`, `DirectPathSecretModel`) with structural validation (`DirectPathSecretModelError`) and invariant-focused tests. |
| 2 | Replace random parent-key generation with deterministic derivation from node secrets | ✅ Done | Added deterministic node-secret-to-public-key derivation in `src/tree.rs` and switched commit builders in `src/bin/ds_client.rs` and `src/bin/ds_ui_gateway.rs` to use `DirectPathSecretModel::parent_updates_leaf_to_root()` instead of random parent keys. |
| 3 | Implement sender direct-path secret chain exactly from leaf secret to root | ✅ Done | Tightened sender semantics by adding explicit node-secret transform policy (`node_secret = KDF(path_secret, parent_node, level_from_leaf)`) and model validation checks in `src/tree.rs`, plus derivation/domain-separation tests. |
| 4 | Bind Commit `path` parent public keys to derived node secrets with strict validation | ✅ Done | `apply_commit_with_path_update` now performs strict lineage validation in `src/tree.rs` by recomputing expected parent keys from derived node secrets and rejecting mismatches; added regression test for tampered commit parent key rejection. |
| 5 | Upgrade receiver path-update processing to reconstruct/verify node-secret lineage | ✅ Done | Receiver processing now decrypts/collects per-level secrets across the whole direct path, enforces ciphertext-width checks for every encoded level, cross-checks reconstructed-vs-observed secrets, validates commit parent keys against derived lineage when `path_secrets` are omitted, and is covered by DS-backed malformed encoded stream negatives (non-receiver-level underflow/overflow). |
| 6 | Feed commit-secret from TreeKEM path lineage into key schedule entry points | ✅ Done | Added `ensure_epoch_with_tree_commit_secret` in `src/key_schedule.rs` and wired TreeKEM lineage commit-secret inputs from sender/receiver/joiner flows (`src/client_state.rs`, `src/bin/ds_client.rs`, `src/bin/ds_ui_gateway.rs`) so commit-path derived secrets now enter key-schedule chain derivation. Added deterministic/behavior tests in `src/key_schedule.rs` and `src/client_state.rs`. |
| 7 | Add deterministic vectors for leaf/path/node secret chain and derived parent keys | ✅ Done | Added deterministic vector tests in `src/tree.rs` for root/leaf-parent `path_secret` + `node_secret` chain values and hybrid parent key material: classic branch exact bytes and PQ branch SHA3-256 digests for leaf-parent/root parent updates. |
| 8 | Add DS-backed end-to-end tests for Add/Update/Remove with strict secret-lineage checks | 🔄 Current | Added DS-backed strict-lineage negatives in `tests/ds_fetch_apply_e2e.rs` for tampered Add commit parent path key rejection and Remove commit + inconsistent path-update payload rejection; existing Update tampered path payload strict-rejection coverage remains in place. |
| 9 | Add migration/compat strategy for existing local state and previously stored commits | ⬜ Todo | Decide version gate or compatibility decode path to avoid breaking existing demo/test data unexpectedly. |
| 10 | Add RFC mapping notes for final TreeKEM lineage model in protocol docs | ⬜ Todo | Update `protocl-actions/*` and README with section-by-section mapping and residual deviations. |

---
Current: `Part 12 / Task 8 - Add DS-backed end-to-end tests for Add/Update/Remove with strict secret-lineage checks`
Next: `Part 12 / Task 9 - Add migration/compat strategy for existing local state and previously stored commits`
