# Hybrid Post-Quantum MLS (Rust)

This repository implements a Hybrid Messaging Layer Security (MLS) protocol in Rust, based on RFC 9420 and TreeKEM. The hybrid design combines classic (X25519/Ed25519) and post-quantum (ML-KEM-768/ML-DSA-65) cryptography so the system remains secure if either component remains unbroken.

**Goals**
- Implement MLS group key establishment and updates using a single integrated hybrid ratchet tree.
- Provide hybrid KEM and hybrid signature primitives (no FFI, pure Rust).
- Enforce “dual verification” so a signature is valid only if both classic and PQ signatures verify.

**Status**
- Progress tracking is maintained in `PROJECT.md`.
- Current implementation priority is Part 11 (RFC tree semantics bug fixes for Admin Demo UI/state).
- RFC compliance note: beyond Welcome, remaining work includes full MLS wire framing, transcript/confirmation/membership authentication pipeline, full proposal set, and deeper RFC key-schedule alignment.
- Post-Welcome RFC hardening tasks are tracked in `PROJECT.md` Part 10.
- `PreSharedKey` proposal support is now implemented in the tree/commit model (`Proposal::PreSharedKey { psk_id }`) with encode/decode and validation coverage.
- `ReInit` proposal support is now implemented in the tree/commit model (`Proposal::ReInit { group_id, version, cipher_suite, extensions }`) with compatibility/validation checks and DS-backed sync coverage.
- `GroupContextExtensions` proposal support is now implemented in the tree/commit model (`Proposal::GroupContextExtensions { extensions }`) with validation and DS-backed mixed-batch sync coverage.
- Key schedule Task 10 is complete with a fuller per-epoch chain: `commit_secret -> joiner_secret -> welcome_secret -> epoch_secret -> root_secret`.
- Welcome flow now uses chain secrets explicitly: committer writes `GroupSecrets.joiner_secret` from key-schedule `joiner_secret`, encrypts `GroupInfo` with `welcome_secret`, and includes `commit_secret` in GroupInfo signature input; joiner validates these against local chain state.
- Stage-key derivation now has explicit helpers for `confirmation_key`, `membership_key`, and `sender_data_key` derived from `epoch_secret` (`src/stage_keys.rs`), and deterministic vectors pin these outputs for drift detection.
- Task 11 RFC alignment is complete: key schedule and stage-key derivation labels now use RFC-like naming (`init_secret`, `commit_secret`, `joiner_secret`, `welcome_secret`, `epoch_secret`, `root_secret`, `handshake_secret`, `application_secret`, `exporter_secret`, plus `confirm`/`membership`/`sender_data`) and per-epoch `group_context_hash` binding (v3 key-schedule encoding with backward decode for v1/v2).
- Task 12 application-message protection is complete: app payloads are now produced/consumed as MLS-style `PrivateMessage` bytes via `src/application_message.rs`, and CLI/UI app-message flows now protect/unprotect using local `ClientGroupState`.
- Task 13 protocol state-machine guards are now in place: DS rejects proposal/commit metadata mismatches and missing required path-update payloads, enforces commit epoch monotonic progression, and receiver sync rejects invalid multi-member no-op commit transitions.
- Task 14 multiple-Add policy hardening is now complete: commits can include multiple distinct `Add` proposals (RFC-aligned), while validation rejects invalid Add key packages, duplicate Add targets (identity/init-key), and attempts to Add an identity already in the group.
- DS-backed integration coverage now includes stage-key stability across persisted state reload + `fetch-and-apply-latest` replay/no-op sync behavior and across a multi-epoch commit chain.
- DS-backed integration tests were rebaselined for strict Task 13 DS guards (malformed proposal/commit/path submits now reject at submission time); `tests/ds_fetch_apply_e2e.rs` currently passes end-to-end (`42 passed`).
- Task 15 is complete with an RFC conformance matrix test suite in `tests/rfc_conformance_matrix.rs` covering deterministic vectors and negative matrices for MLS wire decode, proposal encodings, transcript/confirmation/membership derivations, and key-schedule transition/decode guards.
- Task 15 now also includes deterministic `AuthenticatedContent` vectors in `src/authenticated_content.rs` covering framing bytes, signing-input digest, signature-byte stability (length + digest), encoded-content digest, and membership-tag bytes.
- Task 15 now includes deterministic full-byte payload vectors for `PublicMessage`/`PrivateMessage` and `MLSMessage` wrappers in `src/mls_wire.rs`, not just decode-negative cases.
- Task 15 now includes deterministic full encoded `AuthenticatedContent` decode fixtures (`tests/vectors/authenticated_content_untagged.bin`, `tests/vectors/authenticated_content_tagged.bin`) with fixed SHA3-256 byte-stability checks in unit tests.
- Task 15 now stores wire-level deterministic binary fixtures for `PublicMessage`/`PrivateMessage` and wrapper `MLSMessage` payloads under `tests/vectors/*message_vector.bin`, and `src/mls_wire.rs` tests validate exact bytes + fixed SHA3-256 digests.
- Task 15 now stores deterministic envelope binary fixtures under `tests/vectors/*_envelope_vector.bin` (`proposal`, `commit`, `path_update`), and `src/envelope.rs` tests validate exact bytes + fixed SHA3-256 digests + decode/re-encode stability.
- Task 15 now also includes fixture-hash manifest validation (`tests/vectors/MANIFEST.sha3`, `tests/vector_manifest.rs`), malformed envelope fixture corpus (`tests/vectors/malformed/*`), and DS-backed fixture byte-stability round-trip verification (`tests/ds_fetch_apply_e2e.rs`).
- Part 8 Task 7 is complete: DS bootstraps deterministic `admin/admin@123`, exposes signed admin-only list APIs (`/v1/admin/users`, `/v1/admin/groups`), and UI gateway includes an admin panel at `/ui/admin`.
- Part 8 Task 8 is complete: admin demo index now supports list/create/open flows; demos are persisted under `ui-state/demo/<id>` with index/manifest metadata.
- Part 8 Task 9 is complete: admin demo page now uses a two-pane layout (left actions/logs split, right tree panel) with responsive behavior and demo metadata loading.
- Part 8 Task 10 is complete: admin demo Add/Remove/Update actions are wired end-to-end with persisted deterministic state transitions (epoch advance, member set changes, key-generation increments).
- Part 8 Task 11 is complete: admin demo now records timestamped MLS-style logs for init/Add/Remove/Update with separator lines (`--------------------`) and persists them in per-demo state.
- Part 8 Task 12 is complete: admin demo persistence is enforced end-to-end (state survives UI reload/restart, new demos start clean with A-only baseline, and missing-demo actions fail closed without creating orphan state).
- Review note (2026-02-19): earlier admin demo versions used a simplified member-list model and star renderer; Part 11 migrated this to explicit tree topology + binary render.
- Part 11 Task 1 is complete: admin demo state now persists explicit topology as `leaf_slots` (`Vec<Option<...>>`) with legacy `members`-state migration, and demo detail API now exposes derived `leaf_count`/`node_count`.
- Part 11 Task 2 is complete: admin demo Add placement is now explicit and test-backed (`reuse leftmost blank leaf` before any tree extension), with integration coverage asserting stable leaf indices and width when blank reuse is possible.
- Part 11 Task 3 is complete: admin demo Remove behavior now uses explicit blank+trim semantics (blank target leaf, truncate only right-edge blank leaves, no leaf compaction/reindex), with strict unit and DS-backed integration tests.
- Part 11 Task 4 is complete: admin demo tree panel now renders a real left-balanced binary topology (parent-child edges, internal nodes, blank leaves, and topology-derived leaf/node counts) instead of root-to-all star rendering.
- Part 11 Task 5 is complete: tree labels now explicitly present both LeafIndex and NodeIndex in-node (`Lx/Ny` for leaves, `Ny` for parents), and legend text now clarifies index semantics and the even-node leaf rule.
- Part 11 Task 6 is complete: admin demo logs now use RFC-style operation wording (`RFC9420 Proposal Add/Remove/Update`, `RFC9420 RatchetTree`, `RFC9420 Path Update`, `RFC9420 Commit`) with explicit `LeafIndex`, `NodeIndex`, and `GroupContext.epoch` transitions.
- Added DS-backed UI regression coverage for admin demo tree label behavior after add/remove chains, asserting root/blank label markers remain present while a non-tail remove preserves a blank leaf slot in topology state.
- Part 11 Task 7 is complete: regression coverage now includes binary-topology index invariants (left-balanced node index rules, even/odd leaf/parent mapping, unique node IDs) and DS-backed epoch-chain index stability checks across Add/Update/Remove/Add flows.
- Part 11 Task 8 is complete: legacy admin-demo `members` state migration is now hardened with validation (reject duplicate legacy `leaf_index` and empty usernames) plus DS-backed migration integration coverage that verifies legacy detail load + rewrite to new `leaf_slots` schema after action apply.
- Admin UI page access is now server-guarded: `/ui/admin` and `/ui/admin/demos/:id` require an active admin UI session (cookie + local session state), and non-admin access redirects to `/ui/login`.
- Login UX now routes admin users directly to `/ui/admin` (non-admin users continue to `/ui/groups`).
- Admin demo tree visualization is now significantly enlarged for readability: the demo page uses a wider panel, a right-heavy 3x-style layout ratio, larger node circles/fonts, and taller tree canvas spacing so `LeafIndex`/`NodeIndex` labels are easy to read.
- Q/A coverage in `QUESTIONS.md` now explicitly documents client-side group state fields, DS persisted data model, and admin-demo Add semantics (simulation vs real DS user creation), with code pointers.
- Client-state example snapshots for `ratchet_tree`, `group_context_extensions`, `key_schedule`, and `transcript_state` are now documented in assistant guidance with direct struct references for inspection (`src/client_state.rs`, `src/tree.rs`, `src/key_schedule.rs`, `src/transcript.rs`).
- Assistant guidance now also includes code-level flow notes for: why `ParentNode.parent_hash` exists, where root/epoch secrets are derived in key schedule, and how Add + PathUpdate changes tree keys and receiver-derived path secrets.
- Tree helper alignment fix: `RatchetTree::direct_path`, `copath`, and `filtered_direct_path` now expose leaf-to-root ordering (matching RFC direct-path semantics), with regression tests in `src/tree.rs`.
- Warning debt cleanup: removed dead code `not_implemented` helper in `src/ds/http.rs`; `cargo check` now runs clean with no warnings.

**Architecture**
- `src/crypto.rs` implements hybrid KEM, hybrid signatures, serialization helpers, and HPKE-style path secret encryption.
- `src/tree.rs` implements the ratchet tree, parent hashes, node resolution, proposals/commits, and path update logic.
- `src/key_schedule.rs` implements persisted epoch-secret tree state used to track per-epoch root secrets and derive epoch-level handshake/application/exporter secrets.
- `src/key_schedule.rs` now also persists and exposes chain secrets per epoch (`commit`, `joiner`, `welcome`, `epoch`, `root`) plus a per-epoch `group_context_hash`; decode remains backward-compatible with older key-schedule payloads.
- `src/stage_keys.rs` implements explicit per-epoch stage-key helpers (`confirmation_key`, `membership_key`, `sender_data_key`) derived from `epoch_secret` for tag/sender-data alignment work.
- `src/mls_wire.rs` implements RFC-style wire model skeletons for `MlsMessage`, `PublicMessage`, and `PrivateMessage` with strict framing/codec checks.
- `src/application_message.rs` implements RFC-style `PrivateMessage` application payload protection/deprotection (sender-data encryption + ciphertext AAD binding) using key-schedule-derived `sender_data_key` and `application_secret`.
- `src/authenticated_content.rs` implements `AuthenticatedContent` framing/signature scaffolding over `PublicMessage`, including sign/verify, strict codecs, and envelope conversion helpers.
- Membership tag verification is now implemented in authenticated-content scaffolding (`derive_membership_key`, `derive_membership_tag`, `verify_with_membership_tag`) with canonical signature input that excludes membership-tag bytes from signature material; membership key derivation now uses key-schedule `epoch_secret` stage input.
- `src/transcript.rs` implements confirmed/interim transcript hash state and update helpers for proposal/commit-driven transcript progression.
- Confirmation-tag verification is now wired into Welcome handling: sender computes `GroupInfo.confirmation_tag` from `(confirmation_key, confirmed transcript hash)` where `confirmation_key` is derived from key-schedule `epoch_secret`, and joiner validates it during Welcome processing.
- `src/welcome.rs` implements RFC-style Welcome wire structures/codecs (`Welcome`, `EncryptedGroupSecrets`, `GroupSecrets`, `GroupInfo`) with strict decode behavior.
- `src/welcome.rs` now also provides hybrid HPKE-style Welcome secret protection (`EncryptedGroupSecrets::encrypt_for_recipient` / `decrypt_group_secrets`) bound to group+epoch+key-ref context.
- Committer flows now generate Welcome payloads when a commit includes `Add` proposals (`ds_client create-commit` and UI `commit-from-pending`).
- DS transport now persists Welcome payloads as `kind=welcome` via commit submission (`welcome_bytes`) and allows signed list/fetch using `kind=welcome`.

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
5. Derivation inputs now use `MLS 1.0`-style labeled framing (label + structured context) for path/KEM/AEAD key schedule inputs.

Path update payloads are now serializable via `PathUpdate::encode()` and can be attached to commits with `Commit::encode_with_path_update(...)`.
Receivers can apply a commit and consume a path update in one step via `RatchetTree::apply_commit_with_path_update(...)`.
`PathUpdate::decode(...)` and `PathSecretCiphertext::decode(...)` are available for parsing received payloads.
`Commit::decode(...)` and `Commit::decode_with_path_update(...)` parse commit payloads and (optionally) attached path updates.
Unit tests now cover commit encode/decode round-trips with and without path update payloads.

Unit tests now cover `apply_commit_with_path_update` for both success and wrong-leaf failure cases.
Negative tests now cover tampered path payload bytes, tampered KEM ciphertext bytes, and malformed path level ciphertext counts.
Malformed decode tests now cover truncated and trailing bytes for `CommitEnvelope`, `PathUpdateEnvelope`, `Commit::decode`, `Commit::decode_with_path_update`, and `PathUpdate::decode`.
Field-level malformed tests now cover `PathSecretCiphertext::decode` rejection for wrong classic-key length, wrong PQ ciphertext length, and corrupted `PathUpdate` level-count structures.

**RFC 9420 Mapping (Short Note)**
- RFC concept: `KDF.Extract` / `KDF.ExpandWithLabel` with `MLS 1.0` label framing.
- Current implementation: uses SHA3-based derivation, but now applies `MLS 1.0`-style labeled input framing so label/context separation follows the RFC spirit.
- RFC concept: direct-path `path_secret` evolution and node-secret derivation across epochs.
- Current implementation: `derive_path_secret` now uses labeled context framing keyed by parent index and level to model direct-path secret evolution.
- RFC concept: HPKE context binding for path secret encryption.
- Current implementation: per-recipient path encryption context is labeled and structured by sender leaf, parent node, and recipient node before hybrid KEM + AEAD.
- Important: this is a compatibility-oriented mapping note, not full wire-level RFC equivalence yet (the backend remains prototype hash-based, not full RFC ciphersuite HKDF schedule).

**RFC 9420 Label Mapping (Compact)**

| Current Implementation Label | Where Used | Target RFC Label/Term | RFC 9420 Section | Notes |
| --- | --- | --- | --- | --- |
| `hybrid kem shared secret` | Hybrid combiner KDF in `src/crypto.rs` | `KDF.Extract` + `ExpandWithLabel` pipeline (no single fixed label) | Section 8 | Hybrid combiner is project-specific; aligns to RFC key-schedule role, not an exact RFC label. |
| `hpke key` | AEAD key derivation for path-secret payload encryption | `EncryptWithLabel(..., "UpdatePathNode", group_context, ...)` key schedule role | Sections 5.1.3, 7.6 | Internal label approximates HPKE context separation; target on-wire label is `"UpdatePathNode"`. |
| `hpke nonce` | AEAD nonce derivation for path-secret payload encryption | `EncryptWithLabel(..., "UpdatePathNode", group_context, ...)` nonce schedule role | Sections 5.1.3, 7.6 | Internal label approximates HPKE context separation; target on-wire label is `"UpdatePathNode"`. |
| `derive path secret` | `derive_path_secret` hash label in `src/tree.rs` | `DeriveSecret(path_secret[n-1], "path")` and `DeriveSecret(path_secret[n], "node")` chain | Sections 7.6, 8 | Current prototype collapses path/node derivation into one helper; RFC distinguishes `"path"` and `"node"` labels. |
| `path secret derivation` | Context label for direct-path secret evolution | Generation/position context for tree derivation | Section 9.1 | Current context uses `(parent_index, level)`; RFC tree-ratchet context is generation-based (`uint32`, big-endian). |
| `path secret encryption` | Context label for per-recipient path ciphertext KEM+AEAD | `EncryptWithLabel` context = provisional `GroupContext` | Section 7.6 | Current context is structural tuple `(sender,parent,recipient)`; RFC target is full provisional `GroupContext`. |

**RFC 9420 Context-Input Mapping (Task 11)**

| Current Context Input | Current Use | RFC 9420 Closest Term | RFC Section | Alignment Status |
| --- | --- | --- | --- | --- |
| `group_context_hash` (stored per epoch in `KeyScheduleState`) | Derivation context for epoch-derived secrets and stage keys | `GroupContext` binding in epoch/key schedule and transcript-linked context | Sections 8, 8.1, 8.2, 9.1 | Partial: uses hashed compact binding of `(group_id, epoch, tree_hash, commit_context)` instead of full encoded RFC `GroupContext`. |
| `confirm` stage-key context input | Input to confirmation key used for `confirmation_tag` derivation/verification | `confirmation_key` / confirmation tag path derived from epoch schedule | Sections 8.2, 8.3 | Partial: key role is aligned; derivation primitive remains project SHA3-labeled scheme (not RFC ciphersuite HKDF). |
| `membership` stage-key context input | Input to membership key for `membership_tag` verification | `membership_key` used for `membership_tag` in PublicMessage auth | Sections 7.2, 8.2 | Partial: key role and API usage align; derivation primitive differs from RFC HKDF schedule. |
| `sender_data` stage-key context input | Input for sender-data protection in private application message flow | `sender_data_secret` / sender-data encryption context in PrivateMessage | Sections 6.3, 8.2 | Partial: sender-data/context-bound private-message protection is implemented; full RFC sender ratchet/generation/nonces remain future hardening work. |

**RFC 9420 Welcome Mapping (Compact)**

| Current Object | RFC 9420 Term | RFC Section |
| --- | --- | --- |
| `welcome::Welcome` | `Welcome` wire struct (`version`, `cipher_suite`, `secrets`, `encrypted_group_info`) | Section 12.4.1 |
| `welcome::EncryptedGroupSecrets` | `EncryptedGroupSecrets` wire struct (`new_member`, `encrypted_group_secrets`) | Section 12.4.2 |
| `welcome::GroupSecrets` | `GroupSecrets` payload (`joiner_secret`, optional `path_secret`, `psk_ids`) | Section 12.4.3.1 |
| `welcome::GroupInfo` | `GroupInfo` payload carried in `encrypted_group_info` | Section 12.4.3.2 |
| `build_welcome_for_commit` derivations | `joiner_secret` / welcome key-schedule linkage | Section 8.4 + Section 12.4.3 |

Hybrid note: this project keeps RFC field semantics but uses the project’s hybrid KEM/signature stack for protection/signing.

**Build and Test**
```bash
cargo check
cargo test
```

Receiver-side commit/path integration test (two client states):
```bash
cargo test --test commit_path_two_client_states
```

DS-backed end-to-end sync integration test (`fetch-and-apply-latest`):
```bash
cargo test --test ds_fetch_apply_e2e
```
This suite now includes replay safety, strict-path negative cases, and a DS-backed 3-member cryptographic commit-chain sync test.
It now also includes a DS-backed membership-change chain (`A adds C -> B update -> A removes C`) with final convergence checks for surviving members.
It now also includes DS-backed malformed payload submission coverage: malformed commit bytes are skipped without state advance, and malformed path-update bytes trigger strict receiver rejection.
It also includes malformed proposal payload sync-impact coverage: malformed proposals alone do not advance sync state, and malformed proposal traffic does not block valid commit synchronization.
It now includes a CLI-driven Welcome transport integration case: submit commit+path+welcome and verify DS `list-messages --kind welcome` returns the stored Welcome record.
It now includes a DS-backed Welcome payload stability test that verifies submit/fetch round-trip returns byte-identical Welcome payloads.
It now includes negative auto-bootstrap coverage for Welcome-first sync: wrong base members, wrong receiver private key, and tampered Welcome payload are all rejected.
It now includes DS-backed mixed-proposal-batch coverage for `PreSharedKey` commits: `Update+PSK` and `Remove+PSK` commit batches are submitted over HTTP and applied via `fetch-and-apply-latest`.
It now includes a DS-backed `ReInit` proposal flow test where a `ReInit` commit is created, submitted, and synced/applied end-to-end.
It now includes a DS-backed mixed-proposal-batch `Update+GroupContextExtensions` flow that verifies receiver convergence and persisted group-context extensions update.
It now includes DS-backed negative proposal-matrix coverage for invalid commit proposal sets: duplicate `GroupContextExtensions`, `ReInit+GroupContextExtensions` conflict, duplicate `ReInit`, and unsupported `ReInit` params (version/cipher suite) are rejected on receiver sync/apply.

Deterministic key-schedule vectors (fixed inputs/expected outputs):
```bash
cargo test --lib deterministic_vector_alpha_matches_expected
cargo test --lib deterministic_vector_beta_matches_expected
```
These lock `init_secret`, `root_secret`, and derived `handshake/application/exporter` values to catch accidental derivation drift.

Deterministic Welcome vectors:
```bash
cargo test --lib deterministic_vector_group_secrets_encoding_matches_expected
cargo test --lib deterministic_vector_welcome_encoding_matches_expected
cargo test --bin ds_client deterministic_vector_welcome_joiner_secret_matches_expected
```
These lock Welcome-related wire bytes/hash and joiner-secret derivation behavior to catch accidental drift in onboarding flow.

MLS wire model tests:
```bash
cargo test --lib mls_wire::tests
```
These cover strict public/private wire framing, round-trip encoding, envelope conversions, and malformed decode rejection.

Authenticated content tests:
```bash
cargo test --lib authenticated_content::tests
```
These cover `AuthenticatedContent` sign/verify, round-trip codec behavior, tamper/trailing-byte rejection, and hash behavior (authenticated-content hash with payload-hash fallback).
They now also cover membership-tag generation/verification and tamper rejection.

Transcript pipeline tests:
```bash
cargo test --lib transcript::tests
```
These cover transcript state round-trip, proposal/commit hash progression, and deterministic transcript vectors.

**Example Program**
Run a minimal in-memory flow (group creation + Add commit + path update processing):
```bash
cargo run --example minimal
```
This runs an in-memory flow and prints the derived path secrets on the receiver side. The example is deterministic and not production-safe.

**How to Use (Conceptual Flow)**
The repository now includes a DS server binary and a DS client CLI. The typical MLS flow is:
1. Each client generates a `KeyPackage`.
2. A group creator builds a `Commit` with `Add` proposals and a path update.
3. The commit is distributed to all members, who update their local ratchet trees.

**Run Delivery Service**
```bash
cargo run --bin ds_server
```

**UI Skeleton (DS)**
Visit the DS-hosted placeholder pages:
```bash
http://127.0.0.1:3000/ui/login
http://127.0.0.1:3000/ui/groups
```
These pages are placeholders and do not sign requests.

**UI Gateway (Signed Requests)**
Run the local UI gateway to generate hybrid signatures and forward signed requests to the DS:
```bash
cargo run --bin ds_ui_gateway
```
Then open:
```bash
http://127.0.0.1:4000/ui/login
```
The gateway stores per-user signing material in `./ui-state` by default.
It signs requests locally and forwards them to the DS.
The UI now includes group and app message list/fetch views with per-kind filters for group messages.

Quick UI test:
1. Run `cargo run --bin ds_server`.
2. Run `cargo run --bin ds_ui_gateway`.
3. Open `http://127.0.0.1:4000/ui/login`, register/login, add a group id, and use the group page to list/fetch messages and app messages.
The UI now provides logout on all pages and a KeyPackage library panel on the groups page.
The groups page supports a one-click Generate + Publish KeyPackage action (stores receiver private locally), plus list/copy/publish actions for stored keypackages.
Advanced manual KeyPackage publish remains available under the expandable section.
Group lists now support filter/search, refresh, and forget actions; opening a group auto-tracks it locally.
Group pages now include an Actions menu to create Add/Remove/Update proposals using local group state.
Action flows require a local `ClientGroupState` file at `ui-state/user-<name>-group-<group>.bin` (create via `ds_client bootstrap-group-state` or `join-from-commit`).
Group pages also include a Tree Structure panel that renders the local ratchet tree nodes (leaf/parent/blank) with short key fingerprints.
If the tree view says the group state file is missing, create or import the local group state first; the UI now shows a clearer error message for that case.
UI cards, inputs, and buttons now use consistent sizing and spacing with responsive stacking on smaller screens.
List Messages, Send App Message, and Submit Proposal panels now use the same shadowed card styling and full-width controls for consistent sizing.
Logout is now a fixed top-left action on all UI pages and always returns to `/ui/login`.
All UI controls now share a single fixed height via CSS (`--control-height`) for uniform sizing.
Spacing across panels is now driven by shared CSS spacing tokens (`--space-*`) for consistent layout.
Card content spacing now uses `--space-md` to keep inner element spacing uniform.
Card panels now use `align-content: start` with `grid-auto-rows: min-content` to avoid stretched gaps between inner elements.
KeyPackage fields in the Actions panel now show a short preview by default; users can expand to view the full base64 in a fixed-size textarea.
UI containers now enforce `min-width: 0` and `max-width: 100%` to prevent long base64 values from stretching the layout.
The UI now auto-bootstraps a one-member local group state when you click “Add Group,” so the tree view can render a single creator leaf immediately.
UI pages now include a Back button with browser-history fallback (`/ui/groups` or `/ui/login`).
The tree section now includes both:
- a textual node list
- an SVG binary-tree graph (circles + links) rendered from local ratchet tree topology
Leaf labels use known usernames when available (own leaf and locally mapped added keypackages), otherwise fallback labels like `leaf-<index>`.
Important MLS flow note: `Add` proposal does not make a user a member by itself. A `Commit` containing that proposal must be created and applied before the added user can join/sync.
For an added user (for example Peyman), visibility is commit-driven: after creator submits Add and Commit, the added user must run `Sync + Apply Latest` with receiver private material; only then local state reflects membership and the group appears in that user’s tracked list.
Troubleshooting: if the added user still sees no group, check that the user has a local tracked group entry and a valid local group-state baseline for that group. Current UI sync operates on locally tracked groups and does not yet auto-discover/join unknown groups solely from DS message history.
Troubleshooting (Admin Demo): if admin sees no demos, first create one from `/ui/admin` (demos are not pre-seeded). Demo records are stored in UI gateway local state (`DS_UI_STATE_DIR`, default `./ui-state/demo`), so using a different working directory or state dir shows a different/empty demo list.
The group Actions panel now includes `Create + Submit Commit` to build a real commit from local pending proposals and submit it to DS in one step.
The same panel now includes `Sync + Apply Latest` to fetch DS commits/path updates and apply them into local `ClientGroupState`, so newly added members can materialize membership after commit publication.
The same panel now also includes `Join from latest Welcome` for joiner onboarding when local group state does not exist yet.
Joiner onboarding expects `Onboarding base members` as comma-separated usernames in pre-commit leaf order (for example `parsania` in a one-member base tree) and uses the joiner receiver-private file to locate a valid DS `welcome+commit+path_update` tuple.
UI bootstrap now publishes the creator bootstrap KeyPackage to DS and stores the matching receiver-private material locally so joiner onboarding has a DS-visible base member key package source.
`Sync + Apply Latest` can auto-pick the latest locally stored receiver-private file from the user keypackage library, or accept a manual receiver-private path.
The group page top bar now also includes a quick `Sync + Apply Latest` button next to logout.
After login/refresh, UI now auto-runs sync: groups page syncs all tracked groups once, and group detail page auto-syncs current group once.
Action proposals are dual-tracked by design: they are submitted to DS and queued locally as pending proposals until a commit is created.
DS signature/keypackage verification now runs on a dedicated large-stack worker thread to avoid Tokio worker stack overflows during hybrid ML-DSA verification in local demos.
UI gateway proposal flow now also runs keypackage decode/verify, group-state load/save, signing-key decode, and message signing in dedicated large-stack workers to prevent stack overflows on Add/Update proposal submission.
There is now an end-to-end UI+DS test in `src/bin/ds_ui_gateway.rs` covering: register two users, creator bootstrap, publish/fetch keypackage, Add proposal, Commit creation, receiver sync/apply, and group visibility persistence after logout/login.
Part 8 in `PROJECT.md` tracks the upcoming UI and admin-demo roadmap.
KeyPackage publishing does not require a group; a user can publish a KeyPackage before being added to a group.
Private keys are currently stored locally in files (CLI state and keygen outputs, plus UI gateway `./ui-state`), suitable only for local testing.

Gateway environment variables:
- `DS_UI_BIND` (default `127.0.0.1:4000`)
- `DS_GATEWAY_BASE_URL` (default `http://127.0.0.1:3000`)
- `DS_UI_STATE_DIR` (default `./ui-state`)

Optional environment variables:
- `DS_BIND` (default `127.0.0.1:3000`)
- `DS_DATA_DIR` (default `./data`)
- `DS_DB_PATH` (default `${DS_DATA_DIR}/ds.sqlite`)
- `DS_MAX_BYTES`
- `DS_MIN_PROPOSALS_PER_COMMIT`
- `DS_SESSION_TTL_SECS`
- `DS_SESSION_MAX_PER_USER`

**Local 1-DS / 4-Client Startup Scripts**
```bash
scripts/local-1ds-4clients-up.sh
scripts/local-1ds-4clients-status.sh
scripts/local-1ds-4clients-down.sh
scripts/local-1ds-4clients-demo.sh
```

Environment variables supported by the scripts:
- `DS_BIND`, `BASE_URL`
- `RUN_DIR`, `RESET`, `SKIP_BUILD`
- `CLIENT_NAMES`, `CLIENT_PASSWORD`
- `WAIT_SECONDS`, `CLEAN`

Demo script details:
- `scripts/local-1ds-4clients-demo.sh` runs a full local scenario with fresh reset and per-step logs.
- Default run directory is visible (not hidden): `local-1ds-4clients-demo-run`.
- It forces `DS_MIN_PROPOSALS_PER_COMMIT=1` for demo flow.
- It uses its own fresh reset and calls `up.sh` with `RESET=0` to preserve demo artifact directories (`key-material`, `group`).
- It executes:
  1. A adds B
  2. A key update
  3. B adds C
  4. A removes C
- Logs are written under `RUN_DIR/logs` (`demo.log`, `demo-alice.log`, `demo-bob.log`, etc).

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

**Delivery Service Session Hardening (Current)**
- DS endpoints now enforce session-aware auth (`session_id` + signature + username binding).
- Expired sessions are rejected and cleaned up; login purges stale sessions; logout endpoint is available.
- Session TTL and per-user session rotation limits are configurable (`DS_SESSION_TTL_SECS`, `DS_SESSION_MAX_PER_USER`).
- Signed-request checks are applied across proposal/commit submit, message list/fetch, app-message flows, and keypackage publish/fetch.
- `ds_client` now persists `session_id`, sends it on authenticated requests, and supports `logout`.
- DS-backed integration coverage (`tests/ds_fetch_apply_e2e.rs`) passes for session/misuse/replay/strict-receiver scenarios.

**Delivery Service Client CLI (New)**
The CLI is a prototype tool to register users, submit proposals/commits, and fetch messages from the DS.
Client-side `ClientGroupState` persistence is now available in `src/client_state.rs` (group id, ratchet tree, epoch, own leaf index, pending proposals, and persisted `group_context_extensions`).
Wire-format metadata envelopes are now available in `src/envelope.rs` for proposal/commit/path payloads (`group_id`, `epoch`, `sender_leaf`).
Client group persistence now includes `KeyScheduleState` (epoch-secret nodes + current epoch root secret) and upgrades automatically from older state formats.
`KeyScheduleState` now derives `EpochDerivedSecrets` (`handshake_secret`, `application_secret`, `exporter_secret`) per epoch with label-separated MLS-style inputs.

Example usage:
```bash
cargo run --bin ds_client -- register --base-url http://127.0.0.1:3000 --username alice --password secret
cargo run --bin ds_client -- login --base-url http://127.0.0.1:3000 --username alice --password secret
cargo run --bin ds_client -- keygen --out /path/to/alice-kem.json
cargo run --bin ds_client --state /path/to/alice-client.json -- keypackage-export --kem-file /path/to/alice-kem.json --keypackage-out /path/to/alice.kp --receiver-private-out /path/to/alice-recv.json
cargo run --bin ds_client -- bootstrap-group-state --group-id group1 --member-keypackage /path/to/alice.kp --member-keypackage /path/to/bob.kp --own-leaf 0 --out /path/to/alice-group-state.bin
cargo run --bin ds_client -- join-from-commit --base-member-keypackage /path/to/alice.kp --commit-file /path/to/commit.bin --path-update-file /path/to/path-update.bin --receiver-private-file /path/to/bob-recv.json --out /path/to/bob-group-state.bin
cargo run --bin ds_client -- join-from-welcome --base-member-keypackage /path/to/alice.kp --commit-file /path/to/commit.bin --path-update-file /path/to/path-update.bin --welcome-file /path/to/welcome.bin --receiver-private-file /path/to/bob-recv.json --out /path/to/bob-group-state.bin
cargo run --bin ds_client --state /path/to/alice-client.json -- fetch-and-apply-latest --group-state /path/to/alice-group-state.bin --receiver-private-file /path/to/alice-recv.json --limit 100
cargo run --bin ds_client --state /path/to/bob-client.json -- fetch-and-apply-latest --group-state /path/to/bob-group-state.bin --group-id group1 --base-member-keypackage /path/to/alice.kp --receiver-private-file /path/to/bob-recv.json --limit 100
cargo run --bin ds_client --state /path/to/alice-client.json -- fetch-and-apply-latest --group-state /path/to/alice-group-state.bin --receiver-private-file /path/to/alice-recv.json --watch --poll-interval-ms 2000
cargo run --bin ds_client -- submit-proposal --base-url http://127.0.0.1:3000 --group-id group1 --proposal-file /path/to/proposal.bin
cargo run --bin ds_client -- submit-commit --base-url http://127.0.0.1:3000 --group-id group1 --commit-file /path/to/commit.bin --path-update-file /path/to/path.bin --welcome-file /path/to/welcome.bin
cargo run --bin ds_client -- list-messages --base-url http://127.0.0.1:3000 --group-id group1 --limit 50 --kind commit
cargo run --bin ds_client -- publish-key-package --base-url http://127.0.0.1:3000 --keypackage-file /path/to/keypackage.bin
cargo run --bin ds_client -- fetch-key-package --base-url http://127.0.0.1:3000 --target alice --out /path/to/keypackage.bin
cargo run --bin ds_client -- send-app-message --base-url http://127.0.0.1:3000 --group-id group1 --message-file /path/to/message.bin
cargo run --bin ds_client -- list-app-messages --base-url http://127.0.0.1:3000 --group-id group1 --limit 50 --before-id 100
cargo run --bin ds_client -- fetch-app-message --base-url http://127.0.0.1:3000 --group-id group1 --message-id 123 --out /path/to/message.bin
cargo run --bin ds_client -- create-add-proposal --group-state /path/to/group-state.bin --keypackage-file /path/to/new-member.kp --out /path/to/add.proposal.bin
cargo run --bin ds_client -- create-update-proposal --group-state /path/to/group-state.bin --keypackage-file /path/to/new-self.kp --out /path/to/update.proposal.bin --target-leaf 1
cargo run --bin ds_client -- create-remove-proposal --group-state /path/to/group-state.bin --remove-leaf 2 --out /path/to/remove.proposal.bin
cargo run --bin ds_client -- create-commit --group-state /path/to/group-state.bin --commit-out /path/to/commit.bin --path-update-out /path/to/path-update.bin --welcome-out /path/to/welcome.bin
cargo run --bin ds_client -- apply-received-commit --group-state /path/to/group-state.bin --commit-file /path/to/commit.bin --path-update-file /path/to/path-update.bin --receiver-private-file /path/to/receiver-private.json --derived-out /path/to/derived.json
cargo run --bin ds_client -- show-derived-secrets --group-state /path/to/group-state.bin --epoch 2 --include-root --out /path/to/epoch2-secrets.json
```
The client stores signing keys in `ds-client.json` by default and can now:
- Generate KEM key material (`keygen`) for X25519 + ML-KEM.
- Export a signed MLS `KeyPackage` plus receiver private material (`keypackage-export`) using client identity keys from `--state`.
- Bootstrap initial local group state from ordered member key packages (`bootstrap-group-state`).
- Join a group as a newly-added member from commit/path payloads (`join-from-commit`), with optional automatic leaf detection from receiver private key.
- Join a group as a newly-added member with Welcome validation (`join-from-welcome`), which checks decryptable `GroupSecrets`, validates Welcome `GroupInfo` against reconstructed local state (`group_id`, `epoch`, `tree_hash`, `signer_leaf`), and then persists state.
- Sync and apply DS commits automatically (`fetch-and-apply-latest`) by listing commit/path update messages, fetching payload bytes, and applying in epoch order.
- `fetch-and-apply-latest` can now bootstrap an unknown local group state from DS Welcome stream when `--group-state` does not exist (requires `--group-id`, `--base-member-keypackage`, and `--receiver-private-file`).
- Build metadata-enveloped proposals from `ClientGroupState` files.
- Build a commit + path update from queued pending proposals (`create-commit`), write commit/path envelopes to disk, generate a Welcome payload when Add proposals are present, apply the commit locally, clear pending proposals, and increment the local epoch.
- Submit commit transport now supports optional Welcome payload upload (`submit-commit --welcome-file ...`), and DS group-message listing accepts `kind=welcome`.
- Apply received commit/path envelopes on receivers (`apply-received-commit`) with metadata checks (`group_id`, `epoch`, `sender_leaf`) and optional path-secret derivation.
- Inspect epoch key-schedule outputs for demos with `show-derived-secrets` (chain + epoch fields: commit/joiner/welcome/epoch/handshake/application/exporter and optional root secret).
- Epoch transitions now also advance persisted key-schedule state (`KeyScheduleState`) using commit-context inputs.
This is for development only.

KEM keygen file format (`keygen --out ...`):
```json
{
  "classic_x25519_private_b64": "<base64-32-byte-x25519-private>",
  "classic_x25519_public_b64": "<base64-32-byte-x25519-public>",
  "pq_kem_seed_b64": "<base64-64-byte-ml-kem-seed>",
  "pq_kem_public_b64": "<base64-ml-kem-public>"
}
```

Receiver private file format for `apply-received-commit`:
```json
{
  "classic_x25519_private_b64": "<base64-32-byte-x25519-private>",
  "pq_kem_seed_b64": "<base64-64-byte-ml-kem-seed>"
}
```

Group bootstrap notes:
- `--member-keypackage` order defines initial leaf indices in the ratchet tree.
- `--own-leaf` must point to your own entry in that ordered list.

Joiner onboarding notes:
- `join-from-commit` expects base pre-commit members via `--base-member-keypackage` (ordered by leaf index before the add commit).
- If `--own-leaf` is omitted, the CLI tries to infer it by matching receiver private key to a leaf public key after commit apply.
- Welcome generation and transport are implemented; CLI has `join-from-welcome`, and UI `join-from-latest` now performs Welcome-first onboarding with commit/path material matching and Welcome validation.

Sync notes:
- `fetch-and-apply-latest` requires a DS account state in `--state` for request signing.
- It applies only commits matching the local epoch sequence and stops on gaps.
- For unknown groups, it can auto-bootstrap from Welcome before normal commit/path apply; when no decryptable Welcome is found, non-watch mode fails closed.
- Sync now validates commit envelope metadata strictly (`group_id`, `epoch`, `sender_leaf`) before apply and skips malformed/non-matching records.
- DS commit/path message IDs are sorted, deduplicated, and sanitized before processing.
- Path updates are selected by metadata match to the commit (not only by neighboring message ID).
- Replay protection markers are now persisted in `ClientGroupState` (`last_applied_commit_id` + bounded recent commit ID window), so already-applied/older DS commits are skipped across restarts.
- Replay-skip behavior assumes DS message IDs are monotonic for a given deployment.
- Sync stops the current poll pass when it encounters a future-epoch commit (gap), preventing out-of-order epoch application.
- Strict key-schedule consistency is now enforced on load/save and after each commit-apply path: local state is rejected if key-schedule epoch diverges from group epoch or if the epoch-chain structure is malformed.
- DS-backed sync integration now includes tampered local-state rejection cases: epoch-mismatch tamper before sync and malformed parent-link tamper between commits both fail closed at client load/apply.
- Strict receiver policy: when `--receiver-private-file` is provided to `fetch-and-apply-latest`, a matching path update is required for each commit; missing/mismatched path update aborts sync.
- DS-backed integration coverage now includes strict receiver rejection for both missing path updates and mismatched path-update metadata.
- DS-backed integration coverage now includes malformed payload handling over HTTP: malformed commit payloads are skipped, malformed path-update payloads are rejected under strict receiver policy.
- DS-backed integration coverage now includes malformed proposal payload sync-impact assertions (no-commit no-op and valid-commit sync unaffected).
- DS-backed integration coverage now includes a 3-member commit chain (`A update -> B/C sync -> B update -> A/C sync`) with convergence checks across all members.
- DS-backed integration coverage now includes a 3-member Add/Update/Remove chain (`A adds C -> B updates -> A removes C`) with final convergence checks for remaining members.
- Unit tests now cover derivation context binding for hybrid path secret encryption and tree path-secret derivation labels.
- Unit tests now cover path-update metadata rejection for all mismatch types (`group_id`, `epoch`, `sender_leaf`) in CLI validation helpers.
- Unit tests now cover malformed envelope/payload decode rejection for commit/path structures (truncated + extra trailing bytes).
- Unit tests now cover malformed `PathSecretCiphertext` fields (wrong classic length, wrong PQ length, corrupted level counts).
- Forward-secrecy baseline tests now cover stale receiver-key failure after key rotation and removed-member rejection for future path updates.
- DS-backed forward-secrecy integration now verifies over real HTTP sync that (a) a stale receiver private key fails to apply a later commit while the rotated receiver private key succeeds, and (b) a removed member cannot apply the post-removal commit stream.
- DS-backed PCS recovery-chain integration now verifies compromise recovery behavior for both 2-member and 3-member flows, including `A adds C -> C self-update -> A next commit`, where old compromised C key fails and recovered C key succeeds.
- DS-backed misuse matrix baseline now covers invalid-signature rejection on `submit-proposal`, `submit-commit`, `list-messages`, and `fetch-group-message`, malformed commit bytes with valid envelope metadata (skipped without blocking a subsequent valid commit), replay permutations where duplicated old commits are skipped while newer epochs apply, and malformed `path_update` misuse cases that preserve envelope metadata and still trigger strict receiver rejection.
- Strict receiver policy in `apply-received-commit`: `--path-update-file` and `--receiver-private-file` must be provided together.
- If `--receiver-private-file` is provided, path updates are consumed and derived secrets can be exported via `--derived-out`.
- `--watch` enables continuous polling; use `--poll-interval-ms` and optional `--max-polls` to control loop behavior.
- `show-derived-secrets` is debug-only and intentionally exposes secret material; use only in local test/demo environments.
- Protocol flow documentation templates now live under `protocl-actions/`:
  - `protocl-actions/protocl-style.md` (template)
  - `protocl-actions/create-group-protocol.md` (code+RFC mapped example with explicit gap flags)
- Protocol flow template now enforces a `Math Action` column in flow tables so each cryptographic/state step shows its equation/primitive inputs.
- `create-group-protocol.md` now includes explicit math for state init, tree indexing, tree hash, init secret, full epoch-0 chain (`commit/joiner/welcome/epoch/root`), and derived stage/app secrets.
- TreeKEM lineage gap is now explicitly tracked in roadmap `Part 12`: current code derives/encrypts path secrets, but parent path public keys are still generated randomly in commit build path instead of being fully node-secret-derived end-to-end.
- `PROJECT.md` now includes a dedicated RFC 9420 alignment workstream to migrate sender/receiver commit-path logic to explicit `leaf_secret -> path_secret -> node_secret -> parent_key` lineage with deterministic vectors and DS-backed negatives.
- Part 12 / Task 1 is now implemented in code: explicit secret model structs (`LeafSecret`, `DirectPathSecretLevel`, `DirectPathSecretModel`) and validation invariants were added in `src/tree.rs`, and `build_path_update` now consumes the model while preserving wire behavior.
- Added `protocl-actions/treekem-secret-lineage-protocol.md` to document the current TreeKEM secret-lineage baseline, math flow, and remaining RFC-hardening gaps.
- Part 12 / Task 2 is now implemented: commit path parent public keys are deterministically derived from node secrets (`src/tree.rs`) and both CLI/UI commit builders now use this deterministic path generation instead of random parent key generation.
- Added Agent protocol rule in `agent.md`: after any auto context compaction, the agent must re-read `agent.md`, `PROJECT.md`, and recent `SESSION-LOG.md` lines (including archive fallback if needed) before continuing.
- Part 12 / Task 3 is now implemented: sender direct-path semantics now enforce an explicit node-secret transform policy (`node_secret = KDF(path_secret, parent_node, level_from_leaf)`) with invariant/domain-separation tests in `src/tree.rs`.
- Deterministic commit-path semantics changed one `ds_client` welcome vector; test fixture value was rebaselined in `src/bin/ds_client.rs`.
- Part 12 / Task 4 is now implemented: receiver commit+path apply enforces strict parent-key lineage checks by recomputing expected parent public keys from derived node secrets and rejecting mismatches.
- Added new regression test in `src/tree.rs` to assert malformed/tampered commit parent path keys are rejected under strict lineage validation.
- Part 12 / Task 5 is complete: receiver-side encoded/partial path handling now enforces per-level ciphertext-width checks across the full direct path, multi-level decrypt/reconstruct cross-checks, and strict parent-key lineage validation when encoded payloads omit `path_secrets`.
- Added DS-backed malformed encoded path-update stream negatives (`non-receiver level underflow/overflow`) in `tests/ds_fetch_apply_e2e.rs`, asserting strict receiver rejection with no epoch advance.
- Part 12 / Task 6 is complete: key schedule transitions now accept TreeKEM lineage commit-secret input via `ensure_epoch_with_tree_commit_secret` (`src/key_schedule.rs`) and this is wired from sender/receiver/joiner commit-apply paths in `src/client_state.rs`, `src/bin/ds_client.rs`, and `src/bin/ds_ui_gateway.rs`.
- Added lineage key-schedule tests in `src/key_schedule.rs` and `src/client_state.rs`, plus rebaselined deterministic welcome joiner-secret vector in `src/bin/ds_client.rs`.
- Part 12 / Task 7 is complete: deterministic TreeKEM lineage vectors are now added in `src/tree.rs` for `leaf_secret -> path_secret -> node_secret` chain values and derived parent key material across both hybrid branches (classic exact bytes + PQ key digest fixtures).
- Part 12 / Task 8 is complete: DS-backed strict-lineage coverage now includes Add/Update/Remove tamper negatives and a positive 3-member Add→Update→Remove convergence test with explicit epoch alignment and key-schedule chain-secret lineage equality/rotation assertions in `tests/ds_fetch_apply_e2e.rs`.
- Part 12 / Task 9 is now in progress with an explicit migration compatibility lane: strict lineage remains default, while legacy fallback is available via `ds_client --allow-legacy-path-compat` (apply/join/sync) and UI env toggle `DS_UI_ALLOW_LEGACY_PATH_COMPAT=1`; DS-backed test coverage now proves strict rejection + compat success for pre-lineage-style tampered Add commit artifacts.
- Part 12 / Task 9 now includes persisted per-state compat marker/version-gate: `ClientGroupState` moved to v6 with `legacy_path_compat_enabled` persisted; decoding v1-v5 states auto-enables compat marker for migration, while new v6 states default strict. Runtime compat switches now seed/toggle this per-state marker instead of being runtime-only behavior.
- Added explicit CLI policy control: `ds_client set-path-compat-policy --group-state <path> --mode strict|compat` to clear/set the persisted marker directly.

Last updated: 2026-02-24 22:41
