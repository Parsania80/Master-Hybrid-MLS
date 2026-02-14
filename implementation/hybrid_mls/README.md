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
- `src/key_schedule.rs` implements persisted epoch-secret tree state used to track per-epoch root secrets and derive epoch-level handshake/application/exporter secrets.

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

Deterministic key-schedule vectors (fixed inputs/expected outputs):
```bash
cargo test --lib deterministic_vector_alpha_matches_expected
cargo test --lib deterministic_vector_beta_matches_expected
```
These lock `init_secret`, `root_secret`, and derived `handshake/application/exporter` values to catch accidental derivation drift.

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
Client-side `ClientGroupState` persistence is now available in `src/client_state.rs` (group id, ratchet tree, epoch, own leaf index, pending proposals).
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
cargo run --bin ds_client --state /path/to/alice-client.json -- fetch-and-apply-latest --group-state /path/to/alice-group-state.bin --receiver-private-file /path/to/alice-recv.json --limit 100
cargo run --bin ds_client --state /path/to/alice-client.json -- fetch-and-apply-latest --group-state /path/to/alice-group-state.bin --receiver-private-file /path/to/alice-recv.json --watch --poll-interval-ms 2000
cargo run --bin ds_client -- submit-proposal --base-url http://127.0.0.1:3000 --group-id group1 --proposal-file /path/to/proposal.bin
cargo run --bin ds_client -- submit-commit --base-url http://127.0.0.1:3000 --group-id group1 --commit-file /path/to/commit.bin --path-update-file /path/to/path.bin
cargo run --bin ds_client -- list-messages --base-url http://127.0.0.1:3000 --group-id group1 --limit 50 --kind commit
cargo run --bin ds_client -- publish-key-package --base-url http://127.0.0.1:3000 --keypackage-file /path/to/keypackage.bin
cargo run --bin ds_client -- fetch-key-package --base-url http://127.0.0.1:3000 --target alice --out /path/to/keypackage.bin
cargo run --bin ds_client -- send-app-message --base-url http://127.0.0.1:3000 --group-id group1 --message-file /path/to/message.bin
cargo run --bin ds_client -- list-app-messages --base-url http://127.0.0.1:3000 --group-id group1 --limit 50 --before-id 100
cargo run --bin ds_client -- fetch-app-message --base-url http://127.0.0.1:3000 --group-id group1 --message-id 123 --out /path/to/message.bin
cargo run --bin ds_client -- create-add-proposal --group-state /path/to/group-state.bin --keypackage-file /path/to/new-member.kp --out /path/to/add.proposal.bin
cargo run --bin ds_client -- create-update-proposal --group-state /path/to/group-state.bin --keypackage-file /path/to/new-self.kp --out /path/to/update.proposal.bin --target-leaf 1
cargo run --bin ds_client -- create-remove-proposal --group-state /path/to/group-state.bin --remove-leaf 2 --out /path/to/remove.proposal.bin
cargo run --bin ds_client -- create-commit --group-state /path/to/group-state.bin --commit-out /path/to/commit.bin --path-update-out /path/to/path-update.bin
cargo run --bin ds_client -- apply-received-commit --group-state /path/to/group-state.bin --commit-file /path/to/commit.bin --path-update-file /path/to/path-update.bin --receiver-private-file /path/to/receiver-private.json --derived-out /path/to/derived.json
cargo run --bin ds_client -- show-derived-secrets --group-state /path/to/group-state.bin --epoch 2 --include-root --out /path/to/epoch2-secrets.json
```
The client stores signing keys in `ds-client.json` by default and can now:
- Generate KEM key material (`keygen`) for X25519 + ML-KEM.
- Export a signed MLS `KeyPackage` plus receiver private material (`keypackage-export`) using client identity keys from `--state`.
- Bootstrap initial local group state from ordered member key packages (`bootstrap-group-state`).
- Join a group as a newly-added member from commit/path payloads (`join-from-commit`), with optional automatic leaf detection from receiver private key.
- Sync and apply DS commits automatically (`fetch-and-apply-latest`) by listing commit/path update messages, fetching payload bytes, and applying in epoch order.
- Build metadata-enveloped proposals from `ClientGroupState` files.
- Build a commit + path update from queued pending proposals (`create-commit`), write commit/path envelopes to disk, apply the commit locally, clear pending proposals, and increment the local epoch.
- Apply received commit/path envelopes on receivers (`apply-received-commit`) with metadata checks (`group_id`, `epoch`, `sender_leaf`) and optional path-secret derivation.
- Inspect epoch key-schedule outputs for demos with `show-derived-secrets` (handshake/application/exporter and optional root secret).
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

Sync notes:
- `fetch-and-apply-latest` requires a DS account state in `--state` for request signing.
- It applies only commits matching the local epoch sequence and stops on gaps.
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

Last updated: 2026-02-11 14:56
