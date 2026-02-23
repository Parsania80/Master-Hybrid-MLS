# Create Group Protocol (Code-Mapped)

## Action Summary
- Action Name: `create-group` (local bootstrap to epoch 0, one-member start).
- Actors: Creator `A` (local client), optional DS transport later.
- Trigger: CLI bootstrap (`bootstrap-group-state`) or UI group creation that persists local state.
- Preconditions:
  - Creator has identity + KEM material (`keypackage-export` path).
  - At least one member key package is provided (creator itself for one-member group).
- Outputs:
  - Local `ClientGroupState` file with `epoch=0`, initialized tree, initialized key schedule.

## RFC Note
- This mapping is against **RFC 9420** (MLS). You wrote RFC 9220 in the prompt; RFC 9420 is the MLS standard.

## Flow Table
| Step | Details | Math Action (Equation / Primitive) | Place in Code | RFC 9420 Mapping | Status | Notes |
|---|---|---|---|---|---|---|
| 1 | Collect member KeyPackages and build leaf list. | N/A (state extraction only). | `src/bin/ds_client.rs:515` to `src/bin/ds_client.rs:519` | §11 (group initialization), §7 (ratchet tree objects) | Implemented | `leaf_from_keypackage(...)` builds leaf nodes from KeyPackage. |
| 2 | Build ratchet tree from leaves; parents start blank. | `node_count = 2 * leaf_count - 1`; leaves placed at even node indices (`node_index = 2 * leaf_index`). | `src/bin/ds_client.rs:521`, `src/tree.rs:492` to `src/tree.rs:500`, `src/tree.rs:1264` | §7 tree model | Implemented | For one-member group, tree has one leaf and no parent nodes. |
| 3 | Initialize client group state (`epoch=0`, own leaf, empty pending proposals). | `epoch := 0`, `pending_proposals := []`, `last_applied_commit_id := None`. | `src/bin/ds_client.rs:524`, `src/client_state.rs:40` to `src/client_state.rs:60` | §11 initial group state | Implemented | This step allocates state and then calls key schedule/transcript init. |
| 4 | Compute tree hash and key-schedule init secret. | `tree_hash = SHA3-256(tree.encode())`; `init_secret = labeled_hash("init_secret", context=group_id, parts=[group_id, tree_hash])`. | `src/client_state.rs:46` to `src/client_state.rs:48`, `src/key_schedule.rs:64` to `src/key_schedule.rs:69`, `src/key_schedule.rs:494` to `src/key_schedule.rs:509` | §8 key schedule, §8.1 group context | Implemented (project-specific derivation) | Uses project `labeled_hash` implementation with MLS 1.0 domain string. |
| 5 | Derive chain secrets at epoch 0: `commit_secret -> joiner_secret -> welcome_secret -> epoch_secret -> root_secret`. | `group_context_hash = labeled_hash("group_context", group_id, [group_id, epoch, tree_hash, commit_context])`; `commit_secret = labeled_hash("commit_secret", group_id, [previous_root_secret, epoch, tree_hash, commit_context])`; `joiner_secret = labeled_hash("joiner_secret", group_id, [previous_root_secret, commit_secret, epoch])`; `welcome_secret = labeled_hash("welcome_secret", group_id, [joiner_secret, tree_hash, commit_context])`; `epoch_secret = labeled_hash("epoch_secret", group_id, [joiner_secret, tree_hash, epoch])`; `root_secret = labeled_hash("root_secret", group_id, [epoch_secret, welcome_secret, epoch])`. | `src/key_schedule.rs:70`, `src/key_schedule.rs:378` to `src/key_schedule.rs:429`, `src/key_schedule.rs:469` to `src/key_schedule.rs:481` | §8 key schedule chain, §12.4.1 commit processing model | Implemented (hybrid/prototype alignment) | Material is persisted in `EpochSecretNode`. |
| 6 | Derive stage/application/exporter secrets from `epoch_secret`. | `confirmation_key = stage_kdf("confirm", context_hash, epoch_secret)`; `membership_key = stage_kdf("membership", context_hash, epoch_secret)`; `sender_data_key = stage_kdf("sender_data", context_hash, epoch_secret)`; `handshake_secret = labeled_hash("handshake_secret", group_context_hash, [epoch_secret, group_id, epoch])`; `application_secret = labeled_hash("application_secret", group_context_hash, [epoch_secret, group_id, epoch])`; `exporter_secret = labeled_hash("exporter_secret", group_context_hash, [epoch_secret, group_id, epoch])`. | `src/key_schedule.rs:341` to `src/key_schedule.rs:375`, `src/stage_keys.rs:20` to `src/stage_keys.rs:78` | §8 derived secrets (`confirm`, `membership`, sender/app/export) | Implemented (project labels/context) | Stage keys are domain-separated from `epoch_secret`. |
| 7 | Persist local state to disk. | N/A (serialization + file write). | `src/bin/ds_client.rs:525`, `src/client_state.rs:420` to `src/client_state.rs:427` | Operational (implementation detail) | Implemented | This is what later sync/apply uses. |

## Requested Crypto Steps (Your 3 Items)
| Item | What Happens in Current Code | Place in Code | RFC 9420 Expectation | Gap/Suspicion |
|---|---|---|---|---|
| User A chooses 32-byte nonce | No explicit operator-provided nonce during group creation. Random 32-byte is used later as `leaf_secret` when building a path update for a commit. | `src/bin/ds_client.rs:2111` to `src/bin/ds_client.rs:2113` | Fresh secret input is needed for update path operations (§7.5/§7.6). | **Gap** for “creator-chosen nonce” requirement in your wording. |
| Create `path_secret` and `node_secret` | `path_secret` exists and is derived in path update flow; `node_secret` is now explicit and derived per level from `path_secret` with context binding (`parent_node`, `level_from_leaf`). Commit parent keys are generated deterministically from node secrets. For pure epoch-0 bootstrap, this flow is not invoked yet. | `src/tree.rs:857` to `src/tree.rs:899`, `src/tree.rs:1554` to `src/tree.rs:1561`, `src/tree.rs:1575` to `src/tree.rs:1604`, `src/bin/ds_client.rs:2103` to `src/bin/ds_client.rs:2106` | TreeKEM model ties path secret progression to node key material (§7.5/§7.6). | Implemented for commit/path-update flow; still separate from create-group bootstrap path. |
| Create `root_secret` | Root secret is derived by key schedule chain and stored per epoch. | `src/key_schedule.rs:415` to `src/key_schedule.rs:419`, stored at `src/key_schedule.rs:31`, initialized via `src/key_schedule.rs:70` | §8 key schedule | Implemented, but chain inputs are project-specific. |

## Parent Hash Relation (for tree integrity)
| Detail | Place in Code | RFC 9420 Mapping | Status |
|---|---|---|---|
| Parent nodes carry `parent_hash`. | `src/tree.rs:25` to `src/tree.rs:30` | §7.1, §7.9 | Implemented |
| Parent hash is recomputed root-to-leaf over direct path with sibling tree hash binding. | `src/tree.rs:1044` to `src/tree.rs:1067`, `src/tree.rs:1371` to `src/tree.rs:1380` | §7.9 | Implemented |

## Security-Critical Material Tracking
| Material | Produced At | Consumed At | Place in Code | RFC 9420 Mapping | Notes |
|---|---|---|---|---|---|
| `leaf_secret` (32B) | Commit build | Path update generation | `src/bin/ds_client.rs:2111` to `src/bin/ds_client.rs:2116` | §7.5/§7.6 | Not used in epoch-0 bootstrap. |
| `path_secret` | `derive_path_secret(...)` chain | Path secret HPKE-style encryption/decryption | `src/tree.rs:757`, `src/tree.rs:1383`, `src/tree.rs:772`, `src/tree.rs:821` | §7.5/§7.6 | Receiver derives upward secrets after decap. |
| `root_secret` | Key schedule chain | Derived secret generation + debug inspection | `src/key_schedule.rs:415`, `src/key_schedule.rs:341`, `src/bin/ds_client.rs:2034` to `src/bin/ds_client.rs:2041` | §8 | Persisted per epoch. |

## Gaps / Suspicious Items (Must Review)
| Item | Why Suspicious | Evidence (Code) | RFC Impact | Suggested Fix |
|---|---|---|---|---|
| Sender/receiver strict parent-key lineage validation is not complete | Sender now derives parent keys from node secrets, but strict receiver-side recomputation/rejection for mismatched parent keys is still pending. | `src/tree.rs` commit apply path currently does not enforce strict recomputed-key checks. | Remaining lineage-enforcement gap. | Implement Part 12 / Task 4 and Task 5 strict validation. |
| Creator-nonce not exposed in create-group flow | Your requested “A chooses nonce” is not part of bootstrap API. | `src/bin/ds_client.rs:497` to `src/bin/ds_client.rs:535` | Harder to demonstrate nonce-driven flow in professor demo. | Add optional `--epoch0-secret`/`--nonce` input for deterministic demos (not production default). |
| Commit secret provenance differs from strict RFC path-secret flow | Current chain derives from previous root + context inputs; not directly from update-path root path secret object. | `src/key_schedule.rs:390` to `src/key_schedule.rs:404` | RFC alignment narrative becomes “compatible style” not strict wire-equivalent internals. | Tie `commit_secret` input directly to update-path root path secret where feasible. |

## Verification
```bash
cargo test --lib
cargo test --test ds_fetch_apply_e2e
```

## Operator Notes
- For professor demos, use this file as the baseline explanation for “what happens at create-group”.
- If you want strict RFC wording proof, prioritize the 3 gaps above before claiming full RFC TreeKEM key-lineage equivalence.
