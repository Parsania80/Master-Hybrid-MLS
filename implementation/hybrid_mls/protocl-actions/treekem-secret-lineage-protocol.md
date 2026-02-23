# TreeKEM Secret Lineage Protocol (Task 1 Baseline)

## Action Summary
- Action Name: Define explicit sender-side TreeKEM secret model and invariants.
- Actors: Sender client (local state / tree logic).
- Trigger: Sender prepares path update from a fresh leaf secret.
- Preconditions:
  - Sender leaf is present in ratchet tree.
  - Direct path is computable.
- Outputs:
  - `DirectPathSecretModel` with root-to-leaf levels.
  - Validation rules that bind model shape to tree topology.

## Flow Table
| Step | Details | Math Action (Equation / Primitive) | Place in Code | RFC 9420 Mapping | Status | Notes |
|---|---|---|---|---|---|---|
| 1 | Wrap raw 32-byte seed into explicit `LeafSecret`. | `leaf_secret := bytes32` | `src/tree.rs:105` | §7.5 | Implemented | Type-level clarity only (no crypto op). |
| 2 | Compute sender direct path with copath in root-to-leaf order. | `direct_path_with_copath(sender_leaf)` | `src/tree.rs:889`, `src/tree.rs:1211` | §7.3, §7.5 | Implemented | Internal traversal order is root-to-leaf. |
| 3 | Derive per-level path secrets from leaf toward root. | `path_secret_{i+1} = KDF_path(path_secret_i, parent_node, level_from_leaf)` | `src/tree.rs:869` to `src/tree.rs:878`, `src/tree.rs:1520` to `src/tree.rs:1524` | §7.5 | Implemented | Derivation uses existing labeled-hash helper. |
| 4 | Materialize explicit per-level model entries. | `node_secret_i := path_secret_i` (Task 1 invariant) | `src/tree.rs:873` to `src/tree.rs:878` | §7.5 / §7.6 (pre-hardening stage) | Implemented (transitional) | Node-secret equality is temporary; Task 2+ hardens this. |
| 5 | Validate model against tree topology and ordering invariants. | Verify tuple `(parent,copath,level_from_leaf)` against expected direct-path shape. | `src/tree.rs:160` to `src/tree.rs:221` | §7 tree integrity expectations | Implemented | Rejects parent/copath/level/node-secret mismatches. |
| 6 | Use model to produce PathUpdate ciphertexts and path-secret list. | HPKE-style encrypt over each copath resolution node with per-level path secret. | `src/tree.rs:897` to `src/tree.rs:926` | §7.6 | Implemented | Existing wire behavior preserved. |

## Security-Critical Material Tracking
| Material | Produced At | Consumed At | Place in Code | RFC 9420 Mapping | Notes |
|---|---|---|---|---|---|
| `leaf_secret` | Caller input | Path secret derivation chain | `src/tree.rs:863` | §7.5 | Sender-local input seed. |
| `path_secret` | Derived per level | Path ciphertext payload encryption | `src/tree.rs:871`, `src/tree.rs:918` | §7.5/§7.6 | Stored in model and PathUpdate debug field. |
| `node_secret` | Task 1 model assignment | Invariant validation only (for now) | `src/tree.rs:878`, `src/tree.rs:215` | §7.5 | Transitional equality with path secret until Task 2+ hardening. |

## Gaps / Suspicious Items
| Item | Why Suspicious | Evidence (Code) | RFC Impact | Suggested Fix |
|---|---|---|---|---|
| Parent keys not yet node-secret-derived | Commit path keys still built randomly in CLI commit builder. | `src/bin/ds_client.rs:2105` to `src/bin/ds_client.rs:2108` | Not full TreeKEM secret-to-key lineage. | Implement Part 12 / Task 2 and bind parent keys to node secrets. |
| Node secret currently equals path secret | Transitional invariant is explicit but not final RFC-strength lineage. | `src/tree.rs:878`, `src/tree.rs:215` | Limits semantic separation between path/node materials. | Introduce explicit node-secret transform in next task. |

## Verification
```bash
cargo test --lib
```

## Operator Notes
- This file documents the current baseline after Part 12 / Task 1.
- Use it with `create-group-protocol.md` when explaining what is already RFC-aligned vs what is still pending hardening.
