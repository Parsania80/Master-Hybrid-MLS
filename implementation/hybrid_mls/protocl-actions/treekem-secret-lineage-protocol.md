# TreeKEM Secret Lineage Protocol (Task 1-3 Baseline)

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
| 4 | Materialize explicit per-level model entries with explicit node-secret transform. | `node_secret_i = KDF_node(path_secret_i, parent_node, level_from_leaf)` | `src/tree.rs:892` to `src/tree.rs:899`, `src/tree.rs:1554` to `src/tree.rs:1558` | §7.5 / §7.6 | Implemented | Node secret is now domain-separated from path secret. |
| 5 | Derive commit parent public keys deterministically from each node secret. | `classic_secret = KDF("derive node classic secret", context, node_secret)`; `pq_seed = KDF("derive node pq seed 0/1", context, node_secret)`; `parent_public = (X25519Pub(classic_secret), ML-KEM-Pub(pq_seed))`. | `src/tree.rs:169` to `src/tree.rs:186`, `src/tree.rs:1534` to `src/tree.rs:1561` | §7.5 / §7.6 | Implemented | Commit path now uses `parent_updates_leaf_to_root()` (no random parent keys). |
| 6 | Validate model against tree topology and ordering invariants. | Verify tuple `(parent,copath,level_from_leaf)` against expected direct-path shape. | `src/tree.rs:177` to `src/tree.rs:238` | §7 tree integrity expectations | Implemented | Rejects parent/copath/level/node-secret mismatches. |
| 7 | Use model to produce PathUpdate ciphertexts and path-secret list. | HPKE-style encrypt over each copath resolution node with per-level path secret. | `src/tree.rs:897` to `src/tree.rs:926` | §7.6 | Implemented | Existing wire behavior preserved. |

## Security-Critical Material Tracking
| Material | Produced At | Consumed At | Place in Code | RFC 9420 Mapping | Notes |
|---|---|---|---|---|---|
| `leaf_secret` | Caller input | Path secret derivation chain | `src/tree.rs:863` | §7.5 | Sender-local input seed. |
| `path_secret` | Derived per level | Path ciphertext payload encryption | `src/tree.rs:871`, `src/tree.rs:918` | §7.5/§7.6 | Stored in model and PathUpdate debug field. |
| `node_secret` | Derived from path secret per level | Parent key derivation + model invariant validation | `src/tree.rs:892`, `src/tree.rs:1554`, `src/tree.rs:1575`, `src/tree.rs:232` | §7.5/§7.6 | Explicit transform policy is now enforced. |

## Gaps / Suspicious Items
| Item | Why Suspicious | Evidence (Code) | RFC Impact | Suggested Fix |
|---|---|---|---|---|
| Parent-key validation not yet strict on receiver | Sender now derives parent keys from node secrets, but receiver-side strict key-to-secret verification is still pending. | `src/tree.rs` commit apply path does not yet validate parent keys against derived node secrets. | Remaining gap in strict lineage enforcement. | Implement Part 12 / Task 4 and Task 5. |
| Sender-side lineage not yet verified receiver-side | Sender derives/uses node secrets, but receiver does not yet strictly reject mismatched commit parent keys by recomputing expected node-secret lineage. | `src/tree.rs` apply path currently sets parent keys from commit path without derivation check. | Remaining gap in strict lineage enforcement. | Implement Part 12 / Task 4 and Task 5 strict checks. |

## Verification
```bash
cargo test --lib
```

## Operator Notes
- This file documents the current baseline after Part 12 / Task 3.
- Use it with `create-group-protocol.md` when explaining what is already RFC-aligned vs what is still pending hardening.
