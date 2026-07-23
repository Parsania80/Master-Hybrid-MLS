# ADR 0043: Exact Topology Cover Selection

**Status:** Accepted on 2026-07-23  
**Decision scope:** Task 81 `C_leaf`, `C_new`, `C_old`, and `C_ideal` covers

## Context

Task 80 supplies one authenticated recipient set plus bound active-quaternary
and eligible old-binary topology. The former fixed-width replay did not inspect
either tree. Task 81 must select actual nodes without yet assigning ciphertext
or full-Commit byte costs.

ADR 0010 defines a populated topology node as a node with at least one occupied
descendant. This is a public topology property, not a claim about retained
private key material.

## Decision

1. Every cover node records tree arity, root-relative depth, left-to-right
   ordinal, and the exact active-quaternary recipient leaf ordinals it covers.
2. `C_leaf` contains one active-tree leaf node per authenticated recipient.
3. `C_new` recursively selects each maximal populated active-quaternary subtree
   whose occupied descendants are all recipients.
4. `C_old` maps the same recipient identities to eligible frozen binary leaves,
   then applies the same maximal-subtree selection. A recipient absent from the
   eligible TreeCover makes the route unavailable.
5. `C_ideal` applies the maximal-subtree selection to the fully populated mature
   target-arity topology for the same members and recipient set.
6. The selection is deterministic and minimal in node count because tree
   subtrees form a laminar family: whenever a node contains recipients only,
   replacing it by descendants uses at least one and generally more nodes;
   whenever it also contains an excluded member, it cannot be selected.
7. Every result is checked to cover the target set exactly once. Empty,
   duplicate, unknown, incomplete-mapping, and unavailable-old-cover inputs
   fail with typed errors.
8. These are cover shapes only. Task 82 must prove route materialization and
   serialize canonical same-payload alternatives before any `C_*` byte value is
   available.

## Seed-42 64-Member Result

The authenticated target is all quaternary leaves except committer ordinal 2.

| Alternative | Exact node count | Interpretation |
|---|---:|---|
| `C_leaf` | 63 | One singleton leaf for each recipient |
| `C_new` | 9 | Three singleton siblings, three depth-2 subtrees, and three depth-1 subtrees |
| `C_old` | 6 | Six binary sibling subtrees along the excluded committer's old-tree path |
| `C_ideal` | 9 | Same as `C_new` because the current 64-member arity-4 topology is already fully occupied |

`C_old` rows name covered recipients by their active-quaternary ordinals, while
the selected node coordinates remain binary. The lists therefore need not look
contiguous even though each binary subtree is contiguous in the old tree.

## Consequences

- The prior 1/2/4/8 chunk widths are no longer involved in live cover
  selection.
- `C_new == C_ideal` at the cover-shape level for this full topology; this is an
  observed topology consequence, not a pre-filled ratio.
- Clear-report schema version 4 records the complete cover encodings and keeps
  byte costs unavailable with
  `CorrectedTopologyRouteSerializationNotImplemented`.
