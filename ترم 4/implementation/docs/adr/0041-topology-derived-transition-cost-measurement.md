# ADR 0041: Topology-Derived Transition-Cost Measurement

**Status:** Accepted on 2026-07-23  
**Decision scope:** Correct `C_leaf`, `C_new`, `C_old`, `C_ideal`, `h_newcost`, and `h_oldcost` measurement

## Context

The Task 65 and Task 74–78 report path constructed one synthetic recipient set
and divided it into fixed widths `1`, `2`, `4`, and `8`. The canonical hybrid
serializer measured those constructed payloads exactly, but the partitions
were selected from nominal arity rather than actual covering nodes in the
current new tree or eligible old TreeCover.

The resulting values and ratios are therefore educational fixed-partition
codec examples. They are not actual transition-maturity evidence and cannot
authorize TreeCover retirement. In particular, an arity-2 node can cover more
than two leaves and an arity-4 node can cover more than four leaves depending
on depth, occupancy, the target recipient set, and the committer path.

## Decision

1. A live clear report must not publish the fixed-partition values as available
   `C_*`, `h_*`, or retirement facts. Until Tasks 80–83 complete, these fields
   are typed unavailable with reason
   `CorrectedTopologyRoutesNotImplemented`.
2. Every corrected measurement is bound to one accepted impactful
   post-transition Commit, its authenticated group/epoch/tree version, and
   every relevant path-level recipient set. Alternative routes must carry the
   same logical payload and exclude the committer where the protocol requires.
3. `C_leaf` uses independent singleton delivery to the actual recipients.
   `C_new` uses a valid disjoint cover derived from populated nodes in the
   current new tree. `C_old` uses a valid disjoint cover derived from eligible
   nodes in the frozen old TreeCover. `C_ideal` minimizes a valid cover in a
   fully mature target-arity tree with the same members and recipients.
4. A node's cover capacity derives from its topology position, occupancy, and
   eligibility. Nominal arity is never used as a fixed recipient chunk width.
5. Reported aggregate costs count invariant serialized outer Commit bytes once
   plus the exact alternative route payload bytes. Per-set rows retain their
   own route, bytes, and provenance so the aggregate remains auditable.
6. Actual emitted route bytes are `observed`. Non-emitted alternative routes
   may be `exact_counterfactual` only when constructed from authenticated public
   topology and measured through the canonical serializer. Missing topology or
   routing state produces an unavailable blocker, never a fabricated number.
7. After checked aggregation with `C_leaf > C_ideal`, calculate exactly:

   ```text
   h_newcost = (C_leaf - C_new) / (C_leaf - C_ideal)
   h_oldcost = (C_leaf - C_old) / (C_leaf - C_ideal)
   ```

   The report does not substitute the former fixed `6/7` and `4/7` values and
   does not apply an additional synthetic min/max result to these aggregate
   table fields.
8. Recalculate after every accepted impactful post-transition Commit and
   record `t`, the number of such Commits since transition start. Retirement
   thresholds may be evaluated only from corrected available costs.
9. This correction does not implement an authenticated fork retirement
   Commit. Even an available formula decision must retain
   `UnsupportedNoAuthenticatedRetirementCommit` until that separate protocol
   lifecycle exists and erases applicable old key material atomically.

## Consequences

- Previously generated Task 65 and Task 75–78 maturity values remain historical
  educational artifacts and must not be cited as real retirement evidence.
- Real baseline, transition, quaternary Commit, Welcome, timing, and committer
  observations from those runs are unaffected.
- `test.sh` mode 3 can continue producing real operation evidence while
  corrected cost and retirement fields remain explicitly unavailable.
- Tasks 80–84 must complete before the clean report can publish corrected
  numeric maturity values.

## Verification Criteria

- No live report imports or calls the fixed-partition replay.
- CSV and Markdown preserve unavailable `C_*`, `h_*`, and retirement fields
  with the exact correction reason.
- The event trace records a blocked correction boundary rather than a modelled
  retirement event.
- Educational transition-table generation remains visibly labelled
  `educational_fixed_partition` and cannot be mistaken for live topology
  measurement.
- Formatting, strict lint, focused report tests, redaction, and create-new
  behavior pass.
