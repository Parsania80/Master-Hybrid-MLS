# ADR 0045: Delivery-Endpoint Health Simulation

**Status:** Accepted on 2026-07-23  
**Decision scope:** Tasks 82–84 corrected `C_*`, health, and interactive simulation

## Context

ADR 0044 incorrectly interpreted serialized route bytes as the thesis `C_*`
inputs. The operator clarified that these quantities count delivery endpoints:
one usable internal node costs one send, independent of the number of leaves it
covers.

The experimental fork can authenticate public transition topology, but it does
not retain an authenticated old-TreeCover node-value store and cannot execute a
post-transition Remove that deletes all old values known by the removed
member. Consequently, the corrected dynamic behavior cannot yet be claimed as
a live MLS observation.

## Decision

1. Add a deterministic, public node-value availability simulation for arity
   pairs `2 -> 4` and `4 -> 8`.
2. Freeze each member's old and new leaf ordinals at transition. A later Remove
   creates a hole; it does not remap surviving members.
3. For every non-empty required sibling node on the target-tree committer
   path, calculate `C_new` using only the new tree:
   - if the target-tree node has a usable value, count one;
   - otherwise count one direct send to every active leaf beneath that node.
   The old TreeCover never contributes to `C_new` or `h_newcost`.
4. Calculate `C_old` separately on the old-tree committer path. Each usable
   required old node counts one; an unavailable required node is recursively
   split into safe usable descendant TreeCover nodes. Only when no safe
   internal value remains does the count fall to active leaves.
5. Calculate a separate `C_real` for modeled delivery. For every required
   target-tree recipient set:
   - use one usable new-tree node when available;
   - otherwise use the smallest usable old-TreeCover cover;
   - otherwise send directly to each still-uncovered active leaf.
   `C_real` never enters either health formula.
6. Use the operator's worst-case convention `C_leaf = active member count`.
   `C_ideal` is the number of non-empty target-tree siblings when all required
   target values are usable. Thus a full 128-member arity-4 path has
   `C_ideal = 3 + 3 + 3 + 1 = 10`.
7. Calculate without byte substitutions:

   ```text
   h_newcost = (C_leaf - C_new) / (C_leaf - C_ideal)
   h_oldcost = (C_leaf - C_old) / (C_leaf - C_ideal)
   ```

   The denominator must be positive. Fractions remain exact and are not
   clamped. Retirement is selected when `h_newcost > 0.70` or
   `h_oldcost < 0.50`.
8. Simulate two pre-transition Updates, one transition, and then seeded-random
   Update/Remove Commits with random valid committers. A Remove chooses a
   distinct active target, invalidates every old and new ancestor known by that
   target, removes it, and refreshes the deleting committer's new-tree path.
   An Update refreshes its committer's new-tree path. The transition starts
   with no usable new-tree internal values.
9. Before transition, two Update observations compare educational canonical
   delivery-byte models for the old and target arities. Each model uses
   `744 * delivery_targets + 132 * active_clients`, where delivery targets are
   `ceil(active_clients / arity)`. Saving is reported as `new - old`, so a
   negative value means the target arity wins. The transition starts only after
   both required observations win.
10. Transition and post-transition delivery bytes use
    `744 * C_real + 132 * active_clients`. The report marks the full MLS
    transition Commit bytes unavailable because this simulator does not emit
    one.
11. Interactive mode fixes public seed `42`, caps post-transition work at 128
   Commits, and stops on the first retirement condition. It creates fresh
   `summary.csv`, `events.csv`, and `report.md` artifacts. The Markdown contains
   a pre-transition byte comparison, transition-cost table, one health row per
   post-transition Commit, and clean post-transition averages. Each per-Commit
   health cell contains both its reduced exact fraction and six-place decimal.
12. Run the mode with `CARGO_BUILD_JOBS=1`, nice level 10, and idle I/O priority.
13. Every artifact must state
    `public_node_value_availability_simulation_not_live_mls_key_erasure` and
    `UnsupportedSimulationOnly`. The older real clear-report mode must keep its
    thesis `C_*`/maturity fields unavailable and must not emit the rejected
    exact-cover alternatives or route-byte totals.

## Consequences

- The simulator now keeps the new- and old-tree health routes independent and
  can show both new-tree progress and old-tree degradation.
- `C_real` makes the modeled byte calculation auditable without contaminating
  either health score.
- The public seed makes the operation, committer, and removal sequence
  reproducible without controlling cryptographic entropy.
- A run may retire after its first impactful Commit if the exact threshold is
  already satisfied. The simulator does not force extra Removes or Updates
  merely to lengthen the trace.
- This does not implement an MLS post-transition Remove, authenticated
  TreeCover node-value lifecycle, actual key erasure, or an authenticated
  retirement Commit. Tasks 85–86 retain that boundary.

## Verification

- Unit tests prove the 128-member ideal count of 10 and each independent
  node-value → direct-leaf fallback.
- A 128-member removal regression proves that seven old direct-path values are
  invalidated and that the affected required old node falls directly to its
  active leaves.
- Tests prove `C_real` follows new → old → leaf priority and that modeled bytes
  use `C_real`, not `C_new` or `C_old`.
- Unit tests prove Remove never targets its committer and reduces the old
  usable-node set in the seed-42 workload.
- CLI tests cover required arguments, defaults, and malformed values.
- The interactive seed-42 `2 -> 4`, 128-client run generates fresh artifacts
  under `output/task82-delivery-health-128-seed42/` and
  `report/task82-delivery-health-128-seed42/`.
