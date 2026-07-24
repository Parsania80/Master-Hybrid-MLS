# ADR 0022: TreeCover Retirement Threshold

**Status:** Accepted on 2026-07-20; amended by operator on 2026-07-23
**Decision scope:** Task 48 exact, non-mutating retirement authorization rule

## Decision

1. A unit interval uses `1_000_000` fixed-point micro-units. Defaults are `theta_new=700_000` and `theta_old=500_000`.
2. `h_new_cost > theta_new` and `h_old_cost < theta_old` are both strict. Equality at either threshold does not authorize retirement. Both comparisons use checked exact cross-multiplication of Task 47 clamped rationals.
3. Retirement authorization is exactly the OR of the independent conditions. The typed result records the new-tree and old-TreeCover triggers separately.
4. Any undefined non-empty target set blocks the rule before threshold evaluation. Undefined global maturity also blocks it. No condition defaults to true.
5. The result is an authorization fact only. It does not retire TreeCover, update GroupContext, erase secrets, or mutate an MLS group; Task 49 owns authenticated atomic retirement.

## Verification

- Tests prove new-only, old-only, neither, strict non-trigger at equality 0.70 and 0.50, undefined-data blocking, and out-of-range threshold rejection.
