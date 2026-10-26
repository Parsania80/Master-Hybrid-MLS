# ADR 0013: Exact Preflight Savings Arithmetic

**Status:** Accepted on 2026-07-20
**Decision scope:** Task 37 current/candidate sums, rational averages, preflight savings, and report rounding

## Context

ADR 0006 defines equivalent direct and average forms for transition preflight savings. Computing averages as binary floating-point values or rounding them before multiplying by `q_e` could change a strict transition threshold. The Task 36 preflight total is also an estimate and must remain distinct from later actual-transition reporting.

## Decision

1. `PreflightSavings` accepts only byte records for already-classified impactful commits. It rejects an empty cost set, so no average or transition decision is fabricated for `q_e = 0`.
2. It stores checked `u64` sums: `sum_current` and `sum_candidate`. Each record contains a measured current byte value and an explicitly estimated candidate byte value.
3. `B_bar_current` and `B_hat_bar_candidate` are stored as `RationalByteAverage { numerator, denominator }`, where the denominator is exactly the impactful-record count. They are never converted to floating point for policy arithmetic.
4. The average difference is a signed exact rational `(sum_current - sum_candidate) / q_e`. The direct result is `sum_current - sum_candidate - B_transition_preflight`. The average-form result independently multiplies the rational difference by `q_e` before subtracting preflight bytes. Both results are stored as signed `i128` byte values because a saving may be negative.
5. Display-only rounding is explicit: exact, floor, ceiling, or nearest-half-up. Requesting exact rounding for a fractional average fails. Rounded values never feed the policy formula.
6. `from_impactful_costs_and_preflight` takes the Task 36 estimate without changing its provenance. This task does not evaluate Delta, group-size stability, arity state, or the full transition-start decision.

## Consequences

- Strict later threshold comparisons can use exact savings without rounding drift.
- Negative savings remain reportable instead of being clamped or hidden.
- A later actual transition may recompute realized savings using its actual byte count; preflight mismatch evidence remains intact.
- Formula arithmetic does not make a candidate transition Commit valid, accepted, convergent, interoperable, or secure.

## Verification

- Unit tests cover fractional averages, every rounding rule, empty input, checked sum overflow, and Task 36 preflight integration.
- A bounded property test verifies direct and rational-average forms are exactly equal for varied non-empty cost sets.
- Locked offline formatting, checking, strict Clippy, and transition-policy tests must pass.
