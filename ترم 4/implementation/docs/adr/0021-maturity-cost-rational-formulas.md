# ADR 0021: Maturity Cost Rational Formulas

**Status:** Accepted on 2026-07-20
**Decision scope:** Task 47 checked `h_new_cost` and `h_old_cost` facts from Task 46 measurements

## Context

ADR 0006 defines per-target-set raw maturity ratios, clamping, and conservative aggregation, but Task 46 deliberately stops at raw component costs. Floating point would obscure exact threshold boundaries and missing route data must never become a favorable maturity value. The next task needs a typed result that distinguishes an exact score from an empty-set exclusion or a non-empty blocker.

## Decision

1. `metrics::MaturityCostEvaluation` consumes canonical, strictly ordered Task 46 target-set measurements. Empty target sets remain recorded but are excluded from both aggregate functions.
2. For each non-empty set, `h_new_raw = (C_leaf - C_new) / (C_leaf - C_ideal)` and `h_old_raw = (C_leaf - C_old) / (C_leaf - C_ideal)` use checked `i128` subtraction and normalized exact `SignedRational` values with a positive denominator.
3. A missing `C_leaf`, route-specific input, or `C_ideal` creates a typed `UnavailableCost` result. `C_leaf <= C_ideal` creates `NonPositiveDenominator`. These are non-empty undefined results, never zero or one.
4. Every defined raw score stores both the raw rational and a separately clamped exact rational. `BelowZero`, `InRange`, and `AboveOne` state why the threshold value is zero, unchanged, or one.
5. `h_new_cost` selects the minimum clamped score and `h_old_cost` selects the maximum clamped score, preserving the selecting target-set index and score. If no non-empty set exists or any formula has no defined candidate, its aggregate is typed `Undefined`.
6. The evaluation records whether any non-empty target set is undefined for either formula. Task 48 must treat that condition as a retirement blocker before considering its OR threshold rule.

## Consequences

- Threshold comparisons can use exact rational values in Task 48 without floating-point rounding.
- Existing serializer byte counts are non-negative; signed arithmetic nevertheless preserves a negative raw numerator should a later route measurement exceed leaf delivery, and clamps it transparently.
- This is arithmetic over caller-provided public measurements. It does not authenticate a route, determine TreeCover eligibility, retire state, or establish a protocol/security property.

## Verification

- Unit tests cover exact raw fractions, conservative minimum/maximum selection, empty exclusions, unavailable old routes, non-positive denominators, above-one and below-zero clamps, and non-canonical target-set ordering.
- Locked-offline formatting, focused tests, and strict Clippy must pass.
