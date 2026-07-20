# ADR 0015: Configurable Delta Threshold

**Status:** Accepted on 2026-07-20
**Decision scope:** Task 39 byte-or-percentage Delta configuration, fixed-point resolution, and override precedence

## Context

The Task 38 evaluator compares exact integer preflight savings strictly against an integer-byte Delta. The experiment TOML schema already reserves mutually exclusive `delta_bytes` and `delta_percent_of_transition_micro` fields, but it does not yet specify percentage units, rounding, or how a future command-line override interacts with TOML. Those omissions would make otherwise identical runs choose different start thresholds.

## Decision

1. Every run configures exactly one base Delta form: `delta_bytes` or `delta_percent_of_transition_micro`. There is no implicit default and a missing or ambiguous TOML value is rejected.
2. `delta_percent_of_transition_micro` uses fixed-point micro-percent units: `1_000_000` is one percent and `100_000_000` is one hundred percent. For example, `25_000_000` means 25 percent.
3. A percentage is resolved only when the current `B_transition_preflight` measurement is available. It is calculated using checked integer arithmetic as `ceil(B_transition_preflight * micro_percent / 100_000_000)`. No floating point, later actual-transition byte count, or report rounding enters the start decision.
4. Ceiling resolution is mandatory. A fractional-byte threshold therefore rounds up, preserving the intended strict `Saving_preflight > Delta` condition instead of silently weakening it.
5. `experiment-config::DeltaOverride` is the typed boundary for a future evaluation CLI. If present, its one byte-or-percent variant replaces the TOML Delta for that process; it never combines with the TOML value. The current repository has no transition-evaluation binary, so this is an API boundary rather than a user-facing CLI flag.
6. `DeltaThreshold` retains the selected form and `ResolvedDeltaThreshold` records the preflight byte count and resolved integer bytes used to initialize the Task 38 evaluator.

## Consequences

- A saved TOML configuration and an explicit override produce a deterministic, auditable threshold once the same preflight bytes are supplied.
- A percentage may represent more than 100 percent when its non-negative `u32` fixed-point value does; this is permitted so experiments can intentionally require a large saving.
- The resolved byte value is public measurement metadata, not a proof that the preflight estimate matches a future emitted transition Commit.
- This decision does not implement the transition CLI, emit a candidate Commit, change MLS state, establish interoperability, or establish any security property.

## Verification

- Unit tests cover byte passthrough, exact 25-percent resolution, conservative fractional-byte ceiling resolution, TOML mutual exclusion, and byte/percentage override precedence.
- Locked offline formatting, checking, strict Clippy, and focused crate tests must pass.
