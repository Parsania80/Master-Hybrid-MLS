# ADR 0014: Transition-Start Condition Evaluation

**Status:** Accepted on 2026-07-20
**Decision scope:** Task 38 start gates, stability state, strict saving threshold, and blocker reporting

## Context

ADR 0006 requires five ordered conditions before scheduling a transition. Individual values now exist: the accepted-commit window supplies `q_e`, Task 37 supplies exact preflight savings, and a future simulator will provide accepted post-commit group size and transition state. A boolean-only result would make a blocked experiment impossible to diagnose or reproduce.

## Decision

1. `TransitionStartEvaluator` accepts only an `AcceptedCommitRecord` that is post-warmup. Warmup records are rejected rather than silently evaluated. Evaluation epochs must be strictly increasing.
2. The evaluator retains only the consecutive accepted post-warmup epoch count whose public group size is at least `target_group_size`. A below-target epoch resets it to zero. The group-size condition is satisfied only at or above `stable_epoch_count`.
3. Every evaluation produces all five ordered condition results: transition state is normal; candidate arity equals twice current arity; group size is stable; `q_e >= q_min`; and exact preflight saving is strictly greater than Delta.
4. Each unsatisfied result stores its exact public blocker data. This includes state, arities, group size and consecutive count, `q_e`/`q_min`, unavailable savings, or a saving/Delta pair. The evaluator does not stop at the first blocker.
5. Available `PreflightSavings` must describe exactly the current window `q_e`; a mismatch is rejected. An absent saving is an explicit `PreflightSavingUnavailable` blocker, never an inferred zero. The interim Task 38 config accepts a byte Delta. Task 39 will map the validated byte-or-percent configuration form to this evaluator input.
6. The result triggers only when all five conditions are satisfied. It records a scheduling condition only; it does not create, apply, or authenticate a transition Commit.

## Consequences

- Start decisions and their blockers are deterministic for a public accepted-record sequence and supplied inputs.
- Exact savings preserve the required strict comparison; equality with Delta blocks a transition.
- No private MLS state, secret, randomness, ciphertext body, live group mutation, or candidate Commit enters this boundary.
- The result does not establish a valid, convergent, interoperable, or secure transition.

## Verification

- Unit tests show blockers disappear only when the final required condition is met.
- Unit tests cover all independent blockers, group-size reset, strict equality-to-Delta rejection, savings/window mismatch rejection, warmup rejection, and epoch ordering.
- Locked offline formatting, checking, strict Clippy, and transition-policy tests must pass.
