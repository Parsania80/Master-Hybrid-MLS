# Thesis Measurement and Formula Map

## Purpose

This map is the documentation boundary between a thesis table cell and the
implementation that produced it. It does not create new measurements. Use the
Task 67 value state, provenance, unit, and source artifact together; a number
without those fields is not a thesis result.

## Value-state legend

| State | Meaning | Permitted claim |
|---|---|---|
| `observed` | A public value emitted by a real local workload or collector | State the exact configuration and that it is a local observation. |
| `educational` | A deterministic teaching serializer or topology replay | Do not call it a live MLS Commit, convergence, or lifecycle result. |
| `counterfactual` | A canonical-codec or formula replay of a different possible case | Do not call it measured protocol traffic. |
| `modelled` | A direct, documented analytical calculation | Report its measured comparator and percentage error. |
| `unavailable` | The implementation has no honest value | Preserve the reason; never replace it with zero. |

## Experiment environment and repetition

| Thesis field | Value/source | Implementation and artifact | Status |
|---|---|---|---|
| Compiler, OS, CPU, RAM, profiles, repetitions | Task 63 collector fields | `crates/report/src/environment.rs`; `output/task63-environment-128/{environment.json,environment.csv,peak_rss.csv}` | Observed local environment. |
| Peak RSS | Direct release `compare_modes` child `VmHWM` | Task 63 `peak_rss.csv` | Observed process peak; not per-operation memory. |
| Real comparison configuration | 128 members, 3 updates, zero warmup, one repetition, fixed round-robin | `configs/task62-*.toml`; `output/task62-core-128/mode_comparison.json` | Observed configuration. |

## Three-mode comparison and 128-member example

`emitted_commit_bytes` is the complete serialized accepted Commit-byte total
reported by the selected workload client. It is not a network packet size or a
CPU benchmark. The adaptive total includes its distinct transition Commit.

| Mode | Example bytes | Source artifact | Supported interpretation |
|---|---:|---|---|
| Baseline binary MLS | 33,068 | `output/task62-core-128/mode_comparison.csv` | Real local upstream-baseline workload observation. |
| Binary with mKyber | 87,012 | `output/task62-core-128/mode_comparison.csv` | Real local fork observation; non-standard protocol. |
| Adaptive binary to quaternary | 109,144 | `output/task62-core-128/mode_comparison.csv` | Real local fork observation including the 25,622-byte transition and one post-transition update. |

The acceptance rerun under `output/task68-comparison-128-acceptance/` reports
the same byte totals. Its elapsed lifecycle values remain environment-dependent
observations and must not be used as a general CPU-performance claim.

For a real adaptive run, the report retains both policy quantities:

```text
matched_window_saving = sum(normal_binary_bytes) - sum(matched_compact_bytes)
amortized_preflight_saving = matched_window_saving - transition_preflight_bytes
```

The selected matched-per-Commit policy may authorize only the first quantity.
The documented run has `+7,256` matched-window bytes and `-18,366`
amortized-preflight bytes. It therefore proves the selected authorization and
post-transition convergence, not amortized break-even. See
`crates/report/src/comparison.rs`, ADR 0006, and Task 62 artifacts.

## Normal-operation table

| Table family | Source | Status boundary |
|---|---|---|
| Arity-2 baseline Update/Add/Remove | `crates/report/src/normal_operations.rs`; `output/task64-normal-operations/normal_operations.csv` | Real local baseline observations. |
| Arity-2 fork Update | Same generator and artifact | Real local experimental-fork observation. |
| Arity-4/8 Update rows | Same generator's canonical serializer | Educational-only; not live MLS messages or arity-4/8 protocol support. |

The real fork arity-2 Update example is 4,768 bytes. The educational arity-4
and arity-8 Update examples are 5,524 and 15,220 bytes respectively. Their
provenance, rather than their numerical order, determines their thesis claim.

## Transition maturity and TreeCover table

ADR 0006 defines the target-set costs `C_leaf(S)`, `C_new(S)`, `C_old(S)`, and
`C_ideal(S)`. Task 65 evaluates the corresponding checked rational maturity
values from the existing transition-policy/metrics implementation:

```text
h_new = (C_leaf - C_new) / (C_leaf - C_ideal)
h_old = (C_leaf - C_old) / (C_leaf - C_ideal)
```

The threshold result is formula authorization only. It is not a retirement
Commit or secret-erasure event.

| Transition row | Artifact | Correct interpretation |
|---|---|---|
| Real 2-to-4 bytes | `output/task65-transition-maturity/transition_maturity.json` | Transition and cumulative bytes are observed from Task 61. Task 79 withdrew its fixed-partition costs/maturity as real evidence; those fields are educational serializer examples only. |
| Real 2-to-4 retirement | Same artifact | `UnsupportedNoAuthenticatedRetirementCommit`; no retirement or erasure was measured. |
| 4-to-8 row | Same artifact | Educational 64-member topology replay only; no octal MLS Commit, convergence, or private-key lifecycle exists. |

## Byte/time models and percentage errors

Task 66 uses only a direct measured comparator and a documented simple model.
For any available non-zero measured denominator it applies:

```text
Error_size = abs(B_measured - B_model) / B_measured * 100
Error_time = abs(T_measured - T_estimated) / T_measured * 100
```

The implementation stores percentage values as fixed-point micro-percent to
avoid floating-point ambiguity. It rejects a zero measured denominator and
retains full RFC MLS framing and full transition models as unavailable where
the public artifacts cannot support them.

| Model row | Artifact | Interpretation |
|---|---|---|
| Real binary mKyber Update | `output/task66-model-errors/model_errors.json` | Model 2,503 vs observed 4,768 bytes: `Error_size=47.504194%`; estimated 2,917,226 vs observed 5,917,311 ns: `Error_time=50.700140%`. Local measurement, not a general benchmark. |
| Educational arity-4/8 Update | Same artifact | Byte models exactly reproduce the educational serializer; timing remains local and educational. |
| Full RFC or live transition model | Same artifact | Unavailable with an explicit reason; no inferred percentage is permitted. |

## Final dataset and citation route

`output/task67-thesis-tables/thesis_tables.csv` and `.json` contain 208
long-form rows. Each row provides the stable English field, Persian-ready key,
unit, value state, provenance, and source artifact. The grouped human-readable
version is `report/task67-thesis-tables/thesis_tables.md`.

For each thesis value, cite the final dataset row and its source artifact, then
state its value state. For example: “the 2-to-4 transition byte value is an
observed local fork fact; its historical maturity costs are educational fixed-partition
replay.” This prevents real, educational, modelled, and unsupported results
from being conflated.

## Reproduction boundary

Supported commands use the repository-pinned toolchain plus `--locked
--offline`; see README. They create new output directories and do not overwrite
completed evidence. Task 70 is responsible for a clean-checkout rerun, command
manifest, and hashes. Until then, this map documents the completed local
evidence rather than claiming a clean-checkout reproduction.
