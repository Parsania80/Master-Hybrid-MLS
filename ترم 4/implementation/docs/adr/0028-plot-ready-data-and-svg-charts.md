# ADR 0028: Plot-Ready Data and SVG Charts

**Status:** Accepted on 2026-07-22
**Decision scope:** Task 56 long-form plot data, SVG rendering, availability semantics, and chart paths

## Context

Task 55 produces complete public per-commit report records, but chart consumers need a stable numeric/availability representation. The current maintained baseline can measure Commit/Welcome bytes, member/delivery counts, and accepted lifecycle time. It cannot truthfully provide candidate delivery costs, savings, maturity, TreeCover size, or transition data without future experimental instrumentation.

## Decision

1. Task 56 writes a create-new `plot_data.csv` below `output/<run>`. It is a long-form schema with version, accepted sequence/epoch, metric family, unit, value state, optional numeric value, typed reason, and provenance. Numeric values appear only for real measured or observed facts.
2. Every unavailable point has an empty numeric value and a typed reason. In particular, baseline candidate costs retain `RequiresExperimentalFork`; savings retain `PolicyWindowNotAttached`; maturity retains `TreeCoverNotRetired`; and TreeCover size/transition bytes retain `TransitionNotStarted`. No unavailable value becomes zero or an estimate.
3. Task 56 writes six dependency-free create-new SVG files below `report/<run>`: `bytes.svg`, `costs.svg`, `savings.svg`, `maturity.svg`, `treecover_size.svg`, and `timings.svg`. Bytes and timings render observed bars. The remaining files render an explicit unavailable-state card until matching numeric instrumentation exists.
4. SVG dimensions grow with the number of plot points so long workload runs do not overlap into a fixed-width chart. The byte chart includes a color legend for measured baseline Commit and Welcome bars. SVG output is presentation-only; it never feeds a policy decision.
5. The existing `generate_baseline_report` CLI executes one accepted baseline workload and writes both Task 55 report files and Task 56 plot files from that exact execution. It still accepts only public input and uses create-new paths under `output/` and `report/`.
6. No plotting, image, statistics, or native-code crate is introduced. SVG is generated directly from typed public records with constants-only labels. Future Task 57 mode comparison and independent-run statistics remain separate work.

## Consequences

- Downstream charting can filter or facet `plot_data.csv` without reinterpreting missing values.
- A baseline report visually distinguishes real byte/timing data from unavailable experimental facts.
- Later instrumentation can add a typed extractor for an observed family without changing existing baseline values or falsely backfilling them.

## Verification

- Focused tests require observed baseline points, explicit unavailable candidate/TreeCover points, all six SVG files, unsafe-path rejection inherited from Task 55, and the byte-chart legend.
- A release mixed-workload acceptance run writes all Task 55 and Task 56 artifacts, validates each SVG, and confirms the expected typed unavailability labels.
