# ADR 0027: Public Report Artifact Generation

**Status:** Accepted on 2026-07-22
**Decision scope:** Task 55 CSV, JSON, Markdown, output paths, required report subjects, and redaction behavior

## Context

Task 54 supplies a complete public `PerCommitMetricRecord`, but it does not write experiment artifacts. A report generator must make the directly observed baseline facts usable without fabricating candidate, policy, transition, retirement, crypto, or security results. The thesis plan also requires five canonical artifacts and all 27 report subjects.

## Decision

1. `report::generation` is the sole Task 55 writer for the public artifact family. It converts only accepted, contiguous, epoch-advancing Task 54 records; it performs no MLS transition, secret derivation, or experimental fork operation.
2. The generator writes the following create-new artifacts:

   | Artifact | Directory | Purpose |
   |---|---|---|
   | `commits.csv` | `output/<run>` | One flattened public Task 54 record per accepted commit. Full typed measurement families are preserved as JSON cells where a scalar CSV cell cannot safely express them. |
   | `epochs.csv` | `output/<run>` | One concise public post-commit epoch observation per accepted commit. |
   | `transition_events.csv` | `output/<run>` | Observed transition events, or one explicit unavailable row when none occurred. |
   | `summary.json` | `output/<run>` | Versioned run configuration, final state, safe aggregates, availability summary, the 27 subject list, limitations, and complete public per-commit records. |
   | `report.md` | `report/<run>` | Human-readable report with exactly one numbered section for every required subject. |

3. Artifact directories must be non-empty, relative, traversal-free paths beginning with `output/` and `report/` respectively. Existing artifact files are rejected rather than overwritten. This preserves evidence and keeps generated data outside source-controlled implementation paths.
4. The Markdown report always includes the following 27 subjects, even when a baseline run cannot observe one: artifact/provenance; mode/boundary; workload configuration; group lifecycle; operation sequence; committer placement; membership; baseline Commit bytes; Welcome bytes; delivery/joins; timing; current topology; candidate topology; recipient resolutions; candidate byte comparison; crypto; policy; impact; transition start; transition state; transition bytes; savings/Delta; TreeCover maturity; TreeCover retirement; measured-versus-estimated provenance; unavailable interpretation; and security/redaction limits.
5. `MetricAvailability::Unavailable` remains unavailable in every CSV, JSON, and Markdown artifact. It must never be converted to zero, a favorable outcome, an estimate, or a security claim. The baseline report marks experimental topology, candidate-byte, crypto, policy, transition, and retirement families with their typed reasons.
6. The `generate_baseline_report` CLI requires explicit public workload and artifact-path inputs. It supports the five Task 52 committer strategies and the five Task 53 workload families, but executes only the unchanged baseline adapter. Later mode comparison and multi-run statistics remain Tasks 56–57.
7. No artifact serializes private MLS state, private or mKyber keys, classical/PQ shared secrets, path secrets, AEAD keys/nonces, raw entropy, or a secret-reconstructing seed. Every report repeats the educational-research boundary and SEC-01 through SEC-10 limitation.

## Consequences

- A baseline run now has an auditable, safe, create-new artifact family without pretending that experimental facts exist.
- Task 56 charts must derive only from these typed records and availability states.
- Task 57 may add independent-run aggregation, statistics, and mode comparisons without changing the public per-commit artifact meaning.

## Verification

- Focused tests execute a real mixed baseline workload and require all five files, all 27 Markdown headings, an explicit transition-unavailable CSV row, complete per-commit JSON, and the mandatory security limitation.
- Tests reject unsafe output paths and existing artifact names.
- Formatting, locked offline checks, strict Clippy, the focused suite, and a release CLI acceptance run pass.
