#!/usr/bin/env bash
# Run one real, professor-facing 128-member three-mode protocol demonstration.

set -Eeuo pipefail

script_dir=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
cd -- "$script_dir"

fail() {
    printf 'test.sh: %s\n' "$*" >&2
    exit 1
}

(( $# == 0 )) || fail 'run ./test.sh without command-line parameters; it will prompt for the mode and inputs'

printf '\n=== Adaptive Hybrid MLS Interactive Demo ===\n'
printf 'Choose a mode:\n'
printf '  1) Short protocol demo (real comparison plus charts; about 20 seconds)\n'
printf '  2) Complete thesis tables (comparison, RSS, operation, maturity, model, and final tables)\n'
printf '  3) Clear 32-member report (costs, transition phases, Add/Remove/Update, and retirement estimate)\n'
printf 'Selection [1/2/3]: '
IFS= read -r mode_choice || fail 'could not read mode selection'

generate_thesis_tables=false
generate_clear_32=false
case "$mode_choice" in
    1)
        mode_label='short protocol demonstration'
        ;;
    2)
        generate_thesis_tables=true
        mode_label='complete thesis-table pipeline'
        ;;
    3)
        generate_clear_32=true
        mode_label='clear 32-member cost and transition report'
        ;;
    *)
        fail 'select 1, 2, or 3 from the displayed mode menu'
        ;;
esac

default_run_name="professor-demo-$(date -u +%Y%m%dT%H%M%SZ)"
printf 'Public run label [%s]: ' "$default_run_name"
IFS= read -r requested_run_name || fail 'could not read run label'
run_name="${requested_run_name:-$default_run_name}"

[[ "$run_name" =~ ^[A-Za-z0-9][A-Za-z0-9_-]*$ ]] \
    || fail 'run name must contain only letters, digits, underscores, or hyphens'

output_dir="output/$run_name"
report_dir="report/$run_name"
comparison_output_dir="$output_dir"
comparison_report_dir="$report_dir"
if [[ "$generate_thesis_tables" == true ]]; then
    comparison_output_dir="$output_dir/comparison"
    comparison_report_dir="$report_dir/comparison"
fi
comparison_csv="$comparison_output_dir/mode_comparison.csv"
task61_summary="output/task61-adaptive-128-matched-per-commit/summary.json"

[[ ! -e "$output_dir" ]] || fail "output directory already exists: $output_dir"
[[ ! -e "$report_dir" ]] || fail "report directory already exists: $report_dir"
[[ -f Cargo.lock && -f rust-toolchain.toml ]] || fail 'run this script from the repository root'
if [[ "$generate_clear_32" == false ]]; then
    [[ -f configs/task62-baseline.toml ]] || fail 'missing Task 62 baseline configuration'
    [[ -f configs/task62-mkyber.toml ]] || fail 'missing Task 62 mKyber configuration'
    [[ -f configs/task62-adaptive.toml ]] || fail 'missing Task 62 adaptive configuration'
fi
if [[ "$generate_thesis_tables" == true ]]; then
    printf 'Public Task 61 summary path [%s]: ' "$task61_summary"
    IFS= read -r requested_task61_summary || fail 'could not read Task 61 summary path'
    task61_summary="${requested_task61_summary:-$task61_summary}"
    [[ -s "$task61_summary" ]] || fail "missing required public Task 61 summary: $task61_summary"
fi

printf 'Selected mode: %s\n' "$mode_label"
printf 'Output: %s/\n' "$output_dir"
printf 'Report: %s/\n' "$report_dir"
printf 'Proceed? [y/N]: '
IFS= read -r confirmation || fail 'could not read confirmation'
case "${confirmation,,}" in
    y|yes)
        ;;
    *)
        printf 'Cancelled. No protocol command was run.\n'
        exit 0
        ;;
esac

run_step() {
    local label="$1"
    shift
    printf '  %-40s' "$label"
    if "$@" >/dev/null; then
        printf 'ok\n'
    else
        printf 'failed\n' >&2
        return 1
    fi
}

metric_value() {
    local mode="$1"
    local field="$2"
    local value
    value=$(awk -F ',' -v mode="$mode" -v field="$field" \
        '$1 == mode && $3 == field { print $6; exit }' "$comparison_csv")
    [[ -n "$value" ]] || fail "missing $field for $mode in $comparison_csv"
    printf '%s\n' "$value"
}

if [[ "$generate_clear_32" == true ]]; then
    clear_summary_csv="$output_dir/clear_report.csv"
    clear_events_csv="$output_dir/clear_events.csv"
    clear_markdown="$report_dir/clear_report.md"
    printf '\n=== Clear 32-Member MLS Report ===\n'
    printf 'Members: 32; real baseline operations: Update, Add, Remove\n'
    printf 'Adaptive operations: seeded-random Updates through transition and one maturity evaluation\n\n'
    run_step 'Run clear 32-member experiment' env CARGO_TERM_COLOR=never cargo run --quiet -p report --bin run_clear_32 \
        --release --locked --offline -- \
        --seed 42 \
        --output "$output_dir" \
        --report "$report_dir"
    [[ -s "$clear_summary_csv" ]] || fail "summary CSV was not created: $clear_summary_csv"
    [[ -s "$clear_events_csv" ]] || fail "event CSV was not created: $clear_events_csv"
    [[ -s "$clear_markdown" ]] || fail "Markdown report was not created: $clear_markdown"
    printf '\nGenerated:\n'
    printf '  Summary: %s\n' "$clear_summary_csv"
    printf '  Events:  %s\n' "$clear_events_csv"
    printf '  Report:  %s\n' "$clear_markdown"
    printf '\nScope: TreeCover retirement is formula-authorized/modelled; the live fork retirement Commit remains unsupported.\n'
    exit 0
fi

printf '\n=== Adaptive Hybrid MLS Professor Demo ===\n'
printf 'Run: %s\n' "$run_name"
printf 'Workload: 128 members, 3 updates, 2 regions, fixed public schedule\n\n'

run_step 'Run real three-mode protocol' env CARGO_TERM_COLOR=never cargo run --quiet -p report --bin compare_modes \
    --release --locked --offline -- \
    --baseline-config configs/task62-baseline.toml \
    --mkyber-config configs/task62-mkyber.toml \
    --adaptive-config configs/task62-adaptive.toml \
    --initial-members 128 \
    --maximum-members 128 \
    --operations 3 \
    --regions 2 \
    --output "$comparison_output_dir" \
    --report "$comparison_report_dir"

run_step 'Generate comparison charts' env CARGO_TERM_COLOR=never cargo run --quiet -p report --bin plot_mode_comparison \
    --release --locked --offline -- \
    --comparison-csv "$comparison_csv" \
    --output "$comparison_output_dir" \
    --report "$comparison_report_dir"

[[ -s "$comparison_csv" ]] || fail "comparison CSV was not created: $comparison_csv"
[[ -s "$comparison_output_dir/mode_comparison.json" ]] || fail 'comparison JSON was not created'
[[ -s "$comparison_report_dir/mode_comparison.md" ]] || fail 'comparison Markdown was not created'

baseline_bytes=$(metric_value 'baseline-binary-mls' 'emitted_commit_bytes')
mkyber_bytes=$(metric_value 'binary-mls-with-mkyber' 'emitted_commit_bytes')
adaptive_bytes=$(metric_value 'adaptive-binary-to-quaternary-mls' 'emitted_commit_bytes')
transition_bytes=$(metric_value 'adaptive-binary-to-quaternary-mls' 'actual_transition_bytes')
post_transition_updates=$(metric_value 'adaptive-binary-to-quaternary-mls' 'post_transition_update_count')
matched_saving=$(metric_value 'adaptive-binary-to-quaternary-mls' 'matched_window_saving_bytes')
amortized_saving=$(metric_value 'adaptive-binary-to-quaternary-mls' 'amortized_preflight_saving_bytes')

[[ "$post_transition_updates" == '1' ]] \
    || fail "expected one accepted post-transition update, observed $post_transition_updates"

printf '\n=== Verified Result ===\n'
printf 'Baseline MLS Commit bytes:             %s\n' "$baseline_bytes"
printf 'Binary-with-mKyber Commit bytes:       %s\n' "$mkyber_bytes"
printf 'Adaptive Commit bytes (with transition): %s\n' "$adaptive_bytes"
printf 'Authenticated transition bytes:        %s\n' "$transition_bytes"
printf 'Post-transition updates accepted:      %s\n' "$post_transition_updates"
printf 'Matched-window saving:                 %s bytes\n' "$matched_saving"
printf 'Amortized-preflight saving:            %s bytes\n' "$amortized_saving"
printf '\nEvidence:\n'
printf '  CSV/JSON: %s/\n' "$comparison_output_dir"
printf '  Report/SVG: %s/\n' "$comparison_report_dir"

if [[ "$generate_thesis_tables" == true ]]; then
    environment_output_dir="$output_dir/environment"
    rss_output_dir="$output_dir/rss-comparison"
    rss_report_dir="$report_dir/rss-comparison"
    normal_output_dir="$output_dir/normal-operations"
    normal_report_dir="$report_dir/normal-operations"
    transition_output_dir="$output_dir/transition-maturity"
    transition_report_dir="$report_dir/transition-maturity"
    model_output_dir="$output_dir/model-errors"
    model_report_dir="$report_dir/model-errors"
    thesis_output_dir="$output_dir/thesis-tables"
    thesis_report_dir="$report_dir/thesis-tables"

    printf '\n=== Generate Thesis Tables ===\n'
    run_step 'Collect environment and direct-child RSS' env CARGO_TERM_COLOR=never cargo run --quiet -p report --bin collect_environment \
        --release --locked --offline -- \
        --output "$environment_output_dir" \
        --label "$run_name" \
        --repetitions 1 \
        -- target/release/compare_modes \
        --baseline-config configs/task62-baseline.toml \
        --mkyber-config configs/task62-mkyber.toml \
        --adaptive-config configs/task62-adaptive.toml \
        --initial-members 128 \
        --maximum-members 128 \
        --operations 3 \
        --regions 2 \
        --output "$rss_output_dir" \
        --report "$rss_report_dir"
    run_step 'Generate normal-operation table' env CARGO_TERM_COLOR=never cargo run --quiet -p report --bin generate_normal_operations \
        --release --locked --offline -- \
        --repetitions 1 \
        --output "$normal_output_dir" \
        --report "$normal_report_dir"
    run_step 'Generate transition and maturity table' env CARGO_TERM_COLOR=never cargo run --quiet -p report --bin generate_transition_tables \
        --release --locked --offline -- \
        --task61-summary "$task61_summary" \
        --output "$transition_output_dir" \
        --report "$transition_report_dir"
    run_step 'Generate byte and time model table' env CARGO_TERM_COLOR=never cargo run --quiet -p report --bin generate_model_errors \
        --release --locked --offline -- \
        --environment-json "$environment_output_dir/environment.json" \
        --normal-operations-csv "$normal_output_dir/normal_operations.csv" \
        --transition-maturity-json "$transition_output_dir/transition_maturity.json" \
        --output "$model_output_dir" \
        --report "$model_report_dir" \
        --timing-samples 25
    run_step 'Generate final combined thesis tables' env CARGO_TERM_COLOR=never cargo run --quiet -p report --bin generate_thesis_tables \
        --release --locked --offline -- \
        --comparison-csv "$comparison_csv" \
        --environment-json "$environment_output_dir/environment.json" \
        --normal-operations-csv "$normal_output_dir/normal_operations.csv" \
        --transition-maturity-json "$transition_output_dir/transition_maturity.json" \
        --model-errors-json "$model_output_dir/model_errors.json" \
        --output "$thesis_output_dir" \
        --report "$thesis_report_dir"

    [[ -s "$thesis_output_dir/thesis_tables.csv" ]] || fail 'final thesis-table CSV was not created'
    [[ -s "$thesis_output_dir/thesis_tables.json" ]] || fail 'final thesis-table JSON was not created'
    [[ -s "$thesis_report_dir/thesis_tables.md" ]] || fail 'final thesis-table Markdown was not created'
    thesis_rows=$(sed -n '2,$p' "$thesis_output_dir/thesis_tables.csv" | wc -l | tr -d ' ')
    [[ "$thesis_rows" == '208' ]] || fail "expected 208 final thesis-table rows, observed $thesis_rows"
    printf '\nFinal thesis tables (%s rows):\n' "$thesis_rows"
    printf '  CSV/JSON: %s/\n' "$thesis_output_dir"
    printf '  Markdown: %s/thesis_tables.md\n' "$thesis_report_dir"
fi

printf '\nScope: real local protocol execution; lifecycle timing is environment-dependent.\n'
printf 'The experimental modes are thesis-local and non-interoperable with stock MLS.\n'
