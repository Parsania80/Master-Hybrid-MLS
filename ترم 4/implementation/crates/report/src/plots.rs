#![forbid(unsafe_code)]

//! Task 56 plot-ready records and dependency-free SVG output.
//!
//! Numeric values are emitted only when the Task 54 record observed them. An
//! unavailable metric gets an explicit CSV state and an SVG availability card;
//! it is never rendered as zero.

use std::{collections::BTreeSet, fmt::Write as FmtWrite, path::Path};

use csv::WriterBuilder;
use serde::Serialize;
use thiserror::Error;

use crate::{
    generation::{validate_artifact_directory, write_new, ReportArtifactError},
    MetricAvailability, MetricUnavailableReason, PerCommitMetricRecord, PerCommitSchemaError,
};
use simulation::{BaselineWorkloadConfig, BaselineWorkloadExecution};

/// Version of the Task 56 plot-data schema.
pub const PLOT_DATA_SCHEMA_VERSION: u16 = 1;
/// Long-form typed series generated for every accepted record.
pub const PLOT_DATA_FILE_NAME: &str = "plot_data.csv";
/// Public baseline Commit and Welcome byte chart.
pub const BYTES_SVG_FILE_NAME: &str = "bytes.svg";
/// Candidate-cost availability or observed-cost chart.
pub const COSTS_SVG_FILE_NAME: &str = "costs.svg";
/// Preflight/realized-saving availability or observed-saving chart.
pub const SAVINGS_SVG_FILE_NAME: &str = "savings.svg";
/// New/old maturity availability or observed-maturity chart.
pub const MATURITY_SVG_FILE_NAME: &str = "maturity.svg";
/// TreeCover-size availability or observed-size chart.
pub const TREECOVER_SIZE_SVG_FILE_NAME: &str = "treecover_size.svg";
/// Accepted lifecycle timing chart.
pub const TIMINGS_SVG_FILE_NAME: &str = "timings.svg";

/// Locations of Task 56 public output.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlotArtifactPaths {
    /// Long-form, typed plot points under `output/<run>`.
    pub plot_data_csv: std::path::PathBuf,
    /// Byte chart under `report/<run>`.
    pub bytes_svg: std::path::PathBuf,
    /// Cost chart or explicit unavailability card under `report/<run>`.
    pub costs_svg: std::path::PathBuf,
    /// Saving chart or explicit unavailability card under `report/<run>`.
    pub savings_svg: std::path::PathBuf,
    /// Maturity chart or explicit unavailability card under `report/<run>`.
    pub maturity_svg: std::path::PathBuf,
    /// TreeCover-size chart or explicit unavailability card under `report/<run>`.
    pub treecover_size_svg: std::path::PathBuf,
    /// Timing chart under `report/<run>`.
    pub timings_svg: std::path::PathBuf,
}

/// Errors while producing Task 56 public artifacts.
#[derive(Debug, Error)]
pub enum PlotArtifactError {
    /// Task 54 rejected the supplied public workload records.
    #[error("plot record construction failed")]
    Schema(#[source] PerCommitSchemaError),
    /// The shared report writer rejected an output path or write.
    #[error("plot artifact write failed")]
    Report(#[from] ReportArtifactError),
    /// Long-form plot CSV serialization failed.
    #[error("plot CSV serialization failed")]
    Csv(#[source] csv::Error),
}

/// Writes plot-ready data and SVG output for an accepted baseline workload.
///
/// Only the baseline byte/timing/delivery/member observations have numeric
/// values at this boundary. Future instrumentation can replace unavailable
/// points through the existing Task 54 attachment types without altering the
/// CSV representation.
pub fn write_baseline_plot_artifacts(
    workload: &BaselineWorkloadConfig,
    execution: &BaselineWorkloadExecution,
    output_directory: &Path,
    report_directory: &Path,
) -> Result<PlotArtifactPaths, PlotArtifactError> {
    validate_artifact_directory(output_directory, "output", "machine-readable")?;
    validate_artifact_directory(report_directory, "report", "SVG")?;
    let records = PerCommitMetricRecord::from_baseline_workload(workload, execution)
        .map_err(PlotArtifactError::Schema)?;
    let paths = PlotArtifactPaths {
        plot_data_csv: output_directory.join(PLOT_DATA_FILE_NAME),
        bytes_svg: report_directory.join(BYTES_SVG_FILE_NAME),
        costs_svg: report_directory.join(COSTS_SVG_FILE_NAME),
        savings_svg: report_directory.join(SAVINGS_SVG_FILE_NAME),
        maturity_svg: report_directory.join(MATURITY_SVG_FILE_NAME),
        treecover_size_svg: report_directory.join(TREECOVER_SIZE_SVG_FILE_NAME),
        timings_svg: report_directory.join(TIMINGS_SVG_FILE_NAME),
    };
    for path in [
        &paths.plot_data_csv,
        &paths.bytes_svg,
        &paths.costs_svg,
        &paths.savings_svg,
        &paths.maturity_svg,
        &paths.treecover_size_svg,
        &paths.timings_svg,
    ] {
        if path.exists() {
            return Err(PlotArtifactError::Report(
                ReportArtifactError::ArtifactAlreadyExists,
            ));
        }
    }
    std::fs::create_dir_all(output_directory)
        .map_err(|error| PlotArtifactError::Report(ReportArtifactError::Write(error)))?;
    std::fs::create_dir_all(report_directory)
        .map_err(|error| PlotArtifactError::Report(ReportArtifactError::Write(error)))?;

    let rows = plot_rows(&records);
    write_new(&paths.plot_data_csv, &plot_csv(&rows)?)?;
    write_new(&paths.bytes_svg, &bytes_svg(&records).into_bytes())?;
    write_new(
        &paths.costs_svg,
        &availability_svg("Candidate delivery costs", &rows, "candidate_cost_bytes").into_bytes(),
    )?;
    write_new(
        &paths.savings_svg,
        &availability_svg("Transition savings", &rows, "preflight_savings_bytes").into_bytes(),
    )?;
    write_new(
        &paths.maturity_svg,
        &availability_svg("TreeCover maturity", &rows, "new_tree_maturity_micro").into_bytes(),
    )?;
    write_new(
        &paths.treecover_size_svg,
        &availability_svg("TreeCover size", &rows, "treecover_node_count").into_bytes(),
    )?;
    write_new(&paths.timings_svg, &timings_svg(&records).into_bytes())?;
    Ok(paths)
}

/// One typed long-form public plot point.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PlotDataRow {
    /// Plot-data schema version.
    pub schema_version: u16,
    /// One-based accepted commit sequence.
    pub sequence: u32,
    /// Public epoch after the accepted commit.
    pub epoch_after: u64,
    /// Stable metric-family name for plotting and filtering.
    pub metric_family: &'static str,
    /// Unit used by numeric values, when available.
    pub unit: &'static str,
    /// `measured`, `observed`, `not_applicable`, or `unavailable`.
    pub value_state: &'static str,
    /// Numeric point only when observed; unavailable is never a zero fallback.
    pub numeric_value: Option<u128>,
    /// Typed unavailability or non-applicability reason.
    pub reason: Option<&'static str>,
    /// Origin of the point for report provenance.
    pub provenance: &'static str,
}

fn plot_rows(records: &[PerCommitMetricRecord]) -> Vec<PlotDataRow> {
    let mut rows = Vec::with_capacity(records.len().saturating_mul(12));
    for record in records {
        let identity = (&record.identity.sequence, &record.identity.epoch_after);
        rows.push(observed_row(
            *identity.0,
            *identity.1,
            "baseline_commit_bytes",
            "bytes",
            u128::from(record.bytes.emitted_baseline_commit_bytes),
            "emitted_baseline_commit",
            "measured",
        ));
        rows.push(match record.bytes.emitted_welcome_bytes {
            Some(bytes) => observed_row(
                *identity.0,
                *identity.1,
                "welcome_bytes",
                "bytes",
                u128::from(bytes),
                "emitted_welcome",
                "measured",
            ),
            None => unavailable_row(
                *identity.0,
                *identity.1,
                "welcome_bytes",
                "bytes",
                "not_applicable",
                "NoWelcomeEmitted",
                "baseline_workload_measurement",
            ),
        });
        rows.push(observed_row(
            *identity.0,
            *identity.1,
            "accepted_lifecycle_nanoseconds",
            "nanoseconds",
            record.timing.accepted_lifecycle_elapsed_nanoseconds,
            "accepted_lifecycle_measurement",
            "observed",
        ));
        rows.push(observed_row(
            *identity.0,
            *identity.1,
            "active_member_count",
            "members",
            u128::from(record.identity.active_member_count_after),
            "accepted_workload_state",
            "observed",
        ));
        rows.push(observed_row(
            *identity.0,
            *identity.1,
            "direct_commit_delivery_count",
            "deliveries",
            u128::from(record.direct_commit_delivery_count),
            "accepted_workload_measurement",
            "observed",
        ));
        rows.push(observed_row(
            *identity.0,
            *identity.1,
            "welcome_join_count",
            "joins",
            u128::from(record.welcome_join_count),
            "accepted_workload_measurement",
            "observed",
        ));
        rows.push(metric_availability_row(
            *identity.0,
            *identity.1,
            "candidate_cost_bytes",
            "bytes",
            &record.bytes.comparison,
            "candidate_byte_comparison",
        ));
        rows.push(metric_availability_row(
            *identity.0,
            *identity.1,
            "preflight_savings_bytes",
            "bytes",
            &record.policy_window,
            "transition_policy",
        ));
        rows.push(metric_availability_row(
            *identity.0,
            *identity.1,
            "new_tree_maturity_micro",
            "microfraction",
            &record.retirement,
            "treecover_retirement",
        ));
        rows.push(metric_availability_row(
            *identity.0,
            *identity.1,
            "old_tree_maturity_micro",
            "microfraction",
            &record.retirement,
            "treecover_retirement",
        ));
        rows.push(metric_availability_row(
            *identity.0,
            *identity.1,
            "treecover_node_count",
            "nodes",
            &record.transition,
            "authenticated_transition",
        ));
        rows.push(metric_availability_row(
            *identity.0,
            *identity.1,
            "transition_preflight_bytes",
            "bytes",
            &record.transition,
            "authenticated_transition",
        ));
    }
    rows
}

fn observed_row(
    sequence: u32,
    epoch_after: u64,
    metric_family: &'static str,
    unit: &'static str,
    numeric_value: u128,
    provenance: &'static str,
    value_state: &'static str,
) -> PlotDataRow {
    PlotDataRow {
        schema_version: PLOT_DATA_SCHEMA_VERSION,
        sequence,
        epoch_after,
        metric_family,
        unit,
        value_state,
        numeric_value: Some(numeric_value),
        reason: None,
        provenance,
    }
}

fn unavailable_row(
    sequence: u32,
    epoch_after: u64,
    metric_family: &'static str,
    unit: &'static str,
    value_state: &'static str,
    reason: &'static str,
    provenance: &'static str,
) -> PlotDataRow {
    PlotDataRow {
        schema_version: PLOT_DATA_SCHEMA_VERSION,
        sequence,
        epoch_after,
        metric_family,
        unit,
        value_state,
        numeric_value: None,
        reason: Some(reason),
        provenance,
    }
}

fn metric_availability_row<T>(
    sequence: u32,
    epoch_after: u64,
    metric_family: &'static str,
    unit: &'static str,
    availability: &MetricAvailability<T>,
    provenance: &'static str,
) -> PlotDataRow {
    match availability {
        MetricAvailability::Observed(_) => unavailable_row(
            sequence,
            epoch_after,
            metric_family,
            unit,
            "unavailable",
            "ObservedValueRequiresTask56TypedExtractor",
            provenance,
        ),
        MetricAvailability::Unavailable(reason) => unavailable_row(
            sequence,
            epoch_after,
            metric_family,
            unit,
            "unavailable",
            unavailable_reason_name(*reason),
            provenance,
        ),
    }
}

fn unavailable_reason_name(reason: MetricUnavailableReason) -> &'static str {
    match reason {
        MetricUnavailableReason::NotInstrumented => "NotInstrumented",
        MetricUnavailableReason::NotApplicable => "NotApplicable",
        MetricUnavailableReason::RequiresExperimentalFork => "RequiresExperimentalFork",
        MetricUnavailableReason::PolicyWindowNotAttached => "PolicyWindowNotAttached",
        MetricUnavailableReason::TransitionNotStarted => "TransitionNotStarted",
        MetricUnavailableReason::TreeCoverNotRetired => "TreeCoverNotRetired",
        MetricUnavailableReason::UnsupportedNoAuthenticatedRetirementCommit => {
            "UnsupportedNoAuthenticatedRetirementCommit"
        }
    }
}

fn plot_csv(rows: &[PlotDataRow]) -> Result<Vec<u8>, PlotArtifactError> {
    let mut writer = WriterBuilder::new()
        .has_headers(true)
        .from_writer(Vec::new());
    for row in rows {
        writer.serialize(row).map_err(PlotArtifactError::Csv)?;
    }
    writer
        .into_inner()
        .map_err(|error| PlotArtifactError::Csv(error.into_error().into()))
}

fn bytes_svg(records: &[PerCommitMetricRecord]) -> String {
    let mut points = Vec::with_capacity(records.len().saturating_mul(2));
    for record in records {
        points.push((
            record.identity.sequence,
            u128::from(record.bytes.emitted_baseline_commit_bytes),
            "#1d4ed8",
        ));
        if let Some(bytes) = record.bytes.emitted_welcome_bytes {
            points.push((record.identity.sequence, u128::from(bytes), "#0f766e"));
        }
    }
    numeric_bar_svg(
        "Measured baseline Commit and Welcome bytes",
        "bytes",
        &points,
        Some("blue: baseline Commit; green: Welcome"),
    )
}

fn timings_svg(records: &[PerCommitMetricRecord]) -> String {
    let points = records
        .iter()
        .map(|record| {
            (
                record.identity.sequence,
                record.timing.accepted_lifecycle_elapsed_nanoseconds,
                "#7c3aed",
            )
        })
        .collect::<Vec<_>>();
    numeric_bar_svg(
        "Observed accepted lifecycle timing",
        "nanoseconds",
        &points,
        None,
    )
}

fn numeric_bar_svg(
    title: &str,
    unit: &str,
    points: &[(u32, u128, &str)],
    legend: Option<&str>,
) -> String {
    if points.is_empty() {
        return availability_card_svg(title, "No accepted numeric observations", 0);
    }
    let maximum = points.iter().map(|(_, value, _)| *value).max().unwrap_or(0);
    if maximum == 0 {
        return availability_card_svg(title, "All observed values are zero", points.len());
    }
    let left = 70_u32;
    let point_count = u32::try_from(points.len()).unwrap_or(u32::MAX);
    let slot = 38_u32;
    let width = 920_u32.max(
        left.saturating_add(30)
            .saturating_add(point_count.saturating_mul(slot)),
    );
    let height = 360_u32;
    let bottom = 300_u32;
    let chart_height = 220_u32;
    let bar_width = (slot / 2).max(4);
    let right = width.saturating_sub(30);
    let mut svg = svg_start(title, width, height);
    writeln!(
        svg,
        "<line x1=\"{left}\" y1=\"{bottom}\" x2=\"{right}\" y2=\"{bottom}\" class=\"axis\"/>"
    )
    .expect("string write");
    writeln!(
        svg,
        "<line x1=\"{left}\" y1=\"80\" x2=\"{left}\" y2=\"{bottom}\" class=\"axis\"/>"
    )
    .expect("string write");
    writeln!(
        svg,
        "<text x=\"{left}\" y=\"64\" class=\"label\">max: {maximum} {unit}</text>"
    )
    .expect("string write");
    if let Some(legend) = legend {
        writeln!(
            svg,
            "<text x=\"420\" y=\"64\" class=\"label\">{legend}</text>"
        )
        .expect("string write");
    }
    for (index, (sequence, value, color)) in points.iter().enumerate() {
        let x = left
            + 10
            + u32::try_from(index)
                .unwrap_or(u32::MAX)
                .saturating_mul(slot);
        let bar_height = u128::from(chart_height)
            .saturating_mul(*value)
            .checked_div(maximum)
            .unwrap_or(0);
        let bar_height = u32::try_from(bar_height).unwrap_or(chart_height);
        let y = bottom.saturating_sub(bar_height);
        writeln!(svg, "<rect x=\"{x}\" y=\"{y}\" width=\"{bar_width}\" height=\"{bar_height}\" fill=\"{color}\"/>").expect("string write");
        writeln!(
            svg,
            "<text x=\"{x}\" y=\"322\" class=\"tick\">{sequence}</text>"
        )
        .expect("string write");
    }
    writeln!(
        svg,
        "<text x=\"420\" y=\"348\" class=\"label\">accepted commit sequence</text>"
    )
    .expect("string write");
    svg_end(&mut svg);
    svg
}

fn availability_svg(title: &str, rows: &[PlotDataRow], metric_family: &str) -> String {
    let filtered = rows
        .iter()
        .filter(|row| row.metric_family == metric_family)
        .collect::<Vec<_>>();
    let numeric = filtered
        .iter()
        .filter_map(|row| {
            row.numeric_value
                .map(|value| (row.sequence, value, "#2563eb"))
        })
        .collect::<Vec<_>>();
    if !numeric.is_empty() {
        return numeric_bar_svg(title, filtered[0].unit, &numeric, None);
    }
    let reasons = filtered
        .iter()
        .filter_map(|row| row.reason)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let message = if reasons.is_empty() {
        "No records supplied".to_owned()
    } else {
        reasons.join(", ")
    };
    availability_card_svg(title, &message, filtered.len())
}

fn availability_card_svg(title: &str, reason: &str, record_count: usize) -> String {
    let mut svg = svg_start(title, 920, 220);
    writeln!(svg, "<rect x=\"48\" y=\"72\" width=\"824\" height=\"92\" rx=\"8\" fill=\"#fff7ed\" stroke=\"#c2410c\"/>").expect("string write");
    writeln!(
        svg,
        "<text x=\"72\" y=\"110\" class=\"unavailable\">Unavailable — {reason}</text>"
    )
    .expect("string write");
    writeln!(svg, "<text x=\"72\" y=\"142\" class=\"label\">{record_count} accepted records; no synthetic zero or estimate is plotted.</text>").expect("string write");
    svg_end(&mut svg);
    svg
}

fn svg_start(title: &str, width: u32, height: u32) -> String {
    format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"{width}\" height=\"{height}\" viewBox=\"0 0 {width} {height}\" role=\"img\" aria-label=\"{title}\">\n<style>.title{{font:600 20px sans-serif;fill:#111827}}.label{{font:14px sans-serif;fill:#374151}}.tick{{font:12px sans-serif;fill:#4b5563}}.axis{{stroke:#6b7280;stroke-width:1}}.unavailable{{font:600 18px sans-serif;fill:#9a3412}}</style>\n<rect width=\"100%\" height=\"100%\" fill=\"#ffffff\"/>\n<text x=\"48\" y=\"38\" class=\"title\">{title}</text>\n"
    )
}

fn svg_end(svg: &mut String) {
    writeln!(svg, "</svg>").expect("string write");
}

#[cfg(test)]
mod tests {
    use super::*;
    use simulation::{execute_baseline_workload, CommitterStrategy, WorkloadProfile};
    use tempfile::Builder;

    fn config() -> BaselineWorkloadConfig {
        BaselineWorkloadConfig {
            group_id: b"task-56-plots".to_vec(),
            initial_member_count: 2,
            maximum_member_count: 3,
            operation_count: 3,
            region_count: 2,
            committer_strategy: CommitterStrategy::RoundRobin,
            workload_profile: WorkloadProfile::Mixed,
        }
    }

    fn temporary_directory(parent: &str, prefix: &str) -> tempfile::TempDir {
        std::fs::create_dir_all(parent).expect("test parent directory");
        Builder::new()
            .prefix(prefix)
            .tempdir_in(parent)
            .expect("tempdir")
    }

    fn relative_path(directory: &tempfile::TempDir) -> std::path::PathBuf {
        directory
            .path()
            .strip_prefix(std::env::current_dir().expect("current directory"))
            .expect("temporary directory below current directory")
            .to_path_buf()
    }

    #[test]
    fn plot_data_preserves_observed_and_unavailable_states() {
        let execution = execute_baseline_workload(&config()).expect("workload");
        let records =
            PerCommitMetricRecord::from_baseline_workload(&config(), &execution).expect("records");
        let rows = plot_rows(&records);
        assert!(rows.iter().any(|row| {
            row.metric_family == "baseline_commit_bytes"
                && row.value_state == "measured"
                && row.numeric_value.is_some()
        }));
        assert!(rows.iter().any(|row| {
            row.metric_family == "candidate_cost_bytes"
                && row.value_state == "unavailable"
                && row.numeric_value.is_none()
                && row.reason == Some("RequiresExperimentalFork")
        }));
        assert!(rows.iter().any(|row| {
            row.metric_family == "treecover_node_count"
                && row.reason == Some("TransitionNotStarted")
        }));
    }

    #[test]
    fn writes_six_safe_svg_outputs_and_long_form_csv() {
        let output = temporary_directory("output", "task56-output-");
        let report = temporary_directory("report", "task56-report-");
        let execution = execute_baseline_workload(&config()).expect("workload");
        let paths = write_baseline_plot_artifacts(
            &config(),
            &execution,
            &relative_path(&output),
            &relative_path(&report),
        )
        .expect("plot artifacts");
        for path in [
            &paths.plot_data_csv,
            &paths.bytes_svg,
            &paths.costs_svg,
            &paths.savings_svg,
            &paths.maturity_svg,
            &paths.treecover_size_svg,
            &paths.timings_svg,
        ] {
            assert!(path.is_file(), "missing {}", path.display());
        }
        let data = std::fs::read_to_string(&paths.plot_data_csv).expect("plot CSV");
        assert!(data.contains("candidate_cost_bytes"));
        assert!(data.contains("RequiresExperimentalFork"));
        let costs = std::fs::read_to_string(&paths.costs_svg).expect("cost SVG");
        assert!(costs.contains("Unavailable"));
        assert!(costs.contains("RequiresExperimentalFork"));
        let bytes = std::fs::read_to_string(&paths.bytes_svg).expect("byte SVG");
        assert!(bytes.contains("Measured baseline Commit"));
        assert!(bytes.contains("blue: baseline Commit; green: Welcome"));
    }
}
