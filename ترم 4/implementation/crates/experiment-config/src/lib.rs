#![forbid(unsafe_code)]

//! Typed, validated public experiment configuration.
//!
//! This crate contains no private key material and deliberately provides no
//! implicit Delta default: ADR 0006 requires exactly one configured Delta.

use std::path::{Component, Path};

use serde::Deserialize;
use thiserror::Error;

/// Public execution mode selected for an experiment.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum ExperimentMode {
    /// Unmodified RFC 9420 binary MLS behavior.
    BaselineBinaryMls,
    /// Experimental binary MLS with mKyber delivery.
    BinaryMlsWithMkyber,
    /// Experimental binary-to-quaternary transition evaluation.
    AdaptiveBinaryToQuaternaryMls,
}

/// Complete public configuration accepted by the future experiment binaries.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ExperimentConfig {
    /// Chosen protocol mode.
    pub mode: ExperimentMode,
    /// Public group-shape parameters.
    pub group: GroupConfig,
    /// Transition policy and fixed-point thresholds.
    pub transition: TransitionConfig,
    /// Public workload and repetition controls.
    pub execution: ExecutionConfig,
    /// Relative output/report paths.
    pub output: OutputConfig,
}

/// Public group-shape parameters.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct GroupConfig {
    /// Required minimum group size for the first transition experiment.
    pub target_group_size: u32,
    /// Active tree arity before transition.
    pub current_arity: u8,
    /// Candidate tree arity.
    pub candidate_arity: u8,
}

/// Transition-policy parameters from ADR 0006.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TransitionConfig {
    /// Number of accepted post-warmup commits retained in the policy window.
    pub window_accepted_commits: u32,
    /// Consecutive accepted epochs at or above the target group size.
    pub stable_epoch_count: u32,
    /// Minimum impactful commits in the policy window.
    pub q_min: u32,
    /// New-tree threshold in microfraction units, where one is 1_000_000.
    pub theta_new_micro: u32,
    /// Old-TreeCover threshold in microfraction units, where one is 1_000_000.
    pub theta_old_micro: u32,
    /// Absolute Delta, mutually exclusive with `delta_percent_of_transition_micro`.
    pub delta_bytes: Option<u64>,
    /// Delta as a micro-percent of preflight transition bytes, mutually exclusive with `delta_bytes`.
    pub delta_percent_of_transition_micro: Option<u32>,
}

/// Public workload and reproducibility controls.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ExecutionConfig {
    /// Accepted commits excluded from policy and aggregate timing statistics.
    pub warmup_accepted_commits: u32,
    /// Number of independently seeded runs per configuration.
    pub repetitions: u32,
    /// Public workload seed; it must not reconstruct private key material.
    pub workload_seed: u64,
}

/// Relative output locations for generated public artifacts.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct OutputConfig {
    /// Relative directory below the repository for generated output.
    pub output_directory: String,
    /// Relative directory below the repository for generated reports.
    pub report_directory: String,
}

/// Errors returned when public configuration is malformed or unsafe.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// TOML could not be decoded into the public configuration schema.
    #[error("configuration TOML is invalid")]
    Parse(#[from] toml::de::Error),
    /// A field violates a documented configuration invariant.
    #[error("invalid configuration field {field}: {reason}")]
    Invalid {
        /// Public field name.
        field: &'static str,
        /// Public reason that does not include secret material.
        reason: &'static str,
    },
}

impl ExperimentConfig {
    /// Parses and validates public TOML configuration.
    pub fn parse_toml(input: &str) -> Result<Self, ConfigError> {
        let config: Self = toml::from_str(input)?;
        config.validate()?;
        Ok(config)
    }

    /// Validates the fixed Phase 1 configuration invariants.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.group.target_group_size == 0 {
            return Err(invalid("group.target_group_size", "must be positive"));
        }
        if self.group.current_arity != 2 || self.group.candidate_arity != 4 {
            return Err(invalid(
                "group arity",
                "the first experiment supports only a 2-to-4 transition",
            ));
        }
        if self.transition.window_accepted_commits == 0 {
            return Err(invalid(
                "transition.window_accepted_commits",
                "must be positive",
            ));
        }
        if self.transition.stable_epoch_count == 0 || self.transition.q_min == 0 {
            return Err(invalid("transition sample controls", "must be positive"));
        }
        if self.transition.theta_new_micro > 1_000_000
            || self.transition.theta_old_micro > 1_000_000
        {
            return Err(invalid(
                "transition thresholds",
                "must be between zero and one million microfraction units",
            ));
        }
        if matches!(
            (
                self.transition.delta_bytes.is_some(),
                self.transition.delta_percent_of_transition_micro.is_some(),
            ),
            (false, false) | (true, true)
        ) {
            return Err(invalid(
                "transition Delta",
                "exactly one Delta form must be configured",
            ));
        }
        if self.execution.repetitions == 0 {
            return Err(invalid("execution.repetitions", "must be positive"));
        }
        validate_relative_path("output.output_directory", &self.output.output_directory)?;
        validate_relative_path("output.report_directory", &self.output.report_directory)?;
        Ok(())
    }
}

fn invalid(field: &'static str, reason: &'static str) -> ConfigError {
    ConfigError::Invalid { field, reason }
}

fn validate_relative_path(field: &'static str, value: &str) -> Result<(), ConfigError> {
    let path = Path::new(value);
    if value.is_empty()
        || path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::Prefix(_) | Component::RootDir
            )
        })
    {
        return Err(invalid(
            field,
            "must be a non-empty relative path without parent traversal",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::ExperimentConfig;

    const VALID_CONFIG: &str = r#"
mode = "adaptive-binary-to-quaternary-mls"

[group]
target_group_size = 128
current_arity = 2
candidate_arity = 4

[transition]
window_accepted_commits = 20
stable_epoch_count = 5
q_min = 5
theta_new_micro = 700000
theta_old_micro = 500000
delta_bytes = 2000

[execution]
warmup_accepted_commits = 10
repetitions = 30
workload_seed = 42

[output]
output_directory = "output/run-001"
report_directory = "report/run-001"
"#;

    #[test]
    fn accepts_a_complete_public_configuration() {
        let config = ExperimentConfig::parse_toml(VALID_CONFIG).expect("valid configuration");

        assert_eq!(config.group.target_group_size, 128);
        assert_eq!(config.transition.delta_bytes, Some(2000));
    }

    #[test]
    fn rejects_ambiguous_delta_configuration() {
        let ambiguous = VALID_CONFIG.replace(
            "delta_bytes = 2000",
            "delta_bytes = 2000\ndelta_percent_of_transition_micro = 100000",
        );

        assert!(ExperimentConfig::parse_toml(&ambiguous).is_err());
    }

    #[test]
    fn rejects_parent_traversal_in_output_paths() {
        let unsafe_path = VALID_CONFIG.replace(
            "output_directory = \"output/run-001\"",
            "output_directory = \"../output/run-001\"",
        );

        assert!(ExperimentConfig::parse_toml(&unsafe_path).is_err());
    }
}
