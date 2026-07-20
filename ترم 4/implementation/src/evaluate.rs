#![forbid(unsafe_code)]

//! Public snapshot validation and fresh baseline recreation for transition evaluation.
//!
//! A Task 27 public bootstrap snapshot deliberately excludes private MLS
//! state and key-generation entropy. It can therefore validate public input
//! and drive a fresh, verified baseline bootstrap with the same public
//! committer schedule, but it cannot restore the original MLS group or begin
//! an experimental transition. Tasks 52 through 55 add workload execution,
//! measurements, and reports on top of this safe boundary.

use std::{
    collections::BTreeSet,
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
};

use serde::Serialize;
use thiserror::Error;

use crate::bootstrap::{
    bootstrap_128, validate_snapshot_output_directory, verify_bootstrap_128, BootstrapError,
    BootstrapOptions, BootstrapVerificationError, PublicBootstrapSnapshot, SnapshotError,
    BASELINE_TREE_ARITY, BOOTSTRAP_MEMBER_COUNT, BOOTSTRAP_SUMMARY_FILE_NAME,
};

/// Exact schema identifier accepted for a public bootstrap snapshot.
pub const PUBLIC_BOOTSTRAP_SNAPSHOT_FORMAT: &str =
    "adaptive-hybrid-mls/bootstrap-public-snapshot-v1";
/// Stable name of the Task 51 public fresh-recreation manifest.
pub const TRANSITION_RECREATION_FILE_NAME: &str = "transition_recreation.json";

const BASELINE_MODE: &str = "baseline-binary-mls";
const KEY_GENERATION_ENTROPY_POLICY: &str =
    "operating-system RNG; not persisted and not reconstructible from this snapshot";

/// Validated public input needed to recreate a fresh baseline experiment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotRecreationPlan {
    /// Public schedule seed retained by the original snapshot.
    pub schedule_seed: u64,
    /// Public source epoch, retained for provenance only.
    pub source_epoch: u64,
    /// Public source tree hash retained for provenance only.
    pub source_tree_hash_hex: String,
}

/// Public result of a fresh baseline recreation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FreshBaselineRecreation {
    /// Versioned format for Task 51's safe manifest.
    pub format: String,
    /// Public facts identifying the source snapshot; no local path is retained.
    pub source: SourceSnapshotFacts,
    /// Public facts measured from the newly created baseline group.
    pub recreated: RecreatedBaselineFacts,
    /// Explicit non-restoration and deferred-workload limitations.
    pub limitations: Vec<String>,
}

/// Safe public identity of the source snapshot.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SourceSnapshotFacts {
    /// Source snapshot schema identifier.
    pub format: String,
    /// Source's public final MLS epoch.
    pub epoch: u64,
    /// Source's public authenticated tree hash.
    pub tree_hash_hex: String,
}

/// Safe public facts measured from the newly created baseline group.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RecreatedBaselineFacts {
    /// Public schedule seed reused for this fresh construction.
    pub schedule_seed: u64,
    /// Number of verified active members.
    pub member_count: usize,
    /// Number of public Add commits used to form the fresh group.
    pub add_commit_count: usize,
    /// Number of distinct public committers in the fresh bootstrap schedule.
    pub distinct_committer_count: usize,
    /// Verified public MLS epoch of the new group.
    pub epoch: u64,
    /// Verified public authenticated tree hash of the new group.
    pub tree_hash_hex: String,
}

/// Errors from loading, validating, recreating, or writing public evaluation input.
#[derive(Debug, Error)]
pub enum EvaluationError {
    /// Public snapshot bytes could not be read.
    #[error("the public bootstrap snapshot could not be read")]
    SnapshotRead(#[source] std::io::Error),
    /// Public snapshot JSON did not match the expected schema.
    #[error("the public bootstrap snapshot JSON is invalid")]
    SnapshotDecode(#[source] serde_json::Error),
    /// A public field violates the fixed Task 25 snapshot contract.
    #[error("the public bootstrap snapshot is invalid: {reason}")]
    InvalidSnapshot {
        /// Public validation category; it never includes key material.
        reason: &'static str,
    },
    /// The requested output location is not within the public output boundary.
    #[error("the transition recreation output directory is unsafe")]
    UnsafeOutputDirectory,
    /// The fresh baseline bootstrap failed.
    #[error("fresh baseline recreation failed")]
    Bootstrap(#[source] BootstrapError),
    /// Fresh baseline public-state verification failed.
    #[error("fresh baseline recreation verification failed")]
    Verification(#[source] BootstrapVerificationError),
    /// The recreation manifest could not be serialized.
    #[error("the public transition recreation manifest could not be serialized")]
    Serialization(#[source] serde_json::Error),
    /// The recreation manifest could not be written without overwriting prior evidence.
    #[error("the public transition recreation manifest could not be written")]
    OutputWrite(#[source] std::io::Error),
}

/// Reads and validates a public bootstrap snapshot without restoring any secret state.
pub fn load_snapshot_recreation_plan(
    path: &Path,
) -> Result<SnapshotRecreationPlan, EvaluationError> {
    let bytes = fs::read(path).map_err(EvaluationError::SnapshotRead)?;
    let snapshot = serde_json::from_slice::<PublicBootstrapSnapshot>(&bytes)
        .map_err(EvaluationError::SnapshotDecode)?;
    snapshot_recreation_plan(&snapshot)
}

/// Validates public snapshot invariants and creates a fresh-recreation plan.
pub fn snapshot_recreation_plan(
    snapshot: &PublicBootstrapSnapshot,
) -> Result<SnapshotRecreationPlan, EvaluationError> {
    if snapshot.format != PUBLIC_BOOTSTRAP_SNAPSHOT_FORMAT {
        return Err(invalid_snapshot("unsupported snapshot format"));
    }
    if snapshot.configuration.mode != BASELINE_MODE
        || snapshot.configuration.ciphersuite_id != 0x0001
        || snapshot.configuration.tree_arity != BASELINE_TREE_ARITY
        || snapshot.configuration.member_count != BOOTSTRAP_MEMBER_COUNT
    {
        return Err(invalid_snapshot("unsupported baseline configuration"));
    }
    if snapshot.reproducibility.key_generation_entropy_policy != KEY_GENERATION_ENTROPY_POLICY {
        return Err(invalid_snapshot(
            "missing required entropy-separation statement",
        ));
    }
    if snapshot.group.epoch != (BOOTSTRAP_MEMBER_COUNT - 1) as u64 {
        return Err(invalid_snapshot("unexpected source epoch"));
    }
    canonical_nonempty_hex(&snapshot.group.group_id_hex)?;
    canonical_nonempty_hex(&snapshot.group.group_context_tls_hex)?;
    canonical_nonempty_hex(&snapshot.group.tree_hash_hex)?;
    canonical_nonempty_hex(&snapshot.group.ratchet_tree_tls_hex)?;
    let expected_leaves: Vec<u32> = (0..BOOTSTRAP_MEMBER_COUNT as u32).collect();
    if snapshot.group.occupied_leaf_indices != expected_leaves {
        return Err(invalid_snapshot("unexpected occupied leaf indexes"));
    }
    if snapshot.added_member_key_packages.len() != BOOTSTRAP_MEMBER_COUNT - 1 {
        return Err(invalid_snapshot("unexpected public KeyPackage count"));
    }
    for (offset, key_package) in snapshot.added_member_key_packages.iter().enumerate() {
        let member_index = offset + 1;
        if key_package.member_index != member_index
            || key_package.identity != format!("bootstrap-member-{member_index:03}")
        {
            return Err(invalid_snapshot("noncanonical public KeyPackage ordering"));
        }
        canonical_nonempty_hex(&key_package.tls_hex)?;
    }
    Ok(SnapshotRecreationPlan {
        schedule_seed: snapshot.reproducibility.schedule_seed,
        source_epoch: snapshot.group.epoch,
        source_tree_hash_hex: snapshot.group.tree_hash_hex.clone(),
    })
}

/// Creates and verifies a fresh baseline group using only public snapshot inputs.
///
/// The resulting group has new operating-system-generated key material. It is
/// not an exact restoration of the source group and no private state is read,
/// serialized, or returned.
pub fn recreate_fresh_baseline(
    plan: &SnapshotRecreationPlan,
) -> Result<FreshBaselineRecreation, EvaluationError> {
    let options = BootstrapOptions {
        members: BOOTSTRAP_MEMBER_COUNT,
        schedule_seed: plan.schedule_seed,
    };
    let (mut clients, result) = bootstrap_128(&options).map_err(EvaluationError::Bootstrap)?;
    let verification = verify_bootstrap_128(&mut clients).map_err(EvaluationError::Verification)?;
    drop(clients);

    Ok(FreshBaselineRecreation {
        format: "adaptive-hybrid-mls/transition-recreation-v1".to_owned(),
        source: SourceSnapshotFacts {
            format: PUBLIC_BOOTSTRAP_SNAPSHOT_FORMAT.to_owned(),
            epoch: plan.source_epoch,
            tree_hash_hex: plan.source_tree_hash_hex.clone(),
        },
        recreated: RecreatedBaselineFacts {
            schedule_seed: plan.schedule_seed,
            member_count: BOOTSTRAP_MEMBER_COUNT,
            add_commit_count: result.add_commit_count,
            distinct_committer_count: result.committer_indices.iter().collect::<BTreeSet<_>>().len(),
            epoch: verification.epoch,
            tree_hash_hex: hex::encode(verification.tree_hash),
        },
        limitations: vec![
            "Fresh recreation uses operating-system RNG and does not restore source MLS private state or keys."
                .to_owned(),
            "No workload, transition commit, TreeCover retirement, metric aggregation, or report is executed before Tasks 52 through 55."
                .to_owned(),
            format!(
                "The source bootstrap summary filename is `{BOOTSTRAP_SUMMARY_FILE_NAME}`; it is not required for recreation."
            ),
        ],
    })
}

/// Writes a public recreation manifest once under `output/<run>`.
pub fn write_fresh_recreation_manifest(
    output_directory: &Path,
    recreation: &FreshBaselineRecreation,
) -> Result<(), EvaluationError> {
    validate_snapshot_output_directory(output_directory)
        .map_err(|_: SnapshotError| EvaluationError::UnsafeOutputDirectory)?;
    fs::create_dir_all(output_directory).map_err(EvaluationError::OutputWrite)?;
    let path = output_directory.join(TRANSITION_RECREATION_FILE_NAME);
    let bytes = serde_json::to_vec_pretty(recreation).map_err(EvaluationError::Serialization)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(EvaluationError::OutputWrite)?;
    file.write_all(&bytes)
        .map_err(EvaluationError::OutputWrite)?;
    file.write_all(b"\n").map_err(EvaluationError::OutputWrite)
}

fn canonical_nonempty_hex(value: &str) -> Result<(), EvaluationError> {
    if value.is_empty() {
        return Err(invalid_snapshot("empty required hexadecimal field"));
    }
    let decoded =
        hex::decode(value).map_err(|_| invalid_snapshot("malformed hexadecimal field"))?;
    if hex::encode(decoded) != value {
        return Err(invalid_snapshot("noncanonical hexadecimal field"));
    }
    Ok(())
}

fn invalid_snapshot(reason: &'static str) -> EvaluationError {
    EvaluationError::InvalidSnapshot { reason }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bootstrap::{
        PublicSnapshotConfiguration, PublicSnapshotGroup, PublicSnapshotKeyPackage,
        PublicSnapshotReproducibility,
    };

    fn snapshot() -> PublicBootstrapSnapshot {
        PublicBootstrapSnapshot {
            format: PUBLIC_BOOTSTRAP_SNAPSHOT_FORMAT.to_owned(),
            configuration: PublicSnapshotConfiguration {
                mode: BASELINE_MODE.to_owned(),
                ciphersuite_id: 0x0001,
                tree_arity: BASELINE_TREE_ARITY,
                member_count: BOOTSTRAP_MEMBER_COUNT,
            },
            reproducibility: PublicSnapshotReproducibility {
                schedule_seed: 42,
                key_generation_entropy_policy: KEY_GENERATION_ENTROPY_POLICY.to_owned(),
            },
            group: PublicSnapshotGroup {
                group_id_hex: "00".to_owned(),
                epoch: 127,
                group_context_tls_hex: "01".to_owned(),
                tree_hash_hex: "02".to_owned(),
                ratchet_tree_tls_hex: "03".to_owned(),
                occupied_leaf_indices: (0..128).collect(),
            },
            added_member_key_packages: (1..128)
                .map(|member_index| PublicSnapshotKeyPackage {
                    member_index,
                    identity: format!("bootstrap-member-{member_index:03}"),
                    tls_hex: "04".to_owned(),
                })
                .collect(),
        }
    }

    #[test]
    fn public_snapshot_forms_a_fresh_recreation_plan_without_secret_inputs() {
        let plan = snapshot_recreation_plan(&snapshot()).expect("canonical public snapshot");
        assert_eq!(plan.schedule_seed, 42);
        assert_eq!(plan.source_epoch, 127);
        assert_eq!(plan.source_tree_hash_hex, "02");
    }

    #[test]
    fn snapshot_validation_rejects_noncanonical_or_incomplete_public_facts() {
        let mut bad_hex = snapshot();
        bad_hex.group.tree_hash_hex = "0A".to_owned();
        assert!(matches!(
            snapshot_recreation_plan(&bad_hex),
            Err(EvaluationError::InvalidSnapshot {
                reason: "noncanonical hexadecimal field"
            })
        ));

        let mut bad_package = snapshot();
        bad_package.added_member_key_packages[0].identity = "other".to_owned();
        assert!(matches!(
            snapshot_recreation_plan(&bad_package),
            Err(EvaluationError::InvalidSnapshot {
                reason: "noncanonical public KeyPackage ordering"
            })
        ));

        let mut unknown_field = serde_json::to_value(snapshot()).expect("public snapshot JSON");
        unknown_field
            .as_object_mut()
            .expect("snapshot object")
            .insert("unexpected".to_owned(), serde_json::Value::Null);
        assert!(serde_json::from_value::<PublicBootstrapSnapshot>(unknown_field).is_err());
    }
}
