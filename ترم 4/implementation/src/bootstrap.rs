//! Construction of the baseline 128-member MLS bootstrap group.
//!
//! The public scheduling seed chooses only which existing member stages each
//! Add commit. OpenMLS continues to use its provider's operating-system-backed
//! entropy for credentials, KeyPackages, and MLS cryptographic operations.
//! After successful group verification, Tasks 27 and 28 persist a versioned
//! public snapshot, summary, commit CSV, and Markdown report.

use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Component, Path, PathBuf},
};

use mls_adapter::{
    BaselineClient, BaselineError, BaselineState, InboundEvent, BASELINE_CIPHERSUITE_ID,
};
use serde::Serialize;
use thiserror::Error;

/// The exact group size required by the thesis bootstrap experiment.
pub const BOOTSTRAP_MEMBER_COUNT: usize = 128;
/// The maintained baseline adapter always creates an RFC 9420 binary tree.
pub const BASELINE_TREE_ARITY: u8 = 2;
/// A complete binary tree holding 128 leaves has seven levels above a leaf.
pub const BOOTSTRAP_BINARY_TREE_HEIGHT: u8 = 7;
/// Stable name of the safe public bootstrap snapshot.
pub const PUBLIC_SNAPSHOT_FILE_NAME: &str = "bootstrap_public_snapshot.json";
/// Stable name of the public bootstrap summary.
pub const BOOTSTRAP_SUMMARY_FILE_NAME: &str = "bootstrap_128_summary.json";
/// Stable name of public per-commit bootstrap measurements.
pub const BOOTSTRAP_COMMITS_FILE_NAME: &str = "bootstrap_128_commits.csv";
/// Stable name of the human-readable public bootstrap report.
pub const BOOTSTRAP_REPORT_FILE_NAME: &str = "bootstrap_128_report.md";

/// Public, non-secret options for the baseline bootstrap operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapOptions {
    /// Must be [`BOOTSTRAP_MEMBER_COUNT`] for the first executable.
    pub members: usize,
    /// Public seed used only for the deterministic committer schedule.
    pub schedule_seed: u64,
}

impl BootstrapOptions {
    /// Validates the fixed-scope bootstrap configuration.
    pub fn validate(&self) -> Result<(), BootstrapError> {
        if self.members != BOOTSTRAP_MEMBER_COUNT {
            return Err(BootstrapError::UnsupportedMemberCount {
                requested: self.members,
                required: BOOTSTRAP_MEMBER_COUNT,
            });
        }
        Ok(())
    }
}

/// Public results from a successful construction. No private MLS state,
/// secrets, or entropy are retained here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapResult {
    /// Number of Add commits staged and delivered after group creation.
    pub add_commit_count: usize,
    /// Public indexes of the members that staged each Add commit.
    pub committer_indices: Vec<usize>,
    /// TLS encodings of the public KeyPackages submitted for members 1..127.
    /// The creator is represented by its public leaf in the ratchet tree, not
    /// by an invented KeyPackage that was never used to create the group.
    pub added_member_key_packages: Vec<PublicKeyPackage>,
    /// Public observations for each accepted Add commit.
    pub commit_records: Vec<BootstrapCommitRecord>,
}

/// One actual public KeyPackage supplied in an Add proposal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKeyPackage {
    /// Bootstrap index of the joining member.
    pub member_index: usize,
    /// Canonical TLS encoding of the public RFC 9420 KeyPackage.
    pub tls_bytes: Vec<u8>,
}

/// Public per-commit evidence retained for the bootstrap CSV.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapCommitRecord {
    /// One-based Add-commit sequence number.
    pub sequence: u32,
    /// Public epoch before the Add commit.
    pub epoch_before: u64,
    /// Public epoch after the Add commit.
    pub epoch_after: u64,
    /// Bootstrap member index of the valid committer.
    pub committer_member_index: usize,
    /// Public MLS leaf index of the committer at this bootstrap stage.
    pub committer_leaf_index: u32,
    /// Bootstrap member index added by this commit.
    pub added_member_index: usize,
    /// Actual serialized RFC 9420 Commit byte length.
    pub commit_wire_bytes: usize,
    /// Actual serialized RFC 9420 Welcome byte length.
    pub welcome_wire_bytes: usize,
    /// Number of prior members that processed the Commit wire message.
    pub commit_delivery_recipient_count: usize,
    /// Number of members that joined from the Welcome artifact.
    pub welcome_recipient_count: usize,
}

/// Safe public facts established by a successful 128-member verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapVerification {
    /// Common epoch after the 127 successful Add commits.
    pub epoch: u64,
    /// Fixed arity of the standard RFC 9420 baseline tree.
    pub tree_arity: u8,
    /// Derived height for its fully occupied 128-leaf binary tree.
    pub tree_height: u8,
    /// Authenticated public MLS GroupContext shared by all members.
    pub group_context: Vec<u8>,
    /// Authenticated public RFC 9420 tree hash shared by all members.
    pub tree_hash: Vec<u8>,
    /// Public group identifier shared by all members.
    pub group_id: Vec<u8>,
    /// Public occupied leaf indexes shared by all members.
    pub member_leaf_indices: Vec<u32>,
    /// Canonical TLS encoding of the public RFC 9420 ratchet tree.
    pub ratchet_tree: Vec<u8>,
}

/// Versioned, serializable public experiment snapshot.
///
/// This type contains no private MLS state, private keys, shared secrets,
/// path secrets, AEAD material, raw entropy, or a seed that reconstructs it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PublicBootstrapSnapshot {
    /// Versioned schema identifier for non-secret snapshot readers.
    pub format: String,
    /// Public baseline protocol settings used by this run.
    pub configuration: PublicSnapshotConfiguration,
    /// Public scheduling input and explicit non-reconstructibility statement.
    pub reproducibility: PublicSnapshotReproducibility,
    /// Authenticated public MLS group state.
    pub group: PublicSnapshotGroup,
    /// KeyPackages that were actually submitted for the 127 Add operations.
    pub added_member_key_packages: Vec<PublicSnapshotKeyPackage>,
}

/// Fixed public configuration captured by the first bootstrap executable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PublicSnapshotConfiguration {
    /// Baseline implementation mode, not experimental hybrid behavior.
    pub mode: String,
    /// RFC 9420 ciphersuite identifier.
    pub ciphersuite_id: u16,
    /// Fixed baseline tree arity.
    pub tree_arity: u8,
    /// Required member count.
    pub member_count: usize,
}

/// Reproducibility data that cannot recreate key material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PublicSnapshotReproducibility {
    /// Public input selecting only the committer schedule.
    pub schedule_seed: u64,
    /// Explicit statement that key-generation entropy is absent from the file.
    pub key_generation_entropy_policy: String,
}

/// Authenticated public state serialized as lowercase hexadecimal TLS bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PublicSnapshotGroup {
    /// Public group identifier.
    pub group_id_hex: String,
    /// Common epoch after all Add commits.
    pub epoch: u64,
    /// Public TLS GroupContext encoding.
    pub group_context_tls_hex: String,
    /// Public authenticated tree hash.
    pub tree_hash_hex: String,
    /// Public TLS RatchetTree encoding.
    pub ratchet_tree_tls_hex: String,
    /// Public member occupancy in leaf-index order.
    pub occupied_leaf_indices: Vec<u32>,
}

/// One serialized public KeyPackage in the snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PublicSnapshotKeyPackage {
    /// Bootstrap member index and matching public identity suffix.
    pub member_index: usize,
    /// Public BasicCredential identity.
    pub identity: String,
    /// Public TLS KeyPackage encoding.
    pub tls_hex: String,
}

/// Versioned public summary of one successful bootstrap construction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BootstrapSummary {
    /// Versioned summary schema identifier.
    pub format: String,
    /// Filenames that form the complete public artifact set for this run.
    pub artifacts: BootstrapArtifactNames,
    /// Public baseline protocol settings used by the run.
    pub configuration: PublicSnapshotConfiguration,
    /// Public schedule-only reproducibility information.
    pub reproducibility: PublicSnapshotReproducibility,
    /// Public build and invocation provenance for reproducibility review.
    pub provenance: PublicBootstrapProvenance,
    /// Verified public MLS state needed to identify the run.
    pub group: BootstrapSummaryGroup,
    /// Aggregate public delivery and byte observations.
    pub delivery: BootstrapSummaryDelivery,
}

/// Stable public provenance that identifies this build without recording
/// secrets, private filesystem state, or arbitrary environment variables.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PublicBootstrapProvenance {
    /// Exact public command represented by the emitted artifact set.
    pub command: String,
    /// Rust compiler version used to build this executable.
    pub rustc_version: String,
    /// Root package version embedded by Cargo.
    pub package_version: String,
    /// Pinned direct dependency versions relevant to the baseline artifact.
    pub direct_dependency_versions: PublicDirectDependencyVersions,
}

/// Pinned direct dependency versions represented in public provenance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PublicDirectDependencyVersions {
    /// Maintained RFC 9420 implementation used by the baseline adapter.
    pub openmls: String,
    /// OpenMLS RustCrypto provider used by the baseline adapter.
    pub openmls_rust_crypto: String,
    /// Local adapter package version.
    pub mls_adapter: String,
    /// CSV writer used for the public commit artifact.
    pub csv: String,
    /// Serialization framework used for public JSON artifacts.
    pub serde: String,
    /// JSON encoder used for public artifacts.
    pub serde_json: String,
}

/// Canonical public artifact filenames.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BootstrapArtifactNames {
    /// Public snapshot filename.
    pub snapshot: String,
    /// Public JSON summary filename.
    pub summary: String,
    /// Public CSV filename.
    pub commits: String,
    /// Public Markdown filename.
    pub report: String,
}

/// Public group identifiers included in the summary without duplicating the tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BootstrapSummaryGroup {
    /// Public group identifier.
    pub group_id_hex: String,
    /// Verified common epoch.
    pub epoch: u64,
    /// Verified authenticated tree hash.
    pub tree_hash_hex: String,
    /// Verified public member count.
    pub member_count: usize,
    /// Verified tree height.
    pub tree_height: u8,
}

/// Aggregate public commit-delivery measurements.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BootstrapSummaryDelivery {
    /// Number of valid Add commits.
    pub add_commit_count: usize,
    /// Number of distinct members that created Add commits.
    pub distinct_committer_count: usize,
    /// Sum of actual serialized Commit message bytes.
    pub total_commit_wire_bytes: u64,
    /// Sum of actual serialized Welcome message bytes.
    pub total_welcome_wire_bytes: u64,
    /// Sum of Commit deliveries to pre-existing members.
    pub total_commit_deliveries: u64,
}

/// Paths of the complete public artifact set written for a run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapArtifactPaths {
    /// Versioned public snapshot path.
    pub snapshot: PathBuf,
    /// JSON summary path.
    pub summary: PathBuf,
    /// CSV commit-record path.
    pub commits: PathBuf,
    /// Markdown report path.
    pub report: PathBuf,
}

/// Failures encountered while constructing and delivering bootstrap commits.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum BootstrapError {
    /// Task 25 intentionally supports only the thesis's 128-member group.
    #[error("bootstrap_128 requires exactly {required} members, but received {requested}")]
    UnsupportedMemberCount {
        /// The user-supplied count.
        requested: usize,
        /// The fixed required count.
        required: usize,
    },
    /// The maintained baseline adapter rejected an MLS operation.
    #[error("the baseline MLS operation failed")]
    Baseline,
    /// A delivered commit did not produce the expected upstream merge event.
    #[error("a valid recipient did not merge the delivered commit")]
    CommitDelivery,
    /// A newly added member did not receive the expected Welcome artifact.
    #[error("an Add commit did not contain an MLS Welcome message")]
    MissingWelcome,
}

impl From<BaselineError> for BootstrapError {
    fn from(_: BaselineError) -> Self {
        Self::Baseline
    }
}

/// Fail-closed errors from the Task 26 bootstrap verifier.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum BootstrapVerificationError {
    /// The caller did not provide the complete fixed-size client set.
    #[error("verification requires exactly 128 initialized clients")]
    ClientCount,
    /// An upstream MLS operation failed while reading public state or delivering
    /// the verification application message.
    #[error("the baseline MLS verification operation failed")]
    Baseline,
    /// A member's public MLS state differs from the first member's state.
    #[error("members do not share an identical authenticated public MLS state")]
    DivergentState,
    /// The public group member count is not exactly 128.
    #[error("the MLS group does not contain exactly 128 active members")]
    MemberCount,
    /// The 128 active members do not occupy every expected binary-tree leaf.
    #[error("the MLS tree does not have exactly the expected occupied leaves")]
    LeafOccupancy,
    /// A baseline application message did not decrypt to its expected payload.
    #[error("a baseline application message did not decrypt for every recipient")]
    ApplicationDelivery,
}

impl From<BaselineError> for BootstrapVerificationError {
    fn from(_: BaselineError) -> Self {
        Self::Baseline
    }
}

/// Errors from constructing or persisting the public snapshot.
#[derive(Debug, Error)]
pub enum SnapshotError {
    /// The public construction result is incomplete or inconsistent.
    #[error("the public bootstrap result cannot form a complete snapshot")]
    IncompletePublicResult,
    /// The requested output directory is outside the approved public-output
    /// boundary or otherwise ambiguous.
    #[error("the snapshot output directory must be a relative output/<run> path")]
    UnsafeOutputDirectory,
    /// Public JSON serialization failed.
    #[error("public snapshot serialization failed")]
    Serialization(#[source] serde_json::Error),
    /// Public CSV serialization failed.
    #[error("public commit CSV serialization failed")]
    Csv(#[source] csv::Error),
    /// The snapshot could not be written without overwriting an existing file.
    #[error("the public snapshot could not be written")]
    Io(#[source] std::io::Error),
}

/// Builds the fixed-size group and delivers each Add commit to every current
/// member. The returned client vector remains private to the caller so Task 26
/// can perform its separate convergence and cleanup verification.
pub fn bootstrap_128(
    options: &BootstrapOptions,
) -> Result<(Vec<BaselineClient>, BootstrapResult), BootstrapError> {
    options.validate()?;

    let mut clients = Vec::with_capacity(options.members);
    for member_index in 0..options.members {
        clients.push(BaselineClient::new(member_identity(member_index))?);
    }

    clients[0].create_group(b"adaptive-hybrid-mls-bootstrap-128")?;

    let mut committer_indices = Vec::with_capacity(options.members - 1);
    let mut added_member_key_packages = Vec::with_capacity(options.members - 1);
    let mut commit_records = Vec::with_capacity(options.members - 1);
    for joining_index in 1..options.members {
        let committer_index = committer_for_add(options.schedule_seed, joining_index);
        let (key_package, key_package_tls_bytes) =
            clients[joining_index].key_package_with_wire_bytes()?;
        let outbound = clients[committer_index]
            .add_members(core::slice::from_ref(key_package.key_package()))?;

        for (recipient_index, recipient) in clients[..joining_index].iter_mut().enumerate() {
            if recipient_index != committer_index
                && recipient.process_message(&outbound.commit)? != InboundEvent::CommitMerged
            {
                return Err(BootstrapError::CommitDelivery);
            }
        }
        clients[committer_index].merge_pending_commit()?;
        let welcome = outbound
            .welcome
            .as_deref()
            .ok_or(BootstrapError::MissingWelcome)?;
        let welcome_wire_bytes = welcome.len();
        clients[joining_index].join_from_welcome(welcome)?;
        committer_indices.push(committer_index);
        added_member_key_packages.push(PublicKeyPackage {
            member_index: joining_index,
            tls_bytes: key_package_tls_bytes,
        });
        commit_records.push(BootstrapCommitRecord {
            sequence: joining_index as u32,
            epoch_before: joining_index as u64 - 1,
            epoch_after: joining_index as u64,
            committer_member_index: committer_index,
            committer_leaf_index: committer_index as u32,
            added_member_index: joining_index,
            commit_wire_bytes: outbound.commit.len(),
            welcome_wire_bytes,
            commit_delivery_recipient_count: joining_index - 1,
            welcome_recipient_count: 1,
        });
    }

    Ok((
        clients,
        BootstrapResult {
            add_commit_count: options.members - 1,
            committer_indices,
            added_member_key_packages,
            commit_records,
        },
    ))
}

/// Verifies all Task 26 public bootstrap invariants and application delivery.
///
/// On success the return value contains public state only. The caller must
/// promptly drop the supplied clients; this function neither serializes nor
/// exposes their private MLS state, private keys, or secret-tree material.
pub fn verify_bootstrap_128(
    clients: &mut [BaselineClient],
) -> Result<BootstrapVerification, BootstrapVerificationError> {
    if clients.len() != BOOTSTRAP_MEMBER_COUNT {
        return Err(BootstrapVerificationError::ClientCount);
    }

    let expected_leaf_indices: Vec<u32> = (0..BOOTSTRAP_MEMBER_COUNT as u32).collect();
    let reference_state = clients[0].state()?;
    verify_public_state(&reference_state, &expected_leaf_indices)?;
    for client in &clients[1..] {
        let state = client.state()?;
        if state != reference_state {
            return Err(BootstrapVerificationError::DivergentState);
        }
    }

    let payload = b"bootstrap-128 application delivery verification";
    let message = clients[0].create_application_message(payload)?;
    for recipient in &mut clients[1..] {
        if recipient.process_message(&message)?
            != InboundEvent::ApplicationMessage(payload.to_vec())
        {
            return Err(BootstrapVerificationError::ApplicationDelivery);
        }
    }

    Ok(BootstrapVerification {
        epoch: reference_state.epoch,
        tree_arity: BASELINE_TREE_ARITY,
        tree_height: BOOTSTRAP_BINARY_TREE_HEIGHT,
        group_context: reference_state.group_context,
        tree_hash: reference_state.tree_hash,
        group_id: reference_state.group_id,
        member_leaf_indices: reference_state.member_leaf_indices,
        ratchet_tree: reference_state.ratchet_tree,
    })
}

/// Builds the versioned snapshot exclusively from public bootstrap data.
pub fn public_bootstrap_snapshot(
    options: &BootstrapOptions,
    result: &BootstrapResult,
    verification: &BootstrapVerification,
) -> Result<PublicBootstrapSnapshot, SnapshotError> {
    validate_public_bootstrap_result(result, verification)?;

    let added_member_key_packages = result
        .added_member_key_packages
        .iter()
        .enumerate()
        .map(|(offset, key_package)| {
            if key_package.member_index != offset + 1 {
                return Err(SnapshotError::IncompletePublicResult);
            }
            Ok(PublicSnapshotKeyPackage {
                member_index: key_package.member_index,
                identity: member_identity_string(key_package.member_index),
                tls_hex: hex::encode(&key_package.tls_bytes),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(PublicBootstrapSnapshot {
        format: "adaptive-hybrid-mls/bootstrap-public-snapshot-v1".to_owned(),
        configuration: PublicSnapshotConfiguration {
            mode: "baseline-binary-mls".to_owned(),
            ciphersuite_id: BASELINE_CIPHERSUITE_ID,
            tree_arity: BASELINE_TREE_ARITY,
            member_count: BOOTSTRAP_MEMBER_COUNT,
        },
        reproducibility: PublicSnapshotReproducibility {
            schedule_seed: options.schedule_seed,
            key_generation_entropy_policy:
                "operating-system RNG; not persisted and not reconstructible from this snapshot"
                    .to_owned(),
        },
        group: PublicSnapshotGroup {
            group_id_hex: hex::encode(&verification.group_id),
            epoch: verification.epoch,
            group_context_tls_hex: hex::encode(&verification.group_context),
            tree_hash_hex: hex::encode(&verification.tree_hash),
            ratchet_tree_tls_hex: hex::encode(&verification.ratchet_tree),
            occupied_leaf_indices: verification.member_leaf_indices.clone(),
        },
        added_member_key_packages,
    })
}

/// Builds the public JSON summary from verified construction observations.
pub fn bootstrap_summary(
    options: &BootstrapOptions,
    result: &BootstrapResult,
    verification: &BootstrapVerification,
    output_directory: &Path,
) -> Result<BootstrapSummary, SnapshotError> {
    validate_public_bootstrap_result(result, verification)?;
    validate_snapshot_output_directory(output_directory)?;
    let total_commit_wire_bytes = result
        .commit_records
        .iter()
        .map(|record| record.commit_wire_bytes as u64)
        .sum();
    let total_welcome_wire_bytes = result
        .commit_records
        .iter()
        .map(|record| record.welcome_wire_bytes as u64)
        .sum();
    let total_commit_deliveries = result
        .commit_records
        .iter()
        .map(|record| record.commit_delivery_recipient_count as u64)
        .sum();
    let distinct_committer_count = result
        .committer_indices
        .iter()
        .collect::<std::collections::BTreeSet<_>>()
        .len();

    Ok(BootstrapSummary {
        format: "adaptive-hybrid-mls/bootstrap-summary-v1".to_owned(),
        artifacts: BootstrapArtifactNames {
            snapshot: PUBLIC_SNAPSHOT_FILE_NAME.to_owned(),
            summary: BOOTSTRAP_SUMMARY_FILE_NAME.to_owned(),
            commits: BOOTSTRAP_COMMITS_FILE_NAME.to_owned(),
            report: BOOTSTRAP_REPORT_FILE_NAME.to_owned(),
        },
        configuration: PublicSnapshotConfiguration {
            mode: "baseline-binary-mls".to_owned(),
            ciphersuite_id: BASELINE_CIPHERSUITE_ID,
            tree_arity: BASELINE_TREE_ARITY,
            member_count: BOOTSTRAP_MEMBER_COUNT,
        },
        reproducibility: PublicSnapshotReproducibility {
            schedule_seed: options.schedule_seed,
            key_generation_entropy_policy:
                "operating-system RNG; not persisted and not reconstructible from this summary"
                    .to_owned(),
        },
        provenance: PublicBootstrapProvenance {
            command: bootstrap_command(options, output_directory),
            rustc_version: env!("BOOTSTRAP_RUSTC_VERSION").to_owned(),
            package_version: env!("CARGO_PKG_VERSION").to_owned(),
            direct_dependency_versions: PublicDirectDependencyVersions {
                openmls: "0.8.1".to_owned(),
                openmls_rust_crypto: "0.5.1".to_owned(),
                mls_adapter: "0.1.0".to_owned(),
                csv: "1.4.0".to_owned(),
                serde: "1.0.228".to_owned(),
                serde_json: "1.0.150".to_owned(),
            },
        },
        group: BootstrapSummaryGroup {
            group_id_hex: hex::encode(&verification.group_id),
            epoch: verification.epoch,
            tree_hash_hex: hex::encode(&verification.tree_hash),
            member_count: BOOTSTRAP_MEMBER_COUNT,
            tree_height: BOOTSTRAP_BINARY_TREE_HEIGHT,
        },
        delivery: BootstrapSummaryDelivery {
            add_commit_count: result.add_commit_count,
            distinct_committer_count,
            total_commit_wire_bytes,
            total_welcome_wire_bytes,
            total_commit_deliveries,
        },
    })
}

/// Ensures the CLI output target stays under `output/<run>`.
pub fn validate_snapshot_output_directory(path: &Path) -> Result<(), SnapshotError> {
    let components: Vec<_> = path.components().collect();
    if components.len() < 2
        || !matches!(components.first(), Some(Component::Normal(component)) if *component == std::ffi::OsStr::new("output"))
        || components
            .iter()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(SnapshotError::UnsafeOutputDirectory);
    }
    Ok(())
}

/// Writes a public-only snapshot once, preserving prior experiment evidence.
pub fn write_public_bootstrap_snapshot(
    output_directory: &Path,
    snapshot: &PublicBootstrapSnapshot,
) -> Result<PathBuf, SnapshotError> {
    validate_snapshot_output_directory(output_directory)?;
    fs::create_dir_all(output_directory).map_err(SnapshotError::Io)?;
    let snapshot_path = output_directory.join(PUBLIC_SNAPSHOT_FILE_NAME);
    let encoded = serde_json::to_vec_pretty(snapshot).map_err(SnapshotError::Serialization)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&snapshot_path)
        .map_err(SnapshotError::Io)?;
    file.write_all(&encoded).map_err(SnapshotError::Io)?;
    file.write_all(b"\n").map_err(SnapshotError::Io)?;
    Ok(snapshot_path)
}

/// Writes the complete Task 28 public artifact set without overwriting files.
pub fn write_bootstrap_artifacts(
    output_directory: &Path,
    snapshot: &PublicBootstrapSnapshot,
    summary: &BootstrapSummary,
    commit_records: &[BootstrapCommitRecord],
) -> Result<BootstrapArtifactPaths, SnapshotError> {
    validate_snapshot_output_directory(output_directory)?;
    fs::create_dir_all(output_directory).map_err(SnapshotError::Io)?;
    let snapshot_path = output_directory.join(PUBLIC_SNAPSHOT_FILE_NAME);
    let summary_path = output_directory.join(BOOTSTRAP_SUMMARY_FILE_NAME);
    let commits_path = output_directory.join(BOOTSTRAP_COMMITS_FILE_NAME);
    let report_path = output_directory.join(BOOTSTRAP_REPORT_FILE_NAME);

    write_json_new(&snapshot_path, snapshot)?;
    write_json_new(&summary_path, summary)?;
    write_commit_csv_new(&commits_path, commit_records)?;
    write_markdown_new(&report_path, &bootstrap_report_markdown(summary))?;

    Ok(BootstrapArtifactPaths {
        snapshot: snapshot_path,
        summary: summary_path,
        commits: commits_path,
        report: report_path,
    })
}

fn validate_public_bootstrap_result(
    result: &BootstrapResult,
    verification: &BootstrapVerification,
) -> Result<(), SnapshotError> {
    if result.add_commit_count != BOOTSTRAP_MEMBER_COUNT - 1
        || result.added_member_key_packages.len() != BOOTSTRAP_MEMBER_COUNT - 1
        || result.commit_records.len() != BOOTSTRAP_MEMBER_COUNT - 1
        || verification.member_leaf_indices
            != (0..BOOTSTRAP_MEMBER_COUNT as u32).collect::<Vec<_>>()
    {
        return Err(SnapshotError::IncompletePublicResult);
    }
    for (offset, record) in result.commit_records.iter().enumerate() {
        let joining_index = offset + 1;
        if record.sequence != joining_index as u32
            || record.epoch_before != joining_index as u64 - 1
            || record.epoch_after != joining_index as u64
            || record.added_member_index != joining_index
            || record.committer_member_index >= joining_index
            || record.committer_leaf_index != record.committer_member_index as u32
            || record.commit_delivery_recipient_count != joining_index - 1
            || record.welcome_recipient_count != 1
        {
            return Err(SnapshotError::IncompletePublicResult);
        }
    }
    Ok(())
}

fn write_json_new(path: &Path, value: &impl Serialize) -> Result<(), SnapshotError> {
    let encoded = serde_json::to_vec_pretty(value).map_err(SnapshotError::Serialization)?;
    write_new(path, &encoded)?;
    write_append(path, b"\n")
}

fn write_commit_csv_new(
    path: &Path,
    commit_records: &[BootstrapCommitRecord],
) -> Result<(), SnapshotError> {
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(SnapshotError::Io)?;
    let mut writer = csv::Writer::from_writer(file);
    writer
        .write_record([
            "sequence",
            "epoch_before",
            "epoch_after",
            "committer_member_index",
            "committer_leaf_index",
            "added_member_index",
            "commit_wire_bytes",
            "welcome_wire_bytes",
            "commit_delivery_recipient_count",
            "welcome_recipient_count",
        ])
        .map_err(SnapshotError::Csv)?;
    for record in commit_records {
        writer
            .write_record([
                record.sequence.to_string(),
                record.epoch_before.to_string(),
                record.epoch_after.to_string(),
                record.committer_member_index.to_string(),
                record.committer_leaf_index.to_string(),
                record.added_member_index.to_string(),
                record.commit_wire_bytes.to_string(),
                record.welcome_wire_bytes.to_string(),
                record.commit_delivery_recipient_count.to_string(),
                record.welcome_recipient_count.to_string(),
            ])
            .map_err(SnapshotError::Csv)?;
    }
    writer.flush().map_err(SnapshotError::Io)
}

fn bootstrap_report_markdown(summary: &BootstrapSummary) -> String {
    format!(
        "# Baseline MLS 128-Member Bootstrap Report\n\n\
         Status: verified baseline construction.\n\n\
         ## Public configuration\n\n\
         - Mode: `{}`\n\
         - Ciphersuite: `0x{:04x}`\n\
         - Tree arity: `{}`\n\
         - Members: `{}`\n\
         - Public committer-schedule seed: `{}`\n\n\
         ## Reproducibility provenance\n\n\
         - Command: `{}`\n\
         - Compiler: `{}`\n\
         - Package version: `{}`\n\
         - OpenMLS: `{}`; RustCrypto provider: `{}`\n\
         - CSV: `{}`; Serde: `{}`; serde_json: `{}`\n\n\
         ## Verified state\n\n\
         - Epoch: `{}`\n\
         - Tree height: `{}`\n\
         - Add commits: `{}`\n\
         - Distinct committers: `{}`\n\
         - Total Commit wire bytes: `{}`\n\
         - Total Welcome wire bytes: `{}`\n\
         - Total Commit deliveries: `{}`\n\n\
         ## Artifact set\n\n\
         - `{}`: versioned public tree, group metadata, and submitted Add KeyPackages.\n\
         - `{}`: this public summary.\n\
         - `{}`: one public row per Add commit; it records byte counts, not Commit bodies.\n\
         - `{}`: this report.\n\n\
         ## Security boundary\n\n\
         These artifacts contain no private MLS state, private keys, shared secrets, path secrets, AEAD material, raw entropy, or a seed that reconstructs key material. The public schedule seed reproduces only committer selection. This educational thesis prototype is not production cryptography and this report is not a security proof.\n",
        summary.configuration.mode,
        summary.configuration.ciphersuite_id,
        summary.configuration.tree_arity,
        summary.configuration.member_count,
        summary.reproducibility.schedule_seed,
        summary.provenance.command,
        summary.provenance.rustc_version,
        summary.provenance.package_version,
        summary.provenance.direct_dependency_versions.openmls,
        summary.provenance.direct_dependency_versions.openmls_rust_crypto,
        summary.provenance.direct_dependency_versions.csv,
        summary.provenance.direct_dependency_versions.serde,
        summary.provenance.direct_dependency_versions.serde_json,
        summary.group.epoch,
        summary.group.tree_height,
        summary.delivery.add_commit_count,
        summary.delivery.distinct_committer_count,
        summary.delivery.total_commit_wire_bytes,
        summary.delivery.total_welcome_wire_bytes,
        summary.delivery.total_commit_deliveries,
        summary.artifacts.snapshot,
        summary.artifacts.summary,
        summary.artifacts.commits,
        summary.artifacts.report,
    )
}

fn bootstrap_command(options: &BootstrapOptions, output_directory: &Path) -> String {
    format!(
        "cargo +stable run --bin bootstrap_128 --release --locked --offline -- --members {} --seed {} --output {:?}",
        options.members, options.schedule_seed, output_directory
    )
}

fn write_markdown_new(path: &Path, content: &str) -> Result<(), SnapshotError> {
    write_new(path, content.as_bytes())
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), SnapshotError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(SnapshotError::Io)?;
    file.write_all(bytes).map_err(SnapshotError::Io)
}

fn write_append(path: &Path, bytes: &[u8]) -> Result<(), SnapshotError> {
    let mut file = OpenOptions::new()
        .append(true)
        .open(path)
        .map_err(SnapshotError::Io)?;
    file.write_all(bytes).map_err(SnapshotError::Io)
}

fn verify_public_state(
    state: &BaselineState,
    expected_leaf_indices: &[u32],
) -> Result<(), BootstrapVerificationError> {
    if state.member_count != BOOTSTRAP_MEMBER_COUNT {
        return Err(BootstrapVerificationError::MemberCount);
    }
    if state.member_leaf_indices != expected_leaf_indices {
        return Err(BootstrapVerificationError::LeafOccupancy);
    }
    Ok(())
}

fn member_identity(member_index: usize) -> Vec<u8> {
    member_identity_string(member_index).into_bytes()
}

fn member_identity_string(member_index: usize) -> String {
    format!("bootstrap-member-{member_index:03}")
}

fn committer_for_add(schedule_seed: u64, joining_index: usize) -> usize {
    let active_members = joining_index;
    let offset = (schedule_seed % active_members as u64) as usize;
    (joining_index - 1 + offset) % active_members
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_any_group_size_other_than_the_thesis_bootstrap_size() {
        assert_eq!(
            BootstrapOptions {
                members: BOOTSTRAP_MEMBER_COUNT - 1,
                schedule_seed: 42,
            }
            .validate(),
            Err(BootstrapError::UnsupportedMemberCount {
                requested: BOOTSTRAP_MEMBER_COUNT - 1,
                required: BOOTSTRAP_MEMBER_COUNT,
            })
        );
    }

    #[test]
    fn public_seed_selects_only_existing_committers() {
        for joining_index in 1..BOOTSTRAP_MEMBER_COUNT {
            assert!(committer_for_add(42, joining_index) < joining_index);
        }
    }

    #[test]
    fn public_schedule_uses_multiple_committers_when_the_group_allows_it() {
        let committers: std::collections::BTreeSet<_> = (1..BOOTSTRAP_MEMBER_COUNT)
            .map(|joining_index| committer_for_add(42, joining_index))
            .collect();
        assert!(committers.len() > 1);
    }

    #[test]
    fn snapshot_output_must_stay_below_a_named_output_run_directory() {
        assert!(validate_snapshot_output_directory(Path::new("output/bootstrap-128")).is_ok());
        assert!(validate_snapshot_output_directory(Path::new("output")).is_err());
        assert!(validate_snapshot_output_directory(Path::new("report/bootstrap-128")).is_err());
        assert!(validate_snapshot_output_directory(Path::new("output/../report")).is_err());
    }

    #[test]
    #[ignore = "run in release mode as the 128-member bootstrap acceptance test"]
    fn bootstrap_128_converges_on_public_state_and_delivers_an_application_message() {
        let options = BootstrapOptions {
            members: BOOTSTRAP_MEMBER_COUNT,
            schedule_seed: 42,
        };
        let (mut clients, result) = bootstrap_128(&options).expect("bootstrap must succeed");
        let verification = verify_bootstrap_128(&mut clients).expect("verification must succeed");

        assert_eq!(result.add_commit_count, 127);
        assert_eq!(result.added_member_key_packages.len(), 127);
        assert_eq!(verification.epoch, 127);
        assert_eq!(verification.tree_arity, BASELINE_TREE_ARITY);
        assert_eq!(verification.tree_height, BOOTSTRAP_BINARY_TREE_HEIGHT);
        assert!(!verification.group_context.is_empty());
        assert!(!verification.tree_hash.is_empty());
        assert!(!verification.ratchet_tree.is_empty());

        let snapshot = public_bootstrap_snapshot(&options, &result, &verification)
            .expect("public snapshot must be complete");
        let summary = bootstrap_summary(
            &options,
            &result,
            &verification,
            Path::new("output/release-acceptance"),
        )
        .expect("public summary must be complete");
        let snapshot_json = serde_json::to_string(&snapshot).expect("snapshot must serialize");
        assert_eq!(snapshot.added_member_key_packages.len(), 127);
        assert_eq!(snapshot.added_member_key_packages[0].member_index, 1);
        assert_eq!(snapshot.added_member_key_packages[126].member_index, 127);
        assert_eq!(
            snapshot.group.occupied_leaf_indices,
            (0..128).collect::<Vec<_>>()
        );
        assert!(snapshot_json.contains("operating-system RNG"));
        assert!(!snapshot_json.contains("private_key"));
        assert!(!snapshot_json.contains("shared_secret"));
        assert!(!snapshot_json.contains("path_secret"));
        assert_eq!(summary.delivery.add_commit_count, 127);
        assert_eq!(summary.group.epoch, 127);
        assert_eq!(summary.artifacts.commits, BOOTSTRAP_COMMITS_FILE_NAME);
        assert!(summary.delivery.total_commit_wire_bytes > 0);
        assert!(summary.delivery.total_welcome_wire_bytes > 0);
        assert!(summary.provenance.rustc_version.starts_with("rustc "));
        assert!(summary.provenance.command.contains("--seed 42"));
        drop(clients);
    }
}
