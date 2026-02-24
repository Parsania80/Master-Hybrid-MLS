use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{SecretKey as EdSecretKey, SigningKey as EdSigningKey};
use hybrid_mls::client_state::ClientGroupState;
use hybrid_mls::crypto::HybridSignPrivKey;
use hybrid_mls::ds::config::StorageConfig;
use hybrid_mls::ds::http::{self, ApiState};
use hybrid_mls::envelope::{CommitEnvelope, PathUpdateEnvelope, ProposalEnvelope};
use hybrid_mls::mls_wire::{ContentType, MlsMessage, MlsMessageBody};
use hybrid_mls::tree::{Commit, KeyPackage, Node, Proposal, RatchetTree};
use ml_dsa::{EncodedSigningKey, MlDsa65};
use serde_json::Value;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

fn run_ds_client(bin: &str, base_url: &str, state_path: &Path, args: &[String]) -> String {
    let output = Command::new(bin)
        .arg("--base-url")
        .arg(base_url)
        .arg("--state")
        .arg(state_path)
        .args(args)
        .output()
        .expect("run ds_client");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    assert!(
        output.status.success(),
        "ds_client command failed\nargs={args:?}\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    stdout
}

fn run_ds_client_expect_fail(
    bin: &str,
    base_url: &str,
    state_path: &Path,
    args: &[String],
    expected_error_snippet: &str,
) -> String {
    let output = Command::new(bin)
        .arg("--base-url")
        .arg(base_url)
        .arg("--state")
        .arg(state_path)
        .args(args)
        .output()
        .expect("run ds_client");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    assert!(
        !output.status.success(),
        "expected ds_client command to fail\nargs={args:?}\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stdout.contains(expected_error_snippet) || stderr.contains(expected_error_snippet),
        "expected error snippet not found: {expected_error_snippet}\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    format!("{stdout}\n{stderr}")
}

fn parse_json_from_ds_client_output(output: &str) -> Value {
    let start = output.find('{').expect("json body start");
    serde_json::from_str(&output[start..]).expect("parse json body")
}

fn first_list_message_id(list_json: &Value) -> Option<i64> {
    let item = list_json
        .get("messages")
        .and_then(|m| m.as_array())
        .and_then(|items| items.first())?;
    if let Some(id_num) = item.get("id").and_then(|id| id.as_i64()) {
        return Some(id_num);
    }
    item.get("id")
        .and_then(|id| id.as_str())
        .and_then(|id| id.parse::<i64>().ok())
}

fn temp_state(label: &str) -> (ApiState, PathBuf) {
    let base = std::env::temp_dir().join(format!(
        "hybrid-mls-ds-fetch-apply-{label}-{}",
        rand::random::<u64>()
    ));
    let db_path = base.join("ds.sqlite");
    let mut state = ApiState::default();
    state.storage = StorageConfig::new(&base, &db_path);
    state.min_proposals_per_commit = 1;
    (state, base)
}

async fn start_test_server(
    state: ApiState,
) -> (
    std::net::SocketAddr,
    oneshot::Sender<()>,
    JoinHandle<Result<(), std::io::Error>>,
) {
    let app = http::router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let addr = listener.local_addr().expect("listener addr");

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = shutdown_rx.await;
            })
            .await
    });
    (addr, shutdown_tx, server)
}

fn to_s(path: &Path) -> String {
    path.to_string_lossy().to_string()
}

fn encode_u32_be(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn encode_u64_be(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn encode_bytes_be(out: &mut Vec<u8>, bytes: &[u8]) {
    encode_u32_be(out, bytes.len() as u32);
    out.extend_from_slice(bytes);
}

fn encode_malformed_commit_envelope_with_metadata(
    group_id: &str,
    epoch: u64,
    sender_leaf: usize,
    malformed_commit_bytes: &[u8],
) -> Vec<u8> {
    let mut out = Vec::new();
    encode_bytes_be(&mut out, group_id.as_bytes());
    encode_u64_be(&mut out, epoch);
    encode_u32_be(&mut out, sender_leaf as u32);
    encode_bytes_be(&mut out, malformed_commit_bytes);
    out
}

fn encode_malformed_path_update_envelope_with_metadata(
    group_id: &str,
    epoch: u64,
    sender_leaf: usize,
    malformed_path_update_bytes: &[u8],
) -> Vec<u8> {
    let mut out = Vec::new();
    encode_bytes_be(&mut out, group_id.as_bytes());
    encode_u64_be(&mut out, epoch);
    encode_u32_be(&mut out, sender_leaf as u32);
    encode_bytes_be(&mut out, malformed_path_update_bytes);
    out
}

fn corrupt_classic_secret_key_in_state(original_state: &Path, corrupted_state: &Path) {
    let bytes = fs::read(original_state).expect("read state");
    let mut json: Value = serde_json::from_slice(&bytes).expect("parse state json");
    let bad_secret = STANDARD.encode([0u8; 32]);
    json["classic_sk_b64"] = Value::String(bad_secret);
    fs::write(
        corrupted_state,
        serde_json::to_vec_pretty(&json).expect("serialize corrupted state"),
    )
    .expect("write corrupted state");
}

fn tamper_group_state_key_schedule_epoch(group_state_file: &Path, tampered_epoch: u64) {
    let mut state = ClientGroupState::load_from_file(group_state_file)
        .expect("load group state for epoch tamper");
    state.key_schedule.current_epoch = tampered_epoch;
    state
        .save_to_file(group_state_file)
        .expect("write epoch-tampered group state");
}

fn tamper_group_state_key_schedule_parent_link(group_state_file: &Path) {
    let mut state = ClientGroupState::load_from_file(group_state_file)
        .expect("load group state for parent-link tamper");
    assert!(
        state.key_schedule.epoch_secret_nodes.len() >= 2,
        "need at least two epochs to tamper parent link"
    );
    let latest = state.key_schedule.epoch_secret_nodes.len() - 1;
    state.key_schedule.epoch_secret_nodes[latest].parent_epoch = None;
    state
        .save_to_file(group_state_file)
        .expect("write parent-link-tampered group state");
}

fn queue_psk_proposal(group_state_file: &Path, psk_id: &[u8]) {
    let mut state =
        ClientGroupState::load_from_file(group_state_file).expect("load group state for psk queue");
    state.queue_proposal(&Proposal::PreSharedKey {
        psk_id: psk_id.to_vec(),
    });
    state
        .save_to_file(group_state_file)
        .expect("save group state with psk proposal");
}

fn queue_reinit_proposal(
    group_state_file: &Path,
    group_id: &str,
    version: u16,
    cipher_suite: u16,
    extensions: &[u8],
) {
    let mut state = ClientGroupState::load_from_file(group_state_file)
        .expect("load group state for reinit queue");
    state.queue_proposal(&Proposal::ReInit {
        group_id: group_id.to_string(),
        version,
        cipher_suite,
        extensions: extensions.to_vec(),
    });
    state
        .save_to_file(group_state_file)
        .expect("save group state with reinit proposal");
}

fn queue_group_context_extensions_proposal(group_state_file: &Path, extensions: &[u8]) {
    let mut state = ClientGroupState::load_from_file(group_state_file)
        .expect("load group state for group-context-extensions queue");
    state.queue_proposal(&Proposal::GroupContextExtensions {
        extensions: extensions.to_vec(),
    });
    state
        .save_to_file(group_state_file)
        .expect("save group state with group-context-extensions proposal");
}

fn register_and_export_keypackage(
    client_bin: &str,
    base_url: &str,
    state_file: &Path,
    username: &str,
    kem_out: &Path,
    keypackage_out: &Path,
    receiver_private_out: &Path,
) {
    run_ds_client(
        client_bin,
        base_url,
        state_file,
        &[
            "register".to_string(),
            "--username".to_string(),
            username.to_string(),
            "--password".to_string(),
            "secret".to_string(),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        base_url,
        state_file,
        &[
            "keygen".to_string(),
            "--out".to_string(),
            to_s(kem_out),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        base_url,
        state_file,
        &[
            "keypackage-export".to_string(),
            "--kem-file".to_string(),
            to_s(kem_out),
            "--keypackage-out".to_string(),
            to_s(keypackage_out),
            "--receiver-private-out".to_string(),
            to_s(receiver_private_out),
            "--force".to_string(),
        ],
    );
}

struct EncodedPathSyncFixture {
    base: PathBuf,
    base_url: String,
    shutdown_tx: Option<oneshot::Sender<()>>,
    server: JoinHandle<Result<(), std::io::Error>>,
    client_bin: &'static str,
    group_id: String,
    alice_state: PathBuf,
    alice_group_state: PathBuf,
    carol_state: PathBuf,
    carol_group_state: PathBuf,
    carol_recv: PathBuf,
    commit_file: PathBuf,
    path_file: PathBuf,
}

async fn teardown_encoded_path_sync_fixture(mut fixture: EncodedPathSyncFixture) {
    if let Some(shutdown_tx) = fixture.shutdown_tx.take() {
        let _ = shutdown_tx.send(());
    }
    let result = fixture.server.await.expect("join server");
    if let Err(err) = result {
        panic!("server returned error: {err}");
    }
    let _ = fs::remove_dir_all(&fixture.base);
}

fn find_non_receiver_level(tree: &RatchetTree, sender_leaf: usize, receiver_leaf: usize) -> usize {
    let copath_root_to_leaf: Vec<usize> = tree
        .copath(sender_leaf)
        .expect("copath")
        .into_iter()
        .rev()
        .collect();
    let receiver_node = RatchetTree::leaf_to_node_index(receiver_leaf);
    copath_root_to_leaf
        .iter()
        .enumerate()
        .find_map(|(idx, copath)| {
            let resolution = tree.resolution(*copath)?;
            if !resolution.contains(&receiver_node) {
                Some(idx)
            } else {
                None
            }
        })
        .expect("expected at least one non-receiver direct-path level")
}

async fn setup_encoded_path_sync_fixture(label: &str, group_id: &str) -> EncodedPathSyncFixture {
    let (state, base) = temp_state(label);
    let (addr, shutdown_tx, server) = start_test_server(state).await;
    let base_url = format!("http://{addr}");
    let client_bin = env!("CARGO_BIN_EXE_ds_client");

    let work = base.join("work");
    let _ = fs::create_dir_all(&work);

    let alice_state = work.join("alice.json");
    let bob_state = work.join("bob.json");
    let carol_state = work.join("carol.json");

    let alice_kem = work.join("alice-kem.json");
    let bob_kem = work.join("bob-kem.json");
    let carol_kem = work.join("carol-kem.json");
    let alice_v2_kem = work.join("alice-v2-kem.json");

    let alice_kp = work.join("alice.kp");
    let bob_kp = work.join("bob.kp");
    let carol_kp = work.join("carol.kp");
    let alice_v2_kp = work.join("alice-v2.kp");

    let alice_recv = work.join("alice.recv.json");
    let bob_recv = work.join("bob.recv.json");
    let carol_recv = work.join("carol.recv.json");
    let alice_v2_recv = work.join("alice-v2.recv.json");

    let alice_group_state = work.join("alice-group.bin");
    let carol_group_state = work.join("carol-group.bin");

    let proposal_file = work.join("alice-update.proposal.bin");
    let commit_file = work.join("alice-update.commit.bin");
    let path_file = work.join("alice-update.path.bin");

    register_and_export_keypackage(
        client_bin,
        &base_url,
        &alice_state,
        "alice",
        &alice_kem,
        &alice_kp,
        &alice_recv,
    );
    register_and_export_keypackage(
        client_bin, &base_url, &bob_state, "bob", &bob_kem, &bob_kp, &bob_recv,
    );
    register_and_export_keypackage(
        client_bin,
        &base_url,
        &carol_state,
        "carol",
        &carol_kem,
        &carol_kp,
        &carol_recv,
    );

    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "keygen".to_string(),
            "--out".to_string(),
            to_s(&alice_v2_kem),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "keypackage-export".to_string(),
            "--kem-file".to_string(),
            to_s(&alice_v2_kem),
            "--keypackage-out".to_string(),
            to_s(&alice_v2_kp),
            "--receiver-private-out".to_string(),
            to_s(&alice_v2_recv),
            "--force".to_string(),
        ],
    );

    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "bootstrap-group-state".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--member-keypackage".to_string(),
            to_s(&alice_kp),
            "--member-keypackage".to_string(),
            to_s(&bob_kp),
            "--member-keypackage".to_string(),
            to_s(&carol_kp),
            "--own-leaf".to_string(),
            "0".to_string(),
            "--out".to_string(),
            to_s(&alice_group_state),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &carol_state,
        &[
            "bootstrap-group-state".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--member-keypackage".to_string(),
            to_s(&alice_kp),
            "--member-keypackage".to_string(),
            to_s(&bob_kp),
            "--member-keypackage".to_string(),
            to_s(&carol_kp),
            "--own-leaf".to_string(),
            "2".to_string(),
            "--out".to_string(),
            to_s(&carol_group_state),
            "--force".to_string(),
        ],
    );

    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "create-update-proposal".to_string(),
            "--group-state".to_string(),
            to_s(&alice_group_state),
            "--keypackage-file".to_string(),
            to_s(&alice_v2_kp),
            "--out".to_string(),
            to_s(&proposal_file),
            "--sender-leaf".to_string(),
            "0".to_string(),
            "--target-leaf".to_string(),
            "0".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "submit-proposal".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--proposal-file".to_string(),
            to_s(&proposal_file),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "create-commit".to_string(),
            "--group-state".to_string(),
            to_s(&alice_group_state),
            "--commit-out".to_string(),
            to_s(&commit_file),
            "--path-update-out".to_string(),
            to_s(&path_file),
            "--sender-leaf".to_string(),
            "0".to_string(),
        ],
    );

    EncodedPathSyncFixture {
        base,
        base_url,
        shutdown_tx: Some(shutdown_tx),
        server,
        client_bin,
        group_id: group_id.to_string(),
        alice_state,
        alice_group_state,
        carol_state,
        carol_group_state,
        carol_recv,
        commit_file,
        path_file,
    }
}

struct WelcomeBootstrapFixture {
    base: PathBuf,
    work: PathBuf,
    base_url: String,
    shutdown_tx: Option<oneshot::Sender<()>>,
    server: JoinHandle<Result<(), std::io::Error>>,
    client_bin: &'static str,
    alice_state: PathBuf,
    bob_state: PathBuf,
    alice_kp: PathBuf,
    bob_kp: PathBuf,
    bob_recv: PathBuf,
    welcome_file: PathBuf,
    bob_unknown_group_state: PathBuf,
    group_id: String,
}

async fn setup_unknown_group_welcome_fixture(
    label: &str,
    group_id: &str,
    tamper_welcome_before_submit: bool,
) -> WelcomeBootstrapFixture {
    let (state, base) = temp_state(label);
    let (addr, shutdown_tx, server) = start_test_server(state).await;
    let base_url = format!("http://{addr}");
    let client_bin = env!("CARGO_BIN_EXE_ds_client");

    let work = base.join("work");
    let _ = fs::create_dir_all(&work);

    let alice_state = work.join("alice.json");
    let bob_state = work.join("bob.json");
    let alice_kem = work.join("alice-kem.json");
    let bob_kem = work.join("bob-kem.json");
    let alice_kp = work.join("alice.kp");
    let bob_kp = work.join("bob.kp");
    let alice_recv = work.join("alice.recv.json");
    let bob_recv = work.join("bob.recv.json");
    let alice_group_state = work.join("alice-group-state.bin");
    let bob_unknown_group_state = work.join("bob-unknown-group-state.bin");
    let bob_from_ds = work.join("bob-from-ds.kp");
    let add_proposal = work.join("add-bob.proposal.bin");
    let commit_file = work.join("add-bob.commit.bin");
    let path_file = work.join("add-bob.path.bin");
    let welcome_file = work.join("add-bob.welcome.bin");

    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "register".to_string(),
            "--username".to_string(),
            "alice".to_string(),
            "--password".to_string(),
            "secret".to_string(),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "register".to_string(),
            "--username".to_string(),
            "bob".to_string(),
            "--password".to_string(),
            "secret".to_string(),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "keygen".to_string(),
            "--out".to_string(),
            to_s(&alice_kem),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "keypackage-export".to_string(),
            "--kem-file".to_string(),
            to_s(&alice_kem),
            "--keypackage-out".to_string(),
            to_s(&alice_kp),
            "--receiver-private-out".to_string(),
            to_s(&alice_recv),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "keygen".to_string(),
            "--out".to_string(),
            to_s(&bob_kem),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "keypackage-export".to_string(),
            "--kem-file".to_string(),
            to_s(&bob_kem),
            "--keypackage-out".to_string(),
            to_s(&bob_kp),
            "--receiver-private-out".to_string(),
            to_s(&bob_recv),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "publish-key-package".to_string(),
            "--keypackage-file".to_string(),
            to_s(&bob_kp),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "bootstrap-group-state".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--member-keypackage".to_string(),
            to_s(&alice_kp),
            "--own-leaf".to_string(),
            "0".to_string(),
            "--out".to_string(),
            to_s(&alice_group_state),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "fetch-key-package".to_string(),
            "--target".to_string(),
            "bob".to_string(),
            "--out".to_string(),
            to_s(&bob_from_ds),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "create-add-proposal".to_string(),
            "--group-state".to_string(),
            to_s(&alice_group_state),
            "--keypackage-file".to_string(),
            to_s(&bob_from_ds),
            "--out".to_string(),
            to_s(&add_proposal),
            "--sender-leaf".to_string(),
            "0".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "submit-proposal".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--proposal-file".to_string(),
            to_s(&add_proposal),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "create-commit".to_string(),
            "--group-state".to_string(),
            to_s(&alice_group_state),
            "--commit-out".to_string(),
            to_s(&commit_file),
            "--path-update-out".to_string(),
            to_s(&path_file),
            "--welcome-out".to_string(),
            to_s(&welcome_file),
            "--sender-leaf".to_string(),
            "0".to_string(),
        ],
    );
    if tamper_welcome_before_submit {
        let mut tampered = fs::read(&welcome_file).expect("read welcome bytes for tamper");
        assert!(!tampered.is_empty(), "welcome file should not be empty");
        let last = tampered.len() - 1;
        tampered[last] ^= 0x80;
        fs::write(&welcome_file, tampered).expect("write tampered welcome bytes");
    }
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "submit-commit".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--commit-file".to_string(),
            to_s(&commit_file),
            "--path-update-file".to_string(),
            to_s(&path_file),
            "--welcome-file".to_string(),
            to_s(&welcome_file),
        ],
    );

    WelcomeBootstrapFixture {
        base,
        work,
        base_url,
        shutdown_tx: Some(shutdown_tx),
        server,
        client_bin,
        alice_state,
        bob_state,
        alice_kp,
        bob_kp,
        bob_recv,
        welcome_file,
        bob_unknown_group_state,
        group_id: group_id.to_string(),
    }
}

fn fetch_message_signing_input_for_test(
    username: &str,
    group_id: &str,
    message_id: i64,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"message_fetch|");
    out.extend_from_slice(username.as_bytes());
    out.extend_from_slice(b"|");
    out.extend_from_slice(group_id.as_bytes());
    out.extend_from_slice(b"|");
    out.extend_from_slice(message_id.to_string().as_bytes());
    out
}

fn signing_key_from_state_file(state_path: &Path) -> (String, String, HybridSignPrivKey) {
    let state_json: Value = serde_json::from_slice(&fs::read(state_path).expect("read state file"))
        .expect("parse state file");
    let username = state_json["username"]
        .as_str()
        .expect("state username")
        .to_string();
    let session_id = state_json["session_id"]
        .as_str()
        .expect("state session_id")
        .to_string();
    let classic_sk_b64 = state_json["classic_sk_b64"]
        .as_str()
        .expect("state classic_sk_b64");
    let pq_sk_b64 = state_json["pq_sk_b64"].as_str().expect("state pq_sk_b64");

    let classic_bytes = STANDARD
        .decode(classic_sk_b64)
        .expect("decode classic signing key");
    assert_eq!(
        classic_bytes.len(),
        32,
        "classic signing key must be 32 bytes"
    );
    let mut classic_secret: EdSecretKey = [0u8; 32];
    classic_secret.copy_from_slice(&classic_bytes);
    let classic = EdSigningKey::from_bytes(&classic_secret);

    let pq_bytes = STANDARD.decode(pq_sk_b64).expect("decode pq signing key");
    let encoded: EncodedSigningKey<MlDsa65> = pq_bytes
        .as_slice()
        .try_into()
        .expect("parse pq signing key");
    let pq = ml_dsa::SigningKey::<MlDsa65>::decode(&encoded);

    (username, session_id, HybridSignPrivKey { classic, pq })
}

fn sign_message_b64_with_large_stack(priv_key: HybridSignPrivKey, message: Vec<u8>) -> String {
    let handle = thread::Builder::new()
        .name("e2e-hybrid-sign".to_string())
        .stack_size(64 * 1024 * 1024)
        .spawn(move || STANDARD.encode(priv_key.sign(&message).to_bytes()))
        .expect("spawn signer thread");
    handle.join().expect("join signer thread")
}

async fn fetch_group_message_bytes(
    base_url: &str,
    state_path: &Path,
    group_id: &str,
    message_id: i64,
) -> (String, Vec<u8>) {
    let (username, session_id, signing_key) = signing_key_from_state_file(state_path);
    let sign_input = fetch_message_signing_input_for_test(&username, group_id, message_id);
    let signature = sign_message_b64_with_large_stack(signing_key, sign_input);
    let query = serde_urlencoded::to_string([
        ("username", username.as_str()),
        ("session_id", session_id.as_str()),
        ("signature", signature.as_str()),
    ])
    .expect("encode fetch query");
    let fetch_url = format!(
        "{}/v1/groups/{}/messages/{}?{}",
        base_url, group_id, message_id, query
    );
    let fetch_resp = reqwest::Client::new()
        .get(fetch_url)
        .send()
        .await
        .expect("fetch group message");
    assert_eq!(fetch_resp.status(), reqwest::StatusCode::OK);
    let fetch_json: Value = fetch_resp.json().await.expect("parse fetch response json");
    let kind = fetch_json["kind"]
        .as_str()
        .expect("fetch response kind")
        .to_string();
    let bytes_b64 = fetch_json["message_bytes"]
        .as_str()
        .expect("fetch response message_bytes");
    let bytes = STANDARD
        .decode(bytes_b64)
        .expect("decode fetched message bytes");
    (kind, bytes)
}

async fn teardown_welcome_bootstrap_fixture(mut fixture: WelcomeBootstrapFixture) {
    if let Some(tx) = fixture.shutdown_tx.take() {
        let _ = tx.send(());
    }
    let result = fixture.server.await.expect("join server");
    if let Err(err) = result {
        panic!("server returned error: {err}");
    }
    let _ = fs::remove_dir_all(fixture.base);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fetch_and_apply_latest_is_ds_backed_and_replay_safe() {
    let (state, base) = temp_state("e2e");
    let (addr, shutdown_tx, server) = start_test_server(state).await;
    let base_url = format!("http://{addr}");
    let client_bin = env!("CARGO_BIN_EXE_ds_client");

    let work = base.join("work");
    let _ = fs::create_dir_all(&work);

    let alice_state = work.join("alice.json");
    let bob_state = work.join("bob.json");
    let alice_kem = work.join("alice-kem.json");
    let bob_kem = work.join("bob-kem.json");
    let alice_kp = work.join("alice.kp");
    let bob_kp = work.join("bob.kp");
    let alice_recv = work.join("alice.recv.json");
    let bob_recv = work.join("bob.recv.json");
    let sender_group_state = work.join("alice-sender-state.bin");
    let receiver_group_state = work.join("alice-receiver-state.bin");
    let bob_from_ds = work.join("bob-from-ds.kp");
    let proposal_file = work.join("add-bob.proposal.bin");
    let commit_file = work.join("add-bob.commit.bin");
    let path_file = work.join("add-bob.path.bin");
    let group_id = "group-e2e";

    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "register".to_string(),
            "--username".to_string(),
            "alice".to_string(),
            "--password".to_string(),
            "secret".to_string(),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "register".to_string(),
            "--username".to_string(),
            "bob".to_string(),
            "--password".to_string(),
            "secret".to_string(),
            "--force".to_string(),
        ],
    );

    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "keygen".to_string(),
            "--out".to_string(),
            to_s(&alice_kem),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "keypackage-export".to_string(),
            "--kem-file".to_string(),
            to_s(&alice_kem),
            "--keypackage-out".to_string(),
            to_s(&alice_kp),
            "--receiver-private-out".to_string(),
            to_s(&alice_recv),
            "--force".to_string(),
        ],
    );

    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "keygen".to_string(),
            "--out".to_string(),
            to_s(&bob_kem),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "keypackage-export".to_string(),
            "--kem-file".to_string(),
            to_s(&bob_kem),
            "--keypackage-out".to_string(),
            to_s(&bob_kp),
            "--receiver-private-out".to_string(),
            to_s(&bob_recv),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "publish-key-package".to_string(),
            "--keypackage-file".to_string(),
            to_s(&bob_kp),
        ],
    );

    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "bootstrap-group-state".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--member-keypackage".to_string(),
            to_s(&alice_kp),
            "--own-leaf".to_string(),
            "0".to_string(),
            "--out".to_string(),
            to_s(&sender_group_state),
            "--force".to_string(),
        ],
    );
    fs::copy(&sender_group_state, &receiver_group_state).expect("copy group state snapshot");

    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "fetch-key-package".to_string(),
            "--target".to_string(),
            "bob".to_string(),
            "--out".to_string(),
            to_s(&bob_from_ds),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "create-add-proposal".to_string(),
            "--group-state".to_string(),
            to_s(&sender_group_state),
            "--keypackage-file".to_string(),
            to_s(&bob_from_ds),
            "--out".to_string(),
            to_s(&proposal_file),
            "--sender-leaf".to_string(),
            "0".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "submit-proposal".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--proposal-file".to_string(),
            to_s(&proposal_file),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "create-commit".to_string(),
            "--group-state".to_string(),
            to_s(&sender_group_state),
            "--commit-out".to_string(),
            to_s(&commit_file),
            "--path-update-out".to_string(),
            to_s(&path_file),
            "--sender-leaf".to_string(),
            "0".to_string(),
        ],
    );
    let submit_output = run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "submit-commit".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--commit-file".to_string(),
            to_s(&commit_file),
            "--path-update-file".to_string(),
            to_s(&path_file),
        ],
    );
    let submit_json = parse_json_from_ds_client_output(&submit_output);
    let commit_id: i64 = submit_json["commit_id"]
        .as_str()
        .expect("commit_id str")
        .parse()
        .expect("commit_id i64");

    let first_sync = run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "fetch-and-apply-latest".to_string(),
            "--group-state".to_string(),
            to_s(&receiver_group_state),
            "--limit".to_string(),
            "100".to_string(),
        ],
    );
    assert!(
        first_sync.contains("applied_total=1"),
        "first sync output:\n{first_sync}"
    );

    let loaded_once =
        ClientGroupState::load_from_file(&receiver_group_state).expect("load synced state");
    assert_eq!(loaded_once.epoch, 1);
    assert_eq!(loaded_once.last_applied_commit_id, Some(commit_id));
    assert!(loaded_once.has_applied_commit_id(commit_id));
    let bob_leaf_node = RatchetTree::leaf_to_node_index(1);
    assert!(
        matches!(
            loaded_once.ratchet_tree.nodes.get(bob_leaf_node),
            Some(Node::Leaf(_))
        ),
        "bob leaf should exist after sync"
    );

    let second_sync = run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "fetch-and-apply-latest".to_string(),
            "--group-state".to_string(),
            to_s(&receiver_group_state),
            "--limit".to_string(),
            "100".to_string(),
        ],
    );
    assert!(
        second_sync.contains("applied_total=0"),
        "second sync output:\n{second_sync}"
    );

    let loaded_twice =
        ClientGroupState::load_from_file(&receiver_group_state).expect("reload state after replay");
    assert_eq!(loaded_twice.epoch, 1);
    assert_eq!(loaded_twice.last_applied_commit_id, Some(commit_id));

    let _ = shutdown_tx.send(());
    let result = server.await.expect("join server");
    if let Err(err) = result {
        panic!("server returned error: {err}");
    }

    let _ = fs::remove_dir_all(base);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn strict_receiver_policy_rejects_missing_path_update() {
    let (state, base) = temp_state("strict-missing-path");
    let (addr, shutdown_tx, server) = start_test_server(state).await;
    let base_url = format!("http://{addr}");
    let client_bin = env!("CARGO_BIN_EXE_ds_client");

    let work = base.join("work");
    let _ = fs::create_dir_all(&work);

    let alice_state = work.join("alice.json");
    let bob_state = work.join("bob.json");
    let alice_kem = work.join("alice-kem.json");
    let bob_kem = work.join("bob-kem.json");
    let bob_v2_kem = work.join("bob-v2-kem.json");
    let alice_kp = work.join("alice.kp");
    let bob_kp = work.join("bob.kp");
    let bob_v2_kp = work.join("bob-v2.kp");
    let alice_recv = work.join("alice.recv.json");
    let bob_recv = work.join("bob.recv.json");
    let bob_v2_recv = work.join("bob-v2.recv.json");
    let bob_sender_state = work.join("bob-sender-state.bin");
    let alice_receiver_state = work.join("alice-receiver-state.bin");
    let proposal_file = work.join("bob-update.proposal.bin");
    let commit_file = work.join("bob-update.commit.bin");
    let path_file = work.join("bob-update.path.bin");
    let group_id = "group-strict";

    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "register".to_string(),
            "--username".to_string(),
            "alice".to_string(),
            "--password".to_string(),
            "secret".to_string(),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "register".to_string(),
            "--username".to_string(),
            "bob".to_string(),
            "--password".to_string(),
            "secret".to_string(),
            "--force".to_string(),
        ],
    );

    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "keygen".to_string(),
            "--out".to_string(),
            to_s(&alice_kem),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "keypackage-export".to_string(),
            "--kem-file".to_string(),
            to_s(&alice_kem),
            "--keypackage-out".to_string(),
            to_s(&alice_kp),
            "--receiver-private-out".to_string(),
            to_s(&alice_recv),
            "--force".to_string(),
        ],
    );

    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "keygen".to_string(),
            "--out".to_string(),
            to_s(&bob_kem),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "keypackage-export".to_string(),
            "--kem-file".to_string(),
            to_s(&bob_kem),
            "--keypackage-out".to_string(),
            to_s(&bob_kp),
            "--receiver-private-out".to_string(),
            to_s(&bob_recv),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "keygen".to_string(),
            "--out".to_string(),
            to_s(&bob_v2_kem),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "keypackage-export".to_string(),
            "--kem-file".to_string(),
            to_s(&bob_v2_kem),
            "--keypackage-out".to_string(),
            to_s(&bob_v2_kp),
            "--receiver-private-out".to_string(),
            to_s(&bob_v2_recv),
            "--force".to_string(),
        ],
    );

    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "bootstrap-group-state".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--member-keypackage".to_string(),
            to_s(&alice_kp),
            "--member-keypackage".to_string(),
            to_s(&bob_kp),
            "--own-leaf".to_string(),
            "1".to_string(),
            "--out".to_string(),
            to_s(&bob_sender_state),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "bootstrap-group-state".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--member-keypackage".to_string(),
            to_s(&alice_kp),
            "--member-keypackage".to_string(),
            to_s(&bob_kp),
            "--own-leaf".to_string(),
            "0".to_string(),
            "--out".to_string(),
            to_s(&alice_receiver_state),
            "--force".to_string(),
        ],
    );

    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "create-update-proposal".to_string(),
            "--group-state".to_string(),
            to_s(&bob_sender_state),
            "--keypackage-file".to_string(),
            to_s(&bob_v2_kp),
            "--out".to_string(),
            to_s(&proposal_file),
            "--sender-leaf".to_string(),
            "1".to_string(),
            "--target-leaf".to_string(),
            "1".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "submit-proposal".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--proposal-file".to_string(),
            to_s(&proposal_file),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "create-commit".to_string(),
            "--group-state".to_string(),
            to_s(&bob_sender_state),
            "--commit-out".to_string(),
            to_s(&commit_file),
            "--path-update-out".to_string(),
            to_s(&path_file),
            "--sender-leaf".to_string(),
            "1".to_string(),
        ],
    );

    // Submit commit without path update payload on purpose.
    run_ds_client_expect_fail(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "submit-commit".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--commit-file".to_string(),
            to_s(&commit_file),
        ],
        "missing_path_update",
    );

    let loaded = ClientGroupState::load_from_file(&alice_receiver_state).expect("load state");
    assert_eq!(loaded.epoch, 0);
    assert_eq!(loaded.last_applied_commit_id, None);

    let _ = shutdown_tx.send(());
    let result = server.await.expect("join server");
    if let Err(err) = result {
        panic!("server returned error: {err}");
    }

    let _ = fs::remove_dir_all(base);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn submit_commit_with_welcome_lists_welcome_kind_end_to_end() {
    let (state, base) = temp_state("welcome-list-e2e");
    let (addr, shutdown_tx, server) = start_test_server(state).await;
    let base_url = format!("http://{addr}");
    let client_bin = env!("CARGO_BIN_EXE_ds_client");

    let work = base.join("work");
    let _ = fs::create_dir_all(&work);

    let alice_state = work.join("alice.json");
    let bob_state = work.join("bob.json");
    let alice_kem = work.join("alice-kem.json");
    let bob_kem = work.join("bob-kem.json");
    let alice_kp = work.join("alice.kp");
    let bob_kp = work.join("bob.kp");
    let alice_recv = work.join("alice.recv.json");
    let bob_recv = work.join("bob.recv.json");
    let alice_group_state = work.join("alice-group-state.bin");
    let bob_from_ds = work.join("bob-from-ds.kp");
    let add_proposal = work.join("add-bob.proposal.bin");
    let commit_file = work.join("add-bob.commit.bin");
    let path_file = work.join("add-bob.path.bin");
    let welcome_file = work.join("add-bob.welcome.bin");
    let bob_join_state = work.join("bob-join-from-welcome.bin");
    let bob_join_derived = work.join("bob-join-from-welcome.derived.json");
    let group_id = "group-welcome-e2e";

    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "register".to_string(),
            "--username".to_string(),
            "alice".to_string(),
            "--password".to_string(),
            "secret".to_string(),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "register".to_string(),
            "--username".to_string(),
            "bob".to_string(),
            "--password".to_string(),
            "secret".to_string(),
            "--force".to_string(),
        ],
    );

    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "keygen".to_string(),
            "--out".to_string(),
            to_s(&alice_kem),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "keypackage-export".to_string(),
            "--kem-file".to_string(),
            to_s(&alice_kem),
            "--keypackage-out".to_string(),
            to_s(&alice_kp),
            "--receiver-private-out".to_string(),
            to_s(&alice_recv),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "keygen".to_string(),
            "--out".to_string(),
            to_s(&bob_kem),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "keypackage-export".to_string(),
            "--kem-file".to_string(),
            to_s(&bob_kem),
            "--keypackage-out".to_string(),
            to_s(&bob_kp),
            "--receiver-private-out".to_string(),
            to_s(&bob_recv),
            "--force".to_string(),
        ],
    );

    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "publish-key-package".to_string(),
            "--keypackage-file".to_string(),
            to_s(&bob_kp),
        ],
    );

    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "bootstrap-group-state".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--member-keypackage".to_string(),
            to_s(&alice_kp),
            "--own-leaf".to_string(),
            "0".to_string(),
            "--out".to_string(),
            to_s(&alice_group_state),
            "--force".to_string(),
        ],
    );

    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "fetch-key-package".to_string(),
            "--target".to_string(),
            "bob".to_string(),
            "--out".to_string(),
            to_s(&bob_from_ds),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "create-add-proposal".to_string(),
            "--group-state".to_string(),
            to_s(&alice_group_state),
            "--keypackage-file".to_string(),
            to_s(&bob_from_ds),
            "--out".to_string(),
            to_s(&add_proposal),
            "--sender-leaf".to_string(),
            "0".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "submit-proposal".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--proposal-file".to_string(),
            to_s(&add_proposal),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "create-commit".to_string(),
            "--group-state".to_string(),
            to_s(&alice_group_state),
            "--commit-out".to_string(),
            to_s(&commit_file),
            "--path-update-out".to_string(),
            to_s(&path_file),
            "--welcome-out".to_string(),
            to_s(&welcome_file),
            "--sender-leaf".to_string(),
            "0".to_string(),
        ],
    );

    let welcome_len = fs::metadata(&welcome_file)
        .expect("welcome file metadata")
        .len();
    assert!(welcome_len > 0, "welcome file must not be empty");

    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "submit-commit".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--commit-file".to_string(),
            to_s(&commit_file),
            "--path-update-file".to_string(),
            to_s(&path_file),
            "--welcome-file".to_string(),
            to_s(&welcome_file),
        ],
    );

    let welcome_list_output = run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "list-messages".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--limit".to_string(),
            "10".to_string(),
            "--kind".to_string(),
            "welcome".to_string(),
        ],
    );
    let welcome_list_json = parse_json_from_ds_client_output(&welcome_list_output);
    let messages = welcome_list_json["messages"]
        .as_array()
        .expect("messages array");
    assert_eq!(
        messages.len(),
        1,
        "welcome list output: {welcome_list_output}"
    );
    assert_eq!(
        messages[0]["kind"].as_str(),
        Some("welcome"),
        "welcome list output: {welcome_list_output}"
    );
    assert_eq!(
        messages[0]["size"].as_u64(),
        Some(welcome_len),
        "welcome list output: {welcome_list_output}"
    );
    assert!(
        messages[0]["id"].as_str().is_some(),
        "welcome list output: {welcome_list_output}"
    );

    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "join-from-welcome".to_string(),
            "--base-member-keypackage".to_string(),
            to_s(&alice_kp),
            "--commit-file".to_string(),
            to_s(&commit_file),
            "--path-update-file".to_string(),
            to_s(&path_file),
            "--welcome-file".to_string(),
            to_s(&welcome_file),
            "--receiver-private-file".to_string(),
            to_s(&bob_recv),
            "--out".to_string(),
            to_s(&bob_join_state),
            "--derived-out".to_string(),
            to_s(&bob_join_derived),
            "--force".to_string(),
        ],
    );
    let bob_joined = ClientGroupState::load_from_file(&bob_join_state)
        .expect("load bob join-from-welcome state");
    assert_eq!(bob_joined.group_id, group_id);
    assert_eq!(bob_joined.epoch, 1);
    assert_eq!(bob_joined.own_leaf_index, 1);
    let bob_leaf_node = RatchetTree::leaf_to_node_index(1);
    assert!(
        matches!(
            bob_joined.ratchet_tree.nodes.get(bob_leaf_node),
            Some(Node::Leaf(_))
        ),
        "bob leaf should exist after join-from-welcome"
    );
    let derived_json: Value = serde_json::from_slice(
        &fs::read(&bob_join_derived).expect("read bob join-from-welcome derived json"),
    )
    .expect("parse bob join-from-welcome derived json");
    assert!(
        derived_json["joiner_secret_b64"].as_str().is_some(),
        "derived json must include joiner_secret_b64"
    );

    let _ = shutdown_tx.send(());
    let result = server.await.expect("join server");
    if let Err(err) = result {
        panic!("server returned error: {err}");
    }
    let _ = fs::remove_dir_all(base);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn welcome_payload_is_stable_across_ds_submit_and_fetch_roundtrip() {
    let fixture = setup_unknown_group_welcome_fixture(
        "welcome-roundtrip-stability",
        "group-welcome-roundtrip-stability",
        false,
    )
    .await;

    let local_welcome = fs::read(&fixture.welcome_file).expect("read local welcome payload");
    assert!(
        !local_welcome.is_empty(),
        "local welcome payload must not be empty"
    );

    let list_output = run_ds_client(
        fixture.client_bin,
        &fixture.base_url,
        &fixture.alice_state,
        &[
            "list-messages".to_string(),
            "--group-id".to_string(),
            fixture.group_id.clone(),
            "--limit".to_string(),
            "10".to_string(),
            "--kind".to_string(),
            "welcome".to_string(),
        ],
    );
    let list_json = parse_json_from_ds_client_output(&list_output);
    let welcome_id_str = list_json["messages"]
        .as_array()
        .and_then(|items| items.first())
        .and_then(|item| item.get("id"))
        .and_then(|id| id.as_str())
        .expect("welcome message id from list");
    let welcome_id = welcome_id_str
        .parse::<i64>()
        .expect("welcome message id must parse as i64");

    let (username, session_id, signing_key) = signing_key_from_state_file(&fixture.alice_state);
    let sign_input = fetch_message_signing_input_for_test(&username, &fixture.group_id, welcome_id);
    let signature = sign_message_b64_with_large_stack(signing_key, sign_input);
    let query = serde_urlencoded::to_string([
        ("username", username.as_str()),
        ("session_id", session_id.as_str()),
        ("signature", signature.as_str()),
    ])
    .expect("encode fetch query");
    let fetch_url = format!(
        "{}/v1/groups/{}/messages/{}?{}",
        fixture.base_url, fixture.group_id, welcome_id, query
    );
    let fetch_resp = reqwest::Client::new()
        .get(fetch_url)
        .send()
        .await
        .expect("fetch welcome message");
    assert_eq!(fetch_resp.status(), reqwest::StatusCode::OK);
    let fetch_json: Value = fetch_resp.json().await.expect("parse fetch response json");
    assert_eq!(fetch_json["kind"].as_str(), Some("welcome"));
    let fetched_welcome_b64 = fetch_json["message_bytes"]
        .as_str()
        .expect("fetched welcome message_bytes");
    let fetched_welcome = STANDARD
        .decode(fetched_welcome_b64)
        .expect("decode fetched welcome bytes");

    assert_eq!(
        fetched_welcome, local_welcome,
        "welcome payload bytes changed across DS submit/fetch roundtrip"
    );

    teardown_welcome_bootstrap_fixture(fixture).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn envelope_fixtures_are_stable_across_ds_submit_and_fetch_roundtrip() {
    let (state, base) = temp_state("envelope-fixture-roundtrip");
    let (addr, shutdown_tx, server) = start_test_server(state).await;
    let base_url = format!("http://{addr}");
    let client_bin = env!("CARGO_BIN_EXE_ds_client");
    let work = base.join("work");
    let _ = fs::create_dir_all(&work);

    let group_id = "vector-env";
    let alice_state = work.join("alice.json");
    let alice_kem = work.join("alice-kem.json");
    let alice_kp = work.join("alice.kp");
    let alice_recv = work.join("alice.recv.json");

    register_and_export_keypackage(
        client_bin,
        &base_url,
        &alice_state,
        "alice",
        &alice_kem,
        &alice_kp,
        &alice_recv,
    );

    let vectors = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("vectors");
    let proposal_fixture = vectors.join("proposal_envelope_vector.bin");
    let commit_fixture = vectors.join("commit_envelope_vector.bin");
    let path_fixture = vectors.join("path_update_envelope_vector.bin");
    let proposal_bytes = fs::read(&proposal_fixture).expect("read proposal fixture bytes");
    let commit_bytes = fs::read(&commit_fixture).expect("read commit fixture bytes");
    let path_bytes = fs::read(&path_fixture).expect("read path fixture bytes");

    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "submit-proposal".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--proposal-file".to_string(),
            to_s(&proposal_fixture),
        ],
    );

    let list_proposal = run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "list-messages".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--limit".to_string(),
            "10".to_string(),
            "--kind".to_string(),
            "proposal".to_string(),
        ],
    );
    let proposal_list_json = parse_json_from_ds_client_output(&list_proposal);
    let proposal_id = first_list_message_id(&proposal_list_json)
        .unwrap_or_else(|| panic!("proposal message id; list output: {list_proposal}"));
    let (proposal_kind, fetched_proposal) =
        fetch_group_message_bytes(&base_url, &alice_state, group_id, proposal_id).await;
    assert_eq!(proposal_kind, "proposal");
    assert_eq!(fetched_proposal, proposal_bytes);

    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "submit-commit".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--commit-file".to_string(),
            to_s(&commit_fixture),
            "--path-update-file".to_string(),
            to_s(&path_fixture),
        ],
    );

    let list_commit = run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "list-messages".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--limit".to_string(),
            "10".to_string(),
            "--kind".to_string(),
            "commit".to_string(),
        ],
    );
    let commit_list_json = parse_json_from_ds_client_output(&list_commit);
    let commit_id = first_list_message_id(&commit_list_json)
        .unwrap_or_else(|| panic!("commit message id; list output: {list_commit}"));
    let (commit_kind, fetched_commit) =
        fetch_group_message_bytes(&base_url, &alice_state, group_id, commit_id).await;
    assert_eq!(commit_kind, "commit");
    assert_eq!(fetched_commit, commit_bytes);

    let list_path = run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "list-messages".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--limit".to_string(),
            "10".to_string(),
            "--kind".to_string(),
            "path_update".to_string(),
        ],
    );
    let path_list_json = parse_json_from_ds_client_output(&list_path);
    let path_id = first_list_message_id(&path_list_json)
        .unwrap_or_else(|| panic!("path_update message id; list output: {list_path}"));
    let (path_kind, fetched_path) =
        fetch_group_message_bytes(&base_url, &alice_state, group_id, path_id).await;
    assert_eq!(path_kind, "path_update");
    assert_eq!(fetched_path, path_bytes);

    let _ = shutdown_tx.send(());
    let result = server.await.expect("join server");
    if let Err(err) = result {
        panic!("server returned error: {err}");
    }
    let _ = fs::remove_dir_all(base);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fetch_and_apply_latest_bootstraps_unknown_group_from_welcome() {
    let (state, base) = temp_state("welcome-auto-bootstrap-e2e");
    let (addr, shutdown_tx, server) = start_test_server(state).await;
    let base_url = format!("http://{addr}");
    let client_bin = env!("CARGO_BIN_EXE_ds_client");

    let work = base.join("work");
    let _ = fs::create_dir_all(&work);

    let alice_state = work.join("alice.json");
    let bob_state = work.join("bob.json");
    let alice_kem = work.join("alice-kem.json");
    let bob_kem = work.join("bob-kem.json");
    let alice_kp = work.join("alice.kp");
    let bob_kp = work.join("bob.kp");
    let alice_recv = work.join("alice.recv.json");
    let bob_recv = work.join("bob.recv.json");
    let alice_group_state = work.join("alice-group-state.bin");
    let bob_unknown_group_state = work.join("bob-unknown-group-state.bin");
    let bob_from_ds = work.join("bob-from-ds.kp");
    let add_proposal = work.join("add-bob.proposal.bin");
    let commit_file = work.join("add-bob.commit.bin");
    let path_file = work.join("add-bob.path.bin");
    let welcome_file = work.join("add-bob.welcome.bin");
    let group_id = "group-welcome-auto-bootstrap";

    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "register".to_string(),
            "--username".to_string(),
            "alice".to_string(),
            "--password".to_string(),
            "secret".to_string(),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "register".to_string(),
            "--username".to_string(),
            "bob".to_string(),
            "--password".to_string(),
            "secret".to_string(),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "keygen".to_string(),
            "--out".to_string(),
            to_s(&alice_kem),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "keypackage-export".to_string(),
            "--kem-file".to_string(),
            to_s(&alice_kem),
            "--keypackage-out".to_string(),
            to_s(&alice_kp),
            "--receiver-private-out".to_string(),
            to_s(&alice_recv),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "keygen".to_string(),
            "--out".to_string(),
            to_s(&bob_kem),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "keypackage-export".to_string(),
            "--kem-file".to_string(),
            to_s(&bob_kem),
            "--keypackage-out".to_string(),
            to_s(&bob_kp),
            "--receiver-private-out".to_string(),
            to_s(&bob_recv),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "publish-key-package".to_string(),
            "--keypackage-file".to_string(),
            to_s(&bob_kp),
        ],
    );

    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "bootstrap-group-state".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--member-keypackage".to_string(),
            to_s(&alice_kp),
            "--own-leaf".to_string(),
            "0".to_string(),
            "--out".to_string(),
            to_s(&alice_group_state),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "fetch-key-package".to_string(),
            "--target".to_string(),
            "bob".to_string(),
            "--out".to_string(),
            to_s(&bob_from_ds),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "create-add-proposal".to_string(),
            "--group-state".to_string(),
            to_s(&alice_group_state),
            "--keypackage-file".to_string(),
            to_s(&bob_from_ds),
            "--out".to_string(),
            to_s(&add_proposal),
            "--sender-leaf".to_string(),
            "0".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "submit-proposal".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--proposal-file".to_string(),
            to_s(&add_proposal),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "create-commit".to_string(),
            "--group-state".to_string(),
            to_s(&alice_group_state),
            "--commit-out".to_string(),
            to_s(&commit_file),
            "--path-update-out".to_string(),
            to_s(&path_file),
            "--welcome-out".to_string(),
            to_s(&welcome_file),
            "--sender-leaf".to_string(),
            "0".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "submit-commit".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--commit-file".to_string(),
            to_s(&commit_file),
            "--path-update-file".to_string(),
            to_s(&path_file),
            "--welcome-file".to_string(),
            to_s(&welcome_file),
        ],
    );

    let sync_output = run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "fetch-and-apply-latest".to_string(),
            "--group-state".to_string(),
            to_s(&bob_unknown_group_state),
            "--group-id".to_string(),
            group_id.to_string(),
            "--base-member-keypackage".to_string(),
            to_s(&alice_kp),
            "--receiver-private-file".to_string(),
            to_s(&bob_recv),
            "--limit".to_string(),
            "100".to_string(),
        ],
    );
    assert!(
        sync_output.contains("bootstrapped unknown group state via welcome"),
        "sync output:\n{sync_output}"
    );

    let bob_joined = ClientGroupState::load_from_file(&bob_unknown_group_state)
        .expect("load auto-bootstrapped bob state");
    assert_eq!(bob_joined.group_id, group_id);
    assert_eq!(bob_joined.epoch, 1);
    assert_eq!(bob_joined.own_leaf_index, 1);
    let bob_leaf_node = RatchetTree::leaf_to_node_index(1);
    assert!(
        matches!(
            bob_joined.ratchet_tree.nodes.get(bob_leaf_node),
            Some(Node::Leaf(_))
        ),
        "bob leaf should exist after auto welcome bootstrap"
    );

    let _ = shutdown_tx.send(());
    let result = server.await.expect("join server");
    if let Err(err) = result {
        panic!("server returned error: {err}");
    }
    let _ = fs::remove_dir_all(base);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stage_keys_remain_stable_across_reload_and_fetch_apply() {
    let fixture = setup_unknown_group_welcome_fixture(
        "stage-key-stability",
        "group-stage-key-stability",
        false,
    )
    .await;

    let first_sync = run_ds_client(
        fixture.client_bin,
        &fixture.base_url,
        &fixture.bob_state,
        &[
            "fetch-and-apply-latest".to_string(),
            "--group-state".to_string(),
            to_s(&fixture.bob_unknown_group_state),
            "--group-id".to_string(),
            fixture.group_id.clone(),
            "--base-member-keypackage".to_string(),
            to_s(&fixture.alice_kp),
            "--receiver-private-file".to_string(),
            to_s(&fixture.bob_recv),
            "--limit".to_string(),
            "100".to_string(),
        ],
    );
    assert!(
        first_sync.contains("bootstrapped unknown group state via welcome"),
        "first sync output:\n{first_sync}"
    );
    assert!(
        first_sync.contains("applied_total=1"),
        "first sync output:\n{first_sync}"
    );

    let loaded_once = ClientGroupState::load_from_file(&fixture.bob_unknown_group_state)
        .expect("load bootstrapped group state");
    assert_eq!(loaded_once.epoch, 1);
    let derived_once = loaded_once
        .current_epoch_derived_secrets()
        .expect("derived secrets after first sync");
    let confirmation_once = loaded_once
        .current_confirmation_key()
        .expect("confirmation key after first sync");
    let membership_once = loaded_once
        .current_membership_key()
        .expect("membership key after first sync");
    let sender_data_once = loaded_once
        .current_sender_data_key()
        .expect("sender-data key after first sync");
    assert_eq!(confirmation_once, derived_once.confirmation_key);
    assert_eq!(membership_once, derived_once.membership_key);
    assert_eq!(sender_data_once, derived_once.sender_data_key);

    let reloaded = ClientGroupState::load_from_file(&fixture.bob_unknown_group_state)
        .expect("reload group state after first sync");
    let derived_reloaded = reloaded
        .current_epoch_derived_secrets()
        .expect("derived secrets after reload");
    assert_eq!(
        derived_once.confirmation_key,
        derived_reloaded.confirmation_key
    );
    assert_eq!(derived_once.membership_key, derived_reloaded.membership_key);
    assert_eq!(
        derived_once.sender_data_key,
        derived_reloaded.sender_data_key
    );

    let second_sync = run_ds_client(
        fixture.client_bin,
        &fixture.base_url,
        &fixture.bob_state,
        &[
            "fetch-and-apply-latest".to_string(),
            "--group-state".to_string(),
            to_s(&fixture.bob_unknown_group_state),
            "--limit".to_string(),
            "100".to_string(),
        ],
    );
    assert!(
        second_sync.contains("applied_total=0"),
        "second sync output:\n{second_sync}"
    );

    let reloaded_after_noop = ClientGroupState::load_from_file(&fixture.bob_unknown_group_state)
        .expect("reload group state after no-op sync");
    let derived_after_noop = reloaded_after_noop
        .current_epoch_derived_secrets()
        .expect("derived secrets after no-op sync");
    assert_eq!(
        derived_reloaded.confirmation_key,
        derived_after_noop.confirmation_key
    );
    assert_eq!(
        derived_reloaded.membership_key,
        derived_after_noop.membership_key
    );
    assert_eq!(
        derived_reloaded.sender_data_key,
        derived_after_noop.sender_data_key
    );

    teardown_welcome_bootstrap_fixture(fixture).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stage_keys_remain_stable_across_multi_epoch_commit_chain() {
    let fixture = setup_unknown_group_welcome_fixture(
        "stage-key-stability-multi-epoch",
        "group-stage-key-stability-multi-epoch",
        false,
    )
    .await;

    let alice_group_state = fixture.work.join("alice-group-state.bin");
    let alice_v2_kem = fixture.work.join("alice-v2-kem.json");
    let alice_v2_kp = fixture.work.join("alice-v2.kp");
    let alice_v2_recv = fixture.work.join("alice-v2.recv.json");
    let update_proposal = fixture.work.join("alice-update.proposal.bin");
    let commit_file = fixture.work.join("alice-update.commit.bin");
    let path_file = fixture.work.join("alice-update.path.bin");

    let first_sync = run_ds_client(
        fixture.client_bin,
        &fixture.base_url,
        &fixture.bob_state,
        &[
            "fetch-and-apply-latest".to_string(),
            "--group-state".to_string(),
            to_s(&fixture.bob_unknown_group_state),
            "--group-id".to_string(),
            fixture.group_id.clone(),
            "--base-member-keypackage".to_string(),
            to_s(&fixture.alice_kp),
            "--receiver-private-file".to_string(),
            to_s(&fixture.bob_recv),
            "--limit".to_string(),
            "100".to_string(),
        ],
    );
    assert!(
        first_sync.contains("bootstrapped unknown group state via welcome"),
        "first sync output:\n{first_sync}"
    );
    assert!(
        first_sync.contains("applied_total=1"),
        "first sync output:\n{first_sync}"
    );

    let bob_epoch1 = ClientGroupState::load_from_file(&fixture.bob_unknown_group_state)
        .expect("load bob state at epoch 1");
    assert_eq!(bob_epoch1.epoch, 1);
    let epoch1_derived = bob_epoch1
        .current_epoch_derived_secrets()
        .expect("derive stage keys at epoch 1");

    run_ds_client(
        fixture.client_bin,
        &fixture.base_url,
        &fixture.alice_state,
        &[
            "keygen".to_string(),
            "--out".to_string(),
            to_s(&alice_v2_kem),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        fixture.client_bin,
        &fixture.base_url,
        &fixture.alice_state,
        &[
            "keypackage-export".to_string(),
            "--kem-file".to_string(),
            to_s(&alice_v2_kem),
            "--keypackage-out".to_string(),
            to_s(&alice_v2_kp),
            "--receiver-private-out".to_string(),
            to_s(&alice_v2_recv),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        fixture.client_bin,
        &fixture.base_url,
        &fixture.alice_state,
        &[
            "create-update-proposal".to_string(),
            "--group-state".to_string(),
            to_s(&alice_group_state),
            "--keypackage-file".to_string(),
            to_s(&alice_v2_kp),
            "--out".to_string(),
            to_s(&update_proposal),
            "--sender-leaf".to_string(),
            "0".to_string(),
            "--target-leaf".to_string(),
            "0".to_string(),
        ],
    );
    run_ds_client(
        fixture.client_bin,
        &fixture.base_url,
        &fixture.alice_state,
        &[
            "submit-proposal".to_string(),
            "--group-id".to_string(),
            fixture.group_id.clone(),
            "--proposal-file".to_string(),
            to_s(&update_proposal),
        ],
    );
    run_ds_client(
        fixture.client_bin,
        &fixture.base_url,
        &fixture.alice_state,
        &[
            "create-commit".to_string(),
            "--group-state".to_string(),
            to_s(&alice_group_state),
            "--commit-out".to_string(),
            to_s(&commit_file),
            "--path-update-out".to_string(),
            to_s(&path_file),
            "--sender-leaf".to_string(),
            "0".to_string(),
        ],
    );
    run_ds_client(
        fixture.client_bin,
        &fixture.base_url,
        &fixture.alice_state,
        &[
            "submit-commit".to_string(),
            "--group-id".to_string(),
            fixture.group_id.clone(),
            "--commit-file".to_string(),
            to_s(&commit_file),
            "--path-update-file".to_string(),
            to_s(&path_file),
        ],
    );

    let second_sync = run_ds_client(
        fixture.client_bin,
        &fixture.base_url,
        &fixture.bob_state,
        &[
            "fetch-and-apply-latest".to_string(),
            "--group-state".to_string(),
            to_s(&fixture.bob_unknown_group_state),
            "--limit".to_string(),
            "100".to_string(),
        ],
    );
    assert!(
        second_sync.contains("applied_total=1"),
        "second sync output:\n{second_sync}"
    );

    let bob_epoch2 = ClientGroupState::load_from_file(&fixture.bob_unknown_group_state)
        .expect("load bob state at epoch 2");
    assert_eq!(bob_epoch2.epoch, 2);
    assert_eq!(bob_epoch2.key_schedule.current_epoch, 2);
    let epoch2_derived = bob_epoch2
        .current_epoch_derived_secrets()
        .expect("derive stage keys at epoch 2");

    assert_ne!(
        epoch1_derived.confirmation_key,
        epoch2_derived.confirmation_key
    );
    assert_ne!(epoch1_derived.membership_key, epoch2_derived.membership_key);
    assert_ne!(
        epoch1_derived.sender_data_key,
        epoch2_derived.sender_data_key
    );

    let bob_epoch2_reloaded = ClientGroupState::load_from_file(&fixture.bob_unknown_group_state)
        .expect("reload bob state at epoch 2");
    let epoch2_reloaded_derived = bob_epoch2_reloaded
        .current_epoch_derived_secrets()
        .expect("derive stage keys after reload at epoch 2");
    assert_eq!(
        epoch2_derived.confirmation_key,
        epoch2_reloaded_derived.confirmation_key
    );
    assert_eq!(
        epoch2_derived.membership_key,
        epoch2_reloaded_derived.membership_key
    );
    assert_eq!(
        epoch2_derived.sender_data_key,
        epoch2_reloaded_derived.sender_data_key
    );

    let third_sync = run_ds_client(
        fixture.client_bin,
        &fixture.base_url,
        &fixture.bob_state,
        &[
            "fetch-and-apply-latest".to_string(),
            "--group-state".to_string(),
            to_s(&fixture.bob_unknown_group_state),
            "--limit".to_string(),
            "100".to_string(),
        ],
    );
    assert!(
        third_sync.contains("applied_total=0"),
        "third sync output:\n{third_sync}"
    );

    let bob_epoch2_after_noop = ClientGroupState::load_from_file(&fixture.bob_unknown_group_state)
        .expect("reload bob state after no-op sync");
    let epoch2_after_noop = bob_epoch2_after_noop
        .current_epoch_derived_secrets()
        .expect("derive stage keys after no-op sync");
    assert_eq!(
        epoch2_derived.confirmation_key,
        epoch2_after_noop.confirmation_key
    );
    assert_eq!(
        epoch2_derived.membership_key,
        epoch2_after_noop.membership_key
    );
    assert_eq!(
        epoch2_derived.sender_data_key,
        epoch2_after_noop.sender_data_key
    );

    teardown_welcome_bootstrap_fixture(fixture).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn auto_bootstrap_rejects_wrong_base_members() {
    let fixture = setup_unknown_group_welcome_fixture(
        "welcome-auto-bootstrap-wrong-base",
        "group-welcome-auto-bootstrap-wrong-base",
        false,
    )
    .await;

    let output = run_ds_client_expect_fail(
        fixture.client_bin,
        &fixture.base_url,
        &fixture.bob_state,
        &[
            "fetch-and-apply-latest".to_string(),
            "--group-state".to_string(),
            to_s(&fixture.bob_unknown_group_state),
            "--group-id".to_string(),
            fixture.group_id.clone(),
            "--base-member-keypackage".to_string(),
            to_s(&fixture.bob_kp),
            "--receiver-private-file".to_string(),
            to_s(&fixture.bob_recv),
            "--limit".to_string(),
            "100".to_string(),
        ],
        "could not bootstrap unknown group",
    );
    assert!(
        output.contains("could not bootstrap unknown group"),
        "unexpected bootstrap failure output:\n{output}"
    );
    assert!(
        !fixture.bob_unknown_group_state.exists(),
        "group state must not be created when base members are wrong"
    );

    teardown_welcome_bootstrap_fixture(fixture).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn auto_bootstrap_rejects_wrong_receiver_private_key() {
    let fixture = setup_unknown_group_welcome_fixture(
        "welcome-auto-bootstrap-wrong-recv",
        "group-welcome-auto-bootstrap-wrong-recv",
        false,
    )
    .await;

    let bob_wrong_kem = fixture.work.join("bob-wrong-kem.json");
    let bob_wrong_kp = fixture.work.join("bob-wrong.kp");
    let bob_wrong_recv = fixture.work.join("bob-wrong.recv.json");

    run_ds_client(
        fixture.client_bin,
        &fixture.base_url,
        &fixture.bob_state,
        &[
            "keygen".to_string(),
            "--out".to_string(),
            to_s(&bob_wrong_kem),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        fixture.client_bin,
        &fixture.base_url,
        &fixture.bob_state,
        &[
            "keypackage-export".to_string(),
            "--kem-file".to_string(),
            to_s(&bob_wrong_kem),
            "--keypackage-out".to_string(),
            to_s(&bob_wrong_kp),
            "--receiver-private-out".to_string(),
            to_s(&bob_wrong_recv),
            "--force".to_string(),
        ],
    );

    let output = run_ds_client_expect_fail(
        fixture.client_bin,
        &fixture.base_url,
        &fixture.bob_state,
        &[
            "fetch-and-apply-latest".to_string(),
            "--group-state".to_string(),
            to_s(&fixture.bob_unknown_group_state),
            "--group-id".to_string(),
            fixture.group_id.clone(),
            "--base-member-keypackage".to_string(),
            to_s(&fixture.alice_kp),
            "--receiver-private-file".to_string(),
            to_s(&bob_wrong_recv),
            "--limit".to_string(),
            "100".to_string(),
        ],
        "could not bootstrap unknown group",
    );
    assert!(
        output.contains("could not bootstrap unknown group"),
        "unexpected bootstrap failure output:\n{output}"
    );
    assert!(
        !fixture.bob_unknown_group_state.exists(),
        "group state must not be created when receiver private key is wrong"
    );

    teardown_welcome_bootstrap_fixture(fixture).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn auto_bootstrap_rejects_tampered_welcome_payload() {
    let fixture = setup_unknown_group_welcome_fixture(
        "welcome-auto-bootstrap-tampered",
        "group-welcome-auto-bootstrap-tampered",
        true,
    )
    .await;

    let output = run_ds_client_expect_fail(
        fixture.client_bin,
        &fixture.base_url,
        &fixture.bob_state,
        &[
            "fetch-and-apply-latest".to_string(),
            "--group-state".to_string(),
            to_s(&fixture.bob_unknown_group_state),
            "--group-id".to_string(),
            fixture.group_id.clone(),
            "--base-member-keypackage".to_string(),
            to_s(&fixture.alice_kp),
            "--receiver-private-file".to_string(),
            to_s(&fixture.bob_recv),
            "--limit".to_string(),
            "100".to_string(),
        ],
        "could not bootstrap unknown group",
    );
    assert!(
        output.contains("could not bootstrap unknown group"),
        "unexpected bootstrap failure output:\n{output}"
    );
    assert!(
        !fixture.bob_unknown_group_state.exists(),
        "group state must not be created when welcome is tampered"
    );

    teardown_welcome_bootstrap_fixture(fixture).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn strict_receiver_policy_rejects_mismatched_path_update_metadata() {
    let (state, base) = temp_state("strict-mismatched-path");
    let (addr, shutdown_tx, server) = start_test_server(state).await;
    let base_url = format!("http://{addr}");
    let client_bin = env!("CARGO_BIN_EXE_ds_client");

    let work = base.join("work");
    let _ = fs::create_dir_all(&work);

    let alice_state = work.join("alice.json");
    let bob_state = work.join("bob.json");
    let alice_kem = work.join("alice-kem.json");
    let bob_kem = work.join("bob-kem.json");
    let bob_v2_kem = work.join("bob-v2-kem.json");
    let alice_kp = work.join("alice.kp");
    let bob_kp = work.join("bob.kp");
    let bob_v2_kp = work.join("bob-v2.kp");
    let alice_recv = work.join("alice.recv.json");
    let bob_recv = work.join("bob.recv.json");
    let bob_v2_recv = work.join("bob-v2.recv.json");
    let bob_sender_state = work.join("bob-sender-state.bin");
    let alice_receiver_state = work.join("alice-receiver-state.bin");
    let proposal_file = work.join("bob-update.proposal.bin");
    let commit_file = work.join("bob-update.commit.bin");
    let path_file = work.join("bob-update.path.bin");
    let group_id = "group-strict-mismatch";

    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "register".to_string(),
            "--username".to_string(),
            "alice".to_string(),
            "--password".to_string(),
            "secret".to_string(),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "register".to_string(),
            "--username".to_string(),
            "bob".to_string(),
            "--password".to_string(),
            "secret".to_string(),
            "--force".to_string(),
        ],
    );

    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "keygen".to_string(),
            "--out".to_string(),
            to_s(&alice_kem),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "keypackage-export".to_string(),
            "--kem-file".to_string(),
            to_s(&alice_kem),
            "--keypackage-out".to_string(),
            to_s(&alice_kp),
            "--receiver-private-out".to_string(),
            to_s(&alice_recv),
            "--force".to_string(),
        ],
    );

    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "keygen".to_string(),
            "--out".to_string(),
            to_s(&bob_kem),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "keypackage-export".to_string(),
            "--kem-file".to_string(),
            to_s(&bob_kem),
            "--keypackage-out".to_string(),
            to_s(&bob_kp),
            "--receiver-private-out".to_string(),
            to_s(&bob_recv),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "keygen".to_string(),
            "--out".to_string(),
            to_s(&bob_v2_kem),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "keypackage-export".to_string(),
            "--kem-file".to_string(),
            to_s(&bob_v2_kem),
            "--keypackage-out".to_string(),
            to_s(&bob_v2_kp),
            "--receiver-private-out".to_string(),
            to_s(&bob_v2_recv),
            "--force".to_string(),
        ],
    );

    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "bootstrap-group-state".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--member-keypackage".to_string(),
            to_s(&alice_kp),
            "--member-keypackage".to_string(),
            to_s(&bob_kp),
            "--own-leaf".to_string(),
            "1".to_string(),
            "--out".to_string(),
            to_s(&bob_sender_state),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "bootstrap-group-state".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--member-keypackage".to_string(),
            to_s(&alice_kp),
            "--member-keypackage".to_string(),
            to_s(&bob_kp),
            "--own-leaf".to_string(),
            "0".to_string(),
            "--out".to_string(),
            to_s(&alice_receiver_state),
            "--force".to_string(),
        ],
    );

    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "create-update-proposal".to_string(),
            "--group-state".to_string(),
            to_s(&bob_sender_state),
            "--keypackage-file".to_string(),
            to_s(&bob_v2_kp),
            "--out".to_string(),
            to_s(&proposal_file),
            "--sender-leaf".to_string(),
            "1".to_string(),
            "--target-leaf".to_string(),
            "1".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "submit-proposal".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--proposal-file".to_string(),
            to_s(&proposal_file),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "create-commit".to_string(),
            "--group-state".to_string(),
            to_s(&bob_sender_state),
            "--commit-out".to_string(),
            to_s(&commit_file),
            "--path-update-out".to_string(),
            to_s(&path_file),
            "--sender-leaf".to_string(),
            "1".to_string(),
        ],
    );

    let mut path_envelope =
        PathUpdateEnvelope::decode(&fs::read(&path_file).expect("read path file"))
            .expect("decode path envelope");
    path_envelope.sender_leaf = 0;
    fs::write(&path_file, path_envelope.encode()).expect("rewrite mismatched path envelope");

    run_ds_client_expect_fail(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "submit-commit".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--commit-file".to_string(),
            to_s(&commit_file),
            "--path-update-file".to_string(),
            to_s(&path_file),
        ],
        "path_update_sender_mismatch",
    );

    let loaded = ClientGroupState::load_from_file(&alice_receiver_state).expect("load state");
    assert_eq!(loaded.epoch, 0);
    assert_eq!(loaded.last_applied_commit_id, None);

    let _ = shutdown_tx.send(());
    let result = server.await.expect("join server");
    if let Err(err) = result {
        panic!("server returned error: {err}");
    }

    let _ = fs::remove_dir_all(base);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn three_member_commit_chain_sync_converges_with_path_updates() {
    let (state, base) = temp_state("three-member-chain");
    let (addr, shutdown_tx, server) = start_test_server(state).await;
    let base_url = format!("http://{addr}");
    let client_bin = env!("CARGO_BIN_EXE_ds_client");

    let work = base.join("work");
    let _ = fs::create_dir_all(&work);

    let alice_state = work.join("alice.json");
    let bob_state = work.join("bob.json");
    let carol_state = work.join("carol.json");

    let alice_kem = work.join("alice-kem.json");
    let bob_kem = work.join("bob-kem.json");
    let carol_kem = work.join("carol-kem.json");
    let alice_v2_kem = work.join("alice-v2-kem.json");
    let bob_v2_kem = work.join("bob-v2-kem.json");

    let alice_kp = work.join("alice.kp");
    let bob_kp = work.join("bob.kp");
    let carol_kp = work.join("carol.kp");
    let alice_v2_kp = work.join("alice-v2.kp");
    let bob_v2_kp = work.join("bob-v2.kp");

    let alice_recv = work.join("alice.recv.json");
    let bob_recv = work.join("bob.recv.json");
    let carol_recv = work.join("carol.recv.json");
    let alice_v2_recv = work.join("alice-v2.recv.json");
    let bob_v2_recv = work.join("bob-v2.recv.json");

    let alice_group_state = work.join("alice-group.bin");
    let bob_group_state = work.join("bob-group.bin");
    let carol_group_state = work.join("carol-group.bin");

    let proposal1_file = work.join("alice-update.proposal.bin");
    let commit1_file = work.join("alice-update.commit.bin");
    let path1_file = work.join("alice-update.path.bin");
    let proposal2_file = work.join("bob-update.proposal.bin");
    let commit2_file = work.join("bob-update.commit.bin");
    let path2_file = work.join("bob-update.path.bin");

    let group_id = "group-three-member-chain";

    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "register".to_string(),
            "--username".to_string(),
            "alice".to_string(),
            "--password".to_string(),
            "secret".to_string(),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "register".to_string(),
            "--username".to_string(),
            "bob".to_string(),
            "--password".to_string(),
            "secret".to_string(),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &carol_state,
        &[
            "register".to_string(),
            "--username".to_string(),
            "carol".to_string(),
            "--password".to_string(),
            "secret".to_string(),
            "--force".to_string(),
        ],
    );

    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "keygen".to_string(),
            "--out".to_string(),
            to_s(&alice_kem),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "keypackage-export".to_string(),
            "--kem-file".to_string(),
            to_s(&alice_kem),
            "--keypackage-out".to_string(),
            to_s(&alice_kp),
            "--receiver-private-out".to_string(),
            to_s(&alice_recv),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "keygen".to_string(),
            "--out".to_string(),
            to_s(&alice_v2_kem),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "keypackage-export".to_string(),
            "--kem-file".to_string(),
            to_s(&alice_v2_kem),
            "--keypackage-out".to_string(),
            to_s(&alice_v2_kp),
            "--receiver-private-out".to_string(),
            to_s(&alice_v2_recv),
            "--force".to_string(),
        ],
    );

    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "keygen".to_string(),
            "--out".to_string(),
            to_s(&bob_kem),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "keypackage-export".to_string(),
            "--kem-file".to_string(),
            to_s(&bob_kem),
            "--keypackage-out".to_string(),
            to_s(&bob_kp),
            "--receiver-private-out".to_string(),
            to_s(&bob_recv),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "keygen".to_string(),
            "--out".to_string(),
            to_s(&bob_v2_kem),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "keypackage-export".to_string(),
            "--kem-file".to_string(),
            to_s(&bob_v2_kem),
            "--keypackage-out".to_string(),
            to_s(&bob_v2_kp),
            "--receiver-private-out".to_string(),
            to_s(&bob_v2_recv),
            "--force".to_string(),
        ],
    );

    run_ds_client(
        client_bin,
        &base_url,
        &carol_state,
        &[
            "keygen".to_string(),
            "--out".to_string(),
            to_s(&carol_kem),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &carol_state,
        &[
            "keypackage-export".to_string(),
            "--kem-file".to_string(),
            to_s(&carol_kem),
            "--keypackage-out".to_string(),
            to_s(&carol_kp),
            "--receiver-private-out".to_string(),
            to_s(&carol_recv),
            "--force".to_string(),
        ],
    );

    for (client_state, own_leaf) in [(&alice_state, "0"), (&bob_state, "1"), (&carol_state, "2")] {
        let out = if own_leaf == "0" {
            &alice_group_state
        } else if own_leaf == "1" {
            &bob_group_state
        } else {
            &carol_group_state
        };
        run_ds_client(
            client_bin,
            &base_url,
            client_state,
            &[
                "bootstrap-group-state".to_string(),
                "--group-id".to_string(),
                group_id.to_string(),
                "--member-keypackage".to_string(),
                to_s(&alice_kp),
                "--member-keypackage".to_string(),
                to_s(&bob_kp),
                "--member-keypackage".to_string(),
                to_s(&carol_kp),
                "--own-leaf".to_string(),
                own_leaf.to_string(),
                "--out".to_string(),
                to_s(out),
                "--force".to_string(),
            ],
        );
    }

    // Commit #1: Alice updates her own leaf to v2 and Bob/Carol sync it from DS.
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "create-update-proposal".to_string(),
            "--group-state".to_string(),
            to_s(&alice_group_state),
            "--keypackage-file".to_string(),
            to_s(&alice_v2_kp),
            "--out".to_string(),
            to_s(&proposal1_file),
            "--sender-leaf".to_string(),
            "0".to_string(),
            "--target-leaf".to_string(),
            "0".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "submit-proposal".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--proposal-file".to_string(),
            to_s(&proposal1_file),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "create-commit".to_string(),
            "--group-state".to_string(),
            to_s(&alice_group_state),
            "--commit-out".to_string(),
            to_s(&commit1_file),
            "--path-update-out".to_string(),
            to_s(&path1_file),
            "--sender-leaf".to_string(),
            "0".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "submit-commit".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--commit-file".to_string(),
            to_s(&commit1_file),
            "--path-update-file".to_string(),
            to_s(&path1_file),
        ],
    );

    let bob_sync_1 = run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "fetch-and-apply-latest".to_string(),
            "--group-state".to_string(),
            to_s(&bob_group_state),
            "--receiver-private-file".to_string(),
            to_s(&bob_recv),
            "--limit".to_string(),
            "100".to_string(),
        ],
    );
    assert!(
        bob_sync_1.contains("applied_total=1"),
        "bob sync 1 output:\n{bob_sync_1}"
    );
    let carol_sync_1 = run_ds_client(
        client_bin,
        &base_url,
        &carol_state,
        &[
            "fetch-and-apply-latest".to_string(),
            "--group-state".to_string(),
            to_s(&carol_group_state),
            "--receiver-private-file".to_string(),
            to_s(&carol_recv),
            "--limit".to_string(),
            "100".to_string(),
        ],
    );
    assert!(
        carol_sync_1.contains("applied_total=1"),
        "carol sync 1 output:\n{carol_sync_1}"
    );

    // Commit #2: Bob updates his own leaf to v2 and Alice/Carol sync it from DS.
    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "create-update-proposal".to_string(),
            "--group-state".to_string(),
            to_s(&bob_group_state),
            "--keypackage-file".to_string(),
            to_s(&bob_v2_kp),
            "--out".to_string(),
            to_s(&proposal2_file),
            "--sender-leaf".to_string(),
            "1".to_string(),
            "--target-leaf".to_string(),
            "1".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "submit-proposal".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--proposal-file".to_string(),
            to_s(&proposal2_file),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "create-commit".to_string(),
            "--group-state".to_string(),
            to_s(&bob_group_state),
            "--commit-out".to_string(),
            to_s(&commit2_file),
            "--path-update-out".to_string(),
            to_s(&path2_file),
            "--sender-leaf".to_string(),
            "1".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "submit-commit".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--commit-file".to_string(),
            to_s(&commit2_file),
            "--path-update-file".to_string(),
            to_s(&path2_file),
        ],
    );

    let alice_sync_2 = run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "fetch-and-apply-latest".to_string(),
            "--group-state".to_string(),
            to_s(&alice_group_state),
            "--receiver-private-file".to_string(),
            to_s(&alice_v2_recv),
            "--limit".to_string(),
            "100".to_string(),
        ],
    );
    assert!(
        alice_sync_2.contains("applied_total=1"),
        "alice sync 2 output:\n{alice_sync_2}"
    );
    let carol_sync_2 = run_ds_client(
        client_bin,
        &base_url,
        &carol_state,
        &[
            "fetch-and-apply-latest".to_string(),
            "--group-state".to_string(),
            to_s(&carol_group_state),
            "--receiver-private-file".to_string(),
            to_s(&carol_recv),
            "--limit".to_string(),
            "100".to_string(),
        ],
    );
    assert!(
        carol_sync_2.contains("applied_total=1"),
        "carol sync 2 output:\n{carol_sync_2}"
    );

    let alice_loaded =
        ClientGroupState::load_from_file(&alice_group_state).expect("load alice state");
    let bob_loaded = ClientGroupState::load_from_file(&bob_group_state).expect("load bob state");
    let carol_loaded =
        ClientGroupState::load_from_file(&carol_group_state).expect("load carol state");
    assert_eq!(alice_loaded.epoch, 2);
    assert_eq!(bob_loaded.epoch, 2);
    assert_eq!(carol_loaded.epoch, 2);
    assert_eq!(alice_loaded.ratchet_tree, bob_loaded.ratchet_tree);
    assert_eq!(bob_loaded.ratchet_tree, carol_loaded.ratchet_tree);

    // All leaves should still be populated in the converged 3-member tree.
    for leaf in 0..3usize {
        let node_idx = RatchetTree::leaf_to_node_index(leaf);
        assert!(
            matches!(
                alice_loaded.ratchet_tree.nodes.get(node_idx),
                Some(Node::Leaf(_))
            ),
            "leaf {leaf} missing in final tree"
        );
    }

    let _ = shutdown_tx.send(());
    let result = server.await.expect("join server");
    if let Err(err) = result {
        panic!("server returned error: {err}");
    }

    let _ = fs::remove_dir_all(base);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn three_member_add_update_remove_chain_converges_after_membership_change() {
    let (state, base) = temp_state("three-member-add-update-remove");
    let (addr, shutdown_tx, server) = start_test_server(state).await;
    let base_url = format!("http://{addr}");
    let client_bin = env!("CARGO_BIN_EXE_ds_client");

    let work = base.join("work");
    let _ = fs::create_dir_all(&work);

    let alice_state = work.join("alice.json");
    let bob_state = work.join("bob.json");
    let carol_state = work.join("carol.json");

    let alice_kem = work.join("alice-kem.json");
    let bob_kem = work.join("bob-kem.json");
    let carol_kem = work.join("carol-kem.json");
    let bob_v2_kem = work.join("bob-v2-kem.json");

    let alice_kp = work.join("alice.kp");
    let bob_kp = work.join("bob.kp");
    let carol_kp = work.join("carol.kp");
    let bob_v2_kp = work.join("bob-v2.kp");
    let carol_from_ds_kp = work.join("carol-from-ds.kp");

    let alice_recv = work.join("alice.recv.json");
    let bob_recv = work.join("bob.recv.json");
    let carol_recv = work.join("carol.recv.json");
    let bob_v2_recv = work.join("bob-v2.recv.json");

    let alice_group_state = work.join("alice-group.bin");
    let bob_group_state = work.join("bob-group.bin");
    let carol_group_state = work.join("carol-group.bin");

    let add_proposal_file = work.join("add-carol.proposal.bin");
    let commit1_file = work.join("add-carol.commit.bin");
    let path1_file = work.join("add-carol.path.bin");

    let update_proposal_file = work.join("bob-update.proposal.bin");
    let commit2_file = work.join("bob-update.commit.bin");
    let path2_file = work.join("bob-update.path.bin");

    let remove_proposal_file = work.join("remove-carol.proposal.bin");
    let commit3_file = work.join("remove-carol.commit.bin");
    let path3_file = work.join("remove-carol.path.bin");

    let group_id = "group-three-member-add-update-remove";

    for (state_file, username) in [
        (&alice_state, "alice"),
        (&bob_state, "bob"),
        (&carol_state, "carol"),
    ] {
        run_ds_client(
            client_bin,
            &base_url,
            state_file,
            &[
                "register".to_string(),
                "--username".to_string(),
                username.to_string(),
                "--password".to_string(),
                "secret".to_string(),
                "--force".to_string(),
            ],
        );
    }

    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "keygen".to_string(),
            "--out".to_string(),
            to_s(&alice_kem),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "keypackage-export".to_string(),
            "--kem-file".to_string(),
            to_s(&alice_kem),
            "--keypackage-out".to_string(),
            to_s(&alice_kp),
            "--receiver-private-out".to_string(),
            to_s(&alice_recv),
            "--force".to_string(),
        ],
    );

    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "keygen".to_string(),
            "--out".to_string(),
            to_s(&bob_kem),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "keypackage-export".to_string(),
            "--kem-file".to_string(),
            to_s(&bob_kem),
            "--keypackage-out".to_string(),
            to_s(&bob_kp),
            "--receiver-private-out".to_string(),
            to_s(&bob_recv),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "keygen".to_string(),
            "--out".to_string(),
            to_s(&bob_v2_kem),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "keypackage-export".to_string(),
            "--kem-file".to_string(),
            to_s(&bob_v2_kem),
            "--keypackage-out".to_string(),
            to_s(&bob_v2_kp),
            "--receiver-private-out".to_string(),
            to_s(&bob_v2_recv),
            "--force".to_string(),
        ],
    );

    run_ds_client(
        client_bin,
        &base_url,
        &carol_state,
        &[
            "keygen".to_string(),
            "--out".to_string(),
            to_s(&carol_kem),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &carol_state,
        &[
            "keypackage-export".to_string(),
            "--kem-file".to_string(),
            to_s(&carol_kem),
            "--keypackage-out".to_string(),
            to_s(&carol_kp),
            "--receiver-private-out".to_string(),
            to_s(&carol_recv),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &carol_state,
        &[
            "publish-key-package".to_string(),
            "--keypackage-file".to_string(),
            to_s(&carol_kp),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "fetch-key-package".to_string(),
            "--target".to_string(),
            "carol".to_string(),
            "--out".to_string(),
            to_s(&carol_from_ds_kp),
        ],
    );

    // Initial group starts with Alice + Bob (Carol will be added via commit #1).
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "bootstrap-group-state".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--member-keypackage".to_string(),
            to_s(&alice_kp),
            "--member-keypackage".to_string(),
            to_s(&bob_kp),
            "--own-leaf".to_string(),
            "0".to_string(),
            "--out".to_string(),
            to_s(&alice_group_state),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "bootstrap-group-state".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--member-keypackage".to_string(),
            to_s(&alice_kp),
            "--member-keypackage".to_string(),
            to_s(&bob_kp),
            "--own-leaf".to_string(),
            "1".to_string(),
            "--out".to_string(),
            to_s(&bob_group_state),
            "--force".to_string(),
        ],
    );

    // Commit #1: A adds C.
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "create-add-proposal".to_string(),
            "--group-state".to_string(),
            to_s(&alice_group_state),
            "--keypackage-file".to_string(),
            to_s(&carol_from_ds_kp),
            "--out".to_string(),
            to_s(&add_proposal_file),
            "--sender-leaf".to_string(),
            "0".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "submit-proposal".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--proposal-file".to_string(),
            to_s(&add_proposal_file),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "create-commit".to_string(),
            "--group-state".to_string(),
            to_s(&alice_group_state),
            "--commit-out".to_string(),
            to_s(&commit1_file),
            "--path-update-out".to_string(),
            to_s(&path1_file),
            "--sender-leaf".to_string(),
            "0".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "submit-commit".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--commit-file".to_string(),
            to_s(&commit1_file),
            "--path-update-file".to_string(),
            to_s(&path1_file),
        ],
    );

    let bob_sync_1 = run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "fetch-and-apply-latest".to_string(),
            "--group-state".to_string(),
            to_s(&bob_group_state),
            "--receiver-private-file".to_string(),
            to_s(&bob_recv),
            "--limit".to_string(),
            "100".to_string(),
        ],
    );
    assert!(
        bob_sync_1.contains("applied_total=1"),
        "bob sync 1 output:\n{bob_sync_1}"
    );
    let alice_epoch1 = ClientGroupState::load_from_file(&alice_group_state).expect("alice epoch1");
    let bob_epoch1 = ClientGroupState::load_from_file(&bob_group_state).expect("bob epoch1");
    assert_eq!(alice_epoch1.epoch, 1);
    assert_eq!(bob_epoch1.epoch, 1);
    assert!(alice_epoch1.key_schedule.is_epoch_aligned(1));
    assert!(bob_epoch1.key_schedule.is_epoch_aligned(1));
    let alice_chain1 = alice_epoch1
        .key_schedule
        .chain_secrets_for_epoch(1)
        .expect("alice chain epoch1");
    let bob_chain1 = bob_epoch1
        .key_schedule
        .chain_secrets_for_epoch(1)
        .expect("bob chain epoch1");
    assert_eq!(alice_chain1.commit_secret, bob_chain1.commit_secret);
    assert_eq!(alice_chain1.joiner_secret, bob_chain1.joiner_secret);
    assert_eq!(alice_chain1.epoch_secret, bob_chain1.epoch_secret);
    assert_eq!(alice_chain1.root_secret, bob_chain1.root_secret);

    // C joins from commit #1 material.
    run_ds_client(
        client_bin,
        &base_url,
        &carol_state,
        &[
            "join-from-commit".to_string(),
            "--base-member-keypackage".to_string(),
            to_s(&alice_kp),
            "--base-member-keypackage".to_string(),
            to_s(&bob_kp),
            "--commit-file".to_string(),
            to_s(&commit1_file),
            "--path-update-file".to_string(),
            to_s(&path1_file),
            "--receiver-private-file".to_string(),
            to_s(&carol_recv),
            "--out".to_string(),
            to_s(&carol_group_state),
            "--own-leaf".to_string(),
            "2".to_string(),
            "--force".to_string(),
        ],
    );
    let carol_epoch1 =
        ClientGroupState::load_from_file(&carol_group_state).expect("carol epoch1 after join");
    assert_eq!(carol_epoch1.epoch, 1);
    assert!(carol_epoch1.key_schedule.is_epoch_aligned(1));
    let carol_chain1 = carol_epoch1
        .key_schedule
        .chain_secrets_for_epoch(1)
        .expect("carol chain epoch1");
    assert_eq!(alice_chain1.commit_secret, carol_chain1.commit_secret);
    assert_eq!(alice_chain1.root_secret, carol_chain1.root_secret);

    // Commit #2: B updates self, then A and C sync.
    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "create-update-proposal".to_string(),
            "--group-state".to_string(),
            to_s(&bob_group_state),
            "--keypackage-file".to_string(),
            to_s(&bob_v2_kp),
            "--out".to_string(),
            to_s(&update_proposal_file),
            "--sender-leaf".to_string(),
            "1".to_string(),
            "--target-leaf".to_string(),
            "1".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "submit-proposal".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--proposal-file".to_string(),
            to_s(&update_proposal_file),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "create-commit".to_string(),
            "--group-state".to_string(),
            to_s(&bob_group_state),
            "--commit-out".to_string(),
            to_s(&commit2_file),
            "--path-update-out".to_string(),
            to_s(&path2_file),
            "--sender-leaf".to_string(),
            "1".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "submit-commit".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--commit-file".to_string(),
            to_s(&commit2_file),
            "--path-update-file".to_string(),
            to_s(&path2_file),
        ],
    );

    let alice_sync_2 = run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "fetch-and-apply-latest".to_string(),
            "--group-state".to_string(),
            to_s(&alice_group_state),
            "--limit".to_string(),
            "100".to_string(),
        ],
    );
    assert!(
        alice_sync_2.contains("applied_total=1"),
        "alice sync 2 output:\n{alice_sync_2}"
    );
    let carol_sync_2 = run_ds_client(
        client_bin,
        &base_url,
        &carol_state,
        &[
            "fetch-and-apply-latest".to_string(),
            "--group-state".to_string(),
            to_s(&carol_group_state),
            "--receiver-private-file".to_string(),
            to_s(&carol_recv),
            "--limit".to_string(),
            "100".to_string(),
        ],
    );
    assert!(
        carol_sync_2.contains("applied_total=1"),
        "carol sync 2 output:\n{carol_sync_2}"
    );
    let alice_epoch2 = ClientGroupState::load_from_file(&alice_group_state).expect("alice epoch2");
    let bob_epoch2 = ClientGroupState::load_from_file(&bob_group_state).expect("bob epoch2");
    let carol_epoch2 = ClientGroupState::load_from_file(&carol_group_state).expect("carol epoch2");
    assert_eq!(alice_epoch2.epoch, 2);
    assert_eq!(bob_epoch2.epoch, 2);
    assert_eq!(carol_epoch2.epoch, 2);
    for s in [&alice_epoch2, &bob_epoch2, &carol_epoch2] {
        assert!(s.key_schedule.is_epoch_aligned(2));
    }
    let alice_chain2 = alice_epoch2
        .key_schedule
        .chain_secrets_for_epoch(2)
        .expect("alice chain epoch2");
    let bob_chain2 = bob_epoch2
        .key_schedule
        .chain_secrets_for_epoch(2)
        .expect("bob chain epoch2");
    let carol_chain2 = carol_epoch2
        .key_schedule
        .chain_secrets_for_epoch(2)
        .expect("carol chain epoch2");
    assert_eq!(alice_chain2.commit_secret, bob_chain2.commit_secret);
    assert_eq!(bob_chain2.commit_secret, carol_chain2.commit_secret);
    assert_eq!(alice_chain2.root_secret, bob_chain2.root_secret);
    assert_eq!(bob_chain2.root_secret, carol_chain2.root_secret);
    assert_ne!(alice_chain1.commit_secret, alice_chain2.commit_secret);
    assert_ne!(alice_chain1.root_secret, alice_chain2.root_secret);

    // Commit #3: A removes C (leaf 2), then B syncs and final A/B converge.
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "create-remove-proposal".to_string(),
            "--group-state".to_string(),
            to_s(&alice_group_state),
            "--remove-leaf".to_string(),
            "2".to_string(),
            "--out".to_string(),
            to_s(&remove_proposal_file),
            "--sender-leaf".to_string(),
            "0".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "submit-proposal".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--proposal-file".to_string(),
            to_s(&remove_proposal_file),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "create-commit".to_string(),
            "--group-state".to_string(),
            to_s(&alice_group_state),
            "--commit-out".to_string(),
            to_s(&commit3_file),
            "--path-update-out".to_string(),
            to_s(&path3_file),
            "--sender-leaf".to_string(),
            "0".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "submit-commit".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--commit-file".to_string(),
            to_s(&commit3_file),
            "--path-update-file".to_string(),
            to_s(&path3_file),
        ],
    );

    let bob_sync_3 = run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "fetch-and-apply-latest".to_string(),
            "--group-state".to_string(),
            to_s(&bob_group_state),
            "--receiver-private-file".to_string(),
            to_s(&bob_v2_recv),
            "--limit".to_string(),
            "100".to_string(),
        ],
    );
    assert!(
        bob_sync_3.contains("applied_total=1"),
        "bob sync 3 output:\n{bob_sync_3}"
    );

    let alice_loaded = ClientGroupState::load_from_file(&alice_group_state).expect("load alice");
    let bob_loaded = ClientGroupState::load_from_file(&bob_group_state).expect("load bob");
    let carol_loaded = ClientGroupState::load_from_file(&carol_group_state).expect("load carol");

    assert_eq!(alice_loaded.epoch, 3);
    assert_eq!(bob_loaded.epoch, 3);
    assert_eq!(carol_loaded.epoch, 2);
    assert_eq!(alice_loaded.ratchet_tree, bob_loaded.ratchet_tree);
    assert!(alice_loaded.key_schedule.is_epoch_aligned(3));
    assert!(bob_loaded.key_schedule.is_epoch_aligned(3));
    let alice_chain3 = alice_loaded
        .key_schedule
        .chain_secrets_for_epoch(3)
        .expect("alice chain epoch3");
    let bob_chain3 = bob_loaded
        .key_schedule
        .chain_secrets_for_epoch(3)
        .expect("bob chain epoch3");
    assert_eq!(alice_chain3.commit_secret, bob_chain3.commit_secret);
    assert_eq!(alice_chain3.joiner_secret, bob_chain3.joiner_secret);
    assert_eq!(alice_chain3.epoch_secret, bob_chain3.epoch_secret);
    assert_eq!(alice_chain3.root_secret, bob_chain3.root_secret);
    assert_ne!(alice_chain2.commit_secret, alice_chain3.commit_secret);
    assert_ne!(alice_chain2.root_secret, alice_chain3.root_secret);
    assert!(carol_loaded.key_schedule.chain_secrets_for_epoch(3).is_none());

    let leaf_0 = RatchetTree::leaf_to_node_index(0);
    let leaf_1 = RatchetTree::leaf_to_node_index(1);
    let leaf_2 = RatchetTree::leaf_to_node_index(2);
    assert!(matches!(
        alice_loaded.ratchet_tree.nodes.get(leaf_0),
        Some(Node::Leaf(_))
    ));
    assert!(matches!(
        alice_loaded.ratchet_tree.nodes.get(leaf_1),
        Some(Node::Leaf(_))
    ));
    assert!(matches!(
        alice_loaded.ratchet_tree.nodes.get(leaf_2),
        Some(Node::Blank)
    ));

    let _ = shutdown_tx.send(());
    let result = server.await.expect("join server");
    if let Err(err) = result {
        panic!("server returned error: {err}");
    }

    let _ = fs::remove_dir_all(base);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn malformed_commit_payload_is_skipped_without_state_advance() {
    let (mut state, base) = temp_state("malformed-commit-skip");
    state.min_proposals_per_commit = 0;
    let (addr, shutdown_tx, server) = start_test_server(state).await;
    let base_url = format!("http://{addr}");
    let client_bin = env!("CARGO_BIN_EXE_ds_client");

    let work = base.join("work");
    let _ = fs::create_dir_all(&work);

    let alice_state = work.join("alice.json");
    let alice_kem = work.join("alice-kem.json");
    let alice_kp = work.join("alice.kp");
    let alice_recv = work.join("alice.recv.json");
    let alice_group_state = work.join("alice-group.bin");
    let malformed_commit = work.join("malformed.commit.bin");
    let group_id = "group-malformed-commit";

    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "register".to_string(),
            "--username".to_string(),
            "alice".to_string(),
            "--password".to_string(),
            "secret".to_string(),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "keygen".to_string(),
            "--out".to_string(),
            to_s(&alice_kem),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "keypackage-export".to_string(),
            "--kem-file".to_string(),
            to_s(&alice_kem),
            "--keypackage-out".to_string(),
            to_s(&alice_kp),
            "--receiver-private-out".to_string(),
            to_s(&alice_recv),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "bootstrap-group-state".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--member-keypackage".to_string(),
            to_s(&alice_kp),
            "--own-leaf".to_string(),
            "0".to_string(),
            "--out".to_string(),
            to_s(&alice_group_state),
            "--force".to_string(),
        ],
    );

    fs::write(&malformed_commit, [0xDE, 0xAD, 0xBE, 0xEF]).expect("write malformed commit");
    run_ds_client_expect_fail(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "submit-commit".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--commit-file".to_string(),
            to_s(&malformed_commit),
        ],
        "invalid_commit_payload",
    );

    let sync_output = run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "fetch-and-apply-latest".to_string(),
            "--group-state".to_string(),
            to_s(&alice_group_state),
            "--limit".to_string(),
            "100".to_string(),
        ],
    );
    assert!(
        sync_output.contains("applied_total=0"),
        "sync output:\n{sync_output}"
    );
    assert!(
        sync_output.contains("skipped_total=0"),
        "sync output:\n{sync_output}"
    );

    let loaded = ClientGroupState::load_from_file(&alice_group_state).expect("load state");
    assert_eq!(loaded.epoch, 0);
    assert_eq!(loaded.last_applied_commit_id, None);

    let _ = shutdown_tx.send(());
    let result = server.await.expect("join server");
    if let Err(err) = result {
        panic!("server returned error: {err}");
    }

    let _ = fs::remove_dir_all(base);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn malformed_path_payload_triggers_strict_receiver_rejection() {
    let (state, base) = temp_state("malformed-path-strict");
    let (addr, shutdown_tx, server) = start_test_server(state).await;
    let base_url = format!("http://{addr}");
    let client_bin = env!("CARGO_BIN_EXE_ds_client");

    let work = base.join("work");
    let _ = fs::create_dir_all(&work);

    let alice_state = work.join("alice.json");
    let bob_state = work.join("bob.json");
    let alice_kem = work.join("alice-kem.json");
    let bob_kem = work.join("bob-kem.json");
    let bob_v2_kem = work.join("bob-v2-kem.json");
    let alice_kp = work.join("alice.kp");
    let bob_kp = work.join("bob.kp");
    let bob_v2_kp = work.join("bob-v2.kp");
    let alice_recv = work.join("alice.recv.json");
    let bob_recv = work.join("bob.recv.json");
    let bob_v2_recv = work.join("bob-v2.recv.json");
    let bob_group_state = work.join("bob-group.bin");
    let alice_group_state = work.join("alice-group.bin");
    let proposal_file = work.join("bob-update.proposal.bin");
    let commit_file = work.join("bob-update.commit.bin");
    let path_file = work.join("bob-update.path.bin");
    let group_id = "group-malformed-path";

    for (state_file, username) in [(&alice_state, "alice"), (&bob_state, "bob")] {
        run_ds_client(
            client_bin,
            &base_url,
            state_file,
            &[
                "register".to_string(),
                "--username".to_string(),
                username.to_string(),
                "--password".to_string(),
                "secret".to_string(),
                "--force".to_string(),
            ],
        );
    }

    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "keygen".to_string(),
            "--out".to_string(),
            to_s(&alice_kem),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "keypackage-export".to_string(),
            "--kem-file".to_string(),
            to_s(&alice_kem),
            "--keypackage-out".to_string(),
            to_s(&alice_kp),
            "--receiver-private-out".to_string(),
            to_s(&alice_recv),
            "--force".to_string(),
        ],
    );

    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "keygen".to_string(),
            "--out".to_string(),
            to_s(&bob_kem),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "keypackage-export".to_string(),
            "--kem-file".to_string(),
            to_s(&bob_kem),
            "--keypackage-out".to_string(),
            to_s(&bob_kp),
            "--receiver-private-out".to_string(),
            to_s(&bob_recv),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "keygen".to_string(),
            "--out".to_string(),
            to_s(&bob_v2_kem),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "keypackage-export".to_string(),
            "--kem-file".to_string(),
            to_s(&bob_v2_kem),
            "--keypackage-out".to_string(),
            to_s(&bob_v2_kp),
            "--receiver-private-out".to_string(),
            to_s(&bob_v2_recv),
            "--force".to_string(),
        ],
    );

    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "bootstrap-group-state".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--member-keypackage".to_string(),
            to_s(&alice_kp),
            "--member-keypackage".to_string(),
            to_s(&bob_kp),
            "--own-leaf".to_string(),
            "1".to_string(),
            "--out".to_string(),
            to_s(&bob_group_state),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "bootstrap-group-state".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--member-keypackage".to_string(),
            to_s(&alice_kp),
            "--member-keypackage".to_string(),
            to_s(&bob_kp),
            "--own-leaf".to_string(),
            "0".to_string(),
            "--out".to_string(),
            to_s(&alice_group_state),
            "--force".to_string(),
        ],
    );

    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "create-update-proposal".to_string(),
            "--group-state".to_string(),
            to_s(&bob_group_state),
            "--keypackage-file".to_string(),
            to_s(&bob_v2_kp),
            "--out".to_string(),
            to_s(&proposal_file),
            "--sender-leaf".to_string(),
            "1".to_string(),
            "--target-leaf".to_string(),
            "1".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "submit-proposal".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--proposal-file".to_string(),
            to_s(&proposal_file),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "create-commit".to_string(),
            "--group-state".to_string(),
            to_s(&bob_group_state),
            "--commit-out".to_string(),
            to_s(&commit_file),
            "--path-update-out".to_string(),
            to_s(&path_file),
            "--sender-leaf".to_string(),
            "1".to_string(),
        ],
    );

    let valid_path_bytes = fs::read(&path_file).expect("read valid path update envelope");
    let valid_path_env =
        PathUpdateEnvelope::decode(&valid_path_bytes).expect("decode valid path update envelope");
    let malformed_path_envelope = encode_malformed_path_update_envelope_with_metadata(
        &valid_path_env.group_id,
        valid_path_env.epoch,
        valid_path_env.sender_leaf,
        // Keep malformed bytes bounded to avoid huge decoded length allocations.
        &[0x00, 0x00, 0x00, 0x01],
    );
    fs::write(&path_file, malformed_path_envelope).expect("write malformed path envelope");
    run_ds_client_expect_fail(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "submit-commit".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--commit-file".to_string(),
            to_s(&commit_file),
            "--path-update-file".to_string(),
            to_s(&path_file),
        ],
        "invalid_path_update_payload",
    );

    let sync_output = run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "fetch-and-apply-latest".to_string(),
            "--group-state".to_string(),
            to_s(&alice_group_state),
            "--receiver-private-file".to_string(),
            to_s(&alice_recv),
            "--limit".to_string(),
            "100".to_string(),
        ],
    );
    assert!(
        sync_output.contains("applied_total=0"),
        "sync output:\n{sync_output}"
    );
    assert!(
        sync_output.contains("skipped_total=0"),
        "sync output:\n{sync_output}"
    );

    let loaded = ClientGroupState::load_from_file(&alice_group_state).expect("load state");
    assert_eq!(loaded.epoch, 0);
    assert_eq!(loaded.last_applied_commit_id, None);

    let _ = shutdown_tx.send(());
    let result = server.await.expect("join server");
    if let Err(err) = result {
        panic!("server returned error: {err}");
    }

    let _ = fs::remove_dir_all(base);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tampered_path_update_payload_with_valid_metadata_triggers_strict_receiver_rejection() {
    let (state, base) = temp_state("tampered-path-valid-metadata");
    let (addr, shutdown_tx, server) = start_test_server(state).await;
    let base_url = format!("http://{addr}");
    let client_bin = env!("CARGO_BIN_EXE_ds_client");

    let work = base.join("work");
    let _ = fs::create_dir_all(&work);

    let alice_state = work.join("alice.json");
    let bob_state = work.join("bob.json");
    let alice_kem = work.join("alice-kem.json");
    let bob_kem = work.join("bob-kem.json");
    let bob_v2_kem = work.join("bob-v2-kem.json");
    let alice_kp = work.join("alice.kp");
    let bob_kp = work.join("bob.kp");
    let bob_v2_kp = work.join("bob-v2.kp");
    let alice_recv = work.join("alice.recv.json");
    let bob_recv = work.join("bob.recv.json");
    let bob_v2_recv = work.join("bob-v2.recv.json");
    let bob_group_state = work.join("bob-group.bin");
    let alice_group_state = work.join("alice-group.bin");
    let proposal_file = work.join("bob-update.proposal.bin");
    let commit_file = work.join("bob-update.commit.bin");
    let path_file = work.join("bob-update.path.bin");
    let group_id = "group-tampered-path-valid-metadata";

    for (state_file, username) in [(&alice_state, "alice"), (&bob_state, "bob")] {
        run_ds_client(
            client_bin,
            &base_url,
            state_file,
            &[
                "register".to_string(),
                "--username".to_string(),
                username.to_string(),
                "--password".to_string(),
                "secret".to_string(),
                "--force".to_string(),
            ],
        );
    }

    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "keygen".to_string(),
            "--out".to_string(),
            to_s(&alice_kem),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "keypackage-export".to_string(),
            "--kem-file".to_string(),
            to_s(&alice_kem),
            "--keypackage-out".to_string(),
            to_s(&alice_kp),
            "--receiver-private-out".to_string(),
            to_s(&alice_recv),
            "--force".to_string(),
        ],
    );

    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "keygen".to_string(),
            "--out".to_string(),
            to_s(&bob_kem),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "keypackage-export".to_string(),
            "--kem-file".to_string(),
            to_s(&bob_kem),
            "--keypackage-out".to_string(),
            to_s(&bob_kp),
            "--receiver-private-out".to_string(),
            to_s(&bob_recv),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "keygen".to_string(),
            "--out".to_string(),
            to_s(&bob_v2_kem),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "keypackage-export".to_string(),
            "--kem-file".to_string(),
            to_s(&bob_v2_kem),
            "--keypackage-out".to_string(),
            to_s(&bob_v2_kp),
            "--receiver-private-out".to_string(),
            to_s(&bob_v2_recv),
            "--force".to_string(),
        ],
    );

    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "bootstrap-group-state".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--member-keypackage".to_string(),
            to_s(&alice_kp),
            "--member-keypackage".to_string(),
            to_s(&bob_kp),
            "--own-leaf".to_string(),
            "1".to_string(),
            "--out".to_string(),
            to_s(&bob_group_state),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "bootstrap-group-state".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--member-keypackage".to_string(),
            to_s(&alice_kp),
            "--member-keypackage".to_string(),
            to_s(&bob_kp),
            "--own-leaf".to_string(),
            "0".to_string(),
            "--out".to_string(),
            to_s(&alice_group_state),
            "--force".to_string(),
        ],
    );

    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "create-update-proposal".to_string(),
            "--group-state".to_string(),
            to_s(&bob_group_state),
            "--keypackage-file".to_string(),
            to_s(&bob_v2_kp),
            "--out".to_string(),
            to_s(&proposal_file),
            "--sender-leaf".to_string(),
            "1".to_string(),
            "--target-leaf".to_string(),
            "1".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "submit-proposal".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--proposal-file".to_string(),
            to_s(&proposal_file),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "create-commit".to_string(),
            "--group-state".to_string(),
            to_s(&bob_group_state),
            "--commit-out".to_string(),
            to_s(&commit_file),
            "--path-update-out".to_string(),
            to_s(&path_file),
            "--sender-leaf".to_string(),
            "1".to_string(),
        ],
    );

    let valid_path_bytes = fs::read(&path_file).expect("read valid path update envelope");
    let mut path_env =
        PathUpdateEnvelope::decode(&valid_path_bytes).expect("decode valid path update envelope");
    assert!(
        !path_env.path_update.ciphertexts.is_empty()
            && !path_env.path_update.ciphertexts[0].is_empty(),
        "expected non-empty path ciphertext structure"
    );
    path_env.path_update.ciphertexts[0][0].payload[0] ^= 0x80;
    fs::write(&path_file, path_env.encode()).expect("write tampered path update envelope");

    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "submit-commit".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--commit-file".to_string(),
            to_s(&commit_file),
            "--path-update-file".to_string(),
            to_s(&path_file),
        ],
    );

    run_ds_client_expect_fail(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "fetch-and-apply-latest".to_string(),
            "--group-state".to_string(),
            to_s(&alice_group_state),
            "--receiver-private-file".to_string(),
            to_s(&alice_recv),
            "--limit".to_string(),
            "100".to_string(),
        ],
        "failed to apply commit+path update during sync",
    );

    let loaded = ClientGroupState::load_from_file(&alice_group_state).expect("load state");
    assert_eq!(loaded.epoch, 0);
    assert_eq!(loaded.last_applied_commit_id, None);

    let _ = shutdown_tx.send(());
    let result = server.await.expect("join server");
    if let Err(err) = result {
        panic!("server returned error: {err}");
    }

    let _ = fs::remove_dir_all(base);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn strict_lineage_add_commit_with_tampered_parent_path_key_is_rejected_on_sync() {
    let (state, base) = temp_state("strict-lineage-add-tampered-parent-key");
    let (addr, shutdown_tx, server) = start_test_server(state).await;
    let base_url = format!("http://{addr}");
    let client_bin = env!("CARGO_BIN_EXE_ds_client");

    let work = base.join("work");
    let _ = fs::create_dir_all(&work);

    let alice_state = work.join("alice.json");
    let bob_state = work.join("bob.json");
    let carol_state = work.join("carol.json");
    let alice_kem = work.join("alice-kem.json");
    let bob_kem = work.join("bob-kem.json");
    let carol_kem = work.join("carol-kem.json");
    let alice_kp = work.join("alice.kp");
    let bob_kp = work.join("bob.kp");
    let carol_kp = work.join("carol.kp");
    let alice_recv = work.join("alice.recv.json");
    let bob_recv = work.join("bob.recv.json");
    let carol_recv = work.join("carol.recv.json");
    let alice_group_state = work.join("alice-group.bin");
    let bob_group_state = work.join("bob-group.bin");
    let add_proposal_file = work.join("add-carol.proposal.bin");
    let commit_file = work.join("add-carol.commit.bin");
    let path_file = work.join("add-carol.path.bin");
    let group_id = "group-strict-lineage-add-parent-key";

    register_and_export_keypackage(
        client_bin,
        &base_url,
        &alice_state,
        "alice",
        &alice_kem,
        &alice_kp,
        &alice_recv,
    );
    register_and_export_keypackage(
        client_bin, &base_url, &bob_state, "bob", &bob_kem, &bob_kp, &bob_recv,
    );
    register_and_export_keypackage(
        client_bin,
        &base_url,
        &carol_state,
        "carol",
        &carol_kem,
        &carol_kp,
        &carol_recv,
    );

    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "bootstrap-group-state".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--member-keypackage".to_string(),
            to_s(&alice_kp),
            "--member-keypackage".to_string(),
            to_s(&bob_kp),
            "--own-leaf".to_string(),
            "0".to_string(),
            "--out".to_string(),
            to_s(&alice_group_state),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "bootstrap-group-state".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--member-keypackage".to_string(),
            to_s(&alice_kp),
            "--member-keypackage".to_string(),
            to_s(&bob_kp),
            "--own-leaf".to_string(),
            "1".to_string(),
            "--out".to_string(),
            to_s(&bob_group_state),
            "--force".to_string(),
        ],
    );

    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "create-add-proposal".to_string(),
            "--group-state".to_string(),
            to_s(&alice_group_state),
            "--keypackage-file".to_string(),
            to_s(&carol_kp),
            "--out".to_string(),
            to_s(&add_proposal_file),
            "--sender-leaf".to_string(),
            "0".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "submit-proposal".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--proposal-file".to_string(),
            to_s(&add_proposal_file),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "create-commit".to_string(),
            "--group-state".to_string(),
            to_s(&alice_group_state),
            "--commit-out".to_string(),
            to_s(&commit_file),
            "--path-update-out".to_string(),
            to_s(&path_file),
            "--sender-leaf".to_string(),
            "0".to_string(),
        ],
    );

    let mut commit_env = CommitEnvelope::decode(&fs::read(&commit_file).expect("read commit file"))
        .expect("decode commit envelope");
    assert!(
        !commit_env.commit.path.is_empty(),
        "expected non-empty parent path for add commit"
    );
    let mut classic_bytes = commit_env.commit.path[0].public_key.classic.to_bytes();
    classic_bytes[0] ^= 0x80;
    commit_env.commit.path[0].public_key.classic = x25519_dalek::PublicKey::from(classic_bytes);
    fs::write(&commit_file, commit_env.encode()).expect("rewrite tampered commit envelope");

    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "submit-commit".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--commit-file".to_string(),
            to_s(&commit_file),
            "--path-update-file".to_string(),
            to_s(&path_file),
        ],
    );

    run_ds_client_expect_fail(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "fetch-and-apply-latest".to_string(),
            "--group-state".to_string(),
            to_s(&bob_group_state),
            "--receiver-private-file".to_string(),
            to_s(&bob_recv),
            "--limit".to_string(),
            "100".to_string(),
        ],
        "failed to apply commit+path update during sync",
    );

    let loaded = ClientGroupState::load_from_file(&bob_group_state).expect("load state");
    assert_eq!(loaded.epoch, 0);
    assert_eq!(loaded.last_applied_commit_id, None);

    let _ = shutdown_tx.send(());
    let result = server.await.expect("join server");
    if let Err(err) = result {
        panic!("server returned error: {err}");
    }

    let _ = fs::remove_dir_all(base);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn legacy_path_compat_allows_sync_of_pre_lineage_add_commit_artifact() {
    let (state, base) = temp_state("legacy-path-compat-add-parent-key");
    let (addr, shutdown_tx, server) = start_test_server(state).await;
    let base_url = format!("http://{addr}");
    let client_bin = env!("CARGO_BIN_EXE_ds_client");

    let work = base.join("work");
    let _ = fs::create_dir_all(&work);

    let alice_state = work.join("alice.json");
    let bob_state = work.join("bob.json");
    let carol_state = work.join("carol.json");
    let alice_kem = work.join("alice-kem.json");
    let bob_kem = work.join("bob-kem.json");
    let carol_kem = work.join("carol-kem.json");
    let alice_kp = work.join("alice.kp");
    let bob_kp = work.join("bob.kp");
    let carol_kp = work.join("carol.kp");
    let alice_recv = work.join("alice.recv.json");
    let bob_recv = work.join("bob.recv.json");
    let carol_recv = work.join("carol.recv.json");
    let alice_group_state = work.join("alice-group.bin");
    let bob_group_state = work.join("bob-group.bin");
    let add_proposal_file = work.join("add-carol.proposal.bin");
    let commit_file = work.join("add-carol.commit.bin");
    let path_file = work.join("add-carol.path.bin");
    let group_id = "group-legacy-path-compat-add-parent-key";

    register_and_export_keypackage(
        client_bin,
        &base_url,
        &alice_state,
        "alice",
        &alice_kem,
        &alice_kp,
        &alice_recv,
    );
    register_and_export_keypackage(
        client_bin, &base_url, &bob_state, "bob", &bob_kem, &bob_kp, &bob_recv,
    );
    register_and_export_keypackage(
        client_bin,
        &base_url,
        &carol_state,
        "carol",
        &carol_kem,
        &carol_kp,
        &carol_recv,
    );

    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "bootstrap-group-state".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--member-keypackage".to_string(),
            to_s(&alice_kp),
            "--member-keypackage".to_string(),
            to_s(&bob_kp),
            "--own-leaf".to_string(),
            "0".to_string(),
            "--out".to_string(),
            to_s(&alice_group_state),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "bootstrap-group-state".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--member-keypackage".to_string(),
            to_s(&alice_kp),
            "--member-keypackage".to_string(),
            to_s(&bob_kp),
            "--own-leaf".to_string(),
            "1".to_string(),
            "--out".to_string(),
            to_s(&bob_group_state),
            "--force".to_string(),
        ],
    );

    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "create-add-proposal".to_string(),
            "--group-state".to_string(),
            to_s(&alice_group_state),
            "--keypackage-file".to_string(),
            to_s(&carol_kp),
            "--out".to_string(),
            to_s(&add_proposal_file),
            "--sender-leaf".to_string(),
            "0".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "submit-proposal".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--proposal-file".to_string(),
            to_s(&add_proposal_file),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "create-commit".to_string(),
            "--group-state".to_string(),
            to_s(&alice_group_state),
            "--commit-out".to_string(),
            to_s(&commit_file),
            "--path-update-out".to_string(),
            to_s(&path_file),
            "--sender-leaf".to_string(),
            "0".to_string(),
        ],
    );

    let mut commit_env = CommitEnvelope::decode(&fs::read(&commit_file).expect("read commit file"))
        .expect("decode commit envelope");
    assert!(
        !commit_env.commit.path.is_empty(),
        "expected non-empty parent path for add commit"
    );
    let mut classic_bytes = commit_env.commit.path[0].public_key.classic.to_bytes();
    classic_bytes[0] ^= 0x40;
    commit_env.commit.path[0].public_key.classic = x25519_dalek::PublicKey::from(classic_bytes);
    fs::write(&commit_file, commit_env.encode()).expect("rewrite tampered commit envelope");

    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "submit-commit".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--commit-file".to_string(),
            to_s(&commit_file),
            "--path-update-file".to_string(),
            to_s(&path_file),
        ],
    );

    run_ds_client_expect_fail(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "fetch-and-apply-latest".to_string(),
            "--group-state".to_string(),
            to_s(&bob_group_state),
            "--receiver-private-file".to_string(),
            to_s(&bob_recv),
            "--limit".to_string(),
            "100".to_string(),
        ],
        "failed to apply commit+path update during sync",
    );

    let compat_sync = run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "fetch-and-apply-latest".to_string(),
            "--group-state".to_string(),
            to_s(&bob_group_state),
            "--receiver-private-file".to_string(),
            to_s(&bob_recv),
            "--limit".to_string(),
            "100".to_string(),
            "--allow-legacy-path-compat".to_string(),
        ],
    );
    assert!(
        compat_sync.contains("applied_total=1"),
        "compat sync output:\n{compat_sync}"
    );

    let loaded = ClientGroupState::load_from_file(&bob_group_state).expect("load state");
    assert_eq!(loaded.epoch, 1);
    assert!(loaded.key_schedule.is_epoch_aligned(1));
    assert!(loaded.last_applied_commit_id.is_some());

    let _ = shutdown_tx.send(());
    let result = server.await.expect("join server");
    if let Err(err) = result {
        panic!("server returned error: {err}");
    }

    let _ = fs::remove_dir_all(base);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn strict_lineage_remove_commit_with_inconsistent_path_update_is_rejected_on_sync() {
    let (state, base) = temp_state("strict-lineage-remove-inconsistent-path");
    let (addr, shutdown_tx, server) = start_test_server(state).await;
    let base_url = format!("http://{addr}");
    let client_bin = env!("CARGO_BIN_EXE_ds_client");

    let work = base.join("work");
    let _ = fs::create_dir_all(&work);

    let alice_state = work.join("alice.json");
    let bob_state = work.join("bob.json");
    let carol_state = work.join("carol.json");
    let alice_kem = work.join("alice-kem.json");
    let bob_kem = work.join("bob-kem.json");
    let carol_kem = work.join("carol-kem.json");
    let alice_v2_kem = work.join("alice-v2-kem.json");
    let alice_kp = work.join("alice.kp");
    let bob_kp = work.join("bob.kp");
    let carol_kp = work.join("carol.kp");
    let alice_v2_kp = work.join("alice-v2.kp");
    let alice_recv = work.join("alice.recv.json");
    let bob_recv = work.join("bob.recv.json");
    let carol_recv = work.join("carol.recv.json");
    let alice_v2_recv = work.join("alice-v2.recv.json");
    let alice_group_base = work.join("alice-group-base.bin");
    let alice_group_remove = work.join("alice-group-remove.bin");
    let alice_group_update = work.join("alice-group-update.bin");
    let bob_group_state = work.join("bob-group.bin");
    let remove_proposal_file = work.join("remove-carol.proposal.bin");
    let remove_commit_file = work.join("remove-carol.commit.bin");
    let remove_path_file = work.join("remove-carol.path.bin");
    let update_proposal_file = work.join("update-alice.proposal.bin");
    let update_commit_file = work.join("update-alice.commit.bin");
    let update_path_file = work.join("update-alice.path.bin");
    let group_id = "group-strict-lineage-remove-inconsistent-path";

    register_and_export_keypackage(
        client_bin,
        &base_url,
        &alice_state,
        "alice",
        &alice_kem,
        &alice_kp,
        &alice_recv,
    );
    register_and_export_keypackage(
        client_bin, &base_url, &bob_state, "bob", &bob_kem, &bob_kp, &bob_recv,
    );
    register_and_export_keypackage(
        client_bin,
        &base_url,
        &carol_state,
        "carol",
        &carol_kem,
        &carol_kp,
        &carol_recv,
    );

    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "keygen".to_string(),
            "--out".to_string(),
            to_s(&alice_v2_kem),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "keypackage-export".to_string(),
            "--kem-file".to_string(),
            to_s(&alice_v2_kem),
            "--keypackage-out".to_string(),
            to_s(&alice_v2_kp),
            "--receiver-private-out".to_string(),
            to_s(&alice_v2_recv),
            "--force".to_string(),
        ],
    );

    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "bootstrap-group-state".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--member-keypackage".to_string(),
            to_s(&alice_kp),
            "--member-keypackage".to_string(),
            to_s(&bob_kp),
            "--member-keypackage".to_string(),
            to_s(&carol_kp),
            "--own-leaf".to_string(),
            "0".to_string(),
            "--out".to_string(),
            to_s(&alice_group_base),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "bootstrap-group-state".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--member-keypackage".to_string(),
            to_s(&alice_kp),
            "--member-keypackage".to_string(),
            to_s(&bob_kp),
            "--member-keypackage".to_string(),
            to_s(&carol_kp),
            "--own-leaf".to_string(),
            "1".to_string(),
            "--out".to_string(),
            to_s(&bob_group_state),
            "--force".to_string(),
        ],
    );
    fs::copy(&alice_group_base, &alice_group_remove).expect("copy remove sender state");
    fs::copy(&alice_group_base, &alice_group_update).expect("copy update sender state");

    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "create-remove-proposal".to_string(),
            "--group-state".to_string(),
            to_s(&alice_group_remove),
            "--remove-leaf".to_string(),
            "2".to_string(),
            "--out".to_string(),
            to_s(&remove_proposal_file),
            "--sender-leaf".to_string(),
            "0".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "submit-proposal".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--proposal-file".to_string(),
            to_s(&remove_proposal_file),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "create-commit".to_string(),
            "--group-state".to_string(),
            to_s(&alice_group_remove),
            "--commit-out".to_string(),
            to_s(&remove_commit_file),
            "--path-update-out".to_string(),
            to_s(&remove_path_file),
            "--sender-leaf".to_string(),
            "0".to_string(),
        ],
    );

    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "create-update-proposal".to_string(),
            "--group-state".to_string(),
            to_s(&alice_group_update),
            "--keypackage-file".to_string(),
            to_s(&alice_v2_kp),
            "--out".to_string(),
            to_s(&update_proposal_file),
            "--sender-leaf".to_string(),
            "0".to_string(),
            "--target-leaf".to_string(),
            "0".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "create-commit".to_string(),
            "--group-state".to_string(),
            to_s(&alice_group_update),
            "--commit-out".to_string(),
            to_s(&update_commit_file),
            "--path-update-out".to_string(),
            to_s(&update_path_file),
            "--sender-leaf".to_string(),
            "0".to_string(),
        ],
    );

    let remove_env =
        CommitEnvelope::decode(&fs::read(&remove_commit_file).expect("read remove commit"))
            .expect("decode remove commit");
    let update_path_env =
        PathUpdateEnvelope::decode(&fs::read(&update_path_file).expect("read update path"))
            .expect("decode update path");
    assert_eq!(remove_env.group_id, update_path_env.group_id);
    assert_eq!(remove_env.epoch, update_path_env.epoch);
    assert_eq!(remove_env.sender_leaf, update_path_env.sender_leaf);

    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "submit-commit".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--commit-file".to_string(),
            to_s(&remove_commit_file),
            "--path-update-file".to_string(),
            to_s(&update_path_file),
        ],
    );

    run_ds_client_expect_fail(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "fetch-and-apply-latest".to_string(),
            "--group-state".to_string(),
            to_s(&bob_group_state),
            "--receiver-private-file".to_string(),
            to_s(&bob_recv),
            "--limit".to_string(),
            "100".to_string(),
        ],
        "failed to apply commit+path update during sync",
    );

    let loaded = ClientGroupState::load_from_file(&bob_group_state).expect("load state");
    assert_eq!(loaded.epoch, 0);
    assert_eq!(loaded.last_applied_commit_id, None);

    let _ = shutdown_tx.send(());
    let result = server.await.expect("join server");
    if let Err(err) = result {
        panic!("server returned error: {err}");
    }

    let _ = fs::remove_dir_all(base);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn malformed_encoded_path_update_stream_non_receiver_underflow_triggers_strict_rejection() {
    let fixture = setup_encoded_path_sync_fixture(
        "malformed-encoded-path-underflow",
        "group-malformed-encoded-path-underflow",
    )
    .await;

    let sender_state =
        ClientGroupState::load_from_file(&fixture.alice_group_state).expect("load sender state");
    let mismatch_level = find_non_receiver_level(&sender_state.ratchet_tree, 0, 2);

    let path_bytes = fs::read(&fixture.path_file).expect("read path file");
    let mut path_env = PathUpdateEnvelope::decode(&path_bytes).expect("decode path envelope");
    assert!(
        path_env.path_update.path_secrets.is_empty(),
        "encoded path should not carry raw path_secrets"
    );
    assert!(
        !path_env.path_update.ciphertexts[mismatch_level].is_empty(),
        "non-receiver level should have at least one ciphertext entry"
    );
    let _ = path_env.path_update.ciphertexts[mismatch_level].pop();
    fs::write(&fixture.path_file, path_env.encode()).expect("write malformed path envelope");

    run_ds_client(
        fixture.client_bin,
        &fixture.base_url,
        &fixture.alice_state,
        &[
            "submit-commit".to_string(),
            "--group-id".to_string(),
            fixture.group_id.clone(),
            "--commit-file".to_string(),
            to_s(&fixture.commit_file),
            "--path-update-file".to_string(),
            to_s(&fixture.path_file),
        ],
    );

    run_ds_client_expect_fail(
        fixture.client_bin,
        &fixture.base_url,
        &fixture.carol_state,
        &[
            "fetch-and-apply-latest".to_string(),
            "--group-state".to_string(),
            to_s(&fixture.carol_group_state),
            "--receiver-private-file".to_string(),
            to_s(&fixture.carol_recv),
            "--limit".to_string(),
            "100".to_string(),
        ],
        "failed to apply commit+path update during sync",
    );

    let loaded =
        ClientGroupState::load_from_file(&fixture.carol_group_state).expect("load receiver state");
    assert_eq!(loaded.epoch, 0);
    assert_eq!(loaded.last_applied_commit_id, None);

    teardown_encoded_path_sync_fixture(fixture).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn malformed_encoded_path_update_stream_non_receiver_overflow_triggers_strict_rejection() {
    let fixture = setup_encoded_path_sync_fixture(
        "malformed-encoded-path-overflow",
        "group-malformed-encoded-path-overflow",
    )
    .await;

    let sender_state =
        ClientGroupState::load_from_file(&fixture.alice_group_state).expect("load sender state");
    let mismatch_level = find_non_receiver_level(&sender_state.ratchet_tree, 0, 2);

    let path_bytes = fs::read(&fixture.path_file).expect("read path file");
    let mut path_env = PathUpdateEnvelope::decode(&path_bytes).expect("decode path envelope");
    assert!(
        path_env.path_update.path_secrets.is_empty(),
        "encoded path should not carry raw path_secrets"
    );
    assert!(
        !path_env.path_update.ciphertexts[mismatch_level].is_empty(),
        "non-receiver level should have at least one ciphertext entry"
    );
    let duplicate = path_env.path_update.ciphertexts[mismatch_level][0].clone();
    path_env.path_update.ciphertexts[mismatch_level].push(duplicate);
    fs::write(&fixture.path_file, path_env.encode()).expect("write malformed path envelope");

    run_ds_client(
        fixture.client_bin,
        &fixture.base_url,
        &fixture.alice_state,
        &[
            "submit-commit".to_string(),
            "--group-id".to_string(),
            fixture.group_id.clone(),
            "--commit-file".to_string(),
            to_s(&fixture.commit_file),
            "--path-update-file".to_string(),
            to_s(&fixture.path_file),
        ],
    );

    run_ds_client_expect_fail(
        fixture.client_bin,
        &fixture.base_url,
        &fixture.carol_state,
        &[
            "fetch-and-apply-latest".to_string(),
            "--group-state".to_string(),
            to_s(&fixture.carol_group_state),
            "--receiver-private-file".to_string(),
            to_s(&fixture.carol_recv),
            "--limit".to_string(),
            "100".to_string(),
        ],
        "failed to apply commit+path update during sync",
    );

    let loaded =
        ClientGroupState::load_from_file(&fixture.carol_group_state).expect("load receiver state");
    assert_eq!(loaded.epoch, 0);
    assert_eq!(loaded.last_applied_commit_id, None);

    teardown_encoded_path_sync_fixture(fixture).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn malformed_proposal_payload_has_no_sync_effect_without_commits() {
    let (state, base) = temp_state("malformed-proposal-no-commit");
    let (addr, shutdown_tx, server) = start_test_server(state).await;
    let base_url = format!("http://{addr}");
    let client_bin = env!("CARGO_BIN_EXE_ds_client");

    let work = base.join("work");
    let _ = fs::create_dir_all(&work);

    let alice_state = work.join("alice.json");
    let alice_kem = work.join("alice-kem.json");
    let alice_kp = work.join("alice.kp");
    let alice_recv = work.join("alice.recv.json");
    let alice_group_state = work.join("alice-group.bin");
    let malformed_proposal = work.join("malformed.proposal.bin");
    let group_id = "group-malformed-proposal-no-commit";

    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "register".to_string(),
            "--username".to_string(),
            "alice".to_string(),
            "--password".to_string(),
            "secret".to_string(),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "keygen".to_string(),
            "--out".to_string(),
            to_s(&alice_kem),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "keypackage-export".to_string(),
            "--kem-file".to_string(),
            to_s(&alice_kem),
            "--keypackage-out".to_string(),
            to_s(&alice_kp),
            "--receiver-private-out".to_string(),
            to_s(&alice_recv),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "bootstrap-group-state".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--member-keypackage".to_string(),
            to_s(&alice_kp),
            "--own-leaf".to_string(),
            "0".to_string(),
            "--out".to_string(),
            to_s(&alice_group_state),
            "--force".to_string(),
        ],
    );

    fs::write(&malformed_proposal, [0x01, 0x02, 0x03, 0x04]).expect("write malformed proposal");
    run_ds_client_expect_fail(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "submit-proposal".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--proposal-file".to_string(),
            to_s(&malformed_proposal),
        ],
        "invalid_proposal_payload",
    );

    let sync_output = run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "fetch-and-apply-latest".to_string(),
            "--group-state".to_string(),
            to_s(&alice_group_state),
            "--limit".to_string(),
            "100".to_string(),
        ],
    );
    assert!(
        sync_output.contains("applied_total=0"),
        "sync output:\n{sync_output}"
    );
    assert!(
        sync_output.contains("skipped_total=0"),
        "sync output:\n{sync_output}"
    );

    let loaded = ClientGroupState::load_from_file(&alice_group_state).expect("load state");
    assert_eq!(loaded.epoch, 0);
    assert_eq!(loaded.last_applied_commit_id, None);

    let _ = shutdown_tx.send(());
    let result = server.await.expect("join server");
    if let Err(err) = result {
        panic!("server returned error: {err}");
    }

    let _ = fs::remove_dir_all(base);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn malformed_proposal_payload_does_not_block_valid_commit_sync() {
    let (state, base) = temp_state("malformed-proposal-with-commit");
    let (addr, shutdown_tx, server) = start_test_server(state).await;
    let base_url = format!("http://{addr}");
    let client_bin = env!("CARGO_BIN_EXE_ds_client");

    let work = base.join("work");
    let _ = fs::create_dir_all(&work);

    let alice_state = work.join("alice.json");
    let alice_kem = work.join("alice-kem.json");
    let alice_kp = work.join("alice.kp");
    let alice_recv = work.join("alice.recv.json");
    let sender_group_state = work.join("alice-sender-group.bin");
    let receiver_group_state = work.join("alice-receiver-group.bin");
    let malformed_proposal = work.join("malformed.proposal.bin");
    let local_update_proposal = work.join("local-update.proposal.bin");
    let commit_file = work.join("commit.bin");
    let path_file = work.join("path.bin");
    let group_id = "group-malformed-proposal-with-commit";

    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "register".to_string(),
            "--username".to_string(),
            "alice".to_string(),
            "--password".to_string(),
            "secret".to_string(),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "keygen".to_string(),
            "--out".to_string(),
            to_s(&alice_kem),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "keypackage-export".to_string(),
            "--kem-file".to_string(),
            to_s(&alice_kem),
            "--keypackage-out".to_string(),
            to_s(&alice_kp),
            "--receiver-private-out".to_string(),
            to_s(&alice_recv),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "bootstrap-group-state".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--member-keypackage".to_string(),
            to_s(&alice_kp),
            "--own-leaf".to_string(),
            "0".to_string(),
            "--out".to_string(),
            to_s(&sender_group_state),
            "--force".to_string(),
        ],
    );
    fs::copy(&sender_group_state, &receiver_group_state).expect("copy receiver state");

    fs::write(&malformed_proposal, [0xAA, 0xBB, 0xCC, 0xDD]).expect("write malformed proposal");
    run_ds_client_expect_fail(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "submit-proposal".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--proposal-file".to_string(),
            to_s(&malformed_proposal),
        ],
        "invalid_proposal_payload",
    );

    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "create-update-proposal".to_string(),
            "--group-state".to_string(),
            to_s(&sender_group_state),
            "--keypackage-file".to_string(),
            to_s(&alice_kp),
            "--out".to_string(),
            to_s(&local_update_proposal),
            "--sender-leaf".to_string(),
            "0".to_string(),
            "--target-leaf".to_string(),
            "0".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "submit-proposal".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--proposal-file".to_string(),
            to_s(&local_update_proposal),
        ],
    );

    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "create-commit".to_string(),
            "--group-state".to_string(),
            to_s(&sender_group_state),
            "--commit-out".to_string(),
            to_s(&commit_file),
            "--path-update-out".to_string(),
            to_s(&path_file),
            "--sender-leaf".to_string(),
            "0".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "submit-commit".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--commit-file".to_string(),
            to_s(&commit_file),
            "--path-update-file".to_string(),
            to_s(&path_file),
        ],
    );

    let sync_output = run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "fetch-and-apply-latest".to_string(),
            "--group-state".to_string(),
            to_s(&receiver_group_state),
            "--limit".to_string(),
            "100".to_string(),
        ],
    );
    assert!(
        sync_output.contains("applied_total=1"),
        "sync output:\n{sync_output}"
    );

    let loaded = ClientGroupState::load_from_file(&receiver_group_state).expect("load state");
    assert_eq!(loaded.epoch, 1);
    assert!(loaded.last_applied_commit_id.is_some());

    let _ = shutdown_tx.send(());
    let result = server.await.expect("join server");
    if let Err(err) = result {
        panic!("server returned error: {err}");
    }

    let _ = fs::remove_dir_all(base);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forward_secrecy_ds_sync_stale_receiver_private_fails_after_rotation() {
    let (state, base) = temp_state("forward-secrecy-ds-sync");
    let (addr, shutdown_tx, server) = start_test_server(state).await;
    let base_url = format!("http://{addr}");
    let client_bin = env!("CARGO_BIN_EXE_ds_client");

    let work = base.join("work");
    let _ = fs::create_dir_all(&work);

    let alice_state = work.join("alice.json");
    let bob_state = work.join("bob.json");
    let alice_kem = work.join("alice-kem.json");
    let alice_v2_kem = work.join("alice-v2-kem.json");
    let bob_kem = work.join("bob-kem.json");
    let bob_v2_kem = work.join("bob-v2-kem.json");
    let alice_kp = work.join("alice.kp");
    let alice_v2_kp = work.join("alice-v2.kp");
    let bob_kp = work.join("bob.kp");
    let bob_v2_kp = work.join("bob-v2.kp");
    let alice_recv = work.join("alice.recv.json");
    let bob_recv = work.join("bob.recv.json");
    let bob_v2_recv = work.join("bob-v2.recv.json");

    let bob_sender_state = work.join("bob-sender-state.bin");
    let alice_group_state = work.join("alice-group-state.bin");
    let bob_old_receiver_state = work.join("bob-old-receiver-state.bin");
    let bob_new_receiver_state = work.join("bob-new-receiver-state.bin");

    let bob_update_proposal = work.join("bob-update.proposal.bin");
    let bob_update_commit = work.join("bob-update.commit.bin");
    let bob_update_path = work.join("bob-update.path.bin");
    let alice_update_proposal = work.join("alice-update.proposal.bin");
    let alice_update_commit = work.join("alice-update.commit.bin");
    let alice_update_path = work.join("alice-update.path.bin");
    let group_id = "group-forward-secrecy";

    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "register".to_string(),
            "--username".to_string(),
            "alice".to_string(),
            "--password".to_string(),
            "secret".to_string(),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "register".to_string(),
            "--username".to_string(),
            "bob".to_string(),
            "--password".to_string(),
            "secret".to_string(),
            "--force".to_string(),
        ],
    );

    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "keygen".to_string(),
            "--out".to_string(),
            to_s(&alice_kem),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "keypackage-export".to_string(),
            "--kem-file".to_string(),
            to_s(&alice_kem),
            "--keypackage-out".to_string(),
            to_s(&alice_kp),
            "--receiver-private-out".to_string(),
            to_s(&alice_recv),
            "--force".to_string(),
        ],
    );

    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "keygen".to_string(),
            "--out".to_string(),
            to_s(&bob_kem),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "keypackage-export".to_string(),
            "--kem-file".to_string(),
            to_s(&bob_kem),
            "--keypackage-out".to_string(),
            to_s(&bob_kp),
            "--receiver-private-out".to_string(),
            to_s(&bob_recv),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "keygen".to_string(),
            "--out".to_string(),
            to_s(&bob_v2_kem),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "keypackage-export".to_string(),
            "--kem-file".to_string(),
            to_s(&bob_v2_kem),
            "--keypackage-out".to_string(),
            to_s(&bob_v2_kp),
            "--receiver-private-out".to_string(),
            to_s(&bob_v2_recv),
            "--force".to_string(),
        ],
    );

    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "bootstrap-group-state".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--member-keypackage".to_string(),
            to_s(&alice_kp),
            "--member-keypackage".to_string(),
            to_s(&bob_kp),
            "--own-leaf".to_string(),
            "1".to_string(),
            "--out".to_string(),
            to_s(&bob_sender_state),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "bootstrap-group-state".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--member-keypackage".to_string(),
            to_s(&alice_kp),
            "--member-keypackage".to_string(),
            to_s(&bob_kp),
            "--own-leaf".to_string(),
            "0".to_string(),
            "--out".to_string(),
            to_s(&alice_group_state),
            "--force".to_string(),
        ],
    );

    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "create-update-proposal".to_string(),
            "--group-state".to_string(),
            to_s(&bob_sender_state),
            "--keypackage-file".to_string(),
            to_s(&bob_v2_kp),
            "--out".to_string(),
            to_s(&bob_update_proposal),
            "--sender-leaf".to_string(),
            "1".to_string(),
            "--target-leaf".to_string(),
            "1".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "submit-proposal".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--proposal-file".to_string(),
            to_s(&bob_update_proposal),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "create-commit".to_string(),
            "--group-state".to_string(),
            to_s(&bob_sender_state),
            "--commit-out".to_string(),
            to_s(&bob_update_commit),
            "--path-update-out".to_string(),
            to_s(&bob_update_path),
            "--sender-leaf".to_string(),
            "1".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "submit-commit".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--commit-file".to_string(),
            to_s(&bob_update_commit),
            "--path-update-file".to_string(),
            to_s(&bob_update_path),
        ],
    );

    let alice_sync_1 = run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "fetch-and-apply-latest".to_string(),
            "--group-state".to_string(),
            to_s(&alice_group_state),
            "--receiver-private-file".to_string(),
            to_s(&alice_recv),
            "--limit".to_string(),
            "100".to_string(),
        ],
    );
    assert!(
        alice_sync_1.contains("applied_total=1"),
        "alice sync epoch1 output:\n{alice_sync_1}"
    );

    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "keygen".to_string(),
            "--out".to_string(),
            to_s(&alice_v2_kem),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "keypackage-export".to_string(),
            "--kem-file".to_string(),
            to_s(&alice_v2_kem),
            "--keypackage-out".to_string(),
            to_s(&alice_v2_kp),
            "--receiver-private-out".to_string(),
            to_s(&alice_recv),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "create-update-proposal".to_string(),
            "--group-state".to_string(),
            to_s(&alice_group_state),
            "--keypackage-file".to_string(),
            to_s(&alice_v2_kp),
            "--out".to_string(),
            to_s(&alice_update_proposal),
            "--sender-leaf".to_string(),
            "0".to_string(),
            "--target-leaf".to_string(),
            "0".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "submit-proposal".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--proposal-file".to_string(),
            to_s(&alice_update_proposal),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "create-commit".to_string(),
            "--group-state".to_string(),
            to_s(&alice_group_state),
            "--commit-out".to_string(),
            to_s(&alice_update_commit),
            "--path-update-out".to_string(),
            to_s(&alice_update_path),
            "--sender-leaf".to_string(),
            "0".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "submit-commit".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--commit-file".to_string(),
            to_s(&alice_update_commit),
            "--path-update-file".to_string(),
            to_s(&alice_update_path),
        ],
    );

    fs::copy(&bob_sender_state, &bob_old_receiver_state).expect("copy bob old receiver state");
    fs::copy(&bob_sender_state, &bob_new_receiver_state).expect("copy bob new receiver state");

    let old_key_sync = run_ds_client_expect_fail(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "fetch-and-apply-latest".to_string(),
            "--group-state".to_string(),
            to_s(&bob_old_receiver_state),
            "--receiver-private-file".to_string(),
            to_s(&bob_recv),
            "--limit".to_string(),
            "100".to_string(),
        ],
        "failed to apply commit+path update during sync",
    );
    assert!(
        old_key_sync.contains("failed to apply commit+path update during sync"),
        "old key sync output:\n{old_key_sync}"
    );

    let bob_old_after = ClientGroupState::load_from_file(&bob_old_receiver_state)
        .expect("load bob old receiver state");
    assert_eq!(bob_old_after.epoch, 1);

    let new_key_sync = run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "fetch-and-apply-latest".to_string(),
            "--group-state".to_string(),
            to_s(&bob_new_receiver_state),
            "--receiver-private-file".to_string(),
            to_s(&bob_v2_recv),
            "--limit".to_string(),
            "100".to_string(),
        ],
    );
    assert!(
        new_key_sync.contains("applied_total=1"),
        "new key sync output:\n{new_key_sync}"
    );

    let alice_final =
        ClientGroupState::load_from_file(&alice_group_state).expect("load alice final state");
    let bob_new_after = ClientGroupState::load_from_file(&bob_new_receiver_state)
        .expect("load bob new receiver state");
    assert_eq!(bob_new_after.epoch, 2);
    assert_eq!(alice_final.epoch, 2);
    assert_eq!(bob_new_after.ratchet_tree, alice_final.ratchet_tree);

    let _ = shutdown_tx.send(());
    let result = server.await.expect("join server");
    if let Err(err) = result {
        panic!("server returned error: {err}");
    }

    let _ = fs::remove_dir_all(base);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forward_secrecy_ds_sync_removed_member_cannot_apply_future_commits() {
    let (state, base) = temp_state("forward-secrecy-removed-member");
    let (addr, shutdown_tx, server) = start_test_server(state).await;
    let base_url = format!("http://{addr}");
    let client_bin = env!("CARGO_BIN_EXE_ds_client");

    let work = base.join("work");
    let _ = fs::create_dir_all(&work);

    let alice_state = work.join("alice.json");
    let bob_state = work.join("bob.json");
    let carol_state = work.join("carol.json");

    let alice_kem = work.join("alice-kem.json");
    let bob_kem = work.join("bob-kem.json");
    let bob_v2_kem = work.join("bob-v2-kem.json");
    let carol_kem = work.join("carol-kem.json");

    let alice_kp = work.join("alice.kp");
    let bob_kp = work.join("bob.kp");
    let bob_v2_kp = work.join("bob-v2.kp");
    let carol_kp = work.join("carol.kp");

    let alice_recv = work.join("alice.recv.json");
    let bob_recv = work.join("bob.recv.json");
    let bob_v2_recv = work.join("bob-v2.recv.json");
    let carol_recv = work.join("carol.recv.json");

    let alice_group_state = work.join("alice-group.bin");
    let bob_group_state = work.join("bob-group.bin");
    let carol_group_state = work.join("carol-group.bin");

    let remove_carol_proposal = work.join("remove-carol.proposal.bin");
    let remove_carol_commit = work.join("remove-carol.commit.bin");
    let remove_carol_path = work.join("remove-carol.path.bin");
    let bob_update_proposal = work.join("bob-update.proposal.bin");
    let bob_update_commit = work.join("bob-update.commit.bin");
    let bob_update_path = work.join("bob-update.path.bin");
    let group_id = "group-forward-secrecy-removed-member";

    for (state_file, username) in [
        (&alice_state, "alice"),
        (&bob_state, "bob"),
        (&carol_state, "carol"),
    ] {
        run_ds_client(
            client_bin,
            &base_url,
            state_file,
            &[
                "register".to_string(),
                "--username".to_string(),
                username.to_string(),
                "--password".to_string(),
                "secret".to_string(),
                "--force".to_string(),
            ],
        );
    }

    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "keygen".to_string(),
            "--out".to_string(),
            to_s(&alice_kem),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "keypackage-export".to_string(),
            "--kem-file".to_string(),
            to_s(&alice_kem),
            "--keypackage-out".to_string(),
            to_s(&alice_kp),
            "--receiver-private-out".to_string(),
            to_s(&alice_recv),
            "--force".to_string(),
        ],
    );

    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "keygen".to_string(),
            "--out".to_string(),
            to_s(&bob_kem),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "keypackage-export".to_string(),
            "--kem-file".to_string(),
            to_s(&bob_kem),
            "--keypackage-out".to_string(),
            to_s(&bob_kp),
            "--receiver-private-out".to_string(),
            to_s(&bob_recv),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "keygen".to_string(),
            "--out".to_string(),
            to_s(&bob_v2_kem),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "keypackage-export".to_string(),
            "--kem-file".to_string(),
            to_s(&bob_v2_kem),
            "--keypackage-out".to_string(),
            to_s(&bob_v2_kp),
            "--receiver-private-out".to_string(),
            to_s(&bob_v2_recv),
            "--force".to_string(),
        ],
    );

    run_ds_client(
        client_bin,
        &base_url,
        &carol_state,
        &[
            "keygen".to_string(),
            "--out".to_string(),
            to_s(&carol_kem),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &carol_state,
        &[
            "keypackage-export".to_string(),
            "--kem-file".to_string(),
            to_s(&carol_kem),
            "--keypackage-out".to_string(),
            to_s(&carol_kp),
            "--receiver-private-out".to_string(),
            to_s(&carol_recv),
            "--force".to_string(),
        ],
    );

    for (state_file, own_leaf, out_file) in [
        (&alice_state, "0", &alice_group_state),
        (&bob_state, "1", &bob_group_state),
        (&carol_state, "2", &carol_group_state),
    ] {
        run_ds_client(
            client_bin,
            &base_url,
            state_file,
            &[
                "bootstrap-group-state".to_string(),
                "--group-id".to_string(),
                group_id.to_string(),
                "--member-keypackage".to_string(),
                to_s(&alice_kp),
                "--member-keypackage".to_string(),
                to_s(&bob_kp),
                "--member-keypackage".to_string(),
                to_s(&carol_kp),
                "--own-leaf".to_string(),
                own_leaf.to_string(),
                "--out".to_string(),
                to_s(out_file),
                "--force".to_string(),
            ],
        );
    }

    // Commit #1: A removes C.
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "create-remove-proposal".to_string(),
            "--group-state".to_string(),
            to_s(&alice_group_state),
            "--remove-leaf".to_string(),
            "2".to_string(),
            "--out".to_string(),
            to_s(&remove_carol_proposal),
            "--sender-leaf".to_string(),
            "0".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "submit-proposal".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--proposal-file".to_string(),
            to_s(&remove_carol_proposal),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "create-commit".to_string(),
            "--group-state".to_string(),
            to_s(&alice_group_state),
            "--commit-out".to_string(),
            to_s(&remove_carol_commit),
            "--path-update-out".to_string(),
            to_s(&remove_carol_path),
            "--sender-leaf".to_string(),
            "0".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "submit-commit".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--commit-file".to_string(),
            to_s(&remove_carol_commit),
            "--path-update-file".to_string(),
            to_s(&remove_carol_path),
        ],
    );

    let bob_sync_1 = run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "fetch-and-apply-latest".to_string(),
            "--group-state".to_string(),
            to_s(&bob_group_state),
            "--receiver-private-file".to_string(),
            to_s(&bob_recv),
            "--limit".to_string(),
            "100".to_string(),
        ],
    );
    assert!(
        bob_sync_1.contains("applied_total=1"),
        "bob sync 1 output:\n{bob_sync_1}"
    );

    // Commit #2: B updates self in the post-removal group.
    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "create-update-proposal".to_string(),
            "--group-state".to_string(),
            to_s(&bob_group_state),
            "--keypackage-file".to_string(),
            to_s(&bob_v2_kp),
            "--out".to_string(),
            to_s(&bob_update_proposal),
            "--sender-leaf".to_string(),
            "1".to_string(),
            "--target-leaf".to_string(),
            "1".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "submit-proposal".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--proposal-file".to_string(),
            to_s(&bob_update_proposal),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "create-commit".to_string(),
            "--group-state".to_string(),
            to_s(&bob_group_state),
            "--commit-out".to_string(),
            to_s(&bob_update_commit),
            "--path-update-out".to_string(),
            to_s(&bob_update_path),
            "--sender-leaf".to_string(),
            "1".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "submit-commit".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--commit-file".to_string(),
            to_s(&bob_update_commit),
            "--path-update-file".to_string(),
            to_s(&bob_update_path),
        ],
    );

    let alice_sync_2 = run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "fetch-and-apply-latest".to_string(),
            "--group-state".to_string(),
            to_s(&alice_group_state),
            "--limit".to_string(),
            "100".to_string(),
        ],
    );
    assert!(
        alice_sync_2.contains("applied_total=1"),
        "alice sync 2 output:\n{alice_sync_2}"
    );

    // Removed member C cannot decrypt/apply future commit stream.
    let carol_sync_fail = run_ds_client_expect_fail(
        client_bin,
        &base_url,
        &carol_state,
        &[
            "fetch-and-apply-latest".to_string(),
            "--group-state".to_string(),
            to_s(&carol_group_state),
            "--receiver-private-file".to_string(),
            to_s(&carol_recv),
            "--limit".to_string(),
            "100".to_string(),
        ],
        "failed to apply commit+path update during sync",
    );
    assert!(
        carol_sync_fail.contains("failed to apply commit+path update during sync"),
        "carol sync output:\n{carol_sync_fail}"
    );

    let alice_loaded = ClientGroupState::load_from_file(&alice_group_state).expect("load alice");
    let bob_loaded = ClientGroupState::load_from_file(&bob_group_state).expect("load bob");
    let carol_loaded = ClientGroupState::load_from_file(&carol_group_state).expect("load carol");

    assert_eq!(alice_loaded.epoch, 2);
    assert_eq!(bob_loaded.epoch, 2);
    assert_eq!(carol_loaded.epoch, 0);
    assert_eq!(carol_loaded.last_applied_commit_id, None);
    assert_eq!(alice_loaded.ratchet_tree, bob_loaded.ratchet_tree);

    let _ = shutdown_tx.send(());
    let result = server.await.expect("join server");
    if let Err(err) = result {
        panic!("server returned error: {err}");
    }

    let _ = fs::remove_dir_all(base);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pcs_ds_sync_recovers_after_compromised_member_self_update() {
    let (state, base) = temp_state("pcs-recovery-chain");
    let (addr, shutdown_tx, server) = start_test_server(state).await;
    let base_url = format!("http://{addr}");
    let client_bin = env!("CARGO_BIN_EXE_ds_client");

    let work = base.join("work");
    let _ = fs::create_dir_all(&work);

    let alice_state = work.join("alice.json");
    let bob_state = work.join("bob.json");

    let alice_kem = work.join("alice-kem.json");
    let alice_v2_kem = work.join("alice-v2-kem.json");
    let alice_v3_kem = work.join("alice-v3-kem.json");
    let bob_kem = work.join("bob-kem.json");
    let bob_v2_kem = work.join("bob-v2-kem.json");

    let alice_kp = work.join("alice.kp");
    let alice_v2_kp = work.join("alice-v2.kp");
    let alice_v3_kp = work.join("alice-v3.kp");
    let bob_kp = work.join("bob.kp");
    let bob_v2_kp = work.join("bob-v2.kp");

    let alice_recv = work.join("alice.recv.json");
    let alice_v2_recv = work.join("alice-v2.recv.json");
    let bob_recv = work.join("bob.recv.json");
    let bob_v2_recv = work.join("bob-v2.recv.json");

    let alice_group_state = work.join("alice-group.bin");
    let bob_group_state = work.join("bob-group.bin");
    let bob_compromised_state = work.join("bob-compromised.bin");
    let bob_recovered_state = work.join("bob-recovered.bin");

    let commit1_proposal = work.join("commit1-alice-update.proposal.bin");
    let commit1_file = work.join("commit1-alice-update.commit.bin");
    let path1_file = work.join("commit1-alice-update.path.bin");
    let commit2_proposal = work.join("commit2-bob-update.proposal.bin");
    let commit2_file = work.join("commit2-bob-update.commit.bin");
    let path2_file = work.join("commit2-bob-update.path.bin");
    let commit3_proposal = work.join("commit3-alice-update.proposal.bin");
    let commit3_file = work.join("commit3-alice-update.commit.bin");
    let path3_file = work.join("commit3-alice-update.path.bin");
    let group_id = "group-pcs-recovery-chain";

    for (state_file, username) in [(&alice_state, "alice"), (&bob_state, "bob")] {
        run_ds_client(
            client_bin,
            &base_url,
            state_file,
            &[
                "register".to_string(),
                "--username".to_string(),
                username.to_string(),
                "--password".to_string(),
                "secret".to_string(),
                "--force".to_string(),
            ],
        );
    }

    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "keygen".to_string(),
            "--out".to_string(),
            to_s(&alice_kem),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "keypackage-export".to_string(),
            "--kem-file".to_string(),
            to_s(&alice_kem),
            "--keypackage-out".to_string(),
            to_s(&alice_kp),
            "--receiver-private-out".to_string(),
            to_s(&alice_recv),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "keygen".to_string(),
            "--out".to_string(),
            to_s(&alice_v2_kem),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "keypackage-export".to_string(),
            "--kem-file".to_string(),
            to_s(&alice_v2_kem),
            "--keypackage-out".to_string(),
            to_s(&alice_v2_kp),
            "--receiver-private-out".to_string(),
            to_s(&alice_v2_recv),
            "--force".to_string(),
        ],
    );

    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "keygen".to_string(),
            "--out".to_string(),
            to_s(&bob_kem),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "keypackage-export".to_string(),
            "--kem-file".to_string(),
            to_s(&bob_kem),
            "--keypackage-out".to_string(),
            to_s(&bob_kp),
            "--receiver-private-out".to_string(),
            to_s(&bob_recv),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "keygen".to_string(),
            "--out".to_string(),
            to_s(&bob_v2_kem),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "keypackage-export".to_string(),
            "--kem-file".to_string(),
            to_s(&bob_v2_kem),
            "--keypackage-out".to_string(),
            to_s(&bob_v2_kp),
            "--receiver-private-out".to_string(),
            to_s(&bob_v2_recv),
            "--force".to_string(),
        ],
    );

    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "bootstrap-group-state".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--member-keypackage".to_string(),
            to_s(&alice_kp),
            "--member-keypackage".to_string(),
            to_s(&bob_kp),
            "--own-leaf".to_string(),
            "0".to_string(),
            "--out".to_string(),
            to_s(&alice_group_state),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "bootstrap-group-state".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--member-keypackage".to_string(),
            to_s(&alice_kp),
            "--member-keypackage".to_string(),
            to_s(&bob_kp),
            "--own-leaf".to_string(),
            "1".to_string(),
            "--out".to_string(),
            to_s(&bob_group_state),
            "--force".to_string(),
        ],
    );

    // Commit #1: A updates self (using original compromised B receiver key material).
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "create-update-proposal".to_string(),
            "--group-state".to_string(),
            to_s(&alice_group_state),
            "--keypackage-file".to_string(),
            to_s(&alice_v2_kp),
            "--out".to_string(),
            to_s(&commit1_proposal),
            "--sender-leaf".to_string(),
            "0".to_string(),
            "--target-leaf".to_string(),
            "0".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "submit-proposal".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--proposal-file".to_string(),
            to_s(&commit1_proposal),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "create-commit".to_string(),
            "--group-state".to_string(),
            to_s(&alice_group_state),
            "--commit-out".to_string(),
            to_s(&commit1_file),
            "--path-update-out".to_string(),
            to_s(&path1_file),
            "--sender-leaf".to_string(),
            "0".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "submit-commit".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--commit-file".to_string(),
            to_s(&commit1_file),
            "--path-update-file".to_string(),
            to_s(&path1_file),
        ],
    );
    let bob_sync_1 = run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "fetch-and-apply-latest".to_string(),
            "--group-state".to_string(),
            to_s(&bob_group_state),
            "--receiver-private-file".to_string(),
            to_s(&bob_recv),
            "--limit".to_string(),
            "100".to_string(),
        ],
    );
    assert!(
        bob_sync_1.contains("applied_total=1"),
        "bob sync 1 output:\n{bob_sync_1}"
    );

    // Commit #2: B updates self to recover from compromise.
    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "create-update-proposal".to_string(),
            "--group-state".to_string(),
            to_s(&bob_group_state),
            "--keypackage-file".to_string(),
            to_s(&bob_v2_kp),
            "--out".to_string(),
            to_s(&commit2_proposal),
            "--sender-leaf".to_string(),
            "1".to_string(),
            "--target-leaf".to_string(),
            "1".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "submit-proposal".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--proposal-file".to_string(),
            to_s(&commit2_proposal),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "create-commit".to_string(),
            "--group-state".to_string(),
            to_s(&bob_group_state),
            "--commit-out".to_string(),
            to_s(&commit2_file),
            "--path-update-out".to_string(),
            to_s(&path2_file),
            "--sender-leaf".to_string(),
            "1".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "submit-commit".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--commit-file".to_string(),
            to_s(&commit2_file),
            "--path-update-file".to_string(),
            to_s(&path2_file),
        ],
    );
    let alice_sync_2 = run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "fetch-and-apply-latest".to_string(),
            "--group-state".to_string(),
            to_s(&alice_group_state),
            "--receiver-private-file".to_string(),
            to_s(&alice_v2_recv),
            "--limit".to_string(),
            "100".to_string(),
        ],
    );
    assert!(
        alice_sync_2.contains("applied_total=1"),
        "alice sync 2 output:\n{alice_sync_2}"
    );

    fs::copy(&bob_group_state, &bob_compromised_state).expect("copy bob compromised state");
    fs::copy(&bob_group_state, &bob_recovered_state).expect("copy bob recovered state");

    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "keygen".to_string(),
            "--out".to_string(),
            to_s(&alice_v3_kem),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "keypackage-export".to_string(),
            "--kem-file".to_string(),
            to_s(&alice_v3_kem),
            "--keypackage-out".to_string(),
            to_s(&alice_v3_kp),
            "--receiver-private-out".to_string(),
            to_s(&alice_recv),
            "--force".to_string(),
        ],
    );

    // Commit #3: A updates again; this commit should only be decryptable by B's recovered key.
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "create-update-proposal".to_string(),
            "--group-state".to_string(),
            to_s(&alice_group_state),
            "--keypackage-file".to_string(),
            to_s(&alice_v3_kp),
            "--out".to_string(),
            to_s(&commit3_proposal),
            "--sender-leaf".to_string(),
            "0".to_string(),
            "--target-leaf".to_string(),
            "0".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "submit-proposal".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--proposal-file".to_string(),
            to_s(&commit3_proposal),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "create-commit".to_string(),
            "--group-state".to_string(),
            to_s(&alice_group_state),
            "--commit-out".to_string(),
            to_s(&commit3_file),
            "--path-update-out".to_string(),
            to_s(&path3_file),
            "--sender-leaf".to_string(),
            "0".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "submit-commit".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--commit-file".to_string(),
            to_s(&commit3_file),
            "--path-update-file".to_string(),
            to_s(&path3_file),
        ],
    );

    let compromised_sync = run_ds_client_expect_fail(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "fetch-and-apply-latest".to_string(),
            "--group-state".to_string(),
            to_s(&bob_compromised_state),
            "--receiver-private-file".to_string(),
            to_s(&bob_recv),
            "--limit".to_string(),
            "100".to_string(),
        ],
        "failed to apply commit+path update during sync",
    );
    assert!(
        compromised_sync.contains("failed to apply commit+path update during sync"),
        "compromised sync output:\n{compromised_sync}"
    );

    let recovered_sync = run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "fetch-and-apply-latest".to_string(),
            "--group-state".to_string(),
            to_s(&bob_recovered_state),
            "--receiver-private-file".to_string(),
            to_s(&bob_v2_recv),
            "--limit".to_string(),
            "100".to_string(),
        ],
    );
    assert!(
        recovered_sync.contains("applied_total=1"),
        "recovered sync output:\n{recovered_sync}"
    );

    let compromised_loaded =
        ClientGroupState::load_from_file(&bob_compromised_state).expect("load compromised state");
    let recovered_loaded =
        ClientGroupState::load_from_file(&bob_recovered_state).expect("load recovered state");
    let alice_loaded =
        ClientGroupState::load_from_file(&alice_group_state).expect("load alice state");

    assert_eq!(compromised_loaded.epoch, 2);
    assert!(compromised_loaded.last_applied_commit_id.is_some());
    assert_eq!(recovered_loaded.epoch, 3);
    assert_eq!(alice_loaded.epoch, 3);
    assert_eq!(recovered_loaded.ratchet_tree, alice_loaded.ratchet_tree);

    let _ = shutdown_tx.send(());
    let result = server.await.expect("join server");
    if let Err(err) = result {
        panic!("server returned error: {err}");
    }

    let _ = fs::remove_dir_all(base);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pcs_three_member_add_compromise_self_update_then_recover() {
    let (state, base) = temp_state("pcs-three-member-recovery");
    let (addr, shutdown_tx, server) = start_test_server(state).await;
    let base_url = format!("http://{addr}");
    let client_bin = env!("CARGO_BIN_EXE_ds_client");

    let work = base.join("work");
    let _ = fs::create_dir_all(&work);

    let alice_state = work.join("alice.json");
    let bob_state = work.join("bob.json");
    let carol_state = work.join("carol.json");

    let alice_kem = work.join("alice-kem.json");
    let alice_v2_kem = work.join("alice-v2-kem.json");
    let bob_kem = work.join("bob-kem.json");
    let carol_kem = work.join("carol-kem.json");
    let carol_v2_kem = work.join("carol-v2-kem.json");

    let alice_kp = work.join("alice.kp");
    let alice_v2_kp = work.join("alice-v2.kp");
    let bob_kp = work.join("bob.kp");
    let carol_kp = work.join("carol.kp");
    let carol_v2_kp = work.join("carol-v2.kp");
    let carol_from_ds_kp = work.join("carol-from-ds.kp");

    let alice_recv = work.join("alice.recv.json");
    let alice_v2_recv = work.join("alice-v2.recv.json");
    let bob_recv = work.join("bob.recv.json");
    let carol_recv = work.join("carol.recv.json");
    let carol_v2_recv = work.join("carol-v2.recv.json");

    let alice_group_state = work.join("alice-group.bin");
    let bob_group_state = work.join("bob-group.bin");
    let carol_group_state = work.join("carol-group.bin");
    let carol_compromised_state = work.join("carol-compromised.bin");
    let carol_recovered_state = work.join("carol-recovered.bin");

    let add_carol_proposal = work.join("add-carol.proposal.bin");
    let add_carol_commit = work.join("add-carol.commit.bin");
    let add_carol_path = work.join("add-carol.path.bin");
    let carol_recovery_proposal = work.join("carol-recovery.proposal.bin");
    let carol_recovery_commit = work.join("carol-recovery.commit.bin");
    let carol_recovery_path = work.join("carol-recovery.path.bin");
    let alice_update_proposal = work.join("alice-update.proposal.bin");
    let alice_update_commit = work.join("alice-update.commit.bin");
    let alice_update_path = work.join("alice-update.path.bin");
    let group_id = "group-pcs-three-member-recovery";

    for (state_file, username) in [
        (&alice_state, "alice"),
        (&bob_state, "bob"),
        (&carol_state, "carol"),
    ] {
        run_ds_client(
            client_bin,
            &base_url,
            state_file,
            &[
                "register".to_string(),
                "--username".to_string(),
                username.to_string(),
                "--password".to_string(),
                "secret".to_string(),
                "--force".to_string(),
            ],
        );
    }

    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "keygen".to_string(),
            "--out".to_string(),
            to_s(&alice_kem),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "keypackage-export".to_string(),
            "--kem-file".to_string(),
            to_s(&alice_kem),
            "--keypackage-out".to_string(),
            to_s(&alice_kp),
            "--receiver-private-out".to_string(),
            to_s(&alice_recv),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "keygen".to_string(),
            "--out".to_string(),
            to_s(&alice_v2_kem),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "keypackage-export".to_string(),
            "--kem-file".to_string(),
            to_s(&alice_v2_kem),
            "--keypackage-out".to_string(),
            to_s(&alice_v2_kp),
            "--receiver-private-out".to_string(),
            to_s(&alice_v2_recv),
            "--force".to_string(),
        ],
    );

    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "keygen".to_string(),
            "--out".to_string(),
            to_s(&bob_kem),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "keypackage-export".to_string(),
            "--kem-file".to_string(),
            to_s(&bob_kem),
            "--keypackage-out".to_string(),
            to_s(&bob_kp),
            "--receiver-private-out".to_string(),
            to_s(&bob_recv),
            "--force".to_string(),
        ],
    );

    run_ds_client(
        client_bin,
        &base_url,
        &carol_state,
        &[
            "keygen".to_string(),
            "--out".to_string(),
            to_s(&carol_kem),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &carol_state,
        &[
            "keypackage-export".to_string(),
            "--kem-file".to_string(),
            to_s(&carol_kem),
            "--keypackage-out".to_string(),
            to_s(&carol_kp),
            "--receiver-private-out".to_string(),
            to_s(&carol_recv),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &carol_state,
        &[
            "keygen".to_string(),
            "--out".to_string(),
            to_s(&carol_v2_kem),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &carol_state,
        &[
            "keypackage-export".to_string(),
            "--kem-file".to_string(),
            to_s(&carol_v2_kem),
            "--keypackage-out".to_string(),
            to_s(&carol_v2_kp),
            "--receiver-private-out".to_string(),
            to_s(&carol_v2_recv),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &carol_state,
        &[
            "publish-key-package".to_string(),
            "--keypackage-file".to_string(),
            to_s(&carol_kp),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "fetch-key-package".to_string(),
            "--target".to_string(),
            "carol".to_string(),
            "--out".to_string(),
            to_s(&carol_from_ds_kp),
        ],
    );

    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "bootstrap-group-state".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--member-keypackage".to_string(),
            to_s(&alice_kp),
            "--member-keypackage".to_string(),
            to_s(&bob_kp),
            "--own-leaf".to_string(),
            "0".to_string(),
            "--out".to_string(),
            to_s(&alice_group_state),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "bootstrap-group-state".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--member-keypackage".to_string(),
            to_s(&alice_kp),
            "--member-keypackage".to_string(),
            to_s(&bob_kp),
            "--own-leaf".to_string(),
            "1".to_string(),
            "--out".to_string(),
            to_s(&bob_group_state),
            "--force".to_string(),
        ],
    );

    // Commit #1: A adds C.
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "create-add-proposal".to_string(),
            "--group-state".to_string(),
            to_s(&alice_group_state),
            "--keypackage-file".to_string(),
            to_s(&carol_from_ds_kp),
            "--out".to_string(),
            to_s(&add_carol_proposal),
            "--sender-leaf".to_string(),
            "0".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "submit-proposal".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--proposal-file".to_string(),
            to_s(&add_carol_proposal),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "create-commit".to_string(),
            "--group-state".to_string(),
            to_s(&alice_group_state),
            "--commit-out".to_string(),
            to_s(&add_carol_commit),
            "--path-update-out".to_string(),
            to_s(&add_carol_path),
            "--sender-leaf".to_string(),
            "0".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "submit-commit".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--commit-file".to_string(),
            to_s(&add_carol_commit),
            "--path-update-file".to_string(),
            to_s(&add_carol_path),
        ],
    );
    let bob_sync_1 = run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "fetch-and-apply-latest".to_string(),
            "--group-state".to_string(),
            to_s(&bob_group_state),
            "--receiver-private-file".to_string(),
            to_s(&bob_recv),
            "--limit".to_string(),
            "100".to_string(),
        ],
    );
    assert!(
        bob_sync_1.contains("applied_total=1"),
        "bob sync 1 output:\n{bob_sync_1}"
    );
    run_ds_client(
        client_bin,
        &base_url,
        &carol_state,
        &[
            "join-from-commit".to_string(),
            "--base-member-keypackage".to_string(),
            to_s(&alice_kp),
            "--base-member-keypackage".to_string(),
            to_s(&bob_kp),
            "--commit-file".to_string(),
            to_s(&add_carol_commit),
            "--path-update-file".to_string(),
            to_s(&add_carol_path),
            "--receiver-private-file".to_string(),
            to_s(&carol_recv),
            "--out".to_string(),
            to_s(&carol_group_state),
            "--own-leaf".to_string(),
            "2".to_string(),
            "--force".to_string(),
        ],
    );

    // Commit #2: C self-updates (recovery step).
    run_ds_client(
        client_bin,
        &base_url,
        &carol_state,
        &[
            "create-update-proposal".to_string(),
            "--group-state".to_string(),
            to_s(&carol_group_state),
            "--keypackage-file".to_string(),
            to_s(&carol_v2_kp),
            "--out".to_string(),
            to_s(&carol_recovery_proposal),
            "--sender-leaf".to_string(),
            "2".to_string(),
            "--target-leaf".to_string(),
            "2".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &carol_state,
        &[
            "submit-proposal".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--proposal-file".to_string(),
            to_s(&carol_recovery_proposal),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &carol_state,
        &[
            "create-commit".to_string(),
            "--group-state".to_string(),
            to_s(&carol_group_state),
            "--commit-out".to_string(),
            to_s(&carol_recovery_commit),
            "--path-update-out".to_string(),
            to_s(&carol_recovery_path),
            "--sender-leaf".to_string(),
            "2".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &carol_state,
        &[
            "submit-commit".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--commit-file".to_string(),
            to_s(&carol_recovery_commit),
            "--path-update-file".to_string(),
            to_s(&carol_recovery_path),
        ],
    );
    let alice_sync_2 = run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "fetch-and-apply-latest".to_string(),
            "--group-state".to_string(),
            to_s(&alice_group_state),
            "--limit".to_string(),
            "100".to_string(),
        ],
    );
    assert!(
        alice_sync_2.contains("applied_total=1"),
        "alice sync 2 output:\n{alice_sync_2}"
    );
    let bob_sync_2 = run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "fetch-and-apply-latest".to_string(),
            "--group-state".to_string(),
            to_s(&bob_group_state),
            "--limit".to_string(),
            "100".to_string(),
        ],
    );
    assert!(
        bob_sync_2.contains("applied_total=1"),
        "bob sync 2 output:\n{bob_sync_2}"
    );

    fs::copy(&carol_group_state, &carol_compromised_state).expect("copy carol compromised state");
    fs::copy(&carol_group_state, &carol_recovered_state).expect("copy carol recovered state");

    // Commit #3: A updates again. Compromised old C key should fail; recovered C key should pass.
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "create-update-proposal".to_string(),
            "--group-state".to_string(),
            to_s(&alice_group_state),
            "--keypackage-file".to_string(),
            to_s(&alice_v2_kp),
            "--out".to_string(),
            to_s(&alice_update_proposal),
            "--sender-leaf".to_string(),
            "0".to_string(),
            "--target-leaf".to_string(),
            "0".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "submit-proposal".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--proposal-file".to_string(),
            to_s(&alice_update_proposal),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "create-commit".to_string(),
            "--group-state".to_string(),
            to_s(&alice_group_state),
            "--commit-out".to_string(),
            to_s(&alice_update_commit),
            "--path-update-out".to_string(),
            to_s(&alice_update_path),
            "--sender-leaf".to_string(),
            "0".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "submit-commit".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--commit-file".to_string(),
            to_s(&alice_update_commit),
            "--path-update-file".to_string(),
            to_s(&alice_update_path),
        ],
    );

    let compromised_sync = run_ds_client_expect_fail(
        client_bin,
        &base_url,
        &carol_state,
        &[
            "fetch-and-apply-latest".to_string(),
            "--group-state".to_string(),
            to_s(&carol_compromised_state),
            "--receiver-private-file".to_string(),
            to_s(&carol_recv),
            "--limit".to_string(),
            "100".to_string(),
        ],
        "failed to apply commit+path update during sync",
    );
    assert!(
        compromised_sync.contains("failed to apply commit+path update during sync"),
        "compromised C sync output:\n{compromised_sync}"
    );

    let recovered_sync = run_ds_client(
        client_bin,
        &base_url,
        &carol_state,
        &[
            "fetch-and-apply-latest".to_string(),
            "--group-state".to_string(),
            to_s(&carol_recovered_state),
            "--receiver-private-file".to_string(),
            to_s(&carol_v2_recv),
            "--limit".to_string(),
            "100".to_string(),
        ],
    );
    assert!(
        recovered_sync.contains("applied_total=1"),
        "recovered C sync output:\n{recovered_sync}"
    );

    let alice_loaded = ClientGroupState::load_from_file(&alice_group_state).expect("load alice");
    let bob_loaded = ClientGroupState::load_from_file(&bob_group_state).expect("load bob");
    let compromised_loaded =
        ClientGroupState::load_from_file(&carol_compromised_state).expect("load C compromised");
    let recovered_loaded =
        ClientGroupState::load_from_file(&carol_recovered_state).expect("load C recovered");

    assert_eq!(alice_loaded.epoch, 3);
    assert_eq!(bob_loaded.epoch, 2);
    assert_eq!(compromised_loaded.epoch, 2);
    assert_eq!(compromised_loaded.last_applied_commit_id, None);
    assert_eq!(recovered_loaded.epoch, 3);
    assert_eq!(recovered_loaded.ratchet_tree, alice_loaded.ratchet_tree);

    let _ = shutdown_tx.send(());
    let result = server.await.expect("join server");
    if let Err(err) = result {
        panic!("server returned error: {err}");
    }

    let _ = fs::remove_dir_all(base);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn misuse_bad_signature_is_rejected_by_ds_endpoints() {
    let (state, base) = temp_state("misuse-bad-signature");
    let (addr, shutdown_tx, server) = start_test_server(state).await;
    let base_url = format!("http://{addr}");
    let client_bin = env!("CARGO_BIN_EXE_ds_client");

    let work = base.join("work");
    let _ = fs::create_dir_all(&work);

    let alice_state = work.join("alice.json");
    let alice_bad_state = work.join("alice-bad.json");
    let alice_kem = work.join("alice-kem.json");
    let alice_kp = work.join("alice.kp");
    let alice_recv = work.join("alice.recv.json");
    let alice_group_state = work.join("alice-group.bin");
    let proposal_file = work.join("alice-update.proposal.bin");
    let commit_file = work.join("alice-update.commit.bin");
    let path_file = work.join("alice-update.path.bin");
    let group_id = "group-misuse-bad-signature";

    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "register".to_string(),
            "--username".to_string(),
            "alice".to_string(),
            "--password".to_string(),
            "secret".to_string(),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "keygen".to_string(),
            "--out".to_string(),
            to_s(&alice_kem),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "keypackage-export".to_string(),
            "--kem-file".to_string(),
            to_s(&alice_kem),
            "--keypackage-out".to_string(),
            to_s(&alice_kp),
            "--receiver-private-out".to_string(),
            to_s(&alice_recv),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "bootstrap-group-state".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--member-keypackage".to_string(),
            to_s(&alice_kp),
            "--own-leaf".to_string(),
            "0".to_string(),
            "--out".to_string(),
            to_s(&alice_group_state),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "create-update-proposal".to_string(),
            "--group-state".to_string(),
            to_s(&alice_group_state),
            "--keypackage-file".to_string(),
            to_s(&alice_kp),
            "--out".to_string(),
            to_s(&proposal_file),
            "--sender-leaf".to_string(),
            "0".to_string(),
            "--target-leaf".to_string(),
            "0".to_string(),
        ],
    );

    corrupt_classic_secret_key_in_state(&alice_state, &alice_bad_state);
    let bad_submit = run_ds_client_expect_fail(
        client_bin,
        &base_url,
        &alice_bad_state,
        &[
            "submit-proposal".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--proposal-file".to_string(),
            to_s(&proposal_file),
        ],
        "invalid_signature",
    );
    assert!(
        bad_submit.contains("401 Unauthorized"),
        "bad signature submit output:\n{bad_submit}"
    );
    assert!(
        bad_submit.contains("invalid_signature"),
        "bad signature submit output:\n{bad_submit}"
    );

    // Keep one valid proposal on DS to satisfy commit policy and to have list/fetch targets.
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "submit-proposal".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--proposal-file".to_string(),
            to_s(&proposal_file),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "create-commit".to_string(),
            "--group-state".to_string(),
            to_s(&alice_group_state),
            "--commit-out".to_string(),
            to_s(&commit_file),
            "--path-update-out".to_string(),
            to_s(&path_file),
            "--sender-leaf".to_string(),
            "0".to_string(),
        ],
    );

    let bad_submit_commit = run_ds_client_expect_fail(
        client_bin,
        &base_url,
        &alice_bad_state,
        &[
            "submit-commit".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--commit-file".to_string(),
            to_s(&commit_file),
            "--path-update-file".to_string(),
            to_s(&path_file),
        ],
        "invalid_signature",
    );
    assert!(
        bad_submit_commit.contains("401 Unauthorized"),
        "bad signature submit-commit output:\n{bad_submit_commit}"
    );
    assert!(
        bad_submit_commit.contains("invalid_signature"),
        "bad signature submit-commit output:\n{bad_submit_commit}"
    );

    let bad_list = run_ds_client_expect_fail(
        client_bin,
        &base_url,
        &alice_bad_state,
        &[
            "list-messages".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--limit".to_string(),
            "10".to_string(),
            "--kind".to_string(),
            "any".to_string(),
        ],
        "invalid_signature",
    );
    assert!(
        bad_list.contains("401 Unauthorized"),
        "bad signature list-messages output:\n{bad_list}"
    );
    assert!(
        bad_list.contains("invalid_signature"),
        "bad signature list-messages output:\n{bad_list}"
    );

    // Use a valid list to get a real message id, then fetch that id with a bad signature.
    let good_list = run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "list-messages".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--limit".to_string(),
            "10".to_string(),
            "--kind".to_string(),
            "any".to_string(),
        ],
    );
    let list_json = parse_json_from_ds_client_output(&good_list);
    let message_id = list_json["messages"]
        .as_array()
        .and_then(|items| items.first())
        .and_then(|item| item.get("id"))
        .and_then(|id| id.as_str())
        .expect("message id from valid list")
        .to_string();

    let bad_state_json: Value =
        serde_json::from_slice(&fs::read(&alice_bad_state).expect("read bad state"))
            .expect("parse bad state json");
    let bad_session_id = bad_state_json["session_id"]
        .as_str()
        .expect("session_id in bad state");
    let query = serde_urlencoded::to_string([
        ("username", "alice"),
        ("session_id", bad_session_id),
        ("signature", "AAAA"),
    ])
    .expect("encode bad fetch query");
    let fetch_url = format!(
        "{}/v1/groups/{}/messages/{}?{}",
        base_url, group_id, message_id, query
    );
    let fetch_resp = reqwest::Client::new()
        .get(&fetch_url)
        .send()
        .await
        .expect("fetch group message request");
    let status = fetch_resp.status();
    let body = fetch_resp.text().await.expect("fetch response body");
    assert_eq!(status, reqwest::StatusCode::UNAUTHORIZED);
    assert!(
        body.contains("invalid_signature"),
        "bad signature fetch-group-message body:\n{body}"
    );

    let _ = shutdown_tx.send(());
    let result = server.await.expect("join server");
    if let Err(err) = result {
        panic!("server returned error: {err}");
    }
    let _ = fs::remove_dir_all(base);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn misuse_malformed_commit_with_valid_metadata_is_skipped_without_blocking_valid_commit() {
    let (state, base) = temp_state("misuse-malformed-commit-valid-metadata");
    let (addr, shutdown_tx, server) = start_test_server(state).await;
    let base_url = format!("http://{addr}");
    let client_bin = env!("CARGO_BIN_EXE_ds_client");

    let work = base.join("work");
    let _ = fs::create_dir_all(&work);

    let alice_state = work.join("alice.json");
    let alice_kem = work.join("alice-kem.json");
    let alice_kp = work.join("alice.kp");
    let alice_recv = work.join("alice.recv.json");
    let sender_group_state = work.join("alice-sender-group.bin");
    let receiver_group_state = work.join("alice-receiver-group.bin");
    let proposal_file = work.join("alice-update.proposal.bin");
    let malformed_commit_file = work.join("malformed-metadata.commit.bin");
    let valid_commit_file = work.join("valid.commit.bin");
    let valid_path_file = work.join("valid.path.bin");
    let group_id = "group-misuse-malformed-commit-metadata";

    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "register".to_string(),
            "--username".to_string(),
            "alice".to_string(),
            "--password".to_string(),
            "secret".to_string(),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "keygen".to_string(),
            "--out".to_string(),
            to_s(&alice_kem),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "keypackage-export".to_string(),
            "--kem-file".to_string(),
            to_s(&alice_kem),
            "--keypackage-out".to_string(),
            to_s(&alice_kp),
            "--receiver-private-out".to_string(),
            to_s(&alice_recv),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "bootstrap-group-state".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--member-keypackage".to_string(),
            to_s(&alice_kp),
            "--own-leaf".to_string(),
            "0".to_string(),
            "--out".to_string(),
            to_s(&sender_group_state),
            "--force".to_string(),
        ],
    );
    fs::copy(&sender_group_state, &receiver_group_state).expect("copy receiver state");

    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "create-update-proposal".to_string(),
            "--group-state".to_string(),
            to_s(&sender_group_state),
            "--keypackage-file".to_string(),
            to_s(&alice_kp),
            "--out".to_string(),
            to_s(&proposal_file),
            "--sender-leaf".to_string(),
            "0".to_string(),
            "--target-leaf".to_string(),
            "0".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "submit-proposal".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--proposal-file".to_string(),
            to_s(&proposal_file),
        ],
    );

    let malformed =
        encode_malformed_commit_envelope_with_metadata(group_id, 0, 0, &[0x13, 0x37, 0xAA, 0xBB]);
    fs::write(&malformed_commit_file, malformed).expect("write malformed commit");
    run_ds_client_expect_fail(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "submit-commit".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--commit-file".to_string(),
            to_s(&malformed_commit_file),
        ],
        "invalid_commit_payload",
    );

    // Re-submit the same valid proposal and submit a valid commit after malformed commit traffic.
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "submit-proposal".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--proposal-file".to_string(),
            to_s(&proposal_file),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "create-commit".to_string(),
            "--group-state".to_string(),
            to_s(&sender_group_state),
            "--commit-out".to_string(),
            to_s(&valid_commit_file),
            "--path-update-out".to_string(),
            to_s(&valid_path_file),
            "--sender-leaf".to_string(),
            "0".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "submit-commit".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--commit-file".to_string(),
            to_s(&valid_commit_file),
            "--path-update-file".to_string(),
            to_s(&valid_path_file),
        ],
    );

    let sync_output = run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "fetch-and-apply-latest".to_string(),
            "--group-state".to_string(),
            to_s(&receiver_group_state),
            "--limit".to_string(),
            "100".to_string(),
        ],
    );
    assert!(
        sync_output.contains("applied_total=1"),
        "sync output:\n{sync_output}"
    );
    assert!(
        sync_output.contains("skipped_total=0"),
        "sync output:\n{sync_output}"
    );

    let loaded = ClientGroupState::load_from_file(&receiver_group_state).expect("load receiver");
    assert_eq!(loaded.epoch, 1);

    let _ = shutdown_tx.send(());
    let result = server.await.expect("join server");
    if let Err(err) = result {
        panic!("server returned error: {err}");
    }
    let _ = fs::remove_dir_all(base);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn misuse_replay_permutation_duplicate_old_commit_is_skipped_while_new_epoch_applies() {
    let (mut state, base) = temp_state("misuse-replay-permutation");
    state.min_proposals_per_commit = 0;
    let (addr, shutdown_tx, server) = start_test_server(state).await;
    let base_url = format!("http://{addr}");
    let client_bin = env!("CARGO_BIN_EXE_ds_client");

    let work = base.join("work");
    let _ = fs::create_dir_all(&work);

    let alice_state = work.join("alice.json");
    let alice_kem = work.join("alice-kem.json");
    let alice_kp = work.join("alice.kp");
    let alice_recv = work.join("alice.recv.json");
    let sender_group_state = work.join("alice-sender-group.bin");
    let receiver_group_state = work.join("alice-receiver-group.bin");
    let proposal_1 = work.join("commit1.proposal.bin");
    let commit_1 = work.join("commit1.bin");
    let path_1 = work.join("commit1.path.bin");
    let proposal_2 = work.join("commit2.proposal.bin");
    let commit_2 = work.join("commit2.bin");
    let path_2 = work.join("commit2.path.bin");
    let group_id = "group-misuse-replay-permutation";

    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "register".to_string(),
            "--username".to_string(),
            "alice".to_string(),
            "--password".to_string(),
            "secret".to_string(),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "keygen".to_string(),
            "--out".to_string(),
            to_s(&alice_kem),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "keypackage-export".to_string(),
            "--kem-file".to_string(),
            to_s(&alice_kem),
            "--keypackage-out".to_string(),
            to_s(&alice_kp),
            "--receiver-private-out".to_string(),
            to_s(&alice_recv),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "bootstrap-group-state".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--member-keypackage".to_string(),
            to_s(&alice_kp),
            "--own-leaf".to_string(),
            "0".to_string(),
            "--out".to_string(),
            to_s(&sender_group_state),
            "--force".to_string(),
        ],
    );
    fs::copy(&sender_group_state, &receiver_group_state).expect("copy receiver state");

    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "create-update-proposal".to_string(),
            "--group-state".to_string(),
            to_s(&sender_group_state),
            "--keypackage-file".to_string(),
            to_s(&alice_kp),
            "--out".to_string(),
            to_s(&proposal_1),
            "--sender-leaf".to_string(),
            "0".to_string(),
            "--target-leaf".to_string(),
            "0".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "create-commit".to_string(),
            "--group-state".to_string(),
            to_s(&sender_group_state),
            "--commit-out".to_string(),
            to_s(&commit_1),
            "--path-update-out".to_string(),
            to_s(&path_1),
            "--sender-leaf".to_string(),
            "0".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "submit-commit".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--commit-file".to_string(),
            to_s(&commit_1),
            "--path-update-file".to_string(),
            to_s(&path_1),
        ],
    );
    // Replay permutation attempt: strict DS policy now rejects duplicate-epoch commit submits.
    run_ds_client_expect_fail(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "submit-commit".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--commit-file".to_string(),
            to_s(&commit_1),
            "--path-update-file".to_string(),
            to_s(&path_1),
        ],
        "stale_or_duplicate_commit_epoch",
    );

    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "create-update-proposal".to_string(),
            "--group-state".to_string(),
            to_s(&sender_group_state),
            "--keypackage-file".to_string(),
            to_s(&alice_kp),
            "--out".to_string(),
            to_s(&proposal_2),
            "--sender-leaf".to_string(),
            "0".to_string(),
            "--target-leaf".to_string(),
            "0".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "create-commit".to_string(),
            "--group-state".to_string(),
            to_s(&sender_group_state),
            "--commit-out".to_string(),
            to_s(&commit_2),
            "--path-update-out".to_string(),
            to_s(&path_2),
            "--sender-leaf".to_string(),
            "0".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "submit-commit".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--commit-file".to_string(),
            to_s(&commit_2),
            "--path-update-file".to_string(),
            to_s(&path_2),
        ],
    );

    let sync_output = run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "fetch-and-apply-latest".to_string(),
            "--group-state".to_string(),
            to_s(&receiver_group_state),
            "--limit".to_string(),
            "100".to_string(),
        ],
    );
    assert!(
        sync_output.contains("applied_total=2"),
        "sync output:\n{sync_output}"
    );

    let loaded = ClientGroupState::load_from_file(&receiver_group_state).expect("load receiver");
    assert_eq!(loaded.epoch, 2);

    let _ = shutdown_tx.send(());
    let result = server.await.expect("join server");
    if let Err(err) = result {
        panic!("server returned error: {err}");
    }
    let _ = fs::remove_dir_all(base);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn misuse_tampered_group_state_epoch_mismatch_rejects_ds_sync() {
    let (state, base) = temp_state("misuse-tampered-state-epoch-mismatch");
    let (addr, shutdown_tx, server) = start_test_server(state).await;
    let base_url = format!("http://{addr}");
    let client_bin = env!("CARGO_BIN_EXE_ds_client");

    let work = base.join("work");
    let _ = fs::create_dir_all(&work);

    let alice_state = work.join("alice.json");
    let alice_kem = work.join("alice-kem.json");
    let alice_kp = work.join("alice.kp");
    let sender_group_state = work.join("alice-sender-group.bin");
    let receiver_group_state = work.join("alice-receiver-group.bin");
    let proposal_1 = work.join("commit1.proposal.bin");
    let commit_1 = work.join("commit1.bin");
    let path_1 = work.join("commit1.path.bin");
    let group_id = "group-misuse-tampered-state-epoch";

    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "register".to_string(),
            "--username".to_string(),
            "alice".to_string(),
            "--password".to_string(),
            "secret".to_string(),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "keygen".to_string(),
            "--out".to_string(),
            to_s(&alice_kem),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "keypackage-export".to_string(),
            "--kem-file".to_string(),
            to_s(&alice_kem),
            "--keypackage-out".to_string(),
            to_s(&alice_kp),
            "--receiver-private-out".to_string(),
            to_s(&work.join("alice.recv.json")),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "bootstrap-group-state".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--member-keypackage".to_string(),
            to_s(&alice_kp),
            "--own-leaf".to_string(),
            "0".to_string(),
            "--out".to_string(),
            to_s(&sender_group_state),
            "--force".to_string(),
        ],
    );
    fs::copy(&sender_group_state, &receiver_group_state).expect("copy receiver state");

    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "create-update-proposal".to_string(),
            "--group-state".to_string(),
            to_s(&sender_group_state),
            "--keypackage-file".to_string(),
            to_s(&alice_kp),
            "--out".to_string(),
            to_s(&proposal_1),
            "--sender-leaf".to_string(),
            "0".to_string(),
            "--target-leaf".to_string(),
            "0".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "submit-proposal".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--proposal-file".to_string(),
            to_s(&proposal_1),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "create-commit".to_string(),
            "--group-state".to_string(),
            to_s(&sender_group_state),
            "--commit-out".to_string(),
            to_s(&commit_1),
            "--path-update-out".to_string(),
            to_s(&path_1),
            "--sender-leaf".to_string(),
            "0".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "submit-commit".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--commit-file".to_string(),
            to_s(&commit_1),
            "--path-update-file".to_string(),
            to_s(&path_1),
        ],
    );

    tamper_group_state_key_schedule_epoch(&receiver_group_state, 1);
    run_ds_client_expect_fail(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "fetch-and-apply-latest".to_string(),
            "--group-state".to_string(),
            to_s(&receiver_group_state),
            "--limit".to_string(),
            "100".to_string(),
        ],
        "corrupt client state",
    );

    let _ = shutdown_tx.send(());
    let result = server.await.expect("join server");
    if let Err(err) = result {
        panic!("server returned error: {err}");
    }
    let _ = fs::remove_dir_all(base);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn misuse_tampered_group_state_parent_link_rejects_second_sync_transition() {
    let (state, base) = temp_state("misuse-tampered-state-parent-link");
    let (addr, shutdown_tx, server) = start_test_server(state).await;
    let base_url = format!("http://{addr}");
    let client_bin = env!("CARGO_BIN_EXE_ds_client");

    let work = base.join("work");
    let _ = fs::create_dir_all(&work);

    let alice_state = work.join("alice.json");
    let alice_kem = work.join("alice-kem.json");
    let alice_kp = work.join("alice.kp");
    let sender_group_state = work.join("alice-sender-group.bin");
    let receiver_group_state = work.join("alice-receiver-group.bin");
    let proposal_1 = work.join("commit1.proposal.bin");
    let commit_1 = work.join("commit1.bin");
    let path_1 = work.join("commit1.path.bin");
    let proposal_2 = work.join("commit2.proposal.bin");
    let commit_2 = work.join("commit2.bin");
    let path_2 = work.join("commit2.path.bin");
    let group_id = "group-misuse-tampered-state-parent-link";

    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "register".to_string(),
            "--username".to_string(),
            "alice".to_string(),
            "--password".to_string(),
            "secret".to_string(),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "keygen".to_string(),
            "--out".to_string(),
            to_s(&alice_kem),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "keypackage-export".to_string(),
            "--kem-file".to_string(),
            to_s(&alice_kem),
            "--keypackage-out".to_string(),
            to_s(&alice_kp),
            "--receiver-private-out".to_string(),
            to_s(&work.join("alice.recv.json")),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "bootstrap-group-state".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--member-keypackage".to_string(),
            to_s(&alice_kp),
            "--own-leaf".to_string(),
            "0".to_string(),
            "--out".to_string(),
            to_s(&sender_group_state),
            "--force".to_string(),
        ],
    );
    fs::copy(&sender_group_state, &receiver_group_state).expect("copy receiver state");

    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "create-update-proposal".to_string(),
            "--group-state".to_string(),
            to_s(&sender_group_state),
            "--keypackage-file".to_string(),
            to_s(&alice_kp),
            "--out".to_string(),
            to_s(&proposal_1),
            "--sender-leaf".to_string(),
            "0".to_string(),
            "--target-leaf".to_string(),
            "0".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "submit-proposal".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--proposal-file".to_string(),
            to_s(&proposal_1),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "create-commit".to_string(),
            "--group-state".to_string(),
            to_s(&sender_group_state),
            "--commit-out".to_string(),
            to_s(&commit_1),
            "--path-update-out".to_string(),
            to_s(&path_1),
            "--sender-leaf".to_string(),
            "0".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "submit-commit".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--commit-file".to_string(),
            to_s(&commit_1),
            "--path-update-file".to_string(),
            to_s(&path_1),
        ],
    );

    let sync_output_1 = run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "fetch-and-apply-latest".to_string(),
            "--group-state".to_string(),
            to_s(&receiver_group_state),
            "--limit".to_string(),
            "100".to_string(),
        ],
    );
    assert!(
        sync_output_1.contains("applied_total=1"),
        "sync output:\n{sync_output_1}"
    );

    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "create-update-proposal".to_string(),
            "--group-state".to_string(),
            to_s(&sender_group_state),
            "--keypackage-file".to_string(),
            to_s(&alice_kp),
            "--out".to_string(),
            to_s(&proposal_2),
            "--sender-leaf".to_string(),
            "0".to_string(),
            "--target-leaf".to_string(),
            "0".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "submit-proposal".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--proposal-file".to_string(),
            to_s(&proposal_2),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "create-commit".to_string(),
            "--group-state".to_string(),
            to_s(&sender_group_state),
            "--commit-out".to_string(),
            to_s(&commit_2),
            "--path-update-out".to_string(),
            to_s(&path_2),
            "--sender-leaf".to_string(),
            "0".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "submit-commit".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--commit-file".to_string(),
            to_s(&commit_2),
            "--path-update-file".to_string(),
            to_s(&path_2),
        ],
    );

    tamper_group_state_key_schedule_parent_link(&receiver_group_state);
    run_ds_client_expect_fail(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "fetch-and-apply-latest".to_string(),
            "--group-state".to_string(),
            to_s(&receiver_group_state),
            "--limit".to_string(),
            "100".to_string(),
        ],
        "corrupt client state",
    );

    let _ = shutdown_tx.send(());
    let result = server.await.expect("join server");
    if let Err(err) = result {
        panic!("server returned error: {err}");
    }
    let _ = fs::remove_dir_all(base);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mixed_update_and_psk_commit_applies_over_ds() {
    let (state, base) = temp_state("mixed-update-psk");
    let (addr, shutdown_tx, server) = start_test_server(state).await;
    let base_url = format!("http://{addr}");
    let client_bin = env!("CARGO_BIN_EXE_ds_client");
    let work = base.join("work");
    let _ = fs::create_dir_all(&work);

    let group_id = "group-mixed-update-psk";

    let alice_state = work.join("alice.json");
    let bob_state = work.join("bob.json");
    let alice_kem = work.join("alice-kem.json");
    let bob_kem = work.join("bob-kem.json");
    let alice_kp = work.join("alice.kp");
    let bob_kp = work.join("bob.kp");
    let alice_recv = work.join("alice.recv.json");
    let bob_recv = work.join("bob.recv.json");
    let alice_sender_group = work.join("alice-sender.group.bin");
    let bob_receiver_group = work.join("bob-receiver.group.bin");
    let alice_v2_kem = work.join("alice-v2-kem.json");
    let alice_v2_kp = work.join("alice-v2.kp");
    let alice_v2_recv = work.join("alice-v2.recv.json");
    let update_proposal = work.join("alice-update.proposal.bin");
    let commit_file = work.join("mixed-update-psk.commit.bin");
    let path_file = work.join("mixed-update-psk.path.bin");
    let psk_id = b"psk-mixed-update-001";

    register_and_export_keypackage(
        client_bin,
        &base_url,
        &alice_state,
        "alice",
        &alice_kem,
        &alice_kp,
        &alice_recv,
    );
    register_and_export_keypackage(
        client_bin, &base_url, &bob_state, "bob", &bob_kem, &bob_kp, &bob_recv,
    );

    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "bootstrap-group-state".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--member-keypackage".to_string(),
            to_s(&alice_kp),
            "--member-keypackage".to_string(),
            to_s(&bob_kp),
            "--own-leaf".to_string(),
            "0".to_string(),
            "--out".to_string(),
            to_s(&alice_sender_group),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "bootstrap-group-state".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--member-keypackage".to_string(),
            to_s(&alice_kp),
            "--member-keypackage".to_string(),
            to_s(&bob_kp),
            "--own-leaf".to_string(),
            "1".to_string(),
            "--out".to_string(),
            to_s(&bob_receiver_group),
            "--force".to_string(),
        ],
    );

    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "keygen".to_string(),
            "--out".to_string(),
            to_s(&alice_v2_kem),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "keypackage-export".to_string(),
            "--kem-file".to_string(),
            to_s(&alice_v2_kem),
            "--keypackage-out".to_string(),
            to_s(&alice_v2_kp),
            "--receiver-private-out".to_string(),
            to_s(&alice_v2_recv),
            "--force".to_string(),
        ],
    );

    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "create-update-proposal".to_string(),
            "--group-state".to_string(),
            to_s(&alice_sender_group),
            "--keypackage-file".to_string(),
            to_s(&alice_v2_kp),
            "--out".to_string(),
            to_s(&update_proposal),
            "--sender-leaf".to_string(),
            "0".to_string(),
            "--target-leaf".to_string(),
            "0".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "submit-proposal".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--proposal-file".to_string(),
            to_s(&update_proposal),
        ],
    );

    queue_psk_proposal(&alice_sender_group, psk_id);

    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "create-commit".to_string(),
            "--group-state".to_string(),
            to_s(&alice_sender_group),
            "--commit-out".to_string(),
            to_s(&commit_file),
            "--path-update-out".to_string(),
            to_s(&path_file),
            "--sender-leaf".to_string(),
            "0".to_string(),
        ],
    );

    let commit_env = CommitEnvelope::decode(&fs::read(&commit_file).expect("read commit envelope"))
        .expect("decode commit envelope");
    assert!(
        commit_env
            .commit
            .proposals
            .iter()
            .any(|p| matches!(p, Proposal::Update { leaf_index, .. } if *leaf_index == 0)),
        "mixed commit must include Update proposal"
    );
    assert!(
        commit_env
            .commit
            .proposals
            .iter()
            .any(|p| matches!(p, Proposal::PreSharedKey { psk_id: id } if id.as_slice() == psk_id)),
        "mixed commit must include PreSharedKey proposal"
    );

    let submit_output = run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "submit-commit".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--commit-file".to_string(),
            to_s(&commit_file),
            "--path-update-file".to_string(),
            to_s(&path_file),
        ],
    );
    let submit_json = parse_json_from_ds_client_output(&submit_output);
    let commit_id: i64 = submit_json["commit_id"]
        .as_str()
        .expect("commit_id str")
        .parse()
        .expect("commit_id i64");

    let sync_output = run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "fetch-and-apply-latest".to_string(),
            "--group-state".to_string(),
            to_s(&bob_receiver_group),
            "--receiver-private-file".to_string(),
            to_s(&bob_recv),
            "--limit".to_string(),
            "100".to_string(),
        ],
    );
    assert!(
        sync_output.contains("applied_total=1"),
        "sync output:\n{sync_output}"
    );

    let alice_after =
        ClientGroupState::load_from_file(&alice_sender_group).expect("load alice state");
    let bob_after = ClientGroupState::load_from_file(&bob_receiver_group).expect("load bob state");
    assert_eq!(alice_after.epoch, 1);
    assert_eq!(bob_after.epoch, 1);
    assert_eq!(bob_after.last_applied_commit_id, Some(commit_id));
    assert_eq!(alice_after.ratchet_tree, bob_after.ratchet_tree);

    let _ = shutdown_tx.send(());
    let result = server.await.expect("join server");
    if let Err(err) = result {
        panic!("server returned error: {err}");
    }
    let _ = fs::remove_dir_all(base);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mixed_remove_and_psk_commit_applies_over_ds() {
    let (state, base) = temp_state("mixed-remove-psk");
    let (addr, shutdown_tx, server) = start_test_server(state).await;
    let base_url = format!("http://{addr}");
    let client_bin = env!("CARGO_BIN_EXE_ds_client");
    let work = base.join("work");
    let _ = fs::create_dir_all(&work);

    let group_id = "group-mixed-remove-psk";

    let alice_state = work.join("alice.json");
    let bob_state = work.join("bob.json");
    let carol_state = work.join("carol.json");
    let alice_kem = work.join("alice-kem.json");
    let bob_kem = work.join("bob-kem.json");
    let carol_kem = work.join("carol-kem.json");
    let alice_kp = work.join("alice.kp");
    let bob_kp = work.join("bob.kp");
    let carol_kp = work.join("carol.kp");
    let alice_recv = work.join("alice.recv.json");
    let bob_recv = work.join("bob.recv.json");
    let carol_recv = work.join("carol.recv.json");
    let alice_sender_group = work.join("alice-sender.group.bin");
    let bob_receiver_group = work.join("bob-receiver.group.bin");
    let remove_proposal = work.join("remove-carol.proposal.bin");
    let commit_file = work.join("mixed-remove-psk.commit.bin");
    let path_file = work.join("mixed-remove-psk.path.bin");
    let psk_id = b"psk-mixed-remove-001";

    register_and_export_keypackage(
        client_bin,
        &base_url,
        &alice_state,
        "alice",
        &alice_kem,
        &alice_kp,
        &alice_recv,
    );
    register_and_export_keypackage(
        client_bin, &base_url, &bob_state, "bob", &bob_kem, &bob_kp, &bob_recv,
    );
    register_and_export_keypackage(
        client_bin,
        &base_url,
        &carol_state,
        "carol",
        &carol_kem,
        &carol_kp,
        &carol_recv,
    );

    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "bootstrap-group-state".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--member-keypackage".to_string(),
            to_s(&alice_kp),
            "--member-keypackage".to_string(),
            to_s(&bob_kp),
            "--member-keypackage".to_string(),
            to_s(&carol_kp),
            "--own-leaf".to_string(),
            "0".to_string(),
            "--out".to_string(),
            to_s(&alice_sender_group),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "bootstrap-group-state".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--member-keypackage".to_string(),
            to_s(&alice_kp),
            "--member-keypackage".to_string(),
            to_s(&bob_kp),
            "--member-keypackage".to_string(),
            to_s(&carol_kp),
            "--own-leaf".to_string(),
            "1".to_string(),
            "--out".to_string(),
            to_s(&bob_receiver_group),
            "--force".to_string(),
        ],
    );

    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "create-remove-proposal".to_string(),
            "--group-state".to_string(),
            to_s(&alice_sender_group),
            "--remove-leaf".to_string(),
            "2".to_string(),
            "--out".to_string(),
            to_s(&remove_proposal),
            "--sender-leaf".to_string(),
            "0".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "submit-proposal".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--proposal-file".to_string(),
            to_s(&remove_proposal),
        ],
    );

    queue_psk_proposal(&alice_sender_group, psk_id);

    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "create-commit".to_string(),
            "--group-state".to_string(),
            to_s(&alice_sender_group),
            "--commit-out".to_string(),
            to_s(&commit_file),
            "--path-update-out".to_string(),
            to_s(&path_file),
            "--sender-leaf".to_string(),
            "0".to_string(),
        ],
    );

    let commit_env = CommitEnvelope::decode(&fs::read(&commit_file).expect("read commit envelope"))
        .expect("decode commit envelope");
    assert!(
        commit_env
            .commit
            .proposals
            .iter()
            .any(|p| matches!(p, Proposal::Remove { leaf_index } if *leaf_index == 2)),
        "mixed commit must include Remove proposal"
    );
    assert!(
        commit_env
            .commit
            .proposals
            .iter()
            .any(|p| matches!(p, Proposal::PreSharedKey { psk_id: id } if id.as_slice() == psk_id)),
        "mixed commit must include PreSharedKey proposal"
    );

    let submit_output = run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "submit-commit".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--commit-file".to_string(),
            to_s(&commit_file),
            "--path-update-file".to_string(),
            to_s(&path_file),
        ],
    );
    let submit_json = parse_json_from_ds_client_output(&submit_output);
    let commit_id: i64 = submit_json["commit_id"]
        .as_str()
        .expect("commit_id str")
        .parse()
        .expect("commit_id i64");

    let sync_output = run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "fetch-and-apply-latest".to_string(),
            "--group-state".to_string(),
            to_s(&bob_receiver_group),
            "--receiver-private-file".to_string(),
            to_s(&bob_recv),
            "--limit".to_string(),
            "100".to_string(),
        ],
    );
    assert!(
        sync_output.contains("applied_total=1"),
        "sync output:\n{sync_output}"
    );

    let alice_after =
        ClientGroupState::load_from_file(&alice_sender_group).expect("load alice state");
    let bob_after = ClientGroupState::load_from_file(&bob_receiver_group).expect("load bob state");
    assert_eq!(alice_after.epoch, 1);
    assert_eq!(bob_after.epoch, 1);
    assert_eq!(bob_after.last_applied_commit_id, Some(commit_id));
    assert_eq!(alice_after.ratchet_tree, bob_after.ratchet_tree);

    let carol_node = RatchetTree::leaf_to_node_index(2);
    assert!(
        matches!(
            bob_after.ratchet_tree.nodes.get(carol_node),
            Some(Node::Blank)
        ),
        "carol leaf must be blank after remove proposal apply"
    );

    let _ = shutdown_tx.send(());
    let result = server.await.expect("join server");
    if let Err(err) = result {
        panic!("server returned error: {err}");
    }
    let _ = fs::remove_dir_all(base);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reinit_commit_roundtrip_applies_over_ds() {
    let (state, base) = temp_state("reinit-roundtrip");
    let (addr, shutdown_tx, server) = start_test_server(state).await;
    let base_url = format!("http://{addr}");
    let client_bin = env!("CARGO_BIN_EXE_ds_client");
    let work = base.join("work");
    let _ = fs::create_dir_all(&work);

    let group_id = "group-reinit-roundtrip";

    let alice_state = work.join("alice.json");
    let alice_kem = work.join("alice-kem.json");
    let alice_kp = work.join("alice.kp");
    let alice_recv = work.join("alice.recv.json");
    let sender_group_state = work.join("alice-sender.group.bin");
    let receiver_group_state = work.join("alice-receiver.group.bin");
    let commit_file = work.join("reinit.commit.bin");
    let path_file = work.join("reinit.path.bin");
    let reinit_proposal_file = work.join("reinit.proposal.bin");

    register_and_export_keypackage(
        client_bin,
        &base_url,
        &alice_state,
        "alice",
        &alice_kem,
        &alice_kp,
        &alice_recv,
    );

    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "bootstrap-group-state".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--member-keypackage".to_string(),
            to_s(&alice_kp),
            "--own-leaf".to_string(),
            "0".to_string(),
            "--out".to_string(),
            to_s(&sender_group_state),
            "--force".to_string(),
        ],
    );
    fs::copy(&sender_group_state, &receiver_group_state).expect("copy receiver group state");

    queue_reinit_proposal(
        &sender_group_state,
        "group-reinit-next",
        1,
        0x0001,
        b"hybrid-reinit-ext",
    );
    let reinit_envelope = ProposalEnvelope {
        group_id: group_id.to_string(),
        epoch: 0,
        sender_leaf: 0,
        proposal: Proposal::ReInit {
            group_id: "group-reinit-next".to_string(),
            version: 1,
            cipher_suite: 0x0001,
            extensions: b"hybrid-reinit-ext".to_vec(),
        },
    };
    fs::write(&reinit_proposal_file, reinit_envelope.encode()).expect("write reinit proposal");
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "submit-proposal".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--proposal-file".to_string(),
            to_s(&reinit_proposal_file),
        ],
    );

    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "create-commit".to_string(),
            "--group-state".to_string(),
            to_s(&sender_group_state),
            "--commit-out".to_string(),
            to_s(&commit_file),
            "--path-update-out".to_string(),
            to_s(&path_file),
            "--sender-leaf".to_string(),
            "0".to_string(),
        ],
    );

    let commit_env = CommitEnvelope::decode(&fs::read(&commit_file).expect("read commit envelope"))
        .expect("decode commit envelope");
    assert!(
        commit_env.commit.proposals.iter().any(|proposal| {
            matches!(
                proposal,
                Proposal::ReInit {
                    group_id,
                    version: 1,
                    cipher_suite: 0x0001,
                    ..
                } if group_id == "group-reinit-next"
            )
        }),
        "commit must contain ReInit proposal"
    );

    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "submit-commit".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--commit-file".to_string(),
            to_s(&commit_file),
            "--path-update-file".to_string(),
            to_s(&path_file),
        ],
    );

    let sync_output = run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "fetch-and-apply-latest".to_string(),
            "--group-state".to_string(),
            to_s(&receiver_group_state),
            "--limit".to_string(),
            "100".to_string(),
        ],
    );
    assert!(
        sync_output.contains("applied_total=1"),
        "sync output:\n{sync_output}"
    );

    let sender_after =
        ClientGroupState::load_from_file(&sender_group_state).expect("load sender state");
    let receiver_after =
        ClientGroupState::load_from_file(&receiver_group_state).expect("load receiver state");
    assert_eq!(sender_after.epoch, 1);
    assert_eq!(receiver_after.epoch, 1);
    assert_eq!(sender_after.ratchet_tree, receiver_after.ratchet_tree);

    let _ = shutdown_tx.send(());
    let result = server.await.expect("join server");
    if let Err(err) = result {
        panic!("server returned error: {err}");
    }
    let _ = fs::remove_dir_all(base);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mixed_update_and_group_context_extensions_commit_applies_over_ds() {
    let (state, base) = temp_state("mixed-update-gce");
    let (addr, shutdown_tx, server) = start_test_server(state).await;
    let base_url = format!("http://{addr}");
    let client_bin = env!("CARGO_BIN_EXE_ds_client");
    let work = base.join("work");
    let _ = fs::create_dir_all(&work);

    let group_id = "group-mixed-update-gce";
    let expected_extensions = b"gce-ext-v1";

    let alice_state = work.join("alice.json");
    let bob_state = work.join("bob.json");
    let alice_kem = work.join("alice-kem.json");
    let bob_kem = work.join("bob-kem.json");
    let alice_kp = work.join("alice.kp");
    let bob_kp = work.join("bob.kp");
    let alice_recv = work.join("alice.recv.json");
    let bob_recv = work.join("bob.recv.json");
    let alice_sender_group = work.join("alice-sender.group.bin");
    let bob_receiver_group = work.join("bob-receiver.group.bin");
    let alice_v2_kem = work.join("alice-v2-kem.json");
    let alice_v2_kp = work.join("alice-v2.kp");
    let alice_v2_recv = work.join("alice-v2.recv.json");
    let update_proposal = work.join("alice-update.proposal.bin");
    let commit_file = work.join("mixed-update-gce.commit.bin");
    let path_file = work.join("mixed-update-gce.path.bin");

    register_and_export_keypackage(
        client_bin,
        &base_url,
        &alice_state,
        "alice",
        &alice_kem,
        &alice_kp,
        &alice_recv,
    );
    register_and_export_keypackage(
        client_bin, &base_url, &bob_state, "bob", &bob_kem, &bob_kp, &bob_recv,
    );

    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "bootstrap-group-state".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--member-keypackage".to_string(),
            to_s(&alice_kp),
            "--member-keypackage".to_string(),
            to_s(&bob_kp),
            "--own-leaf".to_string(),
            "0".to_string(),
            "--out".to_string(),
            to_s(&alice_sender_group),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "bootstrap-group-state".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--member-keypackage".to_string(),
            to_s(&alice_kp),
            "--member-keypackage".to_string(),
            to_s(&bob_kp),
            "--own-leaf".to_string(),
            "1".to_string(),
            "--out".to_string(),
            to_s(&bob_receiver_group),
            "--force".to_string(),
        ],
    );

    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "keygen".to_string(),
            "--out".to_string(),
            to_s(&alice_v2_kem),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "keypackage-export".to_string(),
            "--kem-file".to_string(),
            to_s(&alice_v2_kem),
            "--keypackage-out".to_string(),
            to_s(&alice_v2_kp),
            "--receiver-private-out".to_string(),
            to_s(&alice_v2_recv),
            "--force".to_string(),
        ],
    );

    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "create-update-proposal".to_string(),
            "--group-state".to_string(),
            to_s(&alice_sender_group),
            "--keypackage-file".to_string(),
            to_s(&alice_v2_kp),
            "--out".to_string(),
            to_s(&update_proposal),
            "--sender-leaf".to_string(),
            "0".to_string(),
            "--target-leaf".to_string(),
            "0".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "submit-proposal".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--proposal-file".to_string(),
            to_s(&update_proposal),
        ],
    );

    queue_group_context_extensions_proposal(&alice_sender_group, expected_extensions);

    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "create-commit".to_string(),
            "--group-state".to_string(),
            to_s(&alice_sender_group),
            "--commit-out".to_string(),
            to_s(&commit_file),
            "--path-update-out".to_string(),
            to_s(&path_file),
            "--sender-leaf".to_string(),
            "0".to_string(),
        ],
    );

    let commit_env = CommitEnvelope::decode(&fs::read(&commit_file).expect("read commit envelope"))
        .expect("decode commit envelope");
    assert!(
        commit_env
            .commit
            .proposals
            .iter()
            .any(|p| matches!(p, Proposal::Update { leaf_index, .. } if *leaf_index == 0)),
        "mixed commit must include Update proposal"
    );
    assert!(
        commit_env
            .commit
            .proposals
            .iter()
            .any(|p| matches!(p, Proposal::GroupContextExtensions { extensions } if extensions.as_slice() == expected_extensions)),
        "mixed commit must include GroupContextExtensions proposal"
    );

    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "submit-commit".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--commit-file".to_string(),
            to_s(&commit_file),
            "--path-update-file".to_string(),
            to_s(&path_file),
        ],
    );

    let sync_output = run_ds_client(
        client_bin,
        &base_url,
        &bob_state,
        &[
            "fetch-and-apply-latest".to_string(),
            "--group-state".to_string(),
            to_s(&bob_receiver_group),
            "--receiver-private-file".to_string(),
            to_s(&bob_recv),
            "--limit".to_string(),
            "100".to_string(),
        ],
    );
    assert!(
        sync_output.contains("applied_total=1"),
        "sync output:\n{sync_output}"
    );

    let alice_after =
        ClientGroupState::load_from_file(&alice_sender_group).expect("load alice state");
    let bob_after = ClientGroupState::load_from_file(&bob_receiver_group).expect("load bob state");
    assert_eq!(alice_after.epoch, 1);
    assert_eq!(bob_after.epoch, 1);
    assert_eq!(alice_after.ratchet_tree, bob_after.ratchet_tree);
    assert_eq!(alice_after.group_context_extensions, expected_extensions);
    assert_eq!(bob_after.group_context_extensions, expected_extensions);

    let _ = shutdown_tx.send(());
    let result = server.await.expect("join server");
    if let Err(err) = result {
        panic!("server returned error: {err}");
    }
    let _ = fs::remove_dir_all(base);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ds_backed_duplicate_group_context_extensions_commit_rejected_on_sync() {
    let (state, base) = temp_state("dup-gce-reject");
    let (addr, shutdown_tx, server) = start_test_server(state).await;
    let base_url = format!("http://{addr}");
    let client_bin = env!("CARGO_BIN_EXE_ds_client");
    let work = base.join("work");
    let _ = fs::create_dir_all(&work);

    let group_id = "group-dup-gce-reject";
    let alice_state = work.join("alice.json");
    let alice_kem = work.join("alice-kem.json");
    let alice_kp = work.join("alice.kp");
    let alice_recv = work.join("alice.recv.json");
    let sender_group = work.join("alice-sender.group.bin");
    let receiver_group = work.join("alice-receiver.group.bin");
    let valid_update_proposal = work.join("valid-update.proposal.bin");
    let invalid_commit_file = work.join("invalid-dup-gce.commit.bin");

    register_and_export_keypackage(
        client_bin,
        &base_url,
        &alice_state,
        "alice",
        &alice_kem,
        &alice_kp,
        &alice_recv,
    );

    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "bootstrap-group-state".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--member-keypackage".to_string(),
            to_s(&alice_kp),
            "--own-leaf".to_string(),
            "0".to_string(),
            "--out".to_string(),
            to_s(&sender_group),
            "--force".to_string(),
        ],
    );
    fs::copy(&sender_group, &receiver_group).expect("copy receiver state");

    // Keep DS proposal queue non-empty so commit policy (min proposals) is satisfied.
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "create-update-proposal".to_string(),
            "--group-state".to_string(),
            to_s(&sender_group),
            "--keypackage-file".to_string(),
            to_s(&alice_kp),
            "--out".to_string(),
            to_s(&valid_update_proposal),
            "--sender-leaf".to_string(),
            "0".to_string(),
            "--target-leaf".to_string(),
            "0".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "submit-proposal".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--proposal-file".to_string(),
            to_s(&valid_update_proposal),
        ],
    );

    let invalid_commit = CommitEnvelope {
        group_id: group_id.to_string(),
        epoch: 0,
        sender_leaf: 0,
        commit: Commit {
            sender: 0,
            proposals: vec![
                Proposal::GroupContextExtensions {
                    extensions: b"ext-a".to_vec(),
                },
                Proposal::GroupContextExtensions {
                    extensions: b"ext-b".to_vec(),
                },
            ],
            path: Vec::new(),
        },
    };
    fs::write(&invalid_commit_file, invalid_commit.encode()).expect("write invalid commit");

    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "submit-commit".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--commit-file".to_string(),
            to_s(&invalid_commit_file),
        ],
    );

    run_ds_client_expect_fail(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "fetch-and-apply-latest".to_string(),
            "--group-state".to_string(),
            to_s(&receiver_group),
            "--limit".to_string(),
            "100".to_string(),
        ],
        "failed to apply commit during sync",
    );

    let receiver_after = ClientGroupState::load_from_file(&receiver_group).expect("load receiver");
    assert_eq!(receiver_after.epoch, 0);
    assert_eq!(receiver_after.last_applied_commit_id, None);

    let _ = shutdown_tx.send(());
    let result = server.await.expect("join server");
    if let Err(err) = result {
        panic!("server returned error: {err}");
    }
    let _ = fs::remove_dir_all(base);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ds_backed_reinit_and_group_context_extensions_conflict_rejected_on_sync() {
    let (state, base) = temp_state("reinit-gce-conflict-reject");
    let (addr, shutdown_tx, server) = start_test_server(state).await;
    let base_url = format!("http://{addr}");
    let client_bin = env!("CARGO_BIN_EXE_ds_client");
    let work = base.join("work");
    let _ = fs::create_dir_all(&work);

    let group_id = "group-reinit-gce-conflict-reject";
    let alice_state = work.join("alice.json");
    let alice_kem = work.join("alice-kem.json");
    let alice_kp = work.join("alice.kp");
    let alice_recv = work.join("alice.recv.json");
    let sender_group = work.join("alice-sender.group.bin");
    let receiver_group = work.join("alice-receiver.group.bin");
    let valid_update_proposal = work.join("valid-update.proposal.bin");
    let invalid_commit_file = work.join("invalid-reinit-gce-conflict.commit.bin");

    register_and_export_keypackage(
        client_bin,
        &base_url,
        &alice_state,
        "alice",
        &alice_kem,
        &alice_kp,
        &alice_recv,
    );

    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "bootstrap-group-state".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--member-keypackage".to_string(),
            to_s(&alice_kp),
            "--own-leaf".to_string(),
            "0".to_string(),
            "--out".to_string(),
            to_s(&sender_group),
            "--force".to_string(),
        ],
    );
    fs::copy(&sender_group, &receiver_group).expect("copy receiver state");

    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "create-update-proposal".to_string(),
            "--group-state".to_string(),
            to_s(&sender_group),
            "--keypackage-file".to_string(),
            to_s(&alice_kp),
            "--out".to_string(),
            to_s(&valid_update_proposal),
            "--sender-leaf".to_string(),
            "0".to_string(),
            "--target-leaf".to_string(),
            "0".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "submit-proposal".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--proposal-file".to_string(),
            to_s(&valid_update_proposal),
        ],
    );

    let invalid_commit = CommitEnvelope {
        group_id: group_id.to_string(),
        epoch: 0,
        sender_leaf: 0,
        commit: Commit {
            sender: 0,
            proposals: vec![
                Proposal::ReInit {
                    group_id: "group-v2".to_string(),
                    version: 1,
                    cipher_suite: 0x0001,
                    extensions: Vec::new(),
                },
                Proposal::GroupContextExtensions {
                    extensions: b"ext-v2".to_vec(),
                },
            ],
            path: Vec::new(),
        },
    };
    fs::write(&invalid_commit_file, invalid_commit.encode()).expect("write invalid commit");

    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "submit-commit".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--commit-file".to_string(),
            to_s(&invalid_commit_file),
        ],
    );

    run_ds_client_expect_fail(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "fetch-and-apply-latest".to_string(),
            "--group-state".to_string(),
            to_s(&receiver_group),
            "--limit".to_string(),
            "100".to_string(),
        ],
        "failed to apply commit during sync",
    );

    let receiver_after = ClientGroupState::load_from_file(&receiver_group).expect("load receiver");
    assert_eq!(receiver_after.epoch, 0);
    assert_eq!(receiver_after.last_applied_commit_id, None);

    let _ = shutdown_tx.send(());
    let result = server.await.expect("join server");
    if let Err(err) = result {
        panic!("server returned error: {err}");
    }
    let _ = fs::remove_dir_all(base);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ds_backed_duplicate_reinit_commit_rejected_on_sync() {
    let (state, base) = temp_state("dup-reinit-reject");
    let (addr, shutdown_tx, server) = start_test_server(state).await;
    let base_url = format!("http://{addr}");
    let client_bin = env!("CARGO_BIN_EXE_ds_client");
    let work = base.join("work");
    let _ = fs::create_dir_all(&work);

    let group_id = "group-dup-reinit-reject";
    let alice_state = work.join("alice.json");
    let alice_kem = work.join("alice-kem.json");
    let alice_kp = work.join("alice.kp");
    let alice_recv = work.join("alice.recv.json");
    let sender_group = work.join("alice-sender.group.bin");
    let receiver_group = work.join("alice-receiver.group.bin");
    let valid_update_proposal = work.join("valid-update.proposal.bin");
    let invalid_commit_file = work.join("invalid-dup-reinit.commit.bin");

    register_and_export_keypackage(
        client_bin,
        &base_url,
        &alice_state,
        "alice",
        &alice_kem,
        &alice_kp,
        &alice_recv,
    );

    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "bootstrap-group-state".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--member-keypackage".to_string(),
            to_s(&alice_kp),
            "--own-leaf".to_string(),
            "0".to_string(),
            "--out".to_string(),
            to_s(&sender_group),
            "--force".to_string(),
        ],
    );
    fs::copy(&sender_group, &receiver_group).expect("copy receiver state");

    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "create-update-proposal".to_string(),
            "--group-state".to_string(),
            to_s(&sender_group),
            "--keypackage-file".to_string(),
            to_s(&alice_kp),
            "--out".to_string(),
            to_s(&valid_update_proposal),
            "--sender-leaf".to_string(),
            "0".to_string(),
            "--target-leaf".to_string(),
            "0".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "submit-proposal".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--proposal-file".to_string(),
            to_s(&valid_update_proposal),
        ],
    );

    let invalid_commit = CommitEnvelope {
        group_id: group_id.to_string(),
        epoch: 0,
        sender_leaf: 0,
        commit: Commit {
            sender: 0,
            proposals: vec![
                Proposal::ReInit {
                    group_id: "group-v2-a".to_string(),
                    version: 1,
                    cipher_suite: 0x0001,
                    extensions: Vec::new(),
                },
                Proposal::ReInit {
                    group_id: "group-v2-b".to_string(),
                    version: 1,
                    cipher_suite: 0x0001,
                    extensions: Vec::new(),
                },
            ],
            path: Vec::new(),
        },
    };
    fs::write(&invalid_commit_file, invalid_commit.encode()).expect("write invalid commit");

    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "submit-commit".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--commit-file".to_string(),
            to_s(&invalid_commit_file),
        ],
    );

    run_ds_client_expect_fail(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "fetch-and-apply-latest".to_string(),
            "--group-state".to_string(),
            to_s(&receiver_group),
            "--limit".to_string(),
            "100".to_string(),
        ],
        "failed to apply commit during sync",
    );

    let receiver_after = ClientGroupState::load_from_file(&receiver_group).expect("load receiver");
    assert_eq!(receiver_after.epoch, 0);
    assert_eq!(receiver_after.last_applied_commit_id, None);

    let _ = shutdown_tx.send(());
    let result = server.await.expect("join server");
    if let Err(err) = result {
        panic!("server returned error: {err}");
    }
    let _ = fs::remove_dir_all(base);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ds_backed_unsupported_reinit_params_commit_rejected_on_sync() {
    let (state, base) = temp_state("unsupported-reinit-params-reject");
    let (addr, shutdown_tx, server) = start_test_server(state).await;
    let base_url = format!("http://{addr}");
    let client_bin = env!("CARGO_BIN_EXE_ds_client");
    let work = base.join("work");
    let _ = fs::create_dir_all(&work);

    let group_id_version = "group-unsupported-reinit-version-reject";
    let group_id_cipher_suite = "group-unsupported-reinit-ciphersuite-reject";
    let alice_state = work.join("alice.json");
    let alice_kem = work.join("alice-kem.json");
    let alice_kp = work.join("alice.kp");
    let alice_recv = work.join("alice.recv.json");
    let sender_group_version = work.join("alice-sender-version.group.bin");
    let receiver_group_version = work.join("alice-receiver-version.group.bin");
    let valid_update_proposal_version = work.join("valid-update-version.proposal.bin");
    let sender_group_cipher_suite = work.join("alice-sender-ciphersuite.group.bin");
    let receiver_group_cipher_suite = work.join("alice-receiver-ciphersuite.group.bin");
    let valid_update_proposal_cipher_suite = work.join("valid-update-ciphersuite.proposal.bin");
    let invalid_commit_v_file = work.join("invalid-reinit-version.commit.bin");
    let invalid_commit_cs_file = work.join("invalid-reinit-ciphersuite.commit.bin");

    register_and_export_keypackage(
        client_bin,
        &base_url,
        &alice_state,
        "alice",
        &alice_kem,
        &alice_kp,
        &alice_recv,
    );

    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "bootstrap-group-state".to_string(),
            "--group-id".to_string(),
            group_id_version.to_string(),
            "--member-keypackage".to_string(),
            to_s(&alice_kp),
            "--own-leaf".to_string(),
            "0".to_string(),
            "--out".to_string(),
            to_s(&sender_group_version),
            "--force".to_string(),
        ],
    );
    fs::copy(&sender_group_version, &receiver_group_version).expect("copy receiver state");

    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "create-update-proposal".to_string(),
            "--group-state".to_string(),
            to_s(&sender_group_version),
            "--keypackage-file".to_string(),
            to_s(&alice_kp),
            "--out".to_string(),
            to_s(&valid_update_proposal_version),
            "--sender-leaf".to_string(),
            "0".to_string(),
            "--target-leaf".to_string(),
            "0".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "submit-proposal".to_string(),
            "--group-id".to_string(),
            group_id_version.to_string(),
            "--proposal-file".to_string(),
            to_s(&valid_update_proposal_version),
        ],
    );

    let invalid_commit_version = CommitEnvelope {
        group_id: group_id_version.to_string(),
        epoch: 0,
        sender_leaf: 0,
        commit: Commit {
            sender: 0,
            proposals: vec![Proposal::ReInit {
                group_id: "group-v2".to_string(),
                version: 2,
                cipher_suite: 0x0001,
                extensions: Vec::new(),
            }],
            path: Vec::new(),
        },
    };
    fs::write(&invalid_commit_v_file, invalid_commit_version.encode())
        .expect("write invalid version commit");

    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "submit-commit".to_string(),
            "--group-id".to_string(),
            group_id_version.to_string(),
            "--commit-file".to_string(),
            to_s(&invalid_commit_v_file),
        ],
    );

    run_ds_client_expect_fail(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "fetch-and-apply-latest".to_string(),
            "--group-state".to_string(),
            to_s(&receiver_group_version),
            "--limit".to_string(),
            "100".to_string(),
        ],
        "failed to apply commit during sync",
    );

    let receiver_after_version = ClientGroupState::load_from_file(&receiver_group_version)
        .expect("load receiver after version");
    assert_eq!(receiver_after_version.epoch, 0);
    assert_eq!(receiver_after_version.last_applied_commit_id, None);

    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "bootstrap-group-state".to_string(),
            "--group-id".to_string(),
            group_id_cipher_suite.to_string(),
            "--member-keypackage".to_string(),
            to_s(&alice_kp),
            "--own-leaf".to_string(),
            "0".to_string(),
            "--out".to_string(),
            to_s(&sender_group_cipher_suite),
            "--force".to_string(),
        ],
    );
    fs::copy(&sender_group_cipher_suite, &receiver_group_cipher_suite)
        .expect("copy receiver state for ciphersuite case");
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "create-update-proposal".to_string(),
            "--group-state".to_string(),
            to_s(&sender_group_cipher_suite),
            "--keypackage-file".to_string(),
            to_s(&alice_kp),
            "--out".to_string(),
            to_s(&valid_update_proposal_cipher_suite),
            "--sender-leaf".to_string(),
            "0".to_string(),
            "--target-leaf".to_string(),
            "0".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "submit-proposal".to_string(),
            "--group-id".to_string(),
            group_id_cipher_suite.to_string(),
            "--proposal-file".to_string(),
            to_s(&valid_update_proposal_cipher_suite),
        ],
    );

    let invalid_commit_cipher_suite = CommitEnvelope {
        group_id: group_id_cipher_suite.to_string(),
        epoch: 0,
        sender_leaf: 0,
        commit: Commit {
            sender: 0,
            proposals: vec![Proposal::ReInit {
                group_id: "group-v2".to_string(),
                version: 1,
                cipher_suite: 0x9999,
                extensions: Vec::new(),
            }],
            path: Vec::new(),
        },
    };
    fs::write(
        &invalid_commit_cs_file,
        invalid_commit_cipher_suite.encode(),
    )
    .expect("write invalid ciphersuite commit");

    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "submit-commit".to_string(),
            "--group-id".to_string(),
            group_id_cipher_suite.to_string(),
            "--commit-file".to_string(),
            to_s(&invalid_commit_cs_file),
        ],
    );

    run_ds_client_expect_fail(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "fetch-and-apply-latest".to_string(),
            "--group-state".to_string(),
            to_s(&receiver_group_cipher_suite),
            "--limit".to_string(),
            "100".to_string(),
        ],
        "failed to apply commit during sync",
    );

    let receiver_after_cipher_suite =
        ClientGroupState::load_from_file(&receiver_group_cipher_suite)
            .expect("load receiver after ciphersuite");
    assert_eq!(receiver_after_cipher_suite.epoch, 0);
    assert_eq!(receiver_after_cipher_suite.last_applied_commit_id, None);

    let _ = shutdown_tx.send(());
    let result = server.await.expect("join server");
    if let Err(err) = result {
        panic!("server returned error: {err}");
    }
    let _ = fs::remove_dir_all(base);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn app_private_message_ds_roundtrip_with_group_state() {
    let (state, base) = temp_state("app-private-message-roundtrip");
    let (addr, shutdown_tx, server) = start_test_server(state).await;
    let base_url = format!("http://{addr}");
    let client_bin = env!("CARGO_BIN_EXE_ds_client");
    let work = base.join("work");
    let _ = fs::create_dir_all(&work);

    let group_id = "group-app-private";
    let alice_state = work.join("alice.json");
    let alice_kem = work.join("alice-kem.json");
    let alice_kp = work.join("alice.kp");
    let alice_recv = work.join("alice.recv.json");
    let alice_group = work.join("alice.group.bin");
    let plaintext_file = work.join("message.txt");
    let fetched_file = work.join("message.out");
    let plaintext = b"rfc-style private application payload over ds";
    fs::write(&plaintext_file, plaintext).expect("write plaintext file");

    register_and_export_keypackage(
        client_bin,
        &base_url,
        &alice_state,
        "alice",
        &alice_kem,
        &alice_kp,
        &alice_recv,
    );

    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "bootstrap-group-state".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--member-keypackage".to_string(),
            to_s(&alice_kp),
            "--own-leaf".to_string(),
            "0".to_string(),
            "--out".to_string(),
            to_s(&alice_group),
            "--force".to_string(),
        ],
    );

    let send_output = run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "send-app-message".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--group-state".to_string(),
            to_s(&alice_group),
            "--message-file".to_string(),
            to_s(&plaintext_file),
        ],
    );
    let send_json = parse_json_from_ds_client_output(&send_output);
    let message_id = send_json["message_id"]
        .as_str()
        .expect("message_id as str")
        .to_string();

    let fetch_output = run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "fetch-app-message".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--message-id".to_string(),
            message_id.clone(),
            "--group-state".to_string(),
            to_s(&alice_group),
            "--out".to_string(),
            to_s(&fetched_file),
        ],
    );
    let fetch_json = parse_json_from_ds_client_output(&fetch_output);
    let fetched_payload_b64 = fetch_json["message_bytes"]
        .as_str()
        .expect("fetch message bytes");
    let fetched_payload = STANDARD
        .decode(fetched_payload_b64)
        .expect("decode fetched payload");
    let fetched_plaintext = fs::read(&fetched_file).expect("read fetched plaintext");
    assert_eq!(fetched_plaintext, plaintext);

    let mls_message = MlsMessage::decode(&fetched_payload).expect("decode mls private message");
    match mls_message.body {
        MlsMessageBody::Private(private) => {
            assert_eq!(private.group_id, group_id);
            assert_eq!(private.epoch, 0);
            assert_eq!(private.content_type, ContentType::Application);
            assert!(!private.encrypted_sender_data.is_empty());
            assert!(!private.ciphertext.is_empty());
            assert_ne!(private.ciphertext, plaintext);
        }
        MlsMessageBody::Public(_) => panic!("expected private application message"),
    }

    let _ = shutdown_tx.send(());
    let result = server.await.expect("join server");
    if let Err(err) = result {
        panic!("server returned error: {err}");
    }
    let _ = fs::remove_dir_all(base);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ds_rejects_submit_proposal_with_group_id_mismatch() {
    let (state, base) = temp_state("proposal-group-mismatch");
    let (addr, shutdown_tx, server) = start_test_server(state).await;
    let base_url = format!("http://{addr}");
    let client_bin = env!("CARGO_BIN_EXE_ds_client");
    let work = base.join("work");
    let _ = fs::create_dir_all(&work);

    let group_a = "group-proposal-a";
    let group_b = "group-proposal-b";
    let alice_state = work.join("alice.json");
    let alice_kem = work.join("alice-kem.json");
    let alice_kp = work.join("alice.kp");
    let alice_recv = work.join("alice.recv.json");
    let alice_group = work.join("alice.group.bin");
    let update_proposal = work.join("update.proposal.bin");

    register_and_export_keypackage(
        client_bin,
        &base_url,
        &alice_state,
        "alice",
        &alice_kem,
        &alice_kp,
        &alice_recv,
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "bootstrap-group-state".to_string(),
            "--group-id".to_string(),
            group_a.to_string(),
            "--member-keypackage".to_string(),
            to_s(&alice_kp),
            "--own-leaf".to_string(),
            "0".to_string(),
            "--out".to_string(),
            to_s(&alice_group),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "create-update-proposal".to_string(),
            "--group-state".to_string(),
            to_s(&alice_group),
            "--keypackage-file".to_string(),
            to_s(&alice_kp),
            "--out".to_string(),
            to_s(&update_proposal),
            "--sender-leaf".to_string(),
            "0".to_string(),
            "--target-leaf".to_string(),
            "0".to_string(),
        ],
    );

    run_ds_client_expect_fail(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "submit-proposal".to_string(),
            "--group-id".to_string(),
            group_b.to_string(),
            "--proposal-file".to_string(),
            to_s(&update_proposal),
        ],
        "proposal_group_mismatch",
    );

    let _ = shutdown_tx.send(());
    let result = server.await.expect("join server");
    if let Err(err) = result {
        panic!("server returned error: {err}");
    }
    let _ = fs::remove_dir_all(base);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ds_rejects_submit_commit_missing_required_path_update() {
    let (state, base) = temp_state("missing-path-update");
    let (addr, shutdown_tx, server) = start_test_server(state).await;
    let base_url = format!("http://{addr}");
    let client_bin = env!("CARGO_BIN_EXE_ds_client");
    let work = base.join("work");
    let _ = fs::create_dir_all(&work);

    let group_id = "group-missing-path";
    let alice_state = work.join("alice.json");
    let alice_kem = work.join("alice-kem.json");
    let alice_kp = work.join("alice.kp");
    let alice_recv = work.join("alice.recv.json");
    let bob_state = work.join("bob.json");
    let bob_kem = work.join("bob-kem.json");
    let bob_kp = work.join("bob.kp");
    let bob_recv = work.join("bob.recv.json");
    let alice_group = work.join("alice.group.bin");
    let add_proposal = work.join("add.proposal.bin");
    let commit_file = work.join("commit.bin");
    let path_file = work.join("path.bin");

    register_and_export_keypackage(
        client_bin,
        &base_url,
        &alice_state,
        "alice",
        &alice_kem,
        &alice_kp,
        &alice_recv,
    );
    register_and_export_keypackage(
        client_bin, &base_url, &bob_state, "bob", &bob_kem, &bob_kp, &bob_recv,
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "bootstrap-group-state".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--member-keypackage".to_string(),
            to_s(&alice_kp),
            "--own-leaf".to_string(),
            "0".to_string(),
            "--out".to_string(),
            to_s(&alice_group),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "create-add-proposal".to_string(),
            "--group-state".to_string(),
            to_s(&alice_group),
            "--keypackage-file".to_string(),
            to_s(&bob_kp),
            "--out".to_string(),
            to_s(&add_proposal),
            "--sender-leaf".to_string(),
            "0".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "create-commit".to_string(),
            "--group-state".to_string(),
            to_s(&alice_group),
            "--commit-out".to_string(),
            to_s(&commit_file),
            "--path-update-out".to_string(),
            to_s(&path_file),
            "--sender-leaf".to_string(),
            "0".to_string(),
        ],
    );

    run_ds_client_expect_fail(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "submit-commit".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--commit-file".to_string(),
            to_s(&commit_file),
        ],
        "missing_path_update",
    );

    let _ = shutdown_tx.send(());
    let result = server.await.expect("join server");
    if let Err(err) = result {
        panic!("server returned error: {err}");
    }
    let _ = fs::remove_dir_all(base);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ds_rejects_stale_or_duplicate_commit_epoch_on_submit() {
    let (state, base) = temp_state("stale-duplicate-commit-epoch");
    let (addr, shutdown_tx, server) = start_test_server(state).await;
    let base_url = format!("http://{addr}");
    let client_bin = env!("CARGO_BIN_EXE_ds_client");
    let work = base.join("work");
    let _ = fs::create_dir_all(&work);

    let group_id = "group-stale-epoch";
    let alice_state = work.join("alice.json");
    let alice_kem = work.join("alice-kem.json");
    let alice_kp = work.join("alice.kp");
    let alice_recv = work.join("alice.recv.json");
    let alice_group = work.join("alice.group.bin");
    let update_proposal = work.join("update.proposal.bin");
    let commit_file = work.join("commit.bin");
    let path_file = work.join("path.bin");

    register_and_export_keypackage(
        client_bin,
        &base_url,
        &alice_state,
        "alice",
        &alice_kem,
        &alice_kp,
        &alice_recv,
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "bootstrap-group-state".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--member-keypackage".to_string(),
            to_s(&alice_kp),
            "--own-leaf".to_string(),
            "0".to_string(),
            "--out".to_string(),
            to_s(&alice_group),
            "--force".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "create-update-proposal".to_string(),
            "--group-state".to_string(),
            to_s(&alice_group),
            "--keypackage-file".to_string(),
            to_s(&alice_kp),
            "--out".to_string(),
            to_s(&update_proposal),
            "--sender-leaf".to_string(),
            "0".to_string(),
            "--target-leaf".to_string(),
            "0".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "submit-proposal".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--proposal-file".to_string(),
            to_s(&update_proposal),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "create-commit".to_string(),
            "--group-state".to_string(),
            to_s(&alice_group),
            "--commit-out".to_string(),
            to_s(&commit_file),
            "--path-update-out".to_string(),
            to_s(&path_file),
            "--sender-leaf".to_string(),
            "0".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "submit-commit".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--commit-file".to_string(),
            to_s(&commit_file),
            "--path-update-file".to_string(),
            to_s(&path_file),
        ],
    );

    run_ds_client_expect_fail(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "submit-commit".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--commit-file".to_string(),
            to_s(&commit_file),
            "--path-update-file".to_string(),
            to_s(&path_file),
        ],
        "stale_or_duplicate_commit_epoch",
    );

    let _ = shutdown_tx.send(());
    let result = server.await.expect("join server");
    if let Err(err) = result {
        panic!("server returned error: {err}");
    }
    let _ = fs::remove_dir_all(base);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn strict_receiver_policy_rejects_multimember_noop_commit_transition() {
    let (state, base) = temp_state("receiver-noop-commit-reject");
    let (addr, shutdown_tx, server) = start_test_server(state).await;
    let base_url = format!("http://{addr}");
    let client_bin = env!("CARGO_BIN_EXE_ds_client");
    let work = base.join("work");
    let _ = fs::create_dir_all(&work);

    let group_id = "group-noop-transition";
    let alice_state = work.join("alice.json");
    let alice_kem = work.join("alice-kem.json");
    let alice_kp = work.join("alice.kp");
    let alice_recv = work.join("alice.recv.json");
    let bob_state = work.join("bob.json");
    let bob_kem = work.join("bob-kem.json");
    let bob_kp = work.join("bob.kp");
    let bob_recv = work.join("bob.recv.json");
    let receiver_group = work.join("receiver.group.bin");
    let update_proposal = work.join("update.proposal.bin");
    let invalid_noop_commit_file = work.join("invalid-noop.commit.bin");

    register_and_export_keypackage(
        client_bin,
        &base_url,
        &alice_state,
        "alice",
        &alice_kem,
        &alice_kp,
        &alice_recv,
    );
    register_and_export_keypackage(
        client_bin, &base_url, &bob_state, "bob", &bob_kem, &bob_kp, &bob_recv,
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "bootstrap-group-state".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--member-keypackage".to_string(),
            to_s(&alice_kp),
            "--member-keypackage".to_string(),
            to_s(&bob_kp),
            "--own-leaf".to_string(),
            "0".to_string(),
            "--out".to_string(),
            to_s(&receiver_group),
            "--force".to_string(),
        ],
    );

    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "create-update-proposal".to_string(),
            "--group-state".to_string(),
            to_s(&receiver_group),
            "--keypackage-file".to_string(),
            to_s(&alice_kp),
            "--out".to_string(),
            to_s(&update_proposal),
            "--sender-leaf".to_string(),
            "0".to_string(),
            "--target-leaf".to_string(),
            "0".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "submit-proposal".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--proposal-file".to_string(),
            to_s(&update_proposal),
        ],
    );

    let invalid_noop = CommitEnvelope {
        group_id: group_id.to_string(),
        epoch: 0,
        sender_leaf: 0,
        commit: Commit {
            sender: 0,
            proposals: Vec::new(),
            path: Vec::new(),
        },
    };
    fs::write(&invalid_noop_commit_file, invalid_noop.encode()).expect("write invalid noop commit");

    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "submit-commit".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--commit-file".to_string(),
            to_s(&invalid_noop_commit_file),
        ],
    );

    run_ds_client_expect_fail(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "fetch-and-apply-latest".to_string(),
            "--group-state".to_string(),
            to_s(&receiver_group),
            "--limit".to_string(),
            "100".to_string(),
        ],
        "invalid commit state transition",
    );

    let receiver_after = ClientGroupState::load_from_file(&receiver_group).expect("load receiver");
    assert_eq!(receiver_after.epoch, 0);
    assert_eq!(receiver_after.last_applied_commit_id, None);

    let _ = shutdown_tx.send(());
    let result = server.await.expect("join server");
    if let Err(err) = result {
        panic!("server returned error: {err}");
    }
    let _ = fs::remove_dir_all(base);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn multi_add_commit_applies_and_grows_group_on_sync() {
    let (state, base) = temp_state("multi-add-commit-sync");
    let (addr, shutdown_tx, server) = start_test_server(state).await;
    let base_url = format!("http://{addr}");
    let client_bin = env!("CARGO_BIN_EXE_ds_client");
    let work = base.join("work");
    let _ = fs::create_dir_all(&work);

    let group_id = "group-multi-add";
    let alice_state = work.join("alice.json");
    let bob_state = work.join("bob.json");
    let carol_state = work.join("carol.json");
    let alice_kem = work.join("alice-kem.json");
    let bob_kem = work.join("bob-kem.json");
    let carol_kem = work.join("carol-kem.json");
    let alice_kp = work.join("alice.kp");
    let bob_kp = work.join("bob.kp");
    let carol_kp = work.join("carol.kp");
    let alice_recv = work.join("alice.recv.json");
    let bob_recv = work.join("bob.recv.json");
    let carol_recv = work.join("carol.recv.json");
    let alice_sender_group = work.join("alice-sender.group.bin");
    let alice_receiver_group = work.join("alice-receiver.group.bin");
    let add_bob = work.join("add-bob.proposal.bin");
    let add_carol = work.join("add-carol.proposal.bin");
    let commit_file = work.join("multi-add.commit.bin");
    let path_file = work.join("multi-add.path.bin");

    register_and_export_keypackage(
        client_bin,
        &base_url,
        &alice_state,
        "alice",
        &alice_kem,
        &alice_kp,
        &alice_recv,
    );
    register_and_export_keypackage(
        client_bin, &base_url, &bob_state, "bob", &bob_kem, &bob_kp, &bob_recv,
    );
    register_and_export_keypackage(
        client_bin,
        &base_url,
        &carol_state,
        "carol",
        &carol_kem,
        &carol_kp,
        &carol_recv,
    );

    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "bootstrap-group-state".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--member-keypackage".to_string(),
            to_s(&alice_kp),
            "--own-leaf".to_string(),
            "0".to_string(),
            "--out".to_string(),
            to_s(&alice_sender_group),
            "--force".to_string(),
        ],
    );
    fs::copy(&alice_sender_group, &alice_receiver_group).expect("copy receiver baseline");

    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "create-add-proposal".to_string(),
            "--group-state".to_string(),
            to_s(&alice_sender_group),
            "--keypackage-file".to_string(),
            to_s(&bob_kp),
            "--out".to_string(),
            to_s(&add_bob),
            "--sender-leaf".to_string(),
            "0".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "submit-proposal".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--proposal-file".to_string(),
            to_s(&add_bob),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "create-add-proposal".to_string(),
            "--group-state".to_string(),
            to_s(&alice_sender_group),
            "--keypackage-file".to_string(),
            to_s(&carol_kp),
            "--out".to_string(),
            to_s(&add_carol),
            "--sender-leaf".to_string(),
            "0".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "submit-proposal".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--proposal-file".to_string(),
            to_s(&add_carol),
        ],
    );

    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "create-commit".to_string(),
            "--group-state".to_string(),
            to_s(&alice_sender_group),
            "--commit-out".to_string(),
            to_s(&commit_file),
            "--path-update-out".to_string(),
            to_s(&path_file),
            "--sender-leaf".to_string(),
            "0".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "submit-commit".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--commit-file".to_string(),
            to_s(&commit_file),
            "--path-update-file".to_string(),
            to_s(&path_file),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "fetch-and-apply-latest".to_string(),
            "--group-state".to_string(),
            to_s(&alice_receiver_group),
            "--limit".to_string(),
            "100".to_string(),
        ],
    );

    let receiver_after = ClientGroupState::load_from_file(&alice_receiver_group)
        .expect("load receiver after multi-add");
    assert_eq!(receiver_after.epoch, 1);
    assert_eq!(receiver_after.ratchet_tree.leaf_count(), 3);
    let leaf1 = RatchetTree::leaf_to_node_index(1);
    let leaf2 = RatchetTree::leaf_to_node_index(2);
    assert!(matches!(
        receiver_after.ratchet_tree.nodes.get(leaf1),
        Some(Node::Leaf(_))
    ));
    assert!(matches!(
        receiver_after.ratchet_tree.nodes.get(leaf2),
        Some(Node::Leaf(_))
    ));

    let _ = shutdown_tx.send(());
    let result = server.await.expect("join server");
    if let Err(err) = result {
        panic!("server returned error: {err}");
    }
    let _ = fs::remove_dir_all(base);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn duplicate_add_target_commit_is_rejected_on_sync() {
    let (state, base) = temp_state("duplicate-add-target-reject");
    let (addr, shutdown_tx, server) = start_test_server(state).await;
    let base_url = format!("http://{addr}");
    let client_bin = env!("CARGO_BIN_EXE_ds_client");
    let work = base.join("work");
    let _ = fs::create_dir_all(&work);

    let group_id = "group-dup-add-target";
    let alice_state = work.join("alice.json");
    let bob_state = work.join("bob.json");
    let alice_kem = work.join("alice-kem.json");
    let bob_kem = work.join("bob-kem.json");
    let alice_kp = work.join("alice.kp");
    let bob_kp = work.join("bob.kp");
    let alice_recv = work.join("alice.recv.json");
    let bob_recv = work.join("bob.recv.json");
    let sender_group = work.join("sender.group.bin");
    let receiver_group = work.join("receiver.group.bin");
    let valid_update = work.join("valid-update.proposal.bin");
    let invalid_commit = work.join("invalid-duplicate-add.commit.bin");

    register_and_export_keypackage(
        client_bin,
        &base_url,
        &alice_state,
        "alice",
        &alice_kem,
        &alice_kp,
        &alice_recv,
    );
    register_and_export_keypackage(
        client_bin, &base_url, &bob_state, "bob", &bob_kem, &bob_kp, &bob_recv,
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "bootstrap-group-state".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--member-keypackage".to_string(),
            to_s(&alice_kp),
            "--own-leaf".to_string(),
            "0".to_string(),
            "--out".to_string(),
            to_s(&sender_group),
            "--force".to_string(),
        ],
    );
    fs::copy(&sender_group, &receiver_group).expect("copy receiver baseline");

    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "create-update-proposal".to_string(),
            "--group-state".to_string(),
            to_s(&sender_group),
            "--keypackage-file".to_string(),
            to_s(&alice_kp),
            "--out".to_string(),
            to_s(&valid_update),
            "--sender-leaf".to_string(),
            "0".to_string(),
            "--target-leaf".to_string(),
            "0".to_string(),
        ],
    );
    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "submit-proposal".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--proposal-file".to_string(),
            to_s(&valid_update),
        ],
    );

    let invalid = CommitEnvelope {
        group_id: group_id.to_string(),
        epoch: 0,
        sender_leaf: 0,
        commit: Commit {
            sender: 0,
            proposals: vec![
                Proposal::Add(
                    KeyPackage::decode(&fs::read(&bob_kp).expect("read bob kp"))
                        .expect("decode bob kp"),
                ),
                Proposal::Add(
                    KeyPackage::decode(&fs::read(&bob_kp).expect("read bob kp again"))
                        .expect("decode bob kp again"),
                ),
            ],
            path: Vec::new(),
        },
    };
    fs::write(&invalid_commit, invalid.encode()).expect("write invalid commit");

    run_ds_client(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "submit-commit".to_string(),
            "--group-id".to_string(),
            group_id.to_string(),
            "--commit-file".to_string(),
            to_s(&invalid_commit),
        ],
    );

    run_ds_client_expect_fail(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "fetch-and-apply-latest".to_string(),
            "--group-state".to_string(),
            to_s(&receiver_group),
            "--limit".to_string(),
            "100".to_string(),
        ],
        "failed to apply commit during sync",
    );

    let receiver_after =
        ClientGroupState::load_from_file(&receiver_group).expect("load receiver after rejection");
    assert_eq!(receiver_after.epoch, 0);
    assert_eq!(receiver_after.last_applied_commit_id, None);

    let _ = shutdown_tx.send(());
    let result = server.await.expect("join server");
    if let Err(err) = result {
        panic!("server returned error: {err}");
    }
    let _ = fs::remove_dir_all(base);
}
