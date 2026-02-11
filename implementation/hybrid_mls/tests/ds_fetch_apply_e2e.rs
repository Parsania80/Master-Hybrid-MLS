use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use hybrid_mls::client_state::ClientGroupState;
use hybrid_mls::ds::config::StorageConfig;
use hybrid_mls::ds::http::{self, ApiState};
use hybrid_mls::envelope::PathUpdateEnvelope;
use hybrid_mls::tree::{Node, RatchetTree};
use serde_json::Value;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

fn run_ds_client(
    bin: &str,
    base_url: &str,
    state_path: &Path,
    args: &[String],
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

fn corrupt_classic_secret_key_in_state(
    original_state: &Path,
    corrupted_state: &Path,
) {
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

fn tamper_group_state_key_schedule_epoch(
    group_state_file: &Path,
    tampered_epoch: u64,
) {
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
        matches!(loaded_once.ratchet_tree.nodes.get(bob_leaf_node), Some(Node::Leaf(_))),
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
        ],
    );

    run_ds_client_expect_fail(
        client_bin,
        &base_url,
        &alice_state,
        &[
            "fetch-and-apply-latest".to_string(),
            "--group-state".to_string(),
            to_s(&alice_receiver_state),
            "--receiver-private-file".to_string(),
            to_s(&alice_recv),
            "--limit".to_string(),
            "100".to_string(),
        ],
        "strict receiver policy: missing or mismatched path_update",
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
            to_s(&alice_receiver_state),
            "--receiver-private-file".to_string(),
            to_s(&alice_recv),
            "--limit".to_string(),
            "100".to_string(),
        ],
        "strict receiver policy: missing or mismatched path_update",
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

    for (client_state, own_leaf) in [
        (&alice_state, "0"),
        (&bob_state, "1"),
        (&carol_state, "2"),
    ] {
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

    let alice_loaded = ClientGroupState::load_from_file(&alice_group_state).expect("load alice state");
    let bob_loaded = ClientGroupState::load_from_file(&bob_group_state).expect("load bob state");
    let carol_loaded = ClientGroupState::load_from_file(&carol_group_state).expect("load carol state");
    assert_eq!(alice_loaded.epoch, 2);
    assert_eq!(bob_loaded.epoch, 2);
    assert_eq!(carol_loaded.epoch, 2);
    assert_eq!(alice_loaded.ratchet_tree, bob_loaded.ratchet_tree);
    assert_eq!(bob_loaded.ratchet_tree, carol_loaded.ratchet_tree);

    // All leaves should still be populated in the converged 3-member tree.
    for leaf in 0..3usize {
        let node_idx = RatchetTree::leaf_to_node_index(leaf);
        assert!(
            matches!(alice_loaded.ratchet_tree.nodes.get(node_idx), Some(Node::Leaf(_))),
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
    run_ds_client(
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
        sync_output.contains("skipped_total=1"),
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
        "strict receiver policy: missing or mismatched path_update",
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
        !path_env.path_update.ciphertexts.is_empty() && !path_env.path_update.ciphertexts[0].is_empty(),
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
    run_ds_client(
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
    run_ds_client(
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

    let bob_old_after =
        ClientGroupState::load_from_file(&bob_old_receiver_state).expect("load bob old receiver state");
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
    let bob_new_after =
        ClientGroupState::load_from_file(&bob_new_receiver_state).expect("load bob new receiver state");
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
    let alice_loaded = ClientGroupState::load_from_file(&alice_group_state).expect("load alice state");

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

    let malformed = encode_malformed_commit_envelope_with_metadata(
        group_id,
        0,
        0,
        &[0x13, 0x37, 0xAA, 0xBB],
    );
    fs::write(&malformed_commit_file, malformed).expect("write malformed commit");
    run_ds_client(
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
        sync_output.contains("skipped_total=1"),
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
    // Replay permutation: re-submit an old commit as a new DS message id.
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
