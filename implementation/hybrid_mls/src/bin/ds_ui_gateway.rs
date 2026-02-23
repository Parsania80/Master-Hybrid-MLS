use std::collections::{HashMap, HashSet};
use std::convert::Infallible;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    extract::{Path as AxumPath, Query, State},
    http::{
        header::{COOKIE, SET_COOKIE},
        HeaderMap, HeaderValue,
    },
    response::{Html, IntoResponse, Redirect},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{
    SecretKey as EdSecretKey, SigningKey as EdSigningKey, VerifyingKey as EdPublic,
};
use ml_dsa::{EncodedSigningKey, EncodedVerifyingKey, KeyGen, MlDsa65};
use ml_kem::Seed;
use rand::rngs::OsRng;
use rand::RngCore;
use rand_core::{TryCryptoRng, TryRng};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use x25519_dalek::{PublicKey as X25519Pub, StaticSecret as X25519Priv};

use hybrid_mls::application_message::{
    protect_application_message_bytes, unprotect_application_message_bytes,
};
use hybrid_mls::authenticated_content::{
    commit_authenticated_content_hash, path_update_authenticated_content_hash,
    proposal_authenticated_content_hash,
};
use hybrid_mls::client_state::ClientGroupState;
use hybrid_mls::crypto::{
    decrypt_hpke_payload, encrypt_hpke_payload, HybridPrivateKey, HybridPublicKey,
    HybridSignPrivKey, HybridSignPubKey, KyberPriv,
};
use hybrid_mls::ds::admin::{derive_admin_key_material, ADMIN_PASSWORD, ADMIN_USERNAME};
use hybrid_mls::envelope::{CommitEnvelope, PathUpdateEnvelope, ProposalEnvelope};
use hybrid_mls::key_schedule::tree_snapshot_hash;
use hybrid_mls::transcript::{derive_confirmation_tag, verify_confirmation_tag};
use hybrid_mls::tree::{Commit, KeyPackage, LeafNode, Node, PathUpdate, Proposal, RatchetTree};
use hybrid_mls::welcome::{EncryptedGroupSecrets, GroupInfo, GroupSecrets, Welcome};

#[derive(Clone)]
struct UiState {
    base_url: String,
    state_dir: PathBuf,
    client: Client,
}

#[derive(Debug, Serialize, Deserialize)]
struct ClientState {
    username: String,
    classic_sk_b64: String,
    pq_sk_b64: String,
    classic_pk_b64: String,
    pq_pk_b64: String,
    session_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct GroupList {
    groups: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct AuthPayload {
    username: String,
    password: String,
}

#[derive(Debug, Deserialize)]
struct LogoutPayload {
    username: String,
}

#[derive(Debug, Deserialize)]
struct GroupOpenPayload {
    username: String,
    group_id: String,
}

#[derive(Debug, Deserialize)]
struct GroupRemovePayload {
    username: String,
    group_id: String,
}

#[derive(Debug, Deserialize)]
struct ActionAddPayload {
    username: String,
    target_username: Option<String>,
    keypackage_b64: String,
    submit: Option<bool>,
    sender_leaf: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct ActionRemovePayload {
    username: String,
    remove_leaf: usize,
    submit: Option<bool>,
    sender_leaf: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct ActionUpdatePayload {
    username: String,
    keypackage_b64: String,
    target_leaf: Option<usize>,
    submit: Option<bool>,
    sender_leaf: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct GroupMessagePayload {
    username: String,
    message: String,
}

#[derive(Debug, Deserialize)]
struct ProposalPayload {
    username: String,
    proposal_b64: String,
}

#[derive(Debug, Deserialize)]
struct CommitPayload {
    username: String,
    commit_b64: String,
    path_update_b64: Option<String>,
    welcome_b64: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CommitFromPendingPayload {
    username: String,
    sender_leaf: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct SyncApplyPayload {
    username: String,
    limit: Option<usize>,
    receiver_private_path: Option<String>,
}

#[derive(Debug, Deserialize)]
struct JoinFromLatestPayload {
    username: String,
    base_member_usernames: Option<Vec<String>>,
    limit: Option<usize>,
    receiver_private_path: Option<String>,
}

#[derive(Debug, Deserialize)]
struct KeyPackagePublishPayload {
    username: String,
    keypackage_b64: String,
}

#[derive(Debug, Deserialize)]
struct KeyPackageGeneratePayload {
    username: String,
}

#[derive(Debug, Deserialize)]
struct UserQuery {
    username: String,
}

#[derive(Debug, Deserialize)]
struct ListMessagesQuery {
    username: String,
    kind: Option<String>,
    limit: Option<usize>,
    before_id: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct ListAppMessagesQuery {
    username: String,
    limit: Option<usize>,
    before_id: Option<i64>,
}

#[derive(Debug, Serialize)]
struct ApiResult<T> {
    ok: bool,
    data: Option<T>,
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct KeyPackageGenerateResponse {
    published: bool,
    keypackage_b64: String,
    receiver_private_path: String,
}

#[derive(Debug, Serialize)]
struct GroupStateStatus {
    group_id: String,
    epoch: u64,
    own_leaf_index: usize,
    leaf_count: usize,
    pending_proposals: usize,
    state_path: String,
}

#[derive(Debug, Serialize)]
struct GroupBootstrapStatus {
    created: bool,
    state_path: String,
    leaf_count: usize,
    epoch: u64,
}

#[derive(Debug, Serialize)]
struct TreeNodeView {
    node_index: usize,
    node_type: String,
    leaf_index: Option<usize>,
    label: String,
    summary: String,
    x: Option<f32>,
    y: Option<f32>,
}

#[derive(Debug, Serialize)]
struct TreeEdgeView {
    from: usize,
    to: usize,
}

#[derive(Debug, Serialize)]
struct TreeView {
    group_id: String,
    epoch: u64,
    leaf_count: usize,
    own_leaf_index: usize,
    username: String,
    root_index: Option<usize>,
    edges: Vec<TreeEdgeView>,
    nodes: Vec<TreeNodeView>,
}

#[derive(Debug, Serialize)]
struct ActionProposalResponse {
    proposal_b64: String,
    submitted: bool,
    pending_proposals: usize,
    state_path: String,
}

#[derive(Debug, Serialize)]
struct CommitFromPendingResponse {
    commit_b64: String,
    path_update_b64: String,
    welcome_b64: Option<String>,
    submitted: bool,
    sender_leaf: usize,
    epoch: u64,
    pending_proposals: usize,
    state_path: String,
}

#[derive(Debug, Serialize)]
struct SyncApplyResponse {
    applied: usize,
    skipped: usize,
    local_epoch: u64,
    used_receiver_private: bool,
    receiver_private_path: Option<String>,
    state_path: String,
}

#[derive(Debug, Serialize)]
struct JoinFromLatestResponse {
    joined: bool,
    commit_id: i64,
    own_leaf_index: usize,
    local_epoch: u64,
    applied_after_join: usize,
    skipped_after_join: usize,
    receiver_private_path: String,
    state_path: String,
}

#[derive(Debug, Deserialize)]
struct DsMessageSummary {
    id: String,
}

#[derive(Debug, Deserialize)]
struct DsListMessagesResponse {
    messages: Vec<DsMessageSummary>,
}

#[derive(Debug, Deserialize)]
struct DsFetchGroupMessageResponse {
    id: String,
    kind: String,
    message_bytes: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct KeyPackageRecord {
    id: String,
    created_at: i64,
    keypackage_b64: String,
    receiver_private_path: String,
    published: bool,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
struct KeyPackageList {
    items: Vec<KeyPackageRecord>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ReceiverPrivateFile {
    classic_x25519_private_b64: String,
    pq_kem_seed_b64: String,
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct GroupMemberLabels {
    items: HashMap<String, String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct AdminDemoRecord {
    id: String,
    title: String,
    created_at: i64,
    updated_at: i64,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
struct AdminDemoIndex {
    items: Vec<AdminDemoRecord>,
}

#[derive(Debug, Deserialize)]
struct AdminDemoCreatePayload {
    username: String,
    title: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AdminDemoAddActionPayload {
    username: String,
    adder: String,
    added: String,
}

#[derive(Debug, Deserialize)]
struct AdminDemoRemoveActionPayload {
    username: String,
    remover: String,
    removed: String,
}

#[derive(Debug, Deserialize)]
struct AdminDemoUpdateActionPayload {
    username: String,
    updater: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct AdminDemoMember {
    username: String,
    leaf_index: usize,
    key_generation: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct AdminDemoLeafSlot {
    username: String,
    key_generation: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct AdminDemoLogEntry {
    timestamp: i64,
    line: String,
    separator: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct AdminDemoState {
    epoch: u64,
    leaf_slots: Vec<Option<AdminDemoLeafSlot>>,
    #[serde(default)]
    logs: Vec<AdminDemoLogEntry>,
    last_action: Option<String>,
}

#[derive(Debug, Deserialize)]
struct LegacyAdminDemoState {
    epoch: u64,
    #[serde(default)]
    members: Vec<AdminDemoMember>,
    #[serde(default)]
    logs: Vec<AdminDemoLogEntry>,
    last_action: Option<String>,
}

#[derive(Debug, Serialize)]
struct AdminDemoDetail {
    id: String,
    title: String,
    created_at: i64,
    updated_at: i64,
    root_dir: String,
    manifest_path: String,
    epoch: u64,
    leaf_count: usize,
    node_count: usize,
    members: Vec<AdminDemoMember>,
    logs: Vec<AdminDemoLogEntry>,
}

#[derive(Debug, Serialize)]
struct AdminDemoActionResponse {
    action: String,
    epoch: u64,
    members: Vec<AdminDemoMember>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let bind = std::env::var("DS_UI_BIND").unwrap_or_else(|_| "127.0.0.1:4000".to_string());
    let base_url = std::env::var("DS_GATEWAY_BASE_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:3000".to_string());
    let state_dir = std::env::var("DS_UI_STATE_DIR").unwrap_or_else(|_| "./ui-state".to_string());
    let state_dir = PathBuf::from(state_dir);
    fs::create_dir_all(&state_dir)?;

    let ui_state = UiState {
        base_url,
        state_dir,
        client: Client::new(),
    };

    let app = build_ui_router(ui_state);

    let addr: SocketAddr = bind.parse()?;
    println!("UI gateway listening on http://{addr}");
    axum::serve(tokio::net::TcpListener::bind(addr).await?, app).await?;
    Ok(())
}

fn build_ui_router(ui_state: UiState) -> Router {
    Router::new()
        .route("/", get(ui_index))
        .route("/ui", get(ui_index))
        .route("/ui/login", get(ui_login))
        .route("/ui/groups", get(ui_groups))
        .route("/ui/groups/:group_id", get(ui_group_detail))
        .route("/ui/admin", get(ui_admin))
        .route("/ui/admin/demos/:demo_id", get(ui_admin_demo))
        .route("/ui/api/register", post(api_register))
        .route("/ui/api/login", post(api_login))
        .route("/ui/api/logout", post(api_logout))
        .route("/ui/api/admin/users", get(api_admin_users))
        .route("/ui/api/admin/groups", get(api_admin_groups))
        .route(
            "/ui/api/admin/demos",
            get(api_admin_demos).post(api_admin_create_demo),
        )
        .route("/ui/api/admin/demos/:demo_id", get(api_admin_demo_detail))
        .route(
            "/ui/api/admin/demos/:demo_id/actions/add",
            post(api_admin_demo_action_add),
        )
        .route(
            "/ui/api/admin/demos/:demo_id/actions/remove",
            post(api_admin_demo_action_remove),
        )
        .route(
            "/ui/api/admin/demos/:demo_id/actions/update",
            post(api_admin_demo_action_update),
        )
        .route("/ui/api/groups", get(api_groups))
        .route("/ui/api/groups/open", post(api_groups_open))
        .route("/ui/api/groups/remove", post(api_groups_remove))
        .route("/ui/api/groups/:group_id/state", get(api_group_state))
        .route(
            "/ui/api/groups/:group_id/bootstrap",
            post(api_group_bootstrap),
        )
        .route("/ui/api/groups/:group_id/tree", get(api_group_tree))
        .route("/ui/api/groups/:group_id/messages", get(api_list_messages))
        .route(
            "/ui/api/groups/:group_id/messages/:message_id",
            get(api_fetch_message),
        )
        .route(
            "/ui/api/groups/:group_id/app-messages",
            get(api_list_app_messages).post(api_send_app_message),
        )
        .route(
            "/ui/api/groups/:group_id/app-messages/:message_id",
            get(api_fetch_app_message),
        )
        .route(
            "/ui/api/groups/:group_id/proposals",
            post(api_submit_proposal),
        )
        .route("/ui/api/groups/:group_id/commits", post(api_submit_commit))
        .route(
            "/ui/api/groups/:group_id/commit-from-pending",
            post(api_commit_from_pending),
        )
        .route(
            "/ui/api/groups/:group_id/sync-apply-latest",
            post(api_sync_apply_latest),
        )
        .route(
            "/ui/api/groups/:group_id/join-from-latest",
            post(api_join_from_latest),
        )
        .route("/ui/api/groups/:group_id/actions/add", post(api_action_add))
        .route(
            "/ui/api/groups/:group_id/actions/remove",
            post(api_action_remove),
        )
        .route(
            "/ui/api/groups/:group_id/actions/update",
            post(api_action_update),
        )
        .route(
            "/ui/api/keypackages/generate",
            post(api_generate_keypackage),
        )
        .route(
            "/ui/api/keypackages",
            get(api_list_keypackages).post(api_publish_keypackage),
        )
        .route("/ui/api/keypackages/:target", get(api_fetch_keypackage))
        .with_state(ui_state)
}

async fn ui_index() -> impl IntoResponse {
    Redirect::to("/ui/login")
}

fn ui_cookie_username(headers: &HeaderMap) -> Option<String> {
    let cookie_header = headers.get(COOKIE)?.to_str().ok()?;
    for part in cookie_header.split(';') {
        let mut kv = part.trim().splitn(2, '=');
        let key = kv.next()?.trim();
        let value = kv.next()?.trim();
        if key == "ui_username" {
            return Some(value.to_string());
        }
    }
    None
}

fn has_active_local_session(state: &UiState, username: &str) -> bool {
    load_state(state, username)
        .map(|client_state| client_state.session_id.is_some())
        .unwrap_or(false)
}

fn has_admin_ui_session(state: &UiState, headers: &HeaderMap) -> bool {
    let Some(username) = ui_cookie_username(headers) else {
        return false;
    };
    if username != ADMIN_USERNAME {
        return false;
    }
    has_active_local_session(state, ADMIN_USERNAME)
}

fn ui_login_cookie_value(username: &str) -> String {
    let safe_username: String = username
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_' || *c == '.')
        .collect();
    format!(
        "ui_username={}; Path=/; HttpOnly; SameSite=Lax",
        safe_username
    )
}

fn ui_logout_cookie_value() -> &'static str {
    "ui_username=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"
}

async fn ui_login() -> impl IntoResponse {
    ui_shell(
        "DS Login",
        r#"
        <div class="top-left">
            <button class="ghost" type="button" onclick="uiBack('/ui/login')">Back</button>
            <button class="ghost" type="button" onclick="uiLogout()">Logout</button>
        </div>
        <main class="panel">
            <section class="hero">
                <div class="eyebrow">Hybrid MLS Delivery Service</div>
                <h1>Sign In or Register</h1>
                <p class="muted">Local UI gateway signs requests using hybrid keys on this machine.</p>
            </section>
            <section class="card">
                <div id="login-hint" class="note"></div>
                <div class="row">
                    <button id="continue-btn" class="primary" type="button" onclick="uiContinue()">Continue</button>
                </div>
            </section>
            <section class="card">
                <form id="auth-form" class="stack">
                    <label>
                        <span>Username</span>
                        <input id="username" type="text" placeholder="alice" required />
                    </label>
                    <label>
                        <span>Password</span>
                        <input id="password" type="password" placeholder="••••••••" required />
                    </label>
                    <div class="row">
                        <button class="primary" type="button" onclick="uiLogin()">Login</button>
                        <button class="ghost" type="button" onclick="uiRegister()">Register</button>
                    </div>
                    <div id="auth-status" class="note"></div>
                    <div class="muted">Bootstrap admin login: `admin` / `admin@123`.</div>
                </form>
            </section>
        </main>
        <script>
        async function uiRegister() {
          const username = document.getElementById('username').value.trim();
          const password = document.getElementById('password').value.trim();
          const status = document.getElementById('auth-status');
          status.textContent = 'Registering...';
          const resp = await fetch('/ui/api/register', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({username, password})
          });
          const data = await resp.json();
          if (data.ok) {
            localStorage.setItem('ui_username', username);
            status.textContent = 'Registered and logged in.';
            const next = username === 'admin' ? '/ui/admin' : '/ui/groups';
            window.location.href = next;
          } else {
            status.textContent = data.error || 'Registration failed.';
          }
        }
        async function uiLogin() {
          const username = document.getElementById('username').value.trim();
          const password = document.getElementById('password').value.trim();
          const status = document.getElementById('auth-status');
          status.textContent = 'Logging in...';
          const resp = await fetch('/ui/api/login', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({username, password})
          });
          const data = await resp.json();
          if (data.ok) {
            localStorage.setItem('ui_username', username);
            status.textContent = 'Logged in.';
            const next = username === 'admin' ? '/ui/admin' : '/ui/groups';
            window.location.href = next;
          } else {
            status.textContent = data.error || 'Login failed.';
          }
        }
        async function uiLogout() {
          const username = localStorage.getItem('ui_username');
          if (username) {
            await fetch('/ui/api/logout', {
              method: 'POST',
              headers: {'Content-Type': 'application/json'},
              body: JSON.stringify({username})
            });
          }
          localStorage.removeItem('ui_username');
          window.location.href = '/ui/login';
        }
        function uiBack(fallbackPath) {
          if (window.history.length > 1) {
            window.history.back();
            return;
          }
          window.location.href = fallbackPath;
        }
        function uiContinue() {
          const username = localStorage.getItem('ui_username');
          if (username) {
            const next = username === 'admin' ? '/ui/admin' : '/ui/groups';
            window.location.href = next;
          }
        }
        (function initLoginHint() {
          const saved = localStorage.getItem('ui_username');
          const hint = document.getElementById('login-hint');
          const usernameInput = document.getElementById('username');
          const continueBtn = document.getElementById('continue-btn');
          if (saved) {
            hint.textContent = `Existing local session for ${saved}. You can continue or login with a different user.`;
            if (usernameInput && !usernameInput.value) {
              usernameInput.value = saved;
            }
            if (continueBtn) {
              continueBtn.textContent = `Continue as ${saved}`;
            }
          } else {
            hint.textContent = 'No local session found. Register or login to continue.';
            if (continueBtn) {
              continueBtn.disabled = true;
            }
          }
        })();
        </script>
        "#,
    )
}

async fn ui_groups() -> impl IntoResponse {
    ui_shell(
        "Groups",
        r#"
        <div class="top-left">
            <button class="ghost" type="button" onclick="uiBack('/ui/login')">Back</button>
            <button class="ghost" type="button" onclick="uiSyncTrackedGroups(false)">Sync + Apply Latest</button>
            <button class="ghost" type="button" onclick="uiLogout()">Logout</button>
        </div>
        <main class="panel">
            <section class="hero">
                <div class="eyebrow">Groups</div>
                <h1>Membership Overview</h1>
                <p class="muted">Select a group or add a group id for local tracking.</p>
            </section>
            <section class="card">
                <div class="row">
                    <div id="user-badge" class="note"></div>
                    <button id="admin-link" class="ghost is-hidden" type="button" onclick="window.location.href='/ui/admin'">Admin Panel</button>
                </div>
                <div class="row">
                    <input id="group-input" type="text" placeholder="group-alpha" />
                    <button class="primary" type="button" onclick="uiAddGroup()">Add Group</button>
                    <button class="ghost" type="button" onclick="loadGroups()">Refresh</button>
                </div>
                <div class="row">
                    <input id="group-filter" type="text" placeholder="Filter groups" oninput="renderGroups()" />
                    <div id="group-count" class="muted"></div>
                </div>
                <div id="group-list" class="list"></div>
            </section>
            <section class="card">
                <div class="stack">
                    <div class="title">KeyPackage Library</div>
                    <div class="muted">Generate once and share by copy or publish from the library.</div>
                    <button class="primary" type="button" onclick="uiGenerateKeyPackage()">Generate + Publish KeyPackage</button>
                    <div id="keypackage-list" class="list"></div>
                    <details>
                      <summary class="muted">Advanced: manual publish</summary>
                      <label>KeyPackage (base64)
                        <input id="keypackage-b64" type="text" placeholder="..." />
                      </label>
                      <button class="primary" type="button" onclick="uiPublishKeyPackage()">Publish Manual</button>
                    </details>
                    <div id="keypackage-status" class="note"></div>
                </div>
            </section>
        </main>
        <script>
        let _groups = [];
        let _didAutoSync = false;
        async function loadGroups() {
          const username = localStorage.getItem('ui_username');
          const list = document.getElementById('group-list');
          if (!username) {
            window.location.href = '/ui/login';
            return;
          }
          document.getElementById('user-badge').textContent = `Logged in as ${username} (local session cached)`;
          const adminLink = document.getElementById('admin-link');
          if (adminLink) {
            if (username === 'admin') {
              adminLink.classList.remove('is-hidden');
            } else {
              adminLink.classList.add('is-hidden');
            }
          }
          const resp = await fetch(`/ui/api/groups?username=${encodeURIComponent(username)}`);
          const data = await resp.json();
          if (!data.ok) {
            list.innerHTML = `<div class="note">${data.error}</div>`;
            return;
          }
          _groups = data.data.groups || [];
          renderGroups();
          if (!_didAutoSync) {
            _didAutoSync = true;
            await uiSyncTrackedGroups(true);
          }
        }
        function renderGroups() {
          const list = document.getElementById('group-list');
          const filter = document.getElementById('group-filter').value.trim().toLowerCase();
          const groups = (_groups || []).filter(group => group.toLowerCase().includes(filter));
          document.getElementById('group-count').textContent = `Showing ${groups.length} group(s)`;
          if (groups.length === 0) {
            list.innerHTML = '<div class="note">No groups saved yet.</div>';
            return;
          }
          list.innerHTML = groups.map(group => `
            <div class="list-item">
              <div>
                <div class="title">${group}</div>
                <div class="muted">Tracked locally</div>
              </div>
              <div class="row">
                <a class="link" href="/ui/groups/${group}">Open</a>
                <button class="ghost" type="button" onclick="uiRemoveGroup('${group}')">Forget</button>
              </div>
            </div>
          `).join('');
        }
        async function uiAddGroup() {
          const username = localStorage.getItem('ui_username');
          const input = document.getElementById('group-input');
          const group_id = input.value.trim();
          if (!username || !group_id) return;
          await fetch('/ui/api/groups/open', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({username, group_id})
          });
          await fetch(`/ui/api/groups/${group_id}/bootstrap`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({username})
          });
          input.value = '';
          loadGroups();
        }
        async function uiRemoveGroup(group_id) {
          const username = localStorage.getItem('ui_username');
          if (!username || !group_id) return;
          await fetch('/ui/api/groups/remove', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({username, group_id})
          });
          loadGroups();
        }
        async function uiLogout() {
          const username = localStorage.getItem('ui_username');
          if (username) {
            await fetch('/ui/api/logout', {
              method: 'POST',
              headers: {'Content-Type': 'application/json'},
              body: JSON.stringify({username})
            });
          }
          localStorage.removeItem('ui_username');
          window.location.href = '/ui/login';
        }
        function uiBack(fallbackPath) {
          if (window.history.length > 1) {
            window.history.back();
            return;
          }
          window.location.href = fallbackPath;
        }
        async function uiSyncTrackedGroups(silent) {
          const username = localStorage.getItem('ui_username');
          if (!username) {
            window.location.href = '/ui/login';
            return;
          }
          const status = document.getElementById('keypackage-status');
          if (!_groups || _groups.length === 0) {
            if (!silent && status) {
              status.textContent = 'No tracked groups to sync.';
            }
            return;
          }
          if (status) {
            status.textContent = `Syncing ${_groups.length} tracked group(s)...`;
          }
          let appliedTotal = 0;
          let skippedTotal = 0;
          let failed = 0;
          for (const groupId of _groups) {
            const resp = await fetch(`/ui/api/groups/${encodeURIComponent(groupId)}/sync-apply-latest`, {
              method: 'POST',
              headers: {'Content-Type': 'application/json'},
              body: JSON.stringify({username, limit: 50})
            });
            const data = await resp.json();
            if (data.ok && data.data) {
              appliedTotal += Number(data.data.applied || 0);
              skippedTotal += Number(data.data.skipped || 0);
            } else {
              failed += 1;
            }
          }
          if (status) {
            status.textContent = `Sync finished: applied ${appliedTotal}, skipped ${skippedTotal}, failed groups ${failed}.`;
          }
          if (!silent) {
            loadGroups();
          }
        }
        async function uiPublishKeyPackage() {
          const username = localStorage.getItem('ui_username');
          const keypackage_b64 = document.getElementById('keypackage-b64').value.trim();
          const status = document.getElementById('keypackage-status');
          if (!username || !keypackage_b64) return;
          status.textContent = 'Publishing...';
          const resp = await fetch('/ui/api/keypackages', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({username, keypackage_b64})
          });
          const data = await resp.json();
          status.textContent = data.ok ? 'Published.' : (data.error || 'Publish failed.');
        }
        async function uiGenerateKeyPackage() {
          const username = localStorage.getItem('ui_username');
          const status = document.getElementById('keypackage-status');
          if (!username) return;
          status.textContent = 'Generating and publishing...';
          const resp = await fetch('/ui/api/keypackages/generate', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({username})
          });
          const data = await resp.json();
          if (data.ok) {
            status.textContent = `Published. Receiver private stored at ${data.data.receiver_private_path}.`;
            await uiLoadKeypackages();
          } else {
            status.textContent = data.error || 'Generate failed.';
          }
        }
        async function uiLoadKeypackages() {
          const username = localStorage.getItem('ui_username');
          const list = document.getElementById('keypackage-list');
          if (!username) return;
          const resp = await fetch(`/ui/api/keypackages?username=${encodeURIComponent(username)}`);
          const data = await resp.json();
          if (!data.ok) {
            list.innerHTML = `<div class="note">${data.error}</div>`;
            return;
          }
          const items = data.data.items || [];
          if (items.length === 0) {
            list.innerHTML = '<div class="note">No stored keypackages yet.</div>';
            return;
          }
          items.sort((a, b) => b.created_at - a.created_at);
          list.innerHTML = items.map(item => {
            const created = new Date(item.created_at * 1000).toISOString();
            const published = item.published ? 'published' : 'local only';
            const receiver = item.receiver_private_path || 'receiver private not stored';
            return `
              <div class="list-item">
                <div>
                  <div class="title">${item.id}</div>
                  <div class="muted">created ${created} • ${published}</div>
                  <div class="muted">receiver: ${receiver}</div>
                </div>
                <div class="row">
                  <button class="ghost" type="button" onclick="uiUseKeypackage('${item.id}')">Use</button>
                  <button class="ghost" type="button" onclick="uiCopyKeypackage('${item.id}')">Copy</button>
                  <button class="ghost" type="button" onclick="uiPublishStoredKeypackage('${item.id}')">Publish</button>
                </div>
              </div>
            `;
          }).join('');
          window._keypackages = items;
        }
        function uiFindKeypackage(id) {
          const list = window._keypackages || [];
          return list.find(item => item.id === id);
        }
        function uiUseKeypackage(id) {
          const item = uiFindKeypackage(id);
          if (!item) return;
          const input = document.getElementById('keypackage-b64');
          input.value = item.keypackage_b64;
        }
        async function uiCopyKeypackage(id) {
          const item = uiFindKeypackage(id);
          const status = document.getElementById('keypackage-status');
          if (!item) return;
          const payload = item.keypackage_b64;
          if (navigator.clipboard && navigator.clipboard.writeText) {
            await navigator.clipboard.writeText(payload);
          } else {
            const temp = document.createElement('textarea');
            temp.value = payload;
            document.body.appendChild(temp);
            temp.select();
            document.execCommand('copy');
            temp.remove();
          }
          status.textContent = 'KeyPackage copied to clipboard.';
        }
        async function uiPublishStoredKeypackage(id) {
          const item = uiFindKeypackage(id);
          const status = document.getElementById('keypackage-status');
          if (!item) return;
          status.textContent = 'Publishing...';
          const username = localStorage.getItem('ui_username');
          const resp = await fetch('/ui/api/keypackages', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({username, keypackage_b64: item.keypackage_b64})
          });
          const data = await resp.json();
          status.textContent = data.ok ? 'Published.' : (data.error || 'Publish failed.');
          if (data.ok) {
            await uiLoadKeypackages();
          }
        }
        loadGroups();
        uiLoadKeypackages();
        </script>
        "#,
    )
}

async fn ui_admin(State(state): State<UiState>, headers: HeaderMap) -> impl IntoResponse {
    if !has_admin_ui_session(&state, &headers) {
        return Redirect::to("/ui/login").into_response();
    }
    ui_shell(
        "Admin",
        r#"
        <div class="top-left">
            <button class="ghost" type="button" onclick="uiBack('/ui/groups')">Back</button>
            <button class="ghost" type="button" onclick="window.location.href='/ui/groups'">Groups</button>
            <button class="ghost" type="button" onclick="uiLogout()">Logout</button>
        </div>
        <main class="panel">
            <section class="hero">
                <div class="eyebrow">Admin</div>
                <h1>Global Overview</h1>
                <p class="muted">Admin-only view of DS users and groups.</p>
            </section>
            <section class="card">
                <div id="admin-badge" class="note"></div>
                <div class="row">
                    <button class="primary" type="button" onclick="loadAdmin()">Refresh</button>
                </div>
            </section>
            <section class="card">
                <div class="title">Users</div>
                <div id="admin-users" class="list"></div>
            </section>
            <section class="card">
                <div class="title">Groups</div>
                <div id="admin-groups" class="list"></div>
            </section>
            <section class="card">
                <div class="title">Demos</div>
                <div class="row">
                    <input id="demo-title" type="text" placeholder="Demo title (optional)" />
                    <button class="primary" type="button" onclick="createDemo()">Create Demo</button>
                </div>
                <div id="admin-demos" class="list"></div>
                <div id="admin-demos-status" class="note"></div>
            </section>
        </main>
        <script>
        function uiBack(fallbackPath) {
          if (window.history.length > 1) {
            window.history.back();
            return;
          }
          window.location.href = fallbackPath;
        }
        async function uiLogout() {
          const username = localStorage.getItem('ui_username');
          if (username) {
            await fetch('/ui/api/logout', {
              method: 'POST',
              headers: {'Content-Type': 'application/json'},
              body: JSON.stringify({username})
            });
          }
          localStorage.removeItem('ui_username');
          window.location.href = '/ui/login';
        }
        function renderList(listId, rows, emptyLabel) {
          const node = document.getElementById(listId);
          if (!rows || rows.length === 0) {
            node.innerHTML = `<div class="note">${emptyLabel}</div>`;
            return;
          }
          node.innerHTML = rows.join('');
        }
        async function createDemo() {
          const username = localStorage.getItem('ui_username');
          const status = document.getElementById('admin-demos-status');
          if (!username) {
            window.location.href = '/ui/login';
            return;
          }
          status.textContent = 'Creating demo...';
          const title = document.getElementById('demo-title').value.trim();
          const resp = await fetch('/ui/api/admin/demos', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ username, title: title || null })
          });
          const data = await resp.json();
          if (!data.ok) {
            status.textContent = data.error || 'Create demo failed.';
            return;
          }
          const created = data.data;
          status.textContent = `Created ${created.id}.`;
          window.location.href = `/ui/admin/demos/${encodeURIComponent(created.id)}`;
        }
        async function loadDemos(username) {
          const status = document.getElementById('admin-demos-status');
          const resp = await fetch(`/ui/api/admin/demos?username=${encodeURIComponent(username)}`);
          const data = await resp.json();
          if (!data.ok) {
            renderList('admin-demos', [`<div class="note">${data.error || 'Failed to load demos.'}</div>`], 'No demos.');
            status.textContent = data.error || 'Failed to load demos.';
            return;
          }
          const demos = data.data.items || [];
          renderList(
            'admin-demos',
            demos.map(demo => {
              const created = new Date((demo.created_at || 0) * 1000).toISOString();
              return `<div class="list-item"><div><div class="title">${demo.id}</div><div class="muted">${demo.title} • created ${created}</div></div><a class="link" href="/ui/admin/demos/${encodeURIComponent(demo.id)}">Open</a></div>`;
            }),
            'No demos yet. Create the first one.'
          );
          status.textContent = `Loaded ${demos.length} demo(s).`;
        }
        async function loadAdmin() {
          const username = localStorage.getItem('ui_username');
          if (!username) {
            window.location.href = '/ui/login';
            return;
          }
          if (username !== 'admin') {
            window.location.href = '/ui/groups';
            return;
          }
          document.getElementById('admin-badge').textContent = 'Logged in as admin.';
          const [usersResp, groupsResp] = await Promise.all([
            fetch(`/ui/api/admin/users?username=${encodeURIComponent(username)}`),
            fetch(`/ui/api/admin/groups?username=${encodeURIComponent(username)}`)
          ]);
          const usersData = await usersResp.json();
          const groupsData = await groupsResp.json();
          if (!usersData.ok) {
            renderList('admin-users', [`<div class="note">${usersData.error || 'Failed to load users.'}</div>`], 'No users.');
          } else {
            const users = usersData.data.users || [];
            renderList(
              'admin-users',
              users.map(user => `<div class="list-item"><div class="title">${user}</div></div>`),
              'No users.'
            );
          }
          if (!groupsData.ok) {
            renderList('admin-groups', [`<div class="note">${groupsData.error || 'Failed to load groups.'}</div>`], 'No groups.');
          } else {
            const groups = groupsData.data.groups || [];
            renderList(
              'admin-groups',
              groups.map(group => `<div class="list-item"><div><div class="title">${group.group_id}</div><div class="muted">messages: ${group.message_count} • last_at: ${group.last_created_at}</div></div></div>`),
              'No groups.'
            );
          }
          await loadDemos(username);
        }
        loadAdmin();
        </script>
        "#,
    )
    .into_response()
}

async fn ui_admin_demo(
    AxumPath(demo_id): AxumPath<String>,
    State(state): State<UiState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if !has_admin_ui_session(&state, &headers) {
        return Redirect::to("/ui/login").into_response();
    }
    let body = format!(
        r##"
        <div class="top-left">
            <button class="ghost" type="button" onclick="uiBack('/ui/admin')">Back</button>
            <button class="ghost" type="button" onclick="window.location.href='/ui/admin'">Admin</button>
            <button class="ghost" type="button" onclick="uiLogout()">Logout</button>
        </div>
        <main class="panel panel-admin-demo">
            <section class="hero">
                <div class="eyebrow">Admin Demo</div>
                <h1>{demo_id}</h1>
                <p class="muted">Two-pane demo layout: left actions/logs, right tree view.</p>
            </section>
            <section class="card demo-layout">
                <div class="demo-left">
                    <div class="card-sub shadowed demo-actions">
                        <div class="title">Actions</div>
                        <div id="demo-meta" class="note"></div>
                        <div id="demo-action-status" class="note"></div>
                        <div class="row">
                          <button class="ghost" type="button" onclick="reloadDemo()">Reload Demo</button>
                        </div>
                        <details class="action-block" open>
                          <summary class="muted">Add member</summary>
                          <label>Adder
                            <input id="demo-add-adder" type="text" value="A" />
                          </label>
                          <label>Added
                            <input id="demo-add-added" type="text" placeholder="B" />
                          </label>
                          <button class="primary" type="button" onclick="demoActionAdd()">Apply Add</button>
                        </details>
                        <details class="action-block">
                          <summary class="muted">Remove member</summary>
                          <label>Remover
                            <input id="demo-remove-remover" type="text" value="A" />
                          </label>
                          <label>Removed
                            <input id="demo-remove-removed" type="text" placeholder="B" />
                          </label>
                          <button class="primary" type="button" onclick="demoActionRemove()">Apply Remove</button>
                        </details>
                        <details class="action-block">
                          <summary class="muted">Update key</summary>
                          <label>Updater
                            <input id="demo-update-updater" type="text" value="A" />
                          </label>
                          <button class="primary" type="button" onclick="demoActionUpdate()">Apply Update</button>
                        </details>
                        <div class="muted">Actions are deterministic demo transitions mapped to MLS-style proposal/commit steps.</div>
                    </div>
                    <div class="card-sub shadowed demo-logs">
                        <div class="title">Logs</div>
                        <div id="demo-log-list" class="list"></div>
                    </div>
                </div>
                <div class="card-sub shadowed demo-tree">
                    <div class="title">Tree Structure</div>
                    <div id="demo-tree-canvas" class="tree-graph"></div>
                    <div id="demo-tree-legend" class="muted">Legend: LeafIndex (L) = member leaf position, NodeIndex (N) = tree array index. Root is marked as `root`; blank leaves are labeled `blank`.</div>
                    <div class="muted">Live demo tree snapshot for the current epoch and member leaf indices.</div>
                </div>
            </section>
        </main>
        <script>
        function uiBack(fallbackPath) {{
          if (window.history.length > 1) {{
            window.history.back();
            return;
          }}
          window.location.href = fallbackPath;
        }}
        async function uiLogout() {{
          const username = localStorage.getItem('ui_username');
          if (username) {{
            await fetch('/ui/api/logout', {{
              method: 'POST',
              headers: {{'Content-Type': 'application/json'}},
              body: JSON.stringify({{username}})
            }});
          }}
          localStorage.removeItem('ui_username');
          window.location.href = '/ui/login';
        }}
        function escapeHtml(value) {{
          return String(value)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
        }}
        function leftSubtreeSize(leafCount) {{
          if (leafCount <= 1) return 1;
          let size = 1;
          const target = leafCount - 1;
          while ((size << 1) <= target) {{
            size <<= 1;
          }}
          return size;
        }}
        function leafToNodeIndex(leafIndex) {{
          return leafIndex * 2;
        }}
        function rootIndexForRange(startLeaf, leafCount) {{
          if (leafCount <= 1) {{
            return leafToNodeIndex(startLeaf);
          }}
          const leftCount = leftSubtreeSize(leafCount);
          return leafToNodeIndex(startLeaf) + (2 * leftCount - 1);
        }}
        function buildDemoTree(startLeaf, leafCount, depth, xMin, xMax, nodes, edges, memberMap) {{
          const nodeIndex = rootIndexForRange(startLeaf, leafCount);
          const x = (xMin + xMax) / 2;
          if (leafCount <= 1) {{
            nodes.push({{
              kind: 'leaf',
              node_index: nodeIndex,
              leaf_index: startLeaf,
              depth,
              x,
              member: memberMap.get(startLeaf) || null
            }});
            return nodeIndex;
          }}
          nodes.push({{
            kind: 'parent',
            node_index: nodeIndex,
            depth,
            x
          }});
          const leftCount = leftSubtreeSize(leafCount);
          const rightStart = startLeaf + leftCount;
          const rightCount = leafCount - leftCount;
          const leftNode = buildDemoTree(
            startLeaf,
            leftCount,
            depth + 1,
            xMin,
            x,
            nodes,
            edges,
            memberMap
          );
          const rightNode = buildDemoTree(
            rightStart,
            rightCount,
            depth + 1,
            x,
            xMax,
            nodes,
            edges,
            memberMap
          );
          edges.push({{ from: nodeIndex, to: leftNode }});
          edges.push({{ from: nodeIndex, to: rightNode }});
          return nodeIndex;
        }}
        function renderDemoTree(members, epoch, leafCount, nodeCount) {{
          const tree = document.getElementById('demo-tree-canvas');
          const legend = document.getElementById('demo-tree-legend');
          if (!tree) return;
          const items = (members || []).slice().sort((a, b) => a.leaf_index - b.leaf_index);
          const inferredLeafCount = items.length === 0
            ? 0
            : items.reduce((m, item) => Math.max(m, Number(item.leaf_index || 0)), 0) + 1;
          const resolvedLeafCount = Number(leafCount || 0) > 0 ? Number(leafCount) : inferredLeafCount;
          if (resolvedLeafCount === 0) {{
            tree.innerHTML = '<div class="note">No members.</div>';
            if (legend) {{
              legend.textContent = 'No topology to render.';
            }}
            return;
          }}
          const memberMap = new Map(items.map(item => [Number(item.leaf_index), item]));
          const nodes = [];
          const edges = [];
          const width = 1800;
          const rootNodeIndex = buildDemoTree(0, resolvedLeafCount, 0, 80, width - 80, nodes, edges, memberMap);
          const maxDepth = nodes.reduce((m, node) => Math.max(m, Number(node.depth || 0)), 0);
          const rowHeight = 128;
          const height = 120 + (maxDepth + 1) * rowHeight;
          const nodePos = new Map(nodes.map(node => [
            Number(node.node_index),
            {{ x: Number(node.x), y: 84 + Number(node.depth) * rowHeight }}
          ]));
          const edgeSvg = edges.map(edge => {{
            const from = nodePos.get(Number(edge.from));
            const to = nodePos.get(Number(edge.to));
            if (!from || !to) return '';
            return `<line x1="${{from.x}}" y1="${{from.y}}" x2="${{to.x}}" y2="${{to.y}}" stroke="#9aa8b7" stroke-width="2"></line>`;
          }}).join('');
          const nodeSvg = nodes.map(node => {{
            const pos = nodePos.get(Number(node.node_index));
            if (!pos) return '';
            const isRoot = Number(node.node_index) === Number(rootNodeIndex);
            if (node.kind === 'parent') {{
              return `
                <g>
                  <circle cx="${{pos.x}}" cy="${{pos.y}}" r="30" fill="${{isRoot ? '#ffe8cc' : '#fff5ec'}}" stroke="#b45309" stroke-width="2"></circle>
                  <text x="${{pos.x}}" y="${{pos.y - 6}}" text-anchor="middle" font-size="13" font-family="Space Grotesk" fill="#1f2933">parent</text>
                  <text x="${{pos.x}}" y="${{pos.y + 12}}" text-anchor="middle" font-size="13" font-family="Space Grotesk" fill="#5c6b7a">N${{node.node_index}}</text>
                  ${{isRoot ? `<text x="${{pos.x}}" y="${{pos.y - 40}}" text-anchor="middle" font-size="13" font-family="Space Grotesk" fill="#b45309">root</text>` : ''}}
                </g>
              `;
            }}
            const member = node.member || null;
            const isBlank = !member;
            const leafLabel = `L${{node.leaf_index}}`;
            const nodeLabel = `N${{node.node_index}}`;
            const userLabel = isBlank ? 'blank' : String(member.username || '').slice(0, 12);
            const keyGeneration = !isBlank && member && member.key_generation != null
              ? `k${{Number(member.key_generation)}}`
              : '';
            return `
              <g>
                <circle cx="${{pos.x}}" cy="${{pos.y}}" r="34" fill="${{isBlank ? '#f6f7f8' : '#ffffff'}}" stroke="${{isBlank ? '#9aa8b7' : '#b45309'}}" stroke-width="2"></circle>
                <text x="${{pos.x}}" y="${{pos.y - 14}}" text-anchor="middle" font-size="13" font-family="Space Grotesk" fill="#1f2933">${{leafLabel}} / ${{nodeLabel}}</text>
                <text x="${{pos.x}}" y="${{pos.y + 4}}" text-anchor="middle" font-size="12" font-family="Space Grotesk" fill="#5c6b7a">${{escapeHtml(userLabel)}}</text>
                <text x="${{pos.x}}" y="${{pos.y + 22}}" text-anchor="middle" font-size="12" font-family="Space Grotesk" fill="#5c6b7a">${{escapeHtml(keyGeneration)}}</text>
                ${{isRoot ? `<text x="${{pos.x}}" y="${{pos.y - 46}}" text-anchor="middle" font-size="13" font-family="Space Grotesk" fill="#b45309">root</text>` : ''}}
              </g>
            `;
          }}).join('');
          const resolvedNodeCount = Number(nodeCount || 0) > 0
            ? Number(nodeCount)
            : (resolvedLeafCount > 0 ? (2 * resolvedLeafCount - 1) : 0);
          tree.innerHTML = `
            <svg viewBox="0 0 ${{width}} ${{height}}" width="100%" height="${{height}}" preserveAspectRatio="xMidYMid meet">
              <rect x="0" y="0" width="${{width}}" height="${{height}}" fill="#fffef8" stroke="#e7cba1" rx="10"></rect>
              <text x="${{width / 2}}" y="34" text-anchor="middle" font-size="16" font-family="Space Grotesk" fill="#5c6b7a">epoch ${{epoch}} • root N${{rootNodeIndex}} • leaves ${{resolvedLeafCount}} • nodes ${{resolvedNodeCount}}</text>
              ${{edgeSvg}}
              ${{nodeSvg}}
            </svg>
          `;
          if (legend) {{
            const blankCount = nodes.filter(node => node.kind === 'leaf' && !node.member).length;
            legend.textContent = `LeafIndex (L) = member leaf position. NodeIndex (N) = tree-array node id (leaf nodes have even N). Parent nodes display N only. Root is marked as root. Blank leaves are labeled blank. Blank leaves: ${{blankCount}}.`;
          }}
        }}
        function renderDemoLogs(demo) {{
          const logs = document.getElementById('demo-log-list');
          if (!logs) return;
          const rows = [];
          const entries = demo.logs || [];
          if (entries.length === 0) {{
            rows.push('<div class="note">No logs yet.</div>');
          }} else {{
            entries.forEach(entry => {{
              if (entry.separator) {{
                rows.push('<div class="divider"></div>');
                return;
              }}
              const ts = new Date((entry.timestamp || 0) * 1000).toISOString();
              rows.push(`<div class="list-item"><div><div class="title">${{escapeHtml(entry.line || '')}}</div><div class="muted">${{ts}}</div></div></div>`);
            }});
          }}
          rows.push(`<div class="note">Root: ${{demo.root_dir}}</div>`);
          rows.push(`<div class="note">Manifest: ${{demo.manifest_path}}</div>`);
          logs.innerHTML = rows.join('');
        }}
        async function callDemoAction(kind, payload) {{
          const username = localStorage.getItem('ui_username');
          const status = document.getElementById('demo-action-status');
          if (!username) {{
            window.location.href = '/ui/login';
            return;
          }}
          if (username !== 'admin') {{
            window.location.href = '/ui/groups';
            return;
          }}
          status.textContent = `Applying ${{kind}}...`;
          const resp = await fetch(`/ui/api/admin/demos/{demo_id}/actions/${{kind}}`, {{
            method: 'POST',
            headers: {{'Content-Type': 'application/json'}},
            body: JSON.stringify(Object.assign({{ username }}, payload))
          }});
          const data = await resp.json();
          if (!data.ok) {{
            status.textContent = data.error || `${{kind}} failed.`;
            return;
          }}
          const out = data.data;
          status.textContent = `${{out.action}} applied. epoch=${{out.epoch}} members=${{(out.members || []).length}}`;
          await loadDemo();
        }}
        async function demoActionAdd() {{
          const adder = document.getElementById('demo-add-adder').value.trim();
          const added = document.getElementById('demo-add-added').value.trim();
          if (!adder || !added) return;
          await callDemoAction('add', {{ adder, added }});
        }}
        async function demoActionRemove() {{
          const remover = document.getElementById('demo-remove-remover').value.trim();
          const removed = document.getElementById('demo-remove-removed').value.trim();
          if (!remover || !removed) return;
          await callDemoAction('remove', {{ remover, removed }});
        }}
        async function demoActionUpdate() {{
          const updater = document.getElementById('demo-update-updater').value.trim();
          if (!updater) return;
          await callDemoAction('update', {{ updater }});
        }}
        async function reloadDemo() {{
          await loadDemo();
        }}
        async function loadDemo() {{
          const username = localStorage.getItem('ui_username');
          if (!username) {{
            window.location.href = '/ui/login';
            return;
          }}
          if (username !== 'admin') {{
            window.location.href = '/ui/groups';
            return;
          }}
          const resp = await fetch(`/ui/api/admin/demos/{demo_id}?username=${{encodeURIComponent(username)}}`);
          const data = await resp.json();
          const meta = document.getElementById('demo-meta');
          const actionStatus = document.getElementById('demo-action-status');
          if (!data.ok) {{
            meta.textContent = data.error || 'Failed to load demo metadata.';
            if (actionStatus) {{
              actionStatus.textContent = data.error || 'Failed to load demo metadata.';
            }}
            return;
          }}
          const demo = data.data;
          meta.textContent = `Demo: ${{demo.id}} | ${{demo.title}} | epoch=${{demo.epoch}} | leaves=${{demo.leaf_count}} | nodes=${{demo.node_count}} | created: ${{new Date((demo.created_at || 0) * 1000).toISOString()}}`;
          if (actionStatus && !actionStatus.textContent) {{
            actionStatus.textContent = 'Ready.';
          }}
          renderDemoLogs(demo);
          renderDemoTree(
            demo.members || [],
            demo.epoch || 0,
            demo.leaf_count || 0,
            demo.node_count || 0
          );
        }}
        loadDemo();
        </script>
        "##,
        demo_id = demo_id
    );
    ui_shell("Admin Demo", &body).into_response()
}

async fn ui_group_detail(AxumPath(group_id): AxumPath<String>) -> impl IntoResponse {
    let body_template = r##"
        <div class="top-left">
            <button class="ghost" type="button" onclick="uiBack('/ui/groups')">Back</button>
            <button class="ghost" type="button" onclick="uiSyncApplyLatest(false)">Sync + Apply Latest</button>
            <button class="ghost" type="button" onclick="uiLogout()">Logout</button>
        </div>
        <main class="panel">
            <section class="hero">
                <div class="eyebrow">Group</div>
                <h1>__GROUP__</h1>
                <p class="muted">Signed requests are executed through the local UI gateway.</p>
            </section>
            <section class="card stack">
                <div id="user-badge" class="note"></div>
                <div class="grid">
                    <div class="card-sub">
                        <div class="title">Actions</div>
                        <div id="group-state-status" class="note"></div>
                        <details class="action-block" open>
                          <summary class="muted">Add member</summary>
                          <label>Target username (fetch KeyPackage)
                            <input id="add-target" type="text" placeholder="bob" />
                          </label>
                          <div class="row">
                            <button class="ghost" type="button" onclick="uiFetchKeyPackageInto('add')">Fetch KeyPackage</button>
                          </div>
                          <label>KeyPackage (base64)
                            <div id="add-keypackage-preview" class="kp-preview">no keypackage</div>
                            <textarea id="add-keypackage" class="kp-full is-hidden" placeholder="..." oninput="uiSyncKeypackagePreview('add')"></textarea>
                          </label>
                          <div class="row">
                            <button class="ghost" type="button" onclick="uiToggleKeypackage('add', this)">Show full</button>
                          </div>
                          <label>Sender leaf (optional)
                            <input id="add-sender" type="number" placeholder="defaults to own leaf" />
                          </label>
                          <div class="row">
                            <button class="primary" type="button" onclick="uiActionAdd()">Create + Submit Add</button>
                          </div>
                        </details>
                        <details class="action-block">
                          <summary class="muted">Remove member</summary>
                          <label>Remove leaf index
                            <input id="remove-leaf" type="number" placeholder="leaf index" />
                          </label>
                          <label>Sender leaf (optional)
                            <input id="remove-sender" type="number" placeholder="defaults to own leaf" />
                          </label>
                          <div class="row">
                            <button class="primary" type="button" onclick="uiActionRemove()">Create + Submit Remove</button>
                          </div>
                        </details>
                        <details class="action-block">
                          <summary class="muted">Update key</summary>
                          <label>Target username (fetch KeyPackage)
                            <input id="update-target" type="text" placeholder="alice" />
                          </label>
                          <div class="row">
                            <button class="ghost" type="button" onclick="uiFetchKeyPackageInto('update')">Fetch KeyPackage</button>
                          </div>
                          <label>KeyPackage (base64)
                            <div id="update-keypackage-preview" class="kp-preview">no keypackage</div>
                            <textarea id="update-keypackage" class="kp-full is-hidden" placeholder="..." oninput="uiSyncKeypackagePreview('update')"></textarea>
                          </label>
                          <div class="row">
                            <button class="ghost" type="button" onclick="uiToggleKeypackage('update', this)">Show full</button>
                          </div>
                          <label>Target leaf (optional)
                            <input id="update-leaf" type="number" placeholder="defaults to own leaf" />
                          </label>
                          <label>Sender leaf (optional)
                            <input id="update-sender" type="number" placeholder="defaults to own leaf" />
                          </label>
                          <div class="row">
                            <button class="primary" type="button" onclick="uiActionUpdate()">Create + Submit Update</button>
                          </div>
                        </details>
                        <details class="action-block" open>
                          <summary class="muted">Commit + Sync</summary>
                          <label>Commit sender leaf (optional)
                            <input id="commit-sender" type="number" placeholder="defaults to own leaf" />
                          </label>
                          <div class="row">
                            <button class="primary" type="button" onclick="uiCreateCommitFromPending()">Create + Submit Commit</button>
                          </div>
                          <label>Sync limit
                            <input id="sync-limit" type="number" value="50" />
                          </label>
                          <label>Receiver private path (optional)
                            <input id="sync-receiver-path" type="text" placeholder="auto: latest local receiver file" />
                          </label>
                          <div class="row">
                            <button class="ghost" type="button" onclick="uiSyncApplyLatest()">Sync + Apply Latest</button>
                          </div>
                          <label>Onboarding base members (comma usernames in pre-commit leaf order)
                            <input id="join-base-members" type="text" placeholder="parsania" />
                          </label>
                          <div class="row">
                            <button class="ghost" type="button" onclick="uiJoinFromLatest()">Join from latest Welcome</button>
                          </div>
                        </details>
                        <div id="action-status" class="note"></div>
                    </div>
                    <div class="card-sub shadowed">
                        <div class="title">List Messages</div>
                        <label>Kind
                          <select id="msg-kind">
                            <option value="any">any</option>
                            <option value="commit">commit</option>
                            <option value="proposal">proposal</option>
                            <option value="path_update">path_update</option>
                            <option value="welcome">welcome</option>
                            <option value="application">application</option>
                          </select>
                        </label>
                        <label>Limit
                          <input id="msg-limit" type="number" value="10" />
                        </label>
                        <label>Before ID (optional)
                          <input id="msg-before" type="number" placeholder="latest" />
                        </label>
                        <button class="primary" type="button" onclick="uiListMessages()">Fetch</button>
                    </div>
                    <div class="card-sub shadowed">
                        <div class="title">Send App Message</div>
                        <label>Message
                          <input id="app-message" type="text" placeholder="hello group" />
                        </label>
                        <button class="primary" type="button" onclick="uiSendAppMessage()">Send</button>
                    </div>
                    <div class="card-sub">
                        <div class="title">List App Messages</div>
                        <label>Limit
                          <input id="app-limit" type="number" value="10" />
                        </label>
                        <label>Before ID (optional)
                          <input id="app-before" type="number" placeholder="latest" />
                        </label>
                        <button class="primary" type="button" onclick="uiListAppMessages()">Fetch</button>
                    </div>
                    <div class="card-sub shadowed">
                        <div class="title">Submit Proposal (base64)</div>
                        <label>Proposal Bytes
                          <input id="proposal-b64" type="text" placeholder="..." />
                        </label>
                        <button class="primary" type="button" onclick="uiSubmitProposal()">Submit</button>
                    </div>
                    <div class="card-sub">
                        <div class="title">Submit Commit (base64)</div>
                        <label>Commit Bytes
                          <input id="commit-b64" type="text" placeholder="..." />
                        </label>
                        <label>Path Update (base64, optional)
                          <input id="path-b64" type="text" placeholder="..." />
                        </label>
                        <button class="primary" type="button" onclick="uiSubmitCommit()">Submit</button>
                    </div>
                    <div class="card-sub">
                        <div class="title">Publish KeyPackage (base64)</div>
                        <label>KeyPackage Bytes
                          <input id="keypackage-b64" type="text" placeholder="..." />
                        </label>
                        <button class="primary" type="button" onclick="uiPublishKeyPackage()">Publish</button>
                    </div>
                    <div class="card-sub">
                        <div class="title">Fetch KeyPackage</div>
                        <label>Target Username
                          <input id="keypackage-target" type="text" placeholder="bob" />
                        </label>
                        <button class="primary" type="button" onclick="uiFetchKeyPackage()">Fetch</button>
                    </div>
                    <div class="card-sub">
                        <div class="title">KeyPackage Library</div>
                        <div id="keypackage-list" class="list"></div>
                        <div class="row">
                          <button class="ghost" type="button" onclick="uiLoadKeypackages()">Refresh</button>
                        </div>
                        <div id="keypackage-status" class="note"></div>
                    </div>
                </div>
                <div class="divider"></div>
                <div class="stack">
                    <div class="title">Messages</div>
                    <div id="message-list" class="list"></div>
                </div>
                <div class="divider"></div>
                <div class="stack">
                    <div class="title">App Messages</div>
                    <div id="app-message-list" class="list"></div>
                </div>
                <div class="divider"></div>
                <div class="stack">
                    <div class="title">Tree Structure</div>
                    <div class="row">
                      <button class="ghost" type="button" onclick="uiLoadTree()">Refresh</button>
                    </div>
                    <div class="tree-view-grid">
                      <div id="tree-graph" class="tree-graph"></div>
                      <div id="tree-list" class="list"></div>
                    </div>
                </div>
                <div class="divider"></div>
                <pre id="output" class="output"></pre>
            </section>
        </main>
        <script>
        const groupId = __GROUP_JSON__;
        function username() { return localStorage.getItem('ui_username'); }
        function writeOutput(data) {
          document.getElementById('output').textContent = JSON.stringify(data, null, 2);
        }
        async function ensureGroupTracked() {
          const user = ensureUser();
          if (!user) return;
          await fetch('/ui/api/groups/open', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({username: user, group_id: groupId})
          });
        }
        function ensureUser() {
          const user = username();
          if (!user) {
            window.location.href = '/ui/login';
            return null;
          }
          const badge = document.getElementById('user-badge');
          if (badge) {
            badge.textContent = `Logged in as ${user} (local session cached)`;
          }
          return user;
        }
        function renderMessages(items) {
          const list = document.getElementById('message-list');
          if (!items || items.length === 0) {
            list.innerHTML = '<div class="note">No messages found.</div>';
            return;
          }
          list.innerHTML = items.map(item => {
            const created = new Date(item.created_at * 1000).toISOString();
            const id = String(item.id);
            return `
              <div class="list-item">
                <div>
                  <div class="title">${item.kind} #${id}</div>
                  <div class="muted">size ${item.size} bytes • ${created}</div>
                </div>
                <button class="ghost" type="button" onclick="uiFetchMessage('${id}')">Fetch</button>
              </div>
            `;
          }).join('');
        }
        function renderAppMessages(items) {
          const list = document.getElementById('app-message-list');
          if (!items || items.length === 0) {
            list.innerHTML = '<div class="note">No app messages found.</div>';
            return;
          }
          list.innerHTML = items.map(item => {
            const created = new Date(item.created_at * 1000).toISOString();
            const id = String(item.id);
            return `
              <div class="list-item">
                <div>
                  <div class="title">app #${id}</div>
                  <div class="muted">size ${item.size} bytes • ${created}</div>
                </div>
                <button class="ghost" type="button" onclick="uiFetchAppMessage('${id}')">Fetch</button>
              </div>
            `;
          }).join('');
        }
        async function uiLogout() {
          const user = username();
          if (user) {
            const resp = await fetch('/ui/api/logout', {
              method: 'POST',
              headers: {'Content-Type': 'application/json'},
              body: JSON.stringify({username: user})
            });
            const data = await resp.json();
            writeOutput(data);
          }
          localStorage.removeItem('ui_username');
          window.location.href = '/ui/login';
        }
        function uiBack(fallbackPath) {
          if (window.history.length > 1) {
            window.history.back();
            return;
          }
          window.location.href = fallbackPath;
        }
        async function uiListMessages() {
          const user = ensureUser();
          if (!user) return;
          const kind = document.getElementById('msg-kind').value.trim();
          const limit = document.getElementById('msg-limit').value.trim();
          const before = document.getElementById('msg-before').value.trim();
          let url = `/ui/api/groups/${groupId}/messages?username=${encodeURIComponent(user)}&kind=${encodeURIComponent(kind)}&limit=${encodeURIComponent(limit)}`;
          if (before) {
            url += `&before_id=${encodeURIComponent(before)}`;
          }
          const resp = await fetch(url);
          const data = await resp.json();
          if (data.ok) {
            renderMessages(data.data.messages || []);
          }
          writeOutput(data);
        }
        async function uiFetchMessage(messageId) {
          const user = ensureUser();
          if (!user || !messageId) return;
          const url = `/ui/api/groups/${groupId}/messages/${messageId}?username=${encodeURIComponent(user)}`;
          const resp = await fetch(url);
          const data = await resp.json();
          writeOutput(data);
        }
        async function uiSendAppMessage() {
          const user = ensureUser();
          const message = document.getElementById('app-message').value.trim();
          if (!user || !message) return;
          const resp = await fetch(`/ui/api/groups/${groupId}/app-messages`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({username: user, message})
          });
          const data = await resp.json();
          writeOutput(data);
        }
        async function uiListAppMessages() {
          const user = ensureUser();
          if (!user) return;
          const limit = document.getElementById('app-limit').value.trim();
          const before = document.getElementById('app-before').value.trim();
          let url = `/ui/api/groups/${groupId}/app-messages?username=${encodeURIComponent(user)}&limit=${encodeURIComponent(limit)}`;
          if (before) {
            url += `&before_id=${encodeURIComponent(before)}`;
          }
          const resp = await fetch(url);
          const data = await resp.json();
          if (data.ok) {
            renderAppMessages(data.data.messages || []);
          }
          writeOutput(data);
        }
        async function uiFetchAppMessage(messageId) {
          const user = ensureUser();
          if (!user || !messageId) return;
          const url = `/ui/api/groups/${groupId}/app-messages/${messageId}?username=${encodeURIComponent(user)}`;
          const resp = await fetch(url);
          const data = await resp.json();
          writeOutput(data);
        }
        async function uiSubmitProposal() {
          const user = ensureUser();
          const proposal_b64 = document.getElementById('proposal-b64').value.trim();
          if (!user || !proposal_b64) return;
          const resp = await fetch(`/ui/api/groups/${groupId}/proposals`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({username: user, proposal_b64})
          });
          const data = await resp.json();
          writeOutput(data);
        }
        async function uiSubmitCommit() {
          const user = ensureUser();
          const commit_b64 = document.getElementById('commit-b64').value.trim();
          const path_update_b64 = document.getElementById('path-b64').value.trim();
          if (!user || !commit_b64) return;
          const payload = {username: user, commit_b64, path_update_b64: path_update_b64 || null};
          const resp = await fetch(`/ui/api/groups/${groupId}/commits`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(payload)
          });
          const data = await resp.json();
          writeOutput(data);
        }
        async function uiPublishKeyPackage() {
          const user = ensureUser();
          const keypackage_b64 = document.getElementById('keypackage-b64').value.trim();
          if (!user || !keypackage_b64) return;
          const resp = await fetch('/ui/api/keypackages', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({username: user, keypackage_b64})
          });
          const data = await resp.json();
          writeOutput(data);
          if (data.ok) {
            await uiLoadKeypackages();
          }
        }
        async function uiFetchKeyPackage() {
          const user = ensureUser();
          const target = document.getElementById('keypackage-target').value.trim();
          if (!user || !target) return;
          const resp = await fetch(`/ui/api/keypackages/${target}?username=${encodeURIComponent(user)}`);
          const data = await resp.json();
          writeOutput(data);
        }
        function truncateKeypackage(value) {
          if (!value) return 'no keypackage';
          const max = 64;
          return value.length > max ? `${value.slice(0, max)}...` : value;
        }
        function uiSyncKeypackagePreview(prefix) {
          const input = document.getElementById(`${prefix}-keypackage`);
          const preview = document.getElementById(`${prefix}-keypackage-preview`);
          if (!input || !preview) return;
          preview.textContent = truncateKeypackage(input.value.trim());
        }
        function uiToggleKeypackage(prefix, button) {
          const input = document.getElementById(`${prefix}-keypackage`);
          const preview = document.getElementById(`${prefix}-keypackage-preview`);
          if (!input || !preview) return;
          const isHidden = input.classList.contains('is-hidden');
          if (isHidden) {
            input.classList.remove('is-hidden');
            if (button) button.textContent = 'Hide full';
          } else {
            input.classList.add('is-hidden');
            if (button) button.textContent = 'Show full';
          }
          uiSyncKeypackagePreview(prefix);
        }
        async function uiFetchKeyPackageInto(prefix) {
          const user = ensureUser();
          if (!user) return;
          const targetInput = document.getElementById(`${prefix}-target`);
          if (!targetInput) return;
          const target = targetInput.value.trim();
          if (!target) return;
          const resp = await fetch(`/ui/api/keypackages/${target}?username=${encodeURIComponent(user)}`);
          const data = await resp.json();
          if (data.ok && data.data && data.data.keypackage_bytes) {
            const input = document.getElementById(`${prefix}-keypackage`);
            if (input) {
              input.value = data.data.keypackage_bytes;
            }
            uiSyncKeypackagePreview(prefix);
          }
          writeOutput(data);
        }
        async function uiActionAdd() {
          const user = ensureUser();
          const status = document.getElementById('action-status');
          const targetUsername = document.getElementById('add-target').value.trim();
          const keypackage_b64 = document.getElementById('add-keypackage').value.trim();
          const sender = document.getElementById('add-sender').value.trim();
          if (!user || !keypackage_b64) return;
          status.textContent = 'Submitting Add proposal...';
          const resp = await fetch(`/ui/api/groups/${groupId}/actions/add`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
              username: user,
              target_username: targetUsername || null,
              keypackage_b64,
              sender_leaf: sender ? Number(sender) : null,
              submit: true
            })
          });
          const data = await resp.json();
          status.textContent = data.ok ? 'Add proposal submitted.' : (data.error || 'Add failed.');
          writeOutput(data);
          await loadGroupState();
        }
        async function uiActionRemove() {
          const user = ensureUser();
          const status = document.getElementById('action-status');
          const removeLeaf = document.getElementById('remove-leaf').value.trim();
          const sender = document.getElementById('remove-sender').value.trim();
          if (!user || !removeLeaf) return;
          status.textContent = 'Submitting Remove proposal...';
          const resp = await fetch(`/ui/api/groups/${groupId}/actions/remove`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
              username: user,
              remove_leaf: Number(removeLeaf),
              sender_leaf: sender ? Number(sender) : null,
              submit: true
            })
          });
          const data = await resp.json();
          status.textContent = data.ok ? 'Remove proposal submitted.' : (data.error || 'Remove failed.');
          writeOutput(data);
          await loadGroupState();
        }
        async function uiActionUpdate() {
          const user = ensureUser();
          const status = document.getElementById('action-status');
          const keypackage_b64 = document.getElementById('update-keypackage').value.trim();
          const targetLeaf = document.getElementById('update-leaf').value.trim();
          const sender = document.getElementById('update-sender').value.trim();
          if (!user || !keypackage_b64) return;
          status.textContent = 'Submitting Update proposal...';
          const resp = await fetch(`/ui/api/groups/${groupId}/actions/update`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
              username: user,
              keypackage_b64,
              target_leaf: targetLeaf ? Number(targetLeaf) : null,
              sender_leaf: sender ? Number(sender) : null,
              submit: true
            })
          });
          const data = await resp.json();
          status.textContent = data.ok ? 'Update proposal submitted.' : (data.error || 'Update failed.');
          writeOutput(data);
          await loadGroupState();
        }
        async function uiCreateCommitFromPending() {
          const user = ensureUser();
          const status = document.getElementById('action-status');
          const sender = document.getElementById('commit-sender').value.trim();
          if (!user || !status) return;
          status.textContent = 'Creating and submitting commit from pending proposals...';
          const resp = await fetch(`/ui/api/groups/${groupId}/commit-from-pending`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
              username: user,
              sender_leaf: sender ? Number(sender) : null
            })
          });
          const data = await resp.json();
          if (data.ok && data.data) {
            const welcomeNote = data.data.welcome_b64 ? ' Welcome generated for Add proposal(s).' : '';
            status.textContent = `Commit submitted. Local epoch is now ${data.data.epoch}.${welcomeNote}`;
          } else {
            status.textContent = data.error || 'Create+submit commit failed.';
          }
          writeOutput(data);
          await loadGroupState();
          await uiLoadTree();
          await uiListMessages();
        }
        async function uiSyncApplyLatest(silent) {
          const user = ensureUser();
          const status = document.getElementById('action-status');
          const limit = document.getElementById('sync-limit').value.trim();
          const receiverPath = document.getElementById('sync-receiver-path').value.trim();
          if (!user || !status) return;
          status.textContent = 'Syncing and applying latest commits...';
          const resp = await fetch(`/ui/api/groups/${groupId}/sync-apply-latest`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
              username: user,
              limit: limit ? Number(limit) : null,
              receiver_private_path: receiverPath || null
            })
          });
          const data = await resp.json();
          if (data.ok && data.data) {
            const usedPath = data.data.receiver_private_path ? ` receiver=${data.data.receiver_private_path}` : '';
            status.textContent = `Sync done. Applied ${data.data.applied}, skipped ${data.data.skipped}, local epoch ${data.data.local_epoch}.${usedPath}`;
          } else {
            status.textContent = data.error || 'Sync/apply failed.';
          }
          if (!silent) {
            writeOutput(data);
          }
          await loadGroupState();
          await uiLoadTree();
          await uiListMessages();
        }
        async function uiJoinFromLatest() {
          const user = ensureUser();
          const status = document.getElementById('action-status');
          const limit = document.getElementById('sync-limit').value.trim();
          const receiverPath = document.getElementById('sync-receiver-path').value.trim();
          const baseMembersRaw = document.getElementById('join-base-members').value.trim();
          if (!user || !status) return;
          const baseMemberUsernames = baseMembersRaw
            ? baseMembersRaw.split(',').map(v => v.trim()).filter(Boolean)
            : [];
          status.textContent = 'Running joiner onboarding from latest Welcome...';
          const resp = await fetch(`/ui/api/groups/${groupId}/join-from-latest`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
              username: user,
              base_member_usernames: baseMemberUsernames,
              limit: limit ? Number(limit) : null,
              receiver_private_path: receiverPath || null
            })
          });
          const data = await resp.json();
          if (data.ok && data.data) {
            status.textContent = `Joined at commit ${data.data.commit_id}. Own leaf ${data.data.own_leaf_index}, local epoch ${data.data.local_epoch}, catch-up applied ${data.data.applied_after_join}.`;
          } else {
            status.textContent = data.error || 'Joiner onboarding failed.';
          }
          writeOutput(data);
          await loadGroupState();
          await uiLoadTree();
          await uiListMessages();
        }
        async function loadGroupState() {
          const user = ensureUser();
          const status = document.getElementById('group-state-status');
          if (!user || !status) return;
          const resp = await fetch(`/ui/api/groups/${groupId}/state?username=${encodeURIComponent(user)}`);
          const data = await resp.json();
          if (data.ok && data.data) {
            const info = data.data;
            status.textContent = `Local group state: epoch ${info.epoch}, own leaf ${info.own_leaf_index}, leaves ${info.leaf_count}, pending proposals ${info.pending_proposals}`;
            status.classList.remove('error');
          } else {
            status.textContent = data.error || 'Local group state not found. Create/bootstrapped state required.';
            status.classList.add('error');
          }
        }
        function renderTree(tree) {
          const list = document.getElementById('tree-list');
          if (!tree || !list) return;
          const header = `root ${tree.root_index ?? 'n/a'} • leaves ${tree.leaf_count} • epoch ${tree.epoch}`;
          if (!tree.nodes || tree.nodes.length === 0) {
            list.innerHTML = `<div class="note">No tree nodes found. ${header}</div>`;
            renderTreeGraph(null);
            return;
          }
          list.innerHTML = `
            <div class="note">${header}</div>
            ${tree.nodes.map(node => `
              <div class="list-item">
                <div>
                  <div class="title">#${node.node_index} ${node.node_type} (${node.label})</div>
                  <div class="muted">${node.summary}</div>
                </div>
              </div>
            `).join('')}
          `;
          renderTreeGraph(tree);
        }
        function escapeHtml(value) {
          return String(value)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
        }
        function renderTreeGraph(tree) {
          const host = document.getElementById('tree-graph');
          if (!host) return;
          if (!tree || !tree.nodes || tree.nodes.length === 0) {
            host.innerHTML = '<div class="note">No tree graph available.</div>';
            return;
          }
          const visibleNodes = tree.nodes.filter(n => n.node_type !== 'blank' && n.x !== null && n.y !== null);
          if (visibleNodes.length === 0) {
            host.innerHTML = '<div class="note">No visible nodes to render.</div>';
            return;
          }
          const nodeMap = {};
          visibleNodes.forEach(n => { nodeMap[n.node_index] = n; });
          const maxDepth = Math.max(...visibleNodes.map(n => n.y || 0), 0);
          const width = Math.max(host.clientWidth || 420, 320);
          const height = 320;
          const padX = 26;
          const padY = 34;
          const usableW = Math.max(width - padX * 2, 120);
          const usableH = Math.max(height - padY * 2, 120);
          const xPx = (x) => padX + (x * usableW);
          const yPx = (y) => {
            if (maxDepth <= 0) return padY + usableH / 2;
            return padY + ((y / maxDepth) * usableH);
          };

          const lineSvg = (tree.edges || [])
            .map(edge => {
              const a = nodeMap[edge.from];
              const b = nodeMap[edge.to];
              if (!a || !b) return '';
              return `<line x1="${xPx(a.x)}" y1="${yPx(a.y)}" x2="${xPx(b.x)}" y2="${yPx(b.y)}" stroke="#9aa8b7" stroke-width="2" />`;
            })
            .join('');

          const nodeSvg = visibleNodes
            .map(node => {
              const cx = xPx(node.x);
              const cy = yPx(node.y);
              const label = escapeHtml((node.label || '').slice(0, 14));
              const nodeText = escapeHtml(`#${node.node_index}`);
              return `
                <g>
                  <circle cx="${cx}" cy="${cy}" r="22" fill="#fff" stroke="#b45309" stroke-width="2"></circle>
                  <text x="${cx}" y="${cy - 2}" text-anchor="middle" font-size="10" font-family="Space Grotesk" fill="#1f2933">${nodeText}</text>
                  <text x="${cx}" y="${cy + 12}" text-anchor="middle" font-size="9" font-family="Space Grotesk" fill="#5c6b7a">${label}</text>
                </g>
              `;
            })
            .join('');

          host.innerHTML = `
            <svg viewBox="0 0 ${width} ${height}" width="100%" height="${height}" preserveAspectRatio="xMidYMid meet">
              <rect x="0" y="0" width="${width}" height="${height}" fill="#fffef8" stroke="#e7cba1" rx="10"></rect>
              ${lineSvg}
              ${nodeSvg}
            </svg>
          `;
          window._treeData = tree;
        }
        async function uiLoadTree() {
          const user = ensureUser();
          if (!user) return;
          const resp = await fetch(`/ui/api/groups/${groupId}/tree?username=${encodeURIComponent(user)}`);
          const data = await resp.json();
          if (data.ok) {
            renderTree(data.data);
          } else {
            const list = document.getElementById('tree-list');
            const graph = document.getElementById('tree-graph');
            if (list) {
              list.innerHTML = `<div class="note">${data.error}</div>`;
            }
            if (graph) {
              graph.innerHTML = `<div class="note">${data.error}</div>`;
            }
          }
          writeOutput(data);
        }
        async function uiLoadKeypackages() {
          const user = ensureUser();
          const list = document.getElementById('keypackage-list');
          if (!user || !list) return;
          const resp = await fetch(`/ui/api/keypackages?username=${encodeURIComponent(user)}`);
          const data = await resp.json();
          if (!data.ok) {
            list.innerHTML = `<div class="note">${data.error}</div>`;
            return;
          }
          const items = data.data.items || [];
          if (items.length === 0) {
            list.innerHTML = '<div class="note">No stored keypackages yet.</div>';
            return;
          }
          items.sort((a, b) => b.created_at - a.created_at);
          list.innerHTML = items.map(item => {
            const created = new Date(item.created_at * 1000).toISOString();
            const published = item.published ? 'published' : 'local only';
            return `
              <div class="list-item">
                <div>
                  <div class="title">${item.id}</div>
                  <div class="muted">created ${created} • ${published}</div>
                </div>
                <div class="row">
                  <button class="ghost" type="button" onclick="uiUseKeypackage('${item.id}')">Use</button>
                  <button class="ghost" type="button" onclick="uiCopyKeypackage('${item.id}')">Copy</button>
                  <button class="ghost" type="button" onclick="uiPublishStoredKeypackage('${item.id}')">Publish</button>
                </div>
              </div>
            `;
          }).join('');
          window._keypackages = items;
        }
        function uiFindKeypackage(id) {
          const list = window._keypackages || [];
          return list.find(item => item.id === id);
        }
        function uiUseKeypackage(id) {
          const item = uiFindKeypackage(id);
          if (!item) return;
          const input = document.getElementById('keypackage-b64');
          if (input) {
            input.value = item.keypackage_b64;
          }
        }
        async function uiCopyKeypackage(id) {
          const item = uiFindKeypackage(id);
          const status = document.getElementById('keypackage-status');
          if (!item) return;
          const payload = item.keypackage_b64;
          if (navigator.clipboard && navigator.clipboard.writeText) {
            await navigator.clipboard.writeText(payload);
          } else {
            const temp = document.createElement('textarea');
            temp.value = payload;
            document.body.appendChild(temp);
            temp.select();
            document.execCommand('copy');
            temp.remove();
          }
          if (status) {
            status.textContent = 'KeyPackage copied to clipboard.';
          }
        }
        async function uiPublishStoredKeypackage(id) {
          const item = uiFindKeypackage(id);
          const user = ensureUser();
          if (!item || !user) return;
          const status = document.getElementById('keypackage-status');
          if (status) {
            status.textContent = 'Publishing...';
          }
          const resp = await fetch('/ui/api/keypackages', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({username: user, keypackage_b64: item.keypackage_b64})
          });
          const data = await resp.json();
          if (status) {
            status.textContent = data.ok ? 'Published.' : (data.error || 'Publish failed.');
          }
          if (data.ok) {
            await uiLoadKeypackages();
          }
        }
        ensureUser();
        uiLoadKeypackages();
        ensureGroupTracked();
        loadGroupState();
        uiLoadTree();
        uiSyncApplyLatest(true);
        window.addEventListener('resize', () => {
          if (window._treeData) {
            renderTreeGraph(window._treeData);
          }
        });
        </script>
        "##;
    let group_json = serde_json::to_string(&group_id).unwrap_or_else(|_| "\"group\"".to_string());
    let body = body_template
        .replace("__GROUP__", &group_id)
        .replace("__GROUP_JSON__", &group_json);
    ui_shell("Group Detail", &body)
}

fn ui_shell(title: &str, body: &str) -> Html<String> {
    Html(format!(
        r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{title}</title>
  <link href="https://fonts.googleapis.com/css2?family=Spectral:wght@300;400;600&family=Space+Grotesk:wght@400;600&display=swap" rel="stylesheet">
  <style>
    :root {{
      --ink: #1f2933;
      --muted: #5c6b7a;
      --accent: #b45309;
      --accent-soft: #fde68a;
      --surface: #fff9f0;
      --control-height: 46px;
      --space-xs: 6px;
      --space-sm: 10px;
      --space-md: 16px;
      --space-lg: 24px;
    }}
    * {{
      box-sizing: border-box;
    }}
    body {{
      margin: 0;
      font-family: "Spectral", "Merriweather", serif;
      color: var(--ink);
      background: radial-gradient(circle at top, #fff6e4 0%, #f6efe1 40%, #f1e7d6 100%);
      min-height: 100vh;
      display: flex;
      justify-content: center;
      padding: 32px 20px;
      overflow-x: hidden;
    }}
    * {{
      min-width: 0;
    }}
    h1, h2, h3 {{
      font-family: "Space Grotesk", sans-serif;
      margin: 0;
    }}
    .panel {{
      max-width: 1100px;
      width: 100%;
      display: grid;
      gap: var(--space-lg);
    }}
    .panel-admin-demo {{
      max-width: 2200px;
    }}
    .hero {{
      display: grid;
      gap: var(--space-sm);
    }}
    .eyebrow {{
      text-transform: uppercase;
      font-family: "Space Grotesk", sans-serif;
      font-size: 12px;
      letter-spacing: 0.2em;
      color: var(--accent);
    }}
    .card {{
      background: var(--surface);
      border: 1px solid #edd5b3;
      border-radius: 18px;
      padding: 24px;
      box-shadow: 0 30px 60px rgba(15, 23, 42, 0.08);
      min-width: 0;
    }}
    .stack {{
      display: grid;
      gap: var(--space-md);
    }}
    .row {{
      display: flex;
      gap: var(--space-sm);
      flex-wrap: wrap;
      align-items: center;
      min-width: 0;
    }}
    .top-left {{
      position: fixed;
      top: 16px;
      left: 16px;
      z-index: 30;
      display: flex;
      gap: var(--space-sm);
    }}
    .grid {{
      display: grid;
      gap: var(--space-md);
      grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
      align-items: stretch;
      min-width: 0;
    }}
    .demo-layout {{
      display: grid;
      grid-template-columns: minmax(320px, 0.8fr) minmax(980px, 2.4fr);
      gap: var(--space-md);
      min-width: 0;
    }}
    .demo-left {{
      display: grid;
      grid-template-rows: minmax(220px, auto) minmax(280px, 1fr);
      gap: var(--space-md);
      min-width: 0;
    }}
    .demo-actions {{
      align-content: start;
    }}
    .demo-action-grid {{
      grid-template-columns: repeat(1, minmax(0, 1fr));
    }}
    .demo-logs {{
      align-content: start;
    }}
    .demo-tree {{
      align-content: start;
      min-height: 740px;
    }}
    .tree-view-grid {{
      display: grid;
      grid-template-columns: minmax(320px, 1fr) minmax(320px, 1fr);
      gap: var(--space-md);
      min-width: 0;
    }}
    .tree-graph {{
      min-width: 0;
      width: 100%;
      overflow: hidden;
      border-radius: 10px;
      min-height: 660px;
    }}
    label {{
      display: grid;
      gap: var(--space-xs);
      font-family: "Space Grotesk", sans-serif;
      font-size: 14px;
    }}
    input,
    select,
    textarea {{
      padding: 10px 12px;
      border-radius: 10px;
      border: 1px solid #e4c89b;
      font-size: 14px;
      font-family: "Space Grotesk", sans-serif;
      height: var(--control-height);
      width: 100%;
      max-width: 100%;
      min-width: 0;
    }}
    button {{
      border: none;
      padding: 10px 14px;
      border-radius: 10px;
      font-family: "Space Grotesk", sans-serif;
      cursor: pointer;
      height: var(--control-height);
    }}
    .row > button,
    .row > input,
    .row > select {{
      flex: 1 1 140px;
      width: 100%;
    }}
    .row > button {{
      flex: 1 1 140px;
      white-space: nowrap;
    }}
    @media (max-width: 900px) {{
      .panel {{
        padding-top: 32px;
      }}
      .grid {{
        grid-template-columns: 1fr;
      }}
      .tree-view-grid {{
        grid-template-columns: 1fr;
      }}
      .demo-layout {{
        grid-template-columns: 1fr;
      }}
      .demo-left {{
        grid-template-rows: auto auto;
      }}
      .list-item {{
        flex-direction: column;
        align-items: flex-start;
        gap: 12px;
      }}
      .row > button,
      .row > input,
      .row > select {{
        width: 100%;
      }}
    }}
    .primary {{
      background: var(--accent);
      color: #fff;
    }}
    .ghost {{
      background: #fff;
      border: 1px solid #e4c89b;
      color: var(--ink);
    }}
    .muted {{
      color: var(--muted);
    }}
    .list {{
      display: grid;
      gap: var(--space-sm);
    }}
    .list-item {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 12px;
      border: 1px solid #eed9bb;
      border-radius: 12px;
      background: #fff;
      min-width: 0;
    }}
    .link {{
      color: var(--accent);
      text-decoration: none;
      font-family: "Space Grotesk", sans-serif;
    }}
    .note {{
      background: #fff7e6;
      padding: 12px;
      border-radius: 10px;
      border: 1px dashed #e7cba1;
      color: var(--muted);
    }}
    details {{
      border: 1px solid #e7cba1;
      border-radius: 12px;
      padding: var(--space-sm);
      background: #fffaf2;
      box-shadow: 0 12px 24px rgba(15, 23, 42, 0.08);
    }}
    .action-block {{
      background: #fffef8;
    }}
    summary {{
      cursor: pointer;
      font-family: "Space Grotesk", sans-serif;
      margin-bottom: var(--space-xs);
    }}
    .divider {{
      height: 1px;
      background: #ead9be;
      margin: var(--space-md) 0;
    }}
    .card-sub {{
      background: #fbfbfb;
      border: 1px solid #e2e8f0;
      border-radius: 14px;
      padding: var(--space-md);
      display: grid;
      gap: var(--space-md);
      box-shadow: 0 14px 28px rgba(15, 23, 42, 0.08);
      min-height: 100%;
      min-width: 0;
      align-content: start;
      grid-auto-rows: min-content;
    }}
    .shadowed {{
      box-shadow: 0 16px 30px rgba(15, 23, 42, 0.12);
    }}
    .card-sub > button,
    .card-sub .row > button {{
      width: 100%;
    }}
    .card-sub select,
    .card-sub input,
    .card-sub textarea {{
      width: 100%;
    }}
    .output {{
      background: #0f172a;
      color: #f8fafc;
      padding: 16px;
      border-radius: 12px;
      min-height: 120px;
      white-space: pre-wrap;
    }}
    .note.error {{
      border-color: #f2a3a3;
      background: #fff2f2;
      color: #7a1f1f;
    }}
    .kp-preview {{
      border: 1px solid #e4c89b;
      border-radius: 10px;
      padding: 10px 12px;
      min-height: var(--control-height);
      background: #fffdf7;
      font-family: "Space Grotesk", sans-serif;
      font-size: 13px;
      color: var(--muted);
      overflow: hidden;
      white-space: nowrap;
      text-overflow: ellipsis;
      width: 100%;
      max-width: 100%;
    }}
    .kp-full {{
      height: 140px;
      resize: none;
      overflow: auto;
      width: 100%;
      max-width: 100%;
      word-break: break-all;
    }}
    .is-hidden {{
      display: none;
    }}
  </style>
</head>
<body>
  {body}
</body>
</html>"#,
        title = title,
        body = body
    ))
}

async fn api_register(
    State(state): State<UiState>,
    Json(payload): Json<AuthPayload>,
) -> impl IntoResponse {
    match register_user(&state, &payload.username, &payload.password).await {
        Ok(value) => {
            let mut resp = Json(ApiResult {
                ok: true,
                data: Some(value),
                error: None,
            })
            .into_response();
            if let Ok(header_value) =
                HeaderValue::from_str(&ui_login_cookie_value(&payload.username))
            {
                resp.headers_mut().insert(SET_COOKIE, header_value);
            }
            resp
        }
        Err(err) => Json(ApiResult::<serde_json::Value> {
            ok: false,
            data: None,
            error: Some(err),
        })
        .into_response(),
    }
}

async fn api_login(
    State(state): State<UiState>,
    Json(payload): Json<AuthPayload>,
) -> impl IntoResponse {
    match login_user(&state, &payload.username, &payload.password).await {
        Ok(value) => {
            let mut resp = Json(ApiResult {
                ok: true,
                data: Some(value),
                error: None,
            })
            .into_response();
            if let Ok(header_value) =
                HeaderValue::from_str(&ui_login_cookie_value(&payload.username))
            {
                resp.headers_mut().insert(SET_COOKIE, header_value);
            }
            resp
        }
        Err(err) => Json(ApiResult::<serde_json::Value> {
            ok: false,
            data: None,
            error: Some(err),
        })
        .into_response(),
    }
}

async fn api_logout(
    State(state): State<UiState>,
    Json(payload): Json<LogoutPayload>,
) -> impl IntoResponse {
    match logout_user(&state, &payload.username).await {
        Ok(value) => {
            let mut resp = Json(ApiResult {
                ok: true,
                data: Some(value),
                error: None,
            })
            .into_response();
            if let Ok(header_value) = HeaderValue::from_str(ui_logout_cookie_value()) {
                resp.headers_mut().insert(SET_COOKIE, header_value);
            }
            resp
        }
        Err(err) => Json(ApiResult::<serde_json::Value> {
            ok: false,
            data: None,
            error: Some(err),
        })
        .into_response(),
    }
}

async fn api_admin_users(
    State(state): State<UiState>,
    Query(query): Query<UserQuery>,
) -> impl IntoResponse {
    match ds_list_admin_users(&state, &query.username).await {
        Ok(value) => Json(ApiResult {
            ok: true,
            data: Some(value),
            error: None,
        }),
        Err(err) => Json(ApiResult::<serde_json::Value> {
            ok: false,
            data: None,
            error: Some(err),
        }),
    }
}

async fn api_admin_groups(
    State(state): State<UiState>,
    Query(query): Query<UserQuery>,
) -> impl IntoResponse {
    match ds_list_admin_groups(&state, &query.username).await {
        Ok(value) => Json(ApiResult {
            ok: true,
            data: Some(value),
            error: None,
        }),
        Err(err) => Json(ApiResult::<serde_json::Value> {
            ok: false,
            data: None,
            error: Some(err),
        }),
    }
}

async fn api_admin_demos(
    State(state): State<UiState>,
    Query(query): Query<UserQuery>,
) -> impl IntoResponse {
    match load_admin_demos(&state, &query.username) {
        Ok(value) => Json(ApiResult {
            ok: true,
            data: Some(value),
            error: None,
        }),
        Err(err) => Json(ApiResult::<AdminDemoIndex> {
            ok: false,
            data: None,
            error: Some(err),
        }),
    }
}

async fn api_admin_create_demo(
    State(state): State<UiState>,
    Json(payload): Json<AdminDemoCreatePayload>,
) -> impl IntoResponse {
    match create_admin_demo(&state, &payload.username, payload.title.as_deref()) {
        Ok(value) => Json(ApiResult {
            ok: true,
            data: Some(value),
            error: None,
        }),
        Err(err) => Json(ApiResult::<AdminDemoRecord> {
            ok: false,
            data: None,
            error: Some(err),
        }),
    }
}

async fn api_admin_demo_detail(
    AxumPath(demo_id): AxumPath<String>,
    State(state): State<UiState>,
    Query(query): Query<UserQuery>,
) -> impl IntoResponse {
    match load_admin_demo_detail(&state, &query.username, &demo_id) {
        Ok(value) => Json(ApiResult {
            ok: true,
            data: Some(value),
            error: None,
        }),
        Err(err) => Json(ApiResult::<AdminDemoDetail> {
            ok: false,
            data: None,
            error: Some(err),
        }),
    }
}

async fn api_admin_demo_action_add(
    AxumPath(demo_id): AxumPath<String>,
    State(state): State<UiState>,
    Json(payload): Json<AdminDemoAddActionPayload>,
) -> impl IntoResponse {
    match apply_admin_demo_add_action(&state, &demo_id, &payload) {
        Ok(value) => Json(ApiResult {
            ok: true,
            data: Some(value),
            error: None,
        }),
        Err(err) => Json(ApiResult::<AdminDemoActionResponse> {
            ok: false,
            data: None,
            error: Some(err),
        }),
    }
}

async fn api_admin_demo_action_remove(
    AxumPath(demo_id): AxumPath<String>,
    State(state): State<UiState>,
    Json(payload): Json<AdminDemoRemoveActionPayload>,
) -> impl IntoResponse {
    match apply_admin_demo_remove_action(&state, &demo_id, &payload) {
        Ok(value) => Json(ApiResult {
            ok: true,
            data: Some(value),
            error: None,
        }),
        Err(err) => Json(ApiResult::<AdminDemoActionResponse> {
            ok: false,
            data: None,
            error: Some(err),
        }),
    }
}

async fn api_admin_demo_action_update(
    AxumPath(demo_id): AxumPath<String>,
    State(state): State<UiState>,
    Json(payload): Json<AdminDemoUpdateActionPayload>,
) -> impl IntoResponse {
    match apply_admin_demo_update_action(&state, &demo_id, &payload) {
        Ok(value) => Json(ApiResult {
            ok: true,
            data: Some(value),
            error: None,
        }),
        Err(err) => Json(ApiResult::<AdminDemoActionResponse> {
            ok: false,
            data: None,
            error: Some(err),
        }),
    }
}

async fn api_groups(
    State(state): State<UiState>,
    Query(query): Query<UserQuery>,
) -> impl IntoResponse {
    match load_groups(&state, &query.username) {
        Ok(groups) => Json(ApiResult {
            ok: true,
            data: Some(groups),
            error: None,
        }),
        Err(err) => Json(ApiResult::<GroupList> {
            ok: false,
            data: None,
            error: Some(err),
        }),
    }
}

async fn api_groups_open(
    State(state): State<UiState>,
    Json(payload): Json<GroupOpenPayload>,
) -> impl IntoResponse {
    match add_group(&state, &payload.username, &payload.group_id) {
        Ok(groups) => Json(ApiResult {
            ok: true,
            data: Some(groups),
            error: None,
        }),
        Err(err) => Json(ApiResult::<GroupList> {
            ok: false,
            data: None,
            error: Some(err),
        }),
    }
}

async fn api_groups_remove(
    State(state): State<UiState>,
    Json(payload): Json<GroupRemovePayload>,
) -> impl IntoResponse {
    match remove_group(&state, &payload.username, &payload.group_id) {
        Ok(groups) => Json(ApiResult {
            ok: true,
            data: Some(groups),
            error: None,
        }),
        Err(err) => Json(ApiResult::<GroupList> {
            ok: false,
            data: None,
            error: Some(err),
        }),
    }
}

async fn api_group_state(
    AxumPath(group_id): AxumPath<String>,
    State(state): State<UiState>,
    Query(query): Query<UserQuery>,
) -> impl IntoResponse {
    match load_group_state(&state, &query.username, &group_id) {
        Ok(group_state) => {
            let status = GroupStateStatus {
                group_id: group_state.group_id.clone(),
                epoch: group_state.epoch,
                own_leaf_index: group_state.own_leaf_index,
                leaf_count: group_state.ratchet_tree.leaf_count(),
                pending_proposals: group_state.pending_proposals.len(),
                state_path: group_state_path(&state.state_dir, &query.username, &group_id)
                    .to_string_lossy()
                    .to_string(),
            };
            Json(ApiResult {
                ok: true,
                data: Some(status),
                error: None,
            })
        }
        Err(err) => Json(ApiResult::<GroupStateStatus> {
            ok: false,
            data: None,
            error: Some(err),
        }),
    }
}

async fn api_group_bootstrap(
    AxumPath(group_id): AxumPath<String>,
    State(state): State<UiState>,
    Json(payload): Json<UserQuery>,
) -> impl IntoResponse {
    match bootstrap_group_state(&state, &payload.username, &group_id).await {
        Ok(status) => Json(ApiResult {
            ok: true,
            data: Some(status),
            error: None,
        }),
        Err(err) => Json(ApiResult::<GroupBootstrapStatus> {
            ok: false,
            data: None,
            error: Some(err),
        }),
    }
}

async fn api_group_tree(
    AxumPath(group_id): AxumPath<String>,
    State(state): State<UiState>,
    Query(query): Query<UserQuery>,
) -> impl IntoResponse {
    match load_group_state(&state, &query.username, &group_id) {
        Ok(group_state) => {
            let labels = load_group_labels(&state, &query.username, &group_id).unwrap_or_default();
            let view = build_tree_view(&group_state, &query.username, &labels);
            Json(ApiResult {
                ok: true,
                data: Some(view),
                error: None,
            })
        }
        Err(err) => Json(ApiResult::<TreeView> {
            ok: false,
            data: None,
            error: Some(err),
        }),
    }
}

async fn api_action_add(
    AxumPath(group_id): AxumPath<String>,
    State(state): State<UiState>,
    Json(payload): Json<ActionAddPayload>,
) -> impl IntoResponse {
    match action_add_proposal(&state, &payload, &group_id).await {
        Ok(value) => Json(ApiResult {
            ok: true,
            data: Some(value),
            error: None,
        }),
        Err(err) => Json(ApiResult::<ActionProposalResponse> {
            ok: false,
            data: None,
            error: Some(err),
        }),
    }
}

async fn api_action_remove(
    AxumPath(group_id): AxumPath<String>,
    State(state): State<UiState>,
    Json(payload): Json<ActionRemovePayload>,
) -> impl IntoResponse {
    match action_remove_proposal(&state, &payload, &group_id).await {
        Ok(value) => Json(ApiResult {
            ok: true,
            data: Some(value),
            error: None,
        }),
        Err(err) => Json(ApiResult::<ActionProposalResponse> {
            ok: false,
            data: None,
            error: Some(err),
        }),
    }
}

async fn api_action_update(
    AxumPath(group_id): AxumPath<String>,
    State(state): State<UiState>,
    Json(payload): Json<ActionUpdatePayload>,
) -> impl IntoResponse {
    match action_update_proposal(&state, &payload, &group_id).await {
        Ok(value) => Json(ApiResult {
            ok: true,
            data: Some(value),
            error: None,
        }),
        Err(err) => Json(ApiResult::<ActionProposalResponse> {
            ok: false,
            data: None,
            error: Some(err),
        }),
    }
}

async fn api_list_messages(
    AxumPath(group_id): AxumPath<String>,
    State(state): State<UiState>,
    Query(query): Query<ListMessagesQuery>,
) -> impl IntoResponse {
    match ds_list_messages(&state, &query.username, &group_id, &query).await {
        Ok(value) => Json(ApiResult {
            ok: true,
            data: Some(value),
            error: None,
        }),
        Err(err) => Json(ApiResult::<serde_json::Value> {
            ok: false,
            data: None,
            error: Some(err),
        }),
    }
}

async fn api_fetch_message(
    AxumPath((group_id, message_id)): AxumPath<(String, i64)>,
    State(state): State<UiState>,
    Query(query): Query<UserQuery>,
) -> impl IntoResponse {
    match ds_fetch_group_message(&state, &query.username, &group_id, message_id).await {
        Ok(value) => Json(ApiResult {
            ok: true,
            data: Some(value),
            error: None,
        }),
        Err(err) => Json(ApiResult::<serde_json::Value> {
            ok: false,
            data: None,
            error: Some(err),
        }),
    }
}

async fn api_send_app_message(
    AxumPath(group_id): AxumPath<String>,
    State(state): State<UiState>,
    Json(payload): Json<GroupMessagePayload>,
) -> impl IntoResponse {
    match ds_send_app_message(&state, &payload.username, &group_id, &payload.message).await {
        Ok(value) => Json(ApiResult {
            ok: true,
            data: Some(value),
            error: None,
        }),
        Err(err) => Json(ApiResult::<serde_json::Value> {
            ok: false,
            data: None,
            error: Some(err),
        }),
    }
}

async fn api_list_app_messages(
    AxumPath(group_id): AxumPath<String>,
    State(state): State<UiState>,
    Query(query): Query<ListAppMessagesQuery>,
) -> impl IntoResponse {
    match ds_list_app_messages(&state, &query.username, &group_id, &query).await {
        Ok(value) => Json(ApiResult {
            ok: true,
            data: Some(value),
            error: None,
        }),
        Err(err) => Json(ApiResult::<serde_json::Value> {
            ok: false,
            data: None,
            error: Some(err),
        }),
    }
}

async fn api_fetch_app_message(
    AxumPath((group_id, message_id)): AxumPath<(String, i64)>,
    State(state): State<UiState>,
    Query(query): Query<UserQuery>,
) -> impl IntoResponse {
    match ds_fetch_app_message(&state, &query.username, &group_id, message_id).await {
        Ok(value) => Json(ApiResult {
            ok: true,
            data: Some(value),
            error: None,
        }),
        Err(err) => Json(ApiResult::<serde_json::Value> {
            ok: false,
            data: None,
            error: Some(err),
        }),
    }
}

async fn api_submit_proposal(
    AxumPath(group_id): AxumPath<String>,
    State(state): State<UiState>,
    Json(payload): Json<ProposalPayload>,
) -> impl IntoResponse {
    match ds_submit_proposal(&state, &payload.username, &group_id, &payload.proposal_b64).await {
        Ok(value) => Json(ApiResult {
            ok: true,
            data: Some(value),
            error: None,
        }),
        Err(err) => Json(ApiResult::<serde_json::Value> {
            ok: false,
            data: None,
            error: Some(err),
        }),
    }
}

async fn api_submit_commit(
    AxumPath(group_id): AxumPath<String>,
    State(state): State<UiState>,
    Json(payload): Json<CommitPayload>,
) -> impl IntoResponse {
    match ds_submit_commit(
        &state,
        &payload.username,
        &group_id,
        &payload.commit_b64,
        payload.path_update_b64.as_deref(),
        payload.welcome_b64.as_deref(),
    )
    .await
    {
        Ok(value) => Json(ApiResult {
            ok: true,
            data: Some(value),
            error: None,
        }),
        Err(err) => Json(ApiResult::<serde_json::Value> {
            ok: false,
            data: None,
            error: Some(err),
        }),
    }
}

async fn api_commit_from_pending(
    AxumPath(group_id): AxumPath<String>,
    State(state): State<UiState>,
    Json(payload): Json<CommitFromPendingPayload>,
) -> impl IntoResponse {
    match action_commit_from_pending(&state, &payload, &group_id).await {
        Ok(value) => Json(ApiResult {
            ok: true,
            data: Some(value),
            error: None,
        }),
        Err(err) => Json(ApiResult::<CommitFromPendingResponse> {
            ok: false,
            data: None,
            error: Some(err),
        }),
    }
}

async fn api_sync_apply_latest(
    AxumPath(group_id): AxumPath<String>,
    State(state): State<UiState>,
    Json(payload): Json<SyncApplyPayload>,
) -> impl IntoResponse {
    match action_sync_apply_latest(&state, &payload, &group_id).await {
        Ok(value) => Json(ApiResult {
            ok: true,
            data: Some(value),
            error: None,
        }),
        Err(err) => Json(ApiResult::<SyncApplyResponse> {
            ok: false,
            data: None,
            error: Some(err),
        }),
    }
}

async fn api_join_from_latest(
    AxumPath(group_id): AxumPath<String>,
    State(state): State<UiState>,
    Json(payload): Json<JoinFromLatestPayload>,
) -> impl IntoResponse {
    match action_join_from_latest(&state, &payload, &group_id).await {
        Ok(value) => Json(ApiResult {
            ok: true,
            data: Some(value),
            error: None,
        }),
        Err(err) => Json(ApiResult::<JoinFromLatestResponse> {
            ok: false,
            data: None,
            error: Some(err),
        }),
    }
}

async fn api_generate_keypackage(
    State(state): State<UiState>,
    Json(payload): Json<KeyPackageGeneratePayload>,
) -> impl IntoResponse {
    match generate_and_publish_keypackage(&state, &payload.username).await {
        Ok(value) => Json(ApiResult {
            ok: true,
            data: Some(value),
            error: None,
        }),
        Err(err) => Json(ApiResult::<KeyPackageGenerateResponse> {
            ok: false,
            data: None,
            error: Some(err),
        }),
    }
}

async fn api_list_keypackages(
    State(state): State<UiState>,
    Query(query): Query<UserQuery>,
) -> impl IntoResponse {
    match load_keypackages(&state, &query.username) {
        Ok(list) => Json(ApiResult {
            ok: true,
            data: Some(list),
            error: None,
        }),
        Err(err) => Json(ApiResult::<KeyPackageList> {
            ok: false,
            data: None,
            error: Some(err),
        }),
    }
}

async fn api_publish_keypackage(
    State(state): State<UiState>,
    Json(payload): Json<KeyPackagePublishPayload>,
) -> impl IntoResponse {
    match ds_publish_keypackage(&state, &payload.username, &payload.keypackage_b64).await {
        Ok(value) => {
            let _ = upsert_keypackage_record(
                &state,
                &payload.username,
                &payload.keypackage_b64,
                None,
                true,
            );
            Json(ApiResult {
                ok: true,
                data: Some(value),
                error: None,
            })
        }
        Err(err) => Json(ApiResult::<serde_json::Value> {
            ok: false,
            data: None,
            error: Some(err),
        }),
    }
}

async fn api_fetch_keypackage(
    AxumPath(target): AxumPath<String>,
    State(state): State<UiState>,
    Query(query): Query<UserQuery>,
) -> impl IntoResponse {
    match ds_fetch_keypackage(&state, &query.username, &target).await {
        Ok(value) => Json(ApiResult {
            ok: true,
            data: Some(value),
            error: None,
        }),
        Err(err) => Json(ApiResult::<serde_json::Value> {
            ok: false,
            data: None,
            error: Some(err),
        }),
    }
}

fn state_path(state_dir: &Path, username: &str) -> PathBuf {
    state_dir.join(format!("user-{}.json", sanitize(username)))
}

fn groups_path(state_dir: &Path, username: &str) -> PathBuf {
    state_dir.join(format!("user-{}-groups.json", sanitize(username)))
}

fn keypackages_path(state_dir: &Path, username: &str) -> PathBuf {
    state_dir.join(format!("user-{}-keypackages.json", sanitize(username)))
}

fn admin_demo_root_path(state_dir: &Path) -> PathBuf {
    state_dir.join("demo")
}

fn admin_demo_index_path(state_dir: &Path) -> PathBuf {
    admin_demo_root_path(state_dir).join("index.json")
}

fn admin_demo_dir_path(state_dir: &Path, demo_id: &str) -> PathBuf {
    admin_demo_root_path(state_dir).join(sanitize(demo_id))
}

fn admin_demo_manifest_path(state_dir: &Path, demo_id: &str) -> PathBuf {
    admin_demo_dir_path(state_dir, demo_id).join("manifest.json")
}

fn admin_demo_state_path(state_dir: &Path, demo_id: &str) -> PathBuf {
    admin_demo_dir_path(state_dir, demo_id).join("state.json")
}

fn group_state_path(state_dir: &Path, username: &str, group_id: &str) -> PathBuf {
    state_dir.join(format!(
        "user-{}-group-{}.bin",
        sanitize(username),
        sanitize(group_id)
    ))
}

fn group_labels_path(state_dir: &Path, username: &str, group_id: &str) -> PathBuf {
    state_dir.join(format!(
        "user-{}-group-{}-labels.json",
        sanitize(username),
        sanitize(group_id)
    ))
}

fn sanitize(value: &str) -> String {
    value
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn ensure_admin_username(username: &str) -> Result<(), String> {
    if username == ADMIN_USERNAME {
        Ok(())
    } else {
        Err("admin access required".to_string())
    }
}

fn load_admin_demo_index(state: &UiState) -> Result<AdminDemoIndex, String> {
    let path = admin_demo_index_path(&state.state_dir);
    if !path.exists() {
        return Ok(AdminDemoIndex::default());
    }
    let bytes = fs::read(&path).map_err(|err| format!("read demo index: {err}"))?;
    serde_json::from_slice(&bytes).map_err(|err| format!("parse demo index: {err}"))
}

fn initial_admin_demo_state() -> AdminDemoState {
    let mut state = AdminDemoState {
        epoch: 0,
        leaf_slots: vec![Some(AdminDemoLeafSlot {
            username: "A".to_string(),
            key_generation: 1,
        })],
        logs: Vec::new(),
        last_action: Some("init: A".to_string()),
    };
    append_demo_log_block(
        &mut state,
        vec![
            "RFC9420 Demo Init: initialized single-member ratchet tree with A at LeafIndex=0 (NodeIndex=0, root)".to_string(),
            "RFC9420 GroupContext: epoch set to 0".to_string(),
        ],
    );
    state
}

fn migrate_legacy_admin_demo_state(legacy: LegacyAdminDemoState) -> Result<AdminDemoState, String> {
    let mut leaf_slots: Vec<Option<AdminDemoLeafSlot>> = Vec::new();
    let mut seen_leaf_indices = HashSet::new();
    for member in legacy.members {
        if member.username.trim().is_empty() {
            return Err("legacy demo state contains empty member username".to_string());
        }
        if !seen_leaf_indices.insert(member.leaf_index) {
            return Err(format!(
                "legacy demo state contains duplicate leaf_index {}",
                member.leaf_index
            ));
        }
        if member.leaf_index >= leaf_slots.len() {
            leaf_slots.resize(member.leaf_index + 1, None);
        }
        leaf_slots[member.leaf_index] = Some(AdminDemoLeafSlot {
            username: member.username,
            key_generation: member.key_generation,
        });
    }
    Ok(AdminDemoState {
        epoch: legacy.epoch,
        leaf_slots,
        logs: legacy.logs,
        last_action: legacy.last_action,
    })
}

fn decode_admin_demo_state(bytes: &[u8]) -> Result<AdminDemoState, String> {
    match serde_json::from_slice::<AdminDemoState>(bytes) {
        Ok(state) => Ok(state),
        Err(primary_err) => {
            let legacy =
                serde_json::from_slice::<LegacyAdminDemoState>(bytes).map_err(|legacy_err| {
                    format!("parse demo state: {primary_err}; legacy parse failed: {legacy_err}")
                })?;
            migrate_legacy_admin_demo_state(legacy)
        }
    }
}

fn active_members_from_leaf_slots(
    leaf_slots: &[Option<AdminDemoLeafSlot>],
) -> Vec<AdminDemoMember> {
    let mut members = Vec::new();
    for (leaf_index, slot) in leaf_slots.iter().enumerate() {
        if let Some(slot) = slot {
            members.push(AdminDemoMember {
                username: slot.username.clone(),
                leaf_index,
                key_generation: slot.key_generation,
            });
        }
    }
    members
}

fn find_leaf_index_for_username(
    leaf_slots: &[Option<AdminDemoLeafSlot>],
    username: &str,
) -> Option<usize> {
    leaf_slots
        .iter()
        .enumerate()
        .find_map(|(leaf_index, slot)| {
            slot.as_ref().and_then(|slot| {
                if slot.username == username {
                    Some(leaf_index)
                } else {
                    None
                }
            })
        })
}

fn first_blank_demo_leaf_index(leaf_slots: &[Option<AdminDemoLeafSlot>]) -> Option<usize> {
    leaf_slots
        .iter()
        .enumerate()
        .find_map(|(leaf_index, slot)| {
            if slot.is_none() {
                Some(leaf_index)
            } else {
                None
            }
        })
}

fn active_member_count(leaf_slots: &[Option<AdminDemoLeafSlot>]) -> usize {
    leaf_slots.iter().filter(|slot| slot.is_some()).count()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DemoAddPlacement {
    ReusedBlankLeaf {
        leaf_index: usize,
    },
    ExtendedTree {
        leaf_index: usize,
        previous_leaf_count: usize,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DemoRemoveTrimResult {
    previous_leaf_count: usize,
    new_leaf_count: usize,
}

fn place_added_member_in_demo_tree(
    leaf_slots: &mut Vec<Option<AdminDemoLeafSlot>>,
    added_username: &str,
) -> DemoAddPlacement {
    if let Some(blank_leaf) = first_blank_demo_leaf_index(leaf_slots) {
        leaf_slots[blank_leaf] = Some(AdminDemoLeafSlot {
            username: added_username.to_string(),
            key_generation: 1,
        });
        DemoAddPlacement::ReusedBlankLeaf {
            leaf_index: blank_leaf,
        }
    } else {
        let previous_leaf_count = leaf_slots.len();
        leaf_slots.push(Some(AdminDemoLeafSlot {
            username: added_username.to_string(),
            key_generation: 1,
        }));
        DemoAddPlacement::ExtendedTree {
            leaf_index: previous_leaf_count,
            previous_leaf_count,
        }
    }
}

fn trim_trailing_blank_demo_leaves(
    leaf_slots: &mut Vec<Option<AdminDemoLeafSlot>>,
) -> DemoRemoveTrimResult {
    let previous_leaf_count = leaf_slots.len();
    while matches!(leaf_slots.last(), Some(None)) {
        leaf_slots.pop();
    }
    DemoRemoveTrimResult {
        previous_leaf_count,
        new_leaf_count: leaf_slots.len(),
    }
}

fn node_count_for_leaf_count(leaf_count: usize) -> usize {
    if leaf_count == 0 {
        0
    } else {
        2 * leaf_count - 1
    }
}

fn leaf_node_index(leaf_index: usize) -> usize {
    leaf_index.saturating_mul(2)
}

fn append_demo_log_block(demo_state: &mut AdminDemoState, lines: Vec<String>) {
    let ts = now_unix();
    for line in lines {
        demo_state.logs.push(AdminDemoLogEntry {
            timestamp: ts,
            line,
            separator: false,
        });
    }
    demo_state.logs.push(AdminDemoLogEntry {
        timestamp: ts,
        line: "--------------------".to_string(),
        separator: true,
    });
}

fn load_admin_demo_state(state: &UiState, demo_id: &str) -> Result<AdminDemoState, String> {
    let path = admin_demo_state_path(&state.state_dir, demo_id);
    if !path.exists() {
        return Err(format!("demo state missing at {}", path.to_string_lossy()));
    }
    let bytes = fs::read(&path).map_err(|err| format!("read demo state: {err}"))?;
    decode_admin_demo_state(&bytes)
}

fn save_admin_demo_state(
    state: &UiState,
    demo_id: &str,
    demo_state: &AdminDemoState,
) -> Result<(), String> {
    let dir = admin_demo_dir_path(&state.state_dir, demo_id);
    fs::create_dir_all(&dir).map_err(|err| format!("create demo dir: {err}"))?;
    let path = admin_demo_state_path(&state.state_dir, demo_id);
    let bytes = serde_json::to_vec_pretty(demo_state).map_err(|err| err.to_string())?;
    fs::write(path, bytes).map_err(|err| format!("write demo state: {err}"))
}

fn touch_admin_demo_updated_at(
    state: &UiState,
    demo_id: &str,
    updated_at: i64,
) -> Result<(), String> {
    let mut index = load_admin_demo_index(state)?;
    if let Some(item) = index.items.iter_mut().find(|item| item.id == demo_id) {
        item.updated_at = updated_at;
        let manifest_path = admin_demo_manifest_path(&state.state_dir, demo_id);
        let manifest_bytes = serde_json::to_vec_pretty(item).map_err(|err| err.to_string())?;
        fs::write(manifest_path, manifest_bytes).map_err(|err| format!("write manifest: {err}"))?;
        save_admin_demo_index(state, &index)?;
        Ok(())
    } else {
        Err(format!("demo {} not found", demo_id))
    }
}

fn save_admin_demo_index(state: &UiState, index: &AdminDemoIndex) -> Result<(), String> {
    let root = admin_demo_root_path(&state.state_dir);
    fs::create_dir_all(&root).map_err(|err| format!("create demo root: {err}"))?;
    let path = admin_demo_index_path(&state.state_dir);
    let bytes = serde_json::to_vec_pretty(index).map_err(|err| err.to_string())?;
    fs::write(path, bytes).map_err(|err| format!("write demo index: {err}"))
}

fn load_admin_demos(state: &UiState, username: &str) -> Result<AdminDemoIndex, String> {
    ensure_admin_username(username)?;
    let mut index = load_admin_demo_index(state)?;
    index.items.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    Ok(index)
}

fn create_admin_demo(
    state: &UiState,
    username: &str,
    title: Option<&str>,
) -> Result<AdminDemoRecord, String> {
    ensure_admin_username(username)?;
    let now = now_unix();
    let demo_id = format!("demo-{}-{}", now, rand::random::<u16>());
    let demo_title = title
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(ToString::to_string)
        .unwrap_or_else(|| format!("Demo {}", now));

    let demo_dir = admin_demo_dir_path(&state.state_dir, &demo_id);
    fs::create_dir_all(&demo_dir).map_err(|err| format!("create demo dir: {err}"))?;

    let record = AdminDemoRecord {
        id: demo_id.clone(),
        title: demo_title,
        created_at: now,
        updated_at: now,
    };

    let manifest_path = admin_demo_manifest_path(&state.state_dir, &demo_id);
    let manifest_bytes = serde_json::to_vec_pretty(&record).map_err(|err| err.to_string())?;
    fs::write(&manifest_path, manifest_bytes).map_err(|err| format!("write manifest: {err}"))?;
    save_admin_demo_state(state, &demo_id, &initial_admin_demo_state())?;

    let mut index = load_admin_demo_index(state)?;
    index.items.retain(|item| item.id != record.id);
    index.items.push(record.clone());
    save_admin_demo_index(state, &index)?;

    Ok(record)
}

fn load_admin_demo_detail(
    state: &UiState,
    username: &str,
    demo_id: &str,
) -> Result<AdminDemoDetail, String> {
    ensure_admin_username(username)?;
    let index = load_admin_demo_index(state)?;
    let Some(record) = index.items.into_iter().find(|item| item.id == demo_id) else {
        return Err(format!("demo {} not found", demo_id));
    };
    let demo_state = load_admin_demo_state(state, &record.id)?;
    let root = admin_demo_dir_path(&state.state_dir, &record.id);
    let manifest = admin_demo_manifest_path(&state.state_dir, &record.id);
    let members = active_members_from_leaf_slots(&demo_state.leaf_slots);
    let leaf_count = demo_state.leaf_slots.len();
    Ok(AdminDemoDetail {
        id: record.id,
        title: record.title,
        created_at: record.created_at,
        updated_at: record.updated_at,
        root_dir: root.to_string_lossy().to_string(),
        manifest_path: manifest.to_string_lossy().to_string(),
        epoch: demo_state.epoch,
        leaf_count,
        node_count: node_count_for_leaf_count(leaf_count),
        members,
        logs: demo_state.logs,
    })
}

fn apply_admin_demo_add_action(
    state: &UiState,
    demo_id: &str,
    payload: &AdminDemoAddActionPayload,
) -> Result<AdminDemoActionResponse, String> {
    ensure_admin_username(&payload.username)?;
    let adder = payload.adder.trim();
    let added = payload.added.trim();
    if adder.is_empty() || added.is_empty() {
        return Err("adder and added are required".to_string());
    }
    let mut demo_state = load_admin_demo_state(state, demo_id)?;
    if find_leaf_index_for_username(&demo_state.leaf_slots, adder).is_none() {
        return Err(format!("adder {} is not a member", adder));
    }
    if find_leaf_index_for_username(&demo_state.leaf_slots, added).is_some() {
        return Err(format!("member {} already exists", added));
    }
    let previous_epoch = demo_state.epoch;
    let placement = place_added_member_in_demo_tree(&mut demo_state.leaf_slots, added);
    let (new_leaf_index, placement_line) = match placement {
        DemoAddPlacement::ReusedBlankLeaf { leaf_index } => (
            leaf_index,
            format!(
                "RFC9420 RatchetTree Add: filled leftmost blank LeafIndex={} (NodeIndex={}) with {}",
                leaf_index,
                leaf_node_index(leaf_index),
                added
            ),
        ),
        DemoAddPlacement::ExtendedTree {
            leaf_index,
            previous_leaf_count,
        } => (
            leaf_index,
            format!(
                "RFC9420 RatchetTree Add: no blank leaves; extended right edge leaf_count {} -> {} and placed {} at LeafIndex={} (NodeIndex={})",
                previous_leaf_count,
                previous_leaf_count.saturating_add(1),
                added,
                leaf_index,
                leaf_node_index(leaf_index)
            ),
        ),
    };
    demo_state.epoch = demo_state.epoch.saturating_add(1);
    let new_epoch = demo_state.epoch;
    let action_line = format!("add: {} added {}", adder, added);
    demo_state.last_action = Some(action_line.clone());
    append_demo_log_block(
        &mut demo_state,
        vec![
            format!(
                "RFC9420 Proposal Add: sender={} target={} (KeyPackage owner)",
                adder, added
            ),
            placement_line,
            format!(
                "RFC9420 RatchetTree Add result: {} mapped to LeafIndex={} (NodeIndex={})",
                added,
                new_leaf_index,
                leaf_node_index(new_leaf_index)
            ),
            format!(
                "RFC9420 Commit: GroupContext.epoch {} -> {}",
                previous_epoch, new_epoch
            ),
        ],
    );
    save_admin_demo_state(state, demo_id, &demo_state)?;
    touch_admin_demo_updated_at(state, demo_id, now_unix())?;
    Ok(AdminDemoActionResponse {
        action: action_line,
        epoch: demo_state.epoch,
        members: active_members_from_leaf_slots(&demo_state.leaf_slots),
    })
}

fn apply_admin_demo_remove_action(
    state: &UiState,
    demo_id: &str,
    payload: &AdminDemoRemoveActionPayload,
) -> Result<AdminDemoActionResponse, String> {
    ensure_admin_username(&payload.username)?;
    let remover = payload.remover.trim();
    let removed = payload.removed.trim();
    if remover.is_empty() || removed.is_empty() {
        return Err("remover and removed are required".to_string());
    }
    let mut demo_state = load_admin_demo_state(state, demo_id)?;
    if find_leaf_index_for_username(&demo_state.leaf_slots, remover).is_none() {
        return Err(format!("remover {} is not a member", remover));
    }
    let Some(removed_leaf) = find_leaf_index_for_username(&demo_state.leaf_slots, removed) else {
        return Err(format!("member {} not found", removed));
    };
    if active_member_count(&demo_state.leaf_slots) <= 1 {
        return Err("cannot remove the last remaining member".to_string());
    }
    let previous_epoch = demo_state.epoch;
    demo_state.leaf_slots[removed_leaf] = None;
    let trim_result = trim_trailing_blank_demo_leaves(&mut demo_state.leaf_slots);
    let trim_line = if trim_result.new_leaf_count < trim_result.previous_leaf_count {
        format!(
            "RFC9420 RatchetTree Remove: trimmed trailing blank leaves (leaf_count {} -> {})",
            trim_result.previous_leaf_count, trim_result.new_leaf_count
        )
    } else {
        format!(
            "RFC9420 RatchetTree Remove: no trailing blank leaves to trim (leaf_count stays {})",
            trim_result.new_leaf_count
        )
    };
    demo_state.epoch = demo_state.epoch.saturating_add(1);
    let new_epoch = demo_state.epoch;
    let action_line = format!("remove: {} removed {}", remover, removed);
    demo_state.last_action = Some(action_line.clone());
    append_demo_log_block(
        &mut demo_state,
        vec![
            format!(
                "RFC9420 Proposal Remove: sender={} target={}",
                remover, removed
            ),
            format!(
                "RFC9420 RatchetTree Remove: blanked LeafIndex={} (NodeIndex={}) for {}",
                removed_leaf,
                leaf_node_index(removed_leaf),
                removed
            ),
            trim_line,
            format!(
                "RFC9420 Commit: GroupContext.epoch {} -> {}",
                previous_epoch, new_epoch
            ),
        ],
    );
    save_admin_demo_state(state, demo_id, &demo_state)?;
    touch_admin_demo_updated_at(state, demo_id, now_unix())?;
    Ok(AdminDemoActionResponse {
        action: action_line,
        epoch: demo_state.epoch,
        members: active_members_from_leaf_slots(&demo_state.leaf_slots),
    })
}

fn apply_admin_demo_update_action(
    state: &UiState,
    demo_id: &str,
    payload: &AdminDemoUpdateActionPayload,
) -> Result<AdminDemoActionResponse, String> {
    ensure_admin_username(&payload.username)?;
    let updater = payload.updater.trim();
    if updater.is_empty() {
        return Err("updater is required".to_string());
    }
    let mut demo_state = load_admin_demo_state(state, demo_id)?;
    let previous_epoch = demo_state.epoch;
    let Some(updater_leaf_index) = find_leaf_index_for_username(&demo_state.leaf_slots, updater)
    else {
        return Err(format!("updater {} is not a member", updater));
    };
    let (previous_generation, new_generation) =
        match demo_state.leaf_slots.get_mut(updater_leaf_index) {
            Some(Some(member)) => {
                let previous_generation = member.key_generation;
                member.key_generation = member.key_generation.saturating_add(1);
                (previous_generation, member.key_generation)
            }
            _ => return Err(format!("updater {} is not a member", updater)),
        };
    demo_state.epoch = demo_state.epoch.saturating_add(1);
    let new_epoch = demo_state.epoch;
    let action_line = format!("update: {} key_generation={}", updater, new_generation);
    demo_state.last_action = Some(action_line.clone());
    append_demo_log_block(
        &mut demo_state,
        vec![
            format!(
                "RFC9420 Proposal Update: sender={} target={}",
                updater, updater
            ),
            format!(
                "RFC9420 Path Update: {} at LeafIndex={} (NodeIndex={}) key_generation {} -> {}",
                updater,
                updater_leaf_index,
                leaf_node_index(updater_leaf_index),
                previous_generation,
                new_generation
            ),
            format!(
                "RFC9420 Commit: GroupContext.epoch {} -> {}",
                previous_epoch, new_epoch
            ),
        ],
    );
    save_admin_demo_state(state, demo_id, &demo_state)?;
    touch_admin_demo_updated_at(state, demo_id, now_unix())?;
    Ok(AdminDemoActionResponse {
        action: action_line,
        epoch: demo_state.epoch,
        members: active_members_from_leaf_slots(&demo_state.leaf_slots),
    })
}

fn load_state(state: &UiState, username: &str) -> Result<ClientState, String> {
    let path = state_path(&state.state_dir, username);
    let bytes = fs::read(&path).map_err(|err| format!("read state: {err}"))?;
    serde_json::from_slice(&bytes).map_err(|err| format!("parse state: {err}"))
}

fn save_state(state: &UiState, client_state: &ClientState) -> Result<(), String> {
    let path = state_path(&state.state_dir, &client_state.username);
    let json = serde_json::to_vec_pretty(client_state).map_err(|err| err.to_string())?;
    fs::write(path, json).map_err(|err| format!("write state: {err}"))
}

fn load_groups(state: &UiState, username: &str) -> Result<GroupList, String> {
    let path = groups_path(&state.state_dir, username);
    if !path.exists() {
        return Ok(GroupList::default());
    }
    let bytes = fs::read(path).map_err(|err| format!("read groups: {err}"))?;
    serde_json::from_slice(&bytes).map_err(|err| format!("parse groups: {err}"))
}

fn save_groups(state: &UiState, username: &str, groups: &GroupList) -> Result<(), String> {
    let path = groups_path(&state.state_dir, username);
    let json = serde_json::to_vec_pretty(groups).map_err(|err| err.to_string())?;
    fs::write(path, json).map_err(|err| format!("write groups: {err}"))
}

fn load_group_state(
    state: &UiState,
    username: &str,
    group_id: &str,
) -> Result<ClientGroupState, String> {
    let path = group_state_path(&state.state_dir, username, group_id);
    if !path.exists() {
        return Err(format!(
            "group state not found at {}. Create it via ds_client bootstrap-group-state or join-from-commit",
            path.to_string_lossy()
        ));
    }
    let path_for_worker = path.clone();
    let path_for_error = path.to_string_lossy().to_string();
    let group_state = run_with_large_stack("ui-load-group-state", move || {
        ClientGroupState::load_from_file(&path_for_worker)
            .map_err(|err| format!("read group state {}: {err}", path_for_error))
    })?;
    ensure_group_state_consistency(&group_state, "load-group-state")?;
    Ok(group_state)
}

fn save_group_state(
    state: &UiState,
    username: &str,
    group_id: &str,
    group_state: &ClientGroupState,
) -> Result<(), String> {
    let path = group_state_path(&state.state_dir, username, group_id);
    ensure_group_state_consistency(group_state, "save-group-state")?;
    let state_for_worker = group_state.clone();
    let path_for_worker = path.clone();
    let path_for_error = path.to_string_lossy().to_string();
    run_with_large_stack("ui-save-group-state", move || {
        state_for_worker
            .save_to_file(&path_for_worker)
            .map_err(|err| format!("write group state {}: {err}", path_for_error))
    })
}

fn ensure_group_state_consistency(state: &ClientGroupState, context: &str) -> Result<(), String> {
    state
        .ensure_key_schedule_consistency()
        .map_err(|err| format!("key schedule consistency violation after {context}: {err}"))
}

fn load_group_labels(
    state: &UiState,
    username: &str,
    group_id: &str,
) -> Result<GroupMemberLabels, String> {
    let path = group_labels_path(&state.state_dir, username, group_id);
    if !path.exists() {
        return Ok(GroupMemberLabels::default());
    }
    let bytes = fs::read(&path).map_err(|err| format!("read group labels: {err}"))?;
    serde_json::from_slice(&bytes).map_err(|err| format!("parse group labels: {err}"))
}

fn save_group_labels(
    state: &UiState,
    username: &str,
    group_id: &str,
    labels: &GroupMemberLabels,
) -> Result<(), String> {
    let path = group_labels_path(&state.state_dir, username, group_id);
    let json = serde_json::to_vec_pretty(labels).map_err(|err| err.to_string())?;
    fs::write(path, json).map_err(|err| format!("write group labels: {err}"))
}

fn upsert_group_label(
    state: &UiState,
    username: &str,
    group_id: &str,
    key_id: &str,
    display_name: &str,
) -> Result<(), String> {
    let mut labels = load_group_labels(state, username, group_id)?;
    labels
        .items
        .insert(key_id.to_string(), display_name.to_string());
    save_group_labels(state, username, group_id, &labels)
}

async fn bootstrap_group_state(
    state: &UiState,
    username: &str,
    group_id: &str,
) -> Result<GroupBootstrapStatus, String> {
    let path = group_state_path(&state.state_dir, username, group_id);
    if path.exists() {
        let group_state = ClientGroupState::load_from_file(&path)
            .map_err(|err| format!("read group state {}: {err}", path.to_string_lossy()))?;
        return Ok(GroupBootstrapStatus {
            created: false,
            state_path: path.to_string_lossy().to_string(),
            leaf_count: group_state.ratchet_tree.leaf_count(),
            epoch: group_state.epoch,
        });
    }

    let client_state = load_state(state, username)?;
    let (key_package, receiver_private) = generate_keypackage_for_user(&client_state)?;
    let keypackage_b64 = STANDARD.encode(key_package.encode());
    ds_publish_keypackage(state, username, &keypackage_b64).await?;

    let receiver_path = receiver_private_path(&state.state_dir, username);
    let receiver_json =
        serde_json::to_vec_pretty(&receiver_private).map_err(|err| err.to_string())?;
    fs::write(&receiver_path, receiver_json)
        .map_err(|err| format!("write receiver private: {err}"))?;
    let _ = upsert_keypackage_record(
        state,
        username,
        &keypackage_b64,
        Some(&receiver_path.to_string_lossy()),
        true,
    );

    let own_key_id = short_id(&key_package.init_key.to_bytes());
    let leaf = LeafNode {
        public_key: key_package.init_key,
        credential: key_package.identity,
    };
    let tree = RatchetTree::from_leaves(vec![leaf]);
    let group_state = ClientGroupState::new(group_id.to_string(), tree, 0);
    save_group_state(state, username, group_id, &group_state)?;
    upsert_group_label(state, username, group_id, &own_key_id, username)?;
    let _ = add_group(state, username, group_id);

    Ok(GroupBootstrapStatus {
        created: true,
        state_path: path.to_string_lossy().to_string(),
        leaf_count: group_state.ratchet_tree.leaf_count(),
        epoch: group_state.epoch,
    })
}

fn load_keypackages(state: &UiState, username: &str) -> Result<KeyPackageList, String> {
    let path = keypackages_path(&state.state_dir, username);
    if !path.exists() {
        return Ok(KeyPackageList::default());
    }
    let bytes = fs::read(path).map_err(|err| format!("read keypackages: {err}"))?;
    serde_json::from_slice(&bytes).map_err(|err| format!("parse keypackages: {err}"))
}

fn save_keypackages(state: &UiState, username: &str, list: &KeyPackageList) -> Result<(), String> {
    let path = keypackages_path(&state.state_dir, username);
    let json = serde_json::to_vec_pretty(list).map_err(|err| err.to_string())?;
    fs::write(path, json).map_err(|err| format!("write keypackages: {err}"))
}

fn short_hex(bytes: &[u8], take: usize) -> String {
    bytes
        .iter()
        .take(take)
        .map(|b| format!("{:02x}", b))
        .collect()
}

fn short_id(bytes: &[u8]) -> String {
    short_hex(&hash_payload(bytes), 6)
}

fn upsert_keypackage_record(
    state: &UiState,
    username: &str,
    keypackage_b64: &str,
    receiver_private_path: Option<&str>,
    published: bool,
) -> Result<KeyPackageRecord, String> {
    let keypackage_bytes = STANDARD
        .decode(keypackage_b64)
        .map_err(|_| "keypackage_b64 must be base64".to_string())?;
    let id = format!("kp_{}", short_hex(&hash_payload(&keypackage_bytes), 6));
    let mut list = load_keypackages(state, username)?;

    let mut updated = None;
    if let Some(existing) = list.items.iter_mut().find(|item| item.id == id) {
        if existing.receiver_private_path.is_empty() {
            if let Some(path) = receiver_private_path {
                existing.receiver_private_path = path.to_string();
            }
        }
        if published {
            existing.published = true;
        }
        updated = Some(existing.clone());
    }
    if let Some(record) = updated {
        save_keypackages(state, username, &list)?;
        return Ok(record);
    }

    let record = KeyPackageRecord {
        id,
        created_at: now_unix(),
        keypackage_b64: keypackage_b64.to_string(),
        receiver_private_path: receiver_private_path.unwrap_or("").to_string(),
        published,
    };
    list.items.push(record.clone());
    save_keypackages(state, username, &list)?;
    Ok(record)
}

fn node_is_blank(tree: &RatchetTree, node_index: usize) -> bool {
    matches!(
        tree.nodes.get(node_index),
        Some(hybrid_mls::tree::Node::Blank)
    )
}

fn layout_tree_inorder(
    tree: &RatchetTree,
    node_index: usize,
    depth: usize,
    next_x: &mut usize,
    positions: &mut HashMap<usize, (usize, usize)>,
    edges: &mut Vec<TreeEdgeView>,
) {
    if node_index >= tree.nodes.len() {
        return;
    }

    if let Some(left) = tree.left_child(node_index) {
        if left < tree.nodes.len() {
            layout_tree_inorder(tree, left, depth + 1, next_x, positions, edges);
            if !node_is_blank(tree, node_index) && !node_is_blank(tree, left) {
                edges.push(TreeEdgeView {
                    from: node_index,
                    to: left,
                });
            }
        }
    }

    positions.insert(node_index, (*next_x, depth));
    *next_x = (*next_x).saturating_add(1);

    if let Some(right) = tree.right_child(node_index) {
        if right < tree.nodes.len() {
            layout_tree_inorder(tree, right, depth + 1, next_x, positions, edges);
            if !node_is_blank(tree, node_index) && !node_is_blank(tree, right) {
                edges.push(TreeEdgeView {
                    from: node_index,
                    to: right,
                });
            }
        }
    }
}

fn build_tree_view(
    state: &ClientGroupState,
    username: &str,
    labels: &GroupMemberLabels,
) -> TreeView {
    let mut positions: HashMap<usize, (usize, usize)> = HashMap::new();
    let mut edges = Vec::new();
    let mut next_x = 0usize;
    if let Some(root) = state.ratchet_tree.root_index() {
        layout_tree_inorder(
            &state.ratchet_tree,
            root,
            0,
            &mut next_x,
            &mut positions,
            &mut edges,
        );
    }

    let max_x = positions.values().map(|(x, _)| *x).max().unwrap_or(0) as f32;
    let mut nodes = Vec::with_capacity(state.ratchet_tree.nodes.len());
    for (idx, node) in state.ratchet_tree.nodes.iter().enumerate() {
        let position = positions.get(&idx).copied();
        let x = position.map(|(xv, _)| {
            if max_x <= 0.0 {
                0.5
            } else {
                (xv as f32) / max_x
            }
        });
        let y = position.map(|(_, yv)| yv as f32);

        match node {
            hybrid_mls::tree::Node::Leaf(leaf) => {
                let leaf_index = idx / 2;
                let cred_id = short_id(&leaf.credential.to_bytes());
                let pub_id = short_id(&leaf.public_key.to_bytes());
                let leaf_key_id = short_id(&leaf.public_key.to_bytes());
                let label = if leaf_index == state.own_leaf_index {
                    username.to_string()
                } else if let Some(mapped) = labels.items.get(&leaf_key_id) {
                    mapped.clone()
                } else {
                    format!("leaf-{leaf_index}")
                };
                nodes.push(TreeNodeView {
                    node_index: idx,
                    node_type: "leaf".to_string(),
                    leaf_index: Some(leaf_index),
                    label,
                    summary: format!("leaf {leaf_index} cred {cred_id} pub {pub_id}"),
                    x,
                    y,
                });
            }
            hybrid_mls::tree::Node::Parent(parent) => {
                let hash_id = if parent.parent_hash.is_empty() {
                    "none".to_string()
                } else {
                    short_hex(&parent.parent_hash, 6)
                };
                let pub_id = short_id(&parent.public_key.to_bytes());
                let label = if Some(idx) == state.ratchet_tree.root_index() {
                    "root".to_string()
                } else {
                    format!("parent-{idx}")
                };
                nodes.push(TreeNodeView {
                    node_index: idx,
                    node_type: "parent".to_string(),
                    leaf_index: None,
                    label,
                    summary: format!("parent hash {hash_id} pub {pub_id}"),
                    x,
                    y,
                });
            }
            hybrid_mls::tree::Node::Blank => {
                nodes.push(TreeNodeView {
                    node_index: idx,
                    node_type: "blank".to_string(),
                    leaf_index: None,
                    label: "blank".to_string(),
                    summary: "blank".to_string(),
                    x,
                    y,
                });
            }
        }
    }

    TreeView {
        group_id: state.group_id.clone(),
        epoch: state.epoch,
        leaf_count: state.ratchet_tree.leaf_count(),
        own_leaf_index: state.own_leaf_index,
        username: username.to_string(),
        root_index: state.ratchet_tree.root_index(),
        edges,
        nodes,
    }
}

fn add_group(state: &UiState, username: &str, group_id: &str) -> Result<GroupList, String> {
    let mut groups = load_groups(state, username)?;
    if !groups.groups.iter().any(|g| g == group_id) {
        groups.groups.push(group_id.to_string());
    }
    save_groups(state, username, &groups)?;
    Ok(groups)
}

fn remove_group(state: &UiState, username: &str, group_id: &str) -> Result<GroupList, String> {
    let mut groups = load_groups(state, username)?;
    groups.groups.retain(|g| g != group_id);
    save_groups(state, username, &groups)?;
    Ok(groups)
}

fn receiver_private_path(state_dir: &Path, username: &str) -> PathBuf {
    let ts = now_unix();
    state_dir.join(format!("user-{}-receiver-{}.json", sanitize(username), ts))
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn sign_message_b64(priv_key: HybridSignPrivKey, message: &[u8]) -> Result<String, String> {
    let payload = message.to_vec();
    run_with_large_stack("ui-hybrid-sign", move || {
        let sig = priv_key.sign(&payload);
        Ok(STANDARD.encode(sig.to_bytes()))
    })
}

fn signing_key_from_state(state: &ClientState) -> Result<HybridSignPrivKey, String> {
    let classic_b64 = state.classic_sk_b64.clone();
    let pq_b64 = state.pq_sk_b64.clone();
    run_with_large_stack("ui-load-signing-key", move || {
        let classic_bytes = STANDARD
            .decode(&classic_b64)
            .map_err(|_| "invalid classic signing key".to_string())?;
        if classic_bytes.len() != 32 {
            return Err("classic signing key must be 32 bytes".to_string());
        }
        let mut secret: EdSecretKey = [0u8; 32];
        secret.copy_from_slice(&classic_bytes);
        let classic_sk = EdSigningKey::from_bytes(&secret);

        let pq_bytes = STANDARD
            .decode(&pq_b64)
            .map_err(|_| "invalid pq signing key".to_string())?;
        let enc: EncodedSigningKey<MlDsa65> = pq_bytes
            .as_slice()
            .try_into()
            .map_err(|_| "invalid pq signing key".to_string())?;
        let pq_sk = ml_dsa::SigningKey::<MlDsa65>::decode(&enc);

        Ok(HybridSignPrivKey {
            classic: classic_sk,
            pq: pq_sk,
        })
    })
}

fn identity_from_state(state: &ClientState) -> Result<HybridSignPubKey, String> {
    let classic = STANDARD
        .decode(&state.classic_pk_b64)
        .map_err(|_| "invalid classic public key".to_string())?;
    if classic.len() != 32 {
        return Err("classic public key must be 32 bytes".to_string());
    }
    let mut classic_arr = [0u8; 32];
    classic_arr.copy_from_slice(&classic);
    let classic_pub =
        EdPublic::from_bytes(&classic_arr).map_err(|_| "invalid classic public key".to_string())?;

    let pq = STANDARD
        .decode(&state.pq_pk_b64)
        .map_err(|_| "invalid pq public key".to_string())?;
    let pq_enc: EncodedVerifyingKey<MlDsa65> = pq
        .as_slice()
        .try_into()
        .map_err(|_| "invalid pq public key".to_string())?;
    let pq_pub = ml_dsa::VerifyingKey::<MlDsa65>::decode(&pq_enc);

    Ok(HybridSignPubKey {
        classic: classic_pub,
        pq: pq_pub,
    })
}

fn register_state(username: &str, password: &str) -> Result<(ClientState, String), String> {
    let username = username.to_string();
    let password = password.to_string();
    run_with_large_stack("ui-hybrid-register", move || {
        let mut rng = OsRng;

        let mut classic_secret: EdSecretKey = [0u8; 32];
        rng.fill_bytes(&mut classic_secret);
        let classic_sk = EdSigningKey::from_bytes(&classic_secret);
        let classic_pk = classic_sk.verifying_key();

        let kp = MlDsa65::key_gen(&mut rng);
        let pq_sk = kp.signing_key().clone();
        let pq_pk = kp.verifying_key().clone();

        let classic_pk_b64 = STANDARD.encode(classic_pk.as_bytes());
        let pq_pk_b64 = STANDARD.encode(pq_pk.encode());

        let priv_key = HybridSignPrivKey {
            classic: classic_sk.clone(),
            pq: pq_sk.clone(),
        };

        let sign_input = register_signing_input(&username, &password, &classic_pk_b64, &pq_pk_b64);
        let signature = STANDARD.encode(priv_key.sign(&sign_input).to_bytes());

        let state = ClientState {
            username: username.to_string(),
            classic_sk_b64: STANDARD.encode(classic_sk.to_bytes()),
            pq_sk_b64: STANDARD.encode(pq_sk.encode()),
            classic_pk_b64,
            pq_pk_b64,
            session_id: None,
        };

        Ok((state, signature))
    })
}

fn register_signing_input(
    username: &str,
    password: &str,
    classic_pub_b64: &str,
    pq_pub_b64: &str,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"register|");
    out.extend_from_slice(username.as_bytes());
    out.extend_from_slice(b"|");
    out.extend_from_slice(password.as_bytes());
    out.extend_from_slice(b"|");
    out.extend_from_slice(classic_pub_b64.as_bytes());
    out.extend_from_slice(b"|");
    out.extend_from_slice(pq_pub_b64.as_bytes());
    out
}

fn login_signing_input(username: &str, password: &str) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"login|");
    out.extend_from_slice(username.as_bytes());
    out.extend_from_slice(b"|");
    out.extend_from_slice(password.as_bytes());
    out
}

fn logout_signing_input(username: &str, session_id: &str) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"logout|");
    out.extend_from_slice(username.as_bytes());
    out.extend_from_slice(b"|");
    out.extend_from_slice(session_id.as_bytes());
    out
}

fn admin_list_signing_input(kind: &str, username: &str) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"admin-list|");
    out.extend_from_slice(kind.as_bytes());
    out.extend_from_slice(b"|");
    out.extend_from_slice(username.as_bytes());
    out
}

fn proposal_signing_input(username: &str, group_id: &str, proposal: &[u8]) -> Vec<u8> {
    let hash = proposal_authenticated_content_hash(group_id, proposal);
    let mut out = Vec::new();
    out.extend_from_slice(b"proposal|");
    out.extend_from_slice(username.as_bytes());
    out.extend_from_slice(b"|");
    out.extend_from_slice(group_id.as_bytes());
    out.extend_from_slice(b"|");
    out.extend_from_slice(&hash);
    out
}

fn commit_signing_input(
    username: &str,
    group_id: &str,
    commit: &[u8],
    path_update: Option<&[u8]>,
    welcome: Option<&[u8]>,
) -> Vec<u8> {
    let commit_hash = commit_authenticated_content_hash(group_id, commit);
    let mut out = Vec::new();
    out.extend_from_slice(b"commit|");
    out.extend_from_slice(username.as_bytes());
    out.extend_from_slice(b"|");
    out.extend_from_slice(group_id.as_bytes());
    out.extend_from_slice(b"|");
    out.extend_from_slice(&commit_hash);
    out.extend_from_slice(b"|");
    if let Some(path) = path_update {
        let path_hash = path_update_authenticated_content_hash(group_id, path);
        out.extend_from_slice(&path_hash);
    }
    out.extend_from_slice(b"|");
    if let Some(welcome) = welcome {
        let welcome_hash = hash_payload(welcome);
        out.extend_from_slice(&welcome_hash);
    }
    out
}

fn list_signing_input(
    username: &str,
    group_id: &str,
    limit: usize,
    kind: &str,
    before_id: Option<i64>,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"list|");
    out.extend_from_slice(username.as_bytes());
    out.extend_from_slice(b"|");
    out.extend_from_slice(group_id.as_bytes());
    out.extend_from_slice(b"|");
    out.extend_from_slice(limit.to_string().as_bytes());
    out.extend_from_slice(b"|");
    out.extend_from_slice(kind.as_bytes());
    out.extend_from_slice(b"|");
    out.extend_from_slice(before_id.unwrap_or(0).to_string().as_bytes());
    out
}

fn fetch_message_signing_input(username: &str, group_id: &str, message_id: i64) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"message_fetch|");
    out.extend_from_slice(username.as_bytes());
    out.extend_from_slice(b"|");
    out.extend_from_slice(group_id.as_bytes());
    out.extend_from_slice(b"|");
    out.extend_from_slice(message_id.to_string().as_bytes());
    out
}

fn app_publish_signing_input(username: &str, group_id: &str, message: &[u8]) -> Vec<u8> {
    let hash = hash_payload(message);
    let mut out = Vec::new();
    out.extend_from_slice(b"app_publish|");
    out.extend_from_slice(username.as_bytes());
    out.extend_from_slice(b"|");
    out.extend_from_slice(group_id.as_bytes());
    out.extend_from_slice(b"|");
    out.extend_from_slice(&hash);
    out
}

fn app_list_signing_input(
    username: &str,
    group_id: &str,
    limit: usize,
    before_id: Option<i64>,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"app_list|");
    out.extend_from_slice(username.as_bytes());
    out.extend_from_slice(b"|");
    out.extend_from_slice(group_id.as_bytes());
    out.extend_from_slice(b"|");
    out.extend_from_slice(limit.to_string().as_bytes());
    out.extend_from_slice(b"|");
    out.extend_from_slice(before_id.unwrap_or(0).to_string().as_bytes());
    out
}

fn app_fetch_signing_input(username: &str, group_id: &str, message_id: i64) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"app_fetch|");
    out.extend_from_slice(username.as_bytes());
    out.extend_from_slice(b"|");
    out.extend_from_slice(group_id.as_bytes());
    out.extend_from_slice(b"|");
    out.extend_from_slice(message_id.to_string().as_bytes());
    out
}

fn keypackage_publish_signing_input(username: &str, keypackage: &[u8]) -> Vec<u8> {
    let hash = hash_payload(keypackage);
    let mut out = Vec::new();
    out.extend_from_slice(b"keypackage_publish|");
    out.extend_from_slice(username.as_bytes());
    out.extend_from_slice(b"|");
    out.extend_from_slice(&hash);
    out
}

fn keypackage_fetch_signing_input(username: &str, target: &str) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"keypackage_fetch|");
    out.extend_from_slice(username.as_bytes());
    out.extend_from_slice(b"|");
    out.extend_from_slice(target.as_bytes());
    out
}

fn welcome_group_info_context(group_id: &str, epoch: u64, signer_leaf: usize) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"welcome-group-info|");
    out.extend_from_slice(group_id.as_bytes());
    out.extend_from_slice(b"|");
    out.extend_from_slice(&epoch.to_be_bytes());
    out.extend_from_slice(b"|");
    out.extend_from_slice(&(signer_leaf as u32).to_be_bytes());
    out
}

fn hash_payload(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"DS-PAYLOAD");
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn hash32_with_label(label: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(label);
    for part in parts {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

const UI_WORKER_STACK_BYTES: usize = 128 * 1024 * 1024;

fn run_with_large_stack<T, F>(worker_name: &'static str, f: F) -> Result<T, String>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, String> + Send + 'static,
{
    let handle = std::thread::Builder::new()
        .name(worker_name.to_string())
        .stack_size(UI_WORKER_STACK_BYTES)
        .spawn(f)
        .map_err(|err| format!("failed to spawn {worker_name}: {err}"))?;
    handle
        .join()
        .map_err(|_| format!("{worker_name} panicked"))?
}

async fn register_user(
    state: &UiState,
    username: &str,
    password: &str,
) -> Result<serde_json::Value, String> {
    if username == ADMIN_USERNAME {
        return Err(format!(
            "admin account is bootstrap-managed; use login with {}/{}",
            ADMIN_USERNAME, ADMIN_PASSWORD
        ));
    }
    let path = state_path(&state.state_dir, username);
    if path.exists() {
        return Err("state already exists; use a different username".to_string());
    }
    let (mut client_state, signature) = register_state(username, password)?;
    save_state(state, &client_state)?;

    let body = serde_json::json!({
        "username": username,
        "password": password,
        "classic_pub_key": client_state.classic_pk_b64,
        "pq_pub_key": client_state.pq_pk_b64,
        "signature": signature,
    });
    let resp = state
        .client
        .post(format!("{}/v1/auth/register", state.base_url))
        .json(&body)
        .send()
        .await
        .map_err(|err| format!("register failed: {err}"))?;
    let status = resp.status();
    let body_text = resp.text().await.map_err(|err| err.to_string())?;
    if !status.is_success() {
        return Err(format!("register failed: {status} {body_text}"));
    }

    let login_value = login_user(state, username, password).await?;
    client_state = load_state(state, username)?;
    Ok(serde_json::json!({
        "register": body_text,
        "login": login_value,
        "session_id": client_state.session_id,
    }))
}

async fn login_user(
    state: &UiState,
    username: &str,
    password: &str,
) -> Result<serde_json::Value, String> {
    if username == ADMIN_USERNAME {
        ensure_admin_local_state(state)?;
    }
    let mut client_state = load_state(state, username)?;
    let signing_key = signing_key_from_state(&client_state)?;
    let sign_input = login_signing_input(username, password);
    let signature = sign_message_b64(signing_key, &sign_input)?;

    let body = serde_json::json!({
        "username": username,
        "password": password,
        "signature": signature,
    });
    let resp = state
        .client
        .post(format!("{}/v1/auth/login", state.base_url))
        .json(&body)
        .send()
        .await
        .map_err(|err| format!("login failed: {err}"))?;
    let status = resp.status();
    let body_text = resp.text().await.map_err(|err| err.to_string())?;
    if !status.is_success() {
        return Err(format!("login failed: {status} {body_text}"));
    }
    let json: serde_json::Value =
        serde_json::from_str(&body_text).map_err(|err| format!("parse login response: {err}"))?;
    let token = json
        .get("session_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "login response missing session_id".to_string())?;
    client_state.session_id = Some(token.to_string());
    save_state(state, &client_state)?;
    Ok(json)
}

fn ensure_admin_local_state(state: &UiState) -> Result<(), String> {
    let path = state_path(&state.state_dir, ADMIN_USERNAME);
    if path.exists() {
        return Ok(());
    }
    let material = run_with_large_stack("ui-admin-keygen", move || {
        Ok::<_, String>(derive_admin_key_material())
    })?;
    let local_state = ClientState {
        username: ADMIN_USERNAME.to_string(),
        classic_sk_b64: STANDARD.encode(material.classic_secret),
        pq_sk_b64: STANDARD.encode(&material.pq_secret),
        classic_pk_b64: STANDARD.encode(&material.classic_public),
        pq_pk_b64: STANDARD.encode(&material.pq_public),
        session_id: None,
    };
    save_state(state, &local_state)
}

async fn logout_user(state: &UiState, username: &str) -> Result<serde_json::Value, String> {
    let mut client_state = load_state(state, username)?;
    let session_id = client_state
        .session_id
        .clone()
        .ok_or_else(|| "missing session_id; login first".to_string())?;
    let signing_key = signing_key_from_state(&client_state)?;
    let sign_input = logout_signing_input(username, &session_id);
    let signature = sign_message_b64(signing_key, &sign_input)?;

    let body = serde_json::json!({
        "username": username,
        "session_id": session_id,
        "signature": signature,
    });
    let resp = state
        .client
        .post(format!("{}/v1/auth/logout", state.base_url))
        .json(&body)
        .send()
        .await
        .map_err(|err| format!("logout failed: {err}"))?;
    let status = resp.status();
    let body_text = resp.text().await.map_err(|err| err.to_string())?;
    if !status.is_success() {
        return Err(format!("logout failed: {status} {body_text}"));
    }
    client_state.session_id = None;
    save_state(state, &client_state)?;
    Ok(
        serde_json::from_str(&body_text)
            .unwrap_or_else(|_| serde_json::json!({"logged_out": true})),
    )
}

async fn ds_list_admin_users(state: &UiState, username: &str) -> Result<serde_json::Value, String> {
    if username != ADMIN_USERNAME {
        return Err("admin access required".to_string());
    }
    let client_state = load_state(state, username)?;
    let session_id = client_state
        .session_id
        .clone()
        .ok_or_else(|| "missing session_id; login first".to_string())?;
    let signing_key = signing_key_from_state(&client_state)?;
    let sign_input = admin_list_signing_input("users", username);
    let signature = sign_message_b64(signing_key, &sign_input)?;

    let query = serde_urlencoded::to_string([
        ("username", username.to_string()),
        ("session_id", session_id),
        ("signature", signature),
    ])
    .map_err(|err| err.to_string())?;

    let url = format!("{}/v1/admin/users?{}", state.base_url, query);
    let resp = state
        .client
        .get(url)
        .send()
        .await
        .map_err(|err| format!("admin users failed: {err}"))?;
    let status = resp.status();
    let body_text = resp.text().await.map_err(|err| err.to_string())?;
    if !status.is_success() {
        return Err(format!("admin users failed: {status} {body_text}"));
    }
    serde_json::from_str(&body_text).map_err(|err| err.to_string())
}

async fn ds_list_admin_groups(
    state: &UiState,
    username: &str,
) -> Result<serde_json::Value, String> {
    if username != ADMIN_USERNAME {
        return Err("admin access required".to_string());
    }
    let client_state = load_state(state, username)?;
    let session_id = client_state
        .session_id
        .clone()
        .ok_or_else(|| "missing session_id; login first".to_string())?;
    let signing_key = signing_key_from_state(&client_state)?;
    let sign_input = admin_list_signing_input("groups", username);
    let signature = sign_message_b64(signing_key, &sign_input)?;

    let query = serde_urlencoded::to_string([
        ("username", username.to_string()),
        ("session_id", session_id),
        ("signature", signature),
    ])
    .map_err(|err| err.to_string())?;

    let url = format!("{}/v1/admin/groups?{}", state.base_url, query);
    let resp = state
        .client
        .get(url)
        .send()
        .await
        .map_err(|err| format!("admin groups failed: {err}"))?;
    let status = resp.status();
    let body_text = resp.text().await.map_err(|err| err.to_string())?;
    if !status.is_success() {
        return Err(format!("admin groups failed: {status} {body_text}"));
    }
    serde_json::from_str(&body_text).map_err(|err| err.to_string())
}

async fn ds_list_messages(
    state: &UiState,
    username: &str,
    group_id: &str,
    query: &ListMessagesQuery,
) -> Result<serde_json::Value, String> {
    let client_state = load_state(state, username)?;
    let session_id = client_state
        .session_id
        .clone()
        .ok_or_else(|| "missing session_id; login first".to_string())?;
    let signing_key = signing_key_from_state(&client_state)?;
    let kind = query.kind.clone().unwrap_or_else(|| "any".to_string());
    let limit = query.limit.unwrap_or(20);
    let sign_input = list_signing_input(username, group_id, limit, &kind, query.before_id);
    let signature = sign_message_b64(signing_key, &sign_input)?;

    let mut params = vec![
        ("username", username.to_string()),
        ("session_id", session_id),
        ("signature", signature),
        ("limit", limit.to_string()),
        ("kind", kind),
    ];
    if let Some(before) = query.before_id {
        params.push(("before_id", before.to_string()));
    }
    let url = format!(
        "{}/v1/groups/{}/messages?{}",
        state.base_url,
        group_id,
        serde_urlencoded::to_string(params).map_err(|err| err.to_string())?
    );

    let resp = state
        .client
        .get(url)
        .send()
        .await
        .map_err(|err| format!("list messages failed: {err}"))?;
    let status = resp.status();
    let body_text = resp.text().await.map_err(|err| err.to_string())?;
    if !status.is_success() {
        return Err(format!("list messages failed: {status} {body_text}"));
    }
    serde_json::from_str(&body_text).map_err(|err| err.to_string())
}

async fn ds_fetch_group_message(
    state: &UiState,
    username: &str,
    group_id: &str,
    message_id: i64,
) -> Result<serde_json::Value, String> {
    let client_state = load_state(state, username)?;
    let session_id = client_state
        .session_id
        .clone()
        .ok_or_else(|| "missing session_id; login first".to_string())?;
    let signing_key = signing_key_from_state(&client_state)?;
    let sign_input = fetch_message_signing_input(username, group_id, message_id);
    let signature = sign_message_b64(signing_key, &sign_input)?;

    let query = serde_urlencoded::to_string([
        ("username", username),
        ("session_id", &session_id),
        ("signature", &signature),
    ])
    .map_err(|err| err.to_string())?;
    let url = format!(
        "{}/v1/groups/{}/messages/{}?{}",
        state.base_url, group_id, message_id, query
    );
    let resp = state
        .client
        .get(url)
        .send()
        .await
        .map_err(|err| format!("fetch message failed: {err}"))?;
    let status = resp.status();
    let body_text = resp.text().await.map_err(|err| err.to_string())?;
    if !status.is_success() {
        return Err(format!("fetch message failed: {status} {body_text}"));
    }
    serde_json::from_str(&body_text).map_err(|err| err.to_string())
}

fn generate_keypackage_for_user(
    state: &ClientState,
) -> Result<(KeyPackage, ReceiverPrivateFile), String> {
    let mut rng = OsRng;

    let mut classic_private = [0u8; 32];
    rng.fill_bytes(&mut classic_private);
    let classic_priv = X25519Priv::from(classic_private);
    let classic_pub = X25519Pub::from(&classic_priv);

    let mut pq_seed = [0u8; 64];
    rng.fill_bytes(&mut pq_seed);
    let kyber_priv = KyberPriv::from_seed(Seed::from(pq_seed));
    let kyber_pub = kyber_priv.encapsulation_key().clone();

    let init_key = HybridPublicKey {
        classic: classic_pub,
        pq: kyber_pub,
    };
    let identity = identity_from_state(state)?;
    let signer = signing_key_from_state(state)?;
    let signature = signer.sign(&init_key.to_bytes());

    let key_package = KeyPackage {
        identity,
        init_key,
        signature,
    };
    verify_keypackage_signature_only(&key_package)
        .map_err(|_| "generated keypackage failed self-verification".to_string())?;

    let receiver_private = ReceiverPrivateFile {
        classic_x25519_private_b64: STANDARD.encode(classic_private),
        pq_kem_seed_b64: STANDARD.encode(pq_seed),
    };

    Ok((key_package, receiver_private))
}

async fn generate_and_publish_keypackage(
    state: &UiState,
    username: &str,
) -> Result<KeyPackageGenerateResponse, String> {
    let client_state = load_state(state, username)?;
    if client_state.session_id.is_none() {
        return Err("missing session_id; login first".to_string());
    }

    let (key_package, receiver_private) = generate_keypackage_for_user(&client_state)?;
    let keypackage_b64 = STANDARD.encode(key_package.encode());

    ds_publish_keypackage(state, username, &keypackage_b64).await?;

    let receiver_path = receiver_private_path(&state.state_dir, username);
    let receiver_json =
        serde_json::to_vec_pretty(&receiver_private).map_err(|err| err.to_string())?;
    fs::write(&receiver_path, receiver_json)
        .map_err(|err| format!("write receiver private: {err}"))?;

    upsert_keypackage_record(
        state,
        username,
        &keypackage_b64,
        Some(&receiver_path.to_string_lossy()),
        true,
    )?;

    Ok(KeyPackageGenerateResponse {
        published: true,
        keypackage_b64,
        receiver_private_path: receiver_path.to_string_lossy().to_string(),
    })
}

async fn ds_list_app_messages(
    state: &UiState,
    username: &str,
    group_id: &str,
    query: &ListAppMessagesQuery,
) -> Result<serde_json::Value, String> {
    let client_state = load_state(state, username)?;
    let session_id = client_state
        .session_id
        .clone()
        .ok_or_else(|| "missing session_id; login first".to_string())?;
    let signing_key = signing_key_from_state(&client_state)?;
    let limit = query.limit.unwrap_or(20);
    let sign_input = app_list_signing_input(username, group_id, limit, query.before_id);
    let signature = sign_message_b64(signing_key, &sign_input)?;

    let mut params = vec![
        ("username", username.to_string()),
        ("session_id", session_id),
        ("signature", signature),
        ("limit", limit.to_string()),
    ];
    if let Some(before) = query.before_id {
        params.push(("before_id", before.to_string()));
    }
    let url = format!(
        "{}/v1/groups/{}/app-messages?{}",
        state.base_url,
        group_id,
        serde_urlencoded::to_string(params).map_err(|err| err.to_string())?
    );
    let resp = state
        .client
        .get(url)
        .send()
        .await
        .map_err(|err| format!("list app messages failed: {err}"))?;
    let status = resp.status();
    let body_text = resp.text().await.map_err(|err| err.to_string())?;
    if !status.is_success() {
        return Err(format!("list app messages failed: {status} {body_text}"));
    }
    serde_json::from_str(&body_text).map_err(|err| err.to_string())
}

async fn ds_fetch_app_message(
    state: &UiState,
    username: &str,
    group_id: &str,
    message_id: i64,
) -> Result<serde_json::Value, String> {
    let client_state = load_state(state, username)?;
    let session_id = client_state
        .session_id
        .clone()
        .ok_or_else(|| "missing session_id; login first".to_string())?;
    let signing_key = signing_key_from_state(&client_state)?;
    let sign_input = app_fetch_signing_input(username, group_id, message_id);
    let signature = sign_message_b64(signing_key, &sign_input)?;

    let query = serde_urlencoded::to_string([
        ("username", username),
        ("session_id", &session_id),
        ("signature", &signature),
    ])
    .map_err(|err| err.to_string())?;
    let url = format!(
        "{}/v1/groups/{}/app-messages/{}?{}",
        state.base_url, group_id, message_id, query
    );
    let resp = state
        .client
        .get(url)
        .send()
        .await
        .map_err(|err| format!("fetch app message failed: {err}"))?;
    let status = resp.status();
    let body_text = resp.text().await.map_err(|err| err.to_string())?;
    if !status.is_success() {
        return Err(format!("fetch app message failed: {status} {body_text}"));
    }
    let mut json: serde_json::Value =
        serde_json::from_str(&body_text).map_err(|err| err.to_string())?;
    if let Some(encoded) = json.get("message_bytes").and_then(|v| v.as_str()) {
        let payload = STANDARD
            .decode(encoded)
            .map_err(|err| format!("decode fetched app payload base64: {err}"))?;
        let group_state = load_group_state(state, username, group_id)?;
        match unprotect_application_message_bytes(&group_state, &payload) {
            Some(opened) => {
                json["decrypted"] = serde_json::Value::Bool(true);
                json["sender_leaf"] = serde_json::Value::from(opened.sender_leaf);
                json["plaintext_b64"] =
                    serde_json::Value::String(STANDARD.encode(&opened.plaintext));
                json["plaintext_utf8"] = serde_json::Value::String(
                    String::from_utf8(opened.plaintext)
                        .unwrap_or_else(|_| "<non-utf8>".to_string()),
                );
            }
            None => {
                json["decrypted"] = serde_json::Value::Bool(false);
                json["decrypt_error"] = serde_json::Value::String(
                    "message is not a decryptable RFC-style private application message for current group state".to_string(),
                );
            }
        }
    }
    Ok(json)
}

async fn ds_send_app_message(
    state: &UiState,
    username: &str,
    group_id: &str,
    message: &str,
) -> Result<serde_json::Value, String> {
    let client_state = load_state(state, username)?;
    let session_id = client_state
        .session_id
        .clone()
        .ok_or_else(|| "missing session_id; login first".to_string())?;
    let signing_key = signing_key_from_state(&client_state)?;
    let group_state = load_group_state(state, username, group_id)?;
    let payload = protect_application_message_bytes(
        &group_state,
        group_state.own_leaf_index as u32,
        message.as_bytes(),
        b"",
    )
    .ok_or_else(|| "failed to protect app message with local group state".to_string())?;
    let sign_input = app_publish_signing_input(username, group_id, &payload);
    let signature = sign_message_b64(signing_key, &sign_input)?;

    let body = serde_json::json!({
        "username": username,
        "session_id": session_id,
        "message_bytes": STANDARD.encode(payload),
        "signature": signature,
    });
    let resp = state
        .client
        .post(format!(
            "{}/v1/groups/{}/app-messages",
            state.base_url, group_id
        ))
        .json(&body)
        .send()
        .await
        .map_err(|err| format!("send app message failed: {err}"))?;
    let status = resp.status();
    let body_text = resp.text().await.map_err(|err| err.to_string())?;
    if !status.is_success() {
        return Err(format!("send app message failed: {status} {body_text}"));
    }
    serde_json::from_str(&body_text).map_err(|err| err.to_string())
}

async fn ds_submit_proposal(
    state: &UiState,
    username: &str,
    group_id: &str,
    proposal_b64: &str,
) -> Result<serde_json::Value, String> {
    let client_state = load_state(state, username)?;
    let session_id = client_state
        .session_id
        .clone()
        .ok_or_else(|| "missing session_id; login first".to_string())?;
    let signing_key = signing_key_from_state(&client_state)?;
    let proposal_bytes = STANDARD
        .decode(proposal_b64)
        .map_err(|_| "proposal_b64 must be base64".to_string())?;
    let sign_input = proposal_signing_input(username, group_id, &proposal_bytes);
    let signature = sign_message_b64(signing_key, &sign_input)?;

    let body = serde_json::json!({
        "username": username,
        "session_id": session_id,
        "proposal_bytes": proposal_b64,
        "signature": signature,
    });
    let resp = state
        .client
        .post(format!(
            "{}/v1/groups/{}/proposals",
            state.base_url, group_id
        ))
        .json(&body)
        .send()
        .await
        .map_err(|err| format!("submit proposal failed: {err}"))?;
    let status = resp.status();
    let body_text = resp.text().await.map_err(|err| err.to_string())?;
    if !status.is_success() {
        return Err(format!("submit proposal failed: {status} {body_text}"));
    }
    serde_json::from_str(&body_text).map_err(|err| err.to_string())
}

async fn ds_submit_commit(
    state: &UiState,
    username: &str,
    group_id: &str,
    commit_b64: &str,
    path_update_b64: Option<&str>,
    welcome_b64: Option<&str>,
) -> Result<serde_json::Value, String> {
    let client_state = load_state(state, username)?;
    let session_id = client_state
        .session_id
        .clone()
        .ok_or_else(|| "missing session_id; login first".to_string())?;
    let signing_key = signing_key_from_state(&client_state)?;
    let commit_bytes = STANDARD
        .decode(commit_b64)
        .map_err(|_| "commit_b64 must be base64".to_string())?;
    let path_bytes = if let Some(path_b64) = path_update_b64 {
        Some(
            STANDARD
                .decode(path_b64)
                .map_err(|_| "path_update_b64 must be base64".to_string())?,
        )
    } else {
        None
    };
    let welcome_bytes = if let Some(welcome_b64) = welcome_b64 {
        Some(
            STANDARD
                .decode(welcome_b64)
                .map_err(|_| "welcome_b64 must be base64".to_string())?,
        )
    } else {
        None
    };
    let sign_input = commit_signing_input(
        username,
        group_id,
        &commit_bytes,
        path_bytes.as_deref(),
        welcome_bytes.as_deref(),
    );
    let signature = sign_message_b64(signing_key, &sign_input)?;

    let body = serde_json::json!({
        "username": username,
        "session_id": session_id,
        "commit_bytes": commit_b64,
        "path_update_bytes": path_update_b64,
        "welcome_bytes": welcome_b64,
        "signature": signature,
    });
    let resp = state
        .client
        .post(format!("{}/v1/groups/{}/commits", state.base_url, group_id))
        .json(&body)
        .send()
        .await
        .map_err(|err| format!("submit commit failed: {err}"))?;
    let status = resp.status();
    let body_text = resp.text().await.map_err(|err| err.to_string())?;
    if !status.is_success() {
        return Err(format!("submit commit failed: {status} {body_text}"));
    }
    serde_json::from_str(&body_text).map_err(|err| err.to_string())
}

async fn ds_publish_keypackage(
    state: &UiState,
    username: &str,
    keypackage_b64: &str,
) -> Result<serde_json::Value, String> {
    let client_state = load_state(state, username)?;
    let session_id = client_state
        .session_id
        .clone()
        .ok_or_else(|| "missing session_id; login first".to_string())?;
    let signing_key = signing_key_from_state(&client_state)?;
    let keypackage_bytes = STANDARD
        .decode(keypackage_b64)
        .map_err(|_| "keypackage_b64 must be base64".to_string())?;
    let sign_input = keypackage_publish_signing_input(username, &keypackage_bytes);
    let signature = sign_message_b64(signing_key, &sign_input)?;

    let body = serde_json::json!({
        "username": username,
        "session_id": session_id,
        "keypackage_bytes": keypackage_b64,
        "signature": signature,
    });
    let resp = state
        .client
        .post(format!("{}/v1/keypackages", state.base_url))
        .json(&body)
        .send()
        .await
        .map_err(|err| format!("publish keypackage failed: {err}"))?;
    let status = resp.status();
    let body_text = resp.text().await.map_err(|err| err.to_string())?;
    if !status.is_success() {
        return Err(format!("publish keypackage failed: {status} {body_text}"));
    }
    serde_json::from_str(&body_text).map_err(|err| err.to_string())
}

async fn ds_fetch_keypackage(
    state: &UiState,
    username: &str,
    target: &str,
) -> Result<serde_json::Value, String> {
    let client_state = load_state(state, username)?;
    let session_id = client_state
        .session_id
        .clone()
        .ok_or_else(|| "missing session_id; login first".to_string())?;
    let signing_key = signing_key_from_state(&client_state)?;
    let sign_input = keypackage_fetch_signing_input(username, target);
    let signature = sign_message_b64(signing_key, &sign_input)?;

    let query = serde_urlencoded::to_string([
        ("username", username),
        ("session_id", &session_id),
        ("signature", &signature),
    ])
    .map_err(|err| err.to_string())?;
    let url = format!("{}/v1/keypackages/{}?{}", state.base_url, target, query);
    let resp = state
        .client
        .get(url)
        .send()
        .await
        .map_err(|err| format!("fetch keypackage failed: {err}"))?;
    let status = resp.status();
    let body_text = resp.text().await.map_err(|err| err.to_string())?;
    if !status.is_success() {
        return Err(format!("fetch keypackage failed: {status} {body_text}"));
    }
    serde_json::from_str(&body_text).map_err(|err| err.to_string())
}

fn decode_keypackage_b64(keypackage_b64: &str) -> Result<KeyPackage, String> {
    let bytes = STANDARD
        .decode(keypackage_b64)
        .map_err(|_| "keypackage_b64 must be base64".to_string())?;
    decode_and_verify_keypackage_bytes(bytes)
}

fn decode_and_verify_keypackage_bytes(bytes: Vec<u8>) -> Result<KeyPackage, String> {
    run_with_large_stack("ui-keypackage-verify", move || {
        let keypackage =
            KeyPackage::decode(&bytes).ok_or("failed to decode keypackage".to_string())?;
        if !keypackage.verify() {
            return Err("keypackage signature verification failed".to_string());
        }
        Ok(keypackage)
    })
}

fn verify_keypackage_signature_only(key_package: &KeyPackage) -> Result<(), String> {
    let bytes = key_package.encode();
    run_with_large_stack("ui-keypackage-signature-verify", move || {
        let keypackage =
            KeyPackage::decode(&bytes).ok_or("failed to decode keypackage".to_string())?;
        if !keypackage.verify() {
            return Err("invalid add proposal key package signature".to_string());
        }
        Ok(())
    })
}

fn resolve_sender_leaf(
    state: &ClientGroupState,
    sender_leaf: Option<usize>,
) -> Result<usize, String> {
    let sender = sender_leaf.unwrap_or(state.own_leaf_index);
    ensure_leaf_present(&state.ratchet_tree, sender)?;
    Ok(sender)
}

fn ensure_leaf_bounds(tree: &RatchetTree, leaf_index: usize) -> Result<(), String> {
    if leaf_index >= tree.leaf_count() {
        return Err(format!(
            "leaf index {} out of bounds (leaf_count={})",
            leaf_index,
            tree.leaf_count()
        ));
    }
    Ok(())
}

fn ensure_leaf_present(tree: &RatchetTree, leaf_index: usize) -> Result<(), String> {
    ensure_leaf_bounds(tree, leaf_index)?;
    let node_index = RatchetTree::leaf_to_node_index(leaf_index);
    match tree.nodes.get(node_index) {
        Some(Node::Leaf(_)) => Ok(()),
        _ => Err(format!("leaf index {} is blank", leaf_index)),
    }
}

fn first_blank_leaf_index(tree: &RatchetTree) -> Option<usize> {
    for node_index in (0..tree.nodes.len()).step_by(2) {
        if matches!(tree.nodes[node_index], Node::Blank) {
            return Some(node_index / 2);
        }
    }
    None
}

fn grow_tree_by_one_leaf(tree: &mut RatchetTree) {
    if tree.nodes.is_empty() {
        tree.nodes.push(Node::Blank);
    } else {
        tree.nodes.push(Node::Blank);
        tree.nodes.push(Node::Blank);
    }
}

fn insert_key_package_preview(
    tree: &mut RatchetTree,
    key_package: &KeyPackage,
) -> Result<usize, String> {
    verify_keypackage_signature_only(key_package)?;

    let leaf_index = match first_blank_leaf_index(tree) {
        Some(index) => index,
        None => {
            grow_tree_by_one_leaf(tree);
            tree.leaf_count().saturating_sub(1)
        }
    };
    let node_index = RatchetTree::leaf_to_node_index(leaf_index);
    if node_index >= tree.nodes.len() {
        return Err("internal tree indexing error while inserting key package".to_string());
    }
    tree.nodes[node_index] = Node::Leaf(LeafNode {
        public_key: key_package.init_key.clone(),
        credential: key_package.identity.clone(),
    });
    Ok(leaf_index)
}

fn apply_proposals_preview(tree: &mut RatchetTree, proposals: &[Proposal]) -> Result<(), String> {
    for proposal in proposals {
        match proposal {
            Proposal::Add(key_package) => {
                insert_key_package_preview(tree, key_package)?;
            }
            Proposal::Update {
                leaf_index,
                key_package,
            } => {
                ensure_leaf_bounds(tree, *leaf_index)?;
                let node_index = RatchetTree::leaf_to_node_index(*leaf_index);
                tree.nodes[node_index] = Node::Leaf(LeafNode {
                    public_key: key_package.init_key.clone(),
                    credential: key_package.identity.clone(),
                });
            }
            Proposal::Remove { leaf_index } => {
                ensure_leaf_bounds(tree, *leaf_index)?;
                let node_index = RatchetTree::leaf_to_node_index(*leaf_index);
                tree.nodes[node_index] = Node::Blank;
            }
            Proposal::PreSharedKey { .. } => {}
            Proposal::ReInit { .. } => {}
            Proposal::GroupContextExtensions { .. } => {}
        }
    }
    Ok(())
}

#[derive(Debug)]
struct ClientRng(u64);

impl ClientRng {
    fn next_u64_internal(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
}

impl TryRng for ClientRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(self.next_u64_internal() as u32)
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(self.next_u64_internal())
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        let mut offset = 0usize;
        while offset < dst.len() {
            let chunk = self.next_u64_internal().to_le_bytes();
            let take = (dst.len() - offset).min(chunk.len());
            dst[offset..offset + take].copy_from_slice(&chunk[..take]);
            offset += take;
        }
        Ok(())
    }
}

impl TryCryptoRng for ClientRng {}

fn build_commit_from_pending(
    state: &ClientGroupState,
    sender_leaf: usize,
) -> Result<(Commit, PathUpdate), String> {
    let proposals = state
        .decoded_pending_proposals()
        .ok_or_else(|| "failed to decode pending proposals from group state".to_string())?;
    if proposals.is_empty() {
        return Err("no pending proposals in group state".to_string());
    }
    if proposals
        .iter()
        .any(|p| matches!(p, Proposal::Remove { leaf_index } if *leaf_index == sender_leaf))
    {
        return Err("sender leaf cannot remove itself in this action".to_string());
    }

    let validation_commit = Commit {
        sender: sender_leaf,
        proposals: proposals.clone(),
        path: Vec::new(),
    };
    state
        .ratchet_tree
        .validate_commit(&validation_commit)
        .map_err(|e| format!("pending proposals are invalid: {e:?}"))?;

    let mut tree_after_proposals = state.ratchet_tree.clone();
    apply_proposals_preview(&mut tree_after_proposals, &proposals)?;
    ensure_leaf_present(&tree_after_proposals, sender_leaf)?;

    let mut rng = ClientRng(rand::random::<u64>() ^ state.epoch);
    let mut leaf_secret = [0u8; 32];
    rng.try_fill_bytes(&mut leaf_secret)
        .map_err(|_| "failed to generate leaf secret".to_string())?;
    let secret_model = tree_after_proposals
        .derive_direct_path_secret_model(sender_leaf, leaf_secret)
        .ok_or_else(|| "failed to derive direct path secret model".to_string())?;
    let path = secret_model.parent_updates_leaf_to_root();
    let path_update = tree_after_proposals
        .build_path_update(&mut rng, sender_leaf, leaf_secret)
        .ok_or_else(|| "failed to build path update".to_string())?;

    Ok((
        Commit {
            sender: sender_leaf,
            proposals,
            path,
        },
        path_update,
    ))
}

fn build_welcome_for_commit(
    state: &ClientGroupState,
    commit: &Commit,
    path_update: &PathUpdate,
) -> Result<Option<Welcome>, String> {
    let add_keypackages = commit
        .proposals
        .iter()
        .filter_map(|proposal| match proposal {
            Proposal::Add(kp) => Some(kp),
            _ => None,
        })
        .collect::<Vec<_>>();
    if add_keypackages.is_empty() {
        return Ok(None);
    }

    let mut tree_after_commit = state.ratchet_tree.clone();
    tree_after_commit
        .apply_commit(commit)
        .ok_or_else(|| "failed to preview commit tree for welcome generation".to_string())?;
    let mut projected_group_context_extensions = state.group_context_extensions.clone();
    for proposal in &commit.proposals {
        if let Proposal::GroupContextExtensions { extensions } = proposal {
            projected_group_context_extensions = extensions.clone();
        }
    }
    let next_epoch = state.epoch.saturating_add(1);
    let commit_context = commit.encode();
    let tree_hash = tree_snapshot_hash(&tree_after_commit.encode());
    let tree_commit_secret = path_update.path_secrets.first().copied();

    let mut key_schedule = state.key_schedule.clone();
    let _ = key_schedule.ensure_epoch_with_tree_commit_secret(
        next_epoch,
        &state.group_id,
        tree_hash,
        Some(&commit_context),
        tree_commit_secret.as_ref(),
    );
    let chain = key_schedule
        .chain_secrets_for_epoch(next_epoch)
        .ok_or_else(|| "missing key-schedule chain secrets for welcome epoch".to_string())?;
    let derived = key_schedule
        .derive_secrets_for_epoch(&state.group_id, next_epoch)
        .ok_or_else(|| "missing key-schedule derived secrets for welcome epoch".to_string())?;

    let confirmed_transcript_hash =
        state.predict_confirmed_transcript_after_commit(&commit_context);
    let confirmation_tag =
        derive_confirmation_tag(&derived.confirmation_key, &confirmed_transcript_hash);
    let group_info = GroupInfo {
        group_id: state.group_id.clone(),
        epoch: next_epoch,
        tree_hash,
        confirmed_transcript_hash,
        signer_leaf: commit.sender as u32,
        extensions: projected_group_context_extensions.clone(),
        confirmation_tag,
        signature: hash32_with_label(
            b"WELCOME-GROUP-INFO-SIGNATURE",
            &[
                state.group_id.as_bytes(),
                &commit_context,
                &tree_hash,
                &projected_group_context_extensions,
                &chain.commit_secret,
            ],
        )
        .to_vec(),
    };
    let encrypted_group_info = encrypt_hpke_payload(
        &chain.welcome_secret,
        &welcome_group_info_context(&state.group_id, next_epoch, commit.sender),
        &group_info.encode(),
    );

    let mut rng = ClientRng(rand::random::<u64>() ^ state.epoch ^ next_epoch);
    let path_secret = path_update.path_secrets.first().copied();
    let mut encrypted = Vec::with_capacity(add_keypackages.len());
    for key_package in add_keypackages {
        if !key_package.verify() {
            return Err("invalid add proposal key package signature".to_string());
        }
        let key_ref_hash = hash32_with_label(b"WELCOME-KEYPACKAGE-REF", &[&key_package.encode()]);
        let group_secrets = GroupSecrets {
            joiner_secret: chain.joiner_secret,
            path_secret,
            psk_ids: Vec::new(),
        };
        encrypted.push(EncryptedGroupSecrets::encrypt_for_recipient(
            &mut rng,
            &state.group_id,
            next_epoch,
            key_ref_hash,
            &key_package.init_key,
            &group_secrets,
        ));
    }

    Ok(Some(Welcome {
        cipher_suite: 0x0001,
        secrets: encrypted,
        encrypted_group_info,
    }))
}

fn validate_commit_envelope_metadata(
    state: &ClientGroupState,
    envelope: &CommitEnvelope,
) -> Result<(), String> {
    if envelope.group_id != state.group_id {
        return Err(format!(
            "group_id mismatch: state={} envelope={}",
            state.group_id, envelope.group_id
        ));
    }
    if envelope.epoch != state.epoch {
        return Err(format!(
            "epoch mismatch: state={} envelope={}",
            state.epoch, envelope.epoch
        ));
    }
    if envelope.sender_leaf != envelope.commit.sender {
        return Err(format!(
            "sender mismatch: envelope.sender_leaf={} commit.sender={}",
            envelope.sender_leaf, envelope.commit.sender
        ));
    }
    Ok(())
}

fn validate_path_update_envelope_metadata(
    commit: &CommitEnvelope,
    path_update: &PathUpdateEnvelope,
) -> Result<(), String> {
    if path_update.group_id != commit.group_id {
        return Err(format!(
            "path update group_id mismatch: commit={} path={}",
            commit.group_id, path_update.group_id
        ));
    }
    if path_update.epoch != commit.epoch {
        return Err(format!(
            "path update epoch mismatch: commit={} path={}",
            commit.epoch, path_update.epoch
        ));
    }
    if path_update.sender_leaf != commit.sender_leaf {
        return Err(format!(
            "path update sender mismatch: commit={} path={}",
            commit.sender_leaf, path_update.sender_leaf
        ));
    }
    Ok(())
}

fn build_join_state_from_commit_material(
    group_id: &str,
    leaves: Vec<LeafNode>,
    commit: &CommitEnvelope,
    path_update: &PathUpdateEnvelope,
    receiver_private: &HybridPrivateKey,
) -> Result<(ClientGroupState, Vec<Option<[u8; 32]>>), String> {
    validate_path_update_envelope_metadata(commit, path_update)?;
    let tree = RatchetTree::from_leaves(leaves);
    let mut group_state = ClientGroupState::new(group_id.to_string(), tree, 0);
    group_state.set_epoch(commit.epoch);

    group_state
        .ratchet_tree
        .apply_commit(&commit.commit)
        .ok_or_else(|| "failed to apply selected Add commit to base member tree".to_string())?;
    group_state.apply_group_context_extensions_from_proposals(&commit.commit.proposals);

    let receiver_public = hybrid_public_from_private(receiver_private);
    let own_leaf_index =
        find_leaf_by_public_key(&group_state.ratchet_tree, &receiver_public).ok_or_else(|| {
            "could not infer joiner leaf after applying Add commit; verify base member order and receiver key".to_string()
        })?;
    group_state.own_leaf_index = own_leaf_index;

    let derived = group_state
        .ratchet_tree
        .process_path_update_for_leaf(
            commit.commit.sender,
            own_leaf_index,
            receiver_private,
            &path_update.path_update,
        )
        .ok_or_else(|| "failed to process path update during joiner onboarding".to_string())?;

    group_state.clear_pending_proposals();
    let commit_context = commit.commit.encode();
    group_state.advance_epoch_with_context_and_tree_commit_secret(
        Some(&commit_context),
        derived.first().copied().flatten(),
    );
    ensure_group_state_consistency(&group_state, "join-from-latest apply")?;

    Ok((group_state, derived))
}

fn validate_welcome_for_joiner(
    welcome: &Welcome,
    commit: &CommitEnvelope,
    group_state: &ClientGroupState,
    derived: &[Option<[u8; 32]>],
    receiver_private: &HybridPrivateKey,
) -> Result<GroupSecrets, String> {
    if welcome.cipher_suite != 0x0001 {
        return Err(format!(
            "unsupported Welcome cipher suite {}",
            welcome.cipher_suite
        ));
    }
    if welcome.secrets.is_empty() {
        return Err("welcome has no encrypted secrets entries".to_string());
    }

    let expected_refs: HashSet<[u8; 32]> = commit
        .commit
        .proposals
        .iter()
        .filter_map(|proposal| match proposal {
            Proposal::Add(key_package) => Some(hash32_with_label(
                b"WELCOME-KEYPACKAGE-REF",
                &[&key_package.encode()],
            )),
            _ => None,
        })
        .collect();
    if expected_refs.is_empty() {
        return Err("selected commit has no Add proposal for Welcome onboarding".to_string());
    }

    let join_epoch = commit.epoch.saturating_add(1);
    let mut matched: Option<GroupSecrets> = None;
    for enc in &welcome.secrets {
        if !expected_refs.contains(&enc.key_package_ref_hash) {
            continue;
        }
        if let Some(secrets) =
            enc.decrypt_group_secrets(&commit.group_id, join_epoch, receiver_private)
        {
            matched = Some(secrets);
            break;
        }
    }
    let group_secrets = matched.ok_or_else(|| {
        "welcome does not contain decryptable GroupSecrets for this joiner".to_string()
    })?;

    if let Some(path_secret) = group_secrets.path_secret {
        let derived_first = derived
            .first()
            .and_then(|value| *value)
            .ok_or_else(|| "joiner derived no path secret while Welcome carried one".to_string())?;
        if path_secret != derived_first {
            return Err("welcome path_secret mismatch against derived path secret".to_string());
        }
    }

    let chain = group_state
        .key_schedule
        .chain_secrets_for_epoch(group_state.epoch)
        .ok_or_else(|| "missing key schedule chain secrets for welcome epoch".to_string())?;
    if group_secrets.joiner_secret != chain.joiner_secret {
        return Err(
            "welcome GroupSecrets.joiner_secret mismatch against local key schedule chain"
                .to_string(),
        );
    }

    let group_info_bytes = decrypt_hpke_payload(
        &chain.welcome_secret,
        &welcome_group_info_context(
            &group_state.group_id,
            group_state.epoch,
            commit.commit.sender,
        ),
        &welcome.encrypted_group_info,
    )
    .ok_or_else(|| "failed to decrypt welcome group_info".to_string())?;
    let group_info = GroupInfo::decode(&group_info_bytes)
        .ok_or_else(|| "failed to decode decrypted welcome group_info".to_string())?;
    if group_info.group_id != group_state.group_id {
        return Err(format!(
            "welcome group_id mismatch: welcome={} local={}",
            group_info.group_id, group_state.group_id
        ));
    }
    if group_info.epoch != group_state.epoch {
        return Err(format!(
            "welcome epoch mismatch: welcome={} local={}",
            group_info.epoch, group_state.epoch
        ));
    }
    if group_info.signer_leaf as usize != commit.commit.sender {
        return Err(format!(
            "welcome signer mismatch: welcome={} commit={}",
            group_info.signer_leaf, commit.commit.sender
        ));
    }
    if group_info.confirmed_transcript_hash != group_state.confirmed_transcript_hash() {
        return Err(
            "welcome confirmed_transcript_hash mismatch against local transcript state".to_string(),
        );
    }
    if !verify_confirmation_tag(
        &group_state
            .key_schedule
            .derive_secrets_for_epoch(&group_state.group_id, group_state.epoch)
            .ok_or_else(|| "missing key-schedule derived secrets for welcome epoch".to_string())?
            .confirmation_key,
        &group_info.confirmed_transcript_hash,
        &group_info.confirmation_tag,
    ) {
        return Err(
            "welcome confirmation_tag mismatch against transcript+key-schedule state".to_string(),
        );
    }
    let expected_tree_hash = tree_snapshot_hash(&group_state.ratchet_tree.encode());
    if group_info.tree_hash != expected_tree_hash {
        return Err("welcome tree hash mismatch against reconstructed tree".to_string());
    }
    if group_info.extensions != group_state.group_context_extensions {
        return Err(
            "welcome group extensions mismatch against reconstructed group context".to_string(),
        );
    }

    Ok(group_secrets)
}

fn load_receiver_private_from_file(path: &Path) -> Result<HybridPrivateKey, String> {
    let bytes = fs::read(path)
        .map_err(|err| format!("read receiver private {}: {err}", path.to_string_lossy()))?;
    let key_file: ReceiverPrivateFile = serde_json::from_slice(&bytes)
        .map_err(|err| format!("parse receiver private {}: {err}", path.to_string_lossy()))?;

    let classic_bytes = STANDARD
        .decode(&key_file.classic_x25519_private_b64)
        .map_err(|_| "classic_x25519_private_b64 is not valid base64".to_string())?;
    if classic_bytes.len() != 32 {
        return Err("classic_x25519_private_b64 must decode to 32 bytes".to_string());
    }
    let mut classic_arr = [0u8; 32];
    classic_arr.copy_from_slice(&classic_bytes);

    let seed_bytes = STANDARD
        .decode(&key_file.pq_kem_seed_b64)
        .map_err(|_| "pq_kem_seed_b64 is not valid base64".to_string())?;
    if seed_bytes.len() != 64 {
        return Err("pq_kem_seed_b64 must decode to 64 bytes".to_string());
    }
    let mut seed_arr = [0u8; 64];
    seed_arr.copy_from_slice(&seed_bytes);

    Ok(HybridPrivateKey {
        classic: X25519Priv::from(classic_arr),
        pq: KyberPriv::from_seed(Seed::from(seed_arr)),
    })
}

fn latest_receiver_private_path(state: &UiState, username: &str) -> Result<Option<String>, String> {
    let keypackages = load_keypackages(state, username)?;
    Ok(keypackages
        .items
        .iter()
        .filter(|item| !item.receiver_private_path.trim().is_empty())
        .max_by_key(|item| item.created_at)
        .map(|item| item.receiver_private_path.clone()))
}

async fn ds_list_messages_typed(
    state: &UiState,
    username: &str,
    group_id: &str,
    limit: usize,
    kind: &str,
    before_id: Option<i64>,
) -> Result<DsListMessagesResponse, String> {
    let query = ListMessagesQuery {
        username: username.to_string(),
        kind: Some(kind.to_string()),
        limit: Some(limit),
        before_id,
    };
    let value = ds_list_messages(state, username, group_id, &query).await?;
    serde_json::from_value(value).map_err(|err| format!("parse list messages response: {err}"))
}

async fn ds_fetch_group_message_typed(
    state: &UiState,
    username: &str,
    group_id: &str,
    message_id: i64,
) -> Result<DsFetchGroupMessageResponse, String> {
    let value = ds_fetch_group_message(state, username, group_id, message_id).await?;
    serde_json::from_value(value).map_err(|err| format!("parse fetch message response: {err}"))
}

fn extract_sorted_unique_message_ids(messages: &[DsMessageSummary]) -> Vec<i64> {
    let mut ids = Vec::with_capacity(messages.len());
    for item in messages {
        if let Ok(id) = item.id.parse::<i64>() {
            ids.push(id);
        }
    }
    ids.sort_unstable();
    ids.dedup();
    ids
}

fn candidate_path_update_ids(
    commit_id: i64,
    next_commit_id: Option<i64>,
    path_ids: &[i64],
) -> Vec<i64> {
    let mut out = Vec::new();
    for id in path_ids {
        if *id <= commit_id {
            continue;
        }
        if let Some(next) = next_commit_id {
            if *id >= next {
                break;
            }
        }
        out.push(*id);
    }
    out
}

fn hybrid_public_from_private(private: &HybridPrivateKey) -> HybridPublicKey {
    HybridPublicKey {
        classic: X25519Pub::from(&private.classic),
        pq: private.pq.encapsulation_key().clone(),
    }
}

fn find_leaf_by_public_key(tree: &RatchetTree, target: &HybridPublicKey) -> Option<usize> {
    for node_index in (0..tree.nodes.len()).step_by(2) {
        if let Some(Node::Leaf(leaf)) = tree.nodes.get(node_index) {
            if &leaf.public_key == target {
                return Some(node_index / 2);
            }
        }
    }
    None
}

#[derive(Debug)]
struct JoinMaterial {
    commit_id: i64,
    commit: CommitEnvelope,
    path_update: PathUpdateEnvelope,
    welcome: Welcome,
}

async fn load_base_member_leaves_from_ds(
    state: &UiState,
    username: &str,
    base_member_usernames: &[String],
) -> Result<(Vec<LeafNode>, Vec<(String, String)>), String> {
    if base_member_usernames.is_empty() {
        return Err(
            "base_member_usernames is required (comma-separated usernames in pre-commit leaf order)"
                .to_string(),
        );
    }

    let mut leaves = Vec::with_capacity(base_member_usernames.len());
    let mut labels = Vec::with_capacity(base_member_usernames.len());
    for member in base_member_usernames {
        let member_name = member.trim();
        if member_name.is_empty() {
            return Err("base_member_usernames must not contain empty values".to_string());
        }
        let fetched = ds_fetch_keypackage(state, username, member_name).await?;
        let keypackage_b64 = fetched
            .get("keypackage_bytes")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                format!(
                    "fetch keypackage for '{}' did not include keypackage_bytes",
                    member_name
                )
            })?;
        let keypackage = decode_keypackage_b64(keypackage_b64)?;
        let key_id = short_id(&keypackage.init_key.to_bytes());
        leaves.push(LeafNode {
            public_key: keypackage.init_key.clone(),
            credential: keypackage.identity.clone(),
        });
        labels.push((key_id, member_name.to_string()));
    }

    Ok((leaves, labels))
}

async fn find_join_material_from_welcome(
    state: &UiState,
    username: &str,
    group_id: &str,
    limit: usize,
) -> Result<JoinMaterial, String> {
    let welcome_summaries =
        ds_list_messages_typed(state, username, group_id, limit, "welcome", None).await?;
    let commit_summaries =
        ds_list_messages_typed(state, username, group_id, limit, "commit", None).await?;
    let path_summaries =
        ds_list_messages_typed(state, username, group_id, limit, "path_update", None).await?;

    let mut welcome_ids = extract_sorted_unique_message_ids(&welcome_summaries.messages);
    if welcome_ids.is_empty() {
        return Err("no welcome messages found for group".to_string());
    }
    let commit_ids = extract_sorted_unique_message_ids(&commit_summaries.messages);
    if commit_ids.is_empty() {
        return Err("no commit messages found for group".to_string());
    }
    let path_ids = extract_sorted_unique_message_ids(&path_summaries.messages);
    if path_ids.is_empty() {
        return Err("no path_update messages found for group".to_string());
    }

    welcome_ids.reverse();
    for welcome_id in welcome_ids {
        let fetched_welcome =
            ds_fetch_group_message_typed(state, username, group_id, welcome_id).await?;
        if fetched_welcome.kind != "welcome" {
            continue;
        }
        let welcome_bytes = match STANDARD.decode(&fetched_welcome.message_bytes) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let Some(welcome) = Welcome::decode(&welcome_bytes) else {
            continue;
        };

        let mut matched_commit: Option<(usize, i64)> = None;
        for (idx, commit_id) in commit_ids.iter().enumerate() {
            if *commit_id < welcome_id {
                matched_commit = Some((idx, *commit_id));
            } else {
                break;
            }
        }
        let Some((commit_pos, commit_id)) = matched_commit else {
            continue;
        };

        let next_commit = commit_ids.get(commit_pos + 1).copied();
        let fetched_commit =
            ds_fetch_group_message_typed(state, username, group_id, commit_id).await?;
        if fetched_commit.kind != "commit" {
            continue;
        }
        let commit_bytes = match STANDARD.decode(&fetched_commit.message_bytes) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let Some(commit_env) = CommitEnvelope::decode(&commit_bytes) else {
            continue;
        };
        if commit_env.group_id != group_id {
            continue;
        }

        let candidate_path_ids = candidate_path_update_ids(commit_id, next_commit, &path_ids);
        for path_id in candidate_path_ids {
            let fetched_path =
                ds_fetch_group_message_typed(state, username, group_id, path_id).await?;
            if fetched_path.kind != "path_update" {
                continue;
            }
            let path_bytes = match STANDARD.decode(&fetched_path.message_bytes) {
                Ok(bytes) => bytes,
                Err(_) => continue,
            };
            let Some(path_env) = PathUpdateEnvelope::decode(&path_bytes) else {
                continue;
            };
            if validate_path_update_envelope_metadata(&commit_env, &path_env).is_ok() {
                return Ok(JoinMaterial {
                    commit_id,
                    commit: commit_env,
                    path_update: path_env,
                    welcome,
                });
            }
        }
    }

    Err("no valid welcome/commit/path tuple found for onboarding".to_string())
}

#[derive(Debug)]
struct SyncOutcome {
    applied: usize,
    skipped: usize,
}

async fn fetch_and_apply_latest_once(
    state: &UiState,
    username: &str,
    group_state: &mut ClientGroupState,
    receiver_private: Option<&HybridPrivateKey>,
    limit: usize,
) -> Result<SyncOutcome, String> {
    let commit_summaries = ds_list_messages_typed(
        state,
        username,
        &group_state.group_id,
        limit,
        "commit",
        None,
    )
    .await?;
    let path_summaries = ds_list_messages_typed(
        state,
        username,
        &group_state.group_id,
        limit,
        "path_update",
        None,
    )
    .await?;

    let commit_ids = extract_sorted_unique_message_ids(&commit_summaries.messages);
    if commit_ids.is_empty() {
        return Ok(SyncOutcome {
            applied: 0,
            skipped: 0,
        });
    }
    let path_ids = extract_sorted_unique_message_ids(&path_summaries.messages);

    let mut applied = 0usize;
    let mut skipped = 0usize;

    for (idx, commit_id) in commit_ids.iter().enumerate() {
        if group_state.has_applied_commit_id(*commit_id) {
            skipped = skipped.saturating_add(1);
            continue;
        }

        let next_commit = commit_ids.get(idx + 1).copied();
        let fetched_commit =
            ds_fetch_group_message_typed(state, username, &group_state.group_id, *commit_id)
                .await?;
        if fetched_commit.kind != "commit" {
            skipped = skipped.saturating_add(1);
            continue;
        }
        let commit_bytes = STANDARD
            .decode(&fetched_commit.message_bytes)
            .map_err(|_| {
                format!(
                    "commit message {} payload must be base64",
                    fetched_commit.id
                )
            })?;
        let commit_env = match CommitEnvelope::decode(&commit_bytes) {
            Some(v) => v,
            None => {
                skipped = skipped.saturating_add(1);
                continue;
            }
        };

        if commit_env.group_id != group_state.group_id {
            skipped = skipped.saturating_add(1);
            continue;
        }
        if commit_env.epoch > group_state.epoch {
            break;
        }
        if validate_commit_envelope_metadata(group_state, &commit_env).is_err() {
            skipped = skipped.saturating_add(1);
            continue;
        }

        let mut derived_for_commit: Option<Vec<Option<[u8; 32]>>> = None;
        if let Some(receiver_private) = receiver_private {
            let mut matched_path_update: Option<PathUpdateEnvelope> = None;
            let candidate_path_ids = candidate_path_update_ids(*commit_id, next_commit, &path_ids);
            for path_id in candidate_path_ids {
                let fetched_path =
                    ds_fetch_group_message_typed(state, username, &group_state.group_id, path_id)
                        .await?;
                if fetched_path.kind != "path_update" {
                    continue;
                }
                let path_bytes = match STANDARD.decode(&fetched_path.message_bytes) {
                    Ok(bytes) => bytes,
                    Err(_) => continue,
                };
                let Some(path_env) = PathUpdateEnvelope::decode(&path_bytes) else {
                    continue;
                };
                if validate_path_update_envelope_metadata(&commit_env, &path_env).is_ok() {
                    matched_path_update = Some(path_env);
                    break;
                }
            }

            let path_env = matched_path_update.ok_or_else(|| {
                format!(
                    "strict receiver policy: missing or mismatched path_update for commit_id={} (group={}, epoch={}, sender_leaf={})",
                    commit_id, commit_env.group_id, commit_env.epoch, commit_env.sender_leaf
                )
            })?;
            let derived = group_state
                .ratchet_tree
                .apply_commit_with_path_update(
                    &commit_env.commit,
                    &path_env.path_update,
                    group_state.own_leaf_index,
                    receiver_private,
                )
                .ok_or_else(|| "failed to apply commit+path update during sync".to_string())?;
            derived_for_commit = Some(derived);
        } else {
            group_state
                .ratchet_tree
                .apply_commit(&commit_env.commit)
                .ok_or_else(|| "failed to apply commit during sync".to_string())?;
        }
        group_state.apply_group_context_extensions_from_proposals(&commit_env.commit.proposals);

        group_state.clear_pending_proposals();
        let tree_commit_secret = derived_for_commit
            .as_ref()
            .and_then(|secrets| secrets.first().copied().flatten());
        group_state.advance_epoch_with_context_and_tree_commit_secret(
            Some(&commit_bytes),
            tree_commit_secret,
        );
        ensure_group_state_consistency(group_state, "sync-apply-latest commit apply")?;
        group_state.mark_applied_commit_id(*commit_id);
        applied = applied.saturating_add(1);
    }

    Ok(SyncOutcome { applied, skipped })
}

async fn action_commit_from_pending(
    state: &UiState,
    payload: &CommitFromPendingPayload,
    group_id: &str,
) -> Result<CommitFromPendingResponse, String> {
    let mut group_state = load_group_state(state, &payload.username, group_id)?;
    if group_state.group_id != group_id {
        return Err(format!(
            "group_id mismatch: state={} requested={}",
            group_state.group_id, group_id
        ));
    }

    let sender_leaf = resolve_sender_leaf(&group_state, payload.sender_leaf)?;
    let (commit, path_update) = build_commit_from_pending(&group_state, sender_leaf)?;
    let tree_commit_secret = path_update.path_secrets.first().copied();
    let welcome = build_welcome_for_commit(&group_state, &commit, &path_update)?;
    let commit_envelope = CommitEnvelope {
        group_id: group_state.group_id.clone(),
        epoch: group_state.epoch,
        sender_leaf,
        commit: commit.clone(),
    };
    let path_update_envelope = PathUpdateEnvelope {
        group_id: group_state.group_id.clone(),
        epoch: group_state.epoch,
        sender_leaf,
        path_update,
    };
    let commit_b64 = STANDARD.encode(commit_envelope.encode());
    let path_update_b64 = STANDARD.encode(path_update_envelope.encode());
    let welcome_b64 = welcome.map(|msg| STANDARD.encode(msg.encode()));

    ds_submit_commit(
        state,
        &payload.username,
        group_id,
        &commit_b64,
        Some(path_update_b64.as_str()),
        welcome_b64.as_deref(),
    )
    .await?;

    let commit_context = commit.encode();
    group_state
        .ratchet_tree
        .apply_commit(&commit)
        .ok_or_else(|| "failed to apply generated commit to local state".to_string())?;
    group_state.apply_group_context_extensions_from_proposals(&commit.proposals);
    group_state.clear_pending_proposals();
    group_state.advance_epoch_with_context_and_tree_commit_secret(
        Some(&commit_context),
        tree_commit_secret,
    );
    ensure_group_state_consistency(&group_state, "commit-from-pending apply")?;
    save_group_state(state, &payload.username, group_id, &group_state)?;
    let _ = add_group(state, &payload.username, group_id);

    Ok(CommitFromPendingResponse {
        commit_b64,
        path_update_b64,
        welcome_b64,
        submitted: true,
        sender_leaf,
        epoch: group_state.epoch,
        pending_proposals: group_state.pending_proposals.len(),
        state_path: group_state_path(&state.state_dir, &payload.username, group_id)
            .to_string_lossy()
            .to_string(),
    })
}

async fn action_sync_apply_latest(
    state: &UiState,
    payload: &SyncApplyPayload,
    group_id: &str,
) -> Result<SyncApplyResponse, String> {
    let mut group_state = load_group_state(state, &payload.username, group_id)?;
    if group_state.group_id != group_id {
        return Err(format!(
            "group_id mismatch: state={} requested={}",
            group_state.group_id, group_id
        ));
    }

    let receiver_path = match payload.receiver_private_path.as_deref() {
        Some(path) if !path.trim().is_empty() => Some(path.to_string()),
        _ => latest_receiver_private_path(state, &payload.username)?,
    };
    let receiver_private = match receiver_path.as_deref() {
        Some(path) => Some(load_receiver_private_from_file(Path::new(path))?),
        None => None,
    };

    let outcome = fetch_and_apply_latest_once(
        state,
        &payload.username,
        &mut group_state,
        receiver_private.as_ref(),
        payload.limit.unwrap_or(50),
    )
    .await?;
    if outcome.applied > 0 {
        save_group_state(state, &payload.username, group_id, &group_state)?;
    }
    let _ = add_group(state, &payload.username, group_id);

    Ok(SyncApplyResponse {
        applied: outcome.applied,
        skipped: outcome.skipped,
        local_epoch: group_state.epoch,
        used_receiver_private: receiver_private.is_some(),
        receiver_private_path: receiver_path,
        state_path: group_state_path(&state.state_dir, &payload.username, group_id)
            .to_string_lossy()
            .to_string(),
    })
}

async fn action_join_from_latest(
    state: &UiState,
    payload: &JoinFromLatestPayload,
    group_id: &str,
) -> Result<JoinFromLatestResponse, String> {
    let existing_path = group_state_path(&state.state_dir, &payload.username, group_id);
    if existing_path.exists() {
        return Err(format!(
            "group state already exists at {}. Use Sync + Apply Latest.",
            existing_path.to_string_lossy()
        ));
    }

    let receiver_path = match payload.receiver_private_path.as_deref() {
        Some(path) if !path.trim().is_empty() => path.to_string(),
        _ => latest_receiver_private_path(state, &payload.username)?.ok_or_else(|| {
            "no receiver private key found; generate/publish a keypackage first".to_string()
        })?,
    };
    let receiver_private = load_receiver_private_from_file(Path::new(&receiver_path))?;
    let receiver_public = hybrid_public_from_private(&receiver_private);

    let limit = payload.limit.unwrap_or(50);
    let join = find_join_material_from_welcome(state, &payload.username, group_id, limit).await?;

    let base_members = payload.base_member_usernames.clone().unwrap_or_default();
    let (leaves, base_labels) =
        load_base_member_leaves_from_ds(state, &payload.username, &base_members).await?;
    let (mut group_state, derived) = build_join_state_from_commit_material(
        group_id,
        leaves,
        &join.commit,
        &join.path_update,
        &receiver_private,
    )?;
    let _group_secrets = validate_welcome_for_joiner(
        &join.welcome,
        &join.commit,
        &group_state,
        &derived,
        &receiver_private,
    )?;
    let own_leaf_index = group_state.own_leaf_index;
    group_state.mark_applied_commit_id(join.commit_id);

    let outcome = fetch_and_apply_latest_once(
        state,
        &payload.username,
        &mut group_state,
        Some(&receiver_private),
        limit,
    )
    .await?;

    save_group_state(state, &payload.username, group_id, &group_state)?;
    let _ = add_group(state, &payload.username, group_id);

    for (key_id, label) in base_labels {
        let _ = upsert_group_label(state, &payload.username, group_id, &key_id, &label);
    }
    let own_key_id = short_id(&receiver_public.to_bytes());
    let _ = upsert_group_label(
        state,
        &payload.username,
        group_id,
        &own_key_id,
        &payload.username,
    );

    Ok(JoinFromLatestResponse {
        joined: true,
        commit_id: join.commit_id,
        own_leaf_index,
        local_epoch: group_state.epoch,
        applied_after_join: outcome.applied,
        skipped_after_join: outcome.skipped,
        receiver_private_path: receiver_path,
        state_path: group_state_path(&state.state_dir, &payload.username, group_id)
            .to_string_lossy()
            .to_string(),
    })
}

async fn action_add_proposal(
    state: &UiState,
    payload: &ActionAddPayload,
    group_id: &str,
) -> Result<ActionProposalResponse, String> {
    let mut group_state = load_group_state(state, &payload.username, group_id)?;
    if group_state.group_id != group_id {
        return Err(format!(
            "group_id mismatch: state={} requested={}",
            group_state.group_id, group_id
        ));
    }
    let sender_leaf = resolve_sender_leaf(&group_state, payload.sender_leaf)?;
    let keypackage = decode_keypackage_b64(&payload.keypackage_b64)?;
    let key_id = short_id(&keypackage.init_key.to_bytes());
    if let Some(target_username) = payload.target_username.as_deref() {
        upsert_group_label(state, &payload.username, group_id, &key_id, target_username)?;
    }
    let proposal = Proposal::Add(keypackage);
    let envelope = ProposalEnvelope {
        group_id: group_state.group_id.clone(),
        epoch: group_state.epoch,
        sender_leaf,
        proposal: proposal.clone(),
    };
    let proposal_b64 = STANDARD.encode(envelope.encode());
    let submit = payload.submit.unwrap_or(true);
    if submit {
        ds_submit_proposal(state, &payload.username, group_id, &proposal_b64).await?;
    }
    group_state.queue_proposal(&proposal);
    save_group_state(state, &payload.username, group_id, &group_state)?;
    Ok(ActionProposalResponse {
        proposal_b64,
        submitted: submit,
        pending_proposals: group_state.pending_proposals.len(),
        state_path: group_state_path(&state.state_dir, &payload.username, group_id)
            .to_string_lossy()
            .to_string(),
    })
}

async fn action_remove_proposal(
    state: &UiState,
    payload: &ActionRemovePayload,
    group_id: &str,
) -> Result<ActionProposalResponse, String> {
    let mut group_state = load_group_state(state, &payload.username, group_id)?;
    if group_state.group_id != group_id {
        return Err(format!(
            "group_id mismatch: state={} requested={}",
            group_state.group_id, group_id
        ));
    }
    let sender_leaf = resolve_sender_leaf(&group_state, payload.sender_leaf)?;
    if payload.remove_leaf >= group_state.ratchet_tree.leaf_count() {
        return Err(format!(
            "remove leaf {} out of bounds (leaf_count={})",
            payload.remove_leaf,
            group_state.ratchet_tree.leaf_count()
        ));
    }
    let proposal = Proposal::Remove {
        leaf_index: payload.remove_leaf,
    };
    let envelope = ProposalEnvelope {
        group_id: group_state.group_id.clone(),
        epoch: group_state.epoch,
        sender_leaf,
        proposal: proposal.clone(),
    };
    let proposal_b64 = STANDARD.encode(envelope.encode());
    let submit = payload.submit.unwrap_or(true);
    if submit {
        ds_submit_proposal(state, &payload.username, group_id, &proposal_b64).await?;
    }
    group_state.queue_proposal(&proposal);
    save_group_state(state, &payload.username, group_id, &group_state)?;
    Ok(ActionProposalResponse {
        proposal_b64,
        submitted: submit,
        pending_proposals: group_state.pending_proposals.len(),
        state_path: group_state_path(&state.state_dir, &payload.username, group_id)
            .to_string_lossy()
            .to_string(),
    })
}

async fn action_update_proposal(
    state: &UiState,
    payload: &ActionUpdatePayload,
    group_id: &str,
) -> Result<ActionProposalResponse, String> {
    let mut group_state = load_group_state(state, &payload.username, group_id)?;
    if group_state.group_id != group_id {
        return Err(format!(
            "group_id mismatch: state={} requested={}",
            group_state.group_id, group_id
        ));
    }
    let sender_leaf = resolve_sender_leaf(&group_state, payload.sender_leaf)?;
    let target_leaf = payload.target_leaf.unwrap_or(group_state.own_leaf_index);
    if target_leaf >= group_state.ratchet_tree.leaf_count() {
        return Err(format!(
            "target leaf {} out of bounds (leaf_count={})",
            target_leaf,
            group_state.ratchet_tree.leaf_count()
        ));
    }
    let keypackage = decode_keypackage_b64(&payload.keypackage_b64)?;
    let proposal = Proposal::Update {
        leaf_index: target_leaf,
        key_package: keypackage,
    };
    let envelope = ProposalEnvelope {
        group_id: group_state.group_id.clone(),
        epoch: group_state.epoch,
        sender_leaf,
        proposal: proposal.clone(),
    };
    let proposal_b64 = STANDARD.encode(envelope.encode());
    let submit = payload.submit.unwrap_or(true);
    if submit {
        ds_submit_proposal(state, &payload.username, group_id, &proposal_b64).await?;
    }
    group_state.queue_proposal(&proposal);
    save_group_state(state, &payload.username, group_id, &group_state)?;
    Ok(ActionProposalResponse {
        proposal_b64,
        submitted: submit,
        pending_proposals: group_state.pending_proposals.len(),
        state_path: group_state_path(&state.state_dir, &payload.username, group_id)
            .to_string_lossy()
            .to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use hybrid_mls::ds::config::StorageConfig;
    use hybrid_mls::ds::http::{self as ds_http, ApiState as DsApiState};
    use serde_json::json;
    use std::collections::{BTreeMap, HashSet};
    use std::future::Future;
    use tokio::net::TcpListener;
    use tokio::task::JoinHandle;

    async fn spawn_router(app: Router) -> (String, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind listener");
        let addr = listener.local_addr().expect("listener addr");
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve app");
        });
        (format!("http://{}", addr), handle)
    }

    fn test_run_dir(prefix: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "hybrid-mls-{}-{}-{}",
            prefix,
            std::process::id(),
            rand::random::<u64>()
        ));
        fs::create_dir_all(&dir).expect("create run dir");
        dir
    }

    async fn post_json(client: &Client, url: &str, body: serde_json::Value) -> serde_json::Value {
        let resp = client
            .post(url)
            .json(&body)
            .send()
            .await
            .expect("post request");
        let status = resp.status();
        let text = resp.text().await.expect("response text");
        assert!(
            status.is_success(),
            "unexpected status {} for {} with body {}",
            status,
            url,
            text
        );
        serde_json::from_str(&text).expect("parse post json")
    }

    async fn get_json(client: &Client, url: &str) -> serde_json::Value {
        let resp = client.get(url).send().await.expect("get request");
        let status = resp.status();
        let text = resp.text().await.expect("response text");
        assert!(
            status.is_success(),
            "unexpected status {} for {} with body {}",
            status,
            url,
            text
        );
        serde_json::from_str(&text).expect("parse get json")
    }

    async fn get_text(client: &Client, url: &str) -> String {
        let resp = client.get(url).send().await.expect("get request");
        let status = resp.status();
        let text = resp.text().await.expect("response text");
        assert!(
            status.is_success(),
            "unexpected status {} for {} with body {}",
            status,
            url,
            text
        );
        text
    }

    async fn get_text_with_cookie(client: &Client, url: &str, cookie: &str) -> String {
        let resp = client
            .get(url)
            .header("Cookie", cookie)
            .send()
            .await
            .expect("get request with cookie");
        let status = resp.status();
        let text = resp.text().await.expect("response text");
        assert!(
            status.is_success(),
            "unexpected status {} for {} with body {}",
            status,
            url,
            text
        );
        text
    }

    fn run_async_test_on_large_stack<F>(name: &str, fut: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let handle = std::thread::Builder::new()
            .name(name.to_string())
            .stack_size(UI_WORKER_STACK_BYTES)
            .spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("build runtime");
                runtime.block_on(fut);
            })
            .expect("spawn large-stack test thread");
        handle.join().expect("join large-stack test thread");
    }

    fn test_client() -> Client {
        Client::new()
    }

    fn assert_admin_demo_detail_layout_invariants(detail: &serde_json::Value) {
        let leaf_count = detail["data"]["leaf_count"]
            .as_u64()
            .expect("leaf_count as u64");
        let node_count = detail["data"]["node_count"]
            .as_u64()
            .expect("node_count as u64");
        let expected_nodes = if leaf_count == 0 {
            0
        } else {
            2 * leaf_count - 1
        };
        assert_eq!(
            node_count, expected_nodes,
            "node_count must follow 2*leaf_count-1 invariant"
        );
        let members = detail["data"]["members"].as_array().expect("members array");
        for member in members {
            let leaf_index = member["leaf_index"].as_u64().expect("member leaf_index");
            assert!(
                leaf_index < leaf_count,
                "member leaf_index {} must be < leaf_count {}",
                leaf_index,
                leaf_count
            );
        }
    }

    fn admin_demo_member_leaf_map(detail: &serde_json::Value) -> BTreeMap<String, u64> {
        let members = detail["data"]["members"].as_array().expect("members array");
        let mut by_name = BTreeMap::new();
        for member in members {
            let username = member["username"]
                .as_str()
                .expect("member username")
                .to_string();
            let leaf_index = member["leaf_index"].as_u64().expect("member leaf index");
            by_name.insert(username, leaf_index);
        }
        by_name
    }

    #[test]
    fn admin_demo_decode_migrates_legacy_members_state() {
        let legacy = json!({
            "epoch": 7,
            "members": [
                {"username": "A", "leaf_index": 0, "key_generation": 3},
                {"username": "C", "leaf_index": 3, "key_generation": 5}
            ],
            "logs": [],
            "last_action": "legacy"
        });
        let bytes = serde_json::to_vec(&legacy).expect("serialize legacy");
        let migrated = decode_admin_demo_state(&bytes).expect("migrate legacy state");

        assert_eq!(migrated.epoch, 7);
        assert_eq!(migrated.leaf_slots.len(), 4);
        assert!(
            matches!(
                migrated.leaf_slots[0].as_ref(),
                Some(slot) if slot.username == "A" && slot.key_generation == 3
            ),
            "expected A at leaf 0"
        );
        assert!(
            migrated.leaf_slots[1].is_none() && migrated.leaf_slots[2].is_none(),
            "expected intermediate blank leaves to be preserved"
        );
        assert!(
            matches!(
                migrated.leaf_slots[3].as_ref(),
                Some(slot) if slot.username == "C" && slot.key_generation == 5
            ),
            "expected C at leaf 3"
        );
    }

    #[test]
    fn admin_demo_decode_rejects_legacy_duplicate_leaf_indices() {
        let legacy = json!({
            "epoch": 2,
            "members": [
                {"username": "A", "leaf_index": 0, "key_generation": 1},
                {"username": "B", "leaf_index": 0, "key_generation": 1}
            ],
            "logs": [],
            "last_action": "legacy"
        });
        let bytes = serde_json::to_vec(&legacy).expect("serialize legacy");
        let err = decode_admin_demo_state(&bytes).expect_err("duplicate leaf_index must fail");
        assert!(
            err.contains("duplicate leaf_index"),
            "unexpected decode error: {err}"
        );
    }

    #[test]
    fn demo_add_placement_reuses_leftmost_blank_before_extending() {
        let mut leaf_slots = vec![
            Some(AdminDemoLeafSlot {
                username: "A".to_string(),
                key_generation: 1,
            }),
            None,
            Some(AdminDemoLeafSlot {
                username: "C".to_string(),
                key_generation: 2,
            }),
            None,
        ];

        let p1 = place_added_member_in_demo_tree(&mut leaf_slots, "D");
        assert_eq!(p1, DemoAddPlacement::ReusedBlankLeaf { leaf_index: 1 });
        assert_eq!(leaf_slots.len(), 4);
        assert!(
            matches!(
                leaf_slots[1].as_ref(),
                Some(slot) if slot.username == "D"
            ),
            "expected D at reused leftmost blank leaf 1"
        );

        let p2 = place_added_member_in_demo_tree(&mut leaf_slots, "E");
        assert_eq!(p2, DemoAddPlacement::ReusedBlankLeaf { leaf_index: 3 });
        assert_eq!(leaf_slots.len(), 4);
        assert!(
            matches!(
                leaf_slots[3].as_ref(),
                Some(slot) if slot.username == "E"
            ),
            "expected E at reused leftmost blank leaf 3"
        );

        let p3 = place_added_member_in_demo_tree(&mut leaf_slots, "F");
        assert_eq!(
            p3,
            DemoAddPlacement::ExtendedTree {
                leaf_index: 4,
                previous_leaf_count: 4
            }
        );
        assert_eq!(leaf_slots.len(), 5);
        assert!(
            matches!(
                leaf_slots[4].as_ref(),
                Some(slot) if slot.username == "F"
            ),
            "expected F at newly extended leaf 4"
        );
    }

    #[test]
    fn demo_remove_trim_truncates_only_right_edge_blanks() {
        let mut leaf_slots = vec![
            Some(AdminDemoLeafSlot {
                username: "A".to_string(),
                key_generation: 1,
            }),
            None,
            Some(AdminDemoLeafSlot {
                username: "C".to_string(),
                key_generation: 2,
            }),
            None,
            None,
        ];

        let trim = trim_trailing_blank_demo_leaves(&mut leaf_slots);
        assert_eq!(
            trim,
            DemoRemoveTrimResult {
                previous_leaf_count: 5,
                new_leaf_count: 3
            }
        );
        assert_eq!(leaf_slots.len(), 3);
        assert!(
            leaf_slots[1].is_none(),
            "middle blank leaf must be preserved (no compaction)"
        );

        let trim_again = trim_trailing_blank_demo_leaves(&mut leaf_slots);
        assert_eq!(
            trim_again,
            DemoRemoveTrimResult {
                previous_leaf_count: 3,
                new_leaf_count: 3
            }
        );
    }

    #[test]
    fn demo_binary_topology_indices_follow_left_balanced_invariants() {
        fn left_subtree_size(leaf_count: usize) -> usize {
            if leaf_count <= 1 {
                return 1;
            }
            let mut size = 1usize;
            let target = leaf_count - 1;
            while (size << 1) <= target {
                size <<= 1;
            }
            size
        }

        fn root_index_for_range(start_leaf: usize, leaf_count: usize) -> usize {
            if leaf_count <= 1 {
                return leaf_node_index(start_leaf);
            }
            let left_count = left_subtree_size(leaf_count);
            leaf_node_index(start_leaf) + (2 * left_count - 1)
        }

        fn collect_nodes(
            start_leaf: usize,
            leaf_count: usize,
            out: &mut Vec<(usize, Option<usize>)>,
        ) {
            let root = root_index_for_range(start_leaf, leaf_count);
            if leaf_count <= 1 {
                out.push((root, Some(start_leaf)));
                return;
            }
            out.push((root, None));
            let left_count = left_subtree_size(leaf_count);
            let right_start = start_leaf + left_count;
            let right_count = leaf_count - left_count;
            collect_nodes(start_leaf, left_count, out);
            collect_nodes(right_start, right_count, out);
        }

        for leaf_count in 1usize..=12 {
            let mut nodes = Vec::new();
            collect_nodes(0, leaf_count, &mut nodes);
            assert_eq!(
                nodes.len(),
                node_count_for_leaf_count(leaf_count),
                "unexpected node count for {} leaves",
                leaf_count
            );

            let mut unique = HashSet::new();
            for (node_index, _) in &nodes {
                assert!(
                    unique.insert(*node_index),
                    "duplicate node index {} for leaf_count {}",
                    node_index,
                    leaf_count
                );
            }

            let mut leaf_nodes: Vec<(usize, usize)> = nodes
                .iter()
                .filter_map(|(node_index, leaf_index)| leaf_index.map(|leaf| (*node_index, leaf)))
                .collect();
            leaf_nodes.sort_by_key(|(_, leaf_index)| *leaf_index);
            assert_eq!(
                leaf_nodes.len(),
                leaf_count,
                "unexpected leaf node count for {} leaves",
                leaf_count
            );
            for (expected_leaf, (node_index, leaf_index)) in leaf_nodes.iter().enumerate() {
                assert_eq!(*leaf_index, expected_leaf);
                assert_eq!(
                    *node_index,
                    leaf_node_index(*leaf_index),
                    "leaf node must map to even NodeIndex"
                );
                assert_eq!(*node_index % 2, 0, "leaf node index must be even");
            }

            for (node_index, leaf_index) in &nodes {
                if leaf_index.is_none() {
                    assert_eq!(*node_index % 2, 1, "parent node index must be odd");
                }
            }

            let expected_root = root_index_for_range(0, leaf_count);
            assert!(
                nodes
                    .iter()
                    .any(|(node_index, _)| *node_index == expected_root),
                "root NodeIndex {} missing for leaf_count {}",
                expected_root,
                leaf_count
            );
            if leaf_count > 1 {
                assert_eq!(expected_root % 2, 1, "non-trivial root must be odd");
            }
        }
    }

    #[test]
    fn ui_add_member_flow_keeps_group_visible_after_relogin() {
        run_async_test_on_large_stack("ui-add-member-flow", async move {
            let run_dir = test_run_dir("ui-gateway-e2e");
            let ds_data_dir = run_dir.join("data");
            let ds_db_path = run_dir.join("ds.sqlite");
            fs::create_dir_all(&ds_data_dir).expect("create ds data dir");

            let mut ds_state = DsApiState::default();
            ds_state.min_proposals_per_commit = 1;
            ds_state.storage = StorageConfig::new(
                ds_data_dir.to_string_lossy().as_ref(),
                ds_db_path.to_string_lossy().as_ref(),
            );
            let ds_router = ds_http::router(ds_state);
            let (ds_base_url, ds_handle) = spawn_router(ds_router).await;

            let ui_state_dir = run_dir.join("ui-state");
            fs::create_dir_all(&ui_state_dir).expect("create ui state dir");
            let ui_state = UiState {
                base_url: ds_base_url.clone(),
                state_dir: ui_state_dir.clone(),
                client: Client::new(),
            };
            let ui_router = build_ui_router(ui_state.clone());
            let (ui_base_url, ui_handle) = spawn_router(ui_router).await;

            let client = test_client();
            let group_id = "g-ui-test";

            let register_a = post_json(
                &client,
                &format!("{}/ui/api/register", ui_base_url),
                json!({
                    "username": "parsania",
                    "password": "1234"
                }),
            )
            .await;
            assert_eq!(register_a["ok"].as_bool(), Some(true));

            let register_b = post_json(
                &client,
                &format!("{}/ui/api/register", ui_base_url),
                json!({
                    "username": "peyman",
                    "password": "1234"
                }),
            )
            .await;
            assert_eq!(register_b["ok"].as_bool(), Some(true));

            let open_group_a = post_json(
                &client,
                &format!("{}/ui/api/groups/open", ui_base_url),
                json!({
                    "username": "parsania",
                    "group_id": group_id
                }),
            )
            .await;
            assert_eq!(open_group_a["ok"].as_bool(), Some(true));

            let bootstrap_a = post_json(
                &client,
                &format!("{}/ui/api/groups/{}/bootstrap", ui_base_url, group_id),
                json!({
                    "username": "parsania"
                }),
            )
            .await;
            assert_eq!(bootstrap_a["ok"].as_bool(), Some(true));

            let b_keygen = post_json(
                &client,
                &format!("{}/ui/api/keypackages/generate", ui_base_url),
                json!({
                    "username": "peyman"
                }),
            )
            .await;
            assert_eq!(b_keygen["ok"].as_bool(), Some(true));
            let receiver_private_path = b_keygen["data"]["receiver_private_path"]
                .as_str()
                .expect("receiver path")
                .to_string();

            let fetch_b_keypackage = get_json(
                &client,
                &format!(
                    "{}/ui/api/keypackages/peyman?username=parsania",
                    ui_base_url
                ),
            )
            .await;
            assert_eq!(fetch_b_keypackage["ok"].as_bool(), Some(true));
            let b_keypackage_b64 = fetch_b_keypackage["data"]["keypackage_bytes"]
                .as_str()
                .expect("b keypackage")
                .to_string();

            let add_proposal = post_json(
                &client,
                &format!("{}/ui/api/groups/{}/actions/add", ui_base_url, group_id),
                json!({
                    "username": "parsania",
                    "target_username": "peyman",
                    "keypackage_b64": b_keypackage_b64,
                    "sender_leaf": null,
                    "submit": true
                }),
            )
            .await;
            assert_eq!(add_proposal["ok"].as_bool(), Some(true));

            let commit = post_json(
                &client,
                &format!(
                    "{}/ui/api/groups/{}/commit-from-pending",
                    ui_base_url, group_id
                ),
                json!({
                    "username": "parsania",
                    "sender_leaf": null
                }),
            )
            .await;
            assert_eq!(commit["ok"].as_bool(), Some(true));

            let join_b = post_json(
                &client,
                &format!(
                    "{}/ui/api/groups/{}/join-from-latest",
                    ui_base_url, group_id
                ),
                json!({
                    "username": "peyman",
                    "base_member_usernames": ["parsania"],
                    "limit": 50,
                    "receiver_private_path": receiver_private_path
                }),
            )
            .await;
            assert_eq!(
                join_b["ok"].as_bool(),
                Some(true),
                "join response: {}",
                join_b
            );
            assert!(join_b["data"]["joined"].as_bool().expect("joined flag"));
            assert!(
                join_b["data"]["applied_after_join"]
                    .as_u64()
                    .expect("applied count")
                    <= 1
            );

            let b_groups = get_json(
                &client,
                &format!("{}/ui/api/groups?username=peyman", ui_base_url),
            )
            .await;
            assert_eq!(b_groups["ok"].as_bool(), Some(true));
            let groups = b_groups["data"]["groups"].as_array().expect("groups array");
            assert!(groups.iter().any(|g| g.as_str() == Some(group_id)));

            let logout_b = post_json(
                &client,
                &format!("{}/ui/api/logout", ui_base_url),
                json!({
                    "username": "peyman"
                }),
            )
            .await;
            assert_eq!(logout_b["ok"].as_bool(), Some(true));

            let login_b = post_json(
                &client,
                &format!("{}/ui/api/login", ui_base_url),
                json!({
                    "username": "peyman",
                    "password": "1234"
                }),
            )
            .await;
            assert_eq!(login_b["ok"].as_bool(), Some(true));

            let b_groups_after_login = get_json(
                &client,
                &format!("{}/ui/api/groups?username=peyman", ui_base_url),
            )
            .await;
            assert_eq!(b_groups_after_login["ok"].as_bool(), Some(true));
            let groups_after_login = b_groups_after_login["data"]["groups"]
                .as_array()
                .expect("groups array after login");
            assert!(groups_after_login
                .iter()
                .any(|g| g.as_str() == Some(group_id)));

            ui_handle.abort();
            ds_handle.abort();
            let _ = fs::remove_dir_all(&run_dir);
        });
    }

    #[test]
    fn ui_admin_login_and_global_lists() {
        run_async_test_on_large_stack("ui-admin-flow", async move {
            let run_dir = test_run_dir("ui-admin");
            let ds_data_dir = run_dir.join("data");
            let ds_db_path = run_dir.join("ds.sqlite");
            fs::create_dir_all(&ds_data_dir).expect("create ds data dir");

            let mut ds_state = DsApiState::default();
            ds_state.min_proposals_per_commit = 1;
            ds_state.storage = StorageConfig::new(
                ds_data_dir.to_string_lossy().as_ref(),
                ds_db_path.to_string_lossy().as_ref(),
            );
            let ds_router = ds_http::router(ds_state);
            let (ds_base_url, ds_handle) = spawn_router(ds_router).await;

            let ui_state_dir = run_dir.join("ui-state");
            fs::create_dir_all(&ui_state_dir).expect("create ui state dir");
            let ui_state = UiState {
                base_url: ds_base_url.clone(),
                state_dir: ui_state_dir.clone(),
                client: Client::new(),
            };
            let ui_router = build_ui_router(ui_state.clone());
            let (ui_base_url, ui_handle) = spawn_router(ui_router).await;

            let client = test_client();
            let group_id = "admin-visible";

            let register = post_json(
                &client,
                &format!("{}/ui/api/register", ui_base_url),
                json!({
                    "username": "parsania",
                    "password": "1234"
                }),
            )
            .await;
            assert_eq!(register["ok"].as_bool(), Some(true));

            let open_group = post_json(
                &client,
                &format!("{}/ui/api/groups/open", ui_base_url),
                json!({
                    "username": "parsania",
                    "group_id": group_id
                }),
            )
            .await;
            assert_eq!(open_group["ok"].as_bool(), Some(true));

            let bootstrap = post_json(
                &client,
                &format!("{}/ui/api/groups/{}/bootstrap", ui_base_url, group_id),
                json!({
                    "username": "parsania"
                }),
            )
            .await;
            assert_eq!(bootstrap["ok"].as_bool(), Some(true));

            let send_message = post_json(
                &client,
                &format!("{}/ui/api/groups/{}/app-messages", ui_base_url, group_id),
                json!({
                    "username": "parsania",
                    "message": "hello from parsania"
                }),
            )
            .await;
            assert_eq!(send_message["ok"].as_bool(), Some(true));

            let admin_login = post_json(
                &client,
                &format!("{}/ui/api/login", ui_base_url),
                json!({
                    "username": "admin",
                    "password": "admin@123"
                }),
            )
            .await;
            assert_eq!(admin_login["ok"].as_bool(), Some(true));

            let admin_users = get_json(
                &client,
                &format!("{}/ui/api/admin/users?username=admin", ui_base_url),
            )
            .await;
            assert_eq!(admin_users["ok"].as_bool(), Some(true));
            let users = admin_users["data"]["users"]
                .as_array()
                .expect("users array");
            assert!(users.iter().any(|u| u.as_str() == Some("admin")));
            assert!(users.iter().any(|u| u.as_str() == Some("parsania")));

            let admin_groups = get_json(
                &client,
                &format!("{}/ui/api/admin/groups?username=admin", ui_base_url),
            )
            .await;
            assert_eq!(admin_groups["ok"].as_bool(), Some(true));
            let groups = admin_groups["data"]["groups"]
                .as_array()
                .expect("groups array");
            assert!(groups
                .iter()
                .any(|g| { g.get("group_id").and_then(|x| x.as_str()) == Some(group_id) }));

            ui_handle.abort();
            ds_handle.abort();
            let _ = fs::remove_dir_all(&run_dir);
        });
    }

    #[test]
    fn ui_admin_routes_require_admin_cookie_session() {
        run_async_test_on_large_stack("ui-admin-route-guard", async move {
            let run_dir = test_run_dir("ui-admin-route-guard");
            let ds_data_dir = run_dir.join("data");
            let ds_db_path = run_dir.join("ds.sqlite");
            fs::create_dir_all(&ds_data_dir).expect("create ds data dir");

            let mut ds_state = DsApiState::default();
            ds_state.min_proposals_per_commit = 1;
            ds_state.storage = StorageConfig::new(
                ds_data_dir.to_string_lossy().as_ref(),
                ds_db_path.to_string_lossy().as_ref(),
            );
            let ds_router = ds_http::router(ds_state);
            let (ds_base_url, ds_handle) = spawn_router(ds_router).await;

            let ui_state_dir = run_dir.join("ui-state");
            fs::create_dir_all(&ui_state_dir).expect("create ui state dir");
            let ui_state = UiState {
                base_url: ds_base_url,
                state_dir: ui_state_dir,
                client: Client::new(),
            };
            let ui_router = build_ui_router(ui_state);
            let (ui_base_url, ui_handle) = spawn_router(ui_router).await;

            let bootstrap_client = test_client();
            let login_page =
                get_text(&bootstrap_client, &format!("{}/ui/login", ui_base_url)).await;
            assert!(
                login_page.contains("username === 'admin' ? '/ui/admin' : '/ui/groups'"),
                "login UI should route admin users to /ui/admin"
            );

            let non_admin_client = test_client();
            let register_user = post_json(
                &non_admin_client,
                &format!("{}/ui/api/register", ui_base_url),
                json!({
                    "username": "parsania",
                    "password": "1234"
                }),
            )
            .await;
            assert_eq!(register_user["ok"].as_bool(), Some(true));

            let denied_admin_page = get_text_with_cookie(
                &non_admin_client,
                &format!("{}/ui/admin", ui_base_url),
                "ui_username=parsania",
            )
            .await;
            assert!(
                denied_admin_page.contains("Sign In or Register"),
                "non-admin access to /ui/admin should be redirected to login page"
            );

            let admin_client = test_client();
            let admin_login = post_json(
                &admin_client,
                &format!("{}/ui/api/login", ui_base_url),
                json!({
                    "username": "admin",
                    "password": "admin@123"
                }),
            )
            .await;
            assert_eq!(admin_login["ok"].as_bool(), Some(true));

            let admin_page = get_text_with_cookie(
                &admin_client,
                &format!("{}/ui/admin", ui_base_url),
                "ui_username=admin",
            )
            .await;
            assert!(
                admin_page.contains("Global Overview"),
                "admin should be able to access /ui/admin"
            );

            let create_demo = post_json(
                &admin_client,
                &format!("{}/ui/api/admin/demos", ui_base_url),
                json!({
                    "username": "admin",
                    "title": "Access Guard Demo"
                }),
            )
            .await;
            assert_eq!(create_demo["ok"].as_bool(), Some(true));
            let demo_id = create_demo["data"]["id"].as_str().expect("demo id");

            let denied_demo_page = get_text_with_cookie(
                &non_admin_client,
                &format!("{}/ui/admin/demos/{}", ui_base_url, demo_id),
                "ui_username=parsania",
            )
            .await;
            assert!(
                denied_demo_page.contains("Sign In or Register"),
                "non-admin access to /ui/admin/demos/:id should be redirected to login page"
            );

            ui_handle.abort();
            ds_handle.abort();
            let _ = fs::remove_dir_all(&run_dir);
        });
    }

    #[test]
    fn ui_admin_demo_index_create_and_open() {
        run_async_test_on_large_stack("ui-admin-demo-index", async move {
            let run_dir = test_run_dir("ui-admin-demo-index");
            let ds_data_dir = run_dir.join("data");
            let ds_db_path = run_dir.join("ds.sqlite");
            fs::create_dir_all(&ds_data_dir).expect("create ds data dir");

            let mut ds_state = DsApiState::default();
            ds_state.min_proposals_per_commit = 1;
            ds_state.storage = StorageConfig::new(
                ds_data_dir.to_string_lossy().as_ref(),
                ds_db_path.to_string_lossy().as_ref(),
            );
            let ds_router = ds_http::router(ds_state);
            let (ds_base_url, ds_handle) = spawn_router(ds_router).await;

            let ui_state_dir = run_dir.join("ui-state");
            fs::create_dir_all(&ui_state_dir).expect("create ui state dir");
            let ui_state = UiState {
                base_url: ds_base_url,
                state_dir: ui_state_dir.clone(),
                client: Client::new(),
            };
            let ui_router = build_ui_router(ui_state);
            let (ui_base_url, ui_handle) = spawn_router(ui_router).await;

            let client = test_client();
            let admin_login = post_json(
                &client,
                &format!("{}/ui/api/login", ui_base_url),
                json!({
                    "username": "admin",
                    "password": "admin@123"
                }),
            )
            .await;
            assert_eq!(admin_login["ok"].as_bool(), Some(true));

            let create_demo = post_json(
                &client,
                &format!("{}/ui/api/admin/demos", ui_base_url),
                json!({
                    "username": "admin",
                    "title": "Professor Demo"
                }),
            )
            .await;
            assert_eq!(create_demo["ok"].as_bool(), Some(true));
            let demo_id = create_demo["data"]["id"]
                .as_str()
                .expect("demo id")
                .to_string();

            let list_demos = get_json(
                &client,
                &format!("{}/ui/api/admin/demos?username=admin", ui_base_url),
            )
            .await;
            assert_eq!(list_demos["ok"].as_bool(), Some(true));
            let items = list_demos["data"]["items"].as_array().expect("demo items");
            assert!(items
                .iter()
                .any(|item| item.get("id").and_then(|v| v.as_str()) == Some(demo_id.as_str())));

            let detail = get_json(
                &client,
                &format!(
                    "{}/ui/api/admin/demos/{}?username=admin",
                    ui_base_url, demo_id
                ),
            )
            .await;
            assert_eq!(detail["ok"].as_bool(), Some(true));
            assert_eq!(detail["data"]["epoch"].as_u64(), Some(0));
            let manifest_path = detail["data"]["manifest_path"]
                .as_str()
                .expect("manifest path");
            assert!(Path::new(manifest_path).exists());

            let add_action = post_json(
                &client,
                &format!("{}/ui/api/admin/demos/{}/actions/add", ui_base_url, demo_id),
                json!({
                    "username": "admin",
                    "adder": "A",
                    "added": "B"
                }),
            )
            .await;
            assert_eq!(add_action["ok"].as_bool(), Some(true));
            assert_eq!(add_action["data"]["epoch"].as_u64(), Some(1));

            let update_action = post_json(
                &client,
                &format!(
                    "{}/ui/api/admin/demos/{}/actions/update",
                    ui_base_url, demo_id
                ),
                json!({
                    "username": "admin",
                    "updater": "B"
                }),
            )
            .await;
            assert_eq!(update_action["ok"].as_bool(), Some(true));
            assert_eq!(update_action["data"]["epoch"].as_u64(), Some(2));

            let remove_action = post_json(
                &client,
                &format!(
                    "{}/ui/api/admin/demos/{}/actions/remove",
                    ui_base_url, demo_id
                ),
                json!({
                    "username": "admin",
                    "remover": "A",
                    "removed": "B"
                }),
            )
            .await;
            assert_eq!(remove_action["ok"].as_bool(), Some(true));
            assert_eq!(remove_action["data"]["epoch"].as_u64(), Some(3));

            let detail_after_actions = get_json(
                &client,
                &format!(
                    "{}/ui/api/admin/demos/{}?username=admin",
                    ui_base_url, demo_id
                ),
            )
            .await;
            assert_eq!(detail_after_actions["ok"].as_bool(), Some(true));
            assert_eq!(detail_after_actions["data"]["epoch"].as_u64(), Some(3));
            let members_after = detail_after_actions["data"]["members"]
                .as_array()
                .expect("members after actions");
            assert_eq!(members_after.len(), 1);
            assert_eq!(
                members_after[0]["username"].as_str(),
                Some("A"),
                "expected only A after add->update->remove flow"
            );
            let logs_after = detail_after_actions["data"]["logs"]
                .as_array()
                .expect("logs after actions");
            assert!(
                logs_after.len() >= 10,
                "expected persisted MLS-style log entries, got {}",
                logs_after.len()
            );
            assert!(
                logs_after.iter().any(|entry| {
                    entry
                        .get("separator")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false)
                }),
                "expected at least one separator log entry"
            );
            assert!(
                logs_after.iter().any(|entry| {
                    entry
                        .get("line")
                        .and_then(|v| v.as_str())
                        .map(|line| line.contains("RFC9420 Proposal Add"))
                        .unwrap_or(false)
                }),
                "expected RFC9420 Proposal Add log line"
            );
            assert!(
                logs_after.iter().any(|entry| {
                    entry
                        .get("line")
                        .and_then(|v| v.as_str())
                        .map(|line| line.contains("RFC9420 Proposal Update"))
                        .unwrap_or(false)
                }),
                "expected RFC9420 Proposal Update log line"
            );
            assert!(
                logs_after.iter().any(|entry| {
                    entry
                        .get("line")
                        .and_then(|v| v.as_str())
                        .map(|line| line.contains("RFC9420 Proposal Remove"))
                        .unwrap_or(false)
                }),
                "expected RFC9420 Proposal Remove log line"
            );

            let demo_page = get_text_with_cookie(
                &client,
                &format!("{}/ui/admin/demos/{}", ui_base_url, demo_id),
                "ui_username=admin",
            )
            .await;
            assert!(demo_page.contains("demo-layout"));
            assert!(demo_page.contains("Actions"));
            assert!(demo_page.contains("Logs"));
            assert!(demo_page.contains("Tree Structure"));
            assert!(demo_page.contains("demo-add-adder"));
            assert!(demo_page.contains("demo-remove-remover"));
            assert!(demo_page.contains("demo-update-updater"));
            assert!(demo_page.contains("demo-log-list"));
            assert!(demo_page.contains("demo-tree-legend"));
            assert!(demo_page.contains("LeafIndex (L)"));

            ui_handle.abort();
            ds_handle.abort();
            let _ = fs::remove_dir_all(&run_dir);
        });
    }

    #[test]
    fn ui_admin_demo_legacy_state_migrates_and_persists_new_schema_after_action() {
        run_async_test_on_large_stack("ui-admin-demo-legacy-migrate", async move {
            let run_dir = test_run_dir("ui-admin-demo-legacy-migrate");
            let ds_data_dir = run_dir.join("data");
            let ds_db_path = run_dir.join("ds.sqlite");
            fs::create_dir_all(&ds_data_dir).expect("create ds data dir");

            let mut ds_state = DsApiState::default();
            ds_state.min_proposals_per_commit = 1;
            ds_state.storage = StorageConfig::new(
                ds_data_dir.to_string_lossy().as_ref(),
                ds_db_path.to_string_lossy().as_ref(),
            );
            let ds_router = ds_http::router(ds_state);
            let (ds_base_url, ds_handle) = spawn_router(ds_router).await;

            let ui_state_dir = run_dir.join("ui-state");
            fs::create_dir_all(&ui_state_dir).expect("create ui state dir");
            let ui_state = UiState {
                base_url: ds_base_url,
                state_dir: ui_state_dir.clone(),
                client: Client::new(),
            };
            let ui_router = build_ui_router(ui_state);
            let (ui_base_url, ui_handle) = spawn_router(ui_router).await;

            let client = test_client();
            let admin_login = post_json(
                &client,
                &format!("{}/ui/api/login", ui_base_url),
                json!({
                    "username": "admin",
                    "password": "admin@123"
                }),
            )
            .await;
            assert_eq!(admin_login["ok"].as_bool(), Some(true));

            let create_demo = post_json(
                &client,
                &format!("{}/ui/api/admin/demos", ui_base_url),
                json!({
                    "username": "admin",
                    "title": "Legacy Migration"
                }),
            )
            .await;
            assert_eq!(create_demo["ok"].as_bool(), Some(true));
            let demo_id = create_demo["data"]["id"]
                .as_str()
                .expect("demo id")
                .to_string();

            let legacy_state = json!({
                "epoch": 4,
                "members": [
                    {"username": "A", "leaf_index": 0, "key_generation": 2},
                    {"username": "C", "leaf_index": 2, "key_generation": 7}
                ],
                "logs": [
                    {"timestamp": 111, "line": "legacy log", "separator": false}
                ],
                "last_action": "legacy-seed"
            });
            let state_path = admin_demo_state_path(&ui_state_dir, &demo_id);
            fs::write(
                &state_path,
                serde_json::to_vec_pretty(&legacy_state).expect("serialize legacy state"),
            )
            .expect("write legacy state");

            let migrated_detail = get_json(
                &client,
                &format!(
                    "{}/ui/api/admin/demos/{}?username=admin",
                    ui_base_url, demo_id
                ),
            )
            .await;
            assert_eq!(migrated_detail["ok"].as_bool(), Some(true));
            assert_eq!(migrated_detail["data"]["epoch"].as_u64(), Some(4));
            assert_eq!(migrated_detail["data"]["leaf_count"].as_u64(), Some(3));
            assert_eq!(migrated_detail["data"]["node_count"].as_u64(), Some(5));
            let migrated_members = migrated_detail["data"]["members"]
                .as_array()
                .expect("migrated members");
            assert_eq!(migrated_members.len(), 2);
            assert!(migrated_members.iter().any(|m| {
                m.get("username").and_then(|v| v.as_str()) == Some("A")
                    && m.get("leaf_index").and_then(|v| v.as_u64()) == Some(0)
            }));
            assert!(migrated_members.iter().any(|m| {
                m.get("username").and_then(|v| v.as_str()) == Some("C")
                    && m.get("leaf_index").and_then(|v| v.as_u64()) == Some(2)
            }));

            let update_a = post_json(
                &client,
                &format!(
                    "{}/ui/api/admin/demos/{}/actions/update",
                    ui_base_url, demo_id
                ),
                json!({
                    "username": "admin",
                    "updater": "A"
                }),
            )
            .await;
            assert_eq!(update_a["ok"].as_bool(), Some(true));

            let migrated_bytes = fs::read(&state_path).expect("read migrated state");
            let new_state: AdminDemoState =
                serde_json::from_slice(&migrated_bytes).expect("parse migrated new schema");
            assert_eq!(new_state.epoch, 5);
            assert_eq!(new_state.leaf_slots.len(), 3);
            assert!(
                matches!(
                    new_state.leaf_slots[0].as_ref(),
                    Some(slot) if slot.username == "A" && slot.key_generation == 3
                ),
                "expected A migrated at leaf 0 with incremented key_generation"
            );
            assert!(
                new_state.leaf_slots[1].is_none(),
                "expected blank leaf slot 1"
            );
            assert!(
                matches!(
                    new_state.leaf_slots[2].as_ref(),
                    Some(slot) if slot.username == "C" && slot.key_generation == 7
                ),
                "expected C migrated at leaf 2"
            );

            ui_handle.abort();
            ds_handle.abort();
            let _ = fs::remove_dir_all(&run_dir);
        });
    }

    #[test]
    fn ui_admin_demo_remove_preserves_remaining_leaf_indices() {
        run_async_test_on_large_stack("ui-admin-demo-leaf-stability", async move {
            let run_dir = test_run_dir("ui-admin-demo-leaf-stability");
            let ds_data_dir = run_dir.join("data");
            let ds_db_path = run_dir.join("ds.sqlite");
            fs::create_dir_all(&ds_data_dir).expect("create ds data dir");

            let mut ds_state = DsApiState::default();
            ds_state.min_proposals_per_commit = 1;
            ds_state.storage = StorageConfig::new(
                ds_data_dir.to_string_lossy().as_ref(),
                ds_db_path.to_string_lossy().as_ref(),
            );
            let ds_router = ds_http::router(ds_state);
            let (ds_base_url, ds_handle) = spawn_router(ds_router).await;

            let ui_state_dir = run_dir.join("ui-state");
            fs::create_dir_all(&ui_state_dir).expect("create ui state dir");
            let ui_state = UiState {
                base_url: ds_base_url,
                state_dir: ui_state_dir,
                client: Client::new(),
            };
            let ui_router = build_ui_router(ui_state);
            let (ui_base_url, ui_handle) = spawn_router(ui_router).await;

            let client = test_client();
            let admin_login = post_json(
                &client,
                &format!("{}/ui/api/login", ui_base_url),
                json!({
                    "username": "admin",
                    "password": "admin@123"
                }),
            )
            .await;
            assert_eq!(admin_login["ok"].as_bool(), Some(true));

            let create_demo = post_json(
                &client,
                &format!("{}/ui/api/admin/demos", ui_base_url),
                json!({
                    "username": "admin",
                    "title": "Leaf Stability"
                }),
            )
            .await;
            assert_eq!(create_demo["ok"].as_bool(), Some(true));
            let demo_id = create_demo["data"]["id"]
                .as_str()
                .expect("demo id")
                .to_string();

            let add_b = post_json(
                &client,
                &format!("{}/ui/api/admin/demos/{}/actions/add", ui_base_url, demo_id),
                json!({
                    "username": "admin",
                    "adder": "A",
                    "added": "B"
                }),
            )
            .await;
            assert_eq!(add_b["ok"].as_bool(), Some(true));

            let add_c = post_json(
                &client,
                &format!("{}/ui/api/admin/demos/{}/actions/add", ui_base_url, demo_id),
                json!({
                    "username": "admin",
                    "adder": "A",
                    "added": "C"
                }),
            )
            .await;
            assert_eq!(add_c["ok"].as_bool(), Some(true));

            let remove_b = post_json(
                &client,
                &format!(
                    "{}/ui/api/admin/demos/{}/actions/remove",
                    ui_base_url, demo_id
                ),
                json!({
                    "username": "admin",
                    "remover": "A",
                    "removed": "B"
                }),
            )
            .await;
            assert_eq!(remove_b["ok"].as_bool(), Some(true));

            let detail = get_json(
                &client,
                &format!(
                    "{}/ui/api/admin/demos/{}?username=admin",
                    ui_base_url, demo_id
                ),
            )
            .await;
            assert_eq!(detail["ok"].as_bool(), Some(true));
            assert_eq!(detail["data"]["leaf_count"].as_u64(), Some(3));
            assert_eq!(detail["data"]["node_count"].as_u64(), Some(5));

            let members = detail["data"]["members"].as_array().expect("members");
            assert_eq!(members.len(), 2);
            assert!(members.iter().any(|m| {
                m.get("username").and_then(|v| v.as_str()) == Some("A")
                    && m.get("leaf_index").and_then(|v| v.as_u64()) == Some(0)
            }));
            assert!(members.iter().any(|m| {
                m.get("username").and_then(|v| v.as_str()) == Some("C")
                    && m.get("leaf_index").and_then(|v| v.as_u64()) == Some(2)
            }));
            let logs = detail["data"]["logs"].as_array().expect("logs");
            assert!(logs.iter().any(|entry| {
                entry
                    .get("line")
                    .and_then(|v| v.as_str())
                    .map(|line| line.contains("no trailing blank leaves to trim"))
                    .unwrap_or(false)
            }));

            ui_handle.abort();
            ds_handle.abort();
            let _ = fs::remove_dir_all(&run_dir);
        });
    }

    #[test]
    fn ui_admin_demo_add_reuses_leftmost_blank_leaf() {
        run_async_test_on_large_stack("ui-admin-demo-add-placement", async move {
            let run_dir = test_run_dir("ui-admin-demo-add-placement");
            let ds_data_dir = run_dir.join("data");
            let ds_db_path = run_dir.join("ds.sqlite");
            fs::create_dir_all(&ds_data_dir).expect("create ds data dir");

            let mut ds_state = DsApiState::default();
            ds_state.min_proposals_per_commit = 1;
            ds_state.storage = StorageConfig::new(
                ds_data_dir.to_string_lossy().as_ref(),
                ds_db_path.to_string_lossy().as_ref(),
            );
            let ds_router = ds_http::router(ds_state);
            let (ds_base_url, ds_handle) = spawn_router(ds_router).await;

            let ui_state_dir = run_dir.join("ui-state");
            fs::create_dir_all(&ui_state_dir).expect("create ui state dir");
            let ui_state = UiState {
                base_url: ds_base_url,
                state_dir: ui_state_dir,
                client: Client::new(),
            };
            let ui_router = build_ui_router(ui_state);
            let (ui_base_url, ui_handle) = spawn_router(ui_router).await;

            let client = test_client();
            let admin_login = post_json(
                &client,
                &format!("{}/ui/api/login", ui_base_url),
                json!({
                    "username": "admin",
                    "password": "admin@123"
                }),
            )
            .await;
            assert_eq!(admin_login["ok"].as_bool(), Some(true));

            let create_demo = post_json(
                &client,
                &format!("{}/ui/api/admin/demos", ui_base_url),
                json!({
                    "username": "admin",
                    "title": "Add Placement"
                }),
            )
            .await;
            assert_eq!(create_demo["ok"].as_bool(), Some(true));
            let demo_id = create_demo["data"]["id"]
                .as_str()
                .expect("demo id")
                .to_string();

            for added in ["B", "C", "D"] {
                let add = post_json(
                    &client,
                    &format!("{}/ui/api/admin/demos/{}/actions/add", ui_base_url, demo_id),
                    json!({
                        "username": "admin",
                        "adder": "A",
                        "added": added
                    }),
                )
                .await;
                assert_eq!(add["ok"].as_bool(), Some(true));
            }

            let remove_c = post_json(
                &client,
                &format!(
                    "{}/ui/api/admin/demos/{}/actions/remove",
                    ui_base_url, demo_id
                ),
                json!({
                    "username": "admin",
                    "remover": "A",
                    "removed": "C"
                }),
            )
            .await;
            assert_eq!(remove_c["ok"].as_bool(), Some(true));

            let detail_before = get_json(
                &client,
                &format!(
                    "{}/ui/api/admin/demos/{}?username=admin",
                    ui_base_url, demo_id
                ),
            )
            .await;
            assert_eq!(detail_before["ok"].as_bool(), Some(true));
            assert_eq!(detail_before["data"]["leaf_count"].as_u64(), Some(4));
            let before_members = detail_before["data"]["members"]
                .as_array()
                .expect("members");
            assert!(before_members.iter().any(|m| {
                m.get("username").and_then(|v| v.as_str()) == Some("D")
                    && m.get("leaf_index").and_then(|v| v.as_u64()) == Some(3)
            }));

            let add_e = post_json(
                &client,
                &format!("{}/ui/api/admin/demos/{}/actions/add", ui_base_url, demo_id),
                json!({
                    "username": "admin",
                    "adder": "A",
                    "added": "E"
                }),
            )
            .await;
            assert_eq!(add_e["ok"].as_bool(), Some(true));

            let detail_after = get_json(
                &client,
                &format!(
                    "{}/ui/api/admin/demos/{}?username=admin",
                    ui_base_url, demo_id
                ),
            )
            .await;
            assert_eq!(detail_after["ok"].as_bool(), Some(true));
            assert_eq!(
                detail_after["data"]["leaf_count"].as_u64(),
                Some(4),
                "blank-leaf reuse must not extend leaf count"
            );
            let after_members = detail_after["data"]["members"].as_array().expect("members");
            assert!(after_members.iter().any(|m| {
                m.get("username").and_then(|v| v.as_str()) == Some("E")
                    && m.get("leaf_index").and_then(|v| v.as_u64()) == Some(2)
            }));
            assert!(after_members.iter().any(|m| {
                m.get("username").and_then(|v| v.as_str()) == Some("D")
                    && m.get("leaf_index").and_then(|v| v.as_u64()) == Some(3)
            }));

            let logs = detail_after["data"]["logs"].as_array().expect("logs");
            assert!(logs.iter().any(|entry| {
                entry
                    .get("line")
                    .and_then(|v| v.as_str())
                    .map(|line| line.contains("filled leftmost blank LeafIndex=2"))
                    .unwrap_or(false)
            }));

            ui_handle.abort();
            ds_handle.abort();
            let _ = fs::remove_dir_all(&run_dir);
        });
    }

    #[test]
    fn ui_admin_demo_remove_truncates_when_tail_leaf_becomes_blank() {
        run_async_test_on_large_stack("ui-admin-demo-remove-trim", async move {
            let run_dir = test_run_dir("ui-admin-demo-remove-trim");
            let ds_data_dir = run_dir.join("data");
            let ds_db_path = run_dir.join("ds.sqlite");
            fs::create_dir_all(&ds_data_dir).expect("create ds data dir");

            let mut ds_state = DsApiState::default();
            ds_state.min_proposals_per_commit = 1;
            ds_state.storage = StorageConfig::new(
                ds_data_dir.to_string_lossy().as_ref(),
                ds_db_path.to_string_lossy().as_ref(),
            );
            let ds_router = ds_http::router(ds_state);
            let (ds_base_url, ds_handle) = spawn_router(ds_router).await;

            let ui_state_dir = run_dir.join("ui-state");
            fs::create_dir_all(&ui_state_dir).expect("create ui state dir");
            let ui_state = UiState {
                base_url: ds_base_url,
                state_dir: ui_state_dir,
                client: Client::new(),
            };
            let ui_router = build_ui_router(ui_state);
            let (ui_base_url, ui_handle) = spawn_router(ui_router).await;

            let client = test_client();
            let admin_login = post_json(
                &client,
                &format!("{}/ui/api/login", ui_base_url),
                json!({
                    "username": "admin",
                    "password": "admin@123"
                }),
            )
            .await;
            assert_eq!(admin_login["ok"].as_bool(), Some(true));

            let create_demo = post_json(
                &client,
                &format!("{}/ui/api/admin/demos", ui_base_url),
                json!({
                    "username": "admin",
                    "title": "Remove Trim"
                }),
            )
            .await;
            assert_eq!(create_demo["ok"].as_bool(), Some(true));
            let demo_id = create_demo["data"]["id"]
                .as_str()
                .expect("demo id")
                .to_string();

            for added in ["B", "C", "D"] {
                let add = post_json(
                    &client,
                    &format!("{}/ui/api/admin/demos/{}/actions/add", ui_base_url, demo_id),
                    json!({
                        "username": "admin",
                        "adder": "A",
                        "added": added
                    }),
                )
                .await;
                assert_eq!(add["ok"].as_bool(), Some(true));
            }

            let detail_before_remove = get_json(
                &client,
                &format!(
                    "{}/ui/api/admin/demos/{}?username=admin",
                    ui_base_url, demo_id
                ),
            )
            .await;
            assert_eq!(detail_before_remove["ok"].as_bool(), Some(true));
            assert_eq!(detail_before_remove["data"]["leaf_count"].as_u64(), Some(4));
            assert_eq!(detail_before_remove["data"]["node_count"].as_u64(), Some(7));

            let remove_d = post_json(
                &client,
                &format!(
                    "{}/ui/api/admin/demos/{}/actions/remove",
                    ui_base_url, demo_id
                ),
                json!({
                    "username": "admin",
                    "remover": "A",
                    "removed": "D"
                }),
            )
            .await;
            assert_eq!(remove_d["ok"].as_bool(), Some(true));

            let detail_after_remove = get_json(
                &client,
                &format!(
                    "{}/ui/api/admin/demos/{}?username=admin",
                    ui_base_url, demo_id
                ),
            )
            .await;
            assert_eq!(detail_after_remove["ok"].as_bool(), Some(true));
            assert_eq!(
                detail_after_remove["data"]["leaf_count"].as_u64(),
                Some(3),
                "tail blank leaf should be trimmed"
            );
            assert_eq!(detail_after_remove["data"]["node_count"].as_u64(), Some(5));

            let members = detail_after_remove["data"]["members"]
                .as_array()
                .expect("members after remove");
            assert_eq!(members.len(), 3);
            assert!(members.iter().any(|m| {
                m.get("username").and_then(|v| v.as_str()) == Some("A")
                    && m.get("leaf_index").and_then(|v| v.as_u64()) == Some(0)
            }));
            assert!(members.iter().any(|m| {
                m.get("username").and_then(|v| v.as_str()) == Some("B")
                    && m.get("leaf_index").and_then(|v| v.as_u64()) == Some(1)
            }));
            assert!(members.iter().any(|m| {
                m.get("username").and_then(|v| v.as_str()) == Some("C")
                    && m.get("leaf_index").and_then(|v| v.as_u64()) == Some(2)
            }));

            let logs = detail_after_remove["data"]["logs"]
                .as_array()
                .expect("logs after remove");
            assert!(logs.iter().any(|entry| {
                entry
                    .get("line")
                    .and_then(|v| v.as_str())
                    .map(|line| line.contains("trimmed trailing blank leaves (leaf_count 4 -> 3)"))
                    .unwrap_or(false)
            }));

            ui_handle.abort();
            ds_handle.abort();
            let _ = fs::remove_dir_all(&run_dir);
        });
    }

    #[test]
    fn ui_admin_demo_indices_stable_across_epoch_chain_and_layout_invariants_hold() {
        run_async_test_on_large_stack("ui-admin-demo-index-invariants", async move {
            let run_dir = test_run_dir("ui-admin-demo-index-invariants");
            let ds_data_dir = run_dir.join("data");
            let ds_db_path = run_dir.join("ds.sqlite");
            fs::create_dir_all(&ds_data_dir).expect("create ds data dir");

            let mut ds_state = DsApiState::default();
            ds_state.min_proposals_per_commit = 1;
            ds_state.storage = StorageConfig::new(
                ds_data_dir.to_string_lossy().as_ref(),
                ds_db_path.to_string_lossy().as_ref(),
            );
            let ds_router = ds_http::router(ds_state);
            let (ds_base_url, ds_handle) = spawn_router(ds_router).await;

            let ui_state_dir = run_dir.join("ui-state");
            fs::create_dir_all(&ui_state_dir).expect("create ui state dir");
            let ui_state = UiState {
                base_url: ds_base_url,
                state_dir: ui_state_dir,
                client: Client::new(),
            };
            let ui_router = build_ui_router(ui_state);
            let (ui_base_url, ui_handle) = spawn_router(ui_router).await;

            let client = test_client();
            let admin_login = post_json(
                &client,
                &format!("{}/ui/api/login", ui_base_url),
                json!({
                    "username": "admin",
                    "password": "admin@123"
                }),
            )
            .await;
            assert_eq!(admin_login["ok"].as_bool(), Some(true));

            let create_demo = post_json(
                &client,
                &format!("{}/ui/api/admin/demos", ui_base_url),
                json!({
                    "username": "admin",
                    "title": "Index Stability"
                }),
            )
            .await;
            assert_eq!(create_demo["ok"].as_bool(), Some(true));
            let demo_id = create_demo["data"]["id"]
                .as_str()
                .expect("demo id")
                .to_string();

            for added in ["B", "C", "D"] {
                let add = post_json(
                    &client,
                    &format!("{}/ui/api/admin/demos/{}/actions/add", ui_base_url, demo_id),
                    json!({
                        "username": "admin",
                        "adder": "A",
                        "added": added
                    }),
                )
                .await;
                assert_eq!(add["ok"].as_bool(), Some(true));
            }

            let after_initial_adds = get_json(
                &client,
                &format!(
                    "{}/ui/api/admin/demos/{}?username=admin",
                    ui_base_url, demo_id
                ),
            )
            .await;
            assert_eq!(after_initial_adds["ok"].as_bool(), Some(true));
            assert_eq!(after_initial_adds["data"]["epoch"].as_u64(), Some(3));
            assert_admin_demo_detail_layout_invariants(&after_initial_adds);
            assert_eq!(
                admin_demo_member_leaf_map(&after_initial_adds),
                BTreeMap::from([
                    ("A".to_string(), 0),
                    ("B".to_string(), 1),
                    ("C".to_string(), 2),
                    ("D".to_string(), 3),
                ])
            );

            let update_b = post_json(
                &client,
                &format!(
                    "{}/ui/api/admin/demos/{}/actions/update",
                    ui_base_url, demo_id
                ),
                json!({
                    "username": "admin",
                    "updater": "B"
                }),
            )
            .await;
            assert_eq!(update_b["ok"].as_bool(), Some(true));

            let after_update_b = get_json(
                &client,
                &format!(
                    "{}/ui/api/admin/demos/{}?username=admin",
                    ui_base_url, demo_id
                ),
            )
            .await;
            assert_eq!(after_update_b["ok"].as_bool(), Some(true));
            assert_eq!(after_update_b["data"]["epoch"].as_u64(), Some(4));
            assert_admin_demo_detail_layout_invariants(&after_update_b);
            assert_eq!(
                admin_demo_member_leaf_map(&after_update_b),
                BTreeMap::from([
                    ("A".to_string(), 0),
                    ("B".to_string(), 1),
                    ("C".to_string(), 2),
                    ("D".to_string(), 3),
                ]),
                "update must not change member leaf indices"
            );

            let remove_c = post_json(
                &client,
                &format!(
                    "{}/ui/api/admin/demos/{}/actions/remove",
                    ui_base_url, demo_id
                ),
                json!({
                    "username": "admin",
                    "remover": "A",
                    "removed": "C"
                }),
            )
            .await;
            assert_eq!(remove_c["ok"].as_bool(), Some(true));

            let after_remove_c = get_json(
                &client,
                &format!(
                    "{}/ui/api/admin/demos/{}?username=admin",
                    ui_base_url, demo_id
                ),
            )
            .await;
            assert_eq!(after_remove_c["ok"].as_bool(), Some(true));
            assert_eq!(after_remove_c["data"]["epoch"].as_u64(), Some(5));
            assert_eq!(after_remove_c["data"]["leaf_count"].as_u64(), Some(4));
            assert_admin_demo_detail_layout_invariants(&after_remove_c);
            assert_eq!(
                admin_demo_member_leaf_map(&after_remove_c),
                BTreeMap::from([
                    ("A".to_string(), 0),
                    ("B".to_string(), 1),
                    ("D".to_string(), 3),
                ]),
                "non-tail remove must keep unaffected leaf indices stable"
            );

            let update_d = post_json(
                &client,
                &format!(
                    "{}/ui/api/admin/demos/{}/actions/update",
                    ui_base_url, demo_id
                ),
                json!({
                    "username": "admin",
                    "updater": "D"
                }),
            )
            .await;
            assert_eq!(update_d["ok"].as_bool(), Some(true));

            let after_update_d = get_json(
                &client,
                &format!(
                    "{}/ui/api/admin/demos/{}?username=admin",
                    ui_base_url, demo_id
                ),
            )
            .await;
            assert_eq!(after_update_d["ok"].as_bool(), Some(true));
            assert_eq!(after_update_d["data"]["epoch"].as_u64(), Some(6));
            assert_admin_demo_detail_layout_invariants(&after_update_d);
            assert_eq!(
                admin_demo_member_leaf_map(&after_update_d),
                BTreeMap::from([
                    ("A".to_string(), 0),
                    ("B".to_string(), 1),
                    ("D".to_string(), 3),
                ]),
                "update after remove must not alter leaf placement"
            );

            let add_e = post_json(
                &client,
                &format!("{}/ui/api/admin/demos/{}/actions/add", ui_base_url, demo_id),
                json!({
                    "username": "admin",
                    "adder": "A",
                    "added": "E"
                }),
            )
            .await;
            assert_eq!(add_e["ok"].as_bool(), Some(true));

            let after_add_e = get_json(
                &client,
                &format!(
                    "{}/ui/api/admin/demos/{}?username=admin",
                    ui_base_url, demo_id
                ),
            )
            .await;
            assert_eq!(after_add_e["ok"].as_bool(), Some(true));
            assert_eq!(after_add_e["data"]["epoch"].as_u64(), Some(7));
            assert_eq!(after_add_e["data"]["leaf_count"].as_u64(), Some(4));
            assert_admin_demo_detail_layout_invariants(&after_add_e);
            assert_eq!(
                admin_demo_member_leaf_map(&after_add_e),
                BTreeMap::from([
                    ("A".to_string(), 0),
                    ("B".to_string(), 1),
                    ("D".to_string(), 3),
                    ("E".to_string(), 2),
                ]),
                "Add must reuse the first blank leaf to preserve topology width"
            );

            let logs = after_add_e["data"]["logs"]
                .as_array()
                .expect("logs after add E");
            assert!(logs.iter().any(|entry| {
                entry
                    .get("line")
                    .and_then(|v| v.as_str())
                    .map(|line| {
                        line.contains("RFC9420 Path Update: D at LeafIndex=3 (NodeIndex=6)")
                    })
                    .unwrap_or(false)
            }));
            assert!(logs.iter().any(|entry| {
                entry
                    .get("line")
                    .and_then(|v| v.as_str())
                    .map(|line| line.contains("RFC9420 RatchetTree Add: filled leftmost blank LeafIndex=2 (NodeIndex=4) with E"))
                    .unwrap_or(false)
            }));

            ui_handle.abort();
            ds_handle.abort();
            let _ = fs::remove_dir_all(&run_dir);
        });
    }

    #[test]
    fn ui_admin_demo_tree_renderer_root_and_blank_labels_after_add_remove_chain() {
        run_async_test_on_large_stack("ui-admin-demo-tree-labels", async move {
            let run_dir = test_run_dir("ui-admin-demo-tree-labels");
            let ds_data_dir = run_dir.join("data");
            let ds_db_path = run_dir.join("ds.sqlite");
            fs::create_dir_all(&ds_data_dir).expect("create ds data dir");

            let mut ds_state = DsApiState::default();
            ds_state.min_proposals_per_commit = 1;
            ds_state.storage = StorageConfig::new(
                ds_data_dir.to_string_lossy().as_ref(),
                ds_db_path.to_string_lossy().as_ref(),
            );
            let ds_router = ds_http::router(ds_state);
            let (ds_base_url, ds_handle) = spawn_router(ds_router).await;

            let ui_state_dir = run_dir.join("ui-state");
            fs::create_dir_all(&ui_state_dir).expect("create ui state dir");
            let ui_state = UiState {
                base_url: ds_base_url,
                state_dir: ui_state_dir,
                client: Client::new(),
            };
            let ui_router = build_ui_router(ui_state);
            let (ui_base_url, ui_handle) = spawn_router(ui_router).await;

            let client = test_client();
            let admin_login = post_json(
                &client,
                &format!("{}/ui/api/login", ui_base_url),
                json!({
                    "username": "admin",
                    "password": "admin@123"
                }),
            )
            .await;
            assert_eq!(admin_login["ok"].as_bool(), Some(true));

            let create_demo = post_json(
                &client,
                &format!("{}/ui/api/admin/demos", ui_base_url),
                json!({
                    "username": "admin",
                    "title": "Tree Label Regression"
                }),
            )
            .await;
            assert_eq!(create_demo["ok"].as_bool(), Some(true));
            let demo_id = create_demo["data"]["id"]
                .as_str()
                .expect("demo id")
                .to_string();

            for added in ["B", "C", "D"] {
                let add = post_json(
                    &client,
                    &format!("{}/ui/api/admin/demos/{}/actions/add", ui_base_url, demo_id),
                    json!({
                        "username": "admin",
                        "adder": "A",
                        "added": added
                    }),
                )
                .await;
                assert_eq!(add["ok"].as_bool(), Some(true));
            }

            let remove_c = post_json(
                &client,
                &format!(
                    "{}/ui/api/admin/demos/{}/actions/remove",
                    ui_base_url, demo_id
                ),
                json!({
                    "username": "admin",
                    "remover": "A",
                    "removed": "C"
                }),
            )
            .await;
            assert_eq!(remove_c["ok"].as_bool(), Some(true));

            let detail = get_json(
                &client,
                &format!(
                    "{}/ui/api/admin/demos/{}?username=admin",
                    ui_base_url, demo_id
                ),
            )
            .await;
            assert_eq!(detail["ok"].as_bool(), Some(true));
            assert_eq!(
                detail["data"]["leaf_count"].as_u64(),
                Some(4),
                "after removing non-tail member C, blank leaf should persist"
            );
            assert_eq!(detail["data"]["node_count"].as_u64(), Some(7));
            let members = detail["data"]["members"].as_array().expect("members");
            assert_eq!(members.len(), 3);
            assert!(members.iter().any(|m| {
                m.get("username").and_then(|v| v.as_str()) == Some("A")
                    && m.get("leaf_index").and_then(|v| v.as_u64()) == Some(0)
            }));
            assert!(members.iter().any(|m| {
                m.get("username").and_then(|v| v.as_str()) == Some("B")
                    && m.get("leaf_index").and_then(|v| v.as_u64()) == Some(1)
            }));
            assert!(members.iter().any(|m| {
                m.get("username").and_then(|v| v.as_str()) == Some("D")
                    && m.get("leaf_index").and_then(|v| v.as_u64()) == Some(3)
            }));

            let demo_page = get_text_with_cookie(
                &client,
                &format!("{}/ui/admin/demos/{}", ui_base_url, demo_id),
                "ui_username=admin",
            )
            .await;
            assert!(demo_page.contains("demo-tree-legend"));
            assert!(demo_page.contains("blank leaves are labeled `blank`"));
            assert!(demo_page
                .contains("const isRoot = Number(node.node_index) === Number(rootNodeIndex);"));
            assert!(demo_page.contains("const userLabel = isBlank ? 'blank'"));
            assert!(demo_page.contains("root N${rootNodeIndex}"));

            ui_handle.abort();
            ds_handle.abort();
            let _ = fs::remove_dir_all(&run_dir);
        });
    }

    #[test]
    fn ui_admin_demo_persistence_reload_and_new_demo_clean_state() {
        run_async_test_on_large_stack("ui-admin-demo-persistence", async move {
            let run_dir = test_run_dir("ui-admin-demo-persist");
            let ds_data_dir = run_dir.join("data");
            let ds_db_path = run_dir.join("ds.sqlite");
            fs::create_dir_all(&ds_data_dir).expect("create ds data dir");

            let mut ds_state = DsApiState::default();
            ds_state.min_proposals_per_commit = 1;
            ds_state.storage = StorageConfig::new(
                ds_data_dir.to_string_lossy().as_ref(),
                ds_db_path.to_string_lossy().as_ref(),
            );
            let ds_router = ds_http::router(ds_state);
            let (ds_base_url, ds_handle) = spawn_router(ds_router).await;

            let ui_state_dir = run_dir.join("ui-state");
            fs::create_dir_all(&ui_state_dir).expect("create ui state dir");
            let ui_state = UiState {
                base_url: ds_base_url.clone(),
                state_dir: ui_state_dir.clone(),
                client: Client::new(),
            };
            let ui_router = build_ui_router(ui_state.clone());
            let (ui_base_url, ui_handle_1) = spawn_router(ui_router).await;

            let client = test_client();
            let admin_login = post_json(
                &client,
                &format!("{}/ui/api/login", ui_base_url),
                json!({
                    "username": "admin",
                    "password": "admin@123"
                }),
            )
            .await;
            assert_eq!(admin_login["ok"].as_bool(), Some(true));

            let create_demo_1 = post_json(
                &client,
                &format!("{}/ui/api/admin/demos", ui_base_url),
                json!({
                    "username": "admin",
                    "title": "Demo One"
                }),
            )
            .await;
            assert_eq!(create_demo_1["ok"].as_bool(), Some(true));
            let demo_1_id = create_demo_1["data"]["id"]
                .as_str()
                .expect("demo 1 id")
                .to_string();

            let demo_1_state_path = ui_state_dir
                .join("demo")
                .join(sanitize(&demo_1_id))
                .join("state.json");
            assert!(
                demo_1_state_path.exists(),
                "expected demo state file at {}",
                demo_1_state_path.display()
            );

            let add_action_demo_1 = post_json(
                &client,
                &format!(
                    "{}/ui/api/admin/demos/{}/actions/add",
                    ui_base_url, demo_1_id
                ),
                json!({
                    "username": "admin",
                    "adder": "A",
                    "added": "B"
                }),
            )
            .await;
            assert_eq!(add_action_demo_1["ok"].as_bool(), Some(true));
            assert_eq!(add_action_demo_1["data"]["epoch"].as_u64(), Some(1));

            let detail_demo_1_before_reload = get_json(
                &client,
                &format!(
                    "{}/ui/api/admin/demos/{}?username=admin",
                    ui_base_url, demo_1_id
                ),
            )
            .await;
            assert_eq!(detail_demo_1_before_reload["ok"].as_bool(), Some(true));
            assert_eq!(
                detail_demo_1_before_reload["data"]["epoch"].as_u64(),
                Some(1)
            );
            assert_eq!(
                detail_demo_1_before_reload["data"]["members"]
                    .as_array()
                    .expect("demo1 members before reload")
                    .len(),
                2
            );

            ui_handle_1.abort();

            let ui_router_reloaded = build_ui_router(UiState {
                base_url: ds_base_url.clone(),
                state_dir: ui_state_dir.clone(),
                client: Client::new(),
            });
            let (ui_base_url_reloaded, ui_handle_2) = spawn_router(ui_router_reloaded).await;

            let admin_login_reloaded = post_json(
                &client,
                &format!("{}/ui/api/login", ui_base_url_reloaded),
                json!({
                    "username": "admin",
                    "password": "admin@123"
                }),
            )
            .await;
            assert_eq!(admin_login_reloaded["ok"].as_bool(), Some(true));

            let list_after_reload = get_json(
                &client,
                &format!("{}/ui/api/admin/demos?username=admin", ui_base_url_reloaded),
            )
            .await;
            assert_eq!(list_after_reload["ok"].as_bool(), Some(true));
            assert!(
                list_after_reload["data"]["items"]
                    .as_array()
                    .expect("demo list after reload")
                    .iter()
                    .any(|item| item.get("id").and_then(|v| v.as_str()) == Some(demo_1_id.as_str())),
                "expected first demo in demo index after reload"
            );

            let detail_demo_1_after_reload = get_json(
                &client,
                &format!(
                    "{}/ui/api/admin/demos/{}?username=admin",
                    ui_base_url_reloaded, demo_1_id
                ),
            )
            .await;
            assert_eq!(detail_demo_1_after_reload["ok"].as_bool(), Some(true));
            assert_eq!(
                detail_demo_1_after_reload["data"]["epoch"].as_u64(),
                Some(1)
            );
            let demo_1_members_after = detail_demo_1_after_reload["data"]["members"]
                .as_array()
                .expect("demo1 members after reload");
            assert_eq!(demo_1_members_after.len(), 2);
            assert!(
                detail_demo_1_after_reload["data"]["logs"]
                    .as_array()
                    .expect("demo1 logs after reload")
                    .iter()
                    .any(|entry| {
                        entry
                            .get("line")
                            .and_then(|v| v.as_str())
                            .map(|line| line.contains("RFC9420 Proposal Add"))
                            .unwrap_or(false)
                    }),
                "expected persisted RFC9420 Proposal Add log line after reload"
            );

            let create_demo_2 = post_json(
                &client,
                &format!("{}/ui/api/admin/demos", ui_base_url_reloaded),
                json!({
                    "username": "admin",
                    "title": "Demo Two"
                }),
            )
            .await;
            assert_eq!(create_demo_2["ok"].as_bool(), Some(true));
            let demo_2_id = create_demo_2["data"]["id"]
                .as_str()
                .expect("demo 2 id")
                .to_string();
            assert_ne!(demo_1_id, demo_2_id);

            let detail_demo_2 = get_json(
                &client,
                &format!(
                    "{}/ui/api/admin/demos/{}?username=admin",
                    ui_base_url_reloaded, demo_2_id
                ),
            )
            .await;
            assert_eq!(detail_demo_2["ok"].as_bool(), Some(true));
            assert_eq!(detail_demo_2["data"]["epoch"].as_u64(), Some(0));
            let demo_2_members = detail_demo_2["data"]["members"]
                .as_array()
                .expect("demo2 members");
            assert_eq!(demo_2_members.len(), 1);
            assert_eq!(demo_2_members[0]["username"].as_str(), Some("A"));
            let demo_2_logs = detail_demo_2["data"]["logs"]
                .as_array()
                .expect("demo2 logs");
            assert!(demo_2_logs.len() >= 2, "expected initial logs for new demo");
            assert!(
                demo_2_logs.iter().all(|entry| {
                    entry
                        .get("line")
                        .and_then(|v| v.as_str())
                        .map(|line| !line.contains("Proposal("))
                        .unwrap_or(true)
                }),
                "new demo should not inherit proposal logs from previous demos"
            );

            let detail_demo_1_final = get_json(
                &client,
                &format!(
                    "{}/ui/api/admin/demos/{}?username=admin",
                    ui_base_url_reloaded, demo_1_id
                ),
            )
            .await;
            assert_eq!(detail_demo_1_final["ok"].as_bool(), Some(true));
            assert_eq!(detail_demo_1_final["data"]["epoch"].as_u64(), Some(1));
            assert_eq!(
                detail_demo_1_final["data"]["members"]
                    .as_array()
                    .expect("demo1 members final")
                    .len(),
                2
            );

            let missing_demo_id = "missing-demo-for-action";
            let missing_action = post_json(
                &client,
                &format!(
                    "{}/ui/api/admin/demos/{}/actions/add",
                    ui_base_url_reloaded, missing_demo_id
                ),
                json!({
                    "username": "admin",
                    "adder": "A",
                    "added": "B"
                }),
            )
            .await;
            assert_eq!(missing_action["ok"].as_bool(), Some(false));
            let error_text = missing_action["error"].as_str().unwrap_or("");
            assert!(
                error_text.contains("demo state missing"),
                "expected strict missing-state error, got {}",
                error_text
            );
            let missing_demo_state_path = ui_state_dir
                .join("demo")
                .join(sanitize(missing_demo_id))
                .join("state.json");
            assert!(
                !missing_demo_state_path.exists(),
                "missing demo action should not create state file at {}",
                missing_demo_state_path.display()
            );

            ui_handle_2.abort();
            ds_handle.abort();
            let _ = fs::remove_dir_all(&run_dir);
        });
    }
}
