use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    extract::{Path as AxumPath, Query, State},
    response::{Html, IntoResponse, Redirect},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{SecretKey as EdSecretKey, SigningKey as EdSigningKey, VerifyingKey as EdPublic};
use ml_dsa::{EncodedSigningKey, EncodedVerifyingKey, KeyGen, MlDsa65};
use ml_kem::Seed;
use rand::rngs::OsRng;
use rand::RngCore;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use x25519_dalek::{PublicKey as X25519Pub, StaticSecret as X25519Priv};

use hybrid_mls::client_state::ClientGroupState;
use hybrid_mls::crypto::{HybridPublicKey, HybridSignPrivKey, HybridSignPubKey, KyberPriv};
use hybrid_mls::envelope::ProposalEnvelope;
use hybrid_mls::tree::{KeyPackage, LeafNode, Proposal, RatchetTree};

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
    summary: String,
}

#[derive(Debug, Serialize)]
struct TreeView {
    group_id: String,
    epoch: u64,
    leaf_count: usize,
    root_index: Option<usize>,
    nodes: Vec<TreeNodeView>,
}

#[derive(Debug, Serialize)]
struct ActionProposalResponse {
    proposal_b64: String,
    submitted: bool,
    pending_proposals: usize,
    state_path: String,
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

    let app = Router::new()
        .route("/", get(ui_index))
        .route("/ui", get(ui_index))
        .route("/ui/login", get(ui_login))
        .route("/ui/groups", get(ui_groups))
        .route("/ui/groups/:group_id", get(ui_group_detail))
        .route("/ui/api/register", post(api_register))
        .route("/ui/api/login", post(api_login))
        .route("/ui/api/logout", post(api_logout))
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
        .route("/ui/api/groups/:group_id/proposals", post(api_submit_proposal))
        .route("/ui/api/groups/:group_id/commits", post(api_submit_commit))
        .route("/ui/api/groups/:group_id/actions/add", post(api_action_add))
        .route(
            "/ui/api/groups/:group_id/actions/remove",
            post(api_action_remove),
        )
        .route(
            "/ui/api/groups/:group_id/actions/update",
            post(api_action_update),
        )
        .route("/ui/api/keypackages/generate", post(api_generate_keypackage))
        .route(
            "/ui/api/keypackages",
            get(api_list_keypackages).post(api_publish_keypackage),
        )
        .route("/ui/api/keypackages/:target", get(api_fetch_keypackage))
        .with_state(ui_state);

    let addr: SocketAddr = bind.parse()?;
    println!("UI gateway listening on http://{addr}");
    axum::serve(tokio::net::TcpListener::bind(addr).await?, app).await?;
    Ok(())
}

async fn ui_index() -> impl IntoResponse {
    Redirect::to("/ui/login")
}

async fn ui_login() -> impl IntoResponse {
    ui_shell(
        "DS Login",
        r#"
        <div class="top-left">
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
            window.location.href = '/ui/groups';
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
            window.location.href = '/ui/groups';
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
        function uiContinue() {
          const username = localStorage.getItem('ui_username');
          if (username) {
            window.location.href = '/ui/groups';
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
        async function loadGroups() {
          const username = localStorage.getItem('ui_username');
          const list = document.getElementById('group-list');
          if (!username) {
            window.location.href = '/ui/login';
            return;
          }
          document.getElementById('user-badge').textContent = `Logged in as ${username} (local session cached)`;
          const resp = await fetch(`/ui/api/groups?username=${encodeURIComponent(username)}`);
          const data = await resp.json();
          if (!data.ok) {
            list.innerHTML = `<div class="note">${data.error}</div>`;
            return;
          }
          _groups = data.data.groups || [];
          renderGroups();
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

async fn ui_group_detail(AxumPath(group_id): AxumPath<String>) -> impl IntoResponse {
    let body_template = r#"
        <div class="top-left">
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
                    <div id="tree-list" class="list"></div>
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
          const keypackage_b64 = document.getElementById('add-keypackage').value.trim();
          const sender = document.getElementById('add-sender').value.trim();
          if (!user || !keypackage_b64) return;
          status.textContent = 'Submitting Add proposal...';
          const resp = await fetch(`/ui/api/groups/${groupId}/actions/add`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
              username: user,
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
            return;
          }
          list.innerHTML = `
            <div class="note">${header}</div>
            ${tree.nodes.map(node => `
              <div class="list-item">
                <div>
                  <div class="title">#${node.node_index} ${node.node_type}</div>
                  <div class="muted">${node.summary}</div>
                </div>
              </div>
            `).join('')}
          `;
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
            if (list) {
              list.innerHTML = `<div class="note">${data.error}</div>`;
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
        </script>
        "#;
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
    }}
    .grid {{
      display: grid;
      gap: var(--space-md);
      grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
      align-items: stretch;
      min-width: 0;
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

async fn api_login(
    State(state): State<UiState>,
    Json(payload): Json<AuthPayload>,
) -> impl IntoResponse {
    match login_user(&state, &payload.username, &payload.password).await {
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

async fn api_logout(
    State(state): State<UiState>,
    Json(payload): Json<LogoutPayload>,
) -> impl IntoResponse {
    match logout_user(&state, &payload.username).await {
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
    match bootstrap_group_state(&state, &payload.username, &group_id) {
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
            let view = build_tree_view(&group_state);
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

fn group_state_path(state_dir: &Path, username: &str, group_id: &str) -> PathBuf {
    state_dir.join(format!(
        "user-{}-group-{}.bin",
        sanitize(username),
        sanitize(group_id)
    ))
}

fn sanitize(value: &str) -> String {
    value
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect()
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
    ClientGroupState::load_from_file(&path)
        .map_err(|err| format!("read group state {}: {err}", path.to_string_lossy()))
}

fn save_group_state(
    state: &UiState,
    username: &str,
    group_id: &str,
    group_state: &ClientGroupState,
) -> Result<(), String> {
    let path = group_state_path(&state.state_dir, username, group_id);
    group_state
        .save_to_file(&path)
        .map_err(|err| format!("write group state {}: {err}", path.to_string_lossy()))
}

fn bootstrap_group_state(
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
    let (key_package, _) = generate_keypackage_for_user(&client_state)?;
    let leaf = LeafNode {
        public_key: key_package.init_key,
        credential: key_package.identity,
    };
    let tree = RatchetTree::from_leaves(vec![leaf]);
    let group_state = ClientGroupState::new(group_id.to_string(), tree, 0);
    save_group_state(state, username, group_id, &group_state)?;
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

fn build_tree_view(state: &ClientGroupState) -> TreeView {
    let mut nodes = Vec::with_capacity(state.ratchet_tree.nodes.len());
    for (idx, node) in state.ratchet_tree.nodes.iter().enumerate() {
        match node {
            hybrid_mls::tree::Node::Leaf(leaf) => {
                let leaf_index = idx / 2;
                let cred_id = short_id(&leaf.credential.to_bytes());
                let pub_id = short_id(&leaf.public_key.to_bytes());
                nodes.push(TreeNodeView {
                    node_index: idx,
                    node_type: "leaf".to_string(),
                    leaf_index: Some(leaf_index),
                    summary: format!("leaf {leaf_index} cred {cred_id} pub {pub_id}"),
                });
            }
            hybrid_mls::tree::Node::Parent(parent) => {
                let hash_id = if parent.parent_hash.is_empty() {
                    "none".to_string()
                } else {
                    short_hex(&parent.parent_hash, 6)
                };
                let pub_id = short_id(&parent.public_key.to_bytes());
                nodes.push(TreeNodeView {
                    node_index: idx,
                    node_type: "parent".to_string(),
                    leaf_index: None,
                    summary: format!("parent hash {hash_id} pub {pub_id}"),
                });
            }
            hybrid_mls::tree::Node::Blank => {
                nodes.push(TreeNodeView {
                    node_index: idx,
                    node_type: "blank".to_string(),
                    leaf_index: None,
                    summary: "blank".to_string(),
                });
            }
        }
    }

    TreeView {
        group_id: state.group_id.clone(),
        epoch: state.epoch,
        leaf_count: state.ratchet_tree.leaf_count(),
        root_index: state.ratchet_tree.root_index(),
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
    state_dir.join(format!(
        "user-{}-receiver-{}.json",
        sanitize(username),
        ts
    ))
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn sign_message_b64(priv_key: &HybridSignPrivKey, message: &[u8]) -> Result<String, String> {
    let signer = priv_key.clone();
    let payload = message.to_vec();
    run_with_large_stack("ui-hybrid-sign", move || {
        let sig = signer.sign(&payload);
        Ok(STANDARD.encode(sig.to_bytes()))
    })
}

fn signing_key_from_state(state: &ClientState) -> Result<HybridSignPrivKey, String> {
    let classic_bytes = STANDARD
        .decode(&state.classic_sk_b64)
        .map_err(|_| "invalid classic signing key".to_string())?;
    if classic_bytes.len() != 32 {
        return Err("classic signing key must be 32 bytes".to_string());
    }
    let mut secret: EdSecretKey = [0u8; 32];
    secret.copy_from_slice(&classic_bytes);
    let classic_sk = EdSigningKey::from_bytes(&secret);

    let pq_bytes = STANDARD
        .decode(&state.pq_sk_b64)
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
    let classic_pub = EdPublic::from_bytes(&classic_arr)
        .map_err(|_| "invalid classic public key".to_string())?;

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

fn proposal_signing_input(username: &str, group_id: &str, proposal: &[u8]) -> Vec<u8> {
    let hash = hash_payload(proposal);
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
) -> Vec<u8> {
    let commit_hash = hash_payload(commit);
    let mut out = Vec::new();
    out.extend_from_slice(b"commit|");
    out.extend_from_slice(username.as_bytes());
    out.extend_from_slice(b"|");
    out.extend_from_slice(group_id.as_bytes());
    out.extend_from_slice(b"|");
    out.extend_from_slice(&commit_hash);
    out.extend_from_slice(b"|");
    if let Some(path) = path_update {
        let path_hash = hash_payload(path);
        out.extend_from_slice(&path_hash);
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

fn hash_payload(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"DS-PAYLOAD");
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

const UI_WORKER_STACK_BYTES: usize = 32 * 1024 * 1024;

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
    let mut client_state = load_state(state, username)?;
    let signing_key = signing_key_from_state(&client_state)?;
    let sign_input = login_signing_input(username, password);
    let signature = sign_message_b64(&signing_key, &sign_input)?;

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
    let json: serde_json::Value = serde_json::from_str(&body_text)
        .map_err(|err| format!("parse login response: {err}"))?;
    let token = json
        .get("session_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "login response missing session_id".to_string())?;
    client_state.session_id = Some(token.to_string());
    save_state(state, &client_state)?;
    Ok(json)
}

async fn logout_user(state: &UiState, username: &str) -> Result<serde_json::Value, String> {
    let mut client_state = load_state(state, username)?;
    let session_id = client_state
        .session_id
        .clone()
        .ok_or_else(|| "missing session_id; login first".to_string())?;
    let signing_key = signing_key_from_state(&client_state)?;
    let sign_input = logout_signing_input(username, &session_id);
    let signature = sign_message_b64(&signing_key, &sign_input)?;

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
    Ok(serde_json::from_str(&body_text).unwrap_or_else(|_| serde_json::json!({"logged_out": true})))
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
    let signature = sign_message_b64(&signing_key, &sign_input)?;

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
    let signature = sign_message_b64(&signing_key, &sign_input)?;

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
    if !key_package.verify() {
        return Err("generated keypackage failed self-verification".to_string());
    }

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
    let signature = sign_message_b64(&signing_key, &sign_input)?;

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
    let signature = sign_message_b64(&signing_key, &sign_input)?;

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
    serde_json::from_str(&body_text).map_err(|err| err.to_string())
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
    let payload = message.as_bytes();
    let sign_input = app_publish_signing_input(username, group_id, payload);
    let signature = sign_message_b64(&signing_key, &sign_input)?;

    let body = serde_json::json!({
        "username": username,
        "session_id": session_id,
        "message_bytes": STANDARD.encode(payload),
        "signature": signature,
    });
    let resp = state
        .client
        .post(format!("{}/v1/groups/{}/app-messages", state.base_url, group_id))
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
    let signature = sign_message_b64(&signing_key, &sign_input)?;

    let body = serde_json::json!({
        "username": username,
        "session_id": session_id,
        "proposal_bytes": proposal_b64,
        "signature": signature,
    });
    let resp = state
        .client
        .post(format!("{}/v1/groups/{}/proposals", state.base_url, group_id))
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
    let sign_input = commit_signing_input(username, group_id, &commit_bytes, path_bytes.as_deref());
    let signature = sign_message_b64(&signing_key, &sign_input)?;

    let body = serde_json::json!({
        "username": username,
        "session_id": session_id,
        "commit_bytes": commit_b64,
        "path_update_bytes": path_update_b64,
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
    let signature = sign_message_b64(&signing_key, &sign_input)?;

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
    let signature = sign_message_b64(&signing_key, &sign_input)?;

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
    let keypackage = KeyPackage::decode(&bytes).ok_or("failed to decode keypackage".to_string())?;
    if !keypackage.verify() {
        return Err("keypackage signature verification failed".to_string());
    }
    Ok(keypackage)
}

fn resolve_sender_leaf(
    state: &ClientGroupState,
    sender_leaf: Option<usize>,
) -> Result<usize, String> {
    let sender = sender_leaf.unwrap_or(state.own_leaf_index);
    if sender >= state.ratchet_tree.leaf_count() {
        return Err(format!(
            "sender leaf {} out of bounds (leaf_count={})",
            sender,
            state.ratchet_tree.leaf_count()
        ));
    }
    Ok(sender)
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
