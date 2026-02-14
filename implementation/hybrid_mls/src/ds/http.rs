use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};

use crate::ds::auth::{decode_hybrid_signature_b64, decode_hybrid_sign_pub_key_bytes};
use crate::ds::config::{
    DEFAULT_MAX_BYTES,
    DEFAULT_MIN_PROPOSALS_PER_COMMIT,
    DEFAULT_SESSION_MAX_PER_USER,
    DEFAULT_SESSION_TTL_SECS,
    StorageConfig,
};
use crate::ds::storage::{MessageKind, Storage, StorageError};
use crate::tree::KeyPackage;
use sha3::{Digest, Sha3_256};
use rand::rngs::OsRng;
use rand::RngCore;

#[derive(Clone, Debug)]
pub struct ApiState {
    pub max_bytes: u64,
    pub min_proposals_per_commit: usize,
    pub session_ttl_secs: u64,
    pub session_max_per_user: usize,
    pub storage: StorageConfig,
}

impl Default for ApiState {
    fn default() -> Self {
        Self {
            max_bytes: DEFAULT_MAX_BYTES,
            min_proposals_per_commit: DEFAULT_MIN_PROPOSALS_PER_COMMIT,
            session_ttl_secs: DEFAULT_SESSION_TTL_SECS,
            session_max_per_user: DEFAULT_SESSION_MAX_PER_USER,
            storage: StorageConfig::new("./data", "./data/ds.sqlite"),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ApiError {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct RegisterRequest {
    pub username: String,
    pub password: String,
    pub classic_pub_key: String,
    pub pq_pub_key: String,
    pub signature: String,
}

#[derive(Debug, Serialize)]
pub struct RegisterResponse {
    pub user_id: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
    pub signature: String,
}

#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub session_id: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct LogoutRequest {
    pub username: String,
    pub session_id: String,
    pub signature: String,
}

#[derive(Debug, Serialize)]
pub struct LogoutResponse {
    pub logged_out: bool,
}

#[derive(Debug, Deserialize)]
pub struct SubmitProposalRequest {
    pub username: String,
    pub session_id: String,
    pub proposal_bytes: String,
    pub signature: String,
}

#[derive(Debug, Serialize)]
pub struct SubmitProposalResponse {
    pub accepted: bool,
    pub pending_proposals: usize,
    pub message: MessageSummary,
}

#[derive(Debug, Deserialize)]
pub struct SubmitCommitRequest {
    pub username: String,
    pub session_id: String,
    pub commit_bytes: String,
    pub path_update_bytes: Option<String>,
    pub signature: String,
}

#[derive(Debug, Serialize)]
pub struct SubmitCommitResponse {
    pub accepted: bool,
    pub commit_id: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SubmitAppMessageRequest {
    pub username: String,
    pub session_id: String,
    pub message_bytes: String,
    pub signature: String,
}

#[derive(Debug, Serialize)]
pub struct SubmitAppMessageResponse {
    pub accepted: bool,
    pub message_id: String,
}

#[derive(Debug, Deserialize)]
pub struct ListMessagesQuery {
    pub username: Option<String>,
    pub session_id: Option<String>,
    pub signature: Option<String>,
    pub limit: Option<usize>,
    pub kind: Option<String>,
    pub before_id: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct FetchMessageQuery {
    pub username: String,
    pub session_id: String,
    pub signature: String,
}

#[derive(Debug, Serialize)]
pub struct MessageSummary {
    pub id: String,
    pub kind: String,
    pub size: u64,
    pub created_at: i64,
}

#[derive(Debug, Serialize)]
pub struct ListMessagesResponse {
    pub messages: Vec<MessageSummary>,
}

#[derive(Debug, Serialize)]
pub struct FetchAppMessageResponse {
    pub id: String,
    pub group_id: String,
    pub message_bytes: String,
}

#[derive(Debug, Serialize)]
pub struct FetchGroupMessageResponse {
    pub id: String,
    pub group_id: String,
    pub kind: String,
    pub message_bytes: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PublishKeyPackageRequest {
    pub username: String,
    pub session_id: String,
    pub keypackage_bytes: String,
    pub signature: String,
}

#[derive(Debug, Serialize)]
pub struct PublishKeyPackageResponse {
    pub accepted: bool,
    pub username: String,
}

#[derive(Debug, Serialize)]
pub struct FetchKeyPackageResponse {
    pub username: String,
    pub keypackage_bytes: String,
    pub created_at: i64,
}

pub fn router(state: ApiState) -> Router {
    Router::new()
        .route("/healthz", get(health))
        .route("/ui", get(ui_index))
        .route("/ui/login", get(ui_login))
        .route("/ui/groups", get(ui_groups))
        .route("/ui/groups/:group_id", get(ui_group_detail))
        .route("/v1/auth/register", post(register))
        .route("/v1/auth/login", post(login))
        .route("/v1/auth/logout", post(logout))
        .route("/v1/keypackages", post(publish_keypackage))
        .route("/v1/keypackages/:target", get(fetch_keypackage))
        .route("/v1/groups/:group_id/app-messages", post(submit_app_message))
        .route("/v1/groups/:group_id/app-messages", get(list_app_messages))
        .route("/v1/groups/:group_id/app-messages/:message_id", get(fetch_app_message))
        .route("/v1/groups/:group_id/proposals", post(submit_proposal))
        .route("/v1/groups/:group_id/commits", post(submit_commit))
        .route("/v1/groups/:group_id/messages", get(list_messages))
        .route("/v1/groups/:group_id/messages/:message_id", get(fetch_group_message))
        .with_state(state)
}

async fn health() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

async fn ui_index() -> impl IntoResponse {
    Redirect::to("/ui/login")
}

async fn ui_login() -> impl IntoResponse {
    ui_shell(
        "DS Login",
        r#"
        <main class="panel">
            <section class="hero">
                <div class="eyebrow">Hybrid MLS Delivery Service</div>
                <h1>Sign In or Register</h1>
                <p class="muted">
                    This is a skeleton UI for local testing. It does not yet perform
                    request signing or real session handling.
                </p>
            </section>
            <section class="card">
                <form class="stack">
                    <label>
                        <span>Username</span>
                        <input type="text" placeholder="alice" />
                    </label>
                    <label>
                        <span>Password</span>
                        <input type="password" placeholder="••••••••" />
                    </label>
                    <div class="row">
                        <button class="primary" type="button">Login</button>
                        <button class="ghost" type="button">Register</button>
                    </div>
                    <div class="note">API signing is required; wire-up is coming next.</div>
                </form>
            </section>
        </main>
        "#,
    )
}

async fn ui_groups() -> impl IntoResponse {
    ui_shell(
        "Groups",
        r#"
        <main class="panel">
            <section class="hero">
                <div class="eyebrow">Groups</div>
                <h1>Membership Overview</h1>
                <p class="muted">Select a group to inspect proposals, commits, and key updates.</p>
            </section>
            <section class="card">
                <div class="list">
                    <div class="list-item">
                        <div>
                            <div class="title">group-alpha</div>
                            <div class="muted">Members: 3 • Epoch: 4</div>
                        </div>
                        <a class="link" href="/ui/groups/group-alpha">Open</a>
                    </div>
                    <div class="list-item">
                        <div>
                            <div class="title">group-beta</div>
                            <div class="muted">Members: 2 • Epoch: 1</div>
                        </div>
                        <a class="link" href="/ui/groups/group-beta">Open</a>
                    </div>
                </div>
                <div class="actions">
                    <button class="ghost" type="button">Create Group</button>
                    <button class="ghost" type="button">Join Group</button>
                </div>
            </section>
        </main>
        "#,
    )
}

async fn ui_group_detail(Path(group_id): Path<String>) -> impl IntoResponse {
    let body = format!(
        r#"
        <main class="panel">
            <section class="hero">
                <div class="eyebrow">Group</div>
                <h1>{group}</h1>
                <p class="muted">Actions are placeholders until request-signing UI is wired.</p>
            </section>
            <section class="card">
                <div class="grid">
                    <button class="primary" type="button">Add Member</button>
                    <button class="ghost" type="button">Remove Member</button>
                    <button class="ghost" type="button">Update My Keys</button>
                    <button class="ghost" type="button">Submit Commit</button>
                </div>
                <div class="divider"></div>
                <div class="list">
                    <div class="list-item">
                        <div class="title">Latest Commit</div>
                        <div class="muted">Epoch 4 • Commit ID #128</div>
                    </div>
                    <div class="list-item">
                        <div class="title">Pending Proposals</div>
                        <div class="muted">2 proposals awaiting commit</div>
                    </div>
                </div>
            </section>
        </main>
        "#,
        group = group_id
    );
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
  <style>
    :root {{
      --ink: #121826;
      --muted: #52607a;
      --accent: #f97316;
      --accent-dark: #c2410c;
      --panel: #ffffff;
      --bg: #f3f0e9;
      --shadow: 0 24px 60px rgba(15, 23, 42, 0.18);
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: "Spectral", "Merriweather", serif;
      color: var(--ink);
      background: radial-gradient(circle at top, #fff6e4 0%, #f6efe1 40%, #f1e7d6 100%);
      min-height: 100vh;
      display: flex;
      justify-content: center;
      padding: 48px 20px;
    }}
    .panel {{
      max-width: 980px;
      width: 100%;
      display: grid;
      gap: 24px;
    }}
    .hero {{
      padding: 12px 8px;
    }}
    .eyebrow {{
      text-transform: uppercase;
      letter-spacing: 0.2em;
      font-size: 0.7rem;
      color: var(--accent-dark);
      margin-bottom: 10px;
    }}
    h1 {{
      font-size: 2.4rem;
      margin: 0 0 10px 0;
    }}
    .muted {{
      color: var(--muted);
      font-size: 1rem;
    }}
    .card {{
      background: var(--panel);
      border-radius: 18px;
      padding: 28px;
      box-shadow: var(--shadow);
    }}
    .stack {{
      display: grid;
      gap: 16px;
    }}
    label {{
      display: grid;
      gap: 8px;
      font-size: 0.95rem;
    }}
    input {{
      border-radius: 10px;
      border: 1px solid #e2e8f0;
      padding: 12px 14px;
      font-size: 1rem;
      background: #fafafa;
    }}
    .row {{
      display: flex;
      gap: 12px;
      flex-wrap: wrap;
    }}
    button {{
      border: none;
      border-radius: 12px;
      padding: 12px 18px;
      cursor: pointer;
      font-size: 0.95rem;
    }}
    .primary {{
      background: var(--accent);
      color: white;
    }}
    .primary:hover {{
      background: var(--accent-dark);
    }}
    .ghost {{
      background: #f1f5f9;
      color: var(--ink);
    }}
    .note {{
      font-size: 0.85rem;
      color: var(--muted);
    }}
    .list {{
      display: grid;
      gap: 16px;
    }}
    .list-item {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 14px 16px;
      border-radius: 12px;
      background: #f8fafc;
    }}
    .title {{
      font-weight: 600;
    }}
    .link {{
      text-decoration: none;
      color: var(--accent-dark);
      font-weight: 600;
    }}
    .actions {{
      margin-top: 16px;
      display: flex;
      gap: 12px;
      flex-wrap: wrap;
    }}
    .grid {{
      display: grid;
      gap: 12px;
      grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
    }}
    .divider {{
      height: 1px;
      background: #e2e8f0;
      margin: 20px 0;
    }}
    @media (max-width: 720px) {{
      h1 {{ font-size: 2rem; }}
      .card {{ padding: 20px; }}
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

async fn register(
    State(state): State<ApiState>,
    Json(req): Json<RegisterRequest>,
) -> impl IntoResponse {
    let classic_pub = match decode_b64(&req.classic_pub_key) {
        Ok(p) => p,
        Err(err) => return err,
    };
    let pq_pub = match decode_b64(&req.pq_pub_key) {
        Ok(p) => p,
        Err(err) => return err,
    };

    let sign_input = register_signing_input(&req.username, &req.password, &req.classic_pub_key, &req.pq_pub_key);
    if !verify_with_keys(&classic_pub, &pq_pub, &req.signature, &sign_input) {
        return auth_error("invalid_signature");
    }

    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let password_hash = hash_password(&req.password, &salt);

    let mut storage = match open_storage(&state) {
        Ok(s) => s,
        Err(err) => return storage_error(err),
    };

    if let Err(err) = storage.insert_user(
        &req.username,
        &password_hash,
        &salt,
        &classic_pub,
        &pq_pub,
    ) {
        return storage_error(err);
    }

    (
        StatusCode::OK,
        Json(RegisterResponse {
            user_id: req.username,
        }),
    )
        .into_response()
}

async fn login(
    State(state): State<ApiState>,
    Json(req): Json<LoginRequest>,
) -> impl IntoResponse {
    let mut storage = match open_storage(&state) {
        Ok(s) => s,
        Err(err) => return storage_error(err),
    };

    let Some((classic_pub, pq_pub)) = storage
        .get_user_keys(&req.username)
        .map_err(storage_error)
        .ok()
        .flatten()
    else {
        return auth_error("unknown_user");
    };

    let sign_input = login_signing_input(&req.username, &req.password);
    if !verify_with_keys(&classic_pub, &pq_pub, &req.signature, &sign_input) {
        return auth_error("invalid_signature");
    }

    let Some((password_hash, salt)) = storage
        .get_user_auth(&req.username)
        .map_err(storage_error)
        .ok()
        .flatten()
    else {
        return auth_error("unknown_user");
    };

    if !verify_password(&req.password, &salt, &password_hash) {
        return auth_error("invalid_password");
    }

    let token = generate_token();
    let now = now_unix();
    let _ = storage.purge_expired_sessions(now);
    if state.session_max_per_user == 1 {
        if let Err(err) = storage.delete_sessions_for_user(&req.username) {
            return storage_error(err);
        }
    }

    let ttl_secs = i64::try_from(state.session_ttl_secs).unwrap_or(i64::MAX);
    let expires_at = now.saturating_add(ttl_secs);
    if let Err(err) = storage.insert_session(&token, &req.username, now, expires_at) {
        return storage_error(err);
    }
    if state.session_max_per_user > 1 {
        if let Err(err) = storage.trim_sessions_for_user(&req.username, state.session_max_per_user) {
            return storage_error(err);
        }
    }

    let mut headers = HeaderMap::new();
    if let Ok(value) = HeaderValue::from_str(&format!(
        "ds_session={token}; HttpOnly; Path=/; SameSite=Lax"
    )) {
        headers.insert("Set-Cookie", value);
    }

    (
        StatusCode::OK,
        headers,
        Json(LoginResponse {
            session_id: token,
        }),
    )
        .into_response()
}

async fn logout(
    State(state): State<ApiState>,
    Json(req): Json<LogoutRequest>,
) -> impl IntoResponse {
    let sign_input = logout_signing_input(&req.username, &req.session_id);
    if let Err(resp) = verify_authenticated_request(
        &state,
        &req.username,
        &req.session_id,
        sign_input,
        &req.signature,
    ) {
        return resp;
    }

    let mut storage = match open_storage(&state) {
        Ok(s) => s,
        Err(err) => return storage_error(err),
    };
    if let Err(err) = storage.delete_session(&req.session_id) {
        return storage_error(err);
    }

    (
        StatusCode::OK,
        Json(LogoutResponse { logged_out: true }),
    )
        .into_response()
}

async fn submit_proposal(
    State(state): State<ApiState>,
    Path(group_id): Path<String>,
    Json(req): Json<SubmitProposalRequest>,
) -> impl IntoResponse {
    let payload = match decode_b64(&req.proposal_bytes) {
        Ok(p) => p,
        Err(err) => return err,
    };
    if let Err(resp) = verify_request_signature(
        &state,
        &req.username,
        &req.session_id,
        proposal_signing_input(&req.username, &group_id, &payload),
        &req.signature,
    ) {
        return resp;
    }
    let mut storage = match open_storage(&state) {
        Ok(s) => s,
        Err(err) => return storage_error(err),
    };

    let stored = match storage.store_message(&group_id, MessageKind::Proposal, &payload) {
        Ok(s) => s,
        Err(err) => return storage_error(err),
    };

    let pending = match storage.count_by_kind(&group_id, MessageKind::Proposal) {
        Ok(count) => count as usize,
        Err(err) => return storage_error(err),
    };

    (StatusCode::OK, Json(SubmitProposalResponse {
        accepted: true,
        pending_proposals: pending,
        message: MessageSummary {
            id: stored.id.to_string(),
            kind: stored.kind.as_str().to_string(),
            size: stored.size,
            created_at: stored.created_at,
        },
    }))
        .into_response()
}

async fn submit_commit(
    State(state): State<ApiState>,
    Path(group_id): Path<String>,
    Json(req): Json<SubmitCommitRequest>,
) -> impl IntoResponse {
    let commit_payload = match decode_b64(&req.commit_bytes) {
        Ok(p) => p,
        Err(err) => return err,
    };
    let path_update_payload = match req.path_update_bytes {
        Some(ref bytes) => match decode_b64(bytes) {
            Ok(p) => Some(p),
            Err(err) => return err,
        },
        None => None,
    };
    if let Err(resp) = verify_request_signature(
        &state,
        &req.username,
        &req.session_id,
        commit_signing_input(&req.username, &group_id, &commit_payload, path_update_payload.as_deref()),
        &req.signature,
    ) {
        return resp;
    }

    let mut storage = match open_storage(&state) {
        Ok(s) => s,
        Err(err) => return storage_error(err),
    };

    let pending = match storage.count_by_kind(&group_id, MessageKind::Proposal) {
        Ok(count) => count as usize,
        Err(err) => return storage_error(err),
    };

    if pending < state.min_proposals_per_commit {
        return (
            StatusCode::CONFLICT,
            Json(ApiError {
                code: "min_proposals".to_string(),
                message: format!(
                    "commit rejected: {pending} proposals pending; minimum is {}",
                    state.min_proposals_per_commit
                ),
            }),
        )
            .into_response();
    }

    let stored = match storage.store_message(&group_id, MessageKind::Commit, &commit_payload) {
        Ok(s) => s,
        Err(err) => return storage_error(err),
    };

    if let Some(path_payload) = path_update_payload {
        if let Err(err) = storage.store_message(&group_id, MessageKind::PathUpdate, &path_payload) {
            return storage_error(err);
        }
    }

    if let Err(err) = storage.delete_group_kind(&group_id, MessageKind::Proposal) {
        return storage_error(err);
    }

    (StatusCode::OK, Json(SubmitCommitResponse {
        accepted: true,
        commit_id: stored.id.to_string(),
    }))
        .into_response()
}

async fn list_messages(
    State(state): State<ApiState>,
    Path(group_id): Path<String>,
    Query(query): Query<ListMessagesQuery>,
) -> impl IntoResponse {
    if let (Some(username), Some(session_id), Some(signature)) =
        (&query.username, &query.session_id, &query.signature)
    {
        let kind_label = query.kind.as_deref().unwrap_or("any");
        let before_id = query.before_id;
        if let Err(resp) = verify_request_signature(
            &state,
            username,
            session_id,
            list_signing_input(
                username,
                &group_id,
                query.limit.unwrap_or(50),
                kind_label,
                before_id,
            ),
            signature,
        ) {
            return resp;
        }
    } else {
        return auth_error("missing_session");
    }
    let limit = query.limit.unwrap_or(50);
    let storage = match open_storage(&state) {
        Ok(s) => s,
        Err(err) => return storage_error(err),
    };

    let kind = match query.kind.as_deref() {
        None | Some("any") => None,
        Some("proposal") => Some(MessageKind::Proposal),
        Some("commit") => Some(MessageKind::Commit),
        Some("path_update") => Some(MessageKind::PathUpdate),
        Some("application") => Some(MessageKind::Application),
        Some(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiError {
                    code: "invalid_kind".to_string(),
                    message: "kind must be proposal, commit, path_update, application, or any"
                        .to_string(),
                }),
            )
                .into_response()
        }
    };

    let items = match storage.list_group_kind(&group_id, kind, limit, query.before_id) {
        Ok(list) => list,
        Err(err) => return storage_error(err),
    };

    let messages = items
        .into_iter()
        .map(|msg| MessageSummary {
            id: msg.id.to_string(),
            kind: msg.kind.as_str().to_string(),
            size: msg.size,
            created_at: msg.created_at,
        })
        .collect();

    (StatusCode::OK, Json(ListMessagesResponse { messages })).into_response()
}

async fn submit_app_message(
    State(state): State<ApiState>,
    Path(group_id): Path<String>,
    Json(req): Json<SubmitAppMessageRequest>,
) -> impl IntoResponse {
    let payload = match decode_b64(&req.message_bytes) {
        Ok(p) => p,
        Err(err) => return err,
    };
    if let Err(resp) = verify_request_signature(
        &state,
        &req.username,
        &req.session_id,
        app_publish_signing_input(&req.username, &group_id, &payload),
        &req.signature,
    ) {
        return resp;
    }

    let mut storage = match open_storage(&state) {
        Ok(s) => s,
        Err(err) => return storage_error(err),
    };
    let stored = match storage.store_message(&group_id, MessageKind::Application, &payload) {
        Ok(s) => s,
        Err(err) => return storage_error(err),
    };

    (
        StatusCode::OK,
        Json(SubmitAppMessageResponse {
            accepted: true,
            message_id: stored.id.to_string(),
        }),
    )
        .into_response()
}

async fn list_app_messages(
    State(state): State<ApiState>,
    Path(group_id): Path<String>,
    Query(query): Query<ListMessagesQuery>,
) -> impl IntoResponse {
    let (Some(username), Some(session_id), Some(signature)) =
        (&query.username, &query.session_id, &query.signature)
    else {
        return auth_error("missing_session");
    };
    let limit = query.limit.unwrap_or(50);
    let before_id = query.before_id;
    if let Err(resp) = verify_request_signature(
        &state,
        username,
        session_id,
        app_list_signing_input(username, &group_id, limit, before_id),
        signature,
    ) {
        return resp;
    }

    let storage = match open_storage(&state) {
        Ok(s) => s,
        Err(err) => return storage_error(err),
    };
    let items = match storage.list_group_kind(
        &group_id,
        Some(MessageKind::Application),
        limit,
        before_id,
    ) {
        Ok(list) => list,
        Err(err) => return storage_error(err),
    };

    let messages = items
        .into_iter()
        .map(|msg| MessageSummary {
            id: msg.id.to_string(),
            kind: msg.kind.as_str().to_string(),
            size: msg.size,
            created_at: msg.created_at,
        })
        .collect();

    (StatusCode::OK, Json(ListMessagesResponse { messages })).into_response()
}

async fn fetch_app_message(
    State(state): State<ApiState>,
    Path((group_id, message_id)): Path<(String, i64)>,
    Query(query): Query<FetchMessageQuery>,
) -> impl IntoResponse {
    if let Err(resp) = verify_request_signature(
        &state,
        &query.username,
        &query.session_id,
        app_fetch_signing_input(&query.username, &group_id, message_id),
        &query.signature,
    ) {
        return resp;
    }

    let storage = match open_storage(&state) {
        Ok(s) => s,
        Err(err) => return storage_error(err),
    };
    let Some(payload) = (match storage.load_message_group_kind(
        message_id,
        &group_id,
        MessageKind::Application,
    ) {
        Ok(res) => res,
        Err(err) => return storage_error(err),
    }) else {
        return (
            StatusCode::NOT_FOUND,
            Json(ApiError {
                code: "message_not_found".to_string(),
                message: "message not found".to_string(),
            }),
        )
            .into_response();
    };

    let payload_b64 = STANDARD.encode(&payload);
    (
        StatusCode::OK,
        Json(FetchAppMessageResponse {
            id: message_id.to_string(),
            group_id,
            message_bytes: payload_b64,
        }),
    )
        .into_response()
}

async fn fetch_group_message(
    State(state): State<ApiState>,
    Path((group_id, message_id)): Path<(String, i64)>,
    Query(query): Query<FetchMessageQuery>,
) -> impl IntoResponse {
    if let Err(resp) = verify_request_signature(
        &state,
        &query.username,
        &query.session_id,
        fetch_message_signing_input(&query.username, &group_id, message_id),
        &query.signature,
    ) {
        return resp;
    }

    let storage = match open_storage(&state) {
        Ok(s) => s,
        Err(err) => return storage_error(err),
    };
    let Some((kind, payload)) = (match storage.load_message_group(message_id, &group_id) {
        Ok(res) => res,
        Err(err) => return storage_error(err),
    }) else {
        return (
            StatusCode::NOT_FOUND,
            Json(ApiError {
                code: "message_not_found".to_string(),
                message: "message not found".to_string(),
            }),
        )
            .into_response();
    };

    let payload_b64 = STANDARD.encode(&payload);
    (
        StatusCode::OK,
        Json(FetchGroupMessageResponse {
            id: message_id.to_string(),
            group_id,
            kind: kind.as_str().to_string(),
            message_bytes: payload_b64,
        }),
    )
        .into_response()
}

async fn publish_keypackage(
    State(state): State<ApiState>,
    Json(req): Json<PublishKeyPackageRequest>,
) -> impl IntoResponse {
    let payload = match decode_b64(&req.keypackage_bytes) {
        Ok(p) => p,
        Err(err) => return err,
    };

    let Some(keypackage) = KeyPackage::decode(&payload) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiError {
                code: "invalid_keypackage".to_string(),
                message: "failed to decode keypackage".to_string(),
            }),
        )
            .into_response();
    };

    if !keypackage.verify() {
        return auth_error("invalid_keypackage_signature");
    }

    let sign_input = keypackage_publish_signing_input(&req.username, &payload);
    let (classic_pub, pq_pub) = match fetch_user_keys(&state, &req.username) {
        Ok(keys) => keys,
        Err(resp) => return resp,
    };
    if !verify_with_keys(&classic_pub, &pq_pub, &req.signature, &sign_input) {
        return auth_error("invalid_signature");
    }

    if let Err(resp) = verify_session_only(&state, &req.username, &req.session_id) {
        return resp;
    }

    let identity_bytes = keypackage.identity.to_bytes();
    if identity_bytes.len() < 32 {
        return auth_error("invalid_keypackage_identity");
    }
    let keypackage_classic = &identity_bytes[..32];
    let keypackage_pq = &identity_bytes[32..];
    if keypackage_classic != classic_pub.as_slice() || keypackage_pq != pq_pub.as_slice() {
        return auth_error("keypackage_identity_mismatch");
    }

    let mut storage = match open_storage(&state) {
        Ok(s) => s,
        Err(err) => return storage_error(err),
    };
    if let Err(err) = storage.upsert_key_package(&req.username, &payload) {
        return storage_error(err);
    }

    (
        StatusCode::OK,
        Json(PublishKeyPackageResponse {
            accepted: true,
            username: req.username,
        }),
    )
        .into_response()
}

async fn fetch_keypackage(
    State(state): State<ApiState>,
    Path(target): Path<String>,
    Query(query): Query<ListMessagesQuery>,
) -> impl IntoResponse {
    let Some(username) = query.username.as_ref() else {
        return auth_error("missing_session");
    };
    let Some(session_id) = query.session_id.as_ref() else {
        return auth_error("missing_session");
    };
    let Some(signature) = query.signature.as_ref() else {
        return auth_error("missing_signature");
    };

    let sign_input = keypackage_fetch_signing_input(username, &target);
    if let Err(resp) = verify_request_signature(&state, username, session_id, sign_input, signature) {
        return resp;
    }

    let storage = match open_storage(&state) {
        Ok(s) => s,
        Err(err) => return storage_error(err),
    };
    let Some((payload, created_at)) = (match storage.get_key_package(&target) {
        Ok(res) => res,
        Err(err) => return storage_error(err),
    }) else {
        return (
            StatusCode::NOT_FOUND,
            Json(ApiError {
                code: "keypackage_not_found".to_string(),
                message: "keypackage not found".to_string(),
            }),
        )
            .into_response();
    };

    let payload_b64 = STANDARD.encode(&payload);
    (
        StatusCode::OK,
        Json(FetchKeyPackageResponse {
            username: target,
            keypackage_bytes: payload_b64,
            created_at,
        }),
    )
        .into_response()
}

fn not_implemented(endpoint: &str) -> (StatusCode, Json<ApiError>) {
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(ApiError {
            code: "not_implemented".to_string(),
            message: format!("endpoint {endpoint} is not implemented yet"),
        }),
    )
}

fn decode_b64(value: &str) -> Result<Vec<u8>, Response> {
    STANDARD
        .decode(value)
        .map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                Json(ApiError {
                    code: "invalid_base64".to_string(),
                    message: "payload must be base64".to_string(),
                }),
            )
                .into_response()
        })
}

fn storage_error(err: StorageError) -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ApiError {
            code: "storage_error".to_string(),
            message: err.to_string(),
        }),
    )
        .into_response()
}

fn open_storage(state: &ApiState) -> Result<Storage, StorageError> {
    let mut config = state.storage.clone();
    config.max_bytes = state.max_bytes;
    Storage::open(config)
}

fn auth_error(code: &str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(ApiError {
            code: code.to_string(),
            message: "signature verification failed".to_string(),
        }),
    )
        .into_response()
}

fn verify_request_signature(
    state: &ApiState,
    username: &str,
    session_id: &str,
    message: Vec<u8>,
    signature_b64: &str,
) -> Result<(), Response> {
    verify_authenticated_request(
        state,
        username,
        session_id,
        message,
        signature_b64,
    )
}

fn verify_authenticated_request(
    state: &ApiState,
    username: &str,
    session_id: &str,
    message: Vec<u8>,
    signature_b64: &str,
) -> Result<(), Response> {
    let mut storage = open_storage(state).map_err(storage_error)?;
    let now = now_unix();

    let Some((session_username, expires_at)) =
        storage.get_session(session_id).map_err(storage_error)?
    else {
        return Err(auth_error("invalid_session"));
    };
    if session_username != username {
        return Err(auth_error("invalid_session"));
    }
    if expires_at <= now {
        let _ = storage.delete_session(session_id);
        return Err(auth_error("session_expired"));
    }

    let Some((classic_pub, pq_pub)) = storage.get_user_keys(username).map_err(storage_error)? else {
        return Err(auth_error("unknown_user"));
    };

    if verify_with_keys(&classic_pub, &pq_pub, signature_b64, &message) {
        Ok(())
    } else {
        Err(auth_error("invalid_signature"))
    }
}

fn verify_session_only(
    state: &ApiState,
    username: &str,
    session_id: &str,
) -> Result<(), Response> {
    let mut storage = open_storage(state).map_err(storage_error)?;
    let now = now_unix();
    let Some((session_username, expires_at)) =
        storage.get_session(session_id).map_err(storage_error)?
    else {
        return Err(auth_error("invalid_session"));
    };
    if session_username != username {
        return Err(auth_error("invalid_session"));
    }
    if expires_at <= now {
        let _ = storage.delete_session(session_id);
        return Err(auth_error("session_expired"));
    }
    Ok(())
}

fn verify_with_keys(
    classic_pub: &[u8],
    pq_pub: &[u8],
    signature_b64: &str,
    message: &[u8],
) -> bool {
    let Some(pub_key) = decode_hybrid_sign_pub_key_bytes(classic_pub, pq_pub) else {
        return false;
    };
    let Some(sig) = decode_hybrid_signature_b64(signature_b64) else {
        return false;
    };
    sig.verify(&pub_key, message)
}

fn fetch_user_keys(state: &ApiState, username: &str) -> Result<(Vec<u8>, Vec<u8>), Response> {
    let storage = open_storage(state).map_err(storage_error)?;
    let Some((classic_pub, pq_pub)) = storage.get_user_keys(username).map_err(storage_error)? else {
        return Err(auth_error("unknown_user"));
    };
    Ok((classic_pub, pq_pub))
}

fn hash_password(password: &str, salt: &[u8]) -> Vec<u8> {
    let mut hasher = Sha3_256::new();
    hasher.update(b"DS-PASSWORD");
    hasher.update(salt);
    hasher.update(password.as_bytes());
    hasher.finalize().to_vec()
}

fn verify_password(password: &str, salt: &[u8], expected: &[u8]) -> bool {
    hash_password(password, salt) == expected
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

fn now_unix() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn generate_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    STANDARD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{SecretKey, SigningKey as EdSigningKey};
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use ml_kem::Seed;
    use ml_dsa::{KeyGen, MlDsa65};
    use rand::{rngs::OsRng, RngCore};
    use serde_urlencoded;
    use tower::util::ServiceExt;
    use x25519_dalek::{PublicKey as X25519Pub, StaticSecret as X25519Priv};

    use crate::crypto::{HybridSignPrivKey, HybridSignPubKey};
    use crate::crypto::{HybridPublicKey, KyberPriv};
    use crate::tree::KeyPackage;

    #[test]
    fn password_hash_roundtrip() {
        let salt = [7u8; 16];
        let hash = hash_password("correct-horse", &salt);
        assert!(verify_password("correct-horse", &salt, &hash));
        assert!(!verify_password("wrong-battery", &salt, &hash));
    }

    #[test]
    fn verify_with_keys_accepts_valid_signature() {
        let mut rng = OsRng;
        let mut secret: SecretKey = [0u8; 32];
        rng.fill_bytes(&mut secret);
        let classic_sk = EdSigningKey::from_bytes(&secret);
        let classic_pk = classic_sk.verifying_key();

        let kp = MlDsa65::key_gen(&mut rng);
        let pq_sk = kp.signing_key().clone();
        let pq_pk = kp.verifying_key().clone();

        let priv_key = HybridSignPrivKey {
            classic: classic_sk,
            pq: pq_sk,
        };

        let message = b"verify-with-keys";
        let sig = priv_key.sign(message);
        let sig_b64 = STANDARD.encode(sig.to_bytes());

        let ok = verify_with_keys(classic_pk.as_bytes(), &pq_pk.encode(), &sig_b64, message);
        assert!(ok);

        let bad = verify_with_keys(classic_pk.as_bytes(), &pq_pk.encode(), &sig_b64, b"other");
        assert!(!bad);
    }

    fn temp_state(label: &str) -> (ApiState, std::path::PathBuf) {
        let base = std::env::temp_dir().join(format!(
            "hybrid-mls-http-{label}-{}",
            rand::random::<u64>()
        ));
        let db_path = base.join("ds.sqlite");
        let mut state = ApiState::default();
        state.storage = StorageConfig::new(&base, &db_path);
        (state, base)
    }

    fn make_signing_keys(rng: &mut OsRng) -> (HybridSignPrivKey, HybridSignPubKey, String, String) {
        let mut secret: SecretKey = [0u8; 32];
        rng.fill_bytes(&mut secret);
        let classic_sk = EdSigningKey::from_bytes(&secret);
        let classic_pk = classic_sk.verifying_key();

        let kp = MlDsa65::key_gen(rng);
        let pq_sk = kp.signing_key().clone();
        let pq_pk = kp.verifying_key().clone();

        let priv_key = HybridSignPrivKey {
            classic: classic_sk,
            pq: pq_sk,
        };
        let pub_key = HybridSignPubKey {
            classic: classic_pk,
            pq: pq_pk,
        };

        let classic_b64 = STANDARD.encode(classic_pk.as_bytes());
        let pq_b64 = STANDARD.encode(pub_key.pq.encode());
        (priv_key, pub_key, classic_b64, pq_b64)
    }

    fn make_keypackage(seed: u8, identity: HybridSignPubKey, signer: &HybridSignPrivKey) -> KeyPackage {
        let classic_kem_priv = X25519Priv::from([seed; 32]);
        let classic_kem_pub = X25519Pub::from(&classic_kem_priv);

        let kem_seed = Seed::from([seed; 64]);
        let kyber_priv = KyberPriv::from_seed(kem_seed);
        let kyber_pub = kyber_priv.encapsulation_key().clone();

        let init_key = HybridPublicKey {
            classic: classic_kem_pub,
            pq: kyber_pub,
        };
        let signature = signer.sign(&init_key.to_bytes());

        KeyPackage {
            identity,
            init_key,
            signature,
        }
    }

    async fn register_and_login(
        app: &axum::Router,
        username: &str,
        password: &str,
        classic_b64: &str,
        pq_b64: &str,
        priv_key: &HybridSignPrivKey,
    ) -> String {
        let sign_input = register_signing_input(username, password, classic_b64, pq_b64);
        let signature = STANDARD.encode(priv_key.sign(&sign_input).to_bytes());
        let register = RegisterRequest {
            username: username.to_string(),
            password: password.to_string(),
            classic_pub_key: classic_b64.to_string(),
            pq_pub_key: pq_b64.to_string(),
            signature,
        };

        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/auth/register")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&register).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let sign_input = login_signing_input(username, password);
        let signature = STANDARD.encode(priv_key.sign(&sign_input).to_bytes());
        let login = LoginRequest {
            username: username.to_string(),
            password: password.to_string(),
            signature,
        };
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/auth/login")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&login).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        json["session_id"].as_str().unwrap().to_string()
    }

    #[tokio::test]
    async fn keypackage_publish_and_fetch_roundtrip() {
        let (state, base) = temp_state("kp-roundtrip");
        let app = router(state.clone());

        let mut rng = OsRng;
        let (priv_key, pub_key, classic_b64, pq_b64) = make_signing_keys(&mut rng);

        let username = "alice";
        let password = "secret";
        let session_id = register_and_login(
            &app,
            username,
            password,
            &classic_b64,
            &pq_b64,
            &priv_key,
        )
        .await;

        let keypackage = make_keypackage(7, pub_key.clone(), &priv_key);
        let kp_bytes = keypackage.encode();
        let sign_input = keypackage_publish_signing_input(username, &kp_bytes);
        let signature = STANDARD.encode(priv_key.sign(&sign_input).to_bytes());
        let publish = PublishKeyPackageRequest {
            username: username.to_string(),
            session_id: session_id.clone(),
            keypackage_bytes: STANDARD.encode(&kp_bytes),
            signature,
        };

        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/keypackages")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&publish).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let sign_input = keypackage_fetch_signing_input(username, username);
        let signature = STANDARD.encode(priv_key.sign(&sign_input).to_bytes());
        let query = serde_urlencoded::to_string([
            ("username", username),
            ("session_id", session_id.as_str()),
            ("signature", signature.as_str()),
        ])
        .unwrap();
        let resp = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/v1/keypackages/{}?{}", username, query))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let encoded = json.get("keypackage_bytes").unwrap().as_str().unwrap();
        let decoded = STANDARD.decode(encoded).unwrap();
        assert_eq!(decoded, kp_bytes);

        let _ = std::fs::remove_dir_all(base);
    }

    #[tokio::test]
    async fn keypackage_publish_rejects_identity_mismatch() {
        let (state, base) = temp_state("kp-mismatch");
        let app = router(state.clone());

        let mut rng = OsRng;
        let (priv_key, _pub_key, classic_b64, pq_b64) = make_signing_keys(&mut rng);

        let username = "bob";
        let password = "secret";
        let session_id = register_and_login(
            &app,
            username,
            password,
            &classic_b64,
            &pq_b64,
            &priv_key,
        )
        .await;

        let (other_priv, other_pub, _classic_b64, _pq_b64) = make_signing_keys(&mut rng);
        let keypackage = make_keypackage(9, other_pub.clone(), &other_priv);
        let kp_bytes = keypackage.encode();
        let sign_input = keypackage_publish_signing_input(username, &kp_bytes);
        let signature = STANDARD.encode(priv_key.sign(&sign_input).to_bytes());
        let publish = PublishKeyPackageRequest {
            username: username.to_string(),
            session_id,
            keypackage_bytes: STANDARD.encode(&kp_bytes),
            signature,
        };

        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/keypackages")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&publish).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let _ = std::fs::remove_dir_all(base);
    }

    #[tokio::test]
    async fn app_message_publish_list_fetch_roundtrip() {
        let (state, base) = temp_state("app-message");
        let app = router(state.clone());

        let mut rng = OsRng;
        let (priv_key, _pub_key, classic_b64, pq_b64) = make_signing_keys(&mut rng);
        let username = "carol";
        let password = "secret";
        let session_id = register_and_login(
            &app,
            username,
            password,
            &classic_b64,
            &pq_b64,
            &priv_key,
        )
        .await;

        let group_id = "group-app";
        let payload = b"hello-app";
        let sign_input = app_publish_signing_input(username, group_id, payload);
        let signature = STANDARD.encode(priv_key.sign(&sign_input).to_bytes());
        let submit = SubmitAppMessageRequest {
            username: username.to_string(),
            session_id: session_id.clone(),
            message_bytes: STANDARD.encode(payload),
            signature,
        };

        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/groups/{group_id}/app-messages"))
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&submit).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let sign_input = app_list_signing_input(username, group_id, 10, None);
        let signature = STANDARD.encode(priv_key.sign(&sign_input).to_bytes());
        let query = serde_urlencoded::to_string([
            ("username", username),
            ("session_id", session_id.as_str()),
            ("signature", signature.as_str()),
            ("limit", "10"),
        ])
        .unwrap();
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/v1/groups/{group_id}/app-messages?{query}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let message_id = json["messages"][0]["id"].as_str().unwrap().to_string();

        let sign_input = app_fetch_signing_input(username, group_id, message_id.parse().unwrap());
        let signature = STANDARD.encode(priv_key.sign(&sign_input).to_bytes());
        let query = serde_urlencoded::to_string([
            ("username", username),
            ("session_id", session_id.as_str()),
            ("signature", signature.as_str()),
        ])
        .unwrap();
        let resp = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!(
                        "/v1/groups/{group_id}/app-messages/{message_id}?{query}"
                    ))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let encoded = json["message_bytes"].as_str().unwrap();
        let decoded = STANDARD.decode(encoded).unwrap();
        assert_eq!(decoded, payload);

        let _ = std::fs::remove_dir_all(base);
    }

    #[tokio::test]
    async fn login_enforces_ttl_and_rotation() {
        let (mut state, base) = temp_state("session-ttl-rotation");
        state.session_ttl_secs = 60;
        state.session_max_per_user = 1;
        let app = router(state.clone());

        let mut rng = OsRng;
        let (priv_key, _pub_key, classic_b64, pq_b64) = make_signing_keys(&mut rng);
        let username = "alice";
        let password = "secret";
        let session_1 = register_and_login(
            &app,
            username,
            password,
            &classic_b64,
            &pq_b64,
            &priv_key,
        )
        .await;

        let mut config = state.storage.clone();
        config.max_bytes = state.max_bytes;
        let storage = Storage::open(config).expect("open storage");
        let meta = storage
            .get_session_meta(&session_1)
            .expect("get session meta")
            .expect("session meta");
        assert_eq!(meta.0, username);
        assert_eq!(meta.2 - meta.1, 60);

        let sign_input = login_signing_input(username, password);
        let signature = STANDARD.encode(priv_key.sign(&sign_input).to_bytes());
        let login = LoginRequest {
            username: username.to_string(),
            password: password.to_string(),
            signature,
        };
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/auth/login")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&login).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let session_2 = json["session_id"].as_str().unwrap().to_string();

        let mut config = state.storage.clone();
        config.max_bytes = state.max_bytes;
        let storage = Storage::open(config).expect("open storage");
        assert!(storage.get_session(&session_1).expect("get session1").is_none());
        assert!(storage.get_session(&session_2).expect("get session2").is_some());

        let _ = std::fs::remove_dir_all(base);
    }

    #[tokio::test]
    async fn group_message_fetch_commit_and_path_roundtrip() {
        let (mut state, base) = temp_state("group-fetch");
        state.min_proposals_per_commit = 1;
        let app = router(state.clone());

        let mut rng = OsRng;
        let (priv_key, _pub_key, classic_b64, pq_b64) = make_signing_keys(&mut rng);
        let username = "diana";
        let password = "secret";
        let session_id = register_and_login(
            &app,
            username,
            password,
            &classic_b64,
            &pq_b64,
            &priv_key,
        )
        .await;

        let group_id = "group-fetch";

        let proposal_payload = b"proposal-1";
        let sign_input = proposal_signing_input(username, group_id, proposal_payload);
        let signature = STANDARD.encode(priv_key.sign(&sign_input).to_bytes());
        let proposal_req = serde_json::json!({
            "username": username,
            "session_id": session_id.clone(),
            "proposal_bytes": STANDARD.encode(proposal_payload),
            "signature": signature,
        });
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/groups/{group_id}/proposals"))
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&proposal_req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let commit_payload = b"commit-1";
        let path_payload = b"path-1";
        let sign_input = commit_signing_input(username, group_id, commit_payload, Some(path_payload));
        let signature = STANDARD.encode(priv_key.sign(&sign_input).to_bytes());
        let commit_req = serde_json::json!({
            "username": username,
            "session_id": session_id.clone(),
            "commit_bytes": STANDARD.encode(commit_payload),
            "path_update_bytes": STANDARD.encode(path_payload),
            "signature": signature,
        });
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/groups/{group_id}/commits"))
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&commit_req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let sign_input = list_signing_input(username, group_id, 10, "commit", None);
        let signature = STANDARD.encode(priv_key.sign(&sign_input).to_bytes());
        let query = serde_urlencoded::to_string([
            ("username", username),
            ("session_id", session_id.as_str()),
            ("signature", signature.as_str()),
            ("limit", "10"),
            ("kind", "commit"),
        ])
        .unwrap();
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/v1/groups/{group_id}/messages?{query}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let commit_id = json["messages"][0]["id"].as_str().unwrap().parse::<i64>().unwrap();

        let sign_input = fetch_message_signing_input(username, group_id, commit_id);
        let signature = STANDARD.encode(priv_key.sign(&sign_input).to_bytes());
        let query = serde_urlencoded::to_string([
            ("username", username),
            ("session_id", session_id.as_str()),
            ("signature", signature.as_str()),
        ])
        .unwrap();
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/v1/groups/{group_id}/messages/{commit_id}?{query}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["kind"].as_str().unwrap(), "commit");
        let decoded = STANDARD.decode(json["message_bytes"].as_str().unwrap()).unwrap();
        assert_eq!(decoded, commit_payload);

        let sign_input = list_signing_input(username, group_id, 10, "path_update", None);
        let signature = STANDARD.encode(priv_key.sign(&sign_input).to_bytes());
        let query = serde_urlencoded::to_string([
            ("username", username),
            ("session_id", session_id.as_str()),
            ("signature", signature.as_str()),
            ("limit", "10"),
            ("kind", "path_update"),
        ])
        .unwrap();
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/v1/groups/{group_id}/messages?{query}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let path_id = json["messages"][0]["id"].as_str().unwrap().parse::<i64>().unwrap();

        let sign_input = fetch_message_signing_input(username, group_id, path_id);
        let signature = STANDARD.encode(priv_key.sign(&sign_input).to_bytes());
        let query = serde_urlencoded::to_string([
            ("username", username),
            ("session_id", session_id.as_str()),
            ("signature", signature.as_str()),
        ])
        .unwrap();
        let resp = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/v1/groups/{group_id}/messages/{path_id}?{query}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["kind"].as_str().unwrap(), "path_update");
        let decoded = STANDARD.decode(json["message_bytes"].as_str().unwrap()).unwrap();
        assert_eq!(decoded, path_payload);

        let _ = std::fs::remove_dir_all(base);
    }
}
