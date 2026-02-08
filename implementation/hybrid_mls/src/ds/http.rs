use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};

use crate::ds::auth::{decode_hybrid_signature_b64, decode_hybrid_sign_pub_key_bytes};
use crate::ds::config::{DEFAULT_MAX_BYTES, DEFAULT_MIN_PROPOSALS_PER_COMMIT, StorageConfig};
use crate::ds::storage::{MessageKind, Storage, StorageError};
use crate::tree::KeyPackage;
use sha3::{Digest, Sha3_256};
use rand::rngs::OsRng;
use rand::RngCore;

#[derive(Clone, Debug)]
pub struct ApiState {
    pub max_bytes: u64,
    pub min_proposals_per_commit: usize,
    pub storage: StorageConfig,
}

impl Default for ApiState {
    fn default() -> Self {
        Self {
            max_bytes: DEFAULT_MAX_BYTES,
            min_proposals_per_commit: DEFAULT_MIN_PROPOSALS_PER_COMMIT,
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

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
    pub signature: String,
}

#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub session_id: String,
}

#[derive(Debug, Deserialize)]
pub struct SubmitProposalRequest {
    pub username: String,
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
    pub signature: Option<String>,
    pub limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
pub struct FetchMessageQuery {
    pub username: String,
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

#[derive(Debug, Deserialize, Serialize)]
pub struct PublishKeyPackageRequest {
    pub username: String,
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
        .route("/v1/auth/register", post(register))
        .route("/v1/auth/login", post(login))
        .route("/v1/keypackages", post(publish_keypackage))
        .route("/v1/keypackages/:target", get(fetch_keypackage))
        .route("/v1/groups/:group_id/app-messages", post(submit_app_message))
        .route("/v1/groups/:group_id/app-messages", get(list_app_messages))
        .route("/v1/groups/:group_id/app-messages/:message_id", get(fetch_app_message))
        .route("/v1/groups/:group_id/proposals", post(submit_proposal))
        .route("/v1/groups/:group_id/commits", post(submit_commit))
        .route("/v1/groups/:group_id/messages", get(list_messages))
        .with_state(state)
}

async fn health() -> impl IntoResponse {
    (StatusCode::OK, "ok")
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
    let expires_at = now + 60 * 60 * 24;
    if let Err(err) = storage.insert_session(&token, &req.username, now, expires_at) {
        return storage_error(err);
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
    if let (Some(username), Some(signature)) = (&query.username, &query.signature) {
        if let Err(resp) = verify_request_signature(
            &state,
            username,
            list_signing_input(username, &group_id, query.limit.unwrap_or(50)),
            signature,
        ) {
            return resp;
        }
    } else {
        return auth_error("missing_signature");
    }
    let limit = query.limit.unwrap_or(50);
    let storage = match open_storage(&state) {
        Ok(s) => s,
        Err(err) => return storage_error(err),
    };

    let items = match storage.list_group(&group_id, limit) {
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
    let (Some(username), Some(signature)) = (&query.username, &query.signature) else {
        return auth_error("missing_signature");
    };
    let limit = query.limit.unwrap_or(50);
    if let Err(resp) = verify_request_signature(
        &state,
        username,
        app_list_signing_input(username, &group_id, limit),
        signature,
    ) {
        return resp;
    }

    let storage = match open_storage(&state) {
        Ok(s) => s,
        Err(err) => return storage_error(err),
    };
    let items = match storage.list_group_kind(&group_id, Some(MessageKind::Application), limit) {
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
        return auth_error("missing_signature");
    };
    let Some(signature) = query.signature.as_ref() else {
        return auth_error("missing_signature");
    };

    let sign_input = keypackage_fetch_signing_input(username, &target);
    if let Err(resp) = verify_request_signature(&state, username, sign_input, signature) {
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
    message: Vec<u8>,
    signature_b64: &str,
) -> Result<(), Response> {
    let storage = open_storage(state).map_err(storage_error)?;
    let Some((classic_pub, pq_pub)) = storage.get_user_keys(username).map_err(storage_error)? else {
        return Err(auth_error("unknown_user"));
    };

    if verify_with_keys(&classic_pub, &pq_pub, signature_b64, &message) {
        Ok(())
    } else {
        Err(auth_error("invalid_signature"))
    }
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

fn list_signing_input(username: &str, group_id: &str, limit: usize) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"list|");
    out.extend_from_slice(username.as_bytes());
    out.extend_from_slice(b"|");
    out.extend_from_slice(group_id.as_bytes());
    out.extend_from_slice(b"|");
    out.extend_from_slice(limit.to_string().as_bytes());
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

fn app_list_signing_input(username: &str, group_id: &str, limit: usize) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"app_list|");
    out.extend_from_slice(username.as_bytes());
    out.extend_from_slice(b"|");
    out.extend_from_slice(group_id.as_bytes());
    out.extend_from_slice(b"|");
    out.extend_from_slice(limit.to_string().as_bytes());
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

    #[tokio::test]
    async fn keypackage_publish_and_fetch_roundtrip() {
        let (state, base) = temp_state("kp-roundtrip");
        let app = router(state.clone());

        let mut rng = OsRng;
        let (priv_key, pub_key, classic_b64, pq_b64) = make_signing_keys(&mut rng);

        let username = "alice";
        let password = "secret";
        let sign_input = register_signing_input(username, password, &classic_b64, &pq_b64);
        let signature = STANDARD.encode(priv_key.sign(&sign_input).to_bytes());

        let register = RegisterRequest {
            username: username.to_string(),
            password: password.to_string(),
            classic_pub_key: classic_b64.clone(),
            pq_pub_key: pq_b64.clone(),
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

        let keypackage = make_keypackage(7, pub_key.clone(), &priv_key);
        let kp_bytes = keypackage.encode();
        let sign_input = keypackage_publish_signing_input(username, &kp_bytes);
        let signature = STANDARD.encode(priv_key.sign(&sign_input).to_bytes());
        let publish = PublishKeyPackageRequest {
            username: username.to_string(),
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
        let sign_input = register_signing_input(username, password, &classic_b64, &pq_b64);
        let signature = STANDARD.encode(priv_key.sign(&sign_input).to_bytes());
        let register = RegisterRequest {
            username: username.to_string(),
            password: password.to_string(),
            classic_pub_key: classic_b64.clone(),
            pq_pub_key: pq_b64.clone(),
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

        let (other_priv, other_pub, _classic_b64, _pq_b64) = make_signing_keys(&mut rng);
        let keypackage = make_keypackage(9, other_pub.clone(), &other_priv);
        let kp_bytes = keypackage.encode();
        let sign_input = keypackage_publish_signing_input(username, &kp_bytes);
        let signature = STANDARD.encode(priv_key.sign(&sign_input).to_bytes());
        let publish = PublishKeyPackageRequest {
            username: username.to_string(),
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
        let sign_input = register_signing_input(username, password, &classic_b64, &pq_b64);
        let signature = STANDARD.encode(priv_key.sign(&sign_input).to_bytes());
        let register = RegisterRequest {
            username: username.to_string(),
            password: password.to_string(),
            classic_pub_key: classic_b64.clone(),
            pq_pub_key: pq_b64.clone(),
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

        let group_id = "group-app";
        let payload = b"hello-app";
        let sign_input = app_publish_signing_input(username, group_id, payload);
        let signature = STANDARD.encode(priv_key.sign(&sign_input).to_bytes());
        let submit = SubmitAppMessageRequest {
            username: username.to_string(),
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

        let sign_input = app_list_signing_input(username, group_id, 10);
        let signature = STANDARD.encode(priv_key.sign(&sign_input).to_bytes());
        let query = serde_urlencoded::to_string([
            ("username", username),
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
}
