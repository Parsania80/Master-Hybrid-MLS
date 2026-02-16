use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use clap::{Parser, Subcommand};
use ed25519_dalek::{
    SecretKey as EdSecretKey, SigningKey as EdSigningKey, VerifyingKey as EdPublic,
};
use ml_dsa::{EncodedSigningKey, EncodedVerifyingKey, KeyGen, MlDsa65};
use ml_kem::{KeyExport, Seed};
use rand::rngs::OsRng;
use rand::RngCore;
use rand_core::{Infallible, TryCryptoRng, TryRng};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_urlencoded;
use sha3::{Digest, Sha3_256};
use x25519_dalek::{PublicKey as X25519Pub, StaticSecret as X25519Priv};

use hybrid_mls::authenticated_content::{
    commit_authenticated_content_hash, path_update_authenticated_content_hash,
    proposal_authenticated_content_hash,
};
use hybrid_mls::client_state::ClientGroupState;
use hybrid_mls::crypto::{
    decrypt_hpke_payload, encrypt_hpke_payload, HybridPrivateKey, HybridPublicKey,
    HybridSignPrivKey, KyberPriv,
};
use hybrid_mls::envelope::{CommitEnvelope, PathUpdateEnvelope, ProposalEnvelope};
use hybrid_mls::key_schedule::tree_snapshot_hash;
use hybrid_mls::transcript::{
    derive_confirmation_key, derive_confirmation_tag, verify_confirmation_tag,
};
use hybrid_mls::tree::{
    Commit, KeyPackage, LeafNode, Node, ParentUpdate, PathUpdate, Proposal, RatchetTree,
};
use hybrid_mls::welcome::{EncryptedGroupSecrets, GroupInfo, GroupSecrets, Welcome};

#[derive(Parser, Debug)]
#[command(
    name = "ds-client",
    version,
    about = "Hybrid MLS Delivery Service client"
)]
pub struct Cli {
    #[arg(long, default_value = "http://127.0.0.1:3000")]
    pub base_url: String,
    #[arg(long, default_value = "ds-client.json")]
    pub state: PathBuf,
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    Keygen {
        #[arg(long)]
        out: PathBuf,
        #[arg(long, default_value_t = false)]
        force: bool,
    },
    KeypackageExport {
        #[arg(long)]
        kem_file: PathBuf,
        #[arg(long)]
        keypackage_out: PathBuf,
        #[arg(long)]
        receiver_private_out: PathBuf,
        #[arg(long, default_value_t = false)]
        force: bool,
    },
    BootstrapGroupState {
        #[arg(long)]
        group_id: String,
        #[arg(long = "member-keypackage", required = true)]
        member_keypackage: Vec<PathBuf>,
        #[arg(long)]
        own_leaf: usize,
        #[arg(long)]
        out: PathBuf,
        #[arg(long, default_value_t = false)]
        force: bool,
    },
    Register {
        #[arg(long)]
        username: String,
        #[arg(long)]
        password: String,
        #[arg(long, default_value_t = false)]
        force: bool,
    },
    Login {
        #[arg(long)]
        username: Option<String>,
        #[arg(long)]
        password: String,
    },
    Logout {
        #[arg(long)]
        username: Option<String>,
    },
    SubmitProposal {
        #[arg(long)]
        username: Option<String>,
        #[arg(long)]
        group_id: String,
        #[arg(long)]
        proposal_file: PathBuf,
    },
    SubmitCommit {
        #[arg(long)]
        username: Option<String>,
        #[arg(long)]
        group_id: String,
        #[arg(long)]
        commit_file: PathBuf,
        #[arg(long)]
        path_update_file: Option<PathBuf>,
        #[arg(long)]
        welcome_file: Option<PathBuf>,
    },
    ListMessages {
        #[arg(long)]
        username: Option<String>,
        #[arg(long)]
        group_id: String,
        #[arg(long, default_value_t = 50)]
        limit: usize,
        #[arg(long, default_value = "any")]
        kind: String,
        #[arg(long)]
        before_id: Option<i64>,
    },
    SendAppMessage {
        #[arg(long)]
        username: Option<String>,
        #[arg(long)]
        group_id: String,
        #[arg(long)]
        message_file: PathBuf,
    },
    ListAppMessages {
        #[arg(long)]
        username: Option<String>,
        #[arg(long)]
        group_id: String,
        #[arg(long, default_value_t = 50)]
        limit: usize,
        #[arg(long)]
        before_id: Option<i64>,
    },
    FetchAppMessage {
        #[arg(long)]
        username: Option<String>,
        #[arg(long)]
        group_id: String,
        #[arg(long)]
        message_id: String,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    PublishKeyPackage {
        #[arg(long)]
        username: Option<String>,
        #[arg(long)]
        keypackage_file: PathBuf,
    },
    FetchKeyPackage {
        #[arg(long)]
        username: Option<String>,
        #[arg(long)]
        target: String,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    CreateAddProposal {
        #[arg(long)]
        group_state: PathBuf,
        #[arg(long)]
        keypackage_file: PathBuf,
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        sender_leaf: Option<usize>,
    },
    CreateUpdateProposal {
        #[arg(long)]
        group_state: PathBuf,
        #[arg(long)]
        keypackage_file: PathBuf,
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        sender_leaf: Option<usize>,
        #[arg(long)]
        target_leaf: Option<usize>,
    },
    CreateRemoveProposal {
        #[arg(long)]
        group_state: PathBuf,
        #[arg(long)]
        remove_leaf: usize,
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        sender_leaf: Option<usize>,
    },
    CreateCommit {
        #[arg(long)]
        group_state: PathBuf,
        #[arg(long)]
        commit_out: PathBuf,
        #[arg(long)]
        path_update_out: PathBuf,
        #[arg(long)]
        welcome_out: Option<PathBuf>,
        #[arg(long)]
        sender_leaf: Option<usize>,
    },
    ApplyReceivedCommit {
        #[arg(long)]
        group_state: PathBuf,
        #[arg(long)]
        commit_file: PathBuf,
        #[arg(long)]
        path_update_file: Option<PathBuf>,
        #[arg(long)]
        receiver_private_file: Option<PathBuf>,
        #[arg(long)]
        derived_out: Option<PathBuf>,
    },
    JoinFromCommit {
        #[arg(long = "base-member-keypackage", required = true)]
        base_member_keypackage: Vec<PathBuf>,
        #[arg(long)]
        commit_file: PathBuf,
        #[arg(long)]
        path_update_file: PathBuf,
        #[arg(long)]
        receiver_private_file: PathBuf,
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        own_leaf: Option<usize>,
        #[arg(long)]
        derived_out: Option<PathBuf>,
        #[arg(long, default_value_t = false)]
        force: bool,
    },
    JoinFromWelcome {
        #[arg(long = "base-member-keypackage", required = true)]
        base_member_keypackage: Vec<PathBuf>,
        #[arg(long)]
        commit_file: PathBuf,
        #[arg(long)]
        path_update_file: PathBuf,
        #[arg(long)]
        welcome_file: PathBuf,
        #[arg(long)]
        receiver_private_file: PathBuf,
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        own_leaf: Option<usize>,
        #[arg(long)]
        derived_out: Option<PathBuf>,
        #[arg(long, default_value_t = false)]
        force: bool,
    },
    FetchAndApplyLatest {
        #[arg(long)]
        group_state: PathBuf,
        #[arg(long)]
        group_id: Option<String>,
        #[arg(long = "base-member-keypackage")]
        base_member_keypackage: Vec<PathBuf>,
        #[arg(long)]
        own_leaf: Option<usize>,
        #[arg(long)]
        username: Option<String>,
        #[arg(long)]
        receiver_private_file: Option<PathBuf>,
        #[arg(long, default_value_t = 100)]
        limit: usize,
        #[arg(long)]
        derived_out: Option<PathBuf>,
        #[arg(long, default_value_t = false)]
        watch: bool,
        #[arg(long, default_value_t = 2000)]
        poll_interval_ms: u64,
        #[arg(long)]
        max_polls: Option<usize>,
    },
    ShowDerivedSecrets {
        #[arg(long)]
        group_state: PathBuf,
        #[arg(long)]
        epoch: Option<u64>,
        #[arg(long, default_value_t = false)]
        include_root: bool,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    ShowState,
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

#[derive(Debug, Serialize)]
struct RegisterRequest {
    username: String,
    password: String,
    classic_pub_key: String,
    pq_pub_key: String,
    signature: String,
}

#[derive(Debug, Serialize)]
struct LoginRequest {
    username: String,
    password: String,
    signature: String,
}

#[derive(Debug, Serialize)]
struct LogoutRequest {
    username: String,
    session_id: String,
    signature: String,
}

#[derive(Debug, Serialize)]
struct SubmitProposalRequest {
    username: String,
    session_id: String,
    proposal_bytes: String,
    signature: String,
}

#[derive(Debug, Serialize)]
struct SubmitCommitRequest {
    username: String,
    session_id: String,
    commit_bytes: String,
    path_update_bytes: Option<String>,
    welcome_bytes: Option<String>,
    signature: String,
}

#[derive(Debug, Serialize)]
struct SubmitAppMessageRequest {
    username: String,
    session_id: String,
    message_bytes: String,
    signature: String,
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
    kind: String,
    message_bytes: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct ReceiverPrivateFile {
    classic_x25519_private_b64: String,
    pq_kem_seed_b64: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct KemKeygenFile {
    classic_x25519_private_b64: String,
    classic_x25519_public_b64: String,
    pq_kem_seed_b64: String,
    pq_kem_public_b64: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    const CLI_MAIN_STACK_BYTES: usize = 64 * 1024 * 1024;
    let handle = std::thread::Builder::new()
        .name("ds-client-main".to_string())
        .stack_size(CLI_MAIN_STACK_BYTES)
        .spawn(|| run_cli().map_err(|err| err.to_string()))
        .map_err(|err| format!("failed to spawn ds_client main worker: {err}"))?;

    match handle.join() {
        Ok(Ok(())) => Ok(()),
        Ok(Err(err)) => Err(err.into()),
        Err(_) => Err("ds_client main worker panicked".into()),
    }
}

fn run_cli() -> Result<(), Box<dyn std::error::Error>> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async_main())
}

async fn async_main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let client = Client::new();

    match cli.command {
        Commands::Keygen { out, force } => {
            if out.exists() && !force {
                return Err(format!(
                    "output file already exists: {} (use --force to overwrite)",
                    out.display()
                )
                .into());
            }
            let kem_file = generate_kem_keygen_file();
            fs::write(&out, serde_json::to_vec_pretty(&kem_file)?)?;
            println!("generated KEM key material at {}", out.display());
        }
        Commands::KeypackageExport {
            kem_file,
            keypackage_out,
            receiver_private_out,
            force,
        } => {
            if keypackage_out.exists() && !force {
                return Err(format!(
                    "keypackage output already exists: {} (use --force to overwrite)",
                    keypackage_out.display()
                )
                .into());
            }
            if receiver_private_out.exists() && !force {
                return Err(format!(
                    "receiver private output already exists: {} (use --force to overwrite)",
                    receiver_private_out.display()
                )
                .into());
            }

            let state = load_state(&cli.state)?;
            let kem = load_kem_keygen_file(&kem_file)?;
            let init_key = build_hybrid_public_from_kem_file(&kem)?;
            let identity = identity_from_client_state(&state)?;
            let signer = signing_key_from_state(&state)?;
            let signature = signer.sign(&init_key.to_bytes());

            let key_package = KeyPackage {
                identity,
                init_key,
                signature,
            };
            if !key_package.verify() {
                return Err("generated keypackage failed self-verification".into());
            }

            let receiver_private = ReceiverPrivateFile {
                classic_x25519_private_b64: kem.classic_x25519_private_b64.clone(),
                pq_kem_seed_b64: kem.pq_kem_seed_b64.clone(),
            };

            fs::write(&keypackage_out, key_package.encode())?;
            fs::write(
                &receiver_private_out,
                serde_json::to_vec_pretty(&receiver_private)?,
            )?;

            println!(
                "exported keypackage to {} and receiver private material to {}",
                keypackage_out.display(),
                receiver_private_out.display()
            );
        }
        Commands::BootstrapGroupState {
            group_id,
            member_keypackage,
            own_leaf,
            out,
            force,
        } => {
            if out.exists() && !force {
                return Err(format!(
                    "group state output already exists: {} (use --force to overwrite)",
                    out.display()
                )
                .into());
            }
            if member_keypackage.is_empty() {
                return Err("at least one --member-keypackage is required".into());
            }

            let mut leaves = Vec::with_capacity(member_keypackage.len());
            for path in &member_keypackage {
                let key_package = load_keypackage_from_file(path)?;
                leaves.push(leaf_from_keypackage(&key_package));
            }

            let tree = RatchetTree::from_leaves(leaves);
            ensure_leaf_present(&tree, own_leaf)?;

            let state = ClientGroupState::new(group_id.clone(), tree, own_leaf);
            save_group_state(&out, &state)?;

            println!(
                "bootstrapped group state at {} (group={}, members={}, own_leaf={}, epoch={})",
                out.display(),
                group_id,
                member_keypackage.len(),
                own_leaf,
                state.epoch
            );
        }
        Commands::Register {
            username,
            password,
            force,
        } => {
            if cli.state.exists() && !force {
                return Err(format!(
                    "state file already exists: {} (use --force to overwrite)",
                    cli.state.display()
                )
                .into());
            }

            let (mut state, sig_b64) = register_state(&username, &password)?;
            save_state(&cli.state, &state)?;

            let req = RegisterRequest {
                username: username.clone(),
                password: password.clone(),
                classic_pub_key: state.classic_pk_b64.clone(),
                pq_pub_key: state.pq_pk_b64.clone(),
                signature: sig_b64,
            };

            let url = format!("{}/v1/auth/register", cli.base_url);
            let resp = client.post(url).json(&req).send().await?;
            let status = resp.status();
            let body = resp.text().await?;
            println!("{status}\n{body}");
            if !status.is_success() {
                return Err(format!("register failed: {status} {body}").into());
            }

            let priv_key = signing_key_from_state(&state)?;
            let sign_input = login_signing_input(&username, &password);
            let signature = sign_message_b64(&priv_key, &sign_input)?;
            let login_req = LoginRequest {
                username: username.clone(),
                password,
                signature,
            };

            let login_url = format!("{}/v1/auth/login", cli.base_url);
            let login_resp = client.post(login_url).json(&login_req).send().await?;
            let login_status = login_resp.status();
            let login_body = login_resp.text().await?;
            println!("{login_status}\n{login_body}");
            if !login_status.is_success() {
                return Err(format!(
                    "auto-login failed after register: {login_status} {login_body}"
                )
                .into());
            }

            let json: serde_json::Value = serde_json::from_str(&login_body)?;
            let Some(token) = json.get("session_id").and_then(|v| v.as_str()) else {
                return Err("login response missing session_id".into());
            };
            state.session_id = Some(token.to_string());
            save_state(&cli.state, &state)?;
        }
        Commands::Login { username, password } => {
            let mut state = load_state(&cli.state)?;
            let username = resolve_username(username, &state)?;
            if state.username != username {
                return Err("username does not match state".into());
            }

            let priv_key = signing_key_from_state(&state)?;
            let sign_input = login_signing_input(&username, &password);
            let signature = sign_message_b64(&priv_key, &sign_input)?;

            let req = LoginRequest {
                username: username.clone(),
                password,
                signature,
            };

            let url = format!("{}/v1/auth/login", cli.base_url);
            let resp = client.post(url).json(&req).send().await?;
            let status = resp.status();
            let body = resp.text().await?;
            println!("{status}\n{body}");
            if !status.is_success() {
                return Err(format!("login failed: {status} {body}").into());
            }

            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body) {
                if let Some(token) = json.get("session_id").and_then(|v| v.as_str()) {
                    state.session_id = Some(token.to_string());
                    save_state(&cli.state, &state)?;
                }
            }
        }
        Commands::Logout { username } => {
            let mut state = load_state(&cli.state)?;
            let username = resolve_username(username, &state)?;
            let session_id = require_session_id(&state)?;
            let priv_key = signing_key_from_state(&state)?;
            let sign_input = logout_signing_input(&username, &session_id);
            let signature = sign_message_b64(&priv_key, &sign_input)?;
            let req = LogoutRequest {
                username,
                session_id,
                signature,
            };

            let url = format!("{}/v1/auth/logout", cli.base_url);
            let resp = client.post(url).json(&req).send().await?;
            print_response(resp).await?;
            state.session_id = None;
            save_state(&cli.state, &state)?;
        }
        Commands::SubmitProposal {
            username,
            group_id,
            proposal_file,
        } => {
            let state = load_state(&cli.state)?;
            let username = resolve_username(username, &state)?;
            let session_id = require_session_id(&state)?;
            let payload = fs::read(&proposal_file)?;
            let payload_b64 = STANDARD.encode(&payload);

            let priv_key = signing_key_from_state(&state)?;
            let sign_input = proposal_signing_input(&username, &group_id, &payload);
            let signature = sign_message_b64(&priv_key, &sign_input)?;

            let req = SubmitProposalRequest {
                username,
                session_id,
                proposal_bytes: payload_b64,
                signature,
            };

            let url = format!("{}/v1/groups/{}/proposals", cli.base_url, group_id);
            let resp = client.post(url).json(&req).send().await?;
            print_response(resp).await?;
        }
        Commands::SubmitCommit {
            username,
            group_id,
            commit_file,
            path_update_file,
            welcome_file,
        } => {
            let state = load_state(&cli.state)?;
            let username = resolve_username(username, &state)?;
            let session_id = require_session_id(&state)?;
            let commit_payload = fs::read(&commit_file)?;
            let commit_b64 = STANDARD.encode(&commit_payload);
            let path_update_payload = match path_update_file {
                Some(path) => Some(fs::read(path)?),
                None => None,
            };
            let welcome_payload = match welcome_file {
                Some(path) => Some(fs::read(path)?),
                None => None,
            };
            let path_update_b64 = path_update_payload
                .as_ref()
                .map(|bytes| STANDARD.encode(bytes));
            let welcome_b64 = welcome_payload.as_ref().map(|bytes| STANDARD.encode(bytes));

            let priv_key = signing_key_from_state(&state)?;
            let sign_input = commit_signing_input(
                &username,
                &group_id,
                &commit_payload,
                path_update_payload.as_deref(),
                welcome_payload.as_deref(),
            );
            let signature = sign_message_b64(&priv_key, &sign_input)?;

            let req = SubmitCommitRequest {
                username,
                session_id,
                commit_bytes: commit_b64,
                path_update_bytes: path_update_b64,
                welcome_bytes: welcome_b64,
                signature,
            };

            let url = format!("{}/v1/groups/{}/commits", cli.base_url, group_id);
            let resp = client.post(url).json(&req).send().await?;
            print_response(resp).await?;
        }
        Commands::ListMessages {
            username,
            group_id,
            limit,
            kind,
            before_id,
        } => {
            let state = load_state(&cli.state)?;
            let username = resolve_username(username, &state)?;
            let session_id = require_session_id(&state)?;
            let priv_key = signing_key_from_state(&state)?;
            let kind_label = kind.to_lowercase();
            let sign_input =
                list_signing_input(&username, &group_id, limit, &kind_label, before_id);
            let signature = sign_message_b64(&priv_key, &sign_input)?;

            let limit_string = limit.to_string();
            let mut params = vec![
                ("username", username.as_str()),
                ("session_id", session_id.as_str()),
                ("signature", signature.as_str()),
                ("limit", limit_string.as_str()),
                ("kind", kind_label.as_str()),
            ];
            let before_string;
            if let Some(id) = before_id {
                before_string = id.to_string();
                params.push(("before_id", before_string.as_str()));
            }
            let query = serde_urlencoded::to_string(params)?;
            let url = format!("{}/v1/groups/{}/messages?{}", cli.base_url, group_id, query);
            let resp = client.get(url).send().await?;
            print_response(resp).await?;
        }
        Commands::SendAppMessage {
            username,
            group_id,
            message_file,
        } => {
            let state = load_state(&cli.state)?;
            let username = resolve_username(username, &state)?;
            let session_id = require_session_id(&state)?;
            let payload = fs::read(&message_file)?;
            let payload_b64 = STANDARD.encode(&payload);

            let priv_key = signing_key_from_state(&state)?;
            let sign_input = app_publish_signing_input(&username, &group_id, &payload);
            let signature = sign_message_b64(&priv_key, &sign_input)?;

            let req = SubmitAppMessageRequest {
                username,
                session_id,
                message_bytes: payload_b64,
                signature,
            };

            let url = format!("{}/v1/groups/{}/app-messages", cli.base_url, group_id);
            let resp = client.post(url).json(&req).send().await?;
            print_response(resp).await?;
        }
        Commands::ListAppMessages {
            username,
            group_id,
            limit,
            before_id,
        } => {
            let state = load_state(&cli.state)?;
            let username = resolve_username(username, &state)?;
            let session_id = require_session_id(&state)?;
            let priv_key = signing_key_from_state(&state)?;
            let sign_input = app_list_signing_input(&username, &group_id, limit, before_id);
            let signature = sign_message_b64(&priv_key, &sign_input)?;
            let limit_string = limit.to_string();
            let mut params = vec![
                ("username", username.as_str()),
                ("session_id", session_id.as_str()),
                ("signature", signature.as_str()),
                ("limit", limit_string.as_str()),
            ];
            let before_string;
            if let Some(id) = before_id {
                before_string = id.to_string();
                params.push(("before_id", before_string.as_str()));
            }
            let query = serde_urlencoded::to_string(params)?;

            let url = format!(
                "{}/v1/groups/{}/app-messages?{}",
                cli.base_url, group_id, query
            );
            let resp = client.get(url).send().await?;
            print_response(resp).await?;
        }
        Commands::FetchAppMessage {
            username,
            group_id,
            message_id,
            out,
        } => {
            let state = load_state(&cli.state)?;
            let username = resolve_username(username, &state)?;
            let session_id = require_session_id(&state)?;
            let priv_key = signing_key_from_state(&state)?;
            let sign_input = app_fetch_signing_input(&username, &group_id, &message_id);
            let signature = sign_message_b64(&priv_key, &sign_input)?;
            let query = serde_urlencoded::to_string([
                ("username", username.as_str()),
                ("session_id", session_id.as_str()),
                ("signature", signature.as_str()),
            ])?;

            let url = format!(
                "{}/v1/groups/{}/app-messages/{}?{}",
                cli.base_url, group_id, message_id, query
            );
            let resp = client.get(url).send().await?;
            let status = resp.status();
            let body = resp.text().await?;
            println!("{status}\n{body}");
            if !status.is_success() {
                return Err(format!("fetch app message failed: {status} {body}").into());
            }

            if let Some(path) = out {
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body) {
                    if let Some(bytes) = json.get("message_bytes").and_then(|v| v.as_str()) {
                        let decoded = STANDARD.decode(bytes)?;
                        fs::write(path, decoded)?;
                    }
                }
            }
        }
        Commands::PublishKeyPackage {
            username,
            keypackage_file,
        } => {
            let state = load_state(&cli.state)?;
            let username = resolve_username(username, &state)?;
            let session_id = require_session_id(&state)?;
            let payload = fs::read(&keypackage_file)?;
            let payload_b64 = STANDARD.encode(&payload);

            let priv_key = signing_key_from_state(&state)?;
            let sign_input = keypackage_publish_signing_input(&username, &payload);
            let signature = sign_message_b64(&priv_key, &sign_input)?;

            let req = serde_json::json!({
                "username": username,
                "session_id": session_id,
                "keypackage_bytes": payload_b64,
                "signature": signature,
            });

            let url = format!("{}/v1/keypackages", cli.base_url);
            let resp = client.post(url).json(&req).send().await?;
            print_response(resp).await?;
        }
        Commands::FetchKeyPackage {
            username,
            target,
            out,
        } => {
            let state = load_state(&cli.state)?;
            let username = resolve_username(username, &state)?;
            let session_id = require_session_id(&state)?;
            let priv_key = signing_key_from_state(&state)?;
            let sign_input = keypackage_fetch_signing_input(&username, &target);
            let signature = sign_message_b64(&priv_key, &sign_input)?;

            let url = format!("{}/v1/keypackages/{}", cli.base_url, target);
            let resp = client
                .get(url)
                .query(&[
                    ("username", username.as_str()),
                    ("session_id", session_id.as_str()),
                    ("signature", signature.as_str()),
                ])
                .send()
                .await?;
            let status = resp.status();
            let body = resp.text().await?;
            println!("{status}\n{body}");
            if !status.is_success() {
                return Err(format!("fetch keypackage failed: {status} {body}").into());
            }

            if let Some(path) = out {
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body) {
                    if let Some(bytes) = json.get("keypackage_bytes").and_then(|v| v.as_str()) {
                        let decoded = STANDARD.decode(bytes)?;
                        fs::write(path, decoded)?;
                    }
                }
            }
        }
        Commands::CreateAddProposal {
            group_state,
            keypackage_file,
            out,
            sender_leaf,
        } => {
            let mut state = load_group_state(&group_state)?;
            let sender_leaf = resolve_sender_leaf(sender_leaf, &state)?;
            let keypackage = load_keypackage_from_file(&keypackage_file)?;
            let proposal = Proposal::Add(keypackage);
            let envelope = ProposalEnvelope {
                group_id: state.group_id.clone(),
                epoch: state.epoch,
                sender_leaf,
                proposal: proposal.clone(),
            };

            fs::write(&out, envelope.encode())?;
            state.queue_proposal(&proposal);
            save_group_state(&group_state, &state)?;

            println!(
                "created add proposal envelope at {} (group={}, epoch={}, sender_leaf={})",
                out.display(),
                state.group_id,
                state.epoch,
                sender_leaf
            );
        }
        Commands::CreateUpdateProposal {
            group_state,
            keypackage_file,
            out,
            sender_leaf,
            target_leaf,
        } => {
            let mut state = load_group_state(&group_state)?;
            let sender_leaf = resolve_sender_leaf(sender_leaf, &state)?;
            let target_leaf = target_leaf.unwrap_or(sender_leaf);
            ensure_leaf_present(&state.ratchet_tree, target_leaf)?;

            let keypackage = load_keypackage_from_file(&keypackage_file)?;
            let proposal = Proposal::Update {
                leaf_index: target_leaf,
                key_package: keypackage,
            };
            let envelope = ProposalEnvelope {
                group_id: state.group_id.clone(),
                epoch: state.epoch,
                sender_leaf,
                proposal: proposal.clone(),
            };

            fs::write(&out, envelope.encode())?;
            state.queue_proposal(&proposal);
            save_group_state(&group_state, &state)?;

            println!(
                "created update proposal envelope at {} (group={}, epoch={}, sender_leaf={}, target_leaf={})",
                out.display(),
                state.group_id,
                state.epoch,
                sender_leaf,
                target_leaf
            );
        }
        Commands::CreateRemoveProposal {
            group_state,
            remove_leaf,
            out,
            sender_leaf,
        } => {
            let mut state = load_group_state(&group_state)?;
            let sender_leaf = resolve_sender_leaf(sender_leaf, &state)?;
            ensure_leaf_present(&state.ratchet_tree, remove_leaf)?;

            let proposal = Proposal::Remove {
                leaf_index: remove_leaf,
            };
            let envelope = ProposalEnvelope {
                group_id: state.group_id.clone(),
                epoch: state.epoch,
                sender_leaf,
                proposal: proposal.clone(),
            };

            fs::write(&out, envelope.encode())?;
            state.queue_proposal(&proposal);
            save_group_state(&group_state, &state)?;

            println!(
                "created remove proposal envelope at {} (group={}, epoch={}, sender_leaf={}, remove_leaf={})",
                out.display(),
                state.group_id,
                state.epoch,
                sender_leaf,
                remove_leaf
            );
        }
        Commands::CreateCommit {
            group_state,
            commit_out,
            path_update_out,
            welcome_out,
            sender_leaf,
        } => {
            let mut state = load_group_state(&group_state)?;
            let sender_leaf = resolve_sender_leaf(sender_leaf, &state)?;
            let (commit, path_update) = build_commit_from_pending(&state, sender_leaf)?;
            let welcome = build_welcome_for_commit(&state, &commit, &path_update)?;

            let commit_envelope = CommitEnvelope {
                group_id: state.group_id.clone(),
                epoch: state.epoch,
                sender_leaf,
                commit: commit.clone(),
            };
            let path_update_envelope = PathUpdateEnvelope {
                group_id: state.group_id.clone(),
                epoch: state.epoch,
                sender_leaf,
                path_update: path_update.clone(),
            };

            fs::write(&commit_out, commit_envelope.encode())?;
            fs::write(&path_update_out, path_update_envelope.encode())?;
            let welcome_path = if let Some(welcome) = welcome {
                let welcome_bytes = welcome.encode();
                let path = welcome_out.unwrap_or_else(|| default_welcome_out_path(&commit_out));
                fs::write(&path, welcome_bytes)?;
                Some(path)
            } else {
                None
            };

            let commit_context = commit.encode();
            state
                .ratchet_tree
                .apply_commit(&commit)
                .ok_or("failed to apply generated commit to local state")?;
            state.apply_group_context_extensions_from_proposals(&commit.proposals);
            state.clear_pending_proposals();
            state.advance_epoch_with_context(Some(&commit_context));
            ensure_group_state_consistency(&state, "create-commit apply")?;
            save_group_state(&group_state, &state)?;

            println!(
                "created commit envelope at {} and path update envelope at {}{} (group={}, new_epoch={}, sender_leaf={})",
                commit_out.display(),
                path_update_out.display(),
                welcome_path
                    .as_ref()
                    .map(|path| format!(", welcome at {}", path.display()))
                    .unwrap_or_default(),
                state.group_id,
                state.epoch,
                sender_leaf
            );
        }
        Commands::ApplyReceivedCommit {
            group_state,
            commit_file,
            path_update_file,
            receiver_private_file,
            derived_out,
        } => {
            let mut state = load_group_state(&group_state)?;
            let commit_envelope = load_commit_envelope_from_file(&commit_file)?;
            validate_commit_envelope_metadata(&state, &commit_envelope)?;

            let path_update_envelope = match path_update_file.as_ref() {
                Some(path) => {
                    let envelope = load_path_update_envelope_from_file(path)?;
                    validate_path_update_envelope_metadata(&commit_envelope, &envelope)?;
                    Some(envelope)
                }
                None => None,
            };

            if path_update_envelope.is_some() && receiver_private_file.is_none() {
                return Err(
                    "--receiver-private-file is required when --path-update-file is provided"
                        .into(),
                );
            }
            if path_update_envelope.is_none() && receiver_private_file.is_some() {
                return Err(
                    "--path-update-file is required when --receiver-private-file is provided"
                        .into(),
                );
            }

            let derived = if let Some(path_update_envelope) = path_update_envelope {
                let receiver_private = load_receiver_private_from_file(
                    receiver_private_file
                        .as_ref()
                        .expect("receiver_private_file checked above"),
                )?;
                let derived = state
                    .ratchet_tree
                    .apply_commit_with_path_update(
                        &commit_envelope.commit,
                        &path_update_envelope.path_update,
                        state.own_leaf_index,
                        &receiver_private,
                    )
                    .ok_or("failed to apply commit + path update as receiver")?;
                Some(derived)
            } else {
                state
                    .ratchet_tree
                    .apply_commit(&commit_envelope.commit)
                    .ok_or("failed to apply commit")?;
                None
            };

            state.apply_group_context_extensions_from_proposals(&commit_envelope.commit.proposals);

            if let Some(out) = derived_out {
                let json = serialize_derived_path_secrets(&derived);
                fs::write(&out, serde_json::to_vec_pretty(&json)?)?;
            }

            state.clear_pending_proposals();
            let commit_context = commit_envelope.commit.encode();
            state.advance_epoch_with_context(Some(&commit_context));
            ensure_group_state_consistency(&state, "apply-received-commit apply")?;
            save_group_state(&group_state, &state)?;

            println!(
                "applied commit for group={} to local state (new_epoch={}, sender_leaf={}, derived_path_secrets={})",
                state.group_id,
                state.epoch,
                commit_envelope.sender_leaf,
                derived
                    .as_ref()
                    .map(|secrets| secrets.len().to_string())
                    .unwrap_or_else(|| "0".to_string())
            );
        }
        Commands::JoinFromCommit {
            base_member_keypackage,
            commit_file,
            path_update_file,
            receiver_private_file,
            out,
            own_leaf,
            derived_out,
            force,
        } => {
            if out.exists() && !force {
                return Err(format!(
                    "group state output already exists: {} (use --force to overwrite)",
                    out.display()
                )
                .into());
            }
            if base_member_keypackage.is_empty() {
                return Err("at least one --base-member-keypackage is required".into());
            }

            let commit_envelope = load_commit_envelope_from_file(&commit_file)?;
            let path_update_envelope = load_path_update_envelope_from_file(&path_update_file)?;
            let receiver_private = load_receiver_private_from_file(&receiver_private_file)?;
            let (state, derived) = join_from_commit_material(
                &base_member_keypackage,
                &commit_envelope,
                &path_update_envelope,
                &receiver_private,
                own_leaf,
                "join-from-commit apply",
            )?;

            if let Some(path) = derived_out {
                let json = serialize_derived_path_secrets(&Some(derived.clone()));
                fs::write(&path, serde_json::to_vec_pretty(&json)?)?;
            }
            save_group_state(&out, &state)?;

            println!(
                "joined group via commit at {} (group={}, epoch={}, own_leaf={}, derived_path_secrets={})",
                out.display(),
                state.group_id,
                state.epoch,
                state.own_leaf_index,
                derived.len()
            );
        }
        Commands::JoinFromWelcome {
            base_member_keypackage,
            commit_file,
            path_update_file,
            welcome_file,
            receiver_private_file,
            out,
            own_leaf,
            derived_out,
            force,
        } => {
            if out.exists() && !force {
                return Err(format!(
                    "group state output already exists: {} (use --force to overwrite)",
                    out.display()
                )
                .into());
            }
            if base_member_keypackage.is_empty() {
                return Err("at least one --base-member-keypackage is required".into());
            }

            let commit_envelope = load_commit_envelope_from_file(&commit_file)?;
            let path_update_envelope = load_path_update_envelope_from_file(&path_update_file)?;
            let welcome = load_welcome_from_file(&welcome_file)?;
            let receiver_private = load_receiver_private_from_file(&receiver_private_file)?;

            let (state, derived) = join_from_commit_material(
                &base_member_keypackage,
                &commit_envelope,
                &path_update_envelope,
                &receiver_private,
                own_leaf,
                "join-from-welcome apply",
            )?;
            let group_secrets = validate_welcome_for_joiner(
                &welcome,
                &commit_envelope,
                &state,
                &derived,
                &receiver_private,
            )?;

            if let Some(path) = derived_out {
                let mut json = serialize_derived_path_secrets(&Some(derived.clone()));
                if let Some(object) = json.as_object_mut() {
                    object.insert(
                        "joiner_secret_b64".to_string(),
                        serde_json::Value::String(STANDARD.encode(group_secrets.joiner_secret)),
                    );
                    object.insert(
                        "welcome_path_secret_b64".to_string(),
                        group_secrets
                            .path_secret
                            .map(|secret| STANDARD.encode(secret))
                            .map(serde_json::Value::String)
                            .unwrap_or(serde_json::Value::Null),
                    );
                }
                fs::write(&path, serde_json::to_vec_pretty(&json)?)?;
            }
            save_group_state(&out, &state)?;

            println!(
                "joined group via welcome at {} (group={}, epoch={}, own_leaf={}, derived_path_secrets={})",
                out.display(),
                state.group_id,
                state.epoch,
                state.own_leaf_index,
                derived.len()
            );
        }
        Commands::FetchAndApplyLatest {
            group_state,
            group_id,
            base_member_keypackage,
            own_leaf,
            username,
            receiver_private_file,
            limit,
            derived_out,
            watch,
            poll_interval_ms,
            max_polls,
        } => {
            let auth_state = load_state(&cli.state)?;
            let username = resolve_username(username, &auth_state)?;
            let session_id = require_session_id(&auth_state)?;
            let signing_key = signing_key_from_state(&auth_state)?;
            let receiver_private = match receiver_private_file {
                Some(path) => Some(load_receiver_private_from_file(&path)?),
                None => None,
            };
            let mut state_opt = if group_state.exists() {
                Some(load_group_state(&group_state)?)
            } else {
                None
            };
            if state_opt.is_none() {
                if group_id.is_none() {
                    return Err(
                        "--group-id is required when --group-state does not exist (unknown-group Welcome bootstrap)"
                            .into(),
                    );
                }
                if base_member_keypackage.is_empty() {
                    return Err(
                        "at least one --base-member-keypackage is required for unknown-group Welcome bootstrap"
                            .into(),
                    );
                }
                if receiver_private.is_none() {
                    return Err(
                        "--receiver-private-file is required for unknown-group Welcome bootstrap"
                            .into(),
                    );
                }
            }
            let mut polls = 0usize;
            let mut total_applied = 0usize;
            let mut total_skipped = 0usize;
            let mut all_records = Vec::new();

            loop {
                polls = polls.saturating_add(1);

                if state_opt.is_none() {
                    let unknown_group_id = group_id
                        .as_ref()
                        .expect("validated group_id for unknown group");
                    let bootstrap = try_bootstrap_unknown_group_from_welcome_once(
                        &client,
                        &cli.base_url,
                        &username,
                        &session_id,
                        &signing_key,
                        unknown_group_id,
                        &base_member_keypackage,
                        own_leaf,
                        receiver_private
                            .as_ref()
                            .expect("validated receiver private for unknown group"),
                        limit,
                    )
                    .await?;

                    if let Some((state, bootstrap_record)) = bootstrap {
                        println!(
                            "bootstrapped unknown group state via welcome (group={}, epoch={}, own_leaf={})",
                            state.group_id, state.epoch, state.own_leaf_index
                        );
                        save_group_state(&group_state, &state)?;
                        total_applied = total_applied.saturating_add(1);
                        all_records.push(bootstrap_record);
                        state_opt = Some(state);
                    } else if !watch {
                        return Err(format!(
                            "could not bootstrap unknown group '{}' from Welcome stream (no decryptable welcome+commit+path tuple found)",
                            unknown_group_id
                        )
                        .into());
                    }
                }

                let state = match state_opt.as_mut() {
                    Some(state) => state,
                    None => {
                        if let Some(max) = max_polls {
                            if polls >= max {
                                return Err(
                                    "sync finished without local state: no Welcome bootstrap found before max polls"
                                        .into(),
                                );
                            }
                        }
                        std::thread::sleep(std::time::Duration::from_millis(poll_interval_ms));
                        continue;
                    }
                };

                let outcome = fetch_and_apply_latest_once(
                    &client,
                    &cli.base_url,
                    &username,
                    &session_id,
                    &signing_key,
                    state,
                    receiver_private.as_ref(),
                    limit,
                )
                .await?;
                total_applied = total_applied.saturating_add(outcome.applied);
                total_skipped = total_skipped.saturating_add(outcome.skipped);
                all_records.extend(outcome.derived_records);

                if outcome.applied > 0 {
                    save_group_state(&group_state, state)?;
                }

                println!(
                    "sync poll {} complete for group={} (applied={}, skipped={}, local_epoch={})",
                    polls, state.group_id, outcome.applied, outcome.skipped, state.epoch
                );

                if !watch {
                    break;
                }
                if let Some(max) = max_polls {
                    if polls >= max {
                        break;
                    }
                }

                std::thread::sleep(std::time::Duration::from_millis(poll_interval_ms));
            }

            if let Some(path) = derived_out {
                let json = serde_json::json!({ "records": all_records });
                fs::write(path, serde_json::to_vec_pretty(&json)?)?;
            }

            let state = state_opt.ok_or("sync finished without a local group state")?;
            println!(
                "sync finished for group={} (polls={}, applied_total={}, skipped_total={}, local_epoch={})",
                state.group_id, polls, total_applied, total_skipped, state.epoch
            );
        }
        Commands::ShowState => {
            let state = load_state(&cli.state)?;
            let json = serde_json::to_string_pretty(&state)?;
            println!("{json}");
        }
        Commands::ShowDerivedSecrets {
            group_state,
            epoch,
            include_root,
            out,
        } => {
            let state = load_group_state(&group_state)?;
            let target_epoch = epoch.unwrap_or(state.epoch);
            if target_epoch > state.epoch {
                return Err(format!(
                    "requested epoch {} is ahead of local group state epoch {}",
                    target_epoch, state.epoch
                )
                .into());
            }

            let json = epoch_derived_secrets_json(&state, target_epoch, include_root)?;
            if let Some(path) = out {
                fs::write(&path, serde_json::to_vec_pretty(&json)?)?;
                println!(
                    "wrote derived secrets to {} (group={}, epoch={})",
                    path.display(),
                    state.group_id,
                    target_epoch
                );
            } else {
                println!("{}", serde_json::to_string_pretty(&json)?);
            }
        }
    }

    Ok(())
}

fn load_state(path: &Path) -> Result<ClientState, Box<dyn std::error::Error>> {
    let bytes = fs::read(path)?;
    let state = serde_json::from_slice(&bytes)?;
    Ok(state)
}

fn save_state(path: &Path, state: &ClientState) -> Result<(), Box<dyn std::error::Error>> {
    let json = serde_json::to_string_pretty(state)?;
    fs::write(path, json.as_bytes())?;
    Ok(())
}

fn load_group_state(path: &Path) -> Result<ClientGroupState, Box<dyn std::error::Error>> {
    let state = ClientGroupState::load_from_file(path)?;
    state
        .ensure_key_schedule_consistency()
        .map_err(|err| format!("group state consistency check failed: {}", err))?;
    Ok(state)
}

fn save_group_state(
    path: &Path,
    state: &ClientGroupState,
) -> Result<(), Box<dyn std::error::Error>> {
    state
        .ensure_key_schedule_consistency()
        .map_err(|err| format!("refusing to save inconsistent group state: {}", err))?;
    state.save_to_file(path)?;
    Ok(())
}

fn ensure_group_state_consistency(
    state: &ClientGroupState,
    context: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    state.ensure_key_schedule_consistency().map_err(|err| {
        format!(
            "key schedule consistency violation after {}: {}",
            context, err
        )
        .into()
    })
}

fn resolve_sender_leaf(
    explicit: Option<usize>,
    state: &ClientGroupState,
) -> Result<usize, Box<dyn std::error::Error>> {
    let sender_leaf = explicit.unwrap_or(state.own_leaf_index);
    ensure_leaf_present(&state.ratchet_tree, sender_leaf)?;
    Ok(sender_leaf)
}

fn ensure_leaf_present(
    tree: &RatchetTree,
    leaf_index: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    if leaf_index >= tree.leaf_count() {
        return Err(format!("leaf index {leaf_index} is out of bounds").into());
    }
    let node_index = RatchetTree::leaf_to_node_index(leaf_index);
    match tree.nodes.get(node_index) {
        Some(Node::Leaf(_)) => Ok(()),
        _ => Err(format!("leaf index {leaf_index} is blank").into()),
    }
}

fn load_keypackage_from_file(path: &Path) -> Result<KeyPackage, Box<dyn std::error::Error>> {
    let bytes = fs::read(path)?;
    run_with_large_stack("hybrid-keypackage-verify", move || {
        let keypackage = KeyPackage::decode(&bytes)
            .ok_or_else(|| "invalid keypackage file: decode failed".to_string())?;
        if !keypackage.verify() {
            return Err("invalid keypackage file: signature verification failed".to_string());
        }
        Ok(keypackage)
    })
}

fn leaf_from_keypackage(key_package: &KeyPackage) -> LeafNode {
    LeafNode {
        public_key: key_package.init_key.clone(),
        credential: key_package.identity.clone(),
    }
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

fn load_commit_envelope_from_file(
    path: &Path,
) -> Result<CommitEnvelope, Box<dyn std::error::Error>> {
    let bytes = fs::read(path)?;
    CommitEnvelope::decode(&bytes).ok_or_else(|| "invalid commit envelope file".into())
}

fn load_path_update_envelope_from_file(
    path: &Path,
) -> Result<PathUpdateEnvelope, Box<dyn std::error::Error>> {
    let bytes = fs::read(path)?;
    PathUpdateEnvelope::decode(&bytes).ok_or_else(|| "invalid path update envelope file".into())
}

fn load_welcome_from_file(path: &Path) -> Result<Welcome, Box<dyn std::error::Error>> {
    let bytes = fs::read(path)?;
    Welcome::decode(&bytes).ok_or_else(|| "invalid welcome file".into())
}

fn join_from_commit_material(
    base_member_keypackage: &[PathBuf],
    commit_envelope: &CommitEnvelope,
    path_update_envelope: &PathUpdateEnvelope,
    receiver_private: &HybridPrivateKey,
    own_leaf: Option<usize>,
    context_label: &str,
) -> Result<(ClientGroupState, Vec<Option<[u8; 32]>>), Box<dyn std::error::Error>> {
    if commit_envelope.sender_leaf != commit_envelope.commit.sender {
        return Err(format!(
            "commit sender mismatch: envelope.sender_leaf={} commit.sender={}",
            commit_envelope.sender_leaf, commit_envelope.commit.sender
        )
        .into());
    }
    validate_path_update_envelope_metadata(commit_envelope, path_update_envelope)?;

    let mut leaves = Vec::with_capacity(base_member_keypackage.len());
    for path in base_member_keypackage {
        let key_package = load_keypackage_from_file(path)?;
        leaves.push(leaf_from_keypackage(&key_package));
    }
    let tree = RatchetTree::from_leaves(leaves);
    let mut state = ClientGroupState::new(commit_envelope.group_id.clone(), tree, 0);
    state.set_epoch(commit_envelope.epoch);

    state
        .ratchet_tree
        .apply_commit(&commit_envelope.commit)
        .ok_or("failed to apply commit while joining")?;
    state.apply_group_context_extensions_from_proposals(&commit_envelope.commit.proposals);

    let resolved_own_leaf = match own_leaf {
        Some(index) => {
            ensure_leaf_present(&state.ratchet_tree, index)?;
            index
        }
        None => {
            let public = hybrid_public_from_private(receiver_private);
            find_leaf_by_public_key(&state.ratchet_tree, &public)
                .ok_or("could not infer own leaf from receiver private key; use --own-leaf")?
        }
    };
    state.own_leaf_index = resolved_own_leaf;

    let derived = state
        .ratchet_tree
        .process_path_update_for_leaf(
            commit_envelope.commit.sender,
            resolved_own_leaf,
            receiver_private,
            &path_update_envelope.path_update,
        )
        .ok_or("failed to process path update for joiner")?;

    state.clear_pending_proposals();
    let commit_context = commit_envelope.commit.encode();
    state.advance_epoch_with_context(Some(&commit_context));
    ensure_group_state_consistency(&state, context_label)?;

    Ok((state, derived))
}

fn validate_welcome_for_joiner(
    welcome: &Welcome,
    commit_envelope: &CommitEnvelope,
    state: &ClientGroupState,
    derived: &[Option<[u8; 32]>],
    receiver_private: &HybridPrivateKey,
) -> Result<GroupSecrets, Box<dyn std::error::Error>> {
    if welcome.cipher_suite != 0x0001 {
        return Err(format!("unsupported welcome cipher_suite={}", welcome.cipher_suite).into());
    }
    if welcome.secrets.is_empty() {
        return Err("welcome has no encrypted group secrets".into());
    }

    let expected_refs: HashSet<[u8; 32]> = commit_envelope
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
        return Err("join-from-welcome requires an Add commit".into());
    }

    let join_epoch = commit_envelope.epoch.saturating_add(1);
    let mut matched: Option<GroupSecrets> = None;
    for encrypted in &welcome.secrets {
        if !expected_refs.contains(&encrypted.key_package_ref_hash) {
            continue;
        }
        if let Some(group_secrets) =
            encrypted.decrypt_group_secrets(&commit_envelope.group_id, join_epoch, receiver_private)
        {
            matched = Some(group_secrets);
            break;
        }
    }
    let group_secrets = matched.ok_or(
        "welcome does not include decryptable GroupSecrets for this joiner and commit Add set",
    )?;

    if let Some(path_secret) = group_secrets.path_secret {
        let derived_first = derived.first().and_then(|value| *value).ok_or(
            "joiner derived no path secret at index 0 while welcome carried a path_secret",
        )?;
        if path_secret != derived_first {
            return Err("welcome path_secret mismatch against derived path secret".into());
        }
    }

    let chain = state
        .key_schedule
        .chain_secrets_for_epoch(state.epoch)
        .ok_or("missing key schedule chain secrets for current epoch")?;
    if group_secrets.joiner_secret != chain.joiner_secret {
        return Err(
            "welcome GroupSecrets.joiner_secret mismatch against local key schedule chain".into(),
        );
    }

    let group_info_bytes = decrypt_hpke_payload(
        &chain.welcome_secret,
        &welcome_group_info_context(&state.group_id, state.epoch, commit_envelope.commit.sender),
        &welcome.encrypted_group_info,
    )
    .ok_or("failed to decrypt Welcome.encrypted_group_info")?;
    let group_info = GroupInfo::decode(&group_info_bytes)
        .ok_or("failed to decode decrypted Welcome GroupInfo payload")?;
    if group_info.group_id != state.group_id {
        return Err(format!(
            "welcome group_id mismatch: welcome={} state={}",
            group_info.group_id, state.group_id
        )
        .into());
    }
    if group_info.epoch != state.epoch {
        return Err(format!(
            "welcome epoch mismatch: welcome={} state={}",
            group_info.epoch, state.epoch
        )
        .into());
    }
    if group_info.signer_leaf as usize != commit_envelope.commit.sender {
        return Err(format!(
            "welcome signer mismatch: welcome={} commit={}",
            group_info.signer_leaf, commit_envelope.commit.sender
        )
        .into());
    }
    if group_info.confirmed_transcript_hash != state.confirmed_transcript_hash() {
        return Err(
            "welcome GroupInfo confirmed_transcript_hash mismatch against local transcript state"
                .into(),
        );
    }
    let confirmation_key = derive_confirmation_key(&chain.epoch_secret);
    if !verify_confirmation_tag(
        &confirmation_key,
        &group_info.confirmed_transcript_hash,
        &group_info.confirmation_tag,
    ) {
        return Err(
            "welcome GroupInfo confirmation_tag mismatch against transcript+key-schedule state"
                .into(),
        );
    }
    let expected_tree_hash = tree_snapshot_hash(&state.ratchet_tree.encode());
    if group_info.tree_hash != expected_tree_hash {
        return Err("welcome GroupInfo tree_hash mismatch against local reconstructed tree".into());
    }
    if group_info.extensions != state.group_context_extensions {
        return Err(
            "welcome GroupInfo extensions mismatch against local reconstructed group context"
                .into(),
        );
    }

    Ok(group_secrets)
}

fn load_kem_keygen_file(path: &Path) -> Result<KemKeygenFile, Box<dyn std::error::Error>> {
    let bytes = fs::read(path)?;
    let kem: KemKeygenFile = serde_json::from_slice(&bytes)?;
    Ok(kem)
}

fn generate_kem_keygen_file() -> KemKeygenFile {
    let mut rng = OsRng;

    let mut classic_private = [0u8; 32];
    rng.fill_bytes(&mut classic_private);
    let classic_priv = X25519Priv::from(classic_private);
    let classic_pub = X25519Pub::from(&classic_priv);

    let mut pq_seed = [0u8; 64];
    rng.fill_bytes(&mut pq_seed);
    let kyber_priv = KyberPriv::from_seed(Seed::from(pq_seed));
    let kyber_pub = kyber_priv.encapsulation_key().clone();
    let kyber_pub_bytes = kyber_pub.to_bytes();
    let kyber_pub_slice: &[u8] = kyber_pub_bytes.as_ref();

    KemKeygenFile {
        classic_x25519_private_b64: STANDARD.encode(classic_private),
        classic_x25519_public_b64: STANDARD.encode(classic_pub.as_bytes()),
        pq_kem_seed_b64: STANDARD.encode(pq_seed),
        pq_kem_public_b64: STANDARD.encode(kyber_pub_slice),
    }
}

fn build_hybrid_public_from_kem_file(
    kem: &KemKeygenFile,
) -> Result<HybridPublicKey, Box<dyn std::error::Error>> {
    let classic_private = STANDARD.decode(&kem.classic_x25519_private_b64)?;
    if classic_private.len() != 32 {
        return Err("classic_x25519_private_b64 must decode to 32 bytes".into());
    }
    let mut classic_private_arr = [0u8; 32];
    classic_private_arr.copy_from_slice(&classic_private);
    let classic_priv = X25519Priv::from(classic_private_arr);
    let classic_pub = X25519Pub::from(&classic_priv);

    let classic_public = STANDARD.decode(&kem.classic_x25519_public_b64)?;
    if classic_public.len() != 32 {
        return Err("classic_x25519_public_b64 must decode to 32 bytes".into());
    }
    if classic_public.as_slice() != classic_pub.as_bytes() {
        return Err("classic public key does not match provided private key".into());
    }

    let pq_seed = STANDARD.decode(&kem.pq_kem_seed_b64)?;
    if pq_seed.len() != 64 {
        return Err("pq_kem_seed_b64 must decode to 64 bytes".into());
    }
    let mut pq_seed_arr = [0u8; 64];
    pq_seed_arr.copy_from_slice(&pq_seed);
    let kyber_priv = KyberPriv::from_seed(Seed::from(pq_seed_arr));
    let kyber_pub = kyber_priv.encapsulation_key().clone();
    let kyber_pub_bytes = kyber_pub.to_bytes();
    let kyber_pub_slice: &[u8] = kyber_pub_bytes.as_ref();

    let pq_public = STANDARD.decode(&kem.pq_kem_public_b64)?;
    if pq_public.as_slice() != kyber_pub_slice {
        return Err("pq public key does not match provided pq seed".into());
    }

    Ok(HybridPublicKey {
        classic: classic_pub,
        pq: kyber_pub,
    })
}

fn identity_from_client_state(
    state: &ClientState,
) -> Result<hybrid_mls::crypto::HybridSignPubKey, Box<dyn std::error::Error>> {
    let classic = STANDARD.decode(&state.classic_pk_b64)?;
    if classic.len() != 32 {
        return Err("classic public key in state must be 32 bytes".into());
    }
    let mut classic_arr = [0u8; 32];
    classic_arr.copy_from_slice(&classic);
    let classic_pub = EdPublic::from_bytes(&classic_arr)?;

    let pq = STANDARD.decode(&state.pq_pk_b64)?;
    let pq_enc: EncodedVerifyingKey<MlDsa65> = pq
        .as_slice()
        .try_into()
        .map_err(|_| "invalid pq public key in state")?;
    let pq_pub = ml_dsa::VerifyingKey::<MlDsa65>::decode(&pq_enc);

    Ok(hybrid_mls::crypto::HybridSignPubKey {
        classic: classic_pub,
        pq: pq_pub,
    })
}

fn validate_commit_envelope_metadata(
    state: &ClientGroupState,
    envelope: &CommitEnvelope,
) -> Result<(), Box<dyn std::error::Error>> {
    if envelope.group_id != state.group_id {
        return Err(format!(
            "group_id mismatch: state={} envelope={}",
            state.group_id, envelope.group_id
        )
        .into());
    }
    if envelope.epoch != state.epoch {
        return Err(format!(
            "epoch mismatch: state={} envelope={}",
            state.epoch, envelope.epoch
        )
        .into());
    }
    if envelope.sender_leaf != envelope.commit.sender {
        return Err(format!(
            "sender mismatch: envelope.sender_leaf={} commit.sender={}",
            envelope.sender_leaf, envelope.commit.sender
        )
        .into());
    }
    Ok(())
}

fn validate_path_update_envelope_metadata(
    commit: &CommitEnvelope,
    path_update: &PathUpdateEnvelope,
) -> Result<(), Box<dyn std::error::Error>> {
    if path_update.group_id != commit.group_id {
        return Err(format!(
            "path update group_id mismatch: commit={} path={}",
            commit.group_id, path_update.group_id
        )
        .into());
    }
    if path_update.epoch != commit.epoch {
        return Err(format!(
            "path update epoch mismatch: commit={} path={}",
            commit.epoch, path_update.epoch
        )
        .into());
    }
    if path_update.sender_leaf != commit.sender_leaf {
        return Err(format!(
            "path update sender mismatch: commit={} path={}",
            commit.sender_leaf, path_update.sender_leaf
        )
        .into());
    }
    Ok(())
}

fn load_receiver_private_from_file(
    path: &Path,
) -> Result<HybridPrivateKey, Box<dyn std::error::Error>> {
    let bytes = fs::read(path)?;
    let key_file: ReceiverPrivateFile = serde_json::from_slice(&bytes)?;

    let classic_bytes = STANDARD.decode(&key_file.classic_x25519_private_b64)?;
    if classic_bytes.len() != 32 {
        return Err("classic_x25519_private_b64 must decode to 32 bytes".into());
    }
    let mut classic_arr = [0u8; 32];
    classic_arr.copy_from_slice(&classic_bytes);

    let seed_bytes = STANDARD.decode(&key_file.pq_kem_seed_b64)?;
    if seed_bytes.len() != 64 {
        return Err("pq_kem_seed_b64 must decode to 64 bytes".into());
    }
    let mut seed_arr = [0u8; 64];
    seed_arr.copy_from_slice(&seed_bytes);

    Ok(HybridPrivateKey {
        classic: X25519Priv::from(classic_arr),
        pq: KyberPriv::from_seed(Seed::from(seed_arr)),
    })
}

fn serialize_derived_path_secrets(derived: &Option<Vec<Option<[u8; 32]>>>) -> serde_json::Value {
    let list = derived
        .as_ref()
        .map(|levels| {
            levels
                .iter()
                .map(|opt| opt.as_ref().map(|secret| STANDARD.encode(secret)))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    serde_json::json!({ "derived_path_secrets_b64": list })
}

fn epoch_derived_secrets_json(
    state: &ClientGroupState,
    epoch: u64,
    include_root: bool,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let derived = state
        .key_schedule
        .derive_secrets_for_epoch(&state.group_id, epoch)
        .ok_or_else(|| format!("no key-schedule material available for epoch {}", epoch))?;

    let root_secret_b64 = if include_root {
        let root = state
            .key_schedule
            .root_secret_for_epoch(epoch)
            .ok_or_else(|| format!("missing root secret for epoch {}", epoch))?;
        Some(STANDARD.encode(root))
    } else {
        None
    };

    let chain = state
        .key_schedule
        .chain_secrets_for_epoch(epoch)
        .ok_or_else(|| format!("missing chain secrets for epoch {}", epoch))?;

    Ok(serde_json::json!({
        "group_id": state.group_id,
        "epoch": derived.epoch,
        "commit_secret_b64": STANDARD.encode(chain.commit_secret),
        "joiner_secret_b64": STANDARD.encode(chain.joiner_secret),
        "welcome_secret_b64": STANDARD.encode(chain.welcome_secret),
        "epoch_secret_b64": STANDARD.encode(chain.epoch_secret),
        "confirmation_key_b64": STANDARD.encode(derived.confirmation_key),
        "membership_key_b64": STANDARD.encode(derived.membership_key),
        "sender_data_key_b64": STANDARD.encode(derived.sender_data_key),
        "handshake_secret_b64": STANDARD.encode(derived.handshake_secret),
        "application_secret_b64": STANDARD.encode(derived.application_secret),
        "exporter_secret_b64": STANDARD.encode(derived.exporter_secret),
        "root_secret_b64": root_secret_b64,
        "warning": "debug-only output; do not expose in production"
    }))
}

fn build_commit_from_pending(
    state: &ClientGroupState,
    sender_leaf: usize,
) -> Result<(Commit, PathUpdate), Box<dyn std::error::Error>> {
    let proposals = state
        .decoded_pending_proposals()
        .ok_or("failed to decode pending proposals from group state")?;
    if proposals.is_empty() {
        return Err("no pending proposals in group state".into());
    }
    if proposals
        .iter()
        .any(|p| matches!(p, Proposal::Remove { leaf_index } if *leaf_index == sender_leaf))
    {
        return Err("sender leaf cannot remove itself in this command".into());
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

    let direct_path = tree_after_proposals
        .direct_path(sender_leaf)
        .ok_or("failed to compute direct path for sender leaf")?;

    let mut rng = ClientRng(rand::random::<u64>() ^ state.epoch);
    let mut path = Vec::with_capacity(direct_path.len());
    for _ in direct_path {
        path.push(ParentUpdate {
            public_key: generate_hybrid_public_key(&mut rng)?,
            unmerged_leaves: Vec::new(),
        });
    }

    let mut leaf_secret = [0u8; 32];
    rng.try_fill_bytes(&mut leaf_secret)
        .map_err(|_| "failed to generate leaf secret")?;
    let path_update = tree_after_proposals
        .build_path_update(&mut rng, sender_leaf, leaf_secret)
        .ok_or("failed to build path update")?;

    Ok((
        Commit {
            sender: sender_leaf,
            proposals,
            path,
        },
        path_update,
    ))
}

fn default_welcome_out_path(commit_out: &Path) -> PathBuf {
    PathBuf::from(format!("{}.welcome", commit_out.to_string_lossy()))
}

fn build_welcome_for_commit(
    state: &ClientGroupState,
    commit: &Commit,
    path_update: &PathUpdate,
) -> Result<Option<Welcome>, Box<dyn std::error::Error>> {
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
        .ok_or("failed to preview commit tree for welcome generation")?;
    let mut projected_group_context_extensions = state.group_context_extensions.clone();
    for proposal in &commit.proposals {
        if let Proposal::GroupContextExtensions { extensions } = proposal {
            projected_group_context_extensions = extensions.clone();
        }
    }
    let next_epoch = state.epoch.saturating_add(1);
    let commit_context = commit.encode();
    let tree_hash = tree_snapshot_hash(&tree_after_commit.encode());

    let mut key_schedule = state.key_schedule.clone();
    let _ = key_schedule.ensure_epoch(
        next_epoch,
        &state.group_id,
        tree_hash,
        Some(&commit_context),
    );
    let chain = key_schedule
        .chain_secrets_for_epoch(next_epoch)
        .ok_or("missing key-schedule chain secrets for welcome epoch")?;
    let confirmed_transcript_hash =
        state.predict_confirmed_transcript_after_commit(&commit_context);
    let confirmation_key = derive_confirmation_key(&chain.epoch_secret);
    let confirmation_tag = derive_confirmation_tag(&confirmation_key, &confirmed_transcript_hash);
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
            return Err("invalid add proposal key package signature".into());
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

fn apply_proposals_preview(
    tree: &mut RatchetTree,
    proposals: &[Proposal],
) -> Result<(), Box<dyn std::error::Error>> {
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

fn insert_key_package_preview(
    tree: &mut RatchetTree,
    key_package: &KeyPackage,
) -> Result<usize, Box<dyn std::error::Error>> {
    if !key_package.verify() {
        return Err("invalid add proposal key package signature".into());
    }

    let leaf_index = match first_blank_leaf_index(tree) {
        Some(index) => index,
        None => {
            grow_tree_by_one_leaf(tree);
            tree.leaf_count().saturating_sub(1)
        }
    };
    let node_index = RatchetTree::leaf_to_node_index(leaf_index);
    if node_index >= tree.nodes.len() {
        return Err("internal tree indexing error while inserting key package".into());
    }
    tree.nodes[node_index] = Node::Leaf(LeafNode {
        public_key: key_package.init_key.clone(),
        credential: key_package.identity.clone(),
    });
    Ok(leaf_index)
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

fn ensure_leaf_bounds(
    tree: &RatchetTree,
    leaf_index: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    if leaf_index >= tree.leaf_count() {
        return Err(format!("leaf index {leaf_index} is out of bounds").into());
    }
    Ok(())
}

fn generate_hybrid_public_key(
    rng: &mut ClientRng,
) -> Result<HybridPublicKey, Box<dyn std::error::Error>> {
    let mut classic_bytes = [0u8; 32];
    rng.try_fill_bytes(&mut classic_bytes)
        .map_err(|_| "failed to generate classic secret bytes")?;
    let classic_priv = X25519Priv::from(classic_bytes);
    let classic = X25519Pub::from(&classic_priv);

    let mut kem_seed = [0u8; 64];
    rng.try_fill_bytes(&mut kem_seed)
        .map_err(|_| "failed to generate ML-KEM seed bytes")?;
    let kyber_priv = KyberPriv::from_seed(Seed::from(kem_seed));
    let pq = kyber_priv.encapsulation_key().clone();

    Ok(HybridPublicKey { classic, pq })
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

fn resolve_username(
    candidate: Option<String>,
    state: &ClientState,
) -> Result<String, Box<dyn std::error::Error>> {
    Ok(candidate.unwrap_or_else(|| state.username.clone()))
}

const CRYPTO_WORKER_STACK_BYTES: usize = 32 * 1024 * 1024;

fn run_with_large_stack<T, F>(
    worker_name: &'static str,
    f: F,
) -> Result<T, Box<dyn std::error::Error>>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, String> + Send + 'static,
{
    let handle = std::thread::Builder::new()
        .name(worker_name.to_string())
        .stack_size(CRYPTO_WORKER_STACK_BYTES)
        .spawn(f)
        .map_err(|err| format!("failed to spawn {worker_name}: {err}"))?;
    let result = handle
        .join()
        .map_err(|_| format!("{worker_name} panicked"))?;
    result.map_err(|err| err.into())
}

fn sign_message_b64(
    priv_key: &HybridSignPrivKey,
    message: &[u8],
) -> Result<String, Box<dyn std::error::Error>> {
    let signer = priv_key.clone();
    let payload = message.to_vec();
    run_with_large_stack("hybrid-sign", move || {
        let sig = signer.sign(&payload);
        Ok(STANDARD.encode(sig.to_bytes()))
    })
}

fn require_session_id(state: &ClientState) -> Result<String, Box<dyn std::error::Error>> {
    state
        .session_id
        .clone()
        .ok_or_else(|| "missing session_id in state; run login first".into())
}

fn register_state(
    username: &str,
    password: &str,
) -> Result<(ClientState, String), Box<dyn std::error::Error>> {
    let username = username.to_string();
    let password = password.to_string();
    run_with_large_stack("hybrid-register-state", move || {
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

fn signing_key_from_state(
    state: &ClientState,
) -> Result<HybridSignPrivKey, Box<dyn std::error::Error>> {
    let classic_bytes = STANDARD.decode(&state.classic_sk_b64)?;
    if classic_bytes.len() != 32 {
        return Err("classic signing key must be 32 bytes".into());
    }
    let mut secret: EdSecretKey = [0u8; 32];
    secret.copy_from_slice(&classic_bytes);
    let classic_sk = EdSigningKey::from_bytes(&secret);

    let pq_bytes = STANDARD.decode(&state.pq_sk_b64)?;
    let enc: EncodedSigningKey<MlDsa65> = pq_bytes
        .as_slice()
        .try_into()
        .map_err(|_| "invalid pq signing key")?;
    let pq_sk = ml_dsa::SigningKey::<MlDsa65>::decode(&enc);

    Ok(HybridSignPrivKey {
        classic: classic_sk,
        pq: pq_sk,
    })
}

async fn print_response(resp: reqwest::Response) -> Result<(), Box<dyn std::error::Error>> {
    let status = resp.status();
    let body = resp.text().await?;
    println!("{status}\n{body}");
    if !status.is_success() {
        return Err(format!("request failed: {status} {body}").into());
    }
    Ok(())
}

struct SyncOutcome {
    applied: usize,
    skipped: usize,
    derived_records: Vec<serde_json::Value>,
}

async fn fetch_and_apply_latest_once(
    client: &Client,
    base_url: &str,
    username: &str,
    session_id: &str,
    signing_key: &HybridSignPrivKey,
    state: &mut ClientGroupState,
    receiver_private: Option<&HybridPrivateKey>,
    limit: usize,
) -> Result<SyncOutcome, Box<dyn std::error::Error>> {
    let commit_summaries = ds_list_messages(
        client,
        base_url,
        username,
        session_id,
        signing_key,
        &state.group_id,
        limit,
        "commit",
        None,
    )
    .await?;
    let path_summaries = ds_list_messages(
        client,
        base_url,
        username,
        session_id,
        signing_key,
        &state.group_id,
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
            derived_records: Vec::new(),
        });
    }
    let path_ids = extract_sorted_unique_message_ids(&path_summaries.messages);

    let mut applied = 0usize;
    let mut skipped = 0usize;
    let mut derived_records = Vec::new();

    for (idx, commit_id) in commit_ids.iter().enumerate() {
        if state.has_applied_commit_id(*commit_id) {
            skipped += 1;
            continue;
        }

        let next_commit = commit_ids.get(idx + 1).copied();
        let fetched_commit = ds_fetch_group_message(
            client,
            base_url,
            username,
            session_id,
            signing_key,
            &state.group_id,
            *commit_id,
        )
        .await?;
        if fetched_commit.kind != "commit" {
            skipped += 1;
            continue;
        }
        let commit_bytes = STANDARD.decode(&fetched_commit.message_bytes)?;
        let commit_env = match CommitEnvelope::decode(&commit_bytes) {
            Some(v) => v,
            None => {
                skipped += 1;
                continue;
            }
        };

        if commit_env.group_id != state.group_id {
            skipped += 1;
            continue;
        }
        if commit_env.epoch > state.epoch {
            println!(
                "stopping sync at commit_id={} due to epoch gap (local_epoch={}, commit_epoch={})",
                commit_id, state.epoch, commit_env.epoch
            );
            break;
        }
        if let Err(err) = validate_commit_envelope_metadata(state, &commit_env) {
            println!(
                "skipping commit_id={} due to metadata error: {}",
                commit_id, err
            );
            skipped += 1;
            continue;
        }
        let mut derived_for_commit: Option<Vec<Option<[u8; 32]>>> = None;

        if let Some(receiver_private) = receiver_private {
            let mut matched_path_update: Option<(i64, PathUpdateEnvelope)> = None;
            let candidate_path_ids = candidate_path_update_ids(*commit_id, next_commit, &path_ids);

            for path_id in candidate_path_ids {
                let fetched_path = ds_fetch_group_message(
                    client,
                    base_url,
                    username,
                    session_id,
                    signing_key,
                    &state.group_id,
                    path_id,
                )
                .await?;
                if fetched_path.kind != "path_update" {
                    continue;
                }
                let path_bytes = STANDARD.decode(&fetched_path.message_bytes)?;
                let Some(path_env) = PathUpdateEnvelope::decode(&path_bytes) else {
                    continue;
                };
                if validate_path_update_envelope_metadata(&commit_env, &path_env).is_ok() {
                    matched_path_update = Some((path_id, path_env));
                    break;
                }
            }

            if let Some((path_id, path_env)) = matched_path_update {
                let derived = state
                    .ratchet_tree
                    .apply_commit_with_path_update(
                        &commit_env.commit,
                        &path_env.path_update,
                        state.own_leaf_index,
                        receiver_private,
                    )
                    .ok_or("failed to apply commit+path update during sync")?;
                derived_for_commit = Some(derived);
                println!(
                    "applied commit_id={} with matched path_update_id={}",
                    commit_id, path_id
                );
            } else {
                return Err(format!(
                    "strict receiver policy: missing or mismatched path_update for commit_id={} (group={}, epoch={}, sender_leaf={})",
                    commit_id, commit_env.group_id, commit_env.epoch, commit_env.sender_leaf
                )
                .into());
            }
        } else {
            state
                .ratchet_tree
                .apply_commit(&commit_env.commit)
                .ok_or("failed to apply commit during sync")?;
        }
        state.apply_group_context_extensions_from_proposals(&commit_env.commit.proposals);

        state.clear_pending_proposals();
        state.advance_epoch_with_context(Some(&commit_bytes));
        ensure_group_state_consistency(state, "fetch-and-apply-latest commit apply")?;
        state.mark_applied_commit_id(*commit_id);
        applied += 1;

        if let Some(derived) = derived_for_commit {
            derived_records.push(serde_json::json!({
                "commit_id": commit_id,
                "derived_path_secrets_b64": derived
                    .iter()
                    .map(|opt| opt.as_ref().map(|secret| STANDARD.encode(secret)))
                    .collect::<Vec<_>>(),
            }));
        }
    }

    Ok(SyncOutcome {
        applied,
        skipped,
        derived_records,
    })
}

async fn try_bootstrap_unknown_group_from_welcome_once(
    client: &Client,
    base_url: &str,
    username: &str,
    session_id: &str,
    signing_key: &HybridSignPrivKey,
    group_id: &str,
    base_member_keypackage: &[PathBuf],
    own_leaf: Option<usize>,
    receiver_private: &HybridPrivateKey,
    limit: usize,
) -> Result<Option<(ClientGroupState, serde_json::Value)>, Box<dyn std::error::Error>> {
    let commit_summaries = ds_list_messages(
        client,
        base_url,
        username,
        session_id,
        signing_key,
        group_id,
        limit,
        "commit",
        None,
    )
    .await?;
    let path_summaries = ds_list_messages(
        client,
        base_url,
        username,
        session_id,
        signing_key,
        group_id,
        limit,
        "path_update",
        None,
    )
    .await?;
    let welcome_summaries = ds_list_messages(
        client,
        base_url,
        username,
        session_id,
        signing_key,
        group_id,
        limit,
        "welcome",
        None,
    )
    .await?;

    let commit_ids = extract_sorted_unique_message_ids(&commit_summaries.messages);
    let path_ids = extract_sorted_unique_message_ids(&path_summaries.messages);
    let mut welcome_ids = extract_sorted_unique_message_ids(&welcome_summaries.messages);
    if commit_ids.is_empty() || path_ids.is_empty() || welcome_ids.is_empty() {
        return Ok(None);
    }
    welcome_ids.reverse();

    for welcome_id in welcome_ids {
        let fetched_welcome = ds_fetch_group_message(
            client,
            base_url,
            username,
            session_id,
            signing_key,
            group_id,
            welcome_id,
        )
        .await?;
        if fetched_welcome.kind != "welcome" {
            continue;
        }
        let welcome_bytes = match STANDARD.decode(&fetched_welcome.message_bytes) {
            Ok(value) => value,
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
        let next_commit_id = commit_ids.get(commit_pos + 1).copied();

        let fetched_commit = ds_fetch_group_message(
            client,
            base_url,
            username,
            session_id,
            signing_key,
            group_id,
            commit_id,
        )
        .await?;
        if fetched_commit.kind != "commit" {
            continue;
        }
        let commit_bytes = match STANDARD.decode(&fetched_commit.message_bytes) {
            Ok(value) => value,
            Err(_) => continue,
        };
        let Some(commit_env) = CommitEnvelope::decode(&commit_bytes) else {
            continue;
        };
        if commit_env.group_id != group_id {
            continue;
        }

        let candidate_path_ids = candidate_path_update_ids(commit_id, next_commit_id, &path_ids);
        for path_id in candidate_path_ids {
            let fetched_path = ds_fetch_group_message(
                client,
                base_url,
                username,
                session_id,
                signing_key,
                group_id,
                path_id,
            )
            .await?;
            if fetched_path.kind != "path_update" {
                continue;
            }
            let path_bytes = match STANDARD.decode(&fetched_path.message_bytes) {
                Ok(value) => value,
                Err(_) => continue,
            };
            let Some(path_env) = PathUpdateEnvelope::decode(&path_bytes) else {
                continue;
            };

            let (mut state, derived) = match join_from_commit_material(
                base_member_keypackage,
                &commit_env,
                &path_env,
                receiver_private,
                own_leaf,
                "fetch-and-apply-latest welcome bootstrap",
            ) {
                Ok(value) => value,
                Err(_) => continue,
            };
            let group_secrets = match validate_welcome_for_joiner(
                &welcome,
                &commit_env,
                &state,
                &derived,
                receiver_private,
            ) {
                Ok(value) => value,
                Err(_) => continue,
            };
            state.mark_applied_commit_id(commit_id);

            return Ok(Some((
                state,
                serde_json::json!({
                    "kind": "welcome_bootstrap",
                    "commit_id": commit_id,
                    "welcome_id": welcome_id,
                    "joiner_secret_b64": STANDARD.encode(group_secrets.joiner_secret),
                    "welcome_path_secret_b64": group_secrets.path_secret.map(|secret| STANDARD.encode(secret)),
                    "derived_path_secrets_b64": derived
                        .iter()
                        .map(|opt| opt.as_ref().map(|secret| STANDARD.encode(secret)))
                        .collect::<Vec<_>>(),
                }),
            )));
        }
    }

    Ok(None)
}

async fn ds_list_messages(
    client: &Client,
    base_url: &str,
    username: &str,
    session_id: &str,
    signing_key: &HybridSignPrivKey,
    group_id: &str,
    limit: usize,
    kind: &str,
    before_id: Option<i64>,
) -> Result<DsListMessagesResponse, Box<dyn std::error::Error>> {
    let sign_input = list_signing_input(username, group_id, limit, kind, before_id);
    let signature = sign_message_b64(signing_key, &sign_input)?;
    let limit_string = limit.to_string();
    let mut params = vec![
        ("username", username.to_string()),
        ("session_id", session_id.to_string()),
        ("signature", signature),
        ("limit", limit_string),
        ("kind", kind.to_string()),
    ];
    if let Some(id) = before_id {
        params.push(("before_id", id.to_string()));
    }
    let query = serde_urlencoded::to_string(params)?;
    let url = format!("{}/v1/groups/{}/messages?{}", base_url, group_id, query);
    let resp = client.get(url).send().await?;
    let status = resp.status();
    let body = resp.text().await?;
    if !status.is_success() {
        return Err(format!("list messages failed: {status} {body}").into());
    }
    Ok(serde_json::from_str(&body)?)
}

async fn ds_fetch_group_message(
    client: &Client,
    base_url: &str,
    username: &str,
    session_id: &str,
    signing_key: &HybridSignPrivKey,
    group_id: &str,
    message_id: i64,
) -> Result<DsFetchGroupMessageResponse, Box<dyn std::error::Error>> {
    let sign_input = fetch_message_signing_input(username, group_id, message_id);
    let signature = sign_message_b64(signing_key, &sign_input)?;
    let query = serde_urlencoded::to_string([
        ("username", username.to_string()),
        ("session_id", session_id.to_string()),
        ("signature", signature),
    ])?;
    let url = format!(
        "{}/v1/groups/{}/messages/{}?{}",
        base_url, group_id, message_id, query
    );
    let resp = client.get(url).send().await?;
    let status = resp.status();
    let body = resp.text().await?;
    if !status.is_success() {
        return Err(format!("fetch message failed: {status} {body}").into());
    }
    Ok(serde_json::from_str(&body)?)
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

fn app_fetch_signing_input(username: &str, group_id: &str, message_id: &str) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"app_fetch|");
    out.extend_from_slice(username.as_bytes());
    out.extend_from_slice(b"|");
    out.extend_from_slice(group_id.as_bytes());
    out.extend_from_slice(b"|");
    out.extend_from_slice(message_id.as_bytes());
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

#[cfg(test)]
mod tests {
    use super::*;
    use hybrid_mls::crypto::{HybridSignPrivKey, HybridSignPubKey, KyberPriv};
    use hybrid_mls::tree::RatchetTree;
    use hybrid_mls::tree::{LeafNode, Proposal};
    use ml_dsa::{KeyGen, MlDsa65};
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    fn hex(bytes: &[u8; 32]) -> String {
        bytes
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    }

    fn test_member(seed: u8) -> (KeyPackage, HybridPrivateKey) {
        let classic_priv = X25519Priv::from([seed; 32]);
        let classic_pub = X25519Pub::from(&classic_priv);

        let kem_seed = Seed::from([seed.wrapping_add(1); 64]);
        let pq_priv = KyberPriv::from_seed(kem_seed);
        let pq_pub = pq_priv.encapsulation_key().clone();

        let sign_classic = EdSigningKey::from_bytes(&[seed.wrapping_add(2); 32]);
        let mut dsa_rng = StdRng::seed_from_u64(seed as u64 + 777);
        let sign_pair = MlDsa65::key_gen(&mut dsa_rng);

        let identity = HybridSignPubKey {
            classic: EdPublic::from(&sign_classic),
            pq: sign_pair.verifying_key().clone(),
        };
        let signer = HybridSignPrivKey {
            classic: sign_classic,
            pq: sign_pair.signing_key().clone(),
        };
        let init_key = HybridPublicKey {
            classic: classic_pub,
            pq: pq_pub,
        };

        let kp = KeyPackage {
            identity,
            init_key: init_key.clone(),
            signature: signer.sign(&init_key.to_bytes()),
        };
        let priv_key = HybridPrivateKey {
            classic: classic_priv,
            pq: pq_priv,
        };

        (kp, priv_key)
    }

    #[test]
    fn extract_sorted_unique_message_ids_sorts_dedups_and_skips_invalid() {
        let messages = vec![
            DsMessageSummary {
                id: "10".to_string(),
            },
            DsMessageSummary {
                id: "3".to_string(),
            },
            DsMessageSummary {
                id: "10".to_string(),
            },
            DsMessageSummary {
                id: "oops".to_string(),
            },
            DsMessageSummary {
                id: "7".to_string(),
            },
        ];

        let ids = extract_sorted_unique_message_ids(&messages);
        assert_eq!(ids, vec![3, 7, 10]);
    }

    #[test]
    fn candidate_path_update_ids_respects_commit_boundaries() {
        let paths = vec![1, 2, 3, 5, 8, 13, 21];
        let selected = candidate_path_update_ids(5, Some(13), &paths);
        assert_eq!(selected, vec![8]);

        let selected_to_end = candidate_path_update_ids(13, None, &paths);
        assert_eq!(selected_to_end, vec![21]);
    }

    #[test]
    fn validate_commit_envelope_metadata_rejects_sender_mismatch() {
        let mut state = ClientGroupState::new("group-a", RatchetTree::new(1), 0);
        state.set_epoch(4);

        let envelope = CommitEnvelope {
            group_id: "group-a".to_string(),
            epoch: 4,
            sender_leaf: 0,
            commit: Commit {
                sender: 1,
                proposals: Vec::new(),
                path: Vec::new(),
            },
        };

        assert!(validate_commit_envelope_metadata(&state, &envelope).is_err());
    }

    #[test]
    fn validate_path_update_envelope_metadata_rejects_epoch_mismatch() {
        let commit = CommitEnvelope {
            group_id: "group-a".to_string(),
            epoch: 5,
            sender_leaf: 0,
            commit: Commit {
                sender: 0,
                proposals: Vec::new(),
                path: Vec::new(),
            },
        };
        let path = PathUpdateEnvelope {
            group_id: "group-a".to_string(),
            epoch: 6,
            sender_leaf: 0,
            path_update: PathUpdate {
                path_secrets: Vec::new(),
                ciphertexts: Vec::new(),
            },
        };

        assert!(validate_path_update_envelope_metadata(&commit, &path).is_err());
    }

    #[test]
    fn validate_path_update_envelope_metadata_rejects_group_mismatch() {
        let commit = CommitEnvelope {
            group_id: "group-a".to_string(),
            epoch: 5,
            sender_leaf: 0,
            commit: Commit {
                sender: 0,
                proposals: Vec::new(),
                path: Vec::new(),
            },
        };
        let path = PathUpdateEnvelope {
            group_id: "group-b".to_string(),
            epoch: 5,
            sender_leaf: 0,
            path_update: PathUpdate {
                path_secrets: Vec::new(),
                ciphertexts: Vec::new(),
            },
        };

        assert!(validate_path_update_envelope_metadata(&commit, &path).is_err());
    }

    #[test]
    fn validate_path_update_envelope_metadata_rejects_sender_mismatch() {
        let commit = CommitEnvelope {
            group_id: "group-a".to_string(),
            epoch: 5,
            sender_leaf: 1,
            commit: Commit {
                sender: 1,
                proposals: Vec::new(),
                path: Vec::new(),
            },
        };
        let path = PathUpdateEnvelope {
            group_id: "group-a".to_string(),
            epoch: 5,
            sender_leaf: 0,
            path_update: PathUpdate {
                path_secrets: Vec::new(),
                ciphertexts: Vec::new(),
            },
        };

        assert!(validate_path_update_envelope_metadata(&commit, &path).is_err());
    }

    #[test]
    fn epoch_derived_secrets_json_includes_expected_fields() {
        let state = ClientGroupState::new("group-debug", RatchetTree::new(1), 0);
        let json = epoch_derived_secrets_json(&state, 0, true).expect("derive json for epoch 0");

        assert_eq!(json["group_id"].as_str(), Some("group-debug"));
        assert_eq!(json["epoch"].as_u64(), Some(0));
        assert!(json["commit_secret_b64"].as_str().is_some());
        assert!(json["joiner_secret_b64"].as_str().is_some());
        assert!(json["welcome_secret_b64"].as_str().is_some());
        assert!(json["epoch_secret_b64"].as_str().is_some());
        assert!(json["confirmation_key_b64"].as_str().is_some());
        assert!(json["membership_key_b64"].as_str().is_some());
        assert!(json["sender_data_key_b64"].as_str().is_some());
        assert!(json["handshake_secret_b64"].as_str().is_some());
        assert!(json["application_secret_b64"].as_str().is_some());
        assert!(json["exporter_secret_b64"].as_str().is_some());
        assert!(json["root_secret_b64"].as_str().is_some());
    }

    #[test]
    fn epoch_derived_secrets_json_hides_root_when_not_requested() {
        let state = ClientGroupState::new("group-debug", RatchetTree::new(1), 0);
        let json = epoch_derived_secrets_json(&state, 0, false).expect("derive json without root");

        assert!(json["root_secret_b64"].is_null());
    }

    #[test]
    fn ensure_group_state_consistency_rejects_epoch_mismatch() {
        let mut state = ClientGroupState::new("group-check", RatchetTree::new(1), 0);
        state.set_epoch(2);
        state.key_schedule.current_epoch = 1;

        let result = ensure_group_state_consistency(&state, "unit test");
        assert!(result.is_err());
    }

    #[test]
    fn build_welcome_for_commit_returns_none_when_no_add_proposals() {
        let (member_a, _) = test_member(1);
        let (member_b, _) = test_member(2);
        let (member_a_updated, _) = test_member(3);
        let tree = RatchetTree::from_leaves(vec![
            LeafNode {
                public_key: member_a.init_key.clone(),
                credential: member_a.identity.clone(),
            },
            LeafNode {
                public_key: member_b.init_key.clone(),
                credential: member_b.identity.clone(),
            },
        ]);
        let mut state = ClientGroupState::new("group-no-add", tree, 0);
        state.queue_proposal(&Proposal::Update {
            leaf_index: 0,
            key_package: member_a_updated,
        });

        let (commit, path_update) = build_commit_from_pending(&state, 0).expect("build commit");
        let welcome =
            build_welcome_for_commit(&state, &commit, &path_update).expect("welcome generation");
        assert!(welcome.is_none());
    }

    #[test]
    fn build_welcome_for_commit_encrypts_group_secrets_for_added_member() {
        let (member_a, _) = test_member(10);
        let (member_b, member_b_priv) = test_member(11);
        let tree = RatchetTree::from_leaves(vec![leaf_from_keypackage(&member_a)]);
        let mut state = ClientGroupState::new("group-add", tree, 0);
        state.queue_proposal(&Proposal::Add(member_b.clone()));

        let (commit, path_update) = build_commit_from_pending(&state, 0).expect("build commit");
        let welcome = build_welcome_for_commit(&state, &commit, &path_update)
            .expect("welcome generation")
            .expect("welcome must exist for add proposal");

        assert_eq!(welcome.secrets.len(), 1);
        assert!(!welcome.encrypted_group_info.is_empty());
        let key_ref_hash = hash32_with_label(b"WELCOME-KEYPACKAGE-REF", &[&member_b.encode()]);
        let encrypted = &welcome.secrets[0];
        assert_eq!(encrypted.key_package_ref_hash, key_ref_hash);

        let group_secrets = encrypted
            .decrypt_group_secrets("group-add", state.epoch + 1, &member_b_priv)
            .expect("decrypt group secrets");
        assert_eq!(
            group_secrets.path_secret,
            path_update.path_secrets.first().copied()
        );
        let mut tree_after_commit = state.ratchet_tree.clone();
        tree_after_commit
            .apply_commit(&commit)
            .expect("apply commit for joiner secret check");
        let mut key_schedule = state.key_schedule.clone();
        let _ = key_schedule.ensure_epoch(
            state.epoch + 1,
            &state.group_id,
            tree_snapshot_hash(&tree_after_commit.encode()),
            Some(&commit.encode()),
        );
        let chain = key_schedule
            .chain_secrets_for_epoch(state.epoch + 1)
            .expect("chain secrets");
        assert_eq!(group_secrets.joiner_secret, chain.joiner_secret);
    }

    #[test]
    fn build_welcome_for_commit_sets_verifiable_confirmation_tag() {
        let (member_a, _) = test_member(41);
        let (member_b, _) = test_member(42);
        let tree = RatchetTree::from_leaves(vec![leaf_from_keypackage(&member_a)]);
        let mut state = ClientGroupState::new("group-confirmation", tree, 0);
        state.queue_proposal(&Proposal::Add(member_b));

        let (commit, path_update) = build_commit_from_pending(&state, 0).expect("build commit");
        let welcome = build_welcome_for_commit(&state, &commit, &path_update)
            .expect("welcome generation")
            .expect("welcome present");

        let mut tree_after_commit = state.ratchet_tree.clone();
        tree_after_commit
            .apply_commit(&commit)
            .expect("apply commit for welcome verification");
        let next_epoch = state.epoch + 1;
        let commit_context = commit.encode();
        let tree_hash = tree_snapshot_hash(&tree_after_commit.encode());
        let mut key_schedule = state.key_schedule.clone();
        let _ = key_schedule.ensure_epoch(
            next_epoch,
            &state.group_id,
            tree_hash,
            Some(&commit_context),
        );
        let chain = key_schedule
            .chain_secrets_for_epoch(next_epoch)
            .expect("chain secrets");
        let group_info_bytes = decrypt_hpke_payload(
            &chain.welcome_secret,
            &welcome_group_info_context(&state.group_id, next_epoch, commit.sender),
            &welcome.encrypted_group_info,
        )
        .expect("decrypt group info");
        let group_info = GroupInfo::decode(&group_info_bytes).expect("decode group info");
        let confirmation_key = derive_confirmation_key(&chain.epoch_secret);
        assert!(verify_confirmation_tag(
            &confirmation_key,
            &group_info.confirmed_transcript_hash,
            &group_info.confirmation_tag
        ));
    }

    #[test]
    fn validate_welcome_for_joiner_rejects_bad_confirmation_tag() {
        let (member_a, _) = test_member(51);
        let (member_b, member_b_priv) = test_member(52);
        let tree = RatchetTree::from_leaves(vec![leaf_from_keypackage(&member_a)]);
        let mut sender_state = ClientGroupState::new("group-bad-confirmation", tree, 0);
        sender_state.queue_proposal(&Proposal::Add(member_b.clone()));

        let (commit, path_update) =
            build_commit_from_pending(&sender_state, 0).expect("build commit");
        let commit_env = CommitEnvelope {
            group_id: sender_state.group_id.clone(),
            epoch: sender_state.epoch,
            sender_leaf: 0,
            commit: commit.clone(),
        };
        let path_env = PathUpdateEnvelope {
            group_id: sender_state.group_id.clone(),
            epoch: sender_state.epoch,
            sender_leaf: 0,
            path_update: path_update.clone(),
        };
        let mut welcome = build_welcome_for_commit(&sender_state, &commit, &path_update)
            .expect("welcome generation")
            .expect("welcome present");

        let mut tree_after_commit = sender_state.ratchet_tree.clone();
        tree_after_commit
            .apply_commit(&commit)
            .expect("apply commit for welcome tamper");
        let next_epoch = sender_state.epoch + 1;
        let commit_context = commit.encode();
        let tree_hash = tree_snapshot_hash(&tree_after_commit.encode());
        let mut key_schedule = sender_state.key_schedule.clone();
        let _ = key_schedule.ensure_epoch(
            next_epoch,
            &sender_state.group_id,
            tree_hash,
            Some(&commit_context),
        );
        let chain = key_schedule
            .chain_secrets_for_epoch(next_epoch)
            .expect("chain secrets");
        let mut group_info = GroupInfo::decode(
            &decrypt_hpke_payload(
                &chain.welcome_secret,
                &welcome_group_info_context(&sender_state.group_id, next_epoch, commit.sender),
                &welcome.encrypted_group_info,
            )
            .expect("decrypt group info"),
        )
        .expect("decode group info");
        group_info.confirmation_tag[0] ^= 0x01;
        welcome.encrypted_group_info = encrypt_hpke_payload(
            &chain.welcome_secret,
            &welcome_group_info_context(&sender_state.group_id, next_epoch, commit.sender),
            &group_info.encode(),
        );

        let tree = RatchetTree::from_leaves(vec![leaf_from_keypackage(&member_a)]);
        let mut join_state = ClientGroupState::new(sender_state.group_id.clone(), tree, 0);
        join_state.set_epoch(commit_env.epoch);
        join_state
            .ratchet_tree
            .apply_commit(&commit_env.commit)
            .expect("apply commit on join side");
        let own_leaf = find_leaf_by_public_key(
            &join_state.ratchet_tree,
            &hybrid_public_from_private(&member_b_priv),
        )
        .expect("find joiner leaf");
        join_state.own_leaf_index = own_leaf;
        let derived = join_state
            .ratchet_tree
            .process_path_update_for_leaf(
                commit_env.commit.sender,
                own_leaf,
                &member_b_priv,
                &path_env.path_update,
            )
            .expect("process path update");
        join_state.clear_pending_proposals();
        join_state.advance_epoch_with_context(Some(&commit_context));

        let err = validate_welcome_for_joiner(
            &welcome,
            &commit_env,
            &join_state,
            &derived,
            &member_b_priv,
        )
        .expect_err("confirmation mismatch should fail");
        assert!(err.to_string().contains("confirmation_tag mismatch"));
    }

    #[test]
    fn deterministic_vector_welcome_joiner_secret_matches_expected() {
        let (member_a, _) = test_member(30);
        let (member_b, member_b_priv) = test_member(31);
        let tree = RatchetTree::from_leaves(vec![leaf_from_keypackage(&member_a)]);
        let state = ClientGroupState::new("vector-welcome-group", tree, 0);

        let proposals = vec![Proposal::Add(member_b.clone())];
        let mut tree_after_proposals = state.ratchet_tree.clone();
        apply_proposals_preview(&mut tree_after_proposals, &proposals).expect("apply proposals");
        ensure_leaf_present(&tree_after_proposals, 0).expect("sender leaf present");
        let direct_path = tree_after_proposals
            .direct_path(0)
            .expect("direct path for sender");

        let mut rng = ClientRng(0xdecafbad_u64);
        let mut path = Vec::with_capacity(direct_path.len());
        for _ in direct_path {
            path.push(ParentUpdate {
                public_key: generate_hybrid_public_key(&mut rng).expect("deterministic public key"),
                unmerged_leaves: Vec::new(),
            });
        }
        let mut leaf_secret = [0u8; 32];
        rng.try_fill_bytes(&mut leaf_secret)
            .expect("deterministic leaf secret");
        let path_update = tree_after_proposals
            .build_path_update(&mut rng, 0, leaf_secret)
            .expect("path update");

        let commit = Commit {
            sender: 0,
            proposals,
            path,
        };

        let welcome = build_welcome_for_commit(&state, &commit, &path_update)
            .expect("welcome generation")
            .expect("welcome should exist");
        assert_eq!(welcome.secrets.len(), 1);
        let key_ref_hash = hash32_with_label(b"WELCOME-KEYPACKAGE-REF", &[&member_b.encode()]);
        let group_secrets = welcome.secrets[0]
            .decrypt_group_secrets("vector-welcome-group", 1, &member_b_priv)
            .expect("decrypt group secrets");
        assert_eq!(welcome.secrets[0].key_package_ref_hash, key_ref_hash);
        assert_eq!(
            group_secrets.path_secret,
            path_update.path_secrets.first().copied()
        );
        assert_eq!(
            hex(&group_secrets.joiner_secret),
            "f43b10bfa477e02ec6f8eda342c2da5291bf5dad1a570b0ba489b421c20fbac7"
        );
    }
}
