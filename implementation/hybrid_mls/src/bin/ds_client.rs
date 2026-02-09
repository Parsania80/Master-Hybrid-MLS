use std::fs;
use std::path::{Path, PathBuf};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use clap::{Parser, Subcommand};
use ed25519_dalek::{SecretKey as EdSecretKey, SigningKey as EdSigningKey};
use ml_dsa::{EncodedSigningKey, KeyGen, MlDsa65};
use rand::rngs::OsRng;
use rand::RngCore;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_urlencoded;
use sha3::{Digest, Sha3_256};

use hybrid_mls::crypto::{HybridSignPrivKey, HybridSignature};

#[derive(Parser, Debug)]
#[command(name = "ds-client", version, about = "Hybrid MLS Delivery Service client")]
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
struct SubmitProposalRequest {
    username: String,
    proposal_bytes: String,
    signature: String,
}

#[derive(Debug, Serialize)]
struct SubmitCommitRequest {
    username: String,
    commit_bytes: String,
    path_update_bytes: Option<String>,
    signature: String,
}

#[derive(Debug, Serialize)]
struct SubmitAppMessageRequest {
    username: String,
    message_bytes: String,
    signature: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let client = Client::new();

    match cli.command {
        Commands::Register {
            username,
            password,
            force,
        } => {
            if cli.state.exists() && !force {
                return Err(format!("state file already exists: {} (use --force to overwrite)", cli.state.display()).into());
            }

            let (state, sig_b64) = register_state(&username, &password)?;
            save_state(&cli.state, &state)?;

            let req = RegisterRequest {
                username: username.clone(),
                password,
                classic_pub_key: state.classic_pk_b64.clone(),
                pq_pub_key: state.pq_pk_b64.clone(),
                signature: sig_b64,
            };

            let url = format!("{}/v1/auth/register", cli.base_url);
            let resp = client.post(url).json(&req).send().await?;
            print_response(resp).await?;
        }
        Commands::Login { username, password } => {
            let mut state = load_state(&cli.state)?;
            let username = resolve_username(username, &state)?;
            if state.username != username {
                return Err("username does not match state".into());
            }

            let priv_key = signing_key_from_state(&state)?;
            let sign_input = login_signing_input(&username, &password);
            let signature = encode_signature(&priv_key.sign(&sign_input));

            let req = LoginRequest {
                username: username.clone(),
                password,
                signature,
            };

            let url = format!("{}/v1/auth/login", cli.base_url);
            let resp = client.post(url).json(&req).send().await?;
            let body = resp.text().await?;
            println!("{body}");

            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body) {
                if let Some(token) = json.get("session_id").and_then(|v| v.as_str()) {
                    state.session_id = Some(token.to_string());
                    save_state(&cli.state, &state)?;
                }
            }
        }
        Commands::SubmitProposal {
            username,
            group_id,
            proposal_file,
        } => {
            let state = load_state(&cli.state)?;
            let username = resolve_username(username, &state)?;
            let payload = fs::read(&proposal_file)?;
            let payload_b64 = STANDARD.encode(&payload);

            let priv_key = signing_key_from_state(&state)?;
            let sign_input = proposal_signing_input(&username, &group_id, &payload);
            let signature = encode_signature(&priv_key.sign(&sign_input));

            let req = SubmitProposalRequest {
                username,
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
        } => {
            let state = load_state(&cli.state)?;
            let username = resolve_username(username, &state)?;
            let commit_payload = fs::read(&commit_file)?;
            let commit_b64 = STANDARD.encode(&commit_payload);
            let path_update_payload = match path_update_file {
                Some(path) => Some(fs::read(path)?),
                None => None,
            };
            let path_update_b64 = path_update_payload.as_ref().map(|bytes| STANDARD.encode(bytes));

            let priv_key = signing_key_from_state(&state)?;
            let sign_input = commit_signing_input(
                &username,
                &group_id,
                &commit_payload,
                path_update_payload.as_deref(),
            );
            let signature = encode_signature(&priv_key.sign(&sign_input));

            let req = SubmitCommitRequest {
                username,
                commit_bytes: commit_b64,
                path_update_bytes: path_update_b64,
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
            let priv_key = signing_key_from_state(&state)?;
            let kind_label = kind.to_lowercase();
            let sign_input =
                list_signing_input(&username, &group_id, limit, &kind_label, before_id);
            let signature = encode_signature(&priv_key.sign(&sign_input));

            let limit_string = limit.to_string();
            let mut params = vec![
                ("username", username.as_str()),
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
            let payload = fs::read(&message_file)?;
            let payload_b64 = STANDARD.encode(&payload);

            let priv_key = signing_key_from_state(&state)?;
            let sign_input = app_publish_signing_input(&username, &group_id, &payload);
            let signature = encode_signature(&priv_key.sign(&sign_input));

            let req = SubmitAppMessageRequest {
                username,
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
            let priv_key = signing_key_from_state(&state)?;
            let sign_input = app_list_signing_input(&username, &group_id, limit, before_id);
            let signature = encode_signature(&priv_key.sign(&sign_input));
            let limit_string = limit.to_string();
            let mut params = vec![
                ("username", username.as_str()),
                ("signature", signature.as_str()),
                ("limit", limit_string.as_str()),
            ];
            let before_string;
            if let Some(id) = before_id {
                before_string = id.to_string();
                params.push(("before_id", before_string.as_str()));
            }
            let query = serde_urlencoded::to_string(params)?;

            let url = format!("{}/v1/groups/{}/app-messages?{}", cli.base_url, group_id, query);
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
            let priv_key = signing_key_from_state(&state)?;
            let sign_input = app_fetch_signing_input(&username, &group_id, &message_id);
            let signature = encode_signature(&priv_key.sign(&sign_input));
            let query = serde_urlencoded::to_string([
                ("username", username.as_str()),
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
            let payload = fs::read(&keypackage_file)?;
            let payload_b64 = STANDARD.encode(&payload);

            let priv_key = signing_key_from_state(&state)?;
            let sign_input = keypackage_publish_signing_input(&username, &payload);
            let signature = encode_signature(&priv_key.sign(&sign_input));

            let req = serde_json::json!({
                "username": username,
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
            let priv_key = signing_key_from_state(&state)?;
            let sign_input = keypackage_fetch_signing_input(&username, &target);
            let signature = encode_signature(&priv_key.sign(&sign_input));

            let url = format!("{}/v1/keypackages/{}", cli.base_url, target);
            let resp = client
                .get(url)
                .query(&[
                    ("username", username.as_str()),
                    ("signature", signature.as_str()),
                ])
                .send()
                .await?;
            let status = resp.status();
            let body = resp.text().await?;
            println!("{status}\n{body}");

            if let Some(path) = out {
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body) {
                    if let Some(bytes) = json.get("keypackage_bytes").and_then(|v| v.as_str()) {
                        let decoded = STANDARD.decode(bytes)?;
                        fs::write(path, decoded)?;
                    }
                }
            }
        }
        Commands::ShowState => {
            let state = load_state(&cli.state)?;
            let json = serde_json::to_string_pretty(&state)?;
            println!("{json}");
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

fn resolve_username(candidate: Option<String>, state: &ClientState) -> Result<String, Box<dyn std::error::Error>> {
    Ok(candidate.unwrap_or_else(|| state.username.clone()))
}

fn register_state(username: &str, password: &str) -> Result<(ClientState, String), Box<dyn std::error::Error>> {
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

    let sign_input = register_signing_input(username, password, &classic_pk_b64, &pq_pk_b64);
    let signature = encode_signature(&priv_key.sign(&sign_input));

    let state = ClientState {
        username: username.to_string(),
        classic_sk_b64: STANDARD.encode(classic_sk.to_bytes()),
        pq_sk_b64: STANDARD.encode(pq_sk.encode()),
        classic_pk_b64,
        pq_pk_b64,
        session_id: None,
    };

    Ok((state, signature))
}

fn signing_key_from_state(state: &ClientState) -> Result<HybridSignPrivKey, Box<dyn std::error::Error>> {
    let classic_bytes = STANDARD.decode(&state.classic_sk_b64)?;
    if classic_bytes.len() != 32 {
        return Err("classic signing key must be 32 bytes".into());
    }
    let mut secret: EdSecretKey = [0u8; 32];
    secret.copy_from_slice(&classic_bytes);
    let classic_sk = EdSigningKey::from_bytes(&secret);

    let pq_bytes = STANDARD.decode(&state.pq_sk_b64)?;
    let enc: EncodedSigningKey<MlDsa65> = pq_bytes.as_slice().try_into().map_err(|_| "invalid pq signing key")?;
    let pq_sk = ml_dsa::SigningKey::<MlDsa65>::decode(&enc);

    Ok(HybridSignPrivKey { classic: classic_sk, pq: pq_sk })
}

fn encode_signature(sig: &HybridSignature) -> String {
    STANDARD.encode(sig.to_bytes())
}

async fn print_response(resp: reqwest::Response) -> Result<(), Box<dyn std::error::Error>> {
    let status = resp.status();
    let body = resp.text().await?;
    println!("{status}\n{body}");
    Ok(())
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
