use std::fs;
use std::path::{Path, PathBuf};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use clap::{Parser, Subcommand};
use ed25519_dalek::{SecretKey as EdSecretKey, SigningKey as EdSigningKey, VerifyingKey as EdPublic};
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

use hybrid_mls::client_state::ClientGroupState;
use hybrid_mls::crypto::{HybridPrivateKey, HybridPublicKey, HybridSignPrivKey, HybridSignature, KyberPriv};
use hybrid_mls::envelope::{CommitEnvelope, PathUpdateEnvelope, ProposalEnvelope};
use hybrid_mls::tree::{Commit, KeyPackage, LeafNode, Node, ParentUpdate, PathUpdate, Proposal, RatchetTree};

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
    FetchAndApplyLatest {
        #[arg(long)]
        group_state: PathBuf,
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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
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
            sender_leaf,
        } => {
            let mut state = load_group_state(&group_state)?;
            let sender_leaf = resolve_sender_leaf(sender_leaf, &state)?;
            let (commit, path_update) = build_commit_from_pending(&state, sender_leaf)?;

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

            state
                .ratchet_tree
                .apply_commit(&commit)
                .ok_or("failed to apply generated commit to local state")?;
            state.clear_pending_proposals();
            state.epoch = state.epoch.saturating_add(1);
            save_group_state(&group_state, &state)?;

            println!(
                "created commit envelope at {} and path update envelope at {} (group={}, new_epoch={}, sender_leaf={})",
                commit_out.display(),
                path_update_out.display(),
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

            let derived = if let Some(path_update_envelope) = path_update_envelope {
                if let Some(receiver_private_file) = receiver_private_file.as_ref() {
                    let receiver_private = load_receiver_private_from_file(receiver_private_file)?;
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
                        .ok_or("failed to apply commit without path-update decapsulation")?;
                    println!(
                        "note: path update file provided but --receiver-private-file is missing; applied commit only"
                    );
                    None
                }
            } else {
                state
                    .ratchet_tree
                    .apply_commit(&commit_envelope.commit)
                    .ok_or("failed to apply commit")?;
                if receiver_private_file.is_some() {
                    println!(
                        "note: --receiver-private-file was provided without --path-update-file; ignored"
                    );
                }
                None
            };

            if let Some(out) = derived_out {
                let json = serialize_derived_path_secrets(&derived);
                fs::write(&out, serde_json::to_vec_pretty(&json)?)?;
            }

            state.clear_pending_proposals();
            state.epoch = state.epoch.saturating_add(1);
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
            validate_path_update_envelope_metadata(&commit_envelope, &path_update_envelope)?;
            let receiver_private = load_receiver_private_from_file(&receiver_private_file)?;

            let mut leaves = Vec::with_capacity(base_member_keypackage.len());
            for path in &base_member_keypackage {
                let key_package = load_keypackage_from_file(path)?;
                leaves.push(leaf_from_keypackage(&key_package));
            }
            let tree = RatchetTree::from_leaves(leaves);
            let mut state = ClientGroupState::new(commit_envelope.group_id.clone(), tree, 0);
            state.epoch = commit_envelope.epoch;

            state
                .ratchet_tree
                .apply_commit(&commit_envelope.commit)
                .ok_or("failed to apply commit while joining from commit")?;

            let resolved_own_leaf = match own_leaf {
                Some(index) => {
                    ensure_leaf_present(&state.ratchet_tree, index)?;
                    index
                }
                None => {
                    let public = hybrid_public_from_private(&receiver_private);
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
                    &receiver_private,
                    &path_update_envelope.path_update,
                )
                .ok_or("failed to process path update for joiner")?;

            if let Some(path) = derived_out {
                let json = serialize_derived_path_secrets(&Some(derived.clone()));
                fs::write(&path, serde_json::to_vec_pretty(&json)?)?;
            }

            state.clear_pending_proposals();
            state.epoch = state.epoch.saturating_add(1);
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
        Commands::FetchAndApplyLatest {
            group_state,
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
            let signing_key = signing_key_from_state(&auth_state)?;
            let mut state = load_group_state(&group_state)?;
            let receiver_private = match receiver_private_file {
                Some(path) => Some(load_receiver_private_from_file(&path)?),
                None => None,
            };
            let mut polls = 0usize;
            let mut total_applied = 0usize;
            let mut total_skipped = 0usize;
            let mut all_records = Vec::new();

            loop {
                polls = polls.saturating_add(1);
                let outcome = fetch_and_apply_latest_once(
                    &client,
                    &cli.base_url,
                    &username,
                    &signing_key,
                    &mut state,
                    receiver_private.as_ref(),
                    limit,
                )
                .await?;
                total_applied = total_applied.saturating_add(outcome.applied);
                total_skipped = total_skipped.saturating_add(outcome.skipped);
                all_records.extend(outcome.derived_records);

                if outcome.applied > 0 {
                    save_group_state(&group_state, &state)?;
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
    Ok(ClientGroupState::load_from_file(path)?)
}

fn save_group_state(path: &Path, state: &ClientGroupState) -> Result<(), Box<dyn std::error::Error>> {
    state.save_to_file(path)?;
    Ok(())
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
    let keypackage =
        KeyPackage::decode(&bytes).ok_or("invalid keypackage file: decode failed")?;
    if !keypackage.verify() {
        return Err("invalid keypackage file: signature verification failed".into());
    }
    Ok(keypackage)
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

fn load_commit_envelope_from_file(path: &Path) -> Result<CommitEnvelope, Box<dyn std::error::Error>> {
    let bytes = fs::read(path)?;
    CommitEnvelope::decode(&bytes).ok_or_else(|| "invalid commit envelope file".into())
}

fn load_path_update_envelope_from_file(
    path: &Path,
) -> Result<PathUpdateEnvelope, Box<dyn std::error::Error>> {
    let bytes = fs::read(path)?;
    PathUpdateEnvelope::decode(&bytes).ok_or_else(|| "invalid path update envelope file".into())
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

fn load_receiver_private_from_file(path: &Path) -> Result<HybridPrivateKey, Box<dyn std::error::Error>> {
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

fn ensure_leaf_bounds(tree: &RatchetTree, leaf_index: usize) -> Result<(), Box<dyn std::error::Error>> {
    if leaf_index >= tree.leaf_count() {
        return Err(format!("leaf index {leaf_index} is out of bounds").into());
    }
    Ok(())
}

fn generate_hybrid_public_key(rng: &mut ClientRng) -> Result<HybridPublicKey, Box<dyn std::error::Error>> {
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

struct SyncOutcome {
    applied: usize,
    skipped: usize,
    derived_records: Vec<serde_json::Value>,
}

async fn fetch_and_apply_latest_once(
    client: &Client,
    base_url: &str,
    username: &str,
    signing_key: &HybridSignPrivKey,
    state: &mut ClientGroupState,
    receiver_private: Option<&HybridPrivateKey>,
    limit: usize,
) -> Result<SyncOutcome, Box<dyn std::error::Error>> {
    let commit_summaries = ds_list_messages(
        client,
        base_url,
        username,
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
        signing_key,
        &state.group_id,
        limit,
        "path_update",
        None,
    )
    .await?;

    let mut commit_ids = Vec::new();
    for item in commit_summaries.messages {
        if let Ok(id) = item.id.parse::<i64>() {
            commit_ids.push(id);
        }
    }
    if commit_ids.is_empty() {
        return Ok(SyncOutcome {
            applied: 0,
            skipped: 0,
            derived_records: Vec::new(),
        });
    }
    commit_ids.sort_unstable();

    let mut path_ids = Vec::new();
    for item in path_summaries.messages {
        if let Ok(id) = item.id.parse::<i64>() {
            path_ids.push(id);
        }
    }
    path_ids.sort_unstable();

    let mut applied = 0usize;
    let mut skipped = 0usize;
    let mut derived_records = Vec::new();

    for (idx, commit_id) in commit_ids.iter().enumerate() {
        let next_commit = commit_ids.get(idx + 1).copied();
        let fetched_commit = ds_fetch_group_message(
            client,
            base_url,
            username,
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
        if commit_env.epoch < state.epoch {
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

        let maybe_path_id = find_matching_path_update_id(*commit_id, next_commit, &path_ids);
        let mut derived_for_commit: Option<Vec<Option<[u8; 32]>>> = None;

        if let (Some(path_id), Some(receiver_private)) = (maybe_path_id, receiver_private) {
            let fetched_path = ds_fetch_group_message(
                client,
                base_url,
                username,
                signing_key,
                &state.group_id,
                path_id,
            )
            .await?;
            if fetched_path.kind == "path_update" {
                let path_bytes = STANDARD.decode(&fetched_path.message_bytes)?;
                if let Some(path_env) = PathUpdateEnvelope::decode(&path_bytes) {
                    validate_path_update_envelope_metadata(&commit_env, &path_env)?;
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
                } else {
                    state
                        .ratchet_tree
                        .apply_commit(&commit_env.commit)
                        .ok_or("failed to apply commit during sync")?;
                }
            } else {
                state
                    .ratchet_tree
                    .apply_commit(&commit_env.commit)
                    .ok_or("failed to apply commit during sync")?;
            }
        } else {
            state
                .ratchet_tree
                .apply_commit(&commit_env.commit)
                .ok_or("failed to apply commit during sync")?;
        }

        state.clear_pending_proposals();
        state.epoch = state.epoch.saturating_add(1);
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

async fn ds_list_messages(
    client: &Client,
    base_url: &str,
    username: &str,
    signing_key: &HybridSignPrivKey,
    group_id: &str,
    limit: usize,
    kind: &str,
    before_id: Option<i64>,
) -> Result<DsListMessagesResponse, Box<dyn std::error::Error>> {
    let sign_input = list_signing_input(username, group_id, limit, kind, before_id);
    let signature = encode_signature(&signing_key.sign(&sign_input));
    let limit_string = limit.to_string();
    let mut params = vec![
        ("username", username.to_string()),
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
    signing_key: &HybridSignPrivKey,
    group_id: &str,
    message_id: i64,
) -> Result<DsFetchGroupMessageResponse, Box<dyn std::error::Error>> {
    let sign_input = fetch_message_signing_input(username, group_id, message_id);
    let signature = encode_signature(&signing_key.sign(&sign_input));
    let query = serde_urlencoded::to_string([
        ("username", username.to_string()),
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

fn find_matching_path_update_id(
    commit_id: i64,
    next_commit_id: Option<i64>,
    path_ids: &[i64],
) -> Option<i64> {
    for id in path_ids {
        if *id <= commit_id {
            continue;
        }
        if let Some(next) = next_commit_id {
            if *id >= next {
                break;
            }
        }
        return Some(*id);
    }
    None
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

fn hash_payload(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"DS-PAYLOAD");
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}
