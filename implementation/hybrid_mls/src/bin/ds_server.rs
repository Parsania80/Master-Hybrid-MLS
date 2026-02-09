use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;

use hybrid_mls::ds::config::StorageConfig;
use hybrid_mls::ds::http::{self, ApiState};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let bind = env::var("DS_BIND").unwrap_or_else(|_| "127.0.0.1:3000".to_string());
    let addr: SocketAddr = bind.parse()?;

    let data_dir = env::var("DS_DATA_DIR").unwrap_or_else(|_| "./data".to_string());
    let db_path = env::var("DS_DB_PATH").unwrap_or_else(|_| format!("{data_dir}/ds.sqlite"));
    let max_bytes = parse_env_u64("DS_MAX_BYTES")?;
    let min_proposals = parse_env_usize("DS_MIN_PROPOSALS_PER_COMMIT")?;

    let mut state = ApiState::default();
    state.storage = StorageConfig::new(PathBuf::from(data_dir), PathBuf::from(db_path));
    if let Some(value) = max_bytes {
        state.max_bytes = value;
    }
    if let Some(value) = min_proposals {
        state.min_proposals_per_commit = value;
    }

    let app = http::router(state);
    let listener = tokio::net::TcpListener::bind(addr).await?;

    println!("DS server listening on http://{addr}");
    axum::serve(listener, app).await?;
    Ok(())
}

fn parse_env_u64(name: &str) -> Result<Option<u64>, Box<dyn std::error::Error>> {
    match env::var(name) {
        Ok(v) => Ok(Some(v.parse()?)),
        Err(env::VarError::NotPresent) => Ok(None),
        Err(err) => Err(Box::new(err)),
    }
}

fn parse_env_usize(name: &str) -> Result<Option<usize>, Box<dyn std::error::Error>> {
    match env::var(name) {
        Ok(v) => Ok(Some(v.parse()?)),
        Err(env::VarError::NotPresent) => Ok(None),
        Err(err) => Err(Box::new(err)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use ed25519_dalek::{SecretKey as EdSecretKey, SigningKey as EdSigningKey};
    use hybrid_mls::crypto::HybridSignPrivKey;
    use ml_dsa::{KeyGen, MlDsa65};
    use rand::rngs::OsRng;
    use rand::RngCore;
    use std::path::PathBuf;
    use tokio::sync::oneshot;
    use tokio::task::JoinHandle;
    use tokio::time::{sleep, Duration};

    fn temp_state(label: &str) -> (ApiState, PathBuf) {
        let base = std::env::temp_dir().join(format!(
            "hybrid-mls-ds-server-{label}-{}",
            rand::random::<u64>()
        ));
        let db_path = base.join("ds.sqlite");
        let mut state = ApiState::default();
        state.storage = StorageConfig::new(&base, &db_path);
        (state, base)
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

    async fn start_test_server(state: ApiState) -> (std::net::SocketAddr, oneshot::Sender<()>, JoinHandle<Result<(), std::io::Error>>) {
        let app = http::router(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind listener");
        let addr = listener.local_addr().expect("read listener addr");

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

    #[tokio::test]
    async fn health_endpoint_serves_ok_on_random_port() {
        let (state, base) = temp_state("health");
        let (addr, shutdown_tx, server) = start_test_server(state).await;

        let client = reqwest::Client::new();
        let url = format!("http://{addr}/healthz");
        let mut attempts = 0usize;
        let response = loop {
            attempts += 1;
            match client.get(&url).send().await {
                Ok(resp) => break resp,
                Err(err) if attempts < 10 => {
                    let _ = err;
                    sleep(Duration::from_millis(25)).await;
                }
                Err(err) => panic!("failed to call health endpoint: {err}"),
            }
        };

        assert!(response.status().is_success());
        assert_eq!(response.text().await.expect("read body"), "ok");

        let _ = shutdown_tx.send(());
        let result = server.await.expect("join server task");
        if let Err(err) = result {
            panic!("server returned error: {err}");
        }

        let _ = std::fs::remove_dir_all(base);
    }

    #[tokio::test]
    async fn register_happy_path_via_running_listener() {
        let (state, base) = temp_state("register");
        let (addr, shutdown_tx, server) = start_test_server(state).await;

        let mut rng = OsRng;
        let mut classic_secret: EdSecretKey = [0u8; 32];
        rng.fill_bytes(&mut classic_secret);
        let classic_sk = EdSigningKey::from_bytes(&classic_secret);
        let classic_pk = classic_sk.verifying_key();

        let kp = MlDsa65::key_gen(&mut rng);
        let pq_sk = kp.signing_key().clone();
        let pq_pk = kp.verifying_key().clone();

        let signer = HybridSignPrivKey {
            classic: classic_sk,
            pq: pq_sk,
        };

        let username = "alice";
        let password = "secret";
        let classic_pub_b64 = STANDARD.encode(classic_pk.as_bytes());
        let pq_pub_b64 = STANDARD.encode(pq_pk.encode());
        let sign_input =
            register_signing_input(username, password, &classic_pub_b64, &pq_pub_b64);
        let signature = STANDARD.encode(signer.sign(&sign_input).to_bytes());

        let body = serde_json::json!({
            "username": username,
            "password": password,
            "classic_pub_key": classic_pub_b64,
            "pq_pub_key": pq_pub_b64,
            "signature": signature,
        });

        let client = reqwest::Client::new();
        let resp = client
            .post(format!("http://{addr}/v1/auth/register"))
            .json(&body)
            .send()
            .await
            .expect("send register request");

        assert_eq!(resp.status(), reqwest::StatusCode::OK);
        let json: serde_json::Value = resp.json().await.expect("parse register response");
        assert_eq!(json["user_id"], username);

        let _ = shutdown_tx.send(());
        let result = server.await.expect("join server task");
        if let Err(err) = result {
            panic!("server returned error: {err}");
        }

        let _ = std::fs::remove_dir_all(base);
    }
}
