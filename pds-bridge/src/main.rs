//! pds-bridge binary — see lib.rs and
//! `docs/plans/2026-07-24-bsky-pds-bridge-design.md`.

use std::sync::Arc;
use std::time::Duration;

use browserid_rp::StatusCache;
use pds_bridge::{store::Store, BridgeState};

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let port: u16 = env_or("BRIDGE_PORT", "3200").parse().expect("BRIDGE_PORT must be a port");
    let origin = env_or("BRIDGE_ORIGIN", &format!("http://localhost:{port}"));
    let handle_domain = env_or("HANDLE_DOMAIN", "at.browserid.me");
    let pds_url = env_or("PDS_URL", "http://127.0.0.1:2583");
    let pds_admin_password = std::env::var("PDS_ADMIN_PASSWORD")
        .expect("PDS_ADMIN_PASSWORD is required (the stock PDS admin secret)");
    let broker_url = env_or("BROKER_URL", "https://browserid.me");
    let db_path = env_or("BRIDGE_DB", "pds-bridge.db");

    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .expect("failed to build HTTP client");

    // The broker's published key — verifies its signed warrant status lists
    // for the live revocation re-check. Verification of presentations is
    // outsourced to {broker_url}/verify-access (see lib.rs).
    let doc: browserid_core::discovery::SupportDocument = http
        .get(format!("{broker_url}/.well-known/browserid"))
        .send()
        .await
        .and_then(|r| r.error_for_status())
        .expect("broker unreachable")
        .json()
        .await
        .expect("bad broker support document");
    let broker_key = doc.public_key.expect("broker support document has no key");

    let state = BridgeState {
        origin: origin.clone(),
        handle_domain,
        broker_url,
        broker_key,
        // Fail-closed (4lxl): unknown/stale warrant status → reject.
        status_cache: Arc::new(StatusCache::new()),
        store: Store::open(&db_path).expect("failed to open bridge db"),
        pds: pds_bridge::pds::PdsClient::new(pds_url, pds_admin_password),
        http,
    };

    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port))
        .await
        .expect("failed to bind");
    tracing::info!("pds-bridge listening on :{port} (origin {origin})");
    axum::serve(listener, state.router()).await.expect("server error");
}
