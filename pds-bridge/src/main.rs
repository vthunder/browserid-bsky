//! pds-bridge binary — see lib.rs and
//! `docs/plans/2026-07-24-bsky-pds-bridge-design.md`.

use std::sync::Arc;

use browserid_rp::{StatusCache, Verifier};
use pds_bridge::{store::Store, BridgeState, ADVERTISED_SCOPES};

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

    // Fail-closed by default (4lxl): status lists are refreshed on demand in
    // the handlers; unknown status → reject.
    let status_cache = Arc::new(StatusCache::new());
    // TODO(ezk6/P2): DNSSEC-rooted issuer discovery for primary-IdP users;
    // P1 trusts the configured broker as the accepted fallback, like the
    // other reference RPs.
    let verifier = Verifier::new(origin.clone())
        .trust_issuer_from_well_known(&broker_url)
        .await
        .expect("failed to fetch broker key")
        .with_scopes(ADVERTISED_SCOPES.iter().copied())
        .with_status_cache(status_cache.clone());

    let state = BridgeState {
        origin: origin.clone(),
        handle_domain,
        verifier,
        status_cache,
        store: Store::open(&db_path).expect("failed to open bridge db"),
        pds: pds_bridge::pds::PdsClient::new(pds_url, pds_admin_password),
    };

    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port))
        .await
        .expect("failed to bind");
    tracing::info!("pds-bridge listening on :{port} (origin {origin})");
    axum::serve(listener, state.router()).await.expect("server error");
}
