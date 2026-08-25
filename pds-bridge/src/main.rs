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

    // The broker's key — verifies its signed warrant status lists for the
    // live revocation re-check. Resolved from the broker's `_browserid`
    // DNSSEC record (the sole root of trust; 2026-08-25 sweep — support
    // documents no longer serve keys, and reading one was a downgrade
    // vector). Verification of presentations is outsourced to
    // {broker_url}/verify-access (see lib.rs).
    let broker_host = reqwest::Url::parse(&broker_url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_string))
        .expect("bad BROKER_URL");
    let broker_key = if broker_host == "localhost" || broker_host.starts_with("127.") {
        // DEV exception (localhost only, mirroring the broker's own): no
        // DNSSEC exists for localhost, and a localhost broker can never be a
        // production origin — its dev doc serves the key.
        let doc: browserid_core::discovery::SupportDocument = http
            .get(format!("{broker_url}/.well-known/browserid"))
            .send()
            .await
            .and_then(|r| r.error_for_status())
            .expect("broker unreachable")
            .json()
            .await
            .expect("bad broker support document");
        doc.public_key.expect("dev broker support document has no key")
    } else {
        let dns = browserid_dnssec::DnsFetcher::new().expect("dns fetcher");
        browserid_dnssec::resolve_idp_key(&dns, &broker_host)
            .await
            .expect("could not resolve the broker key from its _browserid DNSSEC record")
    };

    // Labeler (optional): k256 signing key → signs labels for verified posts.
    let labeler = std::env::var("LABELER_K256_PRIVATE_KEY_HEX").ok().map(|hex| {
        let did = std::env::var("LABELER_DID").ok();
        pds_bridge::labeler::Labeler::new(&hex, &origin, did).expect("bad LABELER_K256_PRIVATE_KEY_HEX")
    });
    if let Some(l) = &labeler {
        tracing::info!("labeler enabled: {}", l.did);
        if std::env::var("LABELER_ACCOUNT_PASSWORD").is_err() {
            tracing::warn!(
                "LABELER_ACCOUNT_PASSWORD unset: per-pair labels will be emitted but their \
                 labelValueDefinitions cannot be published, so clients render no badge text"
            );
        }
    }

    // The bsky-handle IdP (bean tw1d): this deployment is also the browserid
    // primary for its own origin. Off unless IDP_ENABLED is set, because
    // standing it up means publishing a DNS key and an OAuth client.
    let status_cache = Arc::new(StatusCache::new());
    let idp = std::env::var("IDP_ENABLED")
        .is_ok_and(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .then(|| {
            Arc::new(pds_bridge::idp::IdpState::from_env(&origin, &broker_url).expect("IdP configuration"))
        });
    let idp_verifier = idp
        .as_ref()
        .map(|i| pds_bridge::idp_verifier(i, &origin, status_cache.clone()));
    if let Some(i) = &idp {
        tracing::info!(
            domain = %i.domain,
            "bsky-handle IdP enabled — publish _browserid.{} TXT with this key: {}",
            i.domain,
            i.keypair.public_key().to_base64()
        );
    }

    // The write relay (bean ru7u). Requires the IdP — the pinned handle↔DID
    // binding is what a relayed post is attributed to — and stays off unless
    // WRITE_RELAY_ALLOWLIST names someone.
    // A misconfigured relay is a boot failure, not a degraded mode: the one
    // thing worse than no relay is a relay whose AEAD key was quietly
    // invented and stored beside the database it protects.
    let relay = match &idp {
        Some(_) => match pds_bridge::relay::RelayState::from_env(&origin) {
            Ok(r) => r,
            Err(e) => {
                tracing::error!("write relay misconfigured: {e}");
                std::process::exit(1);
            }
        },
        None => None,
    };

    let state = BridgeState {
        origin: origin.clone(),
        handle_domain,
        broker_url,
        broker_key,
        // Fail-closed (4lxl): unknown/stale warrant status → reject.
        status_cache,
        store: Store::open(&db_path).expect("failed to open bridge db"),
        pds: pds_bridge::pds::PdsClient::new(pds_url, pds_admin_password),
        http,
        labeler,
        labeler_account_password: std::env::var("LABELER_ACCOUNT_PASSWORD").ok(),
        label_tx: pds_bridge::label_channel(),
        idp,
        idp_verifier,
        relay,
    };
    let state = Arc::new(state);
    // Posts made before the labeler existed still need to reach the
    // firehose — that stream, not queryLabels, is what renders badges.
    tokio::spawn(pds_bridge::routes::backfill_labels(state.clone()));

    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port))
        .await
        .expect("failed to bind");
    tracing::info!("pds-bridge listening on :{port} (origin {origin})");
    axum::serve(listener, BridgeState::router_from(state)).await.expect("server error");
}
