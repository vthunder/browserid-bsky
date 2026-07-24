//! bsky.browserid.me — the Bluesky PDS bridge (bean browserid-bsky-aa7g,
//! design doc `docs/plans/2026-07-24-bsky-pds-bridge-design.md`).
//!
//! One public origin, three surfaces:
//! - `/browserid/provision` — browserid login → create an atproto account
//!   on the internal stock PDS, bind grantor-email ↔ DID.
//! - `/browserid/token` — RFC 7521 grant exchange: four-object bundle in,
//!   scoped bridge token out.
//! - `/xrpc/*` — bridge-token requests are scope-enforced then forwarded
//!   with the account's PDS session; everything else passes through
//!   untouched (human clients, relay crawl).
//!
//! Verification is **outsourced to the hosted verifier**
//! (`POST {broker}/verify-access`) — there is exactly one verification
//! algorithm and it runs where it is maintained, with real DNSSEC-rooted
//! discovery (primaries like sandmill.org just work). The bridge keeps only
//! a status-list *client* for live warrant-revocation re-checks on token
//! use. Local in-process verification returns when browserid-ng extracts
//! the algorithm as a crate (bean browserid-ng-kozn).

pub mod pds;
pub mod routes;
pub mod scopes;
pub mod store;

use std::sync::Arc;

use browserid_core::PublicKey;
use browserid_rp::StatusCache;

use crate::pds::PdsClient;
use crate::store::Store;

/// Scopes advertised in the 401 challenge and RFC 8414 metadata. The real
/// vocabulary is the granular-scope grammar (`scopes.rs`); these are the
/// common grants shown to integrators.
pub const ADVERTISED_SCOPES: &[&str] = &[
    "repo:app.bsky.feed.post?action=create",
    "repo:app.bsky.feed.like",
    "blob:image/*",
    "rpc:app.bsky.feed.getTimeline",
];

/// Handle labels that must never become user handles under the handle zone.
pub const RESERVED_LABELS: &[&str] = &[
    "www", "api", "pds", "admin", "xrpc", "mail", "smtp", "broker", "login", "auth", "consent",
    "account", "verify", "status", "bridge",
];

/// Bridge token lifetime (design doc: ≤ 1 h; warrant status re-checked on use)
pub const TOKEN_TTL_MINUTES: i64 = 60;

pub struct BridgeState {
    /// The public origin — the warrant/assertion audience (e.g.
    /// `https://bsky.browserid.me`)
    pub origin: String,
    /// Zone user handles live under (e.g. `at.browserid.me`)
    pub handle_domain: String,
    /// The hosted verifier's base URL (the broker)
    pub broker_url: String,
    /// The broker's published key — used ONLY to verify its signed warrant
    /// status lists for revocation re-checks (a status-list client, not a
    /// verifier)
    pub broker_key: PublicKey,
    pub status_cache: Arc<StatusCache>,
    pub store: Store,
    pub pds: PdsClient,
    pub http: reqwest::Client,
}

impl BridgeState {
    pub fn router(self) -> axum::Router {
        let state = Arc::new(self);
        axum::Router::new()
            .route("/browserid/provision", axum::routing::post(routes::provision))
            .route("/browserid/token", axum::routing::post(routes::token))
            .route(
                "/.well-known/oauth-authorization-server",
                axum::routing::get(routes::oauth_metadata),
            )
            .route("/browserid/health", axum::routing::get(|| async { "ok" }))
            .fallback(routes::proxy)
            .with_state(state)
    }
}
