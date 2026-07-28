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

pub mod attestation;
pub mod guide;
pub mod idp;
pub mod labeler;
pub mod pds;
pub mod relay;
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
    "account:create",
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
    /// The atproto labeler (signs labels for verified posts); None if no
    /// signing key is configured.
    pub labeler: Option<crate::labeler::Labeler>,
    /// The labeler *account*'s PDS password (`LABELER_ACCOUNT_PASSWORD`),
    /// needed only to append per-pair `labelValueDefinition`s to its
    /// `app.bsky.labeler.service` record. Unset degrades gracefully: labels
    /// are still emitted, they just render with no badge text until a
    /// definition exists.
    pub labeler_account_password: Option<String>,
    /// Fan-out to live `subscribeLabels` consumers. Labels are PUSHED: the
    /// AppView ingests this stream into its own index and serves badges from
    /// there, so an unstreamed label is invisible no matter what
    /// `queryLabels` says.
    pub label_tx: tokio::sync::broadcast::Sender<crate::store::EmittedLabel>,
    /// The bsky-handle IdP (bean tw1d) — this deployment also *is* the
    /// primary for `bsky.browserid.me` identities. `None` disables the
    /// whole surface, which is what tests that only exercise the bridge
    /// use.
    pub idp: Option<Arc<crate::idp::IdpState>>,
    /// In-process verifier for presentations issued by our own IdP.
    ///
    /// The bridge normally outsources verification to the hosted verifier,
    /// which resolves issuers through DNSSEC. For D's own identities that
    /// round trip is pointless — the IdP is *this process*, so its key is
    /// pinned directly with [`browserid_rp::Verifier::trust_primary`], and
    /// a login with a Bluesky handle no longer depends on the broker being
    /// up or DNS having propagated. Everyone else still goes the long way.
    pub idp_verifier: Option<browserid_rp::Verifier>,
    /// The OAuth **write relay** (bean ru7u): stored atproto sessions that
    /// let an attested post land in the user's own repo instead of a
    /// bridge-owned account.
    ///
    /// `None` is the default and the safe state — the relay only exists when
    /// `WRITE_RELAY_ALLOWLIST` names someone, so a deployment cannot end up
    /// holding third-party write credentials by forgetting a variable. Same
    /// graceful-degradation shape as `labeler: None` and `idp: None`.
    pub relay: Option<crate::relay::RelayState>,
}

/// Build the in-process verifier that trusts D as a primary for its own
/// domain and nothing else. Shares the bridge's status cache, so a cert
/// revoked through D's status list is rejected here too.
pub fn idp_verifier(idp: &crate::idp::IdpState, state_origin: &str, cache: Arc<StatusCache>) -> browserid_rp::Verifier {
    browserid_rp::Verifier::new(state_origin)
        .trust_primary(idp.domain.clone(), idp.keypair.public_key())
        .with_status_cache(cache)
}

/// Live-stream backlog per consumer. A slow consumer that overruns this is
/// disconnected rather than silently skipped — it reconnects with its cursor
/// and backfills from the store, so nothing is lost.
const LABEL_CHANNEL_CAPACITY: usize = 1024;

/// Build the label fan-out channel (used by `BridgeState` construction).
pub fn label_channel() -> tokio::sync::broadcast::Sender<crate::store::EmittedLabel> {
    tokio::sync::broadcast::channel(LABEL_CHANNEL_CAPACITY).0
}

impl BridgeState {
    pub fn router(self) -> axum::Router {
        Self::router_from(Arc::new(self))
    }

    /// Router over an already-shared state, so callers that need the `Arc`
    /// too (e.g. to spawn the startup label backfill) can keep it.
    pub fn router_from(state: Arc<Self>) -> axum::Router {
        crate::relay::routes::routes(crate::idp::routes(axum::Router::new()))
            .route("/browserid/provision", axum::routing::post(routes::provision))
            .route("/browserid/token", axum::routing::post(routes::token))
            .route("/browserid/post", axum::routing::post(routes::attributed_post))
            .route("/browserid/whoami", axum::routing::get(routes::whoami))
            .route(
                "/.well-known/oauth-authorization-server",
                axum::routing::get(routes::oauth_metadata),
            )
            .route("/", axum::routing::get(routes::root))
            .route("/llms.txt", axum::routing::get(routes::llms_txt))
            .route("/browserid/health", axum::routing::get(|| async { "ok" }))
            .route("/verify", axum::routing::get(routes::verify))
            .route("/.well-known/did.json", axum::routing::get(routes::did_json))
            .route("/xrpc/com.atproto.label.queryLabels", axum::routing::get(routes::query_labels))
            .route(
                "/xrpc/com.atproto.label.subscribeLabels",
                axum::routing::get(routes::subscribe_labels),
            )
            .fallback(routes::proxy)
            .with_state(state)
    }
}
