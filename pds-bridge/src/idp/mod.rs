//! The **bsky-handle browserid IdP** — BigTent for atproto
//! (bean browserid-bsky-tw1d, design doc
//! `docs/plans/2026-07-27-bigtent-bsky-idp-design.md`).
//!
//! Serves identity domain **D** (`bsky.browserid.me`, the bridge's own
//! origin) as a conformant browserid *primary*: it publishes a support
//! document, issues device certs for `<handle>@D`, and mints access certs
//! headlessly. What makes it BigTent rather than yet another email IdP is
//! how ownership is proven: **atproto OAuth**, not an email loop. The
//! person authenticates at their real PDS/entryway, we read the
//! authenticated DID out of exactly one authorization-code exchange, and
//! then throw the tokens away. We never hold write access to anyone's real
//! account.
//!
//! The proof chain, and every link is load-bearing:
//!
//! ```text
//!   handle ──DNS/well-known──▶ DID ──alsoKnownAs──▶ back to handle
//!     └── DID doc ──▶ PDS ──▶ auth server ──OAuth──▶ token.sub == DID
//! ```
//!
//! Break any link and the flow proves nothing, so [`resolve`] refuses to
//! return a DID that does not claim its handle back, and [`oauth`] refuses a
//! token whose `sub` is not the DID we resolved.
//!
//! Beyond issuance the IdP keeps two ongoing obligations:
//!
//! * **Mint-time re-verification** — every access cert (24 h) re-checks the
//!   public handle↔DID binding against the pinned DID before minting, so a
//!   handle that moved, lapsed, or was taken down stops working within a day
//!   without any stored session. See [`certs::access_mint`].
//! * **A status list** — every cert we issue carries a `status` ref into D's
//!   own signed list at `/.well-known/browserid-status`, so a suspended
//!   binding's certs die in minutes rather than at cert TTL.

pub mod certs;
pub mod net;
pub mod oauth;
pub mod pins;
pub mod resolve;
pub mod routes;

use std::path::PathBuf;
use std::sync::Arc;

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use browserid_core::keys::KeyPair;

/// The OAuth scope requested from the user's authorization server.
///
/// `atproto` is the bare marker scope — the documented identity-only
/// minimum, and deliberately *not* any of the granular scopes (still
/// unfinalized upstream). We need the authenticated DID and nothing else.
/// Named because whether a given deployment accepts it standalone is an
/// empirical question; if an entryway ever refuses it, this is the one
/// constant to change.
pub const OAUTH_SCOPE: &str = "atproto";

/// How long a resolved handle↔DID binding may be reused before it must be
/// re-resolved. The spec's sub-10-minute rule for auth-critical paths: it
/// bounds how stale the mint's re-verification can be, and doubles as the
/// fallback window when resolution is simply *down*.
pub const RESOLVE_CACHE_SECONDS: i64 = 600;

/// Seasoning period for handle reassignment (Decision 3). A handle
/// previously bound to a different DID may be re-claimed only once the new
/// DID has held it continuously for this long, measured from the first
/// refused attempt.
pub const REASSIGNMENT_SEASONING_DAYS: i64 = 30;

/// Device-cert lifetime. Kept at the browserid reference constant
/// (Decision 5) — dropping it is a global conversation, not this IdP's.
pub const DEVICE_CERT_DAYS: i64 = browserid_core::device::DEVICE_CERT_VALIDITY_DAYS;

/// How long a pending OAuth flow (PAR request + PKCE verifier + ephemeral
/// DPoP key) stays resumable. Long enough for a real human to type a
/// password and approve, short enough that abandoned flows evaporate.
pub const OAUTH_FLOW_TTL_MINUTES: i64 = 15;

/// First-party IdP session lifetime. This is *our* cookie, not an atproto
/// session — no tokens sit behind it. It exists only so the
/// device-authorize page can issue certs for the handle the user just
/// proved, across the OAuth redirect and any re-issue round trip.
pub const SESSION_TTL_HOURS: i64 = 12;

/// Everything the IdP needs that the bridge proper does not.
pub struct IdpState {
    /// The identity domain D — the cert issuer, e.g. `bsky.browserid.me`.
    /// Always the host of the bridge's own origin.
    pub domain: String,
    /// D's public https base (the bridge origin), used to build absolute
    /// URLs: the OAuth `client_id`, the redirect URI, the status-list URI.
    pub origin: String,
    /// D's browserid signing key (Ed25519). Signs device certs, access
    /// certs, and the status list. This is the key the `_browserid` TXT
    /// record publishes and DNSSEC vouches for.
    pub keypair: KeyPair,
    /// The OAuth confidential client's ES256 key, used for
    /// `private_key_jwt` client authentication. Published (public half) at
    /// the client's `jwks_uri`. Distinct from `keypair`: different
    /// algorithm, different trust domain, different rotation story.
    pub oauth_key: oauth::ClientKey,
    /// The scope requested at the authorization server ([`OAUTH_SCOPE`]).
    pub scope: String,
    /// DNS-over-HTTPS endpoint for `_atproto.<handle>` TXT lookups. The
    /// bridge has no DNS client and atproto handle resolution needs one;
    /// DoH keeps it to an HTTP request. Override to point at a resolver
    /// you trust more than the default.
    pub doh_url: String,
    /// Recently-resolved handle↔DID bindings ([`RESOLVE_CACHE_SECONDS`]).
    pub resolve_cache: resolve::ResolveCache,
    /// The **only** origins the device-authorize page may hand certs to.
    ///
    /// The page receives `return_origin` in its URL fragment, and that
    /// fragment is attacker-controlled: without this list any site could
    /// open the page and collect device+config certs, bound to keys it
    /// supplies, for whoever is signed in. The legitimate caller is the
    /// browserid dialog/broker, so the list defaults to the broker's origin
    /// and is overridable with `IDP_TRUSTED_ORIGINS` (comma-separated).
    /// Server-derived on purpose — never read from the fragment.
    pub trusted_origins: Vec<String>,
}

impl IdpState {
    /// The OAuth client identifier — which, per the atproto profile, *is*
    /// the URL its metadata document is served from.
    pub fn client_id(&self) -> String {
        format!("{}/idp/client-metadata.json", self.origin)
    }

    pub fn redirect_uri(&self) -> String {
        format!("{}/idp/oauth/callback", self.origin)
    }

    pub fn jwks_uri(&self) -> String {
        format!("{}/idp/jwks.json", self.origin)
    }

    /// Where D publishes its signed revocation bitmap. Certs carry this
    /// verbatim in their `status.uri`, so it must stay stable.
    pub fn status_list_uri(&self) -> String {
        format!("{}/.well-known/browserid-status", self.origin)
    }

    /// Build from environment, generating any missing key material.
    ///
    /// `origin` is the bridge's public origin; D is its host. Key
    /// generation is a *development* convenience — a generated browserid
    /// key does not match the deployed `_browserid` TXT record, so every RP
    /// in the world will reject the certs it signs. Production must inject
    /// the real key.
    pub fn from_env(origin: &str, broker_url: &str) -> Result<Self, String> {
        let domain = origin
            .trim_end_matches('/')
            .strip_prefix("https://")
            .or_else(|| origin.strip_prefix("http://"))
            .ok_or("BRIDGE_ORIGIN must be an http(s) URL")?
            .to_string();
        let key_file: PathBuf = std::env::var("IDP_KEY_FILE")
            .unwrap_or_else(|_| "idp-key.json".to_string())
            .into();
        let keypair = load_or_generate_keypair(&key_file)?;
        let oauth_key = oauth::ClientKey::from_env()?;
        Ok(Self {
            domain,
            origin: origin.trim_end_matches('/').to_string(),
            keypair,
            oauth_key,
            scope: std::env::var("IDP_OAUTH_SCOPE").unwrap_or_else(|_| OAUTH_SCOPE.to_string()),
            doh_url: std::env::var("IDP_DOH_URL")
                .unwrap_or_else(|_| "https://cloudflare-dns.com/dns-query".to_string()),
            resolve_cache: resolve::ResolveCache::default(),
            trusted_origins: trusted_origins_from_env(broker_url)?,
        })
    }
}

/// Build the device-authorize allowlist: `IDP_TRUSTED_ORIGINS` if set,
/// otherwise just the broker's origin. Empty is an error rather than a
/// silent "allow nothing", so a typo shows up at boot instead of as a
/// mysteriously broken sign-in.
fn trusted_origins_from_env(broker_url: &str) -> Result<Vec<String>, String> {
    let raw = std::env::var("IDP_TRUSTED_ORIGINS").unwrap_or_else(|_| broker_url.to_string());
    let origins: Vec<String> =
        raw.split(',').filter_map(|s| origin_of(s.trim())).collect();
    if origins.is_empty() {
        return Err(format!("no usable http(s) origin in IDP_TRUSTED_ORIGINS/BROKER_URL ({raw})"));
    }
    Ok(origins)
}

/// `https://host:port` for an http(s) URL, lowercased, no trailing slash.
/// Anything else (other schemes, garbage) yields `None`.
pub fn origin_of(url: &str) -> Option<String> {
    let (scheme, rest) = url.trim().split_once("://")?;
    let scheme = scheme.to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return None;
    }
    let authority = rest.split(['/', '?', '#']).next()?;
    // Strict charset: a host and an optional port, nothing else. The result
    // is inlined into the device-authorize page's script, so anything that
    // could carry markup or a quote must not survive.
    if authority.is_empty()
        || !authority.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | ':'))
    {
        return None;
    }
    Some(format!("{scheme}://{}", authority.to_ascii_lowercase()))
}

/// Load D's Ed25519 signing key: `IDP_SECRET` (base64url seed) beats
/// `IDP_KEY_JSON` (whole StoredKeypair document) beats the file, and a
/// missing file is generated. Same precedence and on-disk shape as the
/// browserid broker and mingo-idp, so a key made by any of them is
/// interchangeable.
pub fn load_or_generate_keypair(path: &std::path::Path) -> Result<KeyPair, String> {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let from_seed = |seed: Vec<u8>| {
        KeyPair::from_seed(&seed).map_err(|e| format!("invalid IdP key seed: {e}"))
    };

    if let Ok(secret) = std::env::var("IDP_SECRET") {
        let seed = b64.decode(secret.trim()).map_err(|e| format!("IDP_SECRET: {e}"))?;
        return from_seed(seed);
    }
    if let Ok(json) = std::env::var("IDP_KEY_JSON") {
        return from_seed(stored_seed(&json)?);
    }
    if path.exists() {
        let contents = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        return from_seed(stored_seed(&contents)?);
    }
    let kp = KeyPair::generate();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let json = serde_json::json!({ "secret_key": b64.encode(kp.secret_bytes()) });
    std::fs::write(path, serde_json::to_string_pretty(&json).unwrap())
        .map_err(|e| format!("write {}: {e}", path.display()))?;
    tracing::warn!(
        path = %path.display(),
        "generated a NEW browserid IdP key — certs signed with it will not match \
         the deployed _browserid DNS record; inject IDP_SECRET in production"
    );
    Ok(kp)
}

/// Pull the base64url seed out of a StoredKeypair JSON document.
fn stored_seed(json: &str) -> Result<Vec<u8>, String> {
    use base64::Engine;
    let v: serde_json::Value = serde_json::from_str(json).map_err(|e| format!("key JSON: {e}"))?;
    let secret = v
        .get("secret_key")
        .and_then(|s| s.as_str())
        .ok_or("key JSON missing secret_key")?;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(secret)
        .map_err(|e| format!("key JSON secret_key: {e}"))
}

/// IdP-side failures, rendered as JSON so the device-authorize page can
/// show the reason to the human (and hand it back to the dialog as
/// `browserid:device_error`).
#[derive(Debug, thiserror::Error)]
pub enum IdpError {
    #[error("not signed in")]
    NotAuthenticated,
    #[error("forbidden")]
    Forbidden,
    #[error("{0}")]
    BadRequest(String),
    /// The handle resolves to a DID other than the pinned one. Fails
    /// closed, and suspends the binding.
    #[error("{0}")]
    BindingSuspended(String),
    #[error("internal error: {0}")]
    Internal(String),
    /// This deployment runs no IdP. Answered as 404 so the bridge origin
    /// does not advertise a half-present `/.well-known/browserid`.
    #[error("not found")]
    NotConfigured,
}

impl IntoResponse for IdpError {
    fn into_response(self) -> Response {
        let status = match &self {
            IdpError::NotAuthenticated => StatusCode::UNAUTHORIZED,
            IdpError::Forbidden | IdpError::BindingSuspended(_) => StatusCode::FORBIDDEN,
            IdpError::BadRequest(_) => StatusCode::BAD_REQUEST,
            IdpError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            IdpError::NotConfigured => StatusCode::NOT_FOUND,
        };
        (status, Json(serde_json::json!({ "error": self.to_string() }))).into_response()
    }
}

impl From<crate::store::StoreError> for IdpError {
    fn from(e: crate::store::StoreError) -> Self {
        IdpError::Internal(format!("db: {e}"))
    }
}

/// Add the IdP's routes to the bridge router.
///
/// Three groups, and the distinction matters:
///
/// * **Public protocol surface** (`/.well-known/*`, the client metadata and
///   JWKS) — read by every RP and every atproto authorization server.
/// * **First-party pages and session endpoints** (`/idp/...`) — driven by
///   the human's browser, cookie-bearing, same-origin.
/// * **`/idp/access/mint`** — headless and called cross-origin by the
///   browserid dialog, so it carries permissive CORS. It needs no session:
///   the device cert *is* the credential.
pub fn routes(router: axum::Router<Arc<crate::BridgeState>>) -> axum::Router<Arc<crate::BridgeState>> {
    use axum::routing::{get, post};
    router
        .route("/.well-known/browserid", get(certs::well_known))
        .route("/.well-known/browserid-status", get(certs::status_list))
        .route("/idp/client-metadata.json", get(oauth::client_metadata))
        .route("/idp/jwks.json", get(oauth::jwks))
        .route("/idp/device-authorize", get(routes::device_authorize_page))
        .route("/idp/oauth/start", post(routes::oauth_start))
        .route("/idp/oauth/callback", get(routes::oauth_callback))
        .route("/idp/whoami", get(routes::whoami))
        .route("/idp/logout", post(routes::logout))
        .route("/idp/retire", post(routes::retire_binding))
        .route("/idp/device_cert", post(certs::device_cert))
        .route("/idp/agent_device_cert", post(certs::agent_device_cert))
        .route("/idp/access/mint", post(certs::access_mint).options(certs::mint_preflight))
}

/// Pull the IdP state out of the bridge, or report that this deployment
/// has no IdP configured.
pub fn require_idp(state: &crate::BridgeState) -> Result<&Arc<IdpState>, IdpError> {
    state.idp.as_ref().ok_or(IdpError::NotConfigured)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[test]
    fn urls_are_built_off_the_origin() {
        let st = test_state();
        assert_eq!(st.client_id(), "https://bsky.browserid.test/idp/client-metadata.json");
        assert_eq!(st.redirect_uri(), "https://bsky.browserid.test/idp/oauth/callback");
        assert_eq!(st.status_list_uri(), "https://bsky.browserid.test/.well-known/browserid-status");
    }

    #[test]
    fn trusted_origins_are_parsed_strictly() {
        // Scheme + host (+ port), lowercased, path and query dropped.
        assert_eq!(origin_of("https://Broker.Example/dialog?x=1"), Some("https://broker.example".into()));
        assert_eq!(origin_of("http://localhost:3000"), Some("http://localhost:3000".into()));
        // Userinfo would let `https://evil.com@broker.example` read as the
        // broker; the charset rejects it, along with anything that could
        // break out of the script the list is inlined into.
        assert_eq!(origin_of("https://evil.com@broker.example"), None);
        assert_eq!(origin_of("https://x\"</script><script>y"), None);
        // Only http(s) — no javascript:, no data:.
        assert_eq!(origin_of("javascript://broker.example"), None);
        assert_eq!(origin_of("broker.example"), None);
    }

    /// The allowlist must never be silently empty: an empty list means the
    /// page can deliver certs nowhere, which is a broken deployment, not a
    /// safe one, and it should announce itself at boot.
    #[test]
    fn an_unusable_allowlist_is_a_configuration_error() {
        assert!(trusted_origins_from_env("not-a-url").is_err());
        assert_eq!(
            trusted_origins_from_env("https://broker.example/").unwrap(),
            vec!["https://broker.example".to_string()]
        );
    }

    /// With no IdP configured the bridge origin must not advertise a broken
    /// browserid primary — 404, not 500.
    #[tokio::test]
    async fn an_unconfigured_deployment_answers_404() {
        let state = test_bridge();
        let state = Arc::new(crate::BridgeState { idp: None, idp_verifier: None, ..unwrap_state(state) });
        let server = axum_test::TestServer::new(crate::BridgeState::router_from(state)).unwrap();

        for path in ["/.well-known/browserid", "/.well-known/browserid-status", "/idp/device-authorize"] {
            assert_eq!(server.get(path).await.status_code(), StatusCode::NOT_FOUND, "{path}");
        }
        // The mint's preflight is gated too, so an IdP-less origin does not
        // look like one that will mint.
        let pre = server.method(axum::http::Method::OPTIONS, "/idp/access/mint").await;
        assert_eq!(pre.status_code(), StatusCode::NOT_FOUND);
    }

    /// `BridgeState` is not `Clone`; unwrap the Arc the test helper returns.
    fn unwrap_state(s: Arc<crate::BridgeState>) -> crate::BridgeState {
        Arc::try_unwrap(s).ok().expect("sole owner")
    }

    /// A bridge with the IdP enabled, for exercising the real router.
    pub(crate) fn test_bridge() -> Arc<crate::BridgeState> {
        let idp = Arc::new(test_state());
        let status_cache = std::sync::Arc::new(browserid_rp::StatusCache::new());
        Arc::new(crate::BridgeState {
            origin: idp.origin.clone(),
            handle_domain: "at.browserid.test".into(),
            broker_url: "https://broker.invalid".into(),
            broker_key: KeyPair::generate().public_key(),
            status_cache: status_cache.clone(),
            store: crate::store::Store::open_in_memory().unwrap(),
            pds: crate::pds::PdsClient::new("http://127.0.0.1:1".to_string(), "admin"),
            http: reqwest::Client::new(),
            labeler: None,
            labeler_account_password: None,
            label_tx: crate::label_channel(),
            idp_verifier: Some(crate::idp_verifier(&idp, &idp.origin, status_cache)),
            idp: Some(idp),
        })
    }

    /// Building the router is itself the assertion for route conflicts —
    /// axum panics on a duplicate path, and the IdP adds three
    /// `/.well-known/*` routes next to the bridge's existing ones.
    #[tokio::test]
    async fn the_public_documents_serve_over_the_real_router() {
        let state = test_bridge();
        let idp = state.idp.clone().unwrap();
        let server =
            axum_test::TestServer::new(crate::BridgeState::router_from(state.clone())).unwrap();

        let doc = server.get("/.well-known/browserid").await;
        doc.assert_status_ok();
        assert_eq!(doc.json::<serde_json::Value>()["device-cert"], "/idp/device_cert");

        let meta = server.get("/idp/client-metadata.json").await;
        meta.assert_status_ok();
        let meta: serde_json::Value = meta.json();
        // The client_id must be the URL this very document is served from.
        assert_eq!(meta["client_id"], idp.client_id());

        // The JWKS must contain exactly the key the client assertions name.
        let jwks: serde_json::Value = server.get("/idp/jwks.json").await.json();
        assert_eq!(jwks["keys"][0]["kid"], idp.oauth_key.kid());

        // The status list is a bare signed token, verifiable under D's key.
        let status = server.get("/.well-known/browserid-status").await;
        status.assert_status_ok();
        browserid_core::status::StatusListToken::parse(status.text().trim())
            .unwrap()
            .verify(&idp.keypair.public_key(), &idp.status_list_uri())
            .unwrap();

        // The device-authorize page is served first-party, same origin as
        // the endpoints it calls.
        server.get("/idp/device-authorize").await.assert_status_ok();
    }

    #[tokio::test]
    async fn the_mint_answers_cors_preflight() {
        // The browserid dialog calls the mint cross-origin; without the
        // preflight the whole headless path fails in the browser only.
        let server = axum_test::TestServer::new(crate::BridgeState::router_from(test_bridge()))
            .unwrap();
        let resp = server.method(axum::http::Method::OPTIONS, "/idp/access/mint").await;
        assert_eq!(resp.status_code(), axum::http::StatusCode::NO_CONTENT);
        assert_eq!(resp.header("access-control-allow-origin"), "*");
    }

    /// An IdP state with throwaway keys, for tests across the module.
    pub(crate) fn test_state() -> IdpState {
        IdpState {
            domain: "bsky.browserid.test".into(),
            origin: "https://bsky.browserid.test".into(),
            keypair: KeyPair::generate(),
            oauth_key: oauth::ClientKey::generate(),
            scope: OAUTH_SCOPE.into(),
            doh_url: "https://example.invalid/dns-query".into(),
            resolve_cache: Default::default(),
            trusted_origins: vec!["https://broker.invalid".into()],
        }
    }
}
