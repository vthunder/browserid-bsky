//! The connect flow: a second, higher-scope authorization of an account the
//! user has *already* proved once.
//!
//! Phase 1 is deliberately bare — a page with a button, and endpoints that
//! answer JSON so the whole thing is drivable with curl. The dashboard
//! (phase 2) and the consent copy in our own words are UI over the boundary
//! argued here; nothing about the security of this file depends on them.
//!
//! The security crux is [`connect_callback`]: **the DID the user
//! authenticated as must equal the DID already pinned for the handle they
//! are signed in as.** Without that check a user could complete the connect
//! hop as a *different* Bluesky account, and the bridge would then relay
//! posts attributed to `dan.bsky.social` into a stranger's repo. Everything
//! else in this module exists to make sure that check has something true to
//! compare against.

use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::Json;
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::idp::oauth::{random_token, AuthServer};
use crate::idp::{resolve, IdpError, IdpState};
use crate::store::{PendingWriteFlow, WriteSession};
use crate::BridgeState;

use super::oauth::{
    exchange_write_code, push_write_authorization_request, write_client_metadata_doc,
    TokenError, WriteDpopKey, WRITE_SCOPE,
};
use super::{RelayState, CONNECT_FLOW_TTL_MINUTES};

type S = Arc<BridgeState>;

/// Ties a connect flow to the browser that started it — same reasoning as
/// the identity flow's cookie: the callback is a plain GET the authorization
/// server redirects to, so a `state` obtained by any other means must not be
/// redeemable elsewhere.
const CONNECT_COOKIE: &str = "bsky_write_connect";

/// Pull out the relay, or answer as an origin that simply has no such
/// surface.
///
/// `NotConfigured` (404), not a 400 explaining itself: the sibling IdP
/// endpoints already answer 404 when the IdP is off, so that an origin
/// running neither does not advertise a half-present feature. A relay-less
/// deployment should be indistinguishable from one that never heard of the
/// relay.
pub(crate) fn require_relay(
    state: &BridgeState,
) -> Result<(&Arc<IdpState>, &RelayState), IdpError> {
    let idp = crate::idp::require_idp(state)?;
    let relay = state.relay.as_ref().ok_or(IdpError::NotConfigured)?;
    Ok((idp, relay))
}

/// Refuse a request that a *cross-site* page could have caused a browser to
/// send with the victim's cookies attached.
///
/// Both state-changing endpoints here are cookie-authenticated POSTs with no
/// request body, and the IdP session cookie is `SameSite=None` (it has to
/// be — the browserid dialog may open the device-authorize page in a
/// third-party context). That combination is exactly what CSRF eats: a
/// hidden form on any site could disconnect a signed-in victim's write
/// session, or spam pending-flow rows.
///
/// The rest of `idp/routes.rs` is protected only *incidentally* — its POSTs
/// take a JSON body, and axum's `Json` extractor rejects the
/// `application/x-www-form-urlencoded` content-type a cross-site form is
/// limited to. Relying on that here would be copying an accident, so this is
/// explicit. Three accepted shapes, in order:
///
/// 1. **Fetch metadata**, which every current browser sends and no page can
///    forge: `Sec-Fetch-Site: same-origin` passes, anything else fails.
/// 2. **`Origin`**, for browsers predating fetch metadata: it must be our
///    own origin. Browsers have sent `Origin` on cross-origin POSTs for
///    years, so a *present but foreign* value is a definite refusal.
/// 3. **Neither header at all** — not a browser. A deliberate client (curl,
///    the phase-1 smoke path) must then say `Content-Type: application/json`,
///    which a cross-site HTML form cannot produce and a cross-site `fetch`
///    cannot send without a CORS preflight we never answer. So the escape
///    hatch for non-browsers is not an escape hatch for attackers.
pub(crate) fn require_same_origin(st: &IdpState, headers: &HeaderMap) -> Result<(), IdpError> {
    let get = |name: &str| headers.get(name).and_then(|v| v.to_str().ok()).map(str::trim);

    if let Some(site) = get("sec-fetch-site") {
        return if site.eq_ignore_ascii_case("same-origin") {
            Ok(())
        } else {
            Err(IdpError::Forbidden)
        };
    }
    if let Some(origin) = get("origin") {
        return if crate::idp::origin_of(origin).as_deref() == Some(st.origin.as_str()) {
            Ok(())
        } else {
            Err(IdpError::Forbidden)
        };
    }
    match get("content-type") {
        // `application/json; charset=utf-8` is the same thing.
        Some(ct) if ct.split(';').next().unwrap_or("").trim().eq_ignore_ascii_case("application/json") => Ok(()),
        _ => Err(IdpError::BadRequest(
            "this endpoint changes state, so it must arrive same-origin or carry an explicit \
             `Content-Type: application/json` — a cross-site form can do neither"
                .into(),
        )),
    }
}

pub fn routes(
    router: axum::Router<Arc<BridgeState>>,
) -> axum::Router<Arc<BridgeState>> {
    use axum::routing::{get, post};
    use super::dashboard;
    router
        .route("/idp/write-client-metadata.json", get(write_client_metadata))
        .route("/idp/connect/start", post(connect_start))
        .route("/idp/connect/callback", get(connect_callback))
        .route("/idp/connect/status", get(connect_status))
        .route("/idp/connect/disconnect", post(disconnect))
        .route("/dashboard", get(dashboard::page))
        .route("/dashboard/login", post(dashboard::login))
        .route("/dashboard/logout", post(dashboard::logout))
        .route("/dashboard/me", get(dashboard::me))
        .route("/dashboard/mint", post(dashboard::mint))
        .route("/dashboard/agents", get(dashboard::agents))
}

/// The human behind this request — from the dashboard's own session
/// (phase 2, the normal way in) or, failing that, from the IdP session the
/// device-authorize page sets. Both are first-party proofs of the same
/// identity class; the connect flow accepts either so a person who just
/// signed into the dashboard is not asked to authenticate a second time on
/// the very next click.
pub(crate) fn require_human_session(
    state: &BridgeState,
    headers: &HeaderMap,
) -> Result<crate::store::IdpSession, IdpError> {
    // Precedence note: a live dashboard cookie wins outright, even if an IdP
    // session cookie for a *different* handle is also present — the connect
    // endpoints then act on the dashboard identity. Both cookies are the
    // same person's first-party proofs, and every downstream step re-derives
    // authority from that identity's pin and allowlist, so this is a UX
    // surprise (which handle a stray old cookie picks), never a boundary
    // crossing.
    if let Some(sid) = crate::idp::routes::cookie(headers, super::dashboard::DASHBOARD_COOKIE) {
        if let Some(s) = state.store.dashboard_session(&sid)? {
            // An email sign-in has no DID here — nothing for the connect
            // endpoints to act on — so it does not count as a human session
            // for them; fall through to the IdP cookie instead.
            if let Some(did) = s.did {
                return Ok(crate::store::IdpSession {
                    handle: s.handle,
                    did,
                    expires_at: s.expires_at,
                });
            }
        }
    }
    crate::idp::routes::require_session(state, headers)
}

/// `GET /idp/write-client-metadata.json` — the **write** client's metadata
/// document, at the URL that is its `client_id`.
pub async fn write_client_metadata(State(state): State<S>) -> Response {
    match require_relay(&state) {
        Ok((_, relay)) => Json(write_client_metadata_doc(&relay.client)).into_response(),
        Err(_) => IdpError::NotConfigured.into_response(),
    }
}

// ---------------------------------------------------------------------------
// Status
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct ConnectStatus {
    pub authenticated: bool,
    pub handle: Option<String>,
    pub did: Option<String>,
    /// Is this identity permitted to connect at all (design doc, Decision 6)?
    pub allowed: bool,
    /// Is a write session attached right now?
    pub connected: bool,
    pub connected_at: Option<String>,
    pub access_expires_at: Option<String>,
    pub state: Option<String>,
    pub scope: Option<String>,
}

/// `GET /idp/connect/status` — "is writing connected?", answerable without
/// posting anything.
pub async fn connect_status(State(state): State<S>, headers: HeaderMap) -> Response {
    let Ok((_, relay)) = require_relay(&state) else {
        return IdpError::NotConfigured.into_response();
    };
    let Ok(session) = require_human_session(&state, &headers) else {
        return Json(ConnectStatus {
            authenticated: false,
            handle: None,
            did: None,
            allowed: false,
            connected: false,
            connected_at: None,
            access_expires_at: None,
            state: None,
            scope: None,
        })
        .into_response();
    };
    let handle = session.handle.clone().unwrap_or_default();
    let allowed = relay.allowlist.permits(&handle, &session.did);
    // Reading the row needs the AEAD key, which is exactly the point: a
    // deployment without one cannot answer this at all.
    let stored = state.store.write_session(&relay.secrets, &session.did).ok().flatten();
    Json(ConnectStatus {
        authenticated: true,
        handle: session.handle,
        did: Some(session.did),
        allowed,
        connected: stored.is_some(),
        connected_at: stored.as_ref().map(|s| s.created_at.to_rfc3339()),
        access_expires_at: stored.as_ref().map(|s| s.access_expires_at.to_rfc3339()),
        state: stored.as_ref().map(|s| s.state.as_str().to_string()),
        scope: stored.as_ref().map(|s| s.scope.clone()),
    })
    .into_response()
}

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------
// There is no interstitial connect page (UX revamp, option 1e): the
// dashboard's own button POSTs `/idp/connect/start` and navigates straight
// to the authorization server, with the consent fine print living in a
// disclosure on the dashboard card. The endpoints are still curl-drivable.

#[derive(Serialize)]
pub struct ConnectStartResp {
    pub authorize_url: String,
    pub handle: String,
    /// The DID the callback will insist the token's `sub` equals.
    pub expected_did: String,
}

fn set_flow_cookie(origin: &str, token: &str, max_age: i64) -> String {
    let secure = if origin.starts_with("https://") { "; Secure" } else { "" };
    format!("{CONNECT_COOKIE}={token}; Path=/idp; HttpOnly; Max-Age={max_age}; SameSite=Lax{secure}")
}

/// `POST /idp/connect/start` — begin the write authorization.
///
/// The gates, in order, and all of them before the browser leaves:
///
/// 1. the caller is signed in **as a handle identity** (a DID-only
///    retirement session cannot connect anything);
/// 2. that identity is on the allowlist (*Decision 6*);
/// 3. the handle has a live, unsuspended pin — the DID we will hold the
///    callback to;
/// 4. the handle still resolves *bidirectionally* to that same DID right
///    now, so we are not about to authorize a handle that has since moved.
pub async fn connect_start(
    State(state): State<S>,
    headers: HeaderMap,
) -> Result<Response, IdpError> {
    let (idp, relay) = require_relay(&state)?;
    // Before the session is even looked at: this POST carries no body, and
    // the IdP session cookie is SameSite=None.
    require_same_origin(idp, &headers)?;
    let session = require_human_session(&state, &headers)?;
    let handle = session.handle.clone().ok_or_else(|| {
        IdpError::BadRequest(
            "connecting write access needs a handle sign-in, not a DID-only session".into(),
        )
    })?;

    // The allowlist. Empty permits nobody, by construction.
    if !relay.allowlist.permits(&handle, &session.did) {
        tracing::info!(%handle, "write-relay connect refused: not allowlisted");
        return Err(IdpError::Forbidden);
    }

    // The pin is the authority on which account this identity *is*. Not the
    // session's DID alone, and never anything from the request.
    let pin = state
        .store
        .idp_pin(&handle)?
        .ok_or_else(|| IdpError::BadRequest(format!("{handle} has no pinned account")))?;
    if pin.suspended {
        return Err(IdpError::BindingSuspended(format!(
            "the binding for {handle} is suspended; it cannot connect write access"
        )));
    }
    if pin.did != session.did {
        // The session outlived a reassignment. Refuse rather than connect
        // whichever of the two we happen to like better.
        return Err(IdpError::Forbidden);
    }

    // Re-resolve now: the pin says who this identity is, and this says the
    // handle still points there. Both must agree before we ask the user's
    // PDS for write access.
    let resolved = resolve::resolve_handle(idp, &state.http, &handle).await?;
    if resolved.did != pin.did {
        return Err(IdpError::BindingSuspended(format!(
            "{handle} now resolves to {} rather than the pinned {}",
            resolved.did, pin.did
        )));
    }
    idp.resolve_cache.put(resolved.clone());

    // The PDS endpoint came out of a DID document, which the account holder
    // controls — so it is validated here, on ingest, before it is stored and
    // long before the post path uses it. `discover_auth_server` guards it
    // again as part of fetching its metadata; this call makes the check
    // explicit rather than incidental, because what gets stored is what the
    // relay will POST to for the life of the session.
    crate::idp::net::guard_external_url(&resolved.pds).await?;
    let auth_server = crate::idp::oauth::discover_auth_server(&resolved.pds).await?;
    // Hint with the DID, not the handle: it is the account we mean, stated
    // in the form that cannot drift.
    let prepared = push_write_authorization_request(
        &relay.client,
        &idp.oauth_key,
        &relay.nonces,
        &auth_server,
        &pin.did,
    )
    .await?;

    let binding = random_token(24);
    state.store.write_put_oauth_flow(&PendingWriteFlow {
        state: prepared.state.clone(),
        handle: handle.clone(),
        did: pin.did.clone(),
        pds: resolved.pds.clone(),
        issuer: auth_server.issuer.clone(),
        token_endpoint: auth_server.token_endpoint.clone(),
        code_verifier: prepared.code_verifier,
        dpop_secret: prepared.dpop_secret,
        browser_binding: binding.clone(),
        expires_at: Utc::now() + Duration::minutes(CONNECT_FLOW_TTL_MINUTES),
    })?;

    Ok((
        [(
            header::SET_COOKIE,
            set_flow_cookie(&idp.origin, &binding, CONNECT_FLOW_TTL_MINUTES * 60),
        )],
        Json(ConnectStartResp {
            authorize_url: prepared.authorize_url,
            handle,
            expected_did: pin.did,
        }),
    )
        .into_response())
}

// ---------------------------------------------------------------------------
// Callback — the security crux
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct ConnectCallbackQuery {
    pub code: Option<String>,
    pub state: Option<String>,
    pub iss: Option<String>,
    pub error: Option<String>,
    pub error_description: Option<String>,
}

pub async fn connect_callback(
    State(state): State<S>,
    headers: HeaderMap,
    Query(q): Query<ConnectCallbackQuery>,
) -> Response {
    let Ok((idp, _)) = require_relay(&state) else {
        return IdpError::NotConfigured.into_response();
    };
    let clear = (header::SET_COOKIE, set_flow_cookie(&idp.origin, "", 0));
    // Land back on the dashboard (which is where the flow started — the
    // interstitial page is gone); it shows the outcome inline on the
    // "Where your posts land" card.
    match connect_callback_inner(&state, &headers, q).await {
        Ok(handle) => {
            ([clear], Redirect::to(&format!("/dashboard?connected={}", urlencode(&handle))))
                .into_response()
        }
        Err(e) => ([clear], Redirect::to(&format!("/dashboard?error={}", urlencode(&e.to_string()))))
            .into_response(),
    }
}

/// Finish the write authorization and store the session.
///
/// Returns the connected handle (what the dashboard shows the user). Every
/// early return leaves **nothing** stored.
pub(crate) async fn connect_callback_inner(
    state: &S,
    headers: &HeaderMap,
    q: ConnectCallbackQuery,
) -> Result<String, IdpError> {
    let (idp, relay) = require_relay(state)?;

    if let Some(err) = q.error {
        let detail = q.error_description.unwrap_or_default();
        return Err(IdpError::BadRequest(format!(
            "the authorization server refused: {err}{}{detail}",
            if detail.is_empty() { "" } else { " — " }
        )));
    }
    let (code, state_tok) = q
        .code
        .zip(q.state)
        .ok_or_else(|| IdpError::BadRequest("the callback carried no code".into()))?;

    // Single-use: taking the flow deletes it.
    let flow = state
        .store
        .write_take_oauth_flow(&state_tok)?
        .ok_or_else(|| IdpError::BadRequest("this connect flow expired — start again".into()))?;

    // Same browser that started it.
    let presented = crate::idp::routes::cookie(headers, CONNECT_COOKIE).unwrap_or_default();
    if presented.is_empty()
        || flow.browser_binding.is_empty()
        || presented != flow.browser_binding
    {
        return Err(IdpError::BadRequest(
            "this connect flow did not start in this browser — start again".into(),
        ));
    }

    // RFC 9207.
    if let Some(iss) = &q.iss {
        if iss.trim_end_matches('/') != flow.issuer {
            return Err(IdpError::BadRequest(format!(
                "callback issuer mismatch: expected {}, got {iss}",
                flow.issuer
            )));
        }
    }

    // Re-read the pin. The flow captured a DID minutes ago; if the binding
    // moved or was suspended in the meantime, connecting it now would attach
    // write credentials to an identity we no longer certify.
    let pin = state
        .store
        .idp_pin(&flow.handle)?
        .ok_or_else(|| IdpError::BadRequest(format!("{} is no longer pinned", flow.handle)))?;
    if pin.suspended || pin.did != flow.did {
        return Err(IdpError::Forbidden);
    }
    // And the allowlist, again — a session started before someone was removed
    // must not land after.
    if !relay.allowlist.permits(&flow.handle, &pin.did) {
        return Err(IdpError::Forbidden);
    }

    let auth_server = AuthServer {
        issuer: flow.issuer.clone(),
        par_endpoint: String::new(),
        authorization_endpoint: String::new(),
        token_endpoint: flow.token_endpoint.clone(),
    };
    let dpop = WriteDpopKey::from_secret_b64(&flow.dpop_secret)?;
    let tokens = exchange_write_code(
        &relay.client,
        &idp.oauth_key,
        &relay.nonces,
        &auth_server,
        &code,
        &flow.code_verifier,
        &dpop,
    )
    .await
    .map_err(|e| match e {
        TokenError::GrantRejected(m) => IdpError::BadRequest(m),
        TokenError::Other(e) => e,
    })?;

    // ── THE CHECK ──────────────────────────────────────────────────────────
    // The authorization server proved that *somebody* authenticated. This is
    // what makes it the right somebody. `login_hint` steered the account
    // picker; it does not bind the answer, so without this a user could
    // connect a Bluesky account that is not the one their grantor handle
    // stands for — and every post the bridge relayed "as dan.bsky.social"
    // would land in a stranger's repo.
    if tokens.sub != pin.did {
        tracing::warn!(
            handle = %flow.handle, expected = %pin.did, got = %tokens.sub,
            "write-relay connect refused: the authorized account is not the pinned one"
        );
        return Err(IdpError::BadRequest(format!(
            "that sign-in authorized {} , but {} is pinned to {}. Connect the account the \
             handle actually belongs to.",
            tokens.sub, flow.handle, pin.did
        )));
    }
    // ───────────────────────────────────────────────────────────────────────

    let expires = Utc::now() + Duration::seconds(tokens.expires_in.max(0));
    state.store.write_session_put(
        &relay.secrets,
        &WriteSession {
            did: pin.did.clone(),
            handle: flow.handle.clone(),
            identity: format!("{}@{}", flow.handle, idp.domain),
            pds: flow.pds.clone(),
            issuer: flow.issuer.clone(),
            token_endpoint: flow.token_endpoint.clone(),
            access_token: tokens.access_token,
            refresh_token: tokens.refresh_token,
            dpop_secret: flow.dpop_secret.clone(),
            dpop_nonce: None,
            scope: if tokens.scope.is_empty() { WRITE_SCOPE.to_string() } else { tokens.scope },
            access_expires_at: expires,
            created_at: Utc::now(),
            state: crate::store::WriteSessionState::Live,
        },
    )?;
    tracing::info!(handle = %flow.handle, did = %pin.did, "write-relay session connected");
    Ok(flow.handle)
}

// ---------------------------------------------------------------------------
// Disconnect
// ---------------------------------------------------------------------------

/// `POST /idp/connect/disconnect` — drop the stored session.
///
/// A convenience, not a security control, and the copy should not sell it as
/// one: it is performed by the party the user would be protecting themselves
/// from (design doc, *Revocation*). The control against a misbehaving agent
/// is warrant revocation; the control against a breached bridge is
/// disconnecting the app at the user's own PDS.
pub async fn disconnect(State(state): State<S>, headers: HeaderMap) -> Result<Response, IdpError> {
    let (idp, _) = require_relay(&state)?;
    require_same_origin(idp, &headers)?;
    let session = require_human_session(&state, &headers)?;
    state.store.write_session_delete(&session.did)?;
    Ok((StatusCode::OK, Json(serde_json::json!({ "disconnected": true }))).into_response())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::relay::RelayState;
    use chrono::Utc;

    /// A bridge with the IdP and a relay allowlisting `dan.bsky.social`.
    pub(crate) fn bridge_with_relay(allowlist: &str) -> S {
        let base = crate::idp::tests::test_bridge();
        let origin = base.origin.clone();
        let mut state =
            Arc::try_unwrap(base).ok().expect("sole owner of the test bridge");
        state.relay = Some(RelayState::for_test(&origin, allowlist));
        Arc::new(state)
    }

    /// A token endpoint that answers with whatever `sub` the test names —
    /// i.e. "somebody really did authenticate", which is exactly the
    /// situation the pinned-DID check exists to survive.
    async fn mock_token_endpoint(sub: &'static str) -> String {
        use axum::routing::post;
        let app = axum::Router::new().route(
            "/token",
            post(move || async move {
                Json(serde_json::json!({
                    "sub": sub,
                    "access_token": "acc",
                    "refresh_token": "ref",
                    "expires_in": 3600,
                    "token_type": "DPoP",
                    "scope": WRITE_SCOPE,
                }))
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("{base}/token")
    }

    fn headers_with(cookie: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(header::COOKIE, cookie.parse().unwrap());
        h
    }

    fn query(state_tok: &str) -> ConnectCallbackQuery {
        ConnectCallbackQuery {
            code: Some("the-code".into()),
            state: Some(state_tok.into()),
            iss: None,
            error: None,
            error_description: None,
        }
    }

    async fn stage_flow(state: &S, state_tok: &str, token_endpoint: &str, pinned: &str) {
        state.store.idp_upsert_pin("dan.bsky.social", pinned, Utc::now()).unwrap();
        state
            .store
            .write_put_oauth_flow(&PendingWriteFlow {
                state: state_tok.into(),
                handle: "dan.bsky.social".into(),
                did: pinned.into(),
                pds: "https://shard.example".into(),
                issuer: "https://bsky.social".into(),
                token_endpoint: token_endpoint.into(),
                code_verifier: "v".into(),
                dpop_secret: WriteDpopKey::generate().to_secret_b64(),
                browser_binding: "bind-1".into(),
                expires_at: Utc::now() + Duration::minutes(15),
            })
            .unwrap();
    }

    /// **The security crux.** The OAuth hop succeeded — somebody really
    /// authenticated — but as a different Bluesky account than the one the
    /// grantor handle is pinned to. Accepting that would let a user attach
    /// *someone else's* repo to their own browserid identity, and every post
    /// relayed "as dan.bsky.social" would land in a stranger's account.
    #[tokio::test]
    async fn a_connect_whose_sub_is_not_the_pinned_did_stores_nothing() {
        let state = bridge_with_relay("dan.bsky.social");
        let endpoint = mock_token_endpoint("did:plc:someone-else").await;
        stage_flow(&state, "st-1", &endpoint, "did:plc:pinned").await;

        let e = connect_callback_inner(&state, &headers_with("bsky_write_connect=bind-1"), query("st-1"))
            .await
            .unwrap_err();
        assert!(e.to_string().contains("did:plc:someone-else"), "{e}");
        assert!(e.to_string().contains("did:plc:pinned"), "the message names what was expected: {e}");

        // Nothing was stored — not under either DID.
        assert!(!state.store.write_session_exists("did:plc:pinned").unwrap());
        assert!(!state.store.write_session_exists("did:plc:someone-else").unwrap());
    }

    /// The same flow with a matching `sub` stores the session — proof that
    /// the mismatch above was refused by the DID check and not by some
    /// unrelated failure earlier in the callback.
    #[tokio::test]
    async fn a_connect_whose_sub_matches_the_pinned_did_is_stored_encrypted() {
        let state = bridge_with_relay("dan.bsky.social");
        let relay = state.relay.as_ref().unwrap();
        let endpoint = mock_token_endpoint("did:plc:pinned").await;
        stage_flow(&state, "st-ok", &endpoint, "did:plc:pinned").await;

        let handle =
            connect_callback_inner(&state, &headers_with("bsky_write_connect=bind-1"), query("st-ok"))
                .await
                .unwrap();
        assert_eq!(handle, "dan.bsky.social", "the callback answers with the handle the dashboard shows");

        let stored = state.store.write_session(&relay.secrets, "did:plc:pinned").unwrap().unwrap();
        assert_eq!(stored.handle, "dan.bsky.social");
        assert_eq!(stored.identity, "dan.bsky.social@bsky.browserid.test");
        assert_eq!(stored.access_token, "acc");
        assert_eq!(stored.pds, "https://shard.example");
        assert_eq!(stored.scope, WRITE_SCOPE);
        // On disk it is ciphertext, even for the row we just wrote.
        let (acc, _, _) = state.store.write_session_raw_secrets("did:plc:pinned").unwrap();
        assert!(!acc.windows(3).any(|w| w == b"acc"));
    }

    /// The allowlist is re-checked at the callback, so a flow started before
    /// someone was removed cannot land after (*Decision 6*).
    #[tokio::test]
    async fn a_callback_for_a_non_allowlisted_identity_is_refused() {
        for allowlist in ["", "someone.else.social"] {
            let state = bridge_with_relay(allowlist);
            let endpoint = mock_token_endpoint("did:plc:pinned").await;
            stage_flow(&state, "st-x", &endpoint, "did:plc:pinned").await;
            let e = connect_callback_inner(
                &state,
                &headers_with("bsky_write_connect=bind-1"),
                query("st-x"),
            )
            .await
            .unwrap_err();
            assert!(matches!(e, IdpError::Forbidden), "allowlist {allowlist:?}: {e}");
            assert!(!state.store.write_session_exists("did:plc:pinned").unwrap());
        }
    }

    /// A pin that moved or was suspended between start and callback must not
    /// gain a write session — that would attach posting credentials to an
    /// identity the IdP no longer certifies.
    #[tokio::test]
    async fn a_binding_that_died_mid_flow_cannot_be_connected() {
        let state = bridge_with_relay("dan.bsky.social");
        let endpoint = mock_token_endpoint("did:plc:pinned").await;

        stage_flow(&state, "st-susp", &endpoint, "did:plc:pinned").await;
        state.store.idp_set_pin_suspended("dan.bsky.social", true).unwrap();
        assert!(matches!(
            connect_callback_inner(&state, &headers_with("bsky_write_connect=bind-1"), query("st-susp"))
                .await
                .unwrap_err(),
            IdpError::Forbidden
        ));

        // Reassigned to a different DID while the browser was away.
        stage_flow(&state, "st-moved", &endpoint, "did:plc:pinned").await;
        state.store.idp_upsert_pin("dan.bsky.social", "did:plc:other", Utc::now()).unwrap();
        assert!(matches!(
            connect_callback_inner(&state, &headers_with("bsky_write_connect=bind-1"), query("st-moved"))
                .await
                .unwrap_err(),
            IdpError::Forbidden
        ));
        assert!(!state.store.write_session_exists("did:plc:pinned").unwrap());
    }

    /// Same defence as the identity flow: a `state` redeemed from any other
    /// browser buys nothing, and the check runs before the code is exchanged.
    #[tokio::test]
    async fn a_callback_from_another_browser_is_refused() {
        let state = bridge_with_relay("dan.bsky.social");
        let endpoint = mock_token_endpoint("did:plc:pinned").await;

        stage_flow(&state, "st-a", &endpoint, "did:plc:pinned").await;
        let e = connect_callback_inner(&state, &HeaderMap::new(), query("st-a")).await.unwrap_err();
        assert!(e.to_string().contains("did not start in this browser"), "{e}");

        stage_flow(&state, "st-b", &endpoint, "did:plc:pinned").await;
        let e = connect_callback_inner(&state, &headers_with("bsky_write_connect=wrong"), query("st-b"))
            .await
            .unwrap_err();
        assert!(e.to_string().contains("did not start in this browser"), "{e}");
        assert!(!state.store.write_session_exists("did:plc:pinned").unwrap());
    }

    /// Starting requires a handle sign-in, allowlist membership, and a pin —
    /// checked before the browser is sent anywhere.
    #[tokio::test]
    async fn connect_start_gates_on_sign_in_and_the_allowlist() {
        // Every call here is same-origin — this test is about the identity
        // gates, not the CSRF gate, which runs first and has its own test.
        let same_origin = |cookie: &str| {
            let mut h = if cookie.is_empty() {
                HeaderMap::new()
            } else {
                headers_with(cookie)
            };
            h.insert("sec-fetch-site", "same-origin".parse().unwrap());
            h
        };
        let state = bridge_with_relay("dan.bsky.social");
        // Not signed in at all.
        let e = connect_start(State(state.clone()), same_origin("")).await.unwrap_err();
        assert!(matches!(e, IdpError::NotAuthenticated), "{e}");

        // Signed in, but as a DID-only (retirement) session.
        let sid = state.store.idp_create_session(None, "did:plc:pinned", 1).unwrap();
        let e = connect_start(State(state.clone()), same_origin(&format!("bsky_idp_session={sid}")))
            .await
            .unwrap_err();
        assert!(e.to_string().contains("handle sign-in"), "{e}");

        // Signed in as a handle that is not allowlisted.
        let other = bridge_with_relay("someone.else");
        other.store.idp_upsert_pin("dan.bsky.social", "did:plc:pinned", Utc::now()).unwrap();
        let sid = other.store.idp_create_session(Some("dan.bsky.social"), "did:plc:pinned", 1).unwrap();
        let e = connect_start(State(other), same_origin(&format!("bsky_idp_session={sid}")))
            .await
            .unwrap_err();
        assert!(matches!(e, IdpError::Forbidden), "{e}");

        // Allowlisted but with no pin: refused before any network call.
        let sid = state.store.idp_create_session(Some("dan.bsky.social"), "did:plc:pinned", 1).unwrap();
        let e = connect_start(State(state), same_origin(&format!("bsky_idp_session={sid}")))
            .await
            .unwrap_err();
        assert!(e.to_string().contains("no pinned account"), "{e}");
    }

    /// CSRF. Both state-changing endpoints are cookie-authed POSTs with no
    /// body, and the IdP session cookie is `SameSite=None`, so a hidden form
    /// on any site would otherwise be able to drive them with the victim's
    /// cookies attached — disconnecting a signed-in user's write session, or
    /// spamming pending-flow rows.
    #[tokio::test]
    async fn a_cross_site_post_cannot_drive_the_state_changing_endpoints() {
        let state = bridge_with_relay("dan.bsky.social");
        state.store.idp_upsert_pin("dan.bsky.social", "did:plc:pinned", Utc::now()).unwrap();
        crate::relay::tests_support::insert_live_session(
            &state,
            "dan.bsky.social",
            "did:plc:pinned",
            "https://shard.example",
        );
        let sid =
            state.store.idp_create_session(Some("dan.bsky.social"), "did:plc:pinned", 1).unwrap();
        let cookie = format!("bsky_idp_session={sid}");
        let server = axum_test::TestServer::new(crate::BridgeState::router_from(state.clone())).unwrap();

        // Every shape a cross-site page can produce, against both endpoints.
        let hostile: [&[(&str, &str)]; 4] = [
            // A plain HTML form: browsers send Sec-Fetch-Site: cross-site
            // and a form content-type.
            &[("sec-fetch-site", "cross-site"), ("content-type", "application/x-www-form-urlencoded")],
            // Same, from a document merely on a sibling site.
            &[("sec-fetch-site", "same-site")],
            // An older browser that sends Origin but no fetch metadata.
            &[("origin", "https://evil.example")],
            // A form content-type with no metadata at all.
            &[("content-type", "text/plain")],
        ];
        for path in ["/idp/connect/start", "/idp/connect/disconnect"] {
            for headers in hostile {
                let mut req = server.post(path).add_header(header::COOKIE, cookie.clone());
                for (k, v) in headers {
                    req = req.add_header(*k, *v);
                }
                let status = req.await.status_code();
                assert!(
                    status == StatusCode::FORBIDDEN || status == StatusCode::BAD_REQUEST,
                    "{path} accepted a cross-site POST with {headers:?} ({status})"
                );
            }
        }
        // The victim's session survived every one of those attempts.
        assert!(state.store.write_session_exists("did:plc:pinned").unwrap());
    }

    /// ...and the legitimate calls still work. Two shapes have to keep
    /// working: the page's same-origin `fetch`, and a deliberate non-browser
    /// client saying `Content-Type: application/json`.
    #[tokio::test]
    async fn same_origin_and_explicit_json_callers_still_get_through() {
        let state = bridge_with_relay("dan.bsky.social");
        state.store.idp_upsert_pin("dan.bsky.social", "did:plc:pinned", Utc::now()).unwrap();
        let sid =
            state.store.idp_create_session(Some("dan.bsky.social"), "did:plc:pinned", 1).unwrap();
        let cookie = format!("bsky_idp_session={sid}");

        for allowed in [
            vec![("sec-fetch-site", "same-origin")],
            vec![("origin", "https://bsky.browserid.test")],
            vec![("content-type", "application/json; charset=utf-8")],
        ] {
            crate::relay::tests_support::insert_live_session(
                &state,
                "dan.bsky.social",
                "did:plc:pinned",
                "https://shard.example",
            );
            let server =
                axum_test::TestServer::new(crate::BridgeState::router_from(state.clone())).unwrap();
            let mut req = server
                .post("/idp/connect/disconnect")
                .add_header(header::COOKIE, cookie.clone());
            for (k, v) in &allowed {
                req = req.add_header(*k, *v);
            }
            req.await.assert_status_ok();
            assert!(
                !state.store.write_session_exists("did:plc:pinned").unwrap(),
                "{allowed:?} should have disconnected"
            );
        }
    }

    /// A relay-less origin answers 404 everywhere, including the two POSTs —
    /// it must not be distinguishable from an origin that never had a relay.
    #[tokio::test]
    async fn a_relay_less_origin_answers_404_on_every_relay_route() {
        let server =
            axum_test::TestServer::new(crate::BridgeState::router_from(crate::idp::tests::test_bridge()))
                .unwrap();
        for path in ["/idp/connect/start", "/idp/connect/disconnect"] {
            let resp = server.post(path).add_header("content-type", "application/json").await;
            assert_eq!(resp.status_code(), StatusCode::NOT_FOUND, "{path}");
        }
        assert_eq!(server.get("/idp/connect/status").await.status_code(), StatusCode::NOT_FOUND);
    }

    /// A deployment with no relay must not serve a write client document —
    /// publishing a `client_id` we cannot honour would leave a dangling
    /// OAuth client on users' app-connections pages.
    #[tokio::test]
    async fn a_bridge_without_a_relay_serves_no_write_client() {
        let server =
            axum_test::TestServer::new(crate::BridgeState::router_from(crate::idp::tests::test_bridge()))
                .unwrap();
        assert_eq!(
            server.get("/idp/write-client-metadata.json").await.status_code(),
            StatusCode::NOT_FOUND
        );
    }

    /// With a relay, the write client's document is served at the URL that
    /// *is* its `client_id`, next to (and distinct from) the identity
    /// client's.
    #[tokio::test]
    async fn the_two_client_documents_are_served_side_by_side() {
        let state = bridge_with_relay("dan.bsky.social");
        let server = axum_test::TestServer::new(crate::BridgeState::router_from(state)).unwrap();

        let write: serde_json::Value = server.get("/idp/write-client-metadata.json").await.json();
        let identity: serde_json::Value = server.get("/idp/client-metadata.json").await.json();
        assert_eq!(write["client_id"], "https://bsky.browserid.test/idp/write-client-metadata.json");
        assert_ne!(write["client_id"], identity["client_id"]);
        assert_eq!(write["jwks_uri"], identity["jwks_uri"], "one key, two clients");
        assert!(write["scope"].as_str().unwrap().contains("transition:generic"));
        assert!(!identity["scope"].as_str().unwrap().contains("transition"));
    }
}

/// Minimal percent-encoding for a query-string value (the bridge carries no
/// URL-encoding dependency; these are short, human-readable strings).
fn urlencode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            b' ' => "+".to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}
