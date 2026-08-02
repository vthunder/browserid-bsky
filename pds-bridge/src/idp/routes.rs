//! The human-facing half: the device-authorize page, the atproto OAuth
//! round trip, and the first-party session that ties them together.
//!
//! This is the seam where this IdP differs from the mingo reference it is
//! adapted from. mingo established its session from an inbound browserid
//! presentation and then asked the user to *claim* a handle; here the OAuth
//! callback establishes the session, and there is nothing left to claim —
//! atproto already proved the handle belongs to the person who just
//! authenticated. The OAuth-verified handle **is** the claim.
//!
//! The session cookie behind all this holds a handle and a DID. No access
//! token, no refresh token, no DPoP key. It exists so the device-authorize
//! page can issue certs across the OAuth redirect and one optional re-issue
//! round trip, and for nothing else.

use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::Json;
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};

use super::{oauth, pins, resolve, IdpError, IdpState, OAUTH_FLOW_TTL_MINUTES, SESSION_TTL_HOURS};
use crate::store::{IdpSession, PendingOauthFlow};
use crate::BridgeState;

type S = Arc<BridgeState>;

const SESSION_COOKIE: &str = "bsky_idp_session";

/// Marks the browser that started an OAuth flow. Not a credential on its
/// own — it is only ever compared against the value stored on the flow row,
/// which is what stops a `state` lifted from someone else's flow from being
/// redeemed in the attacker's browser.
const FLOW_COOKIE: &str = "bsky_idp_flow";

/// `GET /idp/device-authorize` — the first-party page the browserid dialog
/// opens.
///
/// The page is templated at serve time (rather than fetching a
/// `/idp/config`) for one reason: the allowlist of origins it may hand certs
/// to must arrive from the server, and inlining it means there is no window
/// in which the page has parameters but not yet its allowlist.
pub async fn device_authorize_page(State(state): State<S>) -> Response {
    let Ok(st) = super::require_idp(&state) else {
        return IdpError::NotConfigured.into_response();
    };
    Html(render_device_authorize(&st.trusted_origins)).into_response()
}

/// The placeholder the trusted-origin allowlist replaces. Present exactly
/// once in each first-party page; the const is what keeps them in sync.
const TRUSTED_ORIGINS_TOKEN: &str = "__TRUSTED_ORIGINS__";

fn render_device_authorize(trusted: &[String]) -> String {
    let json = serde_json::to_string(trusted).unwrap_or_else(|_| "[]".into());
    include_str!("device-authorize.html").replace(TRUSTED_ORIGINS_TOKEN, &json)
}

/// `GET /idp/claim` — the handle-identity claim hop the browserid dialog
/// opens (browserid-ng-tsqk). Same serve-time allowlist injection as the
/// device-authorize page, for the same reason: the attestation may only be
/// handed back to the broker's dialog origin, and the list must never be
/// fetchable-after-parameters.
pub async fn claim_page(State(state): State<S>) -> Response {
    let Ok(st) = super::require_idp(&state) else {
        return IdpError::NotConfigured.into_response();
    };
    let json = serde_json::to_string(&st.trusted_origins).unwrap_or_else(|_| "[]".into());
    Html(include_str!("claim.html").replace(TRUSTED_ORIGINS_TOKEN, &json)).into_response()
}

// ---------------------------------------------------------------------------
// Session plumbing
// ---------------------------------------------------------------------------

/// The live session behind the request's cookie.
pub fn require_session(state: &BridgeState, headers: &HeaderMap) -> Result<IdpSession, IdpError> {
    let sid = session_cookie(headers).ok_or(IdpError::NotAuthenticated)?;
    state.store.idp_session(&sid)?.ok_or(IdpError::NotAuthenticated)
}

fn session_cookie(headers: &HeaderMap) -> Option<String> {
    cookie(headers, SESSION_COOKIE)
}

pub(crate) fn cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .filter_map(|c| c.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v.to_string())
}

/// The flow-binding cookie. `SameSite=Lax` (not `None`) is deliberate: it
/// still rides the top-level redirect back from the authorization server,
/// which is the only navigation that has to carry it.
fn set_flow_cookie(st: &IdpState, token: &str, max_age: i64) -> String {
    let secure = if st.origin.starts_with("https://") { "; Secure" } else { "" };
    format!("{FLOW_COOKIE}={token}; Path=/idp; HttpOnly; Max-Age={max_age}; SameSite=Lax{secure}")
}

/// Build the `Set-Cookie` value.
///
/// `SameSite=None; Secure` because the dialog may open this page in a
/// context where the cookie is third-party. On a plain-http dev origin
/// `Secure` would make the browser drop the cookie entirely, so there we
/// fall back to `Lax`.
fn set_cookie(st: &IdpState, sid: &str, max_age: i64) -> String {
    let same_site =
        if st.origin.starts_with("https://") { "SameSite=None; Secure" } else { "SameSite=Lax" };
    format!("{SESSION_COOKIE}={sid}; Path=/; HttpOnly; Max-Age={max_age}; {same_site}")
}

#[derive(Serialize)]
pub struct WhoAmI {
    pub authenticated: bool,
    /// The signed-in handle, or `None` for a DID-only (retirement) session.
    pub handle: Option<String>,
    pub did: Option<String>,
    /// The full browserid identity string, `<handle>@<D>`.
    pub identity: Option<String>,
}

/// `GET /idp/whoami` — the session probe the device-authorize page opens with.
pub async fn whoami(State(state): State<S>, headers: HeaderMap) -> Response {
    let Ok(st) = super::require_idp(&state) else {
        return Json(WhoAmI { authenticated: false, handle: None, did: None, identity: None })
            .into_response();
    };
    match require_session(&state, &headers) {
        Ok(s) => Json(WhoAmI {
            authenticated: true,
            identity: s.handle.as_ref().map(|h| format!("{h}@{}", st.domain)),
            handle: s.handle,
            did: Some(s.did),
        })
        .into_response(),
        Err(_) => Json(WhoAmI { authenticated: false, handle: None, did: None, identity: None })
            .into_response(),
    }
}

#[derive(Deserialize)]
pub struct ResolveCheckQuery {
    /// A domain name that may or may not be an atproto handle.
    pub domain: String,
}

#[derive(Serialize)]
pub struct ResolveCheckResp {
    /// Whether the domain is a currently-valid handle binding (both
    /// resolution methods consulted, bidirectional `alsoKnownAs` check
    /// passed).
    pub valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub did: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// `GET /idp/resolve` — the broker's presence check for the authority
/// hierarchy: is this domain a resolved atproto handle binding, right now?
///
/// The answer is deliberately binary. An outage looks the same as absence
/// (`valid: false`), because the hierarchy routes on *current* state — a
/// handle we cannot resolve right now is not a binding the broker may rely
/// on, and the caller falls through to the MX step. The resolve cache (and
/// its bounded stale-on-outage fallback) smooths short outages for handles
/// we have seen recently.
///
/// This endpoint serves the broker as a trusted internal component of the
/// browserid.me fallback; everything it reports is public atproto state.
pub async fn resolve_check(
    State(state): State<S>,
    Query(q): Query<ResolveCheckQuery>,
) -> Result<Response, IdpError> {
    let st = super::require_idp(&state)?;
    let resp = match resolve::resolve_for_assurance(st, &state.http, &q.domain, true).await {
        Ok(r) => ResolveCheckResp {
            valid: true,
            handle: Some(r.handle),
            did: Some(r.did),
            reason: None,
        },
        Err(e) => ResolveCheckResp {
            valid: false,
            handle: None,
            did: None,
            reason: Some(e.to_string()),
        },
    };
    Ok(Json(resp).into_response())
}

#[derive(Serialize)]
pub struct AttestResp {
    /// The signed handle attestation, verbatim JWS.
    pub attestation: String,
    pub handle: String,
    pub did: String,
}

/// `POST /idp/attest` — sign "DID X holds handle H, verified now" for the
/// session's handle, addressed to the broker (browserid-ng-tsqk, bean 031k).
///
/// This is the bridge's half of a handle-identity claim: the broker is the
/// issuer, and this attestation — signed with D's DNSSEC-published IdP key —
/// is what it accepts in place of an SMTP verification loop. The session
/// alone is not enough to sign: the public binding is re-resolved (bounded
/// by the resolve cache) and checked against the pin, the same assurance
/// cadence the access-cert mint runs, so a session that outlives a handle
/// move cannot mint attestations for a handle its holder no longer has.
pub async fn attest(State(state): State<S>, headers: HeaderMap) -> Result<Response, IdpError> {
    let st = super::require_idp(&state)?;
    let session = require_session(&state, &headers)?;
    let handle = session.handle.clone().ok_or_else(|| {
        IdpError::BadRequest("this session holds no handle to attest".into())
    })?;

    // Fresh public state, outage-tolerant within the cadence bound.
    let resolved = resolve::resolve_for_assurance(st, &state.http, &handle, true).await?;
    if resolved.did != session.did {
        return Err(IdpError::Forbidden);
    }
    // The pin table still bounds moves and takedowns; a mismatch suspends.
    pins::verify_still_bound(&state.store, &handle, &resolved.did)?;

    let attestation = browserid_core::HandleAttestation::create(
        &st.domain,
        &broker_audience(&state.broker_url),
        &handle,
        &resolved.did,
        &st.keypair,
    )
    .map_err(|e| IdpError::Internal(format!("attestation: {e}")))?;

    Ok(Json(AttestResp {
        attestation: attestation.encoded().to_string(),
        handle,
        did: resolved.did,
    })
    .into_response())
}

/// The attestation audience: the broker's domain (host[:port]), which is
/// what the broker's own `state.domain` holds and checks against.
fn broker_audience(broker_url: &str) -> String {
    let rest = broker_url
        .trim()
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    rest.split(['/', '?', '#']).next().unwrap_or(rest).to_string()
}

/// `GET /idp/revoke-device` — the cross-issuer revocation page a
/// registrar's account UI opens (browserid-ng-ft55). Same serve-time
/// allowlist injection as the other first-party pages.
pub async fn revoke_device_page(State(state): State<S>) -> Response {
    let Ok(st) = super::require_idp(&state) else {
        return IdpError::NotConfigured.into_response();
    };
    let json = serde_json::to_string(&st.trusted_origins).unwrap_or_else(|_| "[]".into());
    Html(include_str!("revoke-device.html").replace(TRUSTED_ORIGINS_TOKEN, &json)).into_response()
}

#[derive(Deserialize)]
pub struct RevokeDeviceReq {
    /// The identity whose certs die: `<handle>@<D>` (agent sub-identities
    /// of the same handle are included — status granularity is per handle).
    pub identity: String,
}

/// `POST /idp/revoke_device` — flip the status bits for the session's
/// handle. The AUTHORITY here is the first-party session: the user just
/// proved the handle with a Bluesky sign-in, and may only revoke their own.
/// The registrar that sent them here has no say — by design.
pub async fn revoke_device(
    State(state): State<S>,
    headers: HeaderMap,
    Json(req): Json<RevokeDeviceReq>,
) -> Result<Response, IdpError> {
    let st = super::require_idp(&state)?;
    let session = require_session(&state, &headers)?;
    let session_handle = session
        .handle
        .ok_or_else(|| IdpError::BadRequest("this session holds no handle".into()))?;

    let identity = req.identity.to_lowercase();
    let (local, domain) = identity
        .rsplit_once('@')
        .ok_or_else(|| IdpError::BadRequest(format!("invalid identity: {identity}")))?;
    if !domain.eq_ignore_ascii_case(&st.domain) {
        return Err(IdpError::BadRequest(format!(
            "{identity} was not issued here — its certs are not ours to revoke"
        )));
    }
    let handle = local.split('+').next().unwrap_or(local);
    if !handle.eq_ignore_ascii_case(&session_handle) {
        return Err(IdpError::Forbidden);
    }

    let revoked = state.store.idp_revoke_status_for_handle(&session_handle)?;
    tracing::info!(handle = %session_handle, revoked, "user-initiated device revocation (cross-issuer page)");
    Ok(Json(serde_json::json!({ "revoked": revoked, "handle": session_handle })).into_response())
}

/// `POST /idp/logout` — end the session and clear the cookie.
pub async fn logout(State(state): State<S>, headers: HeaderMap) -> Response {
    let Ok(st) = super::require_idp(&state) else {
        return StatusCode::OK.into_response();
    };
    if let Some(sid) = session_cookie(&headers) {
        let _ = state.store.idp_delete_session(&sid);
    }
    ([(header::SET_COOKIE, set_cookie(st, "", 0))], Json(serde_json::json!({ "success": true })))
        .into_response()
}

// ---------------------------------------------------------------------------
// The claim flow
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct OauthStartReq {
    /// A Bluesky handle (`dan.bsky.social`) — or, for the retirement path,
    /// the DID of the account that holds the binding.
    pub identifier: String,
    /// Retire this account's handle bindings instead of claiming one.
    #[serde(default)]
    pub retire: bool,
    /// Which first-party page the callback should land on. Optional;
    /// validated against [`RETURN_PAGES`].
    #[serde(default)]
    pub return_page: Option<String>,
}

/// The only pages an OAuth callback may return to. `device-authorize` is
/// the cert-issuing sign-in; `claim` is the broker's handle-identity
/// attestation hop. The value is stored on the flow at start time and
/// interpolated into a redirect path, so the allowlist is what keeps it
/// from becoming an open-redirect (or header-injection) vector.
const RETURN_PAGES: [&str; 3] = ["device-authorize", "claim", "revoke-device"];

#[derive(Serialize)]
pub struct OauthStartResp {
    /// Where to send the browser. Top-level navigation, never an iframe.
    pub authorize_url: String,
    pub handle: Option<String>,
    pub did: String,
}

/// `POST /idp/oauth/start` — resolve the identifier and push the
/// authorization request.
///
/// Everything that can be checked *before* bothering the user happens here:
/// the handle must resolve bidirectionally, the DID must publish a PDS, and
/// that PDS must name an authorization server whose metadata agrees about
/// its own issuer. Only then does the browser leave.
pub async fn oauth_start(
    State(state): State<S>,
    Json(req): Json<OauthStartReq>,
) -> Result<Response, IdpError> {
    let st = super::require_idp(&state)?;
    let identifier = req.identifier.trim();

    let return_page = match req.return_page.as_deref() {
        None => RETURN_PAGES[0].to_string(),
        Some(p) if RETURN_PAGES.contains(&p) => p.to_string(),
        Some(p) => {
            return Err(IdpError::BadRequest(format!("unknown return_page '{p}'")));
        }
    };

    // Resolve first — both entry points end at a binding that has passed
    // the bidirectional check, so the OAuth hop always has a DID to be
    // checked against.
    let resolved = if resolve::is_did(identifier) {
        resolve::resolve_did(st, &state.http, identifier).await?
    } else {
        let r = resolve::resolve_handle(st, &state.http, identifier).await?;
        st.resolve_cache.put(r.clone());
        r
    };

    let auth_server = oauth::discover_auth_server(&resolved.pds).await?;
    // Hint with whatever the user typed: entryways accept a handle or a DID,
    // and the retirement path depends on the latter.
    let prepared =
        oauth::push_authorization_request(st, &auth_server, identifier).await?;

    // Bind the flow to this browser. The callback is a plain GET the
    // authorization server redirects to, so without this marker anyone who
    // obtains a `state` could complete the sign-in in their own browser and
    // be handed the victim's session cookie.
    let binding = oauth::random_token(24);

    state.store.idp_put_oauth_flow(&PendingOauthFlow {
        state: prepared.state.clone(),
        handle: Some(resolved.handle.clone()),
        did: resolved.did.clone(),
        issuer: auth_server.issuer.clone(),
        token_endpoint: auth_server.token_endpoint.clone(),
        code_verifier: prepared.code_verifier,
        dpop_secret: prepared.dpop_secret,
        retire: req.retire,
        return_page,
        browser_binding: binding.clone(),
        expires_at: Utc::now() + Duration::minutes(OAUTH_FLOW_TTL_MINUTES),
    })?;

    Ok((
        [(header::SET_COOKIE, set_flow_cookie(st, &binding, OAUTH_FLOW_TTL_MINUTES * 60))],
        Json(OauthStartResp {
            authorize_url: prepared.authorize_url,
            handle: Some(resolved.handle),
            did: resolved.did,
        }),
    )
        .into_response())
}

#[derive(Deserialize)]
pub struct OauthCallbackQuery {
    pub code: Option<String>,
    pub state: Option<String>,
    /// The issuer, echoed by the authorization server (RFC 9207).
    pub iss: Option<String>,
    pub error: Option<String>,
    pub error_description: Option<String>,
}

/// `GET /idp/oauth/callback` — finish the exchange and open the session.
///
/// Always lands back on the device-authorize page, success or failure: the
/// pending dialog parameters live in that page's `sessionStorage`, so it is
/// the only place that can complete (or properly abandon) the sign-in.
pub async fn oauth_callback(
    State(state): State<S>,
    headers: HeaderMap,
    Query(q): Query<OauthCallbackQuery>,
) -> Response {
    let st = match super::require_idp(&state) {
        Ok(st) => st,
        Err(e) => return e.into_response(),
    };
    // The flow cookie is spent either way — success or failure, this flow
    // is over.
    let clear_flow = (header::SET_COOKIE, set_flow_cookie(st, "", 0));
    // Which page errors land on: the flow's, once it has been read — a
    // failed claim hop must not strand the user on the device-authorize
    // page, whose sessionStorage knows nothing about it.
    let mut page = RETURN_PAGES[0].to_string();
    match callback_inner(&state, st, &headers, q, &mut page).await {
        Ok((sid, redirect)) => (
            [clear_flow, (header::SET_COOKIE, set_cookie(st, &sid, SESSION_TTL_HOURS * 3600))],
            redirect,
        )
            .into_response(),
        Err(e) => {
            ([clear_flow], back_to_page(&page, &format!("error={}", urlencode(&e.to_string()))))
                .into_response()
        }
    }
}

async fn callback_inner(
    state: &S,
    st: &IdpState,
    headers: &HeaderMap,
    q: OauthCallbackQuery,
    page: &mut String,
) -> Result<(String, Redirect), IdpError> {
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

    // Single-use: taking the flow deletes it, so a replayed callback finds
    // nothing to exchange against.
    let flow = state
        .store
        .idp_take_oauth_flow(&state_tok)?
        .ok_or_else(|| IdpError::BadRequest("this sign-in expired — start again".into()))?;
    if RETURN_PAGES.contains(&flow.return_page.as_str()) {
        *page = flow.return_page.clone();
    }

    // Is this the browser that started the flow? Checked before the code is
    // exchanged and long before any session is issued, so a `state` redeemed
    // from anywhere else buys nothing.
    let presented = cookie(headers, FLOW_COOKIE).unwrap_or_default();
    if presented.is_empty()
        || flow.browser_binding.is_empty()
        || presented != flow.browser_binding
    {
        return Err(IdpError::BadRequest(
            "this sign-in did not start in this browser — start again".into(),
        ));
    }

    // RFC 9207: if the server told us who it is, it had better be the
    // server we pushed the request to.
    if let Some(iss) = &q.iss {
        if iss.trim_end_matches('/') != flow.issuer {
            return Err(IdpError::BadRequest(format!(
                "callback issuer mismatch: expected {}, got {iss}",
                flow.issuer
            )));
        }
    }

    let auth_server = oauth::AuthServer {
        issuer: flow.issuer.clone(),
        // Only the token endpoint is needed from here; the other two have
        // already done their work.
        par_endpoint: String::new(),
        authorization_endpoint: String::new(),
        token_endpoint: flow.token_endpoint.clone(),
    };
    let dpop = oauth::DpopKey::from_secret_b64(&flow.dpop_secret)?;
    let sub =
        oauth::exchange_code(st, &auth_server, &code, &flow.code_verifier, &dpop)
            .await?;

    // THE check. The chain is handle → DID (bidirectional) → that DID's PDS
    // → its authorization server → a token whose `sub` is that same DID. If
    // `sub` is anything else, we authenticated *somebody*, but not the owner
    // of the handle being claimed, and the whole flow proves nothing.
    if sub != flow.did {
        return Err(IdpError::Forbidden);
    }

    if flow.retire {
        let retired = pins::retire_for_did(&state.store, &flow.did)?;
        let sid = state.store.idp_create_session(None, &flow.did, SESSION_TTL_HOURS)?;
        return Ok((sid, back_to_page(page, &format!("retired={}", urlencode(&retired.join(", "))))));
    }

    let handle = flow
        .handle
        .ok_or_else(|| IdpError::Internal("flow carried no handle to claim".into()))?;
    // Pin the DID (or confirm it, or season a reassignment). A contested
    // handle fails here, and the message tells the user how to resolve it.
    pins::claim(&state.store, &handle, &flow.did)?;
    let sid = state.store.idp_create_session(Some(&handle), &flow.did, SESSION_TTL_HOURS)?;
    Ok((sid, back_to_page(page, "signed_in=1")))
}

/// `POST /idp/retire` — start a voluntary retirement.
///
/// Convenience wrapper over [`oauth_start`]: the user signs in with the
/// pinned DID as the account identifier, which is the only proof that
/// releases a binding immediately rather than after the 30-day seasoning.
pub async fn retire_binding(
    State(state): State<S>,
    Json(mut req): Json<OauthStartReq>,
) -> Result<Response, IdpError> {
    req.retire = true;
    oauth_start(State(state), Json(req)).await
}

/// Bounce back to the device-authorize page with a status in the query.
/// `page` is always a [`RETURN_PAGES`] member — enforced at flow start and
/// re-checked when read back — so this cannot be steered off-origin.
fn back_to_page(page: &str, query: &str) -> Redirect {
    Redirect::to(&format!("/idp/{page}?{query}"))
}

/// Minimal percent-encoding for a query-string value. The bridge has no
/// URL-encoding dependency and these are short human-readable strings.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::idp::tests::test_state;
    use crate::store::Store;

    fn headers_with(cookie: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(header::COOKIE, cookie.parse().unwrap());
        h
    }

    #[test]
    fn session_cookie_is_found_among_others() {
        assert_eq!(
            session_cookie(&headers_with("a=1; bsky_idp_session=abc; b=2")).as_deref(),
            Some("abc")
        );
        assert_eq!(session_cookie(&headers_with("a=1")), None);
        assert_eq!(session_cookie(&HeaderMap::new()), None);
    }

    #[test]
    fn cookie_attributes_follow_the_scheme() {
        let mut st = test_state();
        // Third-party context needs SameSite=None, which browsers only
        // honour with Secure.
        assert!(set_cookie(&st, "sid", 3600).contains("SameSite=None; Secure"));
        assert!(set_cookie(&st, "sid", 3600).contains("HttpOnly"));
        // On a plain-http dev origin Secure would drop the cookie entirely.
        st.origin = "http://localhost:3200".into();
        let dev = set_cookie(&st, "sid", 3600);
        assert!(dev.contains("SameSite=Lax") && !dev.contains("Secure"));
    }

    #[test]
    fn sessions_expire_and_can_be_ended() {
        let store = Store::open_in_memory().unwrap();
        let sid = store.idp_create_session(Some("dan.bsky.social"), "did:plc:a", 12).unwrap();
        let s = store.idp_session(&sid).unwrap().unwrap();
        assert_eq!(s.handle.as_deref(), Some("dan.bsky.social"));
        assert_eq!(s.did, "did:plc:a");

        store.idp_delete_session(&sid).unwrap();
        assert!(store.idp_session(&sid).unwrap().is_none());

        // An already-expired session is not live, even though the row exists.
        let stale = store.idp_create_session(Some("dan.bsky.social"), "did:plc:a", -1).unwrap();
        assert!(store.idp_session(&stale).unwrap().is_none());
    }

    #[test]
    fn an_oauth_flow_is_single_use() {
        let store = Store::open_in_memory().unwrap();
        let flow = PendingOauthFlow {
            state: "st-1".into(),
            handle: Some("dan.bsky.social".into()),
            did: "did:plc:a".into(),
            issuer: "https://bsky.social".into(),
            token_endpoint: "https://bsky.social/oauth/token".into(),
            code_verifier: "v".into(),
            dpop_secret: "s".into(),
            retire: false,
            return_page: "device-authorize".into(),
            browser_binding: "b-1".into(),
            expires_at: Utc::now() + Duration::minutes(15),
        };
        store.idp_put_oauth_flow(&flow).unwrap();
        assert_eq!(store.idp_take_oauth_flow("st-1").unwrap().unwrap().did, "did:plc:a");
        // Replaying the same `state` finds nothing to exchange against.
        assert!(store.idp_take_oauth_flow("st-1").unwrap().is_none());
    }

    #[test]
    fn an_expired_flow_is_not_resumable() {
        let store = Store::open_in_memory().unwrap();
        store
            .idp_put_oauth_flow(&PendingOauthFlow {
                state: "old".into(),
                handle: Some("dan.bsky.social".into()),
                did: "did:plc:a".into(),
                issuer: "https://bsky.social".into(),
                token_endpoint: "https://bsky.social/oauth/token".into(),
                code_verifier: "v".into(),
                dpop_secret: "s".into(),
                retire: false,
                return_page: "device-authorize".into(),
                browser_binding: "b-old".into(),
                expires_at: Utc::now() - Duration::minutes(1),
            })
            .unwrap();
        assert!(store.idp_take_oauth_flow("old").unwrap().is_none());
    }

    /// The attest endpoint signs "DID X holds handle H" for the broker —
    /// but only for a live session whose handle still resolves to the
    /// pinned DID. Resolution is served from a seeded cache so the test
    /// runs without network.
    #[tokio::test]
    async fn attest_signs_for_a_verified_session_binding() {
        let bridge = crate::idp::tests::test_bridge();
        let idp = bridge.idp.clone().unwrap();
        let sid = bridge.store.idp_create_session(Some("dan.bsky.social"), "did:plc:dan", 12).unwrap();
        bridge.store.idp_upsert_pin("dan.bsky.social", "did:plc:dan", Utc::now()).unwrap();
        idp.resolve_cache.put(resolve::Resolved {
            handle: "dan.bsky.social".into(),
            did: "did:plc:dan".into(),
            pds: "https://pds.example".into(),
            resolved_at: Utc::now(),
        });
        let server =
            axum_test::TestServer::new(crate::BridgeState::router_from(bridge.clone())).unwrap();

        // No session → 401.
        let resp = server.post("/idp/attest").await;
        assert_eq!(resp.status_code(), StatusCode::UNAUTHORIZED);

        let resp = server
            .post("/idp/attest")
            .add_header(header::COOKIE, format!("{SESSION_COOKIE}={sid}").parse::<axum::http::HeaderValue>().unwrap())
            .await;
        resp.assert_status_ok();
        let body: serde_json::Value = resp.json();
        assert_eq!(body["handle"], "dan.bsky.social");
        assert_eq!(body["did"], "did:plc:dan");

        // The attestation verifies under D's key, addressed to the broker's
        // domain, and claims exactly the session's handle+DID.
        let att = browserid_core::HandleAttestation::parse(body["attestation"].as_str().unwrap())
            .unwrap();
        att.verify(&idp.keypair.public_key(), "broker.invalid").unwrap();
        assert_eq!(att.claims().handle, "dan.bsky.social");
        assert_eq!(att.claims().did, "did:plc:dan");
        assert_eq!(att.claims().iss, idp.domain);
    }

    /// A session that outlives a handle move must not mint attestations:
    /// the cached resolution now answers a different DID than the pin.
    #[tokio::test]
    async fn attest_refuses_when_the_handle_moved() {
        let bridge = crate::idp::tests::test_bridge();
        let idp = bridge.idp.clone().unwrap();
        let sid = bridge.store.idp_create_session(Some("dan.bsky.social"), "did:plc:old", 12).unwrap();
        bridge.store.idp_upsert_pin("dan.bsky.social", "did:plc:old", Utc::now()).unwrap();
        // The public binding now answers a NEW DID.
        idp.resolve_cache.put(resolve::Resolved {
            handle: "dan.bsky.social".into(),
            did: "did:plc:new".into(),
            pds: "https://pds.example".into(),
            resolved_at: Utc::now(),
        });
        let server =
            axum_test::TestServer::new(crate::BridgeState::router_from(bridge.clone())).unwrap();

        let resp = server
            .post("/idp/attest")
            .add_header(header::COOKIE, format!("{SESSION_COOKIE}={sid}").parse::<axum::http::HeaderValue>().unwrap())
            .await;
        // Forbidden before the pin machinery even runs: resolved != session.
        assert_eq!(resp.status_code(), StatusCode::FORBIDDEN);
    }

    /// Cross-issuer revocation (browserid-ng-ft55): the endpoint's
    /// authority is the first-party session, scoped to the session's own
    /// handle — a registrar can send the user here but can never revoke by
    /// itself, and one user can never revoke another's certs.
    #[tokio::test]
    async fn revoke_device_is_session_scoped_and_flips_the_status_list() {
        let bridge = crate::idp::tests::test_bridge();
        let identity = "dan.bsky.social@bsky.browserid.test";
        // Allocate status slots the way issuance does: one for the identity,
        // one for an agent sub-identity, one for a bystander.
        let own = bridge.store.idp_status_idx(identity).unwrap();
        let agent = bridge.store.idp_status_idx("dan.bsky.social+poster@bsky.browserid.test").unwrap();
        let other = bridge.store.idp_status_idx("alice.bsky.social@bsky.browserid.test").unwrap();
        let sid = bridge.store.idp_create_session(Some("dan.bsky.social"), "did:plc:dan", 12).unwrap();
        let server =
            axum_test::TestServer::new(crate::BridgeState::router_from(bridge.clone())).unwrap();
        let cookie = format!("{SESSION_COOKIE}={sid}").parse::<axum::http::HeaderValue>().unwrap();

        // No session → 401.
        let resp = server.post("/idp/revoke_device").json(&serde_json::json!({ "identity": identity })).await;
        assert_eq!(resp.status_code(), StatusCode::UNAUTHORIZED);

        // Someone else's identity → 403, nothing flipped.
        let resp = server
            .post("/idp/revoke_device")
            .add_header(header::COOKIE, cookie.clone())
            .json(&serde_json::json!({ "identity": "alice.bsky.social@bsky.browserid.test" }))
            .await;
        assert_eq!(resp.status_code(), StatusCode::FORBIDDEN);

        // An identity we did not issue → 400.
        let resp = server
            .post("/idp/revoke_device")
            .add_header(header::COOKIE, cookie.clone())
            .json(&serde_json::json!({ "identity": "me@dan.bsky.social" }))
            .await;
        assert_eq!(resp.status_code(), StatusCode::BAD_REQUEST);

        // The session's own identity: revokes it AND its agent sub-identities,
        // never the bystander.
        let resp = server
            .post("/idp/revoke_device")
            .add_header(header::COOKIE, cookie)
            .json(&serde_json::json!({ "identity": identity }))
            .await;
        resp.assert_status_ok();
        let (revoked, _max) = bridge.store.idp_revoked_status_indices().unwrap();
        assert!(revoked.contains(&own) && revoked.contains(&agent));
        assert!(!revoked.contains(&other));
    }

    /// The claim page ships its allowlist server-side, like the
    /// device-authorize page — no placeholder may survive into a browser.
    #[tokio::test]
    async fn the_claim_page_carries_the_server_side_allowlist() {
        let server = axum_test::TestServer::new(crate::BridgeState::router_from(
            crate::idp::tests::test_bridge(),
        ))
        .unwrap();
        let resp = server.get("/idp/claim").await;
        resp.assert_status_ok();
        let page = resp.text();
        assert!(page.contains(r#"TRUSTED_ORIGINS = ["https://broker.invalid"]"#));
        assert!(!page.contains(TRUSTED_ORIGINS_TOKEN));
        assert!(page.contains("TRUSTED_ORIGINS.indexOf(returnOrigin) === -1"));
    }

    #[test]
    fn broker_audience_is_the_hostport() {
        assert_eq!(broker_audience("https://browserid.me"), "browserid.me");
        assert_eq!(broker_audience("http://localhost:3000/"), "localhost:3000");
        assert_eq!(broker_audience("https://broker.example/path?q=1"), "broker.example");
    }

    /// The broker's hierarchy check: absence, malformed input, and
    /// an unresolvable handle all read as `valid: false` — the binary
    /// answer the claim-routing rule needs — while a missing IdP is 404 so
    /// a broker misconfigured against an IdP-less bridge fails loudly
    /// rather than reading every domain as "not a handle".
    #[tokio::test]
    async fn resolve_check_answers_binary() {
        let server = axum_test::TestServer::new(crate::BridgeState::router_from(
            crate::idp::tests::test_bridge(),
        ))
        .unwrap();

        // Not a domain at all.
        let resp = server.get("/idp/resolve").add_query_param("domain", "dan").await;
        resp.assert_status_ok();
        let body: serde_json::Value = resp.json();
        assert_eq!(body["valid"], false);

        // Domain-shaped but unresolvable (the test state's DoH endpoint is
        // .invalid and no well-known answers): still a clean false.
        let resp =
            server.get("/idp/resolve").add_query_param("domain", "nosuch.handle.invalid").await;
        resp.assert_status_ok();
        assert_eq!(resp.json::<serde_json::Value>()["valid"], false);
    }

    /// Finding #1. The page must learn its allowlist from the server, and
    /// the placeholder must never survive into what a browser runs.
    #[test]
    fn the_page_carries_the_server_side_allowlist() {
        let page = render_device_authorize(&["https://broker.example".to_string()]);
        assert!(page.contains(r#"TRUSTED_ORIGINS = ["https://broker.example"]"#));
        assert!(!page.contains(TRUSTED_ORIGINS_TOKEN));
        // The check itself, not just the value, has to be in there.
        assert!(page.contains("TRUSTED_ORIGINS.indexOf(returnOrigin) === -1"));
    }

    /// The OAuth hop makes the popup look CLOSED to the dialog (COOP severs
    /// the handle), so the page must announce the coming handoff before it
    /// navigates — over postMessage to the opener, since the dialog is a
    /// different origin than this page and BroadcastChannel would never reach
    /// it — and the announcement must precede the navigation, not follow it.
    #[test]
    fn the_page_announces_the_pending_handoff_before_the_oauth_navigation() {
        let page = render_device_authorize(&["https://broker.example".to_string()]);
        let announce = page
            .find("type: 'browserid:device_auth_pending'")
            .expect("the page announces the pending handoff");
        let navigate = page
            .find("location.href = res.body.authorize_url;")
            .expect("the page navigates to the authorize URL");
        assert!(announce < navigate, "the announcement must precede the navigation");
        // It rides window.opener.postMessage, aimed at the validated origin.
        assert!(page.contains("window.opener.postMessage("));
        assert!(page.contains("{ type: 'browserid:device_auth_pending', device_pubkey: params.device_pubkey },"));
        // The dialog pairs on the device key, so it must carry one, and agent
        // mode (no resume handoff) must not announce.
        assert!(page.contains("if (window.opener && params.device_pubkey && !params.agent_email) {"));
    }

    /// browserid-bsky-3l4g. The OAuth hop navigates the popup itself, and the
    /// PDS's COOP severs `window.opener` — so the return leg must hand the
    /// certs back by redirecting to the dialog's resume URL instead of giving
    /// up, and that redirect must go to the ALLOWLISTED return origin with the
    /// certs in the fragment (a query would put them in server logs).
    #[test]
    fn the_page_hands_certs_back_by_resume_redirect_when_the_opener_is_gone() {
        let page = render_device_authorize(&["https://broker.example".to_string()]);
        assert!(page.contains("var RESUME_PATH = '/dialog/dialog.html?resume=device_auth';"));
        // The fallback is reached exactly when there is no opener...
        assert!(page.contains("location.replace(returnOrigin + RESUME_PATH + resultFragment(payload));"));
        // ...and it targets the validated origin, not the raw fragment value.
        assert!(!page.contains("params.return_origin + RESUME_PATH"));
        // Certs ride the fragment.
        assert!(page.contains("return '#device_cert=' + encodeURIComponent(payload.device_cert) +"));
        // A failure carries no cert, so it names the device key it was given —
        // without that the dialog cannot tell which of its concurrent sign-in
        // windows the failure belongs to, and would tear down the wrong one.
        assert!(page.contains(
            "return '#device_error=' + encodeURIComponent(payload.reason || 'refused') +"
        ));
        assert!(page.contains("&device_pubkey=' + encodeURIComponent(params.device_pubkey)"));
        // The dead-opener message survives for payloads with no resume form.
        assert!(page.contains("The sign-in dialog window is gone"));
    }

    /// Finding #2. Every string this page shows comes from the URL fragment
    /// or the network, so none of it may reach the DOM as markup.
    #[test]
    fn the_page_never_assigns_html() {
        let page = include_str!("device-authorize.html");
        for sink in ["innerHTML", "outerHTML", "insertAdjacentHTML", "document.write"] {
            // The word appears once, in the comment explaining why it must not.
            let uses = page.matches(sink).count() - usize::from(sink == "innerHTML");
            assert_eq!(uses, 0, "{sink} is used in device-authorize.html");
        }
    }

    /// Finding #3. A `state` is not enough: the callback must arrive in the
    /// browser that started the flow, or no session is issued.
    #[tokio::test]
    async fn a_callback_from_another_browser_is_refused() {
        let state = crate::idp::tests::test_bridge();
        let st = state.idp.clone().unwrap();
        let flow = |s: &str| PendingOauthFlow {
            state: s.into(),
            handle: Some("dan.bsky.social".into()),
            did: "did:plc:a".into(),
            issuer: "https://bsky.social".into(),
            token_endpoint: "https://bsky.social/oauth/token".into(),
            code_verifier: "v".into(),
            dpop_secret: "s".into(),
            retire: false,
            return_page: "device-authorize".into(),
            browser_binding: "bind-1".into(),
            expires_at: Utc::now() + Duration::minutes(15),
        };
        let query = |s: &str| OauthCallbackQuery {
            code: Some("c".into()),
            state: Some(s.into()),
            iss: None,
            error: None,
            error_description: None,
        };

        // No cookie at all — the attacker's browser never visited
        // /idp/oauth/start.
        state.store.idp_put_oauth_flow(&flow("st-a")).unwrap();
        let e = callback_inner(&state, &st, &HeaderMap::new(), query("st-a"), &mut String::new()).await.unwrap_err();
        assert!(e.to_string().contains("did not start in this browser"), "{e}");

        // A cookie that does not match the flow's binding.
        state.store.idp_put_oauth_flow(&flow("st-b")).unwrap();
        let wrong = headers_with(&format!("{FLOW_COOKIE}=bind-2"));
        let e = callback_inner(&state, &st, &wrong, query("st-b"), &mut String::new()).await.unwrap_err();
        assert!(e.to_string().contains("did not start in this browser"), "{e}");

        // The matching cookie gets past the binding check — it then fails at
        // the code exchange, which is as far as an offline test can go, and
        // is proof the binding was not what stopped it.
        state.store.idp_put_oauth_flow(&flow("st-c")).unwrap();
        let right = headers_with(&format!("{FLOW_COOKIE}=bind-1"));
        let e = callback_inner(&state, &st, &right, query("st-c"), &mut String::new()).await.unwrap_err();
        assert!(!e.to_string().contains("did not start in this browser"), "{e}");
    }

    /// A pre-existing flow row (written before the binding column existed)
    /// must not be redeemable with an empty cookie.
    #[tokio::test]
    async fn an_unbound_flow_is_never_redeemable() {
        let state = crate::idp::tests::test_bridge();
        let st = state.idp.clone().unwrap();
        state
            .store
            .idp_put_oauth_flow(&PendingOauthFlow {
                state: "legacy".into(),
                handle: Some("dan.bsky.social".into()),
                did: "did:plc:a".into(),
                issuer: "https://bsky.social".into(),
                token_endpoint: "https://bsky.social/oauth/token".into(),
                code_verifier: "v".into(),
                dpop_secret: "s".into(),
                retire: false,
                return_page: "device-authorize".into(),
                browser_binding: String::new(),
                expires_at: Utc::now() + Duration::minutes(15),
            })
            .unwrap();
        let headers = headers_with(&format!("{FLOW_COOKIE}="));
        let q = OauthCallbackQuery {
            code: Some("c".into()),
            state: Some("legacy".into()),
            iss: None,
            error: None,
            error_description: None,
        };
        let e = callback_inner(&state, &st, &headers, q, &mut String::new()).await.unwrap_err();
        assert!(e.to_string().contains("did not start in this browser"), "{e}");
    }

    #[test]
    fn the_flow_cookie_stays_first_party() {
        let st = test_state();
        let c = set_flow_cookie(&st, "tok", 900);
        assert!(c.contains("HttpOnly") && c.contains("Secure"));
        // Lax, not None: it only has to survive the top-level redirect back
        // from the authorization server.
        assert!(c.contains("SameSite=Lax"));
    }

    #[test]
    fn query_values_are_escaped() {
        assert_eq!(urlencode("dan.bsky.social"), "dan.bsky.social");
        assert_eq!(urlencode("a b&c=d"), "a+b%26c%3Dd");
    }
}
