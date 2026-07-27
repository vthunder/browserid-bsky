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
/// once in the page; the const is what keeps the two in sync.
const TRUSTED_ORIGINS_TOKEN: &str = "__TRUSTED_ORIGINS__";

fn render_device_authorize(trusted: &[String]) -> String {
    let json = serde_json::to_string(trusted).unwrap_or_else(|_| "[]".into());
    include_str!("device-authorize.html").replace(TRUSTED_ORIGINS_TOKEN, &json)
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

fn cookie(headers: &HeaderMap, name: &str) -> Option<String> {
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
}

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
    match callback_inner(&state, st, &headers, q).await {
        Ok((sid, redirect)) => (
            [clear_flow, (header::SET_COOKIE, set_cookie(st, &sid, SESSION_TTL_HOURS * 3600))],
            redirect,
        )
            .into_response(),
        Err(e) => {
            ([clear_flow], back_to_page(&format!("error={}", urlencode(&e.to_string()))))
                .into_response()
        }
    }
}

async fn callback_inner(
    state: &S,
    st: &IdpState,
    headers: &HeaderMap,
    q: OauthCallbackQuery,
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
        return Ok((sid, back_to_page(&format!("retired={}", urlencode(&retired.join(", "))))));
    }

    let handle = flow
        .handle
        .ok_or_else(|| IdpError::Internal("flow carried no handle to claim".into()))?;
    // Pin the DID (or confirm it, or season a reassignment). A contested
    // handle fails here, and the message tells the user how to resolve it.
    pins::claim(&state.store, &handle, &flow.did)?;
    let sid = state.store.idp_create_session(Some(&handle), &flow.did, SESSION_TTL_HOURS)?;
    Ok((sid, back_to_page("signed_in=1")))
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
fn back_to_page(query: &str) -> Redirect {
    Redirect::to(&format!("/idp/device-authorize?{query}"))
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
                browser_binding: "b-old".into(),
                expires_at: Utc::now() - Duration::minutes(1),
            })
            .unwrap();
        assert!(store.idp_take_oauth_flow("old").unwrap().is_none());
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
        let e = callback_inner(&state, &st, &HeaderMap::new(), query("st-a")).await.unwrap_err();
        assert!(e.to_string().contains("did not start in this browser"), "{e}");

        // A cookie that does not match the flow's binding.
        state.store.idp_put_oauth_flow(&flow("st-b")).unwrap();
        let wrong = headers_with(&format!("{FLOW_COOKIE}=bind-2"));
        let e = callback_inner(&state, &st, &wrong, query("st-b")).await.unwrap_err();
        assert!(e.to_string().contains("did not start in this browser"), "{e}");

        // The matching cookie gets past the binding check — it then fails at
        // the code exchange, which is as far as an offline test can go, and
        // is proof the binding was not what stopped it.
        state.store.idp_put_oauth_flow(&flow("st-c")).unwrap();
        let right = headers_with(&format!("{FLOW_COOKIE}=bind-1"));
        let e = callback_inner(&state, &st, &right, query("st-c")).await.unwrap_err();
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
        let e = callback_inner(&state, &st, &headers, q).await.unwrap_err();
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
