//! The dashboard — the demo's web front door (write-relay phase 2).
//!
//! `bsky.browserid.me/dashboard` is where a human signs in *as their Bluesky
//! handle*, connects (or disconnects) write access, reads which agents hold
//! warrants in their name, and copies the delegation prompt their agent
//! needs. It is an ordinary browserid **RP**: the page calls
//! `navigator.id.request()`, the browser hands back a presentation, and
//! [`login`] verifies it in-process against the IdP this same deployment
//! runs. Its session is a plain first-party cookie, deliberately separate
//! from `idp_sessions` (design doc, open question 1 — decided): that table
//! serves the IdP's device-authorize page across the OAuth redirect; this
//! one serves a human reading a management page.
//!
//! Everything here is UI over the phase-1 boundary. Nothing on these routes
//! can write to a repo, mint a cert, or widen a scope; the security-bearing
//! checks stay where they were argued (`relay/routes.rs`, `relay/mod.rs`).
//! The two checks this file does own:
//!
//! 1. **Login accepts only a first-party presentation.** An agent's
//!    warrant-carrying presentation is refused — a warrant says "may post",
//!    never "is the person". Our own IdP's handle identities verify
//!    in-process; any other identity (an email, for the mint-a-handle flow)
//!    verifies through the hosted verifier and opens a session with no
//!    handle or DID attached.
//! 2. **The DID in the session comes from `idp_pins`**, never from the
//!    presentation (which does not carry one) and never from the request.

use std::sync::Arc;

use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::Json;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use rand::RngCore;
use serde::Deserialize;

use crate::idp::{IdpError, SESSION_TTL_HOURS};
use crate::store::DashboardSession;
use crate::BridgeState;

use super::routes::{require_relay, require_same_origin};

type S = Arc<BridgeState>;

pub(crate) const DASHBOARD_COOKIE: &str = "bsky_dashboard";

/// First-party only: the page and its fetches. `Lax`, not `None` — nothing
/// here is ever legitimately third-party, so don't make it available to be.
fn set_session_cookie(origin: &str, sid: &str, max_age: i64) -> String {
    let secure = if origin.starts_with("https://") { "; Secure" } else { "" };
    format!("{DASHBOARD_COOKIE}={sid}; Path=/; HttpOnly; Max-Age={max_age}; SameSite=Lax{secure}")
}

/// The live dashboard session behind the request's cookie.
fn session(state: &BridgeState, headers: &HeaderMap) -> Result<DashboardSession, IdpError> {
    let sid = crate::idp::routes::cookie(headers, DASHBOARD_COOKIE)
        .ok_or(IdpError::NotAuthenticated)?;
    state.store.dashboard_session(&sid)?.ok_or(IdpError::NotAuthenticated)
}

// ---------------------------------------------------------------------------
// The page
// ---------------------------------------------------------------------------

/// The placeholder the broker origin replaces — the page needs it for
/// `include.js` and for the "manage & revoke" link to the registrar's
/// account page.
const BROKER_TOKEN: &str = "__BROKER_ORIGIN__";
const IDP_DOMAIN_TOKEN: &str = "__IDP_DOMAIN__";
const HANDLE_DOMAIN_TOKEN: &str = "__HANDLE_DOMAIN__";
/// The shared stylesheet (`ui::BASE_CSS`) is substituted in whole, so the
/// dashboard and the server-rendered pages share one visual system.
const BASE_CSS_TOKEN: &str = "__BASE_CSS__";

fn render_dashboard(broker_url: &str, idp_domain: &str, handle_domain: &str) -> String {
    // The operator-config values are not attacker-influenced — but they
    // land inside `src=`/`href=` attributes and a `<code>` body, so a stray
    // quote in a mistyped `BROKER_URL` must break the page, not the
    // attribute. Escape rather than trust the config to be clean. The CSS is
    // a trusted compile-time constant and is substituted verbatim.
    include_str!("dashboard.html")
        .replace(BASE_CSS_TOKEN, crate::ui::BASE_CSS)
        .replace(BROKER_TOKEN, &html_escape(broker_url.trim_end_matches('/')))
        .replace(IDP_DOMAIN_TOKEN, &html_escape(idp_domain))
        .replace(HANDLE_DOMAIN_TOKEN, &html_escape(handle_domain))
}

/// Escape the five characters that matter inside an HTML attribute or text
/// node. Enough for the operator-config substitutions above; not a
/// general-purpose sanitizer (the page never assigns untrusted markup).
fn html_escape(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '&' => "&amp;".into(),
            '<' => "&lt;".into(),
            '>' => "&gt;".into(),
            '"' => "&quot;".into(),
            '\'' => "&#x27;".into(),
            other => other.to_string(),
        })
        .collect()
}

/// `frame-ancestors 'none'` on the HTML surfaces: clickjacking on
/// "Disconnect" is already defanged by `SameSite=Lax` (a framed page's
/// fetch arrives cookieless), but denying framing outright is free.
const FRAME_DENY: (header::HeaderName, &str) =
    (header::CONTENT_SECURITY_POLICY, "frame-ancestors 'none'");

/// `GET /dashboard` — the page. 404 when the relay is off: phase 2 lands
/// inert behind the same gate as everything else in this module.
pub async fn page(State(state): State<S>) -> Response {
    let Ok((idp, _)) = require_relay(&state) else {
        return IdpError::NotConfigured.into_response();
    };
    ([FRAME_DENY], Html(render_dashboard(&state.broker_url, &idp.domain, &state.handle_domain)))
        .into_response()
}

// ---------------------------------------------------------------------------
// Login / logout
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct LoginReq {
    /// The access presentation `navigator.id` produced, audience = this
    /// origin.
    pub presentation: String,
    /// The identity the page *asked* the dialog for, via a directed
    /// `provisionEmail` request (`<handle>@<D>`). Absent on the undirected
    /// "or use any email" path.
    ///
    /// `provisionEmail` steers the dialog; it does not bind what comes back
    /// (design doc, *Sign-in*). This is not an authorization input — the
    /// session is always opened for the *cryptographically verified*
    /// identity — but when the two disagree the sign-in is refused rather
    /// than silently completing as an identity the user did not type. So a
    /// forged `expected` can only make a request *fail*, never redirect it.
    #[serde(default)]
    pub expected: Option<String>,
}

/// `POST /dashboard/login` — verify the presentation, open the session.
///
/// Two classes of identity sign in here. Our own IdP's handle identities
/// (`<handle>@<D>`) are verified in-process against the pinned key. Any
/// other identity — an email, issued elsewhere — is verified the long way,
/// through the hosted verifier, and opens a session with no handle or DID:
/// its management surface is the mint-a-handle card and its own warrants
/// (UX revamp, mint flow).
pub async fn login(
    State(state): State<S>,
    headers: HeaderMap,
    Json(req): Json<LoginReq>,
) -> Result<Response, IdpError> {
    let (idp, _) = require_relay(&state)?;
    // A cookie-planting forced-login CSRF is otherwise blocked only
    // incidentally (the JSON extractor a cross-site form cannot satisfy);
    // guard it explicitly, for parity with logout and connect.
    require_same_origin(idp, &headers)?;

    let verified = match crate::routes::verify_locally(&state, &req.presentation).await {
        Some(Ok(v)) => v,
        // Ours and bad: the verifier's refusal (a Response) is the answer.
        Some(Err(resp)) => return Ok(resp),
        // Not ours — an email identity. One verification algorithm, running
        // where it is maintained; a bad presentation's refusal is the answer.
        None => match crate::routes::verify_presentation(&state, &req.presentation).await {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        },
    };

    // A human signing in as themself, not an agent holding a warrant. The
    // presentation formats are the same; the difference is exactly this
    // field, and conflating them would let anyone a user delegated
    // *posting* to walk into their management page.
    if verified.grantee != verified.grantor {
        return Err(IdpError::BadRequest(
            "that is an agent's delegated presentation — the dashboard needs the account \
             holder's own sign-in"
                .into(),
        ));
    }
    // `grantee == grantor` is necessary but NOT sufficient: the IdP mints an
    // "as-you" agent cert whose identity IS the handle itself (`local ==
    // handle` at idp/certs.rs:266), so such an agent can present a warrant
    // with grantor == grantee == the handle identity and clear the check
    // above. That agent holds only posting scopes, though, and a human's
    // plain dialog login carries none — `login` is dropped by the scope
    // grammar. So a presentation carrying ANY bridge-grammar scope is an
    // agent's, not the account holder's, and must not open a management
    // session.
    if verified.scopes.iter().any(|s| crate::scopes::Scope::parse(s).is_some()) {
        return Err(IdpError::BadRequest(
            "that presentation carries agent scopes — the dashboard needs the account \
             holder's own plain sign-in, not a delegated warrant"
                .into(),
        ));
    }
    let identity = verified.grantor;

    // The directed-login match check (design doc, *Sign-in*: "the dashboard
    // must still verify the identity in the returned presentation equals the
    // one it asked for"). The dialog is *supposed* to drive exactly the
    // `provisionEmail` identity straight through, so a mismatch means either
    // the user picked a different account at some prompt or the steer was not
    // honoured — either way, opening a session as an identity they did not
    // type is a surprise, so refuse and name both. Case-insensitive: both
    // sides are identity strings, minted lowercase.
    if let Some(expected) = req.expected.as_deref() {
        if !expected.eq_ignore_ascii_case(&identity) {
            return Err(IdpError::BadRequest(format!(
                "you asked to sign in as {expected}, but that authorized {identity}. \
                 Sign in again as {expected}, or use the \"any email\" option."
            )));
        }
    }

    // A handle identity carries the DID pinned for it; an email identity
    // carries neither — its session manages the mint card and its warrants.
    let (handle, did) = if let Some(h) = identity.strip_suffix(&format!("@{}", idp.domain)) {
        // Legacy bridge-minted shape: the handle is the local part. The pin
        // is the authority on which account this identity is. No pin, no
        // session: this shape's whole point is the DID behind it.
        let handle = h.to_ascii_lowercase();
        let pin = state
            .store
            .idp_pin(&handle)?
            .ok_or_else(|| IdpError::BadRequest(format!("{handle} has no pinned account")))?;
        if pin.suspended {
            return Err(IdpError::BindingSuspended(format!(
                "the binding for {handle} is suspended; sign in again once it is re-verified"
            )));
        }
        (Some(handle), Some(pin.did))
    } else if let Some((_, domain)) = identity.rsplit_once('@') {
        // Native handle-identity shape (browserid-ng-tsqk): the handle IS
        // the domain, pinned by the broker's claim hop. A domain with no
        // pin here is an ordinary email identity — mint card + warrants.
        let handle = domain.to_ascii_lowercase();
        match state.store.idp_pin(&handle)? {
            Some(pin) if pin.suspended => {
                return Err(IdpError::BindingSuspended(format!(
                    "the binding for {handle} is suspended; sign in again once it is re-verified"
                )));
            }
            Some(pin) => (Some(handle), Some(pin.did)),
            None => (None, None),
        }
    } else {
        (None, None)
    };

    let sid = state.store.dashboard_create_session(
        &identity,
        handle.as_deref(),
        did.as_deref(),
        SESSION_TTL_HOURS,
    )?;
    tracing::info!(%identity, "dashboard sign-in");
    Ok((
        [(header::SET_COOKIE, set_session_cookie(&idp.origin, &sid, SESSION_TTL_HOURS * 3600))],
        Json(serde_json::json!({
            "identity": identity,
            "handle": handle,
            "did": did,
        })),
    )
        .into_response())
}

/// `POST /dashboard/logout` — end the session, clear the cookie.
pub async fn logout(State(state): State<S>, headers: HeaderMap) -> Result<Response, IdpError> {
    let (idp, _) = require_relay(&state)?;
    // Cookie-authed POST with no body — same CSRF exposure as the connect
    // endpoints, same guard.
    require_same_origin(idp, &headers)?;
    if let Some(sid) = crate::idp::routes::cookie(&headers, DASHBOARD_COOKIE) {
        state.store.dashboard_delete_session(&sid)?;
    }
    Ok((
        [(header::SET_COOKIE, set_session_cookie(&idp.origin, "", 0))],
        Json(serde_json::json!({ "success": true })),
    )
        .into_response())
}

// ---------------------------------------------------------------------------
// Who am I, and what is connected
// ---------------------------------------------------------------------------

/// `GET /dashboard/me` — everything the page needs to render its state:
/// the signed-in identity (and whether it is a handle or an email), whether
/// it may connect (allowlist), whether a write session is attached, any
/// bridge account it owns (the mint flow's state), and the copyable
/// delegation prompt.
pub async fn me(State(state): State<S>, headers: HeaderMap) -> Response {
    let Ok((_, relay)) = require_relay(&state) else {
        return IdpError::NotConfigured.into_response();
    };
    let Ok(sess) = session(&state, &headers) else {
        return Json(serde_json::json!({ "authenticated": false })).into_response();
    };
    let allowed = match (&sess.handle, &sess.did) {
        (Some(h), Some(d)) => relay.allowlist.permits(h, d),
        _ => false,
    };
    let stored = sess
        .did
        .as_ref()
        .and_then(|d| state.store.write_session(&relay.secrets, d).ok().flatten());
    // The account this identity owns on the bridge PDS, if any — for an
    // email sign-in this is what decides mint card vs. minted card, and it
    // is what unlocks the prompt.
    let account = state.store.account_by_email(&sess.identity).ok().flatten();
    Json(serde_json::json!({
        "authenticated": true,
        "identity": sess.identity,
        "kind": if sess.handle.is_some() { "handle" } else { "email" },
        "handle": sess.handle,
        "did": sess.did,
        "allowed": allowed,
        "connected": stored.is_some(),
        "write_state": stored.as_ref().map(|s| s.state.as_str()),
        "access_expires_at": stored.as_ref().map(|s| s.access_expires_at.to_rfc3339()),
        "connected_at": stored.as_ref().map(|s| s.created_at.to_rfc3339()),
        "account_handle": account.as_ref().map(|a| a.handle.clone()),
        "account_did": account.as_ref().map(|a| a.did.clone()),
        "prompt": delegation_prompt(&state.origin, &sess.identity),
    }))
    .into_response()
}

/// The personalized delegation prompt (design doc, *The personalized
/// delegation prompt*): plain text, the grantor named, nothing hidden. The
/// identity comes from the authenticated session — never from a query
/// parameter — and what renders is exactly what the agent will read. Built
/// on [`crate::guide::agent_prompt`] so the two can never drift.
fn delegation_prompt(origin: &str, identity: &str) -> String {
    format!("{} Act for {identity}.", crate::guide::agent_prompt(origin))
}

// ---------------------------------------------------------------------------
// Mint a handle (UX revamp, option 2c)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct MintReq {
    /// The desired label (the part before `.{handle_domain}`).
    pub handle: String,
}

/// `POST /dashboard/mint` — open a bridge account for the signed-in email
/// identity, **passwordless**: the PDS demands a password at creation, so
/// one is generated and discarded. The human signs in here — and manages
/// the account — with their browserid; their agent posts through warrants
/// only. Nothing to leak, nothing to rotate (bean azxl is removing password
/// login from the PDS altogether).
pub async fn mint(
    State(state): State<S>,
    headers: HeaderMap,
    Json(req): Json<MintReq>,
) -> Result<Response, IdpError> {
    let (idp, _) = require_relay(&state)?;
    // Cookie-authenticated state-changing POST — same CSRF guard as its
    // siblings.
    require_same_origin(idp, &headers)?;
    let sess = session(&state, &headers)?;
    // Minting is the email path's bootstrap. A handle sign-in stands for a
    // real Bluesky account; its path is connecting write access, not opening
    // a second account here.
    if sess.handle.is_some() {
        return Err(IdpError::BadRequest(
            "you signed in with a Bluesky handle — connect write access to that account \
             instead of minting a new one"
                .into(),
        ));
    }

    let label = req
        .handle
        .trim()
        .trim_start_matches('@')
        .trim_end_matches(&format!(".{}", state.handle_domain))
        .to_lowercase();
    if !crate::routes::valid_label(&label) || crate::RESERVED_LABELS.contains(&label.as_str()) {
        return Err(IdpError::BadRequest("that handle label is not available".into()));
    }
    let handle = format!("{label}.{}", state.handle_domain);

    let conflict = |msg: &str| {
        (StatusCode::CONFLICT, Json(serde_json::json!({ "error": msg }))).into_response()
    };
    match (state.store.account_by_email(&sess.identity), state.store.handle_taken(&handle)) {
        (Ok(Some(a)), _) => {
            return Ok(conflict(&format!("you already own @{} here", a.handle)));
        }
        (Ok(None), Ok(true)) => return Ok(conflict("that handle is taken")),
        (Ok(None), Ok(false)) => {}
        (Err(e), _) | (_, Err(e)) => return Err(IdpError::Internal(e.to_string())),
    }

    // The password exists only because account creation demands one. It is
    // never returned and never stored: a password would bypass warrant
    // scoping entirely, and this account's whole point is that it has no
    // credential to leak.
    let mut pw = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut pw);
    let password = URL_SAFE_NO_PAD.encode(pw);

    let invite = state
        .pds
        .create_invite_code()
        .await
        .map_err(|e| IdpError::Internal(e.to_string()))?;
    let created = state
        .pds
        .create_account(&handle, &sess.identity, &password, &invite)
        .await
        .map_err(|e| IdpError::Internal(e.to_string()))?;
    state
        .store
        .insert_account(&crate::store::Account {
            email: sess.identity.clone(),
            did: created.did.clone(),
            handle: created.handle.clone(),
            access_jwt: created.access_jwt,
            refresh_jwt: created.refresh_jwt,
        })
        .map_err(|e| IdpError::Internal(e.to_string()))?;
    tracing::info!(identity = %sess.identity, handle = %created.handle, "dashboard mint");

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "did": created.did,
            "handle": created.handle,
        })),
    )
        .into_response())
}

// ---------------------------------------------------------------------------
// The management surface: who acts in my name
// ---------------------------------------------------------------------------

/// `GET /dashboard/agents` — the signed-in grantor's delegation ledger:
/// every warrant the bridge has seen naming them (with its live revocation
/// verdict), the unexpired bridge tokens under those warrants, and the
/// recent audit trail.
pub async fn agents(State(state): State<S>, headers: HeaderMap) -> Result<Response, IdpError> {
    require_relay(&state)?;
    let sess = session(&state, &headers)?;

    let warrants = state.store.warrants_for_grantor(&sess.identity, 100)?;

    // Verdicts come from the registrar's status list (broker-signed), the
    // same list the post path re-checks — so "revoked" here and "the next
    // post fails" are the same fact, read twice. Refresh any list that is
    // older than the post path would tolerate.
    for w in &warrants {
        let Ok(parsed) = browserid_core::device::Warrant::parse(&w.warrant_jws) else { continue };
        if let Some(r) = &parsed.claims().status {
            if state.status_cache.age(&r.uri).is_none_or(|a| a > crate::routes::STATUS_MAX_AGE) {
                if let Err(e) = state.status_cache.refresh(&r.uri, &state.broker_key).await {
                    tracing::warn!(uri = %r.uri, "warrant status refresh failed: {e}");
                }
            }
        }
    }
    let warrants: Vec<serde_json::Value> = warrants
        .iter()
        .map(|w| {
            let parsed = browserid_core::device::Warrant::parse(&w.warrant_jws).ok();
            let claims = parsed.as_ref().map(|p| p.claims());
            let verdict = match claims.and_then(|c| c.status.as_ref()) {
                Some(r) => match state.status_cache.check(r) {
                    browserid_rp::StatusVerdict::Valid => "live",
                    browserid_rp::StatusVerdict::Revoked => "revoked",
                    browserid_rp::StatusVerdict::Unknown => "unknown",
                },
                None => "unstated",
            };
            serde_json::json!({
                "grantee": w.grantee,
                "scopes": claims.map(|c| c.scopes.clone()).unwrap_or_default(),
                "status": verdict,
                "record_uri": w.record_uri,
            })
        })
        .collect();

    let tokens: Vec<serde_json::Value> = state
        .store
        .tokens_for_grantor(&sess.identity)?
        .iter()
        .map(|t| {
            serde_json::json!({
                "grantee": t.grantee,
                "holder": t.holder,
                // Stored as the JSON the token was minted with.
                "scopes": serde_json::from_str::<Vec<String>>(&t.scopes)
                    .unwrap_or_else(|_| vec![t.scopes.clone()]),
                "expires_at": t.expires_at.to_rfc3339(),
            })
        })
        .collect();

    let recent: Vec<serde_json::Value> = state
        .store
        .audit_for_grantor(&sess.identity, 50)?
        .iter()
        .map(|a| {
            serde_json::json!({
                "at": a.at,
                "grantee": a.grantee,
                "nsid": a.nsid,
                "outcome": a.outcome,
            })
        })
        .collect();

    Ok(Json(serde_json::json!({
        "warrants": warrants,
        "tokens": tokens,
        "recent": recent,
    }))
    .into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relay::routes::tests::bridge_with_relay;
    use crate::store::{BridgeToken, StoredWarrant};
    use axum::http::StatusCode;
    use browserid_core::device::{
        AccessCert, AccessPresentation, DeviceCert, Holder, HolderMatcher, Purpose, Warrant,
    };
    use browserid_core::keys::KeyPair;
    use browserid_core::Assertion;
    use chrono::{Duration, Utc};

    fn server(state: &S) -> axum_test::TestServer {
        axum_test::TestServer::new(crate::BridgeState::router_from(state.clone())).unwrap()
    }

    /// A presentation as `navigator.id` would hand the dashboard: issued by
    /// the test IdP, audience = the bridge origin. `grantee == grantor` is
    /// the first-party shape; a distinct grantee is an agent's.
    fn presentation(state: &S, grantor: &str, grantee: &str) -> String {
        presentation_scoped(state, grantor, grantee, vec!["login".into()])
    }

    fn presentation_scoped(
        state: &S,
        grantor: &str,
        grantee: &str,
        scopes: Vec<String>,
    ) -> String {
        let idp = state.idp.clone().unwrap();
        let audience = state.origin.clone();
        let access_key = KeyPair::generate();
        let config_key = KeyPair::generate();
        let holder = Holder::new("br.main").unwrap();
        let day = chrono::Duration::days(1);

        let access_cert = AccessCert::create(
            &idp.domain,
            grantee,
            holder.clone(),
            &access_key.public_key(),
            day,
            &idp.keypair,
            None,
        )
        .unwrap();
        let config_cert = DeviceCert::create(
            &idp.domain,
            &config_key.public_key(),
            Purpose::Authorization,
            holder.clone(),
            vec![grantor.to_string()],
            day,
            &idp.keypair,
            None,
        )
        .unwrap();
        let warrant = Warrant::create(
            grantor,
            grantee,
            HolderMatcher::new("br.*").unwrap(),
            &audience,
            scopes,
            day,
            &config_key,
            None,
        )
        .unwrap();
        let assertion = Assertion::create(&audience, day, &access_key).unwrap();
        AccessPresentation { access_cert, assertion, warrant, config_cert }.encode()
    }

    fn sid_from(resp: &axum_test::TestResponse) -> String {
        let cookie = resp
            .headers()
            .get(header::SET_COOKIE)
            .expect("a session cookie")
            .to_str()
            .unwrap()
            .to_string();
        assert!(cookie.starts_with(&format!("{DASHBOARD_COOKIE}=")), "{cookie}");
        assert!(cookie.contains("HttpOnly") && cookie.contains("SameSite=Lax"), "{cookie}");
        cookie.split(';').next().unwrap().split('=').nth(1).unwrap().to_string()
    }

    /// The happy path: a first-party sign-in opens a dashboard session whose
    /// DID came from the pin, and `/dashboard/me` renders the state the page
    /// needs — including the personalized prompt with the grantor named.
    #[tokio::test]
    async fn a_first_party_sign_in_opens_a_dashboard_session() {
        let state = bridge_with_relay("dan.bsky.social");
        let identity = format!("dan.bsky.social@{}", state.idp.as_ref().unwrap().domain);
        state.store.idp_upsert_pin("dan.bsky.social", "did:plc:pinned", Utc::now()).unwrap();

        let resp = server(&state)
            .post("/dashboard/login")
            .json(&serde_json::json!({ "presentation": presentation(&state, &identity, &identity) }))
            .await;
        resp.assert_status_ok();
        let body: serde_json::Value = resp.json();
        assert_eq!(body["handle"], "dan.bsky.social");
        assert_eq!(body["did"], "did:plc:pinned");

        let sid = sid_from(&resp);
        let sess = state.store.dashboard_session(&sid).unwrap().unwrap();
        assert_eq!(sess.identity, identity);
        assert_eq!(sess.did.as_deref(), Some("did:plc:pinned"));

        let me: serde_json::Value = server(&state)
            .get("/dashboard/me")
            .add_header(header::COOKIE, format!("{DASHBOARD_COOKIE}={sid}"))
            .await
            .json();
        assert_eq!(me["authenticated"], true);
        assert_eq!(me["allowed"], true, "dan is allowlisted");
        assert_eq!(me["connected"], false);
        let prompt = me["prompt"].as_str().unwrap();
        assert!(prompt.contains(&identity), "the grantor is named: {prompt}");
        assert!(prompt.contains(&state.origin), "the origin to read is named: {prompt}");
    }

    /// A warrant says "may post", never "is the person": an agent's
    /// delegated presentation must not open the management page of the
    /// human who delegated to it.
    #[tokio::test]
    async fn an_agents_delegated_presentation_cannot_sign_in() {
        let state = bridge_with_relay("dan.bsky.social");
        let d = &state.idp.as_ref().unwrap().domain.clone();
        state.store.idp_upsert_pin("dan.bsky.social", "did:plc:pinned", Utc::now()).unwrap();

        let delegated =
            presentation(&state, &format!("dan.bsky.social@{d}"), &format!("agent@{d}"));
        let resp = server(&state)
            .post("/dashboard/login")
            .json(&serde_json::json!({ "presentation": delegated }))
            .await;
        assert_eq!(resp.status_code(), StatusCode::BAD_REQUEST);
        assert!(resp.text().contains("agent"), "{}", resp.text());
    }

    /// The directed-login match check. A presentation whose verified
    /// identity equals the one the page asked for (`expected`) signs in; a
    /// mismatch is refused and names both, and opens no session — even though
    /// the returned identity is one the caller legitimately controls, it is
    /// not the one they typed.
    #[tokio::test]
    async fn directed_login_requires_the_returned_identity_to_match() {
        let state = bridge_with_relay("dan.bsky.social,eve.bsky.social");
        let d = state.idp.as_ref().unwrap().domain.clone();
        let dan = format!("dan.bsky.social@{d}");
        let eve = format!("eve.bsky.social@{d}");
        state.store.idp_upsert_pin("dan.bsky.social", "did:plc:dan", Utc::now()).unwrap();
        state.store.idp_upsert_pin("eve.bsky.social", "did:plc:eve", Utc::now()).unwrap();

        // Asked for dan, dialog returned eve: refused, names both, no session.
        let resp = server(&state)
            .post("/dashboard/login")
            .json(&serde_json::json!({
                "presentation": presentation(&state, &eve, &eve),
                "expected": dan,
            }))
            .await;
        assert_eq!(resp.status_code(), StatusCode::BAD_REQUEST, "{}", resp.text());
        assert!(resp.text().contains(&dan) && resp.text().contains(&eve), "{}", resp.text());
        assert!(resp.headers().get(header::SET_COOKIE).is_none());

        // Asked for dan, got dan (case-insensitively): signs in.
        let resp = server(&state)
            .post("/dashboard/login")
            .json(&serde_json::json!({
                "presentation": presentation(&state, &dan, &dan),
                "expected": dan.to_uppercase(),
            }))
            .await;
        resp.assert_status_ok();
        assert_eq!(resp.json::<serde_json::Value>()["handle"], "dan.bsky.social");
    }

    /// Finding F1 (review). `grantee == grantor` is necessary but not
    /// sufficient: the IdP mints an "as-you" agent cert whose identity is the
    /// handle itself, so an agent can present a warrant with grantor ==
    /// grantee == the handle and clear the first-party check. That agent
    /// carries posting scopes; a human's plain login carries none. So a
    /// presentation carrying any bridge-grammar scope must be refused —
    /// otherwise a delegate given only posting access walks into the
    /// management page.
    #[tokio::test]
    async fn an_as_you_agent_with_posting_scopes_cannot_sign_in() {
        let state = bridge_with_relay("dan.bsky.social");
        let identity = format!("dan.bsky.social@{}", state.idp.as_ref().unwrap().domain);
        state.store.idp_upsert_pin("dan.bsky.social", "did:plc:pinned", Utc::now()).unwrap();

        // grantor == grantee == the handle identity (the as-you shape), but
        // the warrant grants posting.
        let as_you = presentation_scoped(
            &state,
            &identity,
            &identity,
            vec!["login".into(), "repo:app.bsky.feed.post?action=create".into()],
        );
        let resp = server(&state)
            .post("/dashboard/login")
            .json(&serde_json::json!({ "presentation": as_you }))
            .await;
        assert_eq!(resp.status_code(), StatusCode::BAD_REQUEST, "{}", resp.text());
        assert!(resp.text().contains("agent scopes"), "{}", resp.text());
        // No session was minted.
        assert!(resp.headers().get(header::SET_COOKIE).is_none());
    }

    /// Finding F2 (review). Login is a cookie-planting target for forced-login
    /// CSRF, so it carries the same same-origin guard as its siblings: a
    /// cross-site POST is refused, and the legitimate JSON caller still works.
    #[tokio::test]
    async fn login_is_csrf_guarded() {
        let state = bridge_with_relay("dan.bsky.social");
        let identity = format!("dan.bsky.social@{}", state.idp.as_ref().unwrap().domain);
        state.store.idp_upsert_pin("dan.bsky.social", "did:plc:pinned", Utc::now()).unwrap();
        let pres = presentation(&state, &identity, &identity);

        // Even a cross-site request that manages a JSON content-type — the
        // one shape the Json extractor would otherwise wave through — is
        // refused by the same-origin guard on the fetch-metadata header.
        let resp = server(&state)
            .post("/dashboard/login")
            .add_header("sec-fetch-site", "cross-site")
            .json(&serde_json::json!({ "presentation": pres.clone() }))
            .await;
        assert_eq!(resp.status_code(), StatusCode::FORBIDDEN, "{}", resp.text());

        // The page's own same-origin fetch still gets through.
        let resp = server(&state)
            .post("/dashboard/login")
            .add_header("sec-fetch-site", "same-origin")
            .json(&serde_json::json!({ "presentation": pres }))
            .await;
        resp.assert_status_ok();
    }

    /// A first-party presentation from a foreign issuer — an email identity.
    /// Audience = this origin; the hosted verifier (mocked here) is what
    /// vouches for it.
    fn foreign_presentation(state: &S, identity: &str) -> String {
        let foreign_key = KeyPair::generate();
        let access_key = KeyPair::generate();
        let config_key = KeyPair::generate();
        let holder = Holder::new("br.main").unwrap();
        let day = Duration::days(1);
        let domain = identity.split_once('@').unwrap().1;
        AccessPresentation {
            access_cert: AccessCert::create(
                domain,
                identity,
                holder.clone(),
                &access_key.public_key(),
                day,
                &foreign_key,
                None,
            )
            .unwrap(),
            assertion: Assertion::create(&state.origin, day, &access_key).unwrap(),
            warrant: Warrant::create(
                identity,
                identity,
                HolderMatcher::new("br.*").unwrap(),
                &state.origin,
                vec!["login".into()],
                day,
                &config_key,
                None,
            )
            .unwrap(),
            config_cert: DeviceCert::create(
                domain,
                &config_key.public_key(),
                Purpose::Authorization,
                holder,
                vec![identity.to_string()],
                day,
                &foreign_key,
                None,
            )
            .unwrap(),
        }
        .encode()
    }

    /// A hosted verifier that vouches for whatever email the test names.
    async fn mock_broker(email: &'static str) -> String {
        use axum::routing::post;
        let app = axum::Router::new().route(
            "/verify-access",
            post(move || async move {
                Json(serde_json::json!({
                    "status": "okay",
                    "email": email,
                    "holder": "br.main",
                    "scopes": ["login"],
                }))
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        base
    }

    /// A PDS that mints invites and accounts — the two calls the mint
    /// endpoint makes.
    async fn mock_pds() -> String {
        use axum::routing::post;
        let app = axum::Router::new()
            .route(
                "/xrpc/com.atproto.server.createInviteCode",
                post(|| async { Json(serde_json::json!({ "code": "inv-1" })) }),
            )
            .route(
                "/xrpc/com.atproto.server.createAccount",
                post(|Json(req): Json<serde_json::Value>| async move {
                    Json(serde_json::json!({
                        "did": "did:plc:minted",
                        "handle": req["handle"],
                        "accessJwt": "aj",
                        "refreshJwt": "rj",
                    }))
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        base
    }

    /// The mint flow end to end (UX revamp, option 2c): an email identity —
    /// verified through the hosted verifier — signs in to a session with no
    /// handle or DID, mints a passwordless account, and the dashboard state
    /// reflects it. A second mint is refused.
    #[tokio::test]
    async fn an_email_identity_signs_in_and_mints_a_passwordless_handle() {
        let base = bridge_with_relay("dan.bsky.social");
        let mut state = Arc::try_unwrap(base).ok().expect("sole owner");
        state.broker_url = mock_broker("alice@gmail.example").await;
        state.pds = crate::pds::PdsClient::new(mock_pds().await, "admin");
        let state = Arc::new(state);

        let resp = server(&state)
            .post("/dashboard/login")
            .json(&serde_json::json!({
                "presentation": foreign_presentation(&state, "alice@gmail.example"),
            }))
            .await;
        resp.assert_status_ok();
        let body: serde_json::Value = resp.json();
        assert_eq!(body["identity"], "alice@gmail.example");
        assert!(body["handle"].is_null() && body["did"].is_null(), "{body}");
        let sid = sid_from(&resp);
        let cookie = format!("{DASHBOARD_COOKIE}={sid}");

        // The session knows it is an email with no account yet.
        let me: serde_json::Value = server(&state)
            .get("/dashboard/me")
            .add_header(header::COOKIE, cookie.clone())
            .await
            .json();
        assert_eq!(me["kind"], "email");
        assert_eq!(me["allowed"], false, "emails are not on the write relay");
        assert!(me["account_handle"].is_null());

        // Mint. The response carries the account and — the point — no
        // password, not even a hint of one.
        let resp = server(&state)
            .post("/dashboard/mint")
            .add_header(header::COOKIE, cookie.clone())
            .add_header("sec-fetch-site", "same-origin")
            .json(&serde_json::json!({ "handle": "alice" }))
            .await;
        assert_eq!(resp.status_code(), StatusCode::CREATED, "{}", resp.text());
        let minted: serde_json::Value = resp.json();
        assert_eq!(minted["handle"], "alice.at.browserid.test");
        assert_eq!(minted["did"], "did:plc:minted");
        assert!(!resp.text().to_lowercase().contains("password"), "{}", resp.text());

        // The dashboard now shows the owned handle, which unlocks the prompt.
        let me: serde_json::Value = server(&state)
            .get("/dashboard/me")
            .add_header(header::COOKIE, cookie.clone())
            .await
            .json();
        assert_eq!(me["account_handle"], "alice.at.browserid.test");
        assert_eq!(me["account_did"], "did:plc:minted");

        // Returning humans do not mint twice.
        let resp = server(&state)
            .post("/dashboard/mint")
            .add_header(header::COOKIE, cookie)
            .add_header("sec-fetch-site", "same-origin")
            .json(&serde_json::json!({ "handle": "alice-two" }))
            .await;
        assert_eq!(resp.status_code(), StatusCode::CONFLICT, "{}", resp.text());
    }

    /// Minting is the email path's bootstrap only: a handle session stands
    /// for a real Bluesky account and is told to connect instead, and a
    /// reserved or malformed label is refused before any PDS call.
    #[tokio::test]
    async fn mint_refuses_handle_sessions_and_bad_labels() {
        let state = bridge_with_relay("dan.bsky.social");
        let sid = state
            .store
            .dashboard_create_session("dan.bsky.social@x", Some("dan.bsky.social"), Some("did:plc:p"), 1)
            .unwrap();
        let resp = server(&state)
            .post("/dashboard/mint")
            .add_header(header::COOKIE, format!("{DASHBOARD_COOKIE}={sid}"))
            .add_header("sec-fetch-site", "same-origin")
            .json(&serde_json::json!({ "handle": "dan" }))
            .await;
        assert_eq!(resp.status_code(), StatusCode::BAD_REQUEST);
        assert!(resp.text().contains("connect"), "{}", resp.text());

        let sid = state
            .store
            .dashboard_create_session("alice@gmail.example", None, None, 1)
            .unwrap();
        for label in ["admin", "www", "A!", "x"] {
            let resp = server(&state)
                .post("/dashboard/mint")
                .add_header(header::COOKIE, format!("{DASHBOARD_COOKIE}={sid}"))
                .add_header("sec-fetch-site", "same-origin")
                .json(&serde_json::json!({ "handle": label }))
                .await;
            assert_eq!(resp.status_code(), StatusCode::BAD_REQUEST, "{label}");
        }
    }

    /// No pin, no session — and a suspended pin is a refusal, not a sign-in
    /// with a caveat.
    #[tokio::test]
    async fn a_missing_or_suspended_pin_refuses_the_sign_in() {
        let state = bridge_with_relay("dan.bsky.social");
        let identity = format!("dan.bsky.social@{}", state.idp.as_ref().unwrap().domain);

        let resp = server(&state)
            .post("/dashboard/login")
            .json(&serde_json::json!({ "presentation": presentation(&state, &identity, &identity) }))
            .await;
        assert_eq!(resp.status_code(), StatusCode::BAD_REQUEST);
        assert!(resp.text().contains("no pinned account"), "{}", resp.text());

        state.store.idp_upsert_pin("dan.bsky.social", "did:plc:pinned", Utc::now()).unwrap();
        state.store.idp_set_pin_suspended("dan.bsky.social", true).unwrap();
        let resp = server(&state)
            .post("/dashboard/login")
            .json(&serde_json::json!({ "presentation": presentation(&state, &identity, &identity) }))
            .await;
        assert_eq!(resp.status_code(), StatusCode::FORBIDDEN);
    }

    /// The point of `require_human_session`: a dashboard sign-in carries
    /// straight into the connect flow — status answers, and the
    /// state-changing disconnect works — with no second authentication.
    #[tokio::test]
    async fn the_dashboard_session_drives_the_connect_endpoints() {
        let state = bridge_with_relay("dan.bsky.social");
        state.store.idp_upsert_pin("dan.bsky.social", "did:plc:pinned", Utc::now()).unwrap();
        let identity = format!("dan.bsky.social@{}", state.idp.as_ref().unwrap().domain);
        let sid = state
            .store
            .dashboard_create_session(&identity, Some("dan.bsky.social"), Some("did:plc:pinned"), 1)
            .unwrap();
        crate::relay::tests_support::insert_live_session(
            &state,
            "dan.bsky.social",
            "did:plc:pinned",
            "https://shard.example",
        );

        let status: serde_json::Value = server(&state)
            .get("/idp/connect/status")
            .add_header(header::COOKIE, format!("{DASHBOARD_COOKIE}={sid}"))
            .await
            .json();
        assert_eq!(status["authenticated"], true);
        assert_eq!(status["handle"], "dan.bsky.social");
        assert_eq!(status["connected"], true);

        server(&state)
            .post("/idp/connect/disconnect")
            .add_header(header::COOKIE, format!("{DASHBOARD_COOKIE}={sid}"))
            .add_header("sec-fetch-site", "same-origin")
            .await
            .assert_status_ok();
        assert!(!state.store.write_session_exists("did:plc:pinned").unwrap());
    }

    /// Logout is a cookie-authed POST with no body — CSRF-guarded like its
    /// connect siblings, and actually ends the session when legitimate.
    #[tokio::test]
    async fn logout_is_csrf_guarded_and_ends_the_session() {
        let state = bridge_with_relay("dan.bsky.social");
        let sid = state
            .store
            .dashboard_create_session("dan.bsky.social@x", Some("dan.bsky.social"), Some("did:plc:p"), 1)
            .unwrap();
        let cookie = format!("{DASHBOARD_COOKIE}={sid}");

        let resp = server(&state)
            .post("/dashboard/logout")
            .add_header(header::COOKIE, cookie.clone())
            .add_header("sec-fetch-site", "cross-site")
            .add_header("content-type", "application/x-www-form-urlencoded")
            .await;
        assert!(
            resp.status_code() == StatusCode::FORBIDDEN
                || resp.status_code() == StatusCode::BAD_REQUEST
        );
        assert!(state.store.dashboard_session(&sid).unwrap().is_some(), "session survived CSRF");

        server(&state)
            .post("/dashboard/logout")
            .add_header(header::COOKIE, cookie)
            .add_header("sec-fetch-site", "same-origin")
            .await
            .assert_status_ok();
        assert!(state.store.dashboard_session(&sid).unwrap().is_none());
    }

    /// Phase 2 lands inert: without a relay, every dashboard route answers
    /// 404 — indistinguishable from an origin that never had one.
    #[tokio::test]
    async fn a_relay_less_origin_serves_no_dashboard() {
        let server =
            axum_test::TestServer::new(crate::BridgeState::router_from(crate::idp::tests::test_bridge()))
                .unwrap();
        for path in ["/dashboard", "/dashboard/me", "/dashboard/agents"] {
            assert_eq!(server.get(path).await.status_code(), StatusCode::NOT_FOUND, "{path}");
        }
        let resp = server
            .post("/dashboard/login")
            .json(&serde_json::json!({ "presentation": "x" }))
            .await;
        assert_eq!(resp.status_code(), StatusCode::NOT_FOUND);
        let resp = server
            .post("/dashboard/logout")
            .add_header("content-type", "application/json")
            .await;
        assert_eq!(resp.status_code(), StatusCode::NOT_FOUND);
    }

    /// The ledger answers only for the signed-in grantor: someone else's
    /// warrants, tokens, and audit lines do not leak in, expired tokens are
    /// gone, and a warrant with no status ref reads "unstated".
    #[tokio::test]
    async fn the_agents_ledger_is_scoped_to_the_signed_in_grantor() {
        let state = bridge_with_relay("dan.bsky.social");
        let d = state.idp.as_ref().unwrap().domain.clone();
        let identity = format!("dan.bsky.social@{d}");
        let sid = state
            .store
            .dashboard_create_session(&identity, Some("dan.bsky.social"), Some("did:plc:pinned"), 1)
            .unwrap();

        // A real warrant JWS so the endpoint can read scopes off it.
        let pres_str = presentation(&state, &identity, &format!("agent@{d}"));
        let pres = AccessPresentation::parse(&pres_str).unwrap();
        let mine = |grantee: &str, jws: &str| StoredWarrant {
            hash: format!("h-{grantee}"),
            did: "did:plc:pinned".into(),
            grantor: identity.clone(),
            grantee: grantee.into(),
            warrant_jws: jws.into(),
            config_cert_jws: "cc".into(),
            record_uri: None,
        };
        state
            .store
            .upsert_warrant(&mine(&format!("agent@{d}"), pres.warrant.encoded()))
            .unwrap();
        state
            .store
            .upsert_warrant(&StoredWarrant {
                hash: "h-other".into(),
                grantor: "someone.else@x".into(),
                ..mine("other-agent@x", "not-a-warrant")
            })
            .unwrap();

        let token = |grantor: &str, ttl_min: i64| BridgeToken {
            did: "did:plc:pinned".into(),
            grantor: grantor.into(),
            grantee: format!("agent@{d}"),
            holder: "br.main".into(),
            scopes: vec!["repo:app.bsky.feed.post?action=create".into()],
            warrant_status: None,
            warrant_ref: "h".into(),
            expires_at: Utc::now() + Duration::minutes(ttl_min),
        };
        state.store.issue_token(&token(&identity, 30)).unwrap();
        state.store.issue_token(&token(&identity, -5)).unwrap(); // expired
        state.store.issue_token(&token("someone.else@x", 30)).unwrap();

        state.store.audit(&token(&identity, 30), "com.atproto.repo.createRecord", "ok").unwrap();
        state.store.audit(&token("someone.else@x", 30), "com.atproto.repo.createRecord", "ok").unwrap();

        let body: serde_json::Value = server(&state)
            .get("/dashboard/agents")
            .add_header(header::COOKIE, format!("{DASHBOARD_COOKIE}={sid}"))
            .await
            .json();

        let warrants = body["warrants"].as_array().unwrap();
        assert_eq!(warrants.len(), 1, "only the signed-in grantor's warrants: {body}");
        assert_eq!(warrants[0]["grantee"], format!("agent@{d}"));
        assert_eq!(warrants[0]["status"], "unstated", "no status ref on the test warrant");
        assert_eq!(warrants[0]["scopes"][0], "login");

        let tokens = body["tokens"].as_array().unwrap();
        assert_eq!(tokens.len(), 1, "the expired and the foreign token are gone: {body}");
        assert_eq!(tokens[0]["scopes"][0], "repo:app.bsky.feed.post?action=create");

        let recent = body["recent"].as_array().unwrap();
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0]["nsid"], "com.atproto.repo.createRecord");

        // Signed out, the ledger answers nothing.
        assert_eq!(
            server(&state).get("/dashboard/agents").await.status_code(),
            StatusCode::UNAUTHORIZED
        );
    }

    /// The page is templated with the broker origin, the IdP domain, the
    /// handle zone, and the shared stylesheet — and, like device-authorize,
    /// nothing it renders may reach the DOM as markup: identities and error
    /// text originate outside the page.
    #[test]
    fn the_page_is_templated_and_never_assigns_html() {
        let page = render_dashboard("https://broker.example/", "bsky.browserid.test", "at.browserid.test");
        assert!(page.contains(r#"src="https://broker.example/include.js""#));
        assert!(page.contains(r#"href="https://broker.example/account""#));
        assert!(page.contains("your-handle@bsky.browserid.test"));
        // The directed-login machinery is present: the handle box, the JS
        // domain constant that builds the identity, and the provisionEmail
        // request.
        assert!(page.contains("var IDP_DOMAIN = 'bsky.browserid.test';"));
        assert!(page.contains(r#"id="handle""#));
        assert!(page.contains("provisionEmail: expected"));
        assert!(page.contains(r#"id="anyemail""#));
        // The mint card shows the real handle zone, and the shared design
        // system (both palettes) is inlined.
        assert!(page.contains(".at.browserid.test"));
        assert!(page.contains("--bg:#F7F5F0") && page.contains("--bg:#080B15"));
        assert!(
            !page.contains(BROKER_TOKEN)
                && !page.contains(IDP_DOMAIN_TOKEN)
                && !page.contains(HANDLE_DOMAIN_TOKEN)
                && !page.contains(BASE_CSS_TOKEN)
        );
        for sink in ["innerHTML", "outerHTML", "insertAdjacentHTML", "document.write"] {
            assert_eq!(page.matches(sink).count(), 0, "{sink} is used in dashboard.html");
        }
    }

    /// Not a test: a seeded preview server for eyeballing the revamped UI.
    ///
    /// ```sh
    /// cargo test -p pds-bridge ui_preview_server -- --ignored --nocapture
    /// ```
    ///
    /// `/preview/as/dan|eve|alice|bob` signs the browser in as that seeded
    /// state (sets the session cookie, redirects to the dashboard); `/logout`
    /// works as usual. Also serves `/preview/verify?kind=green|amber|red`.
    #[tokio::test]
    #[ignore = "manual UI preview harness; runs until killed"]
    async fn ui_preview_server() {
        use axum::routing::get;
        let base = bridge_with_relay("dan.bsky.social,eve.bsky.social");
        let mut state = Arc::try_unwrap(base).ok().expect("sole owner");
        // The page loads include.js from the broker origin; point it at this
        // server, which serves a stub, so the page's JS runs.
        state.broker_url = "http://127.0.0.1:3999".into();
        let state = Arc::new(state);
        let d = state.idp.as_ref().unwrap().domain.clone();

        // dan: handle sign-in, not yet connected (option 2b).
        state
            .store
            .idp_upsert_pin("dan.bsky.social", "did:plc:44ydse7qpviwxwmwbjwq7e2", Utc::now())
            .unwrap();
        let dan = format!("dan.bsky.social@{d}");
        let sid_dan = state
            .store
            .dashboard_create_session(&dan, Some("dan.bsky.social"), Some("did:plc:44ydse7qpviwxwmwbjwq7e2"), 24)
            .unwrap();

        // eve: handle sign-in, connected (option 1c), with a warrant + audit.
        state.store.idp_upsert_pin("eve.bsky.social", "did:plc:eve", Utc::now()).unwrap();
        crate::relay::tests_support::insert_live_session(
            &state,
            "eve.bsky.social",
            "did:plc:eve",
            "https://shard.example",
        );
        let eve = format!("eve.bsky.social@{d}");
        let sid_eve = state
            .store
            .dashboard_create_session(&eve, Some("eve.bsky.social"), Some("did:plc:eve"), 24)
            .unwrap();
        let pres_str = presentation_scoped(
            &state,
            &eve,
            "eve+scribe@gmail.example",
            vec!["login".into(), "repo:app.bsky.feed.post?action=create".into()],
        );
        let pres = AccessPresentation::parse(&pres_str).unwrap();
        state
            .store
            .upsert_warrant(&crate::store::StoredWarrant {
                hash: "h-preview".into(),
                did: "did:plc:eve".into(),
                grantor: eve.clone(),
                grantee: "eve+scribe@gmail.example".into(),
                warrant_jws: pres.warrant.encoded().to_string(),
                config_cert_jws: pres.config_cert.encoded().to_string(),
                record_uri: None,
            })
            .unwrap();
        let tok = BridgeToken {
            did: "did:plc:eve".into(),
            grantor: eve.clone(),
            grantee: "eve+scribe@gmail.example".into(),
            holder: "br.main".into(),
            scopes: vec!["repo:app.bsky.feed.post?action=create".into()],
            warrant_status: None,
            warrant_ref: "h-preview".into(),
            expires_at: Utc::now() + Duration::minutes(30),
        };
        state.store.audit(&tok, "com.atproto.repo.createRecord", "ok").unwrap();

        // alice: email sign-in, no account yet (mint card, option 2c).
        let sid_alice =
            state.store.dashboard_create_session("alice@gmail.example", None, None, 24).unwrap();

        // bob: email sign-in with a minted account (success card).
        state
            .store
            .insert_account(&crate::store::Account {
                email: "bob@gmail.example".into(),
                did: "did:plc:bob".into(),
                handle: format!("bob.{}", state.handle_domain),
                access_jwt: "a".into(),
                refresh_jwt: "r".into(),
            })
            .unwrap();
        let sid_bob =
            state.store.dashboard_create_session("bob@gmail.example", None, None, 24).unwrap();

        let sids: std::collections::HashMap<&'static str, String> = [
            ("dan", sid_dan),
            ("eve", sid_eve),
            ("alice", sid_alice),
            ("bob", sid_bob),
        ]
        .into();
        let preview = axum::Router::new()
            .route(
                "/include.js",
                get(|| async {
                    (
                        [(header::CONTENT_TYPE, "text/javascript")],
                        "navigator.id={watch:function(){},request:function(){},logout:function(){}};",
                    )
                }),
            )
            .route(
                "/preview/verify",
                get(|q: axum::extract::Query<std::collections::HashMap<String, String>>| async move {
                    axum::response::Html(crate::routes::verify_preview(
                        q.get("kind").map(String::as_str).unwrap_or("green"),
                    ))
                }),
            )
            .route(
                "/preview/as/:who",
                get(move |axum::extract::Path(who): axum::extract::Path<String>| {
                    let sids = sids.clone();
                    async move {
                        match sids.get(who.as_str()) {
                            Some(sid) => (
                                [(header::SET_COOKIE, format!("{DASHBOARD_COOKIE}={sid}; Path=/"))],
                                axum::response::Redirect::to("/dashboard"),
                            )
                                .into_response(),
                            None => (StatusCode::NOT_FOUND, "dan|eve|alice|bob").into_response(),
                        }
                    }
                }),
            )
            .merge(crate::BridgeState::router_from(state.clone()));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:3999").await.unwrap();
        axum::serve(listener, preview).await.unwrap();
    }

    /// Sessions expire like their IdP siblings, and live in their own table:
    /// a dashboard sid is worthless as an IdP session and vice versa.
    #[test]
    fn dashboard_sessions_expire_and_stay_separate() {
        let store = crate::store::Store::open_in_memory().unwrap();
        let sid = store.dashboard_create_session("h@d", Some("h"), Some("did:plc:a"), -1).unwrap();
        assert!(store.dashboard_session(&sid).unwrap().is_none(), "expired");

        let sid = store.dashboard_create_session("h@d", Some("h"), Some("did:plc:a"), 1).unwrap();
        assert!(store.dashboard_session(&sid).unwrap().is_some());
        assert!(store.idp_session(&sid).unwrap().is_none(), "not an IdP session");
        let idp_sid = store.idp_create_session(Some("h"), "did:plc:a", 1).unwrap();
        assert!(store.dashboard_session(&idp_sid).unwrap().is_none(), "and not the reverse");
    }
}
