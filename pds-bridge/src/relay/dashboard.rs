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
//! 1. **Login accepts only a first-party presentation of an identity our
//!    own IdP issued.** An agent's warrant-carrying presentation is refused
//!    — a warrant says "may post", never "is the person" — and a foreign
//!    identity has no pinned DID to manage here anyway.
//! 2. **The DID in the session comes from `idp_pins`**, never from the
//!    presentation (which does not carry one) and never from the request.

use std::sync::Arc;

use axum::extract::State;
use axum::http::{header, HeaderMap};
use axum::response::{Html, IntoResponse, Response};
use axum::Json;
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

fn render_dashboard(broker_url: &str, idp_domain: &str) -> String {
    // Both values are operator config, not attacker-influenced — but they
    // land inside `src=`/`href=` attributes and a `<code>` body, so a stray
    // quote in a mistyped `BROKER_URL` must break the page, not the
    // attribute. Escape rather than trust the config to be clean.
    include_str!("dashboard.html")
        .replace(BROKER_TOKEN, &html_escape(broker_url.trim_end_matches('/')))
        .replace(IDP_DOMAIN_TOKEN, &html_escape(idp_domain))
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
    ([FRAME_DENY], Html(render_dashboard(&state.broker_url, &idp.domain))).into_response()
}

// ---------------------------------------------------------------------------
// Login / logout
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct LoginReq {
    /// The access presentation `navigator.id` produced, audience = this
    /// origin.
    pub presentation: String,
}

/// `POST /dashboard/login` — verify the presentation, open the session.
///
/// In-process only: the identities this dashboard manages are the ones this
/// deployment's own IdP issues, so their verification never needs the hosted
/// verifier. A presentation from any other issuer is refused with directions,
/// not verified the long way — there is nothing here for a foreign identity
/// to manage (phase 3 adds the "or use any email" mint path).
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
        None => {
            return Err(IdpError::BadRequest(format!(
                "sign in with your Bluesky-handle identity (<handle>@{}) — other identities \
                 have nothing to manage here yet",
                idp.domain
            )))
        }
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
    let handle = identity
        .strip_suffix(&format!("@{}", idp.domain))
        .ok_or_else(|| {
            // verify_locally only accepts bundles our IdP issued, so this is
            // unreachable in practice; checked anyway because the session row
            // this creates is what the connect flow trusts.
            IdpError::BadRequest(format!("{identity} is not an identity of this IdP"))
        })?
        .to_ascii_lowercase();

    // The pin is the authority on which account this identity is. No pin,
    // no session: a dashboard session's whole point is the DID behind it.
    let pin = state
        .store
        .idp_pin(&handle)?
        .ok_or_else(|| IdpError::BadRequest(format!("{handle} has no pinned account")))?;
    if pin.suspended {
        return Err(IdpError::BindingSuspended(format!(
            "the binding for {handle} is suspended; sign in again once it is re-verified"
        )));
    }

    let sid =
        state.store.dashboard_create_session(&identity, &handle, &pin.did, SESSION_TTL_HOURS)?;
    tracing::info!(%handle, did = %pin.did, "dashboard sign-in");
    Ok((
        [(header::SET_COOKIE, set_session_cookie(&idp.origin, &sid, SESSION_TTL_HOURS * 3600))],
        Json(serde_json::json!({
            "identity": identity,
            "handle": handle,
            "did": pin.did,
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
/// the signed-in identity, whether it may connect (allowlist), whether a
/// write session is attached, and the copyable delegation prompt.
pub async fn me(State(state): State<S>, headers: HeaderMap) -> Response {
    let Ok((_, relay)) = require_relay(&state) else {
        return IdpError::NotConfigured.into_response();
    };
    let Ok(sess) = session(&state, &headers) else {
        return Json(serde_json::json!({ "authenticated": false })).into_response();
    };
    let allowed = relay.allowlist.permits(&sess.handle, &sess.did);
    let stored = state.store.write_session(&relay.secrets, &sess.did).ok().flatten();
    Json(serde_json::json!({
        "authenticated": true,
        "identity": sess.identity,
        "handle": sess.handle,
        "did": sess.did,
        "allowed": allowed,
        "connected": stored.is_some(),
        "write_state": stored.as_ref().map(|s| s.state.as_str()),
        "access_expires_at": stored.as_ref().map(|s| s.access_expires_at.to_rfc3339()),
        "connected_at": stored.as_ref().map(|s| s.created_at.to_rfc3339()),
        "prompt": delegation_prompt(&state.origin, &sess.identity),
    }))
    .into_response()
}

/// The personalized delegation prompt (design doc, *The personalized
/// delegation prompt*): plain text, the grantor named, nothing hidden. The
/// identity comes from the authenticated session — never from a query
/// parameter — and what renders is exactly what the agent will read.
fn delegation_prompt(origin: &str, identity: &str) -> String {
    format!(
        "Read {origin}/ and follow it so you can post to Bluesky for me. \
         My grantor identity is {identity} — request the warrant for exactly \
         that identity."
    )
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
        assert_eq!(sess.did, "did:plc:pinned");

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

    /// A presentation from any other issuer is refused with directions —
    /// there is no pinned DID for it to manage.
    #[tokio::test]
    async fn a_foreign_identity_is_refused_with_directions() {
        let state = bridge_with_relay("dan.bsky.social");
        let foreign_key = KeyPair::generate();
        let access_key = KeyPair::generate();
        let config_key = KeyPair::generate();
        let holder = Holder::new("br.main").unwrap();
        let day = Duration::days(1);
        let identity = "someone@elsewhere.example";
        let pres = AccessPresentation {
            access_cert: AccessCert::create(
                "elsewhere.example",
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
                "elsewhere.example",
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
        .encode();

        let resp = server(&state)
            .post("/dashboard/login")
            .json(&serde_json::json!({ "presentation": pres }))
            .await;
        assert_eq!(resp.status_code(), StatusCode::BAD_REQUEST);
        assert!(resp.text().contains("Bluesky-handle identity"), "{}", resp.text());
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
            .dashboard_create_session(&identity, "dan.bsky.social", "did:plc:pinned", 1)
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
            .dashboard_create_session("dan.bsky.social@x", "dan.bsky.social", "did:plc:p", 1)
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
            .dashboard_create_session(&identity, "dan.bsky.social", "did:plc:pinned", 1)
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

    /// The page is templated with the broker origin and the IdP domain, and
    /// — like device-authorize — nothing it renders may reach the DOM as
    /// markup: identities and error text originate outside the page.
    #[test]
    fn the_page_is_templated_and_never_assigns_html() {
        let page = render_dashboard("https://broker.example/", "bsky.browserid.test");
        assert!(page.contains(r#"src="https://broker.example/include.js""#));
        assert!(page.contains(r#"href="https://broker.example/account""#));
        assert!(page.contains("your-handle@bsky.browserid.test"));
        assert!(!page.contains(BROKER_TOKEN) && !page.contains(IDP_DOMAIN_TOKEN));
        for sink in ["innerHTML", "outerHTML", "insertAdjacentHTML", "document.write"] {
            assert_eq!(page.matches(sink).count(), 0, "{sink} is used in dashboard.html");
        }
    }

    /// Sessions expire like their IdP siblings, and live in their own table:
    /// a dashboard sid is worthless as an IdP session and vice versa.
    #[test]
    fn dashboard_sessions_expire_and_stay_separate() {
        let store = crate::store::Store::open_in_memory().unwrap();
        let sid = store.dashboard_create_session("h@d", "h", "did:plc:a", -1).unwrap();
        assert!(store.dashboard_session(&sid).unwrap().is_none(), "expired");

        let sid = store.dashboard_create_session("h@d", "h", "did:plc:a", 1).unwrap();
        assert!(store.dashboard_session(&sid).unwrap().is_some());
        assert!(store.idp_session(&sid).unwrap().is_none(), "not an IdP session");
        let idp_sid = store.idp_create_session(Some("h"), "did:plc:a", 1).unwrap();
        assert!(store.dashboard_session(&idp_sid).unwrap().is_none(), "and not the reverse");
    }
}
