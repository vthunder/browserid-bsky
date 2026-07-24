//! HTTP handlers: provisioning, grant exchange, and the scoped XRPC proxy.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Form, Request, State};
use axum::http::{header, HeaderMap, StatusCode, Uri};
use axum::response::{IntoResponse, Json, Response};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{Duration, Utc};
use rand::RngCore;

use browserid_core::device::AccessPresentation;
use browserid_core::rp_auth::{TokenRequest, TokenResponse, GRANT_TYPE_ASSERTION};
use browserid_core::StatusRef;
use browserid_rp::{oauth_metadata_with_scopes, StatusVerdict, VerifiedIdentity};

use crate::scopes::{parse_scopes, required_for, scopes_cover};
use crate::store::{Account, BridgeToken, TOKEN_PREFIX};
use crate::{BridgeState, ADVERTISED_SCOPES, RESERVED_LABELS, TOKEN_TTL_MINUTES};

type S = Arc<BridgeState>;

fn err(status: StatusCode, code: &str, msg: impl Into<String>) -> Response {
    (status, Json(serde_json::json!({ "error": code, "error_description": msg.into() })))
        .into_response()
}

/// Refresh any status list the presentation references that the cache can't
/// currently answer for, then verify. Keeps `Verifier::verify` synchronous
/// while staying fail-closed: a list that still can't be fetched/verified
/// leaves the verdict Unknown → reject.
async fn verify_presentation(state: &S, presentation: &str) -> Result<VerifiedIdentity, Response> {
    if let Ok(pres) = AccessPresentation::parse(presentation) {
        let refs: Vec<StatusRef> = [
            pres.access_cert.claims().status.clone(),
            pres.config_cert.claims().status.clone(),
            pres.warrant.claims().status.clone(),
        ]
        .into_iter()
        .flatten()
        .collect();
        for r in refs {
            if state.status_cache.check(&r) == StatusVerdict::Unknown {
                if let Err(e) = state.verifier.refresh_status(&r.uri).await {
                    tracing::warn!(uri = %r.uri, "status list refresh failed: {e}");
                }
            }
        }
    }
    state
        .verifier
        .verify(presentation)
        .map_err(|e| err(StatusCode::BAD_REQUEST, "invalid_grant", e.to_string()))
}

// ---------------------------------------------------------------------------
// POST /browserid/provision
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
pub struct ProvisionRequest {
    /// Four-object bundle, audience = the bridge origin
    pub presentation: String,
    /// Desired handle label (the part before `.{handle_domain}`)
    pub handle: String,
}

fn valid_label(label: &str) -> bool {
    let bytes = label.as_bytes();
    (2..=63).contains(&label.len())
        && bytes.first().is_some_and(u8::is_ascii_lowercase)
        && bytes.last().is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        && bytes.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

pub async fn provision(
    State(state): State<S>,
    Json(req): Json<ProvisionRequest>,
) -> Response {
    let identity = match verify_presentation(&state, &req.presentation).await {
        Ok(v) => v,
        Err(e) => return e,
    };
    // Provisioning is a first-party action: the signed-in identity itself,
    // not a delegated grantee, opens the account.
    if identity.grantee != identity.email {
        return err(
            StatusCode::FORBIDDEN,
            "invalid_grant",
            "provisioning requires a first-party login (grantee == grantor)",
        );
    }
    let email = identity.email;

    let label = req.handle.to_lowercase();
    if !valid_label(&label) || RESERVED_LABELS.contains(&label.as_str()) {
        return err(StatusCode::BAD_REQUEST, "invalid_request", "handle label not available");
    }
    let handle = format!("{label}.{}", state.handle_domain);

    match (state.store.account_by_email(&email), state.store.handle_taken(&handle)) {
        (Ok(Some(_)), _) => {
            return err(StatusCode::CONFLICT, "invalid_request", "account already provisioned")
        }
        (Ok(None), Ok(false)) => {}
        (Ok(None), Ok(true)) => {
            return err(StatusCode::CONFLICT, "invalid_request", "handle label not available")
        }
        (Err(e), _) | (_, Err(e)) => {
            return err(StatusCode::INTERNAL_SERVER_ERROR, "server_error", e.to_string())
        }
    }

    // Shown once, never stored: the user's credential for ordinary Bluesky
    // clients. The bridge keeps only the session pair.
    let mut pw = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut pw);
    let password = URL_SAFE_NO_PAD.encode(pw);

    let invite = match state.pds.create_invite_code().await {
        Ok(c) => c,
        Err(e) => return err(StatusCode::BAD_GATEWAY, "server_error", e.to_string()),
    };
    let created = match state.pds.create_account(&handle, &email, &password, &invite).await {
        Ok(a) => a,
        Err(e) => return err(StatusCode::BAD_GATEWAY, "server_error", e.to_string()),
    };
    if let Err(e) = state.store.insert_account(&Account {
        email: email.clone(),
        did: created.did.clone(),
        handle: created.handle.clone(),
        access_jwt: created.access_jwt,
        refresh_jwt: created.refresh_jwt,
    }) {
        return err(StatusCode::INTERNAL_SERVER_ERROR, "server_error", e.to_string());
    }

    (
        StatusCode::CREATED,
        Json(serde_json::json!({
            "did": created.did,
            "handle": created.handle,
            "password": password,
        })),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// POST /browserid/token  (RFC 7521 grant exchange)
// ---------------------------------------------------------------------------

pub async fn token(State(state): State<S>, Form(req): Form<TokenRequest>) -> Response {
    if req.grant_type != GRANT_TYPE_ASSERTION {
        return err(StatusCode::BAD_REQUEST, "unsupported_grant_type", req.grant_type);
    }
    let identity = match verify_presentation(&state, &req.assertion).await {
        Ok(v) => v,
        Err(e) => return e,
    };

    // The grantor names the account; only a provisioned grantor can delegate.
    let account = match state.store.account_by_email(&identity.email) {
        Ok(Some(a)) => a,
        Ok(None) => {
            return err(
                StatusCode::FORBIDDEN,
                "invalid_grant",
                format!("{} has no account here — provision first", identity.email),
            )
        }
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, "server_error", e.to_string()),
    };

    // Only scopes that parse under the granular grammar grant anything.
    let raw: Vec<String> = identity.scopes.iter().filter(|s| *s != "login").cloned().collect();
    let parsed = parse_scopes(&raw);
    if parsed.is_empty() {
        return err(
            StatusCode::BAD_REQUEST,
            "invalid_scope",
            "warrant carries no usable bridge scopes (see /.well-known/oauth-authorization-server)",
        );
    }
    // Store the raw strings that survived parsing, verbatim.
    let granted: Vec<String> = raw.iter().filter(|s| crate::scopes::Scope::parse(s).is_some()).cloned().collect();

    let token = BridgeToken {
        did: account.did,
        grantor: identity.email,
        grantee: identity.grantee,
        holder: identity.holder.as_str().to_string(),
        scopes: granted.clone(),
        warrant_status: identity.warrant_status.map(|r| (r.uri, r.idx)),
        expires_at: Utc::now() + Duration::minutes(TOKEN_TTL_MINUTES),
    };
    match state.store.issue_token(&token) {
        Ok(bearer) => Json(TokenResponse {
            access_token: bearer,
            token_type: "Bearer".to_string(),
            expires_in: TOKEN_TTL_MINUTES * 60,
            email: Some(token.grantor),
            holder: Some(token.holder),
            scopes: Some(granted),
        })
        .into_response(),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, "server_error", e.to_string()),
    }
}

// ---------------------------------------------------------------------------
// GET /.well-known/oauth-authorization-server
// ---------------------------------------------------------------------------

pub async fn oauth_metadata(State(state): State<S>) -> Json<serde_json::Value> {
    let scopes: Vec<String> = ADVERTISED_SCOPES.iter().map(|s| s.to_string()).collect();
    Json(oauth_metadata_with_scopes(
        &state.origin,
        &format!("{}/browserid/token", state.origin),
        &scopes,
    ))
}

// ---------------------------------------------------------------------------
// /xrpc/* — scoped proxy (bridge tokens) / transparent passthrough (rest)
// ---------------------------------------------------------------------------

pub async fn proxy(State(state): State<S>, req: Request) -> Response {
    let (parts, body) = req.into_parts();
    let body = match axum::body::to_bytes(body, 1024 * 1024).await {
        Ok(b) => b,
        Err(_) => return err(StatusCode::PAYLOAD_TOO_LARGE, "invalid_request", "body too large"),
    };

    let bearer = parts
        .headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));

    match bearer {
        Some(b) if b.starts_with(TOKEN_PREFIX) => {
            scoped_call(&state, &parts.method.to_string(), &parts.uri, &parts.headers, body, b)
                .await
        }
        // Anyone else (human clients, relay, anonymous reads): pass through.
        _ => passthrough(&state, &parts.method.to_string(), &parts.uri, &parts.headers, body).await,
    }
}

fn xrpc_nsid(uri: &Uri) -> Option<String> {
    uri.path().strip_prefix("/xrpc/").map(|s| s.to_string()).filter(|s| !s.contains('/'))
}

async fn scoped_call(
    state: &S,
    method: &str,
    uri: &Uri,
    headers: &HeaderMap,
    body: Bytes,
    bearer: &str,
) -> Response {
    let challenge = || {
        let mut resp = err(StatusCode::UNAUTHORIZED, "invalid_token", "unknown or expired token");
        let header_value = state
            .verifier
            .challenge(format!("{}/browserid/token", state.origin))
            .to_header_value();
        if let Ok(v) = header_value.parse() {
            resp.headers_mut().insert(header::WWW_AUTHENTICATE, v);
        }
        resp
    };

    let token = match state.store.token(bearer) {
        Ok(Some(t)) => t,
        Ok(None) => return challenge(),
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, "server_error", e.to_string()),
    };

    // Live revocation: re-check the warrant ref on every use (≤5 min cache).
    if let Some((uri_s, idx)) = &token.warrant_status {
        let r = StatusRef { uri: uri_s.clone(), idx: *idx };
        let mut verdict = state.status_cache.check(&r);
        if verdict == StatusVerdict::Unknown {
            if let Err(e) = state.verifier.refresh_status(&r.uri).await {
                tracing::warn!(uri = %r.uri, "status refresh failed: {e}");
            }
            verdict = state.status_cache.check(&r);
        }
        match verdict {
            StatusVerdict::Revoked => {
                let _ = state.store.revoke_tokens_for_warrant(uri_s, *idx);
                let _ = state.store.audit(&token, "-", "warrant-revoked");
                return err(StatusCode::UNAUTHORIZED, "invalid_token", "warrant revoked");
            }
            StatusVerdict::Unknown => {
                return err(
                    StatusCode::FORBIDDEN,
                    "invalid_token",
                    "warrant status unavailable (fail-closed)",
                );
            }
            StatusVerdict::Valid => {}
        }
    }

    let Some(nsid) = xrpc_nsid(uri) else {
        return err(StatusCode::FORBIDDEN, "insufficient_scope", "bridge tokens may only call /xrpc/*");
    };
    let content_type = headers.get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok());
    let json_body: Option<serde_json::Value> = content_type
        .filter(|ct| ct.starts_with("application/json"))
        .and_then(|_| serde_json::from_slice(&body).ok());

    // Allowlist: unmapped call → deny; every required permission must be
    // covered by the warrant's parsed scopes.
    let Some(required) = required_for(method, &nsid, json_body.as_ref(), content_type) else {
        let _ = state.store.audit(&token, &nsid, "denied-unmapped");
        return err(StatusCode::FORBIDDEN, "insufficient_scope", format!("{nsid} is not grantable via the bridge"));
    };
    let scopes = parse_scopes(&token.scopes);
    if !required.iter().all(|r| scopes_cover(&scopes, r)) {
        let _ = state.store.audit(&token, &nsid, "denied-scope");
        return err(StatusCode::FORBIDDEN, "insufficient_scope", format!("warrant does not cover {nsid}"));
    }

    // Repo writes must target the grantor's own repo.
    if let Some(repo) = json_body.as_ref().and_then(|b| b.get("repo")).and_then(|r| r.as_str()) {
        if repo != token.did {
            let _ = state.store.audit(&token, &nsid, "denied-foreign-repo");
            return err(StatusCode::FORBIDDEN, "insufficient_scope", "repo must be the grantor's own");
        }
    }

    // Forward with the account session; refresh once on auth failure.
    let account = match state.store.account_by_did(&token.did) {
        Ok(Some(a)) => a,
        Ok(None) => return err(StatusCode::FORBIDDEN, "invalid_token", "account no longer exists"),
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, "server_error", e.to_string()),
    };
    let query = uri.query();
    let send = |jwt: String, body: Vec<u8>| {
        let (state, method, nsid) = (state.clone(), method.to_string(), nsid.clone());
        let (query, content_type) = (query.map(String::from), content_type.map(String::from));
        async move {
            state
                .pds
                .forward(&method, &nsid, query.as_deref(), content_type.as_deref(), body, &jwt)
                .await
        }
    };

    let mut resp = match send(account.access_jwt.clone(), body.to_vec()).await {
        Ok(r) => r,
        Err(e) => return err(StatusCode::BAD_GATEWAY, "server_error", e.to_string()),
    };
    if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
        match state.pds.refresh_session(&account.refresh_jwt).await {
            Ok(s) => {
                let _ = state.store.update_session(&token.did, &s.access_jwt, &s.refresh_jwt);
                resp = match send(s.access_jwt, body.to_vec()).await {
                    Ok(r) => r,
                    Err(e) => return err(StatusCode::BAD_GATEWAY, "server_error", e.to_string()),
                };
            }
            Err(e) => return err(StatusCode::BAD_GATEWAY, "server_error", e.to_string()),
        }
    }

    let _ = state.store.audit(
        &token,
        &nsid,
        if resp.status().is_success() { "ok" } else { "pds-error" },
    );
    relay_response(resp).await
}

/// Transparent forward of anything that isn't bridge-token traffic.
/// TODO(P1 follow-up): websocket upgrade passthrough for the relay firehose
/// (`com.atproto.sync.subscribeRepos`) — local demos don't need it.
async fn passthrough(
    state: &S,
    method: &str,
    uri: &Uri,
    headers: &HeaderMap,
    body: Bytes,
) -> Response {
    let path_q = uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
    let url = format!("{}{}", state.pds.base(), path_q);
    let client = reqwest::Client::new();
    let mut req = match method {
        "GET" => client.get(&url),
        "POST" => client.post(&url).body(body.to_vec()),
        "PUT" => client.put(&url).body(body.to_vec()),
        "DELETE" => client.delete(&url),
        "HEAD" => client.head(&url),
        _ => return err(StatusCode::METHOD_NOT_ALLOWED, "invalid_request", "method not supported"),
    };
    for name in [header::AUTHORIZATION, header::CONTENT_TYPE, header::ACCEPT] {
        if let Some(v) = headers.get(&name).and_then(|v| v.to_str().ok()) {
            req = req.header(name.clone(), v);
        }
    }
    match req.send().await {
        Ok(resp) => relay_response(resp).await,
        Err(e) => err(StatusCode::BAD_GATEWAY, "server_error", e.to_string()),
    }
}

async fn relay_response(resp: reqwest::Response) -> Response {
    let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let content_type = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(String::from);
    match resp.bytes().await {
        Ok(bytes) => {
            let mut r = Response::builder().status(status);
            if let Some(ct) = content_type {
                r = r.header(header::CONTENT_TYPE, ct);
            }
            r.body(axum::body::Body::from(bytes)).unwrap_or_else(|_| {
                err(StatusCode::BAD_GATEWAY, "server_error", "response relay failed")
            })
        }
        Err(e) => err(StatusCode::BAD_GATEWAY, "server_error", e.to_string()),
    }
}
