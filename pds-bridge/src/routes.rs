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
use browserid_core::{RpChallenge, StatusRef};
use browserid_rp::{oauth_metadata_with_scopes, StatusVerdict};

use crate::scopes::{parse_scopes, required_for, scopes_cover};
use crate::store::{Account, BridgeToken, TOKEN_PREFIX};
use crate::{BridgeState, ADVERTISED_SCOPES, RESERVED_LABELS, TOKEN_TTL_MINUTES};

type S = Arc<BridgeState>;

fn err(status: StatusCode, code: &str, msg: impl Into<String>) -> Response {
    (status, Json(serde_json::json!({ "error": code, "error_description": msg.into() })))
        .into_response()
}

/// What the bridge learns from a verified presentation.
pub struct Verified {
    pub grantor: String,
    pub grantee: String,
    pub holder: String,
    pub scopes: Vec<String>,
    pub warrant_status: Option<StatusRef>,
    /// The signed delegation artifacts, kept so the bridge can publish a
    /// `me.browserid.warrant` record and reference it from provenance
    /// (bean 27c0 phase 1).
    pub warrant_jws: String,
    pub config_cert_jws: String,
}

/// Verify a presentation by **outsourcing to the hosted verifier**
/// (`POST {broker}/verify-access`) — one verification algorithm, running
/// where it is maintained, with real DNSSEC-rooted discovery (bean
/// browserid-ng-kozn tracks in-process reuse of the same algorithm). The
/// hosted response omits grantee/warrant-status (audit D2), so those claims
/// are read from the just-verified bundle and cross-checked against the
/// verifier's answer.
async fn verify_presentation(state: &S, presentation: &str) -> Result<Verified, Response> {
    let resp = state
        .http
        .post(format!("{}/verify-access", state.broker_url))
        .json(&serde_json::json!({ "presentation": presentation, "audience": state.origin }))
        .send()
        .await
        .map_err(|e| {
            err(StatusCode::BAD_GATEWAY, "server_error", format!("hosted verifier unreachable: {e}"))
        })?;
    let v: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| err(StatusCode::BAD_GATEWAY, "server_error", e.to_string()))?;
    if v["status"] != "okay" {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            format!("assertion rejected: {}", v["reason"].as_str().unwrap_or("verification failed")),
        ));
    }
    let email = v["email"]
        .as_str()
        .ok_or_else(|| err(StatusCode::BAD_GATEWAY, "server_error", "verifier response missing email"))?;

    let pres = AccessPresentation::parse(presentation)
        .map_err(|e| err(StatusCode::BAD_REQUEST, "invalid_grant", e.to_string()))?;
    let wc = pres.warrant.claims();
    if wc.grantor != email || wc.audience != state.origin {
        return Err(err(StatusCode::BAD_REQUEST, "invalid_grant", "bundle/verifier mismatch"));
    }
    Ok(Verified {
        grantor: email.to_string(),
        grantee: wc.grantee.clone(),
        holder: v["holder"].as_str().unwrap_or_default().to_string(),
        scopes: v["scopes"]
            .as_array()
            .map(|a| a.iter().filter_map(|s| s.as_str().map(String::from)).collect())
            .unwrap_or_else(|| wc.scopes.clone()),
        warrant_status: wc.status.clone(),
        warrant_jws: pres.warrant.encoded().to_string(),
        config_cert_jws: pres.config_cert.encoded().to_string(),
    })
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
    if identity.grantee != identity.grantor {
        return err(
            StatusCode::FORBIDDEN,
            "invalid_grant",
            "provisioning requires a first-party login (grantee == grantor)",
        );
    }
    let email = identity.grantor;

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
    let account = match state.store.account_by_email(&identity.grantor) {
        Ok(Some(a)) => a,
        Ok(None) => {
            return err(
                StatusCode::FORBIDDEN,
                "invalid_grant",
                format!("{} has no account here — provision first", identity.grantor),
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

    // Persist the delegation artifacts (idempotent) so the post path can
    // publish/reference a single me.browserid.warrant record (bean 27c0).
    let warrant_ref = crate::store::warrant_hash(&identity.warrant_jws);
    if let Err(e) = state.store.upsert_warrant(&crate::store::StoredWarrant {
        hash: warrant_ref.clone(),
        did: account.did.clone(),
        grantor: identity.grantor.clone(),
        grantee: identity.grantee.clone(),
        warrant_jws: identity.warrant_jws.clone(),
        config_cert_jws: identity.config_cert_jws.clone(),
        record_uri: None,
    }) {
        return err(StatusCode::INTERNAL_SERVER_ERROR, "server_error", e.to_string());
    }

    let token = BridgeToken {
        did: account.did,
        grantor: identity.grantor,
        grantee: identity.grantee,
        holder: identity.holder,
        scopes: granted.clone(),
        warrant_status: identity.warrant_status.map(|r| (r.uri, r.idx)),
        warrant_ref,
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
        let header_value =
            RpChallenge::new(state.origin.clone(), format!("{}/browserid/token", state.origin))
                .with_scopes(ADVERTISED_SCOPES.iter().map(|s| s.to_string()))
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
    // Warrant lists come from the broker's registry, so its published key
    // verifies them (a status-list client, not verification logic).
    if let Some((uri_s, idx)) = &token.warrant_status {
        let r = StatusRef { uri: uri_s.clone(), idx: *idx };
        let mut verdict = state.status_cache.check(&r);
        if verdict == StatusVerdict::Unknown {
            if let Err(e) = state.status_cache.refresh(&r.uri, &state.broker_key).await {
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

    let success = resp.status().is_success();
    let _ = state.store.audit(&token, &nsid, if success { "ok" } else { "pds-error" });

    // On a successful post creation, write sidecar provenance (bean 27c0
    // phase 1). Buffer the PDS response so we can read the new record's
    // uri/cid, then relay the same bytes back.
    let is_post_create = method == "POST"
        && nsid == "com.atproto.repo.createRecord"
        && json_body.as_ref().and_then(|b| b["collection"].as_str()) == Some("app.bsky.feed.post");
    if success && is_post_create {
        let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::OK);
        let ct = resp
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(String::from);
        let bytes = match resp.bytes().await {
            Ok(b) => b,
            Err(e) => return err(StatusCode::BAD_GATEWAY, "server_error", e.to_string()),
        };
        if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&bytes) {
            if let Some(uri) = v["uri"].as_str() {
                write_provenance(state, &token, &account, uri, v["cid"].as_str()).await;
            }
        }
        let mut b = Response::builder().status(status);
        if let Some(ct) = ct {
            b = b.header(header::CONTENT_TYPE, ct);
        }
        return b
            .body(axum::body::Body::from(bytes))
            .unwrap_or_else(|_| err(StatusCode::BAD_GATEWAY, "server_error", "relay failed"));
    }

    relay_response(resp).await
}

/// Write the sidecar provenance for a just-created post: ensure the
/// warrant record exists once (dedup), then a per-post provenance record
/// referencing it. Failures are logged, not fatal — the post already
/// succeeded. Phase 1: the post↔grantee link is PDS-asserted (see bean
/// browserid-bsky-n78o for the unforgeable signature).
async fn write_provenance(
    state: &S,
    token: &crate::store::BridgeToken,
    account: &Account,
    post_uri: &str,
    post_cid: Option<&str>,
) {
    let Ok(Some(w)) = state.store.warrant_by_hash(&token.warrant_ref) else {
        tracing::warn!(reff = %token.warrant_ref, "provenance: warrant not found");
        return;
    };

    // Ensure the warrant record is published exactly once.
    let warrant_record_uri = match w.record_uri.clone() {
        Some(u) => u,
        None => {
            let record = serde_json::json!({
                "$type": "me.browserid.warrant",
                "warrant": w.warrant_jws,
                "configCert": w.config_cert_jws,
                "attributedTo": w.grantor,
                "executedBy": w.grantee,
            });
            match state
                .pds
                .put_record(&account.did, "me.browserid.warrant", Some(&token.warrant_ref), record, &account.access_jwt)
                .await
            {
                Ok(uri) => {
                    let _ = state.store.set_warrant_record_uri(&token.warrant_ref, &uri);
                    uri
                }
                Err(e) => {
                    tracing::warn!("provenance: warrant record write failed: {e}");
                    return;
                }
            }
        }
    };

    // Per-post provenance, rkey = the post's rkey (1:1, findable).
    let rkey = post_uri.rsplit('/').next().unwrap_or_default();
    let mut prov = serde_json::json!({
        "$type": "me.browserid.provenance",
        "post": post_uri,
        "warrant": warrant_record_uri,
        "attributedTo": token.grantor,
        "executedBy": token.grantee,
    });
    if let Some(cid) = post_cid {
        prov["postCid"] = serde_json::Value::String(cid.to_string());
    }
    if let Err(e) = state
        .pds
        .put_record(&account.did, "me.browserid.provenance", Some(rkey), prov, &account.access_jwt)
        .await
    {
        tracing::warn!("provenance: record write failed: {e}");
    }
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
