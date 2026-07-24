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
// Labeler: DID doc + com.atproto.label.queryLabels
// ---------------------------------------------------------------------------

/// GET /.well-known/did.json — the did:web labeler document.
pub async fn did_json(State(state): State<S>) -> Response {
    match &state.labeler {
        Some(l) => Json(l.did_document()).into_response(),
        None => (StatusCode::NOT_FOUND, "labeler not configured").into_response(),
    }
}

/// GET /xrpc/com.atproto.label.queryLabels — return a signed label for each
/// requested post URI that is fully browserid-verified. bsky.app's AppView
/// applies these for users who subscribe to this labeler. `uriPatterns` is a
/// repeated query param, which axum's Query (serde_urlencoded) can't decode —
/// parse the raw query instead.
pub async fn query_labels(State(state): State<S>, raw: axum::extract::RawQuery) -> Response {
    let Some(labeler) = &state.labeler else {
        return (StatusCode::NOT_FOUND, "labeler not configured").into_response();
    };
    let patterns: Vec<String> = reqwest::Url::parse(&format!("http://x/?{}", raw.0.unwrap_or_default()))
        .map(|u| {
            u.query_pairs()
                .filter(|(k, _)| k == "uriPatterns")
                .map(|(_, v)| v.into_owned())
                .collect()
        })
        .unwrap_or_default();
    let mut labels = Vec::new();
    for uri in patterns.iter().take(200) {
        // Exact post at-uris only (ignore wildcard patterns for v1).
        let Some((did, coll, rkey)) = parse_at_uri(uri) else { continue };
        if coll != "app.bsky.feed.post" {
            continue;
        }
        // Evaluating here doubles as a catch-up path: a post nobody has
        // labeled yet gets one now, and it goes out on the firehose too, so
        // both surfaces always show the same label with the same `cts`.
        emit_label(&state, &did, &rkey).await;
        if let Ok(stored) = state.store.labels_for(uri) {
            labels.extend(stored.iter().map(|l| labeler.label_json(&l.uri, &l.val, &l.cts, &l.sig)));
        }
    }
    Json(serde_json::json!({ "labels": labels })).into_response()
}

/// Full public-grade verification of a post: delegation (warrant ← config
/// cert ← IdP, authoritative for grantor, audience, unexpired) AND the
/// unforgeable grantee attestation over this exact post. The bar for
/// emitting a label. (Shares logic with the `/verify` handler; a future
/// refactor extracts one `evaluate_post` — bean kozn-adjacent.)
/// GET /xrpc/com.atproto.label.subscribeLabels — the labeler firehose, and
/// the only delivery path that actually renders badges: the AppView ingests
/// this stream into its own label index (it does **not** call queryLabels on
/// the read path). Backfills everything above `cursor`, then tails live.
pub async fn subscribe_labels(
    State(state): State<S>,
    ws: axum::extract::ws::WebSocketUpgrade,
    raw: axum::extract::RawQuery,
) -> Response {
    if state.labeler.is_none() {
        return (StatusCode::NOT_FOUND, "labeler not configured").into_response();
    }
    let cursor: i64 = reqwest::Url::parse(&format!("http://x/?{}", raw.0.unwrap_or_default()))
        .ok()
        .and_then(|u| u.query_pairs().find(|(k, _)| k == "cursor").and_then(|(_, v)| v.parse().ok()))
        .unwrap_or(0);
    ws.on_upgrade(move |socket| stream_labels(state, socket, cursor))
}

async fn stream_labels(state: S, mut socket: axum::extract::ws::WebSocket, cursor: i64) {
    use axum::extract::ws::Message;
    let labeler = state.labeler.as_ref().expect("checked before upgrade");
    // Subscribe BEFORE backfilling so a label emitted mid-backfill is queued
    // rather than lost in the gap between the two.
    let mut live = state.label_tx.subscribe();
    let mut sent_through = cursor;
    loop {
        let batch = match state.store.labels_since(sent_through, 500) {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!("subscribeLabels backfill failed: {e}");
                return;
            }
        };
        if batch.is_empty() {
            break;
        }
        for l in &batch {
            if socket.send(Message::Binary(labeler.labels_frame(l))).await.is_err() {
                return;
            }
            sent_through = l.seq;
        }
    }
    loop {
        match live.recv().await {
            Ok(l) => {
                // Skip anything the backfill already covered.
                if l.seq <= sent_through {
                    continue;
                }
                if socket.send(Message::Binary(labeler.labels_frame(&l))).await.is_err() {
                    return;
                }
                sent_through = l.seq;
            }
            // Lagged: the consumer will reconnect with its cursor and
            // backfill the gap from the store, so just drop it.
            Err(_) => return,
        }
    }
}

/// Label any post in a hosted repo that carries provenance but has no label
/// yet. Run at startup so posts made before the labeler existed (or while it
/// was down) enter the firehose; idempotent, so repeated runs are cheap.
pub async fn backfill_labels(state: S) {
    if state.labeler.is_none() {
        return;
    }
    let accounts = match state.store.all_accounts() {
        Ok(a) => a,
        Err(e) => return tracing::warn!("label backfill: {e}"),
    };
    for account in accounts {
        let url = format!("{}/xrpc/com.atproto.repo.listRecords", state.pds.base_url());
        let resp = state
            .http
            .get(&url)
            .query(&[
                ("repo", account.did.as_str()),
                ("collection", "me.browserid.provenance"),
                ("limit", "100"),
            ])
            .send()
            .await;
        let Ok(v) = resp else { continue };
        let Ok(v) = v.json::<serde_json::Value>().await else { continue };
        let Some(records) = v["records"].as_array() else { continue };
        for r in records {
            // The provenance record shares its rkey with the post it describes.
            let Some((_, _, rkey)) = r["uri"].as_str().and_then(parse_at_uri) else { continue };
            emit_label(&state, &account.did, &rkey).await;
        }
    }
}

/// Verify a post and, if it earns a label, sign + persist + broadcast one.
/// Idempotent: a subject that already has a label is left alone, which keeps
/// firehose sequence numbers stable.
pub async fn emit_label(state: &S, did: &str, rkey: &str) {
    let Some(labeler) = &state.labeler else { return };
    let uri = format!("at://{did}/app.bsky.feed.post/{rkey}");
    match state.store.label_emitted(&uri) {
        Ok(true) => return,
        Ok(false) => {}
        Err(e) => {
            tracing::warn!("label lookup failed: {e}");
            return;
        }
    }
    let Some(on_behalf) = fully_verified(state, did, rkey).await else { return };
    let val = if on_behalf { crate::labeler::LABEL_ON_BEHALF } else { crate::labeler::LABEL_VERIFIED };
    let cts = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let sig = labeler.sign(&uri, val, &cts);
    match state.store.insert_label(&uri, val, &cts, &sig) {
        Ok(Some(l)) => {
            tracing::info!("labeled {uri} {val} (seq {})", l.seq);
            let _ = state.label_tx.send(l); // no subscribers is fine
        }
        Ok(None) => {}
        Err(e) => tracing::warn!("storing label failed: {e}"),
    }
}

/// Returns `Some(on_behalf)` when the post fully verifies — `on_behalf` is
/// true when grantor != grantee (a delegate acted for another identity) —
/// and `None` when anything fails to check out.
async fn fully_verified(state: &S, did: &str, rkey: &str) -> Option<bool> {
    let Some((pds, _)) = resolve_did_doc(state, did).await else { return None };
    let Some(prov) = get_record(state, &pds, did, "me.browserid.provenance", rkey).await else {
        return None;
    };
    let Some((wd, wc_, wk)) = prov["warrant"].as_str().and_then(parse_at_uri) else { return None };
    let Some(wrec) = get_record(state, &pds, &wd, &wc_, &wk).await else { return None };
    let (Ok(warrant), Ok(cc)) = (
        browserid_core::device::Warrant::parse(wrec["warrant"].as_str().unwrap_or("")),
        browserid_core::device::DeviceCert::parse(wrec["configCert"].as_str().unwrap_or("")),
    ) else {
        return None;
    };
    let w = warrant.claims();
    let grantor = &w.grantor;
    let grantee = &w.grantee;
    // Delegation.
    if warrant.verify(cc.public_key()).is_err() || !cc.authorizes_identity(grantor) {
        return None;
    }
    if w.audience != state.origin || Utc::now().timestamp() >= w.exp {
        return None;
    }
    match fetch_well_known_key(state, &cc.claims().iss).await {
        Some(k) if cc.verify(&k).is_ok() => {}
        _ => return None,
    }
    if prov["attributedTo"].as_str() != Some(grantor.as_str())
        || prov["executedBy"].as_str() != Some(grantee.as_str())
    {
        return None;
    }
    // Unforgeable attestation over this exact post.
    let Some(att) = prov.get("attestation") else { return None };
    let claims: Option<crate::attestation::AttestationClaims> =
        serde_json::from_value(att["claims"].clone()).ok();
    let sig = att["sig"].as_str().unwrap_or("");
    let acc = att["accessCert"].as_str().and_then(|c| browserid_core::device::AccessCert::parse(c).ok());
    let post = get_record(state, &pds, did, "app.bsky.feed.post", rkey).await;
    let (Some(cl), Some(a), Some(rec)) = (claims, acc, post) else { return None };
    let ac = a.claims();
    let idp_ok = matches!(fetch_well_known_key(state, &ac.iss).await, Some(k) if a.verify(&k).is_ok());
    let ok = cl.verify(&ac.access_key, sig)
        && ac.identity == *grantee
        && cl.content_hash == crate::attestation::content_hash(&rec)
        && cl.iat < ac.exp
        && prov["nonce"].as_str() == Some(cl.nonce.as_str())
        && idp_ok;
    ok.then(|| grantor != grantee)
}

// ---------------------------------------------------------------------------
// POST /browserid/post — attributed (signed) post (provenance phase 2)
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
pub struct AttestationEnvelope {
    pub claims: crate::attestation::AttestationClaims,
    pub sig: String,
}

#[derive(serde::Deserialize)]
pub struct AttributedPostReq {
    /// The full `app.bsky.feed.post` record the grantee authored & signed
    pub record: serde_json::Value,
    pub attestation: AttestationEnvelope,
    #[serde(rename = "accessCert")]
    pub access_cert: String,
}

/// Resolve + revocation-check a bearer bridge token, or return the 401/err
/// response. (Live warrant re-check mirrors the scoped proxy.)
async fn authorize_token(state: &S, headers: &HeaderMap) -> Result<crate::store::BridgeToken, Response> {
    let bearer = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .filter(|b| b.starts_with(TOKEN_PREFIX));
    let Some(bearer) = bearer else {
        return Err(err(StatusCode::UNAUTHORIZED, "invalid_token", "missing bridge token"));
    };
    let token = match state.store.token(bearer) {
        Ok(Some(t)) => t,
        Ok(None) => return Err(err(StatusCode::UNAUTHORIZED, "invalid_token", "unknown or expired token")),
        Err(e) => return Err(err(StatusCode::INTERNAL_SERVER_ERROR, "server_error", e.to_string())),
    };
    if let Some((uri_s, idx)) = &token.warrant_status {
        let r = StatusRef { uri: uri_s.clone(), idx: *idx };
        let mut verdict = state.status_cache.check(&r);
        if verdict == StatusVerdict::Unknown {
            let _ = state.status_cache.refresh(&r.uri, &state.broker_key).await;
            verdict = state.status_cache.check(&r);
        }
        match verdict {
            StatusVerdict::Revoked => {
                let _ = state.store.revoke_tokens_for_warrant(uri_s, *idx);
                return Err(err(StatusCode::UNAUTHORIZED, "invalid_token", "warrant revoked"));
            }
            StatusVerdict::Unknown => {
                return Err(err(StatusCode::FORBIDDEN, "invalid_token", "warrant status unavailable (fail-closed)"));
            }
            StatusVerdict::Valid => {}
        }
    }
    Ok(token)
}

/// createRecord on the account repo, refreshing the session once on expiry.
/// Returns the created record JSON and the (possibly refreshed) account.
async fn create_via_session(
    state: &S,
    did: &str,
    collection: &str,
    record: &serde_json::Value,
) -> Result<(serde_json::Value, Account), Response> {
    let mut account = match state.store.account_by_did(did) {
        Ok(Some(a)) => a,
        Ok(None) => return Err(err(StatusCode::FORBIDDEN, "invalid_token", "account no longer exists")),
        Err(e) => return Err(err(StatusCode::INTERNAL_SERVER_ERROR, "server_error", e.to_string())),
    };
    let body = serde_json::json!({ "repo": did, "collection": collection, "record": record });
    let body_bytes = serde_json::to_vec(&body).unwrap();
    let call = |jwt: String, bytes: Vec<u8>| {
        let state = state.clone();
        async move {
            state
                .pds
                .forward("POST", "com.atproto.repo.createRecord", None, Some("application/json"), bytes, &jwt)
                .await
                .map_err(|e| e.to_string())
        }
    };
    let mut resp = call(account.access_jwt.clone(), body_bytes.clone()).await;
    let expired = match &resp {
        Ok(r) => r.status() == reqwest::StatusCode::UNAUTHORIZED || r.status() == reqwest::StatusCode::BAD_REQUEST,
        Err(_) => false,
    };
    if expired {
        if let Ok(s) = state.pds.refresh_session(&account.refresh_jwt).await {
            let _ = state.store.update_session(did, &s.access_jwt, &s.refresh_jwt);
            account.access_jwt = s.access_jwt.clone();
            account.refresh_jwt = s.refresh_jwt.clone();
            resp = call(s.access_jwt, body_bytes).await;
        }
    }
    match resp {
        Ok(r) if r.status().is_success() => match r.json::<serde_json::Value>().await {
            Ok(v) => Ok((v, account)),
            Err(e) => Err(err(StatusCode::BAD_GATEWAY, "server_error", e.to_string())),
        },
        Ok(r) => {
            let code = r.status().as_u16();
            let b = r.text().await.unwrap_or_default();
            Err(err(StatusCode::BAD_GATEWAY, "server_error", format!("PDS {code}: {b}")))
        }
        Err(e) => Err(err(StatusCode::BAD_GATEWAY, "server_error", e)),
    }
}

pub async fn attributed_post(
    State(state): State<S>,
    headers: HeaderMap,
    Json(req): Json<AttributedPostReq>,
) -> Response {
    let token = match authorize_token(&state, &headers).await {
        Ok(t) => t,
        Err(e) => return e,
    };
    let att = &req.attestation;
    let claims = &att.claims;

    // 1. The access cert certifies the signing key as the grantee's.
    let Ok(access_cert) = browserid_core::device::AccessCert::parse(&req.access_cert) else {
        return err(StatusCode::BAD_REQUEST, "invalid_grant", "malformed access cert");
    };
    let ac = access_cert.claims();
    if ac.identity != token.grantee {
        return err(StatusCode::FORBIDDEN, "invalid_grant", "access cert is not the token's grantee");
    }
    let now = chrono::Utc::now().timestamp();
    if now >= ac.exp {
        return err(StatusCode::FORBIDDEN, "invalid_grant", "access cert expired");
    }
    // Chain the access cert to its IdP (advisory well-known; the authoritative
    // DNSSEC check happens at token exchange via the hosted verifier).
    match fetch_well_known_key(&state, &ac.iss).await {
        Some(k) if access_cert.verify(&k).is_ok() => {}
        _ => return err(StatusCode::FORBIDDEN, "invalid_grant", "access cert not verifiable to its IdP"),
    }

    // 2. The grantee's signature over the attestation.
    if !claims.verify(&access_cert.claims().access_key, &att.sig) {
        return err(StatusCode::BAD_REQUEST, "invalid_grant", "attestation signature invalid");
    }

    // 3. The attestation binds this exact post + is fresh.
    if claims.did != token.did || claims.collection != "app.bsky.feed.post" {
        return err(StatusCode::BAD_REQUEST, "invalid_grant", "attestation target mismatch");
    }
    if claims.content_hash != crate::attestation::content_hash(&req.record) {
        return err(StatusCode::BAD_REQUEST, "invalid_grant", "content hash does not match the post");
    }
    if (now - claims.iat).abs() > 600 {
        return err(StatusCode::BAD_REQUEST, "invalid_grant", "attestation not fresh (iat skew)");
    }

    // 4. Scope: the warrant must permit creating feed posts.
    let scopes = parse_scopes(&token.scopes);
    let required = crate::scopes::Required::Repo {
        collection: "app.bsky.feed.post".into(),
        action: crate::scopes::RepoAction::Create,
    };
    if !scopes_cover(&scopes, &required) {
        return err(StatusCode::FORBIDDEN, "insufficient_scope", "warrant does not permit creating posts");
    }

    // 5. Replay guard: claim the nonce before writing anything.
    match state.store.reserve_nonce(&claims.nonce, &token.did) {
        Ok(true) => {}
        Ok(false) => return err(StatusCode::CONFLICT, "invalid_grant", "attestation nonce already used (replay)"),
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, "server_error", e.to_string()),
    }

    // 6. Create the post, then wire up nonce + signed provenance.
    let (created, account) = match create_via_session(&state, &token.did, "app.bsky.feed.post", &req.record).await {
        Ok(x) => x,
        Err(e) => return e,
    };
    let post_uri = created["uri"].as_str().unwrap_or_default().to_string();
    let rkey = post_uri.rsplit('/').next().unwrap_or_default();
    let _ = state.store.set_nonce_rkey(&claims.nonce, rkey);
    let _ = state.store.audit(&token, "com.atproto.repo.createRecord", "ok-attested");

    let attestation_json = serde_json::json!({
        "claims": claims,
        "sig": att.sig,
        "accessCert": req.access_cert,
    });
    write_provenance(&state, &token, &account, &post_uri, created["cid"].as_str(), &claims.nonce, Some(attestation_json)).await;

    (StatusCode::OK, Json(created)).into_response()
}

// ---------------------------------------------------------------------------
// GET /verify?uri=<post at-uri>[&format=json] — provenance receipt
// ---------------------------------------------------------------------------
//
// Reads the post's me.browserid.provenance + referenced me.browserid.warrant
// off the repo and verifies the DELEGATION from the published records — not
// by trusting the bridge. Honest phase-1 caveat: the post<->grantee link is
// PDS-asserted until the grantee signature lands (bean n78o).

#[derive(serde::Deserialize)]
pub struct VerifyQuery {
    /// A post reference: an `at://…` URI or a `https://bsky.app/profile/…/post/…` URL
    #[serde(default)]
    pub uri: Option<String>,
    /// A verification nonce (the form an optional in-post link uses)
    #[serde(default)]
    pub n: Option<String>,
    #[serde(default)]
    pub format: Option<String>,
}

/// Turn a user-pasted post reference into `(did, rkey)`. Accepts an
/// `at://did/coll/rkey` URI or a `https://bsky.app/profile/<actor>/post/<rkey>`
/// URL; resolves a handle actor to a DID via the public AppView.
async fn resolve_post_ref(state: &S, raw: &str) -> Option<(String, String)> {
    let raw = raw.trim();
    if let Some((did, _coll, rkey)) = parse_at_uri(raw) {
        return Some((did, rkey));
    }
    // bsky.app / any host: .../profile/<actor>/post/<rkey>
    let after = raw.split("/profile/").nth(1)?;
    let mut seg = after.split('/');
    let actor = seg.next()?;
    if seg.next()? != "post" {
        return None;
    }
    let rkey = seg.next()?.split(['?', '#']).next()?.to_string();
    let did = if actor.starts_with("did:") {
        actor.to_string()
    } else {
        let v: serde_json::Value = state
            .http
            .get("https://public.api.bsky.app/xrpc/com.atproto.identity.resolveHandle")
            .query(&[("handle", actor)])
            .send()
            .await
            .ok()?
            .json()
            .await
            .ok()?;
        v["did"].as_str()?.to_string()
    };
    Some((did, rkey))
}

/// Resolve a did:plc/did:web to `(pds endpoint, handle)` from its DID doc
/// (so the verifier works for any account, not only ours).
async fn resolve_did_doc(state: &S, did: &str) -> Option<(String, Option<String>)> {
    let doc: serde_json::Value = state
        .http
        .get(format!("https://plc.directory/{did}"))
        .send()
        .await
        .ok()?
        .json()
        .await
        .ok()?;
    let pds = doc["service"]
        .as_array()?
        .iter()
        .find(|s| s["id"] == "#atproto_pds")
        .and_then(|s| s["serviceEndpoint"].as_str())
        .map(String::from)?;
    let handle = doc["alsoKnownAs"]
        .as_array()
        .and_then(|a| a.iter().find_map(|v| v.as_str()?.strip_prefix("at://")))
        .map(String::from);
    Some((pds, handle))
}

/// If a post record embeds a `…/verify?n=<nonce>` link (in a facet or in the
/// text), return that nonce — used to flag a post whose own verify link
/// points at a *different* post.
fn embedded_verify_nonce(rec: &serde_json::Value) -> Option<String> {
    let from = |uri: &str| -> Option<String> {
        uri.split_once("/verify?n=").map(|(_, n)| n.split(['&', ' ', '\n']).next().unwrap_or("").to_string())
    };
    // Facet link features.
    if let Some(facets) = rec["facets"].as_array() {
        for f in facets {
            if let Some(feats) = f["features"].as_array() {
                for feat in feats {
                    if let Some(uri) = feat["uri"].as_str() {
                        if let Some(n) = from(uri) {
                            return Some(n);
                        }
                    }
                }
            }
        }
    }
    // Fallback: a bare URL in the text.
    rec["text"].as_str().and_then(from)
}

async fn get_record(state: &S, pds: &str, did: &str, collection: &str, rkey: &str) -> Option<serde_json::Value> {
    let v: serde_json::Value = state
        .http
        .get(format!("{pds}/xrpc/com.atproto.repo.getRecord"))
        .query(&[("repo", did), ("collection", collection), ("rkey", rkey)])
        .send()
        .await
        .ok()?
        .json()
        .await
        .ok()?;
    v.get("value").cloned()
}

/// Split `at://did/collection/rkey` → (did, collection, rkey).
fn parse_at_uri(uri: &str) -> Option<(String, String, String)> {
    let rest = uri.strip_prefix("at://")?;
    let mut parts = rest.splitn(3, '/');
    Some((parts.next()?.to_string(), parts.next()?.to_string(), parts.next()?.to_string()))
}

fn root_identity(email: &str) -> String {
    match email.split_once('@') {
        Some((local, domain)) => format!("{}@{}", local.split('+').next().unwrap_or(local), domain),
        None => email.to_string(),
    }
}

#[cfg(test)]
mod verify_tests {
    use super::{parse_at_uri, root_identity};

    #[test]
    fn at_uri_parsing() {
        let (did, coll, rkey) =
            parse_at_uri("at://did:plc:abc/app.bsky.feed.post/3krfx").unwrap();
        assert_eq!(did, "did:plc:abc");
        assert_eq!(coll, "app.bsky.feed.post");
        assert_eq!(rkey, "3krfx");
        assert!(parse_at_uri("https://x/y").is_none());
        assert!(parse_at_uri("at://did:plc:abc/only-two").is_none());
    }

    #[test]
    fn root_strips_subaddress() {
        assert_eq!(root_identity("danmills+bluesky@sandmill.org"), "danmills@sandmill.org");
        assert_eq!(root_identity("dan@sandmill.org"), "dan@sandmill.org");
        assert_eq!(root_identity("weird"), "weird");
    }

    #[test]
    fn embedded_nonce_from_facet_and_text() {
        use super::embedded_verify_nonce;
        let facet = serde_json::json!({
            "text": "hi 🔗 verify",
            "facets": [{ "features": [{ "$type": "app.bsky.richtext.facet#link",
                          "uri": "https://bsky.browserid.me/verify?n=ABC123" }] }],
        });
        assert_eq!(embedded_verify_nonce(&facet).as_deref(), Some("ABC123"));
        // Bare URL in text fallback.
        let bare = serde_json::json!({ "text": "see https://bsky.browserid.me/verify?n=XYZ now" });
        assert_eq!(embedded_verify_nonce(&bare).as_deref(), Some("XYZ"));
        // No verify link.
        let none = serde_json::json!({ "text": "just a post" });
        assert_eq!(embedded_verify_nonce(&none), None);
    }
}

pub async fn verify(State(state): State<S>, axum::extract::Query(q): axum::extract::Query<VerifyQuery>) -> Response {
    let want_json = q.format.as_deref() == Some("json");
    let fail = |status: StatusCode, reason: &str| -> Response {
        if want_json {
            (status, Json(serde_json::json!({ "ok": false, "reason": reason }))).into_response()
        } else {
            (status, axum::response::Html(verify_html_err(reason))).into_response()
        }
    };

    // Resolve the target post from a nonce, a URI (at:// or bsky.app), or
    // — with neither — serve the paste-a-link page.
    let (did, rkey) = if let Some(nonce) = q.n.as_deref() {
        match state.store.resolve_nonce(nonce) {
            Ok(Some(pair)) => pair,
            Ok(None) => return fail(StatusCode::NOT_FOUND, "unknown verification nonce"),
            Err(e) => return fail(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
        }
    } else if let Some(uri) = q.uri.as_deref() {
        match resolve_post_ref(&state, uri).await {
            Some(pair) => pair,
            None => return fail(StatusCode::BAD_REQUEST, "not a recognizable post link (use an at:// URI or a bsky.app post URL)"),
        }
    } else {
        return axum::response::Html(verify_landing()).into_response();
    };
    let Some((pds, handle)) = resolve_did_doc(&state, &did).await else {
        return fail(StatusCode::NOT_FOUND, "could not resolve the account's PDS");
    };
    let post_uri = format!("at://{did}/app.bsky.feed.post/{rkey}");

    // Fetch the actual post so the receipt SHOWS what was verified — the
    // reader confirms it's the post they came from, defeating a spoofed
    // verify link that points at another (passing) post.
    let post_rec = get_record(&state, &pds, &did, "app.bsky.feed.post", &rkey).await;
    let post_text = post_rec.as_ref().and_then(|r| r["text"].as_str()).unwrap_or("").to_string();

    let Some(prov) = get_record(&state, &pds, &did, "me.browserid.provenance", &rkey).await else {
        return fail(StatusCode::NOT_FOUND, "no browserid provenance for this post");
    };
    let warrant_uri = prov["warrant"].as_str().unwrap_or_default();
    let Some((wdid, wcoll, wrkey)) = parse_at_uri(warrant_uri) else {
        return fail(StatusCode::UNPROCESSABLE_ENTITY, "provenance references no warrant record");
    };
    let Some(wrec) = get_record(&state, &pds, &wdid, &wcoll, &wrkey).await else {
        return fail(StatusCode::NOT_FOUND, "referenced warrant record missing");
    };

    // Verify the delegation from the published artifacts.
    let (warrant_jws, cc_jws) = (wrec["warrant"].as_str().unwrap_or(""), wrec["configCert"].as_str().unwrap_or(""));
    let (Ok(warrant), Ok(cc)) = (
        browserid_core::device::Warrant::parse(warrant_jws),
        browserid_core::device::DeviceCert::parse(cc_jws),
    ) else {
        return fail(StatusCode::UNPROCESSABLE_ENTITY, "malformed warrant/config-cert");
    };
    let wc = warrant.claims();
    let grantor = wc.grantor.clone();
    let grantee = wc.grantee.clone();

    // IdP key for the config cert's issuer (advisory well-known fetch; the
    // authoritative DNSSEC-rooted check runs at post time via the hosted
    // verifier — stated in the receipt).
    let iss = cc.claims().iss.clone();
    let idp_key = fetch_well_known_key(&state, &iss).await;

    let mut checks = serde_json::Map::new();
    let mut ok = true;
    let mut check = |name: &str, pass: bool, checks: &mut serde_json::Map<String, serde_json::Value>, ok: &mut bool| {
        checks.insert(name.into(), serde_json::Value::Bool(pass));
        if !pass { *ok = false; }
    };
    check("warrant_signed_by_config_cert", warrant.verify(cc.public_key()).is_ok(), &mut checks, &mut ok);
    check("config_cert_authoritative_for_grantor", cc.authorizes_identity(&grantor), &mut checks, &mut ok);
    match &idp_key {
        Some(k) => check("config_cert_signed_by_idp", cc.verify(k).is_ok(), &mut checks, &mut ok),
        None => check("config_cert_signed_by_idp", false, &mut checks, &mut ok),
    }
    check("audience_is_this_bridge", wc.audience == state.origin, &mut checks, &mut ok);
    let now = chrono::Utc::now().timestamp();
    check("warrant_unexpired", now < wc.exp, &mut checks, &mut ok);
    check("provenance_matches_warrant",
        prov["attributedTo"].as_str() == Some(&grantor) && prov["executedBy"].as_str() == Some(&grantee),
        &mut checks, &mut ok);

    // Phase 2: if the post carries a grantee attestation, verify the
    // unforgeable post↔grantee binding by recomputing the content hash from
    // the *published* post and checking the grantee's signature.
    let mut post_binding_verified = false;
    if let Some(att) = prov.get("attestation") {
        let mut att_ok = true;
        let claims: Option<crate::attestation::AttestationClaims> =
            serde_json::from_value(att["claims"].clone()).ok();
        let sig = att["sig"].as_str().unwrap_or("");
        let access_cert = att["accessCert"].as_str().and_then(|c| browserid_core::device::AccessCert::parse(c).ok());
        match (&claims, &access_cert, &post_rec) {
            (Some(cl), Some(acc), Some(rec)) => {
                let acc_claims = acc.claims();
                check("attestation_signed_by_grantee", cl.verify(&acc.claims().access_key, sig), &mut checks, &mut att_ok);
                check("access_cert_is_grantee", acc_claims.identity == grantee, &mut checks, &mut att_ok);
                let idp2 = fetch_well_known_key(&state, &acc_claims.iss).await;
                check("access_cert_signed_by_idp", idp2.map(|k| acc.verify(&k).is_ok()).unwrap_or(false), &mut checks, &mut att_ok);
                check("content_hash_matches_post", cl.content_hash == crate::attestation::content_hash(rec), &mut checks, &mut att_ok);
                check("attestation_within_cert_validity", cl.iat < acc_claims.exp, &mut checks, &mut att_ok);
                check("nonce_matches_provenance", prov["nonce"].as_str() == Some(cl.nonce.as_str()), &mut checks, &mut att_ok);
                post_binding_verified = att_ok;
            }
            _ => {
                check("attestation_well_formed", false, &mut checks, &mut att_ok);
            }
        }
        if !att_ok { ok = false; }
    }

    // Anti-spoof: if the post embeds its OWN `verify?n=` link (facet), that
    // nonce must be this post's nonce. A post pointing its verify link at a
    // *different* (passing) post is flagged, and the receipt always shows the
    // actual post below so a reader can confirm it's the one they came from.
    let own_nonce = prov["nonce"].as_str().unwrap_or("");
    if let Some(linked) = post_rec.as_ref().and_then(embedded_verify_nonce) {
        check("embedded_link_matches_this_post", linked == own_nonce, &mut checks, &mut ok);
    }

    let root = root_identity(&grantor);
    let post_url = handle.as_ref().map(|h| format!("https://bsky.app/profile/{h}/post/{rkey}"));
    let caveat = if post_binding_verified {
        "Fully verified: the delegation AND the grantee's signature over this exact post's content are cryptographically checked — unforgeable, independent of the PDS."
    } else if prov.get("attestation").is_some() {
        "This post carries an attestation but it did not verify — treat the post↔grantee binding as unproven."
    } else {
        "Phase 1: the delegation is verified from the published records, but the link from this exact post to the grantee is asserted by the PDS (no grantee signature present)."
    };
    let result = serde_json::json!({
        "ok": ok,
        "post": post_uri,
        "postText": post_text,
        "postHandle": handle,
        "postUrl": post_url,
        "attributedTo": grantor,
        "executedBy": grantee,
        "root": root,
        "onBehalf": grantor != grantee,
        "postBindingVerified": post_binding_verified,
        "audience": wc.audience,
        "scopes": wc.scopes,
        "issuer": iss,
        "delegationVerified": ok,
        "checks": serde_json::Value::Object(checks),
        "warrantRecord": warrant_uri,
        "caveat": caveat,
    });
    if want_json {
        Json(result).into_response()
    } else {
        axum::response::Html(verify_html(&result)).into_response()
    }
}

async fn fetch_well_known_key(state: &S, domain: &str) -> Option<browserid_core::PublicKey> {
    let doc: browserid_core::discovery::SupportDocument = state
        .http
        .get(format!("https://{domain}/.well-known/browserid"))
        .send()
        .await
        .ok()?
        .error_for_status()
        .ok()?
        .json()
        .await
        .ok()?;
    doc.public_key
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

fn verify_landing() -> String {
    "<!doctype html><meta charset=utf-8><title>browserid · verify a Bluesky post</title>\
     <meta name=viewport content='width=device-width,initial-scale=1'>\
     <div style='font:16px/1.5 system-ui;max-width:40rem;margin:4rem auto;padding:0 1rem'>\
     <h1>Verify a Bluesky post</h1>\
     <p>Paste a post link — a <code>bsky.app</code> URL or an <code>at://</code> URI — \
     to see who authorized it and who acted, verified against browserid.</p>\
     <form onsubmit=\"event.preventDefault();location='/verify?uri='+encodeURIComponent(document.getElementById('u').value)\">\
     <input id=u style='width:100%;padding:.6rem;font-size:1rem;box-sizing:border-box' \
     placeholder='https://bsky.app/profile/…/post/… or at://…'>\
     <button style='margin-top:.8rem;padding:.6rem 1.2rem;font-size:1rem'>Verify</button>\
     </form></div>"
        .to_string()
}

fn verify_html_err(reason: &str) -> String {
    format!(
        "<!doctype html><meta charset=utf-8><title>browserid verify</title>\
         <div style='font:16px system-ui;max-width:40rem;margin:4rem auto;padding:0 1rem'>\
         <h1>Not verifiable</h1><p>{}</p></div>",
        esc(reason)
    )
}

fn verify_html(r: &serde_json::Value) -> String {
    let ok = r["ok"].as_bool().unwrap_or(false);
    let badge = if ok { "✓ delegation verified" } else { "✗ verification failed" };
    let color = if ok { "#0a7d33" } else { "#b00020" };
    let bound = r["postBindingVerified"].as_bool().unwrap_or(false);
    let binding_line = if bound {
        "<div style='color:#0a7d33'>🔒 authorship cryptographically bound to this post (unforgeable)</div>"
    } else {
        "<div style='color:#a06000'>authorship of this exact post is PDS-asserted (no valid grantee signature)</div>"
    };
    let on_behalf = r["onBehalf"].as_bool().unwrap_or(false);
    let relation = if on_behalf {
        format!("<b>{}</b> posted <b>on behalf of</b> <b>{}</b>", esc(r["executedBy"].as_str().unwrap_or("")), esc(r["attributedTo"].as_str().unwrap_or("")))
    } else {
        format!("<b>{}</b> posted as itself", esc(r["attributedTo"].as_str().unwrap_or("")))
    };
    // The verified post itself, shown so the reader confirms it's the post
    // they came from (anti-spoof).
    let post_handle = r["postHandle"].as_str().unwrap_or("(unknown handle)");
    let post_text = r["postText"].as_str().unwrap_or("");
    let post_link = r["postUrl"].as_str();
    let post_card = format!(
        "<div style='border:1px solid #ccc;border-radius:8px;padding:.8rem 1rem;margin:1rem 0;background:#fafafa'>\
         <div style='color:#555;font-size:.85rem'>verified post{}</div>\
         <div style='white-space:pre-wrap;margin-top:.3rem'>{}</div>\
         <div style='margin-top:.4rem;font-size:.85rem'>— <b>{}</b>{}</div></div>",
        "", esc(post_text), esc(post_handle),
        post_link.map(|u| format!(" · <a href='{}'>open on bsky.app</a>", esc(u))).unwrap_or_default(),
    );
    let scopes = r["scopes"].as_array().map(|a| a.iter().filter_map(|s| s.as_str()).collect::<Vec<_>>().join(", ")).unwrap_or_default();
    let rows = r["checks"].as_object().map(|m| {
        m.iter().map(|(k, v)| format!("<tr><td>{}</td><td>{}</td></tr>", esc(k), if v.as_bool().unwrap_or(false) {"✓"} else {"✗"})).collect::<String>()
    }).unwrap_or_default();
    format!(
        "<!doctype html><meta charset=utf-8><title>browserid verify</title>\
         <div style='font:16px/1.5 system-ui;max-width:44rem;margin:3rem auto;padding:0 1rem'>\
         <div style='color:{color};font-weight:700;font-size:1.3rem'>{badge}</div>\
         {binding_line}\
         {post_card}\
         <p style='font-size:1.1rem'>{relation}, authorized under <b>{root}</b>.</p>\
         <p>Audience: <code>{aud}</code><br>Scopes: <code>{scopes}</code><br>IdP: <code>{iss}</code></p>\
         <table style='border-collapse:collapse' cellpadding=6>{rows}</table>\
         <p style='color:#666;font-size:.9rem;margin-top:1.5rem'>{caveat}</p>\
         <p style='color:#999;font-size:.8rem'>Post: <code>{post}</code></p></div>",
        color = color, badge = badge, binding_line = binding_line, post_card = post_card, relation = relation,
        root = esc(r["root"].as_str().unwrap_or("")),
        aud = esc(r["audience"].as_str().unwrap_or("")),
        scopes = esc(&scopes), iss = esc(r["issuer"].as_str().unwrap_or("")),
        rows = rows, caveat = esc(r["caveat"].as_str().unwrap_or("")),
        post = esc(r["post"].as_str().unwrap_or("")),
    )
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
    let mut account = match state.store.account_by_did(&token.did) {
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
    // The PDS signals an expired account access JWT as 401, or as 400 with
    // `error: "ExpiredToken"`. On either, refresh via the refresh JWT and
    // retry once. (We must peek the body to see the 400 case, so buffer it
    // and rebuild the response if it turns out not to be an expiry.)
    if resp.status() == reqwest::StatusCode::UNAUTHORIZED
        || resp.status() == reqwest::StatusCode::BAD_REQUEST
    {
        let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
        let ct = resp.headers().get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).map(String::from);
        let bytes = match resp.bytes().await {
            Ok(b) => b,
            Err(e) => return err(StatusCode::BAD_GATEWAY, "server_error", e.to_string()),
        };
        let expired = status == StatusCode::UNAUTHORIZED
            || bytes.windows(12).any(|w| w == b"ExpiredToken");
        if expired {
            match state.pds.refresh_session(&account.refresh_jwt).await {
                Ok(s) => {
                    let _ = state.store.update_session(&token.did, &s.access_jwt, &s.refresh_jwt);
                    // Keep the local copy fresh — write_provenance below uses it.
                    account.access_jwt = s.access_jwt.clone();
                    account.refresh_jwt = s.refresh_jwt.clone();
                    resp = match send(s.access_jwt, body.to_vec()).await {
                        Ok(r) => r,
                        Err(e) => return err(StatusCode::BAD_GATEWAY, "server_error", e.to_string()),
                    };
                }
                Err(e) => return err(StatusCode::BAD_GATEWAY, "server_error", e.to_string()),
            }
        } else {
            // A genuine client error — relay it verbatim.
            let _ = state.store.audit(&token, &nsid, "pds-error");
            let mut b = Response::builder().status(status);
            if let Some(ct) = ct {
                b = b.header(header::CONTENT_TYPE, ct);
            }
            return b
                .body(axum::body::Body::from(bytes))
                .unwrap_or_else(|_| err(StatusCode::BAD_GATEWAY, "server_error", "relay failed"));
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
                // Phase-1 (unsigned proxy) path: bridge mints the nonce.
                let mut nb = [0u8; 16];
                rand::thread_rng().fill_bytes(&mut nb);
                let nonce = URL_SAFE_NO_PAD.encode(nb);
                let rkey = uri.rsplit('/').next().unwrap_or_default();
                let _ = state.store.put_nonce(&nonce, &account.did, rkey);
                write_provenance(state, &token, &account, uri, v["cid"].as_str(), &nonce, None).await;
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
    nonce: &str,
    attestation: Option<serde_json::Value>,
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

    // Per-post provenance, rkey = the post's rkey (1:1, findable by at-uri).
    let rkey = post_uri.rsplit('/').next().unwrap_or_default();

    let mut prov = serde_json::json!({
        "$type": "me.browserid.provenance",
        "post": post_uri,
        "warrant": warrant_record_uri,
        "attributedTo": token.grantor,
        "executedBy": token.grantee,
        "nonce": nonce,
    });
    if let Some(cid) = post_cid {
        prov["postCid"] = serde_json::Value::String(cid.to_string());
    }
    // Phase 2: the grantee's signed attestation, if this post carried one.
    if let Some(att) = attestation {
        prov["attestation"] = att;
    }
    if let Err(e) = state
        .pds
        .put_record(&account.did, "me.browserid.provenance", Some(rkey), prov, &account.access_jwt)
        .await
    {
        tracing::warn!("provenance: record write failed: {e}");
        return;
    }
    // The post is now verifiable, so label it and push it to the firehose —
    // that stream is what puts the badge in front of subscribers.
    emit_label(state, &account.did, rkey).await;
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
