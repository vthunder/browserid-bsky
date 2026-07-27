//! The browserid protocol surface: support document, cert issuance, the
//! headless mint, and D's own status list.
//!
//! Structurally this is the mingo-idp reference IdP — `/device_cert` issues
//! an authentication cert plus an authorization *config* cert covering
//! `<handle>+*@D`, and `/access/mint` is headless, CORS-open, and copies the
//! device cert's holder verbatim. Two things are new here:
//!
//! * **Every cert carries a status ref.** mingo issues with `status: None`;
//!   we allocate an index in D's own list, so revoking a suspended binding
//!   takes minutes rather than a cert lifetime.
//! * **The mint re-verifies the handle.** An access cert is not just a
//!   restatement of the device cert — before minting, the public
//!   handle↔DID binding is re-resolved and checked against the pin. That is
//!   what bounds detection of a handle move, a lapsed domain, a migration,
//!   or a takedown to ~24 hours, with no stored session anywhere.

use std::sync::Arc;

use axum::extract::State;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use browserid_core::device::{
    AccessCert, AccessRequest, DeviceCert, Holder, Purpose, ACCESS_CERT_VALIDITY_HOURS,
};
use browserid_core::discovery::SupportDocument;
use browserid_core::status::{StatusList, StatusListToken};
use browserid_core::{PublicKey, StatusRef};
use serde::{Deserialize, Serialize};

use super::{pins, resolve, IdpError, IdpState, DEVICE_CERT_DAYS};
use crate::BridgeState;

type S = Arc<BridgeState>;

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

/// `GET /.well-known/browserid` — D's support document.
///
/// The `public-key` here is **advisory**. DNSSEC is the trust root: an RP
/// discovers D's key from the signed `_browserid.bsky.browserid.me` TXT
/// record, and this document only tells it which endpoints to call. A
/// document that disagreed with DNS would not become authoritative.
pub async fn well_known(State(state): State<S>) -> Response {
    match super::require_idp(&state) {
        Ok(st) => Json(support_document(st)).into_response(),
        Err(e) => e.into_response(),
    }
}

/// The support document as data, so it can be asserted on directly.
pub fn support_document(st: &IdpState) -> serde_json::Value {
    let doc = SupportDocument::new(st.keypair.public_key())
        .with_device_cert("/idp/device_cert")
        .with_access_cert("/idp/access/mint")
        .with_device_authorization("/idp/device-authorize")
        // The same page serves agent mode (`#agent_email=…`), so named
        // `<handle>+<tag>` agents are supported here, not just as-you ones.
        .with_agent_device_authorization("/idp/device-authorize");
    serde_json::to_value(&doc).unwrap_or_else(|_| serde_json::json!({}))
}

/// `GET /.well-known/browserid-status` — D's signed revocation bitmap
/// (core §6.4), rebuilt per request.
///
/// Rebuilding every time is deliberate, and copied from the registrar: the
/// bitmap is tiny, Ed25519 signing is cheap, and it means `iat` is always
/// honest. Consumers cache by the token's own `ttl`.
pub async fn status_list(State(state): State<S>) -> Response {
    let st = match super::require_idp(&state) {
        Ok(st) => st,
        Err(e) => return e.into_response(),
    };
    let (revoked, max) = match state.store.idp_revoked_status_indices() {
        Ok(v) => v,
        Err(e) => return IdpError::from(e).into_response(),
    };
    let list = StatusList::from_revoked(revoked, max);
    match StatusListToken::create(&st.domain, &st.status_list_uri(), &list, &st.keypair) {
        Ok(token) => token.encoded().to_string().into_response(),
        Err(e) => IdpError::Internal(format!("status list: {e}")).into_response(),
    }
}

// ---------------------------------------------------------------------------
// Device certs
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct PubKeyJson {
    pub algorithm: String,
    #[serde(rename = "publicKey")]
    pub public_key: String,
}

fn parse_pubkey(p: &PubKeyJson) -> Result<PublicKey, IdpError> {
    if p.algorithm != "Ed25519" {
        return Err(IdpError::BadRequest(format!("unsupported algorithm: {}", p.algorithm)));
    }
    PublicKey::from_base64(&p.public_key)
        .map_err(|e| IdpError::BadRequest(format!("invalid public key: {e}")))
}

/// Derive a stable, opaque holder from a device key, for clients that send
/// none. Deterministic so a re-issue lands in the same device slot, and
/// dotted so the browser can form a `<prefix>.*` login matcher.
fn holder_for_device(device_pub: &PublicKey) -> String {
    let clean: String = device_pub
        .to_base64()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect();
    let pre = &clean[..6.min(clean.len())];
    let id = &clean[6.min(clean.len())..16.min(clean.len())];
    format!("br{pre}.{id}")
}

/// This identity's slot in D's status list, as a ref to embed in a cert.
/// The index is per identity and reused across every cert and renewal, so
/// one flipped bit revokes the lot — see `Store::idp_status_idx`.
fn status_ref(st: &IdpState, state: &S, identity: &str) -> Result<StatusRef, IdpError> {
    let idx = state.store.idp_status_idx(identity)?;
    Ok(StatusRef { uri: st.status_list_uri(), idx })
}

#[derive(Deserialize)]
pub struct DeviceCertReq {
    pub device_pubkey: PubKeyJson,
    pub config_pubkey: PubKeyJson,
    /// The broker's stable per-browser holder — opaque, signed verbatim.
    #[serde(default)]
    pub holder: Option<String>,
}

#[derive(Serialize)]
pub struct DeviceCertResp {
    pub success: bool,
    pub device_cert: String,
    pub config_cert: String,
    pub identity: String,
}

/// `POST /idp/device_cert` — issue the session identity's device + config
/// certs.
///
/// Session-gated, and the session only exists because an atproto OAuth hop
/// just proved the handle. Before signing anything we re-confirm the pin
/// is live: a session that outlived a suspension must not keep minting.
pub async fn device_cert(
    State(state): State<S>,
    headers: HeaderMap,
    Json(req): Json<DeviceCertReq>,
) -> Result<Json<DeviceCertResp>, IdpError> {
    let st = super::require_idp(&state)?;
    let session = super::routes::require_session(&state, &headers)?;
    let handle = session
        .handle
        .ok_or_else(|| IdpError::BadRequest("this session is not signed in as a handle".into()))?;
    let pin = state.store.idp_pin(&handle)?;
    if pin.as_ref().is_none_or(|p| p.suspended || p.did != session.did) {
        return Err(IdpError::BindingSuspended(format!(
            "the binding for {handle} is no longer active — sign in again"
        )));
    }

    let identity = format!("{handle}@{}", st.domain);
    let device_pub = parse_pubkey(&req.device_pubkey)?;
    let config_pub = parse_pubkey(&req.config_pubkey)?;
    let validity = chrono::Duration::days(DEVICE_CERT_DAYS);

    // One holder per device slot, carried by both certs. The client's is
    // opaque passthrough; absent, derive one.
    let holder_str = match req.holder.as_deref() {
        Some(h) if !h.is_empty() => h.to_string(),
        _ => holder_for_device(&device_pub),
    };
    let holder =
        Holder::new(holder_str).map_err(|e| IdpError::BadRequest(format!("holder: {e}")))?;

    // One status slot, carried by both certs: they belong to one identity
    // and are revoked together or not at all.
    let status = status_ref(st, &state, &identity)?;

    let device_cert = DeviceCert::create(
        &st.domain,
        &device_pub,
        Purpose::Authentication,
        holder.clone(),
        vec![identity.clone()],
        validity,
        &st.keypair,
        Some(status.clone()),
    )
    .map_err(|e| IdpError::Internal(format!("device cert: {e}")))?;

    // The config cert also covers `<handle>+*@D`, so it can sign warrants
    // for the person's agent sub-identities without another visit here.
    let config_cert = DeviceCert::create(
        &st.domain,
        &config_pub,
        Purpose::Authorization,
        holder,
        vec![identity.clone(), format!("{handle}+*@{}", st.domain)],
        validity,
        &st.keypair,
        Some(status),
    )
    .map_err(|e| IdpError::Internal(format!("config cert: {e}")))?;

    Ok(Json(DeviceCertResp {
        success: true,
        device_cert: device_cert.encoded().to_string(),
        config_cert: config_cert.encoded().to_string(),
        identity,
    }))
}

#[derive(Deserialize)]
pub struct AgentDeviceCertReq {
    pub agent_pubkey: PubKeyJson,
    /// Full agent identity `<handle>+<tag>@D`.
    pub agent_email: String,
    /// The broker-assigned holder (opaque passthrough, required — an
    /// agent's holder is never minted here).
    pub holder: String,
}

#[derive(Serialize)]
pub struct AgentDeviceCertResp {
    pub success: bool,
    pub device_cert: String,
    pub identity: String,
}

/// `POST /idp/agent_device_cert` — certify an agent identity for the
/// signed-in handle.
///
/// Needed because a presentation's config cert and access cert must share
/// one issuer: the warrant for `dan.bsky.social+agent@D` is signed by D's
/// config cert, so D must also sign the agent's authentication cert.
pub async fn agent_device_cert(
    State(state): State<S>,
    headers: HeaderMap,
    Json(req): Json<AgentDeviceCertReq>,
) -> Result<Json<AgentDeviceCertResp>, IdpError> {
    let st = super::require_idp(&state)?;
    let session = super::routes::require_session(&state, &headers)?;
    let handle = session
        .handle
        .ok_or_else(|| IdpError::BadRequest("this session is not signed in as a handle".into()))?;

    let agent_email = req.agent_email.trim().to_lowercase();
    let (local, domain) = agent_email
        .split_once('@')
        .ok_or_else(|| IdpError::BadRequest("agent_email must be an identity".into()))?;
    if domain != st.domain {
        return Err(IdpError::BadRequest(format!("agent_email must be @{}", st.domain)));
    }
    // The agent is either the handle itself (an as-you service, isolated by
    // its holder) or a `+tag` sub-address of it.
    let prefix = format!("{handle}+");
    if local != handle && !(local.starts_with(&prefix) && local.len() > prefix.len()) {
        return Err(IdpError::Forbidden);
    }
    if let Some(tag) = local.strip_prefix(&prefix) {
        if !tag.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')) {
            return Err(IdpError::BadRequest("invalid agent name".into()));
        }
    }

    let pin = state.store.idp_pin(&handle)?;
    if pin.as_ref().is_none_or(|p| p.suspended || p.did != session.did) {
        return Err(IdpError::BindingSuspended(format!(
            "the binding for {handle} is no longer active — sign in again"
        )));
    }

    let agent_pub = parse_pubkey(&req.agent_pubkey)?;
    if req.holder.trim().is_empty() {
        return Err(IdpError::BadRequest("holder required".into()));
    }
    let holder = Holder::new(req.holder.trim().to_string())
        .map_err(|e| IdpError::BadRequest(format!("holder: {e}")))?;

    let device_cert = DeviceCert::create(
        &st.domain,
        &agent_pub,
        Purpose::Authentication,
        holder,
        vec![agent_email.clone()],
        chrono::Duration::days(DEVICE_CERT_DAYS),
        &st.keypair,
        Some(status_ref(st, &state, &agent_email)?),
    )
    .map_err(|e| IdpError::Internal(format!("agent device cert: {e}")))?;

    Ok(Json(AgentDeviceCertResp {
        success: true,
        device_cert: device_cert.encoded().to_string(),
        identity: agent_email,
    }))
}

// ---------------------------------------------------------------------------
// The mint
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct AccessMintReq {
    pub device_cert: String,
    pub access_request: String,
}

#[derive(Serialize)]
pub struct AccessMintResp {
    pub success: bool,
    pub access_cert: String,
}

/// CORS preflight for the mint. The browserid dialog calls it cross-origin
/// with an uncredentialed fetch — there is no session and no cookie to
/// protect, so permissive CORS costs nothing.
pub async fn mint_preflight(State(state): State<S>) -> Response {
    if let Err(e) = super::require_idp(&state) {
        return e.into_response();
    }
    (StatusCode::NO_CONTENT, cors_headers()).into_response()
}

fn cors_headers() -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, HeaderValue::from_static("*"));
    h.insert(header::ACCESS_CONTROL_ALLOW_METHODS, HeaderValue::from_static("POST, OPTIONS"));
    h.insert(header::ACCESS_CONTROL_ALLOW_HEADERS, HeaderValue::from_static("content-type, accept"));
    h.insert(header::ACCESS_CONTROL_MAX_AGE, HeaderValue::from_static("600"));
    h
}

/// `POST /idp/access/mint` — headless issuance of a 24 h access cert.
///
/// The device cert is the credential; there is no session. Beyond the
/// standard §7 checks this endpoint carries the IdP's ongoing obligation:
/// re-verify, against the live public record, that the handle still belongs
/// to the DID it was claimed with. A handle that moved stops working here
/// within a day, and it does so without our holding any session, token, or
/// key belonging to the user.
pub async fn access_mint(State(state): State<S>, Json(req): Json<AccessMintReq>) -> Response {
    match mint_inner(&state, req).await {
        Ok(body) => (cors_headers(), Json(body)).into_response(),
        Err(e) => (cors_headers(), e).into_response(),
    }
}

async fn mint_inner(state: &S, req: AccessMintReq) -> Result<AccessMintResp, IdpError> {
    let st = super::require_idp(state)?;

    // 1–3. The credential checks (spec §7).
    let (device_cert, access_request) =
        check_mint_credentials(&st.keypair.public_key(), &st.domain, &req)?;
    let ar = access_request.claims();

    // 4. The assurance cadence: re-verify the public binding.
    let handle = identity_handle(&ar.identity, &st.domain)?;
    // `allow_stale_on_outage`: a resolution *outage* falls back to the
    // ≤10-minute cache rather than locking everyone out — the same
    // degradation philosophy as status-list staleness. A resolution that
    // succeeds and disagrees is never softened; that path fails closed.
    let resolved = resolve::resolve_for_assurance(st, &state.http, &handle, true).await?;
    pins::verify_still_bound(&state.store, &handle, &resolved.did)?;

    // 5. Mint, copying the device cert's holder verbatim.
    let access_cert = AccessCert::create(
        &st.domain,
        &ar.identity,
        device_cert.holder().clone(),
        &ar.access_key,
        chrono::Duration::hours(ACCESS_CERT_VALIDITY_HOURS),
        &st.keypair,
        Some(status_ref(st, state, &ar.identity)?),
    )
    .map_err(|e| IdpError::Internal(format!("access cert: {e}")))?;

    Ok(AccessMintResp { success: true, access_cert: access_cert.encoded().to_string() })
}

/// The standard §7 credential checks, before any handle re-verification.
///
/// Separated out because these are the properties an access cert rests on,
/// and each one is a distinct way of forging one: a cert we did not sign, a
/// cert for a different issuer, a *config* cert used to mint, an expired
/// cert, a request not signed by the device key, a request for another
/// IdP's domain, an identity the cert does not cover, or a holder the cert
/// does not carry.
fn check_mint_credentials(
    idp_key: &PublicKey,
    domain: &str,
    req: &AccessMintReq,
) -> Result<(DeviceCert, AccessRequest), IdpError> {
    let device_cert = DeviceCert::parse(&req.device_cert)
        .map_err(|e| IdpError::BadRequest(format!("device cert: {e}")))?;
    device_cert
        .verify(idp_key)
        .map_err(|_| IdpError::BadRequest("device cert: bad signature".into()))?;
    if device_cert.iss() != domain {
        return Err(IdpError::BadRequest("device cert: wrong issuer".into()));
    }
    // An authorization (config) cert signs warrants; it must not be usable
    // to mint access certs.
    if device_cert.purpose() != Purpose::Authentication {
        return Err(IdpError::BadRequest("device cert: not an authentication cert".into()));
    }
    if device_cert.is_expired() {
        return Err(IdpError::BadRequest("device cert: expired".into()));
    }

    let access_request = AccessRequest::parse(&req.access_request)
        .map_err(|e| IdpError::BadRequest(format!("access request: {e}")))?;
    access_request
        .verify(device_cert.public_key())
        .map_err(|_| IdpError::BadRequest("access request: bad signature".into()))?;
    if access_request.is_expired() {
        return Err(IdpError::BadRequest("access request: expired".into()));
    }
    let ar = access_request.claims();
    if ar.domain != domain {
        return Err(IdpError::BadRequest("access request: wrong domain".into()));
    }
    if !device_cert.authorizes_identity(&ar.identity) {
        return Err(IdpError::Forbidden);
    }
    // The holder is copied verbatim into the access cert, so a requester
    // that could name a different one could escape its own isolation.
    if ar.holder != *device_cert.holder() {
        return Err(IdpError::BadRequest("access request: holder mismatch".into()));
    }
    Ok((device_cert, access_request))
}

/// The handle behind an identity string: `dan.bsky.social+agent@D` →
/// `dan.bsky.social`. An agent's assurance rides on its owner's binding,
/// which is exactly right — the agent exists because the person does.
pub fn identity_handle(identity: &str, domain: &str) -> Result<String, IdpError> {
    let (local, dom) = identity
        .split_once('@')
        .ok_or_else(|| IdpError::BadRequest(format!("not an identity: {identity}")))?;
    if !dom.eq_ignore_ascii_case(domain) {
        return Err(IdpError::BadRequest(format!("{identity} is not a @{domain} identity")));
    }
    Ok(local.split('+').next().unwrap_or(local).to_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::idp::tests::test_state;
    use browserid_core::keys::KeyPair;

    #[test]
    fn support_document_advertises_the_three_endpoints() {
        let st = test_state();
        let doc = support_document(&st);
        assert_eq!(doc["device-cert"], "/idp/device_cert");
        assert_eq!(doc["access-cert"], "/idp/access/mint");
        assert_eq!(doc["device-authorization"], "/idp/device-authorize");
        // Named `<handle>+<tag>` agents need the agent mode advertised, or
        // the broker will not offer to provision one.
        assert_eq!(doc["agent-device-authorization"], "/idp/device-authorize");
        // The published key is advisory (DNSSEC is the trust root) but must
        // still be the key we actually sign with, or nothing verifies.
        let parsed: SupportDocument = serde_json::from_value(doc).unwrap();
        assert_eq!(parsed.public_key.unwrap(), st.keypair.public_key());
    }

    const DOMAIN: &str = "bsky.browserid.test";
    const IDENTITY: &str = "dan.bsky.social@bsky.browserid.test";

    /// A device cert + a matching access request, both valid, so each test
    /// can spoil exactly one property.
    fn mint_fixture(
        idp: &KeyPair,
        purpose: Purpose,
        identity: &str,
        validity: chrono::Duration,
    ) -> (KeyPair, DeviceCert) {
        let device = KeyPair::generate();
        let cert = DeviceCert::create(
            DOMAIN,
            &device.public_key(),
            purpose,
            Holder::new("br000000.main").unwrap(),
            vec![identity.to_string()],
            validity,
            idp,
            None,
        )
        .unwrap();
        (device, cert)
    }

    fn request_for(device: &KeyPair, cert: &DeviceCert, identity: &str) -> AccessRequest {
        AccessRequest::create(
            DOMAIN,
            identity,
            cert.holder().clone(),
            &KeyPair::generate().public_key(),
            "jti-test",
            device,
        )
        .unwrap()
    }

    fn mint_req(cert: &DeviceCert, ar: &AccessRequest) -> AccessMintReq {
        AccessMintReq {
            device_cert: cert.encoded().to_string(),
            access_request: ar.encoded().to_string(),
        }
    }

    #[test]
    fn mint_accepts_a_well_formed_credential_pair() {
        let idp = KeyPair::generate();
        let (device, cert) =
            mint_fixture(&idp, Purpose::Authentication, IDENTITY, chrono::Duration::days(90));
        let ar = request_for(&device, &cert, IDENTITY);
        check_mint_credentials(&idp.public_key(), DOMAIN, &mint_req(&cert, &ar)).unwrap();
    }

    #[test]
    fn mint_rejects_a_cert_this_idp_did_not_sign() {
        // The forgery that matters most: someone else's IdP key.
        let idp = KeyPair::generate();
        let (device, cert) =
            mint_fixture(&idp, Purpose::Authentication, IDENTITY, chrono::Duration::days(90));
        let ar = request_for(&device, &cert, IDENTITY);
        let err = check_mint_credentials(
            &KeyPair::generate().public_key(),
            DOMAIN,
            &mint_req(&cert, &ar),
        )
        .unwrap_err();
        assert!(err.to_string().contains("bad signature"), "{err}");
    }

    #[test]
    fn mint_rejects_a_config_cert() {
        // A config (authorization) cert signs warrants. Letting it mint
        // access certs would collapse the purpose separation entirely.
        let idp = KeyPair::generate();
        let (device, cert) =
            mint_fixture(&idp, Purpose::Authorization, IDENTITY, chrono::Duration::days(90));
        let ar = request_for(&device, &cert, IDENTITY);
        let err =
            check_mint_credentials(&idp.public_key(), DOMAIN, &mint_req(&cert, &ar)).unwrap_err();
        assert!(err.to_string().contains("not an authentication cert"), "{err}");
    }

    #[test]
    fn mint_rejects_an_expired_cert() {
        let idp = KeyPair::generate();
        let (device, cert) =
            mint_fixture(&idp, Purpose::Authentication, IDENTITY, chrono::Duration::seconds(-1));
        let ar = request_for(&device, &cert, IDENTITY);
        let err =
            check_mint_credentials(&idp.public_key(), DOMAIN, &mint_req(&cert, &ar)).unwrap_err();
        assert!(err.to_string().contains("expired"), "{err}");
    }

    #[test]
    fn mint_rejects_a_request_signed_by_the_wrong_key() {
        // Possession of the device key is the whole credential; a request
        // signed by anything else is someone replaying a public cert.
        let idp = KeyPair::generate();
        let (_, cert) =
            mint_fixture(&idp, Purpose::Authentication, IDENTITY, chrono::Duration::days(90));
        let impostor = KeyPair::generate();
        let ar = request_for(&impostor, &cert, IDENTITY);
        let err =
            check_mint_credentials(&idp.public_key(), DOMAIN, &mint_req(&cert, &ar)).unwrap_err();
        assert!(err.to_string().contains("access request: bad signature"), "{err}");
    }

    #[test]
    fn mint_rejects_an_identity_the_cert_does_not_authorize() {
        let idp = KeyPair::generate();
        let (device, cert) =
            mint_fixture(&idp, Purpose::Authentication, IDENTITY, chrono::Duration::days(90));
        let ar = request_for(&device, &cert, "someone.else@bsky.browserid.test");
        assert!(matches!(
            check_mint_credentials(&idp.public_key(), DOMAIN, &mint_req(&cert, &ar)),
            Err(IdpError::Forbidden)
        ));
    }

    #[test]
    fn mint_rejects_a_holder_the_cert_does_not_carry() {
        // The access cert copies the device cert's holder verbatim, so a
        // requester able to name another holder could escape its isolation.
        let idp = KeyPair::generate();
        let (device, cert) =
            mint_fixture(&idp, Purpose::Authentication, IDENTITY, chrono::Duration::days(90));
        let ar = AccessRequest::create(
            DOMAIN,
            IDENTITY,
            Holder::new("br999999.other").unwrap(),
            &KeyPair::generate().public_key(),
            "jti-test",
            &device,
        )
        .unwrap();
        let err =
            check_mint_credentials(&idp.public_key(), DOMAIN, &mint_req(&cert, &ar)).unwrap_err();
        assert!(err.to_string().contains("holder mismatch"), "{err}");
    }

    #[test]
    fn mint_rejects_a_cert_issued_for_another_domain() {
        let idp = KeyPair::generate();
        let (device, cert) =
            mint_fixture(&idp, Purpose::Authentication, IDENTITY, chrono::Duration::days(90));
        let ar = request_for(&device, &cert, IDENTITY);
        let err = check_mint_credentials(&idp.public_key(), "other.example", &mint_req(&cert, &ar))
            .unwrap_err();
        assert!(err.to_string().contains("wrong issuer"), "{err}");
    }

    #[test]
    fn agent_identities_resolve_to_their_owners_handle() {
        assert_eq!(
            identity_handle("dan.bsky.social@bsky.browserid.test", "bsky.browserid.test").unwrap(),
            "dan.bsky.social"
        );
        // An agent's assurance rides on the person's binding.
        assert_eq!(
            identity_handle("dan.bsky.social+agent@bsky.browserid.test", "bsky.browserid.test")
                .unwrap(),
            "dan.bsky.social"
        );
        // Another domain's identity is not ours to mint for.
        assert!(identity_handle("dan@example.com", "bsky.browserid.test").is_err());
        assert!(identity_handle("nonsense", "bsky.browserid.test").is_err());
    }

    #[test]
    fn holders_derive_deterministically_from_the_device_key() {
        let kp = KeyPair::generate();
        let a = holder_for_device(&kp.public_key());
        assert_eq!(a, holder_for_device(&kp.public_key()), "same key → same device slot");
        assert_ne!(a, holder_for_device(&KeyPair::generate().public_key()));
        assert!(a.starts_with("br") && a.contains('.'), "dotted, for `<prefix>.*` matchers");
    }

    #[test]
    fn status_list_reflects_revocations_and_verifies_under_ds_key() {
        let st = test_state();
        let store = crate::store::Store::open_in_memory().unwrap();
        let live = store.idp_status_idx("dan.bsky.social@bsky.browserid.test").unwrap();
        let doomed = store.idp_status_idx("moved.bsky.social@bsky.browserid.test").unwrap();
        store.idp_revoke_status_for_handle("moved.bsky.social").unwrap();

        let (revoked, max) = store.idp_revoked_status_indices().unwrap();
        let list = StatusList::from_revoked(revoked, max);
        let token =
            StatusListToken::create(&st.domain, &st.status_list_uri(), &list, &st.keypair).unwrap();

        // An RP fetching this must be able to verify it under D's key, at
        // the URI the certs point to.
        let parsed = StatusListToken::parse(token.encoded()).unwrap();
        parsed.verify(&st.keypair.public_key(), &st.status_list_uri()).unwrap();
        assert!(parsed.is_revoked(doomed), "a suspended binding's cert is revoked");
        assert!(!parsed.is_revoked(live), "everyone else is untouched");
        // A different key must not validate it.
        assert!(parsed.verify(&KeyPair::generate().public_key(), &st.status_list_uri()).is_err());
    }

    /// Finding #7: the status list is bounded by identities, not by certs.
    /// Access certs are minted daily, per RP, per device — allocating a
    /// fresh index each time grew a re-signed bitmap without limit.
    #[test]
    fn one_status_index_per_identity_reused_across_every_mint() {
        let store = crate::store::Store::open_in_memory().unwrap();
        let dan = "dan.bsky.social@bsky.browserid.test";
        let first = store.idp_status_idx(dan).unwrap();
        // The device, config and every renewed access cert land in one slot.
        for _ in 0..5 {
            assert_eq!(store.idp_status_idx(dan).unwrap(), first);
        }
        // Distinct identities still get distinct bits…
        let eve = store.idp_status_idx("eve.bsky.social@bsky.browserid.test").unwrap();
        assert_ne!(first, eve);
        // …including a `+tag` agent, which must stay independently revocable.
        let agent = store.idp_status_idx("dan.bsky.social+fable@bsky.browserid.test").unwrap();
        assert_ne!(first, agent);

        // Two identities plus one agent, after eleven allocations.
        let (_, max) = store.idp_revoked_status_indices().unwrap();
        assert_eq!(max, 3);
    }

    /// The point of sharing the bit: one revocation kills the identity's
    /// device cert and its access certs together, rather than leaving live
    /// access certs behind on separate indices.
    #[test]
    fn revoking_an_identity_kills_its_device_and_access_certs_at_once() {
        let store = crate::store::Store::open_in_memory().unwrap();
        let dan = "dan.bsky.social@bsky.browserid.test";
        let device = store.idp_status_idx(dan).unwrap();
        let config = store.idp_status_idx(dan).unwrap();
        let access = store.idp_status_idx(dan).unwrap();
        let agent = store.idp_status_idx("dan.bsky.social+fable@bsky.browserid.test").unwrap();

        store.idp_revoke_status_for_handle("dan.bsky.social").unwrap();
        let (revoked, max) = store.idp_revoked_status_indices().unwrap();
        let list = StatusList::from_revoked(revoked, max);
        for idx in [device, config, access, agent] {
            assert!(list.is_revoked(idx), "index {idx} should be revoked");
        }
    }

    #[test]
    fn revoking_a_handle_takes_its_agents_with_it() {
        // Suspending a person must not leave their agents able to act.
        let store = crate::store::Store::open_in_memory().unwrap();
        let person = store.idp_status_idx("dan.bsky.social@bsky.browserid.test").unwrap();
        let agent =
            store.idp_status_idx("dan.bsky.social+fable@bsky.browserid.test").unwrap();
        let other = store.idp_status_idx("dan.bsky.social.evil@x.test").unwrap();

        store.idp_revoke_status_for_handle("dan.bsky.social").unwrap();
        let (revoked, _) = store.idp_revoked_status_indices().unwrap();
        assert!(revoked.contains(&person));
        assert!(revoked.contains(&agent));
        // …but a *different* handle that merely starts with the same text
        // must not be caught by the prefix match.
        assert!(!revoked.contains(&other));
    }
}
