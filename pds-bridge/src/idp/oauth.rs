//! The atproto OAuth confidential client — the *authentication* half of the
//! IdP.
//!
//! Deliberately hand-rolled and deliberately small. We need exactly one
//! authorization-code exchange per claim, we call no resource endpoints,
//! and we store no tokens; the crates that exist
//! ([`atproto-oauth`](https://crates.io/crates/atproto-oauth),
//! [`atrium-oauth`](https://crates.io/crates/atrium-oauth)) are built for
//! the opposite shape — a long-lived session that refreshes and makes XRPC
//! calls — and pull in a session/DPoP-store stack we would then have to
//! *prevent* from persisting anything. What is left once you drop all that
//! is: two JWT signers, a PKCE pair, and two POSTs.
//!
//! The pieces the atproto profile makes mandatory, and which are easy to
//! get subtly wrong:
//!
//! * **PAR** — the authorization request is pushed server-side and the
//!   browser only ever carries an opaque `request_uri`.
//! * **PKCE S256** — always, even for a confidential client.
//! * **DPoP** — every token-endpoint call is bound to a per-flow ephemeral
//!   P-256 key. Servers demand a nonce they only hand out by rejecting a
//!   request that lacks it (`use_dpop_nonce`, `400` at bsky.social despite
//!   RFC 9449 describing a `401`), so **the first call failing is the
//!   normal handshake**, not an error; [`with_dpop_nonce_retry`] encodes
//!   that and does not key on the status code.
//! * **`private_key_jwt`** — client authentication is an ES256 assertion
//!   signed by the key published at our `jwks_uri`, not a shared secret.
//!
//! And the piece that makes the whole thing mean something: after the
//! exchange we check that the token's `sub` equals the DID we resolved from
//! the handle. Then we drop the tokens on the floor.

use std::sync::Arc;

use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use p256::elliptic_curve::Generate;
use rand::RngCore;
use sha2::{Digest, Sha256};

use super::{IdpError, IdpState};
use crate::BridgeState;

/// How long a `private_key_jwt` client assertion is valid. Short: it is
/// minted per request and travels one hop.
const CLIENT_ASSERTION_TTL_SECONDS: i64 = 60;

// ---------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------

/// The confidential client's ES256 key.
///
/// Its public half is published at [`IdpState::jwks_uri`]; authorization
/// servers fetch it to verify our client assertions. Rotating it means
/// publishing both keys under distinct `kid`s until the old one drains —
/// which is why the `kid` is derived from the key material rather than
/// being a fixed string.
pub struct ClientKey {
    signing_key: SigningKey,
    kid: String,
}

impl ClientKey {
    pub fn generate() -> Self {
        Self::from_signing_key(SigningKey::generate())
    }

    fn from_signing_key(signing_key: SigningKey) -> Self {
        let point = signing_key.verifying_key().to_sec1_point(false);
        let kid = hex16(&Sha256::digest(point.as_ref()));
        Self { signing_key, kid }
    }

    /// Load from `IDP_OAUTH_KEY` (hex or base64url 32-byte P-256 scalar),
    /// else `IDP_OAUTH_KEY_FILE`, else generate and persist.
    ///
    /// Generating is fine for development. In production a regenerated key
    /// invalidates the published JWKS for any authorization server still
    /// caching it, so inject it.
    pub fn from_env() -> Result<Self, String> {
        if let Ok(raw) = std::env::var("IDP_OAUTH_KEY") {
            return Self::from_scalar_text(&raw);
        }
        let path = std::path::PathBuf::from(
            std::env::var("IDP_OAUTH_KEY_FILE").unwrap_or_else(|_| "idp-oauth-key.txt".to_string()),
        );
        if path.exists() {
            let raw = std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
            return Self::from_scalar_text(&raw);
        }
        let key = Self::generate();
        let hex: String = key.signing_key.to_bytes().iter().map(|b| format!("{b:02x}")).collect();
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        std::fs::write(&path, &hex).map_err(|e| format!("write {}: {e}", path.display()))?;
        tracing::warn!(
            path = %path.display(),
            "generated a NEW OAuth client key — authorization servers caching the old \
             JWKS will reject client assertions; inject IDP_OAUTH_KEY in production"
        );
        Ok(key)
    }

    fn from_scalar_text(raw: &str) -> Result<Self, String> {
        let raw = raw.trim();
        let bytes = if raw.len() == 64 && raw.chars().all(|c| c.is_ascii_hexdigit()) {
            (0..64)
                .step_by(2)
                .map(|i| u8::from_str_radix(&raw[i..i + 2], 16).map_err(|e| e.to_string()))
                .collect::<Result<Vec<u8>, _>>()?
        } else {
            URL_SAFE_NO_PAD.decode(raw).map_err(|e| format!("OAuth key: {e}"))?
        };
        let signing_key =
            SigningKey::from_slice(&bytes).map_err(|e| format!("bad P-256 OAuth key: {e}"))?;
        Ok(Self::from_signing_key(signing_key))
    }

    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// The public key as a JWK (`kty: EC, crv: P-256`).
    pub fn public_jwk(&self) -> serde_json::Value {
        let point = self.signing_key.verifying_key().to_sec1_point(false);
        serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": URL_SAFE_NO_PAD.encode(point.x().expect("uncompressed point")),
            "y": URL_SAFE_NO_PAD.encode(point.y().expect("uncompressed point")),
            "alg": "ES256",
            "use": "sig",
            "kid": self.kid,
        })
    }

    fn sign_jwt(&self, header: serde_json::Value, claims: serde_json::Value) -> String {
        sign_es256(&self.signing_key, header, claims)
    }
}

/// A per-flow DPoP key. Ephemeral by construction: minted when the flow
/// starts, carried through the pending-flow row, destroyed with it. Nothing
/// survives the exchange, which is the whole point — a stored DPoP key plus
/// a refresh token *is* custody.
pub struct DpopKey(SigningKey);

impl DpopKey {
    pub fn generate() -> Self {
        Self(SigningKey::generate())
    }

    /// Serialize the private scalar so a pending flow can be resumed after
    /// the browser round trip.
    pub fn to_secret_b64(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.0.to_bytes())
    }

    pub fn from_secret_b64(s: &str) -> Result<Self, IdpError> {
        let bytes = URL_SAFE_NO_PAD
            .decode(s)
            .map_err(|e| IdpError::Internal(format!("dpop key: {e}")))?;
        SigningKey::from_slice(&bytes)
            .map(Self)
            .map_err(|e| IdpError::Internal(format!("dpop key: {e}")))
    }

    fn public_jwk(&self) -> serde_json::Value {
        let point = self.0.verifying_key().to_sec1_point(false);
        serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": URL_SAFE_NO_PAD.encode(point.x().expect("uncompressed point")),
            "y": URL_SAFE_NO_PAD.encode(point.y().expect("uncompressed point")),
        })
    }

    /// An RFC 9449 proof for `method url`, optionally carrying the server's
    /// nonce. The public JWK travels in the header — that is what binds the
    /// request to this key.
    pub fn proof(&self, method: &str, url: &str, nonce: Option<&str>) -> String {
        let mut claims = serde_json::json!({
            "jti": random_token(16),
            "htm": method,
            // The `htu` is the URL without query or fragment.
            "htu": url.split(['?', '#']).next().unwrap_or(url),
            "iat": chrono::Utc::now().timestamp(),
        });
        if let Some(n) = nonce {
            claims["nonce"] = serde_json::Value::String(n.to_string());
        }
        sign_es256(
            &self.0,
            serde_json::json!({ "typ": "dpop+jwt", "alg": "ES256", "jwk": self.public_jwk() }),
            claims,
        )
    }
}

fn sign_es256(key: &SigningKey, header: serde_json::Value, claims: serde_json::Value) -> String {
    let h = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).expect("jwt header"));
    let c = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).expect("jwt claims"));
    let signing_input = format!("{h}.{c}");
    let sig: Signature = key.sign(signing_input.as_bytes());
    format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()))
}

fn hex16(bytes: &[u8]) -> String {
    bytes.iter().take(8).map(|b| format!("{b:02x}")).collect()
}

/// A URL-safe random token: PKCE verifiers, `state`, `jti`.
pub fn random_token(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    URL_SAFE_NO_PAD.encode(buf)
}

/// The S256 challenge for a PKCE verifier.
pub fn pkce_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

// ---------------------------------------------------------------------------
// Published client documents
// ---------------------------------------------------------------------------

/// `GET /idp/client-metadata.json` — the OAuth client metadata document.
///
/// In the atproto profile the `client_id` **is** this document's URL, so
/// the two must agree exactly or every authorization server rejects us.
pub async fn client_metadata(State(state): State<Arc<BridgeState>>) -> Response {
    let st = match super::require_idp(&state) {
        Ok(st) => st,
        Err(e) => return e.into_response(),
    };
    Json(client_metadata_doc(st)).into_response()
}

/// The metadata document as data, so tests can assert on it without HTTP.
pub fn client_metadata_doc(st: &IdpState) -> serde_json::Value {
    serde_json::json!({
        "client_id": st.client_id(),
        "client_name": "browserid — sign in with your Bluesky handle",
        "client_uri": st.origin,
        "application_type": "web",
        // Identity only. We never call a resource endpoint, so there is no
        // refresh grant to ask for — the code exchange is the whole flow.
        "grant_types": ["authorization_code"],
        "response_types": ["code"],
        "scope": st.scope,
        "redirect_uris": [st.redirect_uri()],
        // Confidential client: ES256 assertions signed by the key at jwks_uri.
        "token_endpoint_auth_method": "private_key_jwt",
        "token_endpoint_auth_signing_alg": "ES256",
        "jwks_uri": st.jwks_uri(),
        "dpop_bound_access_tokens": true,
    })
}

/// `GET /idp/jwks.json` — the client's public key set.
pub async fn jwks(State(state): State<Arc<BridgeState>>) -> Response {
    let st = match super::require_idp(&state) {
        Ok(st) => st,
        Err(e) => return e.into_response(),
    };
    Json(serde_json::json!({ "keys": [st.oauth_key.public_jwk()] })).into_response()
}

// ---------------------------------------------------------------------------
// Authorization-server discovery
// ---------------------------------------------------------------------------

/// The authorization server for an account, discovered from its PDS.
#[derive(Debug, Clone)]
pub struct AuthServer {
    pub issuer: String,
    pub par_endpoint: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
}

/// PDS → `/.well-known/oauth-protected-resource` → authorization server
/// metadata.
///
/// This indirection is what makes `bsky.social` accounts work: they
/// authenticate at the *entryway*, not at the PDS holding their repo. A
/// self-hosted PDS simply names itself. The `issuer` check is the security
/// property — metadata that claims a different issuer than the origin it
/// came from is an authorization-server mix-up attack.
pub async fn discover_auth_server(
    http: &reqwest::Client,
    pds: &str,
) -> Result<AuthServer, IdpError> {
    let prm: serde_json::Value = http
        .get(format!("{}/.well-known/oauth-protected-resource", pds.trim_end_matches('/')))
        .send()
        .await
        .and_then(|r| r.error_for_status())
        .map_err(|e| IdpError::BadRequest(format!("{pds} publishes no OAuth metadata: {e}")))?
        .json()
        .await
        .map_err(|e| IdpError::BadRequest(format!("{pds} protected-resource metadata: {e}")))?;

    let issuer = prm
        .get("authorization_servers")
        .and_then(|a| a.as_array())
        .and_then(|a| a.first())
        .and_then(|v| v.as_str())
        .ok_or_else(|| IdpError::BadRequest(format!("{pds} names no authorization server")))?
        .trim_end_matches('/')
        .to_string();

    let meta: serde_json::Value = http
        .get(format!("{issuer}/.well-known/oauth-authorization-server"))
        .send()
        .await
        .and_then(|r| r.error_for_status())
        .map_err(|e| IdpError::BadRequest(format!("{issuer} metadata unreachable: {e}")))?
        .json()
        .await
        .map_err(|e| IdpError::BadRequest(format!("{issuer} metadata: {e}")))?;

    parse_auth_server(&issuer, &meta)
}

/// Validate authorization-server metadata against the origin it was served
/// from, and pull out the three endpoints we use.
pub fn parse_auth_server(issuer: &str, meta: &serde_json::Value) -> Result<AuthServer, IdpError> {
    let declared = meta.get("issuer").and_then(|v| v.as_str()).unwrap_or_default();
    if declared.trim_end_matches('/') != issuer {
        return Err(IdpError::BadRequest(format!(
            "authorization server issuer mismatch: metadata at {issuer} claims to be {declared}"
        )));
    }
    let field = |k: &str| {
        meta.get(k)
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .ok_or_else(|| IdpError::BadRequest(format!("{issuer} metadata has no {k}")))
    };
    Ok(AuthServer {
        issuer: issuer.to_string(),
        par_endpoint: field("pushed_authorization_request_endpoint")?,
        authorization_endpoint: field("authorization_endpoint")?,
        token_endpoint: field("token_endpoint")?,
    })
}

// ---------------------------------------------------------------------------
// The two calls
// ---------------------------------------------------------------------------

/// A prepared authorization request: what the browser is sent to, and what
/// must be kept to finish the exchange afterwards.
pub struct PreparedAuth {
    pub authorize_url: String,
    pub state: String,
    pub code_verifier: String,
    pub dpop_secret: String,
    pub auth_server: AuthServer,
}

/// Push the authorization request (PAR) and build the URL to send the
/// browser to.
///
/// `login_hint` pre-fills the account at the authorization server — the
/// handle the user typed, or the DID for the retirement path.
pub async fn push_authorization_request(
    st: &IdpState,
    http: &reqwest::Client,
    auth_server: &AuthServer,
    login_hint: &str,
) -> Result<PreparedAuth, IdpError> {
    let state_tok = random_token(24);
    let code_verifier = random_token(32);
    let dpop = DpopKey::generate();

    let form = vec![
        ("client_id".to_string(), st.client_id()),
        ("response_type".to_string(), "code".to_string()),
        ("redirect_uri".to_string(), st.redirect_uri()),
        ("scope".to_string(), st.scope.clone()),
        ("state".to_string(), state_tok.clone()),
        ("code_challenge".to_string(), pkce_challenge(&code_verifier)),
        ("code_challenge_method".to_string(), "S256".to_string()),
        ("login_hint".to_string(), login_hint.to_string()),
        (
            "client_assertion_type".to_string(),
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer".to_string(),
        ),
        ("client_assertion".to_string(), client_assertion(st, &auth_server.issuer)),
    ];

    let body = with_dpop_nonce_retry(http, &dpop, "POST", &auth_server.par_endpoint, |req, proof| {
        req.header("DPoP", proof).form(&form)
    })
    .await?;

    let request_uri = body
        .get("request_uri")
        .and_then(|v| v.as_str())
        .ok_or_else(|| IdpError::BadRequest("PAR response carried no request_uri".into()))?;

    let authorize_url = reqwest::Url::parse_with_params(
        &auth_server.authorization_endpoint,
        &[("client_id", st.client_id().as_str()), ("request_uri", request_uri)],
    )
    .map_err(|e| IdpError::Internal(format!("authorize URL: {e}")))?
    .to_string();

    Ok(PreparedAuth {
        authorize_url,
        state: state_tok,
        code_verifier,
        dpop_secret: dpop.to_secret_b64(),
        auth_server: auth_server.clone(),
    })
}

/// Exchange the authorization code and return the authenticated DID.
///
/// The access and refresh tokens in the response are read for `sub` and
/// then **dropped** — they are never returned to the caller, logged, or
/// written anywhere. Zero custody is a structural property of this
/// signature, not a policy we remember to follow.
pub async fn exchange_code(
    st: &IdpState,
    http: &reqwest::Client,
    auth_server: &AuthServer,
    code: &str,
    code_verifier: &str,
    dpop: &DpopKey,
) -> Result<String, IdpError> {
    let form = vec![
        ("grant_type".to_string(), "authorization_code".to_string()),
        ("code".to_string(), code.to_string()),
        ("redirect_uri".to_string(), st.redirect_uri()),
        ("code_verifier".to_string(), code_verifier.to_string()),
        ("client_id".to_string(), st.client_id()),
        (
            "client_assertion_type".to_string(),
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer".to_string(),
        ),
        ("client_assertion".to_string(), client_assertion(st, &auth_server.issuer)),
    ];

    let body = with_dpop_nonce_retry(http, dpop, "POST", &auth_server.token_endpoint, |req, proof| {
        req.header("DPoP", proof).form(&form)
    })
    .await?;

    body.get("sub")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .ok_or_else(|| IdpError::BadRequest("token response carried no sub (the DID)".into()))
    // `body` is dropped here, and with it the tokens.
}

/// A `private_key_jwt` client assertion for `audience` (the AS issuer).
fn client_assertion(st: &IdpState, audience: &str) -> String {
    let now = chrono::Utc::now().timestamp();
    st.oauth_key.sign_jwt(
        serde_json::json!({ "typ": "JWT", "alg": "ES256", "kid": st.oauth_key.kid() }),
        serde_json::json!({
            "iss": st.client_id(),
            "sub": st.client_id(),
            "aud": audience,
            "jti": random_token(16),
            "iat": now,
            "exp": now + CLIENT_ASSERTION_TTL_SECONDS,
        }),
    )
}

/// Send a DPoP-bound request, performing the `use_dpop_nonce` handshake.
///
/// Authorization servers require a nonce they will only give you by
/// rejecting a request that lacks it. So the first attempt failing with a
/// `DPoP-Nonce` header is the *protocol working*: re-sign the proof with
/// the nonce and send it again. Exactly one retry — a second nonce demand
/// is a real failure.
///
/// Deliberately keyed on the header rather than the status code: RFC 9449
/// describes a `401`, but bsky.social's entryway answers `400`
/// (probed 2026-07-27). Anything that hands back a nonce on a rejected
/// first attempt gets one retry, whether or not its body parsed.
///
/// Each call does its own handshake instead of caching nonces across
/// calls. With exactly two requests per claim — PAR, then a token exchange
/// minutes later behind a human — a cached nonce would almost always have
/// rotated (they live ≤5 minutes) and been re-fetched anyway.
async fn with_dpop_nonce_retry<F>(
    http: &reqwest::Client,
    dpop: &DpopKey,
    method: &str,
    url: &str,
    build: F,
) -> Result<serde_json::Value, IdpError>
where
    F: Fn(reqwest::RequestBuilder, String) -> reqwest::RequestBuilder,
{
    let mut nonce: Option<String> = None;
    for attempt in 0..2 {
        let proof = dpop.proof(method, url, nonce.as_deref());
        let resp = build(http.post(url), proof)
            .send()
            .await
            .map_err(|e| IdpError::BadRequest(format!("{url}: {e}")))?;

        let server_nonce =
            resp.headers().get("dpop-nonce").and_then(|v| v.to_str().ok()).map(str::to_string);
        let status = resp.status();
        let body: serde_json::Value = resp.json().await.unwrap_or(serde_json::Value::Null);

        if status.is_success() {
            return Ok(body);
        }
        let error = body.get("error").and_then(|v| v.as_str()).unwrap_or_default();
        // Retry on an explicit `use_dpop_nonce`, and also on any bare 400/401
        // that volunteered a nonce — a body we could not parse must not cost
        // us the handshake.
        let wants_nonce = error == "use_dpop_nonce"
            || matches!(status.as_u16(), 400 | 401) && body.get("error").is_none();
        if attempt == 0 && wants_nonce {
            if let Some(n) = server_nonce {
                nonce = Some(n);
                continue;
            }
        }
        let description =
            body.get("error_description").and_then(|v| v.as_str()).unwrap_or_default();
        return Err(IdpError::BadRequest(format!(
            "authorization server refused ({status}): {error}{}{description}",
            if description.is_empty() { "" } else { " — " }
        )));
    }
    Err(IdpError::BadRequest("authorization server kept demanding a new DPoP nonce".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn parts(jwt: &str) -> (serde_json::Value, serde_json::Value) {
        let mut it = jwt.split('.');
        let h = URL_SAFE_NO_PAD.decode(it.next().unwrap()).unwrap();
        let c = URL_SAFE_NO_PAD.decode(it.next().unwrap()).unwrap();
        (serde_json::from_slice(&h).unwrap(), serde_json::from_slice(&c).unwrap())
    }

    #[test]
    fn client_metadata_matches_the_atproto_profile() {
        let st = super::super::tests::test_state();
        let doc = client_metadata_doc(&st);
        // The client_id IS the document's own URL — the profile's core rule.
        assert_eq!(doc["client_id"], st.client_id());
        assert_eq!(doc["application_type"], "web");
        assert_eq!(doc["token_endpoint_auth_method"], "private_key_jwt");
        assert_eq!(doc["token_endpoint_auth_signing_alg"], "ES256");
        assert_eq!(doc["dpop_bound_access_tokens"], true);
        assert_eq!(doc["jwks_uri"], st.jwks_uri());
        assert_eq!(doc["scope"], super::super::OAUTH_SCOPE);
        // No refresh grant: we discard the tokens, so asking for one would
        // be requesting custody we promised not to take.
        assert_eq!(doc["grant_types"], json!(["authorization_code"]));
    }

    #[test]
    fn jwk_is_a_p256_signing_key_with_a_stable_kid() {
        let key = ClientKey::generate();
        let jwk = key.public_jwk();
        assert_eq!(jwk["kty"], "EC");
        assert_eq!(jwk["crv"], "P-256");
        assert_eq!(jwk["alg"], "ES256");
        assert_eq!(jwk["kid"], key.kid());
        assert_eq!(URL_SAFE_NO_PAD.decode(jwk["x"].as_str().unwrap()).unwrap().len(), 32);
        // The kid is derived from the key, so a round trip reproduces it —
        // what makes rotation (publishing two keys at once) work.
        let hex: String = key.signing_key.to_bytes().iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(ClientKey::from_scalar_text(&hex).unwrap().kid(), key.kid());
    }

    #[test]
    fn dpop_proof_carries_the_method_url_and_key() {
        let dpop = DpopKey::generate();
        let (header, claims) =
            parts(&dpop.proof("POST", "https://as.example/token?x=1#frag", Some("n-1")));
        assert_eq!(header["typ"], "dpop+jwt");
        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["jwk"]["crv"], "P-256");
        assert_eq!(claims["htm"], "POST");
        // htu is the bare URL: no query, no fragment.
        assert_eq!(claims["htu"], "https://as.example/token");
        assert_eq!(claims["nonce"], "n-1");
        // Without a nonce the claim is absent, not null.
        let (_, plain) = parts(&dpop.proof("POST", "https://as.example/token", None));
        assert!(plain.get("nonce").is_none());
    }

    #[test]
    fn dpop_key_survives_the_browser_round_trip() {
        // PAR and the token exchange must use the SAME key, across a
        // redirect — so the serialized form has to round-trip exactly.
        let dpop = DpopKey::generate();
        let restored = DpopKey::from_secret_b64(&dpop.to_secret_b64()).unwrap();
        assert_eq!(dpop.public_jwk(), restored.public_jwk());
    }

    #[test]
    fn client_assertion_is_addressed_to_the_authorization_server() {
        let st = super::super::tests::test_state();
        let (header, claims) = parts(&client_assertion(&st, "https://bsky.social"));
        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["kid"], st.oauth_key.kid());
        assert_eq!(claims["iss"], st.client_id());
        assert_eq!(claims["sub"], st.client_id());
        assert_eq!(claims["aud"], "https://bsky.social");
        assert!(claims["exp"].as_i64().unwrap() > claims["iat"].as_i64().unwrap());
    }

    #[test]
    fn pkce_challenge_is_s256_of_the_verifier() {
        // RFC 7636 test vector.
        assert_eq!(
            pkce_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    /// A token endpoint that behaves like bsky.social's: the first DPoP
    /// request is rejected with `400 use_dpop_nonce` and a `DPoP-Nonce`
    /// header, and only a proof carrying that nonce is accepted.
    ///
    /// Returns the base URL and a handle on every DPoP proof it saw, so a
    /// test can assert the retry actually re-signed with the nonce rather
    /// than replaying the first proof.
    async fn mock_token_endpoint(
        sub: &'static str,
    ) -> (String, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
        use axum::routing::post;
        let proofs: std::sync::Arc<std::sync::Mutex<Vec<String>>> = Default::default();
        let seen = proofs.clone();
        let app = axum::Router::new().route(
            "/token",
            post(move |headers: axum::http::HeaderMap| {
                let seen = seen.clone();
                async move {
                    let proof = headers
                        .get("dpop")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or_default()
                        .to_string();
                    let (_, claims) = parts(&proof);
                    seen.lock().unwrap().push(proof);
                    match claims.get("nonce").and_then(|v| v.as_str()) {
                        Some("n-42") => (
                            axum::http::StatusCode::OK,
                            Json(json!({ "sub": sub, "access_token": "secret", "token_type": "DPoP" })),
                        )
                            .into_response(),
                        _ => (
                            // 400, not 401 — what the real entryway sends.
                            axum::http::StatusCode::BAD_REQUEST,
                            [("DPoP-Nonce", "n-42")],
                            Json(json!({
                                "error": "use_dpop_nonce",
                                "error_description": "Authorization server requires nonce in DPoP proof"
                            })),
                        )
                            .into_response(),
                    }
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (base, proofs)
    }

    #[tokio::test]
    async fn the_nonce_handshake_completes_and_yields_only_the_did() {
        let st = super::super::tests::test_state();
        let (base, proofs) = mock_token_endpoint("did:plc:abc123").await;
        let auth_server = AuthServer {
            issuer: base.clone(),
            par_endpoint: String::new(),
            authorization_endpoint: String::new(),
            token_endpoint: format!("{base}/token"),
        };
        let dpop = DpopKey::generate();

        let sub = exchange_code(
            &st,
            &reqwest::Client::new(),
            &auth_server,
            "the-code",
            "the-verifier",
            &dpop,
        )
        .await
        .unwrap();

        // The whole point: what comes back is the DID and nothing else. The
        // access token in that response is unreachable from here by
        // construction, which is how zero custody stays true.
        assert_eq!(sub, "did:plc:abc123");

        // Two attempts, and the second is a genuinely re-signed proof
        // carrying the nonce — not a replay of the first.
        let proofs = proofs.lock().unwrap();
        assert_eq!(proofs.len(), 2, "the rejected first attempt is the handshake, not a failure");
        assert_ne!(proofs[0], proofs[1]);
        assert!(parts(&proofs[0]).1.get("nonce").is_none());
        assert_eq!(parts(&proofs[1]).1["nonce"], "n-42");
    }

    #[tokio::test]
    async fn a_token_whose_sub_is_not_the_resolved_did_proves_nothing() {
        // The check the entire IdP rests on. Here the OAuth hop succeeds —
        // somebody really did authenticate — but as a different account
        // than the handle being claimed, so the caller must reject it.
        let st = super::super::tests::test_state();
        let (base, _) = mock_token_endpoint("did:plc:someone-else").await;
        let auth_server = AuthServer {
            issuer: base.clone(),
            par_endpoint: String::new(),
            authorization_endpoint: String::new(),
            token_endpoint: format!("{base}/token"),
        };
        let sub = exchange_code(
            &st,
            &reqwest::Client::new(),
            &auth_server,
            "c",
            "v",
            &DpopKey::generate(),
        )
        .await
        .unwrap();
        assert_ne!(sub, "did:plc:abc123", "callback_inner refuses on exactly this inequality");
    }

    #[test]
    fn auth_server_metadata_must_declare_its_own_issuer() {
        let good = json!({
            "issuer": "https://bsky.social",
            "pushed_authorization_request_endpoint": "https://bsky.social/oauth/par",
            "authorization_endpoint": "https://bsky.social/oauth/authorize",
            "token_endpoint": "https://bsky.social/oauth/token",
        });
        let parsed = parse_auth_server("https://bsky.social", &good).unwrap();
        assert_eq!(parsed.token_endpoint, "https://bsky.social/oauth/token");

        // Mix-up defense: metadata served at one origin claiming to be a
        // different issuer is rejected outright.
        let mut lying = good.clone();
        lying["issuer"] = json!("https://evil.example");
        assert!(parse_auth_server("https://bsky.social", &lying).is_err());

        // A missing endpoint is an error, not a silent default.
        let mut incomplete = good.clone();
        incomplete.as_object_mut().unwrap().remove("pushed_authorization_request_endpoint");
        assert!(parse_auth_server("https://bsky.social", &incomplete).is_err());
    }
}
