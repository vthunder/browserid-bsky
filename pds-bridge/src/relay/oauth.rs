//! The **second** atproto OAuth client: the one that asks for write access.
//!
//! This is deliberately a separate client from `idp::oauth`, not a flag on
//! it (design doc, *Decision 1*). A client metadata document carries a
//! single `scope` and a single `grant_types` list, so sharing one
//! `client_id` would advertise `transition:generic` to everyone who merely
//! wanted to *log in* — their consent screen would read as full account
//! access, which destroys the IdP's best property. Two documents, two
//! `client_id`s, one ES256 key, one `jwks_uri`.
//!
//! What this client has that the identity client refuses to have:
//!
//! * a **refresh** grant, and therefore a token that outlives the browser;
//! * a **long-lived** DPoP key, stored with the session, because the access
//!   token is cryptographically bound to it;
//! * **`ath`-bound** DPoP proofs for calls to the resource server (RFC 9449
//!   §4.2: a proof accompanying an access token must carry the base64url
//!   SHA-256 of that token, or a stolen proof could be paired with a
//!   different token);
//! * a **nonce cache**, because unlike the identity flow's two-requests-per-
//!   human this path is hot enough that re-doing the handshake per call
//!   doubles every post.
//!
//! It does *not* have a generic request method. See [`super::RelaySession`]
//! for the one operation it exposes.

use std::collections::HashMap;
use std::sync::Mutex;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use p256::elliptic_curve::Generate;
use sha2::{Digest, Sha256};

use crate::idp::oauth::{pkce_challenge, random_token, AuthServer, ClientKey};
use crate::idp::{net, IdpError};

/// How long a `private_key_jwt` client assertion is valid — minted per
/// request, one hop.
const CLIENT_ASSERTION_TTL_SECONDS: i64 = 60;

/// The scope the write client requests.
///
/// `transition:generic` is the transitional coarse grant: roughly "act as
/// this account". The granular permission-set syntax (`repo:app.bsky.feed.post`)
/// exists but is not finalized upstream and is not honoured by bsky.social,
/// so we ask for the coarse grant and constrain it ourselves — see the
/// hardcoded collection allowlist in [`super::RELAY_COLLECTIONS`], which is
/// the only thing standing between a coarse token and a narrow warrant.
/// Migrating to a narrow scope later changes this constant and nothing else.
pub const WRITE_SCOPE: &str = "atproto transition:generic";

// ---------------------------------------------------------------------------
// The write client's DPoP key
// ---------------------------------------------------------------------------

/// A write session's DPoP key. Unlike [`crate::idp::oauth::DpopKey`] this one
/// is **long-lived** — it is minted at connect time, sealed into the session
/// row, and used for the life of the session, because every access token the
/// authorization server issues is bound to it. That is precisely the custody
/// the identity client refuses to take, and it is why this type lives here.
pub struct WriteDpopKey(SigningKey);

impl WriteDpopKey {
    pub fn generate() -> Self {
        Self(SigningKey::generate())
    }

    pub fn to_secret_b64(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.0.to_bytes())
    }

    pub fn from_secret_b64(s: &str) -> Result<Self, IdpError> {
        let bytes = URL_SAFE_NO_PAD
            .decode(s)
            .map_err(|e| IdpError::Internal(format!("write dpop key: {e}")))?;
        SigningKey::from_slice(&bytes)
            .map(Self)
            .map_err(|e| IdpError::Internal(format!("write dpop key: {e}")))
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

    /// An RFC 9449 proof. `access_token` is `Some` for a call that carries
    /// one, which adds the mandatory `ath` binding.
    pub fn proof(
        &self,
        method: &str,
        url: &str,
        nonce: Option<&str>,
        access_token: Option<&str>,
    ) -> String {
        let mut claims = serde_json::json!({
            "jti": random_token(16),
            "htm": method,
            "htu": url.split(['?', '#']).next().unwrap_or(url),
            "iat": chrono::Utc::now().timestamp(),
        });
        if let Some(n) = nonce {
            claims["nonce"] = serde_json::Value::String(n.to_string());
        }
        if let Some(tok) = access_token {
            claims["ath"] =
                serde_json::Value::String(URL_SAFE_NO_PAD.encode(Sha256::digest(tok.as_bytes())));
        }
        let header =
            serde_json::json!({ "typ": "dpop+jwt", "alg": "ES256", "jwk": self.public_jwk() });
        let h = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).expect("jwt header"));
        let c = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).expect("jwt claims"));
        let signing_input = format!("{h}.{c}");
        let sig: Signature = self.0.sign(signing_input.as_bytes());
        format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()))
    }
}

// ---------------------------------------------------------------------------
// The published client document
// ---------------------------------------------------------------------------

/// The write client's identity: its `client_id` (which *is* the URL its
/// metadata is served from), its redirect URI, and the key + `jwks_uri` it
/// shares with the identity client.
pub struct WriteClient {
    pub origin: String,
}

impl WriteClient {
    pub fn client_id(&self) -> String {
        format!("{}/idp/write-client-metadata.json", self.origin)
    }

    pub fn redirect_uri(&self) -> String {
        format!("{}/idp/connect/callback", self.origin)
    }

    pub fn jwks_uri(&self) -> String {
        format!("{}/idp/jwks.json", self.origin)
    }
}

/// The write client's metadata document, as data so tests can assert on it.
///
/// Every difference from `idp::oauth::client_metadata_doc` is a difference
/// that had to be a second document: the refresh grant, the coarse scope,
/// and a distinct `client_id` and `redirect_uris`.
pub fn write_client_metadata_doc(c: &WriteClient) -> serde_json::Value {
    serde_json::json!({
        "client_id": c.client_id(),
        "client_name": "browserid — post to your Bluesky account on your behalf",
        "client_uri": c.origin,
        "application_type": "web",
        // The session outlives the browser, so the refresh grant is asked
        // for explicitly. This is the custody line the identity client does
        // not cross.
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "scope": WRITE_SCOPE,
        "redirect_uris": [c.redirect_uri()],
        "token_endpoint_auth_method": "private_key_jwt",
        "token_endpoint_auth_signing_alg": "ES256",
        // Same key, same key set, different client — Decision 1.
        "jwks_uri": c.jwks_uri(),
        "dpop_bound_access_tokens": true,
    })
}

// ---------------------------------------------------------------------------
// Nonce cache
// ---------------------------------------------------------------------------

/// Per-server `DPoP-Nonce` cache.
///
/// Keyed by server URL because the **authorization server and the resource
/// server issue different nonces** and mixing them turns every call into a
/// guaranteed round trip. A stale entry is not an error: the caller retries
/// once with whatever the server hands back.
#[derive(Default)]
pub struct NonceCache(Mutex<HashMap<String, String>>);

impl NonceCache {
    pub fn get(&self, server: &str) -> Option<String> {
        self.0.lock().unwrap().get(server).cloned()
    }

    pub fn put(&self, server: &str, nonce: &str) {
        self.0.lock().unwrap().insert(server.to_string(), nonce.to_string());
    }
}

/// The origin a nonce belongs to (scheme + authority). Endpoints on the same
/// server share a nonce, and keying on the full URL would miss that.
pub fn server_key(url: &str) -> String {
    crate::idp::origin_of(url).unwrap_or_else(|| url.to_string())
}

// ---------------------------------------------------------------------------
// Token-endpoint calls
// ---------------------------------------------------------------------------

/// What a successful token or refresh response yields. Everything here is
/// stored; nothing is discarded — the opposite of `idp::oauth::exchange_code`
/// by design, and the reason these are two files.
#[derive(Debug, Clone)]
pub struct WriteTokens {
    pub sub: String,
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: i64,
    pub scope: String,
}

/// A token-endpoint failure the caller has to tell apart from a transport
/// hiccup: the grant is gone and no retry will bring it back.
#[derive(Debug, thiserror::Error)]
pub enum TokenError {
    /// `invalid_grant` — the refresh token was already used, or the user
    /// disconnected the app at their PDS. The session is dead; reconnect.
    #[error("the authorization server rejected the grant: {0}")]
    GrantRejected(String),
    #[error("{0}")]
    Other(#[from] IdpError),
}

/// A `private_key_jwt` assertion addressed to `audience` (the AS issuer).
fn client_assertion(client: &WriteClient, key: &ClientKey, audience: &str) -> String {
    let now = chrono::Utc::now().timestamp();
    key.sign_jwt(
        serde_json::json!({ "typ": "JWT", "alg": "ES256", "kid": key.kid() }),
        serde_json::json!({
            "iss": client.client_id(),
            "sub": client.client_id(),
            "aud": audience,
            "jti": random_token(16),
            "iat": now,
            "exp": now + CLIENT_ASSERTION_TTL_SECONDS,
        }),
    )
}

/// A prepared write authorization request.
pub struct PreparedWriteAuth {
    pub authorize_url: String,
    pub state: String,
    pub code_verifier: String,
    pub dpop_secret: String,
}

/// Push the write authorization request (PAR) and build the URL to send the
/// browser to.
///
/// `login_hint` is the DID already pinned for the handle, not the handle the
/// user typed. That is a hint, not a constraint — the authorization server
/// may still sign the user in as someone else — which is exactly why the
/// callback re-checks `sub` against the same pinned DID.
pub async fn push_write_authorization_request(
    client: &WriteClient,
    key: &ClientKey,
    nonces: &NonceCache,
    auth_server: &AuthServer,
    login_hint: &str,
) -> Result<PreparedWriteAuth, IdpError> {
    let state_tok = random_token(24);
    let code_verifier = random_token(32);
    let dpop = WriteDpopKey::generate();

    let form = vec![
        ("client_id".to_string(), client.client_id()),
        ("response_type".to_string(), "code".to_string()),
        ("redirect_uri".to_string(), client.redirect_uri()),
        ("scope".to_string(), WRITE_SCOPE.to_string()),
        ("state".to_string(), state_tok.clone()),
        ("code_challenge".to_string(), pkce_challenge(&code_verifier)),
        ("code_challenge_method".to_string(), "S256".to_string()),
        ("login_hint".to_string(), login_hint.to_string()),
        (
            "client_assertion_type".to_string(),
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer".to_string(),
        ),
        ("client_assertion".to_string(), client_assertion(client, key, &auth_server.issuer)),
    ];

    let body = post_with_dpop(nonces, &dpop, &auth_server.par_endpoint, None, &form)
        .await
        .map_err(|e| match e {
            TokenError::GrantRejected(m) => IdpError::BadRequest(m),
            TokenError::Other(e) => e,
        })?;

    let request_uri = body
        .get("request_uri")
        .and_then(|v| v.as_str())
        .ok_or_else(|| IdpError::BadRequest("PAR response carried no request_uri".into()))?;

    let authorize_url = reqwest::Url::parse_with_params(
        &auth_server.authorization_endpoint,
        &[("client_id", client.client_id().as_str()), ("request_uri", request_uri)],
    )
    .map_err(|e| IdpError::Internal(format!("authorize URL: {e}")))?
    .to_string();

    Ok(PreparedWriteAuth {
        authorize_url,
        state: state_tok,
        code_verifier,
        dpop_secret: dpop.to_secret_b64(),
    })
}

/// Exchange the authorization code for a **full** session.
pub async fn exchange_write_code(
    client: &WriteClient,
    key: &ClientKey,
    nonces: &NonceCache,
    auth_server: &AuthServer,
    code: &str,
    code_verifier: &str,
    dpop: &WriteDpopKey,
) -> Result<WriteTokens, TokenError> {
    let form = vec![
        ("grant_type".to_string(), "authorization_code".to_string()),
        ("code".to_string(), code.to_string()),
        ("redirect_uri".to_string(), client.redirect_uri()),
        ("code_verifier".to_string(), code_verifier.to_string()),
        ("client_id".to_string(), client.client_id()),
        (
            "client_assertion_type".to_string(),
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer".to_string(),
        ),
        ("client_assertion".to_string(), client_assertion(client, key, &auth_server.issuer)),
    ];
    let body = post_with_dpop(nonces, dpop, &auth_server.token_endpoint, None, &form).await?;
    parse_tokens(&body)
}

/// Spend the refresh token. atproto rotates on every use: the response
/// carries a **new** refresh token and the old one is dead, which is why the
/// caller must hold the per-DID lock across this call and the store write.
pub async fn refresh_write_session(
    client: &WriteClient,
    key: &ClientKey,
    nonces: &NonceCache,
    auth_server: &AuthServer,
    refresh_token: &str,
    dpop: &WriteDpopKey,
) -> Result<WriteTokens, TokenError> {
    let form = vec![
        ("grant_type".to_string(), "refresh_token".to_string()),
        ("refresh_token".to_string(), refresh_token.to_string()),
        ("client_id".to_string(), client.client_id()),
        (
            "client_assertion_type".to_string(),
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer".to_string(),
        ),
        ("client_assertion".to_string(), client_assertion(client, key, &auth_server.issuer)),
    ];
    let body = post_with_dpop(nonces, dpop, &auth_server.token_endpoint, None, &form).await?;
    let mut tokens = parse_tokens(&body)?;
    // Belt and braces: a server that omits the rotated refresh token means
    // "keep using the one you have".
    if tokens.refresh_token.is_empty() {
        tokens.refresh_token = refresh_token.to_string();
    }
    Ok(tokens)
}

fn parse_tokens(body: &serde_json::Value) -> Result<WriteTokens, TokenError> {
    let s = |k: &str| body.get(k).and_then(|v| v.as_str()).unwrap_or_default().to_string();
    let access_token = s("access_token");
    if access_token.is_empty() {
        return Err(TokenError::Other(IdpError::BadRequest(
            "token response carried no access_token".into(),
        )));
    }
    let sub = s("sub");
    if sub.is_empty() {
        return Err(TokenError::Other(IdpError::BadRequest(
            "token response carried no sub (the DID)".into(),
        )));
    }
    Ok(WriteTokens {
        sub,
        access_token,
        refresh_token: s("refresh_token"),
        // No `expires_in` is not a licence to treat the token as immortal;
        // assume the atproto default and let the refresh path correct it.
        expires_in: body.get("expires_in").and_then(|v| v.as_i64()).unwrap_or(3600),
        scope: s("scope"),
    })
}

/// POST a form to an OAuth endpoint with a DPoP proof, doing the
/// `use_dpop_nonce` handshake **against the cache**.
///
/// The identity client re-handshakes on every call and explains why that is
/// right for it (two requests per human, minutes apart). Here it is wrong:
/// with a cached nonce the common case is one request, and the retry exists
/// only for the moment a nonce rotates. Keyed on the response header rather
/// than the status code, for the same reason as the identity client —
/// bsky.social answers `400` where RFC 9449 describes `401`.
async fn post_with_dpop(
    nonces: &NonceCache,
    dpop: &WriteDpopKey,
    url: &str,
    access_token: Option<&str>,
    form: &[(String, String)],
) -> Result<serde_json::Value, TokenError> {
    let key = server_key(url);
    let mut nonce = nonces.get(&key);
    for attempt in 0..2 {
        let proof = dpop.proof("POST", url, nonce.as_deref(), access_token);
        let mut req = net::guarded_client().post(url).header("DPoP", proof).form(form);
        if let Some(tok) = access_token {
            req = req.header(reqwest::header::AUTHORIZATION, format!("DPoP {tok}"));
        }
        let resp = req.send().await.map_err(|e| {
            tracing::warn!(%url, "write-relay token request failed: {e}");
            TokenError::Other(IdpError::BadRequest(
                "could not reach the authorization server".into(),
            ))
        })?;

        let server_nonce =
            resp.headers().get("dpop-nonce").and_then(|v| v.to_str().ok()).map(str::to_string);
        if let Some(n) = &server_nonce {
            nonces.put(&key, n);
        }
        let status = resp.status();
        let body: serde_json::Value = resp.json().await.unwrap_or(serde_json::Value::Null);
        if status.is_success() {
            return Ok(body);
        }
        let error = body.get("error").and_then(|v| v.as_str()).unwrap_or_default();
        let wants_nonce = error == "use_dpop_nonce"
            || (matches!(status.as_u16(), 400 | 401) && body.get("error").is_none());
        if attempt == 0 && wants_nonce {
            if let Some(n) = server_nonce {
                nonce = Some(n);
                continue;
            }
        }
        let description =
            body.get("error_description").and_then(|v| v.as_str()).unwrap_or_default();
        let message = format!(
            "{status}: {error}{}{description}",
            if description.is_empty() { "" } else { " — " }
        );
        // `invalid_grant` is the one failure that means "this session is
        // over" rather than "try again": the refresh token was spent, or
        // the user disconnected the app at their PDS. Conflating it with a
        // transport error would leave a dead session looking retryable
        // forever.
        return Err(if error == "invalid_grant" {
            TokenError::GrantRejected(message)
        } else {
            TokenError::Other(IdpError::BadRequest(format!(
                "the authorization server refused ({message})"
            )))
        });
    }
    Err(TokenError::Other(IdpError::BadRequest(
        "authorization server kept demanding a new DPoP nonce".into(),
    )))
}

/// POST a JSON body to a resource server (the user's PDS) with a DPoP-bound
/// access token.
///
/// Separate from [`post_with_dpop`] only because the body is JSON and the
/// nonce is persisted per session rather than per process. This is the sole
/// transport used by [`super::RelaySession`]'s one method; it is private to
/// the module and takes a fully-built body, so it cannot be reached with a
/// caller-chosen `repo`.
pub(super) async fn post_xrpc(
    nonces: &NonceCache,
    dpop: &WriteDpopKey,
    url: &str,
    access_token: &str,
    body: &serde_json::Value,
    seed_nonce: Option<&str>,
) -> Result<(serde_json::Value, Option<String>), TokenError> {
    let key = server_key(url);
    let mut nonce = nonces.get(&key).or_else(|| seed_nonce.map(str::to_string));
    let mut learned: Option<String> = None;
    for attempt in 0..2 {
        let proof = dpop.proof("POST", url, nonce.as_deref(), Some(access_token));
        let resp = net::guarded_client()
            .post(url)
            .header("DPoP", proof)
            .header(reqwest::header::AUTHORIZATION, format!("DPoP {access_token}"))
            .json(body)
            .send()
            .await
            .map_err(|e| {
                tracing::warn!(%url, "write-relay XRPC call failed: {e}");
                TokenError::Other(IdpError::BadRequest("could not reach the user's PDS".into()))
            })?;

        let server_nonce =
            resp.headers().get("dpop-nonce").and_then(|v| v.to_str().ok()).map(str::to_string);
        if let Some(n) = &server_nonce {
            nonces.put(&key, n);
            learned = Some(n.clone());
        }
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        let parsed: serde_json::Value =
            serde_json::from_str(&text).unwrap_or(serde_json::Value::Null);
        if status.is_success() {
            return Ok((parsed, learned));
        }
        let error = parsed.get("error").and_then(|v| v.as_str()).unwrap_or_default();
        if attempt == 0 && (error == "use_dpop_nonce" || error == "UseDpopNonce") {
            if let Some(n) = server_nonce {
                nonce = Some(n);
                continue;
            }
        }
        let message = parsed
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| text.get(..300).unwrap_or(&text));
        // 401 from the resource server means the access token is no longer
        // accepted — expired, or the grant was withdrawn. The caller turns
        // that into a refresh attempt and, failing that, a reconnect prompt.
        return Err(if status.as_u16() == 401 || error == "invalid_token" {
            TokenError::GrantRejected(format!("{status}: {error} {message}"))
        } else {
            TokenError::Other(IdpError::BadRequest(format!(
                "the user's PDS refused ({status}): {error} {message}"
            )))
        });
    }
    Err(TokenError::Other(IdpError::BadRequest(
        "the user's PDS kept demanding a new DPoP nonce".into(),
    )))
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

    fn client() -> WriteClient {
        WriteClient { origin: "https://bsky.browserid.test".into() }
    }

    /// The write client must be a *different* client_id asking for
    /// *different* things — that separation is Decision 1, and collapsing it
    /// would put a full-account-access consent screen in front of every
    /// identity-only login.
    #[test]
    fn the_write_client_is_a_distinct_document_asking_for_refresh_and_write() {
        let c = client();
        let doc = write_client_metadata_doc(&c);
        assert_eq!(doc["client_id"], c.client_id());
        assert_eq!(doc["client_id"], "https://bsky.browserid.test/idp/write-client-metadata.json");
        assert_ne!(doc["client_id"], "https://bsky.browserid.test/idp/client-metadata.json");
        assert_eq!(doc["grant_types"], json!(["authorization_code", "refresh_token"]));
        assert_eq!(doc["scope"], "atproto transition:generic");
        assert_eq!(doc["redirect_uris"], json!([c.redirect_uri()]));
        // Same key material as the identity client, published once.
        assert_eq!(doc["jwks_uri"], "https://bsky.browserid.test/idp/jwks.json");
        assert_eq!(doc["token_endpoint_auth_method"], "private_key_jwt");
        assert_eq!(doc["token_endpoint_auth_signing_alg"], "ES256");
        assert_eq!(doc["dpop_bound_access_tokens"], true);
    }

    /// The identity client's document must be untouched by any of this: it
    /// still asks for the bare `atproto` scope and no refresh grant.
    #[test]
    fn the_identity_client_still_asks_for_nothing_but_identity() {
        let st = crate::idp::tests::test_state();
        let doc = crate::idp::oauth::client_metadata_doc(&st);
        assert_eq!(doc["grant_types"], json!(["authorization_code"]));
        assert_eq!(doc["scope"], crate::idp::OAUTH_SCOPE);
        assert!(!doc["scope"].as_str().unwrap().contains("transition"));
    }

    /// RFC 9449 §4.2. A proof that accompanies an access token MUST carry
    /// `ath`; without it a proof lifted off one request could be paired with
    /// a different token.
    #[test]
    fn a_proof_carrying_a_token_binds_to_it_with_ath() {
        let dpop = WriteDpopKey::generate();
        let (header, claims) = parts(&dpop.proof(
            "POST",
            "https://pds.example/xrpc/com.atproto.repo.createRecord?x=1",
            Some("n-1"),
            Some("the-access-token"),
        ));
        assert_eq!(header["typ"], "dpop+jwt");
        assert_eq!(header["jwk"]["crv"], "P-256");
        assert_eq!(claims["htm"], "POST");
        assert_eq!(claims["htu"], "https://pds.example/xrpc/com.atproto.repo.createRecord");
        assert_eq!(claims["nonce"], "n-1");
        assert_eq!(
            claims["ath"].as_str().unwrap(),
            URL_SAFE_NO_PAD.encode(Sha256::digest(b"the-access-token")),
        );
        // A token-endpoint proof carries no token, so no ath.
        let (_, bare) = parts(&dpop.proof("POST", "https://as.example/token", None, None));
        assert!(bare.get("ath").is_none());
        assert!(bare.get("nonce").is_none());
    }

    #[test]
    fn the_dpop_key_survives_being_sealed_and_reloaded() {
        // Unlike the identity flow's key this one has to come back after a
        // process restart — the access token is bound to it for the whole
        // session lifetime.
        let dpop = WriteDpopKey::generate();
        let back = WriteDpopKey::from_secret_b64(&dpop.to_secret_b64()).unwrap();
        assert_eq!(dpop.public_jwk(), back.public_jwk());
        assert!(WriteDpopKey::from_secret_b64("not-a-key").is_err());
    }

    /// The authorization server and the resource server hand out different
    /// nonces; caching them under one key would make every call miss.
    #[test]
    fn nonces_are_cached_per_server() {
        let c = NonceCache::default();
        c.put(&server_key("https://bsky.social/oauth/token"), "as-nonce");
        c.put(&server_key("https://shard.example/xrpc/com.atproto.repo.createRecord"), "rs-nonce");
        assert_eq!(c.get(&server_key("https://bsky.social/oauth/par")).as_deref(), Some("as-nonce"));
        assert_eq!(
            c.get(&server_key("https://shard.example/xrpc/anything")).as_deref(),
            Some("rs-nonce")
        );
        assert_eq!(c.get(&server_key("https://other.example/x")), None);
    }

    #[test]
    fn the_client_assertion_is_issued_by_the_write_client_id() {
        let key = ClientKey::generate();
        let (header, claims) = parts(&client_assertion(&client(), &key, "https://bsky.social"));
        assert_eq!(header["kid"], key.kid());
        // Signed by the shared key, but speaking as the WRITE client.
        assert_eq!(claims["iss"], "https://bsky.browserid.test/idp/write-client-metadata.json");
        assert_eq!(claims["sub"], claims["iss"]);
        assert_eq!(claims["aud"], "https://bsky.social");
        assert!(claims["exp"].as_i64().unwrap() > claims["iat"].as_i64().unwrap());
    }

    #[test]
    fn a_token_response_without_a_sub_or_access_token_is_refused() {
        assert!(parse_tokens(&json!({ "access_token": "a" })).is_err(), "no sub");
        assert!(parse_tokens(&json!({ "sub": "did:plc:a" })).is_err(), "no access token");
        let t = parse_tokens(&json!({
            "sub": "did:plc:a", "access_token": "acc", "refresh_token": "ref",
            "expires_in": 900, "scope": WRITE_SCOPE,
        }))
        .unwrap();
        assert_eq!((t.sub.as_str(), t.refresh_token.as_str(), t.expires_in), ("did:plc:a", "ref", 900));
    }
}
