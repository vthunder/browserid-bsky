//! The **OAuth write relay** — attested posts on the user's real Bluesky
//! account (bean browserid-bsky-ru7u, design doc
//! `docs/plans/2026-07-28-write-relay-design.md`), phase 1.
//!
//! Everywhere else in this codebase the bridge is careful not to hold
//! credentials for accounts it does not own. This module is where that
//! stops being true, on purpose, for users who explicitly opt in: it stores
//! a live atproto OAuth session for a real Bluesky account and uses it to
//! create records in that account's repo. That is a real and permanent
//! increase in blast radius, and the design document says so plainly rather
//! than talking around it.
//!
//! What keeps it bounded is not policy but shape. Three things, and they are
//! the parts to review hardest:
//!
//! 1. **One method.** [`RelaySession`] exposes exactly one operation —
//!    *create a record in my own repo, in collection C* — and `C` is checked
//!    against [`RELAY_COLLECTIONS`], a hardcoded array. Not the collection
//!    from the request; not whatever `scopes.rs` can express; not a generic
//!    passthrough. The `repo` is always the session's own pinned DID,
//!    interpolated from the stored row, never read from a request body.
//! 2. **One entry point.** The only caller is `routes::attributed_post`,
//!    and only after a live warrant, a grantee signature over *this exact
//!    content hash*, a freshness check, a scope check and a single-use
//!    nonce have all passed. Revoking the warrant refuses the post before
//!    the relay is reached, which is what makes one kill switch sufficient.
//! 3. **One key, off the disk.** The three secret columns are AEAD blobs
//!    (see [`crypto`]); no accessor in `store.rs` can read or write them
//!    without a [`crypto::SecretBox`], and a deployment with no key
//!    configured has no relay at all.
//!
//! The OAuth session lifecycle — refresh-token rotation under a per-DID
//! single-flight lock, `ath`-bound DPoP, per-server nonce caching — lives in
//! [`oauth`]. It is a second, separate OAuth client from the IdP's: the
//! identity client's zero custody is *structural* (its `exchange_code`
//! returns a DID and nothing else) and nothing here is allowed to soften it.

pub mod crypto;
pub mod oauth;
pub mod routes;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Duration, Utc};

use crate::idp::oauth::AuthServer;
use crate::idp::IdpState;
use crate::store::{Store, WriteSession, WriteSessionState};

use self::crypto::SecretBox;
use self::oauth::{NonceCache, TokenError, WriteClient, WriteDpopKey, WriteTokens};

/// **The enforcement boundary.** The only record collections the relay may
/// ever write into a user's real repo.
///
/// The OAuth grant behind a write session is `transition:generic` — roughly
/// "act as this account". The warrant that authorized the post is narrow
/// (`repo:app.bsky.feed.post?action=create`). This array is the entire thing
/// standing between them, so it is a compile-time constant and the check
/// against it happens inside the single method that can talk to the user's
/// PDS. There is no configuration that widens it and no request field that
/// reaches it.
///
/// Adding an entry means deciding to write a new record type into real
/// people's repos permanently and visibly on the firehose. That is a design
/// decision, not a config change.
pub const RELAY_COLLECTIONS: [&str; 3] =
    ["app.bsky.feed.post", "me.browserid.warrant", "me.browserid.provenance"];

/// Refresh this long before the access token actually expires. Proactive
/// refresh keeps the racing window small; the single-flight lock closes it.
const REFRESH_SKEW_SECONDS: i64 = 120;

/// How long a pending connect flow stays resumable.
pub const CONNECT_FLOW_TTL_MINUTES: i64 = 15;

/// The error the caller has to be able to tell apart. In particular
/// [`RelayError::SessionExpired`] is *not* an authorization failure — the
/// warrant is fine, only the OAuth session died — and conflating the two
/// sends agents down the wrong path.
#[derive(Debug, thiserror::Error)]
pub enum RelayError {
    /// The grantor has no stored write session. The caller must not fall
    /// back to writing on a bridge account: posting somewhere other than
    /// where the human expects is worse than failing.
    #[error("no write session for {0}")]
    NoSession(String),
    /// The session is over — expired, revoked, or its refresh token spent.
    /// Actionable: reconnect.
    #[error("{0}")]
    SessionExpired(String),
    /// The enforcement boundary refused. Reaching this is a bug in the
    /// bridge, not a user error, and it is logged as such.
    #[error("the relay does not write {0}")]
    CollectionNotAllowed(String),
    #[error("{0}")]
    Pds(String),
    #[error("{0}")]
    Internal(String),
}

// ---------------------------------------------------------------------------
// Allowlist
// ---------------------------------------------------------------------------

/// Who may connect a write session (design doc, *Decision 6*).
///
/// v1 is opt-in testers only, until at least one refresh cycle and one
/// session expiry have been observed in production. **Empty means nobody** —
/// never "everybody". An allowlist that silently opens up when its
/// configuration goes missing is not an allowlist, and this is the one
/// control that bounds how many real accounts a bridge compromise reaches.
#[derive(Debug, Clone, Default)]
pub struct Allowlist(Vec<String>);

impl Allowlist {
    /// Parse `WRITE_RELAY_ALLOWLIST`: comma-separated handles
    /// (`dan.bsky.social`, or `dan.bsky.social@bsky.browserid.me`) and/or
    /// DIDs (`did:plc:…`).
    pub fn parse(raw: &str) -> Self {
        Self(
            raw.split(',')
                .map(|s| s.trim().to_ascii_lowercase())
                // An entry written as a full browserid identity is the same
                // person as the bare handle; keep only the handle part.
                .map(|s| match s.split_once('@') {
                    Some((h, _)) if !s.starts_with("did:") => h.to_string(),
                    _ => s,
                })
                .filter(|s| !s.is_empty())
                .collect(),
        )
    }

    pub fn from_env() -> Self {
        Self::parse(&std::env::var("WRITE_RELAY_ALLOWLIST").unwrap_or_default())
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// May this identity connect? Either its handle or its DID must be
    /// listed. An empty list permits nothing.
    pub fn permits(&self, handle: &str, did: &str) -> bool {
        let (h, d) = (handle.to_ascii_lowercase(), did.to_ascii_lowercase());
        self.0.iter().any(|e| *e == h || *e == d)
    }

    pub fn entries(&self) -> &[String] {
        &self.0
    }
}

// ---------------------------------------------------------------------------
// Relay state
// ---------------------------------------------------------------------------

pub struct RelayState {
    /// The write client's identity (a `client_id` distinct from the IdP's).
    pub client: WriteClient,
    /// The AEAD key for the write-session secret columns. Its existence is
    /// what makes the table usable at all.
    pub secrets: SecretBox,
    pub allowlist: Allowlist,
    /// Per-server `DPoP-Nonce` cache, shared across sessions.
    pub nonces: NonceCache,
    /// One lock per DID, held across *check → refresh → store write*.
    ///
    /// atproto refresh tokens are single-use with mandatory rotation: two
    /// concurrent posts that both notice an expiring access token and both
    /// refresh will race, and the loser's rotated token is dead — which may
    /// invalidate the whole session. Serializing per DID is what turns that
    /// from "the user is silently logged out" into "one request waited".
    ///
    /// **In-process only.** Two bridge processes against the same SQLite
    /// file would still race a refresh, because this lock lives in memory
    /// and not in the database. That is sound for the single-process
    /// deployment this is built for, and the failure mode is bounded — the
    /// loser's token is burned, the session is marked revoked, and the human
    /// is told to reconnect — but running the bridge horizontally would need
    /// this moved into a row-level claim (e.g. a conditional UPDATE on
    /// `last_refresh`) before it is correct.
    refresh_locks: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
}

impl RelayState {
    /// Build the relay, or `None` if this deployment does not run one.
    ///
    /// The relay is **off unless `WRITE_RELAY_ALLOWLIST` names someone**.
    /// That is deliberately a single deliberate act of configuration: there
    /// is no way to end up with a live relay by forgetting a variable, and
    /// `Decision 6`'s "allowlisted in v1" is enforced by the same switch
    /// that turns the feature on.
    pub fn from_env(origin: &str) -> Result<Option<Self>, String> {
        let allowlist = Allowlist::from_env();
        if allowlist.is_empty() {
            tracing::info!(
                "write relay disabled — set WRITE_RELAY_ALLOWLIST to the handles or DIDs \
                 permitted to connect one"
            );
            return Ok(None);
        }
        let secrets = SecretBox::from_env()?;
        tracing::info!(
            allowed = allowlist.entries().len(),
            "write relay ENABLED — the bridge will hold live posting credentials for \
             connected accounts"
        );
        Ok(Some(Self {
            client: WriteClient { origin: origin.trim_end_matches('/').to_string() },
            secrets,
            allowlist,
            nonces: NonceCache::default(),
            refresh_locks: Mutex::new(HashMap::new()),
        }))
    }

    /// A relay with a throwaway AEAD key, for tests across the crate.
    #[cfg(test)]
    pub(crate) fn for_test(origin: &str, allowlist: &str) -> Self {
        Self {
            client: WriteClient { origin: origin.trim_end_matches('/').to_string() },
            secrets: SecretBox::from_key_bytes(&[11u8; 32]).unwrap(),
            allowlist: Allowlist::parse(allowlist),
            nonces: NonceCache::default(),
            refresh_locks: Mutex::new(HashMap::new()),
        }
    }

    fn lock_for(&self, did: &str) -> Arc<tokio::sync::Mutex<()>> {
        self.refresh_locks
            .lock()
            .unwrap()
            .entry(did.to_string())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    }

    /// Is there a write session for this DID? Answers without decrypting, so
    /// the post path can pick a backend before touching the AEAD key.
    pub fn has_session(&self, store: &Store, did: &str) -> bool {
        store.write_session_exists(did).unwrap_or(false)
    }

    /// Load the session for `did`, refreshing it first if the access token
    /// is at or near expiry.
    ///
    /// The refresh happens under this DID's lock, and the row is **re-read
    /// after acquiring it** — the whole point of the lock is that the winner
    /// may already have rotated the token, and the loser must use the new
    /// one rather than spend a refresh token that is already dead.
    pub async fn open(
        &self,
        store: &Store,
        idp: &IdpState,
        did: &str,
    ) -> Result<RelaySession<'_>, RelayError> {
        let session = self.load(store, did)?;
        let session = if needs_refresh(&session, Utc::now()) {
            let lock = self.lock_for(did);
            let _guard = lock.lock().await;
            // Re-read: the holder of the lock before us may have refreshed.
            let fresh = self.load(store, did)?;
            if needs_refresh(&fresh, Utc::now()) {
                self.refresh(store, idp, fresh).await?
            } else {
                fresh
            }
        } else {
            session
        };
        let dpop = WriteDpopKey::from_secret_b64(&session.dpop_secret)
            .map_err(|e| RelayError::Internal(e.to_string()))?;
        Ok(RelaySession { relay: self, session, dpop })
    }

    fn load(&self, store: &Store, did: &str) -> Result<WriteSession, RelayError> {
        let session = store
            .write_session(&self.secrets, did)
            .map_err(|e| RelayError::Internal(e.to_string()))?
            .ok_or_else(|| RelayError::NoSession(did.to_string()))?;
        match session.state {
            WriteSessionState::Live => Ok(session),
            WriteSessionState::Expired => Err(RelayError::SessionExpired(format!(
                "the write connection for {} has expired",
                session.handle
            ))),
            WriteSessionState::Revoked => Err(RelayError::SessionExpired(format!(
                "the write connection for {} was revoked at the account's PDS",
                session.handle
            ))),
        }
    }

    /// Spend the refresh token and store the rotated pair. Caller holds the
    /// per-DID lock.
    async fn refresh(
        &self,
        store: &Store,
        idp: &IdpState,
        session: WriteSession,
    ) -> Result<WriteSession, RelayError> {
        let dpop = WriteDpopKey::from_secret_b64(&session.dpop_secret)
            .map_err(|e| RelayError::Internal(e.to_string()))?;
        let auth_server = AuthServer {
            issuer: session.issuer.clone(),
            par_endpoint: String::new(),
            authorization_endpoint: String::new(),
            token_endpoint: session.token_endpoint.clone(),
        };
        let tokens = oauth::refresh_write_session(
            &self.client,
            &idp.oauth_key,
            &self.nonces,
            &auth_server,
            &session.refresh_token,
            &dpop,
        )
        .await;

        let tokens = match tokens {
            Ok(t) => t,
            Err(TokenError::GrantRejected(msg)) => {
                // The refresh token is spent or the user disconnected the
                // app. This is terminal: mark it so every later post fails
                // fast with the reconnect prompt instead of hammering a
                // dead grant.
                let _ = store.write_session_set_state(&session.did, WriteSessionState::Revoked);
                tracing::warn!(did = %session.did, "write session refresh rejected: {msg}");
                return Err(RelayError::SessionExpired(format!(
                    "the write connection for {} is no longer accepted by their PDS",
                    session.handle
                )));
            }
            Err(TokenError::Other(e)) => return Err(RelayError::Pds(e.to_string())),
        };

        // A refresh must never hand back a session for a different account.
        if tokens.sub != session.did {
            let _ = store.write_session_set_state(&session.did, WriteSessionState::Revoked);
            return Err(RelayError::Internal(format!(
                "refresh returned sub {} for the session pinned to {}",
                tokens.sub, session.did
            )));
        }

        let expires = expiry_from(&tokens, Utc::now());
        store
            .write_session_rotate(
                &self.secrets,
                &session.did,
                &tokens.access_token,
                &tokens.refresh_token,
                expires,
            )
            .map_err(|e| RelayError::Internal(e.to_string()))?;
        tracing::info!(did = %session.did, "rotated the write-relay session");
        Ok(WriteSession {
            access_token: tokens.access_token,
            refresh_token: tokens.refresh_token,
            access_expires_at: expires,
            state: WriteSessionState::Live,
            ..session
        })
    }
}

fn needs_refresh(s: &WriteSession, now: DateTime<Utc>) -> bool {
    s.access_expires_at <= now + Duration::seconds(REFRESH_SKEW_SECONDS)
}

fn expiry_from(t: &WriteTokens, now: DateTime<Utc>) -> DateTime<Utc> {
    now + Duration::seconds(t.expires_in.max(0))
}

// ---------------------------------------------------------------------------
// The one method
// ---------------------------------------------------------------------------

/// What a relayed write returns.
#[derive(Debug, Clone)]
pub struct CreatedRecord {
    pub uri: String,
    pub cid: Option<String>,
}

/// A loaded, live write session — and the *entire* surface the relay exposes
/// over the user's account.
///
/// There is one public method. It is not a request forwarder: it takes a
/// collection and a record, and it builds the request body itself. The
/// `repo` field is filled from [`WriteSession::did`], which came out of the
/// stored row, which was written only after the connect callback proved the
/// token's `sub` equalled the DID pinned for the grantor's handle. No value
/// from an inbound HTTP request reaches it.
pub struct RelaySession<'a> {
    relay: &'a RelayState,
    session: WriteSession,
    dpop: WriteDpopKey,
}

/// Hand-written and redacting, not derived. A `RelaySession` wraps live
/// credentials for someone else's account; an accidental `{:?}` in a log
/// line must not be the thing that leaks them.
impl std::fmt::Debug for RelaySession<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RelaySession")
            .field("did", &self.session.did)
            .field("handle", &self.session.handle)
            .field("pds", &self.session.pds)
            .field("access_expires_at", &self.session.access_expires_at)
            .finish_non_exhaustive()
    }
}

impl RelaySession<'_> {
    /// The repo every write from this session lands in.
    pub fn did(&self) -> &str {
        &self.session.did
    }

    pub fn handle(&self) -> &str {
        &self.session.handle
    }

    pub fn pds(&self) -> &str {
        &self.session.pds
    }

    /// **Create a record in this session's own repo.**
    ///
    /// `collection` is validated against [`RELAY_COLLECTIONS`] before
    /// anything is built or sent. `rkey` is `None` to let the PDS assign a
    /// TID (`createRecord`) or `Some` to upsert at a bridge-chosen key
    /// (`putRecord`) — the two provenance collections are 1:1 with something
    /// and need stable keys. `repo` is not a parameter, and cannot become
    /// one without changing this signature.
    pub async fn create_own_record(
        &self,
        store: &Store,
        collection: &str,
        rkey: Option<&str>,
        record: &serde_json::Value,
    ) -> Result<CreatedRecord, RelayError> {
        // THE check. Everything else in this function assumes it passed.
        if !RELAY_COLLECTIONS.contains(&collection) {
            tracing::error!(
                %collection,
                "write relay refused a collection outside the allowlist — this is a bug in \
                 the bridge, not a user error"
            );
            return Err(RelayError::CollectionNotAllowed(collection.to_string()));
        }
        // An rkey is always bridge-derived (a warrant hash, or the rkey the
        // PDS just assigned to the post), but validating the charset costs
        // nothing and keeps a future caller from smuggling one through.
        if let Some(rk) = rkey {
            if rk.is_empty() || rk.len() > 512 || !rk.chars().all(is_rkey_char) {
                return Err(RelayError::Internal(format!("refusing a malformed rkey: {rk:?}")));
            }
        }

        let method = if rkey.is_some() {
            "com.atproto.repo.putRecord"
        } else {
            "com.atproto.repo.createRecord"
        };
        let mut body = serde_json::json!({
            // Always the session's own DID. Never a request field.
            "repo": self.session.did,
            "collection": collection,
            "record": record,
            // Real repo, real timeline: let the PDS reject a malformed post
            // rather than publish it. The two `me.browserid.*` collections
            // are custom lexicons the PDS cannot resolve, so they keep the
            // `validate: false` the bridge already uses for them.
            "validate": collection == "app.bsky.feed.post",
        });
        if let Some(rk) = rkey {
            body["rkey"] = serde_json::Value::String(rk.to_string());
        }

        // `pds` is the stored resource-server URL. It came from the account
        // holder's own DID document and was SSRF-guarded on ingest, at
        // `relay::routes::connect_start`, before the row was written — this
        // path never fetches a URL it learned from the current request.
        let url = format!("{}/xrpc/{}", self.session.pds.trim_end_matches('/'), method);
        let (value, learned_nonce) = oauth::post_xrpc(
            &self.relay.nonces,
            &self.dpop,
            &url,
            &self.session.access_token,
            &body,
            self.session.dpop_nonce.as_deref(),
        )
        .await
        .map_err(|e| match e {
            TokenError::GrantRejected(msg) => {
                // The PDS says this grant is gone. Record it, so the next
                // post fails fast with the reconnect prompt instead of
                // discovering the same thing over the network again.
                let _ =
                    store.write_session_set_state(&self.session.did, WriteSessionState::Revoked);
                tracing::warn!(did = %self.session.did, "write session no longer accepted: {msg}");
                RelayError::SessionExpired(format!(
                    "the write connection for {} is no longer accepted by their PDS",
                    self.session.handle
                ))
            }
            TokenError::Other(e) => RelayError::Pds(e.to_string()),
        })?;

        if let Some(n) = learned_nonce {
            let _ = store.write_session_set_nonce(&self.session.did, &n);
        }
        let uri = value["uri"].as_str().unwrap_or_default().to_string();
        if uri.is_empty() {
            return Err(RelayError::Pds(
                "the user's PDS accepted the write but returned no record URI".into(),
            ));
        }
        Ok(CreatedRecord { uri, cid: value["cid"].as_str().map(str::to_string) })
    }
}

/// atproto record-key charset (RFC 3986 unreserved plus `:~`).
fn is_rkey_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '~' | ':')
}

/// Fixtures other modules' tests need, kept here so the `WriteSession`
/// shape has exactly one place to change.
#[cfg(test)]
pub(crate) mod tests_support {
    use super::*;

    /// Attach a live write session to a bridge that has a relay configured.
    pub(crate) fn insert_live_session(
        state: &crate::BridgeState,
        handle: &str,
        did: &str,
        pds: &str,
    ) {
        let relay = state.relay.as_ref().expect("this bridge has no relay");
        state
            .store
            .write_session_put(
                &relay.secrets,
                &WriteSession {
                    did: did.into(),
                    handle: handle.into(),
                    identity: format!("{handle}@bsky.browserid.test"),
                    pds: pds.into(),
                    issuer: "https://bsky.social".into(),
                    token_endpoint: "https://bsky.social/oauth/token".into(),
                    access_token: "acc".into(),
                    refresh_token: "ref".into(),
                    dpop_secret: oauth::WriteDpopKey::generate().to_secret_b64(),
                    dpop_nonce: None,
                    scope: oauth::WRITE_SCOPE.into(),
                    access_expires_at: Utc::now() + Duration::hours(1),
                    created_at: Utc::now(),
                    state: WriteSessionState::Live,
                },
            )
            .unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_allowlist_permits_nobody() {
        // The failure mode that matters: a missing or blank configuration
        // must not read as "open to everyone".
        for raw in ["", "   ", ",,", " , "] {
            let a = Allowlist::parse(raw);
            assert!(a.is_empty(), "{raw:?}");
            assert!(!a.permits("dan.bsky.social", "did:plc:abc"), "{raw:?}");
        }
    }

    #[test]
    fn the_allowlist_matches_a_handle_or_a_did_and_nothing_else() {
        let a = Allowlist::parse("Dan.Bsky.Social, did:plc:LISTED ,alice.example@bsky.browserid.me");
        assert!(a.permits("dan.bsky.social", "did:plc:whatever"), "listed by handle");
        assert!(a.permits("someone.else", "did:plc:listed"), "listed by DID");
        assert!(a.permits("alice.example", "did:plc:x"), "an @-qualified entry is its handle");
        assert!(!a.permits("bob.bsky.social", "did:plc:unlisted"), "not listed either way");
        // Not a prefix or substring match.
        assert!(!a.permits("evil-dan.bsky.social", "did:plc:x"));
        assert!(!a.permits("x", "did:plc:listed-extra"));
    }

    /// The allowlist is also the on/off switch: no entries, no relay. This
    /// is what keeps Decision 6 ("allowlisted in v1") from being something
    /// a deployment can forget.
    #[test]
    fn the_relay_is_off_unless_someone_is_allowlisted() {
        // `from_env` reads process-wide state, so assert on the branch it
        // takes rather than mutating the environment under other tests.
        assert!(Allowlist::parse("").is_empty());
        assert!(!Allowlist::parse("dan.bsky.social").is_empty());
    }

    #[test]
    fn the_collection_allowlist_is_exactly_the_three_record_types() {
        assert_eq!(
            RELAY_COLLECTIONS,
            ["app.bsky.feed.post", "me.browserid.warrant", "me.browserid.provenance"]
        );
        // Things a coarse `transition:generic` token could otherwise do.
        for forbidden in [
            "app.bsky.feed.like",
            "app.bsky.graph.follow",
            "app.bsky.graph.block",
            "app.bsky.actor.profile",
            "chat.bsky.actor.declaration",
            "app.bsky.feed.repost",
            "",
        ] {
            assert!(!RELAY_COLLECTIONS.contains(&forbidden), "{forbidden}");
        }
    }

    #[test]
    fn rkeys_are_charset_checked() {
        assert!("3kabc-xyz.~:".chars().all(is_rkey_char));
        assert!(!"a/b".chars().all(is_rkey_char));
        assert!(!"a b".chars().all(is_rkey_char));
        assert!(!"a\"b".chars().all(is_rkey_char));
    }

    fn session(expires_in_seconds: i64) -> WriteSession {
        WriteSession {
            did: "did:plc:abc".into(),
            handle: "dan.bsky.social".into(),
            identity: "dan.bsky.social@bsky.browserid.test".into(),
            pds: "https://shard.example".into(),
            issuer: "https://bsky.social".into(),
            token_endpoint: "https://bsky.social/oauth/token".into(),
            access_token: "acc".into(),
            refresh_token: "ref".into(),
            dpop_secret: "s".into(),
            dpop_nonce: None,
            scope: oauth::WRITE_SCOPE.into(),
            access_expires_at: Utc::now() + Duration::seconds(expires_in_seconds),
            created_at: Utc::now(),
            state: WriteSessionState::Live,
        }
    }

    /// Refresh happens *before* expiry, not on the 401 that follows it —
    /// which is what keeps the racing window small enough for the
    /// single-flight lock to be a formality rather than a hot path.
    #[test]
    fn refresh_is_proactive() {
        let now = Utc::now();
        assert!(!needs_refresh(&session(3600), now));
        assert!(needs_refresh(&session(REFRESH_SKEW_SECONDS - 1), now), "inside the skew");
        assert!(needs_refresh(&session(-1), now), "already expired");
    }

    // -- the enforcement boundary, against a live (mock) PDS ---------------

    /// Every request body the relay sent, so a test can assert on what
    /// actually went over the wire rather than on what the code intended.
    type Bodies = Arc<Mutex<Vec<serde_json::Value>>>;

    /// A PDS that accepts any repo write and records it. Deliberately
    /// permissive: it must not be the thing that stops a bad write, or the
    /// test would be asserting the server's behaviour instead of ours.
    async fn mock_pds() -> (String, Bodies) {
        use axum::routing::post;
        let bodies: Bodies = Default::default();
        let seen = bodies.clone();
        let handler = move |axum::Json(body): axum::Json<serde_json::Value>| {
            let seen = seen.clone();
            async move {
                let repo = body["repo"].as_str().unwrap_or_default().to_string();
                let coll = body["collection"].as_str().unwrap_or_default().to_string();
                let rkey = body["rkey"].as_str().unwrap_or("assigned-tid").to_string();
                seen.lock().unwrap().push(body);
                axum::Json(serde_json::json!({
                    "uri": format!("at://{repo}/{coll}/{rkey}"),
                    "cid": "bafy-mock",
                }))
            }
        };
        let app = axum::Router::new()
            .route("/xrpc/com.atproto.repo.createRecord", post(handler.clone()))
            .route("/xrpc/com.atproto.repo.putRecord", post(handler));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (base, bodies)
    }

    /// A store holding one live session for `did`, pointed at `pds`.
    fn store_with_session(relay: &RelayState, did: &str, pds: &str) -> Store {
        let store = Store::open_in_memory().unwrap();
        let mut s = session(3600);
        s.did = did.to_string();
        s.pds = pds.to_string();
        s.dpop_secret = WriteDpopKey::generate().to_secret_b64();
        store.write_session_put(&relay.secrets, &s).unwrap();
        store
    }

    /// **The enforcement boundary.** The OAuth grant behind this session is
    /// `transition:generic` — it could delete the repo. The relay's single
    /// method refuses anything outside [`RELAY_COLLECTIONS`], and refuses it
    /// *locally*, before a request is built or sent: the mock PDS would have
    /// happily accepted every one of these.
    #[tokio::test]
    async fn the_relay_refuses_every_collection_outside_the_allowlist() {
        let relay = RelayState::for_test("https://bsky.browserid.test", "dan.bsky.social");
        let (pds, bodies) = mock_pds().await;
        let store = store_with_session(&relay, "did:plc:abc", &pds);
        let idp = crate::idp::tests::test_state();
        let session = relay.open(&store, &idp, "did:plc:abc").await.unwrap();

        for forbidden in [
            "app.bsky.feed.like",
            "app.bsky.graph.follow",
            "app.bsky.graph.block",
            "app.bsky.actor.profile",
            "app.bsky.feed.repost",
            "com.atproto.repo.deleteRecord",
            "APP.BSKY.FEED.POST",
            "app.bsky.feed.post ",
            "",
        ] {
            let e = session
                .create_own_record(&store, forbidden, None, &serde_json::json!({}))
                .await
                .unwrap_err();
            assert!(
                matches!(e, RelayError::CollectionNotAllowed(_)),
                "{forbidden} was not refused: {e}"
            );
        }
        assert!(bodies.lock().unwrap().is_empty(), "nothing reached the PDS");

        // The three that ARE allowed do go through.
        for allowed in RELAY_COLLECTIONS {
            session.create_own_record(&store, allowed, None, &serde_json::json!({})).await.unwrap();
        }
        assert_eq!(bodies.lock().unwrap().len(), 3);
    }

    /// The `repo` of a relayed write is the session's own pinned DID, full
    /// stop. A record body is agent-supplied JSON, so the test feeds it a
    /// body that tries every shape of override and checks the wire.
    #[tokio::test]
    async fn the_repo_is_always_the_session_did_and_cannot_be_overridden() {
        let relay = RelayState::for_test("https://bsky.browserid.test", "dan.bsky.social");
        let (pds, bodies) = mock_pds().await;
        let store = store_with_session(&relay, "did:plc:mine", &pds);
        let idp = crate::idp::tests::test_state();
        let session = relay.open(&store, &idp, "did:plc:mine").await.unwrap();

        let hostile = serde_json::json!({
            "$type": "app.bsky.feed.post",
            "text": "hello",
            // Every plausible attempt to redirect the write, inside the one
            // field an agent controls.
            "repo": "did:plc:victim",
            "collection": "app.bsky.graph.block",
            "rkey": "../../elsewhere",
            "validate": false,
        });
        session.create_own_record(&store, "app.bsky.feed.post", None, &hostile).await.unwrap();

        let sent = bodies.lock().unwrap()[0].clone();
        assert_eq!(sent["repo"], "did:plc:mine", "the session's DID, not the record's");
        assert_eq!(sent["collection"], "app.bsky.feed.post");
        // The hostile fields are still there — nested under `record`, where
        // they are inert content rather than request parameters.
        assert_eq!(sent["record"]["repo"], "did:plc:victim");
        assert!(sent.get("rkey").is_none(), "no rkey was asked for");
        // A real timeline gets PDS-side validation; the custom lexicons
        // cannot (the PDS has no schema for them).
        assert_eq!(sent["validate"], true);

        session
            .create_own_record(&store, "me.browserid.provenance", Some("rk1"), &hostile)
            .await
            .unwrap();
        let sent = bodies.lock().unwrap()[1].clone();
        assert_eq!(sent["repo"], "did:plc:mine");
        assert_eq!(sent["rkey"], "rk1");
        assert_eq!(sent["validate"], false);
    }

    #[tokio::test]
    async fn a_malformed_rkey_is_refused_before_it_is_sent() {
        let relay = RelayState::for_test("https://bsky.browserid.test", "dan.bsky.social");
        let (pds, bodies) = mock_pds().await;
        let store = store_with_session(&relay, "did:plc:abc", &pds);
        let idp = crate::idp::tests::test_state();
        let session = relay.open(&store, &idp, "did:plc:abc").await.unwrap();

        for bad in ["", "a/b", "a b", "a\"b", "a#b"] {
            assert!(session
                .create_own_record(&store, "me.browserid.warrant", Some(bad), &serde_json::json!({}))
                .await
                .is_err());
        }
        assert!(bodies.lock().unwrap().is_empty());
    }

    /// A dead session must be reported as dead — never as "no session",
    /// which the post path would answer by writing to a bridge account
    /// instead, i.e. silently posting somewhere the human did not expect.
    #[tokio::test]
    async fn a_dead_session_is_distinguished_from_a_missing_one() {
        let relay = RelayState::for_test("https://bsky.browserid.test", "dan.bsky.social");
        let store = store_with_session(&relay, "did:plc:abc", "https://unused.example");
        let idp = crate::idp::tests::test_state();

        store.write_session_set_state("did:plc:abc", WriteSessionState::Expired).unwrap();
        let e = relay.open(&store, &idp, "did:plc:abc").await.unwrap_err();
        assert!(matches!(e, RelayError::SessionExpired(_)), "{e}");

        store.write_session_set_state("did:plc:abc", WriteSessionState::Revoked).unwrap();
        assert!(matches!(
            relay.open(&store, &idp, "did:plc:abc").await.unwrap_err(),
            RelayError::SessionExpired(_)
        ));

        store.write_session_delete("did:plc:abc").unwrap();
        assert!(matches!(
            relay.open(&store, &idp, "did:plc:abc").await.unwrap_err(),
            RelayError::NoSession(_)
        ));
        assert!(!relay.has_session(&store, "did:plc:abc"));
    }

    /// Concurrent posts must not each spend the refresh token. The lock is
    /// per DID, so two different accounts never wait on each other.
    #[tokio::test]
    async fn the_refresh_lock_is_per_did_and_serializes_one_did() {
        let relay = Arc::new(RelayState::for_test("https://x.test", "dan.bsky.social"));
        let a1 = relay.lock_for("did:plc:a");
        let a2 = relay.lock_for("did:plc:a");
        let b = relay.lock_for("did:plc:b");
        assert!(Arc::ptr_eq(&a1, &a2), "one lock per DID");
        assert!(!Arc::ptr_eq(&a1, &b), "distinct DIDs do not contend");

        let held = a1.lock().await;
        assert!(a2.try_lock().is_err(), "the second post waits");
        assert!(b.try_lock().is_ok(), "another account does not");
        drop(held);
        assert!(a2.try_lock().is_ok());
    }
}
