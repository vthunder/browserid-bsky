//! Bridge persistence: grantor-email ↔ atproto account bindings, PDS
//! session material, and issued bridge tokens.
//!
//! Tokens are opaque (`bidb_<random>`); only a SHA-256 hash is stored. The
//! bridge does NOT store account passwords — the password is shown once at
//! provisioning. What it keeps is the PDS **session pair** (access+refresh
//! JWTs) it needs to act on warrant-scoped requests; custody sits with the
//! same operator as the PDS itself (design doc §Security).

use std::path::Path;
use std::sync::Mutex;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{DateTime, Utc};
use rand::RngCore;
use rusqlite::{params, Connection, OptionalExtension};
use sha2::{Digest, Sha256};

use crate::relay::crypto::SecretBox;

pub const TOKEN_PREFIX: &str = "bidb_";

#[derive(Debug, thiserror::Error)]
#[error("store: {0}")]
pub struct StoreError(String);

impl From<rusqlite::Error> for StoreError {
    fn from(e: rusqlite::Error) -> Self {
        StoreError(e.to_string())
    }
}

type Result<T> = std::result::Result<T, StoreError>;

#[derive(Debug, Clone)]
pub struct Account {
    pub email: String,
    pub did: String,
    pub handle: String,
    pub access_jwt: String,
    pub refresh_jwt: String,
}

#[derive(Debug, Clone)]
pub struct BridgeToken {
    pub did: String,
    pub grantor: String,
    pub grantee: String,
    pub holder: String,
    /// Raw warrant scope strings (parsed on use — parsing is cheap and this
    /// keeps the stored form canonical to what the user approved)
    pub scopes: Vec<String>,
    /// Warrant revocation ref, re-checked on use (design doc §Revocation)
    pub warrant_status: Option<(String, u64)>,
    /// Hash of the warrant JWS this token was issued from — links to the
    /// `warrants` table so provenance records can reference the published
    /// warrant record (bean 27c0 phase 1).
    pub warrant_ref: String,
    pub expires_at: DateTime<Utc>,
}

/// The signed delegation artifacts a token was issued from, persisted so the
/// bridge can publish a `me.browserid.warrant` record ONCE and reference it
/// from every post's provenance (rather than repeating it per post).
#[derive(Debug, Clone)]
pub struct StoredWarrant {
    pub hash: String,
    pub did: String,
    pub grantor: String,
    pub grantee: String,
    pub warrant_jws: String,
    pub config_cert_jws: String,
    /// AT-URI of the published `me.browserid.warrant` record, once written
    pub record_uri: Option<String>,
}

/// A label this labeler has emitted, with its firehose sequence number.
/// Stored so `subscribeLabels` consumers can resume from a cursor: the
/// AppView ingests labels from the stream and serves them from its own
/// index, so a label that was never streamed is a label nobody sees.
#[derive(Debug, Clone)]
pub struct EmittedLabel {
    pub seq: i64,
    pub uri: String,
    pub val: String,
    pub cts: String,
    /// A **negation**: retracts an earlier label with the same (uri, val).
    /// Stored as its own row with its own seq — the stream is append-only,
    /// so a retraction is an event, not an edit.
    pub neg: bool,
    /// 64-byte compact k256 signature over the label's DAG-CBOR
    pub sig: Vec<u8>,
}

/// SHA-256 (base64url) of a JWS — the dedup key for a warrant.
pub fn warrant_hash(warrant_jws: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(warrant_jws.as_bytes()))
}

/// 32 bytes of URL-safe randomness — session ids and OAuth `state`.
fn random_token() -> String {
    let mut buf = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    URL_SAFE_NO_PAD.encode(buf)
}

/// A handle bound to the DID that proved it (bean tw1d). The DID is the
/// identity's real anchor; the handle is the label it wears.
#[derive(Debug, Clone)]
pub struct HandlePin {
    pub handle: String,
    pub did: String,
    pub first_claimed: DateTime<Utc>,
    /// Last time the public handle↔DID binding was re-confirmed — updated
    /// at every issuance and every access-cert mint.
    pub last_verified: DateTime<Utc>,
    /// The handle moved to another DID. No new certs; the outstanding ones
    /// are already revoked in the status list.
    pub suspended: bool,
}

/// A first-party IdP session. `handle` is `None` for a DID-only sign-in
/// (the retirement path, where the user authenticated as the pinned DID
/// rather than as a handle).
#[derive(Debug, Clone)]
pub struct IdpSession {
    pub handle: Option<String>,
    pub did: String,
    pub expires_at: DateTime<Utc>,
}

/// An OAuth flow waiting for the browser to come back. Holds the PKCE
/// verifier and the flow's ephemeral DPoP key — and, once the code is
/// exchanged, is deleted. No access token, refresh token, or long-lived
/// DPoP key ever reaches this table; that absence is the zero-custody
/// promise made structural.
#[derive(Debug, Clone)]
pub struct PendingOauthFlow {
    pub state: String,
    /// The handle being claimed; `None` when the user signed in with a DID.
    pub handle: Option<String>,
    /// The DID resolved *before* the redirect. The token's `sub` must equal
    /// this, or the OAuth hop proved nothing about the handle.
    pub did: String,
    pub issuer: String,
    pub token_endpoint: String,
    pub code_verifier: String,
    pub dpop_secret: String,
    /// This flow is a voluntary retirement, not a claim.
    pub retire: bool,
    /// Ties the flow to the browser that started it: the value of the
    /// `bsky_idp_flow` cookie set at `/idp/oauth/start`. The callback must
    /// present it, so a `state` captured from someone else's flow cannot be
    /// redeemed in the attacker's browser (login CSRF / session fixation).
    pub browser_binding: String,
    pub expires_at: DateTime<Utc>,
}

/// A pending write-relay connect flow. Same disposable shape as
/// [`PendingOauthFlow`], with one addition that carries the security crux:
/// `did` is the DID already pinned for `handle`, captured *before* the
/// browser leaves, and the callback refuses unless the token's `sub` equals
/// it. Without that a user could authorize the connect hop as a different
/// Bluesky account and the bridge would relay posts attributed to one handle
/// into someone else's repo.
#[derive(Debug, Clone)]
pub struct PendingWriteFlow {
    pub state: String,
    pub handle: String,
    pub did: String,
    pub pds: String,
    pub issuer: String,
    pub token_endpoint: String,
    pub code_verifier: String,
    pub dpop_secret: String,
    pub browser_binding: String,
    pub expires_at: DateTime<Utc>,
}

/// Where a stored write session stands. `Expired` and `Revoked` both mean
/// "cannot post"; they are kept apart because only one of them is the user's
/// doing, and the human-facing message differs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteSessionState {
    Live,
    Expired,
    Revoked,
}

impl WriteSessionState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Live => "live",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }

    /// Anything unrecognized reads as `Revoked` — the state that refuses.
    fn parse(s: &str) -> Self {
        match s {
            "live" => Self::Live,
            "expired" => Self::Expired,
            _ => Self::Revoked,
        }
    }
}

/// A decrypted write-relay session: live OAuth credentials for an account
/// the bridge does not own.
///
/// This struct is the custody the IdP design deliberately refused to take
/// (its `exchange_code` returns only a DID). It exists only behind the
/// relay, only for allowlisted opted-in accounts, and only the AEAD key can
/// produce one from the database.
#[derive(Debug, Clone)]
pub struct WriteSession {
    /// The account's DID — the pinned one, and the only value ever used as
    /// the `repo` of a relayed write.
    pub did: String,
    pub handle: String,
    /// The browserid identity string, `<handle>@<D>` — what a warrant's
    /// grantor field says.
    pub identity: String,
    /// The resource server holding the repo.
    pub pds: String,
    /// The authorization server that issued these tokens.
    pub issuer: String,
    pub token_endpoint: String,
    pub access_token: String,
    pub refresh_token: String,
    /// The session's long-lived DPoP key, base64url P-256 scalar. Long-lived
    /// by necessity: the access token is bound to it.
    pub dpop_secret: String,
    /// The resource server's most recent `DPoP-Nonce`, persisted so a
    /// restart does not cost every session a rejected first request.
    pub dpop_nonce: Option<String>,
    pub scope: String,
    pub access_expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub state: WriteSessionState,
}

pub struct Store {
    conn: Mutex<Connection>,
}

impl Store {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        Self::init(Connection::open(path)?)
    }

    pub fn open_in_memory() -> Result<Self> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> Result<Self> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS accounts (
                 email       TEXT PRIMARY KEY,
                 did         TEXT NOT NULL UNIQUE,
                 handle      TEXT NOT NULL UNIQUE,
                 access_jwt  TEXT NOT NULL,
                 refresh_jwt TEXT NOT NULL,
                 created_at  TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS tokens (
                 token_hash     TEXT PRIMARY KEY,
                 did            TEXT NOT NULL,
                 grantor        TEXT NOT NULL,
                 grantee        TEXT NOT NULL,
                 holder         TEXT NOT NULL,
                 scopes         TEXT NOT NULL,
                 warrant_uri    TEXT,
                 warrant_idx    INTEGER,
                 warrant_ref    TEXT NOT NULL DEFAULT '',
                 expires_at     TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS nonces (
                 nonce  TEXT PRIMARY KEY,
                 did    TEXT NOT NULL,
                 rkey   TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS warrants (
                 hash            TEXT PRIMARY KEY,
                 did             TEXT NOT NULL,
                 grantor         TEXT NOT NULL,
                 grantee         TEXT NOT NULL,
                 warrant_jws     TEXT NOT NULL,
                 config_cert_jws TEXT NOT NULL,
                 record_uri      TEXT
             );
             CREATE TABLE IF NOT EXISTS labels (
                 seq  INTEGER PRIMARY KEY AUTOINCREMENT,
                 uri  TEXT NOT NULL,
                 val  TEXT NOT NULL,
                 cts  TEXT NOT NULL,
                 sig  BLOB NOT NULL,
                 neg  INTEGER NOT NULL DEFAULT 0
             );
             CREATE TABLE IF NOT EXISTS label_defs (
                 val         TEXT PRIMARY KEY,
                 defined_at  TEXT NOT NULL,
                 grantor     TEXT,
                 grantee     TEXT
             );
             CREATE TABLE IF NOT EXISTS audit_log (
                 id       INTEGER PRIMARY KEY AUTOINCREMENT,
                 at       TEXT NOT NULL,
                 did      TEXT NOT NULL,
                 grantor  TEXT NOT NULL,
                 grantee  TEXT NOT NULL,
                 holder   TEXT NOT NULL,
                 nsid     TEXT NOT NULL,
                 outcome  TEXT NOT NULL
             );
             -- IdP (bean tw1d): the bsky-handle identity provider's own
             -- state. Prefixed `idp_` because it shares the bridge's
             -- database but not its concerns.
             CREATE TABLE IF NOT EXISTS idp_pins (
                 handle        TEXT PRIMARY KEY,
                 did           TEXT NOT NULL,
                 first_claimed TEXT NOT NULL,
                 last_verified TEXT NOT NULL,
                 suspended     INTEGER NOT NULL DEFAULT 0
             );
             CREATE INDEX IF NOT EXISTS idp_pins_did ON idp_pins (did);
             CREATE TABLE IF NOT EXISTS idp_reassignment_attempts (
                 handle     TEXT NOT NULL,
                 did        TEXT NOT NULL,
                 first_seen TEXT NOT NULL,
                 PRIMARY KEY (handle, did)
             );
             -- One row per issued cert: its bit index in D's status list.
             -- AUTOINCREMENT so an index is never recycled onto a new cert.
             CREATE TABLE IF NOT EXISTS idp_status (
                 idx       INTEGER PRIMARY KEY AUTOINCREMENT,
                 identity  TEXT NOT NULL,
                 issued_at TEXT NOT NULL,
                 revoked   INTEGER NOT NULL DEFAULT 0
             );
             CREATE INDEX IF NOT EXISTS idp_status_identity ON idp_status (identity);
             CREATE TABLE IF NOT EXISTS idp_sessions (
                 sid        TEXT PRIMARY KEY,
                 handle     TEXT,
                 did        TEXT NOT NULL,
                 expires_at TEXT NOT NULL
             );
             -- A pending OAuth flow. Holds the PKCE verifier and the
             -- EPHEMERAL DPoP key across the browser round trip; deleted
             -- the moment the code is exchanged, so nothing token-shaped
             -- ever rests here.
             CREATE TABLE IF NOT EXISTS idp_oauth_flows (
                 state         TEXT PRIMARY KEY,
                 handle        TEXT,
                 did           TEXT NOT NULL,
                 issuer        TEXT NOT NULL,
                 token_endpoint TEXT NOT NULL,
                 code_verifier TEXT NOT NULL,
                 dpop_secret   TEXT NOT NULL,
                 retire        INTEGER NOT NULL DEFAULT 0,
                 browser_binding TEXT NOT NULL DEFAULT '',
                 expires_at    TEXT NOT NULL
             );
             -- A pending WRITE-relay OAuth flow. Same shape as the identity
             -- flow above and just as disposable, plus the identity whose
             -- pinned DID the returned `sub` must equal.
             CREATE TABLE IF NOT EXISTS write_oauth_flows (
                 state          TEXT PRIMARY KEY,
                 handle         TEXT NOT NULL,
                 did            TEXT NOT NULL,
                 pds            TEXT NOT NULL,
                 issuer         TEXT NOT NULL,
                 token_endpoint TEXT NOT NULL,
                 code_verifier  TEXT NOT NULL,
                 dpop_secret    TEXT NOT NULL,
                 browser_binding TEXT NOT NULL,
                 expires_at     TEXT NOT NULL
             );
             -- The write relay's stored atproto OAuth sessions (bean ru7u).
             -- Unlike every other table here this one holds live credentials
             -- for accounts the bridge does not own, so the three secret
             -- columns are AEAD blobs, not text — see `relay::crypto`. There
             -- is no accessor that reads or writes them without a key.
             CREATE TABLE IF NOT EXISTS write_sessions (
                 did               TEXT PRIMARY KEY,
                 handle            TEXT NOT NULL,
                 identity          TEXT NOT NULL,
                 pds               TEXT NOT NULL,
                 issuer            TEXT NOT NULL,
                 token_endpoint    TEXT NOT NULL,
                 access_enc        BLOB NOT NULL,
                 refresh_enc       BLOB NOT NULL,
                 dpop_secret_enc   BLOB NOT NULL,
                 dpop_nonce        TEXT,
                 scope             TEXT NOT NULL,
                 access_expires_at TEXT NOT NULL,
                 created_at        TEXT NOT NULL,
                 last_refresh      TEXT NOT NULL,
                 state             TEXT NOT NULL DEFAULT 'live'
             );
             CREATE INDEX IF NOT EXISTS write_sessions_handle ON write_sessions (handle);",
        )?;
        // Idempotent column adds for DBs created before a column existed
        // (CREATE TABLE IF NOT EXISTS won't alter an existing table). A
        // duplicate-column error means it already ran — ignore it.
        for stmt in [
            "ALTER TABLE tokens ADD COLUMN warrant_ref TEXT NOT NULL DEFAULT ''",
            "ALTER TABLE label_defs ADD COLUMN grantor TEXT",
            "ALTER TABLE label_defs ADD COLUMN grantee TEXT",
            "ALTER TABLE idp_oauth_flows ADD COLUMN browser_binding TEXT NOT NULL DEFAULT ''",
        ] {
            if let Err(e) = conn.execute(stmt, []) {
                if !e.to_string().contains("duplicate column name") {
                    return Err(e.into());
                }
            }
        }
        // After the migration, so a legacy `labels` table has grown its
        // `neg` column before the index that mentions it is created.
        Self::migrate_labels_neg(&conn)?;
        conn.execute_batch(
            "CREATE UNIQUE INDEX IF NOT EXISTS labels_uri_val_neg ON labels (uri, val, neg);",
        )?;
        Ok(Self { conn: Mutex::new(conn) })
    }

    /// Add `neg` to a pre-existing `labels` table. This one cannot be a plain
    /// `ADD COLUMN`: the old table carries a `UNIQUE (uri, val)` *table*
    /// constraint, which SQLite cannot drop, and which would reject a
    /// negation of a label the same subject already carries. So rebuild the
    /// table, copying `seq` verbatim — those numbers are the firehose cursor
    /// and renumbering them would rewind or skip every live consumer.
    fn migrate_labels_neg(conn: &Connection) -> Result<()> {
        let has_neg = conn
            .prepare("SELECT 1 FROM pragma_table_info('labels') WHERE name = 'neg'")?
            .exists([])?;
        if has_neg {
            return Ok(());
        }
        conn.execute_batch(
            "BEGIN;
             CREATE TABLE labels_new (
                 seq  INTEGER PRIMARY KEY AUTOINCREMENT,
                 uri  TEXT NOT NULL,
                 val  TEXT NOT NULL,
                 cts  TEXT NOT NULL,
                 sig  BLOB NOT NULL,
                 neg  INTEGER NOT NULL DEFAULT 0
             );
             INSERT INTO labels_new (seq, uri, val, cts, sig, neg)
                 SELECT seq, uri, val, cts, sig, 0 FROM labels;
             DROP TABLE labels;
             ALTER TABLE labels_new RENAME TO labels;
             CREATE UNIQUE INDEX IF NOT EXISTS labels_uri_val_neg ON labels (uri, val, neg);
             COMMIT;",
        )?;
        tracing::info!("migrated labels table: added neg");
        Ok(())
    }

    // -- accounts ----------------------------------------------------------

    pub fn insert_account(&self, a: &Account) -> Result<()> {
        self.conn.lock().unwrap().execute(
            "INSERT INTO accounts (email, did, handle, access_jwt, refresh_jwt, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![a.email, a.did, a.handle, a.access_jwt, a.refresh_jwt, Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }

    pub fn account_by_email(&self, email: &str) -> Result<Option<Account>> {
        self.conn
            .lock()
            .unwrap()
            .query_row(
                "SELECT email, did, handle, access_jwt, refresh_jwt FROM accounts WHERE email = ?1",
                params![email],
                |r| {
                    Ok(Account {
                        email: r.get(0)?,
                        did: r.get(1)?,
                        handle: r.get(2)?,
                        access_jwt: r.get(3)?,
                        refresh_jwt: r.get(4)?,
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn account_by_did(&self, did: &str) -> Result<Option<Account>> {
        self.conn
            .lock()
            .unwrap()
            .query_row(
                "SELECT email, did, handle, access_jwt, refresh_jwt FROM accounts WHERE did = ?1",
                params![did],
                |r| {
                    Ok(Account {
                        email: r.get(0)?,
                        did: r.get(1)?,
                        handle: r.get(2)?,
                        access_jwt: r.get(3)?,
                        refresh_jwt: r.get(4)?,
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    /// Every account this bridge provisioned — the set whose repos are worth
    /// scanning for posts that still need a label.
    pub fn all_accounts(&self) -> Result<Vec<Account>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt =
            conn.prepare("SELECT email, did, handle, access_jwt, refresh_jwt FROM accounts")?;
        let rows = stmt.query_map([], |r| {
            Ok(Account {
                email: r.get(0)?,
                did: r.get(1)?,
                handle: r.get(2)?,
                access_jwt: r.get(3)?,
                refresh_jwt: r.get(4)?,
            })
        })?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    pub fn handle_taken(&self, handle: &str) -> Result<bool> {
        let n: i64 = self.conn.lock().unwrap().query_row(
            "SELECT COUNT(*) FROM accounts WHERE handle = ?1",
            params![handle],
            |r| r.get(0),
        )?;
        Ok(n > 0)
    }

    pub fn update_session(&self, did: &str, access_jwt: &str, refresh_jwt: &str) -> Result<()> {
        self.conn.lock().unwrap().execute(
            "UPDATE accounts SET access_jwt = ?2, refresh_jwt = ?3 WHERE did = ?1",
            params![did, access_jwt, refresh_jwt],
        )?;
        Ok(())
    }

    // -- tokens ------------------------------------------------------------

    fn hash(token: &str) -> String {
        URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes()))
    }

    /// Mint and persist a new bridge token; returns the bearer string.
    pub fn issue_token(&self, t: &BridgeToken) -> Result<String> {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        let token = format!("{TOKEN_PREFIX}{}", URL_SAFE_NO_PAD.encode(bytes));
        let (uri, idx) = match &t.warrant_status {
            Some((u, i)) => (Some(u.clone()), Some(*i as i64)),
            None => (None, None),
        };
        self.conn.lock().unwrap().execute(
            "INSERT INTO tokens (token_hash, did, grantor, grantee, holder, scopes,
                                 warrant_uri, warrant_idx, warrant_ref, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                Self::hash(&token),
                t.did,
                t.grantor,
                t.grantee,
                t.holder,
                serde_json::to_string(&t.scopes).map_err(|e| StoreError(e.to_string()))?,
                uri,
                idx,
                t.warrant_ref,
                t.expires_at.to_rfc3339(),
            ],
        )?;
        Ok(token)
    }

    /// Resolve a bearer token; `None` if unknown or expired.
    pub fn token(&self, bearer: &str) -> Result<Option<BridgeToken>> {
        let row = self
            .conn
            .lock()
            .unwrap()
            .query_row(
                "SELECT did, grantor, grantee, holder, scopes, warrant_uri, warrant_idx, warrant_ref, expires_at
                 FROM tokens WHERE token_hash = ?1",
                params![Self::hash(bearer)],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, String>(3)?,
                        r.get::<_, String>(4)?,
                        r.get::<_, Option<String>>(5)?,
                        r.get::<_, Option<i64>>(6)?,
                        r.get::<_, String>(7)?,
                        r.get::<_, String>(8)?,
                    ))
                },
            )
            .optional()?;
        let Some((did, grantor, grantee, holder, scopes, uri, idx, warrant_ref, exp)) = row else {
            return Ok(None);
        };
        let expires_at = DateTime::parse_from_rfc3339(&exp)
            .map_err(|e| StoreError(e.to_string()))?
            .with_timezone(&Utc);
        if expires_at < Utc::now() {
            return Ok(None);
        }
        Ok(Some(BridgeToken {
            did,
            grantor,
            grantee,
            holder,
            scopes: serde_json::from_str(&scopes).map_err(|e| StoreError(e.to_string()))?,
            warrant_status: uri.zip(idx).map(|(u, i)| (u, i as u64)),
            warrant_ref,
            expires_at,
        }))
    }

    // -- warrants ----------------------------------------------------------

    /// Persist the delegation artifacts (idempotent by hash). Called at token
    /// exchange so the post-time path can publish/reference the warrant record.
    pub fn upsert_warrant(&self, w: &StoredWarrant) -> Result<()> {
        self.conn.lock().unwrap().execute(
            "INSERT INTO warrants (hash, did, grantor, grantee, warrant_jws, config_cert_jws, record_uri)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL)
             ON CONFLICT(hash) DO NOTHING",
            params![w.hash, w.did, w.grantor, w.grantee, w.warrant_jws, w.config_cert_jws],
        )?;
        Ok(())
    }

    pub fn warrant_by_hash(&self, hash: &str) -> Result<Option<StoredWarrant>> {
        self.conn
            .lock()
            .unwrap()
            .query_row(
                "SELECT hash, did, grantor, grantee, warrant_jws, config_cert_jws, record_uri
                 FROM warrants WHERE hash = ?1",
                params![hash],
                |r| {
                    Ok(StoredWarrant {
                        hash: r.get(0)?,
                        did: r.get(1)?,
                        grantor: r.get(2)?,
                        grantee: r.get(3)?,
                        warrant_jws: r.get(4)?,
                        config_cert_jws: r.get(5)?,
                        record_uri: r.get(6)?,
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    /// Record the AT-URI of the published `me.browserid.warrant` record so
    /// later posts reference it instead of republishing.
    pub fn set_warrant_record_uri(&self, hash: &str, record_uri: &str) -> Result<()> {
        self.conn.lock().unwrap().execute(
            "UPDATE warrants SET record_uri = ?2 WHERE hash = ?1",
            params![hash, record_uri],
        )?;
        Ok(())
    }

    /// Drop every token bound to a warrant status ref (used when a re-check
    /// finds the warrant revoked).
    pub fn revoke_tokens_for_warrant(&self, uri: &str, idx: u64) -> Result<usize> {
        Ok(self.conn.lock().unwrap().execute(
            "DELETE FROM tokens WHERE warrant_uri = ?1 AND warrant_idx = ?2",
            params![uri, idx as i64],
        )?)
    }

    // -- nonces ------------------------------------------------------------
    // Map a per-post verification nonce to (did, post rkey) so the verifier
    // can resolve `verify?n=<nonce>` (the form an optional in-post link
    // uses). Phase 1: the bridge mints the nonce; phase 2 (bean n78o) the
    // agent chooses it as the signed attestation nonce.

    pub fn put_nonce(&self, nonce: &str, did: &str, rkey: &str) -> Result<()> {
        self.conn.lock().unwrap().execute(
            "INSERT INTO nonces (nonce, did, rkey) VALUES (?1, ?2, ?3)
             ON CONFLICT(nonce) DO NOTHING",
            params![nonce, did, rkey],
        )?;
        Ok(())
    }

    /// Claim a nonce before creating the post (phase-2 replay guard):
    /// inserts with an empty rkey placeholder. `Ok(false)` = already seen →
    /// the caller MUST reject (replay). Fill the rkey after the post is
    /// created with [`set_nonce_rkey`].
    pub fn reserve_nonce(&self, nonce: &str, did: &str) -> Result<bool> {
        let n = self.conn.lock().unwrap().execute(
            "INSERT INTO nonces (nonce, did, rkey) VALUES (?1, ?2, '')
             ON CONFLICT(nonce) DO NOTHING",
            params![nonce, did],
        )?;
        Ok(n == 1)
    }

    pub fn set_nonce_rkey(&self, nonce: &str, rkey: &str) -> Result<()> {
        self.conn.lock().unwrap().execute(
            "UPDATE nonces SET rkey = ?2 WHERE nonce = ?1",
            params![nonce, rkey],
        )?;
        Ok(())
    }

    /// Resolve a nonce to `(did, rkey)`.
    pub fn resolve_nonce(&self, nonce: &str) -> Result<Option<(String, String)>> {
        self.conn
            .lock()
            .unwrap()
            .query_row(
                "SELECT did, rkey FROM nonces WHERE nonce = ?1",
                params![nonce],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
            )
            .optional()
            .map_err(Into::into)
    }

    // -- labels ------------------------------------------------------------

    /// Record a signed label. The `seq` is the labeler firehose cursor, so
    /// labels must be stored exactly once and never renumbered — a consumer
    /// resuming at `cursor` expects everything above it, in order. Returns
    /// `None` if this (uri, val, neg) was already emitted — a label and its
    /// later negation are distinct rows, so retracting is always possible,
    /// but retracting twice is not.
    pub fn insert_label(
        &self,
        uri: &str,
        val: &str,
        cts: &str,
        neg: bool,
        sig: &[u8],
    ) -> Result<Option<EmittedLabel>> {
        let conn = self.conn.lock().unwrap();
        let changed = conn.execute(
            "INSERT OR IGNORE INTO labels (uri, val, cts, neg, sig) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![uri, val, cts, neg as i64, sig],
        )?;
        if changed == 0 {
            return Ok(None);
        }
        Ok(Some(EmittedLabel {
            seq: conn.last_insert_rowid(),
            uri: uri.to_string(),
            val: val.to_string(),
            cts: cts.to_string(),
            neg,
            sig: sig.to_vec(),
        }))
    }

    /// Every label emitted on a subject, negations included.
    pub fn labels_for(&self, uri: &str) -> Result<Vec<EmittedLabel>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt =
            conn.prepare("SELECT seq, uri, val, cts, neg, sig FROM labels WHERE uri = ?1 ORDER BY seq")?;
        let rows = stmt.query_map(params![uri], |r| {
            Ok(EmittedLabel {
                seq: r.get(0)?,
                uri: r.get(1)?,
                val: r.get(2)?,
                cts: r.get(3)?,
                neg: r.get::<_, i64>(4)? != 0,
                sig: r.get(5)?,
            })
        })?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// Labels with `seq > cursor`, oldest first — the firehose backfill.
    pub fn labels_since(&self, cursor: i64, limit: i64) -> Result<Vec<EmittedLabel>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT seq, uri, val, cts, neg, sig FROM labels WHERE seq > ?1 ORDER BY seq ASC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![cursor, limit], |r| {
            Ok(EmittedLabel {
                seq: r.get(0)?,
                uri: r.get(1)?,
                val: r.get(2)?,
                cts: r.get(3)?,
                neg: r.get::<_, i64>(4)? != 0,
                sig: r.get(5)?,
            })
        })?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    // -- label definitions -------------------------------------------------
    // Which per-pair label values have been declared in the labeler account's
    // `app.bsky.labeler.service` record. Claiming a val here is what keeps
    // two concurrent posts from both read-modify-writing the record; the
    // claim is released again if the write fails, so it is retried.

    /// Claim `val` for definition. `Ok(true)` = this caller should write the
    /// service record; `Ok(false)` = someone already did (or is doing it).
    pub fn claim_label_def(&self, val: &str, grantor: &str, grantee: &str) -> Result<bool> {
        let n = self.conn.lock().unwrap().execute(
            "INSERT INTO label_defs (val, defined_at, grantor, grantee) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(val) DO NOTHING",
            params![val, Utc::now().to_rfc3339(), grantor, grantee],
        )?;
        Ok(n == 1)
    }

    /// Remember which identities a val stands for, even when the definition
    /// itself was claimed earlier (rows written before this column existed
    /// have no identities). This is what lets the emit path re-derive a
    /// stored val's classification without touching the network.
    pub fn record_label_pair(&self, val: &str, grantor: &str, grantee: &str) -> Result<()> {
        self.conn.lock().unwrap().execute(
            "INSERT INTO label_defs (val, defined_at, grantor, grantee) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(val) DO UPDATE SET grantor = ?3, grantee = ?4",
            params![val, Utc::now().to_rfc3339(), grantor, grantee],
        )?;
        Ok(())
    }

    /// The identities behind a pair val, if known.
    pub fn label_def_pair(&self, val: &str) -> Result<Option<(String, String)>> {
        self.conn
            .lock()
            .unwrap()
            .query_row(
                "SELECT grantor, grantee FROM label_defs
                 WHERE val = ?1 AND grantor IS NOT NULL AND grantee IS NOT NULL",
                params![val],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(Into::into)
    }

    /// Release a claim whose record write failed, so a later post retries it.
    pub fn release_label_def(&self, val: &str) -> Result<()> {
        self.conn
            .lock()
            .unwrap()
            .execute("DELETE FROM label_defs WHERE val = ?1", params![val])?;
        Ok(())
    }

    // -- audit -------------------------------------------------------------

    pub fn audit(&self, t: &BridgeToken, nsid: &str, outcome: &str) -> Result<()> {
        self.conn.lock().unwrap().execute(
            "INSERT INTO audit_log (at, did, grantor, grantee, holder, nsid, outcome)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![Utc::now().to_rfc3339(), t.did, t.grantor, t.grantee, t.holder, nsid, outcome],
        )?;
        Ok(())
    }

    // -- IdP: DID pins -----------------------------------------------------
    // The identity anchor for `<handle>@bsky.browserid.me`. Policy lives in
    // `idp::pins`; this is storage only.

    pub fn idp_pin(&self, handle: &str) -> Result<Option<HandlePin>> {
        self.conn
            .lock()
            .unwrap()
            .query_row(
                "SELECT handle, did, first_claimed, last_verified, suspended
                 FROM idp_pins WHERE handle = ?1",
                params![handle],
                |r| {
                    Ok(HandlePin {
                        handle: r.get(0)?,
                        did: r.get(1)?,
                        first_claimed: parse_time(&r.get::<_, String>(2)?),
                        last_verified: parse_time(&r.get::<_, String>(3)?),
                        suspended: r.get::<_, i64>(4)? != 0,
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    /// Bind `handle` to `did`, clearing any suspension. Re-binding preserves
    /// `first_claimed` only when the DID is unchanged — a reassignment is a
    /// new identity's tenure, and dating it from the old owner's first claim
    /// would misreport how long this account has held the handle.
    pub fn idp_upsert_pin(&self, handle: &str, did: &str, now: DateTime<Utc>) -> Result<()> {
        let now = now.to_rfc3339();
        self.conn.lock().unwrap().execute(
            "INSERT INTO idp_pins (handle, did, first_claimed, last_verified, suspended)
             VALUES (?1, ?2, ?3, ?3, 0)
             ON CONFLICT(handle) DO UPDATE SET
                 did = excluded.did,
                 first_claimed = CASE WHEN idp_pins.did = excluded.did
                                      THEN idp_pins.first_claimed ELSE excluded.first_claimed END,
                 last_verified = excluded.last_verified,
                 suspended = 0",
            params![handle, did, now],
        )?;
        Ok(())
    }

    pub fn idp_touch_pin(&self, handle: &str) -> Result<()> {
        self.conn.lock().unwrap().execute(
            "UPDATE idp_pins SET last_verified = ?2 WHERE handle = ?1",
            params![handle, Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }

    pub fn idp_set_pin_suspended(&self, handle: &str, suspended: bool) -> Result<()> {
        self.conn.lock().unwrap().execute(
            "UPDATE idp_pins SET suspended = ?2 WHERE handle = ?1",
            params![handle, i64::from(suspended)],
        )?;
        Ok(())
    }

    pub fn idp_delete_pin(&self, handle: &str) -> Result<()> {
        self.conn
            .lock()
            .unwrap()
            .execute("DELETE FROM idp_pins WHERE handle = ?1", params![handle])?;
        Ok(())
    }

    /// Every handle currently pinned to `did` — the voluntary-retirement
    /// path's working set.
    pub fn idp_pins_for_did(&self, did: &str) -> Result<Vec<String>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT handle FROM idp_pins WHERE did = ?1 ORDER BY handle")?;
        let rows = stmt.query_map(params![did], |r| r.get::<_, String>(0))?;
        rows.collect::<std::result::Result<Vec<_>, _>>().map_err(Into::into)
    }

    /// Record (idempotently) that `did` tried to claim `handle`, and return
    /// when it *first* tried. That timestamp is the seasoning clock, so the
    /// insert must never overwrite an earlier one.
    pub fn idp_note_reassignment_attempt(
        &self,
        handle: &str,
        did: &str,
        now: DateTime<Utc>,
    ) -> Result<DateTime<Utc>> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO idp_reassignment_attempts (handle, did, first_seen) VALUES (?1, ?2, ?3)
             ON CONFLICT(handle, did) DO NOTHING",
            params![handle, did, now.to_rfc3339()],
        )?;
        let seen: String = conn.query_row(
            "SELECT first_seen FROM idp_reassignment_attempts WHERE handle = ?1 AND did = ?2",
            params![handle, did],
            |r| r.get(0),
        )?;
        Ok(parse_time(&seen))
    }

    pub fn idp_clear_reassignment_attempts(&self, handle: &str) -> Result<()> {
        self.conn.lock().unwrap().execute(
            "DELETE FROM idp_reassignment_attempts WHERE handle = ?1",
            params![handle],
        )?;
        Ok(())
    }

    /// Move an attempt's clock back, so a test can exercise the 30-day
    /// seasoning path without waiting 30 days.
    #[cfg(test)]
    pub fn idp_backdate_reassignment_attempt(
        &self,
        handle: &str,
        did: &str,
        when: DateTime<Utc>,
    ) -> Result<()> {
        self.conn.lock().unwrap().execute(
            "UPDATE idp_reassignment_attempts SET first_seen = ?3 WHERE handle = ?1 AND did = ?2",
            params![handle, did, when.to_rfc3339()],
        )?;
        Ok(())
    }

    // -- IdP: status list --------------------------------------------------

    /// This identity's status-list index, allocated on first use and reused
    /// for every cert it ever gets — device, config, access, and every
    /// renewal of each.
    ///
    /// One index per *identity*, not per cert, for two reasons. It bounds
    /// the list: access certs are minted daily, per RP, per device, so a
    /// per-cert index let any client inflate a bitmap that is re-signed on
    /// every `/.well-known/browserid-status` fetch, forever. And it is the
    /// revocation granularity we actually want — suspending a binding must
    /// kill all of that identity's certs at once, which one shared bit does
    /// by construction. `<handle>+tag` agents are separate identities and so
    /// keep separate bits, staying independently revocable while
    /// [`Self::idp_revoke_status_for_handle`] still sweeps them all.
    ///
    /// Backward-safe on an existing database: rows from the per-cert era
    /// simply collapse onto the lowest index an identity already holds, and
    /// nothing renumbers.
    pub fn idp_status_idx(&self, identity: &str) -> Result<u64> {
        let conn = self.conn.lock().unwrap();
        let existing: Option<i64> = conn
            .query_row(
                "SELECT MIN(idx) FROM idp_status WHERE identity = ?1",
                params![identity],
                |r| r.get(0),
            )
            .optional()?
            .flatten();
        if let Some(idx) = existing {
            return Ok(idx as u64);
        }
        conn.execute(
            "INSERT INTO idp_status (identity, issued_at) VALUES (?1, ?2)",
            params![identity, Utc::now().to_rfc3339()],
        )?;
        Ok(conn.last_insert_rowid() as u64)
    }

    /// Revoke every cert issued for `handle` — the identity itself and all
    /// its `+tag` agent sub-identities, which is the whole point: suspending
    /// a person's handle must not leave their agents able to act.
    pub fn idp_revoke_status_for_handle(&self, handle: &str) -> Result<usize> {
        let n = self.conn.lock().unwrap().execute(
            "UPDATE idp_status SET revoked = 1
             WHERE revoked = 0 AND (identity LIKE ?1 || '@%' OR identity LIKE ?1 || '+%')",
            params![handle],
        )?;
        if n > 0 {
            tracing::info!(%handle, revoked = n, "revoked issued certs via the IdP status list");
        }
        Ok(n)
    }

    /// The revoked indices and the highest index ever allocated — the two
    /// inputs to a `StatusList`.
    pub fn idp_revoked_status_indices(&self) -> Result<(Vec<u64>, u64)> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT idx FROM idp_status WHERE revoked = 1")?;
        let revoked = stmt
            .query_map([], |r| r.get::<_, i64>(0).map(|i| i as u64))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let max: i64 =
            conn.query_row("SELECT COALESCE(MAX(idx), 0) FROM idp_status", [], |r| r.get(0))?;
        Ok((revoked, max as u64))
    }

    // -- IdP: first-party sessions ----------------------------------------
    // Our own cookie, not an atproto session: it holds a handle and a DID
    // and no token material whatsoever.

    pub fn idp_create_session(
        &self,
        handle: Option<&str>,
        did: &str,
        ttl_hours: i64,
    ) -> Result<String> {
        let sid = random_token();
        self.conn.lock().unwrap().execute(
            "INSERT INTO idp_sessions (sid, handle, did, expires_at) VALUES (?1, ?2, ?3, ?4)",
            params![
                sid,
                handle,
                did,
                (Utc::now() + chrono::Duration::hours(ttl_hours)).to_rfc3339()
            ],
        )?;
        Ok(sid)
    }

    /// The live session behind a cookie, or `None` if it is unknown or
    /// expired.
    pub fn idp_session(&self, sid: &str) -> Result<Option<IdpSession>> {
        let session = self
            .conn
            .lock()
            .unwrap()
            .query_row(
                "SELECT handle, did, expires_at FROM idp_sessions WHERE sid = ?1",
                params![sid],
                |r| {
                    Ok(IdpSession {
                        handle: r.get(0)?,
                        did: r.get(1)?,
                        expires_at: parse_time(&r.get::<_, String>(2)?),
                    })
                },
            )
            .optional()?;
        Ok(session.filter(|s| s.expires_at > Utc::now()))
    }

    pub fn idp_delete_session(&self, sid: &str) -> Result<()> {
        self.conn
            .lock()
            .unwrap()
            .execute("DELETE FROM idp_sessions WHERE sid = ?1", params![sid])?;
        Ok(())
    }

    // -- IdP: pending OAuth flows -----------------------------------------

    pub fn idp_put_oauth_flow(&self, f: &PendingOauthFlow) -> Result<()> {
        self.conn.lock().unwrap().execute(
            "INSERT INTO idp_oauth_flows
                 (state, handle, did, issuer, token_endpoint, code_verifier, dpop_secret,
                  retire, browser_binding, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                f.state,
                f.handle,
                f.did,
                f.issuer,
                f.token_endpoint,
                f.code_verifier,
                f.dpop_secret,
                i64::from(f.retire),
                f.browser_binding,
                f.expires_at.to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    /// Consume a pending flow: read it and delete it in one shot, so a
    /// replayed `state` finds nothing. Expired rows are dropped too.
    pub fn idp_take_oauth_flow(&self, state: &str) -> Result<Option<PendingOauthFlow>> {
        let conn = self.conn.lock().unwrap();
        let flow = conn
            .query_row(
                "SELECT state, handle, did, issuer, token_endpoint, code_verifier, dpop_secret,
                        retire, browser_binding, expires_at
                 FROM idp_oauth_flows WHERE state = ?1",
                params![state],
                |r| {
                    Ok(PendingOauthFlow {
                        state: r.get(0)?,
                        handle: r.get(1)?,
                        did: r.get(2)?,
                        issuer: r.get(3)?,
                        token_endpoint: r.get(4)?,
                        code_verifier: r.get(5)?,
                        dpop_secret: r.get(6)?,
                        retire: r.get::<_, i64>(7)? != 0,
                        browser_binding: r.get(8)?,
                        expires_at: parse_time(&r.get::<_, String>(9)?),
                    })
                },
            )
            .optional()?;
        conn.execute("DELETE FROM idp_oauth_flows WHERE state = ?1", params![state])?;
        conn.execute(
            "DELETE FROM idp_oauth_flows WHERE expires_at < ?1",
            params![Utc::now().to_rfc3339()],
        )?;
        Ok(flow.filter(|f| f.expires_at > Utc::now()))
    }

    // -- write relay: pending connect flows --------------------------------

    pub fn write_put_oauth_flow(&self, f: &PendingWriteFlow) -> Result<()> {
        self.conn.lock().unwrap().execute(
            "INSERT INTO write_oauth_flows
                 (state, handle, did, pds, issuer, token_endpoint, code_verifier, dpop_secret,
                  browser_binding, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                f.state,
                f.handle,
                f.did,
                f.pds,
                f.issuer,
                f.token_endpoint,
                f.code_verifier,
                f.dpop_secret,
                f.browser_binding,
                f.expires_at.to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    /// Consume a pending connect flow — read and delete in one shot, so a
    /// replayed `state` finds nothing.
    pub fn write_take_oauth_flow(&self, state: &str) -> Result<Option<PendingWriteFlow>> {
        let conn = self.conn.lock().unwrap();
        let flow = conn
            .query_row(
                "SELECT state, handle, did, pds, issuer, token_endpoint, code_verifier,
                        dpop_secret, browser_binding, expires_at
                 FROM write_oauth_flows WHERE state = ?1",
                params![state],
                |r| {
                    Ok(PendingWriteFlow {
                        state: r.get(0)?,
                        handle: r.get(1)?,
                        did: r.get(2)?,
                        pds: r.get(3)?,
                        issuer: r.get(4)?,
                        token_endpoint: r.get(5)?,
                        code_verifier: r.get(6)?,
                        dpop_secret: r.get(7)?,
                        browser_binding: r.get(8)?,
                        expires_at: parse_time(&r.get::<_, String>(9)?),
                    })
                },
            )
            .optional()?;
        conn.execute("DELETE FROM write_oauth_flows WHERE state = ?1", params![state])?;
        conn.execute(
            "DELETE FROM write_oauth_flows WHERE expires_at < ?1",
            params![Utc::now().to_rfc3339()],
        )?;
        Ok(flow.filter(|f| f.expires_at > Utc::now()))
    }

    // -- write relay: sessions ---------------------------------------------
    //
    // Every accessor that touches `access_enc` / `refresh_enc` /
    // `dpop_secret_enc` takes the AEAD key. That is not decoration: it is
    // what makes "the table does not exist before the key does" (design doc,
    // Decision 4) a property of the type system rather than a promise. A
    // deployment with no key configured has no `SecretBox`, and therefore no
    // way to call any of these.

    pub fn write_session_put(&self, key: &SecretBox, s: &WriteSession) -> Result<()> {
        self.conn.lock().unwrap().execute(
            "INSERT INTO write_sessions
                 (did, handle, identity, pds, issuer, token_endpoint, access_enc, refresh_enc,
                  dpop_secret_enc, dpop_nonce, scope, access_expires_at, created_at,
                  last_refresh, state)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, NULL, ?10, ?11, ?12, ?12, 'live')
             ON CONFLICT(did) DO UPDATE SET
                 handle = excluded.handle,
                 identity = excluded.identity,
                 pds = excluded.pds,
                 issuer = excluded.issuer,
                 token_endpoint = excluded.token_endpoint,
                 access_enc = excluded.access_enc,
                 refresh_enc = excluded.refresh_enc,
                 dpop_secret_enc = excluded.dpop_secret_enc,
                 dpop_nonce = NULL,
                 scope = excluded.scope,
                 access_expires_at = excluded.access_expires_at,
                 last_refresh = excluded.last_refresh,
                 state = 'live'",
            params![
                s.did,
                s.handle,
                s.identity,
                s.pds,
                s.issuer,
                s.token_endpoint,
                key.seal_str(&s.did, "access_token", &s.access_token),
                key.seal_str(&s.did, "refresh_token", &s.refresh_token),
                key.seal_str(&s.did, "dpop_secret", &s.dpop_secret),
                s.scope,
                s.access_expires_at.to_rfc3339(),
                Utc::now().to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    /// The stored session for `did`, decrypted. A row whose secrets will not
    /// open (a rotated AEAD key, a tampered file) is reported as an error
    /// rather than as "no session" — a silent fallback to the bridge-account
    /// backend would post somewhere the human did not expect.
    pub fn write_session(&self, key: &SecretBox, did: &str) -> Result<Option<WriteSession>> {
        let row = self
            .conn
            .lock()
            .unwrap()
            .query_row(
                "SELECT did, handle, identity, pds, issuer, token_endpoint, access_enc,
                        refresh_enc, dpop_secret_enc, dpop_nonce, scope, access_expires_at,
                        created_at, state
                 FROM write_sessions WHERE did = ?1",
                params![did],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, String>(3)?,
                        r.get::<_, String>(4)?,
                        r.get::<_, String>(5)?,
                        r.get::<_, Vec<u8>>(6)?,
                        r.get::<_, Vec<u8>>(7)?,
                        r.get::<_, Vec<u8>>(8)?,
                        r.get::<_, Option<String>>(9)?,
                        r.get::<_, String>(10)?,
                        r.get::<_, String>(11)?,
                        r.get::<_, String>(12)?,
                        r.get::<_, String>(13)?,
                    ))
                },
            )
            .optional()?;
        let Some((
            did,
            handle,
            identity,
            pds,
            issuer,
            token_endpoint,
            acc,
            refr,
            dpop,
            dpop_nonce,
            scope,
            expires,
            created,
            state,
        )) = row
        else {
            return Ok(None);
        };
        let open = |column: &str, blob: &[u8]| {
            key.open_str(&did, column, blob).map_err(|e| StoreError(e.to_string()))
        };
        Ok(Some(WriteSession {
            access_token: open("access_token", &acc)?,
            refresh_token: open("refresh_token", &refr)?,
            dpop_secret: open("dpop_secret", &dpop)?,
            did,
            handle,
            identity,
            pds,
            issuer,
            token_endpoint,
            dpop_nonce,
            scope,
            access_expires_at: parse_time(&expires),
            created_at: parse_time(&created),
            state: WriteSessionState::parse(&state),
        }))
    }

    /// Store a rotated token pair. Called under the per-DID refresh lock, so
    /// the read-modify-write around it is serialized; this statement is the
    /// point at which the new refresh token becomes the one of record.
    pub fn write_session_rotate(
        &self,
        key: &SecretBox,
        did: &str,
        access_token: &str,
        refresh_token: &str,
        access_expires_at: DateTime<Utc>,
    ) -> Result<()> {
        let n = self.conn.lock().unwrap().execute(
            "UPDATE write_sessions
                SET access_enc = ?2, refresh_enc = ?3, access_expires_at = ?4,
                    last_refresh = ?5, state = 'live'
              WHERE did = ?1",
            params![
                did,
                key.seal_str(did, "access_token", access_token),
                key.seal_str(did, "refresh_token", refresh_token),
                access_expires_at.to_rfc3339(),
                Utc::now().to_rfc3339(),
            ],
        )?;
        if n == 0 {
            return Err(StoreError(format!("no write session for {did} to rotate")));
        }
        Ok(())
    }

    /// Remember the resource server's latest `DPoP-Nonce`, so a restart does
    /// not cost every session an extra round trip.
    pub fn write_session_set_nonce(&self, did: &str, nonce: &str) -> Result<()> {
        self.conn.lock().unwrap().execute(
            "UPDATE write_sessions SET dpop_nonce = ?2 WHERE did = ?1",
            params![did, nonce],
        )?;
        Ok(())
    }

    pub fn write_session_set_state(&self, did: &str, state: WriteSessionState) -> Result<()> {
        self.conn.lock().unwrap().execute(
            "UPDATE write_sessions SET state = ?2 WHERE did = ?1",
            params![did, state.as_str()],
        )?;
        Ok(())
    }

    /// Drop the write session for a handle whose identity binding just died.
    ///
    /// Called wherever [`Self::idp_revoke_status_for_handle`] is: a suspended
    /// or retired binding must not leave a live write token behind, or the
    /// bridge would still be able to post as an identity it no longer
    /// certifies. Deleting rather than disabling (design doc open question 5)
    /// — the recoverable case is a reconnect, which is cheap, and the
    /// unrecoverable case is a stranger's credentials sitting in our database.
    pub fn write_session_delete_for_handle(&self, handle: &str) -> Result<usize> {
        let n = self
            .conn
            .lock()
            .unwrap()
            .execute("DELETE FROM write_sessions WHERE handle = ?1", params![handle])?;
        if n > 0 {
            tracing::info!(%handle, "handle binding ended — deleted its write-relay session");
        }
        Ok(n)
    }

    pub fn write_session_delete(&self, did: &str) -> Result<()> {
        self.conn
            .lock()
            .unwrap()
            .execute("DELETE FROM write_sessions WHERE did = ?1", params![did])?;
        Ok(())
    }

    /// Does a write session exist for this DID at all? Answers without the
    /// AEAD key, so the post path can pick a backend before decrypting.
    pub fn write_session_exists(&self, did: &str) -> Result<bool> {
        let n: i64 = self.conn.lock().unwrap().query_row(
            "SELECT COUNT(*) FROM write_sessions WHERE did = ?1",
            params![did],
            |r| r.get(0),
        )?;
        Ok(n > 0)
    }

    /// The raw secret columns exactly as they sit on disk — so a test can
    /// assert that what a stolen database file yields is ciphertext.
    #[cfg(test)]
    pub fn write_session_raw_secrets(&self, did: &str) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
        Ok(self.conn.lock().unwrap().query_row(
            "SELECT access_enc, refresh_enc, dpop_secret_enc FROM write_sessions WHERE did = ?1",
            params![did],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?)
    }
}

/// Parse an RFC 3339 timestamp written by this module. A malformed value
/// means the row was corrupted; treat it as epoch, which fails every
/// freshness check rather than passing one.
fn parse_time(s: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(s).map(|t| t.with_timezone(&Utc)).unwrap_or_else(|_| {
        tracing::warn!(value = %s, "unparseable timestamp in the store");
        DateTime::UNIX_EPOCH
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn token(exp_mins: i64) -> BridgeToken {
        BridgeToken {
            did: "did:plc:xyz".into(),
            grantor: "dan@sandmill.org".into(),
            grantee: "dan+agent@sandmill.org".into(),
            holder: "svc.agent".into(),
            scopes: vec!["repo:app.bsky.feed.post?action=create".into()],
            warrant_status: Some(("https://browserid.me/.well-known/browserid-status".into(), 42)),
            warrant_ref: "wh_test".into(),
            expires_at: Utc::now() + Duration::minutes(exp_mins),
        }
    }

    #[test]
    fn account_roundtrip_and_handle_uniqueness() {
        let s = Store::open_in_memory().unwrap();
        s.insert_account(&Account {
            email: "dan@sandmill.org".into(),
            did: "did:plc:xyz".into(),
            handle: "dan.at.browserid.me".into(),
            access_jwt: "a1".into(),
            refresh_jwt: "r1".into(),
        })
        .unwrap();
        let a = s.account_by_email("dan@sandmill.org").unwrap().unwrap();
        assert_eq!(a.did, "did:plc:xyz");
        assert!(s.handle_taken("dan.at.browserid.me").unwrap());
        assert!(!s.handle_taken("other.at.browserid.me").unwrap());
        assert!(s.account_by_email("nobody@example.com").unwrap().is_none());

        s.update_session("did:plc:xyz", "a2", "r2").unwrap();
        assert_eq!(s.account_by_email("dan@sandmill.org").unwrap().unwrap().access_jwt, "a2");
    }

    /// Only the first claimant writes the service record; a failed write
    /// releases the claim so a later post retries it.
    #[test]
    fn label_def_claim_is_exclusive_and_releasable() {
        let s = Store::open_in_memory().unwrap();
        let (g, e) = ("dan@sandmill.org", "dan+fable@sandmill.org");
        assert!(s.claim_label_def("by-agent-deadbeef", g, e).unwrap());
        assert!(!s.claim_label_def("by-agent-deadbeef", g, e).unwrap());
        assert!(s.claim_label_def("by-owner-deadbeef", g, g).unwrap(), "distinct val, own claim");

        s.release_label_def("by-agent-deadbeef").unwrap();
        assert!(s.claim_label_def("by-agent-deadbeef", g, e).unwrap(), "retried after a failed write");

        // The identities behind a val are what the emit path re-classifies
        // from, so they must survive the claim and be fillable after it.
        assert_eq!(s.label_def_pair("by-agent-deadbeef").unwrap(), Some((g.into(), e.into())));
        assert_eq!(s.label_def_pair("by-owner-nosuch").unwrap(), None);
        s.record_label_pair("by-owner-deadbeef", g, g).unwrap();
        assert_eq!(s.label_def_pair("by-owner-deadbeef").unwrap(), Some((g.into(), g.into())));
    }

    /// A label and its negation coexist as separate rows with separate seqs
    /// (the stream is append-only), but neither can be emitted twice.
    #[test]
    fn a_label_can_be_negated_but_not_twice() {
        let s = Store::open_in_memory().unwrap();
        let uri = "at://did:plc:xyz/app.bsky.feed.post/abc";

        let first = s.insert_label(uri, "by-owner-dead", "t1", false, b"sig1").unwrap().unwrap();
        assert!(!first.neg);
        assert!(s.insert_label(uri, "by-owner-dead", "t1", false, b"sig1").unwrap().is_none());

        let neg = s.insert_label(uri, "by-owner-dead", "t2", true, b"sig2").unwrap().unwrap();
        assert!(neg.neg && neg.seq > first.seq, "a retraction is a later event");
        assert!(s.insert_label(uri, "by-owner-dead", "t3", true, b"sig3").unwrap().is_none());

        let all = s.labels_for(uri).unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all.iter().filter(|l| l.neg).count(), 1);
        // The firehose replays both, in order, with neg intact.
        let since = s.labels_since(first.seq - 1, 10).unwrap();
        assert_eq!(since.iter().map(|l| l.neg).collect::<Vec<_>>(), [false, true]);
    }

    /// The pre-`neg` schema had a `UNIQUE (uri, val)` table constraint that
    /// would reject any negation. Opening such a DB must rebuild the table,
    /// keeping every `seq` — they are live consumer cursors.
    #[test]
    fn opening_a_pre_neg_database_migrates_it_without_renumbering() {
        let dir = std::env::temp_dir().join(format!("pds-bridge-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("labels-migration.db");
        let _ = std::fs::remove_file(&path);

        let old = Connection::open(&path).unwrap();
        old.execute_batch(
            "CREATE TABLE labels (
                 seq  INTEGER PRIMARY KEY AUTOINCREMENT,
                 uri  TEXT NOT NULL,
                 val  TEXT NOT NULL,
                 cts  TEXT NOT NULL,
                 sig  BLOB NOT NULL,
                 UNIQUE (uri, val)
             );
             INSERT INTO labels (seq, uri, val, cts, sig)
                 VALUES (41, 'at://a/p/1', 'browserid-verified', 't', x'00'),
                        (42, 'at://a/p/1', 'by-owner-dead', 't', x'01');",
        )
        .unwrap();
        drop(old);

        let s = Store::open(&path).unwrap();
        let all = s.labels_for("at://a/p/1").unwrap();
        assert_eq!(all.iter().map(|l| l.seq).collect::<Vec<_>>(), [41, 42], "cursors preserved");
        assert!(all.iter().all(|l| !l.neg), "existing labels are not negations");

        // The whole point: the old unique constraint no longer blocks this.
        let neg = s.insert_label("at://a/p/1", "by-owner-dead", "t2", true, b"s").unwrap();
        assert!(neg.is_some());
        assert!(neg.unwrap().seq > 42, "new rows continue the sequence");

        // Re-opening is a no-op, not a second rebuild.
        drop(s);
        let s = Store::open(&path).unwrap();
        assert_eq!(s.labels_for("at://a/p/1").unwrap().len(), 3);
        let _ = std::fs::remove_file(&path);
    }

    // -- write relay -------------------------------------------------------

    fn secrets() -> SecretBox {
        SecretBox::from_key_bytes(&[3u8; 32]).unwrap()
    }

    fn write_session(did: &str) -> WriteSession {
        WriteSession {
            did: did.into(),
            handle: "dan.bsky.social".into(),
            identity: "dan.bsky.social@bsky.browserid.test".into(),
            pds: "https://shard.example".into(),
            issuer: "https://bsky.social".into(),
            token_endpoint: "https://bsky.social/oauth/token".into(),
            access_token: "ACCESS-TOKEN-PLAINTEXT".into(),
            refresh_token: "REFRESH-TOKEN-PLAINTEXT".into(),
            dpop_secret: "DPOP-SECRET-PLAINTEXT".into(),
            dpop_nonce: None,
            scope: "atproto transition:generic".into(),
            access_expires_at: Utc::now() + Duration::hours(1),
            created_at: Utc::now(),
            state: WriteSessionState::Live,
        }
    }

    #[test]
    fn a_write_session_round_trips_through_the_aead() {
        let s = Store::open_in_memory().unwrap();
        let k = secrets();
        s.write_session_put(&k, &write_session("did:plc:abc")).unwrap();

        let got = s.write_session(&k, "did:plc:abc").unwrap().unwrap();
        assert_eq!(got.access_token, "ACCESS-TOKEN-PLAINTEXT");
        assert_eq!(got.refresh_token, "REFRESH-TOKEN-PLAINTEXT");
        assert_eq!(got.dpop_secret, "DPOP-SECRET-PLAINTEXT");
        assert_eq!(got.pds, "https://shard.example");
        assert_eq!(got.state, WriteSessionState::Live);
        assert!(s.write_session_exists("did:plc:abc").unwrap());
        assert!(s.write_session(&k, "did:plc:nobody").unwrap().is_none());

        // Rotation replaces the pair and can be read back under the same key.
        let later = Utc::now() + Duration::hours(2);
        s.write_session_rotate(&k, "did:plc:abc", "ACC-2", "REF-2", later).unwrap();
        let got = s.write_session(&k, "did:plc:abc").unwrap().unwrap();
        assert_eq!((got.access_token.as_str(), got.refresh_token.as_str()), ("ACC-2", "REF-2"));
        // Rotating a session that is not there is an error, not a silent
        // insert — that would resurrect a session the user disconnected.
        assert!(s.write_session_rotate(&k, "did:plc:ghost", "a", "r", later).is_err());
    }

    /// What a stolen database file yields. The three secret columns must be
    /// ciphertext on disk — this is the whole justification for the AEAD, so
    /// it is asserted against the bytes rusqlite actually stored, not
    /// against the struct.
    #[test]
    fn the_secret_columns_are_never_plaintext_on_disk() {
        let s = Store::open_in_memory().unwrap();
        let k = secrets();
        s.write_session_put(&k, &write_session("did:plc:abc")).unwrap();

        let (acc, refr, dpop) = s.write_session_raw_secrets("did:plc:abc").unwrap();
        for (name, blob, plain) in [
            ("access_enc", &acc, "ACCESS-TOKEN-PLAINTEXT"),
            ("refresh_enc", &refr, "REFRESH-TOKEN-PLAINTEXT"),
            ("dpop_secret_enc", &dpop, "DPOP-SECRET-PLAINTEXT"),
        ] {
            assert!(
                !blob.windows(plain.len()).any(|w| w == plain.as_bytes()),
                "{name} holds the plaintext"
            );
            assert!(blob.len() > 24, "{name} carries a nonce and a tag");
        }
        assert_ne!(acc, refr, "distinct nonces per column");

        // And the wrong key gets nothing back — not even a partial read.
        let wrong = SecretBox::from_key_bytes(&[4u8; 32]).unwrap();
        assert!(s.write_session(&wrong, "did:plc:abc").is_err());
    }

    /// The hazard the design calls out: a handle whose binding is suspended
    /// or retired must not leave live posting credentials behind, or the
    /// bridge could still post as an identity it no longer certifies.
    #[test]
    fn a_write_session_is_swept_when_its_handle_binding_ends() {
        let s = Store::open_in_memory().unwrap();
        let k = secrets();
        s.write_session_put(&k, &write_session("did:plc:abc")).unwrap();

        assert_eq!(s.write_session_delete_for_handle("someone.else").unwrap(), 0);
        assert!(s.write_session_exists("did:plc:abc").unwrap());

        assert_eq!(s.write_session_delete_for_handle("dan.bsky.social").unwrap(), 1);
        assert!(!s.write_session_exists("did:plc:abc").unwrap());
        assert!(s.write_session(&k, "did:plc:abc").unwrap().is_none());
    }

    /// A dead session must not read as "no session" — the post path treats
    /// those differently, and a silent fallback would post to the wrong repo.
    #[test]
    fn a_dead_session_still_reads_back_with_its_state() {
        let s = Store::open_in_memory().unwrap();
        let k = secrets();
        s.write_session_put(&k, &write_session("did:plc:abc")).unwrap();
        s.write_session_set_state("did:plc:abc", WriteSessionState::Revoked).unwrap();
        assert_eq!(s.write_session(&k, "did:plc:abc").unwrap().unwrap().state, WriteSessionState::Revoked);
        assert!(s.write_session_exists("did:plc:abc").unwrap());

        // Reconnecting clears it back to live.
        s.write_session_put(&k, &write_session("did:plc:abc")).unwrap();
        assert_eq!(s.write_session(&k, "did:plc:abc").unwrap().unwrap().state, WriteSessionState::Live);
    }

    #[test]
    fn a_connect_flow_is_single_use_and_expires() {
        let s = Store::open_in_memory().unwrap();
        let flow = |state: &str, mins: i64| PendingWriteFlow {
            state: state.into(),
            handle: "dan.bsky.social".into(),
            did: "did:plc:abc".into(),
            pds: "https://shard.example".into(),
            issuer: "https://bsky.social".into(),
            token_endpoint: "https://bsky.social/oauth/token".into(),
            code_verifier: "v".into(),
            dpop_secret: "s".into(),
            browser_binding: "b".into(),
            expires_at: Utc::now() + Duration::minutes(mins),
        };
        s.write_put_oauth_flow(&flow("st-1", 15)).unwrap();
        assert_eq!(s.write_take_oauth_flow("st-1").unwrap().unwrap().did, "did:plc:abc");
        assert!(s.write_take_oauth_flow("st-1").unwrap().is_none(), "replayed state finds nothing");

        s.write_put_oauth_flow(&flow("old", -1)).unwrap();
        assert!(s.write_take_oauth_flow("old").unwrap().is_none());
    }

    #[test]
    fn token_issue_resolve_expire_revoke() {
        let s = Store::open_in_memory().unwrap();
        let bearer = s.issue_token(&token(30)).unwrap();
        assert!(bearer.starts_with(TOKEN_PREFIX));
        let t = s.token(&bearer).unwrap().unwrap();
        assert_eq!(t.did, "did:plc:xyz");
        assert_eq!(t.warrant_status.as_ref().unwrap().1, 42);

        // Unknown and expired resolve to None.
        assert!(s.token("bidb_nope").unwrap().is_none());
        let expired = s.issue_token(&token(-1)).unwrap();
        assert!(s.token(&expired).unwrap().is_none());

        // Warrant revocation kills every token bound to that ref.
        let n = s
            .revoke_tokens_for_warrant("https://browserid.me/.well-known/browserid-status", 42)
            .unwrap();
        assert!(n >= 1);
        assert!(s.token(&bearer).unwrap().is_none());
    }
}
