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
    pub expires_at: DateTime<Utc>,
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
                 expires_at     TEXT NOT NULL
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
             );",
        )?;
        Ok(Self { conn: Mutex::new(conn) })
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
                                 warrant_uri, warrant_idx, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                Self::hash(&token),
                t.did,
                t.grantor,
                t.grantee,
                t.holder,
                serde_json::to_string(&t.scopes).map_err(|e| StoreError(e.to_string()))?,
                uri,
                idx,
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
                "SELECT did, grantor, grantee, holder, scopes, warrant_uri, warrant_idx, expires_at
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
                    ))
                },
            )
            .optional()?;
        let Some((did, grantor, grantee, holder, scopes, uri, idx, exp)) = row else {
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
            expires_at,
        }))
    }

    /// Drop every token bound to a warrant status ref (used when a re-check
    /// finds the warrant revoked).
    pub fn revoke_tokens_for_warrant(&self, uri: &str, idx: u64) -> Result<usize> {
        Ok(self.conn.lock().unwrap().execute(
            "DELETE FROM tokens WHERE warrant_uri = ?1 AND warrant_idx = ?2",
            params![uri, idx as i64],
        )?)
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
