//! Envelope encryption for the write-session secret columns.
//!
//! The bridge encrypts nothing else, and that is defensible: the existing
//! `accounts.access_jwt` / `refresh_jwt` columns are sessions for throwaway
//! bridge accounts, and `idp_oauth_flows.dpop_secret` is five minutes of
//! flow state with no token attached. A **real user's** atproto refresh
//! token is a different class of secret — it is live write access to an
//! account with real followers, for the remaining session lifetime — so the
//! three columns that hold one are sealed with a key that lives outside the
//! database (design doc, *Decision 4*).
//!
//! The threat this actually addresses is narrow and worth naming: a DB-only
//! leak (a snapshot, a stray backup, the SQLite file itself) yields
//! ciphertext. An attacker who owns the host owns the key too. Whole-DB
//! SQLCipher was considered and rejected — it protects the uninteresting
//! columns and still leaves the key next to the file.
//!
//! XChaCha20-Poly1305 rather than AES-GCM for one reason: its 192-bit nonce
//! can be drawn at random for every seal with no birthday-bound bookkeeping,
//! and every column here is rewritten on every refresh.
//!
//! **Associated data binds a ciphertext to its slot.** Every seal is
//! authenticated over `write_session:<did>:<column>`, so a ciphertext lifted
//! out of one row cannot be pasted into another (an attacker with write
//! access to the DB but not the key could otherwise swap Alice's refresh
//! token into Bob's row) and a `dpop_secret` blob cannot be replayed as an
//! `access_token`.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::RngCore;

/// XChaCha20-Poly1305's nonce width.
const NONCE_LEN: usize = 24;

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("write-session ciphertext is too short")]
    Truncated,
    /// Wrong key, wrong slot, or tampering — deliberately undifferentiated.
    #[error("write-session ciphertext failed to authenticate")]
    Undecryptable,
}

/// The write-session AEAD key. One per deployment, never in the database.
pub struct SecretBox {
    cipher: XChaCha20Poly1305,
}

/// Redacting, and hand-written so it stays that way. The whole value of this
/// key is that it does not appear anywhere the ciphertext does — a derived
/// `Debug` that printed it into a log line would undo the entire scheme.
impl std::fmt::Debug for SecretBox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretBox(<write-session AEAD key, redacted>)")
    }
}

impl SecretBox {
    pub fn from_key_bytes(key: &[u8]) -> Result<Self, String> {
        if key.len() != 32 {
            return Err(format!("write-session key must be 32 bytes, got {}", key.len()));
        }
        Ok(Self { cipher: XChaCha20Poly1305::new(key.into()) })
    }

    /// Load from `WRITE_SESSION_KEY` (hex or base64url, 32 bytes), else the
    /// file named by `WRITE_SESSION_KEY_FILE`. **There is no third branch.**
    ///
    /// The other key loaders in this codebase (`ClientKey::from_env`,
    /// `load_or_generate_keypair`) generate and persist when nothing is
    /// injected, and that is defensible for them: a generated browserid key
    /// signs certs the world rejects, and a generated OAuth client key gets
    /// rejected by authorization servers — both fail loudly and immediately,
    /// and neither protects anything at rest.
    ///
    /// This key is different in kind. Generating it beside the database
    /// would put the key and the ciphertext it protects in the same blast
    /// radius, which is precisely the property Decision 4 exists to buy —
    /// "the AEAD key lives in the environment/secret store, not the DB; a
    /// DB-only leak yields ciphertext". A snapshot, a backup, or a stray
    /// `scp -r` would then carry both. Worse, it fails *silently*: everything
    /// works, and the encryption is simply worth nothing.
    ///
    /// So a relay-enabled deployment with no injected key refuses to start.
    pub fn from_env() -> Result<Self, String> {
        Self::from_sources(
            std::env::var("WRITE_SESSION_KEY").ok(),
            std::env::var("WRITE_SESSION_KEY_FILE").ok().map(std::path::PathBuf::from),
        )
    }

    /// The body of [`Self::from_env`] with its inputs passed in, so the
    /// refusal can be tested without mutating process-global environment
    /// under every other test in the binary.
    fn from_sources(
        env_key: Option<String>,
        key_file: Option<std::path::PathBuf>,
    ) -> Result<Self, String> {
        if let Some(raw) = env_key {
            return Self::from_key_text(&raw);
        }
        if let Some(path) = key_file {
            if !path.exists() {
                return Err(format!(
                    "WRITE_SESSION_KEY_FILE points at {}, which does not exist. The write \
                     relay will not start without its AEAD key — generating one here would \
                     leave the key next to the database it protects.",
                    path.display()
                ));
            }
            let raw =
                std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
            return Self::from_key_text(&raw);
        }
        Err("the write relay is enabled (WRITE_RELAY_ALLOWLIST names someone) but no \
             write-session key is configured. Set WRITE_SESSION_KEY to 32 bytes of hex or \
             base64 from your secret store, or WRITE_SESSION_KEY_FILE to a path holding one \
             — e.g. `openssl rand -hex 32`. This key is deliberately NOT generated for you: \
             it must not live beside the database it protects, and a session stored under a \
             key that later vanishes can never be read again."
            .to_string())
    }

    fn from_key_text(raw: &str) -> Result<Self, String> {
        let raw = raw.trim();
        let bytes = if raw.len() == 64 && raw.chars().all(|c| c.is_ascii_hexdigit()) {
            (0..64)
                .step_by(2)
                .map(|i| u8::from_str_radix(&raw[i..i + 2], 16).map_err(|e| e.to_string()))
                .collect::<Result<Vec<u8>, _>>()?
        } else {
            URL_SAFE_NO_PAD
                .decode(raw)
                .or_else(|_| base64::engine::general_purpose::STANDARD.decode(raw))
                .map_err(|e| format!("WRITE_SESSION_KEY: {e}"))?
        };
        Self::from_key_bytes(&bytes)
    }

    /// Seal `plaintext` for `(did, column)`. The stored blob is
    /// `nonce || ciphertext||tag` — self-contained, so a row carries
    /// everything needed to open it except the key.
    pub fn seal(&self, did: &str, column: &str, plaintext: &[u8]) -> Vec<u8> {
        let mut nonce = [0u8; NONCE_LEN];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let aad = aad(did, column);
        let ct = self
            .cipher
            .encrypt(XNonce::from_slice(&nonce), Payload { msg: plaintext, aad: aad.as_bytes() })
            // Only fails on a >64GiB message.
            .expect("XChaCha20-Poly1305 seal");
        let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        out
    }

    pub fn open(&self, did: &str, column: &str, blob: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if blob.len() <= NONCE_LEN {
            return Err(CryptoError::Truncated);
        }
        let (nonce, ct) = blob.split_at(NONCE_LEN);
        let aad = aad(did, column);
        self.cipher
            .decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad: aad.as_bytes() })
            .map_err(|_| CryptoError::Undecryptable)
    }

    pub fn seal_str(&self, did: &str, column: &str, s: &str) -> Vec<u8> {
        self.seal(did, column, s.as_bytes())
    }

    pub fn open_str(&self, did: &str, column: &str, blob: &[u8]) -> Result<String, CryptoError> {
        String::from_utf8(self.open(did, column, blob)?).map_err(|_| CryptoError::Undecryptable)
    }
}

/// The associated data for one column of one row. Not a secret — its job is
/// to make a ciphertext meaningless anywhere but where it was written.
fn aad(did: &str, column: &str) -> String {
    format!("write_session:{did}:{column}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn box_() -> SecretBox {
        SecretBox::from_key_bytes(&[7u8; 32]).unwrap()
    }

    #[test]
    fn a_sealed_secret_round_trips_and_hides_its_plaintext() {
        let b = box_();
        let blob = b.seal_str("did:plc:abc", "refresh_token", "ref-tok-secret");
        assert_eq!(b.open_str("did:plc:abc", "refresh_token", &blob).unwrap(), "ref-tok-secret");
        // What lands on disk contains no trace of the token.
        assert!(!blob.windows(3).any(|w| w == b"ref"));
        assert!(blob.len() > NONCE_LEN);
    }

    #[test]
    fn every_seal_uses_a_fresh_nonce() {
        let b = box_();
        let a = b.seal_str("did:plc:abc", "access_token", "same");
        let c = b.seal_str("did:plc:abc", "access_token", "same");
        assert_ne!(a, c, "a deterministic ciphertext would leak equality across refreshes");
    }

    /// The associated data is the whole point of the scheme: a ciphertext is
    /// bound to one DID and one column, so an attacker with write access to
    /// the database but not the key cannot move Alice's refresh token into
    /// Bob's row, nor replay a DPoP key blob as an access token.
    #[test]
    fn a_ciphertext_cannot_be_moved_between_rows_or_columns() {
        let b = box_();
        let blob = b.seal_str("did:plc:alice", "refresh_token", "alice-refresh");
        assert!(b.open_str("did:plc:bob", "refresh_token", &blob).is_err(), "row swap");
        assert!(b.open_str("did:plc:alice", "access_token", &blob).is_err(), "column swap");
        assert!(b.open_str("did:plc:alice", "refresh_token", &blob).is_ok());
    }

    #[test]
    fn a_different_key_cannot_open_it_and_tampering_is_detected() {
        let blob = box_().seal_str("did:plc:abc", "dpop_secret", "k");
        let other = SecretBox::from_key_bytes(&[9u8; 32]).unwrap();
        assert!(other.open_str("did:plc:abc", "dpop_secret", &blob).is_err());

        let mut flipped = blob.clone();
        let last = flipped.len() - 1;
        flipped[last] ^= 1;
        assert!(box_().open_str("did:plc:abc", "dpop_secret", &flipped).is_err());
        assert!(matches!(
            box_().open_str("did:plc:abc", "dpop_secret", &blob[..4]),
            Err(CryptoError::Truncated)
        ));
    }

    /// The footgun this must never reload: a relay-enabled deployment with
    /// no injected key used to generate one and persist it **next to the
    /// database**, putting the key and the ciphertext it protects in one
    /// blast radius and silently reducing Decision 4 to decoration. Nothing
    /// would have looked wrong.
    #[test]
    fn a_missing_key_refuses_to_start_rather_than_generating_one() {
        let dir = std::env::temp_dir().join(format!("relay-key-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let missing = dir.join("write-session-key.txt");
        let _ = std::fs::remove_file(&missing);

        // No env key and no file at all.
        let e = SecretBox::from_sources(None, None).unwrap_err();
        assert!(e.contains("WRITE_SESSION_KEY"), "{e}");
        assert!(e.contains("NOT generated for you"), "the error explains the refusal: {e}");

        // A file path that does not exist is an error, NOT a cue to create it.
        let e = SecretBox::from_sources(None, Some(missing.clone())).unwrap_err();
        assert!(e.contains("does not exist"), "{e}");
        assert!(!missing.exists(), "refusing must not have written a key file");

        // Both real sources still work.
        assert!(SecretBox::from_sources(Some("07".repeat(32)), None).is_ok());
        std::fs::write(&missing, "09".repeat(32)).unwrap();
        assert!(SecretBox::from_sources(None, Some(missing.clone())).is_ok());
        // The env key wins over the file, and a bad one is fatal rather than
        // quietly falling through to the file.
        assert!(SecretBox::from_sources(Some("nonsense".into()), Some(missing.clone())).is_err());

        let _ = std::fs::remove_file(&missing);
    }

    #[test]
    fn keys_load_from_hex_or_base64_and_reject_wrong_lengths() {
        let hex = "07".repeat(32);
        let from_hex = SecretBox::from_key_text(&hex).unwrap();
        let blob = from_hex.seal_str("did:plc:a", "access_token", "x");
        assert_eq!(box_().open_str("did:plc:a", "access_token", &blob).unwrap(), "x");

        let b64 = URL_SAFE_NO_PAD.encode([7u8; 32]);
        assert!(SecretBox::from_key_text(&b64).is_ok());
        assert!(SecretBox::from_key_text("deadbeef").is_err(), "too short");
        assert!(SecretBox::from_key_bytes(&[0u8; 16]).is_err());
    }
}
