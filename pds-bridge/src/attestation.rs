//! Post attestation (provenance phase 2, bean browserid-bsky-n78o).
//!
//! The unforgeable half of provenance: the **grantee** (via its access key,
//! certified by the access cert → grantee identity → IdP) signs a canonical
//! statement binding a specific post's content to a nonce and time. This is
//! what a compromised bridge/PDS cannot forge — it lacks the grantee key.
//!
//! Signed over a **detached Ed25519 signature of canonical bytes** (the JWS
//! helpers in browserid-core aren't public). Domain-separated by `typ`.
//!
//! Replay is prevented by the `nonce` (single-use; also the key an in-post
//! `verify?n=<nonce>` link uses) plus `iat` freshness. The signature covers
//! `content_hash` = the canonical hash of the exact post record published,
//! so it can't be lifted onto a different or duplicate post.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use browserid_core::{KeyPair, PublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const ATTESTATION_TYP: &str = "browserid-bsky-post-attestation-v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationClaims {
    pub typ: String,
    /// Repo the post lives in (the grantor's account DID)
    pub did: String,
    /// Record collection, e.g. `app.bsky.feed.post`
    pub collection: String,
    /// base64url SHA-256 of the canonical post record (see [`content_hash`])
    pub content_hash: String,
    /// Single-use nonce — replay guard and `verify?n=` link key
    pub nonce: String,
    /// Issued-at (unix seconds) — freshness bound
    pub iat: i64,
}

impl AttestationClaims {
    pub fn new(did: &str, collection: &str, content_hash: &str, nonce: &str, iat: i64) -> Self {
        Self {
            typ: ATTESTATION_TYP.to_string(),
            did: did.to_string(),
            collection: collection.to_string(),
            content_hash: content_hash.to_string(),
            nonce: nonce.to_string(),
            iat,
        }
    }

    /// Canonical bytes that get signed — recursively key-sorted JSON, so the
    /// signer and verifier agree byte-for-byte.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let v = serde_json::to_value(self).expect("claims serialize");
        canonical_json(&v).into_bytes()
    }

    pub fn sign(&self, access_key: &KeyPair) -> String {
        URL_SAFE_NO_PAD.encode(access_key.sign(&self.signing_bytes()))
    }

    /// Verify the detached signature against the access key.
    pub fn verify(&self, access_pub: &PublicKey, sig_b64: &str) -> bool {
        if self.typ != ATTESTATION_TYP {
            return false;
        }
        let Ok(sig) = URL_SAFE_NO_PAD.decode(sig_b64) else {
            return false;
        };
        access_pub.verify(&self.signing_bytes(), &sig).is_ok()
    }
}

/// base64url SHA-256 of a post record's canonical (key-sorted) JSON.
pub fn content_hash(record: &serde_json::Value) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(canonical_json(record).as_bytes()))
}

/// Deterministic JSON: object keys sorted recursively, compact, so two
/// parties hash identical bytes. (RFC 8785-ish; sufficient for our records,
/// which are plain JSON with string/number/bool/array/object values.)
pub fn canonical_json(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let inner: Vec<String> = keys
                .into_iter()
                .map(|k| format!("{}:{}", serde_json::to_string(k).unwrap(), canonical_json(&map[k])))
                .collect();
            format!("{{{}}}", inner.join(","))
        }
        serde_json::Value::Array(arr) => {
            let inner: Vec<String> = arr.iter().map(canonical_json).collect();
            format!("[{}]", inner.join(","))
        }
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_is_key_order_invariant() {
        let a: serde_json::Value = serde_json::from_str(r#"{"b":1,"a":{"y":2,"x":3},"c":[3,2,1]}"#).unwrap();
        let b: serde_json::Value = serde_json::from_str(r#"{"c":[3,2,1],"a":{"x":3,"y":2},"b":1}"#).unwrap();
        assert_eq!(canonical_json(&a), canonical_json(&b));
        // Array order is preserved (not sorted).
        assert!(canonical_json(&a).contains("[3,2,1]"));
    }

    #[test]
    fn sign_verify_roundtrip_and_tamper() {
        let kp = KeyPair::generate();
        let record = serde_json::json!({ "text": "hi", "$type": "app.bsky.feed.post" });
        let claims = AttestationClaims::new("did:plc:x", "app.bsky.feed.post", &content_hash(&record), "nonce1", 1000);
        let sig = claims.sign(&kp);
        assert!(claims.verify(&kp.public_key(), &sig));

        // Wrong key rejected.
        assert!(!claims.verify(&KeyPair::generate().public_key(), &sig));

        // Tampered content_hash (signature no longer matches) rejected.
        let mut forged = claims.clone();
        forged.content_hash = content_hash(&serde_json::json!({ "text": "different" }));
        assert!(!forged.verify(&kp.public_key(), &sig));

        // Tampered nonce rejected (replay-onto-another-post guard).
        let mut renonced = claims.clone();
        renonced.nonce = "nonce2".into();
        assert!(!renonced.verify(&kp.public_key(), &sig));
    }
}

#[cfg(test)]
mod cross_impl_vector {
    use super::*;

    /// A FIXED vector the JavaScript implementation must reproduce byte for
    /// byte (see the `attestation` test in the browserid-bsky agent CLI). If
    /// this constant changes, the JS signer stops producing signatures this
    /// bridge accepts — so treat a diff here as a protocol break, not a test
    /// to update.
    #[test]
    fn canonical_json_and_content_hash_are_stable() {
        let record = serde_json::json!({
            "$type": "app.bsky.feed.post",
            "text": "hello \"world\"\n",
            "createdAt": "2026-07-24T00:00:00.000Z",
            "facets": [{
                "index": { "byteStart": 0, "byteEnd": 5 },
                "features": [{ "$type": "app.bsky.richtext.facet#link", "uri": "https://x/y?a=1&b=2" }],
            }],
            "langs": ["en"],
        });
        assert_eq!(
            canonical_json(&record),
            r#"{"$type":"app.bsky.feed.post","createdAt":"2026-07-24T00:00:00.000Z","facets":[{"features":[{"$type":"app.bsky.richtext.facet#link","uri":"https://x/y?a=1&b=2"}],"index":{"byteEnd":5,"byteStart":0}}],"langs":["en"],"text":"hello \"world\"\n"}"#
        );
        assert_eq!(content_hash(&record), "YyPkrj7WIS8fjNwoclhYN1MN1S_8igt7LivI4Tk1ps8");
    }
}
