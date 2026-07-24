//! Minimal atproto labeler (bean browserid-bsky-4zx7): emits **signed
//! labels** on posts that carry valid browserid provenance, so a bsky.app
//! user who subscribes to this labeler sees a client-rendered badge —
//! keyed on the real post, unspoofable by post content (unlike an in-post
//! link).
//!
//! Label signing follows the atproto label spec: build the label WITHOUT
//! `sig`, encode canonical DAG-CBOR, SHA-256, sign the digest with a k256
//! (secp256k1) key, low-S normalized, 64-byte compact; `sig` serializes as
//! a `{"$bytes": base64}` object. The signing key is published in the
//! labeler's DID document at `#atproto_label` as a Multikey; the service
//! endpoint is `#atproto_labeler` (type `AtprotoLabeler`).

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use k256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey};
use serde::Serialize;
use sha2::{Digest, Sha256};

/// The label value this labeler emits for a browserid-verified post.
pub const LABEL_VERIFIED: &str = "browserid-verified";

/// The labeler's k256 signing key + derived identity material.
pub struct Labeler {
    signing_key: SigningKey,
    /// The labeler's DID (did:web:<host>)
    pub did: String,
    /// Public endpoint base, e.g. https://bsky.browserid.me
    pub origin: String,
}

impl Labeler {
    /// `secret_hex` = 32-byte k256 private scalar (hex). `origin` is the
    /// public https base; the DID is `did:web:<host>`.
    pub fn new(secret_hex: &str, origin: &str) -> Result<Self, String> {
        let bytes = hex_decode(secret_hex.trim())?;
        let signing_key = SigningKey::from_slice(&bytes).map_err(|e| format!("bad k256 key: {e}"))?;
        let host = origin
            .trim_end_matches('/')
            .strip_prefix("https://")
            .or_else(|| origin.strip_prefix("http://"))
            .ok_or("origin must be an https URL")?;
        Ok(Self {
            signing_key,
            did: format!("did:web:{host}"),
            origin: origin.trim_end_matches('/').to_string(),
        })
    }

    /// The `#atproto_label` public key as a Multikey (`z` + multicodec + compressed).
    pub fn label_multikey(&self) -> String {
        let compressed = self.signing_key.verifying_key().to_sec1_bytes(); // 33 bytes, compressed
        let mut mc = vec![0xe7u8, 0x01]; // multicodec: secp256k1-pub
        mc.extend_from_slice(&compressed);
        format!("z{}", bs58::encode(mc).into_string())
    }

    /// The did:web DID document with the label key + labeler service.
    pub fn did_document(&self) -> serde_json::Value {
        serde_json::json!({
            "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"],
            "id": self.did,
            "verificationMethod": [{
                "id": format!("{}#atproto_label", self.did),
                "type": "Multikey",
                "controller": self.did,
                "publicKeyMultibase": self.label_multikey(),
            }],
            "service": [{
                "id": "#atproto_labeler",
                "type": "AtprotoLabeler",
                "serviceEndpoint": self.origin,
            }],
        })
    }

    /// Build and sign a label on `uri` with value `val` at time `cts`.
    pub fn sign_label(&self, uri: &str, val: &str, cts: &str) -> serde_json::Value {
        #[derive(Serialize)]
        struct Unsigned<'a> {
            cts: &'a str,
            src: &'a str,
            uri: &'a str,
            val: &'a str,
            ver: i64,
        }
        // Canonical DAG-CBOR of the sig-less label, then SHA-256, then sign.
        let unsigned = Unsigned { cts, src: &self.did, uri, val, ver: 1 };
        let cbor = serde_ipld_dagcbor::to_vec(&unsigned).expect("dag-cbor");
        let digest = Sha256::digest(&cbor);
        let sig: Signature = self.signing_key.sign_prehash(&digest).expect("sign");
        let sig = sig.normalize_s(); // low-S required by atproto
        let sig_bytes = sig.to_bytes(); // 64-byte compact r||s
        serde_json::json!({
            "ver": 1,
            "src": self.did,
            "uri": uri,
            "val": val,
            "cts": cts,
            "sig": { "$bytes": B64.encode(sig_bytes) },
        })
    }
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err("odd hex length".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::{signature::hazmat::PrehashVerifier, VerifyingKey};

    fn test_key() -> String {
        // A fixed 32-byte scalar (hex).
        "1a".repeat(32)
    }

    #[test]
    fn multikey_shape() {
        let l = Labeler::new(&test_key(), "https://bsky.browserid.me").unwrap();
        let mk = l.label_multikey();
        assert!(mk.starts_with('z'), "multibase base58btc prefix");
        assert_eq!(l.did, "did:web:bsky.browserid.me");
        let doc = l.did_document();
        assert_eq!(doc["service"][0]["type"], "AtprotoLabeler");
        assert_eq!(doc["verificationMethod"][0]["id"], "did:web:bsky.browserid.me#atproto_label");
    }

    #[test]
    fn label_signature_verifies() {
        let l = Labeler::new(&test_key(), "https://bsky.browserid.me").unwrap();
        let uri = "at://did:plc:abc/app.bsky.feed.post/xyz";
        let label = l.sign_label(uri, LABEL_VERIFIED, "2026-07-24T00:00:00.000Z");

        // Reconstruct the signed bytes and verify against the published key.
        #[derive(Serialize)]
        struct Unsigned<'a> { cts: &'a str, src: &'a str, uri: &'a str, val: &'a str, ver: i64 }
        let unsigned = Unsigned {
            cts: label["cts"].as_str().unwrap(),
            src: label["src"].as_str().unwrap(),
            uri: label["uri"].as_str().unwrap(),
            val: label["val"].as_str().unwrap(),
            ver: 1,
        };
        let digest = Sha256::digest(&serde_ipld_dagcbor::to_vec(&unsigned).unwrap());
        let sig_b64 = label["sig"]["$bytes"].as_str().unwrap();
        let sig = Signature::from_slice(&B64.decode(sig_b64).unwrap()).unwrap();
        let vk: VerifyingKey = *l.signing_key.verifying_key();
        assert!(vk.verify_prehash(&digest, &sig).is_ok(), "signature must verify");
    }
}
