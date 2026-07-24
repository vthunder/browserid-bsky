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

/// Fully verified, acting as itself (grantor == grantee).
pub const LABEL_VERIFIED: &str = "browserid-verified";
/// Fully verified, but a delegate acted on behalf of another identity.
pub const LABEL_ON_BEHALF: &str = "browserid-on-behalf";

/// The labeler's k256 signing key + derived identity material.
pub struct Labeler {
    signing_key: SigningKey,
    /// The DID labels are issued under (`src`). Defaults to `did:web:<host>`;
    /// overridden with `LABELER_DID` to the labeler *account*'s did:plc, which
    /// is what bsky.app users actually subscribe to (the account carries the
    /// `app.bsky.labeler.service` record the AppView indexes). The same
    /// `#atproto_label` key must be published in whichever DID doc is used.
    pub did: String,
    /// This host's did:web identity, served at `/.well-known/did.json`.
    pub web_did: String,
    /// Public endpoint base, e.g. https://bsky.browserid.me
    pub origin: String,
}

impl Labeler {
    /// `secret_hex` = 32-byte k256 private scalar (hex). `origin` is the
    /// public https base. `did_override` (env `LABELER_DID`) sets the issuing
    /// DID; without it, labels are issued as `did:web:<host>`.
    pub fn new(secret_hex: &str, origin: &str, did_override: Option<String>) -> Result<Self, String> {
        let bytes = hex_decode(secret_hex.trim())?;
        let signing_key = SigningKey::from_slice(&bytes).map_err(|e| format!("bad k256 key: {e}"))?;
        let host = origin
            .trim_end_matches('/')
            .strip_prefix("https://")
            .or_else(|| origin.strip_prefix("http://"))
            .ok_or("origin must be an https URL")?;
        let web_did = format!("did:web:{host}");
        Ok(Self {
            signing_key,
            did: did_override.unwrap_or_else(|| web_did.clone()),
            web_did,
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

    /// The did:web DID document with the label key + labeler service. Kept
    /// alongside the did:plc labeler account so `did:web:<host>` remains a
    /// resolvable, self-hosted view of the same key.
    pub fn did_document(&self) -> serde_json::Value {
        serde_json::json!({
            "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"],
            "id": self.web_did,
            "verificationMethod": [{
                "id": format!("{}#atproto_label", self.web_did),
                "type": "Multikey",
                "controller": self.web_did,
                "publicKeyMultibase": self.label_multikey(),
            }],
            "service": [{
                "id": "#atproto_labeler",
                "type": "AtprotoLabeler",
                "serviceEndpoint": self.origin,
            }],
        })
    }

    /// Sign a label on `uri` with value `val` at time `cts`, returning the
    /// raw 64-byte signature. The same signature is served two ways: as
    /// `{"$bytes": …}` over JSON (`queryLabels`) and as a CBOR byte string
    /// over the firehose (`subscribeLabels`).
    pub fn sign(&self, uri: &str, val: &str, cts: &str) -> Vec<u8> {
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
        sig.to_bytes().to_vec() // 64-byte compact r||s
    }

    /// Build and sign a label, JSON-shaped for `queryLabels`.
    pub fn sign_label(&self, uri: &str, val: &str, cts: &str) -> serde_json::Value {
        self.label_json(uri, val, cts, &self.sign(uri, val, cts))
    }

    /// JSON form of an already-signed label.
    pub fn label_json(&self, uri: &str, val: &str, cts: &str, sig: &[u8]) -> serde_json::Value {
        serde_json::json!({
            "ver": 1,
            "src": self.did,
            "uri": uri,
            "val": val,
            "cts": cts,
            "sig": { "$bytes": B64.encode(sig) },
        })
    }

    /// One `subscribeLabels` message: an atproto event-stream frame, which
    /// is two concatenated DAG-CBOR objects — a header naming the event
    /// type, then the body. `seq` is the consumer's cursor.
    pub fn labels_frame(&self, l: &crate::store::EmittedLabel) -> Vec<u8> {
        #[derive(Serialize)]
        struct Header<'a> {
            t: &'a str,
            op: i64,
        }
        #[derive(Serialize)]
        struct Label<'a> {
            // Field order is the canonical DAG-CBOR map order (keys of equal
            // length, sorted bytewise) — serde_ipld_dagcbor writes struct
            // fields as declared, so the declaration IS the encoding.
            cts: &'a str,
            #[serde(with = "serde_bytes")]
            sig: &'a [u8],
            src: &'a str,
            uri: &'a str,
            val: &'a str,
            ver: i64,
        }
        #[derive(Serialize)]
        struct Body<'a> {
            seq: i64,
            labels: Vec<Label<'a>>,
        }
        let mut frame = serde_ipld_dagcbor::to_vec(&Header { t: "#labels", op: 1 }).expect("hdr");
        let body = Body {
            seq: l.seq,
            labels: vec![Label {
                cts: &l.cts,
                sig: &l.sig,
                src: &self.did,
                uri: &l.uri,
                val: &l.val,
                ver: 1,
            }],
        };
        frame.extend_from_slice(&serde_ipld_dagcbor::to_vec(&body).expect("body"));
        frame
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
        let l = Labeler::new(&test_key(), "https://bsky.browserid.me", None).unwrap();
        let mk = l.label_multikey();
        assert!(mk.starts_with('z'), "multibase base58btc prefix");
        assert_eq!(l.did, "did:web:bsky.browserid.me");
        let doc = l.did_document();
        assert_eq!(doc["service"][0]["type"], "AtprotoLabeler");
        assert_eq!(doc["verificationMethod"][0]["id"], "did:web:bsky.browserid.me#atproto_label");
    }

    #[test]
    fn did_override_changes_label_src_but_not_the_did_web_doc() {
        let plc = "did:plc:iewpoc3kqru4rgqpkojfixhx";
        let l = Labeler::new(&test_key(), "https://bsky.browserid.me", Some(plc.into())).unwrap();
        let label = l.sign_label("at://did:plc:abc/app.bsky.feed.post/xyz", LABEL_VERIFIED, "2026-07-24T00:00:00.000Z");
        assert_eq!(label["src"], plc, "labels issue under the subscribable account DID");
        // The self-hosted did:web document still describes did:web (same key).
        assert_eq!(l.did_document()["id"], "did:web:bsky.browserid.me");
    }

    /// A `subscribeLabels` frame must decode as header-then-body, with the
    /// signature as a CBOR byte string (not the JSON `$bytes` wrapper), and
    /// the signature must verify — this is exactly what the AppView does
    /// before storing a label, and getting it wrong means silent rejection.
    #[test]
    fn firehose_frame_decodes_and_verifies() {
        let l = Labeler::new(&test_key(), "https://bsky.browserid.me", None).unwrap();
        let uri = "at://did:plc:abc/app.bsky.feed.post/xyz";
        let cts = "2026-07-24T00:00:00.000Z";
        let stored = crate::store::EmittedLabel {
            seq: 7,
            uri: uri.into(),
            val: LABEL_VERIFIED.into(),
            cts: cts.into(),
            sig: l.sign(uri, LABEL_VERIFIED, cts),
        };

        #[derive(serde::Deserialize)]
        struct Header { t: String, op: i64 }
        #[derive(serde::Deserialize)]
        struct DecodedLabel {
            cts: String,
            #[serde(with = "serde_bytes")]
            sig: Vec<u8>,
            src: String,
            uri: String,
            val: String,
            ver: i64,
        }
        #[derive(serde::Deserialize)]
        struct Body { seq: i64, labels: Vec<DecodedLabel> }

        let frame = l.labels_frame(&stored);
        // `_once` leaves the reader positioned after the first object — the
        // frame is two objects back to back, which is how consumers read it.
        let mut cur = std::io::Cursor::new(frame);
        let h: Header = serde_ipld_dagcbor::de::from_reader_once(&mut cur).expect("header");
        assert_eq!((h.t.as_str(), h.op), ("#labels", 1));
        let body: Body = serde_ipld_dagcbor::de::from_reader_once(&mut cur).expect("body");
        assert_eq!(body.seq, 7, "seq is the consumer's cursor");
        let got = &body.labels[0];
        assert_eq!((got.uri.as_str(), got.val.as_str(), got.ver), (uri, LABEL_VERIFIED, 1));
        assert_eq!(got.src, l.did);
        assert_eq!(got.sig.len(), 64);

        #[derive(Serialize)]
        struct Unsigned<'a> { cts: &'a str, src: &'a str, uri: &'a str, val: &'a str, ver: i64 }
        let digest = Sha256::digest(
            &serde_ipld_dagcbor::to_vec(&Unsigned {
                cts: &got.cts, src: &got.src, uri: &got.uri, val: &got.val, ver: got.ver,
            })
            .unwrap(),
        );
        let sig = Signature::from_slice(&got.sig).unwrap();
        assert!(l.signing_key.verifying_key().verify_prehash(&digest, &sig).is_ok());
    }

    #[test]
    fn label_signature_verifies() {
        let l = Labeler::new(&test_key(), "https://bsky.browserid.me", None).unwrap();
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
