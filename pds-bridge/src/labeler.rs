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

/// Prefixes of the **per-identity-pair** label values (bean ek9u). A label
/// `val` is an opaque identifier; what a client renders is the matching
/// `labelValueDefinition`'s locale `name` (the badge) and `description` (the
/// click-through). So the val carries no email — it is a hash keying a
/// definition whose *description* names the identities, while many vals
/// share the one short badge name.
pub const PAIR_PREFIX_AGENT: &str = "by-agent-";
pub const PAIR_PREFIX_OWNER: &str = "by-owner-";

/// Badge text (locale `name`) for each pair-label family.
pub const PAIR_NAME_AGENT: &str = "by agent";
pub const PAIR_NAME_OWNER: &str = "by owner";

/// Is this a per-identity-pair val (as opposed to a `browserid-*` one)?
pub fn is_pair_val(val: &str) -> bool {
    val.starts_with(PAIR_PREFIX_AGENT) || val.starts_with(PAIR_PREFIX_OWNER)
}

/// `danmills+fable@sandmill.org` → `danmills@sandmill.org`. A `+tag` local
/// part is a **sub-identity**: same human, separate identity, which is how
/// an agent gets an identity of its own.
pub fn base_identity(email: &str) -> String {
    match email.split_once('@') {
        Some((local, domain)) => format!("{}@{}", local.split('+').next().unwrap_or(local), domain),
        None => email.to_string(),
    }
}

/// Whether an identity is an agent sub-identity rather than a person's own.
fn is_sub_identity(email: &str) -> bool {
    email.split_once('@').map_or(false, |(local, _)| local.contains('+'))
}

/// Which badge family a (grantor, grantee) earns. An agent shows up two
/// ways: acting **for** someone else (grantor != grantee), or owning the
/// account under its own `+tag` sub-identity (grantor == grantee, but that
/// identity is an agent's). Both read "by agent" — only a person posting as
/// plainly themselves is "by owner".
fn is_agent_pair(grantor: &str, grantee: &str) -> bool {
    grantor != grantee || is_sub_identity(grantor)
}

/// The pair label value for a (grantor, grantee): the first 8 hex chars of
/// SHA-256 over `"{grantor}|{grantee}"`, prefixed by which relationship it
/// is. Stable across restarts and hosts (it is the definition's key), and
/// well inside the label-val charset (lowercase alphanumerics + hyphen) and
/// length cap. The prefix is part of the classification, so reclassifying a
/// pair yields a *different* val — which is what lets a stale label be
/// negated and replaced.
pub fn pair_val(grantor: &str, grantee: &str) -> String {
    let digest = Sha256::digest(format!("{grantor}|{grantee}").as_bytes());
    let h: String = digest.iter().take(4).map(|b| format!("{b:02x}")).collect();
    let prefix =
        if is_agent_pair(grantor, grantee) { PAIR_PREFIX_AGENT } else { PAIR_PREFIX_OWNER };
    format!("{prefix}{h}")
}

/// Badge text for a pair val.
pub fn pair_name(val: &str) -> &'static str {
    if val.starts_with(PAIR_PREFIX_OWNER) {
        PAIR_NAME_OWNER
    } else {
        PAIR_NAME_AGENT
    }
}

/// The identity domain of the bsky-handle IdP (bean tw1d). Identities here
/// are `<bluesky handle>@<this domain>`, and the local part is a name the
/// reader already knows — so badge copy shows it bare.
pub const BSKY_HANDLE_DOMAIN: &str = "bsky.browserid.me";

/// How an identity is *displayed*.
///
/// For a bsky-handle identity, the domain is noise: `dan.bsky.social` is
/// the name with the followers and the reputation, and
/// `dan.bsky.social@bsky.browserid.me` reads like a mouthful of
/// infrastructure. So badge and click-through copy show the bare local part
/// — `dan.bsky.social`, `dan.bsky.social+agent` — while the verify receipt
/// keeps the full identity string, because that is where precision matters
/// and where someone is checking rather than skimming.
///
/// Every other domain is displayed verbatim: an email identity's domain is
/// load-bearing information about who vouched for it.
pub fn display_identity(email: &str) -> &str {
    match email.split_once('@') {
        Some((local, domain)) if domain.eq_ignore_ascii_case(BSKY_HANDLE_DOMAIN) => local,
        _ => email,
    }
}

/// The click-through text: this is where the identities are actually named.
pub fn pair_description(grantor: &str, grantee: &str) -> String {
    let (grantor_shown, grantee_shown) = (display_identity(grantor), display_identity(grantee));
    let who = if grantor != grantee {
        format!("Posted by {grantee_shown} on behalf of {grantor_shown}, the owner of this handle.")
    } else if is_sub_identity(grantor) {
        let owner = base_identity(grantor);
        format!("Posted by {grantor_shown}, an agent owned by {}.", display_identity(&owner))
    } else {
        format!("Posted by {grantor_shown}, the owner of this handle.")
    };
    format!(
        "{who}\nFor more information, copy the link to this post and paste it at bsky.browserid.me"
    )
}

/// One `labelValueDefinition`, shaped like the existing `browserid-*` ones
/// (informational, non-blurring).
pub fn pair_definition(val: &str, grantor: &str, grantee: &str) -> serde_json::Value {
    serde_json::json!({
        "identifier": val,
        "severity": "inform",
        "blurs": "none",
        "adultOnly": false,
        "defaultSetting": "warn",
        "locales": [{
            "lang": "en",
            "name": pair_name(val),
            "description": pair_description(grantor, grantee),
        }],
    })
}

/// Read-modify-write of an `app.bsky.labeler.service` record value: append
/// `val` to `policies.labelValues` and its definition to
/// `policies.labelValueDefinitions`, replacing any existing entry for the
/// same identifier. Returns `false` when the record already said exactly
/// this (nothing to write) — the guard against re-putting on every restart
/// and against a concurrent append being duplicated.
pub fn merge_definition(record: &mut serde_json::Value, definition: serde_json::Value) -> bool {
    let val = definition["identifier"].as_str().unwrap_or_default().to_string();
    let policies = record
        .as_object_mut()
        .expect("service record is an object")
        .entry("policies")
        .or_insert_with(|| serde_json::json!({}));

    let mut changed = false;

    let values = policies["labelValues"].as_array().cloned().unwrap_or_default();
    if !values.iter().any(|v| v.as_str() == Some(val.as_str())) {
        let mut values = values;
        values.push(serde_json::Value::String(val.clone()));
        policies["labelValues"] = serde_json::Value::Array(values);
        changed = true;
    }

    let mut defs = policies["labelValueDefinitions"].as_array().cloned().unwrap_or_default();
    match defs.iter_mut().find(|d| d["identifier"].as_str() == Some(val.as_str())) {
        Some(existing) if *existing == definition => {}
        Some(existing) => {
            *existing = definition;
            changed = true;
        }
        None => {
            defs.push(definition);
            changed = true;
        }
    }
    policies["labelValueDefinitions"] = serde_json::Value::Array(defs);
    changed
}

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
    ///
    /// `neg` marks a **negation** — the retraction of a label previously
    /// emitted on the same subject. It is part of the signed body, and (per
    /// the spec) is omitted entirely rather than serialized as `false`, so a
    /// plain label's bytes are unchanged by this parameter existing.
    pub fn sign(&self, uri: &str, val: &str, cts: &str, neg: bool) -> Vec<u8> {
        #[derive(Serialize)]
        struct Unsigned<'a> {
            cts: &'a str,
            // DAG-CBOR map order is by key length then bytewise; every key
            // here is 3 bytes, so the declaration order IS the encoding.
            #[serde(skip_serializing_if = "Option::is_none")]
            neg: Option<bool>,
            src: &'a str,
            uri: &'a str,
            val: &'a str,
            ver: i64,
        }
        // Canonical DAG-CBOR of the sig-less label, then SHA-256, then sign.
        let unsigned =
            Unsigned { cts, neg: neg.then_some(true), src: &self.did, uri, val, ver: 1 };
        let cbor = serde_ipld_dagcbor::to_vec(&unsigned).expect("dag-cbor");
        let digest = Sha256::digest(&cbor);
        let sig: Signature = self.signing_key.sign_prehash(&digest).expect("sign");
        let sig = sig.normalize_s(); // low-S required by atproto
        sig.to_bytes().to_vec() // 64-byte compact r||s
    }

    /// Build and sign a label, JSON-shaped for `queryLabels`.
    pub fn sign_label(&self, uri: &str, val: &str, cts: &str, neg: bool) -> serde_json::Value {
        self.label_json(&crate::store::EmittedLabel {
            seq: 0,
            uri: uri.to_string(),
            val: val.to_string(),
            cts: cts.to_string(),
            neg,
            sig: self.sign(uri, val, cts, neg),
        })
    }

    /// JSON form of an already-signed label.
    pub fn label_json(&self, l: &crate::store::EmittedLabel) -> serde_json::Value {
        let mut json = serde_json::json!({
            "ver": 1,
            "src": self.did,
            "uri": l.uri,
            "val": l.val,
            "cts": l.cts,
            "sig": { "$bytes": B64.encode(&l.sig) },
        });
        if l.neg {
            json["neg"] = serde_json::Value::Bool(true);
        }
        json
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
            #[serde(skip_serializing_if = "Option::is_none")]
            neg: Option<bool>,
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
                neg: l.neg.then_some(true),
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
    fn pair_vals_are_stable_and_in_charset() {
        let owner = pair_val("dan@sandmill.org", "dan@sandmill.org");
        let agent = pair_val("dan@sandmill.org", "dan+agent@sandmill.org");
        assert_eq!(owner, pair_val("dan@sandmill.org", "dan@sandmill.org"), "stable");
        assert!(owner.starts_with(PAIR_PREFIX_OWNER) && agent.starts_with(PAIR_PREFIX_AGENT));
        assert_ne!(owner[PAIR_PREFIX_OWNER.len()..], agent[PAIR_PREFIX_AGENT.len()..]);
        for v in [&owner, &agent] {
            assert_eq!(v.len(), PAIR_PREFIX_OWNER.len() + 8, "prefix + 8 hex chars");
            assert!(
                v.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'),
                "label vals are lowercase alphanumerics + hyphen: {v}"
            );
            assert!(is_pair_val(v));
        }
        assert!(!is_pair_val(LABEL_VERIFIED) && !is_pair_val(LABEL_ON_BEHALF));
        // The hash covers the ordered pair, so a swap is a different val.
        assert_ne!(
            pair_val("a@example.com", "b@example.com"),
            pair_val("b@example.com", "a@example.com")
        );
    }

    /// An account owned by an agent's own `+tag` sub-identity is "by agent"
    /// too, even though grantor == grantee — "by owner" would credit the
    /// agent as the person. The hash input is unchanged, so reclassifying a
    /// pair changes only the prefix, which is what makes the old val
    /// identifiable and negatable.
    #[test]
    fn a_sub_identity_posting_as_itself_is_an_agent_not_an_owner() {
        let agent = "danmills+fable@sandmill.org";
        let human = "danmills@sandmill.org";

        let val = pair_val(agent, agent);
        assert!(val.starts_with(PAIR_PREFIX_AGENT));
        assert_eq!(pair_name(&val), PAIR_NAME_AGENT);
        assert_eq!(
            pair_description(agent, agent),
            format!(
                "Posted by {agent}, an agent owned by {human}.\n\
                 For more information, copy the link to this post and paste it at bsky.browserid.me"
            )
        );

        // Only the prefix moved: same pair, same 8 hex chars.
        assert_eq!(val[PAIR_PREFIX_AGENT.len()..], {
            let d = Sha256::digest(format!("{agent}|{agent}").as_bytes());
            d.iter().take(4).map(|b| format!("{b:02x}")).collect::<String>()
        });

        // A plain identity as itself is still the owner.
        let owner = pair_val(human, human);
        assert!(owner.starts_with(PAIR_PREFIX_OWNER));
        assert_eq!(pair_description(human, human), format!("Posted by {human}, the owner of this handle.\nFor more information, copy the link to this post and paste it at bsky.browserid.me"));

        // On-behalf is untouched by the reclassification.
        let on_behalf = pair_val(human, agent);
        assert!(on_behalf.starts_with(PAIR_PREFIX_AGENT));
        assert!(pair_description(human, agent)
            .starts_with(&format!("Posted by {agent} on behalf of {human}, the owner")));

        assert_eq!(base_identity(agent), human);
        assert_eq!(base_identity(human), human);
        assert_eq!(base_identity("weird"), "weird");
    }

    /// A negation is a distinct signed statement: `neg` is inside the signed
    /// bytes, so a consumer cannot strip it and still verify. A plain label
    /// must be byte-identical to what the pre-`neg` code signed, which is why
    /// `neg: false` is omitted rather than encoded.
    #[test]
    fn negations_sign_differently_and_omit_neg_when_false() {
        let l = Labeler::new(&test_key(), "https://bsky.browserid.me", None).unwrap();
        let (uri, cts) = ("at://did:plc:abc/app.bsky.feed.post/xyz", "2026-07-26T00:00:00.000Z");
        let val = "by-owner-ea7898db";

        assert_ne!(l.sign(uri, val, cts, false), l.sign(uri, val, cts, true));

        let plain = l.sign_label(uri, val, cts, false);
        assert!(plain.get("neg").is_none(), "a plain label carries no neg field");
        let negated = l.sign_label(uri, val, cts, true);
        assert_eq!(negated["neg"], true);
        assert_eq!(negated["val"], val, "a negation names the val it retracts");

        // The frame a consumer actually ingests must carry neg too, and the
        // signature over it must verify.
        let stored = crate::store::EmittedLabel {
            seq: 9,
            uri: uri.into(),
            val: val.into(),
            cts: cts.into(),
            neg: true,
            sig: l.sign(uri, val, cts, true),
        };
        #[derive(serde::Deserialize)]
        struct DecodedLabel {
            cts: String,
            neg: Option<bool>,
            #[serde(with = "serde_bytes")]
            sig: Vec<u8>,
            src: String,
            uri: String,
            val: String,
            ver: i64,
        }
        #[derive(serde::Deserialize)]
        struct Body {
            labels: Vec<DecodedLabel>,
        }
        let mut cur = std::io::Cursor::new(l.labels_frame(&stored));
        // Skip the header; the body is the second object in the frame.
        let _: serde_json::Value =
            serde_ipld_dagcbor::de::from_reader_once(&mut cur).expect("header");
        let body: Body = serde_ipld_dagcbor::de::from_reader_once(&mut cur).expect("body");
        let got = &body.labels[0];
        assert_eq!(got.neg, Some(true));

        #[derive(Serialize)]
        struct Unsigned<'a> {
            cts: &'a str,
            #[serde(skip_serializing_if = "Option::is_none")]
            neg: Option<bool>,
            src: &'a str,
            uri: &'a str,
            val: &'a str,
            ver: i64,
        }
        let digest = Sha256::digest(
            &serde_ipld_dagcbor::to_vec(&Unsigned {
                cts: &got.cts,
                neg: got.neg,
                src: &got.src,
                uri: &got.uri,
                val: &got.val,
                ver: got.ver,
            })
            .unwrap(),
        );
        let sig = Signature::from_slice(&got.sig).unwrap();
        assert!(l.signing_key.verifying_key().verify_prehash(&digest, &sig).is_ok());
    }

    #[test]
    fn descriptions_name_the_identities_and_the_fallback() {
        let d = pair_description("dan@sandmill.org", "dan+agent@sandmill.org");
        assert!(d.starts_with("Posted by dan+agent@sandmill.org on behalf of dan@sandmill.org,"));
        let own = pair_description("dan@sandmill.org", "dan@sandmill.org");
        assert!(own.starts_with("Posted by dan@sandmill.org, the owner"));
        for d in [&d, &own] {
            assert!(d.contains("\nFor more information, copy the link to this post and paste it at bsky.browserid.me"));
        }
        // Many vals, one badge name.
        assert_eq!(pair_name(&pair_val("a@example.com", "b@example.com")), PAIR_NAME_AGENT);
        assert_eq!(pair_name(&pair_val("a@example.com", "a@example.com")), PAIR_NAME_OWNER);
    }

    #[test]
    fn bsky_handle_identities_read_as_the_bare_handle() {
        // The whole point of the bsky-handle IdP is that the grantor is a
        // name with followers. "on behalf of dan.bsky.social" is that name;
        // "on behalf of dan.bsky.social@bsky.browserid.me" is plumbing.
        assert_eq!(display_identity("dan.bsky.social@bsky.browserid.me"), "dan.bsky.social");
        assert_eq!(
            display_identity("dan.bsky.social+fable@bsky.browserid.me"),
            "dan.bsky.social+fable"
        );
        // Case-insensitively, since identity strings are lowercased at store
        // boundaries but may arrive otherwise.
        assert_eq!(display_identity("dan.bsky.social@BSKY.BROWSERID.ME"), "dan.bsky.social");

        // Every other domain stays verbatim — for an email identity the
        // domain says who vouched for it, which is not noise.
        assert_eq!(display_identity("dan@sandmill.org"), "dan@sandmill.org");
        assert_eq!(display_identity("dan@at.browserid.me"), "dan@at.browserid.me");
        // A lookalike domain must not be stripped.
        assert_eq!(
            display_identity("dan.bsky.social@evil-bsky.browserid.me"),
            "dan.bsky.social@evil-bsky.browserid.me"
        );
    }

    #[test]
    fn badge_copy_uses_bare_handles_but_pair_vals_do_not_change() {
        let human = "dan.bsky.social@bsky.browserid.me";
        let agent = "dan.bsky.social+fable@bsky.browserid.me";

        let delegated = pair_description(human, agent);
        assert!(
            delegated.starts_with("Posted by dan.bsky.social+fable on behalf of dan.bsky.social,"),
            "{delegated}"
        );
        assert!(!delegated.contains("@bsky.browserid.me"), "{delegated}");

        let own = pair_description(human, human);
        assert!(own.starts_with("Posted by dan.bsky.social, the owner"), "{own}");

        let agent_alone = pair_description(agent, agent);
        assert!(
            agent_alone.starts_with("Posted by dan.bsky.social+fable, an agent owned by dan.bsky.social."),
            "{agent_alone}"
        );

        // Display is presentation only: the val is still keyed on the FULL
        // identity strings, so two different identities can never collide
        // onto one definition just because they render alike.
        assert_ne!(pair_val(human, agent), pair_val("dan.bsky.social", "dan.bsky.social+fable"));
    }

    /// Merging into a real-shaped service record must append exactly once per
    /// val, leave the existing `browserid-*` vocabulary alone, and be a no-op
    /// the second time (that no-op is what stops a re-put per post).
    #[test]
    fn merge_definition_is_additive_and_idempotent() {
        let mut record = serde_json::json!({
            "$type": "app.bsky.labeler.service",
            "createdAt": "2026-07-24T20:10:00.000Z",
            "policies": {
                "labelValues": ["browserid-verified", "browserid-on-behalf"],
                "labelValueDefinitions": [{
                    "identifier": "browserid-verified",
                    "severity": "inform", "blurs": "none", "adultOnly": false,
                    "defaultSetting": "warn",
                    "locales": [{"lang": "en", "name": "browserid verified", "description": "…"}],
                }],
            },
        });
        let (grantor, grantee) = ("dan@sandmill.org", "dan+agent@sandmill.org");
        let val = pair_val(grantor, grantee);

        assert!(merge_definition(&mut record, pair_definition(&val, grantor, grantee)));
        assert!(
            !merge_definition(&mut record, pair_definition(&val, grantor, grantee)),
            "second merge changes nothing"
        );

        let policies = &record["policies"];
        let values: Vec<&str> =
            policies["labelValues"].as_array().unwrap().iter().map(|v| v.as_str().unwrap()).collect();
        assert_eq!(values, ["browserid-verified", "browserid-on-behalf", val.as_str()]);
        let defs = policies["labelValueDefinitions"].as_array().unwrap();
        assert_eq!(defs.len(), 2, "exactly one definition per val");
        let mine = defs.iter().find(|d| d["identifier"] == val.as_str()).unwrap();
        assert_eq!(mine["severity"], "inform");
        assert_eq!(mine["blurs"], "none");
        assert_eq!(mine["locales"][0]["name"], PAIR_NAME_AGENT);
        assert!(mine["locales"][0]["description"].as_str().unwrap().contains(grantee));
        assert_eq!(record["createdAt"], "2026-07-24T20:10:00.000Z", "untouched");

        // A second pair sharing the badge name still gets its own definition.
        let val2 = pair_val("other@example.com", "other@example.com");
        assert!(merge_definition(
            &mut record,
            pair_definition(&val2, "other@example.com", "other@example.com")
        ));
        assert_eq!(record["policies"]["labelValueDefinitions"].as_array().unwrap().len(), 3);
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
        let label = l.sign_label("at://did:plc:abc/app.bsky.feed.post/xyz", LABEL_VERIFIED, "2026-07-24T00:00:00.000Z", false);
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
            neg: false,
            sig: l.sign(uri, LABEL_VERIFIED, cts, false),
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
        let label = l.sign_label(uri, LABEL_VERIFIED, "2026-07-24T00:00:00.000Z", false);

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
