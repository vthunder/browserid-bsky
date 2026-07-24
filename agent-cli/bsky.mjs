// The bsky-specific half of the flow: everything that is NOT plain browserid.
//
// The generic identity work (provisioning, warrants, access certs, the
// four-part presentation) lives in @browserid-ng/agent. What is special here
// is the POST ATTESTATION: a signature, made with the access key the access
// cert certifies, over the exact record being published. Without it a post
// carries provenance that does not verify — and earns no label.
//
// The canonical form below MUST match pds-bridge/src/attestation.rs byte for
// byte; `canonical_json_and_content_hash_are_stable` there pins the same
// vector this module's test uses.
import { createHash } from "node:crypto";

export const ATTESTATION_TYP = "browserid-bsky-post-attestation-v1";
export const POST_COLLECTION = "app.bsky.feed.post";

const b64u = (buf) => Buffer.from(buf).toString("base64url");

/** Deterministic JSON: object keys sorted recursively, compact — so signer
 *  and verifier hash identical bytes. (Rust: `attestation::canonical_json`.) */
export function canonicalJson(v) {
  if (Array.isArray(v)) return `[${v.map(canonicalJson).join(",")}]`;
  if (v && typeof v === "object") {
    const keys = Object.keys(v).sort();
    return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(v[k])}`).join(",")}}`;
  }
  return JSON.stringify(v);
}

/** base64url SHA-256 of the canonical record — what the signature covers. */
export function contentHash(record) {
  return b64u(createHash("sha256").update(canonicalJson(record), "utf8").digest());
}

/** The claims the access key signs. Field order is irrelevant (the canonical
 *  form sorts), but the values are not: `did` and `content_hash` are what bind
 *  the signature to one post in one repo. */
export function attestationClaims({ did, contentHash: hash, nonce, iat = Math.floor(Date.now() / 1000) }) {
  return {
    typ: ATTESTATION_TYP,
    did,
    collection: POST_COLLECTION,
    content_hash: hash,
    nonce,
    iat,
  };
}

/** Sign claims with the access key. Detached: base64url raw Ed25519 over the
 *  canonical claim bytes. */
export function signAttestation(claims, accessKey) {
  return accessKey.sign(canonicalJson(claims));
}

/**
 * Build a post record. Deliberately NO in-post verify link: the labeler is
 * the trust surface, and a link inside post content is author-controlled — it
 * can point at a convincing fake verifier, so teaching readers to click it
 * trains exactly the wrong reflex. Readers check a post by pasting its link
 * at the verifier they navigated to themselves.
 */
export function buildPostRecord({ text, createdAt = new Date().toISOString() }) {
  return {
    $type: POST_COLLECTION,
    text,
    createdAt,
  };
}

/** A single-use nonce: 32 random bytes, base64url. The attestation's replay
 *  guard, and the key `/verify?n=` looks a receipt up by. */
export function newNonce() {
  return b64u(globalThis.crypto.getRandomValues(new Uint8Array(32)));
}

// ---------------------------------------------------------------------------
// The bridge calls
// ---------------------------------------------------------------------------

async function callJson(http, url, { method = "POST", body, headers = {}, form } = {}) {
  const res = await http(url, {
    method,
    headers: form
      ? { "content-type": "application/x-www-form-urlencoded", ...headers }
      : { "content-type": "application/json", ...headers },
    body: form ? new URLSearchParams(form).toString() : JSON.stringify(body),
  });
  const json = await res.json().catch(() => ({}));
  return { res, json };
}

/** Create the Bluesky account. First-party only: the identity that approved
 *  must be the one provisioning, so present its OWN credential here. */
export async function provisionAccount(bridge, { presentation, handle, http = fetch }) {
  const { res, json } = await callJson(http, `${bridge}/browserid/provision`, {
    body: { presentation, handle },
  });
  if (!res.ok) throw new Error(`provision refused (${res.status}): ${json.error_description || json.error || ""}`);
  return json; // { did, handle, password }
}

/** Exchange the four-part presentation for a scoped bridge token (RFC 7521). */
export async function exchangeToken(bridge, { presentation, http = fetch }) {
  const { res, json } = await callJson(http, `${bridge}/browserid/token`, {
    form: { grant_type: "urn:x-browserid:grant-type:assertion", assertion: presentation },
  });
  if (!res.ok) throw new Error(`token refused (${res.status}): ${json.error_description || json.error || ""}`);
  return json; // { access_token, scopes, ... }
}

/**
 * Publish an attested post: build the record, sign it with the access key,
 * and hand the bridge record + attestation + access cert. This is the call
 * that produces a badge-worthy post.
 */
export async function attestedPost(bridge, { text, did, token, accessKey, accessCert, http = fetch }) {
  const nonce = newNonce();
  const record = buildPostRecord({ text });
  const claims = attestationClaims({ did, contentHash: contentHash(record), nonce });
  const { res, json } = await callJson(http, `${bridge}/browserid/post`, {
    headers: { authorization: `Bearer ${token}` },
    body: {
      record,
      attestation: { claims, sig: signAttestation(claims, accessKey) },
      accessCert,
    },
  });
  if (!res.ok) throw new Error(`post refused (${res.status}): ${json.error_description || json.error || ""}`);
  return { ...json, nonce, verifyUrl: `${bridge}/verify?n=${nonce}` };
}
