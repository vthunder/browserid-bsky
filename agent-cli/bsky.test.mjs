import { test } from "node:test";
import assert from "node:assert/strict";
import { canonicalJson, contentHash, buildPostRecord, attestationClaims, signAttestation, attestedPost, bridgeWhoami } from "./bsky.mjs";

// THE cross-implementation vector. The identical record, canonical string and
// hash are pinned in pds-bridge/src/attestation.rs
// (`canonical_json_and_content_hash_are_stable`). If these two drift, the
// bridge rejects every signature this module makes.
const VECTOR = {
  $type: "app.bsky.feed.post",
  text: 'hello "world"\n',
  createdAt: "2026-07-24T00:00:00.000Z",
  facets: [
    {
      index: { byteStart: 0, byteEnd: 5 },
      features: [{ $type: "app.bsky.richtext.facet#link", uri: "https://x/y?a=1&b=2" }],
    },
  ],
  langs: ["en"],
};
const CANONICAL =
  '{"$type":"app.bsky.feed.post","createdAt":"2026-07-24T00:00:00.000Z","facets":[{"features":[{"$type":"app.bsky.richtext.facet#link","uri":"https://x/y?a=1&b=2"}],"index":{"byteEnd":5,"byteStart":0}}],"langs":["en"],"text":"hello \\"world\\"\\n"}';
const HASH = "YyPkrj7WIS8fjNwoclhYN1MN1S_8igt7LivI4Tk1ps8";

test("canonical JSON matches the Rust implementation byte for byte", () => {
  assert.equal(canonicalJson(VECTOR), CANONICAL);
});

test("content hash matches the Rust implementation", () => {
  assert.equal(contentHash(VECTOR), HASH);
  // Key order in the input must not matter — only the canonical form counts.
  const shuffled = { langs: ["en"], text: VECTOR.text, facets: VECTOR.facets, createdAt: VECTOR.createdAt, $type: VECTOR.$type };
  assert.equal(contentHash(shuffled), HASH);
});

test("a post record carries no in-post verify link", () => {
  // The labeler is the trust surface; an author-controlled link in post
  // content is phishable, so nothing here should add one.
  const record = buildPostRecord({ text: "héllo 🌍" });
  assert.equal(record.text, "héllo 🌍", "the text is the human's, unmodified");
  assert.equal(record.facets, undefined, "no facets — no verify link");
  assert.deepEqual(Object.keys(record).sort(), ["$type", "createdAt", "text"]);
});

test("an attestation signs the exact record and verifies against the access key", async () => {
  const { KeyPair, PublicKey } = await import("@browserid-ng/agent");
  const accessKey = KeyPair.generate();
  const record = buildPostRecord({ text: "hi" });
  const claims = attestationClaims({ did: "did:plc:abc", contentHash: contentHash(record), nonce: "N", iat: 1 });
  const sig = signAttestation(claims, accessKey);
  assert.ok(PublicKey.fromB64u(accessKey.publicKeyB64).verify(canonicalJson(claims), sig));

  // Tampering with the published record breaks the binding.
  const tampered = { ...record, text: record.text + " (edited)" };
  const wrong = attestationClaims({ ...claims, contentHash: contentHash(tampered) });
  assert.notEqual(canonicalJson(wrong), canonicalJson(claims));
});

test("attestedPost sends the record, its attestation, and the access cert", async () => {
  const { KeyPair, PublicKey } = await import("@browserid-ng/agent");
  const accessKey = KeyPair.generate();
  let seen = null;
  const http = async (url, init) => {
    seen = { url, init, body: JSON.parse(init.body) };
    return new Response(JSON.stringify({ uri: "at://did:plc:abc/app.bsky.feed.post/xyz", cid: "bafy" }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  };
  const out = await attestedPost("https://bridge.test", {
    text: "hello",
    did: "did:plc:abc",
    token: "bidb_tok",
    accessKey,
    accessCert: "ACCESS_CERT",
    http,
  });

  assert.equal(seen.url, "https://bridge.test/browserid/post");
  assert.equal(seen.init.headers.authorization, "Bearer bidb_tok");
  assert.equal(seen.body.accessCert, "ACCESS_CERT");
  // The signature must cover the record actually sent, under the nonce that
  // the in-post verify link embeds.
  const { record, attestation } = seen.body;
  assert.equal(attestation.claims.content_hash, contentHash(record));
  assert.equal(attestation.claims.did, "did:plc:abc");
  assert.equal(record.facets, undefined, "no in-post verify link");
  assert.ok(attestation.claims.nonce, "the nonce still guards replay and keys the receipt");
  assert.ok(PublicKey.fromB64u(accessKey.publicKeyB64).verify(canonicalJson(attestation.claims), attestation.sig));
  assert.equal(out.uri, "at://did:plc:abc/app.bsky.feed.post/xyz");
});

test("bridgeWhoami reports the target repo and backend under a bridge token", async () => {
  let seen = null;
  const http = async (url, init) => {
    seen = { url, init };
    return new Response(
      JSON.stringify({ did: "did:plc:real", grantor: "danmills.bsky.social@bsky.browserid.me", backend: "relay" }),
      { status: 200, headers: { "content-type": "application/json" } },
    );
  };
  const who = await bridgeWhoami("https://bridge.test", { token: "bidb_tok", http });
  assert.equal(seen.url, "https://bridge.test/browserid/whoami");
  assert.equal(seen.init.headers.authorization, "Bearer bidb_tok");
  assert.equal(who.did, "did:plc:real");
  assert.equal(who.backend, "relay");
});

test("bridgeWhoami surfaces a bridge refusal as an error", async () => {
  const http = async () =>
    new Response(JSON.stringify({ error: "invalid_token", error_description: "missing bridge token" }), {
      status: 401,
      headers: { "content-type": "application/json" },
    });
  await assert.rejects(() => bridgeWhoami("https://bridge.test", { token: "x", http }), /whoami refused \(401\)/);
});
