# Bluesky PDS bridge (B1) — design

**Date:** 2026-07-24
**Status:** design accepted (B1 shape); handles under `*.at.browserid.me`
**Bean:** browserid-bsky-aa7g (migrated from browserid-ng-ezk6 on repo split)
**Context:** option-B discussion 2026-07-23/24; audit doc
`2026-07-23-spec-code-divergence-audit.md` **in the browserid-ng repo** (deps noted in Security).

## Goal

Give browserid-ng identities a real presence on the AT Protocol network, and
give atproto the thing it lacks: **scoped, revocable, attributable agent
delegation**. A user provisions a Bluesky account with their browserid
identity; their agent obtains a human-approved warrant and posts to the whole
Bluesky network through the standard four-object bundle → token exchange —
verified fail-closed like any browserid RP.

This dogfoods the full stack (consent card → warrant registry → grant
exchange → scoped delegated writes) on a public network, and is the credible
basis for a later upstream proposal (bundle-native auth / verifiable
delegation in atproto).

## Non-goals

- No DID-based browserid identities. Identities remain emails; the trust root
  remains DNSSEC on the email domain. The DID exists only on the atproto side
  of the bridge.
- No custodial bridging of accounts hosted elsewhere (that was rejected
  "Shape A"). Only accounts on our PDS get the feature.
- Not (yet) a patched/native PDS. B1 uses the stock reference PDS; a
  Rust-native integration (rsky-pds) is a later phase.
- Human sign-in *to Bluesky clients* with browserid is out of our control
  (client-side); browserid governs provisioning and agent delegation.

## Architecture

Two services beside (not inside) the broker. The broker participates only in
its ordinary roles: IdP/fallback and warrant registry. The bridge is a plain
relying party — it verifies bundles with `browserid-rp` exactly as any
third party would; browserid.me holds no special position.

```
                    ┌────────────────────────── bsky.browserid.me ─┐
 agent ── bundle ──▶│ pds-bridge (Rust, axum, browserid-rp)        │
 human ── https ───▶│  /browserid/*  provision + token endpoints   │
 relay ── crawl ───▶│  /xrpc/*       scoped proxy / passthrough    │
                    └───────────────┬──────────────────────────────┘
                                    │ internal (admin + service auth)
                            ┌───────▼────────┐
                            │ @atproto/pds   │  accounts, repos, blobs,
                            │ (stock, TS)    │  did:plc ops, firehose
                            └───────┬────────┘
                                    │ federation
                              relay → AppView → all of Bluesky
```

- **`pds-bridge`** — new Rust crate/app. Owns the single public origin
  `https://bsky.browserid.me`. Terminates `/browserid/*` (provisioning, token
  exchange, receipts) and mediates `/xrpc/*`: requests bearing a bridge token
  are scope-enforced then forwarded; everything else (human clients, relay
  crawl, firehose websocket) is transparently proxied to the PDS.
- **PDS** — reference `@atproto/pds`, unmodified, network-internal (e.g.
  `pds.internal`), configured to believe its public URL is
  `https://bsky.browserid.me`. Holds account signing/rotation keys
  (secp256k1/p256) and performs did:plc registration.
- **Deployment** — two dokku apps beside the broker. The bridge is in the hot
  path for all PDS traffic (including the relay websocket); it must
  passthrough-stream anything it doesn't understand. Fail-closed applies only
  to bridge-token traffic; anonymous/human traffic is the PDS's own concern.

### Why not in the broker

The broker is an issuer; the PDS/bridge is a relying party — the *audience*.
Folding the RP into the issuer invites verification shortcuts that would
break the dogfooding claim, couples a storage-heavy federation daemon to IdP
availability, and makes the design browserid.me-only instead of something any
operator can run.

## Identity model across the bridge

| browserid side | atproto side | binding |
|---|---|---|
| `dan@sandmill.org` (grantor) | `did:plc:…` + handle | bridge `accounts` table, created at provisioning |
| grantee (agent identity, possibly cross-issuer) | — | surfaced in receipts/attribution only |
| warrant audience | `https://bsky.browserid.me` | the bridge origin — protocol-consistent RP audience |
| warrant scopes | atproto granular scopes | opaque to browserid (RP-interpreted), parsed by the bridge |

- **Grantor → DID.** The email that provisioned the account is the only
  identity that can grant agent access to it. At token exchange the bridge
  resolves `verified.email` (grantor) → DID; unknown grantor → 403 with a
  provisioning hint.
- **Grantee is attribution, not access.** The grantee (e.g.
  `dan+claude@sandmill.org`, or a cross-issuer service identity) never maps
  to an atproto account; it appears in the audit log, receipts, and phase-2
  provenance. Because the bridge verifies with `browserid-rp` (core path),
  cross-issuer grantees work — unaffected by the hosted-verifier gap
  (bean `i9rr`).
- **Keys never bridge.** Ed25519 (browserid) and secp256k1/p256 (atproto)
  stay on their own sides; the PDS custodies atproto keys, as any PDS does.
  At provisioning the bridge offers a one-time downloadable **recovery
  rotation key** so the user can escape the operator.

## Scope vocabulary

Adopt atproto's granular **auth scopes** syntax from the start (tracking the
upstream spec as it stabilizes), e.g.:

- `repo:app.bsky.feed.post?action=create` — create posts
- `repo:app.bsky.feed.like` — full CRUD on likes
- `rpc:app.bsky.feed.getTimeline?aud=*` — call a read method
- `blob:image/*` — upload image blobs (needed for image posts)

On the browserid side these are opaque strings in the warrant (per protocol
§5 — scopes are interpreted only by the RP), so nothing in core changes. The
bridge parses them strictly: unknown scheme/NSID/param → the scope grants
nothing (fail-closed), and consent-card display falls back to the raw string.

## Flows (wire level)

### 1. Provisioning (human, one-time)

1. User visits `https://bsky.browserid.me/`, signs in with browserid (normal
   RP login; warrant audience `https://bsky.browserid.me`, `login` scope).
2. `POST /browserid/provision` `{ bundle, handle: "dan" }` →
   bridge verifies the bundle (fail-closed), checks handle availability and
   the reserved-label list, then via PDS admin API: mint invite code →
   `com.atproto.server.createAccount` (handle under the handle zone,
   bridge-generated strong password) → PDS registers `did:plc:…`.
3. Bridge stores `{ email, did, handle, created_at }`, returns
   `{ did, handle, password }` — the password shown once, for use in ordinary
   Bluesky clients (until atproto OAuth client support makes this nicer).
4. Offer recovery-key download; optionally write the linkage record
   (phase 2: `alsoKnownAs` / lexicon linkage attestation).

Re-authentication to the bridge dashboard (grants list, receipts, account
deletion, password reset) is always browserid login mapped by grantor email.

### 2. Agent grant + token exchange

1. Agent hits any bridge XRPC route without a token → `401` with
   `WWW-Authenticate: BrowserID realm="bsky.browserid.me"
   audience="https://bsky.browserid.me" token_endpoint="/browserid/token"
   scopes="repo:app.bsky.feed.post?action=create …"` (rp_auth challenge;
   RFC 8414 metadata at `/.well-known/oauth-authorization-server` via
   `oauth_metadata_with_scopes`).
2. Agent requests a warrant through the existing broker consent flow
   (agent-api §6): audience `https://bsky.browserid.me`, the granular scopes
   it wants. User approves one consent card; config cert signs the warrant.
3. `POST /browserid/token` (form): `grant_type=
   urn:x-browserid:grant-type:assertion`, `assertion=<four-object bundle>`.
4. Bridge verifies via `browserid-rp::Verifier` — trusted issuers: DNSSEC
   primaries + accepted fallbacks `{browserid.me}`; **`fail_closed(true)`**,
   all three status authorities checked (depends on bean `4lxl` for the
   library default; the bridge opts in regardless).
5. Resolve grantor → DID; intersect requested/warrant scopes; issue an opaque
   bridge token bound to `{ did, grantor, grantee, grantee_issuer, holder,
   scopes, warrant_status_ref }`, TTL ≤ 1 h (and never beyond warrant `exp`).
   Response: `TokenResponse { access_token, token_type: "Bearer",
   expires_in, scope, holder }` (rp_auth.rs shape).

### 3. Scoped writes (agent)

Agent speaks **standard XRPC** against `https://bsky.browserid.me` with the
bridge token — from its point of view this is just a PDS.

1. `POST /xrpc/com.atproto.repo.createRecord`
   `{ repo: <did>, collection: "app.bsky.feed.post", record: {…} }`.
2. Bridge: token → binding; require `repo == bound did`; map
   (endpoint, params) → required scope (`createRecord` + collection →
   `repo:<collection>?action=create`; `uploadBlob` → `blob:<mime>`; reads →
   `rpc:<nsid>`); reject anything unmapped or uncovered (403, fail-closed —
   unknown lexicons grant nothing).
3. Forward to the PDS with bridge service credentials for the account;
   stream the response back. Append an audit-log row
   `{ ts, did, grantor, grantee, holder, nsid, scope, result }` — this log is
   the receipts source and the phase-2 provenance feed.

### 4. Revocation

- **At exchange:** the three status checks fail-closed; a revoked warrant
  mints nothing.
- **Live tokens:** bridge re-checks the bound `warrant_status_ref` via
  `StatusCache` (≤ 5 min TTL) on use; revoked → token dropped immediately.
  Bound above by token TTL ≤ 1 h regardless.
- **User surfaces:** the grant appears as a normal warrant in the account UI
  (audience `bsky.browserid.me`) — revocation there is the kill switch. The
  bridge dashboard additionally lists per-agent receipts and offers account
  deletion (PDS `deleteAccount` + PLC tombstone).

## Handle zone (decided: `*.at.browserid.me`)

User handles live under `*.at.browserid.me` (`@dan.at.browserid.me` — reads
naturally, app-neutral). The service origin stays `bsky.browserid.me` (infra
naming, not user identity).

- A dedicated sub-zone (rather than apex `*.browserid.me`) is right
  operationally: no interaction with existing broker vhosts, and no
  reserved-label/phishing management on the apex (`login.browserid.me` as a
  user handle would be bad). Wildcard DNS for the zone points at the bridge,
  which serves `/.well-known/atproto-did` per handle.
- "at" over "bsky": a handle is network-wide atproto identity, not
  Bluesky-app-specific, and "bsky" carries mild implied-affiliation optics
  with Bluesky PBC's own domains.
- Known wrinkle, accepted: if browserid later mints email identifiers under
  handle domains, they'd read `<label>@<handle>.at.browserid.me` — a double
  "at". Cosmetic only; and such domains would need `_browserid` DNS records
  under the zone, which we control.
- Stakes are low: handles are mutable atop the stable DID, so the zone can be
  revisited without stranding anyone. Users with their own domains can use
  them as handles regardless (`_atproto` TXT beside their `_browserid`).

Reserved labels within the zone: `www`, `api`, `pds`, `admin`, `xrpc`, plus
a profanity/impersonation list.

## Security considerations

- **Bridge credentials.** The bridge holds PDS admin + per-account service
  credentials — same operator trust domain as the PDS itself (which already
  custodies signing keys), but isolate anyway: dedicated admin token,
  network-internal PDS, no public admin surface.
- **Fail-closed posture.** Depends on audit beans: `4lxl` (status checks
  fail-closed — the bridge opts in via `fail_closed(true)` from day one) and
  `68av` (mint jti replay — broker-side, closes a replay window upstream of
  the bridge). `i9rr` does not block: the bridge verifies via core, not the
  hosted verifier.
- **Audience discipline.** Exact-match `https://bsky.browserid.me` on both
  assertion `aud` and warrant `audience`; one canonical origin, no
  alternates.
- **Scope parser strictness.** Unknown scope shapes and unmapped XRPC
  endpoints deny by default. The scope→endpoint map is an allowlist.
- **Blast radius.** A compromised bridge can act as its own accounts (as any
  PDS operator can); it cannot mint browserid credentials or forge warrants,
  and every action it takes via bridge tokens is audit-logged against a
  verified bundle. Receipts + phase-2 provenance make abuse visible.
- **Abuse/rate limits.** Per-token and per-account XRPC rate limits at the
  bridge; provisioning gated by browserid login + per-email account cap (1).

## Phasing

1. **P1 — end-to-end demo:** provision + `repo:app.bsky.feed.post?action=create`
   + `blob:image/*`; wallet MCP demo: "ask your agent to post to Bluesky" —
   the guestbook, but on a real network. Receipts in the dashboard.
2. **P2 — provenance:** linkage attestation (repo record + `alsoKnownAs`),
   and per-post attribution — a `me.browserid.provenance` record (post rkey →
   grantor/grantee/warrant receipt) and/or a labeler surfacing "posted by
   agent X under a warrant from Y", receipt verifiable via detached-proof
   primitive (§6.3).
3. **P3 — native:** evaluate rsky-pds (Rust) with `browserid-rp` in-process:
   collapse the proxy, enforce scopes at the repo-write layer.
4. **P4 — upstream:** with P1–P2 running, propose bundle-native auth /
   verifiable delegation to the atproto community (their granular-scope work
   is the natural docking point).

## Open questions

- Human client credential story: per-account password now; adopt atproto
  OAuth AS role later so Bluesky clients can log in without a stored
  password?
- Default read scopes: should `repo:…` grants imply the reads needed to
  render one's own posts, or keep reads strictly `rpc:`-scoped?
- Bridge token form: opaque + DB (proposed) vs JWT; DPoP binding later?
- PDS sizing/limits and relay crawl requirements at multi-account scale.
