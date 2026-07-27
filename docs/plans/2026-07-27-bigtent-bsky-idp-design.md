# BigTent for atproto: the bsky-handle browserid IdP — design

**Date:** 2026-07-27
**Status:** draft for review
**Bean:** browserid-bsky-lczv (spec), under epic browserid-bsky-sxy0; build is
browserid-bsky-tw1d, demo rework browserid-bsky-90ut
**Context:** demo-impact discussion 2026-07-27. Persona lineage: this is
identity bridging as BigTent/sideshow did it for Yahoo/Gmail via OpenID,
rebuilt on the browserid-ng device-cert model with atproto OAuth as the
authentication method.

## Goal

Let a person who already owns a Bluesky handle use it as a first-class
browserid identity: **`<handle>@<idp-domain>`** (e.g.
`dan.bsky.social@bsky.browserid.me`), with ownership proven by atproto OAuth
instead of an email verification loop. Consequences, all free once the IdP
exists:

- The **grantor on warrants is their real handle** — consent screens, `whoami`,
  and labeler badges read *on behalf of dan.bsky.social*, a name with
  followers and reputation. The user has something at stake, which is the
  thing the current demo lacks.
- **No email anywhere in the journey.** Claim the handle, approve in one OAuth
  hop. The fallback-IdP email loop never fires.
- **Zero custody.** The IdP performs one authorization-code exchange to read
  the authenticated DID, then discards the tokens. It never holds write
  access to anyone's real account. (Posting *to* the real account is the
  separate, deferred OAuth-write relay, bean browserid-bsky-ru7u.)
- The identity works at **every browserid RP**, not just this bridge — "sign
  in with your Bluesky handle" for the whole ecosystem.

## Non-goals

- **No writes to the user's real PDS account.** Identity only. Posts still go
  to `<label>.at.browserid.me` accounts on our PDS, owned by the handle
  identity.
- **No DID local parts** (`did:plc:...@domain`). The broker/registrar
  lowercase identity strings at every store boundary; bsky handles are
  canonically lowercase so this is safe, but case-sensitive DID methods
  (did:key) would corrupt silently. Handles in the identity string, DID
  pinned internally.
- **Not replacing the email shapes.** Users without a Bluesky handle keep
  today's mint-a-handle flows; the demo grows a second entry path
  (bean browserid-bsky-90ut).
- **No reliance on atproto granular scopes** (still unfinalized). We request
  the bare `atproto` marker scope — documented as the identity-only minimum.

## Architecture

New IdP surface on the bridge's existing axum app (new `idp` module), serving
identity domain **D** (recommendation below). Per core spec §3.1/§7/§9 a
conformant primary must publish a support document and implement device-cert
issuance (both purposes) plus the access-cert mint API; the trust root is
DNSSEC, with the support document's `public-key` advisory only.

```
 dialog (broker) ── popup / top-level redirect ──▶ D's device_auth page
                                                     │  handle → DID resolve
                                                     │  atproto OAuth (PAR+PKCE+DPoP,
                                                     │    scope=atproto, sub==DID check)
                                                     │  DID pin table (sqlite)
                                                     ▼
                                        device certs (auth + authorization)
                                        signed by D's IdP key → back to dialog
```

Components on D:

- **DNS**: DNSSEC-signed discovery records for D per the DNS-discovery design
  (browserid.me zone is the natural parent — ops item: confirm the zone is
  signed and add D's record set).
- **`GET /.well-known/browserid`** — support document, built with
  browserid-core's `SupportDocument`: `public-key` (advisory; DNSSEC is the
  trust root), `device-cert`, `access-cert`, `device-authorization` (the
  device_auth page).
- **device_auth page** — first-party page implementing the claim flow below.
  The dialog's contract is popup + `postMessage({type:
  'browserid:device_certs', ...})` to `window.opener`, or the top-level
  redirect mode returning certs in the URL fragment to
  `/dialog/dialog.html?resume=device_auth` (dialog.js `primaryPopupFlow` /
  `primaryRedirectHop`). OAuth's top-level redirect fits the redirect mode
  natively; in popup mode the OAuth dance runs inside the popup and the final
  page posts back and closes. No iframes anywhere.
- **`POST` access mint** — standard §7: verify device cert + access request,
  issue 24h access cert, holder copied verbatim.
- **OAuth client metadata document** — served from D (client_id is its URL):
  `application_type: web`, confidential client with `private_key_jwt`
  (ES256) and a `jwks`, `dpop_bound_access_tokens: true`, `scope: atproto`,
  `grant_types: ["authorization_code"]` (no refresh — we discard tokens).
- **sqlite** — DID pin table (`handle, did, first_claimed, last_verified`),
  issued-cert bookkeeping, and (should-have, see Open questions) a status
  list for D's own certs at `/.well-known/browserid-status`.

## The claim flow (device_auth)

1. Dialog opens D's device_auth page carrying the pending device keys per the
   existing contract. The typed identity's local part pre-fills the handle;
   the page also accepts a bare handle typed directly.
2. **Resolve handle → DID**: DNS TXT `_atproto.<handle>` and
   `https://<handle>/.well-known/atproto-did` in parallel; DNS wins on
   conflict. **Bidirectional check** — the DID document's `alsoKnownAs` must
   claim the handle back — is mandatory; without it anyone can point a domain
   at someone else's DID. Resolve fresh at claim time (sub-10-minute cache
   rule for auth-critical paths).
3. DID document → PDS endpoint → `/.well-known/oauth-protected-resource` →
   authorization server metadata (verify `issuer` matches origin).
4. **OAuth**: PAR → authorize → token, PKCE S256, DPoP with per-server nonce
   retry (the 401 `use_dpop_nonce` handshake is normal, not an error).
5. **Verify `sub` == the DID from step 2**, then discard the tokens. The
   proof chain is: handle → DID (bidirectional) → auth server (discovered
   from that DID's PDS) → token whose `sub` equals that DID. Any break in
   the chain proves nothing.
6. **DID pin**: first claim records (handle, DID). Re-auth requires the same
   DID; mismatch → refuse and suspend the binding (see Reassignment).
7. **Issue device certs** — `purpose: authentication` and `authorization`,
   90-day TTL, `identities: ["<handle>@D"]`, signed by D's IdP key — and
   return them to the dialog per the contract.

Cert renewal repeats the flow; that is the interactive re-proof cadence for
the handle binding, and why no OAuth session needs to survive between visits.

## Assurance cadence — what backs each cert

- **Device cert (90d reference TTL; consider 30d)**: backed by an interactive
  OAuth proof at issuance. Because re-auth is one OAuth hop with no email
  loop, shortening the reference 90-day TTL is cheap here in a way it isn't
  for email identities — a knob worth turning down.
- **Access cert (24h)**: minted on device-cert validity, key possession, and
  holder match — **plus a fresh public re-verification of the binding**:
  bidirectional handle↔DID resolution (≤10-minute cache) must still match
  the pinned DID. Optionally also `com.atproto.sync.getRepoStatus` to catch
  takedown/deactivation. This bounds detection of handle moves, domain
  lapses, migrations, and takedowns to ~24h (or the next login), headlessly
  and custody-free. Mismatch fails closed; a resolution *outage* falls back
  to the ≤10-minute cache, mirroring the status-list degradation philosophy.
- **What we deliberately do not do in v1: check a stored OAuth session at
  mint.** Considered and deferred, not overlooked. It would re-introduce
  custody (refresh tokens + DPoP keys at rest), and atproto refresh tokens
  are single-use with mandatory rotation — a headless, CORS-open,
  concurrently-called mint endpoint doing rotation needs single-flight
  locking and still strands users whenever the stored session dies
  server-side. It also couples every browserid login of every handle
  identity to entryway uptime (the Persona availability lesson). And the
  probe is weaker than it looks: a live refresh token proves *our client's
  session* wasn't revoked, not that the user still controls the account.
  Its two genuine wins — the user can disconnect the IdP from their PDS's
  app-connections page, and ~24h detection of a compromise the PDS knows
  about — are real but modest (atproto session revocation itself lags up to
  15 minutes), and belong to a v2 *optional linked session*, not to the v1
  mint path.

## Warrants, consent, revocation — unchanged

The registrar layer is already issuer-agnostic, verified in code:

- Primary-issued device certs are accepted in the consent flow when
  `device_cert.iss()` equals the identity's own domain, with the issuer key
  resolved via DNSSEC discovery (`consent.rs:837-862`; the comment cites the
  guestbook bug that forced this). Deployment gate: the registrar's
  `issuer_resolver` must be configured.
- A primary login joins a broker account via `auth_with_presentation`
  (broker `routes/primary.rs`), landing as a verified `EmailType::Primary`
  email — `/account` and `/consent` then work identically, so the human
  approves and **revokes** grants for a handle identity exactly as today.
- Warrants stay signed by the user's config cert and registered against the
  registrar's status list; the bridge's 15-second staleness bound
  (bean browserid-bsky-qixi) and the kill-switch finale
  (bean browserid-bsky-tjat) apply unchanged.
- Grantor pinning already accepts any `local@domain` string
  (`check_grantor_pin` is even case-insensitive), and agent sub-identities
  mint as `dan.bsky.social+agent@D` under the domain-parametric
  `agent_name_allowed` rules.

## The bridge as RP

The bridge and the IdP are the same deployment, so the bridge can **pin D's
IdP key directly** (`Verifier::trust_primary`) rather than round-tripping
through discovery — DNS/DNSSEC discovery remains the path every *other* RP
uses. Provisioning and posting are unchanged: a `<handle>@D` grantor owns
`<label>.at.browserid.me` accounts like any identity. One presentation
decision: the labeler currently prints the full identity string; badge copy
should display the bare handle (`on behalf of dan.bsky.social`) — the full
string stays in the verify receipt.

## Handle reassignment

Handles are mutable pointers; the DID is the stable identifier. The failure
mode to design against: handle H released by DID A, later acquired by DID B —
keying on H alone silently transfers the identity. Policy:

- The DID pin is the identity's anchor. Re-verified (bidirectionally, fresh)
  at every cert issuance.
- On mismatch: the binding is **suspended** — no new certs for `<H>@D`.
  Outstanding access certs age out in ≤24h, device certs in ≤90d (a status
  list for D's certs shortens that to minutes — see Open questions).
  Warrants naming the identity as grantor stay revocable at the registrar as
  always.
- DID B may claim `<H>@D` only after the suspended binding is explicitly
  retired (cooloff length: open question). The atproto ecosystem's own
  sentinel for a failed bidirectional check is `handle.invalid`; we surface
  the same state as "handle moved" in verify receipts.

## Known landmines (from the identity-string audit)

- Identity strings survive every parser in both repos: parsing is
  `split_once('@')`-style throughout, dots in the local part are inert, and
  nothing hardcodes `browserid.me` in a way that misroutes other domains.
- `valid_agent_name` caps local parts at 64 chars — currently unwired, but if
  it ever gates primary identities, long custom-domain handles break. The
  broker dialog's `maxlength="80"` email inputs have the same edge. Accept
  for v1; note in the build bean.
- pds-bridge's `valid_label` (PDS handle labels) rejects dots — never feed a
  handle local part into it.
- The global `to_lowercase()` at store boundaries is exactly why DID local
  parts stay out of scope.

## Demo v2 (sketch — spec'd in bean browserid-bsky-90ut)

Landing page forks on one question: **"Already on Bluesky?"**

- *Yes* → claim `<handle>@D` (one OAuth hop, no email), agent requests the
  warrant with grantor pinned to the handle identity, badge reads *on behalf
  of dan.bsky.social*, finale is the revocation kill-switch.
- *No* → today's shapes (as-itself / on-behalf with a browserid email),
  unchanged, same finale.

## Implementation notes

- **Reference implementation: `mingo-idp`** (`~/src/mingo/mingo-idp`, ~2.4k
  lines of axum Rust + a 282-line `device-authorize.html`). It implements
  this exact primary-IdP shape against browserid-core: `/device_cert` issues
  the authentication cert plus a config cert whose identities include
  `<handle>+*@<domain>` (so agents sub-address cleanly), `/access/mint` is
  headless+CORS with holder copied verbatim, and its device-authorize page
  already speaks both dialog modes (popup `postMessage` and `return_url`
  fragment redirect) including the `hold`/`browserid:reissue` protocol. The
  substitution point is a single seam: replace its
  `/session/from-presentation` (external-presentation sign-in) with the
  atproto OAuth callback establishing the same first-party session cookie,
  and drop `/claim_handle` — atproto already guarantees handle ownership, so
  the OAuth-verified handle *is* the claim. Note mingo-idp issues all certs
  with `status: None`; we should do better (Open question 2).
- **Rust OAuth client**: `atproto-oauth` 0.14.5 (RFC 9449 DPoP with automatic
  nonce-retry middleware — the most error-prone piece, handled) — validate
  its confidential-client `private_key_jwt` support before committing;
  fallbacks are `atrium-oauth` 0.1.7 or the official
  `@atproto/oauth-client-node` as a small sidecar (also useful as a debugging
  oracle).
- **Empirical pre-checks before build** (cheap, load-bearing, both settled by
  one throwaway confidential client against bsky.social):
  1. Does the entryway accept `scope=atproto` standalone? (Documented yes;
     deployment unconfirmed.)
  2. Does a code-exchange-only flow (no refresh token use) complete cleanly
     for a confidential client?
- bsky.social accounts authenticate at the **entryway**, not the individual
  PDS — the protected-resource → auth-server discovery handles this;
  self-hosted PDSes resolve to themselves.

## Decisions (review 2026-07-27)

1. **Identity domain D = `bsky.browserid.me`.** Zero new infrastructure; the
   `browserid.me` zone is DNSSEC-signed (DS + DNSKEY verified), so D's
   discovery records slot in. Badge copy hides the mouthful (decision 4).
2. **Status list for D's own certs: yes, in v1.** A suspended (handle-moved)
   identity's certs die in minutes, not cert-TTL. Served at D's
   `/.well-known/browserid-status`, same machinery as the registrar's.
3. **Reassignment seasoning: 30 days.** A handle previously bound to a
   different DID may be re-claimed once the new DID has held it for 30 days,
   measured from the first re-claim attempt (record `(handle, new_did,
   first_seen)` on the failed attempt; grant when 30 days later the handle
   still resolves to that DID). Early-out: the old owner can retire the
   binding voluntarily by authenticating as the pinned DID — atproto OAuth
   accepts a DID as the account identifier — so graceful renames need no
   waiting.
4. **Badge copy: bare handle.** The labeler special-cases
   `@bsky.browserid.me` identities and displays the bare handle
   (`dan.bsky.social`, `dan.bsky.social+agent`); the full identity string
   stays in the verify receipt.
5. **Device-cert TTL: keep the 90-day reference constant for now.** A global
   drop to 30 days (all IdPs, not just this one) is a separate conversation.
6. **Linked session: dropped.** Not pursuing the optional stored OAuth
   session; mint-time public re-verification is the assurance mechanism.
