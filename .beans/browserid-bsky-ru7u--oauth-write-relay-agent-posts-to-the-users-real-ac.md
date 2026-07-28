---
# browserid-bsky-ru7u
title: 'OAuth write relay: agent posts to the user''s real account'
status: in-progress
type: feature
priority: high
created_at: 2026-07-27T12:54:00Z
updated_at: 2026-07-28T16:44:59Z
parent: browserid-bsky-sxy0
---

Deferred piece 1 from the epic: bridge as atproto OAuth client holding write sessions for connected real accounts; warrants + attestation gate writes; bridge enforces narrow scopes over coarse OAuth grants. Custody trade-off documented in the epic. Revisit after the IdP ships.

## Direction locked 2026-07-28: web-first dashboard demo (v3)

After discussion, the write-relay ships as part of a WEB-FIRST demo, not bolted into the agent flow. Decisions:
- ENTRY: bsky.browserid.me dashboard. browserid.me links to it. Login = a text box where the user types their Bluesky handle; the RP uses browserid's DIRECTED query to auth that exact identity (<handle>@bsky.browserid.me), kicking the IdP OAuth. Secondary 'use any email' path → mint a handle.
- DASHBOARD: choose 'create a local handle' (mint) OR 'connect existing handle for write' (write-relay = 2nd OAuth, transition:generic). Then it shows a PERSONALIZED copy-paste delegation prompt with the grantor baked in (structurally fixes the grantor-guess bug). Also the manage/revoke surface.
- AGENT role shrinks to warrant + post. No more 'do you have a handle' interrogation.
- Write-relay = the connect-existing branch: 2nd OAuth (transition:generic) → encrypted write session keyed by DID → posts for that grantor relay to the real account; NO local handle created for this branch.
- Two OAuth clients (identity hand-rolled zero-custody; write via atproto-oauth crate). Full provenance records in the real repo (trustless verify; consent covers it, user can delete). Envelope-encrypt write-session token columns. Allowlist v1. Kill switch = warrant revoke only (drop app-disconnect). Enforcement boundary: one method, hardcoded collection allowlist, only via attributed_post, repo=pinned DID.
- Build now includes FRONTEND (dashboard) — a new surface. Most security-sensitive build yet → full build+adversarial-review, prod-gated.

## Phase 1 landed 2026-07-28 (backend, allowlist-gated-off)

Write-relay backend built + adversarially reviewed + fixed. Ships inert: WRITE_RELAY_ALLOWLIST empty => BridgeState.relay = None, post path byte-identical to today, /idp/connect 404s. New pds-bridge/src/relay/ (mod, oauth, crypto, routes, connect.html) + edits to store/routes/lib/main/idp/guide. 145 lib + 7 integration tests.

- OAuth: extended the hand-rolled client (verdict C) — the crate has no XRPC/createRecord client, 209 deps; identity flow's structural zero-custody untouched (new sibling functions for the write session).
- Enforcement boundary held under adversarial review: create_own_record checks a hardcoded 3-collection allowlist first, repo always = session's pinned DID (not a param), single entry via attributed_post. Reviewer could not break it.
- Connect crux: stores a session only when OAuth sub == pinned DID; allowlist + browser-binding + suspension re-checked at start AND callback.
- Encryption: XChaCha20-Poly1305, per-column AAD (write_session:<did>:<column>), hard-fail if key unset (no world-readable generated key).
- Review findings all fixed: CSRF same-origin guard on the 2 state-changing POSTs; key hard-fail; allowlist is a live post-path kill switch.
- Kill switch = warrant revoke (checked before backend selection). Provenance fails loudly (502 posted:true/attested:false).

Remaining: Phase 2 (dashboard + connect UI), Phase 3 (directed provisionEmail login + personalized prompt), then lift allowlist after observing a real refresh cycle + expiry. Enable-gated in prod (empty allowlist) until then.

## Phase 2 build plan (2026-07-28, this session)

Dashboard + connect UI, landed inert behind the same relay gate (relay=None => every route 404s).

- [x] store.rs: dashboard_sessions table + create/get/delete (+expiry sweep on write)
- [x] store.rs: grantor-scoped reads: warrants_for_grantor (LIMIT), tokens_for_grantor (live only), audit_for_grantor
- [x] relay/dashboard.rs: page/login/me/agents/logout — login first-party-only + rejects agent-scoped presentations (F1) + same-origin guard (F2)
- [x] relay/dashboard.html: undirected login, write-connection card, agents list, revoke link, copyable prompt; textContent-only; escaped template tokens; frame-ancestors none
- [x] relay/routes.rs: require_human_session (dashboard OR idp session); connect.html links back to /dashboard; frame-ancestors on connect page
- [x] tests: 15 new dashboard tests incl. F1 as-you-agent, F2 login CSRF
- [x] cargo test green (157 lib + 7 integration); adversarially reviewed (1 medium F1 + lows fixed)

## Phase 2 landed 2026-07-28 (dashboard + connect UI, allowlist-gated-off)

Dashboard shell + connect UI built, adversarially reviewed, fixes applied,
lands inert (relay=None => every /dashboard* + /idp/connect* route 404s;
existing paths byte-identical). 157 lib + 7 integration tests.

New: relay/dashboard.rs + dashboard.html (page, login, me, agents, logout);
dashboard_sessions table (plain-cookie RP session, SEPARATE from
idp_sessions, per decision); grantor-scoped store reads; require_human_session
so a dashboard sign-in carries into the connect flow without re-auth.

Sign-in is a plain undirected navigator.id.request for phase 2; the directed
provisionEmail handle box + identity-match check is phase 3.

Adversarial review (subagent): boundary holds against all 6 attack classes.
Findings fixed:
- F1 (MEDIUM): the IdP mints an "as-you" agent cert whose identity IS the
  handle (certs.rs:266), so an agent's warrant with grantor==grantee==handle
  cleared login's first-party gate — a delegate with only posting scopes could
  open the management page. Fixed: login now also rejects any presentation
  carrying a bridge-grammar scope (a human's plain login carries none; `login`
  is dropped by the grammar). Tested.
- F2 (low): added require_same_origin to /dashboard/login (forced-login CSRF
  parity with logout). Tested.
- F3 (low): sweep expired dashboard_sessions on each sign-in.
- F4 (low): LIMIT on warrants_for_grantor (was unbounded per page load).
- F5/F6/F7/F8 (info): HTML-escape the operator-config template tokens;
  frame-ancestors 'none' on both HTML pages; .catch on the agents fetch;
  comment the session-shadowing precedence in require_human_session.
- F9 (info): moot — relay routes are always registered ahead of the fallback
  proxy, so /dashboard* never reaches the PDS proxy (test-covered).

Remaining: Phase 3 (directed provisionEmail login + identity-match +
personalized prompt polish + "or use any email" mint path), then lift the
allowlist after observing a real refresh cycle + expiry in prod.

## Phase 3 built 2026-07-28 (directed login + identity-match + prompt)

Directed provisionEmail sign-in added to the dashboard; still allowlist-gated.
158 lib + 7 integration tests.

- dashboard.html: a "your Bluesky handle" text box → directed
  navigator.id.request({ provisionEmail: "<handle>@<D>" }) (skips the
  chooser). Live identity preview. "or sign in with any email" secondary =
  undirected request. IDP_DOMAIN templated into JS to build the identity.
- dashboard.rs: LoginReq gains optional `expected`; login() refuses when the
  cryptographically-verified identity != expected (case-insensitive), naming
  both. NOT an authorization input — the session is always opened for the
  verified grantor, so a forged `expected` can only make a login FAIL, never
  redirect it. This is the design's mandatory "verify the returned
  presentation's identity equals what it asked for" (provisionEmail steers,
  does not bind).
- Prompt generator already shipped in phase 2 (plain text, grantor named).
- Verified provisionEmail is plumbed in the broker's include.js/dialog.js
  (include.js:880, dialog.js:1655/1717).

Then: lift allowlist after observing a real refresh cycle + expiry in prod.

## Phase 3 reviewed clean 2026-07-28

Focused adversarial review of the directed-login delta: main claim HOLDS —
`expected` is not an authorization input (session always opened for the
verified grantor; a forged `expected` can only make a login fail, never
redirect it). No XSS in the new markup; templated IDP_DOMAIN safe inside the
JS string. No blocking findings. Two INFO notes deferred (not applied, kept
the reviewed diff for deploy):
- the page-level `expected` var could go stale if a user abandons a directed
  dialog then clicks "any email" (fail-open for the UX guard only, never
  authz);
- the mismatch error reflects the caller's own `expected` back to itself
  unbounded (inert: textContent + JSON, self-directed).
Both are candidate follow-ups if we tighten the dashboard UX.

## 2026-07-28: open the relay for live testing (WRITE_RELAY_ALLOWLIST=*)

Decision (user): no external audience knows about this yet, so allowlisting
one tester vs opening to all is the same exposure today. Added an explicit
`*` wildcard to Allowlist so "open to everyone" is a single deliberate value
(empty still = nobody; missing var still = closed). Boot logs a WARN when
open. Enabled in prod: WRITE_RELAY_ALLOWLIST=* + WRITE_SESSION_KEY set on the
bsky-bridge dokku app. Still un-observed in prod: the first real
connect/post/refresh/expiry cycle — that is the live test this unblocks.

## 2026-07-28: agent tooling — CLI shares the wallet's identity store

Feedback from a real agent run (~/browserid-setup-transcript.md): an MCP-first
agent can get the warrant via @browserid-ng/wallet but the wallet has no tool
to sign a Bluesky post (only sign_guestbook, hardcoded), so it dead-ends; and
the @browserid-ng/bsky CLI kept a SEPARATE identity store, forcing a duplicate
approval + a second identity.

Fix (user's design — don't bake bsky into the MCP server; make the CLI consume
wallet-managed identities):
- @browserid-ng/bsky (agent-cli) now reads/writes the SHARED
  ~/.browserid/agent-credential.json (wallet's exact {credential,grants}
  format). Both tools use @browserid-ng/agent, so the formats already matched.
  Minted-account did/handle moved to a bsky-account.json sidecar so wallet
  writes can't clobber them. BROWSERID_HOME shared; BROWSERID_BSKY_HOME still
  overrides for a separate actor.
- setup/delegate now REUSE an existing wallet credential (add a warrant via
  requestWarrants) instead of provisioning a second identity / refusing.
- New no-mint relay post: `post` derives the target repo from
  /browserid/whoami and posts to the REAL account when the grantor connected
  write access — no provisioned account needed. Backend-aware output; whoami
  shows relay-vs-bridge. New bsky.mjs `bridgeWhoami` + tests (7 pass).
- So the MCP flow is now: wallet authorize+get_assertion → shell
  `browserid-bsky post` reusing that approval. No bsky tools in the MCP server.
- Wallet `authorize` grantor doc (F1): document the <handle>@bsky.browserid.me
  shape + "pass it VERBATIM, don't normalise to an email".

To publish (needs npm OTP): @browserid-ng/bsky 0.2.0 (agent-cli),
@browserid-ng/wallet 0.4.2 (browserid-ng/sdk/wallet).
