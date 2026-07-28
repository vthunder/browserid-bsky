---
# browserid-bsky-ru7u
title: 'OAuth write relay: agent posts to the user''s real account'
status: in-progress
type: feature
priority: high
created_at: 2026-07-27T12:54:00Z
updated_at: 2026-07-28T15:58:19Z
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
