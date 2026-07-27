---
# browserid-bsky-lczv
title: 'Spec: bsky-handle browserid IdP (BigTent for atproto)'
status: completed
type: task
priority: high
created_at: 2026-07-27T12:53:49Z
updated_at: 2026-07-27T13:44:43Z
parent: browserid-bsky-sxy0
---

Write the design doc docs/plans/2026-07-27-bigtent-bsky-idp-design.md for an IdP where the local part is a Bluesky handle (e.g. dan.bsky.social@<idp-domain>) and ownership is proven via atproto OAuth (identity-only) instead of an email loop. Pin the DID at first claim; handle-moved => identity forks/refuses.

Inputs: (a) deep-dive of browserid-ng primary-IdP + device-model provisioning (well-known doc, cert issuance, dialog flow, registrar/consent/status-list placement for primary-rooted identities, what the bridge RP must trust); (b) current atproto OAuth client requirements (client metadata, PAR/PKCE/DPoP, minimal identity scope, handle->DID resolution + reassignment semantics).

- [x] Investigation A: browserid-ng primary/device-model internals
- [x] Investigation B: atproto OAuth client requirements (2026)
- [x] Draft spec: flows (claim, agent provisioning, warrant consent, revocation), components, domain choice, DID pinning, threat notes, open questions
- [x] User review of spec

## Summary of Changes

Spec landed as docs/plans/2026-07-27-bigtent-bsky-idp-design.md and reviewed 2026-07-27. All open questions resolved (recorded in the spec's Decisions section): D = bsky.browserid.me; v1 status list for D's certs; 30-day reassignment seasoning with voluntary-retirement early-out; labeler shows bare handles for @bsky.browserid.me; device-cert TTL stays 90d for now; linked session dropped. Assurance model: single OAuth code exchange at claim (zero custody), public bidirectional handle↔DID re-verification at every access mint. Reference skeleton: mingo-idp.
