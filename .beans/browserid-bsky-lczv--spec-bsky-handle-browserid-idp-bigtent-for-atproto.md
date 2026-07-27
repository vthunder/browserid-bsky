---
# browserid-bsky-lczv
title: 'Spec: bsky-handle browserid IdP (BigTent for atproto)'
status: in-progress
type: task
priority: high
created_at: 2026-07-27T12:53:49Z
updated_at: 2026-07-27T13:12:17Z
parent: browserid-bsky-sxy0
---

Write the design doc docs/plans/2026-07-27-bigtent-bsky-idp-design.md for an IdP where the local part is a Bluesky handle (e.g. dan.bsky.social@<idp-domain>) and ownership is proven via atproto OAuth (identity-only) instead of an email loop. Pin the DID at first claim; handle-moved => identity forks/refuses.

Inputs: (a) deep-dive of browserid-ng primary-IdP + device-model provisioning (well-known doc, cert issuance, dialog flow, registrar/consent/status-list placement for primary-rooted identities, what the bridge RP must trust); (b) current atproto OAuth client requirements (client metadata, PAR/PKCE/DPoP, minimal identity scope, handle->DID resolution + reassignment semantics).

- [x] Investigation A: browserid-ng primary/device-model internals
- [x] Investigation B: atproto OAuth client requirements (2026)
- [x] Draft spec: flows (claim, agent provisioning, warrant consent, revocation), components, domain choice, DID pinning, threat notes, open questions
- [ ] User review of spec
