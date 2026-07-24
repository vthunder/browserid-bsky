---
# browserid-bsky-27c0
title: 'P2 provenance: represent agent/warrant attribution on Bluesky (as-itself vs on-behalf-of)'
status: todo
type: feature
priority: high
created_at: 2026-07-24T14:52:18Z
updated_at: 2026-07-24T14:52:18Z
---

atproto has NO native 'on behalf of' — every post's author is the repo DID. Both warrant shapes post as the same DID; the grantor/grantee distinction lives only in the browserid warrant and must be surfaced as ADDED data.

Two attribution paths to support + convey:
1. AS ITSELF (grantor==grantee, e.g. danmills+bluesky@sandmill.org): the agent IS the account. No on-behalf metadata needed. This is what the current bridge does.
2. ON BEHALF OF (grantor=danmills@sandmill.org, grantee=agent): human keeps attribution, agent is actor. Requires relaxing the bridge's provision rule (currently requires grantee==grantor), binding the account to the GRANTOR, allowing warrants where grantee!=grantor, recording grantee as actor. (Cross-issuer agent -> needs browserid-ng i9rr.)

Ways to convey on Bluesky (explore):
- me.browserid.provenance sidecar record (or custom field on the post) carrying {grantor, grantee, warrant receipt} — verifiable by fetching the repo; invisible in stock clients.
- a browserid LABELER stamping 'agent X on behalf of Y (verified)' — shows in subscribing clients; most work, best UX.
- receipt verifiable via the detached-DNSSEC-proof primitive (core §6.3).

Deliverable: bridge supports both warrant shapes; at least one on-wire representation of provenance; demo both. Depends on i9rr for cross-issuer on-behalf.
