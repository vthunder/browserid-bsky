---
# browserid-bsky-27c0
title: 'P2 provenance: represent agent/warrant attribution on Bluesky (as-itself vs on-behalf-of)'
status: in-progress
type: feature
priority: high
created_at: 2026-07-24T14:52:18Z
updated_at: 2026-07-24T15:59:56Z
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



## Refined model (2026-07-24, with Dan)

Drop human/agent labeling entirely — provenance states only IDENTITIES + the delegation edge, per the warrant model (attribution -> grantor; execution -> grantee). Account binds to grantor (already the bridge behavior). as-itself: grantor==grantee. on-behalf: grantor!=grantee.

Root/base identity is DERIVED at read time (strip +tag from grantor) and PROVEN by the config cert (its identities glob includes the base, e.g. danmills@ + danmills+*@). Not stored. This answers "whose agent" without a type claim.

### Phase 1 (THIS chunk): sidecar records, verifiable delegation on-repo
- Publish the warrant ONCE as a me.browserid.warrant record (warrant JWS + config cert) in the account repo; dedup by warrant hash (idempotent rkey). NOT per-post (Dan: per-post duplication is wasteful).
- Per post: a me.browserid.provenance record (rkey = post rkey) referencing the warrant record URI + {post uri/cid, attributedTo=grantor, executedBy=grantee}. Tiny pointer.
- Requires: bridge persists warrant_jws+config_cert at token exchange (new warrants table; token references warrant_hash), and writes the two record types at post time via the account session.
- HONEST CAVEAT recorded in the record: the post<->grantee link is PDS-asserted at this stage (see phase 2). The DELEGATION is verifiable; the binding to this exact post is not yet.

### Phase 2: unforgeable post<->grantee binding (own bean)
Grantee signs the post -> provenance carries the signature. See sibling bean. This is the crux (unforgeable even by the bridge/PDS); phase 1 is display-grade only.

### Both paths demo
Exercise on-behalf (grantor!=grantee, same issuer; cross-issuer needs browserid-ng i9rr) and show the two provenance records differ only by executedBy!=attributedTo.
