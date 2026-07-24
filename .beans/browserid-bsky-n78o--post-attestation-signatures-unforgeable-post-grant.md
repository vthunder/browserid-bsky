---
# browserid-bsky-n78o
title: 'Post-attestation signatures: unforgeable post<->grantee binding (provenance phase 2)'
status: in-progress
type: feature
priority: high
created_at: 2026-07-24T15:59:35Z
updated_at: 2026-07-24T18:56:19Z
blocked_by:
    - browserid-bsky-27c0
---

The crux of on-atproto provenance. Phase-1 provenance proves the DELEGATION (warrant) but the link 'grantee produced THIS post' is only PDS-asserted — a malicious/compromised PDS or bridge could fabricate posts and attach the public (inert, reusable) warrant. Close it: the GRANTEE signs each post; provenance carries the signature so anyone can verify, offline, that this identity produced this exact content under this authority — independent of the PDS.

Design:
- Sign CONTENT, not the commit CID (agent can't know the PDS commit CID beforehand): grantee signs a canonical hash of the post record it authors; reader recomputes from the published post.
- Key chain: signature by the ACCESS key -> access cert -> grantee identity -> IdP (DNSSEC-rooted). Include the access cert in provenance (or reference a once-published copy).
- REPLAY GUARD (Dan): the signed payload MUST include a nonce/jti + iat/timestamp AND bind to the target {did, collection} so a captured signature can't be replayed onto a different or duplicate post. Canonical attestation object, e.g. {typ, did, collection, content_hash, nonce, iat}.
- This IS the typed-signing extension resurfacing: a 'post attestation' is another domain-separated typed payload alongside the SBO envelope. See browserid-ng docs/plans/2026-06-24-typed-signing-extension-design.md — design together.
- Touches: agent SDK (sign at post time), bridge API (accept the signature alongside createRecord; can't be minted bridge-side without the grantee key), provenance record schema.

Blocked-by/related: browserid-bsky-27c0 (phase 1), browserid-ng typed-signing design, i9rr (cross-issuer grantee).
