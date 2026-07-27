---
# browserid-bsky-tw1d
title: 'Build: bsky-handle IdP + handle-identity provisioning'
status: in-progress
type: feature
priority: normal
created_at: 2026-07-27T12:54:00Z
updated_at: 2026-07-27T13:45:20Z
parent: browserid-bsky-sxy0
blocked_by:
    - browserid-bsky-lczv
---

Implement the IdP per docs/plans/2026-07-27-bigtent-bsky-idp-design.md (source of truth, incl. the Decisions section). Reference skeleton: ~/src/mingo/mingo-idp. D = bsky.browserid.me, same axum app as the bridge.

- [ ] Empirical probe: PAR against bsky.social with scope=atproto standalone (no login needed) — load-bearing for the scope constant
- [ ] idp module: SupportDocument well-known, /device_cert (auth + config certs, <handle>+*@D identities), /access/mint with public bidirectional handle↔DID re-verify (≤10-min cache) + DID-pin match
- [ ] atproto OAuth claim flow: confidential client (metadata doc + jwks on D), PAR/PKCE/DPoP, sub==DID check, tokens discarded; device-authorize page adapted from mingo (popup postMessage + return_url fragment modes)
- [ ] DID pin store + 30-day reassignment seasoning + voluntary retirement (OAuth by pinned DID)
- [ ] Status list for D's certs at /.well-known/browserid-status (D's IdP keypair; status refs on all issued certs)
- [ ] Bridge RP: trust_primary(D, own IdP key)
- [ ] Labeler: display bare handle for @bsky.browserid.me identities (full string stays in receipts)
- [ ] Report exact DNS discovery records the user must add for D (zone is DNSSEC-signed; DS/DNSKEY verified 2026-07-27)
- [ ] Confirm registrar issuer_resolver is configured in the browserid.me deployment
- [ ] Tests
