---
# browserid-bsky-tw1d
title: 'Build: bsky-handle IdP + handle-identity provisioning'
status: completed
type: feature
priority: normal
created_at: 2026-07-27T12:54:00Z
updated_at: 2026-07-27T14:47:43Z
parent: browserid-bsky-sxy0
blocked_by:
    - browserid-bsky-lczv
---

Implement the IdP per docs/plans/2026-07-27-bigtent-bsky-idp-design.md (source of truth, incl. the Decisions section). Reference skeleton: ~/src/mingo/mingo-idp. D = bsky.browserid.me, same axum app as the bridge.

- [x] Empirical probe: PAR against bsky.social with scope=atproto standalone (no login needed) — load-bearing for the scope constant: CONFIRMED 2026-07-27, PAR 201; request_uri ttl 299s; use_dpop_nonce handshake per server
- [x] idp module: SupportDocument well-known, /device_cert (auth + config certs, <handle>+*@D identities), /access/mint with public bidirectional handle↔DID re-verify (≤10-min cache) + DID-pin match
- [x] atproto OAuth claim flow: confidential client (metadata doc + jwks on D), PAR/PKCE/DPoP, sub==DID check, tokens discarded; device-authorize page adapted from mingo (popup postMessage + return_url fragment modes)
- [x] DID pin store + 30-day reassignment seasoning + voluntary retirement (OAuth by pinned DID)
- [x] Status list for D's certs at /.well-known/browserid-status (D's IdP keypair; status refs on all issued certs)
- [x] Bridge RP: trust_primary(D, own IdP key)
- [x] Labeler: display bare handle for @bsky.browserid.me identities (full string stays in receipts)
- [x] Report exact DNS discovery records the user must add for D (zone is DNSSEC-signed; DS/DNSKEY verified 2026-07-27)
- [~] registrar issuer_resolver: NOT a config item — broker builds it automatically (routes/mod.rs:61), None only if DNS init fails (logs 'issuer resolver unavailable'). Deployment-time log grep, deferred to the enable step.
- [x] Tests

## Summary of Changes

Bsky-handle browserid IdP built as pds-bridge/src/idp/ (~3200 lines incl. adapted device-authorize.html): SupportDocument well-known, /device_cert (+config cert with <handle>+*@D), /agent_device_cert, /access/mint with public bidirectional handle<->DID re-verify + DID-pin match, confidential atproto OAuth client (hand-rolled PAR/PKCE/DPoP nonce-retry, sub==DID, tokens discarded = structural zero custody), DID pin store with 30-day seasoning + voluntary retirement, D's own signed status list, in-process verifier (trust_primary short-circuit sharing the fail-closed cache), bare-handle labeler display. scope=atproto standalone confirmed live against bsky.social. Adversarially reviewed; enable-blockers fixed (browserid-bsky-qqsv), pre-prod hardening tracked (browserid-bsky-npp9). Ships IDP_ENABLED-off (inert; verified). 86 lib + 7 integration tests pass. Deviations: DoH not a DNS client (configurable), local trust_primary (no hosted verifier to extend), agent-device-authorization advertised (needed for the on-behalf badge).
