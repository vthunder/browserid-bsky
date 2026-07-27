---
# browserid-bsky-npp9
title: 'IdP hardening before prod enable: SSRF, status-list growth, cross-issuer trigger'
status: completed
type: bug
priority: high
created_at: 2026-07-27T14:29:43Z
updated_at: 2026-07-27T15:39:13Z
parent: browserid-bsky-tw1d
---

Non-takeover findings from the 2026-07-27 review. Not enable-blockers in the takeover sense, but SSRF is server-side (reachable regardless of browser) and the bridge talks to an internal PDS, so address before setting IDP_ENABLED in any real deployment. Two carry design questions.

- [x] #6 MEDIUM SSRF: resolve.rs pds_endpoint (~:290) and did_document (~:229), oauth.rs discover_auth_server (~:296-330) fetch attacker-named serviceEndpoint/authorization_servers URLs with no scheme/address validation, echoing transport errors back. A did:web can point at 127.0.0.1/link-local and read reachability. Require https, reject private/loopback/link-local, don't echo the error.
- [x] #7 MEDIUM status-list unbounded growth: store.rs idp_allocate_status_idx + certs.rs:375 allocate a fresh index per access-cert mint (daily, per RP, per device), permanently extending the re-signed bitmap; a client can inflate it deliberately. Design Q: one index per identity or per device cert? Plus prune past TTL. Related nit: certs.rs:191/:205 allocate two indices per device_cert call.
- [x] #8 LOW/design cross-issuer trigger: verify_locally triggers on the access(grantee) issuer; a broker-issued grantee acting for a @D grantor hits a D-only trust table and hard-fails (error is final by contract). Unreachable under today's agent_device_cert design but the trigger condition doesn't match the trust assumption. Decide: trigger on grantor issuer, or document the invariant.

## Resolution (2026-07-27, uncommitted — left for review)

- **#6** New `pds-bridge/src/idp/net.rs`: `guard_external_url` (https-only,
  literal-IP range check, resolve-and-reject-any-internal-answer) + the
  testable halves `check_url_shape` / `check_addrs` / `is_blocked_addr`.
  Redirects are the other half: the shared `http` client follows up to ten,
  so a guarded public URL could 302 to an internal one. Guarded fetches now
  use a dedicated no-redirect client (`net::guarded_client`) and follow hops
  themselves via `net::get_guarded` / `follow_hops`, re-guarding each
  `Location` (relative ones resolved against the hop they came from), capped
  at 3 hops. Applied to `well_known_atproto_did`, the `did:web` branch of
  `did_document`, and all four fetches reachable from
  `discover_auth_server` (oauth-protected-resource, AS metadata, and the
  PAR / authorize / token endpoints the metadata names). Not applied to the
  bridge's own PDS, status list, or the configured PLC directory. Transport
  errors are now logged, never echoed. The PAR and token POSTs also moved to
  the no-redirect client, so `oauth::{discover_auth_server,
  push_authorization_request, exchange_code}` no longer take the shared
  client at all. Residual: resolve-then-connect DNS
  rebind, documented in the module header, accepted for v1.
- **#7** `Store::idp_allocate_status_idx` → `idp_status_idx`, a get-or-create
  keyed on the identity (lowest existing idx wins, so existing DBs collapse
  without renumbering). `device_cert` now takes one `StatusRef` and clones it
  into both certs. `+tag` agents keep their own index and stay independently
  revocable; `idp_revoke_status_for_handle` still sweeps handle + agents.
- **#8** `verify_locally` takes the local path only when BOTH the access
  cert and the config cert are issued by D; a mixed-issuer bundle returns
  `None` and falls through to the hosted verifier.

## Redirect bypass (follow-up)

The initial SSRF guard checked the URL but the shared reqwest client follows up to 10 redirects, so a guarded public URL could 302 into the internal network. Closed: net.rs now has a no-redirect guarded_client() and follow_hops() that re-guards every hop (incl. relative Locations) up to MAX_HOPS=3, returning the same opaque error. All externally-named fetches (well_known_atproto_did, did:web doc, oauth-protected-resource, AS metadata, PAR, token) route through it; DoH and the PLC directory stay on the shared client (config-trusted). Test: a_redirect_to_an_internal_address_is_refused. 96 lib + 7 integration green.
