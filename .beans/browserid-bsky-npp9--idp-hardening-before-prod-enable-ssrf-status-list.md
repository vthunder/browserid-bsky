---
# browserid-bsky-npp9
title: 'IdP hardening before prod enable: SSRF, status-list growth, cross-issuer trigger'
status: todo
type: bug
priority: high
created_at: 2026-07-27T14:29:43Z
updated_at: 2026-07-27T14:29:43Z
parent: browserid-bsky-tw1d
---

Non-takeover findings from the 2026-07-27 review. Not enable-blockers in the takeover sense, but SSRF is server-side (reachable regardless of browser) and the bridge talks to an internal PDS, so address before setting IDP_ENABLED in any real deployment. Two carry design questions.

- [ ] #6 MEDIUM SSRF: resolve.rs pds_endpoint (~:290) and did_document (~:229), oauth.rs discover_auth_server (~:296-330) fetch attacker-named serviceEndpoint/authorization_servers URLs with no scheme/address validation, echoing transport errors back. A did:web can point at 127.0.0.1/link-local and read reachability. Require https, reject private/loopback/link-local, don't echo the error.
- [ ] #7 MEDIUM status-list unbounded growth: store.rs idp_allocate_status_idx + certs.rs:375 allocate a fresh index per access-cert mint (daily, per RP, per device), permanently extending the re-signed bitmap; a client can inflate it deliberately. Design Q: one index per identity or per device cert? Plus prune past TTL. Related nit: certs.rs:191/:205 allocate two indices per device_cert call.
- [ ] #8 LOW/design cross-issuer trigger: verify_locally triggers on the access(grantee) issuer; a broker-issued grantee acting for a @D grantor hits a D-only trust table and hard-fails (error is final by contract). Unreachable under today's agent_device_cert design but the trigger condition doesn't match the trust assumption. Decide: trigger on grantor issuer, or document the invariant.
