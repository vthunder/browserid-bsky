---
# browserid-bsky-qqsv
title: 'IdP enable-blockers: return_origin allowlist, page XSS, callback browser-binding, cold-cache verify, stale bound'
status: completed
type: bug
priority: critical
created_at: 2026-07-27T14:29:43Z
updated_at: 2026-07-27T14:47:03Z
parent: browserid-bsky-tw1d
---

Adversarial review 2026-07-27 of the bsky-handle IdP found a browser-facing takeover chain plus two flow-correctness bugs. All while IDP_ENABLED is off = inert, so this blocks ENABLING, not landing. Fixes in progress (agent idp-fix).

- [x] #1 CRITICAL device-authorize.html: return_origin/return_url unvalidated -> any https site harvests device+config certs for a signed-in victim. Allowlist trusted (broker/dialog) origins from server-injected config, fail closed otherwise.
- [x] #2 CRITICAL device-authorize.html: DOM XSS via innerHTML in fail() fed by fragment (email/user_email/agentEmail). Use textContent.
- [x] #3 HIGH idp/routes.rs: OAuth callback not bound to the initiating browser (login CSRF/fixation). Set a binding cookie at /oauth/start, require match at callback.
- [x] #4 HIGH routes.rs verify_locally: never refreshes the warrant's registrar status list -> cold-cache legit presentations fail closed, no fallback. Refresh warrant status URI against broker_key.
- [x] #5 MEDIUM resolve.rs get_stale: no age bound; outage accepts arbitrarily old binding vs design's <=10min. Bound to 10min.
- [x] nit: require_idp 500 -> 404; gate device_authorize_page + mint_preflight behind require_idp.

Findings #1/#2 inherited verbatim from mingo-idp's device-authorize.html (pre-existing browserid-IdP weakness), fixed here. Core crypto/verification (mint pipeline, local short-circuit, sub-binding, pin/seasoning, zero-custody) all SURVIVED the review.

## Summary of Changes

All six fixed (agent idp-fix), verified in code + tests (86 lib + 7 integration, 0 failed). #1 return_origin: serve-time-templated allowlist (IDP_TRUSTED_ORIGINS or broker origin), strict origin_of() charset blocks userinfo/markup, empty=boot error, page fails closed before issuing. #2: textContent everywhere, no HTML sinks remain. #3: bsky_idp_flow binding cookie (HttpOnly/Lax/Secure) set at start, matched at callback after the single-use take and before code exchange; empty binding never redeemable. #4: verify_locally now refreshes the warrant/registrar status URI against broker_key (red->green integration test with a stone-cold cache). #5: get_stale bounded to the resolve cadence. Nits: require_idp -> 404 (NotConfigured), page+preflight gated. #5 design note (freshness==stale bound makes the outage fallback near-unreachable) accepted deliberately: failing closed on a sustained >10min resolution outage is the correct posture for an identity proof.
