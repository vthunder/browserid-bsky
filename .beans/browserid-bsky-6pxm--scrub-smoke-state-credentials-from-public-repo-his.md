---
# browserid-bsky-6pxm
title: Scrub smoke-state credentials from public repo history + revoke device certs
status: in-progress
type: task
priority: normal
created_at: 2026-08-05T15:23:39Z
updated_at: 2026-08-05T15:55:55Z
---

smoke-state.json (device private key + certs for danmills+bluesky@sandmill.org / claude.at.browserid.me) was tracked in the PUBLIC browserid-bsky repo since 86d9184.

- [x] Scrub smoke-state.json from git history (filter-repo) and force-push (52f4d65, 2026-08-05)
- [x] gitignore smoke-state*.json so it cannot return
- [x] Implement revocation at sandmill.org (deployed 2026-08-05, sandmill 826d7e7): status list at /.well-known/browserid-status + /browserid/revoke-device page + session-scoped POST /api/browserid/revoke_device; advertised via device-revoke.
- [ ] Actually revoke the leaked credential — NOT YET POSSIBLE: the exposed cert was issued BEFORE status refs existed, so it carries no status claim and no bit can be flipped for it. It runs to expiry (exp 1792678013 = 2026-10-21) unless the sandmill IdP key is rotated. Decide: wait out expiry, or rotate the IdP key (invalidates every sandmill cert).
- [ ] Re-issue the bsky smoke credential after deciding (new certs DO carry status refs and are revocable).

Note: GitHub may retain cached copies of scrubbed blobs; treat the key as compromised until revoked.
