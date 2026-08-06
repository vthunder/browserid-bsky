---
# browserid-bsky-6pxm
title: Scrub smoke-state credentials from public repo history + revoke device certs
status: in-progress
type: task
priority: normal
created_at: 2026-08-05T15:23:39Z
updated_at: 2026-08-06T01:23:10Z
---

smoke-state.json (device private key + certs for danmills+bluesky@sandmill.org / claude.at.browserid.me) was tracked in the PUBLIC browserid-bsky repo since 86d9184.

- [x] Scrub smoke-state.json from git history (filter-repo) and force-push (52f4d65, 2026-08-05)
- [x] gitignore smoke-state*.json so it cannot return
- [x] Implement revocation at sandmill.org (deployed 2026-08-05, sandmill 826d7e7): status list at /.well-known/browserid-status + /browserid/revoke-device page + session-scoped POST /api/browserid/revoke_device; advertised via device-revoke.
- [x] Revoked the leaked credential by ROTATING the sandmill IdP key (2026-08-06). The cert predated status refs (no status claim, no bit to flip), so rotation was the only kill. New key 5T9VgQuup-169gZ3vT7tt_CbJjTO0uEyoBDZW-Q6HVQ published in the _browserid.sandmill.org DNSSEC TXT record (the sole root of trust) and installed on the dokku app. Verified: DNS and served discovery agree, status list re-signs under the new key and no longer verifies under the old, and the leaked cert no longer validates.
- [ ] Re-issue the bsky smoke credential after deciding (new certs DO carry status refs and are revocable).

Note: GitHub may retain cached copies of scrubbed blobs; treat the key as compromised until revoked.

## Rotation notes (2026-08-06)

Order that matters: DNS TXT is the ONLY trusted source of an IdP key (the /.well-known key is never trusted), so the leaked cert died the moment the record propagated. Server config was flipped immediately after to close the broken-issuance window.

Every pre-rotation sandmill cert is now invalid — devices must re-authorize by signing in. Certs issued from here carry status refs, so a future leak is revocable WITHOUT a key rotation.
