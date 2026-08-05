---
# browserid-bsky-6pxm
title: Scrub smoke-state credentials from public repo history + revoke device certs
status: in-progress
type: task
created_at: 2026-08-05T15:23:39Z
updated_at: 2026-08-05T15:23:39Z
---

smoke-state.json (device private key + certs for danmills+bluesky@sandmill.org / claude.at.browserid.me) was tracked in the PUBLIC browserid-bsky repo since 86d9184.

- [ ] Scrub smoke-state.json from git history (filter-repo) and force-push
- [ ] gitignore smoke-state*.json so it cannot return
- [ ] Revoke/rotate the exposed device credential — BLOCKED: sandmill.org (issuing IdP) has no revocation endpoint yet; discovery doc advertises no device-revoke. Needs implementation in ~/src/sandmill per browserid-ng 4a0daed (device-revoke support-doc field, ft55).

Note: GitHub may retain cached copies of scrubbed blobs; treat the key as compromised until revoked.
