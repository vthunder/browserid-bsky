---
# browserid-bsky-htjb
title: 'End-to-end setup guide: provision + use the PDS with any browserid email, both provenance paths'
status: todo
type: task
created_at: 2026-07-24T14:52:18Z
updated_at: 2026-07-24T14:52:18Z
---

A guide (docs/) so any user/agent can go from a browserid email to posting on Bluesky through the bridge, covering BOTH attribution paths:
- as-itself (grantor==grantee): provision an agent sub-identity, warrant it for bsky.browserid.me, post.
- on-behalf-of (grantor=human, grantee=agent): once that path exists (see provenance bean).
Include: prerequisites (a browserid identity via any email, primary or fallback IdP), the consent/approval steps, obtaining a warrant with granular scopes, the token exchange, posting, reading back, and revocation. Note primary-IdP users (e.g. @sandmill.org) work via the hosted verifier's DNSSEC discovery; fallback (browser.me) users too. Should be runnable by a human with a Bluesky client AND by a headless agent (browserid-agent SDK / wallet MCP). Supersede/absorb the smoke crate's steps into real docs + a minimal example.
