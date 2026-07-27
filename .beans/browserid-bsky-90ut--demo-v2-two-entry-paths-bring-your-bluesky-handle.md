---
# browserid-bsky-90ut
title: 'Demo v2: two entry paths — bring your Bluesky handle, or mint one'
status: completed
type: feature
priority: normal
created_at: 2026-07-27T12:54:00Z
updated_at: 2026-07-27T21:50:49Z
parent: browserid-bsky-sxy0
blocked_by:
    - browserid-bsky-tw1d
---

Rework the guide/landing so users with an existing Bluesky handle claim it via the IdP (their real identity is the grantor; badge reads 'on behalf of <their handle>'; no email anywhere) while users without one keep today's mint-<label>.at.browserid.me shapes. Both paths end with the revocation kill-switch finale (browserid-bsky-tjat). Blocked by the IdP build.

## Shipped 2026-07-27 (IdP-anchored, agent-only)

Guide reworked (pds-bridge/src/guide.rs) with the bring-handle-vs-mint fork:
- Step 1 now opens with 'do they have a Bluesky account?' — yes: pin grantor to <handle>@bsky.browserid.me, approve by signing in with Bluesky, badge reads 'on behalf of @<handle>'; no: fall back to the existing email shapes (as-yourself / on-behalf). Honest note that the authority is the real handle but posts still land on a new <label>.at.browserid.me account until the write-relay (ru7u).
- Step 2 clarified: the account handle is separate from the brought Bluesky handle.
- Tooling shows setup <label> --for <handle>@bsky.browserid.me. Verified the approval path works end-to-end today (grantor-verify): the /account page routes primary-IdP sign-in and preserves the ?provision code; attribution records the handle grantor.
- agent-cli/cli.mjs: shape-aware approval hint (needs a 0.1.6 publish to take effect; --for already accepts arbitrary grantor in published 0.1.5, so the flow works now).

Kept mint-a-handle. Agent-only. Write-relay (ru7u) is the follow-up that puts posts on the real timeline.
