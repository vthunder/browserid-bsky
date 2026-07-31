---
# browserid-bsky-pgf9
title: 'Demo flip to me@<handle>: relay + token + dashboard + guide + homepage'
status: in-progress
type: feature
priority: normal
created_at: 2026-07-31T14:58:16Z
updated_at: 2026-07-31T15:00:24Z
---

Flip the whole demo flow to the me@<handle> identity shape (browserid-ng-tsqk follow-on, per discussion 2026-07-31).

- [x] relay_did_for_grantor accepts me@<handle> grantors (domain-as-handle, any label) alongside legacy <handle>@D — tested incl. gmail fall-through
- [x] Allowlist: NO code change needed — prod already runs the designed open mode (WRITE_RELAY_ALLOWLIST=*, WRITE_SESSION_KEY set, relay + dashboard live). Empty-means-off stays as the safety invariant; a specific list remains the kill switch.
- [x] /browserid/token: already correct — no-account fallback error says 'provision one, or connect write access at /dashboard'; and verify_presentation already delegates broker-issued identities to the hosted verifier, so me@<handle> verifies unchanged
- [ ] Labeler/badge + provenance attribution derive @handle from the DOMAIN for new-shape grantors (and me+tag local parts)
- [ ] Dashboard logged-out: handle box with LIVE derivation ('-> signing in as me@<handle>'), directed login provisionEmail=me@<handle>, return identity-match check against me@<handle>; 'or use any email' path unchanged
- [ ] Personalized agent prompt bakes grantor me@<handle>
- [ ] guide.rs rewrite (/ and /llms.txt): bring-handle branch teaches me@<handle> everywhere; mint-a-handle unchanged; legacy note for existing <handle>@D identities
- [ ] www.browserid.me homepage copy + #bskyPrompt (browserid-ng marketing/, subtree deploy)
- [ ] agent-cli examples/hints
- [ ] Live end-to-end re-run: sign-in, connect, agent post to real timeline, revoke
