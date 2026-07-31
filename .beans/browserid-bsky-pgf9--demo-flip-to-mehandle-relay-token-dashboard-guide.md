---
# browserid-bsky-pgf9
title: 'Demo flip to me@<handle>: relay + token + dashboard + guide + homepage'
status: in-progress
type: feature
priority: normal
created_at: 2026-07-31T14:58:16Z
updated_at: 2026-07-31T15:42:43Z
---

Flip the whole demo flow to the me@<handle> identity shape (browserid-ng-tsqk follow-on, per discussion 2026-07-31).

- [x] relay_did_for_grantor accepts me@<handle> grantors (domain-as-handle, any label) alongside legacy <handle>@D — tested incl. gmail fall-through
- [x] Allowlist: NO code change needed — prod already runs the designed open mode (WRITE_RELAY_ALLOWLIST=*, WRITE_SESSION_KEY set, relay + dashboard live). Empty-means-off stays as the safety invariant; a specific list remains the kill switch.
- [x] /browserid/token: already correct — no-account fallback error says 'provision one, or connect write access at /dashboard'; and verify_presentation already delegates broker-issued identities to the hosted verifier, so me@<handle> verifies unchanged
- [ ] Labeler/badge + provenance attribution for new-shape grantors — VERIFY on the live post during the end-to-end run (badge text derivation not yet audited)
- [x] Dashboard: live me@<handle> derivation, directed login, server login handler recognizes the native shape (domain-with-pin = handle session); legacy @D unchanged (d3cd133 + d134a9d)
- [x] Personalized prompt: already correct for free — delegation_prompt uses the session identity, which IS me@<handle> for native sign-ins
- [x] guide.rs rewritten: grantor me@<handle>, never the bare handle, never a personal email; connect-at-dashboard framing; legacy-shape note; setup example --for me@dan.bsky.social; tests updated
- [x] Homepage: already shape-agnostic after the UX revamp (no #bskyPrompt survives); added two me@your-handle teaching lines (bsky lede + mingo demo cell). NOT yet subtree-deployed.
- [x] agent-cli: no change needed — --for takes identities verbatim; the guide now shows --for me@dan.bsky.social
- [ ] Live end-to-end re-run: sign-in, connect, agent post to real timeline, revoke
