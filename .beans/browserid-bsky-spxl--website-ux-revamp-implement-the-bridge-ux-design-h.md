---
# browserid-bsky-spxl
title: 'Website UX revamp: implement the Bridge UX design handoff'
status: completed
type: feature
priority: normal
created_at: 2026-07-28T21:25:07Z
updated_at: 2026-07-28T22:05:51Z
---

Implement the design from ~/Browserid Bsky UX Revamp.zip (design_handoff_bridge_ux). High-fidelity recreation of winning options on the browserid.me design language, server-rendered vanilla HTML/JS, textContent-only dynamic strings, light + dark themes (dark palette from browserid-ng marketing/index.html).

- [x] Shared UI module (design tokens light+dark, nav/footer/card styles)
- [x] Root / — option 4a (hero + verify tool panel + two cards) in guide.rs
- [x] /agent — option 1h: guide moves out of /; text/markdown for agents, HTML wrapper for browsers; /llms.txt and non-HTML / unchanged
- [x] agent_prompt() -> "Read {origin}/agent and follow it…" + update guide.rs tests
- [x] /verify report — option 1g (verdict header, post card, chain row, checks panel) + error/landing pages restyled
- [x] Dashboard — 1c + 2b: rail layout, gated prompt card, connect card states (not-connected/connected/reconnect/not-allowlisted), agents list
- [x] Connect flow 1e: no interstitial; delete connect.html + /idp/connect page route; callback redirects to /dashboard?connected=/error=; disclosure copy on card
- [x] Mint a handle 2c: email dashboard sign-in (hosted verifier), POST /dashboard/mint (passwordless, never returns password), success card, prompt unlock
- [x] /dashboard/me: email/account fields for mint state
- [x] Update /idp/connect references in error messages
- [x] cargo test green
- [x] Design update 5a (added mid-task): prompt card → two-step "Set up your agent" (wallet-MCP install with Claude Code/Codex/Other tabs, then the prompt)

## Summary of Changes

All six screens rebuilt on the browserid.me design language (light + dark via prefers-color-scheme, dark palette from marketing/index.html), verified by screenshotting every state in both themes against a seeded preview server.

- **New `ui.rs`**: shared design tokens + component CSS (`BASE_CSS`), document shell, nav/brand builders. The dashboard gets the same CSS via a `__BASE_CSS__` template token — one source of truth.
- **Root `/`** (guide.rs): option 4a — nav, hero, verify tool panel (plain GET form to /verify), agent + labeler cards, footer. The full guide markdown is no longer on the page.
- **`/agent`** (new route): option 1h — markdown for non-HTML Accept, wrapped HTML for browsers; `agent_prompt()` now points at /agent. `/llms.txt` and markdown-on-`/` unchanged so old prompts keep working.
- **`/verify`** (routes.rs): option 1g — 3 verdicts, post card, authorized-by→written-by→scope chain (collapses when not on-behalf), N/N checks with details toggle, footer links (at:// URI, warrant record via getRecord passthrough, json). Landing + error pages share the shell. `verify_preview()` (cfg(test)) renders canned reports.
- **Dashboard** (dashboard.html rewritten): 1c/2b states, mint card 2c, gated vs unlocked prompt (5a two-step setup card), rail with status dots, agents list with humanized scopes + status pills, ?connected=/?error= inline result, consent disclosure, connect button POSTs /idp/connect/start directly (option 1e — connect.html and the /idp/connect page route are deleted; callback now redirects to /dashboard).
- **Backend**: dashboard login accepts email identities via the hosted verifier (session with handle/did NULL); `POST /dashboard/mint` opens a passwordless account for the signed-in email identity (password generated and discarded, never returned); `/dashboard/me` adds kind/account_handle/account_did; delegation prompt built on agent_prompt() ("… Act for <identity>.").
- **Tests**: updated + new coverage (email sign-in + mint end-to-end with mock broker/PDS, mint refusals). 164 lib + 7 integration tests green. `ui_preview_server` (#[ignore]) serves all seeded states: `/preview/as/dan|eve|alice|bob`, `/preview/verify?kind=green|amber|red`.

Follow-up filed in browserid-ng (browserid-ng-2wmh): update the marketing step-2 prompt to /agent.
