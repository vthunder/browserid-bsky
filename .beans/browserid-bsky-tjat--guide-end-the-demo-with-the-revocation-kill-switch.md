---
# browserid-bsky-tjat
title: 'Guide: end the demo with the revocation kill-switch'
status: completed
type: feature
priority: normal
created_at: 2026-07-27T12:44:40Z
updated_at: 2026-07-27T13:02:55Z
blocked_by:
    - browserid-bsky-qixi
---

Restructure the demo finale in pds-bridge/src/guide.rs so the last beat is felt, not explained: after showing the profile/post links and labeler subscription, the agent invites the human to revoke its warrant at the broker, then attempts one more post and reports the refusal plainly. The human turns off their own agent from a web page and watches it fail closed — the visceral core of warrants-vs-passwords.

- [x] Find the concrete revoke/grants URL in browserid-ng registrar consent UI and have the guide tell agents to hand the human that exact link
- [x] Rewrite the finale + "Taking permission away" sections: revoke -> agent retries post -> expects 401 "warrant revoked" -> reports it verbatim, states what just happened
- [x] Note re-approval path (revocation is permanent for that warrant; re-run setup to grant again)
- [x] Optional one-line scope-refusal aside ("ask it to delete the post — out of scope, refused") without adding a journey step
- [x] Match the guide's existing voice; single source serves both HTML and llms.txt
- [x] cargo test -p pds-bridge (check smoke/tests that assert guide text)

Deploy gate: ships only together with/after browserid-bsky-qixi, else the revoked agent can keep posting for up to ~15 min and the moment collapses.

## Summary of Changes

pds-bridge/src/guide.rs: new step 7 "Offer them the off switch" — agent sends the human to https://browserid.me/account (Authorized sites → Revoke), then posts once more, gets `401 invalid_token — warrant revoked`, shows that line verbatim and stops; scope-refusal aside included as a parenthetical; re-approval path noted. "Taking permission away" reference section rewritten to match (concrete URL, permanence, fresh-warrant path). New unit test `guide_ends_with_the_revocation_kill_switch` pins the content. agent-cli/cli.mjs setup checklist echoes the finale (published as @browserid-ng/bsky 0.1.5). Ships together with browserid-bsky-qixi so the promised instant revocation is real.
