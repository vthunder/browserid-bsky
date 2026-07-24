---
# browserid-bsky-azxl
title: Disable password login to the PDS — browserid warrant should be the sole posting path
status: todo
type: task
priority: high
created_at: 2026-07-24T14:52:18Z
updated_at: 2026-07-24T14:52:18Z
---

At provisioning the bridge generates a PDS account password and shows it once. Anyone holding it can log into the PDS with a normal Bluesky client and post as the handle, bypassing browserid entirely (the warrant path is locked down; the account has a second credential). Options: (a) bridge sets a random password it never discloses and holds only the session pair (current code already keeps only the session pair, but it RETURNS the password to the user); stop returning it. (b) investigate disabling password auth / app-password creation on the stock PDS so createSession can't be used by end users; only the bridge's admin-minted sessions work. (c) if a user legitimately wants direct client access, that's a separate opt-in. Decide + implement; update the smoke tool to stop printing the password. Relates to P2 provenance (browserid-as-sole-path is the whole point).
