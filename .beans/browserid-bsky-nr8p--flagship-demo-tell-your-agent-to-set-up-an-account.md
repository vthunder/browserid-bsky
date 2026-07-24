---
# browserid-bsky-nr8p
title: 'Flagship demo: "tell your agent to set up an account at bsky.browserid.me"'
status: todo
type: feature
priority: high
created_at: 2026-07-24T20:50:36Z
updated_at: 2026-07-24T20:50:36Z
---

Dan (2026-07-24): this should be browserid's FLAGSHIP demo. The narrative:

  A user tells their agent: "set up an account at bsky.browserid.me."
  The agent looks that up, finds instructions, follows them, and hands the
  user links to click — add your email at browserid.me, then authorize the
  agent's request. The user clicks, approves, and the agent can post.
  Posts carry unforgeable provenance and render a browserid-verified badge
  in bsky.app for anyone subscribed to the labeler.

The value prop this demonstrates: scoped, revocable, attributable agent
access to a real network, that no other account can forge — with the human
in the loop exactly once, at the consent step.

## What already exists (checked 2026-07-24)

- The whole flow, in Rust: `smoke setup` calls
  `browserid_agent::request_provision` -> prints APPROVE_URL +
  user_code/fingerprint -> `pending.wait()` polls for approval -> POST
  /browserid/provision -> POST /browserid/post. This IS the demo, minus
  discovery and minus being runnable by an arbitrary agent.
- A Node-only wallet MCP: browserid-ng/examples/mcp-agent-auth (wallet
  server: identity / authorize(audience, scopes) / get_assertion(audience),
  built on @browserid-ng/agent). Runs in Claude Code / Desktop / Cursor with
  no Rust. This is the "any agent can drive it" piece.
- The bridge, labeler, provenance, and public verifier are all live.

## Gaps to close

1. DISCOVERY. https://bsky.browserid.me/ currently serves the stock PDS
   ASCII art (the bridge falls through to the PDS for /). An agent told to
   "set up an account at bsky.browserid.me" finds nothing actionable. Needs
   agent-readable instructions at the origin — a content-negotiated root
   and/or /llms.txt — naming the exact steps, endpoints, scopes, and the
   MCP/tool to install. This is the piece that makes the one-liner work.

2. THE JS PATH MAY NOT REACH THE BADGE. sdk/agent (JS) builds a
   presentation as `cert~warrant~assertion` (see backedPresentation in
   sdk/agent/src/protocol.mjs) — no access cert anywhere in that SDK. The
   bridge verifies a four-object AccessPresentation, and /browserid/post
   additionally needs an attestation signed with the ACCESS key (that
   attestation is what makes a post badge-worthy — no attestation, no
   label). NOTE: examples/mcp-agent-auth/README.md describes the bundle as
   `access_cert ~ assertion ~ warrant ~ config_cert`, which contradicts the
   code — resolve which is stale before designing around either. Either the
   JS SDK gains access-cert + attestation support, or the demo ships a
   dedicated agent-facing tool.

3. THE SCRIPT. Once 1+2 are done: a single documented path, tested by
   actually driving it as a naive agent would, with the badge visible at
   the end.

Related: bean htjb (end-to-end setup guide for any browserid email) is the
human-facing version of the same walkthrough and should probably merge into
this. The on-behalf path has still never run live and would make a stronger
demo than as-itself.
