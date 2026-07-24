<!-- This Source Code Form is subject to the terms of the Mozilla Public
   - License, v. 2.0. If a copy of the MPL was not distributed with this
   - file, You can obtain one at http://mozilla.org/MPL/2.0/. -->

# browserid-bsky

Bluesky ⨯ [browserid-ng](https://github.com/vthunder/browserid-ng):
**warrant-scoped, revocable, attributable agent access to the AT Protocol
network.**

atproto has no delegation story — an agent on Bluesky today holds an app
password or a full OAuth session. browserid-ng has exactly the missing
piece: a human-signed **warrant** naming one audience and a set of scopes,
revocable at any time. This repo bridges the two.

## What's here

| Dir | What it is |
|---|---|
| **pds-bridge** | The bridge service (Rust/axum) run at `bsky.browserid.me`: browserid-provisioned accounts on a stock [PDS](https://github.com/bluesky-social/pds), RFC 7521 bundle→token exchange, and a fail-closed scope-enforcing XRPC proxy for agent traffic |
| **docs/plans** | Design + deployment plans |

Planned next (see the design doc): the `me.browserid.*` provenance lexicon,
a labeler surfacing "posted by agent X under a warrant from Y", and
bidirectional email↔DID linkage attestations.

## How it works

1. **Provision** — sign in with browserid at the bridge; it creates an
   atproto account (did:plc, handle under `*.at.browserid.me`) on its PDS
   and binds your email to the DID. Your password is shown once and never
   stored.
2. **Delegate** — your agent requests a warrant for audience
   `https://bsky.browserid.me` with granular scopes
   (`repo:app.bsky.feed.post?action=create`, `blob:image/*`, …); you
   approve one consent card at your broker.
3. **Act** — the agent exchanges its four-object bundle for a bridge token
   and speaks ordinary XRPC. Every call is allowlist-mapped to the scopes
   you granted, pinned to your own repo, and audit-logged; the warrant's
   revocation status is re-checked on every use. Revoke the warrant and
   the agent is out — your own credentials never move.

## Development

```bash
cargo test          # unit + end-to-end tests against a mock PDS
cargo run -p pds-bridge   # needs PDS_ADMIN_PASSWORD + a PDS (see docs)
```

The browserid-ng crates are git dependencies pinned by `Cargo.lock`; bump
with `cargo update -p browserid-core -p browserid-rp`.

## License

[MPL-2.0](./LICENSE).
