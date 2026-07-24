# `me.browserid.*` provenance lexicons (phase 1)

Sidecar records the bridge writes into the account's atproto repo to carry
browserid delegation across into the atproto world (bean
`browserid-bsky-27c0`). They are custom collections — stock Bluesky clients
ignore them; a labeler or verifier reads them.

## `me.browserid.warrant`

Published **once** per distinct warrant (rkey = base64url SHA-256 of the
warrant JWS), referenced by many posts. Holds the signed delegation
artifacts so a reader can verify the delegation itself against browserid's
DNSSEC-rooted keys — not just trust the bridge.

| Field | Meaning |
|---|---|
| `warrant` | the `browserid-warrant-v1` JWS |
| `configCert` | the config cert (`authorization` device cert) that signed it |
| `attributedTo` | warrant grantor (the identity the action attributes to) |
| `executedBy` | warrant grantee (the identity that wields it) |

`root`/base identity is **not stored** — derive it at read time by stripping
the `+tag` from `attributedTo` and cross-checking against the config cert's
`identities` (which includes the base and its `+*` glob).

## `me.browserid.provenance`

One per post (rkey = the post's rkey, so `provenance/<rkey>` maps 1:1 to
`app.bsky.feed.post/<rkey>`).

| Field | Meaning |
|---|---|
| `post` | AT-URI of the post this attributes |
| `postCid` | the post record CID (when known) |
| `warrant` | AT-URI of the `me.browserid.warrant` record above |
| `attributedTo` | grantor |
| `executedBy` | grantee (== `attributedTo` for an as-itself post; differs for on-behalf) |

## Trust level (phase 1) — IMPORTANT

The **delegation** is verifiable (the warrant record carries the signed
artifacts). The link "**this grantee produced this exact post**" is
**PDS-asserted** at this phase — the bridge writes the provenance using the
account session, so a compromised bridge/PDS could fabricate it. The
unforgeable binding (grantee signs the post content, with a replay-guarding
nonce+timestamp) is phase 2 — bean `browserid-bsky-n78o`, built on the
browserid-ng typed-signing extension.
