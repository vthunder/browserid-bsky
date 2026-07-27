---
# browserid-bsky-sxy0
title: Connect existing Bluesky accounts to the bridge
status: in-progress
type: epic
priority: normal
created_at: 2026-07-27T12:44:49Z
updated_at: 2026-07-27T16:07:30Z
---

Give users something at stake: let them connect the Bluesky handle they already own instead of (only) minting <label>.at.browserid.me accounts. Design space discussed 2026-07-27, two composable pieces:

1. atproto OAuth connect (write relay): bridge becomes an atproto OAuth client; user connects their real account; first-party browserid login posts as themselves; agents post to the real account via warrant + attestation, bridge enforces narrow scopes over the coarse OAuth grant. Trade-off: bridge holds powerful tokens (custody).
2. bsky-handle browserid IdP (identity): serve /.well-known/browserid for a domain where the local part is a Bluesky handle (e.g. dan.bsky.social@<domain>); "provisioning" authenticates via atproto OAuth (identity-only) and checks the handle's DID matches. The handle becomes a first-class browserid identity — grantor on warrants, badge text, sign-in anywhere — with no email loop and no write custody. Classic Persona identity-bridging (sideshow/BigTent) applied to atproto. Must pin the DID at first claim (handles are reassignable; DID is stable).

Open questions: which piece first (IdP-first avoids custody and kills email friction; OAuth-write needed for posts to appear under the real handle); broker dialog/consent integration for primary-IdP identities (browserid-ng has trust_primary + auth_with_presentation — prototype the approval-page flow); domain choice for the IdP.

- [ ] Decide shape/sequencing (IdP-first vs OAuth-write-first vs both)
- [ ] Prototype broker consent flow with a primary-IdP identity
- [ ] Spec + build

## Decision (2026-07-27)

User confirmed: this is identity bridging as implemented in Persona's BigTent. **IdP-first is chosen** — spec and build the bsky-handle browserid IdP, and rework the demo around it (as a new path). Users without an existing Bluesky handle keep the current mint-a-handle shapes, so the demo grows two entry paths rather than replacing one with the other. The OAuth *write* relay (piece 1 above) is deferred to its own child bean.

Children: spec → build → demo rework, plus deferred OAuth-write relay.

## IdP LIVE 2026-07-27

The bsky-handle browserid IdP is deployed and ENABLED on bsky.browserid.me. Verified: /.well-known/browserid serves the signing key matching the DNS TXT (ESy5b9bn…); client-metadata.json is the identity-only atproto profile (scope=atproto, private_key_jwt/ES256, authorization_code only, dpop-bound); jwks + status-list serve; boot log clean; the browserid.me broker's issuer-resolver is up (primary-rooted warrants will verify). dokku config: IDP_SECRET, IDP_OAUTH_KEY, IDP_ENABLED=1 all set on bsky-bridge. Security gates qqsv + npp9 cleared before enable.

Remaining: a real end-to-end claim (human atproto OAuth with a live Bluesky handle) is the only untested-in-anger path — the first claim is the real test. Then demo-v2 (browserid-bsky-90ut).
