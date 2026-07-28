# The OAuth write relay: attested posts on the user's real Bluesky account — design

**Date:** 2026-07-28
**Status:** draft for review — web-first revision
**Bean:** browserid-bsky-ru7u, under epic browserid-bsky-sxy0
**Depends on:** the bsky-handle IdP
(`docs/plans/2026-07-27-bigtent-bsky-idp-design.md`) — deployed first, and the
source of the pinned `handle → DID` binding this design builds on. That
document defers "posting *to* the real account" to this one, and its
**Decision 6 ("linked session: dropped")** stands: nothing here re-introduces
an OAuth session into the *cert-mint* path. The write session is a separate,
opt-in artifact used only to publish posts.

**What changed in this revision.** The demo is now **web-first**. The front
door is a dashboard at `bsky.browserid.me`, linked from the browserid.me
homepage — not "paste a prompt into your agent". The user signs in *as their
Bluesky handle* using a directed browserid query, chooses a branch (mint a
local handle, or connect an existing handle for write access), and the
dashboard hands them a **personalized, copy-paste delegation prompt** with the
grantor identity already baked in. Everything below is rewritten around that
entry architecture; the OAuth, session, and enforcement material is unchanged
in substance and is the part to review hardest.

## Goal

Close the last gap in the handle-identity story. Today a user can bring
`dan.bsky.social` as the **authority** on a warrant, but the agent's post
still lands on a freshly minted `<label>.at.browserid.me` account on our PDS —
a stranger's timeline with no followers. The write relay makes the attested,
warrant-scoped post appear **on the user's real account**, in their real repo
on their real PDS (`bsky.social` or self-hosted), on the timeline their
followers actually read.

Concretely:

- `POST /browserid/post` keeps its exact contract — warrant + grantee
  attestation — but the record is created in the **user's own repo** via a
  stored atproto OAuth session, instead of in a bridge-owned account.
- The provenance chain (`me.browserid.warrant` +
  `me.browserid.provenance` + the labeler badge) follows the post into that
  repo, so `/verify` and the badge keep working — verified from published
  records, not from bridge assertions.
- **The bridge holds write custody, deliberately.** This is the line the IdP
  design was careful not to cross, and crossing it is the entire point of this
  bean. It is a real, permanent increase in the system's blast radius; §
  *Security* is honest about that rather than talking around it.
- **A dashboard makes the whole thing legible to a human** — who is connected,
  which agents hold warrants, and one button to revoke.

## Non-goals

- **Not replacing the mint-a-handle path.** Users without a Bluesky handle, or
  with one they won't grant write access to, keep today's
  `<label>.at.browserid.me` flow unchanged. The write relay is a *second
  branch on the dashboard*, not a migration. The bridge must keep both write
  backends alive side by side, chosen per grantor.
- **Not a general proxy onto the user's real account.** The stored session
  could do anything `transition:generic` allows; the bridge exposes exactly
  one operation over it (create an `app.bsky.feed.post`, plus the two
  provenance records). The transparent `fallback(routes::proxy)` and the
  scope-checked XRPC surface stay pointed at *our* PDS only.
- **No deletes, edits, likes, follows, or profile writes** on the real
  account in v1 — even though the coarse grant permits them and
  `scopes.rs` can express them. Adding one is a deliberate later decision,
  not a config change.
- **Not relying on granular atproto scopes.** They exist in the syntax
  (`repo:app.bsky.feed.post`) but the permission-set spec is not finalized or
  shipped on bsky.social. We request `transition:generic` and constrain it
  ourselves; migrating to a narrow scope later is an explicit follow-up.
- **No change to the cert-mint assurance model.** Access-cert minting still
  never consults an OAuth session (IdP design, *Assurance cadence*).
- **Not a general-purpose account-management console.** The dashboard is the
  demo's front door and its revocation surface. It is not a Bluesky client.

## Architecture

The dashboard is new; the second OAuth client, the session manager, and the
second write backend are new; everything else is reuse.

```
  human ── browserid.me homepage ──▶ bsky.browserid.me  (DASHBOARD)
                                          │
                    sign in: type handle ──┤ navigator.id.request({
                                          │   provisionEmail: "<handle>@bsky.browserid.me" })
                                          │   → directed: dialog skips the chooser
                                          │   (secondary: "or use any email" → mint path)
                                          ▼
                              ┌── branch 1: create a local handle
                              │            (<label>.at.browserid.me, unchanged)
                              │
                              └── branch 2: connect existing handle for WRITING
                                          │
                                          ▼
                                   /idp/connect        (2nd OAuth, transition:generic,
                                          │             PAR+PKCE+DPoP, subject pinned
                                          │             to the identity's pinned DID)
                                          ▼
                               write_sessions table  (access+refresh+DPoP key,
                                          │           envelope-encrypted at rest)
                                          │
                    dashboard renders a PERSONALIZED delegation prompt
                    with grantor = "<handle>@bsky.browserid.me" baked in
                                          │
                                    human pastes it
                                          ▼
  agent ── POST /browserid/post ──▶ verify warrant + attestation + scope
           (unchanged contract)           │
                                          ▼
                            relay: com.atproto.repo.createRecord
                            on the USER'S PDS, DPoP-bound OAuth
                                          │
                                          ▼
                     me.browserid.warrant + me.browserid.provenance
                     into the same repo → emit_label(at://<real did>/…)
```

1. **The dashboard** (`bsky.browserid.me`) — a real frontend: directed login,
   branch chooser, connect-consent page, personalized-prompt generator, and
   the connected-agents / warrant list with revoke. See § *The dashboard*.
2. **A second OAuth client** (`/idp/write-client-metadata.json`) that asks for
   `transition:generic` and `grant_types: ["authorization_code",
   "refresh_token"]`. Today's `client_metadata_doc` (`idp/oauth.rs:248`)
   hardcodes `grant_types: ["authorization_code"]` with the comment "there is
   no refresh grant to ask for", and carries a single `scope` field — so the
   write client cannot be the identity client with a flag flipped; it is a
   second document at a second `client_id` URL, sharing the same `jwks_uri`
   and ES256 key (`OAuthKey`, `idp/oauth.rs:59`). See *Decision 1*.
3. **A session manager** — the piece the hand-rolled client does not have.
   The IdP's OAuth code is a deliberate one-shot: `exchange_code`
   (`idp/oauth.rs:446`) returns, `sub` is checked against the pinned DID, and
   the tokens are dropped on the floor. Ongoing use needs refresh rotation,
   a per-server DPoP nonce cache, and DPoP-bound XRPC calls. Built on the
   `atproto-oauth` crate (*Decision 2*).
4. **A second write backend** behind the post handler. `attributed_post`
   (`routes.rs:908`) currently ends in `create_via_session`
   (`routes.rs:858`) → `state.pds.forward(...)` with a bearer session JWT for
   a bridge-owned account, then `write_provenance` (`routes.rs:1763`) →
   `state.pds.put_record(..., &account.access_jwt)`. The relay swaps both for
   an OAuth+DPoP client pointed at the *user's* PDS. Steps 1–5 of the handler
   (cert chain, attestation signature, content hash, freshness, scope check,
   nonce reservation) are backend-independent and must not be duplicated.

## The dashboard

`bsky.browserid.me` is the entry point, linked from the browserid.me homepage.
It replaces the old "paste a prompt into your agent and let it interrogate
you" front door, which asked the human to be the integration layer and — in
practice — let the agent guess wrong about who the grantor was.

### Sign-in: a directed browserid query

The login page has a **text box: "your Bluesky handle"**. The user types
`dan.bsky.social`. The dashboard, acting as an ordinary browserid RP, then
asks browserid to authenticate **that exact identity**:

```js
navigator.id.request({ provisionEmail: "dan.bsky.social@bsky.browserid.me" });
```

**This mechanism exists and is verified in the shipped code**, not assumed:

- `provisionEmail` is accepted by `navigator.id.request(options)` and is
  forwarded to the dialog on both transports — the popup path passes the whole
  options object over the WinChan `params` channel
  (`browserid-broker/static/include.js:803`, read at
  `dialog.js:1655`), and the full-page redirect fallback re-encodes it
  explicitly (`include.js:879`, read at `dialog.js:1783`).
- The dialog treats it as a **directed** request, not a hint: `init()` checks
  `state.provisionEmail` **first**, shows the loading screen, and calls
  `handleEmailChosen(state.provisionEmail)` — the chooser and the email-entry
  screen are skipped entirely (`dialog.js:1717`). From there the ordinary
  primary-IdP discovery runs for that address, so
  `<handle>@bsky.browserid.me` routes into the bsky-handle IdP exactly as it
  does when picked by hand.
- Two behaviors ride along and are worth knowing: a `provisionEmail` request
  suppresses FedCM auto-sign-in (`dialog.js:1156`), and it disables the
  subordinate→parent substitution (`dialog.js:455`) — i.e. the directed
  identity is delivered as itself, never silently swapped for a controlling
  parent account. Both are what we want here.

**Not the same thing, don't confuse them:** `login_hint` is a *URL* parameter
the dialog reads only when it is opened directly (`dialog.js:1784`, used by
`account.html:454`) — it is not exposed through `navigator.id.request`. And
the `email` option (renamed from `experimental_emailHint`,
`include.js:699`/`1056`) is accepted and then never forwarded to the dialog;
it is vestigial. `requiredEmail` is deprecated. **`provisionEmail` is the one
to use.**

The RP-side obligation: the dashboard must still **verify the identity in the
returned presentation equals the one it asked for** before treating the
session as that handle. `provisionEmail` steers the dialog; it is not a
server-enforced constraint on what comes back.

Secondary path, offered as a link under the box: **"or use any email"** — a
plain `navigator.id.request()` with no `provisionEmail`, landing the user in
the existing mint-a-handle flow for people who have no Bluesky handle yet.

### Once signed in: two branches

The dashboard knows the authenticated identity, and therefore (via
`idp_pins`, `store.rs:234`) the pinned DID behind it. It offers:

1. **Create a local handle** — the existing mint path. A
   `<label>.at.browserid.me` account on our PDS, zero custody, unchanged.
2. **Connect existing handle for write access** — the write relay. A
   **second, separate OAuth** (`transition:generic`) to the user's real
   account, producing an encrypted write session. **No local or bridge
   account is created on this branch**; posts go to the real account. This is
   the branch the rest of this document is about.

### The personalized delegation prompt

After the branch is chosen (either branch), the dashboard renders a
**copy-paste prompt for the user's coding agent with the grantor identity
literally baked in** — `dan.bsky.social@bsky.browserid.me` — alongside the
origin to read and the operation to request.

This is not cosmetic. It structurally fixes a bug we actually hit: the agent,
left to infer the grantor, used the human's *personal email* — a real identity
that was not the one the warrant was supposed to speak for. With the grantor
specified in the prompt, **the agent's job shrinks to two steps: request a
warrant for the named grantor, then post.** No interrogating the human about
handles, no guessing the identity shape, no branch logic in `guide.rs` asking
"who do these posts speak for?" — that question is now answered by the person
who actually knows, in the UI where they just proved it.

The generator lives server-side (the identity comes from the authenticated
session, never from a query parameter) and the rendered prompt should be
visibly the *same text* the user pastes — no hidden state, nothing the agent
can't see.

### Management surface

The dashboard is also where a human sees and stops what they started:

- **Connected agents / granted warrants** — for the signed-in identity: which
  grantees hold live warrants, what each is scoped to, when granted, and the
  relay history of posts made under each (from `audit_log`, `store.rs:221`).
- **Write-connection status** — is a live write session attached to this
  identity, when was it connected, when does it expire, and a reconnect link
  when it has died (§ *Session death and re-auth*).
- **Revoke** — one button per warrant, the kill switch (§ *Revocation*).

## The connect flow (branch 2)

The user already proved the handle once, at IdP claim time, and we pinned
`(handle, did)` in `idp_pins`. Connecting for writing is a **second,
higher-scope authorization of the same account**, and it must be unmistakably
a second consent — not something slipped into the sign-in.

1. The human clicks **"connect existing handle for write access"** on the
   dashboard. They are, by construction, already authenticated as
   `<handle>@bsky.browserid.me` (`idp_sessions`, `store.rs:257`), so we know
   *which* pinned DID we are connecting. (`/idp/connect` remains reachable
   directly — e.g. from the reconnect error the agent surfaces — but the
   dashboard is the normal way in.)
2. **A consent page in our own words, before the OAuth hop.** atproto's
   `transition:generic` consent screen says something close to "full access";
   it cannot say "only create posts". So our page must state plainly:
   - what the bridge will be able to do at the protocol level (write anything
     to your repo), and
   - what it will actually do (create `app.bsky.feed.post` records, plus two
     `me.browserid.*` provenance records per post, only when a live,
     unrevoked warrant and a valid grantee attestation say so), and
   - **that those provenance records are permanent, public, firehose-visible
     records in your repo** — they are yours, you can delete them, and the
     bridge will not (*Decision 3*), and
   - that the way to stop it is to revoke the warrant, here on this dashboard
     (§ *Revocation*).
   Saying only the second is a lie of omission; saying only the first makes
   the feature unusable. Say both.
3. PAR → authorize → token, reusing `discover_auth_server`
   (`idp/oauth.rs:298`) and the discovery/metadata plumbing — but with the
   write client's `client_id`, `scope=transition:generic`, and a **long-lived
   DPoP key** rather than the per-flow ephemeral one
   (`idp_oauth_flows.dpop_secret` exists precisely because nothing
   token-shaped rests there today). The flow itself is driven by
   `atproto-oauth` (*Decision 2*), not by the identity client's one-shot code.
4. **Subject pinning is mandatory and is the security crux.** The returned
   `sub` MUST equal the DID pinned for the session's handle in `idp_pins`.
   Without this a user could authenticate the connect hop as a *different*
   Bluesky account, and the bridge would relay posts attributed to
   `dan.bsky.social` into someone else's repo. Mismatch → refuse, store
   nothing, and say which DID was expected. (Reuse of the identity flow's
   `sub`-check discipline, IdP design step 5.)
5. Store the session (§ *Session storage*) and return the human to the
   dashboard, which now shows the connection as live and renders the
   personalized prompt. "Is writing connected?" is answerable from the
   dashboard and from `whoami` without posting.

## The post relay path

`attributed_post` keeps its request shape and its first five checks verbatim.
What changes:

- **Attestation target.** `claims.did` is checked against `token.did`
  (`routes.rs:945`), where `token.did` is today the bridge-owned account's
  DID. In relay mode it must be the **user's real DID**. This is not a bridge
  detail: `AttestationClaims` (`attestation.rs:25`) has `did` in the *signed*
  bytes, so the agent must know the real DID at signing time. The provision /
  token response therefore has to hand the agent the real DID, and the agent
  CLI's attestation vector (the cross-impl test at `attestation.rs:138`) is
  unaffected — only the value changes, not the format.
- **New precondition, after the scope check and before the nonce
  reservation:** load the write session for the grantor identity and assert
  `session.did == pinned_did(grantor) == claims.did`. A grantor with no live
  session gets a distinct, actionable error (§ *Session death and re-auth*),
  never a silent fallback to writing on a bridge account — silently posting
  somewhere else than the human expects is worse than failing.
- **The write itself:** `com.atproto.repo.createRecord` against the user's
  PDS endpoint (from their DID doc, resolved by `idp/resolve.rs`), with an
  `Authorization: DPoP <access_token>` header and a matching DPoP proof
  bound to that access token (`ath` claim), retrying once on
  `use_dpop_nonce`.
- **Provenance follows the post.** `write_provenance` writes
  `me.browserid.warrant` (rkey = warrant ref, once per warrant) and
  `me.browserid.provenance` (rkey = post rkey) — into the user's repo now
  (*Decision 3*). `transition:generic` permits custom collections, so this
  works; but it means the bridge writes **three record types** into a real
  person's repo, and the consent page must say so.

### The enforcement boundary

*(Unchanged from the previous revision. This is the part to review hardest.)*

The OAuth grant is coarse (`transition:generic` ≈ everything); the warrant is
narrow (`repo:app.bsky.feed.post?action=create`, `lib.rs:43`). **The bridge is
the only thing standing between them.** So the boundary must be structural,
not a policy comment:

- The relay client exposes exactly one method — "create a record in repo R,
  collection C" — and C is validated against a **hardcoded allowlist**
  (`app.bsky.feed.post`, `me.browserid.warrant`, `me.browserid.provenance`).
  Not "the collection from the request"; not "whatever `scopes.rs` says".
  The generic `pds.forward` passthrough must never be reachable with a
  relay token.
- Every relay call is reached only through `attributed_post`, i.e. only after
  a verified warrant, a verified grantee signature over *this exact content
  hash*, a freshness check, and a single-use nonce. There is no second entry
  point.
- Repo is always the session's own pinned DID — never a value from the
  request body.
- The existing 15-second warrant-staleness bound and status-list re-check
  apply unchanged; a revoked warrant stops relayed posts exactly as it stops
  bridge-account posts.

## Attestation and labeling in a foreign repo

Good news, verified in code: **the verification path is already
repo-agnostic.** `fully_verified` (`routes.rs:746`) starts with
`resolve_did_doc(state, did)` and reads every record — provenance, warrant,
and the post itself — from *that* DID's PDS via `get_record`
(`routes.rs:1097`), which takes the PDS base as a parameter. It never assumes
our PDS. Likewise the labeler signs a plain `at://` URI
(`labeler.rs:262`/`:286`); `emit_label` (`routes.rs:588`) builds
`at://{did}/app.bsky.feed.post/{rkey}` from whatever DID it is handed, and
atproto labels may target any at-URI subject. So:

- **Attestation record: yes, it can live in the user's repo**, as part of the
  `me.browserid.provenance` record (the attestation is embedded in that
  record, `routes.rs:1819`, not a separate collection). It is data, not a
  protocol object the PDS has an opinion about, and `validate: false`
  (`pds.rs:216`) is already how we write custom lexicons.
- **Labels: yes, `labeler.at.browserid.me` can label a post in a foreign
  repo**, and the badge shows for anyone subscribed to our labeler. Nothing
  about that changes.
- **What does change:**
  - **The user's repo gains records they didn't write by hand.** On the
    bridge-account path the repo was ours and disposable. Now these are
    permanent artifacts in a real person's data, replicated to the firehose
    and to every AppView. The connect consent must cover it and state that
    the records are the user's to delete (they own the repo) even though the
    bridge won't delete them.
  - **A failed provenance write leaves a bare post — and this must now fail
    loudly.** Today `write_provenance` failing just logs a warning
    (`routes.rs:1798`) and the handler returns 200 — acceptable when the
    result was an unbadged post on a throwaway account. On a real timeline
    the same failure is a post **the human's followers can already see**,
    with no provenance and no badge, and no one told anybody. So the relay
    treats provenance as **part of the operation**: write it as part of the
    post transaction, and if it fails, return an error that says the post
    landed but is unattested, so the agent can tell the human. Log-and-200 is
    the wrong shape here and is a deliberate divergence from the bridge path.
  - **Blob/embed handling** (images) needs the same relay treatment
    (`com.atproto.repo.uploadBlob` against the user's PDS) or images stay out
    of scope for v1.
  - **The `validate: false` habit deserves a second look** for
    `app.bsky.feed.post` in a real repo — a malformed post record on a real
    timeline is worse than on ours.

## Session storage and lifecycle

A new `write_sessions` table alongside the `idp_*` tables in `store.rs:165`
(same rusqlite DB, same `CREATE TABLE IF NOT EXISTS` migration style, same
idempotent-`ALTER` convention at `store.rs:281`):

```
write_sessions(
  identity        TEXT PRIMARY KEY,   -- '<handle>@bsky.browserid.me' (lowercased)
  did             TEXT NOT NULL,      -- MUST equal idp_pins.did for that handle
  issuer          TEXT NOT NULL,      -- auth server (entryway or self-hosted PDS)
  pds             TEXT NOT NULL,      -- resource server we call
  access_enc      BLOB NOT NULL,      -- envelope-encrypted
  refresh_enc     BLOB NOT NULL,      -- envelope-encrypted
  dpop_secret_enc BLOB NOT NULL,      -- envelope-encrypted; long-lived, per session
  access_expires  TEXT NOT NULL,
  connected_at    TEXT NOT NULL,
  last_refresh    TEXT NOT NULL,
  state           TEXT NOT NULL       -- live | expired | revoked
)
```

**Envelope encryption of the token columns** (*Decision 4*). Nothing in the
bridge encrypts anything today — the existing `accounts.access_jwt` /
`refresh_jwt` columns (`store.rs:173`) are plaintext, as is
`idp_oauth_flows.dpop_secret`, which is defensible only because those are
throwaway bridge accounts and 5-minute flow state. Real users' write tokens
are a different class of secret. Encrypt **the three token/key columns**, not
the whole database: AEAD (XChaCha20-Poly1305 or AES-GCM) with a key from the
environment/secret store, never from the DB, with the identity as associated
data. Whole-DB SQLCipher was considered and rejected — it protects the
uninteresting columns too, complicates the build and ops for every existing
table, and still leaves the key next to the file. This is new infrastructure
introduced specifically for third-party-account write tokens, and it is the
one place where "we'll add encryption later" is not acceptable: **the table
should not exist before the key does.**

**Refresh rotation with single-flight locking.** atproto refresh tokens are
single-use with mandatory rotation: two concurrent posts that both see an
expired access token and both refresh will race, and the loser's rotated
token is dead — *and may invalidate the whole session*. So refresh must be
serialized per identity: an in-process `Mutex`/`Semaphore` keyed by identity
around a check-then-refresh, with the DB write inside the lock and a re-read
after acquiring it (the winner may already have refreshed). This is exactly
the hazard the IdP design cited as a reason to keep sessions out of the mint
path; here we accept it, but only on the post path, which is low-frequency
and already serialized by the nonce reservation. Refresh proactively (before
expiry) rather than only on 401, to keep the racing window small.

**DPoP nonce cache.** `with_dpop_nonce_retry` deliberately does **not** cache
nonces across calls (`idp/oauth.rs:507`) — correct for a one-shot flow behind
a human, wrong for a hot posting path where it doubles every request. The
relay keeps a per-authorization-server / per-resource-server nonce cache
(updated from every `DPoP-Nonce` response header), with a single-retry
fallback for when the cached nonce goes stale. Note the auth server and the
PDS issue **different** nonces; cache them separately.

**Session death and re-auth.** Confidential-client sessions last on the order
of ~90 days (spec allows up to 180; assume 90 and never rely on the ceiling),
and can die earlier — user disconnect at their PDS, account migration,
entryway policy. The failure must be legible all the way out to the human:

- The relay distinguishes "session expired / revoked" from every other error
  and marks the row `expired`.
- `POST /browserid/post` returns a dedicated error code (e.g.
  `write_session_expired`) with the reconnect URL in the body — **not** a
  generic 502. The warrant is still perfectly valid; only the OAuth session
  is gone, and conflating the two will send agents down the wrong path.
- The guide instructs the agent, on that error, to stop and hand the human
  the reconnect link — the same "hand over a URL and wait" pattern already
  used for warrant approval. The dashboard shows the same reconnect prompt.
- Reconnecting reuses the same connect flow and the same DID pin; nothing
  about the identity or the warrant needs redoing.

## Revocation

**One kill switch: revoke the warrant.** At the registrar, from the
dashboard, existing mechanism. It stops the agent immediately and it stops
**real-account posting too** — the next post fails the status-list re-check
inside the 15-second staleness bound and `/browserid/post` returns
`401 invalid_token — warrant revoked` **before the relay backend is ever
reached**. The write session survives; the agent has no authority to use it.
That ordering is what makes one switch sufficient, and it should be stated
explicitly in the demo copy: revoking the warrant is not a bridge-side
courtesy, it is checked ahead of any write.

**The "disconnect the app at your PDS" second kill switch is dropped**
(*Decision 5*). It works, and a user is of course free to do it, but
demonstrating it demonstrates *atproto's* OAuth disconnect — not browserid —
and putting it in the demo script muddies the claim being made. It also
dragged in `revocation_endpoint` parsing we do not need. The bridge still
treats a revoked-token error from the PDS as authoritative and marks the row
`revoked` on first observation, because that is correctness, not a feature.

A local "disconnect" button on the dashboard that deletes the write-session
row is a convenience — it ends the connection cleanly — but it is performed
by the party the user would be protecting themselves from, so it is not a
security control and should not be sold as one. The security control against
a *misbehaving agent* is warrant revocation; the user's recourse against a
*breached bridge* is disconnecting at their own PDS, which we should mention
honestly in the consent copy without building a demo beat around it.

## Security and threat model

**Be blunt: this is strictly more dangerous than the IdP-only design.** The
IdP's headline property was zero custody — one code exchange, tokens
discarded, nothing at rest that could post as anyone. The write relay
deletes that property for every user who opts in. The bridge database becomes
a store of live write credentials for real Bluesky accounts with real
followers.

**Blast radius if the bridge DB leaks.** An attacker with the rows and the
AEAD key can post as every connected account, for the remaining session
lifetime, until each user notices and disconnects. They are not constrained
to `app.bsky.feed.post` — the `transition:generic` grant lets a raw token do
anything: delete posts, rewrite the profile, follow, block, or wipe the repo.
The bridge's collection allowlist binds *the bridge's code*, not a stolen
token. Mitigations that actually bound it, in rough order of value:

- **Key separation.** The AEAD key lives in the environment/secret store, not
  the DB; a DB-only leak (backup, snapshot, SQLite file) yields ciphertext.
- **Small connected population.** The write relay is **allowlisted in v1**
  (*Decision 6*) — people who knowingly opted into an experiment.
- **Short session horizon.** Do not chase the 180-day ceiling; consider
  proactively re-authing well before 90 days, and expire idle sessions (no
  post in N days → drop the row). A session nobody is using is pure liability.
- **Audit everything.** Every relayed write goes in `audit_log`
  (`store.rs:221`) with the real DID, and the user reads their own relay
  history on the dashboard. Detection is the realistic control here.
- **Operational hygiene:** the DB is not in backups that leave the host
  unencrypted; the host is the same one holding the IdP signing key, so its
  compromise was already fatal to *identity* — now it is also fatal to
  *content*. Ops for this box should be treated accordingly.

**Why the warrant + attestation layer still matters.** It would be easy to
argue the browserid layer is now decorative — if the bridge can post anything,
what does a narrow warrant buy? Two things:

1. It constrains the **agent**, which is the party the user is actually
   delegating to and the one whose behavior they cannot predict. The agent
   never sees an OAuth token; it holds a warrant that says create-post and
   nothing else, revocable in seconds by the human from the dashboard, with
   no ability to escalate. "Delete that post" and "edit my profile" remain
   impossible for the agent even though they are possible for the bridge.
   That is the demo's core claim and it survives intact.
2. It makes each post **attributable and unforgeable**. The grantee's
   signature over the content hash (`attestation.rs`) cannot be produced by
   the bridge — it lacks the access key. A compromised bridge posting with a
   stolen token produces posts with *no valid provenance record and no
   badge*; the labeler will not badge them because `fully_verified` will fail.
   So the trust surface degrades visibly rather than silently.

What the layer does **not** buy: any protection against the bridge itself
being evil or breached. The user's defense there is disconnecting the app at
their own PDS, and nothing else. That should be said out loud on the consent
page, not buried.

**Threats specifically introduced by the relay:**

- *Wrong-account connect* — mitigated by the mandatory `sub` == pinned-DID
  check (connect step 4). Without it the whole design is unsound.
- *Wrong-identity sign-in* — the dashboard must verify the returned
  presentation's identity equals the `provisionEmail` it asked for;
  `provisionEmail` steers the dialog, it does not bind the response.
- *Confused deputy on collection* — mitigated by the hardcoded allowlist and
  the single entry point (§ *Enforcement boundary*).
- *Refresh race bricking a session* — mitigated by single-flight locking;
  worst case is a forced reconnect, not a silent wrong write.
- *Handle reassignment mid-session* — the pin machinery already suspends a
  binding whose DID changed; a suspended binding must also kill its write
  session, or we would keep posting as an identity we no longer certify.
- *Stale grantor pin* — the relay resolves the target DID from `idp_pins`,
  never from the request, so a warrant naming a handle cannot be redirected.

## End-to-end demo narrative

This is the payoff, in order:

1. **browserid.me** — the homepage links to the Bluesky demo.
2. **`bsky.browserid.me`** — the dashboard's login page. "Your Bluesky
   handle:" the user types `dan.bsky.social`.
3. **Directed sign-in.** The dashboard calls
   `navigator.id.request({ provisionEmail: "dan.bsky.social@bsky.browserid.me" })`.
   The browserid dialog skips the chooser and drives that one identity
   straight through the bsky-handle IdP — the user proves the handle and lands
   back on the dashboard signed in *as their handle*.
4. **Connect write access.** They pick "connect existing handle for write
   access", read the consent page (what we can do, what we will do, the
   permanent records in their repo), and complete the second OAuth on their
   own PDS. `sub` matches the pinned DID; the session is stored encrypted.
5. **Copy the personalized prompt.** The dashboard renders it with
   `dan.bsky.social@bsky.browserid.me` already in the text. One copy button.
6. **Paste into the coding agent.** The agent's whole job: request a warrant
   for that named grantor, wait for the human to approve it, then post. No
   questions about who the user is.
7. **The human approves the warrant** at the registrar.
8. **The agent posts — to the user's REAL timeline.** Their followers see it.
   It carries the badge; `/verify` reads the signed `me.browserid.provenance`
   record **from the user's own PDS** and confirms which agent wrote it, under
   whose authority, over exactly that content. Nobody has to trust us.
9. **The user revokes the warrant** on the dashboard.
10. **The next post fails** — `401 invalid_token — warrant revoked`, checked
    before the relay is reached. The write session is still live; the agent
    simply has no authority anymore. That is the whole thesis in one beat.

## Decisions

Locked. Recorded here rather than re-litigated in build.

1. **Two OAuth clients, kept separate.** The identity client stays the
   hand-rolled one-shot: `exchange_code` returns only the DID, tokens hit the
   floor, and tests lock that behavior. **Do not touch it.** The client
   metadata document carries a single `scope` and a single `grant_types` list
   (`idp/oauth.rs:248`), so a shared `client_id` would advertise
   `transition:generic` to *every* user including identity-only ones — the
   consent screen for a pure login would read as full account access,
   destroying the IdP's best property. Two `client_id`s, same key, same
   `jwks_uri`. Cost: two entries on the user's app-connections page.
2. **The write relay adopts `atproto-oauth` (0.14.5)** for full session
   lifecycle: refresh rotation with single-flight, `ath`-bound DPoP XRPC, and
   a per-server nonce cache. Rationale for *not* unifying the two clients on
   the crate: doing so would convert the identity flow's **structural** zero
   custody (there is no code path that stores a token) into a "we promise to
   discard" discipline — for the most sensitive flow in the system. Not worth
   it. Two caveats for build: (a) the crate must accept an **externally
   supplied** ES256 key so the write client shares the bridge's published
   `jwks_uri`; (b) the client metadata document stays ours, served from our
   origin with `client_id` == its URL, so we may use the crate for
   session/DPoP mechanics while keeping `client_metadata_doc`-style documents.
   `atrium-oauth` (0.1.7) is the fallback if confidential-client
   `private_key_jwt` support proves thin.
3. **Full provenance records into the user's real repo** — not labeling only.
   Independent verification (`/verify` reading the signed
   `me.browserid.provenance` record from the *user's* PDS) is the browserid
   thesis; labeling-only makes the badge mean "trust our labeler", which is
   the thing we are arguing against. Accepted cost: permanent,
   firehose-visible custom-lexicon records in a real person's repo, and three
   writes per post. Consequences that are therefore **requirements**: the
   connect consent must disclose the records and say they are the user's to
   delete, and a failed provenance write must fail loudly rather than
   log-and-200 (§ *Attestation and labeling in a foreign repo*).
4. **Envelope-encrypt the write-session token columns**, not the whole DB.
   AEAD key from the secret store; identity as associated data. Not
   SQLCipher. This is new infra introduced specifically for third-party
   write tokens — the bridge encrypts nothing today.
5. **Kill switch = warrant revoke only.** The "disconnect the app at your
   PDS" second switch is dropped from the design and the demo: it
   demonstrates atproto's OAuth disconnect, not browserid, and is off-thesis.
   Warrant revocation already stops relayed posts transparently, because
   `/browserid/post` checks warrant status before reaching the relay backend.
   No `revocation_endpoint` parsing needed.
6. **Allowlist the write relay in v1** — opt-in testers only, until at least
   one refresh cycle and one session expiry have been observed in production.
   Cheap to remove, very expensive to have skipped.
7. **Entry is web-first.** The dashboard is the front door; the agent is
   handed a prompt with the grantor already decided. The old "the agent asks
   the human who the posts speak for" branch in `guide.rs` goes away.

## Build scope and phasing

This is now a bigger bean than the previous revision: it includes a real
frontend. The pieces:

- the `atproto-oauth`-backed write client + encrypted `write_sessions` store;
- the `/browserid/post` relay backend and the enforcement boundary;
- the connect consent flow and second OAuth client;
- the dashboard (directed login, branch chooser, management/revoke);
- the personalized-prompt generator.

Suggested phase order, chosen so each phase is independently reviewable and
the riskiest security surface lands first with the fewest moving parts:

**Phase 1 — write-relay backend + session store, behind the allowlist.**
Second OAuth client metadata, `atproto-oauth` integration, `write_sessions`
with envelope encryption, the `PostBackend` seam in `attributed_post`, the
hardcoded collection allowlist, provenance-fails-loudly, refresh single-flight
and nonce cache. Driven by a bare `/idp/connect` page and curl. **The review
that matters happens here** — everything after this is UI over a boundary
already argued.

**Phase 2 — the dashboard shell and the connect UI.** Sign-in (initially
plain, undirected `navigator.id.request`), branch chooser, the consent page in
our own words, connected-agents list, revoke. This makes the flow usable by a
human and makes revocation demonstrable.

**Phase 3 — directed login and the personalized prompt.** The handle text box
+ `provisionEmail`, the identity-match check on the returned presentation, the
"or use any email" secondary path, and the prompt generator. This is the
polish that removes the grantor-guessing bug class; it needs Phases 1–2 to be
worth looking at, and it is the smallest of the three.

**Then:** lift the allowlist after one observed refresh cycle and one observed
expiry (*Decision 6*).

**Reuse without modification:** `idp/resolve.rs` (handle→DID→PDS, with the
bidirectional check), `discover_auth_server`, `OAuthKey`, the `idp_pins`
table, all of `attestation.rs`, `fully_verified`, `emit_label`, and the
labeler.

**Touch points:** `store.rs` (new table + accessors + encryption helper);
`routes.rs` (`attributed_post` gains a backend switch; `create_via_session`
and `write_provenance` get relay-mode siblings — better as a small
`PostBackend` seam than as branches sprinkled through both functions);
`idp/routes.rs` (connect + consent + disconnect + dashboard routes);
`guide.rs` (drop the who-do-you-speak-for branch; add the
`write_session_expired` instruction); new `relay.rs` (session manager); new
dashboard static assets.

**Config:** the relay is off unless a write-client key/`client_id` and an
AEAD key are configured — same graceful-degradation shape as `labeler: None`
and `idp: None` in `BridgeState`.

## Remaining open questions

Genuinely unsettled build details, not architecture:

1. **Where does the dashboard's own browserid RP session live** — a plain
   cookie session on `bsky.browserid.me`, or reuse `idp_sessions`? The
   identity is the same string either way, but the dashboard authenticates as
   an ordinary RP while `idp_sessions` exists for the IdP side; conflating
   them may be convenient or may be confusing. Decide early — the connect
   flow reads whichever one it is.
2. **Blobs/images in v1** — relay `uploadBlob` against the user's PDS, or
   text-only posts to start? Leaning text-only for Phase 1.
3. **`validate: false` for `app.bsky.feed.post` in a real repo** — flip it to
   `true`? A malformed record on a real timeline is worse than on ours.
4. **Idle-session expiry length** — how many days without a post before we
   drop the row.
5. **Suspended handle binding: delete the write session or merely disable
   it?** Disable is friendlier on a transient DID-doc hiccup; delete is safer.
6. **Does the personalized prompt embed anything besides the grantor** — e.g.
   a pre-issued warrant-request link or a nonce that ties the paste to this
   dashboard session? Tempting, but it adds state the agent can't see; the
   default is plain text with the grantor named and nothing hidden.
