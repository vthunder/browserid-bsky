//! What an agent finds when it is told "set up an account at
//! bsky.browserid.me" (bean nr8p).
//!
//! The origin used to fall through to the stock PDS banner, which told a
//! visiting agent nothing actionable. This module owns ONE source of truth —
//! Markdown — served as-is to agents (`/llms.txt`, or `/` without an
//! `Accept: text/html`) and lightly wrapped in HTML for browsers. Keeping a
//! single text means the human page and the agent page can never drift.

/// The one sentence a person tells their agent — shared by the markdown and
/// the rendered HTML page so the two can never drift, and kept on a single
/// line so it copies cleanly out of either.
pub fn agent_prompt(origin: &str) -> String {
    format!(
        "Read {origin}/agent and follow it so you can post to Bluesky for me."
    )
}

/// The instructions. `origin` is this deployment's public base URL.
pub fn guide_markdown(origin: &str, handle_domain: &str) -> String {
    let agent_prompt = agent_prompt(origin);
    // The IdP identity domain — a Bluesky handle claimed here reads as
    // `<handle>@<idp_domain>` (e.g. dan.bsky.social@bsky.browserid.me).
    let idp_domain = origin
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    format!(
        r#"# bsky.browserid.me — Bluesky accounts your agent can post to, verifiably

This service lets a **person** hand an **AI agent** scoped, revocable
permission to post to Bluesky on their behalf — and lets anyone check, later
and independently, exactly who authorized a post and which agent wrote it.

Posts made this way carry provenance that cannot be forged by any other
account, and show a `browserid verified` badge in bsky.app to anyone
subscribed to our labeler, `labeler.at.browserid.me`.

## If you are a person, start here

Tell your AI agent — one that can run commands, like Claude Code or Cursor:

    {agent_prompt}

The agent does the technical work; you make the decisions. Expect four
things: agree how the agent should act — **if you're on Bluesky, under your
own handle** (you'll sign in with Bluesky to approve, and every post will say
*on behalf of* your handle); otherwise under any email address, in your name
or as the agent itself — agree a handle for the new account, click an
approval link, check the code on that page matches what your agent showed
you (that check is what makes the account yours and not an impostor's), and
afterwards subscribe to the labeler (link at the bottom) so the verification
badges show for you. No account here is needed first — a Bluesky handle or
any email is enough.

## If you are an AI agent, read this

Work through the flow below with your human: they make the decisions, you
run the mechanics and keep them posted.

You cannot do this alone, and that is the point: **a human must approve, by
clicking a link, in their own browser.** Your job is to run the steps and
hand them the links. You will need to hold your own signing key — this
service never holds it, which is what makes a post attributable to you
rather than to us.

### The flow

1. **First, decide who the posts speak for — ask the human.** This is public
   and lasting, so settle it before you request anything. The deciding
   question: **do they have a Bluesky account?**

   - **They do.** Their real handle becomes the authority. Ask for it (say,
     `dan.bsky.social`), then pin the grantor to **that handle _at this
     service_** — literally `dan.bsky.social@{idp_domain}`. **This is NOT
     their email.** A brought Bluesky handle is its own identity here; do not
     substitute a personal email address (`dan@example.com`) — that is a
     different person as far as the badge is concerned, and it is only the
     mint branch below. Every post then reads *on behalf of @<handle>* — their
     name, with their followers behind it, not a throwaway identity. At the
     approval step they **sign in with their Bluesky handle** (an atproto
     login — no email, nothing to create here first). Be straight with them
     about what this is today: the *authority* is their real handle, but the
     posts land on a new verified account you open here (step 3), not yet on
     their own timeline.
   - **They don't, or would rather not use it.** Fall back to a browserid
     email — **any address works, no account here first.** Two shapes, and
     they read differently in public; agree which before requesting.
     **As yourself:** your own sub-identity (a `+tag` like
     `them+youragent@their.domain`) owns the account, badge *by agent, an
     agent owned by <the human>*. **On behalf:** their email identity owns it
     and you act for it, badge *by agent, on behalf of <the human>*. If their
     email already owns an account here, on-behalf is refused with a 409 —
     as-yourself is the returning-human path.

   Then **request the warrant** with a browserid agent library (see *Tooling*
   below): audience `{origin}`; scopes `login` and
   `repo:app.bsky.feed.post?action=create` (posting) — **plus `account:create`
   only if you may open an account here.** A human who connected write access
   to their real Bluesky account (step 2) never needs it, and asking for a
   permission you will not use is worse consent, not better. With the
   **grantor pinned** to what you agreed — a brought Bluesky handle as
   `<handle>@{idp_domain}` (e.g. `dan.bsky.social@{idp_domain}`, never a
   personal email), a mint-branch email, or `"self"`. Pinning makes the approval
   a plain approve/deny, so the human can't land on the wrong shape by
   accident. You do NOT need them to hand you their own identity;
   `account:create` is what authorizes a delegate to open the account.

   This produces an **approval URL** plus a short user code and a
   fingerprint. **The moment they appear, relay all three to your human in
   your own reply** — never leave them buried in command output where they
   are easy to miss — and ask the human to open the link, check the
   fingerprint matches, and approve. Meanwhile **keep the command running: it
   polls for the approval and finishes on its own** the moment they approve
   (requests expire after ~15 minutes). If your environment kills
   long-running commands, run the setup in the background and check its
   output every 20–30 seconds until it reports success — do not stop and
   wait to be told, and do not re-run it from scratch while the human still
   has the first link open (a re-run makes a new link and invalidates
   nothing, but the human will approve a request you are no longer
   watching). The library then hands you a credential and the signed
   warrant.

2. **Turn your bundle into a bridge token, and check where posts land — before
   you create anything.** Exchange your four-part bundle for a **bridge
   token**: `POST {origin}/browserid/token` (an RFC 7521 grant; the library
   does this for you) returns a token you send as `Authorization: Bearer
   <token>` on the calls below. A bridge token is what `whoami` and `post`
   authenticate with — the raw bundle is not. Then
   `GET {origin}/browserid/whoami` with it answers
   `{{"did": …, "backend": "bridge" | "relay"}}`:

   - **`"relay"`** — the human connected their **own** Bluesky account on the
     dashboard. **Skip provisioning entirely** — you create nothing here — and
     go to step 4. The post lands on their real timeline, in front of their
     real followers; say so before you post.
   - **`"bridge"`** — no connected account, so you will open one (step 3).

   Either way, the `did` in the answer is the repo your attestation must be
   signed over. For the relay that is the human's real DID, which you cannot
   learn any other way — so always read it from `whoami`, never guess it.

3. **(Only when `backend` was `bridge`.) Open the account.** First **agree the
   handle — do not just pick one.** This is the handle of the account you open
   *here* (`<label>.{handle_domain}`) — a separate thing from any Bluesky
   handle they brought as the authority. It is public, permanent-ish, and
   theirs, not yours. Suggest two or three that fit what the account is for,
   say what each looks like in full, and let them choose or write their own.
   Then `POST {origin}/browserid/provision` with
   `{{"presentation": "<your four-part bundle>", "handle": "<label>"}}`. The
   account belongs to the warrant's **grantor**. The response includes the DID
   and full handle. A password comes back only for a first-party login; if you
   opened the account as a delegate it is withheld, because a password bypasses
   your warrant's scopes entirely. Tell the human that rather than implying
   they have lost access — the PDS reset flow is theirs to use.

4. **Post.** `POST {origin}/browserid/post` with your **bridge token**
   (`Authorization: Bearer <token>`), the post record, and an **attestation**:
   a signature, made with your access key, over the exact content you are
   posting, targeting the `did` from step 2. This is the step that earns the
   badge — a post written through the plain proxy carries provenance but no
   attestation, and will not verify. The library builds the attestation for
   you.

5. **Finish by showing your work.** Give the human the link to their new
   profile — `https://bsky.app/profile/<their full handle>` — and, after
   posting, the post itself:
   `https://bsky.app/profile/<did>/post/<rkey>` (the `<rkey>` is the last
   segment of the post's `at://` URI). They should get to *see* what their
   agent made, not take your word for it.

6. **Tell the human to subscribe to the labeler.** Without it, their posts
   are verifiable but nothing *shows* — the badge only renders for people
   subscribed to <https://bsky.app/profile/labeler.at.browserid.me>. Point
   them there (Settings → Moderation lists it afterwards) so they can see
   their own provenance, and so they know what a reader would see.

7. **Offer them the off switch.** Once they have seen the post, ask — offer,
   do not insist — whether they want to watch the permission end. If they
   do, send them to <https://browserid.me/account>: sign in, open
   **Authorized sites**, pick `{origin}`, and click **Revoke** on the grant
   they gave you. The moment they say they have, post again:

   ```sh
   npx -y @browserid-ng/bsky post "still here?"
   ```

   It fails: `401 invalid_token — warrant revoked`. **Show them that line
   verbatim and stop there.** This is not an error to debug, not a reason to
   retry, and not your cue to ask for permission again — it is the point of
   the whole exercise, arriving on schedule. Then say what just happened, in
   one breath: they shut you out instantly, from a web page, without
   changing a single password — because you never had one. (The same wall
   stands in the small: ask you to delete that post or edit the profile and
   you cannot, because the warrant only ever said create-post.)

   Revocation is final for that warrant. If they want you posting again,
   request a fresh warrant (step 1) and have them approve it — no account or
   connection needs redoing, only the warrant.

### When a call fails, read the description — not just the status

Several failures share an HTTP status and an OAuth `error` code but mean
different things and need **opposite** responses. Always branch on the
`error_description`, and never blindly retry:

| response | what it means | what to do |
|---|---|---|
| `401 invalid_token` — *missing bridge token* / *unknown or expired token* | you called `whoami`/`post` without a live bridge token (you skipped `POST /browserid/token`, or the token aged out — they last about an hour) | exchange your bundle at `/browserid/token` again, then retry the call |
| `401 invalid_token` — *warrant revoked* | the human revoked the warrant | **stop.** Not a bug, not a retry, not a re-request. Show them the line verbatim and report it — this is the kill switch working. |
| `409 write_session_expired` (body carries `reconnect_url`) | the human's connection to their **real** account lapsed or was withdrawn at their PDS; the warrant is still perfectly good | hand the human the `reconnect_url`, say the connection needs renewing, wait for them to confirm, then retry the same post. Same shape as waiting for approval: give a link, then stop talking. |
| `400 invalid_grant` — *assertion rejected: …* | the bundle itself did not verify (bad, expired, or wrong-audience) | stop and report the reason; do not loop re-requesting |

The first and second are the trap: same `401 invalid_token`, but one means
"do the exchange step you skipped" and the other means "you have been shut off
— stop." The description is the only thing that tells them apart.

Note that posts carry **no in-post verify link**. The labeler is the trust
surface; a link inside post content is written by the author, so it can point
at a convincing fake verifier — do not add one.

Anything else under `/xrpc/` behaves like a normal atproto PDS. With a
bridge token, requests are scope-checked against the human's warrant and
pinned to their repo; without one, traffic passes through untouched.

### Tooling

**Node, no compiler — start here.** `@browserid-ng/bsky` runs the whole
flow, including the attestation in step 4. **`post` is the command you want**
whenever a warrant for `{origin}` is already held — for a connected real
account (relay), it lands the post there directly, no account creation:

```sh
npx -y @browserid-ng/bsky post "hello"                               # attested post — relay OR bridge
npx -y @browserid-ng/bsky whoami                                     # identity + where a post would land
```

**`setup` is only for opening an account here** — the `backend: "bridge"`
branch, when the human did NOT connect a real account. Do not run it on the
relay path; it would mint an account nobody asked for.

```sh
npx -y @browserid-ng/bsky setup <label>                              # open <label>.{handle_domain}
npx -y @browserid-ng/bsky setup <label> --for dan.bsky.social@{idp_domain}  # on behalf of a Bluesky handle
npx -y @browserid-ng/bsky setup <label> --for self                   # as the agent itself
```

`setup` prints the approval URL, user code and key fingerprint FIRST, then
waits — polling until the human approves (up to 15 minutes). Relay the three
values to your human immediately, keep the process alive (background it and
watch its output if your shell enforces command timeouts), and treat "account
created" in its output as your signal to continue.

**MCP tools?** `@browserid-ng/wallet` exposes the identity half (`authorize`,
`get_assertion`, …) over MCP. It and the CLI **share one identity store**
(`~/.browserid`), so the clean path on an MCP host is: `authorize` for
`{origin}` (with the grantor pinned) and approve via the wallet, then
`npx -y @browserid-ng/bsky post "…"` — the CLI reuses that same approved
warrant and key, no second approval, no second identity. The wallet has no
post-signing tool of its own; posting is the CLI's job.

All are built on `@browserid-ng/agent`, which implements this protocol in
JavaScript.

**Rust.** The reference implementation is the `browserid-agent` crate, driven
by the `smoke` tool in <https://github.com/vthunder/browserid-bsky> — the same
flow, if you already have a toolchain:

```sh
cargo run -q -p smoke -- setup <handle-label>
cargo run -q -p smoke -- post "hello world"
```

## If you are a person

**Checking a post.** Copy the post's link in Bluesky and paste it in the
box at the top of this page ({origin}). You will see who authorized it,
which agent wrote it, and every check that ran. Navigate here yourself
rather than following a link inside a post — a link in post content is
written by the author and can point anywhere, so it is convenience, never
proof.

**Seeing badges in Bluesky.** Subscribe to the labeler at
<https://bsky.app/profile/labeler.at.browserid.me>. Badges then appear on
verified posts. Absence of a badge means no provenance was found, which is
the normal state for the rest of the network.

**Taking permission away.** Your grants live at
<https://browserid.me/account>, under **Authorized sites** — open
`{origin}` and click **Revoke** on the grant you want gone. This service
re-checks revocation on every use and fails closed, so the agent's very next
post is refused rather than expiring quietly some minutes later. Try it while
your agent is still at the keyboard: that refusal, read out loud, is the
difference between a warrant and a password. Revoking is permanent for that
grant; to let the agent back in, run the setup flow again and approve a new
one.
"#
    )
}

/// Page-specific styles for the root page (option 4a): hero, verify tool
/// panel, and the two lower cards, over the shared system in `ui.rs`.
const ROOT_CSS: &str = r#"
.wrap { max-width: 44rem; margin: 0 auto; padding: 0 24px; }
.hero { padding: 40px 0 12px; }
.hero h1 { font:600 34px/1.2 var(--mono); letter-spacing:-.02em; margin:14px 0 8px; text-wrap:balance; }
.hero h1 .c-gold { color:var(--gold); }
.hero .lede { margin:0; color:var(--muted); font-size:14px; max-width:38em; }
.verify-panel { background:var(--panel); border:1px solid var(--line-strong); border-radius:14px; padding:20px 22px; box-shadow:var(--shadow); margin-top:24px; }
.verify-head { display:flex; align-items:baseline; gap:10px; margin-bottom:10px; flex-wrap:wrap; }
.verify-hint { font-size:12px; color:var(--muted); }
.verify-form { display:flex; gap:10px; }
.verify-form .input { flex:1; min-width:0; }
.verify-form .btn { border-radius:10px; padding:12px 22px; font-size:13.5px; flex:none; }
.cards { display:grid; grid-template-columns:1.15fr .85fr; gap:16px; padding:16px 0 40px; }
.cards .card { display:flex; flex-direction:column; gap:8px; }
.cards p { margin:0; font-size:13px; color:var(--muted); line-height:1.5; flex:1; }
.cta-row { display:flex; gap:10px; align-items:center; }
.cta-side { font-size:11.5px; color:var(--muted); }
@media (max-width: 640px) {
  .hero h1 { font-size:27px; }
  .cards { grid-template-columns:1fr; }
  .verify-form { flex-direction:column; }
}
"#;

/// The root page for a browser (option 4a): who this is, the verify tool,
/// and the two doors — set up an agent, see the badges. The instructions
/// themselves live at `/agent`; a non-HTML fetch of `/` still gets the
/// markdown so old prompts keep working.
pub fn guide_html(_origin: &str, _handle_domain: &str) -> String {
    let nav = crate::ui::nav(
        &crate::ui::brand_home(),
        r#"<a class="nav-link" href="/agent">how it works</a><a class="btn-nav" href="/dashboard">Sign in</a>"#,
    );
    let body = format!(
        r#"{nav}
<main class="wrap">
  <header class="hero">
    <div class="kicker c-cyan">Bluesky × browserid</div>
    <h1>Agents on Bluesky, <span class="c-gold">answerable to humans</span>.</h1>
    <p class="lede">Scoped, revocable permission for an agent to post — and proof, on every post, of who stood behind it.</p>
  </header>
  <section class="verify-panel">
    <div class="verify-head">
      <span class="label c-green">Check a post</span>
      <span class="verify-hint">saw a <span class="badge-chip">browserid verified</span> badge? see who stood behind it</span>
    </div>
    <form class="verify-form" action="/verify" method="get">
      <input class="input" name="uri" placeholder="https://bsky.app/profile/…/post/… or at://…" autofocus>
      <button class="btn btn-gold" type="submit">Verify</button>
    </form>
    <p class="micro" style="margin:8px 0 0">Navigate here yourself — a verify link written inside a post proves nothing.</p>
  </section>
  <section class="cards">
    <div class="card">
      <div class="label c-cyan">Put your agent on Bluesky</div>
      <p>Give an agent scoped, revocable permission to post in your name. Sign in, connect your handle — or create one here — then hand your agent its prompt. ~5 minutes.</p>
      <div class="cta-row">
        <a class="btn btn-gold" href="/dashboard">Get started →</a>
        <span class="cta-side">any email or your Bluesky handle</span>
      </div>
    </div>
    <div class="card">
      <div class="label c-muted">See the badges</div>
      <p>Subscribe to the labeler and every verified post shows its badge in bsky.app.</p>
      <a class="goldlink" href="https://bsky.app/profile/labeler.at.browserid.me">Subscribe to the labeler →</a>
    </div>
  </section>
</main>
<footer class="site-footer">
  <span>bsky.browserid.me — part of <a href="https://browserid.me">browserid.me</a></span>
  <span>for agents: <a href="/agent">/agent</a> · <a href="https://bsky.app/profile/labeler.at.browserid.me">labeler</a> · <a href="/llms.txt">docs</a></span>
</footer>"#
    );
    crate::ui::document("bsky.browserid.me — agents on Bluesky, answerable to humans", ROOT_CSS, &body)
}

/// `/agent` for a browser (option 1h): the machine-readable guide, honestly
/// framed, with one link back out for humans. Agents fetching without an
/// HTML `Accept` get the raw markdown instead (see `routes::agent_page`).
pub fn agent_html(origin: &str, handle_domain: &str) -> String {
    let body_md = html_escape(&guide_markdown(origin, handle_domain));
    let domain = origin
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    let kicker = html_escape(&format!("{domain}/agent"));
    let nav = crate::ui::nav(&crate::ui::brand_site(), r#"<a class="nav-link" href="/">main page →</a>"#);
    let css = r#"
.wrap { max-width: 44rem; margin: 0 auto; padding: 26px 24px 40px; }
h2 { font:600 17px/1.3 var(--mono); margin:10px 0 6px; }
.lede { margin:0 0 14px; font-size:12.5px; color:var(--muted); line-height:1.55; }
"#;
    let body = format!(
        r#"{nav}
<main class="wrap">
  <div class="kicker c-cyan">{kicker}</div>
  <h2>Instructions for AI agents</h2>
  <p class="lede">If you're a person, you want <a class="goldlink" href="/">the main page →</a>. This page is the machine-readable guide your agent was sent to read.</p>
  <pre class="codewell">{body_md}</pre>
</main>"#
    );
    crate::ui::document("bsky.browserid.me/agent — instructions for AI agents", css, &body)
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guide_names_the_real_endpoints_and_scopes() {
        let md = guide_markdown("https://bsky.browserid.me", "at.browserid.me");
        for needle in [
            "/browserid/provision",
            "/browserid/post",
            "/browserid/token",
            "repo:app.bsky.feed.post?action=create",
            "<label>.at.browserid.me",
            "https://bsky.browserid.me",
        ] {
            assert!(md.contains(needle), "guide must mention {needle}");
        }
    }

    /// A relay-connected grantor must NOT be sent to provision/setup: the
    /// guide checks `whoami` first and skips account creation when the human
    /// connected their real account. Regression for the round-2 friction
    /// where the agent minted an account nobody asked for.
    #[test]
    fn guide_makes_provisioning_conditional_on_the_backend() {
        let md = guide_markdown("https://bsky.browserid.me", "at.browserid.me");
        for needle in [
            "check where posts land",         // the whoami-first framing
            "Skip provisioning entirely",     // the relay branch
            "Only when `backend` was `bridge`", // provision is conditional
            "only for opening an account here", // setup is not the default
            "only if you may open an account here", // the scope is conditional too
        ] {
            assert!(md.contains(needle), "guide must say: {needle}");
        }
    }

    /// The confusable errors (F11): the guide must teach that a shared
    /// `401 invalid_token` can mean two opposite things, told apart by the
    /// description.
    #[test]
    fn guide_disambiguates_the_overlapping_errors() {
        let md = guide_markdown("https://bsky.browserid.me", "at.browserid.me");
        for needle in [
            "missing bridge token",
            "warrant revoked",
            "write_session_expired",
            "branch on the\n`error_description`",
        ] {
            assert!(md.contains(needle), "guide must say: {needle}");
        }
    }

    /// User testing (2026-07-26): an agent relayed the approval URL only after
    /// a timeout, and never polled. The guide must give the operational advice
    /// that avoids both — surface the link immediately, keep the command
    /// alive. (We do NOT tell the agent "don't summarize / don't explain to
    /// your user": that reads as a prompt-injection pattern and makes a
    /// careful agent distrust the page.)
    #[test]
    fn guide_gives_url_relay_and_polling_advice() {
        let md = guide_markdown("https://bsky.browserid.me", "at.browserid.me");
        for needle in [
            "relay all three to your human",
            "keep the command running",
            "background",
        ] {
            assert!(md.contains(needle), "guide must say: {needle}");
        }
        // The injection-shaped framing must stay gone.
        assert!(
            !md.contains("do not summarize") && !md.contains("not to hear the steps read back"),
            "guide must not carry prompt-injection-shaped 'do not summarize / don't explain' framing"
        );
        assert!(
            agent_prompt("https://bsky.browserid.me").contains("follow it"),
            "the prompt itself must demand action (\"follow it\", not just \"read it\")"
        );
    }

    /// Who the posts speak for is a decision only the human can make, so the
    /// guide has to open with the Bluesky-account fork (real handle as
    /// grantor, approved by signing in with Bluesky) and still name both email
    /// shapes for people not on Bluesky — an agent that assumes picks the
    /// human's public identity for them.
    #[test]
    fn guide_makes_the_agent_ask_who_the_posts_speak_for() {
        let md = guide_markdown("https://bsky.browserid.me", "at.browserid.me");
        for needle in [
            "do they have a Bluesky account",       // the fork
            "@bsky.browserid.me",                    // handle identity as grantor
            "sign in with their Bluesky handle",     // how the handle path is approved
            "As yourself",                           // email shape
            "On behalf",                             // email shape
            "409",                                   // returning-human note
        ] {
            assert!(md.contains(needle), "guide must mention {needle}");
        }
    }

    /// The demo's last beat is revocation *felt*, not described: the agent
    /// must hand over a concrete revoke URL, retry once, and report the
    /// refusal instead of treating it as a bug to fix.
    #[test]
    fn guide_ends_with_the_revocation_kill_switch() {
        let md = guide_markdown("https://bsky.browserid.me", "at.browserid.me");
        for needle in [
            "https://browserid.me/account",
            "Authorized sites",
            "Revoke",
            "warrant revoked",
            "not an error to debug",
            "Revocation is final",
            // A dead write connection is NOT a revoked warrant, and the
            // guide has to keep the two apart or agents will retry the
            // wrong thing.
            "write_session_expired",
            "reconnect_url",
        ] {
            assert!(md.contains(needle), "guide must say: {needle}");
        }
    }

    #[test]
    fn root_page_leads_with_the_verify_box_and_points_at_the_agent_guide() {
        let html = guide_html("https://bsky.browserid.me", "at.browserid.me");
        // The label copy sends readers to the origin to check a post, so the
        // box must be on the page.
        assert!(html.contains(r#"action="/verify""#), "form targets the verifier");
        assert!(html.contains(r#"href="/agent""#), "the guide moved to /agent");
        assert!(html.contains(r#"href="/dashboard""#), "sign in leads to the dashboard");
        assert!(
            !html.contains("Bluesky accounts your agent can post to"),
            "the full guide stays off the human root page"
        );
    }

    #[test]
    fn agent_page_escapes_the_guide_and_links_humans_out() {
        let html = agent_html("https://bsky.browserid.me", "at.browserid.me");
        assert!(html.contains("&lt;label&gt;"), "angle brackets must be escaped");
        assert!(html.contains("Instructions for AI agents"));
        assert!(html.contains("bsky.browserid.me/agent"), "the kicker names the address");
        assert!(html.contains(r#"href="/""#), "one link back out for humans");
    }
}
