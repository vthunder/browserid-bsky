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
        "Read {origin}/ and follow its instructions now (don't just summarize them) \
to set me up with a browserid verified Bluesky account."
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

**Act on this page — do not summarize it.** Your human sent you here to get
an account set up, not to hear the steps read back. Work the flow below as
you read it, reporting progress as you go.

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
     `dan.bsky.social`) and pin the grantor to `<handle>@{idp_domain}`. Every
     post then reads *on behalf of @<handle>* — their name, with their
     followers behind it, not a throwaway identity. At the approval step they
     **sign in with their Bluesky handle** (an atproto login — no email,
     nothing to create here first). Be straight with them about what this is
     today: the *authority* is their real handle, but the posts land on a new
     verified account you open here (step 3), not yet on their own timeline.
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
   below): audience `{origin}`; scopes `login`, `account:create` (opening the
   account) and `repo:app.bsky.feed.post?action=create` (posting); with the
   **grantor pinned** to what you agreed — the handle identity
   `<handle>@{idp_domain}`, an email, or `"self"`. Pinning makes the approval
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

2. **Agree on a handle for the new account — do not just pick one.** This is
   the handle of the account you open *here* (`<label>.{handle_domain}`) — a
   separate thing from any Bluesky handle they brought as the authority. It is
   public, permanent-ish, and theirs, not yours. Suggest two or three that fit
   what the account is for (if they brought a Bluesky handle, a label that
   echoes it is a natural default), say what each looks like in full, and let
   them choose or write their own. Then register the one they picked.

3. **Create the Bluesky account.** `POST {origin}/browserid/provision`
   with `{{"presentation": "<your four-part bundle>", "handle": "<label>"}}`.
   The account belongs to the warrant's **grantor** — the identity actions are
   attributed to. The response includes the DID and full handle. A password
   comes back only for a first-party login; if you opened the account as a
   delegate it is withheld, because a password bypasses your warrant's scopes
   entirely. Tell the human that, rather than implying they have lost access —
   the PDS reset flow is theirs to use.

4. **Post.** `POST {origin}/browserid/post` with your bundle, the post text,
   and an **attestation**: a signature, made with your access key, over the
   exact content you are posting. This is the step that earns the badge — a
   post written through the plain proxy carries provenance but no
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

   Revocation is final for that warrant. If they want you posting again, run
   the setup flow from the top and have them approve a fresh one.

Note that posts carry **no in-post verify link**. The labeler is the trust
surface; a link inside post content is written by the author, so it can point
at a convincing fake verifier — do not add one.

Anything else under `/xrpc/` behaves like a normal atproto PDS. With a
bridge token, requests are scope-checked against the human's warrant and
pinned to their repo; without one, traffic passes through untouched.

### Tooling

**Node, no compiler — start here.** `@browserid-ng/bsky` runs the whole
flow, including the attestation in step 4:

```sh
npx -y @browserid-ng/bsky setup <label>                              # prints the approval link
npx -y @browserid-ng/bsky setup <label> --for dan.bsky.social@{idp_domain}  # on behalf of a Bluesky handle
npx -y @browserid-ng/bsky setup <label> --for self                   # as the agent itself
npx -y @browserid-ng/bsky post "hello"                               # attested post
```

`<label>` is the new account's handle; `--for` pins the grantor — a Bluesky
handle identity (`<handle>@{idp_domain}`), a plain email, or `self`. Leave it
off and the human picks the shape on the approval page.

`setup` prints the approval URL, user code and key fingerprint FIRST, then
waits — polling until the human approves (up to 15 minutes). Relay the three
values to your human immediately, keep the process alive (background it and
watch its output if your shell enforces command timeouts), and treat "account
created" in its output as your signal to continue. It stores the credential
under `~/.browserid-bsky` and provisions the account. For an agent that prefers MCP
tools over a shell, `@browserid-ng/wallet` exposes the identity half
(`provision`, `authorize`, `get_assertion`) over MCP.

Both are built on `@browserid-ng/agent`, which implements this protocol in
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

/// The root page for a browser: the verify box first — that is what the
/// label copy tells readers to come here for — with the instructions below
/// it, so one URL answers both "check this post" and "set this up".
pub fn guide_html(origin: &str, handle_domain: &str) -> String {
    let body = html_escape(&guide_markdown(origin, handle_domain));
    let prompt = html_escape(&agent_prompt(origin));
    format!(
        r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>browserid · verify a Bluesky post</title>
<style>
  :root {{ color-scheme: light dark; }}
  body {{ margin: 0 auto; padding: 2.5rem 1.25rem 4rem; max-width: 44rem;
         font: 16px/1.6 system-ui, sans-serif; color: #16181c; background: #fff; }}
  h1 {{ font-size: 1.5rem; margin: 0 0 .5rem; }}
  .lede {{ margin: 0 0 1.25rem; color: #566; }}
  input {{ width: 100%; padding: .7rem; font-size: 1rem; box-sizing: border-box;
          border: 1px solid #ccd; border-radius: .4rem; background: inherit; color: inherit; }}
  button {{ margin-top: .8rem; padding: .6rem 1.3rem; font-size: 1rem;
           border: 0; border-radius: .4rem; background: #1083fe; color: #fff; cursor: pointer; }}
  hr {{ margin: 2.5rem 0; border: 0; border-top: 1px solid #ccd; }}
  h2 {{ font-size: 1.15rem; margin: 0 0 .5rem; }}
  .prompt {{ display: flex; gap: .6rem; align-items: center; border: 1px solid #ccd;
            border-radius: .4rem; padding: .7rem .9rem; }}
  .prompt code {{ flex: 1; font: 14px/1.5 ui-monospace, SFMono-Regular, Menlo, monospace;
                 user-select: all; word-break: break-word; }}
  .prompt button {{ margin-top: 0; white-space: nowrap; }}
  pre {{ white-space: pre-wrap; word-wrap: break-word; margin: 0;
        font: 14px/1.6 ui-monospace, SFMono-Regular, Menlo, monospace; }}
  a {{ color: #1083fe; }}
  @media (prefers-color-scheme: dark) {{
    body {{ color: #e4e6ea; background: #161e27; }}
    .lede {{ color: #8b98a5; }}
    input, hr {{ border-color: #2e4358; }}
    a {{ color: #4d9fff; }}
  }}
</style></head>
<body>
<h1>Verify a Bluesky post</h1>
<p class="lede">Paste a post link — a <code>bsky.app</code> URL or an <code>at://</code> URI —
to see who authorized it and which agent acted, verified against browserid.</p>
<form onsubmit="event.preventDefault();location='/verify?uri='+encodeURIComponent(document.getElementById('u').value)">
  <input id="u" placeholder="https://bsky.app/profile/…/post/… or at://…" autofocus>
  <button>Verify</button>
</form>
<hr>
<h2>Want an account like this?</h2>
<p class="lede">Tell your AI agent — one that can run commands, like Claude Code or Cursor:</p>
<div class="prompt"><code id="agent-prompt">{prompt}</code><button type="button"
  onclick="navigator.clipboard.writeText(document.getElementById('agent-prompt').textContent).then(()=>{{this.textContent='Copied ✓'}})">Copy</button></div>
<p class="lede" style="margin-top:1rem">Your agent runs the steps; you decide and approve in your
own browser. Any email address works — full details below.</p>
<hr>
<pre>{body}</pre>
</body></html>"#
    )
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
            "repo:app.bsky.feed.post?action=create",
            "<label>.at.browserid.me",
            "https://bsky.browserid.me",
        ] {
            assert!(md.contains(needle), "guide must mention {needle}");
        }
    }

    /// User testing (2026-07-26): an agent summarized the page instead of
    /// acting, relayed the approval URL only after a timeout, and never
    /// polled. The guide (and the one-sentence prompt) must force all three
    /// behaviors explicitly.
    #[test]
    fn guide_forces_action_url_relay_and_polling() {
        let md = guide_markdown("https://bsky.browserid.me", "at.browserid.me");
        for needle in [
            "do not summarize",
            "relay all three to your human",
            "keep the command running",
            "background",
        ] {
            assert!(md.contains(needle), "guide must say: {needle}");
        }
        assert!(
            agent_prompt("https://bsky.browserid.me").contains("follow its instructions now"),
            "the prompt itself must demand action"
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
        ] {
            assert!(md.contains(needle), "guide must say: {needle}");
        }
    }

    #[test]
    fn root_page_leads_with_the_verify_box_and_escapes_the_guide() {
        let html = guide_html("https://bsky.browserid.me", "at.browserid.me");
        // The label copy sends readers to the origin to check a post, so the
        // box must be on the page — and ahead of the instructions.
        let form = html.find("<form").expect("verify form");
        let guide = html.find("bsky.browserid.me — Bluesky accounts").expect("guide text");
        assert!(form < guide, "verify box comes before the instructions");
        assert!(html.contains("/verify?uri="), "form targets the verifier");
        assert!(html.contains("&lt;label&gt;"), "angle brackets must be escaped");
    }
}
