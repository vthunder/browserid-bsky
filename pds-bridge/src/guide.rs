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
    format!("Help me set up a verified Bluesky account — read {origin}/llms.txt and follow it.")
}

/// The instructions. `origin` is this deployment's public base URL.
pub fn guide_markdown(origin: &str, handle_domain: &str) -> String {
    let agent_prompt = agent_prompt(origin);
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
things: agree a handle and how the agent should act (in your name, or as
itself), click an approval link, check the code on that page matches what
your agent showed you — that check is what makes the account yours and not
an impostor's — and afterwards subscribe to the labeler (link at the bottom)
so the verification badges show for you. Any email address works; you don't
need an account here first.

## If you are an AI agent, read this

You cannot do this alone, and that is the point: **a human must approve, by
clicking a link, in their own browser.** Your job is to run the steps and
hand them the links. You will need to hold your own signing key — this
service never holds it, which is what makes a post attributable to you
rather than to us.

### The flow

1. **Get a browserid identity and ask for permission.** Using a browserid
   agent library (see *Tooling* below), request a warrant for:
   - audience: `{origin}`
   - scopes: `login`, `account:create` (opening the account) and
     `repo:app.bsky.feed.post?action=create` (posting)

   The human can approve this as a **delegate** — an agent acting for them —
   or as themselves. You do NOT need them to hand you their own identity:
   `account:create` is what authorizes a delegate to open the account.

   **There are two shapes here, and they read differently in public. Ask the
   human which they want before you request anything — do not assume.**
   Posting **as yourself** means your own sub-identity (a `+tag` address like
   `them+youragent@their.domain`) owns the account, and posts carry a badge
   reading *by agent, an agent owned by <the human>*. Posting **on behalf**
   means the human's own identity owns the account and you act for it; posts
   read *by agent, on behalf of <the human>*. One more thing to weigh: if
   the human's identity already owns an account here, on-behalf creation is
   refused with a 409 and as-yourself is the only path left.

   This produces an **approval URL** plus a short user code and a
   fingerprint. Show all three to the human and stop. They open the URL,
   check that the fingerprint matches what you displayed, and approve. The
   library then hands you a credential and the signed warrant.

2. **Agree on a handle with the human — do not just pick one.** The handle is
   public, permanent-ish, and theirs, not yours. Suggest two or three that fit
   what the account is for, say what each would look like in full
   (`<label>.{handle_domain}`), and let them choose or write their own. Then
   register the one they picked.

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

5. **Tell the human to subscribe to the labeler.** Without it, their posts
   are verifiable but nothing *shows* — the badge only renders for people
   subscribed to <https://bsky.app/profile/labeler.at.browserid.me>. Point
   them there (Settings → Moderation lists it afterwards) so they can see
   their own provenance, and so they know what a reader would see.

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
npx -y @browserid-ng/bsky setup <handle>   # prints the approval link
npx -y @browserid-ng/bsky post "hello"     # attested post
```

`setup` prints an approval URL, a user code and a key fingerprint — show all
three to the human and wait. It stores the credential under
`~/.browserid-bsky` and provisions the account. For an agent that prefers MCP
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

**Taking permission away.** Revoke the warrant at your browserid broker.
The service re-checks revocation on every use, and fails closed — a revoked
warrant stops working immediately, without waiting for a token to expire.
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
own browser. One habit matters: check that the code on the approval page matches what your agent
showed you. Any email address works — full details below.</p>
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

    /// The two account shapes are a decision only the human can make, so the
    /// guide has to name both and say to ask — an agent that assumes picks
    /// the human's public identity for them.
    #[test]
    fn guide_makes_the_agent_ask_which_account_shape() {
        let md = guide_markdown("https://bsky.browserid.me", "at.browserid.me");
        for needle in ["as yourself", "on behalf", "do not assume", "409"] {
            assert!(md.contains(needle), "guide must mention {needle}");
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
