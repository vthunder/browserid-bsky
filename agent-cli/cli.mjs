#!/usr/bin/env node
// browserid-bsky — set up a Bluesky account an agent can post to, verifiably.
//
//   npx -y @browserid-ng/bsky setup <handle>      # human approves a link
//   npx -y @browserid-ng/bsky post "text"         # attested post
//   npx -y @browserid-ng/bsky delegate <handle>   # act ON BEHALF OF an
//                                                 # existing account's owner
//   npx -y @browserid-ng/bsky whoami
//
// State (the device key, the warrant, the account DID) lives in
// ~/.browserid-bsky/state.json, 0600. Config: BROWSERID_BROKER, BSKY_BRIDGE.
import { requestProvision, DeviceAgent } from "@browserid-ng/agent";
import { homedir } from "node:os";
import { join } from "node:path";
import { mkdirSync, readFileSync, writeFileSync, chmodSync } from "node:fs";
import { provisionAccount, exchangeToken, attestedPost } from "./bsky.mjs";

const BROKER = (process.env.BROWSERID_BROKER || "https://browserid.me").replace(/\/$/, "");
const BRIDGE = (process.env.BSKY_BRIDGE || "https://bsky.browserid.me").replace(/\/$/, "");
const HOME = process.env.BROWSERID_BSKY_HOME || join(homedir(), ".browserid-bsky");
const STATE = join(HOME, "state.json");
const POST_SCOPE = "repo:app.bsky.feed.post?action=create";
// Lets a DELEGATE open the account, so the human never has to issue an as-me
// warrant just to bootstrap one.
const CREATE_SCOPE = "account:create";

mkdirSync(HOME, { recursive: true, mode: 0o700 });

const load = () => {
  try {
    return JSON.parse(readFileSync(STATE, "utf8"));
  } catch {
    return null;
  }
};
const save = (state) => {
  writeFileSync(STATE, JSON.stringify(state, null, 2), { mode: 0o600 });
  try { chmodSync(STATE, 0o600); } catch {}
};

const die = (msg) => {
  console.error(msg);
  process.exit(1);
};

function agentFrom(state) {
  const agent = new DeviceAgent(state.credential);
  for (const g of state.grants ?? []) agent.addGrant(g.grant);
  return agent;
}

async function setup(handleLabel, { grantor } = {}) {
  // The handle is public and the human's — agree it with them first, don't
  // invent one on their behalf.
  if (!handleLabel) die("usage: browserid-bsky setup <handle> [--for <identity|self>]   (agree the handle with the human first)");
  if (load()) die(`already set up (${STATE}). Delete that file to start over.`);

  // `grantee: "*"` — the approver chooses or mints the agent's identity.
  // Omitting it instead means "the agent demands the human's own bare
  // identity", which the approval page rightly renders as a become-you
  // warning; this tool never needs that.
  //
  // `--for` PINS who the posts are attributed to (agent flows v2): an email
  // pins on-behalf of that identity; `self` pins as-itself (the agent's own
  // sub-identity owns the account — the shape a returning human needs,
  // since on-behalf creation 409s when their email already owns an account
  // here). Unpinned, the human chooses on the approval page's dropdown.
  // Agree the shape with the human FIRST — the guide says so too.
  //
  // The requested handle is a SUGGESTION for the agent identity's tag
  // (`<local>+<tag>@…`), reusing the Bluesky label so the two names rhyme.
  // One approval covers both: opening the account AND posting to it.
  const pending = await requestProvision(BROKER, {
    grants: [{ audience: BRIDGE, scopes: ["login", CREATE_SCOPE, POST_SCOPE] }],
    grantee: "*",
    handle: handleLabel,
    ...(grantor ? { grantor } : {}),
    label: `Bluesky ${handleLabel}`,
    message: `I'll open and run the Bluesky account ${handleLabel} at bsky.browserid.me — create it and post to it, nothing else.`,
  });

  // Everything below waits on a human. Print the link FIRST so an agent can
  // surface it immediately rather than after the poll resolves.
  console.log(`APPROVE_URL: ${pending.verificationUriComplete}`);
  console.log(`  (or open ${pending.verificationUri} and enter code ${pending.userCode})`);
  console.log(`  key fingerprint: ${pending.fingerprint}`);
  console.log("\nShow that link to the human and wait — they add their email at");
  console.log("browserid.me if they haven't, then approve this request.\n");
  console.log("waiting for approval...");

  const { credential, grants, grantsDenied } = await pending.wait();
  if (grantsDenied) {
    // Agent flows v2: identity approved, permission declined. Without the
    // warrant this tool can do nothing — don't save half a setup.
    die(
      `The human approved the identity but declined the permission (${grantsDenied}).\n` +
        `Nothing was saved. Talk it over and re-run setup — the approval page offers\n` +
        `reusing the identity that was just created.`,
    );
  }
  // Save BEFORE anything else can fail: the approval is delivered ONCE.
  save({ credential, grants });

  const agent = agentFrom({ credential, grants });
  console.log(`approved — acting as ${agent.email}`);
  const w = JSON.parse(Buffer.from(grants[0].grant.split("~")[0].split(".")[1], "base64url").toString());
  if (w.grantor !== w.grantee) {
    console.log(`  attributed to ${w.grantor}, acted by ${w.grantee} (on behalf of)`);
  }
  const expected = grantor === "self" ? w.grantee : grantor;
  if (expected && w.grantor.toLowerCase() !== expected.toLowerCase()) {
    console.log(`⚠ expected actions to be attributed to ${expected} — got ${w.grantor}`);
  }

  const { presentation } = await agent.assertionWithAccessKey(BRIDGE);
  const account = await provisionAccount(BRIDGE, { presentation, handle: handleLabel });
  save({ credential, grants, did: account.did, handle: account.handle });

  console.log(`\nBluesky account created:`);
  console.log(`  handle:   ${account.handle}`);
  console.log(`  did:      ${account.did}`);
  if (account.password) {
    console.log(`  password: ${account.password}`);
    console.log(`            ^ shown ONCE — for ordinary Bluesky clients. Offer it to the human.`);
  } else {
    console.log(`  password: withheld — you opened this as a delegate, and a password would`);
    console.log(`            bypass your warrant's scopes. The human can use the PDS reset flow.`);
  }
  console.log(`  profile:  https://bsky.app/profile/${account.handle}`);
  console.log(`\nThings to tell the human:`);
  console.log(`  1. ${account.password ? "Save that password if they want to use ordinary Bluesky clients." : "No password was issued — nothing to save."}`);
  console.log(`  2. Subscribe to the labeler so the provenance badge actually shows:`);
  console.log(`     https://bsky.app/profile/labeler.at.browserid.me`);
  console.log(`  3. Give them their profile link (above) — and after posting, the post's`);
  console.log(`     own link, so they can see what their agent made.`);
  console.log(`\nNow post:  browserid-bsky post "hello world"`);
}

async function post(text) {
  if (!text) die('usage: browserid-bsky post "your text"');
  const state = load() || die("no state — run `browserid-bsky setup <handle>` first");
  if (!state.did) die("no account yet — run `browserid-bsky setup <handle>` first");

  const agent = agentFrom(state);
  const { presentation, accessKey, accessCert } = await agent.assertionWithAccessKey(BRIDGE);
  const { access_token: token, scopes } = await exchangeToken(BRIDGE, { presentation });
  const result = await attestedPost(BRIDGE, {
    text,
    did: state.did,
    token,
    accessKey,
    accessCert,
  });
  console.log(`posted as ${state.handle} (scopes ${JSON.stringify(scopes)})`);
  console.log(`  uri:    ${result.uri ?? "?"}`);
  {
    // at://<did>/app.bsky.feed.post/<rkey> → the link a human can open.
    const m = /^at:\/\/([^/]+)\/app\.bsky\.feed\.post\/(.+)$/.exec(result.uri ?? "");
    if (m) console.log(`  view:   https://bsky.app/profile/${m[1]}/post/${m[2]}  ← show the human`);
  }
  // The receipt, for whoever is running this — NOT embedded in the post.
  console.log(`  verify: ${result.verifyUrl}`);
}

/**
 * Provision a SEPARATE actor identity that posts ON BEHALF OF an existing
 * account's owner: `grantee: "*"` has the approver mint a distinct actor, so
 * the warrant's grantor (who the post is attributed to) differs from its
 * grantee (who wrote it). Posts then carry the `browserid-on-behalf` badge.
 *
 * The account itself must already exist — creating one is first-party only.
 * The approver must pick the identity that OWNS `accountHandle`.
 */
async function delegate(accountHandle, { grantor, grantee } = {}) {
  if (!accountHandle) die("usage: browserid-bsky delegate <account-handle> --for <owner-id> [--as <actor-id>]");
  if (!grantor) {
    die(
      "delegate needs --for <owner-identity>: the identity that OWNS the account, which the post is\n" +
        "attributed to. Without pinning it, the approval page uses whichever identity the human picks\n" +
        "for BOTH sides and you get an as-itself warrant instead of on-behalf-of.",
    );
  }
  if (load()) die(`state already exists (${STATE}). Use BROWSERID_BSKY_HOME to keep a separate actor.`);

  const handle = accountHandle.includes(".") ? accountHandle : `${accountHandle}.at.browserid.me`;
  const did = await resolveHandle(handle);

  const pending = await requestProvision(BROKER, {
    grants: [{ audience: BRIDGE, scopes: ["login", POST_SCOPE] }],
    grantor, // who the post is attributed to — the account's owner (pinned)
    grantee: grantee ?? "*", // who acts; pin it to keep the two identities apart
    label: `posting to ${handle}`,
    message: `I'll post to ${handle} on the owner's behalf. Nothing else.`,
  });
  console.log(`APPROVE_URL: ${pending.verificationUriComplete}`);
  console.log(`  (or open ${pending.verificationUri} and enter code ${pending.userCode})`);
  console.log(`  key fingerprint: ${pending.fingerprint}`);
  console.log(`\nActing ${grantee ? `as ${grantee} ` : ""}ON BEHALF OF ${grantor}`);
  console.log(`  -> posts land in ${handle} (${did}) attributed to ${grantor}`);
  console.log(`The human must approve AS ${grantor}.\n`);
  console.log("waiting for approval...");

  const { credential, grants, grantsDenied } = await pending.wait();
  if (grantsDenied) {
    die(
      `The human approved the identity but declined the permission (${grantsDenied}).\n` +
        `Nothing was saved — talk it over and re-run delegate.`,
    );
  }
  save({ credential, grants, did, handle });

  const agent = agentFrom({ credential, grants });
  const claims = JSON.parse(Buffer.from(grants[0].grant.split("~")[0].split(".")[1], "base64url").toString());
  console.log(`approved — acting as ${agent.email}`);
  if (claims.grantor === claims.grantee) {
    console.log(
      `\n⚠ This warrant is AS-ITSELF (grantor == grantee == ${claims.grantor}), not on-behalf-of.\n` +
        `  The approver picked the same identity for both. Posts will be labelled\n` +
        `  browserid-verified, not browserid-on-behalf.`,
    );
  } else {
    console.log(`  attributed to ${claims.grantor}, executed by ${claims.grantee}`);
  }
  console.log(`\nNow post:  browserid-bsky post "hello"`);
}

/** Resolve a handle to its DID through the bridge's atproto passthrough. */
async function resolveHandle(handle) {
  const res = await fetch(`${BRIDGE}/xrpc/com.atproto.identity.resolveHandle?handle=${encodeURIComponent(handle)}`);
  const json = await res.json().catch(() => ({}));
  if (!res.ok || !json.did) die(`could not resolve ${handle}: ${json.message || res.status}`);
  return json.did;
}

async function whoami() {
  const state = load() || die("no state — run `browserid-bsky setup <handle>` first");
  const agent = agentFrom(state);
  console.log(`identity: ${agent.email} (holder ${agent.holder})`);
  console.log(`warrants: ${agent.warrantedAudiences().join(", ") || "none"}`);
  console.log(`account:  ${state.handle ?? "not provisioned"}${state.did ? ` (${state.did})` : ""}`);
  const w = state.grants?.[0]?.grant;
  if (w) {
    const claims = JSON.parse(Buffer.from(w.split("~")[0].split(".")[1], "base64url").toString());
    console.log(
      claims.grantor === claims.grantee
        ? `acting:   as itself (${claims.grantor})`
        : `acting:   ${claims.grantee} ON BEHALF OF ${claims.grantor}`,
    );
  }
}

const [cmd, ...rest] = process.argv.slice(2);
try {
  const flag = (name) => {
    const i = rest.indexOf(`--${name}`);
    return i >= 0 ? rest[i + 1] : undefined;
  };
  if (cmd === "setup") await setup(rest[0], { grantor: flag("for") }); // --for <email|self>
  else if (cmd === "delegate") await delegate(rest[0], { grantor: flag("for"), grantee: flag("as") });
  else if (cmd === "post") await post(rest.join(" "));
  else if (cmd === "whoami") await whoami();
  else {
    console.log(
      "usage: browserid-bsky <setup <handle> [--for <identity|self>] | " +
        "delegate <account-handle> --for <owner-id> [--as <actor-id>] | post \"text\" | whoami>",
    );
    process.exit(cmd ? 1 : 0);
  }
} catch (e) {
  die(`ERROR: ${e.message}`);
}
