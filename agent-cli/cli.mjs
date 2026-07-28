#!/usr/bin/env node
// browserid-bsky — set up a Bluesky account an agent can post to, verifiably.
//
//   npx -y @browserid-ng/bsky setup <handle>      # human approves a link
//   npx -y @browserid-ng/bsky post "text"         # attested post
//   npx -y @browserid-ng/bsky delegate <handle>   # act ON BEHALF OF an
//                                                 # existing account's owner
//   npx -y @browserid-ng/bsky whoami
//
// The device credential + its warrants live in the SHARED browserid store —
// ~/.browserid/agent-credential.json, 0600, the exact file and
// `{ credential, grants }` format @browserid-ng/wallet uses. So an MCP agent
// that authorized a bsky warrant through the wallet can post with THIS CLI
// (`post`) reusing that same approval — no second identity, no second click.
// bsky-only bits (a minted account's did/handle) live in a sidecar so a
// wallet write to the credential file cannot clobber them.
// Config: BROWSERID_HOME (shared), BROWSERID_BSKY_HOME (override to keep a
// separate actor), BROWSERID_BROKER, BSKY_BRIDGE.
import { requestProvision, requestWarrants, DeviceAgent } from "@browserid-ng/agent";
import { homedir } from "node:os";
import { join } from "node:path";
import { mkdirSync, readFileSync, writeFileSync, chmodSync } from "node:fs";
import { provisionAccount, exchangeToken, attestedPost, bridgeWhoami } from "./bsky.mjs";

const BROKER = (process.env.BROWSERID_BROKER || "https://browserid.me").replace(/\/$/, "");
const BRIDGE = (process.env.BSKY_BRIDGE || "https://bsky.browserid.me").replace(/\/$/, "");
const HOME =
  process.env.BROWSERID_BSKY_HOME ||
  process.env.BROWSERID_HOME ||
  join(homedir(), ".browserid");
const CREDENTIAL = join(HOME, "agent-credential.json"); // SHARED with @browserid-ng/wallet
const ACCOUNT = join(HOME, "bsky-account.json"); // bsky-only: a minted account's did/handle
const POST_SCOPE = "repo:app.bsky.feed.post?action=create";
// Lets a DELEGATE open the account, so the human never has to issue an as-me
// warrant just to bootstrap one.
const CREATE_SCOPE = "account:create";

mkdirSync(HOME, { recursive: true, mode: 0o700 });

const writePrivate = (path, obj) => {
  writeFileSync(path, JSON.stringify(obj, null, 2), { mode: 0o600 });
  try { chmodSync(path, 0o600); } catch {}
};
const readJson = (path) => {
  try { return JSON.parse(readFileSync(path, "utf8")); } catch { return null; }
};

/** The shared credential + its held warrants, or null. */
const loadCred = () => readJson(CREDENTIAL);
/** Persist the credential and EVERY held warrant — the union, so a bsky
 *  warrant lands alongside (not on top of) whatever the wallet already holds. */
const saveCred = (agent) =>
  writePrivate(CREDENTIAL, { credential: agent.credential, grants: agent.storedGrants() });
/** The bsky-only sidecar: a minted account this CLI opened. */
const loadAccount = () => readJson(ACCOUNT);
const saveAccount = (acct) => writePrivate(ACCOUNT, acct);

const die = (msg) => {
  console.error(msg);
  process.exit(1);
};

function agentFrom(stored) {
  const agent = new DeviceAgent(stored.credential);
  for (const g of stored.grants ?? []) agent.addGrant(g.grant);
  return agent;
}

/** The decoded claims of a held `warrant~config_cert` grant. */
function grantClaims(pair) {
  return JSON.parse(Buffer.from(pair.split("~")[0].split(".")[1], "base64url").toString());
}

/**
 * Return an agent holding a BRIDGE-audience warrant, requesting one (a single
 * human approval) only if the shared store does not already have it.
 *
 * Reuses the wallet's device identity when one is present — a warrant is
 * ADDED to it via `requestWarrants`, never a fresh identity provisioned over
 * it — so the two tools share one credential and one set of warrants. A fresh
 * `requestProvision` runs only when the store is empty.
 */
async function ensureBridgeAgent({ scopes, grantor, grantee, handle, label, message }) {
  const stored = loadCred();
  let agent = stored ? agentFrom(stored) : null;

  if (agent && agent.warrantedAudiences().includes(BRIDGE)) {
    return { agent, reused: true };
  }

  const pending = agent
    ? await requestWarrants(BROKER, {
        deviceCert: agent.deviceCert,
        identity: agent.email,
        grants: [{ audience: BRIDGE, scopes }],
        ...(label ? { label } : {}),
        ...(message ? { message } : {}),
        ...(grantor ? { grantor } : {}),
      })
    : await requestProvision(BROKER, {
        grants: [{ audience: BRIDGE, scopes }],
        grantee: grantee ?? "*",
        ...(handle ? { handle } : {}),
        ...(grantor ? { grantor } : {}),
        ...(label ? { label } : {}),
        ...(message ? { message } : {}),
      });

  console.log(`APPROVE_URL: ${pending.verificationUriComplete}`);
  console.log(`  (or open ${pending.verificationUri} and enter code ${pending.userCode})`);
  if (pending.fingerprint) console.log(`  key fingerprint: ${pending.fingerprint}`);
  const approveHint = grantor && grantor.endsWith("@" + new URL(BRIDGE).host)
    ? "they sign in with their Bluesky handle, then approve this request."
    : "they add their email at browserid.me if they haven't, then approve this request.";
  console.log(`\nShow that link to the human and wait — ${approveHint}\n`);
  console.log("waiting for approval...");

  if (agent) {
    // requestWarrants().wait() → grants[] (throws on denial).
    const grants = await pending.wait();
    for (const g of grants) agent.addGrant(g.grant);
  } else {
    // requestProvision().wait() → { credential, grants, grantsDenied }.
    const { credential, grants, grantsDenied } = await pending.wait();
    if (grantsDenied) {
      die(
        `The human approved the identity but declined the permission (${grantsDenied}).\n` +
          `Nothing was saved. Talk it over and re-run — the approval page offers reusing\n` +
          `the identity that was just created.`,
      );
    }
    agent = agentFrom({ credential, grants });
  }
  saveCred(agent);
  return { agent, reused: false };
}

async function setup(handleLabel, { grantor } = {}) {
  // The handle is public and the human's — agree it with them first, don't
  // invent one on their behalf.
  if (!handleLabel) die("usage: browserid-bsky setup <handle> [--for <identity|self>]   (agree the handle with the human first)");
  if (loadAccount()) die(`already set up (${ACCOUNT}). Delete that file to start over, or just \`post\`.`);

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
  // One approval covers both: opening the account AND posting to it — and it
  // reuses the wallet's identity if one is already in the shared store.
  const { agent, reused } = await ensureBridgeAgent({
    scopes: ["login", CREATE_SCOPE, POST_SCOPE],
    grantor,
    handle: handleLabel,
    label: `Bluesky ${handleLabel}`,
    message: `I'll open and run the Bluesky account ${handleLabel} at bsky.browserid.me — create it and post to it, nothing else.`,
  });

  console.log(`${reused ? "reusing existing warrant — " : ""}acting as ${agent.email}`);
  const w = grantClaims(agent.storedGrants().find((g) => g.audience === BRIDGE).grant);
  if (w.grantor !== w.grantee) {
    console.log(`  attributed to ${w.grantor}, acted by ${w.grantee} (on behalf of)`);
  }
  const expected = grantor === "self" ? w.grantee : grantor;
  if (expected && w.grantor.toLowerCase() !== expected.toLowerCase()) {
    console.log(`⚠ expected actions to be attributed to ${expected} — got ${w.grantor}`);
  }

  const { presentation } = await agent.assertionWithAccessKey(BRIDGE);
  const account = await provisionAccount(BRIDGE, { presentation, handle: handleLabel });
  saveAccount({ did: account.did, handle: account.handle });

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
  console.log(`  4. Then offer them the off switch: https://browserid.me/account →`);
  console.log(`     Authorized sites → this service → Revoke. Post once more afterwards;`);
  console.log(`     it fails 401 "warrant revoked". Show them that line — don't debug it.`);
  console.log(`\nNow post:  browserid-bsky post "hello world"`);
}

async function post(text) {
  if (!text) die('usage: browserid-bsky post "your text"');
  const stored = loadCred() || die(
    "no identity — authorize one first: with the @browserid-ng/wallet MCP tool\n" +
      "(`authorize` for https://bsky.browserid.me), or `browserid-bsky setup <handle>`.",
  );
  const agent = agentFrom(stored);
  if (!agent.warrantedAudiences().includes(BRIDGE)) {
    die(
      `no warrant for ${BRIDGE} — authorize one first: the wallet's \`authorize\` for that\n` +
        `audience with scope ${POST_SCOPE}, or \`browserid-bsky setup <handle>\`.`,
    );
  }

  const { presentation, accessKey, accessCert } = await agent.assertionWithAccessKey(BRIDGE);
  const { access_token: token, scopes } = await exchangeToken(BRIDGE, { presentation });
  // The bridge is the authority on which repo this lands in: for a grantor
  // who connected write access on the dashboard it is their REAL DID (the
  // relay), otherwise a bridge-provisioned account. Sign the attestation over
  // whatever it reports — the CLI cannot know a connected handle's real DID
  // any other way, and never needs a minted account to post to the real one.
  const { did, backend } = await bridgeWhoami(BRIDGE, { token });
  const result = await attestedPost(BRIDGE, { text, did, token, accessKey, accessCert });

  const where =
    backend === "relay"
      ? "your REAL Bluesky account"
      : `bridge account ${loadAccount()?.handle ?? did}`;
  console.log(`posted to ${where} (${backend}; scopes ${JSON.stringify(scopes)})`);
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
  if (loadAccount()) die(`state already exists (${ACCOUNT}). Use BROWSERID_BSKY_HOME to keep a separate actor.`);

  const handle = accountHandle.includes(".") ? accountHandle : `${accountHandle}.at.browserid.me`;
  const did = await resolveHandle(handle);

  console.log(`\nActing ${grantee ? `as ${grantee} ` : ""}ON BEHALF OF ${grantor}`);
  console.log(`  -> posts land in ${handle} (${did}) attributed to ${grantor}`);
  console.log(`The human must approve AS ${grantor}.`);

  const { agent } = await ensureBridgeAgent({
    scopes: ["login", POST_SCOPE],
    grantor, // who the post is attributed to — the account's owner (pinned)
    grantee, // who acts; pin it to keep the two identities apart (fresh id only)
    label: `posting to ${handle}`,
    message: `I'll post to ${handle} on the owner's behalf. Nothing else.`,
  });
  saveAccount({ did, handle });

  const claims = grantClaims(agent.storedGrants().find((g) => g.audience === BRIDGE).grant);
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
  const stored = loadCred() || die(
    "no identity — authorize one with the @browserid-ng/wallet MCP tool, or `browserid-bsky setup <handle>`.",
  );
  const agent = agentFrom(stored);
  console.log(`identity: ${agent.email} (holder ${agent.holder})`);
  console.log(`warrants: ${agent.warrantedAudiences().join(", ") || "none"}`);

  const held = agent.storedGrants().find((g) => g.audience === BRIDGE);
  if (held) {
    const claims = grantClaims(held.grant);
    console.log(
      claims.grantor === claims.grantee
        ? `acting:   as itself (${claims.grantor})`
        : `acting:   ${claims.grantee} ON BEHALF OF ${claims.grantor}`,
    );
    // Ask the bridge where a post would actually land — the real account
    // (relay) or a bridge one — the same answer `post` acts on.
    try {
      const { presentation } = await agent.assertionWithAccessKey(BRIDGE);
      const { access_token: token } = await exchangeToken(BRIDGE, { presentation });
      const { did, backend } = await bridgeWhoami(BRIDGE, { token });
      console.log(
        backend === "relay"
          ? `posts to: your REAL Bluesky account (${did}) — write access connected`
          : `posts to: bridge account ${loadAccount()?.handle ?? did} (${did})`,
      );
    } catch (e) {
      console.log(`posts to: (could not reach the bridge: ${e.message})`);
    }
  } else {
    const acct = loadAccount();
    if (acct) console.log(`account:  ${acct.handle} (${acct.did})`);
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
