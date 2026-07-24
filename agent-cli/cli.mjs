#!/usr/bin/env node
// browserid-bsky — set up a Bluesky account an agent can post to, verifiably.
//
//   npx -y @browserid-bsky/agent setup <handle>   # human approves a link
//   npx -y @browserid-bsky/agent post "text"      # attested post
//   npx -y @browserid-bsky/agent whoami
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

async function setup(handleLabel) {
  if (!handleLabel) die("usage: browserid-bsky setup <handle>");
  if (load()) die(`already set up (${STATE}). Delete that file to start over.`);

  const pending = await requestProvision(BROKER, {
    handle: handleLabel,
    grants: [{ audience: BRIDGE, scopes: ["login", POST_SCOPE] }],
    label: "Bluesky posting via bsky.browserid.me",
  });

  // Everything below waits on a human. Print the link FIRST so an agent can
  // surface it immediately rather than after the poll resolves.
  console.log(`APPROVE_URL: ${pending.verificationUriComplete}`);
  console.log(`  (or open ${pending.verificationUri} and enter code ${pending.userCode})`);
  console.log(`  key fingerprint: ${pending.fingerprint}`);
  console.log("\nShow that link to the human and wait — they add their email at");
  console.log("browserid.me if they haven't, then approve this request.\n");
  console.log("waiting for approval...");

  const { credential, grants } = await pending.wait();
  // Save BEFORE anything else can fail: the approval is delivered ONCE.
  save({ credential, grants });

  const agent = agentFrom({ credential, grants });
  console.log(`approved — acting as ${agent.email}`);

  const { presentation } = await agent.assertionWithAccessKey(BRIDGE);
  const account = await provisionAccount(BRIDGE, { presentation, handle: handleLabel });
  save({ credential, grants, did: account.did, handle: account.handle });

  console.log(`\nBluesky account created:`);
  console.log(`  handle:   ${account.handle}`);
  console.log(`  did:      ${account.did}`);
  console.log(`  password: ${account.password}`);
  console.log(`            ^ shown ONCE — for ordinary Bluesky clients. Save it or discard it deliberately.`);
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
  console.log(`  verify: ${result.verifyUrl}`);
}

async function whoami() {
  const state = load() || die("no state — run `browserid-bsky setup <handle>` first");
  const agent = agentFrom(state);
  console.log(`identity: ${agent.email} (holder ${agent.holder})`);
  console.log(`warrants: ${agent.warrantedAudiences().join(", ") || "none"}`);
  console.log(`account:  ${state.handle ?? "not provisioned"}${state.did ? ` (${state.did})` : ""}`);
}

const [cmd, ...rest] = process.argv.slice(2);
try {
  if (cmd === "setup") await setup(rest[0]);
  else if (cmd === "post") await post(rest.join(" "));
  else if (cmd === "whoami") await whoami();
  else {
    console.log("usage: browserid-bsky <setup <handle> | post \"text\" | whoami>");
    process.exit(cmd ? 1 : 0);
  }
} catch (e) {
  die(`ERROR: ${e.message}`);
}
