# bsky bridge — deployment plan (ezk6 P1b–P1d)

**Date:** 2026-07-24
**Goal:** a deployed, testable bsky.browserid.me. Two testability stages:

- **Stage 1 — private loop (the P1 demo):** provision an account with a
  browserid login, agent gets a warrant + bridge token, posts land in the
  PDS repo. Verified with direct XRPC reads. No federation, no handle
  verification, no relay. Everything under our control.
- **Stage 2 — on the real network:** the relay crawls the PDS, posts appear
  on bsky.app, handles resolve. Adds federation + handle plumbing.

## Topology decision (recommended: two hostnames)

The design doc's single-origin shape (bridge fronts everything) requires
websocket passthrough for the relay firehose, which the bridge doesn't have
yet. For deployment, split the surfaces instead:

- **`bsky.browserid.me`** → the **bridge** (dokku app `bsky-bridge`):
  `/browserid/*`, RFC 8414 metadata, and the scoped `/xrpc/*` proxy for
  agent tokens. This is the **warrant audience** — stable across stages.
- **`pds.bsky.browserid.me`** → the **PDS** directly (dokku app `bsky-pds`
  or a plain docker container): `PDS_HOSTNAME=pds.bsky.browserid.me`, so
  DID docs, human clients, and the relay firehose all talk straight to it.
  No websocket work needed; the bridge reaches it over the internal network.

Trade-off: two public hostnames instead of one; the DID service endpoint
names the PDS host, not the bridge. Acceptable — the bridge is the *grant*
surface, not the data plane. (Single-origin can be revisited at P3.)

## Stage 1 — steps

**Decisions (2026-07-24, with Dan):** two-hostname topology confirmed;
CI-image deploys (repo is public → free minutes + public GHCR); same dokku
host as browserid.me for now (disk can grow later — monitor PDS blob
growth); DNS is **Namecheap** (see stage-2 handle analysis below).

1. **Build via CI, not on the host** (per the mingo `sbo-daemon` lesson:
   dokku host builds cold-recompile Rust for 40+ min). Implemented:
   `.github/workflows/deploy-bridge.yml` builds `Dockerfile` →
   pushes `ghcr.io/vthunder/browserid-bsky/pds-bridge:<sha>` →
   `ssh dokku@HOST git:from-image bsky-bridge <image>`.
   One-time setup: repo secret `DOKKU_SSH_KEY` (reuse the existing deploy
   key), repo variable `DOKKU_HOST`, and after the first push flip the
   GHCR package to **public**. Gotcha (from mingo): `git:from-image` is a
   no-op that exits 1 on an unchanged digest — only bites when
   re-deploying the same commit.
2. **PDS app**: run the stock container
   (`ghcr.io/bluesky-social/pds:latest`) as dokku app `bsky-pds` with a
   persistent volume for `/pds`. Required env: `PDS_HOSTNAME`,
   `PDS_JWT_SECRET`, `PDS_ADMIN_PASSWORD`,
   `PDS_PLC_ROTATION_KEY_K256_PRIVATE_KEY_HEX`,
   `PDS_DID_PLC_URL=https://plc.directory`, `PDS_DATA_DIRECTORY=/pds`,
   `PDS_BLOBSTORE_DISK_LOCATION=/pds/blocks`,
   `PDS_SERVICE_HANDLE_DOMAINS=.at.browserid.me`. Invite codes stay
   admin-only (the bridge mints them per provisioning).
3. **Bridge app env**: `BRIDGE_ORIGIN=https://bsky.browserid.me`,
   `PDS_URL=http://<bsky-pds internal>`, `PDS_ADMIN_PASSWORD` (same as PDS),
   `BROKER_URL=https://browserid.me`, `HANDLE_DOMAIN=at.browserid.me`,
   `BRIDGE_DB=/data/pds-bridge.db` + persistent `/data` volume.
4. **DNS + TLS**: `bsky.browserid.me` and `pds.bsky.browserid.me` A records
   → the dokku host; `dokku letsencrypt` for both.
5. **Smoke test (scriptable, no browser needed for the agent side):**
   1. Human: sign in at browserid.me once so the config cert exists; run the
      provisioning call with a bundle for audience
      `https://bsky.browserid.me` (small helper script, or a minimal
      `/browserid/provision` page later).
   2. Agent: `browserid-agent` CLI / `@browserid-ng/wallet` requests a
      warrant for audience `https://bsky.browserid.me`, scopes
      `repo:app.bsky.feed.post?action=create` — approve the consent card at
      browserid.me.
   3. Exchange at `POST /browserid/token`, post via
      `POST /xrpc/com.atproto.repo.createRecord`.
   4. Verify: `GET /xrpc/com.atproto.repo.listRecords?repo=<did>&collection=app.bsky.feed.post`
      against `pds.bsky.browserid.me` (public read).
   5. Revoke the warrant in the browserid.me account UI → the next agent
      post must 401 within the status-cache window.

**Stage-1 blockers to fix first (found while writing this plan):**
- [ ] The bridge's warrant re-check refreshes status lists via
  `Verifier::refresh_status`, which only trusts list issuers in its
  issuer-key table — the broker is there via `BROKER_URL`, so warrant lists
  (browserid.me registry) work; access/config-cert lists from *primary*
  IdPs won't refresh (their keys aren't in the table). Fine for stage 1
  (broker-issued identities only); note for P2 (DNSSEC-rooted resolver).
- [ ] `Verifier::refresh_status` and the status re-check assume the broker
  actually serves `/.well-known/browserid-status` with warrant indices —
  it does (egr7), but the deployed broker must be current.

## Stage 2 — federation & handles (separate pass)

1. **Relay crawl**: `POST /xrpc/com.atproto.sync.requestCrawl` to
   `bsky.network` naming `pds.bsky.browserid.me`. Posts then flow to the
   AppView and show on bsky.app profiles.
2. **Handle verification** for `*.at.browserid.me` — the fiddly bit.
   DNS is Namecheap, and that changes the calculus: Namecheap's
   `setHosts` API call **replaces the entire zone's records** on every
   write, and browserid.me's apex zone carries the DNSSEC-load-bearing
   `_browserid` record — a bad automated write there is protocol-fatal.
   So: **no recurring API writes against the apex zone.**
   - **(a) RECOMMENDED — wildcard vhost + wildcard cert, alias-mode
     DNS-01**: one-time *manual* Namecheap records: `*.at.browserid.me` A
     → the host, and `_acme-challenge.at.browserid.me` CNAME → an
     `_acme-challenge` name in a throwaway zone on an API-friendly free
     DNS host (e.g. deSEC). acme.sh (DNS alias mode) then renews the
     wildcard cert writing TXT only in that zone; Namecheap is never
     touched by automation. `*.at.browserid.me` is added as dokku domains
     on `bsky-pds`, which answers `/.well-known/atproto-did` per Host for
     `PDS_SERVICE_HANDLE_DOMAINS`.
   - **(b) Per-handle DNS TXT automation** (`_atproto.<label>… TXT`): only
     safe if `at.browserid.me` is first **delegated as a subzone** (manual
     one-time NS records at Namecheap) to a host with a sane API — deSEC,
     or self-hosted PowerDNS. The nexys-system/namecheap-sdk wraps the
     Namecheap API and does read-modify-write, but the blast radius of a
     bug is still the whole apex zone; use it (if at all) only for
     one-time IaC of the static records, never in the provisioning path.
   - Until one lands, accounts work but bsky.app shows `handle.invalid` —
     harmless for stage-1 testing.
3. **Email**: the PDS wants SMTP for its own account emails
   (`PDS_EMAIL_SMTP_URL`) — optional for testing, needed before real users.

## Host runbook (stage 1, run on the dokku host)

Verify exact PDS env/image details against
github.com/bluesky-social/pds at execution time; shapes below are the
plan of record. The PDS container listens on 3000; the bridge on 5000.

```sh
# --- bsky-pds: stock image, no build ---
dokku apps:create bsky-pds
sudo mkdir -p /var/lib/dokku/data/storage/bsky-pds
dokku storage:mount bsky-pds /var/lib/dokku/data/storage/bsky-pds:/pds
dokku config:set bsky-pds \
  PDS_HOSTNAME=pds.bsky.browserid.me \
  PDS_JWT_SECRET="$(openssl rand -hex 32)" \
  PDS_ADMIN_PASSWORD="$(openssl rand -hex 24)" \
  PDS_PLC_ROTATION_KEY_K256_PRIVATE_KEY_HEX="$(openssl ecparam -name secp256k1 -genkey -noout -outform DER | tail -c +8 | head -c 32 | xxd -p -c 32)" \
  PDS_DID_PLC_URL=https://plc.directory \
  PDS_DATA_DIRECTORY=/pds \
  PDS_BLOBSTORE_DISK_LOCATION=/pds/blocks \
  PDS_SERVICE_HANDLE_DOMAINS=.at.browserid.me
dokku ports:set bsky-pds http:80:3000
dokku git:from-image bsky-pds ghcr.io/bluesky-social/pds:0.4
dokku domains:set bsky-pds pds.bsky.browserid.me
dokku letsencrypt:enable bsky-pds

# --- bsky-bridge: deployed by CI (deploy-bridge.yml); configure first ---
dokku apps:create bsky-bridge
sudo mkdir -p /var/lib/dokku/data/storage/bsky-bridge
dokku storage:mount bsky-bridge /var/lib/dokku/data/storage/bsky-bridge:/data
dokku config:set bsky-bridge \
  BRIDGE_ORIGIN=https://bsky.browserid.me \
  HANDLE_DOMAIN=at.browserid.me \
  BROKER_URL=https://browserid.me \
  PDS_URL=https://pds.bsky.browserid.me \
  PDS_ADMIN_PASSWORD=<same as bsky-pds>
dokku ports:set bsky-bridge http:80:5000
dokku domains:set bsky-bridge bsky.browserid.me
# first deploy: push to main (CI) or manually:
#   dokku git:from-image bsky-bridge ghcr.io/vthunder/browserid-bsky/pds-bridge:<sha>
dokku letsencrypt:enable bsky-bridge
```

`PDS_URL` uses the public PDS origin for stage 1 (simplest; loops through
nginx). Internal dokku networking is a later optimization.

## One-time setup checklist (Dan)

- [ ] Namecheap: A records `bsky.browserid.me` and `pds.bsky.browserid.me`
      → the dokku host (manual, dashboard).
- [ ] GitHub: repo secret `DOKKU_SSH_KEY` (reuse the dokku deploy key),
      repo variable `DOKKU_HOST`.
- [ ] After first CI push: make the `browserid-bsky/pds-bridge` GHCR package public.
- [ ] Run the host runbook above.

## Decided (2026-07-24)

- Two-hostname topology (bridge = audience; PDS direct for data plane).
- CI-image deploys via GHCR (`.github/workflows/deploy-bridge.yml`).
- Same dokku host as browserid.me; grow disk if PDS blobs demand it.
- DNS: Namecheap; no automated writes against the apex zone ever
  (`setHosts` replaces the whole zone and `_browserid` DNSSEC records live
  there). Stage-2 handles via option (a) alias-mode wildcard cert.
