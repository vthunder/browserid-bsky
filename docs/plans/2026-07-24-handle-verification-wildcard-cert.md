# Handle verification: wildcard cert for `*.at.browserid.me` (stage 2)

**Date:** 2026-07-24
**Decision:** wildcard TLS via **deSEC alias-mode DNS-01** (auto-renewing;
Namecheap apex never written by automation — our hard rule).

## Why

atproto handle verification is bidirectional. The DID doc already claims
`at://<handle>` (forward ✓). The reverse (handle → DID) uses the HTTP
method: `GET https://<handle>/.well-known/atproto-did` → the DID. The stock
PDS already serves this per-`Host` for `PDS_SERVICE_HANDLE_DOMAINS`
(verified: `claude.at.browserid.me` → its DID, unknown → 404), and dokku
nginx now routes `*.at.browserid.me` → `bsky-pds`. The only missing piece
is a TLS cert valid for `*.at.browserid.me`.

Wildcards require DNS-01. Namecheap's API is poor and its `setHosts`
replaces the whole zone (where the DNSSEC `_browserid` records live), so we
never let automation touch it. Alias mode delegates *only the ACME
challenge* to a throwaway deSEC zone with a good API; the cert auto-renews
writing TXT there, and Namecheap gets two manual, one-time records.

## Plumbing already in place

- `bsky-pds` serves `/.well-known/atproto-did` per Host (stock PDS).
- `dokku domains:add bsky-pds "*.at.browserid.me"` — nginx routes the
  wildcard to the PDS (verified via forced-resolution: returns the DID).

## IMPORTANT: one cert must cover BOTH vhosts

`bsky-pds` answers two vhosts — `pds.bsky.browserid.me` (data plane) and
`*.at.browserid.me` (handle verification). dokku serves **one cert bundle
per app**, so `dokku certs:add` replaces the whole cert: a wildcard-only
cert breaks `pds.bsky.browserid.me` (and thus the bridge→PDS TLS calls).
The cert MUST be a single SAN cert covering **both** names. Both are
validated through the same deSEC alias (deSEC holds multiple challenge TXTs
at one `_acme-challenge` name), so each needs its own Namecheap CNAME
pointing at the deSEC challenge name. `dokku letsencrypt` is not used for
this app once the SAN cert is in place.

## Manual, one-time (Dan)

1. **deSEC:** create a free account at desec.io; create a domain (a free
   `dedyn.io` subdomain is fine, e.g. `browserid-acme.dedyn.io`). Generate
   an **API token** (Token management) — this is the only secret.
2. **Namecheap `browserid.me` (Advanced DNS), two records:**

   | Type  | Host                     | Value                                     |
   |-------|--------------------------|-------------------------------------------|
   | A     | `*.at`                   | `198.199.110.160`                         |
   | CNAME | `_acme-challenge.at`     | `_acme-challenge.browserid.dedyn.io.`     |
   | CNAME | `_acme-challenge.pds.bsky`| `_acme-challenge.browserid.dedyn.io.`    |

   (deSEC domain is `browserid.dedyn.io`. The two challenge CNAMEs let one
   SAN cert cover `*.at.browserid.me` + `pds.bsky.browserid.me`.)
3. Hand me the deSEC token (it goes in the host's acme.sh env, not any repo).

## Host side (me, once the above is done)

acme.sh is installed at `/root/.acme.sh` on the host (prep done). Then:

acme.sh is installed at `/root/.acme.sh`, deSEC provider present, and a
deploy helper `/root/.acme.sh/deploy-bsky-pds.sh` tars fullchain+key as
`server.crt`/`server.key` and pipes to `dokku certs:add bsky-pds`.

```sh
# SAN cert: both names, both challenges delegated to the deSEC zone
sudo DEDYN_TOKEN='<deSEC token>' /root/.acme.sh/acme.sh --issue --server letsencrypt \
  --dns dns_desec --challenge-alias browserid.dedyn.io \
  -d '*.at.browserid.me' -d 'pds.bsky.browserid.me'

# install once to the PDS app; deploy hook re-runs on renewal
sudo /root/.acme.sh/acme.sh --install-cert -d '*.at.browserid.me' --ecc \
  --reloadcmd /root/.acme.sh/deploy-bsky-pds.sh

# re-add the wildcard vhost (removed during the single-name-cert stopgap)
dokku domains:add bsky-pds '*.at.browserid.me'
```

acme.sh installs a cron entry; renewal re-runs the deploy hook →
`certs:add` → nginx reload. No Namecheap writes ever. (Interim history:
a wildcard-only cert was installed then rolled back — it broke
`pds.bsky.browserid.me`; the SAN cert above is the fix.)

## Verify

```sh
curl -fsS https://claude.at.browserid.me/.well-known/atproto-did   # -> the DID, valid TLS
```

Then bsky.app resolves `claude.at.browserid.me` (the "Invalid Handle"
warning clears). New handles need no per-handle work — the wildcard cert +
per-Host PDS serving cover them all.

## Follow-ups

- The DNS method (`_atproto.<handle>` TXT) is an alternative that needs no
  cert but per-handle writes; not pursued — the wildcard HTTP method is
  zero-per-handle. If we ever want DNS-method too, the same deSEC zone (if
  `at.browserid.me` were delegated there) could serve it.
- P2 provenance (agent/warrant attribution on posts) is separate from
  handle verification.
