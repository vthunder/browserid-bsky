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

## Manual, one-time (Dan)

1. **deSEC:** create a free account at desec.io; create a domain (a free
   `dedyn.io` subdomain is fine, e.g. `browserid-acme.dedyn.io`). Generate
   an **API token** (Token management) — this is the only secret.
2. **Namecheap `browserid.me` (Advanced DNS), two records:**

   | Type  | Host                | Value                                        |
   |-------|---------------------|----------------------------------------------|
   | A     | `*.at`              | `198.199.110.160`                            |
   | CNAME | `_acme-challenge.at`| `_acme-challenge.browserid-acme.dedyn.io.`   |

   (Use whatever deSEC domain you made in the CNAME target.)
3. Hand me the deSEC token (it goes in the host's acme.sh env, not any repo).

## Host side (me, once the above is done)

acme.sh is installed at `/root/.acme.sh` on the host (prep done). Then:

```sh
# issue the wildcard, challenge delegated to the deSEC zone
export DEDYN_TOKEN='<deSEC token>'
/root/.acme.sh/acme.sh --issue --server letsencrypt \
  --dns dns_desec \
  --challenge-alias browserid-acme.dedyn.io \
  -d '*.at.browserid.me'

# install into the PDS app + reload; the deploy hook re-runs on renewal
/root/.acme.sh/acme.sh --install-cert -d '*.at.browserid.me' \
  --key-file       /var/lib/dokku/data/certs/bsky-pds.key \
  --fullchain-file /var/lib/dokku/data/certs/bsky-pds.crt \
  --reloadcmd "cat /var/lib/dokku/data/certs/bsky-pds.crt /var/lib/dokku/data/certs/bsky-pds.key | dokku certs:add bsky-pds"
```

acme.sh installs a cron entry; renewal re-runs `--install-cert` →
`certs:add` → nginx reload. No Namecheap writes ever.

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
