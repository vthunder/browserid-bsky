---
# browserid-bsky-rjpk
title: Public provenance verifier page (bsky.browserid.me/verify)
status: in-progress
type: feature
created_at: 2026-07-24T16:26:07Z
updated_at: 2026-07-24T16:26:07Z
---

GET /verify?uri=<post at-uri>[&format=json] on the bridge. Resolves the did's PDS via plc.directory, reads me.browserid.provenance + referenced me.browserid.warrant, verifies the delegation from the published artifacts (warrant<-config-cert sig, config-cert authoritative for grantor, config-cert<-IdP key, audience, expiry, provenance matches), derives root identity, renders a receipt (HTML + JSON). Honest phase-1 caveat: post<->grantee link is PDS-asserted (n78o closes it). IdP key via well-known (advisory); authoritative DNSSEC check runs at post time via hosted verifier.
