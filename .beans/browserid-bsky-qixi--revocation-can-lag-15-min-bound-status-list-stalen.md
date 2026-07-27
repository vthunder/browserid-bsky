---
# browserid-bsky-qixi
title: 'Revocation can lag ~15 min: bound status-list staleness on the bridge write path'
status: completed
type: bug
priority: normal
created_at: 2026-07-27T12:44:26Z
updated_at: 2026-07-27T13:02:51Z
---

The guide promises "the service re-checks revocation on every use" (guide.rs:190), but the bridge's StatusCache serves a cached status list as Valid for iat + ttl (300s, STATUS_LIST_TTL_SECONDS) + grace_seconds (600, hardcoded in browserid-rp StatusCache::new) and only refreshes on Unknown (pds-bridge/src/routes.rs:1444-1449, also ~735-761). Worst case: a revoked warrant keeps posting for ~15 minutes. The registrar signs /.well-known/browserid-status fresh per GET, so all staleness is client-side. This also wrecks the planned revocation-finale demo beat.

Fix: bound staleness to ~15s on the bridge's authenticated paths.

- [x] browserid-ng/browserid-rp: track fetch time per cached list; expose a max-age-aware check or refresh-if-older-than API (default behavior unchanged; fail-closed semantics preserved — refresh failure degrades to existing ttl+grace window)
- [x] pds-bridge: both auth paths (bearer-token resolve ~routes.rs:735 and warrant path ~routes.rs:1439) refresh when the cached list is older than 15s
- [x] Fix the misleading "≤5 min cache" comment at routes.rs:1439
- [x] Tests in browserid-rp (stale list -> refresh -> revoked seen) and bridge as feasible
- [x] Land: push browserid-ng main, cargo update -p browserid-rp -p browserid-core -p browserid-agent, drop any temporary [patch] override, commit

## Summary of Changes

browserid-ng f6fff77 (feat(rp)): StatusCache entries record their fetch instant; new `check_within(r, max_age)` reads Unknown for anything fetched longer ago than max_age, triggering the caller's refresh-on-Unknown path, while plain `check()` keeps ttl+grace semantics so a failed refresh degrades instead of hard-failing. `insert_fetched_ago()`/`age()` added for tests. 16 unit + 2 doc tests pass.

pds-bridge: both auth paths (bearer-token resolve and warrant-scoped call) now use `check_within` with `STATUS_MAX_AGE = 15s`; misleading "≤5 min cache" comment fixed. Revocation is now demo-visibly instant: worst case one 15s-old list, refreshed on the next request.
