---
# browserid-bsky-ek9u
title: 'labeler: per-identity-pair labels so the badge says WHO'
status: in-progress
type: feature
priority: normal
created_at: 2026-07-25T23:24:47Z
updated_at: 2026-07-25T23:28:15Z
---

## Goal

The badge should say WHO posted, without putting emails in the label `val`.
In atproto a label `val` is an opaque id; the rendered badge text is the
matching `labelValueDefinition`'s locale `name` and the click-through text is
its `description`. So: unique vals per identity pair (to key unique
descriptions), many vals sharing one display name.

## Design

- New vals emitted **alongside** the existing `browserid-verified` /
  `browserid-on-behalf` (those stay untouched):
  - grantor != grantee -> `by-agent-<h>`
  - grantor == grantee -> `by-owner-<h>`
  - `<h>` = first 8 lowercase hex chars of SHA-256 over `"{grantor}|{grantee}"`.
- Definitions appended to the labeler account's `app.bsky.labeler.service`
  record on first sight of a pair: name `by agent` / `by owner`, description
  naming the real emails + the paste-a-link fallback. `inform` / no blur, to
  match the existing browserid-* definitions.
- Record update authenticates to the PDS as the labeler account using
  `LABELER_ACCOUNT_PASSWORD` (already set in dokku config, previously unread).
  Optional: unset -> log + skip definition updates, still emit labels.
- Idempotence: a `label_defs` table records defined vals; the record is also
  re-read before each write so a concurrent append is not lost.

## Emission points

Same three as today: post-write path, opportunistic `queryLabels`, startup
backfill scan.


## Status 2026-07-26 — implemented, uncommitted, not deployed

Code landed in the working tree (`cargo test -p pds-bridge` green, 23 unit +
6 integration). Files: `labeler.rs` (val/description/definition + merge),
`store.rs` (`label_defs` claim table), `pds.rs` (`create_session`,
`get_record`), `routes.rs` (`emit_label` now emits both vals;
`ensure_pair_definition` / `put_pair_definition`), `lib.rs` + `main.rs`
(`labeler_account_password` from env, warn when unset).

Note for the live rollout: the AppView caches `labelValueDefinitions` from
the labeler service record, so the first badge for a brand-new pair can
render nameless for a few minutes until it re-indexes.
