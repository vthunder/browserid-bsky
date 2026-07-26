---
# browserid-bsky-ek9u
title: 'labeler: per-identity-pair labels so the badge says WHO'
status: completed
type: feature
priority: normal
created_at: 2026-07-25T23:24:47Z
updated_at: 2026-07-25T23:59:54Z
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


## Follow-up 2026-07-26 — agent-owned reclassification + negation migration

Dan reviewed the live behavior (4 pairs declared, fable post carrying
`by-owner-ea7898db`). Two changes, implemented, uncommitted:

**1. `+tag` sub-identities are agents, not owners.** `grantor == grantee` is
no longer sufficient for `by-owner-`; if the identity's local part contains
`+` it is an agent's own sub-identity, so it classifies as `by-agent-` with a
new description ("Posted by X, an agent owned by Y."). The hash input is
unchanged, so reclassifying a pair moves only the prefix — which is exactly
what makes the old val identifiable and retractable.

**2. Negation labels.** Labels grew a `neg` column. The pre-existing
`UNIQUE (uri, val)` *table* constraint would have rejected a negation of a
label the subject already carries, and SQLite cannot drop a table
constraint, so `migrate_labels_neg` rebuilds the table copying `seq`
verbatim (those are live consumer cursors) and replaces the constraint with
a `UNIQUE (uri, val, neg)` index. `neg` is inside the signed DAG-CBOR and is
omitted when false, so plain labels sign byte-identically to before.

**3. The skip-guard.** No longer "has a pair label" — it re-derives the val
from the identities the val was minted for (`label_defs.grantor/grantee`,
new nullable columns) and skips only if it still matches. Purely local, no
network. Vals recorded before those columns existed read as unknown, so they
are re-verified once and then self-heal.

**4. Guide.** `guide.rs` step 1 now tells the agent the two account shapes
exist (as-itself vs on-behalf), what each renders as publicly, to ask the
human before requesting, and that on-behalf creation 409s if the human's
identity already owns an account.

Tests: 30 unit + 6 integration green.

## Deployed + verified live 2026-07-25

Both phases shipped (commits 7956fc7, 2323405). Live verification: fable and scribe posts each carry browserid-verified, the retracted by-owner-<h> (neg), and the reclassified by-agent-<h>; all five pair definitions are in the service record — 'an agent owned by <base>' for agent-owned accounts, 'on behalf of' for the true delegate pair. The pre-neg labels table migrated in place with seqs preserved. Definition-render lag in bsky.app is AppView caching, self-heals.
