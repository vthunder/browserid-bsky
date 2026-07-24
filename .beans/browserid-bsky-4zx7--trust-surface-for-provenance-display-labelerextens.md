---
# browserid-bsky-4zx7
title: 'Trust surface for provenance display: labeler/extension, not the in-post link'
status: completed
type: task
priority: high
created_at: 2026-07-24T19:13:41Z
updated_at: 2026-07-24T20:36:19Z
---

DESIGN NOTE / DECISION (2026-07-24, with Dan). The in-post 'verify' link (facet) is CONVENIENCE, NOT SECURITY: any affordance in post content is attacker-controlled, so a malicious post can link to a fake verifier (evil.com/verify) that renders a legit-looking green receipt. Inherent weakness of the link-to-verify model — unfixable within it, because once the reader is on the fake page nothing it shows is trustworthy. Same class as fake verified-badge / 'click to confirm' phishing.

The fix is to move the trust root OFF author-controlled content:
1. Client-side verification (REAL answer): a browser extension / native-client integration reads the actual post's DID+rkey as rendered by the real client, fetches provenance, verifies independently, stamps its OWN UI. Unphishable — author supplies no URL. The atproto-native version is a LABELER: bsky.app renders the badge from a labeler the USER subscribed to, keyed on the real post. This is why labelers are a separate trusted service, not in-content.
2. User-initiated paste (manual fallback, already built): user grabs the post's real URL from the client share button, pastes into a verifier they navigated to themselves. Phishing-resistant because the user chose both post and verifier.
3. In-post link: UX sugar only.

Hierarchy: labeler/extension = trust surface; paste page = manual fallback; in-post link = sugar (never present as authoritative).

OPEN DECISION: keep the in-post link (but never present it as authoritative) vs drop it (so nobody learns to trust an in-content verify affordance). Leaning keep-for-demo.

Action: prioritize a browserid LABELER and/or a browser extension as the real trust surface. Supersedes treating the in-post link as the primary display. Relates to 27c0/n78o (provenance data these consume).



## Milestone A DONE (2026-07-24) — labeler live, signed labels

did:web:bsky.browserid.me labeler served by the bridge. /.well-known/did.json (k256 #atproto_label Multikey + #atproto_labeler service) and com.atproto.label.queryLabels both live; queryLabels returns a correctly k256-signed browserid-verified label for a fully-verified post (delegation + unforgeable attestation re-checked server-side). uriPatterns parsed from raw query (axum Query cant do repeated keys).

## Design answers (2026-07-24)
- One account = one labeler (DID with #atproto_labeler service; user subscribes by DID). Multiple brands = multiple DIDs. We need only ONE.
- One labeler CAN emit many label values, chosen per post, via app.bsky.labeler.service policies.labelValues + labelValueDefinitions (per-value name/description/severity/blur). So the two provenance paths become distinct badges.

Planned vocabulary (one labeler): browserid-verified (as-itself), browserid-on-behalf (delegate acted for another identity), browserid-unverified/broken (provenance present but failed). All severity=inform, blurs=none.

## Milestone B (next)
One labeler ACCOUNT (did:plc on our PDS) + app.bsky.labeler.service record declaring the vocabulary; add #atproto_label key + #atproto_labeler service to its did:plc doc (PLC op). Then C: subscribe in bsky.app, badge renders. Open: try did:web subscribe first vs go straight to did:plc account.



## Label vocabulary DECIDED (2026-07-24): 3 values, absence = no-sidecar

A literal no-sidecar label is INFEASIBLE — labelers emit positive assertions on specific subjects, not the whole network; labeling every unsidecard post = labeling all of Bluesky. So ABSENCE of a label is the no-sidecar signal. no-sidecar and broken are still distinct: no-sidecar = no badge; broken = a visible warning badge.

Vocabulary:
- browserid-verified — fully verified, as-itself (severity inform, blur none)
- browserid-on-behalf — fully verified, delegate acted for another identity (inform, none)
- browserid-broken — provenance PRESENT but failed verification / tampered (v1 severity INFORM to avoid our-bug false alarms; promote to alert once trusted)

Build note: verified/on-behalf emit fine from queryLabels (AppView asks about posts in view). Reliably emitting broken network-wide wants the subscribeLabels FIREHOSE consumer (watch me.browserid.provenance records, evaluate) — not in milestone A. Sequence: ship verified (+on-behalf) via queryLabels -> badges render -> add firehose to emit broken.

## Milestone B DONE (2026-07-24) — subscribable labeler account, live

Open question answered EMPIRICALLY: a did:web labeler is NOT subscribable.
bsky.app resolves labelers through the AppView's index of
app.bsky.labeler.service records, and those live in a repo — getServices for
did:web:bsky.browserid.me returned {"views":[]}. So the did:plc account was
required after all.

Built:
- Labeler account `labeler.at.browserid.me` = `did:plc:iewpoc3kqru4rgqpkojfixhx`
  on our PDS (profile: "browserid provenance"). Account password stored as
  dokku config `bsky-bridge:LABELER_ACCOUNT_PASSWORD` (nowhere else).
- PLC operation adding `#atproto_label` (the SAME k256 key the bridge signs
  with) + `#atproto_labeler` service -> https://bsky.browserid.me. Signed via
  the PDS identity.signPlcOperation/submitPlcOperation flow; the email token
  was read out of the PDS sqlite (no SMTP configured — see Gotchas).
- `app.bsky.labeler.service` record declaring all three label values with
  labelValueDefinitions (severity inform, blurs none, defaultSetting warn).
  AppView indexed it: getServices now returns the view.
- Bridge: `LABELER_DID` env overrides the label `src` (set in dokku);
  /.well-known/did.json still describes did:web with the same key.
- browserid-on-behalf now emitted: fully_verified returns Option<on_behalf>
  (grantor != grantee) and queryLabels picks the value. Deployed and verified
  live — labels come back signed with src=did:plc:iewpoc3kqru4rgqpkojfixhx.

## Milestone C (next, needs Dan)
Subscribe to `labeler.at.browserid.me` in bsky.app (Settings -> Moderation ->
Add labeler / open the profile) and confirm the browserid-verified badge
renders on the demo post. Then the only vocabulary gap left is
browserid-broken, which wants the subscribeLabels firehose consumer.

## Milestone C DONE (2026-07-24) — badges render in bsky.app

Dan subscribed and the browserid-verified badge is visible on the demo posts.
The trust surface this bean called for exists end to end.

## The thing milestones A+B got wrong: labels are PUSHED, not pulled

Subscribing showed NO labels. The nginx access log said why: label consumers
(LabelRelay/1.0, vortex/0.0.1, Go-http-client) had been retrying
/xrpc/com.atproto.label.subscribeLabels every ~30s and getting 400, while
queryLabels had exactly one caller ever — a test curl of mine.

The AppView ingests a labeler's FIREHOSE into its own label index and renders
badges from that index. queryLabels is a lookup API that is not on the client
read path. A+B built a correct, subscribable labeler IDENTITY with no
delivery mechanism, which is why the identity checked out everywhere
(getServices, DID doc, signatures) and still showed nothing.

Built (commit "subscribeLabels firehose"):
- labels table: monotonic seq = the consumer cursor. Labels are stored once
  and never renumbered; a subject already labeled is left alone.
- subscribeLabels websocket: backfill everything above ?cursor, then tail a
  broadcast channel. A lagging consumer is dropped and refills from its
  cursor on reconnect, so nothing is lost.
- Frames are atproto event-stream frames: header {t:"#labels",op:1} then
  body {seq,labels:[...]}, both DAG-CBOR, sig as a CBOR BYTE STRING (not the
  JSON $bytes wrapper). Unit-tested by decoding a frame and verifying the
  signature the way a consumer does.
- Emission at three points: when provenance is written, opportunistically on
  queryLabels, and a startup scan of hosted repos (so posts predating the
  labeler still enter the stream). All idempotent.
- queryLabels now serves STORED labels, so both surfaces agree on cts/sig.

Verified live: a hand-rolled RFC6455 client got 101 + both backfilled frames
through dokku's nginx; LabelRelay upgraded successfully a minute after
deploy and held the connection open.

Note: the PUBLIC unauthenticated AppView (public.api.bsky.app getPosts /
getPostThread with atproto-accept-labelers) still returns labels: [] even
though the app shows the badge — third-party label hydration appears to be
tied to the authed client path. Don't use that endpoint as the test for
whether labeling works; look at the app.

## Follow-ups
- browserid-broken needs a REPO-firehose consumer to detect tampered/failed
  provenance network-wide: bean arj3.
- The on-behalf path (grantor != grantee) is coded and emits its own label,
  but has never run live.
