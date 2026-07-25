---
# browserid-bsky-adsa
title: 'Structural DID↔browserid-identity binding: user-chain-signed, not bridge-DB-trusted'
status: todo
type: feature
priority: high
created_at: 2026-07-25T23:12:41Z
updated_at: 2026-07-25T23:12:41Z
---

Dan's observation after the friend test (2026-07-25): the claim '@dan.at.browserid.me IS danmills@sandmill.org' is currently just a row in the bridge's sqlite (grantor-email → DID at provision time). Nothing user-signed names the DID, so the binding — and everything the receipt/labeler says about WHOSE account a post landed on — rests on trusting the bridge's database. Concretely: within a warrant's validity the bridge could open a different account against the same warrant and attribute it to the grantor; no signature would contradict it. This weakens the headline value ('unforgeable provenance') at exactly the identity hop readers care about.

Proposal: close the chain by having the AGENT sign the DID at account creation with its warrant-chained access key — e.g. a me.browserid.binding repo record {did, handle, grantor, grantee, sig over the DID by the access key certified for the grantee}. Verification then reads: IdP keys → config cert → warrant (grantor authorized grantee at this bridge) → access key → 'my account is did:X'. Anyone can verify from the repo + IdP keys; the bridge attests nothing. /verify and the labeler check it; absence downgrades the receipt wording (today's trust level). The handle→DID hop stays DNS/PLC (that part is atproto's own trust model and the bridge controls at.browserid.me DNS regardless — the repo record is the portable binding that survives PDS migration.

Also from the same conversation, softer but related: the three-name indirection (danmills@ → danmills+fable@ → @fable.at.browserid.me) is cognitively heavy; a user-chosen display name captured at approval (design-board side quest #1) plus receipts leading with the handle would reduce it.
