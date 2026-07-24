---
# browserid-bsky-4zx7
title: 'Trust surface for provenance display: labeler/extension, not the in-post link'
status: in-progress
type: task
priority: high
created_at: 2026-07-24T19:13:41Z
updated_at: 2026-07-24T19:40:39Z
---

DESIGN NOTE / DECISION (2026-07-24, with Dan). The in-post 'verify' link (facet) is CONVENIENCE, NOT SECURITY: any affordance in post content is attacker-controlled, so a malicious post can link to a fake verifier (evil.com/verify) that renders a legit-looking green receipt. Inherent weakness of the link-to-verify model — unfixable within it, because once the reader is on the fake page nothing it shows is trustworthy. Same class as fake verified-badge / 'click to confirm' phishing.

The fix is to move the trust root OFF author-controlled content:
1. Client-side verification (REAL answer): a browser extension / native-client integration reads the actual post's DID+rkey as rendered by the real client, fetches provenance, verifies independently, stamps its OWN UI. Unphishable — author supplies no URL. The atproto-native version is a LABELER: bsky.app renders the badge from a labeler the USER subscribed to, keyed on the real post. This is why labelers are a separate trusted service, not in-content.
2. User-initiated paste (manual fallback, already built): user grabs the post's real URL from the client share button, pastes into a verifier they navigated to themselves. Phishing-resistant because the user chose both post and verifier.
3. In-post link: UX sugar only.

Hierarchy: labeler/extension = trust surface; paste page = manual fallback; in-post link = sugar (never present as authoritative).

OPEN DECISION: keep the in-post link (but never present it as authoritative) vs drop it (so nobody learns to trust an in-content verify affordance). Leaning keep-for-demo.

Action: prioritize a browserid LABELER and/or a browser extension as the real trust surface. Supersedes treating the in-post link as the primary display. Relates to 27c0/n78o (provenance data these consume).
