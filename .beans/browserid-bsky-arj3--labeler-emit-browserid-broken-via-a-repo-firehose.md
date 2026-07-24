---
# browserid-bsky-arj3
title: 'Labeler: emit browserid-broken via a repo-firehose consumer'
status: todo
type: feature
priority: normal
created_at: 2026-07-24T20:35:57Z
updated_at: 2026-07-24T20:35:57Z
---

The labeler vocabulary declares browserid-broken (provenance PRESENT but failed verification / tampered / warrant revoked), but nothing emits it yet.

Why it needs more than the current machinery: verified/on-behalf are emitted for posts we host, at write time or on a repo scan. Broken is a claim about ANY post on the network that carries a me.browserid.provenance sidecar — including repos we do not host. Catching those needs a consumer of the atproto REPO firehose (com.atproto.sync.subscribeRepos) that watches for me.browserid.provenance records, evaluates them with the same fully_verified logic, and emits browserid-broken when evaluation fails.

Note the label DELIVERY side is now built (bean 4zx7): pds-bridge has a persistent, seq-numbered label store and a working com.atproto.label.subscribeLabels firehose. This bean is only the detection/evaluation half.

v1 severity stays inform (avoid false alarms from our own bugs); promote to alert once trusted.
