---
# browserid-bsky-hfh8
title: 'fd leak: subscribeLabels never reads its socket, so dropped consumers are never reaped'
status: in-progress
type: bug
priority: high
created_at: 2026-07-25T22:49:24Z
updated_at: 2026-07-25T22:49:24Z
---

## Symptom

Deployed `bsky-bridge` wedged 2026-07-25 with `ERROR axum::serve: accept error: Too many open files (os error 24)` repeating every second. Up ~1-2 days since the 2026-07-24 deploy. Restart cleared it. Order of ~1024 fds leaked per day.

## Mechanism

`routes.rs::stream_labels` only ever **sends** on the websocket; it never calls `socket.recv()`. After the backfill drains it parks forever on `live.recv().await` (the label broadcast channel).

A websocket peer disconnect is only observed by *reading*: the peer's Close frame, and even a TCP FIN, sit in the receive buffer unnoticed. Since the bridge emits labels rarely, no write is ever attempted, so the send path never errors either. The task never exits and holds the socket fd for the life of the process.

External consumers (LabelRelay, vortex) reconnect roughly every 30s -> ~2900 connects/day, each leaking one fd. Matches the observed timeline exactly.

## Fix

Split the socket, and select on the read half alongside the live channel: any Close/Err/EOF from the peer ends the task. Also send a periodic Ping so a half-open TCP connection (no FIN) fails a write and gets reaped.

Regression test opens N connections, drops them, and asserts `label_tx.receiver_count()` returns to 0.

## Status 2026-07-26

Fixed in `routes.rs::stream_labels` (split socket + select on the read half + 30s ping). Regression test `dropped_label_consumers_release_their_connections` in `pds-bridge/tests/bridge_test.rs` is red on the old code (times out with 5 live consumers) and green on the new. Full `cargo test -p pds-bridge`: 25 passed. **Uncommitted and undeployed.**
