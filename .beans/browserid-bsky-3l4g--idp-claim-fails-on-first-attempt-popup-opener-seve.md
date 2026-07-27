---
# browserid-bsky-3l4g
title: IdP claim fails on first attempt (popup opener severed by OAuth redirect)
status: completed
type: bug
priority: high
created_at: 2026-07-27T17:38:22Z
updated_at: 2026-07-27T20:38:54Z
parent: browserid-bsky-tw1d
---

First live-claim hiccup: in popup mode the device-authorize page navigates the popup itself to bsky.social for atproto OAuth (device-authorize.html:214 location.href=authorize_url); the browser severs window.opener across the cross-origin round trip (bsky.social COOP), so on return the page has certs but no dialog window to postMessage them to and shows 'the sign-in dialog window is gone' (device-authorize.html:175). Deterministic for every first-time popup user. Retry works only because the IdP session cookie (SameSite=None) then lets /idp/whoami skip OAuth entirely (no navigation, opener intact).

Traced by claim-trace 2026-07-27. Issue 1 (different handle) was also investigated: SAFE, no code change.

Fix: hand certs back via the dialog's redirect/resume path instead of postMessage when returning from OAuth (signed_in=1). Prefer bridge-only using the existing browser-dialog resume convention (return_origin is already known + allowlisted). Touch the broker dialog only if resumeDeviceAuth genuinely needs pre-stored state popup mode doesn't write — and flag it, since deploying the id app affects the whole browserid ecosystem.

- [x] Determine bridge-only feasibility (read browserid-ng dialog.js resumeDeviceAuth / primaryRedirectHop)
- [x] Implement handback via redirect-resume on the signed_in=1 return leg
- [x] Keep the postMessage path for the already-signed-in (no-navigation) case
- [x] Test the return-leg branch
- [ ] BROKER (browserid-ng, NOT done here): make popup mode write the pending keystore record
- [ ] Verify live: first claim from a cold session succeeds

## Feasibility verdict (2026-07-27): NOT bridge-only — the broker must also change

`resumeDeviceAuth` (dialog.js:897-939) reads the certs from the fragment but
takes the *keys and dialog state* from `Keystore.getPending()` (:902); with no
pending record it bails at :904 with "Sign-in state was lost". Only
`primaryRedirectHop` (:862-893) ever calls `Keystore.putPending`.
`primaryPopupFlow` (:521-625) keeps the non-extractable CryptoKeys in the
dialog window's memory and never persists them. So a resume redirect from the
popup lands on a dialog page with certs and no keys.

The mechanism itself is sound: IndexedDB is per-origin, so a pending record
written by the dialog window is readable by the resume page running in the
popup — it just is never written in popup mode.

### Required broker-side change (browserid-ng, deliberately NOT made here)

In `browserid-broker/static/dialog.js`, `primaryPopupFlow` (:521):
1. Before `window.open` (:532), `await Keystore.putPending({...})` with exactly
   the payload `primaryRedirectHop` builds at :864-882 (kind `device_auth`,
   both private keys + pubkey X values, email, domain, mintUrl, and the
   `dialog` state block).
2. Leave the popup URL otherwise unchanged — do NOT add `return_url`, or the
   bridge takes the redirect-mode branch unconditionally and the normal
   (opener-intact) popup handback is lost. The bridge derives the resume URL
   from `return_origin` only when the opener is gone.
3. On the normal postMessage resolution path (`onMessage` :585-609) and on
   every reject/cleanup, `await Keystore.clearPending()` so a stale record
   cannot be picked up by a later resume.
4. `resumeDeviceAuth` needs no change for the cert path, but note its tail
   `sendResponse` (:1040): in the resumed *popup* there is no `state.redirect`
   and no opener, so the RP response has nowhere to go. Popup-mode resume must
   therefore either be given the RP's redirect state in the pending record, or
   deliver via a same-origin channel (BroadcastChannel/storage event) to the
   still-open dialog window, which then completes normally.

Bridge-side alternative if the broker stays frozen: keep the device-authorize
page put and run the OAuth hop in a *child* popup opened synchronously from
the submit gesture, with the callback page signalling back over a same-origin
BroadcastChannel. No opener is ever severed. Costs a popup-in-popup and is
vulnerable to popup blockers; not implemented.

Agent mode has no resume representation (`browserid:agent_device_cert` is not
a fragment the dialog parses), so it still reports the dead opener.

## Decision 2026-07-27: fix the browser dialog (Option A)

User chose the proper dialog fix over the bridge-only child-popup. Touches browserid-ng dialog.js (shared, deployed via the id app = whole browserid ecosystem), so it gets an adversarial review before the id deploy. Bridge half (resume-redirect handback in device-authorize.html) already written and forward-compatible; it's inert until the dialog persists/hands off the keys.

Key topology insight for the routing wrinkle (#4): in popup mode the ORIGINAL dialog window (popup1, broker origin, holds the RP relationship + in-memory keys) stays open awaiting postMessage while it opened device-authorize as popup2 (bridge origin). OAuth severs popup2->popup1 opener. The bridge redirects popup2 to the broker-origin resume URL, putting it same-origin with popup1 — so the resume page can hand certs to the still-open popup1 (BroadcastChannel/storage), which completes with its own keys + RP state. That may be cleaner than persist-keys-and-self-complete; builder to verify against real dialog.js.

- [x] BROKER: dialog.js HANDOFF fix (BroadcastChannel to still-open dialog window)
- [x] Adversarial review: 2 blockers (unpaired error teardown, lenient key check poisoning keystore), both fixed + concurrency test
- [~] Deploy id app + bsky-bridge; verify cold-session first claim (landing)

## Adversarial review (2026-07-27): 2 blockers, both in the untested listener half

Deploy to id app gated on fixing:
- BLOCKER 1 (dialog.js:663-668): device_error branch of the BroadcastChannel listener has NO pairing check — an error broadcast from one flow force-closes/rejects every other waiting dialog window on the origin (two sign-ins in flight = one's failure kills the other). Fix: IdP echoes device_pubkey into the error fragment; error branch requires it to match keys.device.publicKeyX; drop the broadcast if absent. Needs bridge device-authorize.html to add device_pubkey to the device_error fragment.
- BLOCKER 2 (dialog.js:226-232 + 655-662): certCertifiesKey is lenient (unreadable key -> true); with an IdP that omits the advisory public-key claim, two concurrent windows BOTH resolve on the same certs, and the mis-paired cert is persisted to the keystore (storeDevicePair before any signing) -> persistent broken login. Fix: on the handoff path, fail closed — require a readable key AND a match.
- Add the missing coverage: a test with two concurrent primaryPopupFlow windows + a single broadcast (catches both).

Clean on the other 4 areas: normal postMessage handback, redirect-mode stale-pending discard (encodings verified byte-identical), the 2.5s wait (only when a cert actually arrived), the ?resume= watchdog guard.

## REOPENED — deployed fix fails the real round trip

Live cold-session test: after OAuth the resume popup shows 'Finishing sign-in...' then 'Sign-in state was lost' — handoffResume got no ack in 2.5s. The synthetic Playwright tests never drove a real OAuth redirect, so the reviewer's flagged gap bit. Three indistinguishable silent causes: (A) no waiting dialog window, (B) window present but certKeyMatchesStrict mismatch (device-key encoding), (C) no certs in fragment. Adding a diagnostic build (a 'seen-but-not-mine' nack + reason code in the error) to bisect A/B/C on the next retry.

## Redesign 2026-07-27: IdP owns the bsky roundtrip via a child popup (user direction)

Root cause of [no-window] confirmed: the IdP page self-navigates to bsky.social; bsky's COOP severs the IdP-page<->dialog window handle (popup.closed false-fires -> dialog tears down its listener). The handoff-via-browserid-resume-page was a workaround for delivering the cert ACROSS the origin gap (bsky.browserid.me IdP vs browserid.me dialog) and the user rightly rejects it.

New shape (user's 'popup' option = old Option B): the IdP page does NOT navigate. It opens a throwaway child popup for the bsky OAuth; that popup returns to the IdP callback (same bridge origin), signals the IdP page (same-origin BroadcastChannel) and closes; the IdP page — which never moved, so its window.opener to the dialog is intact — re-checks /whoami, signs the cert, and postMessages it to the dialog via the NORMAL path. Bridge-only.

- [ ] Revert browserid-ng dialog.js to pristine (remove handoff listener, handoffResume, resumeDeviceAuth handoff branch, diagnostics, helpers) + remove the new e2e spec
- [ ] Revert the bridge resume-redirect fallback in device-authorize.html
- [ ] device-authorize: 'Continue with Bluesky' gesture -> open child popup -> /idp/oauth/start -> set popup location to authorize_url
- [ ] /idp/oauth/callback: establish session, then serve a tiny page that signals the opener IdP page (BroadcastChannel, same bridge origin) and closes the popup
- [ ] IdP page: on the signal, re-check /whoami and proceed to issue+postMessage to the dialog (reuse the already-signed-in path)
- [ ] Popup-blocker safety: open the child popup synchronously on the click, blank first, then set location
- [ ] Tests + live cold-session verify

## Fix landed 2026-07-27: announce-pending watchdog

Real root cause: the dialog's popup.closed poll false-fired when the IdP popup went cross-origin to bsky.social (COOP severs the handle -> popup.closed true), tearing down the handoff listener before certs returned. Fix: IdP announces via window.opener.postMessage (cross-origin; NOT BroadcastChannel) before navigating; dialog suppresses the closed-reject for that key and waits for the resume handoff. No third popup anywhere (IdP self-navigates), so no grandchild-popup-block. browserid-ng 395bef3 (dialog + e2e), bridge device-authorize.html + routes.rs. Desktop popup path fixed; mobile uses redirect fallback (RP watch+request). Diagnostic build removed.
