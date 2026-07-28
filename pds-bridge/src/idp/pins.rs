//! DID pinning: the identity's real anchor.
//!
//! Handles are mutable pointers; DIDs are the stable identifier. The failure
//! this module exists to prevent: handle `H` is released by DID `A`, later
//! acquired by DID `B`, and because `<H>@bsky.browserid.me` is keyed on the
//! handle, `B` silently inherits `A`'s browserid identity — every warrant,
//! every grant, every badge that ever said "on behalf of H".
//!
//! So the first claim records `(handle, did)` and every later issuance must
//! match it. A mismatch **suspends** the binding: no new certs, and the
//! outstanding ones are revoked through D's status list so they die in
//! minutes rather than at cert TTL.
//!
//! Getting the identity back is deliberately slow in one direction and
//! instant in the other:
//!
//! * **Seasoning** ([`REASSIGNMENT_SEASONING_DAYS`]) — a new DID that wants
//!   `H` has its first attempt recorded and refused. Only once the handle
//!   has *continuously* resolved to it for 30 days is the pin replaced. The
//!   clock starts at the first refused attempt, so squatting a briefly-lapsed
//!   handle buys nothing.
//! Wherever a binding dies — suspended, reassigned, or retired — its
//! write-relay session (bean ru7u) dies with it. A suspended identity that
//! left a live OAuth token behind would leave the bridge able to post as an
//! account it no longer certifies.
//!
//! * **Voluntary retirement** — the old owner authenticates with the pinned
//!   DID itself (atproto OAuth accepts a DID as the account identifier) and
//!   releases the binding immediately. A graceful rename therefore never
//!   waits, and the only people stuck behind the 30 days are the ones who
//!   cannot prove they were ever the previous owner.

use chrono::{DateTime, Duration, Utc};

use super::{IdpError, REASSIGNMENT_SEASONING_DAYS};
use crate::store::{HandlePin, Store};

/// What a claim attempt did to the pin table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimOutcome {
    /// No pin existed; the handle is now bound to this DID.
    FirstClaim,
    /// The pin already named this DID — the ordinary re-auth path.
    Confirmed,
    /// A previously suspended binding was reassigned to this DID after the
    /// seasoning period elapsed.
    Seasoned,
}

/// Decide what a claim of `handle` by `did` should do, given the current
/// pin and (for a contested handle) when this DID first tried.
///
/// Pure, so the policy is testable without a database and without waiting
/// 30 days: `now` and `first_seen` are parameters.
pub fn decide(
    pin: Option<&HandlePin>,
    did: &str,
    first_seen: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
) -> Result<ClaimOutcome, IdpError> {
    let Some(pin) = pin else {
        return Ok(ClaimOutcome::FirstClaim);
    };
    if pin.did == did {
        return Ok(ClaimOutcome::Confirmed);
    }
    // Contested. The caller has already verified — bidirectionally, freshly
    // — that the handle really does resolve to `did` right now; what is
    // missing is *duration*.
    let seasoning = Duration::days(REASSIGNMENT_SEASONING_DAYS);
    let first_seen = first_seen.unwrap_or(now);
    if now - first_seen >= seasoning {
        return Ok(ClaimOutcome::Seasoned);
    }
    let available = first_seen + seasoning;
    Err(IdpError::BindingSuspended(format!(
        "{} was previously claimed by a different account ({}). It can be re-claimed on {} \
         if it still resolves to this account then. To release it sooner, sign in with the \
         previous account — the one that owns {} — and retire the binding.",
        pin.handle,
        pin.did,
        available.format("%-d %B %Y"),
        pin.did,
    )))
}

/// Apply [`decide`] against the store, recording the seasoning clock and
/// suspending a contested binding.
///
/// `did` must have been freshly, bidirectionally verified as the current
/// holder of `handle` before this is called — the pin table records
/// *duration of possession*, and it can only do that if every sample it
/// takes is a real one.
pub fn claim(store: &Store, handle: &str, did: &str) -> Result<ClaimOutcome, IdpError> {
    let now = Utc::now();
    let pin = store.idp_pin(handle)?;

    // For a contested handle the attempt itself is the sample: record it
    // (idempotently) before deciding, so the clock starts on the first try.
    let first_seen = match &pin {
        Some(p) if p.did != did => Some(store.idp_note_reassignment_attempt(handle, did, now)?),
        _ => None,
    };

    match decide(pin.as_ref(), did, first_seen, now) {
        Ok(outcome) => {
            if outcome == ClaimOutcome::Seasoned {
                // The old owner's certs must not outlive the reassignment —
                // and neither may their write-relay session, or the bridge
                // would still hold posting credentials for an account that
                // no longer owns this identity.
                store.idp_revoke_status_for_handle(handle)?;
                store.write_session_delete_for_handle(handle)?;
            }
            store.idp_upsert_pin(handle, did, now)?;
            store.idp_clear_reassignment_attempts(handle)?;
            Ok(outcome)
        }
        Err(e) => {
            // Fail closed AND fail loudly: the contested binding stops
            // issuing, its live certs are revoked via the status list, and
            // any write-relay session it had is deleted.
            store.idp_set_pin_suspended(handle, true)?;
            store.idp_revoke_status_for_handle(handle)?;
            store.write_session_delete_for_handle(handle)?;
            Err(e)
        }
    }
}

/// Confirm that `did` still holds `handle` at mint time.
///
/// This is the [assurance cadence](super) in one function: the caller has
/// just re-resolved the public binding, and here we check it against the
/// pin. A mismatch is not a retryable error — it means the handle moved, so
/// the binding is suspended and its certs revoked on the spot.
pub fn verify_still_bound(store: &Store, handle: &str, resolved_did: &str) -> Result<(), IdpError> {
    let pin = store.idp_pin(handle)?.ok_or_else(|| {
        IdpError::Forbidden
    })?;
    if pin.suspended {
        return Err(IdpError::BindingSuspended(format!(
            "the binding for {handle} is suspended — the handle no longer resolves to the \
             account it was claimed with"
        )));
    }
    if pin.did != resolved_did {
        store.idp_set_pin_suspended(handle, true)?;
        store.idp_revoke_status_for_handle(handle)?;
        store.write_session_delete_for_handle(handle)?;
        tracing::warn!(
            %handle, pinned = %pin.did, resolved = %resolved_did,
            "handle moved to a different DID — binding suspended, certs revoked"
        );
        return Err(IdpError::BindingSuspended(format!(
            "{handle} now resolves to a different account than the one it was claimed with; \
             the identity is suspended"
        )));
    }
    store.idp_touch_pin(handle)?;
    Ok(())
}

/// Voluntary retirement: release every binding pinned to `did`.
///
/// Called after an OAuth login where the *DID itself* was the account
/// identifier, which is the only proof that matters here — whoever controls
/// the pinned DID controls the binding, whatever the handle points at now.
pub fn retire_for_did(store: &Store, did: &str) -> Result<Vec<String>, IdpError> {
    let handles = store.idp_pins_for_did(did)?;
    for handle in &handles {
        store.idp_revoke_status_for_handle(handle)?;
        store.write_session_delete_for_handle(handle)?;
        store.idp_delete_pin(handle)?;
        store.idp_clear_reassignment_attempts(handle)?;
    }
    Ok(handles)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pin(handle: &str, did: &str) -> HandlePin {
        HandlePin {
            handle: handle.into(),
            did: did.into(),
            first_claimed: Utc::now(),
            last_verified: Utc::now(),
            suspended: false,
        }
    }

    #[test]
    fn an_unclaimed_handle_is_a_first_claim() {
        assert_eq!(decide(None, "did:plc:a", None, Utc::now()).unwrap(), ClaimOutcome::FirstClaim);
    }

    #[test]
    fn the_same_did_reauthenticating_is_confirmed() {
        let p = pin("dan.bsky.social", "did:plc:a");
        assert_eq!(
            decide(Some(&p), "did:plc:a", None, Utc::now()).unwrap(),
            ClaimOutcome::Confirmed
        );
    }

    #[test]
    fn a_different_did_is_refused_until_the_handle_has_seasoned() {
        let now = Utc::now();
        let p = pin("dan.bsky.social", "did:plc:a");

        // First attempt: refused, and the clock starts now.
        let err = decide(Some(&p), "did:plc:b", Some(now), now).unwrap_err();
        assert!(matches!(err, IdpError::BindingSuspended(_)));
        // The refusal names the old DID, so a legitimate owner knows which
        // account to sign in with to retire it early.
        assert!(err.to_string().contains("did:plc:a"), "{err}");

        // One day short: still refused. This is the squatting case.
        let almost = now + Duration::days(REASSIGNMENT_SEASONING_DAYS) - Duration::hours(1);
        assert!(decide(Some(&p), "did:plc:b", Some(now), almost).is_err());

        // Seasoned: the handle has resolved to B for the full period.
        let after = now + Duration::days(REASSIGNMENT_SEASONING_DAYS);
        assert_eq!(
            decide(Some(&p), "did:plc:b", Some(now), after).unwrap(),
            ClaimOutcome::Seasoned
        );
    }

    #[test]
    fn seasoning_is_measured_from_the_first_attempt_not_the_latest() {
        // Someone who tried 30 days ago and comes back today wins; someone
        // who first tries today does not, no matter how old the pin is.
        let long_ago = Utc::now() - Duration::days(REASSIGNMENT_SEASONING_DAYS + 5);
        let p = pin("dan.bsky.social", "did:plc:a");
        assert_eq!(
            decide(Some(&p), "did:plc:b", Some(long_ago), Utc::now()).unwrap(),
            ClaimOutcome::Seasoned
        );
        assert!(decide(Some(&p), "did:plc:c", None, Utc::now()).is_err());
    }

    #[test]
    fn store_backed_claim_suspends_then_seasons() {
        let store = Store::open_in_memory().unwrap();
        assert_eq!(claim(&store, "dan.bsky.social", "did:plc:a").unwrap(), ClaimOutcome::FirstClaim);
        assert_eq!(claim(&store, "dan.bsky.social", "did:plc:a").unwrap(), ClaimOutcome::Confirmed);

        // A different DID is refused and the binding suspends.
        assert!(claim(&store, "dan.bsky.social", "did:plc:b").is_err());
        assert!(store.idp_pin("dan.bsky.social").unwrap().unwrap().suspended);
        // The pin still names the original owner — a refused claim must
        // never move it.
        assert_eq!(store.idp_pin("dan.bsky.social").unwrap().unwrap().did, "did:plc:a");

        // Backdate the attempt to simulate 30 days of continuous holding.
        store
            .idp_backdate_reassignment_attempt(
                "dan.bsky.social",
                "did:plc:b",
                Utc::now() - Duration::days(REASSIGNMENT_SEASONING_DAYS + 1),
            )
            .unwrap();
        assert_eq!(claim(&store, "dan.bsky.social", "did:plc:b").unwrap(), ClaimOutcome::Seasoned);
        let after = store.idp_pin("dan.bsky.social").unwrap().unwrap();
        assert_eq!(after.did, "did:plc:b");
        assert!(!after.suspended, "a seasoned reassignment clears the suspension");
    }

    #[test]
    fn mint_verification_refuses_a_moved_handle_and_suspends_it() {
        let store = Store::open_in_memory().unwrap();
        claim(&store, "dan.bsky.social", "did:plc:a").unwrap();
        let idx = store.idp_status_idx("dan.bsky.social@bsky.browserid.test").unwrap();

        // Still bound: fine, and nothing is revoked.
        verify_still_bound(&store, "dan.bsky.social", "did:plc:a").unwrap();
        assert!(!store.idp_revoked_status_indices().unwrap().0.contains(&idx));

        // Moved: refused, suspended, and the outstanding cert is revoked so
        // it dies in status-list time rather than at its TTL.
        let err = verify_still_bound(&store, "dan.bsky.social", "did:plc:b").unwrap_err();
        assert!(matches!(err, IdpError::BindingSuspended(_)));
        assert!(store.idp_pin("dan.bsky.social").unwrap().unwrap().suspended);
        assert!(store.idp_revoked_status_indices().unwrap().0.contains(&idx));

        // And it stays refused even if the handle resolves correctly again:
        // the suspension is sticky until explicitly resolved.
        assert!(verify_still_bound(&store, "dan.bsky.social", "did:plc:a").is_err());
    }

    #[test]
    fn retirement_releases_the_binding_immediately() {
        let store = Store::open_in_memory().unwrap();
        claim(&store, "dan.bsky.social", "did:plc:a").unwrap();
        let idx = store.idp_status_idx("dan.bsky.social@bsky.browserid.test").unwrap();

        let retired = retire_for_did(&store, "did:plc:a").unwrap();
        assert_eq!(retired, vec!["dan.bsky.social".to_string()]);
        assert!(store.idp_pin("dan.bsky.social").unwrap().is_none());
        assert!(store.idp_revoked_status_indices().unwrap().0.contains(&idx));

        // The point of retiring: a rename is now instant for the new owner,
        // with no 30-day wait.
        assert_eq!(claim(&store, "dan.bsky.social", "did:plc:b").unwrap(), ClaimOutcome::FirstClaim);
    }
}
