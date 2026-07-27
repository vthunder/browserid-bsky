//! atproto identity resolution: handle → DID → DID document → PDS.
//!
//! This is the first half of the proof chain, and the half an attacker
//! attacks. Two rules carry the weight:
//!
//! 1. **DNS wins on conflict.** `_atproto.<handle>` TXT and
//!    `https://<handle>/.well-known/atproto-did` are queried in parallel;
//!    if they disagree, the DNS answer is authoritative.
//! 2. **The bidirectional check is mandatory.** The DID document's
//!    `alsoKnownAs` must claim the handle back. Without it, anyone who can
//!    publish a TXT record under a domain can point it at *someone else's*
//!    DID and claim their identity — the forward direction alone proves
//!    nothing about who owns the DID.
//!
//! Resolution results are cached for [`RESOLVE_CACHE_SECONDS`], the
//! sub-10-minute bound the spec sets for auth-critical paths. The cache is
//! also the graceful-degradation path: when resolution is *down* (as
//! opposed to *contradictory*), the mint falls back to a cached binding
//! rather than locking everyone out — the same philosophy as status-list
//! staleness.

use std::collections::HashMap;
use std::sync::Mutex;

use chrono::{DateTime, Duration, Utc};

use super::{IdpError, IdpState, RESOLVE_CACHE_SECONDS};

/// A handle↔DID binding that passed the bidirectional check, plus where the
/// DID's repo lives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    pub handle: String,
    pub did: String,
    /// The `#atproto_pds` service endpoint from the DID document.
    pub pds: String,
    pub resolved_at: DateTime<Utc>,
}

/// Recently-resolved bindings, keyed by handle.
#[derive(Default)]
pub struct ResolveCache(Mutex<HashMap<String, Resolved>>);

impl ResolveCache {
    /// A binding resolved within `max_age_seconds`, if we have one.
    pub fn get_fresh(&self, handle: &str, max_age_seconds: i64) -> Option<Resolved> {
        let map = self.0.lock().unwrap();
        map.get(handle)
            .filter(|r| Utc::now() - r.resolved_at <= Duration::seconds(max_age_seconds))
            .cloned()
    }

    /// The outage fallback: a cached binding, still bounded by
    /// `max_age_seconds`. Callers must reach for this only when resolution
    /// *failed*, never when it succeeded and disagreed — and the bound is
    /// what keeps the Assurance cadence's promise, that no auth decision
    /// rests on a binding older than [`RESOLVE_CACHE_SECONDS`]. Past that,
    /// an outage fails closed.
    ///
    /// Note the consequence of the bound equalling [`RESOLVE_CACHE_SECONDS`]:
    /// the outage window is narrow by construction, because anything inside
    /// it would already have been served by `get_fresh`. That is the
    /// intended trade — the cadence bound wins over availability.
    pub fn get_stale(&self, handle: &str, max_age_seconds: i64) -> Option<Resolved> {
        self.get_fresh(handle, max_age_seconds)
    }

    pub fn put(&self, r: Resolved) {
        self.0.lock().unwrap().insert(r.handle.clone(), r);
    }
}

/// Normalize a user-typed handle: lowercase, strip a leading `@` and any
/// `at://` prefix. atproto handles are canonically lowercase, which is what
/// makes them safe as browserid local parts (the stores lowercase identity
/// strings globally).
pub fn normalize_handle(raw: &str) -> Result<String, IdpError> {
    let h = raw
        .trim()
        .trim_start_matches("at://")
        .trim_start_matches('@')
        .trim_end_matches('.')
        .to_lowercase();
    if h.is_empty() || h.len() > 253 {
        return Err(IdpError::BadRequest("that does not look like a handle".into()));
    }
    // A handle is a domain name: at least one dot, DNS label charset. This
    // also keeps `+` out, which matters because `<handle>+tag@D` is how
    // agent sub-identities are formed — a handle containing `+` would let
    // someone claim an identity that parses as another handle's agent.
    if !h.contains('.') {
        return Err(IdpError::BadRequest("a handle must be a domain name".into()));
    }
    let label_ok = |l: &str| {
        !l.is_empty()
            && l.len() <= 63
            && !l.starts_with('-')
            && !l.ends_with('-')
            && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    };
    if !h.split('.').all(label_ok) {
        return Err(IdpError::BadRequest("that does not look like a handle".into()));
    }
    Ok(h)
}

/// Is this string a DID rather than a handle? Used by the voluntary
/// retirement path, where the user authenticates with the *pinned DID* as
/// the account identifier to release a binding they still control.
pub fn is_did(s: &str) -> bool {
    s.starts_with("did:") && s.split(':').count() >= 3
}

/// Resolve `handle` to a DID, verifying the binding in both directions.
///
/// Returns the DID and its PDS endpoint. Fails when either direction is
/// missing — a forward-only answer is exactly the impersonation case.
pub async fn resolve_handle(
    st: &IdpState,
    http: &reqwest::Client,
    handle: &str,
) -> Result<Resolved, IdpError> {
    let handle = normalize_handle(handle)?;

    // Forward: both lookups in parallel, DNS authoritative on conflict.
    let (dns, well_known) =
        tokio::join!(dns_atproto_did(st, http, &handle), well_known_atproto_did(http, &handle));
    let did = match (dns, well_known) {
        (Some(d), Some(w)) => {
            if d != w {
                tracing::warn!(%handle, dns = %d, well_known = %w, "handle DID conflict — DNS wins");
            }
            d
        }
        (Some(d), None) => d,
        (None, Some(w)) => w,
        (None, None) => {
            return Err(IdpError::BadRequest(format!(
                "{handle} does not resolve to an atproto account — check the handle, \
                 or that its DNS/well-known record is published"
            )))
        }
    };

    finish_resolution(http, handle, did).await
}

/// Resolve starting from a DID instead of a handle (the retirement path).
/// The bidirectional check still applies, but rooted the other way: we read
/// the handle out of `alsoKnownAs` and confirm it points back at this DID.
pub async fn resolve_did(
    st: &IdpState,
    http: &reqwest::Client,
    did: &str,
) -> Result<Resolved, IdpError> {
    let doc = did_document(http, did).await?;
    let handle = also_known_as_handle(&doc).ok_or_else(|| {
        IdpError::BadRequest(format!("{did} declares no handle in its DID document"))
    })?;
    // Forward-verify the handle the document claims, so a DID that lies
    // about its handle cannot retire someone else's binding.
    let forward = resolve_handle(st, http, &handle).await?;
    if forward.did != did {
        return Err(IdpError::BadRequest(format!(
            "{handle} resolves to {}, not {did}",
            forward.did
        )));
    }
    Ok(forward)
}

/// Shared tail of both entry points: fetch the DID document, run the
/// bidirectional check, extract the PDS.
async fn finish_resolution(
    http: &reqwest::Client,
    handle: String,
    did: String,
) -> Result<Resolved, IdpError> {
    let doc = did_document(http, &did).await?;

    // THE bidirectional check. `handle.invalid` is the atproto ecosystem's
    // own sentinel for this failure, and we surface the same state.
    if !claims_handle(&doc, &handle) {
        return Err(IdpError::BadRequest(format!(
            "{handle} points at {did}, but that account does not claim the handle back \
             (handle.invalid) — the binding is not verifiable"
        )));
    }

    let pds = pds_endpoint(&doc).ok_or_else(|| {
        IdpError::BadRequest(format!("{did} publishes no atproto PDS in its DID document"))
    })?;

    Ok(Resolved { handle, did, pds, resolved_at: Utc::now() })
}

/// `_atproto.<handle>` TXT via DNS-over-HTTPS, returning the `did=` value.
/// Any transport failure is `None` (the well-known answer may still carry
/// the day); only a *contradiction* between the two is interesting.
async fn dns_atproto_did(st: &IdpState, http: &reqwest::Client, handle: &str) -> Option<String> {
    let resp = http
        .get(&st.doh_url)
        .query(&[("name", format!("_atproto.{handle}")), ("type", "TXT".into())])
        .header("accept", "application/dns-json")
        .send()
        .await
        .ok()?;
    let body: serde_json::Value = resp.json().await.ok()?;
    body.get("Answer")?
        .as_array()?
        .iter()
        .filter_map(|a| a.get("data")?.as_str())
        // DoH JSON returns TXT data quoted, and long records chunked.
        .map(|d| d.replace(['"', '\\'], "").replace(' ', ""))
        .find_map(|d| d.strip_prefix("did=").map(str::to_string))
        .filter(|d| is_did(d))
}

/// `https://<handle>/.well-known/atproto-did` — the plain-text DID.
async fn well_known_atproto_did(_http: &reqwest::Client, handle: &str) -> Option<String> {
    // The handle is user-supplied, so this URL is externally named: it goes
    // through the guard, on the no-redirect client, every hop checked.
    let url = format!("https://{handle}/.well-known/atproto-did");
    let resp = super::net::get_guarded(&url).await.ok()?.error_for_status().ok()?;
    let body = resp.text().await.ok()?;
    let did = body.trim().to_string();
    is_did(&did).then_some(did)
}

/// Fetch a DID document. `did:plc` resolves at the PLC directory,
/// `did:web` at the host's `/.well-known/did.json`; anything else is
/// out of scope (and, per the design's non-goals, DID local parts stay out
/// of identity strings precisely because other methods are case-sensitive).
pub async fn did_document(http: &reqwest::Client, did: &str) -> Result<serde_json::Value, IdpError> {
    // `did:web` names its own host, so that URL runs the SSRF guard; the
    // PLC directory is our own configuration, not attacker-chosen.
    let mut externally_named = false;
    let url = if let Some(rest) = did.strip_prefix("did:plc:") {
        let directory = std::env::var("IDP_PLC_DIRECTORY")
            .unwrap_or_else(|_| "https://plc.directory".to_string());
        if rest.is_empty() || !rest.chars().all(|c| c.is_ascii_alphanumeric()) {
            return Err(IdpError::BadRequest(format!("malformed DID: {did}")));
        }
        format!("{directory}/{did}")
    } else if let Some(host) = did.strip_prefix("did:web:") {
        // did:web hosts are percent-encoded and `:`-separated for paths;
        // atproto only uses the bare-host form.
        if host.is_empty() || host.contains(':') || host.contains('/') {
            return Err(IdpError::BadRequest(format!("unsupported did:web form: {did}")));
        }
        externally_named = true;
        format!("https://{host}/.well-known/did.json")
    } else {
        return Err(IdpError::BadRequest(format!(
            "unsupported DID method: {did} (did:plc and did:web only)"
        )));
    };

    let resp = if externally_named {
        super::net::get_guarded(&url).await?
    } else {
        http.get(&url).send().await.map_err(|e| {
            // The transport error is a reachability oracle — log, don't echo.
            tracing::warn!(%did, "could not fetch the DID document: {e}");
            IdpError::BadRequest("could not fetch the DID document".into())
        })?
    };
    if !resp.status().is_success() {
        return Err(IdpError::BadRequest(format!(
            "DID document for {did}: HTTP {}",
            resp.status()
        )));
    }
    resp.json()
        .await
        .map_err(|e| IdpError::BadRequest(format!("malformed DID document for {did}: {e}")))
}

/// Does this DID document claim `handle` via `alsoKnownAs: at://<handle>`?
pub fn claims_handle(doc: &serde_json::Value, handle: &str) -> bool {
    let want = format!("at://{handle}");
    doc.get("alsoKnownAs")
        .and_then(|a| a.as_array())
        .is_some_and(|aka| {
            aka.iter()
                .filter_map(|v| v.as_str())
                .any(|v| v.trim_end_matches('/').eq_ignore_ascii_case(&want))
        })
}

/// The first handle a DID document claims, normalized (`at://dan.bsky.social`
/// → `dan.bsky.social`).
pub fn also_known_as_handle(doc: &serde_json::Value) -> Option<String> {
    doc.get("alsoKnownAs")?
        .as_array()?
        .iter()
        .filter_map(|v| v.as_str())
        .find_map(|v| v.strip_prefix("at://"))
        .map(|h| h.trim_end_matches('/').to_lowercase())
}

/// The `#atproto_pds` service endpoint.
pub fn pds_endpoint(doc: &serde_json::Value) -> Option<String> {
    doc.get("service")?.as_array()?.iter().find_map(|s| {
        let id = s.get("id")?.as_str()?;
        let ty = s.get("type")?.as_str()?;
        (id.ends_with("#atproto_pds") && ty == "AtprotoPersonalDataServer")
            .then(|| s.get("serviceEndpoint")?.as_str().map(|e| e.trim_end_matches('/').to_string()))
            .flatten()
    })
}

/// Resolve `handle` for an auth-critical decision, preferring a cache
/// entry younger than [`RESOLVE_CACHE_SECONDS`].
///
/// `allow_stale_on_outage` is the mint's degradation switch: when the
/// network answer cannot be obtained at all, fall back to whatever binding
/// we last saw rather than failing every login. A *successful* resolution
/// that contradicts the pin is never softened this way.
pub async fn resolve_for_assurance(
    st: &IdpState,
    http: &reqwest::Client,
    handle: &str,
    allow_stale_on_outage: bool,
) -> Result<Resolved, IdpError> {
    let handle = normalize_handle(handle)?;
    if let Some(hit) = st.resolve_cache.get_fresh(&handle, RESOLVE_CACHE_SECONDS) {
        return Ok(hit);
    }
    match resolve_handle(st, http, &handle).await {
        Ok(r) => {
            st.resolve_cache.put(r.clone());
            Ok(r)
        }
        Err(e) if allow_stale_on_outage => match st
            .resolve_cache
            .get_stale(&handle, RESOLVE_CACHE_SECONDS)
        {
            Some(stale) => {
                tracing::warn!(%handle, "resolution failed ({e}); falling back to the cached binding");
                Ok(stale)
            }
            None => Err(e),
        },
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn handles_normalize_and_reject_non_domains() {
        assert_eq!(normalize_handle("  @Dan.BSky.Social ").unwrap(), "dan.bsky.social");
        assert_eq!(normalize_handle("at://dan.bsky.social").unwrap(), "dan.bsky.social");
        assert_eq!(normalize_handle("dan.bsky.social.").unwrap(), "dan.bsky.social");
        // A bare label is not a handle.
        assert!(normalize_handle("dan").is_err());
        assert!(normalize_handle("").is_err());
        // `+` must never survive: `<handle>+tag@D` is the agent sub-identity
        // form, so a handle containing `+` could impersonate one.
        assert!(normalize_handle("dan+agent.bsky.social").is_err());
        assert!(normalize_handle("has space.com").is_err());
    }

    #[test]
    fn did_detection() {
        assert!(is_did("did:plc:abc123"));
        assert!(is_did("did:web:example.com"));
        assert!(!is_did("dan.bsky.social"));
        assert!(!is_did("did:plc"));
    }

    #[test]
    fn bidirectional_check_requires_the_handle_back() {
        let doc = json!({ "alsoKnownAs": ["at://dan.bsky.social"] });
        assert!(claims_handle(&doc, "dan.bsky.social"));
        // The attack this check exists to stop: a domain pointed at someone
        // else's DID. The DID never claims the attacker's handle back.
        assert!(!claims_handle(&doc, "evil.example.com"));
        // No alsoKnownAs at all is a failure, not a pass.
        assert!(!claims_handle(&json!({}), "dan.bsky.social"));
        assert!(!claims_handle(&json!({ "alsoKnownAs": [] }), "dan.bsky.social"));
    }

    #[test]
    fn reads_the_pds_and_handle_out_of_a_did_document() {
        let doc = json!({
            "id": "did:plc:abc",
            "alsoKnownAs": ["at://dan.bsky.social"],
            "service": [
                { "id": "#atproto_labeler", "type": "AtprotoLabeler", "serviceEndpoint": "https://l.example" },
                { "id": "#atproto_pds", "type": "AtprotoPersonalDataServer", "serviceEndpoint": "https://pds.example/" }
            ]
        });
        assert_eq!(pds_endpoint(&doc).unwrap(), "https://pds.example");
        assert_eq!(also_known_as_handle(&doc).unwrap(), "dan.bsky.social");
        // A document with no PDS service yields nothing — resolution fails
        // rather than guessing an endpoint.
        assert_eq!(pds_endpoint(&json!({ "service": [] })), None);
    }

    #[test]
    fn cache_respects_freshness_but_keeps_the_stale_entry() {
        let cache = ResolveCache::default();
        cache.put(Resolved {
            handle: "dan.bsky.social".into(),
            did: "did:plc:abc".into(),
            pds: "https://pds.example".into(),
            resolved_at: Utc::now() - Duration::seconds(RESOLVE_CACHE_SECONDS + 60),
        });
        // Too old for an auth-critical decision…
        assert!(cache.get_fresh("dan.bsky.social", RESOLVE_CACHE_SECONDS).is_none());
        // …and, past the same bound, not available as the outage fallback
        // either: a resolution outage fails closed rather than resting an
        // auth decision on an unbounded-age binding.
        assert!(cache.get_stale("dan.bsky.social", RESOLVE_CACHE_SECONDS).is_none());
    }

    /// Finding #5: the outage fallback is age-bounded. The Assurance cadence
    /// promises no auth decision rests on a binding older than
    /// [`RESOLVE_CACHE_SECONDS`], so a resolution outage past that fails
    /// closed rather than honouring an arbitrarily old cache entry.
    #[test]
    fn the_outage_fallback_is_bounded_to_the_cadence() {
        let entry = |age_minutes: i64| Resolved {
            handle: "dan.bsky.social".into(),
            did: "did:plc:abc".into(),
            pds: "https://pds.example".into(),
            resolved_at: Utc::now() - Duration::minutes(age_minutes),
        };

        let cache = ResolveCache::default();
        cache.put(entry(5));
        assert!(cache.get_stale("dan.bsky.social", RESOLVE_CACHE_SECONDS).is_some());

        cache.put(entry(20));
        assert!(cache.get_stale("dan.bsky.social", RESOLVE_CACHE_SECONDS).is_none());
    }
}
