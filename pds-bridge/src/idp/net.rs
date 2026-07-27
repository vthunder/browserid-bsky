//! The SSRF guard for externally-named URLs.
//!
//! Resolution hands us URLs an attacker chose: a `did:web` host, a DID
//! document's `serviceEndpoint`, a PDS's `authorization_servers[0]`, and
//! every endpoint the metadata at that issuer names. The bridge runs next
//! to an internal PDS on a private network, so fetching those blind turns
//! the IdP into a port scanner with a signed oracle attached.
//!
//! Every such fetch goes through [`guard_external_url`] first, which
//! enforces three things:
//!
//! 1. the scheme is `https` — no `http`, no `file:`, no `gopher:`;
//! 2. a literal host is not in a private/loopback/link-local range;
//! 3. *no* address the host resolves to is in those ranges, which is what
//!    catches a public name pointed at `127.0.0.1`.
//!
//! The failure is always the same opaque message: the transport error is
//! logged, never returned, so the caller cannot read reachability out of
//! the difference between "connection refused" and "timed out".
//!
//! Guarding the URL is only half of it: reqwest's default policy follows up
//! to ten redirects, and a redirect is a *new* URL nobody checked — a public
//! host can 302 straight to `127.0.0.1` and walk through the guard. So these
//! fetches run on a dedicated client with redirects disabled
//! ([`guarded_client`]) and follow hops themselves via [`get_guarded`],
//! re-running the guard on every `Location`. The shared client keeps its
//! normal redirect behaviour for everything else the bridge does.
//!
//! Residual risk, accepted for v1: this resolves and then reqwest resolves
//! again when it connects, so a DNS answer that flips between the two
//! (rebinding) still reaches an internal address. Closing it needs
//! connection-level pinning (resolve once, dial the checked IP, carry the
//! SNI/Host) — deliberately out of scope here.

use std::net::IpAddr;
use std::sync::OnceLock;

use super::IdpError;

/// How many `Location` hops a guarded fetch will follow. Each one is
/// guarded; a redirect past the cap is treated as unreachable, same as any
/// other refusal.
const MAX_HOPS: usize = 3;

/// What every guard rejection says to the caller. Deliberately identical
/// for "bad scheme", "private address" and "DNS failed": the caller learns
/// only that we would not or could not reach it.
fn refused() -> IdpError {
    IdpError::BadRequest("could not reach the handle's service".into())
}

/// Is this address one we refuse to have the server reach?
///
/// v4: loopback (127/8), private (10/8, 172.16/12, 192.168/16), link-local
/// (169.254/16), "this network" (0/8), CGNAT (100.64/10), broadcast,
/// multicast. v6: `::1`, `::`, ULA (fc00::/7), link-local (fe80::/10),
/// multicast — and v4-mapped forms are judged as their v4 address.
pub fn is_blocked_addr(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_unspecified()
                || o[0] == 0
                || (o[0] == 100 && (64..128).contains(&o[1]))
        }
        IpAddr::V6(v6) => {
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return is_blocked_addr(IpAddr::V4(mapped));
            }
            let seg = v6.segments();
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (seg[0] & 0xfe00) == 0xfc00
                || (seg[0] & 0xffc0) == 0xfe80
        }
    }
}

/// Scheme and literal-host checks — everything decidable without DNS.
/// Returns the host and the port to resolve.
pub fn check_url_shape(raw: &str) -> Result<(String, u16), IdpError> {
    let url = reqwest::Url::parse(raw).map_err(|e| {
        tracing::warn!(url = %raw, "refusing an externally-named URL: {e}");
        refused()
    })?;
    if url.scheme() != "https" {
        tracing::warn!(url = %raw, scheme = url.scheme(), "refusing a non-https external URL");
        return Err(refused());
    }
    let host = url.host_str().ok_or_else(|| {
        tracing::warn!(url = %raw, "refusing an external URL with no host");
        refused()
    })?;
    // `host_str` keeps the brackets on an IPv6 literal; the parser doesn't
    // want them.
    let literal = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = literal.parse::<IpAddr>() {
        if is_blocked_addr(ip) {
            tracing::warn!(url = %raw, %ip, "refusing an external URL naming an internal address");
            return Err(refused());
        }
    }
    Ok((literal.to_string(), url.port_or_known_default().unwrap_or(443)))
}

/// The post-resolution half: reject if *any* answer is internal. Any is
/// the right quantifier — a host that returns both a public and a private
/// address must not be reachable by retry.
pub fn check_addrs(url: &str, addrs: &[IpAddr]) -> Result<(), IdpError> {
    if addrs.is_empty() {
        tracing::warn!(%url, "refusing an external URL that resolves to nothing");
        return Err(refused());
    }
    if let Some(bad) = addrs.iter().find(|a| is_blocked_addr(**a)) {
        tracing::warn!(%url, ip = %bad, "refusing an external URL resolving to an internal address");
        return Err(refused());
    }
    Ok(())
}

/// Run the whole guard: shape, then real DNS. Call this before every
/// outbound fetch of a URL that a DID document, a handle, or an
/// authorization server named. Do *not* call it on the bridge's own
/// origin — our status list and our own PDS are legitimately local.
pub async fn guard_external_url(raw: &str) -> Result<(), IdpError> {
    let (host, port) = check_url_shape(raw)?;
    let addrs: Vec<IpAddr> = match tokio::net::lookup_host((host.as_str(), port)).await {
        Ok(it) => it.map(|s| s.ip()).collect(),
        Err(e) => {
            tracing::warn!(url = %raw, "could not resolve an external URL: {e}");
            return Err(refused());
        }
    };
    check_addrs(raw, &addrs)
}

/// The client every externally-named fetch uses: redirects disabled, so a
/// hop can never happen behind the guard's back. Separate from the bridge's
/// shared client, which legitimately follows redirects elsewhere.
pub fn guarded_client() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .expect("failed to build the guarded HTTP client")
    })
}

/// Fetch `url`, guarding it and every redirect it leads to.
///
/// Both the guard and the transport are parameters, so the hop logic can be
/// driven by stubs without touching the network. Callers want
/// [`get_guarded`].
pub async fn follow_hops<G, GFut, F, Fut>(
    url: &str,
    guard: G,
    fetch: F,
) -> Result<reqwest::Response, IdpError>
where
    G: Fn(String) -> GFut,
    GFut: std::future::Future<Output = Result<(), IdpError>>,
    F: Fn(String) -> Fut,
    Fut: std::future::Future<Output = reqwest::Result<reqwest::Response>>,
{
    let mut current = url.to_string();
    for _ in 0..=MAX_HOPS {
        guard(current.clone()).await?;
        let resp = fetch(current.clone()).await.map_err(|e| {
            tracing::warn!(url = %current, "guarded fetch failed: {e}");
            refused()
        })?;
        if !resp.status().is_redirection() {
            return Ok(resp);
        }
        // A redirect is a URL nobody has checked yet. Resolve it against the
        // hop it came from (`Location` may be relative) and go round again —
        // the loop head guards it before it is fetched.
        let location = resp
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| {
                tracing::warn!(url = %current, "redirect with no usable Location");
                refused()
            })?;
        current = reqwest::Url::parse(&current)
            .and_then(|base| base.join(location))
            .map_err(|e| {
                tracing::warn!(url = %current, "unresolvable redirect target: {e}");
                refused()
            })?
            .to_string();
    }
    tracing::warn!(%url, "refusing an external URL that redirects more than {MAX_HOPS} times");
    Err(refused())
}

/// The production form: the real guard over the no-redirect client.
pub async fn get_guarded(url: &str) -> Result<reqwest::Response, IdpError> {
    follow_hops(
        url,
        |u| async move { guard_external_url(&u).await },
        |u| guarded_client().get(u).send(),
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn internal_ranges_are_blocked_and_public_ones_are_not() {
        for s in [
            "127.0.0.1", "10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.1.1",
            "169.254.169.254", "0.0.0.0", "100.64.0.1", "::1", "::", "fc00::1", "fd12::5",
            "fe80::1", "::ffff:127.0.0.1",
        ] {
            assert!(is_blocked_addr(ip(s)), "{s} should be blocked");
        }
        for s in ["1.1.1.1", "8.8.8.8", "172.32.0.1", "2606:4700::1111"] {
            assert!(!is_blocked_addr(ip(s)), "{s} should be allowed");
        }
    }

    #[test]
    fn non_https_schemes_are_refused() {
        assert!(check_url_shape("http://example.com/x").is_err());
        assert!(check_url_shape("file:///etc/passwd").is_err());
        assert!(check_url_shape("not a url").is_err());
        assert!(check_url_shape("https://example.com/x").is_ok());
    }

    /// The direct form of the attack: a DID document naming an https URL
    /// whose host *is* an internal address literal.
    #[test]
    fn an_https_url_with_a_loopback_host_is_refused() {
        assert!(check_url_shape("https://127.0.0.1/.well-known/did.json").is_err());
        assert!(check_url_shape("https://[::1]/x").is_err());
        assert!(check_url_shape("https://192.168.0.9:8443/x").is_err());
        assert!(check_url_shape("https://169.254.169.254/latest/meta-data/").is_err());
    }

    /// The indirect form: a perfectly ordinary hostname that resolves to an
    /// internal address. Tested through the resolver seam rather than real
    /// DNS.
    #[test]
    fn a_hostname_resolving_to_a_private_address_is_refused() {
        assert!(check_addrs("https://evil.example/", &[ip("127.0.0.1")]).is_err());
        assert!(check_addrs("https://evil.example/", &[ip("93.184.216.34")]).is_ok());
        // One public answer does not launder a private one.
        assert!(
            check_addrs("https://evil.example/", &[ip("93.184.216.34"), ip("10.0.0.5")]).is_err()
        );
        assert!(check_addrs("https://evil.example/", &[]).is_err());
    }

    /// Finding #6: the transport error is a reachability oracle, so it is
    /// logged and never returned.
    #[test]
    fn the_refusal_never_carries_the_inner_error() {
        let msg = check_url_shape("http://10.0.0.1/x").unwrap_err().to_string();
        assert_eq!(msg, "could not reach the handle's service");
        let msg = check_addrs("https://x.example/", &[ip("10.0.0.1")]).unwrap_err().to_string();
        assert!(!msg.contains("10.0.0.1"), "{msg}");
        assert!(!msg.to_lowercase().contains("connect"), "{msg}");
    }

    /// The guard is per-hop, not per-call. reqwest's default policy follows
    /// redirects, so a public host that 302s to `127.0.0.1` would otherwise
    /// walk straight through a URL that passed the check.
    #[tokio::test]
    async fn a_redirect_to_an_internal_address_is_refused() {
        // Shape-only guard: the same policy minus the DNS lookup, so the hop
        // logic is exercised without the network.
        let guard = |u: String| async move { check_url_shape(&u).map(|_| ()) };
        let redirect_to = |loc: &'static str| {
            move |_url: String| async move {
                Ok(reqwest::Response::from(
                    axum::http::Response::builder()
                        .status(302)
                        .header("location", loc)
                        .body(String::new())
                        .unwrap(),
                ))
            }
        };

        // The first hop passes the guard; the address it redirects to does not.
        let err = follow_hops("https://pds.example/did.json", guard, redirect_to("http://127.0.0.1/"))
            .await
            .unwrap_err();
        assert_eq!(err.to_string(), "could not reach the handle's service");
        assert!(follow_hops(
            "https://pds.example/x",
            guard,
            redirect_to("https://169.254.169.254/")
        )
        .await
        .is_err());
        // Relative Locations resolve against the hop they came from, and are
        // guarded the same way.
        assert!(follow_hops("https://pds.example/x", guard, redirect_to("//127.0.0.1/y"))
            .await
            .is_err());

        // A chain that never terminates stops at the cap instead of running on.
        assert!(follow_hops("https://pds.example/x", guard, redirect_to("https://other.example/y"))
            .await
            .is_err());

        // A non-redirect answer is simply returned.
        let ok = follow_hops("https://pds.example/x", guard, |_| async {
            Ok(reqwest::Response::from(axum::http::Response::new(String::from("{}"))))
        })
        .await
        .unwrap();
        assert!(ok.status().is_success());
    }

    #[tokio::test]
    async fn the_full_guard_refuses_a_name_that_resolves_to_loopback() {
        // `localhost` is the canonical hostname-pointing-at-127.0.0.1.
        assert!(guard_external_url("https://localhost/.well-known/did.json").await.is_err());
    }
}
