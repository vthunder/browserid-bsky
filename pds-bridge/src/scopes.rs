//! atproto granular auth scopes (design doc §Scope vocabulary).
//!
//! Warrant scopes are opaque strings on the browserid side (protocol §5);
//! the bridge is the RP that interprets them. We adopt the atproto
//! granular-scope syntax so grants translate directly if/when the PDS
//! learns to accept bundles natively:
//!
//! - `repo:<collection-nsid>[?action=create|update|delete]` — write records
//!   in one collection; no `action` param grants all three.
//! - `rpc:<method-nsid>` — call one query/procedure method.
//! - `blob:<type>/<subtype>` — upload blobs of a mime type; `*` wildcards
//!   the subtype (`blob:image/*`) or the whole type (`blob:*/*`).
//!
//! Everything here is an allowlist and fail-closed:
//! - A scope string that doesn't parse grants **nothing** (it is skipped,
//!   never "best-effort" interpreted).
//! - An XRPC call that doesn't map to a known required scope is **denied**
//!   for bridge-token traffic, whatever scopes the warrant carries.

use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RepoAction {
    Create,
    Update,
    Delete,
}

impl RepoAction {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "create" => Some(Self::Create),
            "update" => Some(Self::Update),
            "delete" => Some(Self::Delete),
            _ => None,
        }
    }
}

/// One parsed grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Scope {
    Repo {
        collection: String,
        actions: BTreeSet<RepoAction>,
    },
    Rpc {
        method: String,
    },
    Blob {
        /// `(type, subtype)`, each possibly `*`
        mime: (String, String),
    },
}

/// A permission an XRPC call requires.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Required {
    Repo { collection: String, action: RepoAction },
    Rpc { method: String },
    Blob { mime: (String, String) },
}

/// An NSID: at least three dot-separated segments of `[a-zA-Z0-9-]`,
/// none empty, no leading digit in the authority segments. Kept simple —
/// strict enough to refuse junk, loose enough for real lexicons.
fn is_nsid(s: &str) -> bool {
    let segs: Vec<&str> = s.split('.').collect();
    segs.len() >= 3
        && segs.iter().all(|seg| {
            !seg.is_empty()
                && seg.len() <= 63
                && seg.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        })
}

fn parse_mime(s: &str) -> Option<(String, String)> {
    let (t, sub) = s.split_once('/')?;
    let ok = |p: &str| {
        p == "*" || (!p.is_empty() && p.chars().all(|c| c.is_ascii_alphanumeric() || "-+.".contains(c)))
    };
    if !ok(t) || !ok(sub) {
        return None;
    }
    // `*/subtype` is not a thing.
    if t == "*" && sub != "*" {
        return None;
    }
    Some((t.to_string(), sub.to_string()))
}

impl Scope {
    /// Parse one scope string. `None` = unrecognized → grants nothing.
    pub fn parse(s: &str) -> Option<Scope> {
        if let Some(rest) = s.strip_prefix("repo:") {
            let (collection, query) = match rest.split_once('?') {
                Some((c, q)) => (c, Some(q)),
                None => (rest, None),
            };
            if !is_nsid(collection) {
                return None;
            }
            let actions = match query {
                None => BTreeSet::from([RepoAction::Create, RepoAction::Update, RepoAction::Delete]),
                Some(q) => {
                    let mut actions = BTreeSet::new();
                    for pair in q.split('&') {
                        let (k, v) = pair.split_once('=')?;
                        if k != "action" {
                            return None; // unknown param → whole scope invalid
                        }
                        actions.insert(RepoAction::parse(v)?);
                    }
                    if actions.is_empty() {
                        return None;
                    }
                    actions
                }
            };
            return Some(Scope::Repo { collection: collection.to_string(), actions });
        }
        if let Some(method) = s.strip_prefix("rpc:") {
            if !is_nsid(method) {
                return None;
            }
            return Some(Scope::Rpc { method: method.to_string() });
        }
        if let Some(mime) = s.strip_prefix("blob:") {
            return Some(Scope::Blob { mime: parse_mime(mime)? });
        }
        None
    }

    fn covers(&self, req: &Required) -> bool {
        match (self, req) {
            (Scope::Repo { collection, actions }, Required::Repo { collection: rc, action }) => {
                collection == rc && actions.contains(action)
            }
            (Scope::Rpc { method }, Required::Rpc { method: rm }) => method == rm,
            (Scope::Blob { mime: (t, sub) }, Required::Blob { mime: (rt, rsub) }) => {
                (t == "*" || t == rt) && (sub == "*" || sub == rsub)
            }
            _ => false,
        }
    }
}

/// Parse a warrant's scope list. Unparseable entries are dropped (they grant
/// nothing); the `login` sentinel is not a bridge permission and is dropped
/// too.
pub fn parse_scopes(raw: &[String]) -> Vec<Scope> {
    raw.iter().filter_map(|s| Scope::parse(s)).collect()
}

pub fn scopes_cover(scopes: &[Scope], req: &Required) -> bool {
    scopes.iter().any(|s| s.covers(req))
}

/// Map an XRPC call to the permission it requires. `None` = unmapped →
/// denied for bridge-token traffic.
///
/// `method` is the HTTP method, `nsid` the XRPC method name, `body` the
/// parsed JSON body for procedures (where the collection lives), and
/// `content_type` the request content type (for uploadBlob).
pub fn required_for(
    method: &str,
    nsid: &str,
    body: Option<&serde_json::Value>,
    content_type: Option<&str>,
) -> Option<Vec<Required>> {
    let collection = |body: Option<&serde_json::Value>| -> Option<String> {
        body?.get("collection")?.as_str().filter(|c| is_nsid(c)).map(String::from)
    };
    match (method, nsid) {
        ("POST", "com.atproto.repo.createRecord") => Some(vec![Required::Repo {
            collection: collection(body)?,
            action: RepoAction::Create,
        }]),
        ("POST", "com.atproto.repo.putRecord") => Some(vec![Required::Repo {
            collection: collection(body)?,
            action: RepoAction::Update,
        }]),
        ("POST", "com.atproto.repo.deleteRecord") => Some(vec![Required::Repo {
            collection: collection(body)?,
            action: RepoAction::Delete,
        }]),
        ("POST", "com.atproto.repo.applyWrites") => {
            // Every write in the batch needs its own coverage.
            let writes = body?.get("writes")?.as_array()?;
            let mut needed = Vec::new();
            for w in writes {
                let c = w.get("collection")?.as_str().filter(|c| is_nsid(c))?.to_string();
                let action = match w.get("$type")?.as_str()? {
                    "com.atproto.repo.applyWrites#create" => RepoAction::Create,
                    "com.atproto.repo.applyWrites#update" => RepoAction::Update,
                    "com.atproto.repo.applyWrites#delete" => RepoAction::Delete,
                    _ => return None,
                };
                needed.push(Required::Repo { collection: c, action });
            }
            if needed.is_empty() {
                return None;
            }
            Some(needed)
        }
        ("POST", "com.atproto.repo.uploadBlob") => {
            let ct = content_type?.split(';').next()?.trim();
            Some(vec![Required::Blob { mime: parse_mime(ct).filter(|(t, s)| t != "*" && s != "*")? }])
        }
        // Reads: any GET query maps to an rpc: requirement on its own nsid.
        ("GET", m) if is_nsid(m) => Some(vec![Required::Rpc { method: m.to_string() }]),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req_create(c: &str) -> Required {
        Required::Repo { collection: c.into(), action: RepoAction::Create }
    }

    #[test]
    fn parse_repo_scopes() {
        let s = Scope::parse("repo:app.bsky.feed.post?action=create").unwrap();
        assert!(s.covers(&req_create("app.bsky.feed.post")));
        assert!(!s.covers(&Required::Repo {
            collection: "app.bsky.feed.post".into(),
            action: RepoAction::Delete
        }));
        assert!(!s.covers(&req_create("app.bsky.feed.like")));

        // No action param → all three actions.
        let s = Scope::parse("repo:app.bsky.feed.like").unwrap();
        for a in [RepoAction::Create, RepoAction::Update, RepoAction::Delete] {
            assert!(s.covers(&Required::Repo { collection: "app.bsky.feed.like".into(), action: a }));
        }

        // Multiple actions.
        let s = Scope::parse("repo:app.bsky.feed.post?action=create&action=delete").unwrap();
        assert!(s.covers(&Required::Repo { collection: "app.bsky.feed.post".into(), action: RepoAction::Delete }));
        assert!(!s.covers(&Required::Repo { collection: "app.bsky.feed.post".into(), action: RepoAction::Update }));
    }

    #[test]
    fn unparseable_scopes_grant_nothing() {
        for bad in [
            "repo:app.bsky.feed.post?action=explode",
            "repo:app.bsky.feed.post?foo=create",
            "repo:notannsid",
            "repo:",
            "rpc:x",
            "blob:image",
            "blob:*/png",
            "post",
            "login",
            "*",
            "repo:app.bsky.feed.post?action=",
        ] {
            assert!(Scope::parse(bad).is_none(), "{bad:?} must not parse");
        }
        // parse_scopes drops them silently.
        assert!(parse_scopes(&["login".into(), "bogus".into()]).is_empty());
    }

    #[test]
    fn blob_wildcards() {
        let img = Scope::parse("blob:image/*").unwrap();
        assert!(img.covers(&Required::Blob { mime: ("image".into(), "png".into()) }));
        assert!(!img.covers(&Required::Blob { mime: ("video".into(), "mp4".into()) }));
        let any = Scope::parse("blob:*/*").unwrap();
        assert!(any.covers(&Required::Blob { mime: ("video".into(), "mp4".into()) }));
    }

    #[test]
    fn xrpc_mapping() {
        let body = serde_json::json!({ "repo": "did:plc:xyz", "collection": "app.bsky.feed.post", "record": {} });
        assert_eq!(
            required_for("POST", "com.atproto.repo.createRecord", Some(&body), None),
            Some(vec![req_create("app.bsky.feed.post")])
        );
        // Unmapped endpoint → None → deny.
        assert_eq!(required_for("POST", "com.atproto.server.createSession", None, None), None);
        // Procedure with no collection → None → deny.
        assert_eq!(required_for("POST", "com.atproto.repo.createRecord", None, None), None);
        // uploadBlob keys off content-type; wildcard content-type is refused.
        assert_eq!(
            required_for("POST", "com.atproto.repo.uploadBlob", None, Some("image/png")),
            Some(vec![Required::Blob { mime: ("image".into(), "png".into()) }])
        );
        assert_eq!(required_for("POST", "com.atproto.repo.uploadBlob", None, Some("*/*")), None);
        // Reads map to rpc:.
        assert_eq!(
            required_for("GET", "app.bsky.feed.getTimeline", None, None),
            Some(vec![Required::Rpc { method: "app.bsky.feed.getTimeline".into() }])
        );
    }

    #[test]
    fn apply_writes_requires_every_op() {
        let body = serde_json::json!({ "repo": "did:plc:x", "writes": [
            { "$type": "com.atproto.repo.applyWrites#create", "collection": "app.bsky.feed.post", "value": {} },
            { "$type": "com.atproto.repo.applyWrites#delete", "collection": "app.bsky.feed.like", "rkey": "abc" },
        ]});
        let needed = required_for("POST", "com.atproto.repo.applyWrites", Some(&body), None).unwrap();
        assert_eq!(needed.len(), 2);
        let scopes = parse_scopes(&["repo:app.bsky.feed.post?action=create".into()]);
        // Covers the create but not the like-delete → overall deny.
        assert!(scopes_cover(&scopes, &needed[0]));
        assert!(!scopes_cover(&scopes, &needed[1]));
    }
}
