//! End-to-end bridge tests (bean ezk6 P1): provision → grant exchange →
//! scoped XRPC proxy against a mock PDS, including live warrant revocation.

use std::sync::Arc;

use axum::routing::{get, post};
use axum::Json;
use chrono::Duration;
use serde_json::{json, Value};

use browserid_core::device::{
    AccessCert, AccessPresentation, DeviceCert, Holder, HolderMatcher, Purpose, Warrant,
};
use browserid_core::{Assertion, KeyPair, PublicKey, StatusList, StatusListToken, StatusRef};
use browserid_rp::StatusCache;
use pds_bridge::store::Store;
use pds_bridge::{pds::PdsClient, BridgeState};

const ORIGIN: &str = "https://bsky.test";
const ISSUER: &str = "browserid.test";
const STATUS_URI: &str = "https://browserid.test/.well-known/browserid-status";

/// Four-object bundle: grantor authorizes grantee (possibly itself) at
/// `ORIGIN` with `scopes`; warrant may carry a status ref.
fn presentation(
    idp: &KeyPair,
    grantor: &str,
    grantee: &str,
    holder: &str,
    scopes: Vec<String>,
    warrant_status: Option<StatusRef>,
) -> String {
    let access_kp = KeyPair::generate();
    let config_kp = KeyPair::generate();
    let access_cert = AccessCert::create(
        ISSUER, grantee, Holder::new(holder).unwrap(), &access_kp.public_key(),
        Duration::hours(24), idp, None,
    )
    .unwrap();
    let config_cert = DeviceCert::create(
        ISSUER, &config_kp.public_key(), Purpose::Authorization, Holder::new(holder).unwrap(),
        vec![grantor.to_string()], Duration::days(90), idp, None,
    )
    .unwrap();
    let warrant = Warrant::create(
        grantor, grantee, HolderMatcher::new("svc.*").unwrap(), ORIGIN, scopes,
        Duration::days(90), &config_kp, warrant_status,
    )
    .unwrap();
    let assertion = Assertion::create(ORIGIN, Duration::minutes(5), &access_kp).unwrap();
    format!(
        "{}~{}~{}~{}",
        access_cert.encoded(), assertion.encoded(), warrant.encoded(), config_cert.encoded()
    )
}

/// A mock PDS answering the calls the bridge makes; captures repo writes.
async fn mock_pds(captures: Captures) -> String {
    let app = axum::Router::new()
        .route(
            "/xrpc/com.atproto.server.createInviteCode",
            post(|| async { Json(json!({ "code": "invite-1" })) }),
        )
        .route(
            "/xrpc/com.atproto.server.createAccount",
            post(|Json(body): Json<Value>| async move {
                Json(json!({
                    "did": "did:plc:testuser",
                    "handle": body["handle"],
                    "accessJwt": "pds-access-1",
                    "refreshJwt": "pds-refresh-1",
                }))
            }),
        )
        .route(
            "/xrpc/com.atproto.server.refreshSession",
            post(|| async { Json(json!({ "accessJwt": "pds-access-2", "refreshJwt": "pds-refresh-2" })) }),
        )
        .route(
            "/xrpc/com.atproto.repo.createRecord",
            post(|axum::extract::State(cap): axum::extract::State<Captures>, Json(body): Json<Value>| async move {
                let coll = body["collection"].as_str().unwrap();
                let rkey = if coll == "app.bsky.feed.post" { "rkey1" } else { "auto" };
                cap.lock().unwrap().push(body.clone());
                Json(json!({ "uri": format!("at://{}/{}/{}", body["repo"].as_str().unwrap(), coll, rkey), "cid": "cid1" }))
            }),
        )
        .route(
            "/xrpc/com.atproto.repo.putRecord",
            post(|axum::extract::State(cap): axum::extract::State<Captures>, Json(body): Json<Value>| async move {
                cap.lock().unwrap().push(body.clone());
                Json(json!({ "uri": format!("at://{}/{}/{}", body["repo"].as_str().unwrap(), body["collection"].as_str().unwrap(), body["rkey"].as_str().unwrap_or("auto")), "cid": "cid1" }))
            }),
        )
        .route("/xrpc/app.bsky.actor.getProfile", get(|| async { Json(json!({ "handle": "public" })) }))
        .with_state(captures.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    base
}

type Captures = Arc<std::sync::Mutex<Vec<Value>>>;

/// Records the bridge wrote to the account repo (for provenance assertions).
fn captured(cap: &Captures, collection: &str) -> Vec<Value> {
    cap.lock()
        .unwrap()
        .iter()
        .filter(|b| b["collection"] == collection)
        .cloned()
        .collect()
}

/// A mock hosted verifier: runs the REAL core verification algorithm
/// (`AccessPresentation::verify`) with the test issuer key and answers in
/// the broker's `/verify-access` response shape — the bridge outsources
/// verification, so the tests exercise its handling of that contract.
async fn mock_broker(idp_pub: PublicKey) -> String {
    async fn verify_access(
        axum::extract::State(idp_pub): axum::extract::State<PublicKey>,
        Json(body): Json<Value>,
    ) -> Json<Value> {
        let pres = body["presentation"].as_str().unwrap_or_default();
        let audience = body["audience"].as_str().unwrap_or_default().to_string();
        let out = AccessPresentation::parse(pres).and_then(|p| {
            p.verify(&audience, |iss| {
                if iss == ISSUER {
                    Ok(idp_pub.clone())
                } else {
                    Err(browserid_core::Error::DiscoveryFailed {
                        domain: iss.to_string(),
                        reason: "issuer not trusted".to_string(),
                    })
                }
            })
        });
        match out {
            Ok(v) => Json(json!({
                "status": "okay",
                "email": v.email,
                "holder": v.holder.as_str(),
                "scopes": v.scopes,
                "issuer": v.issuer,
            })),
            Err(e) => Json(json!({ "status": "failure", "reason": e.to_string() })),
        }
    }
    let app = axum::Router::new()
        .route("/verify-access", post(verify_access))
        .with_state(idp_pub);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    base
}

async fn bridge(idp: &KeyPair, revoked: &[u64]) -> (axum_test::TestServer, Arc<StatusCache>, Captures) {
    let cache = Arc::new(StatusCache::new());
    let list = StatusList::from_revoked(revoked.iter().copied(), 64);
    let token = StatusListToken::create(ISSUER, STATUS_URI, &list, idp).unwrap();
    cache.insert(STATUS_URI, token);

    let captures: Captures = Arc::new(std::sync::Mutex::new(Vec::new()));
    let state = BridgeState {
        origin: ORIGIN.to_string(),
        handle_domain: "at.browserid.test".to_string(),
        broker_url: mock_broker(idp.public_key()).await,
        broker_key: idp.public_key(),
        status_cache: cache.clone(),
        store: Store::open_in_memory().unwrap(),
        pds: PdsClient::new(mock_pds(captures.clone()).await, "admin-secret"),
        http: reqwest::Client::new(),
    };
    (axum_test::TestServer::new(state.router()).unwrap(), cache, captures)
}

async fn provision(server: &axum_test::TestServer, idp: &KeyPair, email: &str, handle: &str) -> Value {
    let pres = presentation(idp, email, email, "svc.main", vec!["login".into()], None);
    let resp = server
        .post("/browserid/provision")
        .json(&json!({ "presentation": pres, "handle": handle }))
        .await;
    assert_eq!(resp.status_code(), 201, "{}", resp.text());
    resp.json()
}

fn exchange_form(pres: &str) -> Vec<(String, String)> {
    vec![
        ("grant_type".into(), "urn:x-browserid:grant-type:assertion".into()),
        ("assertion".into(), pres.to_string()),
    ]
}

#[tokio::test]
async fn provision_token_post_end_to_end() {
    let idp = KeyPair::generate();
    let (server, _, cap) = bridge(&idp, &[]).await;

    // 1. Provision: browserid login → PDS account + binding.
    let account = provision(&server, &idp, "dan@sandmill.test", "dan").await;
    assert_eq!(account["did"], "did:plc:testuser");
    assert_eq!(account["handle"], "dan.at.browserid.test");
    assert!(account["password"].as_str().unwrap().len() >= 32);

    // 2. Grant exchange: agent presents a scoped warrant from the grantor.
    let pres = presentation(
        &idp, "dan@sandmill.test", "dan+agent@sandmill.test", "svc.agent",
        vec!["repo:app.bsky.feed.post?action=create".into()],
        Some(StatusRef { uri: STATUS_URI.into(), idx: 7 }),
    );
    let resp = server.post("/browserid/token").form(&exchange_form(&pres)).await;
    assert_eq!(resp.status_code(), 200, "{}", resp.text());
    let token: Value = resp.json();
    let bearer = token["access_token"].as_str().unwrap().to_string();
    assert!(bearer.starts_with("bidb_"));
    assert_eq!(token["email"], "dan@sandmill.test");

    // 3. Scoped post goes through to the PDS with the account session.
    let resp = server
        .post("/xrpc/com.atproto.repo.createRecord")
        .authorization_bearer(&bearer)
        .json(&json!({ "repo": "did:plc:testuser", "collection": "app.bsky.feed.post",
                        "record": { "text": "hello from my agent" } }))
        .await;
    assert_eq!(resp.status_code(), 200, "{}", resp.text());
    assert!(resp.text().contains("at://did:plc:testuser/app.bsky.feed.post"));

    // 3b. Sidecar provenance was written (bean 27c0 phase 1): one warrant
    // record (verifiable delegation artifacts) + one per-post provenance
    // record referencing it. This exchange used grantor != grantee, so it's
    // the ON-BEHALF shape: executed_by (the delegate) differs from
    // attributed_to (the authorizer whose repo the post lives in).
    let warrants = captured(&cap, "me.browserid.warrant");
    assert_eq!(warrants.len(), 1, "one warrant record");
    assert!(!warrants[0]["record"]["warrant"].as_str().unwrap().is_empty(), "carries warrant JWS");
    assert!(!warrants[0]["record"]["configCert"].as_str().unwrap().is_empty(), "carries config cert");

    let prov = captured(&cap, "me.browserid.provenance");
    assert_eq!(prov.len(), 1, "one provenance record");
    let pr = &prov[0]["record"];
    assert_eq!(pr["post"], "at://did:plc:testuser/app.bsky.feed.post/rkey1");
    assert_eq!(pr["attributedTo"], "dan@sandmill.test", "authorizer / repo owner");
    assert_eq!(pr["executedBy"], "dan+agent@sandmill.test", "on-behalf: delegate differs");
    assert!(pr["warrant"].as_str().unwrap().contains("me.browserid.warrant"), "references the warrant record");

    // 4. Outside the warrant: delete is not covered → 403.
    let resp = server
        .post("/xrpc/com.atproto.repo.deleteRecord")
        .authorization_bearer(&bearer)
        .json(&json!({ "repo": "did:plc:testuser", "collection": "app.bsky.feed.post", "rkey": "rkey1" }))
        .await;
    assert_eq!(resp.status_code(), 403);

    // 5. Unmapped endpoint → 403 even though the token is valid.
    let resp = server
        .post("/xrpc/com.atproto.server.createSession")
        .authorization_bearer(&bearer)
        .json(&json!({ "identifier": "x", "password": "y" }))
        .await;
    assert_eq!(resp.status_code(), 403);

    // 6. Foreign repo → 403.
    let resp = server
        .post("/xrpc/com.atproto.repo.createRecord")
        .authorization_bearer(&bearer)
        .json(&json!({ "repo": "did:plc:victim", "collection": "app.bsky.feed.post", "record": {} }))
        .await;
    assert_eq!(resp.status_code(), 403);
}

#[tokio::test]
async fn warrant_revocation_kills_live_tokens() {
    let idp = KeyPair::generate();
    let (server, cache, _) = bridge(&idp, &[]).await;
    provision(&server, &idp, "dan@sandmill.test", "dan").await;

    let pres = presentation(
        &idp, "dan@sandmill.test", "dan+agent@sandmill.test", "svc.agent",
        vec!["repo:app.bsky.feed.post?action=create".into()],
        Some(StatusRef { uri: STATUS_URI.into(), idx: 7 }),
    );
    let resp = server.post("/browserid/token").form(&exchange_form(&pres)).await;
    let bearer = resp.json::<Value>()["access_token"].as_str().unwrap().to_string();

    // Works while the warrant is clear...
    let post = || {
        server
            .post("/xrpc/com.atproto.repo.createRecord")
            .authorization_bearer(&bearer)
            .json(&json!({ "repo": "did:plc:testuser", "collection": "app.bsky.feed.post",
                            "record": { "text": "hi" } }))
    };
    assert_eq!(post().await.status_code(), 200);

    // ...the user flips the status bit → next use is refused and the token
    // is deleted.
    let revoked = StatusList::from_revoked([7], 64);
    cache.insert(STATUS_URI, StatusListToken::create(ISSUER, STATUS_URI, &revoked, &idp).unwrap());
    assert_eq!(post().await.status_code(), 401);
    // Even after the list clears again, the token is gone.
    let clear = StatusList::from_revoked([], 64);
    cache.insert(STATUS_URI, StatusListToken::create(ISSUER, STATUS_URI, &clear, &idp).unwrap());
    assert_eq!(post().await.status_code(), 401);
}

#[tokio::test]
async fn exchange_requires_provisioned_grantor_and_usable_scopes() {
    let idp = KeyPair::generate();
    let (server, _, _) = bridge(&idp, &[]).await;

    // Unprovisioned grantor → 403 with a provisioning hint.
    let pres = presentation(
        &idp, "nobody@sandmill.test", "nobody+agent@sandmill.test", "svc.agent",
        vec!["repo:app.bsky.feed.post?action=create".into()], None,
    );
    let resp = server.post("/browserid/token").form(&exchange_form(&pres)).await;
    assert_eq!(resp.status_code(), 403);
    assert!(resp.text().contains("provision"));

    // Provisioned, but the warrant has no scope the bridge understands.
    provision(&server, &idp, "dan@sandmill.test", "dan").await;
    let pres = presentation(
        &idp, "dan@sandmill.test", "dan+agent@sandmill.test", "svc.agent",
        vec!["login".into(), "guestbook-sign".into()], None,
    );
    let resp = server.post("/browserid/token").form(&exchange_form(&pres)).await;
    assert_eq!(resp.status_code(), 400);
    assert!(resp.text().contains("invalid_scope"));
}

#[tokio::test]
async fn provisioning_rules() {
    let idp = KeyPair::generate();
    let (server, _, _) = bridge(&idp, &[]).await;

    // Reserved and malformed labels refused.
    for label in ["admin", "xrpc", "A_b", "-dash", "x"] {
        let pres = presentation(&idp, "dan@sandmill.test", "dan@sandmill.test", "svc.main", vec!["login".into()], None);
        let resp = server
            .post("/browserid/provision")
            .json(&json!({ "presentation": pres, "handle": label }))
            .await;
        assert_eq!(resp.status_code(), 400, "label {label:?} must be refused");
    }

    // Delegated (grantee != grantor) presentations cannot provision.
    let pres = presentation(
        &idp, "dan@sandmill.test", "dan+agent@sandmill.test", "svc.agent", vec!["login".into()], None,
    );
    let resp = server
        .post("/browserid/provision")
        .json(&json!({ "presentation": pres, "handle": "dan" }))
        .await;
    assert_eq!(resp.status_code(), 403);

    // One account per email; handle uniqueness.
    provision(&server, &idp, "dan@sandmill.test", "dan").await;
    let pres = presentation(&idp, "dan@sandmill.test", "dan@sandmill.test", "svc.main", vec!["login".into()], None);
    let resp = server
        .post("/browserid/provision")
        .json(&json!({ "presentation": pres, "handle": "dan2" }))
        .await;
    assert_eq!(resp.status_code(), 409);
}

#[tokio::test]
async fn passthrough_and_metadata() {
    let idp = KeyPair::generate();
    let (server, _, _) = bridge(&idp, &[]).await;

    // Anonymous XRPC reads pass straight through to the PDS.
    let resp = server.get("/xrpc/app.bsky.actor.getProfile").await;
    assert_eq!(resp.status_code(), 200);
    assert!(resp.text().contains("public"));

    // RFC 8414 metadata advertises the token endpoint + example scopes.
    let resp = server.get("/.well-known/oauth-authorization-server").await;
    let meta: Value = resp.json();
    assert_eq!(meta["token_endpoint"], format!("{ORIGIN}/browserid/token"));
    assert!(meta["scopes_supported"]
        .as_array()
        .unwrap()
        .iter()
        .any(|s| s == "repo:app.bsky.feed.post?action=create"));

    // A garbage bridge token gets a 401 with the BrowserID challenge.
    let resp = server
        .post("/xrpc/com.atproto.repo.createRecord")
        .authorization_bearer("bidb_bogus")
        .json(&json!({ "repo": "x", "collection": "app.bsky.feed.post", "record": {} }))
        .await;
    assert_eq!(resp.status_code(), 401);
    let challenge = resp.headers().get("www-authenticate").unwrap().to_str().unwrap();
    assert!(challenge.starts_with("BrowserID "), "{challenge}");
}
