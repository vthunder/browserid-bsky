//! Stage-1 smoke test (bean browserid-bsky-aa7g, P1d-3).
//!
//! `smoke setup [handle]` — one-approval merged provisioning at the broker
//! (device cert + bridge warrant in a single consent), then provisions the
//! Bluesky account at the bridge. State lands in `smoke-state.json`.
//!
//! `smoke post <text>` — mint a fresh access cert, exchange the four-object
//! bundle for a bridge token, create an `app.bsky.feed.post` record, and
//! read it back from the PDS. Run again after revoking the warrant at the
//! broker to watch the 401.

use browserid_agent::{request_provision, DeviceAgent, DeviceCredential, GrantRequest};
use serde::{Deserialize, Serialize};

const BROKER: &str = "https://browserid.me";
const BRIDGE: &str = "https://bsky.browserid.me";
const PDS: &str = "https://pds.bsky.browserid.me";
const POST_SCOPE: &str = "repo:app.bsky.feed.post?action=create";
const STATE: &str = "smoke-state.json";

#[derive(Serialize, Deserialize)]
struct State {
    credential: DeviceCredential,
    /// (audience, "warrant~config_cert") pairs from the merged consent
    grants: Vec<(String, String)>,
    did: Option<String>,
    handle: Option<String>,
}

/// HTTP client; set BRIDGE_IP to pin bridge/PDS hostnames to an address
/// (works around local negative-DNS caching right after records are created).
fn client() -> reqwest::Client {
    let mut b = reqwest::Client::builder();
    if let Ok(ip) = std::env::var("BRIDGE_IP") {
        let addr: std::net::SocketAddr = format!("{ip}:443").parse().expect("bad BRIDGE_IP");
        for host in ["bsky.browserid.me", "pds.bsky.browserid.me"] {
            b = b.resolve(host, addr);
        }
    }
    b.build().expect("client")
}

fn agent_from(state: &State) -> DeviceAgent {
    let mut agent = DeviceAgent::new(state.credential.clone()).expect("bad credential");
    for (_aud, tail) in &state.grants {
        let (warrant, config_cert) = tail.split_once('~').expect("grant is not warrant~config_cert");
        agent.add_grant(warrant, config_cert).expect("bad grant");
    }
    agent
}

async fn setup(handle_label: &str) {
    let pending = request_provision(
        BROKER,
        None, // as-you: the agent holds the approving identity itself
        None,
        &[GrantRequest {
            audience: BRIDGE.to_string(),
            scopes: vec!["login".to_string(), POST_SCOPE.to_string()],
        }],
        Some("Bluesky bridge smoke test"),
    )
    .await
    .expect("provision request failed");

    println!("APPROVE_URL: {}", pending.verification_uri_complete);
    println!("  (code {} — fingerprint {})", pending.user_code, pending.fingerprint);
    println!("waiting for approval...");

    let provisioned = pending.wait().await.expect("approval failed");
    let state = State {
        credential: provisioned.credential.clone(),
        grants: provisioned.grants.clone(),
        did: None,
        handle: None,
    };
    // Save BEFORE anything can fail — the approval is single-delivery.
    std::fs::write(STATE, serde_json::to_string_pretty(&state).unwrap()).expect("state write");
    let agent = agent_from(&state);
    println!("provisioned as {} (grants: {}); state saved", agent.email(), state.grants.len());
    account(handle_label).await;
}

/// Provision the Bluesky account at the bridge using saved state.
async fn account(handle_label: &str) {
    let mut state: State =
        serde_json::from_str(&std::fs::read_to_string(STATE).expect("run `smoke setup` first"))
            .expect("bad state file");
    let mut agent = agent_from(&state);

    let bundle = agent.assertion_for(BRIDGE).await.expect("bundle mint failed");
    let resp = client()
        .post(format!("{BRIDGE}/browserid/provision"))
        .json(&serde_json::json!({ "presentation": bundle, "handle": handle_label }))
        .send()
        .await
        .expect("bridge unreachable");
    let status = resp.status();
    let body: serde_json::Value = resp.json().await.unwrap_or_default();
    if !status.is_success() {
        panic!("bridge provision refused ({status}): {body}");
    }
    println!("bluesky account created:");
    println!("  did:      {}", body["did"].as_str().unwrap_or("?"));
    println!("  handle:   {}", body["handle"].as_str().unwrap_or("?"));
    println!("  password: {}  (shown once — save it if you want to log in with a Bluesky client)", body["password"].as_str().unwrap_or("?"));
    state.did = body["did"].as_str().map(String::from);
    state.handle = body["handle"].as_str().map(String::from);
    std::fs::write(STATE, serde_json::to_string_pretty(&state).unwrap()).expect("state write");
    println!("state saved to {STATE}");
}

async fn post(text: &str) {
    let state: State =
        serde_json::from_str(&std::fs::read_to_string(STATE).expect("run `smoke setup` first"))
            .expect("bad state file");
    let did = state.did.clone().expect("no did in state — setup incomplete");
    let mut agent = agent_from(&state);

    // Get the bundle AND the access key seed, so we can sign a post
    // attestation with the same access key the bundle certifies.
    let (bundle, access_seed) =
        agent.assertion_with_access_seed(BRIDGE).await.expect("bundle mint failed");
    let access_cert = bundle.split('~').next().expect("access cert").to_string();
    let http = client();
    let resp = http
        .post(format!("{BRIDGE}/browserid/token"))
        .form(&[
            ("grant_type", "urn:x-browserid:grant-type:assertion"),
            ("assertion", bundle.as_str()),
        ])
        .send()
        .await
        .expect("bridge unreachable");
    let status = resp.status();
    let body: serde_json::Value = resp.json().await.unwrap_or_default();
    if !status.is_success() {
        println!("TOKEN EXCHANGE REFUSED ({status}): {body}");
        println!("(if you just revoked the warrant: this is the revocation working)");
        std::process::exit(1);
    }
    let token = body["access_token"].as_str().expect("no token").to_string();
    println!("bridge token issued (scopes {:?})", body["scopes"]);

    // Build the post the grantee will sign — including the optional in-post
    // verify link, keyed by the attestation nonce (known before the post
    // exists), so the signature covers exactly what's published.
    // A random single-use nonce (base64url, url-safe). Chosen by the agent
    // before the post exists, so the signed content can embed the link.
    let nonce = browserid_core::KeyPair::generate().public_key().to_base64();
    let verify_url = format!("{BRIDGE}/verify?n={nonce}");

    // Render the link as a compact clickable facet ("🔗 verify") rather than
    // a bare URL: the label is the display text; the URL lives in the facet.
    // Facet ranges are UTF-8 BYTE offsets. The facet is part of the record,
    // so it's covered by the grantee's signature too.
    let label = "🔗 verify";
    let prefix = format!("{text}\n\n");
    let byte_start = prefix.len();
    let full_text = format!("{prefix}{label}");
    let byte_end = full_text.len();
    let record = serde_json::json!({
        "$type": "app.bsky.feed.post",
        "text": full_text,
        "createdAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        "facets": [{
            "index": { "byteStart": byte_start, "byteEnd": byte_end },
            "features": [{ "$type": "app.bsky.richtext.facet#link", "uri": verify_url }],
        }],
    });

    use browserid_core::KeyPair;
    use pds_bridge::attestation::{content_hash, AttestationClaims};
    let access_key = KeyPair::from_seed(&access_seed).expect("access seed");
    let claims = AttestationClaims::new(
        &did,
        "app.bsky.feed.post",
        &content_hash(&record),
        &nonce,
        chrono::Utc::now().timestamp(),
    );
    let sig = claims.sign(&access_key);

    let resp = http
        .post(format!("{BRIDGE}/browserid/post"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "record": record,
            "attestation": { "claims": claims, "sig": sig },
            "accessCert": access_cert,
        }))
        .send()
        .await
        .expect("bridge unreachable");
    let status = resp.status();
    let body: serde_json::Value = resp.json().await.unwrap_or_default();
    if !status.is_success() {
        println!("POST REFUSED ({status}): {body}");
        println!("(if you just revoked the warrant: this is the revocation working)");
        std::process::exit(1);
    }
    println!("posted (signed): {}", body["uri"].as_str().unwrap_or("?"));
    println!("verify: {verify_url}");

    // Read it back from the PDS directly (public, unauthenticated).
    let listed: serde_json::Value = http
        .get(format!("{PDS}/xrpc/com.atproto.repo.listRecords?repo={did}&collection=app.bsky.feed.post&limit=3"))
        .send()
        .await
        .expect("pds unreachable")
        .json()
        .await
        .unwrap_or_default();
    let n = listed["records"].as_array().map(|r| r.len()).unwrap_or(0);
    println!("PDS confirms {} post(s); latest: {:?}", n,
        listed["records"][0]["value"]["text"].as_str().unwrap_or("?"));
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("setup") => setup(args.get(2).map(String::as_str).unwrap_or("claude")).await,
        Some("account") => account(args.get(2).map(String::as_str).unwrap_or("claude")).await,
        Some("post") => post(args.get(2).map(String::as_str).unwrap_or("hello from my agent — via a browserid warrant")).await,
        _ => {
            eprintln!("usage: smoke setup [handle] | smoke account [handle] | smoke post [text]");
            std::process::exit(2);
        }
    }
}
