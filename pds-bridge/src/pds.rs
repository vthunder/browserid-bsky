//! Minimal client for the stock reference PDS (`@atproto/pds`).
//!
//! The bridge only needs four things from the PDS: mint an invite code
//! (admin), create an account, refresh an account session, and forward
//! XRPC requests with an account's access JWT. Everything else passes
//! through the transparent proxy untouched.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::Deserialize;
use std::time::Duration;

#[derive(Debug, thiserror::Error)]
pub enum PdsError {
    #[error("PDS request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("PDS refused: {status} {body}")]
    Refused { status: u16, body: String },
}

type Result<T> = std::result::Result<T, PdsError>;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatedAccount {
    pub did: String,
    pub handle: String,
    pub access_jwt: String,
    pub refresh_jwt: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RefreshedSession {
    pub access_jwt: String,
    pub refresh_jwt: String,
}

pub struct PdsClient {
    /// e.g. `http://127.0.0.1:2583` — network-internal
    base: String,
    admin_password: String,
    http: reqwest::Client,
}

impl PdsClient {
    pub fn new(base: impl Into<String>, admin_password: impl Into<String>) -> Self {
        Self {
            base: base.into().trim_end_matches('/').to_string(),
            admin_password: admin_password.into(),
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .expect("failed to build PDS HTTP client"),
        }
    }

    pub fn base(&self) -> &str {
        &self.base
    }

    fn admin_header(&self) -> String {
        format!("Basic {}", STANDARD.encode(format!("admin:{}", self.admin_password)))
    }

    async fn refused(resp: reqwest::Response) -> PdsError {
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        PdsError::Refused { status, body: body.chars().take(500).collect() }
    }

    pub async fn create_invite_code(&self) -> Result<String> {
        #[derive(Deserialize)]
        struct R {
            code: String,
        }
        let resp = self
            .http
            .post(format!("{}/xrpc/com.atproto.server.createInviteCode", self.base))
            .header("authorization", self.admin_header())
            .json(&serde_json::json!({ "useCount": 1 }))
            .send()
            .await?;
        if !resp.status().is_success() {
            return Err(Self::refused(resp).await);
        }
        Ok(resp.json::<R>().await?.code)
    }

    pub async fn create_account(
        &self,
        handle: &str,
        email: &str,
        password: &str,
        invite_code: &str,
    ) -> Result<CreatedAccount> {
        let resp = self
            .http
            .post(format!("{}/xrpc/com.atproto.server.createAccount", self.base))
            .json(&serde_json::json!({
                "handle": handle,
                "email": email,
                "password": password,
                "inviteCode": invite_code,
            }))
            .send()
            .await?;
        if !resp.status().is_success() {
            return Err(Self::refused(resp).await);
        }
        Ok(resp.json().await?)
    }

    pub async fn refresh_session(&self, refresh_jwt: &str) -> Result<RefreshedSession> {
        let resp = self
            .http
            .post(format!("{}/xrpc/com.atproto.server.refreshSession", self.base))
            .bearer_auth(refresh_jwt)
            .send()
            .await?;
        if !resp.status().is_success() {
            return Err(Self::refused(resp).await);
        }
        Ok(resp.json().await?)
    }

    /// Forward one XRPC call with an account access JWT, returning the raw
    /// response (status + body passthrough is the caller's job).
    pub async fn forward(
        &self,
        method: &str,
        nsid: &str,
        query: Option<&str>,
        content_type: Option<&str>,
        body: Vec<u8>,
        access_jwt: &str,
    ) -> Result<reqwest::Response> {
        let mut url = format!("{}/xrpc/{}", self.base, nsid);
        if let Some(q) = query {
            url = format!("{url}?{q}");
        }
        let mut req = match method {
            "GET" => self.http.get(&url),
            _ => self.http.post(&url).body(body),
        };
        req = req.bearer_auth(access_jwt);
        if let Some(ct) = content_type {
            req = req.header("content-type", ct);
        }
        Ok(req.send().await?)
    }
}
