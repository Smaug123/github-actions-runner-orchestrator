// Installation discovery and token minting.
//
// An account has at most one installation of a given App. We look up the
// installation id once at startup (cached forever via OnceCell) and mint
// installation tokens on demand, holding one in memory with a TTL of ~50
// minutes (GitHub gives us 1 hour, we refresh early to keep the window
// tight).
//
// The discovery endpoint is account-scoped: `/users/{account}/installation`
// works for a personal (user) account. The token-mint endpoint
// (`/app/installations/{id}/access_tokens`) is account-agnostic.
//
// Neither the installation-id lookup nor the token mint holds a lock across
// its HTTP roundtrip; concurrent callers may race to mint a fresh token, and
// the last writer wins the cache. Duplicate mints are harmless — GitHub
// keeps previously-issued tokens valid until their own expiry — and the
// alternative (lock held across the network call) serializes every job's
// token fetch behind one roundtrip.

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use reqwest::Client;
use serde::Deserialize;
use tokio::sync::{Mutex, OnceCell};
use zeroize::Zeroizing;

use super::app_jwt;

#[derive(Deserialize)]
struct Installation {
    id: u64,
}

#[derive(Deserialize)]
struct TokenResp {
    token: String,
}

#[derive(Clone)]
pub struct AppAuth {
    pub app_id: u64,
    pub pem: Arc<Zeroizing<Vec<u8>>>,
}

pub struct Installations {
    api: String,
    http: Client,
    auth: AppAuth,
    installation_id: OnceCell<u64>,
    token: Mutex<Option<CachedToken>>,
}

struct CachedToken {
    token: String,
    valid_until: Instant,
}

impl Installations {
    pub fn new(api: String, http: Client, auth: AppAuth) -> Self {
        Self {
            api,
            http,
            auth,
            installation_id: OnceCell::new(),
            token: Mutex::new(None),
        }
    }

    async fn installation_id(&self, account: &str) -> Result<u64> {
        let id = self
            .installation_id
            .get_or_try_init(|| async {
                let jwt = app_jwt::mint(self.auth.app_id, &self.auth.pem)?;
                let url = format!("{}/users/{}/installation", self.api, account);
                let resp = self
                    .http
                    .get(&url)
                    .bearer_auth(&jwt)
                    .header("Accept", "application/vnd.github+json")
                    .header("X-GitHub-Api-Version", "2022-11-28")
                    .send()
                    .await
                    .context("GET /users/{account}/installation")?;
                if !resp.status().is_success() {
                    anyhow::bail!(
                        "installation lookup: {} {}",
                        resp.status(),
                        resp.text().await.unwrap_or_default()
                    );
                }
                let inst: Installation = resp.json().await?;
                Ok(inst.id)
            })
            .await?;
        Ok(*id)
    }

    pub async fn token(&self, account: &str) -> Result<String> {
        let id = self.installation_id(account).await?;
        // Fast path: snapshot the cache under a brief lock.
        {
            let cache = self.token.lock().await;
            if let Some(cached) = cache.as_ref() {
                if cached.valid_until > Instant::now() + Duration::from_secs(5 * 60) {
                    return Ok(cached.token.clone());
                }
            }
        }
        // Mint outside the cache lock so concurrent token() calls don't
        // serialize behind one HTTP roundtrip. Worst case is a duplicate
        // mint: GitHub returns a fresh token, previous tokens stay valid
        // until their own expiry, and the last writer wins the cache.
        let jwt = app_jwt::mint(self.auth.app_id, &self.auth.pem)?;
        let url = format!("{}/app/installations/{}/access_tokens", self.api, id);
        let resp = self
            .http
            .post(&url)
            .bearer_auth(&jwt)
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .send()
            .await
            .context("POST /app/installations/{id}/access_tokens")?;
        if !resp.status().is_success() {
            anyhow::bail!(
                "token mint: {} {}",
                resp.status(),
                resp.text().await.unwrap_or_default()
            );
        }
        let body: TokenResp = resp.json().await?;
        let cached = CachedToken {
            token: body.token.clone(),
            valid_until: Instant::now() + Duration::from_secs(50 * 60),
        };
        {
            let mut cache = self.token.lock().await;
            *cache = Some(cached);
        }
        Ok(body.token)
    }
}
