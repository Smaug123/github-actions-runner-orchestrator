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
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
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

/// The `permissions` object of a down-scoped token mint. Only the subsets the
/// cache warmer needs are modelled; `None` fields are omitted from the request
/// so the minted token carries no permission we did not explicitly ask for.
#[derive(Serialize, Default)]
pub struct ScopedPermissions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contents: Option<&'static str>,
}

/// Request body for a down-scoped installation-token mint: limit the token to
/// `repository_ids` and `permissions` instead of the installation-wide default.
#[derive(Serialize)]
struct ScopedTokenReq<'a> {
    repository_ids: &'a [u64],
    permissions: &'a ScopedPermissions,
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

/// How long we hold a minted installation token before refreshing. GitHub
/// gives us 60 minutes; we refresh 10 early to keep the window tight.
const TOKEN_TTL: Duration = Duration::from_secs(50 * 60);

/// Don't serve a cached token with less than this much life left, so an
/// in-flight request can't outlive the token it was authorized with.
const REFRESH_MARGIN: Duration = Duration::from_secs(5 * 60);

struct CachedToken {
    token: String,
    // Wall-clock, not monotonic: the token's expiry is wall-clock (60 minutes
    // after mint), and a monotonic `Instant` freezes while the host sleeps, so
    // a monotonic TTL would keep serving a token GitHub had already expired.
    // `SystemTime` advances across sleep, matching app_jwt.rs's expiry maths.
    valid_until: SystemTime,
}

impl CachedToken {
    /// Fresh enough to serve iff more than `REFRESH_MARGIN` of wall-clock life
    /// remains at `now`. Pure so the margin arithmetic is unit-testable without
    /// a real clock.
    fn is_fresh_at(&self, now: SystemTime) -> bool {
        self.valid_until > now + REFRESH_MARGIN
    }
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
                if cached.is_fresh_at(SystemTime::now()) {
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
            valid_until: SystemTime::now() + TOKEN_TTL,
        };
        {
            let mut cache = self.token.lock().await;
            *cache = Some(cached);
        }
        Ok(body.token)
    }

    /// Mint a fresh installation token **down-scoped** to `repository_ids` with
    /// only `permissions`, bypassing the shared cache entirely.
    ///
    /// The cached `token()` above carries every permission the App was granted
    /// across every installed repo (the mint sends no body). The cache warmer
    /// needs the opposite: a short-lived token limited to one repo and
    /// `contents: read`, written to a `0600` netrc and discarded after use. So
    /// this never reads or writes the cache — each call is its own mint — and
    /// the result is the caller's to hold briefly and drop.
    #[allow(dead_code)] // consumed by the cache warmer (a later slice)
    pub async fn scoped_token(
        &self,
        account: &str,
        repository_ids: &[u64],
        permissions: &ScopedPermissions,
    ) -> Result<String> {
        // Reuses the OnceCell-cached installation id; only the token mint is
        // uncached.
        let id = self.installation_id(account).await?;
        let jwt = app_jwt::mint(self.auth.app_id, &self.auth.pem)?;
        let url = format!("{}/app/installations/{}/access_tokens", self.api, id);
        let req = ScopedTokenReq {
            repository_ids,
            permissions,
        };
        let resp = self
            .http
            .post(&url)
            .bearer_auth(&jwt)
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .json(&req)
            .send()
            .await
            .context("POST /app/installations/{id}/access_tokens (scoped)")?;
        if !resp.status().is_success() {
            anyhow::bail!(
                "scoped token mint: {} {}",
                resp.status(),
                resp.text().await.unwrap_or_default()
            );
        }
        let body: TokenResp = resp.json().await?;
        Ok(body.token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A fixed wall-clock instant to anchor the freshness maths, well clear of
    // the epoch so we can subtract without underflow.
    fn base() -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000)
    }

    #[test]
    fn fresh_when_full_ttl_remaining() {
        let t = base();
        let tok = CachedToken {
            token: "x".into(),
            valid_until: t + TOKEN_TTL,
        };
        // Just minted: comfortably more than REFRESH_MARGIN left.
        assert!(tok.is_fresh_at(t));
    }

    #[test]
    fn stale_within_refresh_margin() {
        let t = base();
        let tok = CachedToken {
            token: "x".into(),
            // Only 3 minutes left — inside the 5-minute margin, so refresh.
            valid_until: t + Duration::from_secs(3 * 60),
        };
        assert!(!tok.is_fresh_at(t));
    }

    #[test]
    fn stale_after_wall_clock_advances_past_expiry() {
        // Regression for the sleep-freeze bug: a token minted at T is
        // valid_until T+50min. If the host sleeps and wakes at T+55min of wall
        // time, the token must read as stale. The bug measured this window with
        // a monotonic clock that doesn't advance during sleep, so it kept
        // serving a token GitHub had already expired. Measuring `now` in
        // wall-clock time rejects it.
        let mint = base();
        let tok = CachedToken {
            token: "x".into(),
            valid_until: mint + TOKEN_TTL,
        };
        let woke = mint + Duration::from_secs(55 * 60);
        assert!(!tok.is_fresh_at(woke));
    }

    #[test]
    fn scoped_token_body_shape() {
        // The mint must request exactly one repo id and only contents:read —
        // no broader permission leaks into the body.
        let perms = ScopedPermissions {
            contents: Some("read"),
        };
        let req = ScopedTokenReq {
            repository_ids: &[7],
            permissions: &perms,
        };
        let got = serde_json::to_value(&req).unwrap();
        assert_eq!(
            got,
            serde_json::json!({
                "repository_ids": [7],
                "permissions": { "contents": "read" }
            })
        );
    }

    #[test]
    fn scoped_permissions_omit_unset_fields() {
        // An empty permissions set serializes to `{}` — never a null that GitHub
        // might read as "grant everything".
        let got = serde_json::to_value(ScopedPermissions::default()).unwrap();
        assert_eq!(got, serde_json::json!({}));
    }
}
