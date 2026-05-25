// Mint a short-lived RS256 JWT identifying this process as the GitHub App.
// GitHub permits up to 10 minutes of validity; we use 9 minutes and a 60s
// backdated iat to tolerate small clock skew.

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::Serialize;

#[derive(Serialize)]
struct Claims {
    iat: u64,
    exp: u64,
    iss: u64,
}

pub fn mint(app_id: u64, pem: &[u8]) -> Result<String> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock before unix epoch")?
        .as_secs();
    let claims = Claims {
        iat: now.saturating_sub(60),
        exp: now + 9 * 60,
        iss: app_id,
    };
    let key = EncodingKey::from_rsa_pem(pem).context("parse RSA PEM")?;
    encode(&Header::new(Algorithm::RS256), &claims, &key).context("sign JWT")
}
