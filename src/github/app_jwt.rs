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

#[cfg(test)]
mod tests {
    use super::*;

    // Throwaway 2048-bit RSA key, generated solely for this test. Not a secret.
    const TEST_PEM: &[u8] = b"-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAyDpILWhAraEt1ApjZ8u2BC8DTopCxOGdB6PHpnJOHncXWf37
3C7WS4Y/C6p/vjf0/rneUntZm2Q3E3vXvYE85RMfggwx1VqkSKlZxol2lSM41EOu
EJeekpkiwALUtTlmWXOCCP+eMijOUIGhX9ashL+E5Ob4TTVtxBCjWwHlIf1J+J3u
6B5MOljb2hE9GQb1vOnXfpu03U2e3w6gHyvkx+3fEZrX4XADRA6Gg0yH147uWpmH
7Sg78Lo/TcSrMPQC0QSqnjoT2Yc6Yobw6qfNIKKHKdzaP018rPspBA7PDSqGdmfY
ZE3YLLKbEW1hxyzKbMj3yHjKlr8Y3CT6bCIVhwIDAQABAoIBAQC2bmPU+2fyyyg2
SkDIEZOFvFAG/3JWcDni/BasUPlcSKW+GOuhcgtORMKsnmxFpDZU4ITwIfNC4cxM
tEmdIGObVBEhLHs7KZsFmUdy3UxuFelxfTjbZUnVyDEhQXMMq3/VgKi6CizZBtT0
BShDahVF3jn3VXpm3odkXMR55wAeNkv6VpMFvCcTuityDmpodfEFaLUVY1PTDK8B
3yhQUkN4yM4Pztb1jjzfh22jxudzRtt9MAzb1nM+nZLUonJDJV0LBl5jdpiLI2B9
nlwHgSbAsSHITTExKFFEAGN/26sGZRk4PASPR5U2neQG1g11Zze/pPDSnH3uJ5zP
GjIyoTIBAoGBAPHIP0rNeNKZxUI/YkSisG82Vklud4/nvo6eVrJesvgH67e++kvn
Qe8gT8ivwztYOzgxJ9RUE36ZyYlkBCTxqUPHyw/1In3kH1MZHuSVu/uR7KCxMy9x
X25KI42eXZ5hyIQ2GLU9Rs3Fah48eblMrPxlzIvUh1RbDRjMm3o+KSG7AoGBANQA
epIl1MBZpJ2Hxv6JrjgSZtqf0EfY4jFkDaFFBd+IQYHDjJ/9CesPbBh2S4OsZtrp
dpjuiY/52iLnDd78g/RVWhQIfNm5VVUsU6JB3RPzTpWOaX1Dh/meCI1nEVCgVp+f
J6PKO9cZ9lUpwwFUaJAf1PoesKLpfl59DgW/3IilAoGBALsT+00QwT0K+CNzUcDT
tPrIK2m0DNUPNlW51FE9jvL1hgDtx1N1w4GYGcOpo8FGWsP23N+gkljx+4vQFJjV
V+f3LnrRbPfFzCsLE+lApmxYE6Sel4FNEs8OlIXelIeZF4KdLO8HU8KhzqNIndKv
rmW5CtTjBDdUIEUhA+hJMqBDAoGAPHZifroBYlZup2ro6wFTSbSd1u5LVaJaaGGz
rXHlCepvXFXsDlj5ciu01YkvYj9SGk8JPvaRDxngB6JEB3uXGqEZDquZB/NejesV
cyo7pgv3NpomJc6TwjI7GDDz9D22VtHqWUE9Lcy+v20oq4FqTOh3Mlp8YAodu08J
J8SfXe0CgYEAoX/uaGwpK/fIhRAuKjCY4NV0pwXHFM8ZalBup/HoSLxy7jsbf/MQ
BdWHdpSA+S47kwrCCY0vhHmqa2VhyZpcnw8H57oseRBcyC6f77wFR+cCZf04qpOD
8kveANLE4n9wssXtUMiWVOXwzk6T8dHlLpTmfEoJtQKeZC74aUh8mcI=
-----END RSA PRIVATE KEY-----";

    // Regression guard: jsonwebtoken 10.x resolves its crypto provider lazily
    // and panics on the first sign if neither rust_crypto nor aws_lc_rs is
    // enabled. Minting here exercises that path so a missing feature fails the
    // test suite instead of the daemon at startup.
    #[test]
    fn mint_signs_with_configured_crypto_provider() {
        let token = mint(12345, TEST_PEM).expect("mint should sign an RS256 JWT");
        // header.payload.signature
        assert_eq!(
            token.split('.').count(),
            3,
            "JWT should have three segments"
        );
    }
}
