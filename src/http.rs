use std::{sync::Arc, time::Duration};

use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use reqwest::{Client, Method, redirect::Policy};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{
    audit::AuditLog,
    config::{Config, HttpAuth, Transport},
    policy::authorize_http,
    rate_limit::RateLimiter,
    redact::redact_text,
    vault::Vault,
};

const MAX_CREDENTIAL_BYTES: usize = 64 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpRequestInput {
    pub capability_id: String,
    pub method: String,
    pub path: String,
    #[serde(default)]
    pub body: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct HttpResponseOutput {
    pub status: u16,
    pub content_type: Option<String>,
    pub body: String,
    pub truncated: bool,
}

pub struct HttpBroker {
    config: Arc<Config>,
    vault: Arc<dyn Vault>,
    audit: Arc<AuditLog>,
    rate_limiter: Arc<RateLimiter>,
}

impl HttpBroker {
    pub fn new(
        config: Arc<Config>,
        vault: Arc<dyn Vault>,
        audit: Arc<AuditLog>,
        rate_limiter: Arc<RateLimiter>,
    ) -> Self {
        Self {
            config,
            vault,
            audit,
            rate_limiter,
        }
    }

    pub async fn execute(&self, input: HttpRequestInput) -> Result<HttpResponseOutput> {
        let capability = self
            .config
            .capability(&input.capability_id)
            .ok_or_else(|| anyhow!("unknown capability {:?}", input.capability_id))?;

        let authorized = match authorize_http(capability, &input.method, &input.path) {
            Ok(value) => value,
            Err(error) => {
                let _ = self.audit.record(
                    &input.capability_id,
                    "http_request",
                    &input.path,
                    "denied",
                    Some("policy_denied"),
                );
                return Err(error);
            }
        };

        if let Err(error) = self
            .rate_limiter
            .check(
                &input.capability_id,
                capability.limits.max_requests_per_minute,
            )
            .await
        {
            let _ = self.audit.record(
                &input.capability_id,
                "http_request",
                authorized.url.as_str(),
                "denied",
                Some("rate_limited"),
            );
            return Err(error);
        }

        if matches!(authorized.method.as_str(), "GET" | "HEAD") && input.body.is_some() {
            bail!("GET and HEAD requests cannot include a body");
        }

        let secret = self.vault.get(&capability.credential).await?;
        if secret.expose_secret().len() > MAX_CREDENTIAL_BYTES {
            bail!("credential exceeds the 65536-byte safety limit");
        }
        let method = Method::from_bytes(authorized.method.as_bytes())?;
        let client = Client::builder()
            .redirect(Policy::none())
            .timeout(Duration::from_secs(capability.limits.timeout_seconds))
            .build()
            .context("failed to create HTTP client")?;

        let mut request = client.request(method, authorized.url.clone());
        let mut derived_secret: Option<SecretString> = None;
        let Transport::Http { auth, .. } = &capability.transport;
        request = match auth {
            HttpAuth::Basic { username } => {
                let credentials = Zeroizing::new(format!("{username}:{}", secret.expose_secret()));
                let encoded = STANDARD.encode(credentials.as_bytes());
                request = request.header("Authorization", format!("Basic {encoded}"));
                derived_secret = Some(SecretString::from(encoded));
                request
            }
            HttpAuth::Bearer => request.bearer_auth(secret.expose_secret()),
        };

        if let Some(body) = input.body {
            request = request
                .header("Content-Type", "application/json")
                .body(body);
        }

        let mut response = match request.send().await {
            Ok(value) => value,
            Err(error) => {
                let _ = self.audit.record(
                    &input.capability_id,
                    "http_request",
                    authorized.url.as_str(),
                    "error",
                    Some("transport_error"),
                );
                return Err(error).context("HTTP request failed");
            }
        };

        let mut redactions = vec![&secret];
        if let Some(derived) = &derived_secret {
            redactions.push(derived);
        }

        let status = response.status().as_u16();
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(|value| redact_text(value, &redactions));
        // Read enough overlap to recognize a secret that begins immediately before the
        // visible response boundary. Redaction happens before the final truncation.
        let overlap = derived_secret
            .as_ref()
            .map_or(secret.expose_secret().len(), |derived| {
                derived
                    .expose_secret()
                    .len()
                    .max(secret.expose_secret().len())
            });
        let read_limit = capability.limits.max_response_bytes.saturating_add(overlap);
        let mut bytes = Vec::with_capacity(read_limit.min(8192));
        let mut truncated = false;
        while let Some(chunk) = response
            .chunk()
            .await
            .context("failed to read HTTP response")?
        {
            let remaining = read_limit.saturating_sub(bytes.len());
            if chunk.len() > remaining {
                bytes.extend_from_slice(&chunk[..remaining]);
                truncated = true;
                break;
            }
            bytes.extend_from_slice(&chunk);
        }
        let raw_body = String::from_utf8_lossy(&bytes);
        let mut body = redact_text(&raw_body, &redactions);
        if body.len() > capability.limits.max_response_bytes {
            let mut end = capability.limits.max_response_bytes;
            while !body.is_char_boundary(end) {
                end -= 1;
            }
            body.truncate(end);
            truncated = true;
        }

        self.audit.record(
            &input.capability_id,
            "http_request",
            authorized.url.as_str(),
            "completed",
            None,
        )?;

        Ok(HttpResponseOutput {
            status,
            content_type,
            body,
            truncated,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use base64::{Engine, engine::general_purpose::STANDARD};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    use crate::{
        audit::AuditLog,
        config::{AllowRules, AuditConfig, Capability, HttpAuth, Limits, Transport},
        vault::testing::MemoryVault,
    };

    use super::*;

    #[tokio::test]
    async fn basic_auth_is_injected_locally_and_redacted_from_response() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = vec![0_u8; 8192];
            let count = stream.read(&mut request).await.unwrap();
            let request = String::from_utf8_lossy(&request[..count]);
            let authorization = request
                .lines()
                .find(|line| line.to_ascii_lowercase().starts_with("authorization:"))
                .unwrap();
            let body = format!("echo={authorization}");
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(response.as_bytes()).await.unwrap();
        });

        let config = Arc::new(Config {
            version: 1,
            vault: crate::config::VaultConfig::System,
            audit: AuditConfig::default(),
            capabilities: vec![Capability {
                id: "local-test".into(),
                credential: "local-secret".into(),
                transport: Transport::Http {
                    base_url: format!("http://{address}"),
                    auth: HttpAuth::Basic {
                        username: "tester".into(),
                    },
                    allow_insecure_http: true,
                },
                allow: AllowRules {
                    methods: vec!["GET".into()],
                    paths: vec!["/echo".into()],
                },
                limits: Limits {
                    timeout_seconds: 15,
                    max_response_bytes: 40,
                    max_requests_per_minute: 60,
                },
            }],
            ssh_capabilities: vec![],
        });
        config.validate().unwrap();

        let secret = "not-for-the-model";
        let derived = STANDARD.encode(format!("tester:{secret}"));
        let vault = Arc::new(MemoryVault::with_secret("local-secret", secret));
        let temp = tempfile::tempdir().unwrap();
        let audit = Arc::new(AuditLog::new(temp.path().join("audit.jsonl")));
        let broker = HttpBroker::new(config, vault, audit, Arc::new(RateLimiter::default()));

        let output = broker
            .execute(HttpRequestInput {
                capability_id: "local-test".into(),
                method: "GET".into(),
                path: "/echo".into(),
                body: None,
            })
            .await
            .unwrap();
        server.await.unwrap();

        assert_eq!(output.status, 200);
        assert!(!output.body.contains(secret));
        assert!(!output.body.contains(&derived));
        assert!(!output.body.contains(&derived[..12]));
        assert!(output.body.contains("[REDACTED]"));
    }
}
