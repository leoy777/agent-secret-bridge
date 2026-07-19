use anyhow::{Result, bail};
use url::Url;

use crate::config::{Capability, Transport};

pub struct AuthorizedRequest {
    pub method: String,
    pub url: Url,
}

pub fn authorize_http(
    capability: &Capability,
    method: &str,
    requested_path: &str,
) -> Result<AuthorizedRequest> {
    let method = method.to_ascii_uppercase();
    if !capability
        .allow
        .methods
        .iter()
        .any(|allowed| allowed == &method)
    {
        bail!(
            "method {method} is not allowed by capability {}",
            capability.id
        );
    }

    validate_requested_path(requested_path)?;

    let Transport::Http { base_url, .. } = &capability.transport;
    let base = Url::parse(base_url)?;
    let resolved = base.join(requested_path)?;

    if base.scheme() != resolved.scheme()
        || base.host_str() != resolved.host_str()
        || base.port_or_known_default() != resolved.port_or_known_default()
    {
        bail!("request target escapes the capability origin");
    }

    let normalized_path = resolved.path();
    if !capability
        .allow
        .paths
        .iter()
        .any(|rule| path_matches(rule, normalized_path))
    {
        bail!(
            "path {normalized_path} is not allowed by capability {}",
            capability.id
        );
    }

    Ok(AuthorizedRequest {
        method,
        url: resolved,
    })
}

fn validate_requested_path(path: &str) -> Result<()> {
    let path_only = path.split_once('?').map_or(path, |(head, _)| head);
    if !path.starts_with('/')
        || path.starts_with("//")
        || path.contains("\\")
        || path.contains('#')
        || path.contains("://")
        || path_only.split('/').any(|part| matches!(part, "." | ".."))
    {
        bail!("request path must be an origin-relative URL path");
    }
    Ok(())
}

fn path_matches(rule: &str, requested: &str) -> bool {
    match rule.strip_suffix("/*") {
        Some(prefix) => requested == prefix || requested.starts_with(&format!("{prefix}/")),
        None => requested == rule,
    }
}

#[cfg(test)]
mod tests {
    use crate::config::{AllowRules, HttpAuth, Limits};

    use super::*;

    fn capability() -> Capability {
        Capability {
            id: "test".into(),
            credential: "secret".into(),
            transport: Transport::Http {
                base_url: "https://device.example/root/".into(),
                auth: HttpAuth::Bearer,
                allow_insecure_http: false,
            },
            allow: AllowRules {
                methods: vec!["GET".into()],
                paths: vec!["/api/*".into(), "/health".into()],
            },
            limits: Limits::default(),
        }
    }

    #[test]
    fn allows_exact_origin_and_prefix() {
        let result = authorize_http(&capability(), "get", "/api/info?short=1").unwrap();
        assert_eq!(
            result.url.as_str(),
            "https://device.example/api/info?short=1"
        );
    }

    #[test]
    fn rejects_origin_escape_and_dot_segments() {
        for path in ["//evil.example/", "/api/../admin", "https://evil.example/"] {
            assert!(
                authorize_http(&capability(), "GET", path).is_err(),
                "accepted {path}"
            );
        }
    }

    #[test]
    fn prefix_does_not_match_similar_name() {
        assert!(authorize_http(&capability(), "GET", "/apiary/x").is_err());
    }
}
