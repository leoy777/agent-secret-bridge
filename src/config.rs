use std::{collections::HashSet, fs, path::Path};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::Url;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default = "default_version")]
    pub version: u32,
    #[serde(default)]
    pub vault: VaultConfig,
    #[serde(default)]
    pub audit: AuditConfig,
    #[serde(default)]
    pub capabilities: Vec<Capability>,
    #[serde(default)]
    pub ssh_capabilities: Vec<SshCapability>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum VaultConfig {
    #[default]
    System,
    EncryptedFile {
        path: String,
        key_file: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditConfig {
    #[serde(default = "default_audit_path")]
    pub path: String,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            path: default_audit_path(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Capability {
    pub id: String,
    pub credential: String,
    pub transport: Transport,
    pub allow: AllowRules,
    #[serde(default)]
    pub limits: Limits,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Transport {
    Http {
        base_url: String,
        auth: HttpAuth,
        #[serde(default)]
        allow_insecure_http: bool,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum HttpAuth {
    Basic { username: String },
    Bearer,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllowRules {
    pub methods: Vec<String>,
    pub paths: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
    #[serde(default = "default_response_bytes")]
    pub max_response_bytes: usize,
    #[serde(default = "default_requests_per_minute")]
    pub max_requests_per_minute: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SshCapability {
    pub id: String,
    pub host: String,
    #[serde(default = "default_ssh_port")]
    pub port: u16,
    pub user: String,
    pub known_hosts_file: String,
    pub identity_public_key_file: String,
    pub operations: Vec<SshOperation>,
    #[serde(default)]
    pub limits: Limits,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SshOperation {
    pub id: String,
    pub command: Vec<String>,
    #[serde(default)]
    pub read_only: bool,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            timeout_seconds: default_timeout(),
            max_response_bytes: default_response_bytes(),
            max_requests_per_minute: default_requests_per_minute(),
        }
    }
}

fn default_version() -> u32 {
    1
}

fn default_timeout() -> u64 {
    15
}

fn default_response_bytes() -> usize {
    256 * 1024
}

fn default_requests_per_minute() -> u32 {
    60
}

fn default_ssh_port() -> u16 {
    22
}

fn default_audit_path() -> String {
    "asb-audit.jsonl".to_owned()
}

impl Config {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        Self::load_pinned(path, None)
    }

    pub fn load_pinned(path: impl AsRef<Path>, expected_sha256: Option<&str>) -> Result<Self> {
        let path = path.as_ref();
        validate_config_file(path)?;
        let raw = fs::read_to_string(path)
            .with_context(|| format!("failed to read config {}", path.display()))?;
        if let Some(expected) = expected_sha256 {
            let expected = expected.strip_prefix("sha256:").unwrap_or(expected);
            if expected.len() != 64 || !expected.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                bail!("config SHA-256 pin must contain exactly 64 hexadecimal characters");
            }
            let actual = sha256_bytes(raw.as_bytes());
            if !actual.eq_ignore_ascii_case(expected) {
                bail!(
                    "config SHA-256 mismatch for {}; expected {}, got {}",
                    path.display(),
                    expected.to_ascii_lowercase(),
                    actual
                );
            }
        }
        let config: Self = serde_yml::from_str(&raw)
            .with_context(|| format!("failed to parse config {}", path.display()))?;
        config.validate()?;
        Ok(config)
    }

    pub fn sha256(path: impl AsRef<Path>) -> Result<String> {
        let path = path.as_ref();
        validate_config_file(path)?;
        let raw =
            fs::read(path).with_context(|| format!("failed to read config {}", path.display()))?;
        Ok(sha256_bytes(&raw))
    }

    pub fn validate(&self) -> Result<()> {
        if self.version != 1 {
            bail!("unsupported config version {}; expected 1", self.version);
        }

        if let VaultConfig::EncryptedFile { path, key_file } = &self.vault {
            validate_vault_path("vault path", path)?;
            validate_vault_path("vault key_file", key_file)?;
            if path == key_file {
                bail!("vault path and key_file must be different files");
            }
        }

        let mut ids = HashSet::new();
        for capability in &self.capabilities {
            capability.validate()?;
            if !ids.insert(&capability.id) {
                bail!("duplicate capability id {:?}", capability.id);
            }
        }
        for capability in &self.ssh_capabilities {
            capability.validate()?;
            if !ids.insert(&capability.id) {
                bail!("duplicate capability id {:?}", capability.id);
            }
        }
        Ok(())
    }

    pub fn capability(&self, id: &str) -> Option<&Capability> {
        self.capabilities
            .iter()
            .find(|capability| capability.id == id)
    }

    pub fn ssh_capability(&self, id: &str) -> Option<&SshCapability> {
        self.ssh_capabilities
            .iter()
            .find(|capability| capability.id == id)
    }
}

fn sha256_bytes(raw: &[u8]) -> String {
    format!("{:x}", Sha256::digest(raw))
}

fn validate_config_file(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("config {} is unavailable", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!(
            "config {} must be a regular non-symlink file",
            path.display()
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o022 != 0 {
            bail!(
                "config {} must not be group- or world-writable",
                path.display()
            );
        }
    }
    Ok(())
}

fn validate_vault_path(label: &str, value: &str) -> Result<()> {
    if !Path::new(value).is_absolute() || value.contains('\0') {
        bail!("{label} must be an absolute NUL-free path");
    }
    Ok(())
}

impl Capability {
    fn validate(&self) -> Result<()> {
        validate_identifier("capability id", &self.id)?;
        validate_identifier("credential id", &self.credential)?;

        if self.allow.methods.is_empty() || self.allow.paths.is_empty() {
            bail!(
                "capability {:?} must allow at least one method and path",
                self.id
            );
        }

        let allowed_methods = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"];
        for method in &self.allow.methods {
            if method != &method.to_ascii_uppercase() || !allowed_methods.contains(&method.as_str())
            {
                bail!(
                    "capability {:?} has unsupported HTTP method {:?}",
                    self.id,
                    method
                );
            }
        }

        for path in &self.allow.paths {
            validate_policy_path(path)
                .with_context(|| format!("invalid path rule in capability {:?}", self.id))?;
        }

        if self.limits.timeout_seconds == 0 || self.limits.timeout_seconds > 300 {
            bail!(
                "capability {:?} timeout must be between 1 and 300 seconds",
                self.id
            );
        }
        if self.limits.max_response_bytes == 0 || self.limits.max_response_bytes > 4 * 1024 * 1024 {
            bail!(
                "capability {:?} max_response_bytes must be between 1 and 4194304",
                self.id
            );
        }
        validate_rate_limit(&self.id, self.limits.max_requests_per_minute)?;

        match &self.transport {
            Transport::Http {
                base_url,
                allow_insecure_http,
                ..
            } => {
                let url = Url::parse(base_url)
                    .with_context(|| format!("capability {:?} has invalid base_url", self.id))?;
                if url.username() != "" || url.password().is_some() {
                    bail!(
                        "capability {:?} base_url must not contain credentials",
                        self.id
                    );
                }
                if url.query().is_some() || url.fragment().is_some() {
                    bail!(
                        "capability {:?} base_url must not contain query or fragment",
                        self.id
                    );
                }
                if url.host_str().is_none() {
                    bail!("capability {:?} base_url must contain a host", self.id);
                }
                match url.scheme() {
                    "https" => {}
                    "http" if *allow_insecure_http => {}
                    "http" => bail!(
                        "capability {:?} uses HTTP without allow_insecure_http: true",
                        self.id
                    ),
                    scheme => bail!(
                        "capability {:?} uses unsupported scheme {:?}",
                        self.id,
                        scheme
                    ),
                }
            }
        }

        Ok(())
    }
}

impl SshCapability {
    fn validate(&self) -> Result<()> {
        validate_identifier("SSH capability id", &self.id)?;
        validate_identifier("SSH user", &self.user)?;
        if self.port == 0 {
            bail!("SSH capability {:?} port must not be zero", self.id);
        }
        url::Host::parse(&self.host)
            .with_context(|| format!("SSH capability {:?} has invalid host", self.id))?;

        validate_absolute_path("known_hosts_file", &self.known_hosts_file, &self.id)?;
        validate_absolute_path(
            "identity_public_key_file",
            &self.identity_public_key_file,
            &self.id,
        )?;

        if self.operations.is_empty() {
            bail!(
                "SSH capability {:?} must define at least one operation",
                self.id
            );
        }
        validate_rate_limit(&self.id, self.limits.max_requests_per_minute)?;
        let mut operation_ids = HashSet::new();
        for operation in &self.operations {
            validate_identifier("SSH operation id", &operation.id)?;
            if !operation_ids.insert(&operation.id) {
                bail!(
                    "SSH capability {:?} has duplicate operation {:?}",
                    self.id,
                    operation.id
                );
            }
            if operation.command.is_empty()
                || operation
                    .command
                    .iter()
                    .any(|part| part.is_empty() || part.contains('\0'))
            {
                bail!(
                    "SSH capability {:?} operation {:?} must have a non-empty NUL-free command",
                    self.id,
                    operation.id
                );
            }
        }

        validate_limits(&self.limits, &self.id)
    }
}

fn validate_absolute_path(label: &str, value: &str, capability_id: &str) -> Result<()> {
    if !Path::new(value).is_absolute() || value.contains('\0') {
        bail!("SSH capability {capability_id:?} {label} must be an absolute NUL-free path");
    }
    Ok(())
}

fn validate_limits(limits: &Limits, capability_id: &str) -> Result<()> {
    if limits.timeout_seconds == 0 || limits.timeout_seconds > 300 {
        bail!("capability {capability_id:?} timeout must be between 1 and 300 seconds");
    }
    if limits.max_response_bytes == 0 || limits.max_response_bytes > 4 * 1024 * 1024 {
        bail!("capability {capability_id:?} max_response_bytes must be between 1 and 4194304");
    }
    Ok(())
}

fn validate_rate_limit(capability_id: &str, maximum: u32) -> Result<()> {
    if maximum == 0 || maximum > 60_000 {
        bail!("capability {capability_id:?} max_requests_per_minute must be between 1 and 60000");
    }
    Ok(())
}

fn validate_identifier(label: &str, value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        bail!("{label} must contain only ASCII letters, digits, '.', '_' or '-'");
    }
    Ok(())
}

fn validate_policy_path(path: &str) -> Result<()> {
    let exact = path.strip_suffix("/*").unwrap_or(path);
    if !exact.starts_with('/')
        || exact.starts_with("//")
        || exact.contains("\\")
        || exact.contains('?')
        || exact.contains('#')
        || exact.split('/').any(|part| matches!(part, "." | ".."))
        || (path.contains('*') && !path.ends_with("/*"))
    {
        bail!("paths must be absolute URL paths; only a terminal /* prefix rule is supported");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_yaml(base_url: &str, extra: &str) -> String {
        format!(
            r#"
version: 1
capabilities:
  - id: test
    credential: test-secret
    transport:
      type: http
      base_url: {base_url}
      auth:
        type: bearer
      {extra}
    allow:
      methods: [GET]
      paths: [/api/*]
"#
        )
    }

    #[test]
    fn rejects_insecure_http_by_default() {
        let config: Config = serde_yml::from_str(&config_yaml("http://example.com", "")).unwrap();
        assert!(config.validate().is_err());
    }

    #[test]
    fn accepts_explicit_insecure_http() {
        let config: Config = serde_yml::from_str(&config_yaml(
            "http://127.0.0.1:8080",
            "allow_insecure_http: true",
        ))
        .unwrap();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn rejects_ambiguous_path_rules() {
        for path in ["//evil.example/x", "/api/../admin", "/api?x=1", "/api/*/x"] {
            assert!(validate_policy_path(path).is_err(), "accepted {path}");
        }
    }

    #[test]
    fn verifies_config_sha256_pin() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("asb.yaml");
        std::fs::write(&path, config_yaml("https://example.com", "")).unwrap();
        let hash = Config::sha256(&path).unwrap();
        assert!(Config::load_pinned(&path, Some(&hash)).is_ok());
        assert!(Config::load_pinned(&path, Some(&"0".repeat(64))).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_writable_config_files() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("asb.yaml");
        std::fs::write(&path, config_yaml("https://example.com", "")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(Config::load(&path).is_err());
    }
}
