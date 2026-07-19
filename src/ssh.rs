use std::{path::Path, process::Stdio, sync::Arc, time::Duration};

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    process::Command,
    time::timeout,
};

use crate::{
    Config,
    audit::AuditLog,
    config::{SshCapability, SshOperation},
    rate_limit::RateLimiter,
};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SshExecuteInput {
    pub capability_id: String,
    pub operation_id: String,
}

#[derive(Debug, Serialize)]
pub struct SshExecuteOutput {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub truncated: bool,
}

pub struct SshBroker {
    config: Arc<Config>,
    audit: Arc<AuditLog>,
    rate_limiter: Arc<RateLimiter>,
}

struct Captured {
    bytes: Vec<u8>,
    truncated: bool,
}

impl SshBroker {
    pub fn new(config: Arc<Config>, audit: Arc<AuditLog>, rate_limiter: Arc<RateLimiter>) -> Self {
        Self {
            config,
            audit,
            rate_limiter,
        }
    }

    pub async fn execute(
        &self,
        input: SshExecuteInput,
        require_read_only: bool,
    ) -> Result<SshExecuteOutput> {
        let capability = self
            .config
            .ssh_capability(&input.capability_id)
            .ok_or_else(|| anyhow!("unknown SSH capability {:?}", input.capability_id))?;
        let operation = capability
            .operations
            .iter()
            .find(|operation| operation.id == input.operation_id)
            .ok_or_else(|| {
                anyhow!(
                    "unknown operation {:?} for SSH capability {:?}",
                    input.operation_id,
                    input.capability_id
                )
            })?;

        if require_read_only && !operation.read_only {
            bail!("operation {:?} is not marked read_only", operation.id);
        }
        if !require_read_only && operation.read_only {
            bail!("read-only operations must use the ssh_read tool");
        }
        let audit_action = if require_read_only {
            "ssh_read"
        } else {
            "ssh_execute"
        };

        if let Err(error) = self
            .rate_limiter
            .check(
                &input.capability_id,
                capability.limits.max_requests_per_minute,
            )
            .await
        {
            let target = format!(
                "ssh://{}@{}:{}/{}",
                capability.user, capability.host, capability.port, operation.id
            );
            let _ = self.audit.record(
                &input.capability_id,
                audit_action,
                &target,
                "denied",
                Some("rate_limited"),
            );
            return Err(error);
        }

        validate_runtime_files(capability)?;
        let target = format!(
            "ssh://{}@{}:{}/{}",
            capability.user, capability.host, capability.port, operation.id
        );
        let mut command = build_command(capability, operation);
        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(error) => {
                let _ = self.audit.record(
                    &input.capability_id,
                    audit_action,
                    &target,
                    "error",
                    Some("spawn_error"),
                );
                return Err(error).context("failed to start system SSH client");
            }
        };

        let stdout = child
            .stdout
            .take()
            .context("failed to capture SSH stdout")?;
        let stderr = child
            .stderr
            .take()
            .context("failed to capture SSH stderr")?;
        let max_bytes = capability.limits.max_response_bytes;
        let stdout_task = tokio::spawn(read_limited(stdout, max_bytes));
        let stderr_task = tokio::spawn(read_limited(stderr, max_bytes));

        let status = match timeout(
            Duration::from_secs(capability.limits.timeout_seconds),
            child.wait(),
        )
        .await
        {
            Ok(status) => status.context("failed waiting for SSH process")?,
            Err(_) => {
                let _ = child.kill().await;
                let _ = child.wait().await;
                let _ = stdout_task.await;
                let _ = stderr_task.await;
                self.audit.record(
                    &input.capability_id,
                    audit_action,
                    &target,
                    "error",
                    Some("timeout"),
                )?;
                bail!("SSH operation timed out");
            }
        };

        let stdout = stdout_task.await.context("SSH stdout task failed")??;
        let stderr = stderr_task.await.context("SSH stderr task failed")??;
        let exit_code = status.code().unwrap_or(-1);
        let outcome = if status.success() {
            "completed"
        } else {
            "failed"
        };
        self.audit.record(
            &input.capability_id,
            audit_action,
            &target,
            outcome,
            (!status.success()).then_some("remote_nonzero_exit"),
        )?;

        Ok(SshExecuteOutput {
            exit_code,
            stdout: String::from_utf8_lossy(&stdout.bytes).into_owned(),
            stderr: String::from_utf8_lossy(&stderr.bytes).into_owned(),
            truncated: stdout.truncated || stderr.truncated,
        })
    }
}

pub fn validate_runtime_files(capability: &SshCapability) -> Result<()> {
    validate_security_file("known_hosts_file", Path::new(&capability.known_hosts_file))?;
    let public_key_path = Path::new(&capability.identity_public_key_file);
    validate_security_file("identity_public_key_file", public_key_path)?;
    validate_public_key(public_key_path)?;
    #[cfg(unix)]
    if std::env::var_os("SSH_AUTH_SOCK").is_none() {
        bail!("SSH_AUTH_SOCK is unavailable; load the private key into ssh-agent first");
    }
    Ok(())
}

fn validate_public_key(path: &Path) -> Result<()> {
    let value = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read public key selector {}", path.display()))?;
    if value.len() > 16 * 1024 {
        bail!("public key selector {} exceeds 16384 bytes", path.display());
    }
    let algorithm = value.split_whitespace().next().unwrap_or_default();
    if !algorithm.starts_with("ssh-")
        && !algorithm.starts_with("ecdsa-")
        && !algorithm.starts_with("sk-")
    {
        bail!(
            "identity_public_key_file {} is not an OpenSSH public key",
            path.display()
        );
    }
    Ok(())
}

fn validate_security_file(label: &str, path: &Path) -> Result<()> {
    let metadata = std::fs::metadata(path)
        .with_context(|| format!("{label} {} is unavailable", path.display()))?;
    if !metadata.is_file() {
        bail!("{label} {} is not a regular file", path.display());
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o022 != 0 {
            bail!(
                "{label} {} must not be group- or world-writable",
                path.display()
            );
        }
    }
    Ok(())
}

fn build_command(capability: &SshCapability, operation: &SshOperation) -> Command {
    let mut command = Command::new(system_ssh_path());
    command
        .arg("-F")
        .arg("none")
        .arg("-T")
        .arg("-p")
        .arg(capability.port.to_string())
        .arg("-l")
        .arg(&capability.user)
        .arg("-o")
        .arg("BatchMode=yes")
        .arg("-o")
        .arg("PasswordAuthentication=no")
        .arg("-o")
        .arg("KbdInteractiveAuthentication=no")
        .arg("-o")
        .arg("StrictHostKeyChecking=yes")
        .arg("-o")
        .arg(format!(
            "UserKnownHostsFile={}",
            capability.known_hosts_file
        ))
        .arg("-o")
        .arg("GlobalKnownHostsFile=none")
        .arg("-o")
        .arg("UpdateHostKeys=no")
        .arg("-o")
        .arg("VerifyHostKeyDNS=no")
        .arg("-o")
        .arg("ForwardAgent=no")
        .arg("-o")
        .arg("ClearAllForwardings=yes")
        .arg("-o")
        .arg("PermitLocalCommand=no")
        .arg("-o")
        .arg("RequestTTY=no")
        .arg("-o")
        .arg(format!(
            "ConnectTimeout={}",
            capability.limits.timeout_seconds.min(60)
        ))
        .arg("-o")
        .arg("ConnectionAttempts=1")
        .arg("-o")
        .arg("LogLevel=ERROR");

    command
        .arg("-o")
        .arg("IdentitiesOnly=yes")
        .arg("-i")
        .arg(&capability.identity_public_key_file);

    command
        .arg("--")
        .arg(&capability.host)
        .args(&operation.command)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    command
}

#[cfg(unix)]
fn system_ssh_path() -> &'static str {
    "/usr/bin/ssh"
}

#[cfg(windows)]
fn system_ssh_path() -> &'static str {
    r"C:\Windows\System32\OpenSSH\ssh.exe"
}

async fn read_limited<R>(mut reader: R, limit: usize) -> Result<Captured>
where
    R: AsyncRead + Unpin,
{
    let mut kept = Vec::with_capacity(limit.min(8192));
    let mut buffer = [0_u8; 8192];
    let mut truncated = false;
    loop {
        let count = reader.read(&mut buffer).await?;
        if count == 0 {
            break;
        }
        let remaining = limit.saturating_sub(kept.len());
        kept.extend_from_slice(&buffer[..count.min(remaining)]);
        if count > remaining {
            truncated = true;
        }
    }
    Ok(Captured {
        bytes: kept,
        truncated,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Limits;

    fn capability() -> SshCapability {
        SshCapability {
            id: "ubuntu-status".into(),
            host: "10.0.0.20".into(),
            port: 22,
            user: "codex-maint".into(),
            known_hosts_file: "/secure/known_hosts".into(),
            identity_public_key_file: "/secure/id_ed25519.pub".into(),
            operations: vec![],
            limits: Limits::default(),
        }
    }

    #[test]
    fn command_ignores_user_ssh_config_and_forwards() {
        let operation = SshOperation {
            id: "uptime".into(),
            command: vec!["/usr/bin/uptime".into()],
            read_only: true,
        };
        let command = build_command(&capability(), &operation);
        let args: Vec<String> = command
            .as_std()
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();

        assert!(args.windows(2).any(|pair| pair == ["-F", "none"]));
        assert!(args.iter().any(|arg| arg == "StrictHostKeyChecking=yes"));
        assert!(args.iter().any(|arg| arg == "ClearAllForwardings=yes"));
        assert!(args.iter().any(|arg| arg == "ForwardAgent=no"));
        assert_eq!(args.last().map(String::as_str), Some("/usr/bin/uptime"));
    }

    #[test]
    fn accepts_public_key_selector_and_rejects_private_key_material() {
        let directory = tempfile::tempdir().unwrap();
        let public = directory.path().join("key.pub");
        let private = directory.path().join("key");
        std::fs::write(&public, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest asb\n").unwrap();
        std::fs::write(
            &private,
            "-----BEGIN OPENSSH PRIVATE KEY-----\nnot-a-real-key\n",
        )
        .unwrap();

        assert!(validate_public_key(&public).is_ok());
        assert!(validate_public_key(&private).is_err());
    }
}
