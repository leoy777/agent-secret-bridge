use std::{path::PathBuf, sync::Arc};

use agent_secret_bridge::{
    Config,
    audit::AuditLog,
    config::VaultConfig,
    http::HttpBroker,
    mcp::McpServer,
    rate_limit::RateLimiter,
    ssh::SshBroker,
    vault::{EncryptedFileVault, SystemVault, Vault, from_config},
};
use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use secrecy::SecretString;
use zeroize::Zeroizing;

#[derive(Debug, Parser)]
#[command(
    name = "asb",
    version,
    about = "Local capability broker for agent credentials"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the MCP server over stdin/stdout.
    Serve {
        #[arg(long, default_value = "asb.yaml")]
        config: PathBuf,
        #[arg(long)]
        config_sha256: Option<String>,
    },
    /// Run a privileged broker on a local Unix socket (Linux/macOS).
    Daemon {
        #[arg(long, default_value = "asb.yaml")]
        config: PathBuf,
        #[arg(long)]
        config_sha256: Option<String>,
        #[arg(long)]
        socket: PathBuf,
    },
    /// Bridge STDIO MCP to an isolated local broker socket (Linux/macOS).
    Proxy {
        #[arg(long)]
        socket: PathBuf,
    },
    /// Validate configuration without accessing credentials.
    Check {
        #[arg(long, default_value = "asb.yaml")]
        config: PathBuf,
        #[arg(long)]
        config_sha256: Option<String>,
    },
    /// Diagnose configuration, local security files, and SSH agent readiness.
    Doctor {
        #[arg(long, default_value = "asb.yaml")]
        config: PathBuf,
        #[arg(long)]
        config_sha256: Option<String>,
    },
    /// Inspect security-sensitive configuration metadata.
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    /// Manage credentials in the operating system credential store.
    Secret {
        /// Configuration selecting the credential backend. Defaults to the OS store.
        #[arg(long)]
        config: Option<PathBuf>,
        #[command(subcommand)]
        command: SecretCommand,
    },
    /// Manage an encrypted headless/VPS vault.
    Vault {
        #[command(subcommand)]
        command: VaultCommand,
    },
}

#[derive(Debug, Subcommand)]
enum SecretCommand {
    /// Add or replace a credential. Input is read from a hidden terminal prompt.
    Add { id: String },
    /// Delete a credential from the operating system credential store.
    Delete { id: String },
}

#[derive(Debug, Subcommand)]
enum VaultCommand {
    /// Create a new encrypted vault and a separate owner-only master key file.
    Init {
        #[arg(long, default_value = "asb.yaml")]
        config: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum ConfigCommand {
    /// Print the SHA-256 value used to pin a configuration file.
    Hash {
        #[arg(long, default_value = "asb.yaml")]
        config: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Serve {
            config,
            config_sha256,
        } => serve(config, config_sha256).await,
        Command::Daemon {
            config,
            config_sha256,
            socket,
        } => daemon(config, config_sha256, socket).await,
        Command::Proxy { socket } => proxy(socket).await,
        Command::Check {
            config,
            config_sha256,
        } => {
            let config = Config::load_pinned(&config, config_sha256.as_deref())?;
            let http_count = config.capabilities.len();
            let ssh_count = config.ssh_capabilities.len();
            eprintln!(
                "configuration is valid: {} capabilities ({} HTTP, {} SSH)",
                http_count + ssh_count,
                http_count,
                ssh_count
            );
            Ok(())
        }
        Command::Doctor {
            config,
            config_sha256,
        } => doctor(config, config_sha256).await,
        Command::Config { command } => match command {
            ConfigCommand::Hash { config } => {
                println!("{}", Config::sha256(config)?);
                Ok(())
            }
        },
        Command::Secret { config, command } => secret(config, command).await,
        Command::Vault { command } => vault(command),
    }
}

async fn serve(path: PathBuf, config_sha256: Option<String>) -> Result<()> {
    let config = Config::load_pinned(&path, config_sha256.as_deref())?;
    if matches!(config.vault, VaultConfig::EncryptedFile { .. }) {
        bail!("encrypted_file vaults require daemon + proxy isolation; direct STDIO is refused");
    }
    build_server(path, config_sha256.as_deref())?
        .serve_stdio()
        .await
}

fn build_server(path: PathBuf, config_sha256: Option<&str>) -> Result<McpServer> {
    let config = Arc::new(Config::load_pinned(&path, config_sha256)?);
    let audit_path = resolve_audit_path(&path, &config.audit.path);
    let vault = from_config(&config.vault)?;
    let audit = Arc::new(AuditLog::new(audit_path));
    let rate_limiter = Arc::new(RateLimiter::default());
    let broker = HttpBroker::new(config.clone(), vault, audit.clone(), rate_limiter.clone());
    let ssh = SshBroker::new(config.clone(), audit, rate_limiter);
    Ok(McpServer::new(config, broker, ssh))
}

#[cfg(unix)]
async fn daemon(config: PathBuf, config_sha256: Option<String>, socket: PathBuf) -> Result<()> {
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};
    use tokio::{
        net::{UnixListener, UnixStream},
        signal::unix::{SignalKind, signal},
    };

    if !socket.is_absolute() {
        bail!("daemon socket path must be absolute");
    }
    let parent = socket.parent().context("daemon socket has no parent")?;
    let metadata = std::fs::metadata(parent).with_context(|| {
        format!(
            "daemon socket directory {} is unavailable",
            parent.display()
        )
    })?;
    if !metadata.is_dir() || metadata.permissions().mode() & 0o007 != 0 {
        bail!("daemon socket directory must exist and must not be accessible by other users");
    }

    if socket.exists() {
        let socket_metadata = std::fs::symlink_metadata(&socket)?;
        if !socket_metadata.file_type().is_socket() {
            bail!("refusing to replace non-socket path {}", socket.display());
        }
        match UnixStream::connect(&socket).await {
            Ok(_) => bail!(
                "another ASB broker is already listening on {}",
                socket.display()
            ),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::NotFound
                ) =>
            {
                std::fs::remove_file(&socket).with_context(|| {
                    format!("failed to remove stale socket {}", socket.display())
                })?;
            }
            Err(error) => return Err(error).context("failed to inspect existing broker socket"),
        }
    }

    let server = Arc::new(build_server(config, config_sha256.as_deref())?);
    let listener = UnixListener::bind(&socket)
        .with_context(|| format!("failed to bind daemon socket {}", socket.display()))?;
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o660))?;
    eprintln!("ASB broker listening on {}", socket.display());

    let mut terminate = signal(SignalKind::terminate())?;

    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, _) = accepted?;
                let server = server.clone();
                tokio::spawn(async move {
                    let (reader, writer) = stream.into_split();
                    if let Err(error) = server.serve_io(reader, writer).await {
                        eprintln!("ASB broker client error: {error}");
                    }
                });
            }
            _ = tokio::signal::ctrl_c() => break,
            _ = terminate.recv() => break,
        }
    }
    drop(listener);
    std::fs::remove_file(&socket)
        .with_context(|| format!("failed to remove broker socket {}", socket.display()))?;
    Ok(())
}

#[cfg(not(unix))]
async fn daemon(_config: PathBuf, _config_sha256: Option<String>, _socket: PathBuf) -> Result<()> {
    bail!("daemon sockets are currently supported on Linux and macOS only")
}

#[cfg(unix)]
async fn proxy(socket: PathBuf) -> Result<()> {
    use tokio::{
        io::{AsyncWriteExt, copy},
        net::UnixStream,
    };

    if !socket.is_absolute() {
        bail!("proxy socket path must be absolute");
    }
    let stream = UnixStream::connect(&socket)
        .await
        .with_context(|| format!("failed to connect broker socket {}", socket.display()))?;
    let (mut broker_reader, mut broker_writer) = stream.into_split();

    let upload = tokio::spawn(async move {
        let mut stdin = tokio::io::stdin();
        copy(&mut stdin, &mut broker_writer).await?;
        broker_writer.shutdown().await
    });
    let download = tokio::spawn(async move {
        let mut stdout = tokio::io::stdout();
        copy(&mut broker_reader, &mut stdout).await?;
        stdout.flush().await
    });

    upload.await.context("proxy upload task failed")??;
    download.await.context("proxy download task failed")??;
    Ok(())
}

#[cfg(not(unix))]
async fn proxy(_socket: PathBuf) -> Result<()> {
    bail!("daemon sockets are currently supported on Linux and macOS only")
}

async fn doctor(path: PathBuf, config_sha256: Option<String>) -> Result<()> {
    let actual_hash = Config::sha256(&path)?;
    let config = Config::load_pinned(&path, config_sha256.as_deref())?;
    println!("ok  config: {}", path.display());
    println!("ok  config_sha256: {actual_hash}");
    if config_sha256.is_some() {
        println!("ok  config pin: matched");
    } else {
        println!("warn config pin: not supplied; use --config-sha256 {actual_hash}");
    }

    match &config.vault {
        VaultConfig::System => println!("ok  vault: system credential store selected"),
        VaultConfig::EncryptedFile { path, key_file } => {
            EncryptedFileVault::new(path.into(), key_file.into())?.validate_existing()?;
            println!("ok  vault: encrypted file authenticated and permissions accepted");
        }
    }

    for capability in &config.ssh_capabilities {
        agent_secret_bridge::ssh::validate_runtime_files(capability)
            .with_context(|| format!("SSH capability {:?} is not ready", capability.id))?;
        println!("ok  ssh capability: {}", capability.id);
    }
    println!(
        "ok  capabilities: {} HTTP, {} SSH",
        config.capabilities.len(),
        config.ssh_capabilities.len()
    );
    Ok(())
}

async fn secret(config_path: Option<PathBuf>, command: SecretCommand) -> Result<()> {
    let (vault, backend_name): (Arc<dyn Vault>, &str) = match config_path {
        Some(path) => {
            let config = Config::load(path)?;
            let backend_name = match &config.vault {
                VaultConfig::System => "system credential store",
                VaultConfig::EncryptedFile { .. } => "encrypted file vault",
            };
            (from_config(&config.vault)?, backend_name)
        }
        None => (Arc::new(SystemVault), "system credential store"),
    };
    match command {
        SecretCommand::Add { id } => {
            validate_id(&id)?;
            let first = Zeroizing::new(
                rpassword::prompt_password("Secret: ").context("failed to read secret")?,
            );
            if first.is_empty() {
                bail!("secret must not be empty");
            }
            let second = Zeroizing::new(
                rpassword::prompt_password("Confirm: ").context("failed to confirm secret")?,
            );
            if first != second {
                bail!("secret confirmation did not match");
            }
            vault
                .set(&id, &SecretString::from(first.as_str().to_owned()))
                .await?;
            eprintln!("stored credential {id:?} in the {backend_name}");
            Ok(())
        }
        SecretCommand::Delete { id } => {
            validate_id(&id)?;
            vault.delete(&id).await?;
            eprintln!("deleted credential {id:?}");
            Ok(())
        }
    }
}

fn vault(command: VaultCommand) -> Result<()> {
    match command {
        VaultCommand::Init { config } => {
            let config = Config::load(&config)?;
            let agent_secret_bridge::config::VaultConfig::EncryptedFile { path, key_file } =
                config.vault
            else {
                bail!("vault init requires vault.type: encrypted_file");
            };
            EncryptedFileVault::initialize(path.into(), key_file.into())?;
            eprintln!("initialized encrypted vault and owner-only key file");
            Ok(())
        }
    }
}

fn resolve_audit_path(config_path: &std::path::Path, configured: &str) -> PathBuf {
    let path = PathBuf::from(configured);
    if path.is_absolute() {
        path
    } else {
        config_path
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."))
            .join(path)
    }
}

fn validate_id(id: &str) -> Result<()> {
    if id.is_empty()
        || id.len() > 128
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        bail!("credential id must contain only ASCII letters, digits, '.', '_' or '-'");
    }
    Ok(())
}
