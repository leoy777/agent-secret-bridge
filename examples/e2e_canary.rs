use std::{
    path::PathBuf,
    process,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use agent_secret_bridge::vault::{SystemVault, Vault};
use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use clap::{Parser, Subcommand};
use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    time::timeout,
};
use zeroize::Zeroizing;

#[derive(Debug, Parser)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Store a locally generated canary and echo one received Authorization header.
    Serve {
        #[arg(long)]
        credential_id: String,
        #[arg(long, default_value_t = 38471)]
        port: u16,
    },
    /// Scan a Codex transcript for the canary, then delete it from the OS vault.
    Verify {
        #[arg(long)]
        credential_id: String,
        #[arg(long)]
        username: String,
        #[arg(long)]
        transcript: PathBuf,
    },
    /// Delete the canary after an interrupted test.
    Cleanup {
        #[arg(long)]
        credential_id: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    match Args::parse().command {
        Command::Serve {
            credential_id,
            port,
        } => serve(&credential_id, port).await,
        Command::Verify {
            credential_id,
            username,
            transcript,
        } => verify(&credential_id, &username, transcript).await,
        Command::Cleanup { credential_id } => cleanup(&credential_id).await,
    }
}

async fn serve(credential_id: &str, port: u16) -> Result<()> {
    let vault = SystemVault;
    let seed = format!(
        "{}:{}:{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("clock is before Unix epoch")?
            .as_nanos(),
        process::id(),
        port
    );
    let canary = SecretString::from(format!("asb-e2e-{:x}", Sha256::digest(seed.as_bytes())));
    vault.set(credential_id, &canary).await?;

    let listener = match TcpListener::bind(("127.0.0.1", port)).await {
        Ok(listener) => listener,
        Err(error) => {
            let _ = vault.delete(credential_id).await;
            return Err(error).context("failed to bind canary server");
        }
    };
    println!("ready: credential stored; listening on 127.0.0.1:{port}");

    let accepted = timeout(Duration::from_secs(300), listener.accept()).await;
    let (mut stream, _) = match accepted {
        Ok(Ok(value)) => value,
        Ok(Err(error)) => {
            let _ = vault.delete(credential_id).await;
            return Err(error).context("failed to accept canary request");
        }
        Err(_) => {
            let _ = vault.delete(credential_id).await;
            bail!("timed out waiting for canary request; credential removed");
        }
    };

    let mut request = Zeroizing::new(Vec::with_capacity(4096));
    loop {
        let mut chunk = [0_u8; 2048];
        let count = stream.read(&mut chunk).await?;
        if count == 0 {
            break;
        }
        request.extend_from_slice(&chunk[..count]);
        if request.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
        if request.len() > 64 * 1024 {
            bail!("canary request headers exceeded safety limit");
        }
    }

    let request_text = String::from_utf8_lossy(request.as_slice());
    let authorization = request_text
        .lines()
        .find_map(|line| {
            line.split_once(':').and_then(|(name, value)| {
                name.eq_ignore_ascii_case("authorization")
                    .then(|| value.trim().to_owned())
            })
        })
        .context("canary request did not contain Authorization header")?;
    let authorization = Zeroizing::new(authorization);
    let auth_hash = format!("{:x}", Sha256::digest(authorization.as_bytes()));
    let body = Zeroizing::new(format!(
        "{{\"authorization\":\"{}\",\"target_received_auth\":true}}",
        authorization.as_str()
    ));
    let response_head = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(response_head.as_bytes()).await?;
    stream.write_all(body.as_bytes()).await?;
    stream.shutdown().await?;

    println!("request received: authorization_sha256={auth_hash}");
    println!("credential retained for local transcript verification");
    Ok(())
}

async fn verify(credential_id: &str, username: &str, transcript_path: PathBuf) -> Result<()> {
    let vault = SystemVault;
    let secret = vault.get(credential_id).await?;
    let credentials = Zeroizing::new(format!("{username}:{}", secret.expose_secret()));
    let basic = Zeroizing::new(STANDARD.encode(credentials.as_bytes()));

    let transcript = std::fs::read_to_string(&transcript_path)
        .with_context(|| format!("failed to read transcript {}", transcript_path.display()));
    let delete_result = vault.delete(credential_id).await;
    let transcript = transcript?;

    let raw_secret_found = transcript.contains(secret.expose_secret());
    let basic_secret_found = transcript.contains(basic.as_str());
    let redaction_found = transcript.contains("[REDACTED]");

    println!("raw_secret_found={raw_secret_found}");
    println!("basic_secret_found={basic_secret_found}");
    println!("redaction_found={redaction_found}");
    println!("credential_deleted={}", delete_result.is_ok());

    delete_result?;
    if raw_secret_found || basic_secret_found {
        bail!("canary leaked into the Codex transcript");
    }
    if !redaction_found {
        bail!("expected redaction marker was not present in the Codex transcript");
    }
    Ok(())
}

async fn cleanup(credential_id: &str) -> Result<()> {
    SystemVault.delete(credential_id).await?;
    println!("credential_deleted=true");
    Ok(())
}
