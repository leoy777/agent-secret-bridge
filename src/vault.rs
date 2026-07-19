use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Context, Result, anyhow, bail};
use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::STANDARD};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use fs2::FileExt;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::config::VaultConfig;

const SERVICE_NAME: &str = "agent-secret-bridge";
const FILE_MAGIC: &[u8] = b"ASBVAULT1\n";
const KEY_BYTES: usize = 32;
const NONCE_BYTES: usize = 24;

#[async_trait]
pub trait Vault: Send + Sync {
    async fn get(&self, id: &str) -> Result<SecretString>;
    async fn set(&self, id: &str, secret: &SecretString) -> Result<()>;
    async fn delete(&self, id: &str) -> Result<()>;
}

#[derive(Debug, Default)]
pub struct SystemVault;

pub fn from_config(config: &VaultConfig) -> Result<Arc<dyn Vault>> {
    match config {
        VaultConfig::System => Ok(Arc::new(SystemVault)),
        VaultConfig::EncryptedFile { path, key_file } => Ok(Arc::new(EncryptedFileVault::new(
            PathBuf::from(path),
            PathBuf::from(key_file),
        )?)),
    }
}

#[async_trait]
impl Vault for SystemVault {
    async fn get(&self, id: &str) -> Result<SecretString> {
        let id = id.to_owned();
        let value = tokio::task::spawn_blocking(move || {
            keyring::Entry::new(SERVICE_NAME, &id)
                .context("failed to open system credential store")?
                .get_password()
                .with_context(|| format!("credential {id:?} is unavailable"))
        })
        .await
        .context("credential store task failed")??;
        Ok(SecretString::from(value))
    }

    async fn set(&self, id: &str, secret: &SecretString) -> Result<()> {
        let id = id.to_owned();
        let secret = Zeroizing::new(secret.expose_secret().to_owned());
        tokio::task::spawn_blocking(move || {
            keyring::Entry::new(SERVICE_NAME, &id)
                .context("failed to open system credential store")?
                .set_password(&secret)
                .with_context(|| format!("failed to store credential {id:?}"))
        })
        .await
        .context("credential store task failed")??;
        Ok(())
    }

    async fn delete(&self, id: &str) -> Result<()> {
        let id = id.to_owned();
        tokio::task::spawn_blocking(move || {
            keyring::Entry::new(SERVICE_NAME, &id)
                .context("failed to open system credential store")?
                .delete_credential()
                .with_context(|| format!("failed to delete credential {id:?}"))
        })
        .await
        .context("credential store task failed")??;
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct EncryptedFileVault {
    path: PathBuf,
    key_file: PathBuf,
    lock_file: PathBuf,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct PlainVault {
    #[serde(default)]
    secrets: BTreeMap<String, String>,
}

impl Drop for PlainVault {
    fn drop(&mut self) {
        for value in self.secrets.values_mut() {
            value.zeroize();
        }
    }
}

impl EncryptedFileVault {
    pub fn new(path: PathBuf, key_file: PathBuf) -> Result<Self> {
        if !path.is_absolute() || !key_file.is_absolute() {
            bail!("encrypted vault and key paths must be absolute");
        }
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .context("encrypted vault path must have a UTF-8 file name")?;
        let lock_file = path.with_file_name(format!(".{file_name}.lock"));
        Ok(Self {
            path,
            key_file,
            lock_file,
        })
    }

    pub fn initialize(path: PathBuf, key_file: PathBuf) -> Result<()> {
        let vault = Self::new(path, key_file)?;
        validate_secure_parent(&vault.path)?;
        validate_secure_parent(&vault.key_file)?;
        if vault.path.exists() {
            bail!("encrypted vault {} already exists", vault.path.display());
        }

        let mut key = Zeroizing::new([0_u8; KEY_BYTES]);
        getrandom::fill(key.as_mut()).context("failed to generate vault key")?;
        let encoded = Zeroizing::new(STANDARD.encode(key.as_ref()));
        let mut key_output = open_new_private(&vault.key_file)
            .with_context(|| format!("failed to create key file {}", vault.key_file.display()))?;
        key_output.write_all(encoded.as_bytes())?;
        key_output.write_all(b"\n")?;
        key_output.sync_all()?;

        let result = vault.with_lock_value(|| {
            if vault.path.exists() {
                bail!("encrypted vault {} already exists", vault.path.display());
            }
            vault.save_plain(&PlainVault::default())
        });
        if result.is_err() {
            let _ = std::fs::remove_file(&vault.key_file);
        }
        result
    }

    pub fn validate_existing(&self) -> Result<()> {
        self.with_lock_value(|| {
            let plain = self.load_plain()?;
            drop(plain);
            Ok(())
        })
    }

    fn with_lock_value<T>(&self, action: impl FnOnce() -> Result<T>) -> Result<T> {
        validate_secure_parent(&self.path)?;
        let lock = open_private_rw(&self.lock_file)?;
        FileExt::lock_exclusive(&lock).context("failed to lock encrypted vault")?;
        let result = action();
        let unlock_result = FileExt::unlock(&lock).context("failed to unlock encrypted vault");
        match (result, unlock_result) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error),
        }
    }

    fn load_plain(&self) -> Result<PlainVault> {
        if !self.path.exists() {
            return Ok(PlainVault::default());
        }
        validate_private_file("encrypted vault", &self.path)?;
        let mut encrypted = Vec::new();
        File::open(&self.path)?.read_to_end(&mut encrypted)?;
        if encrypted.len() < FILE_MAGIC.len() + NONCE_BYTES || !encrypted.starts_with(FILE_MAGIC) {
            bail!("encrypted vault has an invalid header");
        }

        let key = read_key(&self.key_file)?;
        let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref())
            .map_err(|_| anyhow!("vault key has invalid length"))?;
        let nonce_start = FILE_MAGIC.len();
        let payload_start = nonce_start + NONCE_BYTES;
        let nonce = XNonce::from_slice(&encrypted[nonce_start..payload_start]);
        let plaintext = cipher
            .decrypt(
                nonce,
                Payload {
                    msg: &encrypted[payload_start..],
                    aad: FILE_MAGIC,
                },
            )
            .map_err(|_| anyhow!("encrypted vault authentication failed"))?;
        let plaintext = Zeroizing::new(plaintext);
        serde_json::from_slice(&plaintext).context("encrypted vault payload is invalid")
    }

    fn save_plain(&self, plain: &PlainVault) -> Result<()> {
        validate_secure_parent(&self.path)?;
        let key = read_key(&self.key_file)?;
        let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref())
            .map_err(|_| anyhow!("vault key has invalid length"))?;
        let mut nonce_bytes = [0_u8; NONCE_BYTES];
        getrandom::fill(&mut nonce_bytes).context("failed to generate vault nonce")?;
        let plaintext = Zeroizing::new(serde_json::to_vec(plain)?);
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce_bytes),
                Payload {
                    msg: &plaintext,
                    aad: FILE_MAGIC,
                },
            )
            .map_err(|_| anyhow!("failed to encrypt vault"))?;

        let parent = self.path.parent().context("vault path has no parent")?;
        let file_name = self
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap();
        let temporary = parent.join(format!(".{file_name}.{}.tmp", std::process::id()));
        let write_result = (|| -> Result<()> {
            let mut output = open_new_private(&temporary)?;
            output.write_all(FILE_MAGIC)?;
            output.write_all(&nonce_bytes)?;
            output.write_all(&ciphertext)?;
            output.sync_all()?;
            std::fs::rename(&temporary, &self.path)?;
            sync_directory(parent)?;
            Ok(())
        })();
        if write_result.is_err() {
            let _ = std::fs::remove_file(&temporary);
        }
        write_result
    }
}

#[async_trait]
impl Vault for EncryptedFileVault {
    async fn get(&self, id: &str) -> Result<SecretString> {
        let vault = self.clone();
        let id = id.to_owned();
        tokio::task::spawn_blocking(move || {
            vault.with_lock_value(|| {
                let plain = vault.load_plain()?;
                plain
                    .secrets
                    .get(&id)
                    .cloned()
                    .map(SecretString::from)
                    .ok_or_else(|| anyhow!("credential {id:?} is unavailable"))
            })
        })
        .await
        .context("encrypted vault task failed")?
    }

    async fn set(&self, id: &str, secret: &SecretString) -> Result<()> {
        let vault = self.clone();
        let id = id.to_owned();
        let secret = Zeroizing::new(secret.expose_secret().to_owned());
        tokio::task::spawn_blocking(move || {
            vault.with_lock_value(|| {
                let mut plain = vault.load_plain()?;
                plain.secrets.insert(id, secret.as_str().to_owned());
                vault.save_plain(&plain)
            })
        })
        .await
        .context("encrypted vault task failed")?
    }

    async fn delete(&self, id: &str) -> Result<()> {
        let vault = self.clone();
        let id = id.to_owned();
        tokio::task::spawn_blocking(move || {
            vault.with_lock_value(|| {
                let mut plain = vault.load_plain()?;
                if plain.secrets.remove(&id).is_none() {
                    bail!("credential {id:?} is unavailable");
                }
                vault.save_plain(&plain)
            })
        })
        .await
        .context("encrypted vault task failed")?
    }
}

fn read_key(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    validate_private_file("vault key", path)?;
    let mut raw = Zeroizing::new(Vec::new());
    File::open(path)?.read_to_end(raw.as_mut())?;
    if raw.len() == KEY_BYTES {
        return Ok(raw);
    }
    let trimmed = trim_ascii_whitespace(raw.as_slice());
    let decoded = STANDARD
        .decode(trimmed)
        .context("vault key must be 32 raw bytes or base64")?;
    if decoded.len() != KEY_BYTES {
        bail!("vault key must decode to exactly 32 bytes");
    }
    Ok(Zeroizing::new(decoded))
}

fn trim_ascii_whitespace(mut bytes: &[u8]) -> &[u8] {
    while bytes.first().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[1..];
    }
    while bytes.last().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[..bytes.len() - 1];
    }
    bytes
}

fn validate_secure_parent(path: &Path) -> Result<()> {
    let parent = path.parent().context("secure file path has no parent")?;
    let metadata = std::fs::metadata(parent)
        .with_context(|| format!("secure directory {} is unavailable", parent.display()))?;
    if !metadata.is_dir() {
        bail!("secure parent {} is not a directory", parent.display());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o022 != 0 {
            bail!(
                "secure directory {} must not be group- or world-writable",
                parent.display()
            );
        }
    }
    Ok(())
}

fn validate_private_file(label: &str, path: &Path) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("{label} {} is unavailable", path.display()))?;
    if !metadata.file_type().is_file() {
        bail!("{label} {} must be a regular file", path.display());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            bail!(
                "{label} {} must have owner-only permissions",
                path.display()
            );
        }
    }
    Ok(())
}

fn open_new_private(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path).map_err(Into::into)
}

fn open_private_rw(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(path)?;
    validate_private_file("vault lock", path)?;
    Ok(file)
}

fn sync_directory(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        File::open(path)?.sync_all()?;
    }
    Ok(())
}

#[cfg(test)]
pub mod testing {
    use std::{collections::HashMap, sync::RwLock};

    use anyhow::{Result, anyhow};
    use async_trait::async_trait;
    use secrecy::SecretString;

    use super::Vault;

    #[derive(Default)]
    pub struct MemoryVault {
        values: RwLock<HashMap<String, SecretString>>,
    }

    impl MemoryVault {
        pub fn with_secret(id: &str, secret: &str) -> Self {
            let mut values = HashMap::new();
            values.insert(id.to_owned(), SecretString::from(secret.to_owned()));
            Self {
                values: RwLock::new(values),
            }
        }
    }

    #[async_trait]
    impl Vault for MemoryVault {
        async fn get(&self, id: &str) -> Result<SecretString> {
            self.values
                .read()
                .expect("memory vault lock poisoned")
                .get(id)
                .cloned()
                .ok_or_else(|| anyhow!("credential not found"))
        }

        async fn set(&self, id: &str, secret: &SecretString) -> Result<()> {
            self.values
                .write()
                .expect("memory vault lock poisoned")
                .insert(id.to_owned(), secret.clone());
            Ok(())
        }

        async fn delete(&self, id: &str) -> Result<()> {
            self.values
                .write()
                .expect("memory vault lock poisoned")
                .remove(id);
            Ok(())
        }
    }
}

#[cfg(test)]
mod encrypted_file_tests {
    use secrecy::ExposeSecret;

    use super::*;

    #[tokio::test]
    async fn encrypted_file_round_trip_and_tamper_detection() {
        let directory = tempfile::tempdir().unwrap();
        let vault_path = directory.path().join("vault.asb");
        let key_path = directory.path().join("vault.key");
        EncryptedFileVault::initialize(vault_path.clone(), key_path.clone()).unwrap();
        let vault = EncryptedFileVault::new(vault_path.clone(), key_path).unwrap();
        let secret = SecretString::from("never-plaintext-on-disk".to_owned());

        vault.set("test", &secret).await.unwrap();
        let stored = vault.get("test").await.unwrap();
        assert_eq!(stored.expose_secret(), secret.expose_secret());

        let encrypted = std::fs::read(&vault_path).unwrap();
        assert!(
            !encrypted
                .windows(secret.expose_secret().len())
                .any(|window| window == secret.expose_secret().as_bytes())
        );

        let mut tampered = encrypted;
        let last = tampered.last_mut().unwrap();
        *last ^= 1;
        std::fs::write(&vault_path, tampered).unwrap();
        assert!(vault.get("test").await.is_err());
    }
}
