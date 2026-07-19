use std::{fs::OpenOptions, io::Write, path::PathBuf, sync::Mutex};

use anyhow::{Context, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

pub struct AuditLog {
    path: PathBuf,
    lock: Mutex<()>,
}

#[derive(Debug, Serialize)]
pub struct AuditEvent<'a> {
    timestamp: String,
    capability_id: &'a str,
    action: &'a str,
    target_hash: String,
    outcome: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'a str>,
}

impl AuditLog {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            lock: Mutex::new(()),
        }
    }

    pub fn record(
        &self,
        capability_id: &str,
        action: &str,
        target: &str,
        outcome: &str,
        reason: Option<&str>,
    ) -> Result<()> {
        let _guard = self.lock.lock().expect("audit lock poisoned");
        let timestamp = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .context("failed to format audit timestamp")?;
        let target_hash = format!("sha256:{:x}", Sha256::digest(target.as_bytes()));
        let event = AuditEvent {
            timestamp,
            capability_id,
            action,
            target_hash,
            outcome,
            reason,
        };
        let mut line = serde_json::to_vec(&event)?;
        line.push(b'\n');

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .with_context(|| format!("failed to open audit log {}", self.path.display()))?;
        file.write_all(&line)
            .with_context(|| format!("failed to append audit log {}", self.path.display()))
    }
}
