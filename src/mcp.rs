use std::sync::Arc;

use anyhow::{Context, Result};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};

use crate::{
    Config,
    http::{HttpBroker, HttpRequestInput},
    ssh::{SshBroker, SshExecuteInput},
};

const MAX_MCP_MESSAGE_BYTES: usize = 1024 * 1024;

pub struct McpServer {
    config: Arc<Config>,
    http: HttpBroker,
    ssh: SshBroker,
}

#[derive(Debug, Deserialize)]
struct ToolCall {
    name: String,
    #[serde(default)]
    arguments: Value,
}

impl McpServer {
    pub fn new(config: Arc<Config>, http: HttpBroker, ssh: SshBroker) -> Self {
        Self { config, http, ssh }
    }

    pub async fn serve_stdio(&self) -> Result<()> {
        self.serve_io(tokio::io::stdin(), tokio::io::stdout()).await
    }

    pub async fn serve_io<R, W>(&self, reader: R, mut writer: W) -> Result<()>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        let mut reader = BufReader::new(reader);
        let mut encoded = Vec::new();

        loop {
            encoded.clear();
            let count = reader
                .read_until(b'\n', &mut encoded)
                .await
                .context("failed to read MCP input")?;
            if count == 0 {
                break;
            }
            if encoded.len() > MAX_MCP_MESSAGE_BYTES {
                let response = error_response(
                    Value::Null,
                    -32700,
                    "MCP message exceeds the 1048576-byte safety limit",
                );
                let mut response_bytes = serde_json::to_vec(&response)?;
                response_bytes.push(b'\n');
                writer.write_all(&response_bytes).await?;
                writer.flush().await?;
                continue;
            }
            let line = String::from_utf8_lossy(&encoded);
            if line.trim().is_empty() {
                continue;
            }

            let response = match serde_json::from_str::<Value>(&line) {
                Ok(message) => self.handle_message(message).await,
                Err(error) => Some(error_response(
                    Value::Null,
                    -32700,
                    &format!("parse error: {error}"),
                )),
            };

            if let Some(response) = response {
                let mut response_bytes = serde_json::to_vec(&response)?;
                response_bytes.push(b'\n');
                writer.write_all(&response_bytes).await?;
                writer.flush().await?;
            }
        }
        Ok(())
    }

    async fn handle_message(&self, message: Value) -> Option<Value> {
        let id = message.get("id").cloned();
        let method = message.get("method").and_then(Value::as_str);

        // Notifications intentionally have no response.
        let id = id?;
        let method = match method {
            Some(value) => value,
            None => return Some(error_response(id, -32600, "invalid request")),
        };

        let result = match method {
            "initialize" => Ok(self.initialize_result(&message)),
            "ping" => Ok(json!({})),
            "tools/list" => Ok(self.tools_list()),
            "tools/call" => self.tools_call(&message).await,
            _ => return Some(error_response(id, -32601, "method not found")),
        };

        Some(match result {
            Ok(result) => json!({"jsonrpc": "2.0", "id": id, "result": result}),
            Err(error) => error_response(id, -32602, &error.to_string()),
        })
    }

    fn initialize_result(&self, message: &Value) -> Value {
        let protocol_version = message
            .pointer("/params/protocolVersion")
            .and_then(Value::as_str)
            .unwrap_or("2025-06-18");
        json!({
            "protocolVersion": protocol_version,
            "capabilities": {"tools": {"listChanged": false}},
            "serverInfo": {
                "name": "agent-secret-bridge",
                "version": env!("CARGO_PKG_VERSION")
            },
            "instructions": "Use capabilities instead of requesting credentials. This server never exposes raw secrets."
        })
    }

    fn tools_list(&self) -> Value {
        json!({
            "tools": [
                {
                    "name": "capabilities_list",
                    "description": "List configured capability IDs and their non-secret policy metadata.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {},
                        "additionalProperties": false
                    },
                    "annotations": {"readOnlyHint": true, "destructiveHint": false}
                },
                {
                    "name": "ssh_read",
                    "description": "Run one preconfigured read-only SSH operation. The agent cannot provide a command, host, user, or key.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "capability_id": {"type": "string"},
                            "operation_id": {"type": "string"}
                        },
                        "required": ["capability_id", "operation_id"],
                        "additionalProperties": false
                    },
                    "annotations": {"readOnlyHint": true, "destructiveHint": false}
                },
                {
                    "name": "ssh_execute",
                    "description": "Run one preconfigured state-changing SSH operation. The agent cannot provide a command, host, user, or key.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "capability_id": {"type": "string"},
                            "operation_id": {"type": "string"}
                        },
                        "required": ["capability_id", "operation_id"],
                        "additionalProperties": false
                    },
                    "annotations": {"readOnlyHint": false, "destructiveHint": true}
                },
                {
                    "name": "http_read",
                    "description": "Perform a GET or HEAD request using a locally stored credential and a fixed capability policy. The credential is never returned.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "capability_id": {"type": "string"},
                            "method": {"type": "string", "enum": ["GET", "HEAD"]},
                            "path": {"type": "string"}
                        },
                        "required": ["capability_id", "method", "path"],
                        "additionalProperties": false
                    },
                    "annotations": {"readOnlyHint": true, "destructiveHint": false}
                },
                {
                    "name": "http_request",
                    "description": "Perform an HTTP request using a locally stored credential and a fixed capability policy. The credential is never returned.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "capability_id": {"type": "string"},
                            "method": {"type": "string"},
                            "path": {"type": "string"},
                            "body": {"type": "string"}
                        },
                        "required": ["capability_id", "method", "path"],
                        "additionalProperties": false
                    },
                    "annotations": {"readOnlyHint": false, "destructiveHint": true}
                }
            ]
        })
    }

    async fn tools_call(&self, message: &Value) -> Result<Value> {
        let call: ToolCall = serde_json::from_value(
            message
                .get("params")
                .cloned()
                .context("tools/call requires params")?,
        )?;

        match call.name.as_str() {
            "capabilities_list" => {
                let mut capabilities: Vec<Value> = self
                    .config
                    .capabilities
                    .iter()
                    .map(|capability| {
                        let crate::config::Transport::Http { base_url, .. } = &capability.transport;
                        json!({
                            "id": capability.id,
                            "transport": "http",
                            "base_url": base_url,
                            "methods": capability.allow.methods,
                            "paths": capability.allow.paths
                        })
                    })
                    .collect();
                capabilities.extend(self.config.ssh_capabilities.iter().map(|capability| {
                    json!({
                        "id": capability.id,
                        "transport": "ssh",
                        "host": capability.host,
                        "port": capability.port,
                        "user": capability.user,
                        "operations": capability.operations.iter().map(|operation| json!({
                            "id": operation.id,
                            "read_only": operation.read_only
                        })).collect::<Vec<_>>()
                    })
                }));
                tool_text(&json!({"capabilities": capabilities}))
            }
            "ssh_read" => {
                let input: SshExecuteInput = serde_json::from_value(call.arguments)?;
                match self.ssh.execute(input, true).await {
                    Ok(response) => tool_text(&response),
                    Err(error) => Ok(json!({
                        "content": [{"type": "text", "text": error.to_string()}],
                        "isError": true
                    })),
                }
            }
            "ssh_execute" => {
                let input: SshExecuteInput = serde_json::from_value(call.arguments)?;
                match self.ssh.execute(input, false).await {
                    Ok(response) => tool_text(&response),
                    Err(error) => Ok(json!({
                        "content": [{"type": "text", "text": error.to_string()}],
                        "isError": true
                    })),
                }
            }
            "http_read" => {
                let input: HttpRequestInput = serde_json::from_value(call.arguments)?;
                if !matches!(input.method.to_ascii_uppercase().as_str(), "GET" | "HEAD") {
                    return Ok(json!({
                        "content": [{"type": "text", "text": "http_read only permits GET or HEAD"}],
                        "isError": true
                    }));
                }
                match self.http.execute(input).await {
                    Ok(response) => tool_text(&response),
                    Err(error) => Ok(json!({
                        "content": [{"type": "text", "text": error.to_string()}],
                        "isError": true
                    })),
                }
            }
            "http_request" => {
                let input: HttpRequestInput = serde_json::from_value(call.arguments)?;
                match self.http.execute(input).await {
                    Ok(response) => tool_text(&response),
                    Err(error) => Ok(json!({
                        "content": [{"type": "text", "text": error.to_string()}],
                        "isError": true
                    })),
                }
            }
            _ => Ok(json!({
                "content": [{"type": "text", "text": "unknown tool"}],
                "isError": true
            })),
        }
    }
}

fn tool_text(value: &impl serde::Serialize) -> Result<Value> {
    Ok(json!({
        "content": [{"type": "text", "text": serde_json::to_string(value)?}],
        "isError": false
    }))
}

fn error_response(id: Value, code: i64, message: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {"code": code, "message": message}
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::{
        audit::AuditLog, config::AuditConfig, http::HttpBroker, rate_limit::RateLimiter,
        vault::testing::MemoryVault,
    };

    use super::*;

    fn server() -> McpServer {
        let config = Arc::new(Config {
            version: 1,
            vault: crate::config::VaultConfig::System,
            audit: AuditConfig::default(),
            capabilities: vec![],
            ssh_capabilities: vec![],
        });
        let vault = Arc::new(MemoryVault::default());
        let audit = Arc::new(AuditLog::new("/tmp/asb-test-audit.jsonl"));
        let rate_limiter = Arc::new(RateLimiter::default());
        let broker = HttpBroker::new(config.clone(), vault, audit.clone(), rate_limiter.clone());
        let ssh = SshBroker::new(config.clone(), audit, rate_limiter);
        McpServer::new(config, broker, ssh)
    }

    #[tokio::test]
    async fn initializes_with_client_protocol_version() {
        let response = server()
            .handle_message(json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {"protocolVersion": "test-version"}
            }))
            .await
            .unwrap();
        assert_eq!(
            response.pointer("/result/protocolVersion"),
            Some(&json!("test-version"))
        );
    }

    #[tokio::test]
    async fn notifications_have_no_response() {
        assert!(
            server()
                .handle_message(json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
                .await
                .is_none()
        );
    }
}
