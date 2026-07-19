# Changelog

All notable changes to Agent Secret Bridge are recorded here. The project uses
semantic versioning while the configuration format remains independently
versioned by its top-level `version` field.

## 0.2.1 - 2026-07-19

### Added

- SHA-256 configuration pinning for `serve`, `daemon`, and `check`;
- `asb config hash` for producing a trusted configuration pin;
- `asb doctor` for configuration, vault, SSH file, and agent checks;
- Linux, macOS, and Windows GitHub Actions CI;
- tagged release builds for Linux x86-64, macOS x86-64/ARM64, and Windows x86-64;
- user-level Unix and Windows installation and removal scripts.

### Changed

- configuration files must be regular, non-symlink files and may not be group-
  or world-writable on Unix;
- SSH read operations now use the accurate `ssh_read` audit action;
- Codex SSH setup documents the required `SSH_AUTH_SOCK` MCP environment
  whitelist.

### Verified

- real Codex to MCP to ASB to HTTP canary flow without raw or derived secret
  exposure;
- real Codex to MCP to ASB to SSH read-only operation against a test VPS;
- encrypted VPS vault daemon/proxy isolation on macOS.

## 0.2.0 - 2026-07-19

- SSH operation allowlists through `ssh-agent`;
- encrypted headless vault and Unix socket isolation;
- per-capability rate limits and bounded MCP messages.

## 0.1.0 - 2026-07-19

- strict HTTP capability policies, local credential injection, redaction,
  audit logging, and STDIO MCP support.
