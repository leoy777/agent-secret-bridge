# Roadmap

## Current direction: lightweight deterministic broker

The near-term project is intentionally small. It uses hard policy rules and OS
credential stores. It has no embedded language model, cloud service, telemetry,
or custom password-sync system.

### v0.1

- strict capability schema;
- HTTP Basic and Bearer adapters;
- OS credential-store abstraction;
- response redaction;
- local JSONL audit;
- STDIO MCP server;
- macOS build and tests.

### v0.2

- SSH operation allowlists through `ssh-agent`, without exporting private keys;
- XChaCha20-Poly1305 vault for headless hosts;
- dedicated-user Unix-socket broker and unprivileged STDIO proxy;
- Windows and Linux CI;
- per-capability sliding-window rate limits;
- tamper-resistant configuration guidance.

### v0.2.1

- SHA-256 configuration pinning and secure-file checks;
- readiness diagnostics;
- Linux, macOS, and Windows CI and tagged release archives;
- user-level installation, upgrade, and removal workflows;
- first GitHub-ready preview release.

### v0.3

- browser extension with exact-origin binding;
- native messaging host;
- protected form injection and redirect defense;
- dedicated browser-profile support.

### v0.4

- small management UI;
- capability setup wizard;
- signed installers and update metadata;
- additional agent SDK adapters.

## Deferred larger product

The long-term AgentVault concept remains intentionally deferred. It may add
team policy, end-to-end encrypted sync, enterprise administration, hardware-key
support, richer application adapters, recovery workflows, and independent
security certification. Those features must not increase the trusted computing
base of the lightweight broker by default.

If a local language model is explored later, it may only propose narrower
policies or explain risk. Cryptography and authorization enforcement must remain
deterministic.
