# Agent Secret Bridge

Agent Secret Bridge (`asb`) is a small local capability broker. It lets an AI
agent perform a narrowly authorized action with a credential without giving the
raw credential to the model, prompt, tool result, or configuration file.

> **Status:** security-focused preview. The core flows have real end-to-end
> tests, but the project has not received an independent security review. Start
> with dedicated low-privilege accounts and narrowly scoped capabilities.

## Security model

The model receives a capability ID, never a password or token:

```text
agent -> capability_id -> local policy -> OS credential store -> fixed target
```

The current invariants are:

- no tool or CLI command can export a stored secret;
- credentials live in the operating-system credential store;
- headless encrypted vaults are isolated behind a separate Unix-socket broker;
- configuration contains credential IDs only;
- the agent cannot choose the scheme, host, port, or authentication method;
- HTTP redirects are disabled;
- methods and paths require an explicit allow rule;
- each capability has a sliding one-minute invocation limit;
- individual MCP messages are limited to 1 MiB;
- response bodies are checked for raw and derived authentication material;
- audit events contain a target hash, not credentials or request bodies.

See [SECURITY.md](SECURITY.md) for boundaries and known limitations.

## Build

```bash
cargo build --release
```

The binary is written to `target/release/asb`.

For verified release archives, user-level installers, upgrades, and removal,
see [`docs/INSTALL.md`](docs/INSTALL.md).

## Configure

Copy [`examples/asb.yaml`](examples/asb.yaml), then validate it:

```bash
asb check --config /absolute/path/to/asb.yaml
```

For normal use, pin the trusted configuration so an Agent-editable workspace
cannot silently broaden a capability:

```bash
PIN=$(asb config hash --config /absolute/path/to/asb.yaml)
asb doctor --config /absolute/path/to/asb.yaml --config-sha256 "$PIN"
```

Put the resulting literal hash in trusted Codex or service configuration; do
not calculate it automatically every time the broker starts.

Add the credential through a hidden terminal prompt:

```bash
asb secret add pikvm-admin
```

The credential ID must match the `credential` field in the capability. The
secret itself must never be put in YAML, a command argument, or a chat message.

## Run as a local MCP server

```bash
asb serve --config /absolute/path/to/asb.yaml
```

For Codex CLI, register the built binary as a local STDIO server:

```bash
codex mcp add agent-secret-bridge -- \
  /absolute/path/to/asb serve --config /absolute/path/to/asb.yaml
```

Restart the client after changing MCP configuration. The server exposes:

- `capabilities_list`
- `http_read`
- `http_request`
- `ssh_read`
- `ssh_execute`

`http_read` is limited to GET/HEAD and is advertised as read-only.
`http_request` supports policy-authorized write methods and is advertised as
potentially destructive. Neither tool accepts a host, authentication header,
credential, or arbitrary request headers.

Every HTTP and SSH capability defaults to 60 invocations per minute. Set a
narrower value under `limits.max_requests_per_minute` for sensitive actions.

## SSH capabilities

SSH tools accept only a capability ID and operation ID. Hosts, users, ports,
and remote command vectors are fixed by trusted configuration. `ssh_read` can
run only operations marked `read_only`; state-changing operations must use the
separately annotated `ssh_execute` tool.

ASB always uses the system OpenSSH client with user configuration disabled,
strict host-key checking, forwarding disabled, no TTY, and batch-only
authentication. Private keys must be held by `ssh-agent`. Configuration points
to a public key file solely to select the matching non-exportable agent key.
See [`examples/ssh-asb.yaml`](examples/ssh-asb.yaml).

Codex filters the environment inherited by STDIO MCP children. Whitelist only
the agent socket so ASB can use the already-unlocked key without receiving a
private-key path or passphrase:

```toml
[mcp_servers.agent-secret-bridge]
command = "/absolute/path/to/asb"
args = ["serve", "--config", "/absolute/path/to/asb.yaml"]
env_vars = ["SSH_AUTH_SOCK"]
```

Do not hard-code the macOS socket value: launchd may assign a different path
after login. Load the key locally with `ssh-add --apple-use-keychain` once, and
never place its passphrase in Codex configuration.

## Headless VPS mode

On a server without Keychain or Secret Service, use the XChaCha20-Poly1305
encrypted file backend. Do not start that backend directly as a Codex STDIO
child: a same-user shell could read its master-key file. Run the broker under a
dedicated OS user and connect through the unprivileged proxy:

```bash
# Run once as the dedicated broker user after creating owner-only directories.
asb vault init --config /etc/agent-secret-bridge/asb.yaml
asb secret --config /etc/agent-secret-bridge/asb.yaml add internal-api-token

# Long-running privileged side.
asb daemon \
  --config /etc/agent-secret-bridge/asb.yaml \
  --socket /run/agent-secret-bridge/broker.sock

# Codex-facing side; this process has no vault key.
asb proxy --socket /run/agent-secret-bridge/broker.sock
```

The included [`packaging/systemd/agent-secret-bridge.service`](packaging/systemd/agent-secret-bridge.service)
provides a hardened starting point. The `asb-clients` group grants capability
use, not raw-secret access. Copy `packaging/systemd/asb.env.example` to the
protected path named by the service and replace its placeholder with the
reviewed configuration hash. Root or hypervisor compromise remains out of
scope.

## Development

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

The GitHub workflows run formatting, Clippy, tests, and release builds across
Linux, macOS, and Windows. See [`docs/RELEASE.md`](docs/RELEASE.md).

## Scope

The first milestone includes deterministic policy enforcement, HTTP Basic and
Bearer authentication, system credential storage, redaction, audit logging,
and a dependency-light STDIO MCP implementation.

Browser integration, GUI management, Windows named-pipe broker isolation, and
signed cross-platform installers are later milestones. The larger product
direction is recorded in [`docs/ROADMAP.md`](docs/ROADMAP.md).

## License

MIT
