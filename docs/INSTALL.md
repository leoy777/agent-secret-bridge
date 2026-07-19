# Installation and first use

## Download verification

Every tagged GitHub release contains an archive and a matching `.sha256` file.
Verify the archive before extraction. Release checksums detect accidental
corruption; they are not a substitute for signed releases, which remain a
future milestone.

macOS:

```bash
shasum -a 256 -c agent-secret-bridge-*.sha256
```

Linux:

```bash
sha256sum -c agent-secret-bridge-*.sha256
```

Windows PowerShell:

```powershell
Get-FileHash .\agent-secret-bridge-*.zip -Algorithm SHA256
```

Compare the result with the downloaded `.sha256` file.

## User-level installation

macOS and Linux:

```bash
./packaging/install.sh ./asb
```

The default destination is `~/.local/bin/asb`. Set `ASB_INSTALL_DIR` to choose
another user-owned directory. Do not install a binary from an untrusted working
tree with elevated privileges.

Windows PowerShell:

```powershell
.\packaging\install.ps1 -SourceBinary .\asb.exe
```

The default destination is `%LOCALAPPDATA%\Programs\AgentSecretBridge`.

## Secure configuration pinning

Store the capability configuration outside repositories an Agent can edit and
make it owner-writable only. Generate its pin:

```bash
asb config hash --config /absolute/path/to/asb.yaml
```

Validate both content and policy:

```bash
asb check \
  --config /absolute/path/to/asb.yaml \
  --config-sha256 64_HEX_CHARACTERS
```

Run diagnostics before registering the server:

```bash
asb doctor \
  --config /absolute/path/to/asb.yaml \
  --config-sha256 64_HEX_CHARACTERS
```

For Codex, place the absolute binary path, configuration path, and pin in the
trusted user-level configuration:

```toml
[mcp_servers.agent-secret-bridge]
command = "/absolute/path/to/asb"
args = [
  "serve",
  "--config", "/absolute/path/to/asb.yaml",
  "--config-sha256", "64_HEX_CHARACTERS"
]
env_vars = ["SSH_AUTH_SOCK"]
```

Omit `env_vars` when no SSH capability is configured.

## Upgrade and removal

To upgrade, verify a new release and run the same installer over the old
binary. Configuration, credentials, and audits are not changed automatically.
Re-run `asb doctor` after every upgrade.

Removal is interactive and intentionally leaves data untouched:

```bash
./packaging/uninstall.sh
```

```powershell
.\packaging\uninstall.ps1
```

Delete configuration, credentials, encrypted vaults, and audit records only as
a separate, explicit operation after confirming they are no longer needed.
