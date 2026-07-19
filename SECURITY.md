# Security policy and threat model

## Protected assets

Agent Secret Bridge is designed to keep raw passwords, API tokens, and derived
HTTP authentication material out of model prompts and tool results. It also
prevents an agent from changing a capability's configured origin or
authentication method at call time.

## Trust assumptions

- The local operating system, process owner, and credential store are trusted.
- The configuration file is administrator-controlled and is not writable by an
  untrusted repository or agent workspace.
- Production launch configuration pins the capability file with
  `--config-sha256`; the expected hash itself is stored outside Agent-writable
  paths.
- The `asb` binary and its dependencies were obtained through a trusted build.
- TLS certificate validation remains enabled for HTTPS capabilities.
- The target service is trusted to receive the credential assigned to it.

## Out of scope

The prototype does not protect against:

- root, kernel, hypervisor, or physical compromise of the local machine;
- a malicious or fully compromised target service;
- an administrator who creates an overbroad capability;
- misuse of an action that policy explicitly allows;
- traffic interception for an explicitly enabled insecure HTTP capability;
- secrets transformed by a target into an unknown representation before it
  echoes them in a response;
- secrets included by the user in prompts, configuration, or request bodies.

## Headless encrypted vault

The encrypted file backend uses XChaCha20-Poly1305 with a random 256-bit master
key, random nonce, authenticated format header, owner-only files, atomic writes,
and an inter-process file lock. Authentication failure is fatal; corrupted data
is never partially loaded.

Encryption at rest does not isolate a key from another process running as the
same OS user. For Agent use, the encrypted vault is therefore refused in direct
STDIO mode. Run `asb daemon` as a dedicated user and expose only its owner/group
controlled Unix socket through `asb proxy`. The Agent user must not be able to
read the broker configuration directory, vault key, vault ciphertext, or audit
file.

The broker's socket group grants the ability to invoke configured capabilities.
It must be treated as an authorization boundary even though it cannot export a
secret.

## Hard rules

- Fail closed on unknown configuration fields and unsupported protocol values.
- Never implement `get_secret`, `export_secret`, or an equivalent primitive.
- Never accept authentication headers or destination origins from an agent.
- Do not follow redirects.
- Rate-limit every configured capability, including read-only operations.
- Reject oversized MCP messages before dispatch.
- Do not log request bodies, response bodies, or credential values.
- Keep STDIO stdout reserved for MCP messages.
- Treat configuration and the executable path as security-sensitive.
- Do not recompute a trusted configuration pin automatically at broker startup;
  review changes first and update the pin explicitly.

## Reporting vulnerabilities

After the repository is published, report vulnerabilities through its private
GitHub Security Advisory interface. Do not open a public issue containing a
working exploit, credential, private host, or sensitive log. Before publication,
record the finding locally and contact the repository owner through a private
channel.
