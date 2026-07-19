# Contributing

Agent Secret Bridge is security-sensitive. Keep changes small, deterministic,
and testable. Do not add a primitive that returns, exports, logs, or displays a
stored credential.

Before opening a pull request:

```bash
cargo fmt --all --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
```

Pull requests that change authentication, origin binding, command execution,
configuration validation, redaction, vault cryptography, or process isolation
must update `SECURITY.md` and include a negative test showing the unsafe path is
rejected.

Never commit real configurations, audit logs, private keys, vault keys,
passwords, tokens, SSH host inventories, or event transcripts. Use reserved
example addresses and synthetic credentials in fixtures.
