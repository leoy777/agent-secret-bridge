# Release checklist

1. Confirm `CHANGELOG.md` and `Cargo.toml` contain the intended version.
2. Run `cargo fmt --all --check`.
3. Run `cargo clippy --locked --all-targets -- -D warnings`.
4. Run `cargo test --locked` on a host that permits loopback tests.
5. Run `cargo build --locked --release`.
6. Run `asb doctor` against a non-production test configuration.
7. Confirm GitHub CI passes on Linux, macOS, and Windows.
8. Create an annotated `vX.Y.Z` tag from the reviewed commit.
9. Let the Release workflow build platform archives and checksum files.
10. Download one archive, verify its checksum, and run `asb --version`.

Do not publish from a dirty tree. Do not add real configurations, audit logs,
private keys, vault keys, passwords, tokens, or canary transcripts to Git.
