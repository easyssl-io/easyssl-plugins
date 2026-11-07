# generic-cli

The general-purpose easySSL Plugin, for anything the others do not cover.

You write one command that puts the certificate and key where they belong and
reloads the service, and it runs exactly that: no configuration parsing,
nothing tied to any particular server software, and no discovery, so every
Target is entered by hand. The command runs under `sh -e`, so a line that fails
fails the deployment; a failure on the left of `&&` or `||`, or inside a
pipeline, does not count, so a command that must fail goes on its own line.

## On the host

- **Needs `/bin/sh`**, and nothing tied to Linux; release binaries are built
  for Linux.
- **Runs the command as the Agent's user**, root on a standard install, in the
  Agent service's private `/tmp`: a process it leaves running ends when the
  Agent restarts.
- **Writes** the certificate, the chain, the full chain and the key to a
  directory of its own (`0700`, the key `0600`), names them in
  `EASYSSL_CERTIFICATE_PATH`, `EASYSSL_CHAIN_PATH`, `EASYSSL_FULLCHAIN_PATH`
  and `EASYSSL_KEY_PATH`, and removes them once the command ends.
- **Connects** nowhere itself.

## Settings

Its `describe` answer, with every setting and its description in each language,
is pinned in [`internal/ops/testdata/describe.json`](internal/ops/testdata/describe.json).

## Build

```bash
GOWORK=off go build ./... && GOWORK=off go test ./...
```

How to rebuild a release binary byte for byte is in the repository's
[README](../README.md#build).
