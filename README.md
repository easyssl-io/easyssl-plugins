# easyssl-plugins

First-party plugins for easySSL. Each plugin is a standalone executable that an
easySSL Client fetches on demand, verifies against a published content digest
before running, and then drives over stdio.

Nothing here is linked into the Client binary. A Client ships with no plugins at
all and gains one only when somebody installs it, which keeps the base install
small enough for constrained hosts and lets this catalog grow without ever
touching the Client.

## Plugins

| Plugin | What it does |
|--------|--------------|
| `generic-cli` | The general-purpose fallback. You tell it where the certificate and key belong and what command reloads the service, and it does exactly that: no configuration parsing, nothing tied to any particular server software. |

Each plugin is its own **Go module** in its own directory, built to its own executable. That is deliberate rather than tidy: a plugin that drives a browser needs dependencies a minimal one must not inherit, and a shared `go.mod` would put them in every plugin's dependency graph. Per-module release tags (`generic-cli/v1.2.0`) also match how the catalog versions each artifact separately.

## Build

There is no module at the repository root, so build from a plugin's own directory:

```bash
cd generic-cli && go build ./... && go test ./... && go vet ./...
```

Cross-compiling one plugin for a Linux host:

```bash
cd generic-cli && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o ../dist/generic-cli-linux-arm64 .
```

Code shared between plugins will land as its own sibling module here when a
second plugin needs it, so sharing costs no cross-repository pin.

## Why this is open source

Everything that runs on an easySSL Client is open source, because a plugin reads
and writes private key material and restarts services on someone else's host.
Anyone running a Client should be able to read every line that touches their
keys, and to rebuild an artifact and check it against the digest the catalog
publishes. That rule covers this repository.
