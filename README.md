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

Each plugin is its own command under `cmd/`, built as its own executable.

## Build

```bash
go build ./... && go test ./... && go vet ./...
```

Cross-compiling one plugin for a Linux host:

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o dist/generic-cli-linux-arm64 ./cmd/generic-cli
```

## Why this is open source

Everything that runs on an easySSL Client is open source, because a plugin reads
and writes private key material and restarts services on someone else's host.
Anyone running a Client should be able to read every line that touches their
keys, and to rebuild an artifact and check it against the digest the catalog
publishes. That rule covers this repository.
