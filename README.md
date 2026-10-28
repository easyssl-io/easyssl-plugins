# easyssl-plugins

First-party plugins for easySSL. Each plugin is a standalone executable that an
easySSL Agent fetches on demand, verifies against a published content digest
before running, and then drives over stdio.

Nothing here is linked into the Agent binary. An Agent ships with no plugins at
all and gains one only when somebody installs it, which keeps the base install
small enough for constrained hosts and lets this catalog grow without ever
touching the Agent.

## Plugins

| Plugin | What it does |
|--------|--------------|
| `apache` | Finds the certificates every running Apache HTTP Server master serves, reading its configuration as httpd itself reports it (`DUMP_CONFIG` with every conditional evaluated, and `DUMP_VHOSTS`), and works out where a client reaches each one. A certificate is suggested as a Target only when nothing about how Apache uses it could make a renewal go wrong; anything else is a discovery warning instead. Deploys by checking the Target and every other certificate and key the reload loads, writing the full chain and the key with everything but their content kept (owner, mode, ACLs and other extended attributes), running the instance's configuration test as the instance's own user, reloading, and checking over TLS that every place the file is served presents the new Certificate. A failure puts the previous files back, and an Apache the reload stopped is started again. |
| `generic-cli` | The general-purpose fallback. You write one command that puts the certificate and key where they belong and reloads the service, and it runs exactly that: no configuration parsing, nothing tied to any particular server software. The command runs under `sh -e`, so a line that fails fails the deployment; a failure on the left of `&&` or `||`, or inside a pipeline, does not count, so a command that must fail goes on its own line. |
| `nginx` | Finds the certificates every running nginx master serves (parsing its configuration with every `include`, pairing dual RSA and ECDSA certificates by algorithm) and suggests each as a Target. Deploys by writing the full chain and the key with the replaced files' permissions (`0600` for a new file), running the instance's `nginx -t`, putting the old files back if that fails, and reloading. A successful reload is not proof nginx serves the new Certificate, and its output says so. |

Each plugin is its own **Go module** in its own directory, built to its own executable. That is deliberate rather than tidy: a plugin that drives a browser needs dependencies a minimal one must not inherit, and a shared `go.mod` would put them in every plugin's dependency graph. Per-module release tags (`generic-cli/v1.2.0`) also match how the catalog versions each artifact separately.

## Languages

What a plugin says to a reader (its description, each setting's label and
description, its discovery warnings) is declared in every language the plugin
carries, as an object of language code to text with English (`en`) always
present. Whoever shows the text picks its reader's language and falls back to
English. Each plugin holds its own translations in `internal/ops/locales/`,
one file per language, embedded in the executable.

What a plugin found or ran is not translated: paths, commands, setting keys
and values, a program's own error text, and everything a deployment prints.

## Build

There is no module at the repository root, so build from a plugin's own directory:

```bash
cd generic-cli && go build ./... && go test ./... && go vet ./...
```

Cross-compiling one plugin for a Linux host:

```bash
cd generic-cli && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o ../dist/generic-cli-linux-arm64 .
```

Code more than one plugin needs is the `internal` module beside them:
`hostfile` replaces a certificate or key file so that only its content changes,
`pemfile` reads certificates and keys, and `tlscheck` asks a server which
certificate it presents. A plugin reaches it through a relative `replace`, so
sharing costs no cross-repository pin, and its path keeps it importable by the
plugins here alone.

## Why this is open source

Everything that runs on an easySSL Agent is open source, because a plugin reads
and writes private key material and restarts services on someone else's host.
Anyone running an Agent should be able to read every line that touches their
keys, and to rebuild an artifact and check it against the digest the catalog
publishes. That rule covers this repository.
