# easyssl-plugins

First-party plugins for easySSL. Each plugin is a standalone executable that an
easySSL Agent fetches on demand from the Server's catalog, installs only when its
SHA-256 matches the digest the catalog publishes for it, and then drives over
stdio. The digest is checked at install; afterwards the Agent reports the
digest of the file on disk with every inventory, so a replaced executable shows
on the Server rather than being refused on the host.

Nothing here is linked into the Agent binary. An Agent ships with no plugins at
all and gains one only when somebody installs it, which keeps the base install
small enough for constrained hosts and lets this catalog grow without ever
touching the Agent.

## Plugins

| Plugin | What it does |
|--------|--------------|
| [`apache`](apache/README.md) | Finds the certificates every running Apache HTTP Server serves, and deploys to one by writing the files, testing, reloading and checking over TLS what is served. |
| [`generic-cli`](generic-cli/README.md) | The general-purpose fallback: runs one command you write, which puts the certificate and key in place and reloads the service. |
| [`nginx`](nginx/README.md) | Finds the certificates every running nginx serves, and deploys to one by writing the files, testing, reloading and checking over TLS what is served. |

Each Plugin's README says what it does on the host: what it runs, as which user, and where it connects.

Each plugin is its own **Go module** in its own directory, built to its own executable. That is deliberate rather than tidy: a plugin that drives a browser needs dependencies a minimal one must not inherit, and a shared `go.mod` would put them in every plugin's dependency graph. Each plugin is released and versioned on its own: its tag, `generic-cli/v1.2.0`, sets the version its `describe` answer reports, the catalog offers each plugin at the version it reports, and its `CHANGELOG.md` records what each release changes. `scripts/release.sh` also records each release at the top of the plugin's `releases.json`: its date, contract version, the settings it declares and the SHA-256 of each platform's build, which a Server lists in its Marketplace and matches a host's build against. `scripts/publish-release.sh` then publishes those builds as a GitHub Release, after building the tag again and checking it has the recorded digests; only finished releases are published. The first release recorded this way records the earlier tags too, rebuilt for their digests, so they can be published the same way.

## Languages

What a plugin says to a reader (its description, each setting's label and
description, its discovery warnings) is declared in every language the plugin
carries, as an object of language code to text with English (`en`) always
present. Whoever shows the text picks its reader's language and falls back to
English. Each plugin holds its own translations in `internal/ops/locales/`,
one file per language, embedded in the executable.

What a plugin found or ran is not translated: paths, commands, setting keys
and values, a program's own error text, and everything a deployment prints.
`relocate`, which points a server's configuration at other files for the
person running the Agent's `migrate` command, speaks that person's language:
the one `EASYSSL_LANG` names, else the locale's.

## Build

There is no module at the repository root, so build from a plugin's own
directory, with `GOWORK=off` so that a Go workspace in a parent directory is
not used:

```bash
cd generic-cli && GOWORK=off go build ./... && GOWORK=off go test ./... && GOWORK=off go vet ./...
```

Each plugin requires a released version of `easyssl-contract`, so a clone of
this repository builds on its own.

A release binary is built for Linux as below, with the Go version the plugin's
`go.mod` names and the version from its tag. The same command reproduces it
byte for byte, so the result can be compared with the SHA-256 digest the
catalog publishes:

```bash
cd generic-cli && GOTOOLCHAIN=go$(awk '/^go /{print $2}' go.mod) GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
  go build -trimpath -buildvcs=false \
  -ldflags "-s -w -buildid= -X github.com/easyssl-io/easyssl-plugins/internal/buildversion.Version=1.2.0" \
  -o ../dist/generic-cli-linux-arm64 .
```

Code more than one plugin needs is the `internal` module beside them:
`hostfile` replaces a certificate or key file so that only its content changes,
`pemfile` reads certificates and keys, `tlscheck` asks a server which
certificate it presents, `relocation` holds what pointing a configuration at
other files needs whatever its syntax, and `buildversion` holds the version a
release stamps. A plugin reaches it through a relative `replace`, so
sharing costs no cross-repository pin, and its path keeps it importable by the
plugins here alone.

## Why this is open source

Everything that runs on an easySSL Agent has its source published, because a
plugin reads and writes private key material and restarts services on someone else's host.
Anyone running an Agent should be able to read every line that touches their
keys, and to rebuild an artifact and check it against the digest the catalog
publishes. That rule covers this repository, which is also open source under
Apache-2.0 (`LICENSE`), so a Plugin of your own can start from any of these and
ship in a product of your own, owing nothing back.
