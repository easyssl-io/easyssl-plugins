# nginx

The easySSL Plugin for nginx.

It finds the certificates every running nginx master serves (parsing its
configuration with every `include`, pairing dual RSA and ECDSA certificates by
algorithm) and suggests each as a Target, unless its file or its key's cannot be
replaced safely, a place nginx serves it from cannot be checked over TLS (no
`ssl` listen, `proxy_protocol`, a server whose names an earlier one claims), its
configuration was edited since nginx loaded it, or the pid file
`nginx -s reload` would read does not name the master, which is a discovery
warning instead and a refusal at deploy. The test and reload commands repeat
the master's own `-p`, `-c` and `-g`.

It deploys by writing the full chain and the key with everything but their
content kept (owner, mode, ACLs and other extended attributes), running the
`test` setting, reloading, and checking over TLS that every place it can work
out from `listen` and `server_name` presents the new Certificate. A failed test
or a Certificate not served puts the previous files back, the latter with
nginx's `[emerg]` reason quoted and a second reload. A failed reload leaves the
new files in place, and nginx keeps serving what it last loaded.

## On the host

- **Linux only.** Discovery reads `/proc`; elsewhere it reports a warning and no
  Targets.
- **Runs as root**, as the Agent runs it. Discovery refuses otherwise. The
  `test` setting runs as the master's user when it is the command discovery
  derived for that master, and so does `reload` when it is the derived
  `nginx -s reload`; an edited command, and a supervisor's reload (`systemctl`,
  `rc-service`), run as root. Each file is written as the user its directory
  belongs to, and a path where another user could swap a directory is refused.
- **Runs** the master's own binary with `-V` and with `-t` (repeating its `-p`,
  `-c` and `-g`), both as the master's user, since anyone can start a process
  with nginx's title; a process whose user cannot be read is skipped.
  Also `systemctl show` for the unit's reload command, and the
  `test` and `reload` settings under `/bin/sh -e`. The configuration itself is
  parsed in the Plugin, not by `nginx -T`.
- **Connects** over TLS, after a reload, to every `listen ... ssl` address (`*`
  at `127.0.0.1`, `::` at `::1`), with the first exact `server_name` as SNI. It
  compares the certificate served with the new one and verifies nothing else.

## Settings

Its `describe` answer, with every setting and its description in each language,
is pinned in [`internal/ops/testdata/describe.json`](internal/ops/testdata/describe.json).

## Build

```bash
GOWORK=off go build ./... && GOWORK=off go test ./...
```

How to rebuild a release binary byte for byte is in the repository's
[README](../README.md#build).
