# apache

The easySSL Plugin for the Apache HTTP Server (`httpd`, `apache2`).

It finds the certificates every running Apache master serves, reading its
configuration as httpd itself reports it (`DUMP_CONFIG` with every conditional
evaluated, and `DUMP_VHOSTS`), and works out where a client reaches each one. A
certificate is suggested as a Target only when nothing about how Apache uses it
could make a renewal go wrong; anything else is a discovery warning instead.

It deploys by checking the Target and every other certificate and key the
reload loads, writing the full chain and the key with everything but their
content kept (owner, mode, ACLs and other extended attributes), running the
instance's configuration test as the instance's own user, reloading, and
checking over TLS that every place the file is served presents the new
Certificate. A failure puts the previous files back, and an Apache the reload
stopped is started again. A file no running Apache loads yet is deployed ahead:
test and reload run as root, nothing is checked over TLS, and a failed reload
leaves the new files in place.

## On the host

- **Linux only.** Discovery reads `/proc`; elsewhere it reports a warning and no
  Targets, and a deployment fails.
- **Runs as root**, as the Agent runs it. Discovery refuses otherwise. Every
  program it runs from an instance's binary runs as that instance's user when
  it is not root, the version probe included; a process whose credentials
  cannot be read is skipped. Each file is written as the user its directory
  belongs to, and a path where another user could swap a directory is refused.
- **Runs** the instance's own binary with the master's own `-d`, `-f`, `-D`,
  `-C` and `-c`: `-v`, `-t -D DUMP_RUN_CFG`, `-t -D DUMP_MODULES`,
  `-t -D DUMP_CONFIG` (loading `mod_info` for that run when the instance has not),
  `-t -D DUMP_VHOSTS` and `-t -D DUMP_INCLUDES`; `systemctl show` for the unit's
  reload command; and the `test` and `reload` settings under `/bin/sh -e`.
- **Connects** over TLS, after a reload, to every address and port the file is
  served on, a `*` virtual host at the loopback and each local IPv4 address. It
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
