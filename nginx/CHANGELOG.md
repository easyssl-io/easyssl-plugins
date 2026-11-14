# Changelog

Every release of the `nginx` Plugin, newest first, each tagged `nginx/v<version>`.

## 0.2.3

Built against `easyssl-contract` 0.2.2. A discovered certificate now carries
its leaf (`certificatePem`) and the certificates after it in the file
(`chainPem`), so the Server can describe a certificate easySSL did not
request.

## 0.2.2

Built against `easyssl-contract` 0.2.0, with Go 1.26.11, which fixes
GO-2026-6859 in `net/http`. No change to the Plugin.

## 0.2.1

Built against `easyssl-contract` 0.2.0. No change to the Plugin: the first
release recorded in `releases.json`, with the SHA-256 of each platform's
build, and published as a GitHub Release, as its earlier releases now are too.

## 0.2.0

Built against `easyssl-contract` 0.2.0.

- A certificate under another ACME client's directory (certbot's
  `/etc/letsencrypt`, acme.sh, dehydrated, lego) is no longer refused by this
  Plugin, in discovery or in a Deployment: the Agent knows those clients,
  warns about such a certificate and refuses to deploy there itself.
- Discovery reports every certificate it can attribute, suggested or not, each
  with the configuration lines that name its certificate and key files
  (`references`) and its own warnings, worded without its path. A certificate
  whose names cannot be read is no longer suggested. The `Locations` extra
  data is gone: the references replace it.
- Adds `relocate`, which points the confirmed configuration lines at other
  files, tests, reloads and checks that nginx applied the reload, putting every
  file back on any failure.
- A Deployment into a directory a non-root user owns no longer fails with
  `as uid <n>: ` and nothing after it.

## 0.1.0

The first release, built against `easyssl-contract` 0.1.0.

- Discovers the certificates every running nginx serves, with the files,
  test command and reload command of each instance, and suggests as a Target
  only what it can replace safely.
- Deploys by writing the certificate and key in place, keeping each file's
  owner, mode, ACLs and SELinux label, testing the configuration, reloading
  only when the test passes, and checking over TLS that nginx serves the new
  Certificate. A failed test puts the previous files back; a failed reload
  leaves the new files in place, and nginx keeps serving what it last
  loaded.
