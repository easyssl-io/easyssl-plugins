# Changelog

Every release of the `apache` Plugin, newest first, each tagged `apache/v<version>`.

## 0.2.6

Built against `easyssl-contract` 0.2.3. The note a move leaves can no longer
end in a backslash, which Apache would read as continuing the comment into
the directive below it.

## 0.2.5

Built against `easyssl-contract` 0.2.3. A move out of certbot's directory
leaves the relocate request's note on a line of its own above each run of
consecutive lines it changes.

## 0.2.4

Built against `easyssl-contract` 0.2.2. The leaf and chain PEM of all the
certificates in one answer are kept within 96 KiB, dropping chains and then
leaves from the last certificate back, so a host with many certificates no
longer sends an answer an Agent refuses for its size.

## 0.2.3

Built against `easyssl-contract` 0.2.2. A discovered certificate now carries
its leaf (`certificatePem`) and the certificates after it in the certificate
file (`chainPem`), so the Server can describe a certificate easySSL did not
request. A chain kept in a separate `SSLCertificateChainFile` is not
reported yet.

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
- Discovery reports every certificate file it can attribute, suggested or not,
  each with the configuration lines that name its certificate and key files
  (`references`, the argument as the file writes it) and its own warnings,
  worded without its path: a name or key type collision is now a warning of
  each certificate in it. A certificate whose names cannot be read is no longer
  suggested. The `Locations` extra data is gone: the references replace it.
- Reads a single-quoted argument in the configuration as httpd does: a key
  file written `'/path'` was read as a path with quotes in it.
- Adds `relocate`, which points the confirmed configuration lines at other
  files, tests, reloads and checks that the master survived, putting every
  file back on any failure.
- A Deployment into a directory a non-root user owns no longer fails with
  `as uid <n>: ` and nothing after it.

## 0.1.0

The first release, built against `easyssl-contract` 0.1.0.

- Discovers the certificates every running Apache serves, reading its
  configuration as httpd reports it, and suggests as a Target only what it
  can replace safely.
- Deploys by writing the full chain and the key in place, keeping each file's
  owner, mode, ACLs and other extended attributes, running the instance's
  configuration test, reloading, and checking over TLS that every place the
  file is served presents the new Certificate. A failure puts the previous
  files back, except a failed reload of a file no running Apache loads yet,
  which leaves the new files in place.
