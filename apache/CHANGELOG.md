# Changelog

Every release of the `apache` Plugin, newest first, each tagged `apache/v<version>`.

## Unreleased

Built against `easyssl-contract` 0.1.1.

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
