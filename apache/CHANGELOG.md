# Changelog

Every release of the `apache` Plugin, newest first, each tagged `apache/v<version>`.

## Unreleased

Built against `easyssl-contract` 0.1.1.

- A certificate under another ACME client's directory (certbot's
  `/etc/letsencrypt`, acme.sh, dehydrated, lego) is no longer refused by this
  Plugin, in discovery or in a Deployment: the Agent knows those clients,
  warns about such a certificate and refuses to deploy there itself.

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
