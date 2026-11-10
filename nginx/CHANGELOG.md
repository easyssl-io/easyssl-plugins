# Changelog

Every release of the `nginx` Plugin, newest first, each tagged `nginx/v<version>`.

## Unreleased

Built against `easyssl-contract` 0.1.1.

- A certificate under another ACME client's directory (certbot's
  `/etc/letsencrypt`, acme.sh, dehydrated, lego) is no longer refused by this
  Plugin, in discovery or in a Deployment: the Agent knows those clients,
  warns about such a certificate and refuses to deploy there itself.

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
