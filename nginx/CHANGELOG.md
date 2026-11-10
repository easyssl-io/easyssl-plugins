# Changelog

Every release of the `nginx` Plugin, newest first, each tagged `nginx/v<version>`.

## Unreleased

Built against `easyssl-contract` 0.1.1.

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
