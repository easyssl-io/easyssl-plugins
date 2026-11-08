# Changelog

Every release of the `nginx` Plugin, newest first, each tagged `nginx/v<version>`.

## 0.1.0

The first release, built against `easyssl-contract` 0.1.0.

- Discovers the certificates every running nginx serves, with the files,
  test command and reload command of each instance, and suggests as a Target
  only what it can replace safely.
- Deploys by writing the certificate and key in place, keeping each file's
  owner, mode, ACLs and SELinux label, testing the configuration, reloading
  only when the test passes, and checking over TLS that nginx serves the new
  Certificate. A failure puts the previous files back.
