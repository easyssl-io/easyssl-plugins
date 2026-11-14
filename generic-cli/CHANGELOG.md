# Changelog

Every release of the `generic-cli` Plugin, newest first, each tagged `generic-cli/v<version>`.

## 0.2.3

Built against `easyssl-contract` 0.2.0. No change to the Plugin: released
because the code the Plugins share changed, so this build is a release
rather than a development build.

## 0.2.2

Built against `easyssl-contract` 0.2.0, with Go 1.26.11, which fixes
GO-2026-6859 in `net/http`. No change to the Plugin.

## 0.2.1

Built against `easyssl-contract` 0.2.0. No change to the Plugin: the first
release recorded in `releases.json`, with the SHA-256 of each platform's
build, and published as a GitHub Release, as its earlier releases now are too.

## 0.2.0

Built against `easyssl-contract` 0.2.0.

- Answers `relocate`: a request with nothing to move succeeds, changing
  nothing, and any move is refused, since this Plugin reads no configuration.

## 0.1.0

The first release, built against `easyssl-contract` 0.1.0.

- Deploys by running a shell script you write, with the Certificate, its
  chain, the full chain and the private key in temporary files named by
  `EASYSSL_CERTIFICATE_PATH`, `EASYSSL_CHAIN_PATH`, `EASYSSL_FULLCHAIN_PATH`
  and `EASYSSL_KEY_PATH`. It discovers nothing.
