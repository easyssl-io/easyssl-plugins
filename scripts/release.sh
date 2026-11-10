#!/bin/sh
# Releases Plugin PLUGIN as version VERSION (MAJOR.MINOR.PATCH, no `v`):
#
#   scripts/release.sh apache 0.2.0
#
# Each Plugin is a Go module in its own directory and is released on its own,
# so its tag is `<PLUGIN>/v<VERSION>`, the Go convention for a module in a
# subdirectory; the tag sets the version its `describe` answer reports. Refuses
# a dirty tree, an existing tag, a directory with no go.mod and a version
# `<PLUGIN>/CHANGELOG.md` has no `## VERSION` entry for, runs the Plugin's
# tests, and tags the current commit. No Plugin keeps released message
# examples, so nothing is committed. Pushing is left to the caller:
# `git push origin HEAD <PLUGIN>/v<VERSION>`.
set -eu
cd "$(dirname "$0")/.."

[ $# -eq 2 ] || { echo "usage: $0 PLUGIN VERSION (e.g. apache 0.2.0)" >&2; exit 2; }
plugin=$1 version=$2
[ -f "$plugin/go.mod" ] && [ -f "$plugin/main.go" ] || { echo "$plugin is not a Plugin directory" >&2; exit 2; }
echo "$version" | grep -Eq '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$' ||
  { echo "$version is not MAJOR.MINOR.PATCH" >&2; exit 2; }
tag="$plugin/v$version"
[ -z "$(git status --porcelain)" ] || { echo "the working tree has changes" >&2; exit 1; }
if git rev-parse -q --verify "refs/tags/$tag" >/dev/null; then
  echo "$tag is already tagged" >&2; exit 1
fi
grep -qx "## $version" "$plugin/CHANGELOG.md" 2>/dev/null ||
  { echo "$plugin/CHANGELOG.md has no \"## $version\" entry: write what this release changes first, in its own commit" >&2; exit 1; }

(cd "$plugin" && GOWORK=off go test ./...)
git tag "$tag"
echo "Tagged $tag. Push with: git push origin HEAD $tag"
