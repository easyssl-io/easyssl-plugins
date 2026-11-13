#!/bin/sh
# Releases Plugin PLUGIN as version VERSION (MAJOR.MINOR.PATCH, no `v`):
#
#   scripts/release.sh apache 0.2.0
#
# Each Plugin is a Go module in its own directory and is released on its own,
# so its tag is `<PLUGIN>/v<VERSION>`, the Go convention for a module in a
# subdirectory; the tag sets the version its `describe` answer reports. Refuses
# a dirty tree, an existing tag, a directory with no go.mod and a version
# `<PLUGIN>/CHANGELOG.md` has no `## VERSION` entry for, and runs the Plugin's
# tests.
#
# It then builds the release for every platform in PLATFORMS, as a Server
# builds it, and records it at the top of `<PLUGIN>/releases.json`: version,
# date, contract version, the `describe` answer's description and
# declarations, and each build's SHA-256. A Server carries that file, so its
# Marketplace lists every release with what it declared, and a host's build
# with one of those digests is that release. The first release recorded this
# way also records the earlier tags, without digests, since their bytes were
# never published. The file is committed and that commit tagged.
#
# Pushing and publishing are left to the caller:
#
#   git push origin HEAD <PLUGIN>/v<VERSION>
#   scripts/publish-release.sh <PLUGIN> <VERSION>
#
# Needs jq.
set -eu
cd "$(dirname "$0")/.."
[ $# -eq 2 ] || { echo "usage: $0 PLUGIN VERSION (e.g. apache 0.2.0)" >&2; exit 2; }
plugin=$1 version=$2
[ -f "$plugin/go.mod" ] && [ -f "$plugin/main.go" ] || { echo "$plugin is not a Plugin directory" >&2; exit 2; }
echo "$version" | grep -Eq '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$' ||
  { echo "$version is not MAJOR.MINOR.PATCH" >&2; exit 2; }
command -v jq >/dev/null || { echo "jq is needed to record the release" >&2; exit 2; }
tag="$plugin/v$version"
[ -z "$(git status --porcelain)" ] || { echo "the working tree has changes" >&2; exit 1; }
if git rev-parse -q --verify "refs/tags/$tag" >/dev/null; then
  echo "$tag is already tagged" >&2; exit 1
fi
grep -qx "## $version" "$plugin/CHANGELOG.md" 2>/dev/null ||
  { echo "$plugin/CHANGELOG.md has no \"## $version\" entry: write what this release changes first, in its own commit" >&2; exit 1; }
(cd "$plugin" && GOWORK=off go test ./...)

. scripts/lib/build.sh
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

builds=$(build_release "$plugin" "$version" "$work")
describe_at "$plugin" "$version" >"$work/describe.json"
records="$plugin/releases.json"
[ -f "$records" ] || seed_records "$plugin" "$tag" >"$records"
release_record "$version" "$(date -u +%Y-%m-%d)" "$work/describe.json" "$builds" >"$work/entry.json"
jq --slurpfile e "$work/entry.json" '$e + .' "$records" >"$work/records.json"
mv "$work/records.json" "$records"

git add "$records"
git commit -q -m "Release $plugin $version" -m "Records this release in $records: what it declares and the SHA-256 of each platform's build."
git tag "$tag"
echo "Tagged $tag. Push, then publish its builds:"
echo "  git push origin HEAD $tag"
echo "  scripts/publish-release.sh $plugin $version"
