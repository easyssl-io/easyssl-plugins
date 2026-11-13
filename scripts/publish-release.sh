#!/bin/sh
# Publishes release VERSION of Plugin PLUGIN as a GitHub Release, after
# scripts/release.sh recorded and tagged it and the tag was pushed:
#
#   scripts/publish-release.sh apache 0.3.0
#
# Builds the tag again, in a worktree of its own, refuses unless every build's
# SHA-256 is the one `<PLUGIN>/releases.json` recorded at that tag, and creates
# the GitHub Release `<PLUGIN>/v<VERSION>` with the builds, a SHA256SUMS file
# and the `describe` answer, its notes the version's CHANGELOG.md entry. A
# Server pinned at the tag downloads these builds and checks them against the
# same record, so every installation hands out the bytes released. A mismatch
# means another Go toolchain than the release's; publish with that one.
#
# Only finished releases are published; a development build is served by the
# Server that built it. Needs gh, signed in with permission to create releases,
# and jq.
set -eu
cd "$(dirname "$0")/.."
[ $# -eq 2 ] || { echo "usage: $0 PLUGIN VERSION (e.g. apache 0.3.0)" >&2; exit 2; }
plugin=$1 version=$2
tag="$plugin/v$version"
command -v jq >/dev/null && command -v gh >/dev/null || { echo "gh and jq are needed" >&2; exit 2; }
git rev-parse -q --verify "refs/tags/$tag" >/dev/null || { echo "$tag is not tagged here" >&2; exit 1; }
[ -n "$(git ls-remote --tags origin "refs/tags/$tag")" ] || { echo "$tag is not pushed: git push origin $tag" >&2; exit 1; }
want=$(git show "$tag:$plugin/releases.json" 2>/dev/null | jq -c --arg v "$version" '.[] | select(.version == $v) | .builds // empty')
[ -n "$want" ] || { echo "$plugin/releases.json at $tag records no builds for $version" >&2; exit 1; }

. scripts/lib/build.sh
work=$(mktemp -d)
trap 'git worktree remove --force "$work/tree" 2>/dev/null; rm -rf "$work"' EXIT
git worktree add -q --detach "$work/tree" "$tag"
mkdir "$work/out"
got=$(build_release "$work/tree/$plugin" "$version" "$work/out")
if [ "$(printf '%s' "$got" | jq -S -c .)" != "$(printf '%s' "$want" | jq -S -c .)" ]; then
  echo "the builds of $tag do not match what it recorded" >&2
  echo "  recorded: $want" >&2
  echo "  built:    $got" >&2
  echo "Publish with the Go toolchain the release was built with ($(go env GOVERSION) here)." >&2
  exit 1
fi
describe_at "$work/tree/$plugin" "$version" >"$work/out/$plugin.describe.json"
(cd "$work/out" && for f in "$plugin"-*-*; do printf '%s  %s\n' "$(sha256 "$f")" "$f"; done) >"$work/out/SHA256SUMS"
awk -v v="## $version" '$0 == v { on = 1; next } on && /^## / { exit } on' "$work/tree/$plugin/CHANGELOG.md" >"$work/notes.md"
gh release create "$tag" --verify-tag --title "$plugin $version" --notes-file "$work/notes.md" "$work/out"/*
