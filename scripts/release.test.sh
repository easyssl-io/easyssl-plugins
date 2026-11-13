#!/bin/sh
# Tests scripts/release.sh in a throwaway clone of this repository, so nothing
# here is ever tagged: a release records itself at the top of
# `<plugin>/releases.json`, with a build per platform whose digest is its
# bytes', commits that and tags `<plugin>/v<version>` on the commit, and
# refuses a repeated tag, a dirty tree, a directory that is not a Plugin and a
# version without a CHANGELOG.md entry. The clone takes no tags,
# and the test uses versions 0.901.x, which no real release reaches, so it
# passes whatever this repository has released.
set -eu
cd "$(dirname "$0")/.."
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
git clone -q --no-tags . "$work/plugins"
mkdir -p "$work/plugins/scripts/lib" && cp scripts/release.sh scripts/publish-release.sh "$work/plugins/scripts/" && cp scripts/lib/build.sh "$work/plugins/scripts/lib/build.sh"
cd "$work/plugins"
export GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@example.com GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@example.com
# The script as it is in this checkout, committed only when it differs from
# the clone's, so the clone's tree is clean either way.
git add scripts/release.sh scripts/publish-release.sh scripts/lib/build.sh
git diff --cached --quiet || git commit -q -m "the script under test"

fail=0
expect() { # expect STATUS DESCRIPTION COMMAND...
  want=$1; what=$2; shift 2
  if "$@" >"$work/out" 2>&1; then got=0; else got=1; fi
  if [ "$got" != "$want" ]; then echo "FAIL: $what (exit $got)"; cat "$work/out"; fail=1; fi
}
entry() { # entry VERSION, committed
  printf '\n## %s\n\nA test release.\n' "$1" >> generic-cli/CHANGELOG.md
  git add generic-cli/CHANGELOG.md && git commit -q -m "entry $1"
}
expect 1 "a directory that is not a Plugin" scripts/release.sh internal 0.901.0
expect 1 "a version CHANGELOG.md has no entry for" scripts/release.sh generic-cli 0.901.0
grep -q 'CHANGELOG.md has no' "$work/out" || { echo "FAIL: the refusal does not name CHANGELOG.md"; fail=1; }
# A release tagged before releases.json existed, which the first recorded
# release records too, rebuilt for its digests.
git tag generic-cli/v0.900.0
entry 0.901.0
expect 0 "a release" scripts/release.sh generic-cli 0.901.0
[ "$(git tag --points-at HEAD)" = generic-cli/v0.901.0 ] || { echo "FAIL: generic-cli/v0.901.0 is not on the current commit"; fail=1; }
git show --stat HEAD | grep -q 'generic-cli/releases.json' || { echo "FAIL: the tagged commit does not carry releases.json"; fail=1; }
records=generic-cli/releases.json
[ "$(jq -r '.[0].version' "$records")" = 0.901.0 ] || { echo "FAIL: the release is not recorded first"; fail=1; }
[ "$(jq '.[0].builds | length' "$records")" = 2 ] || { echo "FAIL: not one build per platform"; fail=1; }
[ "$(jq '.[0].declarations | length > 0' "$records")" = true ] || { echo "FAIL: the declarations are not recorded"; fail=1; }
[ "$(jq -r '.[0].contractVersion' "$records")" != null ] || { echo "FAIL: the contract version is not recorded"; fail=1; }
# The digest recorded is the bytes' of a build of the tag, as publishing checks.
. scripts/lib/build.sh
mkdir "$work/rebuilt"
[ "$(build_release generic-cli 0.901.0 "$work/rebuilt" | jq -S -c .)" = "$(jq -S -c '.[0].builds' "$records")" ] ||
  { echo "FAIL: a rebuild of the tag does not have the recorded digests"; fail=1; }
expect 1 "a version already tagged" scripts/release.sh generic-cli 0.901.0
entry 0.901.1
echo x >> README.md
expect 1 "a working tree with changes" scripts/release.sh generic-cli 0.901.1
git checkout -q README.md
expect 0 "a second release" scripts/release.sh generic-cli 0.901.1
[ "$(jq -r '[.[].version] | join(" ")' "$records")" = "0.901.1 0.901.0 0.900.0" ] || { echo "FAIL: releases are not newest first: $(jq -c '[.[].version]' "$records")"; fail=1; }
[ "$(jq '.[2].builds | length' "$records")" = 2 ] && [ "$(jq '.[2].declarations | length > 0' "$records")" = true ] ||
  { echo "FAIL: the earlier tag is not recorded with its declarations and builds"; fail=1; }

# Publishing, against a throwaway remote and a stand-in gh that records what it
# was asked: nothing is pushed or published for real.
git init -q --bare "$work/origin.git"
git remote set-url origin "$work/origin.git"
mkdir "$work/bin"
printf '#!/bin/sh\nprintf "%%s\\n" "$@" >"%s/gh-args"\nfor a; do [ -f "$a" ] && cp "$a" "%s/published/"; done\n' "$work" "$work" >"$work/bin/gh"
chmod +x "$work/bin/gh" && mkdir "$work/published"
expect 1 "publishing a tag not pushed" env PATH="$work/bin:$PATH" scripts/publish-release.sh generic-cli 0.901.1
git push -q origin generic-cli/v0.901.1
expect 0 "publishing a pushed release" env PATH="$work/bin:$PATH" scripts/publish-release.sh generic-cli 0.901.1
grep -qx 'generic-cli/v0.901.1' "$work/gh-args" || { echo "FAIL: gh was not asked for the release's tag"; fail=1; }
for f in generic-cli-linux-amd64 generic-cli-linux-arm64 SHA256SUMS generic-cli.describe.json; do
  [ -f "$work/published/$f" ] || { echo "FAIL: $f was not published"; fail=1; }
done
[ "$(cut -d' ' -f1 "$work/published/SHA256SUMS" | sort | tr '\n' ' ')" = "$(jq -r '.[0].builds[].sha256' "$records" | sort | tr '\n' ' ')" ] ||
  { echo "FAIL: SHA256SUMS does not list the recorded digests"; fail=1; }
# The earlier tag has no releases.json of its own; the record at HEAD is used.
rm -f "$work/published"/*
git push -q origin generic-cli/v0.900.0
expect 0 "publishing a release tagged before releases.json" env PATH="$work/bin:$PATH" scripts/publish-release.sh generic-cli 0.900.0
[ "$(cut -d' ' -f1 "$work/published/SHA256SUMS" | sort | tr '\n' ' ')" = "$(jq -r '.[2].builds[].sha256' "$records" | sort | tr '\n' ' ')" ] ||
  { echo "FAIL: the earlier release is not published with its recorded digests"; fail=1; }
exit "$fail"
