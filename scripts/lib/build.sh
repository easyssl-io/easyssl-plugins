# Sourced by release.sh and publish-release.sh: how a release is built and
# recorded, so the build a release records and the one it publishes cannot
# differ. Every function runs from the repository root.

# The platforms a release is built for, and the flags: -trimpath drops
# absolute paths, -buildid= the build id and -buildvcs=false the VCS stamp, so
# a digest identifies the source, the version stamped into it and the Go
# toolchain. That toolchain is the Go version the Plugin's go.mod names at the
# tag, through GOTOOLCHAIN, which fetches it when another is installed: a build
# of a tag is then the same bytes on any machine, so anyone can check a
# published build against its record, and seeding can record the digests of
# tags released before releases.json existed.
PLATFORMS="linux/amd64 linux/arm64"
VERSION_VAR=github.com/easyssl-io/easyssl-plugins/internal/buildversion.Version

sha256() {
  if command -v sha256sum >/dev/null; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1
}

# build_release DIR VERSION OUT builds the Plugin in DIR as VERSION for every
# platform into OUT/<plugin>-<os>-<arch>, and prints the builds as the JSON
# array a release records.
build_release() {
  dir=$1 version=$2 out=$3
  toolchain=go$(awk '/^go /{print $2}' "$dir/go.mod")
  id=$(basename "$dir")
  json='[]'
  for p in $PLATFORMS; do
    os=${p%/*} arch=${p#*/}
    (cd "$dir" && GOTOOLCHAIN=$toolchain GOWORK=off CGO_ENABLED=0 GOOS=$os GOARCH=$arch \
      go build -trimpath -buildvcs=false -ldflags "-s -w -buildid= -X $VERSION_VAR=$version" -o "$out/$id-$os-$arch" .)
    json=$(printf '%s' "$json" | jq -c --arg os "$os" --arg arch "$arch" --arg sha "$(sha256 "$out/$id-$os-$arch")" \
      '. + [{os: $os, arch: $arch, sha256: $sha}]')
  done
  printf '%s\n' "$json"
}

# describe_at DIR VERSION prints the `describe` answer of the Plugin in DIR
# built as VERSION, run on this machine.
describe_at() {
  (cd "$1" && GOWORK=off go run -ldflags "-X $VERSION_VAR=$2" . describe)
}

# release_record VERSION DATE DESCRIBE_FILE BUILDS prints one release record,
# BUILDS being the JSON array build_release printed.
release_record() {
  jq -c --arg v "$1" --arg d "$2" --argjson b "$4" \
    '{version: $v, date: $d, contractVersion: .contractVersion, description: .description, declarations: .declarations,
      builds: $b}' "$3"
}

# seed_records PLUGIN TAG prints the records of the Plugin's release tags
# before TAG, newest first, each with the digests of its builds: what
# releases.json starts with. A tag that no longer builds is left out, with a
# warning.
seed_records() {
  plugin=$1 skip=$2
  seed=$(mktemp -d)
  out='[]'
  for t in $(git tag --list "$plugin/v*" --sort=-version:refname); do
    v=${t#"$plugin"/v}
    case $v in *-*) continue ;; esac
    [ "$t" != "$skip" ] || continue
    rm -rf "$seed/tree" && git worktree add -q --detach "$seed/tree" "$t"
    if describe_at "$seed/tree/$plugin" "$v" >"$seed/describe.json" 2>"$seed/err" &&
      b=$(build_release "$seed/tree/$plugin" "$v" "$seed" 2>"$seed/err"); then
      d=$(TZ=UTC git log -1 --format=%cd --date=format-local:%Y-%m-%d "$t")
      out=$(printf '%s' "$out" | jq -c --argjson e "$(release_record "$v" "$d" "$seed/describe.json" "$b")" '. + [$e]')
    else
      echo "warning: $t does not build, so it is not recorded: $(head -1 "$seed/err")" >&2
    fi
    git worktree remove --force "$seed/tree"
  done
  rm -rf "$seed"
  printf '%s\n' "$out" | jq .
}
