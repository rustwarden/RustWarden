#!/usr/bin/env bash
# Decides whether a release is due and writes its notes to notes.md.
# Outputs (to $GITHUB_OUTPUT when set): skip, tag, version.
# First release (no v* tag yet): the notes are README.md with its relative links made absolute.
# Later releases: the commit subjects since the last tag, grouped by type. Subjects only, so no authors.
set -euo pipefail

repo="${GITHUB_REPOSITORY:-rustwarden/RustWarden}"
sha="$(git rev-parse HEAD)"
version="$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n1)"
tag="v$version"
out="${GITHUB_OUTPUT:-/dev/stdout}"
last="$(git describe --tags --abbrev=0 --match "${TAG_MATCH:-v*}" 2>/dev/null || true)"
# The first release of a series (no earlier tag of this kind): the notes cover everything since the last stable release.
base="$last"
[ -z "$base" ] && base="$(git describe --tags --abbrev=0 --match 'v*' --exclude 'v*-*' 2>/dev/null || true)"

skip() { echo "$1"; echo "skip=true" >> "$out"; exit 0; }

if [ -n "$last" ]; then
  count="$(git rev-list --count "$last"..HEAD)"
  [ "$count" -eq 0 ] && skip "No commits since $last; nothing to release."
  if git rev-parse -q --verify "refs/tags/$tag" >/dev/null; then
    echo "::warning::$count commit(s) since $last but Cargo.toml is still $version; bump the version to release them."
    skip "Skipping: $tag already exists."
  fi
fi

if [ -z "$base" ]; then
  # Relative src="..." and ](...) links point into the repo at this commit.
  sed -E \
    -e "s#src=\"([^\":]+)\"#src=\"https://github.com/$repo/raw/$sha/\1\"#g" \
    -e "s#\]\(([^)#:][^):]*)\)#](https://github.com/$repo/blob/$sha/\1)#g" \
    README.md > notes.md
else
  subjects="$(git log "$base"..HEAD --no-merges --format=%s)"
  section() { # title, grep pattern for the type prefix
    local lines
    lines="$(printf '%s\n' "$subjects" | grep -E "^($2)(\(.+\))?!?: " | sed -E 's/^[a-z]+(\([^)]*\))?!?: /- /' || true)"
    [ -n "$lines" ] && printf '### %s\n\n%s\n\n' "$1" "$lines"
    return 0
  }
  {
    echo "## Changes since $base"
    echo
    section "New features" "feat"
    section "Fixes" "fix"
    other="$(printf '%s\n' "$subjects" | grep -vE '^(feat|fix)(\(.+\))?!?: ' | sed -E 's/^[a-z]+(\([^)]*\))?!?: //; s/^/- /' || true)"
    [ -n "$other" ] && printf '### Other\n\n%s\n\n' "$other"
    echo "Full feature log: [changes.md](https://github.com/$repo/blob/$sha/changes.md)"
  } > notes.md
fi

echo "Releasing $tag (previous: ${last:-none})."
{ echo "skip=false"; echo "tag=$tag"; echo "version=$version"; } >> "$out"
