#!/usr/bin/env bash
set -euo pipefail

repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
workspace=$(mktemp -d)
trap 'rm -rf -- "$workspace"' EXIT

# Take one snapshot so both builds use the same committed sources.
git -C "$repo" archive --format=tar HEAD > "$workspace/source.tar"

for run in first second; do
    copy="$workspace/$run"
    mkdir -p -- "$copy"
    tar -xf "$workspace/source.tar" -C "$copy"
    (
        cd -- "$copy/web"
        export CARGO_BUILD_JOBS=2 CARGO_TARGET_DIR="$copy/target"
        npm ci
        npm run build

        cd -- dist
        find . -type f -print0 | LC_ALL=C sort -z | xargs -0 -r sha256sum \
            > "$workspace/$run.sha256"
        test -s "$workspace/$run.sha256"
    )
done

diff -u "$workspace/first.sha256" "$workspace/second.sha256"
printf '%s\n' 'The web bundles have identical SHA-256 hashes.'
