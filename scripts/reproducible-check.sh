#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -gt 1 ]; then
    printf 'Usage: %s [live-origin]\n' "$0" >&2
    exit 2
fi

repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
commit=$(git -C "$repo" rev-parse HEAD)
workspace=$(mktemp -d)
tag="tightlip-repro:$(basename "$workspace" | tr '[:upper:]' '[:lower:]')"
container=
cleanup() {
    if [ -n "$container" ]; then docker rm "$container" >/dev/null 2>&1 || true; fi
    docker image rm "$tag-first" "$tag-second" >/dev/null 2>&1 || true
    rm -rf -- "$workspace"
}
trap cleanup EXIT

mkdir -p -- "$workspace/source"
git -C "$repo" archive --format=tar "$commit" | tar -xf - -C "$workspace/source"

for run in first second; do
    docker buildx build --no-cache --load --build-arg "TIGHTLIP_RELEASE_COMMIT=$commit" \
        --tag "$tag-$run" "$workspace/source"
    container=$(docker create "$tag-$run")
    docker cp "$container:/app/web" "$workspace/$run"
    docker rm "$container" >/dev/null
    container=
done

diff -r "$workspace/first" "$workspace/second"
printf '%s\n' 'The two uncached Docker builds produced identical web bundles.'
if [ "$#" -eq 1 ]; then
    bash "$repo/scripts/verify-live.sh" "$1" "$workspace/first/release.json"
fi
