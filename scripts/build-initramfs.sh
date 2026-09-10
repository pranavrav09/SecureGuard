#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
    echo "usage: $0 STATIC_PAYLOAD OUTPUT_INITRAMFS" >&2
    exit 2
fi

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
PAYLOAD=$(realpath "$1")
OUTPUT=$(realpath -m "$2")
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

make -C "$ROOT" guest-init
mkdir -p "$WORK"/{dev,proc,sys,tmp}
install -m 0755 "$ROOT/bin/securerunner-guest-init" "$WORK/init"
install -m 0755 "$PAYLOAD" "$WORK/payload"

if command -v file >/dev/null && ! file "$PAYLOAD" | grep -q 'statically linked'; then
    echo "payload must be a statically linked Linux executable" >&2
    exit 1
fi

(cd "$WORK" && find . -print0 | cpio --null -o --format=newc 2>/dev/null | gzip -9) >"$OUTPUT"
printf 'built VM initramfs: %s\n' "$OUTPUT"
