#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
ROOTFS="$ROOT/build/test-rootfs"

make -C "$ROOT" fixture-static
rm -rf "$ROOTFS"
mkdir -p "$ROOTFS"/{bin,dev,etc,proc,sys,tmp}
chmod 1777 "$ROOTFS/tmp"
install -m 0755 "$ROOT/bin/fixture-static" "$ROOTFS/bin/fixture"
printf 'root:x:0:0:root:/tmp:/bin/false\n' >"$ROOTFS/etc/passwd"
printf 'built test rootfs: %s\n' "$ROOTFS"
