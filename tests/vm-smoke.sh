#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "usage: $0 LINUX_KERNEL" >&2
    exit 2
fi

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
KERNEL=$(realpath "$1")
INITRD="$ROOT/build/test-initramfs.cpio.gz"

make -C "$ROOT" fixture-static
"$ROOT/scripts/build-initramfs.sh" "$ROOT/bin/fixture-static" "$INITRD"

run_vm() {
    "$ROOT/bin/securerunner" --mode vm --timeout 10000 \
        --vm-kernel "$KERNEL" --vm-initrd "$INITRD" -- "$@"
}

output=$(run_vm /payload ok)
grep -q '^OK$' <<<"$output"
set +e
run_vm /payload exit 23 >/dev/null
status=$?
set -e
[[ $status -eq 23 ]]
output=$(run_vm /payload hostname)
grep -q '^securerunner-vm$' <<<"$output"
echo "VM smoke tests passed"
