#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
MODE=process
ITERATIONS=100
ROOTFS=
KERNEL=
INITRD=

while [[ $# -gt 0 ]]; do
    case "$1" in
        --mode) MODE=$2; shift 2 ;;
        --iterations) ITERATIONS=$2; shift 2 ;;
        --rootfs) ROOTFS=$2; shift 2 ;;
        --kernel) KERNEL=$2; shift 2 ;;
        --initrd) INITRD=$2; shift 2 ;;
        --) shift; break ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done

if [[ $# -eq 0 ]]; then
    if [[ $MODE == container ]]; then COMMAND=(/bin/fixture ok); else COMMAND=("$ROOT/bin/fixture" ok); fi
else
    COMMAND=("$@")
fi

RUN=("$ROOT/bin/securerunner" --mode "$MODE" --timeout 10000)
case "$MODE" in
    process) RUN+=(--network host) ;;
    container) [[ -n $ROOTFS ]] || { echo "--rootfs is required" >&2; exit 2; }; RUN+=(--rootfs "$ROOTFS") ;;
    vm) [[ -n $KERNEL && -n $INITRD ]] || { echo "--kernel and --initrd are required" >&2; exit 2; }; RUN+=(--vm-kernel "$KERNEL" --vm-initrd "$INITRD") ;;
    *) echo "invalid mode: $MODE" >&2; exit 2 ;;
esac

SAMPLES=$(mktemp)
trap 'rm -f "$SAMPLES"' EXIT
for ((i=0; i<ITERATIONS; i++)); do
    start=$(date +%s%N)
    "${RUN[@]}" -- "${COMMAND[@]}" >/dev/null 2>&1
    stop=$(date +%s%N)
    printf '%s\n' "$((stop - start))" >>"$SAMPLES"
done
sort -n "$SAMPLES" -o "$SAMPLES"

percentile() {
    local p=$1
    awk -v p="$p" -v n="$ITERATIONS" 'NR == int((n*p + 99)/100) { printf "%.3f", $1/1000000 }' "$SAMPLES"
}

printf '{"mode":"%s","iterations":%d,"p50_ms":%s,"p95_ms":%s,"p99_ms":%s}\n' \
    "$MODE" "$ITERATIONS" "$(percentile 50)" "$(percentile 95)" "$(percentile 99)"
