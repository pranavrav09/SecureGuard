#!/usr/bin/env bash
set -u

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
RUNNER="$ROOT/bin/securerunner"
FIXTURE="$ROOT/bin/fixture"
ROOTFS="$ROOT/build/test-rootfs"
PROCESS_ONLY=0
PASSED=0
FAILED=0
TEST_TMP=$(mktemp -d)
TEST_OUT="$TEST_TMP/out"
TEST_ERR="$TEST_TMP/err"
trap 'rm -rf "$TEST_TMP"' EXIT

if [[ ${1:-} == "--process-only" ]]; then
    PROCESS_ONLY=1
fi

pass() {
    PASSED=$((PASSED + 1))
    printf 'ok %d - %s\n' "$((PASSED + FAILED))" "$1"
}

fail() {
    FAILED=$((FAILED + 1))
    printf 'not ok %d - %s\n' "$((PASSED + FAILED))" "$1"
}

expect_status() {
    local name=$1 expected=$2
    shift 2
    "$@" >"$TEST_OUT" 2>"$TEST_ERR"
    local actual=$?
    if [[ $actual -eq $expected ]]; then pass "$name"; else
        fail "$name (expected $expected, got $actual)"
        sed 's/^/# /' "$TEST_ERR"
    fi
}

expect_output() {
    local name=$1 expected=$2
    shift 2
    local output
    output=$("$@" 2>"$TEST_ERR")
    local actual=$?
    if [[ $actual -eq 0 && $output == "$expected" ]]; then pass "$name"; else
        fail "$name (status $actual, output '$output')"
        sed 's/^/# /' "$TEST_ERR"
    fi
}

printf 'TAP version 13\n'
if [[ $PROCESS_ONLY -eq 1 ]]; then printf '1..10\n'; else printf '1..16\n'; fi

expect_output "process executes a program" "OK" "$RUNNER" --mode process --network host -- "$FIXTURE" ok
expect_status "process propagates exit status" 23 "$RUNNER" --mode process --network host -- "$FIXTURE" exit 23
expect_output "process preserves arguments" "hello sandbox" "$RUNNER" --mode process --network host -- "$FIXTURE" echo "hello sandbox"
expect_status "wall-clock timeout kills the job" 124 "$RUNNER" --mode process --timeout 25 --network host -- "$FIXTURE" sleep 500
expect_status "address-space limit blocks allocation" 0 "$RUNNER" --mode process --memory 32M --network host -- "$FIXTURE" allocate-denied 96
expect_status "open-file limit is enforced" 0 "$RUNNER" --mode process --nofile 16 --network host -- "$FIXTURE" open-many 64
expect_output "seccomp blocks ptrace" "DENIED" "$RUNNER" --mode process --network host -- "$FIXTURE" syscall ptrace
expect_output "seccomp blocks bpf" "DENIED" "$RUNNER" --mode process --network host -- "$FIXTURE" syscall bpf
expect_output "seccomp blocks mount" "DENIED" "$RUNNER" --mode process --network host -- "$FIXTURE" syscall mount
expect_output "seccomp blocks network creation" "DENIED" "$RUNNER" --mode process --network none -- "$FIXTURE" syscall socket

if [[ $PROCESS_ONLY -eq 0 ]]; then
    if [[ ! -x "$ROOTFS/bin/fixture" ]]; then
        "$ROOT/scripts/build-test-rootfs.sh" || exit 1
    fi
    C=("$RUNNER" --mode container --rootfs "$ROOTFS")
    if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
        printf '# Full suite requires root for delegated cgroup v2 control.\n'
        printf '# Run: sudo make test-security\n'
        exit 1
    fi
    expect_output "PID namespace hides host process IDs" "1" "${C[@]}" -- /bin/fixture pid
    expect_output "UTS namespace has isolated hostname" "sandbox" "${C[@]}" -- /bin/fixture hostname
    expect_status "root filesystem is read-only" 0 "${C[@]}" -- /bin/fixture write-denied /probe
    expect_status "host filesystem is not visible" 0 "${C[@]}" -- /bin/fixture read-denied /host-secret
    expect_status "cgroup pids.max stops fork growth" 0 "${C[@]}" --pids 8 -- /bin/fixture spawn-denied 32
    expect_status "cgroup memory.max stops over-allocation" 0 "${C[@]}" --memory 32M -- /bin/fixture allocate-denied 96
fi

if [[ $FAILED -ne 0 ]]; then
    printf '# %d passed, %d failed\n' "$PASSED" "$FAILED"
    exit 1
fi
printf '# %d/%d security tests passed\n' "$PASSED" "$PASSED"
