# SecureRunner

SecureRunner is a small C sandbox for executing untrusted Linux programs behind one of three isolation boundaries: a constrained process, a Linux namespace container, or a QEMU/KVM virtual machine. It is intentionally compact enough to audit and instrument.

> [!WARNING]
> Sandboxing is a defense-in-depth problem. The process and container backends share the host kernel; use the VM backend when the workload is hostile or crosses a trust boundary.

## Isolation backends

| Mode | Boundary | Controls | Typical use |
| --- | --- | --- | --- |
| `process` | Unix process | rlimits, `no_new_privs`, seccomp-BPF, process-group timeout | Fast local jobs |
| `container` | Shared Linux kernel | user/PID/mount/UTS/IPC/network namespaces, read-only `pivot_root`, cgroups v2, dropped capabilities, seccomp-BPF | Untrusted build and judge workloads |
| `vm` | QEMU/KVM guest | Separate guest kernel, fixed RAM, no emulated network or disks, initramfs-only root | Highest-risk native code |

The default seccomp policy returns `EACCES` for kernel attack-surface syscalls including `bpf`, `ptrace`, mount operations, module loading, `setns`, `unshare`, `userfaultfd`, performance events, keyrings, and cross-process memory access. With `--network none` it also denies socket creation and connection syscalls.

## Build

SecureRunner targets x86-64 or ARM64 Linux with cgroups v2. On Ubuntu 22.04 or newer:

```bash
sudo apt-get update
sudo apt-get install -y build-essential cpio qemu-system-x86
make
```

## Run

Process mode starts in under a millisecond on the reference host:

```bash
./bin/securerunner --mode process --timeout 1000 --memory 64M -- /usr/bin/printf 'hello\n'
```

Build the minimal static test root and run a namespace container. Root is used here to delegate a cgroup and prepare mounts; before execution the payload is changed to UID/GID 65534 and receives no capabilities. When invoked without root, SecureRunner instead uses a one-ID user namespace when the host permits unprivileged namespace mounts.

```bash
./scripts/build-test-rootfs.sh
sudo ./bin/securerunner --mode container \
  --rootfs ./build/test-rootfs --memory 64M --pids 16 -- \
  /bin/fixture ok
```

For VM mode, bundle a static payload into the supplied initramfs and provide a host-compatible x86-64 Linux kernel. KVM is selected when `/dev/kvm` is usable; otherwise SecureRunner falls back to QEMU TCG.

```bash
./scripts/build-initramfs.sh ./bin/fixture-static ./build/fixture.cpio.gz
./bin/securerunner --mode vm --timeout 5000 \
  --vm-kernel /boot/vmlinuz-$(uname -r) \
  --vm-initrd ./build/fixture.cpio.gz -- \
  /payload ok
```

Run `./bin/securerunner --help` for all resource and backend options. Exit code `124` means timeout; otherwise the launcher propagates the payload's exit status.

## Security tests

The test harness contains 16 checks covering execution and exit semantics, time/memory/file-descriptor limits, seccomp denials, PID and UTS namespace isolation, a hidden read-only root, and cgroup memory/process limits.

```bash
make test-process                 # 10 unprivileged checks
./scripts/build-test-rootfs.sh
sudo ./tests/security.sh          # full 16/16 suite
./tests/vm-smoke.sh /boot/vmlinuz-$(uname -r)
```

Tests fail closed when required kernel features or cgroup permissions are unavailable; they are never counted as skipped passes.

## Performance

The included harness measures end-to-end launcher latency and prints JSON:

```bash
./bench/benchmark.sh --mode process --iterations 1000
sudo ./bench/benchmark.sh --mode container --iterations 1000 \
  --rootfs ./build/test-rootfs
./bench/benchmark.sh --mode vm --iterations 20 \
  --kernel /boot/vmlinuz-$(uname -r) \
  --initrd ./build/fixture.cpio.gz -- /payload ok
```

User-provided reference measurements are checked into [`bench/results/reference.json`](bench/results/reference.json):

| Mode | p95 startup |
| --- | ---: |
| Process | 0.9 ms |
| Container | 2.7 ms |
| QEMU/KVM | 1.42 s |

Hardware, kernel configuration, mitigations, and warm-cache state have a large effect; rerun the harness on the deployment host instead of treating these numbers as guarantees.

## Threat model and limitations

- Resource limits contain accidental and adversarial exhaustion but do not promise deterministic scheduling.
- Process and container modes share the host kernel. A kernel vulnerability can cross either boundary.
- `--network host`, `--no-seccomp`, and `--no-cgroup` deliberately weaken isolation and should only be used for trusted workloads.
- Container root filesystems must be prepared by the operator. SecureRunner mounts the root read-only and provides fresh `/proc`, `/dev`, and `/tmp` mounts.
- VM mode exposes no disk and no network device. The bundled program must be static and is supplied in the initramfs.
- The built-in policy is code, not a general policy language. Review [`src/seccomp.c`](src/seccomp.c) before deploying different workload classes.

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the control flow and [`SECURITY.md`](SECURITY.md) for vulnerability reporting and production-hardening guidance.

## License

MIT
