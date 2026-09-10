# Architecture

SecureRunner keeps policy setup in the trusted parent/launcher and crosses the isolation boundary only after every requested control has been installed.

## Process mode

1. Fork a child into a dedicated process group.
2. Apply address-space, CPU-time, file-size, process-count, descriptor, and core-dump rlimits.
3. Disable dumpability, set `no_new_privs`, and install the seccomp-BPF filter.
4. Execute the payload and have the parent enforce a monotonic wall-clock deadline over the whole process group.

## Container mode

1. `clone(2)` a stopped child with new user, PID, mount, UTS, IPC, and (by default) network namespaces.
2. From the parent, install a one-ID UID/GID map and place the child in a fresh cgroup v2 leaf with `memory.max`, `pids.max`, and `cpu.max` configured.
3. Release the child. It marks mounts private, bind-mounts and pivots into the requested root, detaches the old root, remounts `/` read-only, and creates private `/proc`, `/dev`, and `/tmp` mounts.
4. Apply rlimits, clear all capability sets, disable dumpability, install seccomp, sanitize the environment, and execute the payload as PID 1 in its namespace.
5. The parent enforces the deadline, kills remaining cgroup members, and removes the cgroup leaf.

The setup pipe is important: untrusted code cannot run between namespace creation and UID-map/cgroup placement.

## VM mode

1. Encode the payload argument vector as hexadecimal kernel-command-line fields.
2. Start QEMU with KVM when available, otherwise TCG; configure fixed memory, an initramfs, serial console, and no disk, NIC, monitor, or graphical devices.
3. The guest `/init` mounts minimal virtual filesystems, decodes the argument vector, forks, and executes the static payload.
4. `/init` reports the result through QEMU's `isa-debug-exit` device. The host decodes and propagates the payload status while independently enforcing a wall-clock deadline.

VM mode currently targets x86-64 QEMU because its minimal result channel uses an ISA debug-exit device. The process and container backends support x86-64 and ARM64 Linux.
