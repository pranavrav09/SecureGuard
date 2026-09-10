# Security policy

## Reporting

Do not open a public issue for a suspected sandbox escape. Send a private report to the repository owner through GitHub's private vulnerability reporting feature. Include the backend, kernel and QEMU versions, the exact command line, and a minimal reproducer.

## Deployment checklist

- Prefer VM mode for mutually untrusted tenants.
- Run a supported, promptly patched host kernel and QEMU release.
- Give the launcher access only to a dedicated cgroup subtree and immutable rootfs trees.
- Keep networking disabled unless the workload requires it; if enabled, enforce policy outside the sandbox too.
- Run SecureRunner itself under a service manager with a restricted service account and an outer watchdog.
- Treat rootfs contents and guest kernels/initramfs images as trusted inputs.
- Re-run the security suite after kernel, libc, compiler, or QEMU updates.

## Non-goals

SecureRunner does not inspect application-layer behavior, provide a mandatory-access-control policy, encrypt workload data, hide side channels, or make a shared-kernel backend equivalent to a virtual machine.
