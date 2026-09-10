#include "securerunner/linux.h"
#include "securerunner/runtime.h"

#ifdef __linux__

#include <errno.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define SR_STACK_SIZE (1024U * 1024U)

struct child_context {
    const struct sr_config *cfg;
    int ready_fd;
    int unused_write_fd;
};

static int make_device(const char *path, mode_t mode, unsigned int major_no,
                       unsigned int minor_no) {
    dev_t device = makedev(major_no, minor_no);
    if (mknod(path, mode, device) != 0 && errno != EEXIST) return -1;
    return 0;
}

static int mount_rootfs(const char *configured_root) {
    char rootfs[4096];

    if (realpath(configured_root, rootfs) == NULL) return -1;
    if (mount(rootfs, rootfs, NULL, MS_BIND | MS_REC, NULL) != 0) return -1;
    if (chdir(rootfs) != 0) return -1;
    if (mkdir(".sr-oldroot", 0700) != 0 && errno != EEXIST) return -1;
    if (syscall(SYS_pivot_root, ".", ".sr-oldroot") != 0) return -1;
    if (chdir("/") != 0) return -1;
    if (umount2("/.sr-oldroot", MNT_DETACH) != 0) return -1;
    if (rmdir("/.sr-oldroot") != 0) return -1;

    if (mount(NULL, "/", NULL,
              MS_BIND | MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NODEV,
              NULL) != 0) return -1;
    if (mount("proc", "/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) != 0)
        return -1;
    if (mount("tmpfs", "/tmp", "tmpfs", MS_NOSUID | MS_NODEV,
              "mode=1777,size=16m") != 0) return -1;
    if (mount("tmpfs", "/dev", "tmpfs", MS_NOSUID | MS_NOEXEC,
              "mode=755,size=1m") != 0) return -1;
    if (make_device("/dev/null", S_IFCHR | 0666, 1, 3) != 0) return -1;
    if (make_device("/dev/zero", S_IFCHR | 0666, 1, 5) != 0) return -1;
    if (make_device("/dev/random", S_IFCHR | 0666, 1, 8) != 0) return -1;
    if (make_device("/dev/urandom", S_IFCHR | 0666, 1, 9) != 0) return -1;
    return 0;
}

static int drop_capabilities(void) {
    struct __user_cap_header_struct header = {
        .version = _LINUX_CAPABILITY_VERSION_3,
        .pid = 0,
    };
    struct __user_cap_data_struct data[2] = {{0}, {0}};
    int capability;

    for (capability = 0; capability <= CAP_LAST_CAP; ++capability) {
        if (prctl(PR_CAPBSET_DROP, capability, 0, 0, 0) != 0 && errno != EINVAL)
            return -1;
    }
    if (syscall(SYS_capset, &header, &data) != 0) return -1;
    return 0;
}

static int container_child(void *argument) {
    struct child_context *context = argument;
    const struct sr_config *cfg = context->cfg;
    char ready;

    close(context->unused_write_fd);
    if (read(context->ready_fd, &ready, 1) != 1) {
        fprintf(stderr, "securerunner: namespace setup was not released\n");
        return 125;
    }
    close(context->ready_fd);
    (void)setpgid(0, 0);

    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) != 0) {
        perror("securerunner: make mounts private");
        return 125;
    }
    if (sethostname(cfg->hostname, strlen(cfg->hostname)) != 0) {
        perror("securerunner: sethostname");
        return 125;
    }
    if (mount_rootfs(cfg->rootfs) != 0) {
        perror("securerunner: configure rootfs");
        return 125;
    }
    if (sr_apply_limits(cfg) != 0) {
        perror("securerunner: setrlimit");
        return 125;
    }
    if (drop_capabilities() != 0) {
        perror("securerunner: drop capabilities");
        return 125;
    }
    if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0) {
        perror("securerunner: PR_SET_DUMPABLE");
        return 125;
    }
    if (cfg->seccomp && sr_install_seccomp(cfg) != 0) {
        perror("securerunner: seccomp");
        return 125;
    }

    (void)clearenv();
    (void)setenv("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", 1);
    (void)setenv("HOME", "/tmp", 1);
    (void)setenv("LANG", "C", 1);
    execvp(cfg->argv[0], cfg->argv);
    fprintf(stderr, "securerunner: exec %s: %s\n", cfg->argv[0], strerror(errno));
    return errno == ENOENT ? 127 : 126;
}

static int write_id_map(pid_t pid, uid_t uid, gid_t gid) {
    char path[128];
    char mapping[128];

    snprintf(path, sizeof(path), "/proc/%ld/setgroups", (long)pid);
    if (sr_write_file(path, "deny") != 0 && errno != ENOENT) return -1;
    snprintf(path, sizeof(path), "/proc/%ld/uid_map", (long)pid);
    snprintf(mapping, sizeof(mapping), "0 %lu 1", (unsigned long)uid);
    if (sr_write_file(path, mapping) != 0) return -1;
    snprintf(path, sizeof(path), "/proc/%ld/gid_map", (long)pid);
    snprintf(mapping, sizeof(mapping), "0 %lu 1", (unsigned long)gid);
    if (sr_write_file(path, mapping) != 0) return -1;
    return 0;
}

int sr_run_container(const struct sr_config *cfg) {
    struct sr_cgroup cgroup = {{0}, false};
    struct child_context context;
    char *stack = NULL;
    int sync_pipe[2] = {-1, -1};
    int flags = CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWUTS |
                CLONE_NEWIPC | SIGCHLD;
    pid_t pid;
    int result = 125;

    if (cfg->network == SR_NETWORK_NONE) flags |= CLONE_NEWNET;
    if (pipe2(sync_pipe, O_CLOEXEC) != 0) {
        perror("securerunner: pipe");
        return 125;
    }
    stack = malloc(SR_STACK_SIZE);
    if (stack == NULL) {
        perror("securerunner: allocate clone stack");
        goto cleanup;
    }
    context.cfg = cfg;
    context.ready_fd = sync_pipe[0];
    context.unused_write_fd = sync_pipe[1];
    pid = clone(container_child, stack + SR_STACK_SIZE, flags, &context);
    if (pid < 0) {
        perror("securerunner: clone namespaces");
        fprintf(stderr, "securerunner: check that user namespaces are enabled\n");
        goto cleanup;
    }
    close(sync_pipe[0]);
    sync_pipe[0] = -1;

    if (write_id_map(pid, getuid(), getgid()) != 0) {
        perror("securerunner: configure user namespace mappings");
        (void)kill(pid, SIGKILL);
        (void)waitpid(pid, NULL, 0);
        goto cleanup;
    }
    if (cfg->cgroup && sr_cgroup_create(&cgroup, cfg, pid) != 0) {
        perror("securerunner: configure cgroup v2");
        fprintf(stderr, "securerunner: run with cgroup permission or pass --no-cgroup\n");
        (void)kill(pid, SIGKILL);
        (void)waitpid(pid, NULL, 0);
        goto cleanup;
    }
    if (write(sync_pipe[1], "1", 1) != 1) {
        perror("securerunner: release container");
        (void)kill(pid, SIGKILL);
        (void)waitpid(pid, NULL, 0);
        goto cleanup;
    }
    close(sync_pipe[1]);
    sync_pipe[1] = -1;
    if (cfg->verbose) {
        fprintf(stderr, "securerunner: container pid=%ld rootfs=%s\n",
                (long)pid, cfg->rootfs);
    }
    result = sr_wait_child(pid, cfg->timeout_ms, false);

cleanup:
    if (sync_pipe[0] >= 0) close(sync_pipe[0]);
    if (sync_pipe[1] >= 0) close(sync_pipe[1]);
    sr_cgroup_destroy(&cgroup);
    free(stack);
    return result;
}

#endif
