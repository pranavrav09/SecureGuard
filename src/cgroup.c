#include "securerunner/linux.h"

#ifdef __linux__

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define SR_CGROUP_ROOT "/sys/fs/cgroup/securerunner"

static int write_setting(const char *directory, const char *name, const char *value) {
    char path[4096];
    int length = snprintf(path, sizeof(path), "%s/%s", directory, name);
    if (length < 0 || (size_t)length >= sizeof(path)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    return sr_write_file(path, value);
}

int sr_cgroup_create(struct sr_cgroup *group, const struct sr_config *cfg, pid_t pid) {
    char value[128];

    memset(group, 0, sizeof(*group));
    if (access("/sys/fs/cgroup/cgroup.controllers", F_OK) != 0) {
        errno = ENOTSUP;
        return -1;
    }
    if (mkdir(SR_CGROUP_ROOT, 0755) != 0 && errno != EEXIST) return -1;
    (void)sr_write_file(SR_CGROUP_ROOT "/cgroup.subtree_control", "+cpu +memory +pids");

    if (snprintf(group->path, sizeof(group->path), "%s/job-%ld",
                 SR_CGROUP_ROOT, (long)pid) >= (int)sizeof(group->path)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    if (mkdir(group->path, 0755) != 0) return -1;
    group->active = true;

    snprintf(value, sizeof(value), "%llu", (unsigned long long)cfg->memory_bytes);
    if (write_setting(group->path, "memory.max", value) != 0) goto fail;
    snprintf(value, sizeof(value), "%u", cfg->pids_max);
    if (write_setting(group->path, "pids.max", value) != 0) goto fail;
    snprintf(value, sizeof(value), "%u 100000", cfg->cpu_percent * 1000U);
    if (write_setting(group->path, "cpu.max", value) != 0) goto fail;
    snprintf(value, sizeof(value), "%ld", (long)pid);
    if (write_setting(group->path, "cgroup.procs", value) != 0) goto fail;
    return 0;

fail:
    {
        int saved = errno;
        sr_cgroup_destroy(group);
        errno = saved;
        return -1;
    }
}

void sr_cgroup_destroy(struct sr_cgroup *group) {
    if (!group->active) return;
    (void)write_setting(group->path, "cgroup.kill", "1");
    if (rmdir(group->path) != 0 && errno == EBUSY) {
        usleep(10000);
        (void)rmdir(group->path);
    }
    group->active = false;
}

#endif
