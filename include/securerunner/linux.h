#ifndef SECURERUNNER_LINUX_H
#define SECURERUNNER_LINUX_H

#include "securerunner/config.h"

#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>

struct sr_cgroup {
    char path[4096];
    bool active;
};

int sr_apply_limits(const struct sr_config *cfg);
int sr_install_seccomp(const struct sr_config *cfg);
int sr_wait_child(pid_t pid, uint64_t timeout_ms, bool process_group);
int sr_cgroup_create(struct sr_cgroup *group, const struct sr_config *cfg, pid_t pid);
void sr_cgroup_destroy(struct sr_cgroup *group);
int sr_write_file(const char *path, const char *value);
int sr_hex_encode(const char *input, char *output, size_t output_size);

#endif
