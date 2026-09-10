#ifndef SECURERUNNER_CONFIG_H
#define SECURERUNNER_CONFIG_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum sr_mode {
    SR_MODE_PROCESS,
    SR_MODE_CONTAINER,
    SR_MODE_VM,
};

enum sr_network {
    SR_NETWORK_NONE,
    SR_NETWORK_HOST,
};

struct sr_config {
    enum sr_mode mode;
    enum sr_network network;
    uint64_t timeout_ms;
    uint64_t memory_bytes;
    uint64_t file_bytes;
    unsigned int pids_max;
    unsigned int cpu_percent;
    unsigned int nofile;
    bool seccomp;
    bool cgroup;
    bool verbose;
    const char *rootfs;
    const char *hostname;
    const char *qemu_binary;
    const char *vm_kernel;
    const char *vm_initrd;
    unsigned int vm_memory_mb;
    int argc;
    char **argv;
};

void sr_config_defaults(struct sr_config *cfg);
int sr_parse_args(int argc, char **argv, struct sr_config *cfg);
void sr_usage(const char *program);

#endif
