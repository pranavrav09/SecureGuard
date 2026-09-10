#include "securerunner/config.h"

#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int parse_u64(const char *value, uint64_t *result) {
    char *end = NULL;
    unsigned long long parsed;

    errno = 0;
    parsed = strtoull(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0') {
        return -1;
    }
    *result = (uint64_t)parsed;
    return 0;
}

static int parse_uint(const char *name, const char *value, unsigned int *result) {
    uint64_t parsed;

    if (parse_u64(value, &parsed) != 0 || parsed == 0 || parsed > UINT32_MAX) {
        fprintf(stderr, "securerunner: invalid %s: %s\n", name, value);
        return -1;
    }
    *result = (unsigned int)parsed;
    return 0;
}

static int parse_size(const char *value, uint64_t *result) {
    char *end = NULL;
    unsigned long long number;
    uint64_t multiplier = 1;

    errno = 0;
    number = strtoull(value, &end, 10);
    if (errno != 0 || end == value) {
        return -1;
    }
    if (*end != '\0') {
        if (end[1] != '\0') {
            return -1;
        }
        switch (*end) {
        case 'k': case 'K': multiplier = 1024ULL; break;
        case 'm': case 'M': multiplier = 1024ULL * 1024ULL; break;
        case 'g': case 'G': multiplier = 1024ULL * 1024ULL * 1024ULL; break;
        default: return -1;
        }
    }
    if (number > UINT64_MAX / multiplier) {
        return -1;
    }
    *result = (uint64_t)number * multiplier;
    return 0;
}

void sr_config_defaults(struct sr_config *cfg) {
    memset(cfg, 0, sizeof(*cfg));
    cfg->mode = SR_MODE_PROCESS;
    cfg->network = SR_NETWORK_NONE;
    cfg->timeout_ms = 2000;
    cfg->memory_bytes = 256ULL * 1024ULL * 1024ULL;
    cfg->file_bytes = 16ULL * 1024ULL * 1024ULL;
    cfg->pids_max = 64;
    cfg->cpu_percent = 100;
    cfg->nofile = 64;
    cfg->seccomp = true;
    cfg->cgroup = true;
    cfg->hostname = "sandbox";
    cfg->qemu_binary = "qemu-system-x86_64";
    cfg->vm_memory_mb = 256;
}

void sr_usage(const char *program) {
    fprintf(stderr,
        "Usage: %s [options] -- PROGRAM [ARG ...]\n"
        "\n"
        "Modes:\n"
        "  --mode process|container|vm   Isolation backend (default: process)\n"
        "\n"
        "Limits:\n"
        "  --timeout MS                  Wall-clock limit (default: 2000)\n"
        "  --memory SIZE                 Memory limit, K/M/G suffix accepted (default: 256M)\n"
        "  --pids N                      Process limit (default: 64)\n"
        "  --cpu PERCENT                 cgroup CPU quota (default: 100)\n"
        "  --file-size SIZE              Maximum output file size (default: 16M)\n"
        "  --nofile N                    Open-file limit (default: 64)\n"
        "\n"
        "Container:\n"
        "  --rootfs PATH                 Root filesystem (required)\n"
        "  --hostname NAME               UTS hostname (default: sandbox)\n"
        "  --network none|host           Network namespace policy (default: none)\n"
        "  --no-cgroup                   Disable cgroup v2 enforcement\n"
        "\n"
        "VM:\n"
        "  --vm-kernel PATH              Linux bzImage/vmlinuz (required)\n"
        "  --vm-initrd PATH              SecureRunner initramfs (required)\n"
        "  --vm-memory MB                Guest RAM (default: 256)\n"
        "  --qemu PATH                   QEMU executable\n"
        "\n"
        "General:\n"
        "  --no-seccomp                  Disable the syscall policy\n"
        "  -v, --verbose                 Print backend diagnostics\n"
        "  -h, --help                    Show this help\n",
        program);
}

int sr_parse_args(int argc, char **argv, struct sr_config *cfg) {
    enum {
        OPT_MODE = 1000, OPT_TIMEOUT, OPT_MEMORY, OPT_PIDS, OPT_CPU,
        OPT_FILE_SIZE, OPT_NOFILE, OPT_ROOTFS, OPT_HOSTNAME, OPT_NETWORK,
        OPT_NO_CGROUP, OPT_NO_SECCOMP, OPT_VM_KERNEL, OPT_VM_INITRD,
        OPT_VM_MEMORY, OPT_QEMU
    };
    static const struct option options[] = {
        {"mode", required_argument, NULL, OPT_MODE},
        {"timeout", required_argument, NULL, OPT_TIMEOUT},
        {"memory", required_argument, NULL, OPT_MEMORY},
        {"pids", required_argument, NULL, OPT_PIDS},
        {"cpu", required_argument, NULL, OPT_CPU},
        {"file-size", required_argument, NULL, OPT_FILE_SIZE},
        {"nofile", required_argument, NULL, OPT_NOFILE},
        {"rootfs", required_argument, NULL, OPT_ROOTFS},
        {"hostname", required_argument, NULL, OPT_HOSTNAME},
        {"network", required_argument, NULL, OPT_NETWORK},
        {"no-cgroup", no_argument, NULL, OPT_NO_CGROUP},
        {"no-seccomp", no_argument, NULL, OPT_NO_SECCOMP},
        {"vm-kernel", required_argument, NULL, OPT_VM_KERNEL},
        {"vm-initrd", required_argument, NULL, OPT_VM_INITRD},
        {"vm-memory", required_argument, NULL, OPT_VM_MEMORY},
        {"qemu", required_argument, NULL, OPT_QEMU},
        {"verbose", no_argument, NULL, 'v'},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0},
    };
    int option;

    opterr = 0;
    while ((option = getopt_long(argc, argv, "+vh", options, NULL)) != -1) {
        switch (option) {
        case OPT_MODE:
            if (strcmp(optarg, "process") == 0) cfg->mode = SR_MODE_PROCESS;
            else if (strcmp(optarg, "container") == 0) cfg->mode = SR_MODE_CONTAINER;
            else if (strcmp(optarg, "vm") == 0) cfg->mode = SR_MODE_VM;
            else {
                fprintf(stderr, "securerunner: invalid mode: %s\n", optarg);
                return -1;
            }
            break;
        case OPT_TIMEOUT:
            if (parse_u64(optarg, &cfg->timeout_ms) != 0 || cfg->timeout_ms == 0) goto invalid;
            break;
        case OPT_MEMORY:
            if (parse_size(optarg, &cfg->memory_bytes) != 0 || cfg->memory_bytes == 0) goto invalid;
            break;
        case OPT_FILE_SIZE:
            if (parse_size(optarg, &cfg->file_bytes) != 0 || cfg->file_bytes == 0) goto invalid;
            break;
        case OPT_PIDS:
            if (parse_uint("pids", optarg, &cfg->pids_max) != 0) return -1;
            break;
        case OPT_CPU:
            if (parse_uint("cpu", optarg, &cfg->cpu_percent) != 0) return -1;
            if (cfg->cpu_percent > 1000U) {
                fprintf(stderr, "securerunner: cpu percentage must be between 1 and 1000\n");
                return -1;
            }
            break;
        case OPT_NOFILE:
            if (parse_uint("nofile", optarg, &cfg->nofile) != 0) return -1;
            break;
        case OPT_ROOTFS: cfg->rootfs = optarg; break;
        case OPT_HOSTNAME: cfg->hostname = optarg; break;
        case OPT_NETWORK:
            if (strcmp(optarg, "none") == 0) cfg->network = SR_NETWORK_NONE;
            else if (strcmp(optarg, "host") == 0) cfg->network = SR_NETWORK_HOST;
            else {
                fprintf(stderr, "securerunner: invalid network policy: %s\n", optarg);
                return -1;
            }
            break;
        case OPT_NO_CGROUP: cfg->cgroup = false; break;
        case OPT_NO_SECCOMP: cfg->seccomp = false; break;
        case OPT_VM_KERNEL: cfg->vm_kernel = optarg; break;
        case OPT_VM_INITRD: cfg->vm_initrd = optarg; break;
        case OPT_VM_MEMORY:
            if (parse_uint("vm-memory", optarg, &cfg->vm_memory_mb) != 0) return -1;
            break;
        case OPT_QEMU: cfg->qemu_binary = optarg; break;
        case 'v': cfg->verbose = true; break;
        case 'h': sr_usage(argv[0]); exit(0);
        default:
            fprintf(stderr, "securerunner: unknown or incomplete option\n");
            sr_usage(argv[0]);
            return -1;
        }
    }

    if (optind >= argc) {
        fprintf(stderr, "securerunner: PROGRAM is required after --\n");
        sr_usage(argv[0]);
        return -1;
    }
    cfg->argc = argc - optind;
    cfg->argv = &argv[optind];

    if (cfg->mode == SR_MODE_CONTAINER && cfg->rootfs == NULL) {
        fprintf(stderr, "securerunner: --rootfs is required in container mode\n");
        return -1;
    }
    if (cfg->mode == SR_MODE_VM && (cfg->vm_kernel == NULL || cfg->vm_initrd == NULL)) {
        fprintf(stderr, "securerunner: --vm-kernel and --vm-initrd are required in vm mode\n");
        return -1;
    }
    return 0;

invalid:
    fprintf(stderr, "securerunner: invalid numeric value: %s\n", optarg);
    return -1;
}
