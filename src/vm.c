#include "securerunner/linux.h"
#include "securerunner/runtime.h"

#ifdef __linux__

#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define SR_VM_CMDLINE_MAX 4096
#define SR_VM_ARG_MAX 32

static int append_text(char *buffer, size_t size, const char *text) {
    size_t used = strlen(buffer);
    size_t added = strlen(text);
    if (used + added + 1U > size) {
        errno = E2BIG;
        return -1;
    }
    memcpy(buffer + used, text, added + 1U);
    return 0;
}

int sr_run_vm(const struct sr_config *cfg) {
    char command_line[SR_VM_CMDLINE_MAX] =
        "console=ttyS0 panic=-1 quiet rdinit=/init sr.argc=";
    char number[64];
    char memory[32];
    char encoded[2048];
    char token[2112];
    const char *acceleration;
    char *qemu_argv[32];
    size_t q = 0;
    int i;
    pid_t pid;
    int result;

    if (cfg->argc > SR_VM_ARG_MAX) {
        fprintf(stderr, "securerunner: VM mode accepts at most %d arguments\n", SR_VM_ARG_MAX);
        return 2;
    }
    snprintf(number, sizeof(number), "%d", cfg->argc);
    if (append_text(command_line, sizeof(command_line), number) != 0) goto command_too_long;
    for (i = 0; i < cfg->argc; ++i) {
        if (sr_hex_encode(cfg->argv[i], encoded, sizeof(encoded)) != 0) goto command_too_long;
        snprintf(token, sizeof(token), " sr.arg%d=%s", i, encoded);
        if (append_text(command_line, sizeof(command_line), token) != 0) goto command_too_long;
    }

    snprintf(memory, sizeof(memory), "%u", cfg->vm_memory_mb);
    acceleration = access("/dev/kvm", R_OK | W_OK) == 0 ? "kvm" : "tcg";
    qemu_argv[q++] = (char *)cfg->qemu_binary;
    qemu_argv[q++] = "-accel";
    qemu_argv[q++] = (char *)acceleration;
    qemu_argv[q++] = "-machine";
    qemu_argv[q++] = "q35";
    qemu_argv[q++] = "-cpu";
    qemu_argv[q++] = strcmp(acceleration, "kvm") == 0 ? "host" : "max";
    qemu_argv[q++] = "-m";
    qemu_argv[q++] = memory;
    qemu_argv[q++] = "-kernel";
    qemu_argv[q++] = (char *)cfg->vm_kernel;
    qemu_argv[q++] = "-initrd";
    qemu_argv[q++] = (char *)cfg->vm_initrd;
    qemu_argv[q++] = "-append";
    qemu_argv[q++] = command_line;
    qemu_argv[q++] = "-nographic";
    qemu_argv[q++] = "-nodefaults";
    qemu_argv[q++] = "-no-reboot";
    qemu_argv[q++] = "-monitor";
    qemu_argv[q++] = "none";
    qemu_argv[q++] = "-serial";
    qemu_argv[q++] = "stdio";
    qemu_argv[q++] = "-nic";
    qemu_argv[q++] = "none";
    qemu_argv[q++] = "-device";
    qemu_argv[q++] = "isa-debug-exit,iobase=0xf4,iosize=0x04";
    qemu_argv[q] = NULL;

    pid = fork();
    if (pid < 0) {
        perror("securerunner: fork QEMU");
        return 125;
    }
    if (pid == 0) {
        (void)setpgid(0, 0);
        execvp(qemu_argv[0], qemu_argv);
        fprintf(stderr, "securerunner: exec %s: %s\n", qemu_argv[0], strerror(errno));
        _exit(125);
    }
    (void)setpgid(pid, pid);
    if (cfg->verbose) {
        fprintf(stderr, "securerunner: vm pid=%ld accel=%s memory=%sM\n",
                (long)pid, acceleration, memory);
    }
    result = sr_wait_child(pid, cfg->timeout_ms, true);
    if (result == 124 || result == 125) return result;
    if ((result & 1) == 1) return result >> 1;
    fprintf(stderr, "securerunner: QEMU exited unexpectedly with status %d\n", result);
    return 125;

command_too_long:
    fprintf(stderr, "securerunner: VM argument list exceeds the kernel command-line limit\n");
    return 2;
}

#endif
