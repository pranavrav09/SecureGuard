#include "securerunner/linux.h"
#include "securerunner/runtime.h"

#ifdef __linux__

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <unistd.h>

int sr_run_process(const struct sr_config *cfg) {
    pid_t pid = fork();

    if (pid < 0) {
        perror("securerunner: fork");
        return 125;
    }
    if (pid == 0) {
        (void)setpgid(0, 0);
        if (sr_apply_limits(cfg) != 0) {
            perror("securerunner: setrlimit");
            _exit(125);
        }
        if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0) {
            perror("securerunner: PR_SET_DUMPABLE");
            _exit(125);
        }
        if (cfg->seccomp && sr_install_seccomp(cfg) != 0) {
            perror("securerunner: seccomp");
            _exit(125);
        }
        execvp(cfg->argv[0], cfg->argv);
        fprintf(stderr, "securerunner: exec %s: %s\n", cfg->argv[0], strerror(errno));
        _exit(errno == ENOENT ? 127 : 126);
    }

    (void)setpgid(pid, pid);
    if (cfg->verbose) {
        fprintf(stderr, "securerunner: process pid=%ld\n", (long)pid);
    }
    return sr_wait_child(pid, cfg->timeout_ms, true);
}

#endif
