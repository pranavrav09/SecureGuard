#include "securerunner/linux.h"

#ifdef __linux__

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static uint64_t monotonic_ms(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        return 0;
    }
    return (uint64_t)now.tv_sec * 1000ULL + (uint64_t)now.tv_nsec / 1000000ULL;
}

int sr_write_file(const char *path, const char *value) {
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    size_t length = strlen(value);
    ssize_t written;

    if (fd < 0) {
        return -1;
    }
    written = write(fd, value, length);
    if (written < 0 || (size_t)written != length) {
        int saved = errno;
        close(fd);
        errno = saved == 0 ? EIO : saved;
        return -1;
    }
    return close(fd);
}

int sr_apply_limits(const struct sr_config *cfg) {
    struct rlimit limit;
    uint64_t cpu_seconds = cfg->timeout_ms / 1000ULL + 1ULL;

    limit.rlim_cur = limit.rlim_max = (rlim_t)cfg->memory_bytes;
    if (setrlimit(RLIMIT_AS, &limit) != 0) return -1;
    limit.rlim_cur = limit.rlim_max = (rlim_t)cfg->file_bytes;
    if (setrlimit(RLIMIT_FSIZE, &limit) != 0) return -1;
    limit.rlim_cur = limit.rlim_max = (rlim_t)cfg->nofile;
    if (setrlimit(RLIMIT_NOFILE, &limit) != 0) return -1;
    limit.rlim_cur = limit.rlim_max = (rlim_t)cfg->pids_max;
    if (setrlimit(RLIMIT_NPROC, &limit) != 0) return -1;
    limit.rlim_cur = limit.rlim_max = (rlim_t)cpu_seconds;
    if (setrlimit(RLIMIT_CPU, &limit) != 0) return -1;
    limit.rlim_cur = limit.rlim_max = 0;
    if (setrlimit(RLIMIT_CORE, &limit) != 0) return -1;
    return 0;
}

int sr_wait_child(pid_t pid, uint64_t timeout_ms, bool process_group) {
    const uint64_t start = monotonic_ms();
    struct timespec pause = {.tv_sec = 0, .tv_nsec = 1000000L};
    int status;

    for (;;) {
        pid_t result = waitpid(pid, &status, WNOHANG);
        if (result == pid) break;
        if (result < 0) {
            if (errno == EINTR) continue;
            perror("securerunner: waitpid");
            return 125;
        }
        if (monotonic_ms() - start >= timeout_ms) {
            if (process_group) {
                (void)kill(-pid, SIGKILL);
            }
            (void)kill(pid, SIGKILL);
            while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
            fprintf(stderr, "securerunner: timed out after %llu ms\n",
                    (unsigned long long)timeout_ms);
            return 124;
        }
        (void)nanosleep(&pause, NULL);
    }

    if (WIFEXITED(status)) return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
    return 125;
}

int sr_hex_encode(const char *input, char *output, size_t output_size) {
    static const char digits[] = "0123456789abcdef";
    size_t length = strlen(input);
    size_t i;

    if (length > (output_size - 1U) / 2U) {
        errno = E2BIG;
        return -1;
    }
    for (i = 0; i < length; ++i) {
        unsigned char c = (unsigned char)input[i];
        output[i * 2U] = digits[c >> 4U];
        output[i * 2U + 1U] = digits[c & 0x0fU];
    }
    output[length * 2U] = '\0';
    return 0;
}

#endif
