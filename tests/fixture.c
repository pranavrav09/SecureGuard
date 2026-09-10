#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static void sleep_ms(unsigned long milliseconds) {
    struct timespec delay = {
        .tv_sec = (time_t)(milliseconds / 1000UL),
        .tv_nsec = (long)(milliseconds % 1000UL) * 1000000L,
    };
    while (nanosleep(&delay, &delay) != 0 && errno == EINTR) {}
}

static int denied_result(long result) {
    if (result == -1 && errno == EACCES) {
        puts("DENIED");
        return 0;
    }
    fprintf(stderr, "expected seccomp EACCES, got result=%ld errno=%d\n", result, errno);
    return 1;
}

static int syscall_probe(const char *name) {
    errno = 0;
    if (strcmp(name, "ptrace") == 0)
        return denied_result(ptrace(PTRACE_TRACEME, 0, NULL, NULL));
#ifdef __NR_bpf
    if (strcmp(name, "bpf") == 0)
        return denied_result(syscall(__NR_bpf, BPF_MAP_CREATE, NULL, 0));
#endif
    if (strcmp(name, "mount") == 0)
        return denied_result(mount("none", "/tmp", "tmpfs", 0, NULL));
    if (strcmp(name, "socket") == 0)
        return denied_result(socket(AF_INET, SOCK_STREAM, 0));
    fprintf(stderr, "unknown syscall probe: %s\n", name);
    return 2;
}

static int allocate_denied(unsigned long megabytes) {
    size_t bytes = (size_t)megabytes * 1024U * 1024U;
    unsigned char *memory = malloc(bytes);
    size_t i;
    if (memory == NULL) return 0;
    for (i = 0; i < bytes; i += 4096U) memory[i] = (unsigned char)i;
    free(memory);
    fprintf(stderr, "allocation unexpectedly succeeded\n");
    return 1;
}

static int open_many(unsigned long count) {
    unsigned long i;
    for (i = 0; i < count; ++i) {
        int fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
        if (fd < 0) return errno == EMFILE ? 0 : 1;
    }
    fprintf(stderr, "open-file limit was unexpectedly accepted %lu files\n", count);
    return 1;
}

static int spawn_denied(unsigned long count) {
    unsigned long i;
    int saw_denial = 0;
    for (i = 0; i < count; ++i) {
        pid_t pid = fork();
        if (pid < 0) {
            if (errno == EAGAIN) saw_denial = 1;
            break;
        }
        if (pid == 0) {
            sleep_ms(250);
            _exit(0);
        }
    }
    while (waitpid(-1, NULL, 0) > 0 || errno == EINTR) {}
    return saw_denial ? 0 : 1;
}

int main(int argc, char **argv) {
    if (argc < 2) return 2;
    if (strcmp(argv[1], "ok") == 0) {
        puts("OK");
        return 0;
    }
    if (strcmp(argv[1], "exit") == 0 && argc == 3) return atoi(argv[2]);
    if (strcmp(argv[1], "echo") == 0 && argc == 3) {
        puts(argv[2]);
        return 0;
    }
    if (strcmp(argv[1], "sleep") == 0 && argc == 3) {
        sleep_ms(strtoul(argv[2], NULL, 10));
        return 0;
    }
    if (strcmp(argv[1], "allocate-denied") == 0 && argc == 3)
        return allocate_denied(strtoul(argv[2], NULL, 10));
    if (strcmp(argv[1], "open-many") == 0 && argc == 3)
        return open_many(strtoul(argv[2], NULL, 10));
    if (strcmp(argv[1], "syscall") == 0 && argc == 3) return syscall_probe(argv[2]);
    if (strcmp(argv[1], "pid") == 0) {
        printf("%ld\n", (long)getpid());
        return 0;
    }
    if (strcmp(argv[1], "hostname") == 0) {
        char hostname[256];
        if (gethostname(hostname, sizeof(hostname)) != 0) return 1;
        hostname[sizeof(hostname) - 1U] = '\0';
        puts(hostname);
        return 0;
    }
    if (strcmp(argv[1], "read-denied") == 0 && argc == 3) {
        int fd = open(argv[2], O_RDONLY | O_CLOEXEC);
        if (fd < 0) return 0;
        close(fd);
        return 1;
    }
    if (strcmp(argv[1], "write-denied") == 0 && argc == 3) {
        int fd = open(argv[2], O_WRONLY | O_CREAT | O_CLOEXEC, 0600);
        if (fd < 0) return 0;
        close(fd);
        return 1;
    }
    if (strcmp(argv[1], "spawn-denied") == 0 && argc == 3)
        return spawn_denied(strtoul(argv[2], NULL, 10));
    fprintf(stderr, "invalid fixture command\n");
    return 2;
}
