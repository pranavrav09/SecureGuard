#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define SR_VM_ARG_MAX 32
#define SR_ARG_SIZE 1024

static int from_hex(char *value) {
    size_t length = strlen(value);
    size_t i;
    if ((length & 1U) != 0 || length / 2U >= SR_ARG_SIZE) return -1;
    for (i = 0; i < length; i += 2U) {
        char pair[3] = {value[i], value[i + 1U], '\0'};
        char *end = NULL;
        unsigned long byte = strtoul(pair, &end, 16);
        if (end == NULL || *end != '\0' || byte > 255U) return -1;
        value[i / 2U] = (char)byte;
    }
    value[length / 2U] = '\0';
    return 0;
}

static void exit_qemu(unsigned int status) {
    fflush(NULL);
    sync();
#if defined(__x86_64__) || defined(__i386__)
    __asm__ volatile("outl %0, %1" : : "a"(status), "Nd"((unsigned short)0xf4));
#endif
    (void)reboot(RB_POWER_OFF);
    for (;;) pause();
}

int main(void) {
    char command_line[4096] = {0};
    char storage[SR_VM_ARG_MAX][SR_ARG_SIZE];
    char *argv[SR_VM_ARG_MAX + 1] = {0};
    int argc = -1;
    int fd;
    ssize_t length;
    char *token;
    char *save = NULL;
    int i;
    pid_t child;
    int status;

    (void)mkdir("/proc", 0555);
    (void)mkdir("/sys", 0555);
    (void)mkdir("/dev", 0755);
    (void)mkdir("/tmp", 01777);
    if (mount("proc", "/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) != 0)
        exit_qemu(125);
    (void)mount("sysfs", "/sys", "sysfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL);
    (void)mount("devtmpfs", "/dev", "devtmpfs", MS_NOSUID | MS_NOEXEC, NULL);
    (void)mount("tmpfs", "/tmp", "tmpfs", MS_NOSUID | MS_NODEV, "size=16m");
    (void)sethostname("securerunner-vm", 15);

    fd = open("/proc/cmdline", O_RDONLY | O_CLOEXEC);
    if (fd < 0) exit_qemu(125);
    length = read(fd, command_line, sizeof(command_line) - 1U);
    close(fd);
    if (length <= 0) exit_qemu(125);
    command_line[length] = '\0';

    for (token = strtok_r(command_line, " ", &save); token != NULL;
         token = strtok_r(NULL, " ", &save)) {
        if (strncmp(token, "sr.argc=", 8) == 0) {
            argc = atoi(token + 8);
        } else if (strncmp(token, "sr.arg", 6) == 0) {
            char *equals = strchr(token, '=');
            long index;
            if (equals == NULL) continue;
            *equals = '\0';
            index = strtol(token + 6, NULL, 10);
            if (index < 0 || index >= SR_VM_ARG_MAX) continue;
            if (strlen(equals + 1) >= SR_ARG_SIZE) exit_qemu(125);
            strcpy(storage[index], equals + 1);
            if (from_hex(storage[index]) != 0) exit_qemu(125);
            argv[index] = storage[index];
        }
    }
    if (argc <= 0 || argc > SR_VM_ARG_MAX) exit_qemu(125);
    for (i = 0; i < argc; ++i) {
        if (argv[i] == NULL) exit_qemu(125);
    }
    argv[argc] = NULL;

    (void)setenv("PATH", "/bin:/usr/bin", 1);
    (void)setenv("HOME", "/tmp", 1);
    child = fork();
    if (child < 0) exit_qemu(125);
    if (child == 0) {
        execv(argv[0], argv);
        fprintf(stderr, "securerunner-guest: exec %s: %s\n", argv[0], strerror(errno));
        _exit(errno == ENOENT ? 127 : 126);
    }
    while (waitpid(child, &status, 0) < 0) {
        if (errno != EINTR) exit_qemu(125);
    }
    if (WIFEXITED(status)) status = WEXITSTATUS(status);
    else if (WIFSIGNALED(status)) status = 128 + WTERMSIG(status);
    else status = 125;
    printf("SECURERUNNER_EXIT=%d\n", status);
    exit_qemu((unsigned int)status);
}
