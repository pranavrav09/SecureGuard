#include "securerunner/linux.h"

#ifdef __linux__

#include <errno.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

#if defined(__x86_64__)
#define SR_AUDIT_ARCH AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
#define SR_AUDIT_ARCH AUDIT_ARCH_AARCH64
#else
#error "SecureRunner supports seccomp on x86_64 and aarch64"
#endif

#define SR_APPEND(filter, count, statement) \
    do { (filter)[(count)++] = (struct sock_filter)(statement); } while (0)

#define SR_DENY_SYSCALL(filter, count, syscall_number)                         \
    do {                                                                       \
        SR_APPEND((filter), (count), BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,      \
                                               (syscall_number), 0, 1));       \
        SR_APPEND((filter), (count), BPF_STMT(BPF_RET | BPF_K,                 \
                                               SECCOMP_RET_ERRNO | EACCES));   \
    } while (0)

int sr_install_seccomp(const struct sr_config *cfg) {
    struct sock_filter filter[128];
    size_t count = 0;
    struct sock_fprog program;

    SR_APPEND(filter, count, BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                                      offsetof(struct seccomp_data, arch)));
    SR_APPEND(filter, count, BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                                      SR_AUDIT_ARCH, 1, 0));
    SR_APPEND(filter, count, BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));
    SR_APPEND(filter, count, BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                                      offsetof(struct seccomp_data, nr)));

#ifdef __NR_bpf
    SR_DENY_SYSCALL(filter, count, __NR_bpf);
#endif
#ifdef __NR_ptrace
    SR_DENY_SYSCALL(filter, count, __NR_ptrace);
#endif
#ifdef __NR_mount
    SR_DENY_SYSCALL(filter, count, __NR_mount);
#endif
#ifdef __NR_umount2
    SR_DENY_SYSCALL(filter, count, __NR_umount2);
#endif
#ifdef __NR_pivot_root
    SR_DENY_SYSCALL(filter, count, __NR_pivot_root);
#endif
#ifdef __NR_open_by_handle_at
    SR_DENY_SYSCALL(filter, count, __NR_open_by_handle_at);
#endif
#ifdef __NR_init_module
    SR_DENY_SYSCALL(filter, count, __NR_init_module);
#endif
#ifdef __NR_finit_module
    SR_DENY_SYSCALL(filter, count, __NR_finit_module);
#endif
#ifdef __NR_delete_module
    SR_DENY_SYSCALL(filter, count, __NR_delete_module);
#endif
#ifdef __NR_reboot
    SR_DENY_SYSCALL(filter, count, __NR_reboot);
#endif
#ifdef __NR_kexec_load
    SR_DENY_SYSCALL(filter, count, __NR_kexec_load);
#endif
#ifdef __NR_kexec_file_load
    SR_DENY_SYSCALL(filter, count, __NR_kexec_file_load);
#endif
#ifdef __NR_swapon
    SR_DENY_SYSCALL(filter, count, __NR_swapon);
#endif
#ifdef __NR_swapoff
    SR_DENY_SYSCALL(filter, count, __NR_swapoff);
#endif
#ifdef __NR_setns
    SR_DENY_SYSCALL(filter, count, __NR_setns);
#endif
#ifdef __NR_unshare
    SR_DENY_SYSCALL(filter, count, __NR_unshare);
#endif
#ifdef __NR_userfaultfd
    SR_DENY_SYSCALL(filter, count, __NR_userfaultfd);
#endif
#ifdef __NR_perf_event_open
    SR_DENY_SYSCALL(filter, count, __NR_perf_event_open);
#endif
#ifdef __NR_process_vm_readv
    SR_DENY_SYSCALL(filter, count, __NR_process_vm_readv);
#endif
#ifdef __NR_process_vm_writev
    SR_DENY_SYSCALL(filter, count, __NR_process_vm_writev);
#endif
#ifdef __NR_keyctl
    SR_DENY_SYSCALL(filter, count, __NR_keyctl);
#endif
#ifdef __NR_add_key
    SR_DENY_SYSCALL(filter, count, __NR_add_key);
#endif
#ifdef __NR_request_key
    SR_DENY_SYSCALL(filter, count, __NR_request_key);
#endif

    if (cfg->network == SR_NETWORK_NONE) {
#ifdef __NR_socket
        SR_DENY_SYSCALL(filter, count, __NR_socket);
#endif
#ifdef __NR_socketpair
        SR_DENY_SYSCALL(filter, count, __NR_socketpair);
#endif
#ifdef __NR_connect
        SR_DENY_SYSCALL(filter, count, __NR_connect);
#endif
#ifdef __NR_bind
        SR_DENY_SYSCALL(filter, count, __NR_bind);
#endif
#ifdef __NR_listen
        SR_DENY_SYSCALL(filter, count, __NR_listen);
#endif
#ifdef __NR_accept
        SR_DENY_SYSCALL(filter, count, __NR_accept);
#endif
#ifdef __NR_accept4
        SR_DENY_SYSCALL(filter, count, __NR_accept4);
#endif
    }

    SR_APPEND(filter, count, BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
    program.len = (unsigned short)count;
    program.filter = filter;

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) return -1;
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program) != 0) return -1;
    return 0;
}

#endif
