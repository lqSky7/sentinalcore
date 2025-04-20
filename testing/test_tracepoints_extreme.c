#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <string.h>
#include <linux/reboot.h>
#include <sys/syscall.h>
#include <sched.h>

int main() {
    printf("PID: %d\n", getpid());
    sleep(17);
    // openat, write, close
    int fd = openat(AT_FDCWD, "/tmp/testfile.txt", O_CREAT | O_WRONLY, 0644);
    if (fd >= 0) {
        write(fd, "Hello, world!\n", 15);
        close(fd);
    }

    // mmap and mprotect
    void *mem = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem != MAP_FAILED) {
        mprotect(mem, 4096, PROT_READ);
        munmap(mem, 4096);
    }

    // fork + execve (child)
    pid_t pid = fork();
    if (pid == 0) {
        char *argv[] = {"/bin/echo", "Child process!", NULL};
        execve("/bin/echo", argv, NULL);
        perror("execve failed");
        exit(1);
    } else {
        waitpid(pid, NULL, 0);
    }

    // clone3 (if supported, fallback to clone)
#ifdef SYS_clone3
    struct clone_args {
        uint64_t flags;
        uint64_t pidfd;
        uint64_t child_tid;
        uint64_t parent_tid;
        uint64_t exit_signal;
        uint64_t stack;
        uint64_t stack_size;
        uint64_t tls;
        uint64_t set_tid;
        uint64_t set_tid_size;
        uint64_t cgroup;
    } args = {
        .flags = CLONE_VM | CLONE_FS | CLONE_FILES,
        .exit_signal = SIGCHLD
    };
    syscall(SYS_clone3, &args, sizeof(args));
#endif

    // socket + connect (expect fail)
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock >= 0) {
        struct sockaddr_in addr = {
            .sin_family = AF_INET,
            .sin_port = htons(65000),
            .sin_addr.s_addr = htonl(0x7f000001), // 127.0.0.1
        };
        connect(sock, (struct sockaddr*)&addr, sizeof(addr));
        close(sock);
    }

    // ptrace (expect fail)
    ptrace(PTRACE_TRACEME, 0, NULL, NULL);

    // syslog (privileged, expect fail)
    syscall(SYS_syslog, 1, NULL, 0);

    // reboot (privileged, expect fail)
    syscall(SYS_reboot, LINUX_REBOOT_MAGIC1, LINUX_REBOOT_MAGIC2,
            LINUX_REBOOT_CMD_RESTART, NULL);

    return 0;
}

