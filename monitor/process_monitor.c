#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

// Architecture-specific includes and definitions
#ifdef __linux__
    #include <sys/syscall.h>
    #include <sys/user.h>
    // sys/reg.h is not available on ARM64, but we don't need it
    #if defined(__x86_64__) || defined(__i386__)
        #include <sys/reg.h>
    #endif
#elif __APPLE__
    #include <sys/sysctl.h>
    #include <mach/mach.h>
    // macOS doesn't have sys/reg.h or sys/user.h
    // We'll use alternative approaches
#endif

// Architecture detection
#if defined(__x86_64__) || defined(__x86_64) || defined(__amd64__) || defined(__amd64)
    #define ARCH_X86_64 1
#elif defined(__aarch64__) || defined(__arm64__)
    #define ARCH_ARM64 1
#elif defined(__i386__) || defined(__i386) || defined(i386)
    #define ARCH_X86_32 1
#elif defined(__arm__)
    #define ARCH_ARM32 1
#else
    #define ARCH_UNKNOWN 1
#endif

#define MAX_SYSCALLS 1000
#define MAX_PROCESSES 100
#define MAX_FILENAME 256

typedef struct {
    long syscall_num;
    long timestamp;
    pid_t pid;
    long args[6];
    long return_value;
} syscall_info_t;

typedef struct {
    pid_t pid;
    pid_t parent_pid;
    char executable[MAX_FILENAME];
    long start_time;
    long end_time;
    int is_active;
} process_info_t;

typedef struct {
    syscall_info_t syscalls[MAX_SYSCALLS];
    process_info_t processes[MAX_PROCESSES];
    int syscall_count;
    int process_count;
    FILE *output_file;
} monitor_data_t;

// Global monitor data
monitor_data_t monitor;

const char* get_syscall_name(long syscall_num) {
    switch (syscall_num) {
        case SYS_read: return "read";
        case SYS_write: return "write";
        case SYS_open: return "open";
        case SYS_close: return "close";
        case SYS_stat: return "stat";
        case SYS_fstat: return "fstat";
        case SYS_lstat: return "lstat";
        case SYS_poll: return "poll";
        case SYS_lseek: return "lseek";
        case SYS_mmap: return "mmap";
        case SYS_mprotect: return "mprotect";
        case SYS_munmap: return "munmap";
        case SYS_brk: return "brk";
        case SYS_rt_sigaction: return "rt_sigaction";
        case SYS_rt_sigprocmask: return "rt_sigprocmask";
        case SYS_ioctl: return "ioctl";
        case SYS_access: return "access";
        case SYS_pipe: return "pipe";
        case SYS_select: return "select";
        case SYS_mremap: return "mremap";
        case SYS_msync: return "msync";
        case SYS_mincore: return "mincore";
        case SYS_madvise: return "madvise";
        case SYS_dup: return "dup";
        case SYS_dup2: return "dup2";
        case SYS_pause: return "pause";
        case SYS_nanosleep: return "nanosleep";
        case SYS_getitimer: return "getitimer";
        case SYS_alarm: return "alarm";
        case SYS_setitimer: return "setitimer";
        case SYS_getpid: return "getpid";
        case SYS_sendfile: return "sendfile";
        case SYS_socket: return "socket";
        case SYS_connect: return "connect";
        case SYS_accept: return "accept";
        case SYS_sendto: return "sendto";
        case SYS_recvfrom: return "recvfrom";
        case SYS_sendmsg: return "sendmsg";
        case SYS_recvmsg: return "recvmsg";
        case SYS_shutdown: return "shutdown";
        case SYS_bind: return "bind";
        case SYS_listen: return "listen";
        case SYS_getsockname: return "getsockname";
        case SYS_getpeername: return "getpeername";
        case SYS_socketpair: return "socketpair";
        case SYS_setsockopt: return "setsockopt";
        case SYS_getsockopt: return "getsockopt";
        case SYS_clone: return "clone";
        case SYS_fork: return "fork";
        case SYS_vfork: return "vfork";
        case SYS_execve: return "execve";
        case SYS_exit: return "exit";
        case SYS_wait4: return "wait4";
        case SYS_kill: return "kill";
        case SYS_uname: return "uname";
        case SYS_fcntl: return "fcntl";
        case SYS_flock: return "flock";
        case SYS_fsync: return "fsync";
        case SYS_fdatasync: return "fdatasync";
        case SYS_truncate: return "truncate";
        case SYS_ftruncate: return "ftruncate";
        case SYS_getdents: return "getdents";
        case SYS_getcwd: return "getcwd";
        case SYS_chdir: return "chdir";
        case SYS_fchdir: return "fchdir";
        case SYS_rename: return "rename";
        case SYS_mkdir: return "mkdir";
        case SYS_rmdir: return "rmdir";
        case SYS_creat: return "creat";
        case SYS_link: return "link";
        case SYS_unlink: return "unlink";
        case SYS_symlink: return "symlink";
        case SYS_readlink: return "readlink";
        case SYS_chmod: return "chmod";
        case SYS_fchmod: return "fchmod";
        case SYS_chown: return "chown";
        case SYS_fchown: return "fchown";
        case SYS_lchown: return "lchown";
        case SYS_umask: return "umask";
        default: return "unknown";
    }
}

void log_syscall(pid_t pid, long syscall_num, void *regs_ptr) {
    if (monitor.syscall_count >= MAX_SYSCALLS) return;
    
    syscall_info_t *sc = &monitor.syscalls[monitor.syscall_count];
    sc->pid = pid;
    sc->syscall_num = syscall_num;
    sc->timestamp = time(NULL);
    
    // Initialize args to 0
    for (int i = 0; i < 6; i++) {
        sc->args[i] = 0;
    }
    
#ifdef __linux__
    struct user_regs_struct *regs = (struct user_regs_struct *)regs_ptr;
    if (regs) {
        #ifdef ARCH_X86_64
            // x86_64 Linux syscall argument registers
            sc->args[0] = regs->rdi;
            sc->args[1] = regs->rsi;
            sc->args[2] = regs->rdx;
            sc->args[3] = regs->r10;
            sc->args[4] = regs->r8;
            sc->args[5] = regs->r9;
        #elif defined(ARCH_ARM64)
            // ARM64 Linux syscall argument registers
            sc->args[0] = regs->regs[0];
            sc->args[1] = regs->regs[1];
            sc->args[2] = regs->regs[2];
            sc->args[3] = regs->regs[3];
            sc->args[4] = regs->regs[4];
            sc->args[5] = regs->regs[5];
        #elif defined(ARCH_X86_32)
            // x86_32 Linux syscall argument registers
            sc->args[0] = regs->ebx;
            sc->args[1] = regs->ecx;
            sc->args[2] = regs->edx;
            sc->args[3] = regs->esi;
            sc->args[4] = regs->edi;
            sc->args[5] = regs->ebp;
        #endif
    }
#elif __APPLE__
    // macOS doesn't provide easy access to syscall arguments via ptrace
    // We'll capture what we can through other means
    (void)regs_ptr; // Suppress unused parameter warning
#endif
    
    monitor.syscall_count++;
    
    // Write to output file
    if (monitor.output_file) {
        fprintf(monitor.output_file, "SYSCALL,%ld,%d,%s,%ld,%ld,%ld,%ld,%ld,%ld,%ld\n",
                sc->timestamp, pid, get_syscall_name(syscall_num),
                sc->args[0], sc->args[1], sc->args[2], 
                sc->args[3], sc->args[4], sc->args[5]);
        fflush(monitor.output_file);
    }
}

void log_process(pid_t pid, pid_t parent_pid, const char* executable) {
    if (monitor.process_count >= MAX_PROCESSES) return;
    
    process_info_t *proc = &monitor.processes[monitor.process_count];
    proc->pid = pid;
    proc->parent_pid = parent_pid;
    strncpy(proc->executable, executable, MAX_FILENAME - 1);
    proc->executable[MAX_FILENAME - 1] = '\0';
    proc->start_time = time(NULL);
    proc->is_active = 1;
    
    monitor.process_count++;
    
    // Write to output file
    if (monitor.output_file) {
        fprintf(monitor.output_file, "PROCESS_START,%ld,%d,%d,%s\n",
                proc->start_time, pid, parent_pid, executable);
        fflush(monitor.output_file);
    }
}

void log_process_exit(pid_t pid, int exit_code) {
    // Find and update process info
    for (int i = 0; i < monitor.process_count; i++) {
        if (monitor.processes[i].pid == pid && monitor.processes[i].is_active) {
            monitor.processes[i].end_time = time(NULL);
            monitor.processes[i].is_active = 0;
            
            if (monitor.output_file) {
                fprintf(monitor.output_file, "PROCESS_EXIT,%ld,%d,%d\n",
                        monitor.processes[i].end_time, pid, exit_code);
                fflush(monitor.output_file);
            }
            break;
        }
    }
}

void trace_process(pid_t pid) {
    int status;
    int in_syscall = 0;
    
#ifdef __linux__
    struct user_regs_struct regs;
#endif
    
    while (1) {
        if (waitpid(pid, &status, 0) == -1) {
            perror("waitpid");
            break;
        }
        
        if (WIFEXITED(status)) {
            log_process_exit(pid, WEXITSTATUS(status));
            break;
        }
        
        if (WIFSIGNALED(status)) {
            log_process_exit(pid, -WTERMSIG(status));
            break;
        }
        
        if (WIFSTOPPED(status)) {
            if (WSTOPSIG(status) == SIGTRAP) {
#ifdef __linux__
                if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1) {
                    perror("ptrace getregs");
                    break;
                }
                
                long syscall_num = 0;
                #ifdef ARCH_X86_64
                    syscall_num = regs.orig_rax;
                #elif defined(ARCH_ARM64)
                    syscall_num = regs.regs[8];  // ARM64 syscall number in x8
                #elif defined(ARCH_X86_32)
                    syscall_num = regs.orig_eax;
                #endif
                
                if (!in_syscall) {
                    // Entering syscall
                    log_syscall(pid, syscall_num, &regs);
                    in_syscall = 1;
                } else {
                    // Exiting syscall
                    in_syscall = 0;
                }
#elif __APPLE__
                // macOS ptrace is more limited
                // Log basic process activity without detailed syscall info
                if (!in_syscall) {
                    log_syscall(pid, -1, NULL);  // Use -1 to indicate unknown syscall
                    in_syscall = 1;
                } else {
                    in_syscall = 0;
                }
#endif
            }
        }
        
#ifdef __linux__
        if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) == -1) {
            perror("ptrace syscall");
            break;
        }
#elif __APPLE__
        // macOS uses different ptrace options
        if (ptrace(PT_CONTINUE, pid, (caddr_t)1, 0) == -1) {
            perror("ptrace continue");
            break;
        }
#endif
    }
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <output_file> <program> [args...]\n", argv[0]);
        return 1;
    }
    
    // Initialize monitor data
    memset(&monitor, 0, sizeof(monitor));
    monitor.output_file = fopen(argv[1], "w");
    if (!monitor.output_file) {
        perror("fopen output file");
        return 1;
    }
    
    // Write header
    fprintf(monitor.output_file, "# Sentinal Process Monitor Output\n");
    fprintf(monitor.output_file, "# Format: TYPE,timestamp,pid,details...\n");
    fflush(monitor.output_file);
    
    pid_t child_pid = fork();
    
    if (child_pid == -1) {
        perror("fork");
        fclose(monitor.output_file);
        return 1;
    }
    
    if (child_pid == 0) {
        // Child process
#ifdef __linux__
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
            perror("ptrace traceme");
            exit(1);
        }
#elif __APPLE__
        if (ptrace(PT_TRACE_ME, 0, NULL, 0) == -1) {
            perror("ptrace trace_me");
            exit(1);
        }
#endif
        
        // Execute the target program
        execvp(argv[2], &argv[2]);
        perror("execvp");
        exit(1);
    } else {
        // Parent process
        printf("Monitoring process %d...\n", child_pid);
        
        // Wait for child to stop at execve
        int status;
        if (waitpid(child_pid, &status, 0) == -1) {
            perror("waitpid");
            fclose(monitor.output_file);
            return 1;
        }
        
#ifdef __linux__
        // Set ptrace options to trace children and syscalls (Linux)
        if (ptrace(PTRACE_SETOPTIONS, child_pid, NULL, 
                   PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | 
                   PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC) == -1) {
            perror("ptrace setoptions");
        }
        
        // Log initial process
        log_process(child_pid, getpid(), argv[2]);
        
        // Start syscall tracing
        if (ptrace(PTRACE_SYSCALL, child_pid, NULL, NULL) == -1) {
            perror("ptrace syscall");
            fclose(monitor.output_file);
            return 1;
        }
#elif __APPLE__
        // macOS ptrace setup
        // Log initial process
        log_process(child_pid, getpid(), argv[2]);
        
        // Start tracing (macOS style)
        if (ptrace(PT_CONTINUE, child_pid, (caddr_t)1, 0) == -1) {
            perror("ptrace continue");
            fclose(monitor.output_file);
            return 1;
        }
#endif
        
        // Trace the process
        trace_process(child_pid);
        
        printf("Monitoring complete. %d syscalls, %d processes logged.\n", 
               monitor.syscall_count, monitor.process_count);
    }
    
    fclose(monitor.output_file);
    return 0;
}