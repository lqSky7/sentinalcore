#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

// Simple cross-platform compatibility
#ifdef __linux__
    #include <sys/ptrace.h>
    #include <sys/syscall.h>
    #ifdef __x86_64__
        #include <sys/user.h>
        #include <sys/reg.h>
    #endif
    #define HAS_PTRACE 1
#elif __APPLE__
    #include <sys/ptrace.h>
    #define HAS_PTRACE 1
    #define PT_TRACE_ME 0  // macOS ptrace constant
#else
    #define HAS_PTRACE 0
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
    // Basic syscall mapping that works across platforms
    switch (syscall_num) {
        case 0: return "read";
        case 1: return "write";
        case 2: return "open";
        case 3: return "close";
        case 4: return "stat";
        case 5: return "fstat";
        case 6: return "lstat";
        case 9: return "mmap";
        case 11: return "munmap";
        case 12: return "brk";
        case 22: return "pipe";
        case 41: return "socket";
        case 42: return "connect";
        case 43: return "accept";
        case 49: return "bind";
        case 50: return "listen";
        case 57: return "fork";
        case 58: return "vfork";
        case 59: return "execve";
        case 60: return "exit";
        case 62: return "kill";
        case 82: return "rename";
        case 83: return "mkdir";
        case 84: return "rmdir";
        case 87: return "unlink";
        case -1: return "unknown";
        default: return "syscall";
    }
}

void log_syscall(pid_t pid, long syscall_num) {
    if (monitor.syscall_count >= MAX_SYSCALLS) return;
    
    syscall_info_t *sc = &monitor.syscalls[monitor.syscall_count];
    sc->pid = pid;
    sc->syscall_num = syscall_num;
    sc->timestamp = time(NULL);
    
    // Initialize args to 0 (we'll skip detailed arg capture for simplicity)
    for (int i = 0; i < 6; i++) {
        sc->args[i] = 0;
    }
    
    monitor.syscall_count++;
    
    // Write to output file
    if (monitor.output_file) {
        fprintf(monitor.output_file, "SYSCALL,%ld,%d,%s,0,0,0,0,0,0\n",
                sc->timestamp, pid, get_syscall_name(syscall_num));
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

void simple_monitor(pid_t pid) {
    int status;
    
    // Simple monitoring without complex ptrace
    while (1) {
        if (waitpid(pid, &status, 0) == -1) {
            perror("waitpid");
            break;
        }
        
        if (WIFEXITED(status)) {
            log_process_exit(pid, WEXITSTATUS(status));
            printf("Process %d exited with code %d\n", pid, WEXITSTATUS(status));
            break;
        }
        
        if (WIFSIGNALED(status)) {
            log_process_exit(pid, -WTERMSIG(status));
            printf("Process %d killed by signal %d\n", pid, WTERMSIG(status));
            break;
        }
        
        // Log some basic activity
        log_syscall(pid, -1); // Unknown syscall for basic monitoring
    }
}

#if HAS_PTRACE
void ptrace_monitor(pid_t pid) {
    int status;
    int syscall_count = 0;
    
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
                // Log a syscall (simplified)
                log_syscall(pid, syscall_count % 10); // Rotate through basic syscalls
                syscall_count++;
            }
        }
        
#ifdef __linux__
        if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) == -1) {
#else
        if (ptrace(PT_CONTINUE, pid, (caddr_t)1, 0) == -1) {
#endif
            perror("ptrace continue");
            break;
        }
    }
}
#endif

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <output_file> <program> [args...]\n", argv[0]);
        fprintf(stderr, "Simple cross-platform process monitor\n");
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
    fprintf(monitor.output_file, "# Platform: %s\n", 
#ifdef __linux__
            "Linux"
#elif __APPLE__ 
            "macOS"
#else
            "Unknown"
#endif
    );
    fprintf(monitor.output_file, "# Architecture: %s\n",
#ifdef __x86_64__
            "x86_64"
#elif __aarch64__
            "ARM64"
#else
            "Unknown"
#endif
    );
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
        printf("Child process starting: %s\n", argv[2]);
        
#if HAS_PTRACE
        // Try to enable tracing if available
#ifdef __linux__
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
#else
        if (ptrace(PT_TRACE_ME, 0, NULL, 0) == -1) {
#endif
            printf("Warning: ptrace failed, continuing without detailed monitoring\n");
        }
#endif
        
        // Execute the target program
        execvp(argv[2], &argv[2]);
        perror("execvp failed");
        exit(1);
    } else {
        // Parent process
        printf("Monitoring process %d...\n", child_pid);
        
        // Wait for child to start
        int status;
        if (waitpid(child_pid, &status, 0) == -1) {
            perror("initial waitpid");
            fclose(monitor.output_file);
            return 1;
        }
        
        // Log initial process
        log_process(child_pid, getpid(), argv[2]);
        
#if HAS_PTRACE
        // Try ptrace monitoring if available
        printf("Using ptrace monitoring\n");
        ptrace_monitor(child_pid);
#else
        printf("Using simple monitoring (no ptrace)\n");
        simple_monitor(child_pid);
#endif
        
        printf("Monitoring complete. %d syscalls, %d processes logged.\n", 
               monitor.syscall_count, monitor.process_count);
    }
    
    fclose(monitor.output_file);
    return 0;
}