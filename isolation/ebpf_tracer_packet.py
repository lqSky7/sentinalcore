from bcc import BPF
import sys
import time

if len(sys.argv) != 2:
    print("Usage: sudo python3 tracer.py <parent_pid>")
    exit(1)

parent_pid = int(sys.argv[1])

bpf_program = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

BPF_HASH(tracked_pids, u32, u8);

// Automatically track children of the parent
TRACEPOINT_PROBE(sched, sched_process_fork) {
    u32 parent = args->parent_pid;
    u32 child = args->child_pid;
    u8 one = 1;

    if (tracked_pids.lookup(&parent)) {
        tracked_pids.update(&child, &one);
    }

    return 0;
}

#define TRACE_SYSCALL(name) \
TRACEPOINT_PROBE(syscalls, sys_enter_##name) { \
    u32 pid = bpf_get_current_pid_tgid() >> 32; \
    if (tracked_pids.lookup(&pid)) { \
        bpf_trace_printk("[%d][%s]\\n", pid, #name); \
    } \
    return 0; \
}

// 15 critical syscalls + 2 rare
TRACE_SYSCALL(execve)
TRACE_SYSCALL(clone)
TRACE_SYSCALL(clone3)
TRACE_SYSCALL(fork)
TRACE_SYSCALL(vfork)
TRACE_SYSCALL(openat)
TRACE_SYSCALL(read)
TRACE_SYSCALL(write)
TRACE_SYSCALL(close)
TRACE_SYSCALL(unlinkat)
TRACE_SYSCALL(renameat2)
TRACE_SYSCALL(connect)
TRACE_SYSCALL(accept4)
TRACE_SYSCALL(socket)
TRACE_SYSCALL(mmap)
TRACE_SYSCALL(mprotect)
TRACE_SYSCALL(ptrace)
TRACE_SYSCALL(syslog)
TRACE_SYSCALL(reboot)
"""

# Load and initialize BPF
b = BPF(text=bpf_program)

# Seed the parent PID
tracked = b.get_table("tracked_pids")
tracked[b["tracked_pids"].Key(parent_pid)] = b["tracked_pids"].Leaf(1)

print(f"Tracing syscalls for PID {parent_pid} and its children. Ctrl+C to stop.")

try:
    while True:
        (_, _, _, _, _, msg) = b.trace_fields()
        print(msg)
except KeyboardInterrupt:
    print("Tracing stopped.")

