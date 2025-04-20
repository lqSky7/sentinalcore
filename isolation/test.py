from bcc import BPF
import ctypes
import sys

bpf_program = """
#include <uapi/linux/ptrace.h>

struct data_t {
    u32 pid;
    char comm[16];
    char syscall[16];
};

BPF_HASH(tracked_pids, u32, u8);
BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(sched, sched_process_fork) {
    u32 parent = args->parent_pid;
    u32 child = args->child_pid;
    u8 one = 1;

    u8 *p = tracked_pids.lookup(&parent);
    if (p) {
        tracked_pids.update(&child, &one);
    }
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u8 *p = tracked_pids.lookup(&pid);
    if (!p) {
        return 0;
    }

    struct data_t data = {};
    data.pid = pid;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    __builtin_memcpy(&data.syscall, "execve", 7);
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}
"""

if len(sys.argv) < 2:
    print(f"Usage: sudo {sys.argv[0]} <parent-pid>")
    exit(1)

parent_pid = int(sys.argv[1])
b = BPF(text=bpf_program)

# Add parent PID to tracked map
tracked_map = b["tracked_pids"]
tracked_map[ctypes.c_uint(parent_pid)] = ctypes.c_ubyte(1)

class Data(ctypes.Structure):
    _fields_ = [("pid", ctypes.c_uint),
                ("comm", ctypes.c_char * 16),
                ("syscall", ctypes.c_char * 16)]

def handle_event(cpu, data, size):
    event = ctypes.cast(data, ctypes.POINTER(Data)).contents
    print(f"[{event.pid}][{event.comm.decode()}]: {event.syscall.decode()}")

b["events"].open_perf_buffer(handle_event)

print(f"Tracing execve() for PID {parent_pid} and its children. Ctrl+C to exit.")
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit(0)

