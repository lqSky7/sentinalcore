#!/usr/bin/env python3
from bcc import BPF
import ctypes
import sys
import signal

bpf_program = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <net/sock.h>
#include <linux/keyctl.h>
#include <linux/mount.h>
#include <bcc/proto.h>

#define MAX_DATA 256
#define AF_INET 2
#define AF_INET6 10

struct data_t {
    u32 pid;
    u32 ppid;
    char comm[16];
    char syscall[20];
    char arg1[MAX_DATA];
    char arg2[MAX_DATA];
    char arg3[MAX_DATA];
};

BPF_HASH(tracked_pids, u32, u8);
BPF_PERF_OUTPUT(events);
BPF_PERCPU_ARRAY(stack_buf, struct data_t, 1);

static void get_process_info(struct data_t *data) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent;
    bpf_probe_read_kernel(&parent, sizeof(parent), &task->real_parent);
    bpf_probe_read_kernel(&data->ppid, sizeof(data->ppid), &parent->tgid);
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
}

// ──── Common Handler Pattern ────────────────────────────────────────────────
#define HANDLE_SYSCALL(name, ...) \
TRACEPOINT_PROBE(syscalls, sys_enter_##name) { \
    u32 pid = bpf_get_current_pid_tgid() >> 32; \
    if (!tracked_pids.lookup(&pid)) return 0; \
    int zero = 0; \
    struct data_t *data = stack_buf.lookup(&zero); \
    if (!data) return 0; \
    __builtin_memset(data, 0, sizeof(struct data_t)); \
    get_process_info(data); \
    data->pid = pid; \
    __builtin_memcpy(data->syscall, #name, sizeof(#name)); \
    __VA_ARGS__ \
    events.perf_submit(args, data, sizeof(struct data_t)); \
    return 0; \
}

// ──── Syscall Handlers ──────────────────────────────────────────────────────
HANDLE_SYSCALL(execve,
    bpf_probe_read_user_str(data->arg1, sizeof(data->arg1), args->filename);
)

HANDLE_SYSCALL(openat,
    bpf_probe_read_user_str(data->arg1, sizeof(data->arg1), args->filename);
    snprintf(data->arg2, sizeof(data->arg2), "flags: 0x%llx", args->flags);
)

HANDLE_SYSCALL(connect,
    struct sockaddr *addr;
    bpf_probe_read_user(&addr, sizeof(addr), &args->uservaddr);
    if (addr->sa_family == AF_INET) {
        struct sockaddr_in sin;
        bpf_probe_read_user(&sin, sizeof(sin), addr);
        u32 ip = sin.sin_addr.s_addr;
        u16 port = ntohs(sin.sin_port);
        snprintf(data->arg1, sizeof(data->arg1), "%d.%d.%d.%d",
                (ip >> 0)&0xff, (ip >> 8)&0xff,
                (ip >> 16)&0xff, (ip >> 24)&0xff);
        snprintf(data->arg2, sizeof(data->arg2), "%d", port);
    }
)

HANDLE_SYSCALL(bind,
    struct sockaddr *addr;
    bpf_probe_read_user(&addr, sizeof(addr), &args->umyaddr);
    if (addr->sa_family == AF_INET) {
        struct sockaddr_in sin;
        bpf_probe_read_user(&sin, sizeof(sin), addr);
        snprintf(data->arg1, sizeof(data->arg1), "%d.%d.%d.%d",
                sin.sin_addr.s_addr & 0xff,
                (sin.sin_addr.s_addr >> 8) & 0xff,
                (sin.sin_addr.s_addr >> 16) & 0xff,
                (sin.sin_addr.s_addr >> 24) & 0xff);
        snprintf(data->arg2, sizeof(data->arg2), "%d", ntohs(sin.sin_port));
    }
)

HANDLE_SYSCALL(clone,
    snprintf(data->arg1, sizeof(data->arg1), "flags: 0x%08lx", args->clone_flags);
)

HANDLE_SYSCALL(kill,
    snprintf(data->arg1, sizeof(data->arg1), "sig: %lld", args->sig);
)

HANDLE_SYSCALL(ptrace,
    snprintf(data->arg1, sizeof(data->arg1), "req: 0x%lx", args->request);
)

HANDLE_SYSCALL(unlink,
    bpf_probe_read_user_str(data->arg1, sizeof(data->arg1), args->pathname);
)

HANDLE_SYSCALL(mkdir,
    bpf_probe_read_user_str(data->arg1, sizeof(data->arg1), args->pathname);
    snprintf(data->arg2, sizeof(data->arg2), "mode: 0%o", args->mode);
)

HANDLE_SYSCALL(chmod,
    bpf_probe_read_user_str(data->arg1, sizeof(data->arg1), args->filename);
    snprintf(data->arg2, sizeof(data->arg2), "mode: 0%o", args->mode);
)

HANDLE_SYSCALL(mount,
    bpf_probe_read_user_str(data->arg1, sizeof(data->arg1), args->dev_name);
    bpf_probe_read_user_str(data->arg2, sizeof(data->arg2), args->dir_name);
    bpf_probe_read_user_str(data->arg3, sizeof(data->arg3), args->type);
)

HANDLE_SYSCALL(capset,
    struct __user_cap_header_struct header;
    struct __user_cap_data_struct caps[_LINUX_CAPABILITY_U32S_3];
    bpf_probe_read_user(&header, sizeof(header), args->header);
    bpf_probe_read_user(&caps, sizeof(caps), args->data);
    snprintf(data->arg1, sizeof(data->arg1), "ver: %d", header.version);
    snprintf(data->arg2, sizeof(data->arg2), "caps: 0x%08x", caps[0].effective);
)

HANDLE_SYSCALL(keyctl,
    snprintf(data->arg1, sizeof(data->arg1), "op: %lld", args->option);
)

HANDLE_SYSCALL(accept4,
    struct sockaddr addr;
    __u32 addrlen;
    bpf_probe_read_user(&addr, sizeof(addr), args->upeer_sockaddr);
    bpf_probe_read_user(&addrlen, sizeof(addrlen), args->upeer_addrlen);
    if (addr.sa_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)&addr;
        snprintf(data->arg1, sizeof(data->arg1), "%d.%d.%d.%d",
                sin->sin_addr.s_addr & 0xff,
                (sin->sin_addr.s_addr >> 8) & 0xff,
                (sin->sin_addr.s_addr >> 16) & 0xff,
                (sin->sin_addr.s_addr >> 24) & 0xff);
        snprintf(data->arg2, sizeof(data->arg2), "%d", ntohs(sin->sin_port));
    }
)

HANDLE_SYSCALL(rename,
    bpf_probe_read_user_str(data->arg1, sizeof(data->arg1), args->oldname);
    bpf_probe_read_user_str(data->arg2, sizeof(data->arg2), args->newname);
)

TRACEPOINT_PROBE(sched, sched_process_fork) {
    u32 parent = args->parent_pid;
    u32 child = args->child_pid;
    u8 one = 1;
    if (tracked_pids.lookup(&parent)) {
        tracked_pids.update(&child, &one);
    }
    return 0;
}

TRACEPOINT_PROBE(sched, sched_process_exit) {
    u32 pid = args->pid;
    tracked_pids.delete(&pid);
    return 0;
}
"""

class Data(ctypes.Structure):
    _fields_ = [
        ("pid", ctypes.c_uint),
        ("ppid", ctypes.c_uint),
        ("comm", ctypes.c_char * 16),
        ("syscall", ctypes.c_char * 20),
        ("arg1", ctypes.c_char * 256),
        ("arg2", ctypes.c_char * 256),
        ("arg3", ctypes.c_char * 256)
    ]

def handle_event(cpu, data, size):
    event = ctypes.cast(data, ctypes.POINTER(Data)).contents
    syscall = event.syscall.decode()
    
    output = f"[PID:{event.pid}][PPID:{event.ppid}][{event.comm.decode()}] {syscall}"
    
    if syscall in ['execve', 'openat', 'unlink', 'rename']:
        output += f" path='{event.arg1.decode()}'"
    elif syscall == 'connect':
        output += f" to {event.arg1.decode()}:{event.arg2.decode()}"
    elif syscall == 'bind':
        output += f" on {event.arg1.decode()}:{event.arg2.decode()}"
    elif syscall in ['clone', 'ptrace', 'kill']:
        output += f" flags={event.arg1.decode()}"
    elif syscall == 'chmod':
        output += f" {event.arg1.decode()} mode={event.arg2.decode()}"
    elif syscall == 'mount':
        output += f" {event.arg1.decode()} -> {event.arg2.decode()} ({event.arg3.decode()})"
    elif syscall == 'capset':
        output += f" {event.arg1.decode()} caps={event.arg2.decode()}"
    
    print(output)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: sudo {sys.argv[0]} <root-pid>")
        sys.exit(1)

    b = BPF(text=bpf_program)
    root_pid = int(sys.argv[1])
    b["tracked_pids"][ctypes.c_uint(root_pid)] = ctypes.c_ubyte(1)

    def cleanup(sig, frame):
        print("\nDetaching...")
        sys.exit(0)

    signal.signal(signal.SIGINT, cleanup)
    b["events"].open_perf_buffer(handle_event)

    print(f"🔍 Monitoring process tree from PID {root_pid}")
    print("🛑 Ctrl+C to exit")
    try:
        while True:
            b.perf_buffer_poll()
    except KeyboardInterrupt:
        cleanup(None, None)
