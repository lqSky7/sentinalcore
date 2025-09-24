#!/usr/bin/env python3
"""
Enhanced eBPF System Call Tracer for Malware Analysis
Comprehensive monitoring of system calls, process creation, network activity,
file operations, memory operations, and suspicious behaviors.
"""

import os
import sys
import time
import json
import ctypes
import signal
from datetime import datetime
from bcc import BPF

if len(sys.argv) < 2:
    print(f"Usage: sudo {sys.argv[0]} <target_pid>")
    sys.exit(1)

target_pid = int(sys.argv[1])
output_file = f"/tmp/ebpf_trace_{target_pid}_{int(time.time())}.json"
trace_data = {
    'syscalls': [],
    'process_events': [],
    'network_events': [],
    'file_events': [],
    'memory_events': [],
    'start_time': datetime.now().isoformat(),
    'target_pid': target_pid
}

# Enhanced eBPF program with comprehensive tracing
ebpf_program = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <net/sock.h>

// Data structures for different event types
struct syscall_data_t {
    u64 timestamp;
    u32 pid;
    u32 ppid;
    u32 uid;
    char comm[16];
    char syscall[32];
    u64 args[6];
    s64 retval;
};

struct process_event_t {
    u64 timestamp;
    u32 parent_pid;
    u32 child_pid;
    char parent_comm[16];
    char child_comm[16];
    char event_type[16];
    char filename[256];
};

struct network_event_t {
    u64 timestamp;
    u32 pid;
    char comm[16];
    char event_type[16];
    u32 family;
    u32 type;
    u32 protocol;
    u32 local_addr;
    u32 remote_addr;
    u16 local_port;
    u16 remote_port;
};

struct file_event_t {
    u64 timestamp;
    u32 pid;
    char comm[16];
    char event_type[16];
    char filename[256];
    s32 fd;
    u64 size;
    u32 mode;
};

struct memory_event_t {
    u64 timestamp;
    u32 pid;
    char comm[16];
    char event_type[16];
    u64 addr;
    u64 size;
    u32 prot;
    u32 flags;
};

// Hash maps and buffers
BPF_HASH(tracked_pids, u32, u8);
BPF_PERCPU_ARRAY(syscall_buf, struct syscall_data_t, 1);
BPF_PERCPU_ARRAY(process_buf, struct process_event_t, 1);
BPF_PERCPU_ARRAY(network_buf, struct network_event_t, 1);
BPF_PERCPU_ARRAY(file_buf, struct file_event_t, 1);
BPF_PERCPU_ARRAY(memory_buf, struct memory_event_t, 1);

// Perf outputs for different event types
BPF_PERF_OUTPUT(syscall_events);
BPF_PERF_OUTPUT(process_events);
BPF_PERF_OUTPUT(network_events);
BPF_PERF_OUTPUT(file_events);
BPF_PERF_OUTPUT(memory_events);

// Helper functions
static inline int is_tracked_pid(u32 pid) {
    u8 *val = tracked_pids.lookup(&pid);
    return val != NULL;
}

static inline void add_tracked_pid(u32 pid) {
    u8 one = 1;
    tracked_pids.update(&pid, &one);
}

// Process creation/termination tracking
TRACEPOINT_PROBE(sched, sched_process_fork) {
    u32 parent = args->parent_pid;
    u32 child = args->child_pid;
    
    if (is_tracked_pid(parent)) {
        add_tracked_pid(child);
        
        int zero = 0;
        struct process_event_t *event = process_buf.lookup(&zero);
        if (!event) return 0;
        
        event->timestamp = bpf_ktime_get_ns();
        event->parent_pid = parent;
        event->child_pid = child;
        bpf_get_current_comm(&event->parent_comm, sizeof(event->parent_comm));
        __builtin_memcpy(event->event_type, "fork", 5);
        
        process_events.perf_submit(args, event, sizeof(*event));
    }
    return 0;
}

TRACEPOINT_PROBE(sched, sched_process_exec) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    if (is_tracked_pid(pid)) {
        int zero = 0;
        struct process_event_t *event = process_buf.lookup(&zero);
        if (!event) return 0;
        
        event->timestamp = bpf_ktime_get_ns();
        event->child_pid = pid;
        bpf_get_current_comm(&event->child_comm, sizeof(event->child_comm));
        __builtin_memcpy(event->event_type, "exec", 5);
        bpf_probe_read_user_str(event->filename, sizeof(event->filename), args->filename);
        
        process_events.perf_submit(args, event, sizeof(*event));
    }
    return 0;
}

TRACEPOINT_PROBE(sched, sched_process_exit) {
    u32 pid = args->pid;
    
    if (is_tracked_pid(pid)) {
        int zero = 0;
        struct process_event_t *event = process_buf.lookup(&zero);
        if (!event) return 0;
        
        event->timestamp = bpf_ktime_get_ns();
        event->child_pid = pid;
        bpf_get_current_comm(&event->child_comm, sizeof(event->child_comm));
        __builtin_memcpy(event->event_type, "exit", 5);
        
        process_events.perf_submit(args, event, sizeof(*event));
        
        // Remove from tracking
        tracked_pids.delete(&pid);
    }
    return 0;
}

// System call tracing macro
#define TRACE_SYSCALL(name) \\
TRACEPOINT_PROBE(syscalls, sys_enter_##name) { \\
    u32 pid = bpf_get_current_pid_tgid() >> 32; \\
    if (!is_tracked_pid(pid)) return 0; \\
    \\
    int zero = 0; \\
    struct syscall_data_t *data = syscall_buf.lookup(&zero); \\
    if (!data) return 0; \\
    \\
    data->timestamp = bpf_ktime_get_ns(); \\
    data->pid = pid; \\
    data->ppid = bpf_get_current_pid_tgid() & 0xFFFFFFFF; \\
    data->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF; \\
    bpf_get_current_comm(&data->comm, sizeof(data->comm)); \\
    __builtin_memcpy(data->syscall, #name, sizeof(#name)); \\
    \\
    syscall_events.perf_submit(args, data, sizeof(*data)); \\
    return 0; \\
} \\
\\
TRACEPOINT_PROBE(syscalls, sys_exit_##name) { \\
    u32 pid = bpf_get_current_pid_tgid() >> 32; \\
    if (!is_tracked_pid(pid)) return 0; \\
    \\
    int zero = 0; \\
    struct syscall_data_t *data = syscall_buf.lookup(&zero); \\
    if (!data) return 0; \\
    \\
    data->timestamp = bpf_ktime_get_ns(); \\
    data->pid = pid; \\
    data->retval = args->ret; \\
    bpf_get_current_comm(&data->comm, sizeof(data->comm)); \\
    __builtin_memcpy(data->syscall, #name "_exit", sizeof(#name "_exit")); \\
    \\
    syscall_events.perf_submit(args, data, sizeof(*data)); \\
    return 0; \\
}

// File operations
TRACE_SYSCALL(open)
TRACE_SYSCALL(openat)
TRACE_SYSCALL(read)
TRACE_SYSCALL(write)
TRACE_SYSCALL(close)
TRACE_SYSCALL(unlink)
TRACE_SYSCALL(unlinkat)
TRACE_SYSCALL(rename)
TRACE_SYSCALL(renameat)
TRACE_SYSCALL(renameat2)
TRACE_SYSCALL(mkdir)
TRACE_SYSCALL(rmdir)
TRACE_SYSCALL(chmod)
TRACE_SYSCALL(chown)

// Process operations
TRACE_SYSCALL(execve)
TRACE_SYSCALL(execveat)
TRACE_SYSCALL(clone)
TRACE_SYSCALL(clone3)
TRACE_SYSCALL(fork)
TRACE_SYSCALL(vfork)
TRACE_SYSCALL(wait4)
TRACE_SYSCALL(waitid)
TRACE_SYSCALL(kill)
TRACE_SYSCALL(tkill)
TRACE_SYSCALL(tgkill)

// Network operations
TRACE_SYSCALL(socket)
TRACE_SYSCALL(bind)
TRACE_SYSCALL(listen)
TRACE_SYSCALL(accept)
TRACE_SYSCALL(accept4)
TRACE_SYSCALL(connect)
TRACE_SYSCALL(sendto)
TRACE_SYSCALL(recvfrom)
TRACE_SYSCALL(sendmsg)
TRACE_SYSCALL(recvmsg)
TRACE_SYSCALL(shutdown)
TRACE_SYSCALL(setsockopt)
TRACE_SYSCALL(getsockopt)

// Memory operations
TRACE_SYSCALL(mmap)
TRACE_SYSCALL(munmap)
TRACE_SYSCALL(mprotect)
TRACE_SYSCALL(mlock)
TRACE_SYSCALL(munlock)
TRACE_SYSCALL(mlockall)
TRACE_SYSCALL(munlockall)
TRACE_SYSCALL(brk)
TRACE_SYSCALL(mremap)
TRACE_SYSCALL(msync)
TRACE_SYSCALL(madvise)

// Suspicious operations
TRACE_SYSCALL(ptrace)
TRACE_SYSCALL(prctl)
TRACE_SYSCALL(setuid)
TRACE_SYSCALL(setgid)
TRACE_SYSCALL(setresuid)
TRACE_SYSCALL(setresgid)
TRACE_SYSCALL(capset)
TRACE_SYSCALL(mount)
TRACE_SYSCALL(umount2)
TRACE_SYSCALL(pivot_root)
TRACE_SYSCALL(chroot)
TRACE_SYSCALL(reboot)
TRACE_SYSCALL(kexec_load)
TRACE_SYSCALL(init_module)
TRACE_SYSCALL(delete_module)

// Security and audit
TRACE_SYSCALL(seccomp)
TRACE_SYSCALL(setns)
TRACE_SYSCALL(unshare)
TRACE_SYSCALL(keyctl)
TRACE_SYSCALL(add_key)
TRACE_SYSCALL(request_key)

// Enhanced file operations with detailed info
TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (!is_tracked_pid(pid)) return 0;
    
    int zero = 0;
    struct file_event_t *event = file_buf.lookup(&zero);
    if (!event) return 0;
    
    event->timestamp = bpf_ktime_get_ns();
    event->pid = pid;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    __builtin_memcpy(event->event_type, "openat", 7);
    bpf_probe_read_user_str(event->filename, sizeof(event->filename), (void*)args->filename);
    event->mode = args->flags;
    
    file_events.perf_submit(args, event, sizeof(*event));
    return 0;
}

// Enhanced network operations
TRACEPOINT_PROBE(syscalls, sys_enter_socket) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (!is_tracked_pid(pid)) return 0;
    
    int zero = 0;
    struct network_event_t *event = network_buf.lookup(&zero);
    if (!event) return 0;
    
    event->timestamp = bpf_ktime_get_ns();
    event->pid = pid;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    __builtin_memcpy(event->event_type, "socket", 7);
    event->family = args->family;
    event->type = args->type;
    event->protocol = args->protocol;
    
    network_events.perf_submit(args, event, sizeof(*event));
    return 0;
}

// Enhanced memory operations
TRACEPOINT_PROBE(syscalls, sys_enter_mmap) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (!is_tracked_pid(pid)) return 0;
    
    int zero = 0;
    struct memory_event_t *event = memory_buf.lookup(&zero);
    if (!event) return 0;
    
    event->timestamp = bpf_ktime_get_ns();
    event->pid = pid;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    __builtin_memcpy(event->event_type, "mmap", 5);
    event->addr = args->addr;
    event->size = args->len;
    event->prot = args->prot;
    event->flags = args->flags;
    
    memory_events.perf_submit(args, event, sizeof(*event));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_mprotect) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (!is_tracked_pid(pid)) return 0;
    
    int zero = 0;
    struct memory_event_t *event = memory_buf.lookup(&zero);
    if (!event) return 0;
    
    event->timestamp = bpf_ktime_get_ns();
    event->pid = pid;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    __builtin_memcpy(event->event_type, "mprotect", 9);
    event->addr = args->start;
    event->size = args->len;
    event->prot = args->prot;
    
    memory_events.perf_submit(args, event, sizeof(*event));
    return 0;
}
"""

# Data structures for Python
class SyscallData(ctypes.Structure):
    _fields_ = [
        ("timestamp", ctypes.c_uint64),
        ("pid", ctypes.c_uint32),
        ("ppid", ctypes.c_uint32),
        ("uid", ctypes.c_uint32),
        ("comm", ctypes.c_char * 16),
        ("syscall", ctypes.c_char * 32),
        ("args", ctypes.c_uint64 * 6),
        ("retval", ctypes.c_int64),
    ]

class ProcessEvent(ctypes.Structure):
    _fields_ = [
        ("timestamp", ctypes.c_uint64),
        ("parent_pid", ctypes.c_uint32),
        ("child_pid", ctypes.c_uint32),
        ("parent_comm", ctypes.c_char * 16),
        ("child_comm", ctypes.c_char * 16),
        ("event_type", ctypes.c_char * 16),
        ("filename", ctypes.c_char * 256),
    ]

class NetworkEvent(ctypes.Structure):
    _fields_ = [
        ("timestamp", ctypes.c_uint64),
        ("pid", ctypes.c_uint32),
        ("comm", ctypes.c_char * 16),
        ("event_type", ctypes.c_char * 16),
        ("family", ctypes.c_uint32),
        ("type", ctypes.c_uint32),
        ("protocol", ctypes.c_uint32),
        ("local_addr", ctypes.c_uint32),
        ("remote_addr", ctypes.c_uint32),
        ("local_port", ctypes.c_uint16),
        ("remote_port", ctypes.c_uint16),
    ]

class FileEvent(ctypes.Structure):
    _fields_ = [
        ("timestamp", ctypes.c_uint64),
        ("pid", ctypes.c_uint32),
        ("comm", ctypes.c_char * 16),
        ("event_type", ctypes.c_char * 16),
        ("filename", ctypes.c_char * 256),
        ("fd", ctypes.c_int32),
        ("size", ctypes.c_uint64),
        ("mode", ctypes.c_uint32),
    ]

class MemoryEvent(ctypes.Structure):
    _fields_ = [
        ("timestamp", ctypes.c_uint64),
        ("pid", ctypes.c_uint32),
        ("comm", ctypes.c_char * 16),
        ("event_type", ctypes.c_char * 16),
        ("addr", ctypes.c_uint64),
        ("size", ctypes.c_uint64),
        ("prot", ctypes.c_uint32),
        ("flags", ctypes.c_uint32),
    ]

# Event handlers
def handle_syscall_event(cpu, data, size):
    event = ctypes.cast(data, ctypes.POINTER(SyscallData)).contents
    syscall_info = {
        "timestamp": datetime.fromtimestamp(event.timestamp / 1000000000).isoformat(),
        "pid": event.pid,
        "ppid": event.ppid,
        "uid": event.uid,
        "comm": event.comm.decode('utf-8', errors='ignore'),
        "syscall": event.syscall.decode('utf-8', errors='ignore'),
        "retval": event.retval if hasattr(event, 'retval') else None
    }
    trace_data['syscalls'].append(syscall_info)

def handle_process_event(cpu, data, size):
    event = ctypes.cast(data, ctypes.POINTER(ProcessEvent)).contents
    process_info = {
        "timestamp": datetime.fromtimestamp(event.timestamp / 1000000000).isoformat(),
        "parent_pid": event.parent_pid,
        "child_pid": event.child_pid,
        "parent_comm": event.parent_comm.decode('utf-8', errors='ignore'),
        "child_comm": event.child_comm.decode('utf-8', errors='ignore'),
        "event_type": event.event_type.decode('utf-8', errors='ignore'),
        "filename": event.filename.decode('utf-8', errors='ignore').rstrip('\x00')
    }
    trace_data['process_events'].append(process_info)

def handle_network_event(cpu, data, size):
    event = ctypes.cast(data, ctypes.POINTER(NetworkEvent)).contents
    network_info = {
        "timestamp": datetime.fromtimestamp(event.timestamp / 1000000000).isoformat(),
        "pid": event.pid,
        "comm": event.comm.decode('utf-8', errors='ignore'),
        "event_type": event.event_type.decode('utf-8', errors='ignore'),
        "family": event.family,
        "type": event.type,
        "protocol": event.protocol,
        "local_addr": event.local_addr,
        "remote_addr": event.remote_addr,
        "local_port": event.local_port,
        "remote_port": event.remote_port
    }
    trace_data['network_events'].append(network_info)

def handle_file_event(cpu, data, size):
    event = ctypes.cast(data, ctypes.POINTER(FileEvent)).contents
    file_info = {
        "timestamp": datetime.fromtimestamp(event.timestamp / 1000000000).isoformat(),
        "pid": event.pid,
        "comm": event.comm.decode('utf-8', errors='ignore'),
        "event_type": event.event_type.decode('utf-8', errors='ignore'),
        "filename": event.filename.decode('utf-8', errors='ignore').rstrip('\x00'),
        "fd": event.fd,
        "size": event.size,
        "mode": event.mode
    }
    trace_data['file_events'].append(file_info)

def handle_memory_event(cpu, data, size):
    event = ctypes.cast(data, ctypes.POINTER(MemoryEvent)).contents
    memory_info = {
        "timestamp": datetime.fromtimestamp(event.timestamp / 1000000000).isoformat(),
        "pid": event.pid,
        "comm": event.comm.decode('utf-8', errors='ignore'),
        "event_type": event.event_type.decode('utf-8', errors='ignore'),
        "addr": hex(event.addr),
        "size": event.size,
        "prot": event.prot,
        "flags": event.flags
    }
    trace_data['memory_events'].append(memory_info)

def save_trace_data():
    """Save trace data to JSON file"""
    trace_data['end_time'] = datetime.now().isoformat()
    trace_data['total_syscalls'] = len(trace_data['syscalls'])
    trace_data['total_process_events'] = len(trace_data['process_events'])
    trace_data['total_network_events'] = len(trace_data['network_events'])
    trace_data['total_file_events'] = len(trace_data['file_events'])
    trace_data['total_memory_events'] = len(trace_data['memory_events'])
    
    try:
        with open(output_file, 'w') as f:
            json.dump(trace_data, f, indent=2)
        print(f"Trace data saved to: {output_file}")
    except Exception as e:
        print(f"Error saving trace data: {e}")

def cleanup(signum, frame):
    """Cleanup function for signal handling"""
    print(f"\\nStopping tracer for PID {target_pid}...")
    save_trace_data()
    sys.exit(0)

# Main execution
def main():
    print(f"Starting enhanced eBPF tracer for PID {target_pid}")
    print("Press Ctrl+C to stop tracing")
    
    # Set up signal handlers
    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)
    
    # Load BPF program
    try:
        b = BPF(text=ebpf_program)
    except Exception as e:
        print(f"Failed to load BPF program: {e}")
        return 1
    
    # Add target PID to tracking
    tracked_pids = b.get_table("tracked_pids")
    tracked_pids[ctypes.c_uint32(target_pid)] = ctypes.c_ubyte(1)
    
    # Attach perf buffer handlers
    b["syscall_events"].open_perf_buffer(handle_syscall_event)
    b["process_events"].open_perf_buffer(handle_process_event)
    b["network_events"].open_perf_buffer(handle_network_event)
    b["file_events"].open_perf_buffer(handle_file_event)
    b["memory_events"].open_perf_buffer(handle_memory_event)
    
    print(f"eBPF tracer active for PID {target_pid} and children")
    
    try:
        # Main event loop
        while True:
            try:
                b.perf_buffer_poll(timeout=1000)  # 1 second timeout
            except KeyboardInterrupt:
                break
    except Exception as e:
        print(f"Error during tracing: {e}")
    finally:
        cleanup(None, None)

if __name__ == "__main__":
    main()