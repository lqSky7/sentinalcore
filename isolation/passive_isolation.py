import os
import sys
import ctypes
import signal
import time
import subprocess
import logging

# === Logging Setup ===
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    datefmt='%H:%M:%S'
)

# === Namespace Flags (from linux/sched.h) ===
CLONE_NEWNS = 0x00020000       # Mount namespace
CLONE_NEWPID = 0x20000000      # PID namespace
CLONE_NEWUTS = 0x04000000      # UTS namespace (hostname)
CLONE_NEWNET = 0x40000000      # Network namespace
CLONE_NEWIPC = 0x08000000      # IPC namespace
CLONE_NEWUSER = 0x10000000     # User namespace

# Load the libc shared library
libc = ctypes.CDLL("libc.so.6")

def unshare(flags):
    """
    Use unshare syscall to isolate this process into new namespaces.
    """
    logging.info("Calling unshare with flags: 0x%x", flags)
    if libc.unshare(flags) != 0:
        logging.error("unshare failed: %s", os.strerror(ctypes.get_errno()))
        sys.exit(1)

def launch_malware():
    """
    Dummy malware simulation. Writes and executes a fake shell script.
    """
    logging.info("Launching malware subprocess")
    malware_path = "/tmp/malware.sh"

    try:
        with open(malware_path, "w") as f:
            f.write("#!/bin/sh\n")
            f.write("echo '[malware] running...'\n")
            f.write("sleep 60\n")
        os.chmod(malware_path, 0o755)

        logging.info("Executing malware: %s", malware_path)
        os.execv(malware_path, [malware_path])
    except Exception as e:
        logging.exception("Failed to launch malware: %s", str(e))
        sys.exit(1)

def parent_monitor(child_pid):
    """
    Monitors the child process running in the sandbox.
    """
    logging.info("Parent monitoring child process (PID: %d)", child_pid)
    try:
        while True:
            pid, status = os.waitpid(child_pid, 0)
            logging.info("Child exited with status: %d", status)
            break
    except KeyboardInterrupt:
        logging.warning("Interrupted. Killing child.")
        os.kill(child_pid, signal.SIGKILL)

def reap_zombies(signum, frame):
    """
    Reap zombie processes triggered by SIGCHLD.
    """
    while True:
        try:
            pid, _ = os.waitpid(-1, os.WNOHANG)
            if pid == 0:
                break
            logging.info("Reaped zombie process: PID %d", pid)
        except ChildProcessError:
            break

# === Main Execution ===
if __name__ == '__main__':
    if os.getpid() != 1:
        logging.info("[*] Starting parent process PID: %d", os.getpid())
        unshare(CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWUTS | CLONE_NEWNET | CLONE_NEWIPC | CLONE_NEWUSER)

        pid = os.fork()
        if pid == 0:
            logging.info("In wrapper child process. Executing new PID namespace.")
            os.execv("/proc/self/exe", ["/proc/self/exe"] + sys.argv)
        else:
            parent_monitor(pid)
    else:
        logging.info("[*] Inside sandbox namespace as PID 1")
        signal.signal(signal.SIGCHLD, reap_zombies)
        launch_malware()

