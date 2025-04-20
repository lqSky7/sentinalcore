#!/usr/bin/env python3

import os
import sys
import ctypes
import signal
import subprocess
import logging

# ─── Logging Configuration ──────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    datefmt='%H:%M:%S'
)

# ─── Clone Flags for Namespace Isolation ────────────────────────────────────────
CLONE_NEWNS = 0x00020000       # Mount namespace
CLONE_NEWPID = 0x20000000      # PID namespace
CLONE_NEWUTS = 0x04000000      # UTS namespace (hostname)
CLONE_NEWNET = 0x40000000      # Network namespace
CLONE_NEWIPC = 0x08000000      # IPC namespace
CLONE_NEWUSER = 0x10000000     # User namespace

# ─── Unshare Wrapper ────────────────────────────────────────────────────────────
libc = ctypes.CDLL("libc.so.6")

def unshare(flags):
    logging.info("[*] Calling unshare with flags: 0x%x", flags)
    if libc.unshare(flags) != 0:
        logging.error("[!] unshare failed: %s", os.strerror(ctypes.get_errno()))
        sys.exit(1)

# ─── Malware Launcher ───────────────────────────────────────────────────────────
def launch_malware(malware_path="/tmp/malware_sample"):
    logging.info("[*] Preparing to launch: %s", malware_path)

    if not os.path.exists(malware_path):
        logging.error("[!] Malware file does not exist: %s", malware_path)
        sys.exit(1)

    try:
        file_output = subprocess.check_output(['file', '--mime-type', malware_path]).decode()
        mime_type = file_output.split(':')[1].strip()
        logging.info("[*] Detected MIME type: %s", mime_type)
    except Exception as e:
        logging.warning("[!] Failed to detect MIME type: %s", str(e))
        mime_type = None

    try:
        # ─── Handle Common Executables ─────────────────────────────
        if mime_type in ['text/x-python', 'text/x-script.python']:
            logging.info("[*] Launching Python script")
            os.execv('/usr/bin/python3', ['python3', malware_path])

        elif mime_type in ['text/x-shellscript', 'application/x-shellscript']:
            logging.info("[*] Launching shell script")
            os.execv('/bin/bash', ['bash', malware_path])

        elif mime_type in ['application/x-executable', 'application/x-pie-executable']:
            logging.info("[*] Launching ELF binary")
            os.execv(malware_path, [malware_path])

        elif mime_type == 'application/x-dosexec':
            logging.warning("[*] Windows EXE detected. Attempting Wine (if available)")
            os.execv('/usr/bin/wine', ['wine', malware_path])

        # ─── Placeholder: PDFs ─────────────────────────────────────
        elif mime_type == 'application/pdf':
            logging.info("[*] PDF detected — placeholder for sandboxed reader")

        # ─── Placeholder: Office Files ─────────────────────────────
        elif mime_type in ['application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                           'application/msword']:
            logging.info("[*] Word document detected — placeholder for sandboxed analysis")

        elif mime_type in ['application/vnd.ms-excel',
                           'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet']:
            logging.info("[*] Excel document detected — placeholder for sandboxed analysis")

        # ─── Placeholder: Archives ─────────────────────────────────
        elif mime_type in ['application/zip', 'application/x-tar', 'application/x-gzip']:
            logging.info("[*] Archive detected — placeholder for decompression sandbox")

        # ─── Placeholder: Images ───────────────────────────────────
        elif mime_type.startswith("image/"):
            logging.info("[*] Image file detected — placeholder for stego analysis")

        # ─── Unknown File ──────────────────────────────────────────
        else:
            with open(malware_path, 'rb') as f:
                first_line = f.readline().decode(errors='ignore').strip()
                if first_line.startswith("#!"):
                    interpreter = first_line[2:].strip().split(" ")
                    logging.info("[*] Using shebang interpreter: %s", interpreter)
                    os.execv(interpreter[0], interpreter + [malware_path])
                else:
                    logging.warning("[!] Unknown format. Defaulting to Bash.")
                    os.execv('/bin/bash', ['bash', malware_path])

    except Exception as e:
        logging.exception("[!] Failed to launch malware: %s", str(e))
        sys.exit(1)

# ─── Parent Process Monitoring Child PID ────────────────────────────────────────
def parent_monitor(child_pid):
    logging.info("[*] Parent watching child PID: %d", child_pid)
    try:
        while True:
            pid, status = os.waitpid(child_pid, 0)
            logging.info("[*] Child exited with status: %d", status)
            break
    except KeyboardInterrupt:
        logging.warning("[!] Ctrl+C detected. Killing child.")
        os.kill(child_pid, signal.SIGKILL)

# ─── Main ───────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    if os.getpid() != 1:
        logging.info("[*] Parent process starting isolation (PID: %d)", os.getpid())
        unshare(CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWUTS | CLONE_NEWNET | CLONE_NEWIPC)

        pid = os.fork()
        if pid == 0:
            logging.info("[*] Wrapper process (child). Re-execing to enter PID namespace.")
            script_path = os.path.realpath(sys.argv[0])
            os.execv(script_path, [script_path] + sys.argv[1:])

        else:
            parent_monitor(pid)

    else:
        logging.info("[*] Now PID 1 inside isolated namespace")

        def reap_zombies(signum, frame):
            while True:
                try:
                    pid, _ = os.waitpid(-1, os.WNOHANG)
                    if pid == 0:
                        break
                    logging.info("[*] Reaped zombie: PID %d", pid)
                except ChildProcessError:
                    break

        signal.signal(signal.SIGCHLD, reap_zombies)
 # ─── Start eBPF Tracer ────────────────────────────────────────
        tracer = subprocess.Popen(['python3', 'ebpf_tracer_packet.py'])
        

        try:
            launch_malware("/home/jinsakai/wow/sentinalcore/testing/test_payload_shell")
        finally:
            logging.info("[*] Shutting down eBPF tracer")
            tracer.terminate()
            tracer.wait()
