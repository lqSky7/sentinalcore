# # AppArmor.py
# import os
# import subprocess
# import logging
# import hashlib

# class AppArmorManager:
#     def __init__(self, profile_dir='/etc/apparmor.d/', log_enabled=True):
#         self.profile_dir = profile_dir
#         os.makedirs(profile_dir, exist_ok=True)
#         self.logger = logging.getLogger('AppArmorManager')
#         if log_enabled:
#             logging.basicConfig(level=logging.INFO)

#     def is_apparmor_enabled(self):
#         try:
#             output = subprocess.check_output(['aa-status'], stderr=subprocess.STDOUT).decode()
#             return 'apparmor module is loaded' in output
#         except subprocess.CalledProcessError:
#             return False

#     def _sanitize_name(self, path):
#         """Create a unique name from the executable path."""
#         base = os.path.basename(path)
#         digest = hashlib.sha1(path.encode()).hexdigest()[:8]
#         return f"{base}_{digest}"

#     def generate_and_apply_profile(self, executable_path):
#         """Generate a restrictive AppArmor profile and enforce it."""
#         if not os.path.exists(executable_path):
#             self.logger.error(f"Executable not found: {executable_path}")
#             return

#         profile_name = self._sanitize_name(executable_path)
#         profile_path = os.path.join(self.profile_dir, profile_name)

#         profile = f"""
# #include <tunables/global>

# /{executable_path} {{
#   #include <abstractions/base>
#   {executable_path} rix,
#   /tmp/** rw,
#   /dev/null rw,
#   capability net_bind_service,
#   deny network,
# }}
# """

#         with open(profile_path, 'w') as f:
#             f.write(profile)
#         self.logger.info(f"Profile written to {profile_path}")

#         try:
#             subprocess.run(['apparmor_parser', '-r', profile_path], check=True)
#             subprocess.run(['aa-enforce', profile_path], check=True)
#             self.logger.info(f"Profile enforced for {executable_path}")
#         except subprocess.CalledProcessError as e:
#             self.logger.error(f"Failed to load/enforce profile: {e}")

# # Example usage
# if __name__ == "__main__":
#     import sys
#     if len(sys.argv) != 2:
#         print("Usage: python3 AppArmor.py /path/to/executable")
#         exit(1)

#     path_to_exec = sys.argv[1]
#     aa = AppArmorManager()
#     if aa.is_apparmor_enabled():
#         aa.generate_and_apply_profile(path_to_exec)
#     else:
#         print("AppArmor is not enabled on this system.")


import os
import subprocess
import logging
import hashlib
import seccomp

class IsolationSandbox:
    def __init__(self, profile_dir='/etc/apparmor.d/', log_enabled=True):
        self.profile_dir = profile_dir
        os.makedirs(profile_dir, exist_ok=True)
        self.logger = logging.getLogger('IsolationSandbox')
        if log_enabled:
            logging.basicConfig(level=logging.INFO)

    def is_apparmor_enabled(self):
        try:
            output = subprocess.check_output(['aa-status'], stderr=subprocess.STDOUT).decode()
            return 'apparmor module is loaded' in output
        except subprocess.CalledProcessError:
            return False

    def _sanitize_name(self, path):
        base = os.path.basename(path)
        digest = hashlib.sha1(path.encode()).hexdigest()[:8]
        return f"{base}_{digest}"

    def generate_and_apply_profile(self, executable_path):
        profile_name = self._sanitize_name(executable_path)
        profile_path = os.path.join(self.profile_dir, profile_name)

        profile = f"""
#include <tunables/global>

/{executable_path} {{
  #include <abstractions/base>
  /{executable_path} rix,
  /tmp/** rw,
  /dev/null rw,
  deny network,
}}
"""

        with open(profile_path, 'w') as f:
            f.write(profile)
        self.logger.info(f"AppArmor profile written to {profile_path}")

        try:
            subprocess.run(['apparmor_parser', '-r', profile_path], check=True)
            subprocess.run(['aa-enforce', profile_path], check=True)
            self.logger.info(f"AppArmor enforced for {executable_path}")
        except subprocess.CalledProcessError as e:
            self.logger.error(f"AppArmor enforcement failed: {e}")

    def run_with_seccomp(self, executable_path, args=[]):
        self.logger.info("Applying seccomp filter...")
        filt = seccomp.SyscallFilter(defaction=seccomp.SCMP_ACT_KILL)

        allowed_syscalls = [
            "read", "write", "exit", "exit_group", "rt_sigreturn",
            "open", "close", "fstat", "mmap", "mprotect", "munmap",
            "brk", "access", "execve", "arch_prctl", "set_tid_address",
            "set_robust_list", "prlimit64", "getpid", "getuid", "geteuid"
        ]

        for name in allowed_syscalls:
            try:
                filt.add_rule(seccomp.SCMP_ACT_ALLOW, name)
            except Exception as e:
                self.logger.warning(f"Could not allow syscall {name}: {e}")

        filt.load()
        self.logger.info(f"Launching: {executable_path}")
        os.execv(executable_path, [executable_path] + args)

    def isolate_and_run(self, executable_path, args=[]):
        if not os.path.exists(executable_path):
            self.logger.error(f"Executable not found: {executable_path}")
            return

        if self.is_apparmor_enabled():
            self.generate_and_apply_profile(executable_path)
        else:
            self.logger.warning("AppArmor is not enabled.")

        # Run with seccomp
        self.run_with_seccomp(executable_path, args)

# Example CLI usage
if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python3 IsolationSandbox.py /path/to/executable [args...]")
        exit(1)

    sandbox = IsolationSandbox()
    sandbox.isolate_and_run(sys.argv[1], sys.argv[2:])
