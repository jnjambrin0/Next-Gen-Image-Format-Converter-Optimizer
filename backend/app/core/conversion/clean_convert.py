#!/usr/bin/env python3
"""Clean conversion wrapper to ensure no logging pollution."""

import os
import subprocess
import sys

# Get the sandboxed_convert.py path
script_dir = os.path.dirname(os.path.abspath(__file__))
convert_script = os.path.join(script_dir, "sandboxed_convert.py")

# Create a completely clean environment
clean_env = {
    "PATH": "/usr/bin:/bin",
    "PYTHONPATH": "",
}

# Run the conversion script with clean environment and no inherited file descriptors
proc = subprocess.Popen(
    [sys.executable, convert_script] + sys.argv[1:],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.DEVNULL,  # Discard all stderr
    env=clean_env,
    close_fds=True,  # Don't inherit any file descriptors
)

# Pass stdin to the subprocess
stdin_data = sys.stdin.buffer.read()
stdout_data, _ = proc.communicate(input=stdin_data)

# Output only the stdout from the subprocess
sys.stdout.buffer.write(stdout_data)
sys.exit(proc.returncode)
