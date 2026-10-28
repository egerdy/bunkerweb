#!/usr/bin/env python3
import os
import subprocess

subprocess.run(["python3", "/opt/bw-lkg/guard.py", "boot"], check=True)
os.environ["KEEP_CONFIG_ON_RESTART"] = "yes"
os.execv("/usr/share/bunkerweb/entrypoint.sh", ["/usr/share/bunkerweb/entrypoint.sh"])
