#!/usr/bin/env python3
# ==============================================================================
# Script Name   : container_auditor.py
# Description   : Inspects running Podman/Docker containers for security risks.
# Author        : SudoShea
# Version       : 2.0.0
# License       : MIT
# ==============================================================================

import json
import subprocess
import sys

# Terminal Colours
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
CYAN = '\033[96m'
RESET = '\033[0m'

SENSITIVE_MOUNTS = {'/', '/etc', '/var', '/proc', '/sys', '/boot', '/root'}


def inspect_podman_containers():
    try:
        res = subprocess.run(["podman", "ps", "-a", "--format", "json"], capture_output=True, text=True, check=True)
        containers = json.loads(res.stdout)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print(f"{RED}[!] Error: Could not execute 'podman ps'. Is Podman installed?{RESET}")
        return

    print(f"\n{CYAN}===================================================={RESET}")
    print(f"{CYAN}   Podman Container Security Auditor v2.0.0        {RESET}")
    print(f"{CYAN}===================================================={RESET}\n")

    if not containers:
        print(f"{YELLOW}[i] No running or stopped Podman containers found.{RESET}\n")
        return

    for c in containers:
        name = c.get("Names", ["unknown"])[0] if isinstance(c.get("Names"), list) else c.get("Names", "unknown")
        c_id = c.get("Id", "")[:12]

        # Detailed container inspection
        insp_res = subprocess.run(["podman", "inspect", c_id], capture_output=True, text=True)
        if insp_res.returncode != 0:
            continue

        details = json.loads(insp_res.stdout)[0]
        config = details.get("Config", {})
        host_config = details.get("HostConfig", {})
        mounts = details.get("Mounts", [])

        issues = []

        # 1. User check (Root execution)
        user = config.get("User", "")
        if not user or user == "0" or user == "root":
            issues.append("Runs as root user (UID 0)")

        # 2. Privileged flag
        if host_config.get("Privileged", False):
            issues.append("Privileged mode enabled (--privileged)")

        # 3. Host Network Mode
        if host_config.get("NetworkMode", "") == "host":
            issues.append("Bound to host network (--net=host)")

        # 4. Sensitive Volume Mounts
        for m in mounts:
            source = m.get("Source", "")
            if any(source == p or source.startswith(p + "/") for p in SENSITIVE_MOUNTS):
                issues.append(f"Sensitive host mount detected: {source} -> {m.get('Destination')}")

        # Summary output
        if issues:
            print(f"[{RED}FAIL{RESET}] Container: {CYAN}{name}{RESET} ({c_id})")
            for issue in issues:
                print(f"       {YELLOW}↳ {issue}{RESET}")
        else:
            print(f"[{GREEN}PASS{RESET}] Container: {CYAN}{name}{RESET} ({c_id}) - No high-risk configurations found")

    print()


if __name__ == "__main__":
    inspect_podman_containers()
