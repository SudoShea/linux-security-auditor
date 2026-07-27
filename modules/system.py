#!/usr/bin/env python3
# ==============================================================================
# Script Name   : auditor.py
# Description   : Non-destructive Linux security & CIS compliance audit tool.
# Author        : SudoShea
# Version       : 2.0.0
# License       : MIT
# Compatibility : RHEL / Fedora / CentOS / Debian / Ubuntu
# ==============================================================================

import os
import sys
import json
import subprocess
from datetime import datetime

# Terminal Colour Codes
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
CYAN = '\033[96m'
RESET = '\033[0m'


class SecurityAuditor:
    def __init__(self):
        self.results = []
        self.passed_checks = 0
        self.failed_checks = 0

    def log_result(self, category: str, check_name: str, status: str, details: str):
        if status == "PASS":
            self.passed_checks += 1
            print(f"[{GREEN}PASS{RESET}] {category} -> {check_name}")
        else:
            self.failed_checks += 1
            print(f"[{RED}FAIL{RESET}] {category} -> {check_name}")
            print(f"       {YELLOW}↳ Details: {details}{RESET}")

        self.results.append({
            "category": category,
            "check": check_name,
            "status": status,
            "details": details
        })

    # --- Module 1: Live SSH Daemon Evaluation (via sshd -T) ---
    def audit_ssh(self):
        try:
            res = subprocess.run(["sshd", "-T"], capture_output=True, text=True, check=True)
            config_dump = res.stdout.lower()

            expected_rules = {
                "permitrootlogin": "no",
                "passwordauthentication": "no",
                "permitemptypasswords": "no",
                "x11forwarding": "no"
            }

            for directive, expected in expected_rules.items():
                match_found = False
                for line in config_dump.splitlines():
                    parts = line.split()
                    if len(parts) >= 2 and parts[0] == directive:
                        match_found = True
                        actual = parts[1]
                        if actual == expected:
                            self.log_result("SSH", f"Directive: {directive}", "PASS", f"Evaluated runtime as '{expected}'")
                        else:
                            self.log_result("SSH", f"Directive: {directive}", "FAIL", f"Set to '{actual}', expected '{expected}'")
                        break

                if not match_found:
                    self.log_result("SSH", f"Directive: {directive}", "FAIL", "Directive not found in evaluated sshd config")

        except (subprocess.CalledProcessError, FileNotFoundError):
            self.log_result("SSH", "Runtime Config Audit", "FAIL", "Failed to execute 'sshd -T'. Ensure OpenSSH server is installed and run with sudo.")

    # --- Module 2: Active Firewall Verification ---
    def audit_firewall(self):
        firewall_active = False
        details = "No active firewall service detected."

        # Check Firewalld (RHEL family)
        try:
            res = subprocess.run(["systemctl", "is-active", "firewalld"], capture_output=True, text=True)
            if res.stdout.strip() == "active":
                firewall_active = True
                details = "Firewalld is active."
        except FileNotFoundError:
            pass

        # Check UFW (Debian family)
        if not firewall_active:
            try:
                res = subprocess.run(["ufw", "status"], capture_output=True, text=True)
                if "Status: active" in res.stdout:
                    firewall_active = True
                    details = "UFW is active."
            except FileNotFoundError:
                pass

        if firewall_active:
            self.log_result("Firewall", "Active Status Check", "PASS", details)
        else:
            self.log_result("Firewall", "Active Status Check", "FAIL", details)

    # --- Module 3: Network Stack & Plaintext Port Scan ---
    def audit_ports(self):
        try:
            res = subprocess.run(["ss", "-tuln"], capture_output=True, text=True)
            listening_lines = [line for line in res.stdout.splitlines() if "LISTEN" in line]

            insecure_ports = {'21': 'FTP', '23': 'Telnet', '80': 'HTTP'}
            flagged = []

            for line in listening_lines:
                for port, service in insecure_ports.items():
                    if f":{port} " in line or f":{port}\n" in line:
                        flagged.append(f"{service} (Port {port})")

            if flagged:
                self.log_result("Network", "Insecure Ports Scan", "FAIL", f"Unencrypted management services listening: {', '.join(set(flagged))}")
            else:
                self.log_result("Network", "Insecure Ports Scan", "PASS", "No plaintext management ports listening.")
        except Exception as e:
            self.log_result("Network", "Ports Scan", "FAIL", f"Execution error: {str(e)}")

    # --- Module 4: Kernel Parameter Audit (sysctl) ---
    def audit_sysctl(self):
        sysctl_checks = {
            "net.ipv4.ip_forward": "0",
            "net.ipv4.conf.all.accept_redirects": "0",
            "net.ipv4.tcp_syncookies": "1"
        }

        for param, expected in sysctl_checks.items():
            try:
                res = subprocess.run(["sysctl", "-n", param], capture_output=True, text=True)
                actual = res.stdout.strip()
                if actual == expected:
                    self.log_result("Kernel", f"Sysctl: {param}", "PASS", f"Configured as '{expected}'")
                else:
                    self.log_result("Kernel", f"Sysctl: {param}", "FAIL", f"Current value is '{actual}', expected '{expected}'")
            except Exception:
                self.log_result("Kernel", f"Sysctl: {param}", "FAIL", f"Could not read kernel parameter {param}")

    # --- Module 5: Account Security & Shadow Permissions ---
    def audit_accounts(self):
        shadow_file = "/etc/shadow"
        if not os.path.exists(shadow_file):
            self.log_result("Accounts", "Shadow File Check", "FAIL", "/etc/shadow not found.")
            return

        # Permissions check (should be 0000 or 0600 or 0640)
        st_mode = oct(os.stat(shadow_file).st_mode & 0o777)
        if st_mode in ['0o0', '0o600', '0o640', '0000', '0600', '0640']:
            self.log_result("Accounts", "Shadow File Permissions", "PASS", f"Mode permissions set to {st_mode}")
        else:
            self.log_result("Accounts", "Shadow File Permissions", "FAIL", f"Permissions are overly permissive ({st_mode})")

        try:
            with open(shadow_file, "r") as f:
                lines = f.readlines()

            empty_passwords = [line.split(":")[0] for line in lines if len(line.split(":")) > 1 and line.split(":")[1] == ""]

            if empty_passwords:
                self.log_result("Accounts", "Empty Passwords Check", "FAIL", f"Users with no password set: {', '.join(empty_passwords)}")
            else:
                self.log_result("Accounts", "Empty Passwords Check", "PASS", "No accounts with empty password fields found.")
        except PermissionError:
            self.log_result("Accounts", "Shadow File Access", "FAIL", "Permission denied. Run with sudo to inspect /etc/shadow.")

    # --- Module 6: Audit Logging (auditd) ---
    def audit_logging(self):
        try:
            res = subprocess.run(["systemctl", "is-active", "auditd"], capture_output=True, text=True)
            if res.stdout.strip() == "active":
                self.log_result("Logging", "Auditd Service Check", "PASS", "Audit daemon is active and collecting logs.")
            else:
                self.log_result("Logging", "Auditd Service Check", "FAIL", "Audit daemon (auditd) is inactive or not installed.")
        except FileNotFoundError:
            self.log_result("Logging", "Auditd Service Check", "FAIL", "systemctl not found.")

    def run_all(self):
        print(f"\n{CYAN}===================================================={RESET}")
        print(f"{CYAN}   Linux Security & Compliance Auditor v2.0.0       {RESET}")
        print(f"{CYAN}===================================================={RESET}\n")

        self.audit_ssh()
        self.audit_firewall()
        self.audit_ports()
        self.audit_sysctl()
        self.audit_accounts()
        self.audit_logging()

        total = self.passed_checks + self.failed_checks
        score = (self.passed_checks / total * 100) if total > 0 else 0

        print(f"\n{CYAN}----------------------------------------------------{RESET}")
        print(f"Audit Summary: {GREEN}{self.passed_checks} PASSED{RESET} | {RED}{self.failed_checks} FAILED{RESET}")
        print(f"Overall Compliance Score: {CYAN}{score:.1f}%{RESET}")
        print(f"{CYAN}----------------------------------------------------{RESET}\n")

        report_file = f"audit_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        report_data = {
            "timestamp": datetime.now().isoformat(),
            "summary": {
                "total_checks": total,
                "passed": self.passed_checks,
                "failed": self.failed_checks,
                "score_percentage": round(score, 1)
            },
            "results": self.results
        }

        with open(report_file, "w") as f:
            json.dump(report_data, f, indent=4)

        print(f"[{GREEN}+{RESET}] Full report exported to: {report_file}\n")


if __name__ == "__main__":
    if os.geteuid() != 0:
        print(f"{YELLOW}[!] Warning: Running without root privileges. Some checks will fail or be restricted.{RESET}\n")

    auditor = SecurityAuditor()
    auditor.run_all()
