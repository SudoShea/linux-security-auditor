#!/usr/bin/env python3
"""
==============================================================================
Script Name   : auditor.py
Description   : Non-destructive Linux security & compliance audit tool.
Author        : SudoShea
Version       : 1.0.0
License       : MIT
Compatibility : RHEL / Fedora / CentOS / Debian / Ubuntu
==============================================================================
"""

import os
import re
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

    def log_result(self, category, check_name, status, details):
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

    # --- Audit Module 1: SSH Configuration ---
    def audit_ssh(self):
        sshd_config = "/etc/ssh/sshd_config"
        if not os.path.exists(sshd_config):
            self.log_result("SSH", "Config File Check", "FAIL", "sshd_config not found.")
            return

        checks = {
            "PermitRootLogin": "no",
            "PasswordAuthentication": "no",
            "PermitEmptyPasswords": "no"
        }

        try:
            with open(sshd_config, "r") as f:
                lines = f.readlines()

            for setting, expected in checks.items():
                found = False
                for line in lines:
                    line = line.strip()
                    if line.startswith("#") or not line:
                        continue
                    if line.startswith(setting):
                        found = True
                        val = line.split()[-1].lower()
                        if val == expected:
                            self.log_result("SSH", f"Directive: {setting}", "PASS", f"Configured as '{expected}'.")
                        else:
                            self.log_result("SSH", f"Directive: {setting}", "FAIL", f"Set to '{val}', expected '{expected}'.")
                        break
                if not found:
                    self.log_result("SSH", f"Directive: {setting}", "FAIL", f"Setting not explicitly defined (default risk).")
        except PermissionError:
            self.log_result("SSH", "Config Read", "FAIL", "Permission denied. Run script with sudo.")

    # --- Audit Module 2: Firewall Status ---
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

    # --- Audit Module 3: Active Listening Ports ---
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
                self.log_result("Network", "Insecure Ports Scan", "FAIL", f"Unencrypted services listening: {', '.join(flagged)}")
            else:
                self.log_result("Network", "Insecure Ports Scan", "PASS", "No plaintext management ports listening.")
        except Exception as e:
            self.log_result("Network", "Ports Scan", "FAIL", f"Execution error: {str(e)}")

    # --- Audit Module 4: Password Policy / Shadow File ---
    def audit_shadow(self):
        shadow_file = "/etc/shadow"
        if not os.path.exists(shadow_file):
            self.log_result("Accounts", "Shadow File Check", "FAIL", "/etc/shadow not accessible.")
            return

        try:
            with open(shadow_file, "r") as f:
                lines = f.readlines()

            empty_passwords = []
            for line in lines:
                parts = line.split(":")
                if len(parts) > 1 and parts[1] == "":
                    empty_passwords.append(parts[0])

            if empty_passwords:
                self.log_result("Accounts", "Empty Passwords Check", "FAIL", f"Users with no password set: {', '.join(empty_passwords)}")
            else:
                self.log_result("Accounts", "Empty Passwords Check", "PASS", "No accounts with empty password fields found.")
        except PermissionError:
            self.log_result("Accounts", "Shadow File Access", "FAIL", "Permission denied. Must run as root to read /etc/shadow.")

    # --- Execution & Report Generation ---
    def run_all(self):
        print(f"\n{CYAN}===================================================={RESET}")
        print(f"{CYAN}   Linux Security & Compliance Auditor v1.0         {RESET}")
        print(f"{CYAN}===================================================={RESET}\n")

        self.audit_ssh()
        self.audit_firewall()
        self.audit_ports()
        self.audit_shadow()

        total = self.passed_checks + self.failed_checks
        score = (self.passed_checks / total * 100) if total > 0 else 0

        print(f"\n{CYAN}----------------------------------------------------{RESET}")
        print(f"Audit Summary: {GREEN}{self.passed_checks} PASSED{RESET} | {RED}{self.failed_checks} FAILED{RESET}")
        print(f"Overall Compliance Score: {CYAN}{score:.1f}%{RESET}")
        print(f"{CYAN}----------------------------------------------------{RESET}\n")

        # Save Report to JSON
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

        print(f"[{GREEN}+${RESET}] Full report exported to: {report_file}\n")

if __name__ == "__main__":
    if os.geteuid() != 0:
        print(f"{YELLOW}[!] Warning: Running without root privileges. Some checks (/etc/shadow, firewall) will fail or be restricted.{RESET}\n")
    
    auditor = SecurityAuditor()
    auditor.run_all()
