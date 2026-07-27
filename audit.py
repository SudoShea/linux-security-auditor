#!/usr/bin/env python3
# ==============================================================================
# Script Name   : audit.py
# Description   : Unified CLI entrypoint wrapper for the Linux Security Auditor suite.
# Author        : SudoShea
# Version       : 2.0.0
# License       : MIT
# Compatibility : RHEL / Fedora / CentOS / Debian / Ubuntu
# ==============================================================================

import argparse
import json
import os
import sys
from datetime import datetime

# Import auditor modules from the modules package
try:
    from modules.container import inspect_podman_containers
    from modules.diff import compare_reports
    from modules.ssh import parse_logs
    from modules.system import SecurityAuditor
except ImportError as err:
    print(f"Error importing auditor modules: {err}")
    print("Ensure the 'modules/' directory exists with system.py, container.py, ssh.py, and diff.py.")
    sys.exit(1)

# Terminal Colours
CYAN = '\033[96m'
GREEN = '\033[92m'
RESET = '\033[0m'


def run_system_audit():
    if os.geteuid() != 0:
        print("\033[93m[!] Warning: Running system audit without root privileges. Some checks may fail or be restricted.\033[0m\n")
    auditor = SecurityAuditor()
    auditor.run_all()


def run_container_audit():
    inspect_podman_containers()


def run_ssh_audit(log_path, threshold, since, json_output):
    alerts = parse_logs(log_path, threshold, since)
    if json_output:
        report = {
            'scan_time': datetime.now().isoformat(),
            'threshold': threshold,
            'alerts_found': len(alerts),
            'detections': alerts
        }
        print(json.dumps(report, indent=2))
    else:
        print(f"\n[+] SSH Scan Complete: {len(alerts)} suspicious IP(s) detected.\n" + "=" * 60)
        for ip, data in alerts.items():
            print(f"🚨 [ALERT] Suspicious IP: {ip}")
            print(f"   ├─ Failed Attempts : {data['total_failed_attempts']}")
            print(f"   ├─ Targeted Users  : {', '.join(data['targeted_users'])}")
            print(f"   └─ Invalid Users   : {', '.join(data['attempted_invalid_users']) or 'None'}\n")


def run_diff(baseline, target):
    compare_reports(baseline, target)


def run_all_audits():
    print(f"{CYAN}===================================================={RESET}")
    print(f"{CYAN}   Linux Security Auditor - Full Suite Execution    {RESET}")
    print(f"{CYAN}===================================================={RESET}")

    print("\n--- 1. System & CIS Compliance Audit ---")
    run_system_audit()

    print("\n--- 2. Podman Container Security Audit ---")
    run_container_audit()

    print("\n--- 3. SSH Anomaly & Log Scan ---")
    run_ssh_audit(None, 5, "24 hours ago", False)


def main():
    parser = argparse.ArgumentParser(
        description="Linux Security Auditor Suite (v2.0.0) - Unified CLI Interface",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  ./audit.py system                 # Run system & CIS compliance audit
  ./audit.py container              # Run Podman container security check
  ./audit.py ssh -t 3               # Scan SSH logs for >= 3 failed attempts
  ./audit.py diff report1.json report2.json # Compare two JSON audit reports
  ./audit.py all                    # Run all audits sequentially
"""
    )

    subparsers = parser.add_subparsers(dest="command", help="Auditor command to execute")

    # Subcommand: system
    subparsers.add_parser("system", help="Run OS & CIS compliance security audit")

    # Subcommand: container
    subparsers.add_parser("container", help="Inspect local Podman containers for security risks")

    # Subcommand: ssh
    ssh_parser = subparsers.add_parser("ssh", help="Scan SSH logs / journalctl for brute-force attacks")
    ssh_parser.add_argument("-l", "--log", help="Path to custom auth log file")
    ssh_parser.add_argument("-t", "--threshold", type=int, default=5, help="Failed attempt threshold (default: 5)")
    ssh_parser.add_argument("-s", "--since", default="24 hours ago", help="Timeframe for journalctl query (default: '24 hours ago')")
    ssh_parser.add_argument("--json", action="store_true", help="Output alerts in JSON format")

    # Subcommand: diff
    diff_parser = subparsers.add_parser("diff", help="Compare two JSON audit reports to detect security drift")
    diff_parser.add_argument("baseline", help="Baseline JSON report file")
    diff_parser.add_argument("target", help="Target JSON report file")

    # Subcommand: all
    subparsers.add_parser("all", help="Run system, container, and SSH audits in one pass")

    args = parser.parse_args()

    if args.command == "system":
        run_system_audit()
    elif args.command == "container":
        run_container_audit()
    elif args.command == "ssh":
        run_ssh_audit(args.log, args.threshold, args.since, args.json)
    elif args.command == "diff":
        run_diff(args.baseline, args.target)
    elif args.command == "all":
        run_all_audits()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
