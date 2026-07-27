#!/usr/bin/env python3
# ==============================================================================
# Script Name   : ssh_sentinel.py
# Description   : Parse SSH logs & systemd journal for brute-force attacks.
# Author        : SudoShea
# Version       : 2.0.0
# License       : MIT
# Compatibility : RHEL / Fedora / CentOS / Debian / Ubuntu
# ==============================================================================

import re
import os
import sys
import json
import argparse
import subprocess
from datetime import datetime
from collections import defaultdict

FAILED_PASSWORD_RE = re.compile(
    r'(?:Failed password for\s+(?:invalid user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3}))'
)

INVALID_USER_RE = re.compile(
    r'(?:Invalid user\s+(?P<user>\S+)\s+from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3}))'
)


def get_log_stream(custom_log_path=None, since=None):
    """Yields log lines from custom file, /var/log auth files, or journalctl."""
    # 1. User specified explicit log path
    if custom_log_path and os.path.exists(custom_log_path):
        with open(custom_log_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                yield line
        return

    # 2. Check traditional log files
    for path in ['/var/log/auth.log', '/var/log/secure']:
        if os.path.exists(path) and os.access(path, os.R_OK):
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    yield line
            return

    # 3. Fall back to journalctl for systemd-only hosts
    cmd = ["journalctl", "-u", "sshd", "-u", "ssh", "--no-pager"]
    if since:
        cmd.extend(["--since", since])

    try:
        res = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        for line in res.stdout:
            yield line
    except FileNotFoundError:
        print("[!] Error: No log files found and journalctl is unavailable.", file=sys.stderr)
        sys.exit(1)


def parse_logs(custom_log_path, threshold, since):
    """Parse authentication logs and group failed attempts by IP address."""
    failed_attempts = defaultdict(list)
    invalid_user_targets = defaultdict(set)

    for line in get_log_stream(custom_log_path, since):
        match = FAILED_PASSWORD_RE.search(line)
        if match:
            data = match.groupdict()
            failed_attempts[data['ip']].append({
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'user': data['user']
            })
            continue

        inv_match = INVALID_USER_RE.search(line)
        if inv_match:
            inv_data = inv_match.groupdict()
            invalid_user_targets[inv_data['ip']].add(inv_data['user'])

    flagged_ips = {}
    for ip, attempts in failed_attempts.items():
        if len(attempts) >= threshold:
            flagged_ips[ip] = {
                'total_failed_attempts': len(attempts),
                'targeted_users': list(set(a['user'] for a in attempts)),
                'attempted_invalid_users': list(invalid_user_targets.get(ip, []))
            }

    return flagged_ips


def main():
    parser = argparse.ArgumentParser(description="SSH Log Parser & Anomaly Detector (v2.0.0)")
    parser.add_argument("-l", "--log", help="Path to auth log file (default: auto-detect / journalctl)")
    parser.add_argument("-t", "--threshold", type=int, default=5, help="Failed attempt threshold (default: 5)")
    parser.add_argument("-s", "--since", default="24 hours ago", help="Time frame for journalctl query (default: '24 hours ago')")
    parser.add_argument("--json", action="store_true", help="Output report in JSON format")
    args = parser.parse_args()

    print(f"[*] Analyzing SSH logs (Threshold: >= {args.threshold} failed attempts)...", file=sys.stderr)
    alerts = parse_logs(args.log, args.threshold, args.since)

    if args.json:
        report = {
            'scan_time': datetime.now().isoformat(),
            'threshold': args.threshold,
            'alerts_found': len(alerts),
            'detections': alerts
        }
        print(json.dumps(report, indent=2))
    else:
        print(f"\n[+] Scan Complete: {len(alerts)} suspicious IP(s) detected.\n" + "=" * 60)
        for ip, data in alerts.items():
            print(f"🚨 [ALERT] Suspicious IP: {ip}")
            print(f"   ├─ Failed Attempts : {data['total_failed_attempts']}")
            print(f"   ├─ Targeted Users  : {', '.join(data['targeted_users'])}")
            print(f"   └─ Invalid Users   : {', '.join(data['attempted_invalid_users']) or 'None'}\n")


if __name__ == "__main__":
    main()
