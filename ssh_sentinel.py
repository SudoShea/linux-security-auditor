#!/usr/bin/env python3
"""
==============================================================================
Script Name   : ssh_sentinel.py
Description   : Parse Linux auth logs for brute-force SSH attacks & anomalies.
Author        : SudoShea
Version       : 1.0.0
License       : MIT
Compatibility : RHEL / Fedora / CentOS / Debian / Ubuntu
==============================================================================
"""

import re
import os
import sys
import json
import argparse
from datetime import datetime
from collections import defaultdict

# Regex patterns for standard Linux syslog / auth format
# Example: Jul 23 21:14:02 server sshd[1234]: Failed password for invalid user admin from 192.168.1.50 port 49152 ssh2
FAILED_PASSWORD_RE = re.compile(
    r'(?P<timestamp>^[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}).*sshd\[\d+\]:\s+Failed password for\s+(?:invalid user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})'
)

INVALID_USER_RE = re.compile(
    r'(?P<timestamp>^[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}).*sshd\[\d+\]:\s+Invalid user\s+(?P<user>\S+)\s+from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})'
)

def find_auth_log():
    """Detect default log file based on OS distribution."""
    possible_logs = ['/var/log/auth.log', '/var/log/secure']
    for log_path in possible_logs:
        if os.path.exists(log_path) and os.access(log_path, os.R_OK):
            return log_path
    return None

def parse_logs(log_path, threshold):
    """Parse authentication logs and group failed attempts by IP address."""
    failed_attempts = defaultdict(list)
    invalid_user_targets = defaultdict(set)

    try:
        with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                match = FAILED_PASSWORD_RE.search(line)
                if match:
                    data = match.groupdict()
                    failed_attempts[data['ip']].append({
                        'timestamp': data['timestamp'],
                        'user': data['user']
                    })
                    continue

                inv_match = INVALID_USER_RE.search(line)
                if inv_match:
                    inv_data = inv_match.groupdict()
                    invalid_user_targets[inv_data['ip']].add(inv_data['user'])

    except PermissionError:
        print(f"[!] Error: Read permission denied for {log_path}. Try running with sudo.", file=sys.stderr)
        sys.exit(1)

    # Filter IPs exceeding threshold
    flagged_ips = {}
    for ip, attempts in failed_attempts.items():
        if len(attempts) >= threshold:
            flagged_ips[ip] = {
                'total_failed_attempts': len(attempts),
                'targeted_users': list(set(a['user'] for a in attempts)),
                'attempted_invalid_users': list(invalid_user_targets.get(ip, [])),
                'first_seen': attempts[0]['timestamp'],
                'last_seen': attempts[-1]['timestamp']
            }

    return flagged_ips

def main():
    parser = argparse.ArgumentParser(description="SSH Log Parser & Anomaly Detector")
    parser.add_argument("-l", "--log", help="Path to auth log file (default: auto-detect)")
    parser.add_argument("-t", "--threshold", type=int, default=5, help="Failed attempt threshold (default: 5)")
    parser.add_argument("--json", action="store_true", help="Output report in JSON format")
    args = parser.parse_args()

    log_path = args.log or find_auth_log()
    if not log_path:
        print("[!] Error: No readable auth log found at /var/log/auth.log or /var/log/secure.", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Analyzing {log_path} (Threshold: >= {args.threshold} failed attempts)...", file=sys.stderr)
    alerts = parse_logs(log_path, args.threshold)

    if args.json:
        report = {
            'scan_time': datetime.now().isoformat(),
            'log_source': log_path,
            'threshold': args.threshold,
            'alerts_found': len(alerts),
            'detections': alerts
        }
        print(json.dumps(report, indent=2))
    else:
        print(f"\n[+] Scan Complete: {len(alerts)} suspicious IP(s) detected.\n" + "="*60)
        for ip, data in alerts.items():
            print(f"🚨 [ALERT] Suspicious IP: {ip}")
            print(f"   ├─ Failed Attempts : {data['total_failed_attempts']}")
            print(f"   ├─ Targeted Users  : {', '.join(data['targeted_users'])}")
            print(f"   ├─ Time Range      : {data['first_seen']} -> {data['last_seen']}")
            print(f"   └─ Invalid Users   : {', '.join(data['attempted_invalid_users']) or 'None'}\n")

if __name__ == "__main__":
    main()
