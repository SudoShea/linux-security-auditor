#!/usr/bin/env python3
# ==============================================================================
# Script Name   : report_diff.py
# Description   : Compares two auditor.py JSON reports to detect security drift.
# Author        : SudoShea
# Version       : 2.0.0
# License       : MIT
# ==============================================================================

import json
import sys

GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
CYAN = '\033[96m'
RESET = '\033[0m'


def compare_reports(old_path, new_path):
    with open(old_path, "r") as f:
        old_data = json.load(f)
    with open(new_path, "r") as f:
        new_data = json.load(f)

    old_map = {f"{r['category']}:{r['check']}": r for r in old_data.get("results", [])}
    new_map = {f"{r['category']}:{r['check']}": r for r in new_data.get("results", [])}

    print(f"\n{CYAN}===================================================={RESET}")
    print(f"{CYAN}   Security Compliance Drift Analysis               {RESET}")
    print(f"{CYAN}===================================================={RESET}")
    print(f" Baseline : {old_path} ({old_data['summary']['score_percentage']}%)")
    print(f" Target   : {new_path} ({new_data['summary']['score_percentage']}%)")
    print(f"{CYAN}----------------------------------------------------{RESET}\n")

    regressions = []
    improvements = []

    for key, new_item in new_map.items():
        if key in old_map:
            old_status = old_map[key]["status"]
            new_status = new_item["status"]

            if old_status == "PASS" and new_status == "FAIL":
                regressions.append(f"🚨 [REGRESSION] {new_item['category']} -> {new_item['check']}\n   ↳ {new_item['details']}")
            elif old_status == "FAIL" and new_status == "PASS":
                improvements.append(f"✅ [RESOLVED] {new_item['category']} -> {new_item['check']}")

    if regressions:
        print(f"{RED}Security Regressions Detected ({len(regressions)}):{RESET}")
        for r in regressions:
            print(f"  {r}")
        print()

    if improvements:
        print(f"{GREEN}Resolved Security Issues ({len(improvements)}):{RESET}")
        for i in improvements:
            print(f"  {i}")
        print()

    if not regressions and not improvements:
        print(f"{GREEN}[+] Zero security drift detected between reports.{RESET}\n")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 report_diff.py <baseline_report.json> <target_report.json>")
        sys.exit(1)

    compare_reports(sys.argv[1], sys.argv[2])
