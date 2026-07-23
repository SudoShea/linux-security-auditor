# Linux Security & Compliance Auditor 🔍

A zero-dependency Python security toolkit that performs non-destructive compliance checks and authentication log parsing on Linux hosts. Generates clean terminal summaries and structured JSON reports.

---

## 🛠️ Included Modules

* **`auditor.py` (v1.1.0):** Non-destructive security compliance scanner evaluating system configurations, firewalls, and active sockets.
* **`ssh_sentinel.py` (v1.0.0):** Active log parser analyzing `/var/log/auth.log` and `/var/log/secure` for SSH brute-force attempts and anomalous targeting.

---

## ⚡ Key Features

* **Zero Dependencies:** Built entirely with native Python standard libraries (`subprocess`, `json`, `os`, `re`, `collections`, `argparse`). No `pip install` required.
* **Non-Destructive & Safe:** Read-only inspection—leaves system state untouched.
* **System Compliance Audit (`auditor.py`):**
  * **SSH Hardening:** Audits `/etc/ssh/sshd_config` for root access, password authentication, and empty passwords.
  * **Firewall Verification:** Checks active status for both `firewalld` (RHEL family) and `ufw` (Debian family).
  * **Network Inspection:** Scans active sockets using `ss` for insecure management ports (`21/FTP`, `23/Telnet`, `80/HTTP`).
  * **Account Audit:** Inspects `/etc/shadow` for accounts with unset passwords.
  * **Automated Reporting:** Calculates an overall compliance score percentage and exports detailed findings to a timestamped `audit_report_<timestamp>.json`.
* **SSH Log Sentinel & Anomaly Detector (`ssh_sentinel.py`):**
  * **Multi-Distro Log Support:** Auto-detects `/var/log/auth.log` (Debian/Ubuntu) or `/var/log/secure` (RHEL/Fedora).
  * **Brute-Force Thresholding:** Groups failed SSH logins by IP address and flags sources exceeding configurable attempt limits.
  * **Invalid User Tracking:** Pinpoints IPs actively probing non-existent or administrative user accounts (`admin`, `root`, `guest`).
  * **Structured JSON Export:** Emits terminal alert trees or structured JSON outputs (`--json`) for SIEM and webhook ingestion.

---

## 🚀 Quick Start

### 1. Clone the repository
```bash
git clone https://github.com/SudoShea/linux-security-auditor.git
cd linux-security-auditor
chmod +x auditor.py ssh_sentinel.py
```
### 2. Run System Audit (auditor.py)
```bash
sudo ./auditor.py
```
### 3. Run SSH Log Sentinel (ssh_sentinel.py)
```bash
# Check for suspicious IPs with 5 or more failed attempts
sudo ./ssh_sentinel.py -t 5

# Export findings to JSON format
sudo ./ssh_sentinel.py -t 5 --json
```
---

## 📊 Example Outputs
### Compliance Audit JSON (audit_report_[timestamp].json)
```json
{
    "timestamp": "2026-07-23T17:15:00.123456",
    "summary": {
        "total_checks": 6,
        "passed": 5,
        "failed": 1,
        "score_percentage": 83.3
    },
    "results": [
        {
            "category": "SSH",
            "check": "Directive: PermitRootLogin",
            "status": "PASS",
            "details": "Configured as 'no'."
        }
    ]
}
```
### SSH Log Sentinel Alert Output
```text
[*] Analyzing /var/log/secure (Threshold: >= 5 failed attempts)...

[+] Scan Complete: 1 suspicious IP(s) detected.
============================================================
🚨 [ALERT] Suspicious IP: 192.168.1.100
   ├─ Failed Attempts : 12
   ├─ Targeted Users  : root, admin, user1
   ├─ Time Range      : Jul 23 21:00:01 -> Jul 23 21:05:30
   └─ Invalid Users   : admin
```
---
## 📄 License
Distributed under the MIT License. See `LICENSE` for details.
