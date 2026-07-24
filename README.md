# Linux Security & Compliance Auditor 🔍

A zero-dependency Python security toolkit that performs non-destructive compliance checks and authentication log parsing on Linux hosts. Generates clean terminal summaries and structured JSON reports.

---

## 🛠️ Included Modules

* **`auditor.py` (v1.1.1):** Non-destructive security compliance scanner evaluating system configurations, firewalls, and active sockets.
* **`ssh_sentinel.py` (v1.1.1):** Active log parser analyzing `/var/log/auth.log` and `/var/log/secure` for SSH brute-force attempts and anomalous targeting.

![Python Linting](https://github.com/SudoShea/linux-security-auditor/actions/workflows/lint.yml/badge.svg)

A zero-dependency Python CLI tool that performs non-destructive security auditing and compliance checks on Linux hosts. Generates terminal summaries and structured JSON reports.

---

## ⚡ Key Features

* **Zero Dependencies:** Built entirely with native Python standard libraries (`subprocess`, `json`, `os`, `re`). No `pip install` required.
* **Non-Destructive:** Read-only inspection—leaves system state untouched.
* **Audit Modules (`auditor.py`):**
  * **SSH Hardening:** Audits `/etc/ssh/sshd_config` for root access, password authentication, and empty passwords.
  * **Firewall Verification:** Checks active status for both `firewalld` (RHEL family) and `ufw` (Debian family).
  * **Network Inspection:** Scans active sockets using `ss` for insecure management ports (`21/FTP`, `23/Telnet`, `80/HTTP`).
  * **Account Audit:** Inspects `/etc/shadow` for accounts with unset passwords.
* **Real-Time SSH Sentinel (`ssh_sentinel.py`):** Monitors authentication logs in real-time to detect brute-force attempts and automatically ban offending IPs via firewall rules.
* **Automated Reporting:** Calculates an overall compliance score percentage and exports detailed findings to a timestamped `audit_report_<timestamp>.json`.

---

## 🚀 Quick Start

### 1. Clone the repository
```bash
git clone https://github.com/SudoShea/linux-security-auditor.git
cd linux-security-auditor
```
### 2. Make scripts executable
```bash
chmod +x auditor.py ssh_sentinel.py
```
### 3. Run System Security Audit
Execute a non-destructive compliance scan:
```bash
sudo ./auditor.py
```
### 4. Run SSH Sentinel (Real-Time Protection)
Monitor auth logs for brute-force attacks and automatically apply firewall bans:
```bash
# Run interactive sentinel monitoring
sudo ./ssh_sentinel.py

# Run with custom failure threshold (e.g., ban after 3 failed attempts)
sudo ./ssh_sentinel.py --max-retries 3
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
=======
## 📄 License
Distributed under the MIT License. See `LICENSE` for details.
