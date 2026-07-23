# Linux Security & Compliance Auditor 🔍

A zero-dependency Python CLI tool that performs non-destructive security auditing and compliance checks on Linux hosts. Generates terminal summaries and structured JSON reports.

---

## ⚡ Key Features

* **Zero Dependencies:** Built entirely with native Python standard libraries (`subprocess`, `json`, `os`, `re`). No `pip install` required.
* **Non-Destructive:** Read-only inspection—leaves system state untouched.
* **Audit Modules:**
  * **SSH Hardening:** Audits `/etc/ssh/sshd_config` for root access, password authentication, and empty passwords.
  * **Firewall Verification:** Checks active status for both `firewalld` (RHEL family) and `ufw` (Debian family).
  * **Network Inspection:** Scans active sockets using `ss` for insecure management ports (`21/FTP`, `23/Telnet`, `80/HTTP`).
  * **Account Audit:** Inspects `/etc/shadow` for accounts with unset passwords.
* **Automated Reporting:** Calculates an overall compliance score percentage and exports detailed findings to a timestamped `audit_report_<timestamp>.json`.

---

## 🚀 Quick Start

### 1. Clone the repository
```bash
git clone https://github.com/SudoShea/linux-security-auditor.git
cd linux-security-auditor
```
### 2. Make it executable
```bash
chmod +x auditor.py
```
### 3. Run as root
```bash
sudo ./auditor.py
```

---

## 📊 Example JSON Output
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
