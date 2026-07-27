# Changelog

All notable changes to the `linux-security-auditor` project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [2.0.0] - 2026-07-27

### Added
- **Unified CLI Entrypoint**: Introduced `audit.py` wrapper providing a clean subcommand interface (`system`, `container`, `ssh`, `diff`, `all`).
- **Podman Container Security Auditor**: Added `modules/container.py` to inspect rootless container configurations for privileged flags, root execution, host network bindings, and risky volume mounts.
- **Security Drift Detector**: Added `modules/diff.py` to compare two JSON audit reports and highlight new regressions or resolved security items over time.
- **Systemd Journald Integration**: Updated `modules/ssh.py` with `journalctl` query support for systemd-only hosts lacking legacy `/var/log/auth.log` files.

### Changed
- **Modular Directory Architecture**: Reorganized worker scripts into a dedicated `modules/` package (`system.py`, `container.py`, `ssh.py`, `diff.py`).
- **Live SSH Configuration Evaluation**: Refactored `modules/system.py` to evaluate runtime configuration via `sshd -T` rather than parsing static config files, correctly catching OpenSSH drop-in files (`/etc/ssh/sshd_config.d/`).
- **Kernel Parameter Checks**: Added `sysctl` kernel network stack parameter auditing (`ip_forward`, `accept_redirects`, `tcp_syncookies`).
- **Standardized Tooling**: Integrated `scripts/bump_version.py` for repository-wide header and version synchronization.

## [1.1.1] - 2026-07-24
### Added
- Integrated automated CI/CD pipeline using GitHub Actions and `Flake8` for Python quality control.

## [1.1.0] - 2026-07-23
### Added
- Added `ssh_sentinel.py` for parsing Linux authentication logs (`/var/log/auth.log` / `/var/log/secure`).
- Implemented threshold-based brute-force anomaly detection and invalid user targeting analysis.
- Added `--json` flag to `ssh_sentinel.py` for structured report output.

## [1.0.0] - 2026-05-10
### Added
- Initial release of core `auditor.py` security compliance scanner.
