# Changelog

All notable changes to the `linux-security-auditor` project will be documented in this file.

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
