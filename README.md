# Linux Hardening Checklist Auditor

## 1. Project Overview

The Linux Hardening Checklist Auditor is a Python-based security auditing tool developed as part of an internship task at Redkross Research Foundation.

It checks important Linux security configurations, collects system evidence, identifies areas requiring manual review, and generates a JSON audit report with recommendations.

## 2. Project Objectives

- Check important Linux file permissions.
- Review SSH server installation and configuration.
- Identify available system package updates.
- Check firewall status.
- List running system services.
- Generate a structured security audit report.
- Provide recommendations for improving system security.

## 3. Technologies Used

- Operating System: Ubuntu Linux 26.04
- Programming Language: Python 3
- Libraries: Python Standard Library
- Tools: Terminal, systemctl, UFW, APT and VirtualBox

## 4. Security Checks Performed

### A. File Permissions
Checks ownership and permissions of:
- `/etc/passwd`
- `/etc/shadow`

### B. SSH Configuration
Checks whether the OpenSSH server is installed. If installed, the auditor reviews important SSH security settings.

### C. System Updates
Checks for available package upgrades using APT.

### D. Firewall Status
Checks whether the UFW firewall is active and collects its configuration details.

### E. Running Services
Lists currently running system services for manual review. Services are not automatically disabled.

## 5. Audit Status Categories

- PASS: The check meets the implemented security condition.
- REVIEW: Further investigation or manual verification is recommended.

A REVIEW result does not automatically mean that a security vulnerability exists.

## 6. Project Structure

```text
Linux-Hardening-Auditor/
├── auditor.py
├── README.md
└── reports/
    └── audit-report.json
```

## 7. How to Run the Project

Open the project directory:

```bash
cd ~/Linux-Hardening-Auditor
```

Run the auditor:

```bash
python3 auditor.py
```

The generated report is saved at:

```text
reports/audit-report.json
```

## 8. Testing and Results

The auditor was tested in an Ubuntu Linux virtual machine using Oracle VirtualBox.

The recorded audit results after system updates were:

- Total checks: 6
- PASS: 5
- REVIEW: 1

The remaining REVIEW result concerned running services requiring manual assessment.

An additional investigation identified a failure in the auxiliary `apport-autoreport.service`. Its logs showed that crash-report uploads were not confirmed before the timeout. The underlying system services were subsequently verified as active.

The JSON report was also validated using Python's JSON tool.

## 9. Limitations

- The auditor performs basic security checks and is not a complete vulnerability scanner.
- Running services require manual assessment based on system requirements.
- SSH checks depend on the availability of the OpenSSH server.
- The tool does not automatically modify system configurations or disable services.
- Results should be interpreted in the context of the operating system and environment.

## 10. Security References

- Ubuntu Security Guide: https://documentation.ubuntu.com/security/compliance/usg/
- CIS Benchmarks: https://www.cisecurity.org/cis-benchmarks
- Ubuntu Server Guide: https://documentation.ubuntu.com/server/
- OpenSSH Configuration Manual: https://man.openbsd.org/sshd_config

## 11. Conclusion

The Linux Hardening Checklist Auditor provides a simple way to review essential Linux security configurations, collect evidence, and identify areas requiring further attention.

This project demonstrates practical knowledge of Linux administration, Python automation, file permissions, SSH security, package management, firewall configuration, system services, and security auditing.



## Additional Feature: Read-Only SSH Configuration Auditor

As part of the Redkross Research Foundation Linux Security task, an additional read-only auditor was developed using the supplied Linux configuration fixtures.

### Features
- Reads the supplied Linux security baseline.
- Reviews SSH daemon configuration settings.
- Compares observed values with baseline recommendations.
- Identifies PASS, FAIL, and POLICY REVIEW findings.
- Includes evidence, severity, rationale, and safe remediation suggestions.
- Uses the supplied asset inventory to identify the target host.
- Generates a separate JSON audit report.
- Does not automatically modify system configuration.

### Files
- `fixture_auditor.py` – Read-only configuration auditing script.
- `fixtures/` – Supplied Linux configuration resources.
- `reports/fixture-audit-report.json` – Generated audit results.

### How to Run
python3 fixture_auditor.py
```bash
python3 fixture_auditor.py
python3 fixture_auditor.py

```

