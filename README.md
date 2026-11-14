# Linux Hardening Checklist Auditor

## 1. Project Overview

The Linux Hardening Checklist Auditor is a Python-based security auditing project developed as part of the internship task at Redkross Research Foundation.

The project provides two auditing tools:

1. **Linux Hardening Checklist Auditor:** Reviews essential Linux security configurations, including file permissions, SSH availability, package updates, firewall status and running services.
2. **SSH Configuration Auditor:** Performs read-only analysis of supplied SSH configuration fixtures and compares observed settings against the provided security baseline.

Both tools generate structured JSON reports containing audit findings and relevant evidence.

## 2. Project Objectives

- Review important Linux security configurations.
- Check ownership and permissions of sensitive system files.
- Examine SSH server availability and configuration.
- Identify available system package updates.
- Check firewall status.
- Review running system services.
- Compare SSH configuration settings with baseline recommendations.
- Identify security findings and areas requiring manual review.
- Generate structured JSON audit reports.
- Provide safe remediation recommendations.

## 3. Technologies and Tools Used

- Operating System: Ubuntu Linux 26.04
- Programming Language: Python 3
- Libraries: Python Standard Library
- Virtualisation: Oracle VirtualBox
- System Tools: APT, systemctl, UFW and Linux Terminal
- Version Control: Git and GitHub

No additional third-party Python packages are required.

## 4. Project Structure

```text
Linux-Hardening-Auditor/
├── auditor.py
├── fixture_auditor.py
├── README.md
├── fixtures/
│   ├── asset_inventory.csv
│   ├── hardening_task_notes.txt
│   ├── linux_baseline.json
│   ├── sshd_config_hardened_reference.txt
│   └── sshd_config_sample.txt
└── reports/
    ├── audit-report.json
    └── fixture-audit-report.json
```

## 5. Original Linux Hardening Auditor

The original auditor reviews the security condition of a Linux system.

### Security Checks

**A. File Permissions**
- Checks `/etc/passwd`.
- Checks `/etc/shadow`.
- Reviews ownership and file permissions.

**B. SSH Availability and Configuration**
- Checks whether the OpenSSH server is installed.
- Reviews relevant SSH security information when available.

**C. System Updates**
- Checks for available package upgrades using APT.

**D. Firewall Status**
- Checks whether UFW is active.
- Collects firewall configuration information.

**E. Running Services**
- Lists currently running system services for manual security assessment.

### Audit Status

- PASS: The implemented security condition is satisfied.
- REVIEW: Further investigation or manual verification is recommended.

A REVIEW result does not automatically indicate a security vulnerability.

## 6. SSH Configuration Auditor

The additional `fixture_auditor.py` tool analyses the synthetic Linux configuration resources supplied with the internship assignment.

### Features

- Reads the supplied Linux security baseline.
- Parses the sample SSH daemon configuration.
- Compares observed settings with baseline recommendations.
- Identifies security findings and policy-dependent settings.
- Records evidence, including configuration lines and values.
- Provides severity, rationale and safe remediation suggestions.
- Uses the asset inventory to identify the target system.
- Generates a separate JSON audit report.

### Configuration Checks

The auditor evaluates seven SSH settings:

1. PermitRootLogin
2. PasswordAuthentication
3. PermitEmptyPasswords
4. X11Forwarding
5. MaxAuthTries
6. ClientAliveInterval
7. AllowUsers

### Finding Categories

- PASS: The observed configuration satisfies the evaluated condition.
- FAIL: A definite mismatch with the supplied baseline or reference is identified.
- POLICY REVIEW: The setting requires confirmation against organisational policy.
- REVIEW: Additional investigation is required.

The auditor does not automatically modify system configuration.

**Note:** The supplied configuration files are synthetic training fixtures
