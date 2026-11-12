
#!/usr/bin/env python3

import os
import json
import subprocess
from datetime import datetime

results = []


def run_command(command):
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=20
        )
        return result.stdout.strip(), result.returncode
    except Exception as error:
        return str(error), 1


def add_result(check, status, evidence, recommendation):
    results.append({
        "check": check,
        "status": status,
        "evidence": evidence,
        "recommendation": recommendation
    })


# 1. FILE PERMISSIONS
def check_permissions():
    files = ["/etc/passwd", "/etc/shadow"]

    for path in files:
        if not os.path.exists(path):
            add_result(
                "File permissions: " + path,
                "REVIEW",
                "File not found",
                "Check the system configuration."
            )
            continue

        info = os.stat(path)
        mode = info.st_mode & 0o777
        owner = info.st_uid == 0

        if path == "/etc/passwd":
            safe = owner and not (mode & 0o022)
        else:
            safe = owner and not (mode & 0o007)

        evidence = (
            f"Owner UID: {info.st_uid}, "
            f"Permissions: {oct(mode)}"
        )

        add_result(
            "File permissions: " + path,
            "PASS" if safe else "REVIEW",
            evidence,
            "Check ownership and restrict unnecessary access."
            if not safe else "No immediate permission issue detected."
        )


# 2. SSH SECURITY
def check_ssh():
    package_status, code = run_command([
        "dpkg-query", "-W", "-f=${db:Status-Status}", "openssh-server"
    ])

    if code != 0 or package_status != "installed":
        add_result(
            "SSH configuration",
            "PASS",
            "OpenSSH server is not installed. No SSH daemon is running from this package.",
            "No action needed if remote SSH access is not required. If SSH is enabled in future, use key-based authentication and disable root login."
        )
        return

    ssh_output, ssh_code = run_command(["sudo", "-n", "sshd", "-T"])

    if ssh_code != 0:
        add_result(
            "SSH configuration",
            "REVIEW",
            "OpenSSH server is installed, but its effective configuration could not be checked.",
            "Review SSH configuration using sudo sshd -T."
        )
        return

    settings = {}
    for line in ssh_output.splitlines():
        parts = line.split()
        if len(parts) >= 2:
            settings[parts[0]] = parts[1]

    root_login = settings.get("permitrootlogin", "unknown")
    password_auth = settings.get("passwordauthentication", "unknown")

    if root_login == "no" and password_auth == "no":
        status = "PASS"
    else:
        status = "REVIEW"

    add_result(
        "SSH configuration",
        status,
        f"PermitRootLogin: {root_login}, PasswordAuthentication: {password_auth}",
        "Disable root login and password authentication where appropriate. Prefer SSH keys."
    )

# 3. UBUNTU UPDATES
def check_updates():
    output, code = run_command(["apt", "list", "--upgradable"])

    if code != 0:
        add_result(
            "System updates",
            "REVIEW",
            output or "Unable to check available updates.",
            "Refresh package information and check updates."
        )
        return

    packages = [
        line for line in output.splitlines()
        if "/" in line and not line.startswith("Listing")
    ]

    count = len(packages)

    add_result(
        "System updates",
        "PASS" if count == 0 else "REVIEW",
        f"Upgradable packages found: {count}",
        "Review and install available updates using apt."
        if count else "No upgradable packages were reported."
    )


# 4. FIREWALL
def check_firewall():
    output, code = run_command([
        "sudo", "-n", "ufw", "status", "verbose"
    ])

    if code != 0:
        add_result(
            "Firewall status",
            "REVIEW",
            "Unable to read UFW status. Administrator permission may be required.",
            "Run 'sudo ufw status verbose' to inspect firewall status."
        )
        return

    if "Status: active" in output:
        add_result(
            "Firewall status",
            "PASS",
            output,
            "UFW is active. Continue reviewing firewall rules periodically."
        )
    else:
        add_result(
            "Firewall status",
            "REVIEW",
            output,
            "Review firewall rules and enable UFW if appropriate."
        )

# 5. RUNNING SERVICES
def check_services():
    output, code = run_command([
        "systemctl", "list-units",
        "--type=service", "--state=running", "--no-pager"
    ])

    if code != 0:
        add_result(
            "Running services",
            "REVIEW",
            output or "Unable to list running services.",
            "Review system services manually."
        )
        return

    services = [
        line.strip() for line in output.splitlines()
        if ".service" in line
    ]

    add_result(
        "Running services",
        "REVIEW",
        "\n".join(services) if services else "No services listed.",
        "Review running services and disable only those "
        "that are unnecessary for this computer."
    )


# GENERATE REPORT
def save_report():
    report_folder = os.path.expanduser(
        "~/Linux-Hardening-Auditor/reports"
    )

    os.makedirs(report_folder, exist_ok=True)

    report = {
        "audit_date": datetime.now().isoformat(timespec="seconds"),
        "system": "Linux / Ubuntu",
        "results": results
    }

    report_path = os.path.join(
        report_folder, "audit-report.json"
    )

    with open(report_path, "w") as file:
        json.dump(report, file, indent=4)

    print("\n========== LINUX SECURITY AUDIT ==========")

    for item in results:
        print(f"\n[{item['status']}] {item['check']}")
        print("Evidence:", item["evidence"])
        print("Recommendation:", item["recommendation"])

    print("\n==========================================")
    print("Total checks:", len(results))
    print("PASS:", sum(r["status"] == "PASS" for r in results))
    print("REVIEW:", sum(r["status"] == "REVIEW" for r in results))
    print("\nReport saved to:")
    print(report_path)


def main():
    print("Starting Linux Hardening Checklist Auditor...")

    check_permissions()
    check_ssh()
    check_updates()
    check_firewall()
    check_services()

    save_report()


if __name__ == "__main__":
    main()

