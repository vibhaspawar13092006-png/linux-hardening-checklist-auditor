#!/usr/bin/env python3

"""
Read-only Linux SSH configuration fixture auditor.
Uses supplied Redkross training resources.
Does not modify system configuration.
"""

import csv
import json
from datetime import datetime, timezone
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parent
FIXTURES_DIR = PROJECT_DIR / "fixtures"
REPORT_DIR = PROJECT_DIR / "reports"

BASELINE_FILE = FIXTURES_DIR / "linux_baseline.json"
SAMPLE_FILE = FIXTURES_DIR / "sshd_config_sample.txt"
REFERENCE_FILE = FIXTURES_DIR / "sshd_config_hardened_reference.txt"
INVENTORY_FILE = FIXTURES_DIR / "asset_inventory.csv"

REPORT_FILE = REPORT_DIR / "fixture-audit-report.json"


def parse_ssh_config(path):
    """Read simple SSH configuration directives and retain line evidence."""

    settings = {}

    with path.open("r", encoding="utf-8") as file:
        for line_number, raw_line in enumerate(file, start=1):
            stripped = raw_line.strip()

            if not stripped or stripped.startswith("#"):
                continue

            parts = stripped.split(None, 1)

            if len(parts) != 2:
                continue

            setting = parts[0].lower()

            # Retain the first occurrence of each directive.
            if setting not in settings:
                settings[setting] = {
                    "value": parts[1].strip(),
                    "line_number": line_number,
                    "raw_line": stripped
                }

    return settings


def find_asset(hostname):
    """Find the asset matching the hostname in the supplied inventory."""

    with INVENTORY_FILE.open(
        "r", encoding="utf-8", newline=""
    ) as file:
        reader = csv.DictReader(file)

        for row in reader:
            if row.get("hostname") == hostname:
                return row

    return None


def analyse_check(check, sample, reference):
    """Evaluate one baseline check using the supplied SSH fixture."""

    check_id = check["id"]
    setting = check["setting"]
    key = setting.lower()

    actual_entry = sample.get(key)
    reference_entry = reference.get(key)

    actual = actual_entry["value"] if actual_entry else None
    reference_value = (
        reference_entry["value"] if reference_entry else None
    )

    status = "REVIEW"
    classification = "insufficient_evidence"
    rationale = ""
    remediation = ""

    if actual_entry is None:
        rationale = (
            "The directive is not present in the supplied sample. "
            "Its effective value cannot be established by this "
            "simple fixture checker."
        )
        remediation = (
            "Review the complete authorised SSH configuration "
            "and confirm the effective setting."
        )

    else:
        value = actual.lower()

        if check_id == "LIN-01":
            if value == "no":
                status = "PASS"
                classification = "compliant"
                rationale = "Root SSH login is explicitly disabled."
                remediation = "No change indicated by this check."
            else:
                status = "FAIL"
                classification = "definite_mismatch"
                rationale = (
                    "The sample permits root SSH login, while "
                    "the supplied baseline recommends disabling it."
                )
                remediation = (
                    "Disable root SSH login through an authorised, "
                    "tested configuration change."
                )

        elif check_id == "LIN-02":
            if value == "no":
                status = "PASS"
                classification = "compliant"
                rationale = (
                    "Password authentication is explicitly disabled."
                )
                remediation = "No change indicated by this check."
            else:
                status = "POLICY REVIEW"
                classification = "policy_dependent"
                rationale = (
                    "Password authentication is enabled. The baseline "
                    "allows either disabling it or using controlled "
                    "authentication, but the supplied files do not "
                    "establish whether adequate controls exist."
                )
                remediation = (
                    "Confirm the organisation's authentication policy. "
                    "Prefer approved key-based authentication and "
                    "disable password authentication where required."
                )

        elif check_id == "LIN-03":
            if value == "no":
                status = "PASS"
                classification = "compliant"
                rationale = "Empty-password authentication is disabled."
                remediation = "No change indicated by this check."
            else:
                status = "FAIL"
                classification = "definite_mismatch"
                rationale = (
                    "The sample does not meet the baseline requirement "
                    "to disable empty-password authentication."
                )
                remediation = (
                    "Set PermitEmptyPasswords to no through an "
                    "authorised configuration change."
                )

        elif check_id == "LIN-04":
            if value == "no":
                status = "PASS"
                classification = "compliant"
                rationale = "X11 forwarding is explicitly disabled."
                remediation = "No change indicated by this check."
            else:
                status = "POLICY REVIEW"
                classification = "policy_dependent"
                rationale = (
                    "X11 forwarding is enabled. The baseline recommends "
                    "disabling it when it is not required, but the "
                    "inventory does not state whether this asset "
                    "requires X11 forwarding."
                )
                remediation = (
                    "Confirm the requirement with the asset owner. "
                    "Disable X11 forwarding if it is not needed."
                )

        elif check_id == "LIN-05":
            try:
                attempts = int(value)

                if attempts <= 4:
                    status = "PASS"
                    classification = "compliant"
                    rationale = (
                        "The configured authentication-attempt limit "
                        "does not exceed the reference value of 4."
                    )
                    remediation = "No change indicated by this check."
                else:
                    status = "FAIL"
                    classification = "definite_mismatch"
                    rationale = (
                        f"The configured limit is {attempts}, exceeding "
                        "the reference value of 4. No approved exception "
                        "is identified in the supplied resources."
                    )
                    remediation = (
                        "Use a limit of 4 unless the asset owner has "
                        "documented and approved a different value."
                    )

            except ValueError:
                rationale = (
                    "The authentication-attempt value is not numeric."
                )
                remediation = (
                    "Confirm the intended numeric value with the "
                    "asset owner."
                )

        elif check_id == "LIN-06":
            status = "POLICY REVIEW"
            classification = "policy_dependent"

            if value == "0":
                rationale = (
                    "ClientAliveInterval is 0, which means no SSH "
                    "client-alive interval is configured. The baseline "
                    "requires an organisation-approved idle timeout, "
                    "but does not specify its numeric value."
                )
            else:
                rationale = (
                    f"ClientAliveInterval is set to {actual}. The "
                    "supplied baseline does not provide an approved "
                    "numeric timeout for comparison."
                )

            remediation = (
                "Ask the asset owner for the approved idle timeout. "
                "The reference value of 300 seconds is illustrative, "
                "not a confirmed organisational requirement."
            )

        elif check_id == "LIN-07":
            tokens = value.split()

            has_wildcard = any(
                "*" in token or "?" in token
                for token in tokens
            )

            if has_wildcard:
                status = "FAIL"
                classification = "definite_mismatch"
                rationale = (
                    "The AllowUsers directive contains a wildcard "
                    "rather than restricting SSH access to explicit "
                    "approved accounts."
                )
                remediation = (
                    "Obtain the approved SSH account list from the "
                    "asset owner and replace the wildcard with "
                    "the confirmed account names."
                )
            else:
                status = "POLICY REVIEW"
                classification = "policy_dependent"
                rationale = (
                    "The configuration lists specific SSH accounts, "
                    "but the supplied inventory does not identify "
                    "which usernames are approved."
                )
                remediation = (
                    "Verify every listed account with the asset owner "
                    "before treating the restriction as compliant."
                )

        else:
            rationale = (
                "This baseline check ID is not implemented by the auditor."
            )
            remediation = (
                "Review the check definition before adding support."
            )

    sample_matches_baseline = (
        actual is not None
        and str(actual).lower()
        == str(check.get("observed", "")).lower()
    )

    return {
        "id": check_id,
        "setting": setting,
        "status": status,
        "classification": classification,
        "severity": check.get("severity", "unspecified"),
        "observed": actual,
        "baseline_observed": check.get("observed"),
        "recommended": check.get("recommended"),
        "sample_matches_baseline_observation": sample_matches_baseline,
        "evidence": {
            "sample_file": SAMPLE_FILE.name,
            "line_number": (
                actual_entry["line_number"] if actual_entry else None
            ),
            "line": (
                actual_entry["raw_line"]
                if actual_entry
                else "Directive not found in supplied sample."
            ),
            "reference_file": REFERENCE_FILE.name,
            "reference_line_number": (
                reference_entry["line_number"]
                if reference_entry else None
            ),
            "reference_line": (
                reference_entry["raw_line"]
                if reference_entry else None
            ),
            "reference_value_is_illustrative": True
        },
        "reference_example": reference_value,
        "rationale": rationale,
        "safe_remediation": remediation
    }


def main():
    required_files = [
        BASELINE_FILE,
        SAMPLE_FILE,
        REFERENCE_FILE,
        INVENTORY_FILE
    ]

    for path in required_files:
        if not path.is_file():
            raise FileNotFoundError(
                f"Required resource file not found: {path}"
            )

    with BASELINE_FILE.open("r", encoding="utf-8") as file:
        baseline = json.load(file)

    sample = parse_ssh_config(SAMPLE_FILE)
    reference = parse_ssh_config(REFERENCE_FILE)

    hostname = baseline.get("host", "")
    asset = find_asset(hostname)

    findings = [
        analyse_check(check, sample, reference)
        for check in baseline.get("checks", [])
    ]

    summary = {
        "total": len(findings),
        "pass": sum(f["status"] == "PASS" for f in findings),
        "fail": sum(f["status"] == "FAIL" for f in findings),
        "policy_review": sum(
            f["status"] == "POLICY REVIEW" for f in findings
        ),
        "review": sum(f["status"] == "REVIEW" for f in findings)
    }

    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    report = {
        "audit_date": datetime.now(timezone.utc).isoformat(
            timespec="seconds"
        ),
        "project": "Linux Hardening Checklist Auditor",
        "dataset": baseline.get("dataset"),
        "notice": baseline.get("notice"),
        "target_host": hostname,
        "asset_inventory_match": asset,
        "audit_mode": "read-only",
        "configuration_modified": False,
        "summary": summary,
        "findings": findings
    }

    with REPORT_FILE.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=4)

    print("\n========== SSH FIXTURE AUDIT ==========")
    print("Target host:", hostname)
    print("Audit mode: Read-only")

    if asset:
        print("Asset ID:", asset.get("asset_id"))
        print("Owner role:", asset.get("owner_role"))
        print("Criticality:", asset.get("criticality"))
    else:
        print("Asset inventory match: Not found")

    for finding in findings:
        print(
            f"\n[{finding['status']}] "
            f"{finding['id']} - {finding['setting']}"
        )
        print("Severity:", finding["severity"])
        print("Observed:", finding["observed"])
        print("Evidence:", finding["evidence"]["line"])
        print("Rationale:", finding["rationale"])
        print("Safe remediation:", finding["safe_remediation"])

    print("\n========== AUDIT SUMMARY ==========")
    print("Total:", summary["total"])
    print("PASS:", summary["pass"])
    print("FAIL:", summary["fail"])
    print("POLICY REVIEW:", summary["policy_review"])
    print("REVIEW:", summary["review"])

    print("\nJSON report saved to:")
    print(REPORT_FILE)
    print("\nNo system configuration was modified.")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError) as error:
        print("Audit could not be completed:", error)
        raise SystemExit(1)

