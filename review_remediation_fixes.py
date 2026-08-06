"""
review_remediation_fixes.py
----------------------------
Runs every file in the validation test directory through the full pipeline:
  Orchestrator (parallel Code Analysis + Security agents)
    -> RemediationAgent (RAG-grounded fix per finding)

For each finding, prints:
  - The issue type, severity, line number, and source agent
  - The RAG guideline that grounded the fix
  - The plain-language explanation of why the fix works
  - The corrected code snippet to review for correctness / compilability

Usage:
  uv run python review_remediation_fixes.py
"""

import os
import sys
import glob

sys.path.insert(0, r"C:\Users\Aayush\Desktop\milestone 2")

from orchestration import UnifiedOrchestrator
from remediation import RemediationAgent

TEST_DIR = r"C:\Users\Aayush\Desktop\testing validation for analysis and security"

# ── Answer key: what vulnerabilities/smells are deliberately planted ──────────
PLANTED = {
    "AdminService.java": [
        "Hardcoded DB_PASSWORD + ADMIN_TOKEN (hardcoded_secret)",
        "SQL Injection: 'DELETE FROM users WHERE id = ' + userId (sql_injection)",
        "No admin check before deleteUser (broken_access_control)",
    ],
    "CommentServlet.java": [
        "XSS: username + comment reflected raw into HTML (xss)",
        "Deep nesting in doPost — 5 levels of if/else (high_complexity)",
    ],
    "InventoryService.java": [
        "(Clean file — no deliberate vulnerabilities)",
    ],
    "python_account_routes.py": [
        "Missing ownership check on /account/<id>/delete (broken_access_control)",
        "No CSRF token on /account/<id>/update-email (csrf)",
        "No admin check on /admin/reset-password (broken_access_control)",
    ],
    "python_pricing_utils.py": [
        "Functions x() and y() — single-letter names (poor_naming)",
        "Functions x() and y() are structural clones (duplicate_code)",
    ],
    "python_user_service.py": [
        "Hardcoded API_KEY + DB_PASSWORD (hardcoded_secret)",
        "SQL Injection: username concatenated into SELECT query (sql_injection)",
        "SQL Injection: username/email/hashed concatenated into INSERT (sql_injection)",
        "SQL Injection: referral_code concatenated into UPDATE (sql_injection)",
        "process_user_registration has 10 params and many branches (high_complexity)",
    ],
}

SEP  = "=" * 100
DASH = "-" * 100


def print_planted_context(filename: str) -> None:
    planted = PLANTED.get(filename, [])
    if planted:
        print("  Deliberately planted issues:")
        for p in planted:
            print(f"    * {p}")


def main() -> None:
    orchestrator = UnifiedOrchestrator()
    remediator   = RemediationAgent()

    files = sorted(glob.glob(os.path.join(TEST_DIR, "*.*")))

    if not files:
        print(f"No files found in {TEST_DIR}")
        return

    total_findings = 0

    for filepath in files:
        filename = os.path.basename(filepath)
        ext = os.path.splitext(filename)[1].lower()
        lang = "python" if ext == ".py" else "java"

        with open(filepath, "r", encoding="utf-8") as fh:
            source = fh.read()

        findings = orchestrator.analyze_concurrently(source, lang, filename=filename)
        findings = remediator.remediate(findings)
        total_findings += len(findings)

        print(f"\n{SEP}")
        print(f"FILE: {filename}  |  language: {lang}  |  findings: {len(findings)}")
        print_planted_context(filename)
        print(SEP)

        if not findings:
            print("  (no findings detected)")
            continue

        for i, f in enumerate(findings, 1):
            type_str = f.type.value if hasattr(f.type, "value") else str(f.type)
            sev      = f.severity.value.upper()

            print(f"\n  [{i}] [{sev}] {type_str}  (line {f.line_number})  [source: {f.source_agent}]")
            print(f"      Issue: {f.description}")
            print()

            if f.remediation:
                # Split explanation into RAG header + base text
                explanation = f.remediation.explanation
                if "[RAG Guideline]" in explanation:
                    parts = explanation.split("\n\n", 1)
                    print(f"      {parts[0]}")          # RAG Guideline line
                    if len(parts) > 1:
                        print()
                        print(f"      Why this fix works:")
                        for line in parts[1].splitlines():
                            print(f"        {line}")
                else:
                    print(f"      Explanation: {explanation}")

                print()
                print(f"      Principle: {f.remediation.principle}")
                print()
                print(f"      Corrected code snippet:")
                print(f"      " + DASH[:60])
                for line in f.remediation.corrected_code.splitlines():
                    print(f"        {line}")
                print(f"      " + DASH[:60])
            else:
                print("      (no remediation generated)")

    print(f"\n{SEP}")
    print(f"REVIEW COMPLETE  |  Files: {len(files)}  |  Total findings remediated: {total_findings}")
    print(SEP)


if __name__ == "__main__":
    main()
