"""
demo_pr_summary.py
------------------
End-to-end demo: runs all 6 validation test files through the complete
pipeline and prints a structured PR-style review summary for each.

Pipeline: Orchestrator -> RemediationAgent -> PRSummaryAgent
"""

import os
import sys
import glob
import json

sys.path.insert(0, r"C:\Users\Aayush\Desktop\milestone 2")

from orchestration import UnifiedOrchestrator
from remediation import RemediationAgent
from pr_summary import PRSummaryAgent

TEST_DIR = r"C:\Users\Aayush\Desktop\testing validation for analysis and security"
SEP = "=" * 90


def render_summary(summary, filename):
    bd = summary.severity_breakdown
    print(f"\n{SEP}")
    print(f"  PR REVIEW: {filename}")
    print(SEP)

    # Executive overview
    print(f"\n  EXECUTIVE OVERVIEW")
    print(f"  {summary.executive_overview}")

    # Severity breakdown
    print(f"\n  SEVERITY BREAKDOWN")
    print(f"  Critical: {bd.critical}  High: {bd.high}  Medium: {bd.medium}  Low: {bd.low}  |  Total: {bd.total}")

    # CI gate flags
    print(f"\n  CI FLAGS")
    print(f"  has_critical = {summary.has_critical}   has_blocking = {summary.has_blocking}")

    # Agent contributions
    print(f"\n  AGENT CONTRIBUTIONS")
    for agent_name, count in summary.agent_contributions.items():
        print(f"  {agent_name}: {count} finding(s)")

    # Prioritized fix list
    print(f"\n  PRIORITIZED FIX LIST")
    if not summary.prioritized_fixes:
        print("  (none)")
    for fix in summary.prioritized_fixes:
        print(f"\n  [{fix.rank:02d}] [{fix.severity.upper():8s}] {fix.finding_type}  (line {fix.line_number})  [{fix.source_agent}]")
        print(f"       Issue  : {fix.one_liner}")
        print(f"       Fix    : {fix.fix_action}")
        if fix.principle:
            print(f"       Ref    : {fix.principle}")

    print()


def main():
    orchestrator = UnifiedOrchestrator()
    remediator   = RemediationAgent()
    summarizer   = PRSummaryAgent()

    files = sorted(glob.glob(os.path.join(TEST_DIR, "*.*")))
    if not files:
        print(f"No files found in {TEST_DIR}")
        return

    for filepath in files:
        filename = os.path.basename(filepath)
        ext = os.path.splitext(filename)[1].lower()
        lang = "python" if ext == ".py" else "java"

        with open(filepath, "r", encoding="utf-8") as fh:
            source = fh.read()

        findings = orchestrator.analyze_concurrently(source, lang, filename=filename)
        findings = remediator.remediate(findings)
        summary  = summarizer.summarize(findings, filename=filename)

        render_summary(summary, filename)

    print(f"{SEP}")
    print("  DEMO COMPLETE")
    print(SEP)


if __name__ == "__main__":
    main()
