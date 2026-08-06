"""
demo_pr_summary_json.py
------------------------
Demonstrates that PRSummary is a structured data object, not a string.
Prints both the raw JSON (to_dict) and a rendered preview side-by-side.
"""

import sys
import json
sys.path.insert(0, r"C:\Users\Aayush\Desktop\milestone 2")

from shared.models import Finding, Remediation, Severity, SmellType, VulnerabilityType
from pr_summary import PRSummaryAgent
from remediation import RemediationAgent

# ── Build a realistic set of findings ────────────────────────────────────────
def make_finding(ftype, severity, line, source, desc):
    return Finding(
        type=ftype, severity=severity, line_number=line,
        description=desc, source_agent=source,
    )

raw_findings = [
    make_finding(VulnerabilityType.SQL_INJECTION,    Severity.CRITICAL, 15, "security_vulnerability", "SQL injection via string concatenation."),
    make_finding(VulnerabilityType.HARDCODED_SECRET, Severity.CRITICAL,  3, "security_vulnerability", "Hardcoded API key found in source."),
    make_finding(SmellType.HIGH_COMPLEXITY,          Severity.HIGH,     40, "code_analysis",          "Function process() has cyclomatic complexity 14."),
    make_finding(SmellType.POOR_NAMING,              Severity.MEDIUM,    7, "code_analysis",          "Single-letter variable 'x' is not self-documenting."),
    make_finding(SmellType.DUPLICATE_CODE,           Severity.LOW,      22, "code_analysis",          "Duplicate block found at lines 22-28 and 45-51."),
]

# Attach remediations
remediator = RemediationAgent()
findings   = remediator.remediate(raw_findings)

# Generate structured PRSummary
agent   = PRSummaryAgent()
summary = agent.summarize(findings, filename="auth_service.py")

# ── Print 1: Raw structured object (to_dict / JSON) ──────────────────────────
print("=" * 80)
print("  RAW STRUCTURED DATA  (PRSummary.to_dict())")
print("=" * 80)
print(json.dumps(summary.to_dict(), indent=2))

# ── Print 2: Field-by-field access (proving it is structured, not a string) ──
print("\n" + "=" * 80)
print("  DIRECT FIELD ACCESS")
print("=" * 80)

print(f"\n  summary.executive_overview  (str):")
print(f"    {summary.executive_overview}")

print(f"\n  summary.severity_breakdown  (SeverityBreakdown):")
bd = summary.severity_breakdown
print(f"    .critical = {bd.critical}")
print(f"    .high     = {bd.high}")
print(f"    .medium   = {bd.medium}")
print(f"    .low      = {bd.low}")
print(f"    .total    = {bd.total}")

print(f"\n  summary.has_critical  (bool) = {summary.has_critical}")
print(f"  summary.has_blocking  (bool) = {summary.has_blocking}")

print(f"\n  summary.agent_contributions  (dict) = {summary.agent_contributions}")

print(f"\n  summary.prioritized_fixes  (list[FindingSummary]):")
for fix in summary.prioritized_fixes:
    print(f"    [{fix.rank:02d}] [{fix.severity.upper():8s}] .finding_type={fix.finding_type!r:25s}  .line_number={fix.line_number}")
    print(f"          .one_liner  = {fix.one_liner[:70]!r}")
    print(f"          .fix_action = {fix.fix_action[:70]!r}")
    print(f"          .principle  = {fix.principle[:60]!r}")

print("\n" + "=" * 80)
print("  CONFIRMED: PRSummary is a structured object with typed fields,")
print("  not a wall of text. Serialize to JSON, render in a UI, or assert")
print("  against individual fields in CI gates.")
print("=" * 80)
