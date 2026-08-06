"""
verify_pipeline.py
-------------------
Runs the COMPLETE pipeline on python_user_service.py:
  1. Orchestrator (Code Analysis + Security agents in parallel)
  2. RemediationAgent
  3. PRSummaryAgent

Then performs explicit consistency checks:
  - severity_breakdown counts match the actual findings list
  - prioritized_fixes length == len(findings)
  - executive overview mentions the right severity tiers
  - has_critical / has_blocking match breakdown
  - ranks are sequential
  - each fix's severity matches the original finding
"""

import sys
sys.path.insert(0, r"C:\Users\Aayush\Desktop\milestone 2")

from orchestration import UnifiedOrchestrator
from remediation import RemediationAgent
from pr_summary import PRSummaryAgent
from shared.models import Severity

FILEPATH = r"C:\Users\Aayush\Desktop\testing validation for analysis and security\python_user_service.py"

with open(FILEPATH, "r", encoding="utf-8") as fh:
    source = fh.read()

filename = "python_user_service.py"

# ── Step 1: Orchestrate ───────────────────────────────────────────────────────
orchestrator = UnifiedOrchestrator()
findings = orchestrator.analyze_concurrently(source, "python", filename=filename)

print(f"Step 1 — Orchestrator produced {len(findings)} finding(s):")
for f in findings:
    t = f.type.value if hasattr(f.type, "value") else str(f.type)
    print(f"  [{f.severity.value.upper():8s}] {t:25s} line {f.line_number:3d}  [{f.source_agent}]")

# ── Step 2: Remediate ─────────────────────────────────────────────────────────
remediator = RemediationAgent()
findings = remediator.remediate(findings)
print(f"\nStep 2 — Remediation attached to all {len(findings)} findings: "
      f"{'YES' if all(f.remediation for f in findings) else 'SOME MISSING'}")

# ── Step 3: PR Summary ────────────────────────────────────────────────────────
agent   = PRSummaryAgent()
summary = agent.summarize(findings, filename=filename)

# ── Consistency checks ────────────────────────────────────────────────────────
SEP = "-" * 70
print(f"\n{'='*70}")
print("  CONSISTENCY CHECKS")
print(f"{'='*70}")

errors = []

# Count severities from the actual findings list
from collections import Counter
actual_counts = Counter(f.severity.value for f in findings)
bd = summary.severity_breakdown

checks = [
    ("critical count matches",   bd.critical == actual_counts.get("critical", 0)),
    ("high count matches",       bd.high     == actual_counts.get("high", 0)),
    ("medium count matches",     bd.medium   == actual_counts.get("medium", 0)),
    ("low count matches",        bd.low      == actual_counts.get("low", 0)),
    ("total == len(findings)",   bd.total    == len(findings)),
    ("fixes length == findings", len(summary.prioritized_fixes) == len(findings)),
    ("ranks are sequential",     [f.rank for f in summary.prioritized_fixes] == list(range(1, len(findings)+1))),
    ("first fix is most urgent", summary.prioritized_fixes[0].severity in ("critical","high") if findings else True),
    ("has_critical matches",     summary.has_critical == (bd.critical > 0)),
    ("has_blocking matches",     summary.has_blocking == (bd.critical > 0 or bd.high > 0)),
    ("overview mentions filename", filename in summary.executive_overview),
    ("overview non-empty",       len(summary.executive_overview.strip()) > 20),
    ("severity mentions in overview", (
        str(bd.critical) in summary.executive_overview or
        str(bd.total) in summary.executive_overview
    )),
]

for name, passed in checks:
    status = "PASS" if passed else "FAIL"
    print(f"  [{status}] {name}")
    if not passed:
        errors.append(name)

# Per-fix severity alignment check
print(f"\n  Checking each fix's severity matches its original finding...")
finding_by_line_type = {(f.line_number, (f.type.value if hasattr(f.type,"value") else str(f.type))): f.severity.value
                        for f in findings}
for fix in summary.prioritized_fixes:
    key = (fix.line_number, fix.finding_type)
    expected_sev = finding_by_line_type.get(key)
    match = (fix.severity == expected_sev)
    print(f"    [{('OK' if match else 'MISMATCH'):8s}] rank={fix.rank} {fix.finding_type}@L{fix.line_number}: "
          f"expected={expected_sev} got={fix.severity}")
    if not match:
        errors.append(f"severity mismatch for {fix.finding_type}@L{fix.line_number}")

# ── Final rendered summary ────────────────────────────────────────────────────
print(f"\n{'='*70}")
print("  GENERATED PR SUMMARY")
print(f"{'='*70}")
print(f"\n  executive_overview:\n    {summary.executive_overview}")
print(f"\n  severity_breakdown: {summary.severity_breakdown.to_dict()}")
print(f"  has_critical = {summary.has_critical}  |  has_blocking = {summary.has_blocking}")
print(f"  agent_contributions = {summary.agent_contributions}")
print(f"\n  prioritized_fixes ({len(summary.prioritized_fixes)} entries):")
for fix in summary.prioritized_fixes:
    print(f"    [{fix.rank:02d}] [{fix.severity.upper():8s}] {fix.finding_type}  L{fix.line_number}")
    print(f"          one_liner : {fix.one_liner}")
    print(f"          fix_action: {fix.fix_action[:80]}")

print(f"\n{'='*70}")
if errors:
    print(f"  RESULT: {len(errors)} CHECK(S) FAILED:")
    for e in errors:
        print(f"    - {e}")
else:
    print("  RESULT: ALL CHECKS PASSED — summary is consistent with the findings list.")
print(f"{'='*70}")
