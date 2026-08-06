import sys
sys.path.insert(0, ".")
from orchestration import UnifiedOrchestrator
from remediation import RemediationAgent

SOURCE = """
import hashlib, sqlite3

API_KEY = "EXAMPLE_HARDCODED_KEY_DO_NOT_DO_THIS"   # noqa: placeholder for demo

def login(username, pwd):
    h = hashlib.md5(pwd.encode()).hexdigest()
    query = "SELECT * FROM users WHERE username='" + username + "'"
    conn = sqlite3.connect("app.db")
    conn.execute(query)
    return h
"""

orchestrator = UnifiedOrchestrator()
remediator   = RemediationAgent()

findings = orchestrator.analyze_concurrently(SOURCE, "python", filename="demo.py")
findings = remediator.remediate(findings)

print("=" * 90)
print("FULL PIPELINE DEMO -- Orchestrator -> Remediation Agent")
print("=" * 90)
for f in findings:
    print(f"\n[{f.severity.value.upper()}] {f.type.value}  (Line {f.line_number})  [Source: {f.source_agent}]")
    print(f"  Issue    : {f.description}")
    print(f"  Principle: {f.remediation.principle}")
    print(f"  Why it works:")
    print(f"    {f.remediation.explanation[:200]}...")
    print(f"  Fix snippet (first 4 lines):")
    for line in f.remediation.corrected_code.splitlines()[:4]:
        print(f"    {line}")
    print("-" * 90)

print(f"\nTotal findings remediated: {len(findings)}")
