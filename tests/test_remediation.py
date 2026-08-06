"""
tests/test_remediation.py
--------------------------
Unit tests for the RemediationAgent.
"""

import pytest
from shared.models import Finding, Remediation, Severity, SmellType, VulnerabilityType
from remediation import RemediationAgent


# ── Helpers ───────────────────────────────────────────────────────────────────

def make_finding(ftype, line=1):
    return Finding(
        type=ftype,
        severity=Severity.HIGH,
        line_number=line,
        description="test finding",
        source_agent="test",
    )


@pytest.fixture
def agent():
    return RemediationAgent()


# ── Baseline: field starts as None ───────────────────────────────────────────

class TestRemediationFieldDefault:
    def test_remediation_is_none_before_agent(self):
        f = make_finding(SmellType.POOR_NAMING)
        assert f.remediation is None

    def test_remediation_is_none_on_serialisation_before_agent(self):
        f = make_finding(SmellType.POOR_NAMING)
        assert f.to_dict()["remediation"] is None


# ── Every SmellType gets a populated Remediation ──────────────────────────────

class TestSmellTypeRemediation:
    @pytest.mark.parametrize("smell", list(SmellType))
    def test_smell_produces_remediation(self, agent, smell):
        f = make_finding(smell)
        agent.remediate([f])
        assert isinstance(f.remediation, Remediation)

    @pytest.mark.parametrize("smell", list(SmellType))
    def test_smell_corrected_code_non_empty(self, agent, smell):
        f = make_finding(smell)
        agent.remediate([f])
        assert len(f.remediation.corrected_code.strip()) > 0

    @pytest.mark.parametrize("smell", list(SmellType))
    def test_smell_explanation_non_empty(self, agent, smell):
        f = make_finding(smell)
        agent.remediate([f])
        assert len(f.remediation.explanation.strip()) > 0

    @pytest.mark.parametrize("smell", list(SmellType))
    def test_smell_principle_non_empty(self, agent, smell):
        f = make_finding(smell)
        agent.remediate([f])
        assert len(f.remediation.principle.strip()) > 0


# ── Every VulnerabilityType gets a populated Remediation ──────────────────────

class TestVulnerabilityTypeRemediation:
    @pytest.mark.parametrize("vuln", list(VulnerabilityType))
    def test_vuln_produces_remediation(self, agent, vuln):
        f = make_finding(vuln)
        agent.remediate([f])
        assert isinstance(f.remediation, Remediation)

    @pytest.mark.parametrize("vuln", list(VulnerabilityType))
    def test_vuln_corrected_code_non_empty(self, agent, vuln):
        f = make_finding(vuln)
        agent.remediate([f])
        assert len(f.remediation.corrected_code.strip()) > 0

    @pytest.mark.parametrize("vuln", list(VulnerabilityType))
    def test_vuln_explanation_non_empty(self, agent, vuln):
        f = make_finding(vuln)
        agent.remediate([f])
        assert len(f.remediation.explanation.strip()) > 0

    @pytest.mark.parametrize("vuln", list(VulnerabilityType))
    def test_vuln_principle_non_empty(self, agent, vuln):
        f = make_finding(vuln)
        agent.remediate([f])
        assert len(f.remediation.principle.strip()) > 0


# ── Specific rule content checks ──────────────────────────────────────────────

class TestSpecificRuleContent:
    def test_sql_injection_references_parameterized(self, agent):
        f = make_finding(VulnerabilityType.SQL_INJECTION)
        agent.remediate([f])
        assert "parameterized" in f.remediation.corrected_code.lower() or \
               "%" in f.remediation.corrected_code

    def test_sql_injection_principle_mentions_owasp(self, agent):
        f = make_finding(VulnerabilityType.SQL_INJECTION)
        agent.remediate([f])
        assert "OWASP" in f.remediation.principle

    def test_hardcoded_secret_mentions_env(self, agent):
        f = make_finding(VulnerabilityType.HARDCODED_SECRET)
        agent.remediate([f])
        assert "environ" in f.remediation.corrected_code or \
               "env" in f.remediation.corrected_code.lower()

    def test_insecure_auth_mentions_bcrypt(self, agent):
        f = make_finding(VulnerabilityType.INSECURE_AUTH)
        agent.remediate([f])
        assert "bcrypt" in f.remediation.corrected_code.lower()

    def test_xss_principle_mentions_cwe79(self, agent):
        f = make_finding(VulnerabilityType.XSS)
        agent.remediate([f])
        assert "CWE-79" in f.remediation.principle

    def test_poor_naming_principle_mentions_clean_code(self, agent):
        f = make_finding(SmellType.POOR_NAMING)
        agent.remediate([f])
        assert "Clean Code" in f.remediation.principle

    def test_duplicate_code_principle_mentions_dry(self, agent):
        f = make_finding(SmellType.DUPLICATE_CODE)
        agent.remediate([f])
        assert "DRY" in f.remediation.principle


# ── Batch behaviour ───────────────────────────────────────────────────────────

class TestBatchRemediation:
    def test_all_findings_remediated_in_batch(self, agent):
        findings = [
            make_finding(SmellType.LONG_METHOD, line=10),
            make_finding(VulnerabilityType.SQL_INJECTION, line=20),
            make_finding(SmellType.POOR_NAMING, line=30),
        ]
        agent.remediate(findings)
        assert all(f.remediation is not None for f in findings)

    def test_empty_list_returns_empty(self, agent):
        result = agent.remediate([])
        assert result == []

    def test_returns_same_list_object(self, agent):
        findings = [make_finding(SmellType.HIGH_COMPLEXITY)]
        returned = agent.remediate(findings)
        assert returned is findings   # mutated in-place, same list returned

    def test_multiple_findings_all_have_distinct_corrected_code(self, agent):
        """Different finding types must produce different corrected_code snippets."""
        f_sqli = make_finding(VulnerabilityType.SQL_INJECTION)
        f_xss  = make_finding(VulnerabilityType.XSS)
        agent.remediate([f_sqli, f_xss])
        assert f_sqli.remediation.corrected_code != f_xss.remediation.corrected_code


# ── Serialisation ─────────────────────────────────────────────────────────────

class TestSerialization:
    def test_to_dict_includes_remediation_key(self, agent):
        f = make_finding(SmellType.TIGHT_COUPLING)
        agent.remediate([f])
        d = f.to_dict()
        assert "remediation" in d

    def test_to_dict_remediation_has_three_keys(self, agent):
        f = make_finding(SmellType.TIGHT_COUPLING)
        agent.remediate([f])
        rem_dict = f.to_dict()["remediation"]
        assert set(rem_dict.keys()) == {"corrected_code", "explanation", "principle"}

    def test_to_dict_remediation_values_are_strings(self, agent):
        f = make_finding(VulnerabilityType.CSRF)
        agent.remediate([f])
        rem_dict = f.to_dict()["remediation"]
        assert all(isinstance(v, str) for v in rem_dict.values())


# ── Robustness: unknown type gets a fallback, doesn't crash ───────────────────

class TestFallbackRobustness:
    def test_unknown_type_string_does_not_crash(self, agent):
        """Simulate a future finding type not yet in RULES."""
        f = Finding(
            type="some_future_finding_type",   # raw string, not an enum
            severity=Severity.LOW,
            line_number=1,
            description="unknown",
            source_agent="test",
        )
        agent.remediate([f])
        assert f.remediation is not None

    def test_unknown_type_fallback_principle_non_empty(self, agent):
        f = Finding(
            type="another_unknown_type",
            severity=Severity.MEDIUM,
            line_number=5,
            description="test",
            source_agent="test",
        )
        agent.remediate([f])
        assert len(f.remediation.principle.strip()) > 0
