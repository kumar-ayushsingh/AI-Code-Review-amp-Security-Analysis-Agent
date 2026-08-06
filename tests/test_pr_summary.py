"""
tests/test_pr_summary.py
-------------------------
Unit tests for PRSummaryAgent and the associated PRSummary data model.
"""

import pytest
from shared.models import (
    Finding,
    FindingSummary,
    PRSummary,
    Remediation,
    Severity,
    SeverityBreakdown,
    SmellType,
    VulnerabilityType,
)
from pr_summary import PRSummaryAgent


# ── Fixtures and helpers ──────────────────────────────────────────────────────

def make_finding(
    ftype=SmellType.POOR_NAMING,
    severity=Severity.LOW,
    line=10,
    source="code_analysis",
    description="Test finding description. More detail here.",
    remediation=None,
):
    return Finding(
        type=ftype,
        severity=severity,
        line_number=line,
        description=description,
        source_agent=source,
        remediation=remediation,
    )


def make_remediation(principle="OWASP A03", explanation="Fix using X.\n\nBase explanation."):
    return Remediation(
        corrected_code="# fixed code",
        explanation=explanation,
        principle=principle,
    )


@pytest.fixture
def agent():
    return PRSummaryAgent()


@pytest.fixture
def mixed_findings():
    """A realistic set spanning all severities and both agents."""
    return [
        make_finding(VulnerabilityType.SQL_INJECTION,       Severity.CRITICAL, 15, "security_vulnerability",
                     "SQL injection via string concat.",
                     make_remediation("OWASP A03:2021", "[RAG Guideline] SEC-01\n\nUse parameterized queries.")),
        make_finding(VulnerabilityType.HARDCODED_SECRET,    Severity.CRITICAL, 3,  "security_vulnerability",
                     "Hardcoded API key found.",
                     make_remediation("OWASP A02:2021", "[RAG Guideline] SEC-04\n\nStore secrets in env vars.")),
        make_finding(SmellType.HIGH_COMPLEXITY,             Severity.HIGH,     40, "code_analysis",
                     "High cyclomatic complexity in process().",
                     make_remediation("Refactoring", "[RAG Guideline] CC-04\n\nUse guard clauses.")),
        make_finding(SmellType.POOR_NAMING,                 Severity.MEDIUM,   7,  "code_analysis",
                     "Single-letter variable 'x'.",
                     make_remediation("Clean Code", "[RAG Guideline] CC-03\n\nUse descriptive names.")),
        make_finding(SmellType.DUPLICATE_CODE,              Severity.LOW,      22, "code_analysis",
                     "Duplicate block at lines 22-28.",
                     make_remediation("DRY", "[RAG Guideline] CC-02\n\nExtract shared logic.")),
    ]


# ── Return type checks ────────────────────────────────────────────────────────

class TestReturnType:
    def test_summarize_returns_prsummary(self, agent, mixed_findings):
        result = agent.summarize(mixed_findings)
        assert isinstance(result, PRSummary)

    def test_severity_breakdown_is_dataclass(self, agent, mixed_findings):
        result = agent.summarize(mixed_findings)
        assert isinstance(result.severity_breakdown, SeverityBreakdown)

    def test_prioritized_fixes_is_list(self, agent, mixed_findings):
        result = agent.summarize(mixed_findings)
        assert isinstance(result.prioritized_fixes, list)

    def test_each_fix_is_finding_summary(self, agent, mixed_findings):
        result = agent.summarize(mixed_findings)
        for fix in result.prioritized_fixes:
            assert isinstance(fix, FindingSummary)

    def test_agent_contributions_is_dict(self, agent, mixed_findings):
        result = agent.summarize(mixed_findings)
        assert isinstance(result.agent_contributions, dict)

    def test_executive_overview_is_string(self, agent, mixed_findings):
        result = agent.summarize(mixed_findings)
        assert isinstance(result.executive_overview, str)

    def test_has_critical_is_bool(self, agent, mixed_findings):
        result = agent.summarize(mixed_findings)
        assert isinstance(result.has_critical, bool)

    def test_has_blocking_is_bool(self, agent, mixed_findings):
        result = agent.summarize(mixed_findings)
        assert isinstance(result.has_blocking, bool)


# ── Severity breakdown ─────────────────────────────────────────────────────────

class TestSeverityBreakdown:
    def test_critical_count(self, agent, mixed_findings):
        result = agent.summarize(mixed_findings)
        assert result.severity_breakdown.critical == 2

    def test_high_count(self, agent, mixed_findings):
        result = agent.summarize(mixed_findings)
        assert result.severity_breakdown.high == 1

    def test_medium_count(self, agent, mixed_findings):
        result = agent.summarize(mixed_findings)
        assert result.severity_breakdown.medium == 1

    def test_low_count(self, agent, mixed_findings):
        result = agent.summarize(mixed_findings)
        assert result.severity_breakdown.low == 1

    def test_total_count(self, agent, mixed_findings):
        result = agent.summarize(mixed_findings)
        assert result.severity_breakdown.total == 5

    def test_all_zeros_on_empty(self, agent):
        result = agent.summarize([])
        bd = result.severity_breakdown
        assert bd.critical == bd.high == bd.medium == bd.low == 0
        assert bd.total == 0


# ── Prioritized fix list ──────────────────────────────────────────────────────

class TestPrioritizedFixes:
    def test_length_matches_findings(self, agent, mixed_findings):
        result = agent.summarize(mixed_findings)
        assert len(result.prioritized_fixes) == len(mixed_findings)

    def test_sorted_by_severity_critical_first(self, agent, mixed_findings):
        result = agent.summarize(mixed_findings)
        sevs = [f.severity for f in result.prioritized_fixes]
        rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        assert [rank[s] for s in sevs] == sorted(rank[s] for s in sevs)

    def test_rank_starts_at_one(self, agent, mixed_findings):
        result = agent.summarize(mixed_findings)
        assert result.prioritized_fixes[0].rank == 1

    def test_ranks_are_sequential(self, agent, mixed_findings):
        result = agent.summarize(mixed_findings)
        ranks = [f.rank for f in result.prioritized_fixes]
        assert ranks == list(range(1, len(mixed_findings) + 1))

    def test_one_liner_is_non_empty(self, agent, mixed_findings):
        result = agent.summarize(mixed_findings)
        for fix in result.prioritized_fixes:
            assert len(fix.one_liner.strip()) > 0

    def test_fix_action_populated_when_remediation_present(self, agent, mixed_findings):
        result = agent.summarize(mixed_findings)
        for fix in result.prioritized_fixes:
            assert len(fix.fix_action.strip()) > 0

    def test_finding_type_is_string(self, agent, mixed_findings):
        result = agent.summarize(mixed_findings)
        for fix in result.prioritized_fixes:
            assert isinstance(fix.finding_type, str)

    def test_principle_populated_from_remediation(self, agent, mixed_findings):
        result = agent.summarize(mixed_findings)
        for fix in result.prioritized_fixes:
            assert len(fix.principle.strip()) > 0

    def test_same_severity_sorted_by_line_number(self, agent):
        """Within a severity tier, earlier lines should appear first."""
        findings = [
            make_finding(SmellType.POOR_NAMING, Severity.HIGH, line=50),
            make_finding(SmellType.POOR_NAMING, Severity.HIGH, line=10),
            make_finding(SmellType.POOR_NAMING, Severity.HIGH, line=30),
        ]
        result = agent.summarize(findings)
        lines = [f.line_number for f in result.prioritized_fixes]
        assert lines == sorted(lines)

    def test_empty_findings_returns_empty_list(self, agent):
        result = agent.summarize([])
        assert result.prioritized_fixes == []


# ── Agent contributions ────────────────────────────────────────────────────────

class TestAgentContributions:
    def test_both_agents_present(self, agent, mixed_findings):
        result = agent.summarize(mixed_findings)
        assert "security_vulnerability" in result.agent_contributions
        assert "code_analysis" in result.agent_contributions

    def test_security_agent_count(self, agent, mixed_findings):
        result = agent.summarize(mixed_findings)
        assert result.agent_contributions["security_vulnerability"] == 2

    def test_code_analysis_count(self, agent, mixed_findings):
        result = agent.summarize(mixed_findings)
        assert result.agent_contributions["code_analysis"] == 3

    def test_single_agent_findings(self, agent):
        findings = [make_finding(source="code_analysis") for _ in range(3)]
        result = agent.summarize(findings)
        assert result.agent_contributions == {"code_analysis": 3}


# ── has_critical / has_blocking flags ─────────────────────────────────────────

class TestFlags:
    def test_has_critical_true_when_critical_present(self, agent, mixed_findings):
        assert agent.summarize(mixed_findings).has_critical is True

    def test_has_critical_false_when_no_critical(self, agent):
        findings = [make_finding(severity=Severity.HIGH)]
        assert agent.summarize(findings).has_critical is False

    def test_has_blocking_true_for_critical(self, agent, mixed_findings):
        assert agent.summarize(mixed_findings).has_blocking is True

    def test_has_blocking_true_for_high(self, agent):
        findings = [make_finding(severity=Severity.HIGH)]
        assert agent.summarize(findings).has_blocking is True

    def test_has_blocking_false_for_medium_only(self, agent):
        findings = [make_finding(severity=Severity.MEDIUM)]
        assert agent.summarize(findings).has_blocking is False

    def test_has_blocking_false_for_low_only(self, agent):
        findings = [make_finding(severity=Severity.LOW)]
        assert agent.summarize(findings).has_blocking is False

    def test_both_false_on_empty(self, agent):
        result = agent.summarize([])
        assert result.has_critical is False
        assert result.has_blocking is False


# ── Executive overview ─────────────────────────────────────────────────────────

class TestExecutiveOverview:
    def test_overview_non_empty(self, agent, mixed_findings):
        result = agent.summarize(mixed_findings)
        assert len(result.executive_overview.strip()) > 10

    def test_overview_mentions_filename(self, agent, mixed_findings):
        result = agent.summarize(mixed_findings, filename="auth.py")
        assert "auth.py" in result.executive_overview

    def test_overview_mentions_blocking_when_critical(self, agent, mixed_findings):
        result = agent.summarize(mixed_findings, filename="auth.py")
        assert "critical" in result.executive_overview.lower() or \
               "merging" in result.executive_overview.lower() or \
               "attention" in result.executive_overview.lower()

    def test_overview_healthy_on_empty(self, agent):
        result = agent.summarize([], filename="clean.py")
        assert "clean.py" in result.executive_overview
        assert "healthy" in result.executive_overview.lower() or \
               "no findings" in result.executive_overview.lower() or \
               "passed" in result.executive_overview.lower()

    def test_overview_fair_shape_when_no_blocking(self, agent):
        findings = [make_finding(severity=Severity.LOW)]
        result = agent.summarize(findings)
        assert "fair" in result.executive_overview.lower() or \
               "no blocking" in result.executive_overview.lower() or \
               "maintenance" in result.executive_overview.lower()


# ── Serialisation ─────────────────────────────────────────────────────────────

class TestSerialization:
    def test_to_dict_top_level_keys(self, agent, mixed_findings):
        d = agent.summarize(mixed_findings).to_dict()
        assert set(d.keys()) == {
            "executive_overview",
            "severity_breakdown",
            "prioritized_fixes",
            "agent_contributions",
            "has_critical",
            "has_blocking",
        }

    def test_severity_breakdown_serialisable(self, agent, mixed_findings):
        d = agent.summarize(mixed_findings).to_dict()
        bd = d["severity_breakdown"]
        assert set(bd.keys()) == {"critical", "high", "medium", "low", "total"}
        assert all(isinstance(v, int) for v in bd.values())

    def test_prioritized_fixes_serialisable(self, agent, mixed_findings):
        d = agent.summarize(mixed_findings).to_dict()
        for fix in d["prioritized_fixes"]:
            assert set(fix.keys()) == {
                "rank", "severity", "finding_type", "line_number",
                "source_agent", "one_liner", "fix_action", "principle",
            }

    def test_all_values_json_primitive(self, agent, mixed_findings):
        """Ensure to_dict() produces only JSON-safe primitives."""
        import json
        d = agent.summarize(mixed_findings).to_dict()
        # Should not raise
        json.dumps(d)
