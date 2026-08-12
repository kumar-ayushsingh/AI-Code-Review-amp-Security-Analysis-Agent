"""
shared/models.py
---------
Shared data models used across all agents.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Union


class Severity(str, Enum):
    """Impact level on maintainability or security."""

    CRITICAL = "critical"  # Must fix immediately
    HIGH = "high"          # Seriously degrades quality or security
    MEDIUM = "medium"      # Noticeable issue; fix in next cycle
    LOW = "low"            # Minor issue; fix when convenient


class SmellType(str, Enum):
    """Categories of detected code smells."""

    LONG_METHOD = "long_method"
    DUPLICATE_CODE = "duplicate_code"
    POOR_NAMING = "poor_naming"
    HIGH_COMPLEXITY = "high_complexity"
    TIGHT_COUPLING = "tight_coupling"


class VulnerabilityType(str, Enum):
    """Categories of detected security vulnerabilities."""

    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    CSRF = "csrf"
    HARDCODED_SECRET = "hardcoded_secret"
    INSECURE_AUTH = "insecure_auth"
    BROKEN_ACCESS_CONTROL = "broken_access_control"


@dataclass
class Remediation:
    """
    Auto-generated remediation advice attached to a Finding.

    Attributes
    ----------
    corrected_code : str
        A self-contained illustrative code snippet showing the fixed pattern.
    explanation : str
        Plain-language description of why the fix eliminates the issue.
    principle : str
        The named secure-coding or clean-code principle being applied
        (e.g. "OWASP A03:2021 – Injection", "Single Responsibility Principle").
    """

    corrected_code: str
    explanation: str
    principle: str

    def to_dict(self) -> dict:
        return {
            "corrected_code": self.corrected_code,
            "explanation": self.explanation,
            "principle": self.principle,
        }


@dataclass
class Finding:
    """
    A single finding produced by an analysis agent.

    Attributes
    ----------
    type : SmellType or VulnerabilityType
        The category of code smell or vulnerability detected.
    severity : Severity
        How severely this impacts maintainability or security.
    line_number : int
        1-based line number where the issue begins (0 = file-level).
    description : str
        Human-readable explanation of the issue and suggested remedy.
    source_agent : str
        Identifies which agent produced this finding.
    symbol : str, optional
        Name of the method / class / variable involved (if applicable).
    extra : dict
        Arbitrary detector-specific metadata.
    """

    type: Union[SmellType, VulnerabilityType]
    severity: Severity
    line_number: int
    description: str
    source_agent: str
    symbol: Optional[str] = None
    extra: dict = field(default_factory=dict)
    remediation: Optional[Remediation] = None

    # ------------------------------------------------------------------ #
    # Serialisation helpers                                                #
    # ------------------------------------------------------------------ #

    def to_dict(self) -> dict:
        """Return a plain dict suitable for JSON serialisation."""
        return {
            "type": self.type.value if hasattr(self.type, 'value') else self.type,
            "severity": self.severity.value,
            "line_number": self.line_number,
            "description": self.description,
            "source_agent": self.source_agent,
            "symbol": self.symbol,
            "extra": self.extra,
            "remediation": self.remediation.to_dict() if self.remediation else None,
        }

    def __str__(self) -> str:  # pragma: no cover
        loc = f"line {self.line_number}" if self.line_number else "file level"
        sym = f" [{self.symbol}]" if self.symbol else ""
        type_str = self.type.value if hasattr(self.type, 'value') else self.type
        return (
            f"[{self.severity.value.upper()}] {type_str}{sym} @ {loc}: "
            f"{self.description}"
        )


# ═══════════════════════════════════════════════════════════════════════════ #
# PR Summary data model                                                       #
# ═══════════════════════════════════════════════════════════════════════════ #

@dataclass
class FindingSummary:
    """
    A compact, human-readable digest of a single Finding for use inside a
    PRSummary.  All fields are plain strings so the object is trivially
    JSON-serialisable.

    Attributes
    ----------
    rank : int
        1-based position in the prioritised fix list (1 = most urgent).
    severity : str
        Severity label ("critical" | "high" | "medium" | "low").
    finding_type : str
        The finding type value (e.g. "sql_injection", "poor_naming").
    line_number : int
        Source line where the issue begins.
    source_agent : str
        Which agent raised this finding.
    one_liner : str
        One sentence describing the problem.
    fix_action : str
        One sentence describing the concrete fix action.
    principle : str
        Secure-coding / clean-code principle, if a remediation is attached.
    """

    rank: int
    severity: str
    finding_type: str
    line_number: int
    source_agent: str
    one_liner: str
    fix_action: str
    principle: str = ""

    def to_dict(self) -> dict:
        return {
            "rank": self.rank,
            "severity": self.severity,
            "finding_type": self.finding_type,
            "line_number": self.line_number,
            "source_agent": self.source_agent,
            "one_liner": self.one_liner,
            "fix_action": self.fix_action,
            "principle": self.principle,
        }


@dataclass
class SeverityBreakdown:
    """
    Count of findings at each severity level.

    Attributes
    ----------
    critical / high / medium / low : int
        Counts per bucket.
    total : int
        Sum of all findings.
    """

    critical: int = 0
    high: int     = 0
    medium: int   = 0
    low: int      = 0

    @property
    def total(self) -> int:
        return self.critical + self.high + self.medium + self.low

    def to_dict(self) -> dict:
        return {
            "critical": self.critical,
            "high": self.high,
            "medium": self.medium,
            "low": self.low,
            "total": self.total,
        }


@dataclass
class PRSummary:
    """
    A structured pull-request-style review summary produced by PRSummaryAgent.

    Attributes
    ----------
    executive_overview : str
        1-2 sentence health assessment of the submitted code.
    severity_breakdown : SeverityBreakdown
        Counts of findings by severity level.
    prioritized_fixes : list[FindingSummary]
        All findings ordered by severity (critical first), then line number.
        Each entry includes a 1-based rank, one-liner, and fix action.
    agent_contributions : dict[str, int]
        Maps source_agent → number of findings it raised.
    has_critical : bool
        True if any CRITICAL finding exists (convenience flag for CI gates).
    has_blocking : bool
        True if any CRITICAL or HIGH finding exists.
    """

    executive_overview: str
    severity_breakdown: SeverityBreakdown
    prioritized_fixes: list  # list[FindingSummary]
    agent_contributions: dict
    has_critical: bool
    has_blocking: bool

    # ── Convenience properties ────────────────────────────────────────────

    @property
    def total_findings(self) -> int:
        return self.severity_breakdown.total

    @property
    def critical_count(self) -> int:
        return self.severity_breakdown.critical

    @property
    def high_count(self) -> int:
        return self.severity_breakdown.high

    @property
    def medium_count(self) -> int:
        return self.severity_breakdown.medium

    @property
    def low_count(self) -> int:
        return self.severity_breakdown.low

    @property
    def health_score(self) -> int:
        """0-100 score. Deductions: critical=-15, high=-8, medium=-3, low=-1."""
        score = (
            100
            - 15 * self.severity_breakdown.critical
            - 8  * self.severity_breakdown.high
            - 3  * self.severity_breakdown.medium
            - 1  * self.severity_breakdown.low
        )
        return max(0, score)

    def to_dict(self) -> dict:
        return {
            "executive_overview": self.executive_overview,
            "severity_breakdown": self.severity_breakdown.to_dict(),
            "prioritized_fixes": [f.to_dict() for f in self.prioritized_fixes],
            "agent_contributions": self.agent_contributions,
            "has_critical": self.has_critical,
            "has_blocking": self.has_blocking,
            "health_score": self.health_score,
            "total_findings": self.total_findings,
        }
