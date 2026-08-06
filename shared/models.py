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
