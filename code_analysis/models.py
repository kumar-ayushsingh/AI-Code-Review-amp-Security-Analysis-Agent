"""
models.py
---------
Shared data models used across all detectors.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    """Impact level on maintainability."""

    CRITICAL = "critical"  # Must fix immediately; blocks understanding / extension
    HIGH = "high"          # Seriously degrades quality; should be fixed soon
    MEDIUM = "medium"      # Noticeable smell; fix in next refactoring cycle
    LOW = "low"            # Minor issue; fix when convenient


class SmellType(str, Enum):
    """Categories of detected code smells."""

    LONG_METHOD = "long_method"
    DUPLICATE_CODE = "duplicate_code"
    POOR_NAMING = "poor_naming"
    HIGH_COMPLEXITY = "high_complexity"
    TIGHT_COUPLING = "tight_coupling"


@dataclass
class Finding:
    """
    A single code-smell finding produced by the analysis agent.

    Attributes
    ----------
    type : SmellType
        The category of code smell detected.
    severity : Severity
        How severely this smell impacts maintainability.
    line_number : int
        1-based line number where the smell begins (0 = file-level).
    description : str
        Human-readable explanation of the issue and suggested remedy.
    source_agent : str
        Always "code_analysis" for traceability in multi-agent pipelines.
    symbol : str, optional
        Name of the method / class / variable involved (if applicable).
    extra : dict
        Arbitrary detector-specific metadata (e.g. clone pair lines).
    """

    type: SmellType
    severity: Severity
    line_number: int
    description: str
    source_agent: str = "code_analysis"
    symbol: Optional[str] = None
    extra: dict = field(default_factory=dict)

    # ------------------------------------------------------------------ #
    # Serialisation helpers                                                #
    # ------------------------------------------------------------------ #

    def to_dict(self) -> dict:
        """Return a plain dict suitable for JSON serialisation."""
        return {
            "type": self.type.value,
            "severity": self.severity.value,
            "line_number": self.line_number,
            "description": self.description,
            "source_agent": self.source_agent,
            "symbol": self.symbol,
            "extra": self.extra,
        }

    def __str__(self) -> str:  # pragma: no cover
        loc = f"line {self.line_number}" if self.line_number else "file level"
        sym = f" [{self.symbol}]" if self.symbol else ""
        return (
            f"[{self.severity.value.upper()}] {self.type.value}{sym} @ {loc}: "
            f"{self.description}"
        )
